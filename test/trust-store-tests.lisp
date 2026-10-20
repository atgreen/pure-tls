;;; test/trust-store-tests.lisp --- Trust store auto-load regression tests
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Anthony Green <green@moxielogic.com>
;;;
;;; Regression tests for system trust-store auto-loading in MAKE-TLS-CONTEXT.
;;;
;;; Bug: MAKE-TLS-CONTEXT auto-loaded the system CA store only for
;;; +VERIFY-REQUIRED+, leaving a +VERIFY-PEER+ context with an empty trust
;;; store.  +VERIFY-PEER+ still verifies a presented certificate (servers
;;; always present one), so such a context failed every chain with UNKNOWN-CA.
;;; This bit the cl+ssl compatibility layer, whose default context is
;;; +VERIFY-PEER+ -- e.g. drakma-based HTTPS (ocicl's self-update path) failed
;;; on Linux with "No trusted root certificates available for verification".
;;;
;;; These tests pin the trust source with SSL_CERT_FILE (a fixture bundle) so
;;; they do not depend on the host's real system trust store.

(in-package #:pure-tls/test)

(eval-when (:compile-toplevel :load-toplevel :execute)
  (require :sb-posix))

(def-suite trust-store-tests
  :description "System trust-store auto-loading in make-tls-context")

(in-suite trust-store-tests)

(defmacro with-ssl-cert-file ((path) &body body)
  "Run BODY with the SSL_CERT_FILE environment variable bound to PATH,
restoring the previous value afterwards."
  (let ((old (gensym)) (p (gensym)))
    `(let ((,old (uiop:getenv "SSL_CERT_FILE"))
           (,p (namestring ,path)))
       (unwind-protect
            (progn (sb-posix:setenv "SSL_CERT_FILE" ,p 1) ,@body)
         (if ,old
             (sb-posix:setenv "SSL_CERT_FILE" ,old 1)
             (sb-posix:unsetenv "SSL_CERT_FILE"))))))

(defun context-root-count (ctx)
  "Number of trusted roots loaded into CTX (0 when the trust store is NIL)."
  (let ((ts (pure-tls::tls-context-trust-store ctx)))
    (if ts (length (pure-tls::trust-store-certificates ts)) 0)))

(test verify-peer-auto-loads-system-roots
  "+verify-peer+ must auto-load the system trust store (UNKNOWN-CA regression)."
  (with-ssl-cert-file ((test-cert-path "self-signed-valid.pem"))
    (let ((ctx (pure-tls:make-tls-context :verify-mode pure-tls:+verify-peer+)))
      (is (plusp (context-root-count ctx))
          "+verify-peer+ context has an empty trust store; a presented ~
           certificate would fail with UNKNOWN-CA"))))

(test verify-required-auto-loads-system-roots
  "+verify-required+ still auto-loads the system trust store."
  (with-ssl-cert-file ((test-cert-path "self-signed-valid.pem"))
    (let ((ctx (pure-tls:make-tls-context :verify-mode pure-tls:+verify-required+)))
      (is (plusp (context-root-count ctx))))))

(test verify-none-does-not-auto-load
  "+verify-none+ must NOT auto-load a trust store."
  (with-ssl-cert-file ((test-cert-path "self-signed-valid.pem"))
    (let ((ctx (pure-tls:make-tls-context :verify-mode pure-tls:+verify-none+)))
      (is (zerop (context-root-count ctx))))))

(test stream-verify-falls-back-to-system-roots
  "cl+ssl puts the verify mode on the STREAM, not the context: drakma builds
its context with +ssl-verify-none+ and then asks make-ssl-client-stream to
verify.  A context that does not verify therefore still has to yield system
roots to a stream that does, or every chain fails with UNKNOWN-CA."
  (with-ssl-cert-file ((test-cert-path "self-signed-valid.pem"))
    (let ((ctx (pure-tls:make-tls-context :verify-mode pure-tls:+verify-none+)))
      (is (zerop (context-root-count ctx))
          "the context itself must still not auto-load; that policy is deliberate")
      (dolist (verify (list pure-tls:+verify-peer+ pure-tls:+verify-required+))
        (let ((store (pure-tls::effective-trust-store ctx verify)))
          (is (and store (plusp (length (pure-tls::trust-store-certificates store))))
              "a stream asked to verify got no roots from a verify-none context"))))))

(test stream-without-verify-gets-no-roots
  "A stream that does not verify must not quietly acquire a trust store."
  (with-ssl-cert-file ((test-cert-path "self-signed-valid.pem"))
    (let ((ctx (pure-tls:make-tls-context :verify-mode pure-tls:+verify-none+)))
      (is (null (pure-tls::effective-trust-store ctx pure-tls:+verify-none+))))))

(test stream-verify-keeps-the-context-store
  "An explicit trust store on the context wins; the fallback only fills a gap."
  (let ((ctx (pure-tls:make-tls-context
              :verify-mode pure-tls:+verify-peer+
              :ca-file (namestring (test-cert-path "self-signed-valid.pem")))))
    (is (eq (pure-tls::tls-context-trust-store ctx)
            (pure-tls::effective-trust-store ctx pure-tls:+verify-required+)))))

(test explicit-ca-file-overrides-auto-load
  "An explicit :ca-file is honored regardless of verify mode."
  (let ((ctx (pure-tls:make-tls-context
              :verify-mode pure-tls:+verify-peer+
              :ca-file (namestring (test-cert-path "self-signed-valid.pem")))))
    (is (plusp (context-root-count ctx)))))

;;; Trust stores built from CA files are cached per source and write date.
;;; Drakma makes a new context for every connection, so without the cache each
;;; connection re-parsed the whole CA bundle before its ClientHello.

(defmacro with-ca-file-copy ((var) &body body)
  "Run BODY with VAR bound to a fresh copy of the self-signed fixture."
  `(uiop:with-temporary-file (:pathname ,var :type "pem")
     (uiop:copy-file (test-cert-path "self-signed-valid.pem") ,var)
     ,@body))

;;; Portable: FILE-WRITE-DATE has one-second resolution, so wait for the next
;;; second before rewriting the file to be sure it gets a new write date.
(defun rewrite-with-new-write-date (path)
  (let ((before (file-write-date path)))
    (loop do (sleep 0.25)
             (uiop:copy-file (test-cert-path "self-signed-valid.pem") path)
          until (/= before (file-write-date path)))))

(test trust-store-cached-per-source
  "The same CA file yields the same trust store object."
  (with-ca-file-copy (path)
    (let ((a (pure-tls::make-trust-store-from-sources path nil))
          (b (pure-tls::make-trust-store-from-sources path nil)))
      (is (plusp (length (pure-tls::trust-store-certificates a))))
      (is (eq a b)))))

(test trust-store-rebuilt-when-source-changes
  "A new write date on the CA file builds a new trust store."
  (with-ca-file-copy (path)
    (let ((a (pure-tls::make-trust-store-from-sources path nil)))
      (rewrite-with-new-write-date path)
      (let ((b (pure-tls::make-trust-store-from-sources path nil)))
        (is (not (eq a b)))
        (is (plusp (length (pure-tls::trust-store-certificates b))))))))

(test empty-trust-store-not-cached
  "A source that yields no certificates is not cached, so it fails closed
until it holds some."
  (uiop:with-temporary-file (:pathname path :type "pem")
    (is (zerop (length (pure-tls::trust-store-certificates
                        (pure-tls::make-trust-store-from-sources path nil)))))
    (is (null (gethash (pure-tls::trust-store-cache-key path nil)
                       pure-tls::*trust-store-cache*)))))
