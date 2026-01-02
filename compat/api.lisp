;;; api.lisp --- cl+ssl API compatibility layer
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Anthony Green <green@moxielogic.com>
;;;
;;; Provides cl+ssl-compatible API wrapping pure-tls.

(in-package #:cl+ssl)

;;;; Constants (for compatibility)

(defconstant +ssl-verify-none+ 0)
(defconstant +ssl-verify-peer+ 1)
(defconstant +ssl-verify-fail-if-no-peer-cert+ 2)
(defconstant +ssl-verify-client-once+ 4)

(defconstant +ssl-op-no-sslv2+ #x01000000)
(defconstant +ssl-op-no-sslv3+ #x02000000)
(defconstant +ssl-op-no-tlsv1+ #x04000000)
(defconstant +ssl-op-no-tlsv1-1+ #x10000000)
(defconstant +ssl-op-no-tlsv1-2+ #x08000000)

(defconstant +ssl-sess-cache-off+ #x0000)
(defconstant +ssl-sess-cache-client+ #x0001)
(defconstant +ssl-sess-cache-server+ #x0002)
(defconstant +ssl-sess-cache-both+ #x0003)
(defconstant +ssl-sess-cache-no-auto-clear+ #x0080)
(defconstant +ssl-sess-cache-no-internal-lookup+ #x0100)
(defconstant +ssl-sess-cache-no-internal-store+ #x0200)
(defconstant +ssl-sess-cache-no-internal+ #x0300)

;;;; Default Variables

(defvar *default-cipher-list* nil
  "Default cipher list (ignored in TLS 1.3, kept for compatibility).")

(defvar *default-buffer-size* 2048
  "Default buffer size for SSL streams.")

(defvar *make-ssl-client-stream-verify-default* :required
  "Default verification mode for make-ssl-client-stream.")

(defvar *default-unwrap-stream-p* t
  "Whether to unwrap streams by default (compatibility, not used).")

;;;; Global Context

(defvar *ssl-global-context* nil
  "The global SSL context.")

(defun ensure-initialized (&key method)
  "Ensure the SSL library is initialized (no-op for pure Lisp implementation)."
  (declare (ignore method))
  (unless *ssl-global-context*
    (setf *ssl-global-context* (make-context)))
  t)

(defun reload ()
  "Reload the SSL library (no-op for pure Lisp implementation)."
  (setf *ssl-global-context* nil)
  t)

;;;; Context Management

(defun make-context (&key method
                          disabled-protocols
                          options
                          min-proto-version
                          session-cache-mode
                          (verify-location :default)
                          (verify-depth 100)
                          (verify-mode +ssl-verify-peer+)
                          verify-callback
                          cipher-list
                          pem-password-callback
                          certificate-chain-file
                          private-key-file
                          private-key-password
                          private-key-file-type)
  "Create a new SSL context (wraps pure-tls:make-tls-context)."
  (declare (ignore method disabled-protocols options min-proto-version
                   session-cache-mode verify-callback cipher-list
                   pem-password-callback private-key-password
                   private-key-file-type))
  (let ((tls-verify-mode (cond
                           ((zerop verify-mode) pure-tls:+verify-none+)
                           ((logtest verify-mode +ssl-verify-fail-if-no-peer-cert+)
                            pure-tls:+verify-required+)
                           (t pure-tls:+verify-peer+))))
    (pure-tls:make-tls-context
     :verify-mode tls-verify-mode
     :verify-depth verify-depth
     :certificate-chain-file certificate-chain-file
     :private-key-file private-key-file
     :ca-file (when (stringp verify-location) verify-location)
     :ca-directory (when (and (pathnamep verify-location)
                              (cl:directory verify-location))
                     verify-location))))

(defun ssl-ctx-free (context)
  "Free an SSL context."
  (pure-tls:tls-context-free context))

(defmacro with-global-context ((ssl-ctx &key auto-free-p) &body body)
  "Execute BODY with *SSL-GLOBAL-CONTEXT* bound to SSL-CTX."
  `(let ((*ssl-global-context* ,ssl-ctx))
     (pure-tls:with-tls-context (,ssl-ctx :auto-free-p ,auto-free-p)
       ,@body)))

;;;; Stream Creation

(defun make-ssl-client-stream (socket &key
                                        (unwrap-stream-p *default-unwrap-stream-p*)
                                        hostname
                                        close-callback
                                        external-format
                                        (verify *make-ssl-client-stream-verify-default*)
                                        alpn-protocols
                                        certificate key password
                                        (cipher-list *default-cipher-list*)
                                        method
                                        (buffer-size *default-buffer-size*)
                                        (input-buffer-size buffer-size)
                                        (output-buffer-size buffer-size))
  "Create an SSL client stream (wraps pure-tls:make-tls-client-stream)."
  (declare (ignore unwrap-stream-p certificate key password cipher-list method
                   input-buffer-size output-buffer-size))
  (let ((tls-verify-mode (cond
                           ((null verify) pure-tls:+verify-none+)
                           ((eq verify :optional) pure-tls:+verify-peer+)
                           ((eq verify :required) pure-tls:+verify-required+)
                           (t pure-tls:+verify-required+))))
    (pure-tls:make-tls-client-stream
     socket
     :hostname hostname
     :verify tls-verify-mode
     :alpn-protocols alpn-protocols
     :close-callback close-callback
     :external-format external-format
     :buffer-size buffer-size)))

(defun make-ssl-server-stream (socket &key
                                        (unwrap-stream-p *default-unwrap-stream-p*)
                                        close-callback
                                        external-format
                                        certificate key password
                                        (cipher-list *default-cipher-list*)
                                        method
                                        (buffer-size *default-buffer-size*)
                                        (input-buffer-size buffer-size)
                                        (output-buffer-size buffer-size))
  "Create an SSL server stream (wraps pure-tls:make-tls-server-stream)."
  (declare (ignore unwrap-stream-p password cipher-list method
                   input-buffer-size output-buffer-size))
  (pure-tls:make-tls-server-stream
   socket
   :certificate certificate
   :key key
   :close-callback close-callback
   :external-format external-format
   :buffer-size buffer-size))

;;;; Stream Accessors

(defun ssl-stream-x509-certificate (ssl-stream)
  "Get the peer's X.509 certificate."
  (pure-tls:tls-peer-certificate ssl-stream))

(defun get-selected-alpn-protocol (ssl-stream)
  "Get the selected ALPN protocol."
  (pure-tls:tls-selected-alpn ssl-stream))

(defgeneric stream-fd (stream)
  (:documentation "Get the file descriptor for a stream.")
  (:method (stream) stream))

#+sbcl
(defmethod stream-fd ((stream sb-sys:fd-stream))
  (sb-sys:fd-stream-fd stream))

;;;; Certificate Functions

(defun decode-certificate (format bytes)
  "Decode a certificate from bytes."
  (declare (ignore format))
  (pure-tls::parse-certificate bytes))

(defun decode-certificate-from-file (path &key format)
  "Load and decode a certificate from a file."
  (declare (ignore format))
  (pure-tls::parse-certificate-from-file path))

(defun x509-free (cert)
  "Free an X.509 certificate (no-op in pure Lisp)."
  (declare (ignore cert))
  nil)

(defun certificate-not-after-time (cert)
  "Get the notAfter time of a certificate."
  (pure-tls:certificate-not-after cert))

(defun certificate-not-before-time (cert)
  "Get the notBefore time of a certificate."
  (pure-tls:certificate-not-before cert))

(defun certificate-subject-common-names (cert)
  "Get the subject common names of a certificate."
  (pure-tls:certificate-subject-common-names cert))

(defun certificate-fingerprint (cert &optional (algorithm :sha1))
  "Get the fingerprint of a certificate."
  (pure-tls:certificate-fingerprint cert algorithm))

(defun verify-hostname (cert hostname)
  "Verify that a certificate matches a hostname."
  (pure-tls:verify-hostname cert hostname))

;;;; Utility Functions

(defun random-bytes (count)
  "Generate random bytes."
  (pure-tls:random-bytes count))

(defun use-certificate-chain-file (path)
  "Load a certificate chain file into the global context."
  (declare (ignore path))
  (ensure-initialized)
  ;; For compatibility - would need to update context
  (warn "use-certificate-chain-file: not fully implemented"))

(defun ssl-load-global-verify-locations (&rest pathnames)
  "Load verify locations into the global context."
  (declare (ignore pathnames))
  (ensure-initialized)
  (warn "ssl-load-global-verify-locations: not fully implemented"))

(defun ssl-set-global-default-verify-paths ()
  "Set default verify paths in the global context."
  (ensure-initialized)
  (warn "ssl-set-global-default-verify-paths: not fully implemented"))

;;;; PEM Password

(defvar *pem-password* nil
  "Current PEM password for callbacks.")

(defmacro with-pem-password ((password) &body body)
  "Execute BODY with the PEM password set."
  `(let ((*pem-password* ,password))
     ,@body))

;;;; Deprecated Functions

(defun ssl-check-verify-p ()
  "DEPRECATED. Check if verification is enabled."
  (not (eq *make-ssl-client-stream-verify-default* nil)))

(defun (setf ssl-check-verify-p) (value)
  "DEPRECATED. Set verification enabled."
  (setf *make-ssl-client-stream-verify-default*
        (if value :required nil)))

;;;; Conditions

(define-condition ssl-error (error)
  ((message :initarg :message :reader ssl-error-message))
  (:report (lambda (c s)
             (format s "SSL error: ~A" (ssl-error-message c)))))

(define-condition ssl-error-verify (ssl-error)
  ((stream :initarg :stream :reader ssl-error-stream)
   (error-code :initarg :error-code :reader ssl-error-code))
  (:report (lambda (c s)
             (format s "SSL verification error (code ~A)"
                     (ssl-error-code c)))))

(define-condition ssl-error-initialize (ssl-error)
  ((reason :initarg :reason :reader ssl-error-reason))
  (:report (lambda (c s)
             (format s "SSL initialization error: ~A"
                     (ssl-error-reason c)))))
