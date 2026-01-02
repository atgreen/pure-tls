;;; context.lisp --- TLS Context Management
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Anthony Green <green@moxielogic.com>
;;;
;;; Implements TLS context for configuration and session management.

(in-package #:pure-tls)

;;;; TLS Context

(defstruct (tls-context (:constructor make-tls-context-struct))
  "TLS configuration context (similar to SSL_CTX)."
  ;; Verification settings
  (verify-mode +verify-required+ :type fixnum)
  (verify-depth 100 :type fixnum)
  ;; Certificate chain for server mode
  (certificate-chain nil :type list)
  ;; Private key for server mode
  (private-key nil)
  ;; Trusted CA certificates
  (trust-store nil)
  ;; Supported cipher suites
  (cipher-suites (list +tls-aes-128-gcm-sha256+
                       +tls-chacha20-poly1305-sha256+)
                 :type list)
  ;; ALPN protocols
  (alpn-protocols nil :type list)
  ;; Session cache (for session resumption - future)
  (session-cache nil))

;;;; Default Context

(defvar *default-tls-context* nil
  "The default TLS context used when none is specified.")

(defvar *auto-load-system-trust-store* t
  "When true, automatically load system CA trust store for verify-required mode.")

(defun ensure-default-context ()
  "Ensure a default TLS context exists.
   If verify mode is +verify-required+ and auto-load is enabled,
   automatically loads the system trust store."
  (unless *default-tls-context*
    (let ((ctx (make-tls-context)))
      ;; Auto-load system trust store if verify-required and no trust store set
      (when (and *auto-load-system-trust-store*
                 (= (tls-context-verify-mode ctx) +verify-required+)
                 (null (tls-context-trust-store ctx)))
        (setf (tls-context-trust-store ctx) (load-system-trust-store)))
      (setf *default-tls-context* ctx)))
  *default-tls-context*)

;;;; Context Creation

(defun make-tls-context (&key
                           (verify-mode +verify-required+)
                           (verify-depth 100)
                           certificate-chain-file
                           private-key-file
                           ca-file
                           ca-directory
                           cipher-suites
                           alpn-protocols
                           (auto-load-system-ca t))
  "Create a new TLS context with the specified configuration.

   VERIFY-MODE - Certificate verification mode:
     +VERIFY-NONE+ - No verification
     +VERIFY-PEER+ - Verify if certificate presented
     +VERIFY-REQUIRED+ - Require and verify certificate

   VERIFY-DEPTH - Maximum certificate chain depth.

   CERTIFICATE-CHAIN-FILE - PEM file containing certificate chain (for servers).

   PRIVATE-KEY-FILE - PEM file containing private key (for servers).

   CA-FILE - PEM file containing trusted CA certificates.

   CA-DIRECTORY - Directory containing trusted CA certificates.

   CIPHER-SUITES - List of allowed cipher suites.

   ALPN-PROTOCOLS - List of ALPN protocol names.

   AUTO-LOAD-SYSTEM-CA - If T (default), automatically load system CA store
     when verify-mode is +VERIFY-REQUIRED+ and no CA file/directory is specified."
  (let ((ctx (make-tls-context-struct
              :verify-mode verify-mode
              :verify-depth verify-depth
              :alpn-protocols alpn-protocols)))
    ;; Load certificate chain if specified
    (when certificate-chain-file
      (setf (tls-context-certificate-chain ctx)
            (load-certificate-chain certificate-chain-file)))
    ;; Load private key if specified
    (when private-key-file
      (setf (tls-context-private-key ctx)
            (load-private-key private-key-file)))
    ;; Load trusted CAs
    (cond
      ;; Explicit CA file or directory specified
      ((or ca-file ca-directory)
       (setf (tls-context-trust-store ctx)
             (make-trust-store-from-sources ca-file ca-directory)))
      ;; Auto-load system CAs if verify-required and enabled
      ((and auto-load-system-ca
            (= verify-mode +verify-required+))
       (setf (tls-context-trust-store ctx)
             (load-system-trust-store))))
    ;; Set cipher suites
    (when cipher-suites
      (setf (tls-context-cipher-suites ctx) cipher-suites))
    ctx))

;;;; Context Binding

(defmacro with-tls-context ((context &key auto-free-p) &body body)
  "Execute BODY with *DEFAULT-TLS-CONTEXT* bound to CONTEXT.
   If AUTO-FREE-P is true, free the context when done."
  `(let ((*default-tls-context* ,context))
     (unwind-protect
          (progn ,@body)
       (when ,auto-free-p
         (tls-context-free ,context)))))

(defun tls-context-free (context)
  "Free resources associated with a TLS context."
  (declare (ignore context))
  ;; Currently no external resources to free
  nil)

;;;; Certificate Loading

(defun load-certificate-chain (path)
  "Load a certificate chain from a PEM file.
   Skips certificates that fail to parse (with a warning)."
  (let ((bytes (read-file-bytes path))
        (certs nil))
    (if (pem-encoded-p bytes)
        ;; Parse all certificate blocks
        (let ((text (octets-to-string bytes))
              (start 0))
          (loop
            (let ((begin-pos (search "-----BEGIN CERTIFICATE-----" text :start2 start)))
              (unless begin-pos (return))
              (let ((end-pos (search "-----END CERTIFICATE-----" text :start2 begin-pos)))
                (unless end-pos (return))
                (let* ((block-end (+ end-pos (length "-----END CERTIFICATE-----")))
                       (pem-block (subseq text begin-pos block-end)))
                  (handler-case
                      (let ((der (pem-decode (string-to-octets pem-block) "CERTIFICATE")))
                        (push (parse-certificate der) certs))
                    (error (e)
                      (warn "Failed to parse certificate at position ~D: ~A" begin-pos e)))
                  (setf start block-end))))))
        ;; Single DER certificate
        (handler-case
            (push (parse-certificate bytes) certs)
          (error (e)
            (warn "Failed to parse certificate from ~A: ~A" path e))))
    (nreverse certs)))

(defun load-private-key (path)
  "Load a private key from a PEM file."
  (let ((bytes (read-file-bytes path)))
    (if (pem-encoded-p bytes)
        (let ((text (octets-to-string bytes)))
          ;; Try different PEM labels
          (cond
            ((search "-----BEGIN PRIVATE KEY-----" text)
             (pem-decode bytes "PRIVATE KEY"))
            ((search "-----BEGIN RSA PRIVATE KEY-----" text)
             (pem-decode bytes "RSA PRIVATE KEY"))
            ((search "-----BEGIN EC PRIVATE KEY-----" text)
             (pem-decode bytes "EC PRIVATE KEY"))
            (t
             (error 'tls-error :message "Unknown private key format"))))
        ;; Assume DER
        bytes)))

(defun make-trust-store-from-sources (ca-file ca-directory)
  "Create a trust store from a CA file and/or directory."
  (let ((certs nil))
    ;; Load from file
    (when ca-file
      (setf certs (append certs (load-certificate-chain ca-file))))
    ;; Load from directory
    (when ca-directory
      (let ((dir-store (make-trust-store-from-directory ca-directory)))
        (setf certs (append certs (trust-store-certificates dir-store)))))
    (make-trust-store :certificates certs)))

;;;; System CA Certificates

(defun load-system-trust-store ()
  "Load the system's default trusted CA certificates."
  (let ((paths '("/etc/ssl/certs/ca-certificates.crt"      ; Debian/Ubuntu
                 "/etc/pki/tls/certs/ca-bundle.crt"        ; RHEL/CentOS
                 "/etc/ssl/ca-bundle.pem"                   ; OpenSUSE
                 "/usr/local/share/certs/ca-root-nss.crt"  ; FreeBSD
                 "/etc/ssl/cert.pem")))                    ; macOS
    (dolist (path paths)
      (when (probe-file path)
        (return-from load-system-trust-store
          (make-trust-store-from-sources path nil)))))
  ;; Try directory-based stores
  (let ((dirs '("/etc/ssl/certs"
                "/etc/pki/tls/certs")))
    (dolist (dir dirs)
      (when (probe-file dir)
        (return-from load-system-trust-store
          (make-trust-store-from-directory dir)))))
  ;; No system store found
  (warn "Could not find system CA certificates")
  (make-trust-store))

(defun context-with-system-trust (context)
  "Return a new context with system trust store loaded."
  (let ((new-ctx (copy-structure context)))
    (setf (tls-context-trust-store new-ctx)
          (load-system-trust-store))
    new-ctx))
