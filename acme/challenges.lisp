;;; challenges.lisp --- TLS-ALPN-01 challenge handler
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Anthony Green <green@moxielogic.com>
;;;
;;; TLS-ALPN-01 challenge implementation for ACME certificate validation.

(in-package #:pure-tls/acme)

;;; ----------------------------------------------------------------------------
;;; TLS-ALPN-01 Challenge Handler
;;; ----------------------------------------------------------------------------

(defvar *tls-alpn-server* nil
  "Currently running TLS-ALPN-01 validation server state.")

(defun generate-validation-certificate (domain key-authorization)
  "Generate a self-signed validation certificate for TLS-ALPN-01.
   Returns (VALUES cert-pem key-pem private-key)."
  ;; Generate a temporary RSA key for the validation certificate
  (multiple-value-bind (private-key public-key)
      (ironclad:generate-key-pair :rsa :num-bits 2048)
    (let* (
         ;; Hash the key authorization for the acmeIdentifier extension
         (key-auth-hash (ironclad:digest-sequence
                         :sha256
                         (flexi-streams:string-to-octets key-authorization
                                                         :external-format :utf-8)))
         ;; Validity: now to 7 days from now
         (not-before (get-universal-time))
         (not-after (+ not-before (* 7 24 60 60)))
         ;; Random serial number
         (serial (random (expt 2 64)))
         ;; Subject/Issuer: CN=domain (self-signed)
         (subject (encode-subject domain))
         ;; Subject Alternative Name extension with dNSName
         (san-ext (encode-critical-extension
                   *oid-subject-alt-name*
                   (encode-san-extension domain)))
         ;; acmeIdentifier extension (CRITICAL) containing hash
         ;; The value is an OCTET STRING containing the hash
         (acme-id-ext (encode-critical-extension
                       *oid-acme-identifier*
                       (encode-octet-string key-auth-hash)))
         ;; Build TBSCertificate
         (tbs-cert (encode-sequence
                    ;; version [0] EXPLICIT INTEGER (v3 = 2)
                    (encode-context-tag 0 (encode-integer 2))
                    ;; serialNumber
                    (encode-integer serial)
                    ;; signature algorithm (SHA256 with RSA)
                    (encode-sequence
                     (encode-oid *oid-sha256-with-rsa*)
                     (encode-null))
                    ;; issuer (self-signed, same as subject)
                    subject
                    ;; validity
                    (encode-validity not-before not-after)
                    ;; subject
                    subject
                    ;; subjectPublicKeyInfo
                    (encode-rsa-public-key private-key public-key)
                    ;; extensions [3]
                    (encode-x509-extensions (list san-ext acme-id-ext))))
         ;; Sign TBSCertificate
         (signature (let ((digest (ironclad:digest-sequence :sha256 tbs-cert)))
                      (ironclad:sign-message private-key digest)))
         ;; Build Certificate
         (certificate (encode-sequence
                       tbs-cert
                       (encode-sequence
                        (encode-oid *oid-sha256-with-rsa*)
                        (encode-null))
                       (encode-bit-string signature)))
         ;; Convert to PEM
         (cert-pem (wrap-pem "CERTIFICATE" certificate))
         (key-der (encode-rsa-private-key-der private-key))
         (key-pem (wrap-pem "RSA PRIVATE KEY" key-der)))

      (values cert-pem key-pem private-key))))

(defun save-temp-validation-files (cert-pem key-pem)
  "Save validation certificate and key to temporary files.
   Returns (VALUES cert-path key-path)."
  (let ((cert-path (merge-pathnames "acme-validation-cert.pem" *cert-directory*))
        (key-path (merge-pathnames "acme-validation-key.pem" *cert-directory*)))
    (ensure-directories-exist cert-path)
    (with-open-file (out cert-path :direction :output
                                   :if-exists :supersede)
      (write-string cert-pem out))
    (with-open-file (out key-path :direction :output
                                  :if-exists :supersede)
      (write-string key-pem out))
    #+sbcl (sb-posix:chmod (namestring key-path) #o600)
    (values cert-path key-path)))

(defun start-tls-alpn-server (domain key-authorization &optional (port 443))
  "Start TLS-ALPN-01 validation server on the specified port.
   The server responds to connections with ALPN 'acme-tls/1' using
   a self-signed certificate containing the acmeIdentifier extension."
  ;; Generate validation certificate
  (multiple-value-bind (cert-pem key-pem)
      (generate-validation-certificate domain key-authorization)

    ;; Save to temp files (pure-tls needs file paths)
    (multiple-value-bind (cert-path key-path)
        (save-temp-validation-files cert-pem key-pem)

      ;; Create TCP listener
      (let ((listen-socket (usocket:socket-listen "0.0.0.0" port
                                                  :reuse-address t
                                                  :element-type '(unsigned-byte 8)
                                                  :backlog 5)))
        (setf *tls-alpn-server*
              (list :socket listen-socket
                    :cert-path cert-path
                    :key-path key-path
                    :running t))

        ;; Start accept thread
        (bt:make-thread
         (lambda ()
           (unwind-protect
               (tls-alpn-accept-loop listen-socket cert-path key-path)
             nil))
         :name "tls-alpn-01-server")))))

(defun tls-alpn-accept-loop (listen-socket cert-path key-path)
  "Accept loop for TLS-ALPN-01 validation connections."
  (loop while (and *tls-alpn-server*
                   (getf *tls-alpn-server* :running))
        do (handler-case
               (let ((client-socket (usocket:socket-accept listen-socket
                                                           :element-type '(unsigned-byte 8))))
                 (bt:make-thread
                  (lambda ()
                    (handle-tls-alpn-connection client-socket cert-path key-path))
                  :name "tls-alpn-handler"))
             (usocket:socket-error (e)
               (declare (ignore e))
               (unless (and *tls-alpn-server*
                            (getf *tls-alpn-server* :running))
                 (return)))  ; Expected when stopping
             (error (e)
               (declare (ignore e))))))

(defun handle-tls-alpn-connection (client-socket cert-path key-path)
  "Handle a TLS-ALPN-01 validation connection."
  (handler-case
      (let ((client-stream (usocket:socket-stream client-socket)))
        ;; Create TLS server stream with ONLY acme-tls/1 ALPN
        (let ((tls-stream (pure-tls:make-tls-server-stream
                          client-stream
                          :certificate (namestring cert-path)
                          :key (namestring key-path)
                          :alpn-protocols '("acme-tls/1"))))
          ;; The connection will be closed by the ACME server after validation
          ;; Just wait briefly and close
          (sleep 1)
          (close tls-stream)))
    (error (e)
      (declare (ignore e))))
  (ignore-errors (usocket:socket-close client-socket)))

(defun stop-tls-alpn-server ()
  "Stop the TLS-ALPN-01 validation server."
  (when *tls-alpn-server*
    (setf (getf *tls-alpn-server* :running) nil)
    (let ((socket (getf *tls-alpn-server* :socket)))
      (when socket
        (ignore-errors (usocket:socket-close socket))))
    ;; Clean up temp files
    (let ((cert-path (getf *tls-alpn-server* :cert-path))
          (key-path (getf *tls-alpn-server* :key-path)))
      (when cert-path (ignore-errors (delete-file cert-path)))
      (when key-path (ignore-errors (delete-file key-path))))
    (setf *tls-alpn-server* nil)))
