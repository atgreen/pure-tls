;;; csr.lisp --- CSR generation for ACME
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Anthony Green <green@moxielogic.com>
;;;
;;; Certificate Signing Request generation and certificate acquisition.

(in-package #:pure-tls/acme)

;;; ----------------------------------------------------------------------------
;;; Domain key generation
;;; ----------------------------------------------------------------------------

(defun generate-domain-key ()
  "Generate RSA key pair for the certificate (separate from account key).
   Returns (values private-key public-key)."
  (ironclad:generate-key-pair :rsa :num-bits 2048))

;;; ----------------------------------------------------------------------------
;;; CSR generation
;;; ----------------------------------------------------------------------------

(defun encode-extension-request (domains)
  "Encode CSR attributes with extension request for SAN."
  ;; Attributes ::= SET OF Attribute
  ;; Attribute ::= SEQUENCE { type OID, values SET OF ANY }
  (let* ((san-extension (encode-san-extension domains))
         ;; Extension ::= SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }
         (extension (encode-sequence
                     (encode-oid *oid-subject-alt-name*)
                     (encode-octet-string san-extension)))
         ;; Extensions ::= SEQUENCE OF Extension
         (extensions (encode-sequence extension)))
    ;; [0] IMPLICIT Attributes
    (encode-context-tag 0
                        (encode-sequence
                         (encode-oid *oid-extension-request*)
                         (encode-set extensions)))))

(defun build-csr-info (private-key public-key domains)
  "Build the CertificationRequestInfo structure.
   PRIVATE-KEY and PUBLIC-KEY are the RSA key pair.
   DOMAINS is a string or list of domain names."
  (let* ((primary-domain (if (listp domains) (first domains) domains))
         (all-domains (if (listp domains) domains (list domains))))
    ;; CertificationRequestInfo ::= SEQUENCE {
    ;;   version INTEGER (0),
    ;;   subject Name,
    ;;   subjectPKInfo SubjectPublicKeyInfo,
    ;;   attributes [0] IMPLICIT Attributes
    ;; }
    (encode-sequence
     (encode-integer 0)                               ; version
     (encode-subject primary-domain)                  ; subject (CN)
     (encode-rsa-public-key private-key public-key)   ; public key
     (encode-extension-request all-domains))))        ; attributes (SAN)

(defun sign-csr (private-key csr-info)
  "Sign CSR info with RSA-SHA256."
  (let* ((digest (ironclad:digest-sequence :sha256 csr-info))
         (signature (ironclad:sign-message private-key digest)))
    signature))

(defun generate-csr (private-key public-key domains)
  "Generate Certificate Signing Request in DER format.
   PRIVATE-KEY and PUBLIC-KEY are the RSA key pair.
   DOMAINS is a string or list of strings for the certificate.
   Returns the CSR as a byte vector."
  (let* ((csr-info (build-csr-info private-key public-key domains))
         (signature (sign-csr private-key csr-info))
         ;; CertificationRequest ::= SEQUENCE {
         ;;   certificationRequestInfo,
         ;;   signatureAlgorithm AlgorithmIdentifier,
         ;;   signature BIT STRING
         ;; }
         (algorithm-id (encode-sequence
                        (encode-oid *oid-sha256-with-rsa*)
                        (encode-null)))
         (csr (encode-sequence
               csr-info
               algorithm-id
               (encode-bit-string signature))))
    csr))

;;; ----------------------------------------------------------------------------
;;; Key and certificate saving
;;; ----------------------------------------------------------------------------

(defun save-private-key-pem (private-key path)
  "Save RSA private key to PEM file."
  (ensure-directories-exist path)
  (let* ((der (encode-rsa-private-key-der private-key))
         (pem (wrap-pem "RSA PRIVATE KEY" der)))
    (with-open-file (out path :direction :output
                              :if-exists :supersede
                              :element-type 'character)
      (write-string pem out))
    ;; Set restrictive permissions (owner read/write only)
    #+sbcl (sb-posix:chmod (namestring path) #o600)))

(defun save-certificate-pem (cert-pem path)
  "Save certificate PEM chain to file."
  (ensure-directories-exist path)
  (with-open-file (out path :direction :output
                            :if-exists :supersede
                            :element-type 'character)
    (write-string cert-pem out)))

;;; ----------------------------------------------------------------------------
;;; High-level certificate acquisition
;;; ----------------------------------------------------------------------------

(defun obtain-certificate (domain email &key (port 443))
  "Complete workflow to obtain a certificate for domain using TLS-ALPN-01.
   Returns T on success, signals an error on failure.
   Saves certificate to (cert-path domain) and key to (key-path domain).

   PORT is the port for the TLS-ALPN-01 validation server (default 443)."
  ;; 1. Initialize
  (acme-init)

  ;; 2. Register/login account
  (unless (acme-register-account email)
    (error 'acme-error :message "Account registration failed"))

  ;; 3. Create order
  (multiple-value-bind (order order-url)
      (acme-new-order domain)
    (unless order
      (error 'acme-order-error :message "Order creation failed"))

    ;; 4. Process authorizations
    (let ((auth-urls (cdr (assoc :authorizations order))))
      (dolist (auth-url auth-urls)
        (let* ((auth (acme-get-authorization auth-url))
               (challenge (get-tls-alpn-challenge auth)))
          (unless challenge
            (error 'acme-challenge-error
                   :message "TLS-ALPN-01 challenge not available"))

          (let* ((token (cdr (assoc :token challenge)))
                 (challenge-url (cdr (assoc :url challenge)))
                 (key-auth (compute-key-authorization token)))

            ;; 5. Start TLS-ALPN-01 validation server
            (start-tls-alpn-server domain key-auth port)

            ;; Give the server a moment to start
            (sleep 1)

            ;; 6. Tell ACME to verify
            (acme-respond-challenge challenge-url)

            ;; 7. Wait for validation
            (unwind-protect
                (multiple-value-bind (result status)
                    (acme-poll-status auth-url)
                  (declare (ignore result))
                  (unless (eq status :valid)
                    (error 'acme-challenge-error
                           :message (format nil "Challenge validation failed: ~A" status))))
              ;; Clean up validation server
              (stop-tls-alpn-server))))))

    ;; 8. Generate domain key and CSR, then finalize
    (multiple-value-bind (private-key public-key)
        (generate-domain-key)
      (let* ((csr (generate-csr private-key public-key domain))
             (finalize-url (cdr (assoc :finalize order))))

        ;; Save the private key immediately (before finalization, in case of failure)
        (save-private-key-pem private-key (key-path domain))

        ;; Finalize the order with CSR
        (acme-finalize-order finalize-url csr)

        ;; Poll until order is ready
        (multiple-value-bind (final-order status)
            (acme-poll-status order-url)
          (unless (eq status :valid)
            (error 'acme-order-error
                   :message (format nil "Order finalization failed: ~A" status)))

          ;; 9. Download and save certificate
          (let ((cert-url (cdr (assoc :certificate final-order))))
            (unless cert-url
              (error 'acme-certificate-error :message "No certificate URL in finalized order"))

            (let ((cert-pem (acme-download-certificate cert-url)))
              (unless cert-pem
                (error 'acme-certificate-error :message "Failed to download certificate"))

              ;; Save the certificate
              (save-certificate-pem cert-pem (cert-path domain))

              ;; Return success
              t)))))))

;;; ----------------------------------------------------------------------------
;;; Certificate expiration checking
;;; ----------------------------------------------------------------------------

(defun certificate-expires-soon-p (cert-path &optional (days 30))
  "Check if certificate expires within DAYS days.
   Returns T if certificate will expire soon or doesn't exist."
  (declare (ignore days))
  ;; TODO: Parse certificate and check notAfter
  ;; For now, always return NIL (certificate is fine)
  (unless (probe-file cert-path)
    (return-from certificate-expires-soon-p t))
  nil)
