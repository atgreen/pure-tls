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
  "Generate RSA key pair for the certificate with standard e=65537.
   Returns (values private-key public-key)."
  (generate-rsa-key-with-e65537 2048))

(defun generate-rsa-key-with-e65537 (num-bits)
  "Generate RSA key pair with the standard public exponent e=65537.
   This is required for X.509 compatibility (ironclad uses random e by default)."
  (let* ((e 65537)
         (l (floor num-bits 2)))
    ;; Generate primes p and q such that gcd(e, (p-1)(q-1)) = 1
    (multiple-value-bind (p q n)
        (loop for a = (ironclad:generate-prime (- num-bits l))
              for b = (ironclad:generate-prime l)
              for c = (* a b)
              ;; Check that e is coprime to phi(n) = (p-1)(q-1)
              until (and (/= a b)
                         (= num-bits (integer-length c))
                         (= 1 (gcd e (* (1- a) (1- b)))))
              finally (return (values a b c)))
      (let* ((phi (* (1- p) (1- q)))
             (d (ironclad::modular-inverse e phi)))
        (format t "~&[ACME-DEBUG] Generated RSA key with e=65537, n=~A bits~%" (integer-length n))
        (force-output)
        (values (ironclad:make-private-key :rsa :d d :n n :p p :q q)
                (ironclad:make-public-key :rsa :e e :n n))))))

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

(defparameter *sha256-digest-info-prefix*
  ;; DER-encoded DigestInfo prefix for SHA-256
  ;; SEQUENCE { SEQUENCE { OID 2.16.840.1.101.3.4.2.1, NULL }, OCTET STRING (32 bytes) }
  #(#x30 #x31 #x30 #x0d #x06 #x09 #x60 #x86 #x48 #x01 #x65 #x03 #x04 #x02 #x01
    #x05 #x00 #x04 #x20)
  "DER-encoded DigestInfo prefix for SHA-256 (without the hash).")

(defun pkcs1-v15-pad-sha256 (message key-size-bytes)
  "Create PKCS#1 v1.5 padded message for SHA-256 signature.
   Returns the padded EM (encoded message) ready for RSA operation."
  ;; 1. Hash the message with SHA-256
  (let* ((hash (ironclad:digest-sequence :sha256 message))
         ;; 2. Create DigestInfo = prefix || hash
         (digest-info (concatenate '(vector (unsigned-byte 8))
                                   *sha256-digest-info-prefix*
                                   hash))
         ;; 3. Calculate padding length
         (ps-len (- key-size-bytes (length digest-info) 3))
         ;; 4. Create padded message: 0x00 || 0x01 || PS || 0x00 || DigestInfo
         (padded (make-array key-size-bytes :element-type '(unsigned-byte 8))))
    (when (< ps-len 8)
      (error "RSA key too small for SHA-256 signature"))
    ;; Build: 0x00 || 0x01 || PS (0xFF bytes) || 0x00 || DigestInfo
    (setf (aref padded 0) #x00)
    (setf (aref padded 1) #x01)
    (fill padded #xff :start 2 :end (+ 2 ps-len))
    (setf (aref padded (+ 2 ps-len)) #x00)
    (replace padded digest-info :start1 (+ 3 ps-len))
    padded))

(defun sign-csr (private-key public-key csr-info)
  "Sign CSR info with RSA-SHA256 (PKCS#1 v1.5).
   Manually constructs PKCS#1 v1.5 padding, then does raw RSA."
  (let* ((priv-data (ironclad:destructure-private-key private-key))
         (pub-data (ironclad:destructure-public-key public-key))
         (n (getf priv-data :n))
         (d (getf priv-data :d))
         (e (getf pub-data :e))  ; Get actual e from public key
         (key-size-bytes (ceiling (integer-length n) 8))
         ;; Create PKCS#1 v1.5 padded message
         (padded (pkcs1-v15-pad-sha256 csr-info key-size-bytes))
         ;; Convert to integer for RSA operation
         (m (ironclad:octets-to-integer padded))
         ;; RSA signature: s = m^d mod n
         (s (ironclad:expt-mod m d n))
         ;; Convert back to bytes, preserving leading zeros
         (signature (ironclad:integer-to-octets s :n-bits (* key-size-bytes 8))))
    (format t "~&[ACME-DEBUG] PKCS1-v15-SHA256: key=~A bytes, e=~A bits, sig=~A bytes~%"
            key-size-bytes (integer-length e) (length signature))
    ;; Self-verify: decrypt signature and compare with padded message
    (let* ((decrypted (ironclad:expt-mod s e n))
           (matches (= m decrypted)))
      (format t "~&[ACME-DEBUG] Self-verify: m == s^e mod n ? ~A~%" matches)
      (unless matches
        (format t "~&[ACME-DEBUG] ERROR: Signature self-verification failed!~%")))
    (force-output)
    signature))

(defun generate-csr (private-key public-key domains)
  "Generate Certificate Signing Request in DER format.
   PRIVATE-KEY and PUBLIC-KEY are the RSA key pair.
   DOMAINS is a string or list of strings for the certificate.
   Returns the CSR as a byte vector."
  (let* ((csr-info (build-csr-info private-key public-key domains))
         (signature (sign-csr private-key public-key csr-info))
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
    ;; Debug: save CSR for inspection
    (let ((debug-path (merge-pathnames "debug-csr.der" (cert-directory))))
      (ensure-directories-exist debug-path)
      (with-open-file (out debug-path :direction :output
                                       :if-exists :supersede
                                       :element-type '(unsigned-byte 8))
        (write-sequence csr out))
      (format t "~&[ACME-DEBUG] CSR saved to ~A~%" debug-path)
      (format t "~&[ACME-DEBUG] Verify with: openssl req -in ~A -inform DER -noout -text~%" debug-path)
      (force-output))
    csr))

;;; ----------------------------------------------------------------------------
;;; Key and certificate saving
;;; ----------------------------------------------------------------------------

(defun save-private-key-pem (private-key public-key path)
  "Save RSA private key to PEM file.
   PUBLIC-KEY is needed because ironclad's private key doesn't expose :e."
  (ensure-directories-exist path)
  (let* ((der (encode-rsa-private-key-der private-key public-key))
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
        (save-private-key-pem private-key public-key (key-path domain))

        ;; Finalize the order with CSR
        (acme-finalize-order finalize-url csr)

        ;; Poll until order is valid (wait through ready/processing states)
        (multiple-value-bind (final-order status)
            (acme-poll-status order-url :wait-for-valid t)
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
