;;; verify.lisp --- X.509 Certificate Verification
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Anthony Green <green@moxielogic.com>
;;;
;;; Implements X.509 certificate verification including hostname matching.

(in-package #:cl-tls)

;;;; Hostname Verification (RFC 6125)

(defun verify-hostname (cert hostname)
  "Verify that HOSTNAME matches the certificate.
   Returns T if verification succeeds, signals TLS-VERIFICATION-ERROR otherwise."
  ;; First check Subject Alternative Name extension
  (let ((san-names (certificate-dns-names cert)))
    (when san-names
      ;; If SAN is present, only use SAN (ignore CN)
      (if (some (lambda (san-name)
                  (hostname-matches-p san-name hostname))
                san-names)
          (return-from verify-hostname t)
          (error 'tls-verification-error
                 :hostname hostname
                 :message "Hostname does not match any SAN entry"))))
  ;; Fall back to Common Name if no SAN
  (let ((cns (certificate-subject-common-names cert)))
    (when cns
      (if (some (lambda (cn)
                  (hostname-matches-p cn hostname))
                cns)
          (return-from verify-hostname t)
          (error 'tls-verification-error
                 :hostname hostname
                 :message "Hostname does not match certificate CN"))))
  ;; No SAN or CN to check
  (error 'tls-verification-error
         :hostname hostname
         :message "Certificate has no DNS names to verify"))

(defun hostname-matches-p (pattern hostname)
  "Check if HOSTNAME matches PATTERN, supporting wildcards.
   Returns T if they match, NIL otherwise."
  (let ((pattern (string-downcase pattern))
        (hostname (string-downcase hostname)))
    (if (and (>= (length pattern) 2)
             (char= (char pattern 0) #\*)
             (char= (char pattern 1) #\.))
        ;; Wildcard pattern
        (wildcard-hostname-matches-p pattern hostname)
        ;; Exact match
        (string= pattern hostname))))

(defun wildcard-hostname-matches-p (pattern hostname)
  "Check if HOSTNAME matches wildcard PATTERN (e.g., *.example.com).
   Per RFC 6125, wildcard only matches a single label."
  ;; Pattern is *.suffix
  (let* ((suffix (subseq pattern 1))  ; .example.com
         (suffix-len (length suffix)))
    ;; Hostname must end with suffix
    (and (> (length hostname) suffix-len)
         (string= suffix (subseq hostname (- (length hostname) suffix-len)))
         ;; The part before suffix must be a single label (no dots)
         (not (find #\. hostname :end (- (length hostname) suffix-len))))))

;;;; Certificate Validity

(defun verify-certificate-dates (cert &optional (now (get-universal-time)))
  "Verify that the certificate is valid at time NOW.
   Signals TLS-CERTIFICATE-EXPIRED or TLS-CERTIFICATE-NOT-YET-VALID on failure."
  (let ((not-before (certificate-not-before cert))
        (not-after (certificate-not-after cert)))
    (when (and not-before (< now not-before))
      (error 'tls-certificate-not-yet-valid
             :not-before not-before
             :message "Certificate is not yet valid"))
    (when (and not-after (> now not-after))
      (error 'tls-certificate-expired
             :not-after not-after
             :message "Certificate has expired"))
    t))

;;;; Certificate Chain Verification
;;;
;;; Note: Full chain verification requires:
;;; 1. Building the chain from leaf to root
;;; 2. Verifying each signature
;;; 3. Checking basic constraints
;;; 4. Checking key usage
;;; 5. Checking against trusted roots
;;;
;;; For now, we provide basic building blocks.

(defun verify-certificate-chain (chain trusted-roots &optional (now (get-universal-time)))
  "Verify a certificate chain against trusted roots.
   CHAIN is a list of certificates, leaf first.
   TRUSTED-ROOTS is a list of trusted CA certificates.
   Returns T if verification succeeds, signals an error otherwise."
  (when (null chain)
    (error 'tls-certificate-error :message "Empty certificate chain"))
  ;; Verify each certificate's dates
  (dolist (cert chain)
    (verify-certificate-dates cert now))
  ;; Verify the chain links
  (loop for i from 0 below (1- (length chain))
        for cert = (nth i chain)
        for issuer = (nth (1+ i) chain)
        do (unless (certificate-issued-by-p cert issuer)
             (error 'tls-certificate-error
                    :message "Certificate chain is broken")))
  ;; Check if root is trusted
  (let ((root (car (last chain))))
    (unless (find-if (lambda (trusted)
                       (certificate-equal-p root trusted))
                     trusted-roots)
      ;; Maybe the chain's issuer is a trusted root
      (unless (find-if (lambda (trusted)
                         (certificate-issued-by-p root trusted))
                       trusted-roots)
        (error 'tls-verification-error
               :message "Certificate chain not anchored in trusted root"
               :reason :unknown-ca))))
  t)

(defun certificate-issued-by-p (cert issuer-cert)
  "Check if CERT was issued by ISSUER-CERT (by comparing names)."
  (equal (x509-name-rdns (x509-certificate-issuer cert))
         (x509-name-rdns (x509-certificate-subject issuer-cert))))

(defun certificate-equal-p (cert1 cert2)
  "Check if two certificates are the same (by comparing DER)."
  (equalp (x509-certificate-raw-der cert1)
          (x509-certificate-raw-der cert2)))

;;;; Signature Verification

(defun verify-certificate-signature (cert issuer-cert)
  "Verify that CERT's signature was made by ISSUER-CERT's key.
   Returns T on success, signals TLS-CERTIFICATE-ERROR on failure."
  (let* ((tbs (x509-certificate-tbs-raw cert))
         (signature (x509-certificate-signature cert))
         (algorithm (x509-certificate-signature-algorithm cert))
         (public-key-info (x509-certificate-subject-public-key-info issuer-cert))
         (key-algorithm (getf public-key-info :algorithm))
         (public-key (getf public-key-info :public-key)))
    (declare (ignore tbs signature algorithm key-algorithm public-key))
    ;; TODO: Implement actual signature verification
    ;; This requires:
    ;; 1. Parsing the public key based on algorithm
    ;; 2. Performing the appropriate signature verification
    ;; For now, return true (INSECURE - placeholder)
    (warn "Certificate signature verification not implemented")
    t))

;;;; Trust Store

(defstruct trust-store
  "A collection of trusted CA certificates."
  (certificates nil :type list))

(defun make-trust-store-from-directory (path)
  "Load all certificates from a directory into a trust store."
  (let ((certs nil))
    (dolist (file (directory (merge-pathnames "*.pem" path)))
      (handler-case
          (push (parse-certificate-from-file file) certs)
        (error (e)
          (warn "Failed to load certificate ~A: ~A" file e))))
    (dolist (file (directory (merge-pathnames "*.crt" path)))
      (handler-case
          (push (parse-certificate-from-file file) certs)
        (error (e)
          (warn "Failed to load certificate ~A: ~A" file e))))
    (make-trust-store :certificates (nreverse certs))))

(defun trust-store-find-issuer (store cert)
  "Find a certificate in STORE that could have issued CERT."
  (find-if (lambda (ca)
             (certificate-issued-by-p cert ca))
           (trust-store-certificates store)))

;;;; Full Verification Function

(defun verify-peer-certificate (cert hostname &key
                                               verify-mode
                                               trust-store
                                               (check-dates t))
  "Perform full verification of a peer certificate.

   CERT - The certificate to verify.
   HOSTNAME - The hostname to verify against.
   VERIFY-MODE - One of +VERIFY-NONE+, +VERIFY-PEER+, or +VERIFY-REQUIRED+.
   TRUST-STORE - Trust store for chain verification (optional).
   CHECK-DATES - Whether to check validity dates (default T).

   Returns T on success, signals appropriate error on failure."
  ;; Skip if verification disabled
  (when (= verify-mode +verify-none+)
    (return-from verify-peer-certificate t))
  ;; Check dates if requested
  (when check-dates
    (verify-certificate-dates cert))
  ;; Verify hostname
  (when hostname
    (verify-hostname cert hostname))
  ;; Chain verification (if trust store provided)
  (when trust-store
    (let ((issuer (trust-store-find-issuer trust-store cert)))
      (unless issuer
        (when (= verify-mode +verify-required+)
          (error 'tls-verification-error
                 :message "Cannot verify certificate chain"
                 :reason :unknown-ca)))))
  t)
