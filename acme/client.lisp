;;; client.lisp --- ACME protocol client
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Anthony Green <green@moxielogic.com>
;;;
;;; ACME protocol implementation for Let's Encrypt and compatible CAs.

(in-package #:pure-tls/acme)

;;; ----------------------------------------------------------------------------
;;; Configuration
;;; ----------------------------------------------------------------------------

(defparameter *staging-url*
  "https://acme-staging-v02.api.letsencrypt.org/directory"
  "Let's Encrypt staging directory for testing.")

(defparameter *production-url*
  "https://acme-v02.api.letsencrypt.org/directory"
  "Let's Encrypt production directory.")

(defparameter *directory-url* *production-url*
  "Current ACME directory URL. Defaults to staging for safety.")

(defparameter *skip-tls-verify* nil
  "Skip TLS certificate verification (for testing with Pebble).")

(defvar *cert-directory* nil
  "Directory for storing certificates. Defaults to ~/certs/ at runtime.")

(defun cert-directory ()
  "Get the certificate directory, defaulting to ~/certs/."
  (or *cert-directory*
      (merge-pathnames "certs/" (user-homedir-pathname))))

(defun use-production ()
  "Switch to Let's Encrypt production. Call before acme-init."
  (setf *directory-url* *production-url*))

(defun use-staging ()
  "Switch to Let's Encrypt staging."
  (setf *directory-url* *staging-url*))
  "Switch to Let's Encrypt staging (default)."
  (setf *directory-url* *production-url*))

(defun cert-path (domain)
  "Return the certificate file path for a domain."
  (merge-pathnames (format nil "~A.pem" domain) (cert-directory)))

(defun key-path (domain)
  "Return the private key file path for a domain."
  (merge-pathnames (format nil "~A-key.pem" domain) (cert-directory)))

(defun certificates-exist-p (domain)
  "Check if certificate and key files exist for a domain."
  (and (probe-file (cert-path domain))
       (probe-file (key-path domain))))

;;; ----------------------------------------------------------------------------
;;; Client state
;;; ----------------------------------------------------------------------------

(defvar *directory* nil
  "Cached ACME directory endpoints.")

(defvar *account-key* nil
  "Account private key (EC P-256).")

(defvar *account-url* nil
  "Account URL after registration.")

(defvar *nonce* nil
  "Current replay nonce.")

;;; ----------------------------------------------------------------------------
;;; Base64URL encoding (ACME requires this, not standard base64)
;;; ----------------------------------------------------------------------------

(defun base64url-encode (data)
  "Encode bytes to base64url (no padding)."
  (let* ((b64 (cl-base64:usb8-array-to-base64-string
               (if (stringp data)
                   (flexi-streams:string-to-octets data :external-format :utf-8)
                   data)))
         ;; Convert to URL-safe: + -> -, / -> _, remove =
         (url-safe (substitute #\- #\+ (substitute #\_ #\/ b64))))
    (string-right-trim "=" url-safe)))

(defun base64url-decode (string)
  "Decode base64url string to bytes."
  (let* ((padded (case (mod (length string) 4)
                   (2 (concatenate 'string string "=="))
                   (3 (concatenate 'string string "="))
                   (t string)))
         (standard (substitute #\+ #\- (substitute #\/ #\_ padded))))
    (cl-base64:base64-string-to-usb8-array standard)))

;;; ----------------------------------------------------------------------------
;;; Cryptographic operations
;;; ----------------------------------------------------------------------------

(defun generate-account-key ()
  "Generate a new EC P-256 private key for ACME account."
  (ironclad:generate-key-pair :secp256r1))

(defun get-public-key-jwk (private-key)
  "Convert EC private key's public component to JWK format for ACME.
   The private key contains the public point in uncompressed format:
   04 || X (32 bytes) || Y (32 bytes)"
  (let* ((key-data (ironclad:destructure-private-key private-key))
         (public-point (getf key-data :y))  ; Uncompressed public point
         ;; Skip the 04 prefix and extract X and Y coordinates
         (x (subseq public-point 1 33))   ; bytes 1-32
         (y (subseq public-point 33 65))) ; bytes 33-64
    ;; JWK for EC key
    `(("crv" . "P-256")
      ("kty" . "EC")
      ("x" . ,(base64url-encode x))
      ("y" . ,(base64url-encode y)))))

(defun get-jwk-thumbprint (jwk)
  "Calculate JWK thumbprint (SHA-256 of canonical JWK)."
  (let* ((canonical (cl-json:encode-json-to-string
                     ;; Must be sorted: crv, kty, x, y
                     `(("crv" . ,(cdr (assoc "crv" jwk :test #'string=)))
                       ("kty" . ,(cdr (assoc "kty" jwk :test #'string=)))
                       ("x" . ,(cdr (assoc "x" jwk :test #'string=)))
                       ("y" . ,(cdr (assoc "y" jwk :test #'string=))))))
         (hash (ironclad:digest-sequence :sha256
                (flexi-streams:string-to-octets canonical :external-format :utf-8))))
    (base64url-encode hash)))

(defun sign-payload (private-key payload)
  "Sign payload with ES256 (ECDSA P-256 + SHA-256).
   Note: ironclad's ECDSA sign-message expects a pre-hashed message,
   so we must hash with SHA-256 first."
  (let* ((message (flexi-streams:string-to-octets payload :external-format :utf-8))
         ;; ES256 requires SHA-256 hashing before signing
         (hash (ironclad:digest-sequence :sha256 message))
         (signature (ironclad:sign-message private-key hash)))
    ;; ECDSA signature is 64 bytes (r || s, 32 bytes each)
    (base64url-encode signature)))

(defun compute-key-authorization (token)
  "Compute key authorization: token.thumbprint"
  (let ((thumbprint (get-jwk-thumbprint
                     (get-public-key-jwk *account-key*))))
    (format nil "~A.~A" token thumbprint)))

;;; ----------------------------------------------------------------------------
;;; ACME HTTP client
;;; ----------------------------------------------------------------------------

(defun acme-get (url)
  "GET request to ACME endpoint."
  (let ((cl+ssl:*make-ssl-client-stream-verify-default*
          (if *skip-tls-verify* nil cl+ssl:*make-ssl-client-stream-verify-default*)))
    (multiple-value-bind (body status headers)
        (drakma:http-request url :method :get)
      (let ((nonce (cdr (assoc :replay-nonce headers)))
            (body-str (if (stringp body)
                          body
                          (flexi-streams:octets-to-string body :external-format :utf-8))))
        (when nonce (setf *nonce* nonce))
        (values (when (> (length body-str) 0)
                  (cl-json:decode-json-from-string body-str))
                status)))))

(defun acme-post (url payload &key kid)
  "POST request with JWS body to ACME endpoint.
   KID is the account URL (used after registration)."
  ;; Get fresh nonce if needed
  (unless *nonce*
    (acme-get (cdr (assoc :new-nonce *directory*))))

  (let* ((protected-header
           (if kid
               ;; After registration, use kid (account URL)
               `(("alg" . "ES256")
                 ("kid" . ,kid)
                 ("nonce" . ,*nonce*)
                 ("url" . ,url))
               ;; First request, use jwk
               `(("alg" . "ES256")
                 ("jwk" . ,(get-public-key-jwk *account-key*))
                 ("nonce" . ,*nonce*)
                 ("url" . ,url))))
         (protected64 (base64url-encode
                       (cl-json:encode-json-to-string protected-header)))
         (payload64 (if payload
                        (base64url-encode
                         (cl-json:encode-json-to-string payload))
                        ""))  ; Empty string for POST-as-GET
         (signature (sign-payload *account-key*
                                  (format nil "~A.~A" protected64 payload64)))
         (jws `(("protected" . ,protected64)
                ("payload" . ,payload64)
                ("signature" . ,signature))))

    (setf *nonce* nil)  ; Nonce is single-use

    (let ((cl+ssl:*make-ssl-client-stream-verify-default*
            (if *skip-tls-verify* nil cl+ssl:*make-ssl-client-stream-verify-default*)))
      (multiple-value-bind (body status headers)
          (drakma:http-request url
                               :method :post
                               :content-type "application/jose+json"
                               :content (cl-json:encode-json-to-string jws))
        (let* ((nonce (cdr (assoc :replay-nonce headers)))
               (location (cdr (assoc :location headers)))
               (body-str (if (stringp body)
                             body
                             (flexi-streams:octets-to-string body :external-format :utf-8))))
          (when nonce (setf *nonce* nonce))
          (let ((parsed-body (when (> (length body-str) 0)
                               (cl-json:decode-json-from-string body-str))))
            (values parsed-body status location)))))))

;;; ----------------------------------------------------------------------------
;;; ACME workflow
;;; ----------------------------------------------------------------------------

(defun acme-init ()
  "Initialize ACME client - fetch directory."
  (setf *directory* (acme-get *directory-url*)))

(defun acme-register-account (email)
  "Register new account or fetch existing one.
   Returns the account URL on success.
   Signals ACME-ERROR with details on failure."
  (unless *account-key*
    (setf *account-key* (generate-account-key)))

  (multiple-value-bind (response status location)
      (acme-post (cdr (assoc :new-account *directory*))
                 ;; Use vector for contact array (cl-json quirk)
                 `(("termsOfServiceAgreed" . t)
                   ("contact" . #(,(format nil "mailto:~A" email)))))
    (cond
      ((member status '(200 201))
       (setf *account-url* location)
       location)
      (t
       (let ((error-type (cdr (assoc :type response)))
             (error-detail (cdr (assoc :detail response))))
         (error 'acme-error
                :message (format nil "Account registration HTTP ~A: ~A - ~A"
                                 status
                                 (or error-type "unknown")
                                 (or error-detail "no details"))))))))

(defun acme-new-order (domains)
  "Create new certificate order for domains.
   Returns (VALUES order-response order-url) on success.
   Signals ACME-ORDER-ERROR with details on failure."
  (let* ((domain-list (if (listp domains) domains (list domains)))
         ;; Use vector for JSON array encoding (cl-json quirk)
         (identifiers (coerce (mapcar (lambda (d)
                                         `(("type" . "dns")
                                           ("value" . ,d)))
                                       domain-list)
                              'vector)))
    (multiple-value-bind (response status location)
        (acme-post (cdr (assoc :new-order *directory*))
                   `(("identifiers" . ,identifiers))
                   :kid *account-url*)
      (if (member status '(200 201))
          (values response location)
          ;; Extract error details from response
          (let ((error-type (cdr (assoc :type response)))
                (error-detail (cdr (assoc :detail response))))
            (error 'acme-order-error
                   :message (format nil "HTTP ~A: ~A - ~A"
                                    status
                                    (or error-type "unknown")
                                    (or error-detail "no details"))))))))

(defun acme-get-authorization (auth-url)
  "Get authorization details including challenges."
  (acme-post auth-url nil :kid *account-url*))

(defun acme-respond-challenge (challenge-url)
  "Tell ACME server to validate the challenge.
   Payload must be empty JSON object {}."
  (format t "~&[ACME-DEBUG] Responding to challenge at ~A~%" challenge-url)
  (force-output)
  (multiple-value-bind (response status)
      ;; ACME requires empty JSON object {}, use hash-table for cl-json
      (acme-post challenge-url (make-hash-table) :kid *account-url*)
    (format t "~&[ACME-DEBUG] Challenge response status: ~A~%" status)
    (format t "~&[ACME-DEBUG] Challenge response: ~A~%" response)
    (force-output)
    (values response status)))

(defun acme-poll-status (url &key (max-attempts 30) (delay 2) (wait-for-valid nil))
  "Poll order/authorization status until ready or failed.
   Returns (VALUES response status-keyword) where status-keyword is
   :valid, :ready, :invalid, or :timeout.
   If WAIT-FOR-VALID is true, keeps polling through 'ready' and 'processing' states."
  (format t "~&[ACME-DEBUG] Polling status at ~A~%" url)
  (force-output)
  (loop for attempt from 1 to max-attempts
        do (multiple-value-bind (response status)
               (acme-post url nil :kid *account-url*)
             (declare (ignore status))
             (let ((state (cdr (assoc :status response))))
               (format t "~&[ACME-DEBUG] Poll ~A/~A: status=~A~%" attempt max-attempts state)
               (force-output)
               (cond
                 ((string= state "valid")
                  (return (values response :valid)))
                 ((string= state "ready")
                  (if wait-for-valid
                      (sleep delay)  ; Keep waiting for valid
                      (return (values response :ready))))
                 ((string= state "processing")
                  (sleep delay))  ; Always wait through processing
                 ((string= state "invalid")
                  (format t "~&[ACME-DEBUG] INVALID - full response: ~A~%" response)
                  (force-output)
                  (return (values response :invalid)))
                 ((string= state "pending")
                  (sleep delay))
                 (t
                  (sleep delay)))))
        finally (return (values nil :timeout))))

(defun acme-finalize-order (finalize-url csr-der)
  "Submit CSR to finalize the order."
  (format t "~&[ACME-DEBUG] Finalizing order at ~A~%" finalize-url)
  (force-output)
  (multiple-value-bind (response status)
      (acme-post finalize-url
                 `(("csr" . ,(base64url-encode csr-der)))
                 :kid *account-url*)
    (format t "~&[ACME-DEBUG] Finalize response status: ~A~%" status)
    (format t "~&[ACME-DEBUG] Finalize response: ~A~%" response)
    (force-output)
    (values response status)))

(defun acme-download-certificate (cert-url)
  "Download the issued certificate chain (returns PEM string)."
  ;; Get fresh nonce first
  (unless *nonce*
    (acme-get (cdr (assoc :new-nonce *directory*))))

  (let* ((protected-header
           `(("alg" . "ES256")
             ("kid" . ,*account-url*)
             ("nonce" . ,*nonce*)
             ("url" . ,cert-url)))
         (protected64 (base64url-encode
                       (cl-json:encode-json-to-string protected-header)))
         (payload64 "")  ; POST-as-GET
         (signature (sign-payload *account-key*
                                  (format nil "~A.~A" protected64 payload64)))
         (jws `(("protected" . ,protected64)
                ("payload" . ,payload64)
                ("signature" . ,signature))))

    (setf *nonce* nil)

    ;; Request with Accept header for PEM format
    (let ((cl+ssl:*make-ssl-client-stream-verify-default*
            (if *skip-tls-verify* nil cl+ssl:*make-ssl-client-stream-verify-default*)))
      (multiple-value-bind (body status headers)
          (drakma:http-request cert-url
                               :method :post
                               :content-type "application/jose+json"
                               :accept "application/pem-certificate-chain"
                               :content (cl-json:encode-json-to-string jws))
        (let ((nonce (cdr (assoc :replay-nonce headers)))
              (body-str (if (stringp body)
                            body
                            (flexi-streams:octets-to-string body :external-format :utf-8))))
          (when nonce (setf *nonce* nonce))
          (if (= status 200)
              body-str  ; PEM certificate chain as string
              nil))))))

;;; ----------------------------------------------------------------------------
;;; Challenge extraction helpers
;;; ----------------------------------------------------------------------------

(defun get-tls-alpn-challenge (authorization)
  "Extract TLS-ALPN-01 challenge from authorization response."
  (let* ((challenges (cdr (assoc :challenges authorization)))
         (challenge (find "tls-alpn-01" challenges
                          :key (lambda (c) (cdr (assoc :type c)))
                          :test #'string=)))
    challenge))
