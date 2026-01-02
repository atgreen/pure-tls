;;; aead.lisp --- AEAD cipher implementations for TLS 1.3
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Anthony Green <green@moxielogic.com>
;;;
;;; Implements AEAD ciphers used in TLS 1.3:
;;; - AES-128-GCM
;;; - ChaCha20-Poly1305

(in-package #:pure-tls)

;;;; AEAD Cipher Interface

(defstruct aead-cipher
  "Abstract AEAD cipher state."
  (key nil :type (or null octet-vector))
  (implicit-nonce nil :type (or null octet-vector))
  (sequence-number 0 :type (unsigned-byte 64))
  (cipher-suite 0 :type fixnum))

(defun make-aead (cipher-suite key iv)
  "Create an AEAD cipher for the given cipher suite."
  (make-aead-cipher :key (copy-seq key)
                    :implicit-nonce (copy-seq iv)
                    :sequence-number 0
                    :cipher-suite cipher-suite))

(defun aead-compute-nonce (cipher)
  "Compute the per-record nonce by XORing sequence number with implicit nonce.

   In TLS 1.3, the nonce is computed as:
   nonce = implicit_iv XOR padded_sequence_number"
  (let* ((iv (aead-cipher-implicit-nonce cipher))
         (seq (aead-cipher-sequence-number cipher))
         (nonce (copy-seq iv)))
    ;; XOR the sequence number (as 8 bytes, big-endian) with the last 8 bytes of IV
    (loop for i from 0 below 8
          for shift from 56 downto 0 by 8
          for idx from (- (length nonce) 8)
          do (setf (aref nonce idx)
                   (logxor (aref nonce idx)
                           (ldb (byte 8 shift) seq))))
    nonce))

(defun aead-increment-sequence (cipher)
  "Increment the sequence number. Must be called after each encrypt/decrypt."
  (incf (aead-cipher-sequence-number cipher))
  (when (>= (aead-cipher-sequence-number cipher) (ash 1 64))
    (error 'tls-crypto-error
           :operation "AEAD"
           :message "Sequence number overflow")))

;;;; AES-GCM Implementation

(defun aes-gcm-encrypt (key nonce plaintext aad)
  "Encrypt using AES-GCM.

   KEY       - 16 or 32 byte encryption key.
   NONCE     - 12 byte nonce.
   PLAINTEXT - Data to encrypt.
   AAD       - Additional authenticated data.

   Returns ciphertext with 16-byte authentication tag appended."
  (let* ((cipher-name (if (= (length key) 16) :aes :aes))
         (mode (ironclad:make-authenticated-encryption-mode
                :gcm :cipher-name cipher-name :key key
                :initialization-vector nonce))
         (ciphertext (make-octet-vector (length plaintext)))
         (tag (make-octet-vector 16)))
    ;; Process AAD
    (ironclad:process-associated-data mode aad)
    ;; Encrypt
    (ironclad:encrypt mode plaintext ciphertext)
    ;; Get tag
    (ironclad:produce-tag mode :tag tag)
    ;; Return ciphertext || tag
    (concat-octet-vectors ciphertext tag)))

(defun aes-gcm-decrypt (key nonce ciphertext-with-tag aad)
  "Decrypt using AES-GCM.

   KEY               - 16 or 32 byte encryption key.
   NONCE             - 12 byte nonce.
   CIPHERTEXT-WITH-TAG - Ciphertext with 16-byte tag appended.
   AAD               - Additional authenticated data.

   Returns plaintext, or signals TLS-MAC-ERROR if authentication fails."
  (when (< (length ciphertext-with-tag) 16)
    (error 'tls-mac-error))
  (let* ((ct-len (- (length ciphertext-with-tag) 16))
         (ciphertext (subseq ciphertext-with-tag 0 ct-len))
         (tag (subseq ciphertext-with-tag ct-len))
         (cipher-name (if (= (length key) 16) :aes :aes))
         (mode (ironclad:make-authenticated-encryption-mode
                :gcm :cipher-name cipher-name :key key
                :initialization-vector nonce))
         (plaintext (make-octet-vector ct-len))
         (computed-tag (make-octet-vector 16)))
    ;; Process AAD
    (ironclad:process-associated-data mode aad)
    ;; Decrypt
    (ironclad:decrypt mode ciphertext plaintext)
    ;; Get computed tag
    (ironclad:produce-tag mode :tag computed-tag)
    ;; Verify tag (constant-time comparison)
    (unless (constant-time-equal tag computed-tag)
      (error 'tls-mac-error))
    plaintext))

;;;; ChaCha20-Poly1305 Implementation

(defun chacha20-poly1305-encrypt (key nonce plaintext aad)
  "Encrypt using ChaCha20-Poly1305.

   KEY       - 32 byte encryption key.
   NONCE     - 12 byte nonce.
   PLAINTEXT - Data to encrypt.
   AAD       - Additional authenticated data.

   Returns ciphertext with 16-byte authentication tag appended."
  (let* ((mode (ironclad:make-authenticated-encryption-mode
                :chacha/poly1305 :key key
                :initialization-vector nonce))
         (ciphertext (make-octet-vector (length plaintext)))
         (tag (make-octet-vector 16)))
    ;; Process AAD
    (ironclad:process-associated-data mode aad)
    ;; Encrypt
    (ironclad:encrypt mode plaintext ciphertext)
    ;; Get tag
    (ironclad:produce-tag mode :tag tag)
    ;; Return ciphertext || tag
    (concat-octet-vectors ciphertext tag)))

(defun chacha20-poly1305-decrypt (key nonce ciphertext-with-tag aad)
  "Decrypt using ChaCha20-Poly1305.

   KEY               - 32 byte encryption key.
   NONCE             - 12 byte nonce.
   CIPHERTEXT-WITH-TAG - Ciphertext with 16-byte tag appended.
   AAD               - Additional authenticated data.

   Returns plaintext, or signals TLS-MAC-ERROR if authentication fails."
  (when (< (length ciphertext-with-tag) 16)
    (error 'tls-mac-error))
  (let* ((ct-len (- (length ciphertext-with-tag) 16))
         (ciphertext (subseq ciphertext-with-tag 0 ct-len))
         (tag (subseq ciphertext-with-tag ct-len))
         (mode (ironclad:make-authenticated-encryption-mode
                :chacha/poly1305 :key key
                :initialization-vector nonce))
         (plaintext (make-octet-vector ct-len))
         (computed-tag (make-octet-vector 16)))
    ;; Process AAD
    (ironclad:process-associated-data mode aad)
    ;; Decrypt
    (ironclad:decrypt mode ciphertext plaintext)
    ;; Get computed tag
    (ironclad:produce-tag mode :tag computed-tag)
    ;; Verify tag (constant-time comparison)
    (unless (constant-time-equal tag computed-tag)
      (error 'tls-mac-error))
    plaintext))

;;;; Unified AEAD Operations

(defun aead-encrypt (cipher plaintext aad)
  "Encrypt plaintext using the AEAD cipher.
   Returns ciphertext with authentication tag."
  (let* ((key (aead-cipher-key cipher))
         (nonce (aead-compute-nonce cipher))
         (suite (aead-cipher-cipher-suite cipher))
         (result (case suite
                   (#.+tls-aes-128-gcm-sha256+
                    (aes-gcm-encrypt key nonce plaintext aad))
                   (#.+tls-aes-256-gcm-sha384+
                    (aes-gcm-encrypt key nonce plaintext aad))
                   (#.+tls-chacha20-poly1305-sha256+
                    (chacha20-poly1305-encrypt key nonce plaintext aad))
                   (t (error 'tls-crypto-error
                             :operation "AEAD encrypt"
                             :message (format nil "Unsupported cipher suite: ~X" suite))))))
    (aead-increment-sequence cipher)
    result))

(defun aead-decrypt (cipher ciphertext aad)
  "Decrypt ciphertext using the AEAD cipher.
   Returns plaintext or signals TLS-MAC-ERROR on authentication failure."
  (let* ((key (aead-cipher-key cipher))
         (nonce (aead-compute-nonce cipher))
         (suite (aead-cipher-cipher-suite cipher))
         (result (case suite
                   (#.+tls-aes-128-gcm-sha256+
                    (aes-gcm-decrypt key nonce ciphertext aad))
                   (#.+tls-aes-256-gcm-sha384+
                    (aes-gcm-decrypt key nonce ciphertext aad))
                   (#.+tls-chacha20-poly1305-sha256+
                    (chacha20-poly1305-decrypt key nonce ciphertext aad))
                   (t (error 'tls-crypto-error
                             :operation "AEAD decrypt"
                             :message (format nil "Unsupported cipher suite: ~X" suite))))))
    (aead-increment-sequence cipher)
    result))

;;;; TLS 1.3 Record Encryption/Decryption

(defun tls13-encrypt-record (cipher content-type plaintext)
  "Encrypt a TLS 1.3 record.

   The plaintext is padded with the inner content type and optional zeros,
   then encrypted with AAD being the record header.

   Returns the encrypted record payload (ciphertext + tag)."
  ;; Build inner plaintext: content || content_type || zeros
  (let* ((inner (concat-octet-vectors
                 plaintext
                 (octet-vector content-type)))
         ;; AAD is the record header for the outer record
         ;; TLSCiphertext header: content_type(1) || legacy_version(2) || length(2)
         (encrypted-len (+ (length inner) +aead-tag-length+))
         (aad (octet-vector +content-type-application-data+  ; outer type
                            #x03 #x03                         ; legacy TLS 1.2 version
                            (ldb (byte 8 8) encrypted-len)
                            (ldb (byte 8 0) encrypted-len))))
    (aead-encrypt cipher inner aad)))

(defun tls13-decrypt-record (cipher ciphertext record-header)
  "Decrypt a TLS 1.3 record.

   CIPHERTEXT is the encrypted payload (including tag).
   RECORD-HEADER is the 5-byte TLS record header (used as AAD).

   Returns (VALUES plaintext content-type) where content-type is the
   inner content type extracted from the decrypted data."
  (let* ((inner (aead-decrypt cipher ciphertext record-header))
         ;; Find the content type (last non-zero byte)
         (content-type-pos (position-if-not #'zerop inner :from-end t)))
    (unless content-type-pos
      (error 'tls-decode-error :message "No content type in decrypted record"))
    (values (subseq inner 0 content-type-pos)
            (aref inner content-type-pos))))
