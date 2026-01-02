;;; client.lisp --- TLS 1.3 Client Handshake
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Anthony Green <green@moxielogic.com>
;;;
;;; Implements the TLS 1.3 client handshake state machine.

(in-package #:cl-tls)

;;;; Client Handshake State

(defstruct client-handshake
  "Client handshake state."
  ;; Configuration
  (hostname nil :type (or null string))
  (alpn-protocols nil :type list)
  (verify-mode +verify-required+ :type fixnum)
  ;; Cipher suites we support
  (cipher-suites (list +tls-aes-128-gcm-sha256+
                       +tls-chacha20-poly1305-sha256+)
                 :type list)
  ;; Key exchange state
  (key-exchange nil)
  ;; Selected cipher suite
  (selected-cipher-suite nil)
  ;; Key schedule
  (key-schedule nil)
  ;; Record layer
  (record-layer nil)
  ;; Handshake transcript (raw bytes for hashing)
  (transcript nil :type (or null octet-vector))
  ;; Buffer for handshake messages (multiple messages may arrive in one record)
  (message-buffer nil :type (or null octet-vector))
  ;; Server's certificate
  (peer-certificate nil)
  ;; Selected ALPN protocol
  (selected-alpn nil :type (or null string))
  ;; State
  (state :start))

(defun client-handshake-update-transcript (hs message-bytes)
  "Add message bytes to the handshake transcript."
  (setf (client-handshake-transcript hs)
        (if (client-handshake-transcript hs)
            (concat-octet-vectors (client-handshake-transcript hs) message-bytes)
            message-bytes))
  ;; Also update the key schedule's transcript hash
  (when (client-handshake-key-schedule hs)
    (key-schedule-update-transcript (client-handshake-key-schedule hs) message-bytes)))

;;;; ClientHello Generation

(defun generate-client-hello (hs)
  "Generate a ClientHello message."
  (let* ((random (random-bytes 32))
         (session-id (random-bytes 32))  ; Legacy, but some servers expect it
         ;; Generate key share for preferred group
         (key-exchange (generate-key-exchange *preferred-group*))
         ;; Build extensions
         (extensions (list
                      ;; supported_versions (required for TLS 1.3)
                      (make-tls-extension
                       :type +extension-supported-versions+
                       :data (make-supported-versions-ext :versions (list +tls-1.3+)))
                      ;; supported_groups
                      (make-tls-extension
                       :type +extension-supported-groups+
                       :data (make-supported-groups-ext :groups *supported-groups*))
                      ;; signature_algorithms
                      (make-tls-extension
                       :type +extension-signature-algorithms+
                       :data (make-signature-algorithms-ext
                              :algorithms (supported-signature-algorithms)))
                      ;; key_share
                      (make-tls-extension
                       :type +extension-key-share+
                       :data (make-key-share-ext
                              :client-shares
                              (list (make-key-share-entry
                                     :group (key-exchange-group key-exchange)
                                     :key-exchange (key-exchange-public-key key-exchange))))))))
    ;; Add SNI if hostname provided
    (when (client-handshake-hostname hs)
      (push (make-tls-extension
             :type +extension-server-name+
             :data (make-server-name-ext
                    :host-name (client-handshake-hostname hs)))
            extensions))
    ;; Add ALPN if protocols provided
    (when (client-handshake-alpn-protocols hs)
      (push (make-tls-extension
             :type +extension-application-layer-protocol-negotiation+
             :data (make-alpn-ext
                    :protocol-list (client-handshake-alpn-protocols hs)))
            extensions))
    ;; Store key exchange for later
    (setf (client-handshake-key-exchange hs) key-exchange)
    ;; Build ClientHello
    (make-client-hello
     :legacy-version +tls-1.2+
     :random random
     :legacy-session-id session-id
     :cipher-suites (client-handshake-cipher-suites hs)
     :legacy-compression-methods (octet-vector 0)
     :extensions (nreverse extensions))))

(defun send-client-hello (hs)
  "Send ClientHello message."
  (let* ((hello (generate-client-hello hs))
         (hello-bytes (serialize-client-hello hello))
         (message (wrap-handshake-message +handshake-client-hello+ hello-bytes)))
    ;; Update transcript
    (client-handshake-update-transcript hs message)
    ;; Send
    (record-layer-write-handshake (client-handshake-record-layer hs) message)
    (setf (client-handshake-state hs) :wait-server-hello)))

;;;; ServerHello Processing

(defun process-server-hello (hs message)
  "Process ServerHello message."
  (let* ((server-hello (handshake-message-body message))
         (extensions (server-hello-extensions server-hello)))
    ;; Check for HelloRetryRequest
    (when (hello-retry-request-p server-hello)
      (error 'tls-handshake-error
             :message "HelloRetryRequest not yet supported"
             :state :wait-server-hello))
    ;; Verify supported_versions extension
    (let ((sv-ext (find-extension extensions +extension-supported-versions+)))
      (unless sv-ext
        (error 'tls-handshake-error
               :message "Missing supported_versions extension"
               :state :wait-server-hello))
      (unless (= (supported-versions-ext-selected-version (tls-extension-data sv-ext))
                 +tls-1.3+)
        (error 'tls-handshake-error
               :message "Server did not select TLS 1.3"
               :state :wait-server-hello)))
    ;; Get selected cipher suite
    (let ((cipher-suite (server-hello-cipher-suite server-hello)))
      (unless (member cipher-suite (client-handshake-cipher-suites hs))
        (error 'tls-handshake-error
               :message "Server selected unsupported cipher suite"
               :state :wait-server-hello))
      (setf (client-handshake-selected-cipher-suite hs) cipher-suite))
    ;; Process key_share extension
    (let ((ks-ext (find-extension extensions +extension-key-share+)))
      (unless ks-ext
        (error 'tls-handshake-error
               :message "Missing key_share extension"
               :state :wait-server-hello))
      (let* ((ks-data (tls-extension-data ks-ext))
             (server-share (key-share-ext-server-share ks-data))
             (server-group (key-share-entry-group server-share))
             (server-public (key-share-entry-key-exchange server-share)))
        ;; Verify server used our offered group
        (unless (= server-group (key-exchange-group (client-handshake-key-exchange hs)))
          (error 'tls-handshake-error
                 :message "Server used different key exchange group"
                 :state :wait-server-hello))
        ;; Compute shared secret
        (let ((shared-secret (compute-shared-secret
                              (client-handshake-key-exchange hs)
                              server-public)))
          ;; Initialize key schedule
          (let ((ks (make-key-schedule-state (client-handshake-selected-cipher-suite hs))))
            (key-schedule-init ks nil)
            (key-schedule-derive-handshake-secret ks shared-secret)
            ;; Derive handshake traffic secrets from transcript so far
            (key-schedule-derive-handshake-traffic-secrets
             ks (client-handshake-transcript hs))
            (setf (client-handshake-key-schedule hs) ks)
            ;; Feed existing transcript (ClientHello + ServerHello) into the key schedule's
            ;; incremental transcript hash for later use in Finished verification
            (key-schedule-update-transcript ks (client-handshake-transcript hs))
            ;; Install server handshake keys for reading
            (multiple-value-bind (key iv)
                (key-schedule-derive-read-keys ks :handshake)
              (record-layer-install-keys
               (client-handshake-record-layer hs)
               :read key iv
               (client-handshake-selected-cipher-suite hs)))))))
    (setf (client-handshake-state hs) :wait-encrypted-extensions)))

;;;; Encrypted Extensions Processing

(defun process-encrypted-extensions (hs message)
  "Process EncryptedExtensions message."
  (let* ((ee (handshake-message-body message))
         (extensions (encrypted-extensions-extensions ee)))
    ;; Process ALPN if present
    (let ((alpn-ext (find-extension extensions +extension-application-layer-protocol-negotiation+)))
      (when alpn-ext
        (let* ((alpn-data (tls-extension-data alpn-ext))
               (protocols (alpn-ext-protocol-list alpn-data)))
          (when protocols
            (setf (client-handshake-selected-alpn hs) (first protocols))))))
    ;; TODO: Process other extensions
    (setf (client-handshake-state hs) :wait-cert-or-finished)))

;;;; Certificate Processing

(defun process-certificate (hs message)
  "Process Certificate message."
  (let* ((cert-msg (handshake-message-body message))
         (cert-list (certificate-message-certificate-list cert-msg)))
    (when (null cert-list)
      (when (= (client-handshake-verify-mode hs) +verify-required+)
        (error 'tls-certificate-error
               :message "Server did not provide a certificate")))
    ;; Store the first certificate (server's certificate)
    (when cert-list
      (let ((first-cert (first cert-list)))
        (setf (client-handshake-peer-certificate hs)
              (certificate-entry-cert-data first-cert))))
    (setf (client-handshake-state hs) :wait-certificate-verify)))

;;;; CertificateVerify Processing

(defun process-certificate-verify (hs message)
  "Process CertificateVerify message."
  (declare (ignore hs message))
  ;; TODO: Verify signature over transcript
  ;; For now, we trust the signature
  (setf (client-handshake-state hs) :wait-finished))

;;;; Finished Processing

(defun process-server-finished (hs message raw-bytes)
  "Process server Finished message.
   RAW-BYTES are the serialized message bytes for updating transcript after verification."
  (let* ((finished (handshake-message-body message))
         (received-verify-data (finished-message-verify-data finished))
         (ks (client-handshake-key-schedule hs))
         (cipher-suite (client-handshake-selected-cipher-suite hs))
         ;; Compute expected verify_data
         ;; Note: transcript at this point excludes this Finished message (that's critical!)
         (transcript-hash (key-schedule-transcript-hash-value ks))
         (expected-verify-data
           (compute-finished-verify-data
            (key-schedule-server-handshake-traffic-secret ks)
            transcript-hash
            cipher-suite)))
    ;; Verify
    (unless (constant-time-equal received-verify-data expected-verify-data)
      (error 'tls-handshake-error
             :message "Server Finished verification failed"
             :state :wait-finished))
    ;; NOW update transcript with server Finished (after verification)
    (client-handshake-update-transcript hs raw-bytes)
    ;; Derive master secret and application traffic secrets
    (key-schedule-derive-master-secret ks)
    ;; Need transcript including server Finished for app secrets
    (key-schedule-derive-application-traffic-secrets
     ks (client-handshake-transcript hs))
    ;; Install server application keys for reading
    (multiple-value-bind (key iv)
        (key-schedule-derive-read-keys ks :application)
      (record-layer-install-keys
       (client-handshake-record-layer hs)
       :read key iv cipher-suite))
    (setf (client-handshake-state hs) :send-finished)))

;;;; Client Finished

(defun send-client-finished (hs)
  "Send client Finished message."
  (let* ((ks (client-handshake-key-schedule hs))
         (cipher-suite (client-handshake-selected-cipher-suite hs))
         ;; Install client handshake keys for writing (before sending Finished)
         (_  (multiple-value-bind (key iv)
                 (key-schedule-derive-write-keys ks :handshake)
               (record-layer-install-keys
                (client-handshake-record-layer hs)
                :write key iv cipher-suite)))
         ;; Compute verify_data
         (transcript-hash (key-schedule-transcript-hash-value ks))
         (verify-data (compute-finished-verify-data
                       (key-schedule-client-handshake-traffic-secret ks)
                       transcript-hash
                       cipher-suite))
         (finished (make-finished-message :verify-data verify-data))
         (finished-bytes (serialize-finished finished))
         (message (wrap-handshake-message +handshake-finished+ finished-bytes)))
    (declare (ignore _))
    ;; Update transcript (for resumption master secret)
    (client-handshake-update-transcript hs message)
    ;; Send
    (record-layer-write-handshake (client-handshake-record-layer hs) message)
    ;; Derive resumption master secret
    (key-schedule-derive-resumption-master-secret ks (client-handshake-transcript hs))
    ;; Install client application keys for writing
    (multiple-value-bind (key iv)
        (key-schedule-derive-write-keys ks :application)
      (record-layer-install-keys
       (client-handshake-record-layer hs)
       :write key iv cipher-suite))
    (setf (client-handshake-state hs) :connected)))

;;;; Main Handshake Loop

(defun handshake-buffer-has-complete-message-p (buffer)
  "Check if the buffer contains at least one complete handshake message."
  (when (and buffer (>= (length buffer) 4))
    ;; Parse the length from the header
    (let ((msg-length (decode-uint24 buffer 1)))
      (>= (length buffer) (+ 4 msg-length)))))

(defun handshake-buffer-extract-message (buffer)
  "Extract one handshake message from the buffer.
   Returns (VALUES message-bytes remaining-buffer)."
  (let* ((msg-length (decode-uint24 buffer 1))
         (total-length (+ 4 msg-length))
         (message (subseq buffer 0 total-length))
         (remaining (if (> (length buffer) total-length)
                        (subseq buffer total-length)
                        nil)))
    (values message remaining)))

(defun read-handshake-message (hs &key (update-transcript t))
  "Read and parse a handshake message from the record layer.
   Handles multiple messages per TLS record by buffering.
   If UPDATE-TRANSCRIPT is nil, the transcript is not updated (caller must do it).
   Returns (VALUES message raw-bytes) where raw-bytes are the serialized message bytes."
  ;; Read more data if needed
  (loop while (not (handshake-buffer-has-complete-message-p
                    (client-handshake-message-buffer hs)))
        do (multiple-value-bind (content-type data)
               (record-layer-read (client-handshake-record-layer hs))
             ;; Handle alerts
             (when (= content-type +content-type-alert+)
               (process-alert data))
             ;; Skip change_cipher_spec (compatibility) - just continue loop
             (unless (= content-type +content-type-change-cipher-spec+)
               ;; Must be handshake
               (unless (= content-type +content-type-handshake+)
                 (error 'tls-handshake-error
                        :message (format nil "Expected handshake, got content type ~D" content-type)))
               ;; Append to buffer
               (setf (client-handshake-message-buffer hs)
                     (if (client-handshake-message-buffer hs)
                         (concat-octet-vectors (client-handshake-message-buffer hs) data)
                         data)))))
  ;; Extract one message from buffer
  (multiple-value-bind (message-bytes remaining)
      (handshake-buffer-extract-message (client-handshake-message-buffer hs))
    (setf (client-handshake-message-buffer hs) remaining)
    ;; Optionally update transcript with raw message bytes
    (when update-transcript
      (client-handshake-update-transcript hs message-bytes))
    ;; Parse the message and return both parsed message and raw bytes
    (values (parse-handshake-message message-bytes
                                     :hash-length (when (client-handshake-selected-cipher-suite hs)
                                                    (cipher-suite-hash-length
                                                     (client-handshake-selected-cipher-suite hs))))
            message-bytes)))

(defun perform-client-handshake (record-layer &key hostname alpn-protocols
                                                   (verify-mode +verify-required+))
  "Perform the TLS 1.3 client handshake.
   Returns a CLIENT-HANDSHAKE structure on success."
  (let ((hs (make-client-handshake
             :hostname hostname
             :alpn-protocols alpn-protocols
             :verify-mode verify-mode
             :record-layer record-layer)))
    ;; Send ClientHello
    (send-client-hello hs)
    ;; Process server messages
    (loop
      (case (client-handshake-state hs)
        (:wait-server-hello
         (let* ((raw-message (read-raw-handshake-message hs))
                (message (parse-handshake-message raw-message)))
           (unless (= (handshake-message-type message) +handshake-server-hello+)
             (error 'tls-handshake-error
                    :message "Expected ServerHello"
                    :state :wait-server-hello))
           ;; Update transcript with raw bytes
           (client-handshake-update-transcript hs raw-message)
           ;; Initialize key schedule now that we know we have TLS 1.3
           (process-server-hello hs message)))
        (:wait-encrypted-extensions
         (let ((message (read-handshake-message hs)))
           (unless (= (handshake-message-type message) +handshake-encrypted-extensions+)
             (error 'tls-handshake-error
                    :message "Expected EncryptedExtensions"
                    :state :wait-encrypted-extensions))
           (process-encrypted-extensions hs message)))
        (:wait-cert-or-finished
         ;; Don't update transcript automatically - we need to handle Finished specially
         (multiple-value-bind (message raw-bytes)
             (read-handshake-message hs :update-transcript nil)
           (case (handshake-message-type message)
             (#.+handshake-certificate+
              ;; Update transcript now for Certificate
              (client-handshake-update-transcript hs raw-bytes)
              (process-certificate hs message))
             (#.+handshake-finished+
              ;; No certificate, go directly to finished
              ;; Don't update transcript yet - process-server-finished will do it after verification
              (setf (client-handshake-state hs) :wait-finished)
              (process-server-finished hs message raw-bytes))
             (t (error 'tls-handshake-error
                       :message "Expected Certificate or Finished"
                       :state :wait-cert-or-finished)))))
        (:wait-certificate-verify
         (let ((message (read-handshake-message hs)))
           (unless (= (handshake-message-type message) +handshake-certificate-verify+)
             (error 'tls-handshake-error
                    :message "Expected CertificateVerify"
                    :state :wait-certificate-verify))
           (process-certificate-verify hs message)))
        (:wait-finished
         ;; Don't update transcript yet - we need to verify first, THEN update
         (multiple-value-bind (message raw-bytes)
             (read-handshake-message hs :update-transcript nil)
           (unless (= (handshake-message-type message) +handshake-finished+)
             (error 'tls-handshake-error
                    :message "Expected Finished"
                    :state :wait-finished))
           (process-server-finished hs message raw-bytes)))
        (:send-finished
         (send-client-finished hs))
        (:connected
         (return hs))
        (t
         (error 'tls-handshake-error
                :message (format nil "Unknown state: ~A" (client-handshake-state hs))))))))

(defun read-raw-handshake-message (hs)
  "Read a raw handshake message before encryption is established."
  (multiple-value-bind (content-type data)
      (record-layer-read (client-handshake-record-layer hs))
    ;; Handle alerts
    (when (= content-type +content-type-alert+)
      (process-alert data))
    ;; Must be handshake
    (unless (= content-type +content-type-handshake+)
      (error 'tls-handshake-error
             :message (format nil "Expected handshake, got content type ~D" content-type)))
    data))
