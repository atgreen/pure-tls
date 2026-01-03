;;; streams.lisp --- TLS Stream Implementation
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Anthony Green <green@moxielogic.com>
;;;
;;; Implements TLS streams using Gray streams.

(in-package #:pure-tls)

;;;; TLS Stream Class

(defclass tls-stream (trivial-gray-stream-mixin
                      fundamental-binary-input-stream
                      fundamental-binary-output-stream)
  ((underlying-stream
    :initarg :stream
    :reader tls-stream-underlying-stream
    :documentation "The underlying TCP stream.")
   (record-layer
    :accessor tls-stream-record-layer
    :documentation "The TLS record layer.")
   (handshake
    :accessor tls-stream-handshake
    :documentation "The handshake state (after completion).")
   (input-buffer
    :initform (make-octet-vector 0)
    :accessor tls-stream-input-buffer
    :documentation "Buffer for decrypted data not yet read.")
   (input-position
    :initform 0
    :accessor tls-stream-input-position
    :documentation "Current position in input buffer.")
   (output-buffer
    :accessor tls-stream-output-buffer
    :documentation "Buffer for data to be encrypted and sent.")
   (output-position
    :initform 0
    :accessor tls-stream-output-position
    :documentation "Current position in output buffer.")
   (closed
    :initform nil
    :accessor tls-stream-closed-p
    :documentation "Whether the stream has been closed.")
   (close-callback
    :initarg :close-callback
    :initform nil
    :accessor tls-stream-close-callback))
  (:documentation "A TLS-encrypted stream."))

(defclass tls-client-stream (tls-stream)
  ()
  (:documentation "A TLS client stream."))

(defclass tls-server-stream (tls-stream)
  ()
  (:documentation "A TLS server stream."))

(defmethod initialize-instance :after ((stream tls-stream) &key
                                                            (buffer-size *default-buffer-size*)
                                                            &allow-other-keys)
  (setf (tls-stream-output-buffer stream)
        (make-octet-vector buffer-size)))

;;;; Stream Methods

(defmethod stream-element-type ((stream tls-stream))
  '(unsigned-byte 8))

(defmethod open-stream-p ((stream tls-stream))
  (not (tls-stream-closed-p stream)))

(defmethod close ((stream tls-stream) &key abort)
  (unless (tls-stream-closed-p stream)
    ;; Flush pending output unless aborting
    (unless abort
      (force-output stream))
    ;; Send close_notify alert
    (unless abort
      (handler-case
          (record-layer-write-alert (tls-stream-record-layer stream)
                                    +alert-level-warning+
                                    +alert-close-notify+)
        (error () nil)))  ; Ignore errors during shutdown
    ;; Close underlying stream
    (close (tls-stream-underlying-stream stream) :abort abort)
    ;; Mark as closed
    (setf (tls-stream-closed-p stream) t)
    ;; Call close callback
    (when (tls-stream-close-callback stream)
      (funcall (tls-stream-close-callback stream) stream)))
  t)

;;;; Input Methods

(defun tls-stream-fill-buffer (stream)
  "Read more data from the record layer into the input buffer."
  (multiple-value-bind (content-type data)
      (record-layer-read (tls-stream-record-layer stream))
    (case content-type
      (#.+content-type-application-data+
       (setf (tls-stream-input-buffer stream) data)
       (setf (tls-stream-input-position stream) 0)
       t)
      (#.+content-type-alert+
       (process-alert data)
       nil)
      (#.+content-type-handshake+
       ;; Post-handshake messages (e.g., NewSessionTicket, KeyUpdate)
       ;; For now, ignore them
       (tls-stream-fill-buffer stream))
      (t
       (error 'tls-error :message (format nil "Unexpected content type: ~D" content-type))))))

(defun tls-stream-buffer-remaining (stream)
  "Return the number of bytes remaining in the input buffer."
  (- (length (tls-stream-input-buffer stream))
     (tls-stream-input-position stream)))

(defmethod stream-read-byte ((stream tls-stream))
  (when (tls-stream-closed-p stream)
    (return-from stream-read-byte :eof))
  ;; Refill buffer if empty
  (when (zerop (tls-stream-buffer-remaining stream))
    (handler-case
        (tls-stream-fill-buffer stream)
      (tls-connection-closed ()
        (return-from stream-read-byte :eof))))
  ;; Read from buffer
  (if (plusp (tls-stream-buffer-remaining stream))
      (prog1 (aref (tls-stream-input-buffer stream)
                   (tls-stream-input-position stream))
        (incf (tls-stream-input-position stream)))
      :eof))

(defmethod stream-read-sequence ((stream tls-stream) sequence start end &key)
  (when (tls-stream-closed-p stream)
    (return-from stream-read-sequence start))
  (let ((pos start))
    (loop while (< pos end)
          do (progn
               ;; Refill buffer if needed
               (when (zerop (tls-stream-buffer-remaining stream))
                 (handler-case
                     (tls-stream-fill-buffer stream)
                   (tls-connection-closed ()
                     (return-from stream-read-sequence pos))))
               ;; Copy from buffer
               (let* ((remaining (tls-stream-buffer-remaining stream))
                      (to-copy (min remaining (- end pos))))
                 (when (zerop to-copy)
                   (return-from stream-read-sequence pos))
                 (replace sequence (tls-stream-input-buffer stream)
                          :start1 pos
                          :end1 (+ pos to-copy)
                          :start2 (tls-stream-input-position stream))
                 (incf pos to-copy)
                 (incf (tls-stream-input-position stream) to-copy))))
    pos))

(defmethod stream-listen ((stream tls-stream))
  (or (plusp (tls-stream-buffer-remaining stream))
      (listen (tls-stream-underlying-stream stream))))

;;;; Output Methods

(defmethod stream-write-byte ((stream tls-stream) byte)
  (when (tls-stream-closed-p stream)
    (error 'tls-error :message "Cannot write to closed stream"))
  (let ((buf (tls-stream-output-buffer stream))
        (pos (tls-stream-output-position stream)))
    (setf (aref buf pos) byte)
    (incf (tls-stream-output-position stream))
    ;; Flush if buffer is full
    (when (= (tls-stream-output-position stream) (length buf))
      (force-output stream)))
  byte)

(defmethod stream-write-sequence ((stream tls-stream) sequence start end &key)
  (when (tls-stream-closed-p stream)
    (error 'tls-error :message "Cannot write to closed stream"))
  (loop while (< start end)
        do (let* ((buf (tls-stream-output-buffer stream))
                  (pos (tls-stream-output-position stream))
                  (space (- (length buf) pos))
                  (to-copy (min space (- end start))))
             (replace buf sequence
                      :start1 pos
                      :start2 start
                      :end2 (+ start to-copy))
             (incf (tls-stream-output-position stream) to-copy)
             (incf start to-copy)
             ;; Flush if buffer is full
             (when (= (tls-stream-output-position stream) (length buf))
               (force-output stream))))
  sequence)

(defmethod stream-force-output ((stream tls-stream))
  (when (plusp (tls-stream-output-position stream))
    (let ((data (subseq (tls-stream-output-buffer stream)
                        0 (tls-stream-output-position stream))))
      (record-layer-write-application-data
       (tls-stream-record-layer stream) data)
      (setf (tls-stream-output-position stream) 0)))
  (force-output (tls-stream-underlying-stream stream)))

(defmethod stream-finish-output ((stream tls-stream))
  (stream-force-output stream))

;;;; Stream Accessors

(defun tls-peer-certificate (stream)
  "Return the peer's certificate, if available.
   Returns an x509-certificate structure (already parsed)."
  (let ((hs (tls-stream-handshake stream)))
    (when hs
      (typecase hs
        (client-handshake (client-handshake-peer-certificate hs))
        (server-handshake (server-handshake-peer-certificate hs))))))

(defun tls-peer-certificate-chain (stream)
  "Return the peer's full certificate chain, if available.
   Returns a list of x509-certificate structures (leaf first)."
  (let ((hs (tls-stream-handshake stream)))
    (when hs
      (typecase hs
        (client-handshake (client-handshake-peer-certificate-chain hs))
        (server-handshake (server-handshake-peer-certificate-chain hs))))))

(defun tls-selected-alpn (stream)
  "Return the negotiated ALPN protocol, if any."
  (let ((hs (tls-stream-handshake stream)))
    (when hs
      (typecase hs
        (client-handshake (client-handshake-selected-alpn hs))
        (server-handshake (server-handshake-selected-alpn hs))))))

(defun tls-cipher-suite (stream)
  "Return the negotiated cipher suite."
  (let ((hs (tls-stream-handshake stream)))
    (when hs
      (typecase hs
        (client-handshake (client-handshake-selected-cipher-suite hs))
        (server-handshake (server-handshake-selected-cipher-suite hs))))))

(defun tls-version (stream)
  "Return the TLS version (always 1.3 for this implementation)."
  (declare (ignore stream))
  +tls-1.3+)

(defun tls-client-hostname (stream)
  "Return the client's SNI hostname (server-side only)."
  (let ((hs (tls-stream-handshake stream)))
    (when (server-handshake-p hs)
      (server-handshake-client-hostname hs))))

;;;; Stream Creation

(defun make-tls-client-stream (socket &key
                                        hostname
                                        (context (ensure-default-context))
                                        (verify (tls-context-verify-mode context))
                                        alpn-protocols
                                        close-callback
                                        external-format
                                        (buffer-size *default-buffer-size*))
  "Create a TLS client stream over SOCKET.

   SOCKET - The underlying TCP stream or socket.
   HOSTNAME - Server hostname for SNI and verification.
   CONTEXT - TLS context for configuration.
   VERIFY - Certificate verification mode.
   ALPN-PROTOCOLS - List of ALPN protocol names to offer.
   CLOSE-CALLBACK - Function called when stream is closed.
   EXTERNAL-FORMAT - If non-NIL, wrap in a flexi-stream.
   BUFFER-SIZE - Size of I/O buffers.

   Returns the TLS stream, or a flexi-stream if EXTERNAL-FORMAT specified."
  (let* ((stream (make-instance 'tls-client-stream
                                :stream socket
                                :close-callback close-callback
                                :buffer-size buffer-size))
         (record-layer (make-record-layer socket))
         (trust-store (tls-context-trust-store context)))
    (setf (tls-stream-record-layer stream) record-layer)
    ;; Perform handshake (CertificateVerify is verified during handshake)
    (let ((hs (perform-client-handshake
               record-layer
               :hostname hostname
               :alpn-protocols (or alpn-protocols
                                   (tls-context-alpn-protocols context))
               :verify-mode verify
               :trust-store trust-store)))
      (setf (tls-stream-handshake stream) hs)
      ;; Verify certificate chain and hostname if verification enabled
      (when (and (member verify (list +verify-peer+ +verify-required+))
                 (client-handshake-peer-certificate hs))
        (let ((cert (client-handshake-peer-certificate hs))
              (chain (client-handshake-peer-certificate-chain hs)))
          ;; Verify hostname
          (when hostname
            (verify-hostname cert hostname))
          ;; Verify certificate chain with trust store (if we have one and verify is required)
          (when (and (= verify +verify-required+)
                     trust-store
                     chain)
            (verify-certificate-chain chain (trust-store-certificates trust-store))))))
    ;; Wrap with flexi-stream if external-format specified
    (if external-format
        (flexi-streams:make-flexi-stream stream :external-format external-format)
        stream)))

(defun make-tls-server-stream (socket &key
                                        (context (ensure-default-context))
                                        certificate
                                        key
                                        (verify +verify-none+)
                                        alpn-protocols
                                        close-callback
                                        external-format
                                        (buffer-size *default-buffer-size*))
  "Create a TLS server stream over SOCKET.

   SOCKET - The underlying TCP stream or socket.
   CONTEXT - TLS context for configuration.
   CERTIFICATE - Certificate chain (list of x509-certificate) or path to PEM file.
   KEY - Private key (Ironclad key object) or path to PEM file.
   VERIFY - Client certificate verification mode (+verify-none+, +verify-peer+, +verify-required+).
   ALPN-PROTOCOLS - List of ALPN protocol names the server supports.
   CLOSE-CALLBACK - Function called when stream is closed.
   EXTERNAL-FORMAT - If non-NIL, wrap in a flexi-stream.
   BUFFER-SIZE - Size of I/O buffers.

   Returns the TLS stream, or a flexi-stream if EXTERNAL-FORMAT specified."
  (let* ((stream (make-instance 'tls-server-stream
                                :stream socket
                                :close-callback close-callback
                                :buffer-size buffer-size))
         (record-layer (make-record-layer socket))
         ;; Get certificate chain (from parameter, context, or file)
         (cert-chain (cond
                       ((listp certificate) certificate)
                       ((stringp certificate) (load-certificate-chain certificate))
                       ((pathnamep certificate) (load-certificate-chain certificate))
                       (t (tls-context-certificate-chain context))))
         ;; Get private key (from parameter, context, or file)
         (private-key (cond
                        ((or (null key) (stringp key) (pathnamep key))
                         (let ((key-source (or key
                                               (when (stringp certificate) certificate)
                                               (when (pathnamep certificate) certificate))))
                           (if key-source
                               (load-private-key key-source)
                               (tls-context-private-key context))))
                        (t key)))  ; Already an Ironclad key object
         ;; Get trust store for client certificate verification
         (trust-store (when (member verify (list +verify-peer+ +verify-required+))
                        (tls-context-trust-store context)))
         ;; Get ALPN protocols
         (alpn (or alpn-protocols (tls-context-alpn-protocols context))))
    ;; Validate we have certificate and key
    (unless cert-chain
      (error 'tls-error :message "Server requires a certificate chain"))
    (unless private-key
      (error 'tls-error :message "Server requires a private key"))
    (setf (tls-stream-record-layer stream) record-layer)
    ;; Perform server handshake
    (let ((hs (perform-server-handshake
               record-layer
               cert-chain
               private-key
               :alpn-protocols alpn
               :verify-mode verify
               :trust-store trust-store)))
      (setf (tls-stream-handshake stream) hs))
    ;; Wrap with flexi-stream if external-format specified
    (if external-format
        (flexi-streams:make-flexi-stream stream :external-format external-format)
        stream)))
