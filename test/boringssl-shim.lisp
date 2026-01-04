;;; boringssl-shim.lisp --- BoringSSL test runner shim for pure-tls
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Anthony Green <green@moxielogic.com>
;;;
;;; This file implements a shim binary that allows the BoringSSL
;;; ssl/test/runner to test pure-tls. The shim communicates with
;;; the Go test runner over TCP and uses pure-tls for TLS operations.
;;;
;;; Exit codes:
;;;   0  - Test passed
;;;   1  - Test failed
;;;   89 - Feature not implemented (skip test)
;;;   90 - Expected failure

(defpackage #:pure-tls/boringssl-shim
  (:use #:cl)
  (:export #:main))

(in-package #:pure-tls/boringssl-shim)

;;;; Exit Codes
(defconstant +exit-success+ 0)
(defconstant +exit-failure+ 1)
(defconstant +exit-unimplemented+ 89)
(defconstant +exit-expected-failure+ 90)

;;;; Configuration Structure
(defstruct shim-config
  "Configuration parsed from command-line arguments."
  (port 0 :type fixnum)
  (shim-id 0 :type integer)
  (is-server nil :type boolean)
  (is-dtls nil :type boolean)
  (cert-file nil :type (or null string))
  (key-file nil :type (or null string))
  (trust-cert nil :type (or null string))
  (host-name nil :type (or null string))
  (min-version 0 :type fixnum)
  (max-version 0 :type fixnum)
  (no-tls13 nil :type boolean)
  (no-tls12 nil :type boolean)
  (no-tls11 nil :type boolean)
  (no-tls1 nil :type boolean)
  (shim-writes-first nil :type boolean)
  (check-close-notify nil :type boolean)
  (verify-peer nil :type boolean)
  (advertise-alpn nil :type (or null string))
  (select-alpn nil :type (or null string))
  (expect-alpn nil :type (or null string))
  (expect-server-name nil :type (or null string))
  (fallback-scsv nil :type boolean)
  (resume-count 0 :type fixnum)
  (expect-session-miss nil :type boolean)
  (async nil :type boolean)
  (ipv6 nil :type boolean))

;;;; Argument Parsing
(defun parse-args (args)
  "Parse command-line arguments into a shim-config structure.
   Returns (values config remaining-args) or signals an error."
  (let ((config (make-shim-config)))
    (loop with i = 0
          while (< i (length args))
          for arg = (elt args i)
          do (cond
               ;; Port number
               ((string= arg "-port")
                (incf i)
                (when (< i (length args))
                  (setf (shim-config-port config)
                        (parse-integer (elt args i)))))

               ;; Shim ID
               ((string= arg "-shim-id")
                (incf i)
                (when (< i (length args))
                  (setf (shim-config-shim-id config)
                        (parse-integer (elt args i)))))

               ;; Server mode
               ((string= arg "-server")
                (setf (shim-config-is-server config) t))

               ;; DTLS mode
               ((string= arg "-dtls")
                (setf (shim-config-is-dtls config) t))

               ;; IPv6
               ((string= arg "-ipv6")
                (setf (shim-config-ipv6 config) t))

               ;; Certificate file
               ((string= arg "-cert-file")
                (incf i)
                (when (< i (length args))
                  (setf (shim-config-cert-file config) (elt args i))))

               ;; Key file
               ((string= arg "-key-file")
                (incf i)
                (when (< i (length args))
                  (setf (shim-config-key-file config) (elt args i))))

               ;; Trust certificate
               ((string= arg "-trust-cert")
                (incf i)
                (when (< i (length args))
                  (setf (shim-config-trust-cert config) (elt args i))))

               ;; Hostname
               ((string= arg "-host-name")
                (incf i)
                (when (< i (length args))
                  (setf (shim-config-host-name config) (elt args i))))

               ;; Expected server name (SNI)
               ((string= arg "-expect-server-name")
                (incf i)
                (when (< i (length args))
                  (setf (shim-config-expect-server-name config) (elt args i))))

               ;; Version constraints
               ((string= arg "-min-version")
                (incf i)
                (when (< i (length args))
                  (setf (shim-config-min-version config)
                        (parse-integer (elt args i)))))

               ((string= arg "-max-version")
                (incf i)
                (when (< i (length args))
                  (setf (shim-config-max-version config)
                        (parse-integer (elt args i)))))

               ;; Version disabling
               ((string= arg "-no-tls13")
                (setf (shim-config-no-tls13 config) t))

               ((string= arg "-no-tls12")
                (setf (shim-config-no-tls12 config) t))

               ((string= arg "-no-tls11")
                (setf (shim-config-no-tls11 config) t))

               ((string= arg "-no-tls1")
                (setf (shim-config-no-tls1 config) t))

               ;; Behavior flags
               ((string= arg "-shim-writes-first")
                (setf (shim-config-shim-writes-first config) t))

               ((string= arg "-check-close-notify")
                (setf (shim-config-check-close-notify config) t))

               ((string= arg "-verify-peer")
                (setf (shim-config-verify-peer config) t))

               ((string= arg "-async")
                (setf (shim-config-async config) t))

               ;; ALPN
               ((string= arg "-advertise-alpn")
                (incf i)
                (when (< i (length args))
                  (setf (shim-config-advertise-alpn config) (elt args i))))

               ((string= arg "-select-alpn")
                (incf i)
                (when (< i (length args))
                  (setf (shim-config-select-alpn config) (elt args i))))

               ((string= arg "-expect-alpn")
                (incf i)
                (when (< i (length args))
                  (setf (shim-config-expect-alpn config) (elt args i))))

               ;; Session resumption
               ((string= arg "-resume-count")
                (incf i)
                (when (< i (length args))
                  (setf (shim-config-resume-count config)
                        (parse-integer (elt args i)))))

               ((string= arg "-expect-session-miss")
                (setf (shim-config-expect-session-miss config) t))

               ;; Fallback SCSV
               ((string= arg "-fallback-scsv")
                (setf (shim-config-fallback-scsv config) t))

               ;; Skip unknown flags but continue
               (t
                ;; Check if next arg is a value for this flag
                (when (and (< (1+ i) (length args))
                           (not (char= (char (elt args (1+ i)) 0) #\-)))
                  (incf i))))
             (incf i))
    config))

;;;; Feature Detection
(defun check-unimplemented-features (config)
  "Check if the test requires unimplemented features.
   Returns :unimplemented keyword if test should be skipped, nil otherwise."
  (cond
    ;; DTLS not supported
    ((shim-config-is-dtls config)
     :dtls-not-supported)

    ;; Session resumption not fully supported
    ((> (shim-config-resume-count config) 0)
     :resumption-not-supported)

    ;; If only TLS 1.2 or earlier is allowed (no TLS 1.3)
    ((and (shim-config-no-tls13 config)
          (or (zerop (shim-config-max-version config))
              (< (shim-config-max-version config) #x0304)))
     :only-tls13-supported)

    ;; Fallback SCSV is TLS 1.2 specific
    ((shim-config-fallback-scsv config)
     :fallback-scsv-not-supported)

    (t nil)))

;;;; Socket Operations
(defun connect-to-runner (config)
  "Connect to the BoringSSL runner on the specified port.
   Returns the usocket. The runner acts as a TCP server that the shim
   connects to, even for TLS server tests."
  (let* ((host (if (shim-config-ipv6 config) "::1" "127.0.0.1"))
         (socket (usocket:socket-connect host (shim-config-port config)
                                         :element-type '(unsigned-byte 8))))
    socket))

(defun send-shim-id (stream shim-id)
  "Send the shim ID as a 64-bit little-endian integer."
  (let ((buf (make-array 8 :element-type '(unsigned-byte 8))))
    (loop for i from 0 below 8
          do (setf (aref buf i) (ldb (byte 8 (* i 8)) shim-id)))
    (write-sequence buf stream)
    (force-output stream)))

;;;; TLS Operations
(defun load-credentials (config)
  "Load certificate and key from config files.
   Returns (values cert-chain private-key) or (values nil nil)."
  (when (and (shim-config-cert-file config)
             (shim-config-key-file config))
    (handler-case
        (values (pure-tls:load-certificate-chain (shim-config-cert-file config))
                (pure-tls:load-private-key (shim-config-key-file config)))
      (error (e)
        (format *error-output* "Failed to load credentials: ~A~%" e)
        (values nil nil)))))

(defun load-trust-store (config)
  "Load trust store from config.
   NOTE: Trust store loading is simplified - uses verification mode instead."
  (declare (ignore config))
  ;; For now, we don't load a custom trust store
  ;; The shim uses verify-none mode for testing
  nil)

(defun parse-alpn-protocols (alpn-string)
  "Parse ALPN protocol list from wire format or comma-separated string."
  (when alpn-string
    ;; BoringSSL sends ALPN as length-prefixed wire format
    (let ((bytes (map 'vector #'char-code alpn-string)))
      (loop with i = 0
            while (< i (length bytes))
            for len = (aref bytes i)
            collect (map 'string #'code-char
                         (subseq bytes (1+ i) (+ 1 i len)))
            do (incf i (1+ len))))))

(defun run-client-test (config stream)
  "Run TLS client test against the runner.
   STREAM is the raw TCP stream from usocket:socket-stream."
  (let* ((trust-store (load-trust-store config))
         (alpn (parse-alpn-protocols (shim-config-advertise-alpn config)))
         (hostname (or (shim-config-host-name config) "localhost"))
         (tls-stream
           (pure-tls:make-tls-client-stream
            stream
            :hostname hostname
            :alpn-protocols alpn
            :verify (if (shim-config-verify-peer config)
                        pure-tls:+verify-required+
                        pure-tls:+verify-none+))))

    ;; Check ALPN result if expected
    (when (shim-config-expect-alpn config)
      (let ((negotiated (pure-tls:tls-selected-alpn tls-stream)))
        (unless (string= negotiated (shim-config-expect-alpn config))
          (error "ALPN mismatch: expected ~S, got ~S"
                 (shim-config-expect-alpn config) negotiated))))

    ;; Exchange test data
    (if (shim-config-shim-writes-first config)
        (progn
          (write-sequence (babel:string-to-octets "hello") tls-stream)
          (force-output tls-stream)
          (let ((buf (make-array 1024 :element-type '(unsigned-byte 8))))
            (read-sequence buf tls-stream)))
        (progn
          (let ((buf (make-array 1024 :element-type '(unsigned-byte 8))))
            (let ((n (read-sequence buf tls-stream)))
              (when (> n 0)
                (write-sequence buf tls-stream :end n)
                (force-output tls-stream))))))

    ;; Close with close_notify
    (close tls-stream)
    +exit-success+))

(defun run-server-test (config stream)
  "Run TLS server test against the runner.
   STREAM is the raw TCP stream from usocket:socket-stream."
  (multiple-value-bind (cert-chain private-key) (load-credentials config)
    (unless (and cert-chain private-key)
      (error "Server test requires certificate and key"))

    (let* ((sni-callback
             (when (shim-config-expect-server-name config)
               (lambda (hostname)
                 (unless (string= hostname (shim-config-expect-server-name config))
                   (error "SNI mismatch: expected ~S, got ~S"
                          (shim-config-expect-server-name config) hostname))
                 nil)))
           (tls-stream
             (pure-tls:make-tls-server-stream
              stream
              :certificate cert-chain
              :key private-key
              :sni-callback sni-callback)))

      ;; Exchange test data
      (if (shim-config-shim-writes-first config)
          (progn
            (write-sequence (babel:string-to-octets "hello") tls-stream)
            (force-output tls-stream)
            (let ((buf (make-array 1024 :element-type '(unsigned-byte 8))))
              (read-sequence buf tls-stream)))
          (progn
            (let ((buf (make-array 1024 :element-type '(unsigned-byte 8))))
              (let ((n (read-sequence buf tls-stream)))
                (when (> n 0)
                  (write-sequence buf tls-stream :end n)
                  (force-output tls-stream))))))

      ;; Close with close_notify
      (close tls-stream)
      +exit-success+)))

;;;; Main Entry Point
(defun main (&optional (args (uiop:command-line-arguments)))
  "Main entry point for the BoringSSL shim.
   Parses arguments, checks for unimplemented features, and runs the test."
  ;; Handle special query flags before normal processing
  (when (member "-is-handshaker-supported" args :test #'string=)
    ;; Split handshake mode is not supported
    (format t "No~%")
    (return-from main +exit-success+))

  (handler-case
      (let ((config (parse-args args)))
        ;; Check for unimplemented features first
        (let ((unimpl (check-unimplemented-features config)))
          (when unimpl
            (format *error-output* "Unimplemented: ~A~%" unimpl)
            (return-from main +exit-unimplemented+)))

        ;; Validate required parameters
        (when (zerop (shim-config-port config))
          (format *error-output* "Missing required -port argument~%")
          (return-from main +exit-failure+))

        ;; Run the appropriate test
        ;; Note: The shim always connects TO the runner as a TCP client,
        ;; even when acting as a TLS server. The runner is the TCP server.
        (let* ((socket (connect-to-runner config))
               (stream (usocket:socket-stream socket)))
          ;; Send shim-id as 64-bit little-endian before proceeding
          (send-shim-id stream (shim-config-shim-id config))
          (unwind-protect
              (if (shim-config-is-server config)
                  (run-server-test config stream)
                  (run-client-test config stream))
            (usocket:socket-close socket))))

    ;; Handle TLS errors
    (pure-tls:tls-error (e)
      (format *error-output* "TLS error: ~A~%" e)
      +exit-failure+)

    ;; Handle other errors
    (error (e)
      (format *error-output* "Error: ~A~%" e)
      +exit-failure+)))

;;; Build script helper
#+sbcl
(defun shim-toplevel ()
  "Toplevel function that runs main and exits with proper code."
  (sb-ext:exit :code (main)))

#+sbcl
(defun build-shim ()
  "Build the shim as a standalone executable."
  (sb-ext:save-lisp-and-die
   "pure-tls-shim"
   :toplevel #'shim-toplevel
   :executable t))
