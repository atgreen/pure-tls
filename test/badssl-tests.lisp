;;; test/badssl-tests.lisp --- Live network validation tests
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Anthony Green <green@moxielogic.com>
;;;
;;; Network tests for TLS 1.3 connections.
;;; NOTE: badssl.com only supports TLS 1.2, so those tests are not usable
;;; for a TLS 1.3-only library.

(in-package #:pure-tls/test)

(def-suite badssl-tests
  :description "Live TLS 1.3 connection tests")

(in-suite badssl-tests)

;;;; Connection Helper

(defun try-tls-connect (hostname &key (port 443) (verify pure-tls:+verify-required+))
  "Attempt TLS connection. Returns :success or an error keyword."
  (let ((socket nil))
    (unwind-protect
        (handler-case
            (progn
              (setf socket (usocket:socket-connect hostname port
                                                   :element-type '(unsigned-byte 8)))
              (let ((tls (pure-tls:make-tls-client-stream
                          (usocket:socket-stream socket)
                          :hostname hostname :verify verify)))
                (unwind-protect
                    (progn
                      (write-sequence
                       (pure-tls:string-to-octets
                        (format nil "GET / HTTP/1.1\r\nHost: ~A\r\nConnection: close\r\n\r\n"
                                hostname))
                       tls)
                      (force-output tls)
                      (if (read-byte tls nil nil) :success :no-data))
                  (ignore-errors (close tls)))))
          (pure-tls:tls-certificate-error () :cert-error)
          (pure-tls:tls-verification-error () :verify-error)
          (pure-tls:tls-handshake-error () :handshake-error)
          (pure-tls:tls-error () :tls-error)
          (error () :other-error))
      (when socket (ignore-errors (usocket:socket-close socket))))))

;;;; TLS 1.3 Connection Tests (Major Sites)

(test connect-google
  "Connect to google.com"
  (is (eq (try-tls-connect "www.google.com") :success)))

(test connect-cloudflare
  "Connect to cloudflare.com"
  (is (eq (try-tls-connect "www.cloudflare.com") :success)))

(test connect-github
  "Connect to github.com"
  (is (eq (try-tls-connect "github.com") :success)))

(test connect-mozilla
  "Connect to mozilla.org"
  (is (eq (try-tls-connect "www.mozilla.org") :success)))

(test connect-amazon
  "Connect to amazon.com"
  (is (eq (try-tls-connect "www.amazon.com") :success)))

;;;; Test Runner

(defun run-badssl-tests ()
  "Run network validation tests (requires network)."
  (format t "~&Running TLS 1.3 network tests...~%")
  (format t "Note: badssl.com tests removed (only supports TLS 1.2)~%~%")
  (run! 'badssl-tests))
