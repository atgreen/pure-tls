;;; package.lisp --- Package definitions for cl-tls
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Anthony Green <green@moxielogic.com>

(in-package #:cl-user)

(defpackage #:cl-tls
  (:use #:cl #:trivial-gray-streams)
  (:export
   ;; Stream creation
   #:make-tls-client-stream
   #:make-tls-server-stream

   ;; Context management
   #:make-tls-context
   #:tls-context-free
   #:with-tls-context
   #:*default-tls-context*

   ;; Stream class
   #:tls-stream
   #:tls-client-stream
   #:tls-server-stream

   ;; Stream accessors
   #:tls-peer-certificate
   #:tls-selected-alpn
   #:tls-cipher-suite
   #:tls-version

   ;; Certificate handling
   #:parse-certificate
   #:parse-certificate-from-file
   #:certificate-subject-common-names
   #:certificate-fingerprint
   #:certificate-not-before
   #:certificate-not-after
   #:certificate-free
   #:verify-hostname

   ;; Crypto utilities
   #:random-bytes

   ;; Conditions
   #:tls-error
   #:tls-handshake-error
   #:tls-certificate-error
   #:tls-verification-error
   #:tls-alert-error
   #:tls-decode-error

   ;; Verification modes
   #:+verify-none+
   #:+verify-peer+
   #:+verify-required+

   ;; Alert codes
   #:+alert-close-notify+
   #:+alert-unexpected-message+
   #:+alert-bad-record-mac+
   #:+alert-record-overflow+
   #:+alert-handshake-failure+
   #:+alert-bad-certificate+
   #:+alert-certificate-revoked+
   #:+alert-certificate-expired+
   #:+alert-certificate-unknown+
   #:+alert-illegal-parameter+
   #:+alert-unknown-ca+
   #:+alert-decode-error+
   #:+alert-decrypt-error+
   #:+alert-protocol-version+
   #:+alert-insufficient-security+
   #:+alert-internal-error+
   #:+alert-user-canceled+
   #:+alert-missing-extension+
   #:+alert-unsupported-extension+
   #:+alert-unrecognized-name+

   ;; Cipher suites
   #:+tls-aes-128-gcm-sha256+
   #:+tls-chacha20-poly1305-sha256+

   ;; Configuration
   #:*default-buffer-size*
   #:*default-verify-mode*))
