;;; cl-tls.asd
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Anthony Green <green@moxielogic.com>

(asdf:defsystem #:cl-tls
  :description "Pure Common Lisp TLS 1.3 implementation"
  :author "Anthony Green <green@moxielogic.com>"
  :license "MIT"
  :version "0.1.0"
  :depends-on (#:ironclad
               #:trivial-gray-streams
               #:flexi-streams
               #:alexandria
               #:iparse
               #:cl-base64)
  :serial t
  :components ((:file "src/package")
               (:file "src/constants")
               (:file "src/conditions")
               (:file "src/utils")
               (:module "src/crypto"
                :serial t
                :components ((:file "hkdf")
                             (:file "aead")
                             (:file "key-exchange")))
               (:module "src/record"
                :serial t
                :components ((:file "record-layer")))
               (:module "src/handshake"
                :serial t
                :components ((:file "messages")
                             (:file "key-schedule")
                             (:file "extensions")
                             (:file "client")))
               (:module "src/x509"
                :serial t
                :components ((:file "asn1")
                             (:file "certificate")
                             (:file "verify")))
               (:file "src/context")
               (:file "src/streams")))

(asdf:defsystem #:cl-tls/compat
  :description "cl+ssl compatibility layer for cl-tls"
  :author "Anthony Green <green@moxielogic.com>"
  :license "MIT"
  :version "0.1.0"
  :depends-on (#:cl-tls
               #:usocket)
  :serial t
  :components ((:file "compat/package")
               (:file "compat/api")))

(asdf:defsystem #:cl-tls/test
  :description "Tests for cl-tls"
  :author "Anthony Green <green@moxielogic.com>"
  :license "MIT"
  :depends-on (#:cl-tls
               #:fiveam)
  :serial t
  :components ((:module "test"
                :serial t
                :components ((:file "package")
                             (:file "crypto-tests")
                             (:file "record-tests")
                             (:file "handshake-tests")))))
