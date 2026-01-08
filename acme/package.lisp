;;; package.lisp --- Package definition for pure-tls/acme
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Anthony Green <green@moxielogic.com>
;;;
;;; ACME (Automatic Certificate Management Environment) client for pure-tls.
;;; Supports automatic certificate acquisition from Let's Encrypt and other
;;; ACME-compatible certificate authorities.

(in-package #:cl-user)

(defpackage #:pure-tls/acme
  (:use #:cl)
  (:nicknames #:acme)
  (:export
   ;; Configuration
   #:*directory-url*
   #:*staging-url*
   #:*production-url*
   #:*skip-tls-verify*
   #:use-staging
   #:use-production

   ;; Certificate paths
   #:*cert-directory*
   #:cert-directory
   #:cert-path
   #:key-path
   #:certificates-exist-p

   ;; Low-level ACME client
   #:acme-init
   #:acme-register-account
   #:acme-new-order
   #:acme-get-authorization
   #:acme-respond-challenge
   #:acme-poll-status
   #:acme-finalize-order
   #:acme-download-certificate

   ;; Challenge helpers
   #:get-tls-alpn-challenge
   #:compute-key-authorization

   ;; TLS-ALPN-01 challenge
   #:start-tls-alpn-server
   #:stop-tls-alpn-server
   #:generate-validation-certificate

   ;; High-level API
   #:obtain-certificate
   #:certificate-expires-soon-p

   ;; Certificate manager
   #:make-cert-manager
   #:cert-manager-start
   #:cert-manager-stop
   #:cert-manager-certificate
   #:cert-manager-private-key

   ;; CSR generation
   #:generate-csr
   #:generate-domain-key

   ;; TLS server convenience
   #:with-auto-tls-server
   #:make-auto-tls-acceptor

   ;; Conditions
   #:acme-error
   #:acme-challenge-error
   #:acme-order-error
   #:acme-certificate-error))
