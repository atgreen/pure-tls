;;; test/badssl-tests.lisp --- Live validation tests using badssl.com
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Anthony Green <green@moxielogic.com>
;;;
;;; Tests certificate validation against badssl.com endpoints.
;;; These tests require network connectivity.

(in-package #:pure-tls/test)

(def-suite badssl-tests
  :description "Live certificate validation tests using badssl.com")

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

;;;; Test Generation Macros

(defmacro def-should-connect (name host description)
  "Define a test expecting successful connection."
  `(test ,name ,description
     (is (eq (try-tls-connect ,host) :success))))

(defmacro def-should-reject (name host description &optional (errors ''(:cert-error :verify-error :handshake-error)))
  "Define a test expecting certificate/verification rejection."
  `(test ,name ,description
     (is (member (try-tls-connect ,host) ,errors))))

;;;; Valid Certificate Tests

(def-should-connect badssl-sha256 "sha256.badssl.com" "SHA-256 signature")
(def-should-connect badssl-sha384 "sha384.badssl.com" "SHA-384 signature")
(def-should-connect badssl-sha512 "sha512.badssl.com" "SHA-512 signature")
(def-should-connect badssl-ecc256 "ecc256.badssl.com" "ECC P-256")
(def-should-connect badssl-ecc384 "ecc384.badssl.com" "ECC P-384")
(def-should-connect badssl-rsa2048 "rsa2048.badssl.com" "RSA 2048-bit")
(def-should-connect badssl-rsa4096 "rsa4096.badssl.com" "RSA 4096-bit")
(def-should-connect badssl-rsa8192 "rsa8192.badssl.com" "RSA 8192-bit")
(def-should-connect badssl-ev "extended-validation.badssl.com" "Extended Validation")

;;;; Certificate Error Tests

(def-should-reject badssl-expired "expired.badssl.com" "Expired certificate")
(def-should-reject badssl-wrong-host "wrong.host.badssl.com" "Hostname mismatch")
(def-should-reject badssl-self-signed "self-signed.badssl.com" "Self-signed")
(def-should-reject badssl-untrusted "untrusted-root.badssl.com" "Untrusted root")
(def-should-reject badssl-incomplete "incomplete-chain.badssl.com" "Incomplete chain")

;; These may succeed if SAN matches (modern certs often omit CN)
(def-should-reject badssl-no-cn "no-common-name.badssl.com" "No Common Name"
  '(:success :cert-error :verify-error :handshake-error))
(def-should-reject badssl-no-subject "no-subject.badssl.com" "No Subject"
  '(:success :cert-error :verify-error :handshake-error))

;; Revoked: passes without OCSP/CRL checking (not implemented)
(test badssl-revoked "Revoked certificate (no OCSP/CRL)"
  (is (member (try-tls-connect "revoked.badssl.com")
              '(:success :cert-error :verify-error))))

;;;; Protocol Version Tests (TLS 1.3 only - older versions rejected)

(def-should-reject badssl-tls10 "tls-v1-0.badssl.com" "TLS 1.0 rejected"
  '(:handshake-error :tls-error :other-error))
(def-should-reject badssl-tls11 "tls-v1-1.badssl.com" "TLS 1.1 rejected"
  '(:handshake-error :tls-error :other-error))
(def-should-reject badssl-tls12 "tls-v1-2.badssl.com" "TLS 1.2 rejected"
  '(:handshake-error :tls-error :other-error))

;;;; Known Bad CAs (not in trust store)

(def-should-reject badssl-superfish "superfish.badssl.com" "Superfish CA"
  '(:cert-error :verify-error :handshake-error :tls-error))
(def-should-reject badssl-edellroot "edellroot.badssl.com" "eDellRoot CA"
  '(:cert-error :verify-error :handshake-error :tls-error))
(def-should-reject badssl-dsdtest "dsdtestprovider.badssl.com" "DSDTestProvider CA"
  '(:cert-error :verify-error :handshake-error :tls-error))
(def-should-reject badssl-preact "preact-cli.badssl.com" "preact-cli CA"
  '(:cert-error :verify-error :handshake-error :tls-error))
(def-should-reject badssl-webpack "webpack-dev-server.badssl.com" "webpack-dev-server CA"
  '(:cert-error :verify-error :handshake-error :tls-error))

;;;; Verification Disabled Tests

(test badssl-expired-no-verify "Expired cert with verify=none"
  (is (member (try-tls-connect "expired.badssl.com" :verify pure-tls:+verify-none+)
              '(:success :handshake-error :tls-error :other-error))))

(test badssl-self-signed-no-verify "Self-signed with verify=none"
  (is (member (try-tls-connect "self-signed.badssl.com" :verify pure-tls:+verify-none+)
              '(:success :handshake-error :tls-error :other-error))))

;;;; Sanity Checks (Major Sites)

(def-should-connect connect-google "www.google.com" "Google")
(def-should-connect connect-cloudflare "www.cloudflare.com" "Cloudflare")
(def-should-connect connect-github "github.com" "GitHub")

;;;; Test Runner

(defun run-badssl-tests ()
  "Run all badssl.com validation tests (requires network)."
  (format t "~&Running badssl.com validation tests...~%")
  (run! 'badssl-tests))

;;;; Not Tested:
;;;; - DH/static-RSA/weak ciphers: not in TLS 1.3
;;;; - Browser tests (mixed content, HSTS): test browser, not TLS
;;;; - Certificate Transparency: not implemented
