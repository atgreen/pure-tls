;;; test/security-regression-tests.lisp --- Security regression tests
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Anthony Green <green@moxielogic.com>
;;;
;;; Regression tests for security findings surfaced by a SAST triage of the
;;; pure-Lisp verification and handshake-parsing paths.
;;;
;;; Each test asserts the SECURE behaviour for a fixed finding and guards
;;; against regression:
;;;   * CL-SEC-2026-0206 -- out-of-bounds read parsing a hostile ECHConfig
;;;   * CL-SEC-2026-0207 -- ExtendedKeyUsage not enforced during chain verify
;;;
;;; Fixtures (cert-only, no private keys) live in test/certs/ and were produced
;;; with OpenSSL; see the comments on each test for how to regenerate them.

(in-package #:pure-tls/test)

(def-suite security-regression-tests
  :description "Regression tests for SAST security findings (expected-failing until fixed)")

(in-suite security-regression-tests)

;;;; Note: hex-to-bytes is defined in crypto-tests.lisp; test-cert-path and
;;;; *test-certs-dir* are defined in certificate-tests.lisp.  Both files load
;;;; before this one (see pure-tls.asd :serial t component order).

;;;; ---------------------------------------------------------------------------
;;;; Finding: ECH config parsing crashes with a raw, non-TLS error on a
;;;; malformed length field (remote DoS from a single peer message).
;;;;
;;;; src/handshake/ech.lisp parse-ech-config-contents reads attacker-controlled
;;;; length fields (pk_len, pn_len, ext_len) and slices with AREF/SUBSEQ BEFORE
;;;; the only bounds check ((<= pos end), ech.lisp:92).  An oversized length
;;;; makes SUBSEQ raise SB-KERNEL:BOUNDING-INDICES-BAD-ERROR -- an ordinary CL
;;;; error, NOT a subtype of PURE-TLS:TLS-ERROR.  The EncryptedExtensions
;;;; parse path (extensions.lisp ~590) reaches this unconditionally, and the
;;;; handshake error handlers only catch TLS-* conditions, so a malicious peer
;;;; aborts the handshake with an uncaught Lisp error.
;;;;
;;;; Secure behaviour: malformed peer ECH bytes MUST surface as a graceful
;;;; PURE-TLS:TLS-ERROR (e.g. tls-decode-error / tls-handshake-error), never a
;;;; raw bounds error.  This test will pass once the ECH parser validates each
;;;; length against the remaining buffer (or routes through the bounds-checked
;;;; tls-buffer readers).
;;;; ---------------------------------------------------------------------------

(test ech-config-malformed-length-is-graceful
  "Malformed ECHConfigList length must raise a TLS-ERROR, not a raw Lisp crash."
  ;; ECHConfigList:
  ;;   total_len = 0x0009
  ;;   ECHConfig { version = 0xfe0d, length = 0x0005,
  ;;               contents = { config_id=0x00, kem_id=0x0020, pk_len=0xffff } }
  ;; pk_len (0xffff) runs far past the 11-byte buffer.
  (let ((bytes (hex-to-bytes "00 09 fe 0d 00 05 00 00 20 ff ff")))
    ;; Currently raises SB-KERNEL:BOUNDING-INDICES-BAD-ERROR (not a tls-error),
    ;; so this SIGNALS assertion fails until the parser is hardened.
    (signals pure-tls:tls-error
      (pure-tls::parse-ech-config-list bytes))))

;;;; ---------------------------------------------------------------------------
;;;; Finding: ExtendedKeyUsage (EKU) is recognised but never enforced.
;;;;
;;;; The pure-Lisp chain verifier accepts a leaf whose EKU does NOT include
;;;; serverAuth as a valid server certificate.  src/x509/verify.lisp
;;;; verify-certificate-chain checks dates, names, BasicConstraints, keyCertSign,
;;;; path length, and signatures, but contains no EKU enforcement; EKU is even
;;;; listed as a "known critical" extension (certificate.lisp), so a critical
;;;; clientAuth-only EKU passes silently.
;;;;
;;;; Secure behaviour: a leaf valid only for clientAuth must NOT be accepted for
;;;; TLS server authentication.
;;;;
;;;; DESIGN NOTE: verify-certificate-chain is also used for mTLS client-cert
;;;; validation, where a clientAuth leaf is correct.  The fix adds a :purpose
;;;; keyword (the TLS client path requests :server-auth, the server path
;;;; requests :client-auth); a leaf whose EKU is present but lists neither the
;;;; requested purpose nor anyExtendedKeyUsage is rejected.  This test requests
;;;; :server-auth explicitly, mirroring the client handshake path.
;;;;
;;;; Fixtures (regenerate with):
;;;;   openssl req -x509 -newkey rsa:2048 -nodes -keyout root.key \
;;;;     -out security-regression-root-ca.pem -subj "/CN=Test Root CA" \
;;;;     -days 36500 -sha256 \
;;;;     -addext "basicConstraints=critical,CA:TRUE" \
;;;;     -addext "keyUsage=critical,keyCertSign,cRLSign"
;;;;   openssl req -newkey rsa:2048 -nodes -keyout leaf.key -out leaf.csr \
;;;;     -subj "/CN=victim.example" -sha256
;;;;   printf "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=critical,clientAuth\nsubjectAltName=DNS:victim.example\n" > ext.cnf
;;;;   openssl x509 -req -in leaf.csr -CA security-regression-root-ca.pem \
;;;;     -CAkey root.key -CAcreateserial \
;;;;     -out security-regression-clientauth-leaf.pem -days 36500 -sha256 \
;;;;     -extfile ext.cnf
;;;; ---------------------------------------------------------------------------

(test clientauth-only-leaf-rejected-for-server-auth
  "A clientAuth-only leaf must not validate as a server certificate."
  ;; Force the pure-Lisp verification path (not the OS native verifiers).
  (let ((pure-tls:*use-windows-certificate-store* nil)
        (pure-tls:*use-macos-keychain* nil))
    (let* ((root (pure-tls:parse-certificate-from-file
                  (test-cert-path "security-regression-root-ca.pem")))
           (leaf (pure-tls:parse-certificate-from-file
                  (test-cert-path "security-regression-clientauth-leaf.pem"))))
      ;; Sanity: the fixture really is EKU clientAuth-only with a critical EKU
      ;; extension that the verifier currently treats as "known".
      (is (member :extended-key-usage
                  (pure-tls::certificate-critical-extensions leaf))
          "Fixture leaf should carry a critical ExtendedKeyUsage extension")
      ;; With :purpose :server-auth, a clientAuth-only leaf must be rejected.
      ;; (now and hostname are positional &optional args before the &key.)
      (signals pure-tls:tls-certificate-error
        (pure-tls::verify-certificate-chain (list leaf) (list root)
                                            (get-universal-time) nil
                                            :purpose :server-auth)))))

;;;; ---------------------------------------------------------------------------
;;;; Finding: resumption must carry forward the original handshake's
;;;; authentication (RFC 8446 Sections 2.2 and 4.2.11).
;;;;
;;;; On a first verify-required handshake the client verifies the certificate
;;;; chain and hostname, then caches a NewSessionTicket keyed by hostname.  A
;;;; later PSK resumption legitimately skips Certificate/CertificateVerify -- the
;;;; resumed session inherits the authentication of the handshake that minted the
;;;; ticket -- so demanding a fresh certificate breaks valid resumption.
;;;;
;;;; The fix records, on each ticket, the hostname the minting handshake
;;;; certificate-verified under verify-required, and accepts a certificate-less
;;;; resumed Finished ONLY when the accepted PSK's ticket proves verification of
;;;; the SAME host.  Otherwise it fails closed, exactly as before.
;;;;
;;;; These proofs drive a real pure-tls loopback (pure-tls server + pure-tls
;;;; client over 127.0.0.1) so the handshakes are genuine, and they keep the
;;;; process-global ticket cache WARM across connections (no per-connection
;;;; reset) so resumption exercises the real cache.
;;;;
;;;; Fixtures generated with (long-dated CA + leaf, SAN=resumption.test):
;;;;   openssl req -x509 -newkey rsa:2048 -nodes -keyout resumption-ca.key \
;;;;     -out resumption-ca.pem -subj "/CN=pure-tls Resumption Test CA" \
;;;;     -days 36500 -sha256 \
;;;;     -addext "basicConstraints=critical,CA:TRUE" \
;;;;     -addext "keyUsage=critical,keyCertSign,cRLSign"
;;;;   openssl req -newkey rsa:2048 -nodes -keyout resumption-leaf.key \
;;;;     -out resumption-leaf.csr -subj "/CN=resumption.test" -sha256
;;;;   printf "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:resumption.test\n" > ext.cnf
;;;;   openssl x509 -req -in resumption-leaf.csr -CA resumption-ca.pem \
;;;;     -CAkey resumption-ca.key -CAcreateserial \
;;;;     -out resumption-leaf.pem -days 36500 -sha256 -extfile ext.cnf
;;;; (resumption-ca.pem, resumption-leaf.pem, resumption-leaf.key live in
;;;; test/certs/; the transient CA key and CSR are not kept.)
;;;; ---------------------------------------------------------------------------

(defun %resumption-server-loop (port n-conns ready-flag ready-lock ready-cv server-info)
  "Accept N-CONNS sequential pure-tls connections on PORT using the resumption
   test leaf certificate.  Each accepted connection completes the handshake
   (which sends a NewSessionTicket), then a single app-data byte is pushed so
   the client's read loop consumes the post-handshake ticket, then the
   connection closes.  Each connection's server-side psk-accepted flag is pushed
   onto (car SERVER-INFO), newest first."
  (let ((listen-sock nil))
    (unwind-protect
         (handler-case
             (progn
               (setf listen-sock (usocket:socket-listen "127.0.0.1" port
                                                        :reuse-address t
                                                        :element-type '(unsigned-byte 8)))
               (bt:with-lock-held (ready-lock)
                 (setf (car ready-flag) t)
                 (bt:condition-notify ready-cv))
               (dotimes (i n-conns)
                 (let ((client-sock nil)
                       (tls nil))
                   (unwind-protect
                        (handler-case
                            (progn
                              (setf client-sock
                                    (usocket:socket-accept listen-sock
                                                           :element-type '(unsigned-byte 8)))
                              (setf tls (pure-tls:make-tls-server-stream
                                         (usocket:socket-stream client-sock)
                                         :certificate (test-cert-path "resumption-leaf.pem")
                                         :key (test-cert-path "resumption-leaf.key")))
                              (push (pure-tls::server-handshake-psk-accepted
                                     (pure-tls::tls-stream-handshake tls))
                                    (car server-info))
                              ;; App-data byte drives the client's fill-buffer so
                              ;; it consumes the post-handshake NewSessionTicket.
                              (write-byte 42 tls)
                              (force-output tls)
                              ;; Wait for the client's acknowledgement byte (or EOF
                              ;; if the client aborted, e.g. a fail-closed case).
                              (read-byte tls nil nil))
                          (error () nil))
                     (ignore-errors (when tls (close tls)))
                     (ignore-errors (when client-sock
                                      (usocket:socket-close client-sock)))))))
           (error () nil))
      (ignore-errors (when listen-sock (usocket:socket-close listen-sock))))))

(defun %spawn-resumption-server (port n-conns)
  "Spawn the resumption loopback server for N-CONNS connections on PORT.
   Blocks until the server is listening.  Returns (values thread server-info),
   where (car SERVER-INFO) accumulates each connection's server-side
   psk-accepted flag (newest first)."
  (let ((ready-lock (bt:make-lock "resumption-server-ready"))
        (ready-cv (bt:make-condition-variable :name "resumption-server-ready-cv"))
        (ready-flag (list nil))
        (server-info (list nil)))
    (let ((thread (bt:make-thread
                   (lambda ()
                     (%resumption-server-loop port n-conns ready-flag ready-lock
                                              ready-cv server-info))
                   :name "resumption-test-server")))
      (bt:with-lock-held (ready-lock)
        (loop until (car ready-flag)
              do (unless (bt:condition-wait ready-cv ready-lock :timeout 5)
                   (return))))
      ;; Small delay to ensure the listening socket is fully ready.
      (sleep 0.05)
      (values thread server-info))))

(defun %resumption-client (port hostname verify ca-file)
  "Open one pure-tls client connection to PORT for HOSTNAME under VERIFY,
   trusting only CA-FILE.  On a successful handshake, reads the app-data byte
   (consuming the server's NewSessionTicket into the process-global cache),
   sends an acknowledgement byte, and returns the client handshake object so
   callers can inspect psk-accepted / peer-certificate.  Handshake failures
   (e.g. a fail-closed resumption) propagate to the caller."
  (let ((sock nil)
        (tls nil))
    (unwind-protect
         (progn
           (setf sock (usocket:socket-connect "127.0.0.1" port
                                              :element-type '(unsigned-byte 8)))
           (let ((ctx (pure-tls:make-tls-context :verify-mode verify
                                                 :ca-file ca-file
                                                 :auto-load-system-ca nil)))
             (setf tls (pure-tls:make-tls-client-stream
                        (usocket:socket-stream sock)
                        :hostname hostname
                        :verify verify
                        :context ctx))
             (let ((hs (pure-tls::tls-stream-handshake tls)))
               ;; Consume the post-handshake NewSessionTicket, then acknowledge.
               (read-byte tls)
               (write-byte 43 tls)
               (force-output tls)
               hs)))
      (ignore-errors (when tls (close tls)))
      (ignore-errors (when sock (usocket:socket-close sock))))))

(test resumed-psk-carries-forward-verification
  "A verify-required full handshake mints a certificate-verified ticket; later
   connections to the same host resume via PSK (server skips its Certificate)
   and the client accepts them as authenticated -- with the real process-global
   ticket cache warm across all connections.  RFC 8446 Sections 2.2 / 4.2.11."
  (let ((pure-tls:*use-windows-certificate-store* nil)
        (pure-tls:*use-macos-keychain* nil)
        (port (allocate-test-port))
        (ca (test-cert-path "resumption-ca.pem"))
        (host "resumption.test"))
    ;; Start from a clean slate for this host; the cache then stays warm across
    ;; every connection below (never reset between handshakes).
    (pure-tls::session-ticket-cache-clear host)
    (multiple-value-bind (thread server-info)
        (%spawn-resumption-server port 3)
      (unwind-protect
           (let (hs1 hs2 hs3)
             ;; 1st: full handshake with real certificate verification.
             (setf hs1 (%resumption-client port host pure-tls:+verify-required+ ca))
             (is (not (pure-tls::client-handshake-psk-accepted hs1))
                 "First handshake must be a full (non-resumed) handshake")
             (is (pure-tls::client-handshake-peer-certificate hs1)
                 "First handshake must present a server certificate")
             ;; The ticket minted by connection 1 carries proven provenance.
             (let ((tk (pure-tls::session-ticket-cache-get host)))
               (is (and tk (equal (pure-tls::session-ticket-verified-hostname tk) host))
                   "Cached ticket must record the verified hostname"))
             ;; 2nd: resume via PSK; server skips Certificate; accepted as authenticated.
             (setf hs2 (%resumption-client port host pure-tls:+verify-required+ ca))
             (is (pure-tls::client-handshake-psk-accepted hs2)
                 "Second connection must resume via PSK, not full-handshake")
             (is (not (pure-tls::client-handshake-peer-certificate hs2))
                 "Resumed connection must receive no server certificate")
             ;; 3rd: carry-forward keeps repeated warm-cache resumptions working.
             (setf hs3 (%resumption-client port host pure-tls:+verify-required+ ca))
             (is (pure-tls::client-handshake-psk-accepted hs3)
                 "Third connection must also resume via PSK")
             (is (not (pure-tls::client-handshake-peer-certificate hs3))
                 "Third resumed connection must receive no server certificate")
             ;; Server side agrees: one full handshake, then two resumptions.
             (is (equal (reverse (car server-info)) '(nil t t))
                 "Server must full-handshake once then resume twice"))
        (pure-tls::session-ticket-cache-clear host)
        (ignore-errors (bt:join-thread thread))))))

(test resumption-nil-provenance-fails-closed
  "A ticket minted by a non-verified (+verify-none+) origin proves no
   authentication; offering it on a +verify-required+ resumption to that host
   must fail closed with a catchable tls-certificate-error."
  (let ((pure-tls:*use-windows-certificate-store* nil)
        (pure-tls:*use-macos-keychain* nil)
        (port (allocate-test-port))
        (ca (test-cert-path "resumption-ca.pem"))
        (host "resumption.test"))
    (pure-tls::session-ticket-cache-clear host)
    (multiple-value-bind (thread server-info)
        (%spawn-resumption-server port 2)
      (declare (ignore server-info))
      (unwind-protect
           (progn
             ;; 1st: full handshake under +verify-none+ -> NIL-provenance ticket.
             (%resumption-client port host pure-tls:+verify-none+ ca)
             (let ((tk (pure-tls::session-ticket-cache-get host)))
               (is (and tk (null (pure-tls::session-ticket-verified-hostname tk)))
                   "A verify-none origin must cache a NIL-provenance ticket"))
             ;; 2nd: resume under +verify-required+ -> must fail closed.
             (signals pure-tls:tls-certificate-error
               (%resumption-client port host pure-tls:+verify-required+ ca)))
        (pure-tls::session-ticket-cache-clear host)
        (ignore-errors (bt:join-thread thread))))))

(test resumption-cross-hostname-fails-closed
  "A ticket whose proven hostname differs from the host being connected to must
   fail closed on resumption, even though the server accepts the PSK -- exercising
   the hostname-equality guard on the resumed certificate-less Finished."
  (let ((pure-tls:*use-windows-certificate-store* nil)
        (pure-tls:*use-macos-keychain* nil)
        (port (allocate-test-port))
        (ca (test-cert-path "resumption-ca.pem"))
        (host "resumption.test"))
    (pure-tls::session-ticket-cache-clear host)
    (multiple-value-bind (thread server-info)
        (%spawn-resumption-server port 2)
      (declare (ignore server-info))
      (unwind-protect
           (progn
             ;; 1st: full verify-required handshake mints a ticket for HOST.
             (%resumption-client port host pure-tls:+verify-required+ ca)
             ;; Rewrite the cached ticket's proven hostname to a different host
             ;; while leaving it keyed under HOST, so the next resumption offers a
             ;; genuine PSK whose provenance is for the wrong identity.
             (let ((tk (pure-tls::session-ticket-cache-get host)))
               (is (and tk (equal (pure-tls::session-ticket-verified-hostname tk) host))
                   "Sanity: minted ticket is provenance-stamped for HOST")
               (setf (pure-tls::session-ticket-verified-hostname tk) "other-identity.test"))
             ;; 2nd: server resumes the PSK, but its provenance is cross-hostname.
             (signals pure-tls:tls-certificate-error
               (%resumption-client port host pure-tls:+verify-required+ ca)))
        (pure-tls::session-ticket-cache-clear host)
        (ignore-errors (bt:join-thread thread))))))

;;;; Test Runner

(defun run-security-regression-tests ()
  "Run the security regression suite.  Returns T if all tests pass."
  (format t "~&=== Running pure-tls Security Regression Tests ===~%~%")
  (run! 'security-regression-tests))
