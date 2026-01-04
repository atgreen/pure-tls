;;; openssl-tests.lisp --- OpenSSL test suite adaptation for pure-tls
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Anthony Green <green@moxielogic.com>
;;;
;;; This file implements a framework for running OpenSSL's ssl-tests
;;; against pure-tls. It parses the .cnf test configuration files and
;;; executes the tests using pure-tls client/server.

(in-package #:pure-tls/test)

;;;; INI File Parser using iparse
;;;
;;; OpenSSL .cnf files use an INI-style format:
;;;   # comment
;;;   key = value
;;;   [section-name]
;;;   key = value

(iparse:defparser ini-parser "
  file = <ws> (entry <ws>)*
  entry = section | assignment | <comment>
  <ws> = #'[ \\t\\n\\r]*'
  <line-ws> = #'[ \\t]*'
  comment = <'#'> #'[^\\n]*'
  section = <'['> section-name <']'>
  section-name = #'[^\\]\\n]+'
  assignment = key <line-ws> <'='> <line-ws> value
  key = #'[A-Za-z_][A-Za-z0-9_-]*'
  value = #'[^\\n]*'
")

(defun parse-ini-file (pathname)
  "Parse an INI-style configuration file, returning an alist of sections.
   Each section is (section-name . ((key . value) ...))."
  (let ((content (alexandria:read-file-into-string pathname)))
    (multiple-value-bind (tree success-p)
        (ini-parser content)
      (unless success-p
        (error "Failed to parse INI file: ~A" pathname))
      (ini-tree-to-alist tree))))

(defun ini-tree-to-alist (tree)
  "Convert iparse tree to alist of sections."
  (let ((sections (make-hash-table :test 'equal))
        (current-section ""))  ; empty string for header section
    ;; Initialize the header section
    (setf (gethash "" sections) nil)
    ;; Process each entry in the file
    (dolist (entry (cdr tree))  ; skip :FILE tag
      ;; Each entry is (:ENTRY (:SECTION ...) or (:ENTRY (:ASSIGNMENT ...))
      (let ((inner (second entry)))  ; unwrap :ENTRY
        (case (first inner)
          (:SECTION
           (setf current-section (second (second inner)))  ; get section name
           (unless (gethash current-section sections)
             (setf (gethash current-section sections) nil)))
          (:ASSIGNMENT
           (let ((key (second (second inner)))      ; :KEY -> string
                 (value (second (third inner))))    ; :VALUE -> string
             (push (cons key (string-trim " " value))
                   (gethash current-section sections)))))))
    ;; Convert hash-table to alist, reversing each section's pairs
    (let ((result nil))
      (maphash (lambda (k v)
                 (push (cons k (nreverse v)) result))
               sections)
      result)))

(defun get-section (sections name)
  "Get a section by name from parsed INI alist."
  (cdr (assoc name sections :test #'string=)))

(defun get-value (section key &optional default)
  "Get a value from a section alist."
  (let ((pair (assoc key section :test #'string=)))
    (if pair (cdr pair) default)))

;;;; Test Configuration Extraction
;;;
;;; OpenSSL test configs have a specific structure:
;;;   num_tests = N
;;;   test-0 = test-name
;;;   [test-name]
;;;   ssl_conf = ssl-conf-section
;;;   [ssl-conf-section]
;;;   server = server-section
;;;   client = client-section
;;;   [server-section]
;;;   Certificate = ...
;;;   [client-section]
;;;   VerifyMode = ...
;;;   [test-0]
;;;   ExpectedResult = Success

(defstruct openssl-test
  "Represents a single OpenSSL test case."
  (name "" :type string)
  (category :pass :type keyword)  ; :pass, :skip, :xfail, :interop
  (skip-reason nil :type (or null string))
  ;; Server configuration
  (server-certificate nil :type (or null string))
  (server-private-key nil :type (or null string))
  (server-verify-mode nil :type (or null string))
  (server-verify-ca-file nil :type (or null string))
  (server-min-protocol nil :type (or null string))
  (server-max-protocol nil :type (or null string))
  (server-alpn-protocols nil :type list)  ; List of ALPN protocols, :none for empty config
  ;; Client configuration
  (client-certificate nil :type (or null string))
  (client-private-key nil :type (or null string))
  (client-verify-mode nil :type (or null string))
  (client-verify-ca-file nil :type (or null string))
  (client-min-protocol nil :type (or null string))
  (client-max-protocol nil :type (or null string))
  (client-alpn-protocols nil :type list)  ; List of ALPN protocols
  ;; Expected results
  (expected-result nil :type (or null string))
  (expected-client-alert nil :type (or null string))
  (expected-server-alert nil :type (or null string)))

(defparameter *openssl-certs-dir*
  (namestring (merge-pathnames "test/certs/openssl/" (asdf:system-source-directory :pure-tls)))
  "Directory containing OpenSSL test certificates.")

(defun resolve-cert-path (path-template)
  "Resolve ${ENV::TEST_CERTS_DIR}/file.pem to actual path."
  (when path-template
    ;; Strip trailing slash from certs-dir to avoid double slashes
    (let* ((certs-dir (string-right-trim "/" (namestring *openssl-certs-dir*)))
           (resolved (cl-ppcre:regex-replace-all
                      "\\$\\{ENV::TEST_CERTS_DIR\\}"
                      path-template
                      certs-dir)))
      resolved)))

(defun parse-alpn-protocols (alpn-string)
  "Parse comma-separated ALPN protocols string.
   Returns a list of protocol strings, or :none if explicitly empty."
  (cond
    ((null alpn-string) nil)              ; Not configured
    ((string= alpn-string "") '(:none))   ; Explicitly empty
    (t (mapcar (lambda (s) (string-trim " " s))
               (cl-ppcre:split "," alpn-string)))))

(defun extract-test (sections test-index)
  "Extract a single test case from parsed sections."
  (let* ((test-key (format nil "test-~D" test-index))
         (header (get-section sections ""))  ; top-level section
         (test-name (get-value header test-key)))
    (when test-name
      (let* ((test-section (get-section sections test-name))
             (ssl-conf-name (get-value test-section "ssl_conf"))
             (ssl-conf (when ssl-conf-name
                         (get-section sections ssl-conf-name)))
             (server-section-name (when ssl-conf
                                    (get-value ssl-conf "server")))
             (client-section-name (when ssl-conf
                                    (get-value ssl-conf "client")))
             (server-section (when server-section-name
                               (get-section sections server-section-name)))
             (client-section (when client-section-name
                               (get-section sections client-section-name)))
             (result-section (get-section sections test-key))
             ;; Extra sections for ALPN, etc. (referenced from result-section)
             (server-extra-name (get-value result-section "server"))
             (client-extra-name (get-value result-section "client"))
             (server-extra (when server-extra-name
                             (get-section sections server-extra-name)))
             (client-extra (when client-extra-name
                             (get-section sections client-extra-name))))
        (make-openssl-test
         :name test-name
         :category (categorize-test server-section client-section result-section)
         :skip-reason (get-skip-reason server-section client-section result-section)
         ;; Server config
         :server-certificate (resolve-cert-path
                              (get-value server-section "Certificate"))
         :server-private-key (resolve-cert-path
                              (get-value server-section "PrivateKey"))
         :server-verify-mode (get-value server-section "VerifyMode")
         :server-verify-ca-file (resolve-cert-path
                                 (get-value server-section "VerifyCAFile"))
         :server-min-protocol (get-value server-section "MinProtocol")
         :server-max-protocol (get-value server-section "MaxProtocol")
         :server-alpn-protocols (parse-alpn-protocols
                                 (get-value server-extra "ALPNProtocols"))
         ;; Client config
         :client-certificate (resolve-cert-path
                              (get-value client-section "Certificate"))
         :client-private-key (resolve-cert-path
                              (get-value client-section "PrivateKey"))
         :client-verify-mode (get-value client-section "VerifyMode")
         :client-verify-ca-file (resolve-cert-path
                                 (get-value client-section "VerifyCAFile"))
         :client-min-protocol (get-value client-section "MinProtocol")
         :client-max-protocol (get-value client-section "MaxProtocol")
         :client-alpn-protocols (parse-alpn-protocols
                                 (get-value client-extra "ALPNProtocols"))
         ;; Expected results
         :expected-result (get-value result-section "ExpectedResult")
         :expected-client-alert (get-value result-section "ExpectedClientAlert")
         :expected-server-alert (get-value result-section "ExpectedServerAlert"))))))

(defun categorize-test (server-section client-section result-section)
  "Categorize a test as :pass, :skip, :xfail, or :interop."
  (let ((server-min (get-value server-section "MinProtocol"))
        (server-max (get-value server-section "MaxProtocol"))
        (client-min (get-value client-section "MinProtocol"))
        (client-max (get-value client-section "MaxProtocol"))
        (client-cert (get-value client-section "Certificate"))
        (server-verify (get-value server-section "VerifyMode"))
        (handshake-mode (get-value result-section "HandshakeMode")))
    (cond
      ;; Skip tests that require session resumption
      ((and handshake-mode (string-equal handshake-mode "Resume"))
       :skip)
      ;; Skip tests that require protocol versions other than TLS 1.3
      ((and server-max (not (string= server-max "TLSv1.3")))
       :skip)
      ((and client-max (not (string= client-max "TLSv1.3")))
       :skip)
      ;; Skip tests that require protocol version negotiation
      ((and server-min server-max (not (string= server-min server-max)))
       :skip)
      ((and client-min client-max (not (string= client-min client-max)))
       :skip)
      ;; Skip tests that require client certificates (mTLS not yet implemented)
      ((and client-cert (not (string= client-cert "")))
       :skip)
      ;; Skip tests where server requires client certificate
      ((and server-verify (or (string-equal server-verify "Require")
                              (string-equal server-verify "RequirePostHandshake")))
       :skip)
      ;; Default to pass
      (t :pass))))

(defun get-skip-reason (server-section client-section result-section)
  "Get the reason for skipping a test, if applicable."
  (let ((server-min (get-value server-section "MinProtocol"))
        (server-max (get-value server-section "MaxProtocol"))
        (client-min (get-value client-section "MinProtocol"))
        (client-max (get-value client-section "MaxProtocol"))
        (client-cert (get-value client-section "Certificate"))
        (server-verify (get-value server-section "VerifyMode"))
        (handshake-mode (get-value result-section "HandshakeMode")))
    (cond
      ((and handshake-mode (string-equal handshake-mode "Resume"))
       "Requires session resumption (not yet implemented in test framework)")
      ((and server-max (not (string= server-max "TLSv1.3")))
       (format nil "Requires ~A (pure-tls is TLS 1.3 only)" server-max))
      ((and client-max (not (string= client-max "TLSv1.3")))
       (format nil "Requires ~A (pure-tls is TLS 1.3 only)" client-max))
      ((and server-min server-max (not (string= server-min server-max)))
       "Requires protocol version negotiation")
      ((and client-min client-max (not (string= client-min client-max)))
       "Requires protocol version negotiation")
      ((and client-cert (not (string= client-cert "")))
       "Requires client certificate (mTLS not yet implemented)")
      ((and server-verify (or (string-equal server-verify "Require")
                              (string-equal server-verify "RequirePostHandshake")))
       "Requires client certificate (mTLS not yet implemented)")
      (t nil))))

(defun load-openssl-tests (cnf-file)
  "Load all tests from an OpenSSL .cnf file."
  (let* ((sections (parse-ini-file cnf-file))
         (header (get-section sections ""))
         (num-tests-str (get-value header "num_tests" "0"))
         (num-tests (parse-integer num-tests-str :junk-allowed t)))
    (loop for i from 0 below (or num-tests 0)
          for test = (extract-test sections i)
          when test collect test)))

;;;; Test Execution Framework

(defvar *test-port-counter* 19000
  "Counter for allocating test ports.")

(defun allocate-test-port ()
  "Allocate a unique port for testing."
  (incf *test-port-counter*))

(defun openssl-verify-mode-to-pure-tls (mode-string)
  "Convert OpenSSL VerifyMode string to pure-tls constant."
  (cond
    ((null mode-string) pure-tls:+verify-none+)
    ((string-equal mode-string "None") pure-tls:+verify-none+)
    ((string-equal mode-string "Peer") pure-tls:+verify-peer+)
    ((string-equal mode-string "Request") pure-tls:+verify-peer+)
    ((string-equal mode-string "Require") pure-tls:+verify-required+)
    ((string-equal mode-string "RequestPostHandshake") pure-tls:+verify-peer+)
    ((string-equal mode-string "RequirePostHandshake") pure-tls:+verify-required+)
    (t pure-tls:+verify-none+)))

(defun run-tls-server (port cert-file key-file verify-mode ca-file alpn-protocols
                       result-box error-box ready-lock ready-cv)
  "Run a TLS server on PORT. Stores result in RESULT-BOX.
   ALPN-PROTOCOLS is a list of protocol strings, or (:none) for empty list."
  (let ((server-socket nil)
        (client-socket nil))
    (unwind-protect
        (handler-case
            (progn
              ;; Create server socket
              (setf server-socket (usocket:socket-listen "127.0.0.1" port
                                                          :reuse-address t
                                                          :element-type '(unsigned-byte 8)))
              ;; Signal that we're ready
              (bt:with-lock-held (ready-lock)
                (bt:condition-notify ready-cv))
              ;; Accept one connection
              (setf client-socket (usocket:socket-accept server-socket
                                                          :element-type '(unsigned-byte 8)))
              ;; Create TLS context for client cert verification
              ;; alpn-protocols can be:
              ;;   nil - not configured (server ignores ALPN)
              ;;   (:none) - explicitly empty (server rejects any client ALPN)
              ;;   list of strings - supported protocols
              (let* ((context (pure-tls:make-tls-context
                               :verify-mode verify-mode
                               :ca-file ca-file
                               :alpn-protocols alpn-protocols
                               :auto-load-system-ca nil))
                     (tls-stream (pure-tls:make-tls-server-stream
                                  (usocket:socket-stream client-socket)
                                  :certificate cert-file
                                  :key key-file
                                  :verify verify-mode
                                  :alpn-protocols alpn-protocols
                                  :context context)))
                ;; Handshake succeeded
                (close tls-stream)
                (setf (car result-box) :success)))
          (pure-tls:tls-alert-error (e)
            (setf (car result-box) :alert)
            (setf (car error-box) (pure-tls::tls-alert-error-description e)))
          (pure-tls:tls-certificate-error (e)
            (setf (car result-box) :cert-error)
            (setf (car error-box) (princ-to-string e)))
          (pure-tls:tls-error (e)
            (setf (car result-box) :tls-error)
            (setf (car error-box) (princ-to-string e)))
          (error (e)
            (setf (car result-box) :error)
            (setf (car error-box) (format nil "~A: ~A" (type-of e) e))))
      ;; Cleanup
      (when client-socket (ignore-errors (usocket:socket-close client-socket)))
      (when server-socket (ignore-errors (usocket:socket-close server-socket))))))

(defun run-tls-client (port cert-file key-file verify-mode ca-file alpn-protocols)
  "Run a TLS client connecting to PORT. Returns (values result error-info).
   ALPN-PROTOCOLS is a list of protocol strings to offer."
  (let ((socket nil))
    (unwind-protect
        (handler-case
            (progn
              (setf socket (usocket:socket-connect "127.0.0.1" port
                                                    :element-type '(unsigned-byte 8)))
              ;; Filter out :none marker - client should only send real protocols
              (let* ((alpn-list (when (and alpn-protocols
                                           (not (equal alpn-protocols '(:none))))
                                  alpn-protocols))
                     (context (pure-tls:make-tls-context
                               :verify-mode verify-mode
                               :ca-file ca-file
                               :alpn-protocols alpn-list
                               :auto-load-system-ca nil))
                     ;; Use server.example as hostname since that's what the test certs use
                     ;; Disable hostname verification since we're connecting to localhost
                     (tls-stream (if cert-file
                                     ;; Client with certificate (mTLS)
                                     (pure-tls:make-tls-client-stream
                                      (usocket:socket-stream socket)
                                      :hostname nil  ; Skip hostname verification
                                      :verify verify-mode
                                      :context context
                                      :certificate cert-file
                                      :key key-file
                                      :alpn-protocols alpn-list)
                                     ;; Client without certificate
                                     (pure-tls:make-tls-client-stream
                                      (usocket:socket-stream socket)
                                      :hostname nil  ; Skip hostname verification
                                      :verify verify-mode
                                      :context context
                                      :alpn-protocols alpn-list))))
                (close tls-stream)
                (values :success nil)))
          (pure-tls:tls-alert-error (e)
            (values :alert (pure-tls::tls-alert-error-description e)))
          (pure-tls:tls-certificate-error (e)
            (values :cert-error (princ-to-string e)))
          (pure-tls:tls-error (e)
            (values :tls-error (princ-to-string e)))
          (usocket:connection-refused-error ()
            (values :connection-refused nil))
          (error (e)
            (values :error (format nil "~A: ~A" (type-of e) e))))
      (when socket (ignore-errors (usocket:socket-close socket))))))

(defun execute-openssl-test (test)
  "Execute an OpenSSL test case. Returns (values result-keyword message)."
  (let* ((port (allocate-test-port))
         (server-result (list nil))
         (server-error (list nil))
         (ready-lock (bt:make-lock "server-ready"))
         (ready-cv (bt:make-condition-variable :name "server-ready-cv"))
         ;; Server config
         (server-cert (openssl-test-server-certificate test))
         (server-key (openssl-test-server-private-key test))
         (server-verify (openssl-verify-mode-to-pure-tls
                         (openssl-test-server-verify-mode test)))
         (server-ca (openssl-test-server-verify-ca-file test))
         (server-alpn (openssl-test-server-alpn-protocols test))
         ;; Client config
         (client-cert (openssl-test-client-certificate test))
         (client-key (openssl-test-client-private-key test))
         (client-verify (openssl-verify-mode-to-pure-tls
                         (openssl-test-client-verify-mode test)))
         (client-ca (openssl-test-client-verify-ca-file test))
         (client-alpn (openssl-test-client-alpn-protocols test)))
    ;; Start server in background thread
    (bt:make-thread
     (lambda ()
       (run-tls-server port server-cert server-key server-verify server-ca server-alpn
                       server-result server-error ready-lock ready-cv))
     :name "openssl-test-server")
    ;; Wait for server to be ready
    (bt:with-lock-held (ready-lock)
      (bt:condition-wait ready-cv ready-lock :timeout 5))
    ;; Small delay to ensure server is listening
    (sleep 0.1)
    ;; Run client
    (multiple-value-bind (client-result client-error)
        (run-tls-client port client-cert client-key client-verify client-ca client-alpn)
      ;; Wait for server to finish
      (sleep 0.2)
      ;; Determine overall result
      ;; Note: nil or missing ExpectedResult means success is expected
      (let ((expected (or (openssl-test-expected-result test) "Success")))
        (cond
          ;; Expected success
          ((string-equal expected "Success")
           (if (and (eq client-result :success)
                    (eq (car server-result) :success))
               (values :pass "Handshake succeeded as expected")
               (values :fail (format nil "Expected success but got client=~A(~A) server=~A(~A)"
                                     client-result client-error
                                     (car server-result) (car server-error)))))
          ;; Expected client failure
          ((string-equal expected "ClientFail")
           (if (member client-result '(:alert :cert-error :tls-error :error))
               (values :pass (format nil "Client failed as expected: ~A" client-result))
               (values :fail (format nil "Expected ClientFail but client got ~A" client-result))))
          ;; Expected server failure
          ((string-equal expected "ServerFail")
           (if (member (car server-result) '(:alert :cert-error :tls-error :error))
               (values :pass (format nil "Server failed as expected: ~A" (car server-result)))
               (values :fail (format nil "Expected ServerFail but server got ~A" (car server-result)))))
          ;; Unknown expected result
          (t
           (values :skip (format nil "Unknown expected result: ~A" expected))))))))

(defun run-openssl-test (test)
  "Run a single OpenSSL test case. Returns (values result-keyword message)."
  (when (eq (openssl-test-category test) :skip)
    (return-from run-openssl-test
      (values :skipped (openssl-test-skip-reason test))))
  ;; Check we have required files
  (unless (and (openssl-test-server-certificate test)
               (openssl-test-server-private-key test))
    (return-from run-openssl-test
      (values :skip "Missing server certificate or key")))
  ;; Execute the test
  (execute-openssl-test test))

;;;; FiveAM Integration

(def-suite openssl-tests
  :description "OpenSSL test suite adaptation")

(in-suite openssl-tests)

(test ini-parser-basic
  "Test that the INI parser works on basic input."
  (let ((result (ini-parser "
# Comment
[section1]
key1 = value1
key2 = value2

[section2]
foo = bar
")))
    (is (not (null result)))
    (is (eq (first result) :file))))

(test ini-parser-openssl-format
  "Test parsing OpenSSL-style config format."
  (let ((result (ini-parser "
num_tests = 1
test-0 = 0-default

[0-default]
ssl_conf = 0-default-ssl

[0-default-ssl]
server = 0-default-server
client = 0-default-client

[0-default-server]
Certificate = ${ENV::TEST_CERTS_DIR}/servercert.pem
PrivateKey = ${ENV::TEST_CERTS_DIR}/serverkey.pem

[0-default-client]
VerifyCAFile = ${ENV::TEST_CERTS_DIR}/rootcert.pem
VerifyMode = Peer

[test-0]
ExpectedResult = Success
")))
    (is (not (null result)))))

;;; Test loading actual OpenSSL config files
(defparameter *openssl-ssl-tests-dir*
  (merge-pathnames "test/ssl-tests/" (asdf:system-source-directory :pure-tls))
  "Directory containing OpenSSL ssl-tests .cnf files.")

(test openssl-test-loading
  "Test that we can load and parse OpenSSL test configs."
  (is (functionp #'load-openssl-tests))
  (is (functionp #'run-openssl-test)))

(test load-01-simple-cnf
  "Test loading and parsing 01-simple.cnf."
  (let* ((cnf-file (merge-pathnames "01-simple.cnf" *openssl-ssl-tests-dir*))
         (tests (load-openssl-tests cnf-file)))
    ;; Should have 4 tests
    (is (= 4 (length tests)))
    ;; First test should be "0-default"
    (let ((first-test (first tests)))
      (is (string= "0-default" (openssl-test-name first-test)))
      (is (string= "Success" (openssl-test-expected-result first-test)))
      ;; Should have server certificate configured
      (is (not (null (openssl-test-server-certificate first-test))))
      (is (not (null (openssl-test-server-private-key first-test)))))))

(test load-26-tls13-client-auth-cnf
  "Test loading and parsing 26-tls13_client_auth.cnf."
  (let* ((cnf-file (merge-pathnames "26-tls13_client_auth.cnf" *openssl-ssl-tests-dir*))
         (tests (load-openssl-tests cnf-file)))
    ;; Should have 14 tests
    (is (= 14 (length tests)))
    ;; First test should be TLS 1.3 server auth
    (let ((first-test (first tests)))
      (is (string= "0-server-auth-TLSv1.3" (openssl-test-name first-test)))
      (is (string= "TLSv1.3" (openssl-test-server-min-protocol first-test)))
      (is (string= "TLSv1.3" (openssl-test-server-max-protocol first-test)))
      ;; Should be categorized as :pass since it's TLS 1.3 only
      (is (eq :pass (openssl-test-category first-test))))))

;;;; Live Execution Tests

(defun run-all-tests-from-file (cnf-filename)
  "Run all tests from a CNF file, returning (values pass-count fail-count skip-count failed-names)."
  (let* ((cnf-file (merge-pathnames cnf-filename *openssl-ssl-tests-dir*))
         (tests (load-openssl-tests cnf-file))
         (pass 0) (fail 0) (skip 0)
         (failed-names nil))
    (dolist (test tests)
      (let ((category (openssl-test-category test)))
        (if (eq category :skip)
            (incf skip)
            (multiple-value-bind (result message)
                (run-openssl-test test)
              (declare (ignore message))
              (case result
                (:pass (incf pass))
                ((:fail :error)
                 (incf fail)
                 (push (openssl-test-name test) failed-names))
                (t (incf skip)))))))
    (values pass fail skip (nreverse failed-names))))

(test execute-0-default
  "Execute the 0-default test (basic TLS 1.3 handshake)."
  (let* ((cnf-file (merge-pathnames "01-simple.cnf" *openssl-ssl-tests-dir*))
         (tests (load-openssl-tests cnf-file))
         (test-0 (find "0-default" tests :key #'openssl-test-name :test #'string=)))
    (is (not (null test-0)))
    (multiple-value-bind (result message)
        (run-openssl-test test-0)
      (format t "~&Test 0-default: ~A - ~A~%" result message)
      (is (eq :pass result)))))

(test execute-01-simple-all
  "Execute all tests from 01-simple.cnf (basic TLS 1.3 tests)."
  (multiple-value-bind (pass fail skip failed)
      (run-all-tests-from-file "01-simple.cnf")
    (declare (ignore skip))
    (format t "~&01-simple.cnf: ~D pass, ~D fail~%" pass fail)
    (when failed
      (format t "  Failed: ~{~A~^, ~}~%" failed))
    ;; All 4 tests should pass
    (is (= 4 pass))
    (is (= 0 fail))))

(test execute-21-key-update-all
  "Execute all tests from 21-key-update.cnf (TLS 1.3 key update tests)."
  (multiple-value-bind (pass fail skip failed)
      (run-all-tests-from-file "21-key-update.cnf")
    (declare (ignore skip))
    (format t "~&21-key-update.cnf: ~D pass, ~D fail~%" pass fail)
    (when failed
      (format t "  Failed: ~{~A~^, ~}~%" failed))
    ;; All 4 tests should pass
    (is (= 4 pass))
    (is (= 0 fail))))

(test execute-09-alpn-all
  "Execute all tests from 09-alpn.cnf (ALPN negotiation tests)."
  (multiple-value-bind (pass fail skip failed)
      (run-all-tests-from-file "09-alpn.cnf")
    (declare (ignore skip))
    (format t "~&09-alpn.cnf: ~D pass, ~D fail~%" pass fail)
    (when failed
      (format t "  Failed: ~{~A~^, ~}~%" failed))
    (is (= 0 fail) "All ALPN tests should pass")))

(test execute-14-curves-all
  "Execute all tests from 14-curves.cnf (elliptic curve tests)."
  (multiple-value-bind (pass fail skip failed)
      (run-all-tests-from-file "14-curves.cnf")
    (declare (ignore skip))
    (format t "~&14-curves.cnf: ~D pass, ~D fail~%" pass fail)
    (when failed
      (format t "  Failed: ~{~A~^, ~}~%" failed))
    (is (= 0 fail) "All curves tests should pass")))
