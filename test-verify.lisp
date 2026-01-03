(require :asdf)
(push #P"/home/green/git/pure-tls/" asdf:*central-registry*)
(dolist (dir (directory "/home/green/git/pure-tls/ocicl/*/"))
  (push dir asdf:*central-registry*))
(asdf:load-system :pure-tls)
(asdf:load-system :usocket)

(in-package :pure-tls)

(format t "~%=== Testing Certificate Verification ===~%")

;; Test 1: Correct hostname should pass
(format t "~%Test 1: Correct hostname (example.com)...~%")
(handler-case
    (let* ((socket (usocket:socket-connect "example.com" 443 :element-type '(unsigned-byte 8)))
           (stream (usocket:socket-stream socket))
           (tls (make-tls-client-stream stream :hostname "example.com" :verify +verify-peer+)))
      (format t "  PASS: Connection with correct hostname succeeded~%")
      (close tls))
  (error (e)
    (format t "  FAIL: Unexpected error: ~A~%" e)))

;; Test 2: Wrong hostname should fail
(format t "~%Test 2: Wrong hostname (wrong-hostname.com)...~%")
(handler-case
    (let* ((socket (usocket:socket-connect "example.com" 443 :element-type '(unsigned-byte 8)))
           (stream (usocket:socket-stream socket))
           (tls (make-tls-client-stream stream :hostname "wrong-hostname.com" :verify +verify-peer+)))
      (format t "  FAIL: Should have rejected wrong hostname!~%")
      (close tls))
  (tls-verification-error (e)
    (format t "  PASS: Correctly rejected wrong hostname: ~A~%" (tls-error-message e)))
  (error (e)
    (format t "  NOTE: Got different error type (~A): ~A~%" (type-of e) e)))

;; Test 3: Direct hostname matching logic
(format t "~%Test 3: Direct hostname matching logic...~%")
(let ((test-cases '(("example.com" "example.com" t)
                    ("example.com" "other.com" nil)
                    ("*.example.com" "www.example.com" t)
                    ("*.example.com" "example.com" nil)
                    ("*.example.com" "sub.sub.example.com" nil))))
  (loop for (pattern hostname expected) in test-cases
        for result = (hostname-matches-p pattern hostname)
        do (format t "  ~A matches ~A: ~A (~A)~%"
                   pattern hostname
                   (if result "yes" "no")
                   (if (eq result expected) "PASS" "FAIL"))))

(format t "~%=== Verification Tests Complete ===~%")
(sb-ext:exit :code 0)
