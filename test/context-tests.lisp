;;; context-tests.lisp --- Tests for request context (timeout/cancellation)
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Anthony Green <green@moxielogic.com>

(in-package :pure-tls/test)

(def-suite context-tests
    :description "Request context timeout and cancellation tests")

(in-suite context-tests)

(test nil-context-handling
  "Test that NIL context works (backwards compatibility)"
  (finishes
    (pure-tls::check-tls-context nil)))

(test timeout-basic
  "Test basic timeout functionality with cl-context"
  (signals cl-context:context-deadline-exceeded
    (cl-context:with-timeout-context (ctx 0.1)
      (sleep 0.2)
      (cl-context:check-context ctx))))

(test cancellation-basic
  "Test basic cancellation functionality"
  (multiple-value-bind (ctx cancel-fn)
      (cl-context:with-cancel (cl-context:background))
    (funcall cancel-fn)
    (signals cl-context:context-cancelled
      (cl-context:check-context ctx))))

(test check-context-tls-error
  "Test that our check-context raises TLS-specific errors"
  (signals pure-tls:tls-deadline-exceeded
    (cl-context:with-timeout-context (ctx 0.1)
      (sleep 0.2)
      (pure-tls::check-tls-context ctx))))

(test check-context-cancellation
  "Test that cancellation raises tls-context-cancelled"
  (multiple-value-bind (ctx cancel-fn)
      (cl-context:with-cancel (cl-context:background))
    (funcall cancel-fn)
    (signals pure-tls:tls-context-cancelled
      (pure-tls::check-tls-context ctx))))

(test context-remaining-time
  "Test context-remaining-time helper"
  (cl-context:with-timeout-context (ctx 10)
    (let ((remaining (pure-tls::context-remaining-time ctx)))
      (is (and remaining (>= remaining 9) (<= remaining 10))))))

;; Note: Full integration tests (TLS handshake with timeout) require network access
;; and are in network-tests.lisp
