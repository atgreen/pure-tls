;;; cert-manager.lisp --- Certificate manager with auto-renewal
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Anthony Green <green@moxielogic.com>
;;;
;;; High-level certificate management with automatic renewal.

(in-package #:pure-tls/acme)

;;; ----------------------------------------------------------------------------
;;; Conditions
;;; ----------------------------------------------------------------------------

(define-condition acme-error (error)
  ((message :initarg :message :reader acme-error-message))
  (:report (lambda (c s)
             (format s "ACME error: ~A" (acme-error-message c)))))

(define-condition acme-challenge-error (acme-error)
  ()
  (:report (lambda (c s)
             (format s "ACME challenge error: ~A" (acme-error-message c)))))

(define-condition acme-order-error (acme-error)
  ()
  (:report (lambda (c s)
             (format s "ACME order error: ~A" (acme-error-message c)))))

(define-condition acme-certificate-error (acme-error)
  ()
  (:report (lambda (c s)
             (format s "ACME certificate error: ~A" (acme-error-message c)))))

;;; ----------------------------------------------------------------------------
;;; Certificate Manager
;;; ----------------------------------------------------------------------------

(defstruct (cert-manager (:constructor %make-cert-manager))
  "Certificate manager for automatic acquisition and renewal."
  (domain nil :type (or null string))
  (email nil :type (or null string))
  (port 443 :type integer)
  (check-interval-hours 24 :type integer)
  (renewal-days 30 :type integer)
  (running nil :type boolean)
  (thread nil))

(defun make-cert-manager (&key domain email
                               (port 443)
                               (check-interval-hours 24)
                               (renewal-days 30))
  "Create a certificate manager for the given domain.

   DOMAIN is the domain name for the certificate.
   EMAIL is the contact email for ACME registration.
   PORT is the port for TLS-ALPN-01 validation (default 443).
   CHECK-INTERVAL-HOURS is how often to check for renewal (default 24).
   RENEWAL-DAYS is how many days before expiry to renew (default 30)."
  (%make-cert-manager :domain domain
                      :email email
                      :port port
                      :check-interval-hours check-interval-hours
                      :renewal-days renewal-days))

(defun cert-manager-certificate (manager)
  "Get the current certificate path for the manager's domain."
  (cert-path (cert-manager-domain manager)))

(defun cert-manager-private-key (manager)
  "Get the current private key path for the manager's domain."
  (key-path (cert-manager-domain manager)))

(defun cert-manager-start (manager)
  "Start the certificate manager.

   On first start, obtains a certificate if one doesn't exist.
   Then starts a background thread to check for renewal periodically."
  (let ((domain (cert-manager-domain manager))
        (email (cert-manager-email manager))
        (port (cert-manager-port manager)))
    (unless domain
      (error 'acme-error :message "Domain not specified"))
    (unless email
      (error 'acme-error :message "Email not specified"))

    ;; Check if we need to obtain certificates
    (unless (certificates-exist-p domain)
      (obtain-certificate domain email :port port))

    ;; Start renewal thread
    (setf (cert-manager-running manager) t)
    (setf (cert-manager-thread manager)
          (bt:make-thread
           (lambda ()
             (cert-manager-renewal-loop manager))
           :name (format nil "cert-manager-~A" domain)))

    manager))

(defun cert-manager-stop (manager)
  "Stop the certificate manager's renewal thread."
  (setf (cert-manager-running manager) nil)
  (when (cert-manager-thread manager)
    ;; Thread will exit on next check
    (setf (cert-manager-thread manager) nil))
  manager)

(defun cert-manager-renewal-loop (manager)
  "Background loop that checks for certificate renewal."
  (let ((domain (cert-manager-domain manager))
        (email (cert-manager-email manager))
        (port (cert-manager-port manager))
        (interval-seconds (* (cert-manager-check-interval-hours manager) 3600)))
    (loop while (cert-manager-running manager)
          do (sleep interval-seconds)
             (when (cert-manager-running manager)
               (handler-case
                   (when (certificate-expires-soon-p
                          (cert-path domain)
                          (cert-manager-renewal-days manager))
                     (obtain-certificate domain email :port port))
                 (error (e)
                   ;; Log error but continue - will retry next interval
                   (declare (ignore e))))))))

;;; ----------------------------------------------------------------------------
;;; Convenience functions
;;; ----------------------------------------------------------------------------

(defun ensure-certificate (domain email &key (port 443) (renewal-days 30))
  "Ensure a valid certificate exists for domain.

   If no certificate exists, obtains one.
   If certificate exists but expires within RENEWAL-DAYS, renews it.
   PORT is the port for TLS-ALPN-01 validation (default 443).
   Returns T on success."
  (if (and (certificates-exist-p domain)
           (not (certificate-expires-soon-p (cert-path domain) renewal-days)))
      ;; Certificate exists and is valid
      t
      ;; Need to obtain/renew certificate
      (obtain-certificate domain email :port port)))

;;; ----------------------------------------------------------------------------
;;; TLS Server Convenience Functions
;;; ----------------------------------------------------------------------------

(defmacro with-auto-tls-server ((tls-stream-var client-stream
                                 &key domain email (port 443))
                                &body body)
  "Wrap a client connection in TLS, automatically obtaining certificates if needed.

   TLS-STREAM-VAR is bound to the TLS stream for use in BODY.
   CLIENT-STREAM is the raw TCP stream from the client.
   DOMAIN is the domain name for the certificate.
   EMAIL is the contact email for ACME registration.
   PORT is used for TLS-ALPN-01 validation if certificates need to be obtained.

   Example:
     (let ((client (usocket:socket-accept listener)))
       (with-auto-tls-server (tls (usocket:socket-stream client)
                                  :domain \"example.com\"
                                  :email \"admin@example.com\")
         (write-line \"Hello!\" tls)
         (force-output tls)))"
  (let ((domain-var (gensym "DOMAIN"))
        (email-var (gensym "EMAIL"))
        (port-var (gensym "PORT")))
    `(let ((,domain-var ,domain)
           (,email-var ,email)
           (,port-var ,port))
       (ensure-certificate ,domain-var ,email-var :port ,port-var)
       (pure-tls:with-tls-server-stream
           (,tls-stream-var ,client-stream
                            :certificate (namestring (cert-path ,domain-var))
                            :key (namestring (key-path ,domain-var)))
         ,@body))))

(defun make-auto-tls-acceptor (domain email &key (port 443) (listen-address "0.0.0.0"))
  "Create a TLS server socket with automatic certificate management.

   Returns (VALUES listen-socket cert-manager) where:
   - LISTEN-SOCKET is a usocket listener ready to accept connections
   - CERT-MANAGER handles automatic certificate renewal

   Example:
     (multiple-value-bind (listener mgr)
         (make-auto-tls-acceptor \"example.com\" \"admin@example.com\")
       (unwind-protect
           (loop for client = (usocket:socket-accept listener)
                 do (handle-client client
                                   (cert-manager-certificate mgr)
                                   (cert-manager-private-key mgr)))
         (cert-manager-stop mgr)
         (usocket:socket-close listener)))"
  ;; Create and start the certificate manager
  (let ((mgr (make-cert-manager :domain domain
                                :email email
                                :port port)))
    (cert-manager-start mgr)

    ;; Create the listening socket
    (let ((listen-socket (usocket:socket-listen listen-address port
                                                :reuse-address t
                                                :element-type '(unsigned-byte 8)
                                                :backlog 128)))
      (values listen-socket mgr))))
