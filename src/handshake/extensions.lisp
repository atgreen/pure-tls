;;; extensions.lisp --- TLS 1.3 Extensions
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Anthony Green <green@moxielogic.com>
;;;
;;; Implements TLS 1.3 extension parsing and serialization.

(in-package #:cl-tls)

;;;; Extension Structure
;;;
;;; struct {
;;;   ExtensionType extension_type;
;;;   opaque extension_data<0..2^16-1>;
;;; } Extension;

(defstruct tls-extension
  "A TLS extension."
  (type 0 :type fixnum)
  (data nil))

;;;; Extension Parsing

(defun parse-extensions (data)
  "Parse a list of extensions from bytes."
  (let ((buf (make-tls-buffer data))
        (extensions nil))
    (loop while (plusp (buffer-remaining buf))
          do (let* ((ext-type (buffer-read-uint16 buf))
                    (ext-data (buffer-read-vector16 buf)))
               (push (parse-extension ext-type ext-data) extensions)))
    (nreverse extensions)))

(defun parse-extension (ext-type data)
  "Parse a single extension."
  (make-tls-extension
   :type ext-type
   :data (case ext-type
           (#.+extension-supported-versions+
            (parse-supported-versions-extension data))
           (#.+extension-key-share+
            (parse-key-share-extension data))
           (#.+extension-supported-groups+
            (parse-supported-groups-extension data))
           (#.+extension-signature-algorithms+
            (parse-signature-algorithms-extension data))
           (#.+extension-server-name+
            (parse-server-name-extension data))
           (#.+extension-application-layer-protocol-negotiation+
            (parse-alpn-extension data))
           (t data))))  ; Return raw bytes for unknown extensions

(defun serialize-extension (ext)
  "Serialize an extension to bytes."
  (let ((ext-type (tls-extension-type ext))
        (ext-data (tls-extension-data ext)))
    ;; Serialize the data based on type if it's structured
    (let ((serialized-data
            (case ext-type
              (#.+extension-supported-versions+
               (serialize-supported-versions-extension ext-data))
              (#.+extension-key-share+
               (serialize-key-share-extension ext-data))
              (#.+extension-supported-groups+
               (serialize-supported-groups-extension ext-data))
              (#.+extension-signature-algorithms+
               (serialize-signature-algorithms-extension ext-data))
              (#.+extension-server-name+
               (serialize-server-name-extension ext-data))
              (#.+extension-application-layer-protocol-negotiation+
               (serialize-alpn-extension ext-data))
              (t (if (typep ext-data 'octet-vector)
                     ext-data
                     (make-octet-vector 0))))))
      (concat-octet-vectors
       (encode-uint16 ext-type)
       (encode-uint16 (length serialized-data))
       serialized-data))))

;;;; Supported Versions Extension

(defstruct supported-versions-ext
  "supported_versions extension data."
  (versions nil :type list)
  ;; For ServerHello, only one version
  (selected-version nil))

(defun parse-supported-versions-extension (data)
  "Parse supported_versions extension."
  (let ((buf (make-tls-buffer data)))
    (if (= (length data) 2)
        ;; ServerHello format: single selected version
        (make-supported-versions-ext
         :selected-version (buffer-read-uint16 buf))
        ;; ClientHello format: list of versions
        (let ((versions-data (buffer-read-vector8 buf))
              (versions nil))
          (loop for i from 0 below (length versions-data) by 2
                do (push (decode-uint16 versions-data i) versions))
          (make-supported-versions-ext :versions (nreverse versions))))))

(defun serialize-supported-versions-extension (ext)
  "Serialize supported_versions extension for ClientHello."
  (let ((buf (make-tls-write-buffer)))
    (if (supported-versions-ext-selected-version ext)
        ;; ServerHello format
        (write-buffer-append-uint16 buf (supported-versions-ext-selected-version ext))
        ;; ClientHello format
        (let ((versions-buf (make-tls-write-buffer)))
          (dolist (v (supported-versions-ext-versions ext))
            (write-buffer-append-uint16 versions-buf v))
          (write-buffer-append-vector8 buf (write-buffer-contents versions-buf))))
    (write-buffer-contents buf)))

;;;; Key Share Extension

(defstruct key-share-ext
  "key_share extension data."
  ;; For ClientHello: list of key-share-entry
  (client-shares nil :type list)
  ;; For ServerHello: single key-share-entry
  (server-share nil)
  ;; For HelloRetryRequest: selected group
  (selected-group nil))

(defstruct key-share-entry
  "A key share entry."
  (group 0 :type fixnum)
  (key-exchange nil :type (or null octet-vector)))

(defun parse-key-share-extension (data)
  "Parse key_share extension."
  (let ((buf (make-tls-buffer data)))
    (cond
      ;; HelloRetryRequest: just a group
      ((= (length data) 2)
       (make-key-share-ext :selected-group (buffer-read-uint16 buf)))
      ;; ServerHello: single entry (group + key)
      ((< (length data) 6)
       (error 'tls-decode-error :message "Invalid key_share extension"))
      ;; Try to parse as ServerHello first (no length prefix)
      ((let ((potential-group (decode-uint16 data 0))
             (potential-len (decode-uint16 data 2)))
         (= (length data) (+ 4 potential-len)))
       ;; ServerHello format
       (let* ((group (buffer-read-uint16 buf))
              (key-exchange (buffer-read-vector16 buf)))
         (make-key-share-ext
          :server-share (make-key-share-entry :group group
                                              :key-exchange key-exchange))))
      ;; ClientHello: list of entries
      (t
       (let ((shares-data (buffer-read-vector16 buf))
             (shares nil))
         (let ((shares-buf (make-tls-buffer shares-data)))
           (loop while (plusp (buffer-remaining shares-buf))
                 do (let* ((group (buffer-read-uint16 shares-buf))
                           (key-exchange (buffer-read-vector16 shares-buf)))
                      (push (make-key-share-entry :group group
                                                  :key-exchange key-exchange)
                            shares))))
         (make-key-share-ext :client-shares (nreverse shares)))))))

(defun serialize-key-share-extension (ext)
  "Serialize key_share extension."
  (let ((buf (make-tls-write-buffer)))
    (cond
      ;; HelloRetryRequest
      ((key-share-ext-selected-group ext)
       (write-buffer-append-uint16 buf (key-share-ext-selected-group ext)))
      ;; ServerHello
      ((key-share-ext-server-share ext)
       (let ((entry (key-share-ext-server-share ext)))
         (write-buffer-append-uint16 buf (key-share-entry-group entry))
         (write-buffer-append-vector16 buf (key-share-entry-key-exchange entry))))
      ;; ClientHello
      (t
       (let ((entries-buf (make-tls-write-buffer)))
         (dolist (entry (key-share-ext-client-shares ext))
           (write-buffer-append-uint16 entries-buf (key-share-entry-group entry))
           (write-buffer-append-vector16 entries-buf (key-share-entry-key-exchange entry)))
         (write-buffer-append-vector16 buf (write-buffer-contents entries-buf)))))
    (write-buffer-contents buf)))

;;;; Supported Groups Extension

(defstruct supported-groups-ext
  "supported_groups extension data."
  (groups nil :type list))

(defun parse-supported-groups-extension (data)
  "Parse supported_groups extension."
  (let ((buf (make-tls-buffer data))
        (groups nil))
    (let ((groups-data (buffer-read-vector16 buf)))
      (loop for i from 0 below (length groups-data) by 2
            do (push (decode-uint16 groups-data i) groups)))
    (make-supported-groups-ext :groups (nreverse groups))))

(defun serialize-supported-groups-extension (ext)
  "Serialize supported_groups extension."
  (let ((buf (make-tls-write-buffer)))
    (let ((groups-buf (make-tls-write-buffer)))
      (dolist (g (supported-groups-ext-groups ext))
        (write-buffer-append-uint16 groups-buf g))
      (write-buffer-append-vector16 buf (write-buffer-contents groups-buf)))
    (write-buffer-contents buf)))

;;;; Signature Algorithms Extension

(defstruct signature-algorithms-ext
  "signature_algorithms extension data."
  (algorithms nil :type list))

(defun parse-signature-algorithms-extension (data)
  "Parse signature_algorithms extension."
  (let ((buf (make-tls-buffer data))
        (algs nil))
    (let ((algs-data (buffer-read-vector16 buf)))
      (loop for i from 0 below (length algs-data) by 2
            do (push (decode-uint16 algs-data i) algs)))
    (make-signature-algorithms-ext :algorithms (nreverse algs))))

(defun serialize-signature-algorithms-extension (ext)
  "Serialize signature_algorithms extension."
  (let ((buf (make-tls-write-buffer)))
    (let ((algs-buf (make-tls-write-buffer)))
      (dolist (a (signature-algorithms-ext-algorithms ext))
        (write-buffer-append-uint16 algs-buf a))
      (write-buffer-append-vector16 buf (write-buffer-contents algs-buf)))
    (write-buffer-contents buf)))

;;;; Server Name Extension (SNI)

(defstruct server-name-ext
  "server_name extension data."
  (host-name nil :type (or null string)))

(defconstant +server-name-type-hostname+ 0)

(defun parse-server-name-extension (data)
  "Parse server_name extension.
   In server responses, this may be empty (just acknowledging SNI)."
  ;; Empty extension is valid - server acknowledges SNI
  (when (zerop (length data))
    (return-from parse-server-name-extension
      (make-server-name-ext :host-name nil)))
  (let ((buf (make-tls-buffer data)))
    (let ((list-data (buffer-read-vector16 buf)))
      (when (plusp (length list-data))
        (let ((list-buf (make-tls-buffer list-data)))
          (let ((name-type (buffer-read-octet list-buf))
                (name-data (buffer-read-vector16 list-buf)))
            (when (= name-type +server-name-type-hostname+)
              (make-server-name-ext
               :host-name (octets-to-string name-data)))))))))

(defun serialize-server-name-extension (ext)
  "Serialize server_name extension."
  (let ((buf (make-tls-write-buffer))
        (hostname (server-name-ext-host-name ext)))
    (when hostname
      (let ((name-bytes (string-to-octets hostname))
            (entry-buf (make-tls-write-buffer)))
        (write-buffer-append-octet entry-buf +server-name-type-hostname+)
        (write-buffer-append-vector16 entry-buf name-bytes)
        (write-buffer-append-vector16 buf (write-buffer-contents entry-buf))))
    (write-buffer-contents buf)))

;;;; ALPN Extension

(defstruct alpn-ext
  "application_layer_protocol_negotiation extension data."
  (protocol-list nil :type list)
  ;; For server response
  (selected-protocol nil :type (or null string)))

(defun parse-alpn-extension (data)
  "Parse ALPN extension."
  (let ((buf (make-tls-buffer data))
        (protocols nil))
    (let ((list-data (buffer-read-vector16 buf)))
      (let ((list-buf (make-tls-buffer list-data)))
        (loop while (plusp (buffer-remaining list-buf))
              do (let ((proto-data (buffer-read-vector8 list-buf)))
                   (push (octets-to-string proto-data) protocols)))))
    (make-alpn-ext :protocol-list (nreverse protocols))))

(defun serialize-alpn-extension (ext)
  "Serialize ALPN extension."
  (let ((buf (make-tls-write-buffer)))
    (let ((list-buf (make-tls-write-buffer)))
      (dolist (proto (or (and (alpn-ext-selected-protocol ext)
                              (list (alpn-ext-selected-protocol ext)))
                         (alpn-ext-protocol-list ext)))
        (write-buffer-append-vector8 list-buf (string-to-octets proto)))
      (write-buffer-append-vector16 buf (write-buffer-contents list-buf)))
    (write-buffer-contents buf)))

;;;; Extension Lookup Utilities

(defun find-extension (extensions type)
  "Find an extension of the given type in a list of extensions."
  (find type extensions :key #'tls-extension-type))

(defun extension-name (ext-type)
  "Return a human-readable name for an extension type."
  (case ext-type
    (#.+extension-server-name+ "server_name")
    (#.+extension-max-fragment-length+ "max_fragment_length")
    (#.+extension-status-request+ "status_request")
    (#.+extension-supported-groups+ "supported_groups")
    (#.+extension-signature-algorithms+ "signature_algorithms")
    (#.+extension-application-layer-protocol-negotiation+ "alpn")
    (#.+extension-pre-shared-key+ "pre_shared_key")
    (#.+extension-early-data+ "early_data")
    (#.+extension-supported-versions+ "supported_versions")
    (#.+extension-cookie+ "cookie")
    (#.+extension-psk-key-exchange-modes+ "psk_key_exchange_modes")
    (#.+extension-key-share+ "key_share")
    (t (format nil "unknown(~D)" ext-type))))
