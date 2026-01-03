# pure-tls

A pure Common Lisp implementation of TLS 1.3 (RFC 8446).

## Features

- **Pure Common Lisp** - No foreign libraries or OpenSSL dependency
- **TLS 1.3 only** - Modern, secure protocol with simplified handshake
- **Gray streams** - Seamless integration with existing I/O code
- **cl+ssl compatible** - Drop-in replacement API available

### Supported Cipher Suites

- `TLS_AES_256_GCM_SHA384` (0x1302)
- `TLS_AES_128_GCM_SHA256` (0x1301)

### Supported Key Exchange

- X25519 (Curve25519)
- secp256r1 (P-256)

## Installation

Using [ocicl](https://github.com/ocicl/ocicl):

```sh
ocicl install pure-tls
```

Or add to your ASDF system:

```lisp
:depends-on (#:pure-tls)
```

## Usage

### Basic HTTPS Client

```lisp
(asdf:load-system :pure-tls)
(asdf:load-system :usocket)

(let* ((socket (usocket:socket-connect "example.com" 443
                                        :element-type '(unsigned-byte 8)))
       (tls (pure-tls:make-tls-client-stream
              (usocket:socket-stream socket)
              :hostname "example.com")))
  ;; Send HTTP request
  (write-sequence (pure-tls:string-to-octets
                    "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
                  tls)
  (force-output tls)
  ;; Read response
  (loop for byte = (read-byte tls nil nil)
        while byte
        do (write-char (code-char byte)))
  (close tls))
```

### With Certificate Verification

```lisp
(pure-tls:make-tls-client-stream stream
  :hostname "example.com"
  :verify pure-tls:+verify-peer+)  ; Verify server certificate
```

### ALPN Protocol Negotiation

```lisp
(let ((tls (pure-tls:make-tls-client-stream stream
             :hostname "example.com"
             :alpn-protocols '("h2" "http/1.1"))))
  (format t "Selected protocol: ~A~%" (pure-tls:tls-selected-alpn tls)))
```

### TLS Server

```lisp
(asdf:load-system :pure-tls)
(asdf:load-system :usocket)

;; Create a server socket
(let ((server (usocket:socket-listen "0.0.0.0" 8443)))
  (loop
    (let* ((client-socket (usocket:socket-accept server :element-type '(unsigned-byte 8)))
           (tls (pure-tls:make-tls-server-stream
                  (usocket:socket-stream client-socket)
                  :certificate "/path/to/cert.pem"
                  :key "/path/to/key.pem")))
      ;; Handle TLS connection
      (loop for byte = (read-byte tls nil nil)
            while byte
            do (write-byte byte tls))
      (close tls))))
```

### Server with Client Certificate Authentication (mTLS)

```lisp
(pure-tls:make-tls-server-stream stream
  :certificate "/path/to/server-cert.pem"
  :key "/path/to/server-key.pem"
  :verify pure-tls:+verify-required+)  ; Require client certificate
```

### Using the cl+ssl Compatibility Layer

```lisp
(asdf:load-system :pure-tls/compat)

;; Use familiar cl+ssl API
(cl+ssl:make-ssl-client-stream stream
  :hostname "example.com"
  :verify :optional)
```

## API Reference

### Stream Creation

#### `make-tls-client-stream` (socket &key hostname context verify alpn-protocols close-callback external-format buffer-size)

Create a TLS client stream over a TCP socket.

- `socket` - The underlying TCP stream
- `hostname` - Server hostname for SNI and certificate verification
- `context` - TLS context for configuration (optional)
- `verify` - Certificate verification mode: `+verify-none+`, `+verify-peer+`, or `+verify-required+`
- `alpn-protocols` - List of ALPN protocol names to offer
- `close-callback` - Function called when stream is closed
- `external-format` - If specified, wrap in a flexi-stream for character I/O
- `buffer-size` - Size of I/O buffers (default 16384)

#### `make-tls-server-stream` (socket &key context certificate key verify alpn-protocols close-callback external-format buffer-size)

Create a TLS server stream over a TCP socket.

- `socket` - The underlying TCP stream
- `context` - TLS context for configuration (optional)
- `certificate` - Certificate chain (list of certificates or path to PEM file)
- `key` - Private key (Ironclad key object or path to PEM file)
- `verify` - Client certificate verification mode: `+verify-none+`, `+verify-peer+`, or `+verify-required+`
- `alpn-protocols` - List of ALPN protocol names the server supports
- `close-callback` - Function called when stream is closed
- `external-format` - If specified, wrap in a flexi-stream for character I/O
- `buffer-size` - Size of I/O buffers (default 16384)

### Stream Accessors

- `(tls-peer-certificate stream)` - Returns the peer's X.509 certificate
- `(tls-peer-certificate-chain stream)` - Returns the peer's full certificate chain
- `(tls-selected-alpn stream)` - Returns the negotiated ALPN protocol
- `(tls-cipher-suite stream)` - Returns the negotiated cipher suite
- `(tls-version stream)` - Returns the TLS version (always 1.3)
- `(tls-client-hostname stream)` - Returns the client's SNI hostname (server-side only)

### Context Management

#### `make-tls-context` (&key verify-mode certificate-chain private-key alpn-protocols ca-certificates)

Create a reusable TLS context for configuration.

### Verification Modes

- `+verify-none+` (0) - No certificate verification
- `+verify-peer+` (1) - Verify peer certificate if provided
- `+verify-required+` (2) - Require and verify peer certificate

## Side-Channel Hardening

pure-tls implements several measures to mitigate side-channel attacks:

### Constant-Time Operations

All security-sensitive comparisons (MAC verification, key comparison) use Ironclad's constant-time comparison functions to prevent timing attacks. The implementation avoids early-return patterns that could leak information about secret data.

### Uniform Error Handling

All decryption failures produce identical error conditions (`tls-mac-error`) regardless of the failure cause, as required by RFC 8446. This prevents padding oracle attacks by ensuring attackers cannot distinguish between different types of decryption failures.

### Secret Zeroization

Sensitive cryptographic material can be explicitly cleared from memory using the `zeroize` function or the `with-zeroized-vector` macro:

```lisp
;; Explicit zeroization
(let ((key (derive-key ...)))
  (unwind-protect
      (use-key key)
    (pure-tls:zeroize key)))

;; RAII-style zeroization
(pure-tls:with-zeroized-vector (key (derive-key ...))
  (use-key key))
;; key is automatically zeroed here, even if an error occurs
```

Note: In a garbage-collected runtime, zeroization is best-effort as the GC may have already copied the data. For highest security requirements, consider foreign memory that can be mlock'd.

### TLS 1.3 Record Padding

Record padding helps mitigate traffic analysis by hiding the true length of application data. Configure padding via `*record-padding-policy*`:

```lisp
;; Pad all records to 256-byte boundaries
(setf pure-tls:*record-padding-policy* :block-256)

;; Pad to 1024-byte boundaries
(setf pure-tls:*record-padding-policy* :block-1024)

;; Fixed-size records (4096 bytes)
(setf pure-tls:*record-padding-policy* :fixed-4096)

;; Custom padding function
(setf pure-tls:*record-padding-policy*
      (lambda (plaintext-length)
        (* 128 (ceiling plaintext-length 128))))

;; No padding (default)
(setf pure-tls:*record-padding-policy* nil)
```

### Current Limitations

- **ChaCha20-Poly1305**: Not currently supported because Ironclad doesn't provide it as a combined AEAD mode. Only AES-GCM cipher suites are available. Since Ironclad implements AES in pure Common Lisp using table lookups (rather than hardware AES-NI instructions), the implementation may be susceptible to cache-timing attacks. A ChaCha20 implementation would be preferable for side-channel resistance as it uses only ARX (add-rotate-xor) operations.

## Dependencies

- [ironclad](https://github.com/sharplispers/ironclad) - Cryptographic primitives
- [trivial-gray-streams](https://github.com/trivial-gray-streams/trivial-gray-streams) - Gray stream support
- [flexi-streams](https://github.com/edicl/flexi-streams) - Character encoding (optional)
- [alexandria](https://github.com/keithj/alexandria) - Utilities

## Limitations

- No session resumption (PSK)
- No 0-RTT early data
- No HelloRetryRequest handling

## License

MIT License

Copyright (c) 2026 Anthony Green <green@moxielogic.com>

## See Also

- [RFC 8446](https://tools.ietf.org/html/rfc8446) - TLS 1.3 specification
- [cl+ssl](https://github.com/cl-plus-ssl/cl-plus-ssl) - OpenSSL-based TLS for Common Lisp
