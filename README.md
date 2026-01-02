# cl-tls

A pure Common Lisp implementation of TLS 1.3 (RFC 8446).

## Features

- **Pure Common Lisp** - No foreign libraries or OpenSSL dependency
- **TLS 1.3 only** - Modern, secure protocol with simplified handshake
- **Gray streams** - Seamless integration with existing I/O code
- **cl+ssl compatible** - Drop-in replacement API available

### Supported Cipher Suites

- `TLS_AES_128_GCM_SHA256` (0x1301)
- `TLS_CHACHA20_POLY1305_SHA256` (0x1303)

### Supported Key Exchange

- X25519 (Curve25519)
- secp256r1 (P-256)

## Installation

Using [ocicl](https://github.com/ocicl/ocicl):

```sh
ocicl install cl-tls
```

Or add to your ASDF system:

```lisp
:depends-on (#:cl-tls)
```

## Usage

### Basic HTTPS Client

```lisp
(asdf:load-system :cl-tls)
(asdf:load-system :usocket)

(let* ((socket (usocket:socket-connect "example.com" 443
                                        :element-type '(unsigned-byte 8)))
       (tls (cl-tls:make-tls-client-stream
              (usocket:socket-stream socket)
              :hostname "example.com")))
  ;; Send HTTP request
  (write-sequence (cl-tls:string-to-octets
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
(cl-tls:make-tls-client-stream stream
  :hostname "example.com"
  :verify cl-tls:+verify-peer+)  ; Verify server certificate
```

### ALPN Protocol Negotiation

```lisp
(let ((tls (cl-tls:make-tls-client-stream stream
             :hostname "example.com"
             :alpn-protocols '("h2" "http/1.1"))))
  (format t "Selected protocol: ~A~%" (cl-tls:tls-selected-alpn tls)))
```

### Using the cl+ssl Compatibility Layer

```lisp
(asdf:load-system :cl-tls/compat)

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

### Stream Accessors

- `(tls-peer-certificate stream)` - Returns the peer's X.509 certificate
- `(tls-selected-alpn stream)` - Returns the negotiated ALPN protocol
- `(tls-cipher-suite stream)` - Returns the negotiated cipher suite
- `(tls-version stream)` - Returns the TLS version (always 1.3)

### Context Management

#### `make-tls-context` (&key verify-mode certificate-chain private-key alpn-protocols ca-certificates)

Create a reusable TLS context for configuration.

### Verification Modes

- `+verify-none+` (0) - No certificate verification
- `+verify-peer+` (1) - Verify peer certificate if provided
- `+verify-required+` (2) - Require and verify peer certificate

## Dependencies

- [ironclad](https://github.com/sharplispers/ironclad) - Cryptographic primitives
- [trivial-gray-streams](https://github.com/trivial-gray-streams/trivial-gray-streams) - Gray stream support
- [flexi-streams](https://github.com/edicl/flexi-streams) - Character encoding (optional)
- [alexandria](https://github.com/keithj/alexandria) - Utilities

## Limitations

- Client mode only (server mode not yet implemented)
- No session resumption (PSK)
- No 0-RTT early data
- No client certificates

## License

MIT License

Copyright (c) 2026 Anthony Green <green@moxielogic.com>

## See Also

- [RFC 8446](https://tools.ietf.org/html/rfc8446) - TLS 1.3 specification
- [cl+ssl](https://github.com/cl-plus-ssl/cl-plus-ssl) - OpenSSL-based TLS for Common Lisp
