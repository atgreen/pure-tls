# Changelog

All notable changes to pure-tls are documented in this file.

## [1.4.0] - 2026-01-05

### Added

- **mTLS (Mutual TLS)** - Full client certificate authentication support
  - `make-tls-client-stream` now accepts `:client-certificate` and `:client-key` parameters
  - Supports file paths or pre-loaded certificate/key objects
  - Server can request/require client certificates via `:verify` mode

- **BoringSSL Test Integration** - Comprehensive TLS 1.3 test harness
  - Built a full shim binary (`pure-tls-shim`) for BoringSSL's Go test runner
  - 65.4% pass rate (4274/6533 tests) - remaining failures are TLS 1.2 and unimplemented features
  - Validates protocol compliance against 300+ edge cases

- **OpenSSL Test Framework** - Adapted OpenSSL's ssl-tests suite
  - INI-style configuration parser for `.cnf` test files
  - 13 test suites integrated: basic handshakes, ALPN, SNI, key update, curves, compression
  - All 32 enabled tests pass

- **SNI Rejection** - Server can reject unknown hostnames
  - SNI callback can return `:reject` to abort with `unrecognized_name` alert
  - `sni-hostname` parameter for client-side SNI without hostname verification

- **RFC 8701 GREASE Support** - Server sends GREASE extension in NewSessionTicket

### Fixed

- **RFC 8446 Compliance Fixes**
  - KeyUpdate validation - sends `illegal_parameter` for unknown request modes
  - Warning alert rejection - only allows `close_notify` and `user_canceled`
  - Compression method validation - requires `legacy_compression_methods` to be `[0]`
  - Record size limit corrected to 16640 bytes (2^14 + 256)
  - CertificateVerify transcript ordering corrected

- **Alert Handling**
  - Invalid alert levels (not 1 or 2) now detected and rejected
  - Double/oversized alert records (> 2 bytes) rejected with `decode_error`
  - Unknown alert types rejected with `illegal_parameter`

- **Record Layer**
  - Invalid content types rejected immediately (prevents SSLv2 hangs)
  - Inner plaintext size validation for padded records
  - Proper error codes: `:TLSV1_ALERT_RECORD_OVERFLOW:`, `:UNEXPECTED_RECORD:`, `:BAD_ALERT:`

- **Handshake**
  - Handshake message reassembly across multiple TLS records
  - Client-side compression method validation
  - Cipher suite error messages improved for test compatibility

### Changed

- Improved error messages with BoringSSL-compatible error code prefixes
- Test framework enhanced with FiveAM integration for OpenSSL tests
- Documentation updated with current test status and implementation details

### Test Results

- **BoringSSL**: 65.4% pass rate (TLS 1.3 only implementation)
- **OpenSSL**: 100% pass rate on enabled TLS 1.3 tests
- **TLS-Anvil**: RFC compliance testing in progress

## [1.3.0] - Previous Release

See git history for earlier changes.
