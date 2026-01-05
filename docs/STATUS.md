# BoringSSL Test Suite Status (2026-01-05)

## Latest Run
- Command: `go test -v -shim-path=/home/green/git/pure-tls/pure-tls-shim -allow-unimplemented -test "*TLS13*"`
- Shim build: `XDG_CACHE_HOME=/home/green/git/pure-tls/.cache make -B boringssl-shim`
- TLS 1.2 handling: shim now skips any test whose version range permits < TLS 1.3 (returns exit 89 = unimplemented).

## Result Summary
The TLS 1.3-only suite still reports many failures. The failures are clustered in a few areas rather than spread evenly.

### Key Failure Buckets
- GREASE handling:
  - `GREASE-Client-TLS13` (missing GREASE curve)
  - `GREASE-Server-TLS13` (missing GREASE ticket extension)
- Alert validation:
  - `SendWarningAlerts-TLS13` (expected `:BAD_ALERT:`)
  - `SendUserCanceledAlerts-TLS13`
  - `SendUserCanceledAlerts-TooMany-TLS13` (expected `:TOO_MANY_WARNING_ALERTS:`)
- Record size and overflow:
  - `LargePlaintext-TLS13-Padded-8193-8192`
  - `LargePlaintext-TLS13-Padded-16384-1`
  - `MaxSendFragment-TLS13`
- Compression list validation (TLS 1.3 requires legacy compression method to be 0):
  - `TLS13-InvalidCompressionMethod`
  - `ExtraCompressionMethods-TLS13`
  - `NoNullCompression-TLS13`
  - `TLS13-HRR-InvalidCompressionMethod`
- Bad record / MAC error mapping:
  - `TLS-TLS13-CHACHA20_POLY1305_SHA256-BadRecord`
  - `TLS-TLS13-AES_128_GCM_SHA256-BadRecord`
  - `AppDataBeforeTLS13KeyChange` / `AppDataBeforeTLS13KeyChange-Empty`
- Finished verification error mapping:
  - `BadFinished-Client-TLS13`
  - `BadFinished-Server-TLS13`
- Certificate selection behaviors:
  - Several `CertificateSelection-*` cases fail due to sending an unexpected chain size or not enforcing issuer filters.
- ECDSA bad signature handling:
  - `BadECDSA-*` cases expect `:BAD_SIGNATURE:` but receive ECDSA decode errors.

## Notes
- TLS 1.2 is not required by RFC 8446. It is only a SHOULD if earlier versions are supported.
- Even with TLS 1.2 gated off at the shim level, TLS 1.3 behavior still needs alignment with BoringSSL expectations for alerts, GREASE, record limits, and cert selection.
