# Test Suite Status (2026-01-05)

## TLS-Anvil RFC Compliance Testing

### Setup
TLS-Anvil's scanner sends TLS 1.2 probes that timeout against TLS 1.3-only servers. We modified TLS-Anvil (in `~/git/TLS-Anvil`) to add a `-tls13Only` flag that bypasses the scanner.

**Modified files:**
- `TLS-Test-Framework/src/main/java/de/rub/nds/tlstest/framework/config/TlsAnvilConfig.java` - Added `-tls13Only` CLI parameter
- `TLS-Test-Framework/src/main/java/de/rub/nds/tlstest/framework/execution/TestPreparator.java` - Skip scanner, use static TLS 1.3 config

**Usage:**
```bash
cd ~/git/TLS-Anvil
mvn exec:java -pl TLS-Testsuite \
  -Dexec.args="-tls13Only -parallelHandshakes 1 server -connect localhost:4433"
```

### Initial Test Results
With `-tls13Only` flag, tests run immediately without scanner timeout:
- TLS 1.2 tests: Automatically skipped ("ProtocolVersion not supported by target")
- TLS 1.3 tests: Running against pure-tls

**Sample results from initial run:**
- `KeyUpdate.sendUnknownRequestMode`: 5/9 passed, 4/9 failed
  - Failures: "Expected fatal alert but received NEW_SESSION_TICKET" (pure-tls doesn't reject unknown KeyUpdate request modes with alert)

---

## Compliance Fixes Applied (2026-01-05)

The following RFC compliance issues were fixed:

### Fixed Issues

1. **KeyUpdate validation** (RFC 8446 §4.6.3) ✅
   - Now sends `illegal_parameter` alert for unknown `request_update` values
   - File: `src/streams.lisp`

2. **Warning alert rejection** (RFC 8446 §6) ✅
   - Now rejects warning-level alerts except `close_notify` and `user_canceled`
   - File: `src/record/record-layer.lisp`

3. **Compression method validation** (RFC 8446 §4.1.2) ✅
   - Server now validates `legacy_compression_methods` is exactly `[0]`
   - Sends `illegal_parameter` alert for non-compliant values
   - File: `src/handshake/server.lisp`

4. **Record size limit** (RFC 8446 §5.4) ✅
   - Fixed max encrypted record size from 16656 to 16640 bytes (2^14 + 256)
   - File: `src/constants.lisp`

5. **GREASE in NewSessionTicket** (RFC 8701 §4.1) ✅
   - Server now includes GREASE extension in NewSessionTicket
   - `GREASE-Server-TLS13` test now passes
   - File: `src/handshake/server.lisp`

### Remaining Gaps

1. **GREASE-Client-TLS13**: Client-side GREASE test still fails (needs investigation)
2. **MaxSendFragment**: Not enforcing negotiated fragment size limits
3. **Bad record MAC**: Error mapping may differ from expected
4. **Bad Finished**: Verification failures may not produce expected alert code
5. **Bad ECDSA signatures**: Should return `:BAD_SIGNATURE:` not decode errors
6. **Certificate selection**: Issuer filtering and chain size handling

---

# BoringSSL Test Suite Status (2026-01-05)

## Latest Run
- Command: `go test -v -shim-path=/home/green/git/pure-tls/pure-tls-shim -allow-unimplemented -test "*TLS13*"`
- Shim build: `XDG_CACHE_HOME=/home/green/git/pure-tls/.cache make -B boringssl-shim`
- TLS 1.2 handling: shim now skips any test whose version range permits < TLS 1.3 (returns exit 89 = unimplemented).

## Result Summary
The TLS 1.3-only suite still reports many failures. The failures are clustered in a few areas rather than spread evenly.

### Key Failure Buckets
- GREASE handling:
  - `GREASE-Client-TLS13` (client-side GREASE validation - needs investigation)
  - ~~`GREASE-Server-TLS13`~~ ✅ FIXED (server now sends GREASE in NewSessionTicket)
- Alert validation:
  - `SendWarningAlerts-TLS13` (expected `:BAD_ALERT:`)
  - `SendUserCanceledAlerts-TLS13`
  - `SendUserCanceledAlerts-TooMany-TLS13` (expected `:TOO_MANY_WARNING_ALERTS:`)
- Record size and overflow:
  - `LargePlaintext-TLS13-Padded-8193-8192`
  - `LargePlaintext-TLS13-Padded-16384-1`
  - `MaxSendFragment-TLS13`
- ~~Compression list validation~~ ✅ FIXED (server now validates compression method is [0])
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
