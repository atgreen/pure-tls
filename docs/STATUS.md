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
- **Pass rate: 65.4% (4274 passed, 2259 failed out of 6533 tests)**
- Command: `go test -shim-path=/home/green/git/pure-tls/pure-tls-shim -allow-unimplemented`
- Shim build: `make boringssl-shim`
- TLS 1.2 handling: shim skips any test whose version range permits < TLS 1.3 (returns exit 89 = unimplemented)
- Test suite completes fully without hanging

## Recent Fixes (2026-01-05)

### Alert Handling
- ✅ `SendBogusAlertType` - Detect invalid alert levels (not 1 or 2)
- ✅ `DoubleAlert` - Reject oversized alert records (> 2 bytes)
- ✅ `FragmentAlert` - Reject short/incomplete alert records
- ✅ `Alert` - Added `:TLSV1_ALERT_RECORD_OVERFLOW:` error code

### Record Layer
- ✅ `SendInvalidRecordType` - Added `:UNEXPECTED_RECORD:` error code
- ✅ `LargePlaintext-TLS13-Padded-*` - Fixed inner plaintext size validation
- ✅ SSLv2 ClientHello - Content type validation to reject invalid records

### Shim Improvements
- ✅ Fixed test suite hang at 6532/6533 (added `-shim-shuts-down` flag support)
- ✅ Added `-check-close-notify` flag support for bidirectional shutdown

## Remaining Failure Categories

### Not Implemented (Expected)
- TLS 1.2 tests (~35% of suite) - pure-tls is TLS 1.3 only
- ALPS (Application-Level Protocol Settings) - draft extension
- Certificate callbacks - FailCertCallback-* tests
- Peek functionality - Peek-* tests
- 0-RTT early data tests

### Needs Investigation
- GREASE handling:
  - `GREASE-Client-TLS13` (client-side GREASE validation)
- Alert validation edge cases:
  - `SendUserCanceledAlerts-TooMany-TLS13` (expected `:TOO_MANY_WARNING_ALERTS:`)
- Record limits:
  - `MaxSendFragment-TLS13`
- Certificate selection behaviors:
  - Several `CertificateSelection-*` cases (issuer filters, chain size)
- ECDSA signature handling:
  - `BadECDSA-*` cases expect `:BAD_SIGNATURE:` but receive decode errors

## Notes
- TLS 1.2 is not required by RFC 8446. It is only a SHOULD if earlier versions are supported.
- The 65% pass rate reflects that ~35% of tests are TLS 1.2 specific
- Most remaining TLS 1.3 failures are in unimplemented features (ALPS, callbacks, etc.)
