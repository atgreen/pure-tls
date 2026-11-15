# Security Policy

## Reporting a Vulnerability

Email Anthony Green at green@moxielogic.com

## Accepted non-issues

This section records behaviours that look security-relevant but that we have
analysed and do not consider vulnerabilities. We document them here so the
analysis is on record and the behaviour is not re-reported as a bug.

### Verified-chain cache timing (cache-membership side channel)

Certificate-chain verification caches the result of the *cryptographic* steps
(signature chaining and trust-anchoring) in a process-wide bounded cache
(`*verified-chain-cache*`). A chain that was already validated successfully
skips the bignum/EC arithmetic on the next call, so verifying a cached
`(chain, anchors, options)` tuple is much faster than verifying an uncached one.

That timing difference is observable, so it is a side channel: validation
latency leaks whether this exact tuple has previously been validated
successfully in this process. **We do not consider this a vulnerability.**

Rationale:

- **No secret is leaked.** The only fact the oracle exposes is "this certificate
  chain has been seen and validated here before." The certificate is already
  public — it is presented in the clear on the TLS handshake and typically
  published in Certificate Transparency logs — and the trust anchors are the
  deployment's own trust store, not a secret. The oracle reveals nothing an
  observer could not otherwise obtain.

- **No key-material side channel is created or worsened.** Chain verification
  uses only *public* keys. No private key is involved, so this cache cannot leak
  private-key bits. On a cache *hit* the variable-time Ironclad arithmetic is
  skipped entirely, and on a *miss* it runs exactly as it did before the cache
  existed — so repeat-validation exposure of the underlying non-constant-time
  crypto goes down, not up. Constant-time private-key operations remain a
  property of the crypto layer and are out of scope for this cache.

- **The cache key is public data.** The key is `SHA-256(TBS || signature)` of
  each certificate folded together with the anchor set and options. It is a
  digest of public bytes looked up in a hash table; there is no
  secret-dependent comparison.

- **No fast-reject oracle.** Only *successful* verifications are cached, and only
  after the full check passes. Failures always re-run the complete validation,
  so an invalid chain gets no distinguishing fast path. Timing separates
  "previously-validated-valid" from "everything else" — it does not separate
  "valid" from "invalid".

- **Decision-affecting checks are never cached.** Expiry (notBefore/notAfter),
  unknown-critical-extension rejection, and purpose/EKU are re-evaluated live on
  every call, including cache hits; `check-revocation` bypasses the cache
  entirely. The cache can therefore never cause a stale accept of an expired or
  otherwise-invalid chain. This is covered by the
  `verified-chain-cache-preserves-security-invariants` regression test.

Residual risk and mitigation:

- The one place the oracle carries meaning is a **shared, multi-tenant process**
  where one `*verified-chain-cache*` is visible across trust boundaries: a
  tenant could time-probe "was certificate X recently validated by another
  tenant?" — a weak cross-tenant presence signal.
- Mitigation is built in. `*verified-chain-cache*` is a special variable, so a
  deployment that cares can bind a **per-tenant** (or per-listener) cache to
  isolate the oracle, or bind it to `NIL` to disable caching entirely and fall
  back to always doing the full arithmetic.
