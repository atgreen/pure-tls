# pure-tls 1.13.0

**Release date:** 2026-07-12

Feature release. TLS clients can opt into a stricter RFC 6125
hostname-verification profile, and the ACME client now recovers
automatically from transient CA errors (`badNonce`, rate limits,
not-ready responses) instead of failing — or worse, silently dropping an
already-issued certificate. Both contributed by Brian O'Reilly (@fade).

## New features

- **Opt-in hostname-verification policy** (#16). `make-tls-context`
  accepts a `:hostname-policy` argument carrying two orthogonal RFC 6125
  knobs: `:allow-wildcards` (when `nil`, wildcard-pattern `*.` SANs are
  excluded from matching) and `:allow-cn-fallback` (when `nil`, a
  certificate with no subjectAltName is rejected rather than matched
  against its Subject Common Name). Both default to the permissive
  value — `*general-hostname-policy*`, the general web profile — so
  existing callers see no behavior change. `verify-hostname` and
  `verify-peer-certificate` take the policy as a keyword argument.
  Embedded-NUL/non-LDH name rejection and IP-literal handling remain
  unconditional under every policy. New exports: `hostname-policy`,
  `make-hostname-policy`, `hostname-policy-allow-wildcards`,
  `hostname-policy-allow-cn-fallback`, `*general-hostname-policy*`.

- **ACME transient-error recovery via the condition system** (#17).
  Every ACME HTTP request now flows through a single recovery layer:
  recoverable responses signal typed conditions (`acme-http-error` and
  subtypes `acme-bad-nonce`, `acme-rate-limited`, `acme-not-ready`)
  offering a `retry` restart that re-drives the request without
  unwinding the stack — refreshing the nonce for `badNonce` (RFC 8555
  §6.5), or waiting per `Retry-After` for `429`/`202`. Recovery is
  bounded by both a retry count and a total-wait ceiling. The exported
  `with-acme-retries` macro lets an issuance driver place one policy
  around a whole issuance.

  This fixes a real failure mode: `client-download-certificate` issued
  its POST-as-GET outside the retried request path, so a `badNonce` at
  the download step silently collapsed an already-issued certificate to
  `nil`. Validated against Pebble with server-side `badNonce` injection:
  zero silent drops after the change. Public return contracts are
  unchanged for success and terminal responses.

## Testing

- New `pure-tls/acme/test` system (fiveam): 7 tests / 26 checks covering
  nonce refresh-and-retry with JWS re-signing, `Retry-After` waits,
  the certificate-download `badNonce` path, bounded retries under a
  persistently hostile server, and non-retry of terminal errors. The
  HTTP transport and sleep are stubbed via seams, so no network is
  needed.
- Five new security-regression tests prove each hostname-policy knob
  independently and that the general RFC 6125 matcher is unchanged.
