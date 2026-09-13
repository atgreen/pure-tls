# pure-tls 1.14.0

**Release date:** 2026-09-13

Feature and hardening release. The ACME client now implements ACME
Renewal Information (RFC 9773), so certificates renew adaptively inside
the CA's suggested window instead of on a fixed 30-day-before-expiry
schedule — essential now that Let's Encrypt profiles have moved to
45-day and shorter lifetimes. The TLS client greases its
`signature_algorithms` list, completing RFC 8701 GREASE coverage. And
`verify-certificate-chain` gained argument-type guards and a
keyword-argument signature that together eliminate a class of silent
misuse where a misplaced keyword disabled the very check the caller
asked for.

The `verify-certificate-chain` hardening was contributed by Brian
O'Reilly (@fade).

## New features

- **ACME Renewal Information (RFC 9773)**. Let's Encrypt's `tlsserver`
  profile moved to 45-day certificates in May 2026 and all profiles
  shorten further through 2027–2028, so the old fixed renew-at-30-days
  default (tuned for 90-day certificates) no longer fit any profile —
  on ~6-day short-lived certificates it renewed daily against a
  25-per-week rate limit. `acme/ari.lisp` adds the RFC 9773 machinery:
  the certificate identifier (base64url AKI keyIdentifier `.` base64url
  DER serial content octets, verified against the RFC's Appendix A
  vector), an RFC 3339 timestamp parser, an advisory
  `client-renewal-info` query that degrades to `nil` on any failure,
  and the `renewal-due-p` decision rule.

  The `acme-acceptor` now renews adaptively by default: inside the
  CA's suggested window when ARI is available, otherwise once a third
  of the certificate's lifetime remains (30 days on a 90-day
  certificate — exactly the old default). An explicit `:renewal-days`
  keeps the fixed threshold. Renewal orders carry the RFC 9773
  `replaces` identifier so the CA can exempt them from rate limits,
  retrying once without it if the server rejects the value; first
  issuance sends none because the startup placeholder certificate has
  no AKI. New exports: `client-renewal-info`,
  `certificate-ari-cert-id`, `renewal-due-p`, `parse-rfc3339-time`.

- **GREASE in `signature_algorithms` (RFC 8701)**. pure-tls greased
  extension types, cipher suites, versions, and named groups, but not
  the signature-algorithm list — a gap BoringSSL's runner now checks
  for. A GREASE value is generated once per handshake and repeated in
  the second ClientHello after HelloRetryRequest, consistent with the
  other GREASE values.

## Robustness

- **`verify-certificate-chain` takes its verification time and
  hostname as keyword arguments** (#24). `now` and `hostname` were
  positional `&optional` parameters ahead of the `&key` parameters, so
  a caller who went straight to a keyword had it silently consumed as
  a positional: `(verify-certificate-chain chain roots
  :check-revocation t)` bound `now` to `:check-revocation`, bound
  `hostname` to `t`, and never ran the revocation check the call asked
  for. Moving both parameters to `&key` removes that class of misuse
  outright. The function is internal (not exported), but the README's
  CRL example reaches it by its double-colon name — anyone who copied
  that example needs the new keyword shape.

- **Argument-type guards on `now` and `hostname`** (#23). A `now`
  that is not a non-negative real, or a `hostname` that is neither a
  string nor `nil`, now signals `tls-certificate-error` at entry,
  naming the offending argument — instead of surfacing downstream as a
  bare `type-error`, a foreign-string error in the native verifiers, a
  validity failure blaming the certificate, or (worst) a chain that
  verifies with no hostname checked at all.

## Documentation

- README factual refresh: 2026 Let's Encrypt profile lifetimes and the
  clientAuth EKU removal, ECH's real RFC number (9849), ML-DSA-65
  moved to the supported list to match the code, the `make-cert-store`
  `:path` keyword, and the actual dependency list.
- The `verify-certificate-chain` docstring no longer claims OCSP on
  the pure Lisp path: revocation checking there is CRL-only; OCSP
  happens only when the native Windows/macOS paths delegate to the OS.

## Testing and infrastructure

- 34 new ARI tests over the existing stubbed ACME transport, covering
  the certificate identifier (including the RFC 9773 Appendix A
  vector), RFC 3339 parsing, the advisory-query failure modes, the
  renewal decision rule, and the `replaces` retry.
- The `pure-tls/acme/test` suites now actually run in CI on all three
  platforms via a new `make acme-tests` target wired into `all-tests`
  (cl-json was also missing from the CI dependency install).
- `pure-tls-shim` is now `.PHONY`, so `make boringssl-shim` rebuilds
  the shim instead of silently reusing a stale binary.
- `.gitattributes` pins Lisp sources to LF on all platforms: a CRLF
  checkout (Git for Windows default) broke SBCL's compile-time
  checking of literal `format` control strings with tilde-newline
  continuations.
- New and renamed verification-time regression tests pin the type
  rules the guards actually enforce, including
  `negative-verification-time-is-rejected`, which asserts the signaled
  condition is not `tls-certificate-not-yet-valid`.
