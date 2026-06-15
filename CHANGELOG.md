# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project aims to follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Operational certificate revocation in `CertManager`: an owner-managed `revoker` can mark one or
  many certificates revoked, and the owner can rotate the revoker or undo accidental revocations.
- `CertManager.computeCertId(certDER)`: returns a certificate's `(issuer, serial)` revocation
  identity key.
- `CborDecode.skipValue`: a generic CBOR data-item skipper used to walk over values of unknown shape.

### Changed
- Certificate verification and cached reuse now reject revoked certificates and revoked cached
  parent-chain ancestors independently of `notAfter`.
- Revocation is keyed by the `(issuer, serial)` identity `keccak256(issuerHash, serialHash)` (what
  AWS CRLs use), not by `keccak256(certBytes)`. Byte-keying was bypassable, because ECDSA signature
  malleability and DER re-encoding let a revoked certificate be re-presented with different bytes
  that still verify; the signature-protected identity closes that gap and lets operators revoke
  directly from CRL issuer/serial entries.
- Root certificate revocation is owner-only (keyed by the pinned `ROOT_CA_CERT_HASH`, since the root
  is never parsed on-chain), while non-root revocation remains delegated to the revoker role.
- Cold certificate verification rejects submitted cert bytes with trailing data or fields after the
  signature.
- Attestation parser is now forward-compatible with AWS COSE payload format changes: unrecognised
  map keys are skipped instead of reverting, and the payload map plus the nested `pcrs` map and
  `cabundle` array are accepted in both definite- and indefinite-length CBOR encodings. Malformed
  encodings still revert (reserved headers, odd-length maps, mismatched indefinite-string chunks, a
  missing break marker). These are liveness-only changes — the whole payload is still verified
  against AWS's COSE signature, so an ignored or re-encoded field can never change the accept
  decision.

### Fixed
- Reject non-canonical P-384 public key coordinates greater than or equal to the field prime `p`.

## [2.0.0-rc.1] - 2026-06-09

First release candidate of the **hinted P-384** rework. This is a major, breaking change motivated
by the Fusaka upgrade (EIP-7883), which raises `MODEXP` pricing enough that the previous fully
on-chain attestation verification no longer fits in a block on Base. Verification now moves the
modular inversions off-chain as calldata "hints" that are re-verified on-chain (`b · inv ≡ 1 mod m`),
so a wrong hint can only revert, never forge — the accept rule is unchanged.

This is a release candidate: it is intended for the human security audit and partner evaluation, not
yet a general-availability release.

### Changed (breaking)
- Verification is now hinted. Use `CertManager.verifyCACertWithHints` /
  `verifyClientCertWithHints` and `NitroValidator.validateAttestationWithHints`.
- Constructors now take an `IP384Verifier`: deploy `P384Verifier` → `CertManager(p384Verifier)` →
  `NitroValidator(certManager, p384Verifier)`.
- `validateAttestationWithHints` requires the certificate bundle to be verified/cached first; an
  uncached bundle reverts with `"inverse hint underflow"`.

### Removed
- The fully on-chain (non-hinted) verification path. `verifyCACert`, `verifyClientCert`, and
  `validateAttestation` are retained only as reverting stubs (marked deprecated) for ABI continuity.

### Added
- `IP384Verifier` / `P384Verifier` (swappable hinted P-384 verifier) and `ECDSA384Curve` params.
- Off-chain hint generator and tooling under `tools/` (Node.js, no dependencies), cross-checked for
  byte-identical parity with the on-chain reference via FFI tests.
- `docs/hinted-p384-nitro-attestation.md` design/security/gas spec.
- CI job running the FFI hint-parity tests.
- Negative tests: expired cert (cold & cached), validity boundary, out-of-range scalar rejection;
  and malformed-input / fuzz tests for the DER, CBOR, and byte-slicing parsers.

### Internal / hygiene
- Vendored the P-384 verifier (`src/vendor/ECDSA384.sol`, `MemoryUtils.sol`) from
  `dl-solarity/solidity-lib`, removing the personal-fork submodule; provenance and the exact
  upstream diff are recorded in `src/vendor/`.
- Documented integrator responsibilities (freshness/replay, signature malleability, enclave policy)
  in NatSpec, the README, and the design doc.
- Moved the demo `CertManagerDemo` out of `src/` into `test/helpers/`.

[Unreleased]: https://github.com/base/nitro-validator/compare/v2.0.0-rc.1...HEAD
[2.0.0-rc.1]: https://github.com/base/nitro-validator/releases/tag/v2.0.0-rc.1
