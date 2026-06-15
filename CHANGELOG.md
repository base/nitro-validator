# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project aims to follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[2.0.0-rc.1]: https://github.com/base/nitro-validator/releases/tag/v2.0.0-rc.1
