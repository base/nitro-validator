# Vendored dependencies

These files are vendored (copied in-tree) from the Solarity `solidity-lib` so that
nitro-validator is self-contained and the cryptographic code audited here is exactly
the code that is deployed — with no dependency on an external submodule or fork.

| File | Source path in solidity-lib | Modified? |
|------|------------------------------|-----------|
| `ECDSA384.sol` | `contracts/libs/crypto/ECDSA384.sol` (contains both `ECDSA384` and `U384`) | **Yes** — see below |
| `MemoryUtils.sol` | `contracts/libs/utils/MemoryUtils.sol` | No (verbatim) |

## Source & license

- Upstream: https://github.com/dl-solarity/solidity-lib
- Base commit (unmodified upstream): `b947757194de6436062c2d68118c0352be84ac4be`
- License: MIT, Copyright (c) 2023 Solarity (SPDX headers retained on each file).

The only imports either file makes are between these two vendored files; nothing else
from `solidity-lib` is used by this repo.

## Local modifications (audit focus)

`ECDSA384.sol` carries two functional changes on top of the base commit:

- **"Add hinted P384 inverse verification"** — adding `verifyWithHints` /
  `verifyWithHintsConsumed` and the hint-consumption paths in `U384`
  (`initCallWithHints`, `_nextInverseHint`, the hinted branches of `moddivAssign` /
  `modinv`).
- **Strict public key coordinate bounds** — `_isOnCurve` rejects coordinates `>= p`,
  not only `== p`, so non-canonical 48-byte field encodings cannot pass the curve
  equation modulo `p`.

The exact upstream diff is committed next to the file as
[`ECDSA384.hinted.patch`](./ECDSA384.hinted.patch) so reviewers can see precisely
the delta from audited upstream code.

**Safety summary:** every off-chain-supplied inverse `inv` is verified on-chain with
`require(b·inv ≡ 1 (mod m), "bad inverse hint")` before use, plus a bounds check
(`"inverse hint underflow"`) and an exact-consumption check (`"unused inverse hints"`).
Because the moduli (`n`, `p`) are prime, the inverse is unique, so a malicious hint can
only cause a revert — never a false accept. The acceptance rule is identical to upstream
`ECDSA384.verify`. See `docs/hinted-p384-nitro-attestation.md` for the full argument.

## Re-syncing with upstream

To pull a newer upstream `ECDSA384.sol`/`MemoryUtils.sol`, re-copy from the desired
commit, re-apply `ECDSA384.hinted.patch` (or re-derive the hinted change), update the
base commit hash above, and re-run the test suite (including the FFI parity tests).
