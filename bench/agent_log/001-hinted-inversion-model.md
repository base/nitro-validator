# 001 — Hinted inversions (analytical model)

Date: 2026-06-02
Status: ✅ modelled (empirically parameterized) — followed by 002/003 prototypes

## Hypothesis

Field inversion via Fermat (`a^(p-2) mod p`, a 64-byte-operand MODEXP) is 97% of
the post-Fusaka MODEXP gas. Inversion is *expensive to compute* but *cheap to
verify*: if the caller supplies `a_inv` as calldata, the contract confirms it with
a single modular multiply `a · a_inv ≡ 1 (mod p)`. All values are public
(verification, not signing), so there is no secrecy concern. Each `moddiv` changes
from {1 inversion + 1 mulmul} to {2 mulmuls}.

Soundness: the witness MUST be fully constrained on-chain (`a·a_inv == 1 mod p`).
An unconstrained supplied inverse is a signature-forgery vector.

## Model (parameterized by the measured census: 570 inv, 2478 other)

`test/bench/Bench.t.sol::test_HintedInversionModel`

| metric | value |
|--------|-------|
| non-MODEXP verify gas (unchanged) | 2,786,421 |
| hinted verify gas, EIP-2565 | **3,396,021** |
| hinted verify gas, EIP-7883 | **4,310,421** |
| + witness calldata (570×48 B, worst-case 16/B) | 437,760 |
| **= total post-Fusaka** | **4,748,181** |
| fits 1 tx post-Fusaka? | **YES** (cap 16,777,216) |
| witness bytes / verify | 27,360 |

## Outcome

- Post-Fusaka single verify: **50.6M → ~4.75M** (~11× reduction), comfortably under
  the cap with ~3.5M of headroom for parsing/SHA-384/overhead.
- Bonus: at *current* pricing the hinted verify (~3.4M) is also ~2.3× cheaper than
  today's 7.94M.
- Full cold chain (~7 verifies) → ~33M, splits per-cert into 2–3 txs, each well
  under cap; hot path (2 verifies) ~10M fits a single tx.
- This makes the pure-EVM path viable and immune to the EIP-7883 *inversion* blow-up
  without ZK.

## Caveats / open questions for the prototype

1. **Witness plumbing**: ~570 inverses must thread from calldata into each `moddiv`
   site. Need a calldata layout + cursor; the offchain prover replays the verify to
   emit them in order.
2. **Remaining 0x5 dependence**: the 3,048 remaining mulmuls/squarings still call
   MODEXP at the 500-gas floor (~1.5M total post-Fusaka). Optional follow-up:
   replace modexp-based reduction with pure-Yul Montgomery/Barrett to be *fully*
   immune to 0x5 repricing. Probably unnecessary given the headroom — measure first.
3. **Calldata on L2**: 27 KB/verify also incurs Base L1-data-availability cost
   (separate from execution gas). Worth a real cost estimate; blob calldata helps.
4. **Audit**: this modifies audited cryptographic core (`ECDSA384.sol`). Re-audit
   the witness constraint and the existing `r` vs `r+n` edge case.

## Follow-up

- **002 (prototype)** completed a benchmark-only hinted verifier and measured real
  overhead.
- **003** packed witnesses to 48 bytes and added malformed-hint tests.
- **004** should measure the hinted verifier inside the certificate / Nitro path.
