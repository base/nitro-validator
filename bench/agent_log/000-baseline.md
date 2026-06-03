# 000 — Baseline

Date: 2026-06-02
Status: ✅ complete

## Question

Given Fusaka's MODEXP repricing (EIP-7883) and the 16,777,216 per-tx gas cap
(EIP-7825), can the existing nitro-validator P384 path land on Base? Where does
the gas actually go?

## Method

- `forge test` + `gasleft()` for ground-truth current gas (uninstrumented).
- Instrumented copy `test/bench/ECDSA384Bench.sol` with transient counters for an
  exact MODEXP census (inversions vs. other) — see `bench/README.md`.
- Post-Fusaka projection via exact EIP-2565 / EIP-7883 per-call formulas.

## Results

### Full attestation (cold, all certs, one tx)
- `validateAttestation`: **53.4M gas** (measured, `NitroValidator.t.sol`).
  README quotes ~63M; current measured is 53.4M.

### Single ECDSA-P384 verify (the hot unit)
| metric | value |
|--------|-------|
| measured gas (EIP-2565) | **7,938,921** |
| MODEXP calls | 3,048 |
| — field inversions | **570** |
| — other (sq/mul/reduce) | 2,478 |
| MODEXP gas now (EIP-2565) | 5,152,500 (64% of verify) |
| MODEXP gas post-Fusaka (EIP-7883) | 47,860,440 |
| **projected verify post-Fusaka** | **50,646,861 (6.37×)** |
| per-tx cap (EIP-7825) | 16,777,216 |
| fits in 1 tx post-Fusaka? | **NO — ~3× over** |

Inversions are **97%** of the post-Fusaka MODEXP gas (570 × 81,792 = 46.6M).

### Where the inversions live (phase breakdown)
| phase | inversions | other | post-Fusaka MODEXP gas |
|-------|-----------:|------:|-----------------------:|
| on-curve check | 0 | 3 | 1,500 |
| scalar divisions (2× moddiv) | 2 | 2 | 164,584 |
| precompute table | 61 | 187 | 5,082,812 |
| **double-scalar-mult (ladder)** | **507** | 2,285 | **42,611,044** |
| final mod | 0 | 1 | 500 |

The scalar-mult ladder holds 89% of inversions / 84% of post-Fusaka MODEXP gas.
The 61 precompute-table inversions include the **fixed-base** (generator G)
multiples, which are constant and could be hoisted to compile-time constants
(no witness, no calldata) — a free secondary win.

## Findings that correct the prior analysis

1. **"Switch to Jacobian/projective is the dominant win" — FALSE for this repo.**
   The library is already affine + Strauss-Shamir with 6-bit precompute, and its
   own header states projective was tried and was *worse* (~9M vs ~8M) in pure EVM,
   because EVM trades cheap MODEXP inversions for many more mulmuls. Going
   projective is not free wins here; it may even regress.

2. **"~3× repricing" — understated.** For the 64-byte operand profile this library
   uses, a single inversion goes 8,170 → 81,792 ≈ **10×**, not 3×.

3. **Per-cert splitting is already implemented and is NOT sufficient.** `CertManager`
   already pins the AWS root as a constant, caches verified intermediates, supports
   skip-if-verified, and exposes `verifyCACert(cert, parentHash)` for per-cert txs.
   But a *single* ECDSA verify is atomic and is itself ~50.6M post-Fusaka — ~3× the
   cap. **You cannot split one signature check across transactions** without making
   the scalar-mult ladder resumable (storing point state in SSTORE between txs —
   expensive and ugly). So splitting helps the chain, not the unit.

4. **The architecture levers in the prior writeup are already done** (root pinning,
   intermediate caching, 2-verify hot path). The remaining problem is purely the
   per-verify cost.

## Conclusion

Optimization is **mandatory**, not optional: post-Fusaka, no single P384 verify
fits in a Base transaction. The target is unambiguous — **eliminate the 570
on-chain field inversions** (97% of post-Fusaka MODEXP gas).

## Recommended next step

→ Experiment 001: model caller-supplied inverse *witnesses* verified by one modmul
each (eliminates on-chain `modinv`). See `001-hinted-inversion-model.md`.

## Artifacts
- `test/bench/Bench.t.sol::test_Baseline`
- `test/bench/ECDSA384Bench.sol` (instrumented census copy)
