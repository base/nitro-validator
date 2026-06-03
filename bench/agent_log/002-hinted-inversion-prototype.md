# 002 — Hinted inversions (prototype)

Date: 2026-06-02
Status: ✅ complete

## Hypothesis

The analytical hinted-inversion model from 001 should survive real Solidity
control flow: replace every Fermat inversion MODEXP with a caller-supplied inverse
witness, then constrain the witness on-chain with `a * a_inv == 1 mod m`.

## Implementation

Benchmark-only changes:

- Added `ECDSA384Bench.verifyWithHints(...)`.
- Added a transient-storage hint cursor.
- Added inverse-hint collection for test replay.
- Added `BenchHarness.collectInverseHints(...)`.
- Added `BenchHarness.countHintedVerify(...)`.
- Added `BenchTest.test_HintedInversionPrototype()`.

The first passing prototype used 64-byte witnesses because that matches Solarity's
internal two-word `U384` representation. This was intentionally not production
encoding; experiment 003 packs witnesses to 48 bytes.

## Debug finding

The first attempt failed with `bad inverse hint`.

Root cause: scalar inversions are modulo the curve order `n`, while field
inversions are modulo the field prime `p`. The initial hint check verified every
inverse modulo `p`, which correctly rejected the two scalar inverse witnesses.

Fix: add a modulus-specific multiplication check for `modinv(..., m_)`.

## Results

Command:

```sh
forge test --match-path test/bench/Bench.t.sol --gas-report -vv
```

Prototype output with 64-byte witnesses:

| metric | value |
|--------|------:|
| hinted verify gas, EIP-2565 | 5,440,654 |
| MODEXP calls | 3,048 |
| — field inversions | 0 |
| — other / checks | 3,048 |
| projected verify gas, EIP-7883 | 6,355,054 |
| + witness calldata, worst-case | 583,680 |
| **= total post-Fusaka** | **6,938,734** |
| fits 1 tx post-Fusaka? | YES |
| witness bytes / verify | 36,480 |

## Outcome

The hinted-inversion approach is empirically viable in a benchmark copy. Even
with unoptimized 64-byte witnesses and real witness-check overhead, one P384
verify projects to about **6.94M** gas post-Fusaka including pessimistic calldata
gas, far below the 16,777,216 cap.

## Recommended next step

→ Experiment 003: pack witnesses to 48 bytes and add malformed-hint tests.

## Artifacts

- `test/bench/ECDSA384Bench.sol::verifyWithHints`
- `test/bench/Bench.t.sol::test_HintedInversionPrototype`
