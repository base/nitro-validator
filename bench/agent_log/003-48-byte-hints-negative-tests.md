# 003 — 48-byte hints and negative tests

Date: 2026-06-02
Status: ✅ complete

## Hypothesis

The hinted verifier should accept compact 48-byte P384 inverse witnesses while
still rejecting malformed witness streams.

## Implementation

Benchmark-only changes:

- `collectInverseHints(...)` now writes each inverse as 48 big-endian bytes.
- `_nextInverseHint()` reconstructs Solarity's internal two-word `U384`
  representation from each packed hint.
- Added malformed-hint tests:
  - `test_HintedInversionRejectsMutatedHint`
  - `test_HintedInversionRejectsTruncatedHints`
  - `test_HintedInversionRejectsSurplusHints`

## Results

Command:

```sh
forge test --match-path test/bench/Bench.t.sol --gas-report -vv
```

Prototype output with 48-byte witnesses:

| metric | value |
|--------|------:|
| hinted verify gas, EIP-2565 | 5,391,727 |
| MODEXP calls | 3,048 |
| — field inversions | 0 |
| — other / checks | 3,048 |
| projected verify gas, EIP-7883 | 6,306,127 |
| + witness calldata, worst-case | 437,760 |
| **= total post-Fusaka** | **6,743,887** |
| fits 1 tx post-Fusaka? | YES |
| witness bytes / verify | 27,360 |

Focused test results:

- `test_Baseline`: pass
- `test_HintedInversionModel`: pass
- `test_HintedInversionPrototype`: pass
- `test_HintedInversionRejectsMutatedHint`: pass
- `test_HintedInversionRejectsTruncatedHints`: pass
- `test_HintedInversionRejectsSurplusHints`: pass

Full suite:

```sh
forge test --gas-report
```

Result: 32 passed, 0 failed.

## Outcome

The compact hinted verifier stays well under the post-Fusaka per-transaction cap.
The current prototype is about **6.74M gas per P384 verify** including pessimistic
calldata gas. This leaves roughly **10.0M gas** of margin under EIP-7825 for
certificate parsing, SHA-384, storage writes, and production API overhead.

## Caveats

- The implementation is benchmark-only and uses transient storage helpers for
  collection/counters.
- The off-chain witness generator still needs to be built; the test collector
  simulates replay-derived witnesses.
- The verifier still uses MODEXP for floor-priced modular multiplication /
  reduction. That is acceptable for the cap, but it is not fully repricing-proof.
- The production API should not silently alter the existing verifier; it should
  expose an explicit hinted verifier ABI.

## Recommended next step

→ Experiment 004: measure the hinted verifier inside the cert / Nitro path.

Concrete plan:

1. Add a benchmark-only `CertManager` variant that calls a hinted P384 verifier.
2. Use collected hints for one existing cert signature from `CertManager.t.sol`.
3. Measure `verifyCACert` and `verifyClientCert` current gas and projected
   EIP-7883 gas.
4. Repeat for the hot `validateAttestation` path.
5. Decide whether the full per-cert transaction has enough margin after parsing,
   SHA-384, calldata, and storage overhead.

## Artifacts

- `test/bench/ECDSA384Bench.sol`
- `test/bench/Bench.t.sol::test_HintedInversionPrototype`
- `test/bench/Bench.t.sol::test_HintedInversionRejectsMutatedHint`
- `test/bench/Bench.t.sol::test_HintedInversionRejectsTruncatedHints`
- `test/bench/Bench.t.sol::test_HintedInversionRejectsSurplusHints`
