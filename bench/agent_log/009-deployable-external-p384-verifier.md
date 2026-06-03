# 009 - Deployable external P384 verifier

Date: 2026-06-02
Status: complete

## Question

Can the hinted production candidate be made deployable under EIP-170 while
preserving the post-Fusaka split-flow gas result?

## Method

The 008 contracts embedded hinted P384 verification into both the cert manager
and the attestation validator. That kept the code easy to audit, but left the
hinted contracts over the runtime bytecode limit.

This experiment split P384 into a shared external verifier and made the hinted
manager/validator hinted-only:

- `src/IP384Verifier.sol`
- `src/P384Verifier.sol`
- `src/CertManagerHintedExternal.sol`
- `src/NitroValidatorHintedExternal.sol`

The canonical hinted names now wrap the externalized variants:

- `src/CertManagerHinted.sol`
- `src/NitroValidatorHinted.sol`

The benchmark test now deploys:

```text
P384Verifier
CertManagerHinted(P384Verifier)
NitroValidatorHinted(CertManagerHinted, P384Verifier)
```

`CertManagerHinted` still implements `ICertManager` through
`IHintedCertManager`, but its unhinted `verifyCACert` and `verifyClientCert`
entrypoints intentionally revert with `use hinted cert verification`.

## Results

Source-only size command:

```sh
forge build src --sizes
```

Deployable runtime sizes:

| contract | runtime size | EIP-170 margin |
|----------|-------------:|---------------:|
| `P384Verifier` | 7,805 bytes | 16,771 bytes |
| `CertManagerHinted` | 18,496 bytes | 6,080 bytes |
| `NitroValidatorHinted` | 13,101 bytes | 11,475 bytes |

The `test/bench` instrumentation contracts remain oversized and are intentionally
excluded from the deployable source-size check.

Focused sequence command:

```sh
forge test --match-path test/bench/RealAttestationBench.t.sol --match-test test_007_FullColdAndWarmHintedSequence -vv
```

Focused result: `1 passed, 0 failed`.

Full verification:

```sh
forge test
```

Full suite result: `47 passed, 0 failed`.

Gas-report command:

```sh
forge test --gas-report --match-path test/bench/RealAttestationBench.t.sol
```

Gas-report result: `15 passed, 0 failed`.

### Deployable Full Sequence

| tx | action | current hinted gas | hint bytes | hinted MODEXP floor calls | projected post-Fusaka | fits cap? |
|----|--------|-------------------:|-----------:|--------------------------:|----------------------:|:---------:|
| 1 | cache CA cert | 5,441,446 | 27,456 | 3,056 | 6,797,542 | YES |
| 2 | cache CA cert | 5,674,610 | 27,408 | 3,052 | 7,028,738 | YES |
| 3 | cache CA cert | 5,441,378 | 27,408 | 3,052 | 6,795,506 | YES |
| 4 | cache client cert | 5,458,159 | 27,504 | 3,060 | 6,816,223 | YES |
| 5 | validate attestation | 12,330,471 | 27,312 | 3,044 | 13,680,663 | YES |

Cold sequence totals:

| metric | value |
|--------|------:|
| current gas total | 34,346,064 |
| projected post-Fusaka total | 41,118,672 |
| max projected tx gas | 13,680,663 |
| per-tx cap | 16,777,216 |

Warm validation:

| tx | action | current hinted gas | hint bytes | hinted MODEXP floor calls | projected post-Fusaka | fits cap? |
|----|--------|-------------------:|-----------:|--------------------------:|----------------------:|:---------:|
| 1 | warm validate | 12,287,414 | 27,312 | 3,044 | 13,637,606 | YES |

## Tests Added

- `test_009_DeployableHintedContractsFitEIP170`
- `test_009_DeployableCertManagerDisablesUnhintedEntrypoints`

These supplement the 008 negative tests for:

- mutated cert hints,
- truncated cert hints,
- wrong parent hashes,
- expired cached certs,
- cached CA/client role mismatch,
- missing warm cache,
- invalid final attestation signatures,
- surplus final attestation hints.

## Soundness Notes

- Externalizing P384 does not trust the verifier caller. Hints are still consumed
  inside `ECDSA384Hinted` and each inverse is constrained before use.
- `CertManagerHinted` disables the inherited unhinted interface methods, so a
  caller cannot accidentally route through the old MODEXP-heavy path on the
  hinted manager.
- `NitroValidatorHinted` has no unhinted validation method. Its cached cert
  bundle checks still pass empty hint streams, which means missing cache entries
  fail rather than falling back to cert signature verification.
- The external verifier address is immutable in both `CertManagerHinted` and
  `NitroValidatorHinted`.
- The external call adds a small gas cost, but the max projected transaction
  remains 3.10M gas below the 16.78M cap.

## Outcome

The deployable hinted architecture satisfies both constraints measured so far:

- every deployable hinted runtime is below EIP-170,
- the full real-attestation cold and warm flows remain below the EIP-7825
  per-transaction cap after the EIP-7883 projection.

## Recommended Next Step

Experiment 010 should focus on turning the Solidity witness oracle into an
off-chain witness generator and hardening equivalence tests:

1. Add a CLI that parses a DER cert or COSE attestation signature and emits the
   exact 48-byte inverse hint stream expected by `P384Verifier`.
2. Cross-check CLI output against `P384HintCollectorBench` for the real fixture.
3. Add direct equivalence tests for `P384Verifier` vs the unhinted verifier on
   known-good and known-bad signatures.
4. Expand `docs/hinted-p384-nitro-attestation.md` with code-reference tables for
   each invariant before audit handoff.
