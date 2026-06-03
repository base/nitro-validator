# 008 - Production candidate and audit docs

Date: 2026-06-02
Status: complete

## Question

Can the benchmark-only hinted flow be moved into additive production candidate
contracts, with audit-oriented documentation and full-flow negative tests?

## Method

Added production candidate files:

- `src/ECDSA384Hinted.sol`
- `src/IHintedCertManager.sol`
- `src/CertManagerHinted.sol`
- `src/NitroValidatorHinted.sol`

Added audit documentation:

- `docs/hinted-p384-nitro-attestation.md`

Updated benchmark tests:

- `test/bench/RealAttestationBench.t.sol`

The original unhinted contracts remain unchanged. The hinted path is additive.

## Implementation Summary

`ECDSA384Hinted` is a production candidate derived from the benchmark verifier:

- verifier-side transient-storage hint cursor removed,
- benchmark counters removed,
- benchmark inverse collector removed,
- hint state carried in the P384 call context memory,
- every supplied inverse constrained with modular multiplication,
- truncated and surplus hint streams rejected.

`CertManagerHinted` adds:

- `verifyCACertWithHints`
- `verifyClientCertWithHints`
- `loadVerified`

`NitroValidatorHinted` adds:

- `validateAttestationWithHints`

The hinted validator uses empty hint streams for cert bundle checks:

```text
verifyCACertWithHints(cert, parentHash, "")
verifyClientCertWithHints(cert, parentHash, "")
```

Cached certs return before signature verification. Missing certs reach hinted
P384 verification with an empty stream and revert, which prevents accidental
fallback to the unhinted P384 path.

## Results

Focused command:

```sh
forge test --match-path test/bench/RealAttestationBench.t.sol -vv
```

Focused result: `13 passed, 0 failed`.

Full verification:

```sh
forge test
forge test --gas-report
```

Full suite result: `45 passed, 0 failed`.

### Production Candidate Full Sequence

| tx | action | current hinted gas | hint bytes | hinted MODEXP floor calls | projected post-Fusaka | fits cap? |
|----|--------|-------------------:|-----------:|--------------------------:|----------------------:|:---------:|
| 1 | cache CA cert | 5,424,159 | 27,456 | 3,056 | 6,780,255 | YES |
| 2 | cache CA cert | 5,659,854 | 27,408 | 3,052 | 7,013,982 | YES |
| 3 | cache CA cert | 5,426,606 | 27,408 | 3,052 | 6,780,734 | YES |
| 4 | cache client cert | 5,443,681 | 27,504 | 3,060 | 6,801,745 | YES |
| 5 | validate attestation | 12,351,354 | 27,312 | 3,044 | 13,701,546 | YES |

Cold sequence totals:

| metric | value |
|--------|------:|
| current gas total | 34,305,654 |
| projected post-Fusaka total | 41,078,262 |
| max projected tx gas | 13,701,546 |
| per-tx cap | 16,777,216 |

Warm validation:

| tx | action | current hinted gas | hint bytes | hinted MODEXP floor calls | projected post-Fusaka | fits cap? |
|----|--------|-------------------:|-----------:|--------------------------:|----------------------:|:---------:|
| 1 | warm validate | 12,308,297 | 27,312 | 3,044 | 13,658,489 | YES |

## Negative Tests Added

The production candidate rejects:

- mutated cert hint: `bad inverse hint`,
- truncated cert hint: `inverse hint underflow`,
- wrong parent hash: `parent cert unverified`,
- expired cached cert: `cert expired`,
- cached CA/client role mismatch: `cert is not a CA`,
- missing warm cache: `inverse hint underflow`,
- invalid final attestation signature,
- surplus final attestation hint: `unused inverse hints`.

## Deployment Caveat

The production candidate is audit-friendly but not yet deployment-size optimized.
Gas-report deployment sizes:

| contract | deployed size |
|----------|--------------:|
| `CertManager` | 25,315 bytes |
| `CertManagerHinted` | 30,947 bytes |
| `NitroValidatorHinted` | 25,745 bytes |

This needs a dedicated size-reduction pass before Base deployment. The most
likely direction is moving P384 verification behind a shared verifier contract or
linked-library boundary so it is not embedded into multiple large contracts.

## Outcome

The production candidate preserves the post-Fusaka result with better measured
gas than the benchmark wrapper:

- minimum cold flow: 5 transactions,
- optional root no-op flow: 6 transactions,
- warm flow: 1 transaction,
- largest projected transaction: 13.70M gas.

The audit documentation now has the initial threat model, ABI, witness format,
invariants, cold/warm cache semantics, failure modes, gas table, and deployment
caveat.

## Recommended Next Step

Experiment 009 should focus on deployability and audit hardening:

1. Reduce deployed bytecode size below chain limits.
2. Decide whether P384 should be an external verifier contract, linked library,
   or split CertManager/NitroValidator deployment.
3. Add equivalence tests between `ECDSA384.verify` and `ECDSA384Hinted.verify`
   across multiple signatures.
4. Turn the Solidity witness collector into an off-chain CLI.
5. Continue expanding the audit doc with exact code references and sequence
   diagrams.
