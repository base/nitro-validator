# 006 - Production-shaped hinted flow

Date: 2026-06-02
Status: complete

## Question

Can the hinted-inversion P384 path be represented as a production-shaped API for
the split Nitro flow, and do the real attestation certificate and cached
attestation transactions still fit under the 16,777,216 gas cap after EIP-7883?

## Method

Extended benchmark-only code:

- `test/bench/ECDSA384Bench.sol`
- `test/bench/HintedNitroBench.sol`
- `test/bench/RealAttestationBench.t.sol`

Changes:

1. Replaced the verifier-side transient-storage hint cursor with an explicit
   memory cursor stored in the `U384Bench` call context.
2. Kept transient storage only in the benchmark collector that generates witness
   bytes for tests.
3. Added production-shaped benchmark APIs:
   - `verifyCACertWithHints(cert, parentCertHash, signatureHints)`
   - `verifyClientCertWithHints(cert, parentCertHash, signatureHints)`
   - `validateAttestationWithHints(attestationTbs, signature, attestationSigHints)`
4. Added `P384HintCollectorBench`, which emits one packed `bytes` stream per P384
   verification. Each inverse witness is exactly 48 bytes, big-endian, and
   consumed sequentially.
5. Projected post-Fusaka gas from measured hinted EIP-2565 gas by adding:

```text
hinted MODEXP floor calls * (500 - 200) + inverseHintBytes * 16
```

The calldata term is pessimistic execution gas for all-nonzero witness bytes.

## Results

Commands:

```sh
forge test --match-path test/bench/Bench.t.sol -vv
forge test --match-path test/bench/RealAttestationBench.t.sol -vv
forge test
forge test --gas-report
```

All tests passed: `37 passed, 0 failed`.

### Isolated P384

| metric | value |
|--------|------:|
| current unhinted verify | 7,938,921 |
| projected unhinted post-Fusaka | 50,646,861 |
| current hinted verify | 4,688,649 |
| hinted MODEXP floor calls | 3,048 |
| projected hinted post-Fusaka, excluding calldata | 5,603,049 |
| inverse witness bytes | 27,360 |
| projected hinted post-Fusaka, including calldata | 6,040,809 |

### Real attestation, production-shaped per-cert split

| step | current hinted gas | hint bytes | hinted MODEXP floor calls | projected post-Fusaka | fits cap? |
|------|-------------------:|-----------:|--------------------------:|----------------------:|:---------:|
| cabundle[0] root | 25,230 | 0 | 0 | 25,230 | YES |
| cabundle[1] | 6,074,268 | 27,456 | 3,056 | 7,430,364 | YES |
| cabundle[2] | 6,309,056 | 27,408 | 3,052 | 7,663,184 | YES |
| cabundle[3] | 6,075,746 | 27,408 | 3,052 | 7,429,874 | YES |
| client cert | 6,094,419 | 27,504 | 3,060 | 7,452,483 | YES |

### Real attestation, cached hot path

| metric | value |
|--------|------:|
| current hinted cached gas | 12,987,344 |
| inverse hint bytes | 27,312 |
| hinted MODEXP floor calls | 3,044 |
| projected post-Fusaka | 14,337,536 |
| fits cap? | YES |

## Outcome

The production-shaped hinted flow improves the prior replacement projection and
stays comfortably under the EIP-7825 per-transaction cap:

- Cold split cert transactions: about 7.43M-7.66M gas post-Fusaka.
- Cached hot attestation transaction: about 14.34M gas post-Fusaka.

This confirms that the near-term pure-EVM path is viable if the Nitro flow is
split into cert-cache transactions plus a cached attestation validation
transaction.

## Soundness notes

- Each supplied inverse is constrained on-chain by `denominator * inverse == 1`
  modulo the relevant modulus.
- Truncated, mutated, and surplus hints are rejected in the isolated P384 tests.
- The production-shaped attestation path has a surplus-hint negative test.
- The benchmark witness collector still uses transient storage, but that is only
  the test oracle. The verifier-under-measure carries hint state in memory.

## Caveats

- This is still benchmark-only code. Production `src/` remains untouched.
- The API currently takes `bytes memory`, matching existing contract style. A
  deployment version should consider `bytes calldata` for external methods.
- The witness generator is not yet an off-chain CLI; it is a benchmark helper
  that replays the verification and emits the exact packed inverse stream.
- Base L1 data fees for witness payloads are not included in execution gas.

## Recommended next step

Experiment 007 should turn this into an integration sketch:

1. Add production interfaces for hinted cert caching and hinted attestation
   validation.
2. Implement an off-chain witness generator CLI that emits one hint blob per
   cert signature and one hint blob for the COSE attestation signature.
3. Price Base calldata/L1 data cost for the 27KB witness blobs.
4. Add a sequencing benchmark or script for the full cold flow:
   root -> intermediate CAs -> client cert -> cached attestation.
