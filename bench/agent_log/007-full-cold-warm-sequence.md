# 007 - Full cold and warm hinted sequence

Date: 2026-06-02
Status: complete

## Question

Can we demonstrate the full Nitro attestation path as the transactions we would
submit on-chain, and distinguish the cold cert-cache setup from the warm-cache
reuse path?

## Method

Extended:

- `test/bench/RealAttestationBench.t.sol`

Added:

- `test_007_FullColdAndWarmHintedSequence`

The test starts from a fresh `HintedCertManagerBench`, whose constructor has only
the AWS Nitro root pinned. It then:

1. Decodes the real attestation fixture into `attestationTbs` and `signature`.
2. Parses cabundle pointers from the attestation payload.
3. Confirms `cabundle[0]` is the pinned AWS Nitro root cert.
4. Submits the minimum cold sequence:
   - non-root CA cert 1
   - non-root CA cert 2
   - non-root CA cert 3
   - client/leaf cert
   - final attestation validation
5. Submits the warm-cache validation again as one transaction.

Projection formula remains:

```text
postFusakaGas = currentHintedGas
              + hinted MODEXP floor calls * (500 - 200)
              + inverseHintBytes * 16
```

The final term is pessimistic execution gas for all-nonzero hint calldata.

## Cold vs warm cache

Cold cache means the non-root certificate chain and leaf/client cert have not
yet been verified into `CertManager.verified`.

Warm cache means those cert hashes are already stored in `CertManager.verified`
and are still valid at `block.timestamp`. A later attestation can reuse the
cached certs if it uses the exact same DER cert bytes and the same cached
leaf/client certificate. The final attestation signature still needs its own
P384 verification and its own hint blob.

The AWS Nitro root is not a cold-cache transaction in this repo because it is
pinned in `CertManager` at deployment. If we also submit a root no-op check for
operational symmetry, this fixture becomes 6 transactions instead of the minimum
5.

## Results

Command:

```sh
forge test --match-path test/bench/RealAttestationBench.t.sol -vv
```

All focused tests passed: `6 passed, 0 failed`.

Full suite:

```sh
forge test
forge test --gas-report
```

Full suite passed: `38 passed, 0 failed`.

### Cold sequence

Minimum transaction count for this fixture: **5**.

| tx | action | current hinted gas | hint bytes | hinted MODEXP floor calls | projected post-Fusaka | fits cap? |
|----|--------|-------------------:|-----------:|--------------------------:|----------------------:|:---------:|
| 1 | cache CA cert | 6,074,285 | 27,456 | 3,056 | 7,430,381 | YES |
| 2 | cache CA cert | 6,309,132 | 27,408 | 3,052 | 7,663,260 | YES |
| 3 | cache CA cert | 6,075,884 | 27,408 | 3,052 | 7,430,012 | YES |
| 4 | cache client cert | 6,094,655 | 27,504 | 3,060 | 7,452,719 | YES |
| 5 | validate attestation | 12,990,821 | 27,312 | 3,044 | 14,341,013 | YES |

Cold sequence totals:

| metric | value |
|--------|------:|
| current gas total | 37,544,777 |
| projected post-Fusaka total | 44,317,385 |
| max projected tx gas | 14,341,013 |
| per-tx cap | 16,777,216 |

### Warm sequence

Warm-cache transaction count: **1**.

| tx | action | current hinted gas | hint bytes | hinted MODEXP floor calls | projected post-Fusaka | fits cap? |
|----|--------|-------------------:|-----------:|--------------------------:|----------------------:|:---------:|
| 1 | warm validate | 12,947,764 | 27,312 | 3,044 | 14,297,956 | YES |

## Outcome

The full cold path is under the EIP-7825 cap transaction-by-transaction after
EIP-7883, using the hinted P384 path:

- Minimum cold flow for this fixture: **5 transactions**.
- Optional root no-op replay: **6 transactions**.
- Warm-cache flow: **1 transaction**.
- Largest projected transaction: **14.34M gas**, leaving about **2.44M gas** of
  headroom under the 16.78M cap.

The important architectural conclusion is that the full cold flow does not need
one giant transaction. The cert chain is converted into durable on-chain cache
state first, and the final validation transaction then reuses that cache.

## Audit notes

- The root cert is trusted only because its hash/pubkey are pinned by the
  deployed `CertManager` constructor.
- Every non-root cert transaction verifies the parent is cached, unexpired, a CA,
  and has remaining path length before writing the child cert to cache.
- The client cert is cached as non-CA and rejected if later loaded as a CA.
- The final validation still parses the attestation, validates required fields,
  reloads the cert bundle through `verifyCertBundle`, and verifies the COSE
  attestation signature.
- Cached cert reuse is constrained by exact `keccak256(cert)` identity and
  `notAfter >= block.timestamp`.
- Hint blobs do not relax cryptographic checks; each inverse is constrained by
  modular multiplication and surplus hints are rejected.

## Recommended next step

Experiment 008 should move from benchmark-only wrappers to production candidate
code and audit docs:

1. Add production hinted interfaces while preserving the existing unhinted API.
2. Port the explicit-memory hint cursor into a production `ECDSA384` variant.
3. Add negative tests at the full-flow level: mutated cert hint, truncated cert
   hint, wrong parent hash, expired cached cert, CA/client role mismatch, and
   final attestation wrong-key rejection.
4. Start `docs/hinted-p384-nitro-attestation.md` with the threat model, ABI,
   witness format, sequence diagrams, and invariants.
