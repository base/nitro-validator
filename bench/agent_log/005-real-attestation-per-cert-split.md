# 005 — Real attestation per-cert split projection

Date: 2026-06-02
Status: ✅ complete

## Question

If the real attestation cold path is split across certificate transactions, does
each transaction fit under the EIP-7825 cap once P384 verification is moved to the
hinted-inversion path?

## Method

Extended:

- `test/bench/RealAttestationBench.t.sol`

The test:

1. Decodes and repairs the real Base64 attestation fixture from experiment 004.
2. Uses a benchmark-only parse harness to expose `_parseAttestation`.
3. Extracts each `cabundle` certificate and the leaf/client certificate.
4. Measures current `CertManager.verifyCACert` / `verifyClientCert` gas for each
   cert transaction.
5. Projects each non-root certificate by replacing one current P384 verify with
   the hinted post-Fusaka P384 cost including pessimistic witness calldata.

Projection formula for certs that perform one P384 signature check:

```text
projected = currentGas - 7,938,921 + 6,743,887
```

The root cert transaction is already cached/pinned and performs no P384 verify, so
it is left unchanged.

## Results

Command:

```sh
forge test --match-path test/bench/RealAttestationBench.t.sol -vv
```

Output:

| step | current gas | projected hinted post-Fusaka | fits cap? |
|------|------------:|------------------------------:|:---------:|
| cabundle[0] root | 24,670 | 24,670 | YES |
| cabundle[1] | 9,304,997 | 8,109,963 | YES |
| cabundle[2] | 9,527,634 | 8,332,600 | YES |
| cabundle[3] | 9,288,116 | 8,093,082 | YES |
| client cert | 9,312,028 | 8,116,994 | YES |

## Outcome

The cold chain can be split into under-cap transactions with substantial margin.
Each non-root certificate transaction projects to roughly **8.1M-8.3M gas
post-Fusaka**, including pessimistic P384 witness calldata.

Combined with experiment 004:

- Cold path: split cert transactions fit individually.
- Cached hot path: final attestation validation projects to **14.97M**, also
  under cap.

This supports a pure-EVM architecture:

1. Submit/cert-cache the AWS cabundle in order.
2. Submit the leaf/client cert with hints.
3. Submit the attestation validation with hints.

## Caveats

- This is still a projection for hinted cert verification, not a production
  `CertManager.verifyCACertWithHints` implementation.
- The projection assumes one P384 verification per non-root cert, matching the
  current `CertManager` flow.
- L1 data cost for witness payloads on Base is not included in execution gas and
  should be priced separately.

## Recommended next step

→ Experiment 006: build a production-shaped hinted API sketch.

Concrete plan:

1. Define calldata ABI for `verifyCACertWithHints`, `verifyClientCertWithHints`,
   and `validateAttestationWithHints`.
2. Decide whether hints are passed as one packed `bytes` stream per P384 verify or
   grouped by certificate.
3. Implement a minimal off-chain witness generator that replays verification and
   emits 48-byte inverses.
4. Replace the benchmark-only transient-storage hint cursor with normal calldata
   cursor logic.
5. Re-run 004/005 using the production-shaped API.

## Artifacts

- `test/bench/RealAttestationBench.t.sol::test_RealAttestationPerCertSplitProjection`
