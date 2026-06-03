# 010 - Off-chain witness generator

Date: 2026-06-02
Status: complete

## Question

Can the Solidity-only witness oracle be replaced with an off-chain generator that
emits the exact 48-byte inverse hint stream expected by `P384Verifier`?

## Method

Added:

- `bench/p384_hints.js`

The generator is dependency-free Node.js:

- uses built-in `BigInt` for P384 arithmetic,
- uses built-in `crypto` for SHA-384,
- mirrors the Solarity affine Strauss-Shamir P384 verification order,
- records every modular inverse denominator in the same order as
  `ECDSA384Hinted`,
- emits each inverse as exactly 48-byte big-endian bytes.

Supported commands:

```sh
node bench/p384_hints.js verify --hash <0xhash> --signature <0xr_s> --pubkey <0xxy>
node bench/p384_hints.js cert --cert <0xder|base64|@file> --pubkey <0xparent_xy>
node bench/p384_hints.js attestation --attestation <0xcose|base64|@file> --pubkey <0xleaf_xy>
```

Added optional FFI cross-check:

- `test_010_OffchainWitnessGeneratorMatchesSolidityCollector`

The test is skipped in normal `forge test` runs. Enable it with:

```sh
NITRO_RUN_FFI=true forge test --ffi \
  --match-path test/bench/RealAttestationBench.t.sol \
  --match-test test_010_OffchainWitnessGeneratorMatchesSolidityCollector -vv
```

## Results

Syntax check:

```sh
node --check bench/p384_hints.js
```

Result: pass.

Default focused test:

```sh
forge test --match-path test/bench/RealAttestationBench.t.sol --match-test test_010 -vv
```

Result: pass, with the FFI check skipped unless `NITRO_RUN_FFI=true`.

Enabled FFI cross-check:

```sh
NITRO_RUN_FFI=true forge test --ffi \
  --match-path test/bench/RealAttestationBench.t.sol \
  --match-test test_010_OffchainWitnessGeneratorMatchesSolidityCollector -vv
```

Result: `1 passed, 0 failed`.

The enabled test checked 5 real-fixture signatures:

| signature | source |
|-----------|--------|
| 1 | non-root CA cert |
| 2 | non-root CA cert |
| 3 | non-root CA cert |
| 4 | client/leaf cert |
| 5 | COSE attestation |

For each signature, the Node generator output matched
`P384HintCollectorBench` byte-for-byte. The generated hints were then used to
cache the cert chain and validate the Nitro attestation through the deployable
hinted contracts.

Final attestation hint stream size: `27,312` bytes.

Full suite:

```sh
forge test
```

Result: `48 passed, 0 failed`.

Source-only deployability check:

```sh
forge build src --sizes
```

Result: pass; hinted runtime sizes unchanged from 009.

## Soundness Notes

- The off-chain generator is not trusted by the contracts. A malicious or buggy
  generator can only produce hints that are accepted if every inverse satisfies
  the on-chain `denominator * inverse == 1 mod m` check.
- The generator must still match the verifier's deterministic hint order. The
  FFI test proves this for the real fixture against the Solidity collector.
- The `cert` mode parses DER TBS and ECDSA `r,s`; the `attestation` mode
  reconstructs Nitro's COSE `Sig_structure`. Both paths converge to the same
  `verify` hint generator.
- The default test suite does not require FFI, so CI and normal local tests do
  not depend on Node process execution.

## Outcome

The witness-generation loop is now practical:

1. Generate hints off-chain with `bench/p384_hints.js`.
2. Submit cert-cache transactions with cert signature hints.
3. Submit the warm attestation validation transaction with attestation signature
   hints.
4. Use the optional FFI test to prove local generator equivalence before audit or
   deployment rehearsals.

## Recommended Next Step

Experiment 011 should harden audit evidence around equivalence and negative
behavior:

1. Add direct `P384Verifier` equivalence tests against the original unhinted
   verifier for known-good and known-bad signatures.
2. Add CLI negative tests outside Solidity for malformed DER, malformed COSE,
   wrong pubkey, wrong signature, and truncated inputs.
3. Add code-reference tables to `docs/hinted-p384-nitro-attestation.md` mapping
   every audit invariant to the exact Solidity and JS locations.
4. Consider a small deployment rehearsal script that prints the cold/warm
   transaction sequence with generated hints and expected calldata sizes.
