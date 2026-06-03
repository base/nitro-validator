# P384 / Fusaka gas benchmarking loop

Goal: make on-chain AWS Nitro TEE attestation verification (ECDSA over secp384r1)
land **fully within the EIP-7825 per-transaction gas cap (16,777,216) on Base**,
surviving the Fusaka MODEXP repricing (EIP-7883). Each cert verify should fit in a
single tx; a full cold chain may span several txs but must land within ~5s.

## The loop

```
baseline gas  ->  experiment  ->  agent_log/NNN-*.md  ->  recommended next steps  ->  execute & repeat
```

Every iteration is an entry in `agent_log/`. Each entry records: hypothesis, what
was changed, the measured/modelled numbers, whether it fits the cap, soundness
notes, and the recommended next experiment.

## Methodology / tooling

- **Ground-truth current gas**: `forge test` with `gasleft()` around a single
  uninstrumented `ECDSA384.verify` (`test/bench/Bench.t.sol`).
- **Exact MODEXP census**: `test/bench/ECDSA384Bench.sol` is an *instrumented copy*
  of the library (`lib/solidity-lib/.../ECDSA384.sol`) with transient-storage
  counters that tally field inversions vs. other modexp calls per verify. The
  submodule itself is never modified.
- **Post-Fusaka projection**: only the MODEXP portion reprices. We compute exact
  per-call gas under EIP-2565 (current) and EIP-7883 (post-Fusaka) from the EIP
  formulas, applied to this library's operand profiles, and add the unchanged
  non-MODEXP remainder.
- A debug-trace census (`vm.startDebugTraceRecording`) was tried and **abandoned**:
  materializing the step array for a ~8M-gas verify costs >1B gas / OOMs. The
  instrumented-copy approach is the supported method.

### Per-call MODEXP gas (this library's profiles)

| call | base/exp/mod (bytes) | EIP-2565 | EIP-7883 | factor |
|------|----------------------|----------|----------|--------|
| field inversion (`modinv`/`moddivAssign`) | 64 / 64 / 64 | 8,170 | 81,792 | ~10× |
| squaring / mulmul / reduce / mod | ≤96 / ≤32 / 64 | 200 (floor) | 500 (floor) | 2.5× |

EIP-7883 vs EIP-2565 for the inversion compounds three changes: complexity
multiplier `words²→2·words²`, exponent per-word `8→16`, and removal of `÷3`.

## Run

```sh
git submodule update --init --recursive
forge test --match-path "test/bench/Bench.t.sol" -vv
```

## Off-chain hints

Experiment 010 adds a dependency-free Node witness generator:

```sh
node bench/p384_hints.js verify --hash <0xhash> --signature <0xr_s> --pubkey <0xxy>
node bench/p384_hints.js cert --cert <0xder|base64|@file> --pubkey <0xparent_xy>
node bench/p384_hints.js attestation --attestation <0xcose|base64|@file> --pubkey <0xleaf_xy>
```

To cross-check the generator against the Solidity collector for the real Nitro
fixture:

```sh
NITRO_RUN_FFI=true forge test --ffi \
  --match-path test/bench/RealAttestationBench.t.sol \
  --match-test test_010_OffchainWitnessGeneratorMatchesSolidityCollector -vv
```

## Numbers to beat

- Current single verify: **7.94M** gas.
- Projected single verify post-Fusaka (unoptimized): **50.6M** gas — **3× over the cap**.
- Projected hinted single verify post-Fusaka: **6.04M** gas including worst-case
  calldata for 48-byte inverse witnesses.
- Real attestation cached hot path with hinted P384 projection: **13.68M** gas
  post-Fusaka including worst-case witness calldata.
- Real attestation non-root cert split transactions with hinted P384 projection:
  **6.80M-7.03M** gas post-Fusaka each.
- Real attestation full minimum cold sequence for the current fixture:
  **5 transactions**. The max projected tx is **13.68M** gas post-Fusaka.
- Real attestation warm-cache sequence for the current fixture:
  **1 transaction**, projected at **13.64M** gas post-Fusaka.
- Per-tx cap (EIP-7825): **16,777,216**.
