# 004 — Real attestation fixture and hot-path projection

Date: 2026-06-02
Status: ✅ complete

## Question

Does the provided real Nitro attestation validate against the current contracts,
and does the hinted-P384 direction still fit once real Nitro parsing, SHA-384,
certificate cache checks, and attestation signature verification are included?

## Fixture finding

The pasted Base64 sample has a 3-byte corruption in the CBOR payload:

- The COSE payload byte-string header declares length `0x1116`.
- The `public_key` CBOR key is missing bytes `0x69 0x63 0x5f` (`"ic_"`), so it
  appears as `publkey`.
- Because those 3 bytes are missing, the payload break (`0xff`) and signature
  header (`0x58 0x60`) appear 3 bytes earlier than the declared COSE payload end.

The benchmark fixture restores those missing bytes before validation. After that
normalization, the attestation validates successfully.

Timestamp decoded from the attestation:

- `2026-01-03T20:41:07.402Z`
- Foundry warp used: `1767472867`

## Method

Added:

- `test/bench/RealAttestationBench.t.sol`

The test:

1. Decodes the provided Base64 in Solidity test code.
2. Repairs the missing `"ic_"` bytes in `public_key`.
3. Measures `decodeAttestationTbs`.
4. Measures cold `validateAttestation`.
5. Measures cached `validateAttestation` by calling it a second time, after CA /
   client certs are stored in `CertManager`.
6. Projects the cached hot path under post-Fusaka unoptimized P384 and hinted P384.

Projection constants from experiments 000/003:

- Current P384 verify: `7,938,921`
- Unoptimized post-Fusaka P384 verify: `50,646,861`
- Hinted post-Fusaka P384 verify including worst-case 48-byte witness calldata:
  `6,743,887`
- EIP-7825 transaction cap: `16,777,216`

## Results

Command:

```sh
forge test --match-path test/bench/RealAttestationBench.t.sol -vv
```

Output:

| metric | value |
|--------|------:|
| repaired attestation bytes | 4,482 |
| attestationTbs bytes | 4,395 |
| signature bytes | 96 |
| `decodeAttestationTbs` gas | 102,550 |
| `validateAttestation` gas, cold | 53,582,064 |
| `validateAttestation` gas, cached | 16,169,057 |
| cached post-Fusaka, unoptimized | 58,876,997 |
| cached post-Fusaka, hinted + calldata | 14,974,023 |
| cached hinted fits `16,777,216` cap? | YES |

## Outcome

The hinted-P384 path still looks viable after including real Nitro parsing,
SHA-384, certificate-cache checks, and the final attestation signature verify.
The steady-state hot path projects to **14.97M gas post-Fusaka**, including
pessimistic witness calldata, leaving about **1.80M gas** of margin under the
EIP-7825 cap.

This is tighter than the isolated P384 benchmark, but still feasible.

## Implications

- Current cached validation is already close to the cap at **16.17M**; post-Fusaka
  without hinted P384 is impossible.
- With hinted P384, the hot path can remain a single transaction if certificates
  are already cached.
- Cold validation still needs to be split across cert transactions. The next
  measurement should confirm each hinted per-cert transaction stays comfortably
  below the cap.

## Recommended next step

→ Experiment 005: benchmark a hinted `CertManager` path.

Concrete plan:

1. Add a benchmark-only `CertManager` copy that accepts P384 inverse hints.
2. Measure `verifyCACertWithHints` and `verifyClientCertWithHints` on the certs
   extracted from this real attestation.
3. Project and/or directly measure per-cert gas with 48-byte witnesses.
4. Confirm the cold chain can be submitted as sequential under-cap transactions.
5. Then estimate Base L1 data cost for the witness payloads.

## Artifacts

- `test/bench/RealAttestationBench.t.sol`
