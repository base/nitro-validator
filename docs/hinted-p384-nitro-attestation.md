# Hinted P384 Nitro Attestation

On-chain verification of AWS Nitro Enclave attestation documents that stays under the
Fusaka per-transaction gas cap — without a new chain precompile and without ZK.

**Background.** An AWS Nitro Enclave produces a signed *attestation document* (a
COSE/CBOR structure carrying an X.509 certificate chain rooted at a pinned AWS CA)
that proves a given workload ran inside a genuine enclave. Verifying it on-chain means
checking that certificate chain and the document signature — all ECDSA over the NIST
P-384 curve (secp384r1). P-384 verification leans heavily on the EVM's MODEXP
precompile, and that is exactly what the Fusaka upgrade reprices.

- **Problem:** the Fusaka MODEXP repricing makes a standard on-chain P-384 verifier
  far too expensive to land on an L2 such as Base.
- **Idea:** the expensive step (modular inversion) is *hard to compute but easy to
  check*, so the caller supplies it as a verified **hint**.
- **Result:** a full cold verification fits in **5 transactions, each ≤ ~13.8M gas**
  post-Fusaka — under the 16,777,216 cap.

> This guide is self-contained: it covers the construction, why it is sound, the
> complete set of code changes, measured gas, deployment, testing, and known caveats.

---

## Intuition: how hinting works in plain terms

*A non-cryptographer's walkthrough of the idea. §1 onward give the formal construction,
measured gas, and proofs.*

### Some things are hard to find but easy to check

Think about factoring. Ask "what are the factors of 589?" and you have to grind. But
hand someone the answer — 19 and 31 — and they confirm it with one multiplication:
19 × 31 = 589 ✓.

- Finding the answer is hard / expensive.
- Checking a proposed answer is easy / cheap.

A **hint** is exactly this: instead of making the contract *find* a hard value, the
caller finds it off-chain and hands it over, and the contract only *checks* it.

### Our hard thing: a modular inverse

The P-384 verifier constantly divides in modular arithmetic — `a / b mod m`. Division
there means "multiply by the inverse of `b`", where the inverse `inv` is the number with
`b · inv ≡ 1 (mod m)`.

Take a tiny modulus `m = 7` and find the inverse of `b = 3`:

- **The hard way (what the contract used to do):** compute `inv = b^(m−2) mod m`
  (Fermat's little theorem) = `3^5 mod 7`. `3^5 = 243`, and `243 mod 7 = 5` — several
  multiplications to get there. In this toy example the exponent `m−2` is just `5`, but
  for real P-384 the modulus is a **384-bit** number, so the exponent `m−2` is *also*
  ~384 bits — a value around 10¹¹⁵. Raising to a power *that* size is what makes the step
  so expensive (and it's why the curve is called *p384*).
- **The easy way (checking a proposed answer):** someone hands you `inv = 5`. One
  multiply: `3 · 5 = 15`, `15 mod 7 = 1` ✓ — done.

> Same asymmetry as factoring: *finding* 5 took exponentiation; *checking* 5 took one
> multiply.

### Why that gap is huge on-chain

Now scale up: the real modulus is a 384-bit number, not 7.

- **Finding** the inverse (`b^(m−2)`) means raising to that ~384-bit exponent — hundreds
  of big-number multiplications via the EVM's `MODEXP` precompile, which Fusaka made ~10×
  more expensive. And a single signature verify does this ~570 times.
- **Checking** a proposed inverse is still one big-number multiply — cheap, and Fusaka
  barely touches it.

So each inverse goes from hundreds of expensive operations to one cheap one.

### "But can we trust the hint?" — no, and we don't have to

The caller could lie and send `inv = 4`. The contract checks:

```
3 · 4 = 12,   12 mod 7 = 5   ≠ 1   ✗   → revert
```

A wrong hint fails the check and the transaction reverts. A malicious caller can waste
their own gas, but can never push a wrong value through. The hint is a *proposal,
validated before use* — nothing is trusted.

### How it's used in the real verifier

One P-384 signature verify needs ~570 of these inverses.

- **Before (no hints):** the contract computed all ~570 on-chain → ~570 expensive
  `MODEXP` calls. This is what blew past the gas cap.
- **After (with hints):** the caller computes all ~570 off-chain (free, on their own
  machine) and sends them as a list in calldata; the contract pops them one at a time
  and checks each with a single multiply.

Each hint is a **48-byte number** (the inverse), and a verify needs ~570 of them, so the
calldata is roughly 570 × 48 ≈ 27 KB per signature. A cold attestation has five such
signatures:

| signature | hint bytes | inverses (÷ 48) |
|---|---:|---:|
| CA cert 1 | 27,456 | 572 |
| CA cert 2 | 27,408 | 571 |
| CA cert 3 | 27,408 | 571 |
| client / leaf cert | 27,504 | 573 |
| COSE document | 27,312 | 569 |

(§6 maps these five signatures to transactions; §7 has their gas.)

The list is just values back-to-back, consumed in order:

```
caller sends:   [ inv_1 , inv_2 , inv_3 , … , inv_570 ]

contract:   needs 1/b_1  → take inv_1, check  b_1 · inv_1 ≡ 1, use it
            needs 1/b_2  → take inv_2, check  b_2 · inv_2 ≡ 1, use it
            needs 1/b_3  → take inv_3, check  b_3 · inv_3 ≡ 1, use it
            …
```

There are no labels — position `i` is for the `i`-th inverse the contract needs, because
it always does its work in the same deterministic order. (§4 gives the exact stream
format — 48-byte big-endian values — and the two guardrails that force the count to be
exact: it reverts if the list runs out early or has leftover values.)

### Why this is provably safe

Because `m` is **prime**, every nonzero number has exactly *one* inverse — there is no
second valid answer. So if a hint passes `b · inv ≡ 1 (mod m)`, it must be the one true
inverse, bit-for-bit identical to what the contract would have computed itself. The
hinted verifier therefore accepts exactly the same signatures as the original — cheaper,
with nothing changed about what it accepts or rejects, so no new way to forge anything.
(§4, *Why this is sound*, states this formally.)

> **One-line recap.** Computing a modular inverse is expensive; checking one is a single
> multiply. So the caller computes the ~570 inverses off-chain and submits them as hints;
> the contract verifies each (`b · inv ≡ 1`) before using it. Wrong hints revert, and
> since a prime modulus has a unique inverse, a passing hint is guaranteed to be the real
> one.
>
> The contract stops being a *solver* and becomes a *checker* — and checking is what
> blockchains are cheap at.

---

## 1. Why this exists

A P384 ECDSA verify is dominated by **modular inversions** computed on-chain via the
MODEXP precompile (`b⁻¹ = b^(p−2) mod p`, a 384-bit exponentiation). One signature
verify performs ~570 of them.

Two Fusaka changes break the existing validator:

- **EIP-7883** reprices large-operand MODEXP. A single P384 inversion goes from
  8,170 → 81,792 gas (~10×).
- **EIP-7825** caps a transaction at **16,777,216 gas** (2²⁴).

The consequences:

| | now | post-Fusaka |
|---|---:|---:|
| one signature verify | ~7.9M | **~50.6M** (≈3× the cap) |
| full attestation (5 verifies) | ~53M | **~267M** (≈16× the cap) |

A single signature verify is atomic and already exceeds the cap by ~3×, so splitting
the chain per-certificate is **necessary but not sufficient** — the unit of work
itself no longer fits in a transaction.

## 2. The core idea: checked hints

Computing a modular inverse on-chain is expensive; **checking** a proposed inverse is
a single modular multiply. So the caller computes the inverses off-chain and passes
them in calldata as *hints*; the contract verifies each one before using it:

```
need  a / b mod m   (i.e. a · b⁻¹)
  →   read next hint `inv`
  →   require  b · inv == 1 (mod m)      // one multiply; rejects any wrong value
  →   use      a · inv  (mod m)
```

Nothing is trusted: a hint that fails the check reverts. The worst a malicious caller
can do is waste their own gas — never forge a verification (see *Why this is sound*,
§4).

This does **not** reduce the *number* of MODEXP calls. It replaces each ~570
expensive 384-bit inversions (the part EIP-7883 punishes ~10×) with a floor-priced
multiply. Per-signature gas drops from ~50.6M to ~4M post-Fusaka, which makes the
whole attestation splittable into transactions that each fit the cap — see §7.

## 3. Architecture

```
                              caller
                  |                            |
  verifyCACertWithHints /              validateAttestationWithHints
  verifyClientCertWithHints                    |
                  v                            v
       +----------------------+        +----------------------+
       |     CertManager      |<-------|    NitroValidator    |
       | verify + cache certs |  cert  | parse CBOR / COSE,   |
       |    (root pinned)     |  chain | drive the cert chain |
       +----------------------+        +----------------------+
                  |                            |
                  |   P384 signature + inverse hints
                  v                            v
              +---------------------------------+
              |          P384Verifier           |
              |  verifyP384SignatureWithHints   |
              |  (ECDSA-P384 + hint checking)    |
              +---------------------------------+
```

Three deployable contracts:

- **`P384Verifier`** — all ECDSA-P384 math and hint checking, behind one external
  call. It is isolated so the parser/cache contracts stay under the EIP-170 code-size
  limit. It uses the hint-aware `ECDSA384` library vendored at `src/vendor/ECDSA384.sol`
  (see `src/vendor/README.md`). `CertManager` and `NitroValidator` hold **immutable**
  references to it.
- **`CertManager`** — parses/validates certificates, caches verified ones, pins the
  AWS Nitro root, and enforces an owner-managed revocation set. Implements
  `ICertManager`.
- **`NitroValidator`** — parses the CBOR/COSE attestation and drives the
  certificate chain through `CertManager`.

**No unhinted fallback.** The hinted entrypoints are
`verifyCACertWithHints`, `verifyClientCertWithHints`, and
`validateAttestationWithHints`. `CertManager`'s no-hint
`verifyCACert` / `verifyClientCert` **revert** (`use hinted cert verification`), so a
caller cannot accidentally invoke the expensive path. `NitroValidator.validateAttestation`
also reverts (`use hinted attestation verification`). The hinted changes are applied
directly to the original `CertManager.sol` and `NitroValidator.sol` files, instead of
shipping parallel copied contracts, so reviewers can audit the line diff against the
previous implementation.

## 4. How hints work

### Invariant
For every division `a / b mod m` the verifier pulls the next hint `inv`, requires
`b · inv ≡ 1 (mod m)`, then uses `a · inv mod m` (§2). The modulus is contextual:

- **`n`** (the scalar/group order) for the two ECDSA scalar divisions, and
- **`p`** (the field prime) for all elliptic-curve point arithmetic.

The choice is structural, not a runtime flag: point divisions are hard-wired to `p`
and scalar divisions carry an explicit `n`, so the two can never be confused.

### Hint stream
One packed byte stream per signature:

```
inverse_0 ‖ inverse_1 ‖ … ‖ inverse_{k-1}
```

- each inverse is exactly **48 bytes, big-endian**;
- consumed **sequentially** in the verifier's deterministic execution order;
- **not self-describing** — position `i` is bound to the `i`-th inversion by execution
  order alone. There are no tags or lengths in the stream.

### Count
`k` = the number of field inversions the verify actually performs. It is
**data-dependent** (the ladder's point additions depend on the scalar bit pattern),
so it varies slightly per signature — measured 569–573 on the production fixture. The
contract never assumes a fixed `k`; it enforces an exact match at runtime (below).

### Trust and rejection
Hints are public, caller-proposed, and fully constrained before use, so they add no
trust. The verifier rejects:

| condition | revert |
|-----------|--------|
| a hint fails `b · inv ≡ 1` | `bad inverse hint` |
| the stream runs out mid-verify | `inverse hint underflow` |
| the stream has leftover bytes | `unused inverse hints` |

The last two together force the stream length to be **exactly** `48 · k`.

### Why this is sound
Both moduli (`p` and `n`) are prime, so any nonzero element has a *unique* inverse.

- A hint that passes `b · inv ≡ 1 (mod m)` therefore **is** the true inverse `b⁻¹`
  (by uniqueness) — bit-identical to what the original `b^(m-2) mod m` would compute.
  Every hinted division yields the same field element as the original.
- The only operations that changed are these divisions, and everything downstream
  reduces mod `m`. So the hinted verifier returns the **same accept/reject decision**
  as the original verifier for every input — it accepts exactly the same set of
  signatures. Hinting introduces **no new forgery surface**.
- A zero or non-invertible denominator cannot be exploited: `0 · inv ≡ 1` is
  impossible, so the check simply reverts.
- Because hints are public and fully constrained before use, a malicious caller can at
  most cause a revert (wasted gas), never a false accept. (A non-canonical hint such
  as `inv + m` also passes the check and is harmless, since every use reduces mod `m`.)

The equivalence anchor for this argument is that with hints **disabled** the code is
identical to the upstream verifier; the hinted branches only *substitute a
pre-verified value* for the same inverse the original computes.

### What a failed verification does
- With hints **disabled**, behavior is identical to the original verifier.
- A *well-formed but invalid* signature consumes its full hint stream and the verify
  returns `false` normally.
- A signature that fails an **early** guard (scalar bounds or the on-curve check)
  returns before consuming any hints. If a non-empty hint stream was supplied, the
  exact-consumption guard then **reverts** (`unused inverse hints`) instead of
  returning `false`. Both outcomes block acceptance, but integrators should expect a
  revert — not a `false` return — for such inputs on the hinted entrypoint.

## 5. Preparing calls off-chain

Hints are produced off-chain by replaying the verifier's deterministic execution order
and emitting the packed 48-byte inverse stream. The generator only has to get the
**order and count** right: every value is re-checked on-chain (§4), so it is trusted for
*liveness*, not correctness — a bug can cause a revert, never a false accept. A
production caller can therefore implement it in whatever language its backend uses; the
contracts only ever see ordinary calldata via the `*WithHints` entrypoints.

A reference implementation is included in this repo: `tools/p384_hints.js` (Node.js, no
dependencies) generates the hint stream for a raw signature, a certificate, or a full
attestation, and a companion script assembles a ready-to-submit transaction plan (the
cold/warm sequences of §6) from one attestation. These are reference and demo tooling,
not a production dependency — use them as a byte-for-byte oracle when porting.

## 6. The attestation verification flow

### Certificate chain
A Nitro attestation carries a CA bundle (`cabundle`) — in the reference attestation,
4 entries — whose first entry is the AWS Nitro root, plus the enclave's signing
certificate:

- `cabundle[0]`: the **AWS Nitro root CA**. This is pinned in
  `CertManager` at deployment as the trust anchor. It is **not** signature
  verified on-chain, so it is **not** one of the expensive P384 verification
  transactions.
- `cabundle[1]`: the **regional CA**, verified against the pinned root and cached.
- `cabundle[2]`: the **zonal CA**, verified against the regional CA and cached.
- `cabundle[3]`: the **issuer / instance CA**, verified against the zonal CA and
  cached.
- `certificate`: the **client / leaf cert** that signed the attestation document,
  verified against the issuer / instance CA and cached.
- the final **COSE document signature** is verified with the cached leaf cert's key.

The common counting mistake is to include the root CA as a transaction. In this
construction the root is a pinned trust anchor, so a cold verification does **5 P384
signature checks**, each in its own transaction: 3 non-root CAs, 1 leaf cert, and 1
document signature.

### Cold sequence (empty cache)
| tx | action | hints supplied |
|----|--------|----------------|
| - | pinned root CA trust anchor | none; no transaction |
| 1 | verify + cache regional CA | cert signature hints |
| 2 | verify + cache zonal CA | cert signature hints |
| 3 | verify + cache issuer / instance CA | cert signature hints |
| 4 | verify + cache client / leaf cert | cert signature hints |
| 5 | validate Nitro attestation document | attestation signature hints |

### Warm sequence (cache populated)
Once the leaf and its CA chain are cached and unexpired, a later attestation signed by
the same leaf is a **single transaction** (`validateAttestationWithHints`) carrying
only the COSE signature hints. The cabundle certs are not re-verified — they are
reloaded by `keccak256(cert)` identity, checked against their original cached parent,
and their cached metadata is re-checked.

Practical reuse cases:

- **cold chain:** no relevant certs cached → 5 verification transactions;
- **CA chain cached, new leaf:** verify/cache the new leaf, then validate the
  document → 2 transactions;
- **CA chain and leaf cached:** validate the document only → 1 transaction.

**Cache reuse** is allowed when: the submitted DER hashes to a cached cert; the cert
is unexpired (`notAfter ≥ block.timestamp`); the cached CA/client role matches; and
`parentCertHash` matches the parent used during cold verification; and neither the cert
nor its cached parent chain is revoked. The cache is global on-chain state — once any
caller verifies a cert, others reuse it until expiry or revocation, but only under the
same parent binding.

### Revocation model
AWS's Nitro attestation documentation disables CRL checking in its sample validation
flow. This implementation keeps CRL parsing off-chain and exposes an operational
revocation hook on-chain:

- the `CertManager` deployer starts as both `owner` and `revoker`;
- the owner can transfer ownership, rotate the revoker, undo accidental revocations
  with `unrevokeCert`, and revoke `ROOT_CA_CERT_HASH` as an emergency global halt;
- the revoker can call `revokeCert` / `revokeCerts` for non-root AWS certificate hashes
  after checking AWS CRLs off-chain.

Revocation keys are byte-identity hashes: `keccak256(certBytes)`, where `certBytes`
are the exact X.509 DER bytes submitted to `verifyCACertWithHints` /
`verifyClientCertWithHints`. AWS CRLs identify certificates by issuer and serial, so
operators must resolve CRL entries to the exact submitted certificate bytes off-chain
before submitting revocation transactions. Cold verification rejects certificate byte
strings whose outer ASN.1 certificate object does not consume all submitted bytes, or
whose certificate sequence contains fields after the signature.

Revoked certs are rejected during cold verification, cached reuse, and warm attestation
bundle re-walks. Parent-chain revocation is also enforced for cached intermediates, so a
cached descendant cannot keep verifying through an ancestor that was later revoked.
Revocation is checked independently of `notAfter`, so a revoked cert is untrusted even if
its X.509 validity period has not expired.

`loadVerified` is intentionally a raw cache read. A non-empty return value means the cert
metadata was cached previously; it does not imply the cert is currently trusted, unexpired,
or unrevoked.

**Warm-only guard.** `validateAttestationWithHints` re-runs the cabundle checks with an
*empty* hint stream. Cached certs return before signature verification; a missing cert
sends the empty stream into P384 verification and reverts with
`inverse hint underflow`. This makes it impossible for the validator to silently fall
back to the expensive unhinted path during final validation.

## 7. Measured gas

Cold sequence, measured from successful Base Sepolia receipts after the Fusaka
upgrade. These numbers exclude the one-time contract deployment transactions and
include the five logical verification transactions from §6. The receipts were
captured from the equivalent hinted deployment before the auditability refactor folded
the changes into the original `CertManager` / `NitroValidator` names; rerun the demo
after redeploying if exact gas for this commit is needed.

| tx | action | hint bytes | Base Sepolia gas used |
|----|--------|-----------:|----------------------:|
| 1 | cache regional CA | 27,456 | 6,825,140 |
| 2 | cache zonal CA | 27,408 | 7,053,669 |
| 3 | cache issuer / instance CA | 27,408 | 6,813,103 |
| 4 | cache client / leaf cert | 27,504 | 6,825,004 |
| 5 | validate Nitro attestation document | 27,312 | 13,775,541 |

Warm-cache validation reuses the cached CA chain and cached leaf cert, so it repeats
only tx 5:

| path | action | Base Sepolia gas used |
|------|--------|----------------------:|
| warm | validate Nitro attestation document | 13,775,541 |

| metric | value |
|--------|------:|
| cold verification total | 41,292,457 |
| cache setup subtotal, tx 1-4 | 27,516,916 |
| **max verification tx** | **13,775,541** |
| warm validation tx | 13,775,541 |
| per-tx cap (EIP-7825) | 16,777,216 |
| headroom under cap | 3,001,675 |

Every verification transaction landed under the cap. The document validation
transaction was sent with an explicit `16,500,000` gas limit after
`eth_estimateGas` returned `13,886,038`; the receipt used `13,775,541` gas.

Representative Base Sepolia tx hashes:

- cold document validation:
  `0x2cb00a86b943a29cda28be89ad990d9ca29c502c8350ba1ab89e726d44d6702e`;
- warm document validation:
  `0x0563932374215073fd92f8d79920af0f5d79be25c92d26bab910de8bb16a21c7`.

## 8. Deployment

Deploy order (both verifier references are immutable constructor args):

1. `P384Verifier`
2. `CertManager(P384Verifier)`
3. `NitroValidator(CertManager, P384Verifier)`

Runtime sizes (`forge build --sizes`); EIP-170 limit is 24,576 bytes:

| contract | runtime size | margin |
|----------|-------------:|-------:|
| `P384Verifier` | 7,805 | 16,771 |
| `CertManager` | 21,849 | 2,727 |
| `NitroValidator` | 14,062 | 10,514 |

(Test-only helper contracts are not part of the deployable contract set.)

## 9. Testing & audit

The hinted contracts are exercised against the real fixture and adversarial inputs.
Covered failure modes: mutated hint, truncated hint, surplus hint, wrong parent hash,
revoked certs, revoked parents, expired cached cert, expired cert on first (cold)
verification, the `notAfter` validity boundary, CA/client role mismatch, missing warm
cache, invalid final signature, out-of-range ECDSA scalars (`r=0`, `r≥n`, `s=0`,
`s>lowSmax`), disabled unhinted entrypoints, EIP-170 fit, and off-chain↔on-chain hint
equivalence. The DER, CBOR, and byte-slicing parsers additionally have direct unit and
fuzz tests for malformed and out-of-bounds input (`test/Asn1Decode.t.sol`,
`test/CborDecode.t.sol`, `test/LibBytes.t.sol`).

| invariant | component | how it is tested |
|-----------|-----------|------------------|
| every supplied inverse is constrained before use | the two inversion sites | mutated / truncated / surplus hints are rejected |
| hints consumed in verifier order, with exact count | verifier + hint reader | byte-for-byte match against an independent off-chain collector |
| scalar inverses use `n`, field inverses use `p` | verifier | a known-good signature is accepted; a modulus swap would reject it |
| hinted verifier matches the original accept/reject set | `P384Verifier` | accepts a valid signature; rejects mutated hash / signature / public key |
| no unhinted fallback via hinted entrypoints | `CertManager` | the unhinted entrypoints revert |
| warm validation requires cached certs | `NitroValidator` | empty-hint final validation reverts when a cert is uncached |
| revoked certs are never trusted | `CertManager` | revoked cold/cached certs, revoked parents/ancestors, and revoked root/leaf warm paths revert |
| out-of-range scalars are rejected | `P384Verifier` | `r=0` / `r≥n` / `s=0` / `s>lowSmax` signatures return false |
| certificate validity is enforced at the boundary | `CertManager` | cold-path expiry reverts; valid at `notAfter`, expired at `notAfter+1` |
| parsers reject malformed / out-of-bounds input | `Asn1Decode`, `CborDecode`, `LibBytes` | direct unit + fuzz tests for bad tags, lengths, types, and slices |
| off-chain generator matches on-chain order, rejects bad input | off-chain generator | equivalence test + negative-input checks |

The off-chain↔on-chain hint equivalence is checked under an FFI test (it shells out to
the generator and compares streams byte-for-byte), so the generator and the contract
can never silently diverge.

**For auditors.** The entire trust delta versus the upstream library is the two
`if (hintsEnabled)` branches shown in the appendix; the soundness argument is in §4
(*Why this is sound*). Reviewers should confirm:

1. every supplied inverse is constrained by `b · inv ≡ 1` in the correct modulus
   **before** it is used;
2. point inverses use the field prime `p` and scalar inverses use the group order `n`,
   with no crossover;
3. the underflow and surplus guards together force the hint count to match exactly
   (no truncated or leftover hints);
4. the hints-disabled path is byte-identical to the upstream verifier; and
5. the curve parameters (`p`, `n`, `G`, `a`, `b`, low-`s` bound) are correct.

## 10. Caveats and notes

- **Calldata contributes to transaction gas.** The tables in §7 are receipt gas and
  include the intrinsic gas for the ~27 KB hint calldata carried by each signature.
  On Base (as an L2), calldata also incurs an L1 data-availability fee on top of EVM
  gas — budget for that separately.
- **Acceptance rule is inherited unchanged.** The verifier accepts when
  `x_R mod n == r`, exactly as the upstream library, including its handling of the
  negligible (~2⁻¹⁹⁰) case where the recovered x-coordinate lies in `[n, p)`. Hinting
  does not alter this.
- **Audit boundary.** Only the two inversion branches are new cryptographic code; the
  rest of the verifier is the upstream library unchanged, and the certificate parser,
  cache, and CBOR/COSE handling are the pre-existing validator logic.
- **The generator is liveness-critical, not trust-critical.** A bug in the off-chain
  hint generator can only cause a revert (every value is re-checked on-chain), never a
  false accept — but correct hints are required to verify at all, so the generator
  must stay in sync with the verifier's execution order. Its DER/CBOR parsing should
  be reviewed for robustness.

### Integrator responsibilities (what the contract does NOT enforce)

Verification proves an attestation is genuine and well-formed. The following are
deliberately left to the caller and must be handled in the consuming contract:

- **Freshness / anti-replay.** `validateAttestationWithHints` only checks that
  `timestamp` is non-zero and that `nonce` is within a size bound; it never compares
  `timestamp` (milliseconds) to `block.timestamp` (seconds) nor matches `nonce` to a
  challenge. A valid attestation can be replayed until its short-lived leaf certificate
  expires or is revoked. If you need freshness, compare `ptrs.timestamp / 1000` to
  `block.timestamp` and/or verify `ptrs.nonce` against a value you issued.
- **Signature malleability.** Low-S is intentionally not enforced (AWS does not
  guarantee low-S; see `CURVE_LOW_S_MAX` in `ECDSA384Curve.sol`), so for a valid
  signature `(r, s)` the twin `(r, n−s)` also verifies. This cannot forge an
  attestation AWS never produced, but you must NOT use the raw signature (or
  `attestationTbs + signature`, or its hash) as a unique key — dedupe on canonical
  attestation fields (e.g. `moduleID + timestamp + nonce`).
- **Enclave-image / PCR policy.** The contract returns the parsed `pcrs` and
  `moduleID`; deciding which enclave images you trust is application policy.
- **CRL monitoring.** `CertManager` enforces certificate hashes that have been marked
  revoked on-chain, but it does not fetch or parse AWS CRLs. A trusted off-chain
  operator must monitor AWS CRLs, map issuer/serial entries to exact submitted
  certificate-byte hashes, and submit `revokeCert` / `revokeCerts` transactions promptly.

## 11. On-chain demo

A Base Sepolia run of the §6 cold sequence needs: an RPC URL, a funded broadcaster
key, the attestation bytes to submit, and a certificate expiry window. The bundled
fixture is a January 2026 real Nitro attestation, so the demo script uses
`CertManagerDemo` with an explicit expiry grace. Production deployments should
use `CertManager`, which keeps strict X.509 validity checks.

The happy-path script is `script/BaseSepoliaDemo.s.sol`. It deploys
`P384Verifier`, `CertManagerDemo`, and `NitroValidator`; generates cert
hints with `tools/p384_hints.js cert`; submits the four cache transactions; generates
COSE hints with `tools/p384_hints.js attestation`; submits the final
`validateAttestationWithHints`; then submits one warm-cache validation against the
same cached chain and leaf. The script uses `vm.ffi` only because Foundry Solidity
scripts cannot run the off-chain parsing and BigInt witness code in-process. In the
production flow, the caller service prepares the same hints and ABI calldata before
submitting ordinary transactions. Run the demo with Foundry FFI enabled (`--ffi`);
without it, Foundry disables `vm.ffi` by default.

---

## Appendix: the code change

The hinted verifier is the upstream `ECDSA384` verifier from
`dl-solarity/solidity-lib`, vendored into this repo at `src/vendor/ECDSA384.sol` (see
`src/vendor/README.md` for provenance and the exact upstream diff in
`src/vendor/ECDSA384.hinted.patch`) with **one operation — modular inversion — made
hint-aware in two places**. Everything else (the Strauss–Shamir ladder, precompute
table, on-curve check, scalar bounds, final `x_R == r`) is unchanged. When hints are
disabled the code follows the original path, so the unhinted path is the equivalence
anchor.

The entire trust delta is these two `if (hintsEnabled)` branches.

**Point arithmetic — inverses mod `p`** (`moddivAssign`):

```diff
     function moddivAssign(uint256 call_, uint256 a_, uint256 b_) internal view {
         unchecked {
+            uint256 baseCall_ = call_;
+            if (_hintsEnabled(call_)) {
+                uint256 inv_ = _nextInverseHint(call_);
+                uint256 check_ = modmul(call_, b_, inv_);          // modmul modulus is baked = p
+                require(eqInteger(check_, 1), "bad inverse hint"); // b * inv == 1 (mod p)
+                assembly {                                         // b_ <- inv
+                    mstore(b_, mload(inv_))
+                    mstore(add(b_, 0x20), mload(add(inv_, 0x20)))
+                }
+            } else {
                 assembly {                                         // ORIGINAL Fermat path (verbatim)
                     call_ := add(call_, INV_OFFSET)
                     mstore(add(0x60, call_), mload(b_))
                     mstore(add(0x80, call_), mload(add(b_, 0x20)))
                     pop(staticcall(gas(), 0x5, call_, 0x0120, b_, 0x40))
                 }
+            }
-            modmulAssign(call_ - INV_OFFSET, a_, b_);
+            modmulAssign(baseCall_, a_, b_);                       // a <- a * b⁻¹ (mod p), unchanged
         }
     }
```

**ECDSA scalars — inverses mod `n`** (`modinv`, reached via `moddiv`):

```diff
     function modinv(uint256 call_, uint256 b_, uint256 m_) internal view returns (uint256 r_) {
         unchecked {
+            if (_hintsEnabled(call_)) {
+                r_ = _nextInverseHint(call_);
+                uint256 check_ = _modmulWithMod(call_, b_, r_, m_); // explicit modulus m (= n)
+                require(eqInteger(check_, 1), "bad inverse hint");  // b * r == 1 (mod m)
+                return r_;
+            }
             /* ... original Fermat path b^(m-2) mod m, unchanged ... */
         }
     }
```

Both branches call the one new bounds-checked reader, which enforces the
no-truncation guard:

```diff
+    function _nextInverseHint(uint256 call_) private pure returns (uint256 r_) {
+        /* read cursor_, length_ from scratch */
+        require(cursor_ + 48 <= length_, "inverse hint underflow"); // never read past the stream
+        /* load the next 48 big-endian bytes into a field element; cursor += 48 */
+    }
```

The remaining changes are **plumbing**, not logic, and none can affect the
accept/reject decision:

- a few words of scratch memory holding the hint stream pointer, length, cursor, and
  an enabled flag (`initCall` / `initCallWithHints`);
- the `verify` entrypoint split into `verify` (no hints, identical to the original)
  and `verifyWithHints`, which adds the surplus guard
  `require(consumed == length, "unused inverse hints")`.

That is the complete set of changes versus the upstream verifier.
