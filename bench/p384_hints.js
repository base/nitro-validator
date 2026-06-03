#!/usr/bin/env node
"use strict";

const crypto = require("crypto");
const fs = require("fs");

const P = hexToBigInt("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff");
const N = hexToBigInt("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973");
const LOW_S_MAX = N - 1n;
const A = hexToBigInt("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc");
const B = hexToBigInt("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef");
const GX = hexToBigInt("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7");
const GY = hexToBigInt("3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f");
const MASK_256 = (1n << 256n) - 1n;

main();

function main() {
  try {
    const { command, options } = parseArgs(process.argv.slice(2));
    let hints;

    if (command === "verify") {
      hints = collectVerifyHints(
        readBytes(options, "hash"),
        readBytes(options, "signature"),
        readBytes(options, "pubkey"),
      );
    } else if (command === "cert") {
      const cert = readBytes(options, "cert");
      const pubKey = readBytes(options, "pubkey");
      const { hash, signature } = parseCertSignature(cert);
      hints = collectVerifyHints(hash, signature, pubKey);
    } else if (command === "attestation") {
      const attestation = readBytes(options, "attestation");
      const pubKey = readBytes(options, "pubkey");
      const { hash, signature } = parseAttestationSignature(attestation);
      hints = collectVerifyHints(hash, signature, pubKey);
    } else {
      usage();
      process.exit(2);
    }

    process.stdout.write(`0x${Buffer.concat(hints).toString("hex")}`);
  } catch (err) {
    process.stderr.write(`${err.stack || err.message}\n`);
    process.exit(1);
  }
}

function usage() {
  process.stderr.write(`Usage:
  node bench/p384_hints.js verify --hash <hex> --signature <hex> --pubkey <hex>
  node bench/p384_hints.js cert --cert <hex|base64|@file> --pubkey <hex>
  node bench/p384_hints.js attestation --attestation <hex|base64|@file> --pubkey <hex>

Inputs may be 0x-prefixed hex, base64, or @path. Output is a 0x-prefixed packed
stream of 48-byte big-endian inverse hints.
`);
}

function parseArgs(args) {
  const command = args[0] || "";
  const options = {};

  for (let i = 1; i < args.length; i += 2) {
    const key = args[i];
    const value = args[i + 1];
    if (!key || !key.startsWith("--") || value === undefined) {
      usage();
      process.exit(2);
    }
    options[key.slice(2)] = value;
  }

  return { command, options };
}

function readBytes(options, name) {
  const value = options[name];
  if (value === undefined) {
    throw new Error(`missing --${name}`);
  }
  return decodeBytes(value);
}

function decodeBytes(value) {
  let raw = value;
  if (raw.startsWith("@")) {
    raw = fs.readFileSync(raw.slice(1), "utf8").trim();
  }

  if (raw.startsWith("0x") || raw.startsWith("0X")) {
    const hex = raw.slice(2);
    if (hex.length % 2 !== 0 || /[^0-9a-f]/i.test(hex)) {
      throw new Error("invalid hex input");
    }
    return Buffer.from(hex, "hex");
  }

  if (/^[0-9a-f]+$/i.test(raw) && raw.length % 2 === 0) {
    return Buffer.from(raw, "hex");
  }

  return Buffer.from(raw, "base64");
}

function collectVerifyHints(hashBytes, signatureBytes, pubKeyBytes) {
  if (signatureBytes.length !== 96) {
    throw new Error(`signature must be 96 bytes, got ${signatureBytes.length}`);
  }
  if (pubKeyBytes.length !== 96) {
    throw new Error(`pubkey must be 96 bytes, got ${pubKeyBytes.length}`);
  }
  if (hashBytes.length > 48) {
    throw new Error(`hash must be at most 48 bytes, got ${hashBytes.length}`);
  }

  const ctx = { hints: [] };
  const r = bytesToBigInt(signatureBytes.subarray(0, 48));
  const s = bytesToBigInt(signatureBytes.subarray(48, 96));
  const pubX = bytesToBigInt(pubKeyBytes.subarray(0, 48));
  const pubY = bytesToBigInt(pubKeyBytes.subarray(48, 96));

  if (r === 0n || r >= N || s === 0n || s > LOW_S_MAX) {
    throw new Error("signature rejected by scalar bounds");
  }
  if (!isOnCurve(pubX, pubY)) {
    throw new Error("pubkey is not on P384");
  }

  const paddedHash = leftPad(hashBytes, 48);
  const h = bytesToBigInt(paddedHash);
  let scalar1 = modDiv(ctx, h, s, N);
  const scalar2 = modDiv(ctx, r, s, N);

  const points = precomputePointsTable(ctx, pubX, pubY);
  const result = doubleScalarMultiplication(ctx, points, scalar1, scalar2);
  scalar1 = mod(result.x, N);

  if (scalar1 !== r) {
    throw new Error("signature verification failed");
  }

  return ctx.hints;
}

function isOnCurve(x, y) {
  if (x === 0n || x === P || y === 0n || y === P) {
    return false;
  }

  let rhs = modPow(x, 3n, P);
  if (A !== 0n) {
    rhs = modAdd(rhs, modMul(x, A, P), P);
  }
  if (B !== 0n) {
    rhs = modAdd(rhs, B, P);
  }

  return modPow(y, 2n, P) === rhs;
}

function precomputePointsTable(ctx, hx, hy) {
  const points = Array.from({ length: 64 }, () => ({ x: 0n, y: 0n }));
  points[0x01] = { x: hx, y: hy };
  points[0x08] = { x: GX, y: GY };

  for (let i = 0; i < 8; ++i) {
    for (let j = 0; j < 8; ++j) {
      if (i + j < 2) {
        continue;
      }

      const maskTo = (i << 3) | j;
      if (i !== 0) {
        const maskFrom = ((i - 1) << 3) | j;
        points[maskTo] = addAffine(ctx, points[maskFrom], { x: GX, y: GY });
      } else {
        const maskFrom = (i << 3) | (j - 1);
        points[maskTo] = addAffine(ctx, points[maskFrom], { x: hx, y: hy });
      }
    }
  }

  return points;
}

function doubleScalarMultiplication(ctx, points, scalar1, scalar2) {
  let x = 0n;
  let y = 0n;
  const scalar1High = scalar1 >> 256n;
  const scalar2High = scalar2 >> 256n;
  const scalar1Low = scalar1 & MASK_256;
  const scalar2Low = scalar2 & MASK_256;

  ({ x, y } = twiceAffine(ctx, { x, y }));

  let mask = Number((scalar1High >> 183n) << 3n) | Number(scalar2High >> 183n);
  if (mask !== 0) {
    ({ x, y } = addAffine(ctx, points[mask], { x, y }));
  }

  for (let word = 4; word <= 184; word += 3) {
    ({ x, y } = twice3Affine(ctx, { x, y }));

    const shift = BigInt(184 - word);
    mask = Number(((scalar1High >> shift) & 0x07n) << 3n) | Number((scalar2High >> shift) & 0x07n);

    if (mask !== 0) {
      ({ x, y } = addAffine(ctx, points[mask], { x, y }));
    }
  }

  ({ x, y } = twiceAffine(ctx, { x, y }));

  mask = Number((scalar1Low >> 255n) << 3n) | Number(scalar2Low >> 255n);
  if (mask !== 0) {
    ({ x, y } = addAffine(ctx, points[mask], { x, y }));
  }

  for (let word = 4; word <= 256; word += 3) {
    ({ x, y } = twice3Affine(ctx, { x, y }));

    const shift = BigInt(256 - word);
    mask = Number(((scalar1Low >> shift) & 0x07n) << 3n) | Number((scalar2Low >> shift) & 0x07n);

    if (mask !== 0) {
      ({ x, y } = addAffine(ctx, points[mask], { x, y }));
    }
  }

  return { x, y };
}

function twiceAffine(ctx, point) {
  const x1 = point.x;
  const y1 = point.y;
  if (x1 === 0n || y1 === 0n) {
    return { x: 0n, y: 0n };
  }

  let m1 = modPow(x1, 2n, P);
  m1 = modMul(m1, 3n, P);
  m1 = modAdd(m1, A, P);

  const m2 = modShl1(y1, P);
  m1 = modDiv(ctx, m1, m2, P);

  const x2 = modSub(modSub(modPow(m1, 2n, P), x1, P), x1, P);
  const y2 = modSub(modMul(modSub(x1, x2, P), m1, P), y1, P);

  return { x: x2, y: y2 };
}

function twice3Affine(ctx, point) {
  const x1Start = point.x;
  const y1Start = point.y;
  if (x1Start === 0n || y1Start === 0n) {
    return { x: 0n, y: 0n };
  }

  let m1 = modPow(x1Start, 2n, P);
  m1 = modAdd(modMul(m1, 3n, P), A, P);

  let m2 = modShl1(y1Start, P);
  m1 = modDiv(ctx, m1, m2, P);

  let x2 = modSub(modSub(modPow(m1, 2n, P), x1Start, P), x1Start, P);
  let y2 = modSub(modMul(modSub(x1Start, x2, P), m1, P), y1Start, P);

  if (y2 === 0n) {
    return { x: 0n, y: 0n };
  }

  m1 = modPow(x2, 2n, P);
  m1 = modAdd(modMul(m1, 3n, P), A, P);

  m2 = modShl1(y2, P);
  m1 = modDiv(ctx, m1, m2, P);

  let x1 = modSub(modSub(modPow(m1, 2n, P), x2, P), x2, P);
  let y1 = modSub(modMul(modSub(x2, x1, P), m1, P), y2, P);

  if (y1 === 0n) {
    return { x: 0n, y: 0n };
  }

  m1 = modPow(x1, 2n, P);
  m1 = modAdd(modMul(m1, 3n, P), A, P);

  m2 = modShl1(y1, P);
  m1 = modDiv(ctx, m1, m2, P);

  x2 = modSub(modSub(modPow(m1, 2n, P), x1, P), x1, P);
  y2 = modSub(modMul(modSub(x1, x2, P), m1, P), y1, P);

  return { x: x2, y: y2 };
}

function addAffine(ctx, point1, point2) {
  const x1 = point1.x;
  const y1 = point1.y;
  const x2 = point2.x;
  const y2 = point2.y;

  if (x1 === 0n || x2 === 0n) {
    if (x1 === 0n && x2 === 0n) {
      return { x: 0n, y: 0n };
    }
    return x1 === 0n ? { x: x2, y: y2 } : { x: x1, y: y1 };
  }

  if (x1 === x2) {
    if (y1 === y2) {
      return twiceAffine(ctx, point1);
    }
    return { x: 0n, y: 0n };
  }

  let m1 = modSub(y1, y2, P);
  const m2 = modSub(x1, x2, P);
  m1 = modDiv(ctx, m1, m2, P);

  const x3 = modSub(modSub(modPow(m1, 2n, P), x1, P), x2, P);
  const y3 = modSub(modMul(modSub(x1, x3, P), m1, P), y1, P);

  return { x: x3, y: y3 };
}

function modDiv(ctx, a, b, m) {
  const inv = recordInverse(ctx, b, m);
  return modMul(a, inv, m);
}

function recordInverse(ctx, value, modulus) {
  const normalized = mod(value, modulus);
  if (normalized === 0n) {
    throw new Error("cannot invert zero");
  }

  const inverse = modInv(normalized, modulus);
  ctx.hints.push(bigIntToFixedBuffer(inverse, 48));
  return inverse;
}

function mod(value, modulus) {
  const result = value % modulus;
  return result >= 0n ? result : result + modulus;
}

function modAdd(a, b, m) {
  const sum = a + b;
  return sum >= m ? sum - m : sum;
}

function modSub(a, b, m) {
  return a >= b ? a - b : a + m - b;
}

function modMul(a, b, m) {
  return (a * b) % m;
}

function modShl1(a, m) {
  const shifted = a << 1n;
  return shifted >= m ? shifted - m : shifted;
}

function modPow(base, exponent, modulus) {
  let result = 1n;
  let b = mod(base, modulus);
  let e = exponent;
  while (e > 0n) {
    if (e & 1n) {
      result = (result * b) % modulus;
    }
    b = (b * b) % modulus;
    e >>= 1n;
  }
  return result;
}

function modInv(value, modulus) {
  let low = mod(value, modulus);
  let high = modulus;
  let lm = 1n;
  let hm = 0n;

  while (low > 1n) {
    const ratio = high / low;
    const nm = hm - lm * ratio;
    const nw = high - low * ratio;
    hm = lm;
    high = low;
    lm = nm;
    low = nw;
  }

  if (low !== 1n) {
    throw new Error("inverse does not exist");
  }

  return mod(lm, modulus);
}

function parseCertSignature(cert) {
  const root = readAsn1(cert, 0);
  requireTag(root, 0x30, "certificate");

  const tbs = readAsn1(cert, root.contentStart);
  const sigAlgo = readAsn1(cert, tbs.end);
  const sig = readAsn1(cert, sigAlgo.end);
  requireTag(sig, 0x03, "certificate signature bit string");
  if (cert[sig.contentStart] !== 0x00) {
    throw new Error("unsupported nonzero signature unused-bits count");
  }

  const sigRoot = readAsn1(cert, sig.contentStart + 1);
  requireTag(sigRoot, 0x30, "ECDSA signature");
  const rNode = readAsn1(cert, sigRoot.contentStart);
  const sNode = readAsn1(cert, rNode.end);

  const r = parseAsn1Integer(cert.subarray(rNode.contentStart, rNode.contentEnd));
  const s = parseAsn1Integer(cert.subarray(sNode.contentStart, sNode.contentEnd));
  const hash = crypto.createHash("sha384").update(cert.subarray(tbs.start, tbs.end)).digest();

  return { hash, signature: Buffer.concat([r, s]) };
}

function parseAsn1Integer(bytes) {
  let value = bytes;
  while (value.length > 0 && value[0] === 0x00) {
    value = value.subarray(1);
  }
  if (value.length > 48) {
    throw new Error(`ASN.1 integer exceeds 48 bytes: ${value.length}`);
  }
  return leftPad(value, 48);
}

function readAsn1(bytes, start) {
  if (start >= bytes.length) {
    throw new Error("ASN.1 read out of bounds");
  }

  const tag = bytes[start];
  const { length, lengthBytes } = readDerLength(bytes, start + 1);
  const contentStart = start + 1 + lengthBytes;
  const contentEnd = contentStart + length;
  if (contentEnd > bytes.length) {
    throw new Error("ASN.1 length out of bounds");
  }

  return { tag, start, contentStart, contentEnd, end: contentEnd };
}

function readDerLength(bytes, offset) {
  const first = bytes[offset];
  if (first === undefined) {
    throw new Error("missing DER length");
  }
  if (first < 0x80) {
    return { length: first, lengthBytes: 1 };
  }

  const count = first & 0x7f;
  if (count === 0 || count > 4) {
    throw new Error("unsupported DER length");
  }
  if (offset + count >= bytes.length) {
    throw new Error("DER length out of bounds");
  }

  let length = 0;
  for (let i = 0; i < count; ++i) {
    length = (length << 8) | bytes[offset + 1 + i];
  }

  return { length, lengthBytes: 1 + count };
}

function requireTag(node, tag, label) {
  if (node.tag !== tag) {
    throw new Error(`${label} has unexpected ASN.1 tag 0x${node.tag.toString(16)}`);
  }
}

function parseAttestationSignature(attestation) {
  let offset = 1;
  if (attestation[0] === 0xd2) {
    offset = 2;
  }

  const protectedPtr = readCborItem(attestation, offset);
  requireCborMajor(protectedPtr, 2, "protected header");
  const unprotectedPtr = readCborItem(attestation, protectedPtr.end);
  requireCborMajor(unprotectedPtr, 5, "unprotected header");
  const payloadPtr = readCborItem(attestation, unprotectedPtr.end);
  requireCborMajor(payloadPtr, 2, "payload");
  const signaturePtr = readCborItem(attestation, payloadPtr.end);
  requireCborMajor(signaturePtr, 2, "signature");

  const rawProtectedBytes = attestation.subarray(offset, protectedPtr.end);
  const rawPayloadBytes = attestation.subarray(unprotectedPtr.end, payloadPtr.end);
  const attestationTbs = Buffer.concat([
    Buffer.from([0x84, 0x6a]),
    Buffer.from("Signature1", "ascii"),
    rawProtectedBytes,
    Buffer.from([0x40]),
    rawPayloadBytes,
  ]);

  return {
    hash: crypto.createHash("sha384").update(attestationTbs).digest(),
    signature: attestation.subarray(signaturePtr.contentStart, signaturePtr.end),
  };
}

function readCborItem(bytes, start) {
  const initial = bytes[start];
  if (initial === undefined) {
    throw new Error("CBOR read out of bounds");
  }
  const major = initial >> 5;
  const ai = initial & 0x1f;
  const { value, headerLength } = readCborValue(bytes, start + 1, ai);
  const contentStart = start + headerLength;
  let end;

  if (major === 2 || major === 3) {
    end = contentStart + Number(value);
  } else if (major === 4) {
    end = contentStart;
    for (let i = 0n; i < value; ++i) {
      end = readCborItem(bytes, end).end;
    }
  } else if (major === 5) {
    end = contentStart;
    for (let i = 0n; i < value * 2n; ++i) {
      end = readCborItem(bytes, end).end;
    }
  } else if (major === 0 || major === 1 || major === 6 || major === 7) {
    end = contentStart;
  } else {
    throw new Error(`unsupported CBOR major type ${major}`);
  }

  if (end > bytes.length) {
    throw new Error("CBOR item length out of bounds");
  }

  return { major, ai, value, start, contentStart, end };
}

function readCborValue(bytes, offset, ai) {
  if (ai < 24) {
    return { value: BigInt(ai), headerLength: 1 };
  }
  if (ai === 24) {
    return { value: BigInt(bytes[offset]), headerLength: 2 };
  }
  if (ai === 25) {
    return { value: BigInt(readUintBE(bytes, offset, 2)), headerLength: 3 };
  }
  if (ai === 26) {
    return { value: BigInt(readUintBE(bytes, offset, 4)), headerLength: 5 };
  }
  if (ai === 27) {
    return { value: readBigUintBE(bytes, offset, 8), headerLength: 9 };
  }
  throw new Error(`unsupported CBOR additional information ${ai}`);
}

function requireCborMajor(node, major, label) {
  if (node.major !== major) {
    throw new Error(`${label} has unexpected CBOR major type ${node.major}`);
  }
}

function readUintBE(bytes, offset, length) {
  let value = 0;
  for (let i = 0; i < length; ++i) {
    value = value * 256 + bytes[offset + i];
  }
  return value;
}

function readBigUintBE(bytes, offset, length) {
  let value = 0n;
  for (let i = 0; i < length; ++i) {
    value = value * 256n + BigInt(bytes[offset + i]);
  }
  return value;
}

function leftPad(buffer, length) {
  if (buffer.length > length) {
    throw new Error(`value length ${buffer.length} exceeds ${length}`);
  }
  if (buffer.length === length) {
    return Buffer.from(buffer);
  }
  return Buffer.concat([Buffer.alloc(length - buffer.length), buffer]);
}

function bytesToBigInt(bytes) {
  if (bytes.length === 0) {
    return 0n;
  }
  return BigInt(`0x${Buffer.from(bytes).toString("hex")}`);
}

function bigIntToFixedBuffer(value, length) {
  const hex = value.toString(16).padStart(length * 2, "0");
  if (hex.length > length * 2) {
    throw new Error(`integer exceeds ${length} bytes`);
  }
  return Buffer.from(hex, "hex");
}

function hexToBigInt(hex) {
  return BigInt(`0x${hex}`);
}
