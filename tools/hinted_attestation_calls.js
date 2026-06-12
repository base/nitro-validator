#!/usr/bin/env node
"use strict";

const {
  collectAttestationHintBytes,
  collectCertSignatureHintBytes,
  parseAttestationPayload,
  parseAttestationSignature,
  parseCertPublicKey,
  readBytes,
} = require("./p384_hints");
const {
  realFixture,
  repairMissingPublicKeyBytes,
} = require("./nitro_attestation_input");

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
const RATE_BYTES = 136;
const MASK_64 = (1n << 64n) - 1n;

if (require.main === module) {
  main();
}

function main() {
  try {
    const { command, options } = parseArgs(process.argv.slice(2));
    let attestation;

    if (command === "fixture") {
      attestation = repairMissingPublicKeyBytes(realFixture());
    } else if (command === "prepare") {
      attestation = readBytes(options, "attestation");
      if (options.repair === "true") {
        attestation = repairMissingPublicKeyBytes(attestation);
      }
    } else {
      usage();
      process.exit(2);
    }

    const plan = prepareHintedAttestationCalls(attestation, {
      certManager: options["cert-manager"] || null,
      validator: options.validator || null,
    });

    process.stdout.write(`${JSON.stringify(plan, null, 2)}\n`);
  } catch (err) {
    process.stderr.write(`${err.stack || err.message}\n`);
    process.exit(1);
  }
}

function usage() {
  process.stderr.write(`Usage:
  node tools/hinted_attestation_calls.js fixture [--cert-manager <address>] [--validator <address>]
  node tools/hinted_attestation_calls.js prepare --attestation <hex|base64|@file> [--repair true] [--cert-manager <address>] [--validator <address>]

Outputs a JSON transaction plan for the hinted Nitro flow. Each item includes
the target contract, function signature, ABI arguments, packed inverse hints,
and ready-to-submit calldata.
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

function prepareHintedAttestationCalls(attestation, addresses = {}) {
  const certManager = normalizeOptionalAddress(addresses.certManager);
  const validator = normalizeOptionalAddress(addresses.validator);
  const parsed = parseAttestationSignature(attestation);
  const payload = parseAttestationPayload(attestation);

  if (payload.cabundle.length < 2) {
    throw new Error("attestation cabundle must include root plus at least one non-root CA");
  }

  const rootCert = payload.cabundle[0];
  const rootHash = keccak256Hex(rootCert);
  let parentHash = rootHash;
  let parentPubKey = parseCertPublicKey(rootCert);
  const cold = [];

  for (let i = 1; i < payload.cabundle.length; ++i) {
    const cert = payload.cabundle[i];
    const hints = collectCertSignatureHintBytes(cert, parentPubKey);
    const certHash = keccak256Hex(cert);
    cold.push(certTx({
      tx: cold.length + 1,
      label: caLabel(i),
      kind: "cache_ca",
      to: certManager,
      functionName: "verifyCACertWithHints",
      signature: "verifyCACertWithHints(bytes,bytes32,bytes)",
      cert,
      certHash,
      parentCertHash: parentHash,
      hints,
    }));
    parentHash = certHash;
    parentPubKey = parseCertPublicKey(cert);
  }

  const leafHints = collectCertSignatureHintBytes(payload.certificate, parentPubKey);
  const leafHash = keccak256Hex(payload.certificate);
  cold.push(certTx({
    tx: cold.length + 1,
    label: "client / leaf cert",
    kind: "cache_leaf",
    to: certManager,
    functionName: "verifyClientCertWithHints",
    signature: "verifyClientCertWithHints(bytes,bytes32,bytes)",
    cert: payload.certificate,
    certHash: leafHash,
    parentCertHash: parentHash,
    hints: leafHints,
  }));

  const leafPubKey = parseCertPublicKey(payload.certificate);
  const attestationHints = collectAttestationHintBytes(attestation, leafPubKey);
  const finalTx = attestationTx({
    tx: cold.length + 1,
    to: validator,
    attestationTbs: parsed.attestationTbs,
    signature: parsed.signature,
    hints: attestationHints,
  });
  cold.push(finalTx);

  return {
    schema: "nitro-validator.hinted-attestation-calls.v1",
    contracts: {
      certManager,
      validator,
    },
    root: {
      label: "pinned AWS Nitro root CA",
      certHash: rootHash,
      certBytes: hex(rootCert),
      transaction: null,
    },
    leaf: {
      certHash: leafHash,
      pubKey: hex(leafPubKey),
    },
    cold,
    warm: [
      {
        ...finalTx,
        tx: 1,
        label: "validate Nitro attestation document (warm cache)",
      },
    ],
  };
}

function certTx({ tx, label, kind, to, functionName, signature, cert, certHash, parentCertHash, hints }) {
  return {
    tx,
    kind,
    label,
    to,
    function: signature,
    certHash,
    parentCertHash,
    hintBytes: hints.length,
    hintCount: hints.length / 48,
    args: {
      cert: hex(cert),
      parentCertHash,
      signatureHints: hex(hints),
    },
    calldata: encodeCall(signature, [
      { type: "bytes", value: cert },
      { type: "bytes32", value: parentCertHash },
      { type: "bytes", value: hints },
    ]),
    notes: `${functionName} caches this certificate if the parent is already cached and unexpired.`,
  };
}

function attestationTx({ tx, to, attestationTbs, signature, hints }) {
  return {
    tx,
    kind: "validate_attestation",
    label: "validate Nitro attestation document",
    to,
    function: "validateAttestationWithHints(bytes,bytes,bytes)",
    hintBytes: hints.length,
    hintCount: hints.length / 48,
    args: {
      attestationTbs: hex(attestationTbs),
      signature: hex(signature),
      attestationHints: hex(hints),
    },
    calldata: encodeCall("validateAttestationWithHints(bytes,bytes,bytes)", [
      { type: "bytes", value: attestationTbs },
      { type: "bytes", value: signature },
      { type: "bytes", value: hints },
    ]),
    notes: "Requires the cabundle and leaf certificate hashes embedded in attestationTbs to already be cached.",
  };
}

function caLabel(index) {
  if (index === 1) return "regional CA";
  if (index === 2) return "zonal CA";
  if (index === 3) return "issuer / instance CA";
  return `non-root CA ${index}`;
}

function normalizeOptionalAddress(address) {
  if (!address) {
    return null;
  }
  if (!/^0x[0-9a-fA-F]{40}$/.test(address)) {
    throw new Error(`invalid address: ${address}`);
  }
  if (address.toLowerCase() === ZERO_ADDRESS) {
    return ZERO_ADDRESS;
  }
  return `0x${address.slice(2).toLowerCase()}`;
}

function encodeCall(signature, params) {
  const selector = keccak256(Buffer.from(signature, "ascii")).subarray(0, 4);
  return hex(Buffer.concat([selector, encodeParams(params)]));
}

function encodeParams(params) {
  const head = [];
  const tail = [];
  let tailOffset = BigInt(params.length * 32);

  for (const param of params) {
    if (param.type === "bytes") {
      const encoded = encodeBytes(param.value);
      head.push(encodeUint256(tailOffset));
      tail.push(encoded);
      tailOffset += BigInt(encoded.length);
    } else if (param.type === "bytes32") {
      head.push(decodeFixedHex(param.value, 32));
    } else {
      throw new Error(`unsupported ABI type ${param.type}`);
    }
  }

  return Buffer.concat([...head, ...tail]);
}

function encodeBytes(value) {
  const bytes = Buffer.from(value);
  const padding = (32 - (bytes.length % 32)) % 32;
  return Buffer.concat([encodeUint256(BigInt(bytes.length)), bytes, Buffer.alloc(padding)]);
}

function encodeUint256(value) {
  return decodeFixedHex(value.toString(16).padStart(64, "0"), 32);
}

function decodeFixedHex(value, length) {
  const raw = value.startsWith("0x") || value.startsWith("0X") ? value.slice(2) : value;
  if (raw.length !== length * 2 || /[^0-9a-f]/i.test(raw)) {
    throw new Error(`expected ${length}-byte hex value`);
  }
  return Buffer.from(raw, "hex");
}

function keccak256Hex(bytes) {
  return hex(keccak256(bytes));
}

function keccak256(bytes) {
  const state = Array(25).fill(0n);
  let offset = 0;
  const input = Buffer.from(bytes);

  while (offset + RATE_BYTES <= input.length) {
    absorbBlock(state, input.subarray(offset, offset + RATE_BYTES));
    keccakF1600(state);
    offset += RATE_BYTES;
  }

  const finalBlock = Buffer.alloc(RATE_BYTES);
  input.copy(finalBlock, 0, offset);
  finalBlock[input.length - offset] = 0x01;
  finalBlock[RATE_BYTES - 1] |= 0x80;
  absorbBlock(state, finalBlock);
  keccakF1600(state);

  return squeeze(state, 32);
}

function absorbBlock(state, block) {
  for (let i = 0; i < RATE_BYTES / 8; ++i) {
    state[i] ^= readLaneLE(block, i * 8);
  }
}

function squeeze(state, length) {
  const out = Buffer.alloc(length);
  let written = 0;
  for (let i = 0; written < length; ++i) {
    const lane = writeLaneLE(state[i]);
    const take = Math.min(8, length - written);
    lane.copy(out, written, 0, take);
    written += take;
  }
  return out;
}

function keccakF1600(state) {
  const rounds = [
    0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
    0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
    0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
    0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
    0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
    0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
  ];
  const rho = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
  ];

  for (const rc of rounds) {
    const c = Array(5);
    const d = Array(5);
    const b = Array(25);

    for (let x = 0; x < 5; ++x) {
      c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
    }
    for (let x = 0; x < 5; ++x) {
      d[x] = c[(x + 4) % 5] ^ rotl64(c[(x + 1) % 5], 1);
    }
    for (let x = 0; x < 5; ++x) {
      for (let y = 0; y < 5; ++y) {
        state[x + 5 * y] = (state[x + 5 * y] ^ d[x]) & MASK_64;
      }
    }

    for (let x = 0; x < 5; ++x) {
      for (let y = 0; y < 5; ++y) {
        b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl64(state[x + 5 * y], rho[x][y]);
      }
    }

    for (let x = 0; x < 5; ++x) {
      for (let y = 0; y < 5; ++y) {
        state[x + 5 * y] = (b[x + 5 * y] ^ ((~b[((x + 1) % 5) + 5 * y]) & b[((x + 2) % 5) + 5 * y])) & MASK_64;
      }
    }

    state[0] = (state[0] ^ rc) & MASK_64;
  }
}

function rotl64(value, shift) {
  const s = BigInt(shift);
  if (s === 0n) {
    return value & MASK_64;
  }
  return ((value << s) | (value >> (64n - s))) & MASK_64;
}

function readLaneLE(buffer, offset) {
  let value = 0n;
  for (let i = 7; i >= 0; --i) {
    value = (value << 8n) | BigInt(buffer[offset + i]);
  }
  return value;
}

function writeLaneLE(value) {
  const buffer = Buffer.alloc(8);
  let lane = value;
  for (let i = 0; i < 8; ++i) {
    buffer[i] = Number(lane & 0xffn);
    lane >>= 8n;
  }
  return buffer;
}

function hex(bytes) {
  return `0x${Buffer.from(bytes).toString("hex")}`;
}

module.exports = {
  encodeCall,
  keccak256,
  prepareHintedAttestationCalls,
};
