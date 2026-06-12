#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");

if (require.main === module) {
  main();
}

function main() {
  try {
    const { command, options } = parseArgs(process.argv.slice(2));
    let attestation;

    if (command === "fixture") {
      attestation = realFixture();
    } else if (command === "read") {
      attestation = decodeBytes(requireOption(options, "input"));
    } else {
      usage();
      process.exit(2);
    }

    if (options.repair === "true" || command === "fixture") {
      attestation = repairMissingPublicKeyBytes(attestation);
    }

    process.stdout.write(`0x${attestation.toString("hex")}`);
  } catch (err) {
    process.stderr.write(`${err.stack || err.message}\n`);
    process.exit(1);
  }
}

function usage() {
  process.stderr.write(`Usage:
  node tools/nitro_attestation_input.js fixture
  node tools/nitro_attestation_input.js read --input <hex|base64|@file> [--repair true]

The fixture mode extracts the January 2026 real attestation from
test/hinted/HintedNitroAttestation.t.sol and applies the documented public_key
repair used by the happy-path tests.
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

function requireOption(options, name) {
  if (options[name] === undefined) {
    throw new Error(`missing --${name}`);
  }
  return options[name];
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

function realFixture() {
  const testPath = path.join(process.cwd(), "test", "hinted", "HintedNitroAttestation.t.sol");
  const source = fs.readFileSync(testPath, "utf8");
  const match = source.match(/function _realAttestationB64\(\)[\s\S]*?return "([^"]+)";/);
  if (!match) {
    throw new Error("could not find _realAttestationB64 fixture");
  }
  return Buffer.from(match[1], "base64");
}

function repairMissingPublicKeyBytes(attestation) {
  const insertAt = 4338;
  const expected = Buffer.from("7075626c6b6579", "hex");
  if (
    attestation.length <= insertAt + 2 ||
    !attestation.subarray(insertAt - 4, insertAt + 3).equals(expected)
  ) {
    throw new Error("unexpected fixture public_key corruption");
  }

  return Buffer.concat([
    attestation.subarray(0, insertAt),
    Buffer.from("69635f", "hex"),
    attestation.subarray(insertAt),
  ]);
}

module.exports = {
  decodeBytes,
  realFixture,
  repairMissingPublicKeyBytes,
};
