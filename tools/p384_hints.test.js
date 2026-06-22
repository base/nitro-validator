"use strict";

const assert = require("assert");
const test = require("node:test");

const { MAX_CBOR_NESTING_DEPTH, parseAttestationSignature } = require("./p384_hints");

test("parseAttestationSignature rejects excessive CBOR nesting", () => {
  const protectedHeader = Buffer.from([0x44, 0xa1, 0x01, 0x38, 0x22]);
  const unprotectedHeaderPrefix = Buffer.from([0xa1, 0x00]);
  const nestedArrays = Buffer.alloc(MAX_CBOR_NESTING_DEPTH + 1, 0x81);
  const terminalItem = Buffer.from([0x00]);
  const attestation = Buffer.concat([
    Buffer.from([0x84]),
    protectedHeader,
    unprotectedHeaderPrefix,
    nestedArrays,
    terminalItem,
  ]);

  assert.throws(
    () => parseAttestationSignature(attestation),
    (err) =>
      err instanceof Error && !(err instanceof RangeError) && err.message === "CBOR nesting depth exceeded",
  );
});
