// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

import {Test} from "forge-std/Test.sol";
import {CborDecode, CborElement, LibCborElement} from "../src/CborDecode.sol";
import {NitroValidator} from "../src/NitroValidator.sol";
import {ICertManager} from "../src/ICertManager.sol";
import {IP384Verifier} from "../src/IP384Verifier.sol";
import {P384Verifier} from "../src/P384Verifier.sol";

// ──────────────────────────────────────────────────────────────
//  CBOR constants (RFC 8949)
// ──────────────────────────────────────────────────────────────

/// @dev Major type 5 (map) base value.
uint8 constant CBOR_MAP_TYPE = 0xa0;
/// @dev Major type 4 (array) base value.
uint8 constant CBOR_ARRAY_TYPE = 0x80;
/// @dev Indefinite-length map header (major type 5 | ai=31).
uint8 constant CBOR_MAP_INDEFINITE = 0xbf;
/// @dev Indefinite-length array header (major type 4 | ai=31).
uint8 constant CBOR_ARRAY_INDEFINITE = 0x9f;
/// @dev Break stop code terminating indefinite-length items.
uint8 constant CBOR_BREAK = 0xff;
/// @dev Reserved map headers (ai=28..30); must revert.
uint8 constant CBOR_MAP_AI28 = 0xbc;
uint8 constant CBOR_MAP_AI29 = 0xbd;
uint8 constant CBOR_MAP_AI30 = 0xbe;

// ──────────────────────────────────────────────────────────────
//  Expected field dimensions — synthetic test data
// ──────────────────────────────────────────────────────────────

uint256 constant SYNTH_MODULE_ID_LEN = 4; // "test"
uint256 constant SYNTH_DIGEST_LEN = 6; // "SHA384"
uint64 constant SYNTH_TIMESTAMP = 1_000_000;
uint256 constant SYNTH_PCRS_COUNT = 1;
uint256 constant SYNTH_PCR_LEN = 48;
uint256 constant SYNTH_CERT_LEN = 4;
uint256 constant SYNTH_CABUNDLE_COUNT = 1;
uint256 constant SYNTH_CABUNDLE_CERT_LEN = 4;

// ──────────────────────────────────────────────────────────────
//  Expected field dimensions — real AWS Nitro attestation data
// ──────────────────────────────────────────────────────────────

uint256 constant REAL_MODULE_ID_LEN = 39; // "i-0de38b2b6853cc9e8-enc0193685e7fee7d85"
uint256 constant REAL_DIGEST_LEN = 6; // "SHA384"
uint256 constant REAL_PCRS_COUNT = 16;
uint256 constant REAL_PCR_LEN = 48;
uint256 constant REAL_CERT_LEN = 640;
uint256 constant REAL_CABUNDLE_COUNT = 4;
uint256 constant REAL_PUB_KEY_LEN = 65; // non-null ECDSA P-384 uncompressed point

// ──────────────────────────────────────────────────────────────
//  Harness contracts
// ──────────────────────────────────────────────────────────────

/// @notice Exposes CborDecode library internals for unit testing.
contract CborDecodeHarness {
    using CborDecode for bytes;
    using LibCborElement for CborElement;

    function mapAt(bytes memory cbor, uint256 ix) external pure returns (uint8 type_, uint256 start_, uint64 value_) {
        CborElement e = cbor.mapAt(ix);
        return (e.cborType(), e.start(), e.value());
    }

    /// @dev Synthesises a predecessor element ending at `ix` so we can test
    ///      elementAt(cbor, ix, 0x80 /*array*/, true) via nextArray.
    function arrayAt(bytes memory cbor, uint256 ix) external pure returns (uint8 type_, uint256 start_, uint64 value_) {
        // Map type has length()==0, so end()==start()==ix.
        CborElement prev = LibCborElement.toCborElement(CBOR_MAP_TYPE, ix, 0);
        CborElement e = cbor.nextArray(prev);
        return (e.cborType(), e.start(), e.value());
    }

    function skipValue(bytes memory cbor, uint256 ix) external pure returns (uint256) {
        return cbor.skipValue(ix);
    }
}

/// @notice Exposes NitroValidator._parseAttestation (internal pure) for testing.
contract NitroValidatorHarness is NitroValidator {
    constructor(ICertManager cm, IP384Verifier p384Verifier) NitroValidator(cm, p384Verifier) {}

    function parseAttestation(bytes memory attestationTbs) external pure returns (Ptrs memory) {
        return _parseAttestation(attestationTbs);
    }
}

/// @notice Minimal ICertManager stub; _parseAttestation is pure so this is never called.
contract StubCertManager is ICertManager {
    function owner() external pure returns (address) {
        return address(0);
    }

    function revoker() external pure returns (address) {
        return address(0);
    }

    function revoked(bytes32) external pure returns (bool) {
        return false;
    }

    function verifyCACert(bytes memory, bytes32) external pure returns (bytes32) {
        return bytes32(0);
    }

    function verifyClientCert(bytes memory, bytes32) external pure returns (VerifiedCert memory v) {
        return v;
    }

    function verifyCACertWithHints(bytes memory, bytes32, bytes memory) external pure returns (bytes32) {
        return bytes32(0);
    }

    function verifyClientCertWithHints(bytes memory, bytes32, bytes memory)
        external
        pure
        returns (VerifiedCert memory v)
    {
        return v;
    }

    function loadVerified(bytes32) external pure returns (VerifiedCert memory v) {
        return v;
    }

    function isRevoked(bytes32) external pure returns (bool) {
        return false;
    }

    function transferOwnership(address) external pure {}

    function setRevoker(address) external pure {}

    function revokeCert(bytes32) external pure {}

    function revokeCerts(bytes32[] calldata) external pure {}

    function unrevokeCert(bytes32) external pure {}
}

// ──────────────────────────────────────────────────────────────
//  CborDecode-level tests
// ──────────────────────────────────────────────────────────────

/// @notice Unit tests for indefinite-length CBOR support in CborDecode.elementAt.
contract CborDecodeIndefiniteLengthTest is Test {
    CborDecodeHarness harness;

    function setUp() public {
        harness = new CborDecodeHarness();
    }

    // ── shared helper ─────────────────────────────────────────

    function _assertMapReservedReverts(bytes memory header) internal {
        vm.expectRevert("unsupported type");
        harness.mapAt(header, 0);
    }

    // ── Regression: definite-length ───────────────────────────

    /// @dev Definite-length map header 0xA9 (9 entries) still works.
    function test_mapAt_definiteLength() public view {
        (uint8 t, uint256 s, uint64 v) = harness.mapAt(hex"a9", 0);
        assertEq(t, CBOR_MAP_TYPE, "type");
        assertEq(s, 1, "start");
        assertEq(v, 9, "value");
    }

    /// @dev Definite-length map with ai=24 (1-byte count, e.g. 32 entries).
    function test_mapAt_definiteLengthAI24() public view {
        (uint8 t, uint256 s, uint64 v) = harness.mapAt(hex"b820", 0); // ai=24, count=32
        assertEq(t, CBOR_MAP_TYPE, "type");
        assertEq(s, 2, "start after 2-byte header");
        assertEq(v, 32, "value");
    }

    // ── New behaviour: indefinite-length ──────────────────────

    /// @dev Indefinite-length map (0xBF) is accepted, returns value=0.
    function test_mapAt_indefiniteLength() public view {
        (uint8 t, uint256 s, uint64 v) = harness.mapAt(abi.encodePacked(CBOR_MAP_INDEFINITE), 0);
        assertEq(t, CBOR_MAP_TYPE, "type should be base map type");
        assertEq(s, 1, "start after 1-byte header");
        assertEq(v, 0, "value should be 0 (unknown count)");
    }

    /// @dev Indefinite-length array (0x9F) is accepted, returns value=0.
    function test_arrayAt_indefiniteLength() public view {
        (uint8 t, uint256 s, uint64 v) = harness.arrayAt(abi.encodePacked(CBOR_ARRAY_INDEFINITE), 0);
        assertEq(t, CBOR_ARRAY_TYPE, "type should be base array type");
        assertEq(s, 1, "start after 1-byte header");
        assertEq(v, 0, "value should be 0 (unknown count)");
    }

    // ── Negative: reserved additional-info values ─────────────

    /// @dev Reserved additional-info 28 (0xBC) still reverts.
    function test_mapAt_reservedAI28_reverts() public {
        _assertMapReservedReverts(abi.encodePacked(CBOR_MAP_AI28));
    }

    /// @dev Reserved additional-info 29 (0xBD) still reverts.
    function test_mapAt_reservedAI29_reverts() public {
        _assertMapReservedReverts(abi.encodePacked(CBOR_MAP_AI29));
    }

    /// @dev Reserved additional-info 30 (0xBE) still reverts.
    function test_mapAt_reservedAI30_reverts() public {
        _assertMapReservedReverts(abi.encodePacked(CBOR_MAP_AI30));
    }

    // ── skipValue: spans a complete data item of any major type ───

    /// @dev Small unsigned int (ai<24) spans 1 byte.
    function test_skipValue_tinyInt() public view {
        assertEq(harness.skipValue(hex"0a", 0), 1, "uint 10");
    }

    /// @dev 1-byte-argument int (ai=24) spans 2 bytes.
    function test_skipValue_int_ai24() public view {
        assertEq(harness.skipValue(hex"1820", 0), 2, "uint 32");
    }

    /// @dev Byte string spans header + content.
    function test_skipValue_byteString() public view {
        assertEq(harness.skipValue(hex"43aabbcc", 0), 4, "bytes(3)");
    }

    /// @dev Text string spans header + content.
    function test_skipValue_textString() public view {
        assertEq(harness.skipValue(hex"6474657374", 0), 5, "\"test\"");
    }

    /// @dev Definite array recurses through all elements.
    function test_skipValue_definiteArray() public view {
        // [1, [2, 3], 4]
        assertEq(harness.skipValue(hex"830182020304", 0), 6, "array(3) with nested array");
    }

    /// @dev Definite map recurses through key/value pairs.
    function test_skipValue_definiteMap() public view {
        // {1: 2, 3: bytes(2)}
        assertEq(harness.skipValue(hex"a201020342aabb", 0), 7, "map(2)");
    }

    /// @dev Indefinite array stops at break and consumes it.
    function test_skipValue_indefiniteArray() public view {
        // [_ 1, 2 ]
        assertEq(harness.skipValue(hex"9f0102ff", 0), 4, "indefinite array");
    }

    /// @dev Indefinite map stops at break and consumes it.
    function test_skipValue_indefiniteMap() public view {
        // {_ 1: 2 }
        assertEq(harness.skipValue(hex"bf0102ff", 0), 4, "indefinite map");
    }

    /// @dev null / simple values span 1 byte.
    function test_skipValue_null() public view {
        assertEq(harness.skipValue(hex"f6", 0), 1, "null");
    }

    /// @dev Tag spans the tag header plus the tagged item.
    function test_skipValue_tag() public view {
        // tag(0) "..." — 0xC0 then a 1-byte int
        assertEq(harness.skipValue(hex"c001", 0), 2, "tag + int");
    }

    /// @dev Reserved additional-info (28) reverts.
    function test_skipValue_reservedAI_reverts() public {
        vm.expectRevert("invalid cbor additional info");
        harness.skipValue(hex"1c", 0);
    }

    /// @dev A bare break code is not a standalone value.
    function test_skipValue_bareBreak_reverts() public {
        vm.expectRevert("unexpected break");
        harness.skipValue(hex"ff", 0);
    }

    /// @dev Truncated indefinite container (no break) reverts on out-of-bounds read.
    function test_skipValue_truncatedIndefinite_reverts() public {
        vm.expectRevert();
        harness.skipValue(hex"9f0102", 0);
    }
}

// ──────────────────────────────────────────────────────────────
//  NitroValidator._parseAttestation-level tests
// ──────────────────────────────────────────────────────────────

/// @notice Integration tests for indefinite-length map handling in _parseAttestation.
contract NitroValidatorIndefiniteLengthTest is Test {
    using LibCborElement for CborElement;

    NitroValidatorHarness validator;

    function setUp() public {
        validator = new NitroValidatorHarness(ICertManager(address(new StubCertManager())), new P384Verifier());
    }

    // ── Shared assertion helpers ──────────────────────────────

    /// @dev Asserts all fields of a Ptrs parsed from synthetic test data.
    function _assertSyntheticFields(NitroValidator.Ptrs memory p) internal pure {
        assertEq(p.moduleID.length(), SYNTH_MODULE_ID_LEN, "module_id length");
        assertEq(p.timestamp, SYNTH_TIMESTAMP, "timestamp");
        assertEq(p.digest.length(), SYNTH_DIGEST_LEN, "digest length");
        assertEq(p.pcrs.length, SYNTH_PCRS_COUNT, "pcrs count");
        assertEq(p.pcrs[0].length(), SYNTH_PCR_LEN, "pcr[0] length");
        assertEq(p.cert.length(), SYNTH_CERT_LEN, "cert length");
        assertEq(p.cabundle.length, SYNTH_CABUNDLE_COUNT, "cabundle count");
        assertEq(p.cabundle[0].length(), SYNTH_CABUNDLE_CERT_LEN, "cabundle[0] length");
        assertTrue(p.publicKey.isNull(), "public_key null");
        assertTrue(p.userData.isNull(), "user_data null");
        assertTrue(p.nonce.isNull(), "nonce null");
    }

    /// @dev Asserts all fields of a Ptrs parsed from real attestation data.
    function _assertRealFields(NitroValidator.Ptrs memory p) internal pure {
        assertEq(p.moduleID.length(), REAL_MODULE_ID_LEN, "module_id length");
        assertGt(p.timestamp, 0, "timestamp > 0");
        assertEq(p.digest.length(), REAL_DIGEST_LEN, "digest length");
        assertEq(p.pcrs.length, REAL_PCRS_COUNT, "pcrs count");
        for (uint256 i = 0; i < REAL_PCRS_COUNT; i++) {
            assertEq(p.pcrs[i].length(), REAL_PCR_LEN, "pcr length");
        }
        assertEq(p.cert.length(), REAL_CERT_LEN, "cert length");
        assertEq(p.cabundle.length, REAL_CABUNDLE_COUNT, "cabundle count");
        // public_key is NON-null in this real attestation
        assertFalse(p.publicKey.isNull(), "public_key non-null");
        assertEq(p.publicKey.length(), REAL_PUB_KEY_LEN, "public_key length");
        assertTrue(p.userData.isNull(), "user_data null");
        assertTrue(p.nonce.isNull(), "nonce null");
    }

    // ── TBS construction helpers ─────────────────────────────

    /// @dev Wraps raw CBOR map bytes into a valid attestation-TBS envelope.
    ///      Layout: [18B prefix] [payload byte-string header] [mapBytes]
    function _buildTbs(bytes memory mapBytes) internal pure returns (bytes memory) {
        bytes memory prefix = hex"846a5369676e61747572653144a101382240";
        uint256 len = mapBytes.length;
        if (len <= 23) {
            return abi.encodePacked(prefix, uint8(0x40 | len), mapBytes);
        } else if (len <= 255) {
            return abi.encodePacked(prefix, uint8(0x58), uint8(len), mapBytes);
        } else {
            return abi.encodePacked(prefix, uint8(0x59), uint16(len), mapBytes);
        }
    }

    /// @dev Converts a definite-length attestation TBS to indefinite-length by
    ///      replacing the map header with 0xBF, appending 0xFF, and bumping the
    ///      payload byte-string length by 1.
    function _toIndefiniteLength(bytes memory tbs) internal pure returns (bytes memory) {
        bytes memory out = new bytes(tbs.length + 1);
        for (uint256 i = 0; i < tbs.length; i++) {
            out[i] = tbs[i];
        }
        out[tbs.length] = bytes1(CBOR_BREAK);

        // Parse payload byte-string header at index 18 to locate map header.
        uint8 ai = uint8(out[18]) & 0x1f;
        uint256 mapIdx;
        if (ai <= 23) {
            mapIdx = 19;
            out[18] = bytes1(uint8(out[18]) + 1);
        } else if (ai == 24) {
            mapIdx = 20;
            out[19] = bytes1(uint8(out[19]) + 1);
        } else if (ai == 25) {
            mapIdx = 21;
            uint16 len = (uint16(uint8(out[19])) << 8) | uint16(uint8(out[20]));
            len++;
            out[19] = bytes1(uint8(len >> 8));
            out[20] = bytes1(uint8(len));
        } else {
            revert("unsupported payload header ai");
        }

        out[mapIdx] = bytes1(CBOR_MAP_INDEFINITE);
        return out;
    }

    // ── Synthetic CBOR entry builders ─────────────────────────

    /// @dev 9 standard attestation map entries (null optional fields).
    function _entries() internal pure returns (bytes memory) {
        bytes memory part1 = abi.encodePacked(
            hex"696d6f64756c655f6964", // key  "module_id"  (text, 9B)
            hex"6474657374", //           val  "test"       (text, 4B)
            hex"66646967657374", //       key  "digest"     (text, 6B)
            hex"66534841333834", //       val  "SHA384"     (text, 6B)
            hex"6974696d657374616d70", // key  "timestamp"  (text, 9B)
            hex"1a000f4240" //            val  1_000_000    (uint32)
        );
        bytes memory part2 = abi.encodePacked(
            hex"6470637273", //           key  "pcrs"       (text, 4B)
            hex"a1005830", //             val  {0: bytes48(0)} — definite 1-entry map
            new bytes(SYNTH_PCR_LEN) //   48 zero bytes
        );
        bytes memory part3 = abi.encodePacked(
            hex"6b6365727469666963617465", // key  "certificate" (text, 11B)
            hex"4400000000", //               val  bytes(4)
            hex"68636162756e646c65", //       key  "cabundle"    (text, 8B)
            hex"814400000000" //              val  [bytes(4)]    (1-elem array)
        );
        bytes memory part4 = abi.encodePacked(
            hex"6a7075626c69635f6b6579", // key  "public_key" (text, 10B)
            hex"f6", //                     val  null
            hex"69757365725f64617461", //   key  "user_data"  (text, 9B)
            hex"f6", //                     val  null
            hex"656e6f6e6365", //           key  "nonce"      (text, 5B)
            hex"f6" //                      val  null
        );
        return abi.encodePacked(part1, part2, part3, part4);
    }

    /// @dev Subset of entries: only module_id and digest.
    function _partialEntries() internal pure returns (bytes memory) {
        return abi.encodePacked(
            hex"696d6f64756c655f6964", // key  "module_id"
            hex"6474657374", //           val  "test"
            hex"66646967657374", //       key  "digest"
            hex"66534841333834" //        val  "SHA384"
        );
    }

    /// @dev Same 9 entries in a different key order (nonce first, module_id last).
    function _reorderedEntries() internal pure returns (bytes memory) {
        bytes memory part1 = abi.encodePacked(
            hex"656e6f6e6365",
            hex"f6", //                     nonce → null
            hex"66646967657374",
            hex"66534841333834", //       digest → "SHA384"
            hex"6974696d657374616d70",
            hex"1a000f4240" //      timestamp → 1_000_000
        );
        bytes memory part2 = abi.encodePacked(
            hex"6470637273",
            hex"a1005830",
            new bytes(SYNTH_PCR_LEN) // pcrs → {0: 48B}
        );
        bytes memory part3 = abi.encodePacked(
            hex"6b6365727469666963617465",
            hex"4400000000", //  certificate → bytes(4)
            hex"68636162756e646c65",
            hex"814400000000" //       cabundle → [bytes(4)]
        );
        bytes memory part4 = abi.encodePacked(
            hex"6a7075626c69635f6b6579",
            hex"f6", //           public_key → null
            hex"69757365725f64617461",
            hex"f6", //             user_data → null
            hex"696d6f64756c655f6964",
            hex"6474657374" //      module_id → "test"
        );
        return abi.encodePacked(part1, part2, part3, part4);
    }

    // ── Real AWS Nitro attestation TBS ────────────────────────

    /// @dev Real attestation TBS from a running AWS Nitro Enclave (definite-length,
    ///      9-entry map, 16 PCRs, 4-cert cabundle, non-null 65-byte public_key).
    ///      Contains 20 embedded 0xFF bytes inside DER-encoded certificate data —
    ///      critical for verifying the break-marker check does not false-trigger.
    // solhint-disable-next-line function-max-lines
    function _realAttestationTbs() internal pure returns (bytes memory) {
        // Split into chunks to stay within stack limits.
        // Chunk boundaries are arbitrary; the hex is one contiguous blob.
        bytes memory c1 =
            hex"846a5369676e61747572653144a101382240591144a9696d6f64756c655f69647827692d30646533386232623638353363633965382d656e633031393336383565376665653764383566646967657374665348413338346974696d657374616d701b000001937de1c5436470637273b0005830ec74bfbe7f7445a6c7610e152935e028276f638042b74797b119648e13f7a3675796b721034c320f140ea001b41aeae2015830fa2593b59f3e4fc7daba5cbdddfd3449d67cd02d43bb1128885e8f38b914d081dccdb68fff6d5b7a76bcb866a18a74a302583056ba201a72e36cd051e95e5c4724c899039b711770f4d9d4fe7a1de007119a10b364badcd35e90f728a5bdc9109057230358303c9cadd84f0d027d6a5370c3de4af9179824fd6f3f02ebab723ee4439c75d8f5183e1c55f523415d44e9e6580b06655204583098bdf1bde262272618ccd73279e8ee00dd2c36974bd253de55413a25ceb2cd7221421207c2c09dde609f87481b6f6c940558300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000658300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000758300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000858300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000958300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a58300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b58300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c583000000000000000000000000000";
        bytes memory c2 =
            hex"00000000000000000000000000000000000000000000000000000000000000000000000d58300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e58300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f58300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006b63657274696669636174655902803082027c30820201a00302010202100193685e7fee7d8500000000674b3bd8300a06082a8648ce3d04030330818e310b30090603550406130255533113301106035504080c0a57617368696e67746f6e3110300e06035504070c0753656174746c65310f300d060355040a0c06416d617a6f6e310c300a060355040b0c034157533139303706035504030c30692d30646533386232623638353363633965382e75732d656173742d312e6177732e6e6974726f2d656e636c61766573301e170d3234313133303136323234355a170d3234313133303139323234385a308193310b30090603550406130255533113301106035504080c0a57617368696e67746f6e3110300e06035504070c0753656174746c65310f300d060355040a0c06416d617a6f6e310c300a060355040b0c03415753313e303c06035504030c35692d30646533386232623638353363633965382d656e63303139333638356537666565376438352e75732d656173742d312e6177733076301006072a8648ce3d020106052b810400220362000461d930c61be969237398264901d6a37282cfd42c0694d012d9143cc86a339d567913dae552bad2f10d47c50d4e670247f0344983cbdc2d2e0045d4ccbdff59ef7a26ebf1be83a81e24a651c92008fe9f465757792a0877fba02c8b5e1eb2ed90a31d301b300c0603551d130101ff04023000300b0603551d0f0404030206c0300a06082a8648ce3d04030303690030";
        bytes memory c3 =
            hex"66023100e48f39a39b444a6e5ea7a38b808198a2318dd531ed62faf4a9223f71f27dff4a5e495e32dd10f250bbaf1f892a4d328f023100d09fc8e48e233b9e972eecb94798865664dbeb0d75b29041f482777a4b7cae133483dcc9d35509c4967be51db37a745468636162756e646c65845902153082021130820196a003020102021100f93175681b90afe11d46ccb4e4e7f856300a06082a8648ce3d0403033049310b3009060355040613025553310f300d060355040a0c06416d617a6f6e310c300a060355040b0c03415753311b301906035504030c126177732e6e6974726f2d656e636c61766573301e170d3139313032383133323830355a170d3439313032383134323830355a3049310b3009060355040613025553310f300d060355040a0c06416d617a6f6e310c300a060355040b0c03415753311b301906035504030c126177732e6e6974726f2d656e636c617665733076301006072a8648ce3d020106052b8104002203620004fc0254eba608c1f36870e29ada90be46383292736e894bfff672d989444b5051e534a4b1f6dbe3c0bc581a32b7b176070ede12d69a3fea211b66e752cf7dd1dd095f6f1370f4170843d9dc100121e4cf63012809664487c9796284304dc53ff4a3423040300f0603551d130101ff040530030101ff301d0603551d0e041604149025b50dd90547e796c396fa729dcf99a9df4b96300e0603551d0f0101ff040403020186300a06082a8648ce3d0403030369003066023100a37f2f91a1c9bd5ee7b8627c1698d255038e1f0343f95b63a9628c3d39809545a11ebcbf2e3b55d8aeee71b4c3d6adf3023100a2f39b1605b27028a5dd4ba069b5016e65b4fbde8fe0061d6a53197f9cdaf5d943bc61fc2beb03cb6fee8d2302f3dff65902c2308202be30820244a003020102021056bfc987fd05ac99c475061b1a65eedc300a06082a8648ce3d0403033049310b3009060355040613025553310f300d060355040a0c06416d617a6f6e310c300a060355040b0c034157";
        bytes memory c4 =
            hex"53311b301906035504030c126177732e6e6974726f2d656e636c61766573301e170d3234313132383036303734355a170d3234313231383037303734355a3064310b3009060355040613025553310f300d060355040a0c06416d617a6f6e310c300a060355040b0c034157533136303406035504030c2d636264383238303866646138623434642e75732d656173742d312e6177732e6e6974726f2d656e636c617665733076301006072a8648ce3d020106052b81040022036200040713751f4391a24bf27d688c9fdde4b7eec0c4922af63f242186269602eca12354e79356170287baa07dd84fa89834726891f9b4b27032b3e86000d32471a79fbf1a30c1982ad4ed069ad96a7e11d9ae2b5cd6a93ad613ee559ed7f6385a9a89a381d53081d230120603551d130101ff040830060101ff020102301f0603551d230418301680149025b50dd90547e796c396fa729dcf99a9df4b96301d0603551d0e04160414bfbd54a168f57f7391b66ca60a2836f30acfb9a1300e0603551d0f0101ff040403020186306c0603551d1f046530633061a05fa05d865b687474703a2f2f6177732d6e6974726f2d656e636c617665732d63726c2e73332e616d617a6f6e6177732e636f6d2f63726c2f61623439363063632d376436332d343262642d396539662d3539333338636236376638342e63726c300a06082a8648ce3d0403030368003065023100c05dfd13378b1eecd926b0c3ba8da01eec89ec5502ae7ca73cb958557ca323057962fff2681993a0ab223b6eacf11033023035664252d7f9e2c89c988cc4164d390f898a5e8ac2e99dc58595aa4c624e93face7964026a99b4bcca7088b51250ccc459031a308203163082029ba003020102021100cb286a4a4a09207f8b0c14950dcd6861300a06082a8648ce3d0403033064310b3009060355040613025553310f300d060355040a0c06416d617a6f6e310c300a060355040b0c034157533136303406035504030c2d636264383238303866646138623434642e75";
        bytes memory c5 =
            hex"732d656173742d312e6177732e6e6974726f2d656e636c61766573301e170d3234313133303033313435345a170d3234313230363031313435345a308189313c303a06035504030c33343762313739376131663031386266302e7a6f6e616c2e75732d656173742d312e6177732e6e6974726f2d656e636c61766573310c300a060355040b0c03415753310f300d060355040a0c06416d617a6f6e310b3009060355040613025553310b300906035504080c0257413110300e06035504070c0753656174746c653076301006072a8648ce3d020106052b810400220362000423959f700ef87dcbdba686449d944f2a89ad22aa03d73cf93d28853f2fb6a80b0cc714d3090e34cda8234eef8f804e46c0dcb216062afba3e2b36a693660d9965e2370308b8e1ffad8542ddbe3e733077481b0cbc747d8c7beb7612820d4fe95a381ea3081e730120603551d130101ff040830060101ff020101301f0603551d23041830168014bfbd54a168f57f7391b66ca60a2836f30acfb9a1301d0603551d0e04160414bbf52a3a42fdc4f301f72536b90e65aaa1b70a99300e0603551d0f0101ff0404030201863081800603551d1f047930773075a073a071866f687474703a2f2f63726c2d75732d656173742d312d6177732d6e6974726f2d656e636c617665732e73332e75732d656173742d312e616d617a6f6e6177732e636f6d2f63726c2f30366434386638652d326330382d343738312d613634352d6231646534303261656662382e63726c300a06082a8648ce3d0403030369003066023100fa31509230632a002939201eb5686b52d79f0276db5c2b954bed324caa5c3271a60d25e2e05a5e6700e488a074af4ecd02310084770462c2ef86dcdb11fa8a31dcf770866cbd28822b682a112b98c09a30e35e94affd3482bf8b01b59a0a7775b4af185902c3308202bf30820245a003020102021500c8925d382506d820d93d2c704a7523c4ba2ddfaa300a06082a8648ce3d040303308189313c303a06035504030c33";
        bytes memory c6 =
            hex"343762313739376131663031386266302e7a6f6e616c2e75732d656173742d312e6177732e6e6974726f2d656e636c61766573310c300a060355040b0c03415753310f300d060355040a0c06416d617a6f6e310b3009060355040613025553310b300906035504080c0257413110300e06035504070c0753656174746c65301e170d3234313133303132343133315a170d3234313230313132343133315a30818e310b30090603550406130255533113301106035504080c0a57617368696e67746f6e3110300e06035504070c0753656174746c65310f300d060355040a0c06416d617a6f6e310c300a060355040b0c034157533139303706035504030c30692d30646533386232623638353363633965382e75732d656173742d312e6177732e6e6974726f2d656e636c617665733076301006072a8648ce3d020106052b8104002203620004466754b5718024df3564bcd722361e7c65a4922eda7b1f826758e30afac40b04a281062897d085311fd509b70a6bbc5f8280f86ae2ff255ad147146fc97b7afb16064f0712d335c1d473b716be320be625e91c5870973084b3a0005bc020c7b2a366306430120603551d130101ff040830060101ff020100300e0603551d0f0101ff040403020204301d0603551d0e04160414345c86a9ec55bc30cafd923d6b73111d9c57abc0301f0603551d23041830168014bbf52a3a42fdc4f301f72536b90e65aaa1b70a99300a06082a8648ce3d0403030368003065023100aba82c02f40acb9846012bf070578217eeb2ebbfd16414948438cf67eeab6f64cdc5a152998766c88b2cdebd5a97ebd402307421611ed511567bc8e6a0a2805b981ef38dc3bd6a6c661522802b5c5d658cc4fcc9b5e8df148b161d366926896736836a7075626c69635f6b657958410433a4701fa871b188983d570e2c2d8cf98fd66eb19ba8ca7617bc8e20e152a5d7f0205eae76e608ce855077e4565be69db4471ef72857253742f9602c11ff04e569757365725f64617461f6656e6f6e6365f6";
        return abi.encodePacked(c1, c2, c3, c4, c5, c6);
    }

    // ══════════════════════════════════════════════════════════
    //  SYNTHETIC DATA TESTS
    // ══════════════════════════════════════════════════════════

    // ── Regression: definite-length map ───────────────────────

    /// @dev 0xA9 (9-entry definite map) parses all fields correctly.
    function test_synth_definiteLengthMap() public view {
        bytes memory tbs = _buildTbs(abi.encodePacked(hex"a9", _entries()));
        _assertSyntheticFields(validator.parseAttestation(tbs));
    }

    // ── New behaviour: indefinite-length map ──────────────────

    /// @dev 0xBF + entries + 0xFF parses all fields correctly.
    function test_synth_indefiniteLengthMap() public view {
        bytes memory tbs = _buildTbs(abi.encodePacked(CBOR_MAP_INDEFINITE, _entries(), CBOR_BREAK));
        _assertSyntheticFields(validator.parseAttestation(tbs));
    }

    /// @dev Indefinite-length map with keys in a non-standard order.
    function test_synth_indefiniteLengthMap_reorderedKeys() public view {
        bytes memory tbs = _buildTbs(abi.encodePacked(CBOR_MAP_INDEFINITE, _reorderedEntries(), CBOR_BREAK));
        _assertSyntheticFields(validator.parseAttestation(tbs));
    }

    // ══════════════════════════════════════════════════════════
    //  REAL AWS NITRO ATTESTATION DATA TESTS
    // ══════════════════════════════════════════════════════════

    /// @dev Real definite-length attestation (regression).
    function test_real_definiteLengthMap() public view {
        _assertRealFields(validator.parseAttestation(_realAttestationTbs()));
    }

    /// @dev Real attestation converted to indefinite-length.
    ///      The certificate DER data contains 20 embedded 0xFF bytes;
    ///      this test verifies the break-marker check only fires on the
    ///      actual break code, not on 0xFF inside byte-string content.
    function test_real_indefiniteLengthMap() public view {
        bytes memory indef = _toIndefiniteLength(_realAttestationTbs());
        _assertRealFields(validator.parseAttestation(indef));
    }

    // ══════════════════════════════════════════════════════════
    //  EDGE CASES
    // ══════════════════════════════════════════════════════════

    /// @dev Empty indefinite-length map (0xBF 0xFF): returns zero-initialised
    ///      Ptrs without reverting.  Downstream validateAttestation() would
    ///      catch missing required fields.
    function test_edge_emptyIndefiniteLengthMap() public view {
        bytes memory tbs = _buildTbs(abi.encodePacked(CBOR_MAP_INDEFINITE, CBOR_BREAK));

        NitroValidator.Ptrs memory p = validator.parseAttestation(tbs);

        assertEq(p.moduleID.length(), 0, "module_id unset");
        assertEq(p.timestamp, 0, "timestamp unset");
        assertEq(p.pcrs.length, 0, "pcrs unset");
        assertEq(p.cabundle.length, 0, "cabundle unset");
    }

    /// @dev Break marker after only two entries: loop terminates early,
    ///      parsed fields retained, unparsed fields remain zero.
    function test_edge_breakMarkerTerminatesEarly() public view {
        bytes memory tbs = _buildTbs(abi.encodePacked(CBOR_MAP_INDEFINITE, _partialEntries(), CBOR_BREAK));

        NitroValidator.Ptrs memory p = validator.parseAttestation(tbs);

        // Parsed entries
        assertEq(p.moduleID.length(), SYNTH_MODULE_ID_LEN, "module_id parsed");
        assertEq(p.digest.length(), SYNTH_DIGEST_LEN, "digest parsed");
        // Unparsed entries remain zero-initialised
        assertEq(p.timestamp, 0, "timestamp not parsed");
        assertEq(p.pcrs.length, 0, "pcrs not parsed");
        assertEq(p.cert.length(), 0, "cert not parsed");
        assertEq(p.cabundle.length, 0, "cabundle not parsed");
    }

    // ── Converter verification ───────────────────────────────

    /// @dev Verifies _toIndefiniteLength produces structurally correct output:
    ///      +1 byte total, break marker appended, map header replaced with 0xBF,
    ///      payload byte-string length incremented, entry content preserved.
    function test_converter_structurallyCorrect() public pure {
        bytes memory def = _buildTbs(abi.encodePacked(hex"a9", _entries()));
        bytes memory indef = _toIndefiniteLength(def);

        // Output is exactly 1 byte longer (break marker appended)
        assertEq(indef.length, def.length + 1, "length +1");

        // Last byte is break marker
        assertEq(uint8(indef[indef.length - 1]), CBOR_BREAK, "last byte 0xFF");

        // Locate map header via payload byte-string AI
        uint8 bstrAi = uint8(indef[18]) & 0x1f;
        uint256 mapIdx = bstrAi <= 23 ? uint256(19) : bstrAi == 24 ? uint256(20) : uint256(21);

        // Map header replaced with indefinite marker
        assertEq(uint8(indef[mapIdx]), CBOR_MAP_INDEFINITE, "map header 0xBF");

        // Payload byte-string length incremented by 1
        if (bstrAi == 24) {
            assertEq(uint8(indef[19]), uint8(def[19]) + 1, "bstr len +1");
        } else if (bstrAi == 25) {
            uint16 defLen = (uint16(uint8(def[19])) << 8) | uint16(uint8(def[20]));
            uint16 indefLen = (uint16(uint8(indef[19])) << 8) | uint16(uint8(indef[20]));
            assertEq(uint256(indefLen), uint256(defLen + 1), "bstr len +1");
        }

        // Entry content between map header and break marker is preserved
        for (uint256 i = mapIdx + 1; i < def.length; i++) {
            assertEq(uint8(indef[i]), uint8(def[i]), "entry content preserved");
        }
    }

    // ── Break check boundary: 0xFF in value content ─────────

    /// @dev Certificate byte-string whose content is [0xFF, 0xFF], placed
    ///      immediately before the break marker. After parsing, current.end()
    ///      points past the content to the break code. Verifies the break check
    ///      at NitroValidator.sol:157 only examines header positions, not value
    ///      content bytes.
    function test_edge_certValueContainingFF_beforeBreak() public view {
        bytes memory entries = abi.encodePacked(
            hex"6b6365727469666963617465", // key "certificate"
            hex"42ffff" //                    val 2-byte bstr: [0xFF, 0xFF]
        );
        bytes memory tbs = _buildTbs(abi.encodePacked(CBOR_MAP_INDEFINITE, entries, CBOR_BREAK));

        NitroValidator.Ptrs memory p = validator.parseAttestation(tbs);
        assertEq(p.cert.length(), 2, "cert parsed despite 0xFF content");
    }

    // ── Inner indefinite-length structures ───────────────────

    /// @dev Inner PCRs map as empty indefinite-length (0xBF 0xFF) inside a
    ///      definite-length outer map. The inner break marker is consumed by the
    ///      pcrs handler, so the outer loop continues and entries after pcrs are
    ///      parsed normally (L2 forward-compatibility fix).
    function test_edge_innerIndefinitePcrsEmpty_parsesAndContinues() public view {
        bytes memory part1 = abi.encodePacked(
            hex"696d6f64756c655f6964",
            hex"6474657374", //       module_id: "test"
            hex"66646967657374",
            hex"66534841333834", //         digest: "SHA384"
            hex"6974696d657374616d70",
            hex"1a000f4240" //        timestamp: 1_000_000
        );
        bytes memory part2 = abi.encodePacked(
            hex"6470637273", // key "pcrs"
            hex"bfff" //       val: empty indefinite-length map {0xBF, 0xFF}
        );
        bytes memory part3 = abi.encodePacked(
            hex"6b6365727469666963617465",
            hex"4400000000", //   certificate: bytes(4)
            hex"68636162756e646c65",
            hex"814400000000", //       cabundle: [bytes(4)]
            hex"6a7075626c69635f6b6579",
            hex"f6", //            public_key: null
            hex"69757365725f64617461",
            hex"f6", //              user_data: null
            hex"656e6f6e6365",
            hex"f6" //                       nonce: null
        );
        bytes memory tbs = _buildTbs(abi.encodePacked(hex"a9", part1, part2, part3));
        NitroValidator.Ptrs memory p = validator.parseAttestation(tbs);

        // Fields before pcrs: parsed normally
        assertEq(p.moduleID.length(), SYNTH_MODULE_ID_LEN, "module_id parsed");
        assertEq(p.digest.length(), SYNTH_DIGEST_LEN, "digest parsed");
        assertEq(p.timestamp, SYNTH_TIMESTAMP, "timestamp parsed");

        // pcrs: empty (indefinite-length map with no entries)
        assertEq(p.pcrs.length, 0, "pcrs empty");

        // Fields after pcrs: now parsed — the inner break is consumed, not leaked
        assertEq(p.cert.length(), SYNTH_CERT_LEN, "cert parsed");
        assertEq(p.cabundle.length, SYNTH_CABUNDLE_COUNT, "cabundle parsed");
        assertEq(p.cabundle[0].length(), SYNTH_CABUNDLE_CERT_LEN, "cabundle[0] parsed");
        assertTrue(p.publicKey.isNull(), "public_key parsed");
        assertTrue(p.userData.isNull(), "user_data parsed");
        assertTrue(p.nonce.isNull(), "nonce parsed");
    }

    /// @dev Inner non-empty indefinite-length pcrs map ({0:48B, 1:48B} as 0xBF ... 0xFF)
    ///      inside a definite-length outer map parses both PCR entries and continues.
    function test_edge_innerIndefinitePcrsNonEmpty_parses() public view {
        bytes memory part1 = abi.encodePacked(
            hex"696d6f64756c655f6964",
            hex"6474657374", //       module_id: "test"
            hex"66646967657374",
            hex"66534841333834", //         digest: "SHA384"
            hex"6974696d657374616d70",
            hex"1a000f4240" //        timestamp: 1_000_000
        );
        // pcrs: indefinite map {0: 48B, 1: 48B}
        bytes memory pcrs = abi.encodePacked(
            hex"6470637273", // key "pcrs"
            CBOR_MAP_INDEFINITE,
            hex"005830",
            new bytes(SYNTH_PCR_LEN), // 0 -> 48B
            hex"015830",
            new bytes(SYNTH_PCR_LEN), // 1 -> 48B
            CBOR_BREAK
        );
        bytes memory part3 = abi.encodePacked(
            hex"6b6365727469666963617465",
            hex"4400000000", //   certificate: bytes(4)
            hex"68636162756e646c65",
            hex"814400000000", //       cabundle: [bytes(4)]
            hex"6a7075626c69635f6b6579",
            hex"f6",
            hex"69757365725f64617461",
            hex"f6",
            hex"656e6f6e6365",
            hex"f6"
        );
        bytes memory tbs = _buildTbs(abi.encodePacked(hex"a9", part1, pcrs, part3));
        NitroValidator.Ptrs memory p = validator.parseAttestation(tbs);

        assertEq(p.pcrs.length, 2, "two pcrs parsed");
        assertEq(p.pcrs[0].length(), SYNTH_PCR_LEN, "pcr[0] length");
        assertEq(p.pcrs[1].length(), SYNTH_PCR_LEN, "pcr[1] length");
        // entries after pcrs still parsed
        assertEq(p.cert.length(), SYNTH_CERT_LEN, "cert parsed");
        assertEq(p.cabundle.length, SYNTH_CABUNDLE_COUNT, "cabundle parsed");
    }

    // ══════════════════════════════════════════════════════════
    //  NEGATIVE TESTS
    // ══════════════════════════════════════════════════════════

    /// @dev Unknown key in a definite-length map is skipped; known fields still parse
    ///      (L1 forward-compatibility fix). The unknown value here is a nested map, to
    ///      exercise the recursive skipValue path.
    function test_unknownKeyDefinite_isSkipped() public view {
        // 9 known entries + 1 unknown ("extra" -> {1: 2}) = 10-entry definite map (0xAA).
        bytes memory unknownEntry = abi.encodePacked(
            hex"656578747261", // key  "extra" (text, 5B)
            hex"a10102" //        val  {1: 2}  (nested 1-entry map)
        );
        bytes memory tbs = _buildTbs(abi.encodePacked(hex"aa", _entries(), unknownEntry));
        _assertSyntheticFields(validator.parseAttestation(tbs));
    }

    /// @dev Unknown key in an indefinite-length map is skipped; known fields still parse.
    ///      The unknown value here is an array, a different skipValue branch.
    function test_unknownKeyIndefinite_isSkipped() public view {
        bytes memory unknownEntry = abi.encodePacked(
            hex"63626164", // key  "bad" (text, 3B)
            hex"820102" //    val  [1, 2]  (array(2): 0x82, 0x01, 0x02)
        );
        bytes memory tbs = _buildTbs(abi.encodePacked(CBOR_MAP_INDEFINITE, _entries(), unknownEntry, CBOR_BREAK));
        _assertSyntheticFields(validator.parseAttestation(tbs));
    }

    /// @dev Unknown key whose value is a byte string is skipped by length.
    function test_unknownKeyByteStringValue_isSkipped() public view {
        bytes memory unknownEntry = abi.encodePacked(
            hex"63626164", // key  "bad"
            hex"43aabbcc" //  val  bytes(3) = 0xAABBCC
        );
        bytes memory tbs = _buildTbs(abi.encodePacked(hex"aa", _entries(), unknownEntry));
        _assertSyntheticFields(validator.parseAttestation(tbs));
    }

    /// @dev Indefinite-length map without a trailing 0xFF break marker.
    ///      Parser reads past valid entries into trailing garbage, reverting
    ///      when it encounters a non-text-string byte as the next key.
    function test_neg_missingBreakMarker_reverts() public {
        bytes memory entries = _partialEntries();
        bytes memory garbage = hex"0000"; // positive int 0 — not a text string key
        vm.expectRevert("unexpected type");
        validator.parseAttestation(_buildTbs(abi.encodePacked(CBOR_MAP_INDEFINITE, entries, garbage)));
    }

    /// @dev Indefinite-length outer map containing a non-empty indefinite-length
    ///      inner cabundle array now parses every element and continues past the
    ///      inner break marker (L2 forward-compatibility fix).
    function test_nestedIndefiniteNonEmptyArray_parses() public view {
        bytes memory entries = abi.encodePacked(
            hex"68636162756e646c65", // key "cabundle"
            CBOR_ARRAY_INDEFINITE, //   indefinite-length array
            hex"4401020304", //         element 0: bytes(4)
            hex"4405060708", //         element 1: bytes(4)
            CBOR_BREAK //               inner array break
        );
        bytes memory tbs = _buildTbs(abi.encodePacked(CBOR_MAP_INDEFINITE, entries, CBOR_BREAK));
        NitroValidator.Ptrs memory p = validator.parseAttestation(tbs);
        assertEq(p.cabundle.length, 2, "two cabundle elements parsed");
        assertEq(p.cabundle[0].length(), 4, "cabundle[0] length");
        assertEq(p.cabundle[1].length(), 4, "cabundle[1] length");
    }

    /// @dev Empty indefinite-length inner cabundle array ([0x9F, 0xFF]) parses as an
    ///      empty cabundle and the outer loop continues.
    function test_nestedIndefiniteEmptyArray_parses() public view {
        bytes memory entries = abi.encodePacked(
            hex"68636162756e646c65", // key "cabundle"
            CBOR_ARRAY_INDEFINITE,
            CBOR_BREAK,
            hex"66646967657374",
            hex"66534841333834" // digest: "SHA384" after cabundle
        );
        bytes memory tbs = _buildTbs(abi.encodePacked(CBOR_MAP_INDEFINITE, entries, CBOR_BREAK));
        NitroValidator.Ptrs memory p = validator.parseAttestation(tbs);
        assertEq(p.cabundle.length, 0, "cabundle empty");
        assertEq(p.digest.length(), SYNTH_DIGEST_LEN, "digest after empty cabundle parsed");
    }
}
