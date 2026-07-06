// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;

import {Test} from "forge-std/Test.sol";
import {Asn1Decode, Asn1Ptr, LibAsn1Ptr} from "../src/Asn1Decode.sol";

contract Asn1Harness {
    using Asn1Decode for bytes;
    using LibAsn1Ptr for Asn1Ptr;

    function rootLength(bytes memory der) external pure returns (uint256) {
        return der.root().length();
    }

    function rootContent(bytes memory der) external pure returns (uint256) {
        return der.root().content();
    }

    function uintAtRoot(bytes memory der) external pure returns (uint256) {
        return der.uintAt(der.root());
    }

    function uint384AtRoot(bytes memory der) external pure returns (uint128 hi, uint256 lo) {
        return der.uint384At(der.root());
    }

    function timestampAtRoot(bytes memory der) external pure returns (uint256) {
        return der.timestampAt(der.root());
    }

    function bitstringContent(bytes memory der) external pure returns (uint256) {
        return der.bitstring(der.root()).content();
    }

    function bitstringUintAtRoot(bytes memory der) external pure returns (uint256) {
        return der.bitstringUintAt(der.root());
    }

    function firstChildHeader(bytes memory der) external pure returns (uint256) {
        return der.firstChildOf(der.root()).header();
    }
}

contract Asn1DecodeTest is Test {
    Asn1Harness h;

    function setUp() public {
        h = new Asn1Harness();
    }

    // --- readNodeLength / tag handling ---

    function test_root_multiByteTag_reverts() public {
        vm.expectRevert(Asn1Decode.UnsupportedAsn1Tag.selector);
        h.rootLength(hex"1f00"); // low tag bits 0x1f == high-tag-number form
    }

    function test_root_emptyInput_reverts() public {
        vm.expectRevert(); // der[0] out-of-bounds
        h.rootLength(hex"");
    }

    // length encoded over >2 bytes and exceeding 2**64-1 must be rejected
    function test_root_oversizedLength_reverts() public {
        vm.expectRevert(); // require(length <= 2**64-1) has no message
        h.rootLength(hex"0289ffffffffffffffffff"); // INTEGER, 9 length bytes all 0xff
    }

    function test_root_indefiniteLength_reverts() public {
        vm.expectRevert(Asn1Decode.InvalidAsn1Length.selector);
        h.rootLength(hex"0480"); // DER requires definite lengths
    }

    function test_root_longFormForShortLength_reverts() public {
        vm.expectRevert(Asn1Decode.InvalidAsn1Length.selector);
        h.rootLength(hex"04810100"); // length 1 must use short form 0x01
    }

    function test_root_longFormLeadingZero_reverts() public {
        vm.expectRevert(Asn1Decode.InvalidAsn1Length.selector);
        h.rootLength(hex"04820080"); // length 128 must be 0x81 0x80, not 0x82 0x00 0x80
    }

    function test_root_canonicalLongFormLength() public view {
        bytes memory der = abi.encodePacked(bytes3(0x048180), new bytes(128));

        assertEq(h.rootLength(der), 128);
        assertEq(h.rootContent(der), 3);
    }

    // --- uintAt ---

    function test_uintAt_value() public view {
        assertEq(h.uintAtRoot(hex"0203012345"), 0x012345); // INTEGER 0x012345
    }

    function test_uintAt_requiredLeadingZero() public view {
        assertEq(h.uintAtRoot(hex"02020080"), 0x80);
    }

    function test_uintAt_unnecessaryLeadingZero_reverts() public {
        vm.expectRevert(Asn1Decode.InvalidAsn1Value.selector);
        h.uintAtRoot(hex"0202007f");
    }

    function test_uintAt_empty_reverts() public {
        vm.expectRevert(Asn1Decode.InvalidAsn1Length.selector);
        h.uintAtRoot(hex"0200");
    }

    function test_uintAt_notInteger_reverts() public {
        vm.expectRevert(Asn1Decode.InvalidAsn1Type.selector);
        h.uintAtRoot(hex"0401ff"); // OCTET STRING, not INTEGER
    }

    function test_uintAt_negative_reverts() public {
        vm.expectRevert(Asn1Decode.InvalidAsn1Value.selector);
        h.uintAtRoot(hex"020180"); // high bit set
    }

    // declared length runs past the buffer -> readBytesN bound trips
    function test_uintAt_lengthPastBuffer_reverts() public {
        vm.expectRevert(); // require(idx + len <= self.length) has no message
        h.uintAtRoot(hex"02050000"); // claims 5 content bytes, only 2 present
    }

    function test_uint384At_requiredLeadingZero() public view {
        (uint128 hi, uint256 lo) = h.uint384AtRoot(hex"02020080");
        assertEq(hi, 0);
        assertEq(lo, 0x80);
    }

    function test_uint384At_unnecessaryLeadingZero_reverts() public {
        vm.expectRevert(Asn1Decode.InvalidAsn1Value.selector);
        h.uint384AtRoot(hex"0202007f");
    }

    function test_uint384At_empty_reverts() public {
        vm.expectRevert(Asn1Decode.InvalidAsn1Length.selector);
        h.uint384AtRoot(hex"0200");
    }

    // --- timestampAt ---

    function test_timestamp_utcEpoch() public view {
        // UTCTime "700101000000Z" -> 1970-01-01T00:00:00Z
        assertEq(h.timestampAtRoot(_utcTime("700101000000Z")), 0);
    }

    function test_timestamp_generalizedKnownValue() public view {
        // GeneralizedTime "20240101000000Z" -> 2024-01-01T00:00:00Z
        assertEq(h.timestampAtRoot(_generalizedTime("20240101000000Z")), 1704067200);
    }

    function test_timestamp_wrongType_reverts() public {
        bytes memory der = abi.encodePacked(hex"160d", bytes("700101000000Z")); // type 0x16
        vm.expectRevert(Asn1Decode.InvalidAsn1Value.selector);
        h.timestampAtRoot(der);
    }

    function test_timestamp_wrongLength_reverts() public {
        bytes memory der = abi.encodePacked(hex"170c", bytes("70010100000Z")); // UTCTime, length 12
        vm.expectRevert(Asn1Decode.InvalidAsn1Value.selector);
        h.timestampAtRoot(der);
    }

    function test_timestamp_missingZ_reverts() public {
        vm.expectRevert(Asn1Decode.InvalidAsn1Value.selector);
        h.timestampAtRoot(_utcTime("700101000000X"));
    }

    function test_timestamp_nonDigit_reverts() public {
        vm.expectRevert(Asn1Decode.InvalidAsn1Value.selector);
        h.timestampAtRoot(_utcTime("7A0101000000Z"));
    }

    // --- bitstring ---

    function test_bitstring_content() public view {
        // BIT STRING, 0x00 pad byte then 0x41 -> content pointer advances past the pad byte
        assertEq(h.bitstringContent(hex"03020041"), 3);
    }

    function test_bitstring_notBitString_reverts() public {
        vm.expectRevert(Asn1Decode.InvalidAsn1Type.selector);
        h.bitstringContent(hex"0401ff");
    }

    function test_bitstring_nonZeroPadded_reverts() public {
        vm.expectRevert(Asn1Decode.InvalidAsn1Value.selector);
        h.bitstringContent(hex"03020100"); // pad byte is 0x01, not 0x00
    }

    function test_bitstringUintAt_oneByteKeyUsage() public view {
        // X.509 KeyUsage bit 0 (digitalSignature): one content byte, 7 unused low bits.
        assertEq(h.bitstringUintAtRoot(hex"03020780"), 0x80);
    }

    function test_bitstringUintAt_twoByteKeyUsageNormalizesFirstOctet() public view {
        // X.509 KeyUsage bits 5 and 8 (keyCertSign | decipherOnly). The first content octet must
        // remain in the low byte so CertManager's 0x04 keyCertSign mask still targets bit 5.
        uint256 keyCertSignAndDecipherOnly = h.bitstringUintAtRoot(hex"0303070480");
        assertEq(keyCertSignAndDecipherOnly & 0x04, 0x04, "keyCertSign must stay in low byte");
        assertEq(keyCertSignAndDecipherOnly & 0x80, 0, "decipherOnly must not alias digitalSignature");
        assertEq(keyCertSignAndDecipherOnly, 0x8004);
    }

    function test_bitstringUintAt_twoByteDecipherOnlyDoesNotAliasDigitalSignature() public view {
        uint256 decipherOnly = h.bitstringUintAtRoot(hex"0303070080");
        assertEq(decipherOnly & 0x80, 0, "decipherOnly must not satisfy digitalSignature");
        assertEq(decipherOnly, 0x8000);
    }

    function test_bitstringUintAt_nonZeroUnusedBits_reverts() public {
        vm.expectRevert(Asn1Decode.InvalidAsn1Value.selector);
        h.bitstringUintAtRoot(hex"03030700ff");
    }

    function test_bitstringUintAt_invalidUnusedBits_reverts() public {
        vm.expectRevert(Asn1Decode.InvalidAsn1Value.selector);
        h.bitstringUintAtRoot(hex"03020880");
    }

    function test_bitstringUintAt_missingUnusedBits_reverts() public {
        vm.expectRevert(Asn1Decode.InvalidAsn1Length.selector);
        h.bitstringUintAtRoot(hex"0300");
    }

    // --- firstChildOf ---

    function test_firstChildOf_notConstructed_reverts() public {
        vm.expectRevert(Asn1Decode.InvalidAsn1Type.selector);
        h.firstChildHeader(hex"0401ff"); // OCTET STRING is primitive, not constructed
    }

    // --- fuzz ---

    function testFuzz_readNodeLength_shortForm(uint8 lenSeed) public view {
        uint256 len = bound(lenSeed, 0, 127); // short-form length is a single < 0x80 byte
        bytes memory der = abi.encodePacked(bytes1(0x04), bytes1(uint8(len)), new bytes(len));
        assertEq(h.rootLength(der), len);
        assertEq(h.rootContent(der), 2);
    }

    function testFuzz_uintAt_positive(uint64 v) public view {
        bytes memory der = _derEncodeUint64(v);
        assertEq(h.uintAtRoot(der), v);
    }

    function _derEncodeUint64(uint64 v) internal pure returns (bytes memory) {
        if (v == 0) {
            return hex"020100";
        }

        bytes8 raw = bytes8(v);
        uint256 offset;
        while (offset < 8 && raw[offset] == 0) {
            offset++;
        }

        uint256 len = 8 - offset;
        bool needsPad = uint8(raw[offset]) >= 0x80;
        bytes memory der = new bytes(2 + len + (needsPad ? 1 : 0));
        der[0] = 0x02;
        der[1] = bytes1(uint8(der.length - 2));
        uint256 dst = 2;
        if (needsPad) {
            der[dst++] = 0x00;
        }
        for (uint256 i = offset; i < 8; ++i) {
            der[dst++] = raw[i];
        }
        return der;
    }

    function _utcTime(string memory s) internal pure returns (bytes memory) {
        bytes memory b = bytes(s);
        require(b.length == 13, "test: UTCTime must be 13 chars");
        return abi.encodePacked(bytes1(0x17), bytes1(uint8(13)), b);
    }

    function _generalizedTime(string memory s) internal pure returns (bytes memory) {
        bytes memory b = bytes(s);
        require(b.length == 15, "test: GeneralizedTime must be 15 chars");
        return abi.encodePacked(bytes1(0x18), bytes1(uint8(15)), b);
    }
}
