// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;

import {Test} from "forge-std/Test.sol";
import {CborDecode, CborElement, LibCborElement} from "../src/CborDecode.sol";

contract CborHarness {
    using CborDecode for bytes;
    using LibCborElement for CborElement;

    function byteStringLength(bytes memory c) external pure returns (uint256) {
        return c.byteStringAt(0).length();
    }

    function byteStringStart(bytes memory c) external pure returns (uint256) {
        return c.byteStringAt(0).start();
    }

    function byteStringSlice(bytes memory c) external pure returns (bytes memory) {
        return c.slice(c.byteStringAt(0));
    }

    function mapValue(bytes memory c) external pure returns (uint64) {
        return c.mapAt(0).value();
    }

    function isNullAt0(bytes memory c) external pure returns (bool) {
        return c.elementAt(0, 0x40, false).isNull();
    }
}

contract CborDecodeTest is Test {
    CborHarness h;

    function setUp() public {
        h = new CborHarness();
    }

    function test_byteString_shortForm() public view {
        assertEq(h.byteStringLength(hex"43aabbcc"), 3);
        assertEq(h.byteStringStart(hex"43aabbcc"), 1);
        assertEq(h.byteStringSlice(hex"43aabbcc"), hex"aabbcc");
    }

    function test_byteString_ai24Length() public view {
        bytes memory c = abi.encodePacked(hex"5818", new bytes(24)); // 0x40|24, length byte 0x18 = 24
        assertEq(h.byteStringLength(c), 24);
        assertEq(h.byteStringStart(c), 2);
    }

    function test_unexpectedType_reverts() public {
        vm.expectRevert("unexpected type");
        h.byteStringLength(hex"a0"); // map header where a byte string is expected
    }

    function test_unsupportedAdditionalInfo_reverts() public {
        vm.expectRevert("unsupported type");
        h.mapValue(hex"bc"); // 0xa0|28, additional info 28 is reserved
    }

    function test_indefiniteLengthForByteString_reverts() public {
        vm.expectRevert("indefinite-length only for maps/arrays");
        h.byteStringLength(hex"5f"); // 0x40|31, indefinite length not allowed for byte strings
    }

    function test_nullForRequired_reverts() public {
        vm.expectRevert("null value for required element");
        h.byteStringLength(hex"f6"); // null where a value is required
    }

    function test_nullWhenAllowed() public view {
        assertTrue(h.isNullAt0(hex"f6")); // null permitted -> recognized as null
    }

    function test_truncatedLengthByte_reverts() public {
        vm.expectRevert(); // cbor[ix+1] out-of-bounds
        h.byteStringLength(hex"58"); // ai=24 promises a length byte that is missing
    }

    // The element header parses, but a declared length beyond the buffer trips on slice.
    function test_declaredLengthExceedsBuffer_reverts() public {
        vm.expectRevert("index out of bounds");
        h.byteStringSlice(hex"4a"); // 0x40|10: claims 10 content bytes, none present
    }

    function testFuzz_byteString_shortForm(bytes memory payload) public view {
        uint256 len = bound(payload.length, 0, 23); // single-byte short-form length
        bytes memory content = new bytes(len);
        for (uint256 i = 0; i < len; i++) {
            content[i] = payload[i];
        }
        bytes memory c = abi.encodePacked(bytes1(uint8(0x40 | len)), content);
        assertEq(h.byteStringLength(c), len);
        assertEq(h.byteStringStart(c), 1);
        assertEq(h.byteStringSlice(c), content);
    }

    function testFuzz_map_ai24Count(uint8 count) public view {
        bytes memory c = abi.encodePacked(hex"b8", bytes1(count)); // 0xa0|24, count entries
        assertEq(h.mapValue(c), count);
    }
}
