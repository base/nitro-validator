// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;

import {Test} from "forge-std/Test.sol";
import {stdError} from "forge-std/StdError.sol";
import {LibBytes} from "../src/LibBytes.sol";

contract LibBytesHarness {
    using LibBytes for bytes;

    function slice(bytes memory b, uint256 offset, uint256 length) external pure returns (bytes memory) {
        return b.slice(offset, length);
    }

    function keccakRange(bytes memory b, uint256 offset, uint256 length) external pure returns (bytes32) {
        return b.keccak(offset, length);
    }

    function readUint16(bytes memory b, uint256 i) external pure returns (uint16) {
        return b.readUint16(i);
    }

    function readUint32(bytes memory b, uint256 i) external pure returns (uint32) {
        return b.readUint32(i);
    }

    function readUint64(bytes memory b, uint256 i) external pure returns (uint64) {
        return b.readUint64(i);
    }
}

contract LibBytesTest is Test {
    LibBytesHarness h;

    function setUp() public {
        h = new LibBytesHarness();
    }

    function test_slice_basic() public view {
        bytes memory b = hex"00112233445566";
        assertEq(h.slice(b, 2, 3), hex"223344");
        assertEq(h.slice(b, 0, 7), b);
        assertEq(h.slice(b, 7, 0), hex""); // offset == length, zero-length slice at the very end
    }

    function test_slice_outOfBounds_reverts() public {
        bytes memory b = hex"0011";
        vm.expectRevert("index out of bounds");
        h.slice(b, 1, 2);
    }

    function test_slice_offsetPastEnd_reverts() public {
        bytes memory b = hex"0011";
        vm.expectRevert("index out of bounds");
        h.slice(b, 3, 0);
    }

    // offset + length overflowing uint256 must revert (checked arithmetic), not wrap and bypass the bound.
    function test_slice_lengthOverflow_reverts() public {
        bytes memory b = hex"0011";
        vm.expectRevert(stdError.arithmeticError);
        h.slice(b, type(uint256).max, 1);
    }

    function test_keccak_matchesReference() public view {
        bytes memory b = hex"00112233445566";
        assertEq(h.keccakRange(b, 2, 3), keccak256(hex"223344"));
    }

    function test_keccak_outOfBounds_reverts() public {
        bytes memory b = hex"0011";
        vm.expectRevert("index out of bounds");
        h.keccakRange(b, 1, 2);
    }

    function test_readUint_values() public view {
        bytes memory b = hex"0102030405060708090a";
        assertEq(h.readUint16(b, 0), 0x0102);
        assertEq(h.readUint32(b, 1), 0x02030405);
        assertEq(h.readUint64(b, 2), 0x030405060708090a);
    }

    function test_readUint16_outOfBounds_reverts() public {
        bytes memory b = hex"00";
        vm.expectRevert("index out of bounds");
        h.readUint16(b, 0);
    }

    function test_readUint32_outOfBounds_reverts() public {
        bytes memory b = hex"000102";
        vm.expectRevert("index out of bounds");
        h.readUint32(b, 0);
    }

    function test_readUint64_outOfBounds_reverts() public {
        bytes memory b = hex"00010203040506";
        vm.expectRevert("index out of bounds");
        h.readUint64(b, 0);
    }

    function testFuzz_slice_roundTrip(bytes memory data, uint256 offset, uint256 length) public view {
        offset = bound(offset, 0, data.length);
        length = bound(length, 0, data.length - offset);
        bytes memory got = h.slice(data, offset, length);
        assertEq(got.length, length);
        for (uint256 i = 0; i < length; i++) {
            assertEq(got[i], data[offset + i]);
        }
    }

    function testFuzz_readUint16(uint16 v) public view {
        assertEq(h.readUint16(abi.encodePacked(v), 0), v);
    }

    function testFuzz_readUint32(uint32 v) public view {
        assertEq(h.readUint32(abi.encodePacked(v), 0), v);
    }

    function testFuzz_readUint64(uint64 v) public view {
        assertEq(h.readUint64(abi.encodePacked(v), 0), v);
    }
}
