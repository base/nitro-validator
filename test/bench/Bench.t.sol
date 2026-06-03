// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test, console} from "forge-std/Test.sol";
import {ECDSA384} from "@solarity/libs/crypto/ECDSA384.sol";
import {ECDSA384Bench} from "./ECDSA384Bench.sol";
import {ECDSA384Curve} from "../../src/ECDSA384Curve.sol";

contract RealHarness {
    function verify(bytes memory h, bytes memory s, bytes memory p) external view returns (bool) {
        return ECDSA384.verify(ECDSA384Curve.p384(), h, s, p);
    }
}

contract BenchHarness {
    // returns (#inversions, #other modexp calls)
    function countVerify(bytes memory h, bytes memory s, bytes memory p)
        external
        returns (uint256 inv, uint256 other, bool ok)
    {
        assembly {
            tstore(0, 0)
            tstore(1, 0)
        }
        ECDSA384Bench.Parameters memory params = ECDSA384Bench.Parameters({
            a: ECDSA384Curve.CURVE_A,
            b: ECDSA384Curve.CURVE_B,
            gx: ECDSA384Curve.CURVE_GX,
            gy: ECDSA384Curve.CURVE_GY,
            p: ECDSA384Curve.CURVE_P,
            n: ECDSA384Curve.CURVE_N,
            lowSmax: ECDSA384Curve.CURVE_LOW_S_MAX
        });
        ok = ECDSA384Bench.verify(params, h, s, p);
        assembly {
            inv := tload(0)
            other := tload(1)
        }
    }

    function profileVerify(bytes memory h, bytes memory s, bytes memory p)
        external
        returns (uint256[5] memory invByPhase, uint256[5] memory otherByPhase, bool ok)
    {
        assembly {
            tstore(0, 0)
            tstore(1, 0)
        }
        ECDSA384Bench.Parameters memory params = ECDSA384Bench.Parameters({
            a: ECDSA384Curve.CURVE_A,
            b: ECDSA384Curve.CURVE_B,
            gx: ECDSA384Curve.CURVE_GX,
            gy: ECDSA384Curve.CURVE_GY,
            p: ECDSA384Curve.CURVE_P,
            n: ECDSA384Curve.CURVE_N,
            lowSmax: ECDSA384Curve.CURVE_LOW_S_MAX
        });
        ok = ECDSA384Bench.verify(params, h, s, p);

        uint256 prevInv;
        uint256 prevOther;
        for (uint256 i = 0; i < 5; ++i) {
            uint256 inv;
            uint256 other;
            assembly {
                inv := tload(add(10, i))
                other := tload(add(20, i))
            }
            invByPhase[i] = inv - prevInv;
            otherByPhase[i] = other - prevOther;
            prevInv = inv;
            prevOther = other;
        }
    }

    function collectInverseHints(bytes memory h, bytes memory s, bytes memory p) external returns (bytes memory hints) {
        assembly {
            tstore(0, 0)
            tstore(1, 0)
            tstore(2, 0)
            tstore(7, 0)
            tstore(8, 1)
        }
        ECDSA384Bench.Parameters memory params = _params();
        bool ok = ECDSA384Bench.verify(params, h, s, p);
        require(ok, "collect verify failed");

        uint256 count;
        assembly {
            count := tload(2)
            tstore(8, 0)
        }
        hints = new bytes(count * 48);
        for (uint256 i = 0; i < count; ++i) {
            uint256 hi;
            uint256 lo;
            assembly {
                let slot_ := add(1000, mul(i, 2))
                hi := tload(slot_)
                lo := tload(add(slot_, 1))
                let dst_ := add(add(hints, 0x20), mul(i, 48))
                mstore(dst_, shl(128, hi))
                mstore(add(dst_, 0x10), lo)
            }
        }
    }

    function countHintedVerify(bytes memory h, bytes memory s, bytes memory p, bytes memory hints)
        external
        returns (uint256 inv, uint256 other, uint256 consumed, bool ok)
    {
        assembly {
            tstore(0, 0)
            tstore(1, 0)
        }
        (ok, consumed) = ECDSA384Bench.verifyWithHintsConsumed(_params(), h, s, p, hints);
        require(consumed == hints.length, "unused inverse hints");
        assembly {
            inv := tload(0)
            other := tload(1)
        }
    }

    function _params() internal pure returns (ECDSA384Bench.Parameters memory) {
        return ECDSA384Bench.Parameters({
            a: ECDSA384Curve.CURVE_A,
            b: ECDSA384Curve.CURVE_B,
            gx: ECDSA384Curve.CURVE_GX,
            gy: ECDSA384Curve.CURVE_GY,
            p: ECDSA384Curve.CURVE_P,
            n: ECDSA384Curve.CURVE_N,
            lowSmax: ECDSA384Curve.CURVE_LOW_S_MAX
        });
    }
}

/// @notice Baseline benchmark: real per-verify gas + exact MODEXP census + EIP-7883 projection.
contract BenchTest is Test {
    RealHarness real;
    BenchHarness bench;

    // Synthetic-but-valid P384 signature (openssl secp384r1, SHA-384). Counts are
    // input-independent up to ~Hamming-weight variance, so this is representative.
    bytes h = hex"e6bb58cb85db069a2c0c310020f946d9c47e8ff6a43895ae824369325c74fb8d30897d7ea16447ef9975eb351a916a11";
    bytes s =
        hex"1ab266914fb82615eba02dc55eb8d6e32e4adaa12a927786ab2353d9649f645e86b0166c990e36dbce9efcc743b998646025d5af666c17fb103d0c89f8a78aea9f8fff3703e21a3ab69f48b21d0bbf008f7c9702d54fd6f1af65223fe3936b3c";
    bytes p =
        hex"edb97631be68370a653e5601fa2f12da63db7cdb1f6cf7413004f4de274f3d1c046de28a2530240080e7d84c436cb935ebb5c7a9fcd8027f5d97bf49fff3f9a7346270e10e0a529eeb117d75409f3c9acfde069a7a577a6a6b8048d78abfe5f5";

    // Per-call MODEXP gas, derived from EIP-2565 / EIP-7883 for this library's
    // operand profiles (verified against the EIP formulas):
    //   inversion : base=64, exp=64, mod=64, expHead bit-length 128
    //   other     : squaring/mulmul/reduce -> hits the min-gas floor
    uint256 constant INV_2565 = 8170; // floor(8^2 * (8*32+127) / 3)
    uint256 constant INV_7883 = 81792; // 2*8^2 * (16*32+127)
    uint256 constant OTHER_2565 = 200; // EIP-2565 minimum
    uint256 constant OTHER_7883 = 500; // EIP-7883 minimum
    uint256 constant TX_CAP = 16_777_216; // EIP-7825 per-transaction gas cap (2^24)

    function setUp() public {
        real = new RealHarness();
        bench = new BenchHarness();
    }

    function test_Baseline() public {
        // 1) ground-truth current gas for a single verify (uninstrumented)
        uint256 g0 = gasleft();
        bool ok = real.verify(h, s, p);
        uint256 verifyGas2565 = g0 - gasleft();
        assertTrue(ok, "verify must pass");

        // 2) exact MODEXP census (instrumented copy)
        (uint256 inv, uint256 other,) = bench.countVerify(h, s, p);
        (uint256[5] memory invByPhase, uint256[5] memory otherByPhase,) = bench.profileVerify(h, s, p);

        // 3) MODEXP gas under each pricing
        uint256 mod2565 = inv * INV_2565 + other * OTHER_2565;
        uint256 mod7883 = inv * INV_7883 + other * OTHER_7883;

        // 4) project post-Fusaka verify: only the MODEXP portion reprices,
        //    the rest of the verify (EVM arithmetic / memory) is unchanged.
        uint256 verifyGas7883 = verifyGas2565 + (mod7883 - mod2565);

        console.log("==== SINGLE P384 ECDSA VERIFY ====");
        console.log("measured verify gas (EIP-2565)   :", verifyGas2565);
        console.log("MODEXP calls total               :", inv + other);
        console.log("  field inversions               :", inv);
        console.log("  other (sq/mul/reduce)          :", other);
        console.log("MODEXP gas EIP-2565              :", mod2565);
        console.log("MODEXP gas EIP-7883              :", mod7883);
        console.log("  modexp share of verify (2565,%):", (mod2565 * 100) / verifyGas2565);
        console.log("PROJECTED verify gas (EIP-7883)  :", verifyGas7883);
        console.log("  blow-up factor x100            :", (verifyGas7883 * 100) / verifyGas2565);
        console.log("per-tx cap (EIP-7825)            :", TX_CAP);
        console.log("verify fits in 1 tx post-Fusaka? :", verifyGas7883 <= TX_CAP ? 1 : 0);
        console.log("min verifies that must be split  :", (verifyGas7883 + TX_CAP - 1) / TX_CAP);
        console.log("==== MODEXP PHASE BREAKDOWN ====");
        _logPhase("on-curve check", invByPhase[0], otherByPhase[0]);
        _logPhase("scalar divs", invByPhase[1], otherByPhase[1]);
        _logPhase("precompute table", invByPhase[2], otherByPhase[2]);
        _logPhase("double scalar mult", invByPhase[3], otherByPhase[3]);
        _logPhase("final mod", invByPhase[4], otherByPhase[4]);
    }

    /// EXPERIMENT 001 (analytical): replace each on-chain field inversion with a
    /// caller-supplied witness verified by ONE modmul (b * b_inv == 1 mod p).
    /// Each moddiv goes from {1 inversion + 1 mulmul} to {2 mulmuls}: the 570
    /// inversions become 570 cheap mulmuls (floor-priced), nothing else changes.
    function test_HintedInversionModel() public {
        uint256 g0 = gasleft();
        bool ok = real.verify(h, s, p);
        uint256 verifyGas2565 = g0 - gasleft();
        assertTrue(ok);
        (uint256 inv, uint256 other,) = bench.countVerify(h, s, p);

        uint256 nonModexp = verifyGas2565 - (inv * INV_2565 + other * OTHER_2565);
        // hinted profile: 0 inversions, (other + inv) floor-priced calls
        uint256 calls = other + inv;
        uint256 hinted2565 = nonModexp + calls * OTHER_2565;
        uint256 hinted7883 = nonModexp + calls * OTHER_7883;
        uint256 witnessBytes = inv * 48;
        uint256 witnessCalldataGas = witnessBytes * 16; // worst case: all nonzero bytes

        console.log("==== EXPERIMENT 001: HINTED INVERSIONS (model) ====");
        console.log("non-MODEXP verify gas (fixed)    :", nonModexp);
        console.log("hinted verify gas EIP-2565       :", hinted2565);
        console.log("hinted verify gas EIP-7883       :", hinted7883);
        console.log("  + witness calldata (worst) gas :", witnessCalldataGas);
        console.log("  = total post-Fusaka            :", hinted7883 + witnessCalldataGas);
        console.log("fits 1 tx post-Fusaka?           :", (hinted7883 + witnessCalldataGas) <= TX_CAP ? 1 : 0);
        console.log("witness bytes per verify         :", witnessBytes);
    }

    function test_HintedInversionPrototype() public {
        bytes memory hints = bench.collectInverseHints(h, s, p);

        uint256 g0 = gasleft();
        (uint256 inv, uint256 other, uint256 consumed, bool ok) = bench.countHintedVerify(h, s, p, hints);
        uint256 hintedGas2565 = g0 - gasleft();
        assertTrue(ok, "hinted verify must pass");
        assertEq(consumed, hints.length, "must consume all hints");

        uint256 mod2565 = inv * INV_2565 + other * OTHER_2565;
        uint256 mod7883 = inv * INV_7883 + other * OTHER_7883;
        uint256 hintedGas7883 = hintedGas2565 + (mod7883 - mod2565);
        uint256 witnessCalldataGas = hints.length * 16; // worst case: all nonzero bytes

        console.log("==== EXPERIMENT 002: HINTED INVERSIONS (prototype) ====");
        console.log("hinted verify gas EIP-2565       :", hintedGas2565);
        console.log("MODEXP calls total               :", inv + other);
        console.log("  field inversions               :", inv);
        console.log("  other (sq/mul/reduce/check)    :", other);
        console.log("projected verify gas EIP-7883    :", hintedGas7883);
        console.log("  + witness calldata (worst) gas :", witnessCalldataGas);
        console.log("  = total post-Fusaka            :", hintedGas7883 + witnessCalldataGas);
        console.log("fits 1 tx post-Fusaka?           :", (hintedGas7883 + witnessCalldataGas) <= TX_CAP ? 1 : 0);
        console.log("witness bytes per verify         :", hints.length);
    }

    function test_HintedInversionRejectsMutatedHint() public {
        bytes memory hints = bench.collectInverseHints(h, s, p);
        hints[100] = bytes1(uint8(hints[100]) ^ 1);

        vm.expectRevert("bad inverse hint");
        bench.countHintedVerify(h, s, p, hints);
    }

    function test_HintedInversionRejectsTruncatedHints() public {
        bytes memory hints = bench.collectInverseHints(h, s, p);
        assembly {
            mstore(hints, sub(mload(hints), 1))
        }

        vm.expectRevert("inverse hint underflow");
        bench.countHintedVerify(h, s, p, hints);
    }

    function test_HintedInversionRejectsSurplusHints() public {
        bytes memory hints = abi.encodePacked(bench.collectInverseHints(h, s, p), bytes1(0x00));

        vm.expectRevert("unused inverse hints");
        bench.countHintedVerify(h, s, p, hints);
    }

    function _logPhase(string memory name, uint256 inv, uint256 other) internal pure {
        console.log(name);
        console.log("  inversions:", inv);
        console.log("  other     :", other);
        console.log("  EIP-7883 MODEXP gas:", inv * INV_7883 + other * OTHER_7883);
    }
}
