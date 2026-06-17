// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Asn1Decode, Asn1Ptr, LibAsn1Ptr} from "../../src/Asn1Decode.sol";
import {ECDSA384Curve} from "../../src/ECDSA384Curve.sol";
import {Sha2Ext} from "../../src/Sha2Ext.sol";
import {ECDSA384HintCollectorLib} from "./ECDSA384HintCollector.sol";

contract P384HintCollector {
    using Asn1Decode for bytes;
    using LibAsn1Ptr for Asn1Ptr;

    function collectVerifyHints(bytes memory hash, bytes memory signature, bytes memory pubKey)
        public
        returns (bytes memory hints)
    {
        (hints,) = collectVerifyProfile(hash, signature, pubKey);
    }

    function collectVerifyProfile(bytes memory hash, bytes memory signature, bytes memory pubKey)
        public
        returns (bytes memory hints, uint256 hintedOtherCalls)
    {
        assembly {
            tstore(0, 0)
            tstore(1, 0)
            tstore(2, 0)
            tstore(7, 0)
            tstore(8, 1)
        }

        bool ok = ECDSA384HintCollectorLib.verify(_hintParams(), hash, signature, pubKey);
        require(ok, "collect verify failed");

        uint256 count;
        uint256 inv;
        uint256 other;
        assembly {
            count := tload(2)
            inv := tload(0)
            other := tload(1)
            tstore(8, 0)
        }
        require(count == inv, "inverse collection mismatch");
        hintedOtherCalls = inv + other;

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

    /// @dev Like {collectVerifyHints} but does NOT require the signature to verify. The inverse
    ///      hints are gathered during the verification trace (before the final curve equation is
    ///      checked), so this returns a complete, self-consistent hint stream even for a signature
    ///      that ultimately fails — letting a test prove the final ECDSA check (not just the hint
    ///      gate) is what rejects a well-hinted invalid signature. Returns the hints and `ok`
    ///      (whether the signature actually verified).
    function collectVerifyHintsAllowInvalid(bytes memory hash, bytes memory signature, bytes memory pubKey)
        public
        returns (bytes memory hints, bool ok)
    {
        assembly {
            tstore(0, 0)
            tstore(1, 0)
            tstore(2, 0)
            tstore(7, 0)
            tstore(8, 1)
        }

        ok = ECDSA384HintCollectorLib.verify(_hintParams(), hash, signature, pubKey);

        uint256 count;
        uint256 inv;
        assembly {
            count := tload(2)
            inv := tload(0)
            tstore(8, 0)
        }
        require(count == inv, "inverse collection mismatch");

        hints = new bytes(count * 48);
        for (uint256 i = 0; i < count; ++i) {
            assembly {
                let slot_ := add(1000, mul(i, 2))
                let hi := tload(slot_)
                let lo := tload(add(slot_, 1))
                let dst_ := add(add(hints, 0x20), mul(i, 48))
                mstore(dst_, shl(128, hi))
                mstore(add(dst_, 0x10), lo)
            }
        }
    }

    function collectCertSignatureHints(bytes memory certificate, bytes memory parentPubKey)
        external
        returns (bytes memory)
    {
        (bytes memory hints,) = collectCertSignatureProfile(certificate, parentPubKey);
        return hints;
    }

    function collectCertSignatureProfile(bytes memory certificate, bytes memory parentPubKey)
        public
        returns (bytes memory, uint256)
    {
        Asn1Ptr root = certificate.root();
        Asn1Ptr tbsCertPtr = certificate.firstChildOf(root);
        bytes memory hash = Sha2Ext.sha384(certificate, tbsCertPtr.header(), tbsCertPtr.totalLength());

        Asn1Ptr sigAlgoPtr = certificate.nextSiblingOf(tbsCertPtr);
        bytes memory sigPacked = _certSignature(certificate, sigAlgoPtr);

        return collectVerifyProfile(hash, sigPacked, parentPubKey);
    }

    function _certSignature(bytes memory certificate, Asn1Ptr sigAlgoPtr)
        internal
        pure
        returns (bytes memory sigPacked)
    {
        Asn1Ptr sigPtr = certificate.nextSiblingOf(sigAlgoPtr);
        Asn1Ptr sigBPtr = certificate.bitstring(sigPtr);
        Asn1Ptr sigRoot = certificate.rootOf(sigBPtr);
        Asn1Ptr sigRPtr = certificate.firstChildOf(sigRoot);
        Asn1Ptr sigSPtr = certificate.nextSiblingOf(sigRPtr);
        (uint128 rhi, uint256 rlo) = certificate.uint384At(sigRPtr);
        (uint128 shi, uint256 slo) = certificate.uint384At(sigSPtr);
        sigPacked = abi.encodePacked(rhi, rlo, shi, slo);
    }

    function _hintParams() internal pure returns (ECDSA384HintCollectorLib.Parameters memory) {
        return ECDSA384HintCollectorLib.Parameters({
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
