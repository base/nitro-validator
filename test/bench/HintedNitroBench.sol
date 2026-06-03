// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Asn1Decode, Asn1Ptr, LibAsn1Ptr} from "../../src/Asn1Decode.sol";
import {CborDecode, CborElement, LibCborElement} from "../../src/CborDecode.sol";
import {CertManager} from "../../src/CertManager.sol";
import {ECDSA384Curve} from "../../src/ECDSA384Curve.sol";
import {ICertManager} from "../../src/ICertManager.sol";
import {LibBytes} from "../../src/LibBytes.sol";
import {NitroValidator} from "../../src/NitroValidator.sol";
import {Sha2Ext} from "../../src/Sha2Ext.sol";
import {ECDSA384Bench} from "./ECDSA384Bench.sol";

contract HintedCertManagerBench is CertManager {
    using Asn1Decode for bytes;
    using LibAsn1Ptr for Asn1Ptr;
    using LibBytes for bytes;

    function verifyCACertWithHints(bytes memory cert, bytes32 parentCertHash, bytes memory signatureHints)
        external
        returns (bytes32)
    {
        bytes32 certHash = keccak256(cert);
        _verifyCertWithHints(cert, certHash, true, _loadVerified(parentCertHash), signatureHints);
        return certHash;
    }

    function verifyClientCertWithHints(bytes memory cert, bytes32 parentCertHash, bytes memory signatureHints)
        external
        returns (VerifiedCert memory)
    {
        return _verifyCertWithHints(cert, keccak256(cert), false, _loadVerified(parentCertHash), signatureHints);
    }

    function loadVerifiedForBench(bytes32 certHash) external view returns (VerifiedCert memory) {
        return _loadVerified(certHash);
    }

    function _verifyCertWithHints(
        bytes memory certificate,
        bytes32 certHash,
        bool ca,
        VerifiedCert memory parent,
        bytes memory signatureHints
    ) internal returns (VerifiedCert memory cert) {
        if (certHash != ROOT_CA_CERT_HASH) {
            require(parent.pubKey.length > 0, "parent cert unverified");
            require(parent.notAfter >= block.timestamp, "parent cert expired");
            require(parent.ca, "parent cert is not a CA");
            require(!ca || parent.maxPathLen != 0, "maxPathLen exceeded");
        }

        cert = _loadVerified(certHash);
        if (cert.pubKey.length != 0) {
            require(cert.notAfter >= block.timestamp, "cert expired");
            require(cert.ca == ca, "cert is not a CA");
            return cert;
        }

        Asn1Ptr root = certificate.root();
        Asn1Ptr tbsCertPtr = certificate.firstChildOf(root);
        (uint64 notAfter, int64 maxPathLen, bytes32 issuerHash, bytes32 subjectHash, bytes memory pubKey) =
            _parseTbs(certificate, tbsCertPtr, ca);

        require(parent.subjectHash == issuerHash, "issuer / subject mismatch");

        if (parent.maxPathLen > 0 && (maxPathLen < 0 || maxPathLen >= parent.maxPathLen)) {
            maxPathLen = parent.maxPathLen - 1;
        }

        _verifyCertSignatureWithHints(certificate, tbsCertPtr, parent.pubKey, signatureHints);

        cert = VerifiedCert({
            ca: ca, notAfter: notAfter, maxPathLen: maxPathLen, subjectHash: subjectHash, pubKey: pubKey
        });
        _saveVerified(certHash, cert);

        emit CertVerified(certHash);
    }

    function _verifyCertSignatureWithHints(
        bytes memory certificate,
        Asn1Ptr ptr,
        bytes memory pubKey,
        bytes memory signatureHints
    ) internal {
        Asn1Ptr sigAlgoPtr = certificate.nextSiblingOf(ptr);
        require(certificate.keccak(sigAlgoPtr.content(), sigAlgoPtr.length()) == CERT_ALGO_OID, "invalid cert sig algo");

        bytes memory hash = Sha2Ext.sha384(certificate, ptr.header(), ptr.totalLength());
        bytes memory sigPacked = _certSignature(certificate, sigAlgoPtr);

        require(ECDSA384Bench.verifyWithHints(_benchParams(), hash, sigPacked, pubKey, signatureHints), "invalid sig");
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

    function _benchParams() internal pure returns (ECDSA384Bench.Parameters memory) {
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

contract P384HintCollectorBench {
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

        bool ok = ECDSA384Bench.verify(_benchParams(), hash, signature, pubKey);
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

    function _benchParams() internal pure returns (ECDSA384Bench.Parameters memory) {
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

contract HintedNitroValidatorBench is NitroValidator {
    using CborDecode for bytes;
    using LibBytes for bytes;
    using LibCborElement for CborElement;

    constructor(ICertManager certManager_) NitroValidator(certManager_) {}

    function validateAttestationWithHints(
        bytes memory attestationTbs,
        bytes memory signature,
        bytes memory attestationSigHints
    ) public returns (Ptrs memory) {
        Ptrs memory ptrs = _parseAttestation(attestationTbs);

        require(ptrs.moduleID.length() > 0, "no module id");
        require(ptrs.timestamp > 0, "no timestamp");
        require(ptrs.cabundle.length > 0, "no cabundle");
        require(attestationTbs.keccak(ptrs.digest) == ATTESTATION_DIGEST, "invalid digest");
        require(1 <= ptrs.pcrs.length && ptrs.pcrs.length <= 32, "invalid pcrs");
        require(
            ptrs.publicKey.isNull() || (1 <= ptrs.publicKey.length() && ptrs.publicKey.length() <= 1024),
            "invalid pub key"
        );
        require(ptrs.userData.isNull() || (ptrs.userData.length() <= 512), "invalid user data");
        require(ptrs.nonce.isNull() || (ptrs.nonce.length() <= 512), "invalid nonce");

        for (uint256 i = 0; i < ptrs.pcrs.length; i++) {
            require(
                ptrs.pcrs[i].length() == 32 || ptrs.pcrs[i].length() == 48 || ptrs.pcrs[i].length() == 64, "invalid pcr"
            );
        }

        bytes memory cert = attestationTbs.slice(ptrs.cert);
        bytes[] memory cabundle = new bytes[](ptrs.cabundle.length);
        for (uint256 i = 0; i < ptrs.cabundle.length; i++) {
            require(1 <= ptrs.cabundle[i].length() && ptrs.cabundle[i].length() <= 1024, "invalid cabundle cert");
            cabundle[i] = attestationTbs.slice(ptrs.cabundle[i]);
        }

        ICertManager.VerifiedCert memory parent = verifyCertBundle(cert, cabundle);
        bytes memory hash = Sha2Ext.sha384(attestationTbs, 0, attestationTbs.length);
        _verifySignatureWithHints(parent.pubKey, hash, signature, attestationSigHints);

        return ptrs;
    }

    function _verifySignatureWithHints(
        bytes memory pubKey,
        bytes memory hash,
        bytes memory sig,
        bytes memory signatureHints
    ) internal {
        require(ECDSA384Bench.verifyWithHints(_benchParams(), hash, sig, pubKey, signatureHints), "invalid sig");
    }

    function _benchParams() internal pure returns (ECDSA384Bench.Parameters memory) {
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
