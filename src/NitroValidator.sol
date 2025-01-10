// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

import {ICertManager} from "./ICertManager.sol";
import {Sha2Ext} from "./Sha2Ext.sol";
import {CborDecode, CborElement, LibCborElement} from "./CborDecode.sol";
import {ECDSA384} from "@solarity/libs/crypto/ECDSA384.sol";
import {ECDSA384Curve} from "./ECDSA384Curve.sol";
import {LibBytes} from "./LibBytes.sol";

// adapted from https://github.com/marlinprotocol/NitroProver/blob/f1d368d1f172ad3a55cd2aaaa98ad6a6e7dcde9d/src/NitroProver.sol

contract NitroValidator {
    using LibBytes for bytes;
    using CborDecode for bytes;
    using LibCborElement for CborElement;

    bytes32 public constant ATTESTATION_TBS_PREFIX = keccak256(hex"846a5369676e61747572653144a101382240");
    bytes32 public constant ATTESTATION_DIGEST = keccak256("SHA384");

    bytes32 public constant CERTIFICATE_KEY = keccak256(bytes("certificate"));
    bytes32 public constant PUBLIC_KEY_KEY = keccak256(bytes("public_key"));
    bytes32 public constant MODULE_ID_KEY = keccak256(bytes("module_id"));
    bytes32 public constant TIMESTAMP_KEY = keccak256(bytes("timestamp"));
    bytes32 public constant USER_DATA_KEY = keccak256(bytes("user_data"));
    bytes32 public constant CABUNDLE_KEY = keccak256(bytes("cabundle"));
    bytes32 public constant DIGEST_KEY = keccak256(bytes("digest"));
    bytes32 public constant NONCE_KEY = keccak256(bytes("nonce"));
    bytes32 public constant PCRS_KEY = keccak256(bytes("pcrs"));

    struct Ptrs {
        CborElement moduleID;
        uint64 timestamp;
        CborElement digest;
        CborElement[] pcrs;
        CborElement cert;
        CborElement[] cabundle;
        CborElement publicKey;
        CborElement userData;
        CborElement nonce;
    }

    ICertManager public immutable certManager;

    constructor(ICertManager _certManager) {
        certManager = _certManager;
    }

    function decodeAttestationTbs(bytes memory attestation)
        external
        pure
        returns (bytes memory attestationTbs, bytes memory signature)
    {
        uint256 offset = 1;
        if (attestation[0] == 0xD2) {
            offset = 2;
        }

        CborElement protectedPtr = attestation.byteStringAt(offset);
        CborElement unprotectedPtr = attestation.nextMap(protectedPtr);
        CborElement payloadPtr = attestation.nextByteString(unprotectedPtr);
        CborElement signaturePtr = attestation.nextByteString(payloadPtr);

        uint256 rawProtectedLength = protectedPtr.end() - offset;
        uint256 rawPayloadLength = payloadPtr.end() - unprotectedPtr.end();
        bytes memory rawProtectedBytes = attestation.slice(offset, rawProtectedLength);
        bytes memory rawPayloadBytes = attestation.slice(unprotectedPtr.end(), rawPayloadLength);
        attestationTbs =
            _constructAttestationTbs(rawProtectedBytes, rawProtectedLength, rawPayloadBytes, rawPayloadLength);
        signature = attestation.slice(signaturePtr.start(), signaturePtr.length());
    }

    function validateAttestation(bytes memory attestationTbs, bytes memory signature) public returns (Ptrs memory) {
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

        ICertManager.VerifiedCert memory parent = certManager.verifyCertBundle(cert, cabundle);
        bytes memory hash = Sha2Ext.sha384(attestationTbs, 0, attestationTbs.length);
        _verifySignature(parent.pubKey, hash, signature);

        return ptrs;
    }

    function _constructAttestationTbs(
        bytes memory rawProtectedBytes,
        uint256 rawProtectedLength,
        bytes memory rawPayloadBytes,
        uint256 rawPayloadLength
    ) internal pure returns (bytes memory attestationTbs) {
        attestationTbs = new bytes(13 + rawProtectedLength + rawPayloadLength);
        attestationTbs[0] = bytes1(uint8(4 << 5 | 4)); // Outer: 4-length array
        attestationTbs[1] = bytes1(uint8(3 << 5 | 10)); // Context: 10-length string
        attestationTbs[12 + rawProtectedLength] = bytes1(uint8(2 << 5)); // ExternalAAD: 0-length bytes

        string memory sig = "Signature1";
        uint256 dest;
        uint256 sigSrc;
        uint256 protectedSrc;
        uint256 payloadSrc;
        assembly {
            dest := add(attestationTbs, 32)
            sigSrc := add(sig, 32)
            protectedSrc := add(rawProtectedBytes, 32)
            payloadSrc := add(rawPayloadBytes, 32)
        }

        LibBytes.memcpy(dest + 2, sigSrc, 10);
        LibBytes.memcpy(dest + 12, protectedSrc, rawProtectedLength);
        LibBytes.memcpy(dest + 13 + rawProtectedLength, payloadSrc, rawPayloadLength);
    }

    function _parseAttestation(bytes memory attestationTbs) internal pure returns (Ptrs memory) {
        require(attestationTbs.keccak(0, 18) == ATTESTATION_TBS_PREFIX, "invalid attestation prefix");

        CborElement payload = attestationTbs.byteStringAt(18);
        CborElement current = attestationTbs.mapAt(payload.start());

        Ptrs memory ptrs;
        uint256 end = payload.end();
        while (current.end() < end) {
            current = attestationTbs.nextTextString(current);
            bytes32 keyHash = attestationTbs.keccak(current);
            if (keyHash == MODULE_ID_KEY) {
                current = attestationTbs.nextTextString(current);
                ptrs.moduleID = current;
            } else if (keyHash == DIGEST_KEY) {
                current = attestationTbs.nextTextString(current);
                ptrs.digest = current;
            } else if (keyHash == CERTIFICATE_KEY) {
                current = attestationTbs.nextByteString(current);
                ptrs.cert = current;
            } else if (keyHash == PUBLIC_KEY_KEY) {
                current = attestationTbs.nextByteStringOrNull(current);
                ptrs.publicKey = current;
            } else if (keyHash == USER_DATA_KEY) {
                current = attestationTbs.nextByteStringOrNull(current);
                ptrs.userData = current;
            } else if (keyHash == NONCE_KEY) {
                current = attestationTbs.nextByteStringOrNull(current);
                ptrs.nonce = current;
            } else if (keyHash == TIMESTAMP_KEY) {
                current = attestationTbs.nextPositiveInt(current);
                ptrs.timestamp = uint64(current.value());
            } else if (keyHash == CABUNDLE_KEY) {
                current = attestationTbs.nextArray(current);
                ptrs.cabundle = new CborElement[](current.value());
                for (uint256 i = 0; i < ptrs.cabundle.length; i++) {
                    current = attestationTbs.nextByteString(current);
                    ptrs.cabundle[i] = current;
                }
            } else if (keyHash == PCRS_KEY) {
                current = attestationTbs.nextMap(current);
                ptrs.pcrs = new CborElement[](current.value());
                for (uint256 i = 0; i < ptrs.pcrs.length; i++) {
                    current = attestationTbs.nextPositiveInt(current);
                    uint256 key = current.value();
                    require(key < ptrs.pcrs.length, "invalid pcr key value");
                    require(CborElement.unwrap(ptrs.pcrs[key]) == 0, "duplicate pcr key");
                    current = attestationTbs.nextByteString(current);
                    ptrs.pcrs[key] = current;
                }
            } else {
                revert("invalid attestation key");
            }
        }

        return ptrs;
    }

    function _verifySignature(bytes memory pubKey, bytes memory hash, bytes memory sig) internal view {
        require(ECDSA384.verify(ECDSA384Curve.p384(), hash, sig, pubKey), "invalid sig");
    }
}
