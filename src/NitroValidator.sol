// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

import {ICertManager} from "./ICertManager.sol";
import {Sha2Ext} from "./Sha2Ext.sol";
import {CborDecode, CborElement, LibCborElement} from "./CborDecode.sol";
import {IP384Verifier} from "./IP384Verifier.sol";
import {LibBytes} from "./LibBytes.sol";

// adapted from https://github.com/marlinprotocol/NitroProver/blob/f1d368d1f172ad3a55cd2aaaa98ad6a6e7dcde9d/src/NitroProver.sol

contract NitroValidator {
    using LibBytes for bytes;
    using CborDecode for bytes;
    using LibCborElement for CborElement;

    bytes32 public constant ATTESTATION_TBS_PREFIX = 0x63ce814bd924c1ef12c43686e4cbf48ed1639a78387b0570c23ca921e8ce071c; // keccak256(hex"846a5369676e61747572653144a101382240")
    bytes32 public constant ATTESTATION_DIGEST = 0x501a3a7a4e0cf54b03f2488098bdd59bc1c2e8d741a300d6b25926d531733fef; // keccak256("SHA384")

    bytes32 public constant CERTIFICATE_KEY = 0x925cec779426f44d8d555e01d2683a3a765ce2fa7562ca7352aeb09dfc57ea6a; // keccak256(bytes("certificate"))
    bytes32 public constant PUBLIC_KEY_KEY = 0xc7b28019ccfdbd30ffc65951d94bb85c9e2b8434111a000b5afd533ce65f57a4; // keccak256(bytes("public_key"))
    bytes32 public constant MODULE_ID_KEY = 0x8ce577cf664c36ba5130242bf5790c2675e9f4e6986a842b607821bee25372ee; // keccak256(bytes("module_id"))
    bytes32 public constant TIMESTAMP_KEY = 0x4ebf727c48eac2c66272456b06a885c5cc03e54d140f63b63b6fd10c1227958e; // keccak256(bytes("timestamp"))
    bytes32 public constant USER_DATA_KEY = 0x5e4ea5393e4327b3014bc32f2264336b0d1ee84a4cfd197c8ad7e1e16829a16a; // keccak256(bytes("user_data"))
    bytes32 public constant CABUNDLE_KEY = 0x8a8cb7aa1da17ada103546ae6b4e13ccc2fafa17adf5f93925e0a0a4e5681a6a; // keccak256(bytes("cabundle"))
    bytes32 public constant DIGEST_KEY = 0x682a7e258d80bd2421d3103cbe71e3e3b82138116756b97b8256f061dc2f11fb; // keccak256(bytes("digest"))
    bytes32 public constant NONCE_KEY = 0x7ab1577440dd7bedf920cb6de2f9fc6bf7ba98c78c85a3fa1f8311aac95e1759; // keccak256(bytes("nonce"))
    bytes32 public constant PCRS_KEY = 0x61585f8bc67a4b6d5891a4639a074964ac66fc2241dc0b36c157dc101325367a; // keccak256(bytes("pcrs"))

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
    IP384Verifier public immutable p384Verifier;

    constructor(ICertManager _certManager, IP384Verifier _p384Verifier) {
        require(address(_certManager) != address(0), "missing cert manager");
        require(address(_p384Verifier) != address(0), "missing P384 verifier");
        certManager = _certManager;
        p384Verifier = _p384Verifier;
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

    /// @notice DEPRECATED — always reverts. The fully on-chain (non-hinted) path is too expensive
    ///         post-Fusaka and has been removed. Use {validateAttestationWithHints}.
    function validateAttestation(bytes memory, bytes memory) public pure returns (Ptrs memory) {
        revert("use hinted attestation verification");
    }

    /// @notice Validate a Nitro attestation document, supplying off-chain inverse hints for the
    ///         final document signature.
    /// @dev PRECONDITION: the attestation's entire certificate bundle (every CA cert plus the leaf
    ///      cert) MUST already be verified and cached, via prior calls to
    ///      `CertManager.verifyCACertWithHints` / `verifyClientCertWithHints` with real hints.
    ///      This function re-walks the bundle with EMPTY hints (see `verifyCachedCertBundle`),
    ///      which only succeeds on already-cached certs. If any cert is uncached it reverts with
    ///      "inverse hint underflow" — even when `attestationSigHints` itself is valid.
    /// @dev INTEGRATOR RESPONSIBILITIES — this function proves the attestation is genuine and
    ///      well-formed, but deliberately does NOT enforce:
    ///      - Freshness / anti-replay: `ptrs.timestamp` is only checked to be non-zero and `nonce`
    ///        is only length-bounded. A valid attestation can be replayed until its leaf cert
    ///        expires or is revoked. Callers that need freshness must compare `ptrs.timestamp / 1000`
    ///        to `block.timestamp` and/or match `ptrs.nonce` against a challenge they issued.
    ///      - Signature non-malleability: low-S is not enforced (see {ECDSA384Curve.CURVE_LOW_S_MAX}),
    ///        so do not use `signature` (or its hash) as a uniqueness key — dedupe on attestation
    ///        fields instead.
    ///      - PCR / moduleID policy: the caller must check `ptrs.pcrs` / `ptrs.moduleID` against the
    ///        enclave image(s) they trust.
    /// @param attestationTbs The COSE Sign1 to-be-signed bytes (from `decodeAttestationTbs`).
    /// @param signature The 96-byte (r||s) P-384 attestation signature.
    /// @param attestationSigHints Off-chain inverse hints for the attestation signature; re-verified
    ///        on-chain, so a wrong hint only reverts and can never forge a valid signature.
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

        ICertManager.VerifiedCert memory parent = verifyCachedCertBundle(cert, cabundle);
        bytes memory hash = Sha2Ext.sha384(attestationTbs, 0, attestationTbs.length);
        require(
            p384Verifier.verifyP384SignatureWithHints(hash, signature, parent.pubKey, attestationSigHints),
            "invalid sig"
        );

        return ptrs;
    }

    /// @dev Re-walks the cert bundle (cabundle + leaf) passing EMPTY hint streams, relying on the
    ///      CertManager cache short-circuit: an already-verified, unexpired cert returns its cached
    ///      record without re-checking the signature (and so needs no hints). If a cert is NOT
    ///      cached, signature verification is attempted against an empty hint stream and reverts
    ///      with "inverse hint underflow". Callers must therefore pre-cache the whole bundle first.
    function verifyCachedCertBundle(bytes memory certificate, bytes[] memory cabundle)
        internal
        returns (ICertManager.VerifiedCert memory)
    {
        bytes32 parentHash;
        for (uint256 i = 0; i < cabundle.length; i++) {
            parentHash = certManager.verifyCACertWithHints(cabundle[i], parentHash, "");
        }
        return certManager.verifyClientCertWithHints(certificate, parentHash, "");
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

    /// @dev Parses the COSE payload into pointers, without copying. Forward-compatibility notes:
    ///      - Unknown map keys are skipped, not rejected, so AWS adding new attestation fields does
    ///        not brick verification. This is safe because the whole TBS is later checked against
    ///        AWS's COSE signature, so unknown content is signed and ignoring it cannot change the
    ///        accept decision.
    ///      - The outer payload map and the nested `pcrs` map / `cabundle` array are each accepted in
    ///        both definite-length and indefinite-length CBOR form.
    function _parseAttestation(bytes memory attestationTbs) internal pure returns (Ptrs memory) {
        require(attestationTbs.keccak(0, 18) == ATTESTATION_TBS_PREFIX, "invalid attestation prefix");

        CborElement payload = attestationTbs.byteStringAt(18);
        uint256 mapHeaderIx = payload.start();
        CborElement current = attestationTbs.mapAt(mapHeaderIx);
        bool outerIndefinite = _isIndefinite(attestationTbs, mapHeaderIx);
        uint256 entryCount = current.value(); // entry count for a definite-length map

        Ptrs memory ptrs;
        uint256 end = payload.end();
        for (uint256 entry = 0;; entry++) {
            if (outerIndefinite) {
                // An indefinite-length map is terminated only by a 0xFF break marker. Require it to
                // be present (do not silently stop at the payload end on a missing break), and stop
                // exclusively on it.
                require(current.end() < end, "missing break marker");
                if (uint8(attestationTbs[current.end()]) == 0xff) {
                    require(current.end() + 1 == end, "trailing payload bytes");
                    break;
                }
            } else {
                // A definite-length map ends after exactly `entryCount` entries; a stray 0xFF must
                // not terminate it early (it would be parsed as a key and rejected as a non-string).
                if (entry == entryCount) {
                    require(current.end() == end, "trailing payload bytes");
                    break;
                }
            }
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
                (ptrs.cabundle, current) = _parseCabundle(attestationTbs, current);
            } else if (keyHash == PCRS_KEY) {
                (ptrs.pcrs, current) = _parsePcrs(attestationTbs, current);
            } else {
                // Forward-compatibility: skip (rather than reject) keys this parser does not
                // recognise. The entire TBS is covered by AWS's COSE signature verified in
                // {validateAttestationWithHints}, so an unknown key cannot be injected without
                // invalidating that signature, and ignoring it can only ever drop a field we do
                // not read — never change the accept decision. Rejecting unknown keys instead
                // would brick verification the moment AWS adds a new attestation field.
                uint256 nextIx = attestationTbs.skipValue(current.end());
                current = LibCborElement.toCborElement(0x00, nextIx, 0);
            }
        }

        return ptrs;
    }

    /// @dev Parses the `cabundle` array (definite- or indefinite-length) starting from the key
    ///      element `keyPtr`. Returns the parsed cert pointers and the cursor positioned after the
    ///      array (past the break marker, for indefinite encoding).
    function _parseCabundle(bytes memory tbs, CborElement keyPtr)
        private
        pure
        returns (CborElement[] memory cabundle, CborElement current)
    {
        uint256 headerIx = keyPtr.end();
        current = tbs.nextArray(keyPtr);
        bool indefinite = _isIndefinite(tbs, headerIx);
        uint256 count = indefinite ? _countIndefiniteItems(tbs, current.end()) : current.value();
        cabundle = new CborElement[](count);
        for (uint256 i = 0; i < count; i++) {
            current = tbs.nextByteString(current);
            cabundle[i] = current;
        }
        if (indefinite) current = _consumeBreak(tbs, current);
    }

    /// @dev Parses the `pcrs` map (definite- or indefinite-length) starting from the key element
    ///      `keyPtr`. Returns the parsed pcr pointers (indexed by pcr key) and the cursor positioned
    ///      after the map (past the break marker, for indefinite encoding).
    function _parsePcrs(bytes memory tbs, CborElement keyPtr)
        private
        pure
        returns (CborElement[] memory pcrs, CborElement current)
    {
        uint256 headerIx = keyPtr.end();
        current = tbs.nextMap(keyPtr);
        bool indefinite = _isIndefinite(tbs, headerIx);
        uint256 count;
        if (indefinite) {
            // each map entry is a key/value pair, so a well-formed indefinite map holds an even
            // number of items (2 per pcr); an odd count is malformed and must revert rather than
            // silently drop the trailing item.
            uint256 items = _countIndefiniteItems(tbs, current.end());
            require(items % 2 == 0, "invalid pcrs map");
            count = items / 2;
        } else {
            count = current.value();
        }
        pcrs = new CborElement[](count);
        for (uint256 i = 0; i < count; i++) {
            current = tbs.nextPositiveInt(current);
            uint256 key = current.value();
            require(key < count, "invalid pcr key value");
            require(CborElement.unwrap(pcrs[key]) == 0, "duplicate pcr key");
            current = tbs.nextByteString(current);
            pcrs[key] = current;
        }
        if (indefinite) current = _consumeBreak(tbs, current);
    }

    /// @dev True if the CBOR container header at `headerIx` uses indefinite-length encoding (ai=31).
    function _isIndefinite(bytes memory cbor, uint256 headerIx) private pure returns (bool) {
        return (uint8(cbor[headerIx]) & 0x1f) == 31;
    }

    /// @dev Counts the data items of an indefinite-length container whose first item starts at `ix`,
    ///      stopping at the 0xFF break marker. Reverts on truncated input (no break before the end).
    function _countIndefiniteItems(bytes memory cbor, uint256 ix) private pure returns (uint256 count) {
        while (uint8(cbor[ix]) != 0xff) {
            ix = cbor.skipValue(ix);
            count++;
        }
    }

    /// @dev Verifies the byte immediately after `ptr` is the 0xFF break marker and returns a
    ///      zero-length element positioned just past it, so the caller's cursor skips the consumed
    ///      break. Reverts if the marker is absent (e.g. a nested indefinite container that did not
    ///      close where the fill loop ended), turning a malformed encoding into a revert.
    function _consumeBreak(bytes memory cbor, CborElement ptr) private pure returns (CborElement) {
        require(uint8(cbor[ptr.end()]) == 0xff, "expected break marker");
        return LibCborElement.toCborElement(0x00, ptr.end() + 1, 0);
    }
}
