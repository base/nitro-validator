// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test, console} from "forge-std/Test.sol";
import {NitroValidator} from "../../src/NitroValidator.sol";
import {CertManager} from "../../src/CertManager.sol";
import {CertManagerHinted} from "../../src/CertManagerHinted.sol";
import {ICertManager} from "../../src/ICertManager.sol";
import {CborDecode} from "../../src/CborDecode.sol";
import {NitroValidatorHinted} from "../../src/NitroValidatorHinted.sol";
import {P384Verifier} from "../../src/P384Verifier.sol";
import {Sha2Ext} from "../../src/Sha2Ext.sol";
import {P384HintCollectorBench} from "./HintedNitroBench.sol";

contract NitroValidatorParseHarness is NitroValidator {
    constructor(CertManager certManager) NitroValidator(certManager) {}

    function parseAttestation(bytes memory attestationTbs) external pure returns (Ptrs memory) {
        return _parseAttestation(attestationTbs);
    }
}

contract RealAttestationBenchTest is Test {
    using CborDecode for bytes;

    uint256 constant P384_VERIFY_2565 = 7_938_921;
    uint256 constant P384_VERIFY_7883 = 50_646_861;
    uint256 constant HINTED_P384_VERIFY_7883_WITH_CALLDATA = 6_040_809;
    uint256 constant HINTED_MODEXP_FLOOR_DELTA = 300; // EIP-7883 floor 500 - EIP-2565 floor 200
    uint256 constant TX_CAP = 16_777_216;
    uint256 constant EIP170_RUNTIME_LIMIT = 24_576;

    CertManager certManager;
    NitroValidator validator;
    NitroValidatorParseHarness parser;
    CertManagerHinted hintedCertManager;
    NitroValidatorHinted hintedValidator;
    P384Verifier p384Verifier;
    P384HintCollectorBench hintCollector;

    struct SequenceSummary {
        ICertManager.VerifiedCert leaf;
        uint256 txCount;
        uint256 totalCurrentGas;
        uint256 totalProjectedGas;
        uint256 maxProjectedGas;
    }

    struct TxGas {
        uint256 currentGas;
        uint256 projectedGas;
    }

    function setUp() public {
        vm.warp(1767472867); // 2026-01-03T20:41:07Z, matching the attestation timestamp.
        certManager = new CertManager();
        validator = new NitroValidator(certManager);
        parser = new NitroValidatorParseHarness(certManager);
        p384Verifier = new P384Verifier();
        hintedCertManager = new CertManagerHinted(p384Verifier);
        hintedValidator = new NitroValidatorHinted(hintedCertManager, p384Verifier);
        hintCollector = new P384HintCollectorBench();
    }

    function test_RealAttestationBaseline() public {
        bytes memory attestation = _decodeBase64(_realAttestationB64());
        attestation = _repairMissingPublicKeyBytes(attestation);

        uint256 g0 = gasleft();
        (bytes memory attestationTbs, bytes memory signature) = validator.decodeAttestationTbs(attestation);
        uint256 decodeGas = g0 - gasleft();

        g0 = gasleft();
        validator.validateAttestation(attestationTbs, signature);
        uint256 coldValidateGas = g0 - gasleft();

        g0 = gasleft();
        validator.validateAttestation(attestationTbs, signature);
        uint256 cachedValidateGas = g0 - gasleft();
        uint256 cachedPostFusakaUnoptimized = cachedValidateGas + (P384_VERIFY_7883 - P384_VERIFY_2565);
        uint256 cachedPostFusakaHinted = cachedValidateGas - P384_VERIFY_2565 + HINTED_P384_VERIFY_7883_WITH_CALLDATA;

        console.log("==== REAL ATTESTATION BASELINE ====");
        console.log("attestation bytes                 :", attestation.length);
        console.log("attestationTbs bytes              :", attestationTbs.length);
        console.log("signature bytes                   :", signature.length);
        console.log("decodeAttestationTbs gas          :", decodeGas);
        console.log("validateAttestation gas (cold)    :", coldValidateGas);
        console.log("validateAttestation gas (cached)  :", cachedValidateGas);
        console.log("cached post-Fusaka unoptimized    :", cachedPostFusakaUnoptimized);
        console.log("cached post-Fusaka hinted+calldata:", cachedPostFusakaHinted);
        console.log("cached hinted fits tx cap?        :", cachedPostFusakaHinted <= TX_CAP ? 1 : 0);
    }

    function test_RealAttestationPerCertSplitProjection() public {
        bytes memory attestation = _repairMissingPublicKeyBytes(_decodeBase64(_realAttestationB64()));
        (bytes memory attestationTbs,) = validator.decodeAttestationTbs(attestation);
        NitroValidator.Ptrs memory ptrs = parser.parseAttestation(attestationTbs);

        bytes32 parentHash;
        console.log("==== REAL ATTESTATION PER-CERT SPLIT ====");
        for (uint256 i = 0; i < ptrs.cabundle.length; ++i) {
            bytes memory caCert = attestationTbs.slice(ptrs.cabundle[i]);
            uint256 certG0 = gasleft();
            parentHash = certManager.verifyCACert(caCert, parentHash);
            uint256 certGas = certG0 - gasleft();
            uint256 projected = i == 0 ? certGas : _projectOneHintedP384(certGas);
            console.log("cabundle index                    :", i);
            console.log("  current gas                     :", certGas);
            console.log("  projected hinted post-Fusaka    :", projected);
            console.log("  fits tx cap?                    :", projected <= TX_CAP ? 1 : 0);
            assertLe(projected, TX_CAP);
        }

        bytes memory clientCert = attestationTbs.slice(ptrs.cert);
        uint256 clientG0 = gasleft();
        certManager.verifyClientCert(clientCert, parentHash);
        uint256 clientGas = clientG0 - gasleft();
        uint256 clientProjected = _projectOneHintedP384(clientGas);
        console.log("client cert");
        console.log("  current gas                     :", clientGas);
        console.log("  projected hinted post-Fusaka    :", clientProjected);
        console.log("  fits tx cap?                    :", clientProjected <= TX_CAP ? 1 : 0);
        assertLe(clientProjected, TX_CAP);
    }

    function test_ProductionShapedHintedPerCertSplit() public {
        bytes memory attestation = _repairMissingPublicKeyBytes(_decodeBase64(_realAttestationB64()));
        (bytes memory attestationTbs,) = validator.decodeAttestationTbs(attestation);
        NitroValidator.Ptrs memory ptrs = parser.parseAttestation(attestationTbs);

        bytes32 parentHash;
        bytes memory parentPubKey;
        console.log("==== PRODUCTION-SHAPED HINTED PER-CERT SPLIT ====");
        for (uint256 i = 0; i < ptrs.cabundle.length; ++i) {
            bytes memory caCert = attestationTbs.slice(ptrs.cabundle[i]);
            bytes memory hints;
            uint256 hintedOtherCalls;
            if (i != 0) {
                parentPubKey = hintedCertManager.loadVerified(parentHash).pubKey;
                (hints, hintedOtherCalls) = hintCollector.collectCertSignatureProfile(caCert, parentPubKey);
            }

            uint256 certG0 = gasleft();
            parentHash = hintedCertManager.verifyCACertWithHints(caCert, parentHash, hints);
            uint256 certGas = certG0 - gasleft();
            uint256 projected = _projectHintedMeasured(certGas, hints.length, hintedOtherCalls);
            console.log("cabundle index                    :", i);
            console.log("  current hinted gas              :", certGas);
            console.log("  inverse hint bytes              :", hints.length);
            console.log("  hinted MODEXP floor calls       :", hintedOtherCalls);
            console.log("  projected hinted post-Fusaka    :", projected);
            console.log("  fits tx cap?                    :", projected <= TX_CAP ? 1 : 0);
            assertLe(projected, TX_CAP);
        }

        bytes memory clientCert = attestationTbs.slice(ptrs.cert);
        parentPubKey = hintedCertManager.loadVerified(parentHash).pubKey;
        (bytes memory clientHints, uint256 clientHintedOtherCalls) =
            hintCollector.collectCertSignatureProfile(clientCert, parentPubKey);

        uint256 clientG0 = gasleft();
        hintedCertManager.verifyClientCertWithHints(clientCert, parentHash, clientHints);
        uint256 clientGas = clientG0 - gasleft();
        uint256 clientProjected = _projectHintedMeasured(clientGas, clientHints.length, clientHintedOtherCalls);
        console.log("client cert");
        console.log("  current hinted gas              :", clientGas);
        console.log("  inverse hint bytes              :", clientHints.length);
        console.log("  hinted MODEXP floor calls       :", clientHintedOtherCalls);
        console.log("  projected hinted post-Fusaka    :", clientProjected);
        console.log("  fits tx cap?                    :", clientProjected <= TX_CAP ? 1 : 0);
        assertLe(clientProjected, TX_CAP);
    }

    function test_ProductionShapedHintedCachedAttestation() public {
        bytes memory attestation = _repairMissingPublicKeyBytes(_decodeBase64(_realAttestationB64()));
        (bytes memory attestationTbs, bytes memory signature) = validator.decodeAttestationTbs(attestation);
        ICertManager.VerifiedCert memory leaf = _cacheCertBundleWithHints(attestationTbs);

        bytes memory hash = Sha2Ext.sha384(attestationTbs, 0, attestationTbs.length);
        (bytes memory attestationHints, uint256 hintedOtherCalls) =
            hintCollector.collectVerifyProfile(hash, signature, leaf.pubKey);

        uint256 g0 = gasleft();
        hintedValidator.validateAttestationWithHints(attestationTbs, signature, attestationHints);
        uint256 hintedGas = g0 - gasleft();
        uint256 projected = _projectHintedMeasured(hintedGas, attestationHints.length, hintedOtherCalls);

        console.log("==== PRODUCTION-SHAPED HINTED CACHED ATTESTATION ====");
        console.log("current hinted cached gas         :", hintedGas);
        console.log("inverse hint bytes                :", attestationHints.length);
        console.log("hinted MODEXP floor calls         :", hintedOtherCalls);
        console.log("projected hinted post-Fusaka      :", projected);
        console.log("fits tx cap?                      :", projected <= TX_CAP ? 1 : 0);
        assertLe(projected, TX_CAP);
    }

    function test_ProductionShapedHintedAttestationRejectsSurplusHint() public {
        bytes memory attestation = _repairMissingPublicKeyBytes(_decodeBase64(_realAttestationB64()));
        (bytes memory attestationTbs, bytes memory signature) = validator.decodeAttestationTbs(attestation);
        ICertManager.VerifiedCert memory leaf = _cacheCertBundleWithHints(attestationTbs);

        bytes memory hash = Sha2Ext.sha384(attestationTbs, 0, attestationTbs.length);
        bytes memory attestationHints =
            abi.encodePacked(hintCollector.collectVerifyHints(hash, signature, leaf.pubKey), bytes1(0x00));

        vm.expectRevert("unused inverse hints");
        hintedValidator.validateAttestationWithHints(attestationTbs, signature, attestationHints);
    }

    function test_008_ProductionCandidateRejectsMutatedCertHint() public {
        bytes memory attestation = _repairMissingPublicKeyBytes(_decodeBase64(_realAttestationB64()));
        (bytes memory attestationTbs,) = validator.decodeAttestationTbs(attestation);
        NitroValidator.Ptrs memory ptrs = parser.parseAttestation(attestationTbs);
        (bytes memory caCert, bytes32 parentHash, bytes memory parentPubKey) = _firstNonRootCA(attestationTbs, ptrs);
        (bytes memory hints,) = hintCollector.collectCertSignatureProfile(caCert, parentPubKey);
        hints[10] = bytes1(uint8(hints[10]) ^ 1);

        vm.expectRevert("bad inverse hint");
        hintedCertManager.verifyCACertWithHints(caCert, parentHash, hints);
    }

    function test_008_ProductionCandidateRejectsTruncatedCertHint() public {
        bytes memory attestation = _repairMissingPublicKeyBytes(_decodeBase64(_realAttestationB64()));
        (bytes memory attestationTbs,) = validator.decodeAttestationTbs(attestation);
        NitroValidator.Ptrs memory ptrs = parser.parseAttestation(attestationTbs);
        (bytes memory caCert, bytes32 parentHash, bytes memory parentPubKey) = _firstNonRootCA(attestationTbs, ptrs);
        (bytes memory hints,) = hintCollector.collectCertSignatureProfile(caCert, parentPubKey);
        assembly {
            mstore(hints, sub(mload(hints), 1))
        }

        vm.expectRevert("inverse hint underflow");
        hintedCertManager.verifyCACertWithHints(caCert, parentHash, hints);
    }

    function test_008_ProductionCandidateRejectsWrongParentHash() public {
        bytes memory attestation = _repairMissingPublicKeyBytes(_decodeBase64(_realAttestationB64()));
        (bytes memory attestationTbs,) = validator.decodeAttestationTbs(attestation);
        NitroValidator.Ptrs memory ptrs = parser.parseAttestation(attestationTbs);
        bytes memory caCert = attestationTbs.slice(ptrs.cabundle[1]);

        vm.expectRevert("parent cert unverified");
        hintedCertManager.verifyCACertWithHints(caCert, bytes32(0), "");
    }

    function test_008_ProductionCandidateRejectsExpiredCachedCert() public {
        bytes memory attestation = _repairMissingPublicKeyBytes(_decodeBase64(_realAttestationB64()));
        (bytes memory attestationTbs,) = validator.decodeAttestationTbs(attestation);
        NitroValidator.Ptrs memory ptrs = parser.parseAttestation(attestationTbs);
        (bytes memory caCert, bytes32 parentHash, bytes memory parentPubKey) = _firstNonRootCA(attestationTbs, ptrs);
        bytes memory hints = hintCollector.collectCertSignatureHints(caCert, parentPubKey);
        hintedCertManager.verifyCACertWithHints(caCert, parentHash, hints);

        vm.warp(1768953600); // 2026-01-21T00:00:00Z, after this fixture's first non-root CA expiry.

        vm.expectRevert("cert expired");
        hintedCertManager.verifyCACertWithHints(caCert, parentHash, "");
    }

    function test_008_ProductionCandidateRejectsCachedRoleMismatch() public {
        bytes memory attestation = _repairMissingPublicKeyBytes(_decodeBase64(_realAttestationB64()));
        (bytes memory attestationTbs,) = validator.decodeAttestationTbs(attestation);
        NitroValidator.Ptrs memory ptrs = parser.parseAttestation(attestationTbs);
        (bytes memory caCert, bytes32 parentHash, bytes memory parentPubKey) = _firstNonRootCA(attestationTbs, ptrs);
        bytes memory hints = hintCollector.collectCertSignatureHints(caCert, parentPubKey);
        hintedCertManager.verifyCACertWithHints(caCert, parentHash, hints);

        vm.expectRevert("cert is not a CA");
        hintedCertManager.verifyClientCertWithHints(caCert, parentHash, "");
    }

    function test_008_ProductionCandidateValidateRequiresWarmCache() public {
        bytes memory attestation = _repairMissingPublicKeyBytes(_decodeBase64(_realAttestationB64()));
        (bytes memory attestationTbs, bytes memory signature) = validator.decodeAttestationTbs(attestation);
        CertManagerHinted freshCertManager = new CertManagerHinted(p384Verifier);
        NitroValidatorHinted freshValidator = new NitroValidatorHinted(freshCertManager, p384Verifier);

        vm.expectRevert("inverse hint underflow");
        freshValidator.validateAttestationWithHints(attestationTbs, signature, "");
    }

    function test_008_ProductionCandidateRejectsInvalidFinalSignature() public {
        bytes memory attestation = _repairMissingPublicKeyBytes(_decodeBase64(_realAttestationB64()));
        (bytes memory attestationTbs, bytes memory signature) = validator.decodeAttestationTbs(attestation);
        ICertManager.VerifiedCert memory leaf = _cacheCertBundleWithHints(attestationTbs);
        bytes memory hash = Sha2Ext.sha384(attestationTbs, 0, attestationTbs.length);
        bytes memory attestationHints = hintCollector.collectVerifyHints(hash, signature, leaf.pubKey);
        signature[0] = bytes1(uint8(signature[0]) ^ 1);

        vm.expectRevert();
        hintedValidator.validateAttestationWithHints(attestationTbs, signature, attestationHints);
    }

    function test_009_DeployableHintedContractsFitEIP170() public view {
        console.log("==== 009 DEPLOYABLE CONTRACT SIZES ====");
        console.log("P384Verifier runtime bytes        :", address(p384Verifier).code.length);
        console.log("CertManagerHinted runtime bytes   :", address(hintedCertManager).code.length);
        console.log("NitroValidatorHinted runtime bytes:", address(hintedValidator).code.length);
        assertLe(address(p384Verifier).code.length, EIP170_RUNTIME_LIMIT);
        assertLe(address(hintedCertManager).code.length, EIP170_RUNTIME_LIMIT);
        assertLe(address(hintedValidator).code.length, EIP170_RUNTIME_LIMIT);
    }

    function test_009_DeployableCertManagerDisablesUnhintedEntrypoints() public {
        vm.expectRevert("use hinted cert verification");
        hintedCertManager.verifyCACert("", bytes32(0));

        vm.expectRevert("use hinted cert verification");
        hintedCertManager.verifyClientCert("", bytes32(0));
    }

    function test_010_OffchainWitnessGeneratorMatchesSolidityCollector() public {
        if (!vm.envOr("NITRO_RUN_FFI", false)) {
            console.log("==== 010 OFFCHAIN WITNESS GENERATOR ====");
            console.log("skipped; rerun with NITRO_RUN_FFI=true forge test --ffi --match-test test_010");
            return;
        }

        bytes memory attestation = _repairMissingPublicKeyBytes(_decodeBase64(_realAttestationB64()));
        (bytes memory attestationTbs, bytes memory signature) = validator.decodeAttestationTbs(attestation);
        NitroValidator.Ptrs memory ptrs = parser.parseAttestation(attestationTbs);

        bytes memory rootCert = attestationTbs.slice(ptrs.cabundle[0]);
        bytes32 parentHash = keccak256(rootCert);
        bytes memory parentPubKey = hintedCertManager.loadVerified(parentHash).pubKey;
        uint256 signaturesChecked;

        for (uint256 i = 1; i < ptrs.cabundle.length; ++i) {
            bytes memory caCert = attestationTbs.slice(ptrs.cabundle[i]);
            bytes memory expectedHints = hintCollector.collectCertSignatureHints(caCert, parentPubKey);
            bytes memory offchainHints = _ffiCertSignatureHints(caCert, parentPubKey);
            assertEq(offchainHints, expectedHints, "offchain CA cert hints mismatch");

            parentHash = hintedCertManager.verifyCACertWithHints(caCert, parentHash, offchainHints);
            parentPubKey = hintedCertManager.loadVerified(parentHash).pubKey;
            signaturesChecked += 1;
        }

        bytes memory clientCert = attestationTbs.slice(ptrs.cert);
        bytes memory expectedClientHints = hintCollector.collectCertSignatureHints(clientCert, parentPubKey);
        bytes memory offchainClientHints = _ffiCertSignatureHints(clientCert, parentPubKey);
        assertEq(offchainClientHints, expectedClientHints, "offchain client cert hints mismatch");
        ICertManager.VerifiedCert memory leaf =
            hintedCertManager.verifyClientCertWithHints(clientCert, parentHash, offchainClientHints);
        signaturesChecked += 1;

        _assertOffchainAttestationHints(attestation, attestationTbs, signature, leaf.pubKey);
        signaturesChecked += 1;

        console.log("==== 010 OFFCHAIN WITNESS GENERATOR ====");
        console.log("signatures checked                :", signaturesChecked);
    }

    function test_007_FullColdAndWarmHintedSequence() public {
        bytes memory attestation = _repairMissingPublicKeyBytes(_decodeBase64(_realAttestationB64()));
        (bytes memory attestationTbs, bytes memory signature) = validator.decodeAttestationTbs(attestation);
        NitroValidator.Ptrs memory ptrs = parser.parseAttestation(attestationTbs);

        console.log("==== 007 FULL COLD + WARM HINTED SEQUENCE ====");
        console.log("cabundle certs                   :", ptrs.cabundle.length);
        console.log("minimum cold tx count            :", ptrs.cabundle.length + 1);
        console.log("warm-cache tx count              :", uint256(1));
        console.log("root is constructor-pinned tx?   :", uint256(0));

        SequenceSummary memory cold = _runColdCertCacheSequence(attestationTbs, ptrs);

        bytes memory hash = Sha2Ext.sha384(attestationTbs, 0, attestationTbs.length);
        (bytes memory attestationHints, uint256 attestationHintedOtherCalls) =
            hintCollector.collectVerifyProfile(hash, signature, cold.leaf.pubKey);

        TxGas memory coldFinal = _runAttestationValidationTx(
            cold.txCount + 1,
            "validate attestation",
            attestationTbs,
            signature,
            attestationHints.length,
            attestationHintedOtherCalls,
            attestationHints
        );
        cold.txCount += 1;
        cold.totalCurrentGas += coldFinal.currentGas;
        cold.totalProjectedGas += coldFinal.projectedGas;
        cold.maxProjectedGas = _max(cold.maxProjectedGas, coldFinal.projectedGas);

        console.log("cold sequence tx count           :", cold.txCount);
        console.log("cold total current gas           :", cold.totalCurrentGas);
        console.log("cold total projected gas         :", cold.totalProjectedGas);
        console.log("cold max projected tx gas        :", cold.maxProjectedGas);
        console.log("cold sequence all txs fit cap?   :", cold.maxProjectedGas <= TX_CAP ? 1 : 0);

        _runAttestationValidationTx(
            1,
            "warm validate",
            attestationTbs,
            signature,
            attestationHints.length,
            attestationHintedOtherCalls,
            attestationHints
        );
    }

    function _decodeBase64(string memory input) internal pure returns (bytes memory output) {
        bytes memory data = bytes(input);
        require(data.length % 4 == 0, "bad base64 length");

        uint256 decodedLen = (data.length / 4) * 3;
        if (data.length != 0 && data[data.length - 1] == "=") --decodedLen;
        if (data.length > 1 && data[data.length - 2] == "=") --decodedLen;

        output = new bytes(decodedLen);
        uint256 out;

        for (uint256 i = 0; i < data.length; i += 4) {
            uint256 n = (_base64Value(data[i]) << 18) | (_base64Value(data[i + 1]) << 12)
                | (_base64Value(data[i + 2]) << 6) | _base64Value(data[i + 3]);

            if (out < decodedLen) output[out++] = bytes1(uint8(n >> 16));
            if (out < decodedLen) output[out++] = bytes1(uint8(n >> 8));
            if (out < decodedLen) output[out++] = bytes1(uint8(n));
        }
    }

    function _base64Value(bytes1 char) internal pure returns (uint256) {
        uint8 c = uint8(char);
        if (c >= 0x41 && c <= 0x5a) return c - 0x41;
        if (c >= 0x61 && c <= 0x7a) return c - 0x61 + 26;
        if (c >= 0x30 && c <= 0x39) return c - 0x30 + 52;
        if (c == 0x2b) return 62;
        if (c == 0x2f) return 63;
        if (c == 0x3d) return 0;
        revert("bad base64 char");
    }

    function _projectOneHintedP384(uint256 currentGas) internal pure returns (uint256) {
        return currentGas - P384_VERIFY_2565 + HINTED_P384_VERIFY_7883_WITH_CALLDATA;
    }

    function _projectHintedMeasured(uint256 currentHintedGas, uint256 hintBytes, uint256 hintedOtherCalls)
        internal
        pure
        returns (uint256)
    {
        if (hintBytes == 0) {
            return currentHintedGas;
        }

        return currentHintedGas + hintedOtherCalls * HINTED_MODEXP_FLOOR_DELTA + hintBytes * 16;
    }

    function _firstNonRootCA(bytes memory attestationTbs, NitroValidator.Ptrs memory ptrs)
        internal
        view
        returns (bytes memory caCert, bytes32 parentHash, bytes memory parentPubKey)
    {
        caCert = attestationTbs.slice(ptrs.cabundle[1]);
        bytes memory rootCert = attestationTbs.slice(ptrs.cabundle[0]);
        parentHash = keccak256(rootCert);
        parentPubKey = hintedCertManager.loadVerified(parentHash).pubKey;
    }

    function _runColdCertCacheSequence(bytes memory attestationTbs, NitroValidator.Ptrs memory ptrs)
        internal
        returns (SequenceSummary memory summary)
    {
        bytes memory rootCert = attestationTbs.slice(ptrs.cabundle[0]);
        bytes32 parentHash = keccak256(rootCert);
        ICertManager.VerifiedCert memory parent = hintedCertManager.loadVerified(parentHash);
        assertTrue(parent.pubKey.length > 0, "root must already be cached");
        assertTrue(parent.ca, "root must be cached as CA");
        console.log("root cert hash pinned            :");
        console.logBytes32(parentHash);

        uint256 g0;
        for (uint256 i = 1; i < ptrs.cabundle.length; ++i) {
            bytes memory caCert = attestationTbs.slice(ptrs.cabundle[i]);
            (bytes memory hints, uint256 hintedOtherCalls) =
                hintCollector.collectCertSignatureProfile(caCert, parent.pubKey);

            g0 = gasleft();
            parentHash = hintedCertManager.verifyCACertWithHints(caCert, parentHash, hints);
            uint256 currentGas = g0 - gasleft();
            parent = hintedCertManager.loadVerified(parentHash);
            assertTrue(parent.pubKey.length > 0, "CA cert must be cached");
            assertTrue(parent.ca, "CA cert must be cached as CA");

            uint256 projectedGas = _projectHintedMeasured(currentGas, hints.length, hintedOtherCalls);
            summary.txCount += 1;
            _logSequenceTx(summary.txCount, "cache CA cert", currentGas, hints.length, hintedOtherCalls, projectedGas);
            _addTxToSummary(summary, currentGas, projectedGas);
        }

        bytes memory clientCert = attestationTbs.slice(ptrs.cert);
        (bytes memory clientHints, uint256 clientHintedOtherCalls) =
            hintCollector.collectCertSignatureProfile(clientCert, parent.pubKey);

        g0 = gasleft();
        summary.leaf = hintedCertManager.verifyClientCertWithHints(clientCert, parentHash, clientHints);
        uint256 clientCurrentGas = g0 - gasleft();

        bytes32 leafHash = keccak256(clientCert);
        ICertManager.VerifiedCert memory cachedLeaf = hintedCertManager.loadVerified(leafHash);
        assertTrue(cachedLeaf.pubKey.length > 0, "client cert must be cached");
        assertFalse(cachedLeaf.ca, "client cert must be cached as client");

        uint256 clientProjectedGas =
            _projectHintedMeasured(clientCurrentGas, clientHints.length, clientHintedOtherCalls);
        summary.txCount += 1;
        _logSequenceTx(
            summary.txCount,
            "cache client cert",
            clientCurrentGas,
            clientHints.length,
            clientHintedOtherCalls,
            clientProjectedGas
        );
        _addTxToSummary(summary, clientCurrentGas, clientProjectedGas);
    }

    function _runAttestationValidationTx(
        uint256 txIndex,
        string memory label,
        bytes memory attestationTbs,
        bytes memory signature,
        uint256 hintBytes,
        uint256 hintedOtherCalls,
        bytes memory attestationHints
    ) internal returns (TxGas memory txGas) {
        uint256 g0 = gasleft();
        hintedValidator.validateAttestationWithHints(attestationTbs, signature, attestationHints);
        txGas.currentGas = g0 - gasleft();
        txGas.projectedGas = _projectHintedMeasured(txGas.currentGas, hintBytes, hintedOtherCalls);
        _logSequenceTx(txIndex, label, txGas.currentGas, hintBytes, hintedOtherCalls, txGas.projectedGas);
        assertLe(txGas.projectedGas, TX_CAP);
    }

    function _addTxToSummary(SequenceSummary memory summary, uint256 currentGas, uint256 projectedGas) internal pure {
        assert(projectedGas <= TX_CAP);
        summary.totalCurrentGas += currentGas;
        summary.totalProjectedGas += projectedGas;
        summary.maxProjectedGas = _max(summary.maxProjectedGas, projectedGas);
    }

    function _logSequenceTx(
        uint256 txIndex,
        string memory label,
        uint256 currentGas,
        uint256 hintBytes,
        uint256 hintedOtherCalls,
        uint256 projectedGas
    ) internal pure {
        console.log("sequence tx                       :", txIndex);
        console.log("  label                           :", label);
        console.log("  current hinted gas              :", currentGas);
        console.log("  inverse hint bytes              :", hintBytes);
        console.log("  hinted MODEXP floor calls       :", hintedOtherCalls);
        console.log("  projected post-Fusaka gas       :", projectedGas);
        console.log("  fits tx cap?                    :", projectedGas <= TX_CAP ? 1 : 0);
    }

    function _max(uint256 a, uint256 b) internal pure returns (uint256) {
        return a >= b ? a : b;
    }

    function _cacheCertBundleWithHints(bytes memory attestationTbs)
        internal
        returns (ICertManager.VerifiedCert memory leaf)
    {
        NitroValidator.Ptrs memory ptrs = parser.parseAttestation(attestationTbs);

        bytes32 parentHash;
        bytes memory parentPubKey;
        for (uint256 i = 0; i < ptrs.cabundle.length; ++i) {
            bytes memory caCert = attestationTbs.slice(ptrs.cabundle[i]);
            bytes memory hints;
            if (i != 0) {
                parentPubKey = hintedCertManager.loadVerified(parentHash).pubKey;
                hints = hintCollector.collectCertSignatureHints(caCert, parentPubKey);
            }
            parentHash = hintedCertManager.verifyCACertWithHints(caCert, parentHash, hints);
        }

        bytes memory clientCert = attestationTbs.slice(ptrs.cert);
        parentPubKey = hintedCertManager.loadVerified(parentHash).pubKey;
        bytes memory clientHints = hintCollector.collectCertSignatureHints(clientCert, parentPubKey);
        leaf = hintedCertManager.verifyClientCertWithHints(clientCert, parentHash, clientHints);
    }

    function _ffiCertSignatureHints(bytes memory cert, bytes memory parentPubKey) internal returns (bytes memory) {
        string[] memory command = new string[](7);
        command[0] = "node";
        command[1] = string.concat(vm.projectRoot(), "/bench/p384_hints.js");
        command[2] = "cert";
        command[3] = "--cert";
        command[4] = vm.toString(cert);
        command[5] = "--pubkey";
        command[6] = vm.toString(parentPubKey);
        return vm.ffi(command);
    }

    function _ffiVerifyHints(bytes memory hash, bytes memory signature, bytes memory pubKey)
        internal
        returns (bytes memory)
    {
        string[] memory command = new string[](9);
        command[0] = "node";
        command[1] = string.concat(vm.projectRoot(), "/bench/p384_hints.js");
        command[2] = "verify";
        command[3] = "--hash";
        command[4] = vm.toString(hash);
        command[5] = "--signature";
        command[6] = vm.toString(signature);
        command[7] = "--pubkey";
        command[8] = vm.toString(pubKey);
        return vm.ffi(command);
    }

    function _assertOffchainAttestationHints(
        bytes memory attestation,
        bytes memory attestationTbs,
        bytes memory signature,
        bytes memory pubKey
    ) internal {
        bytes memory hash = Sha2Ext.sha384(attestationTbs, 0, attestationTbs.length);
        bytes memory expectedHints = hintCollector.collectVerifyHints(hash, signature, pubKey);
        bytes memory offchainHints = _ffiVerifyHints(hash, signature, pubKey);
        assertEq(offchainHints, expectedHints, "offchain attestation hints mismatch");

        bytes memory offchainCoseHints = _ffiAttestationHints(attestation, pubKey);
        assertEq(offchainCoseHints, expectedHints, "offchain COSE attestation hints mismatch");

        hintedValidator.validateAttestationWithHints(attestationTbs, signature, offchainHints);
        console.log("final attestation hint bytes      :", offchainHints.length);
    }

    function _ffiAttestationHints(bytes memory attestation, bytes memory pubKey) internal returns (bytes memory) {
        string[] memory command = new string[](7);
        command[0] = "node";
        command[1] = string.concat(vm.projectRoot(), "/bench/p384_hints.js");
        command[2] = "attestation";
        command[3] = "--attestation";
        command[4] = vm.toString(attestation);
        command[5] = "--pubkey";
        command[6] = vm.toString(pubKey);
        return vm.ffi(command);
    }

    function _repairMissingPublicKeyBytes(bytes memory attestation) internal pure returns (bytes memory repaired) {
        // The pasted Base64 sample is missing "ic_" in the CBOR key
        // "public_key", but the key length and outer COSE payload length still
        // correspond to the complete bytes. Insert the missing 3 bytes so this
        // fixture matches the signed Nitro document shape.
        uint256 insertAt = 4338;
        require(
            attestation[insertAt - 4] == 0x70 && attestation[insertAt - 3] == 0x75 && attestation[insertAt - 2] == 0x62
                && attestation[insertAt - 1] == 0x6c && attestation[insertAt] == 0x6b
                && attestation[insertAt + 1] == 0x65 && attestation[insertAt + 2] == 0x79,
            "unexpected fixture public_key corruption"
        );

        repaired = new bytes(attestation.length + 3);
        for (uint256 i = 0; i < insertAt; ++i) {
            repaired[i] = attestation[i];
        }
        repaired[insertAt] = 0x69; // i
        repaired[insertAt + 1] = 0x63; // c
        repaired[insertAt + 2] = 0x5f; // _
        for (uint256 i = insertAt; i < attestation.length; ++i) {
            repaired[i + 3] = attestation[i];
        }
    }

    function _realAttestationB64() internal pure returns (string memory) {
        return "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";
    }
}
