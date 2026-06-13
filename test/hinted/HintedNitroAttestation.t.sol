// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test, console} from "forge-std/Test.sol";
import {NitroValidator} from "../../src/NitroValidator.sol";
import {CertManager} from "../../src/CertManager.sol";
import {CertManagerDemo} from "../helpers/CertManagerDemo.sol";
import {ICertManager} from "../../src/ICertManager.sol";
import {CborDecode} from "../../src/CborDecode.sol";
import {P384Verifier} from "../../src/P384Verifier.sol";
import {Sha2Ext} from "../../src/Sha2Ext.sol";
import {P384HintCollector} from "../helpers/HintedNitroTestHelpers.sol";

contract NitroValidatorParseHarness is NitroValidator {
    constructor(CertManager certManager, P384Verifier p384Verifier) NitroValidator(certManager, p384Verifier) {}

    function parseAttestation(bytes memory attestationTbs) external pure returns (Ptrs memory) {
        return _parseAttestation(attestationTbs);
    }
}

contract HintedNitroAttestationTest is Test {
    using CborDecode for bytes;

    uint256 constant HINTED_MODEXP_FLOOR_DELTA = 300; // EIP-7883 floor 500 - EIP-2565 floor 200
    uint256 constant TX_CAP = 16_777_216;
    uint256 constant EIP170_RUNTIME_LIMIT = 24_576;

    CertManager certManager;
    NitroValidator validator;
    NitroValidatorParseHarness parser;
    P384Verifier p384Verifier;
    P384HintCollector hintCollector;

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
        p384Verifier = new P384Verifier();
        certManager = new CertManager(p384Verifier);
        validator = new NitroValidator(certManager, p384Verifier);
        parser = new NitroValidatorParseHarness(certManager, p384Verifier);
        hintCollector = new P384HintCollector();
    }

    function test_HintedAttestationRejectsSurplusHint() public {
        bytes memory attestation = _repairMissingPublicKeyBytes(_decodeBase64(_realAttestationB64()));
        (bytes memory attestationTbs, bytes memory signature) = validator.decodeAttestationTbs(attestation);
        ICertManager.VerifiedCert memory leaf = _cacheCertBundleWithHints(attestationTbs);

        bytes memory hash = Sha2Ext.sha384(attestationTbs, 0, attestationTbs.length);
        bytes memory attestationHints =
            abi.encodePacked(hintCollector.collectVerifyHints(hash, signature, leaf.pubKey), bytes1(0x00));

        vm.expectRevert("unused inverse hints");
        validator.validateAttestationWithHints(attestationTbs, signature, attestationHints);
    }

    function test_HintedCACertRejectsMutatedHint() public {
        bytes memory attestation = _repairMissingPublicKeyBytes(_decodeBase64(_realAttestationB64()));
        (bytes memory attestationTbs,) = validator.decodeAttestationTbs(attestation);
        NitroValidator.Ptrs memory ptrs = parser.parseAttestation(attestationTbs);
        (bytes memory caCert, bytes32 parentHash, bytes memory parentPubKey) = _firstNonRootCA(attestationTbs, ptrs);
        (bytes memory hints,) = hintCollector.collectCertSignatureProfile(caCert, parentPubKey);
        hints[10] = bytes1(uint8(hints[10]) ^ 1);

        vm.expectRevert("bad inverse hint");
        certManager.verifyCACertWithHints(caCert, parentHash, hints);
    }

    function test_HintedCACertRejectsTruncatedHint() public {
        bytes memory attestation = _repairMissingPublicKeyBytes(_decodeBase64(_realAttestationB64()));
        (bytes memory attestationTbs,) = validator.decodeAttestationTbs(attestation);
        NitroValidator.Ptrs memory ptrs = parser.parseAttestation(attestationTbs);
        (bytes memory caCert, bytes32 parentHash, bytes memory parentPubKey) = _firstNonRootCA(attestationTbs, ptrs);
        (bytes memory hints,) = hintCollector.collectCertSignatureProfile(caCert, parentPubKey);
        assembly {
            mstore(hints, sub(mload(hints), 1))
        }

        vm.expectRevert("inverse hint underflow");
        certManager.verifyCACertWithHints(caCert, parentHash, hints);
    }

    function test_HintedCACertRejectsWrongParentHash() public {
        bytes memory attestation = _repairMissingPublicKeyBytes(_decodeBase64(_realAttestationB64()));
        (bytes memory attestationTbs,) = validator.decodeAttestationTbs(attestation);
        NitroValidator.Ptrs memory ptrs = parser.parseAttestation(attestationTbs);
        bytes memory caCert = attestationTbs.slice(ptrs.cabundle[1]);

        vm.expectRevert("parent cert unverified");
        certManager.verifyCACertWithHints(caCert, bytes32(0), "");
    }

    function test_HintedCACertRejectsCachedParentMismatch() public {
        bytes memory attestation = _repairMissingPublicKeyBytes(_decodeBase64(_realAttestationB64()));
        (bytes memory attestationTbs,) = validator.decodeAttestationTbs(attestation);
        NitroValidator.Ptrs memory ptrs = parser.parseAttestation(attestationTbs);

        bytes memory rootCert = attestationTbs.slice(ptrs.cabundle[0]);
        bytes32 rootHash = keccak256(rootCert);
        bytes memory ca1 = attestationTbs.slice(ptrs.cabundle[1]);
        bytes memory ca1Hints = hintCollector.collectCertSignatureHints(ca1, certManager.loadVerified(rootHash).pubKey);
        bytes32 ca1Hash = certManager.verifyCACertWithHints(ca1, rootHash, ca1Hints);

        bytes memory ca2 = attestationTbs.slice(ptrs.cabundle[2]);
        bytes memory ca2Hints = hintCollector.collectCertSignatureHints(ca2, certManager.loadVerified(ca1Hash).pubKey);
        certManager.verifyCACertWithHints(ca2, ca1Hash, ca2Hints);

        vm.expectRevert("parent cert mismatch");
        certManager.verifyCACertWithHints(ca2, rootHash, "");
    }

    function test_HintedClientCertRejectsCachedParentMismatch() public {
        bytes memory attestation = _repairMissingPublicKeyBytes(_decodeBase64(_realAttestationB64()));
        (bytes memory attestationTbs,) = validator.decodeAttestationTbs(attestation);
        NitroValidator.Ptrs memory ptrs = parser.parseAttestation(attestationTbs);
        _cacheCertBundleWithHints(attestationTbs);

        bytes memory rootCert = attestationTbs.slice(ptrs.cabundle[0]);
        bytes memory clientCert = attestationTbs.slice(ptrs.cert);

        vm.expectRevert("parent cert mismatch");
        certManager.verifyClientCertWithHints(clientCert, keccak256(rootCert), "");
    }

    function test_CertManagerRevocationRoles() public {
        assertEq(certManager.owner(), address(this));
        assertEq(certManager.revoker(), address(this));

        bytes32 certHash = keccak256("cert");
        certManager.revokeCert(certHash);
        assertTrue(certManager.revoked(certHash));
        assertTrue(certManager.isRevoked(certHash));

        address newRevoker = address(0xBEEF);
        vm.prank(address(0xCAFE));
        vm.expectRevert("not owner");
        certManager.setRevoker(newRevoker);

        vm.expectRevert("invalid revoker");
        certManager.setRevoker(address(0));

        certManager.setRevoker(newRevoker);
        assertEq(certManager.revoker(), newRevoker);

        bytes32 otherCertHash = keccak256("other cert");
        vm.prank(address(0xCAFE));
        vm.expectRevert("not revoker");
        certManager.revokeCert(otherCertHash);

        vm.prank(newRevoker);
        certManager.revokeCert(otherCertHash);
        assertTrue(certManager.revoked(otherCertHash));

        vm.prank(newRevoker);
        vm.expectRevert("not owner");
        certManager.unrevokeCert(otherCertHash);

        certManager.unrevokeCert(otherCertHash);
        assertFalse(certManager.revoked(otherCertHash));

        vm.expectRevert("invalid owner");
        certManager.transferOwnership(address(0));

        address newOwner = address(0xA11CE);
        vm.prank(address(0xCAFE));
        vm.expectRevert("not owner");
        certManager.transferOwnership(newOwner);

        certManager.transferOwnership(newOwner);
        assertEq(certManager.owner(), newOwner);

        vm.expectRevert("not owner");
        certManager.setRevoker(address(0x1234));

        vm.prank(newOwner);
        certManager.setRevoker(address(0x1234));
        assertEq(certManager.revoker(), address(0x1234));
    }

    function test_CertManagerRevokerCanBatchRevoke() public {
        address newRevoker = address(0xBEEF);
        certManager.setRevoker(newRevoker);

        bytes32[] memory certHashes = new bytes32[](2);
        certHashes[0] = keccak256("cert 1");
        certHashes[1] = keccak256("cert 2");

        vm.prank(newRevoker);
        certManager.revokeCerts(certHashes);

        assertTrue(certManager.revoked(certHashes[0]));
        assertTrue(certManager.revoked(certHashes[1]));
    }

    function test_CertManagerRootRevocationRequiresOwner() public {
        address newRevoker = address(0xBEEF);
        certManager.setRevoker(newRevoker);
        bytes32 rootHash = certManager.ROOT_CA_CERT_HASH();

        vm.prank(newRevoker);
        vm.expectRevert("not owner");
        certManager.revokeCert(rootHash);
        assertFalse(certManager.revoked(rootHash));

        bytes32[] memory certHashes = new bytes32[](2);
        certHashes[0] = keccak256("non-root cert");
        certHashes[1] = rootHash;

        vm.prank(newRevoker);
        vm.expectRevert("not owner");
        certManager.revokeCerts(certHashes);
        assertFalse(certManager.revoked(certHashes[0]));
        assertFalse(certManager.revoked(rootHash));

        certManager.revokeCert(rootHash);
        assertTrue(certManager.revoked(rootHash));
    }

    function test_HintedCACertRejectsTrailingBytes() public {
        bytes memory attestation = _repairMissingPublicKeyBytes(_decodeBase64(_realAttestationB64()));
        (bytes memory attestationTbs,) = validator.decodeAttestationTbs(attestation);
        NitroValidator.Ptrs memory ptrs = parser.parseAttestation(attestationTbs);
        (bytes memory caCert, bytes32 parentHash,) = _firstNonRootCA(attestationTbs, ptrs);

        vm.expectRevert("invalid cert length");
        certManager.verifyCACertWithHints(abi.encodePacked(caCert, bytes1(0x00)), parentHash, "");
    }

    function test_HintedCACertRejectsTrailingFieldInsideCertificateSequence() public {
        bytes memory attestation = _repairMissingPublicKeyBytes(_decodeBase64(_realAttestationB64()));
        (bytes memory attestationTbs,) = validator.decodeAttestationTbs(attestation);
        NitroValidator.Ptrs memory ptrs = parser.parseAttestation(attestationTbs);
        (bytes memory caCert, bytes32 parentHash,) = _firstNonRootCA(attestationTbs, ptrs);

        vm.expectRevert("trailing cert fields");
        certManager.verifyCACertWithHints(_appendInsideOuterSequence(caCert, bytes1(0x00)), parentHash, "");
    }

    function test_HintedCACertRejectsRevokedColdCert() public {
        bytes memory attestation = _repairMissingPublicKeyBytes(_decodeBase64(_realAttestationB64()));
        (bytes memory attestationTbs,) = validator.decodeAttestationTbs(attestation);
        NitroValidator.Ptrs memory ptrs = parser.parseAttestation(attestationTbs);
        (bytes memory caCert, bytes32 parentHash, bytes memory parentPubKey) = _firstNonRootCA(attestationTbs, ptrs);
        bytes memory hints = hintCollector.collectCertSignatureHints(caCert, parentPubKey);

        certManager.revokeCert(keccak256(caCert));

        vm.expectRevert("cert revoked");
        certManager.verifyCACertWithHints(caCert, parentHash, hints);
    }

    function test_HintedCACertRejectsRevokedCachedCert() public {
        bytes memory attestation = _repairMissingPublicKeyBytes(_decodeBase64(_realAttestationB64()));
        (bytes memory attestationTbs,) = validator.decodeAttestationTbs(attestation);
        NitroValidator.Ptrs memory ptrs = parser.parseAttestation(attestationTbs);
        (bytes memory caCert, bytes32 parentHash, bytes memory parentPubKey) = _firstNonRootCA(attestationTbs, ptrs);
        bytes memory hints = hintCollector.collectCertSignatureHints(caCert, parentPubKey);
        bytes32 caHash = certManager.verifyCACertWithHints(caCert, parentHash, hints);

        certManager.revokeCert(caHash);

        vm.expectRevert("cert revoked");
        certManager.verifyCACertWithHints(caCert, parentHash, "");
    }

    function test_HintedCAChildRejectsRevokedParent() public {
        bytes memory attestation = _repairMissingPublicKeyBytes(_decodeBase64(_realAttestationB64()));
        (bytes memory attestationTbs,) = validator.decodeAttestationTbs(attestation);
        NitroValidator.Ptrs memory ptrs = parser.parseAttestation(attestationTbs);

        bytes memory rootCert = attestationTbs.slice(ptrs.cabundle[0]);
        bytes32 rootHash = keccak256(rootCert);
        bytes memory ca1 = attestationTbs.slice(ptrs.cabundle[1]);
        bytes memory ca1Hints = hintCollector.collectCertSignatureHints(ca1, certManager.loadVerified(rootHash).pubKey);
        bytes32 ca1Hash = certManager.verifyCACertWithHints(ca1, rootHash, ca1Hints);

        bytes memory ca2 = attestationTbs.slice(ptrs.cabundle[2]);
        certManager.revokeCert(ca1Hash);

        vm.expectRevert("cert revoked");
        certManager.verifyCACertWithHints(ca2, ca1Hash, "");
    }

    function test_HintedCAChildRejectsRevokedAncestor() public {
        bytes memory attestation = _repairMissingPublicKeyBytes(_decodeBase64(_realAttestationB64()));
        (bytes memory attestationTbs,) = validator.decodeAttestationTbs(attestation);
        NitroValidator.Ptrs memory ptrs = parser.parseAttestation(attestationTbs);

        bytes memory rootCert = attestationTbs.slice(ptrs.cabundle[0]);
        bytes32 rootHash = keccak256(rootCert);
        bytes memory ca1 = attestationTbs.slice(ptrs.cabundle[1]);
        bytes memory ca1Hints = hintCollector.collectCertSignatureHints(ca1, certManager.loadVerified(rootHash).pubKey);
        bytes32 ca1Hash = certManager.verifyCACertWithHints(ca1, rootHash, ca1Hints);
        bytes memory ca2 = attestationTbs.slice(ptrs.cabundle[2]);
        bytes memory ca2Hints = hintCollector.collectCertSignatureHints(ca2, certManager.loadVerified(ca1Hash).pubKey);

        certManager.revokeCert(rootHash);

        vm.expectRevert("cert revoked");
        certManager.verifyCACertWithHints(ca2, ca1Hash, ca2Hints);
    }

    function test_HintedCachedCertRejectsRevokedAncestor() public {
        bytes memory attestation = _repairMissingPublicKeyBytes(_decodeBase64(_realAttestationB64()));
        (bytes memory attestationTbs,) = validator.decodeAttestationTbs(attestation);
        NitroValidator.Ptrs memory ptrs = parser.parseAttestation(attestationTbs);

        bytes memory rootCert = attestationTbs.slice(ptrs.cabundle[0]);
        bytes32 rootHash = keccak256(rootCert);
        bytes memory ca1 = attestationTbs.slice(ptrs.cabundle[1]);
        bytes memory ca1Hints = hintCollector.collectCertSignatureHints(ca1, certManager.loadVerified(rootHash).pubKey);
        bytes32 ca1Hash = certManager.verifyCACertWithHints(ca1, rootHash, ca1Hints);
        bytes memory ca2 = attestationTbs.slice(ptrs.cabundle[2]);
        bytes memory ca2Hints = hintCollector.collectCertSignatureHints(ca2, certManager.loadVerified(ca1Hash).pubKey);
        certManager.verifyCACertWithHints(ca2, ca1Hash, ca2Hints);

        certManager.revokeCert(rootHash);

        vm.expectRevert("cert revoked");
        certManager.verifyCACertWithHints(ca2, ca1Hash, "");
    }

    function test_HintedValidationRejectsRevokedLeaf() public {
        bytes memory attestation = _repairMissingPublicKeyBytes(_decodeBase64(_realAttestationB64()));
        (bytes memory attestationTbs, bytes memory signature) = validator.decodeAttestationTbs(attestation);
        NitroValidator.Ptrs memory ptrs = parser.parseAttestation(attestationTbs);
        ICertManager.VerifiedCert memory leaf = _cacheCertBundleWithHints(attestationTbs);
        bytes memory hash = Sha2Ext.sha384(attestationTbs, 0, attestationTbs.length);
        bytes memory attestationHints = hintCollector.collectVerifyHints(hash, signature, leaf.pubKey);

        certManager.revokeCert(keccak256(attestationTbs.slice(ptrs.cert)));

        vm.expectRevert("cert revoked");
        validator.validateAttestationWithHints(attestationTbs, signature, attestationHints);
    }

    function test_HintedValidationRejectsRevokedRoot() public {
        bytes memory attestation = _repairMissingPublicKeyBytes(_decodeBase64(_realAttestationB64()));
        (bytes memory attestationTbs, bytes memory signature) = validator.decodeAttestationTbs(attestation);
        ICertManager.VerifiedCert memory leaf = _cacheCertBundleWithHints(attestationTbs);
        bytes memory hash = Sha2Ext.sha384(attestationTbs, 0, attestationTbs.length);
        bytes memory attestationHints = hintCollector.collectVerifyHints(hash, signature, leaf.pubKey);

        certManager.revokeCert(certManager.ROOT_CA_CERT_HASH());

        vm.expectRevert("cert revoked");
        validator.validateAttestationWithHints(attestationTbs, signature, attestationHints);
    }

    function test_HintedCachedCertCanVerifyAfterOwnerUnrevokes() public {
        bytes memory attestation = _repairMissingPublicKeyBytes(_decodeBase64(_realAttestationB64()));
        (bytes memory attestationTbs,) = validator.decodeAttestationTbs(attestation);
        NitroValidator.Ptrs memory ptrs = parser.parseAttestation(attestationTbs);
        (bytes memory caCert, bytes32 parentHash, bytes memory parentPubKey) = _firstNonRootCA(attestationTbs, ptrs);
        bytes memory hints = hintCollector.collectCertSignatureHints(caCert, parentPubKey);
        bytes32 caHash = certManager.verifyCACertWithHints(caCert, parentHash, hints);

        certManager.revokeCert(caHash);
        vm.expectRevert("cert revoked");
        certManager.verifyCACertWithHints(caCert, parentHash, "");

        certManager.unrevokeCert(caHash);
        assertEq(certManager.verifyCACertWithHints(caCert, parentHash, ""), caHash);
    }

    function test_HintedCACertRejectsExpiredCachedCert() public {
        bytes memory attestation = _repairMissingPublicKeyBytes(_decodeBase64(_realAttestationB64()));
        (bytes memory attestationTbs,) = validator.decodeAttestationTbs(attestation);
        NitroValidator.Ptrs memory ptrs = parser.parseAttestation(attestationTbs);
        (bytes memory caCert, bytes32 parentHash, bytes memory parentPubKey) = _firstNonRootCA(attestationTbs, ptrs);
        bytes memory hints = hintCollector.collectCertSignatureHints(caCert, parentPubKey);
        certManager.verifyCACertWithHints(caCert, parentHash, hints);

        vm.warp(1768953600); // 2026-01-21T00:00:00Z, after this fixture's first non-root CA expiry.

        vm.expectRevert("cert expired");
        certManager.verifyCACertWithHints(caCert, parentHash, "");
    }

    function test_HintedCACertRejectsCachedRoleMismatch() public {
        bytes memory attestation = _repairMissingPublicKeyBytes(_decodeBase64(_realAttestationB64()));
        (bytes memory attestationTbs,) = validator.decodeAttestationTbs(attestation);
        NitroValidator.Ptrs memory ptrs = parser.parseAttestation(attestationTbs);
        (bytes memory caCert, bytes32 parentHash, bytes memory parentPubKey) = _firstNonRootCA(attestationTbs, ptrs);
        bytes memory hints = hintCollector.collectCertSignatureHints(caCert, parentPubKey);
        certManager.verifyCACertWithHints(caCert, parentHash, hints);

        vm.expectRevert("cert is not a CA");
        certManager.verifyClientCertWithHints(caCert, parentHash, "");
    }

    function test_HintedValidationRequiresWarmCache() public {
        bytes memory attestation = _repairMissingPublicKeyBytes(_decodeBase64(_realAttestationB64()));
        (bytes memory attestationTbs, bytes memory signature) = validator.decodeAttestationTbs(attestation);
        CertManager freshCertManager = new CertManager(p384Verifier);
        NitroValidator freshValidator = new NitroValidator(freshCertManager, p384Verifier);

        vm.expectRevert("inverse hint underflow");
        freshValidator.validateAttestationWithHints(attestationTbs, signature, "");
    }

    function test_HintedValidationRejectsInvalidFinalSignature() public {
        bytes memory attestation = _repairMissingPublicKeyBytes(_decodeBase64(_realAttestationB64()));
        (bytes memory attestationTbs, bytes memory signature) = validator.decodeAttestationTbs(attestation);
        ICertManager.VerifiedCert memory leaf = _cacheCertBundleWithHints(attestationTbs);
        bytes memory hash = Sha2Ext.sha384(attestationTbs, 0, attestationTbs.length);
        bytes memory attestationHints = hintCollector.collectVerifyHints(hash, signature, leaf.pubKey);
        signature[0] = bytes1(uint8(signature[0]) ^ 1);

        vm.expectRevert();
        validator.validateAttestationWithHints(attestationTbs, signature, attestationHints);
    }

    function test_DeployableContractsFitEIP170() public view {
        console.log("==== DEPLOYABLE CONTRACT SIZES ====");
        console.log("P384Verifier runtime bytes        :", address(p384Verifier).code.length);
        console.log("CertManager runtime bytes         :", address(certManager).code.length);
        console.log("NitroValidator runtime bytes      :", address(validator).code.length);
        assertLe(address(p384Verifier).code.length, EIP170_RUNTIME_LIMIT);
        assertLe(address(certManager).code.length, EIP170_RUNTIME_LIMIT);
        assertLe(address(validator).code.length, EIP170_RUNTIME_LIMIT);
    }

    function test_DeployableCertManagerDisablesUnhintedEntrypoints() public {
        vm.expectRevert("use hinted cert verification");
        certManager.verifyCACert("", bytes32(0));

        vm.expectRevert("use hinted cert verification");
        certManager.verifyClientCert("", bytes32(0));

        vm.expectRevert("use hinted attestation verification");
        validator.validateAttestation("", "");
    }

    // Expiry is checked in _verifyValidity during cold parsing, before the signature is verified,
    // so an expired cert is rejected on its FIRST (uncached) verification even with empty hints.
    // Distinct from test_HintedCACertRejectsExpiredCachedCert, which exercises the cached path
    // ("cert expired").
    function test_HintedCACertRejectsExpiredCertOnFirstVerification() public {
        bytes memory attestation = _repairMissingPublicKeyBytes(_decodeBase64(_realAttestationB64()));
        (bytes memory attestationTbs,) = validator.decodeAttestationTbs(attestation);
        NitroValidator.Ptrs memory ptrs = parser.parseAttestation(attestationTbs);
        (bytes memory caCert, bytes32 parentHash,) = _firstNonRootCA(attestationTbs, ptrs);

        vm.warp(1768953600); // 2026-01-21T00:00:00Z, past this fixture's first non-root CA expiry.

        // caCert has never been verified, so this is the cold path; the root parent stays valid.
        vm.expectRevert("certificate not valid anymore");
        certManager.verifyCACertWithHints(caCert, parentHash, "");
    }

    // _certificateExpired is `notAfter < block.timestamp`, so a cert is still valid at the exact
    // notAfter second and expired one second later. Verify both sides of that boundary on a cold
    // (uncached) cert via fresh CertManager instances.
    function test_CertValidityBoundaryAtNotAfter() public {
        bytes memory attestation = _repairMissingPublicKeyBytes(_decodeBase64(_realAttestationB64()));
        (bytes memory attestationTbs,) = validator.decodeAttestationTbs(attestation);
        NitroValidator.Ptrs memory ptrs = parser.parseAttestation(attestationTbs);
        (bytes memory caCert, bytes32 parentHash, bytes memory parentPubKey) = _firstNonRootCA(attestationTbs, ptrs);

        // Learn caCert's notAfter by caching it on the shared manager at the (valid) setUp time.
        bytes memory hints = hintCollector.collectCertSignatureHints(caCert, parentPubKey);
        bytes32 certHash = certManager.verifyCACertWithHints(caCert, parentHash, hints);
        uint64 notAfter = certManager.loadVerified(certHash).notAfter;

        // Exactly at notAfter: cold verification on a fresh manager succeeds (cert still valid).
        CertManager atBoundary = new CertManager(p384Verifier);
        vm.warp(notAfter);
        atBoundary.verifyCACertWithHints(caCert, parentHash, hints);
        assertGt(atBoundary.loadVerified(certHash).pubKey.length, 0, "cert valid at notAfter");

        // One second later: cold verification on a fresh manager is rejected as expired.
        CertManager pastBoundary = new CertManager(p384Verifier);
        vm.warp(uint256(notAfter) + 1);
        vm.expectRevert("certificate not valid anymore");
        pastBoundary.verifyCACertWithHints(caCert, parentHash, hints);
    }

    // ECDSA384 rejects out-of-range scalars (r==0, r>=n, s==0, s>lowSmax) before consuming any
    // hints, so the verifier returns false (no hints needed). Guards against malleable/degenerate
    // signatures independent of the cert-chain plumbing.
    function test_P384VerifierRejectsOutOfRangeScalars() public view {
        bytes memory hash = new bytes(48); // contents irrelevant: rejected before hashing/curve math
        bytes memory pubKey = new bytes(96); // not reached: bounds are checked before _isOnCurve

        bytes memory zero48 = new bytes(48);
        bytes memory one48 = new bytes(48);
        one48[47] = 0x01;
        bytes memory max48 = new bytes(48); // > n and > lowSmax
        for (uint256 i = 0; i < 48; i++) {
            max48[i] = 0xff;
        }

        // r == 0
        assertFalse(p384Verifier.verifyP384SignatureWithHints(hash, abi.encodePacked(zero48, one48), pubKey, ""));
        // r >= n
        assertFalse(p384Verifier.verifyP384SignatureWithHints(hash, abi.encodePacked(max48, one48), pubKey, ""));
        // s == 0
        assertFalse(p384Verifier.verifyP384SignatureWithHints(hash, abi.encodePacked(one48, zero48), pubKey, ""));
        // s > lowSmax
        assertFalse(p384Verifier.verifyP384SignatureWithHints(hash, abi.encodePacked(one48, max48), pubKey, ""));
    }

    function test_P384VerifierRejectsNonCanonicalPubKeyCoordinate() public view {
        bytes memory hash = new bytes(48);
        bytes memory one48 = new bytes(48);
        one48[47] = 0x01;

        // x = p + 2 fits in 48 bytes and reduces to a valid P-384 x-coordinate modulo p.
        bytes memory nonCanonicalX =
            hex"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000001";
        bytes memory y =
            hex"8cdeadbbd04911a3c1931e26df3fa6439dca9c7eb286fbd46fc319f0e2bb780232baf57825fc0c1912ada2fefe84024c";

        assertFalse(
            p384Verifier.verifyP384SignatureWithHints(
                hash, abi.encodePacked(one48, one48), abi.encodePacked(nonCanonicalX, y), ""
            )
        );
    }

    function test_OffchainWitnessGeneratorMatchesSolidityCollector() public {
        if (!vm.envOr("NITRO_RUN_FFI", false)) {
            console.log("==== OFFCHAIN WITNESS GENERATOR ====");
            console.log("skipped; rerun with NITRO_RUN_FFI=true forge test --ffi --match-test test_Offchain");
            return;
        }

        bytes memory attestation = _repairMissingPublicKeyBytes(_decodeBase64(_realAttestationB64()));
        (bytes memory attestationTbs, bytes memory signature) = validator.decodeAttestationTbs(attestation);
        NitroValidator.Ptrs memory ptrs = parser.parseAttestation(attestationTbs);

        bytes memory rootCert = attestationTbs.slice(ptrs.cabundle[0]);
        bytes32 parentHash = keccak256(rootCert);
        bytes memory parentPubKey = certManager.loadVerified(parentHash).pubKey;
        uint256 signaturesChecked;

        for (uint256 i = 1; i < ptrs.cabundle.length; ++i) {
            bytes memory caCert = attestationTbs.slice(ptrs.cabundle[i]);
            bytes memory expectedHints = hintCollector.collectCertSignatureHints(caCert, parentPubKey);
            bytes memory offchainHints = _ffiCertSignatureHints(caCert, parentPubKey);
            assertEq(offchainHints, expectedHints, "offchain CA cert hints mismatch");

            parentHash = certManager.verifyCACertWithHints(caCert, parentHash, offchainHints);
            parentPubKey = certManager.loadVerified(parentHash).pubKey;
            signaturesChecked += 1;
        }

        bytes memory clientCert = attestationTbs.slice(ptrs.cert);
        bytes memory expectedClientHints = hintCollector.collectCertSignatureHints(clientCert, parentPubKey);
        bytes memory offchainClientHints = _ffiCertSignatureHints(clientCert, parentPubKey);
        assertEq(offchainClientHints, expectedClientHints, "offchain client cert hints mismatch");
        ICertManager.VerifiedCert memory leaf =
            certManager.verifyClientCertWithHints(clientCert, parentHash, offchainClientHints);
        signaturesChecked += 1;

        _assertOffchainAttestationHints(attestation, attestationTbs, signature, leaf.pubKey);
        signaturesChecked += 1;

        console.log("==== OFFCHAIN WITNESS GENERATOR ====");
        console.log("signatures checked                :", signaturesChecked);
    }

    function test_OffchainWitnessGeneratorRejectsMalformedInputs() public {
        if (!vm.envOr("NITRO_RUN_FFI", false)) {
            console.log("==== OFFCHAIN WITNESS NEGATIVES ====");
            console.log("skipped; rerun with NITRO_RUN_FFI=true forge test --ffi --match-test test_Offchain");
            return;
        }

        bytes memory attestation = _repairMissingPublicKeyBytes(_decodeBase64(_realAttestationB64()));
        (bytes memory attestationTbs, bytes memory signature) = validator.decodeAttestationTbs(attestation);
        ICertManager.VerifiedCert memory leaf = _cacheCertBundleWithHints(attestationTbs);
        bytes memory hash = Sha2Ext.sha384(attestationTbs, 0, attestationTbs.length);

        _assertFfiVerifyRejects(hash, _mutateAt(signature, 0), leaf.pubKey);
        _assertFfiVerifyRejects(hash, signature, _mutateAt(leaf.pubKey, 0));
        _assertFfiCertRejects(hex"00", leaf.pubKey);
        _assertFfiAttestationRejects(hex"00", leaf.pubKey);

        console.log("==== OFFCHAIN WITNESS NEGATIVES ====");
        console.log("malformed CLI cases checked       :", uint256(4));
    }

    function test_DemoExpiryGraceAllowsOldFixtureAtBaseSepoliaTime() public {
        vm.warp(1780458582); // 2026-06-03T03:49:42Z, matching the Base Sepolia demo.

        CertManagerDemo demoCertManager = new CertManagerDemo(p384Verifier, 365 days);
        NitroValidator demoValidator = new NitroValidator(demoCertManager, p384Verifier);

        bytes memory attestation = _repairMissingPublicKeyBytes(_decodeBase64(_realAttestationB64()));
        (bytes memory attestationTbs, bytes memory signature) = validator.decodeAttestationTbs(attestation);
        NitroValidator.Ptrs memory ptrs = parser.parseAttestation(attestationTbs);

        bytes memory rootCert = attestationTbs.slice(ptrs.cabundle[0]);
        bytes32 parentHash = keccak256(rootCert);
        ICertManager.VerifiedCert memory parent = demoCertManager.loadVerified(parentHash);
        assertTrue(parent.pubKey.length > 0, "root must be pinned");

        for (uint256 i = 1; i < ptrs.cabundle.length; ++i) {
            bytes memory caCert = attestationTbs.slice(ptrs.cabundle[i]);
            bytes memory hints = hintCollector.collectCertSignatureHints(caCert, parent.pubKey);
            parentHash = demoCertManager.verifyCACertWithHints(caCert, parentHash, hints);
            parent = demoCertManager.loadVerified(parentHash);
        }

        bytes memory clientCert = attestationTbs.slice(ptrs.cert);
        bytes memory clientHints = hintCollector.collectCertSignatureHints(clientCert, parent.pubKey);
        ICertManager.VerifiedCert memory leaf =
            demoCertManager.verifyClientCertWithHints(clientCert, parentHash, clientHints);

        bytes memory attestationHints = hintCollector.collectVerifyHints(
            Sha2Ext.sha384(attestationTbs, 0, attestationTbs.length), signature, leaf.pubKey
        );
        demoValidator.validateAttestationWithHints(attestationTbs, signature, attestationHints);

        console.log("==== DEMO EXPIRY GRACE ====");
        console.log("base sepolia timestamp           :", block.timestamp);
        console.log("demo expiry grace seconds        :", uint256(365 days));
    }

    function test_FullColdAndWarmHintedSequence() public {
        bytes memory attestation = _repairMissingPublicKeyBytes(_decodeBase64(_realAttestationB64()));
        (bytes memory attestationTbs, bytes memory signature) = validator.decodeAttestationTbs(attestation);
        NitroValidator.Ptrs memory ptrs = parser.parseAttestation(attestationTbs);

        console.log("==== FULL COLD + WARM HINTED SEQUENCE ====");
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
        parentPubKey = certManager.loadVerified(parentHash).pubKey;
    }

    function _runColdCertCacheSequence(bytes memory attestationTbs, NitroValidator.Ptrs memory ptrs)
        internal
        returns (SequenceSummary memory summary)
    {
        bytes memory rootCert = attestationTbs.slice(ptrs.cabundle[0]);
        bytes32 parentHash = keccak256(rootCert);
        ICertManager.VerifiedCert memory parent = certManager.loadVerified(parentHash);
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
            parentHash = certManager.verifyCACertWithHints(caCert, parentHash, hints);
            uint256 currentGas = g0 - gasleft();
            parent = certManager.loadVerified(parentHash);
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
        summary.leaf = certManager.verifyClientCertWithHints(clientCert, parentHash, clientHints);
        uint256 clientCurrentGas = g0 - gasleft();

        bytes32 leafHash = keccak256(clientCert);
        ICertManager.VerifiedCert memory cachedLeaf = certManager.loadVerified(leafHash);
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
        validator.validateAttestationWithHints(attestationTbs, signature, attestationHints);
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
                parentPubKey = certManager.loadVerified(parentHash).pubKey;
                hints = hintCollector.collectCertSignatureHints(caCert, parentPubKey);
            }
            parentHash = certManager.verifyCACertWithHints(caCert, parentHash, hints);
        }

        bytes memory clientCert = attestationTbs.slice(ptrs.cert);
        parentPubKey = certManager.loadVerified(parentHash).pubKey;
        bytes memory clientHints = hintCollector.collectCertSignatureHints(clientCert, parentPubKey);
        leaf = certManager.verifyClientCertWithHints(clientCert, parentHash, clientHints);
    }

    function _ffiCertSignatureHints(bytes memory cert, bytes memory parentPubKey) internal returns (bytes memory) {
        string[] memory command = new string[](7);
        command[0] = "node";
        command[1] = string.concat(vm.projectRoot(), "/tools/p384_hints.js");
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
        command[1] = string.concat(vm.projectRoot(), "/tools/p384_hints.js");
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

        validator.validateAttestationWithHints(attestationTbs, signature, offchainHints);
        console.log("final attestation hint bytes      :", offchainHints.length);
    }

    function _ffiAttestationHints(bytes memory attestation, bytes memory pubKey) internal returns (bytes memory) {
        string[] memory command = new string[](7);
        command[0] = "node";
        command[1] = string.concat(vm.projectRoot(), "/tools/p384_hints.js");
        command[2] = "attestation";
        command[3] = "--attestation";
        command[4] = vm.toString(attestation);
        command[5] = "--pubkey";
        command[6] = vm.toString(pubKey);
        return vm.ffi(command);
    }

    function _assertFfiVerifyRejects(bytes memory hash, bytes memory signature, bytes memory pubKey) internal {
        vm.expectRevert();
        this.ffiVerifyHintsForTest(hash, signature, pubKey);
    }

    function _assertFfiCertRejects(bytes memory cert, bytes memory pubKey) internal {
        vm.expectRevert();
        this.ffiCertSignatureHintsForTest(cert, pubKey);
    }

    function _assertFfiAttestationRejects(bytes memory attestation, bytes memory pubKey) internal {
        vm.expectRevert();
        this.ffiAttestationHintsForTest(attestation, pubKey);
    }

    function ffiVerifyHintsForTest(bytes memory hash, bytes memory signature, bytes memory pubKey)
        external
        returns (bytes memory)
    {
        return _ffiVerifyHints(hash, signature, pubKey);
    }

    function ffiCertSignatureHintsForTest(bytes memory cert, bytes memory pubKey) external returns (bytes memory) {
        return _ffiCertSignatureHints(cert, pubKey);
    }

    function ffiAttestationHintsForTest(bytes memory attestation, bytes memory pubKey) external returns (bytes memory) {
        return _ffiAttestationHints(attestation, pubKey);
    }

    function _mutateAt(bytes memory input, uint256 index) internal pure returns (bytes memory output) {
        output = new bytes(input.length);
        for (uint256 i = 0; i < input.length; ++i) {
            output[i] = input[i];
        }
        output[index] = bytes1(uint8(output[index]) ^ 1);
    }

    function _appendInsideOuterSequence(bytes memory der, bytes1 value) internal pure returns (bytes memory output) {
        require(der.length >= 4 && der[0] == 0x30 && der[1] == 0x82, "test: expected long sequence");
        uint256 length = uint256(uint8(der[2])) << 8 | uint8(der[3]);
        require(length + 4 == der.length, "test: unexpected sequence length");
        length += 1;

        output = abi.encodePacked(der, value);
        output[2] = bytes1(uint8(length >> 8));
        output[3] = bytes1(uint8(length));
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
