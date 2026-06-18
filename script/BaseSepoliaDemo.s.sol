// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Script, console2} from "forge-std/Script.sol";
import {Asn1Decode, LibAsn1Ptr, Asn1Ptr} from "../src/Asn1Decode.sol";
import {CborDecode, CborElement, LibCborElement} from "../src/CborDecode.sol";
import {CertManagerDemo} from "../test/helpers/CertManagerDemo.sol";
import {ICertManager} from "../src/ICertManager.sol";
import {IP384Verifier} from "../src/IP384Verifier.sol";
import {LibBytes} from "../src/LibBytes.sol";
import {NitroValidator} from "../src/NitroValidator.sol";
import {P384Verifier} from "../src/P384Verifier.sol";

contract NitroValidatorScriptParser is NitroValidator {
    constructor() NitroValidator(ICertManager(address(1)), IP384Verifier(address(1))) {}

    function parseAttestation(bytes memory attestationTbs) external pure returns (Ptrs memory) {
        return _parseAttestation(attestationTbs);
    }
}

/// @dev Uses vm.ffi to run the off-chain hint tools; invoke the script with Foundry's `--ffi` flag.
contract BaseSepoliaDemo is Script {
    using Asn1Decode for bytes;
    using CborDecode for bytes;
    using LibAsn1Ptr for Asn1Ptr;
    using LibBytes for bytes;
    using LibCborElement for CborElement;

    uint256 internal constant DEFAULT_DEMO_CERT_EXPIRY_GRACE_SECONDS = 365 days;

    struct Deployment {
        P384Verifier p384Verifier;
        CertManagerDemo certManager;
        NitroValidator validator;
    }

    function run() external {
        uint256 privateKey = vm.envUint("PRIVATE_KEY");
        uint256 graceSeconds = vm.envOr("DEMO_CERT_EXPIRY_GRACE_SECONDS", DEFAULT_DEMO_CERT_EXPIRY_GRACE_SECONDS);

        NitroValidatorScriptParser parser = new NitroValidatorScriptParser();
        bytes memory attestation = _loadAttestation();
        (bytes memory attestationTbs, bytes memory signature) = parser.decodeAttestationTbs(attestation);
        NitroValidator.Ptrs memory ptrs = parser.parseAttestation(attestationTbs);

        console2.log("base sepolia demo attestation bytes", attestation.length);
        console2.log("attestationTbs bytes", attestationTbs.length);
        console2.log("COSE signature bytes", signature.length);
        console2.log("cabundle certs", ptrs.cabundle.length);
        console2.log("demo cert expiry grace seconds", graceSeconds);

        vm.startBroadcast(privateKey);

        Deployment memory deployment;
        deployment.p384Verifier = new P384Verifier();
        deployment.certManager = new CertManagerDemo(deployment.p384Verifier, graceSeconds);
        deployment.validator = new NitroValidator(deployment.certManager, deployment.p384Verifier);

        console2.log("P384Verifier", address(deployment.p384Verifier));
        console2.log("CertManagerDemo", address(deployment.certManager));
        console2.log("NitroValidator", address(deployment.validator));

        ICertManager.VerifiedCert memory leaf = _runColdHintedCache(deployment.certManager, attestationTbs, ptrs);
        bytes memory attestationHints = _attestationHints(attestation, leaf.pubKey);

        deployment.validator.validateAttestationWithHints(attestationTbs, signature, attestationHints);
        console2.log("hinted cold final validation submitted");

        deployment.validator.validateAttestationWithHints(attestationTbs, signature, attestationHints);
        console2.log("hinted warm validation submitted");

        vm.stopBroadcast();
    }

    function _runColdHintedCache(
        CertManagerDemo certManager,
        bytes memory attestationTbs,
        NitroValidator.Ptrs memory ptrs
    ) internal returns (ICertManager.VerifiedCert memory leaf) {
        bytes memory rootCert = attestationTbs.slice(ptrs.cabundle[0]);
        bytes32 parentHash = keccak256(rootCert);
        ICertManager.VerifiedCert memory parent = certManager.loadVerified(parentHash);
        require(parent.pubKey.length > 0, "root not pinned");

        console2.logBytes32(parentHash);

        for (uint256 i = 1; i < ptrs.cabundle.length; ++i) {
            bytes memory caCert = attestationTbs.slice(ptrs.cabundle[i]);
            bytes memory hints = _certHints(caCert, parent.pubKey);
            parentHash = certManager.verifyCACertWithHints(caCert, parentHash, hints);
            parent = certManager.loadVerified(parentHash);
            require(parent.pubKey.length > 0, "CA not cached");
            console2.log("cached non-root CA index", i);
            console2.logBytes32(parentHash);
        }

        bytes memory clientCert = attestationTbs.slice(ptrs.cert);
        bytes memory clientHints = _certHints(clientCert, parent.pubKey);
        leaf = certManager.verifyClientCertWithHints(clientCert, parentHash, clientHints);
        require(leaf.pubKey.length > 0, "leaf not cached");
        console2.log("cached client cert");
        console2.logBytes32(_certCacheKey(clientCert));
    }

    function _certCacheKey(bytes memory certificate) internal pure returns (bytes32) {
        Asn1Ptr root = certificate.root();
        Asn1Ptr tbsCertPtr = certificate.firstChildOf(root);
        return certificate.keccak(tbsCertPtr.header(), tbsCertPtr.totalLength());
    }

    function _loadAttestation() internal returns (bytes memory) {
        if (vm.envOr("USE_BUNDLED_REAL_ATTESTATION", false)) {
            string[] memory fixtureCommand = new string[](3);
            fixtureCommand[0] = "node";
            fixtureCommand[1] = string.concat(vm.projectRoot(), "/tools/nitro_attestation_input.js");
            fixtureCommand[2] = "fixture";
            return vm.ffi(fixtureCommand);
        }

        string memory input = vm.envOr("ATTESTATION_INPUT", string(""));
        require(bytes(input).length != 0, "set ATTESTATION_INPUT or USE_BUNDLED_REAL_ATTESTATION");

        bool repair = vm.envOr("REPAIR_MISSING_PUBLIC_KEY", false);
        string[] memory inputCommand = new string[](repair ? 7 : 5);
        inputCommand[0] = "node";
        inputCommand[1] = string.concat(vm.projectRoot(), "/tools/nitro_attestation_input.js");
        inputCommand[2] = "read";
        inputCommand[3] = "--input";
        inputCommand[4] = input;
        if (repair) {
            inputCommand[5] = "--repair";
            inputCommand[6] = "true";
        }
        return vm.ffi(inputCommand);
    }

    function _certHints(bytes memory cert, bytes memory parentPubKey) internal returns (bytes memory) {
        // Demo-only FFI boundary. A production caller should compute these hints
        // off-chain in its transaction-preparation service and pass them as
        // calldata to verifyCACertWithHints / verifyClientCertWithHints.
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

    function _attestationHints(bytes memory attestation, bytes memory leafPubKey) internal returns (bytes memory) {
        // Demo-only FFI boundary. A production caller should compute these hints
        // off-chain and pass them as calldata to validateAttestationWithHints.
        string[] memory command = new string[](7);
        command[0] = "node";
        command[1] = string.concat(vm.projectRoot(), "/tools/p384_hints.js");
        command[2] = "attestation";
        command[3] = "--attestation";
        command[4] = vm.toString(attestation);
        command[5] = "--pubkey";
        command[6] = vm.toString(leafPubKey);
        return vm.ffi(command);
    }
}
