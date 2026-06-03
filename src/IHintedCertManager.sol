// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

import {ICertManager} from "./ICertManager.sol";

interface IHintedCertManager is ICertManager {
    function verifyCACertWithHints(bytes memory cert, bytes32 parentCertHash, bytes memory signatureHints)
        external
        returns (bytes32);

    function verifyClientCertWithHints(bytes memory cert, bytes32 parentCertHash, bytes memory signatureHints)
        external
        returns (VerifiedCert memory);

    function loadVerified(bytes32 certHash) external view returns (VerifiedCert memory);
}
