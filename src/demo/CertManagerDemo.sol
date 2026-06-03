// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

import {CertManager} from "../CertManager.sol";
import {IP384Verifier} from "../IP384Verifier.sol";

/// @notice Demo-only certificate manager with configurable certificate expiry grace.
/// @dev This exists only to replay expired Nitro fixtures on testnets. Do not use in production or audit target deployments.
contract CertManagerDemo is CertManager {
    uint256 public immutable certificateExpiryGraceSeconds;

    constructor(IP384Verifier p384Verifier_, uint256 certificateExpiryGraceSeconds_) CertManager(p384Verifier_) {
        certificateExpiryGraceSeconds = certificateExpiryGraceSeconds_;
    }

    function _certificateExpired(uint256 notAfter) internal view override returns (bool) {
        if (notAfter >= block.timestamp) {
            return false;
        }
        return block.timestamp - notAfter > certificateExpiryGraceSeconds;
    }
}
