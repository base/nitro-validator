// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

import {CertManagerHintedExternal} from "./CertManagerHintedExternal.sol";
import {IP384Verifier} from "./IP384Verifier.sol";

/// @notice Deployable hinted Nitro certificate manager.
/// @dev Kept as the canonical hinted name; P384 verification is delegated to `p384Verifier`.
contract CertManagerHinted is CertManagerHintedExternal {
    constructor(IP384Verifier p384Verifier_) CertManagerHintedExternal(p384Verifier_) {}
}
