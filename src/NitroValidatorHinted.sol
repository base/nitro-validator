// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

import {IHintedCertManager} from "./IHintedCertManager.sol";
import {IP384Verifier} from "./IP384Verifier.sol";
import {NitroValidatorHintedExternal} from "./NitroValidatorHintedExternal.sol";

/// @notice Deployable hinted Nitro attestation validator.
/// @dev Kept as the canonical hinted name; P384 verification is delegated to `p384Verifier`.
contract NitroValidatorHinted is NitroValidatorHintedExternal {
    constructor(IHintedCertManager certManager_, IP384Verifier p384Verifier_)
        NitroValidatorHintedExternal(certManager_, p384Verifier_)
    {}
}
