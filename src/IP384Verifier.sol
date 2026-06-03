// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

interface IP384Verifier {
    function verifyP384SignatureWithHints(
        bytes memory hash,
        bytes memory signature,
        bytes memory pubKey,
        bytes memory inverseHints
    ) external returns (bool);
}
