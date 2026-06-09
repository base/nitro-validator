// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

import {ECDSA384Curve} from "./ECDSA384Curve.sol";
import {IP384Verifier} from "./IP384Verifier.sol";
import {ECDSA384} from "./vendor/ECDSA384.sol";

contract P384Verifier is IP384Verifier {
    /// @notice Verify a P-384 ECDSA signature using off-chain-computed modular-inverse hints.
    /// @dev Each hint is re-checked on-chain (`b · inv ≡ 1 mod m`), so a wrong hint can only cause a
    ///      revert, never a false accept; the accept rule is identical to a hint-free verification.
    ///      Scalars are required in range (r, s ∈ [1, n-1]) and the public key must be on-curve, but
    ///      low-S is NOT enforced (see {ECDSA384Curve.CURVE_LOW_S_MAX}): signatures are malleable, so
    ///      callers must not use the signature as a uniqueness key.
    /// @return True iff the signature is valid for `hash` under `pubKey`.
    function verifyP384SignatureWithHints(
        bytes memory hash,
        bytes memory signature,
        bytes memory pubKey,
        bytes memory inverseHints
    ) external view returns (bool) {
        return ECDSA384.verifyWithHints(_p384(), hash, signature, pubKey, inverseHints);
    }

    function _p384() internal pure returns (ECDSA384.Parameters memory) {
        return ECDSA384.Parameters({
            a: ECDSA384Curve.CURVE_A,
            b: ECDSA384Curve.CURVE_B,
            gx: ECDSA384Curve.CURVE_GX,
            gy: ECDSA384Curve.CURVE_GY,
            p: ECDSA384Curve.CURVE_P,
            n: ECDSA384Curve.CURVE_N,
            lowSmax: ECDSA384Curve.CURVE_LOW_S_MAX
        });
    }
}
