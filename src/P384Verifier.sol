// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

import {ECDSA384Curve} from "./ECDSA384Curve.sol";
import {ECDSA384Hinted} from "./ECDSA384Hinted.sol";
import {IP384Verifier} from "./IP384Verifier.sol";

contract P384Verifier is IP384Verifier {
    function verifyP384SignatureWithHints(
        bytes memory hash,
        bytes memory signature,
        bytes memory pubKey,
        bytes memory inverseHints
    ) external returns (bool) {
        return ECDSA384Hinted.verifyWithHints(_p384(), hash, signature, pubKey, inverseHints);
    }

    function _p384() internal pure returns (ECDSA384Hinted.Parameters memory) {
        return ECDSA384Hinted.Parameters({
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
