// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

interface ICertManager {
    struct VerifiedCert {
        bool ca;
        uint64 notAfter;
        int64 maxPathLen;
        bytes32 subjectHash;
        bytes pubKey;
    }

    function verifyCert(bytes memory cert, bool clientCert, bytes32 parentCertHash)
        external
        returns (VerifiedCert memory);

    function verifyCertBundle(bytes memory certificate, bytes[] calldata cabundle)
        external
        returns (VerifiedCert memory);
}
