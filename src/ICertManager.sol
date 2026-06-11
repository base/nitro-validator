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

    // --- Active (hinted) entrypoints ---

    function owner() external view returns (address);

    function revoker() external view returns (address);

    function revoked(bytes32 certHash) external view returns (bool);

    function verifyCACertWithHints(bytes memory cert, bytes32 parentCertHash, bytes memory signatureHints)
        external
        returns (bytes32);

    function verifyClientCertWithHints(bytes memory cert, bytes32 parentCertHash, bytes memory signatureHints)
        external
        returns (VerifiedCert memory);

    function loadVerified(bytes32 certHash) external view returns (VerifiedCert memory);

    function isRevoked(bytes32 certHash) external view returns (bool);

    function transferOwnership(address newOwner) external;

    function setRevoker(address newRevoker) external;

    function revokeCert(bytes32 certHash) external;

    function revokeCerts(bytes32[] calldata certHashes) external;

    function unrevokeCert(bytes32 certHash) external;

    // --- DEPRECATED: these always revert; use the *WithHints variants above. ---

    /// @dev DEPRECATED — always reverts ("use hinted cert verification").
    function verifyCACert(bytes memory cert, bytes32 parentCertHash) external returns (bytes32);

    /// @dev DEPRECATED — always reverts ("use hinted cert verification").
    function verifyClientCert(bytes memory cert, bytes32 parentCertHash) external returns (VerifiedCert memory);
}
