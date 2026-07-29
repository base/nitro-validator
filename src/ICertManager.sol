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

    /// @notice Return the address that controls ownership, revoker rotation, unrevocation, and the
    ///         root emergency halt.
    /// @return owner_ Current owner address.
    function owner() external view returns (address owner_);

    /// @notice Return the address permitted to revoke non-root certificates.
    /// @return revoker_ Current revoker address.
    function revoker() external view returns (address revoker_);

    /// @notice Return whether a certificate identity or the pinned root hash is revoked.
    /// @param certId Certificate revocation identity or the pinned root hash.
    /// @return isRevoked_ True if `certId` is currently revoked.
    function revoked(bytes32 certId) external view returns (bool isRevoked_);

    /// @notice Verify a CA certificate against its already-cached parent and cache the result.
    /// @dev Idempotent with a cache short-circuit: if `cert` is already verified and unexpired, the
    ///      cached record is returned and `signatureHints` is ignored, but `parentCertHash` must
    ///      match the parent used during cold verification. On a cold cert, `signatureHints` must
    ///      contain the real off-chain inverse hints for the cert signature; they are re-verified
    ///      on-chain, so a wrong hint only reverts. Pass zero only when submitting the pinned root.
    /// @param cert DER-encoded CA certificate to verify and cache.
    /// @param parentCertHash Cache key of the CA that signed `cert`, or zero for the pinned root.
    /// @param signatureHints Packed inverse hints for cold certificate signature verification.
    /// @return certHash Cache key for `cert`: ROOT_CA_CERT_HASH for the pinned root, otherwise
    ///         keccak256(tbsCertificate). Suitable as a parent key for child certificates.
    function verifyCACertWithHints(bytes memory cert, bytes32 parentCertHash, bytes memory signatureHints)
        external
        returns (bytes32 certHash);

    /// @notice Verify a leaf certificate against its already-cached parent and cache the result.
    /// @dev Uses the same cold-verification and cache-short-circuit semantics as
    ///      {verifyCACertWithHints}.
    /// @param cert DER-encoded leaf certificate to verify and cache.
    /// @param parentCertHash Cache key of the CA that signed `cert`.
    /// @param signatureHints Packed inverse hints for cold certificate signature verification.
    /// @return verifiedCert Verified leaf certificate metadata.
    function verifyClientCertWithHints(bytes memory cert, bytes32 parentCertHash, bytes memory signatureHints)
        external
        returns (VerifiedCert memory verifiedCert);

    /// @notice Raw cache read by verification cache key. A returned cert may be expired or revoked.
    /// @param certHash Certificate cache key.
    /// @return cert Raw cached metadata, which may no longer be trusted.
    function loadVerified(bytes32 certHash) external view returns (VerifiedCert memory cert);

    /// @notice Return whether a certificate identity or the pinned root hash is revoked.
    /// @param certId Certificate revocation identity or the pinned root hash.
    /// @return isRevoked_ True if `certId` is currently revoked.
    function isRevoked(bytes32 certId) external view returns (bool isRevoked_);

    /// @notice Compute the stable revocation identity for an X.509 certificate.
    /// @dev Returns `keccak256(issuerHash, serialHash)`, which is invariant to certificate signature
    ///      malleability and DER re-encoding. Reverts on malformed DER.
    /// @param cert DER-encoded X.509 certificate.
    /// @return certId Revocation identity `keccak256(issuerHash, serialHash)`.
    function computeCertId(bytes memory cert) external pure returns (bytes32 certId);

    /// @notice Transfer owner privileges to a new address.
    /// @param newOwner Address to receive owner privileges.
    function transferOwnership(address newOwner) external;

    /// @notice Set the address permitted to revoke non-root certificates.
    /// @param newRevoker Address to receive revoker privileges.
    function setRevoker(address newRevoker) external;

    /// @notice Revoke a certificate identity, or trigger the emergency global halt by revoking the
    ///         pinned root hash.
    /// @param certId Certificate revocation identity or the pinned root hash.
    function revokeCert(bytes32 certId) external;

    /// @notice Revoke multiple certificate identities.
    /// @param certIds Certificate revocation identities to revoke.
    function revokeCerts(bytes32[] calldata certIds) external;

    /// @notice Restore a revoked certificate identity or the pinned root hash.
    /// @param certId Certificate revocation identity or the pinned root hash to restore.
    function unrevokeCert(bytes32 certId) external;

    // --- DEPRECATED: these always revert; use the *WithHints variants above. ---

    /// @notice DEPRECATED: always reverts. Use {verifyCACertWithHints}.
    /// @dev Retained as an ABI-compatibility stub. The fully on-chain P-384 verification path
    ///      became too expensive after Fusaka's EIP-7883 MODEXP repricing and has been removed.
    /// @param cert Unused legacy certificate argument.
    /// @param parentCertHash Unused legacy parent cache key argument.
    /// @return certHash Unreachable legacy return value.
    function verifyCACert(bytes memory cert, bytes32 parentCertHash) external returns (bytes32 certHash);

    /// @notice DEPRECATED: always reverts. Use {verifyClientCertWithHints}.
    /// @dev Retained as an ABI-compatibility stub. The fully on-chain P-384 verification path
    ///      became too expensive after Fusaka's EIP-7883 MODEXP repricing and has been removed.
    /// @param cert Unused legacy certificate argument.
    /// @param parentCertHash Unused legacy parent cache key argument.
    /// @return verifiedCert Unreachable legacy return value.
    function verifyClientCert(bytes memory cert, bytes32 parentCertHash)
        external
        returns (VerifiedCert memory verifiedCert);
}
