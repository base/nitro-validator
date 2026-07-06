// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

import {Sha2Ext} from "./Sha2Ext.sol";
import {Asn1Decode, Asn1Ptr, LibAsn1Ptr} from "./Asn1Decode.sol";
import {LibBytes} from "./LibBytes.sol";
import {ICertManager} from "./ICertManager.sol";
import {IP384Verifier} from "./IP384Verifier.sol";

// adapted from https://github.com/marlinprotocol/NitroProver/blob/f1d368d1f172ad3a55cd2aaaa98ad6a6e7dcde9d/src/CertManager.sol

// Manages a mapping of verified certificates and their metadata.
// The root of trust is the AWS Nitro root cert.
// Certificate revocation is applied by an authorized revoker that tracks AWS CRLs off-chain.
contract CertManager is ICertManager {
    using Asn1Decode for bytes;
    using LibAsn1Ptr for Asn1Ptr;
    using LibBytes for bytes;

    error InvalidExtension();
    error InvalidBasicConstraints();
    error InvalidSubjectPublicKey();
    error UnsupportedCriticalExtension();
    error NotOwner();
    error NotRevoker();
    error IncompleteCertChain();
    error DeprecatedEntrypoint();
    error InvalidOwner();
    error InvalidRevoker();

    event CertVerified(bytes32 indexed certHash);
    event CertRevoked(bytes32 indexed certHash, address indexed account);
    event CertUnrevoked(bytes32 indexed certHash, address indexed account);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event RevokerUpdated(address indexed previousRevoker, address indexed newRevoker);

    // root CA certificate constants (don't store it to reduce contract size)
    bytes32 public constant ROOT_CA_CERT_HASH = 0x311d96fcd5c5e0ccf72ef548e2ea7d4c0cd53ad7c4cc49e67471aed41d61f185;
    uint64 public constant ROOT_CA_CERT_NOT_AFTER = 2519044085;
    int64 public constant ROOT_CA_CERT_MAX_PATH_LEN = -1;
    bytes32 public constant ROOT_CA_CERT_SUBJECT_HASH =
        0x3c3e2e5f1dd14dee5db88341ba71521e939afdb7881aa24c9f1e1c007a2fa8b6;
    bytes public constant ROOT_CA_CERT_PUB_KEY =
        hex"fc0254eba608c1f36870e29ada90be46383292736e894bfff672d989444b5051e534a4b1f6dbe3c0bc581a32b7b176070ede12d69a3fea211b66e752cf7dd1dd095f6f1370f4170843d9dc100121e4cf63012809664487c9796284304dc53ff4";

    // OID 1.2.840.10045.4.3.3 represents {iso(1) member-body(2) us(840) ansi-x962(10045) signatures(4) ecdsa-with-SHA2(3) ecdsa-with-SHA384(3)}
    // which essentially means the signature algorithm is Elliptic curve Digital Signature Algorithm (DSA) coupled with the Secure Hash Algorithm 384 (SHA384) algorithm
    // @dev Sig algo is hardcoded here because the root certificate's sig algorithm is known beforehand
    // @dev reference article for encoding https://learn.microsoft.com/en-in/windows/win32/seccertenroll/about-object-identifier
    bytes32 public constant CERT_ALGO_OID = 0x53ce037f0dfaa43ef13b095f04e68a6b5e3f1519a01a3203a1e6440ba915b87e; // keccak256(hex"06082a8648ce3d040303")
    // https://oid-rep.orange-labs.fr/get/1.2.840.10045.2.1
    // 1.2.840.10045.2.1 {iso(1) member-body(2) us(840) ansi-x962(10045) keyType(2) ecPublicKey(1)} represents Elliptic curve public key cryptography
    bytes32 public constant EC_PUB_KEY_OID = 0xb60fee1fd85f867dd7c8d16884a49a20287ebe4c0fb49294e9825988aa8e42b4; // keccak256(hex"2a8648ce3d0201")
    // https://oid-rep.orange-labs.fr/get/1.3.132.0.34
    // 1.3.132.0.34 {iso(1) identified-organization(3) certicom(132) curve(0) ansip384r1(34)} represents NIST 384-bit elliptic curve
    bytes32 public constant SECP_384_R1_OID = 0xbd74344bb507daeb9ed315bc535f24a236ccab72c5cd6945fb0efe5c037e2097; // keccak256(hex"2b81040022")

    // extension OID certificate constants
    bytes32 public constant BASIC_CONSTRAINTS_OID = 0x6351d72a43cb42fb9a2531a28608c278c89629f8f025b5f5dc705f3fe45e950a; // keccak256(hex"551d13")
    bytes32 public constant KEY_USAGE_OID = 0x45529d8772b07ebd6d507a1680da791f4a2192882bf89d518801579f7a5167d2; // keccak256(hex"551d0f")

    // certHash -> VerifiedCert. The root is keyed by ROOT_CA_CERT_HASH; every non-root cert is keyed
    // by keccak256(tbsCertificate), excluding the outer malleable ECDSA signature bytes.
    mapping(bytes32 => bytes) public verified;
    // certHash -> parent cert hash used during cold verification.
    // A cached cert is pinned to the parent it was FIRST verified under: warm reuse requires the
    // caller to present this exact parent (see the mismatch check in `_verifyCert`). This is
    // intentional — warm reuse skips signature verification, so it must reflect the precise chain
    // that was cryptographically checked. A same-key CA renewal (new DER, new parent hash) cannot
    // re-bind an already-cached descendant until its cache entry expires; harmless for Nitro because
    // leaves are short-lived. See docs/hinted-p384-nitro-attestation.md "First-verified parent pinning".
    mapping(bytes32 => bytes32) internal verifiedParent;
    // certHash -> revocation identity key (keccak256(issuerHash, serialHash)), recorded at cold
    // verification so the warm path and parent-chain walk can check revocation without re-parsing.
    mapping(bytes32 => bytes32) internal certIdentity;
    // revocation set, keyed by the (issuer, serial) identity for non-root certs (see {computeCertId})
    // and by the pinned ROOT_CA_CERT_HASH for the root emergency halt. NOT keyed by keccak256(cert):
    // raw cert bytes are not a stable identity (ECDSA signatures are malleable and DER is re-encodable),
    // so byte-keying would let a re-encoded twin of a revoked cert slip through.
    mapping(bytes32 => bool) public revoked;

    IP384Verifier public immutable p384Verifier;
    address public owner;
    address public revoker;

    modifier onlyOwner() {
        _onlyOwner();
        _;
    }

    function _onlyOwner() internal view {
        if (msg.sender != owner) revert NotOwner();
    }

    function _onlyRevoker() internal view {
        if (msg.sender != revoker) revert NotRevoker();
    }

    constructor(IP384Verifier p384Verifier_) {
        require(address(p384Verifier_) != address(0), "missing P384 verifier");
        p384Verifier = p384Verifier_;
        owner = msg.sender;
        revoker = msg.sender;
        _saveVerified(
            ROOT_CA_CERT_HASH,
            VerifiedCert({
                ca: true,
                notAfter: ROOT_CA_CERT_NOT_AFTER,
                maxPathLen: ROOT_CA_CERT_MAX_PATH_LEN,
                subjectHash: ROOT_CA_CERT_SUBJECT_HASH,
                pubKey: ROOT_CA_CERT_PUB_KEY
            })
        );
        emit OwnershipTransferred(address(0), msg.sender);
        emit RevokerUpdated(address(0), msg.sender);
    }

    /// @notice DEPRECATED — always reverts. The fully on-chain (non-hinted) path is too expensive
    ///         post-Fusaka and has been removed. Use {verifyCACertWithHints}.
    function verifyCACert(bytes memory, bytes32) external pure returns (bytes32) {
        revert DeprecatedEntrypoint();
    }

    /// @notice DEPRECATED — always reverts. Use {verifyClientCertWithHints}.
    function verifyClientCert(bytes memory, bytes32) external pure returns (VerifiedCert memory) {
        revert DeprecatedEntrypoint();
    }

    /// @notice Verify a CA certificate against its (already-cached) parent and cache the result.
    /// @dev Idempotent with a cache short-circuit: if `cert` is already verified and unexpired, the
    ///      cached record is returned and `signatureHints` is ignored, but `parentCertHash` must
    ///      match the parent used during cold verification. On a cold cert, `signatureHints` must
    ///      contain the real off-chain inverse hints for the cert signature; they are re-verified
    ///      on-chain, so a wrong hint only reverts. Pass 0 only when submitting the pinned root;
    ///      otherwise pass the cached parent cert hash. The returned hash is ROOT_CA_CERT_HASH for
    ///      the pinned root and keccak256(tbsCertificate) for every non-root cert.
    function verifyCACertWithHints(bytes memory cert, bytes32 parentCertHash, bytes memory signatureHints)
        external
        returns (bytes32)
    {
        bytes32 certHash = _certCacheKey(cert);
        _verifyCert(cert, certHash, true, parentCertHash, signatureHints);
        return certHash;
    }

    /// @notice Verify a leaf (client) certificate against its (already-cached) parent and cache it.
    /// @dev Same cache short-circuit and hint semantics as {verifyCACertWithHints}: on a cold cert
    ///      `signatureHints` must hold the real off-chain inverse hints (re-verified on-chain); on a
    ///      cached cert they are ignored, but `parentCertHash` must match the cold verification parent.
    function verifyClientCertWithHints(bytes memory cert, bytes32 parentCertHash, bytes memory signatureHints)
        external
        returns (VerifiedCert memory)
    {
        return _verifyCert(cert, _certCacheKey(cert), false, parentCertHash, signatureHints);
    }

    /// @notice Return raw cached certificate metadata without current trust checks.
    /// @dev A non-empty return value only means the cert was cached previously. It may now be
    ///      expired or revoked; use the verification entrypoints for trust-aware reuse. Pass the
    ///      cache key returned by the verification entrypoints.
    function loadVerified(bytes32 certHash) external view returns (VerifiedCert memory) {
        return _loadVerified(certHash);
    }

    function isRevoked(bytes32 certId) external view returns (bool) {
        return revoked[certId];
    }

    /// @notice Compute the revocation identity key for a certificate.
    /// @dev Returns `keccak256(issuerHash, serialHash)` — the (issuer DN, serial number) pair that
    ///      uniquely identifies an X.509 certificate and that AWS CRLs use to list revoked certs.
    ///      This key is invariant to ECDSA signature malleability (the `(r, n-s)` twin) and to DER
    ///      re-encoding, unlike `keccak256(cert)`. Operators pass the result to {revokeCert} /
    ///      {revokeCerts}; the same value is recorded on-chain when the cert is first verified, so a
    ///      revocation applies to every byte-encoding of that certificate. Reverts on malformed DER.
    function computeCertId(bytes memory cert) external pure returns (bytes32) {
        Asn1Ptr tbsCertPtr = cert.firstChildOf(cert.root());
        return _certIdentity(cert, tbsCertPtr);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert InvalidOwner();
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    function setRevoker(address newRevoker) external onlyOwner {
        if (newRevoker == address(0)) revert InvalidRevoker();
        emit RevokerUpdated(revoker, newRevoker);
        revoker = newRevoker;
    }

    /// @notice Revoke a certificate by its identity key (see {computeCertId}); use ROOT_CA_CERT_HASH
    ///         to trigger the owner-only emergency global halt.
    function revokeCert(bytes32 certId) external {
        _requireCanRevoke(certId);
        _revokeCert(certId);
    }

    function revokeCerts(bytes32[] calldata certIds) external {
        for (uint256 i = 0; i < certIds.length; ++i) {
            _requireCanRevoke(certIds[i]);
            _revokeCert(certIds[i]);
        }
    }

    function unrevokeCert(bytes32 certId) external onlyOwner {
        revoked[certId] = false;
        emit CertUnrevoked(certId, msg.sender);
    }

    function _revokeCert(bytes32 certId) internal {
        revoked[certId] = true;
        emit CertRevoked(certId, msg.sender);
    }

    function _requireCanRevoke(bytes32 certId) internal view {
        // The root is identified by its pinned cert hash (it is never parsed on-chain); revoking it
        // halts all validation, so it is owner-only. Non-root revocation by (issuer, serial) identity
        // is delegated to the revoker role.
        if (certId == ROOT_CA_CERT_HASH) {
            _onlyOwner();
        } else {
            _onlyRevoker();
        }
    }

    function _requireNotRevoked(bytes32 certId) internal view {
        require(!revoked[certId], "cert revoked");
    }

    /// @dev The revocation key for a cached cert: the pinned hash for the root, otherwise the
    ///      (issuer, serial) identity recorded at cold verification.
    function _revocationKey(bytes32 certHash) internal view returns (bytes32) {
        return certHash == ROOT_CA_CERT_HASH ? ROOT_CA_CERT_HASH : certIdentity[certHash];
    }

    function _requireCachedChainNotRevoked(bytes32 certHash) internal view {
        while (certHash != bytes32(0)) {
            _requireNotRevoked(_revocationKey(certHash));
            if (certHash == ROOT_CA_CERT_HASH) {
                return;
            }
            certHash = verifiedParent[certHash];
        }
        // Fail closed: a chain that terminates at bytes32(0) without reaching the pinned root is
        // broken and must not be treated as a verified, non-revoked chain. Reverting here instead
        // of returning silently means revocation safety never depends on upstream guards.
        revert IncompleteCertChain();
    }

    function _verifyCert(
        bytes memory certificate,
        bytes32 certHash,
        bool ca,
        bytes32 parentCertHash,
        bytes memory signatureHints
    ) internal returns (VerifiedCert memory) {
        VerifiedCert memory parent;
        if (certHash != ROOT_CA_CERT_HASH) {
            parent = _loadVerified(parentCertHash);
            require(parent.pubKey.length > 0, "parent cert unverified");
            _requireCachedChainNotRevoked(parentCertHash);
            require(!_certificateExpired(parent.notAfter), "parent cert expired");
            require(parent.ca, "parent cert is not a CA");
            require(!ca || parent.maxPathLen != 0, "maxPathLen exceeded");
        }

        // skip verification if already verified
        VerifiedCert memory cert = _loadVerified(certHash);
        if (cert.pubKey.length != 0) {
            _requireNotRevoked(_revocationKey(certHash));
            require(!_certificateExpired(cert.notAfter), "cert expired");
            require(cert.ca == ca, "cert is not a CA");
            if (certHash != ROOT_CA_CERT_HASH) {
                require(verifiedParent[certHash] == parentCertHash, "parent cert mismatch");
            }
            return cert;
        }

        bytes32 identity;
        (cert, identity) = _verifyUncachedCert(certificate, ca, parent, signatureHints);
        // The pinned root is already present under ROOT_CA_CERT_HASH. Do not allow a signature
        // malleability twin of that same trust anchor to become a second cached parent key.
        require(!_isPinnedRootAlias(certHash, cert), "root cert alias");
        // Reject by (issuer, serial) identity so a re-encoded twin of a revoked cert cannot pass.
        _requireNotRevoked(identity);
        _saveVerified(certHash, cert);
        verifiedParent[certHash] = parentCertHash;
        certIdentity[certHash] = identity;

        emit CertVerified(certHash);

        return cert;
    }

    function _certCacheKey(bytes memory certificate) internal pure returns (bytes32) {
        bytes32 rawCertHash = keccak256(certificate);
        if (rawCertHash == ROOT_CA_CERT_HASH) {
            return ROOT_CA_CERT_HASH;
        }

        Asn1Ptr root = certificate.root();
        require(root.totalLength() == certificate.length, "invalid cert length");
        Asn1Ptr tbsCertPtr = certificate.firstChildOf(root);
        return certificate.keccak(tbsCertPtr.header(), tbsCertPtr.totalLength());
    }

    function _isPinnedRootAlias(bytes32 certHash, VerifiedCert memory cert) internal pure returns (bool) {
        return certHash != ROOT_CA_CERT_HASH && cert.ca && cert.subjectHash == ROOT_CA_CERT_SUBJECT_HASH
            && cert.pubKey.length == ROOT_CA_CERT_PUB_KEY.length
            && keccak256(cert.pubKey) == keccak256(ROOT_CA_CERT_PUB_KEY);
    }

    function _verifyUncachedCert(
        bytes memory certificate,
        bool ca,
        VerifiedCert memory parent,
        bytes memory signatureHints
    ) internal view returns (VerifiedCert memory cert, bytes32 identity) {
        Asn1Ptr root = certificate.root();
        require(root.totalLength() == certificate.length, "invalid cert length");
        Asn1Ptr tbsCertPtr = certificate.firstChildOf(root);
        (uint64 notAfter, int64 maxPathLen, bytes32 issuerHash, bytes32 subjectHash, bytes memory pubKey) =
            _parseTbs(certificate, tbsCertPtr, ca);

        require(parent.subjectHash == issuerHash, "issuer / subject mismatch");

        identity = _certIdentity(certificate, tbsCertPtr);

        // constrain maxPathLen to parent's maxPathLen-1
        if (parent.maxPathLen > 0 && (maxPathLen < 0 || maxPathLen >= parent.maxPathLen)) {
            maxPathLen = parent.maxPathLen - 1;
        }

        _verifyCertSignatureWithHints(certificate, tbsCertPtr, parent.pubKey, signatureHints);

        cert = VerifiedCert({
            ca: ca, notAfter: notAfter, maxPathLen: maxPathLen, subjectHash: subjectHash, pubKey: pubKey
        });
    }

    /// @dev Derives the (issuer, serial) revocation identity from a parsed certificate. The serial is
    ///      the second TBS field (after the explicit [0] version) and the issuer DN is the fourth
    ///      (after the inner signature algorithm); both lie inside the CA-signed TBS, so the identity
    ///      is fixed for any byte-encoding of the certificate that verifies. Mirrors the issuer-hash
    ///      derivation in `_parseTbsInner`.
    function _certIdentity(bytes memory certificate, Asn1Ptr tbsCertPtr) internal pure returns (bytes32) {
        Asn1Ptr versionPtr = certificate.firstChildOf(tbsCertPtr);
        Asn1Ptr serialPtr = certificate.nextSiblingOf(versionPtr);
        Asn1Ptr sigAlgoPtr = certificate.nextSiblingOf(serialPtr);
        Asn1Ptr issuerPtr = certificate.nextSiblingOf(sigAlgoPtr);
        bytes32 serialHash = certificate.keccak(serialPtr.content(), serialPtr.length());
        bytes32 issuerHash = certificate.keccak(issuerPtr.content(), issuerPtr.length());
        return keccak256(abi.encodePacked(issuerHash, serialHash));
    }

    function _parseTbs(bytes memory certificate, Asn1Ptr ptr, bool ca)
        internal
        view
        returns (uint64 notAfter, int64 maxPathLen, bytes32 issuerHash, bytes32 subjectHash, bytes memory pubKey)
    {
        Asn1Ptr sigAlgoPtr = _verifyTbsHeader(certificate, ptr);

        (notAfter, maxPathLen, issuerHash, subjectHash, pubKey) =
            _parseTbsInner(certificate, sigAlgoPtr, ca, ptr.content() + ptr.length());
    }

    function _verifyTbsHeader(bytes memory certificate, Asn1Ptr ptr) internal pure returns (Asn1Ptr sigAlgoPtr) {
        Asn1Ptr versionPtr = certificate.firstChildOf(ptr);
        Asn1Ptr vPtr = certificate.firstChildOf(versionPtr);
        sigAlgoPtr = certificate.nextSiblingOf(certificate.nextSiblingOf(versionPtr));

        require(certificate.keccak(sigAlgoPtr.content(), sigAlgoPtr.length()) == CERT_ALGO_OID, "invalid cert sig algo");
        uint256 version = certificate.uintAt(vPtr);
        // as extensions are used in cert, version should be 3 (value 2) as per https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.1
        require(version == 2, "version should be 3");
    }

    function _parseTbsInner(bytes memory certificate, Asn1Ptr sigAlgoPtr, bool ca, uint256 tbsEnd)
        internal
        view
        returns (uint64 notAfter, int64 maxPathLen, bytes32 issuerHash, bytes32 subjectHash, bytes memory pubKey)
    {
        Asn1Ptr issuerPtr = _nextSiblingWithin(certificate, sigAlgoPtr, tbsEnd);
        issuerHash = certificate.keccak(issuerPtr.content(), issuerPtr.length());
        Asn1Ptr validityPtr = _nextSiblingWithin(certificate, issuerPtr, tbsEnd);
        Asn1Ptr subjectPtr = _nextSiblingWithin(certificate, validityPtr, tbsEnd);
        subjectHash = certificate.keccak(subjectPtr.content(), subjectPtr.length());
        Asn1Ptr subjectPublicKeyInfoPtr = _nextSiblingWithin(certificate, subjectPtr, tbsEnd);
        Asn1Ptr extensionsPtr = _nextSiblingWithin(certificate, subjectPublicKeyInfoPtr, tbsEnd);

        if (certificate[extensionsPtr.header()] == 0x81) {
            // skip optional issuerUniqueID
            extensionsPtr = _nextSiblingWithin(certificate, extensionsPtr, tbsEnd);
        }
        if (certificate[extensionsPtr.header()] == 0x82) {
            // skip optional subjectUniqueID
            extensionsPtr = _nextSiblingWithin(certificate, extensionsPtr, tbsEnd);
        }
        require(_requireAsn1NodeWithin(extensionsPtr, tbsEnd) == tbsEnd, "trailing tbs fields");

        notAfter = _verifyValidity(certificate, validityPtr);
        maxPathLen = _verifyExtensions(certificate, extensionsPtr, ca);
        pubKey = _parsePubKey(certificate, subjectPublicKeyInfoPtr);
    }

    function _parsePubKey(bytes memory certificate, Asn1Ptr subjectPublicKeyInfoPtr)
        internal
        pure
        returns (bytes memory subjectPubKey)
    {
        Asn1Ptr pubKeyAlgoPtr = certificate.firstChildOf(subjectPublicKeyInfoPtr);
        Asn1Ptr pubKeyAlgoIdPtr = certificate.firstChildOf(pubKeyAlgoPtr);
        Asn1Ptr algoParamsPtr = certificate.nextSiblingOf(pubKeyAlgoIdPtr);
        Asn1Ptr subjectPublicKeyPtr = certificate.nextSiblingOf(pubKeyAlgoPtr);
        Asn1Ptr subjectPubKeyPtr = certificate.bitstring(subjectPublicKeyPtr);

        if (certificate.keccak(pubKeyAlgoIdPtr.content(), pubKeyAlgoIdPtr.length()) != EC_PUB_KEY_OID) {
            revert InvalidSubjectPublicKey();
        }
        if (certificate.keccak(algoParamsPtr.content(), algoParamsPtr.length()) != SECP_384_R1_OID) {
            revert InvalidSubjectPublicKey();
        }

        uint256 keyStart = subjectPubKeyPtr.content();
        uint256 keyLength = subjectPubKeyPtr.length();
        if (keyLength != 97 || keyStart + keyLength > certificate.length || certificate[keyStart] != 0x04) {
            revert InvalidSubjectPublicKey();
        }
        subjectPubKey = certificate.slice(keyStart + 1, 96);
    }

    function _verifyValidity(bytes memory certificate, Asn1Ptr validityPtr) internal view returns (uint64 notAfter) {
        Asn1Ptr notBeforePtr = certificate.firstChildOf(validityPtr);
        Asn1Ptr notAfterPtr = certificate.nextSiblingOf(notBeforePtr);

        uint256 notBefore = certificate.timestampAt(notBeforePtr);
        notAfter = uint64(certificate.timestampAt(notAfterPtr));

        require(notBefore <= block.timestamp, "certificate not valid yet");
        require(!_certificateExpired(notAfter), "certificate not valid anymore");
    }

    function _certificateExpired(uint256 notAfter) internal view virtual returns (bool) {
        return notAfter < block.timestamp;
    }

    function _verifyExtensions(bytes memory certificate, Asn1Ptr extensionsPtr, bool ca)
        internal
        pure
        returns (int64 maxPathLen)
    {
        if (certificate[extensionsPtr.header()] != 0xa3) revert InvalidExtension();
        extensionsPtr = certificate.firstChildOf(extensionsPtr);
        uint256 end = extensionsPtr.content() + extensionsPtr.length();
        Asn1Ptr extensionPtr = _firstChildWithin(certificate, extensionsPtr, end);
        bool basicConstraintsFound = false;
        bool keyUsageFound = false;
        maxPathLen = -1;

        while (true) {
            uint256 extensionEnd = _requireAsn1NodeWithin(extensionPtr, end);
            Asn1Ptr oidPtr = _firstChildWithin(certificate, extensionPtr, extensionEnd);
            bytes32 oid = certificate.keccak(oidPtr.content(), oidPtr.length());
            bool recognized = oid == BASIC_CONSTRAINTS_OID || oid == KEY_USAGE_OID;

            Asn1Ptr valuePtr = _nextSiblingWithin(certificate, oidPtr, extensionEnd);

            if (certificate[valuePtr.header()] == 0x01) {
                if (valuePtr.length() != 1) revert InvalidExtension();
                if (!recognized && certificate[valuePtr.content()] != 0x00) revert UnsupportedCriticalExtension();
                valuePtr = _nextSiblingWithin(certificate, valuePtr, extensionEnd);
            }

            require(_requireAsn1NodeWithin(valuePtr, extensionEnd) == extensionEnd, "trailing extension fields");

            if (recognized) {
                valuePtr = certificate.octetString(valuePtr);

                if (oid == BASIC_CONSTRAINTS_OID) {
                    require(!basicConstraintsFound, "duplicate basicConstraints");
                    basicConstraintsFound = true;
                    maxPathLen = _verifyBasicConstraintsExtension(certificate, valuePtr, ca);
                } else {
                    require(!keyUsageFound, "duplicate keyUsage");
                    keyUsageFound = true;
                    _verifyKeyUsageExtension(certificate, valuePtr, ca);
                }
            }

            if (extensionEnd == end) {
                break;
            }
            extensionPtr = _nextSiblingWithin(certificate, extensionPtr, end);
        }

        if (!basicConstraintsFound || !keyUsageFound || (!ca && maxPathLen != -1)) revert InvalidExtension();
    }

    function _verifyBasicConstraintsExtension(bytes memory certificate, Asn1Ptr valuePtr, bool ca)
        internal
        pure
        returns (int64 maxPathLen)
    {
        if (certificate[valuePtr.header()] != 0x30) revert InvalidBasicConstraints();

        maxPathLen = -1;
        bool isCA;
        uint256 end = valuePtr.content() + valuePtr.length();
        uint256 cursor = valuePtr.content();

        if (cursor < end) {
            Asn1Ptr basicConstraintsPtr = certificate.firstChildOf(valuePtr);
            cursor = _requireAsn1ChildWithin(basicConstraintsPtr, end);

            if (certificate[basicConstraintsPtr.header()] == 0x01) {
                if (basicConstraintsPtr.length() != 1) revert InvalidBasicConstraints();
                isCA = certificate[basicConstraintsPtr.content()] == 0xff;

                if (cursor == end) {
                    if (ca != isCA) revert InvalidBasicConstraints();
                    return maxPathLen;
                }

                basicConstraintsPtr = certificate.nextSiblingOf(basicConstraintsPtr);
                cursor = _requireAsn1ChildWithin(basicConstraintsPtr, end);
            }

            if (ca != isCA) revert InvalidBasicConstraints();

            if (certificate[basicConstraintsPtr.header()] == 0x02) {
                if (basicConstraintsPtr.length() == 0) revert InvalidBasicConstraints();
                maxPathLen = int64(uint64(certificate.uintAt(basicConstraintsPtr)));
            } else {
                revert InvalidBasicConstraints();
            }

            if (cursor != end) revert InvalidBasicConstraints();
            return maxPathLen;
        }

        if (ca != isCA) revert InvalidBasicConstraints();
    }

    function _requireAsn1ChildWithin(Asn1Ptr ptr, uint256 parentEnd) internal pure returns (uint256 childEnd) {
        childEnd = ptr.header() + ptr.totalLength();
        if (childEnd > parentEnd) revert InvalidBasicConstraints();
    }

    function _requireAsn1NodeWithin(Asn1Ptr ptr, uint256 parentEnd) internal pure returns (uint256 nodeEnd) {
        nodeEnd = ptr.header() + ptr.totalLength();
        require(nodeEnd <= parentEnd, "ASN.1 node out of bounds");
    }

    function _firstChildWithin(bytes memory der, Asn1Ptr ptr, uint256 parentEnd) internal pure returns (Asn1Ptr child) {
        child = der.firstChildOf(ptr);
        _requireAsn1NodeWithin(child, parentEnd);
    }

    function _nextSiblingWithin(bytes memory der, Asn1Ptr ptr, uint256 parentEnd)
        internal
        pure
        returns (Asn1Ptr sibling)
    {
        sibling = der.nextSiblingOf(ptr);
        _requireAsn1NodeWithin(sibling, parentEnd);
    }

    function _verifyKeyUsageExtension(bytes memory certificate, Asn1Ptr valuePtr, bool ca) internal pure {
        uint256 value = certificate.bitstringUintAt(valuePtr);
        // X.509 KeyUsage bits are MSB-first. bitstringUintAt keeps the first KeyUsage octet in the
        // low byte, so these masks continue to target the same bits for one- or multi-octet values.
        if (ca) {
            require(value & 0x04 == 0x04, "CertSign must be present");
        } else {
            require(value & 0x80 == 0x80, "DigitalSignature must be present");
        }
    }

    function _verifyCertSignatureWithHints(
        bytes memory certificate,
        Asn1Ptr ptr,
        bytes memory pubKey,
        bytes memory signatureHints
    ) internal view {
        Asn1Ptr sigAlgoPtr = certificate.nextSiblingOf(ptr);
        require(certificate.keccak(sigAlgoPtr.content(), sigAlgoPtr.length()) == CERT_ALGO_OID, "invalid cert sig algo");
        Asn1Ptr sigPtr = certificate.nextSiblingOf(sigAlgoPtr);
        require(sigPtr.header() + sigPtr.totalLength() == certificate.length, "trailing cert fields");

        bytes memory hash = Sha2Ext.sha384(certificate, ptr.header(), ptr.totalLength());
        bytes memory sigPacked = _certSignature(certificate, sigPtr);

        require(p384Verifier.verifyP384SignatureWithHints(hash, sigPacked, pubKey, signatureHints), "invalid sig");
    }

    function _certSignature(bytes memory certificate, Asn1Ptr sigPtr) internal pure returns (bytes memory sigPacked) {
        Asn1Ptr sigBPtr = certificate.bitstring(sigPtr);
        Asn1Ptr sigRoot = certificate.rootOf(sigBPtr);
        Asn1Ptr sigRPtr = certificate.firstChildOf(sigRoot);
        Asn1Ptr sigSPtr = certificate.nextSiblingOf(sigRPtr);
        (uint128 rhi, uint256 rlo) = certificate.uint384At(sigRPtr);
        (uint128 shi, uint256 slo) = certificate.uint384At(sigSPtr);
        sigPacked = abi.encodePacked(rhi, rlo, shi, slo);
    }

    function _saveVerified(bytes32 certHash, VerifiedCert memory cert) internal {
        verified[certHash] = abi.encodePacked(cert.ca, cert.notAfter, cert.maxPathLen, cert.subjectHash, cert.pubKey);
    }

    function _loadVerified(bytes32 certHash) internal view returns (VerifiedCert memory) {
        bytes memory packed = verified[certHash];
        if (packed.length == 0) {
            return VerifiedCert({ca: false, notAfter: 0, maxPathLen: 0, subjectHash: 0, pubKey: ""});
        }
        uint8 ca;
        uint64 notAfter;
        int64 maxPathLen;
        bytes32 subjectHash;
        assembly {
            ca := mload(add(packed, 0x1))
            notAfter := mload(add(packed, 0x9))
            maxPathLen := mload(add(packed, 0x11))
            subjectHash := mload(add(packed, 0x31))
        }
        bytes memory pubKey = packed.slice(0x31, packed.length - 0x31);
        return VerifiedCert({
            ca: ca != 0, notAfter: notAfter, maxPathLen: maxPathLen, subjectHash: subjectHash, pubKey: pubKey
        });
    }
}
