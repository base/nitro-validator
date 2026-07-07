// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {Test, console} from "forge-std/Test.sol";
import {CertManager} from "../src/CertManager.sol";
import {ICertManager} from "../src/ICertManager.sol";
import {Asn1Decode, LibAsn1Ptr, Asn1Ptr} from "../src/Asn1Decode.sol";
import {LibBytes} from "../src/LibBytes.sol";
import {P384Verifier} from "../src/P384Verifier.sol";
import {P384HintCollector} from "./helpers/HintedNitroTestHelpers.sol";

contract Asn1DecodeHarness {
    using Asn1Decode for bytes;

    function uint384At(bytes calldata der, uint256 header, uint256 content, uint256 length)
        external
        pure
        returns (uint128 hi, uint256 lo)
    {
        Asn1Ptr ptr = LibAsn1Ptr.toAsn1Ptr(header, content, length);
        return der.uint384At(ptr);
    }
}

contract CertManagerHarness is CertManager {
    using Asn1Decode for bytes;

    constructor() CertManager(new P384Verifier()) {}

    function verifyBasicConstraints(bytes memory der, bool ca) external pure returns (int64) {
        return _verifyBasicConstraintsExtension(der, der.root(), ca);
    }
}

contract CertManagerTbsHarness is CertManager {
    using Asn1Decode for bytes;

    constructor() CertManager(new P384Verifier()) {}

    function parseTbs(bytes memory cert, bool ca) external view {
        Asn1Ptr root = cert.root();
        Asn1Ptr tbsPtr = cert.firstChildOf(root);
        _parseTbs(cert, tbsPtr, ca);
    }
}

contract CertManagerPubKeyHarness is CertManager {
    using Asn1Decode for bytes;

    constructor() CertManager(new P384Verifier()) {}

    function parsePubKey(bytes memory subjectPublicKeyInfo) external pure returns (bytes memory) {
        return _parsePubKey(subjectPublicKeyInfo, subjectPublicKeyInfo.root());
    }

    function parsePubKeyAt(bytes memory certificate, uint256 header, uint256 content, uint256 length)
        external
        pure
        returns (bytes memory)
    {
        return _parsePubKey(certificate, LibAsn1Ptr.toAsn1Ptr(header, content, length));
    }
}

contract CertManagerExtensionsHarness is CertManager {
    using Asn1Decode for bytes;

    constructor() CertManager(new P384Verifier()) {}

    function verifyExtensions(bytes memory der, bool ca) external pure returns (int64) {
        return _verifyExtensions(der, der.root(), ca);
    }
}

contract CertManagerTest is Test {
    using Asn1Decode for bytes;
    using LibAsn1Ptr for Asn1Ptr;
    using LibBytes for bytes;

    Asn1DecodeHarness public harness;
    CertManagerHarness public certManagerHarness;
    CertManagerTbsHarness public certManagerTbsHarness;
    CertManagerPubKeyHarness public certManagerPubKeyHarness;
    CertManagerExtensionsHarness public certManagerExtensionsHarness;

    function setUp() public {
        harness = new Asn1DecodeHarness();
        certManagerHarness = new CertManagerHarness();
        certManagerTbsHarness = new CertManagerTbsHarness();
        certManagerPubKeyHarness = new CertManagerPubKeyHarness();
        certManagerExtensionsHarness = new CertManagerExtensionsHarness();
    }

    // 's' INTEGER from cabundle[3] (2026-04-02 attestation): DER-encoded with a 0x00
    // sign-padding byte, leaving valueLength=47. Verifies hi/lo are correctly zero-padded
    // to the full 48-byte scalar rather than packed flush against the stripped bytes.
    function test_uint384At_Short47Bytes() public view {
        bytes memory der =
            hex"023000caf59019bfbcc6f6ed365e5a892ceaa2eda9c549dc01460f5fe650814ebe0e7ee855d3bcffde95afd2e82e21df0eac";
        (uint128 hi, uint256 lo) = harness.uint384At(der, 0, 2, 48);
        assertEq(uint8(hi >> 120), 0x00, "hi[0]: expected 0x00 (unfixed: 0xca)");
        assertEq(uint8(lo >> 248), 0xa2, "lo[0]: expected 0xa2 (unfixed: 0x00, byte absorbed into hi)");
        assertEq(hi, uint128(0x00caf59019bfbcc6f6ed365e5a892cea));
        assertEq(lo, 0xa2eda9c549dc01460f5fe650814ebe0e7ee855d3bcffde95afd2e82e21df0eac);
    }

    function test_BasicConstraintsEmptySequenceIsClientCert() public view {
        assertEq(int256(certManagerHarness.verifyBasicConstraints(hex"3000", false)), -1);
    }

    function test_BasicConstraintsEmptySequenceRejectsCACert() public {
        vm.expectRevert(CertManager.InvalidBasicConstraints.selector);
        certManagerHarness.verifyBasicConstraints(hex"3000", true);
    }

    function test_BasicConstraintsAcceptsCAWithoutPathLen() public view {
        assertEq(int256(certManagerHarness.verifyBasicConstraints(hex"30030101ff", true)), -1);
    }

    function test_BasicConstraintsAcceptsCAWithPathLen() public view {
        assertEq(int256(certManagerHarness.verifyBasicConstraints(hex"30060101ff020100", true)), 0);
    }

    function test_BasicConstraintsRejectsEmptyPathLen() public {
        vm.expectRevert(CertManager.InvalidBasicConstraints.selector);
        certManagerHarness.verifyBasicConstraints(hex"30050101ff0200", true);
    }

    function test_BasicConstraintsRejectsOutOfBoundsChild() public {
        vm.expectRevert(Asn1Decode.InvalidAsn1Length.selector);
        certManagerHarness.verifyBasicConstraints(hex"3003020200", false);
    }

    function test_BasicConstraintsRejectsTrailingFields() public {
        vm.expectRevert(CertManager.InvalidBasicConstraints.selector);
        certManagerHarness.verifyBasicConstraints(hex"30090101ff020100020100", true);
    }

    function test_BasicConstraintsRejectsUnknownField() public {
        vm.expectRevert(CertManager.InvalidBasicConstraints.selector);
        certManagerHarness.verifyBasicConstraints(hex"30020400", false);
    }

    function test_ExtensionsRejectDuplicateBasicConstraints() public {
        vm.expectRevert(CertManager.InvalidExtension.selector);
        certManagerExtensionsHarness.verifyExtensions(
            _extensions(bytes.concat(_basicConstraintsExtension(), _basicConstraintsExtension(), _keyUsageExtension())),
            true
        );
    }

    function test_ExtensionsRejectDuplicateKeyUsage() public {
        vm.expectRevert(CertManager.InvalidExtension.selector);
        certManagerExtensionsHarness.verifyExtensions(
            _extensions(bytes.concat(_basicConstraintsExtension(), _keyUsageExtension(), _keyUsageExtension())), true
        );
    }

    function test_ExtensionsRejectTrailingExtensionFields() public {
        vm.expectRevert(CertManager.InvalidExtension.selector);
        certManagerExtensionsHarness.verifyExtensions(
            _extensions(bytes.concat(_basicConstraintsExtensionWithTrailingField(), _keyUsageExtension())), true
        );
    }

    function test_ParseTbsRejectsTrailingSignedFields() public {
        bytes memory mutated = _appendTbsTrailingField(CB1);

        vm.expectRevert(Asn1Decode.InvalidAsn1Length.selector);
        certManagerTbsHarness.parseTbs(mutated, true);
    }

    function test_ParsePubKeyAcceptsUncompressedP384Point() public view {
        bytes memory pubKey = _patternBytes(96);
        bytes memory spki = abi.encodePacked(hex"3076301006072a8648ce3d020106052b8104002203620004", pubKey);

        assertEq(certManagerPubKeyHarness.parsePubKey(spki), pubKey);
    }

    function test_ParsePubKeyRejectsCompressedP384Point() public {
        bytes memory compressedKey = _patternBytes(48);
        bytes memory spki = abi.encodePacked(hex"3046301006072a8648ce3d020106052b8104002203320002", compressedKey);
        bytes memory paddedCertificate = abi.encodePacked(new bytes(128), spki);

        vm.expectRevert(CertManager.InvalidSubjectPublicKey.selector);
        certManagerPubKeyHarness.parsePubKeyAt(paddedCertificate, 128, 130, 0x46);
    }

    function test_ParsePubKeyRejectsOversizedP384Point() public {
        bytes memory oversizedKey = _patternBytes(97);
        bytes memory spki = abi.encodePacked(hex"3077301006072a8648ce3d020106052b8104002203630004", oversizedKey);

        vm.expectRevert(CertManager.InvalidSubjectPublicKey.selector);
        certManagerPubKeyHarness.parsePubKey(spki);
    }

    function test_ParsePubKeyRejectsTruncatedP384Point() public {
        bytes memory truncatedKey = _patternBytes(95);
        bytes memory spki = abi.encodePacked(hex"3076301006072a8648ce3d020106052b8104002203620004", truncatedKey);

        vm.expectRevert(Asn1Decode.InvalidAsn1Length.selector);
        certManagerPubKeyHarness.parsePubKey(spki);
    }

    function test_ParsePubKeyRejectsMissingUncompressedPrefix() public {
        bytes memory pubKey = _patternBytes(96);
        bytes memory spki = abi.encodePacked(hex"3076301006072a8648ce3d020106052b8104002203620002", pubKey);

        vm.expectRevert(CertManager.InvalidSubjectPublicKey.selector);
        certManagerPubKeyHarness.parsePubKey(spki);
    }

    function test_VerifyExtensionsAllowsUnknownNonCriticalExtension() public view {
        bytes memory unknownNameConstraints = hex"30090603551d1e04023000";

        assertEq(
            int256(certManagerExtensionsHarness.verifyExtensions(_clientExtensionsWith(unknownNameConstraints), false)),
            -1
        );
    }

    function test_VerifyExtensionsAllowsUnknownCriticalFalseExtension() public view {
        bytes memory unknownNameConstraints = hex"300c0603551d1e01010004023000";

        assertEq(
            int256(certManagerExtensionsHarness.verifyExtensions(_clientExtensionsWith(unknownNameConstraints), false)),
            -1
        );
    }

    function test_VerifyExtensionsRejectsUnknownCriticalExtension() public {
        bytes memory unknownNameConstraints = hex"300c0603551d1e0101ff04023000";

        vm.expectRevert(CertManager.UnsupportedCriticalExtension.selector);
        certManagerExtensionsHarness.verifyExtensions(_clientExtensionsWith(unknownNameConstraints), false);
    }

    // Cert chain from the 2026-04-02 ~15:35 UTC dev attestation that produced the live revert.
    // CB0 is the AWS Nitro root (keccak256(CB0) == CertManager.ROOT_CA_CERT_HASH, pinned in the
    // constructor), so the chain is verified starting from CB1.
    bytes constant CB0 =
        hex"3082021130820196a003020102021100f93175681b90afe11d46ccb4e4e7f856300a06082a8648ce3d0403033049310b3009060355040613025553310f300d060355040a0c06416d617a6f6e310c300a060355040b0c03415753311b301906035504030c126177732e6e6974726f2d656e636c61766573301e170d3139313032383133323830355a170d3439313032383134323830355a3049310b3009060355040613025553310f300d060355040a0c06416d617a6f6e310c300a060355040b0c03415753311b301906035504030c126177732e6e6974726f2d656e636c617665733076301006072a8648ce3d020106052b8104002203620004fc0254eba608c1f36870e29ada90be46383292736e894bfff672d989444b5051e534a4b1f6dbe3c0bc581a32b7b176070ede12d69a3fea211b66e752cf7dd1dd095f6f1370f4170843d9dc100121e4cf63012809664487c9796284304dc53ff4a3423040300f0603551d130101ff040530030101ff301d0603551d0e041604149025b50dd90547e796c396fa729dcf99a9df4b96300e0603551d0f0101ff040403020186300a06082a8648ce3d0403030369003066023100a37f2f91a1c9bd5ee7b8627c1698d255038e1f0343f95b63a9628c3d39809545a11ebcbf2e3b55d8aeee71b4c3d6adf3023100a2f39b1605b27028a5dd4ba069b5016e65b4fbde8fe0061d6a53197f9cdaf5d943bc61fc2beb03cb6fee8d2302f3dff6";
    bytes constant CB1 =
        hex"308202c030820245a003020102021100e9773f7085209425e1de229b000f01f1300a06082a8648ce3d0403033049310b3009060355040613025553310f300d060355040a0c06416d617a6f6e310c300a060355040b0c03415753311b301906035504030c126177732e6e6974726f2d656e636c61766573301e170d3236303333313035303734355a170d3236303432303036303734355a3064310b3009060355040613025553310f300d060355040a0c06416d617a6f6e310c300a060355040b0c034157533136303406035504030c2d316262313063316530323564363536632e75732d656173742d312e6177732e6e6974726f2d656e636c617665733076301006072a8648ce3d020106052b8104002203620004cd607e358d0c0d7fb6cb74700df27dd799f46a8b3e1e106c2ba4e962b8e1869fb8ee1929a0543e8cf5fe36eb8c85decb1a8e680fde0427d222cd2c43f6103d4f651b98770d9f52439963a83d65ebc45e17f8d16ccb76e343163429e4f4dca36da381d53081d230120603551d130101ff040830060101ff020102301f0603551d230418301680149025b50dd90547e796c396fa729dcf99a9df4b96301d0603551d0e0416041449ed5cf5770acf285a97690e5027f21b81c1bf0d300e0603551d0f0101ff040403020186306c0603551d1f046530633061a05fa05d865b687474703a2f2f6177732d6e6974726f2d656e636c617665732d63726c2e73332e616d617a6f6e6177732e636f6d2f63726c2f61623439363063632d376436332d343262642d396539662d3539333338636236376638342e63726c300a06082a8648ce3d0403030369003066023100fad8167b186ede6765e2fee311718e1c2dfde817a280a316bab19008eb15356795525d52458bdec9818ea7c1f26d054c023100de456629f7833285dc26f68e74b206b83bf39846a76271c7c364c6fc2c00db5da4b435a92cd85963eab5e1b58d049b49";
    bytes constant CB2 =
        hex"308203133082029aa003020102021038fed4b0c2167f2e947b381791999d87300a06082a8648ce3d0403033064310b3009060355040613025553310f300d060355040a0c06416d617a6f6e310c300a060355040b0c034157533136303406035504030c2d316262313063316530323564363536632e75732d656173742d312e6177732e6e6974726f2d656e636c61766573301e170d3236303430323037303834365a170d3236303430383036303834365a308189313c303a06035504030c33396162323162376434663562373139622e7a6f6e616c2e75732d656173742d312e6177732e6e6974726f2d656e636c61766573310c300a060355040b0c03415753310f300d060355040a0c06416d617a6f6e310b3009060355040613025553310b300906035504080c0257413110300e06035504070c0753656174746c653076301006072a8648ce3d020106052b81040022036200041448bacb44a37937f8558d861442956c0c4482f28bd5ced8af0a2a7ec153cb22ab709ef75b37cf273ba2a3415dae125fa5aac4aa063e833c86df6cb68141b35284afb95279a301fadcad98e4edf5740a8461646b31ce52cbba81638395da26b7a381ea3081e730120603551d130101ff040830060101ff020101301f0603551d2304183016801449ed5cf5770acf285a97690e5027f21b81c1bf0d301d0603551d0e041604146a2a38eb4940a886ad9e57e4b7da9dde7f4eb700300e0603551d0f0101ff0404030201863081800603551d1f047930773075a073a071866f687474703a2f2f63726c2d75732d656173742d312d6177732d6e6974726f2d656e636c617665732e73332e75732d656173742d312e616d617a6f6e6177732e636f6d2f63726c2f63336535353365322d363936632d346635302d386233382d6435666165663036306633312e63726c300a06082a8648ce3d0403030367003064023012012108aa4f9678c965ca3746037a230d07c2bc39f3d7ebc9832fbad0e5277c9642d61d3245ba45d741bd88c04692fa02307a4a42535408ed65e5db2bea9aefff587d9187788b715843295efcbbf710d7f65301476ed4338b4755cd3c16b0e12d6a";
    bytes constant CB3 =
        hex"308202bf30820245a003020102021500f2a021cc6a8466d5fe18e8f487b975f35c7c5b05300a06082a8648ce3d040303308189313c303a06035504030c33396162323162376434663562373139622e7a6f6e616c2e75732d656173742d312e6177732e6e6974726f2d656e636c61766573310c300a060355040b0c03415753310f300d060355040a0c06416d617a6f6e310b3009060355040613025553310b300906035504080c0257413110300e06035504070c0753656174746c65301e170d3236303430323135303431355a170d3236303430333135303431355a30818e310b30090603550406130255533113301106035504080c0a57617368696e67746f6e3110300e06035504070c0753656174746c65310f300d060355040a0c06416d617a6f6e310c300a060355040b0c034157533139303706035504030c30692d30396535656634623664666630323535622e75732d656173742d312e6177732e6e6974726f2d656e636c617665733076301006072a8648ce3d020106052b810400220362000420ecb0a645c3e6b4437c1c4149c3f1d0af3e90f0343b0e1e3a47d8b314420266843c345a1e64b01b43331f911ab537b78b355a2419eeb00f1ecd6d4fbd7186ab41603ff2a0430cab7b597362a1054ed4cb8ff32dd76b2c108224b42648bbf026a366306430120603551d130101ff040830060101ff020100300e0603551d0f0101ff040403020204301d0603551d0e0416041499b2d026ad0212b670d2550fb292ca51fdbf8d66301f0603551d230418301680146a2a38eb4940a886ad9e57e4b7da9dde7f4eb700300a06082a8648ce3d040303036800306502310096ca96c46b5a05de3ad9ecdeaab8670916137461d306cf2fcd8a308885eb6063d96de2e28a1a4ad8c2214e1d1479b5b8023000caf59019bfbcc6f6ed365e5a892ceaa2eda9c549dc01460f5fe650814ebe0e7ee855d3bcffde95afd2e82e21df0eac";

    // CB3's 's' component has a 47-byte DER encoding; unpatched Asn1Decode.uint384At misreads it
    // and the corrupted scalar is rejected by ECDSA384.verify, reverting with "invalid sig".
    // Verified through the hinted flow (verifyCACertWithHints) since this branch removed the
    // non-hinted verification path.
    function test_VerifyCACertWithHints_ShortS_Regression() public {
        vm.warp(1775145600);
        CertManager cm = new CertManager(new P384Verifier());
        P384HintCollector collector = new P384HintCollector();

        // CB0 (AWS Nitro root) is pinned in the constructor.
        bytes32 parentHash = keccak256(CB0);
        assertEq(parentHash, cm.ROOT_CA_CERT_HASH(), "CB0 must be the pinned root");

        parentHash = _verifyCA(cm, collector, CB1, parentHash);
        parentHash = _verifyCA(cm, collector, CB2, parentHash);
        _verifyCA(cm, collector, CB3, parentHash); // reverts with "invalid sig" on unpatched code
    }

    function test_VerifyCACertWithHints_MalleableSignatureUsesSameTbsCacheKey() public {
        vm.warp(1775145600);
        CertManager cm = new CertManager(new P384Verifier());
        P384HintCollector collector = new P384HintCollector();

        bytes32 rootHash = keccak256(CB0);
        assertEq(rootHash, cm.ROOT_CA_CERT_HASH(), "CB0 must be the pinned root");

        bytes memory twin = _malleateCertSignature(CB1);
        assertNotEq(keccak256(twin), keccak256(CB1), "malleated cert must have different raw bytes");
        assertEq(_tbsHash(twin), _tbsHash(CB1), "malleated cert must keep the signed TBS");

        bytes memory parentPubKey = cm.loadVerified(rootHash).pubKey;
        bytes memory twinHints = collector.collectCertSignatureHints(twin, parentPubKey);

        bytes32 twinKey = cm.verifyCACertWithHints(twin, rootHash, twinHints);
        assertEq(twinKey, _tbsHash(CB1), "non-root certs are cached by TBS hash");
        assertNotEq(twinKey, keccak256(CB1), "cache key must exclude the malleable signature");

        bytes32 canonicalKey = cm.verifyCACertWithHints(CB1, rootHash, "");
        assertEq(canonicalKey, twinKey, "canonical cert should hit the same warm cache entry");
    }

    function test_VerifyCACertWithHints_RejectsMalleableRootAlias() public {
        vm.warp(1775145600);
        CertManager cm = new CertManager(new P384Verifier());
        P384HintCollector collector = new P384HintCollector();

        bytes32 rootHash = keccak256(CB0);
        assertEq(rootHash, cm.ROOT_CA_CERT_HASH(), "CB0 must be the pinned root");

        bytes memory rootTwin = _malleateCertSignature(CB0);
        assertNotEq(keccak256(rootTwin), rootHash, "malleated root must have a different raw hash");

        bytes memory rootPubKey = cm.loadVerified(rootHash).pubKey;
        bytes memory hints = collector.collectCertSignatureHints(rootTwin, rootPubKey);

        vm.expectRevert("root cert alias");
        cm.verifyCACertWithHints(rootTwin, rootHash, hints);
    }

    function test_VerifyCACertWithHints_RejectsSignatureWrapperTagSubstitution() public {
        vm.warp(1775145600);
        CertManager cm = new CertManager(new P384Verifier());
        P384HintCollector collector = new P384HintCollector();

        bytes32 rootHash = keccak256(CB0);
        bytes memory parentPubKey = cm.loadVerified(rootHash).pubKey;
        bytes memory hints = collector.collectCertSignatureHints(CB1, parentPubKey);

        bytes memory mutated = bytes.concat(CB1);
        (,, Asn1Ptr sigRoot,) = _certSignaturePtrs(mutated);
        mutated[sigRoot.header()] = 0x31; // constructed SET with the same r/s children.

        vm.expectRevert(CertManager.InvalidAsn1Tag.selector);
        cm.verifyCACertWithHints(mutated, rootHash, hints);
    }

    function test_VerifyCACertWithHints_RejectsTrailingSignatureFields() public {
        vm.warp(1775145600);
        CertManager cm = new CertManager(new P384Verifier());
        P384HintCollector collector = new P384HintCollector();

        bytes32 rootHash = keccak256(CB0);
        bytes memory parentPubKey = cm.loadVerified(rootHash).pubKey;
        bytes memory hints = collector.collectCertSignatureHints(CB1, parentPubKey);

        bytes memory mutated = _appendSignatureTrailingField(CB1);

        vm.expectRevert(CertManager.InvalidAsn1Tag.selector);
        cm.verifyCACertWithHints(mutated, rootHash, hints);
    }

    function test_VerifyCACertWithHints_RejectsOuterTagSubstitution() public {
        vm.warp(1775145600);
        CertManager cm = new CertManager(new P384Verifier());

        bytes32 rootHash = keccak256(CB0);
        bytes memory mutated = bytes.concat(CB1);
        mutated[0] = 0x31; // constructed SET with the same children is not an X.509 Certificate SEQUENCE.

        vm.expectRevert(CertManager.InvalidAsn1Tag.selector);
        cm.verifyCACertWithHints(mutated, rootHash, "");
    }

    function test_VerifyCACertWithHints_RejectsTbsAlgorithmTagSubstitution() public {
        vm.warp(1775145600);
        CertManager cm = new CertManager(new P384Verifier());

        bytes32 rootHash = keccak256(CB0);
        bytes memory mutated = bytes.concat(CB1);
        Asn1Ptr root = mutated.root();
        Asn1Ptr tbsPtr = mutated.firstChildOf(root);
        Asn1Ptr versionPtr = mutated.firstChildOf(tbsPtr);
        Asn1Ptr serialPtr = mutated.nextSiblingOf(versionPtr);
        Asn1Ptr sigAlgoPtr = mutated.nextSiblingOf(serialPtr);
        mutated[sigAlgoPtr.header()] = 0x31; // constructed, but not AlgorithmIdentifier SEQUENCE.

        vm.expectRevert(CertManager.InvalidAsn1Tag.selector);
        cm.verifyCACertWithHints(mutated, rootHash, "");
    }

    function _verifyCA(CertManager cm, P384HintCollector collector, bytes memory cert, bytes32 parentHash)
        internal
        returns (bytes32)
    {
        bytes memory parentPubKey = cm.loadVerified(parentHash).pubKey;
        bytes memory hints = collector.collectCertSignatureHints(cert, parentPubKey);
        return cm.verifyCACertWithHints(cert, parentHash, hints);
    }

    // Cache-griefing liveness edge: `verifiedParent[certHash]` is written once on the cold
    // path (gated on cert.pubKey.length == 0) and never updated. If AWS renews an intermediate
    // CA with the SAME signing key but a new validity window, the renewed cert has a different
    // TBS -> a different cache key -> a different parentCertHash in the chain. A leaf
    // already cached under the old parent then permanently reverts "parent cert mismatch"
    // against the renewed parent, with no admin override. (The wrong-parent revert mechanism
    // itself is covered by HintedNitroAttestationTest.test_Hinted{CA,Client}CertRejectsCachedParentMismatch.)
    //
    // SKIPPED: realising this needs a genuine same-key *renewed* CA cert, which requires an
    // AWS signing operation and is unavailable as a static fixture. Documented as a known
    // liveness edge; the binding is intentional (warm reuse skips signature verification, so it
    // must reflect the exact verified chain) and self-heals because Nitro leaves are short-lived.
    function test_CacheGriefingSameKeyCaRenewalBricksCachedLeaf() public {
        vm.skip(
            true,
            "needs a same-key-renewed AWS CA fixture (off-chain signing); documents verifiedParent first-writer-wins"
        );
    }

    function _tbsHash(bytes memory certificate) internal pure returns (bytes32) {
        Asn1Ptr root = certificate.root();
        Asn1Ptr tbsCertPtr = certificate.firstChildOf(root);
        return certificate.keccak(tbsCertPtr.header(), tbsCertPtr.totalLength());
    }

    function _malleateCertSignature(bytes memory certificate) internal pure returns (bytes memory result) {
        (Asn1Ptr root, Asn1Ptr sigPtr, Asn1Ptr sigRoot, Asn1Ptr sigSPtr) = _certSignaturePtrs(certificate);
        bytes memory twinS = _malleatedS(certificate, sigSPtr);

        int256 delta = int256(twinS.length) - int256(sigSPtr.totalLength());
        result = _replaceNode(certificate, sigSPtr, twinS, delta);

        _writeDerLength(result, root, _addDelta(root.length(), delta));
        _writeDerLength(result, sigPtr, _addDelta(sigPtr.length(), delta));
        _writeDerLength(result, sigRoot, _addDelta(sigRoot.length(), delta));
    }

    function _appendTbsTrailingField(bytes memory certificate) internal pure returns (bytes memory result) {
        Asn1Ptr root = certificate.root();
        Asn1Ptr tbsPtr = certificate.firstChildOf(root);
        bytes memory nullField = hex"0500";
        int256 delta = int256(nullField.length);
        result = _insertBytes(certificate, tbsPtr.content() + tbsPtr.length(), nullField);

        _writeDerLength(result, root, _addDelta(root.length(), delta));
        _writeDerLength(result, tbsPtr, _addDelta(tbsPtr.length(), delta));
    }

    function _appendSignatureTrailingField(bytes memory certificate) internal pure returns (bytes memory result) {
        (Asn1Ptr root, Asn1Ptr sigPtr, Asn1Ptr sigRoot,) = _certSignaturePtrs(certificate);
        bytes memory extraInteger = hex"020100";
        int256 delta = int256(extraInteger.length);
        result = _insertBytes(certificate, sigRoot.content() + sigRoot.length(), extraInteger);

        _writeDerLength(result, root, _addDelta(root.length(), delta));
        _writeDerLength(result, sigPtr, _addDelta(sigPtr.length(), delta));
        _writeDerLength(result, sigRoot, _addDelta(sigRoot.length(), delta));
    }

    function _insertBytes(bytes memory input, uint256 offset, bytes memory inserted)
        internal
        pure
        returns (bytes memory result)
    {
        result = new bytes(input.length + inserted.length);
        for (uint256 i = 0; i < offset; ++i) {
            result[i] = input[i];
        }
        for (uint256 i = 0; i < inserted.length; ++i) {
            result[offset + i] = inserted[i];
        }
        for (uint256 i = offset; i < input.length; ++i) {
            result[i + inserted.length] = input[i];
        }
    }

    function _extensions(bytes memory extensionList) internal pure returns (bytes memory) {
        return _derNode(0xa3, _derNode(0x30, extensionList));
    }

    function _basicConstraintsExtension() internal pure returns (bytes memory) {
        return _derNode(0x30, bytes.concat(hex"0603551d13", hex"0101ff", _derNode(0x04, hex"30060101ff020100")));
    }

    function _basicConstraintsExtensionWithTrailingField() internal pure returns (bytes memory) {
        return
            _derNode(0x30, bytes.concat(hex"0603551d13", hex"0101ff", _derNode(0x04, hex"30060101ff020100"), hex"0500"));
    }

    function _keyUsageExtension() internal pure returns (bytes memory) {
        return _derNode(0x30, bytes.concat(hex"0603551d0f", hex"0101ff", _derNode(0x04, hex"03020186")));
    }

    function _derNode(bytes1 tag, bytes memory content) internal pure returns (bytes memory der) {
        require(content.length < 128, "test: long-form length not supported");
        der = new bytes(2 + content.length);
        der[0] = tag;
        der[1] = bytes1(uint8(content.length));
        for (uint256 i = 0; i < content.length; ++i) {
            der[2 + i] = content[i];
        }
    }

    function _certSignaturePtrs(bytes memory certificate)
        internal
        pure
        returns (Asn1Ptr root, Asn1Ptr sigPtr, Asn1Ptr sigRoot, Asn1Ptr sigSPtr)
    {
        root = certificate.root();
        Asn1Ptr tbsCertPtr = certificate.firstChildOf(root);
        Asn1Ptr sigAlgoPtr = certificate.nextSiblingOf(tbsCertPtr);
        sigPtr = certificate.nextSiblingOf(sigAlgoPtr);
        Asn1Ptr sigBPtr = certificate.bitstring(sigPtr);
        sigRoot = certificate.rootOf(sigBPtr);
        Asn1Ptr sigRPtr = certificate.firstChildOf(sigRoot);
        sigSPtr = certificate.nextSiblingOf(sigRPtr);
    }

    function _malleatedS(bytes memory certificate, Asn1Ptr sigSPtr) internal pure returns (bytes memory) {
        (uint128 shi, uint256 slo) = certificate.uint384At(sigSPtr);
        (uint128 twinHi, uint256 twinLo) = _p384OrderMinus(shi, slo);
        return _derEncodeP384Integer(abi.encodePacked(twinHi, twinLo));
    }

    function _replaceNode(bytes memory certificate, Asn1Ptr ptr, bytes memory replacement, int256 delta)
        internal
        pure
        returns (bytes memory result)
    {
        result = new bytes(_addDelta(certificate.length, delta));

        uint256 prefixLen = ptr.header();
        for (uint256 i = 0; i < prefixLen; ++i) {
            result[i] = certificate[i];
        }
        for (uint256 i = 0; i < replacement.length; ++i) {
            result[prefixLen + i] = replacement[i];
        }

        uint256 suffixStart = ptr.header() + ptr.totalLength();
        uint256 suffixLen = certificate.length - suffixStart;
        uint256 resultSuffixStart = prefixLen + replacement.length;
        for (uint256 i = 0; i < suffixLen; ++i) {
            result[resultSuffixStart + i] = certificate[suffixStart + i];
        }
    }

    function _p384OrderMinus(uint128 hi, uint256 lo) internal pure returns (uint128 twinHi, uint256 twinLo) {
        uint128 nHi = type(uint128).max;
        uint256 nLo = 0xffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973;
        uint128 borrow = lo > nLo ? 1 : 0;
        unchecked {
            twinHi = nHi - hi - borrow;
            twinLo = nLo - lo;
        }
    }

    function _addDelta(uint256 value, int256 delta) internal pure returns (uint256) {
        return delta < 0 ? value - uint256(-delta) : value + uint256(delta);
    }

    function _writeDerLength(bytes memory der, Asn1Ptr ptr, uint256 length) internal pure {
        uint256 headerLen = ptr.content() - ptr.header();
        if (headerLen == 2) {
            require(length < 128, "short length overflow");
            der[ptr.header() + 1] = bytes1(uint8(length));
        } else if (headerLen == 3) {
            require(der[ptr.header() + 1] == 0x81, "expected 0x81 length");
            require(length < 256, "0x81 length overflow");
            der[ptr.header() + 2] = bytes1(uint8(length));
        } else if (headerLen == 4) {
            require(der[ptr.header() + 1] == 0x82, "expected 0x82 length");
            require(length < 65536, "0x82 length overflow");
            der[ptr.header() + 2] = bytes1(uint8(length >> 8));
            der[ptr.header() + 3] = bytes1(uint8(length));
        } else {
            revert("unsupported length header");
        }
    }

    function testFuzz_uint384At_LeadingZeros(uint8 numZeros, uint128 hiSeed, uint256 loSeed) public view {
        numZeros = uint8(bound(numZeros, 0, 16));

        uint128 expectedHi;
        uint256 expectedLo;

        if (numZeros == 16) {
            expectedHi = 0;
            expectedLo = loSeed | (uint256(1) << 248);
        } else {
            uint128 mask = type(uint128).max >> (numZeros * 8);
            expectedHi = (hiSeed & mask) | (uint128(1) << ((15 - numZeros) * 8));
            expectedLo = loSeed;
        }

        bytes memory scalar48 = abi.encodePacked(expectedHi, expectedLo);
        bytes memory der = _derEncodeP384Integer(scalar48);

        uint256 contentLen = uint256(uint8(der[1]));
        (uint128 hi, uint256 lo) = harness.uint384At(der, 0, 2, contentLen);

        assertEq(hi, expectedHi);
        assertEq(lo, expectedLo);
    }

    function _derEncodeP384Integer(bytes memory scalar48) internal pure returns (bytes memory) {
        require(scalar48.length == 48);

        uint256 i = 0;
        while (i < 48 && scalar48[i] == 0) {
            i++;
        }

        if (i == 48) return hex"020100";

        uint256 minLen = 48 - i;
        bool needsPad = uint8(scalar48[i]) >= 0x80;
        uint256 contentLen = needsPad ? minLen + 1 : minLen;

        bytes memory der = new bytes(2 + contentLen);
        der[0] = 0x02;
        der[1] = bytes1(uint8(contentLen));

        uint256 offset = 2;
        if (needsPad) {
            der[offset] = 0x00;
            offset++;
        }

        for (uint256 j = i; j < 48; j++) {
            der[offset] = scalar48[j];
            offset++;
        }

        return der;
    }

    function _patternBytes(uint256 len) internal pure returns (bytes memory out) {
        out = new bytes(len);
        for (uint256 i = 0; i < len; i++) {
            out[i] = bytes1(uint8(i + 1));
        }
    }

    function _clientExtensionsWith(bytes memory extraExtension) internal pure returns (bytes memory) {
        bytes memory body =
            abi.encodePacked(hex"300c0603551d130101ff04023000", hex"300e0603551d0f0101ff040403020780", extraExtension);

        return
            abi.encodePacked(
                bytes1(0xa3), bytes1(uint8(body.length + 2)), bytes1(0x30), bytes1(uint8(body.length)), body
            );
    }
}

/// @dev Exposes the internal revocation-chain walk and lets tests seed the `verifiedParent`
///      cache directly so the broken-chain (fail-closed) behaviour can be exercised in isolation.
contract RevocationChainHarness is CertManager {
    constructor() CertManager(new P384Verifier()) {}

    function setParent(bytes32 child, bytes32 parent) external {
        verifiedParent[child] = parent;
    }

    function requireCachedChainNotRevoked(bytes32 certHash) external view {
        _requireCachedChainNotRevoked(certHash);
    }
}

/// @dev Regression coverage for BLOCKSEC-5249 finding L-01: `_requireCachedChainNotRevoked`
///      previously fell through and returned silently when a cached chain terminated at
///      bytes32(0) without reaching the pinned root, i.e. it failed open on a broken chain.
contract RequireCachedChainNotRevokedTest is Test {
    RevocationChainHarness internal cm;

    bytes32 internal constant CHILD = bytes32(uint256(1));
    bytes32 internal constant PARENT = bytes32(uint256(2));

    function setUp() public {
        cm = new RevocationChainHarness();
    }

    function test_PassesWhenChainReachesPinnedRoot() public {
        bytes32 root = cm.ROOT_CA_CERT_HASH();
        cm.setParent(CHILD, PARENT);
        cm.setParent(PARENT, root);
        // Walks CHILD -> PARENT -> ROOT and returns without reverting.
        cm.requireCachedChainNotRevoked(CHILD);
    }

    function test_RevertsWhenChainDoesNotReachRoot() public {
        // verifiedParent[PARENT] is unset (bytes32(0)), so the chain is broken: it can never
        // reach ROOT_CA_CERT_HASH. The fixed function must fail closed instead of returning.
        cm.setParent(CHILD, PARENT);
        vm.expectRevert(CertManager.IncompleteCertChain.selector);
        cm.requireCachedChainNotRevoked(CHILD);
    }

    function test_RevertsOnZeroCertHash() public {
        vm.expectRevert(CertManager.IncompleteCertChain.selector);
        cm.requireCachedChainNotRevoked(bytes32(0));
    }
}

/// @dev Regression coverage for BLOCKSEC-5249 finding I-02: `CertRevoked` / `CertUnrevoked` now
///      include the acting `msg.sender` as an indexed topic so revocation activity is monitorable.
contract CertRevocationEventTest is Test {
    CertManager internal cm;

    event CertRevoked(bytes32 indexed certHash, address indexed account);
    event CertUnrevoked(bytes32 indexed certHash, address indexed account);

    bytes32 internal constant CERT_ID = bytes32(uint256(0xabc));

    function setUp() public {
        // Deployer is both owner and revoker, so this contract can revoke/unrevoke directly.
        cm = new CertManager(new P384Verifier());
    }

    function test_RevokeCertEmitsSender() public {
        vm.expectEmit(true, true, false, true, address(cm));
        emit CertRevoked(CERT_ID, address(this));
        cm.revokeCert(CERT_ID);
    }

    function test_RevokeCertsEmitsSender() public {
        bytes32[] memory ids = new bytes32[](1);
        ids[0] = CERT_ID;
        vm.expectEmit(true, true, false, true, address(cm));
        emit CertRevoked(CERT_ID, address(this));
        cm.revokeCerts(ids);
    }

    function test_UnrevokeCertEmitsSender() public {
        cm.revokeCert(CERT_ID);
        vm.expectEmit(true, true, false, true, address(cm));
        emit CertUnrevoked(CERT_ID, address(this));
        cm.unrevokeCert(CERT_ID);
    }

    /// @dev The recorded account is the actual caller, not the contract: a delegated revoker
    ///      address shows up in the event topic.
    function test_RevokeCertRecordsActualCaller() public {
        address delegatedRevoker = address(0xBEEF);
        cm.setRevoker(delegatedRevoker);

        vm.expectEmit(true, true, false, true, address(cm));
        emit CertRevoked(CERT_ID, delegatedRevoker);
        vm.prank(delegatedRevoker);
        cm.revokeCert(CERT_ID);
    }
}
