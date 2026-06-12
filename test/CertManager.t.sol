// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {Test, console} from "forge-std/Test.sol";
import {CertManager} from "../src/CertManager.sol";
import {ICertManager} from "../src/ICertManager.sol";
import {Asn1Decode, LibAsn1Ptr, Asn1Ptr} from "../src/Asn1Decode.sol";
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

contract CertManagerTest is Test {
    Asn1DecodeHarness public harness;

    function setUp() public {
        harness = new Asn1DecodeHarness();
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

    function _verifyCA(CertManager cm, P384HintCollector collector, bytes memory cert, bytes32 parentHash)
        internal
        returns (bytes32)
    {
        bytes memory parentPubKey = cm.loadVerified(parentHash).pubKey;
        bytes memory hints = collector.collectCertSignatureHints(cert, parentPubKey);
        return cm.verifyCACertWithHints(cert, parentHash, hints);
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
}
