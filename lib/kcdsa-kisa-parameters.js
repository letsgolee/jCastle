const jCastle = require('./jCastle');
require('./kcdsa');

// parameters that kisa provides

jCastle.pki.kcdsa._kisaParams = {};

jCastle.pki.kcdsa._kisaParams['2048-224'] = [
    { // sha-224
        p:  "cbf3fa53 dee5655e 91b58c31 f384c97c 72787f6d 888cd115 c5cf0b38 6c0ebd08" +
            "55d8b713 afcc9f50 886af3b9 83380bf2 6e6397e0 03a2182b 93b711c3 13403b8b" +
            "c721528a 291cbefb 59310b09 a3600ff4 4292d75c 7e790228 c54bbe29 56980bd4" +
            "4cf36adb 1e829c76 98763c5a 3233444f 1a028260 14f4f431 a811e70b 2a18ad17" +
            "e66d4e5d 0c1160a0 0a6828da 031fe7d5 93bb0397 57f7fa0f b06e0e90 828b4f8f" +
            "1b9cc9ae 7e3788d5 7593b18b 51a5cdfc 2e1c416b 380709ea 302f5894 47dcf43f" +
            "a5529ea3 94351cfe ff235694 3ff5000c e582ccfc b34af9be f042e399 3bc0e916" +
            "a5448e9f 3a4f10c6 dd92751b b729b800 8c9f803e 46661df5 c95d11be 8da8c1b5".replace(" ", ''),

        q:  "79a51f53 537f32cc 2a3bb997 e54650f2 fd1be7fe 1ec103cd 864f1884".replace(" ", ''),

        g:  "85681c4e 9b64673f 5e3734e7 f2c9dea3 6ac5de17 400be9e9 f9127cb4 3b9cbe48" +
            "1a7b45c8 2784afe4 ef546241 79c04707 387e7ec9 185c8258 f2317f45 3d1704ee" +
            "2c0580b0 21512d5d e81661f3 85cc9ce2 9147eeaf 167b9434 b5c7653a 27ed1912" +
            "7813d054 e281f7fe bd9be354 e7db16fc e63c605e 358896c4 9d3c3c6f 22c6a3f9" +
            "74ef4839 5bc72556 e68ba17d 17c999db 69850a56 f3480183 6c62f4ec f36618f7" +
            "5104ad03 6953c0c8 2baeb6f0 bada8da6 0b954f25 f7704e99 ea7f8002 2f6e7ee8" +
            "367e4ec7 3ea302d2 1b2dfb0a 854fd93c b24b45cd 68c1eb57 b6e9eb03 7a225044" +
            "0d00c14a 67a6f61c 3edb21aa d385a357 8b079e4a 7a9a5a96 7a414d16 0e9be1f8".replace(" ", '')
    },
    { // sha-256
        p:  "B3C61C13 2194E0D2 9FE9A1E1 8090221F 24EE1611 D1DDDBED 6D4896D0 0A18D49A" +
            "B02DE042 B3F67B66 0BB8FBF9 1C846242 C083991E 14E2567F B0EF6F1A E989B74A" +
            "47628ABC 1F5E1C12 4C66FC09 D40F910B 5B69542E 03F60C10 4937FEDC F684C570" +
            "A9D88FFB 2B26FFED 9648E276 3F070C89 C62F3BC2 828C31EB 8CC2DF0D A54DB7E9" +
            "6DF337D7 34736388 50B386CA 013476D5 08F82601 75159D66 B82370E2 8A3163CF" +
            "E76E93C6 B7F31BF3 29C90E82 6286D964 4088BCBB F4FD27C8 B39F3158 8F7DA5E9" +
            "AC4EF29C B0C6245C F357BD6F 4636A5DE 3A83F8FB 475D78F9 E14C4AFC 35F724BF" +
            "A0D9B98E 2C14F8B8 2C579932 FB16FEB1 9634F7D3 E2A99043 CDBCC00C C3159A30".replace(" ", ''),

        q:  "1e46ae0d 6c7212eb a9eb0cb9 ac9bf881 78246e92 316bd80e bb6a5c40".replace(" ", ''),

        g:  "6FF920BC 7458F898 515537EE 874250ED C01B4245 715329A2 BC5ECFF9 D6529B40" +
            "3A18C06E 46A2557C 1A38592D F08F92AC 75A29E74 08C4A9EF 6692AB82 A5A54E87" +
            "70F5CF19 88ACB5C6 F3EAE17F 1A155C29 5902F6CC 2EDF4E00 1534C63F 13A8B241" +
            "BCD28B77 35EAB4E0 DB270C21 2790E86B 37E7699A EBC330A1 FDFEA922 9BADEAE5" +
            "D81C78A5 FBAAAC80 3625D5A1 14FFC69F BD371FA0 7E0AAE62 A9693AA8 61BC46C0" +
            "738DA7A8 52CBC3D5 0EF3274E DD70BCE4 3284775B 45CAFE2E 45C4B7E4 B90641F8" +
            "F8012956 E5FB52A5 07689A93 1E8A09FA D50BFB42 1B25ADAD AC73ED1F 0DAE9601" +
            "C51B0F29 1DB282E1 F4226F18 49076EE1 453342B7 18F04DBD B67465B7 487844C0".replace(" ", '')
    }
];

jCastle.pki.kcdsa._kisaParams['2048-256'] = [
    {
        p:  "c316c4ef 75de580e 308dd691 b5f778d5 aea5267f 675549b4 baf660ef 5ede6a8b" +
            "1c51d492 1d1387d8 cb4297fe 9e98a2c3 4fd4da1c 0cc0ed54 ecdc431a cd4be4e9" +
            "768114c9 16128197 9b3b5ffe af454b7b e22dac5c 45ec6cf3 eede9cff 561397ab" +
            "da7aca50 19d4a90d d5cfd270 fa511b5e f26e54c0 f4a5c0d2 ed4d3062 f3cd58a1" +
            "c06f8283 6a357f02 4f6e5fb8 f08825ba f1708173 67bc4cb1 2e18840b 826c7508" +
            "d192284b 4cf0ab6c e64d47ee 924e0968 bc2540d2 f39cfd32 17ee768c 26b84707" +
            "50ec5272 eea0e504 1c8febf4 0e674a86 3f6b5877 cdbc44af 458b0667 16a66751" +
            "c6def6f4 f07b4194 4776f95c 2a012684 ad1c3173 2970b578 75b3ac7f d06eb9f2".replace(" ", ''),

        q:  "7f6ffd65 43ffedf9 33128ff1 a0077917 c4cb8187 db100d91 75b5610f cfefed9c".replace(" ", ''),

        g:  "b953206c 8c1be717 3f83951a 954cba47 d5d75b1b 3987b348 45712054 74845a3d" +
            "ae781a75 f80fd32c f1fe2da5 cc467fb7 2a6db325 32f68f28 0dcea4c1 fb73fccb" +
            "997a2d9b 53d13152 7e4268c0 bf676c9f 3fe71f10 f1154f73 56c2d128 352ed26b" +
            "1789c74d da447fd4 d6bed194 d3ed865c 58c18559 08aeb2c6 0862cdce f385824c" +
            "079778b4 58b729bc 2207e4e3 7596c621 939660a5 c5aba363 5285a081 0d30d1a9" +
            "7f186d98 8b216b86 6b65dc65 6b7b3ed7 6bb226c6 a2cf31cf 37c05780 e30d3195" +
            "f982fb99 9ed4e535 84ab9caa 09ee35ff 419c158b 3adcdae0 d3e025d8 aeeb5c9e" +
            "1b0df1dc 5739b986 28d43204 037ac187 b07034af 369dd782 dfa5e5ce 023fec34".replace(" ", '')
    }
];

jCastle.pki.kcdsa._kisaParams['3072-256'] = [
    {
        p:  "9eb85603 c55eca06 e83a318e 1b619b04 c4d65e06 f23e3e02 62be1d85 ca06a300" +
            "87c676a3 c72594a3 bd0e06df dda226c7 f0663a0a aa8bce8f 83ed66f7 b6615508" +
            "692e0ddb d96982c9 33d2b9aa 3d032d18 8539ac78 e1d62d05 172f2648 cb4ad58f" +
            "ca2f4904 3704535f de7737ee 73784334 ba984a2b 115a9fee 8f7f1db3 434f0534" +
            "6a7f9bd7 2639616f ebe43218 5841f198 bd8a4751 40dba3be 594020c2 a12a3625" +
            "9ee5e561 02cd7a31 484eaa63 28bf930f 3b6d3001 32600443 a0c9940a f400c42b" +
            "2bd04b92 05a1f490 6e97adcd 3fdaa347 5d0ca66c 5d6117b8 7a9dccc6 ec71e5a9" +
            "3531bdd9 830b8461 195bcbba f002a2e8 eb0f1c22 8a6aeb20 1055efea 5f08d161" +
            "62d7eb79 8475a422 8db58b84 be5548d7 7e4114b6 edd40818 1007e017 e891933c" +
            "1ee4674b 5040e309 35d09a0e 402fc89b 0919b7e8 702ab6ef 8f6c48c3 eefd4291" +
            "3f3571cc fb77dc4c c16dfb1c 3ecc8887 5e5844f3 31609874 3415bc22 5008c27a" +
            "2d1ee681 813b097d 515839bf 4143b466 2b8b0f43 b2e49c00 677e98ad cbaeace3".replace(" ", ''),

        q:  "a760a401 5d9b872f f2667acb b07f31a8 4eaba3cb 66f2ec13 87180079 c2a8caf4".replace(" ", ''),

        g:  "a942d777 ed2fb547 9a91c2a4 b002215d 5a6469c9 240a5e64 f1f2e7b1 1c06dadc" +
            "ecadc15a aa7e2af2 64bf0238 9fbff84b 53a84ffc 18017b09 a9371c28 b30fc8b8" +
            "31f29528 aed51403 7874fb3d c566516b 5f545012 fe59d32e 8eb00f4c 667c07d8" +
            "c7b6077c edd63047 922a4af3 5645e060 88f6df91 9729e8c0 5c2bc161 6431bc52" +
            "523656a0 98184d73 95c1e0b1 dd0ffc3d 8cc6f496 e8d70a83 612b746f b7482796" +
            "2bff804f 6f574504 32be1905 2d2ad2ed 4d878b48 51509f97 eb89452d 41512fc3" +
            "673a3b1f 5b16792d 55bc30fa d11dda09 baf9a850 4f4f8515 d4e1574e 9b856298" +
            "4cc37e71 5d17289c 5b69c16c e7e06f81 258dbfce 8a840330 121e37d9 373127a2" +
            "c9b6d5a9 bcb3d0ee 1f495bb8 6706e5fe 31fcd33a fcb9c259 0778863f 119eccde" +
            "cd541037 79a85a90 a4b014bc 791c2729 b9caf18f 613fa35d 0c09d631 814e4352" +
            "fba82b45 5409268b b7c3d79a 4e33ad89 1e8acacb c86f31e2 c23252a4 a4b1bba4" +
            "87133749 e026f1f3 c9b678b4 0010848f 63f1bb4f 5149be43 af836cc8 17a1c167".replace(" ", '')
    }
];

/**
 * gets parameters that KISA supplies.
 * 
 * @public
 * @param {number} pbits p bits in number.
 * @param {number} qbits q bits in number.
 * @param {number} i if given, i-th object is returned.
 * @returns parameters object.
 */
jCastle.pki.dsa.getKisaParameters = function(pbits, qbits, i)
{
    var bits = pbits + '-' + qbits;

	if (typeof jCastle.pki.kcdsa._kisaParams[bits] == 'undefined') return null;

	if (typeof i == 'undefined' || i == null || i >= jCastle.pki.kcdsa._kisaParams[bits].length) {
		var i = Math.floor(Math.random() * (jCastle.pki.kcdsa._kisaParams[bits].length));
	}

	return jCastle.pki.kcdsa._kisaParams[bits][i];
};
