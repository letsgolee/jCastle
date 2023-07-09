const jCastle = require('../lib/index');
const QUnit = require('qunit');

QUnit.module('ECKCDSA');
QUnit.test("Step Test", function(assert) {

    // [KISA-WP-2011-0022]_최종보고서.pdf
    // EC-KCDSA_전자서명_알고리즘에_대한_소스코드_활용_매뉴얼.pdf

	var m = //"This is a sample message for EC-KCDSA implementation validation.";
            Buffer.from(
                `54 68 69 73 20 69 73 20 61 20 73 61 6D 70 6C 65 20 6D
                65 73 73 61 67 65 20 66 6F 72 20 45 43 2D 4B 43 44 53
                41 20 69 6D 70 6C 65 6D 65 6E 74 61 74 69 6F 6E 20 76
                61 6C 69 64 61 74 69 6F 6E 2E`.replace(/[^0-9A-F]/gi, ''), 'hex');

    var URAND = 
                //"saldjfawp399u374r098u98^%^%hkrgn;lwkrp47t93c%$89439859kjdmn
                // vcm cvk o4u09r 4j oj2out209xfqw;l*&!^#@U#*#$)(# z xo957tc-95
                // 5 v5oiuv9876 6 vj o5iuv-053,mcvlrkfworet"
                Buffer.from(
                    `73 61 6C 64 6A 66 61 77 70 33 39 39 75 33 37 34 72 30 39
                    38 75 39 38 5E 25 5E 25 68 6B 72 67 6E 3B 6C 77 6B 72 70
                    34 37 74 39 33 63 25 24 38 39 34 33 39 38 35 39 6B 6A 64
                    6D 6E 76 63 6D 20 63 76 6B 20 6F 34 75 30 39 72 20 34 6A
                    20 6F 6A 32 6F 75 74 32 30 39 78 66 71 77 3B 6C 2A 26 21
                    5E 23 40 55 23 2A 23 24 29 28 23 20 7A 20 78 6F 39 35 37
                    74 63 2D 39 35 20 35 20 76 35 6F 69 75 76 39 38 37 36 20
                    36 20 76 6A 20 6F 35 69 75 76 2D 30 35 33 2C 6D 63 76
                    6C 72 6B 66 77 6F 72 65 74`.replace(/[^0-9A-F]/gi, ''), 'hex');


//----------------------------------------------------------------------------------------------------

    var testVectors = [
        // [KISA-WP-2011-0022]_최종보고서.pdf
        {
            curveName: 'secp224r1',
            hashAlgo: 'SHA-224',
            x: "F7F713C5 B8396D6C F926002C EF5BB649 756B845A E67B9797 1996207D",
            Ux: "DBD4F451 3901D6D1 0D6D1BA8 B5FC2278 79DEAEDB 26545EB3 B0B11DFF",
            Uy: "5C91CA9D 2E855B70 6338623D 3D1D3ACB 3D9570F9 8FB28E19 13E50DDC",
            k: "C7FC8AD8 30394C3F 8AE5B1C4 B507287F 126B9CF8 1A5B6220 6F8CA920",
            r: "045C9EC8 91CB4741 EC75C277 BC273C49 345EE055 F94FF9E9 9311B69B",
            s: "AC0CA0C5 B30F066D 369BEC7B A7D22CD8 11849490 98912895 505384C5"
        },
        {
            curveName: 'secp256r1',
            hashAlgo: 'SHA-256',
            x: "72F18E52 29AC104D 502CD0E6 30E997A8 B66B0EA1 9C7B6824 1168E66F 9750571D",
            Ux: "61D4ECD0 385E17FC 300D45EC 7B2630C4 C45A8602 A9CAC191 BF5B1EC6 AA2C3344",
            Uy: "5E6D9361 1B1A6FF6 707269A1 2153313C 0269359D D71E3D20 8E6154D0 AC364C6E",
            k: "08B7FE4B 44541FD7 FA396709 08A2FD7A A58DF7AC 1F9C4B05 3090B32C 9EA5227C",
            r: "CB376EDE B670D86D 53120246 BA2F3CFE 10BF7EF3 97D3133C FC3C2483 022A308A",
            s: "17C6B60D 9CC5340E 89918742 83F94F06 FBD9B8CE 77F8BD93 F9B04A94 250BEF0A"
        },
        {
            curveName: 'sect233r1',
            hashAlgo: 'SHA-224',
            x: "007D 8E64AFE4 8A561354 24003F5E 74EA1DAF 1173106E 0B8978DA 09B155E4",
            Ux: "01F9 CFF8FB6D 1D6DF446 13C3A422 D11A23E4 AFC4AE3D DDE9F4E1 502AD897",
            Uy: "007F 16D737E6 A6B61A73 947E029F DF52465E 96E37287 07F30E26 CBC9C12B",
            k: "0093 274F3DA3 62BB893A CC0354EE 9F13476B E6DD3F76 7CCBD399 C7CC2351",
            r: "14A670CD 402A5889 425ED7C1 5A542AEE A403B302 4E69E0CE 8781B0B9",
            s: "0051 A8548019 C9E1DDE8 E9329B93 476C7F6F 0FB30AEC 861CF02F 0C24EDFC"
        },
        {
            curveName: 'sect233k1',
            hashAlgo: 'SHA-224',
            x: "0052 9FCAB5D8 66DFD672 B409884A 2B4792DA BDD4B642 24138097 7EBF4097",
            Ux: "0155 56B52E19 E2819C0A DAF04EA3 28981411 B0109169 A84334AA C468FF45",
            Uy: "0129 EFE86E19 1CC64D84 B00B9D8A B3561BB0 C1EDCF8B CE0DEF02 0E2ABF84",
            k: "0052 384EE8AB FD08B221 CF3A8AC2 B733B9DE 9DCA5940 36E956EA 7DB86EF8",
            r: "6C976C2F 7BB8E87B 3EE39CA9 604345F2 3562C06F 21E75C8C FD2CC495",
            // s value seems wrong...
            //s: "0064 8CA6FCC9 2F076851 8FBC3C67 62E12F95 6D221726 B3DBE881 DEBD7114"
            s: "0047 5183b13b 4519d798 16abd135 960e1d95 e2cdaa59 75d98435 2f29fe40"
        },
        {
            curveName: 'sect283r1',
            hashAlgo: 'SHA-256',
            x: "01707D42 404C214A 761596DD DE239CE3 3247EC82 05438333 73F868A7 2B4151BE 114ED389",
            Ux: "03FDEFF9 AB79BD20 D4B430D6 D6485CDB 7FC49912 55CE8E1C D9CF63E9 9BAF50FA 46039318",
            Uy: "01B46B5D 365A5E87 ED6F2560 192E3FAB 5A1F2F01 C7012ABF 006BD1C6 372719AC 8FEFB992",
            k: "00221C21 05CF7907 00C06823 F4B9CE5A 57C8FFC7 1EFAFBBB 20AD0756 8641C4EC F6BBEA4A",
            r: "62D1EF31 8EF9A0B1 1C3AF87E 12E1264E 5D91022B 5CC7B2C0 7F04AF56 5651F5D1",
            s: "01455D9C 423B2A11 E79043EC 48C8285D 2C0B2F83 5A33976A E5CA02CD 702F5060 FE6F4D5B"
        },
        {
            curveName: 'sect283k1',
            hashAlgo: 'SHA-256',
            x: "008EBD15 BBADA367 4396271E 4500F50A CBA2C50B 05C20C4F 155AE3DC C25586AC C1DF3895",
            Ux: "0650C40F FFA7B46C F0B5EA67 57B0CF0C AB3B3229 254654DC 03E44286 799C5E02 57DDA807",
            Uy: "03C2C9DE 5EB409F2 EB77C311 E21A97D4 88B87432 C1E0D3E8 6A2B7FBB 3A39DD25 0B989E2F",
            k: "0058C0E6 3D325866 60DC0496 02DEDAFD 011D6B65 0B0F7CE4 FA3742A7 C6BBA5F3 4BDAF0C8",
            r: "3CF555BE 50FBE678 B5132800 92D8FC54 46364B0A 595DEB84 87CF037D 94255175",
            s: "01C6214D C075CC4E 921AD39C DFCE1E06 C6062214 1F13B982 8B3496E3 4090A6C2 0BD9572B"
        },
        // EC-KCDSA_전자서명_알고리즘에_대한_소스코드_활용_매뉴얼.pdf
        {
            curveName: 'secp224r1',
            hashAlgo: 'SHA-224',
            x: "01ACBF47 AFC7FBC3 B66AFB87 653503DD 2EEA26A2 C41B1F7C 6B2CFA0C",
            Ux: "83BA5F8A A5CACAF3 E53DA022 3302B916 E37C7F8A 49AD49B2 8D4BFD1B",
            Uy: "2EFFCBD6 14B15520 44BBA8C9 73446D66 0FC5D6F0 1EE02E57 0E4F5E01",
            CQ: "83BA5F8A A5CACAF3 E53DA022 3302B916 E37C7F8A 49AD49B2 8D4BFD1B 2EFFCBD6 14B15520 44BBA8C9 73446D66 0FC5D6F0 1EE02E57 0E4F5E01 00000000 00000000", // z
            k: "C0A87AD4 88DD44D4 E280D358 83DC6F5F 3994A616 1BE76F0C 55CBE1BE",
            r: "68724941 E617DAE2 C86A4AD3 E86EBC70 C17108BA 07BC5C1B 57FD016E",
            s: "91E89A1F CE4BCDEF EAF6DD7F 90D40841 0B691560 E6AD294E 4D96DB75"

        },
        {
            curveName: 'secp256r1',
            hashAlgo: 'SHA-256',
            x: "45EC2DF3 E517515A 0C370E56 00C86A20 A851E0A6 5BFE114B F1743778 F0E96EA7",
            Ux: "4829D795 FA134536 7B55BA09 CC6E10DA 20B42DD7 5F980E91 E5EE14EA 75701FF2",
            Uy: "63DB1BE5 9253C399 68CCFD61 22ACC8B7 31F3EACE 2EB005DE 711A1F5E 96ABD97F",
            CQ: "4829D795 FA134536 7B55BA09 CC6E10DA 20B42DD7 5F980E91 E5EE14EA 75701FF2 63DB1BE5 9253C399 68CCFD61 22ACC8B7 31F3EACE 2EB005DE 711A1F5E 96ABD97F",
            k: "2937297B 5522150B A43D13F6 1F7C96D4 A13C24FA BEDA8EA9 A7C5788F 7CFD7C08",
            r: "0055529A E29603F9 D7ACEC4A 2B7A6CC8 51D73155 5EBB8B58 DC7C0C02 CFB35AE6",
            s: "4D1BED4D BADB43A9 A179A708 3FD679E9 4BCF3E1B DFE5E009 792FA35F 65A9487D"
        },
        {
            curveName: 'sect233r1',
            hashAlgo: 'SHA-224',
            x: "0014 9E2839BF 5D8A3D45 4BAFF06B 1D55BF6E 7D6B4A6F FCEF7186 43CD8A32",
            Ux: "0025 885FB064 D502E6C1 5B2FCC1E A3F754CE DAE8EE72 B9174985 A2001959",
            Uy: "017F F5C2728D 5D061755 465AFA4E F1DC210F 187CCD1B D77D1A1D 79B88BA4",
            CQ: "0025 885FB064 D502E6C1 5B2FCC1E A3F754CE DAE8EE72 B9174985 A2001959 017F F5C2728D 5D061755 465AFA4E F1DC210F 187CCD1B D77D1A1D 79B88BA4 00000000",
            k: "007D 7E9217F0 C1A2FAD7 3E2C87C1 D7960129 E44AB719 2BDDFFE9 682F038D",
            r: "F841CA66 BEEDE524 30F7EB36 DF51B414 5BB55141 2ABF33F5 DBF975D0",
            s: "00F3 BC272749 4F20D87D 337A25A8 4B093477 E14224E4 051EFF77 8DE0C109"
        },
        {
            curveName: 'sect283r1',
            hashAlgo: 'SHA-256',
            x: "02DD9C90 3B331504 B0CC6C70 C27DAA62 6A495515 E916BBA8 38061E47 53631D47 7E61BE50",
            Ux: "0053CE71 6D824F2E CBDCA246 6A856706 98EBDC09 9293D098 F842FF61 3318928B E110B0C6",
            Uy: "0318D683 521F30CD 3ECA4B4F 9A15B971 CDB74CB1 09405211 4ABB81B2 EFC8C979 E9D68406",
            CQ: "0053CE71 6D824F2E CBDCA246 6A856706 98EBDC09 9293D098 F842FF61 3318928B E110B0C6 0318D683 521F30CD 3ECA4B4F 9A15B971 CDB74CB1 09405211 4ABB81B2",
            k: "021F6389 3CB306A4 8DE92F4D EF13B440 3D6098A1 B42A4238 65F58C36 41DEA601 0CB000C6",
            r: "0E4283DE 967381DA 09C68579 73B27074 43145ED8 D869E832 BA25A070 9EC7D83D",
            s: "014D6F79 D2964596 5F780D2A E20AC406 3D66BA96 74B634A2 569DCDA0 BBD8A4A1 C78DF9DA"
        },
        {
            curveName: 'sect233k1',
            hashAlgo: 'SHA-224',
            x: "0009 B8E708FC ADFE22BE 4C96B24B 9569AEDF BD6D6023 994F22DE BB097BDE",
            Ux: "016A 936F51F3 D05BEBEF 2D42DDFA 1D898DDA 6C765CA6 DBCC4793 AE7C205E",
            Uy: "019F A4858BE7 67671E69 AD432C01 93836F1F 73F54836 F321EFA8 03C8757B",
            CQ: "016A 936F51F3 D05BEBEF 2D42DDFA 1D898DDA 6C765CA6 DBCC4793 AE7C205E 019F A4858BE7 67671E69 AD432C01 93836F1F 73F54836 F321EFA8 03C8757B 00000000",
            k: "0017 4CDB5754 1136C2AA 6C22F593 4CE0E4A7 7087AAC4 951DD5F4 151ADB87",
            r: "275706D8 29B182D2 87E74FC4 5ABEA542 EBC382AC 254C8C41 D7BC48FB",
            s: "24 F5EFE26A 2672D543 CAAC3EB3 804B4A3F 9E3928F1 04DD997A 755B2C2D"
        },
        {
            curveName: 'sect283k1',
            hashAlgo: 'SHA-256',
            x: "0168A841 65B6A894 8C7C9EFC FD862092 A1FE038C 6146A342 4CEFC2BD 482A2042 FFF036B7",
            Ux: "01E0E2D4 E0384F55 93376692 5B09E749 3B87E259 726C3A47 CF7C69A3 186BCDBE 49F2E3BB",
            Uy: "05D3A212 43FA70EE 5DC5E8D7 9097FBC8 1AABECEC E2511C64 57478857 EFA74991 EA39E684",
            CQ: "01E0E2D4 E0384F55 93376692 5B09E749 3B87E259 726C3A47 CF7C69A3 186BCDBE 49F2E3BB 05D3A212 43FA70EE 5DC5E8D7 9097FBC8 1AABECEC E2511C64 57478857",
            k: "0089D874 CD2ED390 EB095FCD 5385E648 0CDFC5F9 32CF2455 78FC9578 AF8B3AE9 8D8AC2EB",
            r: "717EF611 4D356F8F 0C46645F 072678FB 2E524639 46B555C2 4182A22E 70E27C07",
            s: "00E9E272 E3736C51 98B16F4D 2377AA3A 4245CD3C A324B83D 271818F9 637707C7 43F13713"
        }
    ];

    for (var i = 0; i < testVectors.length; i++) {

        var vector = testVectors[i];

        var pkey = new jCastle.pki('ECKCDSA');

        //console.log('Curve: ' + vector.curveName);
        pkey.setParameters(vector.curveName);
    
        var ecInfo = pkey.getCurveInfo();

        var x_i = BigInt('0x' + vector.x.replace(/[^0-9A-F]/gi, ''));

        pkey.setPrivateKey(x_i);

        var privkey = pkey.getPrivateKey();
        var pubkey = pkey.getPublicKey();

        // publc key test

        assert.ok(pubkey.getX().toBigInt().equals(BigInt('0x' + vector.Ux.replace(/[^0-9A-F]/gi, ''))), 'public key x test');
        assert.ok(pubkey.getY().toBigInt().equals(BigInt('0x' + vector.Uy.replace(/[^0-9A-F]/gi, ''))), 'public key y test');

        // signing test

        var l = jCastle.digest.getBlockSize(vector.hashAlgo);
        var z = pubkey.encodePoint().slice(1);
        if (z.length < l) {
            z = Buffer.concat([z, Buffer.alloc(l - z.length, 0x00)]);
        }
        if (z.length > l) {
            z = z.slice(0, l);
        }

        var ba = Buffer.from(m);
        var hash = new jCastle.digest(vector.hashAlgo).start().update(z).update(ba).finalize();
        var hash_bi = BigInt.fromBufferUnsigned(hash);

        // Generate a random number k, such that 0 < k < q.
        //var rng = new jCastle.prng();

        var k = BigInt('0x' + vector.k.replace(/[^0-9A-F]/gi, ''));

        var zero = 0n;

        // (x1, y1) = kG
		var w = ecInfo.G.multiply(k);

        var w_x = w.encodePoint(true).slice(1);
        var r = new jCastle.digest(vector.hashAlgo).digest(w_x);

        var v_r = r.equals(Buffer.from(vector.r.replace(/[^0-9A-F]/gi, ''), 'hex'));
		assert.ok(v_r, 'r test');
        // if (!v_r) {
        //     console.log(r.toString('hex'));
        //     console.log(vector.r.replace(/[^0-9A-F]/gi, ''));
        //     console.log('w_x: ', w_x);
        //     console.log('w_x length: ', w_x.length);
        //     console.log((ecInfo.n.bitLength() + 7) >>> 3);
        // }

		var r_i = BigInt.fromBufferUnsigned(r);

		// v = H(z || M)
		// e = r ⊕ v mod n
		var e = r_i.xor(hash_bi).mod(ecInfo.n);

		// computes the second part s of the signature as s = x(k - e)mod q
        var t = k.subtract(e).mod(ecInfo.n);
        while(t.compareTo(zero) <= 0) t = t.add(ecInfo.n);
        //var t = k.subtract(e);
		var s = privkey.multiply(t).mod(ecInfo.n);

        var v_s = s.equals(BigInt('0x' + vector.s.replace(/[^0-9A-F]/gi, '')));
		assert.ok(v_s, 's test');
        // if (!v_s) {
        //     console.log('s:   ', s.toString(16));
        //     console.log('s_v: ', vector.s.replace(/[^0-9A-F]/gi, ''));
        //     console.log('z:   ', z.toString('hex'));
        //     console.log('hash:', hash.toString('hex'));
        //     console.log('e:   ', e.toString(16));
        // }

        // verifying test
        // ---------------------------------------------------------------------------------

        // computes e = r ⊕ h(z || m) mod n, 
        var r_i = BigInt.fromBufferUnsigned(r);
        var e = r_i.xor(hash_bi).mod(ecInfo.n);

        // (x1, y1) = sQ + eG
        var u1 = pubkey.multiply(s);
        var u2 = ecInfo.G.multiply(e);
        var w = u1.add(u2);

        // finally checks if  r = h(w'). 
        var w_x = w.encodePoint(true).slice(1);
        var v = new jCastle.digest(vector.hashAlgo).digest(w_x);
        v = BigInt.fromBufferUnsigned(v);
                
        // If v == r, the digital signature is valid.

        assert.ok(v.compareTo(r_i) === 0, 'sig verify test');
    }
	
});

QUnit.test("Basic Test", function(assert) {

    var m = "This is a sample message for EC-KCDSA implementation validation.";

//----------------------------------------------------------------------------------------------------

	var curve_name = 'secp224r1'
	var hash_name = 'sha-224';

	var pkey = new jCastle.pki('ECKCDSA');

	pkey.setParameters(curve_name);

	pkey.generateKeypair();

    //console.log(pkey);

	var s = pkey.sign(m, {hashAlgo: hash_name});
	var v = pkey.verify(m, s, {hashAlgo: hash_name});

	assert.ok(v, "KCECDSA sign / verify test 2");


//----------------------------------------------------------------------------------------------------


	var curve_name = "sect233r1";
	var hash_name = "SHA-224";

	var pkey = new jCastle.pki('ECKCDSA');

	pkey.setParameters(curve_name);

	pkey.generateKeypair();

	var s = pkey.sign(m, {hashAlgo: hash_name});
	var v = pkey.verify(m, s, {hashAlgo: hash_name});

	assert.ok(v, "KCECDSA sign / verify test 3");

	//console.log(pkey.exportKey("private"));


});