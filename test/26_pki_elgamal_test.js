const jCastle = require('../lib/index');
const QUnit = require('qunit');
const BigInteger = require('../lib/biginteger');


QUnit.module('ElGamal');

QUnit.test("Step Test", function(assert) {
    //https://sources.debian.org/src/python-crypto/2.6.1-9/lib/Crypto/SelfTest/PublicKey/test_ElGamal.py/

    // # Encryption
    var testVectors = [
        {
            // 256 bits
            'p'  :'BA4CAEAAED8CBE952AFD2126C63EB3B345D65C2A0A73D2A3AD4138B6D09BD933',
            'g'  :'05',
            'y'  :'60D063600ECED7C7C55146020E7A31C4476E9793BEAED420FEC9E77604CAE4EF',
            'x'  :'1D391BA2EE3C37FE1BA175A69B2C73A11238AD77675932',
            'k'  :'F5893C5BAB4131264066F57AB3D8AD89E391A0B68A68A1',
            'pt' :'48656C6C6F207468657265',
            'ct1':'32BFD5F487966CEA9E9356715788C491EC515E4ED48B58F0F00971E93AAA5EC7',
            'ct2':'7BE8FBFF317C93E82FCEF9BD515284BA506603FEA25D01C0CB874A31F315EE68'
        },
        {
        // 512 bits
            'p'  :'F1B18AE9F7B4E08FDA9A04832F4E919D89462FD31BF12F92791A93519F75076D6CE3942689CDFF2F344CAFF0F82D01864F69F3AECF566C774CBACF728B81A227',
            'g'  :'07',
            'y'  :'688628C676E4F05D630E1BE39D0066178CA7AA83836B645DE5ADD359B4825A12B02EF4252E4E6FA9BEC1DB0BE90F6D7C8629CABB6E531F472B2664868156E20C',
            'x'  :'14E60B1BDFD33436C0DA8A22FDC14A2CCDBBED0627CE68',
            'k'  :'38DBF14E1F319BDA9BAB33EEEADCAF6B2EA5250577ACE7',
            'pt' :'48656C6C6F207468657265',
            'ct1':'290F8530C2CC312EC46178724F196F308AD4C523CEABB001FACB0506BFED676083FE0F27AC688B5C749AB3CB8A80CD6F7094DBA421FB19442F5A413E06A9772B',
            'ct2':'1D69AAAD1DC50493FB1B8E8721D621D683F3BF1321BE21BC4A43E11B40C9D4D9C80DE3AAC2AB60D31782B16B61112E68220889D53C4C3136EE6F6CE61F8A23A0'
        }
    ];

    for (var i = 0; i < testVectors.length; i++) {
        var vector = testVectors[i];

        var p = new BigInteger(vector.p, 16);
        var g = new BigInteger(vector.g, 16);
        var y = new BigInteger(vector.y, 16);
        var x = new BigInteger(vector.x, 16);
        var k = new BigInteger(vector.k, 16);
        var pt = Buffer.from(vector.pt, 'hex');
        var ct1 = new BigInteger(vector.ct1, 16);
        var ct2 = new BigInteger(vector.ct2, 16);

        var elgamal = jCastle.pki.elGamal.create();
        elgamal.setParameters({
            p, g
        });
        elgamal.setPrivateKey(x, y);

        // public encrypt test

        var m_bi = BigInteger.fromByteArrayUnsigned(pt);

        var c1 = g.modPow(k, p);
		var c2 = m_bi.multiply(y.modPow(k, p)).mod(p);

        assert.ok(ct1.equals(c1), 'c1 test');
        assert.ok(ct2.equals(c2), 'c2 test');

        // private decrypt test

        var m_bi = c1.modPow(p.subtract(x).subtract(BigInteger.ONE), p).multiply(c2).mod(p);

		var ba = Buffer.from(m_bi.toByteArray());

        assert.ok(ba.equals(pt), 'pt test');

    }


    // # Signature
    var testVectors = [
        {
            // 256 bits
            'p'  :'D2F3C41EA66530838A704A48FFAC9334F4701ECE3A97CEE4C69DD01AE7129DD7',
            'g'  :'05',
            'y'  :'C3F9417DC0DAFEA6A05C1D2333B7A95E63B3F4F28CC962254B3256984D1012E7',
            'x'  :'165E4A39BE44D5A2D8B1332D416BC559616F536BC735BB',
            'k'  :'C7F0C794A7EAD726E25A47FF8928013680E73C51DD3D7D99BFDA8F492585928F',
            'h'  :'48656C6C6F207468657265',
            'sig1':'35CA98133779E2073EF31165AFCDEB764DD54E96ADE851715495F9C635E1E7C2',
            'sig2':'0135B88B1151279FE5D8078D4FC685EE81177EE9802AB123A73925FC1CB059A7',
        },
        {
            // 512 bits
            'p'  :'E24CF3A4B8A6AF749DCA6D714282FE4AABEEE44A53BB6ED15FBE32B5D3C3EF9CC4124A2ECA331F3C1C1B667ACA3766825217E7B5F9856648D95F05330C6A19CF',
            'g'  :'0B',
            'y'  :'2AD3A1049CA5D4ED207B2431C79A8719BB4073D4A94E450EA6CEE8A760EB07ADB67C0D52C275EE85D7B52789061EE45F2F37D9B2AE522A51C28329766BFE68AC',
            'x'  :'16CBB4F46D9ECCF24FF9F7E63CAA3BD8936341555062AB',
            'k'  :'8A3D89A4E429FD2476D7D717251FB79BF900FFE77444E6BB8299DC3F84D0DD57ABAB50732AE158EA52F5B9E7D8813E81FD9F79470AE22F8F1CF9AEC820A78C69',
            'h'  :'48656C6C6F207468657265',
            'sig1':'BE001AABAFFF976EC9016198FBFEA14CBEF96B000CCC0063D3324016F9E91FE80D8F9325812ED24DDB2B4D4CF4430B169880B3CE88313B53255BD4EC0378586F',
            'sig2':'5E266F3F837BA204E3BBB6DBECC0611429D96F8C7CE8F4EFDF9D4CB681C2A954468A357BF4242CEC7418B51DFC081BCD21299EF5B5A0DDEF3A139A1817503DDE',
        }
    ];

    for (var i = 0; i < testVectors.length; i++) {
        var vector = testVectors[i];

        var p = new BigInteger(vector.p, 16);
        var g = new BigInteger(vector.g, 16);
        var y = new BigInteger(vector.y, 16);
        var x = new BigInteger(vector.x, 16);
        var k = new BigInteger(vector.k, 16);
        var h = Buffer.from(vector.h, 'hex');
        var sig1 = new BigInteger(vector.sig1, 16);
        var sig2 = new BigInteger(vector.sig2, 16);

        var elgamal = jCastle.pki.elGamal.create();
        elgamal.setParameters({
            p, g
        });
        elgamal.setPrivateKey(x, y);

        // sign test

        var hash_bi = BigInteger.fromByteArrayUnsigned(h);

        var one = BigInteger.valueOf(1);
		var zero = BigInteger.valueOf(0);
		var p1 = p.subtract(one);

        var r = g.modPow(k, p);
        var t = hash_bi.subtract(x.multiply(r)).mod(p1);
        while (t.compareTo(zero) <= 0) t = t.add(p1); 
        var s = k.modInverse(p1).multiply(t).mod(p1);

        assert.ok(r.equals(sig1), 'sig r test');
        assert.ok(s.equals(sig2), 'sig s test');

        // verify test

        var w = g.modPow(hash_bi, p);
		var v = y.modPow(r, p).multiply(r.modPow(s, p)).mod(p);

        assert.ok(w.equals(v), 'sig verify test');
    }
});

QUnit.test("Basic Test", function(assert) {


    //----------------------------------------------------------------------------------------------------
    
    
        var M = Buffer.from("4E636AF98E40F3ADCFCCB698F4E80B9F", 'hex');
    
        //var params = jCastle.ElGamal.generateParameters(1024);
        // for convienence
        var params = jCastle.pki.dsa.getPredefinedParameters(1024);
    
        var alice = new jCastle.pki.elGamal();
        var bob = new jCastle.pki.elGamal();
    
        alice.setParameters(params);
        bob.setParameters(params);
    
        alice.generateKeypair();
        bob.generateKeypair();
    
        var bob_pubkey = bob.getPublicKey('buffer');
        var alice_pubkey = alice.getPublicKey('buffer');
    
        // alice gets the publicKey from bob and encrypts a message.
        // it's because alice's publicKey is different from bob's.
        var ct = alice.publicEncrypt(M, { publicKey: bob_pubkey });
    
        var pt = bob.privateDecrypt(ct);
    
        assert.ok(pt.equals(M), "ElGamal encrypt / decrypt Test");
    
        var hash_name = 'sha-1';
        var s = alice.sign(M, { hashAlgo: hash_name });
        var v = alice.verify(M, s, { hashAlgo: hash_name });
    
        assert.ok(v, "ElGamal sign / verify Test");
    
});