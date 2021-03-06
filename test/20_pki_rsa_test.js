

const jCastle = require('../lib/index');
const QUnit = require('qunit');
const BigInteger = require('../lib/biginteger');

QUnit.module('RSA');

QUnit.test("RSAES-PKCS1-V1_5 Padding Test", function(assert) {

	//
	// NO PADDING
	//

	// http://cryptomanager.com/tv.html

	var msg = Buffer.from('11 22 33 44'.replace(/[^0-9A-F]/gi, ''), 'hex');

	var padding = 'no-padding';

	var e = parseInt('01 00 01'.replace(/[^0-9A-F]/gi, ''), 16);

	var d = Buffer.from(
		`2489108B 0B6AF86B ED9E44C2 336442D5 E227DBA5 5EF8E26A 7E437194 119077F0 
		03BC9C02 7852BB31 26C99C16 D5F1057B C8361DCB 26A5B2DB 4229DB3D E5BD979B 
		2E597D19 16D7BBC9 2746FC07 595C76B4 4B39A476 A65C86F0 86DC9283 CA6D1EEF 
		C1491598 2F9C4CED 5F62A9FF 3BE24218 A99357B5 B65C3B10 AEB367E9 11EB9E21`.replace(/[^0-9A-F]/gi, ''), 'hex');

	var n = Buffer.from(
		`F0C42DB8 486FEB95 95D8C78F 908D04A9 B6C8C77A 36105B1B F2755377 A6893DC4 
		383C54EC 6B5262E5 688E5F9D 9DD16497 D0E3EA83 3DEE2C8E BCD14383 89FCCA8F 
		EDE7A88A 81257E8B 2709C494 D42F723D EC2E0B5C 09731C55 0DCC9D7E 75258989 
		1CBBC302 1307DD91 8E100B34 C014A559 E0E182AF B21A72B3 07CC395D EC995747`.replace(/[^0-9A-F]/gi, ''), 'hex');

	var em = Buffer.from(
		`505B09BD 5D0E66D7 C8829F5B 473ED34D B5CFDBB5 D58CE783 29C8BF85 20E486D3
		C4CF9B70 C6346594 358080F4 3F47EE86 3CFAF2A2 E5F03D1E 13D6FEC5 7DFB1D55
		2224C461 DA411CFE 5D0B05BA 877E3A42 F6DE4DA4 6A965C9B 695EE2D5 0E400894 
		061CB0A2 1CA3A524 B407E9FF BA87FC96 6B3BA945 90849AEB 908AAFF4 C719C2E4`.replace(/[^0-9A-F]/gi, ''), 'hex');

	var rsa = new jCastle.pki.rsa.create();
	rsa.setPrivateKey({
		n, e, d
	});

	var decrypted = rsa.privateDecrypt(em, {
		padding: { mode: padding }, 
		hashAlgo: 'sha-1'
	});

	assert.ok(decrypted.equals(msg), 'no padding decryption test');

	//
	// RSAES-PKCS1-V1_5 encrypt/decrypt
	//

// https://go.dev/src/crypto/rsa/pkcs1v15_test.go
//
// -----BEGIN RSA KEY-----
// MIIBOgIBAAJBALKZD0nEffqM1ACuak0bijtqE2QrI/KLADv7l3kK3ppMyCuLKoF0
// fd7Ai2KW5ToIwzFofvJcS/STa6HA5gQenRUCAwEAAQJBAIq9amn00aS0h/CrjXqu
// /ThglAXJmZhOMPVn4eiu7/ROixi9sex436MaVeMqSNf7Ex9a8fRNfWss7Sqd9eWu
// RTUCIQDasvGASLqmjeffBNLTXV2A5g4t+kLVCpsEIZAycV5GswIhANEPLmax0ME/
// EO+ZJ79TJKN5yiGBRsv5yvx5UiHxajEXAiAhAol5N4EUyq6I9w1rYdhPMGpLfk7A
// IU2snfRJ6Nq2CQIgFrPsWRCkV+gOYcajD17rEqmuLrdIRexpg8N1DOSXoJ8CIGlS
// tAboUGBxTDq3ZroNism3DaMIbKPyYrAqhKov1h5V
// -----END RSA KEY-----

	var n = new BigInteger("9353930466774385905609975137998169297361893554149986716853295022578535724979677252958524466350471210367835187480748268864277464700638583474144061408845077", 10);
	var e = 65537;
	var d = new BigInteger("7266398431328116344057699379749222532279343923819063639497049039389899328538543087657733766554155839834519529439851673014800261285757759040931985506583861", 10);
	var p = new BigInteger("98920366548084643601728869055592650835572950932266967461790948584315647051443", 10);
	var q = new BigInteger("94560208308847015747498523884063394671606671904944666360068158221458669711639", 10);
	var padding = 'RSAES-PKCS1-V1_5';

	var rsa = new jCastle.pki.rsa();
	rsa.setPrivateKey({
		n, e, d, p, q
	});

	var encrypted = [
		{
			em: "gIcUIoVkD6ATMBk/u/nlCZCCWRKdkfjCgFdo35VpRXLduiKXhNz1XupLLzTXAybEq15juc+EgY5o0DHv/nt3yg==",
			msg: "x"
		},
		{
			em: "Y7TOCSqofGhkRb+jaVRLzK8xw2cSo1IVES19utzv6hwvx+M8kFsoWQm5DzBeJCZTCVDPkTpavUuEbgp8hnUGDw==",
			msg: "testing."
		},
		{
			em: "arReP9DJtEVyV2Dg3dDp4c/PSk1O6lxkoJ8HcFupoRorBZG+7+1fDAwT1olNddFnQMjmkb8vxwmNMoTAT/BFjQ==",
			msg: "testing.\n"
		},
		{
			em: "WtaBXIoGC54+vH0NH0CHHE+dRDOsMc/6BrfFu2lEqcKL9+uDuWaf+Xj9mrbQCjjZcpQuX733zyok/jsnqe/Ftw==",
			msg: "01234567890123456789012345678901234567890123456789012"
		},
	];

	for (var i = 0; i < encrypted.length; i++) {
		var vector = encrypted[i];

		var v_msg = rsa.privateDecrypt(Buffer.from(vector.em, 'base64'), {
			padding: { mode: padding }, 
			hashAlgo: 'sha-1'
		});

		assert.ok(v_msg.toString() == vector.msg, 'rsaes-pkcs1-v1_5 padding test ' + (i+1));
	}

	var sig_vectors = [
		{
			msg: "Test.\n", 
			sig: "a4f3fa6ea93bcdd0c57be020c1193ecbfd6f200a3d95c409769b029578fa0e336ad9a347600e40d3ae823b8c7e6bad88cc07c1d54c3a1523cbbb6d58efc362ae"
		},
		// { // unpadded signature
		//     msg: "Thu Dec 19 18:06:16 EST 2013\n",
		//     sig: Buffer.from("pX4DR8azytjdQ1rtUiC040FjkepuQut5q2ZFX1pTjBrOVKNjgsCDyiJDGZTCNoh9qpXYbhl7iEym30BWWwuiZg==", 'base64')
		// }
	];

	for (var i = 0; i < sig_vectors.length; i++) {
		var vector = sig_vectors[i];

		var v = rsa.verify(vector.msg, vector.sig);
		assert.ok(v, 'emsa-pkcs1-v1_5 padding signature test');
	}

	// signature verifying

	var n = new BigInteger("8272693557323587081220342447407965471608219912416565371060697606400726784709760494166080686904546560026343451112103559482851304715739629410219358933351333", 10);
	var e = 65537;

	var rsa = new jCastle.pki.rsa();
	rsa.setPublicKey(n, e);
	var hashAlgo = 'sha-256';
	var msg = "hello";
	var sig = "193a310d0dcf64094c6e3a00c8219b80ded70535473acff72c08e1222974bb24a93a535b1dc4c59fc0e65775df7ba2007dd20e9193f4c4025a18a7070aee93";

	var v = rsa.verify(msg, sig, {
		hashAlgo
	});

	assert.ok(v, 'emsa-pkcs1-v1_5 padding signature test 2');

	//
	// RSAES-OAEP
	//
});

QUnit.test("RSAES-OAEP Padding Test", function(assert) {
/*
rfc3447

   RSAES-OAEP-ENCRYPT ((n, e), M, L)

   Options:
   Hash     hash function (hLen denotes the length in octets of the hash
            function output)
   MGF      mask generation function

   Input:
   (n, e)   recipient's RSA public key (k denotes the length in octets
            of the RSA modulus n)
   M        message to be encrypted, an octet string of length mLen,
            where mLen <= k - 2hLen - 2
   L        optional label to be associated with the message; the
            default value for L, if L is not provided, is the empty
            string

   Output:
   C        ciphertext, an octet string of length k

   Errors:  "message too long"; "label too long"

   Assumption: RSA public key (n, e) is valid

   Steps:

   1. Length checking:

      a. If the length of L is greater than the input limitation for the
         hash function (2^61 - 1 octets for SHA-1), output "label too
         long" and stop.

      b. If mLen > k - 2hLen - 2, output "message too long" and stop.

   2. EME-OAEP encoding (see Figure 1 below):

      a. If the label L is not provided, let L be the empty string. Let
         lHash = Hash(L), an octet string of length hLen (see the note
         below).

      b. Generate an octet string PS consisting of k - mLen - 2hLen - 2
         zero octets.  The length of PS may be zero.

      c. Concatenate lHash, PS, a single octet with hexadecimal value
         0x01, and the message M to form a data block DB of length k -
         hLen - 1 octets as

            DB = lHash || PS || 0x01 || M.

      d. Generate a random octet string seed of length hLen.

      e. Let dbMask = MGF(seed, k - hLen - 1).

      f. Let maskedDB = DB \xor dbMask.

      g. Let seedMask = MGF(maskedDB, hLen).

      h. Let maskedSeed = seed \xor seedMask.

      i. Concatenate a single octet with hexadecimal value 0x00,
         maskedSeed, and maskedDB to form an encoded message EM of
         length k octets as

            EM = 0x00 || maskedSeed || maskedDB.

   3. RSA encryption:

      a. Convert the encoded message EM to an integer message
         representative m (see Section 4.2):

            m = OS2IP (EM).

      b. Apply the RSAEP encryption primitive (Section 5.1.1) to the RSA
         public key (n, e) and the message representative m to produce
         an integer ciphertext representative c:

            c = RSAEP ((n, e), m).

      c. Convert the ciphertext representative c to a ciphertext C of
         length k octets (see Section 4.1):

            C = I2OSP (c, k).

   4. Output the ciphertext C.

   Note.  If L is the empty string, the corresponding hash value lHash
   has the following hexadecimal representation for different choices of
   Hash:

   SHA-1:   (0x)da39a3ee 5e6b4b0d 3255bfef 95601890 afd80709
   SHA-256: (0x)e3b0c442 98fc1c14 9afbf4c8 996fb924 27ae41e4 649b934c
                a495991b 7852b855
   SHA-384: (0x)38b060a7 51ac9638 4cd9327e b1b1e36a 21fdb711 14be0743
                4c0cc7bf 63f6e1da 274edebf e76f65fb d51ad2f1 4898b95b
   SHA-512: (0x)cf83e135 7eefb8bd f1542850 d66d8007 d620e405 0b5715dc
                83f4a921 d36ce9ce 47d0d13c 5d85f2b0 ff8318d2 877eec2f
                63b931bd 47417a81 a538327a f927da3e

   __________________________________________________________________

                             +----------+---------+-------+
                        DB = |  lHash   |    PS   |   M   |
                             +----------+---------+-------+
                                            |
                  +----------+              V
                  |   seed   |--> MGF ---> xor
                  +----------+              |
                        |                   |
               +--+     V                   |
               |00|    xor <----- MGF <-----|
               +--+     |                   |
                 |      |                   |
                 V      V                   V
               +--+----------+----------------------------+
         EM =  |00|maskedSeed|          maskedDB          |
               +--+----------+----------------------------+
   __________________________________________________________________

   Figure 1: EME-OAEP encoding operation.  lHash is the hash of the
   optional label L.  Decoding operation follows reverse steps to
   recover M and verify lHash and PS.
*/
/*
https://www.inf.pucrs.br/~calazans/graduate/TPVLSI_I/RSA-oaep_spec.pdf

Test vectors
============

In this section, we give an example of the process of encrypting 
and decrypting a message with RSAES-OAEP. 
The message is an octet string of length 16, while the size of 
the modulus in the public key is 1024 bits. The second representation
of the private key is used, which means that CRT is applied in the 
decryption process.

The underlying hash function in the EME-OAEP encoding operation is 
SHA-1; the mask generation function is MGF with SHA-1 as specified 
in Section 1.3.3 in part B.1 of this document.

Integers are represented by strings of octets with the leftmost 
octet being the most significant octet.
For example, 9202000 = 8c 69 50.
*/

// RSA key information
// ===================

// n, the modulus:
	var n = Buffer.from(
`bb f8 2f 09 06 82 ce 9c 23 38 ac 2b 9d a8 71 f7 36 8d 07 ee d4 10 43 a4
40 d6 b6 f0 74 54 f5 1f b8 df ba af 03 5c 02 ab 61 ea 48 ce eb 6f cd 48
76 ed 52 0d 60 e1 ec 46 19 71 9d 8a 5b 8b 80 7f af b8 e0 a3 df c7 37 72
3e e6 b4 b7 d9 3a 25 84 ee 6a 64 9d 06 09 53 74 88 34 b2 45 45 98 39 4e
e0 aa b1 2d 7b 61 a5 1f 52 7a 9a 41 f6 c1 68 7f e2 53 72 98 ca 2a 8f 59
46 f8 e5 fd 09 1d bd cb`.replace(/[^0-9A-F]/gi, ''), 'hex');

// e, the public exponent:
	var e = parseInt('0011', 16);

// p, the first prime factor of n:
	var p = Buffer.from(
`ee cf ae 81 b1 b9 b3 c9 08 81 0b 10 a1 b5 60 01 99 eb 9f 44 ae f4 fd a4
93 b8 1a 9e 3d 84 f6 32 12 4e f0 23 6e 5d 1e 3b 7e 28 fa e7 aa 04 0a 2d
5b 25 21 76 45 9d 1f 39 75 41 ba 2a 58 fb 65 99`.replace(/[^0-9A-F]/gi, ''), 'hex');

// q, the second prime factor of n:
	var q = Buffer.from(
`c9 7f b1 f0 27 f4 53 f6 34 12 33 ea aa d1 d9 35 3f 6c 42 d0 88 66 b1 d0
5a 0f 20 35 02 8b 9d 86 98 40 b4 16 66 b4 2e 92 ea 0d a3 b4 32 04 b5 cf
ce 33 52 52 4d 04 16 a5 a4 41 e7 00 af 46 15 03`.replace(/[^0-9A-F]/gi, ''), 'hex');

// dP, p???s exponent:
	var dmp1 = Buffer.from(
`54 49 4c a6 3e ba 03 37 e4 e2 40 23 fc d6 9a 5a eb 07 dd dc 01 83 a4 d0
ac 9b 54 b0 51 f2 b1 3e d9 49 09 75 ea b7 74 14 ff 59 c1 f7 69 2e 9a 2e
20 2b 38 fc 91 0a 47 41 74 ad c9 3c 1f 67 c9 81`.replace(/[^0-9A-F]/gi, ''), 'hex');

// dQ, q???s exponent:
	var dmq1 = Buffer.from(
`47 1e 02 90 ff 0a f0 75 03 51 b7 f8 78 86 4c a9 61 ad bd 3a 8a 7e 99 1c
5c 05 56 a9 4c 31 46 a7 f9 80 3f 8f 6f 8a e3 42 e9 31 fd 8a e4 7a 22 0d
1b 99 a4 95 84 98 07 fe 39 f9 24 5a 98 36 da 3d`.replace(/[^0-9A-F]/gi, ''), 'hex');

// qInv, the CRT coefficient:
	var iqmp = Buffer.from(
`b0 6c 4f da bb 63 01 19 8d 26 5b db ae 94 23 b3 80 f2 71 f7 34 53 88 50
93 07 7f cd 39 e2 11 9f c9 86 32 15 4f 58 83 b1 67 a9 67 bf 40 2b 4e 9e
2e 0f 96 56 e6 98 ea 36 66 ed fb 25 79 80 39 f7`.replace(/[^0-9A-F]/gi, ''), 'hex');

	var rsa = new jCastle.pki.rsa();
	rsa.setPrivateKey({ // d is not given...
		n, e, d: null, p, q, dmp1, dmq1, iqmp
	});

	// Encryption
	// ----------

	var vector = {
// M, the message to be encrypted:
    M: Buffer.from(
`d4 36 e9 95 69 fd 32 a7 c8 a0 5b bc 90 d3 2c 49`.replace(/[^0-9A-F]/gi, ''), 'hex'),

// Label
// P, encoding parameters:
// NULL
    P: Buffer.alloc(0),

// pHash = Hash(P):
    pHash: Buffer.from(
`da 39 a3 ee 5e 6b 4b 0d 32 55 bf ef 95 60 18 90 af d8 07 09`.replace(/[^0-9A-F]/gi, ''), 'hex'),

//DB = pHashkP Sk01kM:
    DB: Buffer.from(
`da 39 a3 ee 5e 6b 4b 0d 32 55 bf ef 95 60 18 90 af d8 07 09 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 d4 36 e9 95 69
fd 32 a7 c8 a0 5b bc 90 d3 2c 49`.replace(/[^0-9A-F]/gi, ''), 'hex'),

// seed, a random octet string:
    seed: Buffer.from(
`aa fd 12 f6 59 ca e6 34 89 b4 79 e5 07 6d de c2 f0 6c b5 8f`.replace(/[^0-9A-F]/gi, ''), 'hex'),

// dbMask = MGF(seed , 107):
    dbMask: Buffer.from(
`06 e1 de b2 36 9a a5 a5 c7 07 d8 2c 8e 4e 93 24 8a c7 83 de e0 b2 c0 46
26 f5 af f9 3e dc fb 25 c9 c2 b3 ff 8a e1 0e 83 9a 2d db 4c dc fe 4f f4
77 28 b4 a1 b7 c1 36 2b aa d2 9a b4 8d 28 69 d5 02 41 21 43 58 11 59 1b
e3 92 f9 82 fb 3e 87 d0 95 ae b4 04 48 db 97 2f 3a c1 4e af f4 9c 8c 3b
7c fc 95 1a 51 ec d1 dd e6 12 64`.replace(/[^0-9A-F]/gi, ''), 'hex'),

// maskedDB = DB ??? dbMask:
    maskedDB: Buffer.from(
`dc d8 7d 5c 68 f1 ee a8 f5 52 67 c3 1b 2e 8b b4 25 1f 84 d7 e0 b2 c0 46
26 f5 af f9 3e dc fb 25 c9 c2 b3 ff 8a e1 0e 83 9a 2d db 4c dc fe 4f f4
77 28 b4 a1 b7 c1 36 2b aa d2 9a b4 8d 28 69 d5 02 41 21 43 58 11 59 1b
e3 92 f9 82 fb 3e 87 d0 95 ae b4 04 48 db 97 2f 3a c1 4f 7b c2 75 19 52
81 ce 32 d2 f1 b7 6d 4d 35 3e 2d`.replace(/[^0-9A-F]/gi, ''), 'hex'),

// seedMask = MGF(maskedDB, 20):
    seedMask: Buffer.from(
`41 87 0b 5a b0 29 e6 57 d9 57 50 b5 4c 28 3c 08 72 5d be a9`.replace(/[^0-9A-F]/gi, ''), 'hex'),

// maskedSeed = seed ??? seedMask:
    maskedSeed: Buffer.from(
`eb 7a 19 ac e9 e3 00 63 50 e3 29 50 4b 45 e2 ca 82 31 0b 26`.replace(/[^0-9A-F]/gi, ''), 'hex'),

// EM = maskedSeedkmaskedDB:
    EM: Buffer.from( // EM = 0x00 || maskedSeed || maskedDB.
`00 eb 7a 19 ac e9 e3 00 63 50 e3 29 50 4b 45 e2 ca 82 31 0b 26 dc d8 7d 5c
68 f1 ee a8 f5 52 67 c3 1b 2e 8b b4 25 1f 84 d7 e0 b2 c0 46 26 f5 af f9
3e dc fb 25 c9 c2 b3 ff 8a e1 0e 83 9a 2d db 4c dc fe 4f f4 77 28 b4 a1
b7 c1 36 2b aa d2 9a b4 8d 28 69 d5 02 41 21 43 58 11 59 1b e3 92 f9 82
fb 3e 87 d0 95 ae b4 04 48 db 97 2f 3a c1 4f 7b c2 75 19 52 81 ce 32 d2
f1 b7 6d 4d 35 3e 2d`.replace(/[^0-9A-F]/gi, ''), 'hex'),

// C, the RSA encryption of EM:
    CT: Buffer.from(
`12 53 e0 4d c0 a5 39 7b b4 4a 7a b8 7e 9b f2 a0 39 a3 3d 1e 99 6f c8 2a
94 cc d3 00 74 c9 5d f7 63 72 20 17 06 9e 52 68 da 5d 1c 0b 4f 87 2c f6
53 c1 1d f8 23 14 a6 79 68 df ea e2 8d ef 04 bb 6d 84 b1 c3 1d 65 4a 19
70 e5 78 3b d6 eb 96 a0 24 c2 ca 2f 4a 90 fe 9f 2e f5 c9 c1 40 e5 bb 48
da 95 36 ad 87 00 c8 4f c9 13 0a de a7 4e 55 8d 51 a7 4d df 85 d8 b5 0d
e9 68 38 d6 06 3e 09 55`.replace(/[^0-9A-F]/gi, ''), 'hex')

	}; // end of vector.

	// RSAES-OAEP Step Test

	var hashAlgo = 'sha-1';
	var L = vector.P; // null or zero byte.
	var md = new jCastle.digest(hashAlgo);
	var pHash = md.digest(L);
	var k = rsa.getBlockLength();

	assert.ok(pHash.equals(vector.pHash), 'pHash test');

	var hLen = pHash.length;
	var mLen = vector.M.length;

	var PS = Buffer.alloc(k - mLen - (hLen * 2) - 2, 0x00);

	var DB = Buffer.concat([pHash, PS, Buffer.alloc(1, 0x01), vector.M]);

	assert.ok(DB.equals(vector.DB), 'DB test');
	assert.ok(DB.length == k - hLen - 1, 'DB length test');

	var dbMask = jCastle.pki.rsa.padding['rsaes-oaep_mgf1'].mgf1(vector.seed, DB.length, hashAlgo);

	assert.ok(dbMask.equals(vector.dbMask), 'dbMask test');

	var maskedDB = Buffer.xor(DB, dbMask);

	assert.ok(maskedDB.equals(vector.maskedDB), 'maskedDB test');

	var seedMask = jCastle.pki.rsa.padding['rsaes-oaep_mgf1'].mgf1(maskedDB, hLen, hashAlgo);

	assert.ok(seedMask.equals(vector.seedMask), 'seedMask test');

	var maskedSeed = Buffer.xor(vector.seed, seedMask);

	assert.ok(maskedSeed.equals(vector.maskedSeed), 'maskedSeed test');

	var EM = Buffer.concat([Buffer.alloc(1, 0x00), maskedSeed, maskedDB]);

	assert.ok(EM.equals(vector.EM), 'EM test');

	var v_ct = rsa.publicEncrypt(vector.M, {
		padding: {
			mode: 'rsaes-oaep',
			seed: vector.seed
		}
	});

	assert.ok(v_ct.equals(vector.CT), 'CT test');

	var v_M = rsa.privateDecrypt(v_ct, {
		padding: {
			mode: 'rsaes-oaep'
		}
	});

	assert.ok(v_M.equals(vector.M), 'M test');



/*
Decryption
----------

c mod p (c is the integer value of C):
de 63 d4 72 35 66 fa a7 59 bf e4 08 82 1d d5 25 72 ec 92 85 4d df 87 a2
b6 64 d4 4d aa 37 ca 34 6a 05 20 3d 82 ff 2d e8 e3 6c ec 1d 34 f9 8e b6
05 e2 a7 d2 6d e7 af 36 9c e4 ec ae 14 e3 56 33

c mod q:
a2 d9 24 de d9 c3 6d 62 3e d9 a6 5b 5d 86 2c fb ec 8b 19 9c 64 27 9c 54
14 e6 41 19 6e f1 c9 3c 50 7a 9b 52 13 88 1a ad 05 b4 cc fa 02 8a c1 ec
61 42 09 74 bf 16 25 83 6b 0b 7d 05 fb b7 53 36

m1 = c
dP mod p = (c mod p)

dP mod p:
89 6c a2 6c d7 e4 87 1c 7f c9 68 a8 ed ea 11 e2 71 82 4f 0e 03 65 52 17
94 f1 e9 e9 43 b4 a4 4b 57 c9 e3 95 a1 46 74 78 f5 26 49 6b 4b b9 1f 1c
ba ea 90 0f fc 60 2c f0 c6 63 6e ba 84 fc 9f f7

m2 = c
dQ mod q = (c mod q)

dQ mod q:
4e bb 22 75 85 f0 c1 31 2d ca 19 e0 b5 41 db 14 99 fb f1 4e 27 0e 69 8e
23 9a 8c 27 a9 6c da 9a 74 09 74 de 93 7b 5c 9c 93 ea d9 46 2c 65 75 02
1a 23 d4 64 99 dc 9f 6b 35 89 75 59 60 8f 19 be

h = (m1 ??? m2)qInv mod p :
01 2b 2b 24 15 0e 76 e1 59 bd 8d db 42 76 e0 7b fa c1 88 e0 8d 60 47 cf
0e fb 8a e2 ae bd f2 51 c4 0e bc 23 dc fd 4a 34 42 43 94 ad a9 2c fc be
1b 2e ff bb 60 fd fb 03 35 9a 95 36 8d 98 09 25

m = m2 + qh is equal to the integer value of the encoded message EM above. 
The intermediate values of the decoding operation are similar to those 
of the encoding operation.
*/


	// https://go.dev/src/crypto/rsa/rsa_test.go

	// Key 1

	var testVectors = [
		{
			n: Buffer.from(
				`a8b3b284 af8eb50b 387034a8 60f146c4 919f3187 63cd6c55 98c8ae48 11a1e0ab 
				c4c7e0b0 82d693a5 e7fced67 5cf46685 12772c0c bc64a742 c6c630f5 33c8cc72 
				f62ae833 c40bf258 42e984bb 78bdbf97 c0107d55 bdb662f5 c4e0fab9 845cb514 
				8ef7392d d3aaff93 ae1e6b66 7bb3d424 7616d4f5 ba10d4cf d226de88 d39f16fb`.replace(/[^0-9A-F]/gi, ''), 'hex'),
			e: 65537,
			d: Buffer.from(
				`53339cfd b79fc846 6a655c73 16aca85c 55fd8f6d d898fdaf 119517ef 4f52e8fd 
				8e258df9 3fee180f a0e4ab29 693cd83b 152a553d 4ac4d181 2b8b9fa5 af0e7f55 
				fe7304df 41570926 f3311f15 c4d65a73 2c483116 ee3d3d2d 0af3549a d9bf7cbf 
				b78ad884 f84d5beb 04724dc7 369b31de f37d0cf5 39e9cfcd d3de6537 29ead5d1`.replace(/[^0-9A-F]/gi, ''), 'hex'),

			tests: [
				// Example 1.1
				{
					msg: Buffer.from([
						0x66, 0x28, 0x19, 0x4e, 0x12, 0x07, 0x3d, 0xb0,
						0x3b, 0xa9, 0x4c, 0xda, 0x9e, 0xf9, 0x53, 0x23, 0x97,
						0xd5, 0x0d, 0xba, 0x79, 0xb9, 0x87, 0x00, 0x4a, 0xfe,
						0xfe, 0x34]),
					seed: Buffer.from([
						0x18, 0xb7, 0x76, 0xea, 0x21, 0x06, 0x9d, 0x69,
						0x77, 0x6a, 0x33, 0xe9, 0x6b, 0xad, 0x48, 0xe1, 0xdd,
						0xa0, 0xa5, 0xef]),
					ct: Buffer.from([
						0x35, 0x4f, 0xe6, 0x7b, 0x4a, 0x12, 0x6d, 0x5d,
						0x35, 0xfe, 0x36, 0xc7, 0x77, 0x79, 0x1a, 0x3f, 0x7b,
						0xa1, 0x3d, 0xef, 0x48, 0x4e, 0x2d, 0x39, 0x08, 0xaf,
						0xf7, 0x22, 0xfa, 0xd4, 0x68, 0xfb, 0x21, 0x69, 0x6d,
						0xe9, 0x5d, 0x0b, 0xe9, 0x11, 0xc2, 0xd3, 0x17, 0x4f,
						0x8a, 0xfc, 0xc2, 0x01, 0x03, 0x5f, 0x7b, 0x6d, 0x8e,
						0x69, 0x40, 0x2d, 0xe5, 0x45, 0x16, 0x18, 0xc2, 0x1a,
						0x53, 0x5f, 0xa9, 0xd7, 0xbf, 0xc5, 0xb8, 0xdd, 0x9f,
						0xc2, 0x43, 0xf8, 0xcf, 0x92, 0x7d, 0xb3, 0x13, 0x22,
						0xd6, 0xe8, 0x81, 0xea, 0xa9, 0x1a, 0x99, 0x61, 0x70,
						0xe6, 0x57, 0xa0, 0x5a, 0x26, 0x64, 0x26, 0xd9, 0x8c,
						0x88, 0x00, 0x3f, 0x84, 0x77, 0xc1, 0x22, 0x70, 0x94,
						0xa0, 0xd9, 0xfa, 0x1e, 0x8c, 0x40, 0x24, 0x30, 0x9c,
						0xe1, 0xec, 0xcc, 0xb5, 0x21, 0x00, 0x35, 0xd4, 0x7a,
						0xc7, 0x2e, 0x8a])
				},
				// Example 1.2
				{
					msg: Buffer.from([
						0x75, 0x0c, 0x40, 0x47, 0xf5, 0x47, 0xe8, 0xe4,
						0x14, 0x11, 0x85, 0x65, 0x23, 0x29, 0x8a, 0xc9, 0xba,
						0xe2, 0x45, 0xef, 0xaf, 0x13, 0x97, 0xfb, 0xe5, 0x6f,
						0x9d, 0xd5]),
					seed: Buffer.from([
						0x0c, 0xc7, 0x42, 0xce, 0x4a, 0x9b, 0x7f, 0x32,
						0xf9, 0x51, 0xbc, 0xb2, 0x51, 0xef, 0xd9, 0x25, 0xfe,
						0x4f, 0xe3, 0x5f]),
					ct: Buffer.from([
						0x64, 0x0d, 0xb1, 0xac, 0xc5, 0x8e, 0x05, 0x68,
						0xfe, 0x54, 0x07, 0xe5, 0xf9, 0xb7, 0x01, 0xdf, 0xf8,
						0xc3, 0xc9, 0x1e, 0x71, 0x6c, 0x53, 0x6f, 0xc7, 0xfc,
						0xec, 0x6c, 0xb5, 0xb7, 0x1c, 0x11, 0x65, 0x98, 0x8d,
						0x4a, 0x27, 0x9e, 0x15, 0x77, 0xd7, 0x30, 0xfc, 0x7a,
						0x29, 0x93, 0x2e, 0x3f, 0x00, 0xc8, 0x15, 0x15, 0x23,
						0x6d, 0x8d, 0x8e, 0x31, 0x01, 0x7a, 0x7a, 0x09, 0xdf,
						0x43, 0x52, 0xd9, 0x04, 0xcd, 0xeb, 0x79, 0xaa, 0x58,
						0x3a, 0xdc, 0xc3, 0x1e, 0xa6, 0x98, 0xa4, 0xc0, 0x52,
						0x83, 0xda, 0xba, 0x90, 0x89, 0xbe, 0x54, 0x91, 0xf6,
						0x7c, 0x1a, 0x4e, 0xe4, 0x8d, 0xc7, 0x4b, 0xbb, 0xe6,
						0x64, 0x3a, 0xef, 0x84, 0x66, 0x79, 0xb4, 0xcb, 0x39,
						0x5a, 0x35, 0x2d, 0x5e, 0xd1, 0x15, 0x91, 0x2d, 0xf6,
						0x96, 0xff, 0xe0, 0x70, 0x29, 0x32, 0x94, 0x6d, 0x71,
						0x49, 0x2b, 0x44])
				},
				// Example 1.3
				{
					msg: Buffer.from([
						0xd9, 0x4a, 0xe0, 0x83, 0x2e, 0x64, 0x45, 0xce,
						0x42, 0x33, 0x1c, 0xb0, 0x6d, 0x53, 0x1a, 0x82, 0xb1,
						0xdb, 0x4b, 0xaa, 0xd3, 0x0f, 0x74, 0x6d, 0xc9, 0x16,
						0xdf, 0x24, 0xd4, 0xe3, 0xc2, 0x45, 0x1f, 0xff, 0x59,
						0xa6, 0x42, 0x3e, 0xb0, 0xe1, 0xd0, 0x2d, 0x4f, 0xe6,
						0x46, 0xcf, 0x69, 0x9d, 0xfd, 0x81, 0x8c, 0x6e, 0x97,
						0xb0, 0x51]),
					seed: Buffer.from([
						0x25, 0x14, 0xdf, 0x46, 0x95, 0x75, 0x5a, 0x67,
						0xb2, 0x88, 0xea, 0xf4, 0x90, 0x5c, 0x36, 0xee, 0xc6,
						0x6f, 0xd2, 0xfd]),
					ct: Buffer.from([
						0x42, 0x37, 0x36, 0xed, 0x03, 0x5f, 0x60, 0x26,
						0xaf, 0x27, 0x6c, 0x35, 0xc0, 0xb3, 0x74, 0x1b, 0x36,
						0x5e, 0x5f, 0x76, 0xca, 0x09, 0x1b, 0x4e, 0x8c, 0x29,
						0xe2, 0xf0, 0xbe, 0xfe, 0xe6, 0x03, 0x59, 0x5a, 0xa8,
						0x32, 0x2d, 0x60, 0x2d, 0x2e, 0x62, 0x5e, 0x95, 0xeb,
						0x81, 0xb2, 0xf1, 0xc9, 0x72, 0x4e, 0x82, 0x2e, 0xca,
						0x76, 0xdb, 0x86, 0x18, 0xcf, 0x09, 0xc5, 0x34, 0x35,
						0x03, 0xa4, 0x36, 0x08, 0x35, 0xb5, 0x90, 0x3b, 0xc6,
						0x37, 0xe3, 0x87, 0x9f, 0xb0, 0x5e, 0x0e, 0xf3, 0x26,
						0x85, 0xd5, 0xae, 0xc5, 0x06, 0x7c, 0xd7, 0xcc, 0x96,
						0xfe, 0x4b, 0x26, 0x70, 0xb6, 0xea, 0xc3, 0x06, 0x6b,
						0x1f, 0xcf, 0x56, 0x86, 0xb6, 0x85, 0x89, 0xaa, 0xfb,
						0x7d, 0x62, 0x9b, 0x02, 0xd8, 0xf8, 0x62, 0x5c, 0xa3,
						0x83, 0x36, 0x24, 0xd4, 0x80, 0x0f, 0xb0, 0x81, 0xb1,
						0xcf, 0x94, 0xeb])
				}
			]
		},
		// Key 10
		{
			n: Buffer.from(
				`ae45ed56 01cec6b8 cc05f803 935c674d dbe0d75c 4c09fd79 51fc6b0c aec313a8 
				df39970c 518bffba 5ed68f3f 0d7f22a4 029d413f 1ae07e4e be9e4177 ce23e7f5 
				404b569e 4ee1bdcf 3c1fb03e f113802d 4f855eb9 b5134b5a 7c8085ad cae6fa2f 
				a1417ec3 763be171 b0c62b76 0ede23c1 2ad92b98 0884c641 f5a8fac2 6bdad4a0 
				3381a22f e1b75488 5094c825 06d4019a 535a286a feb271bb 9ba592de 18dcf600 
				c2aeeae5 6e02f7cf 79fc14cf 3bdc7cd8 4febbbf9 50ca9030 4b2219a7 aa063aef 
				a2c3c198 0e560cd6 4afe7795 85b61076 57b95785 7efde601 0988ab7d e417fc88 
				d8f384c4 e6e72c3f 943e0c31 c0c4a5cc 36f879d8 a3ac9d7d 59860eaa da6b83bb`.replace(/[^0-9A-F]/gi, ''), 'hex'),
			e: 65537,
			d: Buffer.from(
				`056b0421 6fe5f354 ac77250a 4b6b0c85 25a85c59 b0bd80c5 6450a22d 5f438e59 
				6a333aa8 75e291dd 43f48cb8 8b9d5fc0 d499f9fc d1c397f9 afc070cd 9e398c8d 
				19e61db7 c7410a6b 2675dfbf 5d345b80 4d201add 502d5ce2 dfcb091c e9997bbe 
				be57306f 383e4d58 8103f036 f7e85d19 34d152a3 23e4a8db 451d6f4a 5b1b0f10 
				2cc150e0 2feee2b8 8dea4ad4 c1baccb2 4d84072d 14e1d24a 6771f740 8ee30564 
				fb86d439 3a34bcf0 b788501d 193303f1 3a2284b0 01f0f649 eaf79328 d4ac5c43 
				0ab44149 20a9460e d1b7bc40 ec653e87 6d09abc5 09ae45b5 25190116 a0c26101 
				84829850 9c1c3bf3 a483e727 4054e15e 97075036 e989f609 32807b52 57751e79`.replace(/[^0-9A-F]/gi, ''), 'hex'),
			tests: [
				// Example 10.1
				{
					msg: Buffer.from([
						0x8b, 0xba, 0x6b, 0xf8, 0x2a, 0x6c, 0x0f, 0x86,
						0xd5, 0xf1, 0x75, 0x6e, 0x97, 0x95, 0x68, 0x70, 0xb0,
						0x89, 0x53, 0xb0, 0x6b, 0x4e, 0xb2, 0x05, 0xbc, 0x16,
						0x94, 0xee]),
					seed: Buffer.from([
						0x47, 0xe1, 0xab, 0x71, 0x19, 0xfe, 0xe5, 0x6c,
						0x95, 0xee, 0x5e, 0xaa, 0xd8, 0x6f, 0x40, 0xd0, 0xaa,
						0x63, 0xbd, 0x33]),
					ct: Buffer.from([
						0x53, 0xea, 0x5d, 0xc0, 0x8c, 0xd2, 0x60, 0xfb,
						0x3b, 0x85, 0x85, 0x67, 0x28, 0x7f, 0xa9, 0x15, 0x52,
						0xc3, 0x0b, 0x2f, 0xeb, 0xfb, 0xa2, 0x13, 0xf0, 0xae,
						0x87, 0x70, 0x2d, 0x06, 0x8d, 0x19, 0xba, 0xb0, 0x7f,
						0xe5, 0x74, 0x52, 0x3d, 0xfb, 0x42, 0x13, 0x9d, 0x68,
						0xc3, 0xc5, 0xaf, 0xee, 0xe0, 0xbf, 0xe4, 0xcb, 0x79,
						0x69, 0xcb, 0xf3, 0x82, 0xb8, 0x04, 0xd6, 0xe6, 0x13,
						0x96, 0x14, 0x4e, 0x2d, 0x0e, 0x60, 0x74, 0x1f, 0x89,
						0x93, 0xc3, 0x01, 0x4b, 0x58, 0xb9, 0xb1, 0x95, 0x7a,
						0x8b, 0xab, 0xcd, 0x23, 0xaf, 0x85, 0x4f, 0x4c, 0x35,
						0x6f, 0xb1, 0x66, 0x2a, 0xa7, 0x2b, 0xfc, 0xc7, 0xe5,
						0x86, 0x55, 0x9d, 0xc4, 0x28, 0x0d, 0x16, 0x0c, 0x12,
						0x67, 0x85, 0xa7, 0x23, 0xeb, 0xee, 0xbe, 0xff, 0x71,
						0xf1, 0x15, 0x94, 0x44, 0x0a, 0xae, 0xf8, 0x7d, 0x10,
						0x79, 0x3a, 0x87, 0x74, 0xa2, 0x39, 0xd4, 0xa0, 0x4c,
						0x87, 0xfe, 0x14, 0x67, 0xb9, 0xda, 0xf8, 0x52, 0x08,
						0xec, 0x6c, 0x72, 0x55, 0x79, 0x4a, 0x96, 0xcc, 0x29,
						0x14, 0x2f, 0x9a, 0x8b, 0xd4, 0x18, 0xe3, 0xc1, 0xfd,
						0x67, 0x34, 0x4b, 0x0c, 0xd0, 0x82, 0x9d, 0xf3, 0xb2,
						0xbe, 0xc6, 0x02, 0x53, 0x19, 0x62, 0x93, 0xc6, 0xb3,
						0x4d, 0x3f, 0x75, 0xd3, 0x2f, 0x21, 0x3d, 0xd4, 0x5c,
						0x62, 0x73, 0xd5, 0x05, 0xad, 0xf4, 0xcc, 0xed, 0x10,
						0x57, 0xcb, 0x75, 0x8f, 0xc2, 0x6a, 0xee, 0xfa, 0x44,
						0x12, 0x55, 0xed, 0x4e, 0x64, 0xc1, 0x99, 0xee, 0x07,
						0x5e, 0x7f, 0x16, 0x64, 0x61, 0x82, 0xfd, 0xb4, 0x64,
						0x73, 0x9b, 0x68, 0xab, 0x5d, 0xaf, 0xf0, 0xe6, 0x3e,
						0x95, 0x52, 0x01, 0x68, 0x24, 0xf0, 0x54, 0xbf, 0x4d,
						0x3c, 0x8c, 0x90, 0xa9, 0x7b, 0xb6, 0xb6, 0x55, 0x32,
						0x84, 0xeb, 0x42, 0x9f, 0xcc])
				}
			]
		}
	];

	for (var i = 0; i < testVectors.length; i++) {
		var vector = testVectors[i];

		var rsa = new jCastle.pki.rsa();
		rsa.setPrivateKey({
			n: vector.n,
			e: vector.e,
			d: vector.d
		});

		for (var j = 0; j < vector.tests.length; j++) {
			var test = vector.tests[j];

			var ct = rsa.publicEncrypt(test.msg, {
				padding: {
					mode: 'rsaes-oaep',
					seed: test.seed
				}
			});

			assert.ok(ct.equals(test.ct), 'ct test ' + (j+1));

			var msg = rsa.privateDecrypt(ct, {
				padding: {
					mode: 'rsaes-oaep'
				}
			});

			assert.ok(msg.equals(test.msg), 'pt test ' + (j+1));
		}
	}
});

QUnit.test("EMSA-PSS Padding Test", function(assert) {
/*
9.1 EMSA-PSS

   This encoding method is parameterized by the choice of hash function,
   mask generation function, and salt length.  These options should be
   fixed for a given RSA key, except that the salt length can be
   variable (see [31] for discussion).  Suggested hash and mask
   generation functions are given in Appendix B.  The encoding method is
   based on Bellare and Rogaway's Probabilistic Signature Scheme (PSS)
   [4][5].  It is randomized and has an encoding operation and a
   verification operation.

   Figure 2 illustrates the encoding operation.

   __________________________________________________________________

                                  +-----------+
                                  |     M     |
                                  +-----------+
                                        |
                                        V
                                      Hash
                                        |
                                        V
                          +--------+----------+----------+
                     M' = |Padding1|  mHash   |   salt   |
                          +--------+----------+----------+
                                         |
               +--------+----------+     V
         DB =  |Padding2|maskedseed|   Hash
               +--------+----------+     |
                         |               |
                         V               |    +--+
                        xor <--- MGF <---|    |bc|
                         |               |    +--+
                         |               |      |
                         V               V      V
               +-------------------+----------+--+
         EM =  |    maskedDB       |maskedseed|bc|
               +-------------------+----------+--+
   __________________________________________________________________

   Figure 2: EMSA-PSS encoding operation.  Verification operation
   follows reverse steps to recover salt, then forward steps to
   recompute and compare H.

   Notes.

   1. The encoding method defined here differs from the one in Bellare
      and Rogaway's submission to IEEE P1363a [5] in three respects:

      *  It applies a hash function rather than a mask generation
         function to the message.  Even though the mask generation
         function is based on a hash function, it seems more natural to
         apply a hash function directly.

      *  The value that is hashed together with the salt value is the
         string (0x)00 00 00 00 00 00 00 00 || mHash rather than the
         message M itself.  Here, mHash is the hash of M.  Note that the
         hash function is the same in both steps.  See Note 3 below for
         further discussion.  (Also, the name "salt" is used instead of
         "seed", as it is more reflective of the value's role.)

      *  The encoded message in EMSA-PSS has nine fixed bits; the first
         bit is 0 and the last eight bits form a "trailer field", the
         octet 0xbc.  In the original scheme, only the first bit is
         fixed.  The rationale for the trailer field is for
         compatibility with the Rabin-Williams IFSP-RW signature
         primitive in IEEE Std 1363-2000 [26] and the corresponding
         primitive in the draft ISO/IEC 9796-2 [29].

   2. Assuming that the mask generation function is based on a hash
      function, it is recommended that the hash function be the same as
      the one that is applied to the message; see Section 8.1 for
      further discussion.

   3. Without compromising the security proof for RSASSA-PSS, one may
      perform steps 1 and 2 of EMSA-PSS-ENCODE and EMSA-PSS-VERIFY (the
      application of the hash function to the message) outside the
      module that computes the rest of the signature operation, so that
      mHash rather than the message M itself is input to the module.  In
      other words, the security proof for RSASSA-PSS still holds even if
      an opponent can control the value of mHash.  This is convenient if
      the module has limited I/O bandwidth, e.g., a smart card.  Note
      that previous versions of PSS [4][5] did not have this property.
      Of course, it may be desirable for other security reasons to have
      the module process the full message.  For instance, the module may
      need to "see" what it is signing if it does not trust the
      component that computes the hash value.

   4. Typical salt lengths in octets are hLen (the length of the output
      of the hash function Hash) and 0.  In both cases the security of
      RSASSA-PSS can be closely related to the hardness of inverting
      RSAVP1.  Bellare and Rogaway [4] give a tight lower bound for the
      security of the original RSA-PSS scheme, which corresponds roughly
      to the former case, while Coron [12] gives a lower bound for the
      related Full Domain Hashing scheme, which corresponds roughly to
      the latter case.  In [13] Coron provides a general treatment with
      various salt lengths ranging from 0 to hLen; see [27] for
      discussion.  See also [31], which adapts the security proofs in
      [4][13] to address the differences between the original and the
      present version of RSA-PSS as listed in Note 1 above.

   5. As noted in IEEE P1363a [27], the use of randomization in
      signature schemes - such as the salt value in EMSA-PSS - may
      provide a "covert channel" for transmitting information other than
      the message being signed.  For more on covert channels, see [50].

9.1.1 Encoding operation

   EMSA-PSS-ENCODE (M, emBits)

   Options:

   Hash     hash function (hLen denotes the length in octets of the hash
            function output)
   MGF      mask generation function
   sLen     intended length in octets of the salt

   Input:
   M        message to be encoded, an octet string
   emBits   maximal bit length of the integer OS2IP (EM) (see Section
            4.2), at least 8hLen + 8sLen + 9

   Output:
   EM       encoded message, an octet string of length emLen = \ceil
            (emBits/8)

   Errors:  "encoding error"; "message too long"

   Steps:

   1.  If the length of M is greater than the input limitation for the
       hash function (2^61 - 1 octets for SHA-1), output "message too
       long" and stop.

   2.  Let mHash = Hash(M), an octet string of length hLen.

   3.  If emLen < hLen + sLen + 2, output "encoding error" and stop.

   4.  Generate a random octet string salt of length sLen; if sLen = 0,
       then salt is the empty string.

   5.  Let
         M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt;

       M' is an octet string of length 8 + hLen + sLen with eight
       initial zero octets.

   6.  Let H = Hash(M'), an octet string of length hLen.

   7.  Generate an octet string PS consisting of emLen - sLen - hLen - 2
       zero octets.  The length of PS may be 0.

   8.  Let DB = PS || 0x01 || salt; DB is an octet string of length
       emLen - hLen - 1.

   9.  Let dbMask = MGF(H, emLen - hLen - 1).

   10. Let maskedDB = DB \xor dbMask.

   11. Set the leftmost 8emLen - emBits bits of the leftmost octet in
       maskedDB to zero.

   12. Let EM = maskedDB || H || 0xbc.

   13. Output EM.
*/

	//
	// test 1 - EMSA-PSS-ENCODE
	//

	// https://go.dev/src/crypto/rsa/pss_test.go

	var msg = [
		0x85, 0x9e, 0xef, 0x2f, 0xd7, 0x8a, 0xca, 0x00, 0x30, 0x8b,
		0xdc, 0x47, 0x11, 0x93, 0xbf, 0x55, 0xbf, 0x9d, 0x78, 0xdb,
		0x8f, 0x8a, 0x67, 0x2b, 0x48, 0x46, 0x34, 0xf3, 0xc9, 0xc2,
		0x6e, 0x64, 0x78, 0xae, 0x10, 0x26, 0x0f, 0xe0, 0xdd, 0x8c,
		0x08, 0x2e, 0x53, 0xa5, 0x29, 0x3a, 0xf2, 0x17, 0x3c, 0xd5,
		0x0c, 0x6d, 0x5d, 0x35, 0x4f, 0xeb, 0xf7, 0x8b, 0x26, 0x02,
		0x1c, 0x25, 0xc0, 0x27, 0x12, 0xe7, 0x8c, 0xd4, 0x69, 0x4c,
		0x9f, 0x46, 0x97, 0x77, 0xe4, 0x51, 0xe7, 0xf8, 0xe9, 0xe0,
		0x4c, 0xd3, 0x73, 0x9c, 0x6b, 0xbf, 0xed, 0xae, 0x48, 0x7f,
		0xb5, 0x56, 0x44, 0xe9, 0xca, 0x74, 0xff, 0x77, 0xa5, 0x3c,
		0xb7, 0x29, 0x80, 0x2f, 0x6e, 0xd4, 0xa5, 0xff, 0xa8, 0xba,
		0x15, 0x98, 0x90, 0xfc,
	];

	var salt = [
		0xe3, 0xb5, 0xd5, 0xd0, 0x02, 0xc1, 0xbc, 0xe5, 0x0c, 0x2b,
		0x65, 0xef, 0x88, 0xa1, 0x88, 0xd8, 0x3b, 0xce, 0x7e, 0x61,
	];

	var expected = [
		0x66, 0xe4, 0x67, 0x2e, 0x83, 0x6a, 0xd1, 0x21, 0xba, 0x24,
		0x4b, 0xed, 0x65, 0x76, 0xb8, 0x67, 0xd9, 0xa4, 0x47, 0xc2,
		0x8a, 0x6e, 0x66, 0xa5, 0xb8, 0x7d, 0xee, 0x7f, 0xbc, 0x7e,
		0x65, 0xaf, 0x50, 0x57, 0xf8, 0x6f, 0xae, 0x89, 0x84, 0xd9,
		0xba, 0x7f, 0x96, 0x9a, 0xd6, 0xfe, 0x02, 0xa4, 0xd7, 0x5f,
		0x74, 0x45, 0xfe, 0xfd, 0xd8, 0x5b, 0x6d, 0x3a, 0x47, 0x7c,
		0x28, 0xd2, 0x4b, 0xa1, 0xe3, 0x75, 0x6f, 0x79, 0x2d, 0xd1,
		0xdc, 0xe8, 0xca, 0x94, 0x44, 0x0e, 0xcb, 0x52, 0x79, 0xec,
		0xd3, 0x18, 0x3a, 0x31, 0x1f, 0xc8, 0x96, 0xda, 0x1c, 0xb3,
		0x93, 0x11, 0xaf, 0x37, 0xea, 0x4a, 0x75, 0xe2, 0x4b, 0xdb,
		0xfd, 0x5c, 0x1d, 0xa0, 0xde, 0x7c, 0xec, 0xdf, 0x1a, 0x89,
		0x6f, 0x9d, 0x8b, 0xc8, 0x16, 0xd9, 0x7c, 0xd7, 0xa2, 0xc4,
		0x3b, 0xad, 0x54, 0x6f, 0xbe, 0x8c, 0xfe, 0xbc,
	];

	var hashAlgo = 'sha-1';
	var bits = 1024;

	msg = Buffer.from(msg);
	salt = Buffer.from(salt);
	expected = Buffer.from(expected);

	// const mgf1 =function(seed, len, hash_name)
	// {
	// 	var mask = Buffer.alloc(0), i = 0;
	// 	var md = new jCastle.digest(hash_name);

	// 	while (mask.length < len) {
	// 		var t = md.start()
	// 					.update(seed)
	// 					.update(Buffer.from([(i >>> 24) & 0xff, (i >>> 16) & 0xff, (i >>> 8) & 0xff, i & 0xff]))
	// 					.finalize();
	// 		mask = Buffer.concat([mask, t]);
	// 		i++;
	// 	}

	// 	return mask.slice(0, len);
	// };

	var md = jCastle.digest.create(hashAlgo);
	var mHash = md.start().update(msg).finalize();
	var hLen = mHash.length;
	var sLen = salt.length;
	var H = md.start().update(Buffer.alloc(8)).update(mHash).update(salt).finalize();
	var emLen = bits / 8;
	var PS = Buffer.alloc(emLen - sLen - hLen - 2);
	var DB = Buffer.concat([PS, Buffer.alloc(1, 0x01), salt]);
	var dbMask = jCastle.pki.rsa.padding['pkcs1_pss_mgf1'].mgf1(H, DB.length, hashAlgo);
	var maskedDB = Buffer.xor(DB, dbMask);

	maskedDB[0] &= 0x7f;

	var em = Buffer.concat([maskedDB, H, Buffer.alloc(1, 0xbc)]);

	assert.ok(em.equals(expected), 'em test 1');

	var em2 = jCastle.pki.rsa.padding.create('pkcs1_pss_mgf1').pad(msg, bits, hashAlgo, sLen, salt);
	assert.ok(em2.equals(expected), 'em test 2');


/*
9.1.2 Verification operation

   EMSA-PSS-VERIFY (M, EM, emBits)

   Options:
   Hash     hash function (hLen denotes the length in octets of the hash
            function output)
   MGF      mask generation function
   sLen     intended length in octets of the salt

   Input:
   M        message to be verified, an octet string
   EM       encoded message, an octet string of length emLen = \ceil
            (emBits/8)
   emBits   maximal bit length of the integer OS2IP (EM) (see Section
            4.2), at least 8hLen + 8sLen + 9

   Output:
   "consistent" or "inconsistent"

   Steps:

   1.  If the length of M is greater than the input limitation for the
       hash function (2^61 - 1 octets for SHA-1), output "inconsistent"
       and stop.

   2.  Let mHash = Hash(M), an octet string of length hLen.

   3.  If emLen < hLen + sLen + 2, output "inconsistent" and stop.

   4.  If the rightmost octet of EM does not have hexadecimal value
       0xbc, output "inconsistent" and stop.

   5.  Let maskedDB be the leftmost emLen - hLen - 1 octets of EM, and
       let H be the next hLen octets.

   6.  If the leftmost 8emLen - emBits bits of the leftmost octet in
       maskedDB are not all equal to zero, output "inconsistent" and
       stop.

   7.  Let dbMask = MGF(H, emLen - hLen - 1).

   8.  Let DB = maskedDB \xor dbMask.

   9.  Set the leftmost 8emLen - emBits bits of the leftmost octet in DB
       to zero.

   10. If the emLen - hLen - sLen - 2 leftmost octets of DB are not zero
       or if the octet at position emLen - hLen - sLen - 1 (the leftmost
       position is "position 1") does not have hexadecimal value 0x01,
       output "inconsistent" and stop.

   11.  Let salt be the last sLen octets of DB.

   12.  Let
            M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt ;

       M' is an octet string of length 8 + hLen + sLen with eight
       initial zero octets.

   13. Let H' = Hash(M'), an octet string of length hLen.

   14. If H = H', output "consistent." Otherwise, output "inconsistent."
*/

	var v = jCastle.pki.rsa.padding.create('pkcs1_pss_mgf1').verify(msg, bits, em, hashAlgo, sLen);
	assert.ok(v, 'em verify test');



	//
	// test 2
	//

// https://go.dev/src/crypto/rsa/testdata/

/*
# ===========================
# TEST VECTORS FOR RSASSA-PSS
# ===========================
# 
# This file contains test vectors for the
# RSASSA-PSS signature scheme with appendix as
# defined in PKCS #1 v2.1. 10 RSA keys of
# different sizes have been generated. For each
# key, 6 random messages of length between 1
# and 256 octets have been RSASSA-PSS signed
# via a random salt of length 20 octets. 
#
# The underlying hash function in the EMSA-PSS
# encoding method is SHA-1; the mask generation
# function is MGF1 with SHA-1 as specified in 
# PKCS #1 v2.1.
# 
# Integers are represented by strings of octets
# with the leftmost octet being the most 
# significant octet. For example, 
#
#           9,202,000 = (0x)8c 69 50. 
#
# Key lengths:
# 
# Key  1: 1024 bits
# Key  2: 1025 bits
# Key  3: 1026 bits
# Key  4: 1027 bits
# Key  5: 1028 bits
# Key  6: 1029 bits
# Key  7: 1030 bits
# Key  8: 1031 bits
# Key  9: 1536 bits
# Key 10: 2048 bits
#
# =============================================
*/
// # ==================================
// # Example 1: A 1024-bit RSA Key Pair
// # ==================================
var bits = 1024;
// # ------------------------------
// # Components of the RSA Key Pair
// # ------------------------------

// # RSA modulus n: 

	var n = Buffer.from(
`a5 6e 4a 0e 70 10 17 58 9a 51 87 dc 7e a8 41 d1 
56 f2 ec 0e 36 ad 52 a4 4d fe b1 e6 1f 7a d9 91 
d8 c5 10 56 ff ed b1 62 b4 c0 f2 83 a1 2a 88 a3 
94 df f5 26 ab 72 91 cb b3 07 ce ab fc e0 b1 df 
d5 cd 95 08 09 6d 5b 2b 8b 6d f5 d6 71 ef 63 77 
c0 92 1c b2 3c 27 0a 70 e2 59 8e 6f f8 9d 19 f1 
05 ac c2 d3 f0 cb 35 f2 92 80 e1 38 6b 6f 64 c4 
ef 22 e1 e1 f2 0d 0c e8 cf fb 22 49 bd 9a 21 37`.replace(/[^0-9A-F]/gi, ''), 'hex');

// # RSA public exponent e: 
	var e = parseInt('01 00 01'.replace(/[^0-9A-F]/gi, ''), 16);

// # RSA private exponent d: 
	var d = Buffer.from(
`33 a5 04 2a 90 b2 7d 4f 54 51 ca 9b bb d0 b4 47 
71 a1 01 af 88 43 40 ae f9 88 5f 2a 4b be 92 e8 
94 a7 24 ac 3c 56 8c 8f 97 85 3a d0 7c 02 66 c8 
c6 a3 ca 09 29 f1 e8 f1 12 31 88 44 29 fc 4d 9a 
e5 5f ee 89 6a 10 ce 70 7c 3e d7 e7 34 e4 47 27 
a3 95 74 50 1a 53 26 83 10 9c 2a ba ca ba 28 3c 
31 b4 bd 2f 53 c3 ee 37 e3 52 ce e3 4f 9e 50 3b 
d8 0c 06 22 ad 79 c6 dc ee 88 35 47 c6 a3 b3 25`.replace(/[^0-9A-F]/gi, ''), 'hex');

// # Prime p: 
	var p = Buffer.from(
`e7 e8 94 27 20 a8 77 51 72 73 a3 56 05 3e a2 a1 
bc 0c 94 aa 72 d5 5c 6e 86 29 6b 2d fc 96 79 48 
c0 a7 2c bc cc a7 ea cb 35 70 6e 09 a1 df 55 a1 
53 5b d9 b3 cc 34 16 0b 3b 6d cd 3e da 8e 64 43`.replace(/[^0-9A-F]/gi, ''), 'hex');

// # Prime q: 
	var q = Buffer.from(
`b6 9d ca 1c f7 d4 d7 ec 81 e7 5b 90 fc ca 87 4a 
bc de 12 3f d2 70 01 80 aa 90 47 9b 6e 48 de 8d 
67 ed 24 f9 f1 9d 85 ba 27 58 74 f5 42 cd 20 dc 
72 3e 69 63 36 4a 1f 94 25 45 2b 26 9a 67 99 fd`.replace(/[^0-9A-F]/gi, ''), 'hex');

// # p's CRT exponent dP:
	var dmp1 = Buffer.from(
`28 fa 13 93 86 55 be 1f 8a 15 9c ba ca 5a 72 ea 
19 0c 30 08 9e 19 cd 27 4a 55 6f 36 c4 f6 e1 9f 
55 4b 34 c0 77 79 04 27 bb dd 8d d3 ed e2 44 83 
28 f3 85 d8 1b 30 e8 e4 3b 2f ff a0 27 86 19 79`.replace(/[^0-9A-F]/gi, ''), 'hex');

// # q's CRT exponent dQ: 
	var dmq1 = Buffer.from(
`1a 8b 38 f3 98 fa 71 20 49 89 8d 7f b7 9e e0 a7 
76 68 79 12 99 cd fa 09 ef c0 e5 07 ac b2 1e d7 
43 01 ef 5b fd 48 be 45 5e ae b6 e1 67 82 55 82 
75 80 a8 e4 e8 e1 41 51 d1 51 0a 82 a3 f2 e7 29`.replace(/[^0-9A-F]/gi, ''), 'hex');

// # CRT coefficient qInv: 
	var iqmp = Buffer.from(
`27 15 6a ba 41 26 d2 4a 81 f3 a5 28 cb fb 27 f5 
68 86 f8 40 a9 f6 e8 6e 17 a4 4b 94 fe 93 19 58 
4b 8e 22 fd de 1e 5a 2e 3b d8 aa 5b a8 d8 58 41 
94 eb 21 90 ac f8 32 b8 47 f1 3a 3d 24 a7 9f 4d`.replace(/[^0-9A-F]/gi, ''), 'hex');

	var testVectors = [
		{
// # --------------------------------
// # RSASSA-PSS Signature Example 1.1
// # --------------------------------

// # Message to be signed:
        msg: Buffer.from(
`cd c8 7d a2 23 d7 86 df 3b 45 e0 bb bc 72 13 26 
d1 ee 2a f8 06 cc 31 54 75 cc 6f 0d 9c 66 e1 b6 
23 71 d4 5c e2 39 2e 1a c9 28 44 c3 10 10 2f 15 
6a 0d 8d 52 c1 f4 c4 0b a3 aa 65 09 57 86 cb 76 
97 57 a6 56 3b a9 58 fe d0 bc c9 84 e8 b5 17 a3 
d5 f5 15 b2 3b 8a 41 e7 4a a8 67 69 3f 90 df b0 
61 a6 e8 6d fa ae e6 44 72 c0 0e 5f 20 94 57 29 
cb eb e7 7f 06 ce 78 e0 8f 40 98 fb a4 1f 9d 61 
93 c0 31 7e 8b 60 d4 b6 08 4a cb 42 d2 9e 38 08 
a3 bc 37 2d 85 e3 31 17 0f cb f7 cc 72 d0 b7 1c 
29 66 48 b3 a4 d1 0f 41 62 95 d0 80 7a a6 25 ca 
b2 74 4f d9 ea 8f d2 23 c4 25 37 02 98 28 bd 16 
be 02 54 6f 13 0f d2 e3 3b 93 6d 26 76 e0 8a ed 
1b 73 31 8b 75 0a 01 67 d0`.replace(/[^0-9A-F]/gi, ''), 'hex'),

// # Salt:
        salt: Buffer.from(
`de e9 59 c7 e0 64 11 36 14 20 ff 80 18 5e d5 7f 
3e 67 76 af`.replace(/[^0-9A-F]/gi, ''), 'hex'),

// # Signature:
        sig: Buffer.from(
`90 74 30 8f b5 98 e9 70 1b 22 94 38 8e 52 f9 71 
fa ac 2b 60 a5 14 5a f1 85 df 52 87 b5 ed 28 87 
e5 7c e7 fd 44 dc 86 34 e4 07 c8 e0 e4 36 0b c2 
26 f3 ec 22 7f 9d 9e 54 63 8e 8d 31 f5 05 12 15 
df 6e bb 9c 2f 95 79 aa 77 59 8a 38 f9 14 b5 b9 
c1 bd 83 c4 e2 f9 f3 82 a0 d0 aa 35 42 ff ee 65 
98 4a 60 1b c6 9e b2 8d eb 27 dc a1 2c 82 c2 d4 
c3 f6 6c d5 00 f1 ff 2b 99 4d 8a 4e 30 cb b3 3c`.replace(/[^0-9A-F]/gi, ''), 'hex')
		},
		{
// # --------------------------------
// # RSASSA-PSS Signature Example 1.2
// # --------------------------------

// # Message to be signed:
        msg: Buffer.from(
`85 13 84 cd fe 81 9c 22 ed 6c 4c cb 30 da eb 5c 
f0 59 bc 8e 11 66 b7 e3 53 0c 4c 23 3e 2b 5f 8f 
71 a1 cc a5 82 d4 3e cc 72 b1 bc a1 6d fc 70 13 
22 6b 9e`.replace(/[^0-9A-F]/gi, ''), 'hex'),

// # Salt:
        salt: Buffer.from(
`ef 28 69 fa 40 c3 46 cb 18 3d ab 3d 7b ff c9 8f 
d5 6d f4 2d`.replace(/[^0-9A-F]/gi, ''), 'hex'),

// # Signature:
        sig: Buffer.from(
`3e f7 f4 6e 83 1b f9 2b 32 27 41 42 a5 85 ff ce 
fb dc a7 b3 2a e9 0d 10 fb 0f 0c 72 99 84 f0 4e 
f2 9a 9d f0 78 07 75 ce 43 73 9b 97 83 83 90 db 
0a 55 05 e6 3d e9 27 02 8d 9d 29 b2 19 ca 2c 45 
17 83 25 58 a5 5d 69 4a 6d 25 b9 da b6 60 03 c4 
cc cd 90 78 02 19 3b e5 17 0d 26 14 7d 37 b9 35 
90 24 1b e5 1c 25 05 5f 47 ef 62 75 2c fb e2 14 
18 fa fe 98 c2 2c 4d 4d 47 72 4f db 56 69 e8 43`.replace(/[^0-9A-F]/gi, ''), 'hex')
		},
		{
// # --------------------------------
// # RSASSA-PSS Signature Example 1.3
// # --------------------------------

// # Message to be signed:
        msg: Buffer.from(
`a4 b1 59 94 17 61 c4 0c 6a 82 f2 b8 0d 1b 94 f5 
aa 26 54 fd 17 e1 2d 58 88 64 67 9b 54 cd 04 ef 
8b d0 30 12 be 8d c3 7f 4b 83 af 79 63 fa ff 0d 
fa 22 54 77 43 7c 48 01 7f f2 be 81 91 cf 39 55 
fc 07 35 6e ab 3f 32 2f 7f 62 0e 21 d2 54 e5 db 
43 24 27 9f e0 67 e0 91 0e 2e 81 ca 2c ab 31 c7 
45 e6 7a 54 05 8e b5 0d 99 3c db 9e d0 b4 d0 29 
c0 6d 21 a9 4c a6 61 c3 ce 27 fa e1 d6 cb 20 f4 
56 4d 66 ce 47 67 58 3d 0e 5f 06 02 15 b5 90 17 
be 85 ea 84 89 39 12 7b d8 c9 c4 d4 7b 51 05 6c 
03 1c f3 36 f1 7c 99 80 f3 b8 f5 b9 b6 87 8e 8b 
79 7a a4 3b 88 26 84 33 3e 17 89 3f e9 ca a6 aa 
29 9f 7e d1 a1 8e e2 c5 48 64 b7 b2 b9 9b 72 61 
8f b0 25 74 d1 39 ef 50 f0 19 c9 ee f4 16 97 13 
38 e7 d4 70`.replace(/[^0-9A-F]/gi, ''), 'hex'),

// # Salt:
        salt: Buffer.from(
`71 0b 9c 47 47 d8 00 d4 de 87 f1 2a fd ce 6d f1 
81 07 cc 77`.replace(/[^0-9A-F]/gi, ''), 'hex'),

// # Signature:
        sig: Buffer.from(
`66 60 26 fb a7 1b d3 e7 cf 13 15 7c c2 c5 1a 8e 
4a a6 84 af 97 78 f9 18 49 f3 43 35 d1 41 c0 01 
54 c4 19 76 21 f9 62 4a 67 5b 5a bc 22 ee 7d 5b 
aa ff aa e1 c9 ba ca 2c c3 73 b3 f3 3e 78 e6 14 
3c 39 5a 91 aa 7f ac a6 64 eb 73 3a fd 14 d8 82 
72 59 d9 9a 75 50 fa ca 50 1e f2 b0 4e 33 c2 3a 
a5 1f 4b 9e 82 82 ef db 72 8c c0 ab 09 40 5a 91 
60 7c 63 69 96 1b c8 27 0d 2d 4f 39 fc e6 12 b1`.replace(/[^0-9A-F]/gi, ''), 'hex')
		},
		{
// # --------------------------------
// # RSASSA-PSS Signature Example 1.4
// # --------------------------------

// # Message to be signed:
        msg: Buffer.from(
`bc 65 67 47 fa 9e af b3 f0`.replace(/[^0-9A-F]/gi, ''), 'hex'),

// # Salt:
        salt: Buffer.from(
`05 6f 00 98 5d e1 4d 8e f5 ce a9 e8 2f 8c 27 be 
f7 20 33 5e`.replace(/[^0-9A-F]/gi, ''), 'hex'),

// # Signature:
        sig: Buffer.from(
`46 09 79 3b 23 e9 d0 93 62 dc 21 bb 47 da 0b 4f 
3a 76 22 64 9a 47 d4 64 01 9b 9a ea fe 53 35 9c 
17 8c 91 cd 58 ba 6b cb 78 be 03 46 a7 bc 63 7f 
4b 87 3d 4b ab 38 ee 66 1f 19 96 34 c5 47 a1 ad 
84 42 e0 3d a0 15 b1 36 e5 43 f7 ab 07 c0 c1 3e 
42 25 b8 de 8c ce 25 d4 f6 eb 84 00 f8 1f 7e 18 
33 b7 ee 6e 33 4d 37 09 64 ca 79 fd b8 72 b4 d7 
52 23 b5 ee b0 81 01 59 1f b5 32 d1 55 a6 de 87`.replace(/[^0-9A-F]/gi, ''), 'hex')
		},
		{
// # --------------------------------
// # RSASSA-PSS Signature Example 1.5
// # --------------------------------

// # Message to be signed:
        msg: Buffer.from(
`b4 55 81 54 7e 54 27 77 0c 76 8e 8b 82 b7 55 64 
e0 ea 4e 9c 32 59 4d 6b ff 70 65 44 de 0a 87 76 
c7 a8 0b 45 76 55 0e ee 1b 2a ca bc 7e 8b 7d 3e 
f7 bb 5b 03 e4 62 c1 10 47 ea dd 00 62 9a e5 75 
48 0a c1 47 0f e0 46 f1 3a 2b f5 af 17 92 1d c4 
b0 aa 8b 02 be e6 33 49 11 65 1d 7f 85 25 d1 0f 
32 b5 1d 33 be 52 0d 3d df 5a 70 99 55 a3 df e7 
82 83 b9 e0 ab 54 04 6d 15 0c 17 7f 03 7f dc cc 
5b e4 ea 5f 68 b5 e5 a3 8c 9d 7e dc cc c4 97 5f 
45 5a 69 09 b4`.replace(/[^0-9A-F]/gi, ''), 'hex'),

// # Salt:
        salt: Buffer.from(
`80 e7 0f f8 6a 08 de 3e c6 09 72 b3 9b 4f bf dc 
ea 67 ae 8e`.replace(/[^0-9A-F]/gi, ''), 'hex'),

// # Signature:
        sig: Buffer.from(
`1d 2a ad 22 1c a4 d3 1d df 13 50 92 39 01 93 98 
e3 d1 4b 32 dc 34 dc 5a f4 ae ae a3 c0 95 af 73 
47 9c f0 a4 5e 56 29 63 5a 53 a0 18 37 76 15 b1 
6c b9 b1 3b 3e 09 d6 71 eb 71 e3 87 b8 54 5c 59 
60 da 5a 64 77 6e 76 8e 82 b2 c9 35 83 bf 10 4c 
3f db 23 51 2b 7b 4e 89 f6 33 dd 00 63 a5 30 db 
45 24 b0 1c 3f 38 4c 09 31 0e 31 5a 79 dc d3 d6 
84 02 2a 7f 31 c8 65 a6 64 e3 16 97 8b 75 9f ad`.replace(/[^0-9A-F]/gi, ''), 'hex')
		},
		{

// # --------------------------------
// # RSASSA-PSS Signature Example 1.6
// # --------------------------------

// # Message to be signed:
        msg: Buffer.from(
`10 aa e9 a0 ab 0b 59 5d 08 41 20 7b 70 0d 48 d7 
5f ae dd e3 b7 75 cd 6b 4c c8 8a e0 6e 46 94 ec 
74 ba 18 f8 52 0d 4f 5e a6 9c bb e7 cc 2b eb a4 
3e fd c1 02 15 ac 4e b3 2d c3 02 a1 f5 3d c6 c4 
35 22 67 e7 93 6c fe bf 7c 8d 67 03 57 84 a3 90 
9f a8 59 c7 b7 b5 9b 8e 39 c5 c2 34 9f 18 86 b7 
05 a3 02 67 d4 02 f7 48 6a b4 f5 8c ad 5d 69 ad 
b1 7a b8 cd 0c e1 ca f5 02 5a f4 ae 24 b1 fb 87 
94 c6 07 0c c0 9a 51 e2 f9 91 13 11 e3 87 7d 00 
44 c7 1c 57 a9 93 39 50 08 80 6b 72 3a c3 83 73 
d3 95 48 18 18 52 8c 1e 70 53 73 92 82 05 35 29 
51 0e 93 5c d0 fa 77 b8 fa 53 cc 2d 47 4b d4 fb 
3c c5 c6 72 d6 ff dc 90 a0 0f 98 48 71 2c 4b cf 
e4 6c 60 57 36 59 b1 1e 64 57 e8 61 f0 f6 04 b6 
13 8d 14 4f 8c e4 e2 da 73`.replace(/[^0-9A-F]/gi, ''), 'hex'),

// # Salt:
        salt: Buffer.from(
`a8 ab 69 dd 80 1f 00 74 c2 a1 fc 60 64 98 36 c6 
16 d9 96 81`.replace(/[^0-9A-F]/gi, ''), 'hex'),

// # Signature:
        sig: Buffer.from(
`2a 34 f6 12 5e 1f 6b 0b f9 71 e8 4f bd 41 c6 32 
be 8f 2c 2a ce 7d e8 b6 92 6e 31 ff 93 e9 af 98 
7f bc 06 e5 1e 9b e1 4f 51 98 f9 1f 3f 95 3b d6 
7d a6 0a 9d f5 97 64 c3 dc 0f e0 8e 1c be f0 b7 
5f 86 8d 10 ad 3f ba 74 9f ef 59 fb 6d ac 46 a0 
d6 e5 04 36 93 31 58 6f 58 e4 62 8f 39 aa 27 89 
82 54 3b c0 ee b5 37 dc 61 95 80 19 b3 94 fb 27 
3f 21 58 58 a0 a0 1a c4 d6 50 b9 55 c6 7f 4c 58`.replace(/[^0-9A-F]/gi, ''), 'hex')
		}
	];

	var rsa = new jCastle.pki.rsa();
	rsa.setPrivateKey({
		n, e, d, p, q, dmp1, dmq1, iqmp
	});

	for (var i = 0; i < testVectors.length; i++) {
		var vector = testVectors[i];

		var v_sig = rsa.pssSign(vector.msg, {
			salt: vector.salt,
			hashAlgo: 'sha-1',
			saltLength: vector.salt.length
		});

		assert.ok(v_sig.equals(vector.sig), bits + '-bit pss sign test ' + (i + 1));

		var v = rsa.pssVerify(vector.msg, vector.sig, {
			salt: vector.salt,
			hashAlgo: 'sha-1',
			saltLength: vector.salt.length
		});

		assert.ok(v, bits + '-bit pss verify test ' + (i + 1));
	}

// # =============================================
    
    // # ==================================
    // # Example 2: A 1025-bit RSA Key Pair
    // # ==================================
    var bits = 1025;
    // # ------------------------------
    // # Components of the RSA Key Pair
    // # ------------------------------

    // # RSA modulus n:
    var n = Buffer.from(`
    01 d4 0c 1b cf 97 a6 8a e7 cd bd 8a 7b f3 e3 4f 
    a1 9d cc a4 ef 75 a4 74 54 37 5f 94 51 4d 88 fe 
    d0 06 fb 82 9f 84 19 ff 87 d6 31 5d a6 8a 1f f3 
    a0 93 8e 9a bb 34 64 01 1c 30 3a d9 91 99 cf 0c 
    7c 7a 8b 47 7d ce 82 9e 88 44 f6 25 b1 15 e5 e9 
    c4 a5 9c f8 f8 11 3b 68 34 33 6a 2f d2 68 9b 47 
    2c bb 5e 5c ab e6 74 35 0c 59 b6 c1 7e 17 68 74 
    fb 42 f8 fc 3d 17 6a 01 7e dc 61 fd 32 6c 4b 33 
    c9`.replace(/[^0-9A-F]/gi, ''), 'hex');
    
    // # RSA public exponent e: 
    var e = parseInt(`
    01 00 01`.replace(/[^0-9A-F]/gi, ''), 16);
    
    // # RSA private exponent d: 
    var d = Buffer.from(`
    02 7d 14 7e 46 73 05 73 77 fd 1e a2 01 56 57 72 
    17 6a 7d c3 83 58 d3 76 04 56 85 a2 e7 87 c2 3c 
    15 57 6b c1 6b 9f 44 44 02 d6 bf c5 d9 8a 3e 88 
    ea 13 ef 67 c3 53 ec a0 c0 dd ba 92 55 bd 7b 8b 
    b5 0a 64 4a fd fd 1d d5 16 95 b2 52 d2 2e 73 18 
    d1 b6 68 7a 1c 10 ff 75 54 5f 3d b0 fe 60 2d 5f 
    2b 7f 29 4e 36 01 ea b7 b9 d1 ce cd 76 7f 64 69 
    2e 3e 53 6c a2 84 6c b0 c2 dd 48 6a 39 fa 75 b1`.replace(/[^0-9A-F]/gi, ''), 'hex');
    
    // # Prime p: 
    var p = Buffer.from(`
    01 66 01 e9 26 a0 f8 c9 e2 6e ca b7 69 ea 65 a5 
    e7 c5 2c c9 e0 80 ef 51 94 57 c6 44 da 68 91 c5 
    a1 04 d3 ea 79 55 92 9a 22 e7 c6 8a 7a f9 fc ad 
    77 7c 3c cc 2b 9e 3d 36 50 bc e4 04 39 9b 7e 59 
    d1`.replace(/[^0-9A-F]/gi, ''), 'hex');
    
    // # Prime q: 
    var q = Buffer.from(`
    01 4e af a1 d4 d0 18 4d a7 e3 1f 87 7d 12 81 dd 
    da 62 56 64 86 9e 83 79 e6 7a d3 b7 5e ae 74 a5 
    80 e9 82 7a bd 6e b7 a0 02 cb 54 11 f5 26 67 97 
    76 8f b8 e9 5a e4 0e 3e 8a 01 f3 5f f8 9e 56 c0 
    79`.replace(/[^0-9A-F]/gi, ''), 'hex');
    
    // # p's CRT exponent dP: 
    var dmp1 = Buffer.from(`
    e2 47 cc e5 04 93 9b 8f 0a 36 09 0d e2 00 93 87 
    55 e2 44 4b 29 53 9a 7d a7 a9 02 f6 05 68 35 c0 
    db 7b 52 55 94 97 cf e2 c6 1a 80 86 d0 21 3c 47 
    2c 78 85 18 00 b1 71 f6 40 1d e2 e9 c2 75 6f 31`.replace(/[^0-9A-F]/gi, ''), 'hex');
    
    // # q's CRT exponent dQ: 
    var dmq1 = Buffer.from(`
    b1 2f ba 75 78 55 e5 86 e4 6f 64 c3 8a 70 c6 8b 
    3f 54 8d 93 d7 87 b3 99 99 9d 4c 8f 0b bd 25 81 
    c2 1e 19 ed 00 18 a6 d5 d3 df 86 42 4b 3a bc ad 
    40 19 9d 31 49 5b 61 30 9f 27 c1 bf 55 d4 87 c1`.replace(/[^0-9A-F]/gi, ''), 'hex');
    
    // # CRT coefficient qInv: 
    var iqmp = Buffer.from(`
    56 4b 1e 1f a0 03 bd a9 1e 89 09 04 25 aa c0 5b 
    91 da 9e e2 50 61 e7 62 8d 5f 51 30 4a 84 99 2f 
    dc 33 76 2b d3 78 a5 9f 03 0a 33 4d 53 2b d0 da 
    e8 f2 98 ea 9e d8 44 63 6a d5 fb 8c bd c0 3c ad`.replace(/[^0-9A-F]/gi, ''), 'hex');
    
    var testVectors = [
        {
    // # --------------------------------
    // # RSASSA-PSS Signature Example 2.1
    // # --------------------------------
    
    // # Message to be signed:
            msg: Buffer.from(`
    da ba 03 20 66 26 3f ae db 65 98 48 11 52 78 a5 
    2c 44 fa a3 a7 6f 37 51 5e d3 36 32 10 72 c4 0a 
    9d 9b 53 bc 05 01 40 78 ad f5 20 87 51 46 aa e7 
    0f f0 60 22 6d cb 7b 1f 1f c2 7e 93 60`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Salt:
            salt: Buffer.from(`
    57 bf 16 0b cb 02 bb 1d c7 28 0c f0 45 85 30 b7 
    d2 83 2f f7`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Signature:
            sig: Buffer.from(`
    01 4c 5b a5 33 83 28 cc c6 e7 a9 0b f1 c0 ab 3f 
    d6 06 ff 47 96 d3 c1 2e 4b 63 9e d9 13 6a 5f ec 
    6c 16 d8 88 4b dd 99 cf dc 52 14 56 b0 74 2b 73 
    68 68 cf 90 de 09 9a db 8d 5f fd 1d ef f3 9b a4 
    00 7a b7 46 ce fd b2 2d 7d f0 e2 25 f5 46 27 dc 
    65 46 61 31 72 1b 90 af 44 53 63 a8 35 8b 9f 60 
    76 42 f7 8f ab 0a b0 f4 3b 71 68 d6 4b ae 70 d8 
    82 78 48 d8 ef 1e 42 1c 57 54 dd f4 2c 25 89 b5 
    b3`.replace(/[^0-9A-F]/gi, ''), 'hex')
        },
        {
    
    // # --------------------------------
    // # RSASSA-PSS Signature Example 2.2
    // # --------------------------------
    
    // # Message to be signed:
            msg: Buffer.from(`
    e4 f8 60 1a 8a 6d a1 be 34 44 7c 09 59 c0 58 57 
    0c 36 68 cf d5 1d d5 f9 cc d6 ad 44 11 fe 82 13 
    48 6d 78 a6 c4 9f 93 ef c2 ca 22 88 ce bc 2b 9b 
    60 bd 04 b1 e2 20 d8 6e 3d 48 48 d7 09 d0 32 d1 
    e8 c6 a0 70 c6 af 9a 49 9f cf 95 35 4b 14 ba 61 
    27 c7 39 de 1b b0 fd 16 43 1e 46 93 8a ec 0c f8 
    ad 9e b7 2e 83 2a 70 35 de 9b 78 07 bd c0 ed 8b 
    68 eb 0f 5a c2 21 6b e4 0c e9 20 c0 db 0e dd d3 
    86 0e d7 88 ef ac ca ca 50 2d 8f 2b d6 d1 a7 c1 
    f4 1f f4 6f 16 81 c8 f1 f8 18 e9 c4 f6 d9 1a 0c 
    78 03 cc c6 3d 76 a6 54 4d 84 3e 08 4e 36 3b 8a 
    cc 55 aa 53 17 33 ed b5 de e5 b5 19 6e 9f 03 e8 
    b7 31 b3 77 64 28 d9 e4 57 fe 3f bc b3 db 72 74 
    44 2d 78 58 90 e9 cb 08 54 b6 44 4d ac e7 91 d7 
    27 3d e1 88 97 19 33 8a 77 fe`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Salt:
            salt: Buffer.from(`
    7f 6d d3 59 e6 04 e6 08 70 e8 98 e4 7b 19 bf 2e 
    5a 7b 2a 90`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Signature:
            sig: Buffer.from(`
    01 09 91 65 6c ca 18 2b 7f 29 d2 db c0 07 e7 ae 
    0f ec 15 8e b6 75 9c b9 c4 5c 5f f8 7c 76 35 dd 
    46 d1 50 88 2f 4d e1 e9 ae 65 e7 f7 d9 01 8f 68 
    36 95 4a 47 c0 a8 1a 8a 6b 6f 83 f2 94 4d 60 81 
    b1 aa 7c 75 9b 25 4b 2c 34 b6 91 da 67 cc 02 26 
    e2 0b 2f 18 b4 22 12 76 1d cd 4b 90 8a 62 b3 71 
    b5 91 8c 57 42 af 4b 53 7e 29 69 17 67 4f b9 14 
    19 47 61 62 1c c1 9a 41 f6 fb 95 3f bc bb 64 9d 
    ea`.replace(/[^0-9A-F]/gi, ''), 'hex')
        },
        {
    
    // # --------------------------------
    // # RSASSA-PSS Signature Example 2.3
    // # --------------------------------
    
    // # Message to be signed:
            msg: Buffer.from(`
    52 a1 d9 6c 8a c3 9e 41 e4 55 80 98 01 b9 27 a5 
    b4 45 c1 0d 90 2a 0d cd 38 50 d2 2a 66 d2 bb 07 
    03 e6 7d 58 67 11 45 95 aa bf 5a 7a eb 5a 8f 87 
    03 4b bb 30 e1 3c fd 48 17 a9 be 76 23 00 23 60 
    6d 02 86 a3 fa f8 a4 d2 2b 72 8e c5 18 07 9f 9e 
    64 52 6e 3a 0c c7 94 1a a3 38 c4 37 99 7c 68 0c 
    ca c6 7c 66 bf a1`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Salt:
            salt: Buffer.from(`
    fc a8 62 06 8b ce 22 46 72 4b 70 8a 05 19 da 17 
    e6 48 68 8c`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Signature:
            sig: Buffer.from(`
    00 7f 00 30 01 8f 53 cd c7 1f 23 d0 36 59 fd e5 
    4d 42 41 f7 58 a7 50 b4 2f 18 5f 87 57 85 20 c3 
    07 42 af d8 43 59 b6 e6 e8 d3 ed 95 9d c6 fe 48 
    6b ed c8 e2 cf 00 1f 63 a7 ab e1 62 56 a1 b8 4d 
    f0 d2 49 fc 05 d3 19 4c e5 f0 91 27 42 db bf 80 
    dd 17 4f 6c 51 f6 ba d7 f1 6c f3 36 4e ba 09 5a 
    06 26 7d c3 79 38 03 ac 75 26 ae be 0a 47 5d 38 
    b8 c2 24 7a b5 1c 48 98 df 70 47 dc 6a df 52 c6 
    c4`.replace(/[^0-9A-F]/gi, ''), 'hex')
        },
        {
    
    // # --------------------------------
    // # RSASSA-PSS Signature Example 2.4
    // # --------------------------------
    
    // # Message to be signed:
            msg: Buffer.from(`
    a7 18 2c 83 ac 18 be 65 70 a1 06 aa 9d 5c 4e 3d 
    bb d4 af ae b0 c6 0c 4a 23 e1 96 9d 79 ff`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Salt:
            salt: Buffer.from(`
    80 70 ef 2d e9 45 c0 23 87 68 4b a0 d3 30 96 73 
    22 35 d4 40`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Signature:
            sig: Buffer.from(`
    00 9c d2 f4 ed be 23 e1 23 46 ae 8c 76 dd 9a d3 
    23 0a 62 07 61 41 f1 6c 15 2b a1 85 13 a4 8e f6 
    f0 10 e0 e3 7f d3 df 10 a1 ec 62 9a 0c b5 a3 b5 
    d2 89 30 07 29 8c 30 93 6a 95 90 3b 6b a8 55 55 
    d9 ec 36 73 a0 61 08 fd 62 a2 fd a5 6d 1c e2 e8 
    5c 4d b6 b2 4a 81 ca 3b 49 6c 36 d4 fd 06 eb 7c 
    91 66 d8 e9 48 77 c4 2b ea 62 2b 3b fe 92 51 fd 
    c2 1d 8d 53 71 ba da d7 8a 48 82 14 79 63 35 b4 
    0b`.replace(/[^0-9A-F]/gi, ''), 'hex')
        },
        {
    
    // # --------------------------------
    // # RSASSA-PSS Signature Example 2.5
    // # --------------------------------
    
    // # Message to be signed:
            msg: Buffer.from(`
    86 a8 3d 4a 72 ee 93 2a 4f 56 30 af 65 79 a3 86 
    b7 8f e8 89 99 e0 ab d2 d4 90 34 a4 bf c8 54 dd 
    94 f1 09 4e 2e 8c d7 a1 79 d1 95 88 e4 ae fc 1b 
    1b d2 5e 95 e3 dd 46 1f`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Salt:
            salt: Buffer.from(`
    17 63 9a 4e 88 d7 22 c4 fc a2 4d 07 9a 8b 29 c3 
    24 33 b0 c9`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Signature:
            sig: Buffer.from(`
    00 ec 43 08 24 93 1e bd 3b aa 43 03 4d ae 98 ba 
    64 6b 8c 36 01 3d 16 71 c3 cf 1c f8 26 0c 37 4b 
    19 f8 e1 cc 8d 96 50 12 40 5e 7e 9b f7 37 86 12 
    df cc 85 fc e1 2c da 11 f9 50 bd 0b a8 87 67 40 
    43 6c 1d 25 95 a6 4a 1b 32 ef cf b7 4a 21 c8 73 
    b3 cc 33 aa f4 e3 dc 39 53 de 67 f0 67 4c 04 53 
    b4 fd 9f 60 44 06 d4 41 b8 16 09 8c b1 06 fe 34 
    72 bc 25 1f 81 5f 59 db 2e 43 78 a3 ad dc 18 1e 
    cf`.replace(/[^0-9A-F]/gi, ''), 'hex')
        },
        {
    
    // # --------------------------------
    // # RSASSA-PSS Signature Example 2.6
    // # --------------------------------
    
    // # Message to be signed:
            msg: Buffer.from(`
    04 9f 91 54 d8 71 ac 4a 7c 7a b4 53 25 ba 75 45 
    a1 ed 08 f7 05 25 b2 66 7c f1`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Salt:
            salt: Buffer.from(`
    37 81 0d ef 10 55 ed 92 2b 06 3d f7 98 de 5d 0a 
    ab f8 86 ee`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Signature:
            sig: Buffer.from(`
    00 47 5b 16 48 f8 14 a8 dc 0a bd c3 7b 55 27 f5 
    43 b6 66 bb 6e 39 d3 0e 5b 49 d3 b8 76 dc cc 58 
    ea c1 4e 32 a2 d5 5c 26 16 01 44 56 ad 2f 24 6f 
    c8 e3 d5 60 da 3d df 37 9a 1c 0b d2 00 f1 02 21 
    df 07 8c 21 9a 15 1b c8 d4 ec 9d 2f c2 56 44 67 
    81 10 14 ef 15 d8 ea 01 c2 eb bf f8 c2 c8 ef ab 
    38 09 6e 55 fc be 32 85 c7 aa 55 88 51 25 4f af 
    fa 92 c1 c7 2b 78 75 86 63 ef 45 82 84 31 39 d7 
    a6`.replace(/[^0-9A-F]/gi, ''), 'hex')
        }
    ];

    var rsa = new jCastle.pki.rsa();
    rsa.setPrivateKey({
        n, e, d, p, q, dmp1, dmq1, iqmp
    });

    for (var i = 0; i < testVectors.length; i++) {
        var vector = testVectors[i];

        var v_sig = rsa.pssSign(vector.msg, {
            salt: vector.salt,
            hashAlgo: 'sha-1',
            saltLength: vector.salt.length
        });

        assert.ok(v_sig.equals(vector.sig), bits + '-bit pss sign test ' + (i + 1));
        // console.log(bits + '-bit pss sign test ' + (i + 1) + ': ', v_sig.equals(vector.sig));

        var v = rsa.pssVerify(vector.msg, vector.sig, {
            salt: vector.salt,
            hashAlgo: 'sha-1',
            saltLength: vector.salt.length
        });

        assert.ok(v, bits + '-bit pss verify test ' + (i + 1));
        // console.log(bits + '-bit pss verify test ' + (i + 1) + ': ', v);
    }

    // # =============================================
    
    // # ==================================
    // # Example 3: A 1026-bit RSA Key Pair
    // # ==================================
    var bits = 1026;
    // # ------------------------------
    // # Components of the RSA Key Pair
    // # ------------------------------
    
    // # RSA modulus n: 
    var n = Buffer.from(`
    02 f2 46 ef 45 1e d3 ee bb 9a 31 02 00 cc 25 85 
    9c 04 8e 4b e7 98 30 29 91 11 2e b6 8c e6 db 67 
    4e 28 0d a2 1f ed ed 1a e7 48 80 ca 52 2b 18 db 
    24 93 85 01 28 27 c5 15 f0 e4 66 a1 ff a6 91 d9 
    81 70 57 4e 9d 0e ad b0 87 58 6c a4 89 33 da 3c 
    c9 53 d9 5b d0 ed 50 de 10 dd cb 67 36 10 7d 6c 
    83 1c 7f 66 3e 83 3c a4 c0 97 e7 00 ce 0f b9 45 
    f8 8f b8 5f e8 e5 a7 73 17 25 65 b9 14 a4 71 a4 
    43`.replace(/[^0-9A-F]/gi, ''), 'hex');
    
    // # RSA public exponent e: 
    var e = parseInt(`
    01 00 01`.replace(/[^0-9A-F]/gi, ''), 16);
    
    // # RSA private exponent d: 
    var d = Buffer.from(`
    65 14 51 73 3b 56 de 5a c0 a6 89 a4 ae b6 e6 89 
    4a 69 01 4e 07 6c 88 dd 7a 66 7e ab 32 32 bb cc 
    d2 fc 44 ba 2f a9 c3 1d b4 6f 21 ed d1 fd b2 3c 
    5c 12 8a 5d a5 ba b9 1e 7f 95 2b 67 75 9c 7c ff 
    70 54 15 ac 9f a0 90 7c 7c a6 17 8f 66 8f b9 48 
    d8 69 da 4c c3 b7 35 6f 40 08 df d5 44 9d 32 ee 
    02 d9 a4 77 eb 69 fc 29 26 6e 5d 90 70 51 23 75 
    a5 0f bb cc 27 e2 38 ad 98 42 5f 6e bb f8 89 91`.replace(/[^0-9A-F]/gi, ''), 'hex');
    
    // # Prime p: 
    var p = Buffer.from(`
    01 bd 36 e1 8e ce 4b 0f db 2e 9c 9d 54 8b d1 a7 
    d6 e2 c2 1c 6f dc 35 07 4a 1d 05 b1 c6 c8 b3 d5 
    58 ea 26 39 c9 a9 a4 21 68 01 69 31 72 52 55 8b 
    d1 48 ad 21 5a ac 55 0e 2d cf 12 a8 2d 0e bf e8 
    53`.replace(/[^0-9A-F]/gi, ''), 'hex');
    
    // # Prime q: 
    var q = Buffer.from(`
    01 b1 b6 56 ad 86 d8 e1 9d 5d c8 62 92 b3 a1 92 
    fd f6 e0 dd 37 87 7b ad 14 82 2f a0 01 90 ca b2 
    65 f9 0d 3f 02 05 7b 6f 54 d6 ec b1 44 91 e5 ad 
    ea ce bc 48 bf 0e bd 2a 2a d2 6d 40 2e 54 f6 16 
    51`.replace(/[^0-9A-F]/gi, ''), 'hex');
    
    // # p's CRT exponent dP: 
    var dmp1 = Buffer.from(`
    1f 27 79 fd 2e 3e 5e 6b ae 05 53 95 18 fb a0 cd 
    0e ad 1a a4 51 3a 7c ba 18 f1 cf 10 e3 f6 81 95 
    69 3d 27 8a 0f 0e e7 2f 89 f9 bc 76 0d 80 e2 f9 
    d0 26 1d 51 65 01 c6 ae 39 f1 4a 47 6c e2 cc f5`.replace(/[^0-9A-F]/gi, ''), 'hex');
    
    // # q's CRT exponent dQ: 
    var dmq1 = Buffer.from(`
    01 1a 0d 36 79 4b 04 a8 54 aa b4 b2 46 2d 43 9a 
    50 46 c9 1d 94 0b 2b c6 f7 5b 62 95 6f ef 35 a2 
    a6 e6 3c 53 09 81 7f 30 7b bf f9 d5 9e 7e 33 1b 
    d3 63 f6 d6 68 49 b1 83 46 ad ea 16 9f 0a e9 ae 
    c1`.replace(/[^0-9A-F]/gi, ''), 'hex');
    
    // # CRT coefficient qInv: 
    var iqmp = Buffer.from(`
    0b 30 f0 ec f5 58 75 2f b3 a6 ce 4b a2 b8 c6 75 
    f6 59 eb a6 c3 76 58 5a 1b 39 71 2d 03 8a e3 d2 
    b4 6f cb 41 8a e1 5d 09 05 da 64 40 e1 51 3a 30 
    b9 b7 d6 66 8f bc 5e 88 e5 ab 7a 17 5e 73 ba 35`.replace(/[^0-9A-F]/gi, ''), 'hex');
    
    var testVectors = [
        {
    // # --------------------------------
    // # RSASSA-PSS Signature Example 3.1
    // # --------------------------------
    
    // # Message to be signed:
            msg: Buffer.from(`
    59 4b 37 33 3b bb 2c 84 52 4a 87 c1 a0 1f 75 fc 
    ec 0e 32 56 f1 08 e3 8d ca 36 d7 0d 00 57`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Salt:
            salt: Buffer.from(`
    f3 1a d6 c8 cf 89 df 78 ed 77 fe ac bc c2 f8 b0 
    a8 e4 cf aa`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Signature:
            sig: Buffer.from(`
    00 88 b1 35 fb 17 94 b6 b9 6c 4a 3e 67 81 97 f8 
    ca c5 2b 64 b2 fe 90 7d 6f 27 de 76 11 24 96 4a 
    99 a0 1a 88 27 40 ec fa ed 6c 01 a4 74 64 bb 05 
    18 23 13 c0 13 38 a8 cd 09 72 14 cd 68 ca 10 3b 
    d5 7d 3b c9 e8 16 21 3e 61 d7 84 f1 82 46 7a bf 
    8a 01 cf 25 3e 99 a1 56 ea a8 e3 e1 f9 0e 3c 6e 
    4e 3a a2 d8 3e d0 34 5b 89 fa fc 9c 26 07 7c 14 
    b6 ac 51 45 4f a2 6e 44 6e 3a 2f 15 3b 2b 16 79 
    7f`.replace(/[^0-9A-F]/gi, ''), 'hex')
        },
        {
    
    // # --------------------------------
    // # RSASSA-PSS Signature Example 3.2
    // # --------------------------------
    
    // # Message to be signed:
            msg: Buffer.from(`
    8b 76 95 28 88 4a 0d 1f fd 09 0c f1 02 99 3e 79 
    6d ad cf bd dd 38 e4 4f f6 32 4c a4 51`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Salt:
            salt: Buffer.from(`
    fc f9 f0 e1 f1 99 a3 d1 d0 da 68 1c 5b 86 06 fc 
    64 29 39 f7`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Signature:
            sig: Buffer.from(`
    02 a5 f0 a8 58 a0 86 4a 4f 65 01 7a 7d 69 45 4f 
    3f 97 3a 29 99 83 9b 7b bc 48 bf 78 64 11 69 17 
    95 56 f5 95 fa 41 f6 ff 18 e2 86 c2 78 30 79 bc 
    09 10 ee 9c c3 4f 49 ba 68 11 24 f9 23 df a8 8f 
    42 61 41 a3 68 a5 f5 a9 30 c6 28 c2 c3 c2 00 e1 
    8a 76 44 72 1a 0c be c6 dd 3f 62 79 bd e3 e8 f2 
    be 5e 2d 4e e5 6f 97 e7 ce af 33 05 4b e7 04 2b 
    d9 1a 63 bb 09 f8 97 bd 41 e8 11 97 de e9 9b 11 
    af`.replace(/[^0-9A-F]/gi, ''), 'hex')
        },
        {
    
    // # --------------------------------
    // # RSASSA-PSS Signature Example 3.3
    // # --------------------------------
    
    // # Message to be signed:
            msg: Buffer.from(`
    1a bd ba 48 9c 5a da 2f 99 5e d1 6f 19 d5 a9 4d 
    9e 6e c3 4a 8d 84 f8 45 57 d2 6e 5e f9 b0 2b 22 
    88 7e 3f 9a 4b 69 0a d1 14 92 09 c2 0c 61 43 1f 
    0c 01 7c 36 c2 65 7b 35 d7 b0 7d 3f 5a d8 70 85 
    07 a9 c1 b8 31 df 83 5a 56 f8 31 07 18 14 ea 5d 
    3d 8d 8f 6a de 40 cb a3 8b 42 db 7a 2d 3d 7a 29 
    c8 f0 a7 9a 78 38 cf 58 a9 75 7f a2 fe 4c 40 df 
    9b aa 19 3b fc 6f 92 b1 23 ad 57 b0 7a ce 3e 6a 
    c0 68 c9 f1 06 af d9 ee b0 3b 4f 37 c2 5d bf bc 
    fb 30 71 f6 f9 77 17 66 d0 72 f3 bb 07 0a f6 60 
    55 32 97 3a e2 50 51`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Salt:
            salt: Buffer.from(`
    98 6e 7c 43 db b6 71 bd 41 b9 a7 f4 b6 af c8 0e 
    80 5f 24 23`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Signature:
            sig: Buffer.from(`
    02 44 bc d1 c8 c1 69 55 73 6c 80 3b e4 01 27 2e 
    18 cb 99 08 11 b1 4f 72 db 96 41 24 d5 fa 76 06 
    49 cb b5 7a fb 87 55 db b6 2b f5 1f 46 6c f2 3a 
    0a 16 07 57 6e 98 3d 77 8f ce ff a9 2d f7 54 8a 
    ea 8e a4 ec ad 2c 29 dd 9f 95 bc 07 fe 91 ec f8 
    be e2 55 bf e8 76 2f d7 69 0a a9 bf a4 fa 08 49 
    ef 72 8c 2c 42 c4 53 23 64 52 2d f2 ab 7f 9f 8a 
    03 b6 3f 7a 49 91 75 82 86 68 f5 ef 5a 29 e3 80 
    2c`.replace(/[^0-9A-F]/gi, ''), 'hex')
        },
        {
    
    // # --------------------------------
    // # RSASSA-PSS Signature Example 3.4
    // # --------------------------------
    
    // # Message to be signed:
            msg: Buffer.from(`
    8f b4 31 f5 ee 79 2b 6c 2a c7 db 53 cc 42 86 55 
    ae b3 2d 03 f4 e8 89 c5 c2 5d e6 83 c4 61 b5 3a 
    cf 89 f9 f8 d3 aa bd f6 b9 f0 c2 a1 de 12 e1 5b 
    49 ed b3 91 9a 65 2f e9 49 1c 25 a7 fc e1 f7 22 
    c2 54 36 08 b6 9d c3 75 ec`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Salt:
            salt: Buffer.from(`
    f8 31 2d 9c 8e ea 13 ec 0a 4c 7b 98 12 0c 87 50 
    90 87 c4 78`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Signature:
            sig: Buffer.from(`
    01 96 f1 2a 00 5b 98 12 9c 8d f1 3c 4c b1 6f 8a 
    a8 87 d3 c4 0d 96 df 3a 88 e7 53 2e f3 9c d9 92 
    f2 73 ab c3 70 bc 1b e6 f0 97 cf eb bf 01 18 fd 
    9e f4 b9 27 15 5f 3d f2 2b 90 4d 90 70 2d 1f 7b 
    a7 a5 2b ed 8b 89 42 f4 12 cd 7b d6 76 c9 d1 8e 
    17 03 91 dc d3 45 c0 6a 73 09 64 b3 f3 0b cc e0 
    bb 20 ba 10 6f 9a b0 ee b3 9c f8 a6 60 7f 75 c0 
    34 7f 0a f7 9f 16 af a0 81 d2 c9 2d 1e e6 f8 36 
    b8`.replace(/[^0-9A-F]/gi, ''), 'hex')
        },
        {
    
    // # --------------------------------
    // # RSASSA-PSS Signature Example 3.5
    // # --------------------------------
    
    // # Message to be signed:
            msg: Buffer.from(`
    fe f4 16 1d fa af 9c 52 95 05 1d fc 1f f3 81 0c 
    8c 9e c2 e8 66 f7 07 54 22 c8 ec 42 16 a9 c4 ff 
    49 42 7d 48 3c ae 10 c8 53 4a 41 b2 fd 15 fe e0 
    69 60 ec 6f b3 f7 a7 e9 4a 2f 8a 2e 3e 43 dc 4a 
    40 57 6c 30 97 ac 95 3b 1d e8 6f 0b 4e d3 6d 64 
    4f 23 ae 14 42 55 29 62 24 64 ca 0c bf 0b 17 41 
    34 72 38 15 7f ab 59 e4 de 55 24 09 6d 62 ba ec 
    63 ac 64`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Salt:
            salt: Buffer.from(`
    50 32 7e fe c6 29 2f 98 01 9f c6 7a 2a 66 38 56 
    3e 9b 6e 2d`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Signature:
            sig: Buffer.from(`
    02 1e ca 3a b4 89 22 64 ec 22 41 1a 75 2d 92 22 
    10 76 d4 e0 1c 0e 6f 0d de 9a fd 26 ba 5a cf 6d 
    73 9e f9 87 54 5d 16 68 3e 56 74 c9 e7 0f 1d e6 
    49 d7 e6 1d 48 d0 ca eb 4f b4 d8 b2 4f ba 84 a6 
    e3 10 8f ee 7d 07 05 97 32 66 ac 52 4b 4a d2 80 
    f7 ae 17 dc 59 d9 6d 33 51 58 6b 5a 3b db 89 5d 
    1e 1f 78 20 ac 61 35 d8 75 34 80 99 83 82 ba 32 
    b7 34 95 59 60 8c 38 74 52 90 a8 5e f4 e9 f9 bd 
    83`.replace(/[^0-9A-F]/gi, ''), 'hex')
        },
        {
    
    // # --------------------------------
    // # RSASSA-PSS Signature Example 3.6
    // # --------------------------------
    
    // # Message to be signed:
            msg: Buffer.from(`
    ef d2 37 bb 09 8a 44 3a ee b2 bf 6c 3f 8c 81 b8 
    c0 1b 7f cb 3f eb`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Salt:
            salt: Buffer.from(`
    b0 de 3f c2 5b 65 f5 af 96 b1 d5 cc 3b 27 d0 c6 
    05 30 87 b3`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Signature:
            sig: Buffer.from(`
    01 2f af ec 86 2f 56 e9 e9 2f 60 ab 0c 77 82 4f 
    42 99 a0 ca 73 4e d2 6e 06 44 d5 d2 22 c7 f0 bd 
    e0 39 64 f8 e7 0a 5c b6 5e d4 4e 44 d5 6a e0 ed 
    f1 ff 86 ca 03 2c c5 dd 44 04 db b7 6a b8 54 58 
    6c 44 ee d8 33 6d 08 d4 57 ce 6c 03 69 3b 45 c0 
    f1 ef ef 93 62 4b 95 b8 ec 16 9c 61 6d 20 e5 53 
    8e bc 0b 67 37 a6 f8 2b 4b c0 57 09 24 fc 6b 35 
    75 9a 33 48 42 62 79 f8 b3 d7 74 4e 2d 22 24 26 
    ce`.replace(/[^0-9A-F]/gi, ''), 'hex')
        }
    ];

    var rsa = new jCastle.pki.rsa();
    rsa.setPrivateKey({
        n, e, d, p, q, dmp1, dmq1, iqmp
    });

    for (var i = 0; i < testVectors.length; i++) {
        var vector = testVectors[i];

        var v_sig = rsa.pssSign(vector.msg, {
            salt: vector.salt,
            hashAlgo: 'sha-1',
            saltLength: vector.salt.length
        });

        assert.ok(v_sig.equals(vector.sig), bits + '-bit pss sign test ' + (i + 1));
        // console.log(bits + '-bit pss sign test ' + (i + 1) + ': ', v_sig.equals(vector.sig));

        var v = rsa.pssVerify(vector.msg, vector.sig, {
            salt: vector.salt,
            hashAlgo: 'sha-1',
            saltLength: vector.salt.length
        });

        assert.ok(v, bits + '-bit pss verify test ' + (i + 1));
        // console.log(bits + '-bit pss verify test ' + (i + 1) + ': ', v);
    }

    
    // # =============================================
    
    // # ==================================
    // # Example 4: A 1027-bit RSA Key Pair
    // # ==================================
    var bits = 1027;
    // # ------------------------------
    // # Components of the RSA Key Pair
    // # ------------------------------
    
    // # RSA modulus n: 
    var n = Buffer.from(`
    05 4a db 78 86 44 7e fe 6f 57 e0 36 8f 06 cf 52 
    b0 a3 37 07 60 d1 61 ce f1 26 b9 1b e7 f8 9c 42 
    1b 62 a6 ec 1d a3 c3 11 d7 5e d5 0e 0a b5 ff f3 
    fd 33 8a cc 3a a8 a4 e7 7e e2 63 69 ac b8 1b a9 
    00 fa 83 f5 30 0c f9 bb 6c 53 ad 1d c8 a1 78 b8 
    15 db 42 35 a9 a9 da 0c 06 de 4e 61 5e a1 27 7c 
    e5 59 e9 c1 08 de 58 c1 4a 81 aa 77 f5 a6 f8 d1 
    33 54 94 49 88 48 c8 b9 59 40 74 0b e7 bf 7c 37 
    05`.replace(/[^0-9A-F]/gi, ''), 'hex');
    
    // # RSA public exponent e: 
    var e = parseInt(`
    01 00 01`.replace(/[^0-9A-F]/gi, ''), 16);
    
    // # RSA private exponent d: 
    var d = Buffer.from(`
    fa 04 1f 8c d9 69 7c ee d3 8e c8 ca a2 75 52 3b 
    4d d7 2b 09 a3 01 d3 54 1d 72 f5 d3 1c 05 cb ce 
    2d 69 83 b3 61 83 af 10 69 0b d4 6c 46 13 1e 35 
    78 94 31 a5 56 77 1d d0 04 9b 57 46 1b f0 60 c1 
    f6 84 72 e8 a6 7c 25 f3 57 e5 b6 b4 73 8f a5 41 
    a7 30 34 6b 4a 07 64 9a 2d fa 80 6a 69 c9 75 b6 
    ab a6 46 78 ac c7 f5 91 3e 89 c6 22 f2 d8 ab b1 
    e3 e3 25 54 e3 9d f9 4b a6 0c 00 2e 38 7d 90 11`.replace(/[^0-9A-F]/gi, ''), 'hex');
    
    // # Prime p: 
    var p = Buffer.from(`
    02 92 32 33 6d 28 38 94 5d ba 9d d7 72 3f 4e 62 
    4a 05 f7 37 5b 92 7a 87 ab e6 a8 93 a1 65 8f d4 
    9f 47 f6 c7 b0 fa 59 6c 65 fa 68 a2 3f 0a b4 32 
    96 2d 18 d4 34 3b d6 fd 67 1a 5e a8 d1 48 41 39 
    95`.replace(/[^0-9A-F]/gi, ''), 'hex');
    
    // # Prime q: 
    var q = Buffer.from(`
    02 0e f5 ef e7 c5 39 4a ed 22 72 f7 e8 1a 74 f4 
    c0 2d 14 58 94 cb 1b 3c ab 23 a9 a0 71 0a 2a fc 
    7e 33 29 ac bb 74 3d 01 f6 80 c4 d0 2a fb 4c 8f 
    de 7e 20 93 08 11 bb 2b 99 57 88 b5 e8 72 c2 0b 
    b1`.replace(/[^0-9A-F]/gi, ''), 'hex');
    
    // # p's CRT exponent dP: 
    var dmp1 = Buffer.from(`
    02 6e 7e 28 01 0e cf 24 12 d9 52 3a d7 04 64 7f 
    b4 fe 9b 66 b1 a6 81 58 1b 0e 15 55 3a 89 b1 54 
    28 28 89 8f 27 24 3e ba b4 5f f5 e1 ac b9 d4 df 
    1b 05 1f bc 62 82 4d bc 6f 6c 93 26 1a 78 b9 a7 
    59`.replace(/[^0-9A-F]/gi, ''), 'hex');
    
    // # q's CRT exponent dQ: 
    var dmq1 = Buffer.from(`
    01 2d dc c8 6e f6 55 99 8c 39 dd ae 11 71 86 69 
    e5 e4 6c f1 49 5b 07 e1 3b 10 14 cd 69 b3 af 68 
    30 4a d2 a6 b6 43 21 e7 8b f3 bb ca 9b b4 94 e9 
    1d 45 17 17 e2 d9 75 64 c6 54 94 65 d0 20 5c f4 
    21`.replace(/[^0-9A-F]/gi, ''), 'hex');
    
    // # CRT coefficient qInv: 
    var iqmp = Buffer.from(`
    01 06 00 c4 c2 18 47 45 9f e5 76 70 3e 2e be ca 
    e8 a5 09 4e e6 3f 53 6b f4 ac 68 d3 c1 3e 5e 4f 
    12 ac 5c c1 0a b6 a2 d0 5a 19 92 14 d1 82 47 47 
    d5 51 90 96 36 b7 74 c2 2c ac 0b 83 75 99 ab cc 
    75`.replace(/[^0-9A-F]/gi, ''), 'hex');


    var testVectors = [
        {
    
    // # --------------------------------
    // # RSASSA-PSS Signature Example 4.1
    // # --------------------------------
    
    // # Message to be signed:
            msg: Buffer.from(`
    9f b0 3b 82 7c 82 17 d9`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Salt:
            salt: Buffer.from(`
    ed 7c 98 c9 5f 30 97 4f be 4f bd dc f0 f2 8d 60 
    21 c0 e9 1d`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Signature:
            sig: Buffer.from(`
    03 23 d5 b7 bf 20 ba 45 39 28 9a e4 52 ae 42 97 
    08 0f ef f4 51 84 23 ff 48 11 a8 17 83 7e 7d 82 
    f1 83 6c df ab 54 51 4f f0 88 7b dd ee bf 40 bf 
    99 b0 47 ab c3 ec fa 6a 37 a3 ef 00 f4 a0 c4 a8 
    8a ae 09 04 b7 45 c8 46 c4 10 7e 87 97 72 3e 8a 
    c8 10 d9 e3 d9 5d fa 30 ff 49 66 f4 d7 5d 13 76 
    8d 20 85 7f 2b 14 06 f2 64 cf e7 5e 27 d7 65 2f 
    4b 5e d3 57 5f 28 a7 02 f8 c4 ed 9c f9 b2 d4 49 
    48`.replace(/[^0-9A-F]/gi, ''), 'hex')
        },
        {
    
    // # --------------------------------
    // # RSASSA-PSS Signature Example 4.2
    // # --------------------------------
    
    // # Message to be signed:
            msg: Buffer.from(`
    0c a2 ad 77 79 7e ce 86 de 5b f7 68 75 0d db 5e 
    d6 a3 11 6a d9 9b bd 17 ed f7 f7 82 f0 db 1c d0 
    5b 0f 67 74 68 c5 ea 42 0d c1 16 b1 0e 80 d1 10 
    de 2b 04 61 ea 14 a3 8b e6 86 20 39 2e 7e 89 3c 
    b4 ea 93 93 fb 88 6c 20 ff 79 06 42 30 5b f3 02 
    00 38 92 e5 4d f9 f6 67 50 9d c5 39 20 df 58 3f 
    50 a3 dd 61 ab b6 fa b7 5d 60 03 77 e3 83 e6 ac 
    a6 71 0e ee a2 71 56 e0 67 52 c9 4c e2 5a e9 9f 
    cb f8 59 2d be 2d 7e 27 45 3c b4 4d e0 71 00 eb 
    b1 a2 a1 98 11 a4 78 ad be ab 27 0f 94 e8 fe 36 
    9d 90 b3 ca 61 2f 9f`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Salt:
            salt: Buffer.from(`
    22 d7 1d 54 36 3a 42 17 aa 55 11 3f 05 9b 33 84 
    e3 e5 7e 44`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Signature:
            sig: Buffer.from(`
    04 9d 01 85 84 5a 26 4d 28 fe b1 e6 9e da ec 09 
    06 09 e8 e4 6d 93 ab b3 83 71 ce 51 f4 aa 65 a5 
    99 bd aa a8 1d 24 fb a6 6a 08 a1 16 cb 64 4f 3f 
    1e 65 3d 95 c8 9d b8 bb d5 da ac 27 09 c8 98 40 
    00 17 84 10 a7 c6 aa 86 67 dd c3 8c 74 1f 71 0e 
    c8 66 5a a9 05 2b e9 29 d4 e3 b1 67 82 c1 66 21 
    14 c5 41 4b b0 35 34 55 c3 92 fc 28 f3 db 59 05 
    4b 5f 36 5c 49 e1 d1 56 f8 76 ee 10 cb 4f d7 05 
    98`.replace(/[^0-9A-F]/gi, ''), 'hex')
        },
        {
    
    // # --------------------------------
    // # RSASSA-PSS Signature Example 4.3
    // # --------------------------------
    
    // # Message to be signed:
            msg: Buffer.from(`
    28 80 62 af c0 8f cd b7 c5 f8 65 0b 29 83 73 00 
    46 1d d5 67 6c 17 a2 0a 3c 8f b5 14 89 49 e3 f7 
    3d 66 b3 ae 82 c7 24 0e 27 c5 b3 ec 43 28 ee 7d 
    6d df 6a 6a 0c 9b 5b 15 bc da 19 6a 9d 0c 76 b1 
    19 d5 34 d8 5a bd 12 39 62 d5 83 b7 6c e9 d1 80 
    bc e1 ca`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Salt:
            salt: Buffer.from(`
    4a f8 70 fb c6 51 60 12 ca 91 6c 70 ba 86 2a c7 
    e8 24 36 17`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Signature:
            sig: Buffer.from(`
    03 fb c4 10 a2 ce d5 95 00 fb 99 f9 e2 af 27 81 
    ad a7 4e 13 14 56 24 60 27 82 e2 99 48 13 ee fc 
    a0 51 9e cd 25 3b 85 5f b6 26 a9 0d 77 1e ae 02 
    8b 0c 47 a1 99 cb d9 f8 e3 26 97 34 af 41 63 59 
    90 90 71 3a 3f a9 10 fa 09 60 65 27 21 43 2b 97 
    10 36 a7 18 1a 2b c0 ca b4 3b 0b 59 8b c6 21 74 
    61 d7 db 30 5f f7 e9 54 c5 b5 bb 23 1c 39 e7 91 
    af 6b cf a7 6b 14 7b 08 13 21 f7 26 41 48 2a 2a 
    ad`.replace(/[^0-9A-F]/gi, ''), 'hex')
        },
        {
    
    // # --------------------------------
    // # RSASSA-PSS Signature Example 4.4
    // # --------------------------------
    
    // # Message to be signed:
            msg: Buffer.from(`
    6f 4f 9a b9 50 11 99 ce f5 5c 6c f4 08 fe 7b 36 
    c5 57 c4 9d 42 0a 47 63 d2 46 3c 8a d4 4b 3c fc 
    5b e2 74 2c 0e 7d 9b 0f 66 08 f0 8c 7f 47 b6 93 
    ee`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Salt:
            salt: Buffer.from(`
    40 d2 e1 80 fa e1 ea c4 39 c1 90 b5 6c 2c 0e 14 
    dd f9 a2 26`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Signature:
            sig: Buffer.from(`
    04 86 64 4b c6 6b f7 5d 28 33 5a 61 79 b1 08 51 
    f4 3f 09 bd ed 9f ac 1a f3 32 52 bb 99 53 ba 42 
    98 cd 64 66 b2 75 39 a7 0a da a3 f8 9b 3d b3 c7 
    4a b6 35 d1 22 f4 ee 7c e5 57 a6 1e 59 b8 2f fb 
    78 66 30 e5 f9 db 53 c7 7d 9a 0c 12 fa b5 95 8d 
    4c 2c e7 da a8 07 cd 89 ba 2c c7 fc d0 2f f4 70 
    ca 67 b2 29 fc ce 81 4c 85 2c 73 cc 93 be a3 5b 
    e6 84 59 ce 47 8e 9d 46 55 d1 21 c8 47 2f 37 1d 
    4f`.replace(/[^0-9A-F]/gi, ''), 'hex')
        },
        {
    
    // # --------------------------------
    // # RSASSA-PSS Signature Example 4.5
    // # --------------------------------
    
    // # Message to be signed:
            msg: Buffer.from(`
    e1 7d 20 38 5d 50 19 55 82 3c 3f 66 62 54 c1 d3 
    dd 36 ad 51 68 b8 f1 8d 28 6f dc f6 7a 7d ad 94 
    09 70 85 fa b7 ed 86 fe 21 42 a2 87 71 71 79 97 
    ef 1a 7a 08 88 4e fc 39 35 6d 76 07 7a af 82 45 
    9a 7f ad 45 84 88 75 f2 81 9b 09 89 37 fe 92 3b 
    cc 9d c4 42 d7 2d 75 4d 81 20 25 09 0c 9b c0 3d 
    b3 08 0c 13 8d d6 3b 35 5d 0b 4b 85 d6 68 8a c1 
    9f 4d e1 50 84 a0 ba 4e 37 3b 93 ef 4a 55 50 96 
    69 19 15 dc 23 c0 0e 95 4c de b2 0a 47 cd 55 d1 
    6c 3d 86 81 d4 6e d7 f2 ed 5e a4 27 95 be 17 ba 
    ed 25 f0 f4 d1 13 b3 63 6a dd d5 85 f1 6a 8b 5a 
    ec 0c 8f a9 c5 f0 3c bf 3b 9b 73`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Salt:
            salt: Buffer.from(`
    24 97 dc 2b 46 15 df ae 5a 66 3d 49 ff d5 6b f7 
    ef c1 13 04`.replace(/[^0-9A-F]/gi, ''), 'hex'), 
    
    // # Signature:
            sig: Buffer.from(`
    02 2a 80 04 53 53 90 4c b3 0c bb 54 2d 7d 49 90 
    42 1a 6e ec 16 a8 02 9a 84 22 ad fd 22 d6 af f8 
    c4 cc 02 94 af 11 0a 0c 06 7e c8 6a 7d 36 41 34 
    45 9b b1 ae 8f f8 36 d5 a8 a2 57 98 40 99 6b 32 
    0b 19 f1 3a 13 fa d3 78 d9 31 a6 56 25 da e2 73 
    9f 0c 53 67 0b 35 d9 d3 cb ac 08 e7 33 e4 ec 2b 
    83 af 4b 91 96 d6 3e 7c 4f f1 dd ea e2 a1 22 79 
    1a 12 5b fe a8 de b0 de 8c cf 1f 4f fa f6 e6 fb 
    0a`.replace(/[^0-9A-F]/gi, ''), 'hex')
        },
        {
    
    // # --------------------------------
    // # RSASSA-PSS Signature Example 4.6
    // # --------------------------------
    
    // # Message to be signed:
            msg: Buffer.from(`
    af bc 19 d4 79 24 90 18 fd f4 e0 9f 61 87 26 44 
    04 95 de 11 dd ee e3 88 72 d7 75 fc ea 74 a2 38 
    96 b5 34 3c 9c 38 d4 6a f0 db a2 24 d0 47 58 0c 
    c6 0a 65 e9 39 1c f9 b5 9b 36 a8 60 59 8d 4e 82 
    16 72 2f 99 3b 91 cf ae 87 bc 25 5a f8 9a 6a 19 
    9b ca 4a 39 1e ad bc 3a 24 90 3c 0b d6 67 36 8f 
    6b e7 8e 3f ea bf b4 ff d4 63 12 27 63 74 0f fb 
    be fe ab 9a 25 56 4b c5 d1 c2 4c 93 e4 22 f7 50 
    73 e2 ad 72 bf 45 b1 0d f0 0b 52 a1 47 12 8e 73 
    fe e3 3f a3 f0 57 7d 77 f8 0f bc 2d f1 be d3 13 
    29 0c 12 77 7f 50`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Salt:
            salt: Buffer.from(`
    a3 34 db 6f ae bf 11 08 1a 04 f8 7c 2d 62 1c de 
    c7 93 0b 9b`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Signature:
            sig: Buffer.from(`
    00 93 8d cb 6d 58 30 46 06 5f 69 c7 8d a7 a1 f1 
    75 70 66 a7 fa 75 12 5a 9d 29 29 f0 b7 9a 60 b6 
    27 b0 82 f1 1f 5b 19 6f 28 eb 9d aa 6f 21 c0 5e 
    51 40 f6 ae f1 73 7d 20 23 07 5c 05 ec f0 4a 02 
    8c 68 6a 2a b3 e7 d5 a0 66 4f 29 5c e1 29 95 e8 
    90 90 8b 6a d2 1f 08 39 eb 65 b7 03 93 a7 b5 af 
    d9 87 1d e0 ca a0 ce de c5 b8 19 62 67 56 20 9d 
    13 ab 1e 7b b9 54 6a 26 ff 37 e9 a5 1a f9 fd 56 
    2e`.replace(/[^0-9A-F]/gi, ''), 'hex')
        }
    ];

    var rsa = new jCastle.pki.rsa();
    rsa.setPrivateKey({
        n, e, d, p, q, dmp1, dmq1, iqmp
    });

    for (var i = 0; i < testVectors.length; i++) {
        var vector = testVectors[i];

        var v_sig = rsa.pssSign(vector.msg, {
            salt: vector.salt,
            hashAlgo: 'sha-1',
            saltLength: vector.salt.length
        });

        assert.ok(v_sig.equals(vector.sig), bits + '-bit pss sign test ' + (i + 1));
        // console.log(bits + '-bit pss sign test ' + (i + 1) + ': ', v_sig.equals(vector.sig));

        var v = rsa.pssVerify(vector.msg, vector.sig, {
            salt: vector.salt,
            hashAlgo: 'sha-1',
            saltLength: vector.salt.length
        });

        assert.ok(v, bits + '-bit pss verify test ' + (i + 1));
        // console.log(bits + '-bit pss verify test ' + (i + 1) + ': ', v);
    }

    
    // # =============================================
    
    // # ==================================
    // # Example 5: A 1028-bit RSA Key Pair
    // # ==================================
    var bits = 1028;
    // # ------------------------------
    // # Components of the RSA Key Pair
    // # ------------------------------
    
    // # RSA modulus n: 
    var n = Buffer.from(`
    0d 10 f6 61 f2 99 40 f5 ed 39 aa 26 09 66 de b4 
    78 43 67 9d 2b 6f b2 5b 3d e3 70 f3 ac 7c 19 91 
    63 91 fd 25 fb 52 7e bf a6 a4 b4 df 45 a1 75 9d 
    99 6c 4b b4 eb d1 88 28 c4 4f c5 2d 01 91 87 17 
    40 52 5f 47 a4 b0 cc 8d a3 25 ed 8a a6 76 b0 d0 
    f6 26 e0 a7 7f 07 69 21 70 ac ac 80 82 f4 2f aa 
    7d c7 cd 12 3e 73 0e 31 a8 79 85 20 4c ab cb e6 
    67 0d 43 a2 dd 2b 2d de f5 e0 53 92 fc 21 3b c5 
    07`.replace(/[^0-9A-F]/gi, ''), 'hex');
    
    // # RSA public exponent e: 
    var e = parseInt(`
    01 00 01`.replace(/[^0-9A-F]/gi, ''), 16);
    
    // # RSA private exponent d: 
    var d = Buffer.from(`
    03 ce 08 b1 04 ff f3 96 a9 79 bd 3e 4e 46 92 5b 
    63 19 dd b6 3a cb cf d8 19 f1 7d 16 b8 07 7b 3a 
    87 10 1f f3 4b 77 fe 48 b8 b2 05 a9 6e 91 51 ba 
    8e ce a6 4d 0c ce 7b 23 c3 e6 a6 b8 30 58 bc 49 
    da e8 16 ae 73 6d b5 a4 70 8e 2a d4 35 23 2b 56 
    7f 90 96 ce 59 ff 28 06 1e 79 ab 1c 02 d7 17 e6 
    b2 3c ea 6d b8 eb 51 92 fa 7c 1e ab 22 7d ba 74 
    62 1c 45 60 18 96 ee f1 37 92 c8 44 0b eb 15 aa 
    c1`.replace(/[^0-9A-F]/gi, ''), 'hex');
    
    // # Prime p: 
    var p = Buffer.from(`
    03 f2 f3 31 f4 14 2d 4f 24 b4 3a a1 02 79 a8 96 
    52 d4 e7 53 72 21 a1 a7 b2 a2 5d eb 55 1e 5d e9 
    ac 49 74 11 c2 27 a9 4e 45 f9 1c 2d 1c 13 cc 04 
    6c f4 ce 14 e3 2d 05 87 34 21 0d 44 a8 7e e1 b7 
    3f`.replace(/[^0-9A-F]/gi, ''), 'hex');
    
    // # Prime q: 
    var q = Buffer.from(`
    03 4f 09 0d 73 b5 58 03 03 0c f0 36 1a 5d 80 81 
    bf b7 9f 85 15 23 fe ac 0a 21 24 d0 8d 40 13 ff 
    08 48 77 71 a8 70 d0 47 9d c0 68 6c 62 f7 71 8d 
    fe cf 02 4b 17 c9 26 76 78 05 91 71 33 9c c0 08 
    39`.replace(/[^0-9A-F]/gi, ''), 'hex');
    
    // # p's CRT exponent dP: 
    var dmp1 = Buffer.from(`
    02 aa 66 3a db f5 1a b8 87 a0 18 cb 42 6e 78 bc 
    2f e1 82 dc b2 f7 bc b5 04 41 d1 7f df 0f 06 79 
    8b 50 71 c6 e2 f5 fe b4 d5 4a d8 18 23 11 c1 ef 
    62 d4 c4 9f 18 d1 f5 1f 54 b2 d2 cf fb a4 da 1b 
    e5`.replace(/[^0-9A-F]/gi, ''), 'hex');
    
    // # q's CRT exponent dQ: 
    var dmq1 = Buffer.from(`
    02 bb e7 06 07 8b 5c 0b 39 15 12 d4 11 db 1b 19 
    9b 5a 56 64 b8 40 42 ea d3 7f e9 94 ae 72 b9 53 
    2d fb fb 3e 9e 69 81 a0 fb b8 06 51 31 41 b7 c2 
    16 3f e5 6c 39 5e 4b fa ee 57 e3 83 3f 9b 91 8d 
    f9`.replace(/[^0-9A-F]/gi, ''), 'hex');
    
    // # CRT coefficient qInv: 
    var iqmp = Buffer.from(`
    02 42 b6 cd 00 d3 0a 76 7a ee 9a 89 8e ad 45 3c 
    8e ae a6 3d 50 0b 7d 1e 00 71 3e da e5 1c e3 6b 
    23 b6 64 df 26 e6 3e 26 6e c8 f7 6e 6e 63 ed 1b 
    a4 1e b0 33 b1 20 f7 ea 52 12 ae 21 a9 8f bc 16`.replace(/[^0-9A-F]/gi, ''), 'hex');

    var testVectors = [
        {
    
    // # --------------------------------
    // # RSASSA-PSS Signature Example 5.1
    // # --------------------------------
    
    // # Message to be signed:
            msg: Buffer.from(`
    30 c7 d5 57 45 8b 43 6d ec fd c1 4d 06 cb 7b 96 
    b0 67 18 c4 8d 7d e5 74 82 a8 68 ae 7f 06 58 70 
    a6 21 65 06 d1 1b 77 93 23 df df 04 6c f5 77 51 
    29 13 4b 4d 56 89 e4 d9 c0 ce 1e 12 d7 d4 b0 6c 
    b5 fc 58 20 de cf a4 1b af 59 bf 25 7b 32 f0 25 
    b7 67 9b 44 5b 94 99 c9 25 55 14 58 85 99 2f 1b 
    76 f8 48 91 ee 4d 3b e0 f5 15 0f d5 90 1e 3a 4c 
    8e d4 3f d3 6b 61 d0 22 e6 5a d5 00 8d bf 33 29 
    3c 22 bf bf d0 73 21 f0 f1 d5 fa 9f df 00 14 c2 
    fc b0 35 8a ad 0e 35 4b 0d 29`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Salt:
            salt: Buffer.from(`
    08 1b 23 3b 43 56 77 50 bd 6e 78 f3 96 a8 8b 9f 
    6a 44 51 51`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Signature:
            sig: Buffer.from(`
    0b a3 73 f7 6e 09 21 b7 0a 8f bf e6 22 f0 bf 77 
    b2 8a 3d b9 8e 36 10 51 c3 d7 cb 92 ad 04 52 91 
    5a 4d e9 c0 17 22 f6 82 3e eb 6a df 7e 0c a8 29 
    0f 5d e3 e5 49 89 0a c2 a3 c5 95 0a b2 17 ba 58 
    59 08 94 95 2d e9 6f 8d f1 11 b2 57 52 15 da 6c 
    16 15 90 c7 45 be 61 24 76 ee 57 8e d3 84 ab 33 
    e3 ec e9 74 81 a2 52 f5 c7 9a 98 b5 53 2a e0 0c 
    dd 62 f2 ec c0 cd 1b ae fe 80 d8 0b 96 21 93 ec 
    1d`.replace(/[^0-9A-F]/gi, ''), 'hex')
        },
        {
    
    // # --------------------------------
    // # RSASSA-PSS Signature Example 5.2
    // # --------------------------------
    
    // # Message to be signed:
            msg: Buffer.from(`
    e7 b3 2e 15 56 ea 1b 27 95 04 6a c6 97 39 d2 2a 
    c8 96 6b f1 1c 11 6f 61 4b 16 67 40 e9 6b 90 65 
    3e 57 50 94 5f cf 77 21 86 c0 37 90 a0 7f da 32 
    3e 1a 61 91 6b 06 ee 21 57 db 3d ff 80 d6 7d 5e 
    39 a5 3a e2 68 c8 f0 9e d9 9a 73 20 05 b0 bc 6a 
    04 af 4e 08 d5 7a 00 e7 20 1b 30 60 ef aa db 73 
    11 3b fc 08 7f d8 37 09 3a a2 52 35 b8 c1 49 f5 
    62 15 f0 31 c2 4a d5 bd e7 f2 99 60 df 7d 52 40 
    70 f7 44 9c 6f 78 50 84 be 1a 0f 73 30 47 f3 36 
    f9 15 47 38 67 45 47 db 02 a9 f4 4d fc 6e 60 30 
    10 81 e1 ce 99 84 7f 3b 5b 60 1f f0 6b 4d 57 76 
    a9 74 0b 9a a0 d3 40 58 fd 3b 90 6e 4f 78 59 df 
    b0 7d 71 73 e5 e6 f6 35 0a da c2 1f 27 b2 30 74 
    69`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Salt:
            salt: Buffer.from(`
    bd 0c e1 95 49 d0 70 01 20 cb e5 10 77 db bb b0 
    0a 8d 8b 09`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Signature:
            sig: Buffer.from(`
    08 18 0d e8 25 e4 b8 b0 14 a3 2d a8 ba 76 15 55 
    92 12 04 f2 f9 0d 5f 24 b7 12 90 8f f8 4f 3e 22 
    0a d1 79 97 c0 dd 6e 70 66 30 ba 3e 84 ad d4 d5 
    e7 ab 00 4e 58 07 4b 54 97 09 56 5d 43 ad 9e 97 
    b5 a7 a1 a2 9e 85 b9 f9 0f 4a af cd f5 83 21 de 
    8c 59 74 ef 9a bf 2d 52 6f 33 c0 f2 f8 2e 95 d1 
    58 ea 6b 81 f1 73 6d b8 d1 af 3d 6a c6 a8 3b 32 
    d1 8b ae 0f f1 b2 fe 27 de 4c 76 ed 8c 79 80 a3 
    4e`.replace(/[^0-9A-F]/gi, ''), 'hex')
        },
        {
    
    // # --------------------------------
    // # RSASSA-PSS Signature Example 5.3
    // # --------------------------------
    
    // # Message to be signed:
            msg: Buffer.from(`
    8d 83 96 e3 65 07 fe 1e f6 a1 90 17 54 8e 0c 71 
    66 74 c2 fe c2 33 ad b2 f7 75 66 5e c4 1f 2b d0 
    ba 39 6b 06 1a 9d aa 7e 86 6f 7c 23 fd 35 31 95 
    43 00 a3 42 f9 24 53 5e a1 49 8c 48 f6 c8 79 93 
    28 65 fc 02 00 0c 52 87 23 b7 ad 03 35 74 5b 51 
    20 9a 0a fe d9 32 af 8f 08 87 c2 19 00 4d 2a bd 
    89 4e a9 25 59 ee 31 98 af 3a 73 4f e9 b9 63 8c 
    26 3a 72 8a d9 5a 5a e8 ce 3e b1 58 39 f3 aa 78 
    52 bb 39 07 06 e7 76 0e 43 a7 12 91 a2 e3 f8 27 
    23 7d ed a8 51 87 4c 51 76 65 f5 45 f2 72 38 df 
    86 55 7f 37 5d 09 cc d8 bd 15 d8 cc f6 1f 5d 78 
    ca 5c 7f 5c de 78 2e 6b f5 d0 05 70 56 d4 ba d9 
    8b 3d 2f 95 75 e8 24 ab 7a 33 ff 57 b0 ac 10 0a 
    b0 d6 ea d7 aa 0b 50 f6 e4 d3 e5 ec 0b 96 6b`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Salt:
            salt: Buffer.from(`
    81 57 79 a9 1b 3a 8b d0 49 bf 2a eb 92 01 42 77 
    22 22 c9 ca`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Signature:
            sig: Buffer.from(`
    05 e0 fd bd f6 f7 56 ef 73 31 85 cc fa 8c ed 2e 
    b6 d0 29 d9 d5 6e 35 56 1b 5d b8 e7 02 57 ee 6f 
    d0 19 d2 f0 bb f6 69 fe 9b 98 21 e7 8d f6 d4 1e 
    31 60 8d 58 28 0f 31 8e e3 4f 55 99 41 c8 df 13 
    28 75 74 ba c0 00 b7 e5 8d c4 f4 14 ba 49 fb 12 
    7f 9d 0f 89 36 63 8c 76 e8 53 56 c9 94 f7 97 50 
    f7 fa 3c f4 fd 48 2d f7 5e 3f b9 97 8c d0 61 f7 
    ab b1 75 72 e6 e6 3e 0b de 12 cb dc f1 8c 68 b9 
    79`.replace(/[^0-9A-F]/gi, ''), 'hex')
        },
        {
    
    // # --------------------------------
    // # RSASSA-PSS Signature Example 5.4
    // # --------------------------------
    
    // # Message to be signed:
            msg: Buffer.from(`
    32 8c 65 9e 0a 64 37 43 3c ce b7 3c 14`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Salt:
            salt: Buffer.from(`
    9a ec 4a 74 80 d5 bb c4 29 20 d7 ca 23 5d b6 74 
    98 9c 9a ac`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Signature:
            sig: Buffer.from(`
    0b c9 89 85 3b c2 ea 86 87 32 71 ce 18 3a 92 3a 
    b6 5e 8a 53 10 0e 6d f5 d8 7a 24 c4 19 4e b7 97 
    81 3e e2 a1 87 c0 97 dd 87 2d 59 1d a6 0c 56 86 
    05 dd 7e 74 2d 5a f4 e3 3b 11 67 8c cb 63 90 32 
    04 a3 d0 80 b0 90 2c 89 ab a8 86 8f 00 9c 0f 1c 
    0c b8 58 10 bb dd 29 12 1a bb 84 71 ff 2d 39 e4 
    9f d9 2d 56 c6 55 c8 e0 37 ad 18 fa fb dc 92 c9 
    58 63 f7 f6 1e a9 ef a2 8f ea 40 13 69 d1 9d ae 
    a1`.replace(/[^0-9A-F]/gi, ''), 'hex')
        }, 
        {
    
    // # --------------------------------
    // # RSASSA-PSS Signature Example 5.5
    // # --------------------------------
    
    // # Message to be signed:
            msg: Buffer.from(`
    f3 7b 96 23 79 a4 7d 41 5a 37 6e ec 89 73 15 0b 
    cb 34 ed d5 ab 65 40 41 b6 14 30 56 0c 21 44 58 
    2b a1 33 c8 67 d8 52 d6 b8 e2 33 21 90 13 02 ec 
    b4 5b 09 ec 88 b1 52 71 78 fa 04 32 63 f3 06 7d 
    9f fe 97 30 32 a9 9f 4c b0 8a d2 c7 e0 a2 45 6c 
    dd 57 a7 df 56 fe 60 53 52 7a 5a eb 67 d7 e5 52 
    06 3c 1c a9 7b 1b ef fa 7b 39 e9 97 ca f2 78 78 
    ea 0f 62 cb eb c8 c2 1d f4 c8 89 a2 02 85 1e 94 
    90 88 49 0c 24 9b 6e 9a cf 1d 80 63 f5 be 23 43 
    98 9b f9 5c 4d a0 1a 2b e7 8b 4a b6 b3 78 01 5b 
    c3 79 57 f7 69 48 b5 e5 8e 44 0c 28 45 3d 40 d7 
    cf d5 7e 7d 69 06 00 47 4a b5 e7 59 73 b1 ea 0c 
    5f 1e 45 d1 41 90 af e2 f4 eb 6d 3b df 71 f1 d2 
    f8 bb 15 6a 1c 29 5d 04 aa eb 9d 68 9d ce 79 ed 
    62 bc 44 3e`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Salt:
            salt: Buffer.from(`
    e2 0c 1e 98 78 51 2c 39 97 0f 58 37 5e 15 49 a6 
    8b 64 f3 1d`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Signature:
            sig: Buffer.from(`
    0a ef a9 43 b6 98 b9 60 9e df 89 8a d2 27 44 ac 
    28 dc 23 94 97 ce a3 69 cb bd 84 f6 5c 95 c0 ad 
    77 6b 59 47 40 16 4b 59 a7 39 c6 ff 7c 2f 07 c7 
    c0 77 a8 6d 95 23 8f e5 1e 1f cf 33 57 4a 4a e0 
    68 4b 42 a3 f6 bf 67 7d 91 82 0c a8 98 74 46 7b 
    2c 23 ad d7 79 69 c8 07 17 43 0d 0e fc 1d 36 95 
    89 2c e8 55 cb 7f 70 11 63 0f 4d f2 6d ef 8d df 
    36 fc 23 90 5f 57 fa 62 43 a4 85 c7 70 d5 68 1f 
    cd`.replace(/[^0-9A-F]/gi, ''), 'hex')
        },
        {
    
    // # --------------------------------
    // # RSASSA-PSS Signature Example 5.6
    // # --------------------------------
    
    // # Message to be signed:
            msg: Buffer.from(`
    c6 10 3c 33 0c 1e f7 18 c1 41 e4 7b 8f a8 59 be 
    4d 5b 96 25 9e 7d 14 20 70 ec d4 85 83 9d ba 5a 
    83 69 c1 7c 11 14 03 5e 53 2d 19 5c 74 f4 4a 04 
    76 a2 d3 e8 a4 da 21 00 16 ca ce d0 e3 67 cb 86 
    77 10 a4 b5 aa 2d f2 b8 e5 da f5 fd c6 47 80 7d 
    4d 5e bb 6c 56 b9 76 3c cd ae 4d ea 33 08 eb 0a 
    c2 a8 95 01 cb 20 9d 26 39 fa 5b f8 7c e7 90 74 
    7d 3c b2 d2 95 e8 45 64 f2 f6 37 82 4f 0c 13 02 
    81 29 b0 aa 4a 42 2d 16 22 82`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Salt:
            salt: Buffer.from(`
    23 29 1e 4a 33 07 e8 bb b7 76 62 3a b3 4e 4a 5f 
    4c c8 a8 db`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Signature:
            sig: Buffer.from(`
    02 80 2d cc fa 8d fa f5 27 9b f0 b4 a2 9b a1 b1 
    57 61 1f ae aa f4 19 b8 91 9d 15 94 19 00 c1 33 
    9e 7e 92 e6 fa e5 62 c5 3e 6c c8 e8 41 04 b1 10 
    bc e0 3a d1 85 25 e3 c4 9a 0e ad ad 5d 3f 28 f2 
    44 a8 ed 89 ed ba fb b6 86 27 7c fa 8a e9 09 71 
    4d 6b 28 f4 bf 8e 29 3a a0 4c 41 ef e7 c0 a8 12 
    66 d5 c0 61 e2 57 5b e0 32 aa 46 46 74 ff 71 62 
    62 19 bd 74 cc 45 f0 e7 ed 4e 3f f9 6e ee 75 8e 
    8f`.replace(/[^0-9A-F]/gi, ''), 'hex')
        }
    ];

    var rsa = new jCastle.pki.rsa();
    rsa.setPrivateKey({
        n, e, d, p, q, dmp1, dmq1, iqmp
    });

    for (var i = 0; i < testVectors.length; i++) {
        var vector = testVectors[i];

        var v_sig = rsa.pssSign(vector.msg, {
            salt: vector.salt,
            hashAlgo: 'sha-1',
            saltLength: vector.salt.length
        });

        assert.ok(v_sig.equals(vector.sig), bits + '-bit pss sign test ' + (i + 1));
        // console.log(bits + '-bit pss sign test ' + (i + 1) + ': ', v_sig.equals(vector.sig));

        var v = rsa.pssVerify(vector.msg, vector.sig, {
            salt: vector.salt,
            hashAlgo: 'sha-1',
            saltLength: vector.salt.length
        });

        assert.ok(v, bits + '-bit pss verify test ' + (i + 1));
        // console.log(bits + '-bit pss verify test ' + (i + 1) + ': ', v);
    }


    // # =============================================
    
    // # ==================================
    // # Example 6: A 1029-bit RSA Key Pair
    // # ==================================
    var bits = 1029;
    // # ------------------------------
    // # Components of the RSA Key Pair
    // # ------------------------------
    
    // # RSA modulus n: 
    var n = Buffer.from(`
    16 4c a3 1c ff 60 9f 3a 0e 71 01 b0 39 f2 e4 fe 
    6d d3 75 19 ab 98 59 8d 17 9e 17 49 96 59 80 71 
    f4 7d 3a 04 55 91 58 d7 be 37 3c f1 aa 53 f0 aa 
    6e f0 90 39 e5 67 8c 2a 4c 63 90 05 14 c8 c4 f8 
    aa ed 5d e1 2a 5f 10 b0 9c 31 1a f8 c0 ff b5 b7 
    a2 97 f2 ef c6 3b 8d 6b 05 10 93 1f 0b 98 e4 8b 
    f5 fc 6e c4 e7 b8 db 1f fa eb 08 c3 8e 02 ad b8 
    f0 3a 48 22 9c 99 e9 69 43 1f 61 cb 8c 4d c6 98 
    d1`.replace(/[^0-9A-F]/gi, ''), 'hex');
    
    // # RSA public exponent e: 
    var e = parseInt(`
    01 00 01`.replace(/[^0-9A-F]/gi, ''), 16);
    
    // # RSA private exponent d: 
    var d = Buffer.from(`
    03 b6 64 ee 3b 75 66 72 3f c6 ea f2 8a bb 43 0a 
    39 80 f1 12 6c 81 de 8a d7 09 ea b3 9a c9 dc d0 
    b1 55 0b 37 29 d8 70 68 e9 52 00 9d f5 44 53 4c 
    1f 50 82 9a 78 f4 59 1e b8 fd 57 14 04 26 a6 bb 
    04 05 b6 a6 f5 1a 57 d9 26 7b 7b bc 65 33 91 a6 
    99 a2 a9 0d ac 8a e2 26 bc c6 0f a8 cd 93 4c 73 
    c7 b0 3b 1f 6b 81 81 58 63 18 38 a8 61 2e 6e 6e 
    a9 2b e2 4f 83 24 fa f5 b1 fd 85 87 22 52 67 ba 
    6f`.replace(/[^0-9A-F]/gi, ''), 'hex');
    
    // # Prime p:
    var p = Buffer.from(` 
    04 f0 54 8c 96 26 ab 1e bf 12 44 93 47 41 d9 9a 
    06 22 0e fa 2a 58 56 aa 0e 75 73 0b 2e c9 6a dc 
    86 be 89 4f a2 80 3b 53 a5 e8 5d 27 6a cb d2 9a 
    b8 23 f8 0a 73 91 bb 54 a5 05 16 72 fb 04 ee b5 
    43`.replace(/[^0-9A-F]/gi, ''), 'hex');
    
    // # Prime q: 
    var q = Buffer.from(`
    04 83 e0 ae 47 91 55 87 74 3f f3 45 36 2b 55 5d 
    39 62 d9 8b b6 f1 5f 84 8b 4c 92 b1 77 1c a8 ed 
    10 7d 8d 3e e6 5e c4 45 17 dd 0f aa 48 1a 38 7e 
    90 2f 7a 2e 74 7c 26 9e 7e a4 44 80 bc 53 8b 8e 
    5b`.replace(/[^0-9A-F]/gi, ''), 'hex');
    
    // # p's CRT exponent dP: 
    var dmp1 = Buffer.from(`
    03 a8 e8 ae a9 92 0c 1a a3 b2 f0 d8 46 e4 b8 50 
    d8 1c a3 06 a5 1c 83 54 4f 94 9f 64 f9 0d cf 3f 
    8e 26 61 f0 7e 56 12 20 a1 80 38 8f be 27 3e 70 
    e2 e5 dc a8 3a 0e 13 48 dd 64 90 c7 31 d6 ec e1 
    ab`.replace(/[^0-9A-F]/gi, ''), 'hex');
    
    // # q's CRT exponent dQ: 
    var dmq1 = Buffer.from(`
    01 35 bd cd b6 0b f2 19 7c 43 6e d3 4b 32 cd 8b 
    4f c7 77 78 83 2b a7 67 03 55 1f b2 42 b3 01 69 
    95 93 af 77 fd 8f c3 94 a8 52 6a d2 3c c4 1a 03 
    80 6b d8 97 fe 4b 0e a6 46 55 8a ad dc c9 9e 8a 
    25`.replace(/[^0-9A-F]/gi, ''), 'hex');
    
    // # CRT coefficient qInv: 
    var iqmp = Buffer.from(`
    03 04 c0 3d 9c 73 65 03 a9 84 ab bd 9b a2 23 01 
    40 7c 4a 2a b1 dd 85 76 64 81 b6 0d 45 40 11 52 
    e6 92 be 14 f4 12 1d 9a a3 fd 6e 0b 4d 1d 3a 97 
    35 38 a3 1d 42 ee 6e 1e 5e f6 20 23 1a 2b ba f3 
    5f`.replace(/[^0-9A-F]/gi, ''), 'hex');

    var testVectors = [
        {
    
    // # --------------------------------
    // # RSASSA-PSS Signature Example 6.1
    // # --------------------------------
    
    // # Message to be signed:
            msg: Buffer.from(`
    0a 20 b7 74 ad dc 2f a5 12 45 ed 7c b9 da 60 9e 
    50 ca c6 63 6a 52 54 3f 97 45 8e ed 73 40 f8 d5 
    3f fc 64 91 8f 94 90 78 ee 03 ef 60 d4 2b 5f ec 
    24 60 50 bd 55 05 cd 8c b5 97 ba d3 c4 e7 13 b0 
    ef 30 64 4e 76 ad ab b0 de 01 a1 56 1e fb 25 51 
    58 c7 4f c8 01 e6 e9 19 e5 81 b4 6f 0f 0d dd 08 
    e4 f3 4c 78 10 b5 ed 83 18 f9 1d 7c 8c`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Salt:
            salt: Buffer.from(`
    5b 4e a2 ef 62 9c c2 2f 3b 53 8e 01 69 04 b4 7b 
    1e 40 bf d5`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Signature:
            sig: Buffer.from(`
    04 c0 cf ac ec 04 e5 ba db ec e1 59 a5 a1 10 3f 
    69 b3 f3 2b a5 93 cb 4c c4 b1 b7 ab 45 59 16 a9 
    6a 27 cd 26 78 ea 0f 46 ba 37 f7 fc 9c 86 32 5f 
    29 73 3b 38 9f 1d 97 f4 3e 72 01 c0 f3 48 fc 45 
    fe 42 89 23 35 36 2e ee 01 8b 5b 16 1f 2f 93 93 
    03 12 25 c7 13 01 2a 57 6b c8 8e 23 05 24 89 86 
    8d 90 10 cb f0 33 ec c5 68 e8 bc 15 2b dc 59 d5 
    60 e4 12 91 91 5d 28 56 52 08 e2 2a ee c9 ef 85 
    d1`.replace(/[^0-9A-F]/gi, ''), 'hex')
        },
        {
    
    // # --------------------------------
    // # RSASSA-PSS Signature Example 6.2
    // # --------------------------------
    
    // # Message to be signed:
            msg: Buffer.from(`
    2a af f6 63 1f 62 1c e6 15 76 0a 9e bc e9 4b b3 
    33 07 7a d8 64 88 c8 61 d4 b7 6d 29 c1 f4 87 46 
    c6 11 ae 1e 03 ce d4 44 5d 7c fa 1f e5 f6 2e 1b 
    3f 08 45 2b de 3b 6e f8 19 73 ba fb b5 7f 97 bc 
    ee f8 73 98 53 95 b8 26 05 89 aa 88 cb 7d b5 0a 
    b4 69 26 2e 55 1b dc d9 a5 6f 27 5a 0a c4 fe 48 
    47 00 c3 5f 3d bf 2b 46 9e de 86 47 41 b8 6f a5 
    91 72 a3 60 ba 95 a0 2e 13 9b e5 0d df b7 cf 0b 
    42 fa ea bb fb ba a8 6a 44 97 69 9c 4f 2d fd 5b 
    08 40 6a f7 e1 41 44 42 7c 25 3e c0 ef a2 0e af 
    9a 8b e8 cd 49 ce 1f 1b c4 e9 3e 61 9c f2 aa 8e 
    d4 fb 39 bc 85 90 d0 f7 b9 64 88 f7 31 7a c9 ab 
    f7 be e4 e3 a0 e7 15`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Salt:
            salt: Buffer.from(`
    83 14 6a 9e 78 27 22 c2 8b 01 4f 98 b4 26 7b da 
    2a c9 50 4f`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Signature:
            sig: Buffer.from(`
    0a 23 14 25 0c f5 2b 6e 4e 90 8d e5 b3 56 46 bc 
    aa 24 36 1d a8 16 0f b0 f9 25 75 90 ab 3a ce 42 
    b0 dc 3e 77 ad 2d b7 c2 03 a2 0b d9 52 fb b5 6b 
    15 67 04 6e cf aa 93 3d 7b 10 00 c3 de 9f f0 5b 
    7d 98 9b a4 6f d4 3b c4 c2 d0 a3 98 6b 7f fa 13 
    47 1d 37 eb 5b 47 d6 47 07 bd 29 0c fd 6a 9f 39 
    3a d0 8e c1 e3 bd 71 bb 57 92 61 50 35 cd af 2d 
    89 29 ae d3 be 09 83 79 37 7e 77 7c e7 9a aa 47 
    73`.replace(/[^0-9A-F]/gi, ''), 'hex')
        },
        {
    
    // # --------------------------------
    // # RSASSA-PSS Signature Example 6.3
    // # --------------------------------
    
    // # Message to be signed:
            msg: Buffer.from(`
    0f 61 95 d0 4a 6e 6f c7 e2 c9 60 0d bf 84 0c 39 
    ea 8d 4d 62 4f d5 35 07 01 6b 0e 26 85 8a 5e 0a 
    ec d7 ad a5 43 ae 5c 0a b3 a6 25 99 cb a0 a5 4e 
    6b f4 46 e2 62 f9 89 97 8f 9d df 5e 9a 41`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Salt:
            salt: Buffer.from(`
    a8 7b 8a ed 07 d7 b8 e2 da f1 4d dc a4 ac 68 c4 
    d0 aa bf f8`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Signature:
            sig: Buffer.from(`
    08 6d f6 b5 00 09 8c 12 0f 24 ff 84 23 f7 27 d9 
    c6 1a 5c 90 07 d3 b6 a3 1c e7 cf 8f 3c be c1 a2 
    6b b2 0e 2b d4 a0 46 79 32 99 e0 3e 37 a2 1b 40 
    19 4f b0 45 f9 0b 18 bf 20 a4 79 92 cc d7 99 cf 
    9c 05 9c 29 9c 05 26 85 49 54 aa de 8a 6a d9 d9 
    7e c9 1a 11 45 38 3f 42 46 8b 23 1f 4d 72 f2 37 
    06 d9 85 3c 3f a4 3c e8 ac e8 bf e7 48 49 87 a1 
    ec 6a 16 c8 da f8 1f 7c 8b f4 27 74 70 7a 9d f4 
    56`.replace(/[^0-9A-F]/gi, ''), 'hex')
        },
        {
    
    // # --------------------------------
    // # RSASSA-PSS Signature Example 6.4
    // # --------------------------------
    
    // # Message to be signed:
            msg: Buffer.from(`
    33 7d 25 fe 98 10 eb ca 0d e4 d4 65 8d 3c eb 8e 
    0f e4 c0 66 ab a3 bc c4 8b 10 5d 3b f7 e0 25 7d 
    44 fe ce a6 59 6f 4d 0c 59 a0 84 02 83 36 78 f7 
    06 20 f9 13 8d fe b7 de d9 05 e4 a6 d5 f0 5c 47 
    3d 55 93 66 52 e2 a5 df 43 c0 cf da 7b ac af 30 
    87 f4 52 4b 06 cf 42 15 7d 01 53 97 39 f7 fd de 
    c9 d5 81 25 df 31 a3 2e ab 06 c1 9b 71 f1 d5 bf`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Salt:
            salt: Buffer.from(`
    a3 79 32 f8 a7 49 4a 94 2d 6f 76 74 38 e7 24 d6 
    d0 c0 ef 18`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Signature:
            sig: Buffer.from(`
    0b 5b 11 ad 54 98 63 ff a9 c5 1a 14 a1 10 6c 2a 
    72 cc 8b 64 6e 5c 72 62 50 97 86 10 5a 98 47 76 
    53 4c a9 b5 4c 1c c6 4b f2 d5 a4 4f d7 e8 a6 9d 
    b6 99 d5 ea 52 08 7a 47 48 fd 2a bc 1a fe d1 e5 
    d6 f7 c8 90 25 53 0b da a2 21 3d 7e 03 0f a5 5d 
    f6 f3 4b cf 1c e4 6d 2e df 4e 3a e4 f3 b0 18 91 
    a0 68 c9 e3 a4 4b bc 43 13 3e da d6 ec b9 f3 54 
    00 c4 25 2a 57 62 d6 57 44 b9 9c b9 f4 c5 59 32 
    9f`.replace(/[^0-9A-F]/gi, ''), 'hex')
        },
        {
    
    // # --------------------------------
    // # RSASSA-PSS Signature Example 6.5
    // # --------------------------------
    
    // # Message to be signed:
            msg: Buffer.from(`
    84 ec 50 2b 07 2e 82 87 78 9d 8f 92 35 82 9e a3 
    b1 87 af d4 d4 c7 85 61 1b da 5f 9e b3 cb 96 71 
    7e fa 70 07 22 7f 1c 08 cb cb 97 2e 66 72 35 e0 
    fb 7d 43 1a 65 70 32 6d 2e cc e3 5a db 37 3d c7 
    53 b3 be 5f 82 9b 89 17 54 93 19 3f ab 16 ba db 
    41 37 1b 3a ac 0a e6 70 07 6f 24 be f4 20 c1 35 
    ad d7 ce e8 d3 5f bc 94 4d 79 fa fb 9e 30 7a 13 
    b0 f5 56 cb 65 4a 06 f9 73 ed 22 67 23 30 19 7e 
    f5 a7 48 bf 82 6a 5d b2 38 3a 25 36 4b 68 6b 93 
    72 bb 23 39 ae b1 ac 9e 98 89 32 7d 01 6f 16 70 
    77 6d b0 62 01 ad bd ca f8 a5 e3 b7 4e 10 8b 73`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Salt:
            salt: Buffer.from(`
    7b 79 0c 1d 62 f7 b8 4e 94 df 6a f2 89 17 cf 57 
    10 18 11 0e`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Signature:
            sig: Buffer.from(`
    02 d7 1f a9 b5 3e 46 54 fe fb 7f 08 38 5c f6 b0 
    ae 3a 81 79 42 eb f6 6c 35 ac 67 f0 b0 69 95 2a 
    3c e9 c7 e1 f1 b0 2e 48 0a 95 00 83 6d e5 d6 4c 
    db 7e cd e0 45 42 f7 a7 99 88 78 7e 24 c2 ba 05 
    f5 fd 48 2c 02 3e d5 c3 0e 04 83 9d c4 4b ed 2a 
    3a 3a 4f ee 01 11 3c 89 1a 47 d3 2e b8 02 5c 28 
    cb 05 0b 5c db 57 6c 70 fe 76 ef 52 34 05 c0 84 
    17 fa f3 50 b0 37 a4 3c 37 93 39 fc b1 8d 3a 35 
    6b`.replace(/[^0-9A-F]/gi, ''), 'hex')
        },
        {
    
    // # --------------------------------
    // # RSASSA-PSS Signature Example 6.6
    // # --------------------------------
    
    // # Message to be signed:
            msg: Buffer.from(`
    99 06 d8 9f 97 a9 fd ed d3 cc d8 24 db 68 73 26 
    f3 0f 00 aa 25 a7 fc a2 af cb 3b 0f 86 cd 41 e7 
    3f 0e 8f f7 d2 d8 3f 59 e2 8e d3 1a 5a 0d 55 15 
    23 37 4d e2 2e 4c 7e 8f f5 68 b3 86 ee 3d c4 11 
    63 f1 0b f6 7b b0 06 26 1c 90 82 f9 af 90 bf 1d 
    90 49 a6 b9 fa e7 1c 7f 84 fb e6 e5 5f 02 78 9d 
    e7 74 f2 30 f1 15 02 6a 4b 4e 96 c5 5b 04 a9 5d 
    a3 aa cb b2 ce ce 8f 81 76 4a 1f 1c 99 51 54 11 
    08 7c f7 d3 4a ed ed 09 32 c1 83`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Salt:
            salt: Buffer.from(`
    fb be 05 90 25 b6 9b 89 fb 14 ae 22 89 e7 aa af 
    e6 0c 0f cd`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Signature:
            sig: Buffer.from(`
    0a 40 a1 6e 2f e2 b3 8d 1d f9 05 46 16 7c f9 46 
    9c 9e 3c 36 81 a3 44 2b 4b 2c 2f 58 1d eb 38 5c 
    e9 9f c6 18 8b b0 2a 84 1d 56 e7 6d 30 18 91 e2 
    45 60 55 0f cc 2a 26 b5 5f 4c cb 26 d8 37 d3 50 
    a1 54 bc ac a8 39 2d 98 fa 67 95 9e 97 27 b7 8c 
    ad 03 26 9f 56 96 8f c5 6b 68 bd 67 99 26 d8 3c 
    c9 cb 21 55 50 64 5c cd a3 1c 76 0f f3 58 88 94 
    3d 2d 8a 1d 35 1e 81 e5 d0 7b 86 18 2e 75 10 81 
    ef`.replace(/[^0-9A-F]/gi, ''), 'hex')
        }
    ];

    var rsa = new jCastle.pki.rsa();
    rsa.setPrivateKey({
        n, e, d, p, q, dmp1, dmq1, iqmp
    });

    for (var i = 0; i < testVectors.length; i++) {
        var vector = testVectors[i];

        var v_sig = rsa.pssSign(vector.msg, {
            salt: vector.salt,
            hashAlgo: 'sha-1',
            saltLength: vector.salt.length
        });

        assert.ok(v_sig.equals(vector.sig), bits + '-bit pss sign test ' + (i + 1));
        // console.log(bits + '-bit pss sign test ' + (i + 1) + ': ', v_sig.equals(vector.sig));

        var v = rsa.pssVerify(vector.msg, vector.sig, {
            salt: vector.salt,
            hashAlgo: 'sha-1',
            saltLength: vector.salt.length
        });

        assert.ok(v, bits + '-bit pss verify test ' + (i + 1));
        // console.log(bits + '-bit pss verify test ' + (i + 1) + ': ', v);
    }


    // this test will fail because of failure of key validation.
    // keypair validation result: false
    // reason: d !== e^-1 mod phi
/*    
    // # =============================================
    
    // # ==================================
    // # Example 7: A 1030-bit RSA Key Pair
    // # ==================================
    var bits = 1030;
    // # ------------------------------
    // # Components of the RSA Key Pair
    // # ------------------------------
    
    // # RSA modulus n: 
    var n = Buffer.from(`
    37 c9 da 4a 66 c8 c4 08 b8 da 27 d0 c9 d7 9f 8c 
    cb 1e af c1 d2 fe 48 74 6d 94 0b 7c 4e f5 de e1 
    8a d1 26 47 ce fa a0 c4 b3 18 8b 22 1c 51 53 86 
    75 9b 93 f0 20 24 b2 5a b9 24 2f 83 57 d8 f3 fd 
    49 64 0e e5 e6 43 ea f6 c6 4d ee fa 70 89 72 7c 
    8f f0 39 93 33 39 15 c6 ef 21 bf 59 75 b6 e5 0d 
    11 8b 51 00 8e c3 3e 9f 01 a0 a5 45 a1 0a 83 6a 
    43 dd bc a9 d8 b5 c5 d3 54 80 22 d7 06 4e a2 9a 
    b3`.replace(/[^0-9A-F]/gi, ''), 'hex');
    
    // # RSA public exponent e: 
    var e = Buffer.from(`
    01 00 01`.replace(/[^0-9A-F]/gi, ''), 16);
    
    // # RSA private exponent d: 
    var d = Buffer.from(`
    3b ed 99 90 52 d9 57 bc 06 d6 51 ee f6 e3 a9 80 
    94 b1 62 1b d3 8b 54 49 bd 6c 4a ea 3d e7 e0 84 
    67 9a 44 84 de d2 5b e0 f0 82 6c f3 37 78 25 41 
    4b 14 d4 d6 1d b1 4d e6 26 fb b8 0e 5f 4f ae c9 
    56 f9 a0 a2 d2 4f 99 57 63 80 f0 84 eb 62 e4 6a 
    57 d5 54 27 8b 53 56 26 19 3c e0 20 60 57 5e b6 
    6c 57 98 d3 6f 6c 5d 40 fb 00 d8 09 b4 2a 73 10 
    2c 1c 74 ee 95 bd 71 42 0f ff ef 63 18 b5 2c 29`.replace(/[^0-9A-F]/gi, ''), 'hex');
    
    // # Prime p: 
    var p = Buffer.from(`
    07 ee fb 42 4b 0e 3a 40 e4 20 8e e5 af b2 80 b2 
    23 17 30 81 14 dd e0 b4 b6 4f 73 01 84 ec 68 da 
    6c e2 86 7a 9f 48 ed 77 26 d5 e2 61 4e d0 4a 54 
    10 73 6c 8c 71 4e e7 02 47 42 98 c6 29 2a f0 75 
    35 `.replace(/[^0-9A-F]/gi, ''), 'hex');
    
    // # Prime q: 
    var q = Buffer.from(`
    07 08 30 db f9 47 ea c0 22 8d e2 63 14 b5 9b 66 
    99 4c c6 0e 83 60 e7 5d 38 76 29 8f 8f 8a 7d 14 
    1d a0 64 e5 ca 02 6a 97 3e 28 f2 54 73 8c ee 66 
    9c 72 1b 03 4c b5 f8 e2 44 da dd 7c d1 e1 59 d5 
    47`.replace(/[^0-9A-F]/gi, ''), 'hex');
    
    // # p's CRT exponent dP: 
    var dmp1 = Buffer.from(`
    05 24 d2 0c 3d 95 cf f7 5a f2 31 34 83 22 7d 87 
    02 71 7a a5 76 de 15 5f 96 05 15 50 1a db 1d 70 
    e1 c0 4d e9 1b 75 b1 61 db f0 39 83 56 12 7e de 
    da 7b bc 19 a3 2d c1 62 1c c9 f5 3c 26 5d 0c e3 
    31`.replace(/[^0-9A-F]/gi, ''), 'hex');
    
    // # q's CRT exponent dQ: 
    var dmq1 = Buffer.from(`
    05 f9 84 a1 f2 3c 93 8d 6a 0e 89 72 4b cf 3d d9 
    3f 99 46 92 60 37 fe 7c 6b 13 a2 9e 52 84 85 5f 
    89 08 95 91 d4 40 97 56 27 bf 5c 9e 3a 8b 5c a7 
    9c 77 2a d2 73 e4 0d 32 1a f4 a6 c9 7d fd ed 78 
    d3`.replace(/[^0-9A-F]/gi, ''), 'hex');
    
    // # CRT coefficient qInv: 
    var iqmp = Buffer.from(`
    dd d9 18 ad ad a2 9d ca b9 81 ff 9a cb a4 25 70 
    23 c0 9a 38 01 cc ce 09 8c e2 68 f8 55 d0 df 57 
    0c d6 e7 b9 b1 4b d9 a5 a9 25 4c bc 31 5b e6 f8 
    ba 1e 25 46 dd d5 69 c5 ea 19 ee d8 35 3b de 5e`.replace(/[^0-9A-F]/gi, ''), 'hex');

    var testVectors = [
        {
    
    // # --------------------------------
    // # RSASSA-PSS Signature Example 7.1
    // # --------------------------------
    
    // # Message to be signed:
            msg: Buffer.from(`
    9e ad 0e 01 94 56 40 67 4e b4 1c ad 43 5e 23 74 
    ea ef a8 ad 71 97 d9 79 13 c4 49 57 d8 d8 3f 40 
    d7 6e e6 0e 39 bf 9c 0f 9e af 30 21 42 1a 07 4d 
    1a de 96 2c 6e 9d 3d c3 bb 17 4f e4 df e6 52 b0 
    91 15 49 5b 8f d2 79 41 74 02 0a 06 02 b5 ca 51 
    84 8c fc 96 ce 5e b5 7f c0 a2 ad c1 dd a3 6a 7c 
    c4 52 64 1a 14 91 1b 37 e4 5b fa 11 da a5 c7 ec 
    db 74 f6 d0 10 0d 1d 3e 39 e7 52 80 0e 20 33 97 
    de 02 33 07 7b 9a 88 85 55 37 fa e9 27 f9 24 38 
    0d 78 0f 98 e1 8d cf f3 9c 5e a7 41 b1 7d 6f dd 
    18 85 bc 9d 58 14 82 d7 71 ce b5 62 d7 8a 8b f8 
    8f 0c 75 b1 13 63 e5 e3 6c d4 79 ce b0 54 5f 9d 
    a8 42 03 e0 e6 e5 08 37 5c c9 e8 44 b8 8b 7a c7 
    a0 a2 01 ea 0f 1b ee 9a 2c 57 79 20 ca 02 c0 1b 
    9d 83 20 e9 74 a5 6f 4e fb 57 63 b9 62 55 ab bf 
    80 37 bf 18 02 cf 01 8f 56 37 94 93 e5 69 a9`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Salt:
            salt: Buffer.from(`
    b7 86 7a 59 95 8c b5 43 28 f8 77 5e 65 46 ec 06 
    d2 7e aa 50`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Signature:
            sig: Buffer.from(`
    18 7f 39 07 23 c8 90 25 91 f0 15 4b ae 6d 4e cb 
    ff e0 67 f0 e8 b7 95 47 6e a4 f4 d5 1c cc 81 05 
    20 bb 3c a9 bc a7 d0 b1 f2 ea 8a 17 d8 73 fa 27 
    57 0a cd 64 2e 38 08 56 1c b9 e9 75 cc fd 80 b2 
    3d c5 77 1c db 33 06 a5 f2 31 59 da cb d3 aa 2d 
    b9 3d 46 d7 66 e0 9e d1 5d 90 0a d8 97 a8 d2 74 
    dc 26 b4 7e 99 4a 27 e9 7e 22 68 a7 66 53 3a e4 
    b5 e4 2a 2f ca f7 55 c1 c4 79 4b 29 4c 60 55 58 
    23`.replace(/[^0-9A-F]/gi, ''), 'hex')
        },
        {
    
    // # --------------------------------
    // # RSASSA-PSS Signature Example 7.2
    // # --------------------------------
    
    // # Message to be signed:
            msg: Buffer.from(`
    8d 80 d2 d0 8d bd 19 c1 54 df 3f 14 67 3a 14 bd 
    03 73 52 31 f2 4e 86 bf 15 3d 0e 69 e7 4c bf f7 
    b1 83 6e 66 4d e8 3f 68 01 24 37 0f c0 f9 6c 9b 
    65 c0 7a 36 6b 64 4c 4a b3`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Salt:
            salt: Buffer.from(`
    0c 09 58 22 66 df 08 63 10 82 1b a7 e1 8d f6 4d 
    fe e6 de 09`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Signature:
            sig: Buffer.from(`
    10 fd 89 76 8a 60 a6 77 88 ab b5 85 6a 78 7c 85 
    61 f3 ed cf 9a 83 e8 98 f7 dc 87 ab 8c ce 79 42 
    9b 43 e5 69 06 94 1a 88 61 94 f1 37 e5 91 fe 7c 
    33 95 55 36 1f bb e1 f2 4f eb 2d 4b cd b8 06 01 
    f3 09 6b c9 13 2d ee a6 0a e1 30 82 f4 4f 9a d4 
    1c d6 28 93 6a 4d 51 17 6e 42 fc 59 cb 76 db 81 
    5c e5 ab 4d b9 9a 10 4a af ea 68 f5 d3 30 32 9e 
    bf 25 8d 4e de 16 06 4b d1 d0 03 93 d5 e1 57 0e 
    b8`.replace(/[^0-9A-F]/gi, ''), 'hex')
        },
        {
    
    // # --------------------------------
    // # RSASSA-PSS Signature Example 7.3
    // # --------------------------------
    
    // # Message to be signed:
            msg: Buffer.from(`
    80 84 05 cd fc 1a 58 b9 bb 03 97 c7 20 72 2a 81 
    ff fb 76 27 8f 33 59 17 ef 9c 47 38 14 b3 e0 16 
    ba 29 73 cd 27 65 f8 f3 f8 2d 6c c3 8a a7 f8 55 
    18 27 fe 8d 1e 38 84 b7 e6 1c 94 68 3b 8f 82 f1 
    84 3b da e2 25 7e ee c9 81 2a d4 c2 cf 28 3c 34 
    e0 b0 ae 0f e3 cb 99 0c f8 8f 2e f9`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Salt:
            salt: Buffer.from(`
    28 03 9d cf e1 06 d3 b8 29 66 11 25 8c 4a 56 65 
    1c 9e 92 dd`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Signature:
            sig: Buffer.from(`
    2b 31 fd e9 98 59 b9 77 aa 09 58 6d 8e 27 46 62 
    b2 5a 2a 64 06 40 b4 57 f5 94 05 1c b1 e7 f7 a9 
    11 86 54 55 24 29 26 cf 88 fe 80 df a3 a7 5b a9 
    68 98 44 a1 1e 63 4a 82 b0 75 af bd 69 c1 2a 0d 
    f9 d2 5f 84 ad 49 45 df 3d c8 fe 90 c3 ce fd f2 
    6e 95 f0 53 43 04 b5 bd ba 20 d3 e5 64 0a 2e bf 
    b8 98 aa c3 5a e4 0f 26 fc e5 56 3c 2f 9f 24 f3 
    04 2a f7 6f 3c 70 72 d6 87 bb fb 95 9a 88 46 0a 
    f1`.replace(/[^0-9A-F]/gi, ''), 'hex')
        },
        {
    
    // # --------------------------------
    // # RSASSA-PSS Signature Example 7.4
    // # --------------------------------
    
    // # Message to be signed:
            msg: Buffer.from(`
    f3 37 b9 ba d9 37 de 22 a1 a0 52 df f1 11 34 a8 
    ce 26 97 62 02 98 19 39 b9 1e 07 15 ae 5e 60 96 
    49 da 1a df ce f3 f4 cc a5 9b 23 83 60 e7 d1 e4 
    96 c7 bf 4b 20 4b 5a cf f9 bb d6 16 6a 1d 87 a3 
    6e f2 24 73 73 75 10 39 f8 a8 00 b8 39 98 07 b3 
    a8 5f 44 89 34 97 c0 d0 5f b7 01 7b 82 22 81 52 
    de 6f 25 e6 11 6d cc 75 03 c7 86 c8 75 c2 8f 3a 
    a6 07 e9 4a b0 f1 98 63 ab 1b 50 73 77 0b 0c d5 
    f5 33 ac de 30 c6 fb 95 3c f3 da 68 02 64 e3 0f 
    c1 1b ff 9a 19 bf fa b4 77 9b 62 23 c3 fb 3f e0 
    f7 1a ba de 4e b7 c0 9c 41 e2 4c 22 d2 3f a1 48 
    e6 a1 73 fe b6 39 84 d1 bc 6e e3 a0 2d 91 5b 75 
    2c ea f9 2a 30 15 ec eb 38 ca 58 6c 68 01 b3 7c 
    34 ce fb 2c ff 25 ea 23 c0 86 62 dc ab 26 a7 a9 
    3a 28 5d 05 d3 04 4c`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Salt:
            salt: Buffer.from(`
    a7 78 21 eb bb ef 24 62 8e 4e 12 e1 d0 ea 96 de 
    39 8f 7b 0f`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Signature:
            sig: Buffer.from(`
    32 c7 ca 38 ff 26 94 9a 15 00 0c 4b a0 4b 2b 13 
    b3 5a 38 10 e5 68 18 4d 7e ca ba a1 66 b7 ff ab 
    dd f2 b6 cf 4b a0 71 24 92 37 90 f2 e5 b1 a5 be 
    04 0a ea 36 fe 13 2e c1 30 e1 f1 05 67 98 2d 17 
    ac 3e 89 b8 d2 6c 30 94 03 4e 76 2d 2e 03 12 64 
    f0 11 70 be ec b3 d1 43 9e 05 84 6f 25 45 83 67 
    a7 d9 c0 20 60 44 46 72 67 1e 64 e8 77 86 45 59 
    ca 19 b2 07 4d 58 8a 28 1b 58 04 d2 37 72 fb be 
    19`.replace(/[^0-9A-F]/gi, ''), 'hex')
        },
        {
    
    // # --------------------------------
    // # RSASSA-PSS Signature Example 7.5
    // # --------------------------------
    
    // # Message to be signed:
            msg: Buffer.from(`
    45 01 3c eb af d9 60 b2 55 47 6a 8e 25 98 b9 aa 
    32 ef be 6d c1 f3 4f 4a 49 8d 8c f5 a2 b4 54 8d 
    08 c5 5d 5f 95 f7 bc c9 61 91 63 05 6f 2d 58 b5 
    2f a0 32`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Salt:
            salt: Buffer.from(`
    9d 5a d8 eb 45 21 34 b6 5d c3 a9 8b 6a 73 b5 f7 
    41 60 9c d6`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Signature:
            sig: Buffer.from(`
    07 eb 65 1d 75 f1 b5 2b c2 63 b2 e1 98 33 6e 99 
    fb eb c4 f3 32 04 9a 92 2a 10 81 56 07 ee 2d 98 
    9d b3 a4 49 5b 7d cc d3 8f 58 a2 11 fb 7e 19 31 
    71 a3 d8 91 13 24 37 eb ca 44 f3 18 b2 80 50 9e 
    52 b5 fa 98 fc ce 82 05 d9 69 7c 8e e4 b7 ff 59 
    d4 c5 9c 79 03 8a 19 70 bd 2a 0d 45 1e cd c5 ef 
    11 d9 97 9c 9d 35 f8 c7 0a 61 63 71 76 07 89 0d 
    58 6a 7c 6d c0 1c 79 f8 6a 8f 28 e8 52 35 f8 c2 
    f1`.replace(/[^0-9A-F]/gi, ''), 'hex')
        },
        {
    
    // # --------------------------------
    // # RSASSA-PSS Signature Example 7.6
    // # --------------------------------
    
    // # Message to be signed:
            msg: Buffer.from(`
    23 58 09 70 86 c8 99 32 3e 75 d9 c9 0d 0c 09 f1 
    2d 9d 54 ed fb df 70 a9 c2 eb 5a 04 d8 f3 6b 9b 
    2b df 2a ab e0 a5 bd a1 96 89 37 f9 d6 eb d3 b6 
    b2 57 ef b3 13 6d 41 31 f9 ac b5 9b 85 e2 60 2c 
    2a 3f cd c8 35 49 4a 1f 4e 5e c1 8b 22 6c 80 23 
    2b 36 a7 5a 45 fd f0 9a 7e a9 e9 8e fb de 14 50 
    d1 19 4b f1 2e 15 a4 c5 f9 eb 5c 0b ce 52 69 e0 
    c3 b2 8c fa b6 55 d8 1a 61 a2 0b 4b e2 f5 44 59 
    bb 25 a0 db 94 c5 22 18 be 10 9a 74 26 de 83 01 
    44 24 78 9a aa 90 e5 05 6e 63 2a 69 81 15 e2 82 
    c1 a5 64 10 f2 6c 20 72 f1 93 48 1a 9d cd 88 05 
    72 00 5e 64 f4 08 2e cf`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Salt:
            salt: Buffer.from(`
    3f 2e fc 59 58 80 a7 d4 7f cf 3c ba 04 98 3e a5 
    4c 4b 73 fb`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Signature:
            sig: Buffer.from(`
    18 da 3c dc fe 79 bf b7 7f d9 c3 2f 37 7a d3 99 
    14 6f 0a 8e 81 06 20 23 32 71 a6 e3 ed 32 48 90 
    3f 5c dc 92 dc 79 b5 5d 3e 11 61 5a a0 56 a7 95 
    85 37 92 a3 99 8c 34 9c a5 c4 57 e8 ca 7d 29 d7 
    96 aa 24 f8 34 91 70 9b ef cf b1 51 0e a5 13 c9 
    28 29 a3 f0 0b 10 4f 65 56 34 f3 20 75 2e 13 0e 
    c0 cc f6 75 4f f8 93 db 30 29 32 bb 02 5e b6 0e 
    87 82 25 98 fc 61 9e 0e 98 17 37 a9 a4 c4 15 2d 
    33`.replace(/[^0-9A-F]/gi, ''), 'hex')
        }
    ];
    
    var rsa = new jCastle.pki.rsa();
    rsa.setPrivateKey({
        n, e, d, p, q, dmp1, dmq1, iqmp
    });

    // key validation fails: d !== e^-1 mod phi
    // console.log('key validate: ', rsa.validateKeypair(null, null, true));

    // the following test will all fail in verifying signatures.
    // the failures come from the wrong keypair.

    for (var i = 0; i < testVectors.length; i++) {
        var vector = testVectors[i];

        var v_sig = rsa.pssSign(vector.msg, {
            salt: vector.salt,
            hashAlgo: 'sha-1',
            saltLength: vector.salt.length
        });

        assert.ok(v_sig.equals(vector.sig), bits + '-bit pss sign test ' + (i + 1));
        // console.log(bits + '-bit pss sign test ' + (i + 1) + ': ', v_sig.equals(vector.sig));

        var v = rsa.pssVerify(vector.msg, vector.sig, {
            salt: vector.salt,
            hashAlgo: 'sha-1',
            saltLength: vector.salt.length
        });

        assert.ok(v, bits + '-bit pss verify test ' + (i + 1));
        // console.log(bits + '-bit pss verify test ' + (i + 1) + ': ', v);
    }
*/

    // # =============================================
    
    // # ==================================
    // # Example 8: A 1031-bit RSA Key Pair
    // # ==================================
    var bits = 1031
    // # ------------------------------
    // # Components of the RSA Key Pair
    // # ------------------------------
    
    // # RSA modulus n: 
    var n = Buffer.from(`
    49 53 70 a1 fb 18 54 3c 16 d3 63 1e 31 63 25 5d 
    f6 2b e6 ee e8 90 d5 f2 55 09 e4 f7 78 a8 ea 6f 
    bb bc df 85 df f6 4e 0d 97 20 03 ab 36 81 fb ba 
    6d d4 1f d5 41 82 9b 2e 58 2d e9 f2 a4 a4 e0 a2 
    d0 90 0b ef 47 53 db 3c ee 0e e0 6c 7d fa e8 b1 
    d5 3b 59 53 21 8f 9c ce ea 69 5b 08 66 8e de aa 
    dc ed 94 63 b1 d7 90 d5 eb f2 7e 91 15 b4 6c ad 
    4d 9a 2b 8e fa b0 56 1b 08 10 34 47 39 ad a0 73 
    3f`.replace(/[^0-9A-F]/gi, ''), 'hex');
    
    // # RSA public exponent e: 
    var e = parseInt(`
    01 00 01 `.replace(/[^0-9A-F]/gi, ''), 16);
    
    // # RSA private exponent d: 
    var d = Buffer.from(`
    6c 66 ff e9 89 80 c3 8f cd ea b5 15 98 98 83 61 
    65 f4 b4 b8 17 c4 f6 a8 d4 86 ee 4e a9 13 0f e9 
    b9 09 2b d1 36 d1 84 f9 5f 50 4a 60 7e ac 56 58 
    46 d2 fd d6 59 7a 89 67 c7 39 6e f9 5a 6e ee bb 
    45 78 a6 43 96 6d ca 4d 8e e3 de 84 2d e6 32 79 
    c6 18 15 9c 1a b5 4a 89 43 7b 6a 61 20 e4 93 0a 
    fb 52 a4 ba 6c ed 8a 49 47 ac 64 b3 0a 34 97 cb 
    e7 01 c2 d6 26 6d 51 72 19 ad 0e c6 d3 47 db e9`.replace(/[^0-9A-F]/gi, ''), 'hex');
    
    // # Prime p: 
    var p = Buffer.from(`
    08 da d7 f1 13 63 fa a6 23 d5 d6 d5 e8 a3 19 32 
    8d 82 19 0d 71 27 d2 84 6c 43 9b 0a b7 26 19 b0 
    a4 3a 95 32 0e 4e c3 4f c3 a9 ce a8 76 42 23 05 
    bd 76 c5 ba 7b e9 e2 f4 10 c8 06 06 45 a1 d2 9e 
    db`.replace(/[^0-9A-F]/gi, ''), 'hex');
    
    // # Prime q: 
    var q = Buffer.from(`
    08 47 e7 32 37 6f c7 90 0f 89 8e a8 2e b2 b0 fc 
    41 85 65 fd ae 62 f7 d9 ec 4c e2 21 7b 97 99 0d 
    d2 72 db 15 7f 99 f6 3c 0d cb b9 fb ac db d4 c4 
    da db 6d f6 77 56 35 8c a4 17 48 25 b4 8f 49 70 
    6d`.replace(/[^0-9A-F]/gi, ''), 'hex');
    
    // # p's CRT exponent dP: 
    var dmp1 = Buffer.from(`
    05 c2 a8 3c 12 4b 36 21 a2 aa 57 ea 2c 3e fe 03 
    5e ff 45 60 f3 3d de bb 7a da b8 1f ce 69 a0 c8 
    c2 ed c1 65 20 dd a8 3d 59 a2 3b e8 67 96 3a c6 
    5f 2c c7 10 bb cf b9 6e e1 03 de b7 71 d1 05 fd 
    85`.replace(/[^0-9A-F]/gi, ''), 'hex');
    
    // # q's CRT exponent dQ: 
    var dmq1 = Buffer.from(`
    04 ca e8 aa 0d 9f aa 16 5c 87 b6 82 ec 14 0b 8e 
    d3 b5 0b 24 59 4b 7a 3b 2c 22 0b 36 69 bb 81 9f 
    98 4f 55 31 0a 1a e7 82 36 51 d4 a0 2e 99 44 79 
    72 59 51 39 36 34 34 e5 e3 0a 7e 7d 24 15 51 e1 
    b9`.replace(/[^0-9A-F]/gi, ''), 'hex');
    
    // # CRT coefficient qInv: 
    var iqmp = Buffer.from(`
    07 d3 e4 7b f6 86 60 0b 11 ac 28 3c e8 8d bb 3f 
    60 51 e8 ef d0 46 80 e4 4c 17 1e f5 31 b8 0b 2b 
    7c 39 fc 76 63 20 e2 cf 15 d8 d9 98 20 e9 6f f3 
    0d c6 96 91 83 9c 4b 40 d7 b0 6e 45 30 7d c9 1f 
    3f`.replace(/[^0-9A-F]/gi, ''), 'hex');

    var testVectors = [
        {
    
    // # --------------------------------
    // # RSASSA-PSS Signature Example 8.1
    // # --------------------------------
    
    // # Message to be signed:
            msg: Buffer.from(`
    81 33 2f 4b e6 29 48 41 5e a1 d8 99 79 2e ea cf 
    6c 6e 1d b1 da 8b e1 3b 5c ea 41 db 2f ed 46 70 
    92 e1 ff 39 89 14 c7 14 25 97 75 f5 95 f8 54 7f 
    73 56 92 a5 75 e6 92 3a f7 8f 22 c6 99 7d db 90 
    fb 6f 72 d7 bb 0d d5 74 4a 31 de cd 3d c3 68 58 
    49 83 6e d3 4a ec 59 63 04 ad 11 84 3c 4f 88 48 
    9f 20 97 35 f5 fb 7f da f7 ce c8 ad dc 58 18 16 
    8f 88 0a cb f4 90 d5 10 05 b7 a8 e8 4e 43 e5 42 
    87 97 75 71 dd 99 ee a4 b1 61 eb 2d f1 f5 10 8f 
    12 a4 14 2a 83 32 2e db 05 a7 54 87 a3 43 5c 9a 
    78 ce 53 ed 93 bc 55 08 57 d7 a9 fb`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Salt:
            salt: Buffer.from(`
    1d 65 49 1d 79 c8 64 b3 73 00 9b e6 f6 f2 46 7b 
    ac 4c 78 fa`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Signature:
            sig: Buffer.from(`
    02 62 ac 25 4b fa 77 f3 c1 ac a2 2c 51 79 f8 f0 
    40 42 2b 3c 5b af d4 0a 8f 21 cf 0f a5 a6 67 cc 
    d5 99 3d 42 db af b4 09 c5 20 e2 5f ce 2b 1e e1 
    e7 16 57 7f 1e fa 17 f3 da 28 05 2f 40 f0 41 9b 
    23 10 6d 78 45 aa f0 11 25 b6 98 e7 a4 df e9 2d 
    39 67 bb 00 c4 d0 d3 5b a3 55 2a b9 a8 b3 ee f0 
    7c 7f ec db c5 42 4a c4 db 1e 20 cb 37 d0 b2 74 
    47 69 94 0e a9 07 e1 7f bb ca 67 3b 20 52 23 80 
    c5`.replace(/[^0-9A-F]/gi, ''), 'hex')
        },
        {
    
    // # --------------------------------
    // # RSASSA-PSS Signature Example 8.2
    // # --------------------------------
    
    // # Message to be signed:
            msg: Buffer.from(`
    e2 f9 6e af 0e 05 e7 ba 32 6e cc a0 ba 7f d2 f7 
    c0 23 56 f3 ce de 9d 0f aa bf 4f cc 8e 60 a9 73 
    e5 59 5f d9 ea 08`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Salt:
            salt: Buffer.from(`
    43 5c 09 8a a9 90 9e b2 37 7f 12 48 b0 91 b6 89 
    87 ff 18 38`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Signature:
            sig: Buffer.from(`
    27 07 b9 ad 51 15 c5 8c 94 e9 32 e8 ec 0a 28 0f 
    56 33 9e 44 a1 b5 8d 4d dc ff 2f 31 2e 5f 34 dc 
    fe 39 e8 9c 6a 94 dc ee 86 db bd ae 5b 79 ba 4e 
    08 19 a9 e7 bf d9 d9 82 e7 ee 6c 86 ee 68 39 6e 
    8b 3a 14 c9 c8 f3 4b 17 8e b7 41 f9 d3 f1 21 10 
    9b f5 c8 17 2f ad a2 e7 68 f9 ea 14 33 03 2c 00 
    4a 8a a0 7e b9 90 00 0a 48 dc 94 c8 ba c8 aa be 
    2b 09 b1 aa 46 c0 a2 aa 0e 12 f6 3f bb a7 75 ba 
    7e`.replace(/[^0-9A-F]/gi, ''), 'hex')
        },
        {
    
    // # --------------------------------
    // # RSASSA-PSS Signature Example 8.3
    // # --------------------------------
    
    // # Message to be signed:
            msg: Buffer.from(`
    e3 5c 6e d9 8f 64 a6 d5 a6 48 fc ab 8a db 16 33 
    1d b3 2e 5d 15 c7 4a 40 ed f9 4c 3d c4 a4 de 79 
    2d 19 08 89 f2 0f 1e 24 ed 12 05 4a 6b 28 79 8f 
    cb 42 d1 c5 48 76 9b 73 4c 96 37 31 42 09 2a ed 
    27 76 03 f4 73 8d f4 dc 14 46 58 6d 0e c6 4d a4 
    fb 60 53 6d b2 ae 17 fc 7e 3c 04 bb fb bb d9 07 
    bf 11 7c 08 63 6f a1 6f 95 f5 1a 62 16 93 4d 3e 
    34 f8 50 30 f1 7b bb c5 ba 69 14 40 58 af f0 81 
    e0 b1 9c f0 3c 17 19 5c 5e 88 8b a5 8f 6f e0 a0 
    2e 5c 3b da 97 19 a7`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Salt:
            salt: Buffer.from(`
    c6 eb be 76 df 0c 4a ea 32 c4 74 17 5b 2f 13 68 
    62 d0 45 29`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Signature:
            sig: Buffer.from(`
    2a d2 05 09 d7 8c f2 6d 1b 6c 40 61 46 08 6e 4b 
    0c 91 a9 1c 2b d1 64 c8 7b 96 6b 8f aa 42 aa 0c 
    a4 46 02 23 23 ba 4b 1a 1b 89 70 6d 7f 4c 3b e5 
    7d 7b 69 70 2d 16 8a b5 95 5e e2 90 35 6b 8c 4a 
    29 ed 46 7d 54 7e c2 3c ba df 28 6c cb 58 63 c6 
    67 9d a4 67 fc 93 24 a1 51 c7 ec 55 aa c6 db 40 
    84 f8 27 26 82 5c fe 1a a4 21 bc 64 04 9f b4 2f 
    23 14 8f 9c 25 b2 dc 30 04 37 c3 8d 42 8a a7 5f 
    96`.replace(/[^0-9A-F]/gi, ''), 'hex')
        },
        {
    
    // # --------------------------------
    // # RSASSA-PSS Signature Example 8.4
    // # --------------------------------
    
    // # Message to be signed:
            msg: Buffer.from(`
    db c5 f7 50 a7 a1 4b e2 b9 3e 83 8d 18 d1 4a 86 
    95 e5 2e 8a dd 9c 0a c7 33 b8 f5 6d 27 47 e5 29 
    a0 cc a5 32 dd 49 b9 02 ae fe d5 14 44 7f 9e 81 
    d1 61 95 c2 85 38 68 cb 9b 30 f7 d0 d4 95 c6 9d 
    01 b5 c5 d5 0b 27 04 5d b3 86 6c 23 24 a4 4a 11 
    0b 17 17 74 6d e4 57 d1 c8 c4 5c 3c d2 a9 29 70 
    c3 d5 96 32 05 5d 4c 98 a4 1d 6e 99 e2 a3 dd d5 
    f7 f9 97 9a b3 cd 18 f3 75 05 d2 51 41 de 2a 1b 
    ff 17 b3 a7 dc e9 41 9e cc 38 5c f1 1d 72 84 0f 
    19 95 3f d0 50 92 51 f6 ca fd e2 89 3d 0e 75 c7 
    81 ba 7a 50 12 ca 40 1a 4f a9 9e 04 b3 c3 24 9f 
    92 6d 5a fe 82 cc 87 da b2 2c 3c 1b 10 5d e4 8e 
    34 ac e9 c9 12 4e 59 59 7a c7 eb f8`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Salt:
            salt: Buffer.from(`
    02 1f dc c6 eb b5 e1 9b 1c b1 6e 9c 67 f2 76 81 
    65 7f e2 0a`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Signature:
            sig: Buffer.from(`
    1e 24 e6 e5 86 28 e5 17 50 44 a9 eb 6d 83 7d 48 
    af 12 60 b0 52 0e 87 32 7d e7 89 7e e4 d5 b9 f0 
    df 0b e3 e0 9e d4 de a8 c1 45 4f f3 42 3b b0 8e 
    17 93 24 5a 9d f8 bf 6a b3 96 8c 8e dd c3 b5 32 
    85 71 c7 7f 09 1c c5 78 57 69 12 df eb d1 64 b9 
    de 54 54 fe 0b e1 c1 f6 38 5b 32 83 60 ce 67 ec 
    7a 05 f6 e3 0e b4 5c 17 c4 8a c7 00 41 d2 ca b6 
    7f 0a 2a e7 aa fd cc 8d 24 5e a3 44 2a 63 00 cc 
    c7`.replace(/[^0-9A-F]/gi, ''), 'hex')
        },
        {
    
    // # --------------------------------
    // # RSASSA-PSS Signature Example 8.5
    // # --------------------------------
    
    // # Message to be signed:
            msg: Buffer.from(`
    04 dc 25 1b e7 2e 88 e5 72 34 85 b6 38 3a 63 7e 
    2f ef e0 76 60 c5 19 a5 60 b8 bc 18 bd ed b8 6e 
    ae 23 64 ea 53 ba 9d ca 6e b3 d2 e7 d6 b8 06 af 
    42 b3 e8 7f 29 1b 4a 88 81 d5 bf 57 2c c9 a8 5e 
    19 c8 6a cb 28 f0 98 f9 da 03 83 c5 66 d3 c0 f5 
    8c fd 8f 39 5d cf 60 2e 5c d4 0e 8c 71 83 f7 14 
    99 6e 22 97 ef`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Salt:
            salt: Buffer.from(`
    c5 58 d7 16 7c bb 45 08 ad a0 42 97 1e 71 b1 37 
    7e ea 42 69`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Signature:
            sig: Buffer.from(`
    33 34 1b a3 57 6a 13 0a 50 e2 a5 cf 86 79 22 43 
    88 d5 69 3f 5a cc c2 35 ac 95 ad d6 8e 5e b1 ee 
    c3 16 66 d0 ca 7a 1c da 6f 70 a1 aa 76 2c 05 75 
    2a 51 95 0c db 8a f3 c5 37 9f 18 cf e6 b5 bc 55 
    a4 64 82 26 a1 5e 91 2e f1 9a d7 7a de ea 91 1d 
    67 cf ef d6 9b a4 3f a4 11 91 35 ff 64 21 17 ba 
    98 5a 7e 01 00 32 5e 95 19 f1 ca 6a 92 16 bd a0 
    55 b5 78 50 15 29 11 25 e9 0d cd 07 a2 ca 96 73 
    ee`.replace(/[^0-9A-F]/gi, ''), 'hex')
        },
        {
    
    // # --------------------------------
    // # RSASSA-PSS Signature Example 8.6
    // # --------------------------------
    
    // # Message to be signed:
            msg: Buffer.from(`
    0e a3 7d f9 a6 fe a4 a8 b6 10 37 3c 24 cf 39 0c 
    20 fa 6e 21 35 c4 00 c8 a3 4f 5c 18 3a 7e 8e a4 
    c9 ae 09 0e d3 17 59 f4 2d c7 77 19 cc a4 00 ec 
    dc c5 17 ac fc 7a c6 90 26 75 b2 ef 30 c5 09 66 
    5f 33 21 48 2f c6 9a 9f b5 70 d1 5e 01 c8 45 d0 
    d8 e5 0d 2a 24 cb f1 cf 0e 71 49 75 a5 db 7b 18 
    d9 e9 e9 cb 91 b5 cb 16 86 90 60 ed 18 b7 b5 62 
    45 50 3f 0c af 90 35 2b 8d e8 1c b5 a1 d9 c6 33 
    60 92 f0 cd`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Salt:
            salt: Buffer.from(`
    76 fd 4e 64 fd c9 8e b9 27 a0 40 3e 35 a0 84 e7 
    6b a9 f9 2a`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Signature:
            sig: Buffer.from(`
    1e d1 d8 48 fb 1e db 44 12 9b d9 b3 54 79 5a f9 
    7a 06 9a 7a 00 d0 15 10 48 59 3e 0c 72 c3 51 7f 
    f9 ff 2a 41 d0 cb 5a 0a c8 60 d7 36 a1 99 70 4f 
    7c b6 a5 39 86 a8 8b bd 8a bc c0 07 6a 2c e8 47 
    88 00 31 52 5d 44 9d a2 ac 78 35 63 74 c5 36 e3 
    43 fa a7 cb a4 2a 5a aa 65 06 08 77 91 c0 6a 8e 
    98 93 35 ae d1 9b fa b2 d5 e6 7e 27 fb 0c 28 75 
    af 89 6c 21 b6 e8 e7 30 9d 04 e4 f6 72 7e 69 46 
    3e`.replace(/[^0-9A-F]/gi, ''), 'hex')
        }
    ];

    var rsa = new jCastle.pki.rsa();
    rsa.setPrivateKey({
        n, e, d, p, q, dmp1, dmq1, iqmp
    });

    for (var i = 0; i < testVectors.length; i++) {
        var vector = testVectors[i];

        var v_sig = rsa.pssSign(vector.msg, {
            salt: vector.salt,
            hashAlgo: 'sha-1',
            saltLength: vector.salt.length
        });

        assert.ok(v_sig.equals(vector.sig), bits + '-bit pss sign test ' + (i + 1));
        // console.log(bits + '-bit pss sign test ' + (i + 1) + ': ', v_sig.equals(vector.sig));

        var v = rsa.pssVerify(vector.msg, vector.sig, {
            salt: vector.salt,
            hashAlgo: 'sha-1',
            saltLength: vector.salt.length
        });

        assert.ok(v, bits + '-bit pss verify test ' + (i + 1));
        // console.log(bits + '-bit pss verify test ' + (i + 1) + ': ', v);
    }


    // # =============================================
    
    // # ==================================
    // # Example 9: A 1536-bit RSA Key Pair
    // # ==================================
    var bits = 1536;
    // # ------------------------------
    // # Components of the RSA Key Pair
    // # ------------------------------
    
    // # RSA modulus n: 
    var n = Buffer.from(`
    e6 bd 69 2a c9 66 45 79 04 03 fd d0 f5 be b8 b9 
    bf 92 ed 10 00 7f c3 65 04 64 19 dd 06 c0 5c 5b 
    5b 2f 48 ec f9 89 e4 ce 26 91 09 97 9c bb 40 b4 
    a0 ad 24 d2 24 83 d1 ee 31 5a d4 cc b1 53 42 68 
    35 26 91 c5 24 f6 dd 8e 6c 29 d2 24 cf 24 69 73 
    ae c8 6c 5b f6 b1 40 1a 85 0d 1b 9a d1 bb 8c bc 
    ec 47 b0 6f 0f 8c 7f 45 d3 fc 8f 31 92 99 c5 43 
    3d db c2 b3 05 3b 47 de d2 ec d4 a4 ca ef d6 14 
    83 3d c8 bb 62 2f 31 7e d0 76 b8 05 7f e8 de 3f 
    84 48 0a d5 e8 3e 4a 61 90 4a 4f 24 8f b3 97 02 
    73 57 e1 d3 0e 46 31 39 81 5c 6f d4 fd 5a c5 b8 
    17 2a 45 23 0e cb 63 18 a0 4f 14 55 d8 4e 5a 8b`.replace(/[^0-9A-F]/gi, ''), 'hex');
    
    // # RSA public exponent e: 
    var e = parseInt(`
    01 00 01`.replace(/[^0-9A-F]/gi, ''), 16);
    
    // # RSA private exponent d: 
    var d = Buffer.from(`
    6a 7f d8 4f b8 5f ad 07 3b 34 40 6d b7 4f 8d 61 
    a6 ab c1 21 96 a9 61 dd 79 56 5e 9d a6 e5 18 7b 
    ce 2d 98 02 50 f7 35 95 75 35 92 70 d9 15 90 bb 
    0e 42 7c 71 46 0b 55 d5 14 10 b1 91 bc f3 09 fe 
    a1 31 a9 2c 8e 70 27 38 fa 71 9f 1e 00 41 f5 2e 
    40 e9 1f 22 9f 4d 96 a1 e6 f1 72 e1 55 96 b4 51 
    0a 6d ae c2 61 05 f2 be bc 53 31 6b 87 bd f2 13 
    11 66 60 70 e8 df ee 69 d5 2c 71 a9 76 ca ae 79 
    c7 2b 68 d2 85 80 dc 68 6d 9f 51 29 d2 25 f8 2b 
    3d 61 55 13 a8 82 b3 db 91 41 6b 48 ce 08 88 82 
    13 e3 7e eb 9a f8 00 d8 1c ab 32 8c e4 20 68 99 
    03 c0 0c 7b 5f d3 1b 75 50 3a 6d 41 96 84 d6 29`.replace(/[^0-9A-F]/gi, ''), 'hex');
    
    // # Prime p: 
    var p = Buffer.from(`
    f8 eb 97 e9 8d f1 26 64 ee fd b7 61 59 6a 69 dd 
    cd 0e 76 da ec e6 ed 4b f5 a1 b5 0a c0 86 f7 92 
    8a 4d 2f 87 26 a7 7e 51 5b 74 da 41 98 8f 22 0b 
    1c c8 7a a1 fc 81 0c e9 9a 82 f2 d1 ce 82 1e dc 
    ed 79 4c 69 41 f4 2c 7a 1a 0b 8c 4d 28 c7 5e c6 
    0b 65 22 79 f6 15 4a 76 2a ed 16 5d 47 de e3 67`.replace(/[^0-9A-F]/gi, ''), 'hex')
    
    // # Prime q:
    var q = Buffer.from(`
    ed 4d 71 d0 a6 e2 4b 93 c2 e5 f6 b4 bb e0 5f 5f 
    b0 af a0 42 d2 04 fe 33 78 d3 65 c2 f2 88 b6 a8 
    da d7 ef e4 5d 15 3e ef 40 ca cc 7b 81 ff 93 40 
    02 d1 08 99 4b 94 a5 e4 72 8c d9 c9 63 37 5a e4 
    99 65 bd a5 5c bf 0e fe d8 d6 55 3b 40 27 f2 d8 
    62 08 a6 e6 b4 89 c1 76 12 80 92 d6 29 e4 9d 3d`.replace(/[^0-9A-F]/gi, ''), 'hex');
    
    // # p's CRT exponent dP: 
    var dmp1 = Buffer.from(`
    2b b6 8b dd fb 0c 4f 56 c8 55 8b ff af 89 2d 80 
    43 03 78 41 e7 fa 81 cf a6 1a 38 c5 e3 9b 90 1c 
    8e e7 11 22 a5 da 22 27 bd 6c de eb 48 14 52 c1 
    2a d3 d6 1d 5e 4f 77 6a 0a b5 56 59 1b ef e3 e5 
    9e 5a 7f dd b8 34 5e 1f 2f 35 b9 f4 ce e5 7c 32 
    41 4c 08 6a ec 99 3e 93 53 e4 80 d9 ee c6 28 9f`.replace(/[^0-9A-F]/gi, ''), 'hex');
    
    // # q's CRT exponent dQ: 
    var dmq1 = Buffer.from(`
    4f f8 97 70 9f ad 07 97 46 49 45 78 e7 0f d8 54 
    61 30 ee ab 56 27 c4 9b 08 0f 05 ee 4a d9 f3 e4 
    b7 cb a9 d6 a5 df f1 13 a4 1c 34 09 33 68 33 f1 
    90 81 6d 8a 6b c4 2e 9b ec 56 b7 56 7d 0f 3c 9c 
    69 6d b6 19 b2 45 d9 01 dd 85 6d b7 c8 09 2e 77 
    e9 a1 cc cd 56 ee 4d ba 42 c5 fd b6 1a ec 26 69`.replace(/[^0-9A-F]/gi, ''), 'hex');
    
    // # CRT coefficient qInv: 
    var iqmp = Buffer.from(`
    77 b9 d1 13 7b 50 40 4a 98 27 29 31 6e fa fc 7d 
    fe 66 d3 4e 5a 18 26 00 d5 f3 0a 0a 85 12 05 1c 
    56 0d 08 1d 4d 0a 18 35 ec 3d 25 a6 0f 4e 4d 6a 
    a9 48 b2 bf 3d bb 5b 12 4c bb c3 48 92 55 a3 a9 
    48 37 2f 69 78 49 67 45 f9 43 e1 db 4f 18 38 2c 
    ea a5 05 df c6 57 57 bb 3f 85 7a 58 dc e5 21 56`.replace(/[^0-9A-F]/gi, ''), 'hex');

    var testVectors = [
        {
    
    // # --------------------------------
    // # RSASSA-PSS Signature Example 9.1
    // # --------------------------------
    
    // # Message to be signed:
            msg: Buffer.from(`
    a8 8e 26 58 55 e9 d7 ca 36 c6 87 95 f0 b3 1b 59 
    1c d6 58 7c 71 d0 60 a0 b3 f7 f3 ea ef 43 79 59 
    22 02 8b c2 b6 ad 46 7c fc 2d 7f 65 9c 53 85 aa 
    70 ba 36 72 cd de 4c fe 49 70 cc 79 04 60 1b 27 
    88 72 bf 51 32 1c 4a 97 2f 3c 95 57 0f 34 45 d4 
    f5 79 80 e0 f2 0d f5 48 46 e6 a5 2c 66 8f 12 88 
    c0 3f 95 00 6e a3 2f 56 2d 40 d5 2a f9 fe b3 2f 
    0f a0 6d b6 5b 58 8a 23 7b 34 e5 92 d5 5c f9 79 
    f9 03 a6 42 ef 64 d2 ed 54 2a a8 c7 7d c1 dd 76 
    2f 45 a5 93 03 ed 75 e5 41 ca 27 1e 2b 60 ca 70 
    9e 44 fa 06 61 13 1e 8d 5d 41 63 fd 8d 39 85 66 
    ce 26 de 87 30 e7 2f 9c ca 73 76 41 c2 44 15 94 
    20 63 70 28 df 0a 18 07 9d 62 08 ea 8b 47 11 a2 
    c7 50 f5`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Salt:
            salt: Buffer.from(`
    c0 a4 25 31 3d f8 d7 56 4b d2 43 4d 31 15 23 d5 
    25 7e ed 80`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Signature:
            sig: Buffer.from(`
    58 61 07 22 6c 3c e0 13 a7 c8 f0 4d 1a 6a 29 59 
    bb 4b 8e 20 5b a4 3a 27 b5 0f 12 41 11 bc 35 ef 
    58 9b 03 9f 59 32 18 7c b6 96 d7 d9 a3 2c 0c 38 
    30 0a 5c dd a4 83 4b 62 d2 eb 24 0a f3 3f 79 d1 
    3d fb f0 95 bf 59 9e 0d 96 86 94 8c 19 64 74 7b 
    67 e8 9c 9a ba 5c d8 50 16 23 6f 56 6c c5 80 2c 
    b1 3e ad 51 bc 7c a6 be f3 b9 4d cb db b1 d5 70 
    46 97 71 df 0e 00 b1 a8 a0 67 77 47 2d 23 16 27 
    9e da e8 64 74 66 8d 4e 1e ff f9 5f 1d e6 1c 60 
    20 da 32 ae 92 bb f1 65 20 fe f3 cf 4d 88 f6 11 
    21 f2 4b bd 9f e9 1b 59 ca f1 23 5b 2a 93 ff 81 
    fc 40 3a dd f4 eb de a8 49 34 a9 cd af 8e 1a 9e`.replace(/[^0-9A-F]/gi, ''), 'hex')
        },
        {
    
    // # --------------------------------
    // # RSASSA-PSS Signature Example 9.2
    // # --------------------------------
    
    // # Message to be signed:
            msg: Buffer.from(`
    c8 c9 c6 af 04 ac da 41 4d 22 7e f2 3e 08 20 c3 
    73 2c 50 0d c8 72 75 e9 5b 0d 09 54 13 99 3c 26 
    58 bc 1d 98 85 81 ba 87 9c 2d 20 1f 14 cb 88 ce 
    d1 53 a0 19 69 a7 bf 0a 7b e7 9c 84 c1 48 6b c1 
    2b 3f a6 c5 98 71 b6 82 7c 8c e2 53 ca 5f ef a8 
    a8 c6 90 bf 32 6e 8e 37 cd b9 6d 90 a8 2e ba b6 
    9f 86 35 0e 18 22 e8 bd 53 6a 2e`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Salt:
            salt: Buffer.from(`
    b3 07 c4 3b 48 50 a8 da c2 f1 5f 32 e3 78 39 ef 
    8c 5c 0e 91`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Signature:
            sig: Buffer.from(`
    80 b6 d6 43 25 52 09 f0 a4 56 76 38 97 ac 9e d2 
    59 d4 59 b4 9c 28 87 e5 88 2e cb 44 34 cf d6 6d 
    d7 e1 69 93 75 38 1e 51 cd 7f 55 4f 2c 27 17 04 
    b3 99 d4 2b 4b e2 54 0a 0e ca 61 95 1f 55 26 7f 
    7c 28 78 c1 22 84 2d ad b2 8b 01 bd 5f 8c 02 5f 
    7e 22 84 18 a6 73 c0 3d 6b c0 c7 36 d0 a2 95 46 
    bd 67 f7 86 d9 d6 92 cc ea 77 8d 71 d9 8c 20 63 
    b7 a7 10 92 18 7a 4d 35 af 10 81 11 d8 3e 83 ea 
    e4 6c 46 aa 34 27 7e 06 04 45 89 90 37 88 f1 d5 
    e7 ce e2 5f b4 85 e9 29 49 11 88 14 d6 f2 c3 ee 
    36 14 89 01 6f 32 7f b5 bc 51 7e b5 04 70 bf fa 
    1a fa 5f 4c e9 aa 0c e5 b8 ee 19 bf 55 01 b9 58`.replace(/[^0-9A-F]/gi, ''), 'hex')
        },
        {
    
    // # --------------------------------
    // # RSASSA-PSS Signature Example 9.3
    // # --------------------------------
    
    // # Message to be signed:
            msg: Buffer.from(`
    0a fa d4 2c cd 4f c6 06 54 a5 50 02 d2 28 f5 2a 
    4a 5f e0 3b 8b bb 08 ca 82 da ca 55 8b 44 db e1 
    26 6e 50 c0 e7 45 a3 6d 9d 29 04 e3 40 8a bc d1 
    fd 56 99 94 06 3f 4a 75 cc 72 f2 fe e2 a0 cd 89 
    3a 43 af 1c 5b 8b 48 7d f0 a7 16 10 02 4e 4f 6d 
    df 9f 28 ad 08 13 c1 aa b9 1b cb 3c 90 64 d5 ff 
    74 2d ef fe a6 57 09 41 39 36 9e 5e a6 f4 a9 63 
    19 a5 cc 82 24 14 5b 54 50 62 75 8f ef d1 fe 34 
    09 ae 16 92 59 c6 cd fd 6b 5f 29 58 e3 14 fa ec 
    be 69 d2 ca ce 58 ee 55 17 9a b9 b3 e6 d1 ec c1 
    4a 55 7c 5f eb e9 88 59 52 64 fc 5d a1 c5 71 46 
    2e ca 79 8a 18 a1 a4 94 0c da b4 a3 e9 20 09 cc 
    d4 2e 1e 94 7b 13 14 e3 22 38 a2 de ce 7d 23 a8 
    9b 5b 30 c7 51 fd 0a 4a 43 0d 2c 54 85 94`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Salt:
            salt: Buffer.from(`
    9a 2b 00 7e 80 97 8b bb 19 2c 35 4e b7 da 9a ed 
    fc 74 db f5`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Signature:
            sig: Buffer.from(`
    48 44 08 f3 89 8c d5 f5 34 83 f8 08 19 ef bf 27 
    08 c3 4d 27 a8 b2 a6 fa e8 b3 22 f9 24 02 37 f9 
    81 81 7a ca 18 46 f1 08 4d aa 6d 7c 07 95 f6 e5 
    bf 1a f5 9c 38 e1 85 84 37 ce 1f 7e c4 19 b9 8c 
    87 36 ad f6 dd 9a 00 b1 80 6d 2b d3 ad 0a 73 77 
    5e 05 f5 2d fe f3 a5 9a b4 b0 81 43 f0 df 05 cd 
    1a d9 d0 4b ec ec a6 da a4 a2 12 98 03 e2 00 cb 
    c7 77 87 ca f4 c1 d0 66 3a 6c 59 87 b6 05 95 20 
    19 78 2c af 2e c1 42 6d 68 fb 94 ed 1d 4b e8 16 
    a7 ed 08 1b 77 e6 ab 33 0b 3f fc 07 38 20 fe cd 
    e3 72 7f cb e2 95 ee 61 a0 50 a3 43 65 86 37 c3 
    fd 65 9c fb 63 73 6d e3 2d 9f 90 d3 c2 f6 3e ca`.replace(/[^0-9A-F]/gi, ''), 'hex')
        },
        {
    
    // # --------------------------------
    // # RSASSA-PSS Signature Example 9.4
    // # --------------------------------
    
    // # Message to be signed:
            msg: Buffer.from(`
    1d fd 43 b4 6c 93 db 82 62 9b da e2 bd 0a 12 b8 
    82 ea 04 c3 b4 65 f5 cf 93 02 3f 01 05 96 26 db 
    be 99 f2 6b b1 be 94 9d dd d1 6d c7 f3 de bb 19 
    a1 94 62 7f 0b 22 44 34 df 7d 87 00 e9 e9 8b 06 
    e3 60 c1 2f db e3 d1 9f 51 c9 68 4e b9 08 9e cb 
    b0 a2 f0 45 03 99 d3 f5 9e ac 72 94 08 5d 04 4f 
    53 93 c6 ce 73 74 23 d8 b8 6c 41 53 70 d3 89 e3 
    0b 9f 0a 3c 02 d2 5d 00 82 e8 ad 6f 3f 1e f2 4a 
    45 c3 cf 82 b3 83 36 70 63 a4 d4 61 3e 42 64 f0 
    1b 2d ac 2e 5a a4 20 43 f8 fb 5f 69 fa 87 1d 14 
    fb 27 3e 76 7a 53 1c 40 f0 2f 34 3b c2 fb 45 a0 
    c7 e0 f6 be 25 61 92 3a 77 21 1d 66 a6 e2 db b4 
    3c 36 63 50 be ae 22 da 3a c2 c1 f5 07 70 96 fc 
    b5 c4 bf 25 5f 75 74 35 1a e0 b1 e1 f0 36 32 81 
    7c 08 56 d4 a8 ba 97 af bd c8 b8 58 55 40 2b c5 
    69 26 fc ec 20 9f 9e a8`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Salt:
            salt: Buffer.from(`
    70 f3 82 bd df 4d 5d 2d d8 8b 3b c7 b7 30 8b e6 
    32 b8 40 45`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Signature:
            sig: Buffer.from(`
    84 eb eb 48 1b e5 98 45 b4 64 68 ba fb 47 1c 01 
    12 e0 2b 23 5d 84 b5 d9 11 cb d1 92 6e e5 07 4a 
    e0 42 44 95 cb 20 e8 23 08 b8 eb b6 5f 41 9a 03 
    fb 40 e7 2b 78 98 1d 88 aa d1 43 05 36 85 17 2c 
    97 b2 9c 8b 7b f0 ae 73 b5 b2 26 3c 40 3d a0 ed 
    2f 80 ff 74 50 af 78 28 eb 8b 86 f0 02 8b d2 a8 
    b1 76 a4 d2 28 cc ce a1 83 94 f2 38 b0 9f f7 58 
    cc 00 bc 04 30 11 52 35 57 42 f2 82 b5 4e 66 3a 
    91 9e 70 9d 8d a2 4a de 55 00 a7 b9 aa 50 22 6e 
    0c a5 29 23 e6 c2 d8 60 ec 50 ff 48 0f a5 74 77 
    e8 2b 05 65 f4 37 9f 79 c7 72 d5 c2 da 80 af 9f 
    bf 32 5e ce 6f c2 0b 00 96 16 14 be e8 9a 18 3e`.replace(/[^0-9A-F]/gi, ''), 'hex')
        },
        {
    
    // # --------------------------------
    // # RSASSA-PSS Signature Example 9.5
    // # --------------------------------
    
    // # Message to be signed:
            msg: Buffer.from(`
    1b dc 6e 7c 98 fb 8c f5 4e 9b 09 7b 66 a8 31 e9 
    cf e5 2d 9d 48 88 44 8e e4 b0 97 80 93 ba 1d 7d 
    73 ae 78 b3 a6 2b a4 ad 95 cd 28 9c cb 9e 00 52 
    26 bb 3d 17 8b cc aa 82 1f b0 44 a4 e2 1e e9 76 
    96 c1 4d 06 78 c9 4c 2d ae 93 b0 ad 73 92 22 18 
    55 3d aa 7e 44 eb e5 77 25 a7 a4 5c c7 2b 9b 21 
    38 a6 b1 7c 8d b4 11 ce 82 79 ee 12 41 af f0 a8 
    be c6 f7 7f 87 ed b0 c6 9c b2 72 36 e3 43 5a 80 
    0b 19 2e 4f 11 e5 19 e3 fe 30 fc 30 ea cc ca 4f 
    bb 41 76 90 29 bf 70 8e 81 7a 9e 68 38 05 be 67 
    fa 10 09 84 68 3b 74 83 8e 3b cf fa 79 36 6e ed 
    1d 48 1c 76 72 91 18 83 8f 31 ba 8a 04 8a 93 c1 
    be 44 24 59 8e 8d f6 32 8b 7a 77 88 0a 3f 9c 7e 
    2e 8d fc a8 eb 5a 26 fb 86 bd c5 56 d4 2b be 01 
    d9 fa 6e d8 06 46 49 1c 93 41`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Salt:
            salt: Buffer.from(`
    d6 89 25 7a 86 ef fa 68 21 2c 5e 0c 61 9e ca 29 
    5f b9 1b 67`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Signature:
            sig: Buffer.from(`
    82 10 2d f8 cb 91 e7 17 99 19 a0 4d 26 d3 35 d6 
    4f bc 2f 87 2c 44 83 39 43 24 1d e8 45 48 10 27 
    4c df 3d b5 f4 2d 42 3d b1 52 af 71 35 f7 01 42 
    0e 39 b4 94 a6 7c bf d1 9f 91 19 da 23 3a 23 da 
    5c 64 39 b5 ba 0d 2b c3 73 ee e3 50 70 01 37 8d 
    4a 40 73 85 6b 7f e2 ab a0 b5 ee 93 b2 7f 4a fe 
    c7 d4 d1 20 92 1c 83 f6 06 76 5b 02 c1 9e 4d 6a 
    1a 3b 95 fa 4c 42 29 51 be 4f 52 13 10 77 ef 17 
    17 97 29 cd df bd b5 69 50 db ac ee fe 78 cb 16 
    64 0a 09 9e a5 6d 24 38 9e ef 10 f8 fe cb 31 ba 
    3e a3 b2 27 c0 a8 66 98 bb 89 e3 e9 36 39 05 bf 
    22 77 7b 2a 3a a5 21 b6 5b 4c ef 76 d8 3b de 4c`.replace(/[^0-9A-F]/gi, ''), 'hex')
        },
        {
    
    // # ------------------------------
    // # RSASSA-PSS Signature Example 9.6
    // # ------------------------------
    
    // # Message to be signed:
            msg: Buffer.from(`
    88 c7 a9 f1 36 04 01 d9 0e 53 b1 01 b6 1c 53 25 
    c3 c7 5d b1 b4 11 fb eb 8e 83 0b 75 e9 6b 56 67 
    0a d2 45 40 4e 16 79 35 44 ee 35 4b c6 13 a9 0c 
    c9 84 87 15 a7 3d b5 89 3e 7f 6d 27 98 15 c0 c1 
    de 83 ef 8e 29 56 e3 a5 6e d2 6a 88 8d 7a 9c dc 
    d0 42 f4 b1 6b 7f a5 1e f1 a0 57 36 62 d1 6a 30 
    2d 0e c5 b2 85 d2 e0 3a d9 65 29 c8 7b 3d 37 4d 
    b3 72 d9 5b 24 43 d0 61 b6 b1 a3 50 ba 87 80 7e 
    d0 83 af d1 eb 05 c3 f5 2f 4e ba 5e d2 22 77 14 
    fd b5 0b 9d 9d 9d d6 81 4f 62 f6 27 2f cd 5c db 
    ce 7a 9e f7 97`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Salt:
            salt: Buffer.from(`
    c2 5f 13 bf 67 d0 81 67 1a 04 81 a1 f1 82 0d 61 
    3b ba 22 76`.replace(/[^0-9A-F]/gi, ''), 'hex'),
    
    // # Signature:
            sig: Buffer.from(`
    a7 fd b0 d2 59 16 5c a2 c8 8d 00 bb f1 02 8a 86 
    7d 33 76 99 d0 61 19 3b 17 a9 64 8e 14 cc bb aa 
    de ac aa cd ec 81 5e 75 71 29 4e bb 8a 11 7a f2 
    05 fa 07 8b 47 b0 71 2c 19 9e 3a d0 51 35 c5 04 
    c2 4b 81 70 51 15 74 08 02 48 79 92 ff d5 11 d4 
    af c6 b8 54 49 1e b3 f0 dd 52 31 39 54 2f f1 5c 
    31 01 ee 85 54 35 17 c6 a3 c7 94 17 c6 7e 2d d9 
    aa 74 1e 9a 29 b0 6d cb 59 3c 23 36 b3 67 0a e3 
    af ba c7 c3 e7 6e 21 54 73 e8 66 e3 38 ca 24 4d 
    e0 0b 62 62 4d 6b 94 26 82 2c ea e9 f8 cc 46 08 
    95 f4 12 50 07 3f d4 5c 5a 1e 7b 42 5c 20 4a 42 
    3a 69 91 59 f6 90 3e 71 0b 37 a7 bb 2b c8 04 9f`.replace(/[^0-9A-F]/gi, ''), 'hex')
        }
    ];
    
    var rsa = new jCastle.pki.rsa();
    rsa.setPrivateKey({
        n, e, d, p, q, dmp1, dmq1, iqmp
    });

    for (var i = 0; i < testVectors.length; i++) {
        var vector = testVectors[i];

        var v_sig = rsa.pssSign(vector.msg, {
            salt: vector.salt,
            hashAlgo: 'sha-1',
            saltLength: vector.salt.length
        });

        assert.ok(v_sig.equals(vector.sig), bits + '-bit pss sign test ' + (i + 1));
        // console.log(bits + '-bit pss sign test ' + (i + 1) + ': ', v_sig.equals(vector.sig));

        var v = rsa.pssVerify(vector.msg, vector.sig, {
            salt: vector.salt,
            hashAlgo: 'sha-1',
            saltLength: vector.salt.length
        });

        assert.ok(v, bits + '-bit pss verify test ' + (i + 1));
        // console.log(bits + '-bit pss verify test ' + (i + 1) + ': ', v);
    }


// # =============================================

// # ===================================
// # Example 10: A 2048-bit RSA Key Pair
// # ===================================
var bits = 2048;
// # ------------------------------
// # Components of the RSA Key Pair
// # ------------------------------

// # RSA modulus n:
	var n = Buffer.from(
`a5 dd 86 7a c4 cb 02 f9 0b 94 57 d4 8c 14 a7 70 
ef 99 1c 56 c3 9c 0e c6 5f d1 1a fa 89 37 ce a5 
7b 9b e7 ac 73 b4 5c 00 17 61 5b 82 d6 22 e3 18 
75 3b 60 27 c0 fd 15 7b e1 2f 80 90 fe e2 a7 ad 
cd 0e ef 75 9f 88 ba 49 97 c7 a4 2d 58 c9 aa 12 
cb 99 ae 00 1f e5 21 c1 3b b5 43 14 45 a8 d5 ae 
4f 5e 4c 7e 94 8a c2 27 d3 60 40 71 f2 0e 57 7e 
90 5f be b1 5d fa f0 6d 1d e5 ae 62 53 d6 3a 6a 
21 20 b3 1a 5d a5 da bc 95 50 60 0e 20 f2 7d 37 
39 e2 62 79 25 fe a3 cc 50 9f 21 df f0 4e 6e ea 
45 49 c5 40 d6 80 9f f9 30 7e ed e9 1f ff 58 73 
3d 83 85 a2 37 d6 d3 70 5a 33 e3 91 90 09 92 07 
0d f7 ad f1 35 7c f7 e3 70 0c e3 66 7d e8 3f 17 
b8 df 17 78 db 38 1d ce 09 cb 4a d0 58 a5 11 00 
1a 73 81 98 ee 27 cf 55 a1 3b 75 45 39 90 65 82 
ec 8b 17 4b d5 8d 5d 1f 3d 76 7c 61 37 21 ae 05`.replace(/[^0-9A-F]/gi, ''), 'hex');

// # RSA public exponent e: 
	var e = parseInt(`01 00 01`.replace(/[^0-9A-F]/gi, ''), 16);

// # RSA private exponent d: 
	var d = Buffer.from(
`2d 2f f5 67 b3 fe 74 e0 61 91 b7 fd ed 6d e1 12 
29 0c 67 06 92 43 0d 59 69 18 40 47 da 23 4c 96 
93 de ed 16 73 ed 42 95 39 c9 69 d3 72 c0 4d 6b 
47 e0 f5 b8 ce e0 84 3e 5c 22 83 5d bd 3b 05 a0 
99 79 84 ae 60 58 b1 1b c4 90 7c bf 67 ed 84 fa 
9a e2 52 df b0 d0 cd 49 e6 18 e3 5d fd fe 59 bc 
a3 dd d6 6c 33 ce bb c7 7a d4 41 aa 69 5e 13 e3 
24 b5 18 f0 1c 60 f5 a8 5c 99 4a d1 79 f2 a6 b5 
fb e9 34 02 b1 17 67 be 01 bf 07 34 44 d6 ba 1d 
d2 bc a5 bd 07 4d 4a 5f ae 35 31 ad 13 03 d8 4b 
30 d8 97 31 8c bb ba 04 e0 3c 2e 66 de 6d 91 f8 
2f 96 ea 1d 4b b5 4a 5a ae 10 2d 59 46 57 f5 c9 
78 95 53 51 2b 29 6d ea 29 d8 02 31 96 35 7e 3e 
3a 6e 95 8f 39 e3 c2 34 40 38 ea 60 4b 31 ed c6 
f0 f7 ff 6e 71 81 a5 7c 92 82 6a 26 8f 86 76 8e 
96 f8 78 56 2f c7 1d 85 d6 9e 44 86 12 f7 04 8f`.replace(/[^0-9A-F]/gi, ''), 'hex');

// # Prime p: 
	var p = Buffer.from(
`cf d5 02 83 fe ee b9 7f 6f 08 d7 3c bc 7b 38 36 
f8 2b bc d4 99 47 9f 5e 6f 76 fd fc b8 b3 8c 4f 
71 dc 9e 88 bd 6a 6f 76 37 1a fd 65 d2 af 18 62 
b3 2a fb 34 a9 5f 71 b8 b1 32 04 3f fe be 3a 95 
2b af 75 92 44 81 48 c0 3f 9c 69 b1 d6 8e 4c e5 
cf 32 c8 6b af 46 fe d3 01 ca 1a b4 03 06 9b 32 
f4 56 b9 1f 71 89 8a b0 81 cd 8c 42 52 ef 52 71 
91 5c 97 94 b8 f2 95 85 1d a7 51 0f 99 cb 73 eb`.replace(/[^0-9A-F]/gi, ''), 'hex');

// # Prime q: 
	var q = Buffer.from(
`cc 4e 90 d2 a1 b3 a0 65 d3 b2 d1 f5 a8 fc e3 1b 
54 44 75 66 4e ab 56 1d 29 71 b9 9f b7 be f8 44 
e8 ec 1f 36 0b 8c 2a c8 35 96 92 97 1e a6 a3 8f 
72 3f cc 21 1f 5d bc b1 77 a0 fd ac 51 64 a1 d4 
ff 7f bb 4e 82 99 86 35 3c b9 83 65 9a 14 8c dd 
42 0c 7d 31 ba 38 22 ea 90 a3 2b e4 6c 03 0e 8c 
17 e1 fa 0a d3 78 59 e0 6b 0a a6 fa 3b 21 6d 9c 
be 6c 0e 22 33 97 69 c0 a6 15 91 3e 5d a7 19 cf`.replace(/[^0-9A-F]/gi, ''), 'hex');

// # p's CRT exponent dP: 
	var dmp1 = Buffer.from(
`1c 2d 1f c3 2f 6b c4 00 4f d8 5d fd e0 fb bf 9a 
4c 38 f9 c7 c4 e4 1d ea 1a a8 82 34 a2 01 cd 92 
f3 b7 da 52 65 83 a9 8a d8 5b b3 60 fb 98 3b 71 
1e 23 44 9d 56 1d 17 78 d7 a5 15 48 6b cb f4 7b 
46 c9 e9 e1 a3 a1 f7 70 00 ef be b0 9a 8a fe 47 
e5 b8 57 cd a9 9c b1 6d 7f ff 9b 71 2e 3b d6 0c 
a9 6d 9c 79 73 d6 16 d4 69 34 a9 c0 50 28 1c 00 
43 99 ce ff 1d b7 dd a7 87 66 a8 a9 b9 cb 08 73`.replace(/[^0-9A-F]/gi, ''), 'hex');

// # q's CRT exponent dQ: 
	var dmq1 = Buffer.from(
`cb 3b 3c 04 ca a5 8c 60 be 7d 9b 2d eb b3 e3 96 
43 f4 f5 73 97 be 08 23 6a 1e 9e af aa 70 65 36 
e7 1c 3a cf e0 1c c6 51 f2 3c 9e 05 85 8f ee 13 
bb 6a 8a fc 47 df 4e dc 9a 4b a3 0b ce cb 73 d0 
15 78 52 32 7e e7 89 01 5c 2e 8d ee 7b 9f 05 a0 
f3 1a c9 4e b6 17 31 64 74 0c 5c 95 14 7c d5 f3 
b5 ae 2c b4 a8 37 87 f0 1d 8a b3 1f 27 c2 d0 ee 
a2 dd 8a 11 ab 90 6a ba 20 7c 43 c6 ee 12 53 31`.replace(/[^0-9A-F]/gi, ''), 'hex');

// # CRT coefficient qInv: 
	var iqmp = Buffer.from(
`12 f6 b2 cf 13 74 a7 36 fa d0 56 16 05 0f 96 ab 
4b 61 d1 17 7c 7f 9d 52 5a 29 f3 d1 80 e7 76 67 
e9 9d 99 ab f0 52 5d 07 58 66 0f 37 52 65 5b 0f 
25 b8 df 84 31 d9 a8 ff 77 c1 6c 12 a0 a5 12 2a 
9f 0b f7 cf d5 a2 66 a3 5c 15 9f 99 12 08 b9 03 
16 ff 44 4f 3e 0b 6b d0 e9 3b 8a 7a 24 48 e9 57 
e3 dd a6 cf cf 22 66 b1 06 01 3a c4 68 08 d3 b3 
88 7b 3b 00 34 4b aa c9 53 0b 4c e7 08 fc 32 b6`.replace(/[^0-9A-F]/gi, ''), 'hex');

	var testVectors = [
		{
// # ---------------------------------
// # RSASSA-PSS Signature Example 10.1
// # ---------------------------------

// # Message to be signed:
        msg: Buffer.from(
`88 31 77 e5 12 6b 9b e2 d9 a9 68 03 27 d5 37 0c 
6f 26 86 1f 58 20 c4 3d a6 7a 3a d6 09`.replace(/[^0-9A-F]/gi, ''), 'hex'),

// # Salt:
        salt: Buffer.from(
`04 e2 15 ee 6f f9 34 b9 da 70 d7 73 0c 87 34 ab 
fc ec de 89`.replace(/[^0-9A-F]/gi, ''), 'hex'),

// # Signature:
        sig: Buffer.from(
`82 c2 b1 60 09 3b 8a a3 c0 f7 52 2b 19 f8 73 54 
06 6c 77 84 7a bf 2a 9f ce 54 2d 0e 84 e9 20 c5 
af b4 9f fd fd ac e1 65 60 ee 94 a1 36 96 01 14 
8e ba d7 a0 e1 51 cf 16 33 17 91 a5 72 7d 05 f2 
1e 74 e7 eb 81 14 40 20 69 35 d7 44 76 5a 15 e7 
9f 01 5c b6 6c 53 2c 87 a6 a0 59 61 c8 bf ad 74 
1a 9a 66 57 02 28 94 39 3e 72 23 73 97 96 c0 2a 
77 45 5d 0f 55 5b 0e c0 1d df 25 9b 62 07 fd 0f 
d5 76 14 ce f1 a5 57 3b aa ff 4e c0 00 69 95 16 
59 b8 5f 24 30 0a 25 16 0c a8 52 2d c6 e6 72 7e 
57 d0 19 d7 e6 36 29 b8 fe 5e 89 e2 5c c1 5b eb 
3a 64 75 77 55 92 99 28 0b 9b 28 f7 9b 04 09 00 
0b e2 5b bd 96 40 8b a3 b4 3c c4 86 18 4d d1 c8 
e6 25 53 fa 1a f4 04 0f 60 66 3d e7 f5 e4 9c 04 
38 8e 25 7f 1c e8 9c 95 da b4 8a 31 5d 9b 66 b1 
b7 62 82 33 87 6f f2 38 52 30 d0 70 d0 7e 16 66`.replace(/[^0-9A-F]/gi, ''), 'hex')
		},
		{    
// # ---------------------------------
// # RSASSA-PSS Signature Example 10.2
// # ---------------------------------

// # Message to be signed:
        msg: Buffer.from(
`dd 67 0a 01 46 58 68 ad c9 3f 26 13 19 57 a5 0c 
52 fb 77 7c db aa 30 89 2c 9e 12 36 11 64 ec 13 
97 9d 43 04 81 18 e4 44 5d b8 7b ee 58 dd 98 7b 
34 25 d0 20 71 d8 db ae 80 70 8b 03 9d bb 64 db 
d1 de 56 57 d9 fe d0 c1 18 a5 41 43 74 2e 0f f3 
c8 7f 74 e4 58 57 64 7a f3 f7 9e b0 a1 4c 9d 75 
ea 9a 1a 04 b7 cf 47 8a 89 7a 70 8f d9 88 f4 8e 
80 1e db 0b 70 39 df 8c 23 bb 3c 56 f4 e8 21 ac`.replace(/[^0-9A-F]/gi, ''), 'hex'),

// # Salt:
        salt: Buffer.from(
`8b 2b dd 4b 40 fa f5 45 c7 78 dd f9 bc 1a 49 cb 
57 f9 b7 1b`.replace(/[^0-9A-F]/gi, ''), 'hex'),

// # Signature:
        sig: Buffer.from(
`14 ae 35 d9 dd 06 ba 92 f7 f3 b8 97 97 8a ed 7c 
d4 bf 5f f0 b5 85 a4 0b d4 6c e1 b4 2c d2 70 30 
53 bb 90 44 d6 4e 81 3d 8f 96 db 2d d7 00 7d 10 
11 8f 6f 8f 84 96 09 7a d7 5e 1f f6 92 34 1b 28 
92 ad 55 a6 33 a1 c5 5e 7f 0a 0a d5 9a 0e 20 3a 
5b 82 78 ae c5 4d d8 62 2e 28 31 d8 71 74 f8 ca 
ff 43 ee 6c 46 44 53 45 d8 4a 59 65 9b fb 92 ec 
d4 c8 18 66 86 95 f3 47 06 f6 68 28 a8 99 59 63 
7f 2b f3 e3 25 1c 24 bd ba 4d 4b 76 49 da 00 22 
21 8b 11 9c 84 e7 9a 65 27 ec 5b 8a 5f 86 1c 15 
99 52 e2 3e c0 5e 1e 71 73 46 fa ef e8 b1 68 68 
25 bd 2b 26 2f b2 53 10 66 c0 de 09 ac de 2e 42 
31 69 07 28 b5 d8 5e 11 5a 2f 6b 92 b7 9c 25 ab 
c9 bd 93 99 ff 8b cf 82 5a 52 ea 1f 56 ea 76 dd 
26 f4 3b aa fa 18 bf a9 2a 50 4c bd 35 69 9e 26 
d1 dc c5 a2 88 73 85 f3 c6 32 32 f0 6f 32 44 c3`.replace(/[^0-9A-F]/gi, ''), 'hex'),
		},
		{
// # ---------------------------------
// # RSASSA-PSS Signature Example 10.3
// # ---------------------------------

// # Message to be signed:
        msg: Buffer.from(
`48 b2 b6 a5 7a 63 c8 4c ea 85 9d 65 c6 68 28 4b 
08 d9 6b dc aa be 25 2d b0 e4 a9 6c b1 ba c6 01 
93 41 db 6f be fb 8d 10 6b 0e 90 ed a6 bc c6 c6 
26 2f 37 e7 ea 9c 7e 5d 22 6b d7 df 85 ec 5e 71 
ef ff 2f 54 c5 db 57 7f f7 29 ff 91 b8 42 49 1d 
e2 74 1d 0c 63 16 07 df 58 6b 90 5b 23 b9 1a f1 
3d a1 23 04 bf 83 ec a8 a7 3e 87 1f f9 db`.replace(/[^0-9A-F]/gi, ''), 'hex'),

// # Salt:
        salt: Buffer.from(
`4e 96 fc 1b 39 8f 92 b4 46 71 01 0c 0d c3 ef d6 
e2 0c 2d 73`.replace(/[^0-9A-F]/gi, ''), 'hex'),

// # Signature:
        sig: Buffer.from(
`6e 3e 4d 7b 6b 15 d2 fb 46 01 3b 89 00 aa 5b bb 
39 39 cf 2c 09 57 17 98 70 42 02 6e e6 2c 74 c5 
4c ff d5 d7 d5 7e fb bf 95 0a 0f 5c 57 4f a0 9d 
3f c1 c9 f5 13 b0 5b 4f f5 0d d8 df 7e df a2 01 
02 85 4c 35 e5 92 18 01 19 a7 0c e5 b0 85 18 2a 
a0 2d 9e a2 aa 90 d1 df 03 f2 da ae 88 5b a2 f5 
d0 5a fd ac 97 47 6f 06 b9 3b 5b c9 4a 1a 80 aa 
91 16 c4 d6 15 f3 33 b0 98 89 2b 25 ff ac e2 66 
f5 db 5a 5a 3b cc 10 a8 24 ed 55 aa d3 5b 72 78 
34 fb 8c 07 da 28 fc f4 16 a5 d9 b2 22 4f 1f 8b 
44 2b 36 f9 1e 45 6f de a2 d7 cf e3 36 72 68 de 
03 07 a4 c7 4e 92 41 59 ed 33 39 3d 5e 06 55 53 
1c 77 32 7b 89 82 1b de df 88 01 61 c7 8c d4 19 
6b 54 19 f7 ac c3 f1 3e 5e bf 16 1b 6e 7c 67 24 
71 6c a3 3b 85 c2 e2 56 40 19 2a c2 85 96 51 d5 
0b de 7e b9 76 e5 1c ec 82 8b 98 b6 56 3b 86 bb`.replace(/[^0-9A-F]/gi, ''), 'hex')
		},
		{
// # ---------------------------------
// # RSASSA-PSS Signature Example 10.4
// # ---------------------------------

// # Message to be signed:
        msg: Buffer.from(
`0b 87 77 c7 f8 39 ba f0 a6 4b bb db c5 ce 79 75 
5c 57 a2 05 b8 45 c1 74 e2 d2 e9 05 46 a0 89 c4 
e6 ec 8a df fa 23 a7 ea 97 ba e6 b6 5d 78 2b 82 
db 5d 2b 5a 56 d2 2a 29 a0 5e 7c 44 33 e2 b8 2a 
62 1a bb a9 0a dd 05 ce 39 3f c4 8a 84 05 42 45 
1a`.replace(/[^0-9A-F]/gi, ''), 'hex'),

// # Salt:
        salt: Buffer.from(
`c7 cd 69 8d 84 b6 51 28 d8 83 5e 3a 8b 1e b0 e0 
1c b5 41 ec`.replace(/[^0-9A-F]/gi, ''), 'hex'),

// # Signature:
        sig: Buffer.from(
`34 04 7f f9 6c 4d c0 dc 90 b2 d4 ff 59 a1 a3 61 
a4 75 4b 25 5d 2e e0 af 7d 8b f8 7c 9b c9 e7 dd 
ee de 33 93 4c 63 ca 1c 0e 3d 26 2c b1 45 ef 93 
2a 1f 2c 0a 99 7a a6 a3 4f 8e ae e7 47 7d 82 cc 
f0 90 95 a6 b8 ac ad 38 d4 ee c9 fb 7e ab 7a d0 
2d a1 d1 1d 8e 54 c1 82 5e 55 bf 58 c2 a2 32 34 
b9 02 be 12 4f 9e 90 38 a8 f6 8f a4 5d ab 72 f6 
6e 09 45 bf 1d 8b ac c9 04 4c 6f 07 09 8c 9f ce 
c5 8a 3a ab 10 0c 80 51 78 15 5f 03 0a 12 4c 45 
0e 5a cb da 47 d0 e4 f1 0b 80 a2 3f 80 3e 77 4d 
02 3b 00 15 c2 0b 9f 9b be 7c 91 29 63 38 d5 ec 
b4 71 ca fb 03 20 07 b6 7a 60 be 5f 69 50 4a 9f 
01 ab b3 cb 46 7b 26 0e 2b ce 86 0b e8 d9 5b f9 
2c 0c 8e 14 96 ed 1e 52 85 93 a4 ab b6 df 46 2d 
de 8a 09 68 df fe 46 83 11 68 57 a2 32 f5 eb f6 
c8 5b e2 38 74 5a d0 f3 8f 76 7a 5f db f4 86 fb`.replace(/[^0-9A-F]/gi, ''), 'hex')
		},
		{    
// # ---------------------------------
// # RSASSA-PSS Signature Example 10.5
// # ---------------------------------

// # Message to be signed:
        msg: Buffer.from(
`f1 03 6e 00 8e 71 e9 64 da dc 92 19 ed 30 e1 7f 
06 b4 b6 8a 95 5c 16 b3 12 b1 ed df 02 8b 74 97 
6b ed 6b 3f 6a 63 d4 e7 78 59 24 3c 9c cc dc 98 
01 65 23 ab b0 24 83 b3 55 91 c3 3a ad 81 21 3b 
b7 c7 bb 1a 47 0a ab c1 0d 44 25 6c 4d 45 59 d9 
16`.replace(/[^0-9A-F]/gi, ''), 'hex'),

// # Salt:
        salt: Buffer.from(
`ef a8 bf f9 62 12 b2 f4 a3 f3 71 a1 0d 57 41 52 
65 5f 5d fb`.replace(/[^0-9A-F]/gi, ''), 'hex'),

// # Signature:
        sig: Buffer.from(
`7e 09 35 ea 18 f4 d6 c1 d1 7c e8 2e b2 b3 83 6c 
55 b3 84 58 9c e1 9d fe 74 33 63 ac 99 48 d1 f3 
46 b7 bf dd fe 92 ef d7 8a db 21 fa ef c8 9a de 
42 b1 0f 37 40 03 fe 12 2e 67 42 9a 1c b8 cb d1 
f8 d9 01 45 64 c4 4d 12 01 16 f4 99 0f 1a 6e 38 
77 4c 19 4b d1 b8 21 32 86 b0 77 b0 49 9d 2e 7b 
3f 43 4a b1 22 89 c5 56 68 4d ee d7 81 31 93 4b 
b3 dd 65 37 23 6f 7c 6f 3d cb 09 d4 76 be 07 72 
1e 37 e1 ce ed 9b 2f 7b 40 68 87 bd 53 15 73 05 
e1 c8 b4 f8 4d 73 3b c1 e1 86 fe 06 cc 59 b6 ed 
b8 f4 bd 7f fe fd f4 f7 ba 9c fb 9d 57 06 89 b5 
a1 a4 10 9a 74 6a 69 08 93 db 37 99 25 5a 0c b9 
21 5d 2d 1c d4 90 59 0e 95 2e 8c 87 86 aa 00 11 
26 52 52 47 0c 04 1d fb c3 ee c7 c3 cb f7 1c 24 
86 9d 11 5c 0c b4 a9 56 f5 6d 53 0b 80 ab 58 9a 
cf ef c6 90 75 1d df 36 e8 d3 83 f8 3c ed d2 cc`.replace(/[^0-9A-F]/gi, ''), 'hex')
		},
		{
// # ---------------------------------
// # RSASSA-PSS Signature Example 10.6
// # ---------------------------------

// # Message to be signed:
        msg: Buffer.from(
`25 f1 08 95 a8 77 16 c1 37 45 0b b9 51 9d fa a1 
f2 07 fa a9 42 ea 88 ab f7 1e 9c 17 98 00 85 b5 
55 ae ba b7 62 64 ae 2a 3a b9 3c 2d 12 98 11 91 
dd ac 6f b5 94 9e b3 6a ee 3c 5d a9 40 f0 07 52 
c9 16 d9 46 08 fa 7d 97 ba 6a 29 15 b6 88 f2 03 
23 d4 e9 d9 68 01 d8 9a 72 ab 58 92 dc 21 17 c0 
74 34 fc f9 72 e0 58 cf 8c 41 ca 4b 4f f5 54 f7 
d5 06 8a d3 15 5f ce d0 f3 12 5b c0 4f 91 93 37 
8a 8f 5c 4c 3b 8c b4 dd 6d 1c c6 9d 30 ec ca 6e 
aa 51 e3 6a 05 73 0e 9e 34 2e 85 5b af 09 9d ef 
b8 af d7`.replace(/[^0-9A-F]/gi, ''), 'hex'),

// # Salt:
        salt: Buffer.from(
`ad 8b 15 23 70 36 46 22 4b 66 0b 55 08 85 91 7c 
a2 d1 df 28`.replace(/[^0-9A-F]/gi, ''), 'hex'),

// # Signature:
        sig: Buffer.from(
`6d 3b 5b 87 f6 7e a6 57 af 21 f7 54 41 97 7d 21 
80 f9 1b 2c 5f 69 2d e8 29 55 69 6a 68 67 30 d9 
b9 77 8d 97 07 58 cc b2 60 71 c2 20 9f fb d6 12 
5b e2 e9 6e a8 1b 67 cb 9b 93 08 23 9f da 17 f7 
b2 b6 4e cd a0 96 b6 b9 35 64 0a 5a 1c b4 2a 91 
55 b1 c9 ef 7a 63 3a 02 c5 9f 0d 6e e5 9b 85 2c 
43 b3 50 29 e7 3c 94 0f f0 41 0e 8f 11 4e ed 46 
bb d0 fa e1 65 e4 2b e2 52 8a 40 1c 3b 28 fd 81 
8e f3 23 2d ca 9f 4d 2a 0f 51 66 ec 59 c4 23 96 
d6 c1 1d bc 12 15 a5 6f a1 71 69 db 95 75 34 3e 
f3 4f 9d e3 2a 49 cd c3 17 49 22 f2 29 c2 3e 18 
e4 5d f9 35 31 19 ec 43 19 ce dc e7 a1 7c 64 08 
8c 1f 6f 52 be 29 63 41 00 b3 91 9d 38 f3 d1 ed 
94 e6 89 1e 66 a7 3b 8f b8 49 f5 87 4d f5 94 59 
e2 98 c7 bb ce 2e ee 78 2a 19 5a a6 6f e2 d0 73 
2b 25 e5 95 f5 7d 3e 06 1b 1f c3 e4 06 3b f9 8f`.replace(/[^0-9A-F]/gi, ''), 'hex')
		}
	];

	// # =============================================

	var rsa = new jCastle.pki.rsa();
	rsa.setPrivateKey({
		n, e, d, p, q, dmp1, dmq1, iqmp
	});

	for (var i = 0; i < testVectors.length; i++) {
		var vector = testVectors[i];


		var v_sig = rsa.pssSign(vector.msg, {
			salt: vector.salt,
			hashAlgo: 'sha-1',
			saltLength: vector.salt.length
		});

		assert.ok(v_sig.equals(vector.sig), bits + '-bit pss sign test ' + (i + 1));

		var v = rsa.pssVerify(vector.msg, vector.sig, {
			//salt: vector.salt,
			hashAlgo: 'sha-1',
			saltLength: vector.salt.length
		});

		assert.ok(v, bits + '-bit pss verify test ' + (i + 1));
	}
});

QUnit.test("Sign/Verify Test", function(assert) {

	var n = 
	"A9E167983F39D55FF2A093415EA6798985C8355D9A915BFB1D01DA197026170F"+
	"BDA522D035856D7A986614415CCFB7B7083B09C991B81969376DF9651E7BD9A9"+
	"3324A37F3BBBAF460186363432CB07035952FC858B3104B8CC18081448E64F1C"+
	"FB5D60C4E05C1F53D37F53D86901F105F87A70D1BE83C65F38CF1C2CAA6AA7EB";
	var e = 0x10001;
	var d =
	"67CD484C9A0D8F98C21B65FF22839C6DF0A6061DBCEDA7038894F21C6B0F8B35"+
	"DE0E827830CBE7BA6A56AD77C6EB517970790AA0F4FE45E0A9B2F419DA8798D6"+
	"308474E4FC596CC1C677DCA991D07C30A0A2C5085E217143FC0D073DF0FA6D14"+
	"9E4E63F01758791C4B981C3D3DB01BDFFA253BA3C02C9805F61009D887DB0319";

	var k = Buffer.from("4E636AF98E40F3ADCFCCB698F4E80B9F", 'hex');

	var rsa = new jCastle.pki('RSA');
	rsa.setPrivateKey(n, e, d);

	var ct = rsa.publicEncrypt(k);

	assert.ok(rsa.privateDecrypt(ct).equals(k), "RSA publicEncrypt / privateDecrypt Test");

	var ct = rsa.publicEncrypt(k, {
        padding: {
            mode:'PKCS1_OAEP',
            hashAlgo: 'sha-256'
        }
    });

	assert.ok(rsa.privateDecrypt(ct, {
        padding: {
            mode: 'PKCS1_OAEP',
            hashAlgo: 'sha-256'
        }
    }).equals(k), "RSA publicEncrypt / privateDecrypt with OAEP encoding Test");


	var ct = rsa.privateEncrypt(k);

	assert.ok(rsa.publicDecrypt(ct).equals(k), "RSA privateEncrypt / publicDecrypt Test");

	var s = rsa.sign(k, {hashAlgo: 'sha-1'});

	assert.ok(rsa.verify(k, s, {hashAlgo: 'sha-1'}), "sign/verify Test (RSASSA-PKCS1-V1_5-SIGN)");

	var s = rsa.pssSign(k, {hashAlgo: 'sha-256'});

	assert.ok(rsa.pssVerify(k, s, {hashAlgo: 'sha-256'}), "sign/verify Test (RSASSA-PSS)");

	var s = rsa.ansiX931Sign(k, {hashAlgo: 'sha-256'});

	assert.ok(rsa.ansiX931Verify(k, s, {hashAlgo: 'sha-256'}), "sign/verify Test (ANSIX931-SIGN)");

	// test with setPadding
	rsa.setPadding('pkcs1_oaep', 'sha-256');

	var ct = rsa.publicEncrypt(k);

	assert.ok(rsa.privateDecrypt(ct, {
        padding: {
            mode: 'PKCS1_OAEP',
            hashAlgo: 'sha-256'
        }
    }).equals(k), "RSA publicEncrypt / privateDecrypt Test with PKCS1_OAEP Encoding working with setPadding.");
});


QUnit.test("PEM Test", function(assert) {

/*
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,584BBCF38BE41D90AB16740EE5D2E24C

k5m1gaYDbX+EYPcv/+wvSsYOkBpOxFYXbzMYY8Z2d39mfQ8Y+WzOJnWWYT2tj2d8
LodWRu2PD93or3z8wI0Y5huCs6VikZLtjxKawPwm5wosXud978k3dVw+VG/M8JDh
J6dIAbcmNxaHv1UX5gmdnRcRqSGt0WHXYbXgUlSNLwhrTU9osd7A/eLZf5MZ5hTB
5CQ/Tb9jCZxSyP8YiPvOuR9gCK5L3Ooq820mwZ0oL9r18uby4ElSmFuM+nipThyu
4SinV3MIN5bOMvsb34DDbQ9wbbtvDA1V7iJRItLo9+1v5d7O876BTSwX9Qd12P0C
WqiKUAt/T/ZB/NJC3bw2v9bRL+VifvfLmOigvw7r2NAokpRHb8Elv80S5ZtcZGmp
tQ7wCkO8kz/JFX/UXqqkSSBsegtGm+CwenEvyQ5dtUUu1ETo7vOMp9c+AZyKCNgu
MDC5nhLBm1H93t1Wko45yn/Az7RVw6yzUEp6WrADajjGtLwVbLC5eDd7+9utHp/x
UB/5H+vI+nbYP5KBc/Zqe/IjSrVKFBtoD2MowVtkWg42mGgQ1VNKYhKELLFFtWxd
HuYlHVYYiOHXbMLsofMkqxxJQatS7WtKBWBgmYbqhHxNpZ11QKxzk+Wo+J9ixLbs
ADBhAak4t7eHFZtbKonP+hEGanZGK04Wz8+leo+BL+7J5d4d9WZPFH9q47kM5/Wc
qUkJIZPzwKAlb5ot/9XQmqnECip2yRhyJYcOBqfg4EXfCbDqz3YCFS8HpPOVQqMs
ZGvRA9LrZfsy6V9NCWFZbBtiYjO2gOtYASoDKyo615vdma42L8P+h2UPtk8e0ziM
OpuZiR37HsahyWAcGgomprs+hmV5yFnzIs5O5P6J0uf2TCrUR8cZBuYoPVp9pErc
l/U5m0G+ENTwzs8Dd6ySyDpKlADRnjQYPxulbT4VpT9c9kUg3sxRHWRv5C0FLVPq
M0atErcFtKIlLPsEDKHwfx3kyRrsEopU8f9kTpcTKcHEdrp7zKJFCmKZa9K53/JZ
Y9Z8DQY7e36l7UOuVIMqzBxADZIUJsyw8AmUu2/pwjgNfAjRD11p3k9rz0cMMp0X
5Np2VfSdVSkHFsDqLw7B6AKO+3fXtzqMPD40b+vIDhrpDJNgrwMCKVlkw2J1A6VG
Ec4oSDc3gIXLzA7O/42xSAObA9hZldEqrimMCFlW+qkkWyUh9mWhiUyJyZ5MgPk2
LW80PS+3q3G7ALEnP69cNxJ3CE7nfYUNmcv8cYkJU0Y2SXXYdN75ejVEDLo6TfJT
mxZV476I23gsBnAAk+G5RYSzx/lZ0VEV/8Z0B/X1UV/Oc5bm38chLKLFxYzVr400
KzEb3m0LgwtR+N9kkMLTEkFeCFqublZ9qcJm/GP3+7BNcXaDBq950fZRKz5ET0So
QbDopxjjW8CBPTSj8f1zlRqp1mAiwHdliNjUL5xhqNjKwR5XVpntSqy5KS1QXD2e
hfjciNo1DcBMpSs+X6GqYuqybpU/El/XX7o9+Qb5Dy5zY+5MfOl2/O/4ToYWGc+/
KmpQTLFiCqXrWNRQVbvvmCpuq/dHJL2aeE9Y/JcOH+yt9YEPB7hPZyXM15AVxVfL
-----END RSA PRIVATE KEY-----
*/

	var enc_private_key = `-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,584BBCF38BE41D90AB16740EE5D2E24C
        
k5m1gaYDbX+EYPcv/+wvSsYOkBpOxFYXbzMYY8Z2d39mfQ8Y+WzOJnWWYT2tj2d8
LodWRu2PD93or3z8wI0Y5huCs6VikZLtjxKawPwm5wosXud978k3dVw+VG/M8JDh
J6dIAbcmNxaHv1UX5gmdnRcRqSGt0WHXYbXgUlSNLwhrTU9osd7A/eLZf5MZ5hTB
5CQ/Tb9jCZxSyP8YiPvOuR9gCK5L3Ooq820mwZ0oL9r18uby4ElSmFuM+nipThyu
4SinV3MIN5bOMvsb34DDbQ9wbbtvDA1V7iJRItLo9+1v5d7O876BTSwX9Qd12P0C
WqiKUAt/T/ZB/NJC3bw2v9bRL+VifvfLmOigvw7r2NAokpRHb8Elv80S5ZtcZGmp
tQ7wCkO8kz/JFX/UXqqkSSBsegtGm+CwenEvyQ5dtUUu1ETo7vOMp9c+AZyKCNgu
MDC5nhLBm1H93t1Wko45yn/Az7RVw6yzUEp6WrADajjGtLwVbLC5eDd7+9utHp/x
UB/5H+vI+nbYP5KBc/Zqe/IjSrVKFBtoD2MowVtkWg42mGgQ1VNKYhKELLFFtWxd
HuYlHVYYiOHXbMLsofMkqxxJQatS7WtKBWBgmYbqhHxNpZ11QKxzk+Wo+J9ixLbs
ADBhAak4t7eHFZtbKonP+hEGanZGK04Wz8+leo+BL+7J5d4d9WZPFH9q47kM5/Wc
qUkJIZPzwKAlb5ot/9XQmqnECip2yRhyJYcOBqfg4EXfCbDqz3YCFS8HpPOVQqMs
ZGvRA9LrZfsy6V9NCWFZbBtiYjO2gOtYASoDKyo615vdma42L8P+h2UPtk8e0ziM
OpuZiR37HsahyWAcGgomprs+hmV5yFnzIs5O5P6J0uf2TCrUR8cZBuYoPVp9pErc
l/U5m0G+ENTwzs8Dd6ySyDpKlADRnjQYPxulbT4VpT9c9kUg3sxRHWRv5C0FLVPq
M0atErcFtKIlLPsEDKHwfx3kyRrsEopU8f9kTpcTKcHEdrp7zKJFCmKZa9K53/JZ
Y9Z8DQY7e36l7UOuVIMqzBxADZIUJsyw8AmUu2/pwjgNfAjRD11p3k9rz0cMMp0X
5Np2VfSdVSkHFsDqLw7B6AKO+3fXtzqMPD40b+vIDhrpDJNgrwMCKVlkw2J1A6VG
Ec4oSDc3gIXLzA7O/42xSAObA9hZldEqrimMCFlW+qkkWyUh9mWhiUyJyZ5MgPk2
LW80PS+3q3G7ALEnP69cNxJ3CE7nfYUNmcv8cYkJU0Y2SXXYdN75ejVEDLo6TfJT
mxZV476I23gsBnAAk+G5RYSzx/lZ0VEV/8Z0B/X1UV/Oc5bm38chLKLFxYzVr400
KzEb3m0LgwtR+N9kkMLTEkFeCFqublZ9qcJm/GP3+7BNcXaDBq950fZRKz5ET0So
QbDopxjjW8CBPTSj8f1zlRqp1mAiwHdliNjUL5xhqNjKwR5XVpntSqy5KS1QXD2e
hfjciNo1DcBMpSs+X6GqYuqybpU/El/XX7o9+Qb5Dy5zY+5MfOl2/O/4ToYWGc+/
KmpQTLFiCqXrWNRQVbvvmCpuq/dHJL2aeE9Y/JcOH+yt9YEPB7hPZyXM15AVxVfL
-----END RSA PRIVATE KEY-----`;

	var password = Buffer.from("password");

	var pki = new jCastle.pki('RSA');

	pki.parsePrivateKey(enc_private_key, password);

	// 1. export public key
	var pem = pki.exportPublicKey();

	var pki1 = new jCastle.pki('RSA');
	pki1.parsePublicKey(pem);
	var privkey1 = pki.getPrivateKey();
	var pubkey2 = pki1.getPublicKey();
	assert.ok(privkey1.n.equals(pubkey2.n), 'parse public key');

	// 2. no encryption pkcs#5
	var pem3 = null;
	pem3 = pki.exportPrivateKeyPKCS5();
	var pki2 = new jCastle.pki('RSA');
	pki2.parsePrivateKey(pem3);
	var privkey2 = pki2.getPrivateKey();
	assert.ok(
		privkey1.n.equals(privkey2.n) &&
		privkey1.e == privkey2.e &&
		privkey1.d.equals(privkey2.d) &&
		privkey1.p.equals(privkey2.p) &&
		privkey1.q.equals(privkey2.q) &&
		privkey1.dmp1.equals(privkey2.dmp1) &&
		privkey1.dmq1.equals(privkey2.dmq1), "parse pkcs#5 pem with no encryption.");

	// 3. pkcs#5 encrypted with des-ede3-CBC
    // default is with aes-128-cbc.
	var pem3 = null;
	pem3 = pki.exportPrivateKeyPKCS5({password: password, algo: 'des-ede3'}); 
	var pki2 = new jCastle.pki('RSA');
	pki2.parsePrivateKey(pem3, password);
	var privkey2 = pki2.getPrivateKey();
	assert.ok(
		privkey1.n.equals(privkey2.n) &&
		privkey1.e == privkey2.e &&
		privkey1.d.equals(privkey2.d) &&
		privkey1.p.equals(privkey2.p) &&
		privkey1.q.equals(privkey2.q) &&
		privkey1.dmp1.equals(privkey2.dmp1) &&
		privkey1.dmq1.equals(privkey2.dmq1), "parse pkcs#5 pem with des-ede3-CBC encryption.");

	// pkcs#5 encrypted with camellia-256
	var pem3 = null;
	pem3 = pki.exportPrivateKeyPKCS5({password: password, algo: 'camellia-256'});
	var pki2 = new jCastle.pki('RSA');
	pki2.parsePrivateKey(pem3, password);
	var privkey2 = pki2.getPrivateKey();
	assert.ok(
		privkey1.n.equals(privkey2.n) &&
		privkey1.e == privkey2.e &&
		privkey1.d.equals(privkey2.d) &&
		privkey1.p.equals(privkey2.p) &&
		privkey1.q.equals(privkey2.q) &&
		privkey1.dmp1.equals(privkey2.dmp1) &&
		privkey1.dmq1.equals(privkey2.dmq1), "parse pkcs#5 pem with camellia-256-CBC encryption.");

	// pkcs#8 no encryption
	var pem3 = null;
	pem3 = pki.exportPrivateKey();
	var pki2 = new jCastle.pki('RSA');
	pki2.parsePrivateKey(pem3);
	var privkey2 = pki2.getPrivateKey();
	assert.ok(
		privkey1.n.equals(privkey2.n) &&
		privkey1.e == privkey2.e &&
		privkey1.d.equals(privkey2.d) &&
		privkey1.p.equals(privkey2.p) &&
		privkey1.q.equals(privkey2.q) &&
		privkey1.dmp1.equals(privkey2.dmp1) &&
		privkey1.dmq1.equals(privkey2.dmq1), "parse pkcs#8 pem with no encryption.");

	// pkcs#8 encryption pkcs5 v1.5 / default pbeWithMD5AndDES-CBC
	var pem3 = null;
	pem3 = pki.exportPrivateKey({password: password});
	var pki2 = new jCastle.pki('RSA');
	pki2.parsePrivateKey(pem3, password);
	var privkey2 = pki2.getPrivateKey();
	assert.ok(
		privkey1.n.equals(privkey2.n) &&
		privkey1.e == privkey2.e &&
		privkey1.d.equals(privkey2.d) &&
		privkey1.p.equals(privkey2.p) &&
		privkey1.q.equals(privkey2.q) &&
		privkey1.dmp1.equals(privkey2.dmp1) &&
		privkey1.dmq1.equals(privkey2.dmq1), "parse pkcs#8 pem with pbeWithMD5AndDES encryption.");

	// pkcs#8 encryption pkcs5 v1.5 / pbeWithSHAAnd40BitRC2-CBC
	var pem3 = null;
	pem3 = pki.exportPrivateKey({password: password, algo: 'pbeWithSHAAnd40BitRC2-CBC'});
	var pki2 = new jCastle.pki('RSA');
	pki2.parsePrivateKey(pem3, password);
	var privkey2 = pki2.getPrivateKey();
	assert.ok(
		privkey1.n.equals(privkey2.n) &&
		privkey1.e == privkey2.e &&
		privkey1.d.equals(privkey2.d) &&
		privkey1.p.equals(privkey2.p) &&
		privkey1.q.equals(privkey2.q) &&
		privkey1.dmp1.equals(privkey2.dmp1) &&
		privkey1.dmq1.equals(privkey2.dmq1), "parse pkcs#8 pem with pbeWithSHAAnd40BitRC2-CBC encryption.");

	// pkcs#8 encryption pkcs5 v1.5 / pbeWithSHAAnd64BitRC2-CBC
	var pem3 = null;
	pem3 = pki.exportPrivateKey({password: password, algo: 'pbeWithSHAAnd64BitRC2-CBC'});
	var pki2 = new jCastle.pki('RSA');
	pki2.parsePrivateKey(pem3, password);
	var privkey2 = pki2.getPrivateKey();
	assert.ok(
		privkey1.n.equals(privkey2.n) &&
		privkey1.e == privkey2.e &&
		privkey1.d.equals(privkey2.d) &&
		privkey1.p.equals(privkey2.p) &&
		privkey1.q.equals(privkey2.q) &&
		privkey1.dmp1.equals(privkey2.dmp1) &&
		privkey1.dmq1.equals(privkey2.dmq1), "parse pkcs#8 pem with pbeWithSHAAnd64BitRC2-CBC encryption.");

	// pkcs#8 encryption pkcs12 / pbeWithSHAAnd128BitRC4
	var pem3 = null;
	pem3 = pki.exportPrivateKey({password: password, algo: 'pbeWithSHAAnd128BitRC4'});
	var pki2 = new jCastle.pki('RSA');
	pki2.parsePrivateKey(pem3, password);
	var privkey2 = pki2.getPrivateKey();
	assert.ok(
		privkey1.n.equals(privkey2.n) &&
		privkey1.e == privkey2.e &&
		privkey1.d.equals(privkey2.d) &&
		privkey1.p.equals(privkey2.p) &&
		privkey1.q.equals(privkey2.q) &&
		privkey1.dmp1.equals(privkey2.dmp1) &&
		privkey1.dmq1.equals(privkey2.dmq1), "parse pkcs#8 pem with pbeWithSHAAnd128BitRC4 encryption.");

	// pkcs#8 encryption pkcs12 / pbeWithSHAAnd2-KeyTripleDES-CBC
	var pem3 = null;
	pem3 = pki.exportPrivateKey({password: password, algo: 'pbeWithSHAAnd2-KeyTripleDES-CBC'});
	var pki2 = new jCastle.pki('RSA');
	pki2.parsePrivateKey(pem3, password);
	var privkey2 = pki2.getPrivateKey();
	assert.ok(
		privkey1.n.equals(privkey2.n) &&
		privkey1.e == privkey2.e &&
		privkey1.d.equals(privkey2.d) &&
		privkey1.p.equals(privkey2.p) &&
		privkey1.q.equals(privkey2.q) &&
		privkey1.dmp1.equals(privkey2.dmp1) &&
		privkey1.dmq1.equals(privkey2.dmq1), "parse pkcs#8 pem with pbeWithSHAAnd2-KeyTripleDES-CBC encryption.");

	// pkcs#8 encryption pkcs12 / PBE-SHA1-SEED
	var pem3 = null;
	pem3 = pki.exportPrivateKey({password: password, algo: 'PBE-SHA1-SEED'});
	var pki2 = new jCastle.pki('RSA');
	pki2.parsePrivateKey(pem3, password);
	var privkey2 = pki2.getPrivateKey();
	assert.ok(
		privkey1.n.equals(privkey2.n) &&
		privkey1.e == privkey2.e &&
		privkey1.d.equals(privkey2.d) &&
		privkey1.p.equals(privkey2.p) &&
		privkey1.q.equals(privkey2.q) &&
		privkey1.dmp1.equals(privkey2.dmp1) &&
		privkey1.dmq1.equals(privkey2.dmq1), "parse pkcs#8 pem with PBE-SHA1-SEED encryption.");

	// pkcs#8 encryptions pkcs5 v2.0 / seed-cbc / default prf hmacWithSHA
	var pem3 = null;
	pem3 = pki.exportPrivateKey({password: password, algo: 'seed-cbc'});
	var pki2 = new jCastle.pki('RSA');
	pki2.parsePrivateKey(pem3, password);
	var privkey2 = pki2.getPrivateKey();
	assert.ok(
		privkey1.n.equals(privkey2.n) &&
		privkey1.e == privkey2.e &&
		privkey1.d.equals(privkey2.d) &&
		privkey1.p.equals(privkey2.p) &&
		privkey1.q.equals(privkey2.q) &&
		privkey1.dmp1.equals(privkey2.dmp1) &&
		privkey1.dmq1.equals(privkey2.dmq1), "parse pkcs#5 pem with seed-cbc, hmacWithSHA encryption.");

	// pkcs#8 encryptions pkcs5 v2.0 / idea-cbc / default prf hmacWithSHA384
	var pem3 = null;
	pem3 = pki.exportPrivateKey({password: password, algo: 'ideacbc', prf: 'hmacWithSHA256'});
	var pki2 = new jCastle.pki('RSA');
	pki2.parsePrivateKey(pem3, password);
	var privkey2 = pki2.getPrivateKey();
	assert.ok(
		privkey1.n.equals(privkey2.n) &&
		privkey1.e == privkey2.e &&
		privkey1.d.equals(privkey2.d) &&
		privkey1.p.equals(privkey2.p) &&
		privkey1.q.equals(privkey2.q) &&
		privkey1.dmp1.equals(privkey2.dmp1) &&
		privkey1.dmq1.equals(privkey2.dmq1), "parse pkcs#5 pem with idea-cbc, hmacWithSHA256 encryption.");
});


QUnit.test("PEM Test 2", function(assert) {

	var pem = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAHe+YHFvjkxmqH0v
UtyTSd3WH7CkGcmRtYNFZhYE4dS/hH8D50h9YlINwpQRXStRT70Jj0GmjH58t9/Y
OGXmJJJwYO4muldITFZMD4Y8cFjGOp7+PczqQf8saHLoHO0uDn2K1XEYktb9UQS8
LhMbwyzpn9o5OjThcsK3b2YuGkzQ6+CEnB2XN4qNpJqjzukrxoZwAtRRCGvo92Wt
oucTA5ThTLKsYOLNLZON3+HfKPQfdNk/5X8Df6J1qasgoLfW39JiFlsyvHIxoNL2
583DXyDxesBAcoJds6r2xEhhak/Bu7CS45JmXne0fw9yGTA4NcHenf2dsyep+Us0
ZHE1WFECAwEAAQKCAQANV+qZWWwK+XmXEZnzOHqHvN+lKHQzMQiAC1C37W1Y7sqN
+NpiCo7VQ/FF3LV8KUBweUs8bpnDUpSO3iJSwJWct+clQq2LImRXTXyBYeTHD7fi
lcQ/PG+ERueQvmrSx0oYFUt5odpjGLFZjLq5qGNUcug8QhpJYEIQjq5cPZDytEFz
PiVvtzhmmzsz+gW2jS3hlwwgoZCSPA+/5eT/ber4B2lK62GDDRO+J667Agp/E9L/
OLKShumcgNItZ8nQdzJj+Rg82XBLX44KTE5IyTM7UlLCWix0NbjObOfGSFTUv7nX
3Ef+qNz5qmJ0EFpvaD3Sj3Reetn25k6cxYgvW23tAoGBANY7pyhJM3xgJgmgkGge
pzQRwK/AuVnS4JpGUbVUTZ1DUj9Vd6+FfW8Ij0lROPfj21jXbiCaPD0cX2+RptVv
uGcq4er56dv+do/UeoFevlql7k2rw4gkIvjbwDbm2icF/cAOUXeUxI87rfE4XUIA
GVigHTrUn/7Mus5BygTZT7uTAoGBAI8WxRnivR1tpr6Vo0828aUuyh2hXK3Mb1Fz
bme5uBmoO/Z2UOVwkhLo9adC+jLY3o4bR4XkwuiGfgiGbND8k7t2IKPB+aZE1Wmd
sIFRIvP8n3q8eDCjWZOmGtFGLrZVNW6pKCclh1JIfgOkJ5O3na5yXr9jxN3DR98/
QOfsLjMLAoGActD9wYWZ5mrReA9p1aO4ERwCnS85J37xiT1uxTQtdL+D8RWpU5TD
qSJ5SN4THigsguzSxP5kkowGShFRzMpXllNRSVIvmAxFFsjV70gL1SFhGpeX7/sO
EzoTRllrScbYPHpwBxrgTbO6gbGnqZvL+ce2YrVaGoE3DRwNXZPqO6kCgYEAipZA
MtEj38PbM04VTVzm8Nj/k3E9JWwTCS2m6jm7sMX7xbtUoNTF9iDCBM1fLS5VaAfN
30Xw7WuN2E3ySPvJTlCcTl9KoBqdJN1BHg7qrqun/yVZt6oO0W2ZHcY+6gRfax3V
MQ0tIqnpuzcbyfuWcmZ9lBtaintgOj62a6qaGH8CgYEAnZXFzL8+UQp4zogUH3uY
o5K3y8/dzvuQlUQNShOqySCYZq138TB4GRapbjEtybj5H8ir1lApM1xzcJcisT+f
QClpPUxq1KitZqZPj1PtH6Yn+vP4CWq9D6a+6lt9DhH7rwqyOmcTskmIeGJWerP4
YTdgkw8sWi3fZ9kH06PUPKs=
-----END PRIVATE KEY-----`;

	var rsa = jCastle.pki.create('rsa');
	rsa.parsePrivateKey(pem);
	var pem2 = rsa.exportPrivateKey();

	assert.equal(pem2, pem, 'test for pem generation');


	var pem = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAd75gcW+OTGaofS9S3JNJ3dYfsKQZyZG1g0VmFgTh1L+EfwPn
SH1iUg3ClBFdK1FPvQmPQaaMfny339g4ZeYkknBg7ia6V0hMVkwPhjxwWMY6nv49
zOpB/yxocugc7S4OfYrVcRiS1v1RBLwuExvDLOmf2jk6NOFywrdvZi4aTNDr4ISc
HZc3io2kmqPO6SvGhnAC1FEIa+j3Za2i5xMDlOFMsqxg4s0tk43f4d8o9B902T/l
fwN/onWpqyCgt9bf0mIWWzK8cjGg0vbnzcNfIPF6wEBygl2zqvbESGFqT8G7sJLj
kmZed7R/D3IZMDg1wd6d/Z2zJ6n5SzRkcTVYUQIDAQABAoIBAA1X6plZbAr5eZcR
mfM4eoe836UodDMxCIALULftbVjuyo342mIKjtVD8UXctXwpQHB5SzxumcNSlI7e
IlLAlZy35yVCrYsiZFdNfIFh5McPt+KVxD88b4RG55C+atLHShgVS3mh2mMYsVmM
urmoY1Ry6DxCGklgQhCOrlw9kPK0QXM+JW+3OGabOzP6BbaNLeGXDCChkJI8D7/l
5P9t6vgHaUrrYYMNE74nrrsCCn8T0v84spKG6ZyA0i1nydB3MmP5GDzZcEtfjgpM
TkjJMztSUsJaLHQ1uM5s58ZIVNS/udfcR/6o3PmqYnQQWm9oPdKPdF562fbmTpzF
iC9bbe0CgYEA1junKEkzfGAmCaCQaB6nNBHAr8C5WdLgmkZRtVRNnUNSP1V3r4V9
bwiPSVE49+PbWNduIJo8PRxfb5Gm1W+4Zyrh6vnp2/52j9R6gV6+WqXuTavDiCQi
+NvANubaJwX9wA5Rd5TEjzut8ThdQgAZWKAdOtSf/sy6zkHKBNlPu5MCgYEAjxbF
GeK9HW2mvpWjTzbxpS7KHaFcrcxvUXNuZ7m4Gag79nZQ5XCSEuj1p0L6MtjejhtH
heTC6IZ+CIZs0PyTu3Ygo8H5pkTVaZ2wgVEi8/yferx4MKNZk6Ya0UYutlU1bqko
JyWHUkh+A6Qnk7edrnJev2PE3cNH3z9A5+wuMwsCgYEActD9wYWZ5mrReA9p1aO4
ERwCnS85J37xiT1uxTQtdL+D8RWpU5TDqSJ5SN4THigsguzSxP5kkowGShFRzMpX
llNRSVIvmAxFFsjV70gL1SFhGpeX7/sOEzoTRllrScbYPHpwBxrgTbO6gbGnqZvL
+ce2YrVaGoE3DRwNXZPqO6kCgYCKlkAy0SPfw9szThVNXObw2P+TcT0lbBMJLabq
ObuwxfvFu1Sg1MX2IMIEzV8tLlVoB83fRfDta43YTfJI+8lOUJxOX0qgGp0k3UEe
Duquq6f/JVm3qg7RbZkdxj7qBF9rHdUxDS0iqem7NxvJ+5ZyZn2UG1qKe2A6PrZr
qpoYfwKBgJ2Vxcy/PlEKeM6IFB97mKOSt8vP3c77kJVEDUoTqskgmGatd/EweBkW
qW4xLcm4+R/Iq9ZQKTNcc3CXIrE/n0ApaT1MatSorWamT49T7R+mJ/rz+AlqvQ+m
vupbfQ4R+68KsjpnE7JJiHhiVnqz+GE3YJMPLFot32fZB9Oj1Dyr
-----END RSA PRIVATE KEY-----`;


	var rsa = jCastle.pki.create('rsa');
	rsa.parsePrivateKey(pem);
	var pem2 = rsa.exportPrivateKeyPKCS5();
	var privkey1 = rsa.getPrivateKey();

	var rsa2 = new jCastle.pki('RSA');
	rsa2.parsePrivateKey(pem2);
	var privkey2 = rsa2.getPrivateKey();

	// this assert gets an error...
	//assert.equal(pem2, pem, 'test 2 for pem generation');

	assert.ok(
		privkey1.n.equals(privkey2.n) &&
		privkey1.e == privkey2.e &&
		privkey1.d.equals(privkey2.d) &&
		privkey1.p.equals(privkey2.p) &&
		privkey1.q.equals(privkey2.q) &&
		privkey1.dmp1.equals(privkey2.dmp1) &&
		privkey1.dmq1.equals(privkey2.dmq1), "test 2 for pem generation");


/*
pem generated by jCastle:

-----BEGIN RSA PRIVATE KEY-----
MIIEoQIBAAKCAQB3vmBxb45MZqh9L1Lck0nd1h+wpBnJkbWDRWYWBOHUv4R/A+dI
fWJSDcKUEV0rUU+9CY9Bpox+fLff2Dhl5iSScGDuJrpXSExWTA+GPHBYxjqe/j3M
6kH/LGhy6BztLg59itVxGJLW/VEEvC4TG8Ms6Z/aOTo04XLCt29mLhpM0OvghJwd
lzeKjaSao87pK8aGcALUUQhr6PdlraLnEwOU4UyyrGDizS2Tjd/h3yj0H3TZP+V/
A3+idamrIKC31t/SYhZbMrxyMaDS9ufNw18g8XrAQHKCXbOq9sRIYWpPwbuwkuOS
Zl53tH8PchkwODXB3p39nbMnqflLNGRxNVhRAgMBAAECggEADVfqmVlsCvl5lxGZ
8zh6h7zfpSh0MzEIgAtQt+1tWO7KjfjaYgqO1UPxRdy1fClAcHlLPG6Zw1KUjt4i
UsCVnLfnJUKtiyJkV018gWHkxw+34pXEPzxvhEbnkL5q0sdKGBVLeaHaYxixWYy6
uahjVHLoPEIaSWBCEI6uXD2Q8rRBcz4lb7c4Zps7M/oFto0t4ZcMIKGQkjwPv+Xk
/23q+AdpSuthgw0TvieuuwIKfxPS/ziykobpnIDSLWfJ0HcyY/kYPNlwS1+OCkxO
SMkzO1JSwlosdDW4zmznxkhU1L+519xH/qjc+apidBBab2g90o90XnrZ9uZOnMWI
L1tt7QKBgQDWO6coSTN8YCYJoJBoHqc0EcCvwLlZ0uCaRlG1VE2dQ1I/VXevhX1v
CI9JUTj349tY124gmjw9HF9vkabVb7hnKuHq+enb/naP1HqBXr5ape5Nq8OIJCL4
28A25tonBf3ADlF3lMSPO63xOF1CABlYoB061J/+zLrOQcoE2U+7kwKBgQCPFsUZ
4r0dbaa+laNPNvGlLsodoVytzG9Rc25nubgZqDv2dlDlcJIS6PWnQvoy2N6OG0eF
5MLohn4IhmzQ/JO7diCjwfmmRNVpnbCBUSLz/J96vHgwo1mTphrRRi62VTVuqSgn
JYdSSH4DpCeTt52ucl6/Y8Tdw0ffP0Dn7C4zCwKBgHLQ/cGFmeZq0XgPadWjuBEc
Ap0vOSd+8Yk9bsU0LXS/g/EVqVOUw6kieUjeEx4oLILs0sT+ZJKMBkoRUczKV5ZT
UUlSL5gMRRbI1e9IC9UhYRqXl+/7DhM6E0ZZa0nG2Dx6cAca4E2zuoGxp6mby/nH
tmK1WhqBNw0cDV2T6jupAoGAipZAMtEj38PbM04VTVzm8Nj/k3E9JWwTCS2m6jm7
sMX7xbtUoNTF9iDCBM1fLS5VaAfN30Xw7WuN2E3ySPvJTlCcTl9KoBqdJN1BHg7q
rqun/yVZt6oO0W2ZHcY+6gRfax3VMQ0tIqnpuzcbyfuWcmZ9lBtaintgOj62a6qa
GH8CgYCdlcXMvz5RCnjOiBQfe5ijkrfLz93O+5CVRA1KE6rJIJhmrXfxMHgZFqlu
MS3JuPkfyKvWUCkzXHNwlyKxP59AKWk9TGrUqK1mpk+PU+0fpif68/gJar0Ppr7q
W30OEfuvCrI6ZxOySYh4YlZ6s/hhN2CTDyxaLd9n2QfTo9Q8qw==
-----END RSA PRIVATE KEY-----

all values of rsa are the same.
the difference comes from openssl's treats of integers.
'0x00' value is added to some integers when it seems no adding is needed.
for example:
00 72 D0 FD C1 85 99 E6  6A D1 78 0F 69 D5 A3 B8
11 1C 02 9D 2F 39 27 7E  F1 89 3D 6E C5 34 2D 74
BF 83 F1 15 A9 53 94 C3  A9 22 79 48 DE 13 1E 28
2C 82 EC D2 C4 FE 64 92  8C 06 4A 11 51 CC CA 57
96 53 51 49 52 2F 98 0C  45 16 C8 D5 EF 48 0B D5
21 61 1A 97 97 EF FB 0E  13 3A 13 46 59 6B 49 C6
D8 3C 7A 70 07 1A E0 4D  B3 BA 81 B1 A7 A9 9B CB
F9 C7 B6 62 B5 5A 1A 81  37 0D 1C 0D 5D 93 EA 3B
A9 

this value needs no '00' adding for it starts '72'. it is positive value.
but openssl added '00' to the value.

*/

	var pem = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAtd8As85sOUjjkjV12ujMIZmhyegXkcmGaTWk319vQB3+cpIh
Wu0mBke8R28jRym9kLQj2RjaO1AdSxsLy4hR2HynY7l6BSbIUrAam/aC/eVzJmg7
qjVijPKRTj7bdG5dYNZYSEiL98t/+XVxoJcXXOEY83c5WcCnyoFv58MG4TGeHi/0
coXKpdGlAqtQUqbp2sG7WCrXIGJJdBvUDIQDQQ0Isn6MK4nKBA10ucJmV+ok7DEP
kyGk03KgAx+Vien9ELvo7P0AN75Nm1W9FiP6gfoNvUXDApKF7du1FTn4r3peLzzj
50y5GcifWYfoRYi7OPhxI4cFYOWleFm1pIS4PwIDAQABAoIBAQCBleuCMkqaZnz/
6GeZGtaX+kd0/ZINpnHG9RoMrosuPDDYoZZymxbE0sgsfdu9ENipCjGgtjyIloTI
xvSYiQEIJ4l9XOK8WO3TPPc4uWSMU7jAXPRmSrN1ikBOaCslwp12KkOs/UP9w1nj
/PKBYiabXyfQEdsjQEpN1/xMPoHgYa5bWHm5tw7aFn6bnUSm1ZPzMquvZEkdXoZx
c5h5P20BvcVz+OJkCLH3SRR6AF7TZYmBEsBB0XvVysOkrIvdudccVqUDrpjzUBc3
L8ktW3FzE+teP7vxi6x/nFuFh6kiCDyoLBhRlBJI/c/PzgTYwWhD/RRxkLuevzH7
TU8JFQ9BAoGBAOIrQKwiAHNw4wnmiinGTu8IW2k32LgI900oYu3ty8jLGL6q1IhE
qjVMjlbJhae58mAMx1Qr8IuHTPSmwedNjPCaVyvjs5QbrZyCVVjx2BAT+wd8pl10
NBXSFQTMbg6rVggKI3tHSE1NSdO8kLjITUiAAjxnnJwIEgPK+ljgmGETAoGBAM3c
ANd/1unn7oOtlfGAUHb642kNgXxH7U+gW3hytWMcYXTeqnZ56a3kNxTMjdVyThlO
qGXmBR845q5j3VlFJc4EubpkXEGDTTPBSmv21YyU0zf5xlSp6fYe+Ru5+hqlRO4n
rsluyMvztDXOiYO/VgVEUEnLGydBb1LwLB+MVR2lAoGAdH7s7/0PmGbUOzxJfF0O
OWdnllnSwnCz2UVtN7rd1c5vL37UvGAKACwvwRpKQuuvobPTVFLRszz88aOXiynR
5/jH3+6IiEh9c3lattbTgOyZx/B3zPlW/spYU0FtixbL2JZIUm6UGmUuGucs8FEU
Jbzx6eVAsMojZVq++tqtAosCgYB0KWHcOIoYQUTozuneda5yBQ6P+AwKCjhSB0W2
SNwryhcAMKl140NGWZHvTaH3QOHrC+SgY1Sekqgw3a9IsWkswKPhFsKsQSAuRTLu
i0Fja5NocaxFl/+qXz3oNGB56qpjzManabkqxSD6f8o/KpeqryqzCUYQN69O2LG9
N53L9QKBgQCZd0K6RFhhdJW+Eh7/aIk8m8Cho4Im5vFOFrn99e4HKYF5BJnoQp4p
1QTLMs2C3hQXdJ49LTLp0xr77zPxNWUpoN4XBwqDWL0t0MYkRZFoCAG7Jy2Pgegv
uOuIr6NHfdgGBgOTeucG+mPtADsLYurEQuUlfkl5hR7LgwF+3q8bHQ==
-----END RSA PRIVATE KEY-----`;

	var rsa = jCastle.pki.create('rsa');
	rsa.parsePrivateKey(pem);
	var pem2 = rsa.exportPrivateKeyPKCS5();

	assert.equal(pem2, pem, 'test 3 for pem generation');

});


QUnit.test("PKCS12_PKDF test", function(assert) {
/*
peb-sha1-128bit-rc4

-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIE4zAcBgoqhkiG9w0BDAEBMA4ECOCgJGowufD5AgIIAASCBMFVaN1aJ7DdpEAN
6gJ0fH5s0OWtdnLTBpRmE0OqjgLTZKOJygZsXU+P0UdRXdlF3slgZd28aSk2YgFc
qfZvhxOHLpMOfBttBXQz+3s32pm7HYjCbF9wJrU5qCj2/x9dx+fQmVGknn7ED76Z
HkuhxpUfSP5oS/HFKJNJTZUoY6YI5C1hjR8ckXZDZR7uizsxA2yNiAiCmn0jqWJZ
+K5gjWUgnzoNh99Q8cLPdonp/3f29Lr5wKSVIGhK+rY7fRAHyrfIF5haJM5O2DuA
3qNXYozguwzIJkkH0M5r1nTTPteuYrc+KneiLLLdrhSfzNNyvXMoyXmYtGdgPz2m
EZSxZhad0CMKUT9GuPl9VmwimvdYw1FJU8so9nxZzrXT089yEYSB/5agPbSC1KPd
jkM3Ow+D0qHkKTocWV4rWlR+pGFX0MpK1Kp63tfCdo7PSFgNB5KNEsu54qijUU6W
HEoFjW+7hn6YSAXCaqdqf+zNEaiXLenmyOqWon+hgN3xMW6JrZ0QEC6qNCOn+0zN
3PaD6hpJZ52BhAp9fVLK4X1p8HRu4eNZ5tifW3tIlRxQ70dEr1q1IUIUwtxJ5Lye
jcZSwuXge/MRCUinbgIyIyRg+6ol6EFeF5qKtTH/h+0NuZH7IPgMdV99swg1xe++
k2kPWvVzS4vx/9zUvMJSV/WsP9YxY7E97HUPsU1rm+uDF00Sd0woJqGpj3RRv45C
QXfmODLheMKauRHrPmZSeMPjPIdv5YxJ6qwhv40d0eFZy5R+UvmxzEFTLtmUt7V/
4S+xNnHm9rdztkk5KUABmMWXERJ6RfFxSAnm2lyDi9es/sHIEd5h3zTHvYRgeWo7
v0H7ZtvfJMuakHCV7f0yNWy4ZQ479hN4Fp0Ga64vM84tTANs884cJSaX5YbHZXki
1ux4yGptOAPd3wkkvwLNon0rO4POOcXb8leCglH7WG47D70XOTxQfLe6cgkweaUn
K3BFuQ4OKVpo+oN3NnRBeQQHIEVwKyZX3ADgDwf1b0KG1j2iFZh9TIhMKCmYkJ7p
vRTEFAYGxl5Idm3Nyn4jsZOMZgUvKaGb7/k0/Sl6sdLI7TymPke/FPMYomnWdVo2
964inCjLsr5U3fRloMNjr87BTPazW+wcOdhkredLZTCV4EfdC7jHoqL3i6b2gf66
jmro5bsC9/2r72QxmPy2rD0WsJbQpk942TjdHv1Q73N7rC0E2EO/5Fpc7oFoiUnS
dWCERbh575zeZwlNOsg732uIo2COKDF5e2fJejIMByKW9e7pgd46TSmDgZu8My2W
8we1JTfElUy2Ar9dB2W5zP1P/RzBWoEHvxOOs4qN2u7fRBeo5pbDxrE1G98jY29p
xyXmivA4L9QllyG0amI4iLNDFm0DTaz7vi9pRR6HiuKZCk6jZJMtX4MT06lbgC09
NMZNkt3f26OITgbHAQnU6C9gShfdOJc24YyV8TCx4L+W1QGjBruAlN2za0h/cGi8
8mpEgyHQTMWmFg6fT3Z3DqQU+o6Q7+zRo+ndojtpCSEiFjmaqWjEXbAd+xeQowrU
bHLHVUxTJ8h/jVU+M1GFQga1RqMD8U2cgj+z0IpNbMKVMZDx5g4HoLi1IDFPUKGX
v9x/oZhvKg==
-----END ENCRYPTED PRIVATE KEY-----
*/

	var private_pem = "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"+
	"MIIE4zAcBgoqhkiG9w0BDAEBMA4ECOCgJGowufD5AgIIAASCBMFVaN1aJ7DdpEAN\n"+
	"6gJ0fH5s0OWtdnLTBpRmE0OqjgLTZKOJygZsXU+P0UdRXdlF3slgZd28aSk2YgFc\n"+
	"qfZvhxOHLpMOfBttBXQz+3s32pm7HYjCbF9wJrU5qCj2/x9dx+fQmVGknn7ED76Z\n"+
	"HkuhxpUfSP5oS/HFKJNJTZUoY6YI5C1hjR8ckXZDZR7uizsxA2yNiAiCmn0jqWJZ\n"+
	"+K5gjWUgnzoNh99Q8cLPdonp/3f29Lr5wKSVIGhK+rY7fRAHyrfIF5haJM5O2DuA\n"+
	"3qNXYozguwzIJkkH0M5r1nTTPteuYrc+KneiLLLdrhSfzNNyvXMoyXmYtGdgPz2m\n"+
	"EZSxZhad0CMKUT9GuPl9VmwimvdYw1FJU8so9nxZzrXT089yEYSB/5agPbSC1KPd\n"+
	"jkM3Ow+D0qHkKTocWV4rWlR+pGFX0MpK1Kp63tfCdo7PSFgNB5KNEsu54qijUU6W\n"+
	"HEoFjW+7hn6YSAXCaqdqf+zNEaiXLenmyOqWon+hgN3xMW6JrZ0QEC6qNCOn+0zN\n"+
	"3PaD6hpJZ52BhAp9fVLK4X1p8HRu4eNZ5tifW3tIlRxQ70dEr1q1IUIUwtxJ5Lye\n"+
	"jcZSwuXge/MRCUinbgIyIyRg+6ol6EFeF5qKtTH/h+0NuZH7IPgMdV99swg1xe++\n"+
	"k2kPWvVzS4vx/9zUvMJSV/WsP9YxY7E97HUPsU1rm+uDF00Sd0woJqGpj3RRv45C\n"+
	"QXfmODLheMKauRHrPmZSeMPjPIdv5YxJ6qwhv40d0eFZy5R+UvmxzEFTLtmUt7V/\n"+
	"4S+xNnHm9rdztkk5KUABmMWXERJ6RfFxSAnm2lyDi9es/sHIEd5h3zTHvYRgeWo7\n"+
	"v0H7ZtvfJMuakHCV7f0yNWy4ZQ479hN4Fp0Ga64vM84tTANs884cJSaX5YbHZXki\n"+
	"1ux4yGptOAPd3wkkvwLNon0rO4POOcXb8leCglH7WG47D70XOTxQfLe6cgkweaUn\n"+
	"K3BFuQ4OKVpo+oN3NnRBeQQHIEVwKyZX3ADgDwf1b0KG1j2iFZh9TIhMKCmYkJ7p\n"+
	"vRTEFAYGxl5Idm3Nyn4jsZOMZgUvKaGb7/k0/Sl6sdLI7TymPke/FPMYomnWdVo2\n"+
	"964inCjLsr5U3fRloMNjr87BTPazW+wcOdhkredLZTCV4EfdC7jHoqL3i6b2gf66\n"+
	"jmro5bsC9/2r72QxmPy2rD0WsJbQpk942TjdHv1Q73N7rC0E2EO/5Fpc7oFoiUnS\n"+
	"dWCERbh575zeZwlNOsg732uIo2COKDF5e2fJejIMByKW9e7pgd46TSmDgZu8My2W\n"+
	"8we1JTfElUy2Ar9dB2W5zP1P/RzBWoEHvxOOs4qN2u7fRBeo5pbDxrE1G98jY29p\n"+
	"xyXmivA4L9QllyG0amI4iLNDFm0DTaz7vi9pRR6HiuKZCk6jZJMtX4MT06lbgC09\n"+
	"NMZNkt3f26OITgbHAQnU6C9gShfdOJc24YyV8TCx4L+W1QGjBruAlN2za0h/cGi8\n"+
	"8mpEgyHQTMWmFg6fT3Z3DqQU+o6Q7+zRo+ndojtpCSEiFjmaqWjEXbAd+xeQowrU\n"+
	"bHLHVUxTJ8h/jVU+M1GFQga1RqMD8U2cgj+z0IpNbMKVMZDx5g4HoLi1IDFPUKGX\n"+
	"v9x/oZhvKg==\n"+
	"-----END ENCRYPTED PRIVATE KEY-----";

	var pkey = new jCastle.pki('RSA');

	pkey.parse(private_pem, "password");

	var keyInfo = pkey.getPrivateKeyInfo();

	assert.ok(keyInfo.privateKey.n.equals(keyInfo.privateKey.p.multiply(keyInfo.privateKey.q)), "parsing test");
});

QUnit.test('Keypair Generation Test', function(assert) {
	var seed =  'a8987e4accbc0d1e 7ae51aabdc9ba996 1a111f7384eab1e5' +
				'80f1f7cf562b74eb 967a0340837b72e5 8c3c123ca9d99177';
	seed = seed.replace(/[ ]/g, '');
	seed = Buffer.from(seed, 'hex');

	var pkey = new jCastle.pki('rsa');

	pkey.generateKeypair({
		bits: 2048,
		seed: seed,
		hashAlgo: 'sha-1' // important!
	});


	var n = 
		'80769aa7af19aec2 e5d5f7b480d59187 c2583e37a905af26 8e2ddc7787dfa2a1' +
		'98e2a8166ceb61e3 f4ee18f0e187c00e 73826499198b2721 22a95ee41129c990' +
		'7c398c9f2971311d 798702930c84bb55 7c0c5bda182d6b90 bd2dd26abbbe73fc' +
		'949f639eccd53bb9 73385336d9c11aaf 22fa9c1c2715beb0 eabe2c84f571296a' +
		'12cb345a5e9017ff 5177bcf0cdbace5b b7444ccb9196c027 4030d4e9938d8bb5' +
		'06f78863e8200d8f 00a5ab1c2347023e dc53ee518e7feb40 35f04abd6fb5a13f' +
		'ba25157ff6841676 e79e2c03805c54af b9aebc002f81cf6c 37a857b9e5d5c617' +
		'd90bf6e4f14bd517 34043391b75b4b6a f31e52824efca9fc bdbee0054058d613';
	n = n.replace(/[ ]/g, '');
	n = Buffer.from(n, 'hex');

	n = BigInteger.fromByteArrayUnsigned(n);

	// same seed makes same keypair.
	// console.log('pkey.n: ', pkey.getPublicKeyInfo().publicKey.n.toString(16));
	// console.log('n: ', n.toString(16));
	assert.ok(n.equals(pkey.getPublicKeyInfo().publicKey.n), "Key Generation Test");
});

QUnit.test('FIPS 186-4 Sign/Verify Test', function(assert) {
	// https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/digital-signatures#rsavs
	// SigGen15_186-3.txt

	// # CAVS 11.4
	// # "SigGen PKCS#1 Ver1.5" information 
	// # Combinations selected:Mod Size 2048 with SHA-224 SHA-256 SHA-384 SHA-512; Mod Size 3072 with SHA-224 SHA-256 SHA-384 SHA-512

	var testVectors = [
		{
			bits: 2048,
			n: `cea80475324c1dc8347827818da58bac069d3419c614a6ea1ac6a3b510dcd72cc516954905e9fef908d45e13006adf27d467a7d83c111d1a5df15ef293771aefb920032a5bb989f8e4f5e1b05093d3f130f984c07a772a3683f4dc6fb28a96815b32123ccdd13954f19d5b8b24a103e771a34c328755c65ed64e1924ffd04d30b2142cc262f6e0048fef6dbc652f21479ea1c4b1d66d28f4d46ef7185e390cbfa2e02380582f3188bb94ebbf05d31487a09aff01fcbb4cd4bfd1f0a833b38c11813c84360bb53c7d4481031c40bad8713bb6b835cb08098ed15ba31ee4ba728a8c8e10f7294e1b4163b7aee57277bfd881a6f9d43e02c6925aa3a043fb7fb78d`,

			e: `00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000260445`,
			d: `0997634c477c1a039d44c810b2aaa3c7862b0b88d3708272e1e15f66fc9389709f8a11f3ea6a5af7effa2d01c189c50f0d5bcbe3fa272e56cfc4a4e1d388a9dcd65df8628902556c8b6bb6a641709b5a35dd2622c73d4640bfa1359d0e76e1f219f8e33eb9bd0b59ec198eb2fccaae0346bd8b401e12e3c67cb629569c185a2e0f35a2f741644c1cca5ebb139d77a89a2953fc5e30048c0e619f07c8d21d1e56b8af07193d0fdf3f49cd49f2ef3138b5138862f1470bd2d16e34a2b9e7777a6c8c8d4cb94b4e8b5d616cd5393753e7b0f31cc7da559ba8e98d888914e334773baf498ad88d9631eb5fe32e53a4145bf0ba548bf2b0a50c63f67b14e398a34b0d`,
			sigVectors: [
				{
				hashAlgo: 'sha-224',
				Msg: `74230447bcd492f2f8a8c594a04379271690bf0c8a13ddfc1b7b96413e77ab2664cba1acd7a3c57ee5276e27414f8283a6f93b73bd392bd541f07eb461a080bb667e5ff095c9319f575b3893977e658c6c001ceef88a37b7902d4db31c3e34f3c164c47bbeefde3b946bad416a752c2cafcee9e401ae08884e5b8aa839f9d0b5`,
				S: `27da4104eace1991e08bd8e7cfccd97ec48b896a0e156ce7bdc23fd570aaa9a00ed015101f0c6261c7371ceca327a73c3cecfcf6b2d9ed920c9698046e25c89adb2360887d99983bf632f9e6eb0e5df60715902b9aeaa74bf5027aa246510891c74ae366a16f397e2c8ccdc8bd56aa10e0d01585e69f8c4856e76b53acfd3d782b8171529008fa5eff030f46956704a3f5d9167348f37021fc277c6c0a8f93b8a23cfbf918990f982a56d0ed2aa08161560755adc0ce2c3e2ab2929f79bfc0b24ff3e0ff352e6445d8a617f1785d66c32295bb365d61cfb107e9993bbd93421f2d344a86e4127827fa0d0b2535f9b1d547de12ba2868acdecf2cb5f92a6a159a`,

				},
				{
				hashAlgo: 'sha-224',
				Msg: `9af2c5a919e5dadc668799f365fc23da6231437ea51ca5314645425043851f23d00d3704eeabb5c43f49674a19b7707dd9aa3d657a04ba8c6655c5ab8ba2e382b26631080cd79ec40e6a587b7f99840bd0e43297ab1690e4cec95d031a2ca131e7049cfb9bf1fca67bf353cdc12cc74ceee80c5d61da8f0129a8f4a218abc3f6`,
				S: `c5dfbefd35cec846e2c7b2434dc9c46a5a9b1b6ce65b2b18665aedb1404de1f466e024f849eec308c2d2f2f0193df1898a581c9ea32581185553b171b6507082617c5c018afe0c3af64d2ec5a563795aa585e77753cd18836f6f0c29535f6200ca899928fe78e949b0a216ec47a6adf2223e17236cfc167cf00ed6136f03cf6ffd4f3f7787aeb005840978d8d6ba593d4f4cfe6920be102b9847d10140dff86b0db14ffccc9a96e673c672c1128ae45489d2cbfe6e195ca5206eda519cad3d6e0abf4653e36b5a264e87494a4d63ee91ff7c35a6ab12adfa3bb537f6198b06f5de0717076b0ec83ae0da9ea419cc0c96669d1d7c9e529271428401e09e04888a`,

				},
				{
				hashAlgo: 'sha-224',
				Msg: `59b5b85b9dc246d30a3fc8a2de3c9dfa971643b0c1f7c9e40c9c87e4a15b0c4eb664587560474c06a9b65eece38c91703c0fa5a592728a03889f1b52d93309caecc91578a97b83e38ca6cbf0f7ee9103cd82d7673ca172f0da5ebadef4a08605226c582b1f67d4b2d8967777c36985f972f843be688c67f22b61cd529baa6b48`,
				S: `29b5ac417226444bc8570a279e0e561a4c39707bdbea936064ed603ba96889eb3d786b1999b5180cd5d0611788837a9df1496bacea31cbf8f24a1a2232d4158913c963f5066aad4b65e617d0903359696d759d84c1392e22c246d5f5bed4b806f4091d5e8f71a513f1319bb4e56971cd3e168c9a7e2789832293991a73d3027072ecee6863514549029fb3553478c8f4103bf62d7de1fb53fe76ce9778ada3bb9efa62da44cd00d02bb0eb7488ac24da3814c653cba612301373837a0c3f11885493cbf3024c3572eaed396d0ebb8039ddf843c218d8bc7783549046c33586fb3428562cb8046090040c0e4eea50a19a428bde34626277ff48a84faa189b5440`,

				},
				{
				hashAlgo: 'sha-224',
				Msg: `49a5f3930ad45aca5e22caac6646f0bede1228838d49f8f2e0b2dd27d26a4b590e7eef0c58b9378829bb1489994bff3882ef3a5ae3b958c88263ff1fd69fedb823a839dbe71ddb2f750f6f75e05936761a2f5e3a5dfa837bca63755951ae3c50d04a59667fa64fa98b4662d801159f61eefd1c8bc5b581f500dac73f0a424007`,
				S: `604eb637ca54bea5ad1fd3165911f3baa2e06c859dc73945a38bca7ff9bfa9ed39435348623d3e60f1ce487443840c6b2c000f1582e8526067a5e8923f1a1bdaabb1a40c0f49ee6906a4c8fc9b8cfa6d07c2cc5bdf2ada65c53d79548089c524fa364319a90d46213febdce6db795914cbda04d7bbbf26bbb299fc7d1449dcc81d139e3c33d4c1de96473994730a4b639633d677db25695ffd157e591bddead03dd2f1c1b8f5c8a213b785879bf7c9a992bb11dd5e91df3aff0931ca76c406230a19e307f33419c9d9d3f6f64bf8881c0ddf74a5716cbc433329368d6e55f1f751d7b9f9b0a26eb5811772f5f698530efc1eaceee6e1dc6839b2133c2fccfa8c`,

				},
				{
				hashAlgo: 'sha-224',
				Msg: `9bfc4dac8c2232387216a532ce62d98c1aafa35c65dc388e3d4d37d6d186eae957f8c9edac1a3f2e3abcb1121f99bd4f8c2bbf5b6ac39a2544d8b502619f43ea30ddc8e4eafad8bf7256220380e0ae27fee46304b224cc8a1e2b1cb2a4de6fb3ee5452798de78653e08b01ec385f367c3982963f8428572793ed74cee369f5ae`,
				S: `444f7efbfef586fad431e17fea1a2d59f19b3d619bb6fa3664301833a4db1243459e31aa6a703b22572f0912754e56f7231a55ac7abca514c79d9fb3564214b4af835d7d1eaf2b58ceb6a344f1c36890f5e83b50188c0147d6d1156da289ccf4bdb0b9a66f1e4a1f2643591d5ffb53702cf70ddf351592575488f1929010aca37714b234eeb5b952b9323ae26533e9ecd516df26392d1254228bd9ca21a369bb6ab0a33d5eb44cee92b0ea7471ffe5fa43c21de2a8975d4c5c8e185fcb7aab33d88a8365ddf0119c108803c56288643a056e781abd4a0242a92e2529d405efcfd4248662cfbb332d6e6fad6aceb90b5b58a5541abe07bef25d9d89215e398426`,

				},
				{
				hashAlgo: 'sha-224',
				Msg: `bf5ff1968a39f809de73e6a8014fc6e8df159367f46340da6cc5fb468985b37446c5d89f3aca626fbe9b142b52cb022a3d93518a74243e25bd3a61c114f533874ee5cfb7fc63f599922854b7c9180949415f63f16bbfe9a8a6289ef8a88a836d20e75e4699acba6fa2412fb42cdfe32f33a25102a1df494c6fb738550decaa0c`,
				S: `017e053d1ef85c43193a0009a903952aaf400fbcfee9c028975777ab540d2d22ab5c25f4cf1d3794afac6697e1f243829052a84e2843cc0e254dbac1021572999f2dcafab58b9dfef2fcaf701e431bdcd16dbef110095bcfba501059d7994dad5b0b54d0812a4380a1f0ba8ec2bcba768bf5b544695626a5f395e784d4b2962fb7533818de1d6ec686edc9f66868ad03ee64361a6cb91fd8ef536ca6454d16c537c07aa42923e62057df9dd9e7fa4ad0384f35721f6eb3b816d352a095c605d5c10e0a7a2e8640e27307cd44b9d71ac50c0043caca28ae8d6f8fa5bb483158a4e415ef6cfad47f34c0042a2d588ace0f1371d93865397bd21516da2cc15e909c`,

				},
				{
				hashAlgo: 'sha-224',
				Msg: `2ff4fcd0be260bf4a0d73112d0e5649c0bef5bbcdf15423a05ffb2a1f021e09da63d15a8cf295ee50bd2844c89813e08d65da61df232ea4ea970443e20772cd5af11cce5ee40b40e133bcfdf7bb3953d865a8309a8a6c8fdbdd242d79d27a8baf17909d145f475355e19fa11cd03d204c4efdac629fb460fe92e93b48fb9be13`,
				S: `abee5c868f850c17794f021ee9709cc2301320dd246fb3eadb7802a300a98a67083a2e4e250df13314c25453b898110801f7e7acb9b694644e5c4a2623dff1884913c05e636fe77ed5155d954ee38f1262c6c2e38d1114cf6cc5143c7277c8649f5a423f83dfd5f829d9dc74aa4b2fcdc8960cde5ce146b289136064b13bd0d36a1e64a261d680fb7e23d2ae92efb743c3db54609eca7a1be0e47e6f724dc5cf61cb2a369c2bb173f2c6cfecb9a887d583d277b8e30b24ec8549c4d53ba3988642a61f1f939f0f3898005c5d13aaaa54bcb8ae83b72b3cb644b9439d1d2accc800271d23e52f98480d270fad6aced512252ee98332af903563d982d8cbdefb7d`,

				},
				{
				hashAlgo: 'sha-224',
				Msg: `b5dca1532dffda0831cb2d21ebd1bdca23c9319c6427fdcc5aefe3a27fc9b92df7586c36b7c84572eda66bfb9cf5aa01877e72bd516723a7e20787e90df9a0136f6fa5109ac9475973673868d8bbee7086a2a54b3af4a3b41759bfb6485f2464e6ca53cb1c2c672589b59d50e54b137ee8ddd02d67f5055ac18d92f17924cc89`,
				S: `9ae5b9633f9adc7ff923d8875748bc6220dd8f6781b3d46d6008ae69fda072d205f87a12d54c3c7ecc85b88b6ef4770eeb4b71debeff8401e329f6b3e8dc8a9af13a533b60b962930bc0ce3d65d0b5a276e85a0c74f459fb072992991ba96849023478ab28d381aa67d22c9c3b092a023f06c96e11fd2f1b4d9daf0f3449de1797612a8113d6e626cc3f995e1c110e65d17c636c92929f913639a97cd049155830dc0f76049123be3d3d79159fc2b4258e94b8bf808d7c46beefe6df0a83037d15a72a581d8adedd8f013b38f5502d736d1d2f04b0e5dc22eb1a414e52b1a9e8735e0592288c9e5a0a78531e95974a5d48860f8e5b04ebd3eb56ad12adc46ec7`,

				},
				{
				hashAlgo: 'sha-224',
				Msg: `1e563fc3ad027a9cc606be19b258bf70dd8b5273e296236ee8d7a65331585014f05006515bedd6330250e5985fdaa870aea65766ff569fc48913989041cff6fbabcd83fdf064cd3932001b261c69a670bd48069c96e7ebecf1380d82751966c7f8d69e0e94efc775fd1c4a0c118f213ab179475cd0cf6daec94eef6ff6bd0640`,
				S: `80d3ff1f74a81095d0baa2e9de248c0312ca5a817bc9f5156a293d80896adec5507ee8f2df417afe8779668e25b46f49e4357a7170531ed30761103dbb994135b510d91db9fe1f1268f437e0f3a7a4ba6a4d0b9eb70dfc09fed4b44b35608501c2dfd7a230a28dad14926da4600ba785e496212e57738dd575b40c23347b1635ecdf2b9194d96b1450a6876aa76d04aa5947cce71d85121e0bf578e81cf78c6a047e30fc1d87cfd3019de4bb48294c25860b450355bc2662aa36d6e33f00ad79257d2d8b91f73f27c32a9afcb1e1f015f77cb6b0df51fb39ee1bd76ac42c20791d79cf3f363fb324db30ee82bcc1df1a9564330c12a549659bd3010001573133`,

				},
				{
				hashAlgo: 'sha-224',
				Msg: `900ae7e2e7e5f615750c4ee4c13cca8f9f450714a6b273f2e4aca632d11cf6a8821045771f601ed39791010b92f9fac6a824788cd0775d891b13528ea2fd5d59bc7bb51675c1d5263ccccf1edc8fe313ae4d50150c466af90895ed5c5e5991e4a813dec9d14f4294cc8761278644acfe198635b44266c1c915fa1fa2ef79b9d1`,
				S: `39c64891d9ac4741a57dd8aec7f7243613d155df4492814b40ceabee79eadb8d8bc5fa611bdebe0e0d9714c43d6d29ef309f782bc8e68a4d317ce1ece468552305a73db9d0d2891e2804f4201b1bf8a3246fa082adde1fc9b3d299f88cb93b7b47fe9f73137096c2b8c59ec0612a085363c04cc374769a964feaf1f8e491381e16d7ae2a0c672e69a3667310feed012156dca630a68d339ec80496c6b594fed17091d3a1c6ac3e4da1419b05d589cb32468288f7df4daaceff5a39bcf297dc508ce9549f602e973edbc2aa44332ec3661b19c8c58c5616924beb892f77b5e200d6fb3fc759263a749d157eff9f736798d281b25b71fb470bdb700f211f841db7`,

				},
				{
				hashAlgo: 'sha-256',
				Msg: `5af283b1b76ab2a695d794c23b35ca7371fc779e92ebf589e304c7f923d8cf976304c19818fcd89d6f07c8d8e08bf371068bdf28ae6ee83b2e02328af8c0e2f96e528e16f852f1fc5455e4772e288a68f159ca6bdcf902b858a1f94789b3163823e2d0717ff56689eec7d0e54d93f520d96e1eb04515abc70ae90578ff38d31b`,
				S: `6b8be97d9e518a2ede746ff4a7d91a84a1fc665b52f154a927650db6e7348c69f8c8881f7bcf9b1a6d3366eed30c3aed4e93c203c43f5528a45de791895747ade9c5fa5eee81427edee02082147aa311712a6ad5fb1732e93b3d6cd23ffd46a0b3caf62a8b69957cc68ae39f9993c1a779599cdda949bdaababb77f248fcfeaa44059be5459fb9b899278e929528ee130facd53372ecbc42f3e8de2998425860406440f248d817432de687112e504d734028e6c5620fa282ca07647006cf0a2ff83e19a916554cc61810c2e855305db4e5cf893a6a96767365794556ff033359084d7e38a8456e68e21155b76151314a29875feee09557161cbc654541e89e42`,

				},
				{
				hashAlgo: 'sha-256',
				Msg: `c43011f3ee88c9c9adcac8bf37221afa31769d347dec705e53aca98993e74606591867ccd289ba1b4f19365f983e0c578346da76c5e2228a07e4fc9b3d4807163371a52b68b66873201dc7d6b56616ac2e4cb522120787df7f15a5e8763a54c179c635d65816bc19485de3eb35a52040591094fe0e6485a7e0c60e38e7c61551`,
				S: `aa3a4e12eb87596c711c9a22bcabcb9dadffcabcecbd16228889e9bb457d5d22571a72f034be4783384f43ce6fffc60534b8331cdd5d7c77f49180bfd194b5fd43a508c66d786c558876735894e6a9300952de792f747045e74d87fd50980230707a34a4df013ce050bbff0d6f570885c9c7bf8dc499132caee071b41d81ff91b8ce21aa2f282cbf52389f239afe1490890be21f9d808b3d70b97efd59c0b60e466088bb42714f212bc90db7e942ebcee60e7b107fff44fb3564ff07d6d02850215fd357d897c4d32bef8661689f2d84ff897637fb6d5568a7270e783426b74b7037493e5155fd7cb3ddddfd36bd8a9c877d71d2a966057c08263d2939c84987`,

				},
				{
				hashAlgo: 'sha-256',
				Msg: `61d7b3150131351e7b4c8e5645d38be9335b40289af34cc6b6fc5e48493bf8b7852c73982c99441ef66c7d9d33c29742b1406e02e0aa8dd034b1ac13cb0d775750cc91421fead9caa921eca61a02eb023a457e77915e183acf517d946bc68292896014fd214b7c8c5e14e15944be0f9296127771f736766e4f81dab3708ea2d0`,
				S: `84e92a145ae6be1ff9242d9ed2d68de668e802524e8ac0a79de62fe74048c35491fd2ffdb185057e666dbfaac84c34fde7891263f8b2bc74746230320f67a7bd7319c9b9de4190547014e2d7a2a5060d6200aadc3a44bac029ff3992edd30ec53ab0d9123eaa6b147352a073a98161e64f394bb99492c6977e24f445c7125bfb90f87faf262272134acb18823a99a5228d1495463297fd774877fb63d4918106347e6f29315e48363f39b33299eaa32d8da71b229d8ffee5f66f722ad3aa4175d3f84ece9cc8eca8d6f2f356a85c1524896c18f7b5c8f9bcdef45c496d539179891ddc76e5208ad8353d48c624054f3440eeba4432a10654a11ef53783bd116f`,

				},
				{
				hashAlgo: 'sha-256',
				Msg: `b6771ab0e128b41b32b8b05e05add23ce0fb877b40bfcc3b992f4c8698d1c828abecbcc1c33d401859ea2cb2afbc7fa4588802a5faee2867534639287ad8af84674be18db661de1da8e19c6b6bd452dd9bf3221d0861fb6fba96be42329b9f04f37dcf3b41fc58d2298348b0c15d1190b125300cf27e0dfad60522fc49846053`,
				S: `6276925568626f0cbe6f5150b050e1702582f8daf99a6f880ef75cd96c2d4208fb6e91b01ba6aba2a816b2d3cb975df850b1d268c4662dd1ea3a300c1d7171c633dd2efbac3000c56ab80f989dbc18243e636ba5d4d26a7d3f1965ad3cb0f1a8513f998003f7b67e2ac5c718cb688b3201d56e68f0b9f86257b84794cdffbc1fe3ea24b7bb6e9ef0539bd4fbc1afb55bc1dca39996ea8a63769f6e225707f69047555e1a4ef3c639c5f2a497b889424a90148639bb64df0a06e0b7f0e8ed466a977baca32f482337b2abe3983eaec3fe1075016e5867521760fd0607d799f1766b3ff6e2ae155d69250f8bf08c8edca0b4f31d0f838cfd298cb7312df93f0997`,

				},
				{
				hashAlgo: 'sha-256',
				Msg: `6a81cb6c7b268f4b9fb9172adbbb36a237a0dcf1c3c83a95dcb0271aac6ac330f04a5a00fee38bc00631a98598186159660d9d8e4c14a9528dea94836083dac4abb73fd00e38fe0e23c7236604a736540e52193ae56c33fbb8f5cfc5c7c2be2e222e4483b30d325c7ee14f742851fcb8b6d6189e98b822b8e6399d89e90fb997`,
				S: `b67991050c083e645097db03fff34758868beb19e9c0c48475f0f913361e71d3d6f27a8c4f0b269b49e8534039e53ad3bab9a3e62abe078ee75e7fb5959006fbfb014ca7b81b3d5afe0ee5f6fc2dfbc450f2839543002f33f4f354f827278c76c041686eea7886ebb2a7afa5995c6cddb1c0b58066ddb8dc54a6927c146c3b2a0fa7cef28903c6c672bc20ef68ffbfab247eb688ab4bde7106d9c59d2153096dc9e5207267038d88e2174e76adc1508ae24eb602332e53c0c2e33154a66a97a0f12f66c61258c7bf6bbf3f1dcbe9caf2fd30ec68c0a9d09f4fd776304b540e62fc8512beaabc4be2107a1ec18e87f61f9db25e871dc0693cef17c2a687fc854f`,

				},
				{
				hashAlgo: 'sha-256',
				Msg: `056c1e4644599e3183dd8d2f64e4bb2352ff00d012ab763f9ad6e560279f7ff38a5ecea9c2e4ea87d004ef8cc752ae93232aa37b5bf42884baa7e7fc6a8c951cd245de2d220d9bee2b414b3a7520c1e68bcf1ae99a9ff2bf3a93d80f8c1dfe8b85293517895c192e3c9e898295d65be334f44d62f5353eb6c5a29edfb4db2309`,
				S: `ae05204e409d727eb9e4dc24be8f863328c2813da4fcef28866e21a5dab21a485321b735274af06bf17e271518e11164d722ab073548f02e1b441923db6f1cee65a017edfbaf3361c67fbc2b39fe038cb5cb65a640f95887389ce8a5ad2ec6e69d3d603505b025f6d6330c8b648802caf7e6fa3fe7b38141659986cb89e6232f106222564d5e5195eda6a25f99068572c2fafe97f147f7f2f4119f21385af1fced97f78632d8bf4fd9a9054d8b9aa2a9f4ded587847a91d42c6391125f103ae288547e8489693ae8686b84891b772b10c4796883f66cd459a8c1a6a4187bd6b387d349e92d7b604953727c9e9fdc449e7345e7ca6b339e26b086f5548898cbe9`,

				},
				{
				hashAlgo: 'sha-256',
				Msg: `cec5c9b6f84497ac327f68ef886641fec995178b307192304374115efcc5ee96270c03db0b846d674c528f9d10155a3f61becce1d3a2b79d66cdc409ad99b7663080f51a102f4361e9dbd03ffcd876b98e683d448bd1217e6fb2151c66964723b2caa65c4e6ca201d1c532bd94d91cd4173b719da126563927ca0a7f6fe42536`,
				S: `c48a8e01d4bbfe0f2f05659337ea71d21f38d7f7a10b00b06e1f899eaf40a8e97ead64bca37f13a55ef1cf3fb52cee279cdcb096085a467afa97b03d78d6076e472b12d6be9647cec32d8d91a26247693771687460ba5269de18e1edef6022533a9579f91d584f9e0cee1100c447b77576b1b4ee163ed4700147a9aa61bdc4e2316d2d818c1028ed1c3e372c9f6a1745572444637248091b83f7b539f9bd58b7675676034c20e4ca119b91c4ca5dc76acbff3d0462898352c591c2ca6f2d8b09e2e6338a84336e06f0cc020e9eb8da785889b497f3b98e827ee7a7d3f1b0b73c1958e16aa97861e6675970ce31d9d119bb340be80fd0f43c3dbe64f2a59d629d`,

				},
				{
				hashAlgo: 'sha-256',
				Msg: `9193f8b914dfe0e62521f35afa4fa5d42835e198af673809377a3e7a99733142a180dc0e13e6bb7ceb3b60e5e9d515794d82c392e07913423391d22e2bb19aa0bd88afd7f77e27a240ea4e2de085481ac31ff8d37990211f82f2cbf4c90de98d6e1338bbc88e6a80ab9684dae64785dd107248048593abc9ab03f1737a6f6530`,
				S: `5c2fe453a8b08c90b02eb2c9994242d518f3f21b368895cffd624050e48aa714005ae675fe79aa3cadd4df55bdf12bec5be8a41d87538f7e031b782e34d392468e5f14bc613b8f4d28c8fb79a2537e1e601031da720acd7b2c8dcbe9858624a7a9a92a06f91845f732370d67365c6464f7b68f22eb3edfeec97e3285024d7f6943b6d50a16cc96d60f680351deaa25f0bc868948607a6ba7f1949b85943c6a92bd6172e81bcc055014b78a733972e3f39d14099d1607a20ff8681c29ae1ef99ef115ed6a1084b514b81a69d4a15ce1e2576fdcf2b2af615b52fec70132112dcc5bc19ec17f32281460623420317353e8a255fda502bd1fb11a58832ae2c04f9a`,

				},
				{
				hashAlgo: 'sha-256',
				Msg: `0e57ef40b021bf87f642c5756b6515a0e06c15a01856d716c566a6edb381dfdf44d9033b1cc809e61dfef9a096dfb689b7271be449d04a1a9c354102c077af5ff72005ab6b06cf131d7345c21e821d6201cca4e090440d70be6009d2dd7a98d311751e1605a3b914dce6d2626b16f233a5a3d71d567cc820152f25e473514242`,
				S: `7643aa3fe63e66f79d6b409d145ea820c9f7356f71b4acdcbd43fe1e99f8802cd1662b16240f5cfd94a769b0b3f2cb0b11887e886e5ba43733367490b3fc188f2fb3a0c0c8a68b5d2726c8f7a31902b6b86cd402287d385c3e3c06503ce17fd6e54e582f4a907a91f952d2a360e2fba00028e4d3b02aabf7d220b31d1f8ee7faa070147682ccc8bcc756ca6a68fc20954550c317e87918781a3d1f1923503091090c3c60ca1c0b1c699906fbf85aa70ad9ae48709ff743b82dcc31074cfcea623ea45e48644b19a21772ca107ed64239c56574a087f1a6aadf0f4b00ffe581c1410274c875e4599063e46e5168803f0d28d21fcd3509b4c6222995add7753bf3`,

				},
				{
				hashAlgo: 'sha-256',
				Msg: `0c8491fc348d341fe85c46a56115f26035c59e6a2be765c44e2ec83d407ea096d13b57e3d0c758342246c47510a56793e5daeae1b96d4ab988378966876aa341b7d1c31bba59b7dbe6d1a16898eef0caca928f8ce84d5c64e025dc1679922d95e5cd3c6b994a385c5c8346469ef8764c0c74f5336191850c7f7e2b14be0027d8`,
				S: `cacc8d9f5ecd34c143488461135c4951676145c6e472b92f12f758046f172142fa388f285f3fff068242028829047e248059ed4fd39d2c5ade469dc7c39345e5114950d2031cc7465fe712c4041d05c756d3f2d88a46ceb99f2e24a52e958a03cd2519a9b137e62d5ca2b353f7b047b625c3602313fdb53c8db23d83951a599db328fedc4ae06da89ce7f56259b5c8222f7bd3d9740478fd28e5810db78aee8623fdd39f603f8ddf98081d7873980c4eb0e22a9cd408f7c4134c12d2049a2d120f4b62e6b382b997fc375ef7ac955fcf80b045c3d6385ff422dad350c68870539068a162a2edbb93ceefed9677939b90bd3dfa0dc053460b4e2332efa692179a`,

				},
				{
				hashAlgo: 'sha-384',
				Msg: `6cd59fdd3efd893d091afdc3155d354f10d6d88167427a2cf7246207e51791a6ca6200a914cd2834a9b3c79fcd59e26e457e0683bc33d49267edbdd6e5d90902696f1e7b1a4affc4ba371339868c28015ebbb73e262669866c35db974ba69e468f2583b9191d15d686cd66fb0b9e0ff0a3b4721a6dc342f14f2446b4e028595b`,
				S: `3974900bec3fcb081f0e5a299adf30d087aabaa633911410e87a4979bbe3fa80c3abcf221686399a49bc2f1e5ac40c35df1700e4b9cb7c805a896646573f4a570a9704d2a2e6baee4b43d916906884ad3cf283529ea265e8fcb5cc1bdf7b7dee85941e4b4fb25c1fc7b951fb129ab393cb069be271c1d954da3c43674309f1d212826fabb8e812de2d53d12597de040d32cb28c9f813159cb18c1b51f7a874cbf229cc222caeb98e35ec5e4bf5c5e22cc8528631f15117e8c2be6eac91f4070eecdd07ecc6db6c46eaa65f472f2006988efef0b51c538c6e04d7519c8e3da4b172b1e2761089ed3ad1197992ef37c168dc881c8b5f8bbfee919f7c7afd25b8fc`,

				},
				{
				hashAlgo: 'sha-384',
				Msg: `acb30be9092b2f18f25934a0d678b6bcd6b67c2b88e75884f47b4fcae3adfa405afe2c7e61e2d6c508b92790ac00f76b77c965082668bf900f70a33762de6413af93af2ea8086fda293ded4475f23c4cc31ad494f98d7dd7b7fd6f7d972bb76cb35adc206804c3fe5acdd0e5b8b54e07c29111f788bc5902f40afac30afdbaf2`,
				S: `b5c60d8da9b3943878cb2359cf65e4817c0794f950453ca77c81a5a1c1585591aa50a67468e3b399e4faf1d606bea0d9e6cc1d2d70db8063739e0c27d3dc9f9afe88dea52e73298a07d05c7d9707002efa537c389e38bd37bca74eb0af6261a5da06136202c8ad487eebd50bef74767089c70870be1d8fab9156f9fdbc2f2e9cc330a95018ce7943984becc25621bfa66018ef8320b60059f941156e9cdd87ff0d82cf7be77465e0203e7120aaeced84abd8186947d4ac3daf3f993902aec47c3090475c857b5d359f0a5572d4688e5a76a4653868ff54ce9f999e6bb559d1c11c67c15be9d7fe5f8c1704301d055f3d2907722779d6012036084e950de36f4f`,

				},
				{
				hashAlgo: 'sha-384',
				Msg: `601a6aad3faa7988d5ae528a6969031b10a6f39216946aa89fd4532c8ed141f9a650b126ef488f7c5cf3fb2daa254cc28bdd55560419e80214ef999896dac4946852d24fcd9fb77610eebfbb6ba58bca26f4567f03ac7e56da553f23817bc103ee485592a058fb5e3bc8299c7290c71a29137e75dbf5328c3a2dcd34165b3f2e`,
				S: `301d60d56576f3663a7fbe8036bbe4fbc0fbd82cd6a42e36d7bbc8b206543dc2d56d3198e7911ad138cad222dd99050dd1f85fe19c8a88bf67135e7f8f11b5f5e485c91fc7d478069b72f46ebcdcf2d2ae7de6ac8fe53bb6c04911d122cc231dc210b2147ebe8b052e8b2ccc09f338b349de2025cc87b2619a7b163347ca66a34791a2e46b4e2ac57eb9f6029cdbe024e896d57f7d0491f7783312f8f06c790770150cd139f61fd2b3e7041b37261c6e7ea86d4e06d9300b1a5667cb0288c550b2afb355944834b461cead13794276bb46e5e20aec7b63aaca4d491a500facd59a37c52779cf467d74af1e62b1ebe0fd0be1cacb7ce6d050d86e4eb76cde0693`,

				},
				{
				hashAlgo: 'sha-384',
				Msg: `44d3e0fc90100a1c9316063f26b180326cc2e3834ce56e4324528a0bbb015b3d7812958cd26b91bf08a3a0b1121f9f9dd77acb98a02ad75fcd613c53c732d1c235f59b6873ece6363f279452b6a4b65e80bb59fd47b9a2936dcc1e4dfe1f5362e3459b9859db3209a2698d27fa8aedfecd4d35b927daf8686c59d700490f0aa3`,
				S: `af2229e94a857b89e0e890daca3a8fe12ebdba04948d1883a7d7816a3b682f7da3032540a8769f9ccac9586cf24e8c204b45b85d1bdcc5a5450a215b4048ea42983b3456fa8c76c6786e024f705e088d694559d668caa8684cad0fc57850fcaf34e458aee8fad4e09e6f196557d4e8860284d982c0105d98ce4912e96c3550e2a0c7e8bad5abc29a9a542f57a8c60579038067b3d5391abc21b4f9deb024ca58f9b0c38c0d1f82373f528e939bd73a24d501c591168814c872c525db0e56cae47df00fa3728dc3a0976965323ce8d2dee2b138b50ab7afd48495114673e91bb3ed2205e26a8455474c3d4ec8739bbff6df39b2b72ee050410930423b1472b6ed`,

				},
				{
				hashAlgo: 'sha-384',
				Msg: `5af09077a1f534b89822b26c3272adf8500d3c6bd90f9b5e0d8b211f16d0720ee0eaf6462b6c8a80df6d75359fd19d03a0cafb52bc9d4c37c2aa099911a79a92652cc717f0746fdcad627c72f1c216b243d2175f6d00bf07d3f6aa2a04d4fe9f8fbce93218944b92aa07af6b4fcd80cfde2d7ada15c05e96e777ea1c17df08fc`,
				S: `a56823fa577e8946f1d2f6e351b738b53592544358528af88807ea4f19017dfe81a3d69f62fbff649550d9b310faf27a041fe624f0a02bdcddb79bfb0a465739ec8b64b748cc29e5a02c777e1826d3e2f1eee6fe2edee4a8bcac519c7c7ca5c039e76d630668945a1e5e8618e235864561a440e73e39f6d6842ad7da64ef5b0ce1c4ab88db157b68107174ad7d5c9a6065068768c11c4c96ff67050b5d07b8cd027fcd0d347ec79a197cf43435985bc1aeb479db0022289e8dd3b31bb7c62d8831cfe6952f41d24f89d753789535f918ff68b36950af6fd31dee1ac476a0cf93afe9f4a766f3c4d2c0c3f92825d5572eb2eb8a2b644e329eea1683f90810ed77`,

				},
				{
				hashAlgo: 'sha-384',
				Msg: `f60a3a543768fabe37f003009a8c26f7dc91f1422d4429ed7f9d744cdd4b552afef75d241acda04ffc39672159ee248e602dab7192449e2ed4552995c258f00a476346e36a29a0126bc249040faa57c9380bdd74b83f62c56790920574433432f8d65c5cd185e24fad13127265c6a5ef8db4f114493d5cfa61d91664981408e9`,
				S: `08d396481deef18cb0bef7c3e826fe6e5c9ecc85e5230d35d66772b8d2d015d4e5f5794fbe0550df2f745730d6f8d1d3b850d164fce4630805e711b59308f8608506b7e01e8e9294ed8b7e7582165677f180e965169dca81b3daf24d7b92fe32d6a9ac63821d48b1a0a144fc7a04b0bfc63a3bc16a0fd837b02037ed76e50d46cbfa3857e658e370c586ab1eed825076321ac8e82be374bacb295e4d3408f0cc1fc4c300b84275a51c3573e9cabfdbe3dc51e4a6f5811d860d725aaf8fd0af19a2437b0f1c80f5ac222f6b25f1fa09e93399a6976b1b3ca76afe6086e9b232aae6c7b818255bf963f31c04ae3fa2136c0a442997d4cf12f395fb804a4755b56b`,

				},
				{
				hashAlgo: 'sha-384',
				Msg: `2c07a81de58955b676fec0572d48d1955b4875ff62a44b0010c7a1072b299ee44dd0c076f2178a83d0ae76e767e231f1d81e070afab29c97abd4de2164e437b311f507841f8851d6d69ab51ee9e29e654b54bcee45e9b519c6a21787facb927f1d7d6491926614792fcc6346dcd080bb5cf07bf56ad0fc4e083a358214631510`,
				S: `9aa391e7c2f0e920aac27ed9fc2081d3c9caa3735883d01ad7a7e3b11867d0ad624156477bbbdde659f474682d0d774489e2b5b039d1eb35454c9e3eed78cff9c4262e3aecfca1d817542b486096598e1114bfc03f20a45de36f6df70d144d01dc4866a0f83319e7c2b8530f8c27a41b7add9f692d8a8e646455b67c9ec47a4d2ce3dfe35d6a2e89d9be50c5b6da39bb0254bd23a809ab97b2b48a068a87abde6b6a6e35955fc92a9626f9607d5b3f401517271594bef73859812b6a621ed6bdaf3c5f2a90b1e1680f68dcfccacb65e0081f1ccb6a2073709d1ba067065016ed73ebd7ebe9e7a7b60c8c9dd04a56fab30702c8a6df6a353a301047df4c7aff62`,

				},
				{
				hashAlgo: 'sha-384',
				Msg: `35ec92afdbc2fcefe48f1e2f6e4829ae53b3da0459cc4ea8a96818b5831891ee2f506fff37c89906d3233a51a5cf1469a62c185061f033085fca6a54e24529c3d6f0d8e904bcb0f089a5cd50869484da1a84f6fb8de4e53fce3dc714201519d11013f6f6aa64e8b5ec5cfeb27b611f0895059d8c47720d55e00b577ca5500920`,
				S: `6b0f5b50e678da083ed0f1b64e943e8c6279c7246af5ad079cdbf223e42a0d471e56314bc0d58f202aa6c5e1e5255985b0795d48eb3d4b8e3fc92240ae02b4088c6ce8ab0e8c79c68dfdc48657d6a28295391b9a5a5f35255126bf8ca53cbcc0082eab52ec109d22a1185f6dc792fc290aa8dbaebb2fbe404f1d039aa6343cd7af9fcb2d1e05def48096c237e10daa7cfac5ae9b3b3022005d0d2d5c9c5c502b2f23594e80d1604bbb8f5dec07cd3afe1f777743b0b58a4e0e4e5caa148830eee047968e7f40661f9f1a02e1a7fd2b6caf19326a75e9565efdc0114bcecb14dda06c329cf322a5bd3e6ab48d95f2d2a9c1c1233a0aa015a738f901f13148b454`,

				},
				{
				hashAlgo: 'sha-384',
				Msg: `80c9debdf93174d75750a6cf09af71fc18fd513bff9cb491be60af112a93f000873cf43858a07aca760a37e760c8cb01d276f42d997f01cca5e08a6a602f5fe63edcbed395b8c91fb0b336f21fea49d950e1ff24640c8d8d3b95081ad1596644ce34a558587e4a1e2cd50db9ed1dd3cebbc6dce8084d3e1ba70692e82618ed61`,
				S: `4a15a783adbf274622d5a610bb6fc73337999e445dc2133accb788d6203d70f3cdc63e67daa4171a7952a4986456fab3c077a8941fb259e37a5c0cbb20c408fa24ad0ec850e9bf028c3604609941f5ae2f18bf1ac37a24f755abb9c85ddcd0bf4a12fabd9d253029e081f628e2bbe9f9afe9224954d8315db86c2125512bb98ce9b36930994b091a8a1d7d4e2f4a0e58d0a35876adad14300530b39c8dc11ded3ef2fa95d5f22e67cae34cc21ad5e23f9122b53dfb79f1a2ac63c1844e9ef069a2e41f178d6dcedc518aafcf81e0ebd882556e731cb0ab41d957274a3fbbb7cef2608791000c6b860868cb7393e7d03d945689ffb77555efe08f461451d33c11`,

				},
				{
				hashAlgo: 'sha-384',
				Msg: `31395cef349551343a49271a8d812b4c7b65b455b7eda811fcf74161f397112357ae446257be26c93cfce55e4ba7976ded997ec10d1c8b1ac2fe22dc2ee81d05a6eb1361125cda0197e24ae974cd44092aa9f36fe01352ba05ccefd2370ceed6641950562f1776c39522e023d09a3b097bbe9bc5f87d05d80f8830abd7ac8c80`,
				S: `162f387695cf9d82dda89c749318e46c9be895ec364ea4aece97ccfa63925af3710894da2b7b5967e46f4efa80ca25d2a965a7e15f75e0aa1bd4250f8f41099e6e9714c3fc4311077ae9bddfe35ba4727531529c239d546ab1c298187f165f708ccc0ae3979a8da193e34859a59c2c3bc42253c8346688e6bba6fb1b01b10c1ec2c6493dedcc2696269d851bde63e27e37bed357455c8fee5629f94afa7a986695cfd5b99212657a6c884644596086b89e0c7c05e819faebebef745fd295af8866e0750f5479baed50cbb3d059f8a5eb7e0e61e2733ae50f0c1ec42be71f5dff324195cb4f0e941a21561513c3037db92fec9556b772ccab239e34b1876c56b1`,

				},
				{
				hashAlgo: 'sha-512',
				Msg: `a7c309d44a57188bbd7b726b98b98ce12582228e1415864870a23961d2afb82cd5bc98bec922d5f2ac4168b056da176ef3ba91f6b699ba6acc4144868ff37f26fd06720868d12ad26ecb52572cf10416af68df03ab645a8b704857d2190ffc3f07eabe3a8e2abe34ed6159e884c4fae141d4333d5c3e0db044ff9cccd9cbd67f`,
				S: `148af61ed5ea8a87a08b3f403929bf8031db4fd3999b64409ba489f97a3ee5208ea4202d2ec18734f615003a51f77441085be6ac0f11810ffa2dad58f0e186d5520ac2b8a5d3966e8d2abb8074e13b50a4e7de83be10a66fdc7ca18118c5774f781212de9efebc6376fcdddc65a3b1b8f1ab31492fe478259ce719b3db587498d879a01dec96e8eabeb07ff7073f3f3eb446084955ca26329a791315a2c259d225e26b2154b2047b21faba68115bfd962e5e24ec52d7c5d231e3044cbcd8c8804855703cbaa622b15b6ef78c7421a367166f1b02576c87360593da75b7189efafd1082bd59f6857f1701f646c24d70c95273c49d5b11e6afe258821b55c1680c`,

				},
				{
				hashAlgo: 'sha-512',
				Msg: `ca505d4591121664990747d95d9555cc75bfc3fdaeeceeaa60eafab3fc320cfce56eb9138138bf138f25f3c8bb027b136f5d3d90ed4897779b5951c09df5d08ba9ce8cbe17abc4f038687086e93d771b684322266633d0d65d71ec41234a1dbec07abc8f7df28bc43dd8a45b10ceafac06775805413701914e3bb37eb6ba5b5e`,
				S: `589ccd4ebf9764f87e6afa7f13c4062579b02228117b15a8738ab39cd64477069cb4f52cd8d5f4574c657b453835ca3cedb824f03b92a573d6d3d91361313f11bdcb34d2059fe2e6ce2b854461af58a9294c88cbfb2a639976b56e4748026f3040e2fd7112d6ad44500689ac777c071d17391969762e186417c4400abdda5c16dce0077642f1fc1354e0e8c14e558c923c1bfb85488b8350f415866a60871ed7151f5fbc5b880500011977c778e17fe8918c5d343f70b00d58f718956125fe28b3a5e2d07604a2b8a877204434ce903b35a030936bc71951ca593df97d24e8e8ad8f2dc9b78f76ef13a1d386ca857ced48f19f3ebe39108f9b33ff59eb0556b1`,

				},
				{
				hashAlgo: 'sha-512',
				Msg: `237a7e44b0a6c268bb63364b958ae02b95e7eed36b3ea5bfb18b9b81c38e2663d187144e323f9ceafb479507d184e63cfbec3ecdbb8a05d2dfc8929693ed9e3e79e5f8abfc417ba1e17e3e281e8a0a32f084117f28c3dcbec51b86f5c85b2822441a9423b5b446d3928f977626a334579b39cfaf58f214c98d0cdf640be1ac59`,
				S: `af076bc213caf75619f4bd1d787cc198f7df3324a0dd87a88416e0a4b81c2fb9a9db5f98aed43bc15fe2357143a6e4ff701d9c48f51de9eb803670bbc4b0aea7220be2f84b8300318c77a9f615986c4980abda85e3ad0089564dbaf7f44d81b6664eec0311adb194d46de96bb17d5a5d47426845802ca0f49a169eb82b75afa191027a0cc8fce9dd16055350df9745fc7200ff9f4ea3cfbfc66c42848113e3be3293d510382d0999f032515527bd99f66efa2a755e011247b223a68e51258b6bc319a7cdef4aec533e9dcd8ae26e349e5b33c79121907de509a1cb83c2e59a47c1a884bf68e7229316a62e3c49d1f542ebe7105cfc27099268120a7743908471`,

				},
				{
				hashAlgo: 'sha-512',
				Msg: `ab18939230b096646a37a781629fbd9270f3891a5ceab4a8c3bc6851bc34115dbc066541b764a2ce88cc16a79324e5f8a90807652c639041733c34016fd30af08fed9024e26cf0b07c22811b1ae7911109e9625943447207dcd3fff39c45cb69ee731d22f8f008730ce2efc53f114945573ea2ddebb6e262c527d20f8bb1dc32`,
				S: `95bd0bf2362f34b2e04075b2934f404798703ea472b81ac3cc223aec486e4c3d9c5d1c2f9ee22417132964ed58e49937f5b257d316ca7fffe290b19f5b58103836812bef30ca0327039d8b9ea91295392fc394b881e2d2ac9e30c5a44256700fc9de0dba298273aec30c4f778d2e7127e8b8a88b0274fce04081cc13adbefe555014e1b5d5dcf6224c5ae2775423a66c81818eec014a3faf9ee75a3f6c3e51c556b0a288e8c262946684eb628b88e3f875e62ef6e801cae75f61cee404971c39d24a9712eb342ddc663515dec103b18d97d78ed68212f27900e77c049b60c853002b08022df56f707efa71027589e1a3ca6e415ba5f4437e978b07af3b73ba0d`,

				},
				{
				hashAlgo: 'sha-512',
				Msg: `a280e89ceb2c8cf26297191baf9a955d0d52375da023633e0afcdb0d39dc335d8295852ef4d06714e6511a95d37c04d26818606ada54359b7d0784aa933cc68561ee96a88910aa3d93d10787cd1d7580556731c174a6e3a32d9dcfa416604f0c671481d051f63db6919f4aba4486d1b0fdc6112c1521559f424523c26b4fb738`,
				S: `cd60de3b4a1289a84ca761f90fa63f4d5688bd885f4b531c8515add2de1251f993ff7f986bef3fba692ecdebc81942d7429c7a59c5d3f1fb872fc1da1915e94586a5c3d963603619008f7efeded1d70b0a11ce2cd81b5b0d86b3760c9483674f55e9fa47f2f310d588fb2160e8b5c32be4e7a968d5a8d4ac6576b71a2b91cd6af0016cbc816d4aae8c70649e08dce90b3ce52ab49ce2cb5b0ed8a45e33d94cf2d4cfdee1151270b2073aeffeaf717d39e04192b8b693c53f21a6123813280806920b7dc582201c9d117050320671e86139a027976b7ecf413369a9fc28e0bd719ceb5e107de799f1bc2e255a9f29476d4574d1332f66468afb9004ff7b535302`,

				},
				{
				hashAlgo: 'sha-512',
				Msg: `85ed1e3dfcd5bca24cad1d01ebe192b7d059ec9b884436e18714a43fbcc9c64f687301352ff240817001e757d27309cd1fbbda9456b267dbfb958470b24d06280cf43382a19477875f3259f4210bac9b831d0a07f5e97e5f0f78818c259c289e1a789b6c7942c97bc1485a220131e5eba586643b9071e5366bc482dd3c3c9279`,
				S: `138134bbecefafc7ca8b102cbe87b012f8aada8878995002cf1887694b5be3b8f0bb616bc6e07962d5482d3a52c52ab91b3ee0064d24558e13c75c80f6a95b7dc498442879d5baf8ffa7e2f638808b97ff70136bb645e30944dd97a997a0205169553a5b9e874c5a9441e18c15ebed76043b639dfd64db79e174847a102724a2a05c649473cc7dacd39e2e1d5666bbb5f01246747048fffcdfcddf782da24a6dcc022b2695f70781bd9f8ff7d03be22eb8fc793f5c071a66d9a6ea46c6a2cf0556526ba8b085073546448081732ac15f12833c1db1701ff7f68344ca65dff86211a003adbf5189cfae79eaa8c8b7141ea378e44cc9c5bf024d2c710ff5cd68af`,

				},
				{
				hashAlgo: 'sha-512',
				Msg: `0bdba34e35fca65a1781d4d7c933a5f210d3a59483aebc95ec71b32df13ff4abf401916937fd88ff44ab46b78cc369414e9bcaa8bab0bb8557828d73a2a656c2f816f070b5cb45549e8eca9d7c0b4a7b0a27e51c119358dad2a17fb3a45718f9dec3c94af78d65c3ecd36b71e230cf080d1efdd8d07f1cfc26768fd5407bc2b7`,
				S: `9f48deb96bec0b72fbc4f12f08afb46bccf19d9e0cd0368ebeb312d83872626380ac928b612c5cd77438d47aa9ceea905a9de7182c8ef76e8a7a03d6efec8400b6496362bf6a30ceb1ced2185fc7c2117b6a6d888ac20c1687b0f2aa9b76705fd3154889b6acaf4e63be25880c71e6c239ecfb965004cd6321257f846afd2a6590c72ad83146eefc7b0dc4796339a7f64da0fbe359f94ace1fd151c5ac7bb5707b32eacf564fe1622e66e1844e639602ca36274ae01f93e6b2bd1effd34ab63d852cc9caf3ce8446c29c8ae3c6110fb7538cc8371c2a3981249cdc1be2b24b6a0c951764d0b7efa92a22cd8ed165e182863579377997a9ee50c8ac3aa4df1aca`,

				},
				{
				hashAlgo: 'sha-512',
				Msg: `9aeed85b40ba7f86a228b5a1515ba190b2efff66993a5ece19d18baa9b4e4df92e5152fe1ec56a9fc865f30bac7e949fc4f62f0b158d10b083636b4de9bb05db69fe31b50103fefc5f8daf3af7156b4552ca3667a9d720bbb2e4bcdabadfd4b7f4fc5bc811faa36710a9d17758a98d4a0474fec27e9ef5b74f5c689935442357`,
				S: `9eecdbd7fbf618ddddfb6e75d64440f60445b853c542fe0fbaaa6a431294e6cb6683ae1a71ea055eb49cd2a3cb5154dc93d9aa166399f4e6294f0eb0652800d71e041c1ce1ad849c03c963bc0929dcdd11be5d67a050d02b64b29eaba655642b6436fbfb163690bf432fdceedd106c2f4972ecbf3077ed8b753bb605ec1ea03020839a318a24f8d4c1d7d8df99a7f0010ae41a8b068e2888531056a7dabbe921878dcd3c7d69416867f4012a606ae86855f15aed0da1250e59687706e89c9494baf37f61fb1703b79928795f90ccbe293a1e9472f6e0f4b890fdda3ea2522e3d11d5abdf0069519424d147b5646a5a601f19ec89729a8b48461e71c08bbe9cda`,

				},
				{
				hashAlgo: 'sha-512',
				Msg: `654e189f06c7d42d5539a5872184f8336cf100691f190818fd02082ad68a7609fd095e62fc32b529853aebddac3dbf0d54dd571be72c90404bcc93d01154a9bfeff65065705f8e7eeadf8575b1ca48e28a1eed516265e34540dd867c79d7f175235d1330cb1706356b709bd796f43abaf6fce993f88eaa2fc67f0ab776daf732`,
				S: `af90298bcef615309f235d5c3360f0df11f5fb988789f213d4c46134fee5eb104aa1fabb1307c9a904709de88673ed9951cba93167c67c09d827021b08a22c0505828ab4beb42e59a38832cb4da24ecf91f470a3b412c0712a8a59f6f2739d4e9eb4cc58d2c52592f1452dc65759abe43e8d2bc804e2efb3efc9b23cc1734ff7caefa46b03ba4b397d0714cdb8501a812c1b9f47411c91cba53a3d3b139edbd7cbb543f5bf3829ba7f5fafd8a712c0b111943f53209353afaba176b3f5dc060339d09b1fb3c213dae5d0f004d302828560fb5debf9fe491eaa66f597aa4de23eeef9176358755c952ef96e3672583b6ecd95a02e8ca7b21d7c20cbb7a757af71`,

				},
				{
				hashAlgo: 'sha-512',
				Msg: `121f80b43f9757b3fa80906aeab232195f0e2c41e5bf8c091ac0f1e0bc9e43640680a1823d649bdf86aba277fad8bc85fc957da2caf7323053025ff949706c1476ae9b0953283d34d7c6266f8db65eebe96d195fdce8e965a6383320ec3de0230ab2548eaa69a47a96d80398cad57e14ce9eeac0421c1a6eba69559dcd8f0659`,
				S: `06a2d74585f12ea7a80527b8c635a21cc11b45dbb0885a12722126811dd25d657bfa9fda774301ca3498d05dfdfb78a6aa16a9f8a95f40f1f04bd354a522f6a2d62b324efa3c006c22c2314b01fa0e91a3dba49aa35b46b19804b07ad98fe4bc990393a4a273ce8f1c85fc19cd5eae9af0b7d1957bb23409778a010b00c6959e1b67066fdb9f8495b4de4dcbb987358145b1ff6a39ef6fc588cda1744e0ab9e7eb002c29a78531d25157c5c2cd6470551560a02845db6dbee242f965a255406f6ef47b3221a5110edb44d38b94191aeaf433c0ece3480b9d1b06d8b8b6c0a232a04c567888e6372f2e94bc2be6b827f8712af48c6f1e4f223f5528fcf348799d`,
				}
			]
		},
		{
			bits: 3072,
			n: `dca98304b729e819b340e26cecb730aecbd8930e334c731493b180de970e6d3bc579f86c8d5d032f8cd33c4397ee7ffd019d51b0a7dbe4f52505a1a34ae35d23cfaaf594419d509f469b1369589f9c8616a7d698513bc1d423d70070d3d72b996c23abe68b22ccc39aabd16507124042c88d4da6a7451288ec87c9244be226aac02d1817682f80cc34c6eaf37ec84d247aaedebb56c3bbcaffb5cf42f61fe1b7f3fc89748e213973bf5f679d8b8b42a47ac4afd9e51e1d1214dfe1a7e1169080bd9ad91758f6c0f9b22ae40af6b41403d8f2d96db5a088daa5ef8683f86f501f7ad3f358b6337da55c6cfc003197420c1c75abdb7be1403ea4f3e64259f5c6da3325bb87d605b6e14b5350e6e1455c9d497d81046608e38795dc85aba406c9de1f4f9990d5153b98bbabbdcbd6bb18854312b2da48b411e838f26ae3109f104dfd1619f991824ec819861e5199f26bb9b3b299bfa9ec2fd691271b58a8adecbf0ff627b54336f3df7003d70e37d11ddbd930d9aba7e88ed401acb44092fd53d5`,

			e: `000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000eaf05d`,
			d: `2d6db91eb32e36e5d5127deb034d14072fe60c1cd13c8c3dd9adbc87140b5e7136f4f89e61bbee7826f45ac1d99194fbaa8c5a0bb94db31d93723b51419d9c6f6eeb5f3610b67f4b4e2ade05cc6b8990e8832cf4cd40f2df0388c9a52072e27efebae20b4ad5951f4d20dd18943e58b786d8797652b2bb759c319d2b0046dbf69c53c075d00c287b876042fafa23fe4dd705e4e423277c9000311e94ea3f7456e32fd12afe4a2bde358a65824f1055064823c893fc93be3b8c658bb441d7f0b00ac246bf043a9c0053d319f003ef5a5533f74d630d8ce93bab416a82951e05b82c6036593eca89f0ebacd7d51ed9610af43537fcd266e5e47c0d25fedad6d047a1a1ee3eb444367e3eff7c7520ca4f779f2027fe45036204168454df4918b547a4d19e938f3c6db6ca2702ad9bbda1261c64d00b578285bdcfc9851f96a4f2cd14d66b9c1f65742a1344948c9f1da8d338ed4e3deb1ebadf11f8c281944e8849823496f86111f378bdd084c99f65fb9b4ee6271b1d1be424c294d185d9fd9cdf`,

			sigVectors: [
				{
				hashAlgo: 'sha-224',
				Msg: `254ce36e8ed62e0887d4be00eefa82515acef956540cff45c448e7f9a9d5c9f40de61da439f389e5255ef8c83257ec921bfd150829c522eaa720d7be965860cea2bbe57454fc5e9588d6a96c22f2d989fd0bd21924501367450ad2a3627e4ee3ca15616748ba54219a84f8742495f23de6425710ac7479c4844d0031750f3c38`,
				S: `9dfd3f32091b916a56f4f357a961a525a527fd29b114b3f03829df1b25c0c5973b1c51af36633116f4c77aa2f677a3b0f82368a538bdb33e49db9fa704bd5123edefbd3a86dcc39283c2a03c96c69030f04c648417f544f08a9b4e01ae4d429ef21422ddfe76834f925c5653b1227835a9a4413da7942b0a015196faec31504111c9f084d6dd6d5a6956c55412c1bd14aaf95d828e844961fdd60cc078f169f6e1186cb0cb6ba3d21168c5bfd067dc6e460784e7c6a76ee3d8b332acfa97e5d4b656ec8c611ebd896fe90e619b588d0c615492464a1b3d05d3a963f451051c65d8f81feea925bcbee9ce7a39ba3c915a18a24a451e470e761d09855a965e83edae3fca41678cc9d098ba9928b525b50e48cb030c510c4ce727c6b93bd091b7d20b4b961165ae0e2848aa995bb73abe9a2634378d224128541ab056a31b784885aef8034dedac13167402f9f62b55741220df8aff5defb69c035d9a31e2a5b8817057241bcf854932f5edee7ee66e8917aa4a718b6c446bddf084f5cd769caeff`,

				},
				{
				hashAlgo: 'sha-224',
				Msg: `35adcd3f24b6725518815cf4606f7b1d940c396384370a376e84456974de32ec4c7164da3ac749b73b30fffa836869c92a74830523cdf2866dc0e0a88d1506063bef0a855cf30c9530ac7cb3cd2e2e32ccfab03c4222db14f2aea89dc03d452069f0684a7283e4745ebd7a28240bf1e0e0686810c97fec6763144652f6a016c3`,
				S: `b5120be98bcdfdc1e1e3312dd7b5910f073132a42776c4da75690c641f32d2899187d9b39b55f99ebe6ca0a08036372749816706664f39b27312135c50339f2bb17b2ceee25768c2bc0ac37d6ca6ee903c84e82e2f4d005d73bdc335f135399c49123662e8908119918437edb615b14e906c9f8ba1b85d5b45909f439cc8992951be1684a99eba04ecb0f6df923353516977774f69e826651190affa86a40be75b06a4128e5509c51557ae4fb410c7e5841ac9fdc4bc1f97e2862429f371aaaf99824dacfee0bc3961fb98b3ffc091f77956223ebf5bb546552358208a32ef9c37825e81668fd2c230f788ca16ffbcc0f1d884b30fe8efe6498295004ca7c7f2b173e5666b8b0fdf9d32756559f99d105c1e8042a7aed7262ca9a17025aa096075fe4433f34db6b0f197776c21fbe00e832eba028e6652653018079fee04eb3e3c12803c39830d072ab4971bcab4b79758694b5d3d8ab21ce874b7c42bedd52652219ff516fd694c3d7cb0bef0181bb85eb4b13184ea3aefe3cceea5c57596f7`,

				},
				{
				hashAlgo: 'sha-224',
				Msg: `0ba573a9dbb7f62e5a4d3d841bfd9298e8bb299eb4fdb256d11d2f8d64fe03e615f24cda0bdb73fe179102842f84b5051fa3d37e7b7cbe98d8a4c92c3b594b06d266f2e9e24759d4018edc848585ab3a3c151dbe5ee647a4bfc8cece4952f932aac80add4a42cf38800b748b05489bbfa9daae6844857403f051e37b753036f3`,
				S: `36fd6813ab411c4dcb2d7be1ed616c1e40de291a00acd87d2b4d9d4b73c8864a44413c51f09b37844a9804f823b27a9094627aaaf00a6be942d7558be11b84a73d98029c2e26eb8f650580ecb11b4ec2363597333444569634351600212962fef5352bdba367832899d3188a747236f08528f086d93ca33a06b10392bbbd625c867ddba74bb151dcc6afdd4ce41016dc2ef0ceea2ca20917fbdb0777e23503464d0bb59cd4e12c10945250889bae2ed839b70964b2c9d957eac6222a49b337730411984448e58c027371bcf9c2c7d686de3bdae16738db5276e0f538d15b3541c0ed86d318b423d8c7f1859602108a4b11c2772941396a14a2a88ec7971297c18633020998ee02b3114d19012a09a181d01f11cb8f8cb5f438e82fb45e7678bc8df9a26f1a3495439a7ac1f1bda6fb86c9b3ed6cb5f788634946348b7e24b0894c39c506ced2da657a335e54e8f997384e40c56a17a28a9bb64875a159cada5a644ab3bd6ea7bc4ccaed43dd0955f6be6e459e2e6a7ba652f1e9a3f8a83e4795`,

				},
				{
				hashAlgo: 'sha-224',
				Msg: `89530f816a5e2abd4b422fdf968ffd964e0ccf82a4fc6d9ac5a1a4cbf7fff3e1e4e287ab35226a5a6326f72bcaa7914600b694e564018cb8fa52a5897658631c96aa9359b50982ac9ee56cad9e2337fcdd1e616fedec3870a4e249a0275a1ac148b31cd2129adb7ba18878ac388c59828d4b1f6a6745d8886b5a765a338c8198`,
				S: `27c796caeee6b4bcd750d8df13cbe5164fd726f91baa575f702fe2966744cf2bef38c93efa1111c9277d77f3ecf697d02030f01e3d964c3125533d408834b7ce652824303eb278dca61023a2f9280352f89b5d03d008c103032b2b5c6b8cf7befc1ffffa9b559a995759a8d33c6f49ae574a2d31805ab055e646abed71b30ecf7367030bf26b962d41a2c7d7735ddc0e5f1eda30b1ae6efeaae9a4cf50b68506c21b12e3df2b993feaee448a6443e613cf536e2a711aa526487187b4fcd1fa684e99478c28b84d9af0eb6a4956c0377d08ee26ebd2d8d2f4ce7e66048da3c09c0538ff8efa178690d42f0341b28a8fcb649b531a07af1f21c4243242e045b194a04ad0f92edce482f355f66969cd90254ab159ff9d9c0c6680f78c996d7048e2c5f007ad36219d672a0e76f1bf8bc890faa56e493f0c52d09fa1265ce538e166709a00a2cd64e45b9e5acae2b95dcb22bcfe9630e32f37d0bb529efc8d298c0ba7b8d65e16dee99ad7446a393946258724d08d8476e7f16ccbc0e42638381a58`,

				},
				{
				hashAlgo: 'sha-224',
				Msg: `e37656defdeedfb46b14628dff3f6917b8420e5a97ef6c54afda55e07c6043dd75e7908be466e938f629001d0ece81835f94482abad5d1eaa4d0ef9bacacc133fcbae22e2dfbe13360e2f1f48a5ae1560f0b4ed293d9171a0cae11001c7afc949f78b68d80b2afebd0c79dda19ec71d8ef31891ac906272c0ffd22d974d1db4a`,
				S: `a927ec4ceb2ec147cc457e66c12a646fdc412d9eeb1d51f3b5a3e5a8f4b0d36deba3a71914cc6f2321c39d834addb4857c82abe9280c7c8231893904bd27474cb2cce1012b921f0a4d6380aaed614356d653653388ce86ac71a27c976747c9213cf297e759fc3e2d7b1ad5ba8cb3106c0a67624479ce55d0cd67c24b5a45c180efb5830fc20d87ad3b1515e90b77af87f06c6b0e7129718a2f93aefbd1028b1ac63f6bd7eca0a00269c0473eaac55797511950b11525c24141cb5ac4cfe2d9fdbffcbddf8412a70eb1b8f45648553b7067581bc8ee2d6aa089b97e40dfe61c33faf9fcd5650f61078571f03c6df94e01dd7f90f1dbeaf042d9bbc8b3635c4c89932852b311f63ff619550aaba00f061418886224f8478708f9ecdbd96f0f2515353192ad93d46cfa8a4b3ac3eaf7ab9d1a3c4dfc62746ceb089ed3ab4051ae09274f54f2a9c379ffe8c8c0109487b6883a4849415c6a0cccc68b3096938d6e54669edaf7b82ec901c05333e6c3105541f031ab590461e7f1f776a293e593d00d`,

				},
				{
				hashAlgo: 'sha-224',
				Msg: `99ea30dfbb1eff6f56ad6e0b055989a2cba11fd39e386b0026b5f3a4c28cb1e6cc3d716e1ecb7a77d4707025548f79198cea9f447b1576f8f32bfe459dbfca823d15622a3792e7ea5372f5f7bdb9cda5506cb436130096ef0413ef72155aec4775dbcdbc105c8def591bc52947bfce6d9d8f25516fe2140de2d68fd233455d5d`,
				S: `69210ee27a00dfbfcd50aaf2eb502c5706ddff6d9d23fb38d1112f25c047eaac57dc90a6da673876319d5c04494ece8037c2fb60203c9f23322e2c2063fa7d19165eddd89e1b91935a2b50021e626825bf19cc46aaebfab09b4904dedef8c4632aaedb429feb687bbac2b406f923ff1e844941b0c02b08dc2d8b4265fceb61a82fcef0624f28eef3a9193b86f15f7ac470df590ae855a7aa7540499dd46a67855a5bae6ec5dca8b0c16bcc69c0a1f9218ec7ccae217ac9b47e8f7caefc1e102e3bdb42a677fabe18274a5e69447b33414df5bb29cceb2abd35c94d369eed256302d758df9948bee4efbdcc4ae356e78be735f7425b6443cbff7e85c653a666ded2e74ec7f61103d6e8bac110b157aebf61ce32f8b6f567acbe92f6e3e26efdd3942af6c279c2c7b4f18398cc0ab4e276881b6046cc552594cd9656f22c3ee49807cce0f09f2bfa7abb879727b734dc19c468f4af4d720da8ffd650cdd6938249b6a4c847a51383888d1292a6163222126d5a42dca6fb2283e7bbb6c20d7b60b1`,

				},
				{
				hashAlgo: 'sha-224',
				Msg: `1ee43de2d8797e65bfaf52c25a0b00b6c04e0e40469205565a9674d6af5737bf9be0f9a1bd62f852e28708e32904dbd2666e7f81c54e28e7b0773086f2975c9d1c0d619e27faa7e25c9b4c9c71d66c0cf512a0f5ee4cc450c067fe4250c4fb4c6a137cc26069127ef49225d578a83bca34e4778208b560f8530fe5f213069d34`,
				S: `3dd722d2f0543e66743f8cdb60341d61fd7b6ef8cb23a9e9f34057d7a0af49e30826aa0aaf1fd34efebdbfc93ae5212711a160f2b8786f4f5becc49209bd05ddf8de9fecd00af5304d6615272f2e4940bc8c39c2fbc636f8c105565ec0f15700cdb066c5ca1fd0e3e3f49452e4f6715a582227d59ec104575c174f8cd13ecabc4d5899e02ebd3e81bd2c003242738b3b95b0e0cf0ef02f8ee02896df646068ae233ffc4436f1e97d37d45d497e1a54a0d6fc5aaf275ec50cbf0b402052200f6bc35373828bcdb48a178c9688658a2363a8683ab9eafa9790eef2c79da148a9d995395d9f6a7b310f6f7141d3cb0f206e8baa82a338d519ee881cf61d5e1f906d42c2e85f25cd19d9864ab54a32969c8edf29e5ac52f62006d9219c21140007b05c63e3ba4c04ece5d8805026dbe8ff665252d537d013f709d84999f84b4382a894c1ba0318493783a598f637bc2d8d5678cf65d0383380ada0db5a510737a8b70c3baeeee47085088e96d99438ba5e988788f2886aa7e295d8578eb27f1d6838`,

				},
				{
				hashAlgo: 'sha-224',
				Msg: `740322953bfc8e840cecd9963f58bea70d2bd20a506366d78a0bad86296922bd097824673b99e3060585804a298670e26ae722924da8e1861d77fbe631dc23aa72b414b017e0770bb33e079f72d8f3eb9f5c83256acdff8ce977cdfa5c28d9b8b59d3a97583b123c1f00b5bca1b80e69b4743feb30388892f6f46aea31b50c90`,
				S: `7c414840910ca08fecd23ff12ceebcd48b7afa4e6a87a40654baaec6c9050087b1f0b6fa04e36cd595ad293d0827e9e1c94fe033ec42bbd021f7ce2e75da6dd206b99151768d6d5ae7b1f04416804c2ad7c6744c7343c8f01be259361c116810f0ada1c64348055b2594a06bdc08db390d750e4aeea5435932a04d0e69d5906304c84e19d5fb8688ca2598b6fae6d169593fac2909238c553c664de92cba6d8915e01a6e99d8d92fecbc6eaefd93151c61fbbde2eacf2634e7b6116ad2fe8859b65a7066d7b5b77638650b60a43d8277dab0aca145065b3cf00d963b7f818ddadd7c54be5b4ba769ae013446a574dbbb8f7c22b2d1543e7b5ec08dfde38ef9ad843c1bb6d9558aefcd45d3b12c8206b792ca72bf4950befbeec04fc1a28c3720588513a29af9691d2f31dd7d39a56bcb5f499fb14ca47fa541e2ea67843399e0c8ab89c81e5893415942bfe4e470a678c0e561ed64554711b16be3350c985b61f29219c5274d879308dd25fc033f819c385904654399e5438fd9c8cf1ec76ecc`,

				},
				{
				hashAlgo: 'sha-224',
				Msg: `f7e37820a19d5f6a05eb4779c240e7fb586ae8c3df713bcdf9c2af7c058cc327956bb8d42244eb43ff70622f8c1ca5d0acefcfa479eee46f369d658184672237d94050c42f89db31f934fea35b2810dd9ae7a105d26ec5abe75db007bd578382acac66792e35d73ddb80415e982dd1290b98856f52b98688f448b79817248e11`,
				S: `563e22617dd889e7be8dd26a176ee9f67b9b3eb040ad7a7fabc089b27ed4e7a782f1522b446f42a567492137770c612dc5e428ec28a3c502aa2508fb46b703d79d1fde8e1a507d7062e26440b3a3ff16bc82fcc9b301f2b58fa81852b57f951d925164be0c70bd281d726c9a71b984280352289f8c1b394a85df9e1732a4539a30a759e8f126096bf73f7b25a5ed34c32af345bc32e412e08b6ca9b656a6928519655ec9769cf1dae7c985505a812ee44bb3b42ecbec911beced8fe87365f113aac00a659c0eb37bfe7536f9176afe9c459a08ae23600d4c8543ef3c3af4cd1011e08fdcf199ba49024f08808c475986870561d6a088b79c38ae8ce0e6ec40268bc9fb7a3b618587f55fbcd31cea9370243865492e5f13c9fdad61f40b32d3a915194244949add15026c0ae19f52ad5b70365e77f2cf53298c9e2bad06171b0908df26b22ef1c737c3b321395ffcdb71c8228fe9de027f0d310686b1683a67419ea08971cf0bf1a3e5a1072724834601d5f944fa23f77d8e77e887f88ddbeeb1`,

				},
				{
				hashAlgo: 'sha-224',
				Msg: `8710a877b7a4c2e578793bd3e4d19cb56de97fcd1f2af5fb25a326d68fb737fb521371a690e49f7f1a46b7b634ffbd51986de5c5bdbdf8c4585ef85724b5072cde13853194e47962202932def0282e4108613a2e49c5db2bf323edb269e38a8434f62d414b0d17369109f276a0b3b52cc5aec72f4baa67d7fdd94b10e6a787ac`,
				S: `a78358ef28303deba1bf1bc3cae59ab0ff6614c520eeb7d8c8fd5ced34da7454ad140b539ef75e2d65dd891ebf899a88ada25bcc35726053da68e2e02b6acd2e7e21cb8b37355d19bd4c3e36a8c1647e1a384c8ad2ab39bd22f3d30f0f9dd685fe4dd7f836ec46bbcef0805d08a784a6964cd50f58071ed79f882491a331b445390b43f2a295a13a28ce0f44bb6d63f319d8de90e39017f4cbc14533da33380f553f097e796a671ba29c94582cd519f1f64db3be894b6615f6844ff2fc62101382b044f5856b9bb97871cf137c4e9e484e84a3cd2daea8e1c6358d66cd8326c1925ce1f7d2d2e90457adaa65ec3a67f4865bf6120effa06a79deb6b6ca9f85c9dd967f2f31a22d5db25b15530a9e850aca486bc0cac2be6b0af66ecb568c0955a30495bdd5d05a220cd06cb06f04f216076aaad4382a94040dccda68a19d55b49338c9315aa802910655fe9394aa73590a6b2a0439bbef5ec7ccb520f2c5cb71d393a6cce25bf77d8033444fb3da8ac861c63dc2561ffdcce8c2065b35b5c83b`,

				},
				{
				hashAlgo: 'sha-256',
				Msg: `bcf6074333a7ede592ffc9ecf1c51181287e0a69363f467de4bf6b5aa5b03759c150c1c2b23b023cce8393882702b86fb0ef9ef9a1b0e1e01cef514410f0f6a05e2252fd3af4e566d4e9f79b38ef910a73edcdfaf89b4f0a429614dabab46b08da94405e937aa049ec5a7a8ded33a338bb9f1dd404a799e19ddb3a836aa39c77`,
				S: `d1d21b8dfa55f0681e8fa86135cf292d71b7669713c291d8f8dc246464de3bbb961b596dfc8fda6c823c384008d05bcb3dccc36accf1b2bede1a95e52258d7d1bdf1fc44e18072abd45c1392015ee71692690ef8cdaaed337dd8546783f961bb9620eb5c7b8b6716e8c600351fab7765ee38a15d32d8a2c0949825c49a7f25eedd9be7b807bbfd517913786620d249823dae6fe2fd39ac639dd74821b0c120b42f31c2c639d2c61b395f09f86851bc809b34c4981ac65cf25b2e8adcbce190ef2ef67a0189039c9110f26701c3eed731c8d9ead178220ffcac7f0f678aa22268e1d01942ec51e80eef06e2112830855e87bafe8cc9c22fd737c7abbca5eb7a221d3835a86610d24b507b5dcb4618aa421f63a5609ef5d68f5760fddf970135602efad0851bbff98fe87fa58bc365f38ee7ec8ef5aab17fd11d89d91ef4c604e0d1f001d0e08869df9225e3b4cef52ff86815e13b3efdf45776f9353769a8a51fe7d891a7ef7035eecfa259848738376886edc91cc78f6da31c2f07ee362c3d82`,

				},
				{
				hashAlgo: 'sha-256',
				Msg: `2bcad6e744f2490ba6a6e0722832417ebd910f9146eb62baaa5c749529f79d6ced0b81a2e2a48852c8558e338735dcbfc2285794ae60f81a25237c66f6ce5d5e801a001e7f9e309b2595cb866de2bb74ac51283b6820ec9f6ebe482e1fd2d5680b7fbd23c1e62a2ee4edff35823fc7e4a295ea4f1c332792aeb53eb44b0bedd2`,
				S: `37d960fe391298bbdc223fa1eb1d3cd9a46ba8c62e1da8c563c89a8f0e67b864fc89837ffc08aab7122b84c435c7f9406e165a1029857c1e4dea653569277273b1d9b0a9f5b0dc24afdd214476d47208ad5221a7d793cab80671fb4987c86bd6144880c59d24871400f64bdc6d496dbd497f3dbf642864fe49af3e21515e62d60f0071db4884f49670eaa9e4e4982f269abe724244288859c2adf60a09faaabb07990e09e56de254babbee14be7eb6eda0cdb22f3d0de8724804673fb99f86efb4263dcc5017abc91bd9cd833679475bfac50a2be8db86296bbf8017889357371314604e83d68b6efecd4b79f0a8afa0dffa448fb7fce6d344709a670e0cff432c3e187bcff7fdc4f4e9abe1095c46b01d88b6044bb950e92859010d9a0e3b2d1f27a096eacaa24263a2a0523d6e0da1fba8af768196f7a51f92fdf152bef062dd1f8327cee1d344c200c2115ac6ec1dd8514cef9e36d0ce8c32e58783c4fcba901aa70c2b42966488002ff171d36414a144bf46775183a8815de9ee3e81f31b`,

				},
				{
				hashAlgo: 'sha-256',
				Msg: `c3978bd050d46da4a79227d8270a2202953482875930fb1aeae4e67f87e79495289de293b4a40d92746fc84cc8318c2318fd30650e2bb9ce02fd734eb683410d44bb31ad54fd53cf9296ccd860b426f5c782ea5cb49371d56184f77911ddf1ba0039a0a49aa7e763eb4f5a04575997808b0ad9f6b330ca38edc19989febf4da5`,
				S: `9aed20a8bdaf26f1f119020d8f3ea6ce915138d4c87dce025e7f4e49536c8ec079edc6caf0d603bf42bd6a454a6d52d0d99fd0f59ffb3b22e9e67b3d0bb2d275d9aedc6da96a72cbff35c43e7f39a996fa8a6d338a0725f785254fe91a20834ba557fedfe7152b9956feddfd941741eff9177c2fbb55e200bbe42162b32a940cc300ab375557dffd48dfa539f50edd52df158d9072d14982e96303bc612c2c2506dbca3a939d626d2e7fb444c6ad7d8d9f3bba8210b2ac2f696783c349fc5280c105402a4b3d86bef5026c3dd999e3b22380f9dcce40e3a9cc9f1d7bc38ef3dd7e9413bb579800c0e6c3e9ab912da8fec1a4ab21398e9680ba0d04f3b4c8d53c02f05c7ae49b70a5611cf82e38de84aa8c2426f0b63ea01b289f201d3af40dad5d6e5bccc75b9959e5c9758e79105af7a9afb12aee577cb3991879db0fd8662c5bc49022752498a301d95f4b1d08c01ebc313f89c00b1ec2735a07983fd528e6388245036f0ed4a2dbb65dd33ab7f124c014ec1679f1c2f11edffb93fa2d1d73`,

				},
				{
				hashAlgo: 'sha-256',
				Msg: `0c119502c2a01920a090e43357e7b28e33c7ee858b4330e05c71048931c0ed88468ca931ecf0b79c2fdc1756b7675156ec66b8335e3df09463f5aee7028fbf560f984cf698fe5c4280229ac96a2e5923d8a9d5299449bb665008ecc889797e9bb15d04b88c7210fadb8bf6f238e5d2dc41b9ccd1f80e9a3e6ad147948f273341`,
				S: `8abf2a30774e6e7338eca09cccaca3684399940492fb94b23b5ad62ce3e11d2dbef8966ba5269979eb9653baad719516d3e8399079a2f670275a2ed42c820a9a31fcd703a76637e0d713f32d792b9ae36d7288f60c2d1ae52683bb15941b1cd890d2cd64998b772585e76032a1702e0652cbf259a1ceae695d40cf2f4f6d81341c8bc9082cb96c752c355dfbe296dd21d69846fa37613e73817b2a07046658c9e3fc6d091e17591bb1a4fb6e2ac00a3194c1488e16a9d2903786db86ae90e96acb4de9901aaf1b0651fb76a58dcb3db473efbfb831ef8e30f89967ddd3a6c2f18979a0450657cdaeef6e59377c6db1ec46065f614024a69c518a559942594a46266e0d3ca1334296b968a23a4b11c63a97e29eb16b24c02d545d5b427e6aa585333318e63a204524e0e42ac1edb70d3456780dbead31f785f0b2a77ffeb0d37384cb5f65b4e36ca241f3b2b059105faaa3222d6c135ea5a36651aea396d22fc4ea1b404d7e834b6df1fb838bb5ba0d784a96e2ae2843db3eeea496c7ad2b4241`,

				},
				{
				hashAlgo: 'sha-256',
				Msg: `ddbd8468bdb036f4799f428bc8b4374ed9b7cde541337ac439d441ac0614cb75b816b80c17d237b8db73d4a11bfd929208333afedbb8f2410c741129c53932b596a7881c6a4d7111ba104d4600d1902f6f4a1608e139b71911c11c390a0dd091df369aa29d670b8a7e3f53825f7659ac74c40a0c3bfef0d3ae8307e4bdd6cd91`,
				S: `4e377e2459815d5b33915fa63cd477b5be7c6b7f7814d1350034ce710be67ed69139db622ef60ec6b7638e94b202368bac631e057702b0e6487b324a6b98ed7e03d1f3f20a9814b00e217a4648e4bbc449a2af405ca4b59f8438ddfd75d34d1064e58bfb325c55bd54ea6cdf7712ba807c3e4c665d620cd59513d7bc0855247eb670ecc292509661812702703275d9b2f87ef279d7700e69d995db98144a14c81774a4cd890ec03d13f858f3769e5048ed55caa81201e8785d3771ce6da51175d017d211fa703794416f469b1129d731abde744da5b2facd7a9b093d6c9743509b0103bab9c81c6e5f38bc9718e3e4faa86475d13725a829ac61df8d15f0b27cb40d0eba0b246b9c360b569b81b3abf380eec27492316bc292e5150ee0607219a2bd80ba984c7e3f1989bc51e4c5da3ae5070676e0c150d037a86a0f91bfc07cde64c19f9c7a7af44d6929970041448d3b17c249d5e0b5862e9a25209e8f97d7a0f030181504fead2266c873fd235983df3d0657b92096e2b490df33ca115733`,

				},
				{
				hashAlgo: 'sha-256',
				Msg: `f996f3adc2aba505ad4ae52bc5a43371a33d0f28e1950b66d208240670f352ef96185e9a7044f4ce2f2ff9ae01a31ef640e0b682e940c5105117594613dd1df74d8f2ba20c52223b045a782e850a12a2aa5c12fad484f1a256d0cd0872d304e885c201cd7e1e56d594930bb4392136fb4979cc9b88aab7a44bfc2953751c2f4c`,
				S: `30b348624faa9985fcd95f9c7ead3afe6456badf8c0fedbdadb3a9003a6702973acdb4e86652367db23e0a8141880d6631834f9f171c94a8fe9c315bcb8680ecfb5a4f59b45d4e4c3c05828b7faaa8e4234aada4e766646cc510d07b42bd3883a83b5bcb92d9e7cc1ddf590a690111bfc62a51af7e55543ea5188c92453d41d3e8fdabee3e1defa9d0afdb85c8153a5019ae45563ea3080a3022668168f0c273a6db1afadcd5edbca5021c2e53f4d951c604206ae10f287f451867271d370482791cdfdcb6a4010f6b3d9b928563d168da19f1c1e570f8c158f3d490b29aa23abd1ffdf20866c34c6e63b9e8a9a02d7a1b196d055f4c53ce82b400e4ab9e1b9d70d0049d6d57cf0a4949cfc68d633882882dcfdfc50cf449df10acf20305c2aa43bda10fd8a10b4ecaa23100aa47e92936dce1bfb8d6595235bbfe2c8585cb1647b2beacb1e1d4b6cef758811a68330fa9c3a82573c08fa2cda5a03f3425554e45d98c1645c5bd27d12e6c20b2c462a746e882a3421a7b1b1e25b4c36c8b16a1`,

				},
				{
				hashAlgo: 'sha-256',
				Msg: `6ace052d7e99cd973bb5c9f6679b1c305e07208965fe58c63b10a692f1dbbe22fcd0db15893ab19e107ba2e42c9934a9aafac32adf6c73473f6969e42c983b8f0c96a4639ef77d2c8e88e8cc47d7cfdd08f68d973a7beaf401cb4d1311992ddac3a9c9e067da198adc6304745f5dd312a182e6971c34a515a6c1bae647e57e4c`,
				S: `5f0e74f454754a3074faafc605f3c9af47604a8983650a9b6211fb191d9afa5315df4db4501fd4f04c741d764656d4a5d006388ad8fdb219ec6b756908e23b30cb639ffa7bbf2874713bfd5a1062c19d04e0e4a74b14446a7fdf5cb812e9ac7b6012d9ae991c47656d2aded24074bb8a38b1a88b1c2b131e5b09c93757fdb2d6b69aa8265a435fba00aeb36a1f629bc34b876089d28a948dd6ab4c899430da60a26f6c13603fc889c7b2936ca3c5156bd7fa6e34eac9e04800833ef0cb9b6eef788c0ef0021a4536fb8371fa3e2c8bb8befac16e8092d69c571c1e15fd255ec0a07acf9ae9953831efd3dcbef44e0fccebb1af959d71f50130e8acb4fa2319261fba12f2715def82bfafbf40e345ec5dcdab5c1bf5f66b1d0e9f7a9c62c9375746e1ae0c8f14a489184383e81dce2070ad4b525df76b446b1f22921d424d9ba3ce21577501df6280fdc69f0239ae1127b69950759d5f0b693f54e87e0763623bf5d3ff69430081b9c9e2445a05e115675e090bcab2aa1d75ceee2ad619ec8b80`,

				},
				{
				hashAlgo: 'sha-256',
				Msg: `0e49740fdcca6bfce294c11f45407805b3da412b01ef3fb513e70e62fd9504c0670db69c36b6bebd69a0bcd240179ba8a47816a0c3437a61fb72adcaf9096f2a22efe0b431fc422d225301e850f2f0f4da87d6944a8529ef79781909ad96d1f20596f93e17c57fb4d756974bbbf900521cb089eee0ded5c956a15b096162b07f`,
				S: `7bbb3ddd17a42be7cc4e7eaf456509a4ba58d40c49a3d99573b733e1942f9fca20ba8b910708d6e750367e847302fc603b8063c19af883e7507fb0d9cc2be37479a37cca25b8c7c46f6bf661dc6a3232f88b483f1b8f41b46d49ba3f1795d68eaad4a2556fb5d7873bbb6501ecf06ac558235ed13990b0e16f67965b09366bcb362cfc6fb978f4f68d8146dc8b819804df424e8ca5b63cf1fcf97bbf300d0b998860798a63424383fcd81d37773d59bb13b4fa5d468cd128bbab18a8ce5173be5d9d54d3177f0245788409973df4a9016b944baefbf3bf1146a9393d22e35ec2be0ae6f4c31dc4981f40fc1baf382600699eafcea92cbe24e26ee846fa23bc193b6e721401b7ac3f5f4ebeb633979f8ef35f4ab1117a869d5b9dbb7482f0d5a59e4163548d2512ae067205b57d030c483f720d2c44350428f5268943fc5f6ea1c88e2ec13ab3dc1456e96a3b8e7c121af4d6a5fe4ee55e99fbc3592a487c194bc2f2bf6e79fb79c2876cf3365e075beeacc7db4db7ee69e7f1fe12a327e6cb0f`,

				},
				{
				hashAlgo: 'sha-256',
				Msg: `0e675dac9aec910106a6ab219b4cceb52ded2549e899c9a24d5ee55177761888a3be1a2def6aa32d62f788132d6227d9309806fdc02db7d8a850ff2c6dff37fcd777f1a0acefdf18bf85f1a12979be86d799253945fc34a288f348b7923d764db27a2a2d5ae20e6b25372ef318f8596529d8ca23fd6f08a8f62e0a1b6d989f23`,
				S: `8052d95f12ce0e6e53a5a356a0eb353bdcc1a66514d6cfb3a3d96155310bdda0a0d1795f97643f3a4496634f2dd9b95a2138ee390e1e74be3134f3f47a919ee7b59f8ecd272ab88c82cbce7c217e5f92d057a5b00fbf0575cdaecd7dc285a4218c8a955216598f0742671e018e8e4e76839a575f50b2102a8b77d1b84f6dce98d78e5758e0a6f92bf35d6a2f18ad400925d7880f9efc774a8c7ebf64885cd2f6f629b54a7c12ec91d39b3c2518241fdc322d9b235a8ea44f77e82f3dc4f728f620c07d1e7ff4094f29c674ab0f0802efa1c9e6481ebb84e0bf13ef468d8cca114570b9edcddf98ac4a834fe7a0d5c6fae8a60a48399f3c8af42ff4026e42a81aac36114ffc053f3f729b7cf9a97a56848ebea0115aa8298341aa226963ebdf57ab2d8e4b9000dd051a6c5d69f60e1dc1b33f2094fdbf8e5b627bc0764db9522cbbc081dbf38c21b13f980813bd2b00c757ebb8c0b21213152e694039f306f7342857651f722bdda01212a8552799bda6ef07c5207dc744ef7969afd5af2e6f12`,

				},
				{
				hashAlgo: 'sha-256',
				Msg: `f6a7a6e52659125fbbc8727417283b9a64441f87121e27f386d5019f10cc9b961e09f1b3b0db23630cc0caacb3858c6f93afeeea7e1a6a80dbe0c2bd9c7c939570302dec39a4a25cc0cf1d32a71a75b9a0c302bcdd80b046c86651acf30838cd52e30399a8fab8d03fbd140cdc2f1f02f2480405169820ccb32e5974ffb8b1c8`,
				S: `84603acbfe1f2f769f1a62b0f287f306940b225476714a4b6827c02d7bd052f303f30a5fa6da83e60615305669ca9ec177c5b32b1415eebef78620296ebad6dbbd520839d3aacc9781ac8602ddce0736dcfa7290b45f155b8e924d0afdf7dfc8d199bf09509d0176a68b145756eef53de456e17078859849a352a5bb654239d8ebaf8800ca8263d34a868d52bf8f22644dd9f3c05bd891cd92f263530c5896023c6b213ddb64ede1770ff1686c34036e281e911d9dc960354fd844cb7b22dc0cd81a96203ba818401ccc225f857e59a5cb7ba6dfc7f5135ea32781e63daa14fbda1bacc18ebc50824d4028b8fdecda49e810bae5acc8adc0dca2e236fc832a97330a1214fa0aed15cd10c049efb65ce855c060f05befb317b8065843c4eb5a0371fc6f209f6ffb948c881f2f2091caf0f59f60b72c5f67271bae96b913fd21fa1dfa975d5ecd62b0d50873b686d29c880d36edcad33ec3e2216c9cfcfb4f984c23fde815e280a802428608bed3739af9200de1f85edee2834c04942c068aacd2`,

				},
				{
				hashAlgo: 'sha-384',
				Msg: `bb294b95d913005b110987cde45887484ae6df794873dfc5c41fb7e8992c2fdce70699fcac8004699961b3ad1e1fce9ec8ea5685ccec5e80e4d0792559816f68613434bfaca81a843aac459a6fe35f5369c48e9191e4a32c70789594c5152db8d4bb02260012a8739cf325ddff2aa42fd67b6ee5bfe31591131ff27d0273d292`,
				S: `32637c60798b450bff100bff12838357deff281d5b31e4f4c2cfc96eb779ce6d31b1ce8bd7aa7fa88ddc4279c8c3280604b018ccf452004a1488ed4750181c5025636511ac6724fe51761c27d7cf9a0c8782ea2231268853c4b1f7acb0005e5687c8f3df16c962f02ce56b23d387a2baadc8bec94229c3557526e61707a8b59293a976e32c7fa133285088f3ce3e677788aaa947e7622c757e844b117592be99fe45376f8b3013e8772ec92c5bb0b9fa301b95544599690ad93668d83b2daa7df05c66214e275014780a912d8b1932d7a655058e743f50b074b1d9691ca23a2f95f6affbd516d64ccb2aa43c236eb95d36d272545e3beb8ff5aacd95b30f7f1d6418af042cd9a0cf0189846262322a18875ae4c3e68e4e8ffaa0276cdd99a0047c86c0f71d2deefd50642d29c195e6d14fb46fbac33a508c1f03a232de08aae09faf1da8ed2ba2ae84bcca88b78dccbde9afde08a3beb322dc79356b29c84841698914b050beb75a7b2f6701aa8101a5a4955ee27bafe81b21d03b43e3c77398`,

				},
				{
				hashAlgo: 'sha-384',
				Msg: `f946c6bd5e1d6b89092f3c487c0568fa07c356fae9b8e831b8320289039746a435b122cfbc4a0d316bf90d481d3b7d979cc50d98c1190af8dc58e0035557dd5e94f437f41fab513202643a77748f76c6b77302bf40c392cd18731da082c99bdedeb70e15cd68bff59619cabcc92adcf122753c55afde0817352bc247d1170b8d`,
				S: `50706ba49d9a316688a3ee80a0bd986757d43ec83285af9e78196bd52c900d40b280fa0de54e35ace7d6660012f1a66204092f0e634b97e0e51665b4075e36f1422266c7cad7b2d9981b913df3fa3e6a5a1cadfc6378a8540e0faa26f1cc6fb2fb492a80d0a6945bce5bbc23ddb3b10701f0249b27407a6700802e8842ef3cc761c4823acb5d1453508dcdbb979e7bd8d00128e60a9b3789167c91417d93f0e9fbb00c9af1498e09eb6485eb94cea4883f6a256eab2caa826de4fdac01baca3a216e3d204a3d837ffd4d0be2b2cef711909054c4da1d5b93a8f98451c7002ae84a5e7080d98671c50e3c91c4087d0477b104f916010e742f2d207fb40d122d8f211af6d7c5eca49542d9acb0f166e36abc37155070c12e9f28b907d67a2ca70bfce554e1c44c91520e98fc9ad0c0ee477f750516476a94168066ce47000030a99c23e2c38755de946d5edf0d6aa94212f992315b248c1f82723b29c42216c78cdcb668f11278261cee9252c8fd0ed37d0a8580ca9b9fde7505615943712da19a`,

				},
				{
				hashAlgo: 'sha-384',
				Msg: `9a337d4c0bb9a005b47f4765d696d19dec58bc8482f2173a4a203a0b6d38b4961f6a852e76468e807c7e457683eead5cb8d98642fb76c0a1eeab36414c1899597d57aaf96782ada586f61a423f57953771d520cc4ead90d569f23d950f8dfedddb8355748576e6bbfb6f2e91b3da71753fd2f4ea229f6d20e27db8d05e9fcb68`,
				S: `cff7aa7f875642fb9343e07ef5e7303bbf5f069b44c19fbf83e59d422e25267ef9307414b6b1ef61711ed0013276d1a2ad98390474027a0a703bfe8a6e87706059d89c060980c9c9e60dc7e1fb9f777a41785ab4d2b663ba0e3c1921545c479c2a383a50da8e489cb22b71101d0ec148ac70928732a772195a140d080152762a9c40803a39fa2a6978c2a75ac4d8bd1bccaa1f4204ba65edddf32fedf2d9d0a3aed9b06c47e717733c577812d723dba74a852b2905235c812dc5f1d0df0f0de73dfb86221c6ffdd1eda119bbe98d148add36a4fe50489b06aaeefcb5c2066d90fa79738706cd18e474d69609ff1210c77de7cd23ba2a775a4329cb271a826d602c401a71439019cec10cd9f184c4d04584211827b19eadac3258d8a0f2631613f051aae0c613050cb24442f15ed4fe0dbd290e42629141bd2cd56d20584a1d10e1f2c2a9ec731433d5bcd1d318bed5243b4b7d0f9a7982061c55dfaa86b2c01845c021fdd2a978d42034212f43b3351b6adeb03bdd6caf7de059502f16d77348`,

				},
				{
				hashAlgo: 'sha-384',
				Msg: `32fd45e73f6f6949f20cab78c0cc31d814baea6389546a365d35f54f23f1d995b74101187760c89bb0b40b5057b182e2fafb50b8f5cad879e993d3cb6ae59f61f891da34310d3010441a7153a9a5e7f210ebe6bc97e1a4e33fd34bb8a14b4db6dd34f8c2d43f4ab19786060b1e70070e3ed4d5f6d561767c483d879d2fec8b9c`,
				S: `c389613717ec7476ecda2144d0e8c8f9d66fb469c167c4209ec0bdeebfb471665d33dad47b8f3c319a76fe8a8a9f662b6c690b74903d17f61e2314e5ea8d26670ee4db4dad295b277ca08ade880de2e42d12b92952764c1dc808c266dbbedb670158eef36e896f55a203fb99556ded0597410ba37486b1d841f3d6d5c0b39f2f49f0c5794824fba94a8ec7c2b2c91eadd5c8cbe44895fe3be3bc1727d6fc0e5364f53578639d3b3af696b750a07853694ffe145a28c03620c78dd7377d094d92c3e09546883d4703e62a98ddf81fd01fcdf3c4b215224fe2b1b4992abf31f20d12afa868202390de334a846b2d58b253ea8ab3c5265d84773a659e8bac7af44123d9ea15062e65d4d419cf2d97077d0624f8e5c36f2c7b35ccf95435d5c36886ff9105a6c1ea225e15ea8cbc7b6bf6856151cd76fbb75b5b98f0e3db516a8e218189fcb1cd5de3cafeaa33ef135c5d8b8aa5f881afaacaf4c08bd7281255bc2a33b76d4a36e0b170c45588239e5b38c679b08cf802af73b6d79b3935949461e7`,

				},
				{
				hashAlgo: 'sha-384',
				Msg: `ab66cc487ec951f2119d6e0fa17a6d8feb7d07149bec7db20718e4f31d88c01f9a53d5ba7ece3a4dbc67af6a35d130eae762cb7962b9ae557ca38452464002223f61bcd3c7353e99d62558ceedfcb9374d4bbf89680c8e2b9585603e076f1cdb0058299b4246845dc79d1043b1422efe84018e4c932c45beb8851fbf485e36d2`,
				S: `b51331552b08be35a1698aa6203d84dbfff9001ed5dd776f2be4ddfc07dd4620e9654e82a33465bd20f11863c0ed02a0aea27a44d414c328a938bf877e15838ab99d670d01414262e8865dc1d9fc30fd0812699fa690c34f302f637ec802cd40ac8591e976c0b8bccb1b0137af64a2870210e8fa3dc431fe0956b8addff1e4b18cf07e078aa93af81bb3023c9e594e66595fd92b10226ea126005f4724427352c38e9e85fc2e0723f80af1f61599550b5ef54c5b38ca405738017b89cb9468d9741cd6bdf7112162251ba1d083cc370a4a8261c39b6b94bf21a53b7564531ae9ebc4ccea7ebb8bd314b2e13b58ed1018ae5b415e0f9e3e19a5ead3a44603f90674a190febde25f8ad8778aeead4d0f64fbae37166a54e3a763e35559bf8c3f173f19ff7bab98f3ef803dd56c07628399aff87485ee73dbc3db34ecc7bff3a53226cf87bc81d256e80c09520c8f38e9bcda095e3635128e1bedd9970600546a751eb11dab42e289d6fdfea04bd58d4571a79d24bce4508c54e1ec4cf75b985fd3`,

				},
				{
				hashAlgo: 'sha-384',
				Msg: `fef7fe89b9a59902a70a1d9caad09ced8bee4145edcbe3ef7fa6dab37635129f3b8c5e0860410ecbd9cec3d8693682f25aec08b071f05dc8213bac8cff5d52b576653560bc01575604e6ab90f67227fb5c901a781eddc027700913e54a7fe51318482c9ab42c9d2b911b7ccc39ccb290f9a420a5dad93394d4d7b8c53fe3f242`,
				S: `45068ca6d82f2c123925cde11971215d8fa4a4df6848bb7654868700978764854638921bea5869280dc6ad9581ab43ff7012969948a5677fa0a66136a316a4bfecb89adf4131b5bedf3d4693b780d133af9bf9c133305be78374afda3ba3854203324481a9d10b9ca9b92dc7d74df531872ddfc76caa82de020e2c415643cbcc4280e6d2f4371fda7d9249314a8f437648991a9b03d71b5839ad38a1555ad34526994ba56870b6ea18011295f2ca2b0713b2e92ad77680c0dc5bed8d3b9b31ac14df769949c4a43ea67f6deeb3dc9ed589ea4e8a2cf6695df46f946f1467b28e875477ae4e645080fafda6dd551d2c02fd6b2b194fc0bdb050e06d4c784105f5a33b53e73098055963071efc1bf397fd325f3a6f4e10d76f0411a001e62ec73729018316f56310f893a59363d1f6fe5c17444b6c728a4933b75212fdfa258e4018b7763951ab4e5096411df9e5bc16df3896e46c973d32ac9276a4e2b5b80e3d8d798dc0470b45096b4d738669ce052ed818e560af1e92c915187d66cc308b70`,

				},
				{
				hashAlgo: 'sha-384',
				Msg: `82b3840eeb95c9c57724c70f112b6c2dc617c31785acd0c823f8bcdda285325eb3d308dc790522bc90db93d24ee0063249e55d4219ad97145feaf7f30668623cc8890a70f4f149866f82cf86f98b0053b23c98c8dd5e9107e341460e9bf5d88cc8bcd1f2e4c007cc1c02c4529b93233a0b06bdd15925854ab9e3f156eb925bf5`,
				S: `0593b9fd4421452376d27bc7a280101cfd6e88a6727d7d77cf65ceb723ecd257f32fe10277e85798e0da75917736da1a3bfc22adc7658fbb84da6ebea0b07d1cc405732fb040b585c1b63c8034069bffb8220656f1ac54ce693720d6fb1b5aec67b03c887c8077da148d10f48af7c028f992b18f13c0e57530c086d775483da5f66f3a6a19187868340ac63c6212bcbd6cbb7beda8620afd9b66de47473ef24d1b6a36f4ece9add49514fdf1d84c7a785b7f0e00f382235899790f472d13f48558a4314742f376808dec96edd2e229e943f7b983bea5ec6edfa5e9bb37f588e55ef62ebc9214beaf9da502434e1088df272c6c77c1e1d897c47beab77e3bbe317f8d43d21fd7e94337c7e263e2867bf580a2a8ecb9e36ab7d3e1d5cf9a23230953d59df0d7e23558fb612b7918abba31b164ce178818a1a9e6b6687f4de685d70e16bef6e192faedfe0b2b95477d37b0a3a2d002f33ef4321cb905040ce06fda1c98a008767fbc781a1eaf3375dab8664b590336b99e157b8687a6602fef6a3b`,

				},
				{
				hashAlgo: 'sha-384',
				Msg: `e153cca4431ed9713f4744ba054f5f191cb37b280108ae3a114ad349a872d1308b46211a83758a3b4be32fbeac42ccfee7e23df853ca400147077bb43a44c12f299b917f3aabdf589eeb1709bb3d60b08bc71eaa3ffeba4e2903a5dbd8339aae85fa24b9aee76130000605857a6aa197d00926270dcda58b7de758a6ca67e617`,
				S: `a835cd4146bef465642d494936268a311a5490d2c9f9166c6ce98216a9a23a643597300a0050e6445abd5a9bfc7a2d9b70726c824c383bf5acaddddc34d434a31e5314d25fb58e258f518866c136e52855c16fe64ff8f1c4d66c4e9e39b8cb1196d80944d0746c0a3e1769cd4167df72ab5e4c9dbae9cb35f4828e12099f9b36a5a70c48d4aec9872d7b19e1291b33cbdf08a2263d500c0a83b5237ef6ce92de344b3b41d0d07404fcd5467b046b52b8f85fc6b5d7afc437f1ee9e78390ca9bb6cec618885ece29758f2fd6f4e5f4f896935de5f67cc04055a4c4c0fba5def8d2caa179331a85501ed25822ae79da9bc815cc39c6a979211083e8683136c942e1e17e9eb8f84aacf091aa1e51665fae446bc48c304af65391f279afb98b92e04c2b73d9d94e991198fe7781f0f9696fcba2c03485f76e6de30b9535cf3903db2f3afa851a47bcde72d4ed2e8fabf9bb7d4696cb4ab8c289b0c21e1f979ebc532e280cd9010df4ee72f84bb9e82752828f167030c0fe348ebc31ec17b8f07d94b`,

				},
				{
				hashAlgo: 'sha-384',
				Msg: `9c63899dfc7bdc0db384727244caf71ecfb9b8792b9f57e936b3c2f5695565a9b0979f3c78fd73f00981813a16da342392fe3ceec6e63ffba191cbeb4f4b90050d2fccd83beb0622b2c3fff159d9e608f3abcb843bdd56c03339b975b9f4e3265b32f6bb6ccdfc6c5752d6e0344d749699c74c85b30c04ff95b272dbcfd6c7d3`,
				S: `4d38a297302ad0770d9729ce5b7212eef287ce0250f403e32b4acc3617dc0d2edcccc2d580ddbdbca5722b70704058a3b807f592e400bd563fcaa8b066a614b4906f1433968ed2f520a2f6b034d4b2d6890a241afd1adb8639a6cad9dbfd2e278dfebf79740d75f295759d29130b19ab19983dd68f779de41ffefd4e82b5e62f72f90efb73437f08a2503dd9819dae20ba9706c199de9cf884433eeb756286a85eae14bf9f6dbeb705461d91822282f18efbb10589a578f2c9c345b079a7e9dd07fd4b34051b27119729906c77dfb7d2f8fa6bdd5faa1e132bfba9d391e66395e67f01353fa275eace8b53aa91cb6fb693e19191d42a4c1a85a0c504b1c85f49a4d60936dee4646aca62a94aa4bc7828c1ffafde8be656317d506abec179cc90191d12356ff50644d3e01aa5bcfdd71d3c828dc3539dc0cf3fe8b9b91e0c2524f6a3710379c90affd0d0a50d74387f9ca88b46463ef1bdba58cc9a36e5c2c435a20d968350d15d941c3212cdce815592b310d259860de1dc1a3d70ac22302a51`,

				},
				{
				hashAlgo: 'sha-384',
				Msg: `04846c2e676ac73160bf4e45652bdc6cc4d4c9284577b4320ab77f6ebbb59a1fe0e085588e0f90b346cde6441af3c9d0117d1f3bcd962e406bf5a465ab6cda2d51be598fcbb29ea713651aacd7e47d22d8fa3450904730f51792ea374761a4dc1fc6f1bc657b77768f31f463e4267fc8dff61150d4b343b9d53759cdd7b98094`,
				S: `103bee57e25be8c3a2f774e739b47f93435e414932c0494b6b6aa2475bf7c9305c73747e0adf82c2032007b3f75a69c93112617a62566c5a2deaa25fb95209da49fe9c161cb2ffa40fd9d77f1ff660c8b6cd3b54e3e79a759c57c5719802c9311db704ba3c67b4a3113754a41b8da59c645be3909e7db7e7cf7294dab44f74240f81a281eecd6ef31c7cf18b1a19c7d02a312b91d6edfaa954462d34740af5ab708db5a10b00c542be82fa2b2026b09ef38a4001457e27a6023770e4b4d5003267c85c9eea1d5f8d770bd40b554d5b4daf146dccabac3ea8a13a05c3bddfc971c5158fac027ca19b7232621e9d2e37b6a655af545e44a298be78cd475c22a48bff7c3494a5f8a6abdf1a46f9de082e374fd598867d61e4d51daed84152e43cc6a2affae205edc52613480d411aba84fcc9b69d1c28f16f76836901a7c5b3eb2f2c940d0a3fad38a8efab968a0c85eb22e11d3d0861136ced5f06734fdf8d4f151d23861b1cba9b9c580d3350c76d4dc808461d5f872ec548b2b427dff74b1d1a`,

				},
				{
				hashAlgo: 'sha-512',
				Msg: `db6c9d4badb1d9b74d68346448b4d5340631783b5a35ac2458563ed0672cf54197587fb734c4ac189b2dda954cdfb18b41c010a77e90464eea6f863c5da0956bfa8cc636bf0a28be5addfe8d3e7e6f79f71d7fcbbae23ea141783f91d6cc4c8fad125811760ab57133818892471a79c6d04eafef37b2fbe506785318f9398377`,
				S: `d480d5a979ad1a0c4ca329ebd88a4aa6948a8cf66a3c0bfee2254409c53054d6fff59f72a46f02c668146a144f8f2ba7c4e6b4de31400eba00ae3ee87589dcb6ea139e70f7704f691bc37d722f62bb3b2cd303a34d92fde4deb54a64dd39184382d59ccaf0c07a7ea4107d0808260ed8d421cb8b1407cdf9e915159282b9f7bffdbf40d877885da7399edebd300a7e77a908f756659a1824f95c8a812aa540ebaa64ab54a233723db55caa8b4466ea9ae6614ad1bb869e9d8e0d032f3901671e94c0b673be6537cd54278ed3da2e1edbc04ee3a9e8070d73ba0ffb93e60f30b87ff3862e9c53908f2c8e99915668c1f46635e05bf7163051ff9d92bc71a626553c69dfdd06a49f7ff1ed51e918f3ed801dae62ca276d7063d72a6ebc136ba06cfedf5aa23277e81008c63b2e0083d0fd6814f6d4b4b40a42e8c0206f3c356a5ec709b7c8a4b74b7b48d53c9d8694d27359c2c7701938d2f0161721a57313bb1a2e11da215872498182493d8517043b4c03f93446aac93830276542026ce83055`,

				},
				{
				hashAlgo: 'sha-512',
				Msg: `d5dd3b6ce9772d9a97fe21648497783bac5bb5254aad82b6f7cbf43b15a40f386eea8d151967db149e9465865968133f246e1347301adad2345d6572ca77c58c150dda09a87b5f4da36b266d1fa7a59ccd2bb2e7d97f8b2315431923530b762e126eacaf5e5ac02ff1aaef819efb373cf0bb196f0e829e8fe1a698b4790a2a05`,
				S: `bf9e8b4f2ae513f73d788958003733dbe20957b147b17c3f4fd6d024e8e83f07b65d9f3dbc3b1fe84da021ceabfccd8c57a014fbe5a2bce3e4051b7d03e09fc0350b6a21fad214ae7a073277c77a40dc44a5aeea5194a756b69c93977b69ee9294360eaa73a574548fa6a974a7cd5a6adcf09e80631156af85a8e5c5317e189eead47e2ead65c381396b5cacde260e937284a8e90eff2cbcb9dee22925f2f7256f74c67cf3ffc7b8ce657e8d135f0f376d9d936a79792c981614d98e3f7d662a4fd46dcda96916b32f366ed27dab188f184b984df0b559710d8ff2040be462f91943501bda4840fdd5c8ec15d189064def756e545db319e007c433f0468a6723357ba47d156ab7652b06ae2b18874f0771c626466dbd6423e6cbc518b5e4ae7b8f15e0f2d0471a9516dfa9591697f742862324d8d103fb631d6c2073d406b65cdee7bda543e2e9ebff9906985d1cb365172ea623ed7aa4c7a322f0984680e34e99bc6231b02e3d14581608bc55bca7fbe22d7f03e904da4552e009e5607f0418`,

				},
				{
				hashAlgo: 'sha-512',
				Msg: `591652b6eb1b52c9bebd583256c2228680110b878917dea5ad69e8c5d2ab514277b0ac31e7e2cceab2e5d9c45d77a41f599b38a832f6b2d8097952be4440d1ff84baf51bd70b64f130aeb686145fcd02953869fb841af7f6e34eaa2b996ccd89697c58fa255cc1e81f621400e14146361e31c709e84a56082231199539f7ede9`,
				S: `1de79d7216dde125deb77c34d90ab321a4de5fb11c296656ad9bf9a24653591117ace415e18eadce92823f31afe56fc8e29494e37cf2ba85abc3bac66e019584799aee234ad5559e21c7fd4ffd24d82649f679b4c05d8c15d3d4574a2e76b1f3ee9f8dec0af60b0ced1be8a19c2fa71bcbc1fb190899ec8556958e0782ace7196b36658656cf364d3773de86260fd8987604ef35eae8f38ec2cb0da864cca719219c2ad71c08506c412ec77995f37439c856977b71dfb9647990ef70faf43273ae60839cd0679ec9aa42bf914e421b797cba218a400ff9dbaa206cb9c2b0596c709a322b73cb82721d79f9db24211bf075a1cef74e8f6d2ba07fe0dc8a60f48af511ad469dcd06e07a4ce68072139c46d8be5e721253c3b18b3c94485ce55c0e7c1cbc39b77bc6bb7e5e9f42b1539e442da857658c9e771ccb86be7397647efbc0ccb2c3ad31ac4e32bf248cc0ced3a4f094526b25631cb50247096129b08a9c2cdfb775978b0feee265a6c41991c1dc4452615b78c906c7ed1bd207969d98d0`,

				},
				{
				hashAlgo: 'sha-512',
				Msg: `8dffaa9151271ad22622f228c892e1d9748b3c394397f2cbb6febeaa9244a027eef28db48a9a660162152764830f617e1ec6ea1cdb0ed25b6f999a107175a16669d6dfc92b16d50363fac4a570371ea976343a55ae124b6301ea935ed655d44f28320899dba35122505933b3371201a2a45f95ae65ab442a9479125e68ed212a`,
				S: `b329aef83a56ddc57cd9a0e15eb0b0b7aea7d78d5e8ca3982bd31cc825a0cd1c444d9f7bea9e7a27f3bbb3761060ff95fee1a3e864d2108fc40b64786a96a6d62d201217e03a8ba2c07ee94c267149d1e72cc5779b737e8547acd6aa4bba3ff38bf9687e9e82f511b597ad7ec1d795c36a98bf83a90fc86b0cad41953360738921936a458674b2e9a7012ac3029fdb0a9d12318202d2544a0d976ee536e03b7e8d894b3b9c762dab0110849cc1eaad747e3d88d7dcf49f824df027e645c0b9294e655d9fc9e1ef95eb53aaff5775c349486d4b5d67dba29b6217f8b9976612b57e16fc1f99983f2af04579938606879b7c7253e870714b4f0f24e26dc8c7a6fceffb5f98e3b2fb5db949d2f98cd1ae1aa552696b48c39f678e154351cc756d3e9a97f79279853ebd0db9ae6859fb2d5721385d06f5565a3a8ff0992d517acda1af69a92854a1b32a79cb9e442a90b055bb2ec3af8d9926a0d857e3cb1e7e4a7300d1accb9492ec7832af453529ff0f4a6ad3259757f707f713aaa5df231f7487`,

				},
				{
				hashAlgo: 'sha-512',
				Msg: `71d4163e708c121e931bb9692b217dddd35c7346f61cfc9591f7a4313abd4a9262af820bd7eb37e78c2b95b89daf25ec8e783aa1d4b78dbb96852433b4d478b109a6d65eed7d06f3fe122b172149eae7c365ced66578ebb7571ec218c36b65d2ee22dcdebb28c66a7138432cbdd712f7fb8bf78cb14860b25c2b4789706b5a1b`,
				S: `2522ee3bda30c0434e54b199da8c9733964fd402b707f5b330f4f754a0502c7a713c7814f0e851a4a4db72690db96ea8b8813bd8629a948bb30c1b8272a816b30a755fc6fb1754167c3eb1f194395907a56cf5a73b4154383a05b78b731fedd9077f3c2267a5cf926697871fe0a4bed9c219552dd1c87aff50613094bcaa2dec42a35380a6bac673da2594f824a8f32f21d7593a3e49c78ee280193a478621d3b095c16dce72935314d4a2323eebe7855ca4738a19b5a31a5f95ab91fbe1289c02fea7a65b91327b7b9790556289e1b988e45d50eb8cea1581de5d5dfd21001c73b43921d8b21b9644b0f2b96ee6b09d73709c33338143d6a2fec559a436c5ec865d3acca5fee654f1325ae57255dfd42188c84dcb1f7c1e86028a74e31d736078741ee97c39a56e4de00fc12b8051835bbd0d8fcae737322099adc1017107022dd15c114da57e78b95681ba9945615b59da90f5a2a99a252eb42b2006eedd6e78476c2905473ee6b4f23c1c5cf0b80451c5426ea009141cb3fcb0df2ded92be`,

				},
				{
				hashAlgo: 'sha-512',
				Msg: `d00e1529228c79a20a1c3668ffa4a54140bb170bc5c669fd7560d9309900175e91d5a0e9c5f5471fdfb714bc385d52b08ff7e4230184d8b735593f0dd8c73b8a49f8595b951a21b6a5bfec63b684f67c0af1b471dda1684e9ba3f241501fe957603dea86784230f0c4fd65666361b82b187330fb4267404c0e059bd4eb52494b`,
				S: `1835dd97e5093a33ce1e62d683863f6b3507f358a62fc879b524350fbc7330681cb0c682eef4330419caf8543bd9269b6d91d8e107ec38b6e9c6eaabf906457205d52a900e05579aa11fc581375264e69a925798e5a348e5a16f1567d5d0e40853380b34deac93ad7377aae8a27b090d0d3a92bf7a824d926e2e35a0c3bd0e990b591120d74dd9b052a73568e3c3f29c5a77fb1c921bce9c1e7f764aa67bac119f5839a5303860edeb634814c2386c831fee6200cf55b6bfea058b795a0fcf26eb7216ae1b7587c82e5685e584170cbddc89a77e0989d4ce5c3c7fdb664aaeaadbce1f231e64798f6f9a85456b5a93a502126a80e2d21f46921cc3601f5ecdbd56998a63b865fce7eb299f76af40e91281bfc019f40e0d46811e383691e4024c94566f18024ff2b22aa7e1270233ff16e92f89c68509ea0be2d34511581d472207d1b65f7ede45133de87a5ffb9262c1ff84088ff04c0183f48467996a94d82ba7510cb0b36cf2548209a50603375cb82e678f51493345ca33f9345ffdf54be9`,

				},
				{
				hashAlgo: 'sha-512',
				Msg: `a35926685561f09f30925e94d74e5661892a2ddd524f751f8321163d611ea1591a08e0dffd46b208e98815a306aa8514b4db859dc1fe7bdcdf50c095554bf8b2f4cb9f884d70e55c2143bc26199c2f94b743f5528dd54689ad69eda660749f5c1bea8becaea632a4bf0c79a577edfcea7baaa6861e9d7f2dd5b4c4f6eb5f3d5f`,
				S: `b1a9c45a264d2c9af441a7b2d330dd788089ccef205d5d666bfe864367be9738124e9d74648ad99160bd3af81a81858babe667a5d95c980fe2f6ac34861eb2ec9b4b4e8b642ef3820f56ca388a556530d42754c47212e9b2f25238a1ef5afe29be63408cf38caa2d23a78824ae0b925975d3e983558df6d2e9b1d34a18b1d973ffaccc745e527ce76c663e903719355e45cd6d118ed0b85b70cbb8e496411353f84f8866a01fadc819ca0ff95bbe2cc68c8cf78da5581becc96247b911d185ed1fae36c4cad26208eb80883f42a08123dac68d88f2f9893cde02ef5a57661db2b3e1e9269cbb0e15c407bcf55d92e679383c90802cd0bffd469646dcb60ca01a1dead43228934018391dd81f8b7e797e527fbe1815b91bf3cd6a1f2ffbf5dd166acd5526761ca8bab5d463fb9fb820659f5cd50f8150f12f7e8d52e77773c1e6480c2cc184d411d641f71a9dedc2c5fc2ec37a2770a9383bfbf6a489cf32b56a12cf99378e39b50bdadb9f0591b2065f9d44e511c9dfb6158fddddd1bc2cece6`,

				},
				{
				hashAlgo: 'sha-512',
				Msg: `1271a0ddb99a0e1e9a501ca33c131b0a1c7820a397790869090fba373703ac38ea00a9a0ddeed199d97be1801ffab45206710a61e5ed894c3319012ded0ff414386e56b548ad915d80afcc2bdb976d7c8adddca7dfa28aeb694033a5612660c644e32f85c2805651d713660a38914d70f0e41fdc4b3d162ef3acd70659eef637`,
				S: `bffd010b2ec4e4a32777b77619b87622f8921dab56e102c8d824fe52b5df7a203fe71799eeafdcc0c8872dba6a374407b5639aeb5a30a904712f15097dba0f2d62e845412395cf09540abd6e10c1a2e23dbf2fe1dfd2b02af4eea47515957fa3738b06411a551f8f8dc4b85ea7f5a3a1e26ccc4498bd64af8038c1da5cbd8e80b3cbacdef1a41ec5af205566c8dd80b2eadaf97dd0aa9833ba3fd0e4b673e2f8960b04eda76161643914242b961e74deae497caf005b00515d78492ec2c2deb60a57b9dce36e68dd82007d942ae7c023e1210f0be8a3eb3f004824074b8f725eaf8ac773e60fbbb7cba9630e88b69c8bcb2d74dbdb29bfff8b22545b80bb634e4c05f73e002a928efd5a6aa45621ce1b032a2244de48f4df4358156678cbe039c9ebe4cee945a25b9038469fe00c3092936a8cff9369045f906733a9d2ab3660182069b157ca8f9b99a71fc153c68301e97a38fc3a87ae2b6f03754e6da82d0b0726e0703979c9320289feefbcddcd9d706b71b51e9a1b9dc1412e6ed4b56676`,

				},
				{
				hashAlgo: 'sha-512',
				Msg: `f30c783b4eaeb465767fa1b96d0af52435d85fab912b6aba10efa5b946ed01e15d427a4ecd0ff9556773791798b66956ecc75288d1e9ba2a9ea94857d3132999a225b1ffaf844670156e7a3ea9f077fe8259a098b9ee759a6ddfb7d20a7acd1bcb9f67777e74615e8859ea56281fe5c400748f02d1a263b1867a3b51748ab70f`,
				S: `345e2f60f7c82c89ef7dfd7dff2bc2348bab020479330899d4410213b35e98d9bac92fd8ae806b5bce8a6c4bd8275b0facb4dd13f9d68ba67141fa5085264da6dd685a6d212170a2c9cbf2cf5930180effc250868c984bf50ff69d6069ea28f5bc1b63705d0732416fd829a5f5d6217462c22a33fd4652f7c1d198794646c08406024e8163a7ebe39cfb514c5443897b5894dd19a213e037f27e0ffbd6c5447a805a54dfdf4f65819d4e0fbee25e3dac47fb6b636e8de6190adccbcee937d0977b35b973606b0ca348758b50cdbba028b73d0ef01c56014c031c598fe8db87d2ca4644770aaa0451c376ded82ff5c6b8e7d2ed9d1c8a17c3122c128273c60fd1b0088dfbc9c927f162e43879405964cb11ef7899123feb8f88dd2734df98aa696d936a8df07000e84af90101f7006a9bd2549fdd0ad3f9de093012d32d2afaa828017ee9c607cbf5b54f223666d4b5f3e26e0dfec003961b83d83de39ff6a0e81e1883c1db4aaaf082fec5aa30a7e578553d89774c67907790c96dc4f5be4c8c`,

				},
				{
				hashAlgo: 'sha-512',
				Msg: `132cf50c66ac4cc54339751a0ebb865e1d3d320562fc905c4abd1e78e464066c46c3a0c02db0371ee35a104d66dda864c6133e37cfad9116e883ebb73b295e7016c34ea9911a309272ef90114d8f59fff0a75193fe5ae31ed99121f9c59209bc4bd507b1dc12bc89b79ffe4d0df9209762a1730136290cdee58ec828ccc88eba`,
				S: `b12503b7b2f783618884174bcb9be10877960431ed6363c807e12db71b8b6bd9d6401d064e253740158e8b900152d37faf20333a7d80b3d47c7c7a3fa12091ce31cd8aae272a4da15fe2cb5cfdea541195a469c96bcf695e0b526dfa48a59003c6763af8136392c4b8d24db314746f42aca550acc65e074913ab82232eb8593509158a8ba34bc0f0e3125a834a3ed2d6a8cb1d085f234ae868b86aea8d6f82e13a08842485066e48aae4837873150f44475e12602b552dcb34d1f9fdaadbc6bff5134c6fc76263888be67efe63ee1840fa08c49938858a9d48b1058d18976bf2e3bfc625552f75b3ea44eb91dd366865f240a0c336a0110e0fa09d09cd94c70cbc8895ae3d44ae3dff545f0e8c8cc662ecd40f9099a952494396c6b423ebb463409969281cdd54ad87a308e487ce19745b30d5da76b98d2aa9a007a55783b3037e5b8662322810bdd11d86dc3f61451149391fb2f14ed9c17c751623a4042ce7edb875ee27bcd1f19d6dc9283ad06d15e097e2b0b15a7eb7128adbca0aa6adcc`,

				}
			]
		}
	];

	for (var i = 0; i < testVectors.length; i++) {
		var vector = testVectors[i];

		var n = new BigInteger(vector.n, 16);
		var e = parseInt(vector.e, 16);
		var d = new BigInteger(vector.d, 16);

		var rsa = new jCastle.pki.rsa();
		rsa.setPrivateKey({
			n, e, d
		});

		//console.log((i+1), 'rsa testing ...');

		for (var j = 0; j < vector.sigVectors.length; j++) {
			var sigVector = vector.sigVectors[j];

			var hashAlgo = sigVector.hashAlgo;
			var msg = Buffer.from(sigVector.Msg, 'hex');
			var v_sig = Buffer.from(sigVector.S, 'hex');

			var sig = rsa.sign(msg, {
				hashAlgo
			});

			assert.ok(v_sig.equals(sig), "sign test " + (j+1));

			var v = rsa.verify(msg, sig, {
				hashAlgo
			});

			//console.log((j+1), ' - ', v_sig.equals(sig), ', ', v);
			assert.ok(v, "verify test " + (j+1));
		}

	}

});



// RSASSA-PSS
// SigGenPSS_186-3.txt

// # CAVS 11.4
// # "FIPS186-3 - SigGen RSA PKCS#1 RSASSA-PSS" information
// # Combinations selected:Mod Size 2048 with SHA-224(Salt len: 15); SHA-256(Salt len: 20); SHA-384(Salt len: 25); SHA-512(Salt len: 30);; Mod Size 3072 with SHA-224(Salt len: 28); SHA-256(Salt len: 32); SHA-384(Salt len: 48); SHA-512(Salt len: 62);

QUnit.test('RSASSA-PSS vector test(FIPS186-3)', function(assert) {


	var testVectors = [
	
		{
		bits: 2048,
		
		n: `c5062b58d8539c765e1e5dbaf14cf75dd56c2e13105fecfd1a930bbb5948ff328f126abe779359ca59bca752c308d281573bc6178b6c0fef7dc445e4f826430437b9f9d790581de5749c2cb9cb26d42b2fee15b6b26f09c99670336423b86bc5bec71113157be2d944d7ff3eebffb28413143ea36755db0ae62ff5b724eecb3d316b6bac67e89cacd8171937e2ab19bd353a89acea8c36f81c89a620d5fd2effea896601c7f9daca7f033f635a3a943331d1b1b4f5288790b53af352f1121ca1bef205f40dc012c412b40bdd27585b946466d75f7ee0a7f9d549b4bece6f43ac3ee65fe7fd37123359d9f1a850ad450aaf5c94eb11dea3fc0fc6e9856b1805ef`,
		
		e: `0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000086c94f`,
		d: `49e5786bb4d332f94586327bde088875379b75d128488f08e574ab4715302a87eea52d4c4a23d8b97af7944804337c5f55e16ba9ffafc0c9fd9b88eca443f39b7967170ddb8ce7ddb93c6087c8066c4a95538a441b9dc80dc9f7810054fd1e5c9d0250c978bb2d748abe1e9465d71a8165d3126dce5db2adacc003e9062ba37a54b63e5f49a4eafebd7e4bf5b0a796c2b3a950fa09c798d3fa3e86c4b62c33ba9365eda054e5fe74a41f21b595026acf1093c90a8c71722f91af1ed29a41a2449a320fc7ba3120e3e8c3e4240c04925cc698ecd66c7c906bdf240adad972b4dff4869d400b5d13e33eeba38e075e872b0ed3e91cc9c283867a4ffc3901d2069f`,
		
		
		sigVectors: [

		{
		hashAlgo: 'sha-224',
		Msg: `37ddd9901478ae5c16878702cea4a19e786d35582de44ae65a16cd5370fbe3ffdd9e7ee83c7d2f27c8333bbe1754f090059939b1ee3d71e020a675528f48fdb2cbc72c65305b65125c796162e7b07e044ed15af52f52a1febcf4237e6aa42a69e99f0a9159daf924bba12176a57ef4013a5cc0ab5aec83471648005d67d7122e`,
		S: `7e628bcbe6ff83a937b8961197d8bdbb322818aa8bdf30cdfb67ca6bf025ef6f09a99dba4c3ee2807d0b7c77776cfeff33b68d7e3fa859c4688626b2441897d26e5d6b559dd72a596e7dad7def9278419db375f7c67cee0740394502212ebdd4a6c8d3af6ee2fd696d8523de6908492b7cbf2254f15a348956c19840dc15a3d732ef862b62ede022290de3af11ca5e79a3392fff06f75aca8c88a2de1858b35a216d8f73fd70e9d67958ed39a6f8976fb94ec6e61f238a52f9d42241e8354f89e3ece94d6fa5bfbba1eeb70e1698bff31a685fbe799fb44efe21338ed6eea2129155aabc0943bc9f69a8e58897db6a8abcc2879d5d0c5d3e6dc5eb48cf16dac8`,
		SaltVal: `463729b3eaf43502d9cff129925681`,
		
		},
		{
		hashAlgo: 'sha-224',
		Msg: `5c61546b848a36e8e51f8beb1140823dbd95b06660924d16fdf9a1c33ca0b994c0745e7eb5be48ada8a58e259cf461a95a1efadb0880d1a6fde510d9d44f4714bff561e81e88d73a51ba23e8ca0178b06698b04dfdc886e23865059ca29b409302eb44f2e9704b588767327ec2ee2d198a0cba0266f2d39453806855cf0b0cd9`,
		S: `134e6acd94b76a86e7ff730f064a3d480d1cff1687b993163ce09f21d494a4a15e6d92758a93f7c83ead21c4ca290f9478241c9811c231f32d9d17e0b479a9b34cad02e5bbdde6c8e4ec4f35f93524f8afde49e6a4740bab2f2fdeff3fc5d92a1b50adc7af964eec82fb80be24092ab28791807c664a9106b5df3296747c014b75d69d181f2e58dafbbf9127164f88c862a48d5e9edcd6d2b2cbc20abceb0e98c7e731d27c8d04fad95ff50dd64af20e6388ed74b9b3cf33b4a316b0c752f33697e5a7445ae2f726f30333f107928872776225a3e0b1b14a7e84f9a695c7b3910330d225b4834110b54d6b05e69df6b7a2c9dc352942e3bce970cec677253230`,
		SaltVal: `463729b3eaf43502d9cff129925681`,
		
		},
		{
		hashAlgo: 'sha-224',
		Msg: `7540edea54a4fa579684a5b59c51eb20e61106f82157917c6173ee9babe6e506b6198d8af24e709dcad6ea372684d2e335635c1569a43ebec3da121e506afcd9f43c8c4e66b7e6247ced2025a912eb50c43376290a248f5467bb0c62f13b69ebb513b2ddb7c9a31334310f2a2ae27e901bea1add0dc1cc67d57ca21095437463`,
		S: `45541aa65fbb0773b1434c4fdaafe23fe800f78eba900c6104a6f0e76dc08daedc28a3380c8078f82055cd4a20cf30541c32d9ac625378355c156880b35a29645325d488f7a0d2de7df92cf9bccdf851445c2b834ad0e6849a6549db72affa7ce66fbbfc5bc0194504a5fb031267b6ca9b57f583e7e11c927e3dc203f7d6d4b9df675d2a302231400008fbbd4a05e17f88bea074de9ab8211a18dcceae6c9fd8fad96ce0626eb25c9ab81df55ba4d0a6ae01eb25a2529e16c98ded286cb345d4fd59124297ba9b3efcb67884ed853ea96d74e00951987bcda54d404d08f2baf7f0d7ff13d81d1fa20cde1d21663684c13ffc7164448f4e85a6c811a850a3faed`,
		SaltVal: `463729b3eaf43502d9cff129925681`,
		
		},
		{
		hashAlgo: 'sha-224',
		Msg: `840ff32993223efe341eeb55558e6ab1fbae15d17bcf0731edfd32d4dee0ac4145e04accb88c7016e03d27d72bf670dbc08fd94bb8134d2e8b66302fc82baca10ae445c0275bb43aaa42f2ee841693f3fe4955dcf29ff93a3bd951636a919b72ba650d8f4757b1717a747320c8b479009c22b20b913cb25ee59dbdf72bd921bd`,
		S: `07f07ef5e793d59b0c3f899dc846bb831d88dd4d2d8345ad2d726c5c532d13e05b26f0fd03b2b9bde7b6d5b6febc8fe5d3228887eac443c99ec39fffeb939785f87be8a93e497cfdea3d8d06356518a5254c5946236458b29f1cd47e97718c805b167791d10f9304328635330116a2aeae1e0ecc16bfd5a31356d06892b8ca04aec27a417320be7bf6fc1083d70fa522c23850f5d6beda1a251d1a5e71762bc8fd5f16ef0c7a961f4858a5b760a8032f3fd6bdce2ed26351f2beab8b89d9312d88736ee5253a9da6753283e5b3d0d9cdd3e19ca0b60b9fae3e3dfd67831df72ed9611d5f2b3ac256052a207a5245d2cdeaad0d1266c7177b1a0844d5974a8a41`,
		SaltVal: `463729b3eaf43502d9cff129925681`,
		
		},
		{
		hashAlgo: 'sha-224',
		Msg: `a5fb396eee4045f886191f7ff9ea68aaa1bcd8e781903b6071f3ba2b7cd35cc08691cdb131575d9502ac4b45c046444c1d1f279899cb0b76a20883bd00972148704a38aa8f5fe61efa0c52bdb45b33f4c83892342fc8d0ebf3fdeab49568fccaad4e04c3d0fde97bb660bc4e9cd23d8ae830a1230c3292a9acfb787803eef72f`,
		S: `4428c389d0c80a9320e4859e41cbd4a47f78e4da5d1c0644ff50bad172de9ffe74d84a76d6de4f72bbe34d7dccaa03e1324041cb98308d73dcff0bcf7ffc35936473cf3ec53c66ea8a6135742e0ea9056a4897a7cbd2b0654b344786bf3047d122dcbbc4bea1840e84bce066c3385dccb021a79e8de18dc114a40d824141d8331a4df6901b3409c30552519b097a96ded6793cbb9ae18bb9a4185b6f4e83aad6dce878c689bf595d272719b9f50b3ede1803dfae6dd3f54e4ca9c458c14463f4f19af6cc8127bec80a6a9e5a5fe0d3e14dfcc6ba052750ebbf84a652adde9d6be68d5b134cd09bb94d0875e5527fe3f3fa2a516dc05c14fd5516dff2d434f0c4`,
		SaltVal: `463729b3eaf43502d9cff129925681`,
		
		},
		{
		hashAlgo: 'sha-224',
		Msg: `6e891589d71d2eff6cb986b071a31e2696d8ce671fa18c244267eb33d0c8e24018ebcfbf0910bb24966be0575f3268628df5786dfd2e6deda219661824c5029ccd6b6b90a60093abdd06bdb46aa74039f2048784eccb5dcb020767a7ba3df2c755b4f0e6f8143cfa093326afdc2b2b138fb0049332a0e3262bdcf9c8d9573b2a`,
		S: `01909328c24dd0ef912040f61492e3711243f8ca1262067cca6bdab165efe4157982323f13152999e9f21e6852d8c2efc4130e2c46a38446aacfc59fbca5d1a38946923b7e08be397fb787bc79a71ba08fc2b693d1bcbe897d1dface2858ba80a086a0e0a45efe66fd5350add819fd0dc1931d3eba2765f84f147422f5330d0efa0cd827197a5d89e2dd62db9051d5df8b9680169f349086dd038a9ac62f9941565b3f747d528ec4c36e9c948ad3a73240d07ef14b354ffef1b1965a9aafb13d0fc88a09707c6a0ad3028d5a5c6efaab50aad05304b1d5b2930abb8f58c0188b6a94231f8698c96ddd614343a0218494dfff9a293dfc7d5c3b5afbed8f079458`,
		SaltVal: `463729b3eaf43502d9cff129925681`,
		
		},
		{
		hashAlgo: 'sha-224',
		Msg: `d66747638d8276920352b215158cefe0727a5e2b079d892cbb969f265d470ca2da354dfcb4300322af374699ce963bc17d51e95910c548456c8d9b8f04a300ad08c74602d825fea7bf32d56aded7211766d1b9f70b580a97b5fe67ca78dba1f1c6e7d87ae3a790a79a0c07912f98c76c94c2770cdf9cf6a8fcb3abdf9f3616f8`,
		S: `85f296084bda823556aa369e5cb19e10ce6e982a6d10a85ba6af6d3fed8f2c05599faed069215cc9eed9e72a4fe510a6c09ff721cf1a860e48cf645438c92c5c86d0885e7d246ccf9d0cfd8c56ca8d673b7094a3daa77db272d716f31b1380f72b50378f595471e4e481851c57a6b574bfb3fc7aa03636632045fcc8e9cc54594759f6014b527877e605ef60cf109b4ca71e772a99acfc7243318655ec50f74e48485668ed42859ff2c5934581ba184d926c8467d7c35257dce9964049568a990f65d591c2db86b48a7256da947fd7d978dd6734bd8685025d1a87e32f52a0299394c93e6d518b18e0b8db1d763f46905f405df0cbc8455e039f173e2b68c9de`,
		SaltVal: `463729b3eaf43502d9cff129925681`,
		
		},
		{
		hashAlgo: 'sha-224',
		Msg: `23d92665e88a4f6f732de384034d493d5df37b767a8260557de05688e8d60dcd0eba9cb8cc4bceb174dcbd3c0ab5a37db3b6ecfb6a3d90a4f54a9f1117e11e0c08b0114f22f2d98fdd93c0b9fd95d37c0ab2f00701431f1449602525e849570df704adb353481713969a148546b680424c30ad24a75bb6ad616a104bc2d562da`,
		S: `8beeb201aedb9fe7d535fc7989713062497a03e18ef9977b98a93f18f37545c38f5e5206e2b5df7f4a41ab9e0675f7d46d172dc3af90fb7b1a6fa6c986b803a7f2ea4ed217872cc686165b1278450c23c329ee2855f65e651c3db085e407bf3e3a96eaa833ba2056a084031546cea2f454f7acf84c3b90fd7b6210ef6d1ad71ed1b0049262f5b4e3ca99d10a3307752b2ad8e8fbba3a3e8432bc966553901e87150738aac9170fab1d27219274ec528299f8afbbd861ee837f2c86ecce7e73c9b7bd6f6661d1efe3fd2ff7b3efa0d1fc7b84fefffa14b55a2c5fe3252cae0cf0da6e50e3d615f86ae6721aa5e29ed3a1c71c243c2529eef483c56b902e93718c`,
		SaltVal: `463729b3eaf43502d9cff129925681`,
		
		},
		{
		hashAlgo: 'sha-224',
		Msg: `40abb42db34067fadb5aacbb2fdedd2d0324030bb75ca58f2e2ade378194b2c5f51ea2892b337ee297c77b03333b86f37581d7d77e80c87494bae8f0d22c4bd81e7525685c3b9706e1cbc90f2bff39d6cf6553eab29d41987c0304b14a8fc48ea4f96450ae205a6ca2acbe687df2a0dff9199fcbbc7bb704cf4e5b035184c4ec`,
		S: `54bec66241dc197ad92e695526b3b6a030216b48af90d93c36b2d70644e40cda2cb259f27ca9d141e5753f938497e84208b380ffe1788701c71d89bbea3edd352dabd32d9425edcf9a33e185cbc4031aa6069863fe47d499536a59da12a8bdbbf2a3a9f0039318d066f5117bbf6fce4f6752088ccc3a081d85da461a8bdcaf349fd4054f76384e668d00a6f747688c8420c7e452b0736ad62e1738a3f10cb62bc7ddc12fa670f858b2d5def9a42ac8f2fc91d488738a7c23168f51ddfbdae6a5d8ee1fc561cc3add4a7e14eb103bf9593cebf391c1f7a07d262faf03d47d07424ffb3a916a9564652a1be020a0e922e99a57da1abf931f74cfbdd484c0a9568f`,
		SaltVal: `463729b3eaf43502d9cff129925681`,
		
		},
		{
		hashAlgo: 'sha-224',
		Msg: `ef10b03c04578bd5f783358df367456a73de38c6fab2c35405bc685e3d4c4850f2cb387ac59e1612a44e5e78fce6f8be299d546832b5b970b3a3da8e1a70abb6165f72e14dd021104e64e38ec662f576f65ab776640803d2d17abdac6c75ab82451687f804b553d8db0eed57b9a3e39ac15c8878fa714882488938409b24f1be`,
		S: `4a183b82616f3bbc27a146710b28729161feb17900be62e69eed5d254d15f34bce52d6f3deba89a787ebeb0611e240cc23e16add3796d4a29783e2cbe8797e066cecbd66059c394f0e2f9e377f1ffa194fcb895e1c48874b9b6430a13c779f5ca29e3f42bca4b916710590ab6501809d645a4885b058dba0647971f04f6f2f4a296c45d89dd848b7c2f8777ec50846c97d35c12d54ebb6ff167327b1d4daedf4468031b59057d57ceddb79fdd013167ee6e46d9130693322c3ae6702901a1e90bd4b621d141977d0680acd524921bc540e34ac640ace02f89d5436808283e026e138ba3a5a4310fe1e048833f9b581baef5f891f9cdb2f0673bafa11ceabc7d7`,
		SaltVal: `463729b3eaf43502d9cff129925681`,
		
		},
		{
		hashAlgo: 'sha-256',
		Msg: `dfc22604b95d15328059745c6c98eb9dfb347cf9f170aff19deeec555f22285a6706c4ecbf0fb1458c60d9bf913fbae6f4c554d245d946b4bc5f34aec2ac6be8b33dc8e0e3a9d601dfd53678f5674443f67df78a3a9e0933e5f158b169ac8d1c4cd0fb872c14ca8e001e542ea0f9cfda88c42dcad8a74097a00c22055b0bd41f`,
		S: `8b46f2c889d819f860af0a6c4c889e4d1436c6ca174464d22ae11b9ccc265d743c67e569accbc5a80d4dd5f1bf4039e23de52aece40291c75f8936c58c9a2f77a780bbe7ad31eb76742f7b2b8b14ca1a7196af7e673a3cfc237d50f615b75cf4a7ea78a948bedaf9242494b41e1db51f437f15fd2551bb5d24eefb1c3e60f03694d0033a1e0a9b9f5e4ab97d457dff9b9da516dc226d6d6529500308ed74a2e6d9f3c10595788a52a1bc0664aedf33efc8badd037eb7b880772bdb04a6046e9edeee4197c25507fb0f11ab1c9f63f53c8820ea8405cfd7721692475b4d72355fa9a3804f29e6b6a7b059c4441d54b28e4eed2529c6103b5432c71332ce742bcc`,
		SaltVal: `e1256fc1eeef81773fdd54657e4007fde6bcb9b1`,
		
		},
		{
		hashAlgo: 'sha-256',
		Msg: `fd6a063e61c2b354fe8cb37a5f3788b5c01ff15a725f6b8181e6f6b795ce1cf316e930cc939cd4e865f0bdb88fe6bb62e90bf3ff7e4d6f07320dda09a87584a0620cada22a87ff9ab1e35c7977b0da88eab00ca1d2a0849fec569513d50c5e392afc032aee2d3e522c8c1725dd3eef0e0b35c3a83701af31f9e9b13ce63bb0a5`,
		S: `492b6f6884df461fe10516b6b8cc205385c20108ec47d5db69283f4a7688e318cfdc3c491fb29225325aeb46efc75e855840910bbaf0d1c8d4784542b970754aaa84bfe47c77b3a1b5037d4d79759471e96cc7a527a0ed067e21709ef7f4c4111b60b8c08082c8180c7c96b61c0f7102ed9b90e24de11e6298bb244518f9b446ce641fe995e9cc299ed411b65eb25eaae9e553484a0a7e956eadf0840888c70e5ca6ebc3e479f8c69c53cf31370ab385e8b673dc45a0c1964ec49468d18246213a8f93a2a96aad5a2701c191a14a31519e4f36544d668708ff37be5481cb0ffa2b0e1f145e29f8575dfa9ec30c6cb41c393439292210ea806a505598ebdf0833`,
		SaltVal: `e1256fc1eeef81773fdd54657e4007fde6bcb9b1`,
		
		},
		{
		hashAlgo: 'sha-256',
		Msg: `7e6690203cb068b8530cb1ff4eeaf0fc69a4e304f556072dfeef5c052c886c83e7f58a3dbe9a58dc0a808ccdcea9f33ae2a0b6395153dc43ff2510e78f40a4bf8328d7a4a596531ea683fa1e0683e2f033549e6bf5b7c06b097e9b810de74ee89c28febbb94b6266713c855bbc21c706a5e92502aa28bb8d662287396d2570e5`,
		S: `509a01bb0360d1160ed3ff33432291cfbb63daa2933819600db7dd825aef13dd1e9a888a9fb6fea93debd4cf4bc77129b06dd4727193d7e8a2e5aa5a6020b64524e93abb0406f5a18f74ff0aa804919df4072e319ce8234431c94e8eef8c5ce813a07b2f66dd6a032c3e69a3c58c6b54acf08bbbb019df15f3abd22c67f3e2cbffe99887adee58a39cc30ac45a6e6e59283ee0890aa87072a857845f5cf3ddacdc776e58e50b66e95eb13dec49ce45505c378734e964e8095d34a01317768b7b9fbef6eb24b08b1bf0312ab51e0acea4a3dfdfa6fa7bb115b8b685d354841d1901bc73cc655ae246a5453ea8d160610425c2c14969bf22a7e11e663cff1501f1`,
		SaltVal: `e1256fc1eeef81773fdd54657e4007fde6bcb9b1`,
		
		},
		{
		hashAlgo: 'sha-256',
		Msg: `1dce34c62e4aef45e1e738497b602e82c1fe469f730cf164178b79fdf7272c926d69bd1b5e2de776055753b6f2c2bcbf52795110702a5bdf7cd71f6b8ccf068ee0ddfb916abf15458dd9764f262b73c4c981f5f64de91e8d8a6a30d961f3ab66fd92b6d159e6c0db02d767bc1f8499baae7df9f910338495c8ad74ee807c6443`,
		S: `1bd79d25ac6b0f242f39555c85d858c23680e1ebf9590d05463ebc58454a7822cf0e0c2ab9872b6eac5ae8ce3da773d6b2039e9b26ce751dadc48579320ea63b978b0df038191d9128102128a365c01d9e2b43fe2b5ef1ce9ee8f4a1e12caef1bbe7f3a8d1a93c9f399753bbfd60d22d8f39206a511ea448dc23cc0e4fcf0b77d3f3fbd9188b740de3f85009de94ee157dbf7edc3165e9f69b59db37f7fdc507496de8941a2a2628774b06c8cab034bbe3d2c04d253b5948d6e5712373ada99b7f860612440c5eed81efeea18d76329dc30bd9fcc500e92315677142d5e1b6b45ae0e6e725122f046c9a544ad1ef1ddc7c6b2a7809715ab75ef870ee6670627a`,
		SaltVal: `e1256fc1eeef81773fdd54657e4007fde6bcb9b1`,
		
		},
		{
		hashAlgo: 'sha-256',
		Msg: `c32976432e240d23df6594f2885f00db7fa7e53b7aa84ef89798ec149fab74828b86423847f64285b7e210a5f87e5e93e8c2971ee81bc13fe060a8aa840739a3d6992c13ec63e6dbf46f9d6875b2bd87d8878a7b265c074e13ab17643c2de356ad4a7bfda6d3c0cc9ff381638963e46257de087bbdd5e8cc3763836b4e833a42`,
		S: `be69c54dad9d8b6db7676fe74321a0aeb08d1cc17f6607e87982f99489344e99378c38341e0e605b8ff903c74a973872a9880e05a8ef0bd3e6049931acf152dd54fec9105a57b73f77631db736b427f1bd83275e0173d4e09cd4f8c382e8b502a3b0adbd0c68911d02de17fff3d927e250e1826762efc0b895dfa502f18dc334b4c573f99b51b74fdd23009861028f1eed6875bf31d557acd6de8f63fa1274f7bed7a1b4c079f5a9b85bfab29f552c7f647d6c9241563fac123a739674b0ad09c3f94208795d9a50529d799afc597e025f1254995f043234891620b10d5c5569be14b0f463a495f416024618486c7ff5ec775cfb46fbdff5379c5e09150b81a3`,
		SaltVal: `e1256fc1eeef81773fdd54657e4007fde6bcb9b1`,
		
		},
		{
		hashAlgo: 'sha-256',
		Msg: `218551f425b3557d09ccfdecc9ab499085bd7fe7d60820be626c1a9aae293f5734a2f60fb661313dd15a9f22d5742268d4458306f91d65631b4777be928beecd4af733a416e0d8d94623d1e67bb0e1ceba4a5204c088e98895201953646477f58a0d6e7ded3834998faefcfe63686e0a5f5354a8d2509675f87f6821cbbdc217`,
		S: `96a269e0ca4af626aa8b7f45acdaa76d5dabfea5a7d762ab39b138dc7575fe196aeb182bee5b18503969b5ba111f057ccdbf292d7488173a4a4dd04e62c254d502673d5a076d326c66c9a71a3b83b1005c6366f8a0902987dbf08cee7562d0abffbdd661c3525be8e12dfd73ed31efaa817f61e7fef700a3215e77b6231d59c098fa455b69ec6e658a66cca2e8f2e090ef704270995170ba9a1f561b848676804413645a943d883191d95b024d6ffc9cb611c68f3319403bd7c07ac6694501368e8147a256e928604b63d50e2c65f3b2c30df1eb0363e29fe448f94b6907cdf42fbc9c27b31a43a8f5c15ce813f9b20d16da6c298843f052ed37678b4ef1d78e`,
		SaltVal: `e1256fc1eeef81773fdd54657e4007fde6bcb9b1`,
		
		},
		{
		hashAlgo: 'sha-256',
		Msg: `06b76aaeb946fe6867e4716a8f1ee8d61c483ab345cbf8e5b2bfab5ce0bd5c8bc6ee5a1cb96837e28dbb140ffdc61ea74cd059342dd49dbce11bdef09f10b0a638510989fb02490fd66679acbfb0d04652167ce8bc289fbad760973196fa8283a405015e48bb3dd98c0e28ab9e83069a76432b37b97006c9deb55e878f21dc0a`,
		S: `65e2358bafc9fcb65536a19d27f710596cc31f9a8328cf9de21257506047ab1340a74505581a54f258bcbe0c1520f84ebd2e36913560dbd71574e3738428097d6b819e6900f27df159dcaf08c6e1591b073bfefe3da6bc827a649e0bae9c52fe9ae180d1efc01e5a38adef102c6d106af12163b1a0f6d1543ffce3980ca0f8b70d38007288d47bc565e995b8c21da2f959c928aa2f8574a660226048dc9dba59526a30e3274808683b41c0cf086ea5afc48eb294a88c4b8b7383dae6469e8483345b1daf1d2801bda93ff91ca75dfaa8dd5d47e73cecf0efb0629fda16c601070bee2e8cc0695150739202e3be270b9801d085e11e1df07f9a4cab54fda23da6`,
		SaltVal: `e1256fc1eeef81773fdd54657e4007fde6bcb9b1`,
		
		},
		{
		hashAlgo: 'sha-256',
		Msg: `f91670bf6b8bf5c8c75056d844168fc6ec0c28d09400c1df11c7ef0da9e04664c854b7e8f4e01dd8035612328c4107759bc894aaa9d50ca5cb7655892983f68ab28172f70ec6d577d4de8c93fe2e79749ad747eec2ddfbbecd89cc10c70b35451f6448f2a083452ca2ae6b0382240e4c4f01eaa4c661b7b181c8feab6bc22a1b`,
		S: `2eac03233c4e24b3328447cc09661c259676b569e6a0848b5a193065296a59e3b6d35a2ecd91c6cefda4f2bf9f2252a27334fbbc2d79e450d44bc282f7d7321b46f82028c154f30f6d62edf3672a1019d914ec617aab2d007f844e63e295bbd8f66163deb278d99d66fddc58cca2b911ce0af95265134af55a4b786cc214fa11ffa29bcdfbed12c5ce6438e9b6beaeffa3587978a83409c29f115423174c05cb8c30198da8b193f9446b9b49f7e3e2862ec9a350e8441ba4e5550e87db54712865fc2690a5938aebb28409b88cf0d172111a74f678ee0819ff8bdc22b08fc6fed37b676d0705396f3247a267c60f7ccf1fb260c0c2e924c1ef5540eb6125f3b1`,
		SaltVal: `e1256fc1eeef81773fdd54657e4007fde6bcb9b1`,
		
		},
		{
		hashAlgo: 'sha-256',
		Msg: `64e3f541453170db952c09b93f98bcf5cb77d8b4983861fa652cb2c31639664fb5d279bdb826abdb8298253d2c705f8c84d0412156e989d2eb6e6c0cd0498023d88ed9e564ad7275e2ebcf579413e1c793682a4f13df2298e88bd8814a59dc6ed5fd5de2d32c8f51be0c4f2f01e90a4dff29db655682f3f4656a3e470ccf44d9`,
		S: `76c297fbe302f686377cb155ae8a2b65a6c577af303035c4a755fe67014c560476e7a789b8f2195b0f80416f5f33b7fdccc380f988cebadb640e354bf5679ee973a1e1485b68be432b446ff5949504515a65cddb0faf6dcd1e1188656ce941af3ddc8600cf0e4087ac8382f0d5061d3d05f58c9362eb88f30a724d18a15ee68a60c5e4dedb4084c9d01522999092094c85622e67a66ed034564ac286b0ff8791e9933a23f83b4a88d2e79e3a29d6a3f87e63bb1a96a6bfd6898edaa938f74c72d6c10cb94d055ef3fda9e6dd097d52738754800ed403b1444195a311fd6962007999e31edcf2870d1c3ae3b3646bc7da55e5f1e6627e6248839e8f70b997fc1e`,
		SaltVal: `e1256fc1eeef81773fdd54657e4007fde6bcb9b1`,
		
		},
		{
		hashAlgo: 'sha-256',
		Msg: `33ba932aaf388458639f06eb9d5201fca5d106aaa8dedf61f5de6b5d6c81a96932a512edaa782c27a1dd5cb9c912fb64698fad135231ee1b1597eec173cd9ffd15270c7d7e70eced3d44777667bb78844448a4cd49e02a8f465e8b18e126ac8c43082ae31168ed319e9c002a5f969fe59fc392e07332ba45f1f9ea6b9dd5f8a0`,
		S: `2891cbe23ccf10c396ef76a5840adaad6498b6fc8c6a2f6c26496cb428a9221ed59b3645f9a25f5747feda0f51b45319e0978f22ac4facbc15db9a4e5849ac2a1404aeb6c00e5eed3c07eeeee2435668fd17f16ab244c9d38f9ba0de9d3f3ef0d994094e92e327948f1409ef827752344a1375f608dc3cafe74970745a023b320b3bd3171b62a68a5ccaadbc64b82cee4b8a81840ed8b751ac66a29eb81fb819ec54c76b01c7b412a43ea057a80202f1c3c06a4ee60547c13c6c2fac34a5d5aae982b9dabd119b470829bd77a560e0973409115bd1ab5bdc6bb46fe4048022b0cf4fc6aad4184c28621ec6f82edb54733c902620bf45f2517f24902e56d58038`,
		SaltVal: `e1256fc1eeef81773fdd54657e4007fde6bcb9b1`,
		
		},
		{
		hashAlgo: 'sha-384',
		Msg: `833aa2b1dcc77607a44e804ee77d45408586c536861f6648adcd2fb65063368767c55c6fe2f237f6404250d75dec8fa68bcaf3b6e561863ae01c91aa23d80c6999a558a4c4cb317d540cde69f829aad674a89812f4d353689f04648c7020a73941620018295a4ae4083590cc603e801867a51c105a7fb319130f1022de44f13e`,
		S: `2ca37a3d6abd28c1eaf9bde5e7ac17f1fa799ce1b4b899d19985c2ff7c8ba959fe54e5afb8bc4021a1f1c687eebb8cba800d1c51636b1f68dc3e48f63e2da6bc6d09c6668f68e508c5d8c19bef154759e2f89ade152717370a8944f537578296380d1fe6be809e8b113d2b9d89e6a46f5c333d4fd48770fc1ea1c548104575b84cf071042bfe5acf496392be8351a41c46a2cab0864c4c1c5b5e0c7b27e7b88c69f37ffa7e1a8cd98f343ac84a4ad67025a40ed8f664e9d630337de6e48bb2125e2552123609491f183afd92634487f0b2cf971f2626e88858879d45a29b0fefb66cd41b2e4e968385bd9fc8c7211976bc6bd3e1ad6df60856985a825f4726d2`,
		SaltVal: `b750587671afd76886e8ffb7865e78f706641b2e4251b48706`,
		
		},
		{
		hashAlgo: 'sha-384',
		Msg: `8925b87e9d1d739d8f975450b79d0919dde63e8a9eaa1cb511b40fe3abb9cd8960e894770bc2b253102c4b4640c357f5fd6feab39e3bb8f41564d805ceafc8fbdb00b2ea4f29ed57e700c7eff0b4827964619c0957e1547691e6690f7d45258a42959a3d2ff92c915c3a4fb38e19928c5ce3ddf49045f622d0624a677e23eb1d`,
		S: `43ef93d14e89b05d5e0db2dbd57a12403910646b4b0a24d9b80d947954591afa6e9809e96d7d3e711003ee0a9186ab3d8e0b4d3425c6da4b5f7899537e737b71df9ed6355529aace77a7cba96b5b0a86399252f1286a6fcab180b598455dfe1de4b80470d06318d5f7a52e45b6d0bcc00bd365819a4a142b83072775f485f63c8004f53378a9a0d2345d07b1b326238ed070d1e69fc0b5cf853a807cfb723562d1f5682482e8a4840588bcc7154ce0740c768616cf04d7aa103642917ec5b4b514a3734d9e0c58427cff42f27f43fdfc85991e045acd17af6fba7bdab818e90eb4117684e89f9163dff7b98b82a08baa2b49acde480c5702c335237d1be771b7`,
		SaltVal: `b750587671afd76886e8ffb7865e78f706641b2e4251b48706`,
		
		},
		{
		hashAlgo: 'sha-384',
		Msg: `d0eb4623eedbd97ee03672f8e4174d2e30a68323ce9980e2aafbb864ea2c96b37d2ab550f70e53d29cda03d1ba71a1023de78ba37dfb0e1a5ae21fd98b474c84338ff256b561afc1ca661a54d14db2e2661315e13581731010f6415d4066320519a363fdd2dbd5919362214bceb26716d3b188a39f32950cf5bd87b7b193307e`,
		S: `213ea3fb11cdd71bd5b839de8a598b6a142023825e24db7cb1a4459e78092b32b07643c7270839f247870efbd320b419ff3b1914c41b6ca4bc3cf17017d9a94d86f0f022f4495666c4a89f08e216a161d4664f2d616fa4bb2a17ccb85004e63f488ba29564ca136aa3a6f9561f85cb550b8cf8b0a85afbc8aee2c76891a53e7cb66e36f8709e7990d8de8d0c73865c1cb44727f18c0faf25c53f15e070c430e73f77b1e9c8f8ec13114d7e7ac790ade4ec6f1de0cec13f25a48d534965a8ede12090a928a91d5a1f214aefe6cee576ad43eaeccf635409a8646853d9cef93c9c04a884253380a49e682bff0750577c5a80becdef21a4a9793fabb579eb50e3fa`,
		SaltVal: `b750587671afd76886e8ffb7865e78f706641b2e4251b48706`,
		
		},
		{
		hashAlgo: 'sha-384',
		Msg: `d58e0997224d12e635586e9cedd82dddf6a268aa5570774c417163f635059ea643c1f24cabbab82eac004a8b9a68bb7e318fc526291b02040a445fa44294cf8075ea3c2114c5c38731bf20cb9258670304f5f666f129a7b135324ac92ec752a11211ce5e86f79bb96c9ed8a5fc309b3216dde2b2d620cd1a6a440aab202690d1`,
		S: `4385e67819283d81eab2b59357c51ce37b5ea32b76af345a457e5aa2dd61113865a587d2c8a8f1c8825281c052a88fc67797adb6251d28efb911564671affcbfc7e1a3c055dce8d93497fe80da459647ac71f17e9aa07d1aafd5260ac284d622a03b6670c55b0d40696d436c638f9b48bd08f37db4eaf1d9746d2c24de347dcca0a62df244bd2a554bd08d047efe52cb1266ee5988447e1b2740f960d22e9ed3f2573ea8753a60d306d654a26503a5416a4439ee44aefe08cfebbed56585eaa01a64bc812f589da9e9d51849b4d4feea04e2b03c4d4fe516decea1e3d9e7e35bfec17d7b2c218d8553bab921eab6410ad30cc131579497d186fa25cf62521fe9`,
		SaltVal: `b750587671afd76886e8ffb7865e78f706641b2e4251b48706`,
		
		},
		{
		hashAlgo: 'sha-384',
		Msg: `3b9dc97a36492a68816aff839c135da2d7dec5505ddf496670dbf0e0f6b65ce9352baa38dbc09a9f41f8f0e1f0ca1ac56552126811c786d7a4ad37dd8b4b9f1ab760d655a112b6148b273e690877340ebea10eb46bfe139926d3be59e8cb63064aa4147a9028c6ece75fb0c2eb03f4a66c3481dc726d38d37eb74efa131cf1d4`,
		S: `3fc0e79913fc234e4f271cd6f5aa63bcd00e0c4fe2242815645d384781d5a00485076bc011f4412457bb7a2cb2695abfa18471ff6087038d585f802995159c8beee7607330759f310107c35b4a6a9a48fc910f45f70bffed1281f2215af34759ab08b68acd539ddd37f98a528434cf11ae0e85ef221f7117c757d970f3181e9ccda927469aa88de59ceae91c270818137761e56d75a3c01ac128b65818f28dbf7dd268337356e97bd104df6218db3b1292ec2652b62e5aeaafd905ec8fe67d6ed42e805048deb55cd9d75f818236687bc5b2cf33e17678c45a9b2144d58a4c77c163e57c1ee42cbd92bab46678092aef867968d8e6a387f7cef3920e4ee046eb`,
		SaltVal: `b750587671afd76886e8ffb7865e78f706641b2e4251b48706`,
		
		},
		{
		hashAlgo: 'sha-384',
		Msg: `93ebc05837d0d50897a1d10bf1b08a6a767e52bfaa887da40d631d6cfb0b1011d1793d6e51731aae48a872056dfc659e8d21b0d4e5672ea4d0d59f62a278a9acd3fb1c9d60787a426e8eb75230b43d190ccc33b6f9fcff862cb909e0f324c203e19ae64c2b86fead527a285a027f1ac53ba965cdaeeef7326a37e44db7b866fe`,
		S: `19b1bbc3e4a23b44ec429dc4479f3fa45da87037136ada535bb325c0c03193a2ed8216a9621e9f48ad2c53af330570fdfc85fc1dbb077105af39e8e3a9faba4a79ffe987e1a37e5a49c60320d086e9292060e9fe671f1bfa18ad79f1ae559551a1d5520f8164a877b3fe1938fa51cbe8b5110a332c500585d288d8b30855afdddd233254f62e56eda75ea6854b84bb05e5b4497aca3d20baaf2d6d228a400135ecc45161c3f2e7258f8e4742aa687bd9f7a4468a61558fa0ddf79e5e0ca51ffaf0151bb255152219c76a08c3e46557ed6b1415622bdfd94f733ac10d8f388c0ef646d8f5d71a3205307db703d627287e2b7be15c33fff19147e5daa36d4252b1`,
		SaltVal: `b750587671afd76886e8ffb7865e78f706641b2e4251b48706`,
		
		},
		{
		hashAlgo: 'sha-384',
		Msg: `8bb56404897a19140d112d939f73fd7d18a5d107aaa20332209664a0674cdba64eea4fa48adcc791fd0ed0da385e206d3e5178108a04cff85466ac9711a5d4b539e625c24c39c26b17cc706b345f40a4d0f76f6eb0d78a2f76acd52c2108ee9ed411ae09d87b50c9e3b3d5ed9b5da64956017cc724017dfe0fcfa806a15c728a`,
		S: `12f03c6f02b34f921831df384cc6e30d0b64f8ed133133ff190caca2503f1a4f4f721de6824ffde125bf41ae216e5feb8510e4d6337cec56f18550e78c69b1618457bc1b604d109e526c788628391ad8c29ad6c5da268922a55e4eb3053415a9de109112b5fac1f996236f46ed3a6c2f845c36bab09a4c21da20b17d2590c7b058fec130fbec4856ade373b6b0773994bed5ac7a420a09df8c1de246ad453dc8a62310accc9f0bdff16104dfd74c7752c33df20ef08c52d0bcdeacdf2a31298a3c72bb7397c3f9306fdbec45287688877fd6c965b8dcc513c9bdefc2f9ee7e92bac62438e4d80bd3ee2ca50a024d6fdedf39266480b2ec77eedea6b64a9c58ad`,
		SaltVal: `b750587671afd76886e8ffb7865e78f706641b2e4251b48706`,
		
		},
		{
		hashAlgo: 'sha-384',
		Msg: `35ef7f038e9b98a421b9f6a129ebc641596380ea1648bf9fe35c50c71ddd8930e8a9dc5369a5acda365e5e5f0af1b477be2956ef74e8b25516c806baff01bbb7f78ef5ae658b6852c0e26d6a472655d2f2bffdc2a848a252b235f73e70b975e74ae7f39bea177616a88b4a494652525ade6d9ceb1831389fa0ec4bdad8cb5fc9`,
		S: `af809f10fd160a88d42dc9d92285e2b2afd8162c38eb91a6b6273a66c30c79d7caec94a00fa732710d9f751219767185da5064ce26fec0647cb0670ecc68f2a601390dff07ff0237f284dd4fcb0b11148835c8114c5a15c513713dbc16286707eecaf2c450f588fc96217d34f59e0c716c7348270041b2c4386f5a5877f7fa48510cca8b07b70490f9eee957ec0a52ab955a3f1054695a7f5806f705fe3e9802770d591eddf2a83fe03d8adbf553ae59528051218db1f3fd070f8e1d3d4b4083588cf2710271ecca5d9369468d045b0f2e0ef285f9cfa65a04cd223fd84c01b8c740a4e95b9fb675c0d7c470b3598d06489bb7d6722eb72ab8120d7f0ae29a06`,
		SaltVal: `b750587671afd76886e8ffb7865e78f706641b2e4251b48706`,
		
		},
		{
		hashAlgo: 'sha-384',
		Msg: `b4422216f1e75f1cea1e971e29d945b9a2c7aa3d3cca70bc8dab8e61e50d6b038f9f46fa5396d5323f5b2c7ea880e12e6bf96ee37889d6a2927a8c285091907d6841dbcc2c1ffd725596055500dca177f62486cb301612479b7c303a183e7de0c790a933856a1f05b338e84c3ad4ccbdcbb1bb9c6c596cd23019444045fa7953`,
		S: `0f31c8fb4cef7233cc20bca20eaa5b42a9aed4a4f40855e2c518501ae1cfd71f98bf9ffdec1a74bea75bdf90b9c67c5824a7054ae57ef49806359ed64b2c5efdaf52829395fe426c802665bd7530ca3cbb40d5f29367ea55eba29903e8eba5df7556b5527335ac06a211c597e916fd6978ea5bc6daadccd4fcbc61ee64aacc902f652e545ef48579cd523944461d9161a542e2e7bd2a1da72ec9a751651d184fb75b16951e1b5a98107ab3ba680df0dd06131a9318e47e15326f27fc34dddeeac89b11236fdc9b8f799828dfa9714e6ca3982d8f79efa2a455e6d73421a1c933c92902790eb79adf0e4fb6202b6a0868aecac2208ab673b249a826646518aabc`,
		SaltVal: `b750587671afd76886e8ffb7865e78f706641b2e4251b48706`,
		
		},
		{
		hashAlgo: 'sha-384',
		Msg: `882c97fad763ca235b162fba88fd714d023bf7380133681cfa9e6a8d7cdab00b58853334044bbf3741fcb28cfce201e372517b5a987f52f2ba96d744620885707b234157b6e5e00a2d11ea8147829d91dbc0351898d16b7ba4523c5283c6eb613b2d49cbb5d93482677d5e023087503f83afaedbc8d0bc9dfff7211fa7baebc6`,
		S: `0c4850b815169cda5c11f77bee14ff2fa1399af8dba09fb9485211ddd458e4152f966b2162cced299e496ca0c6cc891fce52fde9be554aa213c9f9dcce053452fe0702bf2e953ac6490c97660d8dae7ae557d94e4de409100951bd3f8be77ad5e6a7f8551190a1f2ede40fa5a12e5d995c7739221fd9be3970c05dfc990a103db1e9dff25e37234be4f70b372a4071a9c921a34de8f6c56f1106a2431b2fc2d60026c7f2cfab11ee75afaab90d72dc8e15c6d6ddee0d4302341f107c541b23368995b6e95a0efb3624e70e7980533a4d6cd823e26072a4bc88f2c01349222472ee394b86ec83f4fb9df8fd105fedc77d28b7a7e9d71451219eb42c25764bfec6`,
		SaltVal: `b750587671afd76886e8ffb7865e78f706641b2e4251b48706`,
		
		},
		{
		hashAlgo: 'sha-512',
		Msg: `5f0fe2afa61b628c43ea3b6ba60567b1ae95f682076f01dfb64de011f25e9c4b3602a78b94cecbc14cd761339d2dc320dba504a3c2dcdedb0a78eb493bb11879c31158e5467795163562ec0ca26c19e0531530a815c28f9b52061076e61f831e2fc45b86631ea7d3271444be5dcb513a3d6de457a72afb67b77db65f9bb1c380`,
		S: `5e0712bb363e5034ef6b23c119e3b498644445faab5a4c0b4e217e4c832ab34c142d7f81dbf8affdb2dacefabb2f83524c5aa883fc5f06e528b232d90fbea9ca08ae5ac180d477eaed27d137e2b51bd613b69c543d555bfc7cd81a4f795753c8c64c6b5d2acd9e26d6225f5b26e4e66a945fd6477a277b580dbeaa46d0be498df9a093392926c905641945ec5b9597525e449af3743f80554788fc358bc0401a968ff98aaf34e50b352751f32274750ff5c1fba503050204cec9c77deede7f8fa20845d95f5177030bc91d51f26f29d2a65b870dc72b81e5ef9eeef990d7c7145bbf1a3bc7aedd19fa7cbb020756525f1802216c13296fd6aac11bf2d2d90494`,
		SaltVal: `aa10fec3f83b7a97e092877a5bf9081283f502a0a46b50e395ab983a49ac`,
		
		},
		{
		hashAlgo: 'sha-512',
		Msg: `9e880ce59f547d592c309c22a2974ba5a52cf1c164f2d8a81ebbd4ede6e326dea33d9f135a4e0947b0b9c267aafbaae9b8583f5ff215074ca1e82f3601ad71fc455a3b6adc350d0bf345223e3b06548cec613a390ada9319e70ce7a5e9526b4e8dc82612ac72524cfdba05d0dc201037492d277834a843b9f80d4564253bdc7c`,
		S: `8c4f819e682081bb16ddd459662a8078bca4793e18110033539460b408c0af747ea5d941f712691f5d9ddb643166fd965f5b51b819d55141d67c1553b27a4682e67d5555b64d7cd3db7fc5c2e701dd26e422af8a1fb52cd5f5a09e0d6db900a992f318deeb6f6e39dfd6af44cb217c6854089ceaa16e3f9b100ef8e78f6b453458b8ef6d71493e7c6e45282c617fa87ccdd4a0f2f9f7166281806fb41d0fe188e00c40afeaa07d2da09a2cd78052f8d56b7af40d4c7314ccf02e490d5e2123bf676f2bcbdabeffcf58792998dd0f67ed24e483d8976b00d6151a6e0ba740bdb57c9bc27fe5df9126a47020075eb222d5ca2470724460c5adf067b5750287cd00`,
		SaltVal: `aa10fec3f83b7a97e092877a5bf9081283f502a0a46b50e395ab983a49ac`,
		
		},
		{
		hashAlgo: 'sha-512',
		Msg: `a6133ca436d3f2e0a6562f138975bcf785cd0c3b58b7671d197b483bc0c003a6e947aa39d5d93229b27ed2dc1cf0acffe34fafd30f16bcc7214e074c9c02c1e5c4f2f47da68baefe5817611f82328a7e1d7d91ee7b96f0128847982b4ffd902ec07ce01ab0d2ad882189a583c4219e9bbcbe7935a51d4d25d5ccc27fe19bbaa9`,
		S: `20ceee0fd620160ef6a40966fa4ef3d8f68c002a66d0103eb62a868a7ad7dce9523a5b83607b8cd0ca54f833f3a68c9fafa1de7fd723e22a0f724dfca1fb6bd1a88a7dbd17255ba1e06102c2cddf584f511bdd09e132b016f867896a592a28c53c70752a0b10d86bdbae9503928d2e0203ab8f845c1f77adef2bd2f4e126066fe15af4a5282d5d9fa73bec18d2e6a5969d766eba55c0bb95e13671f82646c35b31d894e7f95f2fd35f60d88c3e70b20f6f387326400f0a825bb9517df88bbcc4798861144782dd92ccaed36aec47d5365d3b61a495339ed58e2553b74f06a295ae47a309d8477b9ca838e77094718565903432ce243c9dffe6dad464cd5ee279`,
		SaltVal: `aa10fec3f83b7a97e092877a5bf9081283f502a0a46b50e395ab983a49ac`,
		
		},
		{
		hashAlgo: 'sha-512',
		Msg: `6d60a4ee806bf0fdb5e3848f58342c0dbab5ee3929d2996e1f6aa029ba7629c96cec6293f4e314f98df77a1c65ef538f509d365ebe06264febc3666755a78eb073a2df3aa4e5d4606647f94cc8e800be22141208036a635e6b3d094c3a3a0e88e94bc4ea78bc58b9a79daa2869675c2096e22a40e0457923089f32e15277d0d8`,
		S: `912fdcc5719a8af7389db8756bb0f630a4c78a1bd1fec7c4a6f3e50924a9818c9eca4a4efbaf9e8bad55d6468d83c54d0450b53a267a50685e7fb93550c2ef3554f69b4e49d3be359bc0b88f3e753714684ac047b4dfb436140b13129fc4bbfeed86548500d487094d222ed4e249db0a46b34ba5247c1b86e8650a703c9d3e0374433d3af52578d35f0f9108439df0701188da206b579e1712811c1e33b3da32f33acc9cd0bed60cfe977a4a6c6aa6498ecebab9be86c216a7214eecb13c2b7d4d309f5488012056905060c3eabe90f36b01588acb328869034e00bd19bf5c1a44d8ea2a89b747b2875d97047c53f2903f67b5a60aa87aa70a9479735198a508`,
		SaltVal: `aa10fec3f83b7a97e092877a5bf9081283f502a0a46b50e395ab983a49ac`,
		
		},
		{
		hashAlgo: 'sha-512',
		Msg: `1aa215c9f16050f31f0ce5adc8cfa594e44ef29087dc23ac65ed2a2595ce73c0959410618f5314dada903c01c4f8d5058f52d902b9b25cd281ef2627a658a2d672a3f776f726742a994a31bbcc3cf3ea1fe551047a1d15b6a31be52307302334b8b6112fb243398c62220c046903c9ea9df1a0be50851800d659ae4241c0be81`,
		S: `6ba800b8692ae568344c448094e3e16f50dc2c53edcfbbc9c7be9c07461c0e0686fcfed607af2a66291fcf8e9653fb3e9857b208ba210100df9e6c0495ab4d13f1029089cfea49a6be8b62036f30e0d4e4c1d95a5eb9580397d3bcf65a9311c2d8de249c2d1d7472369537cccedf8a7feb0c170eef41341f05e7d17caac4261b62498776a5eb1d9ce7e4746b4849f9021f0aff917179750253c719017fb5dd6855672eeb0847ca075e589e320f356f49872455b30f8cc1a3a7e1a4276ed6a909be06bd9f89c3494ff7db432d0d4d3f3ccb0be71b0bda4f66ff79773004905c6102d964b3b5a5e28e4578840c0e488b7f2b4f31066b61e13821e88a0ddd2b1c2e`,
		SaltVal: `aa10fec3f83b7a97e092877a5bf9081283f502a0a46b50e395ab983a49ac`,
		
		},
		{
		hashAlgo: 'sha-512',
		Msg: `cce6ea5a46bdd6805160dce409d1023cd71d3893303ca0497f392d5c5f936fe50ee2ade61ebd35426edcf00d597a39062dfdef62dfd9c9ccfdb2eaa9e3c1b6a03278e35a7e69d386476421212bdf7af4599bae5e49850653abdbd9a59d8f5a8220f0b43fcd875953c43f96a7e6ca6c0d443f9b0dd608ffe871fb1fd7f3c70494`,
		S: `9a465479c1474c1a54f16f309bd87b0c641a458d86173a4f29c2829fea0410787a81b3c1360cfc525d133dfdecc13acdd5199954dd8440739608545724cf1270caa39a221e9c6bfba399b9b05e55708875bac1578642ba7211260662299bf5ef68a39594e38faee14989ac5b2daa13211ece394cde46afa1b110bb55f631bdae5b848dfdb8920d7c74eff82ecdf59f2c6ed9b818c2336364b2a56d34a22ac42089dc5730e8e57b356cc4822c1e646268dc6a423e034b8b1512d41b88c70b27e431d68151e61a4fa5c89f1e90d621e07228c0346ca46f767a989f1b0d007237645d448030a7fe45ee0f46521272a8cc453a835984f8268752bef801b6226140b5`,
		SaltVal: `aa10fec3f83b7a97e092877a5bf9081283f502a0a46b50e395ab983a49ac`,
		
		},
		{
		hashAlgo: 'sha-512',
		Msg: `cb79cee1e7c3546750dd49fb760546e651e2a42ba4bbe16083e744bd1385c473916d273e9566673e98995903b44590e7acb580a02c6fdf1552af51716c134376049817151ac5823bb02633ed8cfcb697393397a14f94ca44f43c4a9ca34d01fe2ce3e88bfc4a6f059f6e1fe283927e9fff45335793926a9472787a653d9ac5b1`,
		S: `7cfcc23518bc137b94dbc87e83e5c942a5297ab4f70a4ad797b1dfa931c9cfcb30449ba3b443fd3abf4d350b80feaa9687b39e7b5b524ffa35063ae6b4e12a41fd734a24f89c3652b449c2154099a1c7739d5db77ba9de0358a69ec99bcc626f657213a256732631461851c919a93b04ad39800f02d0e627cd01d4b80697a9a1fb0d71df4f32ecaad3f1d5c80cac67a58c71ce81e23fc8a05ec840019c834d78ee1955c5e41065b323d01fdbe81b768448b4a7388886c9740b1541ecd8454f73ab64f90dd46cce6a2329beae9f3ee0bf567b507440ab3ca9de2e855374ddf6e105b3d0b33a138d716d138ce9f9570797a82eae557cf321fa09b862e31ee8d85b`,
		SaltVal: `aa10fec3f83b7a97e092877a5bf9081283f502a0a46b50e395ab983a49ac`,
		
		},
		{
		hashAlgo: 'sha-512',
		Msg: `3ddc491798c6d8c2d6932502e14ca0d6cd90016c219438427268a38b377c84d4d862b2e708d58ff055fb39defde7050c0462292183ebb83543fcd4358a8f1f8835e172f20776d2b9415d9f0773b50f909170db7449573867944e090f8cda53ad7de0f1003eb08967c241be45eabea7a99d42802f1be1a0218ee7abe2e364098d`,
		S: `68a46140382dbf84b1794ce86937812d8220fc59e83dd1afa087efc41883616bfffb8283bd6dd5ee1930337951ded3be23fdc657e1bc07f41b539eb779ec98f436b367259b6841e495bf84555aff07674c9fb705c85a9cc1fde4bad40506e3373cc3a490daada1c10705177c165719104daa8ab675666625335e09a24f7a2363d7b3b878f34fe68fe01425275881c34b60ee78fcc0a54d56ac8304fc7a4bc0d5a447ab89b9206401e3c445bb1cc8e0c2541fe0f3634bb49d5af3a1b7c2e7651d208392718311247f0f15e4041a46301b93da2cda7af833d80191565833926a78468abac9eb4b02c5f047ed38851c3ed7add4edc05e8407481b8b942ab627e03d`,
		SaltVal: `aa10fec3f83b7a97e092877a5bf9081283f502a0a46b50e395ab983a49ac`,
		
		},
		{
		hashAlgo: 'sha-512',
		Msg: `d422e63e3c65eff3ee15c7eeb2ef0de7ab96a3c37e2af9c2b71d8ffa6842b504122796f5c9a5748f94b535b913851f2d64cce071465ad1087ff37be97c5d5b3038b8e2145f0ec019b22b6286adafb91a67613efbbbc633efa5f32bceee9fcc380c7cd48344c85af7111e573ec99364167efec5492297a7dfefc4a692062f9282`,
		S: `2bc6331715b62972a0a5dab2138c5663b0e33961063ce973e68e1ad172723bcea293f7ba35af24504cb2e373b11f80b49f79d3905e0aaef838fc7c7fb5df49a322d7c3daa294a1a0a8b71a52e2c5dd94575f319c64ef9f6fc6bbb70c0c97fa12ae78f73234aaeb93df299f81513458ecd243fca5284f44a1afcd0575dbf5f81d406236ce315e98ba4c9ef7c1d43896af3b5d172e7a786fc58c4220c27b56e5c7a9be49a40b49158305034a295a6c5743cda6c2c69f7ac02f87ed6cf7b4e989ce8218e5e7cbdac12fe7de3a5437170084ef8ce33e3530392c25a58ebeddc086685a4dfb9c0c5b91d946df65161ffbf82aa3d6a80c7c07995aa3ee06b1800a54ee`,
		SaltVal: `aa10fec3f83b7a97e092877a5bf9081283f502a0a46b50e395ab983a49ac`,
		
		},
		{
		hashAlgo: 'sha-512',
		Msg: `6e87214fc1a8b0116f04a45a67e101ac75e9933366c532f96cee4559c4c085b695d1046d1c806d0706d18db41d7812f5273393980b5dd1e936c13d273dacba35c446a3929e21108b361355af2d41cc84447dd5787dd21a1a7d5c188a355ddb2ec18e08a790b32104c6720535de65b6c2946e5fbd024b96f5096ade6cf2fe700b`,
		S: `802db067a8d90967c2860c9076c1a0227560b59b66350490af1153d20b31840918e7d7262f633d37880a153b1a23e40d3cf9fcbd9c1610878b6317d9d1187f80074512524561f1c0f99f1b2ba168a15eac098b2b20673ac63f9b002e60887ff296d1212dc696450e7bb14a3efbdcdbc7f4ae2210ed35a3bf028d3eb99ab696f63a2fc69d8cce4b45846ab88943f89d588a72f00f15e1ea16d99961084542467b8f998c118fe76a2a326cb1ca3f9959c06c810a004a67cb0655f8c6202ff5e4ced43c4d8e0c3683d55607d4ddbcc0d9dd4e1783b58f51f95e159fe593066cec53b544f2391cbf0e3dc4172afd5ff6de23088404f7a496bbc6a4ce22826204b6aa`,
		SaltVal: `aa10fec3f83b7a97e092877a5bf9081283f502a0a46b50e395ab983a49ac`,
		}
		]
		},
		{    
		bits: `3072`,
		
		n: `a7a1882a7fb896786034d07fb1b9f6327c27bdd7ce6fe39c285ae3b6c34259adc0dc4f7b9c7dec3ca4a20d3407339eedd7a12a421da18f5954673cac2ff059156ecc73c6861ec761e6a0f2a5a033a6768c6a42d8b459e1b4932349e84efd92df59b45935f3d0e30817c66201aa99d07ae36c5d74f408d69cc08f044151ff4960e531360cb19077833adf7bce77ecfaa133c0ccc63c93b856814569e0b9884ee554061b9a20ab46c38263c094dae791aa61a17f8d16f0e85b7e5ce3b067ece89e20bc4e8f1ae814b276d234e04f4e766f501da74ea7e3817c24ea35d016676cece652b823b051625573ca92757fc720d254ecf1dcbbfd21d98307561ecaab545480c7c52ad7e9fa6b597f5fe550559c2fe923205ac1761a99737ca02d7b19822e008a8969349c87fb874c81620e38f613c8521f0381fe5ba55b74827dad3e1cf2aa29c6933629f2b286ad11be88fa6436e7e3f64a75e3595290dc0d1cd5eee7aaac54959cc53bd5a934a365e72dd81a2bd4fb9a67821bffedf2ef2bd94913de8b`,
		
		e: `0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001415a7`,
		d: `073a5fc4cd642f6113dffc4f84035cee3a2b8acc549703751a1d6a5eaa13487229a58ef7d7a522bb9f4f25510f1aa0f74c6a8fc8a5c5be8b91a674ede50e92f7e34a90a3c9da999fffb1d695e4588f451256c163484c151350cb9c7825a7d910845ee5cf826fecf9a7c0fbbbba22bb4a531c131d2e7761ba898f002ebef8ab87218511f81d3266e1ec07a7ca8622514c6dfdc86c67679a2c8f5f031de9a0c22b5a88060b46ee0c64d3b9af3c0a379bcd9c6a1b51cf6480456d3fd6def94cd2a6c171dd3f010e3c9d662bc857208248c94ebcb9fd997b9ff4a7e5fd95558569906525e741d78344f6f6cfdbd59d4faa52ee3fa964fb7cccb2d6be1935d211fe1498217716273939a946081fd8509913fd47747c5c2f03efd4d6fc9c6fcfd8402e9f40a0a5b3de3ca2b3c0fac9456938faa6cf2c20e3912e5981c9876d8ca1ff29b87a15eeae0ccce3f8a8f1e405091c083b98bcc5fe0d0deaae33c67c0394437f0eccb385b7efb17aeebba8afaecca30a2f63eac8f0ac8f1eacad85bbcaf3960b`,
		
		sigVectors: [
		{
		hashAlgo: 'sha-224',
		Msg: `c8ed14895c80a91fda8367cf4aee386b8a378645f06afee72f7c94047fddc7aef84c26c83fef13bf65a3c7750c91967ecc02748fd574b933d5ec21c01c8f178afe6c3356789d0112178e04c3169cfabec6e2621b334f3c6705fc1099a4bd3147a0f7431a4fb1fb80b8ed26a0af38ed93428057d154260fe98854687661919e4e`,
		S: `27b4f0aa139565fbd7860760610f6866d5b5f0d777921f06f5053291123e3b259d67294ccb8c0d068b8dae360aad2cf7d07296b539e4d2e9b08c343286d522f7dd63c6620e8672be492f3b039f73d88ab9d22a5463cd1f07d688e8ba3fbad531b0c3870ccbfebb596ce4ec643d309744bdbd675d5841284cbac902cfb70ade6d33946d8dc6109bbbc42412db25b8c62222c5ff94f8eb868982265392a44e807474910b4b39558bbef33197907178ce146fdd7e94092ad58bf41a474e626136789fc2fe6374a1b5fefddd5fecb7f8ca5893220d1ab9e822c3ae8adda1ebaddb18a6a12bfc165d12071441a991377cee6dc8e50839497346fee13f12c5b7b6d024b8ecfdad80d5ef6e9e4996ac21c4eb6036bb51f5be5e38f265181154000824e3c1f231d18589ccdaee90fe307ba56324318b5358468e9f3913b83ab8b34d949629ed7839f8da85bdcda52f3da5a419f777b3860dbf2ffe28d96244312549528a20cc7399fc010844365806167fe43235521c909587c2c7b8db4e296dad2aefa2`,
		SaltVal: `3f805057471aab0a28cfc8430dabcf990612e8a908b158ae36b4ed53`,
		
		},
		{
		hashAlgo: 'sha-224',
		Msg: `d04be758e97644ee60a9212e5eb81a1088041aab31e428b0cd4a8437a9a3f3bedafe576e747182a1fcb84ca21f20e3b3a3a463559f55a7c3e7ff5ec0cb096192019d444fdf092a57cd65de22fb76203c4fd33d8da246e3de2b7532993bc216d02b6fd5819306e419bdf8ff365a8478b173dad0dca281840881f6294b6396bb80`,
		S: `4aba732c6255f0bc443939c131dd4ce64478d4f58dcbf1d73f5f0e660c492315e987cafbc83a1a0be3d359a960783d293d375ccc3ec0d82c72abcacc339f1b42207a03795be6808ba06a891e3b4251e1b3001dfb537252572a33b4c52846dafefb24aca53fc08e63c39da02c4138b3de9510fb790f87566cd14380b138c728c243543b89d1f916ce27cada85fa32d8185deefa25c323c65c7ed578ca57276b66744a7a1a78e66d4e570999d17015bdbdd8d3d6185a3eb1dec8bc3a1287a2e235e4f116a8b91d06128d36b58ed4c9a6ed84773dc49f755e2e27a6f1aea31417069bd066b848095c002f22dd6caa72957e21a1e640f9ab9b9180df8ef8963e3611df2693a7ed064f348221e7edb1a5a81acce24acc335c6ee7d4f1af6d68acaf15d77e128142ca9bfc55a121b1b13fe5bafe2e4d6a5546b8cc631bb9d304c0e9f3d6d5dfe833c346965f0103698d34a51bca5db266afded271d8490645b3f63efc991e01683211f9482d214cfa9220f7bc81e8cbb4d118a2c306709807c070c60d`,
		SaltVal: `3f805057471aab0a28cfc8430dabcf990612e8a908b158ae36b4ed53`,
		
		},
		{
		hashAlgo: 'sha-224',
		Msg: `39d8ec4816fa9365cdf299ce60053b9c1e99540ed29d2d163a249718ba5337ee527e222fce8eaab13ca6774ca306d9e1f22f5c9b37479d7511c05dfd6835d4575b9447847a82dde536fbaffa95391e702bd8695b45377fc067211156f9adec8d3d6286d0849fd607a23a69619f68b350afdda3d564347afd2390dcacd5842799`,
		S: `0df81ec6e9c2f0ebe824c445009902cd55e2718523546f08ed13faf811ec4e57e6f5772037e07025c3c0c99cd9d6c885682e0eb904a3314b825948819acecd195c845a81e22ae62c13251823d6ee386e0be17a604bafc6497b7a6cdaad1a33cd5ae33bdd50e62063bddf6d12b878b31d3b7d490ce86810f9d456739bcebde592b07808350aee542455d1761154188e6e02cbda795e48e4f28acb819440bcd8da53fdf19808456898a18fba517af06b51156129b0b8029547ca9bd9436a0673e5b5cb995340fc425fecc566acc99884e0b4fc87248f5b35bbf08b0dfd0b9ead06737b67c85f94e1eac8802fea1b1dcea446b7cab8a45b25429750946bc8b22e076828a0a9718277568b9b7202a8cc3688d44194e834e0a405fb9eea46bc7e94255d600ff6c95a46ebf46449510fdb39b6ce05a20ac1832938b659318764dc0b7e4a0215fd253f5219296fbc82f03a7b95a12628d219093e2cdac42e20eba3dd5aeeb9dd7bef5d647f151b04ab85c48970cfe73ef9fc3e7d1d8a138dec3f5d5fb5`,
		SaltVal: `3f805057471aab0a28cfc8430dabcf990612e8a908b158ae36b4ed53`,
		
		},
		{
		hashAlgo: 'sha-224',
		Msg: `f7b22de3bee8295c4d8c8a94da8cd704c5541c97214390bc6f5c75baac3f40458f57fa4e0c54e61f1cdc64a6c07d151143e7409cc05874a7e5576f0cf6a53faf1571a757c0cbc4bc9b5bf0e17053e7a374a22992cc6b9f014fb580598e6476b31168fda5e4340c5b5371f8eaf1f495e2dfee9e224a6357f136de704a7a622d76`,
		S: `727669abeb6bcc9502d7e88162f4a6c1dfe1a0f5141d3763e0f7e16744f9063874f153cc2de48784de84426b548b03e05a9074cef6a951640eaf9b32014d97cd9f3a828b45def13527f72a3e5e5adccaece82212c016c28f9f3312853bf52062e719081bc028f70831f9fc9132e8b63824e37c7cdeba463f9034d815683e27750cb9b383c3420f122a3b7fc6e9440925a77d766f93d586161e9607beb8a6e4ac72c32ef7b69ed52f5077a881dd0e494591e2ba552b74731c18cece9905561459f4553d49acfd6cc6be027833a220429d46bcb88dfcff0d2c5cb567371563b4852b7e628c4a6432af967e8ed69c9b6428ac552cd370922a0a4b01ef1bdfdcbc9088cdfb6d9fe326bd6b2bb1fc2acfea3bcf60d1fac5880b0510736b7e201ee8f6bc6332c0756315789700350fa549009d16e0bac084bf6aa3492f63367819506bf0c4f9c232fbd7c4d4ad663a7566108238c31fed887f368666dc75a623f222d357f8e523ff084111be4db6baf444f191ad1468d077349fef8a22f3fa56085975`,
		SaltVal: `3f805057471aab0a28cfc8430dabcf990612e8a908b158ae36b4ed53`,
		
		},
		{
		hashAlgo: 'sha-224',
		Msg: `8d48fddf28b05b42c9b4df4742ed8e735a140a6972165ca6696bf06ebea4e106f44478243bd1efa44c2b7a7c951c88f2962f450d8bc664494b671d8e70577163b86ab560ab194ee17ed5ba02389bd0c713c9489a25307dfb3f6a7273166d13c9a061be79c1af0262275ba7bf7393ee58998819fa897c2e240f1cf903f71150a0`,
		S: `a1a4d16956d718830f625f06c42e99189e36a80523b25f0c9a7bb85568ce76d1e85e437db0a7728b8a9c90d25e6f38150208debe54e1e3f648ff01798a8ce132e4b33f3d26fa8963771440fdc4f5d852117b3ccea975da10e5d4f27af1bec1b853b7b5c9b420012317a6c33b2596dbdcebf97bef821b3076ce86345309b6bdf29a4acd391d3b2e5c4a6866136287d17cb0e2d4d6a6cf89d64272d5c01849ed57fa2842074d3b7734c4c92be50a922d0517ebb9891072b1b47a710887004b238f90079d10fb2cad7f5013e7243089f3c601865c6bce1cb8d0d669f2bb709253e3f1e421936f6a1643bbbb7d503b0631f7e1660382bacf4680de8d70e24abf4450510e6b40475bfc9fe547752d0d5f63f40f62f4dcc903fe6d260fa45a1b85a7501065aa1900a3f841e54c136d686fadbb33b225d15ae6fc348be57fc9ccbfdeb57d5cbf53e3479d9bae9f4ff859cbd3fb076073ca016ad94086700cc85aced83aebb4254b0cfc814585f930dc623c7f85e89de6a554b9898918d7cbb4cd2db075`,
		SaltVal: `3f805057471aab0a28cfc8430dabcf990612e8a908b158ae36b4ed53`,
		
		},
		{
		hashAlgo: 'sha-224',
		Msg: `4753183ce5607fa03636db2fdc84722aeb9d98a6ed70d0282aba3571267a189b6aa6eb65871c5dcc59dbc7db8973c7c355ba2a2e94c110d1f4064a4087eb07077e67b0f634fc10bc6ee9b8b8e1a0a20bf47a14f2c8aac75375704995978fa0b50a003096f1e8df99fdc8766eecf34a2a4f461d9991133fd5355ef8175f4c2bce`,
		S: `2e078b29b5288a77ed25ecececa645f6d9298e4294e3ef08173cc37ccbf727ac9b092cd27d6fbd378fff7b1061b56ed5cf077fd1a227771f58cbb2c1195a01f830f0366f989aa2d0c486d441e112daeaf83e85958f65a9e60a1937d2a7022781fcd1a83b3f7641a743001ebad53a4669405603ba0393bcd94f64324f1b777068a3ab101a086a6972b2c11376307e7d2485fbfad85be7171d20a5251cf9a5f004847d172c77bd80fbac0870a0b6bb9733537ca72bb6eac351c21588287c317625a25f416129e6f53c607ae08f43e5e0339740775a531c720f3f731840184ac7cd3b1f7bb820ff30ba7bb120b21b4bae7f9d7fc34d7418f700b142cf8fff43d81599236ebabe93d2e89f4702fada8742dc3bb4bc8fc5e55b4f874ae59f5dc9636868828efbe1025a8ca5c61ed8cc832686d5d00c08775590b316060285dc5bb9d32c90a474a727ddba9e7a8b7d69bae555604add9de0dab0eb0d551bac067c0088523d134b2e50dfe3ff73eefed934c0984aa4a5c563b862d46ed957ec3446fd24`,
		SaltVal: `3f805057471aab0a28cfc8430dabcf990612e8a908b158ae36b4ed53`,
		
		},
		{
		hashAlgo: 'sha-224',
		Msg: `aad03f3aa4cbd236d30fcf239c40da68de8ef54dcb36f5a6f64b32b6acb6834e887c6a35423f8bccc80863f2904336262c0b49eb1fa85271ef562d717b48d0598fed81a9b672479d4f889e0ce3676e90b6133ee79cdea5990e2e02db7d806db4e6adee5ea76cecef9119e8393eb56beea52d3c08ebdfd7677d5a1bbc5b6543a7`,
		S: `1bc325412cc952a8dd6918db8fb08192cdf81bf4111cb5f0a580a82d4dd2e14d7445eb7cb94cca6da06d2b5cc43e6ec22a5c9c845d99ac0353050c1374866befd9b6b849cf3b0efcc644ce17cca0dafcf7700c9c7d870c1e14511651b1d03a535110139c53b55938cc4a471d756a55b50d1bd280c324ac4dbaf526590c48c197573f3a91c70373ec62bd168288b0d163a09e623589d1ca5a70d17aa54c8627c7a64d921aad12626f7d32d61e8f14d0aa97c2d6502021e70855581f5e353e27f96efe1bc78c7fbaece66a560b93c0e7365d97dc4c729235484abe10bccae99fa8db9425614b673d5bbc188ea8f465424f768d8031f7eefbb698f058e1578ac41426739410aa7eacf796f43a4e4b2b4a463984d3d17d6d667cd15bf2e2b487aec3493440794c09908545f416b701a130f08027b8bcab4dc4a78cf4a55a688b2e1ca3a73a08ff0ed890bee4a0fa858cf69142f2f765400e7c29c4b540530a054641961499c709dbb4f36e7e75a5993cb3ab8cd4c886f6a3f5e3bdd3d68ef0a77750`,
		SaltVal: `3f805057471aab0a28cfc8430dabcf990612e8a908b158ae36b4ed53`,
		
		},
		{
		hashAlgo: 'sha-224',
		Msg: `c828eca460b39703696750999e23486a432d80000882d061316b2e3ef4512d6d22d2c49a0a1551399b5addbec8d5a21131bcca3cff9f7a670ff80f075403a85276cfe4f6bf95ed0a384ab5450f707f6e3c31a21364ae897efe95ffe5b4f1a9e10c47d42147de72608a5e5e943b9de869aeb58ded015a068d446a8540ddc63b02`,
		S: `799450a1256d245df0bb7d5290abcefe69d3b0e3b94924072f2d67d53a966513955fa7a01b830ba2cbbb056716fd605a0cfdc05f8ff58d88cb1bf32248f117de41ddfdc466215fa4e704096947a2dbe836a99071ea7344be0ffc782d14f995e4bfc74dc3ab1fa96d7223ec456497a2f51e1eb199f0464d415aef00f841e39f4578a0c26d726f3065ee687adbe40207801857160d440151fa374257eaa3f777337d129dc8b8c701eed56a276ec90c03df54305f300ef8c51155db30b68c0b06dae4c4aa07e75ef0fb09299b2b04d73d0b3e874ea1b6ac4e16f1bed0cd8dd3cf958a27e14e09705d4f0e10f8d46c75a195380126b437c68183e6bd39097e2f45b1184f519b2eb101110db74519016297683aca4b461cec1d92a7e68cbf30c2bb0d96c3b33dc62d278b9a640478258c3405a6ab5fcef5280408d4573b7ae42408b9c40483768f16a01c9ee4163b325bbb8e377034fd31c787cc0db8a53f6c0ce93e7d854411a136e1013d69fd03a0171176dc0712640ef2f792c340eedd0d07a8e6`,
		SaltVal: `3f805057471aab0a28cfc8430dabcf990612e8a908b158ae36b4ed53`,
		
		},
		{
		hashAlgo: 'sha-224',
		Msg: `87edd97182f322c24e937664c94443a25dd4ebe528fe0cdf5a3e050adfe4b6513f68870cc2fdab32d768a6cab6130ca3455d8c4538352e277de7d923d7351826c9aa1d2cb52b076c45cf60cf0af1eaa763839b9ea1a4e6ec68753cce5829d333ed5ca6b8a4a6bdd6606fae5a0b05641680eb1fd7a975bc97e49137f3ace86edf`,
		S: `9cba01f79f3551acfccf56e74428e270949f78a00b4ff3507ef180ce4c78ef4c53f3b7347ee37633c653aaeca834fc004385f87798922c53f8fd741cbce15de8dcae8bb04c7d481a823eadac7d4d4546fa4b0cc7e25e67b166edde4b6f66748017a4dcef85952cbf37e802fe534ecb984cb32f446c02ccb60e257a18ac368c2d2ed21975093499e35880930f8529790c1c7762ae11526e829dc0621ac904b822ba4815d8f83ac8f0fb0f8fc11bd33b02aff4e406f8fda5efabf39e6641a791cf8241b0946b675fa48d07e48639cc1ecf420380b8581a539a4de60adb0da22e10ad41f8ba6af40d11e2720086a63db72a5d7fbe97929ab23cae1d75c485d614ca38094baca699e47200f7a792292b5c7ab95b960d6921f8beab94d26f9629d8702c40df696787a6fb6ab9d6f3c1240c2fe58c565c9328dcab603897693d9dc7dcdaf500850711e6f30b5d8498a38e348469df79c3628fe1403a7649e82f06161e0ece42479a56eaa845f0582cbf817d4ba7dced36e93a6dc7dc7362f658f06461`,
		SaltVal: `3f805057471aab0a28cfc8430dabcf990612e8a908b158ae36b4ed53`,
		
		},
		{
		hashAlgo: 'sha-224',
		Msg: `02a1a65f8af90a298636fe8fd31164b6907d74c8d38a0ef59a8a4eb80572625cc28398bec829bb544823a06ee0e4fcbc13397811f62d08662b2a782213604899406ab9d2292f288d22079b848b209af2471f4052700a916948650e86739b870964a0312216d5f8dbfc2c16593a8ce55e1577f113a8ea5205d984396d8cebc8b4`,
		S: `740eeb1c71940ccbc041cf204469bd2d6a461558b1d15c9eb23361cd55e1ad418a7d2851ed3d44f9c02881a22f9e4be042d451998bc181887950da38246dc1656243db15fef359fe50d2af8711b3973a57763bfc3964cfe3c911b937572e639aee53a98752598c4b15dd53dd9355aee866d5f1e48137c12c342e8f274690b7b277acd087f293cb8b8c9a3e4b3f0277e831a6864e503f925557511e57b5285221421879696802066587ce6f993aacb70dafd39f63f09cb3dcc28e56782dbfb8b4ccb1b19876101573ee9678a5f6265f808f75e7711946c27c7a22dce9f592acddac81c67afa17bffb766058e2318a1211079842bd5fc58f9cef4b50ff0ee1a293f80ac1bf2eb64ce4e1051e1abe55ee067db6c24130f0bf4c134b0abf1e2f4465dc50fd3799f6dc206b9a7d2fe34b4f4257065d7494ae733c28d70aadb057ce1bcff36edf9f9ca6908cac2141845310660ab759d1f3e651dd9fa8056a624efc714f51f3a4f85adcba68f4a58e3a956af93a5a52f2b89f9c914b48e8dfb919cfc6`,
		SaltVal: `3f805057471aab0a28cfc8430dabcf990612e8a908b158ae36b4ed53`,
		
		},
		{
		hashAlgo: 'sha-256',
		Msg: `c16499110ed577202aed2d3e4d51ded6c66373faef6533a860e1934c63484f87a8d9b92f3ac45197b2909710abba1daf759fe0510e9bd8dd4d73cec961f06ee07acd9d42c6d40dac9f430ef90374a7e944bde5220096737454f96b614d0f6cdd9f08ed529a4ad0e759cf3a023dc8a30b9a872974af9b2af6dc3d111d0feb7006`,
		S: `4335707da735cfd10411c9c048ca9b60bb46e2fe361e51fbe336f9508dc945afe075503d24f836610f2178996b52c411693052d5d7aed97654a40074ed20ed6689c0501b7fbac21dc46b665ac079760086414406cd66f8537d1ebf0dce4cf0c98d4c30c71da359e9cd401ff49718fdd4d0f99efe70ad8dd8ba1304cefb88f24b0eedf70116da15932c76f0069551a245b5fc3b91ec101f1d63b9853b598c6fa1c1acdbacf9626356c760119be0955644301896d9d0d3ea5e6443cb72ca29f4d45246d16d74d00568c219182feb191179e4593dc152c608fd80536329a533b3a631566814cd654f587c2d8ce696085e6ed1b0b0278e60a049ec7a399f94fccae6462371a69695ef525e00936fa7d9781f9ee289d4105ee827a27996583033cedb2f297e7b4926d906ce0d09d84128406ab33d7da0f8a1d4d2f666568686c394d139b0e5e99337758de85910a5fa25ca2aa6d8fb1c777244e7d98de4c79bbd426a5e6f657e37477e01247432f83797fbf31b50d02b83f69ded26d4945b2bc3f86e`,
		SaltVal: `3e07ade72a3f52530f53135a5d7d93217435ba001ea55a8f5d5d1304684874bc`,
		
		},
		{
		hashAlgo: 'sha-256',
		Msg: `60402ded89d0979afb49f8508eb978a841abc2aec59cacef40b31ad34bac1f2d3c166611abbed1e62f6b5fbb69cb53df44ae93ab7a724ea35bbee1beca74fc0188e00052b536ac8c933bf9cf8e42421a795aa81b1bc6b545eaad4024161390edc908c45aae1f71b4b0228e3104048d816917cba4ae7f2afe75e7fcad3873241a`,
		S: `5f183009708b379637dac2b14293709aa6d7e86c267a0b690a3c275031139891267c64e5edecdff14c2cc2f2d985b62f900aee6e04ca51a70a5f946463691cf16c2d45547c5374f15bdb8881641d3040ef57807532cf5b2ced07623d0f638b39ebc2f2ce283eea2247e1df3af5430554d1d4b88b7b21622993419971b7d0d5449122a10fc31b2ddcc53ff751ff4bf4d336fac667b646780272db89a3ea4226afa20877bfb86ba3ff4204e5cd56e13a1dc9d53f5c9465b97a182b2bf671512ef89e6c3969f97307a3e4beba39a78e0ad1bb9799cda92976ca39d99db4ac149c84bb9bc8997e8d5e056d67ca23fe4be28e66c4bc00a25d65bb9d7d623fea2d3b9cf859dfd9efa9e52268bfa297afb1cc2883db0c9c42fc04180e2ec6f49657c7008e4025061f896886613895a35bc2d3655a8f50a9fca2ac648f352eb06bfba2fc340aaeead4a8457c65e2e8fdba568c60a6d8d381f5d9caa30127771f4a94fdb8cde7be4fa7b4f89fe379dd3e1ca66ae1fdd63bebdc0015448e61ef1666594b8f`,
		SaltVal: `3e07ade72a3f52530f53135a5d7d93217435ba001ea55a8f5d5d1304684874bc`,
		
		},
		{
		hashAlgo: 'sha-256',
		Msg: `2f03701c2fe07d47f5fa2c83a8ea824f1d429ce4fa1df2671bfadd6234ca5775b8470249fa886dc693d2928603b2a3899b48062a9ae69e5196da4ceb1d87b5979dbb46a2813c76369da44bcecc6f20edd753a51099d027e1610712ad98cfb418a40643100b2522ffdc1760454b4c82e59b09827e4102177e462a3792edcada61`,
		S: `8291bc1be9c981663156ec80c1ed1675763de06199b9f2760caaed5207fb4b3d6037bd08462b100bb1767e3340105b1a68728bc45c7d6fd078dc1b5e7cbfa193006d52f67e77fcf809cf26172a46db384eaf552a5fb8e33840fa3ef3d6b20c7b46c32ef019e8d15dd38eab66f6e40399ad0bbb07f94b8c555196901c27e2d4573958f53060d800cfff40c602308044b75d6451801c688d276525c3fee17a6792882a074c8a41420109e2511418c9eeaf3ab47350dd8c2d3e066abeb7913e08f0a40abe71d397c3dddafc41fbd04cc8fa3b0641bf53a90031b61a2a9b63d8ed8aacc9b301593c9f425105498cc4f84627f4950758e01a291b9b1a33ba918aacc172b68c9fb2c767c65910816921281aa8e5482512cee686e51cabe88e18f923fde170a506ba3c340fd1d68261986347d30d124931db2ce17602150000b794c050e137f4ebd45cc41f70ef3df1656218ff76f2e75ad96e4167eed524fa2ed9fd1a0cf76926f382ffb16124dfc87bb1a4110928d5b1cd3b16204ceeeccb7db88fce`,
		SaltVal: `3e07ade72a3f52530f53135a5d7d93217435ba001ea55a8f5d5d1304684874bc`,
		
		},
		{
		hashAlgo: 'sha-256',
		Msg: `af90f131f9fc13db0bcebfae4a2e90ad39dc533f34165e3262bc23ffe5b20450538669bf6a5210e1ffe4a583381d9333fb971903a68aa08901f14c2a71e8d1996e59889a36d7c20cc3ca5c26fbcd930128541a56a7926a8ae49a5ae786c4ef2de6527549c653ce6440c80b1ffc06391da65b7dc39ff4643bf3fe74bf8c0c0714`,
		S: `8c45e38eafaaf10a710e131bec63e51e67741774a9ddbfccdd131a123ae2a03067e7a6a92e653a25178bf527b93d6aa83fa366a2bd44896baa8b7f3f54830e4d9f5632c2d1bcae2aaae8c55782132aa7279cf1cbb6b7a81e4965ff84635c296c5ac206a04680e91e7b1ee7e5793701b1feb832250010d4ad4017c1608de8f405014ca73c39adae7c4adcbaee35fbbc71151cf955acecd8083677fe49ececcb62353c0a89c9dcb9c507979b56bfe060fec45567517c05f29e262df50767df7547630d8a7b32483b923bb1e3d510422dd4cc2d61a647e4f9636aa7587d4f8ed84b6174c1fdca9a217d9b907972a66c1f5a2ec2dadb60b93b515bf74072d315d17d54d57d721c8f4ce1a43eedf2025e51a48e9ea28160cf300d7a26010383c3280a186c44a53b7188e6caa364bf4dbe0baf4dcbe37d70e3a475cfdae339386558ccbc119873b1863975e2300ede1e420031b4cdac567e7b9c5d575c8bae27eebb37097050acdc87008ca2380f5631d190029a1d712acda147c5c4378cb6eac81731`,
		SaltVal: `3e07ade72a3f52530f53135a5d7d93217435ba001ea55a8f5d5d1304684874bc`,
		
		},
		{
		hashAlgo: 'sha-256',
		Msg: `e57debad3563fa81f4b9819405e41f98a54096d44f6ed119dceb25f8efe7d7329054de70173deb344c59a710cce03b16af9d168f6745eaf0eb07f80916648e804941ce7e583ab0a8a43a4b51844850edeaa4d7c943135efa9e770e9411a2411c586c423fc00353c34483f5bff5c763079f7e60eba98132213d64efffa94af7ed`,
		S: `851dcd2d4e1d34dae0fd585af126be448d611acaeacfa34f1492aa7d1caff616707dc31b05186cdbef769479243afb341577803b579e105070ad5406a6744f56e55f569370b9fcf6ab10e1aa0383f9182d451afb41358a2f8c29d1a571e11c404e6870cbb04f6ef30414d9b6d7f1416bacab0184eebd8deae72f2a48bea3a7844a8bf472a5f8d349d5973ffde3b1c40623dbaabd6f681485a9691c9be12618bba393b396f41cfeb89e18e378c51f147c7b0ededbc403bb1306454848c9bdb89f947843d0aeaadcdf09bad99efb76e742322521929f034dadffa483958df58a71af7da45461fc408c7c45973fc60c37a6358743315169b3100d4cd54f810d6e0369b9847ee38795cfe58443019523c3c9003edec4cdaa70de31d00958653058d8509907a5149a9f81be0ed028724f7232b57f93dc62ccf093a2635ee1e5bfe6ca9ea017ffab79182eefff542d278c471e1a2b34231700423bd0e757f6a572a14a99c90329dd0701f347d8a679cff25fd6b0d380ee5dc330d6ff1b4b1a347fc98d`,
		SaltVal: `3e07ade72a3f52530f53135a5d7d93217435ba001ea55a8f5d5d1304684874bc`,
		
		},
		{
		hashAlgo: 'sha-256',
		Msg: `28db8ffa55e115df7f188d627cd291fdecfbeea1109e1155e0aabc2157f7fe2a1284611e190365d2fd972d2a23dc793a5f28d4aac4100f5fbb2eed57532220d5d8d774bfa7084b44400249c19dab50e6c3c3af15966a960af1e2cec1f697a694a35c31a5a6f8ae7b73e148f09347004a3f54e7a82db390a0aa4fc526e95d79af`,
		S: `72c5555111eaef954236163753674a6ff81f182cbb379bfc6b548a52f9a5f260a0ed58f562a6086cf5ed00ed30adb023e90076a8adfa17cfd7d74f1e7b1978b210da847eda6b49891e6bd3fc6cd4c87b9326e8481a16c66e40021e5f878c303d3d8532bd7d966513717d5499865b2d03e378e76f7940f0448ab4d112e3c52cb332d340af122de3ee849f2e2544a40691ddf701d902bfe629766b36d82449286fd03f75bb2632dd61d6b3c6ce1c9ea8e5aff92ad2ca95a950eecd998e495e90e1f0966f922b7fb3f03380385f3b143ac1960c3bb688adbfd91d8fe1a1c32160243d3bd231a31c95dd78b6648c1175fa9c3c1244b1fa34d7c6f3255853ebacf5b3ec19b864e0a4eaee63fd719c21a72fc25b30b03207cf2aa45fd15d7102e5bae90882d00a812959593031ea3a436898582cae5eded5c7ce43de3dcac30b8690631e8db9f7a0a7f3f67b7524db275aafe02448727ff629d13afa94801d37526fbd9176fc4c216211037f8ec26b4f2672975887d70bcdbeef1e6ae99edbfb6c9a9c`,
		SaltVal: `3e07ade72a3f52530f53135a5d7d93217435ba001ea55a8f5d5d1304684874bc`,
		
		},
		{
		hashAlgo: 'sha-256',
		Msg: `4839d71aabdad8b15d9f37c3d37a346758d8941b01c83909e460f589855ca0e691096865cf62698353787e7ff517561801a6ca98304f6d11d76065e75ff17a8ef5c86d9582798be4ded181424175721afac7477e6309476c14c5e750576ce3cbdc3d8db3ae68655b6674eb149fdeb1f3a903b4d5823feca1015722cd55140224`,
		S: `796ac3f6adf4eabcb7a528ca63a6168ca6d31d5e357ad7a3fd180334a90d22bab20b762d767a6e3077c2cc8732784e81330041dc79068d50753bd4109c9c6f9ba03b5ac44efbcc23ecda27948511645fa17897dad7c122957ae56bf4ffe3d7bef85010b33d3b91785b0427417d94b11f73fda90e6a8748e6acc1d2d582e8836bc7dbe196876a9545b2a3207c1d4ec28acf8fe6f24c240b56ab3b4e4313a3d951aa1a558230e5f1eaf38cd7fd9b393d58d359f58f4ae51dd3971b418c5b81d0707cd9e2c33a148e492e74bfdd565eba8b1f3935e37a9d1a8764cd30497066e3c4622611fc14c45bf46fc85b3ed3f6c9d4d65e9925fe4b85ed30ec35ffc69c5fdc2bfa35d1bbdcb20e399cf934fe938f4c5798cf091d51100b4db4be42e81901e5dc79a98074119b7980b02821f4c3ff8ea07a2fc09a701978364bbd00ce4c5e2e45629526e34a3652719d27a47371480daf52fa49844f6495f35e6f5e3116c00b27042b3cead283bfc577905f8be87f0d5daa13d1ca74203a9e0d9199e885f4fb`,
		SaltVal: `3e07ade72a3f52530f53135a5d7d93217435ba001ea55a8f5d5d1304684874bc`,
		
		},
		{
		hashAlgo: 'sha-256',
		Msg: `c0b8b24f4b8e0bf29168ba73aa912c97121f7140f3259c40a72a6d6f78da2dfcabfcda00bea48459edaaf7b5fb5a9aed2e6d97959c393cd1a524a269c15e8c207cd09142be4f7e7d5016f6f19c735b8ab4c0f28e96954172af3cbcf29d65a161391b213dd5f7c006c294fe5016423718abffc8546ba373cdcb5a053196573564`,
		S: `8503b85dbd9eba8d6fc57c6ae2103a78df1fff3600585e3e18f6ba6436a3acaf8e49fd12dcbb37c25b4b765037f545c3da8c39ef6842bc9ec264af6f519272f3d8698ef2ceac55393baa9846a7961b738e41f6360053d866763c824bc5873da14a28eb47d68d67f0cad7880853aeb561045f757a31d9f5c756f54d793637d721c88fb1f60126d3d16478f1fc15e0c4edbb531c2ca2e2fd9e8dabe1df2c09fd55bbc724ebeba290a7646249cd779fa1a923909b29345e54a2e25dd935bf0612a5580018b233d765a6fae3b46ef51bd8325912f439a7dc40148fdb754e2d866f357b8f0ebff6f18a6504ba31d10fe45226c88c9207b9be3c63261d75270466b43c271f75b1ab3c1d6b5a00dda8457b4d5c2195f320b0bd545fdd0679c84483c14a46b4d43c8452879725aa91d01fcc2c3867391c72200ca5d628ed9b566389f02fe74ba2a428a7ba31c00ef6b8d38c6b82b7379d2feb11031848fec0fac5b6091eb7607138bf0b96c3d2c174b5713d0dc8470b532eee6ea0ca1e8ffa3b15cbe0bb`,
		SaltVal: `3e07ade72a3f52530f53135a5d7d93217435ba001ea55a8f5d5d1304684874bc`,
		
		},
		{
		hashAlgo: 'sha-256',
		Msg: `4935eaccd2af7c5b99405471bed9b21da8965004f5e6f2a6b7ed3ee2dd26cebcef4d845fff7c1d5edc94093f88de7a3aecf2bc3ecbd8c435f56e0b89bd099de7ac5f6c4377a5eb1c2ff4d801b8f159547cad4b4e60cad743f8e04627f61e1652e9354d8024710d1cfb2969be365a77f2bf8fa63b9e045257270a96c572ad6285`,
		S: `66d1cea94b9603efad92b6ca8a1fbe0c6c4b9dc60ec0ab2c33bb62d27a100e839378a39208715de2102eae384ca407e92787ce1118f91a0ca2640a5c93fdb78635bc91082c99968ceab289890b3ec210d6cc6f1cf7e0fbe2dae88155e88f2fb7b325ab5e529e4b63493e551c53ae38c3fbfae49810050a81cdcea627da21b63224612d4361b9df19761d6ead44488dcabb50127149f077c2963afc049ac8837ff2c29e6a35593e22531ecc2e9ef8bcbaae4349bd7227ff3e13b31bb929bbd49e50059f28fd9ffe8c296a056c2760e5f6d8dab43e9bd557793f0759ad8e08b5c3773a305a0d316ff9bd07b43106335942055adc461a4346f05ab455780f32027de8b8bb6d4845bb24d0c5a21c293d2b0740e8d06ef5fb9dbdacb4fa1c6225fd4e19dae69a8e2cbfdff1ef8b7f21804ead0a45274c735fccbfa1d60bf497a3aa931bebac2e0c8beda9af596dff0cbe11e8d4602d36b2f6c6f5bb80f12f4b9daf2c0748f591098ea63d3193f50a1f4737efacb62ea85fb6fb212b3ec8effe788e55`,
		SaltVal: `3e07ade72a3f52530f53135a5d7d93217435ba001ea55a8f5d5d1304684874bc`,
		
		},
		{
		hashAlgo: 'sha-256',
		Msg: `3b8a68da11b61b5fee1c2ca00a6aa35bbfdbdd42855b284320ec8d0c1848edcf6ac850427d8479eb57bcbe9a11771637886974bd561a5387014592cb717e8364a8183fd4ad463c89c980215ff629d867956ee5e75f71f7a19ea7bd589d7efb915d44dd9789448bc1ac32fdf7a2c911734db2dbc589a83c1a61dab6bd83907ede`,
		S: `790058355d7ab9eccb46ea12368f3be9cf6b895e1734eb20a13c749557b9fecf92b316870f0f765864b607439ee5f7e510e2c83b2756a0d9877b48e0cf257b13c997b9dc70421d2d87c9b9e5625c36a17e21e20ed389657a3e544c677464eefff08a9ee4adb091a9fbce7626cdc127b5cf817c2a5f069e32c720bc2041cd21a6bae816dbbbe28552d022b7b608fa99da4d217dae8a69f54004fa3c004d50540957648296e14cca729f791b38e3645204c2c6d4cb678b0db63a181b40cd9851be84629a068415d54cab5cb5244c8dac8dc9799a0df1b58cebfbcd8377a391778869dd275e0dc8305eb0351d81e3afa46719355eee4f90894f7fed662dd3b03270660adff637b91e18330a4f3a62c914f0d32b4eb6a30b79371ab55190578a1e7d43294bb0a721def7dae3e021981707930bd9b5cb58675851c83acf330c6ba3aecb3a890ad3c151a1e2b583a7dccbf204850daa9f4679e759ec056abef7ba4d6e0bdfa57a5c5afb6368b048a2b74e3530bfa8991c55de7cc8bbfa990d118ada80`,
		SaltVal: `3e07ade72a3f52530f53135a5d7d93217435ba001ea55a8f5d5d1304684874bc`,
		
		},
		{
		hashAlgo: 'sha-384',
		Msg: `9221f0fe9115843554d5685d9fe69dc49e95ceb5793986e428b8a10b894c01d6af8782fd7d952faf74c2b637ca3b19dabc19a7fe259b2b924eb363a908c5b368f8ab1b2333fc67c30b8ea56b2839dc5bdadefb14ada810bc3e92bac54e2ae1ca1594a4b9d8d19337be421f40e0674e0e9fedb43d3ae89e2ca05d90a68203f2c2`,
		S: `9687115be478e4b642cd369392b9dd0f3576e704af7218b1f94d7f8fe7f07073e3e8e1186fa768977d6b514e513459f2373df6ec52e3de9bd83fcc5cc3e6b97f8b3fb534163c64f5267620700e9d8c52b3df61a7c3748ef159d6b390895afa3af59109a5478d016d96c49f68dfc735ba2aafd5012c13515ed6644f0d4109c45556e14a3821e1aa24beb8a81a48da27f131de84f7ba51581d81b8ff31ba92b8a1fde867f07e32e6c2709253448174dd31324dbc32b05f07587f76a9997decb80f38d8c13d0f6eb3c10e3d96a2293f7464f1e04602ef6e84c2d0245d7db256a67d132a47cae9abe06b61a8968f50a1749995dc15ef0dcb1d5f5959e4d454c8547bbb4d195698f484617bfd122acaae2d0e8c76d28b24005ab03caa781ea97b1c4d9396a16f7998eee7ddd9de4cabe57032d9438a5d99c6b34a956122350263c7e998bc61dec91381012e686d079e39e96b1ea4bfdb7cdf630ddb422c6b580e5506c9cc3d6c100f2041d17ceaaaa54589249f04a1370ffa3bf3ff1adeb890688698`,
		SaltVal: `61a762f8968d5f367e2dbcacb4021653dc75437d9000e3169d943729703837a5cbf4de62bdedc95fd0d1004e84751452`,
		
		},
		{
		hashAlgo: 'sha-384',
		Msg: `752a9916f449aebf814ce59ca6e82fa8038e4685419241c1488c6659b2ff3f7b7f38f0900a79c77a3b57151aff613c16f5020ad96ba945db88268722ca584c09b4054a40c00901149bb392f0916cd4244699a5e6a8c37e9621f54b471166797a7b58502cff4083140827052646501f5b5f1bc0b4e129147d7cc157cf6e73ec58`,
		S: `6646a88ee4b845da4931274c23840dada6145fe0af954829d1d56661546a25e46316e216bb6b9446b368884ba14969a6f68ccbc1cf5b4e7a6d3aabec67f64963f63b088fa817c855d776ddcada57e5daa50fc1c877389c3cb9d99095a869a963bc91ec24b2422ef6b8dd18fd20d2b215fee6e98cda415ae44d2d2616fe1708292a3ef50a075170b3a7ebab02918ab0301794c17fb35e2038f369d94dd49569c066f7c392889dc4b878c50c7e52586b5081114d202338d23304f16f912d519a9ad21baff0e3d21761f373d08421e10108a983048fcb90eb2adc7c7f12ffa1571b091c781b255a77a880e97975f14f42baf5aa285ecc142157c3e1addd6aa0c09253a11c59144abd3b1e212d89e27ed96fb75756afc20ec67423b151194cb0b0648c659987a5583cb7757779d8a39e205e7101a5351ce1af2c9c6b0847cca57af52593323905e3d2297c0d54541a0125621640fe1deef13e759f8f6c56a2ec2a94831ac2c614b911e79edd542fef651f5a827f480575ae220c495f2a2842f99ec4`,
		SaltVal: `61a762f8968d5f367e2dbcacb4021653dc75437d9000e3169d943729703837a5cbf4de62bdedc95fd0d1004e84751452`,
		
		},
		{
		hashAlgo: 'sha-384',
		Msg: `0403ef219938b8cdbf85d3b88cbb9c60d174134e43a7284cd87936d37456cdc3c541b4566b682e575dfc7d8f883fa581b9df7257bc82bc1bc6a2ea2a109bb5e6c5022fac1e390306cb40fe2196cece8143a10af3ba1273c368ec7a30e27e021dcbef6609f9d2be41d3fa5e54fd90a0c83862e40b837ed4ac8600edcb31283bcf`,
		S: `0a217503fc4870481264d8308292c663476b25f8dec08ea1d1276f0951ec6df27aae3beb93d630bf8fac08b6cce50bd92994851b4f310fdddce8e0d6a8b7a1e866a567b298c5577dc50d8a906ab1be880084e681b26456279149b4b85201621c445de13d127fb77e7f236c39df34052b4629572abe1c02c09eb198188003dd852f88f4f767f1000458680258fa4b63dafc761822ca8b98c1a121b72b1455393bee416d24051290f02a28a7b49b18b30ccb29c26fbac991401a3a6fe01fcd0608920facae9d5bc56540c80f4740af02c9b7a078958a8d8a7a93a5e5b6d2571f49d775ef7c35a6d674290b52cfbcd67277e2b2e829ec437fb70e90537eaa6fe4548551939bfa98fc98e235b264aa6064a505a8d67946e2c33e5c6f0f34fa86ba65715c258f238b69e4f6e36d86a89822b4802d21ba0ba760b2f3a5bd061f50aaadff12e0d86627294bd0c4cd1085b5dab6a6ab30146c9bbb37de3ac5c4f8ee29736d46047e450cfdcb1279e4ca83ab69e858741bfd01a779d475dfc0f71c621d78`,
		SaltVal: `61a762f8968d5f367e2dbcacb4021653dc75437d9000e3169d943729703837a5cbf4de62bdedc95fd0d1004e84751452`,
		
		},
		{
		hashAlgo: 'sha-384',
		Msg: `453e0835fee7cde81f18c2b309b804c67b9fd9e96ef0a96e3da94b640978830e5cd1c8940c3d4af763f5334a7caf2d20f0b82541b3434fa138016b92dcf14638817a833d79b79bc7a71223a7e0144ed4977bb217ba8d4f07d7adcd38832c05b0fc61c39a0dfcca3f32971931fd8e6dc9b81107d44c77af8a62d5f9c0c7d0c75e`,
		S: `6ec22bd58c32d41374c017a77027e770f678fd81017e20cdaaab48a8324b050749e5d864082f1f77fecf67a59c2885e931c3c2f58130fa6806fe1ca899045114b09d09cf9c513ce1109d2210511a3b2e93af511badad2716f48555310e6c5f547afbdb0b9a684491ff3588df933d6b04dae8883f5f8aad62a4570646f72f3656c4a7085623f5152164a81a06ccb59ca478c5c2315414550b0ad8eecd0328b2db01fff7db0f26596c41f970d032925887f1c8a446da889be64d48925b9c6b79a3d897700ab40af20b451aaa6b427ed162864db89f7824b6ae9b475b5433b865335d6f91491c1e32f635cb930dec1aa3ee7ddaa08e8ebd67b6b11a46ba049922446fa69f1a804acc29f6cee487723f2e61a40007865d80cde0119f3fe6e161a339487f5789e1fd23ac0a63b4673969fd8722e3edc9439778928f09610cbefbb42fe6242c73b68d466cef889da156d9d4ff888362db4cf9a941e80f577c944b79fb27dbe0a6967e88f1f67b91b0d38e083fc0c0228cd49d27352521312163f90fba`,
		SaltVal: `61a762f8968d5f367e2dbcacb4021653dc75437d9000e3169d943729703837a5cbf4de62bdedc95fd0d1004e84751452`,
		
		},
		{
		hashAlgo: 'sha-384',
		Msg: `9aff46c14fd810a039c0a62eda403f5ca902ac41b8e225c6944748a36cb45f8a769ae2a18f713d362206d2af4a1742bf3b1de8e0de69a7fdbb72e66e1c6ed82a6f1f0138edf0f6677940643fcbfe5337cd76ac29456af902b5656dbe7f4c24944d36ab6db07dc39b081662c8a31dfb2c29b4ff04370ea43f4ac7e57adf77ca2e`,
		S: `62a505b3f3adda45c6badb61b464a28bc45d4c66159a34b63c1cce32604242eb8fcd9ac6929ec6ee4ac1144932d725cbf4638511464ec70dbb5543a4487a241396adb804c9794b271f9d35310ee560368d949a20a2b64cb4617fcf63cf7b60978cad734650dae86c7e51b766522ef0be48bceafe2030564d5b7b17ba125097bdafee48e4df60fbb7ac2d9f14af9a270c2b7ef18cadac45b9b54ef230794339d279d72ba48783bb09b1d1d5c1c65301276523fe90e63789ffbcd489e45f8aa9cf98f33de8f7d9c5cdd21a9ab2847896de6dce0b92f07b1ffb4230ee71ba1fe8048c22dd38af80f8762e747cdec6e99f1ce0d1c743ef98ddbaf7c764412446dca58e6ff5ac0dd13322649acbc96f1c5e0bc58d1a8211853a7d2f51538c5e5e803de0b13044608d6e650bace12945a7008194586e3b74809714b2a52e9f3824be41de9fec3f36175a289baf9fd68b7e92f3754e00b41782d055faa65433c25259aa653fda069386b083fb31aeec8e30c769553f8f0389b6e6d4b392cadd24ce3f74`,
		SaltVal: `61a762f8968d5f367e2dbcacb4021653dc75437d9000e3169d943729703837a5cbf4de62bdedc95fd0d1004e84751452`,
		
		},
		{
		hashAlgo: 'sha-384',
		Msg: `b50bf2767250f14fa7b6f5ea21a54da8d01e91151eb491107fd88b2d4a5aa157c72d89ba896b87e0fe989819442bf0213e4aa7fde8d6b026e7a70ae965193a0e1bc7f8b8af96298c41f60d154164ba678333c903958d4ffb50b50f57ad8eedb6da61a6398ddbbf9c9955bba6bf5991c4c6615df1cde156d8e188003dcbc3a399`,
		S: `1f068bd083a26534040f41c1387e71a8c00370c5f1c958127e0bc721751b5940513023fad02a6101bbcefaaaaeea2875952bf859d494bfb23fd89149d91290359ecb44ecf2fcaa5775e2e61e5f8d5151343576fe9c7167e919a5d081dac6bb8117229c420fd2b0fcb521f4e72366bfb443e688a65fa392eaa5115c292ab05bb4db65468aab267178653dfa0a5efc960636fcce86433528dbce955a0b1aa188ac33ea128206ecc0feeab8f7df6f8c381b10489c8cfb2d02459e4cffc16f43a66aa4eaa19bc518ccfcf9fc1e4861cfa13e9b41fcefade2cd2ebc001ec8430a1cb949a0f2f876badc568c703e4209e7ca16f688ba9705c14fa1c882e6c4871b9deff31521d2d418e0342e189c40ed19c1b6f4320d89a36f78eca143d3c16dd3eb338c0743646fd314c725c2d36a13080bfcdeea0e431de71d61f652033a75424fe1e1586695c3dc463ad553c1cf3ab24a41ff4e031f9e0c2cb0024cef68273ea3b8c1be9d923d3e9c9686c41977ac7be94a6d23181936131c17a39a898c943dcc8b`,
		SaltVal: `61a762f8968d5f367e2dbcacb4021653dc75437d9000e3169d943729703837a5cbf4de62bdedc95fd0d1004e84751452`,
		
		},
		{
		hashAlgo: 'sha-384',
		Msg: `5ff000f84a951dbfdd635a4d9f1891e94fc2a6b11c245f26195b76ebebc2edcac412a2f896ce239a80dec3878d79ee509d49b97ea3cabd1a11f426739119071bf610f1337293c3e809e6c33e45b9ee0d2c508d486fe10985e43e00ba36b39845dc32143047ada5b260c482f931a03a26e21f499ae831ea7079822d4a43594951`,
		S: `18cb47bbf80bad51006424830412d281c66ae45c0b756d03e5d8d49f73037968d13df46ebebd9b5b4c58b164d91d0608e8ebe31d8644cb0bebfaa8e2ccaa1f5746ac8f3bc02ff6930e219f53fe13fc070f910ba1cff0617aea6eb312c1ef285869746673ac1348e89c3646f583d7633f5a2341626bc2e7e2087ff9d8f13d573dc6455dc0068c7ac6eaf5b3093b081614f7b252170c4893891e469121fda655a2a55d67f5df0ff6e29ce5f9b0c3a1a88342140ead748edeea9706d6570e900f1cf3a9adcd7ae64f207585417946b104b3990d1a2d950e0e6a5533d3cfc8c470250e4c797273210f248b8922ab00422f2ecf85aef73587e8c5cd1c2ee6ed9509508409673fe07ee2c462c52d091e7a795d8d3c55fdd5a710d5450695a5a31ed76f115e71a73c6757d2def7ef472571b0bdc7558c71eaefeddec946860b0c77936db31f2001d0499a381e5018870b41ba04c8d42ec0dc55c9fa2af237dc1c405dd8f555b07a237cc50cbce46c3016118cf4ea06c047599283ad4719d647a225206e`,
		SaltVal: `61a762f8968d5f367e2dbcacb4021653dc75437d9000e3169d943729703837a5cbf4de62bdedc95fd0d1004e84751452`,
		
		},
		{
		hashAlgo: 'sha-384',
		Msg: `531dc2b8566e01a8bfc580da607ec212fc1fbebd5a2590d897046f0ec069df20a1c2278ad70006642d9ba28625d7c1efd4473b68f38fb064346d762bd2fbd5376c2e77de13a31a32a29b88264d44c9f27d3a97b8dc4d1267ab85b5e05c6389575d6a98fc32dea5dbc6cc1a01034a42e1a000b8f63ae720a9a7511474872a6148`,
		S: `80baa663877615c2e7ca9dd89958a74e54012efad55ad05868dd74b0ce78a661e2b893c3ac1fd837f282327efe4b041220942649b5472c1ac702070787ae5549398a57653d5fca69cd5446d63f6e9d0684925a235acc96b8a10bdf14fbe209fcd4930b5945910d84b08867b2055fe8eb1d771b753759593b90d6aec5ef182cb33bf2fe29e8c67ea4e8433ecfa3f9ba4ce461f0ab19997f299e95409af97bf57e2de410ef7538f699f385c1abafdf9337f7f9d268da87b2b389131fe3dbefd8c67bd2a158cc4e04f9ab7fee2a58d74d063e6c16958a90574e3e4cb881d32c3116987e46bf5bd44f80abe6b9eb717a9fcd4c0cfe80dd2ca62c33b5dd3a59c64810073e0476085ec7b76638983291b69559c815cd3bb87d4b07e24c6b9ebb7028e800a04f09b110c167f6ee3a3bbb73695d89bee92407d4adcea3eaa47811e23f8c7f2fdfe891f8cfc071cb984a63846b95ec04d6261bb1c5980018feee15c4e7bf632dc8306128fa22c47decfd9e8b099554f17253635e6316712e0b95efa3fb00`,
		SaltVal: `61a762f8968d5f367e2dbcacb4021653dc75437d9000e3169d943729703837a5cbf4de62bdedc95fd0d1004e84751452`,
		
		},
		{
		hashAlgo: 'sha-384',
		Msg: `a454391a7c3695486c337a41c2add417d8e9e9c6466d2ebb56ad5f97b9e7ce30784cfcd82d6066e372a3a1639a71a9369f2777435c87d100fc5e6638b3631a0bac639f36429b4594726613e5901816cf3a29f9228b96d66090844c7d0026d2e327e24ab924afda6554c2f74f0e69c2e8913798ec3a61e4e4fb6838ee08f89dc0`,
		S: `261180717edd905b647bc869f5259203811606221f545a3aee5fc123f297cf7d8a7ee6cee3dc8f97d24284ccdec2fd4680f1428ee75797e0379512aecb9fc1667523413e323c4bd7dded5caf9e5c606e5ee0c694d4d1b5a1f1cb613b980129f64146e42e8261c1f7ef5603954d34d56a50f7431beee5ab291a4759168655a5123640d596b744d97979d39f874ea7ff13a7466a7655d02edb492b58049f2208852297eb023e657f3240c5da9a99fd377728bff3cc073109c31712d94bc24e08c433533d4b86a73b58fbf2c598ccad78d46ca0a055601850960195aac1364dfaddbd06f14a78aac2ab4d374505cc61fc72c1050647d95a733517b709aed2d896721e7484208501480058fa4f6044302dd705c273fa7fb42eaeb02d025092b252e16d270d88dab6f68fd7ad571011f89627683e029d1bf1edc149d47452ebe87ec68679579940f5aec25999b0dedb820a5483ec6901abfee041c03b1a7f743548a2caabca613ff5d9f8fd7c694af12b29f2c2468eff55f9e008757443960fae459e`,
		SaltVal: `61a762f8968d5f367e2dbcacb4021653dc75437d9000e3169d943729703837a5cbf4de62bdedc95fd0d1004e84751452`,
		
		},
		{
		hashAlgo: 'sha-384',
		Msg: `a05e5782a96ee6d6f10be8830d8c27c0acf272abbf77e684dd6a6c19e5398381e5d0400d3a21927cf904cb6e8e425c1ca3ece04544f25d6c40f0c640d24bc45c807db53044adf63fea835d8cb93a0a4e55f760ebe4594e247051d38d8c34c1413b0ec1d30d3a97888b2fa7c3d59db8c08ab9f985e8d4411635339be95d1b0299`,
		S: `87d80275df7b196b7e1d0a41147719d773edd80b5627301a500d91665ba86076e6a31c8f3ae86aedb643fe2af223976ea4eb3d4dca2cbcf81ffd14b7ef7de3ee355a8d0f4143e5b0f0a0950a42811102e602cd214e1c945c47e8b7b66d507103c3456f404f9c48aa7fe48dee0aad05e599f242adcf8ccb0cc9db3a6c244a913551ab595600ecfbb67c25a95b54f4054397abe47650e5c4991edaf1441ba9c8e3fbed904ffbc977142ebdc84769865a215158d5b052e75de318d75012172e28c31db2d8bd4edca787216dde2a7387c543f162fc91924918fd6c845bf1ebc0220a1027fb4227340ca4cb0f183e5b34b1e7f93e14fa57bb9d2d2ea53f86d838bcbe3f055b473b0b469afd2960c0d76ce2c30f3d49a3b29065bb9260248e728cbe328bdf502b109e1f20b9d037860cf9e261611b4cbf27ff9b5bf425b2612afc7cfa3138f78ad26077cbfb947fb2aae6f4be85ab2d1a15860839b822dd03a1a92a19a5c7244e98bdf561625ca2a8df410ff855752ebdf3d49f5eb98f228acdd52791`,
		SaltVal: `61a762f8968d5f367e2dbcacb4021653dc75437d9000e3169d943729703837a5cbf4de62bdedc95fd0d1004e84751452`,
		
		},
		{
		hashAlgo: 'sha-512',
		Msg: `44240ce519f00239bd66ba03c84d3160b1ce39e3932866e531a62b1c37cf4170c3dc4809236fb1ade181db49fc9c7ccd794b433d1ad0bc056e14738e0ae45c0e155972a40a989fa4b9bcdc308f11990818835fa2c256b47ee4173fb4fed22ccf4385d2dd54d593c74f0004df08134eb8965dd53a122317f59b95d6b69d017958`,
		S: `8f47abc2326e22cf62404508b442e81ad45afff7274096b9a13e478cdd0a72f99a76bf517f1bb0f872a523d8c588d4402569e948fd6a108ae1a45c65830828a10e94d432765314ba82ead310fc87ac99a5b39f30ab8820bf69e6934a9c1c915c19f36ea7717eaff7af67b4991315b1873ba929bedf18a975be808e7aa14a6726126c79cc93f69541c5cefdeb5b67ec279d8f5a446583e4b4faed1685140ee4b3b757c8ff4a1ef9cd76a88e05319ee62003d2d77290c94c579b0ca2ab0deb3176ef10a3fdb85c80ffbc9e2a665a23744fc836f9a9a103cd9fb756952356a2f1acdd68a645e20179006558b5d4d0b9b0bd3adf5e290f49dae60b9d19920953ea8bb237d5b3dcfe149a60f12a4ee3a889b33bcd3a3b753d610757cbcd093dd5a734255333689695ab636963e3d215a8e77ff31973718a4944a1e9e44f45754d39f6fa431c53f9a2ef36e16a5f70636eb5fba54e15c20a714f2809a7cff4b8dc1165f836607eb5a5a3bb0c4567eee26941fef46fb41e73b565c0cf8c72e404221264`,
		SaltVal: `2d0c49b20789f39502eefd092a2b6a9b2757c1456147569a685fca4492a8d5b0e6234308385d3d629644ca37e3399616c266f199b6521a9987b2be9ee783`,
		
		},
		{
		hashAlgo: 'sha-512',
		Msg: `06d5534b7769256e8cf65c6ce52a3e86965a1fd12c7582d2eb36824a5a9d7053029fbeac721d1b528613e050e912abd7d9f049912abeda338efa2f5213067777edd91b7576f5e6fa7398696599379ed75028cb8db69fa96de7dbc6de7ca128dd51ea334e8cd9cd8fdaefbf53fc825eae836b6c6cd70039a77e420d999b57caae`,
		S: `913fc118d5ac1edffb4b8fcfa4e85986b46231cef3dad911d5e9534cc88261f6b6969b75a3f25d83ece7ec2034b01d3b2be6c5bd958cc4afcd44839e3953f01e4a15ea5ef6e1b4b0e8ae90bdfd404199e8f86547f67ff6b84f2162c4311cc9eee06bfb2fe46198afb9745d9c443833bf2387eb92406a6339521396f2cbda55d98fe64074d2f2e27b8bc6a79be3d1cc568869b0b50fcbf702b0831668fbfdedc2d1b5491e8ec623edeb60ac870e6e8d058593fbbc938fbf741700efc2b2467e7eb254ae008509e91607f8e50aa16a4e851abca7c8d20c6ff61cfee6c1fb676098e5cdf127c9b79538fd1e6c014161054caf43b734fa69fe06a00d76f710acc198f3da906a7d2e73a2ca882526cc354dd7630a303d8f32c655b5b33cf78859beeaba3f9ae052c8d7471cd2bd9edf42fd8f70c3b0aa79c076928068ca9770959afa632ca6aaba6679e45d6888c50125a73b9deb00d42a125f25df5434beff0d5b0ee13a16b17045cece0f2da7577d79d7cd75a4b6c5bc345f460a173487b51bc6a6`,
		SaltVal: `2d0c49b20789f39502eefd092a2b6a9b2757c1456147569a685fca4492a8d5b0e6234308385d3d629644ca37e3399616c266f199b6521a9987b2be9ee783`,
		
		},
		{
		hashAlgo: 'sha-512',
		Msg: `756c51bae61d75e8cf44930e1781dd6b8db6bf8b1f68b4ca4c685d14dcb2d4eece953eba92149f36788df34769987af5d53253b6ec1b4cef117cf9b88bcd03e07ef6c3301ab40ff4133f54b8512ae550e88a931b4a5a7e88bc1e2bd806c7d6266fd709a5e8c56d2a88a3e1ea38fec984b006a842a2eef29b34961bfdb468f4ca`,
		S: `735186ebf08d505161a8bab36786138414bb5ca2f4025289af237a40f8d0963df9117b619f83d9a98dfcf74b8f001a4a742c85ae018c3b51f16eb5015ba7027cb9a0d0b9e6b65c08ba58b671a9b3dd62107bbd5ae932784d328cdb2e1a551eb67e9d33ff1cf9bffdb223afd75d3650459fdb58143cd4490981efb0b3fe36f642e1837a5d95c3d444af73729dd1a5e9937b8114a28e065d1081f061049e650e45ff5ccf75c246e2e9433b27e79a1b06f7b6b57f9b009e97168a61297cfd0a8156d026a6bf8c3764d0b715c619d856b061df35725498d86cec25f7e1da65b99d9ecbb9a1a6364252e4790d97ea0ffd6234b515929b5ef22676c243d386ebb90a22e67a0e1d1094dddf7721099868c31326814887b646ca52a2c4bcd43f7c71399e7d13e19de688ae5c20463df5965d8255a3e6928d614b601274b757cfacdd4002d9ba8b248ae700d8776475d79d0a55ed4241c9919a3c44dfb9a1f5d0fec7ca341774c596144c38174af59af6deb8937a7d14c459b5d768a977445dafee1a4eeb`,
		SaltVal: `2d0c49b20789f39502eefd092a2b6a9b2757c1456147569a685fca4492a8d5b0e6234308385d3d629644ca37e3399616c266f199b6521a9987b2be9ee783`,
		
		},
		{
		hashAlgo: 'sha-512',
		Msg: `a9579cce619ebade345e105a9214b938a21f2b7191c4211b2b75d9d2a853805dc8f1eb8f225b876ab857938bd0ea8cc2ff1ee90087030976e3f46afb9f1b1bae6d3874dd769d0426ee7dcbdceb67a9ad770e1781e34b15a45f656328c88ff485c1b2a083056d195afc5b20178c94f94131761cbd50a52defc8502e22cbb6f42a`,
		S: `603ff63ff638f1ad410e266d82a04c6d475416a0470d97f483c0c99e8fc7212d61e02cc8b4493c9a9dac711d2a8edf196a26563866d68fb04849e82db0f9741f721f2ba4e9db62f6ecfe3b87ebe7feed0c9e2dd46c3f9252d4c122c6bf1bf4ce215ba82fe7c5a91249da70dd30fc9c8ac8b3bb2810b4ff38bfacc13fd41f6fa26507a055e0f1242f18ea8ed8a702d265f893cb4eb61a3dc8e18777157552a1c58db14349a0d0a2a900a0a1f4de863fbadb063ad2a9e526a0a8c3bdcfca5524c181637b1c4a574809fb45b2e4f06f3f89f4ccfb30217b32fc484bb908276d659a0d9a3e7e3fbd46565a0924f918b16b2d6527ec4b5d1d6ef6d6720f3e00485e87de61ed49ed13e85ca6a10d46d4ca4839f486621cca48a7f955a878c4785d55de96facbb91b6ea12e9e4fe4beed00141b0372a3812465e65030f4fb8ddd58701aa3da27d26feb8644f7c80b8ee2a3c3b20a516c7f0b068b503fbb65d3f3b84b253466a887314aa8eb9d85cd035bf8dbb178ebd8d5496fd1b68432457c78c69cad`,
		SaltVal: `2d0c49b20789f39502eefd092a2b6a9b2757c1456147569a685fca4492a8d5b0e6234308385d3d629644ca37e3399616c266f199b6521a9987b2be9ee783`,
		
		},
		{
		hashAlgo: 'sha-512',
		Msg: `c3287c23b613aefc2425a8b8317d647a447816bac56d0c99259bd9711f5fb2b13eab18e8a0b3b81ff9e98f6cda2c51c4343c0c1118720884c0aef32dd3903ac9e5ebbadb3d7698fedcc56d79bb78a71453b32c2a62ce4000ed4da85581120f3abfd1aa2418c51840d4a18c0659ca2d11aac3bd2e2ee879b3b3604112b24df9ad`,
		S: `878b9a443921bc7d720e3e288e8f39e550113e01d04fb1635a26f796fb8b161d5b758cff914a2441d8350f8d3922aa5615edfd86501c9a05c210c93a1ae04ff761151dc8d652fb5509ed100999d2bf6e40b1bbb64cf6c5d8e067b445daf567137cb8f0863996de8de9a647f982c9e21a787ee8d72657a2dd42ec9fec49ea1c3345cf004e94594a064b6b6b222845d64c935b539d3fd2d535fe0e47ac6746028e748556c2d88e4d40707e74a1c0cad5cd95dad263efd3ca637ac6b8f78ddf7ba81e443b836d85a83dbe843bd6271e45d842e1bb241c9c18805f37bc19838ba2bc6cd38401dce0cc9780306ea8a87d43110b3e395bbfb81c3ba45ce1cd71596ed27c03e2090a7ee81f60119e187adff0d96acfbaac38f7cb503039ead9cf9550ded5693d3c257406dd0bc061d451bd81d64f969b7c2b84619f0dd82481781eaf5b8fc82a3ac5b9fc20b42f86d4225a435b903d2258f5cf693d1b5c6a5d144f7f4eab9e70de2f3879f68e4c1c7a38dda63e6186534fcd78d58db709bf57a78a848c`,
		SaltVal: `2d0c49b20789f39502eefd092a2b6a9b2757c1456147569a685fca4492a8d5b0e6234308385d3d629644ca37e3399616c266f199b6521a9987b2be9ee783`,
		
		},
		{
		hashAlgo: 'sha-512',
		Msg: `d54c51f90b278c1c602bb54a23419a62c2e8527229352ed74a17eda6fde02f4b0b012d708515a6215b221d2d291b41cf54a9ad8d562ad16156fb3017fcf2cdf6832fdfa21015cc41429355dd0aa80e09bd2612c867b6f4aa631cf93828bc8492665dd157522ee6c53d06c7226cf0ea5a24e7eae904de7ffb9804aed22a453d69`,
		S: `265749f7afb1e1d16492eebcee9f5004234e1dcb95b832d14165992f4d1c49d518ba15a6b3adedfd803287cf60ce8c915882e2c78d69ffc46fdecef008e5d7f146e38f268efe49065ddb6fd7969a842189b9d7b3ccb32d62aa05e87e932930f7a1775c338736d9bc8f36521609d8be0c29fdd1728430a537f0a2b9b9fef2cd9f0946c221c08aaa0270e3187ee5c518cfeb00169e7718b01ac0faef097e9cb6a4df3e87a5548a6c3d9f1ba230ee1caa01297e5f17d1be1d776552f36638cff13ab73a1058fe7c1eee28c76a145e9ff9b17074963c22c6435b6c5a619a6f39df94ce348b244320b207a9117e98b9aa5a8c58516d39c71878c4ecfd741ce6e51222fcd92ad32d70c3b92cbbe301dacddf2ec3aec21fdd38a7e110f4f5448577b9546f1a7cd71a35670c1ca47a9199437cbbc65926cd17dddd2c0c3b1ffebe682be616e638839744a147ea897885afefbe6f0e37d4e482dd005f4ff199d0d033bb753380780c90228a87d14d8dbfb829a195b5d8b2dbd67c9eedac48ae639c158eb3`,
		SaltVal: `2d0c49b20789f39502eefd092a2b6a9b2757c1456147569a685fca4492a8d5b0e6234308385d3d629644ca37e3399616c266f199b6521a9987b2be9ee783`,
		
		},
		{
		hashAlgo: 'sha-512',
		Msg: `57724b7062193d22f2b6bfd18461d87af122c27bf06093a5dd9c1d92b95f123971706cbf634b0b911ecfa0af6937cb4b884b8092bad7afca065d249d3707acb426df79883742c7752692c011042c9dbb7c9a0f775b09ddf950fdceffef43c9e4fc283b72e7e8b9f99369e79d5b2998f4577536d1dbdd655a41e4e361e9fcb2f1`,
		S: `84a21a5cc060d141ba9caeca77fd04be8ba8270235e9948d0706dca77413ce7f0811da8b2f5372f8ff5a2eb2bbeae43752c5d1c1e3877992a49574899a6ec9d2a9483156540322fdaa66eec4a2601c281ea5ae996190853644b48231bc22729f32c2188e5f5f7b5056fd3e99ccca3effcb9793343f52a9ee60217d1c492102534a334c1c60a9c4ed63ae861bec7de9898c2dde026d9a029e7d9fe44d552cd3763b8ec3f4371f4e682315657d72a888913d15e1a84a981b3d8d437589a6deb37d14e86aaa365124bf165045040b1f959accff35565205d0ee72bc56d273d1973410774cea7735ca79c6bcb256b54fef0172e058ba91619c66bc45e11b6bcc0f68b529ec3a4133598bcf09c9c4bb0f874c7095f3ebbf85a5f669bb3717eef929fb1c22943268c310282e8842840aecfdc942a468045b02595bb16336634da20ca0b8d758cd30a2b7a0bd0e3e2a6f30f36a1422adfed88e211485066d6c0fa5c986f1dc5b4c1d965021dcc24b3f729f07c02b47af75d01f49da3dea0f1bdd6b4c0f`,
		SaltVal: `2d0c49b20789f39502eefd092a2b6a9b2757c1456147569a685fca4492a8d5b0e6234308385d3d629644ca37e3399616c266f199b6521a9987b2be9ee783`,
		
		},
		{
		hashAlgo: 'sha-512',
		Msg: `bf5ff776122898e22333fb6da96d2a87a3e6c4e63f28fe7afbc8e8a40a3af2a3f9e9ae4f9287d70901a293f23579f55b890dc67da47b856a9d88ac44637e35ad5d375d7e4d77a8bc7a7f25c80edef3d5bd8b049fa731215b80ca2ee9ee6fb051326e8c6d0b9e11e3d7ef3957fc452cde868706b512f2da33eab4f7fc71b66a78`,
		S: `86ece9321faf1387de6afa7b1e16c2127e71e6472e093708f0ac4b40e6efb30eedc546907182798535ad6b88ae4a6f8c4fae429d225058294ef76d44ca81defdadd12cea16c58c660a4d158cb6728545307f5a6234c3aa16ae6d989b0b788cc4c18b08c89b57fe302ca6560affc57bd533bdec6ae90fc37167c4355b07c6c7c7aa2bdaf96002832d62c2dd090c61cb8658ecc0e224964b50b9abf1b4271869a8951d81cd5b46af4ead70b0454c01a7229ef2ff27599c7370e747988b45b9a8148575d73014166082947c97e8730d5458ff4a4606b1185f1bfd476e8fea2d1d7fb5d14a061f90e438ce5e36b489b5873b7400ed779ec82adfdc2d9314d6e6547dec3be9853359821e6f6d853c2292f1731789002033ecb46cfc3a7f197a18a677574fcf6870d7e47db874cff258f0f6589386fd9667af292c315ffd849bf71749ef1b4fc5a3fdf39e2782f986bc8f523162c0016c51702513ed17c8f68672cf425fd6ef8b6c8e983bd2128ce4614085e7fb216af7ff01501941f23ffbce556f14`,
		SaltVal: `2d0c49b20789f39502eefd092a2b6a9b2757c1456147569a685fca4492a8d5b0e6234308385d3d629644ca37e3399616c266f199b6521a9987b2be9ee783`,
		
		},
		{
		hashAlgo: 'sha-512',
		Msg: `61b6dd24903672621810cbe3342497a6b298b524f7cd50e342914f483596ecad9122a2b341094dd99ad98d4ee1546b040d233f06cfc8d10bd0d5be4b3a5b1d9179a663924327847dd5b25bd380ea4c7965f9280c7d845074dcdd1ebc367b8020a2a8e6689e7a5f755304fe1a1bcd832d418237dd08e71845ee13364231dd5d82`,
		S: `57d827593ad09f00005ff1ba4521a9ab2717fe34d7af12d7ef5dc07814cb93257a2903cedf0a80704b16fd8aa9dbd06fe3d96fcc7be3843ea161e80ca56f3ef6f760dfc7f1704ed4a50142267b87d244c71fc72102112fe4ea801c82c631edd9d917808c0a1f1c81a9de859dd87569898cba76b35702232aa492850739ec0371b0342318b92eefc45e6ae8547a604d9a15c2829ea85533d6d23fb61ef569be63779d3d2c7cd3bfbc26df02616b7bdbbc0b4e2b5ebba7ec93886a369d10b7bfc0e7f56e7b7ccc814880baa634f4afd874a841d40cdf9c8f117535650b55129b8913d53417bdaf163d68e7044ac011a55ac0e1afd9279d46d31ef83a0bb4a7dbe70bde4b33396750b676576497e202e40cd1401fd6cb08878a6c22db61404b4c2aa88072f7a4851d9faaf016a60a7a49147fc234ad67f8375a90069c274aaddaea43df6292ccdf7daab5f5113070f8ca5e7f43c791acc7e1737cbc311bd5714abb66561703b9ac3629bb10bd1b7709f081840eb3e939c69657ea8f7cfd596b0265`,
		SaltVal: `2d0c49b20789f39502eefd092a2b6a9b2757c1456147569a685fca4492a8d5b0e6234308385d3d629644ca37e3399616c266f199b6521a9987b2be9ee783`,
		
		},
		{
		hashAlgo: 'sha-512',
		Msg: `dcc271b1bb2e50ebc23330be36539d50338baf2e9d7a969358c677e8bcbc7787433615c485c2bc2e670098128f4caa411b9d171392adc6ac1a5b297eec4d5b0f06d96cfd1f26f93fe08effad5147f0c3924307a2cb54d95765942e607b040e6c8b731f6372a22ea697a50b98668c9a5d004327e230b7fa1da23a2b964f29b826`,
		S: `0ac938ab04bf4efa587e34143436ce608ad089420956a72b23103fea769c03f02c3a0db764cd5bf3cc8518565b7efff70c74cc653665dc06e7f1d584e967ba193a70f5e3f7416ed0d4d5dc0e761b24ac8a8be172eb95691f02244379c9aeda8a9f760e061fd476b063b5ededa56bed819fb7136a4604879a92b2cd35507fd49b7d478fbd24c764aa5bc535a6abd7bff5c7692035620597f6329a454ce9188731c4e74d56c5bdef11372540b958cf2f8c42cbdbf915e0c07c77f04b05d876afbc3f2c205a4048826319184d650a243d192fbe35a163ab8ea84a001dd7c1472988a78042cf9fffd96f6948f0e692fc3f3b1c9c13de4b7a021be25c80606e1105cd56815d27c45fef995b1fea36e2e12aafc4a69924785c4855c50c61b1f43be9a1adfd8d7ff2ef5240dcfe5ea4613db4ad085bb0a6fb8627b1ed94dd164a4d9c4c9f375983734f9d2c35ec69d6d7421157d8658dcec1bf6599ea94280a63422376bfabf1b9f730292c498c953654401743c9e6bc499446759484d93e28d5f9f486`,
		SaltVal: `2d0c49b20789f39502eefd092a2b6a9b2757c1456147569a685fca4492a8d5b0e6234308385d3d629644ca37e3399616c266f199b6521a9987b2be9ee783`,
		
		}
		]
		}
	];

	for (var i = 0; i < testVectors.length; i++) {
		var vector = testVectors[i];

		var n = new BigInteger(vector.n, 16);
		var e = parseInt(vector.e, 16);
		var d = new BigInteger(vector.d, 16);

		var rsa = new jCastle.pki.rsa();
		rsa.setPrivateKey({
			n, e, d
		});

		//console.log((i+1), 'rsa testing ...');

		for (var j = 0; j < vector.sigVectors.length; j++) {
			var sigVector = vector.sigVectors[j];

			var hashAlgo = sigVector.hashAlgo;
			var msg = Buffer.from(sigVector.Msg, 'hex');
			var v_sig = Buffer.from(sigVector.S, 'hex');
			var salt = Buffer.from(sigVector.SaltVal, 'hex');

			var sig = rsa.pssSign(msg, {
				hashAlgo,
				salt,
				saltLength: salt.length
			});

			assert.ok(v_sig.equals(sig), 'pssSign test ' + (j+1));

			var v = rsa.pssVerify(msg, sig, {
				hashAlgo,
				salt,
				saltLength: salt.length
			});

			assert.ok(v, 'pssVerify test ' + (j+1));
		}

	}
});