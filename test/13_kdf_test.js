const QUnit = require('qunit');
const jCastle = require('../lib/index');

/*
http://int-payment.com/mvp/mvpenv/lib/python3.5/site-packages/passlib/tests/test_crypto_digest.py

#=============================================================================
# test PBKDF1 support
#=============================================================================
class Pbkdf1_Test(TestCase):
    """test kdf helpers"""
    descriptionPrefix = "passlib.crypto.digest.pbkdf1"

    pbkdf1_tests = [
        # (password, salt, rounds, keylen, hash, result)

        #
        # from http://www.di-mgt.com.au/cryptoKDFs.html
        #
        (b'password', hb('78578E5A5D63CB06'), 1000, 16, 'sha1', hb('dc19847e05c64d2faf10ebfb4a3d2a20')),

        #
        # custom
        #
        (b'password', b'salt', 1000, 0, 'md5',    b''),
        (b'password', b'salt', 1000, 1, 'md5',    hb('84')),
        (b'password', b'salt', 1000, 8, 'md5',    hb('8475c6a8531a5d27')),
        (b'password', b'salt', 1000, 16, 'md5', hb('8475c6a8531a5d27e386cd496457812c')),
        (b'password', b'salt', 1000, None, 'md5', hb('8475c6a8531a5d27e386cd496457812c')),
        (b'password', b'salt', 1000, None, 'sha1', hb('4a8fd48e426ed081b535be5769892fa396293efb')),
    ]
    if not JYTHON: # FIXME: find out why not jython, or reenable this.
        pbkdf1_tests.append(
            (b'password', b'salt', 1000, None, 'md4', hb('f7f2e91100a8f96190f2dd177cb26453'))
        )

    def test_known(self):
        """test reference vectors"""
        from passlib.crypto.digest import pbkdf1
        for secret, salt, rounds, keylen, digest, correct in self.pbkdf1_tests:
            result = pbkdf1(digest, secret, salt, rounds, keylen)
            self.assertEqual(result, correct)

    def test_border(self):
        """test border cases"""
        from passlib.crypto.digest import pbkdf1
        def helper(secret=b'secret', salt=b'salt', rounds=1, keylen=1, hash='md5'):
            return pbkdf1(hash, secret, salt, rounds, keylen)
        helper()

        # salt/secret wrong type
        self.assertRaises(TypeError, helper, secret=1)
        self.assertRaises(TypeError, helper, salt=1)

        # non-existent hashes
        self.assertRaises(ValueError, helper, hash='missing')

        # rounds < 1 and wrong type
        self.assertRaises(ValueError, helper, rounds=0)
        self.assertRaises(TypeError, helper, rounds='1')

        # keylen < 0, keylen > block_size, and wrong type
        self.assertRaises(ValueError, helper, keylen=-1)
        self.assertRaises(ValueError, helper, keylen=17, hash='md5')
        self.assertRaises(TypeError, helper, keylen='1')
*/
QUnit.module('KDF');
QUnit.test("PBKDF#1 Vector Test", function(assert) {

	var vectors = [
        ['password', 'salt', 1000, 1, 'md5',    '84'],
        ['password', 'salt', 1000, 8, 'md5',    '8475c6a8531a5d27'],
        ['password', 'salt', 1000, 16, 'md5', '8475c6a8531a5d27e386cd496457812c'],
        ['password', 'salt', 1000, 0, 'md5', '8475c6a8531a5d27e386cd496457812c'],
        ['password', 'salt', 1000, 0, 'sha1', '4a8fd48e426ed081b535be5769892fa396293efb'],
		['password', 'salt', 1000, 0, 'md4', 'f7f2e91100a8f96190f2dd177cb26453']
	];

	for (var i = 0; i < vectors.length; i++) {
		var vector = vectors[i];

		var pass = vector[0];
		var salt = vector[1];
		var iter = vector[2];
		var len = vector[3];
		var hash_algo = vector[4];
		var expected = vector[5];

		if (len == 0) len = jCastle.digest.getDigestLength(hash_algo);

		// pbkdf1: function(password, salt, iterations, len, hash_algo, format)
		var result = jCastle.kdf.pbkdf1(pass, salt, iter, len, hash_algo);

		assert.equal(result.toString('hex'), expected, 'PBKDF1 with '+hash_algo+' Test');
	}


});



/*
https://www.ietf.org/rfc/rfc6070.txt

2.  PBKDF2 HMAC-SHA1 Test Vectors

   The input strings below are encoded using ASCII [ANSI.X3-4.1986].
   The sequence "\0" (without quotation marks) means a literal ASCII NUL
   value (1 octet).  "DK" refers to the Derived Key.

     Input:
       P = "password" (8 octets)
       S = "salt" (4 octets)
       c = 1
       dkLen = 20

     Output:
       DK = 0c 60 c8 0f 96 1f 0e 71
            f3 a9 b5 24 af 60 12 06
            2f e0 37 a6             (20 octets)


	 Input:
       P = "password" (8 octets)
       S = "salt" (4 octets)
       c = 2
       dkLen = 20

     Output:
       DK = ea 6c 01 4d c7 2d 6f 8c
            cd 1e d9 2a ce 1d 41 f0
            d8 de 89 57             (20 octets)


     Input:
       P = "password" (8 octets)
       S = "salt" (4 octets)
       c = 4096
       dkLen = 20

     Output:
       DK = 4b 00 79 01 b7 65 48 9a
            be ad 49 d9 26 f7 21 d0
            65 a4 29 c1             (20 octets)


     Input:
       P = "password" (8 octets)
       S = "salt" (4 octets)
       c = 16777216
       dkLen = 20

     Output:
       DK = ee fe 3d 61 cd 4d a4 e4
            e9 94 5b 3d 6b a2 15 8c
            26 34 e9 84             (20 octets)


     Input:
       P = "passwordPASSWORDpassword" (24 octets)
       S = "saltSALTsaltSALTsaltSALTsaltSALTsalt" (36 octets)
       c = 4096
       dkLen = 25

     Output:
       DK = 3d 2e ec 4f e4 1c 84 9b
            80 c8 d8 36 62 c0 e4 4a
            8b 29 1a 96 4c f2 f0 70
            38                      (25 octets)


     Input:
       P = "pass\0word" (9 octets)
       S = "sa\0lt" (5 octets)
       c = 4096
       dkLen = 16

     Output:
       DK = 56 fa 6a a7 55 48 09 9d
            cc 37 d7 f0 34 25 e0 c3 (16 octets)
*/
/*
#=============================================================================
# test PBKDF2-HMAC support
#=============================================================================

# import the test subject
from passlib.crypto.digest import pbkdf2_hmac, PBKDF2_BACKENDS

# NOTE: relying on tox to verify this works under all the various backends.
class Pbkdf2Test(TestCase):
    """test pbkdf2() support"""
    descriptionPrefix = "passlib.crypto.digest.pbkdf2_hmac() <backends: %s>" % ", ".join(PBKDF2_BACKENDS)

    pbkdf2_test_vectors = [
        # (result, secret, salt, rounds, keylen, digest="sha1")

        #
        # from rfc 3962
        #

            # test case 1 / 128 bit
            (
                hb("cdedb5281bb2f801565a1122b2563515"),
                b"password", b"ATHENA.MIT.EDUraeburn", 1, 16
            ),

            # test case 2 / 128 bit
            (
                hb("01dbee7f4a9e243e988b62c73cda935d"),
                b"password", b"ATHENA.MIT.EDUraeburn", 2, 16
            ),

            # test case 2 / 256 bit
            (
                hb("01dbee7f4a9e243e988b62c73cda935da05378b93244ec8f48a99e61ad799d86"),
                b"password", b"ATHENA.MIT.EDUraeburn", 2, 32
            ),

            # test case 3 / 256 bit
            (
                hb("5c08eb61fdf71e4e4ec3cf6ba1f5512ba7e52ddbc5e5142f708a31e2e62b1e13"),
                b"password", b"ATHENA.MIT.EDUraeburn", 1200, 32
            ),

            # test case 4 / 256 bit
            (
                hb("d1daa78615f287e6a1c8b120d7062a493f98d203e6be49a6adf4fa574b6e64ee"),
                b"password", b'\x12\x34\x56\x78\x78\x56\x34\x12', 5, 32
            ),

            # test case 5 / 256 bit
            (
                hb("139c30c0966bc32ba55fdbf212530ac9c5ec59f1a452f5cc9ad940fea0598ed1"),
                b"X"*64, b"pass phrase equals block size", 1200, 32
            ),

            # test case 6 / 256 bit
            (
                hb("9ccad6d468770cd51b10e6a68721be611a8b4d282601db3b36be9246915ec82a"),
                b"X"*65, b"pass phrase exceeds block size", 1200, 32
            ),

        #
        # from rfc 6070
        #
            (
                hb("0c60c80f961f0e71f3a9b524af6012062fe037a6"),
                b"password", b"salt", 1, 20,
            ),

            (
                hb("ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"),
                b"password", b"salt", 2, 20,
            ),

            (
                hb("4b007901b765489abead49d926f721d065a429c1"),
                b"password", b"salt", 4096, 20,
            ),

            # just runs too long - could enable if ALL option is set
            ##(
            ##
            ##    hb("eefe3d61cd4da4e4e9945b3d6ba2158c2634e984"),
            ##    "password", "salt", 16777216, 20,
            ##),

            (
                hb("3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"),
                b"passwordPASSWORDpassword",
                b"saltSALTsaltSALTsaltSALTsaltSALTsalt",
                4096, 25,
            ),

            (
                hb("56fa6aa75548099dcc37d7f03425e0c3"),
                b"pass\00word", b"sa\00lt", 4096, 16,
            ),

        #
        # from example in http://grub.enbug.org/Authentication
        #
            (
               hb("887CFF169EA8335235D8004242AA7D6187A41E3187DF0CE14E256D85ED"
                  "97A97357AAA8FF0A3871AB9EEFF458392F462F495487387F685B7472FC"
                  "6C29E293F0A0"),
               b"hello",
               hb("9290F727ED06C38BA4549EF7DE25CF5642659211B7FC076F2D28FEFD71"
                  "784BB8D8F6FB244A8CC5C06240631B97008565A120764C0EE9C2CB0073"
                  "994D79080136"),
               10000, 64, "sha512"
            ),

        #
        # test vectors from fastpbkdf2 <https://github.com/ctz/fastpbkdf2/blob/master/testdata.py>
        #
            (
                hb('55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc'
                   '49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783'),
                b'passwd', b'salt', 1, 64, 'sha256',
            ),

            (
                hb('4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56'
                   'a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d'),
                b'Password', b'NaCl', 80000, 64, 'sha256',
            ),

            (
                hb('120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b'),
                b'password', b'salt', 1, 32, 'sha256',
            ),

            (
                hb('ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43'),
                b'password', b'salt', 2, 32, 'sha256',
            ),

            (
                hb('c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a'),
                b'password', b'salt', 4096, 32, 'sha256',
            ),

            (
                hb('348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c'
                   '635518c7dac47e9'),
                b'passwordPASSWORDpassword', b'saltSALTsaltSALTsaltSALTsaltSALTsalt',
                4096, 40, 'sha256',
            ),

            (
                hb('9e83f279c040f2a11aa4a02b24c418f2d3cb39560c9627fa4f47e3bcc2897c3d'),
                b'', b'salt', 1024, 32, 'sha256',
            ),

            (
                hb('ea5808411eb0c7e830deab55096cee582761e22a9bc034e3ece925225b07bf46'),
                b'password', b'', 1024, 32, 'sha256',
            ),

            (
                hb('89b69d0516f829893c696226650a8687'),
                b'pass\x00word', b'sa\x00lt', 4096, 16, 'sha256',
            ),

            (
                hb('867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252'),
                b'password', b'salt', 1, 32, 'sha512',
            ),

            (
                hb('e1d9c16aa681708a45f5c7c4e215ceb66e011a2e9f0040713f18aefdb866d53c'),
                b'password', b'salt', 2, 32, 'sha512',
            ),

            (
                hb('d197b1b33db0143e018b12f3d1d1479e6cdebdcc97c5c0f87f6902e072f457b5'),
                b'password', b'salt', 4096, 32, 'sha512',
            ),

            (
                hb('6e23f27638084b0f7ea1734e0d9841f55dd29ea60a834466f3396bac801fac1eeb'
                   '63802f03a0b4acd7603e3699c8b74437be83ff01ad7f55dac1ef60f4d56480c35e'
                   'e68fd52c6936'),
                b'passwordPASSWORDpassword', b'saltSALTsaltSALTsaltSALTsaltSALTsalt',
                1, 72, 'sha512',
            ),

            (
                hb('0c60c80f961f0e71f3a9b524af6012062fe037a6'),
                b'password', b'salt', 1, 20, 'sha1',
            ),

        #
        # custom tests
        #
            (
                hb('e248fb6b13365146f8ac6307cc222812'),
                b"secret", b"salt", 10, 16, "sha1",
            ),
            (
                hb('e248fb6b13365146f8ac6307cc2228127872da6d'),
                b"secret", b"salt", 10, None, "sha1",
            ),
            (
                hb('b1d5485772e6f76d5ebdc11b38d3eff0a5b2bd50dc11f937e86ecacd0cd40d1b'
                   '9113e0734e3b76a3'),
                b"secret", b"salt", 62, 40, "md5",
            ),
            (
                hb('ea014cc01f78d3883cac364bb5d054e2be238fb0b6081795a9d84512126e3129'
                   '062104d2183464c4'),
                b"secret", b"salt", 62, 40, "md4",
            ),
        ]

    def test_known(self):
        """test reference vectors"""
        for row in self.pbkdf2_test_vectors:
            correct, secret, salt, rounds, keylen = row[:5]
            digest = row[5] if len(row) == 6 else "sha1"
            result = pbkdf2_hmac(digest, secret, salt, rounds, keylen)
            self.assertEqual(result, correct)

    def test_backends(self):
        """verify expected backends are present"""
        from passlib.crypto.digest import PBKDF2_BACKENDS

        # check for fastpbkdf2
        try:
            import fastpbkdf2
            has_fastpbkdf2 = True
        except ImportError:
            has_fastpbkdf2 = False
        self.assertEqual("fastpbkdf2" in PBKDF2_BACKENDS, has_fastpbkdf2)

        # check for hashlib
        try:
            from hashlib import pbkdf2_hmac
            has_hashlib_ssl = pbkdf2_hmac.__module__ != "hashlib"
        except ImportError:
            has_hashlib_ssl = False
        self.assertEqual("hashlib-ssl" in PBKDF2_BACKENDS, has_hashlib_ssl)

        # check for appropriate builtin
        from passlib.utils.compat import PY3
        if PY3:
            self.assertIn("builtin-from-bytes", PBKDF2_BACKENDS)
        else:
            # XXX: only true as long as this is preferred over hexlify
            self.assertIn("builtin-unpack", PBKDF2_BACKENDS)

    def test_border(self):
        """test border cases"""
        def helper(secret=b'password', salt=b'salt', rounds=1, keylen=None, digest="sha1"):
            return pbkdf2_hmac(digest, secret, salt, rounds, keylen)
        helper()

        # invalid rounds
        self.assertRaises(ValueError, helper, rounds=-1)
        self.assertRaises(ValueError, helper, rounds=0)
        self.assertRaises(TypeError, helper, rounds='x')

        # invalid keylen
        helper(keylen=1)
        self.assertRaises(ValueError, helper, keylen=-1)
        self.assertRaises(ValueError, helper, keylen=0)
        # NOTE: hashlib actually throws error for keylen>=MAX_SINT32,
        #       but pbkdf2 forbids anything > MAX_UINT32 * digest_size
        self.assertRaises(OverflowError, helper, keylen=20*(2**32-1)+1)
        self.assertRaises(TypeError, helper, keylen='x')

        # invalid secret/salt type
        self.assertRaises(TypeError, helper, salt=5)
        self.assertRaises(TypeError, helper, secret=5)

        # invalid hash
        self.assertRaises(ValueError, helper, digest='foo')
        self.assertRaises(TypeError, helper, digest=5)

    def test_default_keylen(self):
        """test keylen==None"""
        def helper(secret=b'password', salt=b'salt', rounds=1, keylen=None, digest="sha1"):
            return pbkdf2_hmac(digest, secret, salt, rounds, keylen)
        self.assertEqual(len(helper(digest='sha1')), 20)
        self.assertEqual(len(helper(digest='sha256')), 32)

#=============================================================================
# eof
#=============================================================================
*/

/*
https://www.rfc-editor.org/rfc/rfc7914.txt

11.  Test Vectors for PBKDF2 with HMAC-SHA-256

   Below is a sequence of octets that illustrate input and output values
   for PBKDF2-HMAC-SHA-256.  The octets are hex encoded and whitespace
   is inserted for readability.  The test vectors below can be used to
   verify the PBKDF2-HMAC-SHA-256 [RFC2898] function.  The password and
   salt strings are passed as sequences of ASCII [RFC20] octets.

   PBKDF2-HMAC-SHA-256 (P="passwd", S="salt",
                       c=1, dkLen=64) =
   55 ac 04 6e 56 e3 08 9f ec 16 91 c2 25 44 b6 05
   f9 41 85 21 6d de 04 65 e6 8b 9d 57 c2 0d ac bc
   49 ca 9c cc f1 79 b6 45 99 16 64 b3 9d 77 ef 31
   7c 71 b8 45 b1 e3 0b d5 09 11 20 41 d3 a1 97 83

   PBKDF2-HMAC-SHA-256 (P="Password", S="NaCl",
                        c=80000, dkLen=64) =
   4d dc d8 f6 0b 98 be 21 83 0c ee 5e f2 27 01 f9
   64 1a 44 18 d0 4c 04 14 ae ff 08 87 6b 34 ab 56
   a1 d4 25 a1 22 58 33 54 9a db 84 1b 51 c9 b3 17
   6a 27 2b de bb a1 d0 78 47 8f 62 b3 97 f3 3c 8d

*/
QUnit.test("PBKDF#2 Vector Test", function(assert) {
	var vectors = [
		["0c60c80f961f0e71f3a9b524af6012062fe037a6", "password", "salt", 1, 20, "sha-1"],
		["ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957", "password", "salt", 2, 20, "sha-1"],
		["4b007901b765489abead49d926f721d065a429c1", "password", "salt", 4096, 20, "sha-1"],
        // just runs too long - could enable if ALL option is set
        //["eefe3d61cd4da4e4e9945b3d6ba2158c2634e984", "password", "salt", 16777216, 20, "sha-1"],
		["3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038", "passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 25,"sha-1"],
        ["56fa6aa75548099dcc37d7f03425e0c3", "pass\00word", "sa\00lt", 4096, 16, "sha-1"]
	];


	// pbkdf2: function(password, salt, iterations, len, hash_algo, format)
	for (var i = 0; i < vectors.length; i++) {
		var vector = vectors[i];

		var pass = vector[1];
		var salt = vector[2];
		var iter = vector[3];
		var len = vector[4];
		var hash_algo = vector[5];
		var expected = vector[0];

		if (len == 0) len = jCastle.digest.getDigestLength(hash_algo);

		// pbkdf1: function(password, salt, iterations, len, hash_algo, format)
		var result = jCastle.kdf.pbkdf2(pass, salt, iter, len, hash_algo);

		assert.equal(result.toString('hex'), expected, 'PBKDF2 with '+hash_algo+' Test');
	}

});


QUnit.test('PKCS#12 PBKDF Vector Test', function(assert) {
    // https://cryptopp.com/wiki/PKCS12_PBKDF
    // openssl's pkcs12 derivekey function treats password as it is.
    // but rfc7292 says password should be transformed as a bmpstring.
    // for this reason, the result values are different.
    //
    // test vectors of openssl:
    //
    //    password: "password"
    //    iterations: 1024
    //    purpose: 0
    //    salt: "salt"
    //    hashAlgo: sha-256
    //    expected: 46FB1E99AA495B548F67302782AFEF4711497437F084C66CB21B37AEB8206EF1
    //
    //    password: "password"
    //    iterations: 1024
    //    purpose: 0
    //    salt: "PKCS12_PBKDF key derivation"
    //    hashAlgo: sha-256
    //    expected: 22571DBE3FC26268CE4F80D7A13F762A
    //
    //    password: "password"
    //    iterations: 1024
    //    purpose: 0
    //    salt: "PKCS12_PBKDF iv derivation"
    //    hashAlgo: sha-256
    //    expected: AFC15EECE0DBEEF3A596281E14DD954B

    var testVectors = [
        {
            password: "password",
            iterations: 1024,
            purpose: 0,
            salt: "salt",
            hashAlgo: "sha-256",
            expected: "46FB1E99AA495B548F67302782AFEF4711497437F084C66CB21B37AEB8206EF1"
        },
        {
            password: "password",
            iterations: 1024,
            purpose: 0,
            salt: "PKCS12_PBKDF key derivation",
            hashAlgo: "sha-256",
            expected: "22571DBE3FC26268CE4F80D7A13F762A"
        },
        {
            password: "password",
            iterations: 1024,
            purpose: 0,
            salt: "PKCS12_PBKDF iv derivation",
            hashAlgo: "sha-256",
            expected: "AFC15EECE0DBEEF3A596281E14DD954B"
        }
    ];

    for (var i = 0; i < testVectors.length; i++) {
        var vector = testVectors[i];

        var password = Buffer.from(vector.password);
        var salt = Buffer.from(vector.salt);
        var iterations = vector.iterations;
        var expected = Buffer.from(vector.expected, 'hex');
        var hash_algo = vector.hashAlgo;
        var purpose = vector.purpose;
        var keylen = expected.length;
    
        // if first parameter is set as null and eighth parameter has a value,
        // then the function accepts the password as it is. it means
        // the given password is not transformed to a bmpstring as openssl works.
        var result = jCastle.kdf.pkcs12DeriveKey(null, salt, iterations, purpose, keylen, hash_algo, password);
    
        var f = result.equals(expected);

        assert.ok(f, 'pkcs12.derivekey test');
    
    }
});

/*
RFC 7518

Appendix C.  Example ECDH-ES Key Agreement Computation

   This example uses ECDH-ES Key Agreement and the Concat KDF to derive
   the CEK in the manner described in Section 4.6.  In this example, the
   ECDH-ES Direct Key Agreement mode ("alg" value "ECDH-ES") is used to
   produce an agreed-upon key for AES GCM with a 128-bit key ("enc"
   value "A128GCM").

   In this example, a producer Alice is encrypting content to a consumer
   Bob.  The producer (Alice) generates an ephemeral key for the key
   agreement computation.  Alice's ephemeral key (in JWK format) used
   for the key agreement computation in this example (including the
   private part) is:

     {"kty":"EC",
      "crv":"P-256",
      "x":"gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
      "y":"SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps",
      "d":"0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo"
     }

   The consumer's (Bob's) key (in JWK format) used for the key agreement
   computation in this example (including the private part) is:

     {"kty":"EC",
      "crv":"P-256",
      "x":"weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
      "y":"e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
      "d":"VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"
     }

   Header Parameter values used in this example are as follows.  The
   "apu" (agreement PartyUInfo) Header Parameter value is the base64url
   encoding of the UTF-8 string "Alice" and the "apv" (agreement
   PartyVInfo) Header Parameter value is the base64url encoding of the
   UTF-8 string "Bob".  The "epk" (ephemeral public key) Header
   Parameter is used to communicate the producer's (Alice's) ephemeral
   public key value to the consumer (Bob).

     {"alg":"ECDH-ES",
      "enc":"A128GCM",
      "apu":"QWxpY2U",
      "apv":"Qm9i",
      "epk":
       {"kty":"EC",
        "crv":"P-256",
        "x":"gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
        "y":"SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps"
       }
     }

   The resulting Concat KDF [NIST.800-56A] parameter values are:

   Z
      This is set to the ECDH-ES key agreement output.  (This value is
      often not directly exposed by libraries, due to NIST security
      requirements, and only serves as an input to a KDF.)  In this
      example, Z is following the octet sequence (using JSON array
      notation):
      [158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132,
      38, 156, 251, 49, 110, 163, 218, 128, 106, 72, 246, 218, 167, 121,
      140, 254, 144, 196].

   keydatalen
      This value is 128 - the number of bits in the desired output key
      (because "A128GCM" uses a 128-bit key).

   AlgorithmID
      This is set to the octets representing the 32-bit big-endian value
      7 - [0, 0, 0, 7] - the number of octets in the AlgorithmID content
      "A128GCM", followed, by the octets representing the ASCII string
      "A128GCM" - [65, 49, 50, 56, 71, 67, 77].

   PartyUInfo
      This is set to the octets representing the 32-bit big-endian value
      5 - [0, 0, 0, 5] - the number of octets in the PartyUInfo content
      "Alice", followed, by the octets representing the UTF-8 string
      "Alice" - [65, 108, 105, 99, 101].

   PartyVInfo
      This is set to the octets representing the 32-bit big-endian value
      3 - [0, 0, 0, 3] - the number of octets in the PartyUInfo content
      "Bob", followed, by the octets representing the UTF-8 string "Bob"
      - [66, 111, 98].

   SuppPubInfo
      This is set to the octets representing the 32-bit big-endian value
      128 - [0, 0, 0, 128] - the keydatalen value.

   SuppPrivInfo
      This is set to the empty octet sequence.

   Concatenating the parameters AlgorithmID through SuppPubInfo results
   in an OtherInfo value of:
   [0, 0, 0, 7, 65, 49, 50, 56, 71, 67, 77, 0, 0, 0, 5, 65, 108, 105,
   99, 101, 0, 0, 0, 3, 66, 111, 98, 0, 0, 0, 128]

   Concatenating the round number 1 ([0, 0, 0, 1]), Z, and the OtherInfo
   value results in the Concat KDF round 1 hash input of:
   [0, 0, 0, 1,
   158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132, 38,
   156, 251, 49, 110, 163, 218, 128, 106, 72, 246, 218, 167, 121, 140,
   254, 144, 196,
   0, 0, 0, 7, 65, 49, 50, 56, 71, 67, 77, 0, 0, 0, 5, 65, 108, 105, 99,
   101, 0, 0, 0, 3, 66, 111, 98, 0, 0, 0, 128]

   The resulting derived key, which is the first 128 bits of the round 1
   hash output is:
   [86, 170, 141, 234, 248, 35, 109, 32, 92, 34, 40, 205, 113, 167, 16,
   26]

   The base64url-encoded representation of this derived key is:

     VqqN6vgjbSBcIijNcacQGg
*/
QUnit.test("singlestepKDF(ConcatKDF) Vector Test", function(assert) {

    var Z = Buffer.from(
        [158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132,
            38, 156, 251, 49, 110, 163, 218, 128, 106, 72, 246, 218, 167, 121,
            140, 254, 144, 196]);
    var keydatalen = 128 / 8;

    var other_info = Buffer.from(
        [0, 0, 0, 7, 65, 49, 50, 56, 71, 67, 77, 0, 0, 0, 5, 65, 108, 105,
        99, 101, 0, 0, 0, 3, 66, 111, 98, 0, 0, 0, 128]);

    var expected_dk = Buffer.from(
        [86, 170, 141, 234, 248, 35, 109, 32, 92, 34, 40, 205, 113, 167, 16,
            26]);

    var hash_algo = 'sha-256';

    var hash_type = 'hash';

    var dkey = jCastle.kdf.singlestepKDF(Z, keydatalen, other_info, hash_algo, hash_type);

    //console.log(dkey.equals(expected_dk));
    assert.ok(dkey.equals(expected_dk), 'singlestepKDF test');
});