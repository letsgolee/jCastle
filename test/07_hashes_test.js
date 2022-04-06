const QUnit = require('qunit');
const jCastle = require('../lib/index');


QUnit.module('MD2');
QUnit.test("Vector Test", function(assert) {

	var testVectors = [
		[ "",
        [0x83,0x50,0xe5,0xa3,0xe2,0x4c,0x15,0x3d,
         0xf2,0x27,0x5c,0x9f,0x80,0x69,0x27,0x73
        ]
      ],
      [ "a",
        [0x32,0xec,0x01,0xec,0x4a,0x6d,0xac,0x72,
         0xc0,0xab,0x96,0xfb,0x34,0xc0,0xb5,0xd1
        ]
      ],
      [ "message digest",
        [0xab,0x4f,0x49,0x6b,0xfb,0x2a,0x53,0x0b,
         0x21,0x9f,0xf3,0x30,0x31,0xfe,0x06,0xb0
        ]
      ],
      [ "abcdefghijklmnopqrstuvwxyz",
        [0x4e,0x8d,0xdf,0xf3,0x65,0x02,0x92,0xab,
         0x5a,0x41,0x08,0xc3,0xaa,0x47,0x94,0x0b
        ]
      ],
      [ "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        [0xda,0x33,0xde,0xf2,0xa4,0x2d,0xf1,0x39,
         0x75,0x35,0x28,0x46,0xc3,0x03,0x38,0xcd
        ]
      ],
      [ "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        [0xd5,0x97,0x6f,0x79,0xd8,0x3d,0x3a,0x0d,
         0xc9,0x80,0x6c,0x3c,0x66,0xf3,0xef,0xd8
        ]
      ]
	];

	for (var i = 0; i < testVectors.length; i++) {
		var vector = testVectors[i];

		var m = Buffer.from(vector[0]);
		var expected = typeof vector[1] == 'string' ? Buffer.from(vector[1].replace(/[ \:]/g, ''), 'hex') : Buffer.from(vector[1])
		var repeat = typeof vector[2] == 'undefined' ? 1 : vector[2];

		var md = jCastle.digest.create('md2');

		md.start();

		for (var j = 0; j < repeat; j++) {
			md.update(m);
		}

		var h = md.finalize();

		assert.ok(h.equals(expected), "Message Digest test passed!");
	}
});

QUnit.module('MD4');
QUnit.test("Vector Test", function(assert) {

	var testVectors = [
		[ "", 
          [0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31,
           0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0, 0x89, 0xc0] ],
        [ "a",
          [0xbd, 0xe5, 0x2c, 0xb3, 0x1d, 0xe3, 0x3e, 0x46,
           0x24, 0x5e, 0x05, 0xfb, 0xdb, 0xd6, 0xfb, 0x24] ],
        [ "abc",
          [0xa4, 0x48, 0x01, 0x7a, 0xaf, 0x21, 0xd8, 0x52, 
           0x5f, 0xc1, 0x0a, 0xe8, 0x7a, 0xa6, 0x72, 0x9d] ],
        [ "message digest", 
          [0xd9, 0x13, 0x0a, 0x81, 0x64, 0x54, 0x9f, 0xe8, 
           0x18, 0x87, 0x48, 0x06, 0xe1, 0xc7, 0x01, 0x4b] ],
        [ "abcdefghijklmnopqrstuvwxyz", 
          [0xd7, 0x9e, 0x1c, 0x30, 0x8a, 0xa5, 0xbb, 0xcd, 
           0xee, 0xa8, 0xed, 0x63, 0xdf, 0x41, 0x2d, 0xa9] ],
        [ "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 
          [0x04, 0x3f, 0x85, 0x82, 0xf2, 0x41, 0xdb, 0x35, 
           0x1c, 0xe6, 0x27, 0xe1, 0x53, 0xe7, 0xf0, 0xe4] ],
        [ "12345678901234567890123456789012345678901234567890123456789012345678901234567890", 
          [0xe3, 0x3b, 0x4d, 0xdc, 0x9c, 0x38, 0xf2, 0x19, 
           0x9c, 0x3e, 0x7b, 0x16, 0x4f, 0xcc, 0x05, 0x36] ],
	];

	for (var i = 0; i < testVectors.length; i++) {
		var vector = testVectors[i];

		var m = Buffer.from(vector[0]);
		var expected = typeof vector[1] == 'string' ? Buffer.from(vector[1].replace(/[ \:]/g, ''), 'hex') : Buffer.from(vector[1])
		var repeat = typeof vector[2] == 'undefined' ? 1 : vector[2];

		var md = jCastle.digest.create('md4');

		md.start();

		for (var j = 0; j < repeat; j++) {
			md.update(m);
		}

		var h = md.finalize();

		assert.ok(h.equals(expected), "Message Digest test passed!");
	}
});

QUnit.module('MD5');
QUnit.test("Vector Test", function(assert) {

	var testVectors = [
		[ "",
      [ 0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 
        0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e ] ],
    [ "a",
      [0x0c, 0xc1, 0x75, 0xb9, 0xc0, 0xf1, 0xb6, 0xa8, 
       0x31, 0xc3, 0x99, 0xe2, 0x69, 0x77, 0x26, 0x61 ] ],
    [ "abc",
      [ 0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0, 
        0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0x7f, 0x72 ] ],
    [ "message digest", 
      [ 0xf9, 0x6b, 0x69, 0x7d, 0x7c, 0xb7, 0x93, 0x8d, 
        0x52, 0x5a, 0x2f, 0x31, 0xaa, 0xf1, 0x61, 0xd0 ] ], 
    [ "abcdefghijklmnopqrstuvwxyz",
      [ 0xc3, 0xfc, 0xd3, 0xd7, 0x61, 0x92, 0xe4, 0x00, 
        0x7d, 0xfb, 0x49, 0x6c, 0xca, 0x67, 0xe1, 0x3b ] ],
    [ "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
      [ 0xd1, 0x74, 0xab, 0x98, 0xd2, 0x77, 0xd9, 0xf5, 
        0xa5, 0x61, 0x1c, 0x2c, 0x9f, 0x41, 0x9d, 0x9f ] ],
    [ "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
      [ 0x57, 0xed, 0xf4, 0xa2, 0x2b, 0xe3, 0xc9, 0x55, 
        0xac, 0x49, 0xda, 0x2e, 0x21, 0x07, 0xb6, 0x7a ] ], 
	];

	for (var i = 0; i < testVectors.length; i++) {
		var vector = testVectors[i];

		var m = Buffer.from(vector[0]);
		var expected = typeof vector[1] == 'string' ? Buffer.from(vector[1].replace(/[ \:]/g, ''), 'hex') : Buffer.from(vector[1])
		var repeat = typeof vector[2] == 'undefined' ? 1 : vector[2];

		var md = jCastle.digest.create('md5');

		md.start();

		for (var j = 0; j < repeat; j++) {
			md.update(m);
		}

		var h = md.finalize();

		assert.ok(h.equals(expected), "Message Digest test passed!");
	}
});

QUnit.module('SHA-1');
QUnit.test("Vector Test", function(assert) {
	var testVectors = [
		[
			"",
			"da39a3ee 5e6b4b0d 3255bfef 95601890 afd80709"
		],
		[
			"abc",
			"a9993e36 4706816a ba3e2571 7850c26c 9cd0d89d"
		],
		[
			"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
			"84983e44 1c3bd26e baae4aa1 f95129e5 e54670f1"
		],
		[
			"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
			"a49b2446 a02c645b f419f995 b6709125 3a04a259"
		],/*
		[
			"a",
			"34aa973c d4c4daa4 f61eeb2b dbad2731 6534016f",
			1000000 // repeats
		],*/
		[
			"Rosetta Code",
			"48c98f7e5a6e736d790ab740dfc3f51a61abe2b5"
		]
	];

	for (var i = 0; i < testVectors.length; i++) {
		var vector = testVectors[i];

		var m = Buffer.from(vector[0]);
		var expected = Buffer.from(vector[1].replace(/[ \:]/g, ''), 'hex');
		var repeat = typeof vector[2] == 'undefined' ? 1 : vector[2];

		var md = jCastle.digest.create('sha-1');

		md.start();

		for (var j = 0; j < repeat; j++) {
			md.update(m);
		}

		var h = md.finalize();

		assert.ok(h.equals(expected), "SHA-1 Message Digest test!");
	}
});

QUnit.module('SHA-224');
QUnit.test("Vector Test", function(assert) {
	var testVectors = [
		[
			"",
			"d14a028c 2a3a2bc9 476102bb 288234c4 15a2b01f 828ea62a c5b3e42f"
		],
		[
			"abc",
			"23097d22 3405d822 8642a477 bda255b3 2aadbce4 bda0b3f7 e36c9da7"
		],
		[	
			"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
			"75388b16 512776cc 5dba5da1 fd890150 b0c6455c b4f58b19 52522525"
		],
		[
			"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
			"c97ca9a5 59850ce9 7a04a96d ef6d99a9 e0e0e2ab 14e6b8df 265fc0b3"
		]/*,
		[
			"a",
			"20794655 980c91d8 bbb4c1ea 97618a4b f03f4258 1948b2ee 4ee7ad67",
			1000000
		]*/
	];

	for (var i = 0; i < testVectors.length; i++) {
		var vector = testVectors[i];

		var m = Buffer.from(vector[0]);
		var expected = Buffer.from(vector[1].replace(/[ \:]/g, ''), 'hex');
		var repeat = typeof vector[2] == 'undefined' ? 1 : vector[2];

		var md = jCastle.digest.create('sha-224');

		md.start();

		for (var j = 0; j < repeat; j++) {
			md.update(m);
		}

		var h = md.finalize();

		assert.ok(h.equals(expected), "SHA-224 Message Digest test!");
	}
});

QUnit.module('SHA-256');
QUnit.test("Vector Test", function(assert) {
	var testVectors = [
		[
			"",
			"e3b0c442 98fc1c14 9afbf4c8 996fb924 27ae41e4 649b934c a495991b 7852b855"
		],
		[
			"abc",
			"ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad"
		],
		[	
			"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
			"248d6a61 d20638b8 e5c02693 0c3e6039 a33ce459 64ff2167 f6ecedd4 19db06c1"
		],
		[
			"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
			"cf5b16a7 78af8380 036ce59e 7b049237 0b249b11 e8f07a51 afac4503 7afee9d1"
		]/*,
		[
			"a",
			"cdc76e5c 9914fb92 81a1c7e2 84d73e67 f1809a48 a497200e 046d39cc c7112cd0",
			1000000
		]*/
	];

	for (var i = 0; i < testVectors.length; i++) {
		var vector = testVectors[i];

		var m = Buffer.from(vector[0]);
		var expected = Buffer.from(vector[1].replace(/[ \:]/g, ''), 'hex');
		var repeat = typeof vector[2] == 'undefined' ? 1 : vector[2];

		var md = jCastle.digest.create('sha-256');

		md.start();

		for (var j = 0; j < repeat; j++) {
			md.update(m);
		}

		var h = md.finalize();

		assert.ok(h.equals(expected), "SHA-256 Message Digest test!");
	}
});

QUnit.module('SHA-384');
QUnit.test("Vector Test", function(assert) {
	var testVectors = [
		[
			"",
			"38b060a751ac9638 4cd9327eb1b1e36a 21fdb71114be0743 4c0cc7bf63f6e1da 274edebfe76f65fb d51ad2f14898b95b"
		],
		[
			"abc",
			"cb00753f45a35e8b b5a03d699ac65007 272c32ab0eded163 1a8b605a43ff5bed 8086072ba1e7cc23 58baeca134c825a7"
		],
		[	
			"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
			"3391fdddfc8dc739 3707a65b1b470939 7cf8b1d162af05ab fe8f450de5f36bc6 b0455a8520bc4e6f 5fe95b1fe3c8452b"
		],
		[
			"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
			"09330c33f71147e8 3d192fc782cd1b47 53111b173b3b05d2 2fa08086e3b0f712 fcc7c71a557e2db9 66c3e9fa91746039"
		]/*,
		[
			"a",
			"9d0e1809716474cb 086e834e310a4a1c ed149e9c00f24852 7972cec5704c2a5b 07b8b3dc38ecc4eb ae97ddd87f3d8985",
			1000000
		]*/
	];

	for (var i = 0; i < testVectors.length; i++) {
		var vector = testVectors[i];

		var m = Buffer.from(vector[0]);
		var expected = Buffer.from(vector[1].replace(/[ \:]/g, ''), 'hex');
		var repeat = typeof vector[2] == 'undefined' ? 1 : vector[2];

		var md = jCastle.digest.create('sha-384');

		md.start();

		for (var j = 0; j < repeat; j++) {
			md.update(m);
		}

		var h = md.finalize();

		assert.ok(h.equals(expected), "SHA-384 Message Digest test!");
	}
});

QUnit.module('SHA-512');
QUnit.test("Vector Test", function(assert) {
	var testVectors = [
		[
			"",
			"cf83e1357eefb8bd f1542850d66d8007 d620e4050b5715dc 83f4a921d36ce9ce 47d0d13c5d85f2b0 ff8318d2877eec2f 63b931bd47417a81 a538327af927da3e"
		],
		[
			"abc",
			"ddaf35a193617aba cc417349ae204131 12e6fa4e89a97ea2 0a9eeee64b55d39a 2192992a274fc1a8 36ba3c23a3feebbd 454d4423643ce80e 2a9ac94fa54ca49f"
		],
		[
			"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
			"204a8fc6dda82f0a 0ced7beb8e08a416 57c16ef468b228a8 279be331a703c335 96fd15c13b1b07f9 aa1d3bea57789ca0 31ad85c7a71dd703 54ec631238ca3445"
		],
		[
			"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
			"8e959b75dae313da 8cf4f72814fc143f 8f7779c6eb9f7fa1 7299aeadb6889018 501d289e4900f7e4 331b99dec4b5433a c7d329eeb6dd2654 5e96e55b874be909"
		]/*,
		[
			"a",
			"e718483d0ce76964 4e2e42c7bc15b463 8e1f98b13b204428 5632a803afa973eb de0ff244877ea60a 4cb0432ce577c31b eb009c5c2c49aa2e 4eadb217ad8cc09b",
			1000000
		]*/
	];

	for (var i = 0; i < testVectors.length; i++) {
		var vector = testVectors[i];

		var m = Buffer.from(vector[0]);
		var expected = Buffer.from(vector[1].replace(/[ \:]/g, ''), 'hex');
		var repeat = typeof vector[2] == 'undefined' ? 1 : vector[2];

		var md = jCastle.digest.create('sha-512');

		md.start();

		for (var j = 0; j < repeat; j++) {
			md.update(m);
		}

		var h = md.finalize();

		assert.ok(h.equals(expected), "SHA-512 Message Digest test!");
	}

	// test for sha-512/224 and sha-512/256

	var testVectors = [
		{
			message: 'abc',
			'224': "4634270F707B6A54DAAE7530460842E20E37ED265CEEE9A43E8924AA",
			'256': "53048E2681941EF99B2E29B76B4C7DABE4C2D0C634FC6D46E0E2F13107E7AF23"
		},
		{
			message: "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
			'224': "23FEC5BB94D60B23308192640B0C453335D664734FE40E7268674AF9",
			'256': "3928E184FB8690F840DA3988121D31BE65CB9D3EF83EE6146FEAC861E19B563A"
		}
	];

	for (var i = 0; i < testVectors.length; i++) {
		var vector = testVectors[i];

		// 224
		var m = Buffer.from(vector.message);
		var expected = Buffer.from(vector['224'], 'hex');
		
		var md = jCastle.digest.create('sha-512/224');
		md.start();
		md.update(m);
		var h = md.finalize();

		assert.ok(h.equals(expected), "SHA-512/224 Message Digest test!");
		
		// 256
		var m = Buffer.from(vector.message);
		var expected = Buffer.from(vector['256'], 'hex');
		
		var md = jCastle.digest.create('sha-512/256');
		md.start();
		md.update(m);
		var h = md.finalize();

		assert.ok(h.equals(expected), "SHA-512/256 Message Digest test!");

	}
});

QUnit.module('HAS-160');
QUnit.test("Vector Test", function(assert) {
	var testVectors = [
		[
			"",
			[0x30,0x79,0x64,0xEF,0x34,0x15,0x1D,0x37,0xC8,0x04,0x7A,0xDE,0xC7,0xAB,0x50,0xF4,0xFF,0x89,0x76,0x2D]
		],
		[
			"abc",
			[0x97, 0x5E, 0x81, 0x04, 0x88, 0xCF, 0x2A, 0x3D, 0x49, 0x83, 0x84, 0x78, 0x12, 0x4A, 0xFC, 0xE4, 0xB1, 0xC7, 0x88, 0x04]
		],
	];

	for (var i = 0; i < testVectors.length; i++) {
		var vector = testVectors[i];

		var m = Buffer.from(vector[0]);
		var expected = typeof vector[1] == 'string' ? Buffer.from(vector[1].replace(/[ \:]/g, ''), 'hex') : Buffer.from(vector[1]);
		var repeat = typeof vector[2] == 'undefined' ? 1 : vector[2];

		var md = jCastle.digest.create('has-160');

		md.start({format: 'hex'});

		for (var j = 0; j < repeat; j++) {
			md.update(m);
		}

		var h = md.finalize();

		assert.ok(h.equals(expected), "Message Digest test passed!");
	}
});

QUnit.module('RIPEMD-128');
QUnit.test("Vector Test", function(assert) {

	var testVectors = [
		[
			"",
			[0xcd, 0xf2, 0x62, 0x13, 0xa1, 0x50, 0xdc, 0x3e,
			 0xcb, 0x61, 0x0f, 0x18, 0xf6, 0xb3, 0x8b, 0x46]
		],
		[
			"a",
			[0x86, 0xbe, 0x7a, 0xfa, 0x33, 0x9d, 0x0f, 0xc7,
			 0xcf, 0xc7, 0x85, 0xe7, 0x2f, 0x57, 0x8d, 0x33]
		],
		[
			"abc",
			[0xc1, 0x4a, 0x12, 0x19, 0x9c, 0x66, 0xe4, 0xba,
			 0x84, 0x63, 0x6b, 0x0f, 0x69, 0x14, 0x4c, 0x77]
		],
		[
			"message digest",
			[0x9e, 0x32, 0x7b, 0x3d, 0x6e, 0x52, 0x30, 0x62,
			 0xaf, 0xc1, 0x13, 0x2d, 0x7d, 0xf9, 0xd1, 0xb8]
		],
		[
			"abcdefghijklmnopqrstuvwxyz",
			[0xfd, 0x2a, 0xa6, 0x07, 0xf7, 0x1d, 0xc8, 0xf5,
			 0x10, 0x71, 0x49, 0x22, 0xb3, 0x71, 0x83, 0x4e]
		],
		[
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
			[0xd1, 0xe9, 0x59, 0xeb, 0x17, 0x9c, 0x91, 0x1f,
			 0xae, 0xa4, 0x62, 0x4c, 0x60, 0xc5, 0xc7, 0x02]
		]
	];

	for (var i = 0; i < testVectors.length; i++) {
		var vector = testVectors[i];

		var m = Buffer.from(vector[0]);
		var expected = typeof vector[1] == 'string' ? Buffer.from(vector[1].replace(/[ \:]/g, ''), 'hex') : Buffer.from(vector[1])
		var repeat = typeof vector[2] == 'undefined' ? 1 : vector[2];

		var md = jCastle.digest.create('ripemd-128');

		md.start();

		for (var j = 0; j < repeat; j++) {
			md.update(m);
		}

		var h = md.finalize();

		assert.ok(h.equals(expected), "RIPEMD-128 Message Digest test!");
	}
});

QUnit.module('RIPEMD-160');
QUnit.test("Vector Test", function(assert) {

	var testVectors = [
		[
			"",
			[0x9c, 0x11, 0x85, 0xa5, 0xc5, 0xe9, 0xfc, 0x54, 0x61, 0x28,
			 0x08, 0x97, 0x7e, 0xe8, 0xf5, 0x48, 0xb2, 0x25, 0x8d, 0x31]
		],
		[
			"a",
			[0x0b, 0xdc, 0x9d, 0x2d, 0x25, 0x6b, 0x3e, 0xe9, 0xda, 0xae,
			 0x34, 0x7b, 0xe6, 0xf4, 0xdc, 0x83, 0x5a, 0x46, 0x7f, 0xfe]
		],
		[
			"abc",
			[0x8e, 0xb2, 0x08, 0xf7, 0xe0, 0x5d, 0x98, 0x7a, 0x9b, 0x04,
			 0x4a, 0x8e, 0x98, 0xc6, 0xb0, 0x87, 0xf1, 0x5a, 0x0b, 0xfc]
		],
		[
			"message digest",
			[0x5d, 0x06, 0x89, 0xef, 0x49, 0xd2, 0xfa, 0xe5, 0x72, 0xb8,
			 0x81, 0xb1, 0x23, 0xa8, 0x5f, 0xfa, 0x21, 0x59, 0x5f, 0x36]
		],
		[
			"abcdefghijklmnopqrstuvwxyz",
			[0xf7, 0x1c, 0x27, 0x10, 0x9c, 0x69, 0x2c, 0x1b, 0x56, 0xbb,
			 0xdc, 0xeb, 0x5b, 0x9d, 0x28, 0x65, 0xb3, 0x70, 0x8d, 0xbc]
		],
		[
			"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
			[0x12, 0xa0, 0x53, 0x38, 0x4a, 0x9c, 0x0c, 0x88, 0xe4, 0x05,
			 0xa0, 0x6c, 0x27, 0xdc, 0xf4, 0x9a, 0xda, 0x62, 0xeb, 0x2b]
		]
	];

	for (var i = 0; i < testVectors.length; i++) {
		var vector = testVectors[i];

		var m = Buffer.from(vector[0]);
		var expected = typeof vector[1] == 'string' ? Buffer.from(vector[1].replace(/[ \:]/g, ''), 'hex') : Buffer.from(vector[1])
		var repeat = typeof vector[2] == 'undefined' ? 1 : vector[2];

		var md = jCastle.digest.create('ripemd-160');

		md.start();

		for (var j = 0; j < repeat; j++) {
			md.update(m);
		}

		var h = md.finalize();

		assert.ok(h.equals(expected), "RIPEMD-160 Message Digest test!");
	}
});

QUnit.module('RIPEMD-256');
QUnit.test("Vector Test", function(assert) {

	var testVectors = [
		[
			"",
			[0x02, 0xba, 0x4c, 0x4e, 0x5f, 0x8e, 0xcd, 0x18,
			 0x77, 0xfc, 0x52, 0xd6, 0x4d, 0x30, 0xe3, 0x7a,
			 0x2d, 0x97, 0x74, 0xfb, 0x1e, 0x5d, 0x02, 0x63,
			 0x80, 0xae, 0x01, 0x68, 0xe3, 0xc5, 0x52, 0x2d]
		],
		[
			"a",
			[0xf9, 0x33, 0x3e, 0x45, 0xd8, 0x57, 0xf5, 0xd9,
			 0x0a, 0x91, 0xba, 0xb7, 0x0a, 0x1e, 0xba, 0x0c,
			 0xfb, 0x1b, 0xe4, 0xb0, 0x78, 0x3c, 0x9a, 0xcf,
			 0xcd, 0x88, 0x3a, 0x91, 0x34, 0x69, 0x29, 0x25 ]
		],
		[ 
			"abc",
			[0xaf, 0xbd, 0x6e, 0x22, 0x8b, 0x9d, 0x8c, 0xbb,
			 0xce, 0xf5, 0xca, 0x2d, 0x03, 0xe6, 0xdb, 0xa1,
			 0x0a, 0xc0, 0xbc, 0x7d, 0xcb, 0xe4, 0x68, 0x0e,
			 0x1e, 0x42, 0xd2, 0xe9, 0x75, 0x45, 0x9b, 0x65 ]
		],
		[
			"message digest",
			[0x87, 0xe9, 0x71, 0x75, 0x9a, 0x1c, 0xe4, 0x7a,
			 0x51, 0x4d, 0x5c, 0x91, 0x4c, 0x39, 0x2c, 0x90,
			 0x18, 0xc7, 0xc4, 0x6b, 0xc1, 0x44, 0x65, 0x55,
			 0x4a, 0xfc, 0xdf, 0x54, 0xa5, 0x07, 0x0c, 0x0e ]
		],
		[
			"abcdefghijklmnopqrstuvwxyz",
			[0x64, 0x9d, 0x30, 0x34, 0x75, 0x1e, 0xa2, 0x16,
			 0x77, 0x6b, 0xf9, 0xa1, 0x8a, 0xcc, 0x81, 0xbc,
			 0x78, 0x96, 0x11, 0x8a, 0x51, 0x97, 0x96, 0x87,
			 0x82, 0xdd, 0x1f, 0xd9, 0x7d, 0x8d, 0x51, 0x33 ]
		],
		[
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
			[0x57, 0x40, 0xa4, 0x08, 0xac, 0x16, 0xb7, 0x20,
			 0xb8, 0x44, 0x24, 0xae, 0x93, 0x1c, 0xbb, 0x1f,
			 0xe3, 0x63, 0xd1, 0xd0, 0xbf, 0x40, 0x17, 0xf1,
			 0xa8, 0x9f, 0x7e, 0xa6, 0xde, 0x77, 0xa0, 0xb8 ]
		]
	];

	for (var i = 0; i < testVectors.length; i++) {
		var vector = testVectors[i];

		var m = Buffer.from(vector[0]);
		var expected = typeof vector[1] == 'string' ? Buffer.from(vector[1].replace(/[ \:]/g, ''), 'hex') : Buffer.from(vector[1])
		var repeat = typeof vector[2] == 'undefined' ? 1 : vector[2];

		var md = jCastle.digest.create('ripemd-256');

		md.start();

		for (var j = 0; j < repeat; j++) {
			md.update(m);
		}

		var h = md.finalize();

		assert.ok(h.equals(expected), "RIPEMD-256 Message Digest test!");
	}
});

QUnit.module('RIPEMD-320');
QUnit.test("Vector Test", function(assert) {

	var testVectors = [
		[
			"",
			[0x22, 0xd6, 0x5d, 0x56, 0x61, 0x53, 0x6c, 0xdc, 0x75, 0xc1,
			 0xfd, 0xf5, 0xc6, 0xde, 0x7b, 0x41, 0xb9, 0xf2, 0x73, 0x25,
			 0xeb, 0xc6, 0x1e, 0x85, 0x57, 0x17, 0x7d, 0x70, 0x5a, 0x0e,
			 0xc8, 0x80, 0x15, 0x1c, 0x3a, 0x32, 0xa0, 0x08, 0x99, 0xb8 ]
		],
		[
			"a",
			[0xce, 0x78, 0x85, 0x06, 0x38, 0xf9, 0x26, 0x58, 0xa5, 0xa5,
			 0x85, 0x09, 0x75, 0x79, 0x92, 0x6d, 0xda, 0x66, 0x7a, 0x57,
			 0x16, 0x56, 0x2c, 0xfc, 0xf6, 0xfb, 0xe7, 0x7f, 0x63, 0x54,
			 0x2f, 0x99, 0xb0, 0x47, 0x05, 0xd6, 0x97, 0x0d, 0xff, 0x5d ]
		],
		[
			"abc",
			[0xde, 0x4c, 0x01, 0xb3, 0x05, 0x4f, 0x89, 0x30, 0xa7, 0x9d,
			 0x09, 0xae, 0x73, 0x8e, 0x92, 0x30, 0x1e, 0x5a, 0x17, 0x08,
			 0x5b, 0xef, 0xfd, 0xc1, 0xb8, 0xd1, 0x16, 0x71, 0x3e, 0x74,
			 0xf8, 0x2f, 0xa9, 0x42, 0xd6, 0x4c, 0xdb, 0xc4, 0x68, 0x2d ]
		],
		[
			"message digest",
			[0x3a, 0x8e, 0x28, 0x50, 0x2e, 0xd4, 0x5d, 0x42, 0x2f, 0x68,
			 0x84, 0x4f, 0x9d, 0xd3, 0x16, 0xe7, 0xb9, 0x85, 0x33, 0xfa,
			 0x3f, 0x2a, 0x91, 0xd2, 0x9f, 0x84, 0xd4, 0x25, 0xc8, 0x8d,
			 0x6b, 0x4e, 0xff, 0x72, 0x7d, 0xf6, 0x6a, 0x7c, 0x01, 0x97 ]
		],
		[
			"abcdefghijklmnopqrstuvwxyz",
			[0xca, 0xbd, 0xb1, 0x81, 0x0b, 0x92, 0x47, 0x0a, 0x20, 0x93,
			 0xaa, 0x6b, 0xce, 0x05, 0x95, 0x2c, 0x28, 0x34, 0x8c, 0xf4,
			 0x3f, 0xf6, 0x08, 0x41, 0x97, 0x51, 0x66, 0xbb, 0x40, 0xed,
			 0x23, 0x40, 0x04, 0xb8, 0x82, 0x44, 0x63, 0xe6, 0xb0, 0x09 ]
		],
		[
			"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
			[0xd0, 0x34, 0xa7, 0x95, 0x0c, 0xf7, 0x22, 0x02, 0x1b, 0xa4,
			 0xb8, 0x4d, 0xf7, 0x69, 0xa5, 0xde, 0x20, 0x60, 0xe2, 0x59,
			 0xdf, 0x4c, 0x9b, 0xb4, 0xa4, 0x26, 0x8c, 0x0e, 0x93, 0x5b,
			 0xbc, 0x74, 0x70, 0xa9, 0x69, 0xc9, 0xd0, 0x72, 0xa1, 0xac ]
		]
	];

	for (var i = 0; i < testVectors.length; i++) {
		var vector = testVectors[i];

		var m = Buffer.from(vector[0]);
		var expected = typeof vector[1] == 'string' ? Buffer.from(vector[1].replace(/[ \:]/g, ''), 'hex') : Buffer.from(vector[1])
		var repeat = typeof vector[2] == 'undefined' ? 1 : vector[2];

		var md = jCastle.digest.create('ripemd-320');

		md.start();

		for (var j = 0; j < repeat; j++) {
			md.update(m);
		}

		var h = md.finalize();

		assert.ok(h.equals(expected), "RIPEMD-320 Message Digest test!");
	}
});

QUnit.module('Tiger');
QUnit.test("Vector Test", function(assert) {

	var testVectors = [
	[ "",
     [ 0x32, 0x93, 0xac, 0x63, 0x0c, 0x13, 0xf0, 0x24,
       0x5f, 0x92, 0xbb, 0xb1, 0x76, 0x6e, 0x16, 0x16,
       0x7a, 0x4e, 0x58, 0x49, 0x2d, 0xde, 0x73, 0xf3 ]
    ],
    [ "abc",
     [ 0x2a, 0xab, 0x14, 0x84, 0xe8, 0xc1, 0x58, 0xf2,
       0xbf, 0xb8, 0xc5, 0xff, 0x41, 0xb5, 0x7a, 0x52,
       0x51, 0x29, 0x13, 0x1c, 0x95, 0x7b, 0x5f, 0x93 ]
    ],
    [ "Tiger",
     [ 0xdd, 0x00, 0x23, 0x07, 0x99, 0xf5, 0x00, 0x9f,
       0xec, 0x6d, 0xeb, 0xc8, 0x38, 0xbb, 0x6a, 0x27,
       0xdf, 0x2b, 0x9d, 0x6f, 0x11, 0x0c, 0x79, 0x37 ]
    ],
    [ "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-",
     [ 0xf7, 0x1c, 0x85, 0x83, 0x90, 0x2a, 0xfb, 0x87,
       0x9e, 0xdf, 0xe6, 0x10, 0xf8, 0x2c, 0x0d, 0x47,
       0x86, 0xa3, 0xa5, 0x34, 0x50, 0x44, 0x86, 0xb5 ]
    ],
    [ "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-",
     [ 0xc5, 0x40, 0x34, 0xe5, 0xb4, 0x3e, 0xb8, 0x00,
       0x58, 0x48, 0xa7, 0xe0, 0xae, 0x6a, 0xac, 0x76,
       0xe4, 0xff, 0x59, 0x0a, 0xe7, 0x15, 0xfd, 0x25 ]
    ]

	];

	for (var i = 0; i < testVectors.length; i++) {
		var vector = testVectors[i];

		var m = Buffer.from(vector[0]);
		var expected = typeof vector[1] == 'string' ? Buffer.from(vector[1].replace(/[ \:]/g, ''), 'hex') : Buffer.from(vector[1])
		var repeat = typeof vector[2] == 'undefined' ? 1 : vector[2];

		var md = jCastle.digest.create('tiger');

		md.start();

		for (var j = 0; j < repeat; j++) {
			md.update(m);
		}

		var h = md.finalize();

		assert.ok(h.equals(expected), "Message Digest test passed!");
	}
});

QUnit.module('Whirlpool');
QUnit.test("Vector Test", function(assert) {

	var testVectors = [
		[
  "",
  [ 0x19, 0xFA, 0x61, 0xD7, 0x55, 0x22, 0xA4, 0x66, 0x9B, 0x44, 0xE3, 0x9C, 0x1D, 0x2E, 0x17, 0x26,
    0xC5, 0x30, 0x23, 0x21, 0x30, 0xD4, 0x07, 0xF8, 0x9A, 0xFE, 0xE0, 0x96, 0x49, 0x97, 0xF7, 0xA7,
    0x3E, 0x83, 0xBE, 0x69, 0x8B, 0x28, 0x8F, 0xEB, 0xCF, 0x88, 0xE3, 0xE0, 0x3C, 0x4F, 0x07, 0x57,
    0xEA, 0x89, 0x64, 0xE5, 0x9B, 0x63, 0xD9, 0x37, 0x08, 0xB1, 0x38, 0xCC, 0x42, 0xA6, 0x6E, 0xB3 ]
],


   /* 448-bits of 0 bits */
[
  [ 0x00 ],
  [ 0x0B, 0x3F, 0x53, 0x78, 0xEB, 0xED, 0x2B, 0xF4, 0xD7, 0xBE, 0x3C, 0xFD, 0x81, 0x8C, 0x1B, 0x03,
    0xB6, 0xBB, 0x03, 0xD3, 0x46, 0x94, 0x8B, 0x04, 0xF4, 0xF4, 0x0C, 0x72, 0x6F, 0x07, 0x58, 0x70,
    0x2A, 0x0F, 0x1E, 0x22, 0x58, 0x80, 0xE3, 0x8D, 0xD5, 0xF6, 0xED, 0x6D, 0xE9, 0xB1, 0xE9, 0x61,
    0xE4, 0x9F, 0xC1, 0x31, 0x8D, 0x7C, 0xB7, 0x48, 0x22, 0xF3, 0xD0, 0xE2, 0xE9, 0xA7, 0xE7, 0xB0 ],
	56
],

   /* 520-bits of 0 bits */
[
  [ 0x00 ],
  [ 0x85, 0xE1, 0x24, 0xC4, 0x41, 0x5B, 0xCF, 0x43, 0x19, 0x54, 0x3E, 0x3A, 0x63, 0xFF, 0x57, 0x1D,
    0x09, 0x35, 0x4C, 0xEE, 0xBE, 0xE1, 0xE3, 0x25, 0x30, 0x8C, 0x90, 0x69, 0xF4, 0x3E, 0x2A, 0xE4,
    0xD0, 0xE5, 0x1D, 0x4E, 0xB1, 0xE8, 0x64, 0x28, 0x70, 0x19, 0x4E, 0x95, 0x30, 0xD8, 0xD8, 0xAF,
    0x65, 0x89, 0xD1, 0xBF, 0x69, 0x49, 0xDD, 0xF9, 0x0A, 0x7F, 0x12, 0x08, 0x62, 0x37, 0x95, 0xB9 ],
	65
],

   /* 512-bits, leading set */
[
  [ 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ],
  [ 0x10, 0x3E, 0x00, 0x55, 0xA9, 0xB0, 0x90, 0xE1, 0x1C, 0x8F, 0xDD, 0xEB, 0xBA, 0x06, 0xC0, 0x5A,
    0xCE, 0x8B, 0x64, 0xB8, 0x96, 0x12, 0x8F, 0x6E, 0xED, 0x30, 0x71, 0xFC, 0xF3, 0xDC, 0x16, 0x94,
    0x67, 0x78, 0xE0, 0x72, 0x23, 0x23, 0x3F, 0xD1, 0x80, 0xFC, 0x40, 0xCC, 0xDB, 0x84, 0x30, 0xA6,
    0x40, 0xE3, 0x76, 0x34, 0x27, 0x1E, 0x65, 0x5C, 0xA1, 0x67, 0x4E, 0xBF, 0xF5, 0x07, 0xF8, 0xCB ]/*,
	64*/
],

   /* 512-bits, leading set of second byte */
[
  [ 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ],
  [ 0x35, 0x7B, 0x42, 0xEA, 0x79, 0xBC, 0x97, 0x86, 0x97, 0x5A, 0x3C, 0x44, 0x70, 0xAA, 0xB2, 0x3E,
    0x62, 0x29, 0x79, 0x7B, 0xAD, 0xBD, 0x54, 0x36, 0x5B, 0x54, 0x96, 0xE5, 0x5D, 0x9D, 0xD7, 0x9F,
    0xE9, 0x62, 0x4F, 0xB4, 0x22, 0x66, 0x93, 0x0A, 0x62, 0x8E, 0xD4, 0xDB, 0x08, 0xF9, 0xDD, 0x35,
    0xEF, 0x1B, 0xE1, 0x04, 0x53, 0xFC, 0x18, 0xF4, 0x2C, 0x7F, 0x5E, 0x1F, 0x9B, 0xAE, 0x55, 0xE0 ]/*,
	64*/
],

   /* 512-bits, leading set of last byte */
[
  [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80 ],
  [ 0x8B, 0x39, 0x04, 0xDD, 0x19, 0x81, 0x41, 0x26, 0xFD, 0x02, 0x74, 0xAB, 0x49, 0xC5, 0x97, 0xF6,
    0xD7, 0x75, 0x33, 0x52, 0xA2, 0xDD, 0x91, 0xFD, 0x8F, 0x9F, 0x54, 0x05, 0x4C, 0x54, 0xBF, 0x0F,
    0x06, 0xDB, 0x4F, 0xF7, 0x08, 0xA3, 0xA2, 0x8B, 0xC3, 0x7A, 0x92, 0x1E, 0xEE, 0x11, 0xED, 0x7B,
    0x6A, 0x53, 0x79, 0x32, 0xCC, 0x5E, 0x94, 0xEE, 0x1E, 0xA6, 0x57, 0x60, 0x7E, 0x36, 0xC9, 0xF7 ]/*,
	64*/
],
	];

	for (var i = 0; i < testVectors.length; i++) {
		var vector = testVectors[i];

		var m = Buffer.from(vector[0]);
		var expected = typeof vector[1] == 'string' ? Buffer.from(vector[1].replace(/[ \:]/g, ''), 'hex') : Buffer.from(vector[1]);
		var repeat = typeof vector[2] == 'undefined' ? 1 : vector[2];

		var md = jCastle.digest.create('whirlpool');

		md.start();

		for (var j = 0; j < repeat; j++) {
			md.update(m);
		}

		var h = md.finalize();

		assert.ok(h.equals(expected), "Message Digest test passed!");
	}
});

QUnit.module('HAVAL');
QUnit.test("Vector Test", function(assert) {

	var message = "";
	var testVectors = [
		{
			hash_name: "haval-128,3",
			expected: "c68f39913f901f3ddf44c707357a7d70"
		},
		{
			hash_name: "haval-160,3",
			expected: "d353c3ae22a25401d257643836d7231a9a95f953"
		},
		{
			hash_name: "haval-192,3",
			expected: "e9c48d7903eaf2a91c5b350151efcb175c0fc82de2289a4e"
		},
		{
			hash_name: "haval-224,3",
			expected: "c5aae9d47bffcaaf84a8c6e7ccacd60a0dd1932be7b1a192b9214b6d"
		},
		{
			hash_name: "haval-256,3",
			expected: "4f6938531f0bc8991f62da7bbd6f7de3fad44562b8c6f4ebf146d5b4e46f7c17"
		},
		{
			hash_name: "haval-128,4",
			expected: "ee6bbf4d6a46a679b3a856c88538bb98"
		},
		{
			hash_name: "haval-160,4",
			expected: "1d33aae1be4146dbaaca0b6e70d7a11f10801525"
		},
		{
			hash_name: "haval-192,4",
			expected: "4a8372945afa55c7dead800311272523ca19d42ea47b72da"
		},
		{
			hash_name: "haval-224,4",
			expected: "3e56243275b3b81561750550e36fcd676ad2f5dd9e15f2e89e6ed78e"
		},
		{
			hash_name: "haval-256,4",
			expected: "c92b2e23091e80e375dadce26982482d197b1a2521be82da819f8ca2c579b99b"
		},
		{
			hash_name: "haval-128,5",
			expected: "184b8482a0c050dca54b59c7f05bf5dd"
		},
		{
			hash_name: "haval-160,5",
			expected: "255158cfc1eed1a7be7c55ddd64d9790415b933b"
		},
		{
			hash_name: "haval-192,5",
			expected: "4839d0626f95935e17ee2fc4509387bbe2cc46cb382ffe85"
		},
		{
			hash_name: "haval-224,5",
			expected: "4a0513c032754f5582a758d35917ac9adf3854219b39e3ac77d1837e"
		},
		{
			hash_name: "haval-256,5",
			expected: "be417bb4dd5cfb76c7126f4f8eeb1553a449039307b1a3cd451dbfdc0fbbe330"
		}
	];

	for (var i = 0; i < testVectors.length; i++) {
		var vector = testVectors[i];

		var hash_name = vector.hash_name;
		var expected = vector.expected.replace(/[ \:]/g, '');
		var repeat = typeof vector.repeat == 'undefined' ? 1 : vector.repeat;

		var md = jCastle.digest.create(hash_name);

		md.start({encoding: 'hex'});

		for (var j = 0; j < repeat; j++) {
			md.update(message);
		}

		var h = md.finalize();

		assert.ok(h == expected, "Message Digest test passed!");
	}

	message = "abc";
	testVectors = [
		{
			hash_name: "haval-128,3",
			expected: "9e40ed883fb63e985d299b40cda2b8f2"
		},
		{
			hash_name: "haval-160,3",
			expected: "b21e876c4d391e2a897661149d83576b5530a089"
		},
		{
			hash_name: "haval-192,3",
			expected: "a7b14c9ef3092319b0e75e3b20b957d180bf20745629e8de"
		},
		{
			hash_name: "haval-224,3",
			expected: "5bc955220ba2346a948d2848eca37bdd5eca6ecca7b594bd32923fab"
		},
		{
			hash_name: "haval-256,3",
			expected: "8699f1e3384d05b2a84b032693e2b6f46df85a13a50d93808d6874bb8fb9e86c"
		},
		{
			hash_name: "haval-128,4",
			expected: "6f2132867c9648419adcd5013e532fa2"
		},
		{
			hash_name: "haval-160,4",
			expected: "77aca22f5b12cc09010afc9c0797308638b1cb9b"
		},
		{
			hash_name: "haval-192,4",
			expected: "7e29881ed05c915903dd5e24a8e81cde5d910142ae66207c"
		},
		{
			hash_name: "haval-224,4",
			expected: "124c43d2ba4884599d013e8c872bfea4c88b0b6bf6303974cbe04e68"
		},
		{
			hash_name: "haval-256,4",
			expected: "8f409f1bb6b30c5016fdce55f652642261575bedca0b9533f32f5455459142b5"
		},
		{
			hash_name: "haval-128,5",
			expected: "d054232fe874d9c6c6dc8e6a853519ea"
		},
		{
			hash_name: "haval-160,5",
			expected: "ae646b04845e3351f00c5161d138940e1fa0c11c"
		},
		{
			hash_name: "haval-192,5",
			expected: "d12091104555b00119a8d07808a3380bf9e60018915b9025"
		},
		{
			hash_name: "haval-224,5",
			expected: "8081027a500147c512e5f1055986674d746d92af4841abeb89da64ad"
		},
		{
			hash_name: "haval-256,5",
			expected: "976cd6254c337969e5913b158392a2921af16fca51f5601d486e0a9de01156e7"
		}
	];

	for (var i = 0; i < testVectors.length; i++) {
		var vector = testVectors[i];

		var hash_name = vector.hash_name;
		var expected = vector.expected.replace(/[ \:]/g, '');
		var repeat = typeof vector.repeat == 'undefined' ? 1 : vector.repeat;

		var md = jCastle.digest.create(hash_name);

		md.start({encoding: 'hex'});

		for (var j = 0; j < repeat; j++) {
			md.update(message);
		}

		var h = md.finalize();

		assert.ok(h == expected, "Message Digest test passed!");
	}

	message = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMOPQRSTUVWXYZ0123456789";
	testVectors = [
		{
			hash_name: "haval-128,3",
			expected: "ddf4304cc5ffa3db8aab60d4f8fc2a00"
		},
		{
			hash_name: "haval-160,3",
			expected: "e709559359b15917623050e41d27a306c6c3a9db"
		},
		{
			hash_name: "haval-192,3",
			expected: "51e25280ad356c06f4b913b3cdb3abaaac5879dda0a4fea4"
		},
		{
			hash_name: "haval-224,3",
			expected: "28aa2c164e10bb3076574cc8aa8584fd6d04f6d82c37ea5c21e451b3"
		},
		{
			hash_name: "haval-256,3",
			expected: "5537364e3d75174b846d21adf9b113f9d8f97e4750df64d428c01e782f9ade4d"
		},
		{
			hash_name: "haval-128,4",
			expected: "c7d981e8270e39888ba96cafe8745636"
		},
		{
			hash_name: "haval-160,4",
			expected: "3444e38cc2a132b818b554ced8f7d9592df28f57"
		},
		{
			hash_name: "haval-192,4",
			expected: "0ca58f140ed92828a27913ce5636611abcada220fccf3af7"
		},
		{
			hash_name: "haval-224,4",
			expected: "a9d0571d0857773e71363e4e9dfcca4696dba3e5019e7225e65e0cb1"
		},
		{
			hash_name: "haval-256,4",
			expected: "1858d106bdc2fc787445364a163cfc6027597a45a58a2490d14203c8b9bdd268"
		},
		{
			hash_name: "haval-128,5",
			expected: "d41e927ea041d2f0c255352b1a9f6195"
		},
		{
			hash_name: "haval-160,5",
			expected: "f3245e222e6581d0c3077bd7af322af4b4fedab7"
		},
		{
			hash_name: "haval-192,5",
			expected: "fc45dc17a7b19adfed2a6485921f7af7951d70703b9357c1"
		},
		{
			hash_name: "haval-224,5",
			expected: "29687958a6f0d54d495105df00dbda0153ee0f5708408db68a5bbea5"
		},
		{
			hash_name: "haval-256,5",
			expected: "f93421623f852ac877584d1e4bba5d9345a95f81bfd277fe36dfeed1815f83d5"
		}
	];

	for (var i = 0; i < testVectors.length; i++) {
		var vector = testVectors[i];

		var hash_name = vector.hash_name;
		var expected = vector.expected.replace(/[ \:]/g, '');
		var repeat = typeof vector.repeat == 'undefined' ? 1 : vector.repeat;

		var md = jCastle.digest.create(hash_name);

		md.start({encoding: 'hex'});

		for (var j = 0; j < repeat; j++) {
			md.update(message);
		}

		var h = md.finalize();

		assert.ok(h == expected, "Message Digest test passed!");
	}
});

QUnit.module('GOST3411');
QUnit.test("Vector Test", function(assert) {

	var testVectors = [
		[
			"",
			" ce85b99cc46752fffee35cab9a7b0278abb4c2d2055cff685af4912c49490f8d"
		],
		[
			"abc",
			"f3134348c44fb1b2a277729e2285ebb5cb5e0f29c975bc753b70497c06a4d51d"
		],
		[	
			"message digest",
			"ad4434ecb18f2c99b60cbe59ec3d2469582b65273f48de72db2fde16a4889a4d"
		],
		[
			"This is message, length=32 bytes",
			"b1c466d37519b82e8319819ff32595e047a28cb6f83eff1c6916a815a637fffa"
		],
	];

	for (var i = 0; i < testVectors.length; i++) {
		var vector = testVectors[i];

		var m = Buffer.from(vector[0]);
		var expected = Buffer.from(vector[1].replace(/[ \:]/g, ''), 'hex');
		var repeat = typeof vector[2] == 'undefined' ? 1 : vector[2];

		var md = jCastle.digest.create('gost3411');

		md.start();

		for (var j = 0; j < repeat; j++) {
			md.update(m);
		}

		var h = md.finalize();
		
		assert.ok(h.equals(expected), "Message Digest test passed!");
	}
});

QUnit.module('SHA3-224');
QUnit.test("Vector Test", function(assert) {
	var testVectors = [
		[
			"",
			"6b4e03423667dbb7 3b6e15454f0eb1ab d4597f9a1b078e3f 5b5a6bc7"
		],
		[
			"abc",
			"e642824c3f8cf24a d09234ee7d3c766f c9a3a5168d0c94ad 73b46fdf"
		],
		[	
			"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
			"8a24108b154ada21 c9fd5574494479ba 5c7e7ab76ef264ea d0fcce33"
		],
		[
			"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
			"543e6868e1666c1a 643630df77367ae5 a62a85070a51c14c bf665cbc"
		],/*
		[
			"a",
			"d69335b93325192e 516a912e6d19a15c b51c6ed5c15243e7 a7fd653c",
			1000000
		]*/
	];

	for (var i = 0; i < testVectors.length; i++) {
		var vector = testVectors[i];

		var m = Buffer.from(vector[0]);
		var expected = Buffer.from(vector[1].replace(/[ \:]/g, ''), 'hex');
		var repeat = typeof vector[2] == 'undefined' ? 1 : vector[2];

		var md = jCastle.digest.create('sha3-224');

		md.start();

		for (var j = 0; j < repeat; j++) {
			md.update(m);
		}

		var h = md.finalize();

		assert.ok(h.equals(expected), "Message Digest test passed!");
	}
});

QUnit.module('SHA3-256');
QUnit.test("Vector Test", function(assert) {
	var testVectors = [
		[
			"",
			"a7ffc6f8bf1ed766 51c14756a061d662 f580ff4de43b49fa 82d80a4b80f8434a"
		],
		[
			"abc",
			"3a985da74fe225b2 045c172d6bd390bd 855f086e3e9d525b 46bfe24511431532"
		],
		[	
			"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
			"41c0dba2a9d62408 49100376a8235e2c 82e1b9998a999e21 db32dd97496d3376"
		],
		[
			"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
			"916f6061fe879741 ca6469b43971dfdb 28b1a32dc36cb325 4e812be27aad1d18"
		],/*
		[
			"a",
			"5c8875ae474a3634 ba4fd55ec85bffd6 61f32aca75c6d699 d0cdcb6c115891c1",
			1000000
		]*/
	];

	for (var i = 0; i < testVectors.length; i++) {
		var vector = testVectors[i];

		var m = Buffer.from(vector[0]);
		var expected = Buffer.from(vector[1].replace(/[ \:]/g, ''), 'hex');
		var repeat = typeof vector[2] == 'undefined' ? 1 : vector[2];

		var md = jCastle.digest.create('sha3-256');

		md.start();

		for (var j = 0; j < repeat; j++) {
			md.update(m);
		}

		var h = md.finalize();

		assert.ok(h.equals(expected), "Message Digest test passed!");
	}
});

QUnit.module('SHA3-384');
QUnit.test("Vector Test", function(assert) {
	var testVectors = [
		[
			"",
			"0c63a75b845e4f7d 01107d852e4c2485 c51a50aaaa94fc61 995e71bbee983a2a c3713831264adb47 fb6bd1e058d5f004"
		],
		[
			"abc",
			"ec01498288516fc9 26459f58e2c6ad8d f9b473cb0fc08c25 96da7cf0e49be4b2 98d88cea927ac7f5 39f1edf228376d25"
		],
		[	
			"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
			"991c665755eb3a4b 6bbdfb75c78a492e 8c56a22c5c4d7e42 9bfdbc32b9d4ad5a a04a1f076e62fea1 9eef51acd0657c22"
		],
		[
			"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
			"79407d3b5916b59c 3e30b09822974791 c313fb9ecc849e40 6f23592d04f625dc 8c709b98b43b3852 b337216179aa7fc7"
		],/*
		[
			"a",
			"eee9e24d78c18553 37983451df97c8ad 9eedf256c6334f8e 948d252d5e0e7684 7aa0774ddb90a842 190d2c558b4b8340",
			1000000
		]*/
	];

	for (var i = 0; i < testVectors.length; i++) {
		var vector = testVectors[i];

		var m = Buffer.from(vector[0]);
		var expected = Buffer.from(vector[1].replace(/[ \:]/g, ''), 'hex');
		var repeat = typeof vector[2] == 'undefined' ? 1 : vector[2];

		var md = jCastle.digest.create('sha3-384');

		md.start();

		for (var j = 0; j < repeat; j++) {
			md.update(m);
		}

		var h = md.finalize();

		assert.ok(h.equals(expected), "Message Digest test passed!");
	}
});

QUnit.module('SHA3-512');
QUnit.test("Vector Test", function(assert) {
	var testVectors = [
		[
			"",
			"a69f73cca23a9ac5 c8b567dc185a756e 97c982164fe25859 e0d1dcc1475c80a6 15b2123af1f5f94c 11e3e9402c3ac558 f500199d95b6d3e3 01758586281dcd26"
		],
		[
			"abc",
			"b751850b1a57168a 5693cd924b6b096e 08f621827444f70d 884f5d0240d2712e 10e116e9192af3c9 1a7ec57647e39340 57340b4cf408d5a5 6592f8274eec53f0"
		],
		[	
			"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
			"04a371e84ecfb5b8 b77cb48610fca818 2dd457ce6f326a0f d3d7ec2f1e91636d ee691fbe0c985302 ba1b0d8dc78c0863 46b533b49c030d99 a27daf1139d6e75e"
		],
		[
			"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
			"afebb2ef542e6579 c50cad06d2e578f9 f8dd6881d7dc824d 26360feebf18a4fa 73e3261122948efc fd492e74e82e2189 ed0fb440d187f382 270cb455f21dd185"
		],/*
		[
			"a",
			"3c3a876da14034ab 60627c077bb98f7e 120a2a5370212dff b3385a18d4f38859 ed311d0a9d5141ce 9cc5c66ee689b266 a8aa18ace8282a0e 0db596c90b0a7b87",
			1000000
		]*/
	];

	for (var i = 0; i < testVectors.length; i++) {
		var vector = testVectors[i];

		var m = Buffer.from(vector[0]);
		var expected = Buffer.from(vector[1].replace(/[ \:]/g, ''), 'hex');
		var repeat = typeof vector[2] == 'undefined' ? 1 : vector[2];

		var md = jCastle.digest.create('sha3-512');

		md.start();

		for (var j = 0; j < repeat; j++) {
			md.update(m);
		}

		var h = md.finalize();

		assert.ok(h.equals(expected), "Message Digest test passed!");
	}
});

QUnit.module('Shake');
QUnit.test("Vector Test", function(assert) {

	var testVectors = [
		['shake-128/256',"", '7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26'],
		['shake-256/512',"", '46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be'],
		['shake-128/256',"The quick brown fox jumps over the lazy dog", 'f4202e3c5852f9182a0430fd8144f0a74b95e7417ecae17db0f8cfeed0e3e66e']
	];

	for (var i = 0; i < testVectors.length; i++) {
		var vector = testVectors[i];

		var m = Buffer.from(vector[1]);
		var expected = Buffer.from(vector[2].replace(/[ \:]/g, ''), 'hex');
		var repeat = 1;
		var algo_name = vector[0];

		var md = jCastle.digest.create(algo_name);

		md.start();

		for (var j = 0; j < repeat; j++) {
			md.update(m);
		}

		var h = md.finalize();

		assert.ok(h.equals(expected), "Message Digest test passed!");
	}
});

QUnit.module('Skein-256/512/1024');
QUnit.test("Vector Test", function(assert) {

	var testVectors = [
		[256, 256, "", "c8877087da56e072870daa843f176e9453115929094c3a40c463a196c29bf7ba"],
		[256, 256, "fb", "088eb23cc2bccfb8171aa64e966d4af937325167dfcd170700ffd21f8a4cbdac"],
		[256, 256, "fbd17c26b61a82e12e125f0d459b96c91ab4837dff22b39b78439430cdfc5dc8",
					"5c3002ff57a627089ea2f97a5000d5678416389019e80e45a3bbcab118315d26"],
		[256, 256, "fbd17c26b61a82e12e125f0d459b96c91ab4837dff22b39b78439430cdfc5dc8"
					+ "78bb393a1a5f79bef30995a85a129233",
					"640c894a4bba6574c83e920ddf7dd2982fc634881bbbcb9d774eae0a285e89ce"],
		[256, 160, "fbd17c26b61a82e12e125f0d459b96c91ab4837dff22b39b78439430cdfc5dc8"
					+ "78bb393a1a5f79bef30995a85a12923339ba8ab7d8fc6dc5fec6f4ed22c122bb"
					+ "e7eb61981892966de5cef576f71fc7a80d14dab2d0c03940b95b9fb3a727c66a"
					+ "6e1ff0dc311b9aa21a3054484802154c1826c2a27a0914152aeb76f1168d4410",
					"0cd491b7715704c3a15a45a1ca8d93f8f646d3a1"],
		[256, 224, "fbd17c26b61a82e12e125f0d459b96c91ab4837dff22b39b78439430cdfc5dc8"
					+ "78bb393a1a5f79bef30995a85a12923339ba8ab7d8fc6dc5fec6f4ed22c122bb"
					+ "e7eb61981892966de5cef576f71fc7a80d14dab2d0c03940b95b9fb3a727c66a"
					+ "6e1ff0dc311b9aa21a3054484802154c1826c2a27a0914152aeb76f1168d4410",
					"afd1e2d0f5b6cd4e1f8b3935fa2497d27ee97e72060adac099543487"],
		[256, 256, "fbd17c26b61a82e12e125f0d459b96c91ab4837dff22b39b78439430cdfc5dc8"
					+ "78bb393a1a5f79bef30995a85a12923339ba8ab7d8fc6dc5fec6f4ed22c122bb"
					+ "e7eb61981892966de5cef576f71fc7a80d14dab2d0c03940b95b9fb3a727c66a"
					+ "6e1ff0dc311b9aa21a3054484802154c1826c2a27a0914152aeb76f1168d4410",
					"4de6fe2bfdaa3717a4261030ef0e044ced9225d066354610842a24a3eafd1dcf"],
		[256, 384, "fbd17c26b61a82e12e125f0d459b96c91ab4837dff22b39b78439430cdfc5dc8"
					+ "78bb393a1a5f79bef30995a85a12923339ba8ab7d8fc6dc5fec6f4ed22c122bb"
					+ "e7eb61981892966de5cef576f71fc7a80d14dab2d0c03940b95b9fb3a727c66a"
					+ "6e1ff0dc311b9aa21a3054484802154c1826c2a27a0914152aeb76f1168d4410",
					"954620fb31e8b782a2794c6542827026fe069d715df04261629fcbe81d7d529b"
						+ "95ba021fa4239fb00afaa75f5fd8e78b"],
		[256, 512, "fbd17c26b61a82e12e125f0d459b96c91ab4837dff22b39b78439430cdfc5dc8"
					+ "78bb393a1a5f79bef30995a85a12923339ba8ab7d8fc6dc5fec6f4ed22c122bb"
					+ "e7eb61981892966de5cef576f71fc7a80d14dab2d0c03940b95b9fb3a727c66a"
					+ "6e1ff0dc311b9aa21a3054484802154c1826c2a27a0914152aeb76f1168d4410",
					"51347e27c7eabba514959f899a6715ef6ad5cf01c23170590e6a8af399470bf9"
						+ "0ea7409960a708c1dbaa90e86389df254abc763639bb8cdf7fb663b29d9557c3"],
		[256, 1024, "fbd17c26b61a82e12e125f0d459b96c91ab4837dff22b39b78439430cdfc5dc8"
					+ "78bb393a1a5f79bef30995a85a12923339ba8ab7d8fc6dc5fec6f4ed22c122bb"
					+ "e7eb61981892966de5cef576f71fc7a80d14dab2d0c03940b95b9fb3a727c66a"
					+ "6e1ff0dc311b9aa21a3054484802154c1826c2a27a0914152aeb76f1168d4410",
					"6c9b6facbaf116b538aa655e0be0168084aa9f1be445f7e06714585e5999a6c9"
						+ "84fffa9d41a316028692d4aad18f573fbf27cf78e84de26da1928382b023987d"
						+ "cfe002b6201ea33713c54a8a5d9eb346f0365e04330d2faaf7bc8aba92a5d7fb"
						+ "6345c6fb26750bce65ab2045c233627679ac6e9acb33602e26fe3526063ecc8b"],

		[512, 512, "", "bc5b4c50925519c290cc634277ae3d6257212395cba733bbad37a4af0fa06af4"
					+ "1fca7903d06564fea7a2d3730dbdb80c1f85562dfcc070334ea4d1d9e72cba7a"],
		[512, 512, "fb", "c49e03d50b4b2cc46bd3b7ef7014c8a45b016399fd1714467b7596c86de98240"
					+ "e35bf7f9772b7d65465cd4cffab14e6bc154c54fc67b8bc340abf08eff572b9e"],
		[512, 512, "fbd17c26b61a82e12e125f0d459b96c91ab4837dff22b39b78439430cdfc5dc8",
					"abefb179d52f68f86941acbbe014cc67ec66ad78b7ba9508eb1400ee2cbdb06f"
						+ "9fe7c2a260a0272d0d80e8ef5e8737c0c6a5f1c02ceb00fb2746f664b85fcef5"],
		[512, 512, "fbd17c26b61a82e12e125f0d459b96c91ab4837dff22b39b78439430cdfc5dc8"
					+ "78bb393a1a5f79bef30995a85a129233",
					"5c5b7956f9d973c0989aa40a71aa9c48a65af2757590e9a758343c7e23ea2df4"
						+ "057ce0b49f9514987feff97f648e1dd065926e2c371a0211ca977c213f14149f"],
		[512, 160, "fbd17c26b61a82e12e125f0d459b96c91ab4837dff22b39b78439430cdfc5dc8"
					+ "78bb393a1a5f79bef30995a85a12923339ba8ab7d8fc6dc5fec6f4ed22c122bb"
					+ "e7eb61981892966de5cef576f71fc7a80d14dab2d0c03940b95b9fb3a727c66a"
					+ "6e1ff0dc311b9aa21a3054484802154c1826c2a27a0914152aeb76f1168d4410",
					"ef03079d61b57c6047e15fa2b35b46fa24279539"],
		[512, 224, "fbd17c26b61a82e12e125f0d459b96c91ab4837dff22b39b78439430cdfc5dc8"
					+ "78bb393a1a5f79bef30995a85a12923339ba8ab7d8fc6dc5fec6f4ed22c122bb"
					+ "e7eb61981892966de5cef576f71fc7a80d14dab2d0c03940b95b9fb3a727c66a"
					+ "6e1ff0dc311b9aa21a3054484802154c1826c2a27a0914152aeb76f1168d4410",
					"d9e3219b214e15246a2038f76a573e018ef69b385b3bd0576b558231"],
		[512, 256, "fbd17c26b61a82e12e125f0d459b96c91ab4837dff22b39b78439430cdfc5dc8"
					+ "78bb393a1a5f79bef30995a85a12923339ba8ab7d8fc6dc5fec6f4ed22c122bb"
					+ "e7eb61981892966de5cef576f71fc7a80d14dab2d0c03940b95b9fb3a727c66a"
					+ "6e1ff0dc311b9aa21a3054484802154c1826c2a27a0914152aeb76f1168d4410",
					"809dd3f763a11af90912bbb92bc0d94361cbadab10142992000c88b4ceb88648"],
		[512, 384, "fbd17c26b61a82e12e125f0d459b96c91ab4837dff22b39b78439430cdfc5dc8"
					+ "78bb393a1a5f79bef30995a85a12923339ba8ab7d8fc6dc5fec6f4ed22c122bb"
					+ "e7eb61981892966de5cef576f71fc7a80d14dab2d0c03940b95b9fb3a727c66a"
					+ "6e1ff0dc311b9aa21a3054484802154c1826c2a27a0914152aeb76f1168d4410",
					"825f5cbd5da8807a7b4d3e7bd9cd089ca3a256bcc064cd73a9355bf3ae67f2bf"
						+ "93ac7074b3b19907a0665ba3a878b262"],
		[512, 512, "fbd17c26b61a82e12e125f0d459b96c91ab4837dff22b39b78439430cdfc5dc8"
					+ "78bb393a1a5f79bef30995a85a12923339ba8ab7d8fc6dc5fec6f4ed22c122bb"
					+ "e7eb61981892966de5cef576f71fc7a80d14dab2d0c03940b95b9fb3a727c66a"
					+ "6e1ff0dc311b9aa21a3054484802154c1826c2a27a0914152aeb76f1168d4410",
					"1a0d5abf4432e7c612d658f8dcfa35b0d1ab68b8d6bd4dd115c23cc57b5c5bcd"
						+ "de9bff0ece4208596e499f211bc07594d0cb6f3c12b0e110174b2a9b4b2cb6a9"],

		[1024, 1024, "", "0fff9563bb3279289227ac77d319b6fff8d7e9f09da1247b72a0a265cd6d2a62"
					+ "645ad547ed8193db48cff847c06494a03f55666d3b47eb4c20456c9373c86297"
					+ "d630d5578ebd34cb40991578f9f52b18003efa35d3da6553ff35db91b81ab890"
					+ "bec1b189b7f52cb2a783ebb7d823d725b0b4a71f6824e88f68f982eefc6d19c6"],
		[1024, 1024, "fb", "6426bdc57b2771a6ef1b0dd39f8096a9a07554565743ac3de851d28258fcff22"
					+ "9993e11c4e6bebc8b6ecb0ad1b140276081aa390ec3875960336119427827473"
					+ "4770671b79f076771e2cfdaaf5adc9b10cbae43d8e6cd2b1c1f5d6c82dc96618"
					+ "00ddc476f25865b8748253173187d81da971c027d91d32fb390301c2110d2db2"],
		[1024, 1024, "fbd17c26b61a82e12e125f0d459b96c91ab4837dff22b39b78439430cdfc5dc8",
					"140e93726ab0b0467c0b8a834ad8cda4d1769d273661902b70db0dcb5ee692ac"
						+ "b3f852d03b11f857850f2428432811309c1dcbe5724f00267ea3667e89fadb4e"
						+ "4911da6b0ba8a7eddf87c1c67152ef0f07b7fead3557318478bdef5ad1e5926d"
						+ "7071fdd4bfa5076d4b3253f8de479ebdf5357676f1641b2f097e9b785e9e528e"],
		[1024, 1024, "fbd17c26b61a82e12e125f0d459b96c91ab4837dff22b39b78439430cdfc5dc8"
					+ "78bb393a1a5f79bef30995a85a129233",
					"31105e1ef042c30b95b16e0f6e6a1a19172bb7d54a0597dd0c711194888efe1d"
						+ "bce82d47416df9577ca387219f06e45cd10964ff36f6711edbbea0e9595b0f66"
						+ "f72b755d70a46857e0aec98561a743d49370d8e572e212811273125f66cc30bf"
						+ "117d3221894c48012bf6e2219de91e064b01523517420a1e00f71c4cc04bab62"],
		[1024, 160, "fbd17c26b61a82e12e125f0d459b96c91ab4837dff22b39b78439430cdfc5dc8"
					+ "78bb393a1a5f79bef30995a85a12923339ba8ab7d8fc6dc5fec6f4ed22c122bb"
					+ "e7eb61981892966de5cef576f71fc7a80d14dab2d0c03940b95b9fb3a727c66a"
					+ "6e1ff0dc311b9aa21a3054484802154c1826c2a27a0914152aeb76f1168d4410",
					"2e6a4cbf2ef05ea9c24b93e8d1de732ddf2739eb"],
		[1024, 224, "fbd17c26b61a82e12e125f0d459b96c91ab4837dff22b39b78439430cdfc5dc8"
					+ "78bb393a1a5f79bef30995a85a12923339ba8ab7d8fc6dc5fec6f4ed22c122bb"
					+ "e7eb61981892966de5cef576f71fc7a80d14dab2d0c03940b95b9fb3a727c66a"
					+ "6e1ff0dc311b9aa21a3054484802154c1826c2a27a0914152aeb76f1168d4410",
					"1d6de19f37f7a3c265440eecb4b9fbd3300bb5ac60895cfc0d4d3c72"],
		[1024, 256, "fbd17c26b61a82e12e125f0d459b96c91ab4837dff22b39b78439430cdfc5dc8"
					+ "78bb393a1a5f79bef30995a85a12923339ba8ab7d8fc6dc5fec6f4ed22c122bb"
					+ "e7eb61981892966de5cef576f71fc7a80d14dab2d0c03940b95b9fb3a727c66a"
					+ "6e1ff0dc311b9aa21a3054484802154c1826c2a27a0914152aeb76f1168d4410",
					"986a4d472b123e8148731a8eac9db23325f0058c4ccbc44a5bb6fe3a8db672d7"],
		[1024, 384, "fbd17c26b61a82e12e125f0d459b96c91ab4837dff22b39b78439430cdfc5dc8"
					+ "78bb393a1a5f79bef30995a85a12923339ba8ab7d8fc6dc5fec6f4ed22c122bb"
					+ "e7eb61981892966de5cef576f71fc7a80d14dab2d0c03940b95b9fb3a727c66a"
					+ "6e1ff0dc311b9aa21a3054484802154c1826c2a27a0914152aeb76f1168d4410",
					"9c3d0648c11f31c18395d5e6c8ebd73f43d189843fc45235e2c35e345e12d62b"
						+ "c21a41f65896ddc6a04969654c2e2ce9"],
		[1024, 512, "fbd17c26b61a82e12e125f0d459b96c91ab4837dff22b39b78439430cdfc5dc8"
					+ "78bb393a1a5f79bef30995a85a12923339ba8ab7d8fc6dc5fec6f4ed22c122bb"
					+ "e7eb61981892966de5cef576f71fc7a80d14dab2d0c03940b95b9fb3a727c66a"
					+ "6e1ff0dc311b9aa21a3054484802154c1826c2a27a0914152aeb76f1168d4410",
					"5d0416f49c2d08dfd40a1446169dc6a1d516e23b8b853be4933513051de8d5c2"
						+ "6baccffb08d3b16516ba3c6ccf3e9a6c78fff6ef955f2dbc56e1459a7cdba9a5"],
		[1024, 1024, "fbd17c26b61a82e12e125f0d459b96c91ab4837dff22b39b78439430cdfc5dc8"
					+ "78bb393a1a5f79bef30995a85a12923339ba8ab7d8fc6dc5fec6f4ed22c122bb"
					+ "e7eb61981892966de5cef576f71fc7a80d14dab2d0c03940b95b9fb3a727c66a"
					+ "6e1ff0dc311b9aa21a3054484802154c1826c2a27a0914152aeb76f1168d4410",
					"96ca81f586c825d0360aef5acaec49ad55289e1797072eee198b64f349ce65b6"
						+ "e6ed804fe38f05135fe769cc56240ddda5098f620865ce4a4278c77fa2ec6bc3"
						+ "1c0f354ca78c7ca81665bfcc5dc54258c3b8310ed421d9157f36c093814d9b25"
						+ "103d83e0ddd89c52d0050e13a64c6140e6388431961685734b1f138fe2243086"]
	];

	for (var i = 0; i < testVectors.length; i++) {
		var vector = testVectors[i];
		// blockSize, outputSize, message, digest

		var block_bitlen = vector[0];
		var output_bitlen = vector[1];
		var m = Buffer.from(vector[2], 'hex');
		var expected = Buffer.from(vector[3].replace(/[ \:]/g, ''), 'hex');
		var repeat = 1;

		var md = jCastle.digest.create('skein-'+block_bitlen);

		md.start({outputBits: output_bitlen}); // important!

		for (var j = 0; j < repeat; j++) {
			md.update(m);
		}

		var h = md.finalize();

		assert.ok(h.equals(expected), "Message Digest test passed!");
	}
});

QUnit.module('CRC32');
QUnit.test("Vector Test", function(assert) {
	var testVectors = [
		[
			"",
			"00000000"
		],
		[
			"a",
			"e8b7be43"
		],
		[
			"abc",
			"352441c2"
		],
		[	
			"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
			"171a3f5f"
		],
		[
			"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
			"191f3349"
		],
		[
			"123456789",
			"cbf43926"
		]
	];

	// https://stackoverflow.com/questions/18638900/javascript-crc32
	var crc32 = (function()
	{
		var table = new Uint32Array(256);

		// Pre-generate crc32 polynomial lookup table
		// http://wiki.osdev.org/CRC32#Building_the_Lookup_Table
		// ... Actually use Alex's because it generates the correct bit order
		//     so no need for the reversal function
		for(var i=256; i--;)
		{
			var tmp = i;

			for(var k=8; k--;)
			{
				tmp = tmp & 1 ? 3988292384 ^ tmp >>> 1 : tmp >>> 1;
			}

			table[i] = tmp;
		}

		// crc32b
		// Example input        : [97, 98, 99, 100, 101] (Uint8Array)
		// Example output       : 2240272485 (Uint32)
		return function( data )
		{
			var crc = -1; // Begin with all bits set ( 0xffffffff )

			for(var i=0, l=data.length; i<l; i++)
			{
				crc = crc >>> 8 ^ table[ crc & 255 ^ data[i] ];
			}

			return (crc ^ -1) >>> 0; // Apply binary NOT
		};

	})();

	for (var i = 0; i < testVectors.length; i++) {
		var vector = testVectors[i];

		var m = Buffer.from(vector[0]);
		var expected = Buffer.from(vector[1].replace(/[ \:]/g, ''), 'hex');

		var md = jCastle.digest.create('crc32');

		md.start();

		md.update(m);

		var h = md.finalize();
//console.log(h.toString('hex'));
//console.log(expected.toString('hex'));
//console.log(crc32(m).toString(16));

		assert.ok(h.equals(expected), "Message Digest test passed!");
	}
});