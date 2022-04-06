const QUnit = require('qunit');
const jCastle = require('../lib/index');

QUnit.module('CMac');
QUnit.test("Vector Test", function(assert) {


	// http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/omac/omac-tv.pdf

	var testVectors = [
		[
			128,
			'2b7e1516 28aed2a6 abf71588 09cf4f3c',
			'',
			'bb1d6929 e9593728 7fa37d12 9b756746'
		],
		[
			128,
			'2b7e1516 28aed2a6 abf71588 09cf4f3c', 
			'6bc1bee2 2e409f96 e93d7e11 7393172a', 
			'070a16b4 6b4d4144 f79bdd9d d04a287c'
		],
		[
			128, 
			'2b7e1516 28aed2a6 abf71588 09cf4f3c',
			'6bc1bee2 2e409f96 e93d7e11 7393172a'+
			'ae2d8a57 1e03ac9c 9eb76fac 45af8e51'+
			'30c81c46 a35ce411',
			'dfa66747 de9ae630 30ca3261 1497c827'
		],
		[
			128,
			'2b7e1516 28aed2a6 abf71588 09cf4f3c',
			'6bc1bee2 2e409f96 e93d7e11 7393172a'+
			'ae2d8a57 1e03ac9c 9eb76fac 45af8e51'+
			'30c81c46 a35ce411 e5fbc119 1a0a52ef'+
			'f69f2445 df4f9b17 ad2b417b e66c3710',
			'51f0bebf 7e3b9d92 fc497417 79363cfe'
		]
	];

	// aes_type, key, cleartext, ep_tag
	for (var i = 0; i < testVectors.length; i++) {
		var vector = testVectors[i];

		var key = Buffer.from(vector[1].replace(/[ \:]/g, ''), 'hex');
		var pt = Buffer.from(vector[2].replace(/[ \:]/g, ''), 'hex');
		var expected = Buffer.from(vector[3].replace(/[ \:]/g, ''), 'hex');

		var mac = new jCastle.mac('CMac');

		mac.start({
			key: key,
			algorithm: 'aes-128'
		});

		mac.update(pt);

		var tag = mac.finalize();

		assert.ok(tag.equals(expected), 'Mac check passed!');
	}
});

QUnit.module('GMac');
QUnit.test("Vector Test", function(assert) {

	var testVectors = [
		[
			128,
			'00000000000000000000000000000000',
			'000000000000000000000000',
			'', 1,
			'',
			'58e2fccefa7e3061367f1d57a4e7455a'],
		[
			128,
			'2fb45e5b8f993a2bfebc4b15b533e0b4',
			'5b05755f984d2b90f94b8027',
			'e85491b2202caf1d7dce03b97e09331c32473941',
			1,
			'',
			'c75b7832b2a2d9bd827412b6ef5769db'],
		[
			128,
			'99e3e8793e686e571d8285c564f75e2b',
			'c2dd0ab868da6aa8ad9c0d23',
			'b668e42d4e444ca8b23cfdd95a9fedd5178aa521144890b093733cf5cf22526c5917ee476541809ac6867a8c399309fc',
			1,
			'',
			'3f4fba100eaf1f34b0baadaae9995d85'],
		[
			128,
			"11754cd72aec309bf52f7687212e8957",
			"3c819d9a9bed087615030b65",
			"", 1,
			'',
			"250327c674aaf477aef2675748cf6971"],
		[
			128,
			"272f16edb81a7abbea887357a58c1917", 
			"794ec588176c703d3d2a7a07",
			"", 1,
			'',
			"b6e6f197168f5049aeda32dafbdaeb", 15],
		[
			128,
			"81b6844aab6a568c4556a2eb7eae752f", 
			"ce600f59618315a6829bef4d", 
			"", 1,
			'',
			"89b43e9dbc1b4f597dbbc7655bb5", 14],
		[
			128,
			"cde2f9a9b1a004165ef9dc981f18651b",
			"29512c29566c7322e1e33e8e",
			"", 1,
			'',
			"2e58ce7dabd107c82759c66a75", 13],
		[
			128,
			"b01e45cc3088aaba9fa43d81d481823f", 
			"5a2c4a66468713456a4bd5e1",
			"", 1, 
			'',
			 "014280f944f53c681164b2ff", 12],
		[
			128,
			"77be63708971c4e240d1cb79e8d77feb",
			"e0e00f19fed7ba0136a797f3",
			"7a43ec1d9c0a5a78a0b16533a6213cab", 1,
			'',
			"209fcc8d3675ed938e9c7166709dd946"],
		[
			128,
			"bea48ae4980d27f357611014d4486625",
			"32bddb5c3aa998a08556454c",
			"8a50b0b8c7654bced884f7f3afda2ead", 1, 
			'',
			"8e0f6d8bf05ffebe6f500eb1", 12],
		[
			128,
			"99e3e8793e686e571d8285c564f75e2b",
			"c2dd0ab868da6aa8ad9c0d23",
			"b668e42d4e444ca8b23cfdd95a9fedd5178aa521144890b093733cf5cf22526c5917ee476541809ac6867a8c399309fc", 1,
			'',
			"3f4fba100eaf1f34b0baadaae9995d85"],
		[
			128,
			"c77acd1b0918e87053cb3e51651e7013", 
			"39ff857a81745d10f718ac00",
			"407992f82ea23b56875d9a3cb843ceb83fd27cb954f7c5534d58539fe96fb534502a1b38ea4fac134db0a42de4be1137", 1,
			'',
			"2a5dc173285375dc82835876", 12],
		[
			128,
			"d0f1f4defa1e8c08b4b26d576392027c",
			"42b4f01eb9f5a1ea5b1eb73b0fb0baed54f387ecaa0393c7d7dffc6af50146ecc021abf7eb9038d4303d91f8d741a11743166c0860208bcc02c6258fd9511a2fa626f96d60b72fcff773af4e88e7a923506e4916ecbd814651e9f445adef4ad6a6b6c7290cc13b956130eef5b837c939fcac0cbbcc9656cd75b13823ee5acdac",
			"", 1,
			'', 
			"7ab49b57ddf5f62c427950111c5c4f0d"],
		[
			128,
			"3cce72d37933394a8cac8a82deada8f0",
			"aa2f0d676d705d9733c434e481972d4888129cf7ea55c66511b9c0d25a92a174b1e28aa072f27d4de82302828955aadcb817c4907361869bd657b45ff4a6f323871987fcf9413b0702d46667380cd493ed24331a28b9ce5bbfa82d3a6e7679fcce81254ba64abcad14fd18b22c560a9d2c1cd1d3c42dac44c683edf92aced894",
			"5686b458e9c176f4de8428d9ebd8e12f569d1c7595cf49a4b0654ab194409f86c0dd3fdb8eb18033bb4338c70f0b97d1", 1,
			'',
			"a3a9444b21f330c3df64c8b6", 12]
	];

	// aes_type, key, nonce, authdata, repeat, cleartext, ep_tag, tag_size
	for (var i = 0; i < testVectors.length; i++) {
		var vector = testVectors[i];

		var key = Buffer.from(vector[1].replace(/[ \:]/g, ''), 'hex');
		var nonce = Buffer.from(vector[2].replace(/[ \:]/g, ''), 'hex');
		var authdata = Buffer.from(vector[3].replace(/[ \:]/g, ''), 'hex');
		var repeat = vector[4];
		var pt = Buffer.from(vector[5].replace(/[ \:]/g, ''), 'hex');
		var expected = Buffer.from(vector[6].replace(/[ \:]/g, ''), 'hex');
		var tag_size = typeof vector[7] != 'undefined' ? vector[7] : 0;

		var mac = new jCastle.mac('GMac');

		var algo_name = 'aes-128';

		var block_size = jCastle._algorithmInfo[algo_name].block_size;

		mac.start({
			key: key,
			nonce: nonce,
			algorithm: algo_name,
			macSize: tag_size ? tag_size : block_size
		});

		// in GMac all data is treated as additional data, so the pt is zero size array.
		mac.update(authdata);

		var tag = mac.finalize();

		assert.ok(tag.equals(expected), 'Mac check passed!');
	}

});

QUnit.module('VMPC-Mac');
QUnit.test("Vector Test", function(assert) {

	var pt = Buffer.alloc(256);
	for (var i = 0; i < 256; i++) {
		pt[i] = i;
	}

	// key, iv, cleartext, expects
	var key = '9661410AB797D8A9EB767C21172DF6C7';
	var iv = '4B5C2F003E67F39557A8D26F3DA2B155';
	var expected = '9BDA16E2AD0E284774A3ACBC8835A8326C11FAAD';

	key = Buffer.from(key.replace(/[ \:]/g, ''), 'hex');
	iv = Buffer.from(iv.replace(/[ \:]/g, ''), 'hex');
//	pt = Buffer.from(pt.replace(/[ \:]/g, ''), 'hex');
	expected = Buffer.from(expected.replace(/[ \:]/g, ''), 'hex');

	var mac = new jCastle.mac('VMPC-Mac');
	mac.start({
		key: key,
		iv: iv
	});

	mac.update(pt);  // important!
						// All data should be treated as additional data.

	var tag = mac.finalize();

	assert.ok(tag.equals(expected), 'Mac check passed!');
});

QUnit.module('Poly1305-Mac');
QUnit.test("Vector Test", function(assert) {

	var testVectors = [
		{
			input:	'27 54 77 61 73 20 62 72 69 6c 6c 69 67 2c 20 61'+
					'6e 64 20 74 68 65 20 73 6c 69 74 68 79 20 74 6f'+
					'76 65 73 0a 44 69 64 20 67 79 72 65 20 61 6e 64'+
					'20 67 69 6d 62 6c 65 20 69 6e 20 74 68 65 20 77'+
					'61 62 65 3a 0a 41 6c 6c 20 6d 69 6d 73 79 20 77'+
					'65 72 65 20 74 68 65 20 62 6f 72 6f 67 6f 76 65'+
					'73 2c 0a 41 6e 64 20 74 68 65 20 6d 6f 6d 65 20'+
					'72 61 74 68 73 20 6f 75 74 67 72 61 62 65 2e',
			key:	'1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0'+
					'47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0',
			tag:	'45 41 66 9a 7e aa ee 61 e7 08 dc 7c bc c5 eb 62'
		},
		{
			input:	'48656c6c6f20776f726c6421',
			key:	'746869732069732033322d62797465206b657920666f7220506f6c7931333035',
			tag:	'a6f745008f81c916a20dcc74eef2b2f0'
		},
		{// https://tools.ietf.org/html/rfc7539
			key:	'85:d6:be:78:57:55:6d:33:7f:44:52:fe:42:d5:06:a8:01:0'+
					'3:80:8a:fb:0d:b2:fd:4a:bf:f6:af:41:49:f5:1b',
			input:	'43 72 79 70 74 6f 67 72 61 70 68 69 63 20 46 6f'+
					'72 75 6d 20 52 65 73 65 61 72 63 68 20 47 72 6f'+
					'75 70',
			tag:	'a8:06:1d:c1:30:51:36:c6:c2:2b:8b:af:0c:01:27:a9'
		},
		{
			key:	"0000000000000000000000000000000000000000000000000000000000000000",
			nonce:	"00000000000000000000000000000000",
			algorithm: 'aes-128',
			input:	"",
			tag:	"66e94bd4ef8a2c3b884cfa59ca342b2e"
		},
		// http://cr.yp.to/mac/poly1305-20050329.pdf
		{
			key:	"ec 07 4c 83 55 80 74 17 01 42 5b 62 32 35 ad d6"+
					"85 1f c4 0c 34 67 ac 0b e0 5c c2 04 04 f3 f7 00",
			nonce:	"fb 44 73 50 c4 e8 68 c5 2a c3 27 5c f9 d4 32 7e",
			algorithm: 'aes-128',
			input:	"f3 f6",
			tag:	"f4 c6 33 c3 04 4f c1 45 f8 4f 33 5c b8 19 53 de"
		},
		{
			key:	"75 de aa 25 c0 9f 20 8e 1d c4 ce 6b 5c ad 3f bf"+
					"a0 f3 08 00 00 f4 64 00 d0 c7 e9 07 6c 83 44 03",
			nonce:	"61 ee 09 21 8d 29 b0 aa ed 7e 15 4a 2c 55 09 cc",
			algorithm: 'aes-128',
			input:	"",
			tag:	"dd 3f ab 22 51 f1 1a c7 59 f0 88 71 29 cc 2e e7"
		},
		{
			key:	"6a cb 5f 61 a7 17 6d d3 20 c5 c1 eb 2e dc dc 74"+
					"48 44 3d 0b b0 d2 11 09 c8 9a 10 0b 5c e2 c2 08",
			nonce:	"ae 21 2a 55 39 97 29 59 5d ea 45 8b c6 21 ff 0e",
			algorithm: 'aes-128',
			input:	"66 3c ea 19 0f fb 83 d8 95 93 f3 f4 76 b6 bc 24"+
					"d7 e6 79 10 7e a2 6a db 8c af 66 52 d0 65 61 36",
			tag:	"0e e1 c1 6b b7 3f 0f 4f d1 98 81 75 3c 01 cd be"
		},
		{
			input:  "ab 08 12 72 4a 7f 1e 34 27 42 cb ed 37 4d 94 d1"+
					"36 c6 b8 79 5d 45 b3 81 98 30 f2 c0 44 91 fa f0"+
					"99 0c 62 e4 8b 80 18 b2 c3 e4 a0 fa 31 34 cb 67"+
					"fa 83 e1 58 c9 94 d9 61 c4 cb 21 09 5c 1b f9",
			key:	"e1 a5 66 8a 4d 5b 66 a5 f6 8c c5 42 4e d5 98 2d"+
					"12 97 6a 08 c4 42 6d 0c e8 a8 24 07 c4 f4 82 07",
			algorithm: 'aes-128',
			nonce:	"9a e8 31 e7 43 97 8d 3a 23 52 7c 71 28 14 9e 3a",
			tag:	"51 54 ad 0d 2c b2 6e 01 27 4f c5 11 48 49 1f 1b"
			
		}
	];

	for (var i = 0; i < testVectors.length; i++) {
		var vector = testVectors[i];

		var key = Buffer.from(vector.key.replace(/[ \:]/g, ''), 'hex');
		var nonce = vector.nonce ? Buffer.from(vector.nonce.replace(/[ \:]/g, ''), 'hex') : null;
		var pt = Buffer.from(vector.input.replace(/[ \:]/g, ''), 'hex');
		var expected = Buffer.from(vector.tag.replace(/[ \:]/g, ''), 'hex');

		var mac = new jCastle.mac('poly1305-mac');

		mac.start({
			key: key,
			nonce: typeof nonce == 'undefined' ? null : nonce,
			algorithm: vector.algorithm ? vector.algorithm : null
		});

		mac.update(pt);

		var tag = mac.finalize();

		assert.ok(tag.equals(expected), 'Mac check passed!');
	}
});

QUnit.module('GOST28147-Mac')
QUnit.test("Vector Test", function(assert) {

	// key, iv, cleartext, expects
	var key = '6d145dc993f4019e104280df6fcd8cd8e01e101e4c113d7ec4f469ce6dcd9e49';
	var pt = '7768617420646f2079612077616e7420666f72206e6f7468696e673f';
	var expected = '93468a46';

	key = Buffer.from(key.replace(/[ \:]/g, ''), 'hex');
	pt = Buffer.from(pt.replace(/[ \:]/g, ''), 'hex');
	expected = Buffer.from(expected.replace(/[ \:]/g, ''), 'hex');

	var mac = new jCastle.mac('GOST28147-Mac');
	mac.start({
		key: key
	});

	mac.update(pt);  // important!
						// All data should be treated as additional data.

	var tag = mac.finalize();

	assert.ok(tag.equals(expected), 'Mac check passed!');

	
});

// cbc-mac
QUnit.module('CBC-Mac');
QUnit.test("Vector Test", function(assert) {
// there is no cbc-mac test vector available,
// we need to generate one.

	var key = "2b7e151628aed2a6abf7158809cf4f3c";

	var pt = "6bc1bee22e409f96e93d7e117393172a"+
			 "ae2d8a571e03ac9c9eb76fac45af8e51"+
			 "30c81c46a35ce411e5fbc1191a0a52ef"+
			 "f69f2445df4f9b17ad2b417be66c3710";

	key = Buffer.from(key.replace(/[ \:]/g, ''), 'hex');
	pt = Buffer.from(pt.replace(/[ \:]/g, ''), 'hex');

	var algoName = 'aes-128';

	var mac = new jCastle.mac('CBC-Mac');
	mac.start({
		key:key,
		algorithm: algoName
	});

	mac.update(pt);

	var tag = mac.finalize();

	// check routine.
	var algorithm = new jCastle.algorithm.aes(algoName);
	algorithm.keySchedule(key, true);
	
	//var cbcMode = new jCastle.Mode['cbc']();
	var cbcMode = jCastle.mcrypt.mode.create('cbc');
	
	var block_size = jCastle._algorithmInfo[algoName].block_size;

	// cbc-mac uses zero iv.
	cbcMode.init(algorithm, {
		iv: Buffer.alloc(block_size),
		blockSize: block_size,
		isEncryption: true
	});

	var v_tag;
	
	var v_pt = Buffer.slice(pt);
	if (v_pt % block_size) {
		v_pt = Buffer.concat([v_pt, Buffer.alloc(block_size - (v_pt % blockSize))]);
	}

	for (var i = 0; i < v_pt.length; i += block_size) {
		v_tag = cbcMode.process(v_pt.slice(i, i + block_size));
	}

	assert.ok(tag.equals(v_tag));
});

// iso9797alg3-mac
QUnit.module('ISO9797Alg3-Mac(DES-EDE-Mac)');
QUnit.test("Vector Test", function(assert) {

	// key, iv, cleartext, expects
	var key = '7CA110454A1A6E570131D9619DC1376E';
	var pt = 'Hello World !!!!';
	var expected = 'F09B856213BAB83B';

	key = Buffer.from(key.replace(/[ \:]/g, ''), 'hex');
	//pt = Buffer.from(pt);
	expected = Buffer.from(expected.replace(/[ \:]/g, ''), 'hex');

	var mac = new jCastle.mac('ISO9797Alg3-Mac');
	mac.start({
		key: key
	});

	mac.update(pt);

	var tag = mac.finalize();

	assert.ok(tag.equals(expected), 'Mac check passed!');
});