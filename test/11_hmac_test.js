const QUnit = require('qunit');
const jCastle = require('../lib/index');


QUnit.module('SHA-1/256/512 HMac');
QUnit.test("Vector Test", function(assert) {

	var str = 'The quick brown fox jumped over the lazy dog.';
	var key = 'secret';

	var testVectors = [
		{
			hash_name: 'sha-1',
			expected: "5d4db2701c7b07de0e23db3e4f22e88bc1a31a49"
		}, {
			hash_name: 'sha-256',
			expected: "9c5c42422b03f0ee32949920649445e417b2c634050833c5165704b825c2a53b"
		}, {
			hash_name: 'sha-512',
			expected: "6e3842ef12d31569c33467d5d214881f6c9bc596332fac121be7e2ad36735504901702057c45d1385d4c1077002b81aa010ba9885f6867c873e682b30f81bd51"
		}
	];

	for (var i = 0; i < testVectors.length; i++) {
		var vector = testVectors[i];

		var expected = Buffer.from(vector.expected.replace(/[ \:]/g, ''), 'hex');

		var hmac = jCastle.hmac.create(vector.hash_name);

		hmac.start({key: key});

		hmac.update(str);

		var h = hmac.finalize();

		assert.ok(h.equals(expected), "Message Digest test passed!");
	}
});

QUnit.module('RIPEMD-160 HMac');
QUnit.test("Vector Test", function(assert) {

	var str = 'The quick brown fox jumped over the lazy dog.';
	var key = 'secret';

	var expected = Buffer.from("b8e7ae12510bdfb1812e463a7f086122cf37e4f7", 'hex');

	var hmac = jCastle.hmac.create('ripemd-160');

	hmac.start({key: key});

	hmac.update(str);

	var h = hmac.finalize();

	assert.ok(h.equals(expected), "Message Digest test passed!");

});

QUnit.module('MD5 HMac');
QUnit.test("Vector Test", function(assert) {

	var str = 'The quick brown fox jumped over the lazy dog.';
	var key = 'secret';

	var expected = Buffer.from("7eb2b5c37443418fc77c136dd20e859c", 'hex');

	var hmac = jCastle.hmac.create('md5');

	hmac.start({key: key});

	hmac.update(str);

	var h = hmac.finalize();

	assert.ok(h.equals(expected), "Message Digest test passed!");
});

QUnit.module('SHA3 HMac');
QUnit.test("Vector Test", function(assert) {

	var testVectors = [
	{
		key: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"+
			"0b0b0b0b",
		data: "4869205468657265",// "Hi There"

		224: "3b16546bbc7be2706a031dcafd56373d"+
			"9884367641d8c59af3c860f7",
		256: "ba85192310dffa96e2a3a40e69774351"+
			"140bb7185e1202cdcc917589f95e16bb",
		384: "68d2dcf7fd4ddd0a2240c8a437305f61"+
			"fb7334cfb5d0226e1bc27dc10a2e723a"+
			"20d370b47743130e26ac7e3d532886bd",
		512: "eb3fbd4b2eaab8f5c504bd3a41465aac"+
			"ec15770a7cabac531e482f860b5ec7ba"+
			"47ccb2c6f2afce8f88d22b6dc61380f2"+
			"3a668fd3888bb80537c0a0b86407689e"
	}, {
		key: "4a656665", //"Jefe"
		data: "7768617420646f2079612077616e7420"+
			"666f72206e6f7468696e673f", // "what do ya want for nothing?"

		224: "7fdb8dd88bd2f60d1b798634ad386811"+
			"c2cfc85bfaf5d52bbace5e66",
		256: "c7d4072e788877ae3596bbb0da73b887"+
			"c9171f93095b294ae857fbe2645e1ba5",
		384: "f1101f8cbf9766fd6764d2ed61903f21"+
			"ca9b18f57cf3e1a23ca13508a93243ce"+
			"48c045dc007f26a21b3f5e0e9df4c20a",
		512: "5a4bfeab6166427c7a3647b747292b83"+
			"84537cdb89afb3bf5665e4c5e709350b"+
			"287baec921fd7ca0ee7a0c31d022a95e"+
			"1fc92ba9d77df883960275beb4e62024"
	}, {
		key: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"+
			"aaaaaaaa",
		data: "dddddddddddddddddddddddddddddddd"+
			"dddddddddddddddddddddddddddddddd"+
			"dddddddddddddddddddddddddddddddd"+
			"dddd",

		224: "676cfc7d16153638780390692be142d2"+
			"df7ce924b909c0c08dbfdc1a",
		256: "84ec79124a27107865cedd8bd82da996"+
			"5e5ed8c37b0ac98005a7f39ed58a4207",
		384: "275cd0e661bb8b151c64d288f1f782fb"+
			"91a8abd56858d72babb2d476f0458373"+
			"b41b6ab5bf174bec422e53fc3135ac6e",
		512: "309e99f9ec075ec6c6d475eda1180687"+
			"fcf1531195802a99b5677449a8625182"+
			"851cb332afb6a89c411325fbcbcd42af"+
			"cb7b6e5aab7ea42c660f97fd8584bf03"
	}, {
		key: "0102030405060708090a0b0c0d0e0f10"+
			"111213141516171819",
		data: "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"+
			"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"+
			"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"+
			"cdcd",

		224: "a9d7685a19c4e0dbd9df2556cc8a7d2a"+
			"7733b67625ce594c78270eeb",
		256: "57366a45e2305321a4bc5aa5fe2ef8a9"+
			"21f6af8273d7fe7be6cfedb3f0aea6d7",
		384: "3a5d7a879702c086bc96d1dd8aa15d9c"+
			"46446b95521311c606fdc4e308f4b984"+
			"da2d0f9449b3ba8425ec7fb8c31bc136",
		512: "b27eab1d6e8d87461c29f7f5739dd58e"+
			"98aa35f8e823ad38c5492a2088fa0281"+
			"993bbfff9a0e9c6bf121ae9ec9bb09d8"+
			"4a5ebac817182ea974673fb133ca0d1d"
	}, {
		key: "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"+
			"0c0c0c0c",
		data: "546573742057697468205472756e6361"+
			"74696f6e", // "Test With Truncation"

		224: "49fdd3abd005ebb8ae63fea946d1883c",
		256: "6e02c64537fb118057abb7fb66a23b3c",
		384: "47c51ace1ffacffd7494724682615783",
		512: "0fa7475948f43f48ca0516671e18978c",
		truncation: 128
	}, {
		key: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"+
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"+
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"+
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"+
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"+
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"+
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"+
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"+
			"aaaaaa",
		data:   "54657374205573696e67204c61726765"+
                "72205468616e20426c6f636b2d53697a"+
                "65204b6579202d2048617368204b6579"+
                "204669727374",               // "Test Using Larger Than Block-Size Key - Hash Key First"

			224: "b4a1f04c00287a9b7f6075b313d279b8"+
                 "33bc8f75124352d05fb9995f",
			256: "ed73a374b96c005235f948032f09674a"+
                 "58c0ce555cfc1f223b02356560312c3b",
			384: "0fc19513bf6bd878037016706a0e57bc"+
                 "528139836b9a42c3d419e498e0e1fb96"+
                 "16fd669138d33a1105e07c72b6953bcc",
			512: "00f751a9e50695b090ed6911a4b65524"+
                 "951cdc15a73a5d58bb55215ea2cd839a"+
                 "c79d2b44a39bafab27e83fde9e11f634"+
                 "0b11d991b1b91bf2eee7fc872426c3a4"
	}
	];
/*
Test Case 6a

Test with a key larger than 144 bytes (= block-size of SHA3-224).
  Key =          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                 aaaaaa                            (147 bytes)
  Data =         54657374205573696e67204c61726765  ("Test Using Large")
                 72205468616e20426c6f636b2d53697a  ("r Than Block-Siz")
                 65204b6579202d2048617368204b6579  ("e Key - Hash Key")
                 204669727374                      (" First")

 HMAC-SHA3-224 = b96d730c148c2daad8649d83defaa371
                 9738d34775397b7571c38515
 HMAC-SHA3-256 = a6072f86de52b38bb349fe84cd6d97fb
                 6a37c4c0f62aae93981193a7229d3467
 HMAC-SHA3-384 = 713dff0302c85086ec5ad0768dd65a13
                 ddd79068d8d4c6212b712e4164944911
                 1480230044185a99103ed82004ddbfcc
 HMAC-SHA3-512 = b14835c819a290efb010ace6d8568dc6
                 b84de60bc49b004c3b13eda763589451
                 e5dd74292884d1bdce64e6b919dd61dc
                 9c56a282a81c0bd14f1f365b49b83a5b
Test Case 7

Test with a key and data that is larger than 128 bytes (= block-size of SHA-384 and SHA-512).
  Key =          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                 aaaaaa                            (131 bytes)
  Data =         54686973206973206120746573742075  ("This is a test u")
                 73696e672061206c6172676572207468  ("sing a larger th")
                 616e20626c6f636b2d73697a65206b65  ("an block-size ke")
                 7920616e642061206c61726765722074  ("y and a larger t")
                 68616e20626c6f636b2d73697a652064  ("han block-size d")
                 6174612e20546865206b6579206e6565  ("ata. The key nee")
                 647320746f2062652068617368656420  ("ds to be hashed ")
                 6265666f7265206265696e6720757365  ("before being use")
                 642062792074686520484d414320616c  ("d by the HMAC al")
                 676f726974686d2e                  ("gorithm.")

 HMAC-SHA3-224 = 05d8cd6d00faea8d1eb68ade28730bbd
                 3cbab6929f0a086b29cd62a0
 HMAC-SHA3-256 = 65c5b06d4c3de32a7aef8763261e49ad
                 b6e2293ec8e7c61e8de61701fc63e123

 HMAC-SHA3-384 = 026fdf6b50741e373899c9f7d5406d4e
                 b09fc6665636fc1a530029ddf5cf3ca5
                 a900edce01f5f61e2f408cdf2fd3e7e8
 HMAC-SHA3-512 = 38a456a004bd10d32c9ab83366841128
                 62c3db61adcca31829355eaf46fd5c73
                 d06a1f0d13fec9a652fb3811b577b1b1
                 d1b9789f97ae5b83c6f44dfcf1d67eba
Test Case 7a

Test with a key larger than 144 bytes (= block-size of SHA3-224).
  Key =          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                 aaaaaa                            (147 bytes)
  Data =         54686973206973206120746573742075  ("This is a test u")
                 73696e672061206c6172676572207468  ("sing a larger th")
                 616e20626c6f636b2d73697a65206b65  ("an block-size ke")
                 7920616e642061206c61726765722074  ("y and a larger t")
                 68616e20626c6f636b2d73697a652064  ("han block-size d")
                 6174612e20546865206b6579206e6565  ("ata. The key nee")
                 647320746f2062652068617368656420  ("ds to be hashed ")
                 6265666f7265206265696e6720757365  ("before being use")
                 642062792074686520484d414320616c  ("d by the HMAC al")
                 676f726974686d2e                  ("gorithm.")

 HMAC-SHA3-224 = c79c9b093424e588a9878bbcb089e018
                 270096e9b4b1a9e8220c866a
 HMAC-SHA3-256 = e6a36d9b915f86a093cac7d110e9e04c
                 f1d6100d30475509c2475f571b758b5a
 HMAC-SHA3-384 = cad18a8ff6c4cc3ad487b95f9769e9b6
                 1c062aefd6952569e6e6421897054cfc
                 70b5fdc6605c18457112fc6aaad45585
 HMAC-SHA3-512 = dc030ee7887034f32cf402df34622f31
                 1f3e6cf04860c6bbd7fa488674782b46
                 59fdbdf3fd877852885cfe6e22185fe7
                 b2ee952043629bc9d5f3298a41d02c66
*/

	for (var i = 0; i < testVectors.length; i++) {
		var vector = testVectors[i];

		var key = Buffer.from(vector.key, 'hex');
		var data = Buffer.from(vector.data, 'hex');

		var bits = [224, 256, 384, 512];

		for (var j = 0; j < bits.length; j++) {
		
			var expected = Buffer.from(vector[bits[j]], 'hex');

			var hmac = jCastle.hmac.create('sha3-'+bits[j]);

			hmac.start({key: key});

			hmac.update(data);

			var h = hmac.finalize();

			if (typeof vector.truncation != 'undefined') {
				var size = (vector.truncation / 8);
				h = Buffer.slice(h, 0, size);
			}

			assert.ok(h.equals(expected), "Message Digest test passed!");
		}
	}
});

QUnit.module('Skein-256/512/1024 HMac');
QUnit.test("Vector Test", function(assert) {

	var testVectors = [
		[256, 256, "", "cb41f1706cde09651203c2d0efbaddf8", "886e4efefc15f06aa298963971d7a25398fffe5681c84db39bd00851f64ae29d"],
		[256, 256, "d3", "cb41f1706cde09651203c2d0efbaddf847a0d315cb2e53ff8bac41da0002672e920244c66e02d5f0dad3e94c42bb65f0d14157decf4105ef5609d5b0984457c193", "979422a94e3afaa46664124d4e5e8b9422b1d8baf11c6ae6725992ac72a112ca"],
		[256, 256, "d3090c72", "cb41f1706cde09651203c2d0efbaddf847a0d315cb2e53ff8bac41da0002672e", "1d658372cbea2f9928493cc47599d6f4ad8ce33536bedfa20b739f07516519d5"],
		[256, 256, "d3090c72167517f7", "cb41f1706cde09651203c2d0efbaddf847a0d315cb2e53ff8bac41da0002672e92", "41ef6b0f0fad81c040284f3b1a91e9c44e4c26a6d7207f3aac4362856ef12aca"],
		[256, 256, "d3090c72167517f7c7ad82a70c2fd3f6", "cb41f1706cde09651203c2d0efbaddf847a0d315cb2e53ff8bac41da0002672e920244c66e02d5f0dad3e94c42bb65f0d14157decf4105ef5609d5b0984457c193", "ca8208119b9e4e4057631ab31015cfd256f6763a0a34381633d97f640899b84f"],
		[256, 256, "d3090c72167517f7c7ad82a70c2fd3f6443f608301591e598eadb195e8357135", "cb41f1706cde09651203c2d0efbaddf847a0d315cb2e53ff8bac41da0002672e", "9e9980fcc16ee082cf164a5147d0e0692aeffe3dcb8d620e2bb542091162e2e9"],
		[256, 256, "d3090c72167517f7c7ad82a70c2fd3f6443f608301591e598eadb195e8357135ba26fede2ee187417f816048d00fc235", "cb41f1706cde09651203c2d0efbaddf847a0d315cb2e53ff8bac41da0002672e920244c66e02d5f0dad3e94c42bb65f0d14157decf4105ef5609d5b0984457c193", "c353a316558ec34f8245dd2f9c2c4961fbc7decc3b69053c103e4b8aaaf20394"],
		[256, 256, "d3090c72167517f7c7ad82a70c2fd3f6443f608301591e598eadb195e8357135ba26fede2ee187417f816048d00fc23512737a2113709a77e4170c49a94b7fdf", "cb41f1706cde09651203c2d0efbaddf8", "b1b8c18188e69a6ecae0b6018e6b638c6a91e6de6881e32a60858468c17b520d"],
		[256, 256, "d3090c72167517f7c7ad82a70c2fd3f6443f608301591e598eadb195e8357135ba26fede2ee187417f816048d00fc23512737a2113709a77e4170c49a94b7fdff45ff579a72287743102e7766c35ca5abc5dfe2f63a1e726ce5fbd2926db03a2", "cb41f1706cde09651203c2d0efbaddf847a0d315cb2e53ff8bac41da0002672e92", "1dfd2515a412e78852cd81a7f2167711b4ca19b2891c2ea36ba94f8451944793"],
		[256, 224, "d3090c72167517f7c7ad82a70c2fd3f6443f608301591e598eadb195e8357135ba26fede2ee187417f816048d00fc23512737a2113709a77e4170c49a94b7fdff45ff579a72287743102e7766c35ca5abc5dfe2f63a1e726ce5fbd2926db03a2dd18b03fc1508a9aac45eb362440203a323e09edee6324ee2e37b4432c1867ed", "cb41f1706cde09651203c2d0efbaddf8", "a097340709b443ed2c0a921f5dcefef3ead65c4f0bcd5f13da54d7ed"],
		[256, 256, "d3090c72167517f7c7ad82a70c2fd3f6443f608301591e598eadb195e8357135ba26fede2ee187417f816048d00fc23512737a2113709a77e4170c49a94b7fdff45ff579a72287743102e7766c35ca5abc5dfe2f63a1e726ce5fbd2926db03a2dd18b03fc1508a9aac45eb362440203a323e09edee6324ee2e37b4432c1867ed", "cb41f1706cde09651203c2d0efbaddf847a0d315cb2e53ff8bac41da0002672e", "ac1b4fab6561c92d0c487e082daec53e0db4f505e08bf51cae4fd5375e37fc04"],
		[256, 384, "d3090c72167517f7c7ad82a70c2fd3f6443f608301591e598eadb195e8357135ba26fede2ee187417f816048d00fc23512737a2113709a77e4170c49a94b7fdff45ff579a72287743102e7766c35ca5abc5dfe2f63a1e726ce5fbd2926db03a2dd18b03fc1508a9aac45eb362440203a323e09edee6324ee2e37b4432c1867ed", "cb41f1706cde09651203c2d0efbaddf847a0d315cb2e53ff8bac41da0002672e92", "96e6cebb23573d0a70ce36a67aa05d2403148093f25c695e1254887cc97f9771d2518413af4286bf2a06b61a53f7fcec"],
		[256, 512, "d3090c72167517f7c7ad82a70c2fd3f6443f608301591e598eadb195e8357135ba26fede2ee187417f816048d00fc23512737a2113709a77e4170c49a94b7fdff45ff579a72287743102e7766c35ca5abc5dfe2f63a1e726ce5fbd2926db03a2dd18b03fc1508a9aac45eb362440203a323e09edee6324ee2e37b4432c1867ed", "cb41f1706cde09651203c2d0efbaddf847a0d315cb2e53ff8bac41da0002672e920244c66e02d5f0dad3e94c42bb65f0d14157decf4105ef5609d5b0984457c193", "0e95e597e71d6350f20b99c4179f54f43a4722705c06ba765a82cb0a314fe2fe87ef8090063b757e53182706ed18737dadc0da1e1c66518f08334052702c5ed7"],
		[256, 264, "d3090c72167517f7c7ad82a70c2fd3f6443f608301591e598eadb195e8357135ba26fede2ee187417f816048d00fc23512737a2113709a77e4170c49a94b7fdff45ff579a72287743102e7766c35ca5abc5dfe2f63a1e726ce5fbd2926db03a2dd18b03fc1508a9aac45eb362440203a323e09edee6324ee2e37b4432c1867ed", "cb41f1706cde09651203c2d0efbaddf8", "064abd4896f460b1953f5a357e7f7c5256e29cdb62b8740d0b52295cfa2ef4c7a2"],
		[256, 520, "d3090c72167517f7c7ad82a70c2fd3f6443f608301591e598eadb195e8357135ba26fede2ee187417f816048d00fc23512737a2113709a77e4170c49a94b7fdff45ff579a72287743102e7766c35ca5abc5dfe2f63a1e726ce5fbd2926db03a2dd18b03fc1508a9aac45eb362440203a323e09edee6324ee2e37b4432c1867ed", "cb41f1706cde09651203c2d0efbaddf847a0d315cb2e53ff8bac41da0002672e", "edf220e43e048603bd16197d59b673b9974de5b8bcf7cb1558a4799f6fd3743eb5fb400cd6129afc0c60e7b741b7e5806f0e0b93eb8429fbc7efa222175a9c80fd"],
		[256, 1032, "d3090c72167517f7c7ad82a70c2fd3f6443f608301591e598eadb195e8357135ba26fede2ee187417f816048d00fc23512737a2113709a77e4170c49a94b7fdff45ff579a72287743102e7766c35ca5abc5dfe2f63a1e726ce5fbd2926db03a2dd18b03fc1508a9aac45eb362440203a323e09edee6324ee2e37b4432c1867ed", "cb41f1706cde09651203c2d0efbaddf847a0d315cb2e53ff8bac41da0002672e92", "f3f59fb07399c7b73aae02a8590883cb2fdfde75c55654e71846522301bde48d267169adcc559e038e8c2f28faa552b550d51874055384adea93c036c71a1f0af0c7bcc3bc923738d5307b9da7cb423d4e615c629c4aba71f70d4c9d1fa008176825e51bfa0203445a4083947ec19f6a0fbd082b5b970f2396fb67420639410447"],
		[256, 2056, "d3090c72167517f7c7ad82a70c2fd3f6443f608301591e598eadb195e8357135ba26fede2ee187417f816048d00fc23512737a2113709a77e4170c49a94b7fdff45ff579a72287743102e7766c35ca5abc5dfe2f63a1e726ce5fbd2926db03a2dd18b03fc1508a9aac45eb362440203a323e09edee6324ee2e37b4432c1867ed", "cb41f1706cde09651203c2d0efbaddf847a0d315cb2e53ff8bac41da0002672e920244c66e02d5f0dad3e94c42bb65f0d14157decf4105ef5609d5b0984457c193", "80eb80d9b8836b32fa576fc84ba08edfbdfd6979123d61914e610a70a372b37f560a10909484f9f4a377c93e29ba681dfe522c41dc83b5ee0567e5370007c7bbe4df0b2b4a25e088f80d72fc30734cdcd76d817b42fbd44dca881019afb25306f19d4e91848778af306517d2072cef72caa327e877c5b6554f83cec3d00877131b47c4d3b557f5a13541c4d5080ee3ce7a658993d083efd0db3496a8752060c3c8552f44b290cabdcc867f691ad605836c08dbd59c9528d885b600b85fdfc8a9d0e636ac3ad8b4295bcb0169e78dc358e77eacc8c4b61bddfa9e5f32d2268a006cfe05c57150fe8e68cabd21cf6cf6035aa1fe4db36c922b765aad0b64e82a2c37"],
		[256, 256, "d3090c72167517f7c7ad82a70c2fd3f6443f608301591e598eadb195e8357135ba26fede2ee187417f816048d00fc23512737a2113709a77e4170c49a94b7fdff45ff579a72287743102e7766c35ca5abc5dfe2f63a1e726ce5fbd2926db03a2dd18b03fc1508a9aac45eb362440203a323e09edee6324ee2e37b4432c1867ed696e6c9db1e6abea026288954a9c2d5758d7c5db7c9e48aa3d21cae3d977a7c3926066aa393dbd538dd0c30da8916c8757f24c18488014668a2627163a37b261833dc2f8c3c56b1b2e0be21fd3fbdb507b2950b77a6cc02efb393e57419383a920767bca2c972107aa61384542d47cbfb82cfe5c415389d1b0a2d74e2c5da851", "cb41f1706cde09651203c2d0efbaddf847a0d315cb2e53ff8bac41da0002672e", "8f88de68f03cd2f396ccdd49c3a0f4ff15bcda7eb357da9753f6116b124de91d"],
		[512, 512, "", "cb41f1706cde09651203c2d0efbaddf847a0d315cb2e53ff8bac41da0002672e920244c66e02d5f0dad3e94c42bb65f0d14157decf4105ef5609d5b0984457c1935df3061ff06e9f204192ba11e5bb2cac0430c1c370cb3d113fea5ec1021eb875e5946d7a96ac69a1626c6206b7252736f24253c9ee9b85eb852dfc814631346c", "9bd43d2a2fcfa92becb9f69faab3936978f1b865b7e44338fc9c8f16aba949ba340291082834a1fc5aa81649e13d50cd98641a1d0883062bfe2c16d1faa7e3aa"],
		[512, 512, "d3", "cb41f1706cde09651203c2d0efbaddf847a0d315cb2e53ff8bac41da0002672e920244c66e02d5f0dad3e94c42bb65f0d14157decf4105ef5609d5b0984457c1", "f0c0a10f031c8fc69cfabcd54154c318b5d6cd95d06b12cf20264402492211ee010d5cecc2dc37fd772afac0596b2bf71e6020ef2dee7c860628b6e643ed9ff6"],
		[512, 512, "d3090c72167517f7", "cb41f1706cde09651203c2d0efbaddf847a0d315cb2e53ff8bac41da0002672e", "0c1f1921253dd8e5c2d4c5f4099f851042d91147892705829161f5fc64d89785226eb6e187068493ee4c78a4b7c0f55a8cbbb1a5982c2daf638fc6a74b16b0d7"],
		[512, 512, "d3090c72167517f7c7ad82a70c2fd3f6", "cb41f1706cde09651203c2d0efbaddf847a0d315cb2e53ff8bac41da0002672e920244c66e02d5f0dad3e94c42bb65f0d14157decf4105ef5609d5b0984457c1", "478d7b6c0cc6e35d9ebbdedf39128e5a36585db6222891692d1747d401de34ce3db6fcbab6c968b7f2620f4a844a2903b547775579993736d2493a75ff6752a1"],
		[512, 512, "d3090c72167517f7c7ad82a70c2fd3f6443f608301591e59", "cb41f1706cde09651203c2d0efbaddf847a0d315cb2e53ff8bac41da0002672e920244c66e02d5f0dad3e94c42bb65f0d14157decf4105ef5609d5b0984457c193", "13c170bac1de35e5fb843f65fabecf214a54a6e0458a4ff6ea5df91915468f4efcd371effa8965a9e82c5388d84730490dcf3976af157b8baf550655a5a6ab78"],
		[512, 512, "d3090c72167517f7c7ad82a70c2fd3f6443f608301591e598eadb195e8357135ba26fede2ee187417f816048d00fc235", "cb41f1706cde09651203c2d0efbaddf847a0d315cb2e53ff8bac41da0002672e920244c66e02d5f0dad3e94c42bb65f0d14157decf4105ef5609d5b0984457c1", "a947812529a72fd3b8967ec391b298bee891babc8487a1ec4ea3d88f6b2b5be09ac6a780f30f8e8c3bbb4f18bc302a28f3e87d170ba0f858a8fefe3487478cca"],
		[512, 512, "d3090c72167517f7c7ad82a70c2fd3f6443f608301591e598eadb195e8357135ba26fede2ee187417f816048d00fc23512737a2113709a77e4170c49a94b7fdf", "cb41f1706cde09651203c2d0efbaddf847a0d315cb2e53ff8bac41da0002672e920244c66e02d5f0dad3e94c42bb65f0d14157decf4105ef5609d5b0984457c1935df3061ff06e9f204192ba11e5bb2cac0430c1c370cb3d113fea5ec1021eb875e5946d7a96ac69a1626c6206b7252736f24253c9ee9b85eb852dfc814631346c", "7690ba61f10e0bba312980b0212e6a9a51b0e9aadfde7ca535754a706e042335b29172aae29d8bad18efaf92d43e6406f3098e253f41f2931eda5911dc740352"],
		[512, 512, "d3090c72167517f7c7ad82a70c2fd3f6443f608301591e598eadb195e8357135ba26fede2ee187417f816048d00fc23512737a2113709a77e4170c49a94b7fdff45ff579a72287743102e7766c35ca5abc5dfe2f63a1e726ce5fbd2926db03a2", "cb41f1706cde09651203c2d0efbaddf847a0d315cb2e53ff8bac41da0002672e", "d10e3ba81855ac087fbf5a3bc1f99b27d05f98ba22441138026225d34a418b93fd9e8dfaf5120757451adabe050d0eb59d271b0fe1bbf04badbcf9ba25a8791b"],
		[512, 160, "d3090c72167517f7c7ad82a70c2fd3f6443f608301591e598eadb195e8357135ba26fede2ee187417f816048d00fc23512737a2113709a77e4170c49a94b7fdff45ff579a72287743102e7766c35ca5abc5dfe2f63a1e726ce5fbd2926db03a2dd18b03fc1508a9aac45eb362440203a323e09edee6324ee2e37b4432c1867ed", "cb41f1706cde09651203c2d0efbaddf847a0d315cb2e53ff8bac41da0002672e920244c66e02d5f0dad3e94c42bb65f0d14157decf4105ef5609d5b0984457c193", "5670b226156570dff3efe16661ab86eb24982cdf"],
		[512, 224, "d3090c72167517f7c7ad82a70c2fd3f6443f608301591e598eadb195e8357135ba26fede2ee187417f816048d00fc23512737a2113709a77e4170c49a94b7fdff45ff579a72287743102e7766c35ca5abc5dfe2f63a1e726ce5fbd2926db03a2dd18b03fc1508a9aac45eb362440203a323e09edee6324ee2e37b4432c1867ed", "cb41f1706cde09651203c2d0efbaddf847a0d315cb2e53ff8bac41da0002672e920244c66e02d5f0dad3e94c42bb65f0d14157decf4105ef5609d5b0984457c1935df3061ff06e9f204192ba11e5bb2cac0430c1c370cb3d113fea5ec1021eb875e5946d7a96ac69a1626c6206b7252736f24253c9ee9b85eb852dfc814631346c", "c41b9ff9753e6c0f8ed88866e320535e927fe4da552c289841a920db"],
		[512, 384, "d3090c72167517f7c7ad82a70c2fd3f6443f608301591e598eadb195e8357135ba26fede2ee187417f816048d00fc23512737a2113709a77e4170c49a94b7fdff45ff579a72287743102e7766c35ca5abc5dfe2f63a1e726ce5fbd2926db03a2dd18b03fc1508a9aac45eb362440203a323e09edee6324ee2e37b4432c1867ed", "cb41f1706cde09651203c2d0efbaddf847a0d315cb2e53ff8bac41da0002672e", "dfbf5c1319a1d9d70efb2f1600fbcf694f935907f31d24a16d6cd2fb2d7855a769681766c0a29da778eed346cd1d740f"],
		[512, 512, "d3090c72167517f7c7ad82a70c2fd3f6443f608301591e598eadb195e8357135ba26fede2ee187417f816048d00fc23512737a2113709a77e4170c49a94b7fdff45ff579a72287743102e7766c35ca5abc5dfe2f63a1e726ce5fbd2926db03a2dd18b03fc1508a9aac45eb362440203a323e09edee6324ee2e37b4432c1867ed", "cb41f1706cde09651203c2d0efbaddf847a0d315cb2e53ff8bac41da0002672e920244c66e02d5f0dad3e94c42bb65f0d14157decf4105ef5609d5b0984457c1", "04d8cddb0ad931d54d195899a094684344e902286037272890bce98a41813edc37a3cee190a693fcca613ee30049ce7ec2bdff9613f56778a13f8c28a21d167a"],
		[512, 1024, "d3090c72167517f7c7ad82a70c2fd3f6443f608301591e598eadb195e8357135ba26fede2ee187417f816048d00fc23512737a2113709a77e4170c49a94b7fdff45ff579a72287743102e7766c35ca5abc5dfe2f63a1e726ce5fbd2926db03a2dd18b03fc1508a9aac45eb362440203a323e09edee6324ee2e37b4432c1867ed", "cb41f1706cde09651203c2d0efbaddf847a0d315cb2e53ff8bac41da0002672e920244c66e02d5f0dad3e94c42bb65f0d14157decf4105ef5609d5b0984457c193", "08fca368b3b14ac406676adf37ac9be2dbb8704e694055a0c6331184d4f0070098f23f0963ee29002495771bf56fb4d3d9ff3506abcd80be927379f7880d5d7703919fbf92184f498ac44f47f015ce676eded9165d47d53733f5a27abbc05f45acd98b97cc15ffdced641defd1a5119ef841b452a1b8f94ee69004466ccdc143"],
		[512, 264, "d3090c72167517f7c7ad82a70c2fd3f6443f608301591e598eadb195e8357135ba26fede2ee187417f816048d00fc23512737a2113709a77e4170c49a94b7fdff45ff579a72287743102e7766c35ca5abc5dfe2f63a1e726ce5fbd2926db03a2dd18b03fc1508a9aac45eb362440203a323e09edee6324ee2e37b4432c1867ed", "cb41f1706cde09651203c2d0efbaddf847a0d315cb2e53ff8bac41da0002672e920244c66e02d5f0dad3e94c42bb65f0d14157decf4105ef5609d5b0984457c1935df3061ff06e9f204192ba11e5bb2cac0430c1c370cb3d113fea5ec1021eb875e5946d7a96ac69a1626c6206b7252736f24253c9ee9b85eb852dfc814631346c", "669e770ebe7eacc2b64caaf049923ad297a5b37cfa61c283392d81ccfcb9bbbc09"],
		[512, 1032, "d3090c72167517f7c7ad82a70c2fd3f6443f608301591e598eadb195e8357135ba26fede2ee187417f816048d00fc23512737a2113709a77e4170c49a94b7fdff45ff579a72287743102e7766c35ca5abc5dfe2f63a1e726ce5fbd2926db03a2dd18b03fc1508a9aac45eb362440203a323e09edee6324ee2e37b4432c1867ed", "cb41f1706cde09651203c2d0efbaddf847a0d315cb2e53ff8bac41da0002672e", "acc2e03f07f33e9820a6038421089429adcd6a7a83f733beec048c05bf37531a170a5537fcb565c348a70a83217f8be768ff6f95fd2b3d89cb7d8a3dc849505e3710eb4e65a8e7134bbf580d92fe18c9aa987563669b1f014aa5e092519089355534eaa9f0bdc99f6839f54080ffe74623254c906ecb8896b4346c3178a0bc2898"],
		[512, 2056, "d3090c72167517f7c7ad82a70c2fd3f6443f608301591e598eadb195e8357135ba26fede2ee187417f816048d00fc23512737a2113709a77e4170c49a94b7fdff45ff579a72287743102e7766c35ca5abc5dfe2f63a1e726ce5fbd2926db03a2dd18b03fc1508a9aac45eb362440203a323e09edee6324ee2e37b4432c1867ed", "cb41f1706cde09651203c2d0efbaddf847a0d315cb2e53ff8bac41da0002672e920244c66e02d5f0dad3e94c42bb65f0d14157decf4105ef5609d5b0984457c1", "9f3e082223c43090a4a3ffbdcd469cbabfe0c1399d1edf45a5dfc18f4db5428928a76e979b8d0d5dffec0e6a59ada448c1ffbc06cc80a2006f002adc0c6dbf458563762228dce4381944e460ebebfe06f1237093634625107469a22a189a47f8b025899265d8890a1b39df64552394377e88ba2ad44a8c8d174f884ac8c3ae24ddb0affca5fceb6aa76e09706881e8371774b9b050a69b96ef5e97e81043f8b7e9479e287ab441bacd62caf768a82c8c3e3107be70eb8799a39856fe29842a04e25de0ef9de1b7e65bd0f1f7306835287fc957388e2035b7d22d3aa9c06a9fefbca16f3f60e1c4def89038d918942152a069aa2e0be8ae7475d859031adec84583"],
		[1024, 1024, "", "cb41f1706cde09651203c2d0efbaddf847a0d315cb2e53ff8bac41da0002672e920244c66e02d5f0dad3e94c42bb65f0d14157decf4105ef5609d5b0984457c1935df3061ff06e9f204192ba11e5bb2cac0430c1c370cb3d113fea5ec1021eb875e5946d7a96ac69a1626c6206b7252736f24253c9ee9b85eb852dfc81463134", "bcf37b3459c88959d6b6b58b2bfe142cef60c6f4ec56b0702480d7893a2b0595aa354e87102a788b61996b9cbc1eade7dafbf6581135572c09666d844c90f066b800fc4f5fd1737644894ef7d588afc5c38f5d920bdbd3b738aea3a3267d161ed65284d1f57da73b68817e17e381ca169115152b869c66b812bb9a84275303f0"],
		[1024, 1024, "d3090c72", "cb41f1706cde09651203c2d0efbaddf847a0d315cb2e53ff8bac41da0002672e920244c66e02d5f0dad3e94c42bb65f0d14157decf4105ef5609d5b0984457c1935df3061ff06e9f204192ba11e5bb2cac0430c1c370cb3d113fea5ec1021eb875e5946d7a96ac69a1626c6206b7252736f24253c9ee9b85eb852dfc814631346c", "df0596e5808835a3e304aa27923db05f61dac57c0696a1d19abf188e70aa9dbcc659e9510f7c9a37fbc025bd4e5ea293e78ed7838dd0b08864e8ad40ddb3a88031ebefc21572a89960d1916107a7da7ac0c067e34ec46a86a29ca63fa250bd398eb32ec1ed0f8ac8329f26da018b029e41e2e58d1dfc44de81615e6c987ed9c9"],
		[1024, 1024, "d3090c72167517f7", "cb41f1706cde09651203c2d0efbaddf847a0d315cb2e53ff8bac41da0002672e920244c66e02d5f0dad3e94c42bb65f0d14157decf4105ef5609d5b0984457c1935df3061ff06e9f204192ba11e5bb2cac0430c1c370cb3d113fea5ec1021eb875e5946d7a96ac69a1626c6206b7252736f24253c9ee9b85eb852dfc814631346c042eb4187aa1c015a4767032c0bb28f076b66485f51531c12e948f47dbc2cb904a4b75d1e8a6d931dab4a07e0a54d1bb5b55e602141746bd09fb15e8f01a8d74e9e63959cb37336bc1b896ec78da734c15e362db04368fbba280f20a043e0d0941e9f5193e1b360a33c43b266524880125222e648f05f28be34ba3cabfc9c544", "3cfbb79cd88af8ee09c7670bcbab6907a31f80fa31d9d7c9d50826c9568f307a78bd254961398c76b6e338fd9ca5f351059350d30963c3320659b223b991fc46d1307686fe2b4763d9f593c57ad5adbc45caf2ea3dc6090f5a74fa5fa6d9e9838964ea0a2aa216831ab069b00629a1a9b037083403bdb25d3d06a21c430c87dd"],
		[1024, 1024, "d3090c72167517f7c7ad82a70c2fd3f6443f608301591e59", "cb41f1706cde09651203c2d0efbaddf847a0d315cb2e53ff8bac41da0002672e920244c66e02d5f0dad3e94c42bb65f0d14157decf4105ef5609d5b0984457c1", "0a1b960099fc9d653b0fd1f5b6b972fb366907b772cbce5a59b6171d7935506f70c212bd169d68c5cfd8618343611b7eb2e686ff1dc7c03a57e1a55ed10726848161eea903d53b58459be42d95df989c66c2eea4e51cde272c2d8be67bf3bca2aee633777eb8486781eaa060d0f538abd6c93dbd2d1bf66e6f50bfdcac3725a4"],
		[1024, 1024, "d3090c72167517f7c7ad82a70c2fd3f6443f608301591e598eadb195e8357135", "cb41f1706cde09651203c2d0efbaddf847a0d315cb2e53ff8bac41da0002672e920244c66e02d5f0dad3e94c42bb65f0d14157decf4105ef5609d5b0984457c1935df3061ff06e9f204192ba11e5bb2cac0430c1c370cb3d113fea5ec1021eb875e5946d7a96ac69a1626c6206b7252736f24253c9ee9b85eb852dfc814631346c", "3e0cd7938d71c39ffbb08a6ba7995ade3ad140e2c0c45cdbafb099247e08e4c20b61c1f885ced5ed2f816680925034918236e5807f0eecf3f27e9cfca36675eb75873efa1fb41f17541dc2f7c2469eaecb35cc7ca58e489804caf56f09fb97c9f689c64ad49c6888f86c483e901bd3d25798b394ef93faf9154900f92f31f433"],
		[1024, 1024, "d3090c72167517f7c7ad82a70c2fd3f6443f608301591e598eadb195e8357135ba26fede2ee187417f816048d00fc23512737a2113709a77e4170c49a94b7fdf", "cb41f1706cde09651203c2d0efbaddf847a0d315cb2e53ff8bac41da0002672e920244c66e02d5f0dad3e94c42bb65f0d14157decf4105ef5609d5b0984457c1935df3061ff06e9f204192ba11e5bb2cac0430c1c370cb3d113fea5ec1021eb875e5946d7a96ac69a1626c6206b7252736f24253c9ee9b85eb852dfc81463134", "7266752f7e9aa04bd7d8a1b16030677de6021301f6a62473c76bae2b98bbf8aad73bd00a4b5035f741caf2317ab80e4e97f5c5bbe8acc0e8b424bcb13c7c6740a985801fba54addde8d4f13f69d2bfc98ae104d46a211145217e51d510ea846cec9581d14fda079f775c8b18d66cb31bf7060996ee8a69eee7f107909ce59a97"],
		[1024, 1024, "d3090c72167517f7c7ad82a70c2fd3f6443f608301591e598eadb195e8357135ba26fede2ee187417f816048d00fc23512737a2113709a77e4170c49a94b7fdff45ff579a72287743102e7766c35ca5abc5dfe2f63a1e726ce5fbd2926db03a2", "cb41f1706cde09651203c2d0efbaddf847a0d315cb2e53ff8bac41da0002672e920244c66e02d5f0dad3e94c42bb65f0d14157decf4105ef5609d5b0984457c1935df3061ff06e9f204192ba11e5bb2cac0430c1c370cb3d113fea5ec1021eb875e5946d7a96ac69a1626c6206b7252736f24253c9ee9b85eb852dfc814631346c042eb4187aa1c015a4767032c0bb28f076b66485f51531c12e948f47dbc2cb904a4b75d1e8a6d931dab4a07e0a54d1bb5b55e602141746bd09fb15e8f01a8d74e9e63959cb37336bc1b896ec78da734c15e362db04368fbba280f20a043e0d0941e9f5193e1b360a33c43b266524880125222e648f05f28be34ba3cabfc9c544", "71f40bf2aa635125ef83c8df0d4e9ea18b73b56be4f45e89b910a7c68d396b65b09d18abc7d1b6de3f53fd5de583e6f22e612dd17b292068af6027daaf8b4cd60acf5bc85044741e9f7a1f423f5827f5e360930a2e71912239af9fc6343604fdcf3f3569854f2bb8d25a81e3b3f5261a02fe8292aaaa50c324101ab2c7a2f349"],
		[1024, 160, "d3090c72167517f7c7ad82a70c2fd3f6443f608301591e598eadb195e8357135ba26fede2ee187417f816048d00fc23512737a2113709a77e4170c49a94b7fdff45ff579a72287743102e7766c35ca5abc5dfe2f63a1e726ce5fbd2926db03a2dd18b03fc1508a9aac45eb362440203a323e09edee6324ee2e37b4432c1867ed", "cb41f1706cde09651203c2d0efbaddf847a0d315cb2e53ff8bac41da0002672e920244c66e02d5f0dad3e94c42bb65f0d14157decf4105ef5609d5b0984457c1", "17c3c533b27d666da556ae586e641b7a3a0bcc45"],
		[1024, 224, "d3090c72167517f7c7ad82a70c2fd3f6443f608301591e598eadb195e8357135ba26fede2ee187417f816048d00fc23512737a2113709a77e4170c49a94b7fdff45ff579a72287743102e7766c35ca5abc5dfe2f63a1e726ce5fbd2926db03a2dd18b03fc1508a9aac45eb362440203a323e09edee6324ee2e37b4432c1867ed", "cb41f1706cde09651203c2d0efbaddf847a0d315cb2e53ff8bac41da0002672e920244c66e02d5f0dad3e94c42bb65f0d14157decf4105ef5609d5b0984457c1935df3061ff06e9f204192ba11e5bb2cac0430c1c370cb3d113fea5ec1021eb875e5946d7a96ac69a1626c6206b7252736f24253c9ee9b85eb852dfc81463134", "6625df9801581009125ea4e5c94ad6f1a2d692c278822ccb6eb67235"],
		[1024, 256, "d3090c72167517f7c7ad82a70c2fd3f6443f608301591e598eadb195e8357135ba26fede2ee187417f816048d00fc23512737a2113709a77e4170c49a94b7fdff45ff579a72287743102e7766c35ca5abc5dfe2f63a1e726ce5fbd2926db03a2dd18b03fc1508a9aac45eb362440203a323e09edee6324ee2e37b4432c1867ed", "cb41f1706cde09651203c2d0efbaddf847a0d315cb2e53ff8bac41da0002672e920244c66e02d5f0dad3e94c42bb65f0d14157decf4105ef5609d5b0984457c1935df3061ff06e9f204192ba11e5bb2cac0430c1c370cb3d113fea5ec1021eb875e5946d7a96ac69a1626c6206b7252736f24253c9ee9b85eb852dfc814631346c", "6c5b671c1766f6eecea6d24b641d4a6bf84bba13a1976f8f80b3f30ee2f93de6"],
		[1024, 384, "d3090c72167517f7c7ad82a70c2fd3f6443f608301591e598eadb195e8357135ba26fede2ee187417f816048d00fc23512737a2113709a77e4170c49a94b7fdff45ff579a72287743102e7766c35ca5abc5dfe2f63a1e726ce5fbd2926db03a2dd18b03fc1508a9aac45eb362440203a323e09edee6324ee2e37b4432c1867ed", "cb41f1706cde09651203c2d0efbaddf847a0d315cb2e53ff8bac41da0002672e920244c66e02d5f0dad3e94c42bb65f0d14157decf4105ef5609d5b0984457c1935df3061ff06e9f204192ba11e5bb2cac0430c1c370cb3d113fea5ec1021eb875e5946d7a96ac69a1626c6206b7252736f24253c9ee9b85eb852dfc814631346c042eb4187aa1c015a4767032c0bb28f076b66485f51531c12e948f47dbc2cb904a4b75d1e8a6d931dab4a07e0a54d1bb5b55e602141746bd09fb15e8f01a8d74e9e63959cb37336bc1b896ec78da734c15e362db04368fbba280f20a043e0d0941e9f5193e1b360a33c43b266524880125222e648f05f28be34ba3cabfc9c544", "98af454d7fa3706dfaafbf58c3f9944868b57f68f493987347a69fce19865febba0407a16b4e82065035651f0b1e0327"],
		[1024, 1024, "d3090c72167517f7c7ad82a70c2fd3f6443f608301591e598eadb195e8357135ba26fede2ee187417f816048d00fc23512737a2113709a77e4170c49a94b7fdff45ff579a72287743102e7766c35ca5abc5dfe2f63a1e726ce5fbd2926db03a2dd18b03fc1508a9aac45eb362440203a323e09edee6324ee2e37b4432c1867ed", "cb41f1706cde09651203c2d0efbaddf847a0d315cb2e53ff8bac41da0002672e920244c66e02d5f0dad3e94c42bb65f0d14157decf4105ef5609d5b0984457c1", "211ac479e9961141da3aac19d320a1dbbbfad55d2dce87e6a345fcd58e36827597378432b482d89bad44dddb13e6ad86e0ee1e0882b4eb0cd6a181e9685e18dd302ebb3aa74502c06254dcadfb2bd45d288f82366b7afc3bc0f6b1a3c2e8f84d37fbedd07a3f8fcff84faf24c53c11da600aaa118e76cfdcb366d0b3f7729dce"],
		[1024, 264, "d3090c72167517f7c7ad82a70c2fd3f6443f608301591e598eadb195e8357135ba26fede2ee187417f816048d00fc23512737a2113709a77e4170c49a94b7fdff45ff579a72287743102e7766c35ca5abc5dfe2f63a1e726ce5fbd2926db03a2dd18b03fc1508a9aac45eb362440203a323e09edee6324ee2e37b4432c1867ed", "cb41f1706cde09651203c2d0efbaddf847a0d315cb2e53ff8bac41da0002672e920244c66e02d5f0dad3e94c42bb65f0d14157decf4105ef5609d5b0984457c1935df3061ff06e9f204192ba11e5bb2cac0430c1c370cb3d113fea5ec1021eb875e5946d7a96ac69a1626c6206b7252736f24253c9ee9b85eb852dfc81463134", "dc1d253b7cadbdaef18503b1809a7f1d4f8c323b7f6f8ca50b76d3864649ce1c7d"],
		[1024, 520, "d3090c72167517f7c7ad82a70c2fd3f6443f608301591e598eadb195e8357135ba26fede2ee187417f816048d00fc23512737a2113709a77e4170c49a94b7fdff45ff579a72287743102e7766c35ca5abc5dfe2f63a1e726ce5fbd2926db03a2dd18b03fc1508a9aac45eb362440203a323e09edee6324ee2e37b4432c1867ed", "cb41f1706cde09651203c2d0efbaddf847a0d315cb2e53ff8bac41da0002672e920244c66e02d5f0dad3e94c42bb65f0d14157decf4105ef5609d5b0984457c1935df3061ff06e9f204192ba11e5bb2cac0430c1c370cb3d113fea5ec1021eb875e5946d7a96ac69a1626c6206b7252736f24253c9ee9b85eb852dfc814631346c", "decd79578d12bf6806530c382230a2c7836429c70cac941179e1dd982938bab91fb6f3638df1cc1ef615ecfc4249e5aca8a73c4c1eebef662a836d0be903b00146"],
		[1024, 1032, "d3090c72167517f7c7ad82a70c2fd3f6443f608301591e598eadb195e8357135ba26fede2ee187417f816048d00fc23512737a2113709a77e4170c49a94b7fdff45ff579a72287743102e7766c35ca5abc5dfe2f63a1e726ce5fbd2926db03a2dd18b03fc1508a9aac45eb362440203a323e09edee6324ee2e37b4432c1867ed", "cb41f1706cde09651203c2d0efbaddf847a0d315cb2e53ff8bac41da0002672e920244c66e02d5f0dad3e94c42bb65f0d14157decf4105ef5609d5b0984457c1935df3061ff06e9f204192ba11e5bb2cac0430c1c370cb3d113fea5ec1021eb875e5946d7a96ac69a1626c6206b7252736f24253c9ee9b85eb852dfc814631346c042eb4187aa1c015a4767032c0bb28f076b66485f51531c12e948f47dbc2cb904a4b75d1e8a6d931dab4a07e0a54d1bb5b55e602141746bd09fb15e8f01a8d74e9e63959cb37336bc1b896ec78da734c15e362db04368fbba280f20a043e0d0941e9f5193e1b360a33c43b266524880125222e648f05f28be34ba3cabfc9c544", "440fe691e04f1fed8c253d6c4670646156f33fffaea702de9445df5739eb960cecf85d56e2e6860a610211a5c909932ab774b978aa0b0d5bbce82775172ab12dceddd51d1eb030057ce61bea6c18f6bb368d26ae76a9e44a962eb132e6c42c25d9fecc4f13348300ca55c78e0990de96c1ae24eb3ee3324782c93dd628260a2c8d"],
		[1024, 1024, "d3090c72167517f7c7ad82a70c2fd3f6443f608301591e598eadb195e8357135ba26fede2ee187417f816048d00fc23512737a2113709a77e4170c49a94b7fdff45ff579a72287743102e7766c35ca5abc5dfe2f63a1e726ce5fbd2926db03a2dd18b03fc1508a9aac45eb362440203a323e09edee6324ee2e37b4432c1867ed696e6c9db1e6abea026288954a9c2d5758d7c5db7c9e48aa3d21cae3d977a7c3926066aa393dbd538dd0c30da8916c8757f24c18488014668a2627163a37b261833dc2f8c3c56b1b2e0be21fd3fbdb507b2950b77a6cc02efb393e57419383a920767bca2c972107aa61384542d47cbfb82cfe5c415389d1b0a2d74e2c5da851", "cb41f1706cde09651203c2d0efbaddf847a0d315cb2e53ff8bac41da0002672e920244c66e02d5f0dad3e94c42bb65f0d14157decf4105ef5609d5b0984457c1935df3061ff06e9f204192ba11e5bb2cac0430c1c370cb3d113fea5ec1021eb875e5946d7a96ac69a1626c6206b7252736f24253c9ee9b85eb852dfc814631346c", "46a42b0d7b8679f8fcea156c072cf9833c468a7d59ac5e5d326957d60dfe1cdfb27eb54c760b9e049fda47f0b847ac68d6b340c02c39d4a18c1bdfece3f405fae8aa848bdbefe3a4c277a095e921228618d3be8bd1999a071682810de748440ad416a97742cc9e8a9b85455b1d76472cf562f525116698d5cd0a35ddf86e7f8a"],
	];

	for (var i = 0; i < testVectors.length; i++) {
		var vector = testVectors[i];
		// blockSize, outputSize, message, key, digest

		var block_bitlen = vector[0];
		var output_bitlen = vector[1];
		var m = Buffer.from(vector[2], 'hex');
		var key = Buffer.from(vector[3], 'hex');
		var expected = Buffer.from(vector[4].replace(/[ \:]/g, ''), 'hex');
		var repeat = 1;

		var hmac = jCastle.hmac.create('skein-'+block_bitlen);

		hmac.start({key: key, outputBits: output_bitlen}); // important!

		for (var j = 0; j < repeat; j++) {
			hmac.update(m);
		}

		var h = hmac.finalize();

		assert.ok(h.equals(expected), "Message Digest test passed!");
	}

});