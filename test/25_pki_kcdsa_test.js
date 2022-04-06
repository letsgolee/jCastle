const jCastle = require('../lib/index');
const BigInteger = require('../lib/biginteger');
const QUnit = require('qunit');

QUnit.module('KCDSA');

QUnit.test('Vector Test', function(assert) {
	// [KISA-WP-2011-0022]_최종보고서.pdf

	var M = "This is a test message for KCDSA usage!";

	var testVectors = [
		{
			pBits: 1024,
			qBits: 160,
			hashAlgo: 'has-160',
			Q: `c3ddd371 7bf05b8f 8dd725c1 62f0b943 2c6f77fb`,
			P: `d7b9afc1 04f4d53f 737db88d 6bf77e12 cd7ec3d7 1cbe3cb7
				4cd224bf f348154a fba6bfed 797044df c655dcc2 0c952c0e
				c43a97e1 ad67e687 d10729ca f622845d 162afca8 f0248cc4
				12b3596c 4c5d3384 f7e25ee6 44ba87bb 09b164fb 465477b8
				7fdba5ea a400ffa0 925714ae 19464ffa cead3a97 50d12194
				8ab2d8d6 5c82379f`,
			G: `50e414c7 a56892d1 ad633e42 d5cd8346 f2c09808 111c772c
				c30b0c54 4102c27e 7b5f9bec 57b9df2a 15312891 9d795e46
				652b2a07 2e1f2517 f2a3afff 5815253a aefe3572 4cfa1af6
				afce3a6b 41e3d0e1 3bed0eff 54383c46 65e69b47 ba79bbc3
				339f86b9 be2b5889 4a18b201 afc41fe3 a0d93d31 25efda79
				bc50dbbb 2c3ab639`,
			X: `068c4ef3 55d8b6f5 3eff1df6 f243f985 63896c58`,
			Y: `96dce0e7 b2f17009 3d9b51d2 ba782027 33b62c40 6d376975
				8b3e0cbb a1ff6c78 727a3570 3cb6bc24 76c3c293 743dfee9
				4aa4b9ef a9a17fa6 bf790ac2 5a82c615 23f50aba ac7b6464
				7eb15c95 7b07f5ed 7d467243 089f7469 5cd58fbf 57920cc0
				c05d4582 9c0a8161 b943f184 51845760 ed096540 e78aa975
				0b03d024 48cbf8de`,
			Z: `23f50aba ac7b6464 7eb15c95 7b07f5ed 7d467243
				089f7469 5cd58fbf 57920cc0 c05d4582 9c0a8161
				b943f184 51845760 ed096540 e78aa975 0b03d024
				48cbf8de`,
			K: `4b037e4b 573bb7e3 34cad0a7 0bed6b58 81df9e8e`,
			W: `0d2ace49 f0415880 843e4cff 2a224dcc a4d12a79 11323aac
				e1eaf5b4 f479a91f 94d01820 193d40a5 f71347e3 8f97ef41
				8bd25959 879ea7f6 2d3fbaa7 e70a9d78 b8dc7933 00bbf669
				0829961a ab4e59a8 410510da ada05ef8 7e48144d 6efe5075
				29011382 38c84b5d 2c3f590c 06e1b918 7ee5d509 e15ccab2
				c257d549 ac1a5086`,
			R: `8f996a98 eda57cc8 d88aa6ff dfaea22f 39d7fa8a`,
			H: `af3fb04b 0703c6ea 5608d89b 38c33b35 9cbca2b0`,
			S: `541f7dc4 f92c65eb 7f63b6b4 f22177f1 ee2cf339`
		},
		{
			pBits: 2048,
			qBits: 224,
			hashAlgo: 'sha-224',
			Q: `c223aad2 e86ecb17 11921a23 36d7eba9 b0d3dc82 4224a4cd
				db5ef0b7`,
			P: `d478f35f 01c72832 bcbbd508 c4a340f4 33dcd60b 2e023c94
				1fda5a09 3a220727 73b3d962 af981c9e a037edcc edfc63a5
				02d0dc9b 3e708789 4cf9b159 56b7bac8 da216b66 bddbe71e
				28e2f828 490aff3c 8d36be50 41728f4f ee34f7f1 9ab8a6ae
				6fe6fe65 13a504c1 99a83b88 707f43c7 d0913c9a 26c80fb3
				861a698a 562c919b ffa798a0 6966d588 2822e448 e686bca6
				08d83ef7 35937988 d65398ca aa995e98 e53eb9a1 8cd0e05c
				33ad0950 e2b87402 fc284972 3f69d564 62aaa089 57bb45ff
				854792c6 337247b6 888d0cf0 016e83d1 29e47c80 9a1bc68f
				83739502 8e9b1658 d5c178ec 1678a6fd 1daf0e0a 41f4b6ce
				bb642cec cb749ada 0fd4a2ba 94426efb`,
			G: `cc824e25 383509a0 22781161 e3d2af50 9ae9184d 2751ccb3
				3f6b8fad e18d86c6 a2ad3b06 d9899118 57d26c59 f1fa85fb
				fb14e3d3 393cc3f2 fcf9da68 65014fc9 b3e8c8c0 f8295f82
				76bac6f6 944f56de eb48ab86 218f4071 33471505 e3b33c7b
				ea69108a 643267da 36e0762e 570b9b61 57897992 d0f7806f
				d6de0773 d61657db 882d634c 8bd05403 3f2b34f2 28fc89b9
				c5df6524 3a628121 34845b14 302c25fa d3ca1c92 fa552c5a
				f2ddfbe8 a67f03a3 79ac791f c196d204 c505558e 789ae98f
				aa1ce7fe 8dc7555a c6abbbb7 3d779f3d 1db8038f 22d2baf2
				4e8adec1 5f6209de 61e058cc 2913047d c071cb90 b0769ce2
				296a5daa f94201df 82de0343 de50333f`,
			X: `12f3f124 ae8f9da6 9fbc0a60 63ac018c 002786f2 760daca3
				e918d1e4`,
			Y: `62b69417 15910140 965e3540 0d865480 43ba1f66 54d1d38f
				8c988506 0d001498 a2d3d5eb 44393eeb 5f42d776 31329e1e
				937a4c09 1fcc4f52 98a0d5e9 04b40716 a7155c7c 4c5db673
				9c748031 a9651723 7c79358c 1069d463 2d2b73d3 2a559310
				84f4064b 18ae05e3 a8c1ae9a dcb28803 bb367399 c3edfbd7
				91f75ecb 90955692 8ee2ce97 782d5ed7 70ea668e 0dec254e
				fffad320 67a4957e be2accc3 62054775 af0cd032 44d6615b
				0037b53b 67ef2521 847aa797 7cf831cf 6b54b862 f36f5197
				632b074a 2b0cc9b0 eaf6c473 20e7f30c 6042d052 1dbe7690
				1768fe8e 9832a973 1b31ff67 53918fdd 0ff774de 5c06292f
				091a763d fef8c4d7 2925e054 6c0d69c0`,
			Z: `632b074a 2b0cc9b0 eaf6c473 20e7f30c 6042d052
				1dbe7690 1768fe8e 9832a973 1b31ff67 53918fdd
				0ff774de 5c06292f 091a763d fef8c4d7 2925e054
				6c0d69c0`,
			K: `10a3d44a 23d8204b 88aa4c1b 33806aeb 825354e9 2f986d44
				532f4441`,
			W: `5088aac8 9570eb88 13e45703 98c135c9 d093939e d109d56e
				be18b66e 07266548 978ef116 b29c8629 d5d2fda0 42f49610
				b8fc3ae4 d2c1fe01 4e29cd1d f4214ffd 14fa95fd 8f61240b
				52f33508 09b5be2a ec7453e4 5ae67b88 e01d72cf 69a9768c
				0d790f9c c8b59b29 1ca78d79 d983f091 e40f657e 35862078
				35e0e80a baf79489 a20fb02b e225a924 7b94eb0d f02d0472
				2887b7e8 ee3cf107 1510f70f 3e3080df e3d91c6f 4d0635cf
				41ab730a 076209b1 2da6683a ce215d30 56687c28 f89e8e30
				1a60490b 10cf98fd d00bfcad 56b4846e 897fd005 661df40c
				f5df0027 b5ee9421 093e9c40 7474274c 55557cad b2c1bd20
				61379cf5 e4694214 ccd4d330 9c06c8c3`,
			R: `59f4d18d 4068e5f9 fff1fd6c ef7e3a1a 0a2d4671
				000bf7d0 a236ff01`,
			H: `c674ea6a 3f67e261 32bfef0d 2644f597 651a6669
				d5ae4c69 7ced894b`,
			S: `74e33c8c cd2a4816 18087e91 f8c1ddec f0b3ffa7 b1c84314
				dca4a430`
		},
		{
			pBits: 2048,
			qBits: 256,
			hashAlgo: 'sha-256',
			Q: `dedc989a d0f984cd 4d3e54bf aebc2dd1 de19152c 49aa526d
				da4cab54 879ffb2d`,
			P: `f4119d06 45045e98 3045e27e 74ec6352 81ed1d9d 3a7053ff
				e519994b 98671be7 3f044683 6904aea9 b853aa32 a46169cc
				4d0106d7 da4b16be 41b5853d 31df183f 4fd3b8f9 81b94269
				312fef6f 15ee9e1f da146179 a91daa7e b855d6a8 425fbbab
				501c525f 733e0bc2 d3371370 a93b34bf 633d7e8d efa5601f
				233a69ac 91050162 f33d57fd bb3fa870 5a4b59a9 76bb4847
				8ce6ef8e 170d91f1 9cd36e17 d006855e e6616301 ff9b3c3f
				291c3db9 132cebcb 786582a7 5c027bd1 8e568d92 979b0d33
				f571871a ca50755b a13a2d66 d7bcaa6c 53767bc7 c25a9967
				c033af3a 34b23070 c11b43e6 ceb1c584 7f69db51 f069fb57
				5e88dacf d264970b 0b4bdaaa c55ed467`,
			G: `cf565bc4 f9628539 bf780966 2cc58dfe 6e8243de e7c3af77
				abc65dec 969b77be 8871afa3 4498d376 11c854e0 03c8928c
				11c3f27c 18ba1a09 b0628bae d37dc3e9 83026ae7 17cda927
				829a7f7b 5aa1aa6c e0112880 61ebeb69 2c7d6843 46c1878c
				c4a45067 eb927494 dd3202d6 c8fba6b3 8352d407 858ad3aa
				19b3e09f 2b75c849 df191568 0b8d4a35 c0ead2da 4436432f
				cdcbbcc4 3b74d12f 266f4ae0 2d2e5538 530ec3ce 15f719d4
				e86fdca8 892e0cfd f3e08d40 761b6d65 0b59e132 082bfdff
				64106e9b 85501a5c 7a63b85d da266923 cb5703b7 34f0a14c
				ab930343 0b4a9fc8 66da806a dad3da65 06fc2e32 5a12220f
				9593c2e5 f9f00358 5af63940 bb687369`,
			X: `2a37f3f2 af743c65 92828433 ed60543d e76d097f 4ac99d9d
				89b1a76b 0f72cf4d`,
			Y: `0a78a3c3 376c7169 7c6afc13 dde77bfd bb755517 f2b5ce76
				1955d536 5b0e76eb 3ebfacd6 b3514c1d d64b0269 533790c3
				72380efc 9bab77f2 55d476a1 3262dd53 8b76c880 bceeade5
				989cb259 2692c37c 6dc48bc8 1b556790 88f19fe1 edcaccd7
				0f40abd0 79d16f59 1bcce2b3 59151240 df6a5adc 1a8c4e17
				e2b78b5a 422f9d5d 7797320e e843e079 5ea691d8 358136d7
				71afc16f cdb33c7f 4aa12e6e e47d7ed2 7fd77fd6 6e3c11a2
				157a21e5 74cd3281 0f51a74c a2a93a33 b3e5579e 9a1efb06
				a006133f ff64af12 230f252b cd40174d abac5120 e01a7578
				6d964859 5360bce3 71015ef6 f4ebd843 304d1bf2 a7b763a8
				788c4f7f 206da4ec 2e5171dc eeb24fb7`,
			Z: `a006133f ff64af12 230f252b cd40174d abac5120
				e01a7578 6d964859 5360bce3 71015ef6 f4ebd843
				304d1bf2 a7b763a8 788c4f7f 206da4ec 2e5171dc
				eeb24fb7`,
			K: `95ce2d19 4c86bc96 f60abd47 9f1a9f43 8a348714 8104fec0
				8218f0c7 ab574b9d`,
			W: `87402b17 b90c595a a712a9c0 72e3cc18 14c37d21 a83ca38e
				54e12626 8b43c19d 540edcf1 6213039b 86f9ac6e 2f763bd3
				866c20d7 a01cc18b 1533e201 0ea3612d d9c2b4b0 039a73fd
				15f07e71 f66941a4 085c4904 2aed20db fd7a5f33 a38333db
				fd680216 6d80f7a1 2bf1da59 775fc5ea 4475da50 6c4244c8
				b23126af a6497bab 6e7a49b6 c6a2f9a9 ae27f405 5866f3d2
				ce0aa8cf ad3f1031 268fb5ea 77620c35 7a500ffb ec777cb8
				c62314d8 83ed40e4 559917f6 a3de17a3 f1a5da6e 0109c467
				b6fcf817 29710047 32ee549b 0d2b9907 73b91a48 cc203f20
				ebfab841 b7849a48 eddbac59 b869ac0a e2bfcfee 12ecfcd7
				03322f99 b7732435 97560efb e06c8d06`,
			R: `11767369 438be94c 930e9d34 4856057b 65818275
				f7fb1efa f248e71f 4af981b7`,
			H: `741c9860 5c76d982 c7bbfa10 5116a737 7d757b03
				9cf2abe9 ae523cd3 cca80aa2`,
			S: `c2d57c58 8bb2a3f3 cf705162 564b6660 d28a88f9 c732603b
				447bf1b1 5801016c`
		},
		{
			pBits: 3072,
			qBits: 256,
			hashAlgo: 'sha-256',
			Q: `dc121d3f 13ec39ec b4bd4fc6 d08d2c1b f66562b1 e4d3f344
				a2546f11 51821293`,
			P: `f491f199 36144931 fd42b3a8 00f6df74 2730ca32 5d622bd2
				3bf0dec9 cca51d1d 1b79bf70 5a88c7ba 943e0691 1aff7c2c
				b9a2ffbe 31168532 38b13517 4e1107ae f0914497 62b2aa48
				aeb1bd32 37e615c3 ecc491aa bbf1d93f ea956530 f971b7c4
				4b165c68 c4f3de5f 153847ff ac8d49aa bfcb3b80 86a835d1
				4d6cfa51 65725807 6144536a b74c53c5 771c70a3 6aecbbc4
				64c01425 7e275642 e403b40d fef0953c 9f3bfdf4 82de7805
				7a2bf103 fd786b3e fe53a7cf 1eef8c26 893c5568 f5b72c93
				908407a5 0ca5a13b 0e685d4d 975b7545 ac34bb91 1e577533
				1d392a26 b74b487d 27239f4e da51a8ed 926dee4b 996386e8
				0f3b3b5a b90e3b4a 32f445b5 0f94fb0c 438f825d 70d8ff2a
				79157abb 6790e303 d6479fb7 a07559e4 3099f396 891eadef
				6999df55 885be17c 712a3c6f e98a8c4a 6f0fa344 fe06a5f9
				ab187609 52ff2d60 b27130b7 bd4dab8e 6c4e296b 68bcded9
				bb770eb6 38eb4ed1 2df66674 50e77d28 27539706 02388bff
				bf036bd7 1e0d2fa4 55c3098c ef627aba 02986336 64650bf7`,
			G: `7c54f18f e661e6d5 04674614 0617e24e c360e330 e95661a5
				de38f42c 31485806 b473b114 1bb966ce c1946c96 92e46aa1
				adc4c58d 69ac60ce 12344ad9 b5661112 e234848b d50060ae
				1d948050 d028c5ec 09b40f80 e9c42195 9b61d425 7a003578
				7334d152 18531645 f1ae34f9 54c8a309 057a4516 52a594f3
				7e593a49 bce07bcb a4efa9a5 55e61355 c3741055 a19e518c
				e735c1b6 2d537b72 21004cd1 7c635484 8e4a2e73 c590b4e9
				7387a108 e312fe34 91a1e776 28be5ea1 2e44f298 33e32144
				9e1d4666 d20fc8c2 ea308945 c481e831 c79f1c71 884adb1f
				0e4c21f4 5d4698f8 ea76710e c36e698e a56192d3 5dfc35d8
				cf214651 b844d4fa 1f415230 69613238 c802afec f3943381
				35facb29 71427bd0 b237c824 57b56e8c e2e5c1db bd81d155
				88c31beb b8ed7ee2 45013ce2 583d9926 53bfd3b9 761ea408
				1d01df80 4100be09 daa014d8 76abfc72 851967c7 1d33be57
				5878a02b 9342692d 54790f8e e525e1b7 b4ff0b49 6866d469
				9618c1e8 c9bf0d69 458c3abd c957f443 0ade37f8 2000c071`,
			X: `29bbbf8a 756f376b 6e6d34ab e8aa3334 dc7053ec d1a0c961
				8b26decd bdde8498`,
			Y: `0a7e0f20 5a06a8f5 28759c8c 993becd3 e495571b 21a1da64
				a1c3eae5 6bc60824 dfa3d9c8 c6845df3 e7022f4b bcab8b85
				62e96254 3c46229d 056fc716 b173e515 e9fe490d a9afaea9
				c56c1fb3 05832fac 2f406ab0 16b94ee0 827ba2f6 f91a51f5
				d3e4fc9f 0daac7e7 2cdd2154 b57bbf7e 0ed04814 d04ecd7f
				82a6da88 cfb65b80 3fdf6428 51f05fdc d6eab055 f01567aa
				0504f1d8 a9536a73 da4c6e6b 6e48b675 433b7350 e39f12dc
				6a9e85aa cea4e958 e0e07212 5622de36 e7f69ef3 64bac1e0
				8cb43f7c a5663e19 3c907d80 c7c9e3a8 b06616f9 9fa0b358
				3e5c17f0 2848cb2b eb13400b 2b37cacf 9b3abe9c c9e05352
				9e218fa5 84a07be8 ea090ab8 f5a9116f b715b0d8 053b3448
				02b2ba6f dac790b2 3aaebf9a 0ae3914e 5a1d4cfc 58c8528f
				f953b937 0e1682a9 4192860a d18106ee f8812f74 687ec12c
				e7f83d23 19c06d96 a6c02fba 09894810 78f0e20f 22f90f31
				10ddac2d 97958f82 3068e1c9 ca58d05d 0778346f bd925654
				8259ba5c 1b07a144 5eae2623 d687dabd 496e1a9a 6029d8ac`,
			Z: `a6c02fba 09894810 78f0e20f 22f90f31 10ddac2d
				97958f82 3068e1c9 ca58d05d 0778346f bd925654
				8259ba5c 1b07a144 5eae2623 d687dabd 496e1a9a
				6029d8ac`,
			K: `9345c79a 66078f92 42596268 850efed8 e64c1734 5c66a8d7
				2d9ce471 2726c6f5`,
			W: `1233de1a 2b72938b 71baff66 93be5864 08360696 3182b7db
				1dc1430f 5d9e28e7 12a1f2a4 d3104558 6406ea77 10681e31
				dc1b69e1 33b8265d bc8d677c ef0576a4 60042049 c7a975ee
				59f3cc0e 2c01ecce 2d2d698c 154ebd2f 6dcbaca9 cc6f341c
				ab8bcdfe 05a64bdd 1a4f2166 438e27d1 05721e5d 9bbd6bce
				3143e306 775bb22f 29548606 f8470d23 1782a6ca 02d6ea24
				0129067c a80527c0 5155af27 00c842f0 b41188f1 351ce9ee
				f11379a8 0fb53400 c232ac09 e2f6240d f62b374e a84bc389
				4ca416a3 4f13df2a 0b659bb5 c2e72f88 d1ddefd1 2e4d3638
				2957b9ce 15344fb5 88bb0145 d8dc86e4 98559a9e 148059b5
				b4540736 dad5f674 d14614db 3e318149 dcb1b17c 408cf9a2
				531d24c4 c966de0c 14692fe2 9b0dd459 3f6c7854 8754a0f6
				c10fc265 cec97e72 d6ac9af5 ff121f3a ed4427fb e776f6d4
				bb2bab5c c8d365bd c629e4bb b683735d 15458bb8 8ab6220e
				9e8d91bc b16f5bae dcea62a2 c0c452fe 3961d584 ec0e210e
				c3e46149 4c85cf3e 20ab147a dd4e2574 070de83c 9127bd5f`,
			R: `41f53dea c47f0b1e 0f34557f a3a29d4c f461d4d9
				6d8d5bee d08c46da 279eb96d`,
			H: `ed712b01 8e597106 aa8b3daf 0e9a4379 987150e7
				6a18e94b 21e07c50 cccaf681`,
			S: `196c86f8 f898c95d 345c60f3 7f807eec af1a4686 b2ddd395
				6ba0b34c 7533125a`
		},
		{
			pBits: 2048,
			qBits: 224,
			hashAlgo: 'sha-224',
			Q: `82755938 4DCAC1E2 64F965AB 254C64D6 52F89420 CDE6917A 05F65871`,
			P: `88D3A57A FA058CB5 02A3023B AA907A86 55DA97F9 27B7B24A B456FF6C 9811097A
				80544BCD 664CC68D E3964324 AA9E203F D14F6CAC E2783EA9 F534AD00 2C976BC5
				B02C78BC D5059F59 5E89D310 D085AEA9 BE0E17F9 60C73AE1 3EC6F339 951938BF
				6DD5B220 03004AE3 FD746CD6 308DF9D9 A9A9468A 97AAA120 B71669CF F502BE27
				80D8AF84 C29FA801 345EED31 CCBDB952 F4166A60 16A8DAD6 186DBEAA 93A04DBF
				41565036 A5D4D44B 37885E9B 45D3B621 E9B7A648 65FB0AC0 96862C08 29AC541B
				B4CE7098 47FE20A2 095D0EBD 9F67197F 1F6CBC52 F0465403 EC04372E 8B9D1C7F
				B91F81F1 06E86253 0A51580D 03A0A74F 85E8F6F0 F944A562 1F66C4A2 0C31848F`,
			G: `501afc9ea043da06 d1d5834ac0bcef60 1b5006f7eecdad25 f57af4200cb466c2 78cbb620ee27569f
				3c25f7bb44f0e337 76a16548c58d88c9 6f2bc1d11839aa84 570dcdf683e8b4f5 7bd4b77cd79bb0cc
				2c566c68d86134b1 04a54195c563ff58 61e2be23d1c53a1e 3ec93c0d2b846d90 cf248bb7b0c16b97 
				2287c44e34ba853c ce01ff30cd44a9bc 3f6b11a228b33dc5 36fc1c620b43d618 1a3e9fe67901a642 
				a2c9c37939aaaeaf f189e19d1f54f6e9 70bc90a92edd24e1 a6fb2a5f57782f46 082214ff09253a8e 
				965daf5ec7317c03 0ea62c9fdf5fd526 d35237e3a1372778 aa10e77ab4818e32 e3c2920d1758ceb8 
				d9e359de3ffebee2 d2012cffacf2a225`,
			X: `464E82CA A3DA60DD BB3C3131 788973F3 4B5A7D80 B47BB161 92EDB2F9`,
			Y: `1AC2C5EB 5998D20E B2C73BE6 20D77E25 0BCBAD2B 7FE4C85D 26F649E3 A55D3A8C
				D5644E19 56E50481 E2BE2F61 F44F7AD0 77EEC771 097066C0 13C55A3C D5BF3906
				EAD40A8D A1025366 E867F388 B12042C4 06E31E26 B9F44308 14A52CFB B2C18E70
				66A260CC BD5CA4C0 F4404C53 E1695887 D6E5C867 DDFE4DD1 F7E94C94 7C73430D
				7EA8D6FE B342DB8C C04FD846 492A352E 675DCFF8 D0C1E31E EBE9D832 A823BA4C
				F8D94F76 2F8BE95F F3B38DD7 C035B94D 0F208F34 CBFF6569 ACADB384 C4F6A1D5
				66B0E76C 2DCB30DC 2282520E 39EECE08 DDC21457 1243F8EF 857F9D23 FBC6AE4F
				C459C1D8 0FA2E2FB 03C9E5D6 48B72C11 F4A27BC1 D36E0AD4 4B6F01DE 755EE957`,
			K: `53E52682 0786E334 345C8941 55575CEB 67E662D1 43FD33B5 FE84BA94`,
			W: `4FE47490 C452AFD3 42EC02E8 89822912 CBE73ECA 76BDD67E 1100C9FD C9B80136
				E7E4F9CA 6B7BBFEB 770BFFF6 43A7E975 F05E6671 E35483DC 7E72ACC3 24F5E9EA
				428BC7C0 23DD0CD8 BD47AD93 D03383D2 E0231B26 3824EDAE F5820B4F FB1D5601
				1D40144E B727611B BD6F2BC8 EEB6E19F 54A5E4A3 ECF04F74 1103C0F1 9C5FD233
				3CA06A7E C3B19D32 9251B79D F5AF4261 5B09B731 B36F5959 0D779148 CB7D1A62
				508C23C2 0D410C52 69035A3B 38241FA0 AE7DFA78 F4D7EE96 E89F5BE9 D9730AAA
				82153E6D 1EF9FADE 91568014 5EA952DD 8AA46CF7 25984797 F0F9DFBB B4C6471E
				FE395056 EF06CE65 0DBAEC7F 34B3FA67 6C17FEAF E00689F7 A9BC8EF0 C051B813`,
			R: `855505E2 90822C1C 67A121D8 89F4794F 0C9C510A D44BFC2F 1F569FEC`,
			Z: `66B0E76C 2DCB30DC 2282520E 39EECE08 DDC21457 1243F8EF 857F9D23 FBC6AE4F
				C459C1D8 0FA2E2FB 03C9E5D6 48B72C11 F4A27BC1 D36E0AD4 4B6F01DE 755EE957`,
			H: `48DA69AD 653ED0C6 52B0DBBC 5950B06C C29A1945 4DF8A1AC 93AD378C`,
			S: `3EF2F8DF F899CB15 E11C8ED1 D35C7DCF 0EDA1D54 1F806D5D 1730CF58`
		},
		{
			pBits: 2048,
			qBits: 256,
			hashAlgo: 'sha-256',
			Q: `B15362B9 71E23ED9 9C26CD53 5442A85B 181F7B94 D5E05B4A 25110175 FDA38443`,
			P: `B3F892B8 F5FD174B ED8BE901 CC64D664 9391BADD 54ED13BE DBE4EA7C DE0025AB
				6D4159FC 141B63B4 33597337 15D4EF8F 33AC2415 11C0D5E0 B30B7187 F649B399
				2C2F90F1 C174C637 8220039D B68EB148 399FD08E B748C61D F53AAED1 B623A020
				41C4C262 D7A15F0B 9CE9D812 3A7F4E12 D44FE5F7 5AC14351 B606F0C1 DFD6F640
				E57921A8 04E45358 D765E1A0 960B973C 961DD627 0FDF5E15 53F1D8E2 BAE7B997
				D8B5E8B9 8DEA2E76 79BF1B1A EA3BA5EF 97CBA400 16E51BD7 81B3296A 7F0A72CE
				DF13C66A 003F6029 8A325104 1F548AC3 579DE845 3819D239 C1566B9E BEC02678
				E3541FF9 58A8E30E 456D13F0 9E8042DD E32F9E47 B47DB2A6 541D6EE4 ACAD0A0B`,
			G: `12CDA8EB 2FF484DF B55E8CCF AA73ABB3 17E79792 95C86F0B 6E687CE2 AA37038B
				E2404C73 C1522931 26313062 4131A1CD 960B828C 4C3543B1 AC64DAD7 74E593F3
				41758188 F829F08C 846ECF46 F8881300 831415F9 CF0FA6D2 72948044 F5670CE0
				7EE54119 FE9400D9 8AFF8F12 97D13CC9 88800C79 FD64C393 55E6F9ED C3D12F50
				468385FB CB1D4344 8695B3EE 6A6EF903 DA0964BB 2D267D2C D2476986 9372BD36
				F7FF0F67 976A5EE9 0C8E43AE 8FDF8B47 29933D56 910D38C5 99D4D548 E577723F
				4367752D 1F506E99 803329DC DE83F185 3186F8C7 1D6E0011 49F943F7 D197B977
				4BC4840E F9EC8281 A41413AA ADCF4AC0 2FD58F45 325C2EC9 132E53DF C61B8E33`,
			X: `284826CA DA3F9892 D6EE6B2D 3B639D8A 5FB53922 8A386105 7EAED49F E2BF4D1E`,
			Y: `13D376FC 6C969CB7 DFC03837 51D93C4A 20F64072 5BE51604 0707A595 F0659241
				DE4598F9 FE4ACE9D FF302C03 6B92149E E72DD727 E2A9BDA8 EAB56DB4 60EAEAA5
				44BF0BA3 66B6A316 1CC058EF 2522CF26 15406747 7C3B3173 DCFC7AE5 4555438D
				50F91D3A 16101156 5908D6B5 887710B4 01F75353 8597FD25 1FC8728F 196A6756
				07A4A706 1430E776 A3D0A7F5 D6DA7D80 6E8A656E 09B18965 AC46CC12 25CFACB9
				DAAF369E 2CD1DFBC D790F0A2 7230596C EF6D5687 F8D99B93 4775CFCA 9B16043A
				8E9ED34B 3B9A8291 C2A1E38F F8E095CC 872443C8 81B05DB7 DAD3A60E 9518EA91
				81D64207 4D4D37AA E94D8FE6 7A2426C9 CE0706C4 D9EFBFEA 7019E82C 58A570C9`,
			K: `345927E3 9B09743D 1F26A2B3 F7C696E7 6F0E5492 9E957A55 7ABA2940 70745143`,
			W: `7170BDF4 85328944 8CE972E7 4D15C873 748CCCA4 68EA5F9E 44A89C4E 81F02993
				3829A8FB A4FB4DCD 217F5BD2 AAF1964A A22ED5A5 D3E1EE60 F4AB0CDA E0AEE988
				B447D43C E37BA9C9 BB67DDEF 89F60E02 F096A16A 039C5CDB E8FACC9B A6EDE6FA
				1B75D46A 8CD2C8FD A45618ED 89FAC35C 9FE0C4CE CAFB315E 833A2ADB 91A470D8
				1B5B69F7 C3B86F05 D022B338 AAF4F615 93FBDD6B 2982F9BF B7D54AFF 9F8D1CB3
				1486CBED 4B70326D 408951FF 243615DB CB1221CB 410B6C50 7B93BBBE 1EDA51CC
				21431213 3B884E32 BAD270A4 DD3411AF 0A1F98D7 39378413 824252A6 62ABC71C
				05886CAC 13548338 0B66EA2A 97F6055F C4E83EBF B56E405E BA27310C CC0FED55`,
			R: `1F571639 7ECC3407 EA4B8B56 7457B725 6E71026A 2365C532 3421843E 75DF52C9`,
			Z: `8E9ED34B 3B9A8291 C2A1E38F F8E095CC 872443C8 81B05DB7 DAD3A60E 9518EA91 
				81D64207 4D4D37AA E94D8FE6 7A2426C9 CE0706C4 D9EFBFEA 7019E82C 58A570C9`,
			H: `61242425 D9A68C5E 0D485E4B E8B2CC5B B6CAA794 5A28A3D3 458F7466 44DA9E59`,
			S: `9568B0C6 77172C86 CB980FD1 842A8535 E656EF90 B6632FBE 4D572196 8721A40D`

		}
	];

	var zero = BigInteger.valueOf(0);
	var one = BigInteger.valueOf(1);

	for (var i = 0; i < testVectors.length; i++) {
		var vector = testVectors[i];

		var p = Buffer.from(vector.P.replace(/[^0-9A-F]/gi, ''), 'hex');
		var q = Buffer.from(vector.Q.replace(/[^0-9A-F]/gi, ''), 'hex');
		var g = Buffer.from(vector.G.replace(/[^0-9A-F]/gi, ''), 'hex');
		var x = Buffer.from(vector.X.replace(/[^0-9A-F]/gi, ''), 'hex');
		var y = Buffer.from(vector.Y.replace(/[^0-9A-F]/gi, ''), 'hex');
		var Z = Buffer.from(vector.Z.replace(/[^0-9A-F]/gi, ''), 'hex');
		var K = Buffer.from(vector.K.replace(/[^0-9A-F]/gi, ''), 'hex');
		var W = Buffer.from(vector.W.replace(/[^0-9A-F]/gi, ''), 'hex');
		var R = Buffer.from(vector.R.replace(/[^0-9A-F]/gi, ''), 'hex');
		var H = Buffer.from(vector.H.replace(/[^0-9A-F]/gi, ''), 'hex');
		var S = Buffer.from(vector.S.replace(/[^0-9A-F]/gi, ''), 'hex');

		var kcdsa = new jCastle.pki.kcdsa();
		kcdsa.setParameters(p, q, g);
		kcdsa.setPrivateKey(x);

		var pubkey = kcdsa.getPublicKey();
		var pubkey_buf = Buffer.from(pubkey.toByteArrayUnsigned());

		assert.ok(pubkey_buf.equals(y), 'public key test');

		var params = kcdsa.getParameters('object');
		var privkey = kcdsa.getPrivateKey();

		// signing test

		var hash_algo = vector.hashAlgo;
		hash_algo = jCastle.digest.getValidAlgoName(hash_algo);

		var ba = Buffer.from(M);

		var l = jCastle.digest.getBlockSize(hash_algo) * 8;
		var z = Buffer.from(pubkey.mod(one.shiftLeft(l)).toByteArrayUnsigned());

		assert.ok(z.equals(Z), 'z test');

		var h = jCastle.digest.create(hash_algo).start().update(z).update(ba).finalize();

		assert.ok(h.equals(H), 'h test');

		var h_bi = BigInteger.fromByteArrayUnsigned(h);
		var k = BigInteger.fromByteArrayUnsigned(K);
		var w = params.g.modPow(k, params.p);

		var w_buf = Buffer.from(w.toByteArrayUnsigned());

		assert.ok(w_buf.equals(W), 'w test');


		var r = new jCastle.digest(hash_algo).digest(w_buf);

		assert.ok(r.equals(R), 'r test');

		var r_bi = BigInteger.fromByteArrayUnsigned(r);

		var e = r_bi.xor(h_bi).mod(params.q);

		var s = privkey.multiply(k.subtract(e)).mod(params.q);

		assert.ok(s.equals(BigInteger.fromByteArrayUnsigned(S)), 's test');

		// verifying test

		var u1 = pubkey.modPow(s, params.p);
		var u2 = params.g.modPow(e, params.p);
		var w = u1.multiply(u2).mod(params.p);

		var w_buf = Buffer.from(w.toByteArrayUnsigned());

		assert.ok(w_buf.equals(W), 'w test 2');

		// finally checks if  r = h(w'). 
		var v = new jCastle.digest(hash_algo).digest(w_buf);
		v = BigInteger.fromByteArrayUnsigned(v);
				
		// If v == r, the digital signature is valid.
		assert.ok(v.compareTo(r_bi) == 0, 'verify test');

	}

});

QUnit.test("Step Test", function(assert) {


	var p = "d7b9afc1 04f4d53f 737db88d 6bf77e12 cd7ec3d7 1cbe3cb7"+
			"4cd224bf f348154a fba6bfed 797044df c655dcc2 0c952c0e"+
			"c43a97e1 ad67e687 d10729ca f622845d 162afca8 f0248cc4"+
			"12b3596c 4c5d3384 f7e25ee6 44ba87bb 09b164fb 465477b8"+
			"7fdba5ea a400ffa0 925714ae 19464ffa cead3a97 50d12194"+
			"8ab2d8d6 5c82379f";

	var q = "c3ddd371 7bf05b8f 8dd725c1 62f0b943 2c6f77fb";

	var g = "50e414c7 a56892d1 ad633e42 d5cd8346 f2c09808 111c772c"+
			"c30b0c54 4102c27e 7b5f9bec 57b9df2a 15312891 9d795e46"+
			"652b2a07 2e1f2517 f2a3afff 5815253a aefe3572 4cfa1af6"+
			"afce3a6b 41e3d0e1 3bed0eff 54383c46 65e69b47 ba79bbc3"+
			"339f86b9 be2b5889 4a18b201 afc41fe3 a0d93d31 25efda79"+
			"bc50dbbb 2c3ab639";

	var x = "068c4ef3 55d8b6f5 3eff1df6 f243f985 63896c58";

	var y = "96dce0e7 b2f17009 3d9b51d2 ba782027 33b62c40 6d376975"+
			"8b3e0cbb a1ff6c78 727a3570 3cb6bc24 76c3c293 743dfee9"+
			"4aa4b9ef a9a17fa6 bf790ac2 5a82c615 23f50aba ac7b6464"+
			"7eb15c95 7b07f5ed 7d467243 089f7469 5cd58fbf 57920cc0"+
			"c05d4582 9c0a8161 b943f184 51845760 ed096540 e78aa975"+
			"0b03d024 48cbf8de";

	var z = "23 f5 0a ba ac 7b 64 64 7e b1 5c 95 7b 07 f5 ed 7d 46 72 43"+
			"08 9f 74 69 5c d5 8f bf 57 92 0c c0 c0 5d 45 82 9c 0a 81 61"+
			"b9 43 f1 84 51 84 57 60 ed 09 65 40 e7 8a a9 75 0b 03 d0 24"+
			"48 cb f8 de";

	var m = "This is a test message for KCDSA usage!";
	//var m = "54 68 69 73 20 69 73 20 61 20 74 65 73 74 20 6d 65 73 73 61"+
	//		"67 65 20 66 6f 72 20 4b 43 44 53 41 20 75 73 61 67 65 21";

    var H = 'af 3f b0 4b 07 03 c6 ea 56 08 d8 9b 38 c3 3b 35 9c bc a2 b0';

	// randdom number for signature
	var k = "4b037e4b 573bb7e3 34cad0a7 0bed6b58 81df9e8e";

	var W = "0d2ace49 f0415880 843e4cff 2a224dcc a4d12a79 11323aac"+
			"e1eaf5b4 f479a91f 94d01820 193d40a5 f71347e3 8f97ef41"+
			"8bd25959 879ea7f6 2d3fbaa7 e70a9d78 b8dc7933 00bbf669"+
			"0829961a ab4e59a8 410510da ada05ef8 7e48144d 6efe5075"+
			"29011382 38c84b5d 2c3f590c 06e1b918 7ee5d509 e15ccab2"+
			"c257d549 ac1a5086";

    var R = '8f 99 6a 98 ed a5 7c c8 d8 8a a6 ff df ae a2 2f 39 d7 fa 8a';
    var S = '541f7dc4 f92c65eb 7f63b6b4 f22177f1 ee2cf339';

	var hash_name = 'has-160';

	//var block_length = jCastle._algorithmInfo[hash_name].block_size * 8;
    var block_length = jCastle.digest.getBlockSize(hash_name) * 8;

	var params = {
		p: p.replace(/ /g, ''),
		q: q.replace(/ /g, ''),
		g: g.replace(/ /g, ''),
		l: block_length
	};

//----------------------------------------------------------------------------------------------------


	var kcdsa = new jCastle.pki.kcdsa();

	kcdsa.setParameters(params);

	//console.log(kcdsa.p.toString(16));

	//kcdsa.generateKeypair();

	kcdsa.privateKey = new BigInteger(x.replace(/ /g, ''), 16);
	kcdsa.hasPrivateKey = true;

	//var xmodinv = kcdsa.x.modInverse(kcdsa.q);
	//console.log(xmodinv.toString(16));

	kcdsa.publicKey = kcdsa.params.g.modPow(kcdsa.privateKey.modInverse(kcdsa.params.q), kcdsa.params.p);
	kcdsa.hasPublicKey = true;

//	console.log('Y: '+kcdsa.y.toString(16));

	// check whether y is equal
	assert.equal(kcdsa.publicKey.toString(16), y.replace(/ /g, ''), 'Check if Y is equal');

	kcdsa.z = kcdsa.publicKey.mod(BigInteger.ONE.shiftLeft(block_length));

//	console.log('Z: '+kcdsa.z.toString(16));

	// check whether y is equal
	assert.equal(kcdsa.z.toString(16), z.replace(/ /g, ''), 'Check if Z is equal');

/*
	var s = kcdsa.sign(m, 'sha-256');
	var v = kcdsa.verify(m, s, 'sha-256');
	assert.ok(v, "KCDSA sign / verify test");
*/

	hash_name = jCastle.digest.getValidAlgoName(hash_name);
	if (!hash_name || jCastle._algorithmInfo[hash_name].oid == null) {
		throw jCastle.throwException("UNSUPPORTED_HASHER");
	}

	var str = Buffer.from(m);

//	console.log('M: '+ str.toString());


	var l = jCastle._algorithmInfo[hash_name].block_size * 8;
    var Z = Buffer.from(kcdsa.publicKey.mod(BigInteger.ONE.shiftLeft(l)).toByteArray());

//  Z == z


	var hash = jCastle.digest.create(hash_name).start().update(Z).update(str).finalize().toString('hex');

//	console.log('H: '+hash);
	assert.equal(hash, H.replace(/ /g, ''), 'Check if H is equal');


	hash = hash.substr(0, (kcdsa.params.q.bitLength() >>> 3) * 2);
	var hash_bi = new BigInteger(hash, 16);

	// Generate a random number k, such that 0 < k < q.
	var rng = new jCastle.prng();
	var get_signature = false;

	while (!get_signature) {
/*
		//var k = BigInteger.randomInRange(BigInteger.ONE, kcdsa.q.subtract(BigInteger.ONE), rng);
		do {
			var k = BigInteger.random(kcdsa.q.bitLength(), rng);
		} while (k.compareTo(BigInteger.ZERO) <= 0 || k.compareTo(kcdsa.q) >= 0);
*/
		// for test we have already random number k.
		var K = new BigInteger(k.replace(/ /g, ''), 16);
//		console.log(k.toString(16));
		
		// w = g^k mod p
		var w = kcdsa.params.g.modPow(K, kcdsa.params.p);
//		console.log('W: ' + w.toString(16));

		assert.ok(w.equals(new BigInteger(W.replace(/ /g, ''), 16)), 'Check if W is equal');

		var r = new jCastle.digest(hash_name).digest(w.toByteArray());
//		console.log('R: ' + r);
		assert.ok(r.toString('hex') == R.replace(/ /g, ''), 'Check if R is equal');

		//var r_bi = new BigInteger(r.toString('hex'), 16);
        var r_bi = BigInteger.fromByteArrayUnsigned(r);

		//if (r_bi.compareTo(BigInteger.ZERO) <= 0) continue;

		// e = r ⊕ h(z||m) mod q
		var e = r_bi.xor(hash_bi).mod(kcdsa.params.q);

//		console.log(e.toString(16));

		// computes the second part s of the signature as s = x(k - e)mod q
		var s = kcdsa.privateKey.multiply(K.subtract(e)).mod(kcdsa.params.q);

//		console.log('S: '+s.toString(16));
		assert.ok(s.equals(new BigInteger(S.replace(/ /g, ''), 16)), 'Check if S is equal');

		if (s.compareTo(BigInteger.ZERO) > 0) get_signature = true;
		else {
			console.log("s is smaller than zero");
		}
	}

	// Package the digital signature as {r,s}.
	var res = new jCastle.asn1().getDER({
		type: jCastle.asn1.tagSequence,
		items:[{
//			type: jCastle.asn1.tagInteger,
//			value: r
			type: jCastle.asn1.tagOctetString,
			value: r
		}, {
			type: jCastle.asn1.tagInteger,
			intVal: s
		}]
	});

//	console.log(jCastle.HEX.encode(res));

	// verifying...

	var sequence = new jCastle.asn1().parse(res);

	if (!jCastle.asn1.isSequence(sequence)) {
		return false;
	}

//	console.log(sequence);

	var r = BigInteger.fromByteArrayUnsigned(Buffer.from(sequence.items[0].value, 'latin1'));
	var s = sequence.items[1].intVal;

	if (r.compareTo(BigInteger.ZERO) <= 0 || r.compareTo(kcdsa.params.q.multiply(BigInteger.valueOf(2))) >= 0 ||
		s.compareTo(BigInteger.ZERO) <= 0 || s.compareTo(kcdsa.params.q) >= 0
	) {
		console.log("invalid DSA Signature");
		return false;
	}

//	console.log(r.toString(16));
//	console.log(s.toString(16));

	// computes e = r ⊕ h(z || m) mod q, 
	var e = r.xor(hash_bi).mod(kcdsa.params.q);

//	console.log(e.toString(16));

	// w' = (y^s)(g^e) mod p 

	//console.log(kcdsa.y.toString(16));

//	console.log(kcdsa.y.modPow(s, kcdsa.p).toString(16));

	// it gets an different value!
	//var w = kcdsa.y.pow(s).multiply(kcdsa.g.pow(e)).mod(kcdsa.p);

	var u1 = kcdsa.publicKey.modPow(s, kcdsa.params.p);
	var u2 = kcdsa.params.g.modPow(e, kcdsa.params.p);

	var w = u1.multiply(u2).mod(kcdsa.params.p);


//	console.log(w.toString(16));

	// finally checks if  r = h(w'). 
	var v = new jCastle.digest(hash_name).digest(w.toByteArray()).toString('hex');
	var v = new BigInteger(v, 16);
			
	// If v == r, the digital signature is valid.

	assert.ok(v.compareTo(r) == 0, "KCDSA sign / verify test");	


//----------------------------------------------------------------------------------------------------

	var p = "d7b9afc1 04f4d53f 737db88d 6bf77e12 cd7ec3d7 1cbe3cb7"+
			"4cd224bf f348154a fba6bfed 797044df c655dcc2 0c952c0e"+
			"c43a97e1 ad67e687 d10729ca f622845d 162afca8 f0248cc4"+
			"12b3596c 4c5d3384 f7e25ee6 44ba87bb 09b164fb 465477b8"+
			"7fdba5ea a400ffa0 925714ae 19464ffa cead3a97 50d12194"+
			"8ab2d8d6 5c82379f";

	var q = "c3ddd371 7bf05b8f 8dd725c1 62f0b943 2c6f77fb";

	var g = "50e414c7 a56892d1 ad633e42 d5cd8346 f2c09808 111c772c"+
			"c30b0c54 4102c27e 7b5f9bec 57b9df2a 15312891 9d795e46"+
			"652b2a07 2e1f2517 f2a3afff 5815253a aefe3572 4cfa1af6"+
			"afce3a6b 41e3d0e1 3bed0eff 54383c46 65e69b47 ba79bbc3"+
			"339f86b9 be2b5889 4a18b201 afc41fe3 a0d93d31 25efda79"+
			"bc50dbbb 2c3ab639";

	var hash_name = 'has-160';
	var m = "This is a test message for KCDSA usage!";		

	var params = {
		p: p.replace(/ /g, ''),
		q: q.replace(/ /g, ''),
		g: g.replace(/ /g, '')
	};		

	var kcdsa = new jCastle.pki('KCDSA');

	kcdsa.setParameters(params);

	kcdsa.generateKeypair();

	var s = kcdsa.sign(m, { hashAlgo: hash_name });
	var v = kcdsa.verify(m, s, { hashAlgo: hash_name });

	assert.ok(v, "KCDSA sign /verify test");

});

QUnit.test("Sign/Verify Test", function(assert) {
//----------------------------------------------------------------------------------------------------



	var p = 
		"d478f35f 01c72832 bcbbd508 c4a340f4 33dcd60b 2e023c94"+
		"1fda5a09 3a220727 73b3d962 af981c9e a037edcc edfc63a5"+
		"02d0dc9b 3e708789 4cf9b159 56b7bac8 da216b66 bddbe71e"+
		"28e2f828 490aff3c 8d36be50 41728f4f ee34f7f1 9ab8a6ae"+
		"6fe6fe65 13a504c1 99a83b88 707f43c7 d0913c9a 26c80fb3"+
		"861a698a 562c919b ffa798a0 6966d588 2822e448 e686bca6"+
		"08d83ef7 35937988 d65398ca aa995e98 e53eb9a1 8cd0e05c"+
		"33ad0950 e2b87402 fc284972 3f69d564 62aaa089 57bb45ff"+
		"854792c6 337247b6 888d0cf0 016e83d1 29e47c80 9a1bc68f"+
		"83739502 8e9b1658 d5c178ec 1678a6fd 1daf0e0a 41f4b6ce"+
		"bb642cec cb749ada 0fd4a2ba 94426efb";

	var q =
		"c223aad2 e86ecb17 11921a23 36d7eba9 b0d3dc82 4224a4cd"+
		"db5ef0b7";


	var g =
		"cc824e25 383509a0 22781161 e3d2af50 9ae9184d 2751ccb3"+
		"3f6b8fad e18d86c6 a2ad3b06 d9899118 57d26c59 f1fa85fb"+
		"fb14e3d3 393cc3f2 fcf9da68 65014fc9 b3e8c8c0 f8295f82"+
		"76bac6f6 944f56de eb48ab86 218f4071 33471505 e3b33c7b"+
		"ea69108a 643267da 36e0762e 570b9b61 57897992 d0f7806f"+
		"d6de0773 d61657db 882d634c 8bd05403 3f2b34f2 28fc89b9"+
		"c5df6524 3a628121 34845b14 302c25fa d3ca1c92 fa552c5a"+
		"f2ddfbe8 a67f03a3 79ac791f c196d204 c505558e 789ae98f"+
		"aa1ce7fe 8dc7555a c6abbbb7 3d779f3d 1db8038f 22d2baf2"+
		"4e8adec1 5f6209de 61e058cc 2913047d c071cb90 b0769ce2"+
		"296a5daa f94201df 82de0343 de50333f";

	var m = "This is a test message for KCDSA usage!";

	var kcdsa = new jCastle.pki('KCDSA');

	kcdsa.setParameters(
		p.replace(/ /g, ''),
		q.replace(/ /g, ''),
		g.replace(/ /g, '')
	);

	kcdsa.generateKeypair();

	var hash_name = 'sha-224';
	var s = kcdsa.sign(m, { hashAlgo: hash_name });
	var v = kcdsa.verify(m, s, { hashAlgo: hash_name });

	assert.ok(v, "KCDSA sign /verify test");



//----------------------------------------------------------------------------------------------------


	var p =
		"f4119d06 45045e98 3045e27e 74ec6352 81ed1d9d 3a7053ff"+
		"e519994b 98671be7 3f044683 6904aea9 b853aa32 a46169cc"+
		"4d0106d7 da4b16be 41b5853d 31df183f 4fd3b8f9 81b94269"+
		"312fef6f 15ee9e1f da146179 a91daa7e b855d6a8 425fbbab"+
		"501c525f 733e0bc2 d3371370 a93b34bf 633d7e8d efa5601f"+
		"233a69ac 91050162 f33d57fd bb3fa870 5a4b59a9 76bb4847"+
		"8ce6ef8e 170d91f1 9cd36e17 d006855e e6616301 ff9b3c3f"+
		"291c3db9 132cebcb 786582a7 5c027bd1 8e568d92 979b0d33"+
		"f571871a ca50755b a13a2d66 d7bcaa6c 53767bc7 c25a9967"+
		"c033af3a 34b23070 c11b43e6 ceb1c584 7f69db51 f069fb57"+
		"5e88dacf d264970b 0b4bdaaa c55ed467";


	var q =
		"dedc989a d0f984cd 4d3e54bf aebc2dd1 de19152c 49aa526d"+
		"da4cab54 879ffb2d";

	var g =
		"cf565bc4 f9628539 bf780966 2cc58dfe 6e8243de e7c3af77"+
		"abc65dec 969b77be 8871afa3 4498d376 11c854e0 03c8928c"+
		"11c3f27c 18ba1a09 b0628bae d37dc3e9 83026ae7 17cda927"+
		"829a7f7b 5aa1aa6c e0112880 61ebeb69 2c7d6843 46c1878c"+
		"c4a45067 eb927494 dd3202d6 c8fba6b3 8352d407 858ad3aa"+
		"19b3e09f 2b75c849 df191568 0b8d4a35 c0ead2da 4436432f"+
		"cdcbbcc4 3b74d12f 266f4ae0 2d2e5538 530ec3ce 15f719d4"+
		"e86fdca8 892e0cfd f3e08d40 761b6d65 0b59e132 082bfdff"+
		"64106e9b 85501a5c 7a63b85d da266923 cb5703b7 34f0a14c"+
		"ab930343 0b4a9fc8 66da806a dad3da65 06fc2e32 5a12220f"+
		"9593c2e5 f9f00358 5af63940 bb687369";

	var m = "This is a test message for KCDSA usage!";

	var kcdsa = new jCastle.pki('KCDSA');

	kcdsa.setParameters(
		p.replace(/ /g, ''),
		q.replace(/ /g, ''),
		g.replace(/ /g, '')
	);

	kcdsa.generateKeypair();

	var hash_name = 'sha-256';
	var s = kcdsa.sign(m, { hashAlgo: hash_name });
	var v = kcdsa.verify(m, s, { hashAlgo: hash_name });

	assert.ok(v, "KCDSA sign /verify test");


//----------------------------------------------------------------------------------------------------


	var p =
		"f491f199 36144931 fd42b3a8 00f6df74 2730ca32 5d622bd2"+
		"3bf0dec9 cca51d1d 1b79bf70 5a88c7ba 943e0691 1aff7c2c"+
		"b9a2ffbe 31168532 38b13517 4e1107ae f0914497 62b2aa48"+
		"aeb1bd32 37e615c3 ecc491aa bbf1d93f ea956530 f971b7c4"+
		"4b165c68 c4f3de5f 153847ff ac8d49aa bfcb3b80 86a835d1"+
		"4d6cfa51 65725807 6144536a b74c53c5 771c70a3 6aecbbc4"+
		"64c01425 7e275642 e403b40d fef0953c 9f3bfdf4 82de7805"+
		"7a2bf103 fd786b3e fe53a7cf 1eef8c26 893c5568 f5b72c93"+
		"908407a5 0ca5a13b 0e685d4d 975b7545 ac34bb91 1e577533"+
		"1d392a26 b74b487d 27239f4e da51a8ed 926dee4b 996386e8"+
		"0f3b3b5a b90e3b4a 32f445b5 0f94fb0c 438f825d 70d8ff2a"+
		"79157abb 6790e303 d6479fb7 a07559e4 3099f396 891eadef"+
		"6999df55 885be17c 712a3c6f e98a8c4a 6f0fa344 fe06a5f9"+
		"ab187609 52ff2d60 b27130b7 bd4dab8e 6c4e296b 68bcded9"+
		"bb770eb6 38eb4ed1 2df66674 50e77d28 27539706 02388bff"+
		"bf036bd7 1e0d2fa4 55c3098c ef627aba 02986336 64650bf7";

	var q = 
		"dc121d3f 13ec39ec b4bd4fc6 d08d2c1b f66562b1 e4d3f344"+
		"a2546f11 51821293";

	var g =
		"7c54f18f e661e6d5 04674614 0617e24e c360e330 e95661a5"+
		"de38f42c 31485806 b473b114 1bb966ce c1946c96 92e46aa1"+
		"adc4c58d 69ac60ce 12344ad9 b5661112 e234848b d50060ae"+
		"1d948050 d028c5ec 09b40f80 e9c42195 9b61d425 7a003578"+
		"7334d152 18531645 f1ae34f9 54c8a309 057a4516 52a594f3"+
		"7e593a49 bce07bcb a4efa9a5 55e61355 c3741055 a19e518c"+
		"e735c1b6 2d537b72 21004cd1 7c635484 8e4a2e73 c590b4e9"+
		"7387a108 e312fe34 91a1e776 28be5ea1 2e44f298 33e32144"+
		"9e1d4666 d20fc8c2 ea308945 c481e831 c79f1c71 884adb1f"+
		"0e4c21f4 5d4698f8 ea76710e c36e698e a56192d3 5dfc35d8"+
		"cf214651 b844d4fa 1f415230 69613238 c802afec f3943381"+
		"35facb29 71427bd0 b237c824 57b56e8c e2e5c1db bd81d155"+
		"88c31beb b8ed7ee2 45013ce2 583d9926 53bfd3b9 761ea408"+
		"1d01df80 4100be09 daa014d8 76abfc72 851967c7 1d33be57"+
		"5878a02b 9342692d 54790f8e e525e1b7 b4ff0b49 6866d469"+
		"9618c1e8 c9bf0d69 458c3abd c957f443 0ade37f8 2000c071";

	var m = "This is a test message for KCDSA usage!";

	var kcdsa = new jCastle.pki('KCDSA');

	kcdsa.setParameters(
		p.replace(/ /g, ''),
		q.replace(/ /g, ''),
		g.replace(/ /g, '')
	);

	kcdsa.generateKeypair();

	var hash_name = 'sha-256';
	var s = kcdsa.sign(m, { hashAlgo: hash_name });
	var v = kcdsa.verify(m, s, { hashAlgo: hash_name });

	assert.ok(v, "KCDSA sign /verify test");

});

