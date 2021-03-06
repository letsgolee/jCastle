/*
https://tools.ietf.org/html/rfc4269

Appendix B.  Test Vectors

   This appendix provides test vectors for the SEED cipher described in
   this document.

   All data are hexadecimal numbers (not prefixed by "0x").

B.1.

      Key        : 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
      Plaintext  : 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
      Ciphertext : 5E BA C6 E0 05 4E 16 68 19 AF F1 CC 6D 34 6C DB

                            Intermediate Value
   ------------------------------------------------------------------
                 Ki0      Ki1        L0       L1       R0       R1
   ==================================================================
   Round  1 : 7C8F8C7E C737A22C | 00010203 04050607 08090A0B 0C0D0E0F
   Round  2 : FF276CDB A7CA684A | 08090A0B 0C0D0E0F 8081BC57 C4EA8A1F
   Round  3 : 2F9D01A1 70049E41 | 8081BC57 C4EA8A1F 117A8B07 D7358C24
   Round  4 : AE59B3C4 4245E90C | 117A8B07 D7358C24 D1738C94 7326CAB0
   Round  5 : A1D6400F DBC1394E | D1738C94 7326CAB0 577ECE6D 1F8433EC
   Round  6 : 85963508 0C5F1FCB | 577ECE6D 1F8433EC 910F62AB DDA096C1
   Round  7 : B684BDA7 61A4AEAE | 910F62AB DDA096C1 EA4D39B4 B17B1938
   Round  8 : D17E0741 FEE90AA1 | EA4D39B4 B17B1938 B04E251F 97D7442C
   Round  9 : 76CC05D5 E97A7394 | B04E251F 97D7442C B86D31BF A5988C06
   Round 10 : 50AC6F92 1B2666E5 | B86D31BF A5988C06 9008EABF 38DF7430
   Round 11 : 65B7904A 8EC3A7B3 | 9008EABF 38DF7430 33E47DE0 54EFF76C
   Round 12 : 2F7E2E22 A2B121B9 | 33E47DE0 54EFF76C 6BE9C434 BF3F378A
   Round 13 : 4D0BFDE4 4E888D9B | 6BE9C434 BF3F378A B8DC3842 03A02D33
   Round 14 : 631C8DDC 4378A6C4 | B8DC3842 03A02D33 6679FCF7 9791DFCB
   Round 15 : 216AF65F 7878C031 | 6679FCF7 9791DFCB 1A415792 A02B8C54
   Round 16 : 71891150 98B255B0 | 1A415792 A02B8C54 19AFF1CC 6D346CDB

B.2.

      Key        : 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
      Plaintext  : 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
      Ciphertext : C1 1F 22 F2 01 40 50 50 84 48 35 97 E4 37 0F 43

                            Intermediate Value
   ------------------------------------------------------------------
                 Ki0      Ki1        L0       L1       R0       R1
   ==================================================================
   Round  1 : C119F584 5AE033A0 | 00000000 00000000 00000000 00000000
   Round  2 : 62947390 A600AD14 | 00000000 00000000 9D8DB62C 911F0C19
   Round  3 : F6F6544E 596C4B49 | 9D8DB62C 911F0C19 21229A97 4AB4B7B8
   Round  4 : C1A3DE02 CE483C49 | 21229A97 4AB4B7B8 5A27B404 899D7315
   Round  5 : 5E742E6D 7E25163D | 5A27B404 899D7315 B8489E76 BA0EF3EA
   Round  6 : 8299D2B4 790A46CE | B8489E76 BA0EF3EA 04A3DF29 31A27FB4
   Round  7 : EA67D836 55F354F2 | 04A3DF29 31A27FB4 EC9C17BF 81AA2AA0
   Round  8 : C47329FB F50DB634 | EC9C17BF 81AA2AA0 4FA74E8D CDB21BB8
   Round  9 : 2BD30235 51679CE6 | 4FA74E8D CDB21BB8 D93492FE 4F71A4DA
   Round 10 : FA8D6B76 A9F37E02 | D93492FE 4F71A4DA B14053D9 A911379B
   Round 11 : 8B99CC60 0F6092D4 | B14053D9 A911379B 5A7024D6 3905668B
   Round 12 : BDAEFCFA 489C2242 | 5A7024D6 3905668B 605C8C3A 73DFBB75
   Round 13 : F6357C14 CFCCB126 | 605C8C3A 73DFBB75 40282F39 31CB8987
   Round 14 : A0AA6D85 F8C10774 | 40282F39 31CB8987 E9F834A8 3B9586D4
   Round 15 : 47F4FEC5 353AE1BA | E9F834A8 3B9586D4 4B60324B 761C9958
   Round 16 : FECCEA48 A4EF9F9B | 4B60324B 761C9958 84483597 E4370F43

B.3.

      Key        : 47 06 48 08 51 E6 1B E8 5D 74 BF B3 FD 95 61 85
      Plaintext  : 83 A2 F8 A2 88 64 1F B9 A4 E9 A5 CC 2F 13 1C 7D
      Ciphertext : EE 54 D1 3E BC AE 70 6D 22 6B C3 14 2C D4 0D 4A

                            Intermediate Value
   ------------------------------------------------------------------
                 Ki0      Ki1        L0       L1       R0       R1
   ==================================================================
   Round  1 : 56BE4A0F E9F62877 | 83A2F8A2 88641FB9 A4E9A5CC 2F131C7D
   Round  2 : 68BCB66C 078911DD | A4E9A5CC 2F131C7D 7CE5F012 47F8C1E6
   Round  3 : 5B82740B FD24D09B | 7CE5F012 47F8C1E6 AAC99520 609F4CB7
   Round  4 : 8D608015 A120E0BE | AAC99520 609F4CB7 3E126D1F 44FA99F0
   Round  5 : 810A75AE 1BF223E5 | 3E126D1F 44FA99F0 11716365 9BA775AC
   Round  6 : F9C0D2D0 0F676C02 | 11716365 9BA775AC 32C9838F BA5757CB
   Round  7 : 8F9B5C84 8A7C8DDD | 32C9838F BA5757CB 77E00C64 CF9F6B32
   Round  8 : D4AB4896 18E93447 | 77E00C64 CF9F6B32 3F09B1F7 DE7D6D58
   Round  9 : CF090F51 5A4C8202 | 3F09B1F7 DE7D6D58 300E5CAA D0BF2345
   Round 10 : 4EC3196F 61B1A0DC | 300E5CAA D0BF2345 9574FDD7 4DF050D1
   Round 11 : 244E07C1 D0D10B12 | 9574FDD7 4DF050D1 A15EDA6F 624265FD
   Round 12 : 69917C6C 7FF94FB3 | A15EDA6F 624265FD 9F39B682 D841C76F
   Round 13 : 9A7EB482 723B5738 | 9F39B682 D841C76F EEBBAD8B C1F488EF
   Round 14 : B97522C5 39CC6349 | EEBBAD8B C1F488EF 45CF5D4E BEEA4AA2
   Round 15 : FFC2AFD5 1412E731 | 45CF5D4E BEEA4AA2 43B7FE1B BCF87781
   Round 16 : A9AF7241 A3E67359 | 43B7FE1B BCF87781 226BC314 2CD40D4A

B.4.

      Key        : 28 DB C3 BC 49 FF D8 7D CF A5 09 B1 1D 42 2B E7
      Plaintext  : B4 1E 6B E2 EB A8 4A 14 8E 2E ED 84 59 3C 5E C7
      Ciphertext : 9B 9B 7B FC D1 81 3C B9 5D 0B 36 18 F4 0F 51 22

                            Intermediate Value
   ------------------------------------------------------------------
                 Ki0      Ki1        L0       L1       R0       R1
   ==================================================================
   Round  1 : B2B11B63 2EE9E2D1 | B41E6BE2 EBA84A14 8E2EED84 593C5EC7
   Round  2 : 11967260 71A62F24 | 8E2EED84 593C5EC7 1B31F2F7 3DDE00BA
   Round  3 : 2E017A5A 35DAD7A7 | 1B31F2F7 3DDE00BA 35CC49C0 2AFB59EA
   Round  4 : 1B2AB5FF A3ADA69F | 35CC49C0 2AFB59EA D7AB53AA AE82F1C7
   Round  5 : 519C9903 DA90AAEE | D7AB53AA AE82F1C7 24139958 B840E56F
   Round  6 : 29FD95AD B94C3F13 | 24139958 B840E56F 24AB5291 544C9DBA
   Round  7 : 6F629D19 8ACE692F | 24AB5291 544C9DBA E8152994 75D0B424
   Round  8 : 30A26E73 2F22338E | E8152994 75D0B424 A2CD1153 F32BB23A
   Round  9 : 9721073A 98EE8DAE | A2CD1153 F32BB23A C386008B E3257731
   Round 10 : C597A8A9 27DCDC97 | C386008B E3257731 98396BFD 814F8972
   Round 11 : F5163A00 5FFD0003 | 98396BFD 814F8972 E74D2D0D 11D889D1
   Round 12 : 5CBE65DA A73403E4 | E74D2D0D 11D889D1 29D8C7B3 D1B71C0C
   Round 13 : 7D5CF070 1D3B8092 | 29D8C7B3 D1B71C0C C4E692C2 D2F57F18
   Round 14 : 388C702B 1BAA4945 | C4E692C2 D2F57F18 2FAFB300 5F0C4BFF
   Round 15 : 87D1AB5A FA13FB5C | 2FAFB300 5F0C4BFF 60E5F17C 5626BB68
   Round 16 : C97D7EED 90724A6E | 60E5F17C 5626BB68 5D0B3618 F40F5122
*/
const QUnit = require('qunit');
const jCastle = require('../lib/index');

QUnit.module('SEED');

QUnit.test("Vector Test", function(assert) {
	var testVectors = [
		{
			key        : '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00',
			plaintext  : '00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F',
			ciphertext : '5E BA C6 E0 05 4E 16 68 19 AF F1 CC 6D 34 6C DB'
		},
		{
			key        : '00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F',
			plaintext  : '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00',
			ciphertext : 'C1 1F 22 F2 01 40 50 50 84 48 35 97 E4 37 0F 43'
		},
		{
			key        : '47 06 48 08 51 E6 1B E8 5D 74 BF B3 FD 95 61 85',
			plaintext  : '83 A2 F8 A2 88 64 1F B9 A4 E9 A5 CC 2F 13 1C 7D',
			ciphertext : 'EE 54 D1 3E BC AE 70 6D 22 6B C3 14 2C D4 0D 4A'
		},
		{
			key        : '28 DB C3 BC 49 FF D8 7D CF A5 09 B1 1D 42 2B E7',
			plaintext  : 'B4 1E 6B E2 EB A8 4A 14 8E 2E ED 84 59 3C 5E C7',
			ciphertext : '9B 9B 7B FC D1 81 3C B9 5D 0B 36 18 F4 0F 51 22'
		},
		{ //1 - ????????????_????????????_??????_?????????(SEED).pdf ??????
			key        : '88 E3 4F 8F 08 17 79 F1 E9 F3 94 37 0A D4 05 89',
			plaintext  : 'D7 6D 0D 18 32 7E C5 62 B1 5E 6B C3 65 AC 0C 0F',
			ciphertext : '0F 4E 7F C7 8C 48 D5 AD 95 10 BA D8 98 7B A5 22'
		},
		{ //2
			key        : '88 E3 4F 8F 08 17 79 F1 E9 F3 94 37 0A D4 05 89',
			plaintext  : '8D 41 E0 BB 93 85 68 AE EB FD 92 ED 1A FF A0 96',
			ciphertext : '39 86 9D 94 74 48 58 38 24 99 67 68 D1 31 F0 A5'
		},
		{ //3
			key        : '88 E3 4F 8F 08 17 79 F1 E9 F3 94 37 0A D4 05 89',
			plaintext  : '39 4D 20 FC 52 77 DD FC 4D E8 B0 FC E1 EB 2B 93',
			ciphertext : 'D6 8C 46 19 B7 C3 45 A7 80 CB 8E 16 77 0B 25 9A'
		},
		{ //4
			key        : '88 E3 4F 8F 08 17 79 F1 E9 F3 94 37 0A D4 05 89',
			plaintext  : 'D4 AE 40 EF 47 68 C6 13 B5 0B 89 42 F7 D4 B9 B3',
			ciphertext : '36 8C B3 C5 B5 B1 2F FD 78 08 6F D0 5F 39 FC DC'
		},
		{ //1
			key        : 'ED 24 01 AD 22 FA 25 59 91 BA FD B0 1F EF D6 97',
			plaintext  : 'B4 0D 70 03 D9 B6 90 4B 35 62 27 50 C9 1A 24 57',
			ciphertext : 'C0 92 AC 0B AA 9A 98 B0 6F 53 E0 37 0A EB 2B A2'
		},
		{ //2
			key        : 'ED 24 01 AD 22 FA 25 59 91 BA FD B0 1F EF D6 97',
			plaintext  : '5B B9 A6 32 36 4A A2 6E 3A C0 CF 3A 9C 9D 0D CB',
			ciphertext : '68 41 00 CC 59 42 B0 25 D8 C3 0E 67 DF 16 D5 FA'
		},
		{ //3
			key        : 'ED 24 01 AD 22 FA 25 59 91 BA FD B0 1F EF D6 97',
			plaintext  : '38 13 33 2C 97 15 E7 BB 9F 1C 34 A6 6B 8A 8F 93',
			ciphertext : '7D AE 6E 42 70 EE 4D F6 9B 4F B5 27 74 5A 74 E5'
		},
		{ //4
			key        : 'ED 24 01 AD 22 FA 25 59 91 BA FD B0 1F EF D6 97',
			plaintext  : '77 DC A1 A8 71 EF 3F 72 10 92 65 56 DE 48 C0 DC',
			ciphertext : 'D9 E3 4B 2A F6 3B 64 5B 4F 5A A8 96 68 FD 61 24'
		},
		{ //5
			key        : 'ED 24 01 AD 22 FA 25 59 91 BA FD B0 1F EF D6 97',
			plaintext  : '47 31 6C 66 B4 36 92 D5 92 9C 2A 35 F3 E5 63 8D',
			ciphertext : 'BA 47 DA 33 22 86 72 CC C1 FD F1 F3 20 23 9D 35'
		},
		{ //6
			key        : 'ED 24 01 AD 22 FA 25 59 91 BA FD B0 1F EF D6 97',
			plaintext  : '6E B1 32 C1 7A B6 E1 53 3B F3 50 3C B4 B2 17 13',
			ciphertext : '9E C9 27 C0 FF 1F 51 F8 98 7C FF 13 0D 7C EA 9E'
		},
		{ //7
			key        : 'ED 24 01 AD 22 FA 25 59 91 BA FD B0 1F EF D6 97',
			plaintext  : '8F 8A 8A B8 F8 92 29 CC 22 EE BB 14 42 76 EE 86',
			ciphertext : '79 8C 01 DC C3 80 F1 34 50 79 9C 48 3D A1 1A 24'
		},
		{ //8
			key        : 'ED 24 01 AD 22 FA 25 59 91 BA FD B0 1F EF D6 97',
			plaintext  : 'E5 71 B4 FA 5F 95 15 93 DC F8 91 BD 67 E5 51 1A',
			ciphertext : '34 75 A6 41 19 3F 1D 72 13 1B CC 7C CF E2 20 F6'
		},
		{ //9
			key        : 'ED 24 01 AD 22 FA 25 59 91 BA FD B0 1F EF D6 97',
			plaintext  : '8D 06 00 FF A3 73 26 A7 4E 08 CA 60 25 2C F7 6A',
			ciphertext : 'EE B2 79 86 8D A1 60 12 AB 68 69 1D 0D AB D3 B7'
		},
		{ //10
			key        : 'ED 24 01 AD 22 FA 25 59 91 BA FD B0 1F EF D6 97',
			plaintext  : '7A 00 FD D6 C4 0C BB 0C B4 03 12 6E EF E2 7B 85',
			ciphertext : '60 FB E9 5F 88 54 AD 8A 76 7F 40 25 8D C0 4F 1D'
		},

	];

	for (var i = 0; i < testVectors.length; i++) {
		var vector = testVectors[i];

		var key = Buffer.from(vector.key.replace(/[ \:]/g, ''), 'hex');
		var pt = Buffer.from(vector.plaintext.replace(/[ \:]/g, ''), 'hex');
		var expected = Buffer.from(vector.ciphertext.replace(/[ \:]/g, ''), 'hex');

		var cipher = new jCastle.algorithm.seed('seed-128');

		cipher.keySchedule(key);

		var ct = cipher.encryptBlock(pt);

		assert.ok(ct.equals(expected) , "Encryption passed!");

		var dt = cipher.decryptBlock(ct);

		assert.ok(dt.equals(pt), "Decryption passed!");
	}
});

/*
https://tools.ietf.org/html/rfc5669

Appendix A.  Test Vectors

   All values are in hexadecimal.

A.1.  SEED-CTR Test Vectors

   Session Key:               0c5ffd37a11edc42c325287fc0604f2e

   Rollover Counter:          00000000

   Sequence Number:           315e

   SSRC:                      20e8f5eb

   Authentication Key:        f93563311b354748c978913795530631

   Session Salt:              cd3a7c42c671e0067a2a2639b43a

   Initialization Vector:     cd3a7c42e69915ed7a2a263985640000

   RTP Payload:               f57af5fd4ae19562976ec57a5a7ad55a
                              5af5c5e5c5fdf5c55ad57a4a7272d572
                              62e9729566ed66e97ac54a4a5a7ad5e1
                              5ae5fdd5fd5ac5d56ae56ad5c572d54a
                              e54ac55a956afd6aed5a4ac562957a95
                              16991691d572fd14e97ae962ed7a9f4a
                              955af572e162f57a956666e17ae1f54a
                              95f566d54a66e16e4afd6a9f7ae1c5c5
                              5ae5d56afde916c5e94a6ec56695e14a
                              fde1148416e94ad57ac5146ed59d1cc5

   Encrypted RTP Payload:     df5a89291e7e383e9beff765e691a737
                              49c9e33139ad3001cd8da73ad07f69a2
                              805a70358b5c7c8c60ed359f95cf5e08
                              f713c53ff7b808250d79a19ccb8d1073
                              4e3cb72ed1f0a4e85b002b248049ab07
                              63dbe571bec52cf9153fdf2019e421ef
                              779cd6f4bd1c8211da8c272e2fce4393
                              4b9eabb87362510f254149f992599036
                              f5e43102327db1ac5e78adc4f66546ed
                              7abfb5a4db320fb7b9c52a61bc554e44

   Authentication Tag:        a5cdaa4d9edc53763855








Yoon, et al.                 Standards Track                   [Page 10]
 
RFC 5669                        SEED-SRTP                    August 2010


A.2.  SEED-CCM Test Vectors

   Key:                       974bee725d44fc3992267b284c3c6750

   Rollover Counter:          00000000

   Sequence Number:           315e

   SSRC:                      20e8f5eb

   Nonce:                     000020e8f5eb00000000315e

   Payload:                   f57af5fd4ae19562976ec57a5a7ad55a
                              5af5c5e5c5fdf5c55ad57a4a7272d572
                              62e9729566ed66e97ac54a4a5a7ad5e1
                              5ae5fdd5fd5ac5d56ae56ad5c572d54a
                              e54ac55a956afd6aed5a4ac562957a95
                              16991691d572fd14e97ae962ed7a9f4a
                              955af572e162f57a956666e17ae1f54a
                              95f566d54a66e16e4afd6a9f7ae1c5c5
                              5ae5d56afde916c5e94a6ec56695e14a
                              fde1148416e94ad57ac5146ed59d1cc5

   AAD:                       8008315ebf2e6fe020e8f5eb

   Encrypted RTP Payload:     486843a881df215a8574650ddabf5dbb
                              2650f06f51252bccaeb4012899d6d71e
                              30c64dad5ead5d8ba65ffe9d79aaf30d
                              c9e6334490c07e7533d704114a9006ec
                              b3b3bff59ecf585485bc0bd286ed434c
                              fd684d19a1ad514ca5f37b71d93288c0
                              7cf4d5e9b83db8becc8c692a7279b6a9
                              ac62ba970fc54f46dcc926d434c0b5ad
                              8678fbf0e7a03037924dae342ef64fa6
                              5b8eaea260fecb477a57e3919c5dab82

   Authentication Tag:        b0a8274cf6a8bb6cc466














Yoon, et al.                 Standards Track                   [Page 11]
 
RFC 5669                        SEED-SRTP                    August 2010


A.3.  SEED-GCM Test Vectors

   Key:                       e91e5e75da65554a48181f3846349562

   Rollover Counter:          00000000

   Sequence Number:           315e

   SSRC:                      20e8f5eb

   Nonce:                     000020e8f5eb00000000315e

   Payload:                   f57af5fd4ae19562976ec57a5a7ad55a
                              5af5c5e5c5fdf5c55ad57a4a7272d572
                              62e9729566ed66e97ac54a4a5a7ad5e1
                              5ae5fdd5fd5ac5d56ae56ad5c572d54a
                              e54ac55a956afd6aed5a4ac562957a95
                              16991691d572fd14e97ae962ed7a9f4a
                              955af572e162f57a956666e17ae1f54a
                              95f566d54a66e16e4afd6a9f7ae1c5c5
                              5ae5d56afde916c5e94a6ec56695e14a
                              fde1148416e94ad57ac5146ed59d1cc5

   AAD:                       8008315ebf2e6fe020e8f5eb

   Encrypted RTP Payload:     8a5363682c6b1bbf13c0b09cf747a551
                              2543cb2f129b8bd0e92dfadf735cda8f
                              88c4bbf90288f5e58d20c4f1bb0d5844
                              6ea009103ee57ba99cdeabaaa18d4a9a
                              05ddb46e7e5290a5a2284fe50b1f6fe9
                              ad3f1348c354181e85b24f1a552a1193
                              cf0e13eed5ab95ae854fb4f5b0edb2d3
                              ee5eb238c8f4bfb136b2eb6cd7876042
                              0680ce1879100014f140a15e07e70133
                              ed9cbb6d57b75d574acb0087eefbac99

   Authentication Tag:        36cd9ae602be3ee2cd8d5d9d
*/