/**
 * A Javascript implemenation of PBE (Password Based Encryption)
 *
 * @author Jacob Lee
 * 
 * Copyright (C) 2015-2022 Jacob Lee.
 */

var jCastle = require('./jCastle');
require('./util');

/*
For Korean SEED refer to http://www.rootca.or.kr/kcac/down/TechSpec/2.3-KCAC.TS.ENC.pdf
*/
jCastle.pbe = {

	getPrfHashName: function(prf_id)
	{
		var name = jCastle.oid.getName(prf_id);
		if (name) {
			var m = /hmac(With)?([a-z0-9\-]+)/i.exec(name);
			if (m) return jCastle.digest.getValidAlgoName(m[2]);
		}

		throw jCastle.exception("UNSUPPORTED_PRF", 'PBE001');
	},

	getPrfHashOID: function(prf_hash)
	{
		var prf = prf_hash.replace('-', '').toUpperCase();
		var oid = jCastle.oid.getOID('hmacWith' + prf);
		if (oid) return oid;
		else {
			oid = jCastle.oid.getOID('hmac'+prf);
			if (oid) return oid;
		}

		throw jCastle.exception("UNSUPPORTED_PRF", 'PBE002');
	},

	getAlgorithmInfo: function(enc_algo, no_oid_check)
	{
		var mode = 'cbc';
		var padding = 'pkcs7';
		var bits = false;
		var key_size = 0;
		var algo = enc_algo;
		var list_reg = new RegExp('(\\-)?(' + jCastle.mcrypt.mode.listModes().join('|') + ')$', 'i');

		//var m = /(\-)?(ecb|cbc|cfb|ofb|ctr|cts|gcm|ccm)$/i.exec(algo);
		var m = list_reg.exec(algo);
		if (m) {
			mode = m[2].toLowerCase();
			//algo = algo.replace(/(\-)?(ecb|cbc|cfb|ofb|ctr|cts|gcm|ccm)$/i, '');
			algo = algo.replace(list_reg, '');
		}

		var bits_reg = new RegExp('(\\-)?(128|160|196|224|256|384|512|1024)$');

		//m = /(\-)?(128|160|196|224|256|384|512|1024)$/.exec(algo);
		m = bits_reg.exec(algo);
		if (m) {
			bits = m[2];
			//algo = algo.replace(/(\-)?(128|160|196|224|256|384|512|1024)$/, '');
			algo = algo.replace(bits_reg, '');
		}

		algo = algo.toLowerCase();

		if (algo == 'aes') {
			algo +='-128';
			key_size = parseInt(bits) / 8;
		} else if (bits) {
			if (typeof jCastle._algorithmInfo[algo + '-' + bits] != 'undefined') {
				algo += '-' + bits;
			}
			key_size = parseInt(bits) / 8;
		}

		// console.log('algo: '+algo+', mode: '+mode);

		var cipher_info = jCastle.mcrypt.getAlgorithmInfo(algo);

		if (!key_size) {
			key_size = cipher_info.keySize;
		}

		var block_size = cipher_info.blockSize;

		if (block_size == 1) {
			mode = 'stream';
			padding = 'none';
		}
		
		var algo_info = {
			algo: algo,
			mode: mode,
			padding: padding,
			keySize: key_size,
			blockSize: block_size
		};

		if (no_oid_check) return algo_info;

		var oid = jCastle.oid.getOID(enc_algo);

		if (oid) {
			algo_info.oid = oid;

			return algo_info;
		}

		throw jCastle.exception("INVALID_ENCRYPTION_METHOD", 'PBE004');
	},

	getAlgorithmInfoByOID: function(oid)
	{
		var enc_algo = jCastle.oid.getName(oid);
		return jCastle.pbe.getAlgorithmInfo(enc_algo);
	},


	getPbeAlgorithmInfo: function(enc_algo)
	{
		// alias
		// https://www.openssl.org/docs/man1.0.2/man1/pkcs8.html
		switch (enc_algo) {
			// pkcs5
			case 'PBE-MD2-DES': enc_algo = 'pbeWithMD2AndDES-CBC'; break;
			case 'PBE-MD5-DES': enc_algo = 'pbeWithMD5AndDES-CBC'; break;
			case 'PBE-MD2-RC2-64': enc_algo = 'pbeWithMD2AndRC2-CBC'; break;
			case 'PBE-MD5-RC2-64': enc_algo = 'pbeWithMD5AndRC2-CBC'; break;
			case 'PBE-SHA1-DES': enc_algo = 'pbeWithSHAAndDES-CBC'; break;
			case 'PBE-SHA1-RC2-64': enc_algo = 'pbeWithSHAAnd64BitRC2-CBC'; break;
			// pkcs12
			case 'PBE-SHA1-RC4-128': enc_algo = 'pbeWithSHAAnd128BitRC4'; break;
			case 'PBE-SHA1-RC4-40': enc_algo = 'pbeWithSHAAnd40BitRC4'; break;
			//case 'PBE-SHA1-3DES': enc_algo = 'pbeWithSHA1AndDES-EDE3-CBC'; break;
			case 'PBE-SHA1-3DES': enc_algo = 'pbeWithSHAAnd3-KeyTripleDES-CBC'; break;
			case 'PBE-SHA1-2DES': enc_algo = 'pbeWithSHAAnd2-KeyTripleDES-CBC'; break;
			case 'PBE-SHA1-RC2-128': enc_algo = 'pbeWithSHAAnd128BitRC2-CBC'; break;
			case 'PBE-SHA1-RC2-40': enc_algo = 'pbeWithSHAAnd40BitRC2-CBC'; break;

			case 'PBE-HAS160-SEED': enc_algo = "pbeWithHAS160AndSEED-CBC"; break;
			case 'PBE-SHA1-SEED': enc_algo = "pbeWithSHA1AndSEED-CBC"; break;
		}

		var oid = jCastle.oid.getOID(enc_algo);

		if (!oid) throw jCastle.exception("INVALID_ENCRYPTION_METHOD", 'PBE005');

// error : pbeWithHAS160AndSEED-CBC, pbeWithSHA1AndSEED-CBC belongs to pkcs#5
//		var type = oid.indexOf("1.2.840.113549.1.5") === -1 ? 'pkcs12' : 'pkcs5';
		var type = oid.indexOf("1.2.840.113549.1.12") === -1 ? 'pkcs5' : 'pkcs12';

		var algo = enc_algo;

		var m = /pbeWith([a-z0-9\-]+)And([a-z0-9\-]+)$/i.exec(algo);
		if (!m) {
			// console.log('something wrong happened');
			throw jCastle.exception("UNKNOWN", 'PBE006');
		}

		var hash_name = m[1].toLowerCase();
		algo = m[2];
		if (hash_name == 'sha') hash_name = 'sha-1';

		var key_size = 0;
		var using_2key = false;

//	console.log(algo);

		m = /^([0-9]+)Bit(.*)/i.exec(algo);
		if (m) {
			key_size = parseInt(m[1]) / 8;
			algo = algo.replace(/^([0-9]+)Bit/i, '');
		}

//	console.log(algo);
		
		// 2|3-KeyTripleDES
		m = /^(2|3)\-Key/i.exec(algo);
		if (m) {
			if (parseInt(m[1]) == 2) {
				using_2key = true;
				key_size = 16;
			}
			algo = algo.replace(/^(2|3)\-Key/i, '');
		}

		var algo_info = jCastle.pbe.getAlgorithmInfo(algo, true);

		algo_info.oid = oid;
		algo_info.type = type;
		algo_info.hashAlgo = hash_name;

		if (key_size) algo_info.keySize = key_size;

		if (using_2key) algo_info.using2Key = true;

//	console.log(algo_info);

		return algo_info;
	},

	getPbeAlgorithmInfoByOID: function(oid)
	{
		var enc_algo = jCastle.oid.getName(oid);
		return jCastle.pbe.getPbeAlgorithmInfo(enc_algo);
	},

	encrypt: function(data, options = {})
	{
		var algo = "pbeWithSHAAnd3-KeyTripleDES-CBC", salt, password, salt_len, iterations;

		if ('oid' in options) {
			algo = jCastle.oid.getName(options.oid);
		} else if ('algo' in options) {
			algo = options.algo;
		}

		if (!('password' in options)) {
			throw jCastle.exception("NO_PASSPHRASE", 'PBE007');
		}
	
		password = Buffer.from(options.password, 'latin1');

		iterations = options.iterations || 2048;


		if ('salt' in options) {
			salt = Buffer.from(salt, 'latin1');
		} else if ('saltLength' in options) {
			salt_len = options.saltLength;
		}

		var pbe_info = {
			kdfInfo: {
				salt: salt,
				saltLength: salt_len,
				iterations: iterations
			},
			params: jCastle.mcrypt.getAlgoParameters(options)
		};

		// pkcs#5 v2.0 algorithm
		if (algo.indexOf('pbeWith') === -1 && algo.indexOf('PBE-') === -1) {

//			console.log('pkcs#5 v2.0 algorithm');

			var prf_hash = 'sha-1';
			algo = algo.toLowerCase();

			var key_size = options.keySize || 0;

			var algo_info = jCastle.pbe.getAlgorithmInfo(algo);

			pbe_info.type = 'pkcs5PBKDF2';
			pbe_info.algo = algo_info.algo;
			pbe_info.algoInfo = algo_info;

//			console.log(algo_info);


			// for SEED algorithm, refer to http://www.rootca.or.kr/kcac/down/TechSpec/2.3-KCAC.TS.ENC.pdf
			if ((algo_info.algo == 'seed' || algo_info.algo == 'seed-128') && 
				(('oid' in options && options.oid == '1.2.410.200004.1.4') || ('oid' in algo_info && algo_info.oid == '1.2.410.200004.1.4'))) {
				pbe_info.algoInfo.type = 'pkcs5';
				pbe_info.algoInfo.oid = '1.2.410.200004.1.4';
				pbe_info.algoInfo.staticIV = Buffer.from('123456789012345', 'latin1');
				pbe_info.algoInfo.hashAlgo = 'sha-1';

				res = jCastle.pbe.pbes1.encrypt(pbe_info, password, data);
				return res;
			}

			if (algo_info.algo == 'rc2' && !key_size) {
				// rc2 default key size
				key_size = 16;
			}

			if ('prfHash' in options) {
				prf_hash = options.prfHash.toLowerCase();
			} else if ('prf' in options) {
				var flag = false;
				if (jCastle.oid.getOID(options.prf)) {
					var m = /hmacWith([a-z0-9\-]+)/i.exec(options.prf);
					if (m) {
						prf_hash = m[1];
						flag = true;
					}
				}

				if (!flag) {
					throw jCastle.exception("UNSUPPORTED_PRF", 'PBE008');
				}
			}

			pbe_info.kdfInfo.prfHash = prf_hash;

			if (key_size) {
				pbe_info.kdfInfo.keySize = key_size;
				pbe_info.params.keySize = key_size;
			}

			var res = jCastle.pbe.pbes2.encrypt(pbe_info, password, data);
		} else {
			// PKCS#5 v1.5 or PKCS#12 Password Based Encryption

//			console.log('pkcs#5 v1.5 or pkcs#12 algorithm');

			var algo_info = jCastle.pbe.getPbeAlgorithmInfo(algo);

			pbe_info.algo = algo_info.algo;
			pbe_info.algoInfo = algo_info;
			pbe_info.type = algo_info.type == 'pkcs5' ? 'pkcs5PBKDF1' : 'pkcs12DeriveKey';
			
//			console.log(algo_info);

			if (algo_info.type == 'pkcs5') {
				// pkcs#5 v1.5 - PBKDF1
				res = jCastle.pbe.pbes1.encrypt(pbe_info, password, data);
			} else {
				// pkcs#12 - pbe
				res = jCastle.pbe.pkcs12pbes.encrypt(pbe_info, password, data);
			}
		}

		return res;
	},

	decrypt: function(data, options = {})
	{
		var algo = "pbeWithSHAAnd3-KeyTripleDES-CBC", salt, password, iterations;

		if ('oid' in options) {
			algo = jCastle.oid.getName(options.oid);
		} else if ('algo' in options) {
			algo = options.algo;
		}

		if (!('password' in options)) {
			throw jCastle.exception("NO_PASSPHRASE", 'PBE009');
		}

		password = Buffer.from(options.password, 'latin1');

		iterations = options.iterations || 2048;

		if ('salt' in options) {
			salt = Buffer.from(options.salt, 'latin1');
		}

		var pbe_info = {
			kdfInfo: {
				salt: salt,
				iterations: iterations
			},
			params: jCastle.mcrypt.getAlgoParameters(options)
		};

		// pkcs#5 v2.0 algorithm
		if (algo.indexOf('pbeWith') === -1 && algo.indexOf('PBE-') === -1) {

//			console.log('pkcs#5 v2.0 algorithm');

			var prf_hash = 'sha-1';
			algo = algo.toLowerCase();

			var key_size = options.keySize || 0;

			var algo_info = jCastle.pbe.getAlgorithmInfo(algo);

			pbe_info.type = 'pkcs5PBKDF2';
			pbe_info.algo = algo_info.algo;
			pbe_info.algoInfo = algo_info;

//console.log(algo_info);

			if ((algo_info.algo == 'seed' || algo_info.algo == 'seed-128') && algo_info.oid == '1.2.410.200004.1.4') {
				// Refer to Korean Encryption Algorithm Specification
				// http://www.rootca.or.kr/kcac/down/TechSpec/2.3-KCAC.TS.ENC.pdf
				pbe_info.algoInfo.type = 'pkcs5';
				pbe_info.algoInfo.hashAlgo = 'sha-1';
				pbe_info.algoInfo.staticIV = '123456789012345';

				res = jCastle.pbe.pbes1.decrypt(pbe_info, password, data);

				return res;
			}

			if (algo_info.algo == 'rc2' && key_size == 0) {
				// rc2 default key size
				key_size = 16;
			}

			if ('prfHash' in options) {
				prf_hash = options.prfHash.toLowerCase();
			} else if ('prf' in options) {
				var flag = false;
				if (jCastle.oid.getOID(options.prf)) {
					var m = /hmacWith([a-z0-9\-]+)/i.exec(options.prf);
					if (m) {
						prf_hash = m[1];
						flag = true;
					}
				}

				if (!flag) {
					throw jCastle.exception("UNSUPPORTED_PRF", 'PBE010');
				}
			}

			pbe_info.kdfInfo.prfHash = prf_hash;

			if (key_size) {
				pbe_info.kdfInfo.keySize = key_size;
				pbe_info.params.keySize = key_size;
			}

			var res = jCastle.pbe.pbes2.decrypt(pbe_info, password, data);
		} else {
			// PKCS#5 v1.5 or PKCS#12 Password Based Encryption

			// console.log('pkcs#5 v1.5 or pkcs#12 algorithm');

			var algo_info = jCastle.pbe.getPbeAlgorithmInfo(algo);
			
			// console.log(algo_info);

			pbe_info.algo = algo_info.algo;
			pbe_info.algoInfo = algo_info;
			pbe_info.type = algo_info.type == 'pkcs5' ? 'pkcs5PBKDF1' : 'pkcs12DeriveKey';

			// console.log('pbe_info: ', pbe_info);

			if (algo_info.type == 'pkcs5') {
				// pkcs#5 v1.5 - PBKDF1
				res = jCastle.pbe.pbes1.decrypt(pbe_info, password, data);
			} else {
				// pkcs#12 - pbe
				res = jCastle.pbe.pkcs12pbes.decrypt(pbe_info, password, data);
			}
		}

		return res;
	}
};

jCastle.pbe.pbes1 = {

/*
RFC 2898

6.1   PBES1

   PBES1 combines the PBKDF1 function (Section 5.1) with an underlying
   block cipher, which shall be either DES [15] or RC2(tm) [21] in CBC
   mode [16]. PBES1 is compatible with the encryption scheme in PKCS #5
   v1.5.

   PBES1 is recommended only for compatibility with existing
   applications, since it supports only two underlying encryption
   schemes, each of which has a key size (56 or 64 bits) that may not be
   large enough for some applications.

6.1.1   Encryption Operation

   The encryption operation for PBES1 consists of the following steps,
   which encrypt a message M under a password P to produce a ciphertext
   C:

      1. Select an eight-octet salt S and an iteration count c, as
         outlined in Section 4.

      2. Apply the PBKDF1 key derivation function (Section 5.1) to the
         password P, the salt S, and the iteration count c to produce at
         derived key DK of length 16 octets:

                 DK = PBKDF1 (P, S, c, 16) .

      3. Separate the derived key DK into an encryption key K consisting
         of the first eight octets of DK and an initialization vector IV
         consisting of the next eight octets:

                 K   = DK<0..7> ,
                 IV  = DK<8..15> .

      4. Concatenate M and a padding string PS to form an encoded
         message EM:

                 EM = M || PS ,

         where the padding string PS consists of 8-(||M|| mod 8) octets
         each with value 8-(||M|| mod 8). The padding string PS will
         satisfy one of the following statements:

                 PS = 01, if ||M|| mod 8 = 7 ;
                 PS = 02 02, if ||M|| mod 8 = 6 ;
                 ...
                 PS = 08 08 08 08 08 08 08 08, if ||M|| mod 8 = 0.

         The length in octets of the encoded message will be a multiple
         of eight and it will be possible to recover the message M
         unambiguously from the encoded message. (This padding rule is
         taken from RFC 1423 [3].)

      5. Encrypt the encoded message EM with the underlying block cipher
         (DES or RC2) in cipher block chaining mode under the encryption
         key K with initialization vector IV to produce the ciphertext
         C. For DES, the key K shall be considered as a 64-bit encoding
         of a 56-bit DES key with parity bits ignored (see [9]). For
         RC2, the "effective key bits" shall be 64 bits.

      6.   Output the ciphertext C.

   The salt S and the iteration count c may be conveyed to the party
   performing decryption in an AlgorithmIdentifier value (see Appendix
   A.3).

6.1.2 Decryption Operation

   The decryption operation for PBES1 consists of the following steps,
   which decrypt a ciphertext C under a password P to recover a message
   M:

      1. Obtain the eight-octet salt S and the iteration count c.

      2. Apply the PBKDF1 key derivation function (Section 5.1) to the
         password P, the salt S, and the iteration count c to produce a
         derived key DK of length 16 octets:

                 DK = PBKDF1 (P, S, c, 16)

      3. Separate the derived key DK into an encryption key K consisting
         of the first eight octets of DK and an initialization vector IV
         consisting of the next eight octets:

                 K = DK<0..7> ,
                 IV  = DK<8..15> .

      4. Decrypt the ciphertext C with the underlying block cipher (DES
         or RC2) in cipher block chaining mode under the encryption key
         K with initialization vector IV to recover an encoded message
         EM. If the length in octets of the ciphertext C is not a
         multiple of eight, output "decryption error" and stop.

      5. Separate the encoded message EM into a message M and a padding
         string PS:

                 EM = M || PS ,

         where the padding string PS consists of some number psLen
         octets each with value psLen, where psLen is between 1 and 8.
         If it is not possible to separate the encoded message EM in
         this manner, output "decryption error" and stop.

      6. Output the recovered message M.
*/
	encrypt: function(pbe_info, password, data)
	{
		var algo_info = pbe_info.algoInfo;
		var kdf_info = 'kdfInfo' in pbe_info ? pbe_info.kdfInfo : {};
		var salt = 'salt' in kdf_info ? kdf_info.salt : null;
		var iterations = 'iterations' in kdf_info ? kdf_info.iterations : 1;
		var salt_len = kdf_info.saltLength;
		var pbe_params = 'params' in pbe_info ? pbe_info.params : {};

		if (jCastle.util.isString(algo_info)) {
			algo_info = jCastle.pbe.getPbeAlgorithmInfo(algo_info);
		}

		var key_size = 'keySize' in kdf_info ? kdf_info.keySize : ('keySize' in pbe_params ? pbe_params.keySize : algo_info.keySize);

		if (!salt) {
			salt_len = salt_len || 8;
			salt = new jCastle.prng().nextBytes(salt_len, true);
			jCastle.util.avoidAsn1Format(salt);
		}

		// for SEED algorithm, refer to http://www.rootca.or.kr/kcac/down/TechSpec/2.3-KCAC.TS.ENC.pdf
		if (algo_info.algo == 'seed' || algo_info.algo == 'seed-128') {
			var pbdk_size = 20;
		} else {
			var pbdk_size = key_size + algo_info.blockSize;
		}

		var pbdk = jCastle.kdf.pbkdf1(
			password,
			salt,
			iterations,
			pbdk_size,
			algo_info.hashAlgo
		);

		var key = Buffer.slice(pbdk, 0, key_size);

		if (algo_info.algo == 'seed' || algo_info.algo == 'seed-128') {
			if (algo_info.oid == '1.2.410.200004.1.4') {
				var iv = Buffer.from('123456789012345', 'latin1');
			} else {
				var div = Buffer.slice(pbdk, key_size);
				var md = new jCastle.digest(algo_info.hashAlgo);
				div = md.digest(div);
				var iv = Buffer.slice(div, 0, algo_info.blockSize);
			}
		} else {
			var iv = Buffer.slice(pbdk, algo_info.keySize, algo_info.keySize + algo_info.blockSize);
		}

		var params = jCastle.mcrypt.getAlgoParameters(pbe_params);
		params.iv = iv;
		//params.padding = 'pkcs7';
		params.padding = algo_info.padding;
		params.key = key;
		params.mode = algo_info.mode;
		params.isEncryption = true;

		// enc_data should be always 'latin1' buffer.
		if (!Buffer.isBuffer(data)) data = Buffer.from(data, 'latin1');

		var crypto = new jCastle.mcrypt(algo_info.algo);
		crypto.start(params);
		crypto.update(data);
		var encrypted = crypto.finalize();

		return {
			oid: algo_info.oid,
			salt: salt,
			iterations: iterations,
			encrypted: encrypted
		};
	},

/*
SEQUENCE(2 elem)
	SEQUENCE(2 elem)
		OBJECT IDENTIFIER				1.2.840.113549.1.5.3  -- pbeWithMD5AndDES-CBC
		SEQUENCE(2 elem)
			OCTET STRING(8 byte)		700D193F07B862AF
			INTEGER						2048
	OCTET STRING(1224 byte)				363AEA0326F8FD5B0943D3E165BD9D9A82BB58EACD981DB23EB859F0A2470A560D09…
*/

	decrypt: function(pbe_info, password, enc_data)
	{
		var algo_info = pbe_info.algoInfo;
		var kdf_info = 'kdfInfo' in pbe_info ? pbe_info.kdfInfo : {};
		var salt = 'salt' in kdf_info ? kdf_info.salt : null;
		var iterations = 'iterations' in kdf_info ? kdf_info.iterations : 1;
		var pbe_params = 'params' in pbe_info ? pbe_info.params : {};

		if (jCastle.util.isString(algo_info)) {
			algo_info = jCastle.pbe.getPbeAlgorithmInfo(algo_info);
		}

		var key_size = 'keySize' in kdf_info ? kdf_info.keySize : ('keySize' in pbe_params ? pbe_params.keySize : algo_info.keySize);

		if (!Buffer.isBuffer(salt)) salt = Buffer.from(salt, 'latin1');

	/* openssl pkcs8 -in privkey-plain.pem -topk8 -out enc_pkcs8_pbe_sha1_3des_pki.pem -v1 PBE-SHA1-3DES */
	/*
	PKCS#5 v1.5 and PKCS#12 algorithms.
	-----------------------------------
			
	Various algorithms can be used with the -v1 command line option,
	including PKCS#5 v1.5 and PKCS#12. These are described in more detail below.
			
	PBE-MD2-DES, PBE-MD5-DES
		
	These algorithms were included in the original PKCS#5 v1.5 specification.
	They only offer 56 bits of protection since they both use DES.
			
	PBE-SHA1-RC2-64, PBE-MD2-RC2-64, PBE-MD5-RC2-64, PBE-SHA1-DES
		
	These algorithms are not mentioned in the original PKCS#5 v1.5 specification
	but they use the same key derivation algorithm and are supported by some software. 
	They are mentioned in PKCS#5 v2.0. They use either 64 bit RC2 or 56 bit DES.
		
	PBE-SHA1-RC4-128, PBE-SHA1-RC4-40, PBE-SHA1-3DES, PBE-SHA1-2DES, PBE-SHA1-RC2-128, PBE-SHA1-RC2-40			
	*/
		
//console.log(algo_info);

		// http://blogs.msdn.com/b/shawnfa/archive/2004/04/14/generating-a-key-from-a-password.aspx
		// for PasswordDeriveBytes see: https://community.oracle.com/thread/1528029
		// http://gilchris.tistory.com/m/post/3
		// https://groups.google.com/forum/#!topic/crypto-js/tPMswvxZ7Cw

		// for SEED algorithm, refer to http://www.rootca.or.kr/kcac/down/TechSpec/2.3-KCAC.TS.ENC.pdf
		if (algo_info.algo == 'seed' || algo_info.algo == 'seed-128') {
			var dk_size = 20;
		} else {
			var dk_size = key_size + algo_info.blockSize;
		}

		// console.log(pbe_info);

		var pbdk = jCastle.kdf.pbkdf1(
			password,
			salt,
			iterations,
			dk_size,
			algo_info.hashAlgo
		);

		var key = Buffer.slice(pbdk, 0, key_size);

		if (algo_info.algo == 'seed' || algo_info.algo == 'seed-128') {
			if (algo_info.oid == '1.2.410.200004.1.4') {
				var iv = Buffer.from('123456789012345', 'latin1');
			} else {
				// oid : 1.2.410.200004.1.15
				var div = Buffer.slice(pbdk, key_size);
				var md = new jCastle.digest(algo_info.hashAlgo);
				div = md.digest(div);
				var iv = Buffer.slice(div, 0, algo_info.blockSize);
			}
		} else {
			var iv = Buffer.slice(pbdk, algo_info.keySize, algo_info.keySize + algo_info.blockSize);
		}

		var params = jCastle.mcrypt.getAlgoParameters(pbe_params);
		params.iv = iv;
		//params.padding = 'pkcs7';
		params.padding = algo_info.padding;
		params.key = key;
		params.mode = algo_info.mode;
		params.isEncryption = false;

		// enc_data should be always 'latin1' buffer.
		if (!Buffer.isBuffer(enc_data)) enc_data = Buffer.from(enc_data, 'latin1');

		var crypto = new jCastle.mcrypt(algo_info.algo);
		crypto.start(params);
		crypto.update(enc_data);
		var der = crypto.finalize();

		return der;
	}
};

jCastle.pbe.PBES1 = jCastle.pbe.pbes1;

jCastle.pbe.pbes2 = {
/*
RFC 2898

6.2 PBES2

   PBES2 combines a password-based key derivation function, which shall
   be PBKDF2 (Section 5.2) for this version of PKCS #5, with an
   underlying encryption scheme (see Appendix B.2 for examples). The key
   length and any other parameters for the underlying encryption scheme
   depend on the scheme.

   PBES2 is recommended for new applications.

6.2.1   Encryption Operation

   The encryption operation for PBES2 consists of the following steps,
   which encrypt a message M under a password P to produce a ciphertext
   C, applying a selected key derivation function KDF and a selected
   underlying encryption scheme:

      1. Select a salt S and an iteration count c, as outlined in
         Section 4.

      2. Select the length in octets, dkLen, for the derived key for the
         underlying encryption scheme.

      3. Apply the selected key derivation function to the password P,
         the salt S, and the iteration count c to produce a derived key
         DK of length dkLen octets:

                 DK = KDF (P, S, c, dkLen) .

      4. Encrypt the message M with the underlying encryption scheme
         under the derived key DK to produce a ciphertext C. (This step
         may involve selection of parameters such as an initialization
         vector and padding, depending on the underlying scheme.)

      5. Output the ciphertext C.

   The salt S, the iteration count c, the key length dkLen, and
   identifiers for the key derivation function and the underlying
   encryption scheme may be conveyed to the party performing decryption
   in an AlgorithmIdentifier value (see Appendix A.4).

6.2.2   Decryption Operation

   The decryption operation for PBES2 consists of the following steps,
   which decrypt a ciphertext C under a password P to recover a message
   M:

      1. Obtain the salt S for the operation.

      2. Obtain the iteration count c for the key derivation function.

      3. Obtain the key length in octets, dkLen, for the derived key for
         the underlying encryption scheme.

      4. Apply the selected key derivation function to the password P,
         the salt S, and the iteration count c to produce a derived key
         DK of length dkLen octets:

                 DK = KDF (P, S, c, dkLen) .

      5. Decrypt the ciphertext C with the underlying encryption scheme
         under the derived key DK to recover a message M. If the
         decryption function outputs "decryption error," then output
         "decryption error" and stop.

      6. Output the recovered message M.
*/
	//encrypt: function(algo_info, prf_hash, password, salt, iterations, data, key_size, iv, salt_len)
	encrypt: function(pbe_info, password, data)
	{
		var algo_info = pbe_info.algoInfo;
		var kdf_info = 'kdfInfo' in pbe_info ? pbe_info.kdfInfo : {};
		var pbe_params = 'params' in pbe_info ? pbe_info.params : {};
		var iv = 'iv' in pbe_params ? pbe_params.iv : null;
		var salt = 'salt' in kdf_info ? kdf_info.salt : null;
		var iterations = 'iterations' in kdf_info ? kdf_info.iterations : 1;
		var salt_len = 'saltLength' in kdf_info ? kdf_info.saltLength : null;
		var prf_hash = 'prfHash' in kdf_info ? kdf_info.prfHash : 'sha-1';

		if (jCastle.util.isString(algo_info)) {
			algo_info = jCastle.pbe.getAlgorithmInfo(algo_info);
		}

		var key_size = 'keySize' in kdf_info ? kdf_info.keySize : ('keySize' in pbe_params ? pbe_params.keySize : algo_info.keySize);

		var prng = new jCastle.prng();

		if (!iv) {
			if (algo_info.algo != 'rc4') { // stream cipher
//				iv = jCastle.mcrypt.createInitialVector(algo_info.blockSize);
				iv = prng.nextBytes(algo_info.blockSize, true);
			}
		}

		if (!salt) {
			salt_len = salt_len || 8;
			var salt = prng.nextBytes(salt_len, true);
			jCastle.util.avoidAsn1Format(salt);
		}

		var key = jCastle.kdf.pbkdf2(
			password,
			salt,
			iterations,
			key_size,
			prf_hash
		);

		// console.log('iv: ', iv);
		// console.log('salt: ', salt);
		// console.log('iterations: ', iterations);
		// console.log('key_size: ', key_size);
		// console.log('key: ', key);

		var params = jCastle.mcrypt.getAlgoParameters(pbe_params);
		params.iv = iv;
		//params.padding = 'pkcs7';
		params.padding = algo_info.padding;
		params.key = key;
		params.mode = algo_info.mode;
		params.isEncryption = true;

		// enc_data should be always 'latin1' buffer.
		if (!Buffer.isBuffer(data)) data = Buffer.from(data, 'latin1');

		var crypto = new jCastle.mcrypt(algo_info.algo);
		crypto.start(params);
		crypto.update(data);
		var encrypted = crypto.finalize();

		return {
			oid: algo_info.oid,
			salt: salt, 
			iterations: iterations,
			iv: iv,
			encrypted: encrypted
		};
	},

	decrypt: function(pbe_info, password, enc_data)
	{
		var algo_info = pbe_info.algoInfo;
		var kdf_info = 'kdfInfo' in pbe_info ? pbe_info.kdfInfo : {};
		var salt = 'salt' in kdf_info ? kdf_info.salt : null;
		var iterations = 'iterations' in kdf_info ? kdf_info.iterations : 1;
		var pbe_params = 'params' in pbe_info ? pbe_info.params : {};
		var prf_hash = 'prfHash' in kdf_info ? kdf_info.prfHash : 'sha-1';

		if (jCastle.util.isString(algo_info)) {
			algo_info = jCastle.pbe.getAlgorithmInfo(algo_info);
		}

		var key_size = 'keySize' in kdf_info ? kdf_info.keySize : ('keySize' in pbe_params ? pbe_params.keySize : algo_info.keySize);

		if (!Buffer.isBuffer(salt)) salt = Buffer.from(salt, 'latin1');

		// PBKDF2 with HmacSHA1
		var key = jCastle.kdf.pbkdf2(
			password,
			salt,
			iterations,
			key_size,
			prf_hash
		);

		// params should have iv for decryption.
		var params = jCastle.mcrypt.getAlgoParameters(pbe_params);
		//params.padding = 'pkcs7';
		params.padding = algo_info.padding;
		params.key = key;
		params.mode = algo_info.mode;
		params.isEncryption = false;

		// enc_data should be always 'latin1' buffer.
		if (!Buffer.isBuffer(enc_data)) enc_data = Buffer.from(enc_data, 'latin1');

		var crypto = new jCastle.mcrypt(algo_info.algo);
		crypto.start(params);
		crypto.update(enc_data);
		var der = crypto.finalize();

		return der;
	}
};

jCastle.pbe.PBES2 = jCastle.pbe.pbes2;

jCastle.pbe.pkcs12pbes = 
{
	encrypt: function(pbe_info, password, data)
	{
		var algo_info = pbe_info.algoInfo;
		var kdf_info = 'kdfInfo' in pbe_info ? pbe_info.kdfInfo : {};
		var salt = 'salt' in kdf_info ? kdf_info.salt : null;
		var iterations = 'iterations' in kdf_info ? kdf_info.iterations : 1;
		var pbe_params = 'params' in pbe_info ? pbe_info.params : {};
		var salt_len = 'saltLength' in kdf_info ? kdf_info.saltLength : null;

		if (jCastle.util.isString(algo_info)) {
			algo_info = jCastle.pbe.getPbeAlgorithmInfo(algo_info);
		}
		var key_size = 'keySize' in kdf_info ? kdf_info.keySize : ('keySize' in pbe_params ? pbe_params.keySize : algo_info.keySize);
		

		if (!salt) {
			salt_len = salt_len || 8;
			salt = new jCastle.prng().nextBytes(salt_len, true);
			jCastle.util.avoidAsn1Format(salt);
		}

		if (!Buffer.isBuffer(salt)) salt = Buffer.from(salt, 'latin1');

		var key = jCastle.kdf.pkcs12DeriveKey(
			password,
			salt,
			iterations,
			1,
			key_size,
			algo_info.hashAlgo
		);

		// console.log(pbe_info);
		// console.log(algo_info);
		
		if ('using2Key' in algo_info && algo_info.using2Key) {
			//key += key.substr(0, 8);
			key = Buffer.concat([key, key.slice(0, 8)]);
		}

		var iv = null;

		// stream block size is 1. and stream mode need no IV.
		if ('blockSize' in algo_info && algo_info.blockSize > 1) {
			iv = jCastle.kdf.pkcs12DeriveKey(
				password,
				salt,
				iterations,
				2,
				algo_info.blockSize,
				algo_info.hashAlgo
			);
		}

		// console.log('iv: ', iv);

		var params = jCastle.mcrypt.getAlgoParameters(pbe_params);
		//params.padding = 'pkcs7';
		params.padding = algo_info.padding;
		params.key = key;
		params.iv = iv;
		params.mode = algo_info.mode;
		params.isEncryption = true;

		// enc_data should be always 'latin1' buffer.
		if (!Buffer.isBuffer(data)) data = Buffer.from(data, 'latin1');

		var crypto = new jCastle.mcrypt(algo_info.algo);
		crypto.start(params);
		crypto.update(data);
		var encrypted = crypto.finalize();

		return {
			oid: algo_info.oid,
			salt: salt,
			iterations: iterations,
			encrypted: encrypted
		};
	},


/*
SEQUENCE(2 elem)
	SEQUENCE(2 elem)
		OBJECT IDENTIFIER				1.2.840.113549.1.12.1.4  -- pbeWithSHAAnd2-KeyTripleDES-CBC
		SEQUENCE(2 elem)
			OCTET STRING(8 byte)		4951BCEF79DFF202
			INTEGER						2048
	OCTET STRING(1224 byte)				CB93E00BAC2597C0D23E0DACFAAF55D60863360380B3E7C3677E6248ABC3AA72D8D3…
*/
	decrypt: function(pbe_info, password, enc_data)
	{
		var algo_info = pbe_info.algoInfo;
		var kdf_info = 'kdfInfo' in pbe_info ? pbe_info.kdfInfo : {};
		var salt = 'salt' in kdf_info ? kdf_info.salt : null;
		var iterations = 'iterations' in kdf_info ? kdf_info.iterations : 1;
		var pbe_params = 'params' in pbe_info ? pbe_info.params : {};
		var iv;
		
		if (jCastle.util.isString(algo_info)) {
			algo_info = jCastle.pbe.getPbeAlgorithmInfo(algo_info);
		}
		var key_size = 'keySize' in kdf_info ? kdf_info.keySize : ('keySize' in pbe_params ? pbe_params.keySize : algo_info.keySize);

		// console.log('key_size: ', key_size);

		if (!Buffer.isBuffer(salt)) salt = Buffer.from(salt, 'latin1');

		var key = jCastle.kdf.pkcs12DeriveKey(
			password,
			salt,
			iterations,
			1,
			key_size,
			algo_info.hashAlgo
		);
					
		if ('using2Key' in algo_info && algo_info.using2Key) {
			// 2-KeyTripleDES
			/*
			http://en.wikipedia.org/wiki/Triple_DES

			The standards define three keying options:

				Keying option 1: All three keys are independent.
				Keying option 2: K1 and K2 are independent, and K3 = K1.
				Keying option 3: All three keys are identical, i.e. K1 = K2 = K3.

			Keying option 1 is the strongest, with 3 × 56 = 168 independent key bits.

			Keying option 2 provides less security, with 2 × 56 = 112 key bits.
			This option is stronger than simply DES encrypting twice, 
			e.g. with K1 and K2, because it protects against meet-in-the-middle attacks.

			Keying option 3 is equivalent to DES, with only 56 key bits. 
			This option provides backward compatibility with DES, 
			because the first and second DES operations cancel out. 
			It is no longer recommended by the National Institute of Standards and Technology (NIST),
			and is not supported by ISO/IEC 18033-3.
			*/
			//key += key.substr(0, 8);
			key = Buffer.concat([key, key.slice(0, 8)]);
		}

		// console.log('pbe_info: ', pbe_info);
		// console.log('algo_info: ', algo_info);
		// console.log('salt: ', salt);
		// console.log('password: ', password);
		// console.log('key: ', key);

		
		// stream block size is 1. and stream mode need no IV.
		if ('blockSize' in algo_info && algo_info.blockSize > 1) {
			iv = jCastle.kdf.pkcs12DeriveKey(
				password,
				salt,
				iterations,
				2,
				algo_info.blockSize,
				algo_info.hashAlgo,
			);
		}
		// } else {
		// 	iv = null;
		// }

		var params = jCastle.mcrypt.getAlgoParameters(pbe_params);
		//params.padding = iv ? 'pkcs7' : 'none';
		params.padding = algo_info.padding;
		params.key = key;
		params.iv = iv;
		params.mode = algo_info.mode;
		params.isEncryption = false;

		// console.log('crypto params: ', params);

		// enc_data should be always 'latin1' buffer.
		if (!Buffer.isBuffer(enc_data)) enc_data = Buffer.from(enc_data, 'latin1');

		var crypto = new jCastle.mcrypt(algo_info.algo);
		crypto.start(params);
		crypto.update(enc_data);
		var der = crypto.finalize();

		return der;
	}
};

jCastle.pbe.PKCS12PBES = jCastle.pbe.pkcs12pbes;

// parse asn1 sequence and decrypt
jCastle.pbe.asn1 = {
	// encrypt data and build pbe sequence
	encrypt: function(data, options = {})
	{
		var der;
		var enc_algo = 'pbeWithMD5AndDES-CBC';
		var iterations = 2048;
		var salt, salt_len, iv;
		var asn1 = new jCastle.asn1();
		var password = options.password;

		if (!password || password.leng === 0) {
			throw jCastle.exception("NO_PASSPHRASE", 'PBE011');
		}

		if (!Buffer.isBuffer(password))
			password = Buffer.from(password, 'latin1');

		if ('algo' in options) {
			enc_algo = options.algo;
		}

		if ('salt' in options) {
			salt = options.salt;
			if (!Buffer.isBuffer(salt))
				salt = Buffer.from(salt, 'latin1');
		} else if ('saltLength' in options) {
			salt_len = options.saltLength;
			// var salt = new jCastle.prng().nextBytes(salt_len, true);
			// jCastle.util.avoidAsn1Format(salt);
		}

		if ('iterations' in options) {
			iterations = options.iterations;
		}

		// pkcs#5 v2.0 algorithm
		if (enc_algo.indexOf('pbeWith') === -1 && enc_algo.indexOf('PBE-') === -1) {

//console.log('pkcs#5 v2.0 algorithm');

			var prf_hash = 'sha-1';
			enc_algo = enc_algo.toLowerCase();

			var key_size = 0;
			if ('keySize' in options) {
				key_size = options.keySize;
			}

			var algo_info = jCastle.pbe.getAlgorithmInfo(enc_algo);
//console.log(algo_info);
			if (algo_info.algo == 'rc2' && key_size == 0) {
				// rc2 default key size
				key_size = 16;
			}

			if ('prfHash' in options) {
				prf_hash = options.prfHash.toLowerCase();
			} else if ('prf' in options) {
				var flag = false;
				if (jCastle.oid.getOID(options.prf)) {
					var m = /hmacWith([a-z0-9\-]+)/i.exec(options.prf);
					if (m) {
						prf_hash = m[1];
						flag = true;
					}
				}

				if (!flag) {
					throw jCastle.exception("UNSUPPORTED_PRF", 'PBE012');
				}
			}

			var pbe_info = {
				type: 'pkcs5PBKDF2',
				algo: algo_info.algo,
				algoInfo: algo_info,
				kdfInfo: {
					salt: salt,
					iterations: iterations,
					prfHash: prf_hash
				},
				params: jCastle.mcrypt.getAlgoParameters(options)
			};

			if (key_size) {
				pbe_info.kdfInfo.keySize = key_size;
				pbe_info.params.keySize = key_size;
			}
			//if (iv) pbe_info.params.iv = iv;

//			jCastle.mcrypt.checkAlgoParameters(pbe_info.params, pbe_info.algoInfo.algo, pbe_info.algoInfo.mode, prng);

			var res = jCastle.pbe.pbes2.encrypt(pbe_info, password, data);

			pbe_info.kdfInfo.salt = res.salt;
			pbe_info.params.iv = res.iv;

			var pbe_sequence = jCastle.pbe.asn1.pbeInfo.schema(pbe_info);

//console.log(pbe_sequence);
			der = asn1.getDER({
				type: jCastle.asn1.tagSequence,
				items: [ 
					pbe_sequence, {
					type: jCastle.asn1.tagOctetString,
					value: res.encrypted
				}]
			});
		} else {
			// PKCS#5 v1.5 or PKCS#12 Password Based Encryption

	//		console.log('pkcs#5 v1.5 or pkcs#12 algorithm');

			var algo_info = jCastle.pbe.getPbeAlgorithmInfo(enc_algo);
//console.log(algo_info);

/*
SEQUENCE(2 elem)
	SEQUENCE(2 elem)
		OBJECT IDENTIFIER				1.2.840.113549.1.5.3 -- pbeWithMD5AndDES-CBC
		SEQUENCE(2 elem)
			OCTET STRING(8 byte)		700D193F07B862AF
			INTEGER						2048
	OCTET STRING(1224 byte)				363AEA0326F8FD5B0943D3E165BD9D9A82BB58EACD981DB23EB859F0A2470A560D09…
*/
/*
SEQUENCE(2 elem)
	SEQUENCE(2 elem)
		OBJECT IDENTIFIER				1.2.840.113549.1.12.1.4  -- pbeWithSHAAnd2-KeyTripleDES-CBC
		SEQUENCE(2 elem)
			OCTET STRING(8 byte)		4951BCEF79DFF202
			INTEGER						2048
	OCTET STRING(1224 byte)				CB93E00BAC2597C0D23E0DACFAAF55D60863360380B3E7C3677E6248ABC3AA72D8D3…
*/
			var pbe_info = {
				type: algo_info.type == 'pkcs5' ? 'pkcs5PBKDF1' : 'pkcs12DeriveKey',
				algo: algo_info.algo,
				algoInfo: algo_info,
				kdfInfo: {
					salt: salt,
					iterations: iterations,
					saltLength: salt_len
				},
				params: jCastle.mcrypt.getAlgoParameters(options)
			};
				
				
			if (algo_info.type == 'pkcs5') {
				// pkcs#5 v1.5 - PBKDF1
				res = jCastle.pbe.pbes1.encrypt(pbe_info, password, data);
			} else {
				// pkcs#12 - pbe
				res = jCastle.pbe.pkcs12pbes.encrypt(pbe_info, password, data);
			}

			pbe_info.kdfInfo.salt = res.salt;

			var pbe_sequence = jCastle.pbe.asn1.pbeInfo.schema(pbe_info);

			der = asn1.getDER({
				type: jCastle.asn1.tagSequence,
				items: [
					pbe_sequence, {
					type: jCastle.asn1.tagOctetString,
					value: res.encrypted
				}]
			});
		}

		return der;
	},

/*
SEQUENCE (2 elem)
  SEQUENCE (2 elem)
    OBJECT IDENTIFIER 1.2.840.113549.1.12.1.1 pbeWithSHAAnd128BitRC4 (PKCS #12 PbeIds.)
    SEQUENCE (2 elem)
      OCTET STRING (8 byte) E0A0246A30B9F0F9
      INTEGER 2048
  OCTET STRING (1217 byte) 5568DD5A27B0DDA4400DEA02747C7E6CD0E5AD7672D30694661343AA8E02D364A389…
*/	
	decrypt: function(sequence, password)
	{
		if (Buffer.isBuffer(sequence) || jCastle.util.isString(sequence)) {
			sequence = jCastle.asn1.create().parse(sequence);
		}

		var pbe_info = jCastle.pbe.asn1.pbeInfo.parse(sequence.items[0]);
//console.log(pbe_info);
		var enc_data = Buffer.from(sequence.items[1].value, 'latin1');

		switch (pbe_info.type) {
			case 'pkcs5PBKDF2':			
				return jCastle.pbe.pbes2.decrypt(
					pbe_info, 
					password,
					enc_data);
			case 'pkcs5PBKDF1':
				return jCastle.pbe.pbes1.decrypt(
					pbe_info,
					password,
					enc_data);
			case 'pkcs12DeriveKey':
				return jCastle.pbe.pkcs12pbes.decrypt(
					pbe_info,
					password,
					enc_data);

			default:
				throw jCastle.exception("UNKNOWN_KDF_TYPE", 'PBE013');
		}
	}
};

jCastle.pbe.asn1.pbkdf2 = {
/* openssl pkcs8 -in privkey-plain.pem -topk8 -v2 des-ede3-cbc -out enc_pkcs8__des3_cbc_pki.pem */
			
/*
SEQUENCE(2 elem)
	SEQUENCE(2 elem)
		OBJECT IDENTIFIER					1.2.840.113549.1.5.13  -- pkcs5PBES2
		SEQUENCE(2 elem)
			SEQUENCE(2 elem)
				OBJECT IDENTIFIER			1.2.840.113549.1.5.12  -- pkcs5PBKDF2 (PKCS #5 v2.0)
				SEQUENCE(2 elem)
					OCTET STRING(8 byte) 	A73C87E488ED0B24
					INTEGER					2048
			SEQUENCE(2 elem)
				OBJECT IDENTIFIER			1.2.840.113549.3.7  -- des-EDE3-CBC
				OCTET STRING(8 byte) 		937BC960ACEB7796
	OCTET STRING(1224 byte) 				7D5409B4BA9BB12D07CF62D118FFDD60EC230B4040501918DAB8B8EFA7F64D3C0B49…
*/
			
/* openssl pkcs8 -in privkey-plain.pem -topk8 -v2 rc2-cbc -out enc_pkcs8_rc2_cbc_pki.pem */
			
/*
SEQUENCE(2 elem)
	SEQUENCE(2 elem)
		OBJECT IDENTIFIER					1.2.840.113549.1.5.13  -- pkcs5PBES2
		SEQUENCE(2 elem)
			SEQUENCE(2 elem)
				OBJECT IDENTIFIER			1.2.840.113549.1.5.12  -- pkcs5PBKDF2 (PKCS #5 v2.0)
				SEQUENCE(3 elem)
					OCTET STRING(8 byte) 	611E83AA529335AD
					INTEGER					2048
					INTEGER					16
			SEQUENCE(2 elem)
				OBJECT IDENTIFIER			1.2.840.113549.3.2  -- rc2-CBC
				SEQUENCE(2 elem)
					INTEGER					58
					OCTET STRING			d4¬ci
	OCTET STRING(1224 byte) 				46C1FA0C4CB8ED10649C2EABDFD89436BE6FD767A1B1B97FFDE78C0F9B58729568D2…
*/


/* openssl pkcs8 -in privkey-plain.pem -topk8 -v2 rc2-cbc -v2prf hmacWithSHA384 -out enc_pkcs8_rc2_cbc_hmac_sha384_pki.pem */

/*
SEQUENCE(2 elem)
	SEQUENCE(2 elem)
		OBJECT IDENTIFIER					1.2.840.113549.1.5.13  -- -- pkcs5PBES2
		SEQUENCE(2 elem)
			SEQUENCE(2 elem)
				OBJECT IDENTIFIER			1.2.840.113549.1.5.12  -- pkcs5PBKDF2 (PKCS #5 v2.0)
				SEQUENCE(4 elem)
					OCTET STRING(8 byte)	16F4A659DE30BB2D
					INTEGER					2048
					INTEGER					16
					SEQUENCE(2 elem)
						OBJECT IDENTIFIER	1.2.840.113549.2.10  -- hmacWithSHA384
						NULL
			SEQUENCE(2 elem)
				OBJECT IDENTIFIER			1.2.840.113549.3.2  -- rc2-CBC
				SEQUENCE(2 elem)
					INTEGER					58
					OCTET STRING(8 byte)	D41DAD6354DD7E19
	OCTET STRING(1224 byte)					389B0B63564DEE6DBA26319C70116CF2A4D8E3E99F3EA5975D002AEA327E2DDD4796…
*/
			
/* openssl pkcs8 -in privkey-plain.pem -topk8 -v2 aes-128-cbc -v2prf hmacWithSHA384 
		-out enc_pkcs8_aes128_cbc__hmac_sha384_pki.pem */
			
/*
SEQUENCE(2 elem)
	SEQUENCE(2 elem)						
		OBJECT IDENTIFIER					1.2.840.113549.1.5.13
		SEQUENCE(2 elem)
			SEQUENCE(2 elem)
				OBJECT IDENTIFIER			1.2.840.113549.1.5.12
				SEQUENCE(3 elem)
					OCTET STRING(8 byte) 	848B15C3A6AF80CD
					INTEGER					2048
					SEQUENCE(2 elem)
						OBJECT IDENTIFIER	1.2.840.113549.2.9
						NULL
			SEQUENCE(2 elem)
				OBJECT IDENTIFIER			2.16.840.1.101.3.4.1.42
				OCTET STRING(16 byte) 		507C72DA9758B54AFB246E8F8FE21BA3
	OCTET STRING(1232 byte) 					96C6DD981F43B378F4BC4DE7752D715D595911680B1D1F35066254D1E4C947676E98…
*/
	parse: function(sequence)
	{
		var kdfIdentifier = sequence.items[0].value;

		jCastle.assert(kdfIdentifier, jCastle.oid.getOID("pkcs5PBKDF2"), "UNSUPPORTED_KDF", 'PBE014'); // "1.2.840.113549.1.5.12" | PKCS#5 MGF1 or pkcs5PBKDF2

		var idx = 0;
		var salt = Buffer.from(sequence.items[1].items[idx++].value, 'latin1');
		var iterations = sequence.items[1].items[idx++].intVal;

		// default is hmacWithSHA1(1.2.840.113549.2.7)
		var prf_hash = 'sha-1';

		if (typeof sequence.items[1].items[idx] != 'undefined' &&
			sequence.items[1].items[idx].type == jCastle.asn1.tagInteger) {
			//var key_size = jCastle.util.str2int(sequence.items[1].items[idx++].value);
			var key_size = sequence.items[1].items[idx++].intVal;
		}

/*
https://www.ietf.org/rfc/rfc2898.txt
							
							
rc2CBC OBJECT IDENTIFIER ::= {encryptionAlgorithm 2}

   The parameters field associated with OID in an AlgorithmIdentifier
   shall have type RC2-CBC-Parameter:

   RC2-CBC-Parameter ::= SEQUENCE {
	   rc2ParameterVersion INTEGER OPTIONAL,
	   iv OCTET STRING (SIZE(8)) }

   The fields of type RC2-CBCParameter have the following meanings:

   -  rc2ParameterVersion is a proprietary RSA Security Inc. encoding of
	  the "effective key bits" for RC2. The following encodings are
	  defined:

		 Effective Key Bits         Encoding
				 40                    160
				 64                    120
				128                     58
			   b >= 256                  b

   If the rc2ParameterVersion field is omitted, the "effective key bits"
   defaults to 32. (This is for backward compatibility with certain very
   old implementations.)

   -  iv is the eight-octet initialization vector.
*/
								
		// get prf hmac id
		if (typeof sequence.items[1].items[idx] != 'undefined' &&
			sequence.items[1].items[idx].type == jCastle.asn1.tagSequence
		) {
			var prf_id = sequence.items[1].items[idx].items[0].value;
			prf_hash = jCastle.pbe.getPrfHashName(prf_id);
		}

		var kdf_info = {
			type: 'pkcs5PBKDF2',
			salt: salt,
			iterations: iterations,
			prfHash: prf_hash
		};
		if (key_size) kdf_info.keySize = key_size;

		return kdf_info;
	},

	schema: function(kdf_info, type, key_size_schema)
	{
//		var kdf_info = pbe_info.kdfInfo;
//console.log(kdf_info);

		key_size_schema = !!key_size_schema;

		var prf_schema = {
			type: jCastle.asn1.tagSequence,
			items: [{
				type: jCastle.asn1.tagOctetString,
				value: kdf_info.salt
			}, {
				type: jCastle.asn1.tagInteger,
				intVal: kdf_info.iterations
			}]
		};

		var key_size = kdf_info.keySize;

//		if (pbe_info.algo == 'rc2') {
		if (key_size_schema) {
			prf_schema.items.push({
				type: jCastle.asn1.tagInteger,
				intVal: key_size
			});
		}				

		var prf_hash = kdf_info.prfHash;
		if (prf_hash) prf_hash = jCastle.digest.getValidAlgoName(prf_hash);

		// if prf hash is not sha-1 then
		if (prf_hash != 'sha-1') {
			prf_schema.items.push({
				type: jCastle.asn1.tagSequence,
				items: [{
					type: jCastle.asn1.tagOID,
					value: jCastle.pbe.getPrfHashOID(prf_hash)
				}, {
					type: jCastle.asn1.tagNull,
					value: null
				}]
			});
		}

		if (type == jCastle.asn1.tagSequence) {
			var schema = {
				type: type,
				items: []
			};
		} else {
			var schema = {
				tagClass: jCastle.asn1.tagClassContextSpecific,
				type: type,
				constructed: true,
				items: []
			};
		}

		schema.items.push({
			type: jCastle.asn1.tagOID,
			value: jCastle.oid.getOID("pkcs5PBKDF2") //"1.2.840.113549.1.5.12"
		}, prf_schema);

		return schema;
	}
};

/*
		SEQUENCE(2 elem)
			OBJECT IDENTIFIER						2.16.840.1.101.3.4.1.2 -- aes-128-CBC
			OCTET STRING(16 byte)					9E8D877D8003A552859DC6F3B9DFC752
*/
/*
        SEQUENCE (2 elem)
          OBJECT IDENTIFIER 2.16.840.1.101.3.4.1.46 aes256-GCM (NIST Algorithm)
          SEQUENCE (2 elem)
            OCTET STRING (12 byte) EA9CBDCB9785B610BFFEED41
            INTEGER 16
*/
/*
RCF 5084			Using AES-CCM and AES-GCM in the CMS

   With all three AES-CCM algorithm identifiers, the AlgorithmIdentifier
   parameters field MUST be present, and the parameters field must
   contain a CCMParameter:

      CCMParameters ::= SEQUENCE {
        aes-nonce         OCTET STRING (SIZE(7..13)),
        aes-ICVlen        AES-CCM-ICVlen DEFAULT 12 }

      AES-CCM-ICVlen ::= INTEGER (4 | 6 | 8 | 10 | 12 | 14 | 16)
*/
/*
RCF 5084			Using AES-CCM and AES-GCM in the CMS

   With all three AES-GCM algorithm identifiers, the AlgorithmIdentifier
   parameters field MUST be present, and the parameters field must
   contain a GCMParameter:

      GCMParameters ::= SEQUENCE {
        aes-nonce        OCTET STRING, -- recommended size is 12 octets
        aes-ICVlen       AES-GCM-ICVlen DEFAULT 12 }

      AES-GCM-ICVlen ::= INTEGER (12 | 13 | 14 | 15 | 16)

*/
jCastle.pbe.asn1.encAlgoInfo = {
	parse: function(sequence)
	{
		var enc_algo = sequence.items[0].value;
						
	//		console.log('pem is encrypted with pkcs#5 mgf1 or pkcs#5 pbkdf2');
	//		console.log(enc_algo);

		var algo = jCastle.oid.getName(enc_algo);

		var algo_info = jCastle.pbe.getAlgorithmInfoByOID(enc_algo);
		if (!algo_info) {
			throw jCastle.exception("UNSUPPORTED_ALGO_OID", 'PBE015');
		}
	//		console.log(algo_info);

		var enc_algo_info = {
			type: 'enc',
			algo: algo,
			algoInfo: algo_info,
			params: {}
		};


		var iv, nonce, tagSize = 12; // default
						
		// iv
		if (sequence.items[1].type == jCastle.asn1.tagOctetString) {
			iv = Buffer.from(sequence.items[1].value, 'latin1');
			enc_algo_info.params.iv = iv;
		} else if (sequence.items[1].type == jCastle.asn1.tagSequence) {
			var params_seq = sequence.items[1];
			switch (algo_info.mode) {
				case 'gcm':
				case 'ccm':
				case 'eax':
				case 'cwc':
					// GCM or CCM
					nonce = Buffer.from(params_seq.items[0].value, 'latin1');
					tagSize = params_seq.items[1].intVal;

					enc_algo_info.params.nonce = nonce;
					enc_algo_info.params.tagSize = tagSize;
					break;
				case 'cbc':
					if (algo_info.algo == 'rc2') {
/*
https://www.ietf.org/rfc/rfc2898.txt
							
							
rc2CBC OBJECT IDENTIFIER ::= {encryptionAlgorithm 2}

   The parameters field associated with OID in an AlgorithmIdentifier
   shall have type RC2-CBC-Parameter:

   RC2-CBC-Parameter ::= SEQUENCE {
	   rc2ParameterVersion INTEGER OPTIONAL,
	   iv OCTET STRING (SIZE(8)) }

   The fields of type RC2-CBCParameter have the following meanings:

   -  rc2ParameterVersion is a proprietary RSA Security Inc. encoding of
	  the "effective key bits" for RC2. The following encodings are
	  defined:

		 Effective Key Bits         Encoding
				 40                    160
				 64                    120
				128                     58
			   b >= 256                  b

   If the rc2ParameterVersion field is omitted, the "effective key bits"
   defaults to 32. (This is for backward compatibility with certain very
   old implementations.)

   -  iv is the eight-octet initialization vector.
*/
						var rc2ParameterVersion = 32; // default
						if (params_seq.items[0].type == jCastle.asn1.tagInteger) {
							//var rc2ParameterVersion = parseInt(jCastle.hex.encode(params_seq.items[0].value), 16);
							//var rc2ParameterVersion = jCastle.util.str2int(params_seq.items[0].value);
							var rc2ParameterVersion = params_seq.items[0].intVal;
							// rc2ParameterVersion should be matched with key size
							// we will not check it right now...
							iv = Buffer.from(params_seq.items[1].value, 'latin1');
						} else {
							iv = Buffer.from(params_seq.items[0].value, 'latin1');
						}
						enc_algo_info.params.iv = iv;
						//enc_algo_info.params.rc2ParameterVersion = rc2ParameterVersion;
						enc_algo_info.params.effectiveKeyBits = jCastle.algorithm.rc2.getEffectiveKeyBits(rc2ParameterVersion);
					} else if (algo_info.algo == 'rc5') {
/*
RFC 2898

B.2.4 RC5-CBC-Pad

   RC5-CBC-Pad is the RC5(tm) encryption algorithm [20] in CBC mode with
   a generalization of the RFC 1423 padding operation. This scheme is
   fully specified in [2]. RC5-CBC-Pad has a variable key length, from 0
   to 256 octets, and supports both a 64-bit block size and a 128-bit
   block size. For the former, it has an eight-octet initialization
   vector, and for the latter, a 16-octet initialization vector.
   RC5-CBC-Pad also has a variable number of "rounds" in the encryption
   operation, from 8 to 127.

   Note: The generalization of the padding operation is as follows. For
   RC5 with a 64-bit block size, the padding string is as defined in RFC
   1423. For RC5 with a 128-bit block size, the padding string consists
   of 16-(||M|| mod 16) octets each with value 16-(||M|| mod 16).

   The object identifier rc5-CBC-PAD [2] identifies RC5-CBC-Pad
   encryption scheme:

   rc5-CBC-PAD OBJECT IDENTIFIER ::= {encryptionAlgorithm 9}

   The parameters field associated with this OID in an
   AlgorithmIdentifier shall have type RC5-CBC-Parameters:

   RC5-CBC-Parameters ::= SEQUENCE {
       version INTEGER {v1-0(16)} (v1-0),
       rounds INTEGER (8..127),
       blockSizeInBits INTEGER (64 | 128),
       iv OCTET STRING OPTIONAL }

   The fields of type RC5-CBC-Parameters have the following meanings:

   -  version is the version of the algorithm, which shall be v1-0.

   -  rounds is the number of rounds in the encryption operation, which
      shall be between 8 and 127.

   -  blockSizeInBits is the block size in bits, which shall be 64 or
      128.

   -  iv is the initialization vector, an eight-octet string for 64-bit
      RC5 and a 16-octet string for 128-bit RC5. The default is a string
      of the appropriate length consisting of zero octets.
*/
						// var version = jCastle.util.str2int(params_seq.items[0].value);
						// var rounds =  jCastle.util.str2int(params_seq.items[1].value);
						// var blockSizeInBits = jCastle.util.str2int(params_seq.items[2].value);
						var version = params_seq.items[0].intVal;
						var rounds =  params_seq.items[1].intVal;
						var blockSizeInBits = params_seq.items[2].intVal;
						if (params_seq.items[3]) iv = Buffer.from(params_seq.items[3].value, 'latin1');

						enc_algo_info.params = {
							version: version,
							rounds: rounds,
							blockSizeInBits: blockSizeInBits
						};
						if (iv.length) enc_algo_info.params.iv = iv;
					}
					break;
				//default:
			}

		}

		return enc_algo_info;
	},

	schema: function(enc_algo_info)
	{
		var infoSchema = {
			type: jCastle.asn1.tagSequence,
			items:[{
				type: jCastle.asn1.tagOID,
				value: enc_algo_info.algoInfo.oid
			}]
		};

		var iv = 'iv' in enc_algo_info.params ? enc_algo_info.params.iv : null;
		if (iv && !Buffer.isBuffer(iv))
			iv = Buffer.from(iv, 'latin1');

		switch (enc_algo_info.algoInfo.mode) {
			case 'gcm':
			case 'ccm':
			case 'eax':
			case 'cwc':
/*
RFC 5084          Using AES-CCM and AES-GCM in the CMS

   With all three AES-CCM algorithm identifiers, the AlgorithmIdentifier
   parameters field MUST be present, and the parameters field must
   contain a CCMParameter:

      CCMParameters ::= SEQUENCE {
        aes-nonce         OCTET STRING (SIZE(7..13)),
        aes-ICVlen        AES-CCM-ICVlen DEFAULT 12 }

      AES-CCM-ICVlen ::= INTEGER (4 | 6 | 8 | 10 | 12 | 14 | 16)

   The aes-nonce parameter field contains 15-L octets, where L is the
   size of the length field.  With the CMS, the normal situation is for
   the content-authenticated-encryption key to be used for a single
   content; therefore, L=8 is RECOMMENDED.  See [CCM] for a discussion
   of the trade-off between the maximum content size and the size of the
   nonce.  Within the scope of any content-authenticated-encryption key,
   the nonce value MUST be unique.  That is, the set of nonce values
   used with any given key MUST NOT contain any duplicate values.

   The aes-ICVlen parameter field tells the size of the message
   authentication code.  It MUST match the size in octets of the value
   in the AuthEnvelopedData mac field.  A length of 12 octets is
   RECOMMENDED.
*/
/*
RFC 5084          Using AES-CCM and AES-GCM in the CMS

   With all three AES-GCM algorithm identifiers, the AlgorithmIdentifier
   parameters field MUST be present, and the parameters field must
   contain a GCMParameter:

      GCMParameters ::= SEQUENCE {
        aes-nonce        OCTET STRING, -- recommended size is 12 octets
        aes-ICVlen       AES-GCM-ICVlen DEFAULT 12 }

      AES-GCM-ICVlen ::= INTEGER (12 | 13 | 14 | 15 | 16)

   The aes-nonce is the AES-GCM initialization vector.  The algorithm
   specification permits the nonce to have any number of bits between 1
   and 2^64.  However, the use of OCTET STRING within GCMParameters
   requires the nonce to be a multiple of 8 bits.  Within the scope of
   any content-authenticated-encryption key, the nonce value MUST be
   unique, but need not have equal lengths.  A nonce value of 12 octets
   can be processed more efficiently, so that length is RECOMMENDED.

   The aes-ICVlen parameter field tells the size of the message
   authentication code.  It MUST match the size in octets of the value
   in the AuthEnvelopedData mac field.  A length of 12 octets is
   RECOMMENDED.
*/
				var nonce = enc_algo_info.params.nonce;
				if (!Buffer.isBuffer(nonce)) nonce = Buffer.from(nonce, 'latin1');

				var tag_size = enc_algo_info.params.tagSize;
				if (!tag_size) tag_size = 12; // default

				infoSchema.items.push({
					type: jCastle.asn1.tagSequence,
					items: [{
						type: jCastle.asn1.tagOctetString,
						value: nonce
					}, {
						type: jCastle.asn1.tagInteger,
						intVal: tag_size
					}]
				});
				break;
			case 'cbc':
				if (enc_algo_info.algoInfo.algo == 'rc2') {
					// rc2 needs key bits
					if ('effectiveKeyBits' in enc_algo_info.params) {
						var rc2_pversion = jCastle.algorithm.rc2.getVersion(enc_algo_info.params.effectiveKeyBits);
					} else {
						var key_size = 'keySize' in enc_algo_info.params ? enc_algo_info.params.keySize : enc_algo_info.algoInfo.keySize;
						var rc2_pversion = jCastle.algorithm.rc2.getVersion(key_size * 8);
					}

					infoSchema.items.push({
						type: jCastle.asn1.tagSequence,
						items: [{
							type: jCastle.asn1.tagInteger,
							intVal: rc2_pversion
						}, {
							type: jCastle.asn1.tagOctetString,
							value: iv
						}]
					});
				} else if (enc_algo_info.algoInfo.algo == 'rc5') {
					var params = enc_algo_info.params;
/*
   RC5-CBC-Parameters ::= SEQUENCE {
       version INTEGER {v1-0(16)} (v1-0),
       rounds INTEGER (8..127),
       blockSizeInBits INTEGER (64 | 128),
       iv OCTET STRING OPTIONAL }
*/
					// need to check if all parameters are there...
					infoSchema.items.push({
						type: jCastle.asn1.tagSequence,
						items: [{
							type: jCastle.asn1.tagInteger,
							intVal: params.version || 0
						}, {
							type: jCastle.asn1.tagInteger,
							intVal: params.rounds || 12
						}, {
							type: jCastle.asn1.tagInteger,
							intVal: params.blockSizeInBits || enc_algo_info.algoInfo.blockSize * 8
						}]
					});

					if (iv) {
						infoSchema.items[0].items.push({
							type: jCastle.asn1.tagOctetString,
							value: iv
						});
					}
				} else {
					infoSchema.items.push({
						type: jCastle.asn1.tagOctetString,
						value: iv
					});
				}
				break;
			default:
/*
https://tools.ietf.org/html/rfc4269

2.5.  SEED Object Identifiers

   For those who may be using SEED in algorithm negotiation within a
   protocol, or in any other context that may require the use of Object
   Identifiers (OIDs), the following three OIDs have been defined.

     algorithm OBJECT IDENTIFIER ::= { iso(1) member-body(2) korea(410)
       kisa(200004) algorithm(1) }

     id-seedCBC OBJECT IDENTIFIER ::= { algorithm seedCBC(4) }

     seedCBCParameter ::= OCTET STRING (SIZE(16))
     -- 128-bit Initialization Vector

*/
				if (iv) {
					infoSchema.items.push({
						type: jCastle.asn1.tagOctetString,
						value: iv
					});
				}
		}

		return infoSchema;	
	}
};

jCastle.pbe.asn1.pbeInfo = {
	parse: function(sequence)
	{
		//console.log(sequence);

		var algo_id = sequence.items[0].value;
		var kdf_type, pbe_info;

		if (algo_id == jCastle.oid.getOID("pkcs5PBES2")) { // "1.2.840.113549.1.5.13" | PKCS#5 v2.0 pbkdf2 hmac or pkcs5PBES2
/*
RFC 2898

A.4 PBES2

   The object identifier id-PBES2 identifies the PBES2 encryption scheme
   (Section 6.2).

   id-PBES2 OBJECT IDENTIFIER ::= {pkcs-5 13}

   The parameters field associated with this OID in an
   AlgorithmIdentifier shall have type PBES2-params:

   PBES2-params ::= SEQUENCE {
       keyDerivationFunc AlgorithmIdentifier {{PBES2-KDFs}},
       encryptionScheme AlgorithmIdentifier {{PBES2-Encs}} }

   The fields of type PBES2-params have the following meanings:

   -  keyDerivationFunc identifies the underlying key derivation
      function. It shall be an algorithm ID with an OID in the set
      PBES2-KDFs, which for this version of PKCS #5 shall consist of
      id-PBKDF2 (Appendix A.2).

   PBES2-KDFs ALGORITHM-IDENTIFIER ::=
       { {PBKDF2-params IDENTIFIED BY id-PBKDF2}, ... }

   -  encryptionScheme identifies the underlying encryption scheme. It
      shall be an algorithm ID with an OID in the set PBES2-Encs, whose
      definition is left to the application. Example underlying
      encryption schemes are given in Appendix B.2.

   PBES2-Encs ALGORITHM-IDENTIFIER ::= { ... }
*/
			kdf_type = 'pkcs5PBKDF2';

/*
RFC 2898

A.2   PBKDF2

   The object identifier id-PBKDF2 identifies the PBKDF2 key derivation
   function (Section 5.2).

   id-PBKDF2 OBJECT IDENTIFIER ::= {pkcs-5 12}

   The parameters field associated with this OID in an
   AlgorithmIdentifier shall have type PBKDF2-params:

   PBKDF2-params ::= SEQUENCE {
       salt CHOICE {
           specified OCTET STRING,
           otherSource AlgorithmIdentifier {{PBKDF2-SaltSources}}
       },
       iterationCount INTEGER (1..MAX),
       keyLength INTEGER (1..MAX) OPTIONAL,
       prf AlgorithmIdentifier {{PBKDF2-PRFs}} DEFAULT algid-hmacWithSHA1 }

   The fields of type PKDF2-params have the following meanings:

   -  salt specifies the salt value, or the source of the salt value.
      It shall either be an octet string or an algorithm ID with an OID
      in the set PBKDF2-SaltSources, which is reserved for future
      versions of PKCS #5.

      The salt-source approach is intended to indicate how the salt
      value is to be generated as a function of parameters in the
      algorithm ID, application data, or both. For instance, it may
      indicate that the salt value is produced from the encoding of a
      structure that specifies detailed information about the derived
      key as suggested in Section 4.1. Some of the information may be
      carried elsewhere, e.g., in the encryption algorithm ID. However,
      such facilities are deferred to a future version of PKCS #5.

      In this version, an application may achieve the benefits mentioned
      in Section 4.1 by choosing a particular interpretation of the salt
      value in the specified alternative.

   PBKDF2-SaltSources ALGORITHM-IDENTIFIER ::= { ... }

   -  iterationCount specifies the iteration count. The maximum
      iteration count allowed depends on the implementation. It is
      expected that implementation profiles may further constrain the
      bounds.

   -  keyLength, an optional field, is the length in octets of the
      derived key. The maximum key length allowed depends on the
      implementation; it is expected that implementation profiles may
      further constrain the bounds. The field is provided for
      convenience only; the key length is not cryptographically
      protected. If there is concern about interaction between
      operations with different key lengths for a given salt (see
      Section 4.1), the salt should distinguish among the different key
      lengths.

   -  prf identifies the underlying pseudorandom function. It shall be
      an algorithm ID with an OID in the set PBKDF2-PRFs, which for this
      version of PKCS #5 shall consist of id-hmacWithSHA1 (see Appendix
      B.1.1) and any other OIDs defined by the application.

      PBKDF2-PRFs ALGORITHM-IDENTIFIER ::=
          { {NULL IDENTIFIED BY id-hmacWithSHA1}, ... }

      The default pseudorandom function is HMAC-SHA-1:

      algid-hmacWithSHA1 AlgorithmIdentifier {{PBKDF2-PRFs}} ::=
          {algorithm id-hmacWithSHA1, parameters NULL : NULL}
*/
			var kdf_info = jCastle.pbe.asn1.pbkdf2.parse(sequence.items[1].items[0]);
			pbe_info = jCastle.pbe.asn1.encAlgoInfo.parse(sequence.items[1].items[1]);

			pbe_info.kdfInfo = kdf_info;
			pbe_info.type = kdf_type;
		} else {
	//			console.log('pem is encrypted with pkcs#5 pbkdf1 or pkcs#12 derivekey');

/*
RFC 2898

A.3 PBES1

   Different object identifiers identify the PBES1 encryption scheme
   (Section 6.1) according to the underlying hash function in the key
   derivation function and the underlying block cipher, as summarized in
   the following table:

        Hash Function  Block Cipher      OID
             MD2           DES         pkcs-5.1
             MD2           RC2         pkcs-5.4
             MD5           DES         pkcs-5.3
             MD5           RC2         pkcs-5.6
            SHA-1          DES         pkcs-5.10
            SHA-1          RC2         pkcs-5.11

   pbeWithMD2AndDES-CBC OBJECT IDENTIFIER ::= {pkcs-5 1}
   pbeWithMD2AndRC2-CBC OBJECT IDENTIFIER ::= {pkcs-5 4}
   pbeWithMD5AndDES-CBC OBJECT IDENTIFIER ::= {pkcs-5 3}
   pbeWithMD5AndRC2-CBC OBJECT IDENTIFIER ::= {pkcs-5 6}
   pbeWithSHA1AndDES-CBC OBJECT IDENTIFIER ::= {pkcs-5 10}
   pbeWithSHA1AndRC2-CBC OBJECT IDENTIFIER ::= {pkcs-5 11}

   For each OID, the parameters field associated with the OID in an
   AlgorithmIdentifier shall have type PBEParameter:

   PBEParameter ::= SEQUENCE {
       salt OCTET STRING (SIZE(8)),
       iterationCount INTEGER }

   The fields of type PBEParameter have the following meanings:

   -  salt specifies the salt value, an eight-octet string.

   -  iterationCount specifies the iteration count.
*/
			var algo = jCastle.oid.getName(algo_id);
			var algo_info = jCastle.pbe.getPbeAlgorithmInfoByOID(algo_id);
			if (!algo_info) {
				throw jCastle.exception("UNSUPPORTED_ALGO_OID", 'PBE017');
			}

			kdf_type = algo_info.type == 'pkcs5' ? 'pkcs5PBKDF1' : 'pkcs12DeriveKey';

			var salt = Buffer.from(sequence.items[1].items[0].value, 'latin1');
			var iterations = sequence.items[1].items[1].intVal;

			pbe_info = {
				algo: algo,
				type: kdf_type,
				algoInfo: algo_info,
				kdfInfo: {
					salt: salt,
					iterations: iterations
				},
				params: {}
			};
		}

		return pbe_info;
	},

	schema: function(pbe_info)
	{
		switch (pbe_info.type) {
			case 'pkcs5PBKDF2':
				var enc_schema = jCastle.pbe.asn1.encAlgoInfo.schema(pbe_info);
				var kdf_schema = jCastle.pbe.asn1.pbkdf2.schema(pbe_info.kdfInfo, jCastle.asn1.tagSequence, pbe_info.algo == 'rc2');
	/*
		SEQUENCE(2 elem)
			SEQUENCE(2 elem)
				OBJECT IDENTIFIER					1.2.840.113549.1.5.13
				SEQUENCE(2 elem)
					SEQUENCE(2 elem)
						OBJECT IDENTIFIER			1.2.840.113549.1.5.12
						SEQUENCE(2 elem)
							OCTET STRING(8 byte) 	A73C87E488ED0B24
							INTEGER					2048
					SEQUENCE(2 elem)
						OBJECT IDENTIFIER			1.2.840.113549.3.7
						OCTET STRING(8 byte) 		937BC960ACEB7796
			OCTET STRING(1224 byte) 				7D5409B4BA9BB12D07CF62D118FFDD60EC230B4040501918DAB8B8EFA7F64D3C0B49…
	*/
				var pbe_sequence = {
					type: jCastle.asn1.tagSequence,
					items: [{
						type: jCastle.asn1.tagOID,
						value: jCastle.oid.getOID("pkcs5PBES2") //"1.2.840.113549.1.5.13"
					}, {
						type: jCastle.asn1.tagSequence,
						items: [
							kdf_schema, enc_schema
						]
					}]
				};
				break;
			case 'pkcs5PBKDF1':
			case 'pkcs12DeriveKey':
				var pbe_sequence = {
					type: jCastle.asn1.tagSequence,
					items: [{
						type: jCastle.asn1.tagOID,
						value: pbe_info.algoInfo.oid
					}, {
						type: jCastle.asn1.tagSequence,
						items: [{
							type: jCastle.asn1.tagOctetString,
							value: pbe_info.kdfInfo.salt
						}, {
							type: jCastle.asn1.tagInteger,
							intVal: pbe_info.kdfInfo.iterations
						}]
					}]
				};
				break;
			default:
				throw jCastle.exception("INVALID_ENCRYPTION_METHOD", 'PBE018');
		}

		return pbe_sequence;
	}
};

/*
RFC 2898

7. Message Authentication Schemes

   A message authentication scheme consists of a MAC (message
   authentication code) generation operation and a MAC verification
   operation, where the MAC generation operation produces a message
   authentication code from a message under a key, and the MAC
   verification operation verifies the message authentication code under
   the same key. In a password-based message authentication scheme, the
   key is a password.

   One scheme is specified in this section: PBMAC1.

7.1 PBMAC1

   PBMAC1 combines a password-based key derivation function, which shall
   be PBKDF2  (Section 5.2) for this version of PKCS #5, with an
   underlying message authentication scheme (see Appendix B.3 for an
   example). The key length and any other parameters for the underlying
   message authentication scheme depend on the scheme.

7.1.1 MAC Generation

   The MAC generation operation for PBMAC1 consists of the following
   steps, which process a message M under a password P to generate a
   message authentication code T, applying a selected key derivation
   function KDF and a selected underlying message authentication scheme:

      1. Select a salt S and an iteration count c, as outlined in
         Section 4.

      2. Select a key length in octets, dkLen, for the derived key for
         the underlying message authentication function.

      3. Apply the selected key derivation function to the password P,
         the salt S, and the iteration count c to produce a derived key
         DK of length dkLen octets:

                 DK = KDF (P, S, c, dkLen) .

      4. Process the message M with the underlying message
         authentication scheme under the derived key DK to generate a
         message authentication code T.

      5. Output the message authentication code T.

   The salt S, the iteration count c, the key length dkLen, and
   identifiers for the key derivation function and underlying message
   authentication scheme may be conveyed to the party performing
   verification in an AlgorithmIdentifier value (see Appendix A.5).

7.1.2   MAC Verification

   The MAC verification operation for PBMAC1 consists of the following
   steps, which process a message M under a password P to verify a
   message authentication code T:

      1. Obtain the salt S and the iteration count c.

      2. Obtain the key length in octets, dkLen, for the derived key for
         the underlying message authentication scheme.

      3. Apply the selected key derivation function to the password P,
         the salt S, and the iteration count c to produce a derived key
         DK of length dkLen octets:

                 DK = KDF (P, S, c, dkLen) .

      4. Process the message M with the underlying message
         authentication scheme under the derived key DK to verify the
         message authentication code T.

      5. If the message authentication code verifies, output "correct";
         else output "incorrect."
*/
/*
RFC 2898

A.5 PBMAC1

   The object identifier id-PBMAC1 identifies the PBMAC1 message
   authentication scheme (Section 7.1).

   id-PBMAC1 OBJECT IDENTIFIER ::= {pkcs-5 14}

   The parameters field associated with this OID in an
   AlgorithmIdentifier shall have type PBMAC1-params:

   PBMAC1-params ::=  SEQUENCE {
       keyDerivationFunc AlgorithmIdentifier {{PBMAC1-KDFs}},
       messageAuthScheme AlgorithmIdentifier {{PBMAC1-MACs}} }

   The keyDerivationFunc field has the same meaning as the corresponding
   field of PBES2-params (Appendix A.4) except that the set of OIDs is
   PBMAC1-KDFs.

   PBMAC1-KDFs ALGORITHM-IDENTIFIER ::=
       { {PBKDF2-params IDENTIFIED BY id-PBKDF2}, ... }

   The messageAuthScheme field identifies the underlying message
   authentication scheme. It shall be an algorithm ID with an OID in the
   set PBMAC1-MACs, whose definition is left to the application. Example
   underlying encryption schemes are given in Appendix B.3.

   PBMAC1-MACs ALGORITHM-IDENTIFIER ::= { ... }
*/

/*
RFC 2898

B.3 Message Authentication Schemes

   An example message authentication scheme for PBMAC1 (Section 7.1) is
   HMAC-SHA-1.

B.3.1 HMAC-SHA-1

   HMAC-SHA-1 is the HMAC message authentication scheme [7] based on the
   SHA-1 hash function [18]. HMAC-SHA-1 has a variable key length and a
   20-octet (160-bit) message authentication code.

   The object identifier id-hmacWithSHA1 (see Appendix B.1.1) identifies
   the HMAC-SHA-1 message authentication scheme. (The object identifier
   is the same for both the pseudorandom function and the message
   authentication scheme; the distinction is to be understood by
   context.) This object identifier is intended to be employed in the
   object set PBMAC1-Macs (Appendix A.5).
*/
// "1.2.840.113549.1.5.14": { name: "pkcs5PBMAC1", comment: "PKCS #5 v2.0", obsolete: false },


jCastle.pbe.pbmac1 = function(message, password, salt, iterations, keylen, hash_algo, mac_algo, mac_params)
{
	var dk = jCastle.kdf.pbkdf2(password, salt, iterations, keylen, hash_algo);

	var mac_type = 'mcrypt';

	try {
		mac_algo = jCastle.mcrypt.getValidAlgoName(mac_algo);
	} catch (e) {
		mac_algo = jCastle.digest.getValidAlgoName(mac_algo);
		mac_type = 'digest';
	}

	mac_params = mac_params || {};
	mac_params.algoName = mac_algo;
	mac_params.key = dk;

	if (mac_type == 'mcrypt') {
		var md = jCastle.mac.create('cmac');
	} else {
		var md = jCastle.hmac.create();
	}

	var mac = md.start(mac_params)
		.update(message)
		.finalize();

	return mac;
};

jCastle.pbe.getMacInfo = function(macAlgo)
{
	var m = /(hmac(With)?([a-z0-9\-]+))|(([a-z0-9\-]+)(\-|With)?MAC)/i.exec(macAlgo);
//console.log(m);

	if (m[5]) {
		var macInfo = {
			type: 'cmac',
			algo: jCastle.mcrypt.getValidAlgoName(m[5])
		};

		var algoInfo = jCastle.mcrypt.getAlgorithmInfo(macInfo.algo);
		macInfo.algoInfo = algoInfo;
		return macInfo;
	} else if (m[3]) {
		var macInfo = {
			type: 'hmac',
			algo: jCastle.digest.getValidAlgoName(m[3])
		};

		var mdInfo = jCastle.digest.getAlgorithmInfo(macInfo.algo);
		macInfo.algoInfo = mdInfo;
		return macInfo;
	} else {
		if (macAlgo == 'pkcs5PBMAC1') {
			// to do
			// the parameters are not known and I haven't get any example...
		}
	}
	throw jCastle.exception('UNSUPPORTED_MAC', 'PBE019');
};

jCastle.pbe.asn1.macAlgorithm = {
	parse: function(obj)
	{
		var macAlgorithm = {};
		macAlgorithm.algorithm = jCastle.oid.getName(obj.items[0].value);

		var macInfo = jCastle.pbe.getMacInfo(macAlgorithm.algorithm);
		macAlgorithm.macInfo = macInfo;

		if (obj.items[1] && obj.items[1].type != jCastle.asn1.tagNull) {
			macAlgorithm.parameters = jCastle.pbe.asn1.macAlgoParameters.parse(obj.items[1], macInfo);
		}

		return macAlgorithm;
	},

	schema: function(macAlgorithm)
	{
		var schema = {
			type: jCastle.asn1.tagSequence,
			items: [{
				type: jCastle.asn1.tagOID,
				value: jCastle.oid.getOID(macAlgorithm.algorithm)
			}]
		};

		if ('parameters' in macAlgorithm) {
			var paramSchema = jCastle.pbe.asn1.macAlgoParameters.schema(macAlgorithm.parameters, macAlgorithm.macInfo);
			if (paramSchema) schema.items.push(paramSchema);
		} else {
			schema.items.push({
				type: jCastle.asn1.tagNull,
				value: null
			});
		}

		return schema;
	}
};
/*
https://tools.ietf.org/html/rfc4269

2.5.  SEED Object Identifiers

   For those who may be using SEED in algorithm negotiation within a
   protocol, or in any other context that may require the use of Object
   Identifiers (OIDs), the following three OIDs have been defined.

     algorithm OBJECT IDENTIFIER ::= { iso(1) member-body(2) korea(410)
       kisa(200004) algorithm(1) }

     id-seedCBC OBJECT IDENTIFIER ::= { algorithm seedCBC(4) }

     seedCBCParameter ::= OCTET STRING (SIZE(16))
     -- 128-bit Initialization Vector

   The id-seedCBC OID is used when the Cipher Block Chaining (CBC) mode
   of operation based on the SEED block cipher is provided.

     id-seedMAC OBJECT IDENTIFIER ::= { algorithm seedMAC(7) }

     seedMACParameter ::= INTEGER  -- MAC length, in bits

   The id-seedMAC OID is used when the message authentication code (MAC)
   algorithm based on the SEED block cipher is provided.

     pbeWithSHA1AndSEED-CBC OBJECT IDENTIFIER ::=
       { algorithm seedCBCwithSHA1(15) }

     PBEParameters ::= SEQUENCE { salt          OCTET STRING, iteration
       INTEGER }  -- Total number of hash iterations

   This OID is used when a password-based encryption in CBC mode based
   on SHA-1 and the SEED block cipher is provided.  The details of the
   Password-Based Encryption (PBE) computation are well described in
   Section 6.1 of [RFC2898].

*/
/*
https://www.alvestrand.no/objectid/1.3.14.3.2.10.html

DES MAC algorithm

desMAC ALGORITHM
   PARAMETER MACParameter
   ::= {algorithm 10}

MACParameter ::= INTEGER    -- Length of MAC (16, 24,  32, 40, 40 or 64 bits)
*/
jCastle.pbe.asn1.macAlgoParameters = {
	parse: function(obj, macInfo)
	{
		var parameters = [];

		if (obj.type == jCastle.asn1.tagSequence) {
			for (var i = 0; i < obj.items.length; i++) {
				parameters.push(obj.items[i].value);
			}
		} else {
			parameters.push(obj.value);
		}
		
		return parameters;
	},

	schema: function(parameters, macInfo)
	{
		var schema = null;
		if (parameters && parameters.length) {
			if (parameters.length == 1) {
				var type = jCastle.util.isInteger(parameters[0]) ? jCastle.asn1.tagInteger : jCastle.asn1.tagOctetString;
				// schema = {
				// 	type: type,
				// 	value: parameters[0]
				// };
				schema = {type: type};
				if (type === jCastle.asn1.tagInteger) schema.intVal = parameters[0];
				else schema.value = parameters[0];
			} else {
				schema = {
					type: jCastle.asn1.tagSequence,
					items: []
				};

				for (var i = 0; i < parameters.length; i++) {
					var type = jCastle.util.isInteger(parameters[i]) ? jCastle.asn1.tagInteger : jCastle.asn1.tagOctetString;
					// schema.items.push({
					// 	type: type,
					// 	value: parameters[i]
					// });
					var item = {type: type};
					if (type === jCastle.asn1.tagInteger) item.intVal = parameters[0];
					else item.value = parameters[0];
					schema.push(item);
				}
			}
		}

		return schema;
	}
};



jCastle.pbe.ASN1 = jCastle.pbe.asn1;

jCastle.PBE = jCastle.pbe;

module.exports = jCastle.pbe;
