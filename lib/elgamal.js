/**
 * A Javascript implemenation of PKI - ElGamal
 * 
 * @author Jacob Lee
 *
 * Copyright (C) 2015-2022 Jacob Lee.
 */

var jCastle = require('./jCastle');
var BigInteger = require('./biginteger');

require('./util');

jCastle.pki.elGamal = class
{
	/**
	 * An implementation of ElGamal.
	 * 
	 * @constructor
	 */
	constructor()
	{
		this.params = {};

		this.hasPrivKey = false;
		this.hasPubKey = false;
		this.pkiName = "ELGAMAL";
		this.OID = "1.3.6.1.4.1.3029.1.2.1";

		this.privateKey = null;
		this.publicKey = null;

		this.blockLength = 0;
		this.bitLength = 0;

		this._pkiClass = true;
	}

	/**
	 * resets internal variables.
	 * 
	 * @public
	 * @returns this class instance.
	 */
	reset()
	{
		this.params = {};

		this.hasPrivKey = false;
		this.hasPubKey = false;

		this.privateKey = null;
		this.publicKey = null;

		this.blockLength = 0;
		this.bitLength = 0;

		return this;
	}

	/**
	 * gets block length of parameter p in bytes.
	 * 
	 * @public
	 * @returns block length in bytes.
	 */
	getBlockLength()
	{
		return this.blockLength;
	}

	/**
	 * gets block length of parameter p in bits.
	 * 
	 * @public
	 * @returns block length in bits.
	 */
	getBitLength()
	{
		return this.bitLength;
	}

	/**
	 * sets publicKey.
	 * 
	 * @public
	 * @param {mixed} y publicKey object or buffer.
	 * @param {object} params parameters object.
	 * @returns this class instance.
	 */
	setPublicKey(y, params)
	{
		if (!params && typeof y == 'object' && 'kty' in y && y.kty == 'ElGamal') {
			params = {
				p: Buffer.from(y.p, 'base64url').toString('hex'),
				g: Buffer.from(y.g, 'base64url').toString('hex')
			};
			
			var yy = BigInteger.fromByteArrayUnsigned(Buffer.from(y.y, 'base64url'));

			return this.setPublicKey(yy, params);
		}

		if (params) {
			this.setParameters(params);
		}

		if (!this.params || !this.params.p) {
			throw jCastle.exception("PARAMETERS_NOT_SET", 'ELG001');
		}

		if (!y && this.privateKey) {
			// pkcs8 pem format doesn't give you 'y'.
			y = this.params.g.modPow(this.privateKey, this.params.p);
		}

		this.publicKey = jCastle.util.toBigInteger(y);

		this.blockLength = (this.params.p.bitLength() + 7) >>> 3;
		this.bitLength = this.params.p.bitLength();

		this.hasPubKey = true;

		return this;
	}

	/**
	 * gets publicKey.
	 * 
	 * @public
	 * @param {string} format format string.
	 * @returns publicKey in format.
	 */
	getPublicKey(format = 'object')
	{
		if (this.hasPubKey) {
			if (format.toLowerCase() == 'jwt') {
				var params = this.getParameters('hex');

				return {
					kty: 'ElGamal',
					p: Buffer.from(params.p, 'hex').toString('base64url'),
					g: Buffer.from(params.g, 'hex').toString('base64url'),
					y: Buffer.from(this.publicKey.toString(16), 'hex').toString('base64url')
				};
			}

			return jCastle.util.formatBigInteger(this.publicKey, format);
		}

		return null;
	}

	/**
	 * gets privateKey.
	 * 
	 * @public
	 * @param {string} format format string
	 * @returns privateKey in format.
	 */
	getPrivateKey(format = 'object')
	{
		if (this.hasPrivKey) {
			if (format.toLowerCase() == 'jwt') {
				var params = this.getParameters('hex');

				return {
					kty: 'ElGamal',
					p: Buffer.from(params.p, 'hex').toString('base64url'),
					g: Buffer.from(params.g, 'hex').toString('base64url'),
					x: Buffer.from(this.privateKey.toString(16), 'hex').toString('base64url'),
					y: Buffer.from(this.publicKey.toString(16), 'hex').toString('base64url')
				};
			}

			return jCastle.util.formatBigInteger(this.privateKey, format);
		}

		return null;
	}

	/**
	 * sets privateKey and publicKey. publicKey will be computed if it does not exist.
	 * 
	 * @public
	 * @param {mixed} x privateKey object or buffer.
	 * @param {mixed} y publicKey object or buffer.
	 * @param {object} params parameters object.
	 * @returns this class instance.
	 */
	setPrivateKey(x, y, params)
	{
		if (typeof y == 'undefined' && typeof x == 'object' && 'kty' in x && x.kty == 'ElGamal') {
			params = {
				p: Buffer.from(x.p, 'base64url').toString('hex'),
				g: Buffer.from(x.g, 'base64url').toString('hex')
			};
			
			var xx = BigInteger.fromByteArrayUnsigned(Buffer.from(x.x, 'base64url'));
			var yy = BigInteger.fromByteArrayUnsigned(Buffer.from(x.y, 'base64url'));

			return this.setPublicKey(xx, yy, params);
		}

		if (params) {
			this.setParameters(params);
		}

		if (!this.params || !this.params.p) {
			throw jCastle.exception("PARAMETERS_NOT_SET", 'ELG002');
		}

		this.privateKey = jCastle.util.toBigInteger(x);

		this.setPublicKey(y);

		this.hasPrivKey = true;

		return this;
	}

	/**
	 * gets publicKey information object.
	 * 
	 * @public
	 * @param {string} format publicKey format string
	 * @param {string} param_format parameters format string
	 * @returns publicKey information object in format.
	 */
	getPublicKeyInfo(format = 'object', param_format = 'hex')
	{
		var pubkey_info = {};
		pubkey_info.type = 'public';
		pubkey_info.algo = this.pkiName;
		pubkey_info.parameters = this.getParameters(param_format);
		pubkey_info.publicKey = this.getPublicKey(format);

		return pubkey_info;	
	}

	/**
	 * gets privateKey information object.
	 * 
	 * @public
	 * @param {string} format privateKey format string
	 * @param {string} param_format parameters format string
	 * @returns privateKey information object in format.
	 */
	getPrivateKeyInfo(format = 'object', param_format = 'hex')
	{
		var privkey_info = {};
		privkey_info.type = 'private';
		privkey_info.algo = this.pkiName;
		privkey_info.parameters = this.getParameters(param_format);
		privkey_info.privateKey = this.getPrivateKey(format);

		return privkey_info;	
	}

	/**
	 * checks if the pubkey is the same with the publicKey of the class instance.
	 * 
	 * @public
	 * @param {object} pubkey publicKey object or buffer.
	 * @returns true if the pubkey is the same with the publicKey of this class instance.
	 */
	publicKeyEquals(pubkey)
	{
		if (!this.hasPubKey) return false;

		var p = jCastle.util.toBigInteger(pubkey);
		if (this.y.equals(p)) return true;
		return false;
	}

	/**
	 * checks if publicKey is set.
	 * 
	 * @public
	 * @returns true if publicKey is set.
	 */
	hasPublicKey()
	{
		return this.hasPubKey;
	}

	/**
	 * checks if privateKey is set.
	 * 
	 * @public
	 * @returns true if privateKey is set.
	 */
	hasPrivateKey()
	{
		return this.hasPrivKey;
	}

	/**
	 * sets parameter values.
	 * 
	 * @public
	 * @param {mixed} p parameter p object or buffer
	 * @param {mixed} g parameter g object or buffer
	 * @returns this class instance.
	 */
	setParameters(p, g)
	{
		if (typeof g == 'undefined' && typeof p == 'object') {
			var params = p;
			p = params.p;
			g = params.g;
		}

		this.params = {
			p: jCastle.util.toBigInteger(p),
			g: jCastle.util.toBigInteger(g)
		};

		return this;
	}

	/**
	 * gets DSA parameters.
	 * 
	 * @public
	 * @param {string} format parameters format string
	 * @returns parameters in format
	 */
	getParameters(format = 'hex')
	{
		return jCastle.pki.elGamal.formatParameters(this.params, format);
	}

	/**
	 * generates ElGamal parameters
	 * 
	 * @public
	 * @param {object} options options object for generation of ElGamal parameters
	 * @returns this class instance.
	 */
	generateParameters(options)
	{
		options.format = 'object';
		var params = jCastle.pki.elGamal.generateParameters(options);
		this.params = params;

		return this;
	}


	/*
	Algorithm: ElGamal Encryption

	INPUT: Domain parameters (p, g); recipient's public key B; encoded message m in range 0 < m < p−1. 
	OUTPUT: Ciphertext (c1,c2). 

	Choose a random k in the range 1 < k < p−1.
	Compute c1 = g**k mod p
	Compute c2 = mB**k mod p
	Return ciphertext (c1,c2).
	*/
	/**
	 * encrypt a message by publicKey.
	 * 
	 * @public
	 * @param {buffer} str message to be encrypted.
	 * @param {object} options options object.
	 *                 {object} publicKey the other's publicKey object. if not given then this class's publicKey is used.
	 *                 {buffer} kRandom random K value for encrypting a message. this is for test mode.
	 * @returns the encrypted message in buffer.
	 */
	publicEncrypt(str, options = {})
	{
		var ba, k;
		var rng = new jCastle.prng();
		// use other's publicKey or this.publicKey?
		// this will be usefull when you have to encrypt message with other's publicKey.
		var pubkey = 'publicKey' in options ? options.publicKey : this.publicKey; 

		if (!pubkey) throw jCastle.exception("PUBKEY_NOT_SET", 'ELG003');

		pubkey = jCastle.util.toBigInteger(pubkey);

		ba = Buffer.from(str);

		var m_bi = BigInteger.fromByteArrayUnsigned(ba);
		var one = BigInteger.valueOf(1);
		
		if (m_bi.compareTo(this.params.p.subtract(one)) >= 0) {
			throw jCastle.exception("MSG_TOO_LONG", 'ELG004'); // "message too big for domain parameter p";
		}

		if ('kRandom' in options) {
			k = options.kRandom;

			if (!(k instanceof BigInteger)) {
				if (!Buffer.isBuffer(k) && /^[0-9A-F]+$/i.test(k)) {
					k = BigInteger.fromByteArrayUnsigned(Buffer.from(k, 'hex'));
				} else {
					k = BigInteger.fromByteArrayUnsigned(Buffer.from(k));
				}
			}
		} else {
			do {
				k = BigInteger.random(this.params.p.bitLength(), rng);
			} while (k.compareTo(one) <= 0 || k.compareTo(this.params.p.subtract(one)) <= 0);
		}

		var c1 = this.params.g.modPow(k, this.params.p);
		var c2 = m_bi.multiply(pubkey.modPow(k, this.params.p)).mod(this.params.p);

		var res = new jCastle.asn1().getDER({
			type: jCastle.asn1.tagSequence,
			items: [{
				type: jCastle.asn1.tagInteger,
				intVal: c1
			}, {
				type: jCastle.asn1.tagInteger,
				intVal: c2
			}]
		});

		res = Buffer.from(res, 'latin1');

        if ('encoding' in options) res = res.toString(options.encoding);

		return res;
	}

	/*
	Algorithm: ElGamal Decryption

	INPUT: Domain parameters (p,q,g), ciphertext (c1,c2). 
	OUTPUT: Message representative, m. 

	Compute m = c1**(p−b−1)c2 mod p
	Return m.
	*/
	/**
	 * decrypt the ciphertext by privateKey.
	 * 
	 * @public
	 * @param {buffer} str message to be decrypted
	 * @param {object} options options object.
	 * @returns the decrypted message in buffer.
	 */
	privateDecrypt(str, options = {})
	{
		if (!this.hasPrivateKey()) throw jCastle.exception("PRIVKEY_NOT_SET", 'ELG011');

		var ba = Buffer.from(str);
		var sequence = new jCastle.asn1().parse(ba);

		if (!jCastle.asn1.isSequence(sequence)) {
			return null;
		}

		var c1 = sequence.items[0].intVal;
		var c2 = sequence.items[1].intVal;

		var m_bi = c1.modPow(this.params.p.subtract(this.privateKey).subtract(BigInteger.ONE), this.params.p).multiply(c2).mod(this.params.p);

		var ba = Buffer.from(m_bi.toByteArray());

		if ('encoding' in options) ba = ba.toString(options.encoding);

		return ba;
	}

	/**
	 * generates privateKey and publicKey.
	 * 
	 * @public
	 * @param {object} parameters parameters object. DSA parameters must be set if it is not given.
	 * @returns this class instance.
	 */
	generateKeypair(parameters)
	{
		if (typeof parameters == 'undefined' && (!this.params || !this.params.p)) {
			throw jCastle.exception("PARAMS_NOT_SET", 'ELG005');
		}

		if (typeof parameters != 'undefined') {
			this.setParameters(parameters);
		}

		// Choose an integer, such that 0 < x < q.
		var rng = new jCastle.prng();
		var certainty = 10;
		var x;
		do {
			x = BigInteger.random(this.params.p.bitLength(), rng);
		} while (x.compareTo(BigInteger.ZERO) <= 0 || x.compareTo(this.params.p.subtract(BigInteger.ONE)) >= 0);

		this.privateKey = x; // private key
		this.hasPrivKey = true;

		// Compute y as g^x mod p.
		this.publicKey = this.params.g.modPow(x, this.params.p); // public key
		this.hasPubKey = true;

		this.blockLength = (this.params.p.bitLength() + 7) >>> 3;
		this.bitLength = this.params.p.bitLength();

		return this;
	}

	/*
	To sign a message m the signer performs the following steps.

	Choose a random k such that 1 < k < p - 1 and gcd(k, p - 1) = 1.
	Compute r = g^k mod p
	Compute s = (H(m) - xr)k^(-1) mod (p - 1)
	if s = 0 start over again.
	*/
	/**
	 * gets a signature of the message.
	 * 
	 * @public
	 * @param {buffer} str buffer or string to be signed
	 * @param {object} options options object.
	 *                 {string} hashAlgo hash algorithm name. (default: 'sha-1')
	 *                 {string} returnType return type string. 'concat' | 'object' | 'asn1'. (default: 'asn1')
	 *                 {buffer} kRandom random K value for generating signature. this is for test mode.
	 * @returns the signature in return type.
	 */
	sign(str, options = {})
	{
		var hash_algo = 'hashAlgo' in options ? options.hashAlgo : 'sha-1';
		var ret_type = 'returnType' in options ? options.returnType.toLowerCase() : 'asn1';
		var random_k = 'kRandom' in options ? options.kRandom : null;
		var ba;

		if (!this.hasPrivKey) throw jCastle.exception("PRIVKEY_NOT_SET", 'ELG006');

		if (Buffer.isBuffer(str)) ba = str;
		else ba = Buffer.from(str, 'latin1');

		hash_algo = jCastle.digest.getValidAlgoName(hash_algo);
		if (!hash_algo || jCastle._algorithmInfo[hash_algo].oid == null) {
			throw jCastle.exception("UNSUPPORTED_HASHER", 'ELG007');
		}

		if (random_k){
			if (!Buffer.isBuffer(random_k)) {
				if (/^[0-9A-F]+$/i.test(random_k)) random_k = Buffer.from(random_k, 'hex');
				else random_k = Buffer.from(random_k, 'latin1');
			}
		}

		var hash = new jCastle.digest(hash_algo).digest(ba);
		var hash_bi = BigInteger.fromByteArrayUnsigned(hash);
		var one = BigInteger.valueOf(1);
		var zero = BigInteger.valueOf(0);
		var p1 = this.params.p.subtract(one);
		var k, t, r, s, res;

		// Generate a random number k, such that 0 < k < q.
		var rng = new jCastle.prng();

		var counter = 0;

		for(;;) {
			if (random_k) {
				if (counter) {
					throw  jCastle.exception("INVALID_SALT", 'DSA020');
				}
				k = BigInteger.fromByteArrayUnsigned(random_k);
			} else {
				// Choose a random k such that 1 < k < p - 1 and gcd(k, p - 1) = 1.
				do {
					k = BigInteger.random(this.params.p.bitLength(), rng);
				} while (k.compareTo(zero) <= 0 || k.compareTo(p1) >= 0);
			}

			// Compute r as (g^k mod p). If r = 0, select a different k.
			r = this.params.g.modPow(k, this.params.p);

			if (r.compareTo(zero) <= 0) continue;
			
			// Compute i, such that k*i mod p-1 = 1. i is called the modular multiplicative inverse of k modulo q-1.
			// Compute s = (H(m) - xr)k^(-1) mod (p - 1). If s = 0, select a different k.
			t = hash_bi.subtract(this.privateKey.multiply(r)).mod(p1);
			while (t.compareTo(zero) <= 0) t = t.add(p1);
			s = k.modInverse(p1).multiply(t).mod(p1);

			if (s.compareTo(zero) > 0) break;

			counter++;
		}

		// Package the digital signature as {r,s}.
		switch (ret_type) {
			case 'concat':
				// r and s should be same length with blockLength
				var r_ba = Buffer.from(r.toByteArray());
				var s_ba = Buffer.from(s.toByteArray());

				if (r_ba.length < this.blockLength) 
					r_ba = Buffer.concat([Buffer.alloc(this.blockLength - r_ba.length, 0x00), r_ba]);
                if (s_ba.length < this.blockLength) 
					s_ba = Buffer.concat([Buffer.alloc(this.blockLength - s_ba.length, 0x00), s_ba]);

				res = Buffer.concat([r_ba, s_ba]);
				break;
			case 'object':
				res = {
					r: Buffer.from(r.toByteArray()),
					s: Buffer.from(s.toByteArray())
				};
                break;
			case 'asn1':
			default:
				// Package the digital signature as {r,s}.
				res = new jCastle.asn1().getDER({
					type: jCastle.asn1.tagSequence,
					items:[{
						type: jCastle.asn1.tagInteger,
						intVal: r
					}, {
						type: jCastle.asn1.tagInteger,
						intVal: s
					}]
				});
                res = Buffer.from(res, 'latin1');
				break;
		}

        if ('encoding' in options) {
            if (ret_type === 'object') {
                res.r = res.r.toString(options.encoding);
                res.s = res.s.toString(options.encoding);
            } else {
            	res = res.toString(options.encoding);
			}
        }
		return res;
	}

	/*
	A signature (r,s) of a message m is verified as follows.

	0 < r < p and 0 < s < p-1
	g^H(m) == (y^r)(r^s) mod p 
	*/
	/**
	 * checks if the signature is right.
	 * 
	 * @public
	 * @param {buffer} str buffer or string to be signed
	 * @param {mixed} signature signature value.
	 * @param {object} options options object.
	 *                 {string} hashAlgo hash algorithm name. (default: 'sha-1')
	 * @returns true if the signature is right.
	 */
	verify(str, signature, options = {})
	{
		if (!this.hasPubKey) throw jCastle.exception("PUBKEY_NOT_SET", 'ELG008');

		var hash_algo = 'hashAlgo' in options ? options.hashAlgo : 'sha-1';
		var ba, r, s;

		if (Buffer.isBuffer(str)) ba = str;
		else ba = Buffer.from(str, 'latin1');

		hash_algo = jCastle.digest.getValidAlgoName(hash_algo);
		if (!hash_algo || jCastle._algorithmInfo[hash_algo].oid == null) {
			throw jCastle.exception("UNSUPPORTED_HASHER", 'ELG009');
		}

		if (typeof signature === 'object' && 'r' in signature && 's' in signature) {
			// object {r, s}
			if (!Buffer.isBuffer(signature.r)) {
				if (/^[0-9A-F]+$/i.test(signature.r)) {
					r = Buffer.from(signature.r, 'hex');
					s = Buffer.from(signature.s, 'hex');
				} else {
					r = Buffer.from(signature.r, 'latin1');
					s = Buffer.from(signature.s, 'latin1');
				}
			} else {
				r = Buffer.from(signature.r);
				s = Buffer.from(signature.s);
			}
			r = BigInteger.fromByteArrayUnsigned(r);
			s = BigInteger.fromByteArrayUnsigned(s);
		} else {
			if (!Buffer.isBuffer(signature)) {
				if (/^[0-9A-F]+$/i.test(signature)) signature = Buffer.from(signature, 'hex');
				else signature = Buffer.from(signature, 'latin1');
			}

			if (jCastle.asn1.isAsn1Format(signature)) {
				try {
					// asn1
					var sequence = new jCastle.asn1().parse(signature);

					if (!jCastle.asn1.isSequence(sequence)) return false;

					r = sequence.items[0].intVal;
					s = sequence.items[1].intVal;
				} catch (ex) {
					// concat
					r = BigInteger.fromByteArrayUnsigned(signature.slice(0, signature.length / 2));
					s = BigInteger.fromByteArrayUnsigned(signature.slice(signature.length / 2));
				}
			} else {
				// concat
				r = BigInteger.fromByteArrayUnsigned(signature.slice(0, signature.length / 2));
				s = BigInteger.fromByteArrayUnsigned(signature.slice(signature.length / 2));
			}
		}

		var hash = new jCastle.digest(hash_algo).digest(ba);
		var hash_bi = BigInteger.fromByteArrayUnsigned(hash);

		var one = BigInteger.valueOf(1);
		var zero = BigInteger.valueOf(0);
		var p1 = this.params.p.subtract(one);

		// 0 < r < p and 0 < s < p-1
		if (r.compareTo(zero) <= 0 || r.compareTo(this.params.p) >= 0 ||
			s.compareTo(zero) <= 0 || s.compareTo(p1) >= 0
		) {
			return false;
		}

		// g**H(m) == (y**r)(r**s) mod p 

		// Compute w, g**H(m)
		var w = this.params.g.modPow(hash_bi, this.params.p);
		// Compute (y**r)(r**s) mod p.
		var v = this.publicKey.modPow(r, this.params.p).multiply(r.modPow(s, this.params.p)).mod(this.params.p);
				
		// If v == w, the digital signature is valid.
		return v.compareTo(w) == 0;
	}
}

jCastle.pki.ElGamal = jCastle.pki.elgamal = jCastle.pki.elGamal;

/**
 * creates a new ElGamal pki object.
 * 
 * @public
 * @returns the new ElGamal pki object.
 */
jCastle.pki.elGamal.create = function()
{
	return new jCastle.pki.elGamal();
};

jCastle.pki.elGamal._PPGF = function(md, seed, hash_len, bits)
{
	var len = Math.ceil(((bits + 7) & 0xFFFFFFF8) / 8);
	var tmp;
	var result = Buffer.alloc(len);

	for (var count = 0;; count++) {
		md.start();
		md.update(seed);
		md.update(Buffer.alloc(1, count & 0xff));
		tmp = md.finalize();

		if (len >= hash_len) {
			len -= hash_len;
			tmp.copy(result, len, 0, tmp.length);
			if (len === 0) break;
		} else {
			tmp.copy(result, 0, hash_len - len, hash_len);
			break;
		}
	}

	len = bits & 0x07;
	if (len !== 0) result[0] &= (1 << len) - 1;

	return result;
};

/**
 * generates ElGamal parameters.
 * 
 * @public
 * @param {object} options options object.
 *                 {number} bits bits length for parameter p. (default: 1024)
 *                 {string} hashAlgo hash algorithm name. (default: 'sha-1')
 *                 {string} format format string.
 *                 {buffer} seed seed buffer
 * @returns generated parameters object.
 */
jCastle.pki.elGamal.generateParameters = function(options = {})
{
	var bits = 'bits' in options ? options.bits : 1024;
	var format  = 'format' in options ? options.format : 'hex';
	var hash_algo = 'hashAlgo' in options ? options.hashAlgo : 'sha-1';
	var seed = 'seed' in options ? options.seed : null;

	if (bits % 64 != 0) {
		throw "illegal bit length.";
	}
	if (bits < 512) bits = 512;

	if (seed && !Buffer.isBuffer(seed)) seed = Buffer.from(seed);

	var rng = new jCastle.prng();
	var certainty = 10;
	var one = BigInteger.valueOf(1);
	var hash_len = jCastle.digest.getDigestLength(hash_algo);
	var md = new jCastle.digest(hash_algo);
	var seed_provided = seed ? true : false;
	var counter = 0;
	var limit = 1 << 24;

	// Choose a prime number p, which is called the prime divisor.
	var p, g, U;

	do {
		if (counter && seed_provided) {
			// seed 값이 주어졌으나 생성된 BigInteger J가 소수가 되지 못함.
			// 루프문을 빠져나갈 수 없으므로 throw error한다.
			throw jCastle.exception("INVALID_SEED", 'ELG010');
		}
		if (!seed_provided) seed = rng.nextBytes(hash_len);

		U = jCastle.pki.elGamal._PPGF(md, seed, hash_len, bits);

		U[0] |= 0x80;
        U[U.length - 1] |= 0x01;

		p = BigInteger.fromByteArrayUnsigned(U);

		counter++;

	} while(!b.isProbablePrime(certainty));

	// Choose an integer g, such that 1 < g < p. 
	do {
		g = BigInteger.random(bits, rng);
	}
	while (g.compareTo(p.subtract(one)) >= 0 || g.compareTo(one) <= 0);

	var params = {
		p: p, 
		g: g
	};

	return jCastle.pki.elGamal.formatParameters(params, format);
};

jCastle.pki.elGamal.formatParameters = function(params, format = 'hex')
{
	if (!params || !params.p) return null;

	switch (format) {
        case 'hex':
            var pp = {
                p: params.p.toString(16),
                g: params.g.toString(16)
            };
            break;
        case 'object':
            var pp = {
                p: params.p.clone(),
                g: params.g.clone()
            };
            break;
        default:
            var pp = {
                p: Buffer.from(params.p.toByteArray()),
                g: Buffer.from(params.g.toByteArray())
            };
            if (format !== 'buffer') {
                pp.p = pp.p.toString(format);
                pp.g = pp.g.toString(format);
            }
            break;
    }

	if ('validity' in params) {
		pp.validity = {};
		pp.validity.counter = params.validity.counter;
		pp.validity.seed = params.validity.seed;
	}

    return pp;
};

jCastle._pkiInfo['elgamal'] = {
	pki_name: 'ELGAMAL',
	object_name: 'elGamal',
	oid: "1.3.6.1.4.1.3029.1.2.1"
};

module.exports = jCastle.pki.elGamal;