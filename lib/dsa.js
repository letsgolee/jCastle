/**
 * A Javascript implemenation of PKI - DSA
 * 
 * @author Jacob Lee
 * Copyright (C) 2015-2022 Jacob Lee.
 */

const jCastle = require('./jCastle');

require('./bigint-extend');
require('./util');
require('./lang/en');
require('./error');

/* https://www.openssl.org/docs/crypto/dsa.html */

jCastle.pki.dsa = class
{
	/**
	 * An implementation of Digital Signature Algorithm(DSA).
	 * 
	 * @constructor
	 */
    constructor()
    {
        this.OID = "1.2.840.10040.4.1";
        this.pkiName = 'DSA';
        this.blockLength = 0;
		this.bitLength = 0;
        this.hasPrivKey = false;
        this.hasPubKey = false;

        this.params = {};
        this.publicKey = null;
        this.privateKey = null;

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
		this.publicKey = null;
		this.privateKey = null;

		this.blockLength = 0;
		this.bitLength = 0;

		this.hasPrivKey = false;
		this.hasPubKey = false;

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
		if (!params && typeof y == 'object' && 'kty' in y && y.kty == 'DSA') {
			params = {
				p: Buffer.from(y.p.replace(/[ \t\r\n]/g, ''), 'base64url').toString('hex'),
				q: Buffer.from(y.q.replace(/[ \t\r\n]/g, ''), 'base64url').toString('hex'),
				g: Buffer.from(y.g.replace(/[ \t\r\n]/g, ''), 'base64url').toString('hex')
			};
			
			var yy = BigInt.fromBufferUnsigned(Buffer.from(y.y.replace(/[ \t\r\n]/g, ''), 'base64url'));

			return this.setPublicKey(yy, params);
		}

		if (params) {
			this.setParameters(params);
		}

		if (!this.params || !this.params.p) {
			throw jCastle.exception("PARAMETERS_NOT_SET", 'DSA001');
		}

		if (!y && this.privateKey) {
			// pkcs8 pem format doesn't give you 'y'.

			y = this.params.g.modPow(this.privateKey, this.params.p);
		}

		this.publicKey = jCastle.util.toBigInt(y);

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
					kty: 'DSA',
					p: Buffer.from(params.p, 'hex').toString('base64url'),
					q: Buffer.from(params.q, 'hex').toString('base64url'),
					g: Buffer.from(params.g, 'hex').toString('base64url'),
					y: Buffer.from(this.publicKey.toString(16), 'hex').toString('base64url')
				};
			}

			return jCastle.util.formatBigInt(this.publicKey, format);
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
					kty: 'DSA',
					p: Buffer.from(params.p, 'hex').toString('base64url'),
					q: Buffer.from(params.q, 'hex').toString('base64url'),
					g: Buffer.from(params.g, 'hex').toString('base64url'),
					x: Buffer.from(this.privateKey.toString(16), 'hex').toString('base64url'),
					y: Buffer.from(this.publicKey.toString(16), 'hex').toString('base64url')
				};
			}
			return jCastle.util.formatBigInt(this.privateKey, format);
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
		if (typeof y == 'undefined' && typeof x == 'object' && 'kty' in x && x.kty == 'DSA') {
			params = {
				p: Buffer.from(x.p.replace(/[ \t\r\n]/g, ''), 'base64url').toString('hex'),
				q: Buffer.from(x.q.replace(/[ \t\r\n]/g, ''), 'base64url').toString('hex'),
				g: Buffer.from(x.g.replace(/[ \t\r\n]/g, ''), 'base64url').toString('hex')
			};
			
			var xx = BigInt.fromBufferUnsigned(Buffer.from(x.x.replace(/[ \t\r\n]/g, ''), 'base64url'));
			var yy = BigInt.fromBufferUnsigned(Buffer.from(x.y.replace(/[ \t\r\n]/g, ''), 'base64url'));

			return this.setPrivateKey(xx, yy, params);
		}

		if (params) {
			this.setParameters(params);
		}

		if (!this.params || !this.params.p) {
			throw jCastle.exception("PARAMETERS_NOT_SET", 'DSA002');
		}

		this.privateKey = jCastle.util.toBigInt(x);

		if (!y) y = this.params.g.modPow(this.privateKey, this.params.p);

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

		if (typeof pubkey == 'object' && 'kty' in pubkey && pubkey.kty == 'DSA') {
			var y = BigInt.fromBufferUnsigned(Buffer.from(pubkey.y.replace(/[ \t\r\n]/g, ''), 'base64url'));
			return this.publicKeyEquals(y);
		}

		var p = jCastle.util.toBigInt(pubkey);
		if (this.publicKey.equals(p)) return true;
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
	 * @param {mixed} q parameter q object or buffer
	 * @param {mixed} g parameter g object or buffer
	 * @returns this class instance.
	 */
	setParameters(p, q, g)
	{
		if (typeof q == 'undefined' && typeof p == 'object') {
			var params = p;
			q = params.q;
			g = params.g;
			p = params.p;
		}

		this.params = {
			p: jCastle.util.toBigInt(p),
			q: jCastle.util.toBigInt(q),
			g: jCastle.util.toBigInt(g)
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
		return jCastle.pki.dsa.formatParameters(this.params, format);
	}

/*
https://www.openssl.org/docs/HOWTO/keys.txt

3. To generate a DSA key

A DSA key can be used for signing only.  This is important to keep
in mind to know what kind of purposes a certificate request with a
DSA key can really be used for.

Generating a key for the DSA algorithm is a two-step process.  First,
you have to generate parameters from which to generate the key:

  openssl dsaparam -out dsaparam.pem 2048

The number 2048 is the size of the key, in bits.  Today, 2048 or
higher is recommended for DSA keys, as fewer amount of bits is
consider insecure or to be insecure pretty soon.

When that is done, you can generate a key using the parameters in
question (actually, several keys can be generated from the same
parameters):

  openssl gendsa -des3 -out privkey.pem dsaparam.pem

With this variant, you will be prompted for a protecting password.  If
you don't want your key to be protected by a password, remove the flag
'-des3' from the command line above.

	NOTE: if you intend to use the key together with a server
	certificate, it may be a good thing to avoid protecting it
	with a password, since that would mean someone would have to
	type in the password every time the server needs to access
	the key.
*/

/*
The first part of the DSA algorithm is the public key and private key generation, 
which can be described as:

	Choose a prime number q, which is called the prime divisor.
	Choose another primer number p, such that p-1 mod q = 0. p is called the prime modulus.
	Choose an integer g, such that 1 < g < p, g**q mod p = 1 and g = h**((p–1)/q) mod p. 
	q is also called g's multiplicative order modulo p.
	Choose an integer, such that 0 < x < q.
	Compute y as g**x mod p.
	Package the public key as {p,q,g,y}.
	Package the private key as {p,q,g,x}.
*/
	/**
	 * generates DSA parameters
	 * 
	 * @public
	 * @param {object} options options object for generation of DSA parameters
	 * @returns this class instance.
	 */
	generateParameters(options = {})
	{
		options.format = 'object';
		var params = jCastle.pki.dsa.generateParameters(options);
		this.params = params;

		return this;
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
			throw jCastle.exception("PARAMS_NOT_SET", 'DSA003');
		}

		if (typeof parameters != 'undefined') {
			this.setParameters(parameters);
		}

		// Choose an integer, such that 0 < x < q.
		var rng = new jCastle.prng();
		var x;
		var certainty = 10;

		do {
			x = BigInt.random(this.params.q.bitLength(), rng);
		} while (x.compareTo(0n) <= 0 || x.compareTo(this.params.q) >= 0);

		this.privateKey = x; // private key
		this.hasPrivKey = true;

		// Compute y as g**x mod p.
		this.publicKey = this.params.g.modPow(x, this.params.p); // public key
		this.hasPubKey = true;

		this.blockLength = (this.params.p.bitLength() + 7) >>> 3;
		this.bitLength = this.params.p.bitLength();

		return this;
	}

/*
RFC 6979

2.4.  Signature Generation

   Signature generation uses a cryptographic hash function H and an
   input message m.  The message is first processed by H, yielding the
   value H(m), which is a sequence of bits of length hlen.  Normally, H
   is chosen such that its output length hlen is roughly equal to qlen,
   since the overall security of the signature scheme will depend on the
   smallest of hlen and qlen; however, the relevant standards support
   all combinations of hlen and qlen.

   The following steps are then applied:

   1.  H(m) is transformed into an integer modulo q using the bits2int
       transform and an extra modular reduction:

          h = bits2int(H(m)) mod q

       As was noted in the description of bits2octets, the extra modular
       reduction is no more than a conditional subtraction.

   2.  A random value modulo q, dubbed k, is generated.  That value
       shall not be 0; hence, it lies in the [1, q-1] range.  Most of
       the remainder of this document will revolve around the process
       used to generate k.  In plain DSA or ECDSA, k should be selected
       through a random selection that chooses a value among the q-1
       possible values with uniform probability.

   3.  A value r (modulo q) is computed from k and the key parameters:

       *  For DSA:

             r = g^k mod p mod q

          (The exponentiation is performed modulo p, yielding a number
          between 0 and p-1, which is then further reduced modulo q.)

       *  For ECDSA: the point kG is computed; its X coordinate (a
          member of the field over which E is defined) is converted to
          an integer, which is reduced modulo q, yielding r.

       If r turns out to be zero, a new k should be selected and r
       computed again (this is an utterly improbable occurrence).

   4.  The value s (modulo q) is computed:

          s = (h+x*r)/k mod q

       The pair (r, s) is the signature.  How a signature is to be
       encoded is not covered by the DSA and ECDSA standards themselves;
       a common way is to use a DER-encoded ASN.1 structure (a SEQUENCE
       of two INTEGERs, for r and s, in that order).
*/	
	/**
	 * calculates E value. RFC 6979 says, h = bits2int(H(m)) mod q.
	 * 
	 * @private
	 * @param {buffer} input hashed buffer
	 * @param {BigInt} q modulo q
	 * @returns the calculated BigInt value.
	 */
	_calculateE(input, q)
    {
        var bits = input.length * 8;
        var qBits = q.bitLength();
        var z = BigInt.fromBufferUnsigned(input);

        //if (qBits > bits) return z.mod(q);
        if (bits > qBits) {
            z = z.shiftRight(bits - qBits);
        }
        return z.mod(q);
    }

	/*
	To generate a message signature, the sender can follow these steps:

		Generate the message digest h, using a hash algorithm like SHA1.
		Generate a random number k, such that 0 < k < q.
		Compute r as (g**k mod p) mod q. If r = 0, select a different k.
		Compute i, such that k*i mod q = 1. i is called the modular multiplicative inverse of k modulo q.
		Compute s = i*(h+r*x) mod q. If s = 0, select a different k.
		Package the digital signature as {r,s}.
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

		if (!this.hasPrivKey) throw jCastle.exception("PRIVKEY_NOT_SET", 'DSA004');

		if (Buffer.isBuffer(str)) ba = str;
		else ba = Buffer.from(str, 'latin1');

		hash_algo = jCastle.digest.getValidAlgoName(hash_algo);
		if (!hash_algo || jCastle._algorithmInfo[hash_algo].oid == null) {
			throw jCastle.exception("UNSUPPORTED_HASHER", 'DSA005');
		}

		if (random_k){
			if (!Buffer.isBuffer(random_k)) {
				if (/^[0-9A-F]+$/i.test(random_k)) random_k = Buffer.from(random_k, 'hex');
				else random_k = Buffer.from(random_k, 'latin1');
			}
		}
/*
		// if p's bit length is greater than 2048 then hash length should be above 256.
		// look at q_bit_len in jCastle.pki.dsa.generateKeypair()
		if (this.p.bitLength() >= 2048 && jCastle._algorithmInfo[hash_name].digest_size * 8 < 256) {
			throw "Hash bit length should be above 256 or the same. at least sha-256 should be selected.";
		}
*/
		var hash = new jCastle.digest(hash_algo).digest(ba);
		// var hash_bi = BigInt.fromBufferUnsigned(hash.slice(0, this.params.q.bitLength() >>> 3));
		var hash_bi = this._calculateE(hash, this.params.q);
		//var zero = 0n;
		var k, r, s, res;

		// Generate a random number k, such that 0 < k < q.
		var rng = new jCastle.prng();

		var counter = 0;

		for (;;) {
			if (random_k) {
				if (counter) {
					throw  jCastle.exception("INVALID_SALT", 'DSA020');
				}
				k = BigInt.fromBufferUnsigned(random_k);
			} else {
				do {
					k = BigInt.random(this.params.q.bitLength(), rng, true);
				} while (k.compareTo(0n) <= 0 || k.compareTo(this.params.q) >= 0);
			}

			// Compute r as (g^k mod p) mod q. If r = 0, select a different k.
			r = this.params.g.modPow(k, this.params.p).mod(this.params.q);

			if (r.compareTo(0n) <= 0) continue;
				
			// Compute i, such that k*i mod q = 1. i is called the modular multiplicative inverse of k modulo q.
			k = k.modInverse(this.params.q).multiply(hash_bi.add(this.privateKey.multiply(r)));
			// Compute s = i*(h+r*x) mod q. If s = 0, select a different k.
			s = k.mod(this.params.q);

			if (s.compareTo(0n) > 0) break;

			counter++;
		}

		// Package the digital signature as {r,s}.
		var bl = (this.params.q.bitLength() + 7) >>> 3;

		// r and s should be same length with q's blockLength
		var r_ba = r.toBuffer();
		var s_ba = s.toBuffer();

		if (r_ba.length < bl) 
			r_ba = Buffer.concat([Buffer.alloc(bl - r_ba.length, 0x00), r_ba]);
		if (s_ba.length < bl) 
			s_ba = Buffer.concat([Buffer.alloc(bl - s_ba.length, 0x00), s_ba]);
		if (r_ba.length > bl)
			r_ba = r_ba.slice(r_ba.length - bl);
		if (s_ba.length > bl)
			s_ba = s_ba.slice(s_ba.length - bl);

		switch (ret_type) {
			case 'concat':
				res = Buffer.concat([r_ba, s_ba]);
				break;
			case 'object':
				res = {
					r: r_ba,
					s: s_ba
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
	To verify a message signature, the receiver of the message and the digital signature can follow these steps:

		Generate the message digest h, using the same hash algorithm.
		Compute w, such that s*w mod q = 1. w is called the modular multiplicative inverse of s modulo q.
		Compute u1 = h*w mod q.
		Compute u2 = r*w mod q.
		Compute v = (((g**u1)*(y**u2)) mod p) mod q.
		If v == r, the digital signature is valid.
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
		if (!this.hasPubKey) throw jCastle.exception("PUBKEY_NOT_SET", 'DSA006');

		var hash_algo = 'hashAlgo' in options ? options.hashAlgo : 'sha-1';
		var ba, r, s;

		if (Buffer.isBuffer(str)) ba = str;
		else ba = Buffer.from(str, 'latin1');

		hash_algo = jCastle.digest.getValidAlgoName(hash_algo);
		if (!hash_algo || jCastle._algorithmInfo[hash_algo].oid == null) {
			throw jCastle.exception("UNSUPPORTED_HASHER", 'DSA007');
		}
/*
		// if p's bit length is greater than 2048 then hash length should be above 256.
		// look at q_bit_len in jCastle.pki.dsa.generateKeypair()
		if (this.p.bitLength() >= 2048 && jCastle._algorithmInfo[hash_name].digest_size * 8 < 256) {
			return false;
		}
*/
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
			r = BigInt.fromBufferUnsigned(r);
			s = BigInt.fromBufferUnsigned(s);
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
					r = BigInt.fromBufferUnsigned(signature.slice(0, signature.length / 2));
					s = BigInt.fromBufferUnsigned(signature.slice(signature.length / 2));
				}
			} else {
				// concat
				r = BigInt.fromBufferUnsigned(signature.slice(0, signature.length / 2));
				s = BigInt.fromBufferUnsigned(signature.slice(signature.length / 2));
			}
		}

		var hash = new jCastle.digest(hash_algo).digest(ba);
		//var hash_bi = BigInt.fromBufferUnsigned(hash.slice(0, this.params.q.bitLength() >>> 3));
		var hash_bi = this._calculateE(hash, this.params.q);
		//var zero = 0n;

		if (r.compareTo(0n) <= 0 || r.compareTo(this.params.q) >= 0 ||
			s.compareTo(0n) <= 0 || s.compareTo(this.params.q) >= 0
		) {
			return false;
		}

		// Compute w, such that s*w mod q = 1. w is called the modular multiplicative inverse of s modulo q.
		var w = s.modInverse(this.params.q);
		// Compute u1 = h*w mod q.
		var u1 = hash_bi.multiply(w).mod(this.params.q);
		// Compute u2 = r*w mod q.
		var u2 = r.multiply(w).mod(this.params.q);

		u1 = this.params.g.modPow(u1, this.params.p);
		u2 = this.publicKey.modPow(u2, this.params.p);

		// Compute v = (((g**u1)*(y**u2)) mod p) mod q.
		var v = u1.multiply(u2).mod(this.params.p).mod(this.params.q);

		//var v = this.params.g.modPow(u1, this.params.p).multiply(this.publicKey.modPow(u2, this.params.p)).mod(this.params.p).mod(this.params.q);
				
		// If v == r, the digital signature is valid.
		return v.compareTo(r) === 0;
	}
};

/**
 * creates a new DSA pki object.
 * 
 * @public
 * @returns the new DSA pki object.
 */
jCastle.pki.dsa.create = function()
{
	return new jCastle.pki.dsa();
};

jCastle.pki.dsa._PPGF = function(md, seed, hash_len, bits)
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
 * generates DSA parameters.
 * 
 * @public
 * @param {object} options options object.
 *                 {number} bits bits length for parameter p. (default: 1024)
 *                 {string} hashAlgo hash algorithm name. (default: 'sha-1')
 *                 {string} format format string.
 *                 {buffer} seed seed buffer
 * @returns generated parameters object.
 */
jCastle.pki.dsa.generateParameters = function(options = {})
{
	// function PPGF(md, seed, hash_len, bits)
	// {
	// 	var len = Math.ceil(((bits + 7) & 0xFFFFFFF8) / 8);
	// 	var tmp;
	// 	var result = Buffer.alloc(len);

	// 	for (var count = 0;; count++) {
	// 		md.start();
	// 		md.update(seed);
	// 		md.update(Buffer.alloc(1, count & 0xff));
	// 		tmp = md.finalize();

	// 		if (len >= hash_len) {
	// 			len -= hash_len;
	// 			tmp.copy(result, len, 0, tmp.length);
	// 			if (len === 0) break;
	// 		} else {
	// 			tmp.copy(result, 0, hash_len - len, hash_len);
	// 			break;
	// 		}
	// 	}

	// 	len = bits & 0x07;
	// 	if (len !== 0) result[0] &= (1 << len) - 1;

	// 	return result;
	// }

	var pBits = 'bits' in options ? options.bits : 1024;
	var hash_algo = 'hashAlgo' in options ? options.hashAlgo : 'sha-1';
	var format = 'format' in options ? options.format : 'object';
	var seed = 'seed' in options ? options.seed : null;
	var qBits = 160;

	if (pBits % 64 != 0) {
		throw jCastle.exception("INVALID_BITLENGTH", 'DSA008');
	}
	if (pBits < 512) pBits = 512;
	if (pBits >= 2048) {
		qBits = 256;
		hash_algo = 'sha-256';
	}

	if (seed && !Buffer.isBuffer(seed)) seed = Buffer.from(seed);

	var certainty = 10;
	// var one = 1n;
	// var two = 2n;
	var repeat = 160 - pBits / 32;
	var hash_len = jCastle.digest.getDigestLength(hash_algo);
	var seed_len = qBits >>> 3;

	var p, q, g, U, x, c, p1;


	var rng = new jCastle.prng();
	var md = new jCastle.digest(hash_algo);
	var seed_provided = seed ? true : false;
	var counter = 0;
	var limit = 1 << 24;

	do {
		if (counter && seed_provided) {
			// seed 값이 주어졌으나 생성된 BigInt J가 소수가 되지 못함.
			// 루프문을 빠져나갈 수 없으므로 throw error한다.
			throw jCastle.exception("INVALID_SEED", 'DSA009');
		}
		if (!seed_provided) seed = rng.nextBytes(seed_len);

		U = jCastle.pki.dsa._PPGF(md, seed, hash_len, qBits);

		U[0] |= 0x80;
        U[U.length - 1] |= 0x01;

		q = BigInt.fromBufferUnsigned(U);

		counter++;

	} while(!q.isProbablePrime(certainty));

	for (counter = 0; counter < limit; counter++) {
		// Choose another primer number p, such that p-1 mod q = 0. p is called the prime modulus.

		var cb = Buffer.alloc(4);
		cb.writeInt32BE(counter, 0);

		U = jCastle.pki.dsa._PPGF(md, Buffer.concat([seed, cb]), hash_len, pBits);

		U[0] |= 0x80;

		x = BigInt.fromBufferUnsigned(U);
		c = x.mod(q.multiply(2n));
		p = x.subtract(c.subtract(1n));

		if (p.testBit(pBits - 1) && p.isProbablePrime(certainty)) break;
	}

	if (counter == limit) throw jCastle.exception("FATAL_ERROR", 'DSA010');

	//
	// calculate the generator g.
	//

	// Choose an integer g, such that 1 < g < p, g**q mod p = 1 and g = h**((p–1)/q) mod p. 
	// q is also called g's multiplicative order modulo p.

	var p1q = p.subtract(1n).divide(q);

	do {
		var h = BigInt.random(pBits, rng);

		if (h.compareTo(p.subtract(1n)) >= 0 || h.compareTo(1n) <= 0) {
			continue;
		}

		g = h.modPow(p1q, p);
	}
	while (!g || g.compareTo(1n) <= 0);

    var params = {
		p: p,
		q: q,
		g: g
	};

	params.validity = {};
	params.validity.counter = counter;
	params.validity.seed = seed.toString('hex');

    return jCastle.pki.dsa.formatParameters(params, format);
};


jCastle.pki.dsa.generateParametersExt = function(options = {})
{
	var pBits = 'bits' in options ? options.bits : 1024;
	var format = 'format' in options ? options.format.toLowerCase() : 'object';
	var hash_algo = 'hashAlgo' in options ? options.hashAlgo : 'sha-1';
	var certainty = 'certainty' in options ? options.certainty : 10;
	var seed = 'seed' in options ? Buffer.from(options.seed) : null;
	var qBits = 160;
	var rng = new jCastle.prng();

	/**
     * add value to b, returning the result in a. The a value is treated
     * as a BigInt of length (a.length * 8) bits. The result is
     * modulo 2^a.length in case of overflow.
     */
	function add(a, b, value)
	{
		var x = (b[b.length - 1] & 0xff) + value;

		a[b.length - 1] = x & 0xff;
		x >>>= 8;

		for (var i = b.length - 2; i >= 0; i--) {
            x += (b[i] & 0xff);
            a[i] = x & 0xff;
            x >>>= 8;
        }
	}

	if (pBits % 64 != 0) {
		throw jCastle.exception("INVALID_BITLENGTH", 'DSA011');
	}
	if (pBits < 512) pBits = 512;
	if (pBits >= 2048) {
		qBits = 256;
		hash_algo = 'sha-256';
	}

	var len = qBits >>> 3;

	var hash_len = jCastle.digest.getDigestLength(hash_algo);

	if (seed && seed.length !== hash_len) {
		throw jCastle.exception("INVALID_SEED", 'DSA012');
	}

	var seed_provided = seed ? true : false;
	var counter = 0;

	var md = new jCastle.digest(hash_algo);
	var p1, p2, u, p, q, g;

	do {
		if (counter && seed_provided) {
			// seed 값이 주어졌으나 생성된 BigInt J가 소수가 되지 못함.
			// 루프문을 빠져나갈 수 없으므로 throw error한다.
			throw jCastle.exception("INVALID_BITLENGTH", 'DSA013');
		}
		if (!seed_provided) seed = rng.nextBytes(hash_len);

		p1 = md.digest(seed);
		p2 = Buffer.alloc(hash_len);
		seed.copy(p2);
		add(p2, seed, 1);
		p2 = md.digest(p2);

		u = Buffer.alloc(hash_len);

		for (var l = 0; l < u.length; l++) {
			u[l] = p1[l] ^ p2[l];
		}
		u[0] |= 0x80;
		u[u.length-1] |= 0x01;

		q = BigInt.fromBufferUnsigned(u);

		counter++;
	}
	while (!q.isProbablePrime(certainty));

	counter = 0;
	var offset = 2;
	var n = Math.floor((pBits - 1) / qBits);
	var len = pBits / 8;
	var w = Buffer.alloc(len);
	// var one = 1n;
	// var two = 2n;
	var limit = 1 << 24;

	for (counter = 0; counter < limit; counter++) {
		for (var k = 0; k < n; k++) {
			add(p1, seed, offset + k);
			p1 = md.digest(p1);
			p1.copy(w, len - (k + 1) * p1.length, 0, p1.length);
		}
		add(p1, seed, offset + n);
		p1 = md.digest(p1);
		p1.copy(w,0, p1.lengh - (len - n * p1.length), len -  n * p1.length);

		w[0] |= 0x80;

		var x = BigInt.fromBufferUnsigned(w);
		var c = x.mod(q.multiply(2n));
		var p = x.subtract(c.subtract(1n));

		if (p.testBit(pBits - 1) && p.isProbablePrime(certainty)) break;

		offset += n + 1;
	}
	if (counter == limit) throw jCastle.exception("FATAL_ERROR", 'DSA014');

	var p1q = p.subtract(1n).divide(q);

	for (;;) {
		var h = BigInt.random(pBits, rng);

		if (h.compareTo(1n) <= 0 || h.compareTo(p.subtract(1n)) >= 0) {
			continue;
		}

		g = h.modPow(p1q, p);
		if (g.compareTo(1n) <= 0) {
			continue;
		}
		break;
	}

	var params = {
		p: p,
		q: q,
		g: g
	};

	params.validity = {};
	params.validity.counter = counter;
	params.validity.seed = seed.toString('hex');

	params = jCastle.pki.dsa.formatParameters(params, format);

	return params;
};


jCastle.pki.dsa.formatParameters = function(params, format = 'hex')
{
    if (!params || !params.p) return null;

	var pp;

    switch (format) {
        case 'hex':
            pp = {
                p: params.p.toString(16),
                q: params.q.toString(16),
                g: params.g.toString(16)
            };
            break;
        // case 'raw':
        // case 'utf8':
        // 	var pp = {
        // 		p: jCastle.encoding.hex.decode(params.p.toString(16)),
        // 		q: jCastle.encoding.hex.decode(params.q.toString(16)),
        // 		g: jCastle.encoding.hex.decode(params.g.toString(16))
        // 	};
        // 	break;
        case 'object':
            pp = {
                p: params.p.clone(),
                q: params.q.clone(),
                g: params.g.clone()
            };
            break;
        default:
            pp = {
                p: params.p.toBuffer(),
                q: params.q.toBuffer(),
                g: params.g.toBuffer()
            };
            if (format !== 'buffer') {
                pp.p = pp.p.toString(format);
                pp.q = pp.q.toString(format);
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

/*
http://www.di-mgt.com.au/public-key-crypto-discrete-logs-1-diffie-hellman.html

Algorithm: Generate Domain Parameters.

	INPUT: Required bit lengths for modulus p and prime divisor q. 
	OUTPUT: Parameters (p,q,g). 

	Generate a random prime q of the required bit length.
	Choose an even random number j of bit length equal to bitlen(p) − bitlen(q)
	Compute p = jq+1. If p is not prime, then go to step 2.
	Choose a random number h in the range 1 < h < p−1.
	Compute g=hj mod p. If g = 1 then go to step 4.
	Return (p,q,g).

Algorithm: Verify Domain Parameters.

	INPUT: Parameters (p,q,g). 
	OUTPUT: "Accept parameters" or "Reject parameters". 

	Check that 1 < g < p−1. If not, then return "Reject parameters" and stop
	Test q for primality. If q is not prime then return "Reject parameters" and stop
	Test p for primality. If p is not prime then return "Reject parameters" and stop
	Compute (p−1) mod q. If this is not equal to 0 then return "Reject parameters" and stop
	Compute gq mod p. If this is not equal to 1 then return "Reject parameters" and stop
	Return "Accept parameters".
*/


// This taks too much time, still you may not see the result!
// don't use it....
/*
Let L-1 = 160*n + b, where b,n ∈ ℕ and 0 ≤ b < 160

    Choose a random number seed > 2¹⁶⁰. Let g be the length of seed in bits.
    U = sha(seed) XOR sha(seed+1 mod 2^g) (where sha is the Secure Hash Algorithm)
    q = U OR 2¹⁵⁹ OR 1
    Test if q is prime, if not go to step 1.
    counter = 0, offset = 2
    For k = 0,...,n: V_k = sha((seed + offset + k) mod 2^g)
    W = V_0 + V_1 * 2^160 + ... + V_(n-1) * 2^((n-1)*160) + (V_n mod 2^b) * 2^(n*160)
    X = W + 2^(L-1)
    c = X mod 2*q
    p = X - (c-1)
    If p < 2^(L-1) go to step 13.
    Test if p is prime, if so go to step 15.
    counter = counter + 1, offset = offset + n + 1
    If counter >= 4096 go to step 1, if not go to step 7.
    We have now p and q so that q is a divisor of p-1.
*/



jCastle._pkiInfo['dsa'] = {
	pki_name: 'DSA',
	object_name: 'dsa',
	oid: "1.2.840.10040.4.1"
};

jCastle.pki.dsa = jCastle.pki.dsa;

module.exports = jCastle.pki.dsa;

/*
http://www.di-mgt.com.au/public-key-crypto-discrete-logs-1-diffie-hellman.html

Algorithm: Key Pair Generation.

	INPUT: Parameters (p,q,g). 
	OUTPUT: Party A's private/public key pair (a, A). 

	Party A chooses a number a in the range [2,q−2].
	Compute A = ga mod p.
	Return (a, A). Keep a secret.

Think of ga mod p as the action of "throwing" the secret key a somewhere in the large range [1,p−1]. Because it is done modulo p there is no efficient way to go backwards and find a for a large enough p.

Algorithm: Computation of shared secret by Party A.
	INPUT: Parameters (p,q,g), B, a. 
	OUTPUT: Shared secret Z. 

	Check that 1 < B < p and that Bq mod p = 1. If not then return "Failure" and stop.
	Compute Z = Ba mod p.
	Return Z.
*/



/*
http://etutorials.org/Programming/secure+programming/Chapter+8.+Authentication+and+Key+Exchange/8.18+Using+Diffie-Hellman+and+DSA+Together/:

8.18 Using Diffie-Hellman and DSA Together
 
8.18.1 Problem

You want to use Diffie-Hellman for key exchange, 
and you need some secure way to authenticate the key agreement 
to protect against a man-in-the-middle attack.

8.18.2 Solution

Use the station-to-station protocol for two-way authentication. 
A simple modification provides one-way authentication. 
For example, the server may not care to authenticate the client 
using public key cryptography.

8.18.3 Discussion

	
Remember, authentication requires a trusted third party 
or a secure channel for exchange of public DSA keys. 
If you'd prefer a password-based protocol that can achieve all the same properties
you would get from Diffie-Hellman and DSA, see the discussion of PAX in Recipe 8.15.

Given a client initiating a connection with a server,
the station-to-station protocol is as follows:

	The client generates a random Diffie-Hellman secret x and the corresponding public value A.

	The client sends A to the server.

	The server generates a random Diffie-Hellman secret y and the corresponding public value B.

	The server computes the Diffie-Hellman shared secret.

	The server signs a string consisting of the public values A and B with the server's private DSA key.

	The server sends B and the signature to the client.

	The client computes the shared secret.

	The client validates the signature, failing if it isn't valid.

	The client signs A concatenated with B using its private DSA key, 
	and it encrypts the result using the shared secret 
	(the secret can be postprocessed first, as long as both sides do the same processing).

	The client sends the encrypted signature to the server.

	The server decrypts the signature and validates it.

The station-to-station protocol works only if your Diffie-Hellman keys are always one-time values.
If you need a protocol that doesn't expose the private values of each party, use Recipe 8.16. 
That basic protocol can be adapted from RSA to Diffie-Hellman with DSA if you so desire.

Unless you allow for anonymous connection establishment, 
the client needs to identify itself as part of this protocol. 
The client can send its public key (or a digital certificate containing the public key) at Step 2.
The server should already have a record of the client based on its public key, 
or else it should fail. 
Alternatively, you can drop the client validation steps (9-11) 
and use a traditional login mechanism after the encrypted link is established.

	
In many circumstances, the client won't have the server's public key in advance.
In such a case, the server will often send a copy of its public key 
(or a digital certificate containing the public key) at Step 6. 
In this case, the client can't assume that the public signing key is valid; 
there's nothing to distinguish it from an attacker's public key! 
Therefore, the key needs to be validated using a trusted third party 
before the client trusts that the party on the other end is really the intended server. 
(We discuss this problem in Recipe 7.1 and Recipe 10.1.)

*/
