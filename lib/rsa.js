/**
 * A Javascript implemenation of PKI - RSA
 * 
 * @author Jacob Lee
 *
 * Copyright (C) 2015-2022 Jacob Lee.
 */

const jCastle = require('./jCastle');
require('./bigint-extend');
require('./util');


// http://www.di-mgt.com.au/rsa_alg.html#pkcs1schemes

/*
https://tools.ietf.org/html/rfc3447#section-8.1


3.1 RSA public key

   For the purposes of this document, an RSA public key consists of two
   components:

      n        the RSA modulus, a positive integer
      e        the RSA public exponent, a positive integer

   In a valid RSA public key, the RSA modulus n is a product of u
   distinct odd primes r_i, i = 1, 2, ..., u, where u >= 2, and the RSA
   public exponent e is an integer between 3 and n - 1 satisfying GCD(e,
   \lambda(n)) = 1, where \lambda(n) = LCM(r_1 - 1, ..., r_u - 1).  By
   convention, the first two primes r_1 and r_2 may also be denoted p
   and q respectively.

   A recommended syntax for interchanging RSA public keys between
   implementations is given in Appendix A.1.1; an implementation's
   internal representation may differ.

3.2 RSA private key

   For the purposes of this document, an RSA private key may have either
   of two representations.

   1. The first representation consists of the pair (n, d), where the
      components have the following meanings:

         n        the RSA modulus, a positive integer
         d        the RSA private exponent, a positive integer

   2. The second representation consists of a quintuple (p, q, dP, dQ,
      qInv) and a (possibly empty) sequence of triplets (r_i, d_i, t_i),
      i = 3, ..., u, one for each prime not in the quintuple, where the
      components have the following meanings:

         p        the first factor, a positive integer
         q        the second factor, a positive integer
         dP       the first factor's CRT exponent, a positive integer
         dQ       the second factor's CRT exponent, a positive integer
         qInv     the (first) CRT coefficient, a positive integer
         r_i      the i-th factor, a positive integer
         d_i      the i-th factor's CRT exponent, a positive integer
         t_i      the i-th factor's CRT coefficient, a positive integer

   In a valid RSA private key with the first representation, the RSA
   modulus n is the same as in the corresponding RSA public key and is
   the product of u distinct odd primes r_i, i = 1, 2, ..., u, where u
   >= 2.  The RSA private exponent d is a positive integer less than n
   satisfying

      e * d == 1 mod φ(n),

   where e is the corresponding RSA public exponent and φ(n) is
   defined as in Section 3.1.

   In a valid RSA private key with the second representation, the two
   factors p and q are the first two prime factors of the RSA modulus n
   (i.e., r_1 and r_2), the CRT exponents dP and dQ are positive
   integers less than p and q respectively satisfying

      e * dP == 1 (mod (p-1))
      e * dQ == 1 (mod (q-1)) ,

   and the CRT coefficient qInv is a positive integer less than p
   satisfying

      q * qInv == 1 (mod p).

   If u > 2, the representation will include one or more triplets (r_i,
   d_i, t_i), i = 3, ..., u.  The factors r_i are the additional prime
   factors of the RSA modulus n.  Each CRT exponent d_i (i = 3, ..., u)
   satisfies

      e * d_i == 1 (mod (r_i - 1)).

   Each CRT coefficient t_i (i = 3, ..., u) is a positive integer less
   than r_i satisfying

      R_i * t_i == 1 (mod r_i) ,

   where R_i = r_1 * r_2 * ... * r_(i-1).

   A recommended syntax for interchanging RSA private keys between
   implementations, which includes components from both representations,
   is given in Appendix A.1.2; an implementation's internal
   representation may differ.

   Notes.

   1. The definition of the CRT coefficients here and the formulas that
      use them in the primitives in Section 5 generally follow Garner's
      algorithm [22] (see also Algorithm 14.71 in [37]). However, for
      compatibility with the representations of RSA private keys in PKCS
      #1 v2.0 and previous versions, the roles of p and q are reversed
      compared to the rest of the primes.  Thus, the first CRT
      coefficient, qInv, is defined as the inverse of q mod p, rather
      than as the inverse of R_1 mod r_2, i.e., of p mod q.

   2. Quisquater and Couvreur [40] observed the benefit of applying the
      Chinese Remainder Theorem to RSA operations.
*/
jCastle.pki.rsa = class
{
	/**
	 * An implemenation of PKI - RSA
	 * 
	 * @constructor
	 */
	constructor()
	{
		this.OID = "1.2.840.113549.1.1.1";
		this.pkiName = 'RSA';
		this.blockLength = 0;
		this.bitLength = 0;
		this.hasPrivKey = false;
		this.hasPubKey = false;

		this.padding = {
			mode: 'rsaes-pkcs1-v1_5' // 'PKCS1_Type_2'
		};

/*
The PEM private key format uses the header and footer lines:

 -----BEGIN RSA PRIVATE KEY-----
 -----END RSA PRIVATE KEY-----


RSAPrivateKey ::= SEQUENCE {
    version           Version,
    modulus           INTEGER,  -- n
    publicExponent    INTEGER,  -- e
    privateExponent   INTEGER,  -- d
    prime1            INTEGER,  -- p
    prime2            INTEGER,  -- q
    exponent1         INTEGER,  -- d mod (p-1)
    exponent2         INTEGER,  -- d mod (q-1)
    coefficient       INTEGER,  -- (inverse of q) mod p
    otherPrimeInfos   OtherPrimeInfos OPTIONAL
}

OtherPrimeInfos ::= SEQUENCE SIZE(1..MAX) OF OtherPrimeInfo

OtherPrimeInfo ::= SEQUENCE {
    prime             INTEGER,  -- ri
    exponent          INTEGER,  -- di
    coefficient       INTEGER   -- ti
}
*/
		this.privateKey = {};
		this.publicKey = {};

		this._pkiClass = true;
		this.keyID = null;
	}

/*
RSA's input block size:
encryption: (n.bitLength() + 7) / 8 - 1
decryption: (n.bitLength() + 7) / 8

output block size is the reverse of input block size.
*/
	/**
	 * resets internal variables.
	 * 
	 * @public
	 * @returns this class instance.
	 */
	reset()
	{
		this.hasPubKey = false;
		this.hasPrivKey = false;

		this.padding = {
			mode: 'rsaes-pkcs1-v1_5' // 'PKCS1_Type_2'
		};

		this.privateKey = {};
		this.publicKey = {};
		this.bitLength = 0;
		this.blockLength = 0;
		this.keyID = null;

		return this;
	}

	/**
	 * gets block length of n in bytes.
	 * 
	 * @public
	 * @returns block length in bytes.
	 */
	getBlockLength()
	{
		return this.blockLength;
	}

	/**
	 * gets block length of n in bits.
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
	 * @param {mixed} n publicKey n object or buffer.
	 * @param {mixed} e exponent value.
	 * @returns this class instance.
	 */
	setPublicKey(n, e)
	{
		var keyid;

		if (typeof e == 'undefined' && typeof n == 'object') {
			if ('kty' in n && n.kty == 'RSA') { // jwt
				var arg = n;

				if (arg.n) n = BigInt.fromBufferUnsigned(Buffer.from(arg.n.replace(/[ \t\r\n]/g, ''), 'base64url'));
				if (arg.e) e = parseInt(Buffer.from(arg.e.replace(/[ \t\r\n]/g, ''), 'base64url').toString('hex'), 16);
				if ('kid' in arg) keyid = arg.kid;
			} else {
				var arg = n;

				if (arg.n) n = arg.n;
				if (arg.e) e = arg.e;
			}
		}

		var pubkey = {};

		pubkey.n = jCastle.util.toBigInt(n);

		if (typeof e == 'number' && e % 1 === 0) {
			pubkey.e = e;
		} else if (jCastle.util.isString(e)) {
			if (!/^[0-9A-F]+$/i.test(e)) {
				e = Buffer.from(e).toString('hex');
			}
			pubkey.e = parseInt(e.replace(/^00/, ''), 16);
		} else {
			var e_i = jCastle.util.toBigInt(e);
			pubkey.e = e_i.intValue();
			//throw jCastle.exception("INVALID_PUBKEY", 'RSA001');
		}

		if (BigInt.is(pubkey.n)) {
			this.blockLength = (pubkey.n.bitLength() + 7) >>> 3;
			this.bitLength = pubkey.n.bitLength();
		}

		this.hasPubKey = true;
		this.publicKey = pubkey;

		if (keyid) this.keyID = keyid;

		// for function chaining
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

			switch (format.toLowerCase()) {
				case 'hex':
					return {
						n: this.publicKey.n.toString(16),
						e: this.publicKey.e.toString(16)
					};
				case 'jwt':
					return {
						kty: 'RSA',
						n: Buffer.from(this.publicKey.n.toString(16), 'hex').toString('base64url'),
						e: Buffer.from(this.publicKey.e.toString(16), 'hex').toString('base64url')
					};						
				case 'object':
					return {
						n: this.publicKey.n.clone(),
						e: this.publicKey.e
					};
				default:
					return {
						n: jCastle.util.formatBigInt(this.publicKey.n, format),
						e: jCastle.util.formatBigInt(BigInt('0x' + this.publicKey.e.toString(16)), format)
					};

			}
		}

		return false;
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

			switch (format.toLowerCase()) {
				case 'hex':
					return {
						n: this.privateKey.n.toString(16),
						e: this.privateKey.e.toString(16),
						d: this.privateKey.d.toString(16),
						p: this.privateKey.p.toString(16),
						q: this.privateKey.q.toString(16),
						dmp1: this.privateKey.dmp1.toString(16),
						dmq1: this.privateKey.dmq1.toString(16),
						iqmp: this.privateKey.iqmp.toString(16)
					};
				case 'jwt':
					return {
						kty: 'RSA',
						n: Buffer.from(this.privateKey.n.toString(16), 'hex').toString('base64url'),
						e: Buffer.from(this.privateKey.e.toString(16), 'hex').toString('base64url'),
						d: Buffer.from(this.privateKey.d.toString(16), 'hex').toString('base64url'),
						p: Buffer.from(this.privateKey.p.toString(16), 'hex').toString('base64url'),
						q: Buffer.from(this.privateKey.q.toString(16), 'hex').toString('base64url'),
						dp: Buffer.from(this.privateKey.dmp1.toString(16), 'hex').toString('base64url'),
						dq: Buffer.from(this.privateKey.dmq1.toString(16), 'hex').toString('base64url'),
						qi: Buffer.from(this.privateKey.iqmp.toString(16), 'hex').toString('base64url')
					};
				case 'object':
					return {
						n: this.privateKey.n.clone(),
						e: this.privateKey.e,
						d: this.privateKey.d.clone(),
						p: this.privateKey.p.clone(),
						q: this.privateKey.q.clone(),
						dmp1: this.privateKey.dmp1.clone(),
						dmq1: this.privateKey.dmq1.clone(),
						iqmp: this.privateKey.iqmp.clone()
					};
				default:
					return {
						n: jCastle.util.formatBigInt(this.publicKey.n, format),
						e: jCastle.util.formatBigInt(BigInt('0x' + this.publicKey.e.toString(16)), format),
						d: jCastle.util.formatBigInt(this.privateKey.d, format),
						p: jCastle.util.formatBigInt(this.privateKey.p, format),
						q: jCastle.util.formatBigInt(this.privateKey.q, format),
						dmp1: jCastle.util.formatBigInt(this.privateKey.dmp1, format),
						dmq1: jCastle.util.formatBigInt(this.privateKey.dmq1, format),
						iqmp: jCastle.util.formatBigInt(this.privateKey.iqmp, format)
					};
			}
		}

		return false;
	}

	/**
	 * gets publicKey information object.
	 * 
	 * @public
	 * @param {string} format publicKey format string
	 * @returns publicKey information object in format.
	 */
	getPublicKeyInfo(format = 'object')
	{
		var pubkey_info = {};
		pubkey_info.type = 'public';
		pubkey_info.algo = this.pkiName;
		pubkey_info.padding = this.padding;
		pubkey_info.publicKey = this.getPublicKey(format);

		return pubkey_info;	
	}

	/**
	 * gets privateKey information object.
	 * 
	 * @public
	 * @param {string} format privateKey format string
	 * @returns privateKey information object in format.
	 */
	getPrivateKeyInfo(format = 'object')
	{
		var privkey_info = {};
		privkey_info.type = 'private';
		privkey_info.algo = this.pkiName;
		privkey_info.padding = this.padding;
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

		try {
			var n = jCastle.util.toBigInt(pubkey.n);
			if (!this.publicKey.n.equals(n)) return false;

			if (typeof pubkey.e == 'number' && pubkey.e % 1 === 0) {
				if (this.publicKey.e != pubkey.e) return false;
			} else {
				var e = pubkey.e;
				if (!/^[0-9A-F]+$/i.test(e)) {
					e = Buffer.from(e).toString('hex');
				}
				e = parseInt(e, 16);
				if (this.publicKey.e != e) return false;
			}
		} catch (ex) {
			return false;
		}

		return true;
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
	 * sets privateKey and publicKey.
	 * 
	 * @public
	 * @param {mixed} n publicKey n object or buffer.
	 * @param {mixed} e publicKey exponent e object or buffer.
	 * @param {mixed} d privateKey d object or buffer.
	 * @param {mixed} p privateKey p object or buffer.
	 * @param {mixed} q privateKey q object or buffer.
	 * @param {mixed} dmp1 privateKey dmp1 object or buffer.
	 * @param {mixed} dmq1 privateKey dmq1 object or buffer.
	 * @param {mixed} iqmp privateKey iqmp object or buffer.
	 * @returns this class instance.
	 */
	setPrivateKey(n, e, d, p, q, dmp1, dmq1, iqmp)
	{
		var keyid;

		if (typeof e == 'undefined' && typeof n == 'object') {
			if ('kty' in n && n.kty == 'RSA') { // jwt
				var arg = n;

				if (arg.n) n = BigInt.fromBufferUnsigned(Buffer.from(arg.n.replace(/[ \t\r\n]/g, ''), 'base64url'));
				if (arg.e) e = parseInt(Buffer.from(arg.e.replace(/[ \t\r\n]/g, ''), 'base64url').toString('hex'), 16);
				if (arg.d) d = BigInt.fromBufferUnsigned(Buffer.from(arg.d.replace(/[ \t\r\n]/g, ''), 'base64url'));
				if (arg.p) p = BigInt.fromBufferUnsigned(Buffer.from(arg.p.replace(/[ \t\r\n]/g, ''), 'base64url'));
				if (arg.q) q = BigInt.fromBufferUnsigned(Buffer.from(arg.q.replace(/[ \t\r\n]/g, ''), 'base64url'));
				if (arg.dp) dmp1 = BigInt.fromBufferUnsigned(Buffer.from(arg.dp.replace(/[ \t\r\n]/g, ''), 'base64url'));
				if (arg.dq) dmq1 = BigInt.fromBufferUnsigned(Buffer.from(arg.dq.replace(/[ \t\r\n]/g, ''), 'base64url'));
				if (arg.qi) iqmp = BigInt.fromBufferUnsigned(Buffer.from(arg.qi.replace(/[ \t\r\n]/g, ''), 'base64url'));
				if ('kid' in arg) keyid = arg.kid;
			} else {
				var arg = n;

				if (arg.n) n = arg.n;
				if (arg.e) e = arg.e;
				if (arg.d) d = arg.d;
				if (arg.p) p = arg.p;
				if (arg.q) q = arg.q;
				if (arg.dmp1) dmp1 = arg.dmp1;
				if (arg.dmq1) dmq1 = arg.dmq1;
				if (arg.iqmp) iqmp = arg.iqmp;
			}
		}

		this.setPublicKey(n, e);

		var privkey = {};

		if (d) privkey.d = jCastle.util.toBigInt(d);

		if (typeof p != 'undefined' && typeof q != 'undefined') {
			// p
			privkey.p = jCastle.util.toBigInt(p);

			// q
			privkey.q = jCastle.util.toBigInt(q);

			var p1 = privkey.p.subtract(1n);
			var q1 = privkey.q.subtract(1n);

			if (!d) {
				var phi = p1.multiply(q1);
				var e_i = BigInt(this.publicKey.e);
				d = e_i.modInverse(phi);
				privkey.d = d;				
			}

			if (typeof dmp1 != 'undefined' && typeof dmq1 != 'undefined' && typeof iqmp != 'undefined') {
				// dmp1
				privkey.dmp1 = jCastle.util.toBigInt(dmp1);

				// dmq1
				privkey.dmq1 = jCastle.util.toBigInt(dmq1);

				// iqmp
				privkey.iqmp = jCastle.util.toBigInt(iqmp);
			} else {
				if (!this.publicKey.n) {
					this.publicKey.n = privkey.p.multiply(privkey.q);
				}
				privkey.dmp1 = privkey.d.mod(p1);
				privkey.dmq1 = privkey.d.mod(q1);
				privkey.iqmp = privkey.q.modInverse(privkey.p);
			}
		}

		if (BigInt.is(this.publicKey.n)) {
			this.blockLength = (this.publicKey.n.bitLength() + 7) >>> 3;
			this.bitLength = this.publicKey.n.bitLength();
		}

		privkey.n = this.publicKey.n;
		privkey.e = this.publicKey.e;

		this.privateKey = privkey;
		this.hasPrivKey = true;

		if (keyid && !this.keyID) this.keyID = keyid;

		return this;
	}

	/**
	 * check if the privateKey is right.
	 * 
	 * @public
	 * @param {object} privkey privateKey object
	 * @param {number} certainty certainty value for probablePrime check.
	 * @param {boolean} display_err flag for displaying errors
	 * @returns true if the privateKey is right.
	 */
	validateKeypair(privkey, certainty = 10, display_err = false)
	{
		var n, e, e_i, d, p, q, dmp1, dmq1, iqmp, p1, q1, phi;

		if (!privkey) privkey = this.getPrivateKey();

		if(!certainty) certainty = 10;

		if ('kty' in privkey && privkey.kty == 'RSA') { // jwt
			n = BigInt.fromBufferUnsigned(Buffer.from(arg.n, 'base64url'));
			e_i = BigInt.fromBufferUnsigned(Buffer.from(arg.e, 'base64url'));
			e = e_i.intValue();
//			e = parseInt(ByteBuffer.parseBase64(privkey.e, true).toString(16), 16);
//			e_i = BigInt('0x' + e.toString(16));
			d = BigInt.fromBufferUnsigned(Buffer.from(arg.d, 'base64url'));
			p = BigInt.fromBufferUnsigned(Buffer.from(arg.p, 'base64url'));
			q = BigInt.fromBufferUnsigned(Buffer.from(arg.q, 'base64url'));
			dmp1 = BigInt.fromBufferUnsigned(Buffer.from(arg.dmp1, 'base64url'));
			dmq1 = BigInt.fromBufferUnsigned(Buffer.from(arg.dmq1, 'base64url'));
			iqmp = BigInt.fromBufferUnsigned(Buffer.from(arg.iqmp, 'base64url'));
		} else {
			n = jCastle.util.toBigInt(privkey.n);
			e_i = jCastle.util.toBigInt(privkey.e);
			e = e_i.intValue();
			d = jCastle.util.toBigInt(privkey.d);
			p = jCastle.util.toBigInt(privkey.p);
			q = jCastle.util.toBigInt(privkey.q);
			dmp1 = jCastle.util.toBigInt(privkey.dmp1);
			dmq1 = jCastle.util.toBigInt(privkey.dmq1);
			iqmp = jCastle.util.toBigInt(privkey.iqmp);
		}

		p1 = p.subtract(1n);
		q1 = q.subtract(1n);
		phi = p1.multiply(q1);

		if (!n.equals(p.multiply(q))) {
			if (display_err) console.log('n !== p * q');
			return false;
		}
		
		if (!phi.gcd(e_i).isOne()) {
			if (display_err) console.log('gcd(phi, e) !== 1');
			return false;
		}
		
		if (!d.equals(e_i.modInverse(phi))) {
			if (display_err) console.log('d !== e^-1 mod phi');
			return false;
		}
		
		if (!dmp1.equals(d.mod(p1))) {
			if (display_err) console.log('dmp1 !== d mod p1');
			return false;
		}
		
		if (!dmq1.equals(d.mod(q1))) {
			if (display_err) console.log('dmq1 !== d mod q1');
			return false;
		}
		
		if (!iqmp.equals(q.modInverse(p))) {
			if (display_err) console.log('iqmp !== q^-1 mod p');
			return false;
		}

		
		if (!p.subtract(1n).gcd(e_i).isOne()) {
			if (display_err) console.log('gcd(p-1, e) !== 1');
			return false;
		}
		
		if (!q.subtract(1n).gcd(e_i).isOne()) {
			if (display_err) console.log('gcd(q-1, e) !== 1');
			return false;
		}
		
		if (!p.isProbablePrime(certainty)) {
			if (display_err) console.log('p is not a prime.');
			return false;
		}
		
		if (!q.isProbablePrime(certainty)) {
			if (display_err) console.log('q is not a prime.');
			return false;
		}
/*
		if (certainty < 10) {
			if (!p.isLucasLehmerPrime()) {
				if (display_err) console.log('p is not a prime.');
				return false;
			}
			if (!q.isLucasLehmerPrime()) {
				if (display_err) console.log('q is not a prime.');
				return false;
			}
		}
*/
		return true;		
	}

	/**
	 * sets padding for RSA
	 * 
	 * @public
	 * @param {mixed} mode mode value string or object
	 * @param {string} hash_algo hash algorithm name
	 * @param {string} label lable for padding
	 * @param {string} mgf mgf function name
	 * @returns 
	 */
	setPadding(mode, hash_algo = 'sha-1', label = '', mgf = 'mgf1')
	{
		if (jCastle.util.isString(mode)) {
			mode = mode.toLowerCase();
			switch (mode) {
				case 'rsaes-oaep':
				case 'pkcs1_oaep':
					this.padding = {
						mode: mode,
						hashAlgo: (typeof hash_algo != 'undefined' && hash_algo) ? hash_algo : 'sha-1',
						label: (typeof label != 'undefined' && label) ? label : '',
						mgf: (typeof mgf != 'undefined' && mgf) ? mgf : 'mgf1'
					};
					break;
				case 'pkcs1_type_1':
					this.padding = {
						mode: mode,
						blockType: typeof hash_algo === 'number' ? hash_algo : 0x01
					};
					break;
				case 'rsaes-pkcs1-v1_5':
				case 'pkcs1_type_2':
					this.padding = {
						mode: mode
					};
					break;
				case 'no-padding':
				case 'none':
					this.padding = {
						mode: 'no-padding'
					};
					break;
				default:
					throw jCastle.exception("INVALID_PADDING_METHOD", 'RSA002');
			}
		} else {
			this.padding = mode;
		}

		return this;
	}

/*
5.1.1 RSAEP

   RSAEP ((n, e), m)

   Input:
   (n, e)   RSA public key
   m        message representative, an integer between 0 and n - 1

   Output:
   c        ciphertext representative, an integer between 0 and n - 1

   Error: "message representative out of range"

   Assumption: RSA public key (n, e) is valid

   Steps:

   1. If the message representative m is not between 0 and n - 1, output
      "message representative out of range" and stop.

   2. Let c = m^e mod n.

   3. Output c.
*/
/*
5.2.2 RSAVP1

   RSAVP1 ((n, e), s)

   Input:
   (n, e)   RSA public key
   s        signature representative, an integer between 0 and n - 1

   Output:
   m        message representative, an integer between 0 and n - 1

   Error: "signature representative out of range"

   Assumption: RSA public key (n, e) is valid

   Steps:

   1. If the signature representative s is not between 0 and n - 1,
      output "signature representative out of range" and stop.

   2. Let m = s^e mod n.

   3. Output m.
*/
	_publicCrypt(x)
	{
		//return x.modPowInt(this.publicKey.e, this.publicKey.n);
		return x.modPow(this.publicKey.e, this.publicKey.n);
	}

/*
5.1.2   RSADP

   RSADP (K, c)

   Input:
   K        RSA private key, where K has one of the following forms:
            - a pair (n, d)
            - a quintuple (p, q, dP, dQ, qInv) and a possibly empty
              sequence of triplets (r_i, d_i, t_i), i = 3, ..., u
   c        ciphertext representative, an integer between 0 and n - 1

   Output:
   m        message representative, an integer between 0 and n - 1

   Error: "ciphertext representative out of range"

   Assumption: RSA private key K is valid

   Steps:

   1. If the ciphertext representative c is not between 0 and n - 1,
      output "ciphertext representative out of range" and stop.

   2. The message representative m is computed as follows.

      a. If the first form (n, d) of K is used, let m = c^d mod n.

      b. If the second form (p, q, dP, dQ, qInv) and (r_i, d_i, t_i)
         of K is used, proceed as follows:

         i.    Let m_1 = c^dP mod p and m_2 = c^dQ mod q.

         ii.   If u > 2, let m_i = c^(d_i) mod r_i, i = 3, ..., u.

         iii.  Let h = (m_1 - m_2) * qInv mod p.

         iv.   Let m = m_2 + q * h.

         v.    If u > 2, let R = r_1 and for i = 3 to u do

                  1. Let R = R * r_(i-1).

                  2. Let h = (m_i - m) * t_i mod r_i.

                  3. Let m = m + R * h.

   3.   Output m.

   Note.  Step 2.b can be rewritten as a single loop, provided that one
   reverses the order of p and q.  For consistency with PKCS #1 v2.0,
   however, the first two primes p and q are treated separately from
   the additional primes.
*/
/*
5.2.1 RSASP1

   RSASP1 (K, m)

   Input:
   K        RSA private key, where K has one of the following forms:
            - a pair (n, d)
            - a quintuple (p, q, dP, dQ, qInv) and a (possibly empty)
              sequence of triplets (r_i, d_i, t_i), i = 3, ..., u
   m        message representative, an integer between 0 and n - 1

   Output:
   s        signature representative, an integer between 0 and n - 1

   Error: "message representative out of range"

   Assumption: RSA private key K is valid

   Steps:

   1. If the message representative m is not between 0 and n - 1,
      output "message representative out of range" and stop.

   2. The signature representative s is computed as follows.

      a. If the first form (n, d) of K is used, let s = m^d mod n.

         b. If the second form (p, q, dP, dQ, qInv) and (r_i, d_i, t_i)
         of K is used, proceed as follows:

         i.    Let s_1 = m^dP mod p and s_2 = m^dQ mod q.

         ii.   If u > 2, let s_i = m^(d_i) mod r_i, i = 3, ..., u.

         iii.  Let h = (s_1 - s_2) * qInv mod p.

         iv.   Let s = s_2 + q * h.

         v.    If u > 2, let R = r_1 and for i = 3 to u do

                  1. Let R = R * r_(i-1).

                  2. Let h = (s_i - s) * t_i mod r_i.

                  3. Let s = s + R * h.

   3. Output s.

   Note.  Step 2.b can be rewritten as a single loop, provided that one
   reverses the order of p and q.  For consistency with PKCS #1 v2.0,
   however, the first two primes p and q are treated separately from the
   additional primes.
*/
	// protected
	// Perform raw private operation on "x": return x^d (mod n)
	_privateCrypt(x)
	{
		if(!this.privateKey.p || !this.privateKey.q) {
			//return x.modPow(this.privateKey.d, this.privateKey.n);
			return this._privateCrypt2(x);
		}

		// var xp = x.mod(this.privateKey.p).modPow(this.privateKey.dmp1, this.privateKey.p);
		// var xq = x.mod(this.privateKey.q).modPow(this.privateKey.dmq1, this.privateKey.q);

		// while(xp.compareTo(xq) < 0) xp = xp.add(this.privateKey.p);
		// return xp.subtract(xq).multiply(this.privateKey.iqmp).mod(this.privateKey.p).multiply(this.privateKey.q).add(xq);

		var xp, xq, h, m;

		// mP = ((input mod p) ^ dP)) mod p
		xp = (x.mod(this.privateKey.p)).modPow(this.privateKey.dmp1, this.privateKey.p);

		// mQ = ((input mod q) ^ dQ)) mod q
		xq = (x.mod(this.privateKey.q)).modPow(this.privateKey.dmq1, this.privateKey.q);

		// h = qInv * (mP - mQ) mod p
		h = xp.subtract(xq).mod(this.privateKey.p);
		while (h.compareTo(1n) <= 0) h = h.add(this.privateKey.p);
		h = h.multiply(this.privateKey.iqmp).mod(this.privateKey.p);

		// m = h * q + mQ
		m = h.multiply(this.privateKey.q).add(xq);

		return m;
	}

	_privateCrypt2(x)
	{
		return x.modPow(this.privateKey.d, this.privateKey.n);
	}

/*
   RSAES-PKCS1-V1_5-ENCRYPT ((n, e), M)

   Input:
   (n, e)   recipient's RSA public key (k denotes the length in octets
            of the modulus n)
   M        message to be encrypted, an octet string of length mLen,
            where mLen <= k - 11

   Output:
   C        ciphertext, an octet string of length k

   Error: "message too long"

   Steps:

   1. Length checking: If mLen > k - 11, output "message too long" and
      stop.

   2. EME-PKCS1-v1_5 encoding:

      a. Generate an octet string PS of length k - mLen - 3 consisting
         of pseudo-randomly generated nonzero octets.  The length of PS
         will be at least eight octets.

      b. Concatenate PS, the message M, and other padding to form an
         encoded message EM of length k octets as

            EM = 0x00 || 0x02 || PS || 0x00 || M.

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
*/
/*
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
	/**
	 * encrypt a message by publicKey.
	 * 
	 * @public
	 * @param {buffer} str message to be encrypted.
	 * @param {object} options options object.
	 *                 {mixed} padding padding string or object for RSA padding.
	 * @returns the encrypted message in buffer.
	 */
	publicEncrypt(pt, options)
	{
		if (!this.hasPubKey) {
			throw jCastle.exception('PUBKEY_NOT_SET', 'RSA003');
		}
		return this._encrypt(false, pt, options);
	}

	/**
	 * encrypt the ciphertext by privateKey.
	 * 
	 * @public
	 * @param {buffer} str message to be encrypted
	 * @param {object} options options object.
	 *                 {mixed} padding padding string or object for RSA padding.
	 * @returns the encrypted message in buffer.
	 */
	privateEncrypt(pt, options)
	{
		if (!this.hasPrivKey) {
			throw jCastle.exception('PRIVKEY_NOT_SET', 'RSA004');
		}
		return this._encrypt(true, pt, options);
	}

	_encrypt(is_private, pt, options = {})
	{
		var padding = 'padding' in options ? options.padding : this.padding;

		var padding_mode = padding.mode.toLowerCase();
		var mgf = 'mgf' in padding ? padding.mgf.toLowerCase() : 'mgf1';
		var hash_algo = 'hashAlgo' in padding ? padding.hashAlgo : 'sha-1';
		var label = 'label' in padding ? padding.label : Buffer.alloc(0);
		var blockType = 'blockType' in padding ? padding.blockType : 0x02;
		var seed = 'seed' in padding ? padding.seed : null;
		var ba;

		ba = Buffer.from(pt);

		// https://www.openssl.org/docs/manmaster/man3/RSA_padding_add_PKCS1_type_1.html
		switch (padding_mode) {
			case 'rsaes-oaep':
			case 'pkcs1_oaep':
				ba = jCastle.pki.rsa.padding.create('rsaes-oaep' + '_' + mgf).pad(ba, this.getBitLength(), hash_algo, label, seed);
				break;
			case 'pkcs1_type_1':
			case 'pkcs1_type_2':
			case 'rsaes-pkcs1-v1_5':
				if (padding_mode == 'pkcs1_type_2' || padding_mode == 'rsaes-pkcs1-v1_5')
					blockType = 0x02;
				ba = jCastle.pki.rsa.padding.create('rsaes-pkcs1-v1_5').pad(ba, this.getBitLength(), blockType); 
				break;
			case 'sslv23':
				ba = jCastle.pki.rsa.padding.create('sslv23').pad(ba, this.getBitLength()); 
				break;
			case 'no-padding':
			case 'none': 
				break;
			default:
				throw jCastle.exception("INVALID_PADDING", 'RSA005');
		}

		if (ba === null || !ba.length) return null;

		var bi_ba = BigInt.fromBufferUnsigned(ba);

		var c = is_private ? this._privateCrypt(bi_ba) : this._publicCrypt(bi_ba);
		if (c === null) return null;

		ba = c.toBuffer();

		if (ba.length < this.blockLength) 
			ba = Buffer.concat([Buffer.alloc(this.blockLength - ba.length, 0x00), ba]);
		if (ba.length > this.blockLength)
			ba = Buffer.slice(ba, ba.length - this.blockLength);

		if ('encoding' in options)
			ba = ba.toString(options.encoding);

		return ba;
	}


	// Return the PKCS#1 RSA decryption of "ct".
	// "ct" is an even-length hex string and the output is a plain string.
	/**
	 * decrypt a message by publicKey.
	 * 
	 * @public
	 * @param {buffer} str message to be decrypted.
	 * @param {object} options options object.
	 *                 {mixed} padding padding string or object for RSA padding.
	 * @returns the decrypted message in buffer.
	 */
	publicDecrypt(ct, options)
	{
		if (!this.hasPubKey) {
			throw jCastle.exception('PUBKEY_NOT_SET', 'RSA006');
		}
		return this._decrypt(false, ct, options);
	}


/*
   RSAES-PKCS1-V1_5-DECRYPT (K, C)

   Input:
   K        recipient's RSA private key
   C        ciphertext to be decrypted, an octet string of length k,
            where k is the length in octets of the RSA modulus n

   Output:
   M        message, an octet string of length at most k - 11

   Error: "decryption error"

   Steps:

   1. Length checking: If the length of the ciphertext C is not k octets
      (or if k < 11), output "decryption error" and stop.

   2. RSA decryption:

      a. Convert the ciphertext C to an integer ciphertext
         representative c (see Section 4.2):

            c = OS2IP (C).

      b. Apply the RSADP decryption primitive (Section 5.1.2) to the RSA
         private key (n, d) and the ciphertext representative c to
         produce an integer message representative m:

            m = RSADP ((n, d), c).

         If RSADP outputs "ciphertext representative out of range"
         (meaning that c >= n), output "decryption error" and stop.

      c. Convert the message representative m to an encoded message EM
         of length k octets (see Section 4.1):

            EM = I2OSP (m, k).

   3. EME-PKCS1-v1_5 decoding: Separate the encoded message EM into an
      octet string PS consisting of nonzero octets and a message M as

         EM = 0x00 || 0x02 || PS || 0x00 || M.

      If the first octet of EM does not have hexadecimal value 0x00, if
      the second octet of EM does not have hexadecimal value 0x02, if
      there is no octet with hexadecimal value 0x00 to separate PS from
      M, or if the length of PS is less than 8 octets, output
      "decryption error" and stop.  (See the note below.)

   4. Output M.

   Note.  Care shall be taken to ensure that an opponent cannot
   distinguish the different error conditions in Step 3, whether by
   error message or timing.  Otherwise an opponent may be able to obtain
   useful information about the decryption of the ciphertext C, leading
   to a strengthened version of Bleichenbacher's attack [6]; compare to
   Manger's attack [36].
*/
/*
   RSAES-OAEP-DECRYPT (K, C, L)

   Options:
   Hash     hash function (hLen denotes the length in octets of the hash
            function output)
   MGF      mask generation function

   Input:
   K        recipient's RSA private key (k denotes the length in octets
            of the RSA modulus n)
   C        ciphertext to be decrypted, an octet string of length k,
            where k = 2hLen + 2
   L        optional label whose association with the message is to be
            verified; the default value for L, if L is not provided, is
            the empty string

   Output:
   M        message, an octet string of length mLen, where mLen <= k -
            2hLen - 2

   Error: "decryption error"

   Steps:

   1. Length checking:

      a. If the length of L is greater than the input limitation for the
         hash function (2^61 - 1 octets for SHA-1), output "decryption
         error" and stop.

      b. If the length of the ciphertext C is not k octets, output
         "decryption error" and stop.

      c. If k < 2hLen + 2, output "decryption error" and stop.

   2.    RSA decryption:

      a. Convert the ciphertext C to an integer ciphertext
         representative c (see Section 4.2):

            c = OS2IP (C).

         b. Apply the RSADP decryption primitive (Section 5.1.2) to the
         RSA private key K and the ciphertext representative c to
         produce an integer message representative m:

            m = RSADP (K, c).

         If RSADP outputs "ciphertext representative out of range"
         (meaning that c >= n), output "decryption error" and stop.

      c. Convert the message representative m to an encoded message EM
         of length k octets (see Section 4.1):

            EM = I2OSP (m, k).

   3. EME-OAEP decoding:

      a. If the label L is not provided, let L be the empty string. Let
         lHash = Hash(L), an octet string of length hLen (see the note
         in Section 7.1.1).

      b. Separate the encoded message EM into a single octet Y, an octet
         string maskedSeed of length hLen, and an octet string maskedDB
         of length k - hLen - 1 as

            EM = Y || maskedSeed || maskedDB.

      c. Let seedMask = MGF(maskedDB, hLen).

      d. Let seed = maskedSeed \xor seedMask.

      e. Let dbMask = MGF(seed, k - hLen - 1).

      f. Let DB = maskedDB \xor dbMask.

      g. Separate DB into an octet string lHash' of length hLen, a
         (possibly empty) padding string PS consisting of octets with
         hexadecimal value 0x00, and a message M as

            DB = lHash' || PS || 0x01 || M.

         If there is no octet with hexadecimal value 0x01 to separate PS
         from M, if lHash does not equal lHash', or if Y is nonzero,
         output "decryption error" and stop.  (See the note below.)

   4. Output the message M.

   Note.  Care must be taken to ensure that an opponent cannot
   distinguish the different error conditions in Step 3.g, whether by
   error message or timing, or, more generally, learn partial
   information about the encoded message EM.  Otherwise an opponent may
   be able to obtain useful information about the decryption of the
   ciphertext C, leading to a chosen-ciphertext attack such as the one
   observed by Manger [36].
*/
	/**
	 * decrypt a message by privateKey.
	 * 
	 * @public
	 * @param {buffer} str message to be decrypted.
	 * @param {object} options options object.
	 *                 {mixed} padding padding string or object for RSA padding.
	 * @returns the decrypted message in buffer.
	 */
	privateDecrypt(ct, options)
	{
		if (!this.hasPrivKey) {
			throw jCastle.exception('PRIVKEY_NOT_SET', 'RSA007');
		}
		return this._decrypt(true, ct, options);
	}

	_decrypt(is_private, ct, options = {})
	{
		var padding = 'padding' in options ? options.padding : this.padding;

		var padding_mode = padding.mode.toLowerCase();
		var mgf = 'mgf' in padding ? padding.mgf.toLowerCase() : 'mgf1';
		var hash_algo = 'hashAlgo' in padding ? padding.hashAlgo : 'sha-1';
		var label = 'label' in padding ? padding.label : '';
		var blockType = 'blockType' in padding ? padding.blockType : 0x02;

	// when a BigInt starts a digit bigger than or equal 0x80 
	// then it might be treated as a minus number...
	// therefore BigInt.fromBufferUnsigned() must be used.

		var c = ct;

		if (!Buffer.isBuffer(c)) {
			if (/^[0-9a-f]+$/i.test(c)) c = Buffer.from(c, 'hex');
			else c = Buffer.from(c);
		}
		
		c = BigInt.fromBufferUnsigned(c);

		var bi_m = is_private ? this._privateCrypt(c) : this._publicCrypt(c);

		if(bi_m == null) {
			// console.log('bi_m is null');
			return null;
		}

		var ba = bi_m.toBuffer();

		// console.log('ba: ', ba);
		// console.log('padding: ', padding_mode);

		switch (padding_mode) {
			case 'rsaes-oaep':
			case 'pkcs1_oaep':
				ba = jCastle.pki.rsa.padding.create('rsaes-oaep' + '_' + mgf).unpad(ba, this.getBitLength(), hash_algo, label); 
				break;
			case 'pkcs1_type_1':
			case 'pkcs1_type_2':
			case 'rsaes-pkcs1-v1_5':
				if (padding_mode == 'pkcs1_type_2' || padding_mode == 'rsaes-pkcs1-v1_5') {
					blockType = 0x02;
				}
				ba = jCastle.pki.rsa.padding.create('rsaes-pkcs1-v1_5').unpad(ba, this.getBitLength(), blockType);
				break;
			case 'sslv23':
				ba = jCastle.pki.rsa.padding.create('sslv23').unpad(ba, this.getBitLength());
				break;
			case 'no-padding':
			case 'none': 
				break;
			default:
				throw jCastle.exception("INVALID_PADDING", 'RSA008');
		}

		if (ba == null || !ba.length) return null;

		if ('encoding' in options)
			ba = ba.toString(options.encoding);

		return ba;
	}

/*
var RSA_DEFAULT_BIT_LENGTH = 1024;
var RSA_DEFAULT_EXPONENT_HEX_VALUE = '10001';
*/

/*
https://www.openssl.org/docs/HOWTO/keys.txt

2. To generate a RSA key

A RSA key can be used both for encryption and for signing.

Generating a key for the RSA algorithm is quite easy, all you have to
do is the following:

  openssl genrsa -des3 -out privkey.pem 2048

With this variant, you will be prompted for a protecting password.  If
you don't want your key to be protected by a password, remove the flag
'-des3' from the command line above.

    NOTE: if you intend to use the key together with a server
    certificate, it may be a good thing to avoid protecting it
    with a password, since that would mean someone would have to
    type in the password every time the server needs to access
    the key.

The number 2048 is the size of the key, in bits.  Today, 2048 or
higher is recommended for RSA keys, as fewer amount of bits is
consider insecure or to be insecure pretty soon.
*/
// Generate a new random private key B bits long, using public exponent E

	/**
	 * generates privateKey and publicKey.
	 * 
	 * @public
	 * @param {object} options options object.
	 *                 {number} bits RSA bits length. (default: 2048)
	 *                 {number} exponent publicKey exponent (default: 0x10001)
	 *                 {string} hashAlgo hash algorithm.
	 *                 {number} certainty certainty for probablePrime check.
	 *                 {buffer} seed seed value
	 * @returns this class instance.
	 */
	generateKeypair(options = {})
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

		var bits = 'bits' in options ? options.bits : 2048;
		var exponent = 'exponent' in options ? options.exponent : 0x10001;
		var hash_algo = 'hashAlgo' in options ? options.hashAlgo : null;
		var certainty = 'certainty' in options ? options.certainty : 10;
		var seed = 'seed' in options ? Buffer.from(options.seed, 'latin1') : null;
		// var hash_len = jCastle.digest.getDigestLength(hash_algo);
		// var md = jCastle.digest.create(hash_algo);

		if (!bits) {
			throw jCastle.exception("PARAMS_NOT_SET", 'RSA011');
		}

		if (bits % 8) {
			throw jCastle.exception("INVALID_BIT_LENGTH", 'RSA012');
		}

		var rng = new jCastle.prng(seed, hash_algo);
		var qBits = bits >>> 1;
		var pBits = bits - qBits;
		var min_diff_bits = parseInt(bits / 3);
		var bi_e, n, e, d, p, q, dmp1, dmq1, iqmp, p1, q1, phi;
		var T;
		var pCounter = 0;
		var qCounter = 0;

		if (typeof exponent == 'number' && exponent % 1 == 0) {
		//if (jCastle.util.isInteger(exponent)) {
			e = exponent;
			bi_e = BigInt(exponent);
		} else {
			bi_e = jCastle.util.toBigInt(exponent);
			e = parseInt(bi_e.toString(16), 16);
		}

		for (;;) {
			// seed = rng.nextBytes(hash_len);
			// T = PPGF(md, seed, hash_len, pBits);
			T = rng.nextBytes(pBits / 8);

			T[0] |= 0x80;
			T[T.length - 1] |= 0x01;

			p = BigInt.fromBufferUnsigned(T);

			if (!p.isProbablePrime(certainty)) continue;

			if (p.bitLength() != pBits) continue;
			if(p.subtract(1n).gcd(bi_e).isOne()) break;

			pCounter++;
		}

		for (;;) {
			// generate q and check min_diff_bits
			for (;;) {
				// seed = rng.nextBytes(hash_len);
				// T = PPGF(md, seed, hash_len, qBits);
				T = rng.nextBytes(qBits / 8);

				T[0] |= 0x80;
				T[T.length - 1] |= 0x01;

				q = BigInt.fromBufferUnsigned(T);

				if (!q.isProbablePrime(certainty)) continue;

				if (q.bitLength() != qBits) continue;
				// consider safe primes for p and q
				if (p.subtract(q).abs().bitLength() < min_diff_bits) continue;
				if(q.subtract(1n).gcd(bi_e).isOne()) break;

				qCounter++;
			}

			// calculate the modulus
			n = p.multiply(q);

			if (n.bitLength() != bits) continue;

			if(p.compareTo(q) < 0) {
				var t = p;
				p = q;
				q = t;
			}

			p1 = p.subtract(1n);
			q1 = q.subtract(1n);
			phi = p1.multiply(q1);

			if(phi.gcd(bi_e).isOne()) break;
		}

		d = bi_e.modInverse(phi);
		dmp1 = d.mod(p1);
		dmq1 = d.mod(q1);
		iqmp = q.modInverse(p);



		// save to keypair

		var privkey = {};
		var pubkey = {};
		pubkey.n = n;
		pubkey.e = e;
		privkey.n = pubkey.n;
		privkey.e = pubkey.e;
		privkey.d = d;
		privkey.p = p;
		privkey.q = q;
		privkey.dmp1 = dmp1;
		privkey.dmq1 = dmq1;
		privkey.iqmp = iqmp;

		this.publicKey = pubkey;
		this.privateKey = privkey;

		this.hasPubKey = true;
		this.hasPrivKey = true;

		if (BigInt.is(this.publicKey.n)) {
			this.blockLength = (this.publicKey.n.bitLength() + 7) >>> 3;
			this.bitLength = this.publicKey.n.bitLength();
		}

		// for function chaining
		return this;
	}

	generateKeypairExt(options = {})
	{
		var bits = 'bits' in options ? options.bits : 2048;
		var exponent = 'exponent' in options ? options.exponent : 0x10001;
		var certainty = 'certainty' in options ? options.certainty : 10;
		var hash_algo = 'hashAlgo' in options ? options.hashAlgo : null;
		var seed = 'seed' in options ? Buffer.from(options.seed, 'latin1') : null;

		if (!bits) {
			throw jCastle.exception("PARAMS_NOT_SET", 'RSA011');
		}

		if (bits % 8) {
			throw jCastle.exception("INVALID_BIT_LENGTH", 'RSA012');
		}

		var rng = new jCastle.prng(seed, hash_algo);
		var qBits = bits >>> 1;
		var pBits = bits - qBits;
		var min_diff_bits = parseInt(bits / 3);
		var bi_e, n, e, d, p, q, dmp1, dmq1, iqmp, p1, q1, phi;

		if (typeof exponent == 'number' && exponent % 1 == 0) {
			e = exponent;
			bi_e = BigInt(exponent);
		} else {
			bi_e = jCastle.util.toBigInt(exponent);
			e = parseInt(bi_e.toString(16), 16);
		}
		for(;;) {
			p = BigInt.probablePrime(pBits, rng, certainty);
			
			if (p.bitLength() != pBits) continue;
			if(p.subtract(1n).gcd(bi_e).isOne()) break;
		}

		for (;;) {
			// generate q and check min_diff_bits
			for (;;) {
				q = BigInt.probablePrime(qBits ,rng, certainty);
				if (q.bitLength() != qBits) continue;

				// consider safe primes for p and q
				if (p.subtract(q).abs().bitLength() < min_diff_bits) continue;

				if(q.subtract(1n).gcd(bi_e).isOne()) break;
			}

			// calculate the modulus
			n = p.multiply(q);

			if (n.bitLength() != bits) continue;

			if(p.compareTo(q) < 0) {
				var t = p;
				p = q;
				q = t;
			}

			p1 = p.subtract(1n);
			q1 = q.subtract(1n);
			phi = p1.multiply(q1);

			if(phi.gcd(bi_e).isOne()) break;
		}

		d = bi_e.modInverse(phi);
		dmp1 = d.mod(p1);
		dmq1 = d.mod(q1);
		iqmp = q.modInverse(p);

		// save to keypair

		var privkey = {};
		var pubkey = {};
		pubkey.n = n;
		pubkey.e = e;
		privkey.n = pubkey.n;
		privkey.e = pubkey.e;
		privkey.d = d;
		privkey.p = p;
		privkey.q = q;
		privkey.dmp1 = dmp1;
		privkey.dmq1 = dmq1;
		privkey.iqmp = iqmp;

		this.publicKey = pubkey;
		this.privateKey = privkey;

		this.hasPubKey = true;
		this.hasPrivKey = true;

		if (BigInt.is(this.publicKey.n)) {
			this.blockLength = (this.publicKey.n.bitLength() + 7) >>> 3;
			this.bitLength = this.publicKey.n.bitLength();
		}

		// for function chaining
		return this;
	}

/*
https://tools.ietf.org/html/rfc3447#section-8.1


5.2.1 RSASP1

   RSASP1 (K, m)

   Input:
   K        RSA private key, where K has one of the following forms:
            - a pair (n, d)
            - a quintuple (p, q, dP, dQ, qInv) and a (possibly empty)
              sequence of triplets (r_i, d_i, t_i), i = 3, ..., u
   m        message representative, an integer between 0 and n - 1

   Output:
   s        signature representative, an integer between 0 and n - 1

   Error: "message representative out of range"

   Assumption: RSA private key K is valid

   Steps:

   1. If the message representative m is not between 0 and n - 1,
      output "message representative out of range" and stop.

   2. The signature representative s is computed as follows.

      a. If the first form (n, d) of K is used, let s = m^d mod n.

      b. If the second form (p, q, dP, dQ, qInv) and (r_i, d_i, t_i)
         of K is used, proceed as follows:

         i.    Let s_1 = m^dP mod p and s_2 = m^dQ mod q.

         ii.   If u > 2, let s_i = m^(d_i) mod r_i, i = 3, ..., u.

         iii.  Let h = (s_1 - s_2) * qInv mod p.

         iv.   Let s = s_2 + q * h.

         v.    If u > 2, let R = r_1 and for i = 3 to u do

                  1. Let R = R * r_(i-1).

                  2. Let h = (s_i - s) * t_i mod r_i.

                  3. Let s = s + R * h.

   3. Output s.

   Note.  Step 2.b can be rewritten as a single loop, provided that one
   reverses the order of p and q.  For consistency with PKCS #1 v2.0,
   however, the first two primes p and q are treated separately from the
   additional primes.

   ----------------------------------------------------------------------------

   RSASSA-PKCS1-V1_5-SIGN (K, M)

   Input:
   K        signer's RSA private key
   M        message to be signed, an octet string

   Output:
   S        signature, an octet string of length k, where k is the
            length in octets of the RSA modulus n

   Errors: "message too long"; "RSA modulus too short"

   Steps:

   1. EMSA-PKCS1-v1_5 encoding: Apply the EMSA-PKCS1-v1_5 encoding
      operation (Section 9.2) to the message M to produce an encoded
      message EM of length k octets:

         EM = EMSA-PKCS1-V1_5-ENCODE (M, k).

      If the encoding operation outputs "message too long," output
      "message too long" and stop.  If the encoding operation outputs
      "intended encoded message length too short," output "RSA modulus
      too short" and stop.

   2. RSA signature:

      a. Convert the encoded message EM to an integer message
         representative m (see Section 4.2):

            m = OS2IP (EM).

      b. Apply the RSASP1 signature primitive (Section 5.2.1) to the RSA
         private key K and the message representative m to produce an
         integer signature representative s:

            s = RSASP1 (K, m).

      c. Convert the signature representative s to a signature S of
         length k octets (see Section 4.1):

            S = I2OSP (s, k).

   3. Output the signature S.
*/
/*
http://www.di-mgt.com.au/rsa_alg.html#pkcs1schemes

Algorithm: Signing using PKCS#1v1.5 
INPUT: Sender's RSA private key, (n, d) of length k = |n| bytes; 
       message, M, to be signed; message digest algorithm, Hash.
OUTPUT: Signed data block of length k bytes

    1. Compute the message digest H of the message,

    H = Hash(M)

    2. Form the byte string, T, from the message digest, H, 
	   according to the message digest algorithm, Hash, as follows:

    Hash	T
    MD5		30 20 30 0c 06 08 2a 86 48 86 f7 0d 02 05 05 00 04 10 || H
    SHA-1	30 21 30 09 06 05 2b 0e 03 02 1a 05 00 04 14 || H
    SHA-224	30 2d 30 0d 06 09 60 86 48 01 65 03 04 02 04 05 00 04 1c || H
    SHA-256	30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20 || H
    SHA-384	30 41 30 0d 06 09 60 86 48 01 65 03 04 02 02 05 00 04 30 || H
    SHA-512	30 51 30 0d 06 09 60 86 48 01 65 03 04 02 03 05 00 04 40 || H

    where T is an ASN.1 value of type DigestInfo encoded 
	using the Distinguished Encoding Rules (DER).
    
	3. Form the k-byte encoded message block, EB,

    EB = 00 || 01 || PS || 00 || T

    where || denotes concatenation and PS is a string of bytes all of value
	0xFF of such length so that |EB|=k.
    
	4. Convert the byte string, EB, to an integer m, most significant byte first,

    m = StringToInteger(EB)

    5. Sign with the RSA algorithm

    s = m^d mod n

    6. Convert the resulting signature value, s, to a k-byte output block, OB

    OB = IntegerToString(s, k)

    7. Output OB.

*/
	/**
	 * gets a signature of the message.
	 * 
	 * @public
	 * @param {buffer} str buffer or string to be signed
	 * @param {object} options options object.
	 *                 {string} hashAlgo hash algorithm name. (default: 'sha-1')
	 * @returns the signature in return type.
	 */
	sign(str, options = {})
	{
		var hash_algo = 'hashAlgo' in options ? options.hashAlgo : 'sha-1';
		var ba;

		if (!this.hasPrivKey) throw jCastle.exception("PRIVKEY_NOT_SET", 'RSA013');

		if (Buffer.isBuffer(str)) ba = str;
		else ba = Buffer.from(str, 'latin1');

		var em = jCastle.pki.rsa.padding.create('emsa-pkcs1-v1_5').pad(ba, this.getBitLength(), hash_algo);
		//var em_i = BigInt(em);
		var em_i = BigInt.fromBufferUnsigned(em);
		var s_i = this._privateCrypt(em_i);
		var s = s_i.toBuffer();

		if (s.length < this.blockLength) 
			s = Buffer.concat([Buffer.alloc(this.blockLength - s.length, 0x00), s]);
		if (s.length > this.blockLength)
			s = Buffer.slice(s, s.length - this.blockLength);

		if ('encoding' in options)
			s = s.toString(options.encoding);

		return s;
	}

/*
https://tools.ietf.org/html/rfc3447#section-8.1

5.2.2 RSAVP1

   RSAVP1 ((n, e), s)

   Input:
   (n, e)   RSA public key
   s        signature representative, an integer between 0 and n - 1

   Output:
   m        message representative, an integer between 0 and n - 1

   Error: "signature representative out of range"

   Assumption: RSA public key (n, e) is valid

   Steps:

   1. If the signature representative s is not between 0 and n - 1,
      output "signature representative out of range" and stop.

   2. Let m = s^e mod n.

   3. Output m.

   --------------------------------------------------------------------------

   RSASSA-PKCS1-V1_5-VERIFY ((n, e), M, S)

   Input:
   (n, e)   signer's RSA public key
   M        message whose signature is to be verified, an octet string
   S        signature to be verified, an octet string of length k, where
            k is the length in octets of the RSA modulus n

   Output:
   "valid signature" or "invalid signature"

   Errors: "message too long"; "RSA modulus too short"

   Steps:

   1. Length checking: If the length of the signature S is not k octets,
      output "invalid signature" and stop.

   2. RSA verification:

      a. Convert the signature S to an integer signature representative
         s (see Section 4.2):

            s = OS2IP (S).

      b. Apply the RSAVP1 verification primitive (Section 5.2.2) to the
         RSA public key (n, e) and the signature representative s to
         produce an integer message representative m:

            m = RSAVP1 ((n, e), s).

         If RSAVP1 outputs "signature representative out of range,"
         output "invalid signature" and stop.

      c. Convert the message representative m to an encoded message EM
         of length k octets (see Section 4.1):

            EM' = I2OSP (m, k).

         If I2OSP outputs "integer too large," output "invalid
         signature" and stop.

   3. EMSA-PKCS1-v1_5 encoding: Apply the EMSA-PKCS1-v1_5 encoding
      operation (Section 9.2) to the message M to produce a second
      encoded message EM' of length k octets:

            EM' = EMSA-PKCS1-V1_5-ENCODE (M, k).

      If the encoding operation outputs "message too long," output
      "message too long" and stop.  If the encoding operation outputs
      "intended encoded message length too short," output "RSA modulus
      too short" and stop.

   4. Compare the encoded message EM and the second encoded message EM'.
      If they are the same, output "valid signature"; otherwise, output
      "invalid signature."

   Note.  Another way to implement the signature verification operation
   is to apply a "decoding" operation (not specified in this document)
   to the encoded message to recover the underlying hash value, and then
   to compare it to a newly computed hash value.  This has the advantage
   that it requires less intermediate storage (two hash values rather
   than two encoded messages), but the disadvantage that it requires
   additional code.
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
		var hash_algo = 'hashAlgo' in options ? options.hashAlgo : 'sha-1';
		var ba, s_i;

		if (!this.hasPubKey) throw jCastle.exception("PUBKEY_NOT_SET", 'RSA014');

		if (Buffer.isBuffer(str)) ba = str;
		else ba = Buffer.from(str, 'latin1');

		if (!Buffer.isBuffer(signature)) {
			if (/^[0-9A-f]+$/i.test(signature)) 
				s_i = BigInt.fromBufferUnsigned(Buffer.from(signature, 'hex'));
			else 
				s_i = BigInt.fromBufferUnsigned(Buffer.from(signature, 'latin1'));
		} else {
			s_i = BigInt.fromBufferUnsigned(signature);
		}

		var v_i = this._publicCrypt(s_i);
		var em = jCastle.pki.rsa.padding.create('emsa-pkcs1-v1_5').pad(ba, this.getBitLength(), hash_algo);
		var em_i = BigInt.fromBufferUnsigned(em);

		return v_i.equals(em_i);
	}

/*
https://www.ietf.org/rfc/rfc4055.txt

3.  RSASSA-PSS Signature Algorithm

   This section describes the conventions for using the RSASSA-PSS
   signature algorithm with the Internet X.509 Certificate and CRL
   profile [PROFILE].  The RSASSA-PSS signature algorithm is specified
   in PKCS #1 version 2.1 [P1v2.1].  The five one-way hash functions
   discussed in Section 2.1 and the one mask generation function
   discussed in Section 2.2 can be used with RSASSA-PSS.

   CAs that issue certificates with the id-RSASSA-PSS algorithm
   identifier SHOULD require the presence of parameters in the
   publicKeyAlgorithms field if the cA boolean flag is set in the basic
   constraints certificate extension.  CAs MAY require that the
   parameters be present in the publicKeyAlgorithms field for end-entity
   certificates.

   CAs that use the RSASSA-PSS algorithm for signing certificates SHOULD
   include RSASSA-PSS-params in the subjectPublicKeyInfo algorithm
   parameters in their own certificates.  CAs that use the RSASSA-PSS
   algorithm for signing certificates or CRLs MUST include RSASSA-PSS-
   params in the signatureAlgorithm parameters in the TBSCertificate or
   TBSCertList structures.

   Entities that validate RSASSA-PSS signatures MUST support SHA-1.
   They MAY also support any other one-way hash functions in Section
   2.1.

   The data to be signed (e.g., the one-way hash function output value)
   is formatted for the signature algorithm to be used.  Then, a private
   key operation (e.g., RSA decryption) is performed to generate the
   signature value.  This signature value is then ASN.1 encoded as a BIT
   STRING and included in the Certificate or CertificateList in the
   signatureValue field.  Section 3.2 specifies the format of RSASSA-PSS
   signature values.

3.1.  RSASSA-PSS Public Keys

   When RSASSA-PSS is used in an AlgorithmIdentifier, the parameters
   MUST employ the RSASSA-PSS-params syntax.  The parameters may be
   either absent or present when used as subject public key information.
   The parameters MUST be present when used in the algorithm identifier
   associated with a signature value.

   When signing, it is RECOMMENDED that the parameters, except for
   possibly saltLength, remain fixed for all usages of a given RSA key
   pair.

	  id-RSASSA-PSS  OBJECT IDENTIFIER  ::=  { pkcs-1 10 }

	  RSASSA-PSS-params  ::=  SEQUENCE  {
		 hashAlgorithm      [0] HashAlgorithm DEFAULT
								   sha1Identifier,
		 maskGenAlgorithm   [1] MaskGenAlgorithm DEFAULT
								   mgf1SHA1Identifier,
		 saltLength         [2] INTEGER DEFAULT 20,
		 trailerField       [3] INTEGER DEFAULT 1  }

   The fields of type RSASSA-PSS-params have the following meanings:

	  hashAlgorithm

		 The hashAlgorithm field identifies the hash function.  It MUST
		 be one of the algorithm identifiers listed in Section 2.1, and
		 the default hash function is SHA-1.  Implementations MUST
		 support SHA-1 and MAY support any of the other one-way hash
		 functions listed in Section 2.1.  Implementations that perform
		 signature generation MUST omit the hashAlgorithm field when
		 SHA-1 is used, indicating that the default algorithm was used.
		 Implementations that perform signature validation MUST
		 recognize both the sha1Identifier algorithm identifier and an
		 absent hashAlgorithm field as an indication that SHA-1 was
		 used.

	  maskGenAlgorithm

		 The maskGenAlgorithm field identifies the mask generation
		 function.  The default mask generation function is MGF1 with
		 SHA-1.  For MGF1, it is strongly RECOMMENDED that the
		 underlying hash function be the same as the one identified by
		 hashAlgorithm.  Implementations MUST support MGF1.  MGF1
		 requires a one-way hash function that is identified in the
		 parameters field of the MGF1 algorithm identifier.
		 Implementations MUST support SHA-1 and MAY support any of the
		 other one-way hash functions listed in section Section 2.1.
		 The MGF1 algorithm identifier is comprised of the id-mgf1
		 object identifier and a parameter that contains the algorithm
		 identifier of the one-way hash function employed with MGF1.
		 The SHA-1 algorithm identifier is comprised of the id-sha1
		 object identifier and an (optional) parameter of NULL.
		 Implementations that perform signature generation MUST omit the
		 maskGenAlgorithm field when MGF1 with SHA-1 is used, indicating
		 that the default algorithm was used.

		 Although mfg1SHA1Identifier is defined as the default value for
		 this field, implementations MUST accept both the default value
		 encoding (i.e., an absent field) and mfg1SHA1Identifier to be
		 explicitly present in the encoding.

	  saltLength

		 The saltLength field is the octet length of the salt.  For a
		 given hashAlgorithm, the recommended value of saltLength is the
		 number of octets in the hash value.  Unlike the other fields of
		 type RSASSA-PSS-params, saltLength does not need to be fixed
		 for a given RSA key pair; a different value could be used for
		 each RSASSA-PSS signature generated.

	  trailerField

		 The trailerField field is an integer.  It provides
		 compatibility with IEEE Std 1363a-2004 [P1363A].  The value
		 MUST be 1, which represents the trailer field with hexadecimal
		 value 0xBC.  Other trailer fields, including the trailer field
		 composed of HashID concatenated with 0xCC that is specified in
		 IEEE Std 1363a, are not supported.  Implementations that
		 perform signature generation MUST omit the trailerField field,
		 indicating that the default trailer field value was used.
		 Implementations that perform signature validation MUST
		 recognize both a present trailerField field with value 1 and an
		 absent trailerField field.

   If the default values of the hashAlgorithm, maskGenAlgorithm, and
   trailerField fields of RSASSA-PSS-params are used, then the algorithm
   identifier will have the following value:

	  rSASSA-PSS-Default-Identifier  AlgorithmIdentifier  ::=  {
						   id-RSASSA-PSS, rSASSA-PSS-Default-Params }

	  rSASSA-PSS-Default-Params RSASSA-PSS-Params ::= {
						   sha1Identifier, mgf1SHA1Identifier, 20, 1}

3.2.  RSASSA-PSS Signature Values

   The output of the RSASSA-PSS signature algorithm is an octet string,
   which has the same length in octets as the RSA modulus n.

   Signature values in CMS [CMS] are represented as octet strings, and
   the output is used directly.  However, signature values in
   certificates and CRLs [PROFILE] are represented as bit strings, and
   conversion is needed.

   To convert a signature value to a bit string, the most significant
   bit of the first octet of the signature value SHALL become the first
   bit of the bit string, and so on through the least significant bit of
   the last octet of the signature value, which SHALL become the last
   bit of the bit string.

3.3.  RSASSA-PSS Signature Parameter Validation

   Three possible parameter validation scenarios exist for RSASSA-PSS
   signature values.

   1.  The key is identified by the rsaEncryption algorithm identifier.
	   In this case no parameter validation is needed.

   2.  The key is identified by the id-RSASSA-PSS signature algorithm
	   identifier, but the parameters field is absent.  In this case no
	   parameter validation is needed.

   3.  The key is identified by the id-RSASSA-PSS signature algorithm
	   identifier and the parameters are present.  In this case all
	   parameters in the signature structure algorithm identifier MUST
	   match the parameters in the key structure algorithm identifier
	   except the saltLength field.  The saltLength field in the
	   signature parameters MUST be greater or equal to that in the key
	   parameters field.
*/
/*
   RSASSA-PSS-SIGN (K, M)

   Input:
   K        signer's RSA private key
   M        message to be signed, an octet string

   Output:
   S        signature, an octet string of length k, where k is the
            length in octets of the RSA modulus n

   Errors: "message too long;" "encoding error"

   Steps:

   1. EMSA-PSS encoding: Apply the EMSA-PSS encoding operation (Section
      9.1.1) to the message M to produce an encoded message EM of length
      \ceil ((modBits - 1)/8) octets such that the bit length of the
      integer OS2IP (EM) (see Section 4.2) is at most modBits - 1, where
      modBits is the length in bits of the RSA modulus n:

         EM = EMSA-PSS-ENCODE (M, modBits - 1).

      Note that the octet length of EM will be one less than k if
      modBits - 1 is divisible by 8 and equal to k otherwise.  If the
      encoding operation outputs "message too long," output "message too
      long" and stop.  If the encoding operation outputs "encoding
      error," output "encoding error" and stop.

   2. RSA signature:

      a. Convert the encoded message EM to an integer message
         representative m (see Section 4.2):

            m = OS2IP (EM).

      b. Apply the RSASP1 signature primitive (Section 5.2.1) to the RSA
         private key K and the message representative m to produce an
         integer signature representative s:

            s = RSASP1 (K, m).

      c. Convert the signature representative s to a signature S of
         length k octets (see Section 4.1):

            S = I2OSP (s, k).

   3. Output the signature S.
*/

/*
salt_len: salt byte length option from 0 to (keyByteLen - hashByteLen - 2).
There are two special values:

	-1: sets the salt length to the digest length
	-2: sets the salt length to maximum permissible value
	(i.e. keybytelen - hashbytelen - 2)

	DEFAULT is -1. (NOTE: OpenSSL's default is -2.)
*/
	/**
	 * gets a PSS signature of the message.
	 * 
	 * @public
	 * @param {buffer} str buffer or string to be signed
	 * @param {object} options options object.
	 *                 {string} hashAlgo hash algorithm name. (default: 'sha-1')
	 *                 {buffer} salt salt value
	 *                 {number} saltLength salt length.
	 * @returns the PSS signature in return type.
	 */
	pssSign(str, options = {})
	{
		var hash_algo = 'hashAlgo' in options ? options.hashAlgo : 'sha-1';
		var salt = 'salt' in options ? options.salt : null;
		var salt_len = 'saltLength' in options ? options.saltLength : -1;
		var ba, bi, M;

		if (!this.hasPrivKey) throw jCastle.exception("PRIVKEY_NOT_SET", 'RSA015');

		if (Buffer.isBuffer(str)) M = str;
		else M = Buffer.from(str, 'latin1');

		//if (salt && !Buffer.isBuffer(salt)) salt = Buffer.from(salt, 'latin1');
		if (salt) {
			if (!Buffer.isBuffer(salt)) {
				if (/^[0-9A-F]+$/i.test(salt)) salt = Buffer.from(salt, 'hex');
				else salt = Buffer.from(salt, 'latin1');
			}
		}

		var counter = 0;

		for (;;) {
			if (salt && counter) {
				throw  jCastle.exception("INVALID_SALT", 'RSA020');
			}

			ba = jCastle.pki.rsa.padding.create('emsa-pss_mgf1').pad(M, this.getBitLength(), hash_algo, salt_len, salt);
			bi = BigInt.fromBufferUnsigned(ba);

			if (salt) counter++;

			//
			// bi should be smaller than privateKey.n
			//
			if (bi.compareTo(this.privateKey.n) < 0) break;
		}

		// console.log('ba: ', ba.toString('hex'));

		var sig_bi = this._privateCrypt(bi);
		var sig = sig_bi.toBuffer();
		// var embits = this.bitLength - 1;
		// var bl = (embits + 7) >>> 3;

		if (sig.length < this.blockLength) 
			sig = Buffer.concat([Buffer.alloc(this.blockLength - sig.length, 0x00), sig]);
		if (sig.length > this.blockLength)
			sig = Buffer.slice(sig, sig.length - this.blockLength);

		if ('encoding' in options)
			sig = sig.toString(options.encoding);

		return sig;
	}

/*
   RSASSA-PSS-VERIFY ((n, e), M, S)

   Input:
   (n, e)   signer's RSA public key
   M        message whose signature is to be verified, an octet string
   S        signature to be verified, an octet string of length k, where
            k is the length in octets of the RSA modulus n

   Output:
   "valid signature" or "invalid signature"

   Steps:

   1. Length checking: If the length of the signature S is not k octets,
      output "invalid signature" and stop.

   2. RSA verification:

      a. Convert the signature S to an integer signature representative
         s (see Section 4.2):

            s = OS2IP (S).

      b. Apply the RSAVP1 verification primitive (Section 5.2.2) to the
         RSA public key (n, e) and the signature representative s to
         produce an integer message representative m:

            m = RSAVP1 ((n, e), s).

         If RSAVP1 output "signature representative out of range,"
         output "invalid signature" and stop.

      c. Convert the message representative m to an encoded message EM
         of length emLen = \ceil ((modBits - 1)/8) octets, where modBits
         is the length in bits of the RSA modulus n (see Section 4.1):

            EM = I2OSP (m, emLen).

         Note that emLen will be one less than k if modBits - 1 is
         divisible by 8 and equal to k otherwise.  If I2OSP outputs
         "integer too large," output "invalid signature" and stop.

   3. EMSA-PSS verification: Apply the EMSA-PSS verification operation
      (Section 9.1.2) to the message M and the encoded message EM to
      determine whether they are consistent:

         Result = EMSA-PSS-VERIFY (M, EM, modBits - 1).

   4. If Result = "consistent," output "valid signature." Otherwise,
      output "invalid signature."
*/
/*
salt_len: salt byte length option from 0 to (keyByteLen - hashByteLen - 2).
There are two special values:

	-1: sets the salt length to the digest length
	-2: sets the salt length to maximum permissible value
	(i.e. keybytelen - hashbytelen - 2)

	DEFAULT is -1. (NOTE: OpenSSL's default is -2.)
*/
	/**
	 * checks if the PSS signature is right.
	 * 
	 * @public
	 * @param {buffer} str buffer or string to be signed
	 * @param {mixed} signature signature value.
	 * @param {object} options options object.
	 *                 {string} hashAlgo hash algorithm name. (default: 'sha-1')
	 *                 {number} saltLength salt length.
	 * @returns true if the PSS signature is right.
	 */
	pssVerify(str, signature, options = {})
	{
		var hash_algo = 'hashAlgo' in options ? options.hashAlgo : 'sha-1';
		var salt_len = 'saltLength' in options ? options.saltLength : -1;
		var ba, s_i, bi_ba;
		//var bits = this.blockLength * 8;
		var bits = this.getBitLength();

		if (!this.hasPubKey) throw jCastle.exception("PUBKEY_NOT_SET", 'RSA016');

		if (Buffer.isBuffer(str)) ba = str;
		else ba = Buffer.from(str, 'latin1');

		if (!Buffer.isBuffer(signature)) {
			if (/^[0-9A-f]+$/i.test(signature)) 
				s_i = BigInt.fromBufferUnsigned(Buffer.from(signature, 'hex'));
			else 
				s_i = BigInt.fromBufferUnsigned(Buffer.from(signature, 'latin1'));
		} else {
			s_i = BigInt.fromBufferUnsigned(signature);
		}
		
		if (s_i.bitLength() > bits) {
			console.log('s_i.bitLength greater than bits');
			return false;
		}

		bi_ba = this._publicCrypt(s_i);

		var em = bi_ba.toBuffer();

		// console.log('em: ', em.toString('hex'));
		var res = jCastle.pki.rsa.padding.create('emsa-pss_mgf1').verify(ba, this.getBitLength(), em, hash_algo, salt_len);
		return res;
	}

/*
http://www.di-mgt.com.au/rsa_alg.html#pkcs1schemes

ANSI standard X9.31 [AX931] requires using strong primes derived in a way 
to avoid particular attacks that are probably no longer relevant.
X9.31 uses a method of encoding the message digest specific to the hash algorithm.
It expects a key with length an exact multiple of 256 bits.
The same algorithm is also specified in P1363 [P1363] where it is called IFSP-RSA2.
The scheme allows for the public exponent to be an even value, 
but we do not consider that case here; all our values of e are assumed to be odd.
The message digest hash, H, is encapsulated to form a byte string as follows

EB = 06 || PS || 0xBA || H || 0x33 || 0xCC

where PS is a string of bytes all of value 0xBB of length such that |EB|=|n|,
and 0x33 is the ISO/IEC 10118 part number† for SHA-1. 
The byte string, EB, is converted to an integer value, the message representative, f.

ISO/IEC 10118 part numbers for other hash functions are:
SHA-1=0x33, SHA-256=0x34, SHA-384=0x36, SHA-512=0x35, RIPEMD=0x31. 
*/
	/**
	 * gets a ANSI standard X9.31 signature of the message.
	 * 
	 * @public
	 * @param {buffer} str buffer or string to be signed
	 * @param {object} options options object.
	 *                 {string} hashAlgo hash algorithm name. (default: 'sha-1')
	 *                 {buffer} salt salt value
	 *                 {number} saltLength salt length.
	 * @returns the signature in return type.
	 */
	ansiX931Sign(str, options = {})
	{
		// N = Modulus Length (in bytes) = 256, where modulus is 2048-bits (length of private key)
		// M = Message
		// k = Hash Output = Digest = Hash(M)
		// z = Len(k) (in bytes) = 32, where using Hash = SHA-256
		// p = number of fixed padding bytes, in this case 4 (6b, ba, 34, and cc)
		// 
		// Padded Hash = 6b [bb]*x ba [k] 34 cc, where x = 220 (N - z - 4 = 256 - 32 - 4 = 220)
		// [6b bb bb ... bb ba] [Hash(M)] [hashID=34] [cc]
		// 
		// See: 
		// http://www.drdobbs.com/rsa-digital-signatures/184404605?pgno=6
		// http://books.google.com/books?id=7gBn_gEBQesC&lpg=PA388&dq=x9.31%20padding&pg=PA386#v=onepage&q=x9.31%20padding&f=false

		var hash_algo = 'hashAlgo' in options ? options.hashAlgo : 'sha-1';
		var ba;

		if (!this.hasPrivKey) throw jCastle.exception("PRIVKEY_NOT_SET", 'RSA017');

		if (Buffer.isBuffer(str)) ba = str;
		else ba = Buffer.from(str, 'latin1');

		var pad_ba = jCastle.pki.rsa.padding.create('ansi_x931').pad(ba, this.getBitLength(), hash_algo);
		var sign_bi = this._privateCrypt(BigInt.fromBufferUnsigned(pad_ba));
		var sig = sign_bi.toBuffer();

		if (sig.length < this.blockLength)
			sig = Buffer.concat([Buffer.alloc(this.blockLength - sig.length, 0x00), sig]);
		if (sig.length > this.blockLength)
			sig = Buffer.slice(sig, sig.length - this.blockLength);

		if ('encoding' in options)
			sig = sig.toString(options.encoding);

		return sig;
	}

	/**
	 * checks if the ANSI standard X9.31 signature is right.
	 * 
	 * @public
	 * @param {buffer} str buffer or string to be signed
	 * @param {mixed} signature signature value.
	 * @param {object} options options object.
	 *                 {string} hashAlgo hash algorithm name. (default: 'sha-1')
	 *                 {number} saltLength salt length.
	 * @returns true if the signature is right.
	 */
	ansiX931Verify(str, signature, options = {})
	{
		//var hash_algo = 'hashAlgo' in options ? options.hashAlgo : 'sha-1';
		var ba, s_i;
		var bits = this.blockLength * 8;

		if (!this.hasPubKey) throw jCastle.exception("PUBKEY_NOT_SET", 'RSA019');

		if (Buffer.isBuffer(str)) ba = str;
		else ba = Buffer.from(str, 'latin1');

		if (!Buffer.isBuffer(signature)) {
			if (/^[0-9A-f]+$/i.test(signature)) 
				s_i = BigInt.fromBufferUnsigned(Buffer.from(signature, 'hex'));
			else 
				s_i = BigInt.fromBufferUnsigned(Buffer.from(signature, 'latin1'));
		} else {
			s_i = BigInt.fromBufferUnsigned(signature);
		}

		if (s_i.bitLength() > bits) {
			return false;
		}

		var bi_em = this._publicCrypt(s_i);
		var em = bi_em.toBuffer();
		var res = jCastle.pki.rsa.padding.create('ansi_x931').verify(ba, this.getBitLength(), em);

		return res;
	}
};

jCastle.pki.rsa.create = function()
{
	return new jCastle.pki.rsa();
};

jCastle._pkiInfo['rsa'] = {
	pki_name: 'RSA',
	object_name: 'rsa',
	oid: "1.2.840.113549.1.1.1"
};

jCastle.pki.RSA = jCastle.pki.rsa;

module.exports = jCastle.pki.rsa;
