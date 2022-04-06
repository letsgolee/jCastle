/**
 * A Javascript implemenation of PKI - ECDSA
 * 
 * @author Jacob Lee
 *
 * Copyright (C) 2015-2022 Jacob Lee.
 */

var jCastle = require('./jCastle');
var BigInteger = require('./biginteger');
require('./util');
require('./lang/en');
require('./error');
require('./prng');
require('./ec');

// if (typeof jCastle.math.ec == 'undefined') {
// 	throw jCastle.exception("EC_REQUIRED", 'ECD001');
// }


jCastle.pki.ecdsa = class
{
	/**
	 * The Implementation of ECDSA
	 * 
	 * @constructor
	 */
    constructor()
    {
        this.pkiName = 'ECDSA';
        this.OID = "1.2.840.10045.2.1";
        this.blockLength = 0;
		this.bitLength = 0;
        this.hasPubKey = false;
        this.hasPrivKey = false;

        this.params = null;
        this.ecInfo = {};
        this.privateKey = null;
        this.publicKey = null;

		this._pkiClass = true;
		this.keyID = null;
    }

	/**
	 * resets internal variables.
	 * 
	 * @public
	 * @returns this class instance
	 */
	reset()
	{
		this.ecInfo = {};
		this.privateKey = null;
		this.publicKey = null;

		this.params = null;

		this.blockLength = 0;
		this.bitLength = 0;
		this.hasPubKey = false;
		this.hasPrivKey = false;
		this.keyID = null;

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
		var keyid;

		if (typeof y == 'undefined' && typeof x == 'object' && 'kty' in x && x.kty == 'EC') {
			var args = x;
			params = args.crv;
			x = BigInteger.fromByteArrayUnsigned(Buffer.from(args.d.replace(/[ \t\r\n]/g, ''), 'base64url'));
			y = Buffer.concat([
				Buffer.alloc(1, 0x04), 
				Buffer.from(args.x.replace(/[ \t\r\n]/g, ''), 'base64url'), 
				Buffer.from(args.y.replace(/[ \t\r\n]/g, ''), 'base64url')]);
			if ('kid' in args) keyid = args.kid;
		}

		if (params) this.setParameters(params);

		if (!this.params) {
			throw jCastle.exception("PARAMS_NOT_SET", 'ECD002');
		}

		this.privateKey = jCastle.util.toBigInteger(x);

		this.hasPrivKey = true;

		if (keyid) this.keyID = keyid;

		if (!y) {
			// Compute y as x * G.
			var xG = this.ecInfo.G.multiply(this.privateKey);
			y = xG;
		}
		
		this.setPublicKey(y);

		// if the curve type is characteristic-two-field, then bitLength should come from params.m.
		// therefore these values should be set in setParameters().
		// this.blockLength = (this.ecInfo.n.bitLength() + 7) >>> 3;
		// this.bitLength = this.ecInfo.n.bitLength();

		return this;
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
		var keyid;

		if (typeof params == 'undefined' && typeof y == 'object' && 'kty' in y && y.kty == 'EC') {
			var args = y;
			params = args.crv;
			y = Buffer.concat([
				Buffer.alloc(1, 0x04), 
				Buffer.from(args.x.replace(/[ \t\r\n]/g, ''), 'base64url'), 
				Buffer.from(args.y.replace(/[ \t\r\n]/g, ''), 'base64url')]);
			if ('kid' in args) keyid = args.kid;
		}

		if (params) {
			this.setParameters(params);
		}

		if (!this.params) {
			throw jCastle.exception("PARAMS_NOT_SET", 'ECD002');
		}

		var pubkey = null;

		if (y instanceof jCastle.math.ec.point.fp || y instanceof jCastle.math.ec.point.f2m) {
			pubkey = y;
		} else if (Buffer.isBuffer(y)) {
			pubkey = this.ecInfo.curve.decodePoint(y);
		} else {
			var encoding;
			if (/^[0-9A-F]+$/i.test(y)) encoding = 'hex';
			else encoding = 'latin1';
			pubkey = this.ecInfo.curve.decodePoint(Buffer.from(y, encoding));
		}

		if (!pubkey.validate()) {
			throw jCastle.exception("INVALID_PUBKEY", 'ECD003');
		}

		this.publicKey = pubkey;

		this.hasPubKey = true;

		if (keyid && !this.keyID) this.keyID = keyid;

		// if the curve type is characteristic-two-field, then bitLength should come from params.m.
		// therefore these values should be set in setParameters().
		// this.blockLength = (this.ecInfo.n.bitLength() + 7) >>> 3;
		// this.bitLength = this.ecInfo.n.bitLength();

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
					return this.publicKey.encodePoint().toString('hex');
				case 'buffer':
					return this.publicKey.encodePoint();
				case 'jwt':
					var jwk = {};
					jwk.kty = 'EC';
					if (this.keyID) jwk.kid = this.keyID;
					jwk.crv = this.params.curveName;
					jwk.x = Buffer.from(this.publicKey.getX().toBigInteger().toByteArray()).toString('base64url');
					jwk.y = Buffer.from(this.publicKey.getY().toBigInteger().toByteArray()).toString('base64url');
					return jwk;
					// return {
					// 	kty: 'EC',
					// 	crv: this.params.curveName,
					// 	x: Buffer.from(this.publicKey.getX().toBigInteger().toByteArray()).toString('base64url'),
					// 	y: Buffer.from(this.publicKey.getY().toBigInteger().toByteArray()).toString('base64url')
					// };
				case 'object':
				default:
					return this.publicKey.clone();
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
			if (format.toLowerCase() == 'jwt') return {
				kty: 'EC',
				crv: this.params.curveName,
				x: Buffer.from(this.publicKey.getX().toBigInteger().toByteArray()).toString('base64url'),
				y: Buffer.from(this.publicKey.getY().toBigInteger().toByteArray()).toString('base64url'),
				d: Buffer.from(this.privateKey.toByteArray()).toString('base64url')
			};

			return jCastle.util.formatBigInteger(this.privateKey, format);
		}

		return false;
	}

	/**
	 * gets publicKey information object.
	 * 
	 * @public
	 * @param {string} format publicKey format string
	 * @param {string} param_format parameters format string
	 * @returns publicKey information object in format.
	 */
	getPublicKeyInfo(format = 'buffer', param_format = 'hex')
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
	getPrivateKeyInfo(format = 'buffer', param_format = 'hex')
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

		var y;

		if (pubkey instanceof jCastle.math.ec.point.fp || pubkey instanceof jCastle.math.ec.point.f2m) {
			y = pubkey;
		} else {
			if (!Buffer.isBuffer(pubkey)) {
				if (/^[0-9A-F]+$/i.test(pubkey)) pubkey = Buffer.from(pubkey, 'hex');
				else pubkey = Buffer.from(pubkey, 'latin1');
			}
			y = this.ecInfo.curve.decodePoint(pubkey);
		}

		if (!y.validate()) {
			return false;
		}

		if (this.publicKey.equals(y)) return true;
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
	 * @param {mixed} params parameters object or curve name
	 * @returns this class instance.
	 */
	setParameters(params)
	{
		if (jCastle.util.isString(params)) {
			// setParameters('secp256r1');
			params = jCastle.pki.ecdsa.getParameters(params);
		} else {
			if (!('gx' in params) || !('gy' in params)) {
				if (!('g' in params)) {
					throw jCastle.exception("INVALID_PARAMS", 'ECD004'); // 'Cannot find any base point in parameters';
				}

				if (Buffer.isBuffer(params.g)) params.g = params.g.toString('hex');
				else if (!/^[0-9A-F]+$/i.test(params.g)) params.g = Buffer.from(params.g, 'latin1').toString('hex');

				var gt = params.g.substr(2);
				params.gx = gt.slice(0, gt.length / 2);
				params.gy = gt.slice(gt.length / 2);
			}

			var targets = ['p', 'a', 'b', 'gx', 'gy', 'n'];
			for (var i in targets) {
				if (Buffer.isBuffer(params[i])) params[i] = params[i].toString('hex');
				else if (params[i] instanceof BigInteger) params[i] = params[i].toString(16);
			}

			if (typeof params.h !== 'number') {
				params.h = parseInt(params.h, 16);
			}
		}

		if (!params) throw jCastle.exception("INVALID_PARAMS", 'ECD013');
		

		this.params = params;

		var p = new BigInteger(params.p, 16);
		var a = new BigInteger(params.a, 16);
		var b = new BigInteger(params.b, 16);
		var n = new BigInteger(params.n, 16);
		var h = new BigInteger(params.h);

		if (!this.ecInfo) this.ecInfo = {};

		this.ecInfo.n = n;
		this.ecInfo.h = h;
		this.ecInfo.type = params.type.toLowerCase();

		switch(params.type.toLowerCase()) {
			case "prime-field": // prime field
				var curve = new jCastle.math.ec.curve.fp(p, a, b, n, h);
				var G = new jCastle.math.ec.point.fp(
					curve,
					curve.fromBigInteger(new BigInteger(params.gx, 16)),
					curve.fromBigInteger(new BigInteger(params.gy, 16))
				);

				this.ecInfo.curve = curve;
				this.ecInfo.G = G;

				this.bitLength = p.bitLength();
				this.blockLength = (this.bitLength + 7) >>> 3;
				break;
			case "characteristic-two-field": // binary field - characteristic two curves
				//if (typeof jCastle.math.ec.curve.f2m == 'undefined') break;
				var curve = new jCastle.math.ec.curve.f2m(params.m, params.k1, params.k2, params.k3, a, b, n, h);
				var G = new jCastle.math.ec.point.f2m(
					curve,
					curve.fromBigInteger(new BigInteger(params.gx, 16)),
					curve.fromBigInteger(new BigInteger(params.gy, 16))
				);

				this.ecInfo.curve = curve;
				this.ecInfo.G = G;

				//this.bitLength = this.ecInfo.curve.getM();
				this.bitLength = params.m;
				this.blockLength = (this.bitLength + 7) >>> 3;
				break;
			default:
				throw jCastle.exception("UNSUPPORTED_EC_TYPE", 'ECD005');
		}

		return this;
	}

	/**
	 * gets the curve information data object.
	 * 
	 * @public
	 * @returns the curve information data object.
	 */
	getCurveInfo()
	{
		return this.ecInfo;
	}

	/**
	 * gets the ephemeral publicKey corresponding to the ephemeral privateKey.
	 * 
	 * @public
	 * @param {object} ephemeral_privkey ephemeral privateKey object or buffer
	 * @param {string} format format string
	 * @returns the ephemeral publicKey in format.
	 */
	getEphemeralPublicKey(ephemeral_privkey, format='object')
	{
		var ephepriv = jCastle.util.toBigInteger(ephemeral_privkey);
		//return Buffer.from(this.ecInfo.G.multiply(ephepriv).toByteArray());
		var ephepub = this.ecInfo.G.multiply(ephepriv);

		switch (format.toLowerCase()) {
			case 'hex':
				return ephepub.encodePoint().toString('hex');
			case 'buffer':
				return ephepub.encodePoint();
			case 'jwt':
				return {
					kty: 'EC',
					crv: this.params.curveName,
					x: Buffer.from(ephepub.getX().toBigInteger().toByteArray()).toString('base64url'),
					y: Buffer.from(ephepub.getY().toBigInteger().toByteArray()).toString('base64url')
				};
			case 'object':
			default:
				return ephepub.clone();
		}
	}

	/**
	 * import the encoded point onto the curve.
	 * 
	 * @public
	 * @param {mixed} mixed_point point value.
	 * @returns EC point.
	 */
	importPoint(mixed_point)
	{
		if (!this.ecInfo || !this.ecInfo.curve) throw jCastle.exception("CURVE_NOT_LOADED", 'ECD011');

		var curve = this.ecInfo.curve;
		var type = this.params.type.toLowerCase();
        var encoded_point;

		if (mixed_point instanceof jCastle.math.ec.point.fp || mixed_point instanceof jCastle.math.ec.point.f2m) {
			encoded_point = mixed_point;
		} else if (typeof mixed_point == 'object' && 'kty' in mixed_point && mixed_point.kty == 'EC') {
			encoded_point = Buffer.concat([Buffer.alloc(1, 0x04),
				Buffer.from(mixed_point.x, 'base64url'),
				Buffer.from(mixed_point.y, 'base64url')]);
		} else if (Buffer.isBuffer(mixed_point)) {
			encoded_point = mixed_point;
		} else if (/^[0-9A-F]+$/i.test(mixed_point)) {
			encoded_point = Buffer.from(mixed_point, 'hex');
		} else {
			encoded_point = Buffer.from(mixed_point, 'latin1');
		}

		var point;

		if ((type == 'prime-field' && encoded_point instanceof jCastle.math.ec.point.fp) ||
			(type == 'characteristic-two-field' && encoded_point instanceof jCastle.math.ec.point.f2m)) {
			point = encoded_point;
		} else {
			try {
				point = curve.decodePoint(encoded_point);
			} catch (e) {
				throw jCastle.exception("UNSUPPORTED_EC_TYPE", 'ECD012');
			}
		}

		return point;
	}

	/**
	 * gets ECDSA parameters.
	 * 
	 * @public
	 * @param {string} format parameters format string
	 * @returns parameters in format
	 */
	getParameters(format = 'object')
	{
		if (this.params.OID != null && format == 'curve') return this.params.name;
		return this.params;
	}

	/*

	The private key is a random integer d chosen from {1,…,n−1} (where n is the order of the subgroup).
	The public key is the point H=dG (where G is the base point of the subgroup).
	*/
	/**
	 * generates privateKey and publicKey.
	 * 
	 * @public
	 * @param {object} parameters parameters object. ECDSA parameters must be set if it is not given.
	 * @returns this class instance.
	 */
	generateKeypair(params)
	{
		if (typeof params == 'undefined' && (!this.params || !this.ecInfo)) {
			throw jCastle.exception("PARAMETERS_NOT_SET", 'ECD006');
		}

		if (typeof params != 'undefined') {
			this.setParameters(params);
		}

		var rng = new jCastle.prng();
		var x;
		var n1 = this.ecInfo.n.subtract(BigInteger.ONE);
		var certainty = 10;

		// x should be l < x < n-1,
		// however small x is not good.
//		do {
//			x = BigInteger.probablePrime(this.ecInfo.n.bitLength(), rng);
//			if (!x.isLucasLehmerPrime()) continue;
//			x = BigInteger.random(this.ecInfo.n.bitLength(), rng);
//		} while (x.compareTo(n1) >= 0 || x.compareTo(BigInteger.ONE) <= 0);

		// x is ok if it is not prime number.
		x = BigInteger.random(this.ecInfo.n.bitLength(), rng);
		x = x.mod(n1).add(BigInteger.ONE);

		this.privateKey = x; // private key
		this.hasPrivKey = true;

		// Compute y as x * G.
		var xG = this.ecInfo.G.multiply(x);
		this.publicKey = xG;
		this.hasPubKey = true;

		// if the curve type is characteristic-two-field, then bitLength should come from params.m.
		// therefore these values should be set in setParameters().
		// this.blockLength = (this.ecInfo.n.bitLength() + 7) >>> 3;
		// this.bitLength = this.ecInfo.n.bitLength();

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
	 * @param {BigInteger} q modulo q
	 * @returns the calculated BigInteger value.
	 */
	_calculateE(input, q)
    {
        var bits = input.length * 8;
        var qBits = q.bitLength();
        var z = BigInteger.fromByteArrayUnsigned(input);

        if (qBits > bits) return z;
        if (bits > qBits) {
            z = z.shiftRight(bits - qBits);
        }
        return z.mod(q);
    }

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
		var ba, res;

		if (!this.hasPrivKey) throw jCastle.exception("PRIVKEY_NOT_SET", 'ECD007');

        if (Buffer.isBuffer(str)) ba = str;
		else ba = Buffer.from(str, 'latin1');

		hash_algo = jCastle.digest.getValidAlgoName(hash_algo);
		if (!hash_algo || jCastle._algorithmInfo[hash_algo].oid == null) {
			throw jCastle.exception("UNSUPPORTED_HASHER", 'ECD008');
		}

		var hash = new jCastle.digest(hash_algo).digest(ba);
		// hash = hash.slice(0, this.ecInfo.n.bitLength() >>> 3);
		// var hash_bi = BigInteger.fromByteArrayUnsigned(hash);
		var hash_bi = this._calculateE(hash, this.ecInfo.n);

		if (random_k){
			if (!Buffer.isBuffer(random_k)) {
				if (/^[0-9A-F]+$/i.test(random_k)) random_k = Buffer.from(random_k, 'hex');
				else random_k = Buffer.from(random_k, 'latin1');
			}
		}

		// Generate a random number k, such that 0 < k < q.
		var rng = new jCastle.prng();
		var k, q, r, s;
		var zero = BigInteger.valueOf(0);
		var one = BigInteger.valueOf(1);
		var counter = 0;
		var n = this.ecInfo.n;

		for  (;;) {
			if (random_k) {
				if (counter) {
					throw  jCastle.exception("INVALID_SALT", 'DSA020');
				}
				k = BigInteger.fromByteArrayUnsigned(random_k);
			} else {
				do {
					k = BigInteger.random(n.bitLength(), rng);
				} while (k.compareTo(zero) <= 0 || k.compareTo(n.subtract(one)) >= 0);
			}

			q = this.ecInfo.G.multiply(k);

			r = q.getX().toBigInteger().mod(n);

			if (r.compareTo(zero) <= 0) continue;

			s = k.modInverse(n).multiply(hash_bi.add(this.privateKey.multiply(r))).mod(n);

			if (s.compareTo(zero) >= 0) break;

			counter++;
		}

		// r and s should be same length with blockLength
		var bl = this.blockLength;
		var r_ba = Buffer.from(r.toByteArray());
		var s_ba = Buffer.from(s.toByteArray());

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
		if (!this.hasPubKey) throw jCastle.exception("PUBKEY_NOT_SET", 'ECD009');

		var hash_algo = 'hashAlgo' in options ? options.hashAlgo : 'sha-1';
		var ba, r, s;

		if (Buffer.isBuffer(str)) ba = str;
		else ba = Buffer.from(str, 'latin1');

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
					// if (!jCastle.asn1.isSequence(sequence)) return false;
					// if (!jCastle.asn1.isSequence(sequence)) throw jCastle.exception("NOT_SEQUENCE", 'ECD020');
					if (!jCastle.asn1.isSequence(sequence)) throw Error('not sequence');
	
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

		var zero = BigInteger.valueOf(0);

		if (r.compareTo(zero) <= 0 || r.compareTo(this.ecInfo.n) >= 0 ||
			s.compareTo(zero) <= 0 || s.compareTo(this.ecInfo.n) >= 0
		) {
			return false;
		}
		
		hash_algo = jCastle.digest.getValidAlgoName(hash_algo);
		if (!hash_algo || jCastle._algorithmInfo[hash_algo].oid == null) {
			throw jCastle.exception("UNSUPPORTED_HASHER", 'ECD010');
		}

		var hash = new jCastle.digest(hash_algo).digest(ba);
		// hash = hash.slice(0, this.ecInfo.n.bitLength() >>> 3);
		// var hash_bi = BigInteger.fromByteArrayUnsigned(hash);
		var hash_bi = this._calculateE(hash, this.ecInfo.n);

		var w = s.modInverse(this.ecInfo.n);
		var u1 = hash_bi.multiply(w).mod(this.ecInfo.n);
		var u2 = r.multiply(w).mod(this.ecInfo.n);
		var point = jCastle.math.ec.implementShamirsTrick(this.ecInfo.G, u1, this.publicKey, u2);
		//var point = this.G.multiply(u1).add(this.publicKey.multiply(u2));
		var v = point.getX().toBigInteger().mod(this.ecInfo.n);

		return v.compareTo(r) === 0;
	}
}

/**
 * creates a new ECDSA pki object.
 * 
 * @public
 * @returns the new ECDSA pki object.
 */
jCastle.pki.ecdsa.create = function()
{
	return new jCastle.pki.ecdsa();
};

jCastle.pki.ECDSA = jCastle.pki.ecdsa;

jCastle._pkiInfo['ecdsa'] = {
	pki_name: 'ECDSA',
	object_name: 'ecdsa',
	oid: "1.2.840.10045.2.1"
};

module.exports = jCastle.pki.ecdsa;
