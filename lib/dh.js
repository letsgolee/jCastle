/**
 * A Javascript implemenation of KeyAgreement - DH(DiffieHellman)
 * 
 * @author Jacob Lee
 *
 * Copyright (C) 2015-2022 Jacob Lee. All rights reserved.
 */

var jCastle = require('./jCastle');
//var BigInteger = require('./biginteger');
require('./util');

require('./dsa');
require('./kcdsa');

// DiffieHellman key agreement
jCastle.dh = class
{
	/**
	 * An object for Diffie-Hellman Key Agreement
	 * 
	 * @param {object} algo pki object for DH
	 * @constructor
	 */
	constructor(algo)
	{
		this.algo = null;
		this.secret = null;

		if (algo) {
			if (algo instanceof jCastle.pki) this.algo = algo;
			else if (algo instanceof jCastle.pki.dsa || 
					 algo instanceof jCastle.pki.kcdsa || 
					 algo instanceof jCastle.pki.elGamal) {
				this.algo = jCastle.pki.create().init(algo);
			}
		}
	}

	/**
	 * resets internal variables.
	 * 
	 * @returns this class instance.
	 */
	reset()
	{
	//	this.algo = null;
		this.secret = null;

		return this;
	}

	/**
	 * initialize.
	 * 
	 * @public
	 * @param {object} algo pki object for DH
	 * @returns this class instance.
	 */
	init(algo)
	{
		if (algo instanceof jCastle.pki) this.algo = algo;
		else if (algo instanceof jCastle.pki.dsa || algo instanceof jCastle.kcdsa) {
			this.algo = jCastle.pki.create().init(algo);
		}

		return this;
	}

	/**
	 * get publicKey of the pki.
	 * 
	 * @public
	 * @param {string} format format string for publicKey
	 * @returns the publicKey of the set pki.
	 */
	getPublicKey(format)
	{
		if (!this.algo) {
			throw jCastle.exception("PKI_NOT_SET", 'DH001');
		}
		return this.algo.getPublicKey(format);
	}

	/**
	 * compute DH secret between two.
	 * 
	 * @public
	 * @param {object} other_pubkey other party's publicKey.
	 * @param {mixed} additional additional data for computing DH secret.
	 * @returns the buffer of DH secret value.
	 */
	computeSecret(other_pubkey, additional)
	{
		if (typeof other_pubkey == 'object' && 'kty' in other_pubkey && other_pubkey.kty == 'ElGamal') {
			var y = BigInteger.fromByteArrayUnsigned(Buffer.from(other_pubkey.y.replace(/[ \t\r\n]/g, ''), 'base64url'));
			return this.computeSecret(y, additional);
		}

		other_pubkey = jCastle.util.toBigInteger(other_pubkey);

		var privkey = this.algo.getPrivateKey('object');
		var params = this.algo.getParameters('object');

		this.secret = other_pubkey.modPow(privkey, params.p);

		if (additional) {
			additional = jCastle.util.toBigInteger(additional);
			this.secret = this.secret.modPow(additional, params.p);
		}

		var secret = Buffer.from(this.secret.toByteArray());

		return secret;
	}
};

/**
 * creates DH class instance.
 * 
 * @public
 * @param {object} pki object for DH.
 * @returns this class instance.
 */
jCastle.dh.create = function(algo)
{
	return new jCastle.dh(algo);
};

/**
 * creates a new class instance and initialize with the given pki.
 * 
 * @public
 * @param {object} pki pki object for DH
 * @returns this class instance.
 */
jCastle.dh.init = function(pki)
{
	return new jCastle.dh().init(pki);
};

jCastle.DH = jCastle.dh;

module.exports = jCastle.dh;
