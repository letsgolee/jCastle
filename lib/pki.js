/**
 * A Javascript implemenation of PKI (Public Key Infrastructure)
 * 
 * @author Jacob Lee
 *
 * Copyright (C) 2015-2022 Jacob Lee.
 */

var jCastle = require('./jCastle');
var BigInteger = require('./biginteger');
require('./util');


// require('./rsa');
// require('./rsa-padding');
// require('./dsa');
// require('./dsa-parameters');
// require('./ecdsa');
// require('./ec-parameters');

jCastle.pki = class
{
	/**
	 * An implemenation of PKI (Public Key Infrastructure)
	 * @param {mixed} pkey pki object or name
	 * @constructor
	 */
	constructor(pkey)
	{
		this.pkiName = '';
		this.OID = '';

		this.pkiObject = null;

		if (pkey) {
			this.init(pkey);
		}
	}

	/**
	 * initialize class instance with the given pki value.
	 * 
	 * @public
	 * @param {mixed} pkey pki object or name
	 * @returns this class instance.
	 */
	init(pkey)
	{
		var pki_name;

		if (jCastle.util.isString(pkey)) {
			pki_name = pkey.toLowerCase().trim();

			if (!(pki_name in jCastle._pkiInfo)) {
				throw jCastle.exception("UNSUPPORTED_PKI", 'PKI001');
			}

			this.pkiObject = new jCastle.pki[jCastle._pkiInfo[pki_name].object_name]();
		} else {
			if ('pkiName' in pkey && '_pkiClass' in pkey) {
				pki_name = pkey.pkiName.toLowerCase();

				if (!(pki_name in jCastle._pkiInfo)) {
					throw jCastle.exception("UNSUPPORTED_PKI", 'PKI002');
				}

				this.pkiObject = pkey;
			} else if ('pkiName' in pkey && 'pkiObject' in pkey) {
				if (pkey.pkiObject) this.pkiObject = pkey.pkiObject;
			} else if ('algo' in pkey && ('privateKey' in pkey || 'publicKey' in pkey)) {
				// privateKeyInfo or publicKeyInfo
				pki_name = pkey.algo.toLowerCase();

				if (!(pki_name in jCastle._pkiInfo)) {
					throw jCastle.exception("UNSUPPORTED_PKI", 'PKI004');
				}

				var keyInfo = pkey;

				this.pkiObject = new jCastle.pki[jCastle._pkiInfo[pki_name].object_name]();

				if (jCastle._pkiInfo[pki_name].pki_name == 'RSA') {
					if ('padding' in keyInfo) this.pkiObject.setPadding(keyInfo.padding);
				} else {
					if ('parameters' in keyInfo) this.pkiObject.setParameters(keyInfo.parameters);
				}

				if ('privateKey' in keyInfo) {
					this.pkiObject.setPrivateKey(keyInfo.privateKey);
				} else {
					this.pkiObject.setPublicKey(keyInfo.publicKey);
				}
			}
		}

		this.pkiName = this.pkiObject.pkiName;
		this.OID = this.pkiObject.OID;
	 
		return this;
	}

	/**
	 * gets block length in bytes.
	 * 
	 * @public
	 * @returns block length in bytes.
	 */
	getBlockLength()
	{
		return this.pkiObject.hasPubKey ? this.pkiObject.blockLength : 0;
	}

	/**
	 * gets block length in bits.
	 * 
	 * @public
	 * @returns block length in bits.
	 */
	getBitLength()
	{
		return this.pkiObject.hasPubKey ? this.pkiObject.blockLength * 8 : 0;
	}

/* 
There are 4 types of private key PEM:

1. PKCS#5 with no encryption

-----BEGIN RSA PRIVATE KEY-----
MIIBOwIBAAJBANxtmQ1Kccdp7HBNt8zgTai48Vv617bj4SnhkcMN99sCQ2Naj/sp
... (snip) ...
NiCYNLiCawBbpZnYw/ztPVACK4EwOpUy+u19cMB0JA==
-----END RSA PRIVATE KEY-----

2. PKCS#5 with encryption

-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,E83B4019057F55E9

iIPs59nQn4RSd7ppch9/vNE7PfRSHLoQFmaAjaF0DxjV9oucznUjJq2gphAB2E2H
... (snip) ...
y5IT1MZPgN3LNkVSsLPWKo08uFZQdfu0JTKcn7NPyRc=
-----END RSA PRIVATE KEY-----

3. PKCS#8 with no encryption

-----BEGIN PRIVATE KEY-----
MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEA6GZN0rQFKRIVaPOz
... (snip) ...
LaLGdd9G63kLg85eldSy55uIAXsvqQIgfSYaliVtSbAgyx1Yfs3hJ+CTpNKzTNv/
Fx80EltYV6k=
-----END PRIVATE KEY-----

4. PKCS#8 with encryption

-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIBpjBABgkqhkiG9w0BBQ0wMzAbBgkqhkiG9w0BBQwwDgQIU9Y9p2EfWucCAggA
... (snip) ...
IjsZNp6zmlqf/RXnETsJjGd0TXRWaEdu+XOOyVyPskX2177X9DUJoD31
-----END ENCRYPTED PRIVATE KEY-----

*/

/*
http://juliusdavies.ca/commons-ssl/pkcs8.html


Both RSA and DSA keys are supported. Here is a list of supported formats:

    OpenSSL "Traditional SSLeay Compatible Format"
        Unencrypted PEM or DER
        Encrypted PEM:
            des | des2 | des3 | blowfish | aes128 | aes192 | aes256 | rc2-40 | rc2-64 | rc2-128

        Note:
            OpenSSL "traditional SSLeay" format does not allow encrypted keys to be encoded in DER. 
			Only unencrypted keys can be encoded in DER.

    PKCS #8 (Unencrypted)
        PEM or DER
    PKCS #8 with PKCS #5 Version 1.5 Encryption
        PEM or DER:
            MD2 with DES | MD2 with RC2-64 | MD5 with DES | MD5 with RC2-64 | SHA1 with DES | SHA1 with RC2-64

    PKCS #8 with PKCS #5 Version 1.5 Encryption and PKCS #12 Key Derivation
        PEM or DER:
            SHA1 with 3DES | SHA1 with 2DES | SHA1 with RC2-128 | SHA1 with RC2-40 | SHA1 with RC4-128 | SHA1 with RC4-40

    PKCS #8 with PKCS #5 Version 2.0 Encryption and HmacSHA1
        PEM or DER:
            DES | 3DES | Blowfish | AES-128 | AES-192 | AES-256 | RC2-40 | RC2-64 | RC2-128


*/
	/**
	 * resets internal variables.
	 * 
	 * @public
	 * @returns this class instance.
	 */
	reset()
	{
		if (!this.pkiObject) {
			throw jCastle.exception("PKI_NOT_SET", 'PKI080');
		}
		this.pkiObject.reset();

		this.pkiName = '';
		this.pkiObject = null;

		return this;
	}

	/**
	 * sets publicKey. With RSA: n, e. Others: y, params.
	 * 
	 * @public
	 * @param {mixed} p1 object or buffer.
	 * @param {mixed} p2 object or buffer. in RSA pki integer can be acceptable.
	 * @returns this class instance.
	 */
	setPublicKey(p1, p2)
	{
		if (!this.pkiObject) {
			throw jCastle.exception("PKI_NOT_SET", 'PKI081');
		}
		this.pkiObject.setPublicKey(p1, p2);

		return this;
	}

	/**
	 * gets publicKey.
	 * 
	 * @public
	 * @param {string} format format string.
	 * @returns publicKey in format.
	 */
	getPublicKey(format)
	{
		if (!this.pkiObject) {
			throw jCastle.exception("PKI_NOT_SET", 'PKI082');
		}
		return this.pkiObject.getPublicKey(format);
	}

	/**
	 * gets privateKey.
	 * 
	 * @public
	 * @param {string} format format string
	 * @returns privateKey in format.
	 */
	getPrivateKey(format)
	{
		if (!this.pkiObject) {
			throw jCastle.exception("PKI_NOT_SET", 'PKI083');
		}
		return this.pkiObject.getPrivateKey(format);
	}

	/**
	 * sets privateKey and publicKey. With RSA: n, e, d, p, q, dmp1, dmq1, iqmp. Ohers: x, y, params.
	 * 
	 * @public
	 * @param {mixed} p1 object or buffer.
	 * @param {mixed} p2 object or buffer.
	 * @param {mixed} p3 object or buffer.
	 * @param {mixed} p4 object or buffer.
	 * @param {mixed} p5 object or buffer.
	 * @param {mixed} p6 object or buffer.
	 * @param {mixed} p7 object or buffer.
	 * @param {mixed} p8 object or buffer.
	 * @returns this class instance.
	 */
	setPrivateKey(p1, p2, p3, p4, p5, p6, p7, p8)
	{
		if (!this.pkiObject) {
			throw jCastle.exception("PKI_NOT_SET", 'PKI084');
		}
		return this.pkiObject.setPrivateKey(p1, p2, p3, p4, p5, p6, p7, p8);
	}

	/**
	 * gets publicKey information object.
	 * 
	 * @public
	 * @param {string} format publicKey format string
	 * @param {string} param_format parameters format string. For RSA this parameter is not required.
	 * @returns publicKey information object in format.
	 */
	getPublicKeyInfo(format, param_format)
	{
		if (!this.pkiObject) {
			throw jCastle.exception("PKI_NOT_SET", 'PKI085');
		}
		return this.pkiObject.getPublicKeyInfo(format, param_format);
	}

	/**
	 * gets privateKey information object.
	 * 
	 * @public
	 * @param {string} format privateKey format string
	 * @param {string} param_format parameters format string. For RSA this parameter is not required.
	 * @returns privateKey information object in format.
	 */
	getPrivateKeyInfo(format, param_format)
	{
		if (!this.pkiObject) {
			throw jCastle.exception("PKI_NOT_SET", 'PKI086');
		}
		return this.pkiObject.getPrivateKeyInfo(format, param_format);
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
		if (!this.pkiObject) {
			throw jCastle.exception("PKI_NOT_SET", 'PKI087');
		}
		return this.pkiObject.publicKeyEquals(pubkey);

	}

	/**
	 * checks if publicKey is set.
	 * 
	 * @public
	 * @returns true if publicKey is set.
	 */
	hasPublicKey()
	{
		if (!this.pkiObject) return false;
		return this.pkiObject.hasPublicKey();
	}

	/**
	 * checks if privateKey is set.
	 * 
	 * @public
	 * @returns true if privateKey is set.
	 */
	hasPrivateKey()
	{
		if (!this.pkiObject) return false;
		return this.pkiObject.hasPrivateKey();
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
		if (!this.pkiObject) {
			throw jCastle.exception("PKI_NOT_SET", 'PKI088');
		}
		if (this.pkiObject.pkiName === 'RSA') {
			throw jCastle.exception("UNSUPPORTED_PKI_FUNC", 'PKI089');
		}
		this.pkiObject.setParameters(p, q, g);

		return this;
	}

	/**
	 * gets parameters.
	 * 
	 * @public
	 * @param {string} format parameters format string
	 * @returns parameters in format
	 */
	getParameters(format)
	{
		if (!this.pkiObject) {
			throw jCastle.exception("PKI_NOT_SET", 'PKI090');
		}
		if (this.pkiObject.pkiName === 'RSA') {
			throw jCastle.exception("UNSUPPORTED_PKI_FUNC", 'PKI091');
		}
		return this.pkiObject.getParameters(format);
	}

	/**
	 * generates parameters
	 * 
	 * @public
	 * @param {object} options options object for generation of parameters
	 * @returns this class instance.
	 */
	generateParameters(options)
	{
		if (!this.pkiObject) {
			throw jCastle.exception("PKI_NOT_SET", 'PKI092');
		}
		if (this.pkiObject.pkiName === 'RSA' || this.pkiObject.pkiName === 'ECDSA') {
			throw jCastle.exception("UNSUPPORTED_PKI_FUNC", 'PKI093');
		}
		this.pkiObject.generateParameters(options);

		return this;
	}

	/**
	 * generates privateKey and publicKey.
	 * 
	 * @public
	 * @param {object} p1 parameters object. DSA parameters must be set if it is not given. 
	 *                            For RSA this is options object.
	 * @returns this class instance.
	 */
	generateKeypair(p1)
	{
		if (!this.pkiObject) {
			throw jCastle.exception("PKI_NOT_SET", 'PKI094');
		}
		this.pkiObject.generateKeypair(p1);

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
	validateKeypair(privkey, certainty, display_err)
	{
		if (!this.pkiObject) {
			throw jCastle.exception("PKI_NOT_SET", 'PKI095');
		}
		return this.pkiObject.validateKeypair(privkey, certainty, display_err);
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
	setPadding(mode, hash_algo, label, mgf)
	{
		if (!this.pkiObject) {
			throw jCastle.exception("PKI_NOT_SET", 'PKI096');
		}
		if (this.pkiObject.pkiName !== 'RSA') {
			throw jCastle.exception("UNSUPPORTED_PKI_FUNC", 'PKI097');
		}
		this.pkiObject.setPadding(mode, hash_algo, label, mgf);

		return this;
	}

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
		if (!this.pkiObject) {
			throw jCastle.exception("PKI_NOT_SET", 'PKI098');
		}
		if (this.pkiObject.pkiName !== 'RSA') {
			throw jCastle.exception("UNSUPPORTED_PKI_FUNC", 'PKI099');
		}
		return this.pkiObject.publicEncrypt(pt, options);
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
		if (!this.pkiObject) {
			throw jCastle.exception("PKI_NOT_SET", 'PKI100');
		}
		if (this.pkiObject.pkiName !== 'RSA') {
			throw jCastle.exception("UNSUPPORTED_PKI_FUNC", 'PKI101');
		}
		return this.pkiObject.privateEncrypt(pt, options);
	}

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
		if (!this.pkiObject) {
			throw jCastle.exception("PKI_NOT_SET", 'PKI102');
		}
		if (this.pkiObject.pkiName !== 'RSA') {
			throw jCastle.exception("UNSUPPORTED_PKI_FUNC", 'PKI103');
		}
		return this.pkiObject.publicDecrypt(ct, options);
	}

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
		if (!this.pkiObject) {
			throw jCastle.exception("PKI_NOT_SET", 'PKI104');
		}
		if (this.pkiObject.pkiName !== 'RSA') {
			throw jCastle.exception("UNSUPPORTED_PKI_FUNC", 'PKI105');
		}
		return this.pkiObject.privateDecrypt(ct, options);
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
	sign(str, options)
	{
		if (!this.pkiObject) {
			throw jCastle.exception("PKI_NOT_SET", 'PKI106');
		}
		return this.pkiObject.sign(str, options);
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
	verify(str, signature, options)
	{
		if (!this.pkiObject) {
			throw jCastle.exception("PKI_NOT_SET", 'PKI107');
		}
		return this.pkiObject.verify(str, signature, options);
	}

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
	pssSign(str, options)
	{
		if (!this.pkiObject) {
			throw jCastle.exception("PKI_NOT_SET", 'PKI108');
		}
		if (this.pkiObject.pkiName !== 'RSA') {
			throw jCastle.exception("UNSUPPORTED_PKI_FUNC", 'PKI109');
		}
		return this.pkiObject.pssSign(str, options);
	}

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
	pssVerify(str, signature, options)
	{
		if (!this.pkiObject) {
			throw jCastle.exception("PKI_NOT_SET", 'PKI110');
		}
		if (this.pkiObject.pkiName !== 'RSA') {
			throw jCastle.exception("UNSUPPORTED_PKI_FUNC", 'PKI111');
		}
		return this.pkiObject.pssVerify(str, signature, options);
	}

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
	ansiX931Sign(str, options)
	{
		if (!this.pkiObject) {
			throw jCastle.exception("PKI_NOT_SET", 'PKI112');
		}
		if (this.pkiObject.pkiName !== 'RSA') {
			throw jCastle.exception("UNSUPPORTED_PKI_FUNC", 'PKI113');
		}
		return this.pkiObject.ansiX931Sign(str, options);
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
	ansiX931Verify(str, signature, options)
	{
		if (!this.pkiObject) {
			throw jCastle.exception("PKI_NOT_SET", 'PKI114');
		}
		if (this.pkiObject.pkiName !== 'RSA') {
			throw jCastle.exception("UNSUPPORTED_PKI_FUNC", 'PKI115');
		}
		return this.pkiObject.ansiX931Verify(str, signature, options);
	}

	// getCurve()
	// {
	// 	if (!this.pkiObject) {
	// 		throw jCastle.exception("PKI_NOT_SET", 'PKI116');
	// 	}
	// 	if (this.pkiObject.pkiName !== 'ECDSA' && this.pkiObject.pkiName !== 'ECKCDSA') {
	// 		throw jCastle.exception("UNSUPPORTED_PKI_FUNC", 'PKI117');
	// 	}
	// 	return this.pkiObject.getCurve();
	// }

	/**
	 * gets block length in bytes.
	 * 
	 * @public
	 * @returns block length in bytes.
	 */
	getBlockLength()
	{
		if (!this.pkiObject) {
			throw jCastle.exception("PKI_NOT_SET", 'PKI118');
		}
		return this.pkiObject.getBlockLength();
	}

	/**
	 * gets block length in bits.
	 * 
	 * @public
	 * @returns block length in bits.
	 */
	getBitLength()
	{
		if (!this.pkiObject) {
			throw jCastle.exception("PKI_NOT_SET", 'PKI119');
		}
		return this.pkiObject.getBitLength();
	}

	/**
	 * gets the ephemeral publicKey corresponding to the ephemeral privateKey.
	 * 
	 * @public
	 * @param {object} ephemeral_privkey ephemeral privateKey object or buffer
	 * @param {string} format format string
	 * @returns the ephemeral publicKey in format.
	 */
	getEphemeralPublicKey(ephemeral_privkey, format)
	{
		if (!this.pkiObject) {
			throw jCastle.exception("PKI_NOT_SET", 'PKI120');
		}
		if (this.pkiObject.pkiName !== 'ECDSA' && this.pkiObject.pkiName !== 'ECKCDSA') {
			throw jCastle.exception("UNSUPPORTED_PKI_FUNC", 'PKI121');
		}
		return this.pkiObject.getEphemeralPublicKey(ephemeral_privkey, format);
	}

	/**
	 * gets the curve information data object.
	 * 
	 * @public
	 * @returns the curve information data object.
	 */
	getCurveInfo()
	{
		if (!this.pkiObject) {
			throw jCastle.exception("PKI_NOT_SET", 'PKI122');
		}
		if (this.pkiObject.pkiName !== 'ECDSA' && this.pkiObject.pkiName !== 'ECKCDSA') {
			throw jCastle.exception("UNSUPPORTED_PKI_FUNC", 'PKI123');
		}
		return this.pkiObject.getCurveInfo();
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
		if (!this.pkiObject) {
			throw jCastle.exception("PKI_NOT_SET", 'PKI124');
		}
		if (this.pkiObject.pkiName !== 'ECDSA' && this.pkiObject.pkiName !== 'ECKCDSA') {
			throw jCastle.exception("UNSUPPORTED_PKI_FUNC", 'PKI125');
		}
		return this.pkiObject.importPoint(mixed_point);
	}

	/**
	 * parse a pem or object and initialize with it.
	 * 
	 * @param {mixed} pem pem string or buffer. ASN1 object is acceptable.
	 * @param {buffer} password password value.
	 * @returns this class instance.
	 */
	parse(pem, password)
	{
		if (pem instanceof jCastle.pki) {
			this.init(pem);
			return this;
		}

		var result = jCastle.util.toAsn1Object(pem, { 
			match: "-----BEGIN (RSA |EC |DSA |KCDSA |ECKCDSA |ELGAMAL )?(ENCRYPTED )?(PUBLIC|PRIVATE) KEY-----" 
		});

		if ('matches' in result) {
			return result.matches[3] == 'PUBLIC' ? this.parsePublicKey(pem, 'pem') : this.parsePrivateKey(pem, password, 'pem');
		}

		try {
			this.parsePrivateKey(result.asn1, password, 'asn1');
		} catch (ex) {
			this.parsePublicKey(result.asn1, 'asn1');
		}

		return this;
	}

	/**
	 * parse a publicKey pem or object and initialize with it.
	 * 
	 * @public
	 * @param {mixed} pem pem string or buffer. ASN1 object is acceptable.
	 * @param {string} format format string (default: 'auto')
	 * @returns 
	 */
	parsePublicKey(pem, format = 'auto')
	{
		var pkcs5 = false;

		format = format.toLowerCase();

		if (pem instanceof jCastle.pki) {
			if (!pem.hasPublicKey()) throw jCastle.exception('PUBKEY_NOT_SET', 'PKI077');
			this.init(pem);
			return this;
		}

		var result = jCastle.util.toAsn1Object(pem, {
			format: format,
			match: "-----BEGIN (RSA |EC |DSA |KCDSA |ECKCDSA |ELGAMAL )?PUBLIC KEY-----"

		});

		if ('maches' in result) {
			if (result.matches[1]) {
				pkcs5 = true;

				var pki_name = result.matches[1].trim();
				if (pki_name  == 'EC') pki_name = 'ECDSA';

				if (this.pkiName == '') {
					this.init(pki_name);
				} else {
					if (this.pkiName.toUpperCase() != pki_name) {
						throw jCastle.exception("INVALID_PEM_FORMAT", 'PKI013');
					}
				}
			}
		}

		var sequence = result.asn1;

		if (!jCastle.asn1.isSequence(sequence)) {
			throw jCastle.exception("INVALID_PEM_FORMAT", 'PKI016');
		}

		if (pkcs5) {
			// pkcs#5 format

			switch (this.pkiName) {
				case 'RSA':
/*
The PEM RSAPublicKey format uses the header and footer lines:

 -----BEGIN RSA PUBLIC KEY-----
 -----END RSA PUBLIC KEY-----

RSAPublicKey ::= SEQUENCE {
	modulus				INTEGER, -- n
	publicExponent		INTEGER, -- e
}
*/
					this.setPublicKey(
						sequence.items[0].intVal,
						sequence.items[1].intVal
					);
					break;

				case 'DSA':
				case 'KCDSA':
/*
http://opensource.apple.com/source/ruby/ruby-96/ruby/test/openssl/test_pkey_dsa.rb

-----BEGIN DSA PUBLIC KEY-----
MIHfAkEAyJSJ+g+P/knVcgDwwTzC7Pwg/pWs2EMd/r+lYlXhNfzg0biuXRul8VR4
VUC/phySExY0PdcqItkR/xYAYNMbNwJBAOoV57X0FxKO/PrNa/MkoWzkCKV/hzhE
p0zbFdsicw+hIjJ7S6Sd/FlDlo89HQZ2FuvWJ6wGLM1j00r39+F2qbMCFQCrkhIX
SG+is37hz1IaBeEudjB2HQJAR0AloavBvtsng8obsjLb7EKnB+pSeHr/BdIQ3VH7
fWLOqqkzFeRrYMDzUpl36XktY6Yq8EJYlW9pCMmBVNy/dQ==
-----END DSA PUBLIC KEY-----


SEQUENCE(4 elem)
	INTEGER(512 bit) 1050523907498276150424082342242281336272149889604071975946029630630585…					y
	INTEGER(512 bit) 1226005593687129356582771238521252910640044452144966332557663457996163…					p
	INTEGER(160 bit) 979494906553787301107832405790107343409973851677											q
	INTEGER(511 bit) 3731695366899846297271147240305742456317979984190506040697507048095553…					g
*/
					this.setPublicKey(
						sequence.items[0].intVal, {
							p: sequence.items[1].intVal,
							q: sequence.items[2].intVal,
							g: sequence.items[3].intVal
						}
					);
				case 'ECDSA': /* I recommend not to use PKCS#5 ec public key pem */
				case 'ECKCDSA':
/*
what I found is this one:

-----BEGIN EC PUBLIC KEY-----
RUNTMzAAAABMrWvMrqah61dhnjTXm8YYZzgE2TtVO8d5DCHak7wjrJ21VIvl/Bou
L7Hyp/aHiDReIs+nGT7VsNp+CPaGt3Ek5V8DMmNxb5jl2mlgVq/Fvwu/Ktuhso49
/Vc582SH1gg=
-----END EC PUBLIC KEY-----

Application 5(67 byte) 					5333300000004CAD6BCCAEA6A1EB57619E34D79BC618673804D93B553BC7790C21DA93…
*/
//				if (sequence.tagClass == jCastle.asn1.tagClassApplication) {
//					this.setPublicKey(sequence.value, null);
//				} else {
//					throw jCastle.exception("NO_PKCS5_PEM_SUPPORTED", 'PKI017');
//				}
//				break;

// It maybe ECDSA doesn't support pkcs5 public key.

				default:
					throw jCastle.exception("UNSUPPORTED_PKI", 'PKI018');
			}

			return this;
		}
		
		// this.pkiName can be empty
		if (this.pkiName == '') {
			switch (sequence.items[0].items[0].value) {
				case jCastle.oid.getOID("rsaEncryption"):
					this.init('RSA');
					break;
				case jCastle.oid.getOID("dsaPublicKey"):
					this.init('DSA');
					break;
				case jCastle.oid.getOID("kcdsa"):
					this.init('KCDSA');
					break;
				case jCastle.oid.getOID("ecPublicKey"):
					this.init('ECDSA');
					break;
				case jCastle.oid.getOID("eckdsa-PublicKey"):
					this.init('ECKCDSA');
					break;
				default:
					throw jCastle.exception("UNSUPPORTED_PKI", 'PKI019');
			}
		}

		// pkcs#8 format
		var params;

		switch (this.pkiName) {
			case 'RSA':
				if (sequence.items[0].items[0].value != jCastle.oid.getOID("rsaEncryption")) {
					throw jCastle.exception("INVALID_PEM_FORMAT", 'PKI020');
				}

/*
SEQUENCE(2 elem)
	SEQUENCE(2 elem)
		OBJECT IDENTIFIER		1.2.840.113549.1.1.1
		NULL
	BIT STRING(1 elem)
		SEQUENCE(2 elem)
			INTEGER(1023 bit)	722608733133111661585229270073948506509109752292816595953562525256298…
			INTEGER				65537
*/
				this.setPublicKey(
					sequence.items[1].value.items[0].intVal, // n
					sequence.items[1].value.items[1].intVal // e
				);
				break;

			case 'DSA':
				if (this.pkiName == 'DSA' && sequence.items[0].items[0].value != jCastle.oid.getOID("dsaPublicKey")) {
					throw jCastle.exception("INVALID_PEM_FORMAT", 'PKI021');
				}
			case 'KCDSA':
				if (this.pkiName == 'KCDSA' && sequence.items[0].items[0].value != jCastle.oid.getOID("kcdsa")) {
					throw jCastle.exception("INVALID_PEM_FORMAT", 'PKI022');
				}

				/*
				PublicKeyInfo ::= SEQUENCE {
				  algorithm AlgorithmIdentifier,
				  PublicKey BIT STRING
				}

				AlgorithmIdentifier ::= SEQUENCE {
				  algorithm ALGORITHM.id, -- 1.2.840.10040.4.1
				  parameters Dss-Parms
				}

				Dss-Parms ::= SEQUENCE {
				  p INTEGER,
				  q INTEGER,
				  g INTEGER
				}

				DSAPublicKey ::= BITSTRING {
				  publicExponent INTEGER
				}
				*/
/*
SEQUENCE(2 elem)
	SEQUENCE(2 elem)
		OBJECT IDENTIFIER			1.2.840.10040.4.1
		SEQUENCE(3 elem)
			INTEGER(2048 bit) 		178603344521910810331025134906443426957028075706054818492858868432114…
			INTEGER(256 bit) 		6740557547405118602307919070313939777208749178291490982581455316799392…
			INTEGER(2047 bit) 		929636291285612574486849105691058687781469316110849390255544885189707…
	BIT STRING(1 elem)
		INTEGER(2047 bit) 			121732077429953631163473627988276921184717244206695728306501904869933…
*/
				params = {
					p: sequence.items[0].items[1].items[0].intVal.toString(16),
					q: sequence.items[0].items[1].items[1].intVal.toString(16),
					g: sequence.items[0].items[1].items[2].intVal.toString(16)
				};
				this.setPublicKey(
					sequence.items[1].value.intVal,
					params
				);
				break;
			case 'ECDSA':
				if (this.pkiName == 'ECDSA' && 
					sequence.items[0].items[0].value != jCastle.oid.getOID("ecPublicKey")) {
					throw jCastle.exception("INVALID_PEM_FORMAT", 'PKI023');
				}
			case 'ECKCDSA':
				if (this.pkiName == 'ECKCDSA' &&
					sequence.items[0].items[0].value != jCastle.oid.getOID("eckdsa-PublicKey")) {
					throw jCastle.exception("INVALID_PEM_FORMAT", 'PKI024');
				}
/*
SEQUENCE(2 elem)
	SEQUENCE(2 elem)
		OBJECT IDENTIFIER					1.2.840.10045.2.1
		OBJECT IDENTIFIER					1.2.840.10045.3.1.3
	BIT STRING(392 bit) 					0000010011111001100011111010101000111110101000100011011110000001111010…


SubjectPublicKeyInfo  ::=  SEQUENCE  {
	algorithm         AlgorithmIdentifier,
	subjectPublicKey  BIT STRING
}

AlgorithmIdentifier  ::=  SEQUENCE  {
	algorithm   OBJECT IDENTIFIER,
	parameters  ANY DEFINED BY algorithm OPTIONAL
}

*/
				if (sequence.items[0].items[1].type == jCastle.asn1.tagOID) {
					params = jCastle.pki.ecdsa.getParametersByOID(sequence.items[0].items[1].value);
					if (!params) {
						throw jCastle.exception("UNKNOWN_ECDSA_CURVE", 'PKI025');
					}
				} else {
					/*
					EC-parameters::= SEQUENCE {
						version 					INTEGER
						SEQUENCE {
							1.2.840.10045.1.1 		OID
							p 			 			INTEGER
						}
						SEQUENCE {
							a 						OCTET STRING
							b 						OCTET STRING
						}
						G (uncompressed)			OCTET STRING
						n (order)					INTEGER
						cofactor 					INTEGER
					}
					*/
					var paramSeq = sequence.items[0].items[1];			
					params = {
						p: paramSeq.items[1].items[1].intVal.toString(16),
						a: Buffer.from(paramSeq.items[2].items[0].value, 'latin1').toString('hex'),
						b: Buffer.from(paramSeq.items[2].items[1].value, 'latin1').toString('hex'),
						g: Buffer.from(paramSeq.items[3].value, 'latin1').toString('hex'),
						n: paramSeq.items[4].intVal.toString(16),
						h: paramSeq.items[5].intVal,
						//type: (paramSeq.items[1].items[0].value == '1.2.840.10045.1.1' ?
						type: jCastle.oid.getName(paramSeq.items[1].items[0].value),
						seed: typeof paramSeq.items[2].items[2] == 'undefined' ?
								null : Buffer.from(paramSeq.items[2].items[2].value, 'latin1').toString('hex')
					};
				}

				this.setPublicKey(
					Buffer.from(sequence.items[1].value, 'latin1'),
					params
				);
				break;
				
			default:
				throw jCastle.exception("UNSUPPORTED_PKI", 'PKI026');
		}

		return this;
	}

	/**
	 * parse a privateKey pem or object and initialize with it.
	 * 
	 * @public
	 * @param {mixed} pem pem string or buffer. ASN1 object is acceptable.
	 * @param {buffer} password password value, if pem is encrypted.
	 * @param {string} format format string (default: 'auto')
	 * @returns this class instance.
	 */
	parsePrivateKey(pem, password, format = 'auto')
	{
		var encrypted = false;

		format = format.toLowerCase();

		if (pem instanceof jCastle.pki) {
			if (!pem.hasPrivateKey()) throw jCastle.exception('PRIVKEY_NOT_SET', 'PKI076');
			this.init(pem);
			return this;
		}

		var result = jCastle.util.toAsn1Object(pem, {
			format: format,
			match: "-----BEGIN (RSA |EC |DSA |KCDSA |ECKCDSA |ELGAMAL )?(ENCRYPTED )?PRIVATE KEY-----"			
		});


/*
private key with no encryption:

SEQUENCE (9 elem)
  INTEGER 0
  INTEGER (2047 bit) 151162365558548723872104645510163820602277233031184951756775213355301…
  INTEGER 65537
  INTEGER (2044 bit) 168445115839004124454579890162919630416166536891640402014088130847271…
  INTEGER (1024 bit) 150439542258000660814436210025849609239833700737115410528267857972834…
  INTEGER (1024 bit) 100480474275379299049013636292469555122573011202301485331234634341190…
  INTEGER (1023 bit) 806267983317822788721830025931602251390805026884117625065974982595762…
  INTEGER (1023 bit) -8.245027073740725e+307
  INTEGER (1023 bit) -6.910932851481997e+307

  
private key with encryption:  

SEQUENCE (2 elem)
  SEQUENCE (2 elem)
    OBJECT IDENTIFIER 1.2.840.113549.1.12.1.1 pbeWithSHAAnd128BitRC4 (PKCS #12 PbeIds.)
    SEQUENCE (2 elem)
      OCTET STRING (8 byte) E0A0246A30B9F0F9
      INTEGER 2048
  OCTET STRING (1217 byte) 5568DD5A27B0DDA4400DEA02747C7E6CD0E5AD7672D30694661343AA8E02D364A389…
*/
		if ('matches' in result) {
			// PKCS #5 
			// openssl genrsa -des3 -out herong_rsa.key 
			if (result.matches && result.matches[1]) {

				return this.parsePrivateKeyPKCS5(pem, password);
			}

			if (result.matches && result.matches[2]) {
				encrypted = true;
			}
		}

		var sequence = result.asn1;

		if (!jCastle.asn1.isSequence(sequence))
			throw jCastle.exception("INVALID_PEM_FORMAT", 'PKI031');

		if (sequence.items[0].type != jCastle.asn1.tagInteger) { // version
			encrypted = true;
		}

		// encrypted
		if (encrypted) {
			if (!password.length) {
				throw jCastle.exception("NO_PASSPHRASE", 'PKI032');
			}
			if (!Buffer.isBuffer(password))
				password = Buffer.from(password, 'latin1');




			var der = jCastle.pbe.asn1.decrypt(sequence, password);
			sequence = new jCastle.asn1().parse(der);

			if (!jCastle.asn1.isSequence(sequence)) {
				throw jCastle.exception("INCORRECT_PASSPHRASE", 'PKI033');
			}
		}

		if (sequence.items[0].value != '\x00') { // version
			throw jCastle.exception("UNSUPPORTED_PEM_VERSION", 'PKI034');
		}
		
		// this.pkiName can be empty
		if (this.pkiName == '') {
			switch (sequence.items[1].items[0].value) {
				case jCastle.oid.getOID("rsaEncryption"):
					this.init('RSA');
					break;
				case jCastle.oid.getOID("dsaPublicKey"):
					this.init('DSA');
					break;
				case jCastle.oid.getOID("kcdsa"):
					this.init('KCDSA');
					break;
				case jCastle.oid.getOID("ecPublicKey"):
					this.init('ECDSA');
					break;
				case jCastle.oid.getOID("eckdsa-PublicKey"):
					this.init('ECKCDSA');
					break;
				default:
					throw jCastle.exception("UNSUPPORTED_PKI", 'PKI035');
			}
		}

		var params;

		switch (this.pkiName) {
			case 'RSA':
				if (sequence.items[1].items[0].value != jCastle.oid.getOID("rsaEncryption")) {
					throw jCastle.exception("INVALID_PEM_FORMAT", 'PKI036');
				}
/*
SEQUENCE(3 elem)
	INTEGER							0
	SEQUENCE(2 elem)
		OBJECT IDENTIFIER			1.2.840.113549.1.1.1
		NULL
	OCTET STRING(1 elem)
		SEQUENCE(9 elem)
			INTEGER					0
			INTEGER(2047 bit)		151162365558548723872104645510163820602277233031184951756775213355301…
			INTEGER					65537
			INTEGER(2044 bit)		168445115839004124454579890162919630416166536891640402014088130847271…
			INTEGER(1024 bit)		150439542258000660814436210025849609239833700737115410528267857972834…
			INTEGER(1024 bit)		100480474275379299049013636292469555122573011202301485331234634341190…
			INTEGER(1023 bit)		806267983317822788721830025931602251390805026884117625065974982595762…
			INTEGER(1024 bit)		973190427488243436095051736219922335689049221976301445198913348918483…
			INTEGER(1024 bit)		110659984971411622188431412411155397287683213958155381552845963178193…
*/
				this.setPrivateKey(
					sequence.items[2].value.items[1].intVal, //n
					sequence.items[2].value.items[2].intVal, //e
					sequence.items[2].value.items[3].intVal, //d
					sequence.items[2].value.items[4].intVal, //p
					sequence.items[2].value.items[5].intVal, //q
					sequence.items[2].value.items[6].intVal, //dmp1
					sequence.items[2].value.items[7].intVal, //dmq1
					sequence.items[2].value.items[8].intVal //iqmp
				);
				break;

			case 'DSA':
				if (this.pkiName == 'DSA' && sequence.items[1].items[0].value != jCastle.oid.getOID("dsaPublicKey")) {
					throw jCastle.exception("INVALID_PEM_FORMAT", 'PKI037');
				}
			case 'KCDSA':
				if (this.pkiName == 'KCDSA' && sequence.items[1].items[0].value != jCastle.oid.getOID("kcdsa")) {
					throw jCastle.exception("INVALID_PEM_FORMAT", 'PKI038');
				}

/*
SEQUENCE(3 elem)
	INTEGER						0
	SEQUENCE(2 elem)
		OBJECT IDENTIFIER		1.2.840.10040.4.1
		SEQUENCE(3 elem)
			INTEGER(2048 bit)	178603344521910810331025134906443426957028075706054818492858868432114…
			INTEGER(256 bit)	6740557547405118602307919070313939777208749178291490982581455316799392…
			INTEGER(2047 bit)	929636291285612574486849105691058687781469316110849390255544885189707…
	OCTET STRING(1 elem)
		INTEGER(255 bit)		4634705039688674346218177458887675782838098427960186805723182071401908…
*/
				params = {
					p: sequence.items[1].items[1].items[0].intVal.toString(16), //p
					q: sequence.items[1].items[1].items[1].intVal.toString(16), //q
					g: sequence.items[1].items[1].items[2].intVal.toString(16) //g
				};

				this.setPrivateKey(
					sequence.items[2].value.intVal, //x
					null, // y
					params
				);
				break;

			case 'ECDSA':
				if (this.pkiName == 'ECDSA' &&
					sequence.items[1].items[0].value != jCastle.oid.getOID("ecPublicKey")) {
					throw jCastle.exception("INVALID_PEM_FORMAT", 'PKI039');
				}
			case 'ECKCDSA':
				if (this.pkiName == 'ECKCDSA' &&
					sequence.items[1].items[0].value != jCastle.oid.getOID("eckdsa-PublicKey")) {
					throw jCastle.exception("INVALID_PEM_FORMAT", 'PKI040');
				}

				if (sequence.items[1].items[1].type == jCastle.asn1.tagOID) {
/*
SEQUENCE(3 elem)
	INTEGER 								0
	SEQUENCE(2 elem)
		OBJECT IDENTIFIER 					1.2.840.10045.2.1 ----- ecPublicKey
		OBJECT IDENTIFIER 					1.2.840.10045.3.1.7 ----- prime256v1
	OCTET STRING(1 elem)
		SEQUENCE(3 elem)
			INTEGER 						1
			OCTET STRING(32 byte)  			17551E79F3666266F99D4701860E665BE707C0E3F24571F57047FBA5025A5194
			[1](1 elem)
				BIT STRING(520 bit)  		0000010001001110000100111110100111111111000110000000010010100010111111…
*/
					params = jCastle.pki.ecdsa.getParametersByOID(sequence.items[1].items[1].value);
					if (!params) {
						throw jCastle.exception("UNKNOWN_ECDSA_CURVE", 'PKI041');
					}
				} else {
/*

SEQUENCE(3 elem)
	INTEGER										0
	SEQUENCE(2 elem)
		OBJECT IDENTIFIER						1.2.840.10045.2.1
		SEQUENCE(6 elem)
			INTEGER								1
			SEQUENCE(2 elem)
				OBJECT IDENTIFIER				1.2.840.10045.1.1
				INTEGER(192 bit) 				6277101735386680763835789423207666416083908700390324961279 -- p
			SEQUENCE(3 elem)
				OCTET STRING(24 byte) 			FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC -- a
				OCTET STRING(24 byte) 			22123DC2395A05CAA7423DAECCC94760A7D462256BD56916 -- b
				BIT STRING(160 bit) 			1100010001101001011010000100010000110101110111101011001101111000110001… -- seed
			OCTET STRING(49 byte) 				047D29778100C65A1DA1783716588DCE2B8B4AEE8E228F189638A90F22637337334B49… -- g
			INTEGER(192 bit) 					6277101735386680763835789423166314882687165660350679936019 -- n
			INTEGER								1 -- h
	OCTET STRING(1 elem)
		SEQUENCE(3 elem)
			INTEGER								1
			OCTET STRING(24 byte) 				8AB70B2CAABC4763F82E2830F84209B22C329AA81BF6C045  -- x
			[1](1 elem)
				BIT STRING(392 bit) 			0000010011111001100011111010101000111110101000100011011110000001111010…  -- y


ECPrivateKey ::= SEQUENCE {
	version		INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
	privateKey	 OCTET STRING,
	parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
	publicKey  [1] BIT STRING OPTIONAL
}

*/
					var paramSeq = sequence.items[1].items[1];
					params = {
						p: paramSeq.items[1].items[1].intVal.toString(16),
						a: Buffer.from(paramSeq.items[2].items[0].value, 'latin1').toString('hex'),
						b: Buffer.from(paramSeq.items[2].items[1].value, 'latin1').toString('hex'),
						g: Buffer.from(paramSeq.items[3].value, 'latin1').toString('hex'),
						n: paramSeq.items[4].intVal.toString(16),
						h: paramSeq.items[5].intVal,
						type: jCastle.oid.getName(paramSeq.items[1].items[0].value),
						seed: typeof paramSeq.items[2].items[2] == 'undefined' ?
								null : Buffer.from(paramSeq.items[2].items[2].value, 'latin1').toString('hex')
					};
				}



				var x = Buffer.from(sequence.items[2].value.items[1].value, 'latin1');
				// y is optional
				var y = typeof sequence.items[2].value.items[2] != 'undefined' ? 
					Buffer.from(sequence.items[2].value.items[2].items[0].value, 'latin1') : null;

				this.setPrivateKey(x, y, params);
				break;

			default:
				throw jCastle.exception("UNSUPPORTED_PKI", 'PKI042');
			
		}

		return this;
	}

/*
Private key pem format:
-----BEGIN RSA PRIVATE KEY-----
(snip)
-----END RSA PRIVATE KEY-----
*/
	/**
	 * parse a privateKey pem in PKCS#5 format and initialize with it.
	 * 
	 * @public
	 * @param {mixed} pem pem string or buffer. ASN1 object is acceptable.
	 * @param {buffer} password password value, if pem is encrypted.
	 * @param {string} format format string (default: 'auto')
	 * @returns this class instance.
	 */
	parsePrivateKeyPKCS5(pem, password, format = 'auto')
	{
		format = format.toLowerCase();

		var result = jCastle.util.toAsn1Object(pem, {
			format: format,
			match: "-----BEGIN ([A-Z]+) PRIVATE KEY-----" 
		});

		var sequence, asn1;

		if ('encrypted' in result && result.encrypted) {
			// encrypted
			if (!password.length) {
				throw jCastle.exception("NO_PASSPHRASE", 'PKI051');
			}
			if (!Buffer.isBuffer(password))
				password = Buffer.from(password, 'latin1');

			var algo_name = result.encryptedInfo.algo;
			var algo_info = jCastle.mcrypt.getAlgorithmInfo(algo_name);
			var key_size = algo_info.keySize;
			var block_size = algo_info.blockSize;
				
			// get a key
			var iv = result.encryptedInfo.iv;
			var salt = iv.slice(0, 8);
			var dk = jCastle.kdf.pkcs5DeriveKey(password, salt, key_size + block_size, 'MD5');
			var key = dk.slice(0, key_size);
			var unused_iv = dk.slice(key_size);

			var crypto = new jCastle.mcrypt(algo_name);
			crypto.start({
				key: key,
				mode: result.encryptedInfo.mode,
				isEncryption: false,
				iv: iv,
				padding: 'pkcs7'
			});
			crypto.update(result.buffer);
			var buf = crypto.finalize();

			asn1 = new jCastle.asn1();
			//asn1.ignoreLengthError();

			try {
				sequence = asn1.parse(buf);
			} catch (e) {
				throw jCastle.exception("INCORRECT_PASSPHRASE", 'PKI053');
			}
		} else {
			sequence = result.asn1;
		}

		if (!jCastle.asn1.isSequence(sequence)) {
			throw jCastle.exception("INVALID_PEM_FORMAT", 'PKI054');
		}

		if (result.matches && this.pkiName === '') {
			var pki_name = result.matches[1].trim();
			if (pki_name === 'EC') pki_name = 'ECDSA';

			this.init(pki_name);
		}

		var params;

		switch (this.pkiName) {
			case 'RSA':
				if (sequence.items[0].value != '\x00') { // version
					throw jCastle.exception("UNSUPPORTED_PEM_VERSION", 'PKI055');
				}

				this.setPrivateKey(
					sequence.items[1].intVal, //n
					sequence.items[2].intVal, //e
					sequence.items[3].intVal, //d
					sequence.items[4].intVal, //p
					sequence.items[5].intVal, //q
					sequence.items[6].intVal, //dmp1
					sequence.items[7].intVal, //dmq1
					sequence.items[8].intVal //iqmp
				);
				break;

			case 'DSA':
			case 'KCDSA':
/*
SEQUENCE(6 elem)
	INTEGER					0
	INTEGER(2048 bit) 		178603344521910810331025134906443426957028075706054818492858868432114…
	INTEGER(256 bit) 		6740557547405118602307919070313939777208749178291490982581455316799392…
	INTEGER(2047 bit) 		929636291285612574486849105691058687781469316110849390255544885189707…
	INTEGER(2047 bit) 		121732077429953631163473627988276921184717244206695728306501904869933…
	INTEGER(255 bit) 		4634705039688674346218177458887675782838098427960186805723182071401908…
*/
				params = {
					p: sequence.items[1].intVal, // p
					q: sequence.items[2].intVal, // q
					g: sequence.items[3].intVal // g
				};

				this.setPrivateKey(
					sequence.items[5].intVal, // x
					sequence.items[4].intVal, // y
					params
				);
				break;

			case 'ECDSA':
			case 'ECKCDSA':
				if (sequence.items[2].items[0].type === jCastle.asn1.tagOID) {
/*
SEQUENCE(4 elem)
	INTEGER 								1
	OCTET STRING(32 byte) 					17551E79F3666266F99D4701860E665BE707C0E3F24571F57047FBA5025A5194
	[0](1 elem)
		OBJECT IDENTIFIER 					1.2.840.10045.3.1.7 ----- prime256v1
	[1](1 elem)
		BIT STRING(520 bit) 				0000010001001110000100111110100111111111000110000000010010100010111111…
*/
					params = jCastle.pki.ecdsa.getParametersByOID(sequence.items[2].items[0].value);

					if (!params) {
						throw jCastle.exception("UNKNOWN_ECDSA_CURVE", 'PKI056');
					}
				} else {

/*
SEQUENCE(4 elem)
	INTEGER									1
	OCTET STRING(24 byte) 					77CCA1684F3DF45687DECC3C683E05FEFB6931504B7D5AA6
	[0](1 elem)
		SEQUENCE(6 elem)
			INTEGER 						1
			SEQUENCE(2 elem)
				OBJECT IDENTIFIER			1.2.840.10045.1.1
				INTEGER(192 bit) 			6277101735386680763835789423207666416083908700390324961279
			SEQUENCE(3 elem)
				OCTET STRING(24 byte) 		FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC
				OCTET STRING(24 byte) 		22123DC2395A05CAA7423DAECCC94760A7D462256BD56916
				BIT STRING(160 bit) 		1100010001101001011010000100010000110101110111101011001101111000110001…
			OCTET STRING(49 byte) 			047D29778100C65A1DA1783716588DCE2B8B4AEE8E228F189638A90F22637337334B49…
			INTEGER(192 bit) 				6277101735386680763835789423166314882687165660350679936019
			INTEGER							1
	[1](1 elem)
		BIT STRING(392 bit) 				0000010000011011001001011111000110010100100001100010011010100111000101…



ECPrivateKey ::= SEQUENCE {
	version		INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
	privateKey	 OCTET STRING,
	parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
	publicKey  [1] BIT STRING OPTIONAL
}
*/
					var paramSeq = sequence.items[2].items[0];
					params = {
						p: paramSeq.items[1].items[1].intVal,
						a: Buffer.from(paramSeq.items[2].items[0].value, 'latin1').toString('hex'),
						b: Buffer.from(paramSeq.items[2].items[1].value, 'latin1').toString('hex'),
						g: Buffer.from(paramSeq.items[3].value, 'latin1').toString('hex'),
						n: paramSeq.items[4].intVal,
						h: paramSeq.items[5].intVal,
						type: jCastle.oid.getName(paramSeq.items[1].items[0].value),
						seed: typeof paramSeq.items[2].items[2] == 'undefined' ?
							null : Buffer.from(paramSeq.items[2].items[2].value, 'latin1').toString('hex')
					};


				}

				var x = Buffer.from(sequence.items[1].value, 'latin1');
				// y is optional
				var y = typeof sequence.items[3] != 'undefined' ? Buffer.from(sequence.items[3].items[0].value, 'latin1') : null;

				this.setPrivateKey(x, y, params);
				break;
			default:
				throw jCastle.exception("UNSUPPORTED_PKI", 'PKI057');
		}

		return this;
	}

	/**
	 * exports publicKey or privateKey.
	 * 
	 * @public
	 * @param {string} key_type key type string. 'public' | 'private'
	 * @param {object} options options object
	 *                 {buffer} password password for encryption of privateKey.
	 *                 {string} algo algorithm name. ex) 'pbeWithMD5AndDES-CBC' or 'aes128-CBC'.
	 *                 {string} prf prf algorithm name. ex) 'hmacWithSHA1'
	 *                 {string} prfHash prf hash algorithm name. ex) 'sha-1'.
	 *                 {number} keySize key size. rc2 can set specific key size.
	 *                 {string} type type for pem format. 'pkcs5' | 'pkcs8'
	 *                 {string} format return type. 'der' | 'pem' | 'buffer'. (defualt: 'pem')
	 * @returns publicKey or privateKey.
	 */
	exportKey(key_type, options)
	{
		if (!/private|public/i.test(key_type)) throw jCastle.exception("INVALID_PARAMS", 'PKI058');
		return key_type.toLowerCase() == 'private' ? this.exportPrivateKey(options) : this.exportPublicKey(options);
	}

	/**
	 * exports privateKey.
	 * 
	 * @public
	 * @param {object} options options object
	 *                 {buffer} password password for encryption of privateKey.
	 *                 {string} algo algorithm name. ex) 'pbeWithMD5AndDES-CBC' or 'aes128-CBC'.
	 *                 {string} prf prf algorithm name. ex) 'hmacWithSHA1'
	 *                 {string} prfHash prf hash algorithm name. ex) 'sha-1'.
	 *                 {number} keySize key size. rc2 can set specific key size.
	 *                 {string} type type for pem format. 'pkcs5' | 'pkcs8'
	 *                 {string} format return type. 'der' | 'pem' | 'buffer'. (defualt: 'pem')
	 * @returns privateKey.
	 */
	exportPrivateKey(options = {})
	{
		if (this.pkiName == '') throw jCastle.exception("PKI_NOT_SET", 'PKI059');

		var type = 'type' in options ? options.type.toLowerCase() : 'pkcs#8';
		if (type === 'pkcs#5' || type === 'pkcs5') {
			return this.exportPrivateKeyPKCS5(options);
		}

		var format = 'format' in options ? options.format.toLowerCase() : 'pem';
		var asn1 = new jCastle.asn1();
		var der;

		switch (this.pkiName) {
			case 'RSA':
/*
SEQUENCE(3 elem)
	INTEGER							0
	SEQUENCE(2 elem)
		OBJECT IDENTIFIER			1.2.840.113549.1.1.1
		NULL
	OCTET STRING(1 elem)
		SEQUENCE(9 elem)
			INTEGER					0
			INTEGER(2047 bit)		151162365558548723872104645510163820602277233031184951756775213355301…
			INTEGER					65537
			INTEGER(2044 bit)		168445115839004124454579890162919630416166536891640402014088130847271…
			INTEGER(1024 bit)		150439542258000660814436210025849609239833700737115410528267857972834…
			INTEGER(1024 bit)		100480474275379299049013636292469555122573011202301485331234634341190…
			INTEGER(1023 bit)		806267983317822788721830025931602251390805026884117625065974982595762…
			INTEGER(1024 bit)		973190427488243436095051736219922335689049221976301445198913348918483…
			INTEGER(1024 bit)		110659984971411622188431412411155397287683213958155381552845963178193…
*/
				var privkey = this.getPrivateKey();
				
				der = asn1.getDER({
					type: jCastle.asn1.tagSequence,
					items: [{
						type: jCastle.asn1.tagInteger,
						intVal: 0 // version
					}, {
						type: jCastle.asn1.tagSequence,
						items: [{
							type: jCastle.asn1.tagOID,
							value: jCastle.oid.getOID("rsaEncryption")
						}, {
							type: jCastle.asn1.tagNull,
							value: null
						}]
					}, {
						type: jCastle.asn1.tagOctetString,
						value: {
							type: jCastle.asn1.tagSequence,
							items: [{
								type: jCastle.asn1.tagInteger,
								intVal: 0
							}, {
								type: jCastle.asn1.tagInteger,
								intVal: privkey.n
							}, {
								type: jCastle.asn1.tagInteger,
								intVal: privkey.e
							}, {
								type: jCastle.asn1.tagInteger,
								intVal: privkey.d
							}, {
								type: jCastle.asn1.tagInteger,
								intVal: privkey.p
							}, {
								type: jCastle.asn1.tagInteger,
								intVal: privkey.q
							}, {
								type: jCastle.asn1.tagInteger,
								intVal: privkey.dmp1
							}, {
								type: jCastle.asn1.tagInteger,
								intVal: privkey.dmq1
							}, {
								type: jCastle.asn1.tagInteger,
								intVal: privkey.iqmp
							}]
						}
					}]
				});
				break;

			case 'DSA':
			case 'KCDSA':
/*
SEQUENCE(3 elem)
	INTEGER						0
	SEQUENCE(2 elem)
		OBJECT IDENTIFIER		1.2.840.10040.4.1
		SEQUENCE(3 elem)
			INTEGER(2048 bit)	178603344521910810331025134906443426957028075706054818492858868432114…
			INTEGER(256 bit)	6740557547405118602307919070313939777208749178291490982581455316799392…
			INTEGER(2047 bit)	929636291285612574486849105691058687781469316110849390255544885189707…
	OCTET STRING(1 elem)
		INTEGER(255 bit)		4634705039688674346218177458887675782838098427960186805723182071401908…
*/
				var params = this.getParameters('object');
				var privkey = this.getPrivateKey();

				der = asn1.getDER({
					type: jCastle.asn1.tagSequence,
					items: [{
						type: jCastle.asn1.tagInteger,
						intVal: 0 // version
					}, {
						type: jCastle.asn1.tagSequence,
						items: [{
							type: jCastle.asn1.tagOID,
							value: this.pkiName == 'DSA'? jCastle.oid.getOID("dsaPublicKey") : jCastle.oid.getOID("kcdsa")
						}, {
							type: jCastle.asn1.tagSequence,
							items: [{
								type: jCastle.asn1.tagInteger,
								intVal: params.p
							}, {
								type: jCastle.asn1.tagInteger,
								intVal: params.q
							}, {
								type: jCastle.asn1.tagInteger,
								intVal: params.g
							}]
						}]
					}, {
						type: jCastle.asn1.tagOctetString,
						value: {
							type: jCastle.asn1.tagInteger,
							intVal: privkey
						}
					}]
				});
				break;

			case 'ECDSA':
			case 'ECKCDSA':
				var params = this.getParameters();
				var privkey = this.getPrivateKey();
				var pubkey = this.getPublicKey();
				var params_schema = null;

				if (params.OID && jCastle.pki.ecdsa.getParametersByOID(params.OID)) {
/*
SEQUENCE(3 elem)
	INTEGER 								0
	SEQUENCE(2 elem)
		OBJECT IDENTIFIER 					1.2.840.10045.2.1 ----- ecPublicKey
		OBJECT IDENTIFIER 					1.2.840.10045.3.1.7 ----- prime256v1
	OCTET STRING(1 elem)
		SEQUENCE(3 elem)
			INTEGER 						1
			OCTET STRING(32 byte)  			17551E79F3666266F99D4701860E665BE707C0E3F24571F57047FBA5025A5194
			[1](1 elem)
				BIT STRING(520 bit)  		0000010001001110000100111110100111111111000110000000010010100010111111…
*/				
					params_schema = {
						type: jCastle.asn1.tagOID,
						value: params.OID
					};

				} else {
/*

SEQUENCE(3 elem)
	INTEGER										0
	SEQUENCE(2 elem)
		OBJECT IDENTIFIER						1.2.840.10045.2.1
		SEQUENCE(6 elem)
			INTEGER								1
			SEQUENCE(2 elem)
				OBJECT IDENTIFIER				1.2.840.10045.1.1
				INTEGER(192 bit) 				6277101735386680763835789423207666416083908700390324961279 -- p
			SEQUENCE(3 elem)
				OCTET STRING(24 byte) 			FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC -- a
				OCTET STRING(24 byte) 			22123DC2395A05CAA7423DAECCC94760A7D462256BD56916 -- b
				BIT STRING(160 bit) 			1100010001101001011010000100010000110101110111101011001101111000110001… -- seed
			OCTET STRING(49 byte) 				047D29778100C65A1DA1783716588DCE2B8B4AEE8E228F189638A90F22637337334B49… -- g
			INTEGER(192 bit) 					6277101735386680763835789423166314882687165660350679936019 -- n
			INTEGER								1 -- h
	OCTET STRING(1 elem)
		SEQUENCE(3 elem)
			INTEGER								1
			OCTET STRING(24 byte) 				8AB70B2CAABC4763F82E2830F84209B22C329AA81BF6C045  -- x
			[1](1 elem)
				BIT STRING(392 bit) 			0000010011111001100011111010101000111110101000100011011110000001111010…  -- y


ECPrivateKey ::= SEQUENCE {
	version		INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
	privateKey	 OCTET STRING,
	parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
	publicKey  [1] BIT STRING OPTIONAL
}

*/
					if ('g' in params) {
						var g = params.g;
					} else {
						var g = '04' + params.gx + params.gy;
					}
					params_schema = {
						type: jCastle.asn1.tagSequence,
						items: [{
							type: jCastle.asn1.tagInteger,
							intVal: 1
						}, {
							type: jCastle.asn1.tagSequence,
							items: [{
								type: jCastle.asn1.tagOID,
								value: jCastle.oid.getOID(params.type)
							}, {
								type: jCastle.asn1.tagInteger,
								intVal: new BigInteger(params.p, 16)
							}]
						}, {
							type: jCastle.asn1.tagSequence,
							items: [{
								type: jCastle.asn1.tagOctetString,
								value: Buffer.from(params.a, 'hex').toString('latin1')
							}, {
								type: jCastle.asn1.tagOctetString,
								value: Buffer.from(params.b, 'hex').toString('latin1')
							}]
						}, {
							type: jCastle.asn1.tagOctetString,
							value: Buffer.from(g, 'hex').toString('latin1')
						}, {
							type: jCastle.asn1.tagInteger,
							intVal: new BigInteger(params.n, 16)
						}, {
							type: jCastle.asn1.tagInteger,
							intVal: params.h
						}]
					};

					if ('seed' in params && params.seed) {
						params_schema.items[2].items.push({
							type: jCastle.asn1.tagBitString,
							value: Buffer.from(params.seed, 'hex').toString('latin1')
						});
					}
				}

				var schema = {
					type: jCastle.asn1.tagSequence,
					items: [{
						type: jCastle.asn1.tagInteger,
						intVal: 0
					}, {
						type: jCastle.asn1.tagSequence,
						items: [{
							type: jCastle.asn1.tagOID,
							value: this.OID
						},
						params_schema 
						]
					}, {
						type: jCastle.asn1.tagOctetString,
						value: {
							type: jCastle.asn1.tagSequence,
							items: [{
								type: jCastle.asn1.tagInteger,
								intVal: 1
							}, {
								type: jCastle.asn1.tagOctetString,
								value: Buffer.from(privkey.toByteArrayUnsigned()).toString('latin1') // important!
							}, {
								tagClass: jCastle.asn1.tagClassContextSpecific,
								type: 0x01,
								constructed: true,
								items: [{
									type: jCastle.asn1.tagBitString,
									value: pubkey.encodePoint().toString('latin1') // public key
								}]
							}]
						}
					}]
				};

				der = asn1.getDER(schema);
				break;
			default:
				throw jCastle.exception("UNSUPPORTED_PKI", 'PKI060');
		}
		

		// if encypted
		var encrypted = '';
		if ('password' in options && options.password.length) {

			der = jCastle.pbe.asn1.encrypt(Buffer.from(der, 'latin1'), options);
			encrypted = 'ENCRYPTED ';
		}

		switch (format) {
			case 'der':
				return der;
			case 'pem':
				return "-----BEGIN " + encrypted + "PRIVATE KEY-----\n" +
					jCastle.util.lineBreak(Buffer.from(der, 'latin1').toString('base64'), 64) +
					"\n-----END " + encrypted + "PRIVATE KEY-----";
			case 'buffer':
				return Buffer.from(der, 'latin1');
			default:
				return Buffer.from(der, 'latin1').toString(format);
		}
	}

	/**
	 * exports PKCS#5 privateKey.
	 * 
	 * @public
	 * @param {object} options options object
	 *                 {buffer} password password for encryption of privateKey.
	 *                 {string} algo algorithm name. ex) 'aes128-CBC'.
	 *                 {string} format return type. 'der' | 'pem' | 'buffer'. (defualt: 'pem')
	 * @returns PKCS#5 privateKey.
	 */
	exportPrivateKeyPKCS5(options = {})
	{
		if (this.pkiName == '') throw jCastle.exception("PKI_NOT_SET", 'PKI061');

		var password = 'password' in options ? Buffer.from(options.password, 'latin1') : null;
		var format = 'format' in options ? options.format.toLowerCase() : 'pem';
		var asn1 = new jCastle.asn1();
		var der;
		
		switch (this.pkiName) {
			case 'RSA':
				var privkey = this.getPrivateKey();

				der = asn1.getDER({
					type: jCastle.asn1.tagSequence,
					items: [{
						type: jCastle.asn1.tagInteger,
						intVal: 0 // version
					}, {
						type: jCastle.asn1.tagInteger,
						intVal: privkey.n
					}, {
						type: jCastle.asn1.tagInteger,
						intVal: privkey.e
					}, {
						type: jCastle.asn1.tagInteger,
						intVal: privkey.d
					}, {
						type: jCastle.asn1.tagInteger,
						intVal: privkey.p
					}, {
						type: jCastle.asn1.tagInteger,
						intVal: privkey.q
					}, {
						type: jCastle.asn1.tagInteger,
						intVal: privkey.dmp1
					}, {
						type: jCastle.asn1.tagInteger,
						intVal: privkey.dmq1
					}, {
						type: jCastle.asn1.tagInteger,
						intVal: privkey.iqmp
					}]		
				});
				break;

			case 'DSA':
			case 'KCDSA':
/*
SEQUENCE(6 elem)
	INTEGER					0
	INTEGER(2048 bit) 		178603344521910810331025134906443426957028075706054818492858868432114…
	INTEGER(256 bit) 		6740557547405118602307919070313939777208749178291490982581455316799392…
	INTEGER(2047 bit) 		929636291285612574486849105691058687781469316110849390255544885189707…
	INTEGER(2047 bit) 		121732077429953631163473627988276921184717244206695728306501904869933…
	INTEGER(255 bit) 		4634705039688674346218177458887675782838098427960186805723182071401908…
*/
				var params = this.getParameters('object');
				var privkey = this.getPrivateKey();
				var pubkey = this.getPublicKey();

				der = asn1.getDER({
					type: jCastle.asn1.tagSequence,
					items: [{
						type: jCastle.asn1.tagInteger,
						intVal: 0
					}, {
						type: jCastle.asn1.tagInteger,
						intVal: params.p
					}, {
						type: jCastle.asn1.tagInteger,
						intVal: params.q
					}, {
						type: jCastle.asn1.tagInteger,
						intVal: params.g
					}, {
						type: jCastle.asn1.tagInteger,
						intVal: pubkey
					}, {
						type: jCastle.asn1.tagInteger,
						intVal: privkey
					}]
				});
				break;

			case 'ECDSA':
			case 'ECKCDSA':
				var params = this.getParameters();
				var privkey = this.getPrivateKey();
				var pubkey = this.getPublicKey();
				var params_schema = null;

				if (params.OID && jCastle.pki.ecdsa.getParametersByOID(params.OID)) {
/*
SEQUENCE(4 elem)
	INTEGER 								1
	OCTET STRING(32 byte) 					17551E79F3666266F99D4701860E665BE707C0E3F24571F57047FBA5025A5194
	[0](1 elem)
		OBJECT IDENTIFIER 					1.2.840.10045.3.1.7 ----- prime256v1
	[1](1 elem)
		BIT STRING(520 bit) 				0000010001001110000100111110100111111111000110000000010010100010111111…
*/
					params_schema = {
						type: jCastle.asn1.tagOID,
						value: params.OID
					}
				} else {
/*
SEQUENCE(4 elem)
	INTEGER									1
	OCTET STRING(24 byte) 					77CCA1684F3DF45687DECC3C683E05FEFB6931504B7D5AA6 -- x
	[0](1 elem)
		SEQUENCE(6 elem)
			INTEGER 						1
			SEQUENCE(2 elem)
				OBJECT IDENTIFIER			1.2.840.10045.1.1
				INTEGER(192 bit) 			6277101735386680763835789423207666416083908700390324961279
			SEQUENCE(3 elem)
				OCTET STRING(24 byte) 		FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC
				OCTET STRING(24 byte) 		22123DC2395A05CAA7423DAECCC94760A7D462256BD56916
				BIT STRING(160 bit) 		1100010001101001011010000100010000110101110111101011001101111000110001…
			OCTET STRING(49 byte) 			047D29778100C65A1DA1783716588DCE2B8B4AEE8E228F189638A90F22637337334B49…
			INTEGER(192 bit) 				6277101735386680763835789423166314882687165660350679936019
			INTEGER							1
	[1](1 elem)
		BIT STRING(392 bit) 				0000010000011011001001011111000110010100100001100010011010100111000101… -- y



ECPrivateKey ::= SEQUENCE {
	version		INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
	privateKey	 OCTET STRING,
	parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
	publicKey  [1] BIT STRING OPTIONAL
}
*/
					var g;
					if ('g' in params) {
						g = params.g;
					} else {
						g = '04' + params.gx + params.gy;
					}

					params_schema = {
						type: jCastle.asn1.tagSequence,
						items: [{
							type: jCastle.asn1.tagInteger,
							intVal: 1
						}, {
							type: jCastle.asn1.tagSequence,
							items: [{
								type: jCastle.asn1.tagOID,
								value: jCastle.oid.getOID(params.type)
							}, {
								type: jCastle.asn1.tagInteger,
								intVal: new BigInteger(params.p, 16)
							}]
						}, {
							type: jCastle.asn1.tagSequence,
							items: [{
								type: jCastle.asn1.tagOctetString,
								value: Buffer.from(params.a, 'hex').toString('latin1')
							}, {
								type: jCastle.asn1.tagOctetString,
								value: Buffer.from(params.b, 'hex').toString('latin1')
							}]
						}, {
							type: jCastle.asn1.tagOctetString,
							value: Buffer.from(g, 'hex').toString('latin1')
						}, {
							type: jCastle.asn1.tagInteger,
							intVal: new BigInteger(params.n, 16)
						}, {
							type: jCastle.asn1.tagInteger,
							intVal: params.h
						}]
					};

					if ('seed' in params && params.seed) {
						params_schema.items[2].items.push({
							type: jCastle.asn1.tagBitString,
							value: Buffer.from(params.seed, 'hex').toString('latin1')
						});
					}
/*
SEQUENCE(4 elem)
	INTEGER 								1
	OCTET STRING(32 byte) 					17551E79F3666266F99D4701860E665BE707C0E3F24571F57047FBA5025A5194
	[0](1 elem)
		OBJECT IDENTIFIER 					1.2.840.10045.3.1.7 ----- prime256v1
	[1](1 elem)
		BIT STRING(520 bit) 				0000010001001110000100111110100111111111000110000000010010100010111111…
*/
				}
/*
				var der = asn1.getDER({
					type: jCastle.asn1.tagSequence,
					items: [{
						type: jCastle.asn1.tagInteger,
						value: 1
						}, {
						type: jCastle.asn1.tagOctetString,
						value: ByteBuffer.parseArray(privkey.toByteArrayUnsigned()).toString('utf8')
					}, {
						tagClass: jCastle.asn1.tagClassContextSpecific,
						type: 0x00,
						constructed: true,
						items: [params_schema]
					}, {
						tagClass: jCastle.asn1.tagClassContextSpecific,
						type: 0x01,
						constructed: true,
						items: [{
							type: jCastle.asn1.tagBitString,
							value: pubkey.encodePoint() // public key
						}]
					}]
				});
*/
				var schema = {
					type: jCastle.asn1.tagSequence,
					items: [{
						type: jCastle.asn1.tagInteger,
						intVal: 1
						}, {
						type: jCastle.asn1.tagOctetString,
						value: Buffer.from(privkey.toByteArrayUnsigned()).toString('latin1') // important!
					}]
				};

				if (!('noParameters' in options) || !options.noParameters) {
					schema.items.push({
						tagClass: jCastle.asn1.tagClassContextSpecific,
						type: 0x00,
						constructed: true,
						items: [params_schema]
					});
				}
						
				if (!('noPublicKey' in options) || !options.noPublicKey) {
					schema.items.push({
						tagClass: jCastle.asn1.tagClassContextSpecific,
						type: 0x01,
						constructed: true,
						items: [{
							type: jCastle.asn1.tagBitString,
							value: pubkey.encodePoint().toString('latin1') // public key
						}]
					});
				}

				der = asn1.getDER(schema);
				break;
			default:
				throw jCastle.exception("UNSUPPORTED_PKI", 'PKI062');
		}

		if (!password || !password.length) {

			switch (format) {
				case 'der':
					return der;
				case 'pem':
					return "-----BEGIN " + (this.pkiName == 'ECDSA' ? 'EC' : this.pkiName.toUpperCase()) + " PRIVATE KEY-----\n" + 
							jCastle.util.lineBreak(Buffer.from(der, 'latin1').toString('base64'), 64) +
							"\n-----END " + (this.pkiName == 'ECDSA' ? 'EC' : this.pkiName.toUpperCase()) + " PRIVATE KEY-----";
				case 'buffer':
					return Buffer.from(der, 'latin1');
				default:
					return Buffer.from(der, 'latin1').toString(format);
			}
		}

		// encryption
/*
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,584BBCF38BE41D90AB16740EE5D2E24C

k5m1gaYDbX+EYPcv/+wvSsYOkBpOxFYXbzMYY8Z2d39mfQ8Y+WzOJnWWYT2tj2d8
...snip...
KmpQTLFiCqXrWNRQVbvvmCpuq/dHJL2aeE9Y/JcOH+yt9YEPB7hPZyXM15AVxVfL
-----END RSA PRIVATE KEY-----
*/
		var algo_name = options.algoName || options.algo || 'AES-128';
		algo_name = algo_name.toUpperCase();

		var algo_mode = 'mode' in options ? options.mode.toUpperCase() : 'CBC';
		var algo_info = jCastle.mcrypt.getAlgorithmInfo(algo_name);
		var key_size = algo_info.keySize;
		var block_size = algo_info.blockSize;
		var iv;


		if('iv' in options) {
			iv = options.iv;
			if (!Buffer.isBuffer(iv)) iv = Buffer.from(iv, 'latin1');
		} else {
			// create a random iv
//			var iv = jCastle.mcrypt.createInitialVector(block_size, 'utf8');
			iv = new jCastle.prng().nextBytes(block_size, true);
		}

		// create a key
		var salt = iv.slice(0, 8);
		var dk = jCastle.kdf.pkcs5DeriveKey(password, salt, key_size + block_size, 'MD5');
		var key = dk.slice(0, key_size);
		var crypto = new jCastle.mcrypt(algo_name);
		crypto.start({
//			algoName: algo_name,
			key: key,
			mode: algo_mode,
			iv: iv,
			isEncryption: true,
			padding: 'pkcs7'
		});
		crypto.update(Buffer.from(der, 'latin1'));
		var enc_der = crypto.finalize();

		switch (format) {
			case 'der':
				return {
					pkiName: this.pkiName,
					algo: algo_name,
					mode: algo_mode,
					iv: iv.toString('latin1'),
					data: enc_der.toString('latin1')
				};
			case 'hex':
				return {
					pkiName: this.pkiName,
					algo: algo_name,
					mode: algo_mode,
					iv: iv.toString('hex'),
					data: enc_der.toString('hex')
				};
			case 'base64':
				return {
					pkiName: this.pkiName,
					algo: algo_name,
					mode: algo_mode,
					iv: iv.toString('base64'),
					data: enc_der.toString('base64')
				};
			case 'pem':
			default:
				return "-----BEGIN " + (this.pkiName == 'ECDSA' ? 'EC' : this.pkiName.toUpperCase()) + " PRIVATE KEY-----\n" + 
					"Proc-Type: 4,ENCRYPTED\n" + 
					"DEK-Info: " + algo_name + '-' + algo_mode + ',' + iv.toString('hex').toUpperCase() + "\n\n" +
					jCastle.util.lineBreak(enc_der.toString('base64'), 64) +
					"\n-----END " + (this.pkiName == 'ECDSA' ? 'EC' : this.pkiName.toUpperCase()) + " PRIVATE KEY-----";
		}
	}



/*
Two types of public key pem:

openssl rsa -in key.pem -RSAPublicKey_out -out pubkey.pem

-----BEGIN RSA PUBLIC KEY-----
MIIBCQKCAQB3vmBxb45MZqh9L1Lck0nd1h+wpBnJkbWDRWYWBOHUv4R/A+dIfWJS
DcKUEV0rUU+9CY9Bpox+fLff2Dhl5iSScGDuJrpXSExWTA+GPHBYxjqe/j3M6kH/
LGhy6BztLg59itVxGJLW/VEEvC4TG8Ms6Z/aOTo04XLCt29mLhpM0OvghJwdlzeK
jaSao87pK8aGcALUUQhr6PdlraLnEwOU4UyyrGDizS2Tjd/h3yj0H3TZP+V/A3+i
damrIKC31t/SYhZbMrxyMaDS9ufNw18g8XrAQHKCXbOq9sRIYWpPwbuwkuOSZl53
tH8PchkwODXB3p39nbMnqflLNGRxNVhRAgMBAAE=
-----END RSA PUBLIC KEY-----

SEQUENCE(2 elem)
INTEGER(2047 bit)		151162365558548723872104645510163820602277233031184951756775213355301…
INTEGER					65537



openssl rsa -in key.pem -pubout -out pubkey.pem

-----BEGIN PUBLIC KEY-----
MIIBITANBgkqhkiG9w0BAQEFAAOCAQ4AMIIBCQKCAQB3vmBxb45MZqh9L1Lck0nd
1h+wpBnJkbWDRWYWBOHUv4R/A+dIfWJSDcKUEV0rUU+9CY9Bpox+fLff2Dhl5iSS
cGDuJrpXSExWTA+GPHBYxjqe/j3M6kH/LGhy6BztLg59itVxGJLW/VEEvC4TG8Ms
6Z/aOTo04XLCt29mLhpM0OvghJwdlzeKjaSao87pK8aGcALUUQhr6PdlraLnEwOU
4UyyrGDizS2Tjd/h3yj0H3TZP+V/A3+idamrIKC31t/SYhZbMrxyMaDS9ufNw18g
8XrAQHKCXbOq9sRIYWpPwbuwkuOSZl53tH8PchkwODXB3p39nbMnqflLNGRxNVhR
AgMBAAE=
-----END PUBLIC KEY-----

SEQUENCE(2 elem)
	SEQUENCE(2 elem)
		OBJECT IDENTIFIER			1.2.840.113549.1.1.1
		NULL
	BIT STRING(1 elem)
		SEQUENCE(2 elem)
			INTEGER(2047 bit)		151162365558548723872104645510163820602277233031184951756775213355301…
			INTEGER					65537

*/

/*
The PEM public key format uses the header and footer lines:

 -----BEGIN PUBLIC KEY-----
 -----END PUBLIC KEY-----


RSAPublicKey ::= SEQUENCE {
	SEQUENCE {
		Object Identifier 		1.2.840.113549.1.1.1
		NULL
	},
	BitString := SEQUENCE {
    	modulus           INTEGER,  -- n
    	publicExponent    INTEGER   -- e
	}
}
*/
	/**
	 * exports publicKey.
	 * 
	 * @public
	 * @param {object} options options object
	 *                 {string} type type for pem format. 'pkcs5' | 'pkcs8'
	 *                 {string} format return type. 'der' | 'pem' | 'buffer'. (defualt: 'pem')
	 * @returns publicKey.
	 */
	exportPublicKey(options = {})
	{
		if (this.pkiName == '') throw jCastle.exception("PKI_NOT_SET", 'PKI064');

		var type = 'type' in options ? options.type.toLowerCase() : 'pkcs#8';
		if (type === 'pkcs#5' || type === 'pkcs5') {
			return this.exportPublicKeyPKCS5(options);
		}

		var format = 'format' in options ? options.format.toLowerCase() : 'pem';
		var asn1 = new jCastle.asn1();
		var der;

		switch (this.pkiName) {
			case 'RSA':
				var pubkey = this.getPublicKey();

				der = asn1.getDER({
					type: jCastle.asn1.tagSequence,
					items: [{
						type: jCastle.asn1.tagSequence,
						items: [{
							type: jCastle.asn1.tagOID,
							value: jCastle.oid.getOID("rsaEncryption") //"1.2.840.113549.1.1.1"
						}, {
							type: jCastle.asn1.tagNull,
							value: null
						}]
					}, {
						type: jCastle.asn1.tagBitString,
						value: {
							type: jCastle.asn1.tagSequence,
							items: [{
								type: jCastle.asn1.tagInteger,
								intVal: pubkey.n
							}, {
								type: jCastle.asn1.tagInteger,
								intVal: pubkey.e
							}]
						}			
					}]
				});
				break;

			case 'DSA':
			case 'KCDSA':
/*
SEQUENCE(2 elem)
	SEQUENCE(2 elem)
		OBJECT IDENTIFIER			1.2.840.10040.4.1
		SEQUENCE(3 elem)
			INTEGER(2048 bit) 		178603344521910810331025134906443426957028075706054818492858868432114…
			INTEGER(256 bit) 		6740557547405118602307919070313939777208749178291490982581455316799392…
			INTEGER(2047 bit) 		929636291285612574486849105691058687781469316110849390255544885189707…
	BIT STRING(1 elem)
		INTEGER(2047 bit) 			121732077429953631163473627988276921184717244206695728306501904869933…
*/
				var params = this.getParameters('object');
				var pubkey = this.getPublicKey();

				der = asn1.getDER({
					type: jCastle.asn1.tagSequence,
					items: [{
						type: jCastle.asn1.tagSequence,
						items: [{
							type: jCastle.asn1.tagOID,
							value: this.pkiName == 'DSA' ? jCastle.oid.getOID("dsaPublicKey") /* '1.2.840.10040.4.1' */ : jCastle.oid.getOID("kcdsa") /* '1.2.410.200004.1.1' */
						}, {
							type: jCastle.asn1.tagSequence,
							items: [{
								type: jCastle.asn1.tagInteger,
								intVal: params.p
							}, {
								type: jCastle.asn1.tagInteger,
								intVal: params.q
							}, {
								type: jCastle.asn1.tagInteger,
								intVal: params.g
							}]
						}]
					}, {
						type: jCastle.asn1.tagBitString,
						value: {
							type: jCastle.asn1.tagInteger,
							intVal: pubkey // public key
						}
					}]
				});
				break;

			case 'ECDSA':
			case 'ECKCDSA':
				var params = this.getParameters();
				var pubkey = this.getPublicKey();
				var params_schema;
/*
SEQUENCE(2 elem)
	SEQUENCE(2 elem)
		OBJECT IDENTIFIER					1.2.840.10045.2.1
		OBJECT IDENTIFIER					1.2.840.10045.3.1.3
	BIT STRING(392 bit) 					0000010011111001100011111010101000111110101000100011011110000001111010…


SubjectPublicKeyInfo  ::=  SEQUENCE  {
	algorithm         AlgorithmIdentifier,
	subjectPublicKey  BIT STRING
}

AlgorithmIdentifier  ::=  SEQUENCE  {
	algorithm   OBJECT IDENTIFIER,
	parameters  ANY DEFINED BY algorithm OPTIONAL
}

*/
				if (params.OID && jCastle.pki.ecdsa.getParametersByOID(params.OID)) {
					params_schema = {
						type: jCastle.asn1.tagOID,
						value: params.OID
					}
				} else {
					var g;
					if ('g' in params) {
						g = params.g;
					} else {
						g = '04' + params.gx + params.gy;
					}
					params_schema = {
						type: jCastle.asn1.tagSequence,
						items: [{
							type: jCastle.asn1.tagInteger,
							intVal: 1
						}, {
							type: jCastle.asn1.tagSequence,
							items: [{
								type: jCastle.asn1.tagOID,
								value: jCastle.oid.getOID(params.type)
							}, {
								type: jCastle.asn1.tagInteger,
								intVal: new BigInteger(params.p, 16)
							}]
						}, {
							type: jCastle.asn1.tagSequence,
							items: [{
								type: jCastle.asn1.tagOctetString,
								value: Buffer.from(params.a, 'hex').toString('latin1')
							}, {
								type: jCastle.asn1.tagOctetString,
								value: Buffer.from(params.b, 'hex').toString('latin1')
							}]
						}, {
							type: jCastle.asn1.tagOctetString,
							value: Buffer.from(g, 'hex').toString('latin1')
						}, {
							type: jCastle.asn1.tagInteger,
							intVal: new BigInteger(params.n, 16)
						}, {
							type: jCastle.asn1.tagInteger,
							intVal: params.h
						}]
					};

					if ('seed' in params && params.seed) {
						params_schema.items[2].items.push({
							type: jCastle.asn1.tagBitString,
							value: Buffer.from(params.seed, 'hex').toString('latin1')
						});
					}
				}

				der = asn1.getDER({
					type: jCastle.asn1.tagSequence,
					items: [{
						type: jCastle.asn1.tagSequence,
						items: [{
							type: jCastle.asn1.tagOID,
							value: this.OID
						},
							params_schema
						]
					}, {
						type: jCastle.asn1.tagBitString,
						value: pubkey.encodePoint().toString('latin1')
					}]
				});
				break;
			default:
				throw jCastle.exception("UNSUPPORTED_PKI", 'PKI065');
		}

		switch (format) {
			case 'der':
				return der;
			case 'pem':
				return "-----BEGIN PUBLIC KEY-----\n" +
					jCastle.util.lineBreak(Buffer.from(der, 'latin1').toString('base64'), 64) +
					"\n-----END PUBLIC KEY-----";
			case 'buffer':
				return Buffer.from(der, 'latin1');
			default:
				return Buffer.from(der, 'latin1').toString(format);
		}
	}

	/**
	 * exports PKCS#5 publicKey.
	 * 
	 * @public
	 * @param {object} options options object
	 *                 {string} format return type. 'der' | 'pem' | 'buffer'. (defualt: 'pem')
	 * @returns PKCS#5 publicKey.
	 */
	exportPublicKeyPKCS5(options = {})
	{
		if (this.pkiName == '') throw jCastle.exception("PKI_NOT_SET", 'PKI066');

		var format = 'format' in options ? options.format.toLowerCase() : 'pem';
		var asn1 = new jCastle.asn1();
		var der;

		switch (this.pkiName) {
			case 'RSA':
				var pubkey = this.getPublicKey();

				der = asn1.getDER({
					type: jCastle.asn1.tagSequence,
					items: [{
						type: jCastle.asn1.tagInteger,
						intVal: pubkey.n
					}, {
						type: jCastle.asn1.tagInteger,
						intVal: pubkey.e
					}]
				});
				break;

			case 'DSA':
			case 'KCDSA':
/*
http://opensource.apple.com/source/ruby/ruby-96/ruby/test/openssl/test_pkey_dsa.rb

-----BEGIN DSA PUBLIC KEY-----
MIHfAkEAyJSJ+g+P/knVcgDwwTzC7Pwg/pWs2EMd/r+lYlXhNfzg0biuXRul8VR4
VUC/phySExY0PdcqItkR/xYAYNMbNwJBAOoV57X0FxKO/PrNa/MkoWzkCKV/hzhE
p0zbFdsicw+hIjJ7S6Sd/FlDlo89HQZ2FuvWJ6wGLM1j00r39+F2qbMCFQCrkhIX
SG+is37hz1IaBeEudjB2HQJAR0AloavBvtsng8obsjLb7EKnB+pSeHr/BdIQ3VH7
fWLOqqkzFeRrYMDzUpl36XktY6Yq8EJYlW9pCMmBVNy/dQ==
-----END DSA PUBLIC KEY-----


SEQUENCE(4 elem)
	INTEGER(512 bit) 1050523907498276150424082342242281336272149889604071975946029630630585…					y
	INTEGER(512 bit) 1226005593687129356582771238521252910640044452144966332557663457996163…					p
	INTEGER(160 bit) 979494906553787301107832405790107343409973851677											q
	INTEGER(511 bit) 3731695366899846297271147240305742456317979984190506040697507048095553…					g
*/
				var params = this.getParameters('object');
				var pubkey = this.getPublicKey();

				der = asn1.getDER({
					type: jCastle.asn1.tagSequence,
					items: [{
						type: jCastle.asn1.tagInteger,
						intVal: pubkey
					}, {
						type: jCastle.asn1.tagInteger,
						intVal: params.p
					}, {
						type: jCastle.asn1.tagInteger,
						intVal: params.q
					}, {
						type: jCastle.asn1.tagInteger,
						intVal: params.g
					}]
				});
				break;

			case 'ECDSA':
			case 'ECKCDSA':
/*
http://pastebin.com/G3ErZatg
*** This seems to be wrong. ***

-----BEGIN EC PUBLIC KEY-----
RUNTMzAAAABMrWvMrqah61dhnjTXm8YYZzgE2TtVO8d5DCHak7wjrJ21VIvl/Bou
L7Hyp/aHiDReIs+nGT7VsNp+CPaGt3Ek5V8DMmNxb5jl2mlgVq/Fvwu/Ktuhso49
/Vc582SH1gg=
-----END EC PUBLIC KEY-----

Application 5(67 byte) 					5333300000004CAD6BCCAEA6A1EB57619E34D79BC618673804D93B553BC7790C21DA93…

-----BEGIN EC PRIVATE KEY-----
RUNTNDAAAABMrWvMrqah61dhnjTXm8YYZzgE2TtVO8d5DCHak7wjrJ21VIvl/Bou
L7Hyp/aHiDReIs+nGT7VsNp+CPaGt3Ek5V8DMmNxb5jl2mlgVq/Fvwu/Ktuhso49
/Vc582SH1ggkTg5HnE3IaucuTV/Rtdub4JktPk2fb3vIJgGiTsLeAuE6KvBfXTGX
RoZsNRSriqg=
-----END EC PRIVATE KEY-----

Application 5(67 byte)					5334300000004CAD6BCCAEA6A1EB57619E34D79BC618673804D93B553BC7790C21DA93…

2019.12.28
reference:
https://stackoverflow.com/questions/48101258/how-to-convert-an-ecdsa-key-to-pem-format
https://bitcoin.stackexchange.com/questions/66594/signing-transaction-with-ssl-private-key-to-pem

*/
//			var params = this.getParameters();
//			var pubkey = this.getPublicKey();
//
//			var der = asn1.getDER({
//				tagClass: jCastle.asn1.tagClassApplication,
//				type: 0x05,
//				constructed: false,
//				value: pubkey.encodePoint()
//			});
//			break;
			default:
				throw jCastle.exception("UNSUPPORTED_PKI", 'PKI067');
		}
		
		switch (format) {
			case 'der':
				return der;
			case 'pem':
				return "-----BEGIN " + (this.pkiName == 'EC' ? 'ECDSA' : this.pki.toUpperCase()) + " PUBLIC KEY-----\n" + 
					jCastle.util.lineBreak(Buffer.from(der, 'latin1').toString('base64'), 64) +
					"\n-----END " + (this.pkiName == 'EC' ? 'ECDSA' : this.pki.toUpperCase()) + " PUBLIC KEY-----";
			case 'buffer':
				return Buffer.from(der, 'latin1');
			default:
				return Buffer.from(der, 'latin1').toString(format);
		}
	}

	/**
	 * parse parameters
	 * 
	 * @public
	 * @param {mixed} pem parameters pem string or buffer
	 * @returns this class instance.
	 */
	parseParameters(pem)
	{
		if (this.pkiName == '') throw jCastle.exception("PKI_NOT_SET", 'PKI068');

		var pki_name = this.pkiName;
		if (pki_name == 'ECDSA' || pki_name == 'ECKCDSA') pki_name = 'EC';
		if (pki_name == 'ELGAMAL') pki_name = 'DSA';

		var format = jCastle.util.seekPemFormat(pem);
		var der, sequence, asn1;

		asn1 = new jCastle.asn1();
		//asn1.ignoreLengthError();

		if (format === 'asn1') {
			sequence = pem;
		} else {
			switch (format) {
				case 'pem':
					p = "-----(BEGIN|END) "  + pki_name + " PARAMETERS-----";
					var regex = new RegExp(p, "g");
					pem = pem.replace(regex, '').replace(/[\r\n]/g, '');
					der = Buffer.from(pem, 'base64');
					break;
				case 'der':
					der = pem;
					break;
				case 'hex':
					der = Buffer.from(pem, 'hex');
					break;
				case 'base64':
					der = Buffer.from(pem, 'base64');
					break;
				case 'buffer':
				default:
					der = Buffer.from(pem);
					break;
					//throw jCastle.exception("INVALID_PEM_FORMAT", 'PKI069');
			}

			try {
				sequence = asn1.parse(der);
			} catch (e) {
				throw jCastle.exception("INVALID_PEM_FORMAT", 'PKI070');
			}
			
			if (!jCastle.asn1.isSequence(sequence)) {
				throw jCastle.exception("INVALID_PEM_FORMAT", 'PKI071');
			}
		}

		switch (this.pkiName) {
			case 'DSA':
			case 'KCDSA':
			case 'ELGAMAL':
/*
-----BEGIN DSA PARAMETERS-----
MIICLAKCAQEAjXspeahIbDpFfSxWBn0lUuB79GXOUqY0yBqU+QfPWrK8tY1EXgEH
Apd113b+D3ihkzIEtr/jWKWuHI1nBfx7Gu6NaNrfh7TbiFAvYTfXIHkvaRG4edwK
LtFe2fFIPhaqlvtuo04zdhCMdyUcQerY1aOipn5Q4djCYlWvay0pxKV3Q2x/ZE3M
m5wbiQrKcXD8jSzAu979dgrmVDJblx3QarznyzBeclZ7g8RNCdz3r9A6huafQ0Th
CAxUrna1fd/6lxojs5RCYV5m83oa2y4lYOCGtviHeOQmY3WnoiMqqKVG3/OYn9Hl
OE1GcTszJwNaa/no4cKalToAxJW7F6KciQIhAJUGNCdjxzgA7i25OP0Ere60VP+K
O5HPwUVRbKtBuRr/AoIBAEmkMXEAp/YvCh70savzWno7Tq5tGsq4eU3w6Q12a1GK
OdrR7AS4dByaUfLCo3zdIuY8/LRLzn+61RMHNbUXh2Fmt4LCVwTRmpCI9Ivx7laD
Z9qXLoAadFRBr3Bx3qrgIyaHskJBSsqzG8lkdKuf6hhM1M/eNtQsrF9R1sck+5PO
WqFYvD2PKNeuhtXNNReYE4PJmr1XmaNVWIrzr7z62qgeC3sEkFbBrm4gQjwwmBcZ
gD4yM20m6qm2ZvrOipwsXMwkEmP5oc3BRZyLiT36CBgVvskj9ayR1y0erFrqXltP
Cyzi8JXyf8HgjQcMrhLbBO3Bn0G6eQBP/MQiLEukYAw=
-----END DSA PARAMETERS-----

SEQUENCE(3 elem)
	INTEGER(2048 bit) 		178603344521910810331025134906443426957028075706054818492858868432114…
	INTEGER(256 bit) 		6740557547405118602307919070313939777208749178291490982581455316799392…
	INTEGER(2047 bit) 		929636291285612574486849105691058687781469316110849390255544885189707…


(This kcdsa sample made by jacobswell)

-----BEGIN KCDSA PARAMETERS-----
MIIDLAKCAYEA9JHxmTYUSTH9QrOoAPbfdCcwyjJdYivSO/DeycylHR0beb9wWojH
upQ+BpEa/3wsuaL/vjEWhTI4sTUXThEHrvCRRJdisqpIrrG9MjfmFcPsxJGqu/HZ
P+qVZTD5cbfESxZcaMTz3l8VOEf/rI1Jqr/LO4CGqDXRTWz6UWVyWAdhRFNqt0xT
xXcccKNq7LvEZMAUJX4nVkLkA7QN/vCVPJ87/fSC3ngFeivxA/14az7+U6fPHu+M
Jok8VWj1tyyTkIQHpQyloTsOaF1Nl1t1Raw0u5EeV3UzHTkqJrdLSH0nI59O2lGo
7ZJt7kuZY4boDzs7WrkOO0oy9EW1D5T7DEOPgl1w2P8qeRV6u2eQ4wPWR5+3oHVZ
5DCZ85aJHq3vaZnfVYhb4XxxKjxv6YqMSm8Po0T+BqX5qxh2CVL/LWCycTC3vU2r
jmxOKWtovN7Zu3cOtjjrTtEt9mZ0UOd9KCdTlwYCOIv/vwNr1x4NL6RVwwmM72J6
ugKYYzZkZQv3AiEA3BIdPxPsOey0vU/G0I0sG/ZlYrHk0/NEolRvEVGCEpMCggGA
fFTxj+Zh5tUEZ0YUBhfiTsNg4zDpVmGl3jj0LDFIWAa0c7EUG7lmzsGUbJaS5Gqh
rcTFjWmsYM4SNErZtWYREuI0hIvVAGCuHZSAUNAoxewJtA+A6cQhlZth1CV6ADV4
czTRUhhTFkXxrjT5VMijCQV6RRZSpZTzflk6Sbzge8uk76mlVeYTVcN0EFWhnlGM
5zXBti1Te3IhAEzRfGNUhI5KLnPFkLTpc4ehCOMS/jSRoed2KL5eoS5E8pgz4yFE
nh1GZtIPyMLqMIlFxIHoMcefHHGIStsfDkwh9F1GmPjqdnEOw25pjqVhktNd/DXY
zyFGUbhE1PofQVIwaWEyOMgCr+zzlDOBNfrLKXFCe9CyN8gkV7VujOLlwdu9gdFV
iMMb67jtfuJFATziWD2ZJlO/07l2HqQIHQHfgEEAvgnaoBTYdqv8coUZZ8cdM75X
WHigK5NCaS1UeQ+O5SXht7T/C0loZtRplhjB6Mm/DWlFjDq9yVf0QwreN/ggAMBx
-----END KCDSA PARAMETERS-----
*/		
				/*
				Dss-Parms  ::=  SEQUENCE  {
				p             INTEGER,
				q             INTEGER,
				g             INTEGER  }
				*/
				this.setParameters({
					p: sequence.items[0].intVal,
					q: sequence.items[1].intVal,
					g: sequence.items[2].intVal
				});
				break;

			case 'ECDSA':
			case 'ECKCDSA':
/*		
-----BEGIN EC PARAMETERS-----
BggqhkjOPQMBBw==
-----END EC PARAMETERS-----

OBJECT IDENTIFIER 							1.2.840.10045.3.1.7
*/
				if (sequence.name == 'OID') {
					var params = jCastle.pki.ecdsa.getParametersByOID(sequence.value);
					this.setParameters(params);
				} else {
					/*
					EC-parameters::= SEQUENCE {
						version 					INTEGER
						SEQUENCE {
							1.2.840.10045.1.1 		OID
							p 			 			INTEGER
						}
						SEQUENCE {
							a 						OCTET STRING
							b 						OCTET STRING
						}
						G (uncompressed)			OCTET STRING
						n (order)					INTEGER
						cofactor 					INTEGER
					}
					*/
					var type = jCastle.oid.getName(sequence.items[1].items[0].value);

					var params = {
						p: sequence.items[1].items[1].intVal.toString(16),
						a: Buffer.from(sequence.items[2].items[0].value, 'latin1').toString('hex'),
						b: Buffer.from(sequence.items[2].items[1].value, 'latin1').toString('hex'),
						g: Buffer.from(sequence.items[3].value, 'latin1').toString('hex'),
						n: sequence.items[4].intVal.toString(16),
						h: sequence.items[5].intVal
					};

					var curveName = jCastle.pki.ecdsa.getCurveNameByParams(params);
					var oid = null;
					if (!curveName) {
						curveName = '';
					} else {
						var p = jCastle.pki.ecdsa._registeredParams[curveName];
						oid = p.OID;
					}

					this.setParameters({
						p: params.p,
						a: params.a,
						b: params.b,
						g: params.g,
						n: params.n,
						h: params.h,
						curveName: curveName, 
						type: type,
						OID: oid,
						seed: null 
					});
				}
				break;

			default: 
				throw jCastle.exception("UNSUPPORTED_PKI_METHOD", 'PKI072');
		}

		return this;
	}

	/**
	 * export parameters.
	 * 
	 * @public
	 * @param {object} options options object
	 *                 {string} format return type. 'pem' | 'der' | 'buffer'. (default: 'pem')
	 * @returns parameters pem or buffer.
	 */
	exportParameters(options = {})
	{
		if (this.pkiName == '') throw jCastle.exception("PKI_NOT_SET", 'PKI073');

		var pki_name = this.pkiName;
		if (pki_name == 'ELGAMAL') pki_name = 'DSA';
		
		var format = 'format' in options ? options.format.toLowerCase() : 'pem';
		var der;

		switch (this.pkiName) {
			case 'DSA':
			case 'KCDSA':
			case 'ELGAMAL':
				var params = this.getParameters('object');

				var asn1 = new jCastle.asn1();
				der = asn1.getDER({
					type: jCastle.asn1.tagSequence,
					items:[{
						type: jCastle.asn1.tagInteger,
						intVal: params.p
					}, {
						type: jCastle.asn1.tagInteger,
						intVal: params.q
					}, {
						type: jCastle.asn1.tagInteger,
						intVal: params.g
					}]
				});
				break;

			case 'ECDSA':
			case 'ECKCDSA':
			/*
			EC-parameters::= SEQUENCE {
				version 					INTEGER
				SEQUENCE {
					1.2.840.10045.1.1 		OID
					p 			 			INTEGER
				}
				SEQUENCE {
					a 						OCTET STRING
					b 						OCTET STRING
				}
				G (uncompressed)			OCTET STRING
				n (order)					INTEGER
				cofactor 					INTEGER
			}
			*/
				pki_name = 'EC';

				var params = this.getParameters();

				der = new jCastle.asn1().getDER({
					type: jCastle.asn1.tagSequence,
					items: [{
						type: jCastle.asn1.tagInteger,
						intVal: 0x01
					}, {
						type: jCastle.asn1.tagSequence,
						items: [{
							type: jCastle.asn1.tagOID,
							value: jCastle.oid.getOID(params.type)
						}, {
							type: jCastle.asn1.tagInteger,
							intVal: new BigInteger(params.p, 16)
						}]
					}, {
						type: jCastle.asn1.tagSequence,
						items: [{
							type: jCastle.asn1.tagOctetString,
							value: Buffer.from(params.a, 'hex').toString('latin1')
						}, {
							type: jCastle.asn1.tagOctetString,
							value: Buffer.from(params.b, 'hex').toString('latin1')
						}]
					}, {
						type: jCastle.asn1.tagOctetString,
						value: Buffer.from('04' + params.gx + params.gy, 'hex').toString('latin1')
					}, {
						type: jCastle.asn1.tagInteger,
						intVal: new BigInteger(params.n, 16)
					}, {
						type: jCastle.asn1.tagInteger,
						intVal: params.h
					}]
				});

				break;
			default:
				throw jCastle.exception("UNSUPPORTED_PKI_METHOD", 'PKI074');
		}

		switch (format) {
			case 'der':
				return der;
			case 'pem':
				return "-----BEGIN " + pki_name + " PARAMETERS-----\n" + 
					jCastle.util.lineBreak(Buffer.from(der, 'latin1').toString('base64'), 64) +
					"\n-----END " + pki_name + " PARAMETERS-----";
			case 'buffer':
				return Buffer.from(der, 'latin1');
			default:
				return Buffer.from(der, 'latin1').toString(format);
		}
	}

};

/**
 * creates pki class instance.
 * 
 * @public
 * @param {object} pkey pki object or publicKeyInfo object.
 * @returns pki class instance
 */
jCastle.pki.create = function(pkey)
{
	return new jCastle.pki(pkey);
};

/**
 * creates pki class instance and initialize with pki value.
 * 
 * @public
 * @param {object} pki pki object or publicKeyInfo object.
 * @returns pki class instance.
 */
jCastle.pki.init = function(pki)
{
	return new jCastle.pki().init(pki);
};


/**
 * creates pki class instance and parses pem value.
 * 
 * @public
 * @param {mixed} pem 
 * @param {buffer} password 
 * @returns pki class instance.
 */
jCastle.pki.parse = function(pem, password)
{
	return new jCastle.pki().parse(pem, password);
};

/**
 * creates pki class instance and parses private pem value.
 * 
 * @public
 * @param {mixed} pem 
 * @param {buffer} password password value
 * @param {string} format pem format type. (default: 'auto')
 * @returns pki class instance.
 */
jCastle.pki.parsePrivateKey = function(pem, password, format)
{
	return new jCastle.pki().parsePrivateKey(pem, password, format);
};

/**
 * creates pki class instance and parses public pem value.
 * 
 * @public
 * @param {mixed} pem 
 * @param {string} format pem format type. (default: 'auto')
 * @returns pki class instance.
 */
jCastle.pki.parsePublicKey = function(pem, format)
{
	return new jCastle.pki().parsePublicKey(pem, format);
};

/**
 * creates pki class instance from publicKeyInfo object.
 * 
 * @public
 * @param {object} publicKeyInfo publicKeyInfo object
 * @returns pki class instance.
 */
jCastle.pki.createFromPublicKeyInfo = function(publicKeyInfo)
{
	var pub_pki = null;

	switch (publicKeyInfo.algo) {
		case 'DSA':
		case 'KCDSA':
			pub_pki = new jCastle.pki(publicKeyInfo.algo).setPublicKey(
				publicKeyInfo.publicKey, {
					p: publicKeyInfo.parameters.p,
					q: publicKeyInfo.parameters.q,
					g: publicKeyInfo.parameters.g
				}
			);
			break;
		case 'ECDSA':
		case 'ECKCDSA':
			pub_pki = new jCastle.pki(publicKeyInfo.algo).setPublicKey(
				publicKeyInfo.publicKey,
				publicKeyInfo.parameters
			);
			break;
		case 'RSA':
			pub_pki = new jCastle.pki(publicKeyInfo.algo).setPublicKey(
				publicKeyInfo.publicKey.n,
				publicKeyInfo.publicKey.e
			);
			pub_pki.setPadding(publicKeyInfo.padding);
			break;

		default:
			throw jCastle.exception("UNSUPPORTED_PKI", 'PKI075');
	}

	return pub_pki;
};

/*
RFC 5280

4.2.1.2.  Subject Key Identifier

   The subject key identifier extension provides a means of identifying
   certificates that contain a particular public key.

   To facilitate certification path construction, this extension MUST
   appear in all conforming CA certificates, that is, all certificates
   including the basic constraints extension (Section 4.2.1.9) where the
   value of cA is TRUE.  In conforming CA certificates, the value of the
   subject key identifier MUST be the value placed in the key identifier
   field of the authority key identifier extension (Section 4.2.1.1) of
   certificates issued by the subject of this certificate.  Applications
   are not required to verify that key identifiers match when performing
   certification path validation.

   For CA certificates, subject key identifiers SHOULD be derived from
   the public key or a method that generates unique values.  Two common
   methods for generating key identifiers from the public key are:

      (1) The keyIdentifier is composed of the 160-bit SHA-1 hash of the
           value of the BIT STRING subjectPublicKey (excluding the tag,
           length, and number of unused bits).

      (2) The keyIdentifier is composed of a four-bit type field with
           the value 0100 followed by the least significant 60 bits of
           the SHA-1 hash of the value of the BIT STRING
           subjectPublicKey (excluding the tag, length, and number of
           unused bits).

   Other methods of generating unique numbers are also acceptable.

   For end entity certificates, the subject key identifier extension
   provides a means for identifying certificates containing the
   particular public key used in an application.  Where an end entity
   has obtained multiple certificates, especially from multiple CAs, the
   subject key identifier provides a means to quickly identify the set
   of certificates containing a particular public key.  To assist
   applications in identifying the appropriate end entity certificate,
   this extension SHOULD be included in all end entity certificates.

   For end entity certificates, subject key identifiers SHOULD be
   derived from the public key.  Two common methods for generating key
   identifiers from the public key are identified above.

   Where a key identifier has not been previously established, this
   specification RECOMMENDS use of one of these methods for generating
   keyIdentifiers or use of a similar method that uses a different hash
   algorithm.  Where a key identifier has been previously established,
   the CA SHOULD use the previously established identifier.

   Conforming CAs MUST mark this extension as non-critical.

   id-ce-subjectKeyIdentifier OBJECT IDENTIFIER ::=  { id-ce 14 }

   SubjectKeyIdentifier ::= KeyIdentifier
*/
/**
 * creates publicKey identifier as specified in RFC 5280.
 * 
 * @public
 * @param {object} pki pki object.
 * @returns the publicKey identifier.
 */
jCastle.pki.createPublicKeyIdentifier = function(pki)
{
	var der, schema;

	switch (pki.pkiName) {
		case 'RSA':
			var publicKey = pki.getPublicKey('object');
			schema = {
				type: jCastle.asn1.tagSequence,
				items: [{
					type: jCastle.asn1.tagInteger,
					intVal: publicKey.n
				}, {
					type: jCastle.asn1.tagInteger,
					intVal: publicKey.e
				}]
			};
			
			der = new jCastle.asn1().getDER(schema);
			break;
		case 'DSA':
		case 'KCDSA':
			schema = {
				type: jCastle.asn1.tagInteger,
				//value: new BigInteger(jCastle.encoding.hex.encode(pki.getPublicKey('utf8')), 16)
				intVal: pki.getPublicKey('object')
			};
			
			der = new jCastle.asn1().getDER(schema);
			break;
		case 'ECDSA':
		case 'ECKCDSA':
			der = pki.getPublicKey('buffer');
			break;
	}
	
	return new jCastle.digest('sha-1').digest(der);
};

/**
 * validates publicKey and privateKey.
 * 
 * @public
 * @param {mixed} pem pem string or buffer.
 * @param {number} certainty certainty value for probablePrime.
 * @param {boolean} display_err flag for displaying errors.
 * @returns true if the keypair is right.
 */
jCastle.pki.validateKeypair = function(pem, certainty = 10, display_err = false)
{
	var pki = jCastle.pki.create();
	pki.parse(pem);
	var privateKey = pki.getPrivateKey();
	return pki.validateKeypair(privateKey, certainty, display_err);
};

jCastle.PKI = jCastle.pki;

module.exports = jCastle.pki;

/*

EXAMPLES

Convert a private from traditional to PKCS#5 v2.0 format using triple DES:

 openssl pkcs8 -in key.pem -topk8 -v2 des3 -out enckey.pem

Convert a private from traditional to PKCS#5 v2.0 format using AES with 256 bits in CBC mode and hmacWithSHA256 PRF:

 openssl pkcs8 -in key.pem -topk8 -v2 aes-256-cbc -v2prf hmacWithSHA256 -out enckey.pem

Convert a private key to PKCS#8 using a PKCS#5 1.5 compatible algorithm (DES):

 openssl pkcs8 -in key.pem -topk8 -out enckey.pem

Convert a private key to PKCS#8 using a PKCS#12 compatible algorithm (3DES):

 openssl pkcs8 -in key.pem -topk8 -out enckey.pem -v1 PBE-SHA1-3DES

Read a DER unencrypted PKCS#8 format private key:

 openssl pkcs8 -inform DER -nocrypt -in key.der -out key.pem

Convert a private key from any PKCS#8 format to traditional format:

 openssl pkcs8 -in pk8.pem -out key.pem
 

Convert a private key to PKCS#8 format, encrypting with AES-256 and with one million iterations of the password:

 openssl pkcs8 -in raw.pem -topk8 -v2 aes-256-cbc -iter 1000000 -out pk8.pem

*/
