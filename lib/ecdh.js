/**
 * A Javascript implemenation of KeyAgreement - ECDH
 * 
 * @author Jacob Lee
 *
 * Copyright (C) 2015-2022 Jacob Lee.
 */

var jCastle = require('./jCastle');

require('./bigint-extend');
require('./util');
require('./lang/en');
require('./error');
require('./ec');
require('./ecdsa');
require('./ec-parameters');

jCastle.ecdh = class
{
	/**
	 * An Implementation of ECDSA Diffie-Hellman Key Agreement
	 * 
	 * @param {object} ecdsa ecdsa pki object
	 * @constructor
	 */
	constructor(ecdsa)
	{
		this.pki = null;
		this.secret = null;

		if (ecdsa) {
			if (ecdsa instanceof jCastle.pki && ecdsa.pkiName == 'ECDSA') this.pki = ecdsa;
			else if (ecdsa instanceof jCastle.pki.ecdsa) {
				this.pki = jCastle.pki.create().init(ecdsa);
			}
		}
	}

	/**
	 * resets internal variables.
	 * 
	 * @public
	 * @returns this class instance.
	 */
	reset()
	{
	//	this.pki = null;
		this.secret = null;

		return this;
	}

	/**
	 * initialize
	 * 
	 * @public
	 * @param {object} ecdsa ecdsa pki object
	 * @returns this class instance.
	 */
	init(ecdsa)
	{
		if (ecdsa instanceof jCastle.pki && ecdsa.pkiName == 'ECDSA') this.pki = ecdsa;
		else if (ecdsa instanceof jCastle.pki.ecdsa) {
			this.pki = jCastle.pki.create().init(ecdsa);
		}

		return this;
	}

	/**
	 * gets publicKey.
	 * 
	 * @public
	 * @param {string} format format string
	 * @returns publicKey of the pki.
	 */
	getPublicKey(format)
	{
		if (!this.pki) {
			throw jCastle.exception("PKI_NOT_SET", 'ECDH001');
		}
		return this.pki.getPublicKey(format);
	}

	/**
	 * computes secret of ecdh.
	 * 
	 * @public
	 * @param {object} party_pubkey other party's publicKey
	 * @param {buffer} additional additional data for ECDH
	 * @returns computed secret value.
	 */
	computeSecret(party_pubkey, additional)
	{
		if (!this.pki.hasPrivateKey()) {
			throw jCastle.exception("PRIVKEY_NOT_SET", 'ECDH002');
		}

		if (typeof party_pubkey == 'object' && 
			'kty' in party_pubkey && party_pubkey.kty == 'EC' &&
			'x' in party_pubkey && 'y' in party_pubkey) {
			// jwk
			var jwk = party_pubkey;
			party_pubkey = Buffer.concat([Buffer.alloc(1, 0x04),
				Buffer.from(jwk.x, 'base64url'),
				Buffer.from(jwk.y, 'base64url')]);
		}

		var ecdsa = this.pki.pkiObject;

		var point = ecdsa.importPoint(party_pubkey);
		this.secret = point.multiply(this.pki.getPrivateKey('object'));

		if (additional) {
			var extra;
			if (BigInt.is(additional)) {
				extra = additional;
			} else if (jCastle.util.isString(additional) && /^[0-9A-F]+$/i.test(additional)) {
				extra = BigInt('0x' + additional);
			} else {
				extra = BigInt.fromBufferUnsigned(Buffer.from(additional, 'latin1'));
			}

			this.secret = this.secret.multiply(extra);
		}

		if (this.secret.isInfinity()) throw jCastle.exception('INVALID_POINT_VALUE', 'ECDH003');

		return this.secret.encodePoint();
	}

/*
https://www.secg.org/sec1-v2.pdf


6.1  Elliptic Curve Diffie-Hellman Scheme

The elliptic curve Diffie-Hellman scheme is a key agreement scheme based on ECC.
It is designed to provide a variety of security goals depending on its application
— goals it can provide include unilateral implicit key authentication, mutual 
implicit key authentication, known-key security, and forward secrecy — depending 
on factors such as whether or not public keys are exchanged in an authentic manner,
and whether key pairs are ephemeral or static. See Appendix B for a further 
discussion.

The setup procedure for the elliptic curve Diffie-Hellman scheme is specified in 
Section 6.1.1, the key deployment procedure is specified in Section 6.1.2, and the 
key agreement operation is specified in Section 6.1.3.


6.1.1  Scheme Setup

Entities U and V should perform the following setup procedure to prepare to use the
elliptic curveDiffie-Hellman scheme:

    1. Entities U and V should establish which of the key derivation functions 
	supported in Section 3.6 to use, and select any options involved in the 
	operation of the key derivation function.Let KDF denote the key derivation 
	function chosen.

    2. Entities U and V should establish whether to use the “standard” elliptic 
	curve Diffie-Hellman primitive specified in Section 3.3.1, or the elliptic curve
	cofactor Diffie-Hellman primitives pecified in Section 3.3.2.

    3. Entities U and V should establish at the desired security level elliptic
	curve domain param-eters T= (p, a, b, G, n, h) or (m, f(x), a, b, G, n, h). 
	The elliptic curve domain parameters T should be generated using the primitive
	specified in Section 3.1.1.1 or the primitive specified in Section 3.1.2.1.
	Both U and V should receive an assurance that the elliptic curve domain 
	parameters T are valid using one of the methods specified in Section 3.1.1.2
	or Section 3.1.2.2.

6.1.2  Key Deployment

Entities U and V should perform the following key deployment procedure to prepare 
to use the elliptic curve Diffie-Hellman scheme:

    1. Entity U should establish an elliptic curve key pair (dU, QU) associated 
	with the elliptic curve domain parameters T established during the setup
	procedure. The key pair should be generated using the primitive specified in 
	Section 3.2.1.

    2. Entity V should establish an elliptic curve key pair (dV, QV) associated 
	with the elliptic curve domain parameters T established during the setup 
	procedure. The key pair should be generated using the primitive specified in
	Section 3.2.1.

    3. Entities U and V should exchange their public keys QU and QV.

    4. If the “standard” elliptic curve Diffie-Hellman primitive is being used, 
	U should receive an assurance that QV is valid using one of the methods 
	specified in Section 3.2.2, and if the elliptic curve cofactor Diffie-Hellman 
	primitive is being used, U should receive an assurance that QV is at least 
	partially valid using one of the methods specified in Section 3.2.2 or Section 
	3.2.3.

    5. If the “standard” elliptic curve Diffie-Hellman primitive is being used, 
	V should receive an assurance that QU is valid using one of the methods 
	specified in Section 3.2.2, and if the elliptic curve cofactor Diffie-Hellman
	primitive is being used, V should receive an assurance that QU is at least 
	partially valid using one of the methods specified in Section 3.2.2 orSection
	3.2.3.

6.1.3  Key Agreement Operation

Entities U and V should perform the key agreement operation described in this 
section to establish keying data using the elliptic curve Diffie-Hellman scheme.
For clarity, only U’s use of the operation is described. Entity V’s use of the 
operation is analogous, but with the roles of U and V reversed. Entity U should 
establish keying data with V using the keys and parameters established during 
the setup procedure and the key deployment procedure as follows:

Input: The input to the key agreement operation is:

    1. An integer keydatalen - which is the number of octets of keying data 
	required.

    2. (Optional) An octet string SharedInfo - which consists of some data shared
	by U and V.

Output: An octet string K which is the keying data of length keydatalen octets,
or “invalid”.

Actions: Establish keying data as follows:

    1. Use one of the Diffie-Hellman primitives specified in Section 3.3 to derive 
	a shared secretfield element z ∈ Fq from U’s secret key dU established during
	the key deployment procedure and V’s public key QV obtained during the key
	deployment procedure. If the Diffie-Hellman primitive outputs “invalid”, output
	“invalid” and stop. Decide whether to use the “standard” elliptic curve Diffie-
	Hellman primitive or the elliptic curve cofactor Diffie-Hellman primitive 
	according to the convention established during the setup procedure.

    2. Convert z ∈ Fq to an octet string Z using the conversion routine specified 
	in Section 2.3.5.

    3. Use the key derivation function KDF established during the setup procedure 
	to generate keying data K of length keydatalen octets from Z and [SharedInfo].
	If the key derivation function outputs “invalid”, output “invalid” and stop.

    4. Output K.
*/
	/**
	 * calculates the party's agreement.
	 * 
	 * @public
	 * @param {object} party_pubkey the other party's publicKey
	 * @param {buffer} additional additional data for ECDH
	 * @returns buffer of the calculated data.
	 */
	calculateAgreement(party_pubkey, additional)
	{
		var secret = this.computeSecret(party_pubkey, additional);
		var point = this.secret; // point
		
		var bi = point.getX().toBigInt();
		var ecInfo = this.pki.getCurveInfo();
		var bl = (ecInfo.n.bitLength() + 7) >>> 3;

		var res = bi.toBuffer();

		if (res.length < bl) 
			res = Buffer.concat([Buffer.alloc(bl - res.length, 0x00), res]);
		if (res.length > bl)
			res = res.slice(res.length - bl);

		return res;
	}

/*
https://www.secg.org/sec1-v2.pdf

6.2  Elliptic Curve MQV Scheme

The elliptic curve MQV scheme is a key agreement scheme based on ECC. It is 
designed to providea variety of security goals depending on its application 
— goals it can provide include mutualimplicit key authentication, known-key 
security, and forward secrecy — depending on factors such as whether or not
U and V both contribute ephemeral key pairs. See Appendix B for a further 
discussion. The setup procedure for the elliptic curve MQV scheme is specified
in Section 6.2.1, the key deployment procedure is specified in Section 6.2.2,
and the key agreement operation is specified inSection 6.2.3.

6.2.1  Scheme Setup

Entities U and V should perform the following setup procedure to prepare to 
use the elliptic curve MQV scheme:

    1. Entities U and V should establish which of the key derivation functions 
	supported in Section 3.6 to use, and select any options involved in the 
	operation of the key derivation function.Let KDF denote the key derivation
	function chosen.

    2. Entities U and V should establish at the desired security level elliptic
	curve domain parameters T = (p, a, b, G, n, h) or (m, f(x), a, b, G, n, h). 
	The elliptic curve domain parameters T should be generated using the 
	primitive specified in Section 3.1.1.1 or the primitive specified in 
	Section 3.1.2.1. Both U and V should receive an assurance that the elliptic
	curve domain parameters T are valid using one of the methods specified in 
	Section 3.1.1.2 or Section 3.1.2.2.

6.2.2  Key Deployment

Entities U and V should perform the following key deployment procedure to prepare
to use the elliptic curve MQV scheme:

    1. Entity U should establish two elliptic curve key pairs (d1U, Q1U) and 
	(d2U, Q2U) associated with the elliptic curve domain parameters T
	established during the setup procedure. The key pairs should both be
	generated using the primitive specified in Section 3.2.1.

    2. Entity V should establish two elliptic curve key pairs (d1V, Q1V) and 
	(d2V, Q2V) associated with the elliptic curve domain parameters T 
	established during the setup procedure. The key pairs should both be
	generated using the primitive specified in Section 3.2.1.

    3. Entity U should obtain in an authentic manner the first elliptic curve
	public key Q1V selected by V.  Entity U should receive an assurance that 
	Q1V is valid using one of the methods specified in Section 3.2.2.

    4. Entity V should obtain in an authentic manner the first elliptic curve
	public key Q1U selected by U.  Entity V should receive an assurance that 
	Q1U is valid using one of the methods specified in Section 3.2.2.

    5. Entities U and V should exchange their second public keys Q2U and Q2V.

    6. Entity U should receive an assurance that Q2V is at least partially 
	valid using one of the methods specified in Section 3.2.2 or Section 3.2.3.

    7. Entity V should receive an assurance that Q2U is at least partially 
	valid using one of the methods specified in Section 3.2.2 or Section 3.2.3.

6.2.3  Key Agreement Operation

Entities U and V should perform the key agreement operation described in this
section to establish keying data using the elliptic curve MQV scheme. For
clarity, only U’s use of the operation is described. Entity V’s use of the
operation is analogous, but with the roles of U and V reversed.

Entity U should establish keying data with V using the keys and parameters
established during the setup procedure and the key deployment procedure as 
follows:

Input: The input to the key agreement operation is:

    1. An integer keydatalen - which is the number of octets of keying data
	required.

    2. (Optional) An octet string SharedInfo - which consists of some data
	shared by U and V. This octet string should be included, and should 
	contain information identifying the entities U and V.

Output: An octet string K - which is the keying data of length keydatalen 
octets, or “invalid”.

Actions: Establish keying data as follows:

    1. Use the elliptic curve MQV primitive specified in Section 3.4 to
	derive a shared secret field element z ∈ Fq from U’s key pairs (d1U, Q1U) 
	and (d2U, Q2U) established during the key deployment procedure and V’s 
	public keys Q1V and Q2V obtained during the key deployment procedure. 
	If the MQV primitive outputs “invalid”, output “invalid” and stop.

    2. Convert z ∈ Fq to an octet string Z using the conversion routine 
	specified in Section 2.3.5.

    3. Use the key derivation function KDF established during the setup 
	procedure to generate keying data K of length keydatalen octets from Z
	and [SharedInfo]. If the key derivation function outputs “invalid”, 
	output “invalid” and stop.

    4. OutputK.
*/
	/**
	 * calculates MQV Agreement of each party.
	 * 
	 * @public
	 * @param {object} ephemeral_prvkey ephemeral privateKey.
	 * @param {object} party_pubkey the other party's publicKey
	 * @param {object} ephemeral_party_pubkey the other party's ephemeral publicKey
	 * @returns buffer of the calculated data of MQV Agreement.
	 */
	calculateMQVAgreement(ephemeral_prvkey, party_pubkey, ephemeral_party_pubkey)
	{
		if (!this.pki.hasPrivateKey()) {
			throw jCastle.exception("PRIVKEY_NOT_SET", 'ECDH004');
		}

		// var ecdsa = this.pki.pkiObject;
		// var ecInfo = ecdsa.ecInfo;
		var ecdsa = this.pki;
		var ecInfo = ecdsa.getCurveInfo();

		var n = ecInfo.n;

		var e = parseInt((n.bitLength() + 1) / 2);
		var E = 1n.shiftLeft(e);

		var d1u = ecdsa.getPrivateKey();
		var d2u = jCastle.util.toBigInt(ephemeral_prvkey);
		var q2u = ecInfo.G.multiply(d2u);

		var q1v = ecdsa.importPoint(party_pubkey);
		var q2v = ecdsa.importPoint(ephemeral_party_pubkey);

		var a = q2u.getX().toBigInt();
		var q2uBar = a.mod(E).setBit(e);

		var b = q2v.getX().toBigInt();
		var q2vBar = b.mod(E).setBit(e);

		var s = d1u.multiply(q2uBar).add(d2u).mod(n);
		var l = ecInfo.h.multiply(s).mod(n);
		var k = q2vBar.multiply(l).mod(n);

		var point = jCastle.math.ec.implementShamirsTrick(q1v, k, q2v, l);
		var bi = point.getX().toBigInt();

		return bi.toBuffer();
	}
};

/**
 * creates a new ecdh class instance.
 * 
 * @public
 * @param {object} ecdsa ecdsa pki object
 * @returns the new class instance
 */
jCastle.ecdh.create = function(ecdsa)
{
	return new jCastle.ecdh(ecdsa);
};

/**
 * creates a new ecdh class instance and initialize with the pki.
 * 
 * @public
 * @param {object} ecdsa ecdsa pki object
 * @returns the class instance.
 */
jCastle.ecdh.init = function(ecdsa)
{
	return new jCastle.ecdh().init(ecdsa);
};

jCastle.ECDH = jCastle.ecdh;

module.exports = jCastle.ecdh;
