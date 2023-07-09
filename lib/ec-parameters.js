/**
 * A Javascript implemenation of EC-Parameters 
 * 
 * @author Jacob Lee
 *
 * Copyright (C) 2015-2022 Jacob Lee.
 */

// if (typeof jCastle.pki.ecdsa == 'undefined') {
// 	throw jCastle.exception('ECDSA_NOT_LOADED', 'ECP001');
// }

var jCastle = require('./jCastle');

require('./bigint-extend');
require('./util');
require('./lang/en');
require('./error');
require('./prng');
require('./ec');
require('./ecdsa');

/*
Parameters

CURVE : the elliptic curve field and equation used
G : elliptic curve base point, a generator of the elliptic curve with large prime order n
n : integer order of G, means that n x G = O 
*/

/**
 * gets ECDSA parameters.
 * 
 * @public
 * @param {string} name ECDSA curve name.
 * @returns ECDSA parameters object.
 */
jCastle.pki.ecdsa.getParameters = function(name)
{
	// alias
	switch (name) {
		// prime
		case "P-192":
		case "secp192r1":
		case "ansix9p192r1":
			name = "prime192v1"; break;
		case "P-224":
			name = "secp224r1"; break;
		case "P-384":
			name = "secp384r1"; break;
		case "P-521":
			name = "secp521r1"; break;
		case "P-256":
		case "secp256r1":
			name = "prime256v1"; break;
		case "ansix9p192v2":
			name = "prime192v2"; break;
		case "ansix9p192v3":
			name = "prime192v3"; break;
		case "ansix9p239v1":
			name = "prime239v1"; break;
		case "ansix9p239v2":
			name = "prime239v2"; break;
		case "ansix9p239v3":
			name = "prime239v3"; break;
		case "ansix9p256v1":
			name = "prime256v1"; break;
		// binary
		case "B-163":
			name = "sect163r2"; break;
		case "B-233":
		case "wap_wsg_idm_ecid_wtls11":
			name = "sect233r1"; break;
		case "B-283":
			name = "sect283r1"; break;
		case "B-409":
			name = "sect409r1"; break;
		case "B-571":
			name = "sect571r1"; break;
		case "K-163":
		case "ansix9t163k1":
		case "wap_wsg_idm_ecid_wtls3":
			name = "sect163k1"; break;
		case "K-233":
		case "wap_wsg_idm_ecid_wtls10":
			name = "sect233k1"; break;
		case "K-283":
			name = "sect283k1"; break;
		case "K-409":
			name = "sect409k1"; break;
		case "K-571":
			name = "sect571k1"; break;
		case "wap_wsg_idm_ecid_wtls4":
			name = "sect113rl"; break;
		case "wap_wsg_idm_ecid_wtls5":
			name = "c2pnb163v1"; break;
	}

	//if (!jCastle.pki.ecdsa._registeredParams.hasOwnProperty(name)) {
	if (!(name in jCastle.pki.ecdsa._registeredParams)) {
		return null;
	}

	return 	jCastle.pki.ecdsa._registeredParams[name];
};

/**
 * gets ECDSA parameters by object id.
 * 
 * @public
 * @param {string} oid object id
 * @returns ECDSA parameters object.
 */
jCastle.pki.ecdsa.getParametersByOID = function(oid)
{
	for (var i in jCastle.pki.ecdsa._registeredParams) {
		if (jCastle.pki.ecdsa._registeredParams[i].OID == oid) {
			return jCastle.pki.ecdsa._registeredParams[i];
		}
	}

	return null;
};

/**
 * gets the curve name fitting to the object id.
 * 
 * @public
 * @param {string} oid object id
 * @returns the curve name.
 */
jCastle.pki.ecdsa.getCurveNameByOID = function(oid)
{
	for (var i in jCastle.pki.ecdsa._registeredParams) {
		if (jCastle.pki.ecdsa._registeredParams[i].OID == oid) {
			return i;
		}
	}

	return null;
};

/**
 * gets the curve name corresponding to the parameters.
 * @param {object} params parameters object
 * @returns the curve name if exists. null if not.
 */
jCastle.pki.ecdsa.getCurveNameByParams = function(params)
{
	if (!('gx' in params) && !('gy' in params) && 'g' in params) {
		var g = params.g.substr(2);
		params.gx = g.substr(0, g.length / 2);
		params.gy = g.substr(g.length / 2);
	}

	var p = BigInt('0x' + params.p);
	var a = BigInt('0x' + params.a);
	var b = BigInt('0x' + params.b);
	var gx = BigInt('0x' + params.gx);
	var gy = BigInt('0x' + params.gy);
	var n = BigInt('0x' + params.n);


	for (var i in jCastle.pki.ecdsa._registeredParams) {
		var v_params = jCastle.pki.ecdsa._registeredParams[i];

		if (BigInt('0x' + v_params.p).equals(p) &&
			BigInt('0x' + v_params.a).equals(a) &&
			BigInt('0x' + v_params.b).equals(b) &&
			BigInt('0x' + v_params.gx).equals(gx) &&
			BigInt('0x' + v_params.gy).equals(gy) &&
			BigInt('0x' + v_params.n).equals(n) &&
			v_params.h == params.h
		) {
			return i;
		}
	}
	return null;
};

/**
 * gets all curve name.
 * 
 * @public
 * @returns arrays of parameters curve name.
 */
jCastle.pki.ecdsa.listParameters = function()
{
	var l = [];
	for (var i in jCastle.pki.ecdsa._registeredParams) {
		l.push(i);
	}
	return l;
};

/**
 * gets parameters object that has some functions with it.
 * 
 * @public
 * @param {string} name curve name
 * @returns the parameters object.
 */
jCastle.pki.ecdsa.getParametersObject = function(name)
{
	var params = jCastle.pki.ecdsa.getParameters(name);

	var p = BigInt('0x' + params.p);
	var a = BigInt('0x' + params.a);
	var b = BigInt('0x' + params.b);

	var curve = new jCastle.ec.curve.fp(p, a, b);

	var gx = new jCastle.ec.fieldElement.fp(curve.q, BigInt('0x' + params.gx));
	var gy = new jCastle.ec.fieldElement.fp(curve.q, BigInt('0x' + params.gy));
	var G = new jCastle.ec.Point.Fp(curve, gx, gy);

	var n = BigInt('0x' + params.n);
	var h = BigInt(params.h);

	var obj = {
		curve: curve,
		G: G,
		n: n,
		h: h,
		type: params.type,
		curveName: name, // original name, ie) P-256 -> name: secp256r1, curveName: P-256

		getCurve: function() {
			return this.curve;
		},
		getG: function() {
			return this.G;
		},
		getN: function() {
			return this.n;
		},
		getH: function() {
			return this.h;
		}
	};

	if (params.type == "characteristic-two-field") {
		obj.m = params.m;
		obj.k1 = params.k1;
		obj.k2 = params.k2;
		obj.k3 = params.k3;

		obj.getM = function() {
			return this.m;
		};
		obj.getK1 = function() {
			return this.k1;
		};
		obj.getK2 = function() {
			return this.k2;
		};
		obj.getK3 = function() {
			return this.k3;
		};
	}

	return obj;
};

/*
	EC-parameters::= SEQUENCE {
		version					 INTEGER
		SEQUENCE {
			1.2.840.10045.1.1	   OID
			p					   INTEGER
		}
		SEQUENCE {
			a					   OCTET STRING
			b					   OCTET STRING
		}
		G (uncompressed)			OCTET STRING
		n (order)					INTEGER
		h		 					INTEGER
	}
*/
jCastle.pki.ecdsa._registeredParams = {};

//
// prime field
// 

jCastle.pki.ecdsa._registeredParams['prime192v1'] = 
{
	p: "fffffffffffffffffffffffffffffffeffffffffffffffff",
	a: "fffffffffffffffffffffffffffffffefffffffffffffffc",
	b: "64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1",
	gx: "188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012",
	gy: "07192b95ffc8da78631011ed6b24cdd573f977a11e794811",
	n: "ffffffffffffffffffffffff99def836146bc9b1b4d22831",
	h: 0x01,

	name: 'prime192v1',
	type: "prime-field",
	OID: "1.2.840.10045.3.1.1",
	comment: "NIST/X9.62/SECG curve over a 192 bit prime field",
	seed: "3045ae6fc8422f64ed579528d38120eae12196d5"
};

jCastle.pki.ecdsa._registeredParams['secp224r1'] = 
{
	p: "ffffffffffffffffffffffffffffffff000000000000000000000001",
	a: "fffffffffffffffffffffffffffffffefffffffffffffffffffffffe",
	b: "b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4",
	gx: "b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21",
	gy: "bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34",
	n: "ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d",
	h: 0x01,

	name: 'secp224r1',
	type: "prime-field",
	OID: "1.3.132.0.33",
	comment: "NIST/SECG curve over a 224 bit prime field",
	seed: "bd71344799d5c7fcdc45b59fa3b9ab8f6a948bc5"
};

jCastle.pki.ecdsa._registeredParams['secp384r1'] = 
{
	p: "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
	a: "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc",
	b: "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
	gx: "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
	gy: "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
	n: "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
	h: 0x01,

	name: 'secp384r1',
	type: "prime-field",
	OID: "1.3.132.0.34",
	comment: "NIST/SECG curve over a 384 bit prime field",
	seed: "a335926aa319a27a1d00896a6773a4827acdac73"
};

jCastle.pki.ecdsa._registeredParams['secp521r1'] = 
{
	p: "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	a: "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc",
	b: "0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00",
	gx: "00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66",
	gy: "011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650",
	n: "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",
	h: 0x01,

	name: 'secp521r1',
	type: "prime-field",
	OID: "1.3.132.0.35",
	comment: "NIST/SECG curve over a 521 bit prime field",
	seed: "d09e8800291cb85396cc6717393284aaa0da64ba"
};

jCastle.pki.ecdsa._registeredParams['prime192v2'] = 
{
	p: "fffffffffffffffffffffffffffffffeffffffffffffffff",
	a: "fffffffffffffffffffffffffffffffefffffffffffffffc",
	b: "cc22d6dfb95c6b25e49c0d6364a4e5980c393aa21668d953",
	gx: "eea2bae7e1497842f2de7769cfe9c989c072ad696f48034a",
	gy: "6574d11d69b6ec7a672bb82a083df2f2b0847de970b2de15",
	n: "fffffffffffffffffffffffe5fb1a724dc80418648d8dd31",
	h: 0x01,

	name: 'prime192v2',
	type: "prime-field",
	OID: "1.2.840.10045.3.1.2",
	comment: "X9.62 curve over a 192 bit prime field",
	seed: "31a92ee2029fd10d901b113e990710f0d21ac6b6"
};

jCastle.pki.ecdsa._registeredParams['prime192v3'] = 
{
	p: "fffffffffffffffffffffffffffffffeffffffffffffffff",
	a: "fffffffffffffffffffffffffffffffefffffffffffffffc",
	b: "22123dc2395a05caa7423daeccc94760a7d462256bd56916",
	gx: "7d29778100c65a1da1783716588dce2b8b4aee8e228f1896",
	gy: "38a90f22637337334b49dcb66a6dc8f9978aca7648a943b0",
	n: "ffffffffffffffffffffffff7a62d031c83f4294f640ec13",
	h: 0x01,

	name: 'prime192v3',
	type: "prime-field",
	OID: "1.2.840.10045.3.1.3",
	comment: "X9.62 curve over a 192 bit prime field",
	seed: "c469684435deb378c4b65ca9591e2a5763059a2e"
};

jCastle.pki.ecdsa._registeredParams['prime239v1'] = 
{
	p: "7fffffffffffffffffffffff7fffffffffff8000000000007fffffffffff",
	a: "7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc",
	b: "6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a",
	gx: "0ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf",
	gy: "7debe8e4e90a5dae6e4054ca530ba04654b36818ce226b39fccb7b02f1ae",
	n: "7fffffffffffffffffffffff7fffff9e5e9a9f5d9071fbd1522688909d0b",
	h: 0x01,

	name: 'prime239v1',
	type: "prime-field",
	OID: "1.2.840.10045.3.1.4",
	comment: "X9.62 curve over a 239 bit prime field",
	seed: "e43bb460f0b80cc0c0b075798e948060f8321b7d"
};

jCastle.pki.ecdsa._registeredParams['prime239v2'] = 
{
	p: "7fffffffffffffffffffffff7fffffffffff8000000000007fffffffffff",
	a: "7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc",
	b: "617fab6832576cbbfed50d99f0249c3fee58b94ba0038c7ae84c8c832f2c",
	gx: "38af09d98727705120c921bb5e9e26296a3cdcf2f35757a0eafd87b830e7",
	gy: "5b0125e4dbea0ec7206da0fc01d9b081329fb555de6ef460237dff8be4ba",
	n: "7fffffffffffffffffffffff800000cfa7e8594377d414c03821bc582063",
	h: 0x01,

	name: 'prime239v2',
	type: "prime-field",
	OID: "1.2.840.10045.3.1.5",
	comment: "X9.62 curve over a 239 bit prime field",
	seed: "e8b4011604095303ca3b8099982be09fcb9ae616"
};

jCastle.pki.ecdsa._registeredParams['prime239v3'] = 
{
	p: "7fffffffffffffffffffffff7fffffffffff8000000000007fffffffffff",
	a: "7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc",
	b: "255705fa2a306654b1f4cb03d6a750a30c250102d4988717d9ba15ab6d3e",
	gx: "6768ae8e18bb92cfcf005c949aa2c6d94853d0e660bbf854b1c9505fe95a",
	gy: "1607e6898f390c06bc1d552bad226f3b6fcfe48b6e818499af18e3ed6cf3",
	n: "7fffffffffffffffffffffff7fffff975deb41b3a6057c3c432146526551",
	h: 0x01,

	name: 'prime239v3',
	type: "prime-field",
	OID: "1.2.840.10045.3.1.6",
	comment: "X9.62 curve over a 239 bit prime field",
	seed: "7d7374168ffe3471b60a857686a19475d3bfa2ff"
};

jCastle.pki.ecdsa._registeredParams['prime256v1'] = 
{
	p: "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
	a: "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
	b: "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
	gx: "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
	gy: "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
	n: "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
	h: 0x01,

	name: 'prime256v1',
	type: "prime-field",
	OID: "1.2.840.10045.3.1.7",
	comment: "X9.62/SECG curve over a 256 bit prime field",
	seed: "c49d360886e704936a6678e1139d26b7819f7e90"
};

jCastle.pki.ecdsa._registeredParams['secp112r1'] = 
{
	p: "db7c2abf62e35e668076bead208b",
	a: "db7c2abf62e35e668076bead2088",
	b: "659ef8ba043916eede8911702b22",
	gx: "09487239995a5ee76b55f9c2f098",
	gy: "a89ce5af8724c0a23e0e0ff77500",
	n: "db7c2abf62e35e7628dfac6561c5",
	h: 0x01,

	name: 'secp112r1',
	type: "prime-field",
	OID: "1.3.132.0.6",
	comment: "SECG/WTLS curve over a 112 bit prime field",
	seed: "00f50b028e4d696e676875615175290472783fb1"
};

jCastle.pki.ecdsa._registeredParams['secp112r2'] = 
{
	p: "db7c2abf62e35e668076bead208b",
	a: "6127c24c05f38a0aaaf65c0ef02c",
	b: "51def1815db5ed74fcc34c85d709",
	gx: "4ba30ab5e892b4e1649dd0928643",
	gy: "adcd46f5882e3747def36e956e97",
	n: "36df0aafd8b8d7597ca10520d04b",
	h: 0x04,

	name: 'secp112r2',
	type: "prime-field",
	OID: "1.3.132.0.7",
	comment: "SECG curve over a 112 bit prime field",
	seed: "002757a1114d696e6768756151755316c05e0bd4"
};

jCastle.pki.ecdsa._registeredParams['secp128r1'] = 
{
	p: "fffffffdffffffffffffffffffffffff",
	a: "fffffffdfffffffffffffffffffffffc",
	b: "e87579c11079f43dd824993c2cee5ed3",
	gx: "161ff7528b899b2d0c28607ca52c5b86",
	gy: "cf5ac8395bafeb13c02da292dded7a83",
	n: "fffffffe0000000075a30d1b9038a115",
	h: 0x01,

	name: 'secp128r1',
	type: "prime-field",
	OID: "1.3.132.0.28",
	comment: "SECG curve over a 128 bit prime field",
	seed: "000e0d4d696e6768756151750cc03a4473d03679"
};

jCastle.pki.ecdsa._registeredParams['secp128r2'] = 
{
	p: "fffffffdffffffffffffffffffffffff",
	a: "d6031998d1b3bbfebf59cc9bbff9aee1",
	b: "5eeefca380d02919dc2c6558bb6d8a5d",
	gx: "7b6aa5d85e572983e6fb32a7cdebc140",
	gy: "27b6916a894d3aee7106fe805fc34b44",
	n: "3fffffff7fffffffbe0024720613b5a3",
	h: 0x04,

	name: 'secp128r2',
	type: "prime-field",
	OID: "1.3.132.0.29",
	comment: "SECG curve over a 128 bit prime field",
	seed: "004d696e67687561517512d8f03431fce63b88f4"
};

jCastle.pki.ecdsa._registeredParams['secp160k1'] = 
{
	p: "00fffffffffffffffffffffffffffffffeffffac73",
	a: "000000000000000000000000000000000000000000",
	b: "000000000000000000000000000000000000000007",
	gx: "003b4c382ce37aa192a4019e763036f4f5dd4d7ebb",
	gy: "00938cf935318fdced6bc28286531733c3f03c4fee",
	n: "0100000000000000000001b8fa16dfab9aca16b6b3",
	h: 0x01,

	name: 'secp160k1',
	type: "prime-field",
	OID: "1.3.132.0.9",
	comment: "SECG curve over a 160 bit prime field"
};

jCastle.pki.ecdsa._registeredParams['secp160r1'] = 
{
	p: "00ffffffffffffffffffffffffffffffff7fffffff",
	a: "00ffffffffffffffffffffffffffffffff7ffffffc",
	b: "001c97befc54bd7a8b65acf89f81d4d4adc565fa45",
	gx: "004a96b5688ef573284664698968c38bb913cbfc82",
	gy: "0023a628553168947d59dcc912042351377ac5fb32",
	n: "0100000000000000000001f4c8f927aed3ca752257",
	h: 0x01,

	name: 'secp160r1',
	type: "prime-field",
	OID: "1.3.132.0.8",
	comment: "SECG curve over a 160 bit prime field",
	seed: "1053cde42c14d696e67687561517533bf3f83345"
};

jCastle.pki.ecdsa._registeredParams['secp160r2'] = 
{
	p: "00fffffffffffffffffffffffffffffffeffffac73",
	a: "00fffffffffffffffffffffffffffffffeffffac70",
	b: "00b4e134d3fb59eb8bab57274904664d5af50388ba",
	gx: "0052dcb034293a117e1f4ff11b30f7199d3144ce6d",
	gy: "00feaffef2e331f296e071fa0df9982cfea7d43f2e",
	n: "0100000000000000000000351ee786a818f3a1a16b",
	h: 0x01,

	name: 'secp160r2',
	type: "prime-field",
	OID: "1.3.132.0.30",
	comment: "SECG/WTLS curve over a 160 bit prime field",
	seed: "b99b99b099b323e02709a4d696e6768756151751"
};

jCastle.pki.ecdsa._registeredParams['secp192k1'] = 
{
	p: "fffffffffffffffffffffffffffffffffffffffeffffee37",
	a: "000000000000000000000000000000000000000000000000",
	b: "000000000000000000000000000000000000000000000003",
	gx: "db4ff10ec057e9ae26b07d0280b7f4341da5d1b1eae06c7d",
	gy: "9b2f2f6d9c5628a7844163d015be86344082aa88d95e2f9d",
	n: "fffffffffffffffffffffffe26f2fc170f69466a74defd8d",
	h: 0x01,

	name: 'secp192k1',
	type: "prime-field",
	OID: "1.3.132.0.31",
	comment: "SECG curve over a 192 bit prime field"
};

jCastle.pki.ecdsa._registeredParams['secp224k1'] = 
{
	p: "00fffffffffffffffffffffffffffffffffffffffffffffffeffffe56d",
	a: "0000000000000000000000000000000000000000000000000000000000",
	b: "0000000000000000000000000000000000000000000000000000000005",
	gx: "00a1455b334df099df30fc28a169a467e9e47075a90f7e650eb6b7a45c",
	gy: "007e089fed7fba344282cafbd6f7e319f7c0b0bd59e2ca4bdb556d61a5",
	n: "010000000000000000000000000001dce8d2ec6184caf0a971769fb1f7",
	h: 0x01,

	name: 'secp224k1',
	type: "prime-field",
	OID: "1.3.132.0.32",
	comment: "SECG curve over a 224 bit prime field"
};

jCastle.pki.ecdsa._registeredParams['secp256k1'] = 
{
	p: "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
	a: "0000000000000000000000000000000000000000000000000000000000000000",
	b: "0000000000000000000000000000000000000000000000000000000000000007",
	gx: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
	gy: "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
	n: "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
	h: 0x01,

	name: 'secp256k1',
	type: "prime-field",
	OID: "1.3.132.0.10",
	comment: "SECG curve over a 256 bit prime field"
};

jCastle.pki.ecdsa._registeredParams['wap-wsg-idm-ecid-wtls8'] = 
{
	p: "00fffffffffffffffffffffffffde7",
	a: "000000000000000000000000000000",
	b: "000000000000000000000000000003",
	gx: "000000000000000000000000000001",
	gy: "000000000000000000000000000002",
	n: "0100000000000001ecea551ad837e9",
	h: 0x01,

	name: 'wap-wsg-idm-ecid-wtls8',
	type: "prime-field",
	OID: "2.23.43.1.4.8",
	comment: "WTLS curve over a 112 bit prime field"
};

jCastle.pki.ecdsa._registeredParams['wap-wsg-idm-ecid-wtls9'] = 
{
	p: "00fffffffffffffffffffffffffffffffffffc808f",
	a: "000000000000000000000000000000000000000000",
	b: "000000000000000000000000000000000000000003",
	gx: "000000000000000000000000000000000000000001",
	gy: "000000000000000000000000000000000000000002",
	n: "0100000000000000000001cdc98ae0e2de574abf33",
	h: 0x01,

	name: 'wap-wsg-idm-ecid-wtls9',
	type: "prime-field",
	OID: "2.23.43.1.4.9",
	comment: "WTLS curve over a 160 bit prime field"
};

jCastle.pki.ecdsa._registeredParams['wap-wsg-idm-ecid-wtls12'] = 
{
	p: "ffffffffffffffffffffffffffffffff000000000000000000000001",
	a: "fffffffffffffffffffffffffffffffefffffffffffffffffffffffe",
	b: "b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4",
	gx: "b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21",
	gy: "bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34",
	n: "ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d",
	h: 0x01,

	name: 'wap-wsg-idm-ecid-wtls12',
	type: "prime-field",
	OID: "2.23.43.1.4.12",
	comment: "WTLS curvs over a 224 bit prime field"
};

jCastle.pki.ecdsa._registeredParams['brainpoolP160r1'] = 
{
	p: "e95e4a5f737059dc60dfc7ad95b3d8139515620f",
	a: "340e7be2a280eb74e2be61bada745d97e8f7c300",
	b: "1e589a8595423412134faa2dbdec95c8d8675e58",
	gx: "bed5af16ea3f6a4f62938c4631eb5af7bdbcdbc3",
	gy: "1667cb477a1a8ec338f94741669c976316da6321",
	n: "e95e4a5f737059dc60df5991d45029409e60fc09",
	h: 0x01,

	name: 'brainpoolP160r1',
	type: "prime-field",
	OID: "1.3.36.3.3.2.8.1.1.1",
	comment: "RFC 5639 curve over a 160 bit prime field"
};

jCastle.pki.ecdsa._registeredParams['brainpoolP160t1'] = 
{
	p: "e95e4a5f737059dc60dfc7ad95b3d8139515620f",
	a: "e95e4a5f737059dc60dfc7ad95b3d8139515620c",
	b: "7a556b6dae535b7b51ed2c4d7daa7a0b5c55f380",
	gx: "b199b13b9b34efc1397e64baeb05acc265ff2378",
	gy: "add6718b7c7c1961f0991b842443772152c9e0ad",
	n: "e95e4a5f737059dc60df5991d45029409e60fc09",
	h: 0x01,

	name: 'brainpoolP160t1',
	type: "prime-field",
	OID: "1.3.36.3.3.2.8.1.1.2",
	comment: "RFC 5639 curve over a 160 bit prime field"
};

jCastle.pki.ecdsa._registeredParams['brainpoolP192r1'] = 
{
	p: "c302f41d932a36cda7a3463093d18db78fce476de1a86297",
	a: "6a91174076b1e0e19c39c031fe8685c1cae040e5c69a28ef",
	b: "469a28ef7c28cca3dc721d044f4496bcca7ef4146fbf25c9",
	gx: "c0a0647eaab6a48753b033c56cb0f0900a2f5c4853375fd6",
	gy: "14b690866abd5bb88b5f4828c1490002e6773fa2fa299b8f",
	n: "c302f41d932a36cda7a3462f9e9e916b5be8f1029ac4acc1",
	h: 0x01,

	name: 'brainpoolP192r1',
	type: "prime-field",
	OID: "1.3.36.3.3.2.8.1.1.3",
	comment: "RFC 5639 curve over a 192 bit prime field"
};

jCastle.pki.ecdsa._registeredParams['brainpoolP192t1'] = 
{
	p: "c302f41d932a36cda7a3463093d18db78fce476de1a86297",
	a: "c302f41d932a36cda7a3463093d18db78fce476de1a86294",
	b: "13d56ffaec78681e68f9deb43b35bec2fb68542e27897b79",
	gx: "3ae9e58c82f63c30282e1fe7bbf43fa72c446af6f4618129",
	gy: "097e2c5667c2223a902ab5ca449d0084b7e5b3de7ccc01c9",
	n: "c302f41d932a36cda7a3462f9e9e916b5be8f1029ac4acc1",
	h: 0x01,

	name: 'brainpoolP192t1',
	type: "prime-field",
	OID: "1.3.36.3.3.2.8.1.1.4",
	comment: "RFC 5639 curve over a 192 bit prime field"
};

jCastle.pki.ecdsa._registeredParams['brainpoolP224r1'] = 
{
	p: "d7c134aa264366862a18302575d1d787b09f075797da89f57ec8c0ff",
	a: "68a5e62ca9ce6c1c299803a6c1530b514e182ad8b0042a59cad29f43",
	b: "2580f63ccfe44138870713b1a92369e33e2135d266dbb372386c400b",
	gx: "0d9029ad2c7e5cf4340823b2a87dc68c9e4ce3174c1e6efdee12c07d",
	gy: "58aa56f772c0726f24c6b89e4ecdac24354b9e99caa3f6d3761402cd",
	n: "d7c134aa264366862a18302575d0fb98d116bc4b6ddebca3a5a7939f",
	h: 0x01,

	name: 'brainpoolP224r1',
	type: "prime-field",
	OID: "1.3.36.3.3.2.8.1.1.5",
	comment: "RFC 5639 curve over a 224 bit prime field"
};

jCastle.pki.ecdsa._registeredParams['brainpoolP224t1'] = 
{
	p: "d7c134aa264366862a18302575d1d787b09f075797da89f57ec8c0ff",
	a: "d7c134aa264366862a18302575d1d787b09f075797da89f57ec8c0fc",
	b: "4b337d934104cd7bef271bf60ced1ed20da14c08b3bb64f18a60888d",
	gx: "6ab1e344ce25ff3896424e7ffe14762ecb49f8928ac0c76029b4d580",
	gy: "0374e9f5143e568cd23f3f4d7c0d4b1e41c8cc0d1c6abd5f1a46db4c",
	n: "d7c134aa264366862a18302575d0fb98d116bc4b6ddebca3a5a7939f",
	h: 0x01,

	name: 'brainpoolP224t1',
	type: "prime-field",
	OID: "1.3.36.3.3.2.8.1.1.6",
	comment: "RFC 5639 curve over a 224 bit prime field"
};

jCastle.pki.ecdsa._registeredParams['brainpoolP256r1'] = 
{
	p: "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377",
	a: "7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9",
	b: "26dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b6",
	gx: "8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262",
	gy: "547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997",
	n: "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7",
	h: 0x01,

	name: 'brainpoolP256r1',
	type: "prime-field",
	OID: "1.3.36.3.3.2.8.1.1.7",
	comment: "RFC 5639 curve over a 256 bit prime field"
};

jCastle.pki.ecdsa._registeredParams['brainpoolP256t1'] = 
{
	p: "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377",
	a: "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5374",
	b: "662c61c430d84ea4fe66a7733d0b76b7bf93ebc4af2f49256ae58101fee92b04",
	gx: "a3e8eb3cc1cfe7b7732213b23a656149afa142c47aafbc2b79a191562e1305f4",
	gy: "2d996c823439c56d7f7b22e14644417e69bcb6de39d027001dabe8f35b25c9be",
	n: "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7",
	h: 0x01,

	name: 'brainpoolP256t1',
	type: "prime-field",
	OID: "1.3.36.3.3.2.8.1.1.8",
	comment: "RFC 5639 curve over a 256 bit prime field"
};

jCastle.pki.ecdsa._registeredParams['brainpoolP320r1'] = 
{
	p: "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e27",
	a: "3ee30b568fbab0f883ccebd46d3f3bb8a2a73513f5eb79da66190eb085ffa9f492f375a97d860eb4",
	b: "520883949dfdbc42d3ad198640688a6fe13f41349554b49acc31dccd884539816f5eb4ac8fb1f1a6",
	gx: "43bd7e9afb53d8b85289bcc48ee5bfe6f20137d10a087eb6e7871e2a10a599c710af8d0d39e20611",
	gy: "14fdd05545ec1cc8ab4093247f77275e0743ffed117182eaa9c77877aaac6ac7d35245d1692e8ee1",
	n: "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59311",
	h: 0x01,

	name: 'brainpoolP320r1',
	type: "prime-field",
	OID: "1.3.36.3.3.2.8.1.1.9",
	comment: "RFC 5639 curve over a 320 bit prime field"
};

jCastle.pki.ecdsa._registeredParams['brainpoolP320t1'] = 
{
	p: "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e27",
	a: "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e24",
	b: "a7f561e038eb1ed560b3d147db782013064c19f27ed27c6780aaf77fb8a547ceb5b4fef422340353",
	gx: "925be9fb01afc6fb4d3e7d4990010f813408ab106c4f09cb7ee07868cc136fff3357f624a21bed52",
	gy: "63ba3a7a27483ebf6671dbef7abb30ebee084e58a0b077ad42a5a0989d1ee71b1b9bc0455fb0d2c3",
	n: "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59311",
	h: 0x01,

	name: 'brainpoolP320t1',
	type: "prime-field",
	OID: "1.3.36.3.3.2.8.1.1.10",
	comment: "RFC 5639 curve over a 320 bit prime field"
};

jCastle.pki.ecdsa._registeredParams['brainpoolP384r1'] = 
{
	p: "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53",
	a: "7bc382c63d8c150c3c72080ace05afa0c2bea28e4fb22787139165efba91f90f8aa5814a503ad4eb04a8c7dd22ce2826",
	b: "04a8c7dd22ce28268b39b55416f0447c2fb77de107dcd2a62e880ea53eeb62d57cb4390295dbc9943ab78696fa504c11",
	gx: "1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1e",
	gy: "8abe1d7520f9c2a45cb1eb8e95cfd55262b70b29feec5864e19c054ff99129280e4646217791811142820341263c5315",
	n: "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565",
	h: 0x01,

	name: 'brainpoolP384r1',
	type: "prime-field",
	OID: "1.3.36.3.3.2.8.1.1.11",
	comment: "RFC 5639 curve over a 384 bit prime field"
};

jCastle.pki.ecdsa._registeredParams['brainpoolP384t1'] = 
{
	p: "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53",
	a: "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec50",
	b: "7f519eada7bda81bd826dba647910f8c4b9346ed8ccdc64e4b1abd11756dce1d2074aa263b88805ced70355a33b471ee",
	gx: "18de98b02db9a306f2afcd7235f72a819b80ab12ebd653172476fecd462aabffc4ff191b946a5f54d8d0aa2f418808cc",
	gy: "25ab056962d30651a114afd2755ad336747f93475b7a1fca3b88f2b6a208ccfe469408584dc2b2912675bf5b9e582928",
	n: "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565",
	h: 0x01,

	name: 'brainpoolP384t1',
	type: "prime-field",
	OID: "1.3.36.3.3.2.8.1.1.12",
	comment: "RFC 5639 curve over a 384 bit prime field"
};

jCastle.pki.ecdsa._registeredParams['brainpoolP512r1'] = 
{
	p: "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3",
	a: "7830a3318b603b89e2327145ac234cc594cbdd8d3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94ca",
	b: "3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94cadc083e67984050b75ebae5dd2809bd638016f723",
	gx: "81aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098eff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f822",
	gy: "7dde385d566332ecc0eabfa9cf7822fdf209f70024a57b1aa000c55b881f8111b2dcde494a5f485e5bca4bd88a2763aed1ca2b2fa8f0540678cd1e0f3ad80892",
	n: "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069",
	h: 0x01,

	name: 'brainpoolP512r1',
	type: "prime-field",
	OID: "1.3.36.3.3.2.8.1.1.13",
	comment: "RFC 5639 curve over a 512 bit prime field"
};

jCastle.pki.ecdsa._registeredParams['brainpoolP512t1'] = 
{
	p: "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3",
	a: "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f0",
	b: "7cbbbcf9441cfab76e1890e46884eae321f70c0bcb4981527897504bec3e36a62bcdfa2304976540f6450085f2dae145c22553b465763689180ea2571867423e",
	gx: "640ece5c12788717b9c1ba06cbc2a6feba85842458c56dde9db1758d39c0313d82ba51735cdb3ea499aa77a7d6943a64f7a3f25fe26f06b51baa2696fa9035da",
	gy: "5b534bd595f5af0fa2c892376c84ace1bb4e3019b71634c01131159cae03cee9d9932184beef216bd71df2dadf86a627306ecff96dbb8bace198b61e00f8b332",
	n: "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069",
	h: 0x01,

	name: 'brainpoolP512t1',
	type: "prime-field",
	OID: "1.3.36.3.3.2.8.1.1.14",
	comment: "RFC 5639 curve over a 512 bit prime field"
};


//
// binary field - characteristic two curves
// 

// http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.38.8014&rep=rep1&type=pdf

// f(x) = x^113 + x^9 + 1
jCastle.pki.ecdsa._registeredParams['sect113r1'] = 
{
	p: "020000000000000000000000000201",
	a: "003088250CA6E7C7FE649CE85820F7",
	b: "00E8BEE4D3E2260744188BE0E9C723",
	gx: "009D73616F35F4AB1407D73562C10F",
	gy: "00A52830277958EE84D1315ED31886",
	n: "0100000000000000D9CCEC8A39E56F",
	h: 0x02,

	m: 113,
	k1: 9,
	k2: 0,
	k3: 0,

	name: 'sect113r1',
	type: "characteristic-two-field",
	OID: "1.3.132.0.4",
	comment: "SECG/WTLS curve over a 113 bit binary field",
	seed: "10E723AB14D696E6768756151756FEBF8FCB49A9"
};

// f(x) = x^113 + x^9 + 1
jCastle.pki.ecdsa._registeredParams['sect113r2'] = 
{
	p: "020000000000000000000000000201",
	a: "00689918DBEC7E5A0DD6DFC0AA55C7",
	b: "0095E9A9EC9B297BD4BF36E059184F",
	gx: "01A57A6A7B26CA5EF52FCDB8164797",
	gy: "00B3ADC94ED1FE674C06E695BABA1D",
	n: "010000000000000108789B2496AF93",
	h: 0x02,

	m: 113,
	k1: 9,
	k2: 0,
	k3: 0,

	name: 'sect113r2',
	type: "characteristic-two-field",
	OID: "1.3.132.0.5",
	comment: "SECG curve over a 113 bit binary field",
	seed: "10C0FB15760860DEF1EEF4D696E676875615175D"
};

// f(x) = x^131 + x^8 + x^3 +x^2 + 1
jCastle.pki.ecdsa._registeredParams['sect131r1'] = 
{
	p: "080000000000000000000000000000010D",
	a: "07A11B09A76B562144418FF3FF8C2570B8",
	b: "0217C05610884B63B9C6C7291678F9D341",
	gx: "0081BAF91FDF9833C40F9C181343638399",
	gy: "078C6E7EA38C001F73C8134B1B4EF9E150",
	n: "0400000000000000023123953A9464B54D",
	h: 0x02,

	m: 131,
	k1: 2,
	k2: 3,
	k3: 8,

	name: 'sect131r1',
	type: "characteristic-two-field",
	OID: "1.3.132.0.22",
	comment: "SECG curve over a 113 bit binary field",
	seed: "4D696E676875615175985BD3ADBADA21B43A97E2"
};

// f(x) = x^131 + x^8 + x^3 +x^2 + 1
jCastle.pki.ecdsa._registeredParams['sect131r2'] = 
{
	p: "080000000000000000000000000000010D",
	a: "03E5A88919D7CAFCBF415F07C2176573B2",
	b: "04B8266A46C55657AC734CE38F018F2192",
	gx: "0356DCD8F2F95031AD652D23951BB366A8",
	gy: "0648F06D867940A5366D9E265DE9EB240F",
	n: "0400000000000000016954A233049BA98F",
	h: 0x02,

	m: 131,
	k1: 2,
	k2: 3,
	k3: 8,

	name: 'sect131r2',
	type: "characteristic-two-field",
	OID: "1.3.132.0.23",
	comment: "SECG curve over a 131 bit binary field",
	seed: "985BD3ADBAD4D696E676875615175A21B43A97E3"
};

// Gaussian Normal Basis, T=4
// K-163
// f(x) = x^163 + x^7 + x^6 + x^3 + 1
jCastle.pki.ecdsa._registeredParams['sect163k1'] = 
{
	p: "0800000000000000000000000000000000000000C9",
	a: "000000000000000000000000000000000000000001",
	b: "000000000000000000000000000000000000000001",
	gx: "02FE13C0537BBC11ACAA07D793DE4E6D5E5C94EEE8",
	gy: "0289070FB05D38FF58321F2E800536D538CCDAA3D9",
	n: "04000000000000000000020108A2E0CC0D99F8A5EF",
	h: 0x02,

	m: 163,
	k1: 3,
	k2: 6,
	k3: 7,

	name: 'sect163k1',
	type: "characteristic-two-field",
	OID: "1.3.132.0.1",
	comment: "NIST/SECG/WTLS curve over a 163 bit binary field"
};

// f(x) = x^163 + x^7 + x^6 + x^3 + 1
jCastle.pki.ecdsa._registeredParams['sect163r1'] = 
{
	p: "0800000000000000000000000000000000000000C9",
	a: "07B6882CAAEFA84F9554FF8428BD88E246D2782AE2",
	b: "0713612DCDDCB40AAB946BDA29CA91F73AF958AFD9",
	gx: "0369979697AB43897789566789567F787A7876A654",
	gy: "00435EDB42EFAFB2989D51FEFCE3C80988F41FF883",
	n: "03FFFFFFFFFFFFFFFFFFFF48AAB689C29CA710279B",
	h: 0x02,

	m: 163,
	k1: 3,
	k2: 6,
	k3: 7,

	name: 'sect163r1',
	type: "characteristic-two-field",
	OID: "1.3.132.0.2",
	comment: "SECG curve over a 163 bit binary field"
};

// Gaussian Normal Basis, T=4
// B-163
// f(x) = x^163 + x^7 + x^6 + x^3 + 1
jCastle.pki.ecdsa._registeredParams['sect163r2'] = 
{
	p: "0800000000000000000000000000000000000000C9",
	a: "000000000000000000000000000000000000000001",
	b: "020A601907B8C953CA1481EB10512F78744A3205FD",
	gx: "03F0EBA16286A2D57EA0991168D4994637E8343E36",
	gy: "00D51FBC6C71A0094FA2CDD545B11C5C0C797324F1",
	n: "040000000000000000000292FE77E70C12A4234C33",
	h: 0x02,

	m: 163,
	k1: 3,
	k2: 6,
	k3: 7,

	name: 'sect163r2',
	type: "characteristic-two-field",
	OID: "1.3.132.0.15",
	comment: "NIST/SECG curve over a 163 bit binary field"
};

// f(x) = x^193 + x^15 + 1
jCastle.pki.ecdsa._registeredParams['sect193r1'] = 
{
	p: "02000000000000000000000000000000000000000000008001",
	a: "0017858FEB7A98975169E171F77B4087DE098AC8A911DF7B01",
	b: "00FDFB49BFE6C3A89FACADAA7A1E5BBC7CC1C2E5D831478814",
	gx: "01F481BC5F0FF84A74AD6CDF6FDEF4BF6179625372D8C0C5E1",
	gy: "0025E399F2903712CCF3EA9E3A1AD17FB0B3201B6AF7CE1B05",
	n: "01000000000000000000000000C7F34A778F443ACC920EBA49",
	h: 0x02,

	m: 193,
	k1: 15,
	k2: 0,
	k3: 0,

	name: 'sect193r1',
	type: "characteristic-two-field",
	OID: "1.3.132.0.24",
	comment: "SECG curve over a 193 bit binary field",
	seed: "103FAEC74D696E676875615175777FC5B191EF30"
};

// f(x) = x^193 + x^15 + 1
jCastle.pki.ecdsa._registeredParams['sect193r2'] = 
{
	p: "02000000000000000000000000000000000000000000008001",
	a: "0163F35A5137C2CE3EA6ED8667190B0BC43ECD69977702709B",
	b: "00C9BB9E8927D4D64C377E2AB2856A5B16E3EFB7F61D4316AE",
	gx: "00D9B67D192E0367C803F39E1A7E82CA14A651350AAE617E8F",
	gy: "01CE94335607C304AC29E7DEFBD9CA01F596F927224CDECF6C",
	n: "010000000000000000000000015AAB561B005413CCD4EE99D5",
	h: 0x02,

	m: 193,
	k1: 15,
	k2: 0,
	k3: 0,

	name: 'sect193r2',
	type: "characteristic-two-field",
	OID: "1.3.132.0.25",
	comment: "SECG curve over a 193 bit binary field",
	seed: "10B7B4D696E676875615175137C8A16FD0DA2211"
};

// Gaussian Normal Basis, T=2
// K-233
// f(x) = x^233 + x^74 + 1
jCastle.pki.ecdsa._registeredParams['sect233k1'] = 
{
	p: "020000000000000000000000000000000000000004000000000000000001",
	a: "000000000000000000000000000000000000000000000000000000000000",
	b: "000000000000000000000000000000000000000000000000000000000001",
	gx: "017232BA853A7E731AF129F22FF4149563A419C26BF50A4C9D6EEFAD6126",
	gy: "01DB537DECE819B7F70F555A67C427A8CD9BF18AEB9B56E0C11056FAE6A3",
	n: "008000000000000000000000000000069D5BB915BCD46EFB1AD5F173ABDF",
	h: 0x04,

	m: 233,
	k1: 74,
	k2: 0,
	k3: 0,

	name: 'sect233k1',
	type: "characteristic-two-field",
	OID: "1.3.132.0.26",
	comment: "NIST/SECG/WTLS curve over a 233 bit binary field"
};

// Gaussian Normal Basis, T=2
// B-233
// f(x) = x^233 + x^74 + 1
jCastle.pki.ecdsa._registeredParams['sect233r1'] = 
{
	p: "020000000000000000000000000000000000000004000000000000000001",
	a: "000000000000000000000000000000000000000000000000000000000001",
	b: "0066647EDE6C332C7F8C0923BB58213B333B20E9CE4281FE115F7D8F90AD",
	gx: "00FAC9DFCBAC8313BB2139F1BB755FEF65BC391F8B36F8F8EB7371FD558B",
	gy: "01006A08A41903350678E58528BEBF8A0BEFF867A7CA36716F7E01F81052",
	n: "01000000000000000000000000000013E974E72F8A6922031D2603CFE0D7",
	h: 0x02,

	m: 233,
	k1: 74,
	k2: 0,
	k3: 0,

	name: 'sect233r1',
	type: "characteristic-two-field",
	OID: "1.3.132.0.27",
	comment: "NIST/SECG/WTLS curve over a 233 bit binary field",
	seed: "74D59FF07F6B413D0EA14B344B20A2DB049B50C3"
};

// f(x) = x^239 + x^158 + 1
jCastle.pki.ecdsa._registeredParams['sect239k1'] = 
{
	p: "800000000000000000004000000000000000000000000000000000000001",
	a: "000000000000000000000000000000000000000000000000000000000000",
	b: "000000000000000000000000000000000000000000000000000000000001",
	gx: "29A0B6A887A983E9730988A68727A8B2D126C44CC2CC7B2A6555193035DC",
	gy: "76310804F12E549BDB011C103089E73510ACB275FC312A5DC6B76553F0CA",
	n: "2000000000000000000000000000005A79FEC67CB6E91F1C1DA800E478A5",
	h: 0x04,

	m: 239,
	k1: 158,
	k2: 0,
	k3: 0,

	name: 'sect239k1',
	type: "characteristic-two-field",
	OID: "1.3.132.0.3",
	comment: "SECG curve over a 239 bit binary field"
};

// Gaussian Normal Basis, T=6
// K-283
// f(x) = x^283 + x^12 + x^7 + x^5 + 1
jCastle.pki.ecdsa._registeredParams['sect283k1'] = 
{
	p: "0800000000000000000000000000000000000000000000000000000000000000000010A1",
	a: "000000000000000000000000000000000000000000000000000000000000000000000000",
	b: "000000000000000000000000000000000000000000000000000000000000000000000001",
	gx: "0503213F78CA44883F1A3B8162F188E553CD265F23C1567A16876913B0C2AC2458492836",
	gy: "01CCDA380F1C9E318D90F95D07E5426FE87E45C0E8184698E45962364E34116177DD2259",
	n: "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE9AE2ED07577265DFF7F94451E061E163C61",
	h: 0x04,

	m: 283,
	k1: 5,
	k2: 7,
	k3: 12,

	name: 'sect283k1',
	type: "characteristic-two-field",
	OID: "1.3.132.0.16",
	comment: "NIST/SECG curve over a 283 bit binary field"
};

// Gaussian Normal Basis, T=6
// B-283
// f(x) = x^283 + x^12 + x^7 + x^5 + 1
jCastle.pki.ecdsa._registeredParams['sect283r1'] = 
{
	p: "0800000000000000000000000000000000000000000000000000000000000000000010A1",
	a: "000000000000000000000000000000000000000000000000000000000000000000000001",
	b: "027B680AC8B8596DA5A4AF8A19A0303FCA97FD7645309FA2A581485AF6263E313B79A2F5",
	gx: "05F939258DB7DD90E1934F8C70B0DFEC2EED25B8557EAC9C80E2E198F8CDBECD86B12053",
	gy: "03676854FE24141CB98FE6D4B20D02B4516FF702350EDDB0826779C813F0DF45BE8112F4",
	n: "03FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEF90399660FC938A90165B042A7CEFADB307",
	h: 0x02,

	m: 283,
	k1: 5,
	k2: 7,
	k3: 12,

	name: 'sect283r1',
	type: "characteristic-two-field",
	OID: "1.3.132.0.17",
	comment: "NIST/SECG curve over a 283 bit binary field",
	seed: "77E2B07370EB0F832A6DD5B62DFC88CD06BB84BE"
};

// Gaussian Normal Basis, T=4
// K-409
// f(x) = x^409 + x^87 + 1
jCastle.pki.ecdsa._registeredParams['sect409k1'] = 
{
	p: "02000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000001",
	a: "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	b: "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
	gx: "0060F05F658F49C1AD3AB1890F7184210EFD0987E307C84C27ACCFB8F9F67CC2C460189EB5AAAA62EE222EB1B35540CFE9023746",
	gy: "01E369050B7C4E42ACBA1DACBF04299C3460782F918EA427E6325165E9EA10E3DA5F6C42E9C55215AA9CA27A5863EC48D8E0286B",
	n: "007FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE5F83B2D4EA20400EC4557D5ED3E3E7CA5B4B5C83B8E01E5FCF",
	h: 0x04,

	m: 409,
	k1: 87,
	k2: 0,
	k3: 0,

	name: 'sect409k1',
	type: "characteristic-two-field",
	OID: "1.3.132.0.36",
	comment: "NIST/SECG curve over a 409 bit binary field"
};

// Gaussian Normal Basis, T=4
// B-409
// f(x) = x^409 + x^87 + 1
jCastle.pki.ecdsa._registeredParams['sect409r1'] = 
{
	p: "02000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000001",
	a: "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
	b: "0021A5C2C8EE9FEB5C4B9A753B7B476B7FD6422EF1F3DD674761FA99D6AC27C8A9A197B272822F6CD57A55AA4F50AE317B13545F",
	gx: "015D4860D088DDB3496B0C6064756260441CDE4AF1771D4DB01FFE5B34E59703DC255A868A1180515603AEAB60794E54BB7996A7",
	gy: "0061B1CFAB6BE5F32BBFA78324ED106A7636B9C5A7BD198D0158AA4F5488D08F38514F1FDF4B4F40D2181B3681C364BA0273C706",
	n: "010000000000000000000000000000000000000000000000000001E2AAD6A612F33307BE5FA47C3C9E052F838164CD37D9A21173",
	h: 0x02,

	m: 409,
	k1: 87,
	k2: 0,
	k3: 0,

	name: 'sect409r1',
	type: "characteristic-two-field",
	OID: "1.3.132.0.37",
	comment: "NIST/SECG curve over a 409 bit binary field",
	seed: "4099B5A457F9D69F79213D094C4BCD4D4262210B"
};

// Gaussian Normal Basis, T=10
// K-571
// f(x) = x^571 + x^10 + x^5 + x^2 + 1
jCastle.pki.ecdsa._registeredParams['sect571k1'] = 
{
	p: "080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000425",
	a: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	b: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
	gx: "026EB7A859923FBC82189631F8103FE4AC9CA2970012D5D46024804801841CA44370958493B205E647DA304DB4CEB08CBBD1BA39494776FB988B47174DCA88C7E2945283A01C8972",
	gy: "0349DC807F4FBF374F4AEADE3BCA95314DD58CEC9F307A54FFC61EFC006D8A2C9D4979C0AC44AEA74FBEBBB9F772AEDCB620B01A7BA7AF1B320430C8591984F601CD4C143EF1C7A3",
	n: "020000000000000000000000000000000000000000000000000000000000000000000000131850E1F19A63E4B391A8DB917F4138B630D84BE5D639381E91DEB45CFE778F637C1001",
	h: 0x04,

	m: 571,
	k1: 2,
	k2: 5,
	k3: 10,

	name: 'sect571k1',
	type: "characteristic-two-field",
	OID: "1.3.132.0.38",
	comment: "NIST/SECG curve over a 571 bit binary field"
};

// Gaussian Normal Basis, T=10
// B-571
// f(x) = x^571 + x^10 + x^5 + x^2 + 1
jCastle.pki.ecdsa._registeredParams['sect571r1'] = 
{
	p: "080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000425",
	a: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
	b: "02F40E7E2221F295DE297117B7F3D62F5C6A97FFCB8CEFF1CD6BA8CE4A9A18AD84FFABBD8EFA59332BE7AD6756A66E294AFD185A78FF12AA520E4DE739BACA0C7FFEFF7F2955727A",
	gx: "0303001D34B856296C16C0D40D3CD7750A93D1D2955FA80AA5F40FC8DB7B2ABDBDE53950F4C0D293CDD711A35B67FB1499AE60038614F1394ABFA3B4C850D927E1E7769C8EEC2D19",
	gy: "037BF27342DA639B6DCCFFFEB73D69D78C6C27A6009CBBCA1980F8533921E8A684423E43BAB08A576291AF8F461BB2A8B3531D2F0485C19B16E2F1516E23DD3C1A4827AF1B8AC15B",
	n: "03FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE661CE18FF55987308059B186823851EC7DD9CA1161DE93D5174D66E8382E9BB2FE84E47",
	h: 0x02,

	m: 571,
	k1: 2,
	k2: 5,
	k3: 10,

	name: 'sect571r1',
	type: "characteristic-two-field",
	OID: "1.3.132.0.39",
	comment: "NIST/SECG curve over a 409 bit binary field",
	seed: "2AA058F73A0E33AB486B0F610410C53A7F132310"
};

// f(x) = x^163 + x^8 + x^2 + x^1 + 1
jCastle.pki.ecdsa._registeredParams['c2pnb163v1'] = 
{
	p: "080000000000000000000000000000000000000107",
	a: "072546B5435234A422E0789675F432C89435DE5242",
	b: "00C9517D06D5240D3CFF38C74B20B6CD4D6F9DD4D9",
	gx: "07AF69989546103D79329FCC3D74880F33BBE803CB",
	gy: "01EC23211B5966ADEA1D3F87F7EA5848AEF0B7CA9F",
	n: "0400000000000000000001E60FC8821CC74DAEAFC1",
	h: 0x02,

	m: 163,
	k1: 1,
	k2: 2,
	k3: 8,

	name: 'c2pnb163v1',
	type: "characteristic-two-field",
	OID: "1.2.840.10045.3.0.1",
	comment: "X9.62 curve over a 163 bit binary field",
	seed: "D2C0FB15760860DEF1EEF4D696E6768756151754"
};

// f(x) = x^163 + x^8 + x^2 + x^1 + 1
jCastle.pki.ecdsa._registeredParams['c2pnb163v2'] = 
{
	p: "080000000000000000000000000000000000000107",
	a: "0108B39E77C4B108BED981ED0E890E117C511CF072",
	b: "0667ACEB38AF4E488C407433FFAE4F1C811638DF20",
	gx: "0024266E4EB5106D0A964D92C4860E2671DB9B6CC5",
	gy: "079F684DDF6684C5CD258B3890021B2386DFD19FC5",
	n: "03FFFFFFFFFFFFFFFFFFFDF64DE1151ADBB78F10A7",
	h: 0x02,

	m: 163,
	k1: 1,
	k2: 2,
	k3: 8,

	name: 'c2pnb163v2',
	type: "characteristic-two-field",
	OID: "1.2.840.10045.3.0.2",
	comment: "X9.62 curve over a 163 bit binary field",
	seed: "53814C050D44D696E67687561517580CA4E29FFD"
};

// f(x) = x^163 + x^8 + x^2 + x^1 + 1
jCastle.pki.ecdsa._registeredParams['c2pnb163v3'] = 
{
	p: "080000000000000000000000000000000000000107",
	a: "07A526C63D3E25A256A007699F5447E32AE456B50E",
	b: "03F7061798EB99E238FD6F1BF95B48FEEB4854252B",
	gx: "02F9F87B7C574D0BDECF8A22E6524775F98CDEBDCB",
	gy: "05B935590C155E17EA48EB3FF3718B893DF59A05D0",
	n: "03FFFFFFFFFFFFFFFFFFFE1AEE140F110AFF961309",
	h: 0x02,

	m: 163,
	k1: 1,
	k2: 2,
	k3: 8,

	name: 'c2pnb163v3',
	type: "characteristic-two-field",
	OID: "1.2.840.10045.3.0.3",
	comment: "X9.62 curve over a 163 bit binary field",
	seed: "50CBF1D95CA94D696E676875615175F16A36A3B8"
};

// f(x) = x^176 + x^43 + x^2 + x^1 + 1
jCastle.pki.ecdsa._registeredParams['c2pnb176v1'] = 
{
	p: "0100000000000000000000000000000000080000000007",
	a: "00E4E6DB2995065C407D9D39B8D0967B96704BA8E9C90B",
	b: "005DDA470ABE6414DE8EC133AE28E9BBD7FCEC0AE0FFF2",
	gx: "008D16C2866798B600F9F08BB4A8E860F3298CE04A5798",
	gy: "006FA4539C2DADDDD6BAB5167D61B436E1D92BB16A562C",
	n: "0000010092537397ECA4F6145799D62B0A19CE06FE26AD",
	h: 0xFF6E,

	m: 176,
	k1: 1,
	k2: 2,
	k3: 43,

	name: 'c2pnb176v1',
	type: "characteristic-two-field",
	OID: "1.2.840.10045.3.0.4",
	comment: "X9.62 curve over a 176 bit binary field"
};

// f(x) = x^191 + x^9 + 1
jCastle.pki.ecdsa._registeredParams['c2tnb191v1'] = 
{
	p: "800000000000000000000000000000000000000000000201",
	a: "2866537B676752636A68F56554E12640276B649EF7526267",
	b: "2E45EF571F00786F67B0081B9495A3D95462F5DE0AA185EC",
	gx: "36B3DAF8A23206F9C4F299D7B21A9C369137F2C84AE1AA0D",
	gy: "765BE73433B3F95E332932E70EA245CA2418EA0EF98018FB",
	n: "40000000000000000000000004A20E90C39067C893BBB9A5",
	h: 0x02,

	m: 191,
	k1: 9,
	k2: 0,
	k3: 0,

	name: 'c2tnb191v1',
	type: "characteristic-two-field",
	OID: "1.2.840.10045.3.0.5",
	comment: "X9.62 curve over a 191 bit binary field",
	seed: "4E13CA542744D696E67687561517552F279A8C84"
};

// f(x) = x^191 + x^9 + 1
jCastle.pki.ecdsa._registeredParams['c2tnb191v2'] = 
{
	p: "800000000000000000000000000000000000000000000201",
	a: "401028774D7777C7B7666D1366EA432071274F89FF01E718",
	b: "0620048D28BCBD03B6249C99182B7C8CD19700C362C46A01",
	gx: "3809B2B7CC1B28CC5A87926AAD83FD28789E81E2C9E3BF10",
	gy: "17434386626D14F3DBF01760D9213A3E1CF37AEC437D668A",
	n: "20000000000000000000000050508CB89F652824E06B8173",
	h: 0x04,

	m: 191,
	k1: 9,
	k2: 0,
	k3: 0,

	name: 'c2tnb191v2',
	type: "characteristic-two-field",
	OID: "1.2.840.10045.3.0.6",
	comment: "X9.62 curve over a 191 bit binary field",
	seed: "0871EF2FEF24D696E6768756151758BEE0D95C15"
};

// f(x) = x^191 + x^9 + 1
jCastle.pki.ecdsa._registeredParams['c2tnb191v3'] = 
{
	p: "800000000000000000000000000000000000000000000201",
	a: "6C01074756099122221056911C77D77E77A777E7E7E77FCB",
	b: "71FE1AF926CF847989EFEF8DB459F66394D90F32AD3F15E8",
	gx: "375D4CE24FDE434489DE8746E71786015009E66E38A926DD",
	gy: "545A39176196575D985999366E6AD34CE0A77CD7127B06BE",
	n: "155555555555555555555555610C0B196812BFB6288A3EA3",
	h: 0x06,

	m: 191,
	k1: 9,
	k2: 0,
	k3: 0,

	name: 'c2tnb191v3',
	type: "characteristic-two-field",
	OID: "1.2.840.10045.3.0.7",
	comment: "X9.62 curve over a 191 bit binary field",
	seed: "E053512DC684D696E676875615175067AE786D1F"
};

// f(x) = x^208 + x^83 + x^2 + x^1 + 1
jCastle.pki.ecdsa._registeredParams['c2pnb208w1'] = 
{
	p: "010000000000000000000000000000000800000000000000000007",
	a: "000000000000000000000000000000000000000000000000000000",
	b: "00C8619ED45A62E6212E1160349E2BFA844439FAFC2A3FD1638F9E",
	gx: "0089FDFBE4ABE193DF9559ECF07AC0CE78554E2784EB8C1ED1A57A",
	gy: "000F55B51A06E78E9AC38A035FF520D8B01781BEB1A6BB08617DE3",
	n: "00000101BAF95C9723C57B6C21DA2EFF2D5ED588BDD5717E212F9D",
	h: 0xFE48,

	m: 208,
	k1: 1,
	k2: 2,
	k3: 83,

	name: 'c2pnb208w1',
	type: "characteristic-two-field",
	OID: "1.2.840.10045.3.0.10",
	comment: "X9.62 curve over a 208 bit binary field"
};

// f(x) = x^239 + x^36 + 1
jCastle.pki.ecdsa._registeredParams['c2tnb239v1'] = 
{
	p: "800000000000000000000000000000000000000000000000001000000001",
	a: "32010857077C5431123A46B808906756F543423E8D27877578125778AC76",
	b: "790408F2EEDAF392B012EDEFB3392F30F4327C0CA3F31FC383C422AA8C16",
	gx: "57927098FA932E7C0A96D3FD5B706EF7E5F5C156E16B7E7C86038552E91D",
	gy: "61D8EE5077C33FECF6F1A16B268DE469C3C7744EA9A971649FC7A9616305",
	n: "2000000000000000000000000000000F4D42FFE1492A4993F1CAD666E447",
	h: 0x04,

	m: 239,
	k1: 36,
	k2: 0,
	k3: 0,

	name: 'c2tnb239v1',
	type: "characteristic-two-field",
	OID: "1.2.840.10045.3.0.11",
	comment: "X9.62 curve over a 239 bit binary field",
	seed: "D34B9A4D696E676875615175CA71B920BFEFB05D"
};

// f(x) = x^239 + x^36 + 1
jCastle.pki.ecdsa._registeredParams['c2tnb239v2'] = 
{
	p: "800000000000000000000000000000000000000000000000001000000001",
	a: "4230017757A767FAE42398569B746325D45313AF0766266479B75654E65F",
	b: "5037EA654196CFF0CD82B2C14A2FCF2E3FF8775285B545722F03EACDB74B",
	gx: "28F9D04E900069C8DC47A08534FE76D2B900B7D7EF31F5709F200C4CA205",
	gy: "5667334C45AFF3B5A03BAD9DD75E2C71A99362567D5453F7FA6E227EC833",
	n: "1555555555555555555555555555553C6F2885259C31E3FCDF154624522D",
	h: 0x06,

	m: 239,
	k1: 36,
	k2: 0,
	k3: 0,

	name: 'c2tnb239v2',
	type: "characteristic-two-field",
	OID: "1.2.840.10045.3.0.12",
	comment: "X9.62 curve over a 239 bit binary field",
	seed: "2AA6982FDFA4D696E676875615175D266727277D"
};

// f(x) = x^239 + x^36 + 1
jCastle.pki.ecdsa._registeredParams['c2tnb239v3'] = 
{
	p: "800000000000000000000000000000000000000000000000001000000001",
	a: "01238774666A67766D6676F778E676B66999176666E687666D8766C66A9F",
	b: "6A941977BA9F6A435199ACFC51067ED587F519C5ECB541B8E44111DE1D40",
	gx: "70F6E9D04D289C4E89913CE3530BFDE903977D42B146D539BF1BDE4E9C92",
	gy: "2E5A0EAF6E5E1305B9004DCE5C0ED7FE59A35608F33837C816D80B79F461",
	n: "0CCCCCCCCCCCCCCCCCCCCCCCCCCCCCAC4912D2D9DF903EF9888B8A0E4CFF",
	h: 0x0A,

	m: 239,
	k1: 36,
	k2: 0,
	k3: 0,

	name: 'c2tnb239v3',
	type: "characteristic-two-field",
	OID: "1.2.840.10045.3.0.13",
	comment: "X9.62 curve over a 239 bit binary field",
	seed: "9E076F4D696E676875615175E11E9FDD77F92041"
};

// f(x) = x^272 + x^56 + x^3 + x^1 + 1
jCastle.pki.ecdsa._registeredParams['c2pnb272w1'] = 
{
	p: "010000000000000000000000000000000000000000000000000000010000000000000B",
	a: "0091A091F03B5FBA4AB2CCF49C4EDD220FB028712D42BE752B2C40094DBACDB586FB20",
	b: "007167EFC92BB2E3CE7C8AAAFF34E12A9C557003D7C73A6FAF003F99F6CC8482E540F7",
	gx: "006108BABB2CEEBCF787058A056CBE0CFE622D7723A289E08A07AE13EF0D10D171DD8D",
	gy: "0010C7695716851EEF6BA7F6872E6142FBD241B830FF5EFCACECCAB05E02005DDE9D23",
	n: "00000100FAF51354E0E39E4892DF6E319C72C8161603FA45AA7B998A167B8F1E629521",
	h: 0xFF06,

	m: 272,
	k1: 1,
	k2: 3,
	k3: 56,

	name: 'c2pnb272w1',
	type: "characteristic-two-field",
	OID: "1.2.840.10045.3.0.16",
	comment: "X9.62 curve over a 272 bit binary field"
};

// f(x) = x^304 + x^11 + x^2 + x^1 + 1
jCastle.pki.ecdsa._registeredParams['c2pnb304w1'] = 
{
	p: "010000000000000000000000000000000000000000000000000000000000000000000000000807",
	a: "00FD0D693149A118F651E6DCE6802085377E5F882D1B510B44160074C1288078365A0396C8E681",
	b: "00BDDB97E555A50A908E43B01C798EA5DAA6788F1EA2794EFCF57166B8C14039601E55827340BE",
	gx: "00197B07845E9BE2D96ADB0F5F3C7F2CFFBD7A3EB8B6FEC35C7FD67F26DDF6285A644F740A2614",
	gy: "00E19FBEB76E0DA171517ECF401B50289BF014103288527A9B416A105E80260B549FDC1B92C03B",
	n: "00000101D556572AABAC800101D556572AABAC8001022D5C91DD173F8FB561DA6899164443051D",
	h: 0xFE2E,

	m: 304,
	k1: 1,
	k2: 2,
	k3: 11,

	name: 'c2pnb304w1',
	type: "characteristic-two-field",
	OID: "1.2.840.10045.3.0.17",
	comment: "X9.62 curve over a 304 bit binary field"
};

// f(x) = x^359 + x^68 + 1
jCastle.pki.ecdsa._registeredParams['c2tnb359v1'] = 
{
	p: "800000000000000000000000000000000000000000000000000000000000000000000000100000000000000001",
	a: "5667676A654B20754F356EA92017D946567C46675556F19556A04616B567D223A5E05656FB549016A96656A557",
	b: "2472E2D0197C49363F1FE7F5B6DB075D52B6947D135D8CA445805D39BC345626089687742B6329E70680231988",
	gx: "3C258EF3047767E7EDE0F1FDAA79DAEE3841366A132E163ACED4ED2401DF9C6BDCDE98E8E707C07A2239B1B097",
	gy: "53D7E08529547048121E9C95F3791DD804963948F34FAE7BF44EA82365DC7868FE57E4AE2DE211305A407104BD",
	n: "01AF286BCA1AF286BCA1AF286BCA1AF286BCA1AF286BC9FB8F6B85C556892C20A7EB964FE7719E74F490758D3B",
	h: 0x4C,

	m: 359,
	k1: 68,
	k2: 0,
	k3: 0,

	name: 'c2tnb359v1',
	type: "characteristic-two-field",
	OID: "1.2.840.10045.3.0.18",
	comment: "X9.62 curve over a 359 bit binary field",
	seed: "2B354920B724D696E67687561517585BA1332DC6"
};

// f(x) = x^368 + x^85 + x^2 + x^1 + 1
jCastle.pki.ecdsa._registeredParams['c2pnb368w1'] = 
{
	p: "0100000000000000000000000000000000000000000000000000000000000000000000002000000000000000000007",
	a: "00E0D2EE25095206F5E2A4F9ED229F1F256E79A0E2B455970D8D0D865BD94778C576D62F0AB7519CCD2A1A906AE30D",
	b: "00FC1217D4320A90452C760A58EDCD30C8DD069B3C34453837A34ED50CB54917E1C2112D84D164F444F8F74786046A",
	gx: "001085E2755381DCCCE3C1557AFA10C2F0C0C2825646C5B34A394CBCFA8BC16B22E7E789E927BE216F02E1FB136A5F",
	gy: "007B3EB1BDDCBA62D5D8B2059B525797FC73822C59059C623A45FF3843CEE8F87CD1855ADAA81E2A0750B80FDA2310",
	n: "0000010090512DA9AF72B08349D98A5DD4C7B0532ECA51CE03E2D10F3B7AC579BD87E909AE40A6F131E9CFCE5BD967",
	h: 0xFF70,

	m: 368,
	k1: 1,
	k2: 2,
	k3: 85,

	name: 'c2pnb368w1',
	type: "characteristic-two-field",
	OID: "1.2.840.10045.3.0.19",
	comment: "X9.62 curve over a 368 bit binary field"
};

// f(x) = x^431 + x^120 + 1
jCastle.pki.ecdsa._registeredParams['c2tnb431r1'] = 
{
	p: "800000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000001",
	a: "1A827EF00DD6FC0E234CAF046C6A5D8A85395B236CC4AD2CF32A0CADBDC9DDF620B0EB9906D0957F6C6FEACD615468DF104DE296CD8F",
	b: "10D9B4A3D9047D8B154359ABFB1B7F5485B04CEB868237DDC9DEDA982A679A5A919B626D4E50A8DD731B107A9962381FB5D807BF2618",
	gx: "120FC05D3C67A99DE161D2F4092622FECA701BE4F50F4758714E8A87BBF2A658EF8C21E7C5EFE965361F6C2999C0C247B0DBD70CE6B7",
	gy: "20D0AF8903A96F8D5FA2C255745D3C451B302C9346D9B7E485E7BCE41F6B591F3E8F6ADDCBB0BC4C2F947A7DE1A89B625D6A598B3760",
	n: "000340340340340340340340340340340340340340340340340340340323C313FAB50589703B5EC68D3587FEC60D161CC149C1AD4A91",
	h: 0x2760,

	m: 431,
	k1: 120,
	k2: 0,
	k3: 0,

	name: 'c2tnb431r1',
	type: "characteristic-two-field",
	OID: "1.2.840.10045.3.0.20",
	comment: "X9.62 curve over a 431 bit binary field"
};

// Cannot find the polynomial f(x) definition anywhere!

/*
jCastle.pki.ecdsa._registeredParams['wap_wsg_idm_ecid_wtls1'] = 
{
	p: "020000000000000000000000000201",
	a: "000000000000000000000000000001",
	b: "000000000000000000000000000001",
	gx: "01667979A40BA497E5D5C270780617",
	gy: "00F44B4AF1ECC2630E08785CEBCC15",
	n: "00FFFFFFFFFFFFFFFDBF91AF6DEA73",
	h: 0x02,

	name: 'wap_wsg_idm_ecid_wtls1',
	type: "characteristic-two-field",
	OID: "2.23.43.1.4.1",
	comment: "WTLS curve over a 113 bit binary field"
};

// IPSec curves

// NOTE: The curves over a extension field of non prime degree is not
// recommended (Weil-descent). As the group order is not a prime, this curve
// is not suitable for ECDSA.
jCastle.pki.ecdsa._registeredParams['ipsec3'] = 
{
	p: "0800000000000000000000004000000000000001",
	a: "0000000000000000000000000000000000000000",
	b: "000000000000000000000000000000000007338f",
	gx: "000000000000000000000000000000000000007b",
	gy: "00000000000000000000000000000000000001c8",
	n: "02AAAAAAAAAAAAAAAAAAC7F3C7881BD0868FA86C",
	h: 0x03,

	name: 'ipsec3',
	type: "characteristic-two-field",
	OID: null,
	comment: "IPSec/IKE/Oakley curve #3 over a 155 bit binary field.\n"+
		"\tNot suitable for ECDSA.\n\tQuestionable extension field!"
};

// NOTE: The curves over a extension field of non prime degree is not
// recommended (Weil-descent). As the group order is not a prime, this curve
// is not suitable for ECDSA.
jCastle.pki.ecdsa._registeredParams['ipsec4'] = 
{
	p: "020000000000000000000000000000200000000000000001",
	a: "000000000000000000000000000000000000000000000000",
	b: "000000000000000000000000000000000000000000001ee9",
	gx: "000000000000000000000000000000000000000000000018",
	gy: "00000000000000000000000000000000000000000000000d",
	n: "00FFFFFFFFFFFFFFFFFFFFFFEDF97C44DB9F2420BAFCA75E",
	h: 0x02,

	name: 'ipsec4',
	type: "characteristic-two-field",
	OID: null,
	comment: "IPSec/IKE/Oakley curve #4 over a 185 bit binary field.\n"+
		"\tNot suitable for ECDSA.\n\tQuestionable extension field!"
};
*/