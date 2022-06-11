/**
 * jCastle - A Javascript implemenation of JOSE - Javascript Object Signing & Encryption
 * 
 * @author Jacob Lee
 *
 * Copyright (C) 2015-2022 Jacob Lee.
 */

// for vector test: RFC 7520.

var jCastle = require('./jCastle');
require('./util');

/*
 * A Javascript implementation of JWS - JSON Web Signature
 * -------------------------------------------------------
 */

jCastle.jose = class
{
	/**
	 * An implementation of JOSE (Javascript Object Signing & Encryption)
	 * 
	 * @constructor
	 */
	constructor()
	{
		this.joseInfo = null;
	}

	/**
	 * resets internal variables.
	 * 
	 * @public
	 * @returns this class instance.
	 */
	reset()
	{
		this.joseInfo = null;

		return this;
	}

/*
jCastle.jose.sign(payload, algo_params, options)
----------------------------------------------------
jCastle.jose.sign(
	payload,
	{ // algorithm_params_info
		type: 'JWT',
		algoName: 'RS256',
		keyID: '2010-12-29',
		key: rsaPrivateKey
	},
	{ // options
		serialize: 'general'
	}
);

jCastle.jose.sign(
	payload,
	[
		{
			algoName:"RS256",
			keyID:"2010-12-29",
			key: rsa_private_key
		}, {
			algoName:"ES256",
			keyID:"e9bc097a-ce51-4036-9562-d2ade882db0d",
			key: ecdsa_private_key,

			// Protecting Content Only
			// if only content is protected. it means 'alg' is not protected.
			protectContentOnly: true
		},
		{
			algoName: "HS256",
			keyID: "018c0ae5-4d9b-471b-bfd6-eef314bc7037",

			// Protecting JWS Header
			// all header values need to be protected.
			protectHeader: true
		}
	],
	{ // options
		serialize: 'general',

		// if 'detachedPayload' is true, 
		// then the resulting JWS objects do not include the Payload content.
		detachedPayload: true,

		
	}
);
*/
	/**
	 * signs a message for JWS.
	 * 
	 * @public
	 * @param {buffer} message message string or buffer
	 * @param {mixed} params array of algorithm info parameters or algorithm info parameters object.
	 *                {string} algoName algorithm name ex) 'ES256' or 'HS256'
	 *                {mixed} key key string or object for algorithm.
	 *                {string} keyID key id value. if key object has kid or keyID then it is used for it.
	 *                {boolean} protectContentOnly flag for protecting content only.
	 *                {boolean} protectHeader flag for protecting all header values.
	 * @param {object} options options object.
	 *                {string} serialize serialization option. 'general' | 'flattened' | 'compact'. (default: 'compact')
	 *                {boolean} detachedPayload flag for detached payload. this option is not needed when serialize is 'compact'.
	 * @returns JWS string or object.
	 */
	sign(message, params, options = {})
	{
		var serialize = 'serialize' in options ? options.serialize.toLowerCase() : 'compact';
		// if 'detached' is true, 
		// then the resulting JWS objects do not include the Payload content.
		var detached = 'detachedPayload' in options ? options.detachedPayload : false;
		// Protecting Content Only
		// if only content is protected. it means 'alg' is not protected.
		// it works only when serialize is 'general' or 'flattened'.
		var algo_params;
		var compact_header;
		var payload_b64u;
		var payload;

		// console.log('jose.sign()');

		if (!Buffer.isBuffer(payload)) payload = Buffer.from(message);
		else payload = message;
		
		payload_b64u = payload.toString('base64url');

		if (Array.isArray(params)) {
			algo_params = params;
		} else {
			algo_params = [params];
		}

		//var flattened = algo_params.length == 1;
		var signatures = [];
		var protectContentOnly;

		for (var i = 0; i < algo_params.length; i++) {
			var algo = algo_params[i].algoName || algo_params[i].alg;
			var algo_info = jCastle.jose.fn.getSignAlgoInfo(algo);
			var key = algo_params[i].privateKey || algo_params[i].key || algo_params[i].k;
			var signature = {};
			var header = {};
			protectContentOnly = 'protectContentOnly' in algo_params[i] && algo_params[i].protectContentOnly ? true : false;
			var protectHeader = 'protectHeader' in algo_params[i] && algo_params[i].protectHeader ? true : false;

			// two modes cannot be co-exist
			if (protectContentOnly && protectHeader) throw jCastle.exception('CONFLICT_EACH_OPTION', 'JOS030');

			if (algo_info.algoName != 'none' && !key) throw jCastle.exception('KEY_NOT_SET', 'JOS001');

			if ('header' in algo_params[i]) {
				signature.header = jCastle.util.isString(algo_params[i].header) ? algo_params[i].header : JSON.stringify(algo_params[i].header);
				if (i == 0 && serialize == 'compact') {
					compact_header = Buffer.from(signature.header).toString('base64url');
				}
			} else {

				if (i == 0 && serialize == 'compact') {
					protectContentOnly = false;
					protectHeader = false;

					compact_header = {};
					compact_header.alg = algo;
				}

				if (protectContentOnly || protectHeader) {
					header.alg = algo;
				}

				var type = algo_params[i].type || algo_params[i].typ || null;
				if (type) header.typ = type;
		
				for (var p in jCastle.jose.headerParameters) {
					if (p in algo_params[i]) {
						header[jCastle.jose.headerParameters[p]] = algo_params[i][p];
					}
					if (p == 'kid' && 'kid' in key && !('kid' in header)) header.kid = key.kid;
				}

				// KeyID can be included in the key object.
				// example: 
				// {
				//     "kty": "RSA",
				//     "kid": "bilbo.baggins@hobbiton.example",
				//     "use": "sig",
				//     ...
				// }
				//if ('kid' in key && !('kid' in header)) header.kid = key.kid;

				// critical header parameter
				if ('crit' in header) {
					var critical = algo_params[i].critical || algo_params[i].crit;
					for (var c = 0; c < critical.length; c++) {
						if (critical[c] in algo_params[i] && !(critical[c] in header)) {
							header[critical[c]] = algo_params[i][critical[c]];
						}
					}
				}

				

				var header_str = JSON.stringify(header);
				//console.log('header_str: ', header_str);

				if (header_str != '{}' && !protectHeader) {
					signature.header = header;
					//signature.header = JSON.parse(header_str);
				}

				if (i == 0 && serialize == 'compact') {
					compact_header = Object.assign(compact_header, header);
					compact_header = JSON.stringify(compact_header);

					// console.log('compact_header: ', compact_header);
					compact_header = Buffer.from(compact_header).toString('base64url');
				}
			}

			// console.log('algo_info: ', algo_info);

			// var protected_b64u = (i == 0 && serialize == 'compact') ? 
			// 					compact_header : Buffer.from('{"alg":"' + algo + '"}').toString('base64url');
			var protected_b64u;
			if (i == 0 && serialize == 'compact') {
				protected_b64u = compact_header;
			} else {
				if (protectHeader) protected_b64u = Buffer.from(JSON.stringify(header)).toString('base64url');
				else protected_b64u = Buffer.from('{"alg":"' + algo + '"}').toString('base64url');
			}

			var signature_b64u = jCastle.jose.fn.getSignature(
				(protectContentOnly ? '' : protected_b64u) + '.' + payload_b64u, 
				algo_info, 
				key);

			if (!protectContentOnly) {
				signature.protected = protected_b64u;
			}
			signature.signature = signature_b64u;

			signatures.push(signature);
		}

		// if (flattened) {
		// 	this.joseInfo = {
		// 		payload: payload_b64u,
		// 		protected: signatures[0].protected
		// 	};
		// 	if ('header' in signatures[0]) this.joseInfo.header = signatures[0].header;
		// 	this.joseInfo.signature = signatures[0].signature;
		// } else {
		// 	this.joseInfo = {
		// 		payload: payload_b64u,
		// 		signatures: signatures
		// 	};
		// }


		switch (serialize) {
			case 'general':
/*
RFC 7515

A.6.  Example JWS Using General JWS JSON Serialization

   This section contains an example using the general JWS JSON
   Serialization syntax.  This example demonstrates the capability for
   conveying multiple digital signatures and/or MACs for the same
   payload.

   The JWS Payload used in this example is the same as that used in the
   examples in Appendix A.2 and Appendix A.3 (with line breaks for
   display purposes only):

     eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt
     cGxlLmNvbS9pc19yb290Ijp0cnVlfQ

   Two digital signatures are used in this example: the first using
   RSASSA-PKCS1-v1_5 SHA-256 and the second using ECDSA P-256 SHA-256.
   For the first, the JWS Protected Header and key are the same as in
   Appendix A.2, resulting in the same JWS Signature value; therefore,
   its computation is not repeated here.  For the second, the JWS
   Protected Header and key are the same as in Appendix A.3, resulting
   in the same JWS Signature value; therefore, its computation is not
   repeated here.

A.6.1.  JWS Per-Signature Protected Headers

   The JWS Protected Header value used for the first signature is:

     {"alg":"RS256"}

   Encoding this JWS Protected Header as BASE64URL(UTF8(JWS Protected
   Header)) gives this value:

     eyJhbGciOiJSUzI1NiJ9

   The JWS Protected Header value used for the second signature is:

     {"alg":"ES256"}

   Encoding this JWS Protected Header as BASE64URL(UTF8(JWS Protected
   Header)) gives this value:

     eyJhbGciOiJFUzI1NiJ9

A.6.2.  JWS Per-Signature Unprotected Headers

   Key ID values are supplied for both keys using per-signature Header
   Parameters.  The two JWS Unprotected Header values used to represent
   these key IDs are:

     {"kid":"2010-12-29"}

   and

     {"kid":"e9bc097a-ce51-4036-9562-d2ade882db0d"}

A.6.3.  Complete JOSE Header Values

   Combining the JWS Protected Header and JWS Unprotected Header values
   supplied, the JOSE Header values used for the first and second
   signatures, respectively, are:

     {"alg":"RS256",
      "kid":"2010-12-29"}

   and

     {"alg":"ES256",
      "kid":"e9bc097a-ce51-4036-9562-d2ade882db0d"}

A.6.4.  Complete JWS JSON Serialization Representation

   The complete JWS JSON Serialization for these values is as follows
   (with line breaks within values for display purposes only):

     {
      "payload":
       "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGF
        tcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
      "signatures":[
       {"protected":"eyJhbGciOiJSUzI1NiJ9",
        "header":
         {"kid":"2010-12-29"},
        "signature":
         "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZ
          mh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjb
          KBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHl
          b1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZES
          c6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AX
          LIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw"},
       {"protected":"eyJhbGciOiJFUzI1NiJ9",
        "header":
         {"kid":"e9bc097a-ce51-4036-9562-d2ade882db0d"},
        "signature":
         "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8IS
          lSApmWQxfKTUJqPP3-Kg6NU1Q"}]
     }

A.7.  Example JWS Using Flattened JWS JSON Serialization

   This section contains an example using the flattened JWS JSON
   Serialization syntax.  This example demonstrates the capability for
   conveying a single digital signature or MAC in a flattened JSON
   structure.

   The values in this example are the same as those in the second
   signature of the previous example in Appendix A.6.

   The complete JWS JSON Serialization for these values is as follows
   (with line breaks within values for display purposes only):

     {
      "payload":
       "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGF
        tcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
      "protected":"eyJhbGciOiJFUzI1NiJ9",
      "header":
       {"kid":"e9bc097a-ce51-4036-9562-d2ade882db0d"},
      "signature":
       "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8IS
        lSApmWQxfKTUJqPP3-Kg6NU1Q"
     }

*/
				var joseInfo = {};
	 			if (!detached) joseInfo.payload = payload_b64u;
				joseInfo.signatures = signatures;

				this.joseInfo = joseInfo;

				return joseInfo;

			case 'flattened':
				var joseInfo = {};
				if (!detached) joseInfo.payload = payload_b64u;
				if (!protectContentOnly) joseInfo.protected = signatures[0].protected;
				if ('header' in signatures[0]) joseInfo.header = signatures[0].header;
				joseInfo.signature = signatures[0].signature;

				this.joseInfo = joseInfo;

				return joseInfo;

			case 'compact':
			default:
/*
RFC 7519

3.  JSON Web Token (JWT) Overview

   JWTs represent a set of claims as a JSON object that is encoded in a
   JWS and/or JWE structure.  This JSON object is the JWT Claims Set.
   As per Section 4 of RFC 7159 [RFC7159], the JSON object consists of
   zero or more name/value pairs (or members), where the names are
   strings and the values are arbitrary JSON values.  These members are
   the claims represented by the JWT.  This JSON object MAY contain
   whitespace and/or line breaks before or after any JSON values or
   structural characters, in accordance with Section 2 of RFC 7159
   [RFC7159].

   The member names within the JWT Claims Set are referred to as Claim
   Names.  The corresponding values are referred to as Claim Values.

   The contents of the JOSE Header describe the cryptographic operations
   applied to the JWT Claims Set.  If the JOSE Header is for a JWS, the
   JWT is represented as a JWS and the claims are digitally signed or
   MACed, with the JWT Claims Set being the JWS Payload.  If the JOSE
   Header is for a JWE, the JWT is represented as a JWE and the claims
   are encrypted, with the JWT Claims Set being the plaintext encrypted
   by the JWE.  A JWT may be enclosed in another JWE or JWS structure to
   create a Nested JWT, enabling nested signing and encryption to be
   performed.

   A JWT is represented as a sequence of URL-safe parts separated by
   period ('.') characters.  Each part contains a base64url-encoded
   value.  The number of parts in the JWT is dependent upon the
   representation of the resulting JWS using the JWS Compact
   Serialization or JWE using the JWE Compact Serialization.

3.1.  Example JWT

   The following example JOSE Header declares that the encoded object is
   a JWT, and the JWT is a JWS that is MACed using the HMAC SHA-256
   algorithm:

     {"typ":"JWT",
      "alg":"HS256"}

   To remove potential ambiguities in the representation of the JSON
   object above, the octet sequence for the actual UTF-8 representation
   used in this example for the JOSE Header above is also included
   below.  (Note that ambiguities can arise due to differing platform
   representations of line breaks (CRLF versus LF), differing spacing at
   the beginning and ends of lines, whether the last line has a
   terminating line break or not, and other causes.  In the
   representation used in this example, the first line has no leading or
   trailing spaces, a CRLF line break (13, 10) occurs between the first
   and second lines, the second line has one leading space (32) and no
   trailing spaces, and the last line does not have a terminating line
   break.)  The octets representing the UTF-8 representation of the JOSE
   Header in this example (using JSON array notation) are:

   [123, 34, 116, 121, 112, 34, 58, 34, 74, 87, 84, 34, 44, 13, 10, 32,
   34, 97, 108, 103, 34, 58, 34, 72, 83, 50, 53, 54, 34, 125]

   Base64url encoding the octets of the UTF-8 representation of the JOSE
   Header yields this encoded JOSE Header value:

     eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9

   The following is an example of a JWT Claims Set:

     {"iss":"joe",
      "exp":1300819380,
      "http://example.com/is_root":true}

   The following octet sequence, which is the UTF-8 representation used
   in this example for the JWT Claims Set above, is the JWS Payload:

   [123, 34, 105, 115, 115, 34, 58, 34, 106, 111, 101, 34, 44, 13, 10,
   32, 34, 101, 120, 112, 34, 58, 49, 51, 48, 48, 56, 49, 57, 51, 56,
   48, 44, 13, 10, 32, 34, 104, 116, 116, 112, 58, 47, 47, 101, 120, 97,
   109, 112, 108, 101, 46, 99, 111, 109, 47, 105, 115, 95, 114, 111,
   111, 116, 34, 58, 116, 114, 117, 101, 125]

   Base64url encoding the JWS Payload yields this encoded JWS Payload
   (with line breaks for display purposes only):

     eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly
     9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ

   Computing the MAC of the encoded JOSE Header and encoded JWS Payload
   with the HMAC SHA-256 algorithm and base64url encoding the HMAC value
   in the manner specified in [JWS] yields this encoded JWS Signature:

     dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk

   Concatenating these encoded parts in this order with period ('.')
   characters between the parts yields this complete JWT (with line
   breaks for display purposes only):

     eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9
     .
     eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt
     cGxlLmNvbS9pc19yb290Ijp0cnVlfQ
     .
     dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk

   This computation is illustrated in more detail in Appendix A.1 of
   [JWS].  See Appendix A.1 for an example of an encrypted JWT.

*/
				// if (flattened) {
				// 	return this.joseInfo.protected + '.' + 
				// 		this.joseInfo.payload + '.' +
				// 		(this.joseInfo.signature.length ? this.joseInfo.signature : '');
				// } else {
				// 	return this.joseInfo.signatures[0].protected + '.' + 
				// 		this.joseInfo.payload + '.' +
				// 		(this.joseInfo.signatures[0].signature.length ? this.joseInfo.signatures[0].signature : '');
				// }
				return signatures[0].protected + '.' + (detached ? '' : payload_b64u) + '.' + signatures[0].signature;
		}
	}

	
/*

jCastle.jose.verify(jwt, algo_params)
-----------------------------------------
jCastle.jose.verify(
	jwt,
	{
		key: rsaPublicKey
	}
);

sign() can create more than one signatures, but verify only needs one algo_params.

*/
	/**
	 * verifies JWS token or object.
	 * 
	 * @public
	 * @param {mixed} jwt string or object to be verified.
	 * @param {object} params algorithm parameters object.
	 *                 {mixed} key key for verifing.
	 * @param {object} options options object
	 *                 {mixed} payload payload value. when jwt is signed with detachedPayload flag, payload value must be supplied.
	 * @returns true if the given key fits and verification of the signature is right.
	 */
	verify(jwt, params, options = {})
	{
		var algo_params, serialize;
		var payload = 'payload' in options ? options.payload : null;
		var detached = false;
		var payload_b64u;

		if (payload) {
			if(!Buffer.isBuffer(payload)) payload = Buffer.from(payload);
			payload_b64u = payload.toString('base64url');
			detached = true;
		}

		// if (Array.isArray(params)) {
		// 	algo_params = params;
		// } else {
		// 	algo_params = [params];
		// }
		algo_params = params;

		// console.log('jose.verify()');

		if (jCastle.util.isString(jwt)) {
			// compact serialization
			if (!/^([a-z0-9\.\-_]+)$/i.test(jwt)) throw jCastle.exception('NOT_JWT', 'JOS002');

			serialize = 'compact';
		} else {
			serialize = 'general';
		}

		var key = algo_params.publicKey || algo_params.key || algo_params.k || null;

		switch (serialize) {
			case 'flattened':
			case 'general':
/*
     {
      "payload":
       "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGF
        tcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
      "signatures":[
       {"protected":"eyJhbGciOiJSUzI1NiJ9",
        "header":
         {"kid":"2010-12-29"},
        "signature":
         "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZ
          mh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjb
          KBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHl
          b1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZES
          c6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AX
          LIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw"},
       {"protected":"eyJhbGciOiJFUzI1NiJ9",
        "header":
         {"kid":"e9bc097a-ce51-4036-9562-d2ade882db0d"},
        "signature":
         "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8IS
          lSApmWQxfKTUJqPP3-Kg6NU1Q"}]
     }

     {
      "payload":
       "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGF
        tcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
      "protected":"eyJhbGciOiJFUzI1NiJ9",
      "header":
       {"kid":"e9bc097a-ce51-4036-9562-d2ade882db0d"},
      "signature":
       "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8IS
        lSApmWQxfKTUJqPP3-Kg6NU1Q"
     }

*/
				var algo_info, protected_header;

				// algo_params count should be only one.
				// check key count
				// if ('signatures' in jwt && jwt.signatures.length != algo_params.length) {
				// 	//throw jCastle.exception('KEYS_COUNT_NOT_MATCH', 'JOS003');
				// 	console.log(jCastle.message('KEYS_COUNT_NOT_MATCH', 'JOS003'));
				// 	return false;
				// }

				var signatures, sig_item;

				if ('signature' in jwt) {
					signatures = [];
					sig_item = {};
					sig_item.header = jwt.header;
					if ('protected' in jwt) sig_item.protected = jwt.protected;
					sig_item.signature = jwt.signature;
					signatures.push(sig_item);
				} else {
					signatures = jwt.signatures;
				}

				for (var i = 0; i < signatures.length; i++) {

					if (!key && 'header' in signatures[i] && 'jwk' in signatures[i].header) {
						key = signatures[i].header.jwt;
					}

					var protectContentOnly = false;

					if ('protected' in signatures[i]) {
						protected_header = Buffer.from(signatures[i].protected, 'base64url').toString();
						protected_header = JSON.parse(protected_header);
						algo_info = jCastle.jose.fn.getSignAlgoInfo(protected_header.alg);
						if (!key && 'jwk' in protected_header) {
							key = protected_header.jwt;
						}
					} else {
						// if signatures[i] does not have 'protected' property,
						// then it means only contents protected. 
						// see protectContentOnly in options.
						var header = signatures[i].header;
						// console.log(header);
						algo_info = jCastle.jose.fn.getSignAlgoInfo(header.alg);
						protectContentOnly = true;
					}

					var protected_b64u = protectContentOnly ? '' : signatures[i].protected;

					if (jCastle.jose.fn.verifySignature(
						(protectContentOnly ? '' : protected_b64u) + '.' + (detached ? payload_b64u : jwt.payload), 
						signatures[i].signature, algo_info, key)) {
						return true;
					}
				}

				return false;

			case 'compact':
			default:
				// var key = algo_params.publicKey || algo_params.key || null;
				var jwt_arr = jwt.split('.');
				var header_b64u = jwt_arr[0];
				if (!detached) payload_b64u = jwt_arr[1];
				var signature_b64u = null;
				if (jwt_arr.length == 3) {
					signature_b64u = jwt_arr[2];
				}

				var jose_header = JSON.parse(Buffer.from(header_b64u, 'base64url').toString());

				// console.log('jose_header: ', jose_header);

				if (!key && 'jwk' in jose_header) {
						key = jose_header.jwt;
					}

				if (!('alg' in jose_header) || ('typ' in jose_header && jose_header.typ != 'JWT')) {
					//throw jCastle.exception('NOT_JWT', 'JOS004');
					// console.log(jCastle.getMessage('NOT_JWT', 'JOS004'));
					return false;
				}

				var algo_info = jCastle.jose.fn.getSignAlgoInfo(jose_header.alg);

				// console.log('algo_info: ', algo_info);

				if (algo_info.algoName != 'none' && !key) {
					//throw jCastle.exception('KEY_NOT_SET', 'JOS005');
					// console.log(jCastle.getMessage('KEY_NOT_SET', 'JOS005'));
					return false;
				}

				return jCastle.jose.fn.verifySignature(header_b64u + '.' + payload_b64u, signature_b64u, algo_info, key);

		}
	}

/*
jCastle.jose.validate(jwt, algo_params)
-------------------------------------------
jCastle.jose.validate(jwt, {
	key: key
})
*/
	/**
	 * validates jws token or object. it verifies the signature and checks the date.
	 * 
	 * @public
	 * @param {mixed} jwt string or object
	 * @param {object} algo_params algorithm parameters object.
	 * @returns true if all conditions are met.
	 */
	validate(jwt, algo_params)
	{
		if (!this.verify(jwt, algo_params)) return false;

		var info = this.parse(jwt);

		if (typeof info.payload == 'object') {
/*
https://stackoverflow.com/questions/33322407/unable-to-set-exp-and-iat-for-jwt-correctly

	new Date().getTime()

give you time in miliseconds. But time in jwt token (iat, exp) is in seconds, 
therefore we have to divide result by 1000.

	var actualTimeInSeconds = new Date().getTime()/1000;

How to get some time in seconds from now:

	(new Date().getTime() + someTimeInSeconds * 1000)/1000

If you need 1 hour from now:

	(new Date().getTime() + 60 * 60 * 1000)/1000

because 1h = 60min * 60 s
*/
			var date = new Date();
			var time = Math.floor(date.getTime() / 1000);

			if ('exp' in info.header && time >= info.header.exp) { // expires
				console.log('The expiration date has passed. ');
				return false;
			}

			if ('nbf' in info.header && time < info.header.nbf) { // not before
				console.log('The usage date has not yet come.');
				return false;
			}
		}

		return true;
	}

	/**
	 * parses jws token string and returns its information object.
	 * @param {string} jwt jws token string
	 * @returns the information object.
	 */
	parse(jwt)
	{
		if (jCastle.util.isString(jwt)) {
			var info = {};
			var jwt_arr = jwt.split('.');
			var jose_header = JSON.parse(Buffer.from(jwt_arr[0], 'base64url').toString());
			info.protected = {};
			info.protected.alg = jose_header.alg;

			var header_cnt = 0;
			var header = {};
			
			for (var p in jose_header) {
				if ('p' in jose_header && p != 'typ' && p != 'alg') {	
					header_cnt++;
					header[p] = jose_header[p];
				}
			}
			if (header_cnt) {
				info.header = header;
			}

			info.payload = jwt_arr[1];

			if (jwt_arr.length == 3) {
				info.signature = jwt_arr[2];
			}
		} else {
			if (!jwt || typeof jwt != 'object') throw jCastle.exception('INVALID_PARAMS', 'JOS008');

			var info = jCastle.util.clone(jwt);
			
			if ('signatures' in info) {
				for (var i = 0; i < info.signatures.length; i++) {
					info.signatures[i].protected = JSON.parse(Buffer.from(info.signatures[i].protected, 'base64url').toString());
					// if ('header' in info.signatures[i]) {
					// 	info.signatures[i].header = JSON.parse(info.signatures[i].header);
					// }
				}
			} else {
				info.protected = JSON.parse(Buffer.from(info.protected, 'base64url').toString());
				// if ('header' in info) {
				// 	info.header = JSON.parse(info.header);
				// }
			}
		}

		info.payload = Buffer.from(info.payload, 'base64url').toString();

		try {
			info.payload = JSON.parse(info.payload);
		} catch (e) {
			// nothing to do
			// console.log(e);
		}

		return info;
	}



/*
 * A Javascript implementation of JWE - JSON Web Encryption
 * --------------------------------------------------------
 */

/*
// plaintext is encrypted by cek with enc_algo_params. enc_algo_params can have cek.
// cek (content encryption key) is encrypted by keywrap_algo_params.
jCastle.jose.encrypt(plaintext, keywrap_algo_params, enc_algo_params, options)
------------------------------------------------------------------------------
jCastle.jose.encrypt(
	plaintext,
	{
		algoName: 'RSA1_5',
		keyID: '2011-04-29',
		key: rsa_publicKey
	},
	{
		algoName: 'AES256GCM',
	},
	{
		serialize: 'general'
	}
);

jCastle.jose.encrypt(
	plaintext,
	[ // keywrap_algo_params. arrays of objects of keywrap or an object of keywrap.
		{ // if key_encyption parameter is not an array then the serialization will be flattened.
			algoName: 'RSA1_5',
			keyID: '2011-04-29',
			key: rsa_public_key,
		},{
			algoName: 'PBES2-HS256+A128KW',
			keyID: '3045-2543-2884',
			password: password,
			salt: salt,
			count: 1000
		}, {
			algoName: 'A128GCMKW',
			keyID: '7',
			key: key,
			iv: initial_vector // 96 bits = 12 bytes
		}, {
			algoName: 'ECDH-ES+A128KW',
			partyPublicKey: party_public_key,
			key: issuer_temporal_key,
			apu: apu,
			apv: apv
		}, {
			algoName: 'DIR',
			cek: content_encrypt_key
		}
	],
	{ // encryption algorithm params
		algoName: 'AES256GCM',
		key: cek,	// if it does not exist then it will be created.
		iv: iv,		// if it does not exist then it will be created.

		// custom authenticated additional data
		// aad should be base64url string
		aad: aad_b64u
	},
	{
		unprotected: {"jku":"https://server.example.com/keys.jwks"}, // this one is shared unprotected header
		serialize: 'general',

		// protecting JWE header
		// this option only works when keywrap_algo_params counter or length is 1.
		//
		// this is for NIST RFC 7520 cookbook example.
		// the general JWE in RFC 7520 has a different structure from RFC 7516.
		// when this option is true then JOSE header is protected.
		protectHeader: true
	}
);

Differences between RFC 7520 and RFC 7516.
To me RFC 7520 structures are invalid. Just think about when there are recipients more than one.

RFC 7516 example of general JWE:
https://datatracker.ietf.org/doc/html/rfc7516#appendix-A.4.7

{
	"protected": "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
	"unprotected": {"jku":"https://server.example.com/keys.jwks"},
	"recipients":[
		{
			"header": {"alg":"RSA1_5","kid":"2011-04-29"},
			"encrypted_key":
				"UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-
				kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKx
				GHZ7PcHALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3
				YvkkysZIFNPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPh
				cCdZ6XDP0_F8rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPg
				wCp6X-nZZd9OHBv-B3oWh2TbqmScqXMR4gp_A"
		},
		{
			"header": {"alg":"A128KW","kid":"7"},
			"encrypted_key":
				"6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ"
		}
	],
	"iv": "AxY8DCtDaGlsbGljb3RoZQ",
	"ciphertext": "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
	"tag": "Mz-VPPyU4RlcuYv1IwIvzw"
}

RFC 7520 example:
https://datatracker.ietf.org/doc/html/rfc7520#section-5.1.5

// when JWE header protected:
{
	"recipients": [
		{
			"encrypted_key": 
				"laLxI0j-nLH-_BgLOXMozKxmy9gffy2gTdvqzf
				TihJBuuzxg0V7yk1WClnQePFvG2K-pvSlWc9BRIazDrn50RcRai_
				_3TDON395H3c62tIouJJ4XaRvYHFjZTZ2GXfz8YAImcc91Tfk0WX
				C2F5Xbb71ClQ1DDH151tlpH77f2ff7xiSxh9oSewYrcGTSLUeeCt
				36r1Kt3OSj7EyBQXoZlN7IxbyhMAfgIe7Mv1rOTOI5I8NQqeXXW8
				VlzNmoxaGMny3YnGir5Wf6Qt2nBq4qDaPdnaAuuGUGEecelIO1wx
				1BpyIfgvfjOhMBs9M8XL223Fg47xlGsMXdfuY-4jaqVw"
       }
	],
	"protected": 
		"eyJhbGciOiJSU0ExXzUiLCJraWQiOiJmcm9kby5iYWdnaW
		5zQGhvYmJpdG9uLmV4YW1wbGUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In
		0",
	"iv": "bbd5sTkYwhAIqfHsx8DayA",
	"ciphertext": 
		"0fys_TY_na7f8dwSfXLiYdHaA2DxUjD67ieF7fcVbIR62
		JhJvGZ4_FNVSiGc_raa0HnLQ6s1P2sv3Xzl1p1l_o5wR_RsSzrS8Z-wn
		I3Jvo0mkpEEnlDmZvDu_k8OWzJv7eZVEqiWKdyVzFhPpiyQU28GLOpRc
		2VbVbK4dQKPdNTjPPEmRqcaGeTWZVyeSUvf5k59yJZxRuSvWFf6KrNtm
		RdZ8R4mDOjHSrM_s8uwIFcqt4r5GX8TKaI0zT5CbL5Qlw3sRc7u_hg0y
		KVOiRytEAEs3vZkcfLkP6nbXdC_PkMdNS-ohP78T2O6_7uInMGhFeX4c
		tHG7VelHGiT93JfWDEQi5_V9UN1rhXNrYu-0fVMkZAKX3VWi7lzA6BP4
		30m",
	"tag": "kvKuFBXHe5mQr4lqgobAUg"
}

// When JWE header is not protected:
{
	"recipients": [
	{
		"encrypted_key": "jJIcM9J-hbx3wnqhf5FlkEYos0sHsF0H"
	}
	],
	"unprotected": {
		"alg": "A128KW",
		"kid": "81b20965-8332-43d9-a468-82160ad91ac8"
	},
	"protected": "eyJlbmMiOiJBMTI4R0NNIn0",
	"iv": "WgEJsDS9bkoXQ3nR",
	"ciphertext": "lIbCyRmRJxnB2yLQOTqjCDKV3H30ossOw3uD9DPsqLL2D
         M3swKkjOwQyZtWsFLYMj5YeLht_StAn21tHmQJuuNt64T8D4t6C7kC9O
         CCJ1IHAolUv4MyOt80MoPb8fZYbNKqplzYJgIL58g8N2v46OgyG637d6
         uuKPwhAnTGm_zWhqc_srOvgiLkzyFXPq1hBAURbc3-8BqeRb48iR1-_5
         g5UjWVD3lgiLCN_P7AW8mIiFvUNXBPJK3nOWL4teUPS8yHLbWeL83olU
         4UAgL48x-8dDkH23JykibVSQju-f7e-1xreHWXzWLHs1NqBbre0dEwK3
         HX_xM0LjUz77Krppgegoutpf5qaKg3l-_xMINmf",
	"tag": "fNYLqpUe84KD45lvDiaBAQ"
}

// when content only protected:
{
	"recipients": [
	{
		"encrypted_key": "244YHfO_W7RMpQW81UjQrZcq5LSyqiPv"
	}
	],
	"unprotected": {
		"alg": "A128KW",
		"kid": "81b20965-8332-43d9-a468-82160ad91ac8",
		"enc": "A128GCM"
	},
	"iv": "YihBoVOGsR1l7jCD",
	"ciphertext": "qtPIMMaOBRgASL10dNQhOa7Gqrk7Eal1vwht7R4TT1uq-
         arsVCPaIeFwQfzrSS6oEUWbBtxEasE0vC6r7sphyVziMCVJEuRJyoAHF
         SP3eqQPb4Ic1SDSqyXjw_L3svybhHYUGyQuTmUQEDjgjJfBOifwHIsDs
         RPeBz1NomqeifVPq5GTCWFo5k_MNIQURR2Wj0AHC2k7JZfu2iWjUHLF8
         ExFZLZ4nlmsvJu_mvifMYiikfNfsZAudISOa6O73yPZtL04k_1FI7WDf
         rb2w7OqKLWDXzlpcxohPVOLQwpA3mFNRKdY-bQz4Z4KX9lfz1cne31N4
         -8BKmojpw-OdQjKdLOGkC445Fb_K1tlDQXw2sBF",
	"tag": "e2m0Vm7JvjK2VpCKXS-kyg"
}
*/
	/**
	 * encrypts a message.
	 * 
	 * @public
	 * @param {buffer} message message to be encrypted.
	 * @param {mixed} algo_params key encryption algorithm parameters object or array. 
	 *                array when recipients are more than one, object when there is only one recipient.
	 *                {string} algoName key encryption algorithm name. ex) RSA1_5.
	 *                {mixed} key key string or object for algorithm.
	 *                {string} keyID key id value. if key object has kid or keyID then it is used for it.
	 *                {buffer} password password value, when algoName is password-based-algorithm.
	 *                {number} count count number, when algoName is password-based-algorithm.
	 *                {mixed} salt salt buffer or base64url string, when algoName is password-based-algorithm.
	 *                {mixed} iv initial vector buffer or base64url string, when algoName is crypto algorithm.
	 *                {mixed} partyPublicKey other party's publicKey, when algoName is ECDH-ES or relevant to it.
	 *                {buffer} apu apu value, when algoName is ECDH-ES or relevant to it.
	 *                {buffer} apv apv value, when algoName is ECDH-ES or relevant to it.
	 * @param {object} enc_algo_params content encryption algorithm parameters object.
	 *                 {string} algoName algorithm name. ex) 'AES256GCM'
	 *                 {mixed} key key buffer or jwk object.
	 *                 {mixed} iv initial vector buffer or base64url string.
	 *                 {mixed} aad Authenticated additional data buffer or string.
	 * @param {object} options options object.
	 *                 {string} serialize serialization option. 'general' | 'flattened' | 'compact'. (default: 'compact')
	 *                 {boolean} protectHeader flag for protecting header. it works only when there is only one recipient.
	 * @returns jwe token string or object.
	 */
	encrypt(message, algo_params, enc_algo_params, options = {})
	{
		var prng = new jCastle.prng();
		var serialize = 'serialize' in options ? options.serialize.toLowerCase() : 'compact';
		var protect_header = 'protectHeader' in options ? options.protectHeader : false;
		var keywrap_algo_params;

		// console.log('jose.encrypt()');

		if (!enc_algo_params) enc_algo_params = 'AES256GCM';

		if (Array.isArray(algo_params)) {
			keywrap_algo_params = algo_params;
		} else {
			keywrap_algo_params = [algo_params];
		}

		// get encryption algorithm
		if (jCastle.util.isString(enc_algo_params)) {
			enc_algo_params = {
				algoName: enc_algo_params
			};
		}
		var enc_algo = enc_algo_params.algoName || enc_algo_params.alg;
		var enc_algo_info = jCastle.jose.fn.getEncAlgoInfo(enc_algo);

		// console.log('enc_algo_info: ', enc_algo_info);

		// protect header option
		// if keywrap_algo_params length is more than one
		// then protect_header should be false.
		// when serialize is 'compact' protect_header is true always.
		// if true, then the recipient's header will be protected, 
		// and the value will be the same as compact_header.
		if (serialize == 'compact') protect_header = true;
		if (serialize != 'compact' && keywrap_algo_params.length > 1) protect_header = false;

		// if keywrap_algo_params[i].algoName is 'ECDH-ES' without key wrapping mode,
		// then the result key agreement with KDF.singlestepKDF should be content encryption key(CEK)!
		// otherwise CEK should be generated.

		// check whether there is ECDH-ES or not.
		var ecdh_direct_key = false;
		var direct_key = false;
		var ecdh_iter = 0;
		var dir_iter = 0;

		for (var i = 0; i < keywrap_algo_params.length; i++) {
			var algo = keywrap_algo_params[i].algoName || keywrap_algo_params[i].alg;
			if (algo.toUpperCase() == 'ECDH-ES') {
				ecdh_direct_key = true;
				ecdh_iter = i;
				break;
			}
		}

		for (var i = 0; i < keywrap_algo_params.length; i++) {
			var algo = keywrap_algo_params[i].algoName || keywrap_algo_params[i].alg;
			if (algo.toUpperCase() == 'DIR') {
				direct_key = true;
				dir_iter = i;
				break;
			}
		}

		if (direct_key && ecdh_direct_key) {
			throw jCastle.exception('DIR_AND_ECDHES_COEXIST', 'JOS009');
		}

		var cek_length = enc_algo_info.keySize + ('macKeySize' in enc_algo_info ? enc_algo_info.macKeySize : 0);

		var cek;

		if (ecdh_direct_key) {
			// CEK is the result of key agreement with KDF.singlestepKDF.
			// CEK will be generated using the first ECDH-ES parameters.

			// The key agreement result will be used directly as
			// the Content Encryption Key (CEK) for the "enc" 
			// algorithm, in the Direct Key Agreement mode.

			var algo = keywrap_algo_params[ecdh_iter].algoName || keywrap_algo_params[ecdh_iter].alg;
			var algo_info = jCastle.jose.fn.getKeyAlgoInfo(algo);

			var other_pubkey = keywrap_algo_params[ecdh_iter].partyPublicKey; // other party's ephememal public key.
			var privkey = keywrap_algo_params[ecdh_iter].privateKey || keywrap_algo_params[ecdh_iter].key || keywrap_algo_params[ecdh_iter].k; // private key
			var apu = keywrap_algo_params[ecdh_iter].partyUInfo || keywrap_algo_params[ecdh_iter].apu || null;
			var apv = keywrap_algo_params[ecdh_iter].partyVInfo || keywrap_algo_params[ecdh_iter].apv || null;

			if (apu) apu = Buffer.from(apu);
			if (apv) apv = Buffer.from(apv);

			cek = jCastle.jose.fn.deriveKeyUsingECDHAndSinglestepKDF(other_pubkey, privkey, apu, apv, enc_algo, cek_length);
		} else {
			if (direct_key) {
				// when algo is DIR then content-encrypt-key should be provided.
				cek = keywrap_algo_params[dir_iter].contentEncryptKey || keywrap_algo_params[dir_iter].cek || keywrap_algo_params[dir_iter].key || null;
				if (!cek) throw jCastle.exception('KEY_NOT_SET', 'JOS010');
			} else {
				// cek = 'key' in enc_algo_params ? Buffer.from(enc_algo_params.key, 'latin1') : null;
				cek = enc_algo_params.key || enc_algo_params.k || null;

				if (!cek) {
					cek = prng.nextBytes(cek_length);
				}
			}

			if (typeof cek == 'object' && 'kty' in cek && cek.kty == 'oct') {
				var jwk = cek;
				cek = Buffer.from(cek.k, 'base64url');
			}

			if (cek && !Buffer.isBuffer(cek)) cek = Buffer.from(cek, 'latin1');

			// key check
			if (cek.length != cek_length) throw jCastle.exception('INVALID_KEYSIZE', 'JOS011');
		}

		var enc_mac_key, enc_key;
		
		if ('macKeySize' in enc_algo_info) {
			enc_mac_key = cek.slice(0, enc_algo_info.macKeySize);
			enc_key = cek.slice(enc_algo_info.macKeySize);
		} else {
			enc_key = cek;
		}

		var recipients = [];


		// first, encrypt cek with key algorithm
/*
		var header_params = {
			'kid': 'kid',
			'keyID': 'kid',
			'zip': 'zip',
			'jku': 'jku',
			'jsonKeyURL': 'jku',
			'jwk': 'jwk',
			'jsonWebKey': 'jwk',
			'x5u': 'x5u',
			'certificateURL': 'x5u',
			'x509CertificateURL': 'x5u',
			'x5c': 'x5c',
			'certificateChain': 'x5c',
			'x509CertificateChain': 'x5c',
			'x5t': 'x5t',
			'certificateSHA1Thumbprint': 'x5t',
			'x509CertificateSHA1Thumbprint': 'x5t',
			'x5t#S256': 'x5t#S256',
			'certificateSHA256Thumbprint': 'x5t#S256',
			'x509CertificateSHA256Thumbprint': 'x5t#S256',
			'cty': 'cty',
			'contentType': 'cty',
			'crit': 'crit',
			'critical': 'crit'
		};
*/
		var header_key_params = ['tag', 'iv', 'epk', 'apu', 'apv', 'p2s', 'p2c'];
		var compact_header = '';

		for (var i = 0; i < keywrap_algo_params.length; i++) {
			var algo = keywrap_algo_params[i].algoName || keywrap_algo_params[i].alg;
			var algo_info = jCastle.jose.fn.getKeyAlgoInfo(algo);
			// console.log('algo_info: ', algo_info);
			var encrypted_key_info = jCastle.jose.fn.encryptContentEncKey(
				//'macKeySize' in enc_algo_info ? cek : enc_key,
				cek,
				keywrap_algo_params[i], 
				algo_info, 
				enc_algo,
				enc_algo_info,
				prng);
			var recipient = {};

			// protecting JWE header option.
			// var protect_header = false;
			// if ('protectHeader' in keywrap_algo_params[i] && keywrap_algo_params[i].protectHeader) protect_header = true;

			// console.log('encrypted_key_info: ', encrypted_key_info);

			var header;

			if ('header' in keywrap_algo_params[i]) {
				recipient.header = jCastle.util.isString(keywrap_algo_params[i].header) ? keywrap_algo_params[i].header : JSON.stringify(keywrap_algo_params[i].header);
			} else {
				header = {};
				header.alg = algo;

				var type = keywrap_algo_params[i].type || keywrap_algo_params[i].typ || null;
				if (type) header.typ = type;

				// keyID should come first
				// keyID can be in key object
				if ('kid' in keywrap_algo_params[i] || 'keyID' in keywrap_algo_params[i]) {
					header['kid'] = keywrap_algo_params[i].kid || keywrap_algo_params[i].keyID;
				} else if ('key' in keywrap_algo_params[i] && 'kid' in keywrap_algo_params[i].key) {
					header['kid'] = keywrap_algo_params[i].key.kid;
				}

				// A128GCMKW has iv and tag
				// ECDH has epk, apu, apv
				// PBES2 has p2s, p2c
				// tag comes before iv...
				// for (var p in encrypted_key_info) {
				// 	if (header_key_params.includes(p)) {
				// 		header[p] = encrypted_key_info[p];
				// 	}
				// }
				for (var p of header_key_params) {
					if (p in encrypted_key_info) header[p] = encrypted_key_info[p];
				}

				// kid, jku, jwk, x5u, x5c, cty
				for (var p in jCastle.jose.headerParameters) {
					if (p in keywrap_algo_params[i] && !(jCastle.jose.headerParameters[p] in header)) {
						header[jCastle.jose.headerParameters[p]] = keywrap_algo_params[i][p];
					}
				}

				// critical header parameter
				if ('crit' in header) {
					var critical = keywrap_algo_params[i].critical || keywrap_algo_params[i].crit;
					for (var c = 0; c < critical.length; c++) {
						if (critical[c] in keywrap_algo_params[i] && !(critical[c] in header)) {
							header[critical[c]] = keywrap_algo_params[i][critical[c]];
						}
					}
				}

				//if (!protect_header && serialize != 'compact' && 'zip' in keywrap_algo_params[i])
				if (!protect_header && 'zip' in keywrap_algo_params[i])
					header.zip = keywrap_algo_params[i].zip;

				if (!protect_header) {
					recipient.header = header;
				}
			}

			if (encrypted_key_info.encrypted_key) {
				// encrypted_key can be null when algo is ECDH-ES
				recipient.encrypted_key = encrypted_key_info.encrypted_key;
			}

			recipients.push(recipient);

			//if ((i == 0 && serialize == 'compact') || protect_header) {
			if (i == 0 && protect_header) {
				compact_header = header;
				compact_header.enc = enc_algo;
				if ('zip' in keywrap_algo_params[i]) compact_header.zip = keywrap_algo_params[i].zip;
				compact_header = JSON.stringify(compact_header);

				// console.log('compact_header: ', compact_header);

				compact_header = Buffer.from(compact_header).toString('base64url');
			}
		}

		// second, encrypt message with cek

		var iv = enc_algo_params.iv || enc_algo_params.initialVector || null;
		if (jCastle.util.isString(iv)) {
			if (/^[0-9A-F]+$/i.test(iv)) iv = Buffer.from(iv, 'hex');
			else iv = Buffer.from(iv, 'latin1');
		} else if (iv) iv = Buffer.from(iv);

		var protected_header = 'protected' in enc_algo_params ? enc_algo_params.protected : null;

		if (!protected_header && !protect_header) {
			protected_header = '{"enc":"' + enc_algo + '"}';

			// console.log('protected_header: ', protected_header);

			protected_header = Buffer.from(protected_header).toString('base64url');
		}

		if (protect_header) protected_header = compact_header;

		var aad = enc_algo_params.additionalData || enc_algo_params.aad || null;
		var aad_included = aad ? true : false;

		// if (aad_included) console.log('aad_included');

		// if (aad_included && serialize == 'compact')
		// 	throw jCastle.exception('COMPACT_AAD_NOT_ALLOWED', 'JOS050');
		if (serialize == 'comapct') aad_included = false;

		if (!aad_included || serialize == 'compact') {
			aad = (serialize == 'compact') ? compact_header : protected_header;
		}

		// console.log('aad: ', aad);
		// console.log('aad length: ', aad.length);

		var cipher = new jCastle.mcrypt(enc_algo_info.algoName);

		if (!iv) {
			iv = prng.nextBytes(cipher.getIVSize(enc_algo_info.mode));
		}

//		if (iv.length != cipher.getIVSize(enc_algo_info.mode)) {
//			throw jCastle.exception('INVALID_IV', 'JOS012');
//		}

		var params = {
			isEncryption: true,
			padding: 'pkcs7',
			mode: enc_algo_info.mode,
			iv: iv,
			key: enc_key
		};

		// var nonce_mode = ['eax', 'ccm', 'gcm', 'cwc', 'poly1305-aead'];

		//if (nonce_mode.includes(enc_algo_info.mode.toLowerCase())) {
		if (!('macHashAlgo' in enc_algo_info)) {
			params.additionalData = aad_included ? (protected_header + '.' + aad) : aad;
			params.nonce = iv;
			params.tagSize = 16;
		}
		// console.log('params: ', params);

		cipher.start(params);
		cipher.update(message);
		var ct = cipher.finalize();

		var tag;

		//if (nonce_mode.includes(enc_algo_info.mode.toLowerCase())) {
		if (!('macHashAlgo' in enc_algo_info)) {
			tag = ct.slice(ct.length - enc_algo_info.tagSize);
			ct = ct.slice(0, ct.length - enc_algo_info.tagSize);
		} else {
			if (enc_algo_info.mac == 'HMac') {
/*
RFC 7516

Appendix B.  Example AES_128_CBC_HMAC_SHA_256 Computation

   This example shows the steps in the AES_128_CBC_HMAC_SHA_256
   authenticated encryption computation using the values from the
   example in Appendix A.3.  As described where this algorithm is
   defined in Sections 5.2 and 5.2.3 of JWA, the AES_CBC_HMAC_SHA2
   family of algorithms are implemented using Advanced Encryption
   Standard (AES) in Cipher Block Chaining (CBC) mode with Public-Key
   Cryptography Standards (PKCS) #7 padding to perform the encryption
   and an HMAC SHA-2 function to perform the integrity calculation -- in
   this case, HMAC SHA-256.

B.1.  Extract MAC_KEY and ENC_KEY from Key

   The 256 bit AES_128_CBC_HMAC_SHA_256 key K used in this example
   (using JSON array notation) is:

   [4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106,
   206, 107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156,
   44, 207]

   Use the first 128 bits of this key as the HMAC SHA-256 key MAC_KEY,
   which is:

   [4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106,
   206]

   Use the last 128 bits of this key as the AES-CBC key ENC_KEY, which
   is:

   [107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156, 44,
   207]

   Note that the MAC key comes before the encryption key in the input
   key K; this is in the opposite order of the algorithm names in the
   identifiers "AES_128_CBC_HMAC_SHA_256" and "A128CBC-HS256".

B.2.  Encrypt Plaintext to Create Ciphertext

   Encrypt the plaintext with AES in CBC mode using PKCS #7 padding
   using the ENC_KEY above.  The plaintext in this example is:

   [76, 105, 118, 101, 32, 108, 111, 110, 103, 32, 97, 110, 100, 32,
   112, 114, 111, 115, 112, 101, 114, 46]

   The encryption result is as follows, which is the ciphertext output:

   [40, 57, 83, 181, 119, 33, 133, 148, 198, 185, 243, 24, 152, 230, 6,
   75, 129, 223, 127, 19, 210, 82, 183, 230, 168, 33, 215, 104, 143,
   112, 56, 102]

B.3.  64-Bit Big-Endian Representation of AAD Length

   The Additional Authenticated Data (AAD) in this example is:

   [101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 66, 77, 84, 73, 52,
   83, 49, 99, 105, 76, 67, 74, 108, 98, 109, 77, 105, 79, 105, 74, 66,
   77, 84, 73, 52, 81, 48, 74, 68, 76, 85, 104, 84, 77, 106, 85, 50, 73,
   110, 48]

   This AAD is 51-bytes long, which is 408-bits long.  The octet string
   AL, which is the number of bits in AAD expressed as a big-endian
   64-bit unsigned integer is:

   [0, 0, 0, 0, 0, 0, 1, 152]

B.4.  Initialization Vector Value

   The Initialization Vector value used in this example is:

   [3, 22, 60, 12, 43, 67, 104, 105, 108, 108, 105, 99, 111, 116, 104,
   101]

B.5.  Create Input to HMAC Computation

   Concatenate the AAD, the Initialization Vector, the ciphertext, and
   the AL value.  The result of this concatenation is:

   [101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 66, 77, 84, 73, 52,
   83, 49, 99, 105, 76, 67, 74, 108, 98, 109, 77, 105, 79, 105, 74, 66,
   77, 84, 73, 52, 81, 48, 74, 68, 76, 85, 104, 84, 77, 106, 85, 50, 73,
   110, 48, 3, 22, 60, 12, 43, 67, 104, 105, 108, 108, 105, 99, 111,
   116, 104, 101, 40, 57, 83, 181, 119, 33, 133, 148, 198, 185, 243, 24,
   152, 230, 6, 75, 129, 223, 127, 19, 210, 82, 183, 230, 168, 33, 215,
   104, 143, 112, 56, 102, 0, 0, 0, 0, 0, 0, 1, 152]

B.6.  Compute HMAC Value

   Compute the HMAC SHA-256 of the concatenated value above.  This
   result M is:

   [83, 73, 191, 98, 104, 205, 211, 128, 201, 189, 199, 133, 32, 38,
   194, 85, 9, 84, 229, 201, 219, 135, 44, 252, 145, 102, 179, 140, 105,
   86, 229, 116]

B.7.  Truncate HMAC Value to Create Authentication Tag

   Use the first half (128 bits) of the HMAC output M as the
   Authentication Tag output T.  This truncated value is:

   [83, 73, 191, 98, 104, 205, 211, 128, 201, 189, 199, 133, 32, 38,
   194, 85]

*/
				var hmac = new jCastle.hmac();
				hmac.start({
					algoName: enc_algo_info.macHashAlgo,
					key: enc_mac_key
				});

				hmac.update(aad_included ? (protected_header + '.' + aad) : aad).update(iv).update(ct);

				// AL - 64bit length of aad_b64u
				var AL = Buffer.alloc(8);
				var aad_len = aad_included ? (protected_header.length + aad.length + 1) : aad.length;
				AL.writeInt32BE(aad_len * 8, 4);

				tag = hmac.update(AL).finalize();

				tag = tag.slice(0, enc_algo_info.tagSize);
			} else {
				throw jCastle.exception('UNKNOWN_ALGORITHM', 'JOS013');
			}
		}

		this.joseInfo = {};

		switch (serialize) {
			case 'general':
/*
RFC 7516

7.2.  JWE JSON Serialization

   The JWE JSON Serialization represents encrypted content as a JSON
   object.  This representation is neither optimized for compactness nor
   URL safe.

   Two closely related syntaxes are defined for the JWE JSON
   Serialization: a fully general syntax, with which content can be
   encrypted to more than one recipient, and a flattened syntax, which
   is optimized for the single-recipient case.

7.2.1.  General JWE JSON Serialization Syntax

   The following members are defined for use in top-level JSON objects
   used for the fully general JWE JSON Serialization syntax:

   protected
      The "protected" member MUST be present and contain the value
      BASE64URL(UTF8(JWE Protected Header)) when the JWE Protected
      Header value is non-empty; otherwise, it MUST be absent.  These
      Header Parameter values are integrity protected.

   unprotected
      The "unprotected" member MUST be present and contain the value JWE
      Shared Unprotected Header when the JWE Shared Unprotected Header
      value is non-empty; otherwise, it MUST be absent.  This value is
      represented as an unencoded JSON object, rather than as a string.
      These Header Parameter values are not integrity protected.

   iv
      The "iv" member MUST be present and contain the value
      BASE64URL(JWE Initialization Vector) when the JWE Initialization
      Vector value is non-empty; otherwise, it MUST be absent.

   aad
      The "aad" member MUST be present and contain the value
      BASE64URL(JWE AAD)) when the JWE AAD value is non-empty;
      otherwise, it MUST be absent.  A JWE AAD value can be included to
      supply a base64url-encoded value to be integrity protected but not
      encrypted.

   ciphertext
      The "ciphertext" member MUST be present and contain the value
      BASE64URL(JWE Ciphertext).

   tag
      The "tag" member MUST be present and contain the value
      BASE64URL(JWE Authentication Tag) when the JWE Authentication Tag
      value is non-empty; otherwise, it MUST be absent.

   recipients
      The "recipients" member value MUST be an array of JSON objects.
      Each object contains information specific to a single recipient.
      This member MUST be present with exactly one array element per
      recipient, even if some or all of the array element values are the
      empty JSON object "{}" (which can happen when all Header Parameter
      values are shared between all recipients and when no encrypted key
      is used, such as when doing Direct Encryption).

   The following members are defined for use in the JSON objects that
   are elements of the "recipients" array:

   header
      The "header" member MUST be present and contain the value JWE Per-
      Recipient Unprotected Header when the JWE Per-Recipient
      Unprotected Header value is non-empty; otherwise, it MUST be
      absent.  This value is represented as an unencoded JSON object,
      rather than as a string.  These Header Parameter values are not
      integrity protected.

   encrypted_key
      The "encrypted_key" member MUST be present and contain the value
      BASE64URL(JWE Encrypted Key) when the JWE Encrypted Key value is
      non-empty; otherwise, it MUST be absent.

   At least one of the "header", "protected", and "unprotected" members
   MUST be present so that "alg" and "enc" Header Parameter values are
   conveyed for each recipient computation.

   Additional members can be present in both the JSON objects defined
   above; if not understood by implementations encountering them, they
   MUST be ignored.

   Some Header Parameters, including the "alg" parameter, can be shared
   among all recipient computations.  Header Parameters in the JWE
   Protected Header and JWE Shared Unprotected Header values are shared
   among all recipients.

   The Header Parameter values used when creating or validating per-
   recipient ciphertext and Authentication Tag values are the union of
   the three sets of Header Parameter values that may be present: (1)
   the JWE Protected Header represented in the "protected" member, (2)
   the JWE Shared Unprotected Header represented in the "unprotected"
   member, and (3) the JWE Per-Recipient Unprotected Header represented
   in the "header" member of the recipient's array element.  The union
   of these sets of Header Parameters comprises the JOSE Header.  The
   Header Parameter names in the three locations MUST be disjoint.

   Each JWE Encrypted Key value is computed using the parameters of the
   corresponding JOSE Header value in the same manner as for the JWE
   Compact Serialization.  This has the desirable property that each JWE
   Encrypted Key value in the "recipients" array is identical to the
   value that would have been computed for the same parameter in the JWE
   Compact Serialization.  Likewise, the JWE Ciphertext and JWE
   Authentication Tag values match those produced for the JWE Compact
   Serialization, provided that the JWE Protected Header value (which
   represents the integrity-protected Header Parameter values) matches
   that used in the JWE Compact Serialization.

   All recipients use the same JWE Protected Header, JWE Initialization
   Vector, JWE Ciphertext, and JWE Authentication Tag values, when
   present, resulting in potentially significant space savings if the
   message is large.  Therefore, all Header Parameters that specify the
   treatment of the plaintext value MUST be the same for all recipients.
   This primarily means that the "enc" (encryption algorithm) Header
   Parameter value in the JOSE Header for each recipient and any
   parameters of that algorithm MUST be the same.

   In summary, the syntax of a JWE using the general JWE JSON
   Serialization is as follows:

     {
      "protected":"<integrity-protected shared header contents>",
      "unprotected":<non-integrity-protected shared header contents>,
      "recipients":[
       {"header":<per-recipient unprotected header 1 contents>,
        "encrypted_key":"<encrypted key 1 contents>"},
       ...
       {"header":<per-recipient unprotected header N contents>,
        "encrypted_key":"<encrypted key N contents>"}],
      "aad":"<additional authenticated data contents>",
      "iv":"<initialization vector contents>",
      "ciphertext":"<ciphertext contents>",
      "tag":"<authentication tag contents>"
     }

   See Appendix A.4 for an example JWE using the general JWE JSON
   Serialization syntax.

7.2.2.  Flattened JWE JSON Serialization Syntax

   The flattened JWE JSON Serialization syntax is based upon the general
   syntax, but flattens it, optimizing it for the single-recipient case.
   It flattens it by removing the "recipients" member and instead
   placing those members defined for use in the "recipients" array (the
   "header" and "encrypted_key" members) in the top-level JSON object
   (at the same level as the "ciphertext" member).

   The "recipients" member MUST NOT be present when using this syntax.
   Other than this syntax difference, JWE JSON Serialization objects
   using the flattened syntax are processed identically to those using
   the general syntax.

   In summary, the syntax of a JWE using the flattened JWE JSON
   Serialization is as follows:

     {
      "protected":"<integrity-protected header contents>",
      "unprotected":<non-integrity-protected header contents>,
      "header":<more non-integrity-protected header contents>,
      "encrypted_key":"<encrypted key contents>",
      "aad":"<additional authenticated data contents>",
      "iv":"<initialization vector contents>",
      "ciphertext":"<ciphertext contents>",
      "tag":"<authentication tag contents>"
     }

   Note that when using the flattened syntax, just as when using the
   general syntax, any unprotected Header Parameter values can reside in
   either the "unprotected" member or the "header" member, or in both.

   See Appendix A.5 for an example JWE using the flattened JWE JSON
   Serialization syntax.
*/
				var joseInfo = {
					protected: protected_header,
					recipients: recipients
				};
				if (aad_included) joseInfo.aad = aad;
				if (iv) joseInfo.iv = iv.toString('base64url');
				joseInfo.ciphertext = ct.toString('base64url');
				if (tag) joseInfo.tag = tag.toString('base64url');

				if ('unprotected' in options) joseInfo.unprotected = options.unprotected;

				this.joseInfo = joseInfo;

				return joseInfo;
			case 'flattened':
				var joseInfo = {};
				joseInfo.protected = protected_header;

				if (!protect_header) joseInfo.header = recipients[0].header;
				if ('encrypted_key' in recipients[0]) joseInfo.encrypted_key = recipients[0].encrypted_key;
				if (aad_included) joseInfo.aad = aad;
				if (iv) joseInfo.iv = iv.toString('base64url');
				joseInfo.ciphertext = ct.toString('base64url');
				if (tag) joseInfo.tag = tag.toString('base64url');

				if ('unprotected' in options) joseInfo.unprotected = options.unprotected;

				this.joseInfo = joseInfo;

				return joseInfo;

			case 'compact':
/*
RFC 7516

7.1.  JWE Compact Serialization

   The JWE Compact Serialization represents encrypted content as a
   compact, URL-safe string.  This string is:

      BASE64URL(UTF8(JWE Protected Header)) || '.' ||
      BASE64URL(JWE Encrypted Key) || '.' ||
      BASE64URL(JWE Initialization Vector) || '.' ||
      BASE64URL(JWE Ciphertext) || '.' ||
      BASE64URL(JWE Authentication Tag)

   Only one recipient is supported by the JWE Compact Serialization and
   it provides no syntax to represent JWE Shared Unprotected Header, JWE
   Per-Recipient Unprotected Header, or JWE AAD values.

*/

				// this.joseInfo = {
				// 	protected: Buffer.from(protected_header).toString('base64url'),
				// 	header: recipients[0].header,
				// 	encrypted_key: 'encrypted_key' in recipients[0] ? recipients[0].encrypted_key : ''
				// };
				// //if (aad_included) this.joseInfo.aad = aad;
				// if (iv) this.joseInfo.iv = iv.toString('base64url');
				// this.joseInfo.ciphertext = ct.toString('base64url');
				// if (tag) this.joseInfo.tag = tag.toString('base64url');

				// if ('unprotected' in options) this.joseInfo.unprotected = options.unprotected;

				// return Buffer.from(compact_header).toString('base64url') + '.' +
				// 	this.joseInfo.encrypted_key + '.' +
				// 	this.joseInfo.iv + '.' +
				// 	this.joseInfo.ciphertext + '.' +
				// 	this.joseInfo.tag;

				var compact_jwe = compact_header;
				// even when encrypted_key value is empty a dot is needed.
				// https://tools.ietf.org/id/draft-ietf-jose-cookbook-02.html#jwe-ecdh-output
				compact_jwe += '.' + ('encrypted_key' in recipients[0] ? recipients[0].encrypted_key : ''); 
				compact_jwe += '.' + iv.toString('base64url');
				compact_jwe += '.' + ct.toString('base64url');
				compact_jwe += '.' + tag.toString('base64url');

				return compact_jwe;

			default:
				throw jCastle.exception('UNKNOWN_ALGORITHM', 'JOS014');
		}

	}

/*
jCastle.jose.decrypt(ciphertext, algo_params)
-------------------------------------------------
jCastle.jose.decrypt(
	ciphertext,
	{
		key: rsaPrivateKey
	}
);
*/
	/**
	 * decrypts a message.
	 * 
	 * @public
	 * @param {mixed} jwt jwe token string or object to be decrypted.
	 * @param {object} keywrap_algo_params keywrap algorithm parameters object
	 *                 {mixed} key key buffer or jwk object.
	 * @param {object} options object.
	 * @returns decrypted message in buffer.
	 */
	decrypt(jwt, keywrap_algo_params, options = {})
	{
		// console.log('jose.decrypt()');

		var encrypted_key, jose_header, enc_algo;
		var iv, aad, aad_included, ciphertext, auth_tag;

		if (jCastle.util.isString(jwt)) {
			// compact serialization
			if (!/^([a-z0-9\.\-_]+)$/i.test(jwt)) throw jCastle.exception('NOT_JWT', 'JOS015');
			
			var jwt_arr = jwt.split('.');

/*
      BASE64URL(UTF8(JWE Protected Header)) || '.' ||
      BASE64URL(JWE Encrypted Key) || '.' ||
      BASE64URL(JWE Initialization Vector) || '.' ||
      BASE64URL(JWE Ciphertext) || '.' ||
      BASE64URL(JWE Authentication Tag)
*/
			// console.log('compact serialization');
			// console.log('jwt_arr.length: ', jwt_arr.length);

			var jwt_header = Buffer.from(jwt_arr[0], 'base64url').toString();
			encrypted_key = Buffer.from(jwt_arr[1], 'base64url');
			iv = Buffer.from(jwt_arr[2], 'base64url');
			ciphertext = Buffer.from(jwt_arr[3], 'base64url');
			auth_tag = Buffer.from(jwt_arr[4], 'base64url');
			jose_header = JSON.parse(jwt_header);
			enc_algo = jose_header.enc;
			aad = jwt_arr[0];
			aad_included = false;

			// console.log('enc_algo: ', enc_algo);
		} else {
/*
     {
      "protected":"<integrity-protected shared header contents>",
      "unprotected":<non-integrity-protected shared header contents>,
      "recipients":[
       {"header":<per-recipient unprotected header 1 contents>,
        "encrypted_key":"<encrypted key 1 contents>"},
       ...
       {"header":<per-recipient unprotected header N contents>,
        "encrypted_key":"<encrypted key N contents>"}],
      "aad":"<additional authenticated data contents>",
      "iv":"<initialization vector contents>",
      "ciphertext":"<ciphertext contents>",
      "tag":"<authentication tag contents>"
     }


     {
      "protected":"<integrity-protected header contents>",
      "unprotected":<non-integrity-protected header contents>,
      "header":<more non-integrity-protected header contents>,
      "encrypted_key":"<encrypted key contents>",
      "aad":"<additional authenticated data contents>",
      "iv":"<initialization vector contents>",
      "ciphertext":"<ciphertext contents>",
      "tag":"<authentication tag contents>"
     }
*/
			// console.log('JSON serialization');

			// there can be recipients more than one, and we have to find the right recipient.
			var recipients, recipient;
			var keywrap_algo = keywrap_algo_params.algoName || keywrap_algo_params.algo || keywrap_algo_params.alg;

			if ('recipients' in jwt) {
				recipients = jwt.recipients;

				if (recipients.length == 1) {
					recipient = recipients[0];
				} else {
					for (var i = 0; i < recipients.length; i++) {
						recipient = recipients[i];
						if (keywrap_algo.toUpperCase() == recipient.header.alg.toUpperCase()) break;
					}
				}
			} else {
				recipient = jwt;
			}

			// console.log(keywrap_algo);

			// when protectHeader option value is true then recipient has no header.
			var protect_header = false;

			if (!('header' in recipient)) protect_header = true;

			var protected_header = JSON.parse(Buffer.from(jwt.protected, 'base64url').toString());
			enc_algo = protected_header.enc;

			if (protect_header) {
				jose_header = protected_header;
			} else {
				jose_header = recipient.header;
				jose_header.enc = enc_algo;
			}

			// when the algo is ECDH-ES then there should be no encrypted key inside the recipient property.
			encrypted_key = 'encrypted_key' in recipient ? Buffer.from(recipient.encrypted_key, 'base64url') : '';
			iv = Buffer.from(jwt.iv, 'base64url');
			ciphertext = Buffer.from(jwt.ciphertext, 'base64url');
			aad = 'aad' in jwt ? jwt.aad : null;
			aad_included = aad ? true : false;
			auth_tag = Buffer.from(jwt.tag, 'base64url');

			if (!aad) aad = jwt.protected;
		}

		// console.log('jose_header: ', JSON.stringify(jose_header));

		// console.log('jose_header: ', jose_header);
		// console.log('keywrap_algo_params: ', keywrap_algo_params);

		var cek = jCastle.jose.fn.decryptContentEncKey(encrypted_key, jose_header, keywrap_algo_params);

		// console.log('cek: ', cek.toString('base64url'));

		var enc_algo_info = jCastle.jose.fn.getEncAlgoInfo(enc_algo);
		var enc_mac_key, enc_key;

		if ('macKeySize' in enc_algo_info) {
			enc_mac_key = cek.slice(0, enc_algo_info.macKeySize);
			enc_key = cek.slice(enc_algo_info.macKeySize);
		} else {
			enc_key = cek;
		}

		var params = {
			isEncryption: false,
			padding: 'pkcs7',
			mode: enc_algo_info.mode,
			iv: iv,
			key: enc_key
		};
		// console.log('params: ', params);

		// if (enc_algo_info.mode.toUpperCase() == 'GCM') {
		if (!('macHashAlgo' in enc_algo_info)) {
			params.additionalData = aad_included ? jwt.protected + '.' + aad : aad;
			params.nonce = iv;
			params.tagSize = 16;
		}

		var cipher = new jCastle.mcrypt(enc_algo_info.algoName);
		cipher.start(params);
		cipher.update(ciphertext);
		

		//if (enc_algo_info.mode.toUpperCase() == 'GCM') {
		if (!('macHashAlgo' in enc_algo_info)) {
			cipher.update(auth_tag);
			var pt = cipher.finalize();

			if ('encoding' in options) pt = pt.toString(options.encoding);

			return pt;

		} else {
			if (enc_algo_info.mac == 'HMac') {
				var pt = cipher.finalize();

				var hmac = new jCastle.hmac();
				hmac.start({
					algoName: enc_algo_info.macHashAlgo,
					key: enc_mac_key
				});

				hmac.update(aad_included ? jwt.protected + '.' + aad : aad).update(iv).update(ciphertext);

				var aad_len = aad_included ? (jwt.protected.length + aad.length + 1) : aad.length;

				// AL - 64bit length of aad_b64u
				var AL = Buffer.alloc(8);
				AL.writeInt32BE(aad_len * 8, 4);

				var tag = hmac.update(AL).finalize();
				tag = tag.slice(0, enc_algo_info.tagSize);

				if (!tag.equals(auth_tag)) {
					throw jCastle.exception('MAC_CHECK_FAIL', 'JOS016');
				}

				if ('encoding' in options) pt = pt.toString(options.encoding);

				return pt;
			} else {
				throw jCastle.exception('UNKNOWN_ALGORITHM', 'JOS017');
			}
		}
	}
};

jCastle.jose.headerParameters = {
//	'kid': 'kid',
//	'keyID': 'kid',
//	'zip': 'zip',
	'jku': 'jku',
	'jsonKeyURL': 'jku',
	'jwk': 'jwk',
	'jsonWebKey': 'jwk',
	'x5u': 'x5u',
	'certificateURL': 'x5u',
	'x509CertificateURL': 'x5u',
	'x5c': 'x5c',
	'certificateChain': 'x5c',
	'x509CertificateChain': 'x5c',
	'x5t': 'x5t',
	'certificateSHA1Thumbprint': 'x5t',
	'x509CertificateSHA1Thumbprint': 'x5t',
	'x5t#S256': 'x5t#S256',
	'certificateSHA256Thumbprint': 'x5t#S256',
	'x509CertificateSHA256Thumbprint': 'x5t#S256',
	'cty': 'cty',
	'contentType': 'cty',
	'crit': 'crit',
	'critical': 'crit'
};



jCastle.jose.fn = {};

jCastle.jose.fn.getSignAlgoInfo = function(algo)
{
/*
RFC 7518
3.1.  "alg" (Algorithm) Header Parameter Values for JWS

   The table below is the set of "alg" (algorithm) Header Parameter
   values defined by this specification for use with JWS, each of which
   is explained in more detail in the following sections:

   +--------------+-------------------------------+--------------------+
   | "alg" Param  | Digital Signature or MAC      | Implementation     |
   | Value        | Algorithm                     | Requirements       |
   +--------------+-------------------------------+--------------------+
   | HS256        | HMAC using SHA-256            | Required           |
   | HS384        | HMAC using SHA-384            | Optional           |
   | HS512        | HMAC using SHA-512            | Optional           |
   | RS256        | RSASSA-PKCS1-v1_5 using       | Recommended        |
   |              | SHA-256                       |                    |
   | RS384        | RSASSA-PKCS1-v1_5 using       | Optional           |
   |              | SHA-384                       |                    |
   | RS512        | RSASSA-PKCS1-v1_5 using       | Optional           |
   |              | SHA-512                       |                    |
   | ES256        | ECDSA using P-256 and SHA-256 | Recommended+       |
   | ES384        | ECDSA using P-384 and SHA-384 | Optional           |
   | ES512        | ECDSA using P-521 and SHA-512 | Optional           |
   | PS256        | RSASSA-PSS using SHA-256 and  | Optional           |
   |              | MGF1 with SHA-256             |                    |
   | PS384        | RSASSA-PSS using SHA-384 and  | Optional           |
   |              | MGF1 with SHA-384             |                    |
   | PS512        | RSASSA-PSS using SHA-512 and  | Optional           |
   |              | MGF1 with SHA-512             |                    |
   | none         | No digital signature or MAC   | Optional           |
   |              | performed                     |                    |
   +--------------+-------------------------------+--------------------+

   The use of "+" in the Implementation Requirements column indicates
   that the requirement strength is likely to be increased in a future
   version of the specification.

   See Appendix A.1 for a table cross-referencing the JWS digital
   signature and MAC "alg" (algorithm) values defined in this
   specification with the equivalent identifiers used by other standards
   and software packages.
*/

/*
		switch (algo.toUpperCase()) {
			case 'HS256': return {
					type: 'sign',
					algoName: 'HMac',
					hashAlgo: 'sha-256'
				};

			case 'HS384': return {
					type: 'sign',
					algoName: 'HMac',
					hashAlgo: 'sha-384'
				};

			case 'HS512': return {
					type: 'sign',
					algoName: 'HMac',
					hashAlgo: 'sha-512'
				};

			case 'RS256': return {
					type: 'sign',
					algoName: 'RSASSA-PKCS1-v1_5',
					hashAlgo: 'sha-256'
				};

			case 'RS384': return {
					type: 'sign',
					algoName: 'RSASSA-PKCS1-v1_5',
					hashAlgo: 'sha-384'
				};

			case 'RS512': return {
					type: 'sign',
					algoName: 'RSASSA-PKCS1-v1_5',
					hashAlgo: 'sha-512'
				};

			case 'ES256': return {
					type: 'sign',
					algoName: 'ECDSA',
					curve: 'P-256',
					hashAlgo: 'sha-256'
				};

			case 'ES384': return {
					type: 'sign',
					algoName: 'ECDSA',
					curve: 'P-384',
					hashAlgo: 'sha-384'
				};

			case 'ES512': return {
					type: 'sign',
					algoName: 'ECDSA',
					curve: 'P-512',
					hashAlgo: 'sha-512'
				};

			case 'PS256': return {
					type: 'sign',
					algoName: 'RSASSA-PSS',
					hashAlgo: 'sha-256'
				};
			case 'PS384': return {
					type: 'sign',
					algoName: 'RSASSA-PSS',
					hashAlgo: 'sha-384'
				};
			case 'PS512': return {
					type: 'sign',
					algoName: 'RSASSA-PSS',
					hashAlgo: 'sha-384'
				};
				
			case 'NONE': return {
					type: 'sign',
					algoName: 'none'
				};

			default:
				throw jCastle.exception('UNKNOWN_ALGORITHM', 'JOS006');
		}
*/
	var algo = algo.toUpperCase();

	if (algo == 'NONE') return {type: 'sign', algoName: 'none'};

	var m = algo.match(/^(HS|RS|ES|PS)(256|384|512)$/);

	if (!m) throw jCastle.exception('UNKNOWN_ALGORITHM', 'JOS007');

	var info = {};
	info.type = 'sign';
	info.hashAlgo = 'sha-' + m[2];
		
	switch (m[1]) {
		case 'HS': info.algoName = 'HMac'; break;
		case 'RS': info.algoName = 'RSASSA-PKCS1-v1_5'; break;
		case 'PS': info.algoName = 'RSASSA-PSS'; break;
		case 'ES': info.algoName = 'ECDSA'; info.curve = 'P-' + m[2]; break;
	}

	return info;
};

jCastle.jose.fn.getSignature = function(str, algo_info, key)
{
	var signature;

	if (!Buffer.isBuffer(str)) str = Buffer.from(str);

	switch (algo_info.algoName) {
		case 'HMac':
			if (typeof key == 'object' && 'kty' in key && key.kty == 'oct') {
				var jwk = key;
				key = Buffer.from(jwk.k, 'base64url');
			}

			var hmac = new jCastle.hmac(algo_info.hashAlgo);
			hmac.start({
				key: key
			});
			hmac.update(str);
			signature = hmac.finalize();

			return signature.toString('base64url');

		case 'RSASSA-PKCS1-v1_5':
		case 'RSASSA-PSS':
			var signer = new jCastle.pki('RSA');
			signer.setPrivateKey(key);
			signature = algo_info.algoName == 'RSASSA-PKCS1-v1_5' ? 
				signer.sign(str, { hashAlgo: algo_info.hashAlgo }) : 
				signer.pssSign(str, { hashAlgo: algo_info.hashAlgo, saltLength: -1 });

			return signature.toString('base64url');

		case 'ECDSA':
			var signer = new jCastle.pki('ECDSA');
			//signer.setParameters(algo_info.curve);
			signer.setPrivateKey(key);
			signature = signer.sign(str, { hashAlgo: algo_info.hashAlgo, returnType: 'concat' });

			return signature.toString('base64url');

		case 'none':
			return '';
	}
};

jCastle.jose.fn.verifySignature = function(str, signature_b64u, algo_info, key)
{
	if (!Buffer.isBuffer(str)) str = Buffer.from(str);

	switch (algo_info.algoName) {
		case 'HMac':
			if (typeof key == 'object' && 'kty' in key && key.kty == 'oct') {
				var jwk = key;
				key = Buffer.from(jwk.k, 'base64url');
			}

			try {
				var hmac = new jCastle.hmac(algo_info.hashAlgo);
				hmac.start({
					key: key
				});
				hmac.update(str);
				var signature = hmac.finalize();
				return signature_b64u == signature.toString('base64url');
			} catch (ex) {
				// console.log(ex.message);
				return false;
			}

		case 'RSASSA-PKCS1-v1_5':
		case 'RSASSA-PSS':
			try {
				var signer = new jCastle.pki('RSA');
				signer.setPublicKey(key);
				var signature = Buffer.from(signature_b64u, 'base64url');
				return algo_info.algoName == 'RSASSA-PKCS1-v1_5' ? 
					signer.verify(str, signature, { hashAlgo: algo_info.hashAlgo }) :
					signer.pssVerify(str, signature, { hashAlgo: algo_info.hashAlgo, saltLength: -1 });
			} catch (ex) {
				// console.log(ex.message);
				return false;
			}

		case 'ECDSA':
			try {
				var signer = new jCastle.pki('ECDSA');
				//signer.setParameters(algo_info.curve);
				signer.setPublicKey(key);
				var signature = Buffer.from(signature_b64u, 'base64url');
				return signer.verify(str, signature, { hashAlgo: algo_info.hashAlgo });
			} catch (ex) {
				// console.log(ex.message);
				return false;
			}

		case 'none':
			return true;
	}
};


jCastle.jose.fn.getHeaderParameter = function(name, value)
{
	switch (name) {
		case 'alg':
		case 'algoName':
			return '"alg":"' + value + '"';
		case 'cty':
		case 'contentType':
			return '"cty":"' + value + '"';
		case 'typ':
		case 'type':
			return '"typ":"' + value + '"';
		case 'kid':
		case 'keyID':
			return '"kid":"' + value + '"';
		case 'jku': // JWK Set URL
		case 'jsonKeyURL':
			return '"jku":"' + value + '"';
		case 'jwk': // JSON Web Key
		case 'jsonWebKey':
			return '"jwk":"' + value + '"';
		case 'x5u': // X.509 Certificate URL
		case 'certificateURL':
		case 'x509CertificateURL':
			return '"x5u":"' + value + '"';
		case 'x5c': // X.509 Certificate Chain
		case 'certificateChain':
		case 'x509CertificateChain':
			return '"x5c":"' + value + '"';
		case 'iv':
		case 'initialVector':
			return '"iv":"' + value + '"';
		case 'tag':
			return '"' + name + '":"' + value + '"';
		case 'epk':
//		case 'ephemeralPublicKey':
		case 'publicKey':
			return '"epk":"' + value + '"';
		case 'apu':
		case 'partyUInfo':
			return '"apu":"' + value + '"';
		case 'apv':
		case 'partyVInfo':
			return '"apv":"' + value + '"';
		case 'p2s':
		case 'salt':
			return '"p2s":"' + value + '"';
		case 'p2c':
		case 'count':
			return '"p2c":"' + value + '"';
		default:
			throw jCastle.exception('INVALID_PARAMS', 'JOS018');
	}
};

/*
https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar2.pdf

5.8.1.2.1 The Concatenation Format for OtherInfo

This section specifies the concatenation format for OtherInfo. This format has
been designed to provide a simple means of binding the derived keying material
to the context of the keyagreement transaction, independent of other actions 
taken by the relying application. Note: When the single-step KDF specified in 
Section 5.8.1.1 is used with H = hash as the auxiliary function and this 
concatenation format for OtherInfo, the resulting key-derivation method is the
Concatenation Key Derivation Function specified in the original version of 
SP 800-56A.

For this format, OtherInfo is a bit string equal to the following concatenation:

 AlgorithmID || PartyUInfo || PartyVInfo {|| SuppPubInfo }{|| SuppPrivInfo },

where the five subfields are bit strings comprised of items of information as 
described in Section 5.8.1.2.

Each of the three required subfields AlgorithmID, PartyUInfo, and PartyVInfo 
shall be the concatenation of a pre-determined sequence of substrings in which
each substring represents a distinct item of information. Each such substring 
shall have one of these two formats: either it is a fixed-length bit string, 
or it has the form Datalen || Data – where Data is a variable-length string 
of zero or more (eight-bit) bytes, and Datalen is a fixed-length, big-endian 
counter that indicates the length (in bytes) of Data. (In this variable-length
format, a null string of data shall be represented by a zero value for Datalen, 
indicating the absence of following data.) A protocol using this format for 
OtherInfo shall specify the number, ordering and meaning of the information-
bearing substrings that are included in each of the subfields AlgorithmID,
PartyUInfo, and PartyVInfo, and shall also specify which of the two formats 
(fixed-length or variable-length) is used by each such substring to represent 
its distinct item of information. The protocol shall specify the lengths for 
all fixed-length quantities, including the Datalen counters.

Each of the optional subfields SuppPrivInfo and SuppPubInfo (when allowed by 
the protocol employing the one-step KDF) shall be the concatenation of a 
pre-determined sequence of substrings representing additional items of 
information that may be used during key derivation upon mutual agreement 
of parties U and V. Each substring representing an item of information
shall be of the form Datalen || Data, where Data is a variable-length string 
of zero or more (eight-bit) bytes and Datalen is a fixed-length, big-endian 
counter that indicates the length (in bytes) of Data; the use of this form 
for the information allows parties U and V to omit a particular information 
item without confusion about the meaning of the other information that is
provided in the SuppPrivInfo or SuppPubInfo subfield. The substrings 
representing items of information that parties U and V choose not to 
contribute are set equal to Null, and are represented in this variable-length
format by setting Datalen equal to zero. If a protocol allows the use of 
the OtherInfo subfield SuppPrivInfo and/or the subfield SuppPubInfo, then the
protocol shall specify the number, ordering and meaning of additional items 
of information that may be used in the allowed subfield(s) and shall specify 
the fixed-length of the Datalen counters.
*/
jCastle.jose.fn.buildOtherInfo = function(algo_id, pu_info, pv_info, pub_info, priv_info)
{
	if (!algo_id) {
		throw jCastle.exception('INVALID_PARAMS', 'JOS019');
	}

	var algo_id_size_blk = Buffer.alloc(4);
	algo_id_size_blk.writeInt32BE(algo_id.length, 0);

	var pu_info_size_blk = Buffer.alloc(4);
	pu_info_size_blk.writeInt32BE(pu_info.length, 0);

	var pv_info_size_blk = Buffer.alloc(4);
	pv_info_size_blk.writeInt32BE(pv_info.length, 0);

	var other_info = Buffer.concat([
		algo_id_size_blk, algo_id,
		pu_info_size_blk, pu_info,
		pv_info_size_blk, pv_info
	]);

	if (pub_info && pub_info.length) {
		other_info = Buffer.concat([other_info, Buffer.from(pub_info)]);
	}

	if (priv_info && priv_info.length) {
		other_info = Buffer.concat([other_info, Buffer.from(priv_info)]);
	}

	return other_info;
};

// important!
// got hint from numbus-jose-jwt ... ECDH1PU.java
// algo_id:
//     when ECDH-ES / A128GCM then content encryption algorithm should be algo_id. so algo_id is A128GCM.
//     when ECDH-ES+A128KW / A128GCM then key encryption algorithm should be algo_id. so algo_id is ECDH-ES+A128KW.
jCastle.jose.fn.deriveKeyUsingECDHAndSinglestepKDF = function(other_pubkey_jwk, privkey_jwk, apu, apv, algo_id, key_size)
{
	// console.log('jose.fn.deriveKeyUsingECDHAndSinglestepKDF()');
	// console.log('algo_id: ', algo_id);
	// console.log('key_size: ', key_size);

	var pubkey = Buffer.concat([Buffer.alloc(1, 0x04),
		Buffer.from(other_pubkey_jwk.x, 'base64url'),
		Buffer.from(other_pubkey_jwk.y, 'base64url')]);

	var pki = new jCastle.pki('ECDSA');
	pki.setPrivateKey(privkey_jwk);

	var ecdh = new jCastle.ecdh(pki);
	var Z = ecdh.calculateAgreement(pubkey, null);

	// console.log('Z: ', Z.toString('hex'));

	var keydatalen = key_size * 8;

	var supp_pub_info = Buffer.alloc(4);
	supp_pub_info.writeInt32BE(keydatalen, 0);

	var supp_priv_info = Buffer.alloc(0);

	var other_info = jCastle.jose.fn.buildOtherInfo(
		Buffer.from(algo_id), 
		apu ? apu : Buffer.alloc(0), 
		apu ? apv : Buffer.alloc(0), 
		supp_pub_info, supp_priv_info);

	var key = jCastle.kdf.singlestepKDF(Z, key_size, other_info, 'sha-256', 'hash', null);

	return key_size && key_size != key.length ? key.slice(0, key_size) : key;
};

jCastle.jose.fn.encryptContentEncKey = function(cek, keywrap_algo_params, algo_info, enc_algo, enc_algo_info, prng)
{
	// console.log('jose.fn.encryptContentEncKey()');
	// console.log('algo_info: ', algo_info);
	// console.log('enc_algo: ', enc_algo);

	switch (algo_info.algoName) {
		case 'RSA':
/*
RFC 7518

4.2.  Key Encryption with RSAES-PKCS1-v1_5

   This section defines the specifics of encrypting a JWE CEK with
   RSAES-PKCS1-v1_5 [RFC3447].  The "alg" (algorithm) Header Parameter
   value "RSA1_5" is used for this algorithm.

   A key of size 2048 bits or larger MUST be used with this algorithm.

   An example using this algorithm is shown in Appendix A.2 of [JWE].

4.3.  Key Encryption with RSAES OAEP

   This section defines the specifics of encrypting a JWE CEK with RSAES
   using Optimal Asymmetric Encryption Padding (OAEP) [RFC3447].  Two
   sets of parameters for using OAEP are defined, which use different
   hash functions.  In the first case, the default parameters specified
   in Appendix A.2.1 of RFC 3447 are used.  (Those default parameters
   are the SHA-1 hash function and the MGF1 with SHA-1 mask generation
   function.)  In the second case, the SHA-256 hash function and the
   MGF1 with SHA-256 mask generation function are used.

   The following "alg" (algorithm) Header Parameter values are used to
   indicate that the JWE Encrypted Key is the result of encrypting the
   CEK using the corresponding algorithm:

   +-------------------+-----------------------------------------------+
   | "alg" Param Value | Key Management Algorithm                      |
   +-------------------+-----------------------------------------------+
   | RSA-OAEP          | RSAES OAEP using default parameters           |
   | RSA-OAEP-256      | RSAES OAEP using SHA-256 and MGF1 with        |
   |                   | SHA-256                                       |
   +-------------------+-----------------------------------------------+

   A key of size 2048 bits or larger MUST be used with these algorithms.
   (This requirement is based on Table 4 (Security-strength time frames)
   of NIST SP 800-57 [NIST.800-57], which requires 112 bits of security
   for new uses, and Table 2 (Comparable strengths) of the same, which
   states that 2048-bit RSA keys provide 112 bits of security.)

   An example using RSAES OAEP with the default parameters is shown in
   Appendix A.1 of [JWE].

*/
			var pki = new jCastle.pki('RSA');
			var key = keywrap_algo_params.publicKey || keywrap_algo_params.key;

			pki.setPublicKey(key);
			pki.setPadding(algo_info.padding, algo_info.hashAlgo);

			var encrypted_key = pki.publicEncrypt(cek);

			return {
				encrypted_key: encrypted_key.toString('base64url')
			};

		case 'KeyWrap':
/*
RFC 7518

4.4.  Key Wrapping with AES Key Wrap

   This section defines the specifics of encrypting a JWE CEK with the
   Advanced Encryption Standard (AES) Key Wrap Algorithm [RFC3394] using
   the default initial value specified in Section 2.2.3.1 of that
   document.

   The following "alg" (algorithm) Header Parameter values are used to
   indicate that the JWE Encrypted Key is the result of encrypting the
   CEK using the corresponding algorithm and key size:

   +-----------------+-------------------------------------------------+
   | "alg" Param     | Key Management Algorithm                        |
   | Value           |                                                 |
   +-----------------+-------------------------------------------------+
   | A128KW          | AES Key Wrap with default initial value using   |
   |                 | 128-bit key                                     |
   | A192KW          | AES Key Wrap with default initial value using   |
   |                 | 192-bit key                                     |
   | A256KW          | AES Key Wrap with default initial value using   |
   |                 | 256-bit key                                     |
   +-----------------+-------------------------------------------------+

   An example using this algorithm is shown in Appendix A.3 of [JWE].

*/
			var wrapper = new jCastle.keyWrap();
			var key = keywrap_algo_params.wrappingKey || keywrap_algo_params.key;

			if (typeof key == 'object' && 'kty' in key && key.kty == 'oct') { // jwk
				var jwk = key;
				key = Buffer.from(jwk.k, 'base64url');
			}

			var encrypted_key = wrapper.wrap(cek, {
				algoName: algo_info.wrapAlgo,
				wrappingKey: key
			});

			return {
				encrypted_key: encrypted_key.toString('base64url')
			};

		case 'ECDH':
/*
RFC 7518

4.6.  Key Agreement with Elliptic Curve Diffie-Hellman Ephemeral Static
      (ECDH-ES)

   This section defines the specifics of key agreement with Elliptic
   Curve Diffie-Hellman Ephemeral Static [RFC6090], in combination with
   the Concat KDF, as defined in Section 5.8.1 of [NIST.800-56A].  The
   key agreement result can be used in one of two ways:

   1.  directly as the Content Encryption Key (CEK) for the "enc"
       algorithm, in the Direct Key Agreement mode, or

   2.  as a symmetric key used to wrap the CEK with the "A128KW",
       "A192KW", or "A256KW" algorithms, in the Key Agreement with Key
       Wrapping mode.

   A new ephemeral public key value MUST be generated for each key
   agreement operation.

   In Direct Key Agreement mode, the output of the Concat KDF MUST be a
   key of the same length as that used by the "enc" algorithm.  In this
   case, the empty octet sequence is used as the JWE Encrypted Key
   value.  The "alg" (algorithm) Header Parameter value "ECDH-ES" is
   used in the Direct Key Agreement mode.

   In Key Agreement with Key Wrapping mode, the output of the Concat KDF
   MUST be a key of the length needed for the specified key wrapping
   algorithm.  In this case, the JWE Encrypted Key is the CEK wrapped
   with the agreed-upon key.

   The following "alg" (algorithm) Header Parameter values are used to
   indicate that the JWE Encrypted Key is the result of encrypting the
   CEK using the result of the key agreement algorithm as the key
   encryption key for the corresponding key wrapping algorithm:

   +-----------------+-------------------------------------------------+
   | "alg" Param     | Key Management Algorithm                        |
   | Value           |                                                 |
   +-----------------+-------------------------------------------------+
   | ECDH-ES+A128KW  | ECDH-ES using Concat KDF and CEK wrapped with   |
   |                 | "A128KW"                                        |
   | ECDH-ES+A192KW  | ECDH-ES using Concat KDF and CEK wrapped with   |
   |                 | "A192KW"                                        |
   | ECDH-ES+A256KW  | ECDH-ES using Concat KDF and CEK wrapped with   |
   |                 | "A256KW"                                        |
   +-----------------+-------------------------------------------------+

4.6.1.  Header Parameters Used for ECDH Key Agreement

   The following Header Parameter names are used for key agreement as
   defined below.

4.6.1.1.  "epk" (Ephemeral Public Key) Header Parameter

   The "epk" (ephemeral public key) value created by the originator for
   the use in key agreement algorithms.  This key is represented as a
   JSON Web Key [JWK] public key value.  It MUST contain only public key
   parameters and SHOULD contain only the minimum JWK parameters
   necessary to represent the key; other JWK parameters included can be
   checked for consistency and honored, or they can be ignored.  This
   Header Parameter MUST be present and MUST be understood and processed
   by implementations when these algorithms are used.

4.6.1.2.  "apu" (Agreement PartyUInfo) Header Parameter

   The "apu" (agreement PartyUInfo) value for key agreement algorithms
   using it (such as "ECDH-ES"), represented as a base64url-encoded
   string.  When used, the PartyUInfo value contains information about
   the producer.  Use of this Header Parameter is OPTIONAL.  This Header
   Parameter MUST be understood and processed by implementations when
   these algorithms are used.

4.6.1.3.  "apv" (Agreement PartyVInfo) Header Parameter

   The "apv" (agreement PartyVInfo) value for key agreement algorithms
   using it (such as "ECDH-ES"), represented as a base64url encoded
   string.  When used, the PartyVInfo value contains information about
   the recipient.  Use of this Header Parameter is OPTIONAL.  This
   Header Parameter MUST be understood and processed by implementations
   when these algorithms are used.

4.6.2.  Key Derivation for ECDH Key Agreement

   The key derivation process derives the agreed-upon key from the
   shared secret Z established through the ECDH algorithm, per
   Section 6.2.2.2 of [NIST.800-56A].

   Key derivation is performed using the Concat KDF, as defined in
   Section 5.8.1 of [NIST.800-56A], where the Digest Method is SHA-256.
   The Concat KDF parameters are set as follows:

   Z
      This is set to the representation of the shared secret Z as an
      octet sequence.

   keydatalen
      This is set to the number of bits in the desired output key.  For
      "ECDH-ES", this is length of the key used by the "enc" algorithm.
      For "ECDH-ES+A128KW", "ECDH-ES+A192KW", and "ECDH-ES+A256KW", this
      is 128, 192, and 256, respectively.

   AlgorithmID
      The AlgorithmID value is of the form Datalen || Data, where Data
      is a variable-length string of zero or more octets, and Datalen is
      a fixed-length, big-endian 32-bit counter that indicates the
      length (in octets) of Data.  In the Direct Key Agreement case,
      Data is set to the octets of the ASCII representation of the "enc"
      Header Parameter value.  In the Key Agreement with Key Wrapping
      case, Data is set to the octets of the ASCII representation of the
      "alg" (algorithm) Header Parameter value.

   PartyUInfo
      The PartyUInfo value is of the form Datalen || Data, where Data is
      a variable-length string of zero or more octets, and Datalen is a
      fixed-length, big-endian 32-bit counter that indicates the length
      (in octets) of Data.  If an "apu" (agreement PartyUInfo) Header
      Parameter is present, Data is set to the result of base64url
      decoding the "apu" value and Datalen is set to the number of
      octets in Data.  Otherwise, Datalen is set to 0 and Data is set to
      the empty octet sequence.

   PartyVInfo
      The PartyVInfo value is of the form Datalen || Data, where Data is
      a variable-length string of zero or more octets, and Datalen is a
      fixed-length, big-endian 32-bit counter that indicates the length
      (in octets) of Data.  If an "apv" (agreement PartyVInfo) Header
      Parameter is present, Data is set to the result of base64url
      decoding the "apv" value and Datalen is set to the number of
      octets in Data.  Otherwise, Datalen is set to 0 and Data is set to
      the empty octet sequence.

   SuppPubInfo
      This is set to the keydatalen represented as a 32-bit big-endian
      integer.

   SuppPrivInfo
      This is set to the empty octet sequence.

   Applications need to specify how the "apu" and "apv" Header
   Parameters are used for that application.  The "apu" and "apv" values
   MUST be distinct, when used.  Applications wishing to conform to
   [NIST.800-56A] need to provide values that meet the requirements of
   that document, e.g., by using values that identify the producer and
   consumer.  Alternatively, applications MAY conduct key derivation in
   a manner similar to "Diffie-Hellman Key Agreement Method" [RFC2631]:
   in that case, the "apu" parameter MAY either be omitted or represent
   a random 512-bit value (analogous to PartyAInfo in Ephemeral-Static
   mode in RFC 2631) and the "apv" parameter SHOULD NOT be present.

   See Appendix C for an example key agreement computation using this
   method.

*/
			var other_pubkey = keywrap_algo_params.partyPublicKey; // public key from the other part.
			var privkey_jwk = keywrap_algo_params.privateKey || keywrap_algo_params.key; // private key
			var apu = keywrap_algo_params.partyUInfo || keywrap_algo_params.apu || null;
			var apv = keywrap_algo_params.partyVInfo || keywrap_algo_params.apv || null;

			if (apu) apu = Buffer.from(apu);
			if (apv) apv = Buffer.from(apv);

			// var pki = new jCastle.pki('ECDSA');
			// pki.setPrivateKey(privkey_jwk);
			// var pubkey = pki.getPublicKey('jwt');

			// encryptor's public key
			var pubkey = {};
			pubkey.kty = "EC";
			// if ('kid' in privkey_jwk) pubkey.kid = privkey_jwk.kid;
			pubkey.crv = privkey_jwk.crv;
			pubkey.x = privkey_jwk.x;
			pubkey.y = privkey_jwk.y;

			if ('wrapAlgo' in algo_info) {
				// ECDH-ES+A128KW ...
				// the result of key agreement with concat kdf will be 
				// used for wrapping key.

				var key_size = jCastle.mcrypt.getKeySize(algo_info.wrapAlgo, 'KW');
				// console.log('key_size: ', key_size);

				var wrapping_key = jCastle.jose.fn.deriveKeyUsingECDHAndSinglestepKDF(
					other_pubkey,
					privkey_jwk,
					apu, apv,
					algo_info.name,
					key_size);

				// console.log('wrapping_key: ', wrapping_key.toString('base64url'));

				var wrapper = new jCastle.keyWrap();

				var encrypted_key = wrapper.wrap(cek, {
					algoName: algo_info.wrapAlgo,
					wrappingKey: wrapping_key
				});

				// console.log('encrypted_key: ', encrypted_key.toString('base64url'));

				var res = {};
				res.encrypted_key = encrypted_key.toString('base64url');
				res.epk = pubkey;
				if (apu) res.apu = apu.toString('base64url');
				if (apv) res.apv = apv.toString('base64url');
				return res;

				// return {
				// 	encrypted_key: encrypted_key.toString('base64url'),
				// 	epk: pubkey,
				// 	apu: apu,
				// 	apv: apv
				// };
			} else {
				// ECDH-ES
				// key agreement with concat kdf is already processed.
				// now there is no more process.
				var res = {};
				res.encrypted_key = '';
				res.epk = pubkey;
				if (apu) res.apu = apu.toString('base64url');
				if (apv) res.apv = apv.toString('base64url');
				return res;

				// return {
				// 	encrypted_key: '',
				// 	epk: pubkey,
				// 	apu: apu,
				// 	apv: apv
				// };
			}

		case 'AESGCM':
/*
RFC 7518

4.7.  Key Encryption with AES GCM

   This section defines the specifics of encrypting a JWE Content
   Encryption Key (CEK) with Advanced Encryption Standard (AES) in
   Galois/Counter Mode (GCM) ([AES] and [NIST.800-38D]).

   Use of an Initialization Vector (IV) of size 96 bits is REQUIRED with
   this algorithm.  The IV is represented in base64url-encoded form as
   the "iv" (initialization vector) Header Parameter value.

   The Additional Authenticated Data value used is the empty octet
   string.

   The requested size of the Authentication Tag output MUST be 128 bits,
   regardless of the key size.

   The JWE Encrypted Key value is the ciphertext output.

   The Authentication Tag output is represented in base64url-encoded
   form as the "tag" (authentication tag) Header Parameter value.

   The following "alg" (algorithm) Header Parameter values are used to
   indicate that the JWE Encrypted Key is the result of encrypting the
   CEK using the corresponding algorithm and key size:

    +-------------------+---------------------------------------------+
    | "alg" Param Value | Key Management Algorithm                    |
    +-------------------+---------------------------------------------+
    | A128GCMKW         | Key wrapping with AES GCM using 128-bit key |
    | A192GCMKW         | Key wrapping with AES GCM using 192-bit key |
    | A256GCMKW         | Key wrapping with AES GCM using 256-bit key |
    +-------------------+---------------------------------------------+

4.7.1.  Header Parameters Used for AES GCM Key Encryption

   The following Header Parameters are used for AES GCM key encryption.

4.7.1.1.  "iv" (Initialization Vector) Header Parameter

   The "iv" (initialization vector) Header Parameter value is the
   base64url-encoded representation of the 96-bit IV value used for the
   key encryption operation.  This Header Parameter MUST be present and
   MUST be understood and processed by implementations when these
   algorithms are used.

4.7.1.2.  "tag" (Authentication Tag) Header Parameter

   The "tag" (authentication tag) Header Parameter value is the
   base64url-encoded representation of the 128-bit Authentication Tag
   value resulting from the key encryption operation.  This Header
   Parameter MUST be present and MUST be understood and processed by
   implementations when these algorithms are used.

*/
			var iv = 'nonce' in keywrap_algo_params ? Buffer.from(keywrap_algo_params.nonce, 'base64url') : Buffer.from(keywrap_algo_params.iv, 'base64url');

			if (jCastle.util.isString(iv)) iv = Buffer.from(iv, 'base64url');
			else if (iv) iv = Buffer.from(iv);

			if (!iv || iv.length != algo_info.ivSize) {
				throw jCastle.exception('INVALID_IV', 'JOS020');
			}

			var tag_size = 'tagSize' in keywrap_algo_params ? keywrap_algo_params.tagSize : 16;

			var key = keywrap_algo_params.wrappingKey || keywrap_algo_params.key;

			if (typeof key == 'object' && 'kty' in key && key.kty == 'oct') { // jwk
				var jwk = key;
				key = Buffer.from(jwk.k, 'base64url');
			}

			var params = {
				key: key,
				nonce: iv,
				tagSize: tag_size,
				mode: algo_info.mode,
				isEncryption: true,
				padding: 'pkcs7'
				// additionalData should be empty string
			};

			var cipher = new jCastle.mcrypt(algo_info.wrapAlgo);
			cipher.start(params);
			cipher.update(cek);
			var encrypted_key = cipher.finalize();
			var tag = encrypted_key.slice(encrypted_key.length - algo_info.tagSize);
			encrypted_key = encrypted_key.slice(0, encrypted_key.length - algo_info.tagSize);					

			return {
				encrypted_key: encrypted_key.toString('base64url'),
				iv: iv.toString('base64url'),
				tag: tag.toString('base64url')
			};

		case 'PBES2':
/*
RFC 7518

4.8.  Key Encryption with PBES2

   This section defines the specifics of performing password-based
   encryption of a JWE CEK, by first deriving a key encryption key from
   a user-supplied password using PBES2 schemes as specified in
   Section 6.2 of [RFC2898], then by encrypting the JWE CEK using the
   derived key.

   These algorithms use HMAC SHA-2 algorithms as the Pseudorandom
   Function (PRF) for the PBKDF2 key derivation and AES Key Wrap
   [RFC3394] for the encryption scheme.  The PBES2 password input is an
   octet sequence; if the password to be used is represented as a text
   string rather than an octet sequence, the UTF-8 encoding of the text
   string MUST be used as the octet sequence.  The salt parameter MUST
   be computed from the "p2s" (PBES2 salt input) Header Parameter value
   and the "alg" (algorithm) Header Parameter value as specified in the
   "p2s" definition below.  The iteration count parameter MUST be
   provided as the "p2c" (PBES2 count) Header Parameter value.  The
   algorithms respectively use HMAC SHA-256, HMAC SHA-384, and HMAC
   SHA-512 as the PRF and use 128-, 192-, and 256-bit AES Key Wrap keys.
   Their derived-key lengths respectively are 16, 24, and 32 octets.

   The following "alg" (algorithm) Header Parameter values are used to
   indicate that the JWE Encrypted Key is the result of encrypting the
   CEK using the result of the corresponding password-based encryption
   algorithm as the key encryption key for the corresponding key
   wrapping algorithm:

   +--------------------+----------------------------------------------+
   | "alg" Param Value  | Key Management Algorithm                     |
   +--------------------+----------------------------------------------+
   | PBES2-HS256+A128KW | PBES2 with HMAC SHA-256 and "A128KW"         |
   |                    | wrapping                                     |
   | PBES2-HS384+A192KW | PBES2 with HMAC SHA-384 and "A192KW"         |
   |                    | wrapping                                     |
   | PBES2-HS512+A256KW | PBES2 with HMAC SHA-512 and "A256KW"         |
   |                    | wrapping                                     |
   +--------------------+----------------------------------------------+

   See Appendix C of the JWK specification [JWK] for an example key
   encryption computation using "PBES2-HS256+A128KW".

4.8.1.  Header Parameters Used for PBES2 Key Encryption

   The following Header Parameters are used for Key Encryption with
   PBES2.

4.8.1.1.  "p2s" (PBES2 Salt Input) Header Parameter

   The "p2s" (PBES2 salt input) Header Parameter encodes a Salt Input
   value, which is used as part of the PBKDF2 salt value.  The "p2s"
   value is BASE64URL(Salt Input).  This Header Parameter MUST be
   present and MUST be understood and processed by implementations when
   these algorithms are used.

   The salt expands the possible keys that can be derived from a given
   password.  A Salt Input value containing 8 or more octets MUST be
   used.  A new Salt Input value MUST be generated randomly for every
   encryption operation; see RFC 4086 [RFC4086] for considerations on
   generating random values.  The salt value used is (UTF8(Alg) || 0x00
   || Salt Input), where Alg is the "alg" (algorithm) Header Parameter
   value.

4.8.1.2.  "p2c" (PBES2 Count) Header Parameter

   The "p2c" (PBES2 count) Header Parameter contains the PBKDF2
   iteration count, represented as a positive JSON integer.  This Header
   Parameter MUST be present and MUST be understood and processed by
   implementations when these algorithms are used.

   The iteration count adds computational expense, ideally compounded by
   the possible range of keys introduced by the salt.  A minimum
   iteration count of 1000 is RECOMMENDED.

*/
			var salt_input = keywrap_algo_params.salt || keywrap_algo_params.p2s || null;
			if (!salt_input) throw jCastle.exception('INVALID_PARAMS', 'JOS021');
			salt_input = jCastle.util.isString(salt_input) ? Buffer.from(salt_input, 'base64url') : Buffer.from(salt_input);

			var count = keywrap_algo_params.count || keywrap_algo_params.p2c || 1024;
			// if (count < 1000) throw jCastle.exception('COUNTER_TOO_SMALL', 'JOS022');

			var password = keywrap_algo_params.password;
			if (!Buffer.isBuffer(password)) password = Buffer.from(password);
			if (!password) throw jCastle.exception('INVALID_PARAMS', 'JOS023');

			var algo = keywrap_algo_params.algoName || keywrap_algo_params.alg;

			var salt = Buffer.concat([Buffer.from(algo), Buffer.alloc(1), salt_input]);

			var key_len = algo_info.keySize;

			var wrapping_key = jCastle.kdf.pbkdf2(password, salt, count, key_len, algo_info.hashAlgo);

			var wrapper = new jCastle.keyWrap();

			var encrypted_key = wrapper.wrap(cek, {
				algoName: algo_info.wrapAlgo,
				wrappingKey: wrapping_key
			});

			// console.log('algo: ', algo);
			// console.log('salt input: ', salt_input, ', ', salt_input.toString('base64url'));
			// console.log('salt: ', salt);
			// console.log('wrapping_key: ', wrapping_key);

			return {
				encrypted_key: encrypted_key.toString('base64url'),
				p2s: salt_input.toString('base64url'),
				p2c: count
			};

		case 'dir':
		case 'DIR':
			// direct key usage for content encryption key
			return {
				encrypted_key: ''
			};

		default:
			throw jCastle.exception('UNKNOWN_ALGORITHM', 'JOS024');	
	}
};

jCastle.jose.fn.decryptContentEncKey = function(encrypted_key, jose_header, keywrap_algo_params)
{
	// console.log('jose.fn.decryptcontentEncKey()');
	// console.log('jose_header: ', jose_header);
	// console.log('keywrap_algo_params: ', keywrap_algo_params);
	// console.log('jose_header: ', jose_header);

	var algo = jose_header.alg;
	var algo_info = jCastle.jose.fn.getKeyAlgoInfo(algo);

	// console.log('algo_info: ', algo_info);

	switch (algo_info.algoName) {

		case 'RSA':
			var pki = new jCastle.pki('RSA');
			var key = keywrap_algo_params.privateKey || keywrap_algo_params.key;

			pki.setPrivateKey(key);
			pki.setPadding(algo_info.padding, algo_info.hashAlgo);

			var cek = pki.privateDecrypt(encrypted_key);

			return cek;

		case 'KeyWrap':
			var wrapper = new jCastle.keyWrap();
			var key = keywrap_algo_params.wrappingKey || keywrap_algo_params.key;

			if (typeof key == 'object' && 'kty' in key && key.kty == 'oct') { // jwk
				var jwk = key;
				key = Buffer.from(jwk.k, 'base64url');
			}

			var cek = wrapper.unwrap(encrypted_key, {
				algoName: algo_info.wrapAlgo,
				wrappingKey: key
			});

			return cek;
			
		case 'ECDH':
			var other_pubkey_jwk = jose_header.epk || keywrap_algo_params.partyPublicKey || null; // public key from the other part.
			var privkey_jwk = keywrap_algo_params.privateKey || keywrap_algo_params.key; // private key
			var apu = 'apu' in jose_header ? jose_header.apu : null;
			var apv = 'apv' in jose_header ? jose_header.apv : null;
			var cek;

			if (apu) apu = Buffer.from(apu, 'base64url');
			if (apv) apv = Buffer.from(apv, 'base64url');

			if (!other_pubkey_jwk) {
				throw jCastle.exception('PUBKEY_NOT_SET', 'JOS025');
			}

			if ('wrapAlgo' in algo_info) {
				var key_size = jCastle.mcrypt.getKeySize(algo_info.wrapAlgo, 'KW');

				var wrapping_key = jCastle.jose.fn.deriveKeyUsingECDHAndSinglestepKDF(
					other_pubkey_jwk,
					privkey_jwk,
					apu, apv, 
					algo_info.name,
					key_size);

				// console.log('wrapping_key: ', wrapping_key.toString('base64url'));

				var wrapper = new jCastle.keyWrap();

				cek = wrapper.unwrap(encrypted_key, {
					algoName: algo_info.wrapAlgo,
					wrappingKey: wrapping_key
				});

				// console.log('cek: ', cek.toString('base64url'));
			} else {
				var enc_algo_info = jCastle.jose.fn.getEncAlgoInfo(jose_header.enc);
				var mackey_size = enc_algo_info.macKeySize;
				var key_size = enc_algo_info.keySize;

				// console.log('enc_algo_info: ', enc_algo_info);
				// console.log('key_size: ', key_size);

				cek = jCastle.jose.fn.deriveKeyUsingECDHAndSinglestepKDF(
					other_pubkey_jwk,
					privkey_jwk,
					apu, apv,
					jose_header.enc,
					key_size + mackey_size);
			}

			return cek;

		case 'AESGCM':
			//var iv = 'nonce' in keywrap_algo_params ? Buffer.from(keywrap_algo_params.nonce, 'base64url') : Buffer.from(keywrap_algo_params.iv, 'base64url');
			var iv = Buffer.from(jose_header.iv, 'base64url');
			var tag_size = 'tagSize' in keywrap_algo_params ? keywrap_algo_params.tagSize : 16;
			var tag = Buffer.from(jose_header.tag, 'base64url');
			var key = keywrap_algo_params.wrappingKey || keywrap_algo_params.key;

			if (typeof key == 'object' && 'kty' in key && key.kty == 'oct') { // jwk
				var jwk = key;
				key = Buffer.from(jwk.k, 'base64url');
			}

			var cipher = new jCastle.mcrypt(algo_info.wrapAlgo);
			var params = {
				key: key,
				nonce: iv,
				tagSize: tag_size,
				mode: algo_info.mode,
				isEncryption: false,
				padding: 'pkcs7'
				// additionalData should be empty string
			};

			cipher.start(params);
			cipher.update(encrypted_key);
			cipher.update(tag);
			var cek = cipher.finalize();

			return cek;

		case 'PBES2':
			var salt_input = Buffer.from(jose_header.p2s, 'base64url');
			var count = jose_header.p2c;

			var password = keywrap_algo_params.password;
			if (!Buffer.isBuffer(password)) password = Buffer.from(password, 'latin1');
			if (!password) throw jCastle.exception('INVALID_PARAMS', 'JOS026');

			var salt = Buffer.concat([Buffer.from(algo), Buffer.alloc(1), salt_input]);

			var key_len = algo_info.keySize;
			var wrapping_key = jCastle.kdf.pbkdf2(password, salt, count, key_len, algo_info.hashAlgo);

			var wrapper = new jCastle.keyWrap();

			var cek = wrapper.unwrap(encrypted_key, {
				algoName: algo_info.wrapAlgo,
				wrappingKey: wrapping_key
			});

			return cek;

		case 'DIR':
			var key = keywrap_algo_params.key;

			if (typeof key == 'object' && 'kty' in key && key.kty == 'oct') { // jwk
				var jwk = key;
				key = Buffer.from(jwk.k, 'base64url');
			}

			return key;

		default:
			throw jCastle.exception('UNKNOWN_ALGORITHM', 'JOS027');	
	}
};

jCastle.jose.fn.getKeyAlgoInfo = function(algo)
{
/*
RFC 7518

4.1.  "alg" (Algorithm) Header Parameter Values for JWE

   The table below is the set of "alg" (algorithm) Header Parameter
   values that are defined by this specification for use with JWE.
   These algorithms are used to encrypt the CEK, producing the JWE
   Encrypted Key, or to use key agreement to agree upon the CEK.

   +--------------------+--------------------+--------+----------------+
   | "alg" Param Value  | Key Management     | More   | Implementation |
   |                    | Algorithm          | Header | Requirements   |
   |                    |                    | Params |                |
   +--------------------+--------------------+--------+----------------+
   | RSA1_5             | RSAES-PKCS1-v1_5   | (none) | Recommended-   |
   | RSA-OAEP           | RSAES OAEP using   | (none) | Recommended+   |
   |                    | default parameters |        |                |
   | RSA-OAEP-256       | RSAES OAEP using   | (none) | Optional       |
   |                    | SHA-256 and MGF1   |        |                |
   |                    | with SHA-256       |        |                |
   | A128KW             | AES Key Wrap with  | (none) | Recommended    |
   |                    | default initial    |        |                |
   |                    | value using        |        |                |
   |                    | 128-bit key        |        |                |
   | A192KW             | AES Key Wrap with  | (none) | Optional       |
   |                    | default initial    |        |                |
   |                    | value using        |        |                |
   |                    | 192-bit key        |        |                |
   | A256KW             | AES Key Wrap with  | (none) | Recommended    |
   |                    | default initial    |        |                |
   |                    | value using        |        |                |
   |                    | 256-bit key        |        |                |
   | dir                | Direct use of a    | (none) | Recommended    |
   |                    | shared symmetric   |        |                |
   |                    | key as the CEK     |        |                |
   | ECDH-ES            | Elliptic Curve     | "epk", | Recommended+   |
   |                    | Diffie-Hellman     | "apu", |                |
   |                    | Ephemeral Static   | "apv"  |                |
   |                    | key agreement      |        |                |
   |                    | using Concat KDF   |        |                |
   | ECDH-ES+A128KW     | ECDH-ES using      | "epk", | Recommended    |
   |                    | Concat KDF and CEK | "apu", |                |
   |                    | wrapped with       | "apv"  |                |
   |                    | "A128KW"           |        |                |
   | ECDH-ES+A192KW     | ECDH-ES using      | "epk", | Optional       |
   |                    | Concat KDF and CEK | "apu", |                |
   |                    | wrapped with       | "apv"  |                |
   |                    | "A192KW"           |        |                |
   | ECDH-ES+A256KW     | ECDH-ES using      | "epk", | Recommended    |
   |                    | Concat KDF and CEK | "apu", |                |
   |                    | wrapped with       | "apv"  |                |
   |                    | "A256KW"           |        |                |
   | A128GCMKW          | Key wrapping with  | "iv",  | Optional       |
   |                    | AES GCM using      | "tag"  |                |
   |                    | 128-bit key        |        |                |
   | A192GCMKW          | Key wrapping with  | "iv",  | Optional       |
   |                    | AES GCM using      | "tag"  |                |
   |                    | 192-bit key        |        |                |
   | A256GCMKW          | Key wrapping with  | "iv",  | Optional       |
   |                    | AES GCM using      | "tag"  |                |
   |                    | 256-bit key        |        |                |
   | PBES2-HS256+A128KW | PBES2 with HMAC    | "p2s", | Optional       |
   |                    | SHA-256 and        | "p2c"  |                |
   |                    | "A128KW" wrapping  |        |                |
   | PBES2-HS384+A192KW | PBES2 with HMAC    | "p2s", | Optional       |
   |                    | SHA-384 and        | "p2c"  |                |
   |                    | "A192KW" wrapping  |        |                |
   | PBES2-HS512+A256KW | PBES2 with HMAC    | "p2s", | Optional       |
   |                    | SHA-512 and        | "p2c"  |                |
   |                    | "A256KW" wrapping  |        |                |
   +--------------------+--------------------+--------+----------------+

   The More Header Params column indicates what additional Header
   Parameters are used by the algorithm, beyond "alg", which all use.
   All but "dir" and "ECDH-ES" also produce a JWE Encrypted Key value.

   The use of "+" in the Implementation Requirements column indicates
   that the requirement strength is likely to be increased in a future
   version of the specification.  The use of "-" indicates that the
   requirement strength is likely to be decreased in a future version of
   the specification.

   See Appendix A.2 for a table cross-referencing the JWE "alg"
   (algorithm) values defined in this specification with the equivalent
   identifiers used by other standards and software packages.

*/
	algo = algo.toUpperCase();
	switch (algo) {
		case 'RSA1_5': return {
				name: algo,
				type: 'key',
				algoName: 'RSA',
				padding: 'RSAES-PKCS1-V1_5', // 'PKCS1_Type_2',
				hashAlgo: 'sha-1'
			};

		case 'RSA-OAEP': return {
				name: algo,
				type: 'key',
				algoName: 'RSA',
				padding: 'RSAES-OAEP', // 'PKCS1_OAEP',
				hashAlgo: 'sha-1'
			};

		case 'RSA-OAEP-256': return {
				name: algo,
				type: 'key',
				algoName: 'RSA',
				padding: 'RSAES-OAEP', //'PKCS1_OAEP',
				hashAlgo: 'sha-256'
			};

		case 'A128KW': return {
				name: algo,
				type: 'key',
				algoName: 'KeyWrap',
				wrapAlgo: 'AES-128'
			};

		case 'A192KW':  return {
				name: algo,
				type: 'key',
				algoName: 'KeyWrap',
				wrapAlgo: 'AES-192'
			};

		case 'A256KW':  return {
				name: algo,
				type: 'key',
				algoName: 'KeyWrap',
				wrapAlgo: 'AES-256'
			};

		case 'ECDH-ES': return {
				name: algo,
				type: 'key',
				algoName: 'ECDH'
			};

		case 'ECDH-ES+A128KW': return {
				name: algo,
				type: 'key',
				algoName: 'ECDH',
				wrapAlgo: 'AES-128'
			};

		case 'ECDH-ES+A192KW': return {
				name: algo,
				type: 'key',
				algoName: 'ECDH',
				wrapAlgo: 'AES-192'
			};

		case 'ECDH-ES+A256KW': return {
				name: algo,
				type: 'key',
				algoName: 'ECDH',
				wrapAlgo: 'AES-256'
			};

		case 'A128GCMKW': return {
				name: algo,
				type: 'key',
				algoName: 'AESGCM',
				wrapAlgo: 'AES-128',
				mode: 'GCM',
				keySize: 16,
				ivSize: 12,
				tagSize: 16
			};

		case 'A192GCMKW': return {
				name: algo,
				type: 'key',
				algoName: 'AESGCM',
				wrapAlgo: 'AES-192',
				mode: 'GCM',
				keySize: 24,
				ivSize: 12,
				tagSize: 16
			};

		case 'A256GCMKW': return {
				name: algo,
				type: 'key',
				algoName: 'AESGCM',
				wrapAlgo: 'AES-256',
				keySize: 32,
				mode: 'GCM',
				ivSize: 12,
				tagSize: 16
			};

		case 'PBES2-HS256+A128KW': return {
				name: algo,
				type: 'key',
				algoName: 'PBES2',
				hashAlgo: 'sha-256',
				wrapAlgo: 'aes-128',
				keySize: 16
			};

		case 'PBES2-HS384+A192KW': return {
				name: algo,
				type: 'key',
				algoName: 'PBES2',
				hashAlgo: 'sha-384',
				wrapAlgo: 'aes-192',
				keySize: 24
			};

		case 'PBES2-HS512+A256KW': return {
				name: algo,
				type: 'key',
				algoName: 'PBES2',
				hashAlgo: 'sha-512',
				wrapAlgo: 'aes-256',
				keySize: 32
			};

		case 'DIR': return {
				name: algo,
				type: 'key',
				algoName: 'DIR'
			};					

		default:
			throw jCastle.exception('UNKNOWN_ALGORITHM', 'JOS028');
	}
};

jCastle.jose.fn.getEncAlgoInfo = function(algo)
{
	switch (algo.toUpperCase()) {

/*
RFC 7518

5.3.  Content Encryption with AES GCM

   This section defines the specifics of performing authenticated
   encryption with AES in Galois/Counter Mode (GCM) ([AES] and
   [NIST.800-38D]).

   The CEK is used as the encryption key.

   Use of an IV of size 96 bits is REQUIRED with this algorithm.

   The requested size of the Authentication Tag output MUST be 128 bits,
   regardless of the key size.

   The following "enc" (encryption algorithm) Header Parameter values
   are used to indicate that the JWE Ciphertext and JWE Authentication
   Tag values have been computed using the corresponding algorithm and
   key size:

           +-------------------+------------------------------+
           | "enc" Param Value | Content Encryption Algorithm |
           +-------------------+------------------------------+
           | A128GCM           | AES GCM using 128-bit key    |
           | A192GCM           | AES GCM using 192-bit key    |
           | A256GCM           | AES GCM using 256-bit key    |
           +-------------------+------------------------------+

   An example using this algorithm is shown in Appendix A.1 of [JWE].

*/
		case 'A128GCM': return {
				name: algo,
				type: 'enc',
				algoName: 'AES-128',
				mode: 'GCM', 
				keySize: 16,
				tagSize: 16
			};

		case 'A192GCM': return {
				name: algo,
				type: 'enc',
				algoName: 'AES-192',
				mode: 'GCM', 
				keySize: 24,
				tagSize: 16
			}; 

		case 'A256GCM': return {
				name: algo,
				type: 'enc',
				algoName: 'AES-256',
				mode: 'GCM', 
				keySize: 32,
				tagSize: 16
			};

/*
RFC 7518

5.2.3.  AES_128_CBC_HMAC_SHA_256

   This algorithm is a concrete instantiation of the generic
   AES_CBC_HMAC_SHA2 algorithm above.  It uses the HMAC message
   authentication code [RFC2104] with the SHA-256 hash function [SHS] to
   provide message authentication, with the HMAC output truncated to 128
   bits, corresponding to the HMAC-SHA-256-128 algorithm defined in
   [RFC4868].  For encryption, it uses AES in the CBC mode of operation
   as defined in Section 6.2 of [NIST.800-38A], with PKCS #7 padding and
   a 128-bit IV value.

   The AES_CBC_HMAC_SHA2 parameters specific to AES_128_CBC_HMAC_SHA_256
   are:

      The input key K is 32 octets long.
      ENC_KEY_LEN is 16 octets.
      MAC_KEY_LEN is 16 octets.
      The SHA-256 hash algorithm is used for the HMAC.
      The HMAC-SHA-256 output is truncated to T_LEN=16 octets, by
      stripping off the final 16 octets.

5.2.4.  AES_192_CBC_HMAC_SHA_384

   AES_192_CBC_HMAC_SHA_384 is based on AES_128_CBC_HMAC_SHA_256, but
   with the following differences:

      The input key K is 48 octets long instead of 32.
      ENC_KEY_LEN is 24 octets instead of 16.
      MAC_KEY_LEN is 24 octets instead of 16.
      SHA-384 is used for the HMAC instead of SHA-256.
      The HMAC SHA-384 value is truncated to T_LEN=24 octets instead of
      16.

5.2.5.  AES_256_CBC_HMAC_SHA_512

   AES_256_CBC_HMAC_SHA_512 is based on AES_128_CBC_HMAC_SHA_256, but
   with the following differences:

      The input key K is 64 octets long instead of 32.
      ENC_KEY_LEN is 32 octets instead of 16.
      MAC_KEY_LEN is 32 octets instead of 16.
      SHA-512 is used for the HMAC instead of SHA-256.
      The HMAC SHA-512 value is truncated to T_LEN=32 octets instead of
      16.

*/
		case 'A128CBC-HS256': return {
				name: algo,
				type: 'enc',
				algoName: 'AES-128',
				mode: 'CBC', 
				keySize: 16,
				macKeySize: 16,
				tagSize: 16,
				mac: 'HMac',
				macHashAlgo: 'sha-256'
			};

		case 'A192CBC-HS384': return {
				name: algo,
				type: 'enc',
				algoName: 'AES-192',
				mode: 'CBC', 
				keySize: 24,
				macKeySize: 24,
				tagSize: 24,
				mac: 'HMac',
				macHashAlgo: 'sha-384'
			};

		case 'A256CBC-HS512': return {
				name: algo,
				type: 'enc',
				algoName: 'AES-256',
				mode: 'CBC', 
				keySize: 32,
				macKeySize: 32,
				tagSize: 32,
				mac: 'HMac',
				macHashAlgo: 'sha-512'
			};

		default:
			throw jCastle.exception('UNKNOWN_ALGORITHM', 'JOS029');
	}
};


jCastle.jose.rasterize =
jCastle.jose.rasterizeJWT = function(jwt)
{
	function rasterizeHeader(header)
	{
		if ('typ' in header) {
			header.type = header.typ;
			delete header.typ;
		}
		if ('cty' in header) {
			header.contentType = header.cty;
			delete header.cty;
		}
		if ('kid' in header) {
			header.keyID = header.kid;
			delete header.kid;
		}
		if ('jku' in header) {
			header.jwtSetURL = header.jku;
			delete header.jku;
		}
		if ('jwk' in header) {
			header.jsonWebKey = header.jwk;
			delete header.jwk;
		}
		if ('x5u' in header) {
			header.x509URL = header.x5u;
			delete header.x5u;
		}
		if ('x5c' in header) {
			header.x509CertificateChain = header.x5c;
			delete header.x5c;
		}
		if ('x5t' in header) {
			header.x509CertificateSHA1Thumbprint = header.x5t;
			delete header.x5t;
		}
		if ('x5t#S256' in header) {
			header.x509CertificateSHA256Thumbprint = header['x5t#S256'];
			delete header['x5t#S256'];
		}
		if ('crit' in header) {
			header.critical = header.crit;
			delete header.crit;
		}
	};

	function rasterizePayload(payload)
	{
		if ('iss' in payload) {
			payload.issuer = payload.iss;
			delete payload.iss;
		}
		if ('sub' in payload) {
			payload.subject = payload.sub;
			delete payload.sub;
		}
		if ('aud' in payload) {
			payload.audience = payload.aud;
			delete payload.aud;
		}
		if ('exp' in payload) {
			var date = new Date(payload.exp * 1000);
			payload.expirationTime = date.toUTCString();
			delete payload.exp;
		}
		if ('nbf' in payload) {
			var nbf = new Date(payload.nbf * 1000);
			payload.notBefore = nbf.toUTCString();
			delete payload.nbf;
		}
		if ('iat' in payload) {
			var iat = new Date(payload.iat * 1000);
			payload.issueAt = iat.toUTCString();
			delete payload.iat;
		}
		if ('jti' in payload) {
			payload.jwtID = jti;
			delete payload.jti;
		}
	};

	if (jCastle.util.isString(jwt)) {
		var jws = new jCastle.jose();
		jwt = jws.parse(jwt);
	}

	var res = jCastle.util.clone(jwt);

	if ('protected' in res) {
		res.protected.algo = res.protected.alg;
		delete res.protected.alg;
	}

	if ('payload' in res) {
		if (!jCastle.util.isString(res.payload)) {
			rasterizePayload(res.payload);
		}
	}

	if ('header' in res) {
		rasterizeHeader(res.header);
	}

	if ('signatures' in res) {
		for (var i = 0; i < res.signatures.length; i++) {
			var signature = res.signatures[i];

			if ('protected' in signature) {
				signature.protected.algo = signature.protected.alg;
				delete signature.protected.alg;
			}

			if ('header' in signature) {
				rasterizeHeader(signature.header);
			}
		}
	}

	return res;
};

/**
 * creates a new class instance.
 * 
 * @public
 * @returns the new class instance.
 */
jCastle.jose.create = function()
{
	return new jCastle.jose();
};

jCastle.jose.jws = {
	sign: function (payload, algo_params, options) 
	{
		return jCastle.jose.create().sign(payload, algo_params, options);
	},
	verify: function (jwt, algo_params, options) 
	{
		return jCastle.jose.create().verify(jwt, algo_params, options);
	},
	validate: function (jwt, algo_params) 
	{
		return jCastle.jose.create().validate(jwt, algo_params);
	},
	parse: function (jwt) 
	{
		return jCastle.jose.create().parse(jwt);
	}
};

jCastle.jose.jwe = {
	encrypt: function (message, algo_params, enc_algo_params, options)
	{
		return jCastle.jose.create().encrypt(message, algo_params, enc_algo_params, options);
	},
	decrypt: function (jwt, algo_params, options)
	{
		return jCastle.jose.create().decrypt(jwt, algo_params, options);
	}
};

jCastle.JOSE = jCastle.jose;

module.exports = jCastle.jose;
