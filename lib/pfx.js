/**
 * A Javascript implemenation of Personal Information Exchange(PFX)
 * 
 * @author Jacob Lee
 *
 * Copyright (C) 2015-2022 Jacob Lee.
 */
var jCastle = require('./jCastle');
// var BigInteger = require('./biginteger');
require('./util');
require('./pbe');
require('./pki');
require('./certificate');
require('./cert-config');

// https://tools.ietf.org/html/rfc7292

jCastle.pfx = class
{
	/**
	 * An implemenation of Personal Information Exchange(PFX)
	 * 
	 * @constructor
	 */
	constructure()
	{
		this.pfxInfo = null;
		this.password = null;
		this.signKey = null;
	}

	/**
	 * sets pki for signKey.
	 * 
	 * @public
	 * @param {mixed} signkey pki instance or pem string or buffer.
	 * @param {buffer} password password value. if signkey is encrypted privateKey pem.
	 * @returns this class instance.
	 */
	setSignKey(signkey, password)
	{
		var pkey;

		if (jCastle.util.isString(signkey)) {
			var pem = signkey;
			pkey = new jCastle.pki(); // empty PKI
			pkey.parse(pem, password);
		} else {
			pkey = new jCastle.pki().init(signkey);
		}

		this.signKey = pkey;

		return this;
	}

/*
pfxInfo = {
	version: 3,
	authSafe: [safeContents_0, safeContents_1, safeContents_2, ... safeContents_i],
	dataType: data | signedData,
	macInfo: macInfo (if dataType is data),
	signedInfo: signedInfo (if dataType is signedData)
};

var macInfo = {
	algo: hash_algo,
	salt: salt,
	iterations: iterations
};

safeContents_i = {
	dataType: data | encryptedData | envelopedData,
	contents: [safeBag_0, safeBag_1, safeBag_2, ... , safeBag_i],
	encryptedInfo: pbe_info if dataType is encryptedData,
	publicKeyInfo: publickey_info if dataType is envelopedData
};

safeBag_i = {
	bagId: keyBag | pkcs8ShroudedKeyBag | certBag | crlBag | secretBag | safeContentsBag,
	content: bag_content,
	attributes: bag_attributes,
	encryptedInfo: pbe_info if bagId is pkcs8ShroudedKeyBag
};

var encryptedInfo = {
	algo: "pbeWithSHAAnd40BitRC2-CBC", // for certBag,
//	algo: "pbeWithSHAAnd3-KeyTripleDES-CBC", // for pkcs8ShroudedKeyBag
	kdfInfo: {
		salt: salt_value, // if not given it will be generated.
		iterations: 2048
	}
};
*/
/*
options = {
	signKey: sign_key for envelopedData or signedData // not supported yet though
	password: password,
	format: 'der'
}
*/
	/**
	 * parses pfx value.
	 * 
	 * @public
	 * @param {mixed} pfx pfx pem string or buffer. ASN1 object is acceptable.
	 * @param {object} options options object
	 *                 {string} format pem format type. 'asn1' | 'base64' | 'der' | 'buffer' | 'pem'. (default: 'pem')
	 *                 {buffer} password password value.
	 * @returns the parsed pfx information data object.
	 */
	parse(pfx, options = {})
	{
		var format = 'format' in options ? options.format.toLowerCase() : 'auto';

		var buf, pfxSequence, asn1 = new jCastle.asn1();
		//asn1.ignoreLengthError();

		var password = 'password' in options ? Buffer.from(options.password, 'latin1') : null;

		if ('signKey' in options) this.setSignKey(options.signKey, password);
		if (format == 'auto') format = jCastle.util.seekPemFormat(pfx);

		if (format == 'asn1') {
			pfxSequence = pfx;
		} else {
			switch (format) {
				case 'hex':
					buf = Buffer.from(pfx, 'hex');
					break;
				case 'base64':
					buf = Buffer.from(pfx, 'base64');
					break;
				case 'der':
				case 'buffer':
				default:
					buf = Buffer.from(pfx);
					break;
			}

			try {
				pfxSequence = asn1.parse(buf);
			} catch (e) {
				pfxSequence = null;
			}

			if (!jCastle.asn1.isSequence(pfxSequence)) {
				throw jCastle.exception("INVALID_PFX_FORMAT", 'PFX001');
			}
		}


/*
 PFX ::= SEQUENCE {
     version    INTEGER {v3(3)}(v3,...),
     authSafe   ContentInfo,
     macData    MacData OPTIONAL
 }
*/
		var version = pfxSequence.items[0].intVal;
		if (version != 3) {
			console.log("This PFX structure might have contents that cannot be recognized by the current version of jCastle.pfx.");
		}

		var dataType = jCastle.oid.getName(pfxSequence.items[1].items[0].value);

		if (dataType == 'signedData') {

			throw jCastle.exception("UNSUPPORTED_PFX_STRUCTURE", 'PFX002');
		} else {
			jCastle.assert(dataType, 'data', 'UNSUPPORTED_PFX_STRUCTURE', 'PFX003');
		}

		var authSafeSequence = pfxSequence.items[1].items[1].items[0].value;
		var macInfo = null;

		if (dataType == 'data' && typeof pfxSequence.items[2] != 'undefined') { // optional
/*
 MacData ::= SEQUENCE {
     mac        DigestInfo,
     macSalt    OCTET STRING,
     iterations INTEGER DEFAULT 1
     -- Note: The default is for historical reasons and its use is
     -- deprecated.
 }
*/
			var macDataSequence = pfxSequence.items[2];

			macInfo = this._parseMacData(macDataSequence, authSafeSequence.buffer);

			// console.log('macInfo: ', macInfo);

			if (!macInfo.check && !options.skipMacCheck) {
				throw jCastle.exception("MAC_CHECK_FAIL", 'PFX004');
			}
		}

		var authSafe = this._parseAuthSafe(authSafeSequence);

		var pfxInfo = {
			type: 'PFX',
			version: version,
			authSafe: authSafe,
			dataType: dataType
		};
		
		if (dataType == 'data' && macInfo) pfxInfo.macInfo = macInfo;
		if (dataType == 'signedData' && signedInfo) pfxInfo.signedInfo = signedInfo;

		this.pfxInfo = pfxInfo;

		return pfxInfo;
	}


	// openssl style
/*
var options = {
	certificate: userCert,
	privateKey: userPrivKey,
	password: password,
	format: 'der'
};
*/
	/**
	 * export certificate and privateKey as OpenSSL does.
	 * 
	 * @public
	 * @param {object} options options object
	 *                 {mixed} certificate certificate pem or object to be incapsulated.
	 *                 {mixed} privateKey privateKey pem or object to be shrouded.
	 *                 {buffer} password password value for encryption.
	 *                 {object} certificateEncryptAlgo certificate encryption algorithm
	 *                                                 {string} algo algorithm name. ex) "pbeWithSHAAnd40BitRC2-CBC"
	 *                                                 {buffer} salt salt value. if not given, it will be generated.
	 *                                                 {number} iterations iterations number.
	 *                 {object} privateKeyEncryptAlgo privateKey encryption algorithm
	 *                                                 {string} algo algorithm name. ex) "pbeWithSHAAnd3-KeyTripleDES-CBC"
	 *                                                 {buffer} salt salt value. if not given, it will be generated.
	 *                                                 {number} iterations iterations number.
	 *                 {object} macInfo mac information for mac tag.
	 *                                  {string} algo hash algorithm name. ex) 'sha-1'
	 *                                  {number} iterations iterations number.
	 * @returns 
	 */
	exportCertificateAndPrivateKey(options = {})
	{
		if (!('certificate' in options) || !('privateKey' in options)) {
			throw jCastle.exception('INVALID_PARAMS', 'PFX005');
		}

		// we do only support for encryptedData and data, not signedData nor envelopedData
		// right now.

		var password = 'password' in options ? Buffer.from(options.password, 'latin1') : null;
		var format = 'format' in options ? options.format.toLowerCase() : 'buffer';
		var macInfo = 'macInfo' in options ? options.macInfo : {};

		if (!('algo' in macInfo)) macInfo.algo = 'sha-1';
		if (!('iterations' in macInfo)) macInfo.iterations = 1;
		// salt will be generated if not given.

		var certEncryptAlgo = 'certificateEncryptAlgo' in options ? options.certificateEncryptAlgo : {
			algo: "pbeWithSHAAnd40BitRC2-CBC",
			salt: null,
			iterations: 2048
		};
		var privKeyEncryptAlgo = 'privateKeyEncryptAlgo' in options ? options.privateKeyEncryptAlgo : {
			algo: "pbeWithSHAAnd3-KeyTripleDES-CBC",
			salt: null,
			iterations: 2048
		};

		var skipMacData = 'skipMacData' in options ? options.skipMacData : false;

		// private key can be encrypted.
		var privateKeyInfo;
		if (typeof options.privateKey == 'object' &&
			'algo' in options.privateKey && 
			'privateKey' in options.privateKey) {// privateKeyInfo
			privateKeyInfo = options.privateKey;
		} else if (typeof options.privateKey == 'object' && 
			'pkiName' in options.privateKey) {// pki
			privateKeyInfo = options.privateKey.getPrivateKeyInfo();
		} else {
			var pki = new jCastle.pki();
			pki.parsePrivateKey(options.privateKey, password);
			privateKeyInfo = pki.getPrivateKeyInfo();
		}

		var authSafe = [];

		if (!certEncryptAlgo && !privKeyEncryptAlgo) {
			// no encryption for certificate & private key
			// pasword will be used for macData though.
			var safeContents = {
				dataType: 'data',
				contents: []
			};

			safeContents.contents.push({
				bagId: 'certBag',
				content: options.certificate
			});

			safeContents.contents.push({
				bagId: 'keyBag',
				content: options.privateKey
			});

			authSafe.push(safeContents);
		} else {
			var safeContents_1, safeContents_2;

			if (!certEncryptAlgo) {
				safeContents_1 = {
					dataType: 'data',
					contents: [{
						bagId: 'certBag',
						content: options.certificate
					}]
				};
			} else {
				safeContents_1 = {
					dataType: 'encryptedData',
					contents: [{
						bagId: 'certBag',
						content: options.certificate						
					}],
					encryptedInfo: certEncryptAlgo
				};
			}

			if (!privKeyEncryptAlgo) {
				safeContents_2 = {
					dataType: 'data',
					contents: [{
						bagId: 'keyBag',
						content: privateKeyInfo
					}]
				};
			} else {
				safeContents_2 = {
					dataType: 'data',
					contents: [{
						bagId: 'pkcs8ShroudedKeyBag',
						content: privateKeyInfo,
						encryptedInfo: privKeyEncryptAlgo
					}]
				};
			}

			authSafe.push(safeContents_1);
			authSafe.push(safeContents_2);
		}
		
		var pfx_info = {
			version: 3,
			authSafe: authSafe,
			dataType: 'data',
			macInfo: macInfo
		};

//console.log(pfx_info);

		return this.exportPFX(pfx_info, {
			format: format,
			password: password,
			skipMacData: skipMacData
		});
	}

/*
options = {
	password: password,
	signKey: signKey,
	format: 'der'
};
*/
	/**
	 * alias for exportPFX()
	 * 
	 * @public
	 * @param {object} pfxInfo pfx information data object.
	 * @param {object} options options object.
	 *                 {buffer} password password value for encryption.
	 *                 {object} signKey pki object.
	 * @returns pfx pem string or buffer.
	 */
	export(pfxInfo, options)
	{
		return this.exportPFX(pfxInfo, options);
	}

	/**
	 * exports pfx pem with the given pfxInfo object.
	 * 
	 * @public
	 * @param {object} pfxInfo pfx information data object.
	 * @param {object} options options object
	 *                 {buffer} password password value for encryption.
	 *                 {object} signKey pki object.
	 * @returns pfx pem string or buffer.
	 */
	exportPFX(pfxInfo, options = {})
	{
		var format = 'format' in options ? options.format.toLowerCase() : 'buffer';

		if ('password' in options) this.password = Buffer.from(options.password);
		if ('signKey' in options) this.signKey = options.signKey;

		var dataType = 'dataType' in options ? options.dataType : 'data';

		var version = 3;
		if ('version' in pfxInfo) {
			jCastle.assert(pfxInfo.version, 3, "INVALID_PFX_FORMAT", 'PFX006');
		}

		var asn1 = new jCastle.asn1();
		var authSafeSchema = this._getAuthSafeSchema(pfxInfo.authSafe);

//console.log(authSafeSchema);

		var authSafeDer = asn1.getDER(authSafeSchema);


		var contentInfoSchema = {
			type: jCastle.asn1.tagSequence,
			items: [{
				type: jCastle.asn1.tagOID,
				value: jCastle.oid.getOID('data')
			}, {
				tagClass: jCastle.asn1.tagClassContextSpecific,
				type: 0x00,
				constructed: true,
				items: [{
					type: jCastle.asn1.tagOctetString,
					value: authSafeDer
				}]
			}]
		};

		var pfxSchema;

		if (dataType == 'signedData') {
			if (!this.signKey) {
				throw jCastle.exception('PKI_NOT_SET', 'PFX007');
			}

			// not supported yet!
			throw jCastle.exception("UNSUPPORTED_PFX_STRUCTURE", 'PFX008');

/*
The signed-data content type shall have ASN.1 type SignedData:

      SignedData ::= SEQUENCE {
        version CMSVersion,
        digestAlgorithms DigestAlgorithmIdentifiers,
        encapContentInfo EncapsulatedContentInfo,
        certificates [0] IMPLICIT CertificateSet OPTIONAL,
        crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
        signerInfos SignerInfos }

      DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier

      SignerInfos ::= SET OF SignerInfo
*/


		} else {
			// dataType is data
			var macDataSchema = null;

			if (!options.skipMacData) {
				if ('macInfo' in pfxInfo) {
					if (!this.password) {
						throw jCastle.exception('NO_PASSPHRASE', 'PFX009');
					}
					macDataSchema = this._getMacDataSchema(pfxInfo.macInfo, authSafeDer);
				}
			}

			pfxSchema = {
				type: jCastle.asn1.tagSequence,
				items: [{
					type: jCastle.asn1.tagInteger, // version
					intVal: version
				}, contentInfoSchema
			]};

			if (macDataSchema) {
				pfxSchema.items.push(macDataSchema);
			}
		}

		var der = asn1.getDER(pfxSchema);
		var buf = Buffer.from(der, 'latin1');

		switch (format) {
			case 'hex': return buf.toString('hex');
			case 'base64': return buf.toString('base64');
			case 'der': return der;
			case 'buffer': return buf;
			default: return buf.toString(format);
		}
	}

	_parseAuthSafe(authSafeSequence)
	{
		// console.log('pfx._parseAuthSafe()');
/*
 AuthenticatedSafe ::= SEQUENCE OF ContentInfo
     -- Data if unencrypted
     -- EncryptedData if password-encrypted
     -- EnvelopedData if public key-encrypted

 SafeContents ::= SEQUENCE OF SafeBag
*/
		var authSafe = [];
		var asn1 = new jCastle.asn1();
		//asn1.ignoreLengthError();

		for (var i = 0; i < authSafeSequence.items.length; i++) {
/*
safeContents_i = {
	dataType: data | encryptedData | envelopedData,
	contents: [safeBag_0, safeBag_1, safeBag_2, ... , safeBag_i],
	encryptedInfo: pbe_info if dataType is encryptedData,
	publicKeyInfo: publickey_info if dataType is envelopedData
};
*/
			var safeContentsSequence = authSafeSequence.items[i];
			var dataType = jCastle.oid.getName(safeContentsSequence.items[0].value);
			var safeContents = {};
			var contentsSequence;
			safeContents.dataType = dataType;

			// console.log('dataType: ', dataType);

			if (dataType == 'encryptedData') {
/*
SEQUENCE(2 elem)
	OBJECT IDENTIFIER										1.2.840.113549.1.7.6  -- encryptedData
	[0](1 elem)
		SEQUENCE(2 elem)
			INTEGER											0
			SEQUENCE(3 elem)
				OBJECT IDENTIFIER							1.2.840.113549.1.7.1  -- data
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER						1.2.840.113549.1.12.1.6  -- pbeWithSHAAnd40BitRC2-CBC
					SEQUENCE(2 elem)
						OCTET STRING(8 byte)				DCC4AB26FEEBEDBF
						INTEGER								2048
				[0](1000 byte)								F874E18A79592AF9C55016B620DC38240D3CC4636A4DC533B74C8F19D1050C0425ED…
*/
				var idx = 0;
				if (safeContentsSequence.items[1].items[0].items[idx].type == jCastle.asn1.tagInteger) idx++;

				jCastle.assert(
					jCastle.oid.getName(safeContentsSequence.items[1].items[0].items[idx].items[0].value),
					'data', 
					"UNSUPPORTED_PFX_STRUCTURE", 'PFX010'
				);

				var pbe_info = jCastle.pbe.asn1.pbeInfo.parse(safeContentsSequence.items[1].items[0].items[idx].items[1]);

// there are two cases...
// it seems that there is no rule...
/*
	[0](1 elem)
		OCTET STRING(1024 byte)					494E7732CC0829601BFD3251FC4E50F1777E955D4225D3689E5D00C29BD0407848E3…
*/
/*
	[0](3 elem)
		OCTET STRING(1024 byte)					3141D60EBEA82560FE739AFEB6FD7E6CBAD024841C52530C69B9BEECEB73FC94F6DC…
		OCTET STRING(1024 byte)					331C341C70E03CEE77C4D821AD3E5E3FF9F303A7AA64A57B3F72D91BB1FEF1E0BC6E…
		OCTET STRING(96 byte)					D8EE640A888ABA13CAAA91F7168E9333A17D3492E3EFEB178A4831F7BCABE2C2390B2C…
*/
/*
	[0](1000 byte)								F874E18A79592AF9C55016B620DC38240D3CC4636A4DC533B74C8F19D1050C0425ED…
*/

				var enc_data = this._combineData(safeContentsSequence.items[1].items[0].items[idx].items[2]);

				if (!Buffer.isBuffer(enc_data)) enc_data = Buffer.from(enc_data, 'latin1');

				// console.log('pbe_info: ', pbe_info);

				var der = this._pbeDecrypt(pbe_info, enc_data);

				try {
					contentsSequence = asn1.parse(der);
				} catch (e) {
					throw jCastle.exception('WRONG_PASSPHRASE', 'PFX011');
				}

				if (!jCastle.asn1.isSequence(contentsSequence)) {
					throw jCastle.exception('WRONG_PASSPHRASE', 'PFX012');
				}

				//safeContents.encryptedInfo = this._getEncryptedInfo(pbe_info);
				safeContents.encryptedInfo = pbe_info;

			} else if (dataType == 'envelopedData') {
/*
https://tools.ietf.org/html/rfc5652

6.1.  EnvelopedData Type

   The following object identifier identifies the enveloped-data content
   type:

      id-envelopedData OBJECT IDENTIFIER ::= { iso(1) member-body(2)
          us(840) rsadsi(113549) pkcs(1) pkcs7(7) 3 }

   The enveloped-data content type shall have ASN.1 type EnvelopedData:

      EnvelopedData ::= SEQUENCE {
        version CMSVersion,
        originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
        recipientInfos RecipientInfos,
        encryptedContentInfo EncryptedContentInfo,
        unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }

      OriginatorInfo ::= SEQUENCE {
        certs [0] IMPLICIT CertificateSet OPTIONAL,
        crls [1] IMPLICIT RevocationInfoChoices OPTIONAL }

      RecipientInfos ::= SET SIZE (1..MAX) OF RecipientInfo

      EncryptedContentInfo ::= SEQUENCE {
        contentType ContentType,
        contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
        encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL }

      EncryptedContent ::= OCTET STRING

      UnprotectedAttributes ::= SET SIZE (1..MAX) OF Attribute

   The fields of type EnvelopedData have the following meanings:

      version is the syntax version number.  The appropriate value
      depends on originatorInfo, RecipientInfo, and unprotectedAttrs.
      The version MUST be assigned as follows:

         IF (originatorInfo is present) AND
            ((any certificates with a type of other are present) OR
            (any crls with a type of other are present))
         THEN version is 4
         ELSE
            IF ((originatorInfo is present) AND
               (any version 2 attribute certificates are present)) OR
               (any RecipientInfo structures include pwri) OR
               (any RecipientInfo structures include ori)
            THEN version is 3
            ELSE
               IF (originatorInfo is absent) AND
                  (unprotectedAttrs is absent) AND
                  (all RecipientInfo structures are version 0)
               THEN version is 0
               ELSE version is 2

      originatorInfo optionally provides information about the
      originator.  It is present only if required by the key management
      algorithm.  It may contain certificates and CRLs:

         certs is a collection of certificates.  certs may contain
         originator certificates associated with several different key
         management algorithms.  certs may also contain attribute
         certificates associated with the originator.  The certificates
         contained in certs are intended to be sufficient for all
         recipients to build certification paths from a recognized
         "root" or "top-level certification authority".  However, certs
         may contain more certificates than necessary, and there may be
         certificates sufficient to make certification paths from two or
         more independent top-level certification authorities.
         Alternatively, certs may contain fewer certificates than
         necessary, if it is expected that recipients have an alternate
         means of obtaining necessary certificates (e.g., from a
         previous set of certificates).

         crls is a collection of CRLs.  It is intended that the set
         contain information sufficient to determine whether or not the
         certificates in the certs field are valid, but such
         correspondence is not necessary.  There MAY be more CRLs than
         necessary, and there MAY also be fewer CRLs than necessary.

      recipientInfos is a collection of per-recipient information.
      There MUST be at least one element in the collection.

      encryptedContentInfo is the encrypted content information.

      unprotectedAttrs is a collection of attributes that are not
      encrypted.  The field is optional.  Useful attribute types are
      defined in Section 11.

   The fields of type EncryptedContentInfo have the following meanings:

      contentType indicates the type of content.

      contentEncryptionAlgorithm identifies the content-encryption
      algorithm, and any associated parameters, used to encrypt the
      content.  The content-encryption process is described in Section
      6.3.  The same content-encryption algorithm and content-encryption
      key are used for all recipients.

      encryptedContent is the result of encrypting the content.  The
      field is optional, and if the field is not present, its intended
      value must be supplied by other means.

   The recipientInfos field comes before the encryptedContentInfo field
   so that an EnvelopedData value may be processed in a single pass.
*/
/*
SEQUENCE(2 elem)
	OBJECT IDENTIFIER										1.2.840.113549.1.7.3  -- envelopedData
	[0](1 elem)                                             
		SEQUENCE(3 elem)                                    ----> EnvelopedData-Sequence
			INTEGER											2  ----> cmsVersion
			SET(1 elem)                                     ----> recipientInfos
				SEQUENCE(4 elem)                            ----> recipientInfo
					INTEGER									0
					SEQUENCE(2 elem)
						SEQUENCE(1 elem)
							SET(2 elem)
								SEQUENCE(2 elem)
									OBJECT IDENTIFIER		2.5.4.6  -- countryName
									PrintableString			US
								SEQUENCE(2 elem)
									OBJECT IDENTIFIER		2.5.4.3  -- commonName
									BMPString				Peculiar Ventures
						INTEGER								1
					SEQUENCE(2 elem)
						OBJECT IDENTIFIER					1.2.840.113549.1.1.7 -- rsaOAEP
						SEQUENCE(2 elem)
							[0](1 elem)
								SEQUENCE(2 elem)
									OBJECT IDENTIFIER		2.16.840.1.101.3.4.2.3  -- sha-512
									NULL
							[1](1 elem)
								SEQUENCE(2 elem)
									OBJECT IDENTIFIER		1.2.840.113549.1.1.8 -- pkcs1-MGF
									SEQUENCE(2 elem)
										OBJECT IDENTIFIER	2.16.840.1.101.3.4.2.3  -- sha-512
										NULL
					OCTET STRING(256 byte)					D6B3F5916C8C26A2F2604537E94740CA5ACA49BB3240E902A8E49548CDF4855F99DFC…
			SEQUENCE(3 elem)                                ---->  encryptedContentInfo
				OBJECT IDENTIFIER							1.2.840.113549.1.7.1  -- data
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER						2.16.840.1.101.3.4.1.2 -- aes-128-CBC
					OCTET STRING(16 byte)					9E8D877D8003A552859DC6F3B9DFC752
				[0](3 elem)
					OCTET STRING(1024 byte)					D6E88BA9EAEA9D0D04C4682D4E85117472EF43CFB47206ECCA7F9E3180258E5C339D…
					OCTET STRING(1024 byte)					7B8BF701A533B13A77C85F02DEC71CEB7E6D9A0B49EAE7D21641718304701C6B8875…
					OCTET STRING(96 byte)					A3D6FC257A49D9AB20B35A9FBAD10952B50B5AD6A8B0ACB8272473CF3DA9A502C8B6FE…
*/
				var sequence = safeContentsSequence.items[1].items[0];
				var result = this._decryptEnvelopedData(sequence);

				try {
					contentsSequence = asn1.parse(result.buffer);
				} catch (e) {
					throw jCastle.exception('PKI_NOT_MATCH', 'PFX013');
				}

				if (!jCastle.asn1.isSequence(contentsSequence)) {
					throw jCastle.exception('PKI_NOT_MATCH', 'PFX014');
				}

				safeContents.envelopedInfo = result.envelopedInfo;
			} else {
/*
SEQUENCE(2 elem)
	OBJECT IDENTIFIER												1.2.840.113549.1.7.1  -- data
	[0](1 elem)
		OCTET STRING(1 elem)
			SEQUENCE(2 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER								1.2.840.113549.1.12.10.1.1  -- keyBag
					[0](1 elem)
						SEQUENCE(3 elem)
							INTEGER0
							SEQUENCE(2 elem)
								OBJECT IDENTIFIER					1.2.840.113549.1.1.1  -- rsaEncryption
								NULL
							OCTET STRING(1 elem)
								SEQUENCE(9 elem)
									INTEGER							0
									INTEGER(2048 bit)				286093241866849712004460914154496840984222441819662416691202949065049…
									INTEGER							65537
									INTEGER(2048 bit)				266435981569209840585932640104148194037429734562480368956938535380567…
									INTEGER(1024 bit)				177873172927109931538968188574191405271114869627825502415916775271800…
									INTEGER(1024 bit)				160841141561064371523763071645921854446629678940298963533877439500510…
									INTEGER(1024 bit)				158405021052502312347839226054657783805229843461836941315631882325455…
									INTEGER(1023 bit)				737929939493428677384760980552905735615188547900713983785743450402269…
									INTEGER(1023 bit)				663042909414007878995513477868946331797501234466899680305480466335559…

*/
				jCastle.assert(
					dataType,
					'data', 
					"UNSUPPORTED_PFX_STRUCTURE", 'PFX016'
				);

				contentsSequence = safeContentsSequence.items[1].items[0].value;
			}

			var contents = [];
			for (var j = 0; j < contentsSequence.items.length; j++) {
				var safeBagSequence = contentsSequence.items[j];
				var safeBag = this._parseSafeBag(safeBagSequence);
				contents.push(safeBag);
			}

			safeContents.contents = contents;

			authSafe.push(safeContents);
		}

		return authSafe;
	}

	_decryptEnvelopedData(sequence)
	{
		var envelopedInfo = this._parseEnvelopedData(sequence);
// console.log('envelopedInfo: ', envelopedInfo);
		var key = this._getKeyFromEnvelopedInfo(envelopedInfo);
/*
		var der = jCastle.mcrypt.decrypt({
			message: envelopedInfo.encryptedContentInfo.encryptedContent,
			algoName: envelopedInfo.encryptedContentInfo.contentEncryptionAlgo.algoInfo.algo,
			mode: envelopedInfo.encryptedContentInfo.contentEncryptionAlgo.algoInfo.mode,
			keySize: envelopedInfo.encryptedContentInfo.contentEncryptionAlgo.algoInfo.keySize,
			key: key,
			iv: envelopedInfo.encryptedContentInfo.contentEncryptionAlgo.iv,
			padding: 'pkcs7',
			format: 'utf8'
		});
*/
		var crypto = new jCastle.mcrypt(envelopedInfo.encryptedContentInfo.contentEncryptionAlgo.algoInfo.algo);
		crypto.start({
			mode: envelopedInfo.encryptedContentInfo.contentEncryptionAlgo.algoInfo.mode,
			isEncryption: false,
			keySize: envelopedInfo.encryptedContentInfo.contentEncryptionAlgo.algoInfo.keySize,
			key: key,
			iv: envelopedInfo.encryptedContentInfo.contentEncryptionAlgo.iv,
			padding: 'pkcs7'
		});
		crypto.update(envelopedInfo.encryptedContentInfo.encryptedContent);
		var buf = crypto.finalize();

		return {
			envelopedInfo: envelopedInfo,
			buffer: buf
		};
	}


	_getRecipientInfoByType(recipientInfos, type)
	{
		var recipientInfo = null;

		for (var i = 0; i < recipientInfos.length; i++) {
			if (recipientInfos[i].type == type) {
				recipientInfo = recipientInfos[i];
				break;
			}
		}

		return recipientInfo;
	}

	_getKeyFromEnvelopedInfo(envelopedData)
	{
		var key;

		if (!this.signKey || !this.signKey.hasPrivateKey()) {
			throw jCastle.exception("PKI_NOT_SET", 'PFX017');
		}

		switch (this.signKey.pkiName) {
			case 'RSA':
				var recipientInfo = this._getRecipientInfoByType(envelopedData.recipientInfos, 'keyTransRecipientInfo');
				if (recipientInfo == null || recipientInfo.keyEncryptionAlgo.algo != 'RSA') {
					throw jCastle.exception('PKI_NOT_MATCH', 'PFX018');
				}

				key = this.signKey.privateDecrypt(recipientInfo.encryptedKey, {
					padding: recipientInfo.keyEncryptionAlgo.padding
				});
				break;
			case 'DSA':
			case 'KCDSA':
			case 'ECDSA':
			case 'ECKCDSA':
				throw jCastle.exception("UNSUPPORTED_PFX_STRUCTURE", 'PFX019');
		}

		return key;
	}

	_parseEnvelopedData(sequence)
	{
		var idx = 0;

		// version
		var version = sequence.items[idx].intVal;
		idx++;

		// originatorInfo, [0] IMPLICIT, optional
		var originatorInfo = null;
/*
      OriginatorInfo ::= SEQUENCE {
        certs [0] IMPLICIT CertificateSet OPTIONAL,
        crls [1] IMPLICIT RevocationInfoChoices OPTIONAL }
*/
		if ('tagClass' in sequence.items[idx] &&
			sequence.items[idx].tagClass == jCastle.asn1.tagClassContextSpecific) {
			// to do: parsing
			jCastle.assert(sequence.items[idx].type, 0x00, 'INVALID_PFX_FORMAT', 'PFX020');
			originatorInfo = {};

			originatorInfoSequence = sequence.items[idx].items;
			var oidx = 0;

			jCastle.assert(originatorInfoSequence.items[oidx].tagClass, jCastle.asn1.tagClassContextSpecific, 'INVALID_PFX_FORMAT', 'PFX021');

			if (originatorInfoSequence.items[oidx].type == 0x00) {
				// certs
				var certsSequence = originatorInfoSequence.items[oidx].items;
				var certs = [];
				for (var i = 0; i < certsSequenece.items.length; i++) {
					var certInfo = new jCastle.certificate().parse(certsSequence.items[i], 'asn1', jCastle.certificate.typeCRT);
					certs.push(certInfo);
				}
				originatorInfo.certs = certs;
				oidx++;
			}
			if (originatorInfoSequence.items[oidx].type == 0x01) {
				// crls
				var crlsSequence = originatorInfoSequence.items[oidx].items;
				var crls = [];
				for (var i = 0; i < crlsSequence.items.length; i++) {
					var crlInfo = new jCastle.certificate().parse(crlsSequence.items[i], 'asn1', jCastle.certificate.typeCRL);
					crls.push(crlInfo);
				}
				originatorInfo.crls = crls;
			}

			idx++;
		}

	// recipientInfos, MUST have at least one
/*
      RecipientInfo ::= CHOICE {
        ktri KeyTransRecipientInfo,
        kari [1] KeyAgreeRecipientInfo,
        kekri [2] KEKRecipientInfo,
        pwri [3] PasswordRecipientinfo,
        ori [4] OtherRecipientInfo }
*/
		var recipientInfos = [];
		for (var i = 0; i < sequence.items[idx].items.length; i++) {
			var riSequence = sequence.items[idx].items[i];
			var ri = {};
			ri.version = riSequence.items[0].intVal;
			
			switch (ri.version) {
				case 0: 
					if (riSequence.items[1].type == jCastle.asn1.tagSequence &&
						riSequence.items[1].items.length == 2 &&
						riSequence.items[1].items[1].type == jCastle.asn1.tagInteger) {
						ri.type = 'keyTransRecipientInfo';
					} else {
						ri.type = 'passwordRecipientInfo';
					}
					break;
				case 2: ri.type = 'keyTransRecipientInfo'; break;
				case 3: ri.type = 'keyAgreeRecipientInfo'; break;
				case 4: ri.type = 'kekRecipientInfo'; break;
			}

			switch (ri.type) {
				case 'keyTransRecipientInfo':
/*
      KeyTransRecipientInfo ::= SEQUENCE {
        version CMSVersion,  -- always set to 0 or 2
        rid RecipientIdentifier,
        keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
        encryptedKey EncryptedKey }

      RecipientIdentifier ::= CHOICE {
        issuerAndSerialNumber IssuerAndSerialNumber,
        subjectKeyIdentifier [0] SubjectKeyIdentifier }

      version is the syntax version number.  If the RecipientIdentifier
      is the CHOICE issuerAndSerialNumber, then the version MUST be 0.
      If the RecipientIdentifier is subjectKeyIdentifier, then the
      version MUST be 2.
*/
					if (ri.version == 0) { // issuerAndSerialNumber
						ri.issuer = jCastle.certificate.asn1.directoryName.parse(riSequence.items[1].items[0]);
						ri.serialNumber = riSequence.items[1].items[1].intVal;
					} else { // ri.version == 2, not tested!
						//ri.subjectKeyIdentifier = jCastle.certificate.extensions["subjectKeyIdentifier"].parse(riSequence.items[1].items[0]);
						// octet string
						ri.subjectKeyIdentifier = riSequence.items[1].items[0].value;
					}

					// keyEncryptionAlgorithm
					ri.keyEncryptionAlgo = jCastle.certificate.asn1.encryptionInfo.parse(riSequence.items[2]);
					ri.encryptedKey = Buffer.from(riSequence.items[3].value, 'latin1');
					break;		

				case 'keyAgreeRecipientInfo':
/*
      KeyAgreeRecipientInfo ::= SEQUENCE {
        version CMSVersion,  -- always set to 3
        originator [0] EXPLICIT OriginatorIdentifierOrKey,
        ukm [1] EXPLICIT UserKeyingMaterial OPTIONAL,
        keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
        recipientEncryptedKeys RecipientEncryptedKeys }

      OriginatorIdentifierOrKey ::= CHOICE {
        issuerAndSerialNumber IssuerAndSerialNumber,
        subjectKeyIdentifier [0] SubjectKeyIdentifier,
        originatorKey [1] OriginatorPublicKey }

      OriginatorPublicKey ::= SEQUENCE {
        algorithm AlgorithmIdentifier,
        publicKey BIT STRING }

      RecipientEncryptedKeys ::= SEQUENCE OF RecipientEncryptedKey

      RecipientEncryptedKey ::= SEQUENCE {
        rid KeyAgreeRecipientIdentifier,
        encryptedKey EncryptedKey }

      KeyAgreeRecipientIdentifier ::= CHOICE {
        issuerAndSerialNumber IssuerAndSerialNumber,
        rKeyId [0] IMPLICIT RecipientKeyIdentifier }

      RecipientKeyIdentifier ::= SEQUENCE {
        subjectKeyIdentifier SubjectKeyIdentifier,
        date GeneralizedTime OPTIONAL,
        other OtherKeyAttribute OPTIONAL }

      SubjectKeyIdentifier ::= OCTET STRING
*/
				case 'kekRecipientInfo':
/*
      KEKRecipientInfo ::= SEQUENCE {
        version CMSVersion,  -- always set to 4
        kekid KEKIdentifier,
        keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
        encryptedKey EncryptedKey }

      KEKIdentifier ::= SEQUENCE {
        keyIdentifier OCTET STRING,
        date GeneralizedTime OPTIONAL,
        other OtherKeyAttribute OPTIONAL }
*/
				case 'passwordRecipientInfo':
/*
      PasswordRecipientInfo ::= SEQUENCE {
        version CMSVersion,   -- Always set to 0
        keyDerivationAlgorithm [0] KeyDerivationAlgorithmIdentifier
                                     OPTIONAL,
        keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
        encryptedKey EncryptedKey }
*/
				default:
/*
      OtherRecipientInfo ::= SEQUENCE {
        oriType OBJECT IDENTIFIER,
        oriValue ANY DEFINED BY oriType }

   The fields of type OtherRecipientInfo have the following meanings:

      oriType identifies the key management technique.

      oriValue contains the protocol data elements needed by a recipient
      using the identified key management technique.
*/
					throw jCastle.exception("UNSUPPORTED_PFX_STRUCTURE", 'PFX022');
			}
		
			recipientInfos.push(ri);
		}
		idx++;

		// encryptedContentInfo
/*
      EncryptedContentInfo ::= SEQUENCE {
        contentType ContentType,
        contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
        encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL }

      EncryptedContent ::= OCTET STRING
*/
/*
SEQUENCE(3 elem)
	OBJECT IDENTIFIER							1.2.840.113549.1.7.1  -- data
	SEQUENCE(2 elem)
		OBJECT IDENTIFIER						2.16.840.1.101.3.4.1.2 -- aes-128-CBC
		OCTET STRING(16 byte)					9E8D877D8003A552859DC6F3B9DFC752
	[0](3 elem)
		OCTET STRING(1024 byte)					D6E88BA9EAEA9D0D04C4682D4E85117472EF43CFB47206ECCA7F9E3180258E5C339D…
		OCTET STRING(1024 byte)					7B8BF701A533B13A77C85F02DEC71CEB7E6D9A0B49EAE7D21641718304701C6B8875…
		OCTET STRING(96 byte)					A3D6FC257A49D9AB20B35A9FBAD10952B50B5AD6A8B0ACB8272473CF3DA9A502C8B6FE…
*/
		var seq = sequence.items[idx];
		jCastle.assert(jCastle.oid.getName(seq.items[0].value), 'data', 'INVALID_PFX_FORMAT', 'PFX023');

		var algo = jCastle.oid.getName(seq.items[1].items[0].value);
		var algoInfo = jCastle.pbe.getAlgorithmInfo(algo);
		var iv = null;
		if (seq.items[1].items.length == 2) {
			iv = Buffer.from(seq.items[1].items[1].value, 'latin1');
		}
		var encryptedContent = this._combineData(seq.items[2]);

		var encryptedContentInfo = {
			contentType: 'data',
			contentEncryptionAlgo: {
				algo: algo,
				algoInfo: algoInfo,
				iv: iv
			},
			encryptedContent: Buffer.from(encryptedContent, 'latin1')
		};
		idx++;

		var unprotectedAttrs = null;

		if (typeof sequence.items[idx] != 'undefined' &&
			'tagClass' in sequence.items[idx] && sequence.items[idx].tagClass == jCastle.asn1.tagClassContextSpecific) { // [1] IMPLICIT optional
			jCastle.assert(sequence.items[idx].type, 0x01, 'INVALID_PFX_FORMAT', 'PFX024');

			unprotectedAttrs = this._parseUnprotectedAttrs(sequence.items[idx]);
		}

		var envelopedInfo = {};
		envelopedInfo.version = version;
		if (originatorInfo) envelopedInfo.originatorInfo = originatorInfo;
		envelopedInfo.recipientInfos = recipientInfos;
		envelopedInfo.encryptedContentInfo = encryptedContentInfo;
		if (unprotectedAttrs) envelopedInfo.unprotectedAttrs = unprotectedAttrs;

		return envelopedInfo;
	}

	_parseUnprotectedAttrs(implicit)
	{
/*
[0](3 elem)
	SEQUENCE(2 elem)
		OBJECT IDENTIFIER															1.2.840.113549.1.9.3  -- contentType
		SET(1 elem)
			OBJECT IDENTIFIER														1.2.840.113549.1.7.1  -- data
	SEQUENCE(2 elem)
		OBJECT IDENTIFIER															1.2.840.113549.1.9.5  -- signingTime
		SET(1 elem)
			UTCTime																	2016-06-22 06:10:54 UTC
	SEQUENCE(2 elem)
		OBJECT IDENTIFIER															1.2.840.113549.1.9.4  -- messageDigest
		SET(1 elem)
			OCTET STRING(32 byte)													DB083C86F67DC67F4A44F74D74A7414E11CE38C8F9F7FB8DDA1AF0EF9052A16B
*/
		var attrs = {};

		for (var i = 0; i < implicit.items.length; i++) {
			var attrSequence = implicit.items[i];
			var name = jCastle.oid.getName(attrSequence.items[0].value);
			if (!name) throw jCastle.exception('INVALID_PFX_FORMAT', 'PFX025');

			switch (name) {
				case 'contentType':
/*
11.  Useful Attributes

   This section defines attributes that may be used with signed-data,
   enveloped-data, encrypted-data, or authenticated-data.  The syntax of
   Attribute is compatible with X.501 [X.501-88] and RFC 5280 [PROFILE].
   Some of the attributes defined in this section were originally
   defined in PKCS #9 [PKCS#9]; others were originally defined in a
   previous version of this specification [CMS1].  The attributes are
   not listed in any particular order.

   Additional attributes are defined in many places, notably the S/MIME
   Version 3.1 Message Specification [MSG3.1] and the Enhanced Security
   Services for S/MIME [ESS], which also include recommendations on the
   placement of these attributes.

11.1.  Content Type

   The content-type attribute type specifies the content type of the
   ContentInfo within signed-data or authenticated-data.  The content-
   type attribute type MUST be present whenever signed attributes are
   present in signed-data or authenticated attributes present in
   authenticated-data.  The content-type attribute value MUST match the
   encapContentInfo eContentType value in the signed-data or
   authenticated-data.

   The content-type attribute MUST be a signed attribute or an
   authenticated attribute; it MUST NOT be an unsigned attribute,
   unauthenticated attribute, or unprotected attribute.

   The following object identifier identifies the content-type
   attribute:

      id-contentType OBJECT IDENTIFIER ::= { iso(1) member-body(2)
          us(840) rsadsi(113549) pkcs(1) pkcs9(9) 3 }

   Content-type attribute values have ASN.1 type ContentType:

      ContentType ::= OBJECT IDENTIFIER

   Even though the syntax is defined as a SET OF AttributeValue, a
   content-type attribute MUST have a single attribute value; zero or
   multiple instances of AttributeValue are not permitted.

   The SignedAttributes and AuthAttributes syntaxes are each defined as
   a SET OF Attributes.  The SignedAttributes in a signerInfo MUST NOT
   include multiple instances of the content-type attribute.  Similarly,
   the AuthAttributes in an AuthenticatedData MUST NOT include multiple
   instances of the content-type attribute.
*/
					attrs[name] = jCastle.oid.getName(attrSequence.items[1].items[0].value);
					break;
				case 'messageDigest':
/*
11.2.  Message Digest

   The message-digest attribute type specifies the message digest of the
   encapContentInfo eContent OCTET STRING being signed in signed-data
   (see Section 5.4) or authenticated in authenticated-data (see Section
   9.2).  For signed-data, the message digest is computed using the
   signer's message digest algorithm.  For authenticated-data, the
   message digest is computed using the originator's message digest
   algorithm.

   Within signed-data, the message-digest signed attribute type MUST be
   present when there are any signed attributes present.  Within
   authenticated-data, the message-digest authenticated attribute type
   MUST be present when there are any authenticated attributes present.

   The message-digest attribute MUST be a signed attribute or an
   authenticated attribute; it MUST NOT be an unsigned attribute,
   unauthenticated attribute, or unprotected attribute.

   The following object identifier identifies the message-digest
   attribute:

      id-messageDigest OBJECT IDENTIFIER ::= { iso(1) member-body(2)
          us(840) rsadsi(113549) pkcs(1) pkcs9(9) 4 }

   Message-digest attribute values have ASN.1 type MessageDigest:

      MessageDigest ::= OCTET STRING

   A message-digest attribute MUST have a single attribute value, even
   though the syntax is defined as a SET OF AttributeValue.  There MUST
   NOT be zero or multiple instances of AttributeValue present.

   The SignedAttributes syntax and AuthAttributes syntax are each
   defined as a SET OF Attributes.  The SignedAttributes in a signerInfo
   MUST include only one instance of the message-digest attribute.
   Similarly, the AuthAttributes in an AuthenticatedData MUST include
   only one instance of the message-digest attribute.
*/
				case 'signingTime':
/*
11.3.  Signing Time

   The signing-time attribute type specifies the time at which the
   signer (purportedly) performed the signing process.  The signing-time
   attribute type is intended for use in signed-data.

   The signing-time attribute MUST be a signed attribute or an
   authenticated attribute; it MUST NOT be an unsigned attribute,
   unauthenticated attribute, or unprotected attribute.

   The following object identifier identifies the signing-time
   attribute:

      id-signingTime OBJECT IDENTIFIER ::= { iso(1) member-body(2)
          us(840) rsadsi(113549) pkcs(1) pkcs9(9) 5 }

   Signing-time attribute values have ASN.1 type SigningTime:

      SigningTime ::= Time

      Time ::= CHOICE {
        utcTime UTCTime,
        generalizedTime GeneralizedTime }

   Note: The definition of Time matches the one specified in the 1997
   version of X.509 [X.509-97].

   Dates between 1 January 1950 and 31 December 2049 (inclusive) MUST be
   encoded as UTCTime.  Any dates with year values before 1950 or after
   2049 MUST be encoded as GeneralizedTime.

   UTCTime values MUST be expressed in Coordinated Universal Time
   (formerly known as Greenwich Mean Time (GMT) and Zulu clock time) and
   MUST include seconds (i.e., times are YYMMDDHHMMSSZ), even where the
   number of seconds is zero.  Midnight MUST be represented as
   "YYMMDD000000Z".  Century information is implicit, and the century
   MUST be determined as follows:

      Where YY is greater than or equal to 50, the year MUST be
      interpreted as 19YY; and

      Where YY is less than 50, the year MUST be interpreted as 20YY.

   GeneralizedTime values MUST be expressed in Coordinated Universal
   Time and MUST include seconds (i.e., times are YYYYMMDDHHMMSSZ), even
   where the number of seconds is zero.  GeneralizedTime values MUST NOT
   include fractional seconds.

   A signing-time attribute MUST have a single attribute value, even
   though the syntax is defined as a SET OF AttributeValue.  There MUST
   NOT be zero or multiple instances of AttributeValue present.

   The SignedAttributes syntax and the AuthAttributes syntax are each
   defined as a SET OF Attributes.  The SignedAttributes in a signerInfo
   MUST NOT include multiple instances of the signing-time attribute.
   Similarly, the AuthAttributes in an AuthenticatedData MUST NOT
   include multiple instances of the signing-time attribute.

   No requirement is imposed concerning the correctness of the signing
   time, and acceptance of a purported signing time is a matter of a
   recipient's discretion.  It is expected, however, that some signers,
   such as time-stamp servers, will be trusted implicitly.
*/
					attrs[name] = attrSequence.items[1].items[0].value;
					break;
				case 'countersignature':
/*
11.4.  Countersignature

   The countersignature attribute type specifies one or more signatures
   on the contents octets of the signature OCTET STRING in a SignerInfo
   value of the signed-data.  That is, the message digest is computed
   over the octets comprising the value of the OCTET STRING, neither the
   tag nor length octets are included.  Thus, the countersignature
   attribute type countersigns (signs in serial) another signature.

   The countersignature attribute MUST be an unsigned attribute; it MUST
   NOT be a signed attribute, an authenticated attribute, an
   unauthenticated attribute, or an unprotected attribute.

   The following object identifier identifies the countersignature
   attribute:

      id-countersignature OBJECT IDENTIFIER ::= { iso(1) member-body(2)
          us(840) rsadsi(113549) pkcs(1) pkcs9(9) 6 }

   Countersignature attribute values have ASN.1 type Countersignature:

      Countersignature ::= SignerInfo

   Countersignature values have the same meaning as SignerInfo values
   for ordinary signatures, except that:

   1.  The signedAttributes field MUST NOT contain a content-type
       attribute; there is no content type for countersignatures.

   2.  The signedAttributes field MUST contain a message-digest
       attribute if it contains any other attributes.

   3.  The input to the message-digesting process is the contents octets
       of the DER encoding of the signatureValue field of the SignerInfo
       value with which the attribute is associated.

   A countersignature attribute can have multiple attribute values.  The
   syntax is defined as a SET OF AttributeValue, and there MUST be one
   or more instances of AttributeValue present.

   The UnsignedAttributes syntax is defined as a SET OF Attributes.  The
   UnsignedAttributes in a signerInfo may include multiple instances of
   the countersignature attribute.

   A countersignature, since it has type SignerInfo, can itself contain
   a countersignature attribute.  Thus, it is possible to construct an
   arbitrarily long series of countersignatures.
*/
				default:
					throw jCastle.exception('UNSUPPORTED_PFX_STRUCTURE', 'PFX026');
			}
		}

		return attrs;
	}
/*
	_getEncryptedInfo(pbe_info)
	{
		var pfxPbeInfo = {};

		switch(pbe_info.type) {
			case 'pkcs5PBKDF2':
				pfxPbeInfo = {
					algo: pbe_info.algo,
					type: pbe_info.type,
					prfHash: pbe_info.prfHash,
					salt: pbe_info.salt,
					iterations: pbe_info.iterations
				};
				if ('keySize' in pbe_info && pbe_info.keySize > 0) pfxPbeInfo.keySize = pbe_info.keySize;
				if ('iv' in pbe_info) pfxPbeInfo.iv = pbe_info.iv;
				break;
			case 'pkcs5PBKDF1':
			case 'pkcs12DeriveKey':
				pfxPbeInfo = {
					algo: pbe_info.algo,
					type: pbe_info.type,
					salt: pbe_info.salt,
					iterations: pbe_info.iterations
				};
				break;
			default:
				throw jCastle.exception("UNKNOWN_PBE_TYPE", 'PFX027');
		}
		return pfxPbeInfo;
	}
*/
	_parseMacData(macDataSequence, authSafeBuf)
	{
//console.log(jCastle.encoding.hex.encode(authSafeBuf));

		var salt = Buffer.from(macDataSequence.items[1].value, 'latin1');
		var iterations = typeof macDataSequence.items[2] != 'undefined' ? macDataSequence.items[2].intVal : 1;
		var hash_algo = jCastle.digest.getValidAlgoName(jCastle.oid.getName(macDataSequence.items[0].items[0].items[0].value));
		var hmac_check = Buffer.from(macDataSequence.items[0].items[1].value, 'latin1');
		var key = jCastle.kdf.pkcs12DeriveKey(this.password, salt, iterations, 3, jCastle.digest.getDigestLength(hash_algo), hash_algo);
		var hmac = new jCastle.hmac(hash_algo).start({ key: key });

		// console.log('pfx._parseMacData()');
		// console.log('password: ', this.password);
		// console.log('salt: ', salt);
		// console.log('iterations: ', iterations);
		// console.log('hash algo: ', hash_algo);
		// console.log('hmac check: ', hmac_check);
		// console.log('key: ', key);

		if (!Buffer.isBuffer(authSafeBuf)) authSafeBuf = Buffer.from(authSafeBuf, 'latin1');

		var result = hmac.update(authSafeBuf).finalize();

		// console.log('hmac result: ', result);

		var v = result.equals(hmac_check);

		// if (v) {
		// 	console.log('hmac check is ok!');
		// } else {
		// 	console.log('hmac is not right! maybe wrong password.');
		// }

		var macInfo = {
			algo: hash_algo,
			salt: salt,
			iterations: iterations,
			data: hmac_check,
			check: v
		};

		return macInfo;
	}

	_parseSafeBag(safeBagSequence)
	{
		var bagId = jCastle.oid.getName(safeBagSequence.items[0].value);

/*
 SafeBag ::= SEQUENCE {
     bagId         BAG-TYPE.&id ({PKCS12BagSet}),
     bagValue      [0] EXPLICIT BAG-TYPE.&Type({PKCS12BagSet}{@bagId}),
     bagAttributes SET OF PKCS12Attribute OPTIONAL
 }

 -- ============================
 -- Bag types
 -- ============================

 keyBag BAG-TYPE ::=
     {KeyBag              IDENTIFIED BY {bagtypes 1}}
 pkcs8ShroudedKeyBag BAG-TYPE ::=
     {PKCS8ShroudedKeyBag IDENTIFIED BY {bagtypes 2}}
 certBag BAG-TYPE ::=
     {CertBag             IDENTIFIED BY {bagtypes 3}}
 crlBag BAG-TYPE ::=
     {CRLBag              IDENTIFIED BY {bagtypes 4}}
 secretBag BAG-TYPE ::=
     {SecretBag           IDENTIFIED BY {bagtypes 5}}
 safeContentsBag BAG-TYPE ::=
     {SafeContents        IDENTIFIED BY {bagtypes 6}}

 PKCS12BagSet BAG-TYPE ::= {
     keyBag |
     pkcs8ShroudedKeyBag |
     certBag |
     crlBag |
     secretBag |
     safeContentsBag,
     ... -- For future extensions
 }

 BAG-TYPE ::= TYPE-IDENTIFIER

 -- KeyBag
 KeyBag ::= PrivateKeyInfo

 -- Shrouded KeyBag
 PKCS8ShroudedKeyBag ::= EncryptedPrivateKeyInfo

 -- CertBag
 CertBag ::= SEQUENCE {
     certId    BAG-TYPE.&id   ({CertTypes}),
     certValue [0] EXPLICIT BAG-TYPE.&Type ({CertTypes}{@certId})
 }

 x509Certificate BAG-TYPE ::=
     {OCTET STRING IDENTIFIED BY {certTypes 1}}
     -- DER-encoded X.509 certificate stored in OCTET STRING
 sdsiCertificate BAG-TYPE ::=
     {IA5String IDENTIFIED BY {certTypes 2}}
     -- Base64-encoded SDSI certificate stored in IA5String

 CertTypes BAG-TYPE ::= {
     x509Certificate |
     sdsiCertificate,
     ... -- For future extensions
 }

 -- CRLBag
 CRLBag ::= SEQUENCE {
     crlId     BAG-TYPE.&id ({CRLTypes}),
     crltValue [0] EXPLICIT BAG-TYPE.&Type ({CRLTypes}{@crlId})
 }

 x509CRL BAG-TYPE ::=
     {OCTET STRING IDENTIFIED BY {crlTypes 1}}
     -- DER-encoded X.509 CRL stored in OCTET STRING

 CRLTypes BAG-TYPE ::= {
     x509CRL,
     ... -- For future extensions
 }

 -- Secret Bag
 SecretBag ::= SEQUENCE {
     secretTypeId  BAG-TYPE.&id ({SecretTypes}),
     secretValue   [0] EXPLICIT BAG-TYPE.&Type ({SecretTypes}
                                                {@secretTypeId})
 }

 SecretTypes BAG-TYPE ::= {
     ... -- For future extensions
 }
 */

		var bagContent, pbe_info, subType, der;

		switch (bagId) {
			case 'keyBag':
/*
SEQUENCE(2 elem)
	OBJECT IDENTIFIER										1.2.840.113549.1.12.10.1.1  -- keyBag
	[0](1 elem)
		SEQUENCE(3 elem)
			INTEGER0
			SEQUENCE(2 elem)
				OBJECT IDENTIFIER							1.2.840.113549.1.1.1  -- rsaEncryption
				NULL
			OCTET STRING(1 elem)
				SEQUENCE(9 elem)
					INTEGER									0
					INTEGER(2048 bit)						286093241866849712004460914154496840984222441819662416691202949065049…
					INTEGER									65537
					INTEGER(2048 bit)						266435981569209840585932640104148194037429734562480368956938535380567…
					INTEGER(1024 bit)						177873172927109931538968188574191405271114869627825502415916775271800…
					INTEGER(1024 bit)						160841141561064371523763071645921854446629678940298963533877439500510…
					INTEGER(1024 bit)						158405021052502312347839226054657783805229843461836941315631882325455…
					INTEGER(1023 bit)						737929939493428677384760980552905735615188547900713983785743450402269…
					INTEGER(1023 bit)						663042909414007878995513477868946331797501234466899680305480466335559…
*/
				var pki = new jCastle.pki();
				//pki.parse(safeBagSequence.items[1].items[0], null, 'asn1', 'private');
				pki.parse(safeBagSequence.items[1].items[0], null);
				bagContent = pki.getPrivateKeyInfo();
				break;
			case 'pkcs8ShroudedKeyBag':
/*
SEQUENCE(3 elem)
	OBJECT IDENTIFIER										1.2.840.113549.1.12.10.1.2  -- pkcs8ShroudedKeyBag
	[0](1 elem)
		SEQUENCE(2 elem)
			SEQUENCE(2 elem)
				OBJECT IDENTIFIER							1.2.840.113549.1.5.13 -- pkcs5PBES2
					SEQUENCE(2 elem)
					SEQUENCE(2 elem)
						OBJECT IDENTIFIER					1.2.840.113549.1.5.12 -- pkcs5PBKDF2
						SEQUENCE(3 elem)
							OCTET STRING(64 byte)			31BD85E29B12983984BF78FD7C05F007D7934D8CB5DE38DEE070E7EA805CD513AB734A…
							INTEGER							100000
							SEQUENCE(2 elem)
								OBJECT IDENTIFIER			1.2.840.113549.2.7  -- hmacWithSHA1
								NULL
					SEQUENCE(2 elem)
						OBJECT IDENTIFIER					2.16.840.1.101.3.4.1.2 -- aes-128-CBC
						OCTET STRING(16 byte)				C9EC4391F732B47D63218067CF460BC5
			OCTET STRING(2 elem)
				OCTET STRING(1024 byte)						40FA447F33481223A2C82643B72C664AEE14C624A39974FBFB5CE33A8979180D69CF…
				OCTET STRING(224 byte)						18277252352C3F118C42BB9A940788FD04C9397C255C3FABD446F1A8AABA9815549D6…
*/
/*
SEQUENCE(3 elem)
	OBJECT IDENTIFIER						1.2.840.113549.1.12.10.1.2  -- pkcs8ShroudedKeyBag
	[0](1 elem)
		SEQUENCE(2 elem)
			SEQUENCE(2 elem)
				OBJECT IDENTIFIER			1.2.840.113549.1.12.1.3  -- pbeWithSHAAnd3-KeyTripleDES-CBC
				SEQUENCE(2 elem)
					OCTET STRING(8 byte)	0776107D38B880C0
					INTEGER					2048
			OCTET STRING(1224 byte)			99B4E119DF9174D01F27D5C0A1A2723E225A41A6636FFA8965B2948DB6AF7372D9B9…
*/
				pbe_info = jCastle.pbe.asn1.pbeInfo.parse(safeBagSequence.items[1].items[0].items[0]);
				var enc_data = this._combineData(safeBagSequence.items[1].items[0].items[1]);

				der = this._pbeDecrypt(pbe_info, enc_data);

				var pki = new jCastle.pki();
				//pki.parse(der, null, 'der', 'private');
				pki.parse(der, null);
				bagContent = pki.getPrivateKeyInfo();
				break;
			case 'certBag':
/*
4.2.3.  The CertBag Type

   A CertBag contains a certificate of a certain type.  Object
   identifiers are used to distinguish between different certificate
   types.

   CertBag ::= SEQUENCE {
       certId      BAG-TYPE.&id   ({CertTypes}),
       certValue   [0] EXPLICIT BAG-TYPE.&Type ({CertTypes}{@certId})
   }

   x509Certificate BAG-TYPE ::=
       {OCTET STRING IDENTIFIED BY {certTypes 1}}
       -- DER-encoded X.509 certificate stored in OCTET STRING
   sdsiCertificate BAG-TYPE ::=
       {IA5String IDENTIFIED BY {certTypes 2}}
       -- Base64-encoded SDSI certificate stored in IA5String

   CertTypes BAG-TYPE ::= {
       x509Certificate |
       sdsiCertificate,
       ... -- For future extensions
   }
*/
/*
SEQUENCE(3 elem)
	OBJECT IDENTIFIER														1.2.840.113549.1.12.10.1.3  -- certBag
	[0](1 elem)
		SEQUENCE(2 elem)
			OBJECT IDENTIFIER												1.2.840.113549.1.9.22.1  -- x509Certificate
			[0](1 elem)
				OCTET STRING(1 elem)
					SEQUENCE(3 elem)
						SEQUENCE(6 elem)
							INTEGER(64 bit)									15180685160134022708
							SEQUENCE(2 elem)
								OBJECT IDENTIFIER							1.2.840.113549.1.1.11  -- sha256WithRSAEncryption
								NULL
							SEQUENCE(6 elem)
								SET(1 elem)
									SEQUENCE(2 elem)
										OBJECT IDENTIFIER					2.5.4.6
										PrintableString						KR
								SET(1 elem)
									SEQUENCE(2 elem)
										OBJECT IDENTIFIER					2.5.4.8
										UTF8String							Chung-cheong
								SET(1 elem)
									SEQUENCE(2 elem)
										OBJECT IDENTIFIER					2.5.4.7
										UTF8String							Cheong-ju
										...
*/
				subType = jCastle.oid.getName(safeBagSequence.items[1].items[0].items[0].value);
				var cert = new jCastle.certificate();
				var cert_info;

				if (subType == 'x509Certificate') {				
					cert_info = cert.parse(safeBagSequence.items[1].items[0].items[1].items[0].value, 'asn1', jCastle.certificate.typeCRT);
				} else if (subType == 'sdsiCertificate') {
					//der = jCastle.base64.decode(safeBagSequence.items[1].items[0].items[1].items[0].value, true);
					der = Buffer.from(safeBagSequence.items[1].items[0].items[1].items[0].value, 'base64').toString('latin1');
					cert_info = cert.parse(der, 'der', jCastle.certificate.typeCRT);
				} else {
					throw jCastle.exception("UNSUPPORTED_PFX_STRUCTURE", 'PFX028');
				}
				bagContent = cert_info;
				break;
			case 'crlBag':
/*
4.2.4.  The CRLBag Type

   A CRLBag contains a Certificate Revocation List (CRL) of a certain
   type.  Object identifiers are used to distinguish between different
   CRL types.

   CRLBag ::= SEQUENCE {
       crlId      BAG-TYPE.&id  ({CRLTypes}),
       crlValue  [0] EXPLICIT BAG-TYPE.&Type ({CRLTypes}{@crlId})
   }

   x509CRL BAG-TYPE ::=
       {OCTET STRING IDENTIFIED BY {crlTypes 1}}
       -- DER-encoded X.509 CRL stored in OCTET STRING

   CRLTypes BAG-TYPE ::= {
       x509CRL,
       ... -- For future extensions
   }
*/
				var cert = new jCastle.certificate();
				cert_info = cert.parse(safeBagSequence.items[1].items[0].value, 'asn1', jCastle.certificate.typeCRL);
				bagContent = cert_info;
				break;
			case 'secretBag':
/*
4.2.5.  The SecretBag Type

   Each of the user's miscellaneous personal secrets is contained in an
   instance of SecretBag, which holds an object identifier-dependent
   value.  Note that a SecretBag contains only one secret.

   SecretBag ::= SEQUENCE {
       secretTypeId   BAG-TYPE.&id ({SecretTypes}),
       secretValue    [0] EXPLICIT BAG-TYPE.&Type ({SecretTypes}
                          {@secretTypeId})
   }

   SecretTypes BAG-TYPE ::= {
       ... -- For future extensions
   }

   Implementers can add values to this set at their own discretion.
*/
			case 'safeContentsBag':
/*
4.2.6.  The SafeContents Type

   The sixth type of bag that can be held in a SafeBag is a
   SafeContents.  This recursive structure allows for arbitrary nesting
   of multiple KeyBags, PKCS8ShroudedKeyBags, CertBags, CRLBags, and
   SecretBags within the top-level SafeContents.
*/
			default:
				throw jCastle.exception("UNSUPPORTED_PFX_STRUCTURE", 'PFX029');
		}

		// pkcs#12 attributes
		var attributes;
		if (safeBagSequence.items.length == 3) {
			attributes = this._parseAttributes(safeBagSequence.items[2]); // SET
		}

		var safeBag = {
			bagId: bagId,
			content: bagContent
		};

		if (attributes) safeBag.attributes = attributes;

		if (subType) {
			safeBag.subType = subType;
		}

		if (bagId == 'pkcs8ShroudedKeyBag') {
			//safeBag.encryptedInfo = this._getEncryptedInfo(pbe_info);
			safeBag.encryptedInfo = pbe_info;
		}

		if (bagId == 'pkcs8ShroudedKeyBag') {
			//safeBag.der = der;
			safeBag.buffer = Buffer.from(der, 'latin1');
		} else {
			//safeBag.der = safeBagSequence.der;
			safeBag.buffer = safeBagSequence.buffer;
		}

		return safeBag;
	}

	_combineData(explicit)
	{
		var enc_data = '';
		if (explicit.constructed) {
			for (var j = 0; j < explicit.items.length; j++) {
				enc_data += explicit.items[j].value;
			}
		} else {
			enc_data = explicit.value;
		}
		return enc_data;
	}

	_pbeDecrypt(pbe_info, enc_data)
	{
		var der;
		switch (pbe_info.type) {
			case 'pkcs5PBKDF2':			
				der = jCastle.pbe.pbes2.decrypt(pbe_info, this.password, enc_data);
				break;
			case 'pkcs5PBKDF1':
				der = jCastle.pbe.pbes1.decrypt(pbe_info, this.password, enc_data);
				break;
			case 'pkcs12DeriveKey':
				der = jCastle.pbe.pkcs12pbes.decrypt(pbe_info, this.password, enc_data);
				break;
			default:
				throw jCastle.exception("UNKNOWN_PBE_TYPE", 'PFX030');
		}

		return der;
	}

/*
		encryptedInfo: {
			algo: "pbeWithSHAAnd40BitRC2-CBC",
			kdfInfo: {
				salt: salt_value, // if not given it will be generated.
				iterations: 2048
			}
		},
*/
	_getPbeInfo(encrypted_info)
	{
		encrypted_info = encrypted_info || {};
//console.log(encrypted_info);

		if (!('algo' in encrypted_info)) {
			throw jCastle.exception('ALGORITHM_NOT_SET', 'PFX031');
		}

		var algo = encrypted_info.algo;
		var salt, iv;
		var kdf_info = encrypted_info.kdfInfo || {};
		var params = encrypted_info.params || {};
		var pbe_info;

		if ('salt' in kdf_info && kdf_info.salt) {
			salt = Buffer.from(kdf_info.salt, 'latin1');
		} else {
			var len = 'saltLength' in kdf_info ? kdf_info.saltLength : 8;
			salt = new jCastle.prng().nextBytes(len);
		}

		var iterations = 'iterations' in kdf_info ? kdf_info.iterations : 2048;

		if (algo.indexOf('pbeWith') === -1 && algo.indexOf('PBE-') === -1) {

	//		console.log('pkcs#5 v2.0 algorithm');

			var prf_hash = 'sha-1';

			var key_size = 0;
			if ('keySize' in kdf_info) {
				key_size = kdf_info.keySize;
			}

			var algo_info = jCastle.pbe.getAlgorithmInfo(algo.toLowerCase());

			if (algo_info.algo == 'rc2' && key_size == 0) {
				// rc2 default key size
				key_size = 16;
			}

			if ('prfHash' in kdf_info) {
				prf_hash = kdf_info.prfHash.toLowerCase();
			} else if ('prf' in kdf_info) {
				var flag = false;
				if (jCastle.oid.getOID(kdf_info.prf)) {
					var m = /hmacWith([a-z0-9\-]+)/i.exec(kdf_info.prf);
					if (m) {
						prf_hash = m[1];
						flag = true;
					}
				}

				if (!flag) {
					throw jCastle.exception("UNSUPPORTED_PRF", 'PFX032');
				}
			}

			if ('iv' in params) {
				iv = Buffer.from(params.iv, 'latin1');
			}
			
			pbe_info = {
				algo: algo,
				type: 'pkcs5PBKDF2',
				algoInfo: algo_info,
				kdfInfo: {
					prfHash: prf_hash,
					salt: salt,
					iterations: iterations,
					keySize: key_size
				},
				params: {
					iv: iv,
					keySize: key_size
				}
			};
		} else {
			var algo_info = jCastle.pbe.getPbeAlgorithmInfo(algo);
			if (!algo_info) {
				throw jCastle.exception("UNSUPPORTED_ALGO_OID", 'PFX033');
			}

			var pbe_type = algo_info.type == 'pkcs5' ? 'pkcs5PBKDF1' : 'pkcs12DeriveKey';

			pbe_info = {
				algo: algo,
				type: pbe_type,
				algoInfo: algo_info,
				kdfInfo: {
					salt: salt,
					iterations: iterations
				},
				params: {}
			};
		}

		return pbe_info;
	}

	_pbeEncrypt(pbe_info, data)
	{
		switch (pbe_info.type) {
			case 'pkcs5PBKDF2':
				return jCastle.pbe.pbes2.encrypt(pbe_info, this.password, data);

			case 'pkcs5PBKDF1':
				return jCastle.pbe.pbes1.encrypt(pbe_info, this.password, data);

			case 'pkcs12DeriveKey':
				return jCastle.pbe.pkcs12pbes.encrypt(pbe_info, this.password, data);
			default:
				throw jCastle.exception("UNKNOWN_PBE_TYPE", 'PFX034');
		}
	}

/*
 -- ============================
 -- Attributes
 -- ============================

 PKCS12Attribute ::= SEQUENCE {
     attrId      ATTRIBUTE.&id ({PKCS12AttrSet}),
     attrValues  SET OF ATTRIBUTE.&Type ({PKCS12AttrSet}{@attrId})
 } -- This type is compatible with the X.500 type 'Attribute'

 PKCS12AttrSet ATTRIBUTE ::= {
     friendlyName |
     localKeyId,
     ... -- Other attributes are allowed
 }
*/
	_parseAttributes(set)
	{
		var attributes = {};
		
		for (var i = 0; i < set.items.length; i++) {
			var id = jCastle.oid.getName(set.items[i].items[0].value);
			var value = set.items[i].items[1].items[0].value;
			attributes[id] = value;
		}

		return attributes;
	}

	_getAuthSafeSchema(authSafe)
	{
		var authSafeSchema = {
			type: jCastle.asn1.tagSequence,
			items: []
		};

		for (var i = 0; i < authSafe.length; i++) {
			var safeContents = authSafe[i];

			var safeContentsSchema = this._getSafeContentsSchema(safeContents);
			authSafeSchema.items.push(safeContentsSchema);
		}

		return authSafeSchema;
	}

/*
safeContents_i = {
	dataType: data | encryptedData | envelopedData,
	contents: [safeBag_0, safeBag_1, safeBag_2, ... , safeBag_i],
	encryptedInfo: pbe_info if dataType is encryptedData,
	envelopedInfo: enveloped_info if dataType is envelopedData
};
*/
	_getSafeContentsSchema(safeContents)
	{
//console.log(safeContents);
		var asn1 = new jCastle.asn1();
		var contentsSchema = {
			type: jCastle.asn1.tagSequence,
			items: []
		};
		var safeContentsSchema;

		var dataType = 'dataType' in safeContents ? safeContents.dataType : 'data';

		for (var i = 0; i < safeContents.contents.length; i++) {
			var safeBag = safeContents.contents[i];
//console.log(safeBag);
			var safeBagSchema = this._getSafeBagSchema(safeBag);
//console.log(safeBagSchema);
			contentsSchema.items.push(safeBagSchema);
		}

		switch (dataType) {
			case 'encryptedData':
				if (!this.password) {
					throw jCastle.exception('NO_PASSPHRASE', 'PFX035');
				}

				var data_der = asn1.getDER(contentsSchema);
				var pbe_info = this._getPbeInfo(safeContents.encryptedInfo);
				var result = this._pbeEncrypt(pbe_info, data_der);

				pbe_info.kdfInfo.salt = result.salt;
				if (result.iv) pbe_info.params.iv = result.iv;

//				if (pbe_info.type == 'pkcs5PBKDF2') {
//					var pbe_sequence = jCastle.pbe.asn1.pbeInfo.schema(
//						'pkcs5PBKDF2',
//						pbe_info.algoInfo, {
//							oid: result.oid,
//							salt: result.salt,
//							iterations: pbe_info.iterations,
//							keySize: pbe_info.keySize,
//							iv: result.iv,
//							prfHash: pbe_info.prfHash
//						});
//				} else {
//					var pbe_sequence = jCastle.pbe.asn1.pbeInfo.schema(
//						pbe_info.type,
//						pbe_info.algoInfo, {
//							salt: result.salt,
//							iterations: pbe_info.iterations
//						});
//				}

				var pbe_sequence = jCastle.pbe.asn1.pbeInfo.schema(pbe_info);

				safeContentsSchema = {
					type: jCastle.asn1.tagSequence,
					items: [{
						type: jCastle.asn1.tagOID,
						value: jCastle.oid.getOID('encryptedData')
					}, {
						tagClass: jCastle.asn1.tagClassContextSpecific,
						type: 0x00,
						constructed: true,
						items: [{
							type: jCastle.asn1.tagSequence,
							items: [{
								type: jCastle.asn1.tagInteger,
								intVal: 0x00 // version ?
							}, {
								type: jCastle.asn1.tagSequence,
								items: [{
									type: jCastle.asn1.tagOID,
									value: jCastle.oid.getOID('data')
								}, pbe_sequence, {
									tagClass: jCastle.asn1.tagClassContextSpecific,
									type: 0x00,
									constructed: false,
									value: result.encrypted
								}]
							}]
						}]
					}]
				};
				break;


			case 'envelopedData':
				var envelopedInfo = safeContents.envelopedInfo;
				var keyMethod = null;

				for (var j = 0; j < envelopedInfo.recipientInfos.length; j++) {
					var ri = envelopedInfo.recipientInfos[j];
					switch (ri.type) {
						case 'keyTransRecipientInfo':
							if (this.signKey && this.signKey.hasPrivateKey() && this.signKey.pkiName == 'RSA') {
								keyMethod = 'keyTransRecipientInfo';
							}
							break;
						case 'keyAgreeRecipientInfo':
						case 'kekRecipientInfo':
						case 'passwordRecipientInfo':
					}

				}

				
				throw jCastle.exception("UNSUPPORTED_PFX_STRUCTURE", 'PFX036');

			case 'data':
				safeContentsSchema = {
					type: jCastle.asn1.tagSequence,
					items: [{
						type: jCastle.asn1.tagOID,
						value: jCastle.oid.getOID('data')
					}, {
						tagClass: jCastle.asn1.tagClassContextSpecific,
						type: 0x00,
						constructed: true,
						items: [{
							type: jCastle.asn1.tagOctetString,
							value: contentsSchema
						}]
					}]
				};
				break;
			default:
				throw jCastle.exception('UNSUPPORTED_PFX_STRUCTURE', 'PFX037');
		}

		return safeContentsSchema;
	}

/*
safeBag_i = {
	bagId: keyBag | pkcs8ShroudedKeyBag | certBag | crlBag | secretBag | safeContentsBag,
	content: bag_content,
	attributes: bag_attributes,
	encryptedInfo: pbe_info if bagId is pkcs8ShroudedKeyBag
};
*/
	_getSafeBagSchema(safeBag)
	{
		var safeBagSchema;

		switch (safeBag.bagId) {
			case 'keyBag':
				var pki = new jCastle.pki();

//				if (typeof safeBag.content == 'string') {// pem or der
				if (jCastle.util.isString(safeBag.content)) {
					//pki.parse(safeBag.content, this.password, 'auto', 'private');
					pki.parse(safeBag.content, this.password);
				} else { // privateKeyInfo or pki
					try {
						pki.init(safeBag.content);
					} catch (e) {
						throw jCastle.exception("NO_SAFEBAG_CONTENT", 'PFX038');
					}
				}

				if (!pki.hasPrivateKey()) {
					throw jCastle.exception("NO_SAFEBAG_CONTENT", 'PFX039');
				}
				var der = pki.exportKey('private', {
					format: 'der'
				});

				safeBagSchema = {
					type: jCastle.asn1.tagSequence,
					items: [{
						type: jCastle.asn1.tagOID,
						value: jCastle.oid.getOID('keyBag')
					}, {
						tagClass: jCastle.asn1.tagClassContextSpecific,
						type: 0x00,
						constructed: true,
						items: [{
							type: jCastle.asn1.tagOctetString,
							value: der
						}]
					}]
				};

				if (safeBag.attributes) {
					var attributesSchema = this._getAttributesSchema(safeBag.attributes);
					safeBagSchema.items[1].items[0].value.items.push(attributesSchema);
				}

				return safeBagSchema;

			case 'pkcs8ShroudedKeyBag':
				if (!this.password) {
					throw jCastle.exception('NO_PASSPHRASE', 'PFX040');
				}

				var pki = new jCastle.pki();

				if (jCastle.util.isString(safeBag.content)) {
					//pki.parse(safeBag.content, this.password, 'auto', 'private');
					pki.parse(safeBag.content, this.password);
				} else { // privateKeyInfo or pki
					try {
						pki.init(safeBag.content);
					} catch (e) {
						throw jCastle.exception("NO_SAFEBAG_CONTENT", 'PFX041');
					}
				}

				if (!pki.hasPrivateKey()) {
					throw jCastle.exception("NO_SAFEBAG_CONTENT", 'PFX042');
				}
				var der = pki.exportKey('private', {
					format: 'der'
				});

				var pbe_info = this._getPbeInfo(safeBag.encryptedInfo);
				var result = this._pbeEncrypt(pbe_info, der);

				pbe_info.kdfInfo.salt = result.salt;
				if (result.iv) pbe_info.params.iv = result.iv;

//				if (pbe_info.type == 'pkcs5PBKDF2') {
//					var pbe_sequence = jCastle.pbe.asn1.pbeInfo.schema(
//						'pkcs5PBKDF2',
//						pbe_info.algoInfo, {
//							oid: result.oid,
//							salt: result.salt,
//							iterations: pbe_info.iterations,
//							keySize: pbe_info.keySize,
//							iv: result.iv,
//							prfHash: pbe_info.prfHash
//						});
//				} else {
//					var pbe_sequence = jCastle.pbe.asn1.pbeInfo.schema(
//						pbe_info.type,
//						pbe_info.algoInfo, {
//							salt: result.salt,
//							iterations: pbe_info.iterations
//						});
//				}
				var pbe_sequence = jCastle.pbe.asn1.pbeInfo.schema(pbe_info);

				safeBagSchema = {
					type: jCastle.asn1.tagSequence,
					items: [{
						type: jCastle.asn1.tagOID,
						value: jCastle.oid.getOID('pkcs8ShroudedKeyBag')
					}, {
						tagClass: jCastle.asn1.tagClassContextSpecific,
						type: 0x00,
						constructed: true,
						items: [{
							type: jCastle.asn1.tagSequence,
							items: [pbe_sequence, {
								type: jCastle.asn1.tagOctetString,
								value: result.encrypted
							}]
						}]
					}]
				};

				if (safeBag.attributes) {
					var attributesSchema = this._getAttributesSchema(safeBag.attributes);
					safeBagSchema.items.push(attributesSchema);
				}

				return safeBagSchema;

			case 'certBag':
				/*
				// we need a function that can build der from certInfo.
				// the third parameter of exportCertificate() is for it.
				// if the third parameter is true, then signaure of cert_info will be used,
				// not generated by sign key for there is no sign key known.
				var der;
				if (jCastle.util.isString(safeBag.content)) { // pem or der string
					var format = jCastle.util.seekPemFormat(safeBag.content);
					switch (format) {
						case 'pem':
							var pem = safeBag.content.replace(/-----(BEGIN|END) (X509 CRL|(NEW )?CERTIFICATE( REQUEST)?)-----/g, '').replace("\n", '');
							der = jCastle.base64.decode(pem, true);
							break;
						case 'hex':
							der = jCastle.encoding.hex.decode(safeBag.content);
							break;
						case 'base64':
							der = jCastle.base64.decode(safeBag.content, true);
							break;
						case 'der':
						default:
							der = safeBag.content;
					}
				} else { // certificateInfo or certificate object
					if (safeBag.content instanceof jCastle.certificate) {
						var cert = safeBag.content;
						if (cert.certInfo) {
							der =  'der' in cert.certInfo ? cert.certInfo.der : cert.exportCertificate(cert.certInfo, 'der', true);
						} else {
							throw jCastle.exception('INVALID_CERT_INFO', 'PFX043');
						}
					} else {
						var der = new jCastle.certificate().exportCertificate(safeBag.content, 'der', true);
					}
				}
				*/
				var der = jCastle.certificate.getDER(safeBag.content);
				var subtype = safeBag.subType ? safeBag.subType : 'x509Certificate';
				if (subtype != 'x509Certificate' && subtype != 'sdsiCertificate') {
					throw jCastle.exception('INVALID_CERT_TYPE', 'PFX044');
				}

/*
SEQUENCE(1 elem)
	SEQUENCE(3 elem)
		OBJECT IDENTIFIER														1.2.840.113549.1.12.10.1.3  -- certBag
		[0](1 elem)
			SEQUENCE(2 elem)
				OBJECT IDENTIFIER												1.2.840.113549.1.9.22.1  -- x509Certificate
				[0](1 elem)
					OCTET STRING(1 elem)
						SEQUENCE(3 elem)
*/

				var certSchema = {
					type: subtype == 'x509Certificate' ? jCastle.asn1.tagOctetString : jCastle.asn1.tagIA5String,
					value: subtype == 'x509Certificate' ? der : Buffer.from(der).toString('base64')
				};

				safeBagSchema = {
					type: jCastle.asn1.tagSequence,
					items: [{
						type: jCastle.asn1.tagOID,
						value: jCastle.oid.getOID('certBag')
					}, {
						tagClass: jCastle.asn1.tagClassContextSpecific,
						type: 0x00,
						constructed: true,
						items: [{
							type: jCastle.asn1.tagSequence,
							items: [{
								type: jCastle.asn1.tagOID,
								value: jCastle.oid.getOID(subtype)
							}, {
								tagClass: jCastle.asn1.tagClassContextSpecific,
								type: 0x00,
								constructed: true,
								items: [certSchema]
							}]
						}]
					}]
				};

				if (safeBag.attributes) {
					var attributesSchema = this._getAttributesSchema(safeBag.attributes);
					safeBagSchema.items.push(attributesSchema);
				}

				return safeBagSchema;

			case 'crlBag':
				var der = new jCastle.certificate().exportCertificate(safeBag.content, 'der');

				safeBagSchema = {
					type: jCastle.asn1.tagSequence,
					items: [{
						type: jCastle.asn1.tagOID,
						value: jCastle.oid.getOID('crlBag')
					}, {
						tagClass: jCastle.asn1.tagClassContextSpecific,
						type: 0x00,
						constructed: true,
						items: [{
							type: jCastle.asn1.tagOctetString,
							value: der
						}]
					}]
				};

				if (safeBag.attributes) {
					var attributesSchema = this._getAttributesSchema(safeBag.attributes);
					safeBagSchema.items.push(attributesSchema);
				}

				return safeBagSchema;

			case 'secretBag':
			case 'safeContentsBag':
			default:
				throw jCastle.exception("UNSUPPORTED_PFX_STRUCTURE", 'PFX045');
		}
	}

	_getAttributesSchema(attributes)
	{
		var attributesSchema = {
			type: jCastle.asn1.tagSet,
			items: []
		};

		for (var attrName in attributes) {
			var attrValue = attributes[attrName];
			var attrOID = jCastle.oid.getOID(attrName);
			if (!attrOID) {
				throw jCastle.exception('INVALID_OID', 'PFX046');
			}

			// currently only localKeyID & friendlyName are supported
			var attrSchema = {
				type: jCastle.asn1.tagSequence,
				items: [{
					type: jCastle.asn1.tagOID,
					value: attrOID
				},{
					type: jCastle.asn1.tagSet,
					items: [{
						type: jCastle.asn1.tagOctetString,
						value: attrValue
					}]
				}]
			};
			
			attributesSchema.items.push(attrSchema);
		}

		return attributesSchema;
	}

/*
	SEQUENCE(3 elem)
		SEQUENCE(2 elem)
			SEQUENCE(2 elem)
				OBJECT IDENTIFIER												1.3.14.3.2.26  -- sha1 / OIW
				NULL
			OCTET STRING(20 byte)												A26DFA83697E8321DB17A6E24CAB8007A2BD19C2
		OCTET STRING(8 byte)													95B779F1087197D3
		INTEGER																	2048
*/
	_getMacDataSchema(macInfo, authSafe)
	{
		var algo, salt, iterations = 1;

		if ('salt' in macInfo) {
			salt = Buffer.from(macInfo.salt, 'latin1');
		} else {
			// generate. default is 8
			var len = 'saltLength' in macInfo ? macInfo.saltLength : 8;
			salt = new jCastle.prng().nextBytes(len);
		}

		if (salt.length < 8) {
			throw jCastle.exception('SALT_LENGTH_TOO_SHORT', 'PFX047');
		}

		if ('iterations' in macInfo) {
			iterations = macInfo.iterations;
		}

//		if (iterations < 1024 || (iterations % 8) != 0) {
//			throw jCastle.exception('INVALID_ITERATIONS', 'PFX048');
//		}

		algo = jCastle.digest.getValidAlgoName(macInfo.algo);

		//var key = new jCastle.digest(algo).pkcs12DeriveKey(this.password, salt, iterations, 3, jCastle.digest.getDigestLength(algo));
		var key = jCastle.kdf.pkcs12DeriveKey(this.password, salt, iterations, 3, jCastle.digest.getDigestLength(algo), algo, 'utf8');
		//var key = jCastle.kdf.pkcs12pbkdf(this.password, salt, iterations, 3, jCastle.digest.getDigestLength(algo), algo, 'utf8');

		var hmac = new jCastle.hmac(algo).start({
			key: key
		});
		hmac.update(Buffer.from(authSafe, 'latin1'));
		var data = hmac.finalize();

		var macDataSchema = {
			type: jCastle.asn1.tagSequence,
			items: [{
				type: jCastle.asn1.tagSequence,
				items: [{
					type: jCastle.asn1.tagSequence,
					items: [{
						type: jCastle.asn1.tagOID,
						value: jCastle.oid.getOID(algo == 'sha-1' ? 'sha1' : algo) // traditional way...
					}, {
						type: jCastle.asn1.tagNull,
						value: null
					}]
				}, {
					type: jCastle.asn1.tagOctetString,
					value: data
				}]
			}, {
				type: jCastle.asn1.tagOctetString,
				value: salt
			}]
		};

		// if iterations is 1 then omit it.
		if (iterations > 1) {
			macDataSchema.items.push( {
				type: jCastle.asn1.tagInteger,
				intVal: iterations
			});
		}

		return macDataSchema;
	}


};


jCastle.pfx.create = function()
{
	return new jCastle.pfx();
};

jCastle.pfx.rasterizeSchema = function(pfxInfo)
{
	var info = jCastle.util.clone(pfxInfo);

	if ('type' in info) {
		jCastle.assert(info.type, 'PFX', 'INVALID_PFX_INFO', 'PFX049');
		info.type = 'PFX(Personal Information Exchange)';
	}

	if ('macInfo' in info) {
		if ('salt' in info.macInfo) info.macInfo.salt = jCastle.encoding.hex.encode(info.macInfo.salt);
		if ('iv' in info.macInfo) info.macInfo.iv = jCastle.encoding.hex.encode(info.macInfo.iv);
		info.macInfo.data = jCastle.encoding.hex.encode(info.macInfo.data);
	}

	for (var i = 0; i < info.authSafe.length; i++) {
		var safeContents = info.authSafe[i];
		//if ('encryptedInfo' in safeContents) {
		if (safeContents.dataType == 'encryptedData') {
			safeContents.encryptedInfo = jCastle.pfx._rasterizeEncryptedInfo(safeContents.encryptedInfo);
		}
		for (var j = 0; j < safeContents.contents.length; j++) {
			var safeBag = safeContents.contents[j];

			switch (safeBag.bagId) {
				case 'keyBag':
					safeBag.content = jCastle.pfx._rasterizePrivateKeyInfo(safeBag.content);
					break;
				case 'pkcs8ShroudedKeyBag': // clone does not give a perfect clone...
					safeBag.content = jCastle.pfx._rasterizePrivateKeyInfo(safeBag.content);
					safeBag.encryptedInfo = jCastle.pfx._rasterizeEncryptedInfo(safeBag.encryptedInfo);
					break;
				case 'certBag':
				case 'crlBag':
					safeBag.content = jCastle.certificate.rasterizeSchema(safeBag.content);
					break;
			}

			if ('attributes' in safeBag && 'localKeyID' in safeBag.attributes) {
				safeBag.attributes.localKeyID = jCastle.encoding.hex.encode(safeBag.attributes.localKeyID);
			}

			//if ('der' in safeBag) safeBag.der = jCastle.encoding.hex.encode(safeBag.der);
			if ('buffer' in safeBag) safeBag.buffer = safeBag.buffer.toString('hex');
		}
	}

	return info;
};

jCastle.pfx._rasterizeEncryptedInfo = function(encryptedInfo)
{
	var info = jCastle.util.clone(encryptedInfo);
	if ('salt' in info.kdfInfo) 
		info.kdfInfo.salt = jCastle.encoding.hex.encode(info.kdfInfo.salt);
	if ('iv' in info.params) 
		info.params.iv = jCastle.encoding.hex.encode(info.params.iv);

	return info;
};

jCastle.pfx._rasterizePrivateKeyInfo = function(privateKeyInfo)
{
	switch (privateKeyInfo.algo) {
		case 'RSA':
			privateKeyInfo.privateKey.n = privateKeyInfo.privateKey.n.toString(16);
			privateKeyInfo.privateKey.e = privateKeyInfo.privateKey.e;
			privateKeyInfo.privateKey.d = privateKeyInfo.privateKey.d.toString(16);
			privateKeyInfo.privateKey.p = privateKeyInfo.privateKey.p.toString(16);
			privateKeyInfo.privateKey.q = privateKeyInfo.privateKey.q.toString(16);
			privateKeyInfo.privateKey.dmp1 = privateKeyInfo.privateKey.dmp1.toString(16);
			privateKeyInfo.privateKey.dmq1 = privateKeyInfo.privateKey.dmq1.toString(16);
			privateKeyInfo.privateKey.iqmp = privateKeyInfo.privateKey.iqmp.toString(16);
			break;
		case 'DSA':
		case 'ECDSA':
		case 'ECKCDSA':
		case 'KCDSA':
		case 'ELGAMAL':
			privateKeyInfo.privateKey = privateKeyInfo.privateKey.toString(16);
			break;
	}

	return privateKeyInfo;
};

jCastle.PFX = jCastle.pfx;

module.exports = jCastle.pfx;
