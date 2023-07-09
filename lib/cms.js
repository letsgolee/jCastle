/**
 * A Javascript implemenation of Cryptographic Message Syntax(CMS)
 *
 * @author Jacob Lee
 *
 * Copyright (C) 2015-2022 Jacob Lee. All rights reserved.
 */

var jCastle = require('./jCastle');

require('./bigint-extend');
require('./util');
require('./certificate');

/*
https://tools.ietf.org/html/rfc5652
*/

jCastle.cms = class
{
	constructor()
	{
		this.cmsInfo = null;
	//	this.password = null;
	//	this.signKey = null;
	}

	/**
	 * resets internal variables
	 * 
	 * @public
	 * 
	 * @returns this class instance.
	 */
	reset()
	{
		this.cmsInfo = null;
//		this.password = null;
//		this.signKey = null;
		return this;
	}

	/**
	 * gets contentType of the cms data.
	 * 
	 * @public
	 * 
	 * @param {string} cms cms data string or buffer
	 * @param {object} options options object for parsing.
	 * 
	 * @returns cms content-type.
	 */
	parseType(cms, options = {})
	{
		options.returnContentType = true;

		return this.parse(cms, options);
	}

	/**
	 * parses cms data.
	 * 
	 * @public
	 * 
	 * @param {string} cms cms data string or buffer
	 * @param {object} options options object for parsing.
	 * 
	 * @returns cms schema structured object.
	 */
	parse(cms, options = {})
	{
		var format = 'format' in options ? options.format : 'auto';
		var cmsSequence, cmsInfo;
		var result = jCastle.util.toAsn1Object(cms);
		cmsSequence = result.asn1;

		if (!jCastle.asn1.isSequence(cmsSequence)) {
			throw jCastle.exception('INVALID_CMS_FORMAT', 'CMS001');
		}


/*
3.  General Syntax

   The following object identifier identifies the content information
   type:

      id-ct-contentInfo OBJECT IDENTIFIER ::= { iso(1) member-body(2)
         us(840) rsadsi(113549) pkcs(1) pkcs9(9) smime(16) ct(1) 6 }

   The CMS associates a content type identifier with a content.  The
   syntax MUST have ASN.1 type ContentInfo:

      ContentInfo ::= SEQUENCE {
        contentType ContentType,
        content [0] EXPLICIT ANY DEFINED BY contentType }

      ContentType ::= OBJECT IDENTIFIER

   The fields of ContentInfo have the following meanings:

      contentType indicates the type of the associated content.  It is
      an object identifier; it is a unique string of integers assigned
      by an authority that defines the content type.

      content is the associated content.  The type of content can be
      determined uniquely by contentType.  Content types for data,
      signed-data, enveloped-data, digested-data, encrypted-data, and
      authenticated-data are defined in this document.  If additional
      content types are defined in other documents, the ASN.1 type
      defined SHOULD NOT be a CHOICE type.
*/
/*
ContentInfo ::= SEQUENCE {
 contentType ContentType,
 content [0] EXPLICIT ANY DEFINED BY contentType }
*/
		var contentType = jCastle.oid.getName(cmsSequence.items[0].value);

		// console.log('contentType: ', contentType);

		if (options.returnContentType) return contentType;

		if (contentType in jCastle.cms.contentType) {
			cmsInfo = jCastle.cms.contentType[contentType].parse(cmsSequence, options);
		} else {
			throw jCastle.exception('UNSUPPORTED_CMS_STRUCTURE', 'CMS002');
		}

		this.cmsInfo = cmsInfo;

		return cmsInfo;
	}

	/**
	 * alias function of exportCMS().
	 * 
	 * @public
	 * 
	 * @param {object} cmsInfo cms schema structured object.
	 * @param {object} options options object for getting cms string.
	 * @returns cms string or buffer.
	 */
	export(cmsInfo, options)
	{
		return this.exportCMS(cmsInfo, options);
	}

	/**
	 * gets cms string or buffer.
	 * 
	 * @public
	 * 
	 * @param {object} cmsInfo cms schema structured object.
	 * @param {object} options options object for getting cms string.
	 * @returns cms string or buffer.
	 */
	exportCMS(cmsInfo, options = {})
	{
		var format = 'format' in options ? options.format.toLowerCase() : 'pem';

		var der = '';

		if (cmsInfo.contentType in jCastle.cms.contentType) {
			der = jCastle.cms.contentType[cmsInfo.contentType].getDER(cmsInfo, options);
		} else {
			throw jCastle.exception('UNSUPPORTED_CMS_STRUCTURE', 'CMS009');
		}

		var buf = Buffer.from(der, 'latin1');

		switch (format) {
			case 'hex':
				return buf.toString('hex');
			case 'base64':
				return buf.toString('base64');
			case 'buffer':
				return buf;
			case 'der':
				return der;
			case 'pem':
			default:
				return "-----BEGIN CMS-----\n" + 
					jCastle.util.lineBreak(buf.toString('base64'), 64) +
					"\n-----END CMS-----";
		}
	}
};

jCastle.cms.contentType = {};
jCastle.cms.contentType.data = {
/*
4.  Data Content Type

   The following object identifier identifies the data content type:

      id-data OBJECT IDENTIFIER ::= { iso(1) member-body(2)
         us(840) rsadsi(113549) pkcs(1) pkcs7(7) 1 }

   The data content type is intended to refer to arbitrary octet
   strings, such as ASCII text files; the interpretation is left to the
   application.  Such strings need not have any internal structure
   (although they could have their own ASN.1 definition or other
   structure).

   S/MIME uses id-data to identify MIME-encoded content.  The use of
   this content identifier is specified in RFC 2311 for S/MIME v2
   [MSG2], RFC 2633 for S/MIME v3 [MSG3], and RFC 3851 for S/MIME v3.1
   [MSG3.1].

   The data content type is generally encapsulated in the signed-data,
   enveloped-data, digested-data, encrypted-data, or authenticated-data
   content type.
*/
	parse: function(cmsSequence, options = {})
	{
		var explicit = cmsSequence.items[1];
		var value = explicit.items[0].value;
		var content = jCastle.cms.content.parse(value, options);
		var cmsInfo = {
			contentType: 'data',
			content: content
		};

		return cmsInfo;
	},

	getDER: function(cmsInfo, options = {})
	{
		var ber_encoding = !!options.berEncoding;
		var content = jCastle.cms.content.getDER('content' in options ? options.content : cmsInfo.content, options);

		var cmsSchema = {
			type: jCastle.asn1.tagSequence,
			items:[{
				type: jCastle.asn1.OID,
				value: jCastle.oid.getOID('data')
			}, {
				type: 0x00,
				tagClass: jCastle.asn1.tagClassContextSpecific,
				constructed: true,
				items: [{
					type: jCastle.asn1.tagOctetString,
					value: content
//				}],
//				indefiniteLength: true
				}]
//			}],
//			indefiniteLength: true
			}]
		};

		if (ber_encoding) {
			cmsSchema.items[1].indefiniteLength = true;
			cmsSchema.indefiniteLength = true;
		}

		var der = new jCastle.asn1().getDER(cmsSchema);
		return der;
	}
};

jCastle.cms.contentType.signedData = {
/*
5.  Signed-data Content Type

   The signed-data content type consists of a content of any type and
   zero or more signature values.  Any number of signers in parallel can
   sign any type of content.

   The typical application of the signed-data content type represents
   one signer's digital signature on content of the data content type.
   Another typical application disseminates certificates and certificate
   revocation lists (CRLs).

   The process by which signed-data is constructed involves the
   following steps:

   1.  For each signer, a message digest, or hash value, is computed on
       the content with a signer-specific message-digest algorithm.  If
       the signer is signing any information other than the content, the
       message digest of the content and the other information are
       digested with the signer's message digest algorithm (see Section
       5.4), and the result becomes the "message digest."

   2.  For each signer, the message digest is digitally signed using the
       signer's private key.

   3.  For each signer, the signature value and other signer-specific
       information are collected into a SignerInfo value, as defined in
       Section 5.3.  Certificates and CRLs for each signer, and those
       not corresponding to any signer, are collected in this step.

   4.  The message digest algorithms for all the signers and the
       SignerInfo values for all the signers are collected together with
       the content into a SignedData value, as defined in Section 5.1.

   A recipient independently computes the message digest.  This message
   digest and the signer's public key are used to verify the signature
   value.  The signer's public key is referenced in one of two ways.  It
   can be referenced by an issuer distinguished name along with an
   issuer-specific serial number to uniquely identify the certificate
   that contains the public key.  Alternatively, it can be referenced by
   a subject key identifier, which accommodates both certified and
   uncertified public keys.  While not required, the signer's
   certificate can be included in the SignedData certificates field.

   When more than one signature is present, the successful validation of
   one signature associated with a given signer is usually treated as a
   successful signature by that signer.  However, there are some
   application environments where other rules are needed.  An
   application that employs a rule other than one valid signature for
   each signer must specify those rules.  Also, where simple matching of
   the signer identifier is not sufficient to determine whether the
   signatures were generated by the same signer, the application
   specification must describe how to determine which signatures were
   generated by the same signer.  Support of different communities of
   recipients is the primary reason that signers choose to include more
   than one signature.  For example, the signed-data content type might
   include signatures generated with the RSA signature algorithm and
   with the Elliptic Curve Digital Signature Algorithm (ECDSA) signature
   algorithm.  This allows recipients to verify the signature associated
   with one algorithm or the other.

   This section is divided into six parts.  The first part describes the
   top-level type SignedData, the second part describes
   EncapsulatedContentInfo, the third part describes the per-signer
   information type SignerInfo, and the fourth, fifth, and sixth parts
   describe the message digest calculation, signature generation, and
   signature verification processes, respectively.

5.1.  SignedData Type

   The following object identifier identifies the signed-data content
   type:

      id-signedData OBJECT IDENTIFIER ::= { iso(1) member-body(2)
         us(840) rsadsi(113549) pkcs(1) pkcs7(7) 2 }

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

   The fields of type SignedData have the following meanings:
*/

	parse: function(cmsSequence, options = {})
	{
		var explicit = cmsSequence.items[1];
		var sequence = explicit.items[0];
		var idx = 0;
		var obj = sequence.items[idx++];

/*
      version is the syntax version number.  The appropriate value
      depends on certificates, eContentType, and SignerInfo.  The
      version MUST be assigned as follows:

         IF ((certificates is present) AND
            (any certificates with a type of other are present)) OR
            ((crls is present) AND
            (any crls with a type of other are present))
         THEN version MUST be 5
         ELSE
            IF (certificates is present) AND
               (any version 2 attribute certificates are present)
            THEN version MUST be 4
            ELSE
               IF ((certificates is present) AND
                  (any version 1 attribute certificates are present)) OR
                  (any SignerInfo structures are version 3) OR
                  (encapContentInfo eContentType is other than id-data)
               THEN version MUST be 3
               ELSE version MUST be 1
*/
		var version = obj.intVal;
		obj = sequence.items[idx++];

/*
      digestAlgorithms is a collection of message digest algorithm
      identifiers.  There MAY be any number of elements in the
      collection, including zero.  Each element identifies the message
      digest algorithm, along with any associated parameters, used by
      one or more signer.  The collection is intended to list the
      message digest algorithms employed by all of the signers, in any
      order, to facilitate one-pass signature verification.
      Implementations MAY fail to validate signatures that use a digest
      algorithm that is not included in this set.  The message digesting
      process is described in Section 5.4.
*/
		var digestAlgorithms = [];
		if (obj.type == jCastle.asn1.tagSet) {
			for(var i = 0; i < obj.items.length; i++) {
				var hash_algo = jCastle.oid.getName(obj.items[i].items[0].value);
				digestAlgorithms.push(hash_algo);
			}
			obj = sequence.items[idx++];
		}

/*
      encapContentInfo is the signed content, consisting of a content
      type identifier and the content itself.  Details of the
      EncapsulatedContentInfo type are discussed in Section 5.2.
*/
/*
5.2.  EncapsulatedContentInfo Type

   The content is represented in the type EncapsulatedContentInfo:

      EncapsulatedContentInfo ::= SEQUENCE {
        eContentType ContentType,
        eContent [0] EXPLICIT OCTET STRING OPTIONAL }

      ContentType ::= OBJECT IDENTIFIER

   The fields of type EncapsulatedContentInfo have the following
   meanings:

      eContentType is an object identifier.  The object identifier
      uniquely specifies the content type.

      eContent is the content itself, carried as an octet string.  The
      eContent need not be DER encoded.

   The optional omission of the eContent within the
   EncapsulatedContentInfo field makes it possible to construct
   "external signatures".  In the case of external signatures, the
   content being signed is absent from the EncapsulatedContentInfo value
   included in the signed-data content type.  If the eContent value
   within EncapsulatedContentInfo is absent, then the signatureValue is
   calculated and the eContentType is assigned as though the eContent
   value was present.

   In the degenerate case where there are no signers, the
   EncapsulatedContentInfo value being "signed" is irrelevant.  In this
   case, the content type within the EncapsulatedContentInfo value being
   "signed" MUST be id-data (as defined in Section 4), and the content
   field of the EncapsulatedContentInfo value MUST be omitted.

5.2.1.  Compatibility with PKCS #7

   This section contains a word of warning to implementers that wish to
   support both the CMS and PKCS #7 [PKCS#7] SignedData content types.
   Both the CMS and PKCS #7 identify the type of the encapsulated
   content with an object identifier, but the ASN.1 type of the content
   itself is variable in PKCS #7 SignedData content type.

   PKCS #7 defines content as:

      content [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL

   The CMS defines eContent as:

      eContent [0] EXPLICIT OCTET STRING OPTIONAL

   The CMS definition is much easier to use in most applications, and it
   is compatible with both S/MIME v2 and S/MIME v3.  S/MIME signed
   messages using the CMS and PKCS #7 are compatible because identical
   signed message formats are specified in RFC 2311 for S/MIME v2
   [MSG2], RFC 2633 for S/MIME v3 [MSG3], and RFC 3851 for S/MIME v3.1
   [MSG3.1].  S/MIME v2 encapsulates the MIME content in a Data type
   (that is, an OCTET STRING) carried in the SignedData contentInfo
   content ANY field, and S/MIME v3 carries the MIME content in the
   SignedData encapContentInfo eContent OCTET STRING.  Therefore, in
   S/MIME v2, S/MIME v3, and S/MIME v3.1, the MIME content is placed in
   an OCTET STRING and the message digest is computed over the identical
   portions of the content.  That is, the message digest is computed
   over the octets comprising the value of the OCTET STRING, neither the
   tag nor length octets are included.

   There are incompatibilities between the CMS and PKCS #7 SignedData
   types when the encapsulated content is not formatted using the Data
   type.  For example, when an RFC 2634 signed receipt [ESS] is
   encapsulated in the CMS SignedData type, then the Receipt SEQUENCE is
   encoded in the SignedData encapContentInfo eContent OCTET STRING and
   the message digest is computed using the entire Receipt SEQUENCE
   encoding (including tag, length and value octets).  However, if an
   RFC 2634 signed receipt is encapsulated in the PKCS #7 SignedData
   type, then the Receipt SEQUENCE is DER encoded [X.509-88] in the
   SignedData contentInfo content ANY field (a SEQUENCE, not an OCTET
   STRING).  Therefore, the message digest is computed using only the
   value octets of the Receipt SEQUENCE encoding.

   The following strategy can be used to achieve backward compatibility
   with PKCS #7 when processing SignedData content types.  If the
   implementation is unable to ASN.1 decode the SignedData type using
   the CMS SignedData encapContentInfo eContent OCTET STRING syntax,
   then the implementation MAY attempt to decode the SignedData type
   using the PKCS #7 SignedData contentInfo content ANY syntax and
   compute the message digest accordingly.

   The following strategy can be used to achieve backward compatibility
   with PKCS #7 when creating a SignedData content type in which the
   encapsulated content is not formatted using the Data type.
   Implementations MAY examine the value of the eContentType, and then
   adjust the expected DER encoding of eContent based on the object
   identifier value.  For example, to support Microsoft Authenticode
   [MSAC], the following information MAY be included:

      eContentType Object Identifier is set to { 1 3 6 1 4 1 311 2 1 4 }

      eContent contains DER-encoded Authenticode signing information
*/
		var encapContentInfo = jCastle.cms.asn1.encapContentInfo.parse(obj, options);
		obj = sequence.items[idx++];

/*
      certificates is a collection of certificates.  It is intended that
      the set of certificates be sufficient to contain certification
      paths from a recognized "root" or "top-level certification
      authority" to all of the signers in the signerInfos field.  There
      may be more certificates than necessary, and there may be
      certificates sufficient to contain certification paths from two or
      more independent top-level certification authorities.  There may
      also be fewer certificates than necessary, if it is expected that
      recipients have an alternate means of obtaining necessary
      certificates (e.g., from a previous set of certificates).  The
      signer's certificate MAY be included.  The use of version 1
      attribute certificates is strongly discouraged.
*/
		var certs = null;
		if (obj.tagClass == jCastle.asn1.tagClassContextSpecific && obj.type == 0x00) {
			certs = jCastle.cms.asn1.certificateSet.parse(obj);

			obj = sequence.items[idx++];
		}
/*
      crls is a collection of revocation status information.  It is
      intended that the collection contain information sufficient to
      determine whether the certificates in the certificates field are
      valid, but such correspondence is not necessary.  Certificate
      revocation lists (CRLs) are the primary source of revocation
      status information.  There MAY be more CRLs than necessary, and
      there MAY also be fewer CRLs than necessary.
*/
		var crls = null;
		if (obj.tagClass == jCastle.asn1.tagClassContextSpecific && obj.type == 0x01) {
			crls = jCastle.cms.asn1.revocationInfoChoices.parse(obj);

			obj = sequence.items[idx++];
		}
/*
      signerInfos is a collection of per-signer information.  There MAY
      be any number of elements in the collection, including zero.  When
      the collection represents more than one signature, the successful
      validation of one of signature from a given signer ought to be
      treated as a successful signature by that signer.  However, there
      are some application environments where other rules are needed.
      The details of the SignerInfo type are discussed in Section 5.3.
      Since each signer can employ a different digital signature
      technique, and future specifications could update the syntax, all
      implementations MUST gracefully handle unimplemented versions of
      SignerInfo.  Further, since all implementations will not support
      every possible signature algorithm, all implementations MUST
      gracefully handle unimplemented signature algorithms when they are
      encountered.
*/
/*
5.3.  SignerInfo Type

   Per-signer information is represented in the type SignerInfo:

      SignerInfo ::= SEQUENCE {
        version CMSVersion,
        sid SignerIdentifier,
        digestAlgorithm DigestAlgorithmIdentifier,
        signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
        signatureAlgorithm SignatureAlgorithmIdentifier,
        signature SignatureValue,
        unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL }

      SignerIdentifier ::= CHOICE {
        issuerAndSerialNumber IssuerAndSerialNumber,
        subjectKeyIdentifier [0] SubjectKeyIdentifier }

      SignedAttributes ::= SET SIZE (1..MAX) OF Attribute

      UnsignedAttributes ::= SET SIZE (1..MAX) OF Attribute

      Attribute ::= SEQUENCE {
        attrType OBJECT IDENTIFIER,
        attrValues SET OF AttributeValue }

      AttributeValue ::= ANY

      SignatureValue ::= OCTET STRING

   The fields of type SignerInfo have the following meanings:

      version is the syntax version number.  If the SignerIdentifier is
      the CHOICE issuerAndSerialNumber, then the version MUST be 1.  If
      the SignerIdentifier is subjectKeyIdentifier, then the version
      MUST be 3.

      sid specifies the signer's certificate (and thereby the signer's
      public key).  The signer's public key is needed by the recipient
      to verify the signature.  SignerIdentifier provides two
      alternatives for specifying the signer's public key.  The
      issuerAndSerialNumber alternative identifies the signer's
      certificate by the issuer's distinguished name and the certificate
      serial number; the subjectKeyIdentifier identifies the signer's
      certificate by a key identifier.  When an X.509 certificate is
      referenced, the key identifier matches the X.509
      subjectKeyIdentifier extension value.  When other certificate
      formats are referenced, the documents that specify the certificate
      format and their use with the CMS must include details on matching
      the key identifier to the appropriate certificate field.
      Implementations MUST support the reception of the
      issuerAndSerialNumber and subjectKeyIdentifier forms of
      SignerIdentifier.  When generating a SignerIdentifier,
      implementations MAY support one of the forms (either
      issuerAndSerialNumber or subjectKeyIdentifier) and always use it,
      or implementations MAY arbitrarily mix the two forms.  However,
      subjectKeyIdentifier MUST be used to refer to a public key
      contained in a non-X.509 certificate.

      digestAlgorithm identifies the message digest algorithm, and any
      associated parameters, used by the signer.  The message digest is
      computed on either the content being signed or the content
      together with the signed attributes using the process described in
      Section 5.4.  The message digest algorithm SHOULD be among those
      listed in the digestAlgorithms field of the associated SignerData.
      Implementations MAY fail to validate signatures that use a digest
      algorithm that is not included in the SignedData digestAlgorithms
      set.

      signedAttrs is a collection of attributes that are signed.  The
      field is optional, but it MUST be present if the content type of
      the EncapsulatedContentInfo value being signed is not id-data.
      SignedAttributes MUST be DER encoded, even if the rest of the
      structure is BER encoded.  Useful attribute types, such as signing
      time, are defined in Section 11.  If the field is present, it MUST
      contain, at a minimum, the following two attributes:

         A content-type attribute having as its value the content type
         of the EncapsulatedContentInfo value being signed.  Section
         11.1 defines the content-type attribute.  However, the
         content-type attribute MUST NOT be used as part of a
         countersignature unsigned attribute as defined in Section 11.4.

         A message-digest attribute, having as its value the message
         digest of the content.  Section 11.2 defines the message-digest
         attribute.

      signatureAlgorithm identifies the signature algorithm, and any
      associated parameters, used by the signer to generate the digital
      signature.

      signature is the result of digital signature generation, using the
      message digest and the signer's private key.  The details of the
      signature depend on the signature algorithm employed.

      unsignedAttrs is a collection of attributes that are not signed.
      The field is optional.  Useful attribute types, such as
      countersignatures, are defined in Section 11.

   The fields of type SignedAttribute and UnsignedAttribute have the
   following meanings:

      attrType indicates the type of attribute.  It is an object
      identifier.

      attrValues is a set of values that comprise the attribute.  The
      type of each value in the set can be determined uniquely by
      attrType.  The attrType can impose restrictions on the number of
      items in the set.

5.4.  Message Digest Calculation Process

   The message digest calculation process computes a message digest on
   either the content being signed or the content together with the
   signed attributes.  In either case, the initial input to the message
   digest calculation process is the "value" of the encapsulated content
   being signed.  Specifically, the initial input is the
   encapContentInfo eContent OCTET STRING to which the signing process
   is applied.  Only the octets comprising the value of the eContent
   OCTET STRING are input to the message digest algorithm, not the tag
   or the length octets.

   The result of the message digest calculation process depends on
   whether the signedAttrs field is present.  When the field is absent,
   the result is just the message digest of the content as described
   above.  When the field is present, however, the result is the message
   digest of the complete DER encoding of the SignedAttrs value
   contained in the signedAttrs field.  Since the SignedAttrs value,
   when present, must contain the content-type and the message-digest
   attributes, those values are indirectly included in the result.  The
   content-type attribute MUST NOT be included in a countersignature
   unsigned attribute as defined in Section 11.4.  A separate encoding
   of the signedAttrs field is performed for message digest calculation.
   The IMPLICIT [0] tag in the signedAttrs is not used for the DER
   encoding, rather an EXPLICIT SET OF tag is used.  That is, the DER
   encoding of the EXPLICIT SET OF tag, rather than of the IMPLICIT [0]
   tag, MUST be included in the message digest calculation along with
   the length and content octets of the SignedAttributes value.

   When the signedAttrs field is absent, only the octets comprising the
   value of the SignedData encapContentInfo eContent OCTET STRING (e.g.,
   the contents of a file) are input to the message digest calculation.
   This has the advantage that the length of the content being signed
   need not be known in advance of the signature generation process.

   Although the encapContentInfo eContent OCTET STRING tag and length
   octets are not included in the message digest calculation, they are
   protected by other means.  The length octets are protected by the
   nature of the message digest algorithm since it is computationally
   infeasible to find any two distinct message contents of any length
   that have the same message digest.

5.5.  Signature Generation Process

   The input to the signature generation process includes the result of
   the message digest calculation process and the signer's private key.
   The details of the signature generation depend on the signature
   algorithm employed.  The object identifier, along with any
   parameters, that specifies the signature algorithm employed by the
   signer is carried in the signatureAlgorithm field.  The signature
   value generated by the signer MUST be encoded as an OCTET STRING and
   carried in the signature field.

5.6.  Signature Verification Process

   The input to the signature verification process includes the result
   of the message digest calculation process and the signer's public
   key.  The recipient MAY obtain the correct public key for the signer
   by any means, but the preferred method is from a certificate obtained
   from the SignedData certificates field.  The selection and validation
   of the signer's public key MAY be based on certification path
   validation (see [PROFILE]) as well as other external context, but is
   beyond the scope of this document.  The details of the signature
   verification depend on the signature algorithm employed.

   The recipient MUST NOT rely on any message digest values computed by
   the originator.  If the SignedData signerInfo includes
   signedAttributes, then the content message digest MUST be calculated
   as described in Section 5.4.  For the signature to be valid, the
   message digest value calculated by the recipient MUST be the same as
   the value of the messageDigest attribute included in the
   signedAttributes of the SignedData signerInfo.

   If the SignedData signerInfo includes signedAttributes, then the
   content-type attribute value MUST match the SignedData
   encapContentInfo eContentType value.
*/
		var signerInfos = jCastle.cms.asn1.signerInfos.parse(obj);

		var signedData = {
			version: version,
			digestAlgorithms: digestAlgorithms,
			encapContentInfo: encapContentInfo,
			signerInfos: signerInfos
		};

		if (certs) signedData.certificates = certs;
		if (crls) signedData.crls = crls;

		// to do:
		// if certs exists then validation should be processed.
		// if crls exists then certs must be checked.

		var cmsInfo = {
			contentType: 'signedData',
			content: signedData
		};

		var valid = jCastle.cms.verifySignedData(cmsInfo);

		cmsInfo.validation = valid;

		return cmsInfo;
	},

/*
// export signedData

var cms_info = {
	contentType: "signedData",
	content: {
//		digestAlgorithms: [
//			"sha-256"
//		],
		signerInfos: [
			{
				digestAlgorithm: "sha-256",
				signatureAlgorithm: {
					algo: "RSA",
					encoding: {
						mode: "PKCS1_Type_2"
					}
				}
			}
		],
//		encapContentInfo: {
//			contentType: "data",
//			content: content
//		},
//		certificates: [],
//		crls: []
	}
};

// when signerInfos has just one info item:
var options = {
		cmsKey: {
		privateKey: private_key,
		password: password_for_private_key,
		certificate: cert_pem
	},
	certificates: [cert_pem] // for certificateSet, optional
	//crls: crls, // for crls, optional
	content: content_to_be_signed
};

// when signerInfos has items more than one:
var options = {
	cmsKeys: [
		{
			privateKey: privateKey01,
			password: password_for_private_key, // if private key pem is encrypted
			certificate: certificate01
		},
			{
			privateKey: privateKey02,
			password: password_for_private_key, // if private key pem is encrypted
			certificate: certificate02
		}
	],
	certificates: [certificate01, certificate02], // for certificateSet, optional
	crls: [], // for crls, optional

	content: content_to_be_signed
};

var cms = jCastle.cms.crate();
var cms_data = cms.exportCMS(cms_info, options);
*/

/*
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
	getDER: function(cmsInfo, options = {})
	{
		var ber_encoding = !!options.berEncoding;

		var cmsSchema = {
			type: jCastle.asn1.tagSequence,
			items: [{
				type: jCastle.asn1.tagOID,
				value: jCastle.oid.getOID('signedData')
			}, {
				type: 0x00,
				tagClass: jCastle.asn1.tagClassContextSpecific,
				constructed: true,
//				indefiniteLength: true,
				items: []
			}]
		};
				
		var signedDataSchema = {
			type: jCastle.asn1.tagSequence,
			items:[]
		};

		if (ber_encoding) {
			cmsSchema.items[1]. indefiniteLength = true;
			cmsSchema.indefiniteLength = true;
			signedDataSchema.indefiniteLength = true;
		}

		// preparation
		var digestAlgorithms = cmsInfo.content.digestAlgoritms || [];
		var signerInfos = cmsInfo.content.signerInfos;
		for (var i = 0; i < signerInfos.length; i++) {
			if (!('digestAlgorithm' in signerInfos[i])) signerInfos[i].digestAlgorithm = 'sha-1';
			//if (!jCastle.util.inArray(signerInfos[i].digestAlgorithm, digestAlgorithms)) 
			if (!digestAlgorithms.includes(signerInfos[i].digestAlgorithm))
				digestAlgorithms.push(signerInfos[i].digestAlgorithm);
		}

		var cmsKeys;

		if (signerInfos.length == 1 && 'cmsKey' in options) {
			cmsKeys = [options.cmsKey];
		} else {
			cmsKeys = options.cmsKeys;
		}

		if (!cmsKeys || !cmsKeys.length) throw jCastle.exception('NO_CERT_GIVEN', 'CMS104');
		if (signerInfos.length > cmsKeys.length) {
			while (signerInfos.length != cmsKeys.length) cmsKeys[cmsKeys.length] = cmsKeys[cmsKeys.length - 1];
		}

		var encapContentInfo;

		if ('content' in options) encapContentInfo = {
			content: options.content,
			contentType: options.contentType || 'data'
		};
		else encapContentInfo =  cmsInfo.content.encapContentInfo;
		if (!('contentType' in encapContentInfo)) encapContentInfo.contentType = 'data';
		encapContentInfo.content = jCastle.cms.content.getDER(encapContentInfo.content, options);

		var certificates;

		if ('certificates' in options) certificates = options.certificates;
		else certificates = cmsInfo.content.certificates;

		var crls;

		if ('crls' in options) crls = options.crls;
		else crls = cmsInfo.content.crls;

		// version
		var version = 'version' in cmsInfo.content ? cmsInfo.content.version : jCastle.cms.version.signedData(signerInfos, encapContentInfo, certificates, crls);
		signedDataSchema.items.push({
			type: jCastle.asn1.tagInteger,
			intVal: version
		});

		// digestAlgorithms
		var digestAlgorithmsSchema = {
			type: jCastle.asn1.tagSet,
			items:[]
		};		
		for (var i = 0; i < digestAlgorithms.length; i++) {
			digestAlgorithmsSchema.items.push({
				type: jCastle.asn1.tagSequence,
				items: [{
					type: jCastle.asn1.tagOID,
					value: jCastle.oid.getOID(digestAlgorithms[i])
				}

				, {
					type: jCastle.asn1.tagNull,
					value: null
				}

			]
			});
		}
		signedDataSchema.items.push(digestAlgorithmsSchema);

		// encapContentInfo
/*
      SEQUENCE (2 elem)
        OBJECT IDENTIFIER 1.2.840.113549.1.7.1 data (PKCS #7)
        [0] (1 elem)
          OCTET STRING imgg
*/
		// console.log(encapContentInfo);

		var encapContentInfoSchema = jCastle.cms.asn1.encapContentInfo.schema(encapContentInfo, options);
		signedDataSchema.items.push(encapContentInfoSchema);

		// certificates
		if (certificates && certificates.length) {
			var certSchema = {
				type: 0,
				tagClass: jCastle.asn1.tagClassContextSpecific,
				constructed: true,
				items:[]
			};
			for (var i = 0; i < certificates.length; i++) {
				var der = jCastle.certificate.getDER(certificates[i]);
				certSchema.items.push(der);
			}
			signedDataSchema.items.push(certSchema);
		}

		// crls
		if (crls && crls.length) {
			var crlsSchema = {
				type: 1,
				tagClass: jCastle.asn1.tagClassContextSpecific,
				constructed: true,
				items:[]
			};
			for (var i = 0; i < crls.length; i++) {
				var der = jCastle.certificate.getDER(crls[i]);
				crlsSchema.items.push(der);
			}
			signedDataSchema.items.push(crlsSchema);
		}

		// signerInfos
		var signerInfosSchema = jCastle.cms.asn1.signerInfos.schema(signerInfos, encapContentInfo.content, encapContentInfo.contentType, cmsKeys);
		signedDataSchema.items.push(signerInfosSchema);
		cmsSchema.items[1].items.push(signedDataSchema);

		var asn1 = new jCastle.asn1();
		var der = asn1.getDER(cmsSchema);

		return der;
	}
};

/*
// export envelopedData
var cms_info = {
	contentType: "envelopedData",
	content: {
		recipientInfos: [
			{
				type: "keyTransRecipientInfo",
				keyEncryptionAlgorithm: {
					algo: "RSA",
					encoding: {
						mode: "PKCS1_OAEP",
						hashAlgo: "sha-1",
						//mgf: "mgf1",
						//label: ""
					}
				}
			},
			{
				type: "keyAgreeRecipientInfo",
				keyEncryptionAlgorithm: {
					algo: "dhSinglePass-stdDH-sha1kdf-scheme",
					wrap: "3des"
				}
			},
			{
				type: "passwordRecipientInfo",
				keyDerivationAlgorithm: {
					prfHash: 'sha-512'
				},
				keyEncryptionAlgorithm: "aes-256"
			},
			{
				type: 'kekRecipientInfo',
				keyEncryptionAlgorithm: 'aes-256'
			}
		],
		encryptedContentInfo: {
			//contentType:"data",
			contentEncryptionAlgorithm: {
				algo: "des-EDE3-CBC"
			}
		}
	}
};
	
	
// need parameters:

// when multiple recipients:
var options = {
	content: content_to_be_encrypted,
	
	certificates: [cert1, cert2], // for originatorInfo, optional
	crls: [], // for originatorInfo, optional
	
	cmsKeys: [
		{ 
			// keyTransRecipientInfo
			privateKey: privkey_for_ktri_kari,
			password: password_for_privkey,
			
			recipient: {
				// keyTransRecipientInfo
				certificate: party_rsa_certificate
			}
		},
		{
			// keyAgreeRecipientInfo
			privateKey: privkey_for_ktri_kari,
			password: password_for_privkey,
			ephemeralPrivateKey: ephemeral_privkey, // if algo is mqvSinglePass-stdDH
		
			recipient: {
				// keyTransRecipientInfo
				certificate: party_rsa_certificate,
				//ephemerialPublicKey: party_ephemeral_pubkey // if algo is mqvSinglePass-stdDH
			}
		// or
		//	recipients: [ //keyAgreeRecipientInfo can has multiple recipients
		//		{
		//			//keyAgreeRecipientInfo
		//			certificate: party_ec_certificate1
		//		},
		//		{
		//			certificate: party_ec_certificate2
		//		}
		//	]

		},
		{
			// kekRecipientInfo
			wrappingKey: wrapkey
		},
		{
			// passwordRecipientInfo
			password: password
		}
	
	]
};


// when one recipient:
var options = {
	content: content_to_be_encrypted,
	
	certificates: [], // for originatorInfo, optional
	//crls: [], // for originatorInfo, optional
	
	cmsKey: { 
		// keyTransRecipientInfo
		privateKey: privkey_for_ktri_kari,
		password: password_for_privkey,
			
		recipient: {
			// keyTransRecipientInfo
			certificate: party_rsa_certificate
		}
	}
};

// parse envelopedData
var options = {
	cmsKey: {
		privateKey: privkey_for_ktri_kari,
		password: password_for_privkey,
	}
};

// or
var options = {
	privateKey: privkey_for_ktri_kari, // for keyTransRecipientInfo & keyAgreeRecipientInfo
	password: password_for_privkey, // for parsing privateKey or for passwordRecipientInfo
	ephemeralPrivateKey: ephemeral_privkey, // for keyAgreeRecipientInfo if algo is mqvSinglePass-stdDH
	certificate: certificate_for kari, // for keyAgreeRecipientInfo
	wrappingKey: wrapkey, // for kekRecipientInfo
};
*/
jCastle.cms.contentType.envelopedData = {
/*
6.  Enveloped-data Content Type

   The enveloped-data content type consists of an encrypted content of
   any type and encrypted content-encryption keys for one or more
   recipients.  The combination of the encrypted content and one
   encrypted content-encryption key for a recipient is a "digital
   envelope" for that recipient.  Any type of content can be enveloped
   for an arbitrary number of recipients using any of the supported key
   management techniques for each recipient.

   The typical application of the enveloped-data content type will
   represent one or more recipients' digital envelopes on content of the
   data or signed-data content types.

   Enveloped-data is constructed by the following steps:

   1.  A content-encryption key for a particular content-encryption
       algorithm is generated at random.

   2.  The content-encryption key is encrypted for each recipient.  The
       details of this encryption depend on the key management algorithm
       used, but four general techniques are supported:

         key transport:  the content-encryption key is encrypted in the
         recipient's public key;

         key agreement:  the recipient's public key and the sender's
         private key are used to generate a pairwise symmetric key, then
         the content-encryption key is encrypted in the pairwise
         symmetric key;

         symmetric key-encryption keys:  the content-encryption key is
         encrypted in a previously distributed symmetric key-encryption
         key; and

         passwords: the content-encryption key is encrypted in a key-
         encryption key that is derived from a password or other shared
         secret value.

   3.  For each recipient, the encrypted content-encryption key and
       other recipient-specific information are collected into a
       RecipientInfo value, defined in Section 6.2.

   4.  The content is encrypted with the content-encryption key.
       Content encryption may require that the content be padded to a
       multiple of some block size; see Section 6.3.

   5.  The RecipientInfo values for all the recipients are collected
       together with the encrypted content to form an EnvelopedData
       value as defined in Section 6.1.

   A recipient opens the digital envelope by decrypting one of the
   encrypted content-encryption keys and then decrypting the encrypted
   content with the recovered content-encryption key.

   This section is divided into four parts.  The first part describes
   the top-level type EnvelopedData, the second part describes the per-
   recipient information type RecipientInfo, and the third and fourth
   parts describe the content-encryption and key-encryption processes.

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
*/
	parse: function(cmsSequence, options = {})
	{
/*
      EnvelopedData ::= SEQUENCE {
        version CMSVersion,
        originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
        recipientInfos RecipientInfos,
        encryptedContentInfo EncryptedContentInfo,
        unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }
*/
		// preparation
		var cmsKey = options.cmsKey;

		var explicit = cmsSequence.items[1];
		var sequence = explicit.items[0];
		var idx = 0;
		var envelopedData = {};

//console.log(sequence);

		var obj = sequence.items[idx++];

		// version
/*
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
*/
		jCastle.assert(obj.type, jCastle.asn1.tagInteger, 'INVALID_DATA_TYPE', 'CMS003');

		var version = obj.intVal;
		envelopedData.version = version;

		obj = sequence.items[idx++];

		// originatorInfo
/*
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
*/
		if (obj.tagClass == jCastle.asn1.tagClassContextSpecific && obj.type == 0x00) {
			var originatorInfo = jCastle.cms.asn1.originatorInfo.parse(obj, options);
			envelopedData.originatorInfo = originatorInfo;

			obj = sequence.items[idx++];
		}

		// recipientInfos
/*
      recipientInfos is a collection of per-recipient information.
      There MUST be at least one element in the collection.
*/
//		var recipientInfos = jCastle.cms.asn1.recipientInfos.parse(obj, options);
		var recipientInfos = jCastle.cms.asn1.recipientInfos.parse(obj, cmsKey);
		envelopedData.recipientInfos = recipientInfos;

		obj = sequence.items[idx++];

		// encryptedContentInfo
/*
      encryptedContentInfo is the encrypted content information.

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
		var encryptedContentInfo = jCastle.cms.asn1.encryptedContentInfo.parse(obj, options);	
		envelopedData.encryptedContentInfo = encryptedContentInfo;

		obj = sequence.items[idx++];

		// decrypt content
		var decryptedKey = null;
		for (var i = 0; i < recipientInfos.length; i++) {
			if ('decryptedKey' in recipientInfos[i]) {
				decryptedKey = recipientInfos[i].decryptedKey;
				break;
			}
		}

		if (decryptedKey) {
			var enc_algo_info = encryptedContentInfo.contentEncryptionAlgorithm;
			var algo = enc_algo_info.algo;
			var algoInfo = 'algoInfo' in enc_algo_info ? enc_algo_info.algoInfo : jCastle.pbe.getAlgorithmInfo(algo);
			var params = enc_algo_info.params;

//console.log(encryptedContentInfo);

			if (!Buffer.isBuffer(decryptedKey)) decryptedKey = Buffer.from(decryptedKey, 'latin1');

			params.key = decryptedKey;
			params.mode = algoInfo.mode;
			params.isEncryption = false;
			params.padding = 'pkcs7';

			var crypto = new jCastle.mcrypt(algoInfo.algo);
			crypto.start(params);
			crypto.update(encryptedContentInfo.encryptedContent);
			var content = crypto.finalize();

			envelopedData.encryptedContentInfo.content = content;
		}


		// unprotectedAttrs
/*
      unprotectedAttrs is a collection of attributes that are not
      encrypted.  The field is optional.  Useful attribute types are
      defined in Section 11.
*/
		if (sequence.items[idx] && sequence.items[idx].tagClass == jCastle.asn1.tagClassContextSpecific) {
			jCastle.assert(sequence.items[idx].type, 0x01, 'UNKNOWN_TAG_TYPE', 'CMS004');
			var unprotectedAttrs = jCastle.cms.asn1.attrs.parse(sequence.items[idx]);
			envelopedData.unprotectedAttrs = unprotectedAttrs;
		}

		var cmsInfo = {
			contentType: 'envelopedData',
			content: envelopedData
		};

		return cmsInfo;
	},

/*
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
*/
	getDER: function(cmsInfo, options = {})
	{
		var ber_encoding = !!options.berEncoding;

		var cmsSchema = {
			type: jCastle.asn1.tagSequence,
			items: [{
				type: jCastle.asn1.tagOID,
				value: jCastle.oid.getOID('envelopedData')
			}, {
				type: 0x00,
				tagClass: jCastle.asn1.tagClassContextSpecific,
				constructed: true,
				items: []
			}]
		};

		var envelopedDataSchema = {
			type: jCastle.asn1.tagSequence,
			items:[]
		};

		if (ber_encoding) {
			cmsSchema.items[1].indefiniteLength = true;
			cmsSchema.indefiniteLength = true;
			envelopedDataSchema.indefiniteLength = true;
		}

		// preparation

		var originatorInfo = 'originatorInfo' in cmsInfo.content ? cmsInfo.content.originatorInfo : {};
		
//		var certificates = 'certificates' in options ? options.certificates : ('certificates' in originatorInfo ? originatorInfo.certificates : []);
//		var crls = 'crls' in options ? options.crls : ('crls' in originatorInfo ? originatorInfo.crls : []);
		if ('certificates' in options) originatorInfo.certificates = options.certificates;
		if ('crls' in options) originatorInfo.crls = options.crls;

		var recipientInfos = cmsInfo.content.recipientInfos;

		var unprotectedAttrs = 'unprotectedAttrs' in cmsInfo.content ? cmsInfo.content.unprotectedAttrs : [];

		var cmsKeys;

		if (recipientInfos.length == 1 && 'cmsKey' in options) {
			cmsKeys = [options.cmsKey];
		} else {
			cmsKeys = options.cmsKeys;
		}

		if (recipientInfos.length > cmsKeys.length) {
			while (recipientInfos.length != cmsKeys.length) 
				cmsKeys[cmsKeys.length] = cmsKeys[cmsKeys.lenggh - 1];
		}

		// version
		var version = 'version' in cmsInfo.content ? cmsInfo.content.version : 
			jCastle.cms.version.envelopedData(
				originatorInfo, 
				recipientInfos,
				unprotectedAttrs
			);
		envelopedDataSchema.items.push({
			type: jCastle.asn1.tagInteger,
			intVal: version
		});

		// originatorInfo
		if (('certificates' in originatorInfo && originatorInfo.certificates.length) ||
			('crls' in originatorInfo && originatorInfo.crls.length)) {
			var originatorInfoSchema = jCastle.cms.asn1.originatorInfo.schema(originatorInfo, options);

			envelopedDataSchema.items.push(originatorInfoSchema);
		}

		// key must be made first
		var encryptedContentInfo = cmsInfo.content.encryptedContentInfo;
		if ('content' in options) encryptedContentInfo.content = options.content;
		if (!('contentType' in encryptedContentInfo)) encryptedContentInfo.contentType = 'contentType' in options ? options.contentType : 'data';
		encryptedContentInfo.content = jCastle.cms.content.getDER(encryptedContentInfo.content, options);

		var enc_algo_info = encryptedContentInfo.contentEncryptionAlgorithm;
		var algo = enc_algo_info.algo;
		if (!('algoInfo' in enc_algo_info)) enc_algo_info.algoInfo = jCastle.pbe.getAlgorithmInfo(algo);

		var params = jCastle.cms.fn.getEncryptionParameters(enc_algo_info, options);

		var key_size = 'keySize' in params ? params.keySize : enc_algo_info.algoInfo.keySize;

		var encryptKey;

		if ('encryptKey' in options) {
			encryptKey = Buffer.from(options.encryptKey, 'latin1');
			//if (encryptKey.length != key_size) throw jCastle.exception('INVALID_KEYSIZE', 'CMS010');
			//while (encryptKey.length < key_size) encryptKey.push(0x00);
			if (encryptKey.length < key_size) encryptKey = Buffer.concat([encryptKey, Buffer.alloc(key_size - encryptKey.length)]);
		} else {
			var prng = jCastle.prng.create();
			encryptKey = prng.nextBytes(key_size);
		}

		// recipientInfos
		var recipientInfosSchema = jCastle.cms.asn1.recipientInfos.schema(recipientInfos, encryptKey, cmsKeys, options);
		envelopedDataSchema.items.push(recipientInfosSchema);

		// encryptedContentInfo
		var encryptedContentInfoSchema = jCastle.cms.asn1.encryptedContentInfo.schema(encryptedContentInfo, encryptKey, params, ber_encoding);
		envelopedDataSchema.items.push(encryptedContentInfoSchema);

		// unprotectedAttrs
		if (unprotectedAttrs.length) {
			envelopedDataSchema.items.push(jCastle.cms.asn1.attrs.schema(unprotectedAttrs, 0x01));
		}

		cmsSchema.items[1].items.push(envelopedDataSchema);
//console.log(cmsSchema);
//console.log(JSON.stringify(cmsSchema));
		var asn1 = new jCastle.asn1();
		var der = asn1.getDER(cmsSchema);

		return der;

	}
};

jCastle.cms.contentType.digestedData = {
/*
7.  Digested-data Content Type

   The digested-data content type consists of content of any type and a
   message digest of the content.

   Typically, the digested-data content type is used to provide content
   integrity, and the result generally becomes an input to the
   enveloped-data content type.

   The following steps construct digested-data:

   1.  A message digest is computed on the content with a message-digest
       algorithm.

   2.  The message-digest algorithm and the message digest are collected
       together with the content into a DigestedData value.

   A recipient verifies the message digest by comparing the message
   digest to an independently computed message digest.

   The following object identifier identifies the digested-data content
   type:

      id-digestedData OBJECT IDENTIFIER ::= { iso(1) member-body(2)
          us(840) rsadsi(113549) pkcs(1) pkcs7(7) 5 }

   The digested-data content type shall have ASN.1 type DigestedData:

      DigestedData ::= SEQUENCE {
        version CMSVersion,
        digestAlgorithm DigestAlgorithmIdentifier,
        encapContentInfo EncapsulatedContentInfo,
        digest Digest }

      Digest ::= OCTET STRING

   The fields of type DigestedData have the following meanings:

      version is the syntax version number.  If the encapsulated content
      type is id-data, then the value of version MUST be 0; however, if
      the encapsulated content type is other than id-data, then the
      value of version MUST be 2.

      digestAlgorithm identifies the message digest algorithm, and any
      associated parameters, under which the content is digested.  The
      message-digesting process is the same as in Section 5.4 in the
      case when there are no signed attributes.

      encapContentInfo is the content that is digested, as defined in
      Section 5.2.

      digest is the result of the message-digesting process.

   The ordering of the digestAlgorithm field, the encapContentInfo
   field, and the digest field makes it possible to process a
   DigestedData value in a single pass.
*/
	parse: function(cmsSequence, options = {})
	{
/*
SEQUENCE (2 elem)
	OBJECT IDENTIFIER 1.2.840.113549.1.7.5 digestedData (PKCS #7)
	[0] (1 elem)
		SEQUENCE (4 elem)
			INTEGER 0
			SEQUENCE (1 elem)
				OBJECT IDENTIFIER 1.3.14.3.2.26 sha1 (OIW)
			SEQUENCE (2 elem)
				OBJECT IDENTIFIER 1.2.840.113549.1.7.1 data (PKCS #7)
				[0] (1 elem)
					OCTET STRING (39 byte) 436F6E74656E742D547970653A20746578742F706C61696E0D0A0D0A68656C6C6F2077…
			OCTET STRING (20 byte) CFCC1DAF7AC0B723C4D5249B6E3C64D7B4C51F26

*/
		var explicit = cmsSequence.items[1];
		var sequence = explicit.items[0];
		var idx = 0;
		var digestedData = {};

		var obj = sequence.items[idx++];

		// version
		digestedData.version = obj.intVal;
		obj = sequence.items[idx++];

		// digestAlgorithm
		digestedData.digestAlgorithm = jCastle.digest.getValidAlgoName(jCastle.oid.getName(obj.items[0].value));
		obj = sequence.items[idx++];

		// encapContentInfo
		digestedData.encapContentInfo = jCastle.cms.asn1.encapContentInfo.parse(obj, options);
		obj = sequence.items[idx++];

		// digest
		digestedData.digest = Buffer.from(obj.value, 'latin1');

		var cmsInfo = {
			contentType: 'digestedData',
			content: digestedData
		};

		var valid = jCastle.cms.verifyDigestedData(cmsInfo);

		cmsInfo.validation = valid;

		return cmsInfo;
	},

	getDER: function(cmsInfo, options = {})
	{
/*
	var cmsInfo = {
		contentType: "digestedData",
		content: {
			digestAlgorithm: "sha-1",
			encapContentInfo: {
				contentType: "data",
				content: "hello world"
			}
		}
	};
*/

/*
      DigestedData ::= SEQUENCE {
        version CMSVersion,
        digestAlgorithm DigestAlgorithmIdentifier,
        encapContentInfo EncapsulatedContentInfo,
        digest Digest }

      Digest ::= OCTET STRING

   The fields of type DigestedData have the following meanings:

      version is the syntax version number.  If the encapsulated content
      type is id-data, then the value of version MUST be 0; however, if
      the encapsulated content type is other than id-data, then the
      value of version MUST be 2.

*/
		var ber_encoding = !!options.berEncoding;

		var cmsSchema = {
			type: jCastle.asn1.tagSequence,
			items: [{
				type: jCastle.asn1.tagOID,
				value: jCastle.oid.getOID('digestedData')
			}, {
				type: 0x00,
				tagClass: jCastle.asn1.tagClassContextSpecific,
				constructed: true,
				items: []
			}]
		};

		var encapContentInfo;

		if ('content' in options) {
			encapContentInfo = {
				content: options.content,
				contentType: options.contentType || 'data'
			};
		} else encapContentInfo =  cmsInfo.content.encapContentInfo;
		encapContentInfo.content = jCastle.cms.content.getDER(encapContentInfo.content, options);
		if (!('contentType' in encapContentInfo)) encapContentInfo.contentType = 'data';

		var digestedDataSchema = {
			type: jCastle.asn1.tagSequence,
			items:[]
		};

		if (ber_encoding) {
			cmsSchema.items[1].indefiniteLength = true;
			cmsSchema.indefiniteLength = true;
			digestedDataSchema.indefiniteLength = true;
		}

		// version
		digestedDataSchema.items.push({
			type: jCastle.asn1.tagInteger,
			intVal: encapContentInfo.contentType == 'data' ? 0 : 2
		});

		// digestAlgorithm
		var digestAlgorithm = 'digestAlgorithm' in cmsInfo.content ? jCastle.digest.getValidAlgoName(cmsInfo.content.digestAlgorithm) : 'sha-1';
		digestedDataSchema.items.push({
			type: jCastle.asn1.tagSequence,
			items: [{
				type: jCastle.asn1.tagOID,
				value: jCastle.oid.getOID(digestAlgorithm)
			}]
		});

		// encapContentInfo
		var encapContentInfoSchema = jCastle.cms.asn1.encapContentInfo.schema(encapContentInfo, options);
		digestedDataSchema.items.push(encapContentInfoSchema);

		// digest
		var md = new jCastle.digest(digestAlgorithm);
		var eContent = Buffer.from(encapContentInfoSchema.items[1].items[0].value, 'latin1');
		var digest = md.digest(eContent);
		digestedDataSchema.items.push({
			type: jCastle.asn1.tagOctetString,
			value: digest
		});


		cmsSchema.items[1].items.push(digestedDataSchema);
//console.log(cmsSchema);
//console.log(JSON.stringify(cmsSchema));
		var asn1 = new jCastle.asn1();
		var der = asn1.getDER(cmsSchema);

		return der;
	}
};

jCastle.cms.contentType.encryptedData = {
/*
8.  Encrypted-data Content Type

   The encrypted-data content type consists of encrypted content of any
   type.  Unlike the enveloped-data content type, the encrypted-data
   content type has neither recipients nor encrypted content-encryption
   keys.  Keys MUST be managed by other means.

   The typical application of the encrypted-data content type will be to
   encrypt the content of the data content type for local storage,
   perhaps where the encryption key is derived from a password.

   The following object identifier identifies the encrypted-data content
   type:

      id-encryptedData OBJECT IDENTIFIER ::= { iso(1) member-body(2)
          us(840) rsadsi(113549) pkcs(1) pkcs7(7) 6 }

   The encrypted-data content type shall have ASN.1 type EncryptedData:

      EncryptedData ::= SEQUENCE {
        version CMSVersion,
        encryptedContentInfo EncryptedContentInfo,
        unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }

   The fields of type EncryptedData have the following meanings:

      version is the syntax version number.  If unprotectedAttrs is
      present, then the version MUST be 2.  If unprotectedAttrs is
      absent, then version MUST be 0.

      encryptedContentInfo is the encrypted content information, as
      defined in Section 6.1.

      unprotectedAttrs is a collection of attributes that are not
      encrypted.  The field is optional.  Useful attribute types are
      defined in Section 11.
*/
	parse: function(cmsSequence, options = {})
	{
/*
SEQUENCE (2 elem)
  OBJECT IDENTIFIER 1.2.840.113549.1.7.6 encryptedData (PKCS #7)
  [0] (1 elem)
    SEQUENCE (2 elem)
      INTEGER 0
      SEQUENCE (3 elem)
        OBJECT IDENTIFIER 1.2.840.113549.1.7.1 data (PKCS #7)
        SEQUENCE (2 elem)
          OBJECT IDENTIFIER 2.16.840.1.101.3.4.1.2 aes128-CBC (NIST Algorithm)
          OCTET STRING (16 byte) ACD6965B617E6FEA51FF7B7BDF61F740
        [0] (1 elem)
          OCTET STRING (16 byte) 2E36E2D983FE1EB865BC64BD4AA38B73
*/
		var explicit = cmsSequence.items[1];
		var sequence = explicit.items[0];
/*
      EncryptedData ::= SEQUENCE {
        version CMSVersion,
        encryptedContentInfo EncryptedContentInfo,
        unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }
*/
		var idx = 0;
		var encryptedData = {};

		var obj = sequence.items[idx++];

		// cmsVersion
		jCastle.assert(obj.type, jCastle.asn1.tagInteger, 'INVALID_DATA_TYPE', 'CMS006');

		var cmsVersion = obj.intVal;

		obj = sequence.items[idx++];

		// encryptedContentInfo
		var encryptedContentInfo = jCastle.cms.asn1.encryptedContentInfo.parse(obj, options);
		encryptedData.encryptedContentInfo = encryptedContentInfo;

		// unprotectedAttrs
		if (sequence.items[idx] && sequence.items[idx].tagClass == jCastle.asn1.tagClassContextSpecific) {
			jCastle.assert(sequence.items[idx].type, 0x01, 'UNKNOWN_TAG_TYPE', 'CMS007');
			var unprotectedAttrs = jCastle.cms.asn1.attrs.parse(sequence.items[idx]);
			encryptedData.unprotectedAttrs = unprotectedAttrs;
		}

		var algo_type = encryptedContentInfo.contentEncryptionAlgorithm.type;
		var encryptedContent = Buffer.from(encryptedContentInfo.encryptedContent, 'latin1');

		// console.log('algo_type: ', algo_type);

		// if content encryption key is provided
		if (algo_type == 'enc' && 
			('encryptKey' in options || 'contentEncryptionKey' in options || 'cek' in options)) {
			var cek = Buffer.from(options.encryptKey || options.contentEncryptionKey || options.cek, 'latin1');

			var enc_algo_info = encryptedContentInfo.contentEncryptionAlgorithm;
			var algo = enc_algo_info.algo;
			var algoInfo = 'algoInfo' in enc_algo_info ? enc_algo_info.algoInfo : jCastle.pbe.getAlgorithmInfo(algo);
			var params = enc_algo_info.params;

			params.key = cek;
			params.mode = algoInfo.mode;
			params.isEncryption = false;
			params.padding = 'pkcs7';

			var crypto = new jCastle.mcrypt(algoInfo.algo);
			crypto.start(params);
			crypto.update(encryptedContent);
			var content = crypto.finalize();

			encryptedData.encryptedContentInfo.content = content;

		} else if (algo_type != 'enc' && 'password' in options) {
			var password = Buffer.from(options.password, 'latin1');
			var pbe_info = encryptedContentInfo.contentEncryptionAlgorithm;
			var content;

			switch (algo_type) {
				case 'pkcs5PBKDF2':			
					content = jCastle.pbe.pbes2.decrypt(
						pbe_info, 
						password,
						encryptedContent);
						break;
				case 'pkcs5PBKDF1':
					content = jCastle.pbe.pbes1.decrypt(
						pbe_info,
						password,
						encryptedContent);
						break;
				case 'pkcs12DeriveKey':
					content = jCastle.pbe.pkcs12pbes.decrypt(
						pbe_info,
						password,
						encryptedContent);
						break;	
				default:
					throw jCastle.exception("UNKNOWN_KDF_TYPE", 'CMS070');
			}

			encryptedData.encryptedContentInfo.content = content;
		}

		var cmsInfo = {
			contentType: 'encryptedData',
			content: encryptedData
		};

		return cmsInfo;
	},

	getDER: function(cmsInfo, options = {})
	{
/*
      EncryptedData ::= SEQUENCE {
        version CMSVersion,
        encryptedContentInfo EncryptedContentInfo,
        unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }

   The fields of type EncryptedData have the following meanings:

      version is the syntax version number.  If unprotectedAttrs is
      present, then the version MUST be 2.  If unprotectedAttrs is
      absent, then version MUST be 0.
*/
/*
SEQUENCE (2 elem)
  OBJECT IDENTIFIER 1.2.840.113549.1.7.6 encryptedData (PKCS #7)
  [0] (1 elem)
    SEQUENCE (2 elem)
      INTEGER 0
      SEQUENCE (3 elem)
        OBJECT IDENTIFIER 1.2.840.113549.1.7.1 data (PKCS #7)
        SEQUENCE (2 elem)
          OBJECT IDENTIFIER 2.16.840.1.101.3.4.1.2 aes128-CBC (NIST Algorithm)
          OCTET STRING (16 byte) ACD6965B617E6FEA51FF7B7BDF61F740
        [0] (1 elem)
          OCTET STRING (16 byte) 2E36E2D983FE1EB865BC64BD4AA38B73
*/
		var ber_encoding = !!options.berEncoding;

		var cmsSchema = {
			type: jCastle.asn1.tagSequence,
			items: [{
				type: jCastle.asn1.tagOID,
				value: jCastle.oid.getOID('encryptedData')
			}, {
				type: 0x00,
				tagClass: jCastle.asn1.tagClassContextSpecific,
				constructed: true,
//				items: [],
//				indefiniteLength: true
				items: []
//			}],
//			indefiniteLength: true
			}]
		};

		if (ber_encoding) {
			cmsSchema.items[1].indefiniteLength = true;
			cmsSchema.indefiniteLength = true;
			cmsSchema.indefiniteLength = true;
		}

		var encryptedDataSchema = {
			type: jCastle.asn1.tagSequence,
			items:[]
		};

		var unprotectedAttrs = cmsInfo.content.unprotectedAttrs || [];

		// version
		var version = unprotectedAttrs.length ? 2 : 0;
		encryptedDataSchema.items.push({
			type: jCastle.asn1.tagInteger,
			intVal: version
		});

		// encryptedContentInfo
		var encryptedContentInfo = cmsInfo.content.encryptedContentInfo;
		var enc_algo_info = encryptedContentInfo.contentEncryptionAlgorithm;
		var enc_algo = enc_algo_info.algo;
		var is_pbe = false;
		var params = {};

		try {
			algo_info = jCastle.pbe.getAlgorithmInfo(enc_algo);
			if (!('algoInfo' in enc_algo_info)) enc_algo_info.algoInfo = algo_info;
		} catch (ex) {
			is_pbe = true;
		}

		if (!('content' in encryptedContentInfo)) encryptedContentInfo.content = options.content;
		if (!('contentType' in encryptedContentInfo)) encryptedContentInfo.contentType = 'contentType' in options ? options.contentType : 'data';
		encryptedContentInfo.content = jCastle.cms.content.getDER(encryptedContentInfo.content, options);

		
		var password, encryptKey;

		if (is_pbe) {
			if (!('password') in options) throw jCastle.exception('NO_PASSPHRASE', 'CMS071');
			password = Buffer.from(options.password, 'latin1');
		} else {
			params = jCastle.cms.fn.getEncryptionParameters(enc_algo_info, options);
			// var key_size = 'keySize' in params ? params.keySize : algoInfo.keySize;
			// var tagSize = 'tagSize' in params ? params.tagSize : 12; // default
			// params.tagSize = tagSize;

			if (!('encryptKey' in options) && !('contentEncryptionKey' in options) && !('cek' in options))
				throw jCastle.exception('KEY_NOT_SET', 'CMS011');
			encryptKey = Buffer.from(options.encryptKey || options.contentEncryptionKey || options.cek, 'latin1');
		}

		var encryptedContentInfoSchema = jCastle.cms.asn1.encryptedContentInfo.schema(
			encryptedContentInfo, 
			is_pbe ? password : encryptKey, 
			params, 
			ber_encoding);
		encryptedDataSchema.items.push(encryptedContentInfoSchema);

		// console.log('encryptedContentInfoSchema: ', encryptedContentInfoSchema);
		// console.log(JSON.stringify(encryptedContentInfoSchema), null, 4);

		// unprotectedAttrs
		if (unprotectedAttrs.length) {
			encryptedDataSchema.items.push(jCastle.cms.asn1.attrs.schema(unprotectedAttrs, 0x01));
		}

		cmsSchema.items[1].items.push(encryptedDataSchema);

		// console.log('cmsSchema: ', cmsSchema);
		// console.log(JSON.stringify(cmsSchema), null, 4);

		var asn1 = new jCastle.asn1();
		var der = asn1.getDER(cmsSchema);

		return der;
	}
};

jCastle.cms.contentType.authenticatedData = {
/*
9.  Authenticated-data Content Type

   The authenticated-data content type consists of content of any type,
   a message authentication code (MAC), and encrypted authentication
   keys for one or more recipients.  The combination of the MAC and one
   encrypted authentication key for a recipient is necessary for that
   recipient to verify the integrity of the content.  Any type of
   content can be integrity protected for an arbitrary number of
   recipients.

   The process by which authenticated-data is constructed involves the
   following steps:

   1.  A message-authentication key for a particular message-
       authentication algorithm is generated at random.

   2.  The message-authentication key is encrypted for each recipient.
       The details of this encryption depend on the key management
       algorithm used.

   3.  For each recipient, the encrypted message-authentication key and
       other recipient-specific information are collected into a
       RecipientInfo value, defined in Section 6.2.

   4.  Using the message-authentication key, the originator computes a
       MAC value on the content.  If the originator is authenticating
       any information in addition to the content (see Section 9.2), a
       message digest is calculated on the content, the message digest
       of the content and the other information are authenticated using
       the message-authentication key, and the result becomes the "MAC
       value".

9.1.  AuthenticatedData Type

   The following object identifier identifies the authenticated-data
   content type:

      id-ct-authData OBJECT IDENTIFIER ::= { iso(1) member-body(2)
         us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16)
         ct(1) 2 }

   The authenticated-data content type shall have ASN.1 type
   AuthenticatedData:

      AuthenticatedData ::= SEQUENCE {
        version CMSVersion,
        originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
        recipientInfos RecipientInfos,
        macAlgorithm MessageAuthenticationCodeAlgorithm,
        digestAlgorithm [1] DigestAlgorithmIdentifier OPTIONAL,
        encapContentInfo EncapsulatedContentInfo,
        authAttrs [2] IMPLICIT AuthAttributes OPTIONAL,
        mac MessageAuthenticationCode,
        unauthAttrs [3] IMPLICIT UnauthAttributes OPTIONAL }

      AuthAttributes ::= SET SIZE (1..MAX) OF Attribute

      UnauthAttributes ::= SET SIZE (1..MAX) OF Attribute

      MessageAuthenticationCode ::= OCTET STRING

   The fields of type AuthenticatedData have the following meanings:

      version is the syntax version number.  The version MUST be
      assigned as follows:

         IF (originatorInfo is present) AND
            ((any certificates with a type of other are present) OR
            (any crls with a type of other are present))
         THEN version is 3
         ELSE
            IF ((originatorInfo is present) AND
               (any version 2 attribute certificates are present))
            THEN version is 1
            ELSE version is 0

      originatorInfo optionally provides information about the
      originator.  It is present only if required by the key management
      algorithm.  It MAY contain certificates, attribute certificates,
      and CRLs, as defined in Section 6.1.

      recipientInfos is a collection of per-recipient information, as
      defined in Section 6.1.  There MUST be at least one element in the
      collection.

      macAlgorithm is a message authentication code (MAC) algorithm
      identifier.  It identifies the MAC algorithm, along with any
      associated parameters, used by the originator.  Placement of the
      macAlgorithm field facilitates one-pass processing by the
      recipient.

      digestAlgorithm identifies the message digest algorithm, and any
      associated parameters, used to compute a message digest on the
      encapsulated content if authenticated attributes are present.  The
      message digesting process is described in Section 9.2.  Placement
      of the digestAlgorithm field facilitates one-pass processing by
      the recipient.  If the digestAlgorithm field is present, then the
      authAttrs field MUST also be present.

      encapContentInfo is the content that is authenticated, as defined
      in Section 5.2.

      authAttrs is a collection of authenticated attributes.  The
      authAttrs structure is optional, but it MUST be present if the
      content type of the EncapsulatedContentInfo value being
      authenticated is not id-data.  If the authAttrs field is present,
      then the digestAlgorithm field MUST also be present.  The
      AuthAttributes structure MUST be DER encoded, even if the rest of
      the structure is BER encoded.  Useful attribute types are defined
      in Section 11.  If the authAttrs field is present, it MUST
      contain, at a minimum, the following two attributes:

         A content-type attribute having as its value the content type
         of the EncapsulatedContentInfo value being authenticated.
         Section 11.1 defines the content-type attribute.

         A message-digest attribute, having as its value the message
         digest of the content.  Section 11.2 defines the message-digest
         attribute.

      mac is the message authentication code.

      unauthAttrs is a collection of attributes that are not
      authenticated.  The field is optional.  To date, no attributes
      have been defined for use as unauthenticated attributes, but other
      useful attribute types are defined in Section 11.

9.2.  MAC Generation

   The MAC calculation process computes a message authentication code
   (MAC) on either the content being authenticated or a message digest
   of content being authenticated together with the originator's
   authenticated attributes.

   If the authAttrs field is absent, the input to the MAC calculation
   process is the value of the encapContentInfo eContent OCTET STRING.
   Only the octets comprising the value of the eContent OCTET STRING are
   input to the MAC algorithm; the tag and the length octets are
   omitted.  This has the advantage that the length of the content being
   authenticated need not be known in advance of the MAC generation
   process.

   If the authAttrs field is present, the content-type attribute (as
   described in Section 11.1) and the message-digest attribute (as
   described in Section 11.2) MUST be included, and the input to the MAC
   calculation process is the DER encoding of authAttrs.  A separate
   encoding of the authAttrs field is performed for message digest
   calculation.  The IMPLICIT [2] tag in the authAttrs field is not used
   for the DER encoding, rather an EXPLICIT SET OF tag is used.  That
   is, the DER encoding of the SET OF tag, rather than of the IMPLICIT
   [2] tag, is to be included in the message digest calculation along
   with the length and content octets of the authAttrs value.

   The message digest calculation process computes a message digest on
   the content being authenticated.  The initial input to the message
   digest calculation process is the "value" of the encapsulated content
   being authenticated.  Specifically, the input is the encapContentInfo
   eContent OCTET STRING to which the authentication process is applied.
   Only the octets comprising the value of the encapContentInfo eContent
   OCTET STRING are input to the message digest algorithm, not the tag
   or the length octets.  This has the advantage that the length of the
   content being authenticated need not be known in advance.  Although
   the encapContentInfo eContent OCTET STRING tag and length octets are
   not included in the message digest calculation, they are still
   protected by other means.  The length octets are protected by the
   nature of the message digest algorithm since it is computationally
   infeasible to find any two distinct contents of any length that have
   the same message digest.

   The input to the MAC calculation process includes the MAC input data,
   defined above, and an authentication key conveyed in a recipientInfo
   structure.  The details of MAC calculation depend on the MAC
   algorithm employed (e.g., Hashed Message Authentication Code (HMAC)).
   The object identifier, along with any parameters, that specifies the
   MAC algorithm employed by the originator is carried in the
   macAlgorithm field.  The MAC value generated by the originator is
   encoded as an OCTET STRING and carried in the mac field.

9.3.  MAC Verification

   The input to the MAC verification process includes the input data
   (determined based on the presence or absence of the authAttrs field,
   as defined in 9.2), and the authentication key conveyed in
   recipientInfo.  The details of the MAC verification process depend on
   the MAC algorithm employed.

   The recipient MUST NOT rely on any MAC values or message digest
   values computed by the originator.  The content is authenticated as
   described in Section 9.2.  If the originator includes authenticated
   attributes, then the content of the authAttrs is authenticated as
   described in Section 9.2.  For authentication to succeed, the MAC
   value calculated by the recipient MUST be the same as the value of
   the mac field.  Similarly, for authentication to succeed when the
   authAttrs field is present, the content message digest value
   calculated by the recipient MUST be the same as the message digest
   value included in the authAttrs message-digest attribute.

   If the AuthenticatedData includes authAttrs, then the content-type
   attribute value MUST match the AuthenticatedData encapContentInfo
   eContentType value.
*/
	parse: function(cmsSequence, options = {})
	{
		// preparation
		var cmsKey = options.cmsKey;

		var explicit = cmsSequence.items[1];
		var sequence = explicit.items[0];
		var idx = 0;
		var authenticatedData = {};
		
		var obj = sequence.items[idx++];
		
		// version CMSVersion		
		jCastle.assert(obj.type, jCastle.asn1.tagInteger, 'INVALID_DATA_TYPE', 'CMS106');
		
		var version = obj.intVal;
		authenticatedData.version = version;
		
		obj = sequence.items[idx++];
		
		// originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL
		if (obj.tagClass == jCastle.asn1.tagClassContextSpecific && obj.type == 0x00) {
			var originatorInfo = jCastle.cms.asn1.originatorInfo.parse(obj, options);
			authenticatedData.originatorInfo = originatorInfo;

			obj = sequence.items[idx++];
		}
		
		// recipientInfos RecipientInfos
		var recipientInfos = jCastle.cms.asn1.recipientInfos.parse(obj, cmsKey);
		authenticatedData.recipientInfos = recipientInfos;

		obj = sequence.items[idx++];
		
		// macAlgorithm MessageAuthenticationCodeAlgorithm
		var macAlgorithm = jCastle.pbe.asn1.macAlgorithm.parse(obj);
		authenticatedData.macAlgorithm = macAlgorithm;
		
		obj = sequence.items[idx++];	
		
		// digestAlgorithm [1] DigestAlgorithmIdentifier OPTIONAL
		if (obj.tagClass == jCastle.asn1.tagClassContextSpecific && obj.type == 0x01) {
			var digestAlgorithm = jCastle.oid.getName(obj.items[0].value);
			authenticatedData.digestAlgorithm = digestAlgorithm;
			
			obj = sequence.items[idx++];
		}
		
		// encapContentInfo EncapsulatedContentInfo
		var encapContentInfo = jCastle.cms.asn1.encapContentInfo.parse(obj, options);
		authenticatedData.encapContentInfo = encapContentInfo;
		
		obj = sequence.items[idx++];
		
		// authAttrs [2] IMPLICIT AuthAttributes OPTIONAL
		var authAttrs = null;
		if (obj.tagClass == jCastle.asn1.tagClassContextSpecific && obj.type == 0x02) {
			authAttrs = jCastle.cms.asn1.attrs.parse(obj);
			authAttrsDer = obj.der;
			
			authenticatedData.authAttrs = authAttrs;
			authenticatedData.authAttrsDer = authAttrsDer;
			
			obj = sequence.items[idx++];
		}
		
		// mac MessageAuthenticationCode
		var mac = Buffer.from(obj.value, 'latin1');
		authenticatedData.mac = mac;
		
		obj = sequence.items[idx++];		
		
		
		// unauthAttrs [3] IMPLICIT UnauthAttributes OPTIONAL
		if (sequence.items[idx] && sequence.items[idx].tagClass == jCastle.asn1.tagClassContextSpecific) {
			jCastle.assert(sequence.items[idx].type, 0x03, 'UNKNOWN_TAG_TYPE', 'CMS004');
			var unauthAttrs = jCastle.cms.asn1.attrs.parse(sequence.items[idx]);
			authenticatedData.unauthAttrs = unauthAttrs;
		}

		var cmsInfo = {
			contentType: 'authenticatedData',
			content: authenticatedData
		};

		// decrypt content
		var decryptedKey = null;
		for (var i = 0; i < recipientInfos.length; i++) {
			if ('decryptedKey' in recipientInfos[i]) {
				decryptedKey = recipientInfos[i].decryptedKey;
				break;
			}
		}

		if (decryptedKey) {
			// mac validation
			var valid = jCastle.cms.verifyAuthenticatedData(cmsInfo, cmsKey);
			cmsInfo.validation = valid;
		}

		return cmsInfo;		
	},

	getDER: function(cmsInfo, options = {})
	{
		var ber_encoding = !!options.berEncoding;
		
		var  cmsSchema = {
			type: jCastle.asn1.tagSequence,
			items: [{
				type: jCastle.asn1.tagOID,
				value: jCastle.oid.getOID('authenticatedData')
			}, {
				type: 0x00,
				tagClass: jCastle.asn1.tagClassContextSpecific,
				constructed: true,
				items: []
			}]
		};
		
		var authenticatedDataSchema = {
			type: jCastle.asn1.tagSequence,
			items: []
		};

		if (ber_encoding) {
			cmsSchema.items[1].indefiniteLength = true;
			cmsSchema.indefiniteLength = true;
			authenticatedDataSchema.indefiniteLength = true;
		}
		
		// preparation

		var originatorInfo = 'originatorInfo' in cmsInfo.content ? cmsInfo.content.originatorInfo : {};
		
//		var certificates = 'certificates' in options ? options.certificates : ('certificates' in originatorInfo ? originatorInfo.certificates : []);
//		var crls = 'crls' in options ? options.crls : ('crls' in originatorInfo ? originatorInfo.crls : []);
		if ('certificates' in options) originatorInfo.certificates = options.certificates;
		if ('crls' in options) originatorInfo.crls = options.crls;

		var recipientInfos = cmsInfo.content.recipientInfos;

		var cmsKeys;

		if (recipientInfos.length == 1 && 'cmsKey' in options) {
			cmsKeys = [options.cmsKey];
		} else {
			cmsKeys = options.cmsKeys;
		}

		if (recipientInfos.length > cmsKeys.length) {
			while (recipientInfos.length != cmsKeys.length) 
				cmsKeys[cmsKeys.length] = cmsKeys[cmsKeys.lenggh - 1];
		}

		var macAlgorithm = cmsInfo.content.macAlgorithm;
		if (!('algorithm' in macAlgorithm)) {
			if (!('macInfo' in macAlgorithm) || !('algo' in macAlgorithm.macInfo))
				throw jCastle.exception('ALGORITHM_NOT_SET', 'CMS108');

			algo = macAlgorithm.macInfo.algo;

			var macName = jCastle.mac.getMacName(algo);
			if (!macName) macName = jCastle.digest.getAlgorithmInfo(algo);
			if (!macName) throw jCastle.exception('UNSUPPORTED_MAC', 'CMS109');

			macAlgorithm.algorithm = macName;
			macAlgorithm.macInfo = jCastle.pbe.getMacInfo(macName);
		} else if (!('macInfo' in macAlgorithm)) {
			macAlgorithm.macInfo = jCastle.pbe.getMacInfo(macAlgorithm.algorithm);
		}

		var key_size = 'keySize' in options ? options.keySize : 0;
		var encryptKey;
		
		if ('encryptKey' in options) {
			encryptKey = Buffer.from(options.encryptKey, 'latin1');
			
			//while (encryptKey.length < key_size) encryptKey.push(0x00);
			if (encryptKey.length < key_size) encryptKey = Buffer.concat([encryptKey, Buffer.alloc(key_size - encryptKey.length)]);
		} else {
			if (!key_size) {
				if ('keySize' in macAlgorithm.macInfo.algoInfo) key_size = macAlgorithm.macInfo.algoInfo.keySize;
				else key_size = 16; // default key size if key size is not given
			}
			var prng = jCastle.prng.create();
			encryptKey = prng.nextBytes(key_size);
		}

		var encapContentInfo;
		
		if ('content' in options) encapContentInfo = {
			content: options.content,
			contentType: options.contentType || 'data'
		};
		else encapContentInfo =  cmsInfo.content.encapContentInfo;
		if (!('contentType' in encapContentInfo)) encapContentInfo.contentType = 'data';
		encapContentInfo.content = jCastle.cms.content.getDER(encapContentInfo.content, options);
		
		var authAttrs = 'authAttrs' in cmsInfo.content ? cmsInfo.content.authAttrs : [];
		
		var messageDigest, digestAlgorithm;
		
		if (encapContentInfo.contentType != 'data') {
			if ('digestAlgorithm' in cmsInfo.content) {
				digestAlgorithm = cmsInfo.content.digestAlgorithm;
			} else {
				if ('hmac' == macAlgorithm.macInfo.type) digestAlgorithm = macAlgorithm.macInfo.algo;
				else 'sha-1'; // default hash algo
			}
			
			var md = jCastle.digest.create(digestAlgorithm);
			messageDigest = md.start().update(Buffer.from(encapContentInfo.content, 'latin1')).finalize();
			
			jCastle.cms.fn.updateAttr(authAttrs, 'update', 'contentType', {
				type: jCastle.asn1.tagOID,
				value: jCastle.oid.getOID(encapContentInfo.contentType)
			});
			jCastle.cms.fn.updateAttr(authAttrs, 'update', 'messageDigest', {
				type: jCastle.asn1.tagOctetString,
				value: messageDigest
			});
		}
		
		var unauthAttrs = 'unauthAttrs' in cmsInfo.content ? cmsInfo.content.unauthAttrs : [];
		
			
		// version CMSVersion
		var version = 'version' in cmsInfo.content ? cmsInfo.content.version : 
			jCastle.cms.version.authenticatedData(originatorInfo);
		authenticatedDataSchema.items.push({
			type: jCastle.asn1.tagInteger,
			intVal: version
		});
		
		// originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL
		if (('certificates' in originatorInfo && originatorInfo.certificates.length) ||
			('crls' in originatorInfo && originatorInfo.crls.length)) {
			var originatorInfoSchema = jCastle.cms.asn1.originatorInfo.schema(originatorInfo, options);

			authenticatedDataSchema.items.push(originatorInfoSchema);
		}
		
		// recipientInfos RecipientInfos
		var recipientInfosSchema = jCastle.cms.asn1.recipientInfos.schema(recipientInfos, encryptKey, cmsKeys, options);
		authenticatedDataSchema.items.push(recipientInfosSchema);
		
		// macAlgorithm MessageAuthenticationCodeAlgorithm
		var macAlgorithmSchema = jCastle.pbe.asn1.macAlgorithm.schema(macAlgorithm);
		authenticatedDataSchema.items.push(macAlgorithmSchema);
		
		// digestAlgorithm [1] DigestAlgorithmIdentifier OPTIONAL
		if (digestAlgorithm) {
			var da = jCastle.digest.getValidAlgoName(digestAlgorithm);
			var digestAlgorithmSchema = {
				tagClass: jCastle.asn1.tagClassContextSpecific,
				type: 0x01,
				constructed: true,
				items: [{
					type: jCastle.asn1.tagOID,
					value: jCastle.digest.getOID(da)
				}]
			};
			authenticatedDataSchema.items.push(digestAlgorithmSchema);
		}
			
		
		// encapContentInfo EncapsulatedContentInfo
		var encapContentInfoSchema = jCastle.cms.asn1.encapContentInfo.schema(encapContentInfo, options);
		authenticatedDataSchema.items.push(encapContentInfoSchema);
		
		// authAttrs [2] IMPLICIT AuthAttributes OPTIONAL
		if (authAttrs.length) {
			var authAttrsSchema = jCastle.cms.asn1.attrs.schema(authAttrs, 0x02);
			authenticatedDataSchema.items.push(authAttrsSchema);
		}
		
		// mac MessageAuthenticationCode
/*
9.2.  MAC Generation

   The MAC calculation process computes a message authentication code
   (MAC) on either the content being authenticated or a message digest
   of content being authenticated together with the originator's
   authenticated attributes.

   If the authAttrs field is absent, the input to the MAC calculation
   process is the value of the encapContentInfo eContent OCTET STRING.
   Only the octets comprising the value of the eContent OCTET STRING are
   input to the MAC algorithm; the tag and the length octets are
   omitted.  This has the advantage that the length of the content being
   authenticated need not be known in advance of the MAC generation
   process.

   If the authAttrs field is present, the content-type attribute (as
   described in Section 11.1) and the message-digest attribute (as
   described in Section 11.2) MUST be included, and the input to the MAC
   calculation process is the DER encoding of authAttrs.  A separate
   encoding of the authAttrs field is performed for message digest
   calculation.  The IMPLICIT [2] tag in the authAttrs field is not used
   for the DER encoding, rather an EXPLICIT SET OF tag is used.  That
   is, the DER encoding of the SET OF tag, rather than of the IMPLICIT
   [2] tag, is to be included in the message digest calculation along
   with the length and content octets of the authAttrs value.

   The message digest calculation process computes a message digest on
   the content being authenticated.  The initial input to the message
   digest calculation process is the "value" of the encapsulated content
   being authenticated.  Specifically, the input is the encapContentInfo
   eContent OCTET STRING to which the authentication process is applied.
   Only the octets comprising the value of the encapContentInfo eContent
   OCTET STRING are input to the message digest algorithm, not the tag
   or the length octets.  This has the advantage that the length of the
   content being authenticated need not be known in advance.  Although
   the encapContentInfo eContent OCTET STRING tag and length octets are
   not included in the message digest calculation, they are still
   protected by other means.  The length octets are protected by the
   nature of the message digest algorithm since it is computationally
   infeasible to find any two distinct contents of any length that have
   the same message digest.

   The input to the MAC calculation process includes the MAC input data,
   defined above, and an authentication key conveyed in a recipientInfo
   structure.  The details of MAC calculation depend on the MAC
   algorithm employed (e.g., Hashed Message Authentication Code (HMAC)).
   The object identifier, along with any parameters, that specifies the
   MAC algorithm employed by the originator is carried in the
   macAlgorithm field.  The MAC value generated by the originator is
   encoded as an OCTET STRING and carried in the mac field.
*/		
		var mac = jCastle.cms.fn.generateAuthMAC(
			encapContentInfo.content, 
			encapContentInfo.contentType, 
			authAttrs, 
			macAlgorithm, 
			encryptKey);
		authenticatedDataSchema.items.push({
			type: jCastle.asn1.tagOctetString,
			value: mac
		});

		// unauthAttrs [3] IMPLICIT UnauthAttributes OPTIONAL
		if (unauthAttrs.length) {
			authenticatedDataSchema.items.push(jCastle.cms.asn1.attrs.schema(unauthAttrs, 0x03));
		}
		
		cmsSchema.items[1].items.push(authenticatedDataSchema);
//console.log(cmsSchema);
//console.log(JSON.stringify(cmsSchema));
		var asn1 = new jCastle.asn1();
		var der = asn1.getDER(cmsSchema);

		return der;		
	}
};

jCastle.cms.contentType.authEnvelopedData = {
/*
https://tools.ietf.org/html/rfc6010
https://tools.ietf.org/html/rfc5083
*/
/*
https://tools.ietf.org/html/rfc5083

2.  Authenticated-Enveloped-Data Content Type

   The authenticated-enveloped-data content type consists of an
   authenticated and encrypted content of any type and encrypted
   content-authenticated-encryption keys for one or more recipients.
   The combination of the authenticated and encrypted content and one
   encrypted content-authenticated-encryption key for a recipient is a
   "digital envelope" for that recipient.  Any type of content can be
   enveloped for an arbitrary number of recipients using any of the
   supported key management techniques for each recipient.  In addition,
   authenticated but not encrypted attributes may be provided by the
   originator.

   The typical application of the authenticated-enveloped-data content
   type will represent one or more recipients' digital envelopes on an
   encapsulated content.

   Authenticated-enveloped-data is constructed by the following steps:

   1.  A content-authenticated-encryption key for a particular content-
       authenticated-encryption algorithm is generated at random.

   2.  The content-authenticated-encryption key is encrypted for each
       recipient.  The details of this encryption depend on the key
       management algorithm used, but four general techniques are
       supported:

         Key Transport: the content-authenticated-encryption key is
            encrypted in the recipient's public key;

         Key Agreement: the recipient's public key and the sender's
            private key are used to generate a pairwise symmetric key-
            encryption key, then the content-authenticated-encryption
            key is encrypted in the pairwise symmetric key-encryption
            key;

         Symmetric Key-Encryption Keys: the content-authenticated-
            encryption key is encrypted in a previously distributed
            symmetric key-encryption key; and

         Passwords: the content-authenticated-encryption key is
            encrypted in a key-encryption key that is derived from a
            password or other shared secret value.

   3.  For each recipient, the encrypted content-authenticated-
       encryption key and other recipient-specific information are
       collected into a RecipientInfo value, defined in Section 6.2 of
       [CMS].

   4.  Any attributes that are to be authenticated but not encrypted are
       collected in the authenticated attributes.

   5.  The attributes collected in step 4 are authenticated and the CMS
       content is authenticated and encrypted with the content-
       authenticated-encryption key.  If the authenticated encryption
       algorithm requires either the additional authenticated data (AAD)
       or the content to be padded to a multiple of some block size,
       then the padding is added as described in Section 6.3 of [CMS].

   6.  Any attributes that are to be provided without authentication or
       encryption are collected in the unauthenticated attributes.

   7.  The RecipientInfo values for all the recipients, the
       authenticated attributes, the unauthenticated attributes, and the
       authenticated and encrypted content are collected together to
       form an AuthEnvelopedData value as defined in Section 2.1.

   A recipient opens the digital envelope by decrypting one of the
   encrypted content-authenticated-encryption keys, and then using the
   recovered key to decrypt and verify the integrity of the
   authenticated and encrypted content as well as to verify the
   integrity of the authenticated attributes.

   The recipient MUST verify the integrity of the received content
   before releasing any information, especially the plaintext of the
   content.  If the integrity verification fails, the receiver MUST
   destroy all of the plaintext of the content.

   This section is divided into three parts.  The first part describes
   the AuthEnvelopedData content type, the second part describes the
   authentication and encryption process, and the third part describes
   the key encryption process.

2.1.  AuthEnvelopedData Type

   The following object identifier identifies the authenticated-
   enveloped-data content type:

      id-ct-authEnvelopedData OBJECT IDENTIFIER ::= { iso(1)
          member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-9(9)
          smime(16) ct(1) 23 }

   The authenticated-enveloped-data content type MUST have ASN.1 type
   AuthEnvelopedData:

      AuthEnvelopedData ::= SEQUENCE {
        version CMSVersion,
        originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
        recipientInfos RecipientInfos,
        authEncryptedContentInfo EncryptedContentInfo,
        authAttrs [1] IMPLICIT AuthAttributes OPTIONAL,
        mac MessageAuthenticationCode,
        unauthAttrs [2] IMPLICIT UnauthAttributes OPTIONAL }

   The fields of type AuthEnvelopedData have the following meanings:

      version is the syntax version number.  It MUST be set to 0.

      originatorInfo optionally provides information about the
         originator.  It is present only if required by the key
         management algorithm.  It may contain certificates and
         Certificate Revocation Lists (CRLs), and the OriginatorInfo
         type is defined in Section 6.1 of [CMS].

      recipientInfos is a collection of per-recipient information.
         There MUST be at least one element in the collection.  The
         RecipientInfo type is defined in Section 6.2 of [CMS].

      authEncryptedContentInfo is the authenticated and encrypted
         content.  The CMS enveloped-data content type uses the same
         type to carry the encrypted content.  The EncryptedContentInfo
         type is defined in Section 6.1 of [CMS].

      authAttrs optionally contains the authenticated attributes.  The
         CMS authenticated-data content type uses the same type to carry
         authenticated attributes.  The authAttrs MUST be present if the
         content type carried in EncryptedContentInfo is not id-data.
         AuthAttributes MUST be DER encoded, even if the rest of the
         AuthEnvelopedData structure is BER encoded.  The AuthAttributes
         type is defined in Section 9.1 of [CMS]; however, in this case,
         the message-digest attribute SHOULD NOT be included.  Useful
         attribute types are defined in Section 11 of [CMS].

      mac is the integrity check value (ICV) or message authentication
         code (MAC) that is generated by the authenticated encryption
         algorithm.  The CMS authenticated-data content type uses the
         same type to carry a MAC.  In this case, the MAC covers the
         authenticated attributes and the content directly, and a digest
         algorithm is not used.  The MessageAuthenticationCode type is
         defined in Section 9.1 of [CMS].

      unauthAttrs optionally contains the unauthenticated attributes.
         The CMS authenticated-data content type uses the same type to
         carry unauthenticated attributes.  The UnauthAttributes type is
         defined in Section 9.1 of [CMS].  Useful attribute types are
         defined in Section 11 of [CMS].

2.2.  Authentication and Encryption Process

   The content-authenticated-encryption key for the desired content-
   authenticated-encryption algorithm is randomly generated.

   If the authenticated encryption algorithm requires the content to be
   padded to a multiple of some block size, then the padding MUST be
   added as described in Section 6.3 of [CMS].  This padding method is
   well defined if and only if the block size is less than 256 octets.

   If optional authenticated attributes are present, then they are DER
   encoded.  A separate encoding of the authAttrs field is performed to
   construct the authenticated associated data (AAD) input to the
   authenticated encryption algorithm.  For the purposes of constructing
   the AAD, the IMPLICIT [1] tag in the authAttrs field is not used for
   the DER encoding: rather a universal SET OF tag is used.  That is,
   the DER encoding of the SET OF tag, rather than of the IMPLICIT [1]
   tag, is to be included in the construction for the AAD along with the
   length and content octets of the authAttrs value.  If the
   authenticated encryption algorithm requires the AAD to be padded to a
   multiple of some block size, then the padding MUST be added as
   described in Section 6.3 of [CMS].  This padding method is well
   defined if and only if the block size is less than 256 octets.

   If optional authenticated attributes are absent, then zero bits of
   input are provided for the AAD input to the authenticated encryption
   algorithm.

   The inputs to the authenticated encryption algorithm are the content
   (the data, which is padded if necessary), the DER-encoded
   authenticated attributes (the AAD, which is padded if necessary), and
   the content-authenticated-encryption key.  Under control of a
   content-authenticated-encryption key, the authenticated encryption
   operation maps an arbitrary string of octets (the data) to another
   string of octets (the ciphertext) and it computes an authentication
   tag over the AAD and the data.  The encrypted data is included in the
   AuthEnvelopedData authEncryptedContentInfo encryptedContent as an
   OCTET STRING, and the authentication tag is included in the
   AuthEnvelopedData mac.

2.3.  Key Encryption Process

   The input to the key encryption process -- the value supplied to the
   recipient's key-encryption algorithm -- is just the "value" of the
   content-authenticated-encryption key.

   Any of the aforementioned key management techniques can be used for
   each recipient of the same encrypted content.
*/	
	parse: function(cmsSequence, options = {})
	{
/*
      AuthEnvelopedData ::= SEQUENCE {
        version CMSVersion,
        originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
        recipientInfos RecipientInfos,
        authEncryptedContentInfo EncryptedContentInfo,
        authAttrs [1] IMPLICIT AuthAttributes OPTIONAL,
        mac MessageAuthenticationCode,
        unauthAttrs [2] IMPLICIT UnauthAttributes OPTIONAL }
*/
		// preparation
		var cmsKey = options.cmsKey;

		var explicit = cmsSequence.items[1];
		var sequence = explicit.items[0];
		var idx = 0;
		var authEnvelopedData = {};

//console.log(sequence);

		var obj = sequence.items[idx++];

		// version CMSVersion
/*
      version is the syntax version number.  It MUST be set to 0.
*/
		jCastle.assert(obj.type, jCastle.asn1.tagInteger, 'INVALID_DATA_TYPE', 'CMS003');

		var version = obj.intVal;
		authEnvelopedData.version = version;

		obj = sequence.items[idx++];

		// originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL
/*
      originatorInfo optionally provides information about the
         originator.  It is present only if required by the key
         management algorithm.  It may contain certificates and
         Certificate Revocation Lists (CRLs), and the OriginatorInfo
         type is defined in Section 6.1 of [CMS].
*/
		if (obj.tagClass == jCastle.asn1.tagClassContextSpecific && obj.type == 0x00) {
			var originatorInfo = jCastle.cms.asn1.originatorInfo.parse(obj, options);
			authEnvelopedData.originatorInfo = originatorInfo;

			obj = sequence.items[idx++];
		}

		// recipientInfos RecipientInfos
/*
      recipientInfos is a collection of per-recipient information.
         There MUST be at least one element in the collection.  The
         RecipientInfo type is defined in Section 6.2 of [CMS].
*/
//		var recipientInfos = jCastle.cms.asn1.recipientInfos.parse(obj, options);
		var recipientInfos = jCastle.cms.asn1.recipientInfos.parse(obj, cmsKey);
		authEnvelopedData.recipientInfos = recipientInfos;

		obj = sequence.items[idx++];

		// authEncryptedContentInfo EncryptedContentInfo
/*
      authEncryptedContentInfo is the authenticated and encrypted
         content.  The CMS enveloped-data content type uses the same
         type to carry the encrypted content.  The EncryptedContentInfo
         type is defined in Section 6.1 of [CMS].
*/
		var authEncryptedContentInfo = jCastle.cms.asn1.encryptedContentInfo.parse(obj, options);	
		authEnvelopedData.authEncryptedContentInfo = authEncryptedContentInfo;
		
		obj = sequence.items[idx++];

		// decrypt content
		var decryptedKey = null;
		for (var i = 0; i < recipientInfos.length; i++) {
			if ('decryptedKey' in recipientInfos[i]) {
				decryptedKey = Buffer.from(recipientInfos[i].decryptedKey, 'latin1');
				break;
			}
		}

		// authAttrs [1] IMPLICIT AuthAttributes OPTIONAL
/*
      authAttrs optionally contains the authenticated attributes.  The
         CMS authenticated-data content type uses the same type to carry
         authenticated attributes.  The authAttrs MUST be present if the
         content type carried in EncryptedContentInfo is not id-data.
         AuthAttributes MUST be DER encoded, even if the rest of the
         AuthEnvelopedData structure is BER encoded.  The AuthAttributes
         type is defined in Section 9.1 of [CMS]; however, in this case,
         the message-digest attribute SHOULD NOT be included.  Useful
         attribute types are defined in Section 11 of [CMS].
*/		
		var authAttrs = null;
		if (obj.tagClass == jCastle.asn1.tagClassContextSpecific && obj.type == 0x01) {
			authAttrs = jCastle.cms.asn1.attrs.parse(obj);
			var authAttrsBuffer = obj.buffer;
			
			authEnvelopedData.authAttrs = authAttrs;
			authEnvelopedData.authAttrsBuffer = authAttrsBuffer;
			
			obj = sequence.items[idx++];
		}

		// mac MessageAuthenticationCode
/*
      mac is the integrity check value (ICV) or message authentication
         code (MAC) that is generated by the authenticated encryption
         algorithm.  The CMS authenticated-data content type uses the
         same type to carry a MAC.  In this case, the MAC covers the
         authenticated attributes and the content directly, and a digest
         algorithm is not used.  The MessageAuthenticationCode type is
         defined in Section 9.1 of [CMS].
*/
		var mac = Buffer.from(obj.value, 'latin1');
		authEnvelopedData.mac = mac;
		
		obj = sequence.items[idx++];

		var validation;
		
		if (decryptedKey) {
			var enc_algo_info = authEncryptedContentInfo.contentEncryptionAlgorithm;
			var algo = enc_algo_info.algo;
			var algoInfo = 'algoInfo' in enc_algo_info ? enc_algo_info.algoInfo : jCastle.pbe.getAlgorithmInfo(algo);
			var params = enc_algo_info.params;
//console.log(authEncryptedContentInfo);

/*
2.2.  Authentication and Encryption Process

   The content-authenticated-encryption key for the desired content-
   authenticated-encryption algorithm is randomly generated.

   If the authenticated encryption algorithm requires the content to be
   padded to a multiple of some block size, then the padding MUST be
   added as described in Section 6.3 of [CMS].  This padding method is
   well defined if and only if the block size is less than 256 octets.

   If optional authenticated attributes are present, then they are DER
   encoded.  A separate encoding of the authAttrs field is performed to
   construct the authenticated associated data (AAD) input to the
   authenticated encryption algorithm.  For the purposes of constructing
   the AAD, the IMPLICIT [1] tag in the authAttrs field is not used for
   the DER encoding: rather a universal SET OF tag is used.  That is,
   the DER encoding of the SET OF tag, rather than of the IMPLICIT [1]
   tag, is to be included in the construction for the AAD along with the
   length and content octets of the authAttrs value.  If the
   authenticated encryption algorithm requires the AAD to be padded to a
   multiple of some block size, then the padding MUST be added as
   described in Section 6.3 of [CMS].  This padding method is well
   defined if and only if the block size is less than 256 octets.

   If optional authenticated attributes are absent, then zero bits of
   input are provided for the AAD input to the authenticated encryption
   algorithm.

   The inputs to the authenticated encryption algorithm are the content
   (the data, which is padded if necessary), the DER-encoded
   authenticated attributes (the AAD, which is padded if necessary), and
   the content-authenticated-encryption key.  Under control of a
   content-authenticated-encryption key, the authenticated encryption
   operation maps an arbitrary string of octets (the data) to another
   string of octets (the ciphertext) and it computes an authentication
   tag over the AAD and the data.  The encrypted data is included in the
   AuthEnvelopedData authEncryptedContentInfo encryptedContent as an
   OCTET STRING, and the authentication tag is included in the
   AuthEnvelopedData mac.
*/

			params.key = decryptedKey;
			params.mode = algoInfo.mode;
			params.isEncryption = false;
//			params.padding = 'pkcs7';
			
			if (authAttrs && authAttrs.length) {
				var attrsSchema = jCastle.cms.asn1.attrs.schema(authAttrs, null);
				var aad = jCastle.asn1.create().getDER(attrsSchema);
				params.additionalData = Buffer.from(aad, 'latin1');
			}

			try {
				var crypto = new jCastle.mcrypt(algoInfo.algo);
				crypto.start(params);
				crypto.update(Buffer.from(authEncryptedContentInfo.encryptedContent, 'latin1'));
				crypto.update(mac);
				var content = crypto.finalize();

				authEnvelopedData.authEncryptedContentInfo.content = content;
				
				validation = true;
			} catch (e) {
				validation = false;				
			}
		}
		

		// unauthAttrs [2] IMPLICIT UnauthAttributes OPTIONAL
/*		
      unauthAttrs optionally contains the unauthenticated attributes.
         The CMS authenticated-data content type uses the same type to
         carry unauthenticated attributes.  The UnauthAttributes type is
         defined in Section 9.1 of [CMS].  Useful attribute types are
         defined in Section 11 of [CMS].
*/
		if (sequence.items[idx] && sequence.items[idx].tagClass == jCastle.asn1.tagClassContextSpecific) {
			jCastle.assert(sequence.items[idx].type, 0x02, 'UNKNOWN_TAG_TYPE', 'CMS004');
			var unauthAttrs = jCastle.cms.asn1.attrs.parse(sequence.items[idx]);
			authEnvelopedData.unauthAttrs = unauthAttrs;
		}
		
		var cmsInfo = {
			contentType: 'authEnvelopedData',
			content: authEnvelopedData
		};

		// if decrypted key then verify mac
		if (decryptedKey) {
			// mac validation
//			var valid = jCastle.cms.verifyAuthEnvelopedData(cmsInfo, cmsKey);
			cmsInfo.validation = validation;
		}


		return cmsInfo;
	},

/*
      AuthEnvelopedData ::= SEQUENCE {
        version CMSVersion,
        originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
        recipientInfos RecipientInfos,
        authEncryptedContentInfo EncryptedContentInfo,
        authAttrs [1] IMPLICIT AuthAttributes OPTIONAL,
        mac MessageAuthenticationCode,
        unauthAttrs [2] IMPLICIT UnauthAttributes OPTIONAL }
*/
	getDER: function(cmsInfo, options = {})
	{
		var ber_encoding = !!options.berEncoding;

		var cmsSchema = {
			type: jCastle.asn1.tagSequence,
			items: [{
				type: jCastle.asn1.tagOID,
				value: jCastle.oid.getOID('authEnvelopedData')
			}, {
				type: 0x00,
				tagClass: jCastle.asn1.tagClassContextSpecific,
				constructed: true,
				items: []
			}]
		};

		var authEnvelopedDataSchema = {
			type: jCastle.asn1.tagSequence,
			items:[]
		};

		if (ber_encoding) {
			cmsSchema.items[1].indefiniteLength = true;
			cmsSchema.indefiniteLength = true;
			authEnvelopedDataSchema.indefiniteLength = true;
		}

		// preparation

		var originatorInfo = 'originatorInfo' in cmsInfo.content ? cmsInfo.content.originatorInfo : {};
		
//		var certificates = 'certificates' in options ? options.certificates : ('certificates' in originatorInfo ? originatorInfo.certificates : []);
//		var crls = 'crls' in options ? options.crls : ('crls' in originatorInfo ? originatorInfo.crls : []);
		if ('certificates' in options) originatorInfo.certificates = options.certificates;
		if ('crls' in options) originatorInfo.crls = options.crls;

		var recipientInfos = cmsInfo.content.recipientInfos;
		var cmsKeys;

		if (recipientInfos.length == 1 && 'cmsKey' in options) {
			cmsKeys = [options.cmsKey];
		} else {
			cmsKeys = options.cmsKeys;
		}

		if (recipientInfos.length > cmsKeys.length) {
			while (recipientInfos.length != cmsKeys.length) 
				cmsKeys[cmsKeys.length] = cmsKeys[cmsKeys.lenggh - 1];
		}
		
		var authEncryptedContentInfo = cmsInfo.content.authEncryptedContentInfo;
		if (!('contentType' in authEncryptedContentInfo)) authEncryptedContentInfo.contentType = 'data';
		
		var authAttrs = 'authAttrs' in cmsInfo.content ? cmsInfo.content.authAttrs : [];
		
		if (authEncryptedContentInfo.contentType != 'data') {
			jCastle.cms.fn.updateAttr(authAttrs, 'update', 'contentType', {
				type: jCastle.asn1.tagOID,
				value: jCastle.oid.getOID(authEncryptedContentInfo.contentType)
			});
		}

		var unauthAttrs = 'unauthAttrs' in cmsInfo.content ? cmsInfo.content.unauthAttrs : [];

		// version
		var version = 0;
		
		authEnvelopedDataSchema.items.push({
			type: jCastle.asn1.tagInteger,
			intVal: version
		});

		// originatorInfo
		if (('certificates' in originatorInfo && originatorInfo.certificates.length) ||
			('crls' in originatorInfo && originatorInfo.crls.length)) {
			var originatorInfoSchema = jCastle.cms.asn1.originatorInfo.schema(originatorInfo, options);

			authEnvelopedDataSchema.items.push(originatorInfoSchema);
		}

		// key must be made first
		if ('content' in options) authEncryptedContentInfo.content = options.content;
		if (!('contentType' in authEncryptedContentInfo)) authEncryptedContentInfo.contentType = 'contentType' in options ? options.contentType : 'data';
		authEncryptedContentInfo.content = jCastle.cms.content.getDER(authEncryptedContentInfo.content, options);

		var enc_algo_info = authEncryptedContentInfo.contentEncryptionAlgorithm;
		var algo = enc_algo_info.algo;
		if (!('algoInfo' in enc_algo_info)) enc_algo_info.algoInfo = jCastle.pbe.getAlgorithmInfo(algo);

		if (!jCastle.mcrypt.mode.hasMacTag(enc_algo_info.algoInfo.mode)) throw jCastle.exception('MODE_NOT_SUPPORT_MAC', 'CMS112');

		var params = jCastle.cms.fn.getEncryptionParameters(enc_algo_info, options);

		var key_size = 'keySize' in params ? params.keySize : enc_algo_info.algoInfo.keySize;
		var tag_size = 'tagSize' in params ? params.tagSize : 12; // default
		var encryptKey;
		params.tagSize = tag_size;

		if (authAttrs.length) {
			var attrsSchema = jCastle.cms.asn1.attrs.schema(authAttrs, null);
			var aad = jCastle.asn1.create().getDER(attrsSchema);
			params.additionalData = Buffer.from(aad, 'latin1');
		}

		if ('encryptKey' in options) {
			encryptKey = Buffer.from(options.encryptKey, 'latin1');
			//if (encryptKey.length != key_size) throw jCastle.exception('INVALID_KEYSIZE', 'CMS010');
			//while (encryptKey.length < key_size) encryptKey.push(0x00);
			if (encryptKey.length < key_size) encryptKey = Buffer.concat([encryptKey, Buffer.alloc(key_size - encryptKey.length)]);
		} else {
			var prng = jCastle.prng.create();
			encryptKey = prng.nextBytes(key_size);
		}

		// recipientInfos
		var recipientInfosSchema = jCastle.cms.asn1.recipientInfos.schema(recipientInfos, encryptKey, cmsKeys, options);
		authEnvelopedDataSchema.items.push(recipientInfosSchema);

		// authEncryptedContentInfo
		var authEncryptedContentInfoSchema = jCastle.cms.asn1.encryptedContentInfo.schema(authEncryptedContentInfo, encryptKey, params, ber_encoding);
		
		// we need to extract mac data from authEncryptedContentInfoSchema
		var encryptedContentSchema = authEncryptedContentInfoSchema.items[2];


		// {{{
/*
		var encryptedContent = '';
		for (var i = 0; i < encryptedContentSchema.items.length; i++) {
			encryptedContent += encryptedContentSchema.items[i].value;
		}
		var len = encryptedContent.length - tag_size;
		var mac = encryptedContent.substr(len);
		encryptedContent = encryptedContent.substr(0, len);

		var items = [];
		do {
			items.push({
				type: jCastle.asn1.tagOctetString,
				value: encryptedContent.substr(0, 1024)			
			});
			encryptedContent = encryptedContent.substr(1024);
		} while (encryptedContent.length > 1024);
		
		authEncryptedContentInfoSchema.items[2].items = items;
*/
		// }}}
		// else {{{

		var items = encryptedContentSchema.items;
		var index = items.length - 1;
		var len, mac = null;
		
		if (items[index].value.length > tag_size) {
			len = items[index].value.length - tag_size;
			mac = items[index].value.slice(len);
			items[index].value = items[index].value.slice(0, len);
		} else if (items[index].value.length == tag_size) {
			mac = items[index].value;
			items.pop();
		} else {
			len = tag_size - items[index].value.length;
			mac = items[index--].value;
			items.pop();
			len = items[index].value.length - len;
			mac = Buffer.concat([items[index].value.slice(len), mac]);
			items[index].value = items[index].value.slice(0, len);
		}

		// }}}

		authEnvelopedDataSchema.items.push(authEncryptedContentInfoSchema);

		// authAttrs [1] IMPLICIT AuthAttributes OPTIONAL
		if (authAttrs.length) {
			var authAttrsSchema = jCastle.cms.asn1.attrs.schema(authAttrs, 0x01);
			authEnvelopedDataSchema.items.push(authAttrsSchema);
		}
		
		// mac MessageAuthenticationCode
		var macSchema = {
			type: jCastle.asn1.tagOctetString,
			value: mac
		};
		authEnvelopedDataSchema.items.push(macSchema);
		
		// unauthAttrs [2] IMPLICIT UnauthAttributes OPTIONAL
		if (unauthAttrs.length) {
			authEnvelopedDataSchema.items.push(jCastle.cms.asn1.attrs.schema(unauthAttrs, 0x02));
		}

		cmsSchema.items[1].items.push(authEnvelopedDataSchema);
//console.log(cmsSchema);
//console.log(JSON.stringify(cmsSchema));
		var asn1 = new jCastle.asn1();
		var der = asn1.getDER(cmsSchema);

		return der;

	}
};


jCastle.cms.content = {
	parse: function(content, options)
	{
		// console.log('cms.content.parse()');
		// console.log('content: ', content);
		if (jCastle.util.isString(content)) content = Buffer.from(content, 'latin1');
		//if (jCastle.util.isString(content)) return content;
		if (Buffer.isBuffer(content)) return content;

		if (jCastle.asn1.isSequence(content)) {
			// nested or encapsulated cms.
			try {
				var cms_info = new jCastle.cms().parse(content);
				// console.log('nested');

				return cms_info;
			} catch (ex) {
				// it might be a encapsulated certicate or private key.
				if ('buffer' in content) return content.buffer;

				var der = new jCastle.asn1().getDER(content);
				return Buffer.from(der, 'latin1');
			}
		}
		return content;
	},

	getDER: function(content, options = {})
	{
//		if (jCastle.util.isString(content)) return ByteBuffer.parseString(content).toString('utf8');

		// in browser, string must be checked to be UTF-8
		if (jCastle.util.isString(content)) return Buffer.from(content).toString('latin1');
		if (Buffer.isBuffer(content)) return content.toString('latin1');

		if (typeof content == 'numbrer') return Buffer.from(content.toString(16), 'hex').toString('latin1');

		// try {
		// 	var der = jCastle.asn1.create().getDER(content);
		// 	return der;
		// } catch (e) {
		// 	try {
		// 		var opt = jCastle.util.clone(options);
		// 		opt.format = 'der';
		// 		var der = jCastle.cms.create().export(content, opt);
		// 		return der;
		// 	} catch (e) {
		// 		return Buffer.from(content, 'latin1').toString('latin1');
		// 	}
		// }
		if (jCastle.asn1.isSequence(content)) {
			try {
				var der = jCastle.asn1.create().getDER(content);
				return der;
			} catch (ex) {
				//return Buffer.from(content, 'latin1').toString('latin1');
				throw jCastle.exception('MALFORMED_DATA', 'CMS130');
			}
		}

		//if ('contentType' in content && 'content' in content) {
			try {
				var der = jCastle.cms.create().getDER(content, options);
				return der;
			} catch (ex) {
				//return Buffer.from(content, 'latin1').toString('latin1');
				throw jCastle.exception('MALFORMED_DATA', 'CMS131');
			}
		//}
	}
};

jCastle.cms.fn = {};

jCastle.cms.fn.kariGetKeyEncryptionAlgoInfo = function(dh_algo)
{
	var keyEncryptionAlgo = {};
	var m = /(dhSinglePass|mqvSinglePass)(\-stdDH|\-cofactorDH)?\-([a-z0-9\-]+)kdf-scheme/i.exec(dh_algo);
	if (m) {
/*
// RFC 5753  Use of ECC Algorithms in CMS


6.  SMIMECapabilities Attribute and ECC

   A sending agent MAY announce to receiving agents that it supports one
   or more of the ECC algorithms specified in this document by using the
   SMIMECapabilities signed attribute [MSG] in either a signed message
   or a certificate [CERTCAP].

   The SMIMECapabilities attribute value indicates support for one of
   the ECDSA signature algorithms in a SEQUENCE with the capabilityID
   field containing the object identifier ecdsa-with-SHA1 with NULL
   parameters and ecdsa-with-SHA* (where * is 224, 256, 384, or 512)
   with absent parameters.  The DER encodings are:

      ecdsa-with-SHA1:   30 0b 06 07 2a 86 48 ce 3d 04 01 05 00

      ecdsa-with-SHA224: 30 0a 06 08 2a 86 48 ce 3d 04 03 01

      ecdsa-with-SHA256: 30 0a 06 08 2a 86 48 ce 3d 04 03 02

      ecdsa-with-SHA384: 30 0a 06 08 2a 86 48 ce 3d 04 03 03

      ecdsa-with-SHA512: 30 0a 06 08 2a 86 48 ce 3d 04 03 04

   NOTE: The SMIMECapabilities attribute indicates that parameters for
   ECDSA with SHA-1 are NULL; however, the parameters are absent when
   used to generate a digital signature.

   The SMIMECapabilities attribute value indicates support for

      a)  the standard ECDH key agreement algorithm,
      b)  the cofactor ECDH key agreement algorithm, or
      c)  the 1-Pass ECMQV key agreement algorithm and

   is a SEQUENCE with the capabilityID field containing the object
   identifier

      a)  dhSinglePass-stdDH-sha*kdf-scheme,
      b)  dhSinglePass-cofactorDH-sha*kdf-scheme, or
      c)  mqvSinglePass-sha*kdf-scheme

   respectively (where * is 1, 224, 256, 384, or 512) with the
   parameters present.  The parameters indicate the supported key-
   encryption algorithm with the KeyWrapAlgorithm algorithm identifier.
*/

/*
2020.01.04 added to oid.js
OID:

	"1.3.132.1":      { name: "secg-scheme", comment: "#", obsolete: false },
	"1.3.132.1.11.0": { name: "dhSinglePass-stdDH-sha224kdf-scheme", comment: "NIST Key Agreement Algorithms in rfc5753", obsolete: false },
	"1.3.132.1.11.1": { name: "dhSinglePass-stdDH-sha256kdf-scheme", comment: "NIST Key Agreement Algorithms in rfc5753", obsolete: false },
	"1.3.132.1.11.2": { name: "dhSinglePass-stdDH-sha384kdf-scheme", comment: "NIST Key Agreement Algorithms in rfc5753", obsolete: false },
	"1.3.132.1.11.3": { name: "dhSinglePass-stdDH-sha512kdf-scheme", comment: "NIST Key Agreement Algorithms in rfc5753", obsolete: false },
	"1.3.132.1.14.0": { name: "dhSinglePass-cofactorDH-sha224kdf-scheme", comment: "NIST Key Agreement Algorithms in rfc5753", obsolete: false },
	"1.3.132.1.14.1": { name: "dhSinglePass-cofactorDH-sha256kdf-scheme", comment: "NIST Key Agreement Algorithms in rfc5753", obsolete: false },
	"1.3.132.1.14.2": { name: "dhSinglePass-cofactorDH-sha384kdf-scheme", comment: "NIST Key Agreement Algorithms in rfc5753", obsolete: false },
	"1.3.132.1.14.3": { name: "dhSinglePass-cofactorDH-sha512kdf-scheme", comment: "NIST Key Agreement Algorithms in rfc5753", obsolete: false },
	"1.3.132.1.15.0": { name: "mqvSinglePass-sha224kdf-scheme", comment: "NIST Key Agreement Algorithms in rfc5753", obsolete: false },
	"1.3.132.1.15.1": { name: "mqvSinglePass-sha256kdf-scheme", comment: "NIST Key Agreement Algorithms in rfc5753", obsolete: false },
	"1.3.132.1.15.2": { name: "mqvSinglePass-sha384kdf-scheme", comment: "NIST Key Agreement Algorithms in rfc5753", obsolete: false },
	"1.3.132.1.15.3": { name: "mqvSinglePass-sha512kdf-scheme", comment: "NIST Key Agreement Algorithms in rfc5753", obsolete: false },

	"1.3.133.16.840.63.0":    { name: "x9-63-scheme", comment: "NIST Key Agreement Algorithms in rfc5753", obsolete: false },
	"1.3.133.16.840.63.0.2":  { name: "dhSinglePass-stdDH-sha1kdf-scheme", comment: "NIST Key Agreement Algorithms in rfc5753", obsolete: false },
	"1.3.133.16.840.63.0.3":  { name: "dhSinglePass-cofactorDH-sha1kdf-scheme", comment: "NIST Key Agreement Algorithms in rfc5753", obsolete: false },
	"1.3.133.16.840.63.0.16": { name: "mqvSinglePass-sha1kdf-scheme", comment: "NIST Key Agreement Algorithms in rfc5753", obsolete: false },
*/
//console.log(m);
		keyEncryptionAlgo.algo = dh_algo;
		keyEncryptionAlgo.kdf = jCastle.digest.getValidAlgoName(m[3]);
		keyEncryptionAlgo.keyAgreement = m[1] + (m[2] && m[2].length ? m[2] : '');

		return keyEncryptionAlgo;
	}
	throw jCastle.exception('UNSUPPORTED_ENCRYPTION_ALGO', 'CMS100');
};

/*
var params = {
	privateKey: private key,
	partyPublicKey: party's public key,
	ephemeralPrivateKey: ephemeral private key,
	partyEphemeralPublicKey: party's ephemeral public key
}
*/
jCastle.cms.fn.kariCalculateWrapKey = function(keyEncryptionAlgorithm, ukm, params)
{
	if (!params.privateKey) throw jCastle.exception('PKI_NOT_SET', 'CMS050');

	var ecdsa = jCastle.pki.create('ecdsa');
	try {
		ecdsa.parsePrivateKey(params.privateKey, params.password);
	} catch (e) {
		if ('parameters' in params) {
			ecdsa.setPrivateKey(params.privateKey, null, params.parameters);
		} else {
			throw jCastle.exception('PARAMS_NOT_SET', 'CMS046');
		}
	}
//console.log(ecdsa);

	var calc_cofactor = false;
	var keylen = jCastle.mcrypt.getKeySize(keyEncryptionAlgorithm.wrap);
//console.log(keylen);

	var other_pubkey = params.partyPublicKey;

	var ecdh = jCastle.ecdh.create();
	ecdh.init(ecdsa);

	var zz;

	switch (keyEncryptionAlgorithm.keyAgreement) {
		case 'dhSinglePass-cofactorDH':
			calc_cofactor = true;
		case 'dhSinglePass-stdDH':

			var cofactor = calc_cofactor ? jCastle.util.toBigInt(ecdsa.getCurveInfo().curve.getH()) : null;
			zz = ecdh.calculateAgreement(other_pubkey, cofactor);
			break;
		case 'mqvSinglePass':
			var ephemeral_prvkey = params.ephemeralPrivateKey;
			if (!ephemeral_prvkey) throw jCastle.exception('PKI_NOT_SET', 'CMS049');

			var ephemeral_other_pubkey = params.partyEphemeralPublicKey;

			zz = ecdh.calculateMQVAgreement(ephemeral_prvkey, other_pubkey, ephemeral_other_pubkey);
			break;
		default: 
			throw jCastle.exception('UNSUPPORTED_ENCRYPTION_ALGO', 'CMS045');
	}

//console.log(jCastle.hex.encode(zz)+'('+zz.length+')');

/*
RFC 5753              Use of ECC Algorithms in CMS

7.2.  Other Syntax

   The following additional syntax is used here.

   When using ECDSA with SignedData, ECDSA signatures are encoded using
   the type:

      ECDSA-Sig-Value ::= SEQUENCE {
        r INTEGER,
        s INTEGER }

   ECDSA-Sig-Value is specified in [PKI-ALG].  Within CMS, ECDSA-Sig-
   Value is DER-encoded and placed within a signature field of
   SignedData.

   When using ECDH and ECMQV with EnvelopedData, AuthenticatedData, and
   AuthEnvelopedData, ephemeral and static public keys are encoded using
   the type ECPoint.  Implementations MUST support uncompressed keys,
   MAY support compressed keys, and MUST NOT support hybrid keys.

      ECPoint ::= OCTET STRING

   When using ECMQV with EnvelopedData, AuthenticatedData, and
   AuthEnvelopedData, the sending agent's ephemeral public key and
   additional keying material are encoded using the type:

      MQVuserKeyingMaterial ::= SEQUENCE {
        ephemeralPublicKey      OriginatorPublicKey,
        addedukm            [0] EXPLICIT UserKeyingMaterial OPTIONAL  }

   The ECPoint syntax is used to represent the ephemeral public key and
   is placed in the ephemeralPublicKey publicKey field.  The additional
   user keying material is placed in the addedukm field.  Then the
   MQVuserKeyingMaterial value is DER-encoded and placed within the ukm
   field of EnvelopedData, AuthenticatedData, or AuthEnvelopedData.

   When using ECDH or ECMQV with EnvelopedData, AuthenticatedData, or
   AuthEnvelopedData, the key-encryption keys are derived by using the
   type:

      ECC-CMS-SharedInfo ::= SEQUENCE {
        keyInfo         AlgorithmIdentifier,
        entityUInfo [0] EXPLICIT OCTET STRING OPTIONAL,
        suppPubInfo [2] EXPLICIT OCTET STRING  }

   The fields of ECC-CMS-SharedInfo are as follows:

      keyInfo contains the object identifier of the key-encryption
      algorithm (used to wrap the CEK) and associated parameters.  In
      this specification, 3DES wrap has NULL parameters while the AES
      wraps have absent parameters.

      entityUInfo optionally contains additional keying material
      supplied by the sending agent.  When used with ECDH and CMS, the
      entityUInfo field contains the octet string ukm.  When used with
      ECMQV and CMS, the entityUInfo contains the octet string addedukm
      (encoded in MQVuserKeyingMaterial).

      suppPubInfo contains the length of the generated KEK, in bits,
      represented as a 32-bit number, as in [CMS-DH] and [CMS-AES].
      (For example, for AES-256 it would be 00 00 01 00.)

   Within CMS, ECC-CMS-SharedInfo is DER-encoded and used as input to
   the key derivation function, as specified in Section 3.6.1 of [SEC1].

   NOTE: ECC-CMS-SharedInfo differs from the OtherInfo specified in
   [CMS-DH].  Here, a counter value is not included in the keyInfo field
   because the key derivation function specified in Section 3.6.1 of
   [SEC1] ensures that sufficient keying data is provided.
*/
	var keylen_bl = Buffer.alloc(4);
	keylen_bl.writeInt32BE(keylen * 8, 0);

	var schema = {
		type: jCastle.asn1.tagSequence,
		items: [{
			type: jCastle.asn1.tagSequence,
			items: [{
				type: jCastle.asn1.tagOID,
				value: jCastle.keyWrap.getOID(keyEncryptionAlgorithm.wrap)
			}/*, {
				type: jCastle.asn1.tagNull,
				value: null
			}*/]
		}]
	};

	if (['3des', 'des3', 'tripledes', 'des-ede3', 'rc2'].includes(keyEncryptionAlgorithm.wrap)) {
		schema.items[0].items.push({
			type: jCastle.asn1.tagNull,
			value: null
		});
	}

	// partyUInfo
	if (ukm && ukm.length) {
		schema.items.push({
			tagClass: jCastle.asn1.tagClassContextSpecific,
			type: 0x00,
			constructed: true,
			items: [{
				type: jCastle.asn1.tagOctetString,
				value: ukm
			}]
		});
	}

	schema.items.push({
		tagClass: jCastle.asn1.tagClassContextSpecific,
		type: 0x02,
		constructed: true,
		items: [{
			type: jCastle.asn1.tagOctetString,
			value: keylen_bl
		}]
	});

	var sharedInfo = Buffer.from(jCastle.asn1.create().getDER(schema), 'latin1');

	var wrapkey = jCastle.kdf.ansX963DeriveKey(keyEncryptionAlgorithm.kdf, keylen, zz, sharedInfo);

	return wrapkey;
};

jCastle.cms.fn.generateAuthMAC = function(content, contentType, authAttrs, macAlgorithm, mackey)
{
	var digestInput;
	if (authAttrs && authAttrs.length) {
		var attrsSchema = jCastle.cms.asn1.attrs.schema(authAttrs, null);
		digestInput = jCastle.asn1.create().getDER(attrsSchema);
	} else {
		digestInput = content;
	}

	if (!Buffer.isBuffer(digestInput)) digestInput = Buffer.from(digestInput, 'latin1');

	var md, mac_params = {};
	mac_params.algoName = macAlgorithm.macInfo.algo;
	mac_params.key = Buffer.from(mackey, 'latin1');

	if ('hmac' == macAlgorithm.macInfo.type) {
		md = jCastle.hmac.create();
	} else {
		md = jCastle.mac.create('cmac');
	}

	var mac = md.start(mac_params)
		.update(digestInput)
		.finalize();

	return mac;
};

jCastle.cms.fn.updateAttr = function(attrs, method, name, data)
{
	var found = false;

	for (var i = 0; i < attrs.length; i++) {
		if (attrs[i].name == name) {
			switch (method) {
				case 'add':
					if (!Array.isArray(attrs[i].data)) {
						attrs[i].data = [attrs[i].data];
					}
					attrs[i].data.push(data);
					break;
				case 'update':
					if (Array.isArray(attrs[i].data)) {
						// to do:
						// what data should be updated?
						attrs[i].data[attrs[i].data.length-1] = data;
					} else {
						attrs[i].data = data;
					}
			}
			found = true;
			break;
		}
	}
	if (!found) attrs.push({
		name: name,
		data: data
	});
};

jCastle.cms.fn.getEncryptionParameters = function(enc_algo_info, options = {})
{
//console.log(enc_algo_info);
	var prng = new jCastle.prng();
	var params = enc_algo_info.params || {};
	var algo_info = enc_algo_info.algoInfo;

//	if ('mode' in algo_info) params.mode = algo_info.mode;
//	if ('keySize' in algo_info) params.keySize = algo_info.keySize;

	var opt_params = jCastle.mcrypt.getAlgoParameters(options);
	for (var i in opt_params) params[i] = opt_params[i];

	jCastle.mcrypt.checkAlgoParameters(params, algo_info.algo, algo_info.mode, prng);
//console.log(params);
	return params;
};


jCastle.cms.version = {

	signedData: function(signerInfos, encapContentInfo, certs, crls)
	{
/*
      version is the syntax version number.  The appropriate value
      depends on certificates, eContentType, and SignerInfo.  The
      version MUST be assigned as follows:

         IF ((certificates is present) AND
            (any certificates with a type of other are present)) OR
            ((crls is present) AND
            (any crls with a type of other are present))
         THEN version MUST be 5
         ELSE
            IF (certificates is present) AND
               (any version 2 attribute certificates are present)
            THEN version MUST be 4
            ELSE
               IF ((certificates is present) AND
                  (any version 1 attribute certificates are present)) OR
                  (any SignerInfo structures are version 3) OR
                  (encapContentInfo eContentType is other than id-data)
               THEN version MUST be 3
               ELSE version MUST be 1
*/
/*
https://en.wikipedia.org/wiki/X.509

The structure of version 1 is given in RFC 1422.[5]

ITU-T introduced issuer and subject unique identifiers in version 2 to permit the reuse
of issuer or subject name after some time. An example of reuse will be when a CA goes
bankrupt and its name is deleted from the country's public list. After some time another
CA with the same name may register itself, even though it is unrelated to the first one.
However, IETF recommends that no issuer and subject names be reused. Therefore, version 2
is not widely deployed in the Internet.

Extensions were introduced in version 3. A CA can use extensions to issue a certificate
only for a specific purpose (e.g. only for signing digital objects).

In all versions, the serial number must be unique for each certificate issued by a specific
CA (as mentioned in RFC 5280). 
*/
		certs = certs || [];
		crls = crls || [];

		if (certs.length && crls.length) return 5;

		var ver1_attr = false;
		for (var i = 0; i < certs.length; i++) {
			var cert_info = new jCastle.certificate().parse(certs[i]);
			if (!('version' in cert_info.tbs)) ver1_attr = true;
			if ('issuerUniqueID' in cert_info.tbs || 'subjectUniqueID' in cert_info.tbs) return 4;
		}
		if (ver1_attr) return 3;

		for (var i = 0; i < signerInfos.length; i++) {
			if (certs.length && signerInfos[i].version == 3) return 3;
		}

		if (certs.length && encapContentInfo.contentType && encapContentInfo.contentType != 'data') return 3;

		return 1;
	},

	envelopedData: function(originatorInfo, recipientInfos, unprotectedAttrs)
	{
/*
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
*/
		var certs = originatorInfo.certificates || [];
		var crls = originatorInfo.crls || [];

		if (certs.length && crls.length) return 4;

		var ver2_attr = false;
		for (var i = 0; i < certs.length; i++) {
			var cert_info = new jCastle.certificate().parse(certs[i]);
			if ('version' in cert_info.tbs && cert_info.tbs.version > 1) return 4; // 2 means version 3
			if ('issuerUniqueID' in cert_info.tbs || 'subjectUniqueID' in cert_info.tbs) ver2_attr = true;
		}

		var f_ver0 = true;
		for (var i = 0; i < recipientInfos.length; i++) {
			var type = recipientInfos[i].type;
			if (ver2_attr && (type == 'passwordRecipientInfo' || type == 'otherRecipientInfo')) return 3;
			if (recipientInfos[i].version != 0) f_ver0 = false;
		}

		if (!certs.length && !crls.length && !unprotectedAttrs.length && f_ver0) return 0;

		return 2;
	},

	authenticatedData: function(originatorInfo)
	{
/*
      version is the syntax version number.  The version MUST be
      assigned as follows:

		 IF (originatorInfo is present) AND
            ((any certificates with a type of other are present) OR
            (any crls with a type of other are present))
         THEN version is 3
         ELSE
            IF ((originatorInfo is present) AND
               (any version 2 attribute certificates are present))
            THEN version is 1
            ELSE version is 0
*/
		var certs = originatorInfo.certificates || [];
		var crls = originatorInfo.crls || [];

		if (certs.length && crls.length) return 3;

		var ver2_attr = false;
		for (var i = 0; i < certs.length; i++) {
			var cert_info = new jCastle.certificate().parse(certs[i]);
			if ('version' in cert_info.tbs && cert_info.tbs.version > 1) return 3; // 2 means version 3
			if ('issuerUniqueID' in cert_info.tbs || 'subjectUniqueID' in cert_info.tbs) ver2_attr = true;
		}

		if (ver2_attr) return 1;

		return 0;
	}
};


jCastle.cms.verifySignedData = function(cms_info, strict = false)
{
	if (jCastle.util.isString(cms_info) && Buffer.isBuffer(cms_info)) {
		cms_info = jCastle.cms.create().parse(cms_info);
	}

	var content = cms_info.content.encapContentInfo.content;
	var cert = new jCastle.certificate();

	for (var i = 0; i < cms_info.content.signerInfos.length; i++) {
		var signer_info = cms_info.content.signerInfos[i];
		var cert_info = cms_info.content.certificates[i];
		cert.parse(cert_info);
		var pubkey = cert.createPKIFromPublicKeyInfo();
		var hash_algo = signer_info.digestAlgorithm;
		var signature = signer_info.signature;
		if ('signedAttrs' in signer_info && signer_info.signedAttrs.length) {
//			var der = jCastle.asn1.create().getDER(jCastle.cms.asn1.attrs.schema(signer_info.signedAttrs, null));
//			content += der;
			content = jCastle.asn1.create().getDER(jCastle.cms.asn1.attrs.schema(signer_info.signedAttrs, null));
		}
		var result = pubkey.verify(content, signature, { hashAlgo: hash_algo });

		if (strict) {
			if (!result) return false;
			cert.reset();
		} else {
			if (result) return true;
		}
	}

	return strict ? true : false;
};

/*
9.3.  MAC Verification

   The input to the MAC verification process includes the input data
   (determined based on the presence or absence of the authAttrs field,
   as defined in 9.2), and the authentication key conveyed in
   recipientInfo.  The details of the MAC verification process depend on
   the MAC algorithm employed.

   The recipient MUST NOT rely on any MAC values or message digest
   values computed by the originator.  The content is authenticated as
   described in Section 9.2.  If the originator includes authenticated
   attributes, then the content of the authAttrs is authenticated as
   described in Section 9.2.  For authentication to succeed, the MAC
   value calculated by the recipient MUST be the same as the value of
   the mac field.  Similarly, for authentication to succeed when the
   authAttrs field is present, the content message digest value
   calculated by the recipient MUST be the same as the message digest
   value included in the authAttrs message-digest attribute.

   If the AuthenticatedData includes authAttrs, then the content-type
   attribute value MUST match the AuthenticatedData encapContentInfo
   eContentType value.
*/
jCastle.cms.verifyDigestedData = function(cms_info)
{
	if (jCastle.util.isString(cms_info) && Buffer.isBuffer(cms_info)) {
		cms_info = jCastle.cms.create().parse(cms_info);
	}

	var content = Buffer.from(cms_info.content.encapContentInfo.content, 'latin1');
	var hashAlgo = cms_info.content.digestAlgorithm;

	var md = new jCastle.digest(hashAlgo);
	var hash = md.digest(content);

	return hash.equals(Buffer.from(cms_info.content.digest, 'latin1'));
};

jCastle.cms.verifyAuthenticatedData = function(cms_info, cmsKey)
{
	if (jCastle.util.isString(cms_info) && Buffer.isBuffer(cms_info)) {
		cms_info = jCastle.cms.create().parse(cms_info, cmsKey);
	}

	var decryptedKey = null;
	var recipientInfos = cms_info.content.recipientInfos;
	for (var i = 0; i < recipientInfos.length; i++) {
		// decryptedKey can be null.
		if ('decryptedKey' in recipientInfos[i] && recipientInfos[i].decryptedKey) {
			decryptedKey = Buffer.from(recipientInfos[i].decryptedKey, 'latin1');
			break;
		}
	}

	if (decryptedKey) {
		var content = cms_info.content.encapContentInfo.content;
		var contentType = cms_info.content.encapContentInfo.contentType;
		var authAttrs = cms_info.content.authAttrs;
		var macAlgorithm = cms_info.content.macAlgorithm;

		var mac = jCastle.cms.fn.generateAuthMAC(
				content, 
				contentType, 
				authAttrs, 
				macAlgorithm, 
				decryptedKey);

		return mac.equals(Buffer.from(cms_info.content.mac, 'latin1'));
	}
	return false;
};


jCastle.cms.verifyAuthEnvelopedData = function(cms_info, cmsKey)
{
	if (jCastle.util.isString(cms_info) && Buffer.isBuffer(cms_info)) {
		cms_info = jCastle.cms.create().parse(cms_info, cmsKey);
	}

	var decryptedKey = null;
	var recipientInfos = cms_info.content.recipientInfos;
	var authEncryptedContentInfo = cms_info.content.authEncryptedContentInfo;
	for (var i = 0; i < recipientInfos.length; i++) {
		if ('decryptedKey' in recipientInfos[i]) {
			decryptedKey = Buffer.from(recipientInfos[i].decryptedKey, 'latin1');
			break;
		}
	}

	if (decryptedKey) {
		var enc_algo_info = authEncryptedContentInfo.contentEncryptionAlgorithm;
		var algo = enc_algo_info.algo;
		var algoInfo = 'algoInfo' in enc_algo_info ? enc_algo_info.algoInfo : jCastle.pbe.getAlgorithmInfo(algo);
		var params = enc_algo_info.params;


		params.key = decryptedKey;
		params.mode = algoInfo.mode;
		params.isEncryption = true;
		params.padding = 'pkcs7';
			
		if (authAttrs) {
			var attrsSchema = jCastle.cms.asn1.attrs.schema(authAttrs, null);
			var aad = jCastle.asn1.create().getDER(attrsSchema);
			params.additionalData = Buffer.from(aad, 'latin1');
		}

		var crypto = new jCastle.mcrypt(algoInfo.algo);
		crypto.start(params);
		crypto.update(Buffer.from(authEncryptedContentInfo.encryptedContent, 'latin1'));
		var decryptedContent = crypto.finalize();

		var tag_size = 'tagSize' in params ? params.tagSize : algoInfo.blockSize;

		var mac_check = decryptedContent.slice(decryptedContent.length - tag_size);

		return mac_check.equals(Buffer.from(cms_info.content.mac, 'latin1'));
	}

	return false;
};

jCastle.cms.verify = {
	signedData: jCastle.cms.verifySignedData,
	digestedData: jCastle.cms.verifyDigestedData,
	authenticatedData: jCastle.cms.verifyAuthenticatedData,
	authEnvelopedData: jCastle.cms.verifyAuthEnvelopedData
};

jCastle.cms.asn1 = {};

jCastle.cms.asn1.signerInfos = {
/*
      SignerInfo ::= SEQUENCE {
        version CMSVersion,
        sid SignerIdentifier,
        digestAlgorithm DigestAlgorithmIdentifier,
        signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
        signatureAlgorithm SignatureAlgorithmIdentifier,
        signature SignatureValue,
        unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL }

      SignerIdentifier ::= CHOICE {
        issuerAndSerialNumber IssuerAndSerialNumber,
        subjectKeyIdentifier [0] SubjectKeyIdentifier }

      SignedAttributes ::= SET SIZE (1..MAX) OF Attribute

      UnsignedAttributes ::= SET SIZE (1..MAX) OF Attribute

      Attribute ::= SEQUENCE {
        attrType OBJECT IDENTIFIER,
        attrValues SET OF AttributeValue }

      AttributeValue ::= ANY

      SignatureValue ::= OCTET STRING
*/

	parse: function(set_obj)
	{
		var signerInfos = [];

		for (var i = 0; i < set_obj.items.length; i++) {
			var signerInfo = jCastle.cms.asn1.signerInfo.parse(set_obj.items[i]);
			signerInfos.push(signerInfo);
		}

		return signerInfos;
	},

	schema: function(signerInfos, content, contentType, cmsKeys)
	{
/*
      SignerInfo ::= SEQUENCE {
        version CMSVersion,
        sid SignerIdentifier,
        digestAlgorithm DigestAlgorithmIdentifier,
        signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
        signatureAlgorithm SignatureAlgorithmIdentifier,
        signature SignatureValue,
        unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL }

      SignerIdentifier ::= CHOICE {
        issuerAndSerialNumber IssuerAndSerialNumber,
        subjectKeyIdentifier [0] SubjectKeyIdentifier }

      SignedAttributes ::= SET SIZE (1..MAX) OF Attribute

      UnsignedAttributes ::= SET SIZE (1..MAX) OF Attribute

      Attribute ::= SEQUENCE {
        attrType OBJECT IDENTIFIER,
        attrValues SET OF AttributeValue }

      AttributeValue ::= ANY

      SignatureValue ::= OCTET STRING
*/
/*
      SET (1 elem)
        SEQUENCE (5 elem)
          INTEGER 1
          SEQUENCE (2 elem)
            SEQUENCE (4 elem)
              SET (1 elem)
                SEQUENCE (2 elem)
                  OBJECT IDENTIFIER 2.5.4.6 countryName (X.520 DN component)
                  PrintableString kr
              SET (1 elem)
                SEQUENCE (2 elem)
                  OBJECT IDENTIFIER 2.5.4.10 organizationName (X.520 DN component)
                  UTF8String yessign
              SET (1 elem)
                SEQUENCE (2 elem)
                  OBJECT IDENTIFIER 2.5.4.11 organizationalUnitName (X.520 DN component)
                  UTF8String AccreditedCA
              SET (1 elem)
                SEQUENCE (2 elem)
                  OBJECT IDENTIFIER 2.5.4.3 commonName (X.520 DN component)
                  UTF8String yessignCA Class 2
            INTEGER 591952899
          SEQUENCE (2 elem)
            OBJECT IDENTIFIER 2.16.840.1.101.3.4.2.1 sha-256 (NIST Algorithm)
            NULL
          SEQUENCE (2 elem)
            OBJECT IDENTIFIER 1.2.840.113549.1.1.1 rsaEncryption (PKCS #1)
            NULL
          OCTET STRING (256 byte) DAD5D7E4145180499FE828827246051BA03DA828A1648ACAA8C9CB9F27B3EBAC097EC…
*/
		var signerInfosSchema = {
			type: jCastle.asn1.tagSet,
			items:[]
		};

		for (var i = 0; i < signerInfos.length; i++) {
			var infoSchema = jCastle.cms.asn1.signerInfo.schema(signerInfos[i], content, contentType, cmsKeys[i]);
			signerInfosSchema.items.push(infoSchema);
		}

		return signerInfosSchema;
	}
};

/*
      SignerInfo ::= SEQUENCE {
        version CMSVersion,
        sid SignerIdentifier,
        digestAlgorithm DigestAlgorithmIdentifier,
        signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
        signatureAlgorithm SignatureAlgorithmIdentifier,
        signature SignatureValue,
        unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL }

      SignerIdentifier ::= CHOICE {
        issuerAndSerialNumber IssuerAndSerialNumber,
        subjectKeyIdentifier [0] SubjectKeyIdentifier }

      SignedAttributes ::= SET SIZE (1..MAX) OF Attribute

      UnsignedAttributes ::= SET SIZE (1..MAX) OF Attribute

      Attribute ::= SEQUENCE {
        attrType OBJECT IDENTIFIER,
        attrValues SET OF AttributeValue }

      AttributeValue ::= ANY

      SignatureValue ::= OCTET STRING
*/
jCastle.cms.asn1.signerInfo = {
	parse: function(sequence)
	{
		var idx = 0;

		// version CMSVersion
		var version = sequence.items[idx++].intVal;
		var obj = sequence.items[idx++];

		// sid SignerIdentifier
		var sid = {}; // signerIdentifier
		if (obj.tagClass == jCastle.asn1.tagClassContextSpecific && obj.type == 0x00) {
			// subjectKeyIdentifier
/*
SEQUENCE(2 elem)
	OBJECT IDENTIFIER					2.5.29.14 -- subjectKeyIdentifier
	OCTET STRING(1 elem)
		OCTET STRING(20 byte)			2C268A2F0BC21023A34940DCC45A3156770E41B1
*/
			sid.subjectKeyIdentifier = Buffer.from(obj.items[1].value.value, 'latin1');
		} else if (obj.type == jCastle.asn1.tagSequence) {
			// issuerAndSerialNumber
/*
          SEQUENCE (2 elem)
            SEQUENCE (4 elem)
              SET (1 elem)
                SEQUENCE (2 elem)
                  OBJECT IDENTIFIER 2.5.4.6																	countryName (X.520 DN component)
                  PrintableString kr
              SET (1 elem)
                SEQUENCE (2 elem)
                  OBJECT IDENTIFIER 2.5.4.10																organizationName (X.520 DN component)
                  UTF8String yessign
              SET (1 elem)
                SEQUENCE (2 elem)
                  OBJECT IDENTIFIER 2.5.4.11																organizationalUnitName (X.520 DN component)
                  UTF8String AccreditedCA
              SET (1 elem)
                SEQUENCE (2 elem)
                  OBJECT IDENTIFIER 2.5.4.3																	commonName (X.520 DN component)
                  UTF8String yessignCA Class 2
            INTEGER 591952899
*/
			sid.issuer = jCastle.certificate.asn1.directoryName.parse(obj.items[0]);
			sid.serialNumber = obj.items[1].intVal;
		}
		obj = sequence.items[idx++];

		// digestAlgorithm DigestAlgorithmIdentifier
		var digestAlgorithm;
		if (obj.type == jCastle.asn1.tagSequence) {
			digestAlgorithm = jCastle.oid.getName(obj.items[0].value);
			obj = sequence.items[idx++];
		}

		// signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL
		var signedAttrs = null;
		if (obj.tagClass == jCastle.asn1.tagClassContextSpecific && obj.type == 0x00) {
			signedAttrs = jCastle.cms.asn1.attrs.parse(obj);
//			signedAttrsDer = obj.der;
			obj = sequence.items[idx++];
		}


		// signatureAlgorithm SignatureAlgorithmIdentifier
		var signatureAlgorithm;
		if (obj.type == jCastle.asn1.tagSequence) {
			//var signatureAlgorithm = jCastle.oid.getName(obj.items[0].value);
			signatureAlgorithm = jCastle.certificate.asn1.encryptionInfo.parse(obj);
			obj = sequence.items[idx++];
		}

		// signature SignatureValue
		var signature = Buffer.from(obj.value, 'latin1');
			
		idx++;

		// unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL
		var unsignedAttrs = null;
		if (obj.tagClass == jCastle.asn1.tagClassContextSpecific && obj.type == 0x00) {
			unsignedAttrs = jCastle.cms.asn1.attrs.parse(obj);
		}

		var signerInfo = {
			version: version,
			signerIdentifier: sid,
			digestAlgorithm: digestAlgorithm,
			signatureAlgorithm: signatureAlgorithm,
			signature: signature			
		};

		if (signedAttrs) {
			signerInfo.signedAttrs = signedAttrs;
//			signerInfo.signedAttrsDer = signedAttrsDer;
		}
		if (unsignedAttrs) signerInfo.unsignedAttrs = unsignedAttrs;

		return signerInfo;
	},

/*
      SignerInfo ::= SEQUENCE {
        version CMSVersion,
        sid SignerIdentifier,
        digestAlgorithm DigestAlgorithmIdentifier,
        signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
        signatureAlgorithm SignatureAlgorithmIdentifier,
        signature SignatureValue,
        unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL }
*/
	schema: function(signerInfo, content, contentType, cmsKey)
	{
		// prepare

		var version = 1;

		var cert_info = jCastle.certificate.create().parse(cmsKey.certificate);
		var signerIdentifier = {};

		var identifierType = 'identifierType' in signerInfo ? signerInfo.identifierType : 'issuerAndSerialNumber';
		if (identifierType == 'subjectKeyIdentifier' &&
			(!('extensions' in cert_info.tbs) || !('subjectKeyIdentifier' in cert_info.tbs.extensions))) {
			identifierType = 'issuerAndSerialNumber';
		}

		if (identifierType == 'subjectKeyIdentifier') {
			version = 3;
			signerIdentifier.subjectKeyIdentifier = cert_info.tbs.extensions.subjectKeyIdentifier;
		} else {
			signerIdentifier.issuer = cert_info.tbs.issuer;
			signerIdentifier.serialNumber = cert_info.tbs.serialNumber;
		}
		
		var digestAlgorithm = 'digestAlgorithm' in signerInfo ? signerInfo.digestAlgorithm : 'sha-1';

		var signedAttrs = 'signedAttrs' in signerInfo ? signerInfo.signedAttrs : [];

		if (contentType != 'data') {
			var input = content;
			if (!jCastle.util.isString(input) && !Buffer.isBuffer(input)) {
				input = jCastle.cms.create().getDER(input);
				input = Buffer.from(input, 'latin1');
			}
			var md = jCastle.digest.create(digestAlgorithm);
			var messageDigest = md.start().update(input)
			.finalize();
			
			jCastle.cms.fn.updateAttr(signedAttrs, 'update', 'contentType', {
				type: jCastle.asn1.tagOID,
				value: jCastle.oid.getOID(contentType)
			});
			jCastle.cms.fn.updateAttr(signedAttrs, 'update', 'messageDigest', {
				type: jCastle.asn1.tagOctetString,
				value: messageDigest
			});
		}

		var unsignedAttrs = 'unsignedAttrs' in signerInfo ? signerInfo.unsignedAttrs : [];

		var infoSchema = {
			type: jCastle.asn1.tagSequence,
			items:[]
		};

		// version CMSVersion
		infoSchema.items.push({
			type: jCastle.asn1.tagInteger,
			intVal: version
		});

		// sid SignerIdentifier
		var signerIdentifierSchema;
		if ('subjectKeyIdentifier' in signerIdentifier) {
			signerIdentifierSchema = {
				type: 0x00,
				tagClass: jCastle.asn1.tagClassContextSpecific,
				constructed: false,
				value: signerIdentifier.subjectKeyIdentifier
			}
		} else {
			signerIdentifierSchema = {
				type: jCastle.asn1.tagSequence,
				items:[
					jCastle.certificate.asn1.directoryName.schema(signerIdentifier.issuer),
				{
					type: jCastle.asn1.tagInteger,
					intVal: signerIdentifier.serialNumber
				}]
			};
		}
		infoSchema.items.push(signerIdentifierSchema);

		// digestAlgorithm DigestAlgorithmIdentifier
		infoSchema.items.push({
			type: jCastle.asn1.tagSequence,
			items:[{
				type: jCastle.asn1.tagOID,
				value: jCastle.oid.getOID(digestAlgorithm)
			}, {
				type: jCastle.asn1.tagNull,
				value: null
			}]
		});

		// signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL
		if (signedAttrs.length) {
			infoSchema.items.push(jCastle.cms.asn1.attrs.schema(signedAttrs, 0x00));
		}

		// signatureAlgorithm SignatureAlgorithmIdentifier
		infoSchema.items.push(jCastle.certificate.asn1.encryptionInfo.schema(signerInfo.signatureAlgorithm));

		// signature SignatureValue
		var signature = '';

		if (!('privateKey' in cmsKey)) throw jCastle.exception('PRIVKEY_NOT_SET', 'CMS013');

		var hashAlgo = signerInfo.digestAlgorithm;
		var pki = new jCastle.pki();
		var privkey = cmsKey.privateKey;

		if (jCastle.util.isString(privkey) || Buffer.isBuffer(privkey)) {
			pki.parsePrivateKey(privkey, cmsKey.password);
		} else {
			// console.log('privkey: ', privkey);
			pki.init(privkey);
		}

		if (pki.pkiName != signerInfo.signatureAlgorithm.algo) throw jCastle.exception('INVALID_PRIVKEY', 'CMS014');

		var data = content;

		if (!jCastle.util.isString(data) && !Buffer.isBuffer(data)) {
			data = jCastle.cms.create().getDER(data);
			data = Buffer.from(data, 'latin1');
		}

		if (signedAttrs.length) {
//			var der = jCastle.asn1.create().getDER(jCastle.cms.asn1.attrs.schema(signedAttrs, null));
//			data += der;
			data = jCastle.asn1.create().getDER(jCastle.cms.asn1.attrs.schema(signedAttrs, null));
			data = Buffer.from(data, 'latin1');
		}

		signature = pki.sign(data, {hashAlgo: hashAlgo});

		infoSchema.items.push({
			type: jCastle.asn1.tagOctetString,
			value: signature
		});

		// unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL
		if (unsignedAttrs.length) {
			infoSchema.items.push(jCastle.cms.asn1.attrs.schema(unsignedAttrs, 0x01));
		}

		return infoSchema;
	}
};

jCastle.cms.asn1.attrs = {
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
	parse: function(implicit)
	{
		var attrs = [];
			
		for (var i = 0; i < implicit.items.length; i++) {
			var attr = jCastle.cms.asn1.attr.parse(implicit.items[i]);
			attrs.push(attr);
		}

		return attrs;
	},

	schema: function(attrs, type)
	{
		var attrsSchema;

		if (type === null) { // set
			attrsSchema = {
				type: jCastle.asn1.tagSet,
				items: []
			};
		} else {
			attrsSchema = {
				type: type,
				tagClass: jCastle.asn1.tagClassContextSpecific,
				constructed: true,
				items: []
			};
		}

		for (var i = 0; i < attrs.length; i++) {
			var attrSchema = jCastle.cms.asn1.attr.schema(attrs[i]);
			attrsSchema.items.push(attrSchema);
		}

		return attrsSchema;
	}
};

/*
{
	name: 'contentType',
	data: {
		type: jCastle.asn1.tagOID,
		value: 'data'
	}
}
or 
{
	name: 'some-oid-name',
	data: [
		{
			type: jCastle.asn1.tagUTCTime,
			value: 'time-value'
		}, {
			type: jCastle.asn1.tagGeneralizedTime,
			value: 'time-value-1'
		}
	]
}
*/
/*
	SEQUENCE(2 elem)
		OBJECT IDENTIFIER															1.2.840.113549.1.9.3  -- contentType
		SET(1 elem)
			OBJECT IDENTIFIER														1.2.840.113549.1.7.1  -- data
*/
// to do: countersignature
jCastle.cms.asn1.attr = {
	parse: function(sequence)
	{
		var name = jCastle.oid.getName(sequence.items[0].value);
		var value, attr;

		var seq = sequence.items[1];

		if (seq.items.length == 1) {
			attr = {
				name: name,
				data: {
					type: seq.items[0].type,
					value: seq.items[0].value
				}
			};

			if (attr.data.type == jCastle.asn1.tagOID) {
				value = jCastle.oid.getName(attr.data.value);
				if (value !== false) attr.data.value = value;
			}
		} else {
			attr = {
				name: name,
				data: []
			};
			for (var i = 0; i < seq.items.length; i++) {
				var data = {
					type: seq.items[i].type,
					value: seq.items[i].value
				};

				if (data.data.type == jCastle.asn1.tagOID) {
					value = jCastle.oid.getName(data.data.value);
					if (value !== false) data.data.value = value;
				}

				attr.data.push(data);
			}
		}

		return attr;
	},

	schema: function(attr)
	{
		var attrSchema = {
			type: jCastle.asn1.tagSequence,
			items: [{
				type: jCastle.asn1.tagOID,
				value: jCastle.oid.getOID(attr.name)
			}, {
				type: jCastle.asn1.tagSet,
				items: []
			}]
		};

		var data;

		if (Array.isArray(attr.data)) {
			data = attr.data;
		} else {
			data = [attr.data];
		}

		for (var i = 0; i < data.length; i++) {
			attrSchema.items[1].items.push({
				type: data[i].type,
				value: data[i].type == jCastle.asn1.tagOID ? jCastle.oid.getOID(data[i].value) : data[i].value
			});
		}

		return attrSchema;
	}
};

jCastle.cms.asn1.encapContentInfo = {
	parse: function(obj, options = {})
	{
		var encapContentInfo = {};

		if (obj.type == jCastle.asn1.tagSequence) {
			var eContentType = jCastle.oid.getName(obj.items[0].value);
			var eContent = null;
			if (typeof obj.items[1] != 'undefined' && 
				obj.items[1].tagClass == jCastle.asn1.tagClassContextSpecific && obj.items[1].type == 0x00) {
				eContent = obj.items[1].items[0].value;

				eContent = jCastle.cms.content.parse(eContent);
			}
			encapContentInfo.contentType = eContentType;
			encapContentInfo.content = eContent;
		}

		return encapContentInfo;
	},

	//schema: function(cmsInfo, options)
	schema: function(encapContentInfo, options = {})
	{
/*
      SEQUENCE (2 elem)
        OBJECT IDENTIFIER 1.2.840.113549.1.7.1 data (PKCS #7)
        [0] (1 elem)
          OCTET STRING imgg
*/
		var contentType = 'contentType' in encapContentInfo ? encapContentInfo.contentType : 'data';
		var eContent;
		
		if (jCastle.util.isString(encapContentInfo.content)) eContent = encapContentInfo.content;
		else eContent = jCastle.cms.content.getDER(encapContentInfo.content);

		var encapContentInfoSchema = {
			type: jCastle.asn1.tagSequence,
			items:[{
				type: jCastle.asn1.tagOID,
				value: jCastle.oid.getOID(contentType)
			}, {
				type: 0,
				tagClass: jCastle.asn1.tagClassContextSpecific,
				constructed: true,
				items:[{
					type: jCastle.asn1.tagOctetString,
					value: eContent
				}]
			}]
		};

		return encapContentInfoSchema;
	}
};

jCastle.cms.asn1.certificateSet = {
	parse: function(set_obj)
	{
/*
RFC 5652

10.2.2.  CertificateChoices

   The CertificateChoices type gives either a PKCS #6 extended
   certificate [PKCS#6], an X.509 certificate, a version 1 X.509
   attribute certificate (ACv1) [X.509-97], a version 2 X.509 attribute
   certificate (ACv2) [X.509-00], or any other certificate format.  The
   PKCS #6 extended certificate is obsolete.  The PKCS #6 certificate is
   included for backward compatibility, and PKCS #6 certificates SHOULD
   NOT be used.  The ACv1 is also obsolete.  ACv1 is included for
   backward compatibility, and ACv1 SHOULD NOT be used.  The Internet
   profile of X.509 certificates is specified in the "Internet X.509
   Public Key Infrastructure: Certificate and CRL Profile" [PROFILE].
   The Internet profile of ACv2 is specified in the "An Internet
   Attribute Certificate Profile for Authorization" [ACPROFILE].  The
   OtherCertificateFormat alternative is provided to support any other
   certificate format without further modifications to the CMS.

   The definition of Certificate is taken from X.509.

   The definitions of AttributeCertificate are taken from X.509-1997 and
   X.509-2000.  The definition from X.509-1997 is assigned to
   AttributeCertificateV1 (see Section 12.2), and the definition from
   X.509-2000 is assigned to AttributeCertificateV2.

      CertificateChoices ::= CHOICE {
       certificate Certificate,
       extendedCertificate [0] IMPLICIT ExtendedCertificate, -- Obsolete
       v1AttrCert [1] IMPLICIT AttributeCertificateV1,       -- Obsolete
       v2AttrCert [2] IMPLICIT AttributeCertificateV2,
       other [3] IMPLICIT OtherCertificateFormat }

      OtherCertificateFormat ::= SEQUENCE {
        otherCertFormat OBJECT IDENTIFIER,
        otherCert ANY DEFINED BY otherCertFormat }

10.2.3.  CertificateSet

   The CertificateSet type provides a set of certificates.  It is
   intended that the set be sufficient to contain certification paths
   from a recognized "root" or "top-level certification authority" to
   all of the sender certificates with which the set is associated.
   However, there may be more certificates than necessary, or there MAY
   be fewer than necessary.

   The precise meaning of a "certification path" is outside the scope of
   this document.  However, [PROFILE] provides a definition for X.509
   certificates.  Some applications may impose upper limits on the
   length of a certification path; others may enforce certain
   relationships between the subjects and issuers of certificates within
   a certification path.

      CertificateSet ::= SET OF CertificateChoices
*/
		var certs = [], cert;
		var cert_parser = jCastle.certificate.create();

		for (var i = 0; i < set_obj.items.length; i++) {
			if (set_obj.items[i].tagClass && set_obj.items[i].tagClass == jCastle.asn1.tagClassContextSpecific) {
				throw jCastle.exception('UNSUPPORTED_CERT_TYPE', 'CMS015');
			}
			try {
				cert = cert_parser.parse(set_obj.items[i], 'asn1');
			} catch (e) {
				throw jCastle.exception('INVALID_ASN1', 'CMS016');
			}

			certs.push(cert);
			cert_parser.reset();
		}

		return certs;
	}
};

jCastle.cms.asn1.revocationInfoChoices = {
	parse: function(set_obj)
	{
/*
10.2.1.  RevocationInfoChoices

   The RevocationInfoChoices type gives a set of revocation status
   information alternatives.  It is intended that the set contain
   information sufficient to determine whether the certificates and
   attribute certificates with which the set is associated are revoked.
   However, there MAY be more revocation status information than
   necessary or there MAY be less revocation status information than
   necessary.  X.509 Certificate revocation lists (CRLs) [X.509-97] are
   the primary source of revocation status information, but any other
   revocation information format can be supported.  The
   OtherRevocationInfoFormat alternative is provided to support any
   other revocation information format without further modifications to
   the CMS.  For example, Online Certificate Status Protocol (OCSP)
   Responses [OCSP] can be supported using the
   OtherRevocationInfoFormat.

   The CertificateList may contain a CRL, an Authority Revocation List
   (ARL), a Delta CRL, or an Attribute Certificate Revocation List.  All
   of these lists share a common syntax.

   The CertificateList type gives a certificate revocation list (CRL).
   CRLs are specified in X.509 [X.509-97], and they are profiled for use
   in the Internet in RFC 5280 [PROFILE].

   The definition of CertificateList is taken from X.509.

      RevocationInfoChoices ::= SET OF RevocationInfoChoice

      RevocationInfoChoice ::= CHOICE {
        crl CertificateList,
        other [1] IMPLICIT OtherRevocationInfoFormat }

      OtherRevocationInfoFormat ::= SEQUENCE {
        otherRevInfoFormat OBJECT IDENTIFIER,
        otherRevInfo ANY DEFINED BY otherRevInfoFormat }
*/
		var crls = [], crl;
		var cert_parser = jCastle.certificate.create();

		for (var i = 0; i < set_obj.items.length; i++) {
			if (set_obj.items[i].tagClass && set_obj.items[i].tagClass == jCastle.asn1.tagClassContextSpecific) {
				throw jCastle.exception('UNSUPPORTED_CERT_TYPE', 'CMS017');
			}
			try {
				crl = cert_parser.parse(set_obj.items[i], 'asn1');
			} catch (e) {
				throw jCastle.exception('INVALID_ASN1', 'CMS018');
			}

			crls.push(crl);
			cert_parser.reset();
		}

		return crls;

	}
};

jCastle.cms.asn1.recipientInfos = {
	parse: function(set_obj, cmsKey)
	{
		var recipientInfos = [];
//console.log(set_obj);	
		for (var i = 0; i < set_obj.items.length; i++) {
//			var recipientInfo = jCastle.cms.asn1.recipientInfo.parse(set_obj.items[i], options);
			var recipientInfo = jCastle.cms.asn1.recipientInfo.parse(set_obj.items[i], cmsKey);
			recipientInfos.push(recipientInfo);
		}

		return recipientInfos;
	},

	schema: function(recipientInfos, encryptKey, cmsKeys, options)
	{
		var recipientInfosSchema = {
			type: jCastle.asn1.tagSet,
			items:[]
		};

		for (var i = 0; i < recipientInfos.length; i++) {
			//var recipientInfoSchema = jCastle.cms.asn1.recipientInfo.schema(recipientInfos[i], keymaterial, options);
			var recipientInfoSchema = jCastle.cms.asn1.recipientInfo.schema(recipientInfos[i], encryptKey, cmsKeys[i], options);
			recipientInfosSchema.items.push(recipientInfoSchema);
		}

		return recipientInfosSchema;
	}
};

jCastle.cms.asn1.recipientInfo = {
	parse: function(riObj, cmsKey)
	{
/*
      RecipientInfos ::= SET SIZE (1..MAX) OF RecipientInfo

      RecipientInfo ::= CHOICE {
        ktri KeyTransRecipientInfo,
        kari [1] KeyAgreeRecipientInfo,
        kekri [2] KEKRecipientInfo,
        pwri [3] PasswordRecipientinfo,
        ori [4] OtherRecipientInfo }

      EncryptedKey ::= OCTET STRING
*/
/*
6.2.  RecipientInfo Type

   Per-recipient information is represented in the type RecipientInfo.
   RecipientInfo has a different format for each of the supported key
   management techniques.  Any of the key management techniques can be
   used for each recipient of the same encrypted content.  In all cases,
   the encrypted content-encryption key is transferred to one or more
   recipients.

   Since all implementations will not support every possible key
   management algorithm, all implementations MUST gracefully handle
   unimplemented algorithms when they are encountered.  For example, if
   a recipient receives a content-encryption key encrypted in their RSA
   public key using RSA-OAEP (Optimal Asymmetric Encryption Padding) and
   the implementation only supports RSA PKCS #1 v1.5, then a graceful
   failure must be implemented.

   Implementations MUST support key transport, key agreement, and
   previously distributed symmetric key-encryption keys, as represented
   by ktri, kari, and kekri, respectively.  Implementations MAY support
   the password-based key management as represented by pwri.
   Implementations MAY support any other key management technique as
   represented by ori.  Since each recipient can employ a different key
   management technique and future specifications could define
   additional key management techniques, all implementations MUST
   gracefully handle unimplemented alternatives within the RecipientInfo
   CHOICE, all implementations MUST gracefully handle unimplemented
   versions of otherwise supported alternatives within the RecipientInfo
   CHOICE, and all implementations MUST gracefully handle unimplemented
   or unknown ori alternatives.

      RecipientInfo ::= CHOICE {
        ktri KeyTransRecipientInfo,
        kari [1] KeyAgreeRecipientInfo,
        kekri [2] KEKRecipientInfo,
        pwri [3] PasswordRecipientinfo,
        ori [4] OtherRecipientInfo }

      EncryptedKey ::= OCTET STRING
*/
		var idx = 0;
		var obj = riObj.items[idx++];

		jCastle.assert(obj.type, jCastle.asn1.tagInteger, 'INVALID_CMS_FORMAT', 'CMS019');
		var version = obj.intVal;

		if (riObj.tagClass == jCastle.asn1.tagClassUniversal && riObj.type == jCastle.asn1.tagSequence) { // keyTransRecipientInfo
			return jCastle.cms.asn1.keyTransRecipientInfo.parse(
			riObj, 
			cmsKey);
		}	

		jCastle.assert(riObj.tagClass, jCastle.asn1.tagClassContextSpecific, 'INVALID_CMS_FORMAT', 'CMS020');

		switch (riObj.type) {
			case 1: return jCastle.cms.asn1.keyAgreeRecipientInfo.parse(riObj, cmsKey); // keyAgreeRecipientInfo
			case 2: return jCastle.cms.asn1.kekRecipientInfo.parse(riObj, cmsKey); //kekRecipientInfo
			case 3: return jCastle.cms.asn1.passwordRecipientInfo.parse(riObj, cmsKey); // passwordRecipentInfo
			case 4: return jCastle.cms.asn1.otherRecipientInfo.parse(riObj, cmsKey); // otherRecipientInfo
			default: throw jCastle.exception("UNSUPPORTED_CMS_STRUCTURE", 'CMS021');
		}

	},


/*
      RecipientInfo ::= CHOICE {
        ktri KeyTransRecipientInfo,
        kari [1] KeyAgreeRecipientInfo,
        kekri [2] KEKRecipientInfo,
        pwri [3] PasswordRecipientinfo,
        ori [4] OtherRecipientInfo }

      EncryptedKey ::= OCTET STRING
*/
	schema: function(recipientInfo, encryptKey, cmsKey, options = {})
	{
		var type = recipientInfo.type;
		if (type in jCastle.cms.asn1) return jCastle.cms.asn1[type].schema(recipientInfo, encryptKey, cmsKey, options);
		throw jCaslte.exception('UNSUPPORTED_CMS_STRUCTURE', 'CMS023');
	}
};

/*
6.2.1.  KeyTransRecipientInfo Type

   Per-recipient information using key transport is represented in the
   type KeyTransRecipientInfo.  Each instance of KeyTransRecipientInfo
   transfers the content-encryption key to one recipient.

      KeyTransRecipientInfo ::= SEQUENCE {
        version CMSVersion,  -- always set to 0 or 2
        rid RecipientIdentifier,
        keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
        encryptedKey EncryptedKey }

      RecipientIdentifier ::= CHOICE {
        issuerAndSerialNumber IssuerAndSerialNumber,
        subjectKeyIdentifier [0] SubjectKeyIdentifier }

   The fields of type KeyTransRecipientInfo have the following meanings:

      version is the syntax version number.  If the RecipientIdentifier
      is the CHOICE issuerAndSerialNumber, then the version MUST be 0.
      If the RecipientIdentifier is subjectKeyIdentifier, then the
      version MUST be 2.

      rid specifies the recipient's certificate or key that was used by
      the sender to protect the content-encryption key.  The content-
      encryption key is encrypted with the recipient's public key.  The
      RecipientIdentifier provides two alternatives for specifying the
      recipient's certificate, and thereby the recipient's public key.
      The recipient's certificate must contain a key transport public
      key.  Therefore, a recipient X.509 version 3 certificate that
      contains a key usage extension MUST assert the keyEncipherment
      bit.  The issuerAndSerialNumber alternative identifies the
      recipient's certificate by the issuer's distinguished name and the
      certificate serial number; the subjectKeyIdentifier identifies the
      recipient's certificate by a key identifier.  When an X.509
      certificate is referenced, the key identifier matches the X.509
      subjectKeyIdentifier extension value.  When other certificate
      formats are referenced, the documents that specify the certificate
      format and their use with the CMS must include details on matching
      the key identifier to the appropriate certificate field.  For
      recipient processing, implementations MUST support both of these
      alternatives for specifying the recipient's certificate.  For
      sender processing, implementations MUST support at least one of
      these alternatives.

      keyEncryptionAlgorithm identifies the key-encryption algorithm,
      and any associated parameters, used to encrypt the content-
      encryption key for the recipient.  The key-encryption process is
      described in Section 6.4.

      encryptedKey is the result of encrypting the content-encryption
      key for the recipient.
*/
jCastle.cms.asn1.keyTransRecipientInfo = {
	parse: function(sequence, cmsKey)
	{
		// console.log('cms.asn1.keyTransRecipientInfo()');

		var idx = 0, info = {type: 'keyTransRecipientInfo'};
		var obj = sequence.items[idx++];

		// version
		info.version = obj.intVal;
		
		obj = sequence.items[idx++];

		// recipientIdentifier
		info.recipientIdentifier = {};
		if (obj.type == jCastle.asn1.tagSequence) { // issuerAndSerialNumber
			info.recipientIdentifier.issuer = jCastle.certificate.asn1.directoryName.parse(obj.items[0]);
			info.recipientIdentifier.serialNumber = obj.items[1].intVal;

		} else {
			// subjectKeyIdentifier
			jCastle.assert(obj.tagClass, jCastle.asn1.tagClassContextSpecific, 'INVALID_CMS_STRUCTURE', 'CMS024');
			info.recipientIdentifier.subjectKeyIdentifier = Buffer.from(obj.value, 'latin1');
		}
		obj = sequence.items[idx++];
//console.log(info.recipientIdentifier);

		// keyEncryptionAlgorithm
		info.keyEncryptionAlgorithm = jCastle.certificate.asn1.encryptionInfo.parse(obj);

		obj = sequence.items[idx++];

		info.encryptedKey = Buffer.from(obj.value, 'latin1');
//console.log('encryptedKey length: '+info.encryptedKey.length);

		// decrypt key
		if ('privateKey' in cmsKey) {
			// console.log('cmsKey has privateKey');

			var privkey = cmsKey.privateKey;
			var password = 'password' in cmsKey ? cmsKey.password : null;

			try {
				var pki = new jCastle.pki();

				if (typeof privkey == 'object' && 'algo' in privkey && 'privateKey' in privkey) {// privateKeyInfo
					pki.init(privkey);
				} else if (typeof privkey == 'object' && 'pkiName' in privkey) {// pki
					pki.init(privkey);
				} else {
					pki = new jCastle.pki(info.keyEncryptionAlgorithm.algo);
					pki.parsePrivateKey(privkey, password);
				}

				// only RSA has encrypt / decrypt ability.
				if('padding' in info.keyEncryptionAlgorithm) {
					pki.setPadding(info.keyEncryptionAlgorithm.padding);
				}

				// console.log('pki is ready.');

				if (pki.hasPrivateKey()) {
					var decryptedKey = pki.privateDecrypt(info.encryptedKey);
					// console.log('decryptedKey: ', decryptedKey);
					info.decryptedKey = decryptedKey;
				}
			} catch (ex) {
				// console.log(ex.message);
				// key not in agreement
			}
		}

		return info;
	},

	schema: function(recipientInfo, encryptKey, cmsKey, options = {})
	{
/*
      KeyTransRecipientInfo ::= SEQUENCE {
        version CMSVersion,  -- always set to 0 or 2
        rid RecipientIdentifier,
        keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
        encryptedKey EncryptedKey }

      RecipientIdentifier ::= CHOICE {
        issuerAndSerialNumber IssuerAndSerialNumber,
        subjectKeyIdentifier [0] SubjectKeyIdentifier }
*/
		// console.log('cms.asn1.KeyTransRecipientInfo.schema()');

		var recipientIdentifier, pki;

		if ('certificate' in cmsKey.recipient) {
			var recipientCert = cmsKey.recipient.certificate;
			recipientIdentifier = {};
			var cert_info = jCastle.certificate.create().parse(recipientCert);

			// console.log('cert_info: ', cert_info);

			var identifierType = 'identifierType' in recipientInfo ? recipientInfo.identifierType : 'issuerAndSerialNumber';
			if (identifierType == 'subjectKeyIdentifier' &&
				(!('extensions' in cert_info.tbs) || !('subjectKeyIdentifier' in cert_info.tbs.extensions))) {
				identifierType = 'issuerAndSerialNumber';
			}

			if (identifierType == 'subjectKeyIdentifier') {
				recipientIdentifier.subjectKeyIdentifier = cert_info.tbs.extensions.subjectKeyIdentifier;
			} else {
				recipientIdentifier.issuer = cert_info.tbs.issuer;
				recipientIdentifier.serialNumber = cert_info.tbs.serialNumber;
			}

			pki = jCastle.pki.createFromPublicKeyInfo(cert_info.tbs.subjectPublicKeyInfo);

			if (recipientInfo.keyEncryptionAlgorithm) {
				if (recipientInfo.keyEncryptionAlgorithm.algo &&
					pki.pkiName.toUpperCase() != recipientInfo.keyEncryptionAlgorithm.algo.toUpperCase())
					throw jCastle.exception('PKI_NOT_MATCH', 'CMS102');
				if ('padding' in recipientInfo.keyEncryptionAlgorithm) pki.setPadding(recipientInfo.keyEncryptionAlgorithm.padding);
			}
		} else {
			recipientIdentifier = recipientInfo.recipientIdentifier;
			if (!recipientIdentifier) throw jCastle.exception('NO_RID', 'CMS105');

			// now we need recipient public key
			var pubkey = cmsKey.recipient.publicKey;
			if (!pubkey) jCastle.exception('INVALID_PUBKEY', 'CMS025');

			pki = new jCastle.pki(recipientInfo.keyEncryptionAlgorithm.algo);
			pki.parsePublicKey(pubkey);
			if (!pki.hasPublicKey()) jCastle.exception('INVALID_PUBKEY', 'CMS026');
			if ('padding' in recipientInfo.keyEncryptionAlgorithm) pki.setPadding(recipientInfo.keyEncryptionAlgorithm.padding);
		}

		// console.log('pki: ', pki);


		var schema = {
			type: jCastle.asn1.tagSequence,
			items:[]
		};

		// verseion
		var version = 0;
		if ('subjectKeyIdentifier' in recipientIdentifier) version = 2;

		schema.items.push({
			type: jCastle.asn1.tagInteger,
			intVal: version
		});

		// recipientIdentifier - rid
		var ridSchema;

		if ('subjectKeyIdentifier' in recipientIdentifier) {
			ridSchema = {
				type: 0x00,
				tagClass: jCastle.asn1.tagClassContextSpecific,
				constructed: false,
				value: recipientIdentifier.subjectKeyIdentifier
			};
		} else {
			ridSchema = {
				type: jCastle.asn1.tagSequence,
				items:[
					jCastle.certificate.asn1.directoryName.schema(recipientIdentifier.issuer),
					{
						type: jCastle.asn1.tagInteger,
						intVal: recipientIdentifier.serialNumber
					}
				]
			};
		}

		schema.items.push(ridSchema);

		// keyEncryptionAlgorithm
		var encAlgoSchema = jCastle.certificate.asn1.encryptionInfo.schema(recipientInfo.keyEncryptionAlgorithm);
		schema.items.push(encAlgoSchema);

		// encryptedKey

		// key must be created before and should be used for encryption of the content.
		// therefore encryptedContentInfo should be made first then comes recipientInfos.
		if (!Buffer.isBuffer(encryptKey)) encryptKey = Buffer.from(encryptKey, 'latin1');

		var encryptedKey = pki.publicEncrypt(encryptKey);

		schema.items.push({
			type: jCastle.asn1.tagOctetString,
			value: encryptedKey
		});

		return schema;
	}
};

/*
6.2.2.  KeyAgreeRecipientInfo Type

   Recipient information using key agreement is represented in the type
   KeyAgreeRecipientInfo.  Each instance of KeyAgreeRecipientInfo will
   transfer the content-encryption key to one or more recipients that
   use the same key agreement algorithm and domain parameters for that
   algorithm.

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

   The fields of type KeyAgreeRecipientInfo have the following meanings:

      version is the syntax version number.  It MUST always be 3.

      originator is a CHOICE with three alternatives specifying the
      sender's key agreement public key.  The sender uses the
      corresponding private key and the recipient's public key to
      generate a pairwise key.  The content-encryption key is encrypted
      in the pairwise key.  The issuerAndSerialNumber alternative
      identifies the sender's certificate, and thereby the sender's
      public key, by the issuer's distinguished name and the certificate
      serial number.  The subjectKeyIdentifier alternative identifies
      the sender's certificate, and thereby the sender's public key, by
      a key identifier.  When an X.509 certificate is referenced, the
      key identifier matches the X.509 subjectKeyIdentifier extension
      value.  When other certificate formats are referenced, the
      documents that specify the certificate format and their use with
      the CMS must include details on matching the key identifier to the
      appropriate certificate field.  The originatorKey alternative
      includes the algorithm identifier and sender's key agreement
      public key.  This alternative permits originator anonymity since
      the public key is not certified.  Implementations MUST support all
      three alternatives for specifying the sender's public key.

      ukm is optional.  With some key agreement algorithms, the sender
      provides a User Keying Material (UKM) to ensure that a different
      key is generated each time the same two parties generate a
      pairwise key.  Implementations MUST accept a KeyAgreeRecipientInfo
      SEQUENCE that includes a ukm field.  Implementations that do not
      support key agreement algorithms that make use of UKMs MUST
      gracefully handle the presence of UKMs.

      keyEncryptionAlgorithm identifies the key-encryption algorithm,
      and any associated parameters, used to encrypt the content-
      encryption key with the key-encryption key.  The key-encryption
      process is described in Section 6.4.

      recipientEncryptedKeys includes a recipient identifier and
      encrypted key for one or more recipients.  The
      KeyAgreeRecipientIdentifier is a CHOICE with two alternatives
      specifying the recipient's certificate, and thereby the
      recipient's public key, that was used by the sender to generate a
      pairwise key-encryption key.  The recipient's certificate must
      contain a key agreement public key.  Therefore, a recipient X.509
      version 3 certificate that contains a key usage extension MUST
      assert the keyAgreement bit.  The content-encryption key is
      encrypted in the pairwise key-encryption key.  The
      issuerAndSerialNumber alternative identifies the recipient's
      certificate by the issuer's distinguished name and the certificate
      serial number; the RecipientKeyIdentifier is described below.  The
      encryptedKey is the result of encrypting the content-encryption
      key in the pairwise key-encryption key generated using the key
      agreement algorithm.  Implementations MUST support both
      alternatives for specifying the recipient's certificate.

   The fields of type RecipientKeyIdentifier have the following
   meanings:

      subjectKeyIdentifier identifies the recipient's certificate by a
      key identifier.  When an X.509 certificate is referenced, the key
      identifier matches the X.509 subjectKeyIdentifier extension value.
      When other certificate formats are referenced, the documents that
      specify the certificate format and their use with the CMS must
      include details on matching the key identifier to the appropriate
      certificate field.

      date is optional.  When present, the date specifies which of the
      recipient's previously distributed UKMs was used by the sender.

      other is optional.  When present, this field contains additional
      information used by the recipient to locate the public keying
      material used by the sender.
*/
/*
http://openssl.6102.n7.nabble.com/Is-the-structure-of-this-CMS-object-correct-td63420.html

  SEQUENCE {
    OBJECT IDENTIFIER envelopedData (1 2 840 113549 1 7 3)
    [0] {
      SEQUENCE {
        INTEGER 0
        SET {
          [1] {   -- KeyAgreeRecipientInfo
            INTEGER 3   -- version CMSVersion
            [0] {    -- originator [0] EXPLICIT OriginatorIdentifierOrKey
              SEQUENCE {    -- originatorKey [1] OriginatorPublicKey
                SEQUENCE {    -- algorithm AlgorithmIdentifier
                  OBJECT IDENTIFIER ecPublicKey (1 2 840 10045 2 1)
                  OBJECT IDENTIFIER secp521r1 (1 3 132 0 35)
                  }
                BIT STRING    -- publicKey
                  04 00 69 68 2B EA A2 DD 50 48 52 D2 D7 FF 40 9A
                  9F 86 8E 43 33 42 D5 A4 DE 4A 41 5A 73 F3 99 19
                  A4 C5 19 DF 4D 4E EF 4E 47 54 A1 5A 74 41 F3 50
                  43 94 92 35 2B 37 28 49 53 A8 1D 6E BA 21 C2 E0
                  B0 A1 F0 01 E0 61 B6 91 29 23 52 BA 39 D5 1D FE
                  DA 08 DF C8 7C 11 76 56 73 13 51 B7 8D 69 45 CC
                  A1 D4 57 50 45 2A 63 93 5C A8 FB D4 F3 8F 46 68
                  38 BC 57 81 FD C6 06 86 43 C3 3B 53 90 28 C8 B1
                          [ Another 5 bytes skipped ]
                }
              }
            [1] {    -- ukm [1] EXPLICIT UserKeyingMaterial OPTIONAL
              OCTET STRING C8 71 12 9C B5 64 24 52
              }
            SEQUENCE {    -- keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier
              OBJECT IDENTIFIER '1 3 132 1 11 3'
              SEQUENCE {
                OBJECT IDENTIFIER aes256-wrap (2 16 840 1 101 3 4 1 45)
                }
              }
            SEQUENCE {    -- recipientEncryptedKeys RecipientEncryptedKeys
              SEQUENCE {  -- RecipientEncryptedKey
                SEQUENCE {    -- rid KeyAgreeRecipientIdentifier  -- issuerAndSerialNumber IssuerAndSerialNumber
                  SEQUENCE {    -- issuer
                    SET {
                      SEQUENCE {
                        OBJECT IDENTIFIER countryName (2 5 4 6)
                        PrintableString 'DE'
                        }
                      }
                    SET {
                      SEQUENCE {
                        OBJECT IDENTIFIER localityName (2 5 4 7)
                        UTF8String 'Munich'
                        }
                      }
                    SET {
                      SEQUENCE {
                        OBJECT IDENTIFIER organizationName (2 5 4 10)
                        UTF8String 'PDFlib GmbH'
                        }
                      }
                    SET {
                      SEQUENCE {
                        OBJECT IDENTIFIER commonName (2 5 4 3)
                        UTF8String 'PDFlib GmbH ATS Demo Intermediate CA'
                        }
                      }
                    }
                  INTEGER 27    -- serialNumber
                  }
                OCTET STRING    -- encryptedKey EncryptedKey
                  63 CE 50 C7 31 8A B9 C8 A3 6A 7B 7C 9D 14 50 33
                  09 7C 5D 3D 7B 34 1B 30
                }
              }
            }
          }
        SEQUENCE {
          OBJECT IDENTIFIER data (1 2 840 113549 1 7 1)
          SEQUENCE {
            OBJECT IDENTIFIER aes128-CBC (2 16 840 1 101 3 4 1 2)
            OCTET STRING
              88 9B F1 E8 96 0B A8 4D 9C F1 6F FC E3 7D B8 AC
            }
          [0]
            AB 19 35 70 7F CE 88 17 A0 AD FA A2 55 33 68 FD
            48 9D 26 2E DC 7B A7 96 95 19 FA 1F B8 0C DE E0
          }
        }
      }
    }
*/
/*
openssl command process:
------------------------
openssl ecparam -genkey -name secp256r1 -out ec_privkey_secp256r1.pem
openssl req -x509 -new -key ec_privkey_secp256r1.pem -out ecc.crt
openssl cms -encrypt -in hello.txt -out ec_example_enveloped.pem -outform PEM ecc.crt
openssl cms -decrypt -in ec_example_enveloped.pem -out decrypted.txt -inform PEM -inkey ec_privkey_secp256r1.pem -recip ecc.crt


ec_example_enveloped.pem:
-------------------------
-----BEGIN CMS-----
MIIBqAYJKoZIhvcNAQcDoIIBmTCCAZUCAQIxggFZoYIBVQIBA6BRoU8wCQYHKoZI
zj0CAQNCAAQu5b3KWeFm3XQ44ENItEqcad7CgpezI+lcCakgdX9z6r1ckKyQf91c
prCp53M7SSD6Xqalmq+LZy7eDKIszZ1jMBwGCSuBBRCGSD8AAjAPBgsqhkiG9w0B
CRADBgUAMIHeMIHbMIGuMIGgMQswCQYDVQQGEwJLUjEXMBUGA1UECBMOQ2h1bmdj
aGVvbmdidWsxEzARBgNVBAcUCkxvY2FsX25hbWUxFTATBgNVBAoUDG9yaWdfZXhh
bXBsZTESMBAGA1UECxQJb3JpZ191bml0MRQwEgYDVQQDEwtqY2FzdGxlLm5ldDEi
MCAGCSqGSIb3DQEJARYTbGV0c2dvbGVlQG5hdmVyLmNvbQIJAOoxzNZyQlShBCjy
rljdZlbJMOp1LHc9b7d+rINd1rY7wRNqZ3TgHMq59wO9L/mQmRTgMDMGCSqGSIb3
DQEHATAUBggqhkiG9w0DBwQIusSaNAbbbGaAEHtFWF9ZDOIS2RFTjnGuwOU=
-----END CMS-----


ASN1 Structure:
---------------
SEQUENCE (2 elem)
  OBJECT IDENTIFIER 1.2.840.113549.1.7.3 envelopedData (PKCS #7)
  [0] (1 elem)
    SEQUENCE (3 elem)
      INTEGER 2
      SET (1 elem)
        [1] (4 elem)    -- KeyAgreeRecipientInfo
          INTEGER 3    -- version CMSVersion
          [0] (1 elem)    -- originator [0] EXPLICIT OriginatorIdentifierOrKey
            [1] (2 elem)    -- originatorKey [1] OriginatorPublicKey
              SEQUENCE (1 elem)    -- algorithm AlgorithmIdentifier
                OBJECT IDENTIFIER 1.2.840.10045.2.1 ecPublicKey (ANSI X9.62 public key type)
              BIT STRING (520 bit) 0000010000101110111001011011110111001010010110011110000101100110110111…    -- publicKey
          SEQUENCE (2 elem)    -- keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier
            OBJECT IDENTIFIER 1.3.133.16.840.63.0.2 dhSinglePass-stdDH-sha1kdf-scheme
            SEQUENCE (2 elem)
              OBJECT IDENTIFIER 1.2.840.113549.1.9.16.3.6 cms3DESwrap (S/MIME Algorithms)
              NULL
          SEQUENCE (1 elem)    -- recipientEncryptedKeys RecipientEncryptedKeys
            SEQUENCE (2 elem)    -- RecipientEncryptedKey
              SEQUENCE (2 elem)    -- rid KeyAgreeRecipientIdentifier  -- issuerAndSerialNumber IssuerAndSerialNumber
                SEQUENCE (7 elem)    -- issuer
                  SET (1 elem)
                    SEQUENCE (2 elem)
                      OBJECT IDENTIFIER 2.5.4.6 countryName (X.520 DN component)
                      PrintableString KR
                  SET (1 elem)
                    SEQUENCE (2 elem)
                      OBJECT IDENTIFIER 2.5.4.8 stateOrProvinceName (X.520 DN component)
                      PrintableString Chungcheongbuk
                  SET (1 elem)
                    SEQUENCE (2 elem)
                      OBJECT IDENTIFIER 2.5.4.7 localityName (X.520 DN component)
                      TeletexString Local_name
                  SET (1 elem)
                    SEQUENCE (2 elem)
                      OBJECT IDENTIFIER 2.5.4.10 organizationName (X.520 DN component)
                      TeletexString orig_example
                  SET (1 elem)
                    SEQUENCE (2 elem)
                      OBJECT IDENTIFIER 2.5.4.11 organizationalUnitName (X.520 DN component)
                      TeletexString orig_unit
                  SET (1 elem)
                    SEQUENCE (2 elem)
                      OBJECT IDENTIFIER 2.5.4.3 commonName (X.520 DN component)
                      PrintableString jcastle.net
                  SET (1 elem)
                    SEQUENCE (2 elem)
                      OBJECT IDENTIFIER 1.2.840.113549.1.9.1 emailAddress (PKCS #9. Deprecated, use an altName extension instead)
                      IA5String letsgolee@naver.com
                INTEGER (64 bit) 16875494500145976481    -- serialNumber
              OCTET STRING (40 byte) F2AE58DD6656C930EA752C773D6FB77EAC835DD6B63BC1136A6774E01CCAB9F703BD2F…    -- encryptedKey EncryptedKey
      SEQUENCE (3 elem)
        OBJECT IDENTIFIER 1.2.840.113549.1.7.1 data (PKCS #7)
        SEQUENCE (2 elem)
          OBJECT IDENTIFIER 1.2.840.113549.3.7 des-EDE3-CBC (RSADSI encryptionAlgorithm)
          OCTET STRING (8 byte) BAC49A3406DB6C66
        [0] (16 byte) 7B45585F590CE212D911538E71AEC0E5
*/
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
jCastle.cms.asn1.keyAgreeRecipientInfo = {
	parse: function(sequence, cmsKey)
	{
//console.log('keyAgreeRecipientInfo type');
		var idx = 0, info = {type: 'keyAgreeRecipientInfo'};
		var obj = sequence.items[idx++];

		// version
		info.version = obj.intVal;
		jCastle.assert(info.version, 3, 'INVALID_CMS_VERSION', 'CMS044');
		obj = sequence.items[idx++];

		// originator
		jCastle.assert(obj.tagClass, jCastle.asn1.tagClassContextSpecific, 'INVALID_CMS_STRUCTURE', 'CMS042');
		//var originator = jCastle.cms.asn1.originator.parse(obj.items[0]);
		var originator = jCastle.cms.asn1.originator.parse(obj);
		info.originator = originator;
		obj = sequence.items[idx++];

		// In fact there is no need in so long UKM, but RFC2631
		// has requirement that "UserKeyMaterial" must be 512 bits long

		// ukm [1] EXPLICIT UserKeyingMaterial OPTIONAL
		if (obj.tagClass == jCastle.asn1.tagClassContextSpecific && obj.type == 0x01) {
			if (obj.items[0].type == jCastle.asn1.tagSequence) {
/*
      MQVuserKeyingMaterial ::= SEQUENCE {
        ephemeralPublicKey      OriginatorPublicKey,
        addedukm            [0] EXPLICIT UserKeyingMaterial OPTIONAL  }

      OriginatorPublicKey ::= SEQUENCE {
        algorithm AlgorithmIdentifier,
        publicKey BIT STRING }

*/
				var mqvSeq = obj.items[0];
				var pubkeySeq = mqvSeq.items[0];
				info.mqvukm = {};
				info.mqvukm.ephemeralPublicKey = {
					algorithm: jCastle.oid.getName(pubkeySeq.items[0].value),
					publicKey: Buffer.from(pubkeySeq.items[1].value, 'latin1')
				};
				if (mqvSeq.items[1]) info.mqvukm.addedukm = Buffer.from(mqvSeq.items[1].value, 'latin1');

			} else {
				//info.userKeyingMaterial = obj.items[0].value;
				info.ukm = Buffer.from(obj.items[0].value, 'latin1');
			}
			obj = sequence.items[idx++];
		}

		// keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier
		var keyEncryptionAlgorithm = jCastle.cms.asn1.kariKeyEncryptionAlgorithm.parse(obj);
		info.keyEncryptionAlgorithm = keyEncryptionAlgorithm;
		obj = sequence.items[idx++];

		// recipientEncryptedKeys RecipientEncryptedKeys
		info.recipientEncryptedKeys = jCastle.cms.asn1.recipientEncryptedKeys.parse(obj);
//console.log(info);
		// decrypt key

		if (cmsKey && 'privateKey' in cmsKey) {
		// preparations:
		//     party's public key or certificate
		//     party's ephemaral public key if the agreement is mqvSinglePass-sha*kdf-scheme
		//     private key
		//     ephemaral private key if the agreement is mqvSinglePass-sha*kdf-scheme
			var originator_pubkey;

			if (!('publicKey' in originator)) {
				// originator value is not originatorKey.
				// so we need originator's certificate.
				if (!('originator' in cmsKey) || !('certificate' in cmsKey.originator.certificate))
					throw jCastle.exception('ORIGINTOR_CERT_NOT_GIVEN', 'CMS110');
				var cert_info = jCastle.certificate.create().parse(cmsKey.originator.certificate);
				var pubkey_info = cert_info.tbs.subjectPublicKeyInfo;
				if (pubkey_info.algo != 'ECDSA') throw jCastle.exception('PKI_ISNT_ECDSA', 'CMS111');
				originator_pubkey = pubkey_info.publicKey;
			} else {
				originator_pubkey = originator.publicKey;
			}

			var ukm = info.ukm;
			var params = {
				privateKey: cmsKey.privateKey,
				partyPublicKey: originator_pubkey,
				password: cmsKey.password // if privateKey is encrypted pem
			};
			if ('parameters' in cmsKey) params.parameters = cmsKey.parameters;
			if (keyEncryptionAlgorithm.keyAgreement == 'mqvSinglePass') {
				params.ephemeralPrivateKey = cmsKey.ephemeralPrivateKey;
				params.partyEphemeralPublicKey = info.mqvukm.ephemeralPublicKey;
				ukm = info.mqvukm.addedukm;
			}

			for (var i = 0; i < info.recipientEncryptedKeys.length; i++) {
				var encryptedKey = Buffer.from(info.recipientEncryptedKeys[i].encryptedKey, 'latin1');

				var wrapkey = jCastle.cms.fn.kariCalculateWrapKey(keyEncryptionAlgorithm, ukm, params);
				var decryptedKey = null;

				try {
					decryptedKey = jCastle.keyWrap
					.create(keyEncryptionAlgorithm.wrap)
					.unwrap(encryptedKey, {
						wrappingKey: wrapkey
					});
				} catch (e) {
					// nothing to do
				}

				if (decryptedKey &&!info.decryptedKey) {
					info.decryptedKey = decryptedKey;
					break;
				}
			}

		}

//console.log(info);
		return info;
	},

	schema: function(recipientInfo, encryptKey, cmsKey, options)
	{
/*
      KeyAgreeRecipientInfo ::= SEQUENCE {
        version CMSVersion,  -- always set to 3
        originator [0] EXPLICIT OriginatorIdentifierOrKey,
        ukm [1] EXPLICIT UserKeyingMaterial OPTIONAL,
        keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
        recipientEncryptedKeys RecipientEncryptedKeys }
*/ 
//		throw jCastle.exception("UNSUPPORTED_CMS_STRUCTURE", 'CMS028');
		var version = 3;
		var schema = {
			tagClass: jCastle.asn1.tagClassContextSpecific,
			type: 0x01,
			constructed: true,
			items: [{
				type: jCastle.asn1.tagInteger,
				intVal: version
			}]
		};

		// originator
		var originator;

		var originatorType = 'originatorType' in recipientInfo ? recipientInfo.originatorType : 'originatorKey';
		
		if ('certificate' in cmsKey) {
			var cert_info = jCastle.certificate.create().parse(cmsKey.certificate);
			var pubkey_info = cert_info.tbs.subjectPublicKeyInfo;
			if (pubkey_info.algo != 'ECDSA') throw jCastle.exception('PKI_ISNT_ECDSA', 'CMS097');

			switch (originatorType) {
				case 'issuerAndSerialNumber':
					originator = {
						issuer: cert_info.tbs.issuer,
						serialNumber: cert_info.tbs.serialNumber
					};
					break;
				case 'subjectKeyIdentifier':
					if ('extensions' in cert_info.tbs && 'subjectKeyIdentifier' in cert_info.tbs.extensions) {
						originator = {
							subjectKeyIdentifier: cert_info.tbs.extensions.subjectKeyIdentifier
						};
						break;
					}
					// if the certificate doesn't have extensions or subjectKeyIdentifier value then
					// originatorKey should be used.
				case 'originatorKey':
				default:
					originator = {
						algorithm: 'ecPublicKey',
						publicKey: pubkey_info.publicKey
					};
			}
		} else if ('originator' in recipientInfo) {
			originator = recipientInfo.originator;
		} else {
			// we should have private key
			var pki;
			if (jCastle.util.isString(cmsKey.privateKey)) {
				pki = jCastle.pki.create().parsePrivateKey(cmsKey.privateKey, cmsKey.password);
			} else if (cmsKey.privateKey instanceof jCastle.pki) {
				pki = options.privateKey;
				if (pki.pkiName != 'ECDSA') throw jCastle.exception('PKI_ISNT_ECDSA', 'CMS098');
				if (!pki.hasPrivateKey()) throw jCastle.exception('PRIVKEY_NOT_SET', 'CMS099');
				originator = {
					algorithm: 'ecPublicKey',
					publicKey: pki.getPublicKey('buffer')
				};
			} else {
				throw jCastle.exception('PRIVKEY_NOT_SET', 'CMS100');
			}
		}

		var originatorSchema = jCastle.cms.asn1.originator.schema(originator, options);
		schema.items.push(originatorSchema);

		// ukm
		var ukm, ukmSchema;

		if (('ukm' in recipientInfo && recipientInfo.ukm.length) || 'ukm' in options) {
			ukm = recipientInfo.ukm || options.ukm;
			ukmSchema = {
				tagClass: jCastle.asn1.tagClassContextSpecific,
				type: 0x01,
				constructed: true,
				items: [{
					type: jCastle.asn1.tagOctetString,
					value: ukm
				}]
			};

			schema.items.push(ukmSchema);
		} else if ('mqvukm' in recipientInfo) {
			// ephemeralPublicKey = {
			//	algorithm: 'ecPublicKey',
			//	publicKey: '....'
			// }
			var ephemeralPublicKey = cmsKey.ephemeralPublicKey || recipientInfo.mqvukm.ephemeralPublicKey;
			ukm = recipientInfo.mqvukm.addedukm || options.ukm || '';

			ukmSchema = {
				tagClass: jCastle.asn1.tagClassContextSpecific,
				type: 0x01,
				constructed: true,
				items: [{
					type: jCastle.asn1.tagSequence,
					items: [{
						type: jCastel.asn1.tagSequence,
						items: [{
							type: jCastle.asn1.tagOID,
							value: jCastle.oid.getOID(ephemeralPublicKey.algorithm)
						}, {
							type: jCastle.asn1.tagBitString,
							value: ephemeralPublicKey.publicKey
						}]
					}]
				}]
			};

			if (ukm && ukm.length) {
				ukmSchema.items[0].push({
					tagClass: jCastle.asn1.tagClassContextSpecific,
					type: 0x00,
					constructed: true,
					items: [{
						type: jCastle.asn1.tagOctetString,
						value: ukm
					}]
				});
			}

			schema.items.push(ukmSchema);
		}

		// keyEncryptionAlgorithm
		var keyEncryptionAlgo = recipientInfo.keyEncryptionAlgorithm || {};
		if (!('algo' in keyEncryptionAlgo)) keyEncryptionAlgo.algo = 'dhSinglePass-stdDH-sha1kdf-scheme'; // default
		var keyEncryptionAlgorithm = jCastle.cms.fn.kariGetKeyEncryptionAlgoInfo(keyEncryptionAlgo.algo);
		keyEncryptionAlgorithm.wrap = 'wrap' in keyEncryptionAlgo ? keyEncryptionAlgo.wrap : 'aes-128'; // default

		var keaSchema = jCastle.cms.asn1.kariKeyEncryptionAlgorithm.schema(keyEncryptionAlgorithm, options);
		schema.items.push(keaSchema);

//		var recipientEncryptedKeys = jCastle.util.clone(recipientInfo.recipientEncryptedKeys);
//		var keyEncryptionAlgorithm = recipientInfo.keyEncryptionAlgorithm;

//		var encryptKey = keymaterial.encryptKey;

		// recipientEncryptedKeys
/*
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
		var recipients;

		if ('recipient' in cmsKey) {
			recipients = [cmsKey.recipient];
		} else {
			recipients = cmsKey.recipients;
		}

		if (!recipients.length) jCastle.exception('RECIPIENTS_CERT_NOT_GIVEN', 'CMS101');

		var recipientEncryptedKeys = [];

		for (var i = 0; i < recipients.length; i++) {
			var recipient = recipients[i];
			var recipientEncryptedKey = {};

			var cert = jCastle.certificate.create();
			var cert_info = cert.parse(recipient.certificate);
			var pubkey_info = cert_info.tbs.subjectPublicKeyInfo;
			if (pubkey_info.algo != 'ECDSA') throw jCastle.exception('INVALID_PUBKEY', 'CMS051');
			other_pubkey = pubkey_info.publicKey;
//			if (recipient.parameters && recipient.parameters != pubkey_info.parameters) throw jCastle.exception('PARAMETERS_DISMATCH', 'CMS052');
			var parameters = pubkey_info.parameters;

			var params = {
				privateKey: cmsKey.privateKey,
				partyPublicKey: other_pubkey,
				password: cmsKey.password // if privateKey is encrypted pem
			};
			if (parameters) params.parameters = parameters;

			if (keyEncryptionAlgorithm.keyAgreement == 'mqvSinglePass') {
				params.ephemeralPrivateKey = cmsKey.ephemeralPrivateKey;
				params.partyEphemeralPublicKey = recipient.ephemeralPublicKey;
			}

			var wrapkey = jCastle.cms.fn.kariCalculateWrapKey(keyEncryptionAlgorithm, ukm, params);

			var encryptedKey = jCastle.keyWrap
				.create(keyEncryptionAlgorithm.wrap)
				.wrap(Buffer.from(encryptKey, 'latin1'), {
					wrappingKey: wrapkey
				});

			var identifierType = 'identifierType' in recipient ? recipient.identifierType : 'issuerAndSerialNumber';
			if (!('extensions' in cert_info.tbs) || !('subjectKeyIdentifier' in cert_info.tbs.extensions)) {
				identifierType = 'isserAndSerialNumber';
			}

			if (identifierType == 'subjectKeyIdentifier') {
				recipientEncryptedKey.keyAgreeRecipientIdentifier = {
					recipientKeyIdentifier: {
						subjectKeyIdentifier: cert_info.tbs.extensions.subjectKeyIdentifier
					}
				};
			} else {
				recipientEncryptedKey.keyAgreeRecipientIdentifier = {
					issuer: cert_info.tbs.issuer,
					serialNumber: cert_info.tbs.serialNumber
				};
			}

			recipientEncryptedKey.encryptedKey = encryptedKey;

			recipientEncryptedKeys.push(recipientEncryptedKey);
		}
//console.log(recipientEncryptedKeys);

		var reksSchema = jCastle.cms.asn1.recipientEncryptedKeys.schema(recipientEncryptedKeys);
		schema.items.push(reksSchema);

//console.log(JSON.stringify(schema));
		
		return schema;
	}
};



jCastle.cms.asn1.kariKeyEncryptionAlgorithm = {
	parse: function(obj)
	{
		var keyEncryptionAlgorithm = {};
		var dh_algo = jCastle.oid.getName(obj.items[0].value);

		keyEncryptionAlgorithm = jCastle.cms.fn.kariGetKeyEncryptionAlgoInfo(dh_algo);
/*
          SEQUENCE (2 elem)    -- keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier
            OBJECT IDENTIFIER 1.3.133.16.840.63.0.2 dhSinglePass-stdDH-sha1kdf-scheme
            SEQUENCE (2 elem)
              OBJECT IDENTIFIER 1.2.840.113549.1.9.16.3.6 cms3DESwrap (S/MIME Algorithms)
              NULL
*/
		var wrap_algo = jCastle.oid.getName(obj.items[1].items[0].value);
		keyEncryptionAlgorithm.wrap = jCastle.keyWrap.getAlgoName(wrap_algo);

		return keyEncryptionAlgorithm;
	},

	schema: function(keyEncryptionAlgorithm, options)
	{
		var kdf = jCastle.digest.getValidAlgoName(keyEncryptionAlgorithm.kdf);
		var keyAgreement = keyEncryptionAlgorithm.keyAgreement;
		var wrap = jCastle.mcrypt.getValidAlgoName(keyEncryptionAlgorithm.wrap);

		var algo = keyAgreement + '-' + kdf.replace(/-/g, '') + 'kdf-scheme';
		var algo_oid = jCastle.oid.getOID(algo);
		var wrap_oid = jCastle.keyWrap.getOID(wrap);

		var schema = {
			type: jCastle.asn1.tagSequence,
			items: [{
				type: jCastle.asn1.tagOID,
				value: algo_oid
			}, {
				type: jCastle.asn1.tagSequence,
				items: [{
					type: jCastle.asn1.tagOID,
					value: wrap_oid
				}]
			}]
		};

		if (wrap == 'rc2' || ['3des', 'des3', 'des-ede3', 'tripledes'].includes(wrap)) {
			schema.items[1].items.push({
				type: jCastle.asn1.tagNull,
				value: null
			});
		}

		return schema;
	}
};


jCastle.cms.asn1.originator = {
	parse: function(obj)
	{
		var seq = obj.items[0];

		var originator = {};
		if (seq.tagClass == jCastle.asn1.tagClassContextSpecific && seq.type == 0x00) {
			// subjectKeyIdentifier
			originator.subjectKeyIdentifier = Buffer.from(seq.value, 'latin1'); // need to check
		} else if (seq.tagClass == jCastle.asn1.tagClassContextSpecific && seq.type == 0x01) {
			// originatorKey
			// originatorPublicKey
/*
		[1] (2 elem)
			SEQUENCE (1 elem)
				OBJECT IDENTIFIER 1.2.840.10045.2.1 ecPublicKey (ANSI X9.62 public key type)
			BIT STRING (520 bit) 0000010000101110111001011011110111001010010110011110000101100110110111…
*/
//console.log(seq.items[0]);
			originator.algorithm = jCastle.oid.getName(seq.items[0].items[0].value);
			originator.publicKey = Buffer.from(seq.items[1].value, 'latin1');
		} else if (seq.type == jCastle.asn1.tagSequence) {
			// issuerAndSerialNumber
			originator.issuer = jCastle.certificate.asn1.directoryName.parse(seq.items[0]);
			originator.serialNumber = seq.items[1].intVal;
		}

		return originator;
	},
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

*/
	schema: function(originator, options)
	{
		originator = originator || {};

		if ('originator' in options) {
			for (var i in options.originator) {
				originator[i] = options.originator[i];
			}
		}

		var schema = {
			tagClass: jCastle.asn1.tagClassContextSpecific,
			type: 0x00,
			constructed: true,
			items:[]
		};

		var s;

		if ('subjectKeyIdentifier' in originator) {
			// subjectKeyIdentifier
			s = {
				type: 0x00,
				tagClass: jCastle.asn1.tagClassContextSpecific,
				constructed: false,
				value: originator.subjectKeyIdentifier
			};
		} else if ('algorithm' in originator) {
			// originatorKey
			// originatorPublicKey
			s = {
				type: 0x01,
				tagClass: jCastle.asn1.tagClassContextSpecific,
				constructed: true,
				items: [{
					type: jCastle.asn1.tagSequence,
					items: [{
						type: jCastle.asn1.tagOID,
						value: jCastle.oid.getOID(originator.algorithm)
					}]
				}, {
					type: jCastle.asn1.tagBitString,
					value: originator.publicKey
				}]
			};
		} else {
			// issuerAndSerialNumber
			s = {
				type: jCastle.asn1.tagSequence,
				items: [jCastle.certificate.asn1.directoryName.schema(originator.issuer), {
					type: jCastle.asn1.tagInteger,
					intVal: originator.serialNumber
				}]
			};
		}
		schema.items.push(s);

		return schema;
	}
};
/*
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
jCastle.cms.asn1.recipientEncryptedKeys = {
	parse: function(sequence)
	{
		var recipientEncryptedKeys = [];
		for (var i = 0; i < sequence.items.length; i++) {
			var recipientEncryptedKey = jCastle.cms.asn1.recipientEncryptedKey.parse(sequence.items[i]);
			recipientEncryptedKeys.push(recipientEncryptedKey);
		}

		return recipientEncryptedKeys;
	},

	schema: function(recipientEncryptedKeys)
	{
		var schema = {
			type: jCastle.asn1.tagSequence,
			items: []
		};

		for (var i = 0; i < recipientEncryptedKeys.length; i++) {
			var recipientEncryptedKey = recipientEncryptedKeys[i];
			var rekSchema = jCastle.cms.asn1.recipientEncryptedKey.schema(recipientEncryptedKey);
			schema.items.push(rekSchema);
		}

		return schema;
	}
};

jCastle.cms.asn1.recipientEncryptedKey = {
	parse: function(obj)
	{
		var recipientEncryptedKey = {};

		// rid KeyAgreeRecipientIdentifier
		var keyAgreeRecipientIdentifier = {};

		if (obj.items[0].tagClass ==  jCastle.asn1.tagClassContextSpecific && obj.items[0].type == 0x00) {
			// to do... check... 
			// rKeyId [0] IMPLICIT RecipientKeyIdentifier
			var seq = obj.items[0];
			var recipientKeyIdentifier = {};

			var idx = 0;
			var o = seq.items[idx++];

			recipientKeyIdentifier.subjectKeyIdentifier = Buffer.from(o.value, 'latin1');

			o = seq.items[idx++];
			if (o && o.type == jCastle.asn1.tagGeneralizedTime) {
				recipientKeyIdentifier.date = o.value;
				
				o = seq.items[idx++];
			}

			if (o && o.type == jCastle.asn1.tagSequence) {
				var otherKeyAttribute = {};
				otherKeyAttribute.keyAttrId = jCastle.oid.getName(o.items[0].value);
				if (o.items[1]) {
					otherKeyAttribute.keyAttr = jCastle.cms.asn1.attrs.parse(o.items[1]);
				}
				recipientKeyIdentifier.otherKeyAttribute = otherKeyAttribute;
			}

			keyAgreeRecipientIdentifier.recipientKeyIdentifier = recipientKeyIdentifier;
		} else {
			// issuerAndSerialNumber
			keyAgreeRecipientIdentifier.issuer = jCastle.certificate.asn1.directoryName.parse(obj.items[0].items[0]);
			keyAgreeRecipientIdentifier.serialNumber = obj.items[0].items[1].intVal;
		}

		recipientEncryptedKey.keyAgreeRecipientIdentifier = keyAgreeRecipientIdentifier;

		// encryptedKey
		recipientEncryptedKey.encryptedKey = Buffer.from(obj.items[1].value, 'latin1');

		return recipientEncryptedKey;
	},

	schema: function(recipientEncryptedKey)
	{
/*
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
		var keyAgreeRecipientIdentifier = recipientEncryptedKey.keyAgreeRecipientIdentifier;

		var schema = {
			type: jCastle.asn1.tagSequence,
			items: []
		};

		if ('issuer' in keyAgreeRecipientIdentifier) {
			var iasSchema = {
				type: jCastle.asn1.tagSequence,
				items: [
					jCastle.certificate.asn1.directoryName.schema(keyAgreeRecipientIdentifier.issuer), {
					type: jCastle.asn1.tagInteger,
					intVal: keyAgreeRecipientIdentifier.serialNumber
				}]
			};
			schema.items.push(iasSchema);
		} else {
			// RecipientKeyIdentifier
			if (!('recipientKeyIdentifier' in keyAgreeRecipientIdentifier)) throw jCastle.exception('INVALID_CMS_INFO', 'CMS047');
			var recipientKeyIdentifier = keyAgreeRecipientIdentifier.recipientKeyIdentifier;

			var rkiSchema = {
				tagClass: jCastle.asn1.tagClassContextSpecific,
				type: 0x00,
				constructed: false,
				value: {
					type: jCastle.asn1.tagSequence,
					items: [{
						type: jCastle.asn1.tagOctetString,
						value: recipientKeyIdentifier.subjectKeyIdentifier
					}]
				}
			};

			if ('date' in recipientKeyIdentifier) {
				rkiSchema.value.items.push({
					type: jCastle.asn1.tagGeneralizedTime,
					value: recipientKeyIdentifier.date
				});
			}
			if ('otherKeyAttribute' in recipientKeyIdentifier) {
				rkiSchema.value.items.push({
					type: jCastle.asn1.tagSequence,
					items: [{
						type: jCastle.asn1.tagOID,
						value: jCastle.oid.getOID(recipientKeyIdentifier.otherKeyAttribute.keyAttrId)
					}, jCastle.cms.asn1.attr.schema(recipientKeyIdentifier.otherKeyAttribute.keyAttr)
				]});
			};

			schema.items.push(rkiSchema);
		}

		// encryptedKey
		schema.items.push({
			type: jCastle.asn1.tagOctetString,
			value: Buffer.from(recipientEncryptedKey.encryptedKey, 'latin1')
		});

		return schema;
	}
};

/*
6.2.3.  KEKRecipientInfo Type

   Recipient information using previously distributed symmetric keys is
   represented in the type KEKRecipientInfo.  Each instance of
   KEKRecipientInfo will transfer the content-encryption key to one or
   more recipients who have the previously distributed key-encryption
   key.

      KEKRecipientInfo ::= SEQUENCE {
        version CMSVersion,  -- always set to 4
        kekid KEKIdentifier,
        keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
        encryptedKey EncryptedKey }

      KEKIdentifier ::= SEQUENCE {
        keyIdentifier OCTET STRING,
        date GeneralizedTime OPTIONAL,
        other OtherKeyAttribute OPTIONAL }

   The fields of type KEKRecipientInfo have the following meanings:

      version is the syntax version number.  It MUST always be 4.

      kekid specifies a symmetric key-encryption key that was previously
      distributed to the sender and one or more recipients.

      keyEncryptionAlgorithm identifies the key-encryption algorithm,
      and any associated parameters, used to encrypt the content-
      encryption key with the key-encryption key.  The key-encryption
      process is described in Section 6.4.

      encryptedKey is the result of encrypting the content-encryption
      key in the key-encryption key.

   The fields of type KEKIdentifier have the following meanings:

      keyIdentifier identifies the key-encryption key that was
      previously distributed to the sender and one or more recipients.

      date is optional.  When present, the date specifies a single key-
      encryption key from a set that was previously distributed.

      other is optional.  When present, this field contains additional
      information used by the recipient to determine the key-encryption
      key used by the sender.
*/
jCastle.cms.asn1.kekRecipientInfo = {
	parse: function(explicit, cmsKey)
	{
/*
[2] (4 elem)
	INTEGER 4
	SEQUENCE (1 elem)
		OCTET STRING (16 byte) FFEC8B9D2CFA55E849819476B1818C42
	SEQUENCE (2 elem)
		OBJECT IDENTIFIER 2.16.840.1.101.3.4.1.45 aes256-wrap (NIST Algorithm)
		NULL
	OCTET STRING (24 byte) 53FE00F573E08DBB4A493F5F1CDA529DFD8B9D8D7820A1FD
*/
		var idx = 0, info = {type: 'kekRecipientInfo'};
		var obj = explicit.items[idx++];

		// version
		info.version = obj.intVal;
		jCastle.assert(info.version, 4, 'INVALID_CMS_FORMAT', 'CMS029');
		
		obj = explicit.items[idx++];

		// kekIdentifier
		jCastle.assert(obj.type, jCastle.asn1.tagSequence, 'INVALID_CMS_FORMAT', 'CMS030');
		info.kekIdentifier = {};
		var i = 0;
		info.kekIdentifier.keyIdentifier = Buffer.from(obj.items[i++].value, 'latin1');
		if (obj.items[i] && obj.items[i].type == jCastle.asn1.tagGeneralizedTime) {
			info.kekIdentifier.date = obj.items[i].value;
			i++;
		}
/*
10.2.7.  OtherKeyAttribute

   The OtherKeyAttribute type gives a syntax for the inclusion of other
   key attributes that permit the recipient to select the key used by
   the sender.  The attribute object identifier must be registered along
   with the syntax of the attribute itself.  Use of this structure
   should be avoided since it might impede interoperability.

      OtherKeyAttribute ::= SEQUENCE {
        keyAttrId OBJECT IDENTIFIER,
        keyAttr ANY DEFINED BY keyAttrId OPTIONAL }
*/
		if (obj.items[i] && obj.items[i].type == jCastle.asn1.tagSequence) {
			var otherKeyAttribute = {};
			otherKeyAttribute.keyAttrId = jCastle.oid.getName(obj.items[i].items[0].value);
			if (obj.items[i].items[1]) {
				otherKeyAttribute.keyAttr = jCastle.cms.asn1.attrs.parse(obj.items[i].items[1]);
			}
			info.kekIdentifier.otherKeyAttribute = otherKeyAttribute;
		}


		obj = explicit.items[idx++];

		// keyEncryptionAlgorithm
		jCastle.assert(obj.type, jCastle.asn1.tagSequence, 'INVALID_CMS_FORMAT', 'CMS031');
		var wrap_algo = jCastle.oid.getName(obj.items[0].value);
		var algo = jCastle.keyWrap.getAlgoName(wrap_algo);

		info.keyEncryptionAlgorithm = algo;

		obj = explicit.items[idx++];

		// encryptedKey
		info.encryptedKey = Buffer.from(obj.value, 'latin1');

		// console.log('cmsKey: ', cmsKey);
		// console.log('keySize: ', jCastle._algorithmInfo[algo].key_size);

		if ('wrappingKey' in cmsKey || 'keyEncryptionKey' in cmsKey) { // enveopKey
			var wrappingKey = Buffer.from(cmsKey.wrappingKey || cmsKey.keyEncryptionKey, 'latin1');
			var keySize = jCastle._algorithmInfo[algo].key_size;
			//while (wrappingKey.length < keySize) wrappingKey.push(0x00);
			if (wrappingKey.length < keySize) wrappingKey = Buffer.concat([wrappingKey, Buffer.alloc(keySize - wrappingKey.length)]);

			var kw = new jCastle.keyWrap(algo);
			try {
				var decryptedKey = kw.unwrap(info.encryptedKey, {
					wrappingKey: wrappingKey
				});

				info.decryptedKey = decryptedKey;
			} catch (ex) {
				// console.log('encrypt key for the decryption of content encryption key(CEK) is not correct');
				// console.log(ex.message);
			}
		}

		return info;
	},

	schema: function(recipientInfo, encryptKey, cmsKey, options = {})
	{
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
		var schema = {
			type: 0x02,
			tagClass: jCastle.asn1.tagClassContextSpecific,
			constructed: true,
			items: []
		};

		// version
		schema.items.push({
			type: jCastle.asn1.tagInteger,
			intVal: 4 // always 4
		});

		// kekIdentifier
		var kekIdentifier = 'kekIdentifier' in recipientInfo ? recipientInfo.kekIdentifier : {};
		var keyIdentifier = null, kekIdentifierSchema = {type: jCastle.asn1.tagSequence, items: []};
		if ('keyIdentifier' in kekIdentifier) {
			keyIdentifier = Buffer.from(kekIdentifier.keyIdentifier, 'latin1');
		} else {
			var prng = new jCastle.prng(Buffer.from(encryptKey, 'latin1').toString('latin1'), 'sha-1');
			keyIdentifier = prng.nextBytes(16);
		}
		kekIdentifierSchema.items.push({
			type: jCastle.asn1.tagOctetString,
			value: keyIdentifier
		});

		if ('date' in kekIdentifier) {
			kekIdentifierSchema.items.push({
				type: jCastle.asn1.tagGeneralizedTime,
				value: kekIdentifier.date
			});
		}

		if ('otherKeyAttribute' in kekIdentifier) {
			kekIdentifierSchema.items.push(jCastle.cms.asn1.attr.schema(kekIdentifier.otherKeyAttribute));
		}

		schema.items.push(kekIdentifierSchema);

		// keyEncryptionAlgorithm
		var keyEncryptionAlgorithm = {
			type: jCastle.asn1.tagSequence,
			items: []
		};
		var algo = recipientInfo.keyEncryptionAlgorithm;
		var wrapAlgo = jCastle.keyWrap.getWrapName(algo);
		var oid = jCastle.keyWrap.getOID(algo);
		if (!oid) throw jCastle.exception('UNKNOWN_ALGORITHM', 'CMS032');

		keyEncryptionAlgorithm.items.push({
			type: jCastle.asn1.tagOID,
			value: oid
		});
		keyEncryptionAlgorithm.items.push({
			type: jCastle.asn1.tagNull,
			value: null
		});
		schema.items.push(keyEncryptionAlgorithm);

		// encryptedKey
		
		// we need wrappingKey and encryptKey.
		// wrappingKey must be given by user.
		// encryptKey can either be given by user or be generated by PRNG.
		if (!('wrappingKey' in cmsKey)) throw jCastle.exception('KEY_NOT_SET', 'CMS033');
		var wrappingKey = Buffer.from(cmsKey.wrappingKey, 'latin1');
		var keySize = jCastle._algorithmInfo[algo].key_size;
		//while(wrappingKey.length < keySize) wrappingKey.push(0x00);
		if (wrappingKey.length < keySize) wrappingKey = Buffer.concat([wrappingKey, Buffer.alloc(keySize - wrappingKey.length)]);
		var kw = new jCastle.keyWrap(algo);
		var encryptedKey = kw.wrap(encryptKey, {
			wrappingKey: wrappingKey
		});
		schema.items.push({
			type: jCastle.asn1.tagOctetString,
			value: encryptedKey
		});

		return schema;		
	}
};

/*
6.2.4.  PasswordRecipientInfo Type

   Recipient information using a password or shared secret value is
   represented in the type PasswordRecipientInfo.  Each instance of
   PasswordRecipientInfo will transfer the content-encryption key to one
   or more recipients who possess the password or shared secret value.

   The PasswordRecipientInfo Type is specified in RFC 3211 [PWRI].  The
   PasswordRecipientInfo structure is repeated here for completeness.

      PasswordRecipientInfo ::= SEQUENCE {
        version CMSVersion,   -- Always set to 0
        keyDerivationAlgorithm [0] KeyDerivationAlgorithmIdentifier
                                     OPTIONAL,
        keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
        encryptedKey EncryptedKey }

   The fields of type PasswordRecipientInfo have the following meanings:

      version is the syntax version number.  It MUST always be 0.

      keyDerivationAlgorithm identifies the key-derivation algorithm,
      and any associated parameters, used to derive the key-encryption
      key from the password or shared secret value.  If this field is
      absent, the key-encryption key is supplied from an external
      source, for example a hardware crypto token such as a smart card.

      keyEncryptionAlgorithm identifies the encryption algorithm, and
      any associated parameters, used to encrypt the content-encryption
      key with the key-encryption key.

      encryptedKey is the result of encrypting the content-encryption
      key with the key-encryption key.
*/
jCastle.cms.asn1.passwordRecipientInfo = {
	parse: function(explicit, cmsKey)
	{
/*
[3] (4 elem)
	INTEGER 0
	[0] (2 elem)
		OBJECT IDENTIFIER 1.2.840.113549.1.5.12				pkcs5PBKDF2 (PKCS #5 v2.0)
		SEQUENCE (3 elem)
			OCTET STRING (64 byte) DC183E8D90906228963B0963BEB9CE02FF5FD0D5F15B7CE059277421AB36D78922AB77…
			INTEGER 2048
			SEQUENCE (2 elem)
				OBJECT IDENTIFIER 1.2.840.113549.2.11		hmacWithSHA512 (RSADSI digestAlgorithm)
				NULL
	SEQUENCE (2 elem)
		OBJECT IDENTIFIER 2.16.840.1.101.3.4.1.45			aes256-wrap (NIST Algorithm)
		NULL
	OCTET STRING (24 byte) A81B7390BFDB9BAB900B0085370D3C9ADEAA1134851FA572
*/
		var idx = 0, info = {type: 'passwordRecipientInfo'};
		var obj = explicit.items[idx++];
		var kdfInfo;

		// version
		info.version = obj.intVal;
		jCastle.assert(info.version, 0, 'INVALID_CMS_FORMAT', 'CMS034');
		
		obj = explicit.items[idx++];

		// keyDerivationAlgorithm
		if (obj.tagClass == jCastle.asn1.tagClassContextSpecific) {
			jCastle.assert(obj.type, 0x00, 'INVALID_CMS_FORMAT', 'CMS035');

			kdfInfo = jCastle.pbe.asn1.pbkdf2.parse(obj);
			info.keyDerivationAlgorithm = kdfInfo;
			obj = explicit.items[idx++];
		}

		// keyEncryptionAlgorithm
		jCastle.assert(obj.type, jCastle.asn1.tagSequence, 'INVALID_CMS_FORMAT', 'CMS036');
		var wrap_algo = jCastle.oid.getName(obj.items[0].value);
		var algo = jCastle.keyWrap.getAlgoName(wrap_algo);

		info.keyEncryptionAlgorithm = algo;

		obj = explicit.items[idx++];

		// encryptedKey
		info.encryptedKey = Buffer.from(obj.value, 'latin1');

		if ('password' in cmsKey) {
			var password = Buffer.from(cmsKey.password, 'latin1');
			var keySize = 'keySize' in kdfInfo ? kdfInfo.keySize : jCastle._algorithmInfo[algo].key_size;

			var wrappingKey = jCastle.kdf.pbkdf2(
				password,
				kdfInfo.salt,
				kdfInfo.iterations,
				keySize,
				kdfInfo.prfHash
			);

			var kw = new jCastle.keyWrap(algo);
			try {
				var decryptedKey = kw.unwrap(info.encryptedKey, {
					wrappingKey: wrappingKey
				});

				info.decryptedKey = decryptedKey;
			} catch (e) {
				//console.log('encrypt key for the decryption of content encrytion key(CEK) is not correct');
				// nothing to do...
			}
		}

		return info;
	},

	schema: function(recipientInfo, encryptKey, cmsKey, options)
	{
/*
[3] (4 elem)
	INTEGER 0
	[0] (2 elem)
		OBJECT IDENTIFIER 1.2.840.113549.1.5.12				pkcs5PBKDF2 (PKCS #5 v2.0)
		SEQUENCE (3 elem)
			OCTET STRING (64 byte) DC183E8D90906228963B0963BEB9CE02FF5FD0D5F15B7CE059277421AB36D78922AB77…
			INTEGER 2048
			SEQUENCE (2 elem)
				OBJECT IDENTIFIER 1.2.840.113549.2.11		hmacWithSHA512 (RSADSI digestAlgorithm)
				NULL
	SEQUENCE (2 elem)
		OBJECT IDENTIFIER 2.16.840.1.101.3.4.1.45			aes256-wrap (NIST Algorithm)
		NULL
	OCTET STRING (24 byte) A81B7390BFDB9BAB900B0085370D3C9ADEAA1134851FA572
*/

		var schema = {
			type: 0x03,
			tagClass: jCastle.asn1.tagClassContextSpecific,
			constructed: true,
			items: []
		};

		// version
		schema.items.push({
			type: jCastle.asn1.tagInteger,
			intVal: 0 // always 0
		});

		// keyDerivationAlgorithm
		var kdf = recipientInfo.keyDerivationAlgorithm || {};
		if (!('salt' in kdf)) {
			var salt = null, saltLength = 64;
			if ('salt' in cmsKey) salt = Buffer.from(cmsKey.salt, 'latin1');
			else if ('saltLength' in cmsKey) saltLength = cmsKey.saltLength;

			if (!salt) {
				var prng = new jCastle.prng();
				salt = prng.nextBytes(saltLength);
			}
			kdf.salt = salt;
		}
		if (!('iterations' in kdf)) kdf.iterations = 'iterations' in cmsKey ? cmsKey.iterations : 2048;
		kdf.prfHash = 'prfHash' in kdf ? jCastle.digest.getValidAlgoName(kdf.prfHash) : 
			('prfHash' in cmsKey ? jCastle.digest.getValidAlgoName(cmsKey.prfHash) : 'sha-1');

		kdf.keySize = kdf.keySize || cmsKey.keySize || 0;

		var algo = recipientInfo.keyEncryptionAlgorithm;
		var algoInfo = jCastle.pbe.getAlgorithmInfo(algo, true);

		if (algoInfo.algo == 'rc2' && !kdf.keySize) {
			// rc2 default key size
			kdf.keySize = 16;
		}

		if (!kdf.keySize) kdf.keySize = jCastle._algorithmInfo[algo].key_size;

		var params = jCastle.mcrypt.getAlgoParameters(cmsKey);
		var pbe_info = {
			type: 'pkcs5PBKDF2',
			algo: algo,
			algoInfo: algoInfo,
			kdfInfo: kdf,
			params: params
		};


//console.log(pbe_info);

		var keyDerivationAlgorithmSchema = jCastle.pbe.asn1.pbkdf2.schema(pbe_info.kdfInfo, 0x00, pbe_info.algo == 'rc2');

		schema.items.push(keyDerivationAlgorithmSchema);

		var wrappingKey = jCastle.kdf.pbkdf2(
			cmsKey.password,
			kdf.salt,
			kdf.iterations,
			kdf.keySize,
			kdf.prfHash
		);

		// keyEncryptionAlgorithm
		var keyEncryptionAlgorithm = {
			type: jCastle.asn1.tagSequence,
			items: []
		};
		
		var wrapAlgo = jCastle.keyWrap.getWrapName(algo);
		var oid = jCastle.keyWrap.getOID(algo);
		if (!oid) throw jCastle.exception('UNKNOWN_ALGORITHM', 'CMS037');

		keyEncryptionAlgorithm.items.push({
			type: jCastle.asn1.tagOID,
			value: oid
		});
		keyEncryptionAlgorithm.items.push({
			type: jCastle.asn1.tagNull,
			value: null
		});
		schema.items.push(keyEncryptionAlgorithm);

		// encryptedKey
		
		// we need wrappingKey and encryptKey.
		// encryptKey can either be given by user or be generated by PRNG.
		var keySize = kdf.keySize ? kdf.keySize : jCastle._algorithmInfo[algo].key_size;
		var kw = new jCastle.keyWrap(algo);
		var encryptedKey = kw.wrap(Buffer.from(encryptKey, 'latin1'), {
			wrappingKey: wrappingKey
		});
		schema.items.push({
			type: jCastle.asn1.tagOctetString,
			value: encryptedKey
		});

		return schema;
	}
};

/*
6.2.5.  OtherRecipientInfo Type

   Recipient information for additional key management techniques are
   represented in the type OtherRecipientInfo.  The OtherRecipientInfo
   type allows key management techniques beyond key transport, key
   agreement, previously distributed symmetric key-encryption keys, and
   password-based key management to be specified in future documents.
   An object identifier uniquely identifies such key management
   techniques.

      OtherRecipientInfo ::= SEQUENCE {
        oriType OBJECT IDENTIFIER,
        oriValue ANY DEFINED BY oriType }

   The fields of type OtherRecipientInfo have the following meanings:

      oriType identifies the key management technique.

      oriValue contains the protocol data elements needed by a recipient
      using the identified key management technique.
*/
jCastle.cms.asn1.otherRecipientInfo = {
	parse: function(explicit, cmsKey)
	{
		var idx = 0;
		var obj = explicit.items[idx++];

		// otherRecipientInfo
		jCastle.assert(obj.type, jCastle.asn1.tagOID, "UNSUPPORTED_CMS_STRUCTURE", 'CMS038');

		var oriType = jCastle.oid.getName(obj.value);
		obj = explicit.items[idx++];

		var oriValue = obj; // we don't know what to do now...

		return {
			type: 'otherRecipientInfo',
			info: {
				oriType: oriType,
				oriValue: oriValue
			}
		};
	}
};



jCastle.cms.asn1.encryptedContentInfo = {
	parse: function(sequence, options)
	{
/*
6.3.  Content-encryption Process

   The content-encryption key for the desired content-encryption
   algorithm is randomly generated.  The data to be protected is padded
   as described below, then the padded data is encrypted using the
   content-encryption key.  The encryption operation maps an arbitrary
   string of octets (the data) to another string of octets (the
   ciphertext) under control of a content-encryption key.  The encrypted
   data is included in the EnvelopedData encryptedContentInfo
   encryptedContent OCTET STRING.

   Some content-encryption algorithms assume the input length is a
   multiple of k octets, where k is greater than one.  For such
   algorithms, the input shall be padded at the trailing end with
   k-(lth mod k) octets all having value k-(lth mod k), where lth is
   the length of the input.  In other words, the input is padded at
   the trailing end with one of the following strings:

                     01 -- if lth mod k = k-1
                  02 02 -- if lth mod k = k-2
                      .
                      .
                      .
            k k ... k k -- if lth mod k = 0

   The padding can be removed unambiguously since all input is padded,
   including input values that are already a multiple of the block size,
   and no padding string is a suffix of another.  This padding method is
   well defined if and only if k is less than 256.

6.4.  Key-encryption Process

   The input to the key-encryption process -- the value supplied to the
   recipient's key-encryption algorithm -- is just the "value" of the
   content-encryption key.

   Any of the aforementioned key management techniques can be used for
   each recipient of the same encrypted content.
*/
/*
10.1.4.  ContentEncryptionAlgorithmIdentifier

   The ContentEncryptionAlgorithmIdentifier type identifies a content-
   encryption algorithm.  Examples include Triple-DES and RC2.  A
   content-encryption algorithm supports encryption and decryption
   operations.  The encryption operation maps an octet string (the
   plaintext) to another octet string (the ciphertext) under control of
   a content-encryption key.  The decryption operation is the inverse of
   the encryption operation.  Context determines which operation is
   intended.

      ContentEncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
*/

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

		var encryptedContentInfo = {};

		contentType = jCastle.oid.getName(sequence.items[0].value);
		jCastle.assert(contentType, 'data', 'INVALID_OID', 'CMS039');
		encryptedContentInfo.contentType = contentType;

		// enc algo can be a password based algorithm lik pbkdf2.
		try {
			encryptedContentInfo.contentEncryptionAlgorithm = jCastle.pbe.asn1.encAlgoInfo.parse(sequence.items[1]);
		} catch (ex) {
			encryptedContentInfo.contentEncryptionAlgorithm = jCastle.pbe.asn1.pbeInfo.parse(sequence.items[1]);
		}

		var encryptedContent = '';

		if (sequence.items[2].constructed) {
			for (var i = 0; i < sequence.items[2].items.length; i++) {
				encryptedContent += sequence.items[2].items[i].value;
			}
		} else {
			encryptedContent = sequence.items[2].value;
		}

		encryptedContentInfo.encryptedContent = Buffer.from(encryptedContent, 'latin1');

		return encryptedContentInfo;
	},

	// encryptKey or password
	schema: function(encryptedContentInfo, encryptKey, params, ber_encoding)
	{
		// console.log('cms.asn1.encryptedContentInfo()');
/*
      EncryptedContentInfo ::= SEQUENCE {
        contentType ContentType,
        contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
        encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL }
*/
		var enc_algo_info = encryptedContentInfo.contentEncryptionAlgorithm;

		var content = encryptedContentInfo.content;
		var data;

		if (content) {
			data = jCastle.cms.content.getDER(content);	
			data = Buffer.from(data, 'latin1');
		}

		// console.log('conent: ', content);

		var encryptedContent = null;

		// check what encryption algorithm is.
		var algo = enc_algo_info.algo;
		var algo_info, pbe_info;
		var is_pbe = false;

		try {
			algo_info = jCastle.pbe.getAlgorithmInfo(algo);
			if (!('algoInfo' in enc_algo_info)) enc_algo_info.algoInfo = algo_info;
		} catch (ex) {
			is_pbe = true;
		}


		// algorithm can be key based encryption or password based encryption.
		if (is_pbe) {
			// console.log('password based encryption');

			var password = Buffer.from(encryptKey, 'latin1');
			pbe_info = enc_algo_info;
			var res;

			if (!('kdfInfo' in pbe_info)) pbe_info.kdfInfo = {};

			if ('salt' in pbe_info.kdfInfo) {
				pbe_info.kdfInfo.salt = Buffer.from(pbe_info.kdfInfo.salt, 'latin1');
			} else if ('saltLength' in pbe_info.kdfInfo) {
				pbe_info.kdfInfo.salt = new jCastle.prng().nextBytes(pbe_info.kdfInfo.saltLength);
			}

			if (!('iterations' in pbe_info.kdfInfo)) pbe_info.kdfInfo.iterations = 2048;
			if ('prfHash' in pbe_info.kdfInfo) pbe_info.kdfInfo.prfHash = jCastle.digest.getValidAlgoName(pbe_info.kdfInfo.prfHash);
			else pbe_info.kdfInfo.prfHash = 'sha-1';

			if (!('params' in pbe_info)) pbe_info.params = {};

			// pkcs#5 v2.0 algorithm
			if (algo.indexOf('pbeWith') === -1 && algo.indexOf('PBE-') === -1) {
				pbe_info.type = 'pkcs5PBKDF2';

				algo_info = jCastle.pbe.getAlgorithmInfo(enc_algo);
				if (!('algoInfo' in pbe_info)) pbe_info.algoInfo = algo_info;

				var key_size = 'keySize' in kdf_info ? kdf_info.keySize : 0;

				if (!key_size) {
					if (algo_info.algo == 'rc2') {
						// rc2 default key size
						key_size = 16;
					} else {
						key_size = algo_info.keySize;
					}
				}

				if (key_size) {
					pbe_info.kdfInfo.keySize = key_size;
					pbe_info.params.keySize = key_size;
				}

				if (content) {
					res = jCastle.pbe.pbes2.encrypt(pbe_info, password, data);

					encryptedContent = res.encrypted;
	
					pbe_info.kdfInfo.salt = res.salt;
					pbe_info.params.iv = res.iv;
				}
			} else {

				algo_info = jCastle.pbe.getPbeAlgorithmInfo(algo);

				pbe_info.type = algo_info.type == 'pkcs5' ? 'pkcs5PBKDF1' : 'pkcs12DeriveKey';

				if (!('algoInfo' in pbe_info)) pbe_info.algoInfo = algo_info;

				if (content) {
					if (algo_info.type == 'pkcs5') {
						// pkcs#5 v1.5 - PBKDF1
						res = jCastle.pbe.pbes1.encrypt(pbe_info, password, data);
					} else {
						// pkcs#12 - pbe
						res = jCastle.pbe.pkcs12pbes.encrypt(pbe_info, password, data);
					}
					
					encryptedContent = res.encrypted;
	
					pbe_info.kdfInfo.salt = res.salt;
				}
			}
		} else {

			if (!('params' in enc_algo_info)) enc_algo_info.params = params;

			if (content) {
				params.key = Buffer.from(encryptKey, 'latin1');
				params.mode = algo_info.mode;
				params.isEncryption = true;
	
				// var padding_mode = ['ecb', 'cbc', 'pcbc'];
				// if (padding_mode.includes(algo_info.mode)) params.padding = 'pkcs7';
				if (jCastle.mcrypt.mode.needsPadding(algo_info.mode)) params.padding = 'pkcs7';
	
				var crypto = new jCastle.mcrypt(algo_info.algo);
				crypto.start(params);
				crypto.update(data);
				encryptedContent = crypto.finalize();
			}
		}

		var encryptedContentInfoSchema = {
			type: jCastle.asn1.tagSequence,
			items:[{
				type: jCastle.asn1.tagOID,
				value: jCastle.oid.getOID(encryptedContentInfo.contentType || 'data')
//			}],
//			indefiniteLength: true
			}]
		};

		if (ber_encoding) encryptedContentInfoSchema.indefiniteLength = true;

		// encryption algorithm
		var encAlgoSchema;
		if (is_pbe) {
			encAlgoSchema = jCastle.pbe.asn1.pbeInfo.schema(pbe_info);
		} else {
			enc_algo_info.params.keySize = encryptKey.length;
			encAlgoSchema = jCastle.pbe.asn1.encAlgoInfo.schema(enc_algo_info);
		}
		
		encryptedContentInfoSchema.items.push(encAlgoSchema);

		if (encryptedContent) {
			var contentSchema = {
				type: 0x00,
				tagClass: jCastle.asn1.tagClassContextSpecific,
				constructed: true,
//				indefiniteLength: true,
				items: []
			};
			
			// do {
			// 	contentSchema.items.push({
			// 		type: jCastle.asn1.tagOctetString,
			// 		value: encryptedContent.substr(0, 1024)			
			// 	});
			// 	encryptedContent = encryptedContent.substr(1024);
			// } while (encryptedContent.length > 1024);
			var pos = 0;
			while (pos < encryptedContent.length) {
				contentSchema.items.push({
					type: jCastle.asn1.tagOctetString,
					value: encryptedContent.slice(pos, pos + 1024)
				});
				pos += 1024;
			}

			if (ber_encoding) contentSchema.indefiniteLength = true;

			encryptedContentInfoSchema.items.push(contentSchema);
		}

		return encryptedContentInfoSchema;
	}
};

jCastle.cms.asn1.originatorInfo = {
	parse: function(implicit, options)
	{
/*
      OriginatorInfo ::= SEQUENCE {
        certs [0] IMPLICIT CertificateSet OPTIONAL,
        crls [1] IMPLICIT RevocationInfoChoices OPTIONAL }
*/
		var sequence = implicit.items[0];

		var originatorInfo = {};

		jCastle.assert(sequence.type, jCastle.asn1.tagSequence, 'INVALID_DATA_TYPE', 'CMS041');

		var idx = 0, certs, crls;

		if (sequence.items[idx].tagClass == jCastle.asn1.tagClassContextSpecific && sequence.items[idx].type == 0x00) {
			certs = jCastle.cms.asn1.certificateSet.parse(sequence.items[idx]);
			idx++;
		}

		if (sequence.items[idx] &&
			sequence.items[idx].tagClass == jCastle.asn1.tagClassContextSpecific && sequence.items[idx].type == 0x01) {
			crls = jCastle.cms.asn1.revocationInfoChoices.parse(sequence.items[idx]);
		}

		if (certs) originatorInfo.certs = certs;
		if (crls) originatorInfo.crls = crls;

		return originatorInfo;
	},

	schema: function(originatorInfo, options)
	{
		var originatorInfoSchema = {
			type: 0x00,
			tagClass: jCastle.asn1.tagClassContextSpecific,
			constructed: true,
			items:[]
		};

		if ('certificates' in originatorInfo && originatorInfo.certificates.length) {
			var certs = originatorInfo.certificates;

			var certSchema = {
				type: 0x00,
				tagClass: jCastle.asn1.tagClassContextSpecific,
				constructed: true,
				items:[]
			};

			for (var i = 0; i < certs.length; i++) {
				var der = jCastle.certificate.getDER(certs[i]);
				certSchema.items.push(der);
			}

			originatorInfoSchema.items.push(certSchema);
		}

		if ('crls' in originatorInfo && originatorInfo.crls.length) {
			var crls = originatorInfo.crls;

			var crlsSchema = {
				type: 0x01,
				tagClass: jCastle.asn1.tagClassContextSpecific,
				constructed: true,
				items:[]
			};

			for (var i = 0; i < crls.length; i++) {
				var der = jCastle.certificate.getDER(crls[i]);
				crlsSchema.items.push(der);
			}

			originatorInfoSchema.items.push(crlsSchema);
		}
		
		return originatorInfoSchema;
	}
};

jCastle.cms.ASN1 = jCastle.cms.asn1;

jCastle.cms.create = function()
{
	return new jCastle.cms();
};

// jCastle.cms.rasterizeSchema = function(cmsInfo)
// {

// };

jCastle.CMS = jCastle.cms;

module.exports = jCastle.cms;
