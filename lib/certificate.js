/**
 * A Javascript implemenation of X509 Certificate 
 * 
 * @author Jacob Lee
 *
 * Copyright (C) 2015-2022 Jacob Lee. All rights reserved.
 */
var jCastle = require('./jCastle');

require('./bigint-extend');
require('./util');
require('./cert-config');

/*

X.509 Certificate
=================

Version 
Serial Number 
Algorithm ID 
Issuer 
Validity 
	- Not Before 
	- Not After 
Subject 
Subject Public Key Info 
	- Public Key Algorithm 
	- Subject Public Key 
Issuer Unique Identifier (Optional) 
Subject Unique Identifier (Optional) 
Extensions (Optional) 
	- ... 
Certificate Signature Algorithm 
Certificate Signature 

example:
--------

Signer 
	Issuer: C=US, O=Equifax, OU=Equifax Secure Certificate Authority 
Validity dates
	Not Before: Jul 7 19:51:50 2005 GMT 
	Not After : Oct 7 19:51:50 2006 GMT 
Algorithms (RSA, SHA1, MD5)
	Signature Algorithm: sha1WithRSAEncryption 
Certificate Revocation List (CRL)
	X509v3 CRL Distribution Points: URI:http://crl.geotrust.com/crls/secureca.crl 
Certificate usage — encryption and authentication, but not for issuing other certificates
	X509v3 extensions: 
		X509v3 Key Usage: critical Digital Signature, Non Repudiation, Key Encipherment, Data Encipherment 
		…
		X509v3 Extended Key Usage: TLS Web Server Authentication, TLS Web Client Authentication 


If certificate was for vouching for other certificates, would contain:
	X509v3 extensions: 
		X509v3 Basic Constraints: critical 
		CA:TRUE 


Root Certificate:
-----------------
Issuer and subject are the same
Manually install in application/installed in default list (example: browsers)


http://docs.oracle.com/javase/1.5.0/docs/tooldocs/windows/keytool.html
*/

jCastle.certificate = class
{
	constructor()
	{
		this.config = null;
		this.signKey = null;

		this.certInfo = null;
		// this.der = null;
		this.buffer = null;
	}

	/********************
	 * Public functions *
	 ********************/

	/**
	 * resets internal variables.
	 * 
	 * @public
	 * 
	 * @returns this class instance.
	 */
	reset()
	{
		this.config = null;
		this.signKey = null;

		this.certInfo = null;
		// this.der = null;
		this.buffer = null;

		return this;
	}

	/**
	 * accepts OpenSSL's cnf string or a parsed object and sets it.
	 * 
	 * @public
	 * 
	 * @param {mixed} config OpenSSL's cnf string or a parsed object.
	 * 
	 * @returns this class instance.
	 */
	setConfig(config)
	{
		if (config) {
			if (jCastle.util.isString(config)) {
				this.config = new jCastle.certConfig().parse(config);
			} else {
				if (config instanceof jCastle.certConfig) {
					this.config = config.contents;
				} else if (typeof config == 'object' && 'type' in config && config.type == 'CONFIG') {
					this.config = config;
				} else {
					throw jCastle.exception('INVALID_PARAMS', 'CRT001');
				}
			}
		}

		return this;
	}

	/**
	 * sets pki for a sign key.
	 * 
	 * @public
	 * 
	 * @param {mixed} signkey a pki object, or PEM string. A asn1 parsed object can be given for it.
	 * @param {buffer} password a string or buffer value for password
	 * 
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
https://www.ietf.org/rfc/rfc5280.txt

4.  Certificate and Certificate Extensions Profile

   This section presents a profile for public key certificates that will
   foster interoperability and a reusable PKI.  This section is based
   upon the X.509 v3 certificate format and the standard certificate
   extensions defined in [X.509].  The ISO/IEC and ITU-T documents use
   the 1997 version of ASN.1; while this document uses the 1988 ASN.1
   syntax, the encoded certificate and standard extensions are
   equivalent.  This section also defines private extensions required to
   support a PKI for the Internet community.

   Certificates may be used in a wide range of applications and
   environments covering a broad spectrum of interoperability goals and
   a broader spectrum of operational and assurance requirements.  The
   goal of this document is to establish a common baseline for generic
   applications requiring broad interoperability and limited special
   purpose requirements.  In particular, the emphasis will be on
   supporting the use of X.509 v3 certificates for informal Internet
   electronic mail, IPsec, and WWW applications.

4.1.  Basic Certificate Fields

   The X.509 v3 certificate basic syntax is as follows.  For signature
   calculation, the data that is to be signed is encoded using the ASN.1
   distinguished encoding rules (DER) [X.690].  ASN.1 DER encoding is a
   tag, length, value encoding system for each element.

   Certificate  ::=  SEQUENCE  {
        tbsCertificate       TBSCertificate,
        signatureAlgorithm   AlgorithmIdentifier,
        signatureValue       BIT STRING  }

   TBSCertificate  ::=  SEQUENCE  {
        version         [0]  EXPLICIT Version DEFAULT v1,
        serialNumber         CertificateSerialNumber,
        signature            AlgorithmIdentifier,
        issuer               Name,
        validity             Validity,
        subject              Name,
        subjectPublicKeyInfo SubjectPublicKeyInfo,
        issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
                             -- If present, version MUST be v2 or v3
        subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
                             -- If present, version MUST be v2 or v3
        extensions      [3]  EXPLICIT Extensions OPTIONAL
                             -- If present, version MUST be v3
        }

   Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }

   CertificateSerialNumber  ::=  INTEGER

   Validity ::= SEQUENCE {
        notBefore      Time,
        notAfter       Time }

   Time ::= CHOICE {
        utcTime        UTCTime,
        generalTime    GeneralizedTime }

   UniqueIdentifier  ::=  BIT STRING

   SubjectPublicKeyInfo  ::=  SEQUENCE  {
        algorithm            AlgorithmIdentifier,
        subjectPublicKey     BIT STRING  }

   Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension

   Extension  ::=  SEQUENCE  {
        extnID      OBJECT IDENTIFIER,
        critical    BOOLEAN DEFAULT FALSE,
        extnValue   OCTET STRING
                    -- contains the DER encoding of an ASN.1 value
                    -- corresponding to the extension type identified
                    -- by extnID
        }

*/
	/**
	 * parses input data for certificate.
	 * 
	 * @public
	 * 
	 * @param {buffer} pem pem data of certificate.
	 * @param {string} format pem format. 'buffer' | 'der' | 'hex' | 'base64' | 'object'. (default: 'auto')
	 * @param {integer} type a asn1 type integer. (default: jCastle.certificate.typeCRT)
	 * 
	 * @returns the certificate object.
	 */
	parse(pem, format = 'auto', type = jCastle.certificate.typeCRT)
	{
		var asn1 = new jCastle.asn1();
		var buf, sequence;
		//asn1.ignoreLengthError();

		if (format == null) format = 'auto';
		format = format.toLowerCase();
		if (typeof format == 'undefined' || format.toLowerCase() == 'auto') {
			format = jCastle.util.seekPemFormat(pem);
		}

		if (typeof pem == 'object' && 'type' in pem && 'tbs' in pem && 'algo' in pem && 'signature' in pem) {
			this.certInfo = pem;

			return this.certInfo;
		}

		// console.log('format: ', format);

		if (format == 'asn1') {
			sequence = pem;
		} else {
			switch (format) {
				case 'base64':
					buf = Buffer.from(pem.trim(), 'base64');
					break;
				case 'hex':
					buf = Buffer.from(pem.replace(/[^0-9A-F]+/ig, ''), 'hex');
					break;
				case 'der': 
					buf = Buffer.from(pem, 'latin1');
					break;
				case 'pem':
					pem = pem.trim();

					var m = /-----BEGIN (X509 CRL|(NEW )?CERTIFICATE( REQUEST)?)-----/g.exec(pem);
					if (!m) {
						throw jCastle.exception("INVALID_PEM_FORMAT", 'CRT002');
					}

					switch (m[1]) {
						case 'X509 CRL':
							type = jCastle.certificate.typeCRL;
							break;
						case 'CERTIFICATE REQUEST':
						case 'NEW CERTIFICATE REQUEST':
							type = jCastle.certificate.typeCSR;
							break;
						case 'CERTIFICATE':
							type = jCastle.certificate.typeCRT;
							break;
					}

					pem = pem.replace(/-----(BEGIN|END) (X509 CRL|(NEW )?CERTIFICATE( REQUEST)?)-----/g, '').replace(/[ \t\r\n]/g, '');
					buf = Buffer.from(pem, 'base64');
					break;
				default:
					buf = Buffer.from(pem);
					break;
			}

			try {
				sequence = asn1.parse(buf);
			} catch (err) {
				// console.log(err.message);
				throw jCastle.exception("INVALID_PEM_FORMAT", 'CRT003');
			}

			if (!jCastle.asn1.isSequence(sequence)) {
				throw jCastle.exception("INVALID_PEM_FORMAT", 'CRT004');
			}
		}



		// default: CRT
		if ((typeof type == 'undefined' || type == null ) && format != 'pem') {
			type = jCastle.certificate.typeCRT;
		}

		

	
/*
4.1.1.  Certificate Fields

   The Certificate is a SEQUENCE of three required fields.  The fields
   are described in detail in the following subsections.

4.1.1.1.  tbsCertificate

   The field contains the names of the subject and issuer, a public key
   associated with the subject, a validity period, and other associated
   information.  The fields are described in detail in Section 4.1.2;
   the tbsCertificate usually includes extensions, which are described
   in Section 4.2.
*/
		var tbs_info;

		switch (type) {
			case jCastle.certificate.typeCRT:
				tbs_info = this._parseTbsCertificate(sequence.items[0]);
				break;
			case jCastle.certificate.typeCSR:
				tbs_info = this._parseCsrTbsCertificate(sequence.items[0]);
				break;		
			case jCastle.certificate.typeCRL:
				tbs_info = this._parseCrlTbsCertificate(sequence.items[0]);
				break;
			default: 
				throw jCastle.exception("UNSUPPORTED_CERT_TYPE", 'CRT005');
		}



/*
4.1.1.2.  signatureAlgorithm

   The signatureAlgorithm field contains the identifier for the
   cryptographic algorithm used by the CA to sign this certificate.
   [RFC3279], [RFC4055], and [RFC4491] list supported signature
   algorithms, but other signature algorithms MAY also be supported.

   An algorithm identifier is defined by the following ASN.1 structure:

   AlgorithmIdentifier  ::=  SEQUENCE  {
        algorithm               OBJECT IDENTIFIER,
        parameters              ANY DEFINED BY algorithm OPTIONAL  }

   The algorithm identifier is used to identify a cryptographic
   algorithm.  The OBJECT IDENTIFIER component identifies the algorithm
   (such as DSA with SHA-1).  The contents of the optional parameters
   field will vary according to the algorithm identified.

   This field MUST contain the same algorithm identifier as the
   signature field in the sequence tbsCertificate (Section 4.1.2.3).
*/
		var algo_info = jCastle.certificate.asn1.signAlgorithm.parse(sequence.items[1]);




/*
4.1.1.3.  signatureValue

   The signatureValue field contains a digital signature computed upon
   the ASN.1 DER encoded tbsCertificate.  The ASN.1 DER encoded
   tbsCertificate is used as the input to the signature function.  This
   signature value is encoded as a BIT STRING and included in the
   signature field.  The details of this process are specified for each
   of the algorithms listed in [RFC3279], [RFC4055], and [RFC4491].

   By generating this signature, a CA certifies the validity of the
   information in the tbsCertificate field.  In particular, the CA
   certifies the binding between the public key material and the subject
   of the certificate.
*/
		var signature = '';

/*
		switch (algo_info.signAlgo) {
			case 'DSA':
			case 'KCDSA':
			case 'ECDSA':
			case 'ECKCDSA':
				signature = sequence.items[2].value.der;
				break;
			case 'RSASSA-PKCS1-V1_5':
			case 'RSASSA-PSS':
			default:
				if (sequence.items[2].type == jCastle.asn1.tagBitString) {
					signature = sequence.items[2].value;
				} else {
					throw jCastle.exception("SIGNATURE_GET_FAIL", 'CRT006');
				}
		}
*/
		signature = jCastle.certificate.asn1.signature.parse(sequence.items[2], algo_info.signAlgo);



		var certInfo = {
			type: type,
			tbs: tbs_info,
			algo: algo_info,
			signature: signature
		};

		if (buf) {
			this.buffer = buf;
			// this.der = buf.toString('latin1');
		}
		
		this.certInfo = certInfo;

		return certInfo;
	}

/*
https://tools.ietf.org/html/rfc2986

3. Overview

   A certification request consists of three parts: "certification
   request information," a signature algorithm identifier, and a digital
   signature on the certification request information.  The
   certification request information consists of the entity's
   distinguished name, the entity's public key, and a set of attributes
   providing other information about the entity.

   The process by which a certification request is constructed involves
   the following steps:

        1. A CertificationRequestInfo value containing a subject
           distinguished name, a subject public key, and optionally a
           set of attributes is constructed by an entity requesting
           certification.

        2. The CertificationRequestInfo value is signed with the subject
           entity's private key.  (See Section 4.2.)

        3. The CertificationRequestInfo value, a signature algorithm
           identifier, and the entity's signature are collected together
           into a CertificationRequest value, defined below.

   A certification authority fulfills the request by authenticating the
   requesting entity and verifying the entity's signature, and, if the
   request is valid, constructing an X.509 certificate from the
   distinguished name and public key, the issuer name, and the
   certification authority's choice of serial number, validity period,
   and signature algorithm.  If the certification request contains any
   PKCS #9 attributes, the certification authority may also use the
   values in these attributes as well as other information known to the
   certification authority to construct X.509 certificate extensions.

   In what form the certification authority returns the new certificate
   is outside the scope of this document.  One possibility is a PKCS #7
   cryptographic message with content type signedData, following the
   degenerate case where there are no signers.  The return message may
   include a certification path from the new certificate to the
   certification authority.  It may also include other certificates such
   as cross-certificates that the certification authority considers
   helpful, and it may include certificate-revocation lists (CRLs).
   Another possibility is that the certification authority inserts the
   new certificate into a central database.

   Note 1 - An entity would typically send a certification request after
   generating a public-key/private-key pair, but may also do so after a
   change in the entity's distinguished name.

   Note 2 - The signature on the certification request prevents an
   entity from requesting a certificate with another party's public key.
   Such an attack would give the entity the minor ability to pretend to
   be the originator of any message signed by the other party.  This
   attack is significant only if the entity does not know the message
   being signed and the signed part of the message does not identify the
   signer.  The entity would still not be able to decrypt messages
   intended for the other party, of course.

   Note 3 - How the entity sends the certification request to a
   certification authority is outside the scope of this document.  Both
   paper and electronic forms are possible.

   Note 4 - This document is not compatible with the certification
   request syntax for Privacy-Enhanced Mail, as described in RFC 1424
   [5].  The syntax here differs in three respects: It allows a set of
   attributes; it does not include issuer name, serial number, or
   validity period; and it does not require an "innocuous" message to be
   signed.  This document is designed to minimize request size, an
   important feature for certification authorities accepting requests on
   paper.

4. Certification request syntax

   This section is divided into two parts.  The first part describes the
   certification-request-information type CertificationRequestInfo, and
   the second part describes the top-level type CertificationRequest.

 4.1 CertificationRequestInfo

   Certification request information shall have ASN.1 type
   CertificationRequestInfo:

   CertificationRequestInfo ::= SEQUENCE {
        version       INTEGER { v1(0) } (v1,...),
        subject       Name,
        subjectPKInfo SubjectPublicKeyInfo{{ PKInfoAlgorithms }},
        attributes    [0] Attributes{{ CRIAttributes }}
   }

   SubjectPublicKeyInfo { ALGORITHM : IOSet} ::= SEQUENCE {
        algorithm        AlgorithmIdentifier {{IOSet}},
        subjectPublicKey BIT STRING
   }

   PKInfoAlgorithms ALGORITHM ::= {
        ...  -- add any locally defined algorithms here -- }

   Attributes { ATTRIBUTE:IOSet } ::= SET OF Attribute{{ IOSet }}

   CRIAttributes  ATTRIBUTE  ::= {
        ... -- add any locally defined attributes here -- }

   Attribute { ATTRIBUTE:IOSet } ::= SEQUENCE {
        type   ATTRIBUTE.&id({IOSet}),
        values SET SIZE(1..MAX) OF ATTRIBUTE.&Type({IOSet}{@type})
   }

   The components of type CertificationRequestInfo have the following
   meanings:

        version is the version number, for compatibility with future
          revisions of this document.  It shall be 0 for this version of
          the standard.

        subject is the distinguished name of the certificate subject
          (the entity whose public key is to be certified).

        subjectPublicKeyInfo contains information about the public key
          being certified.  The information identifies the entity's
          public-key algorithm (and any associated parameters); examples
          of public-key algorithms include the rsaEncryption object
          identifier from PKCS #1 [1].  The information also includes a
          bit-string representation of the entity's public key.  For the
          public-key algorithm just mentioned, the bit string contains
          the DER encoding of a value of PKCS #1 type RSAPublicKey.  The
          values of type SubjectPublicKeyInfo{} allowed for
          subjectPKInfo are constrained to the values specified by the
          information object set PKInfoAlgorithms, which includes the
          extension marker (...).  Definitions of specific algorithm
          objects are left to specifications that reference this
          document.  Such specifications will be interoperable with
          their future versions if any additional algorithm objects are
          added after the extension marker.

        attributes is a collection of attributes providing additional
          information about the subject of the certificate.  Some
          attribute types that might be useful here are defined in PKCS
          #9.  An example is the challenge-password attribute, which
          specifies a password by which the entity may request
          certificate revocation.  Another example is information to
          appear in X.509 certificate extensions (e.g. the
          extensionRequest attribute from PKCS #9).  The values of type
          Attributes{} allowed for attributes are constrained to the
          values specified by the information object set CRIAttributes.
          Definitions of specific attribute objects are left to
          specifications that reference this document.  Such
          specifications will be interoperable with their future
          versions if any additional attribute objects are added after
          the extension marker.

 4.2 CertificationRequest

   A certification request shall have ASN.1 type CertificationRequest:

   CertificationRequest ::= SEQUENCE {
        certificationRequestInfo CertificationRequestInfo,
        signatureAlgorithm AlgorithmIdentifier{{ SignatureAlgorithms }},
        signature          BIT STRING
   }

   AlgorithmIdentifier {ALGORITHM:IOSet } ::= SEQUENCE {
        algorithm          ALGORITHM.&id({IOSet}),
        parameters         ALGORITHM.&Type({IOSet}{@algorithm}) OPTIONAL
   }

   SignatureAlgorithms ALGORITHM ::= {
        ... -- add any locally defined algorithms here -- }

   The components of type CertificationRequest have the following
   meanings:

        certificateRequestInfo is the "certification request
          information." It is the value being signed.

        signatureAlgorithm identifies the signature algorithm (and any
          associated parameters) under which the certification-request
          information is signed.  For example, a specification might
          include an ALGORITHM object for PKCS #1's
          md5WithRSAEncryption in the information object set
          SignatureAlgorithms:

          SignatureAlgorithms ALGORITHM ::= {
               ...,
               { NULL IDENTIFIED BY md5WithRSAEncryption }
          }

        signature is the result of signing the certification request
          information with the certification request subject's private
          key.

   The signature process consists of two steps:

        1. The value of the certificationRequestInfo component is DER
           encoded, yielding an octet string.

        2. The result of step 1 is signed with the certification request
           subject's private key under the specified signature
           algorithm, yielding a bit string, the signature.

   Note - An equivalent syntax for CertificationRequest could be
   written:

   CertificationRequest ::= SIGNED { EncodedCertificationRequestInfo }
        (CONSTRAINED BY { -- Verify or sign encoded
         -- CertificationRequestInfo -- })

   EncodedCertificationRequestInfo ::=
        TYPE-IDENTIFIER.&Type(CertificationRequestInfo)

   SIGNED { ToBeSigned } ::= SEQUENCE {
        toBeSigned ToBeSigned,
        algorithm  AlgorithmIdentifier { {SignatureAlgorithms} },
        signature  BIT STRING
   }
*/
/*
CSR(Certificate Signing Request)
================================

	What is contained in a CSR?

	---------------------+------------------------------------------------------------------+--------------------------
			Name         |                         Explanation                              |         Examples
	---------------------+------------------------------------------------------------------+--------------------------
	Common Name          | The fully qualified domain name (FQDN) of your server.           | *.google.com
						 | This must match exactly what you type in your web browser        | mail.google.com
						 | or you will receive a name mismatch error. 	                    |
	---------------------+------------------------------------------------------------------+--------------------------
	Organization         | The legal name of your organization.                             | Google Inc.
						 | This should not be abbreviated and should include                |
						 | suffixes such as Inc, Corp, or LLC.                              |
	---------------------+------------------------------------------------------------------+--------------------------
	Organizational Unit  | The division of your organization handling the certificate. 	    | Information Technology
						 |                                                                  | IT Department
	---------------------+------------------------------------------------------------------+--------------------------
	City/Locality        | The city where your organization is located.                     | Mountain View
	---------------------+------------------------------------------------------------------+--------------------------
	State/County/Region  | The state/region where your organization is located.             | California
						 | This shouldn't be abbreviated.                                   |
	---------------------+------------------------------------------------------------------+--------------------------
	Country              | The two-letter ISO code for the country                          | US
						 | where your organization is location.                             | GB
	---------------------+------------------------------------------------------------------+--------------------------
	Email address        | An email address used to contact your organization.              | webmaster@google.com
	---------------------+------------------------------------------------------------------+--------------------------
	Public Key           | The public key that will go into the certificate.                | The public key is
						 |                                                                  | created automatically
	---------------------+------------------------------------------------------------------+--------------------------
*/
/*
var subject = [{
		name: 'C',
		value: countryName.value
	}, {
		name: 'ST',
		value: stateOrProvinceName.value
	}, {
		name: 'L',
		value: localityName.value
	}, {
		name: 'O',
		value: organizationName.value
	}, {
		name: 'OU',
		value: organizationalUnitName.value
	}, {
		name: 'CN',
		value: commonName.value
	}, {
		name: 'E',
		value: emailAddress.value
	}, {
		name: 'STREET',
		value: streetAddress.value
	}
];


new cert = new jCastle.certificate();
cert.setConfig(cert_config);
cert.setSignKey(sign_key);

var csr_pem = cert.request({
	subject: subject,
	algo: {
		signAlgo: 'RSASSA-PKCS1-V1_5',
		hashAlgo: 'sha-256'
	}
}, {
	signKey: issuer_privateKey, // or use .setSignKey()
	config: cert_config, // or use .setConfig()
	extensionName: config_ext_name,
	format: 'pem' // default
});
*/
	/**
	 * accepts request info object and issues a request certificate.
	 * 
	 * @public
	 * 
	 * @param {object} req_info request information object.
	 * @param {object} options options object.
	 *                     {string} format return type. 'der' | 'buffer' | 'hex' | 'base64' | 'pem'. (default: 'pem')
	 *                     {mixed} signKey pki object or pem for sign key.
	 *                     {string | buffer} password password for signKey.
	 *                     {mixed} config certficate config object or string.
	 * 
	 * @returns the request certficate pem or string.
	 */
	request(req_info, options = {})
	{
		var format = 'format' in options ? options.format.toLowerCase() : 'pem';

		if (typeof req_info != 'object') {
			throw jCastle.exception("INVALID_PARAMS", 'CRT007');
		}

		if ('signKey' in options) this.setSignKey(options.signKey, options.password);
		if ('config' in options) this.setConfig(options.config);

		if (!this.signKey || !this.signKey.hasPrivateKey()) {
			throw jCastle.exception("PKI_NOT_SET", 'CRT008');
		}

		// build cert_info using config
		var req_build = {};
		req_build.tbs = {};

		req_build.type = jCastle.certificate.typeCSR;
		req_build.tbs.version = 0x00;

		// build req_build.tbs.subject

		var string_mask = jCastle.certConfig.fn.getStringMask(
			this.config && 'req' in this.config && 'string_mask' in this.config.req ? this.config.req.string_mask : 'default'
		);

		req_build.tbs.subject = [];

		if (!req_info.hasOwnProperty('subject')) {
			throw jCastle.exception("INVALID_CERT_INFO", 'CRT009');
		}

		var subject = jCastle.certificate.fn.reviseDirectoryName(req_info.subject);

		for (var i = 0; i < subject.length; i++) {
			// matching test is not supported now
			// args.config.policy_match
			var name = subject[i].name;
			var value = subject[i].value;

			if (this.config && 'req' in this.config) {
				if (!value.length) {
					if (name + '_default' in this.config.req.distinguished_name && 
						this.config.req.distinguished_name[name + '_default'].length
					) {
						value = this.config.req.distinguished_name[name + '_default'];
					}
				}

				if (name + '_min' in this.config.req.distinguished_name && 
					this.config.req.distinguished_name[name + '_min'] &&
					value.length < this.config.req.distinguished_name[name + '_min']
				) {
					throw jCastle.exception("TOO_SHORT_VALUE", 'CRT010');
				}

				if (name + '_max' in this.config.req.distinguished_name && 
					this.config.req.distinguished_name[name + '_max'] &&
					value.length > this.config.req.distinguished_name[name + '_max']
				) {
					throw jCastle.exception("TOO_LONGER_VALUE", 'CRT011');
				}
			}

			if (!value.length) {
				if (this.config && this.config.policy_anything[name] == 'supplied') {
					throw jCastle.exception("VALUE_NOT_SUPPLIED", 'CRT012');
				}
				continue;
			}

			var o = {
				name: name,
				value: value,
				type: 'type' in subject[i] ? subject[i].type : string_mask
			};

			req_build.tbs.subject.push(o);
		}

		// sign algorithm
		var algo = {
			signAlgo: req_info.algo && 'signAlgo' in req_info.algo ? req_info.algo.signAlgo : this.signKey.pkiName,
			signHash: req_info.algo && 'signHash' in req_info.algo ? req_info.algo.signHash : (
				this.config && 'req' in this.config && 'default_md' in this.config.req ? this.config.req.default_md : (
					this.config && 'ca' in this.config && 'default_md' in this.config.ca.default_ca ? this.config.ca.default_ca.default_md : 'sha-1'
				)
			)
		};

		// if (algo.signAlgo == 'EC') algo.signAlgo = 'ECDSA';
		if (algo.signAlgo == 'RSA') algo.signAlgo = 'RSASSA-PKCS1-V1_5';

		if (!jCastle.certificate.fn.isSignAlgoSameWithPKI(algo.signAlgo, this.signKey)) {
			throw jCastle.exception("SIGN_ALGO_MISMATCH", 'CRT013');
		}

		req_build.algo = algo;

		// create public key info
		req_build.tbs.subjectPublicKeyInfo = this.signKey.getPublicKeyInfo();

		// get extension
		var extensions = null;

		if ('extensionName' in options && this.config && options.extensionName in this.config) {
			extensions = jCastle.util.clone(this.config[options.extensionName]);			
		} else if ('extensions' in req_info) {
			extensions = req_info.extensions;
		} else if (this.config && 'req' in this.config && 'req_extensions' in this.config.req && typeof this.config.req.req_extensions == 'object') {
			extensions = jCastle.util.clone(this.config.req.req_extensions);
		} else if (this.config && 'req_ext' in this.config && typeof this.config.req_ext == 'object') {
			extensions = jCastle.util.clone(this.cofig.req_ext);
		}

		if (extensions) {
			req_build.tbs.extensionRequest = extensions;
			jCastle.certificate.fn.transformConfigExtensions(req_build, this.config, this.signKey);
		}

		return this.exportCertificate(req_build, format);
	}

	/**
	 * validates a pem.
	 * 
	 * @public
	 * 
	 * @param {mixed} pem certificate object or pem string.
	 * @param {mixed} pub_pki publicKey object or pem string for verifying the signature.
	 * @returns true if the input certificate is validated.
	 */
	validate(pem, pub_pki)
	{
		var format = jCastle.util.seekPemFormat(pem);
		var cert_info = this.parse(pem, format);
		var verifying_pkey;

		if (pub_pki) {
			if (jCastle.util.isString(pub_pki)) {
				// certificate pem that signed the certificate that are to be verified
				var signing_cert_info = new jCastle.certificate().parse(pub_pki);
				verifying_pkey = jCastle.pki.createFromPublicKeyInfo(signing_cert_info.tbs.subjectPublicKeyInfo);
			} else {
				verifying_pkey = jCastle.pki.create().init(pub_pki);
			}
		} else {
			if (this.signKey && this.signKey.hasPublicKey()) {
				verifying_pkey = this.signKey;
			} else {
				verifying_pkey = jCastle.pki.createFromPublicKeyInfo(cert_info.tbs.subjectPublicKeyInfo);
			}
		}

		// verify if CSR or self-signed
		// in this case the pub_pki should be the same public key with the one inside the pem.
		if (cert_info.type == jCastle.certificate.typeCSR ||
			(cert_info.type == jCastle.certificate.typeCRT && jCastle.certificate.fn.isIssuerAndSubjectIdentical(cert_info))
		) {
			var v = this.verify(pem, verifying_pkey, format);
			if (!v) return false;
		}

		// subject key identifier
		if (cert_info.type == jCastle.certificate.typeCSR &&
			cert_info.tbs.extensionRequest && 'subjectKeyIdetifier' in cert_info.tbs.extensionRequest) {



			var subjectKeyIdetifier = cert_info.tbs.extensionRequest.subjectKeyIdetifier;
			if (subjectKeyIdetifier != jCastle.pki.createPublicKeyIdentifier(verifying_pkey)) {
				return false;
			}
		} else if (cert_info.type == jCastle.certificate.typeCRT &&
			cert_info.tbs.extensions && 'subjectKeyIdetifier' in cert_info.tbs.extensions) {
			var subjectKeyIdetifier = cert_info.tbs.extensions.subjectKeyIdetifier;
			if (subjectKeyIdetifier != jCastle.pki.createPublicKeyIdentifier(verifying_pkey)) {
				return false;
			}
		}

		return true;
	}

/*
Managing a CA
=============

Now that you have a CA, this page will cover how to do things with it.

Initial Preperation
-------------------

You'll want to adjust the policy line (under your default ca section) 
in your openssl.conf. If it's set to policy_match then that means 
all certificates must match country, state, and organizationName of 
our CA, and must supply a locality and commonName. If you set it 
to policy_anything then the only thing required is a commonName.

Of course, in reality, you probably want to define your own policy,
one which requires various things to be present, but 
doesn't require they match your CA. Any, set the policy line 
to the appropriate policy.

Additionally, you'll want to make sure that x509_extensions 
(under your default ca section) is set to whatever section of extensions
you want to give people when you sign extensions. 
See the extensions page for details on what these are and 
which ones you might want.

Lastly, you'll probably want to setup the following aliases for ease-of-use:

alias cert='openssl x509 -noout -text -in'
alias req='openssl req -noout -text -in'
alias crl='openssl crl -noout -text -in'

As you'll see below, there is plenty of room for other aliases, 
but these will allow you to look at a certificate 
by typing cert foo.crt, a request by typing req foo.csr, 
and a CRL by typing crl foo.crl.

Signing Certificates
--------------------

To sign a certificate request, dump it in your certreqs directory,
and then type:

openssl ca -config openssl.cnf -infiles certreqs/foo.csr

This will dump out information about the foo.csr request as well as
the certificate that will result if you sign. You should verify 
this information carefully. If you decide you want to sign, 
you will need to confirm by typing "y", as well as provide 
the passphrase for the CA's private key.

At this point you'll have the signed certificate under the certsdb
directory named by the serial number it was given, and with a .pem
extension. You may deliver this to the original requestor. 
You may use plain-text means as this public cert does not need
to be kept secure.

If you are signing a certificate that needs a different set of
extensions, for example, a subordinate CA, you can do:

openssl ca -config openssl.cnf -extensions v3_ca -infiles certreqs/foo.csr

And by the same token, you may choose a different policy with:

openssl ca -config openssl.cnf -policy policy_match -infiles certreqs/foo.csr
And obviously, you may use both.

Revoking a Certificate
----------------------

If a key gets compromised, is superseded, or otherwise no longer needed,
the CA should revoke it. This is done via:

openssl ca -config openssl.cnf -revoke certsdb/5FE840894254A22.pem
This will ask you for the passphrase of the CA's private key 
and then revoke the certificate. You can also specify a -crl_reason
option where the reason is one of the following:

unspecified
keyCompromise
CACompromise
affiliationChanged
superseded
cessationOfOperation
certificateHold

Technically another reason, "removeFromCRL" is valid, but unsupported 
in openssl. An example of using one of these would be:

openssl ca -config openssl.cnf -crl_reason superseded -revoke certsdb/5FE840894254A22.pem

The options -crl_compromise and -crl_CA_compromise allow you 
to specify times of compromise and set the crl_reason to 
the respective setting.

Once you've revoked a certificate be sure to update the CRL. 
Instructions on how to do that are below.

Creating CRLs
-------------

CRLs should be created regularly and made available to the users 
of your CA - and their users! CRLs can be created without having 
ever revoked a certificate. However, if you revoke a certificate,
a new CRL should be generated immediately.

To generate a CRL, simply do:

openssl ca -config openssl.cnf -gencrl -out crl.pem

Then provide this CRL in the URL provided in your crlDistributionPoint extension.
*/


/*
var issuer = [{
		name: 'C',
		value: countryName.value
	}, {
		name: 'ST',
		value: stateOrProvinceName.value
	}, {
		name: 'L',
		value: localityName.value
	}, {
		name: 'O',
		value: organizationName.value
	}, {
		name: 'OU',
		value: organizationalUnitName.value
	}, {
		name: 'CN',
		value: commonName.value
	}, {
		name: 'E',
		value: emailAddress.value
	}, {
		name: 'STREET',
		value: streetAddress.value
	}
];

new cert = new jCastle.certificate();
cert.setConfig(cert_config);
cert.setSignKey(sign_key);

var crt_pem = cert.issue(csr_pem, {
	issuer: issuer,
	validity: {
		notBefore: not_before,
		notAfter: not_after,
	},
	issuerUniqueId: iuid,
	subjectUniqueId: suid,
	algo: {
		signAlgo: 'RSASSA-PKCS1-V1_5',
		hashAlgo: 'sha-256'
	}
}, {
	issuerCertificate: issuer_cert, // if exists, then issuer will be the subject of the certificate.
	extentionName: config_ext_name,
	format: 'pem' // default
});

*/
/*
http://superuser.com/questions/692503/incorrect-authority-key-identifier-on-openssl-end-cert

Q:
I have a Root CA which looks like this:

Serial Number: 14296918985177649921 (0xc668dc11960d5301)
Issuer: C=US, ST=xROOTx, L=xROOTx, O=xROOTx, CN=xROOTx
Subject: C=US, ST=xROOTx, L=xROOTx, O=xROOTx, CN=xROOTx
X509v3 Subject Key Identifier:
  1A:E5:27:E9:EF:2F:90:A7:13:91:1A:12:A9:3A:1D:AE:BA:1E:B8:35

Which has signed an intermediate CA which looks like this:

Serial Number: 0 (0x0)
Issuer: C=US, ST=xROOTx, L=xROOTx, O=xROOTx, CN=xROOTx
Subject: C=US, ST=xINTERx, O=xINTERx, CN=xINTERx
X509v3 Authority Key Identifier:
  keyid:1A:E5:27:E9:EF:2F:90:A7:13:91:1A:12:A9:3A:1D:AE:BA:1E:B8:35
  DirName:/C=US/ST=xROOTx/L=xROOTx/O=xROOTx/CN=xROOTx
  serial:C6:68:DC:11:96:0D:53:01
X509v3 Subject Key Identifier:
  16:BF:D6:2F:0D:58:A5:C3:84:95:4B:F6:FE:27:3E:0B:79:0C:6F:04

And when I sign the end-server cert I get this:

Serial Number: 1 (0x1)
Issuer: C=US, ST=xINTERx, O=xINTERx, CN=xINTERx
Subject: C=US, ST=xENDx, O=xENDx, CN=xENDx
X509v3 Authority Key Identifier:
  keyid:16:BF:D6:2F:0D:58:A5:C3:84:95:4B:F6:FE:27:3E:0B:79:0C:6F:04
  DirName:/C=US/ST=xROOTx/L=xROOTx/O=xROOTx/CN=xROOTx
  serial:00
X509v3 Subject Key Identifier:
  3B:86:64:4B:80:EE:BF:92:0D:A9:D6:FD:8C:FD:DD:FF:55:55:C6:11

This shows the correct KeyId and Serial from the intermediate CA
but the wrong DirName, which for some reason is the Root CA's DN.

A:
This is normal behavior.

The DirName in the Authority Key Identifier is actually the Subject name of
the Issuer of the Issuer. Just including the Subject of the Issuer 
would be duplicating the Issuer DN already available in the certificate.

This is a common question that is also answered in the OpenSSL FAQ

https://www.openssl.org/docs/faq.html#USER15

15. Why does OpenSSL set the authority key identifier (AKID) extension incorrectly?  

It doesn't: this extension is often the cause of confusion.

Consider a certificate chain A->B->C so that A signs B and B signs C.
Suppose certificate C contains AKID.

The purpose of this extension is to identify the authority certificate B.
This can be done either by including the subject key identifier of B 
or its issuer name and serial number.

In this latter case because it is identifying certifcate B
it must contain the issuer name and serial number of B.

It is often wrongly assumed that it should contain the subject name of B.
If it did this would be redundant information because it would duplicate the issuer name of C.
*/
/*
	// sign key should be set using setSignKey() 
	// or options should have signKey for self-signing.
	issueSelfSigned(req_info, options)
	{
		var csr_pem = this.request(req_info, 'pem');

		return this.issue(csr_pem, {
			issuer: req_info.subject,
			algo: req_info.algo
		}, options);
	}
*/
	/**
	 * issues a X.509 certificate.
	 * 
	 * @public
	 * 
	 * @param {mixed} csr_pem Certificate Signing Request(CSR) PEM or buffer.
	 * @param {object} issue_info information data object for issuing the certificate.
	 *                 issue_info object can have properties of 'issuer', 'validity'(it has 'notBefore', 'notAfter'),
	 *                 'issuerUniqueID', 'subjectUniqueID', 'extensions',
	 *                 and 'algo' for sign algorithm.
	 * @param {object} options options for issuing certificate.
	 *                     {string} format return type. 'der' | 'buffer' | 'hex' | 'base64' | 'pem'. (default: 'pem')
	 *                     {mixed} signKey pki object or pem for sign key.
	 *                     {string | buffer} password password for signKey
	 *                     {mixed} config certficate config object or string.
	 *                     {mixed} issuerCertificate issuer's certificate object or pem string.
	 *                     {string} extensionName extension name of cert-config object.
	 * 
	 * @returns the X.509 certificate.
	 */
	issue(csr_pem, issue_info, options = {})
	{
		var format = 'format' in options ? options.format.toLowerCase() : 'pem';
		var csr_info;

		if ('signKey' in options) this.setSignKey(options.signKey, options.password);
		if ('config' in options) this.setConfig(options.config);

		if (!this.signKey || !this.signKey.hasPrivateKey()) {
			throw jCastle.exception("PKI_NOT_SET", 'CRT014');
		}

		// before issuing, verify csr
		if (typeof csr_pem == 'object' && 'type' in csr_pem && 'tbs' in csr_pem && 'signature' in csr_pem) {
			csr_info = csr_pem;
		} else {
			// this.parse will erase the data you have set
			//var csr_info = this.parse(csr_pem);
			csr_info = new jCastle.certificate().parse(csr_pem);
		}

		if (csr_info.type != jCastle.certificate.typeCSR) {
			throw jCastle.exception("NOT_CSR", 'CRT015');
		}

		var pub_pki = jCastle.pki.createFromPublicKeyInfo(csr_info.tbs.subjectPublicKeyInfo);

		// try to avoid from using signKey...
		//if (!this.validate(csr_pem, pub_pki)) {
		if (!jCastle.certificate.create().validate(csr_pem, pub_pki)) {
			throw jCastle.exception("VERIFICATION_FAIL", 'CRT016');
		}

		var cert_build = {};
		cert_build.type = jCastle.certificate.typeCRT;

		cert_build.tbs = {};
		cert_build.tbs.version = 2; // default. it can be changed.

		cert_build.tbs.serialNumber = issue_info.serialNumber;
		
		// issuer should be provided. you can get from your own certificate.

		var cert_info;

		if ('issuerCertificate' in options) {
			if (jCastle.util.isString(options.issuerCertificate)) {
				cert_info = new jCastle.certificate().parse(options.issuerCertificate);
			} else {
				cert_info = options.issuerCertificate;
			}

			issue_info.issuer = cert_info.tbs.subject;

			if ('extensionName' in options && this.config && options.extensionName in this.config) {
				if ('authorityKeyIdentifier' in this.config[options.extensionName] &&
					'authorityCertIssuer' in this.config[options.extensionName].authorityKeyIdentifier &&
					(this.config[options.extensionName].authorityKeyIdentifier.authorityCertIssuer == 'always' ||
					!('keyIdentifier' in this.config[options.extensionName].authorityKeyIdentifier))
				) {
					issue_info.authorityCertIssuer = cert_info.tbs.issuer;
					if (this.config[options.extensionName].authorityKeyIdentifier.authorityCertIssuer == 'always') {
						issue_info.authorityCertSerialNumber = cert_info.tbs.serialNumber;
					}
				}
			} else if (this.config && 'ca' in this.config && 'x509_extensions' in this.config.ca.default_ca &&
				typeof this.config.ca.default_ca.x509_extensions == 'object') {
				if ('authorityKeyIdentifier' in this.config.ca.default_ca.x509_extensions &&
					'authorityCertIssuer' in this.config.ca.default_ca.x509_extensions.authorityKeyIdentifier &&
					(this.config.ca.default_ca.x509_extensions.authorityKeyIdentifier.authorityCertIssuer == 'always' ||
					!('keyIdentifier' in this.config.ca.default_ca.x509_extensions.authorityKeyIdentifier))
				) {
					issue_info.authorityCertIssuer = cert_info.tbs.issuer;
					if (this.config.ca.default_ca.x509_extensions.authorityKeyIdentifier.authorityCertIssuer == 'always') {
						issue_info.authorityCertSerialNumber = cert_info.tbs.serialNumber;
					}
				}
			}
		}

		if (!('issuer' in issue_info)) {
			throw jCastle.exception("INVALID_PARAMS", 'CRT017');
		}
		cert_build.tbs.issuer = jCastle.certificate.fn.reviseDirectoryName(issue_info.issuer);

		var validity;
		if ('validity' in issue_info) {
			validity = issue_info.validity;
		} else {
			validity = {};
		}

		if (!('notBefore' in validity)) {
			validity.notBefore = new Date();
		} else if (jCastle.util.isString(validity.notBefore)) {
			validity.notBefore = jCastle.util.str2date(validity.notBefore);
		}
		
		if (!('notAfter' in validity)) {
			var days = 'days' in validity ? validity.days : (
				this.config && 'ca' in this.config && 'default_days' in this.config.ca.default_ca ? this.config.ca.default_ca.default_days : 365
			); // if empty, default is 1 year.
			var curdate = new Date();
			validity.notAfter = new Date(validity.notBefore.getTime() + days * 24 * 60 * 60 * 1000);
		}

		cert_build.tbs.validity = validity;
		cert_build.tbs.subject = jCastle.certificate.fn.reviseDirectoryName(csr_info.tbs.subject);
		cert_build.tbs.subjectPublicKeyInfo = csr_info.tbs.subjectPublicKeyInfo;

		if ('issuerUniqueID' in issue_info) cert_build.tbs.issuerUniqueID = issue_info.issuerUniqueID;
		if ('subjectUniqueID' in issue_info) cert_build.tbs.subjectUniqueID = issue_info.subjectUniqueID;

		// extensions
		var extensions = null;

		if ('extenssionName' in options && this.config && options.extensionName in this.config) {
			extensions = jCastle.util.clone(this.config[options.extensionName]);
		} else if ('extensions' in issue_info) {
			extensions = jCastle.util.clone(issue_info.extensions);
		} else if (jCastle.certificate.fn.isIssuerAndSubjectIdentical(cert_build) &&
			this.config && 'req' in this.config && 'x509_extensions' in this.config.req && typeof this.config.req.x509_extensions == 'object') {
			
			// self-signed.
			if (this.signKey.pkiName != csr_info.tbs.subjectPublicKeyInfo.algo ||
				!this.signKey.publicKeyEquals(csr_info.tbs.subjectPublicKeyInfo.publicKey)) {
				throw jCastle.exception('PKI_NOT_MATCH', 'CRT018');
			}
			
			extensions = jCastle.util.clone(this.config.req.x509_extensions);
		} else if (this.config && 'ca' in this.config && 'x509_extensions' in this.config.ca.default_ca &&
			typeof this.config.ca.default_ca.x509_extensions == 'object') {
			extensions = jCastle.util.clone(this.config.ca.default_ca.x509_extensions);
		} else if (this.config && 'cert_ext' in this.config && typeof this.config.cert_ext == 'object') {
			extensions = jCastle.util.clone(this.config.cert_ext);
		}

		if ('extensionRequest' in csr_info.tbs) {
			if (!extensions) extensions = {};

			for (var ext in csr_info.tbs.extensionRequest) {
				extensions[ext] = csr_info.tbs.extensionRequest[ext];
			}
		}

		if (extensions) {
			cert_build.tbs.extensions = extensions;

			var req_pki = jCastle.pki.createFromPublicKeyInfo(cert_build.tbs.subjectPublicKeyInfo);

			// https://www.openssl.org/docs/faq.html#USER15
			// A signs B, B signs C.
			// then C should have B's subjectKeyIdentifier & B's issuer not B's subject for authorityKeyIdentifier.
			// because of that we need authorityCertIssuer

			jCastle.certificate.fn.transformConfigExtensions(cert_build, this.config, req_pki, this.signKey, issue_info);
		}

		// sign algorithm
		var algo = {
			signAlgo: issue_info.algo.signAlgo ? issue_info.algo.signAlgo : this.signKey.pkiName,
			signHash: issue_info.algo.signHash ? issue_info.algo.signHash : (
				this.config && 'ca' in this.config && 'default_md' in this.config.ca.default_ca ? this.config.ca.default_ca.default_md : 'sha-1'
			)
		};

	//	if (algo.signAlgo == 'EC') algo.signAlgo = 'ECDSA';
		if (algo.signAlgo == 'RSA') algo.signAlgo = 'RSASSA-PKCS1-V1_5';

		if (!jCastle.certificate.fn.isSignAlgoSameWithPKI(algo.signAlgo, this.signKey)) {
			throw jCastle.exception("SIGN_ALGO_MISMATCH", 'CRT019');
		}

		cert_build.algo = algo;

		// if it is self-signed then...
		if (cert_build.type == jCastle.certificate.typeCRT &&
			jCastle.certificate.fn.isIssuerAndSubjectIdentical(cert_build)
		) {
			// we need cRLSign bit for keyUsage, when the certificate is self-signed
			if (!('extensions' in cert_build.tbs)) cert_build.tbs.extensions = {};
			if (!('keyUsage' in cert_build.tbs.extensions)) {
				cert_build.tbs.extensions.keyUsage = {};
				cert_build.tbs.extensions.keyUsage.list = [];
			}
			if (!jCastle.util.inArray('cRLSign', cert_build.tbs.extensions.keyUsage.list)) {
				cert_build.tbs.extensions.keyUsage.list.push('cRLSign');
			}
		}

		// check the pki and extension
		var ext;

		if (cert_build.type == jCastle.certificate.typeCRT) { 
			switch (cert_build.algo.signAlgo) {
				case 'RSASSA-PKCS1-V1_5':
					if ('padding' in cert_build.tbs.subjectPublicKeyInfo && 
						'mode' in cert_build.tbs.subjectPublicKeyInfo.padding &&
						(cert_build.tbs.subjectPublicKeyInfo.padding.mode.toUpperCase() == 'PKCS1_OAEP' ||
						cert_build.tbs.subjectPublicKeyInfo.padding.mode.toUpperCase() == 'RSAES-OAEP')
					) {
						cert_build.tbs.subjectPublicKeyInfo.padding.mode = 'RSAES-OAEP';

						if (!('extensions' in cert_build.tbs)) cert_build.tbs.extensions = {};
						ext = cert_build.tbs.extensions;

						if (!('keyUsage' in ext)) {
							ext.keyUsage = {
								list: ['dataEncipherment']
							};
						} else {
							if (!jCastle.util.inArray('keyEncipherment', ext.keyUsage.list) &&
								!jCastle.util.inArray('dataEncipherment', ext.keyUsage.list)
							) {
								ext.keyUsage.list.push('dataEncipherment');
							}
						}
					}
					break;
				case 'RSA-PSS':
					cert_build.algo.signAlgo = 'RSASSA-PSS';
				case 'RSASSA-PSS':
					if (!('saltLength' in cert_build.algo)) cert_build.algo.saltLength = -1;

					if (!('extensions' in cert_build.tbs)) cert_build.tbs.extensions = {};
					ext = cert_build.tbs.extensions;

					if (!('keyUsage' in ext)) {
						ext.keyUsage = {
							list: ['contentCommitment', 'digitalSignature']
						};
					} else {
						if (!jCastle.util.inArray('contenCommitment', ext.keyUsage.list) &&
							!jCastle.util.inArray('nonRepudiation', ext.keyUsage.list)
						) {
							ext.keyUsage.list.push('contenCommitment');
						}
						if (!jCastle.util.inArray('digitalSignature', ext.keyUsage.list)) {
							ext.keyUsage.list.push('digitalSignature');
						}
					}
					break;
				case 'DSA':
				case 'ECDSA':
				case 'KCDSA':
				case 'ECKCDSA':
				case 'ELGAMAL':
					break;
				default:
					throw jCastle.exception("UNSUPPORTED_PKI", 'CRT020');
			}
		}

		return this.exportCertificate(cert_build, format);
	}

/*
5.1.  CRL Fields

   The X.509 v2 CRL syntax is as follows.  For signature calculation,
   the data that is to be signed is ASN.1 DER encoded.  ASN.1 DER
   encoding is a tag, length, value encoding system for each element.

   CertificateList  ::=  SEQUENCE  {
        tbsCertList          TBSCertList,
        signatureAlgorithm   AlgorithmIdentifier,
        signatureValue       BIT STRING  }

   TBSCertList  ::=  SEQUENCE  {
        version                 Version OPTIONAL,
                                     -- if present, MUST be v2
        signature               AlgorithmIdentifier,
        issuer                  Name,
        thisUpdate              Time,
        nextUpdate              Time OPTIONAL,
        revokedCertificates     SEQUENCE OF SEQUENCE  {
             userCertificate         CertificateSerialNumber,
             revocationDate          Time,
             crlEntryExtensions      Extensions OPTIONAL
                                      -- if present, version MUST be v2
                                  }  OPTIONAL,
        crlExtensions           [0]  EXPLICIT Extensions OPTIONAL
                                      -- if present, version MUST be v2
                                  }

   -- Version, Time, CertificateSerialNumber, and Extensions
   -- are all defined in the ASN.1 in Section 4.1

   -- AlgorithmIdentifier is defined in Section 4.1.1.2
*/
/*
CRLReason ::= ENUMERATED {
        unspecified             (0),
        keyCompromise           (1),
        cACompromise            (2),
        affiliationChanged      (3),
        superseded              (4),
        cessationOfOperation    (5),
        certificateHold         (6),
             -- value 7 is not used
        removeFromCRL           (8),
        privilegeWithdrawn      (9),
        aACompromise           (10) }
*/
/*

new cert = new jCastle.certificate();
cert.setConfig(cert_config);
cert.setSignKey(sign_key);

var revoked_cert_list = [
	{
		userCertificate: serial,
		revocationDate: "2013-02-18 10:22:12 UTC",
		crlEntryExtensions: {
			cRLReason: "affiliationChanged",
			invalidityDate: "2013-02-18 10:22:00 UTC"
		}
	},
	{
		userCertificate: serial,
		revocationDate: "2013-02-18 10:22:22 UTC",
		crlEntryExtensions: {
			cRLReason: "certificateHold",
			invalidityDate: "2013-02-18 10:22:00 UTC"
		}
	},
	{
		userCertificate: serial,
		revocationDate: "2013-02-18 10:22:32 UTC",
		crlEntryExtensions: {
			cRLReason: "superseded",
			invalidityDate: "2013-02-18 10:22:00 UTC"
		}
	},
	{
		userCertificate: serial,
		revocationDate: "2013-02-18 10:22:42 UTC",
		crlEntryExtensions: {
			cRLReason: "keyCompromise",
			invalidityDate: "2013-02-18 10:22:00 UTC"
		}
	},
	{
		userCertificate: serial,
		revocationDate: "2013-02-18 10:22:51 UTC",
		crlEntryExtensions: {
			cRLReason: "cessationOfOperation",
			invalidityDate: "2013-02-18 10:22:00 UTC"
		}
	}
];

var crl_pem = cert.revoke(revoked_cert_list, {
	issuer: issuer,
	thisUpdate: tu,
	nextUpdate: nu,
	algo: {
		signAlgo: 'RSASSA-PKCS1-V1_5',
		hashAlgo: 'sha-256'
	}
}, {
	issuerCertificate: issuer_cert, // if exists then issuer should be subject of the certificate.
	signKey: issuer_signKey, // or use .setSignKey()
	config: cert_config, // or use .setConfig()
	extensionName: config_ext_name,
	format: 'pem' // default
});
*/
	// Certificate Revocation List
	/**
	 * issues certificate revocation list(CRL)
	 * 
	 * @public
	 * 
	 * @param {array} revoked_list arrays of revoked certificate list. each crl item includes
	 *                'userCertificate', 'revocationDate' and 'crlEntryExtensions'.
	 * @param {object} revoke_info the information data for CRL. it includes
	 *                 'issuer', 'thisUpdate', 'nextUpdate', 'algo'.
	 * @param {object} options options for issuing CRL.
	 *                     {string} format return type. 'der' | 'buffer' | 'hex' | 'base64' | 'pem'. (default: 'pem')
	 *                     {mixed} signKey pki object or pem for sign key.
	 *                     {string | buffer} password password for signKey
	 *                     {mixed} config certficate config object or string.
	 *                     {mixed} issuerCertificate issuer's certificate object or pem string.
	 *                     {string} extensionName extension name of cert-config object.
	 * 
	 * @returns the crl pem string or buffer.
	 */
	revoke(revoked_list, revoke_info, options = {})
	{
		var format = 'format' in options ? options.format.toLowerCase() : 'pem';

		if ('signKey' in options) this.setSignKey(options.signKey, options.password);
		if ('config' in options) this.setConfig(options.config);

		if (!this.signKey || !this.signKey.hasPrivateKey()) {
			throw jCastle.exception("PKI_NOT_SET", 'CRT021');
		}
		
		var crl_build = {};
		crl_build.type = jCastle.certificate.typeCRL;

		crl_build.tbs = {};
		crl_build.tbs.version = 2; // default. it can be changed.
		
		// issuer should be provided. you can get from your own certificate.
		var cert_info;

		if ('certificate' in options) {
			if (jCastle.util.isString(options.certificate)) {
				cert_info = new jCastle.certificate().parse(options.certificate);
			} else {
				cert_info = options.certificate;
			}

			revoke_info.issuer = cert_info.tbs.subject;

			if ('extensionName' in options && this.config && options.extensionName in this.config) {
				if ('authorityKeyIdentifier' in this.config[options.extensionName] &&
					'authorityCertIssuer' in this.config[options.extensionName].authorityKeyIdentifier &&
					(this.config[options.extensionName].authorityKeyIdentifier.authorityCertIssuer == 'always' ||
					!('keyIdentifier' in this.config[options.extensionName].authorityKeyIdentifier))
				) {
					revoke_info.authorityCertIssuer = cert_info.tbs.issuer;
					if (this.config[options.extensionName].authorityKeyIdentifier.authorityCertIssuer == 'always') {
						revoke_info.authorityCertSerialNumber = cert_info.tbs.serialNumber;
					}
				}
			} else if (this.config && 'crl_extensions' in this.config.ca.default_ca &&
				typeof this.config.ca.default_ca.crl_extensions == 'object') {
				if ('authorityKeyIdentifier' in this.config.ca.default_ca.crl_extensions &&
					'authorityCertIssuer' in this.config.ca.default_ca.crl_extensions.authorityKeyIdentifier &&
					(this.config.ca.default_ca.crl_extensions.authorityKeyIdentifier.authorityCertIssuer == 'always' ||
					!('keyIdentifier' in this.config.ca.default_ca.crl_extensions.authorityKeyIdentifier))
				) {
					revoke_info.authorityCertIssuer = cert_info.tbs.issuer;
					if (this.config.ca.default_ca.crl_extensions.authorityKeyIdentifier.authorityCertIssuer == 'always') {
						revoke_info.authorityCertSerialNumber = cert_info.tbs.serialNumber;
					}
				}
			}
		}

		crl_build.tbs.issuer = jCastle.certificate.fn.reviseDirectoryName(revoke_info.issuer);

		if ('thisUpdate' in revoke_info) {
			if (jCastle.util.isString(revoke_info.thisUpdate)) {
				crl_build.tbs.thisUpdate = jCastle.util.str2date(revoke_info.thisUpdate);			
			} else {
				crl_build.tbs.thisUpdate = revoke_info.thisUpdate;
			}
		} else {
			crl_build.tbs.thisUpdate = new Date();
		}

		if ('nextUpdate' in revoke_info) {
			if (jCastle.util.isString(revoke_info.nextUpdate)) {
				crl_build.tbs.nextUpdate = jCastle.util.str2date(revoke_info.nextUpdate);			
			} else {
				crl_build.tbs.nextUpdate = revoke_info.nextUpdate;
			}
		} else{
			var default_crl_days = (this.config && 'ca' in this.config && 
			'default_crl_days' in this.config.ca.default_ca && this.config.ca.default_ca.default_crl_days) ? this.config.ca.default_ca.default_crl_days : 30;

			crl_build.tbs.nextUpdate = new Date(crl_build.tbs.thisUpdate.getTime() + default_crl_days * 24 * 60 * 60 * 1000);
		}

		// revokedCertificates
		crl_build.tbs.revokedCertificates = jCastle.certificate.fn.reviseRevokedCertificates(revoked_list);

		// extensions
		var extensions = null;

		if ('extensionName' in options && this.config && options.extensionName in this.config) {
			extensions = jCastle.util.clone(this.config[options.extensionName]);
		} else if ('extensions' in revoke_info) {
			extensions = jCastle.util.clone(revoke_info.extensions);
		} else if (this.config && 'crl_extensions' in this.config.ca.default_ca && typeof this.config.ca.default_ca.crl_extensions == 'object') {
			extensions = jCastle.util.clone(this.config.ca.default_ca.crl_extensions);
		} else if (this.config && 'crl_ext' in this.config && typeof this.config.crl_ext == 'object') {
			extensions = jCastle.util.clone(this.config.crl_ext);
		}

		if (extensions) {
			crl_build.tbs.crlExtensions = extensions;

			// https://www.openssl.org/docs/faq.html#USER15
			// A signs B, B signs C.
			// then C should have B's subjectKeyIdentifier & B's issuer not B's subject for authorityKeyIdentifier.
			// because of that we need authorityCertIssuer

			jCastle.certificate.fn.transformConfigExtensions(crl_build, this.config, this.signKey, this.signKey, revoke_info);
		}

		// sign algorithm
		var algo = {
			signAlgo: revoke_info.algo.signAlgo ? revoke_info.algo.signAlgo : this.signKey.pkiName,
			signHash: revoke_info.algo.signHash ? revoke_info.algo.signHash : (
				this.config && 'default_md' in this.config.ca.default_ca ? this.config.ca.default_ca.default_md : 'sha-1'
			)
		};

	//	if (algo.signAlgo == 'EC') algo.signAlgo = 'ECDSA';
		if (algo.signAlgo == 'RSA') algo.signAlgo = 'RSASSA-PKCS1-V1_5';


		if (!jCastle.certificate.fn.isSignAlgoSameWithPKI(algo.signAlgo, this.signKey)) {
			throw jCastle.exception("SIGN_ALGO_MISMATCH", 'CRT022');
		}

		crl_build.algo = algo;



		return this.exportCertificate(crl_build, format);
	}

	/**
	 * issues certificate according to the cert_info object.
	 * 
	 * @public
	 * 
	 * @param {object} cert_info certificate structure object for issuing a certificate.
	 * @param {mixed} options options object or format string.
	 *                     {string} format return type. 'der' | 'buffer' | 'hex' | 'base64' | 'pem'. (default: 'pem')
	 *                     {mixed} signKey pki object or pem for sign key.
	 *                     {string | buffer} password password for signKey
	 *                     {mixed} config certficate config object or string.
	 * @param {boolean} reuseSignature if true and a signature is given inside cert_info,
	 *                                 then the signature is used again.
	 *                                 this is for the test to see that the signature building is alright.
	 * 
	 * @returns the certificate pem string or buffer.
	 */
	exportCertificate(cert_info, options = {}, reuseSignature = false)
	{
		if (jCastle.util.isString(options)) options = { format: options };

		var format = 'format' in options ? options.format.toLowerCase() : 'pem';
		if ('signKey' in options) this.setSignKey(options.signKey, options.password);
		if ('config' in options) this.setConfig(options.config);

		if (!reuseSignature && (!this.signKey || !this.signKey.hasPrivateKey())) {
			throw jCastle.exception("PKI_NOT_SET", 'CRT023');
		}

		var asn1 = new jCastle.asn1();
		var der = asn1.getDER(this._getCertificateSchema(cert_info, this.signKey, reuseSignature));
		var buf = Buffer.from(der, 'latin1');
		var format_str = '';

		switch (format) {
			case 'der':
				//return buf.toString('latin1');
				return der;
			case 'buffer':
				return buf;
			case 'pem':
				switch (cert_info.type) {
					case jCastle.certificate.typeCRT:
						format_str = 'CERTIFICATE'; break;
					case jCastle.certificate.typeCSR:
						format_str = 'CERTIFICATE REQUEST'; break;
					case jCastle.certificate.typeCRL:
						format_str = 'X509 CRL'; break;
					default:
						throw jCastle.exception("UNSUPPORTED_CERT_TYPE", 'CRT024');
				}

				return "-----BEGIN " + format_str + "-----\n" + 
					jCastle.util.lineBreak(buf.toString('base64'), 64) +
					"\n-----END " + format_str + "-----";
			default: 
				return buf.toString(format);
		}
	}

	/**
	 * alias function of exportCertificate()
	 * @public
	 * 
	 * @param {object} cert_info certificate structure object for issuing a certificate.
	 * @param {mixed} options options object or format string.
	 *                     {string} format return type. 'der' | 'buffer' | 'hex' | 'base64' | 'pem'. (default: 'pem')
	 *                     {mixed} signKey pki object or pem for sign key.
	 *                     {mixed} config certficate config object or string.
	 * @param {boolean} reuseSignature if true and a signature is given inside cert_info,
	 *                                 then the signature is used again.
	 *                                 this is for the test to see that the signature building is alright.
	 * 
	 * @returns the certificate pem string or buffer.
	 */
	export(cert_info, options = {}, reuseSignature = false)
	{
		return this.exportCertificate(cert_info, options, reuseSignature);
	}

	/**
	 * verifies the certificate pem.
	 * 
	 * @public
	 * 
	 * @param {string} pem certificate pem string or buffer.
	 * @param {object} pub_pki if pub_pki is given then it will be the signKey. 
	 *                 if not given then subjectPublicKeyInfo inside the certificate is used.
	 * @param {string} format certificate format.
	 * 
	 * @returns true if the certificate signature is right.
	 */
	verify(pem, pub_pki = null, format = 'auto')
	{
		var cert_info;

		if (!pem && this.certInfo) {
			cert_info = this.certInfo;
		} else {
			cert_info = new jCastle.certificate().parse(pem, format);
		}

		var verifying_pkey;

		// if pub_pki is provided then use it.
		// if not then check if this.signKey is set, if set then use it.
		// if not then extract one from the pem.

		if (pub_pki) {
			if (jCastle.util.isString(pub_pki)) {
				// certificate pem that signed the certificate that are to be verified
				var signing_cert_info = new jCastle.certificate().parse(pub_pki);
				verifying_pkey = jCastle.pki.createFromPublicKeyInfo(signing_cert_info.tbs.subjectPublicKeyInfo);
			} else {
				verifying_pkey = jCastle.pki.create().init(pub_pki);
			}
		} else {
			if (this.signKey && this.signKey.hasPublicKey()) {
				verifying_pkey = this.signKey;
			} else {
				verifying_pkey = jCastle.pki.createFromPublicKeyInfo(cert_info.tbs.subjectPublicKeyInfo);
			}
		}

		switch (cert_info.algo.signAlgo) {
			case 'RSASSA-PSS':
				return verifying_pkey.pssVerify(cert_info.tbs.buffer, cert_info.signature, {
					hashAlgo: cert_info.algo.signHash,
					saltLength: cert_info.algo.saltLength
				});
			case 'RSASSA-PKCS1-V1_5':
			case 'DSA':
			case 'KCDSA':
			case 'ECDSA':
			case 'ECKCDSA':
			case 'ELGAMAL':
				return verifying_pkey.verify(cert_info.tbs.buffer, cert_info.signature, {
					hashAlgo: cert_info.algo.signHash
				});
			default:
				throw jCastle.exception("UNSUPPORTED_PKI", 'CRT025');
		}
	}

	/**
	 * check whether the pem is valid in date and not in crl pem.
	 * 
	 * @public
	 * 
	 * @param {string} pem pem string or buffer
	 * @param {string} crl_pem crl pem string or buffer
	 * 
	 * @returns true if the pem's date is ok and it is not in crl pem.
	 */
	isValid(pem, crl_pem)
	{
		var cert_info, crl_info, serial, not_before, not_after, current;
		var cert = new jCastle.certificate();

		if (jCastle.util.isString(pem)) {
			cert_info = cert.parse(pem);
		} else {
			cert_info = pem;
		}

		// check date validity
		not_after = jCastle.util.isString(cert_info.tbs.validity.notAfter) ? 
			jCastle.util.str2date(cert_info.tbs.validity.notAfter).getTime() : cert_info.tbs.validity.notAfter.getTime();
		not_before = jCastle.util.isString(cert_info.tbs.validity.notBefore) ?
			jCastle.util.str2date(cert_info.tbs.validity.notBefore).getTime() : cert_info.tbs.validity.notBefore.getTime();
		current = new Date().getTime();

		if (current > not_after) return false;
		if (current < not_before) return false;

		// check if the certificate is in CRL
		if (!crl_pem) return true;

		if (jCastle.util.isString(crl_pem)) {
			crl_info = cert.parse(crl_pem);
		} else {
			crl_info = crl_pem;
		}

		serial = BigInt.is(cert_info.tbs.serialNumber) ? cert_info.tbs.serialNumber : (
			typeof cert_info.tbs.serialNumber == 'number' ? BigInt(cert_info.tbs.serialNumber) : (
				/^[0-9A-F]+$/i.test(cert_info.tbs.serialNumber) ? 
					BigInt('0x' + cert_info.tbs.serialNumber) : BigInt.fromBuffer(Buffer.from(cert_info.tbs.serialNumber, 'latin1'))
			)
		);

		for (var i = 0; i < crl_info.tbs.revokedCertificates.length; i++) {
			var revoked = crl_info.tbs.revokedCertificates[i];
			var revoked_serial = BigInt.is(revoked.userCertificate) ? revoked.userCertificate : (
				typeof revoked.userCertificate == 'number' ? BigInt(revoked.userCertificate) : (
					/^[0-9A-F]+$/i.test(revoked.userCertificate) ?
						BigInt('0x' + revoked.userCertificate) : BigInt.fromBuffer(Buffer.from(revoked.userCertificate, 'latin1'))
				)
			);
			if (serial.equals(revoked_serial)) return false;
		}

		return true;
	}

	/*********************
	 * Private functions *
	 *********************/

	/**
	 * parses tbs of the crl certificate.
	 * 
	 * @private
	 * 
	 * @param {object} sequence asn1 sequence object.
	 * 
	 * @returns the crl tbs object.
	 */
	_parseCrlTbsCertificate(sequence)
	{
/*
   CertificateList  ::=  SEQUENCE  {
        tbsCertList          TBSCertList,
        signatureAlgorithm   AlgorithmIdentifier,
        signatureValue       BIT STRING  }

   TBSCertList  ::=  SEQUENCE  {
        version                 Version OPTIONAL,
                                     -- if present, MUST be v2
        signature               AlgorithmIdentifier,
        issuer                  Name,
        thisUpdate              Time,
        nextUpdate              Time OPTIONAL,
        revokedCertificates     SEQUENCE OF SEQUENCE  {
             userCertificate         CertificateSerialNumber,
             revocationDate          Time,
             crlEntryExtensions      Extensions OPTIONAL
                                      -- if present, version MUST be v2
                                  }  OPTIONAL,
        crlExtensions           [0]  EXPLICIT Extensions OPTIONAL
                                      -- if present, version MUST be v2
                                  }

   -- Version, Time, CertificateSerialNumber, and Extensions
   -- are all defined in the ASN.1 in Section 4.1

   -- AlgorithmIdentifier is defined in Section 4.1.1.2
*/
		var tbs_info = {};

		// tbs_info.der = sequence.der;
		tbs_info.buffer = sequence.buffer;

		var idx = 0;
		var obj = sequence.items[idx++];

/*
5.1.2.1.  Version

   This optional field describes the version of the encoded CRL.  When
   extensions are used, as required by this profile, this field MUST be
   present and MUST specify version 2 (the integer value is 1).
*/
		// version
		if (obj.type == jCastle.asn1.tagInteger) {
			//tbs_info.version = parseInt(jCastle.encoding.hex.encode(obj.value), 16);
			//tbs_info.version = obj.value.charCodeAt(0);
			tbs_info.version = obj.intVal;

			obj = sequence.items[idx++];
		}

/*
SEQUENCE(3 elem)
	SEQUENCE(7 elem)
		INTEGER											1
		SEQUENCE(2 elem)
			OBJECT IDENTIFIER							1.2.840.113549.1.1.5 -- sha1WithRSAEncryption
			NULL
		SEQUENCE(3 elem)
			SET(1 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER					2.5.4.10
					PrintableString						Sample Signer Organization
			SET(1 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER					2.5.4.11
					PrintableString						Sample Signer Unit
			SET(1 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER					2.5.4.3
					PrintableString						Sample Signer Cert
		UTCTime											2013-02-18 10:32:00 UTC
		UTCTime											2013-02-18 10:42:00 UTC
		SEQUENCE(5 elem)
			SEQUENCE(3 elem)
				INTEGER									1341767
				UTCTime									2013-02-18 10:22:12 UTC
				SEQUENCE(2 elem)
					SEQUENCE(2 elem)
						OBJECT IDENTIFIER				2.5.29.21 -- cRLReason
						OCTET STRING(1 elem)
							ENUMERATED
					SEQUENCE(2 elem)
						OBJECT IDENTIFIER				2.5.29.24 -- invalidityDate
						OCTET STRING(1 elem)
							GeneralizedTime				2013-02-18 10:22:00 UTC
*/

/*
5.1.2.2.  Signature

   This field contains the algorithm identifier for the algorithm used
   to sign the CRL.  [RFC3279], [RFC4055], and [RFC4491] list OIDs for
   the most popular signature algorithms used in the Internet PKI.

   This field MUST contain the same algorithm identifier as the
   signatureAlgorithm field in the sequence CertificateList (Section
   5.1.1.2).
*/
		if (obj.type == jCastle.asn1.tagSequence && obj.items[0].type == jCastle.asn1.tagOID) {
			tbs_info.algo = jCastle.certificate.asn1.signAlgorithm.parse(obj);

			obj = sequence.items[idx++];
		}			

/*
5.1.2.3.  Issuer Name

   The issuer name identifies the entity that has signed and issued the
   CRL.  The issuer identity is carried in the issuer field.
   Alternative name forms may also appear in the issuerAltName extension
   (Section 5.2.2).  The issuer field MUST contain a non-empty X.500
   distinguished name (DN).  The issuer field is defined as the X.501
   type Name, and MUST follow the encoding rules for the issuer name
   field in the certificate (Section 4.1.2.4).
*/
		if (obj.type == jCastle.asn1.tagSequence && 
			obj.items[0].type == jCastle.asn1.tagSet
		) {
			tbs_info.issuer = jCastle.certificate.asn1.directoryName.parse(obj);

			obj = sequence.items[idx++];
		}
/*
5.1.2.4.  This Update

   This field indicates the issue date of this CRL.  thisUpdate may be
   encoded as UTCTime or GeneralizedTime.

   CRL issuers conforming to this profile MUST encode thisUpdate as
   UTCTime for dates through the year 2049.  CRL issuers conforming to

   this profile MUST encode thisUpdate as GeneralizedTime for dates in
   the year 2050 or later.  Conforming applications MUST be able to
   process dates that are encoded in either UTCTime or GeneralizedTime.

   Where encoded as UTCTime, thisUpdate MUST be specified and
   interpreted as defined in Section 4.1.2.5.1.  Where encoded as
   GeneralizedTime, thisUpdate MUST be specified and interpreted as
   defined in Section 4.1.2.5.2.
*/
		if (obj.type == jCastle.asn1.tagUTCTime) {
			tbs_info.thisUpdate = obj.value;

			obj = sequence.items[idx++];
		}
/*
5.1.2.5.  Next Update

   This field indicates the date by which the next CRL will be issued.
   The next CRL could be issued before the indicated date, but it will
   not be issued any later than the indicated date.  CRL issuers SHOULD
   issue CRLs with a nextUpdate time equal to or later than all previous
   CRLs.  nextUpdate may be encoded as UTCTime or GeneralizedTime.

   Conforming CRL issuers MUST include the nextUpdate field in all CRLs.
   Note that the ASN.1 syntax of TBSCertList describes this field as
   OPTIONAL, which is consistent with the ASN.1 structure defined in
   [X.509].  The behavior of clients processing CRLs that omit
   nextUpdate is not specified by this profile.

   CRL issuers conforming to this profile MUST encode nextUpdate as
   UTCTime for dates through the year 2049.  CRL issuers conforming to
   this profile MUST encode nextUpdate as GeneralizedTime for dates in
   the year 2050 or later.  Conforming applications MUST be able to
   process dates that are encoded in either UTCTime or GeneralizedTime.

   Where encoded as UTCTime, nextUpdate MUST be specified and
   interpreted as defined in Section 4.1.2.5.1.  Where encoded as
   GeneralizedTime, nextUpdate MUST be specified and interpreted as
   defined in Section 4.1.2.5.2.
*/
		if (obj.type == jCastle.asn1.tagUTCTime) {
			tbs_info.nextUpdate = obj.value;

			obj = sequence.items[idx++];
		}
/*
5.1.2.6.  Revoked Certificates

   When there are no revoked certificates, the revoked certificates list
   MUST be absent.  Otherwise, revoked certificates are listed by their
   serial numbers.  Certificates revoked by the CA are uniquely
   identified by the certificate serial number.  The date on which the
   revocation occurred is specified.  The time for revocationDate MUST
   be expressed as described in Section 5.1.2.4.  Additional information
   may be supplied in CRL entry extensions; CRL entry extensions are
   discussed in Section 5.3.
*/
		if (obj.type == jCastle.asn1.tagSequence) {
			tbs_info.revokedCertificates = jCastle.certificate.asn1.revokedCerts.parse(obj);

			obj = sequence.items[idx++];
		}
/*
5.1.2.7.  Extensions

   This field may only appear if the version is 2 (Section 5.1.2.1).  If
   present, this field is a sequence of one or more CRL extensions.  CRL
   extensions are discussed in Section 5.2.
*/
		// extensions
		if (typeof obj != 'undefined' && 
			obj.tagClass == jCastle.asn1.tagClassContextSpecific &&
			obj.type == 0x00
		) {
			var extensions = this._parseExtensions(obj.items[0]);
			tbs_info.crlExtensions = extensions;
		}

		return tbs_info;
	}

	/**
	 * parses tbs of csr certificate.
	 * 
	 * @private
	 * 
	 * @param {object} sequence asn1 sequence object 
	 * 
	 * @returns the csr tbs object.
	 */
	_parseCsrTbsCertificate(sequence)
	{
		var tbs_info = {};
		// tbs_info.der = sequence.der;
		tbs_info.buffer = sequence.buffer;

		var idx = 0;
		var obj = sequence.items[idx++];

		// version
		if (obj.type == jCastle.asn1.tagInteger) {
			//tbs_info.version = parseInt(jCastle.encoding.hex.encode(obj.value), 16);
			//tbs_info.version = obj.value.charCodeAt(0);
			tbs_info.version = obj.intVal;

			obj = sequence.items[idx++];
		}

		// subject
		if (obj.type == jCastle.asn1.tagSequence && 
			obj.items[0].type == jCastle.asn1.tagSet
		) {
			tbs_info.subject = jCastle.certificate.asn1.directoryName.parse(obj);

			obj = sequence.items[idx++];
		}

		// public key info
		var publicKeyInfo = jCastle.certificate.asn1.publicKeyInfo.parse(obj);
		tbs_info.subjectPublicKeyInfo = publicKeyInfo;
		obj = sequence.items[idx++];

		// extensions
		if (typeof obj != 'undefined' && 
			obj.tagClass == jCastle.asn1.tagClassContextSpecific &&
			obj.type == 0x00
		) {
/*
extensionRequest can be empty!

[0]

or 

[0](1 elem)
	SEQUENCE(2 elem)
		OBJECT IDENTIFIER					1.2.840.113549.1.9.14 -- extensionRequest
		SET(1 elem)
			SEQUENCE(1 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER		2.5.29.17 -- subjectAltName
					OCTET STRING(1 elem)
						SEQUENCE(1 elem)
							[2]				client.example.com
*/
/*
[0](1 elem)
	SEQUENCE(2 elem)
		OBJECT IDENTIFIER					1.2.840.113549.1.9.7 -- challengePassword
		SET(1 elem)
			UTF8String						password
*/
			if (obj.items.length) {
				for (var s = 0; s < obj.items.length; s++) {
					switch (jCastle.oid.getName(obj.items[s].items[0].value)) {
						case "extensionRequest":	
							var extensionRequest = this._parseExtensions(obj.items[s].items[1].items[0]);
							tbs_info.extensionRequest = extensionRequest;
							break;
						case "challengePassword":
							tbs_info.challengePassword = obj.items[s].items[1].items[0].value;
							break;
						default:
							throw jCastle.exception("UNSUPPORTED_EXTENSION", 'CRT026');

					}
				}
			}
		}
		
		return tbs_info;
	}

	/**
	 * parses certificate tbs.
	 * 
	 * @private
	 * 
	 * @param {object} sequence asn1 sequence object
	 * 
	 * @returns the certificate tbs object.
	 */
	_parseTbsCertificate(sequence)
	{
		var tbs_info = {};
		var issuer_flag = false;

		// tbs_info.der = sequence.der;
		tbs_info.buffer = sequence.buffer;



		var idx = 0;
		var obj = sequence.items[idx++];
/*
4.1.2.  TBSCertificate

   The sequence TBSCertificate contains information associated with the
   subject of the certificate and the CA that issued it.  Every
   TBSCertificate contains the names of the subject and issuer, a public
   key associated with the subject, a validity period, a version number,
   and a serial number; some MAY contain optional unique identifier
   fields.  The remainder of this section describes the syntax and
   semantics of these fields.  A TBSCertificate usually includes
   extensions.  Extensions for the Internet PKI are described in Section
   4.2.

4.1.2.1.  Version

   This field describes the version of the encoded certificate.  When
   extensions are used, as expected in this profile, version MUST be 3
   (value is 2).  If no extensions are present, but a UniqueIdentifier
   is present, the version SHOULD be 2 (value is 1); however, the
   version MAY be 3.  If only basic fields are present, the version
   SHOULD be 1 (the value is omitted from the certificate as the default
   value); however, the version MAY be 2 or 3.

   Implementations SHOULD be prepared to accept any version certificate.
   At a minimum, conforming implementations MUST recognize version 3
   certificates.

   Generation of version 2 certificates is not expected by
   implementations based on this profile.
*/
/*
[0](1 elem)
	INTEGER		2 -- version
*/
		// version
		if (obj.tagClass == jCastle.asn1.tagClassContextSpecific &&
			obj.type == 0x00 && obj.items[0].type == jCastle.asn1.tagInteger
		) {
			//tbs_info.version = parseInt(jCastle.encoding.hex.encode(obj.items[0].value), 16);
			//tbs_info.version = obj.items[0].value.charCodeAt(0);
			tbs_info.version = obj.items[0].intVal;

			obj = sequence.items[idx++];
		}
/*
4.1.2.2.  Serial Number

   The serial number MUST be a positive integer assigned by the CA to
   each certificate.  It MUST be unique for each certificate issued by a
   given CA (i.e., the issuer name and serial number identify a unique
   certificate).  CAs MUST force the serialNumber to be a non-negative
   integer.

   Given the uniqueness requirements above, serial numbers can be
   expected to contain long integers.  Certificate users MUST be able to
   handle serialNumber values up to 20 octets.  Conforming CAs MUST NOT
   use serialNumber values longer than 20 octets.

   Note: Non-conforming CAs may issue certificates with serial numbers
   that are negative or zero.  Certificate users SHOULD be prepared to
   gracefully handle such certificates.
*/
		// serial number
		if (obj.type == jCastle.asn1.tagInteger) {
			//tbs_info.serialNumber = parseInt(jCastle.encoding.hex.encode(obj.value), 16);
			//tbs_info.serialNumber = BigInt.fromBuffer(Buffer.from(obj.value, 'latin1'));
			tbs_info.serialNumber = obj.intVal;

			// console.log('parsed serial number: ', tbs_info.serialNumber.toString());
			// console.log('val: ', Buffer.from(obj.value, 'latin1').toString('hex'));

			obj = sequence.items[idx++];
		}
/*
4.1.2.3.  Signature

   This field contains the algorithm identifier for the algorithm used
   by the CA to sign the certificate.

   This field MUST contain the same algorithm identifier as the
   signatureAlgorithm field in the sequence Certificate (Section
   4.1.1.2).  The contents of the optional parameters field will vary
   according to the algorithm identified.  [RFC3279], [RFC4055], and
   [RFC4491] list supported signature algorithms, but other signature
   algorithms MAY also be supported.
*/
		if (obj.type == jCastle.asn1.tagSequence && obj.items[0].type == jCastle.asn1.tagOID) {
			tbs_info.algo = jCastle.certificate.asn1.signAlgorithm.parse(obj);

			obj = sequence.items[idx++];
		}			

/*
4.1.2.4.  Issuer

   The issuer field identifies the entity that has signed and issued the
   certificate.  The issuer field MUST contain a non-empty distinguished
   name (DN).  The issuer field is defined as the X.501 type Name
   [X.501].  Name is defined by the following ASN.1 structures:

   Name ::= CHOICE { -- only one possibility for now --
     rdnSequence  RDNSequence }

   RDNSequence ::= SEQUENCE OF RelativeDistinguishedName

   RelativeDistinguishedName ::=
     SET SIZE (1..MAX) OF AttributeTypeAndValue

   AttributeTypeAndValue ::= SEQUENCE {
     type     AttributeType,
     value    AttributeValue }

   AttributeType ::= OBJECT IDENTIFIER

   AttributeValue ::= ANY -- DEFINED BY AttributeType

   DirectoryString ::= CHOICE {
         teletexString           TeletexString (SIZE (1..MAX)),
         printableString         PrintableString (SIZE (1..MAX)),
         universalString         UniversalString (SIZE (1..MAX)),
         utf8String              UTF8String (SIZE (1..MAX)),
         bmpString               BMPString (SIZE (1..MAX)) }

   The Name describes a hierarchical name composed of attributes, such
   as country name, and corresponding values, such as US.  The type of
   the component AttributeValue is determined by the AttributeType; in
   general it will be a DirectoryString.

   The DirectoryString type is defined as a choice of PrintableString,
   TeletexString, BMPString, UTF8String, and UniversalString.  CAs
   conforming to this profile MUST use either the PrintableString or
   UTF8String encoding of DirectoryString, with two exceptions.  When
   CAs have previously issued certificates with issuer fields with
   attributes encoded using TeletexString, BMPString, or
   UniversalString, then the CA MAY continue to use these encodings of
   the DirectoryString to preserve backward compatibility.  Also, new
   CAs that are added to a domain where existing CAs issue certificates
   with issuer fields with attributes encoded using TeletexString,
   BMPString, or UniversalString MAY encode attributes that they share
   with the existing CAs using the same encodings as the existing CAs
   use.

   As noted above, distinguished names are composed of attributes.  This
   specification does not restrict the set of attribute types that may
   appear in names.  However, conforming implementations MUST be
   prepared to receive certificates with issuer names containing the set
   of attribute types defined below.  This specification RECOMMENDS
   support for additional attribute types.

   Standard sets of attributes have been defined in the X.500 series of
   specifications [X.520].  Implementations of this specification MUST
   be prepared to receive the following standard attribute types in
   issuer and subject (Section 4.1.2.6) names:

      * country,
      * organization,
      * organizational unit,
      * distinguished name qualifier,
      * state or province name,
      * common name (e.g., "Susan Housley"), and
      * serial number.

   In addition, implementations of this specification SHOULD be prepared
   to receive the following standard attribute types in issuer and
   subject names:

      * locality,
      * title,
      * surname,
      * given name,
      * initials,
      * pseudonym, and
      * generation qualifier (e.g., "Jr.", "3rd", or "IV").

   The syntax and associated object identifiers (OIDs) for these
   attribute types are provided in the ASN.1 modules in Appendix A.

   In addition, implementations of this specification MUST be prepared
   to receive the domainComponent attribute, as defined in [RFC4519].
   The Domain Name System (DNS) provides a hierarchical resource
   labeling system.  This attribute provides a convenient mechanism for
   organizations that wish to use DNs that parallel their DNS names.
   This is not a replacement for the dNSName component of the
   alternative name extensions.  Implementations are not required to
   convert such names into DNS names.  The syntax and associated OID for
   this attribute type are provided in the ASN.1 modules in Appendix A.
   Rules for encoding internationalized domain names for use with the
   domainComponent attribute type are specified in Section 7.3.

   Certificate users MUST be prepared to process the issuer
   distinguished name and subject distinguished name (Section 4.1.2.6)
   fields to perform name chaining for certification path validation
   (Section 6).  Name chaining is performed by matching the issuer
   distinguished name in one certificate with the subject name in a CA
   certificate.  Rules for comparing distinguished names are specified
   in Section 7.1.  If the names in the issuer and subject field in a
   certificate match according to the rules specified in Section 7.1,
   then the certificate is self-issued.
*/
		if (obj.type == jCastle.asn1.tagSequence && 
			obj.items[0].type == jCastle.asn1.tagSet
		) {
			tbs_info.issuer = jCastle.certificate.asn1.directoryName.parse(obj);

			obj = sequence.items[idx++];
		}

/*
4.1.2.5.  Validity

   The certificate validity period is the time interval during which the
   CA warrants that it will maintain information about the status of the
   certificate.  The field is represented as a SEQUENCE of two dates:
   the date on which the certificate validity period begins (notBefore)
   and the date on which the certificate validity period ends
   (notAfter).  Both notBefore and notAfter may be encoded as UTCTime or
   GeneralizedTime.

   CAs conforming to this profile MUST always encode certificate
   validity dates through the year 2049 as UTCTime; certificate validity
   dates in 2050 or later MUST be encoded as GeneralizedTime.
   Conforming applications MUST be able to process validity dates that
   are encoded in either UTCTime or GeneralizedTime.

   The validity period for a certificate is the period of time from
   notBefore through notAfter, inclusive.

   In some situations, devices are given certificates for which no good
   expiration date can be assigned.  For example, a device could be
   issued a certificate that binds its model and serial number to its
   public key; such a certificate is intended to be used for the entire
   lifetime of the device.

   To indicate that a certificate has no well-defined expiration date,
   the notAfter SHOULD be assigned the GeneralizedTime value of
   99991231235959Z.

   When the issuer will not be able to maintain status information until
   the notAfter date (including when the notAfter date is
   99991231235959Z), the issuer MUST ensure that no valid certification
   path exists for the certificate after maintenance of status
   information is terminated.  This may be accomplished by expiration or
   revocation of all CA certificates containing the public key used to
   verify the signature on the certificate and discontinuing use of the
   public key used to verify the signature on the certificate as a trust
   anchor.

4.1.2.5.1.  UTCTime

   The universal time type, UTCTime, is a standard ASN.1 type intended
   for representation of dates and time.  UTCTime specifies the year
   through the two low-order digits and time is specified to the
   precision of one minute or one second.  UTCTime includes either Z
   (for Zulu, or Greenwich Mean Time) or a time differential.

   For the purposes of this profile, UTCTime values MUST be expressed in
   Greenwich Mean Time (Zulu) and MUST include seconds (i.e., times are
   YYMMDDHHMMSSZ), even where the number of seconds is zero.  Conforming
   systems MUST interpret the year field (YY) as follows:

      Where YY is greater than or equal to 50, the year SHALL be
      interpreted as 19YY; and

      Where YY is less than 50, the year SHALL be interpreted as 20YY.

4.1.2.5.2.  GeneralizedTime

   The generalized time type, GeneralizedTime, is a standard ASN.1 type
   for variable precision representation of time.  Optionally, the
   GeneralizedTime field can include a representation of the time
   differential between local and Greenwich Mean Time.

   For the purposes of this profile, GeneralizedTime values MUST be
   expressed in Greenwich Mean Time (Zulu) and MUST include seconds
   (i.e., times are YYYYMMDDHHMMSSZ), even where the number of seconds
   is zero.  GeneralizedTime values MUST NOT include fractional seconds.
*/
		if (obj.type == jCastle.asn1.tagSequence &&
			(obj.items[0].type == jCastle.asn1.tagUTCTime ||obj.items[0].type == jCastle.asn1.tagGeneralizedTime)
		) {
//			tbs_info.notBefore = obj.items[0].value;
//			tbs_info.notAfter = obj.items[1].value;
			tbs_info.validity = jCastle.certificate.asn1.validity.parse(obj);
			
			obj = sequence.items[idx++];
		}

/*
4.1.2.6.  Subject

   The subject field identifies the entity associated with the public
   key stored in the subject public key field.  The subject name MAY be
   carried in the subject field and/or the subjectAltName extension.  If
   the subject is a CA (e.g., the basic constraints extension, as
   discussed in Section 4.2.1.9, is present and the value of cA is
   TRUE), then the subject field MUST be populated with a non-empty
   distinguished name matching the contents of the issuer field (Section
   4.1.2.4) in all certificates issued by the subject CA.  If the
   subject is a CRL issuer (e.g., the key usage extension, as discussed
   in Section 4.2.1.3, is present and the value of cRLSign is TRUE),
   then the subject field MUST be populated with a non-empty
   distinguished name matching the contents of the issuer field (Section
   5.1.2.3) in all CRLs issued by the subject CRL issuer.  If subject
   naming information is present only in the subjectAltName extension
   (e.g., a key bound only to an email address or URI), then the subject
   name MUST be an empty sequence and the subjectAltName extension MUST
   be critical.

   Where it is non-empty, the subject field MUST contain an X.500
   distinguished name (DN).  The DN MUST be unique for each subject
   entity certified by the one CA as defined by the issuer field.  A CA
   MAY issue more than one certificate with the same DN to the same
   subject entity.

   The subject field is defined as the X.501 type Name.  Implementation
   requirements for this field are those defined for the issuer field
   (Section 4.1.2.4).  Implementations of this specification MUST be
   prepared to receive subject names containing the attribute types
   required for the issuer field.  Implementations of this specification
   SHOULD be prepared to receive subject names containing the
   recommended attribute types for the issuer field.  The syntax and
   associated object identifiers (OIDs) for these attribute types are
   provided in the ASN.1 modules in Appendix A.  Implementations of this
   specification MAY use the comparison rules in Section 7.1 to process
   unfamiliar attribute types (i.e., for name chaining) whose attribute
   values use one of the encoding options from DirectoryString.  Binary
   comparison should be used when unfamiliar attribute types include
   attribute values with encoding options other than those found in
   DirectoryString.  This allows implementations to process certificates
   with unfamiliar attributes in the subject name.

   When encoding attribute values of type DirectoryString, conforming
   CAs MUST use PrintableString or UTF8String encoding, with the
   following exceptions:

      (a)  When the subject of the certificate is a CA, the subject
           field MUST be encoded in the same way as it is encoded in the
           issuer field (Section 4.1.2.4) in all certificates issued by
           the subject CA.  Thus, if the subject CA encodes attributes
           in the issuer fields of certificates that it issues using the
           TeletexString, BMPString, or UniversalString encodings, then
           the subject field of certificates issued to that CA MUST use
           the same encoding.

      (b)  When the subject of the certificate is a CRL issuer, the
           subject field MUST be encoded in the same way as it is
           encoded in the issuer field (Section 5.1.2.3) in all CRLs
           issued by the subject CRL issuer.

      (c)  TeletexString, BMPString, and UniversalString are included
           for backward compatibility, and SHOULD NOT be used for
           certificates for new subjects.  However, these types MAY be
           used in certificates where the name was previously
           established, including cases in which a new certificate is
           being issued to an existing subject or a certificate is being
           issued to a new subject where the attributes being encoded
           have been previously established in certificates issued to
           other subjects.  Certificate users SHOULD be prepared to
           receive certificates with these types.

   Legacy implementations exist where an electronic mail address is
   embedded in the subject distinguished name as an emailAddress
   attribute [RFC2985].  The attribute value for emailAddress is of type
   IA5String to permit inclusion of the character '@', which is not part
   of the PrintableString character set.  emailAddress attribute values
   are not case-sensitive (e.g., "subscriber@example.com" is the same as
   "SUBSCRIBER@EXAMPLE.COM").

   Conforming implementations generating new certificates with
   electronic mail addresses MUST use the rfc822Name in the subject
   alternative name extension (Section 4.2.1.6) to describe such
   identities.  Simultaneous inclusion of the emailAddress attribute in
   the subject distinguished name to support legacy implementations is
   deprecated but permitted.
*/
		if (obj.type == jCastle.asn1.tagSequence && 
			obj.items[0].type == jCastle.asn1.tagSet
		) {
			tbs_info.subject = jCastle.certificate.asn1.directoryName.parse(obj);

			obj = sequence.items[idx++];
		}

/*
4.1.2.7.  Subject Public Key Info

   This field is used to carry the public key and identify the algorithm
   with which the key is used (e.g., RSA, DSA, or Diffie-Hellman).  The
   algorithm is identified using the AlgorithmIdentifier structure
   specified in Section 4.1.1.2.  The object identifiers for the
   supported algorithms and the methods for encoding the public key
   materials (public key and parameters) are specified in [RFC3279],
   [RFC4055], and [RFC4491].
*/
		var publicKeyInfo = jCastle.certificate.asn1.publicKeyInfo.parse(obj);
		tbs_info.subjectPublicKeyInfo = publicKeyInfo;
		obj = sequence.items[idx++];

	// check for if there is no extensions
//	if (idx > sequence.items.length) {
//		return tbs_info;
//	}

/*
4.1.2.8.  Unique Identifiers

   These fields MUST only appear if the version is 2 or 3 (Section
   4.1.2.1).  These fields MUST NOT appear if the version is 1.  The
   subject and issuer unique identifiers are present in the certificate
   to handle the possibility of reuse of subject and/or issuer names
   over time.  This profile RECOMMENDS that names not be reused for
   different entities and that Internet certificates not make use of
   unique identifiers.  CAs conforming to this profile MUST NOT generate
   certificates with unique identifiers.  Applications conforming to
   this profile SHOULD be capable of parsing certificates that include
   unique identifiers, but there are no processing requirements
   associated with the unique identifiers.
*/
// http://openssl.6102.n7.nabble.com/How-put-issuerUniqueID-into-certificate-td11399.html
		if (typeof obj != 'undefined' &&
			obj.tagClass == jCastle.asn1.tagClassContextSpecific &&
			obj.type == 0x01
		) {
			// issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
			tbs_info.issuerUniqueID = obj.value;

			obj = sequence.items[idx++];
		}

		if (typeof obj != 'undefined' && 
			obj.tagClass == jCastle.asn1.tagClassContextSpecific &&
			obj.type == 0x02
		) {
			// subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
			tbs_info.subjectUniqueID = obj.value;

			obj = sequence.items[idx++];
		}

/*
4.1.2.9.  Extensions

   This field MUST only appear if the version is 3 (Section 4.1.2.1).
   If present, this field is a SEQUENCE of one or more certificate
   extensions.  The format and content of certificate extensions in the
   Internet PKI are defined in Section 4.2.

4.2.  Certificate Extensions

   The extensions defined for X.509 v3 certificates provide methods for
   associating additional attributes with users or public keys and for
   managing relationships between CAs.  The X.509 v3 certificate format
   also allows communities to define private extensions to carry
   information unique to those communities.  Each extension in a
   certificate is designated as either critical or non-critical.  A
   certificate-using system MUST reject the certificate if it encounters
   a critical extension it does not recognize or a critical extension
   that contains information that it cannot process.  A non-critical
   extension MAY be ignored if it is not recognized, but MUST be
   processed if it is recognized.  The following sections present
   recommended extensions used within Internet certificates and standard
   locations for information.  Communities may elect to use additional
   extensions; however, caution ought to be exercised in adopting any
   critical extensions in certificates that might prevent use in a
   general context.

   Each extension includes an OID and an ASN.1 structure.  When an
   extension appears in a certificate, the OID appears as the field
   extnID and the corresponding ASN.1 DER encoded structure is the value
   of the octet string extnValue.  A certificate MUST NOT include more
   than one instance of a particular extension.  For example, a
   certificate may contain only one authority key identifier extension
   (Section 4.2.1.1).  An extension includes the boolean critical, with
   a default value of FALSE.  The text for each extension specifies the
   acceptable values for the critical field for CAs conforming to this
   profile.

   Conforming CAs MUST support key identifiers (Sections 4.2.1.1 and
   4.2.1.2), basic constraints (Section 4.2.1.9), key usage (Section
   4.2.1.3), and certificate policies (Section 4.2.1.4) extensions.  If
   the CA issues certificates with an empty sequence for the subject
   field, the CA MUST support the subject alternative name extension
   (Section 4.2.1.6).  Support for the remaining extensions is OPTIONAL.
   Conforming CAs MAY support extensions that are not identified within
   this specification; certificate issuers are cautioned that marking
   such extensions as critical may inhibit interoperability.

   At a minimum, applications conforming to this profile MUST recognize
   the following extensions: key usage (Section 4.2.1.3), certificate
   policies (Section 4.2.1.4), subject alternative name (Section
   4.2.1.6), basic constraints (Section 4.2.1.9), name constraints
   (Section 4.2.1.10), policy constraints (Section 4.2.1.11), extended
   key usage (Section 4.2.1.12), and inhibit anyPolicy (Section
   4.2.1.14).

   In addition, applications conforming to this profile SHOULD recognize
   the authority and subject key identifier (Sections 4.2.1.1 and
   4.2.1.2) and policy mappings (Section 4.2.1.5) extensions.

4.2.1.  Standard Extensions

   This section identifies standard certificate extensions defined in
   [X.509] for use in the Internet PKI.  Each extension is associated
   with an OID defined in [X.509].  These OIDs are members of the id-ce
   arc, which is defined by the following:

   id-ce   OBJECT IDENTIFIER ::=  { joint-iso-ccitt(2) ds(5) 29 }

4.2.1.1.  Authority Key Identifier

   The authority key identifier extension provides a means of
   identifying the public key corresponding to the private key used to
   sign a certificate.  This extension is used where an issuer has
   multiple signing keys (either due to multiple concurrent key pairs or
   due to changeover).  The identification MAY be based on either the
   key identifier (the subject key identifier in the issuer's
   certificate) or the issuer name and serial number.

   The keyIdentifier field of the authorityKeyIdentifier extension MUST
   be included in all certificates generated by conforming CAs to
   facilitate certification path construction.  There is one exception;
   where a CA distributes its public key in the form of a "self-signed"
   certificate, the authority key identifier MAY be omitted.  The
   signature on a self-signed certificate is generated with the private
   key associated with the certificate's subject public key.  (This
   proves that the issuer possesses both the public and private keys.)
   In this case, the subject and authority key identifiers would be
   identical, but only the subject key identifier is needed for
   certification path building.

   The value of the keyIdentifier field SHOULD be derived from the
   public key used to verify the certificate's signature or a method
   that generates unique values.  Two common methods for generating key
   identifiers from the public key are described in Section 4.2.1.2.
   Where a key identifier has not been previously established, this
   specification RECOMMENDS use of one of these methods for generating
   keyIdentifiers or use of a similar method that uses a different hash
   algorithm.  Where a key identifier has been previously established,
   the CA SHOULD use the previously established identifier.

   This profile RECOMMENDS support for the key identifier method by all
   certificate users.

   Conforming CAs MUST mark this extension as non-critical.

   id-ce-authorityKeyIdentifier OBJECT IDENTIFIER ::=  { id-ce 35 }

   AuthorityKeyIdentifier ::= SEQUENCE {
      keyIdentifier             [0] KeyIdentifier           OPTIONAL,
      authorityCertIssuer       [1] GeneralNames            OPTIONAL,
      authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL  }

   KeyIdentifier ::= OCTET STRING

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

4.2.1.3.  Key Usage

   The key usage extension defines the purpose (e.g., encipherment,
   signature, certificate signing) of the key contained in the
   certificate.  The usage restriction might be employed when a key that
   could be used for more than one operation is to be restricted.  For
   example, when an RSA key should be used only to verify signatures on
   objects other than public key certificates and CRLs, the
   digitalSignature and/or nonRepudiation bits would be asserted.
   Likewise, when an RSA key should be used only for key management, the
   keyEncipherment bit would be asserted.

   Conforming CAs MUST include this extension in certificates that
   contain public keys that are used to validate digital signatures on
   other public key certificates or CRLs.  When present, conforming CAs
   SHOULD mark this extension as critical.

      id-ce-keyUsage OBJECT IDENTIFIER ::=  { id-ce 15 }

      KeyUsage ::= BIT STRING {
           digitalSignature        (0),
           nonRepudiation          (1), -- recent editions of X.509 have
                                -- renamed this bit to contentCommitment
           keyEncipherment         (2),
           dataEncipherment        (3),
           keyAgreement            (4),
           keyCertSign             (5),
           cRLSign                 (6),
           encipherOnly            (7),
           decipherOnly            (8) }

   Bits in the KeyUsage type are used as follows:

      The digitalSignature bit is asserted when the subject public key
      is used for verifying digital signatures, other than signatures on
      certificates (bit 5) and CRLs (bit 6), such as those used in an
      entity authentication service, a data origin authentication
      service, and/or an integrity service.

      The nonRepudiation bit is asserted when the subject public key is
      used to verify digital signatures, other than signatures on
      certificates (bit 5) and CRLs (bit 6), used to provide a non-
      repudiation service that protects against the signing entity
      falsely denying some action.  In the case of later conflict, a
      reliable third party may determine the authenticity of the signed
      data.  (Note that recent editions of X.509 have renamed the
      nonRepudiation bit to contentCommitment.)

      The keyEncipherment bit is asserted when the subject public key is
      used for enciphering private or secret keys, i.e., for key
      transport.  For example, this bit shall be set when an RSA public
      key is to be used for encrypting a symmetric content-decryption
      key or an asymmetric private key.

      The dataEncipherment bit is asserted when the subject public key
      is used for directly enciphering raw user data without the use of
      an intermediate symmetric cipher.  Note that the use of this bit
      is extremely uncommon; almost all applications use key transport
      or key agreement to establish a symmetric key.

      The keyAgreement bit is asserted when the subject public key is
      used for key agreement.  For example, when a Diffie-Hellman key is
      to be used for key management, then this bit is set.

      The keyCertSign bit is asserted when the subject public key is
      used for verifying signatures on public key certificates.  If the
      keyCertSign bit is asserted, then the cA bit in the basic
      constraints extension (Section 4.2.1.9) MUST also be asserted.

      The cRLSign bit is asserted when the subject public key is used
      for verifying signatures on certificate revocation lists (e.g.,
      CRLs, delta CRLs, or ARLs).

      The meaning of the encipherOnly bit is undefined in the absence of
      the keyAgreement bit.  When the encipherOnly bit is asserted and
      the keyAgreement bit is also set, the subject public key may be
      used only for enciphering data while performing key agreement.

      The meaning of the decipherOnly bit is undefined in the absence of
      the keyAgreement bit.  When the decipherOnly bit is asserted and
      the keyAgreement bit is also set, the subject public key may be
      used only for deciphering data while performing key agreement.

   If the keyUsage extension is present, then the subject public key
   MUST NOT be used to verify signatures on certificates or CRLs unless
   the corresponding keyCertSign or cRLSign bit is set.  If the subject
   public key is only to be used for verifying signatures on
   certificates and/or CRLs, then the digitalSignature and
   nonRepudiation bits SHOULD NOT be set.  However, the digitalSignature
   and/or nonRepudiation bits MAY be set in addition to the keyCertSign
   and/or cRLSign bits if the subject public key is to be used to verify
   signatures on certificates and/or CRLs as well as other objects.

   Combining the nonRepudiation bit in the keyUsage certificate
   extension with other keyUsage bits may have security implications
   depending on the context in which the certificate is to be used.
   Further distinctions between the digitalSignature and nonRepudiation
   bits may be provided in specific certificate policies.

   This profile does not restrict the combinations of bits that may be
   set in an instantiation of the keyUsage extension.  However,
   appropriate values for keyUsage extensions for particular algorithms
   are specified in [RFC3279], [RFC4055], and [RFC4491].  When the
   keyUsage extension appears in a certificate, at least one of the bits
   MUST be set to 1.

4.2.1.4.  Certificate Policies

   The certificate policies extension contains a sequence of one or more
   policy information terms, each of which consists of an object
   identifier (OID) and optional qualifiers.  Optional qualifiers, which
   MAY be present, are not expected to change the definition of the
   policy.  A certificate policy OID MUST NOT appear more than once in a
   certificate policies extension.

   In an end entity certificate, these policy information terms indicate
   the policy under which the certificate has been issued and the
   purposes for which the certificate may be used.  In a CA certificate,
   these policy information terms limit the set of policies for
   certification paths that include this certificate.  When a CA does
   not wish to limit the set of policies for certification paths that
   include this certificate, it MAY assert the special policy anyPolicy,
   with a value of { 2 5 29 32 0 }.

   Applications with specific policy requirements are expected to have a
   list of those policies that they will accept and to compare the
   policy OIDs in the certificate to that list.  If this extension is
   critical, the path validation software MUST be able to interpret this
   extension (including the optional qualifier), or MUST reject the
   certificate.

   To promote interoperability, this profile RECOMMENDS that policy
   information terms consist of only an OID.  Where an OID alone is
   insufficient, this profile strongly recommends that the use of
   qualifiers be limited to those identified in this section.  When
   qualifiers are used with the special policy anyPolicy, they MUST be
   limited to the qualifiers identified in this section.  Only those
   qualifiers returned as a result of path validation are considered.

   This specification defines two policy qualifier types for use by
   certificate policy writers and certificate issuers.  The qualifier
   types are the CPS Pointer and User Notice qualifiers.

   The CPS Pointer qualifier contains a pointer to a Certification
   Practice Statement (CPS) published by the CA.  The pointer is in the
   form of a URI.  Processing requirements for this qualifier are a
   local matter.  No action is mandated by this specification regardless
   of the criticality value asserted for the extension.

   User notice is intended for display to a relying party when a
   certificate is used.  Only user notices returned as a result of path
   validation are intended for display to the user.  If a notice is
   duplicated, only one copy need be displayed.  To prevent such
   duplication, this qualifier SHOULD only be present in end entity
   certificates and CA certificates issued to other organizations.

   The user notice has two optional fields: the noticeRef field and the
   explicitText field.  Conforming CAs SHOULD NOT use the noticeRef
   option.

      The noticeRef field, if used, names an organization and
      identifies, by number, a particular textual statement prepared by
      that organization.  For example, it might identify the
      organization "CertsRUs" and notice number 1.  In a typical
      implementation, the application software will have a notice file
      containing the current set of notices for CertsRUs; the
      application will extract the notice text from the file and display
      it.  Messages MAY be multilingual, allowing the software to select
      the particular language message for its own environment.

      An explicitText field includes the textual statement directly in
      the certificate.  The explicitText field is a string with a
      maximum size of 200 characters.  Conforming CAs SHOULD use the
      UTF8String encoding for explicitText, but MAY use IA5String.
      Conforming CAs MUST NOT encode explicitText as VisibleString or
      BMPString.  The explicitText string SHOULD NOT include any control
      characters (e.g., U+0000 to U+001F and U+007F to U+009F).  When
      the UTF8String encoding is used, all character sequences SHOULD be
      normalized according to Unicode normalization form C (NFC) [NFC].

   If both the noticeRef and explicitText options are included in the
   one qualifier and if the application software can locate the notice
   text indicated by the noticeRef option, then that text SHOULD be
   displayed; otherwise, the explicitText string SHOULD be displayed.

   Note: While the explicitText has a maximum size of 200 characters,
   some non-conforming CAs exceed this limit.  Therefore, certificate
   users SHOULD gracefully handle explicitText with more than 200
   characters.

   id-ce-certificatePolicies OBJECT IDENTIFIER ::=  { id-ce 32 }

   anyPolicy OBJECT IDENTIFIER ::= { id-ce-certificatePolicies 0 }

   certificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation

   PolicyInformation ::= SEQUENCE {
        policyIdentifier   CertPolicyId,
        policyQualifiers   SEQUENCE SIZE (1..MAX) OF
                                PolicyQualifierInfo OPTIONAL }

   CertPolicyId ::= OBJECT IDENTIFIER

   PolicyQualifierInfo ::= SEQUENCE {
        policyQualifierId  PolicyQualifierId,
        qualifier          ANY DEFINED BY policyQualifierId }

   -- policyQualifierIds for Internet policy qualifiers

   id-qt          OBJECT IDENTIFIER ::=  { id-pkix 2 }
   id-qt-cps      OBJECT IDENTIFIER ::=  { id-qt 1 }
   id-qt-unotice  OBJECT IDENTIFIER ::=  { id-qt 2 }

   PolicyQualifierId ::= OBJECT IDENTIFIER ( id-qt-cps | id-qt-unotice )

   Qualifier ::= CHOICE {
        cPSuri           CPSuri,
        userNotice       UserNotice }

   CPSuri ::= IA5String

   UserNotice ::= SEQUENCE {
        noticeRef        NoticeReference OPTIONAL,
        explicitText     DisplayText OPTIONAL }

   NoticeReference ::= SEQUENCE {
        organization     DisplayText,
        noticeNumbers    SEQUENCE OF INTEGER }

   DisplayText ::= CHOICE {
        ia5String        IA5String      (SIZE (1..200)),
        visibleString    VisibleString  (SIZE (1..200)),
        bmpString        BMPString      (SIZE (1..200)),
        utf8String       UTF8String     (SIZE (1..200)) }

4.2.1.5.  Policy Mappings

   This extension is used in CA certificates.  It lists one or more
   pairs of OIDs; each pair includes an issuerDomainPolicy and a
   subjectDomainPolicy.  The pairing indicates the issuing CA considers
   its issuerDomainPolicy equivalent to the subject CA's
   subjectDomainPolicy.

   The issuing CA's users might accept an issuerDomainPolicy for certain
   applications.  The policy mapping defines the list of policies
   associated with the subject CA that may be accepted as comparable to
   the issuerDomainPolicy.

   Each issuerDomainPolicy named in the policy mappings extension SHOULD
   also be asserted in a certificate policies extension in the same
   certificate.  Policies MUST NOT be mapped either to or from the
   special value anyPolicy (Section 4.2.1.4).

   In general, certificate policies that appear in the
   issuerDomainPolicy field of the policy mappings extension are not
   considered acceptable policies for inclusion in subsequent
   certificates in the certification path.  In some circumstances, a CA
   may wish to map from one policy (p1) to another (p2), but still wants
   the issuerDomainPolicy (p1) to be considered acceptable for inclusion
   in subsequent certificates.  This may occur, for example, if the CA
   is in the process of transitioning from the use of policy p1 to the
   use of policy p2 and has valid certificates that were issued under
   each of the policies.  A CA may indicate this by including two policy
   mappings in the CA certificates that it issues.  Each policy mapping
   would have an issuerDomainPolicy of p1; one policy mapping would have
   a subjectDomainPolicy of p1 and the other would have a
   subjectDomainPolicy of p2.

   This extension MAY be supported by CAs and/or applications.
   Conforming CAs SHOULD mark this extension as critical.

   id-ce-policyMappings OBJECT IDENTIFIER ::=  { id-ce 33 }

   PolicyMappings ::= SEQUENCE SIZE (1..MAX) OF SEQUENCE {
        issuerDomainPolicy      CertPolicyId,
        subjectDomainPolicy     CertPolicyId }

4.2.1.6.  Subject Alternative Name

   The subject alternative name extension allows identities to be bound
   to the subject of the certificate.  These identities may be included
   in addition to or in place of the identity in the subject field of
   the certificate.  Defined options include an Internet electronic mail
   address, a DNS name, an IP address, and a Uniform Resource Identifier
   (URI).  Other options exist, including completely local definitions.
   Multiple name forms, and multiple instances of each name form, MAY be
   included.  Whenever such identities are to be bound into a
   certificate, the subject alternative name (or issuer alternative
   name) extension MUST be used; however, a DNS name MAY also be
   represented in the subject field using the domainComponent attribute
   as described in Section 4.1.2.4.  Note that where such names are
   represented in the subject field implementations are not required to
   convert them into DNS names.

   Because the subject alternative name is considered to be definitively
   bound to the public key, all parts of the subject alternative name
   MUST be verified by the CA.

   Further, if the only subject identity included in the certificate is
   an alternative name form (e.g., an electronic mail address), then the
   subject distinguished name MUST be empty (an empty sequence), and the
   subjectAltName extension MUST be present.  If the subject field
   contains an empty sequence, then the issuing CA MUST include a
   subjectAltName extension that is marked as critical.  When including
   the subjectAltName extension in a certificate that has a non-empty
   subject distinguished name, conforming CAs SHOULD mark the
   subjectAltName extension as non-critical.

   When the subjectAltName extension contains an Internet mail address,
   the address MUST be stored in the rfc822Name.  The format of an
   rfc822Name is a "Mailbox" as defined in Section 4.1.2 of [RFC2821].
   A Mailbox has the form "Local-part@Domain".  Note that a Mailbox has
   no phrase (such as a common name) before it, has no comment (text
   surrounded in parentheses) after it, and is not surrounded by "<" and
   ">".  Rules for encoding Internet mail addresses that include
   internationalized domain names are specified in Section 7.5.

   When the subjectAltName extension contains an iPAddress, the address
   MUST be stored in the octet string in "network byte order", as
   specified in [RFC791].  The least significant bit (LSB) of each octet
   is the LSB of the corresponding byte in the network address.  For IP
   version 4, as specified in [RFC791], the octet string MUST contain
   exactly four octets.  For IP version 6, as specified in
   [RFC2460], the octet string MUST contain exactly sixteen octets.

   When the subjectAltName extension contains a domain name system
   label, the domain name MUST be stored in the dNSName (an IA5String).
   The name MUST be in the "preferred name syntax", as specified by
   Section 3.5 of [RFC1034] and as modified by Section 2.1 of
   [RFC1123].  Note that while uppercase and lowercase letters are
   allowed in domain names, no significance is attached to the case.  In
   addition, while the string " " is a legal domain name, subjectAltName
   extensions with a dNSName of " " MUST NOT be used.  Finally, the use
   of the DNS representation for Internet mail addresses
   (subscriber.example.com instead of subscriber@example.com) MUST NOT
   be used; such identities are to be encoded as rfc822Name.  Rules for
   encoding internationalized domain names are specified in Section 7.2.

   When the subjectAltName extension contains a URI, the name MUST be
   stored in the uniformResourceIdentifier (an IA5String).  The name
   MUST NOT be a relative URI, and it MUST follow the URI syntax and
   encoding rules specified in [RFC3986].  The name MUST include both a
   scheme (e.g., "http" or "ftp") and a scheme-specific-part.  URIs that
   include an authority ([RFC3986], Section 3.2) MUST include a fully
   qualified domain name or IP address as the host.  Rules for encoding
   Internationalized Resource Identifiers (IRIs) are specified in
   Section 7.4.

   As specified in [RFC3986], the scheme name is not case-sensitive
   (e.g., "http" is equivalent to "HTTP").  The host part, if present,
   is also not case-sensitive, but other components of the scheme-
   specific-part may be case-sensitive.  Rules for comparing URIs are
   specified in Section 7.4.

   When the subjectAltName extension contains a DN in the directoryName,
   the encoding rules are the same as those specified for the issuer
   field in Section 4.1.2.4.  The DN MUST be unique for each subject
   entity certified by the one CA as defined by the issuer field.  A CA
   MAY issue more than one certificate with the same DN to the same
   subject entity.

   The subjectAltName MAY carry additional name types through the use of
   the otherName field.  The format and semantics of the name are
   indicated through the OBJECT IDENTIFIER in the type-id field.  The
   name itself is conveyed as value field in otherName.  For example,
   Kerberos [RFC4120] format names can be encoded into the otherName,
   using a Kerberos 5 principal name OID and a SEQUENCE of the Realm and
   the PrincipalName.

   Subject alternative names MAY be constrained in the same manner as
   subject distinguished names using the name constraints extension as
   described in Section 4.2.1.10.

   If the subjectAltName extension is present, the sequence MUST contain
   at least one entry.  Unlike the subject field, conforming CAs MUST
   NOT issue certificates with subjectAltNames containing empty
   GeneralName fields.  For example, an rfc822Name is represented as an
   IA5String.  While an empty string is a valid IA5String, such an
   rfc822Name is not permitted by this profile.  The behavior of clients
   that encounter such a certificate when processing a certification
   path is not defined by this profile.

   Finally, the semantics of subject alternative names that include
   wildcard characters (e.g., as a placeholder for a set of names) are
   not addressed by this specification.  Applications with specific
   requirements MAY use such names, but they must define the semantics.

   id-ce-subjectAltName OBJECT IDENTIFIER ::=  { id-ce 17 }

   SubjectAltName ::= GeneralNames

   GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName

   GeneralName ::= CHOICE {
        otherName                       [0]     OtherName,
        rfc822Name                      [1]     IA5String,
        dNSName                         [2]     IA5String,
        x400Address                     [3]     ORAddress,
        directoryName                   [4]     Name,
        ediPartyName                    [5]     EDIPartyName,
        uniformResourceIdentifier       [6]     IA5String,
        iPAddress                       [7]     OCTET STRING,
        registeredID                    [8]     OBJECT IDENTIFIER }

   OtherName ::= SEQUENCE {
        type-id    OBJECT IDENTIFIER,
        value      [0] EXPLICIT ANY DEFINED BY type-id }

   EDIPartyName ::= SEQUENCE {
        nameAssigner            [0]     DirectoryString OPTIONAL,
        partyName               [1]     DirectoryString }

4.2.1.7.  Issuer Alternative Name

   As with Section 4.2.1.6, this extension is used to associate Internet
   style identities with the certificate issuer.  Issuer alternative
   name MUST be encoded as in 4.2.1.6.  Issuer alternative names are not
   processed as part of the certification path validation algorithm in
   Section 6.  (That is, issuer alternative names are not used in name
   chaining and name constraints are not enforced.)

   Where present, conforming CAs SHOULD mark this extension as non-
   critical.

   id-ce-issuerAltName OBJECT IDENTIFIER ::=  { id-ce 18 }

   IssuerAltName ::= GeneralNames

   The subject directory attributes extension is used to convey
   identification attributes (e.g., nationality) of the subject.  The
   extension is defined as a sequence of one or more attributes.
   Conforming CAs MUST mark this extension as non-critical.

   id-ce-subjectDirectoryAttributes OBJECT IDENTIFIER ::=  { id-ce 9 }

   SubjectDirectoryAttributes ::= SEQUENCE SIZE (1..MAX) OF Attribute

4.2.1.9.  Basic Constraints

   The basic constraints extension identifies whether the subject of the
   certificate is a CA and the maximum depth of valid certification
   paths that include this certificate.

   The cA boolean indicates whether the certified public key may be used
   to verify certificate signatures.  If the cA boolean is not asserted,
   then the keyCertSign bit in the key usage extension MUST NOT be
   asserted.  If the basic constraints extension is not present in a
   version 3 certificate, or the extension is present but the cA boolean
   is not asserted, then the certified public key MUST NOT be used to
   verify certificate signatures.

   The pathLenConstraint field is meaningful only if the cA boolean is
   asserted and the key usage extension, if present, asserts the
   keyCertSign bit (Section 4.2.1.3).  In this case, it gives the
   maximum number of non-self-issued intermediate certificates that may
   follow this certificate in a valid certification path.  (Note: The
   last certificate in the certification path is not an intermediate
   certificate, and is not included in this limit.  Usually, the last
   certificate is an end entity certificate, but it can be a CA
   certificate.)  A pathLenConstraint of zero indicates that no non-
   self-issued intermediate CA certificates may follow in a valid
   certification path.  Where it appears, the pathLenConstraint field
   MUST be greater than or equal to zero.  Where pathLenConstraint does
   not appear, no limit is imposed.

   Conforming CAs MUST include this extension in all CA certificates
   that contain public keys used to validate digital signatures on
   certificates and MUST mark the extension as critical in such
   certificates.  This extension MAY appear as a critical or non-
   critical extension in CA certificates that contain public keys used
   exclusively for purposes other than validating digital signatures on
   certificates.  Such CA certificates include ones that contain public
   keys used exclusively for validating digital signatures on CRLs and
   ones that contain key management public keys used with certificate
   enrollment protocols.  This extension MAY appear as a critical or
   non-critical extension in end entity certificates.

   CAs MUST NOT include the pathLenConstraint field unless the cA
   boolean is asserted and the key usage extension asserts the
   keyCertSign bit.

   id-ce-basicConstraints OBJECT IDENTIFIER ::=  { id-ce 19 }

   BasicConstraints ::= SEQUENCE {
        cA                      BOOLEAN DEFAULT FALSE,
        pathLenConstraint       INTEGER (0..MAX) OPTIONAL }

4.2.1.10.  Name Constraints

   The name constraints extension, which MUST be used only in a CA
   certificate, indicates a name space within which all subject names in
   subsequent certificates in a certification path MUST be located.
   Restrictions apply to the subject distinguished name and apply to
   subject alternative names.  Restrictions apply only when the
   specified name form is present.  If no name of the type is in the
   certificate, the certificate is acceptable.

   Name constraints are not applied to self-issued certificates (unless
   the certificate is the final certificate in the path).  (This could
   prevent CAs that use name constraints from employing self-issued
   certificates to implement key rollover.)

   Restrictions are defined in terms of permitted or excluded name
   subtrees.  Any name matching a restriction in the excludedSubtrees
   field is invalid regardless of information appearing in the
   permittedSubtrees.  Conforming CAs MUST mark this extension as
   critical and SHOULD NOT impose name constraints on the x400Address,
   ediPartyName, or registeredID name forms.  Conforming CAs MUST NOT
   issue certificates where name constraints is an empty sequence.  That
   is, either the permittedSubtrees field or the excludedSubtrees MUST
   be present.

   Applications conforming to this profile MUST be able to process name
   constraints that are imposed on the directoryName name form and
   SHOULD be able to process name constraints that are imposed on the
   rfc822Name, uniformResourceIdentifier, dNSName, and iPAddress name
   forms.  If a name constraints extension that is marked as critical
   imposes constraints on a particular name form, and an instance of
   that name form appears in the subject field or subjectAltName
   extension of a subsequent certificate, then the application MUST
   either process the constraint or reject the certificate.

   Within this profile, the minimum and maximum fields are not used with
   any name forms, thus, the minimum MUST be zero, and maximum MUST be
   absent.  However, if an application encounters a critical name
   constraints extension that specifies other values for minimum or
   maximum for a name form that appears in a subsequent certificate, the
   application MUST either process these fields or reject the
   certificate.

   For URIs, the constraint applies to the host part of the name.  The
   constraint MUST be specified as a fully qualified domain name and MAY
   specify a host or a domain.  Examples would be "host.example.com" and
   ".example.com".  When the constraint begins with a period, it MAY be
   expanded with one or more labels.  That is, the constraint
   ".example.com" is satisfied by both host.example.com and
   my.host.example.com.  However, the constraint ".example.com" is not
   satisfied by "example.com".  When the constraint does not begin with
   a period, it specifies a host.  If a constraint is applied to the
   uniformResourceIdentifier name form and a subsequent certificate
   includes a subjectAltName extension with a uniformResourceIdentifier
   that does not include an authority component with a host name
   specified as a fully qualified domain name (e.g., if the URI either
   does not include an authority component or includes an authority
   component in which the host name is specified as an IP address), then
   the application MUST reject the certificate.

   A name constraint for Internet mail addresses MAY specify a
   particular mailbox, all addresses at a particular host, or all
   mailboxes in a domain.  To indicate a particular mailbox, the
   constraint is the complete mail address.  For example,
   "root@example.com" indicates the root mailbox on the host
   "example.com".  To indicate all Internet mail addresses on a
   particular host, the constraint is specified as the host name.  For
   example, the constraint "example.com" is satisfied by any mail
   address at the host "example.com".  To specify any address within a
   domain, the constraint is specified with a leading period (as with
   URIs).  For example, ".example.com" indicates all the Internet mail
   addresses in the domain "example.com", but not Internet mail
   addresses on the host "example.com".

   DNS name restrictions are expressed as host.example.com.  Any DNS
   name that can be constructed by simply adding zero or more labels to
   the left-hand side of the name satisfies the name constraint.  For
   example, www.host.example.com would satisfy the constraint but
   host1.example.com would not.

   Legacy implementations exist where an electronic mail address is
   embedded in the subject distinguished name in an attribute of type
   emailAddress (Section 4.1.2.6).  When constraints are imposed on the
   rfc822Name name form, but the certificate does not include a subject
   alternative name, the rfc822Name constraint MUST be applied to the
   attribute of type emailAddress in the subject distinguished name.
   The ASN.1 syntax for emailAddress and the corresponding OID are
   supplied in Appendix A.

   Restrictions of the form directoryName MUST be applied to the subject
   field in the certificate (when the certificate includes a non-empty
   subject field) and to any names of type directoryName in the
   subjectAltName extension.  Restrictions of the form x400Address MUST
   be applied to any names of type x400Address in the subjectAltName
   extension.

   When applying restrictions of the form directoryName, an
   implementation MUST compare DN attributes.  At a minimum,
   implementations MUST perform the DN comparison rules specified in
   Section 7.1.  CAs issuing certificates with a restriction of the form
   directoryName SHOULD NOT rely on implementation of the full ISO DN
   name comparison algorithm.  This implies name restrictions MUST be
   stated identically to the encoding used in the subject field or
   subjectAltName extension.

   The syntax of iPAddress MUST be as described in Section 4.2.1.6 with
   the following additions specifically for name constraints.  For IPv4
   addresses, the iPAddress field of GeneralName MUST contain eight (8)
   octets, encoded in the style of RFC 4632 (CIDR) to represent an
   address range [RFC4632].  For IPv6 addresses, the iPAddress field
   MUST contain 32 octets similarly encoded.  For example, a name
   constraint for "class C" subnet 192.0.2.0 is represented as the
   octets C0 00 02 00 FF FF FF 00, representing the CIDR notation
   192.0.2.0/24 (mask 255.255.255.0).

   Additional rules for encoding and processing name constraints are
   specified in Section 7.

   The syntax and semantics for name constraints for otherName,
   ediPartyName, and registeredID are not defined by this specification,
   however, syntax and semantics for name constraints for other name
   forms may be specified in other documents.

      id-ce-nameConstraints OBJECT IDENTIFIER ::=  { id-ce 30 }

      NameConstraints ::= SEQUENCE {
           permittedSubtrees       [0]     GeneralSubtrees OPTIONAL,
           excludedSubtrees        [1]     GeneralSubtrees OPTIONAL }

      GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree

      GeneralSubtree ::= SEQUENCE {
           base                    GeneralName,
           minimum         [0]     BaseDistance DEFAULT 0,
           maximum         [1]     BaseDistance OPTIONAL }

      BaseDistance ::= INTEGER (0..MAX)

4.2.1.11.  Policy Constraints

   The policy constraints extension can be used in certificates issued
   to CAs.  The policy constraints extension constrains path validation
   in two ways.  It can be used to prohibit policy mapping or require
   that each certificate in a path contain an acceptable policy
   identifier.

   If the inhibitPolicyMapping field is present, the value indicates the
   number of additional certificates that may appear in the path before
   policy mapping is no longer permitted.  For example, a value of one
   indicates that policy mapping may be processed in certificates issued
   by the subject of this certificate, but not in additional
   certificates in the path.

   If the requireExplicitPolicy field is present, the value of
   requireExplicitPolicy indicates the number of additional certificates
   that may appear in the path before an explicit policy is required for
   the entire path.  When an explicit policy is required, it is
   necessary for all certificates in the path to contain an acceptable
   policy identifier in the certificate policies extension.  An
   acceptable policy identifier is the identifier of a policy required
   by the user of the certification path or the identifier of a policy
   that has been declared equivalent through policy mapping.

   Conforming applications MUST be able to process the
   requireExplicitPolicy field and SHOULD be able to process the
   inhibitPolicyMapping field.  Applications that support the
   inhibitPolicyMapping field MUST also implement support for the
   policyMappings extension.  If the policyConstraints extension is
   marked as critical and the inhibitPolicyMapping field is present,
   applications that do not implement support for the
   inhibitPolicyMapping field MUST reject the certificate.

   Conforming CAs MUST NOT issue certificates where policy constraints
   is an empty sequence.  That is, either the inhibitPolicyMapping field
   or the requireExplicitPolicy field MUST be present.  The behavior of
   clients that encounter an empty policy constraints field is not
   addressed in this profile.

   Conforming CAs MUST mark this extension as critical.

   id-ce-policyConstraints OBJECT IDENTIFIER ::=  { id-ce 36 }

   PolicyConstraints ::= SEQUENCE {
        requireExplicitPolicy           [0] SkipCerts OPTIONAL,
        inhibitPolicyMapping            [1] SkipCerts OPTIONAL }

   SkipCerts ::= INTEGER (0..MAX)

4.2.1.12.  Extended Key Usage

   This extension indicates one or more purposes for which the certified
   public key may be used, in addition to or in place of the basic
   purposes indicated in the key usage extension.  In general, this
   extension will appear only in end entity certificates.  This
   extension is defined as follows:

   id-ce-extKeyUsage OBJECT IDENTIFIER ::= { id-ce 37 }

   ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId

   KeyPurposeId ::= OBJECT IDENTIFIER

   Key purposes may be defined by any organization with a need.  Object
   identifiers used to identify key purposes MUST be assigned in
   accordance with IANA or ITU-T Recommendation X.660 [X.660].

   This extension MAY, at the option of the certificate issuer, be
   either critical or non-critical.

   If the extension is present, then the certificate MUST only be used
   for one of the purposes indicated.  If multiple purposes are
   indicated the application need not recognize all purposes indicated,
   as long as the intended purpose is present.  Certificate using
   applications MAY require that the extended key usage extension be
   present and that a particular purpose be indicated in order for the
   certificate to be acceptable to that application.

   If a CA includes extended key usages to satisfy such applications,
   but does not wish to restrict usages of the key, the CA can include
   the special KeyPurposeId anyExtendedKeyUsage in addition to the
   particular key purposes required by the applications.  Conforming CAs
   SHOULD NOT mark this extension as critical if the anyExtendedKeyUsage
   KeyPurposeId is present.  Applications that require the presence of a
   particular purpose MAY reject certificates that include the
   anyExtendedKeyUsage OID but not the particular OID expected for the
   application.

   If a certificate contains both a key usage extension and an extended
   key usage extension, then both extensions MUST be processed
   independently and the certificate MUST only be used for a purpose
   consistent with both extensions.  If there is no purpose consistent
   with both extensions, then the certificate MUST NOT be used for any
   purpose.

   The following key usage purposes are defined:

   anyExtendedKeyUsage OBJECT IDENTIFIER ::= { id-ce-extKeyUsage 0 }

   id-kp OBJECT IDENTIFIER ::= { id-pkix 3 }

   id-kp-serverAuth             OBJECT IDENTIFIER ::= { id-kp 1 }
   -- TLS WWW server authentication
   -- Key usage bits that may be consistent: digitalSignature,
   -- keyEncipherment or keyAgreement

   id-kp-clientAuth             OBJECT IDENTIFIER ::= { id-kp 2 }
   -- TLS WWW client authentication
   -- Key usage bits that may be consistent: digitalSignature
   -- and/or keyAgreement

   id-kp-codeSigning             OBJECT IDENTIFIER ::= { id-kp 3 }
   -- Signing of downloadable executable code
   -- Key usage bits that may be consistent: digitalSignature

   id-kp-emailProtection         OBJECT IDENTIFIER ::= { id-kp 4 }
   -- Email protection
   -- Key usage bits that may be consistent: digitalSignature,
   -- nonRepudiation, and/or (keyEncipherment or keyAgreement)

   id-kp-timeStamping            OBJECT IDENTIFIER ::= { id-kp 8 }
   -- Binding the hash of an object to a time
   -- Key usage bits that may be consistent: digitalSignature
   -- and/or nonRepudiation

   id-kp-OCSPSigning            OBJECT IDENTIFIER ::= { id-kp 9 }
   -- Signing OCSP responses
   -- Key usage bits that may be consistent: digitalSignature
   -- and/or nonRepudiation

4.2.1.13.  CRL Distribution Points

   The CRL distribution points extension identifies how CRL information
   is obtained.  The extension SHOULD be non-critical, but this profile
   RECOMMENDS support for this extension by CAs and applications.
   Further discussion of CRL management is contained in Section 5.

   The cRLDistributionPoints extension is a SEQUENCE of
   DistributionPoint.  A DistributionPoint consists of three fields,
   each of which is optional: distributionPoint, reasons, and cRLIssuer.
   While each of these fields is optional, a DistributionPoint MUST NOT
   consist of only the reasons field; either distributionPoint or
   cRLIssuer MUST be present.  If the certificate issuer is not the CRL
   issuer, then the cRLIssuer field MUST be present and contain the Name
   of the CRL issuer.  If the certificate issuer is also the CRL issuer,
   then conforming CAs MUST omit the cRLIssuer field and MUST include
   the distributionPoint field.

   When the distributionPoint field is present, it contains either a
   SEQUENCE of general names or a single value, nameRelativeToCRLIssuer.
   If the DistributionPointName contains multiple values, each name
   describes a different mechanism to obtain the same CRL.  For example,
   the same CRL could be available for retrieval through both LDAP and
   HTTP.

   If the distributionPoint field contains a directoryName, the entry
   for that directoryName contains the current CRL for the associated
   reasons and the CRL is issued by the associated cRLIssuer.  The CRL
   may be stored in either the certificateRevocationList or
   authorityRevocationList attribute.  The CRL is to be obtained by the
   application from whatever directory server is locally configured.
   The protocol the application uses to access the directory (e.g., DAP
   or LDAP) is a local matter.

   If the DistributionPointName contains a general name of type URI, the
   following semantics MUST be assumed: the URI is a pointer to the
   current CRL for the associated reasons and will be issued by the
   associated cRLIssuer.  When the HTTP or FTP URI scheme is used, the
   URI MUST point to a single DER encoded CRL as specified in
   [RFC2585].  HTTP server implementations accessed via the URI SHOULD
   specify the media type application/pkix-crl in the content-type
   header field of the response.  When the LDAP URI scheme [RFC4516] is
   used, the URI MUST include a <dn> field containing the distinguished
   name of the entry holding the CRL, MUST include a single <attrdesc>
   that contains an appropriate attribute description for the attribute
   that holds the CRL [RFC4523], and SHOULD include a <host>
   (e.g., <ldap://ldap.example.com/cn=example%20CA,dc=example,dc=com?
   certificateRevocationList;binary>).  Omitting the <host> (e.g.,
   <ldap:///cn=CA,dc=example,dc=com?authorityRevocationList;binary>) has
   the effect of relying on whatever a priori knowledge the client might
   have to contact an appropriate server.  When present,
   DistributionPointName SHOULD include at least one LDAP or HTTP URI.

   If the DistributionPointName contains the single value
   nameRelativeToCRLIssuer, the value provides a distinguished name
   fragment.  The fragment is appended to the X.500 distinguished name
   of the CRL issuer to obtain the distribution point name.  If the
   cRLIssuer field in the DistributionPoint is present, then the name
   fragment is appended to the distinguished name that it contains;
   otherwise, the name fragment is appended to the certificate issuer
   distinguished name.  Conforming CAs SHOULD NOT use
   nameRelativeToCRLIssuer to specify distribution point names.  The
   DistributionPointName MUST NOT use the nameRelativeToCRLIssuer
   alternative when cRLIssuer contains more than one distinguished name.

   If the DistributionPoint omits the reasons field, the CRL MUST
   include revocation information for all reasons.  This profile
   RECOMMENDS against segmenting CRLs by reason code.  When a conforming
   CA includes a cRLDistributionPoints extension in a certificate, it
   MUST include at least one DistributionPoint that points to a CRL that
   covers the certificate for all reasons.

   The cRLIssuer identifies the entity that signs and issues the CRL.
   If present, the cRLIssuer MUST only contain the distinguished name
   (DN) from the issuer field of the CRL to which the DistributionPoint
   is pointing.  The encoding of the name in the cRLIssuer field MUST be
   exactly the same as the encoding in issuer field of the CRL.  If the
   cRLIssuer field is included and the DN in that field does not
   correspond to an X.500 or LDAP directory entry where CRL is located,
   then conforming CAs MUST include the distributionPoint field.

   id-ce-cRLDistributionPoints OBJECT IDENTIFIER ::=  { id-ce 31 }

   CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint

   DistributionPoint ::= SEQUENCE {
        distributionPoint       [0]     DistributionPointName OPTIONAL,
        reasons                 [1]     ReasonFlags OPTIONAL,
        cRLIssuer               [2]     GeneralNames OPTIONAL }

   DistributionPointName ::= CHOICE {
        fullName                [0]     GeneralNames,
        nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }

   ReasonFlags ::= BIT STRING {
        unused                  (0),
        keyCompromise           (1),
        cACompromise            (2),
        affiliationChanged      (3),
        superseded              (4),
        cessationOfOperation    (5),
        certificateHold         (6),
        privilegeWithdrawn      (7),
        aACompromise            (8) }

4.2.1.14.  Inhibit anyPolicy

   The inhibit anyPolicy extension can be used in certificates issued to
   CAs.  The inhibit anyPolicy extension indicates that the special
   anyPolicy OID, with the value { 2 5 29 32 0 }, is not considered an
   explicit match for other certificate policies except when it appears
   in an intermediate self-issued CA certificate.  The value indicates
   the number of additional non-self-issued certificates that may appear
   in the path before anyPolicy is no longer permitted.  For example, a
   value of one indicates that anyPolicy may be processed in
   certificates issued by the subject of this certificate, but not in
   additional certificates in the path.

   Conforming CAs MUST mark this extension as critical.

   id-ce-inhibitAnyPolicy OBJECT IDENTIFIER ::=  { id-ce 54 }

   InhibitAnyPolicy ::= SkipCerts

   SkipCerts ::= INTEGER (0..MAX)

4.2.1.15.  Freshest CRL (a.k.a. Delta CRL Distribution Point)

   The freshest CRL extension identifies how delta CRL information is
   obtained.  The extension MUST be marked as non-critical by conforming
   CAs.  Further discussion of CRL management is contained in Section 5.

   The same syntax is used for this extension and the
   cRLDistributionPoints extension, and is described in Section
   4.2.1.13.  The same conventions apply to both extensions.

   id-ce-freshestCRL OBJECT IDENTIFIER ::=  { id-ce 46 }

   FreshestCRL ::= CRLDistributionPoints
*/
/*
4.2.2.  Private Internet Extensions

   This section defines two extensions for use in the Internet Public
   Key Infrastructure.  These extensions may be used to direct
   applications to on-line information about the issuer or the subject.
   Each extension contains a sequence of access methods and access
   locations.  The access method is an object identifier that indicates
   the type of information that is available.  The access location is a
   GeneralName that implicitly specifies the location and format of the
   information and the method for obtaining the information.

   Object identifiers are defined for the private extensions.  The
   object identifiers associated with the private extensions are defined
   under the arc id-pe within the arc id-pkix.  Any future extensions
   defined for the Internet PKI are also expected to be defined under
   the arc id-pe.

      id-pkix  OBJECT IDENTIFIER  ::=
               { iso(1) identified-organization(3) dod(6) internet(1)
                       security(5) mechanisms(5) pkix(7) }

      id-pe  OBJECT IDENTIFIER  ::=  { id-pkix 1 }

4.2.2.1.  Authority Information Access

   The authority information access extension indicates how to access
   information and services for the issuer of the certificate in which
   the extension appears.  Information and services may include on-line
   validation services and CA policy data.  (The location of CRLs is not
   specified in this extension; that information is provided by the
   cRLDistributionPoints extension.)  This extension may be included in
   end entity or CA certificates.  Conforming CAs MUST mark this
   extension as non-critical.

   id-pe-authorityInfoAccess OBJECT IDENTIFIER ::= { id-pe 1 }

   AuthorityInfoAccessSyntax  ::=
           SEQUENCE SIZE (1..MAX) OF AccessDescription

   AccessDescription  ::=  SEQUENCE {
           accessMethod          OBJECT IDENTIFIER,
           accessLocation        GeneralName  }

   id-ad OBJECT IDENTIFIER ::= { id-pkix 48 }

   id-ad-caIssuers OBJECT IDENTIFIER ::= { id-ad 2 }

   id-ad-ocsp OBJECT IDENTIFIER ::= { id-ad 1 }

   Each entry in the sequence AuthorityInfoAccessSyntax describes the
   format and location of additional information provided by the issuer
   of the certificate in which this extension appears.  The type and
   format of the information are specified by the accessMethod field;
   the accessLocation field specifies the location of the information.
   The retrieval mechanism may be implied by the accessMethod or
   specified by accessLocation.

   This profile defines two accessMethod OIDs: id-ad-caIssuers and
   id-ad-ocsp.

   In a public key certificate, the id-ad-caIssuers OID is used when the
   additional information lists certificates that were issued to the CA
   that issued the certificate containing this extension.  The
   referenced CA issuers description is intended to aid certificate
   users in the selection of a certification path that terminates at a
   point trusted by the certificate user.

   When id-ad-caIssuers appears as accessMethod, the accessLocation
   field describes the referenced description server and the access
   protocol to obtain the referenced description.  The accessLocation
   field is defined as a GeneralName, which can take several forms.

   When the accessLocation is a directoryName, the information is to be
   obtained by the application from whatever directory server is locally
   configured.  The entry for the directoryName contains CA certificates
   in the crossCertificatePair and/or cACertificate attributes as
   specified in [RFC4523].  The protocol that application uses to access
   the directory (e.g., DAP or LDAP) is a local matter.

   Where the information is available via LDAP, the accessLocation
   SHOULD be a uniformResourceIdentifier.  The LDAP URI [RFC4516] MUST
   include a <dn> field containing the distinguished name of the entry
   holding the certificates, MUST include an <attributes> field that
   lists appropriate attribute descriptions for the attributes that hold
   the DER encoded certificates or cross-certificate pairs [RFC4523],
   and SHOULD include a <host> (e.g., <ldap://ldap.example.com/cn=CA,
   dc=example,dc=com?cACertificate;binary,crossCertificatePair;binary>).
   Omitting the <host> (e.g., <ldap:///cn=exampleCA,dc=example,dc=com?
   cACertificate;binary>) has the effect of relying on whatever a priori
   knowledge the client might have to contact an appropriate server.

   Where the information is available via HTTP or FTP, accessLocation
   MUST be a uniformResourceIdentifier and the URI MUST point to either
   a single DER encoded certificate as specified in [RFC2585] or a
   collection of certificates in a BER or DER encoded "certs-only" CMS
   message as specified in [RFC2797].

   Conforming applications that support HTTP or FTP for accessing
   certificates MUST be able to accept individual DER encoded
   certificates and SHOULD be able to accept "certs-only" CMS messages.

   HTTP server implementations accessed via the URI SHOULD specify the
   media type application/pkix-cert [RFC2585] in the content-type header
   field of the response for a single DER encoded certificate and SHOULD
   specify the media type application/pkcs7-mime [RFC2797] in the
   content-type header field of the response for "certs-only" CMS
   messages.  For FTP, the name of a file that contains a single DER
   encoded certificate SHOULD have a suffix of ".cer" [RFC2585] and the
   name of a file that contains a "certs-only" CMS message SHOULD have a
   suffix of ".p7c" [RFC2797].  Consuming clients may use the media type
   or file extension as a hint to the content, but should not depend
   solely on the presence of the correct media type or file extension in
   the server response.

   The semantics of other id-ad-caIssuers accessLocation name forms are
   not defined.

   An authorityInfoAccess extension may include multiple instances of
   the id-ad-caIssuers accessMethod.  The different instances may
   specify different methods for accessing the same information or may
   point to different information.  When the id-ad-caIssuers
   accessMethod is used, at least one instance SHOULD specify an
   accessLocation that is an HTTP [RFC2616] or LDAP [RFC4516] URI.

   The id-ad-ocsp OID is used when revocation information for the
   certificate containing this extension is available using the Online
   Certificate Status Protocol (OCSP) [RFC2560].

   When id-ad-ocsp appears as accessMethod, the accessLocation field is
   the location of the OCSP responder, using the conventions defined in
   [RFC2560].

   Additional access descriptors may be defined in other PKIX
   specifications.

4.2.2.2.  Subject Information Access

   The subject information access extension indicates how to access
   information and services for the subject of the certificate in which
   the extension appears.  When the subject is a CA, information and
   services may include certificate validation services and CA policy
   data.  When the subject is an end entity, the information describes
   the type of services offered and how to access them.  In this case,
   the contents of this extension are defined in the protocol
   specifications for the supported services.  This extension may be
   included in end entity or CA certificates.  Conforming CAs MUST mark
   this extension as non-critical.

   id-pe-subjectInfoAccess OBJECT IDENTIFIER ::= { id-pe 11 }

   SubjectInfoAccessSyntax  ::=
           SEQUENCE SIZE (1..MAX) OF AccessDescription

   AccessDescription  ::=  SEQUENCE {
           accessMethod          OBJECT IDENTIFIER,
           accessLocation        GeneralName  }

   Each entry in the sequence SubjectInfoAccessSyntax describes the
   format and location of additional information provided by the subject
   of the certificate in which this extension appears.  The type and
   format of the information are specified by the accessMethod field;
   the accessLocation field specifies the location of the information.
   The retrieval mechanism may be implied by the accessMethod or
   specified by accessLocation.

   This profile defines one access method to be used when the subject is
   a CA and one access method to be used when the subject is an end
   entity.  Additional access methods may be defined in the future in
   the protocol specifications for other services.

   The id-ad-caRepository OID is used when the subject is a CA that
   publishes certificates it issues in a repository.  The accessLocation
   field is defined as a GeneralName, which can take several forms.

   When the accessLocation is a directoryName, the information is to be
   obtained by the application from whatever directory server is locally
   configured.  When the extension is used to point to CA certificates,
   the entry for the directoryName contains CA certificates in the
   crossCertificatePair and/or cACertificate attributes as specified in
   [RFC4523].  The protocol the application uses to access the directory
   (e.g., DAP or LDAP) is a local matter.

   Where the information is available via LDAP, the accessLocation
   SHOULD be a uniformResourceIdentifier.  The LDAP URI [RFC4516] MUST
   include a <dn> field containing the distinguished name of the entry
   holding the certificates, MUST include an <attributes> field that
   lists appropriate attribute descriptions for the attributes that hold
   the DER encoded certificates or cross-certificate pairs [RFC4523],
   and SHOULD include a <host> (e.g., <ldap://ldap.example.com/cn=CA,
   dc=example,dc=com?cACertificate;binary,crossCertificatePair;binary>).

   Omitting the <host> (e.g., <ldap:///cn=exampleCA,dc=example,dc=com?
   cACertificate;binary>) has the effect of relying on whatever a priori
   knowledge the client might have to contact an appropriate server.

   Where the information is available via HTTP or FTP, accessLocation
   MUST be a uniformResourceIdentifier and the URI MUST point to either
   a single DER encoded certificate as specified in [RFC2585] or a
   collection of certificates in a BER or DER encoded "certs-only" CMS
   message as specified in [RFC2797].

   Conforming applications that support HTTP or FTP for accessing
   certificates MUST be able to accept individual DER encoded
   certificates and SHOULD be able to accept "certs-only" CMS messages.

   HTTP server implementations accessed via the URI SHOULD specify the
   media type application/pkix-cert [RFC2585] in the content-type header
   field of the response for a single DER encoded certificate and SHOULD
   specify the media type application/pkcs7-mime [RFC2797] in the
   content-type header field of the response for "certs-only" CMS
   messages.  For FTP, the name of a file that contains a single DER
   encoded certificate SHOULD have a suffix of ".cer" [RFC2585] and the
   name of a file that contains a "certs-only" CMS message SHOULD have a
   suffix of ".p7c" [RFC2797].  Consuming clients may use the media type
   or file extension as a hint to the content, but should not depend
   solely on the presence of the correct media type or file extension in
   the server response.

   The semantics of other id-ad-caRepository accessLocation name forms
   are not defined.

   A subjectInfoAccess extension may include multiple instances of the
   id-ad-caRepository accessMethod.  The different instances may specify
   different methods for accessing the same information or may point to
   different information.  When the id-ad-caRepository accessMethod is
   used, at least one instance SHOULD specify an accessLocation that is
   an HTTP [RFC2616] or LDAP [RFC4516] URI.

   The id-ad-timeStamping OID is used when the subject offers
   timestamping services using the Time Stamp Protocol defined in
   [RFC3161].  Where the timestamping services are available via HTTP or
   FTP, accessLocation MUST be a uniformResourceIdentifier.  Where the
   timestamping services are available via electronic mail,
   accessLocation MUST be an rfc822Name.  Where timestamping services
   are available using TCP/IP, the dNSName or iPAddress name forms may
   be used.  The semantics of other name forms of accessLocation (when
   accessMethod is id-ad-timeStamping) are not defined by this
   specification.

   Additional access descriptors may be defined in other PKIX
   specifications.

   id-ad OBJECT IDENTIFIER ::= { id-pkix 48 }

   id-ad-caRepository OBJECT IDENTIFIER ::= { id-ad 5 }

   id-ad-timeStamping OBJECT IDENTIFIER ::= { id-ad 3 }
*/
		if (typeof obj != 'undefined' && 
			obj.tagClass == jCastle.asn1.tagClassContextSpecific &&
			obj.type == 0x03 &&
			obj.items[0].type == jCastle.asn1.tagSequence
		) {
			var extensions = this._parseExtensions(obj.items[0]);
			tbs_info.extensions = extensions;
		}

		return tbs_info;
	}

	/**
	 * parses extension of the certificate.
	 * 
	 * @private
	 * 
	 * @param {object} sequence asn1 sequence object
	 * 
	 * @returns the extension object.
	 */
	_parseExtensions(sequence)
	{
		var ext = {};

		for (var i = 0; i < sequence.items.length; i++) {
			var seq = sequence.items[i];

			var ext_name = jCastle.oid.getName(seq.items[0].value, this.config);

			if (!ext_name) throw jCastle.exception("UNSUPPORTED_EXTENSION", 'CRT027');

	//		try {
				ext[ext_name] = jCastle.certificate.extensions[ext_name].parse(seq, this.config);
	//		} catch (e) {
				//throw jCastle.exception("UNSUPPORTED_EXTENSION", 'CRT028');
	//		}
		}

		return ext;
	}

/*
Certificate  ::=  SEQUENCE  {
        tbsCertificate       TBSCertificate,
        signatureAlgorithm   AlgorithmIdentifier,
        signatureValue       BIT STRING  }

   TBSCertificate  ::=  SEQUENCE  {
        version         [0]  EXPLICIT Version DEFAULT v1,
        serialNumber         CertificateSerialNumber,
        signature            AlgorithmIdentifier,
        issuer               Name,
        validity             Validity,
        subject              Name,
        subjectPublicKeyInfo SubjectPublicKeyInfo,
        issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
                             -- If present, version MUST be v2 or v3
        subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
                             -- If present, version MUST be v2 or v3
        extensions      [3]  EXPLICIT Extensions OPTIONAL
                             -- If present, version MUST be v3
        }

   Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }

   CertificateSerialNumber  ::=  INTEGER

   Validity ::= SEQUENCE {
        notBefore      Time,
        notAfter       Time }

   Time ::= CHOICE {
        utcTime        UTCTime,
        generalTime    GeneralizedTime }

   UniqueIdentifier  ::=  BIT STRING

   SubjectPublicKeyInfo  ::=  SEQUENCE  {
        algorithm            AlgorithmIdentifier,
        subjectPublicKey     BIT STRING  }

   Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension

   Extension  ::=  SEQUENCE  {
        extnID      OBJECT IDENTIFIER,
        critical    BOOLEAN DEFAULT FALSE,
        extnValue   OCTET STRING
                    -- contains the DER encoding of an ASN.1 value
                    -- corresponding to the extension type identified
                    -- by extnID
        }

   The following items describe the X.509 v3 certificate for use in the
   Internet.
/*
 4.2 CertificationRequest

   A certification request shall have ASN.1 type CertificationRequest:

   CertificationRequest ::= SEQUENCE {
        certificationRequestInfo CertificationRequestInfo,
        signatureAlgorithm AlgorithmIdentifier{{ SignatureAlgorithms }},
        signature          BIT STRING
   }

   AlgorithmIdentifier {ALGORITHM:IOSet } ::= SEQUENCE {
        algorithm          ALGORITHM.&id({IOSet}),
        parameters         ALGORITHM.&Type({IOSet}{@algorithm}) OPTIONAL
   }

   SignatureAlgorithms ALGORITHM ::= {
        ... -- add any locally defined algorithms here -- }
*/
/*
5.1.  CRL Fields

   The X.509 v2 CRL syntax is as follows.  For signature calculation,
   the data that is to be signed is ASN.1 DER encoded.  ASN.1 DER
   encoding is a tag, length, value encoding system for each element.

   CertificateList  ::=  SEQUENCE  {
        tbsCertList          TBSCertList,
        signatureAlgorithm   AlgorithmIdentifier,
        signatureValue       BIT STRING  }

   TBSCertList  ::=  SEQUENCE  {
        version                 Version OPTIONAL,
                                     -- if present, MUST be v2
        signature               AlgorithmIdentifier,
        issuer                  Name,
        thisUpdate              Time,
        nextUpdate              Time OPTIONAL,
        revokedCertificates     SEQUENCE OF SEQUENCE  {
             userCertificate         CertificateSerialNumber,
             revocationDate          Time,
             crlEntryExtensions      Extensions OPTIONAL
                                      -- if present, version MUST be v2
                                  }  OPTIONAL,
        crlExtensions           [0]  EXPLICIT Extensions OPTIONAL
                                      -- if present, version MUST be v2
                                  }

   -- Version, Time, CertificateSerialNumber, and Extensions
   -- are all defined in the ASN.1 in Section 4.1

   -- AlgorithmIdentifier is defined in Section 4.1.1.2
*/

	// if reuseSignature is true then,
	// signature is not created but the signature that cert_info has will be reused.
	// this is for the test of certificate. if you want to check whether the certificate is made well.
	/**
	 * builds certificate schema obejct.
	 * 
	 * @private
	 * 
	 * @param {object} cert_info certificate schema object
	 * @param {object} sign_pki pki object for signKey
	 * @param {boolean} reuseSignature if true then the signature of cert_info is re-used.
	 * 
	 * @returns the certificate schema object.
	 */
	_getCertificateSchema(cert_info, sign_pki, reuseSignature)
	{
		if (typeof cert_info != 'object') {
			throw jCastle.exception("INVALID_CERT_INFO", 'CRT029');
		}

		var tbsCertificate = this._getTbsSchema(cert_info, sign_pki);

		//var tbsCertificateDER = new jCastle.asn1().getDER(tbsCertificate);
		var tbsCertBuf = new jCastle.asn1().getBuffer(tbsCertificate);
		var signature;

		if (!reuseSignature) {	
			switch (cert_info.algo.signAlgo.toUpperCase()) {
				case 'RSASSA-PSS': 
					signature = sign_pki.pssSign(
						//tbsCertificateDER, {
						tbsCertBuf, {
							hashAlgo: cert_info.algo.signHash,
							saltLength: cert_info.algo.saltLength
						}
					);
					break;
				case 'RSASSA-PKCS1-V1_5':
				case 'DSA':
				case 'ECDSA':
				case 'KCDSA':
				case 'ECKCDSA':
				default:
					signature = sign_pki.sign(
						//tbsCertificateDER, {
						tbsCertBuf, {
							hashAlgo: cert_info.algo.signHash
						}
					);
					break;
			}
			//signature = signature.toString('latin1');

		} else {
			signature = cert_info.signature;
		}

		var cert_schema = {
			type: jCastle.asn1.tagSequence,
			items: [
				tbsCertificate,
				jCastle.certificate.asn1.signAlgorithm.schema(cert_info.algo.signHash, cert_info.algo.signAlgo),
				jCastle.certificate.asn1.signature.schema(signature)
			]
		};

		return cert_schema;
	}

	/**
	 * builds tbs schema object.
	 * 
	 * @private
	 * 
	 * @param {object} cert_info 
	 * @param {object} sign_pki pki object
	 * 
	 * @returns the tbs schema object.
	 */
	_getTbsSchema(cert_info, sign_pki)
	{
		if (!('version' in cert_info.tbs)) {
			switch (cert_info.type) {
				case jCastle.certificate.typeCRT:
/*
4.1.2.1.  Version

   This field describes the version of the encoded certificate.  When
   extensions are used, as expected in this profile, version MUST be 3
   (value is 2).  If no extensions are present, but a UniqueIdentifier
   is present, the version SHOULD be 2 (value is 1); however, the
   version MAY be 3.  If only basic fields are present, the version
   SHOULD be 1 (the value is omitted from the certificate as the default
   value); however, the version MAY be 2 or 3.

   Implementations SHOULD be prepared to accept any version certificate.
   At a minimum, conforming implementations MUST recognize version 3
   certificates.

   Generation of version 2 certificates is not expected by
   implementations based on this profile.
*/
					cert_info.tbs.version = 0x00; 
					break;
				case jCastle.certificate.typeCRL:
/*
5.1.2.1.  Version

   This optional field describes the version of the encoded CRL.  When
   extensions are used, as required by this profile, this field MUST be
   present and MUST specify version 2 (the integer value is 1).
*/
					cert_info.tbs.version = 0x00;
					break;
				case jCastle.certificate.typeCSR:
					cert_info.tbs.version = 0x00;
					break;
				default:
					throw jCastle.exception("UNSUPPORTED_CERT_TYPE", 'CRT030');
			}
		}

		if (cert_info.type == jCastle.certificate.typeCRT) {
			cert_info.tbs.serialNumber = cert_info.tbs.serialNumber || false;

			if (!cert_info.tbs.serialNumber) { // generate serialNumber
				var bytes = new jCastle.prng().nextBytes(4);
				var serial = BigInt.fromBufferUnsigned(bytes);
				//console.log(serial.gt(0n));
				//serial = serial.intValue();
				cert_info.tbs.serialNumber = serial;

				// console.log('generated serial: ', serial.toString());
			}
		}

		if (cert_info.type != jCastle.certificate.typeCRL && !('subjectPublicKeyInfo' in cert_info.tbs)) {
			throw jCastle.exception("PUBKEYINFO_NOT_SET", 'CRT031');
		}

		if (cert_info.type != jCastle.certificate.typeCSR && 
			!('algo' in cert_info) && 'algo' in cert_info.tbs) {
			cert_info.algo = cert_info.tbs.algo;
		}

		cert_info.algo.signHash = 'signHash' in cert_info.algo ? jCastle.digest.getValidAlgoName(cert_info.algo.signHash) : 'SHA-1';
		cert_info.algo.signAlgo = 'signAlgo' in cert_info.algo ? cert_info.algo.signAlgo : sign_pki.pkiName;

		if (cert_info.algo.signAlgo == 'RSA') cert_info.algo.signAlgo = 'RSASSA-PKCS1-V1_5';
		if (cert_info.algo.signAlgo == 'RSA-PSS') cert_info.algo.signAlgo = 'RSASSA-PSS';

		if (cert_info.type != jCastle.certificate.typeCSR && 
			(!('algo' in cert_info.tbs) || 
			cert_info.tbs.algo.signAlgo != cert_info.algo.signAlgo ||
			cert_info.tbs.algo.signHash != cert_info.algo.signHash)
		) {
			cert_info.tbs.algo = cert_info.algo;
		}
	
	/*
	Certificate:

	TBSCertificate  ::=  SEQUENCE  {
        version         [0]  EXPLICIT Version DEFAULT v1,
        serialNumber         CertificateSerialNumber,
        signature            AlgorithmIdentifier,
        issuer               Name,
        validity             Validity,
        subject              Name,
        subjectPublicKeyInfo SubjectPublicKeyInfo,
        issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
                             -- If present, version MUST be v2 or v3
        subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
                             -- If present, version MUST be v2 or v3
        extensions      [3]  EXPLICIT Extensions OPTIONAL
        -- If present, version MUST be v3
    }

	CRL:

   TBSCertList  ::=  SEQUENCE  {
        version                 Version OPTIONAL,
                                     -- if present, MUST be v2
        signature               AlgorithmIdentifier,
        issuer                  Name,
        thisUpdate              Time,
        nextUpdate              Time OPTIONAL,
        revokedCertificates     SEQUENCE OF SEQUENCE  {
             userCertificate         CertificateSerialNumber,
             revocationDate          Time,
             crlEntryExtensions      Extensions OPTIONAL
                                      -- if present, version MUST be v2
                                  }  OPTIONAL,
        crlExtensions           [0]  EXPLICIT Extensions OPTIONAL
                                      -- if present, version MUST be v2
                                  }
	*/
		var tbsCertificate = {
			type: jCastle.asn1.tagSequence,
			items: []
		};
/*
		// we don't know what version will be used yet. 
		if (!isCSR && (typeof cert_info.tbs.extensions != 'undefined' || cert_info.tbs.extensions)) {
			tbsCertificate.items.push({
				tagClass: jCastle.asn1.tagClassContextSpecific,
				type: 0x00,
				constructed: true,
				items: [{ // version
					type: jCastle.asn1.tagInteger,
					value: cert_info.tbs.version // default
				}]
			});
		}
*/

		// serial number
		if (cert_info.type == jCastle.certificate.typeCRT) {
			tbsCertificate.items.push({
				type: jCastle.asn1.tagInteger,
				intVal: cert_info.tbs.serialNumber
			});
		}

		// sign algorithm
		// issuer
		if (cert_info.type != jCastle.certificate.typeCSR) {
			tbsCertificate.items.push(
				jCastle.certificate.asn1.signAlgorithm.schema(cert_info.algo.signHash, cert_info.algo.signAlgo), 
				jCastle.certificate.asn1.directoryName.schema(cert_info.tbs.issuer)
			);
		}

		// validity
		if (cert_info.type == jCastle.certificate.typeCRT) {
			var default_days = 365;
			if (this.config && 'ca' in this.config && 'default_ca' in this.config.ca && 'default_days' in this.config.ca.default_ca)
				default_days = this.config.ca.default_ca;

			tbsCertificate.items.push(
				jCastle.certificate.asn1.validity.schema(cert_info.tbs.validity, default_days)
			);
		}

		// subject
		// subject public key info
		if (cert_info.type != jCastle.certificate.typeCRL) {
			tbsCertificate.items.push(
				jCastle.certificate.asn1.directoryName.schema(cert_info.tbs.subject),
				jCastle.certificate.asn1.publicKeyInfo.schema(cert_info.tbs.subjectPublicKeyInfo)
			);
		}
		
		if (cert_info.type == jCastle.certificate.typeCRT) {
			// issuer unique id
			if ('issuerUniqueID' in cert_info.tbs) {
				tbsCertificate.items.push({
					tagClass: jCastle.asn1.tagClassContextSpecific,
					type: 0x01,
					value: cert_info.tbs.issuerUniqueID
				});

				cert_info.tbs.version = 0x01;
			}

			// subject unique id
			if ('subjectUniqueID' in cert_info.tbs) {
				tbsCertificate.items.push({
					tagClass: jCastle.asn1.tagClassContextSpecific,
					type: 0x02,
					value: cert_info.tbs.subjectUniqueID
				});

				cert_info.tbs.version = 0x01;
			}
		}

		// thisUpdate
		// nextUpdate
		// revokedCertificates
		if (cert_info.type == jCastle.certificate.typeCRL) {
			tbsCertificate.items.push({
				type: jCastle.asn1.tagUTCTime,
				value: cert_info.tbs.thisUpdate
			});

			if ('nextUpdate' in cert_info.tbs) {
				tbsCertificate.items.push({
					type: jCastle.asn1.tagUTCTime,
					value: cert_info.tbs.nextUpdate
				});
			}

			tbsCertificate.items.push(
				jCastle.certificate.asn1.revokedCerts.schema(cert_info.tbs.revokedCertificates)
			);

			for (var r = 0; r < cert_info.tbs.revokedCertificates.length; r++) {
				if ('crlEntryExtensions' in cert_info.tbs.revokedCertificates[r]) {
					cert_info.tbs.version = 0x01;
					break;
				}
			}
		}

		// extensions
		var extensions;

		if (cert_info.type == jCastle.certificate.typeCSR) {
			var extensionRequest = [];

			var extSchema = {
				tagClass: jCastle.asn1.tagClassContextSpecific,
				type: 0x00,
				constructed: true,
				items: [] // empty
			};

			if ('extensionRequest' in cert_info.tbs) {
/*
extensionRequest can be empty!

[0]

or 

[0](1 elem)
	SEQUENCE(2 elem)
		OBJECT IDENTIFIER					1.2.840.113549.1.9.14 -- extensionRequest
		SET(1 elem)
			SEQUENCE(1 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER		2.5.29.17 -- subjectAltName
					OCTET STRING(1 elem)
						SEQUENCE(1 elem)
							[2]				client.example.com
*/
		
				var ext = cert_info.tbs.extensionRequest;

				for (var ext_name in ext) {
					//if (ext.hasOwnProperty(ext_name)) {
						extensionRequest.push(jCastle.certificate.extensions[ext_name].schema(ext[ext_name], ext_name, this.config));
					//}
				}

				var extRequestSchema = {
					type: jCastle.asn1.tagSequence,
					items: [{
						type: jCastle.asn1.tagOID,
						value: jCastle.oid.getOID("extensionRequest")
					}, {
						type: jCastle.asn1.tagSet,
						items: [{
							type: jCastle.asn1.tagSequence,
							items: extensionRequest
						}]
					}]
				};

				extSchema.items.push(extRequestSchema);
			}
/*
[0](1 elem)
	SEQUENCE(2 elem)
		OBJECT IDENTIFIER					1.2.840.113549.1.9.7 -- challengePassword
		SET(1 elem)
			UTF8String						password
*/
			if ('challengePassword' in cert_info.tbs) {
				var cpSchema = {
					type: jCastle.asn1.tagSequence,
					items: [{
						type: jCastle.asn1.tagOID,
						value: jCastle.oid.getOID("challengePassword")
					}, {
						type: jCastle.asn1.tagSet,
						items: [{
							type: jCastle.asn1.tagUTF8String,
							value: cert_info.tbs.challengePassword
						}]
					}]
				};

				extSchema.items.push(cpSchema);
			}

			if (extSchema.items.length)
				tbsCertificate.items.push(extSchema);

		} else if (cert_info.type == jCastle.certificate.typeCRT &&
			'extensions' in cert_info.tbs
		) {
			extensions = [];
			var ext = cert_info.tbs.extensions;

			for (var ext_name in ext) {
				//if (ext.hasOwnProperty(ext_name)) {
					extensions.push(jCastle.certificate.extensions[ext_name].schema(ext[ext_name], ext_name, this.config));
				//}
			}

			if (extensions.length) {
				var extensionsSchema = {
					tagClass: jCastle.asn1.tagClassContextSpecific,
					type: 0x03,
					constructed: true,
					items: [{
						type: jCastle.asn1.tagSequence,
						items: extensions
					}]
				};
				tbsCertificate.items.push(extensionsSchema);

				cert_info.tbs.version = 0x02;
			}
		} else if (cert_info.type == jCastle.certificate.typeCRL &&
			'crlExtensions' in cert_info.tbs
		) {
			extensions = [];
			var ext = cert_info.tbs.crlExtensions;

			for (var ext_name in ext) {
				//if (ext.hasOwnProperty(ext_name)) {
					extensions.push(jCastle.certificate.extensions[ext_name].schema(ext[ext_name], ext_name, this.config));
				//}
			}

			if (extensions.length) {
				var extensionsSchema = {
					tagClass: jCastle.asn1.tagClassContextSpecific,
					type: 0x00,
					constructed: true,
					items: [{
						type: jCastle.asn1.tagSequence,
						items: extensions
					}]
				};
				tbsCertificate.items.push(extensionsSchema);

				cert_info.tbs.version = 0x01;
			}
		}

		// version - unshifting
		if (cert_info.type == jCastle.certificate.typeCRT) {
			// if 0, then omitted(version 1)
			if (cert_info.tbs.version > 0) {
				tbsCertificate.items.unshift({
					tagClass: jCastle.asn1.tagClassContextSpecific,
					type: 0x00,
					constructed: true,
					items: [{ // version
						type: jCastle.asn1.tagInteger,
						intVal: cert_info.tbs.version
					}]
				});
			}
		} else {
			if (cert_info.tbs.version > 0) {
				tbsCertificate.items.unshift({
					type: jCastle.asn1.tagInteger,
					intVal: cert_info.tbs.version
				});
			}
		}

		return tbsCertificate;
	}

	/**
	 * extract publicKey from the certificate.
	 * 
	 * @public
	 * 
	 * @returns the publicKey from the certificate.
	 */
	exportPublicKey()
	{
		return this.certInfo && this.certInfo.tbs ? jCastle.pki.createFromPublicKeyInfo(this.certInfo.tbs.subjectPublicKeyInfo) : null;
	}

	/**
	 * alias function of exportPublicKey()
	 * 
	 * @public
	 * 
	 * @returns the publicKey from the certificate.
	 */
	createPKIFromPublicKeyInfo()
	{
		return this.exportPublicKey();
	}

	/**
	 * gets subjectPublicKeyInfo of the certificate.
	 * 
	 * @public
	 * 
	 * @returns the subjectPublicKeyInfo object.
	 */
	getSubjectPublicKeyInfo()
	{
		return this.certInfo && this.certInfo.tbs ? this.certInfo.tbs.subjectPublicKeyInfo : null;
	}

	/**
	 * register extension function.
	 * 
	 * @public 
	 * 
	 * @param {string} ext_name extension name string
	 * @param {function} parse_func function for parsing the extension.
	 * @param {function} schema_func function for building the schema object of the extension.
	 */
	registerExtension(ext_name, parse_func, schema_func)
	{
		return jCastle.certificate.registerExtension(ext_name, parse_func, schema_func);
	}

	/**
	 * 
	 * @param {string} otherName rule name of a otherName.
	 * @param {function} parse_func function for parsing the otherName.
	 * @param {function} schema_func function for building the schema object of the otherName.
	 */
	registerOtherNameRule(otherName, parse_func, schema_func)
	{
		return jCastle.certificate.registerOtherNameRule(otherName, parse_func, schema_func);
	}
};

/**
 * creates certificate class instance.
 * 
 * @public
 * 
 * @returns certificate class instance.
 */
jCastle.certificate.create = function()
{
	return new jCastle.certificate();
};

/**
 * parses input data for certificate.
 * 
 * @public
 * 
 * @param {buffer} pem pem data of certificate.
 * @param {string} format pem format. 'buffer' | 'der' | 'hex' | 'base64' | 'object'. (default: 'auto')
 * @param {integer} type a asn1 type integer. (default: jCastle.certificate.typeCRT)
 * 
 * @returns the certificate object.
 */
jCastle.certificate.parse = function(pem, format, type)
{
	return new jCastle.certificate().parse(pem, format, type);
};

/**
 * accepts OpenSSL's cnf string or a parsed object and sets it.
 * 
 * @public
 * 
 * @param {mixed} config OpenSSL's cnf string or a parsed object.
 * 
 * @returns this class instance.
 */
jCastle.certificate.setConfig = function(config)
{
	return new jCastle.certificate().setConfig(config);
};

/**
 * sets pki for a sign key.
 * 
 * @public
 * 
 * @param {mixed} signkey a pki object, or PEM string. A asn1 parsed object can be given for it.
 * @param {buffer} password a string or buffer value for password
 * 
 * @returns this class instance.
 */
jCastle.certificate.setSignKey = function(signkey, password)
{
	return new jCastle.certificate().setSignKey(signkey, password);
};

jCastle.certificate.extensions = {};
jCastle.certificate.otherNameRules = {};

jCastle.certificate.typeCRT = 0x01;
jCastle.certificate.typeCSR = 0x02;
jCastle.certificate.typeCRL = 0x03;


jCastle.certificate.getBuffer = function(certInfo)
{
	// we need a function that can build der from certInfo.
	// the third parameter of exportCertificate() is for it.
	// if the third parameter is true, then signaure of cert_info will be used,
	// not generated by sign key for there is no sign key known.
	var buf;

	if (jCastle.util.isString(certInfo)) { // pem or der string
		var format = jCastle.util.seekPemFormat(certInfo);
		switch (format) {
			case 'pem':
				var pem = certInfo.replace(/-----(BEGIN|END) (X509 CRL|(NEW )?CERTIFICATE( REQUEST)?)-----/g, '').replace(/[ \t\r\n]/g, '');
				return Buffer.from(pem, 'base64');
			case 'hex':
				return Buffer.from(certInfo, 'hex');
			case 'base64':
				return Buffer.from(certInfo, 'base64');
			case 'der':
				return Buffer.from(certInfo, 'latin1');
			default:
				return Buffer.from(certInfo);
		}
	} else if (Buffer.isBuffer(certInfo)) {
		return certInfo;
	} else { // certificateInfo or certificate object
		if (certInfo instanceof jCastle.certificate) {
			var cert = certInfo;
			if (cert.certInfo) {
				buf =  'buffer' in cert.certInfo ? cert.certInfo.buffer : cert.exportCertificate(cert.certInfo, 'buffer', true);
			} else {
				throw jCastle.exception('INVALID_CERT_INFO', 'CRT032');
			}
		} else {
			buf = new jCastle.certificate().exportCertificate(certInfo, 'buffer', true);
		}
		return buf;
	}
};

jCastle.certificate.getDER = function(certInfo)
{
	var buf = jCastle.certificate.getBuffer(certInfo);
	return buf.toString('latin1');
};

/**
 * register extension function.
 * 
 * @public 
 * 
 * @param {string} ext_name extension name string
 * @param {function} parse_func function for parsing the extension.
 * @param {function} schema_func function for building the schema object of the extension.
 */
jCastle.certificate.registerExtension = function(ext_name, parse_func, schema_func)
{
	//if (ext_name in jCastle.certificate.extensions) return false;

	if (typeof parse_func != 'function' || typeof schema_func != 'function') return false;

	jCastle.certificate.extensions[ext_name] = {
		parse: parse_func,
		schema: schema_func
	};

	return true;
};

/**
 * 
 * @param {string} otherName rule name of a otherName.
 * @param {function} parse_func function for parsing the otherName.
 * @param {function} schema_func function for building the schema object of the otherName.
 */
jCastle.certificate.registerOtherNameRule = function(otherName, parse_func, schema_func)
{
	if (typeof parse_func != 'function' || typeof schema_func != 'function') {
		return false;
	}

	jCastle.certificate.otherNameRules[otherName] = {
		parse: parse_func,
		schema: schema_func
	};
	
	return true;
};

jCastle.certificate.fn = {

/*
var revoked_cert_list = [
	{
		userCertificate: serial,
		revocationDate: "2013-02-18 10:22:12 UTC",
		crlEntryExtensions: {
			cRLReason: "affiliationChanged",
			invalidityDate: "2013-02-18 10:22:00 UTC"
		}
	},
	{
		userCertificate: serial,
		revocationDate: "2013-02-18 10:22:22 UTC",
		crlEntryExtensions: {
			cRLReason: "certificateHold",
			invalidityDate: "2013-02-18 10:22:00 UTC"
		}
	},
	{
		userCertificate: serial,
		revocationDate: "2013-02-18 10:22:32 UTC",
		crlEntryExtensions: {
			cRLReason: "superseded",
			invalidityDate: "2013-02-18 10:22:00 UTC"
		}
	},
	{
		userCertificate: serial,
		revocationDate: "2013-02-18 10:22:42 UTC",
		crlEntryExtensions: {
			cRLReason: "keyCompromise",
			invalidityDate: "2013-02-18 10:22:00 UTC"
		}
	},
	{
		userCertificate: serial,
		revocationDate: "2013-02-18 10:22:51 UTC",
		crlEntryExtensions: {
			cRLReason: "cessationOfOperation",
			invalidityDate: "2013-02-18 10:22:00 UTC"
		}
	}
];

or 
var revoked_cert_list = [
	{
		serial: serial,
		revoked: "2013-02-18 10:22:12 UTC",
		reason: "affiliationChanged",
		invalid: "2013-02-18 10:22:00 UTC"
	}
	...
];
*/
	reviseRevokedCertificates: function(revoked_list)
	{
		var list = [];

		for (var i = 0; i < revoked_list.length; i++) {
			var l = {};
			var f = revoked_list[i];

			// serial
			l.userCertificate = 'userCertificate' in f ? f.userCertificate : ('serial' in f ? f.serial : false);
			if (!l.userCertificate) {
				throw jCastle.exception("SERIAL_NOT_GIVEN", 'CRT033');
			}
			if (jCastle.util.isString(l.userCertificate) && /^[0-9A-F]+$/i.test(l.userCertificate)) {
				l.userCertificate = BigInt('0x' + l.userCertificate);
			}

			// revoked
			l.revocationDate = 'revocationDate' in f ? f.revocationDate : ('revoked' in f ? f.revoked : new Date());

			l.crlEntryExtensions = {};

			// reason
			l.crlEntryExtensions.cRLReason = ('crlEntryExtensions' in f && 'cRLReason' in f.crlEntryExtensions) ? 
					f.crlEntryExtensions.cRLReason : ('reason' in f ? f.reason : 'unspecified');

			// invalid
			l.crlEntryExtensions.invalidityDate = ('crlEntryExtensions' in f && 'invalidityDate' in f.crlEntryExtensions) ?
					f.crlEntryExtensions.invalidityDate : ('invalid' in f ? f.invalid : new Date());

			list.push(l);
		}

		return list;
	},

	isSignAlgoSameWithPKI: function(sign_algo, sign_key)
	{
		if (sign_algo == sign_key.pkiName) return true;

		switch (sign_algo) {
			case 'RSASSA-PKCS1-V1_5':
			case 'RSASSA-PSS':
				return sign_key.pkiName == 'RSA';
	//		case 'DSA':
	//			return sign_key.pkiName == 'DSA';
	//		case 'KCDSA':
	//			return sign_key.pkiName == 'KCDSA';
	//		case 'ECDSA':
	//			return sign_key.pkiName == 'EC';
	//		case 'ECKCDSA':
	//			return sign_key.pkiName == 'ECKCDSA';
			default:
				return false;
		}
	},

	reviseDirectoryName: function(dn)
	{
		var n = [];

		for (var i = 0; i < dn.length; i++) {
			var field = dn[i];
			var name;

			switch (field.name.toUpperCase()) {
				case 'COUNTRYNAME':
				case 'C':
					name = 'countryName';
					break;
				case 'STATEORPROVINCENAME':
				case 'ST':
					name = 'stateOrProvinceName';
					break;
				case 'LOCALITYNAME':
				case 'L':
					name = 'localityName';
					break;
				case 'ORGANIZATIONNAME':
				case 'O':
					name = 'organizationName';
					break;
				case 'ORGANIZATIONALUNITNAME':
				case 'OU':
					name = 'organizationalUnitName';
					break;
				case 'COMMONNAME':
				case 'CN':
					name = 'commonName';
					break;
				case 'EMAILADDRESS':
				case 'E':
					name = 'emailAddress';
					break;
				case 'STREETADDRESS':
				case 'STREET':
					name = 'streetAddress';
					break;
			}

			var value = field.value;

			var o = {
				name: name,
				value: value
			};

			if ('type' in field) o.type = field.type;

			n.push(o);
		}

		return n;
	},

	transformConfigExtensions: function(cert_build, config, req_pki, sign_pki, cert_info)
	{
		var extensions;

		switch (cert_build.type) {
			case jCastle.certificate.typeCSR:
				extensions = cert_build.tbs.extensionRequest; break;
			case jCastle.certificate.typeCRL:
				extensions = cert_build.tbs.crlExtensions; break;
			default:
				extensions = cert_build.tbs.extensions; break;
		}

		for (var ext in extensions) {
			switch (ext) {
				case 'subjectAltName':
					var i = 0;
					var finish = false;
					do {
						if (jCastle.util.isString(extensions[ext][i]) && extensions[ext][i] == 'copy') {
							// get email from subject
							var changed = false;
							var subject = cert_build.tbs.subject;

							for (var j = 0; j < subject.length; j++) {
								if (subject[j].name == 'emailAddress') {
									var email = subject[j].value;
									var type = subject[j].type;

									extensions[ext][i] = {
										name: "rfc822Name",
										value: email,
										type: type
									};
									changed = true;
								}
							}

							if (!changed) {
								extensions[ext].splice(i, 1);
							}
							finish = true;
						}
						i++;
					} while (i < extensions[ext].length && !finish);
					break;
				case 'issuerAltName':
					if (cert_build.type == jCastle.certificate.typeCSR) {
						delete extensions[ext];

						break;
					}

					var i = 0;
					var finish = false;
					do {
						if (jCastle.util.isString(extensions[ext][i]) && extensions[ext][i] == 'copy') {
							var dirName = {
								name: "directoryName",
								value: cert_build.tbs.issuer
							};
							
							// insert array into array
							extensions[ext].splice.apply(extensions[ext], [i, 1].concat(dirName));
							finish = true;
						}
						i++;
					} while (i < extensions[ext].length && !finish);
					break;
				case 'subjectKeyIdentifier':
					if (extensions[ext] == 'hash') {
						extensions[ext] = jCastle.pki.createPublicKeyIdentifier(req_pki);
					}
					// nothing to do more.
					break;
				case 'authorityKeyIdentifier':
					if (cert_build.type == jCastle.certificate.typeCSR) {
						delete extensions[ext];

						break;
					}

					if ('keyIdentifier' in extensions[ext]) {
						if (extensions[ext]['keyIdentifier'] == 'always' || 
							!extensions[ext].hasOwnProperty('authorityCertIssuer') ||
							extensions[ext]['authorityCertIssuer'] == null
						) {
							extensions[ext]['keyIdentifier'] = jCastle.pki.createPublicKeyIdentifier(sign_pki);
						} else {
							delete extensions[ext]['keyIdentifier'];
						}
					}

					if ('authorityCertIssuer' in extensions[ext]) {
						if (!extensions[ext].hasOwnProperty('keyIdentifier') ||
							extensions[ext]['authorityCertIssuer'] == 'always'
						) {
							extensions[ext]['authorityCertIssuer'] = {
								name: "directoryName",
								value: (cert_info && 'authorityCertIssuer' in cert_info) ? jCastle.util.clone(cert_info.authorityCertIssuer) : jCastle.util.clone(cert_build.tbs.issuer)
							};
						} else {
							delete extensions[ext]['authorityCertIssuer'];
						}
					}

					if (cert_info && 'authorityCertSerialNumber' in cert_info && cert_info.authorityCertSerialNumber) {
						var serial = jCastle.util.toBigInt(cert_info.authorityCertSerialNumber);
						extensions[ext]['authorityCertSerialNumber'] = serial;
					}
					break;
				case 'certificatePolicies':
					delete extensions[ext]['ia5org'];
					break;
				// there are nothing more because jCastle.certificate.CertConfig.parse() do all things already!
			}
		}
	},

	isIssuerAndSubjectIdentical: function(cert_info)
	{
		if (!('issuer' in cert_info.tbs)) return false;
		if (cert_info.tbs.subject.length != cert_info.tbs.issuer.length) return false;

		var subject = {};
		var issuer = {};

		for (var i = 0; i < cert_info.tbs.subject.length; i++) {
			subject[cert_info.tbs.subject[i].name] = cert_info.tbs.subject[i].value;
			issuer[cert_info.tbs.issuer[i].name] = cert_info.tbs.issuer[i].value;
		}

		for (var i in subject) {
			if (subject[i] != issuer[i]) return false;
		}

		return true;
	}
};

jCastle.certificate.asn1 = {};

jCastle.certificate.asn1.signAlgorithm = 
{
	parse: function(sequence)
	{


		if (sequence.items[0].type != jCastle.asn1.tagOID) {
			throw jCastle.exception("INVALID_SIGN_ALGO", 'CRT035');
		}

		var oid = sequence.items[0].value;
		var name = jCastle.oid.getName(oid);
		var hash_name;
		if (name.indexOf('WithRSAEncryption') !== -1) {
			hash_name = jCastle.digest.getValidAlgoName(name.replace('WithRSAEncryption', ''));
			return {signAlgo:'RSASSA-PKCS1-V1_5', signHash: hash_name};
		}

		if (name.indexOf('ecdsaWith') !== -1) {
			hash_name = name.replace('ecdsaWith', '');
			return {signAlgo:'ECDSA', signHash: hash_name};
		}

		if (name.indexOf('eckcdsaWith') !== -1) {
			hash_name = name.replace('eckcdsaWith', '');
			return {signAlgo:'ECKCDSA', signHash: hash_name};
		}

		if (name.indexOf('kcdsaWith') !== -1) {
			hash_name = name.replace('kcdsaWith', '');
			return {signAlgo:'KCDSA', signHash: hash_name};
		}

		if (name.indexOf('dsaWith') !== -1) {
			hash_name = name.replace('dsaWith', '');
			return {signAlgo:'DSA', signHash: hash_name};
		}


		/* RSASSA-PSS */
/*
	SEQUENCE(2 elem)
		OBJECT IDENTIFIER						1.2.840.113549.1.1.10					-- rsaPSS
		SEQUENCE(3 elem)
			[0](1 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER			2.16.840.1.101.3.4.2.1					-- sha-256
					NULL
			[1](1 elem)
			SEQUENCE(2 elem)
				OBJECT IDENTIFIER				1.2.840.113549.1.1.8					-- pkcs1-MGF
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER			2.16.840.1.101.3.4.2.1					-- sha-256
					NULL
			[2](1 elem)
				INTEGER							32										-- salt length
*/
		if (jCastle.oid.getOID('rsaPSS') == sequence.items[0].value) {
			if (sequence.items[1].items[0].items[0].items[0].type == jCastle.asn1.tagOID) {
				hash_name = jCastle.digest.getHashNameByOID(sequence.items[1].items[0].items[0].items[0].value);
				if (!hash_name) throw jCastle.exception("INVALID_HASH_ALGO", 'CRT036');

				if (jCastle.oid.getOID("pkcs1-MGF") != sequence.items[1].items[1].items[0].items[0].value) {
					throw jCastle.exception("INVALID_MGF", 'CRT037');
				}
				// get the salt length
				var salt_length = -1;
				if (typeof sequence.items[1].items[2] != 'undefined' &&
					sequence.items[1].items[2].items[0].type == jCastle.asn1.tagInteger
				) {
					salt_length = sequence.items[1].items[2].items[0].intVal;
				}
				return {
					signAlgo:'RSASSA-PSS', 
					signHash: hash_name,
					saltLength: salt_length
				};
			}
		}
		
		throw jCastle.exception("INVALID_PEM_FORMAT", 'CRT038');
	},

	schema: function(hash_algo, sign_algo)
	{
		var oid;
/*
http://crypto.stackexchange.com/questions/1217/rsa-pss-salt-size


RSASSA-PSS-params ::= SEQUENCE {
    hashAlgorithm      [0] HashAlgorithm      DEFAULT sha1,
    maskGenAlgorithm   [1] MaskGenAlgorithm   DEFAULT mgf1SHA1,
    saltLength         [2] INTEGER            DEFAULT 20,
    trailerField       [3] TrailerField       DEFAULT trailerFieldBC
}
*/
/*
	RSASSA-PSS:
	SEQUENCE(2 elem)
		OBJECT IDENTIFIER						1.2.840.113549.1.1.10					-- rsaPSS
		SEQUENCE(3 elem)
			[0](1 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER			2.16.840.1.101.3.4.2.1					-- sha-256
					NULL
			[1](1 elem)
			SEQUENCE(2 elem)
				OBJECT IDENTIFIER				1.2.840.113549.1.1.8					-- pkcs1-MGF
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER			2.16.840.1.101.3.4.2.1					-- sha-256
					NULL
			[2](1 elem)
				INTEGER							32										-- salt length
					
	RSASSA-PCKS1-V1_5:
		SEQUENCE(1 elem)
			OBJECT IDENTIFIER					1.2.840.113549.1.1.11					-- sha256WithRSAEncryption
			
	ECDSA:
		SEQUENCE(1 elem)
			OBJECT IDENTIFIER					1.2.840.10045.4.3.2
*/
		switch (sign_algo) {
			case 'RSASSA-PSS':
				return {
					type: jCastle.asn1.tagSequence,
					items: [{
						type: jCastle.asn1.tagOID,
						value: jCastle.oid.getOID('rsaPSS')
					}, {
						type: jCastle.asn1.tagSequence,
						items: [{
							tagClass: jCastle.asn1.tagClassContextSpecific,
							type: 0x00,
							constructed: true,
							items: [{
								type: jCastle.asn1.tagSequence,
								items: [{
									type: jCastle.asn1.tagOID,
									value: jCastle.digest.getOID(hash_algo)
								}, {
									type: jCastle.asn1.tagNull,
									value: null
								}]
							}]
						}, {
							tagClass: jCastle.asn1.tagClassContextSpecific,
							type: 0x01,
							constructed: true,
							items: [{
								type: jCastle.asn1.tagSequence,
								items: [{
									type: jCastle.asn1.tagOID,
									value: jCastle.oid.getOID("pkcs1-MGF")
								}, {
									type: jCastle.asn1.tagSequence,
									items: [{
										type: jCastle.asn1.tagOID,
										value: jCastle.digest.getOID(hash_algo)
									}, {
										type: jCastle.asn1.tagNull,
										value: null
									}]
								}]
							}]
						}, {
							tagClass: jCastle.asn1.tagClassContextSpecific,
							type: 0x02,
							constructed: true,
							items: [{
								type: jCastle.asn1.tagInteger,
								intVal: jCastle.digest.getDigestLength(hash_algo)
							}]
						}]
					}]
				};						
			case 'RSASSA-PKCS1-V1_5':
				oid = jCastle.oid.getOID(hash_algo.replace('-', '') + 'WithRSAEncryption');
				if (oid === false) {

					throw jCastle.exception("UNSUPPORTED_HASHER", 'CRT055');
				}

				return {
					type: jCastle.asn1.tagSequence,
					items: [{
						type: jCastle.asn1.tagOID,
						value: oid
					}, {
						type: jCastle.asn1.tagNull,
						value: null
					}]
				};
			case 'DSA':
			case 'KCDSA':
				if (sign_algo == 'DSA') {
					oid = jCastle.oid.getOID('dsaWith'+hash_algo.replace('-', ''));
				} else {
					oid = jCastle.oid.getOID('kcdsaWith'+hash_algo.replace('-', ''));
				}
				if (oid === false) {
					throw jCastle.exception("UNSUPPORTED_HASHER", 'CRT056');
				}

				return {
					type: jCastle.asn1.tagSequence,
					items: [{
						type: jCastle.asn1.tagOID,
						value: oid
					}]
				};
			case 'ECDSA':
			case 'ECKCDSA':
				if (sign_algo == 'ECDSA') {
					oid = jCastle.oid.getOID('ecdsaWith'+hash_algo.replace('-', ''));
				} else {
					oid = jCastle.oid.getOID('eckcdsaWith'+hash_algo.replace('-', ''));
				}
				if (oid === false) {
					throw jCastle.exception("UNSUPPORTED_HASHER", 'CRT057');
				}

				return {
					type: jCastle.asn1.tagSequence,
					items: [{
						type: jCastle.asn1.tagOID,
						value: oid
					}]
				};						   
			default:
				throw jCastle.exception("INVALID_SIGN_ALGO", 'CRT058');
		}
	}
};

// https://www.itu.int/ITU-T/formal-language/itu-t/x/x509/2012/CertificateExtensions.html

/*
    TBSCertList  ::=  SEQUENCE  {
        version                 Version OPTIONAL,
                                     -- if present, MUST be v2
        signature               AlgorithmIdentifier,
        issuer                  Name,
        thisUpdate              Time,
        nextUpdate              Time OPTIONAL,
        revokedCertificates     SEQUENCE OF SEQUENCE  {
            userCertificate         CertificateSerialNumber,
            revocationDate          Time,
            crlEntryExtensions      Extensions OPTIONAL
            -- if present, version MUST be v2
        }  OPTIONAL,
        crlExtensions           [0]  EXPLICIT Extensions OPTIONAL
        -- if present, version MUST be v2
    }
*/

jCastle.certificate.asn1.revokedCerts = 
{
	parse: function(sequence)
	{
/*
		SEQUENCE(5 elem)
			SEQUENCE(3 elem)
				INTEGER									1341767
				UTCTime									2013-02-18 10:22:12 UTC
				SEQUENCE(2 elem)
					SEQUENCE(2 elem)
						OBJECT IDENTIFIER				2.5.29.21 -- cRLReason
						OCTET STRING(1 elem)
							ENUMERATED
					SEQUENCE(2 elem)
						OBJECT IDENTIFIER				2.5.29.24 -- invalidityDate
						OCTET STRING(1 elem)
							GeneralizedTime				2013-02-18 10:22:00 UTC
*/
		var revokedCertificates = [];

		for (var i = 0; i < sequence.items.length; i++) {
			var seq = sequence.items[i];

			var o = {};
			o.userCertificate = seq.items[0].intVal;
			o.revocationDate = seq.items[1].value;

			if (typeof seq.items[2] != 'undefined') {
				o.crlEntryExtensions = {};
/*

5.3.  CRL Entry Extensions

   The CRL entry extensions defined by ISO/IEC, ITU-T, and ANSI X9 for
   X.509 v2 CRLs provide methods for associating additional attributes
   with CRL entries [X.509] [X9.55].  The X.509 v2 CRL format also
   allows communities to define private CRL entry extensions to carry
   information unique to those communities.  Each extension in a CRL
   entry may be designated as critical or non-critical.  If a CRL
   contains a critical CRL entry extension that the application cannot
   process, then the application MUST NOT use that CRL to determine the
   status of any certificates.  However, applications may ignore
   unrecognized non-critical CRL entry extensions.

   The following subsections present recommended extensions used within
   Internet CRL entries and standard locations for information.
   Communities may elect to use additional CRL entry extensions;
   however, caution should be exercised in adopting any critical CRL
   entry extensions in CRLs that might be used in a general context.

   Support for the CRL entry extensions defined in this specification is
   optional for conforming CRL issuers and applications.  However, CRL
   issuers SHOULD include reason codes (Section 5.3.1) and invalidity
   dates (Section 5.3.2) whenever this information is available.
*/
				for (var j = 0; j < seq.items[2].items.length; j++) {
					var s = seq.items[2].items[j];

					switch (s.items[0].value) {
						case jCastle.oid.getOID('cRLReason'):
/*
5.3.1.  Reason Code

   The reasonCode is a non-critical CRL entry extension that identifies
   the reason for the certificate revocation.  CRL issuers are strongly
   encouraged to include meaningful reason codes in CRL entries;
   however, the reason code CRL entry extension SHOULD be absent instead
   of using the unspecified (0) reasonCode value.

   The removeFromCRL (8) reasonCode value may only appear in delta CRLs
   and indicates that a certificate is to be removed from a CRL because
   either the certificate expired or was removed from hold.  All other
   reason codes may appear in any CRL and indicate that the specified
   certificate should be considered revoked.

   id-ce-cRLReasons OBJECT IDENTIFIER ::= { id-ce 21 }

   -- reasonCode ::= { CRLReason }

   CRLReason ::= ENUMERATED {
        unspecified             (0),
        keyCompromise           (1),
        cACompromise            (2),
        affiliationChanged      (3),
        superseded              (4),
        cessationOfOperation    (5),
        certificateHold         (6),
             -- value 7 is not used
        removeFromCRL           (8),
        privilegeWithdrawn      (9),
        aACompromise           (10) }
*/
							var code = s.items[1].value.intVal;
							var reasonCode;
							switch (code) {
								case 0: reasonCode = 'unspecified'; break;
								case 1: reasonCode = 'keyCompromise'; break;
								case 2: reasonCode = 'cACompromise'; break;
								case 3: reasonCode = 'affiliationChanged'; break;
								case 4: reasonCode = 'superseded'; break;
								case 5: reasonCode = 'cessationOfOperation'; break;
								case 6: reasonCode = 'certificateHold'; break;
								case 8: reasonCode = 'removeFromCRL'; break;
								case 9: reasonCode = 'privilegeWithdrawn'; break;
								case 10: reasonCode = 'aACompromise'; break;
							}
							o.crlEntryExtensions.cRLReason = reasonCode;
							break;
						case jCastle.oid.getOID('invalidityDate'):
/*
5.3.2.  Invalidity Date

   The invalidity date is a non-critical CRL entry extension that
   provides the date on which it is known or suspected that the private
   key was compromised or that the certificate otherwise became invalid.
   This date may be earlier than the revocation date in the CRL entry,
   which is the date at which the CA processed the revocation.  When a
   revocation is first posted by a CRL issuer in a CRL, the invalidity
   date may precede the date of issue of earlier CRLs, but the
   revocation date SHOULD NOT precede the date of issue of earlier CRLs.
   Whenever this information is available, CRL issuers are strongly
   encouraged to share it with CRL users.

   The GeneralizedTime values included in this field MUST be expressed
   in Greenwich Mean Time (Zulu), and MUST be specified and interpreted
   as defined in Section 4.1.2.5.2.

   id-ce-invalidityDate OBJECT IDENTIFIER ::= { id-ce 24 }

   InvalidityDate ::=  GeneralizedTime
*/
							o.crlEntryExtensions.invalidityDate = s.items[1].value.value;
							break;
						case jCastle.oid.getOID('certificateIssuer'):
/*
5.3.3.  Certificate Issuer

   This CRL entry extension identifies the certificate issuer associated
   with an entry in an indirect CRL, that is, a CRL that has the
   indirectCRL indicator set in its issuing distribution point
   extension.  When present, the certificate issuer CRL entry extension
   includes one or more names from the issuer field and/or issuer
   alternative name extension of the certificate that corresponds to the
   CRL entry.  If this extension is not present on the first entry in an
   indirect CRL, the certificate issuer defaults to the CRL issuer.  On
   subsequent entries in an indirect CRL, if this extension is not
   present, the certificate issuer for the entry is the same as that for
   the preceding entry.  This field is defined as follows:

   id-ce-certificateIssuer   OBJECT IDENTIFIER ::= { id-ce 29 }

   CertificateIssuer ::=     GeneralNames

   Conforming CRL issuers MUST include in this extension the
   distinguished name (DN) from the issuer field of the certificate that
   corresponds to this CRL entry.  The encoding of the DN MUST be
   identical to the encoding used in the certificate.

   CRL issuers MUST mark this extension as critical since an
   implementation that ignored this extension could not correctly
   attribute CRL entries to certificates.  This specification RECOMMENDS
   that implementations recognize this extension.
*/
						o.crlEntryExtensions.certificateIssuer = jCastle.certificate.asn1.generalNames.parse(s.items[1].value.value);
						break;
					}
				}
			}

			revokedCertificates.push(o);
		}

		return revokedCertificates;
	},

	schema: function(revokedCertificates)
	{
/*
		SEQUENCE(5 elem)
			SEQUENCE(3 elem)
				INTEGER									1341767
				UTCTime									2013-02-18 10:22:12 UTC
				SEQUENCE(2 elem)
					SEQUENCE(2 elem)
						OBJECT IDENTIFIER				2.5.29.21 -- cRLReason
						OCTET STRING(1 elem)
							ENUMERATED
					SEQUENCE(2 elem)
						OBJECT IDENTIFIER				2.5.29.24 -- invalidityDate
						OCTET STRING(1 elem)
							GeneralizedTime				2013-02-18 10:22:00 UTC
*/
/*
    TBSCertList  ::=  SEQUENCE  {
        version                 Version OPTIONAL,
                                     -- if present, MUST be v2
        signature               AlgorithmIdentifier,
        issuer                  Name,
        thisUpdate              Time,
        nextUpdate              Time OPTIONAL,
        revokedCertificates     SEQUENCE OF SEQUENCE  {
            userCertificate         CertificateSerialNumber,
            revocationDate          Time,
            crlEntryExtensions      Extensions OPTIONAL
            -- if present, version MUST be v2
        }  OPTIONAL,
        crlExtensions           [0]  EXPLICIT Extensions OPTIONAL
        -- if present, version MUST be v2
    }
*/

		var revokedSchema = {
			type: jCastle.asn1.tagSequence,
			items: []
		};

		for (var i = 0; i < revokedCertificates.length; i++) {
			var revoked = revokedCertificates[i];

			var schema = {
				type: jCastle.asn1.tagSequence,
				items: [{
					type: jCastle.asn1.tagInteger,
					intVal: revoked.userCertificate
				}, {
					type: jCastle.asn1.tagUTCTime,
					value: revoked.revocationDate
				}]
			};
			
			if ('crlEntryExtensions' in revoked) {
				var extSchema = {
					type: jCastle.asn1.tagSequence,
					items: []
				};

				var code;
				for (var j in revoked.crlEntryExtensions) {
					switch (j) {
						case 'cRLReason':
							switch (revoked.crlEntryExtensions.cRLReason) {
								case 'unspecified':				code = 0; break;
								case 'keyCompromise':			code = 1; break;
								case 'cACompromise':			code = 2; break;
								case 'affiliationChanged':		code = 3; break;
								case 'superseded':				code = 4; break;
								case 'cessationOfOperation':	code = 5; break;
								case 'certificateHold':			code = 6; break;
								case 'removeFromCRL':			code = 8; break;
								case 'privilegeWithdrawn':		code = 9; break;
								case 'aACompromise':			code = 10; break;
							}
							extSchema.items.push({
								type: jCastle.asn1.tagSequence,
								items: [{
									type: jCastle.asn1.tagOID,
									value: jCastle.oid.getOID('cRLReason')
								}, {
									type: jCastle.asn1.tagOctetString,
									value: {
										type: jCastle.asn1.tagEnumerated,
										intVal: code
									}
								}]
							});
							break;
						case 'invalidityDate':
							extSchema.items.push({
								type: jCastle.asn1.tagSequence,
								items: [{
									type: jCastle.asn1.tagOID,
									value: jCastle.oid.getOID('invalidityDate')
								}, {
									type: jCastle.asn1.tagOctetString,
									value: {
										type: jCastle.asn1.tagGeneralizedTime,
										value: revoked.crlEntryExtensions.invalidityDate
									}
								}]
							});
							break;
						case 'certificateIssuer':
							extSchema.items.push({
								type: jCastle.asn1.tagSequence,
								items: [{
									type: jCastle.asn1.tagOID,
									value: jCastle.oid.getOID('certificateIssuer')
								}, {
									type: jCastle.asn1.tagOctetString,
									value: jCastle.certificate.asn1.generalNames.schema(revoked.crlEntryExtensions.certificateIssuer)
								}]
							});
							break;
					}
				}
				schema.items.push(extSchema);
			}

			revokedSchema.items.push(schema);
		}

		return revokedSchema;	
	}
};

jCastle.certificate.asn1.accessDescription = 
{
	parse: function(sequence, critical)
	{
/*
SEQUENCE(2 elem)
	OBJECT IDENTIFIER					1.3.6.1.5.5.7.1.1 -- authorityInfoAcess
	OCTET STRING(1 elem)
		SEQUENCE(1 elem) <!--
			SEQUENCE(2 elem)
				OBJECT IDENTIFIER		1.3.6.1.5.5.7.48.1 -- ocsp
				[6]						http://ocsp.yessign.org:4612
*/
/*
 AuthorityInfoAccessSyntax  ::=
          SEQUENCE SIZE (1..MAX) OF AccessDescription

 AccessDescription  ::=  SEQUENCE {
          accessMethod          OBJECT IDENTIFIER,
          accessLocation        GeneralName  }
*/



		var description = [];
		for (var i = 0; i < sequence.items.length; i++) {
			var seq = sequence.items[i];
			var oid = jCastle.oid.getName(seq.items[0].value);
			if (!oid && critical) {
				throw jCastle.exception("UNSUPPORTED_EXTENSION", 'CRT039');
			}
			var ia = {
				accessMethod: oid ? oid : seq.items[0].value,
				accessLocation: jCastle.certificate.asn1.generalName.parse(seq.items[1])
			};
			description.push(ia);
		}
		return description;
	},

	schema: function(accessDescription, config)
	{
		var v = [];

		for (var i = 0; i < accessDescription.length; i++) {
			var description = accessDescription[i];
			var d = {
				type: jCastle.asn1.tagSequence,
				items: [{
					type: jCastle.asn1.tagOID,
					value: jCastle.oid.getOID(description.accessMethod, null, config)
				}, jCastle.certificate.asn1.generalName.schema(description.accessLocation)
				]
			};
			v.push(d);
		}

		var schema = {
			type: jCastle.asn1.tagSequence,
			items: v
		};

		return schema;
	}
};

jCastle.certificate.asn1.generalNames = 
{
	parse: function(obj)
	{
		var gns = [];
		for (var i = 0; i < obj.items.length; i++) {
			var gn = jCastle.certificate.asn1.generalName.parse(obj.items[i]);
			gns.push(gn);
		}

		return gns;
	},

	schema: function(a, is_explicit)
	{
		var v = [];
		for (var i = 0; i < a.length; i++) {
			v.push(jCastle.certificate.asn1.generalName.schema(a[i]));
		}

		if (is_explicit) return v;

		var schema = {
			type: jCastle.asn1.tagSequence,
			items: v
		};

		return schema;
	}
};

/*
https://tools.ietf.org/html/rfc5280

   GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName

   GeneralName ::= CHOICE {
        otherName                       [0]     OtherName,
        rfc822Name                      [1]     IA5String,
        dNSName                         [2]     IA5String,
        x400Address                     [3]     ORAddress,
        directoryName                   [4]     Name,
        ediPartyName                    [5]     EDIPartyName,
        uniformResourceIdentifier       [6]     IA5String,
        iPAddress                       [7]     OCTET STRING,
        registeredID                    [8]     OBJECT IDENTIFIER }

   OtherName ::= SEQUENCE {
        type-id    OBJECT IDENTIFIER,
        value      [0] EXPLICIT ANY DEFINED BY type-id }

   EDIPartyName ::= SEQUENCE {
        nameAssigner            [0]     DirectoryString OPTIONAL,
        partyName               [1]     DirectoryString }

*/
jCastle.certificate.asn1.generalName = 
{
	parse: function(obj)
	{


		var gn = {};

		switch (obj.type) {
			case 0: 
				gn.name = 'otherName';
				gn.value = jCastle.certificate.asn1.otherName.parse(obj);
				break;
			case 1:
				gn.name = 'rfc822Name';
				gn.value = obj.value;
				gn.type = jCastle.asn1.tagIA5String;
				break;
			case 2:
				gn.name = 'dNSName';
				gn.value = obj.value;
				gn.type = jCastle.asn1.tagIA5String;
				break;
			case 3:
				gn.name = 'x400Address';
				gn.value = jCastle.certificate._parseORAddress(obj.items[0]);
				break;
			case 4:
				gn.name = 'directoryName';
				gn.value = jCastle.certificate.asn1.directoryName.parse(obj.items[0]);
				break;
			case 5:
/*
EDIPartyName ::= SEQUENCE {
  nameAssigner  [0]  UnboundedDirectoryString OPTIONAL,
  partyName     [1]  UnboundedDirectoryString,
  ...
}

UnboundedDirectoryString ::= CHOICE {
  teletexString    TeletexString(SIZE (1..MAX)),
  printableString  PrintableString(SIZE (1..MAX)),
  bmpString        BMPString(SIZE (1..MAX)),
  universalString  UniversalString(SIZE (1..MAX)),
  utf8String       UTF8String(SIZE (1..MAX))
}

*/
				gn.name = 'ediPartyName';
						
				var idx = 0;
				var seq = obj.items[0];
				var o = seq.items[idx++];
				var ediPartyName = {};

				if (o.type == 0x00) {
					ediPartyName.nameAssigner = {
						name: o.value.value,
						type: o.value.type
					};

					o = seq.items[idxx++];
				}

				ediPartyName.partyName = [];
				while (typeof o != 'undefined') {
					ediPartyName.partyName.push({
						name: o.value,
						type: o.type
					});
						
					o = seq.items[idxx++];
				}

				gn.value = ediPartyName;
				break;
			case 6:
				gn.name = 'uniformResourceIdentifier';
				gn.value = obj.value;
				gn.type = jCastle.asn1.tagIA5String;
				break;
			case 7:
				gn.name = 'iPAddress';
				var ip_address;
				if (obj.value.length == 4 || obj.value.length == 8) {
					ip_address = jCastle.util.loadIPv4(obj.value);
				} else { // 16 bytes

					ip_address = jCastle.util.loadIPv6(obj.value);
				}

				//gn.value = obj.value;
				gn.value = ip_address;
				gn.type = jCastle.asn1.tagOctetString;
				break;
			case 8:
				gn.name = 'registeredID';

				var oid = jCastle.asn1.parseOID(obj.value);

				var n = jCastle.oid.getName(oid);
				gn.value = n ? n : oid;

				break;
		}

		return gn;
	},

	schema: function(obj)
	{
		var schema = {};
		switch (obj.name) {
			case 'otherName':
				schema = {
					tagClass: jCastle.asn1.tagClassContextSpecific,
					type: 0x00,
					constructed: true,
					items:
						jCastle.certificate.asn1.otherName.schema(obj.value) // should be array
					
				};
				return schema;				
			case 'rfc822Name':
				schema = {
					tagClass: jCastle.asn1.tagClassContextSpecific,
					type: 0x01,
					constructed: false,
					value: obj.value
				};
				return schema;				
			case 'dNSName':
				schema = {
					tagClass: jCastle.asn1.tagClassContextSpecific,
					type: 0x02,
					constructed: false,
					value: obj.value
				};
				return schema;				
			case 'x400Address':
				throw jCastle.exception("UNSUPPORTED_EXTENSION", 'CRT062');
			case 'directoryName':
				schema = {
					tagClass: jCastle.asn1.tagClassContextSpecific,
					type: 0x04,
					constructed: true,
					items:[
						jCastle.certificate.asn1.directoryName.schema(obj.value)
					]
				};
				return schema;
			case 'ediPartyName':
				schema = {
					type: jCastle.asn1.tagSequence,
					items: []
				};

				if ('nameAssigner' in obj) {
					schema.items.push({
						tagClass: jCastle.asn1.tagClassContextSpecific,
						type: 0x00,
						constructed: true,
						items: [{
							type: 'type' in obj ? obj.nameAssigner.type : jCastle.asn1.tagUTF8String,
							value: obj.nameAssigner.name
						}]
					});
				}

				schema.items.push({
					tagClass: jCastle.asn1.tagClassContextSpecific,
					type: 0x01,
					constructed: true,
					items: [{
						type: 'type' in obj ? obj.partyName.type : jCastle.asn1.tagUTF8String,
						value: obj.partyName.name
					}]
				});

				return schema;
			case 'uniformResourceIdentifier':
				schema = {
					tagClass: jCastle.asn1.tagClassContextSpecific,
					type: 0x06,
					constructed: false,
					value: obj.value
				};
				return schema;
			case 'iPAddress':
				schema = {
					tagClass: jCastle.asn1.tagClassContextSpecific,
					type: 0x07,
					constructed: false,
					value: obj.value.indexOf(':') === -1 ? jCastle.util.storeIPv4(obj.value) : jCastle.util.storeIPv6(obj.value)
				};
				return schema;
			case 'registeredID':
				schema = {
					tagClass: jCastle.asn1.tagClassContextSpecific,
					type: 0x08,
	//				constructed: true,
	//				items: [{
	//					type: jCastle.asn1.tagOID,
	//					value: jCastle.oid.getOID(obj.value)
	//				}]
					constructed: false,
					value: jCastle.asn1.getOIDDER(jCastle.oid.getOID(obj.value))
				};
				return schema;				
		}
	}
};


jCastle.certificate.asn1.generalSubtrees = 
{
	parse: function(sequence)
	{
/*
GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree

GeneralSubtree ::= SEQUENCE {
  base     GeneralName,
  minimum  [0]  BaseDistance DEFAULT 0,
  maximum  [1]  BaseDistance OPTIONAL,
  ...
}

BaseDistance ::= INTEGER(0..MAX)
*/
/*
openssl doesn't support multiple generalsubtrees
so we need to check it...
*/
		var GeneralSubtrees = [];

		if (sequence.items[0].type != jCastle.asn1.tagSequence) {
			// it is not multiple subtrees.
			// openssl has it...
			var gst = {};

			gst.base = jCastle.certificate.asn1.generalName.parse(sequence.items[0]);

			if (typeof sequence.items[1] != 'undefined') {
				gst.minimum = sequence.items[1].items[0].intVal;
			}

			if (typeof sequence.items[2] != 'undefined') {
				gst.maximum = sequence.items[2].items[0].intVal;
			}

			GeneralSubtrees.push(gst);
		} else {
			for (var i = 0; i < sequence.items.length; i++) {
				var seq = sequence.items[i];
				var gst = {};

				gst.base = jCastle.certificate.asn1.generalName.parse(seq.items[0]);

				if (typeof seq.items[1] != 'undefined') {
					gst.minimum = seq.items[1].items[0].intVal;
				}

				if (typeof seq.items[2] != 'undefined') {
					gst.maximum = seq.items[2].items[0].intVal;
				}

				GeneralSubtrees.push(gst);
			}
		}

		return GeneralSubtrees;
	},

	schema: function()
	{
		throw jCastle.exception("UNSUPPORTED_EXTENSION", 'CRT078');
	}
};

jCastle.certificate.asn1.otherName = 
{
	parse: function(obj)
	{
/*
[0](2 elem)
	OBJECT IDENTIFIER						1.2.3.4
	[0](1 elem)
		UTF8String							some other identifier
*/
/*
   OtherName ::= SEQUENCE {
        type-id    OBJECT IDENTIFIER,
        value      [0] EXPLICIT ANY DEFINED BY type-id }
*/



		var n = jCastle.oid.getName(obj.items[0].value);
		if (!n) n = obj.items[0].value;

		if (n in jCastle.certificate.otherNameRules) {
			return jCastle.certificate.otherNameRules[n].parse(n, obj.items[1]);
		}

		// obj.items[1] == explicit

		if (obj.items[1].items[0].type == jCastle.asn1.tagSequence) {
			return {
				name: n,
				items: jCastle.certificate.asn1.asn1items.parse(obj.items[1].items[0]),
				type: jCastle.asn1.tagSequence
			};
		} else {
			return {
				name: n,
				value: obj.items[1].items[0].value,
				type: obj.items[1].items[0].type
			};
		}
	},

	schema: function(obj)
	{
		var schema;

		if (obj.name in jCastle.certificate.otherNameRules) {
			schema = jCastle.certificate.otherNameRules[obj.name].schema(obj);
			return schema;
		}

		schema = [];

		schema.push({
			type: jCastle.asn1.tagOID,
			value: jCastle.oid.getOID(obj.name)
		});

		var valueSchema = {
			tagClass: jCastle.asn1.tagClassContextSpecific,
			type: 0x00,
			constructed: true,
			items: []
		};

		var childSchema;

		if (obj.type == jCastle.asn1.tagSequence) {
			childSchema = {
				type: jCastle.asn1.tagSequence,
				items: jCastle.certificate.asn1.asn1items.schema(obj)
			};
		} else {
			childSchema = {
				type: 'type' in obj ? obj.type : jCastle.asn1.tagUTF8String,
				value: obj.value
			};
		}

		valueSchema.items.push(childSchema);

		schema.push(valueSchema);

		return schema;
	}
};



jCastle.certificate.asn1.asn1items = 
{
	parse: function(sequence)
	{
		var res = [];

		for (var i = 0; i < sequence.items.length; i++) {
			var child = jCastle.util.clone(sequence.items[i]);

			if ('tagClass' in child &&
				child.tagClass > 0 &&
				child.constructed
			) {
				child.items = jCastle.certificate.asn1.asn1items.parse(child)
			} else if (child.type == jCastle.asn1.tagSequence) {
				child.items = jCastle.certificate.asn1.asn1items.parse(child);
			} else {
				if (child.type == jCastle.asn1.tagOID) {
					var name = jCastle.oid.getName(child.value);
					if (name) child.value = name;
				}
			}

			res.push(child);
		}

		return res;
	},

	schema: function(obj)
	{
		var res = [];
		var schema;

		for (var i = 0; i < obj.items.length; i++) {
			if ('tagClass' in obj.items[i] && obj.items[i].tagClass > 0) {
				if (obj.items[i].constructed) {
					schema = {
						tagClass: obj.items[i].tagClass,
						constructed: true,
						type: obj.items[i].type,
						items: jCastle.certificate.asn1.asn1items.schema(obj.items[i])
					};
				} else {
					schema = {
						tagClass: obj.items[i].tagClass,
						constructed: false,
						type: obj.items[i].type,
						items: obj.items[i].value
					};
				}
			} else if (obj.items[i].type == jCastle.asn1.tagSequence) {
				schema = {
					type: jCastle.asn1.tagSequence,
					items: jCastle.certificate.asn1.asn1items.schema(obj.items[i])
				};
			} else {
				schema = {
					type: 'type' in obj.items[i] ? obj.items[i].type : jCastle.asn1.tagUTF8String,
					value: obj.items[i].type == jCastle.asn1.tagOID ? jCastle.oid.getOID(obj.items[i].value) : obj.items[i].value
				}
			}

			res.push(schema);
		}

		return res;
	}
};

jCastle.certificate.asn1.orAddress = 
{
	parse: function(sequence)
	{
/*
ORAddress ::= SEQUENCE {
  built-in-standard-attributes        BuiltInStandardAttributes,
  built-in-domain-defined-attributes  BuiltInDomainDefinedAttributes OPTIONAL,
  -- see also teletex-domain-defined-attributes
  extension-attributes                ExtensionAttributes OPTIONAL
}

--	The OR-address is semantically absent from the OR-name if the built-in-standard-attribute
--	sequence is empty and the built-in-domain-defined-attributes and extension-attributes are both omitted.
--	Built-in Standard Attributes
BuiltInStandardAttributes ::= SEQUENCE {
  country-name                CountryName OPTIONAL,
  administration-domain-name  AdministrationDomainName OPTIONAL,
  network-address             [0]  NetworkAddress OPTIONAL,
  -- see also extended-network-address
  terminal-identifier         [1]  TerminalIdentifier OPTIONAL,
  private-domain-name         [2]  PrivateDomainName OPTIONAL,
  organization-name           [3]  OrganizationName OPTIONAL,
  -- see also teletex-organization-name
  numeric-user-identifier     [4]  NumericUserIdentifier OPTIONAL,
  personal-name               [5]  PersonalName OPTIONAL,
  -- see also teletex-personal-name
  organizational-unit-names   [6]  OrganizationalUnitNames OPTIONAL
  -- see also teletex-organizational-unit-names 
}

CountryName ::= [APPLICATION 1]  CHOICE {
  x121-dcc-code         NumericString(SIZE (ub-country-name-numeric-length)),
  iso-3166-alpha2-code  PrintableString(SIZE (ub-country-name-alpha-length))
}

AdministrationDomainName ::= [APPLICATION 2]  CHOICE {
  numeric    NumericString(SIZE (0..ub-domain-name-length)),
  printable  PrintableString(SIZE (0..ub-domain-name-length))
}

NetworkAddress ::= X121Address

-- see also extended-network-address
X121Address ::= NumericString(SIZE (1..ub-x121-address-length))

TerminalIdentifier ::= PrintableString(SIZE (1..ub-terminal-id-length))

PrivateDomainName ::= CHOICE {
  numeric    NumericString(SIZE (1..ub-domain-name-length)),
  printable  PrintableString(SIZE (1..ub-domain-name-length))
}

OrganizationName ::= PrintableString(SIZE (1..ub-organization-name-length))

-- see also teletex-organization-name
NumericUserIdentifier ::= NumericString(SIZE (1..ub-numeric-user-id-length))

PersonalName ::= SET {
  surname               [0]  PrintableString(SIZE (1..ub-surname-length)),
  given-name
    [1]  PrintableString(SIZE (1..ub-given-name-length)) OPTIONAL,
  initials
    [2]  PrintableString(SIZE (1..ub-initials-length)) OPTIONAL,
  generation-qualifier
    [3]  PrintableString(SIZE (1..ub-generation-qualifier-length)) OPTIONAL
}

-- see also teletex-personal-name
OrganizationalUnitNames ::=
  SEQUENCE SIZE (1..ub-organizational-units) OF OrganizationalUnitName

-- see also teletex-organizational-unit-names
OrganizationalUnitName ::=
  PrintableString(SIZE (1..ub-organizational-unit-name-length))

--	Built-in Domain-defined Attributes
BuiltInDomainDefinedAttributes ::=
  SEQUENCE SIZE (1..ub-domain-defined-attributes) OF
    BuiltInDomainDefinedAttribute

BuiltInDomainDefinedAttribute ::= SEQUENCE {
  type   PrintableString(SIZE (1..ub-domain-defined-attribute-type-length)),
  value  PrintableString(SIZE (1..ub-domain-defined-attribute-value-length))
}

--	Extension Attributes
ExtensionAttributes ::=
  SET SIZE (1..ub-extension-attributes) OF ExtensionAttribute

ExtensionAttribute ::= SEQUENCE {
  extension-attribute-type
    [0]  EXTENSION-ATTRIBUTE.&id({ExtensionAttributeTable}),
  extension-attribute-value
    [1]  EXTENSION-ATTRIBUTE.&Type
           ({ExtensionAttributeTable}{@extension-attribute-type})
}
*/
		throw jCastle.exception("UNSUPPORTED_EXTENSION", 'CRT041');
	},

	schema: function()
	{
		throw jCastle.exception("UNSUPPORTED_EXTENSION", 'CRT080');
	}
};

jCastle.certificate.asn1.encryptionInfo = 
{
	parse: function(sequence)
	{
		if (sequence.items[0].type != jCastle.asn1.tagOID) {
			throw jCastle.exception("PUBKEY_INFO_FAIL", 'CRT042');
		}

		var encName = jCastle.oid.getName(sequence.items[0].value);

		switch (encName) {
			case 'rsaEncryption':
/*
	SEQUENCE(2 elem)
		OBJECT IDENTIFIER				1.2.840.113549.1.1.1 -- rsaEncryption
		NULL
*/
				return {
					algo: 'RSA',
					padding: {
						mode: 'RSAES-PKCS1-V1_5' // 'PKCS1_Type_2'
					}
				};
			case 'rsaOAEP':
/*
	SEQUENCE(2 elem)
		OBJECT IDENTIFIER					1.2.840.113549.1.1.7			-- rsaOAEP
		SEQUENCE(3 elem)
			[0](1 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER		2.16.840.1.101.3.4.2.1			-- sha-256
					NULL
			[1](1 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER		1.2.840.113549.1.1.8			-- pkcs1-MGF
					SEQUENCE(2 elem)
						OBJECT IDENTIFIER	2.16.840.1.101.3.4.2.1			-- sha-256
						NULL
			[2](1 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER		1.2.840.113549.1.1.9			-- rsaOAEP-pSpecified
					OCTET STRING(5 byte)	5443504100
*/
/*
	SEQUENCE (2 elem)
		OBJECT IDENTIFIER 1.2.840.113549.1.1.7 rsaOAEP (PKCS #1)
		SEQUENCE (0 elem)
*/
/*
This class specifies the set of parameters used with OAEP Padding,
as defined in the PKCS #1 standard.
Its ASN.1 definition in PKCS#1 standard is described below:

 RSAES-OAEP-params ::= SEQUENCE {
   hashAlgorithm      [0] OAEP-PSSDigestAlgorithms     DEFAULT sha1,
   maskGenAlgorithm   [1] PKCS1MGFAlgorithms  DEFAULT mgf1SHA1,
   pSourceAlgorithm   [2] PKCS1PSourceAlgorithms  DEFAULT pSpecifiedEmpty
 }
 

where

 OAEP-PSSDigestAlgorithms    ALGORITHM-IDENTIFIER ::= {
   { OID id-sha1 PARAMETERS NULL   }|
   { OID id-sha256 PARAMETERS NULL }|
   { OID id-sha384 PARAMETERS NULL }|
   { OID id-sha512 PARAMETERS NULL },
   ...  -- Allows for future expansion --
 }
 PKCS1MGFAlgorithms    ALGORITHM-IDENTIFIER ::= {
   { OID id-mgf1 PARAMETERS OAEP-PSSDigestAlgorithms },
   ...  -- Allows for future expansion --
 }
 PKCS1PSourceAlgorithms    ALGORITHM-IDENTIFIER ::= {
   { OID id-pSpecified PARAMETERS OCTET STRING },
   ...  -- Allows for future expansion --
 }

 Note: the OAEPParameterSpec.DEFAULT uses the following: 
	message digest -- "SHA-1"
	mask generation function (mgf) -- "MGF1"
	parameters for mgf -- MGF1ParameterSpec.SHA1
	source of encoding input -- PSource.PSpecified.DEFAULT

*/
/*
https://code.google.com/p/chromium/issues/detail?id=477181

https://www.ietf.org/rfc/rfc4055.txt

4.  RSAES-OAEP Key Transport Algorithm

   This section describes the conventions for using the RSAES-OAEP key
   transport algorithm with the Internet X.509 Certificate and CRL
   profile [PROFILE].  RSAES-OAEP is specified in PKCS #1 version 2.1
   [P1v2.1].  The five one-way hash functions discussed in Section 2.1
   and the one mask generation function discussed in Section 2.2 can be
   used with RSAES-OAEP.  Conforming CAs and applications MUST support
   RSAES-OAEP key transport algorithm using SHA-1.  The other four one-
   way hash functions MAY also be supported.

   CAs that issue certificates with the id-RSAES-OAEP algorithm
   identifier SHOULD require the presence of parameters in the
   publicKeyAlgorithms field for all certificates.  Entities that use a
   certificate with a publicKeyAlgorithm value of id-RSA-OAEP where the
   parameters are absent SHOULD use the default set of parameters for
   RSAES-OAEP-params.  Entities that use a certificate with a
   publicKeyAlgorithm value of rsaEncryption SHOULD use the default set
   of parameters for RSAES-OAEP-params.

4.1.  RSAES-OAEP Public Keys

   When id-RSAES-OAEP is used in an AlgorithmIdentifier, the parameters
   MUST employ the RSAES-OAEP-params syntax.  The parameters may be
   either absent or present when used as subject public key information.
   The parameters MUST be present when used in the algorithm identifier
   associated with an encrypted value.

      id-RSAES-OAEP  OBJECT IDENTIFIER  ::=  { pkcs-1 7 }

      RSAES-OAEP-params  ::=  SEQUENCE  {
         hashFunc          [0] AlgorithmIdentifier DEFAULT
                                  sha1Identifier,
         maskGenFunc       [1] AlgorithmIdentifier DEFAULT
                                  mgf1SHA1Identifier,
         pSourceFunc       [2] AlgorithmIdentifier DEFAULT
                                  pSpecifiedEmptyIdentifier  }

      pSpecifiedEmptyIdentifier  AlgorithmIdentifier  ::=
                           { id-pSpecified, nullOctetString }

      nullOctetString  OCTET STRING (SIZE (0))  ::=  { ''H }

   The fields of type RSAES-OAEP-params have the following meanings:

      hashFunc

         The hashFunc field identifies the one-way hash function.  It
         MUST be one of the algorithm identifiers listed in Section 2.1,
         and the default hash function is SHA-1.  Implementations MUST
         support SHA-1 and MAY support other one-way hash functions
         listed in Section 2.1.  Implementations that perform encryption
         MUST omit the hashFunc field when SHA-1 is used, indicating
         that the default algorithm was used.  Implementations that
         perform decryption MUST recognize both the sha1Identifier
         algorithm identifier and an absent hashFunc field as an
         indication that SHA-1 was used.

      maskGenFunc

         The maskGenFunc field identifies the mask generation function.
         The default mask generation function is MGF1 with SHA-1.  For
         MGF1, it is strongly RECOMMENDED that the underlying hash
         function be the same as the one identified by hashFunc.
         Implementations MUST support MGF1.  MGF1 requires a one-way
         hash function that is identified in the parameter field of the
         MGF1 algorithm identifier.  Implementations MUST support SHA-1
         and MAY support any of the other one-way hash functions listed
         in Section 2.1.  The MGF1 algorithm identifier is comprised of
         the id-mgf1 object identifier and a parameter that contains the
         algorithm identifier of the one-way hash function employed with
         MGF1.  The SHA-1 algorithm identifier is comprised of the id-
         sha1 object identifier and an (optional) parameter of NULL.
         Implementations that perform encryption MUST omit the
         maskGenFunc field when MGF1 with SHA-1 is used, indicating that
         the default algorithm was used.

         Although mfg1SHA1Identifier is defined as the default value for
         this field, implementations MUST accept both the default value
         encoding (i.e., an absent field) and the mfg1SHA1Identifier to
         be explicitly present in the encoding.

      pSourceFunc

         The pSourceFunc field identifies the source (and possibly the
         value) of the encoding parameters, commonly called P.
         Implementations MUST represent P by an algorithm identifier,
         id-pSpecified, indicating that P is explicitly provided as an
         OCTET STRING in the parameters.  The default value for P is an
         empty string.  In this case, pHash in EME-OAEP contains the
         hash of a zero length string.  Implementations MUST support a
         zero length P value.  Implementations that perform encryption
         MUST omit the pSourceFunc field when a zero length P value is
         used, indicating that the default value was used.
         Implementations that perform decryption MUST recognize both the
         id-pSpecified object identifier and an absent pSourceFunc field
         as an indication that a zero length P value was used.
         Implementations that perform decryption MUST support a zero
         length P value and MAY support other values.  Compliant
         implementations MUST NOT use any value other than id-pSpecified
         for pSourceFunc.

   If the default values of the hashFunc, maskGenFunc, and pSourceFunc
   fields of RSAES-OAEP-params are used, then the algorithm identifier
   will have the following value:

      rSAES-OAEP-Default-Identifier  AlgorithmIdentifier  ::=
                            { id-RSAES-OAEP,
                              rSAES-OAEP-Default-Params }

      rSAES-OAEP-Default-Params RSASSA-OAEP-params ::=
                               { sha1Identifier,
                                 mgf1SHA1Identifier,
                                 pSpecifiedEmptyIdentifier  }


*/
				var seq = sequence.items[1];
				var idx = 0;
				var hash_name = '';
				var label = '';
				var mgf;

				// seq.items are all jCastle.asn1.tagClassContextSpecific
				// hashFunc
				if (seq.items[idx] && seq.items[idx].type == 0) {
					hash_name = jCastle.digest.getHashNameByOID(seq.items[0].items[0].items[0].value);

					idx++;
				} else {
					hash_name = 'sha-1'; // default hash algo
				}

				if (hash_name.length == 0) throw jCastle.exception("UNSUPPORTED_HASHER", 'CRT046');

				// maskGenFunc
				if (seq.items[idx] && seq.items[idx].type == 1) {
					mgf = jCastle.oid.getName(seq.items[1].items[0].items[0].value);
					var tmp_hash = jCastle.digest.getHashNameByOID(seq.items[1].items[0].items[1].items[0].value);

					if (hash_name != tmp_hash) throw jCastle.exception("HASH_NAME_MISMATCH", 'CRT047');
					if (mgf != 'pkcs1-MGF') throw jCastle.exception("INVALID_MGF", 'CRT048');

					if (mgf == 'pkcs1-MGF') mgf = 'mgf1'; // we now support only mgf1!

					idx++;
				} else {
					mgf = 'mgf1';
				}

				if (seq.items[idx] && seq.items[idx].type == 2) {
					jCastle.assert(jCastle.oid.getName(seq.items[2].items[0].items[0].value), "rsaOAEP-pSpecified", "UNSUPPORTED_OID", 'CRT049');

					label = seq.items[2].items[0].items[1].value;
				}

				return {
					algo: 'RSA',
					padding: {
						mode: 'RSAES-OAEP', // 'PKCS1_OAEP', 
						hashAlgo: hash_name,
						mgf: mgf,
						label: label
					}
				};
			case 'dsaPublicKey':
			case 'kcdsa':
				var algo = encName == 'dsaPublicKey' ? 'DSA' : 'KCDSA';

				var parameters = {
					p: sequence.items[1].items[0].intVal.toString(16),
					q: sequence.items[1].items[1].intVal.toString(16),
					g: sequence.items[1].items[2].intVal.toString(16)
				};

				return {
					algo: algo,
					parameters: parameters
				};

			case 'ecPublicKey':
			case 'eckcdsa-PublicKey':
/*
	SEQUENCE(2 elem)
		OBJECT IDENTIFIER				1.2.840.10045.2.1
		OBJECT IDENTIFIER				1.3.132.0.39
*/
				var algo = encName == 'ecPublicKey' ? 'ECDSA' : 'ECKCDSA';

				var parameters;
				if (sequence.items[1].type == jCastle.asn1.tagOID) {
					parameters = jCastle.pki.ecdsa.getCurveNameByOID(sequence.items[1].value);

				} else {
					var obj = sequence.items[1];

					parameters = {
						p: obj.items[1].items[1].intVal.toString(16),
						a: Buffer.from(obj.items[2].items[0].value, 'latin1').toString('hex'),
						b: Buffer.from(obj.items[2].items[1].value, 'latin1').toString('hex'),
						g: Buffer.from(obj.items[3].value, 'latin1').toString('hex'),
						n: obj.items[4].intVal.toString(16),
						h: obj.items[5].intVal,
						type: (obj.items[1].items[0].value == '1.2.840.10045.1.1' ?
							'prime' : 'binary'),
						seed: typeof obj.items[2].items[2] == 'undefined' ?
							null : Buffer.from(obj.items[2].items[2].value, 'latin1').toString('hex')
					};
				}

				return {
					algo: algo,
					parameters: parameters
				};

			default:
				throw jCastle.exception("UNSUPPORTED_PKI", 'CRT050');
		}
	},

	schema: function(pubkey_info)
	{

		var encryptionInfoSchema;

		switch (pubkey_info.algo) {
			case 'RSA':
				if ('padding' in pubkey_info && 
					'mode' in pubkey_info.padding && 
					(pubkey_info.padding.mode.toLowerCase() == 'rsaes-oaep' || 
					pubkey_info.padding.mode.toLowerCase() == 'pkcs1_oaep')) { // pkcs1_oaep
/*
		SEQUENCE(2 elem)
			SEQUENCE(2 elem)
				OBJECT IDENTIFIER					1.2.840.113549.1.1.7			-- rsaOAEP
				SEQUENCE(3 elem)
					[0](1 elem)
						SEQUENCE(2 elem)
							OBJECT IDENTIFIER		2.16.840.1.101.3.4.2.1			-- sha-256
							NULL
					[1](1 elem)
						SEQUENCE(2 elem)
							OBJECT IDENTIFIER		1.2.840.113549.1.1.8			-- pkcs1-MGF
							SEQUENCE(2 elem)
								OBJECT IDENTIFIER	2.16.840.1.101.3.4.2.1			-- sha-256
								NULL
					[2](1 elem)
						SEQUENCE(2 elem)
							OBJECT IDENTIFIER		1.2.840.113549.1.1.9			-- rsaOAEP-pSpecified
							OCTET STRING(5 byte)	5443504100
			BIT STRING(1 elem)
				SEQUENCE(2 elem)
					INTEGER(4096 bit)				664158030327658656011019037255739017511931322784390718439712888538135…
					INTEGER							65537
*/
					var hash_name = 'sha-1';
					var label = '';
					//if (typeof pubkey_info.padding.hashAlgo != 'undefined') {
					if ('hashAlgo' in pubkey_info.padding) {
						hash_name = jCastle.digest.getValidAlgoName(pubkey_info.padding.hashAlgo);
					}
					//if (typeof pubkey_info.padding.label != 'undefined') {
					if ('label' in pubkey_info.padding) {
						label = pubkey_info.padding.label;
					}

					encryptionInfoSchema = {
						type: jCastle.asn1.tagSequence,
						items: [{
							type: jCastle.asn1.tagOID,
							value: jCastle.oid.getOID("rsaOAEP")
						}]
					};

					encryptionInfoSchema.items.push({
						type: jCastle.asn1.tagSequence,
						items: []
					});

					if (hash_name != 'sha-1') {
	//					encryptionInfoSchema.items.push({
	//						type: jCastle.asn1.tagSequence,
	//						items: []
	//					});

						encryptionInfoSchema.items[1].items.push({
							tagClass: jCastle.asn1.tagClassContextSpecific,
							type: 0x00,
							constructed: true,
							items: [{
								type: jCastle.asn1.tagSequence,
								items: [{
									type: jCastle.asn1.tagOID,
									value: jCastle.digest.getOID(hash_name)
								}, {
									type: jCastle.asn1.tagNull,
									value: null
								}]
							}]
						});

						encryptionInfoSchema.items[1].items.push({
							tagClass: jCastle.asn1.tagClassContextSpecific,
							type: 0x01,
							constructed: true,
							items: [{
								type: jCastle.asn1.tagSequence,
								items: [{
									type: jCastle.asn1.tagOID,
									value: jCastle.oid.getOID("pkcs1-MGF")
								}, {
									type: jCastle.asn1.tagSequence,
									items: [{
										type: jCastle.asn1.tagOID,
										value: jCastle.digest.getOID(hash_name)
									}, {
										type: jCastle.asn1.tagNull,
										value: null
									}]
								}]
							}]
						});
					}

					if (label.length) {
						encryptionInfoSchema.items[1].items.push({
							tagClass: jCastle.asn1.tagClassContextSpecific,
							type: 0x02,
							constructed: true,
							items: [{
								type: jCastle.asn1.tagSequence,
								items: [{
									type: jCastle.asn1.tagOID,
									value: jCastle.oid.getOID("rsaOAEP-pSpecified")
								}, {
									type: jCastle.asn1.tagOctetString,
									value: label
								}]
							}]
						});
					}

				} else {
					encryptionInfoSchema = {
						type: jCastle.asn1.tagSequence,
						items:[{
								type: jCastle.asn1.tagOID,
								value: jCastle.oid.getOID("rsaEncryption")
							}, {
								type: jCastle.asn1.tagNull,
								value: null
							}
						]
					};
				}
				break;

			case 'DSA':
			case 'KCDSA':
				encryptionInfoSchema = {
					type: jCastle.asn1.tagSequence,
					items: [{
						type: jCastle.asn1.tagOID,
						//value: jCastle.oid.DSAPublicKey
						value: pubkey_info.algo == 'DSA' ? jCastle.oid.getOID("dsaPublicKey") : jCastle.oid.getOID("kcdsa")
					}, {
						type: jCastle.asn1.tagSequence,
						items: [{
							type: jCastle.asn1.tagInteger,
							intVal: BigInt('0x' + pubkey_info.parameters.p)
						}, {
							type: jCastle.asn1.tagInteger,
							intVal: BigInt('0x' + pubkey_info.parameters.q)
						}, {
							type: jCastle.asn1.tagInteger,
							intVal: BigInt('0x' + pubkey_info.parameters.g)
						}]
					}]
				};
				break;

			case 'ECDSA':
			case 'ECKCDSA':
				var params_schema;

				if (jCastle.util.isString(pubkey_info.parameters)) {
					var parameters = jCastle.pki.ecdsa.getParameters(pubkey_info.parameters);
					if (!parameters) {
						throw jCastle.exception("UNKNOWN_ECDSA_CURVE", 'CRT052');
					}
					params_schema = {
						type: jCastle.asn1.tagOID,
						value: parameters.OID
					};				
				} else if (pubkey_info.parameters.OID && jCastle.pki.ecdsa.getParametersByOID(pubkey_info.parameters.OID)) {
					params_schema = {
						type: jCastle.asn1.tagOID,
						value: pubkey_info.parameters.OID
					}
				} else {
					var g;

					if ('g' in pubkey_info.parameters) {
						g = pubkey_info.parameters.g;
					} else {
						g = '04' + pubkey_info.parameters.gx + pubkey_info.parameters.gy;
					}

					params_schema = {
						type: jCastle.asn1.tagSequence,
						items: [{
							type: jCastle.asn1.tagInteger,
							intVal: 0x01
						}, {
							type: jCastle.asn1.tagSequence,
							items: [{
								type: jCastle.asn1.tagOID,
								value: jCastle.oid.getOID(pubkey_info.parameters.type)
							}, {
								type: jCastle.asn1.tagInteger,
								intVal: BigInt('0x' + pubkey_info.parameters.p)
							}]
						}, {
							type: jCastle.asn1.tagSequence,
							items: [{
								type: jCastle.asn1.tagOctetString,
								value: Buffer.from(pubkey_info.parameters.a, 'hex').toString('latin1')
							}, {
								type: jCastle.asn1.tagOctetString,
								value: Buffer.from(pubkey_info.parameters.b, 'hex').toString('latin1')
							}]
						}, {
							type: jCastle.asn1.tagOctetString,
							value: Buffer.from(g, 'hex').toString('latin1')
						}, {
							type: jCastle.asn1.tagInteger,
							intVal: BigInt('0x' + pubkey_info.parameters.n)
						}, {
							type: jCastle.asn1.tagInteger,
							intVal: pubkey_info.parameters.h
						}]
					};

					if ('seed' in pubkey_info.parameters) {
						params_schema.items[2].items.push({
							type: jCastle.asn1.tagBitString,
							value: Buffer.from(pubkey_info.parameters.seed, 'hex').toString('latin1')
						});
					}
				}

				encryptionInfoSchema = {
					type: jCastle.asn1.tagSequence,
					items: [{
						type: jCastle.asn1.tagOID,
						value: pubkey_info.algo == 'ECDSA' ? jCastle.oid.getOID("ecPublicKey") : jCastle.oid.getOID("eckcdsa-PublicKey")
					},
					params_schema
					]
				};

				break;

			default:
				throw jCastle.exception("UNSUPPORTED_PKI", 'CRT053');
		}

		return encryptionInfoSchema;
	}
};

jCastle.certificate.asn1.publicKeyInfo =
{
	parse: function(sequence)
	{
		var encryptionInfo = jCastle.certificate.asn1.encryptionInfo.parse(sequence.items[0]);
		var publicKeyInfo = {};
		publicKeyInfo.algo = encryptionInfo.algo;

		switch (encryptionInfo.algo) {
			case 'RSA':
/*
SEQUENCE(2 elem)
	SEQUENCE(2 elem)
		OBJECT IDENTIFIER				1.2.840.113549.1.1.1 -- rsaEncryption
		NULL
	BIT STRING(1 elem)
		SEQUENCE(2 elem)
			INTEGER(2048 bit)			227779114708502272098325245002574518989245659902413298145007125468342…
			INTEGER						65537
*/
/*
SEQUENCE(2 elem)
	SEQUENCE(2 elem)
		OBJECT IDENTIFIER					1.2.840.113549.1.1.7			-- rsaOAEP
		SEQUENCE(3 elem)
			[0](1 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER		2.16.840.1.101.3.4.2.1			-- sha-256
					NULL
			[1](1 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER		1.2.840.113549.1.1.8			-- pkcs1-MGF
					SEQUENCE(2 elem)
						OBJECT IDENTIFIER	2.16.840.1.101.3.4.2.1			-- sha-256
						NULL
			[2](1 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER		1.2.840.113549.1.1.9			-- rsaOAEP-pSpecified
					OCTET STRING(5 byte)	5443504100
	BIT STRING(1 elem)
		SEQUENCE(2 elem)
			INTEGER(4096 bit)				664158030327658656011019037255739017511931322784390718439712888538135…
			INTEGER							65537
*/
				publicKeyInfo.padding = encryptionInfo.padding;
				// RSA public key
				publicKeyInfo.publicKey = {
					n: sequence.items[1].value.items[0].intVal,
					e: sequence.items[1].value.items[1].intVal
				};
				break;

			case 'DSA':
			case 'KCDSA':
/*
SEQUENCE(2 elem)
	SEQUENCE(2 elem)
		OBJECT IDENTIFIER							1.2.840.10040.4.1
		SEQUENCE(3 elem)
			INTEGER(512 bit)						1059737101307583423773365291471308579078488704489115911085634432411115…
			INTEGER(160 bit)						1136771903766864588646460987672585907071280159691
			INTEGER(511 bit)						6080403149879288484722246281095513413782108194542709043888624572962448…
	BIT STRING(1 elem)
		INTEGER(510 bit)							3105422500172510974640640172011055463815065000953138033165236981533719…
*/
				publicKeyInfo.parameters = encryptionInfo.parameters;
				publicKeyInfo.publicKey = sequence.items[1].value.intVal;
				break;

			case 'ECDSA':
			case 'ECKCDSA':
/*
SEQUENCE(2 elem)
	SEQUENCE(2 elem)
		OBJECT IDENTIFIER				1.2.840.10045.2.1
		OBJECT IDENTIFIER				1.3.132.0.39
	BIT STRING(1160 bit)				000001000000001000011001110100010001011100110100011000110111100011101…
*/
				publicKeyInfo.parameters = encryptionInfo.parameters;
				publicKeyInfo.publicKey = Buffer.from(sequence.items[1].value, 'latin1');
				break;

			default:
				throw jCastle.exception("UNSUPPORTED_PKI", 'CRT051');
		}

		publicKeyInfo.type = 'public';

		return publicKeyInfo;
	},

	schema: function(pubkey_info)
	{
		var schema = {
			type: jCastle.asn1.tagSequence,
			items: []
		};
		
		var encryptionInfoSchema = jCastle.certificate.asn1.encryptionInfo.schema(pubkey_info);
		
		schema.items.push(encryptionInfoSchema);

		switch (pubkey_info.algo) {
			case 'RSA':
				schema.items.push({	
					type: jCastle.asn1.tagBitString,
					value: {
						type: jCastle.asn1.tagSequence,
						items:[{
							type: jCastle.asn1.tagInteger,
							intVal: jCastle.util.toBigInt(pubkey_info.publicKey.n)
						}, {
							type: jCastle.asn1.tagInteger,
							intVal: pubkey_info.publicKey.e
						}]
					}
				});
				break;

			case 'DSA':
			case 'KCDSA':
				schema.items.push({
					type: jCastle.asn1.tagBitString,
					value: {
						type: jCastle.asn1.tagInteger,
						intVal: jCastle.util.toBigInt(pubkey_info.publicKey)
					}
				});
				break;

			case 'ECDSA':
			case 'ECKCDSA':
				schema.items.push({
					type: jCastle.asn1.tagBitString,
					value: pubkey_info.publicKey // should be buffer data
				});
				break;

			default:
				throw jCastle.exception("UNSUPPORTED_PKI", 'CRT054');
		}

		return schema;
	}
};

jCastle.certificate.asn1.relativeDistinguishedName = 
{
	parse: function(set)
	{
		var names = [];

		for (var i = 0; i < set.items.length; i++) {
			var obj = set.items[i];
			var n = {};

			n.name = jCastle.oid.getName(obj.items[0].value);
			n.value = obj.items[1].value;
			n.type = obj.items[1].type;

			names.push(n);
		}

		return names;	
	},

	schema: function(names)
	{
		var schema = {
			type: jCastle.asn1.tagSet,
			items: []
		};

		for (var i = 0; i < names.length; i++) {
			var o = {
				type: jCastle.asn1.tagSequence,
				items: [{
					type: jCastle.asn1.tagOID,
					value: jCastle.oid.getOID(names[i].name)
				}, {
					type: names[i].type,
					value: names[i].value
				}]
			};
			
			schema.items.push(o);
		}

		return schema;
	}
};
	
jCastle.certificate.asn1.directoryName =
{
	parse: function(sequence)
	{
		var names = [];
		for (var i = 0; i < sequence.items.length; i++) {
			var n = jCastle.certificate.asn1.relativeDistinguishedName.parse(sequence.items[i]);
			names = names.concat(n);
		}

		return names;
	},

	schema: function(names)
	{
		var obj = {
			type: jCastle.asn1.tagSequence,
			items: []
		};

		for (var i = 0; i < names.length; i++) {
			var n = names[i];

			if (!n.value.length) continue;

			switch (n.name) {
				case 'countryName':
				case 'C':
					obj.items.push({
						type: jCastle.asn1.tagSet,
						items: [{
								type: jCastle.asn1.tagSequence,
								items: [{
										type: jCastle.asn1.tagOID,
										value: jCastle.oid.getOID("countryName")
									}, {
										type: 'type' in n ? n.type : jCastle.asn1.tagPrintableString,
										value: n.value
									}
								]
							}
						]
					});
					break;
				case 'stateOrProvinceName':
				case 'ST':
					obj.items.push({
						type: jCastle.asn1.tagSet,
						items: [{
								type: jCastle.asn1.tagSequence,
								items: [{
										type: jCastle.asn1.tagOID,
										value: jCastle.oid.getOID("stateOrProvinceName")
									}, {
										type: 'type' in n ? n.type : jCastle.asn1.tagUTF8String,
										value: n.value
									}
								]
							}
						]
					});
					break;
				case 'localityName':
				case 'L':
					obj.items.push({
						type: jCastle.asn1.tagSet,
						items: [{
								type: jCastle.asn1.tagSequence,
								items: [{
										type: jCastle.asn1.tagOID,
										value: jCastle.oid.getOID("localityName")
									}, {
										type: 'type' in n ? n.type : jCastle.asn1.tagUTF8String,
										value: n.value
									}
								]
							}
						]
					});
					break;
				case 'organizationName':
				case 'O':
					obj.items.push({
						type: jCastle.asn1.tagSet,
						items: [{
								type: jCastle.asn1.tagSequence,
								items: [{
										type: jCastle.asn1.tagOID,
										value: jCastle.oid.getOID("organizationName")
									}, {
										type: 'type' in n ? n.type : jCastle.asn1.tagUTF8String,
										value: n.value
									}
								]
							}
						]
					});
					break;
				case 'organizationalUnitName':
				case 'OU':
					obj.items.push({
						type: jCastle.asn1.tagSet,
						items: [{
								type: jCastle.asn1.tagSequence,
								items: [{
										type: jCastle.asn1.tagOID,
										value: jCastle.oid.getOID("organizationalUnitName")
									}, {
										type: 'type' in n ? n.type : jCastle.asn1.tagUTF8String,
										value: n.value
									}
								]
							}
						]
					});
					break;
				case 'commonName':
				case 'CN':
					obj.items.push({
						type: jCastle.asn1.tagSet,
						items: [{
								type: jCastle.asn1.tagSequence,
								items: [{
										type: jCastle.asn1.tagOID,
										value: jCastle.oid.getOID("commonName")
									}, {
										type: 'type' in n ? n.type : jCastle.asn1.tagUTF8String,
										value: n.value
									}
								]
							}
						]
					});
					break;
				case 'emailAddress':
				case 'E':
					obj.items.push({
						type: jCastle.asn1.tagSet,
						items: [{
								type: jCastle.asn1.tagSequence,
								items: [{
										type: jCastle.asn1.tagOID,
										value: jCastle.oid.getOID("emailAddress")
									}, {
										type: 'type' in n ? n.type : jCastle.asn1.tagIA5String,
										value: n.value
									}
								]
							}
						]
					});
					break;
				case 'streetAddress':
				case 'STREET':
					obj.items.push({
						type: jCastle.asn1.tagSet,
						items: [{
								type: jCastle.asn1.tagSequence,
								items: [{
										type: jCastle.asn1.tagOID,
										value: jCastle.oid.getOID("streetAddress")
									}, {
										type: 'type' in n ? n.type : jCastle.asn1.tagUTF8String,
										value: n.value
									}
								]
							}
						]
					});
					break;
			}
		}
		
		return obj;
	}
};



jCastle.certificate.asn1.signature = 
{
	parse: function(obj, signAlgo)
	{
		// switch (signAlgo) {
		// 	case 'DSA':
		// 	case 'KCDSA':
		// 	case 'ECDSA':
		// 	case 'ECKCDSA':
		// 	case 'ELGAMAL':
		// 		if ('buffer' in obj.value) return obj.value.buffer.toString('latin1');
		// 		if ('der' in obj.value) return obj.value.der;
		// 		return obj.value;
		// 	case 'RSASSA-PKCS1-V1_5':
		// 	case 'RSASSA-PSS':
		// 	default:
		// 		if (obj.type == jCastle.asn1.tagBitString) return obj.value;
		// 		throw jCastle.exception("SIGNATURE_GET_FAIL", 'CRT006');
		// }

		if (typeof obj.value == 'object' && 'buffer' in obj.value) return obj.value.buffer;
		// if (typeof obj.value == 'object' && 'der' in obj.value) return Buffer.from(obj.value.der, 'latin1');
		return Buffer.from(obj.value, 'latin1');
	},

	schema: function(signature)
	{
		//if (/^[0-9A-F]+/i.test(signature)) signature = Buffer.from(signature, 'hex').toString('latin1');
		if (/^[0-9A-F]+/i.test(signature)) signature = Buffer.from(signature, 'hex');
		return {
			type: jCastle.asn1.tagBitString,
			value: signature
		};
	}
};

jCastle.certificate.asn1.validity = 
{
	parse: function(seq)
	{
		var validity = {};

		if (seq.items[0].type != jCastle.asn1.tagUTCTime &&
			seq.items[0].type == jCastle.asn1.tagGeneralizedTime)
			throw jCastle.exception('INVALID_PEM_FORMAT', 'CRT076');
		 
		validity.notBefore = seq.items[0].value;

		if (seq.items[1].type != jCastle.asn1.tagUTCTime &&
			seq.items[1].type == jCastle.asn1.tagGeneralizedTime)
			throw jCastle.exception('INVALID_PEM_FORMAT', 'CRT077');

		validity.notAfter = seq.items[1].value;

		return validity;
	},

	schema: function(validity, default_days)
	{
		validity = validity || {};
		default_days = default_days || 365;

		var notBefore, notAfter;

		// if no dates given then
		if ('notBefore' in validity) notBefore = validity.notBefore;
		else notBefore = new Date();

		if ('notAfter' in validity) notAfter = validity.notAfter;
		else {
			notAfter = new Date();

			if (default_days % 365) 
				notAfter.setDate(notAfter.getDate + default_days);
			else {
				var years = parseInt(default_days / 365);
				notAfter.setYear(notAfter.getFullYear() + years);
			}
		}

		return {
			type: jCastle.asn1.tagSequence,
			items:[{
					type: jCastle.asn1.tagUTCTime,
					value: notBefore
				}, {
					type: jCastle.asn1.tagUTCTime,
					value: notAfter
				}
			]
		};
	}
};


jCastle.certificate.asn1.policyInformation = 
{
	parse: function(sequence, critical)
	{
/*
SEQUENCE(3 elem)
	OBJECT IDENTIFIER						2.5.29.32 -- certificatePolicies
	BOOLEAN									true
	OCTET STRING(1 elem)
		SEQUENCE(1 elem) <--
			SEQUENCE(2 elem)
				OBJECT IDENTIFIER			1.2.410.200005.1.1.4 -- 금융결제원 은행개인
				SEQUENCE(2 elem)
					SEQUENCE(2 elem)
						OBJECT IDENTIFIER	1.3.6.1.5.5.7.2.2 -- unotice
						SEQUENCE(1 elem)
							BMPString		이 인증서는 공인인증서 입니다
					SEQUENCE(2 elem)
						OBJECT IDENTIFIER	1.3.6.1.5.5.7.2.1 -- cps
						IA5String			http://www.yessign.or.kr/cps.htm
*/
/*
SEQUENCE(2 elem)
	OBJECT IDENTIFIER								2.5.29.32 -- certificatePolicies
	OCTET STRING(1 elem)
		SEQUENCE(2 elem)
			SEQUENCE(1 elem)
				OBJECT IDENTIFIER					1.3.6.1.4.1.23485.5.1.1.0.1
			SEQUENCE(1 elem)
				OBJECT IDENTIFIER					1.3.6.1.4.1.23485.5.1.1.0.3
*/
/*
openssl config setting:

certificatePolicies=ia5org,1.2.3.4,1.5.7.8,@polsect

[polsect]

policyIdentifier=1.3.5.8
CPS.1="http://my.host.name/"
CPS.2="http://my.your.name/"
userNotice.1=@notice

[notice]
explicitText="Explicit Text here"
organization="organisation Name"
noticeNumbers=1,2,3,4


SEQUENCE(2 elem)
	OBJECT IDENTIFIER								2.5.29.32
	OCTET STRING(1 elem)
		SEQUENCE(3 elem)
			SEQUENCE(1 elem)
				OBJECT IDENTIFIER						1.2.3.4
			SEQUENCE(1 elem)
				OBJECT IDENTIFIER						1.5.7.8
			SEQUENCE(2 elem)
				OBJECT IDENTIFIER						1.3.5.8
				SEQUENCE(3 elem)
					SEQUENCE(2 elem)
						OBJECT IDENTIFIER				1.3.6.1.5.5.7.2.1 -- cps
						IA5String						http://my.host.name/
					SEQUENCE(2 elem)
						OBJECT IDENTIFIER				1.3.6.1.5.5.7.2.1 -- cps
						IA5String						http://my.your.name/
					SEQUENCE(2 elem)
						OBJECT IDENTIFIER				1.3.6.1.5.5.7.2.2 -- unotice
						SEQUENCE(2 elem)
							SEQUENCE(2 elem)
								IA5String				organisation Name
								SEQUENCE(4 elem)
									INTEGER				1
									INTEGER				2
									INTEGER				3
									INTEGER				4
							VisibleString				Explicit Text here
*/
/*
SEQUENCE (3 elem)
	OBJECT IDENTIFIER 2.5.29.32 certificatePolicies (X.509 extension)
	BOOLEAN true
	OCTET STRING (1 elem)
		SEQUENCE (1 elem)
			SEQUENCE (2 elem)
				OBJECT IDENTIFIER 1.2.410.200004.5.4.2.14
				SEQUENCE (2 elem)
					SEQUENCE (2 elem)
						OBJECT IDENTIFIER 1.3.6.1.5.5.7.2.1 cps (PKIX policy qualifier)
						IA5String http://gca.crosscert.com/cps.html
					SEQUENCE (2 elem)
						OBJECT IDENTIFIER 1.3.6.1.5.5.7.2.2 unotice (PKIX policy qualifier)
						SEQUENCE (1 elem)
							BMPString 이 인증서는 공인 인증서입니다.
*/
/*
certificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation

PolicyInformation ::= SEQUENCE {
  policyIdentifier  CertPolicyId,
  policyQualifiers  SEQUENCE SIZE (1..MAX) OF PolicyQualifierInfo OPTIONAL,
  ...
}

CertPolicyId ::= OBJECT IDENTIFIER

PolicyQualifierInfo ::= SEQUENCE {
  policyQualifierId  CERT-POLICY-QUALIFIER.&id({SupportedPolicyQualifiers}),
  qualifier
    CERT-POLICY-QUALIFIER.&Qualifier
      ({SupportedPolicyQualifiers}{@policyQualifierId}) OPTIONAL,
  ...
}

SupportedPolicyQualifiers CERT-POLICY-QUALIFIER ::=
  {...}

anyPolicy OBJECT IDENTIFIER ::= {id-ce-certificatePolicies 0}

CERT-POLICY-QUALIFIER ::= CLASS {
  &id         OBJECT IDENTIFIER UNIQUE,
  &Qualifier  OPTIONAL
}WITH SYNTAX {POLICY-QUALIFIER-ID &id
              [QUALIFIER-TYPE &Qualifier]
}
*/


		var policyInformation = [];

		for (var i = 0; i < sequence.items.length; i++) {
			var seq = sequence.items[i];
			var policyIdentifier = jCastle.oid.getName(seq.items[0].value);
			if (!policyIdentifier) {
				// for the time being we will comment this.
				// for I don't find oid: 1.2.410.200004.5.4.2.14
				//if (critical) throw jCastle.exception("UNSUPPORTED_EXTENSION", 'CRT040');
				policyIdentifier = seq.items[0].value;
			}
			var policyQualifiers = [];

			if (seq.items.length > 1) {
				for (var j = 0; j < seq.items[1].items.length; j++) {
					var s = seq.items[1].items[j];
					var policyQualifierInfo = {};
					var policyQualifierId = jCastle.oid.getName(s.items[0].value);
					if (!policyQualifierId) policyQualifierId = s.items[0].value;

/*
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER				1.3.6.1.5.5.7.2.1 -- cps
					IA5String						http://my.your.name/
				SEQUENCE(2 elem)                                                       <!-- s
					OBJECT IDENTIFIER				1.3.6.1.5.5.7.2.2 -- unotice
					SEQUENCE(2 elem)                                                   <!-- s.items[1]
						SEQUENCE(2 elem)
							IA5String				organisation Name
							SEQUENCE(4 elem)
								INTEGER				1
								INTEGER				2
								INTEGER				3
								INTEGER				4
						VisibleString				Explicit Text here
*/

					var qualifier;

					if (s.items[1].type == jCastle.asn1.tagSequence) {
						if (policyQualifierId == 'unotice') {
							qualifier = {};
							var idx = 0;
							if (s.items[1].items[idx].type == jCastle.asn1.tagSequence) {
								var idx2 = 0;
								if (s.items[1].items[idx].items[idx2].type != jCastle.asn1.tagSequence) {
									qualifier.organization = {
										value: s.items[1].items[idx].items[idx2].value,
										type: s.items[1].items[idx].items[idx2].type
									};
									idx2++;
								}
								if (typeof s.items[1].items[idx].items[idx2] != 'undefined' &&
									s.items[1].items[idx].items[idx2].type == jCastle.asn1.tagSequence
								) {
									qualifier.noticeNumbers = [];
									for (var n = 0; n < s.items[1].items[idx].items[idx2].items.length; n++) {
										qualifier.noticeNumbers.push(
											s.items[1].items[idx].items[idx2].items[n].intVal
										);
									}
								}
								idx++;
							}

							if (typeof s.items[1].items[idx] != 'undefined') {
								qualifier.explicitText = {
									value: s.items[1].items[idx].value,
									type: s.items[1].items[idx].type
								};
							}

						} else {
							qualifier = [];
							for (var l = 0; l < s.items[1].items.length; l++) {
								var q = s.items[1].items[l];
								qualifier.push({
									value: q.value,
									type: q.type
								});
							}
						}
					} else {
						qualifier = {
							value: s.items[1].value,
							type: s.items[1].type
						};
					}

					policyQualifierInfo.policyQualifierId = policyQualifierId;
					policyQualifierInfo.qualifier = qualifier;

					policyQualifiers.push(policyQualifierInfo);
				}
			}

			var information = {
				policyIdentifier: policyIdentifier
			};

			if (policyQualifiers.length) {
				information.policyQualifiers = policyQualifiers;
			}

			policyInformation.push(information);
		}

		return policyInformation;
	},

	schema: function(policyInformation, config)
	{
		var infoSchema = [];

		for (var i = 0; i < policyInformation.length; i++) {
			var information = policyInformation[i];
			var qualifiers = [];

			if ('policyQualifiers' in information) {
				for (var j = 0; j < information.policyQualifiers.length; j++) {
					var qual = information.policyQualifiers[j];
					var oid = jCastle.oid.getOID(qual.policyQualifierId, null, config);
					if (!oid) throw jCastle.exception("UNSUPPORTED_EXTENSION", 'CRT059');

					var q = {
						type: jCastle.asn1.tagSequence,
						items: [{
							type: jCastle.asn1.tagOID,
							value: oid
						}]
					};

/*
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER				1.3.6.1.5.5.7.2.1 -- cps
					IA5String						http://my.your.name/
				SEQUENCE(2 elem)                                                       <!-- s
					OBJECT IDENTIFIER				1.3.6.1.5.5.7.2.2 -- unotice
					SEQUENCE(2 elem)                                                   <!-- s.items[1]
						SEQUENCE(2 elem)
							IA5String				organisation Name
							SEQUENCE(4 elem)
								INTEGER				1
								INTEGER				2
								INTEGER				3
								INTEGER				4
						VisibleString				Explicit Text here
*/

					if (qual.policyQualifierId == 'unotice') {
						/*
						qualifier = {
							organization: type-value,
							noticeNumbers: array,
							explicitText: type-value
						}
						*/
						var v = [];

						if ('organization' in qual.qualifier || 'noticeNumbers' in qual.qualifier) {
							var notice = {
								type: jCastle.asn1.tagSequence,
								items: []
							};

							if ('organization' in qual.qualifier) {
								notice.items.push({
									type: qual.qualifier.organization.type ? qual.qualifier.organization.type : jCastle.asn1.tagIA5String,
									value: qual.qualifier.organization.value
								});
							}

							if ('noticeNumbers' in qual.qualifier) {
								var numbers = {
									type: jCastle.asn1.tagSequence,
									items: []
								};

								for (var n = 0; n < qual.qualifier.noticeNumbers.length; n++) {
									numbers.items.push({
										type: jCastle.asn1.tagInteger,
										intVal: qual.qualifier.noticeNumbers[n]
									});
								}
								notice.items.push(numbers);
							}

							v.push(notice);
						}

						if ('explicitText' in qual.qualifier) {
							v.push({
								type: 'type' in qual.qualifier.explicitText ? qual.qualifier.explicitText.type : jCastle.asn1.tagUTF8String, //jCastle.asn1.tagVisibleString,
								value: qual.qualifier.explicitText.value
							});
						}

						q.items.push({
							type: jCastle.asn1.tagSequence,
							items: v
						});
					} else {
						if (Array.isArray(qual.qualifier)) {
							var v = [];
							for (var k = 0; k < qual.qualifier.length; k++) {
								v.push({
									type: 'type' in qual.qualifier[k] ? qual.qualifier[k].type : jCastle.asn1.tagBMPString,
									value: qual.qualifier[k].value
								});
							}

							q.items.push({
								type: jCastle.asn1.tagSequence,
								items: v
							});
						} else {
							q.items.push({
								type: 'type' in qual.qualifier ? qual.qualifier.type : jCastle.asn1.tagIA5String,
								value: qual.qualifier.value
							});
						}
					}

					qualifiers.push(q);
				}
			}

			var schema = {
				type: jCastle.asn1.tagSequence,
				items: [{
					type: jCastle.asn1.tagOID,
					value: jCastle.oid.getOID(information.policyIdentifier, null, config)
				}]
			};

			if (qualifiers.length) {
				schema.items.push({
					type: jCastle.asn1.tagSequence,
					items: qualifiers
				});
			}
			
			infoSchema.push(schema);
		}

		var piSchema = {
			type: jCastle.asn1.tagSequence,
			items: infoSchema
		};

		return piSchema;
	}
};


jCastle.certificate.ASN1 = jCastle.certificate.asn1;

/*
STANDARD EXTENSIONS
===================

The following sections describe each supported extension in detail.

*/

/*
Key Usage
---------

Key usage is a multi valued extension consisting of a list of names of the permitted key usages.

The supported names are: digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment,
keyAgreement, keyCertSign, cRLSign, encipherOnly and decipherOnly.

Examples:

	keyUsage=digitalSignature, nonRepudiation

	keyUsage=critical, keyCertSign
*/
/*
https://www.ietf.org/rfc/rfc4055.txt

   Here, the modulus is the modulus n, and publicExponent is the public
   exponent e.  The DER encoded RSAPublicKey is carried in the
   subjectPublicKey BIT STRING within the subject public key
   information.

   The intended application for the key MAY be indicated in the keyUsage
   certificate extension (see [PROFILE], Section 4.2.1.3).

   If the keyUsage extension is present in an end-entity certificate
   that conveys an RSA public key with the id-RSASSA-PSS object
   identifier, then the keyUsage extension MUST contain one or both of
   the following values:

      nonRepudiation; and
      digitalSignature.

   If the keyUsage extension is present in a certification authority
   certificate that conveys an RSA public key with the id-RSASSA-PSS
   object identifier, then the keyUsage extension MUST contain one or
   more of the following values:

      nonRepudiation;
      digitalSignature;
      keyCertSign; and
      cRLSign.

   When a certificate conveys an RSA public key with the id-RSASSA-PSS
   object identifier, the certificate user MUST only use the certified
   RSA public key for RSASSA-PSS operations, and, if RSASSA-PSS-params
   is present, the certificate user MUST perform those operations using
   the one-way hash function, mask generation function, and trailer
   field identified in the subject public key algorithm identifier
   parameters within the certificate.

   If the keyUsage extension is present in a certificate conveys an RSA
   public key with the id-RSAES-OAEP object identifier, then the
   keyUsage extension MUST contain only the following values:

      keyEncipherment; and
      dataEncipherment.

   However, both keyEncipherment and dataEncipherment SHOULD NOT be
   present.

   When a certificate that conveys an RSA public key with the
   id-RSAES-OAEP object identifier, the certificate user MUST only use
   the certified RSA public key for RSAES-OAEP operations, and, if
   RSAES-OAEP-params is present, the certificate user MUST perform those
   operations using the one-way hash function and mask generation
   function identified in the subject public key algorithm identifier
   parameters within the certificate.

*/
jCastle.certificate.extensions["keyUsage"] = 
{
/*
 OID value: 2.5.29.15

OID description:
id-ce-keyUsage

This extension indicates the purpose for which the certified public key is used.

This extension may, at the option of the certificate issuer, be either critical or non-critical.

keyUsage EXTENSION ::= {
	SYNTAX KeyUsage
	IDENTIFIED BY id-ce-keyUsage
}

KeyUsage ::= BIT STRING {
	digitalSignature(0),
	nonRepudiation(1),
	keyEncipherment(2),
	dataEncipherment(3),
	keyAgreement(4),
	keyCertSign(5),
	cRLSign(6),
	encipherOnly(7),
	decipherOnly(8)
}

explain: cRLSign(6) turns 7th bit on then it will be like "00000010" which is 0x02
*/
	parse: function(seq)
	{
/*
SEQUENCE(3 elem)
	OBJECT IDENTIFIER		2.5.29.15 -- keyUsage
	BOOLEAN					true
	OCTET STRING(1 elem)
		BIT STRING(2 bit)	11
*/
		var keyUsage = {};
		var idx = 1;
		keyUsage.list = [];
		keyUsage.critical = false; // default

		if (seq.items[idx].type == jCastle.asn1.tagBoolean) {
			keyUsage.critical = seq.items[idx].value ? true : false;
			idx++;
		}


		// tagBitString can be parsed more and have no errors.
		//var c = seq.items[idx].value.value.charCodeAt(0);
		var c = jCastle.util.isString(seq.items[idx].value.value) ? 
			// seq.items[idx].value.value.charCodeAt(0) : seq.items[idx].value.value.der.charCodeAt(0);
			seq.items[idx].value.value.charCodeAt(0) : seq.items[idx].value.value.buffer[0];

		if (c & 0x80) keyUsage.list.push('digitalSignature');			// 1000 0000
		if (c & 0x40) keyUsage.list.push('nonRepudiation');				// 0100 0000
//		if (c & 0x40) keyUsage.list.push('contentCommitment');			// 0100 0000
		if (c & 0x20) keyUsage.list.push('keyEncipherment');			// 0010 0000
		if (c & 0x10) keyUsage.list.push('dataEncipherment');			// 0001 0000
		if (c & 0x08) keyUsage.list.push('keyAgreement');				// 0000 1000
		if (c & 0x04) keyUsage.list.push('keyCertSign');				// 0000 0100
		if (c & 0x02) keyUsage.list.push('cRLSign');					// 0000 0010
		//if (c & 0x01 && c & 0x08) keyUsage.list.push('encipherOnly');	// 0000 0001
		if (c & 0x01) keyUsage.list.push('encipherOnly');				// 0000 0001

		if (seq.items[idx].value.value.length == 2) {
			var c2 = seq.items[idx].value.value.charCodeAt(1);
			//if (c2 & 0x80 && c & 0x08) keyUsage.list.push('decipherOnly');
			if (c2 & 0x80) keyUsage.list.push('decipherOnly');
		}

		return keyUsage;
	},

	schema: function(keyUsage)
	{
		// self-signed signature is cRLSign
		var c = 0;
		var c2 = 0;

		for (var i = 0; i < keyUsage.list.length; i++) {
			switch (keyUsage.list[i]) {
				case 'digitalSignature':	c |= 0x80; break;
				case 'nonRepudiation':
				case 'contentCommitment':	c |= 0x40; break;
				case 'keyEncipherment':		c |= 0x20; break;
				case 'dataEncipherment':	c |= 0x10; break;
				case 'keyAgreement':		c |= 0x08; break;
				case 'keyCertSign':			c |= 0x04; break;
				case 'cRLSign' :			c |= 0x02; break;
				case 'encipherOnly': 		c |= 0x01;
											c |= 0x08; break;
				case 'decipherOnly':		c2 |= 0x80;
											c |= 0x08; break;					
			}
		}

		// get unused
		var unused = 0;
		var bit = 0x01;
		if (c2) {
			while (!(c2 & bit)) {
				if (bit >= 0x80) break;
				unused++;
				bit <<= 1;
			}
		} else if (c) {
			while (!(c & bit)) {
				if (bit >= 0x80) break;
				unused++;
				bit <<= 1;
			}
		}

		var keyUsageSchema = {
			type: jCastle.asn1.tagSequence,
			items: [{
				type: jCastle.asn1.tagOID,
				value: jCastle.oid.getOID('keyUsage')
			}]
		};

		if ('critical' in keyUsage && keyUsage.critical) {
			keyUsageSchema.items.push({
				type: jCastle.asn1.tagBoolean,
				value: true
			});
		}			

		keyUsageSchema.items.push({
			type: jCastle.asn1.tagOctetString,
			value: {
				type: jCastle.asn1.tagBitString,
				value: String.fromCharCode(c) + (c2 ? String.fromCharCode(c2) : ''),
				unused: unused
			}
		});

		return keyUsageSchema;
	}
};

jCastle.certificate.extensions["privateKeyUsagePeriod"] = 
{
	parse: function(seq)
	{
/*
[3](1 elem)
	SEQUENCE(1 elem)
		SEQUENCE(2 elem)
			OBJECT IDENTIFIER				2.5.29.16 -- privateKeyUsagePeriod
			OCTET STRING(1 elem)
				SEQUENCE(2 elem)
					[0]						19980101080000Z
					[1]						20000101080002Z
*/
		var idx = 1;
		var privateKeyUsagePeriod = {};
		privateKeyUsagePeriod.critical = false;

		if (seq.items[idx].type == jCastle.asn1.tagBoolean) {
			privateKeyUsagePeriod.critical = seq.items[idx].value ? true : false;
			idx++;
		}

		privateKeyUsagePeriod.notBefore = jCastle.asn1.parseDateTime(
			jCastle.asn1.tagGeneralizedTime, 
			seq.items[idx].value.items[0].value
		);
		privateKeyUsagePeriod.notAfter = jCastle.asn1.parseDateTime(
			jCastle.asn1.tagGeneralizedTime,
			seq.items[idx].value.items[1].value
		);

		return privateKeyUsagePeriod;
	},

	schema: function(privateKeyUsagePeriod)
	{
		var schema = {
			type: jCastle.asn1.tagSequence,
			items: [{
				type: jCastle.asn1.tagOID,
				value: jCastle.oid.getOID("privateKeyUsagePeriod")
			}, {
				type: jCastle.asn1.tagOctetString,
				value: {
					type: jCastle.asn1.tagSequence,
					items: [{
						tagClass: jCastle.asn1.tagClassContextSpecific,
						type: 0x00,
						constructed: false,
						value: jCastle.asn1.formatDateTime(privateKeyUsagePeriod.notBefore, jCastle.asn1.tagGeneralizedTime)
					}, {
						tagClass: jCastle.asn1.tagClassContextSpecific,
						type: 0x01,
						constructed: false,
						value: jCastle.asn1.formatDateTime(privateKeyUsagePeriod.notAfter, jCastle.asn1.tagGeneralizedTime)
					}]
				}
			}]
		};

		return schema;
	}
};

/*
Authority Key Identifier
------------------------

The authority key identifier extension permits two options. 
keyid and issuer: both can take the optional value "always".

If the keyid option is present an attempt is made to copy the subject key identifier 
from the parent certificate. If the value "always" is present 
then an error is returned if the option fails.

The issuer option copies the issuer and serial number from the issuer certificate.
This will only be done if the keyid option fails or is not included 
unless the "always" flag will always include the value.

Example:

	authorityKeyIdentifier=keyid,issuer

--- from www.v13.gr ---

Short version:

Edit openssl.cnf and make sure that authorityKeyIdentifier does not include “issuer”

Long version:

There’s an issue when using the default OpenSSL configuration or 
when basing a config on that: the default OpenSSL configuration has the following:

	authorityKeyIdentifier=keyid,issuer

In the section that lists options for user certificates (i.e. not the CA section).
The above results in new certificates using the extension and 
include two identifiers for the signing CA:

The Key ID of the CA’s cert (because if “keyid”)
The subject and the serial number of the CA’s cert (because of issuer)
For example:

	X509v3 Authority Key Identifier: 
		keyid:7E:E5:82:FF:FF:FF:15:96:9B:40:FF:C9:5E:51:FF:69:67:4D:BF:FF
		DirName:/C=UK/O=V13/OU=V13/CN=V13 Certificate Authority
		serial:8E:FF:A2:1B:74:DD:54:FF

And this is where the pain and the suffering happens:
If you ever decide that you want to re-create the CA’s certificate 
using the same private key then you won’t be able to do so 
because all certificates that are already signed dictate  the subject 
and the serial number of the old certificate as the CA certificate identifier.
Thus your new CA certificate will not be able to verify the existing certificates.

Thus the only way to replace your certificate would be:

To start from scratch recreating all certificates, or
to create another CA certificate with the same subject and serial number (not tested)
Recreating a certificate with the same details (like serial number) 
will make it impossible to have both certificates available and will most probably
cause a mess.

The best approach is to completely remove the “issuer” from authorityKeyIdentifier
from the configuration file. Then only the Key ID will be used to identify the CA
which should be more than enough.

So use the following and live a happy life:

	authorityKeyIdentifier=keyid
*/
jCastle.certificate.extensions["authorityKeyIdentifier"] = 
{
	parse: function(seq)
	{
/*
SEQUENCE(2 elem)
	OBJECT IDENTIFIER							2.5.29.35 -- authorityKeyIdentifier
	OCTET STRING(1 elem)
		SEQUENCE(3 elem)
			[0](20 byte)							5204329F8F9D2172BAFA3398A8617E2733248D5F
			[1](1 elem)
				[4](1 elem)
					SEQUENCE(4 elem)
						SET(1 elem)
							SEQUENCE(2 elem)
								OBJECT IDENTIFIER	2.5.4.6 -- countryName
								PrintableString		KR
						SET(1 elem)
							SEQUENCE(2 elem)
								OBJECT IDENTIFIER	2.5.4.10 -- organizationName
								UTF8String			KISA
						SET(1 elem)
							SEQUENCE(2 elem)
								OBJECT IDENTIFIER	2.5.4.11 -- organizationalUnitName
								UTF8String			Korea Certification Authority Central
						SET(1 elem)
							SEQUENCE(2 elem)
								OBJECT IDENTIFIER	2.5.4.3 -- commonName
								UTF8String			KISA RootCA 4
			[2](2 byte)								1003
*/
/*qui
   AuthorityKeyIdentifier ::= SEQUENCE {
      keyIdentifier             [0] KeyIdentifier           OPTIONAL,
      authorityCertIssuer       [1] GeneralNames            OPTIONAL,
      authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL  }

   KeyIdentifier ::= OCTET STRING
   GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
 

   GeneralName ::= CHOICE {
      otherName                       [0]     OtherName,
      rfc822Name                      [1]     IA5String,
      dNSName                         [2]     IA5String,
      x400Address                     [3]     ORAddress,
      directoryName                   [4]     Name,
      ediPartyName                    [5]     EDIPartyName,
      uniformResourceIdentifier       [6]     IA5String,
      iPAddress                       [7]     OCTET STRING,
      registeredID                    [8]     OBJECT IDENTIFIER }
 

 CertificateSerialNumber  ::=  INTEGER
*/
		var sequence = seq.items[1].value;

		var authorityKeyIdentifier = {};
		var idx = 0;
		var obj = sequence.items[idx++];

		if (obj.type == 0x00) {
			authorityKeyIdentifier.keyIdentifier = obj.value;

			obj = sequence.items[idx++];
		}

		if (typeof obj != 'undefined' && obj.type == 0x01) {
			// here we have generalNames but just one.
			//authorityKeyIdentifier.authorityCertIssuer = jCastle.certificate.asn1.generalNames.parse(obj);
			authorityKeyIdentifier.authorityCertIssuer = jCastle.certificate.asn1.generalName.parse(obj.items[0]);

			obj = sequence.items[idx++];
		}

		if (typeof obj != 'undefined' && obj.type == 0x02) {
			authorityKeyIdentifier.authorityCertSerialNumber = BigInt.fromBuffer(Buffer.from(obj.value, 'latin1'));
			//authorityKeyIdentifier.authorityCertSerialNumber = obj.intVal;
		}

		return authorityKeyIdentifier;
	},

	schema: function(authorityKeyIdentifier)
	{
		var schema = [];

		if ('keyIdentifier' in authorityKeyIdentifier) {
			schema.push({
				tagClass: jCastle.asn1.tagClassContextSpecific,
				type: 0x00,
				constructed: false,
				value: authorityKeyIdentifier.keyIdentifier
			});
		}

		if ('authorityCertIssuer' in authorityKeyIdentifier) {
			schema.push({
				tagClass: jCastle.asn1.tagClassContextSpecific,
				type: 0x01,
				constructed: true,
				items:[
					jCastle.certificate.asn1.generalName.schema(authorityKeyIdentifier.authorityCertIssuer)
				]
			});
		}

		if ('authorityCertSerialNumber' in authorityKeyIdentifier) {
			var serial = authorityKeyIdentifier.authorityCertSerialNumber;

			schema.push({
				tagClass: jCastle.asn1.tagClassContextSpecific,
				type: 0x02,
				constructed: false,
	//			value: (typeof serial == 'number' || BigInt.is(serial)) ? Buffer.from(serial.toString(16), 'hex').toString('latin1') : serial
				value: serial
			});
		}

		var authorityKeyIdentifierSchema = {
			type: jCastle.asn1.tagSequence,
			items: [{
				type: jCastle.asn1.tagOID,
				value: jCastle.oid.getOID("authorityKeyIdentifier")
			}, {
				type: jCastle.asn1.tagOctetString,
				value: {
					type: jCastle.asn1.tagSequence,
					items: schema
				}
			}]
		};

		return authorityKeyIdentifierSchema;
	}
};

/*
Subject Key Identifier
----------------------

This is really a string extension and can take two possible values. 
Either the word hash which will automatically follow the guidelines in RFC3280 
or a hex string giving the extension value to include. 
The use of the hex string is strongly discouraged.

Example:

	subjectKeyIdentifier=hash
*/
jCastle.certificate.extensions["subjectKeyIdentifier"] = 
{
/*
For CA certificates, subject key identifiers SHOULD be derived from
the public key or a method that generates unique values. Two common
methods for generating key identifiers from the public key are:

  (1) The keyIdentifier is composed of the 160-bit SHA-1 hash of the
  value of the BIT STRING subjectPublicKey (excluding the tag,
  length, and number of unused bits).

  (2) The keyIdentifier is composed of a four bit type field with
  the value 0100 followed by the least significant 60 bits of the
  SHA-1 hash of the value of the BIT STRING subjectPublicKey
  (excluding the tag, length, and number of unused bit string bits).
*/
/*
subjectKeyIdentifier is made of:
	{
		type: jCastle.asn1.tagSequence,
		items: [{
			type: jCastle.asn1.tagInteger,
			value: rsa.n
		}, {
			type: jCastle.asn1.tagInteger,
			value: rsa.e
		}]
	}
authorityKeyIdentifier.keyIdentifier is made using the the same method of subjectKeyIdentifier's.
The only difference is authorityKeyIdentifier.keyIdentifier is made from issuer's public key.
Therefore if the certificate is self-signed then both are same.
*/
	parse: function(seq)
	{
/*
SEQUENCE(2 elem)
	OBJECT IDENTIFIER					2.5.29.14 -- subjectKeyIdentifier
	OCTET STRING(1 elem)
		OCTET STRING(20 byte)			2C268A2F0BC21023A34940DCC45A3156770E41B1
*/
		return Buffer.from(seq.items[1].value.value, 'latin1');
	},

	schema: function(subjectKeyIdentifier)
	{
		var schema = {
			type: jCastle.asn1.tagSequence,
			items: [{
				type: jCastle.asn1.tagOID,
				value: jCastle.oid.getOID('subjectKeyIdentifier')
			}, {
				type: jCastle.asn1.tagOctetString,
				value: {
					type: jCastle.asn1.tagOctetString,
					value: subjectKeyIdentifier
				}
			}]
		};

		return schema;
	}
};

/*
Certificate Policies
--------------------

This is a raw extension. All the fields of this extension can be set
by using the appropriate syntax.

If you follow the PKIX recommendations and just using one OID 
then you just include the value of that OID. Multiple OIDs can be
set separated by commas, for example:

 certificatePolicies= 1.2.4.5, 1.1.3.4
If you wish to include qualifiers then the policy OID and qualifiers
need to be specified in a separate section: this is done 
by using the @section syntax instead of a literal OID value.

The section referred to must include the policy OID 
using the name policyIdentifier, cPSuri qualifiers can be 
included using the syntax:

	CPS.nnn=value

userNotice qualifiers can be set using the syntax:

	userNotice.nnn=@notice

The value of the userNotice qualifier is specified in the relevant section.
This section can include explicitText, organization and noticeNumbers options.
explicitText and organization are text strings, noticeNumbers is 
a comma separated list of numbers. The organization and noticeNumbers options 
(if included) must BOTH be present. If you use the userNotice option 
with IE5 then you need the 'ia5org' option at the top level 
to modify the encoding: otherwise it will not be interpreted properly.

Example:

	certificatePolicies=ia5org,1.2.3.4,1.5.6.7.8,@polsect

	[polsect]

	policyIdentifier = 1.3.5.8
	CPS.1="http://my.host.name/"
	CPS.2="http://my.your.name/"
	userNotice.1=@notice

	[notice]

	explicitText="Explicit Text Here"
	organization="Organisation Name"
	noticeNumbers=1,2,3,4

The ia5org option changes the type of the organization field.
In RFC2459 it can only be of type DisplayText. In RFC3280 
IA5Strring is also permissible. Some software 
(for example some versions of MSIE) may require ia5org.
*/
jCastle.certificate.extensions["certificatePolicies"] = 
{
	parse: function(seq, config)
	{
/*
SEQUENCE(3 elem)
	OBJECT IDENTIFIER						2.5.29.32 -- certificatePolicies
	BOOLEAN									true
	OCTET STRING(1 elem)
		SEQUENCE(1 elem)
			SEQUENCE(2 elem)
				OBJECT IDENTIFIER			1.2.410.200005.1.1.4 -- 금융결제원 은행개인
				SEQUENCE(2 elem)
					SEQUENCE(2 elem)
						OBJECT IDENTIFIER	1.3.6.1.5.5.7.2.2 -- unotice
						SEQUENCE(1 elem)
							BMPString		이 인증서는 공인인증서 입니다
					SEQUENCE(2 elem)
						OBJECT IDENTIFIER	1.3.6.1.5.5.7.2.1 -- cps
						IA5String			http://www.yessign.or.kr/cps.htm
*/
/*
SEQUENCE(2 elem)
	OBJECT IDENTIFIER								2.5.29.32 -- certificatePolicies
	OCTET STRING(1 elem)
		SEQUENCE(2 elem)
			SEQUENCE(1 elem)
				OBJECT IDENTIFIER					1.3.6.1.4.1.23485.5.1.1.0.1
			SEQUENCE(1 elem)
				OBJECT IDENTIFIER					1.3.6.1.4.1.23485.5.1.1.0.3
*/
/*
openssl config setting:

certificatePolicies=ia5org,1.2.3.4,1.5.7.8,@polsect

[polsect]

policyIdentifier=1.3.5.8
CPS.1="http://my.host.name/"
CPS.2="http://my.your.name/"
userNotice.1=@notice

[notice]
explicitText="Explicit Text here"
organization="organisation Name"
noticeNumbers=1,2,3,4


SEQUENCE(2 elem)
	OBJECT IDENTIFIER								2.5.29.32
	OCTET STRING(1 elem)
		SEQUENCE(3 elem)
			SEQUENCE(1 elem)
				OBJECT IDENTIFIER						1.2.3.4
			SEQUENCE(1 elem)
				OBJECT IDENTIFIER						1.5.7.8
			SEQUENCE(2 elem)
				OBJECT IDENTIFIER						1.3.5.8
				SEQUENCE(3 elem)
					SEQUENCE(2 elem)
						OBJECT IDENTIFIER				1.3.6.1.5.5.7.2.1
						IA5String						http://my.host.name/
					SEQUENCE(2 elem)
						OBJECT IDENTIFIER				1.3.6.1.5.5.7.2.1
						IA5String						http://my.your.name/
					SEQUENCE(2 elem)
						OBJECT IDENTIFIER				1.3.6.1.5.5.7.2.2
						SEQUENCE(2 elem)
							SEQUENCE(2 elem)
								IA5String				organisation Name
								SEQUENCE(4 elem)
									INTEGER				1
									INTEGER				2
									INTEGER				3
									INTEGER				4
							VisibleString				Explicit Text here
*/
/*
certificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation

PolicyInformation ::= SEQUENCE {
  policyIdentifier  CertPolicyId,
  policyQualifiers  SEQUENCE SIZE (1..MAX) OF PolicyQualifierInfo OPTIONAL,
  ...
}

CertPolicyId ::= OBJECT IDENTIFIER

PolicyQualifierInfo ::= SEQUENCE {
  policyQualifierId  CERT-POLICY-QUALIFIER.&id({SupportedPolicyQualifiers}),
  qualifier
    CERT-POLICY-QUALIFIER.&Qualifier
      ({SupportedPolicyQualifiers}{@policyQualifierId}) OPTIONAL,
  ...
}

SupportedPolicyQualifiers CERT-POLICY-QUALIFIER ::=
  {...}

anyPolicy OBJECT IDENTIFIER ::= {id-ce-certificatePolicies 0}

CERT-POLICY-QUALIFIER ::= CLASS {
  &id         OBJECT IDENTIFIER UNIQUE,
  &Qualifier  OPTIONAL
}WITH SYNTAX {POLICY-QUALIFIER-ID &id
              [QUALIFIER-TYPE &Qualifier]
}
*/
		var idx = 1;
		var critical = false;
		var certificatePolicies = {};
		if (seq.items[idx].type == jCastle.asn1.tagBoolean) {
			critical = seq.items[idx].value ? true : false;
			idx++;
			if (critical) {
				certificatePolicies.critical = true;
			}
		}

		var policyInformation = jCastle.certificate.asn1.policyInformation.parse(seq.items[idx].value, critical);
		certificatePolicies.policyInformation = policyInformation;
				
		return certificatePolicies;
	},

	schema: function(certificatePolicies, cp_name, config)
	{
		var cpSchema = {
			type: jCastle.asn1.tagSequence,
			items: [{
				type: jCastle.asn1.tagOID,
				value: jCastle.oid.getOID('certificatePolicies')
			}]
		};

		if ('critical' in certificatePolicies && certificatePolicies.critical) {
			cpSchema.items.push({
				type: jCastle.asn1.tagBoolean,
				value: true
			});
		}
				
		cpSchema.items.push({
			type: jCastle.asn1.tagOctetString,
			value: jCastle.certificate.asn1.policyInformation.schema(certificatePolicies.policyInformation, config)
		});

		return cpSchema;
	}
};

/*
Subject Alternative Name
------------------------

The subject alternative name extension allows various literal values 
to be included in the configuration file. These include email (an email address)
URI a uniform resource indicator, DNS (a DNS domain name), 
RID (a registered ID: OBJECT IDENTIFIER), IP (an IP address), 
dirName (a distinguished name) and otherName.

The email option include a special 'copy' value. This will automatically include
and email addresses contained in the certificate subject name in the extension.

The IP address used in the IP options can be in either IPv4 or IPv6 format.

The value of dirName should point to a section containing the distinguished name
to use as a set of name value pairs. Multi values AVAs can be formed 
by prefacing the name with a + character.

otherName can include arbitrary data associated with an OID: 
the value should be the OID followed by a semicolon and the content 
in standard ASN1_generate_nconf format.

Examples:

	subjectAltName=email:copy,email:my@other.address,URI:http://my.url.here/
	subjectAltName=IP:192.168.7.1
	subjectAltName=IP:13::17
	subjectAltName=email:my@other.address,RID:1.2.3.4
	subjectAltName=otherName:1.2.3.4;UTF8:some other identifier

	subjectAltName=dirName:dir_sect

	[dir_sect]
	C=UK
	O=My Organization
	OU=My Unit
	CN=My Name
*/
jCastle.certificate.extensions["subjectAltName"] = 
{
	parse: function(seq)
	{
/*
SEQUENCE(2 elem)
	OBJECT IDENTIFIER											2.5.29.17 -- subjectAltName
	OCTET STRING(1 elem)
		SEQUENCE(1 elem)
			[0](2 elem)
				OBJECT IDENTIFIER								1.2.410.200004.10.1.1 -- npkiIdentifyData
				[0](1 elem)
					SEQUENCE(2 elem)
						UTF8String								이준오
						SEQUENCE(1 elem)
							SEQUENCE(2 elem)
								OBJECT IDENTIFIER				1.2.410.200004.10.1.1.1 -- npkiVID
								SEQUENCE(2 elem)
									SEQUENCE(1 elem)
										OBJECT IDENTIFIER		2.16.840.1.101.3.4.2.1 -- sha-256
									[0](1 elem)
										OCTET STRING(32 byte)	49800B859C322622E0F3A27F8E77463EF60663ACC773953AA6D640BF166C738E
*/
/*
SEQUENCE(2 elem)
	OBJECT IDENTIFIER						2.5.29.17 -- subjectAltName
	OCTET STRING(1 elem)
		SEQUENCE(1 elem)
			[0](2 elem)
				OBJECT IDENTIFIER			1.2.410.200004.10.1.1 -- npkiIdentifyData
				[0](1 elem)
					SEQUENCE(1 elem)
						UTF8String			한국전자인증
*/
/*
   SubjectAltName ::= GeneralNames

   GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName

   GeneralName ::= CHOICE {
        otherName                       [0]     OtherName,
        rfc822Name                      [1]     IA5String,
        dNSName                         [2]     IA5String,
        x400Address                     [3]     ORAddress,
        directoryName                   [4]     Name,
        ediPartyName                    [5]     EDIPartyName,
        uniformResourceIdentifier       [6]     IA5String,
        iPAddress                       [7]     OCTET STRING,
        registeredID                    [8]     OBJECT IDENTIFIER }

   OtherName ::= SEQUENCE {
        type-id    OBJECT IDENTIFIER,
        value      [0] EXPLICIT ANY DEFINED BY type-id }

   EDIPartyName ::= SEQUENCE {
        nameAssigner            [0]     DirectoryString OPTIONAL,
        partyName               [1]     DirectoryString }
*/
				// here we have generalNames but it has sequence parent
		return jCastle.certificate.asn1.generalNames.parse(seq.items[1].value);
	},

	schema: function(subjectAltName)
	{
		var saSchema = {
			type: jCastle.asn1.tagSequence,
			items: [{
				type: jCastle.asn1.tagOID,
				value: jCastle.oid.getOID('subjectAltName')
			}, {
				type: jCastle.asn1.tagOctetString,
				value: jCastle.certificate.asn1.generalNames.schema(subjectAltName)
			}]
		};

		return saSchema;
	}
};

/*
Issuer Alternative Name
-----------------------

The issuer alternative name option supports all the literal options of subject alternative name.
It does not support the email:copy option because that would not make sense. 
It does support an additional issuer:copy option that will copy all the subject alternative name values
from the issuer certificate (if possible).

Example:

	issuserAltName = issuer:copy
*/
jCastle.certificate.extensions["issuerAltName"] = 
{
	parse: function(seq)
	{
/*
issuerAltName EXTENSION ::= {
  SYNTAX         GeneralNames
  IDENTIFIED BY  id-ce-issuerAltName
}
*/
				// here we have generalNames but it has sequence parent
		return jCastle.certificate.asn1.generalNames.parse(seq.items[1].value);
	},

	schema: function(issuerAltName)
	{
		var iaSchema = {
			type: jCastle.asn1.tagSequence,
			items: [{
				type: jCastle.asn1.tagOID,
				value: jCastle.oid.getOID('issuerAltName')
			}, {
				type: jCastle.asn1.tagOctetString,
				value: jCastle.certificate.asn1.generalNames.schema(issuerAltName)
			}]
		};

		return iaSchema;
	}
};

/*
Basic Constraints
-----------------

This is a multi valued extension which indicates whether a certificate is a CA certificate.
The first (mandatory) name is CA followed by TRUE or FALSE. 
If CA is TRUE then an optional pathlen name followed by an non-negative value can be included.

For example:

	basicConstraints=CA:TRUE

	basicConstraints=CA:FALSE

	basicConstraints=critical,CA:TRUE, pathlen:0

A CA certificate must include the basicConstraints value with the CA field set to TRUE.
An end user certificate must either set CA to FALSE or exclude the extension entirely.
Some software may require the inclusion of basicConstraints with CA set to FALSE 
for end entity certificates.

The pathlen parameter indicates the maximum number of CAs 
that can appear below this one in a chain. So if you have a CA with a pathlen of zero
it can only be used to sign end user certificates and not further CAs.
*/
jCastle.certificate.extensions["basicConstraints"] = 
{
/*
OID value: 2.5.29.19

OID description:
id-ce-basicConstraints

This extension indicates if the subject may act as a CA, with the certified public key 
being used to verify certificate signatures. If so, 
a certification path length constraint may also be specified.

This extension may, at the option of the certificate issuer, be either critical or non-critical.

basicConstraints EXTENSION ::= {
	SYNTAX BasicConstraintsSyntax
	IDENTIFIED BY id-ce-basicConstraints
}

BasicConstraintsSyntax ::= SEQUENCE {
	cA	BOOLEAN DEFAULT FALSE,
	pathLenConstraint INTEGER (0..MAX) OPTIONAL
}
*/
	parse: function(seq)
	{
/*
BasicConstraints ::= SEQUENCE {
  cA                 BOOLEAN DEFAULT FALSE,
  pathLenConstraint  INTEGER(0..MAX) OPTIONAL,
  ...
}

SEQUENCE(2 elem)
	OBJECT IDENTIFIER			2.5.29.19
	OCTET STRING(1 elem)
		SEQUENCE(1 elem)
			BOOLEAN					true




SEQUENCE(2 elem)
	OBJECT IDENTIFIER2.5.29.19
	OCTET STRING(1 elem)
		SEQUENCE(0 elem)
*/
		var idx = 1;
		var critical = false;
		var basicConstraints = {};

		if (seq.items[idx].type == jCastle.asn1.tagBoolean) {
			critical = seq.items[idx].value ? true : false;
			idx++;
			if (critical) {
				basicConstraints.critical = true;
			}
		}

		if (typeof seq.items[idx].value.items[0] != 'undefined') {
			basicConstraints.cA = seq.items[idx].value.items[0].value ? true : false;
		} else {
			// empty measn false
			basicConstraints.cA = false;
		}

		if (typeof seq.items[idx].value.items[1] != 'undefined') {
			basicConstraints.pathLenConstraint = seq.items[idx].value.items[1].intVal;
		}

		return basicConstraints;
	},

	schema: function(basicConstraints)
	{
		var schema = {
			type: jCastle.asn1.tagSequence,
			items: [{
				type: jCastle.asn1.tagOID,
				value: jCastle.oid.getOID('basicConstraints')
			}]
		};

		if ('critical' in basicConstraints && basicConstraints.critical) {
			schema.items.push({
				type: jCastle.asn1.tagBoolean,
				value: true
			});
		}

//		if (basicConstraints.cA) {
			var caSchema = [{
				type: jCastle.asn1.tagBoolean,
				value: basicConstraints.cA
			}];
//		} else {
//			var caSchema = [];
//		}

		schema.items.push({
			type: jCastle.asn1.tagOctetString,
			value: {
				type: jCastle.asn1.tagSequence,
				items: caSchema
			}
		});

		if ('pathLenConstraint' in basicConstraints) {
			schema.items[schema.items.length - 1].value.items.push({
				type: jCastle.asn1.tagInteger,
				intVal: basicConstraints.pathLenConstraint
			});
		}

		return schema;
	}
};

/*
Name Constraints
----------------

The name constraints extension is a multi-valued extension.
The name should begin with the word permitted or excluded followed by a ;.
The rest of the name and the value follows the syntax of subjectAltName
except email:copy is not supported and the IP form should 
consist of an IP addresses and subnet mask separated by a /.

Examples:

	nameConstraints=permitted;IP:192.168.0.0/255.255.0.0

	nameConstraints=permitted;email:.somedomain.com

	nameConstraints=excluded;email:.com
*/
jCastle.certificate.extensions["nameConstraints"] = 
{
	parse: function(seq)
	{
/*
nameConstraints ::= SEQUENCE {
  permittedSubtrees  [0]  GeneralSubtrees OPTIONAL,
  excludedSubtrees   [1]  GeneralSubtrees OPTIONAL,
  ...
}
(WITH COMPONENTS {
   ...,
   permittedSubtrees  PRESENT
 } | WITH COMPONENTS {
       ...,
       excludedSubtrees  PRESENT
     })

GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree

GeneralSubtree ::= SEQUENCE {
  base     GeneralName,
  minimum  [0]  BaseDistance DEFAULT 0,
  maximum  [1]  BaseDistance OPTIONAL,
  ...
}

BaseDistance ::= INTEGER(0..MAX)
*/
/*
nameConstraints=permitted;IP:192.168.0.0/255.255.0.0

SEQUENCE(2 elem)
	OBJECT IDENTIFIER						2.5.29.30
	OCTET STRING(1 elem)
		SEQUENCE(1 elem)
			[0](1 elem)
				SEQUENCE(1 elem)
					[7](8 byte)				C0A80000FFFF0000


nameConstraints=excluded;email:.com

SEQUENCE(2 elem)
	OBJECT IDENTIFIER						2.5.29.30
	OCTET STRING(1 elem)
		SEQUENCE(1 elem)
			[1](1 elem)
				SEQUENCE(1 elem)
					[1]							.com


nameConstraints = excluded;DNS:.east.corp.contoso.com

SEQUENCE(2 elem)
	OBJECT IDENTIFIER2.5.29.30
	OCTET STRING(1 elem)
		SEQUENCE(1 elem)
			[1](1 elem)
				SEQUENCE(1 elem)
					[2]							.east.corp.contoso.com
*/
/*
openssl doesn't support multiple trees...
and it does not support having both of permitted and excluded trees
*/
		var nameConstraints = {};
		var idx = 1;
		var critical = false;

		if (seq.items[idx].type == jCastle.asn1.tagBoolean) {
			critical = seq.items[idx].value ? true : false;
			idx++;
			if (critical) {
				nameConstraints.critical = true;
			}
		}

		var idx2 = 0;
		var s = seq.items[idx].value;

		if (s.items[idx2].type == 0x00) {
			nameConstraints.permittedSubtrees = jCastle.certificate.asn1.generalSubtrees.parse(s.items[idx2].items[0]);
			idx++;
		}

		if (s.items[idx2].type == 0x01) {
			nameConstraints.excludedSubtrees = jCastle.certificate.asn1.generalSubtrees.parse(s.items[idx2].items[0]);
		}

		return nameConstraints;
	},

	schema: function(nameConstraints)
	{
		var schema = {
			type: jCastle.asn1.tagSequence,
			items: [{
				type: jCastle.asn1.tagOID,
				value: jCastle.oid.getOID('nameConstraints')
			}]
		};

		if ('critical' in nameConstraints && nameConstraints.critical) {
			schema.items.push({
				type: jCastle.asn1.tagBoolean,
				value: true
			});
		}

		var v = [];

		if ('permittedSubtrees' in nameConstraints) {
			var idx = 0;
			var trees = [];

			while (idx < nameConstraints.permittedSubtrees.length) {
				var tree = {
					type: jCastle.asn1.tagSequence,
					items: [
						jCastle.certificate.asn1.generalName.schema(nameConstraints.permittedSubtrees[idx].base)
					]
				};

				if ('minimum' in nameConstraints.permittedSubtrees[idx]) {
					tree.items.push({
						tagClass: jCastle.asn1.tagClassContextSpecific,
						type: 0x00,
						constructed: true,
						items: [{
							type: jCastle.asn1.tagInteger,
							intVal: nameConstraints.permittedSubtrees[idx].minimum
						}]
					});
				}

				if ('maximum' in nameConstraints.permittedSubtrees[idx]) {
					tree.items.push({
						tagClass: jCastle.asn1.tagClassContextSpecific,
						type: 0x01,
						constructed: true,
						items: [{
							type: jCastle.asn1.tagInteger,
							intVal: nameConstraints.permittedSubtrees[idx].maximum
						}]
					});
				}

				trees.push(tree);
				idx++;
			}

			v.push({
				tagClass: jCastle.asn1.tagClassContextSpecific,
				type: 0x00,
				constructed: true,
				// openssl doesn't support multiple trees...
				// and it does not support having both of permitted and excluded trees
				items: trees.length == 1 ? [trees[0]] : [{
					type: jCastle.asn1.tagSequence,
					items: trees
				}]
			});
		}

		if ('excludedSubtrees' in nameConstraints) {
			var idx = 0;
			var trees = [];

			while (idx < nameConstraints.excludedSubtrees.length) {

				var tree = {
					type: jCastle.asn1.tagSequence,
					items: [
						jCastle.certificate.asn1.generalName.schema(nameConstraints.excludedSubtrees[idx].base)
					]
				};

				if ('minimum' in nameConstraints.excludedSubtrees[idx]) {
					tree.items.push({
						tagClass: jCastle.asn1.tagClassContextSpecific,
						type: 0x00,
						constructed: true,
						items: [{
							type: jCastle.asn1.tagInteger,
							intval: nameConstraints.excludedSubtrees[idx].minimum
						}]
					});
				}

				if ('maximum' in nameConstraints.excludedSubtrees[idx]) {
					tree.items.push({
						tagClass: jCastle.asn1.tagClassContextSpecific,
						type: 0x01,
						constructed: true,
						items: [{
							type: jCastle.asn1.tagInteger,
							intVal: nameConstraints.excludedSubtrees[idx].maximum
						}]
					});
				}
				trees.push(tree);
				idx++;
			}

			v.push({
				tagClass: jCastle.asn1.tagClassContextSpecific,
				type: 0x01,
				constructed: true,
				// openssl doesn't support multiple trees...
				// and it does not support having both of permitted and excluded trees
				items: trees.length == 1 ? [trees[0]] : [{
					type: jCastle.asn1.tagSequence,
					items: trees
				}]
			});
		}

		schema.items.push({
			type: jCastle.asn1.tagOctetString,
			value: {
				type: jCastle.asn1.tagSequence,
				items: v
			}
		});

		return schema;
	}
};

/*
Policy Constraints
------------------

This is a multi-valued extension which consisting of the names 
requireExplicitPolicy or inhibitPolicyMapping and 
a non negative integer value. At least one component must be present.

Example:

	policyConstraints = requireExplicitPolicy:3
*/
jCastle.certificate.extensions["policyConstraints"] = 
{
	parse: function(seq)
	{
/*
SEQUENCE(3 elem)
	OBJECT IDENTIFIER				2.5.29.36
	BOOLEAN							true
	OCTET STRING(1 elem)
		SEQUENCE(1 elem)
			[0](1 byte)				00
*/
/*
policyConstraints EXTENSION ::= {
  SYNTAX         PolicyConstraintsSyntax
  IDENTIFIED BY  id-ce-policyConstraints
}

PolicyConstraintsSyntax ::= SEQUENCE {
  requireExplicitPolicy  [0]  SkipCerts OPTIONAL,
  inhibitPolicyMapping   [1]  SkipCerts OPTIONAL,
  ...
}
(WITH COMPONENTS {
   ...,
   requireExplicitPolicy  PRESENT
 } | WITH COMPONENTS {
       ...,
       inhibitPolicyMapping  PRESENT
     })

SkipCerts ::= INTEGER(0..MAX)
*/
		var policyConstraints = {};
		var idx = 1;
		var critical = false;

		if (seq.items[idx].type == jCastle.asn1.tagBoolean) {
			critical = seq.items[idx].value ? true : false;
			idx++;
			if (critical) {
				policyConstraints.critical = true;
			}
		}

		var idx2 = 0;

		var s = seq.items[idx].value;

		if (s.items[idx2].type == 0x00) {
			policyConstraints.requireExplicitPolicy = parseInt(jCastle.encoding.hex.encode(s.items[idx2].value), 16);
			idx++;
		}

		if (s.items[idx2].type == 0x01) {
			policyConstraints.inhibitPolicyMapping = parseInt(jCastle.encoding.hex.encode(s.items[idx2].value), 16);
		}

		return policyConstraints;
	},

	schema: function(policyConstraints)
	{
		var schema = {
			type: jCastle.asn1.tagSequence,
			items: [{
				type: jCastle.asn1.tagOID,
				value: jCastle.oid.getOID('policyConstraints')
			}]
		};

		if ('critical' in policyConstraints && policyConstraints.critical) {
			schema.items.push({
				type: jCastle.asn1.tagBoolean,
				value: true
			});
		}

		var v = [];

		if ('requireExplicitPolicy' in policyConstraints) {
			v.push({
				tagClass: jCastle.asn1.tagClassContextSpecific,
				type: 0x00,
				constructed: false,
				value: policyConstraints.requireExplicitPolicy
			});
		}

		if ('inhibitPolicyMapping' in policyConstraints) {
			v.push({
				tagClass: jCastle.asn1.tagClassContextSpecific,
				type: 0x01,
				constructed: false,
				value: policyConstraints.inhibitPolicyMapping
			});
		}


		schema.items.push({
			type: jCastle.asn1.tagOctetString,
			value: {
				type: jCastle.asn1.tagSequence,
				items: v
			}
		});

		return schema;
	}
};

/*
CRL distribution points
-----------------------

This is a multi-valued extension whose options can be either 
in name:value pair using the same form as subject alternative name 
or a single value representing a section name containing 
all the distribution point fields.

For a name:value pair a new DistributionPoint with the fullName field set
to the given value both the cRLissuer and reasons fields are omitted in this case.

In the single option case the section indicated contains values
for each field. In this section:

If the name is "fullname" the value field should contain 
the full name of the distribution point in the same format 
as subject alternative name.

If the name is "relativename" then the value field should 
contain a section name whose contents represent a DN fragment 
to be placed in this field.

The name "CRLIssuer" if present should contain a value 
for this field in subject alternative name format.

If the name is "reasons" the value field should consist of
a comma separated field containing the reasons. Valid reasons are:
"keyCompromise", "CACompromise", "affiliationChanged", "superseded",
"cessationOfOperation", "certificateHold", "privilegeWithdrawn" and "AACompromise".

Simple examples:

	crlDistributionPoints=URI:http://myhost.com/myca.crl
	crlDistributionPoints=URI:http://my.com/my.crl,URI:http://oth.com/my.crl

Full distribution point example:

	crlDistributionPoints=crldp1_section

	[crldp1_section]

	fullname=URI:http://myhost.com/myca.crl
	CRLissuer=dirName:issuer_sect
	reasons=keyCompromise, CACompromise

	[issuer_sect]
	C=UK
	O=Organisation
	CN=Some Name
*/
jCastle.certificate.extensions["cRLDistributionPoints"] = 
{
	parse: function(seq)
	{
/*
SEQUENCE(2 elem)
	OBJECT IDENTIFIER					2.5.29.31 -- cRLDistributionPoints
	OCTET STRING(1 elem)
		SEQUENCE(1 elem)
			SEQUENCE(1 elem)
				[0](1 elem)
					[0](1 elem)
						[6]				ldap://ds.yessign.or.kr:389/ou=dp4p54541,ou=AccreditedCA,o=yessign,c=kr?certific…
*/
/*
cRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint

DistributionPoint ::= SEQUENCE {
  distributionPoint  [0]  DistributionPointName OPTIONAL,
  reasons            [1]  ReasonFlags OPTIONAL,
  cRLIssuer          [2]  GeneralNames OPTIONAL,
  ...
}

DistributionPointName ::= CHOICE {
  fullName                 [0]  GeneralNames,
  nameRelativeToCRLIssuer  [1]  RelativeDistinguishedName,
  ...
}

ReasonFlags ::= BIT STRING {
  unused(0), keyCompromise(1), cACompromise(2), affiliationChanged(3),
  superseded(4), cessationOfOperation(5), certificateHold(6),
  privilegeWithdrawn(7), aACompromise(8)}
*/
/*
SEQUENCE(2 elem)
	OBJECT IDENTIFIER									2.5.29.31
	OCTET STRING(1 elem)
		SEQUENCE(1 elem)
			SEQUENCE(3 elem)
				[0](1 elem)
					[0](1 elem)
						[6]									http://myhost.com/myca.crl
				[1](2 byte)									0560
				[2](1 elem)
					[4](1 elem)
						SEQUENCE(3 elem)
							SET(1 elem)
								SEQUENCE(2 elem)
									OBJECT IDENTIFIER		2.5.4.6
									PrintableString			UK
							SET(1 elem)
								SEQUENCE(2 elem)
									OBJECT IDENTIFIER		2.5.4.10
									UTF8String				My Organisation
							SET(1 elem)
								SEQUENCE(2 elem)
									OBJECT IDENTIFIER		2.5.4.3
									UTF8String				some Name
					[2]										http://www.foo.com
*/

		var idx = 1;
		var critical = false;
		var cRLDistributionPoints = {};

		if (seq.items[idx].type == jCastle.asn1.tagBoolean) {
			critical = seq.items[idx].value ? true : false;
			idx++;
			if (critical) {
				cRLDistributionPoints.critical = true;
			}
		}

		var distributionPoints = [];

		for (var i = 0; i < seq.items[idx].value.items.length; i++) {
			var dp = {};
			var s = seq.items[idx].value.items[i];
			var j = 0;

			if (s.items[j].type == 0x00) {
				dp.distributionPoint = s.items[j].items[0].type == 0x00 ? 
					jCastle.certificate.asn1.generalName.parse(s.items[j].items[0].items[0]) : jCastle.certificate.asn1.relativeDistinguishedName.parse(s.items[j].items[0].items[0]);

				j++;
			}

			if (typeof s.items[j] != 'undefined' && s.items[j].type == 0x01) {
				var reasons = [];
				// the value is bitstring: unused(1byte) + reasonFlag(1 or 2 bytes)
				var unused = s.items[j].value.charCodeAt(0);
				var c = s.items[j].value.charCodeAt(1);

				if (c & 0x40) reasons.push('keyCompromise');			// 0100 0000
				if (c & 0x20) reasons.push('cACompromise');			// 0010 0000
				if (c & 0x10) reasons.push('affiliationChanged');		// 0001 0000
				if (c & 0x08) reasons.push('superseded');				// 0000 1000
				if (c & 0x04) reasons.push('cessationOfOperation');	// 0000 0100
				if (c & 0x02) reasons.push('certificateHold');		// 0000 0010
				if (c & 0x01) reasons.push('removeFromCRL');		// 0000 0001

				if (s.items[j].value.length == 3) {
					var c2 = s.items[j].value.charCodeAt(2);
					if (c2 & 0x80) reasons.push('privilegeWithdrawn');		// 1000 0000
					if (c2 & 0x40) reasons.push('aACompromise');			// 0100 0000
				}

				dp.reasons = reasons;

				j++;
			}

			if (typeof s.items[j] != 'undefined' && s.items[j].type == 0x02) {
				dp.cRLIssuer = jCastle.certificate.asn1.generalNames.parse(s.items[j]); // explicit
			}

			distributionPoints.push(dp);
		}

		cRLDistributionPoints.distributionPoints = distributionPoints;

		return cRLDistributionPoints;
	},

	schema: function(cRLDistributionPoints)
	{
		var schema = {
			type: jCastle.asn1.tagSequence,
			items: [{
				type: jCastle.asn1.tagOID,
				value: jCastle.oid.getOID('cRLDistributionPoints')
			}]
		};

		if ('critical' in cRLDistributionPoints && cRLDistributionPoints.critical) {
			schema.items.push({
				type: jCastle.asn1.tagBoolean,
				value: true
			});
		}

		var v = [];

		for (var i = 0; i < cRLDistributionPoints.distributionPoints.length; i++) {
			var point = cRLDistributionPoints.distributionPoints[i];

			var p = {
				type: jCastle.asn1.tagSequence,
				items: []
			};

			if ('distributionPoint' in point) {
				var name = {
					tagClass: jCastle.asn1.tagClassContextSpecific,
					type: 0x00,
					constructed: true,
					items: []
				};

				if (Array.isArray(point.distributionPoint)) { // relative distinguished name
					name.items.push({
						tagClass: jCastle.asn1.tagClassContextSpecific,
						type: 0x01,
						constructed: true,
						items: [jCastle.certificate.asn1.relativeDistinguishedName.schema(point.distributionPoint)]
					});
				} else {
					name.items.push({
						tagClass: jCastle.asn1.tagClassContextSpecific,
						type: 0x00,
						constructed: true,
						items: [jCastle.certificate.asn1.generalName.schema(point.distributionPoint)]
					});
				}

				p.items.push(name);
			}

			if ('reasons' in point) {
				var c = 0;
				var c2 = 0;

				for (var l = 0; l < point.reasons.length; l++) {
					switch (point.reasons[l]) {
						case 'keyCompromise':			c |= 0x40; break;
						case 'cACompromise':			c |= 0x20; break;
						case 'affiliationChanged':		c |= 0x10; break;
						case 'superseded':				c |= 0x08; break;
						case 'cessationOfOperation':	c |= 0x04; break;
						case 'certificateHold':			c |= 0x02; break;
						case 'removeFromCRL':			c |= 0x01; break;
						case 'privilegeWithdrawn' :		c2 |= 0x80; break;
						case 'aACompromise': 			c2 |= 0x40; break;
					}
				}

				// get unused
				var unused = 0;
				var bit = 0x01;
				if (c2) {
					while (!(c2 & bit)) {
						if (bit >= 0x80) break;
						unused++;
						bit <<= 1;
					}
				} else if (c) {
					while (!(c & bit)) {
						if (bit >= 0x80) break;
						unused++;
						bit <<= 1;
					}
				}

				var reasons = {
					tagClass: jCastle.asn1.tagClassContextSpecific,
					type: 0x01,
					constructed: false,
					value: String.fromCharCode(unused) + String.fromCharCode(c) + (c2 ? String.fromCharCode(c2) : '')
				};

				p.items.push(reasons);
			}
						

			if ('cRLIssuer' in point) {
				var issuer = {
					tagClass: jCastle.asn1.tagClassContextSpecific,
					type: 0x02,
					constructed: true,
					items: jCastle.certificate.asn1.generalNames.schema(point.cRLIssuer, true)
				};

				p.items.push(issuer);
			}

			v.push(p);
		}

		schema.items.push({
			type: jCastle.asn1.tagOctetString,
			value: {
				type: jCastle.asn1.tagSequence,
				items: v
			}
		});

		return schema;
	}
};

/*
Issuing Distribution Point
--------------------------

This extension should only appear in CRLs. It is a multi valued extension
whose syntax is similar to the "section" pointed to 
by the CRL distribution points extension with a few differences.

The names "reasons" and "CRLissuer" are not recognized.

The name "onlysomereasons" is accepted which sets this field. 
The value is in the same format as the CRL distribution point "reasons" field.

The names "onlyuser", "onlyCA", "onlyAA" and "indirectCRL" are also 
accepted the values should be a boolean value (TRUE or FALSE) 
to indicate the value of the corresponding field.

Example:

	issuingDistributionPoint=critical, @idp_section

	[idp_section]

	fullname=URI:http://myhost.com/myca.crl
	indirectCRL=TRUE
	onlysomereasons=keyCompromise, CACompromise

	[issuer_sect]
	C=UK
	O=Organisation
	CN=Some Name
*/
/*
in openssl
onlyuser - onlyContainsUserCerts
onlyCA - onlyContainsCACerts
onlyAA - onlyContainsAttributeCerts
*/
jCastle.certificate.extensions["issuingDistributionPoint"] = 
{
/*
id-ce-issuingDistributionPoint OBJECT IDENTIFIER ::= { id-ce 28 }

   issuingDistributionPoint ::= SEQUENCE {
        distributionPoint          [0] DistributionPointName OPTIONAL,
        onlyContainsUserCerts      [1] BOOLEAN DEFAULT FALSE,
        onlyContainsCACerts        [2] BOOLEAN DEFAULT FALSE,
        onlySomeReasons            [3] ReasonFlags OPTIONAL,
        indirectCRL                [4] BOOLEAN DEFAULT FALSE,
        onlyContainsAttributeCerts [5] BOOLEAN DEFAULT FALSE }


DistinguishedName ::= RDNSequence

RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue

AttributeTypeAndValue ::= SEQUENCE {
  type   ATTRIBUTE.&id({SupportedAttributes}),
  value  ATTRIBUTE.&Type({SupportedAttributes}{@type}),
  ...
}
*/
	parse: function(seq)
	{
/*
SEQUENCE(3 elem)
	OBJECT IDENTIFIER						2.5.29.28
	BOOLEAN									true
	OCTET STRING(1 elem)
		SEQUENCE(3 elem)
			[0](1 elem)
				[0](1 elem)
					[6]						http://myhost.com/myca.crl
			[3](2 byte)						0560
			[4](1 byte)						FF
*/
		var idx = 1;
		var critical = false;
		var idp = {};

		if (seq.items[idx].type == jCastle.asn1.tagBoolean) {
			critical = seq.items[idx].value ? true : false;
			idx++;
			if (critical) {
				idp.critical = true;
			}
		}

		var s = seq.items[idx].value;
		var j = 0;

		if (s.items[j].type == 0x00) {
			idp.distributionPoint = s.items[j].items[0].type == 0x00 ? 
				jCastle.certificate.asn1.generalName.parse(s.items[j].items[0].items[0]) : jCastle.certificate.asn1.relativeDistinguishedName.parse(s.items[j].items[0].items[0]);

			j++;
		}

		if (typeof s.items[j] != 'undefined' && s.items[j].type == 0x01) {
			var b = s.items[j].value == "\xff" ? true : false;
			idp.onlyContainsUserPublicKeyCerts = b;

			j++;
		}

		if (typeof s.items[j] != 'undefined' && s.items[j].type == 0x02) {
			var b = s.items[j].value == "\xff" ? true : false;
			idp.onlyContainsCACerts = b;

			j++;
		}

		if (typeof s.items[j] != 'undefined' && s.items[j].type == 0x03) {
			var reasons = [];
			// the value is bitstring: unused(1byte) + reasonFlag(1 or 2 bytes)
			var unused = s.items[j].value.charCodeAt(0);
			var c = s.items[j].value.charCodeAt(1);

			if (c & 0x40) reasons.push('keyCompromise');		// 0100 0000
			if (c & 0x20) reasons.push('cACompromise');			// 0010 0000
			if (c & 0x10) reasons.push('affiliationChanged');	// 0001 0000
			if (c & 0x08) reasons.push('superseded');			// 0000 1000
			if (c & 0x04) reasons.push('cessationOfOperation');	// 0000 0100
			if (c & 0x02) reasons.push('certificateHold');		// 0000 0010
			if (c & 0x01) reasons.push('removeFromCRL');		// 0000 0001

			if (s.items[j].value.length == 3) {
				var c2 = s.items[j].value.charCodeAt(2);
				if (c2 & 0x80) reasons.push('privilegeWithdrawn');		// 1000 0000
				if (c2 & 0x40) reasons.push('aACompromise');			// 0100 0000
			}

			idp.onlySomeReasons = reasons;

			j++;
		}

		if (typeof s.items[j] != 'undefined' && s.items[j].type == 0x04) {
			var b = s.items[j].value == "\xff" ? true : false;
			idp.indirectCRL = b;

			j++;
		}

		if (typeof s.items[j] != 'undefined' && s.items[j].type == 0x05) {
			var b = s.items[j].value == "\xff" ? true : false;
			idp.onlyContainsAttributeCerts = b;

			j++;
		}

		return idp;
	},

	schema: function(idp)
	{
		var schema = {
			type: jCastle.asn1.tagSequence,
			items: [{
				type: jCastle.asn1.tagOID,
				value: jCastle.oid.getOID('issuingDistributionPoint')
			}]
		};

		if ('critical' in idp && idp.critical) {
			schema.items.push({
				type: jCastle.asn1.tagBoolean,
				value: true
			});
		}

		var v = [];

		if ('distributionPoint' in idp) {
			var name = {
				tagClass: jCastle.asn1.tagClassContextSpecific,
				type: 0x00,
				constructed: true,
				items: []
			};

			if (jCastle.util.isArray(idp.distributionPoint)) { // relative distinguished name
				name.items.push({
					tagClass: jCastle.asn1.tagClassContextSpecific,
					type: 0x01,
					constructed: true,
					items: [jCastle.certificate.asn1.relativeDistinguishedName.schema(idp.distributionPoint)]
				});
			} else {
				name.items.push({
					tagClass: jCastle.asn1.tagClassContextSpecific,
					type: 0x00,
					constructed: true,
					items: [jCastle.certificate.asn1.generalName.schema(idp.distributionPoint)]
				});
			}

			v.push(name);
		}

		if ('onlyContainsUserPublicKeyCerts' in idp && idp.onlyContainsUserPublicKeyCerts) {
			v.push({
				tagClass: jCastle.asn1.tagClassContextSpecific,
				type: 0x01,
				constructed: false,
				value: "\xff"
			});
		}

		if ('onlyContainsCACerts' in idp && idp.onlyContainsCACerts) {
			v.push({
				tagClass: jCastle.asn1.tagClassContextSpecific,
				type: 0x02,
				constructed: false,
				value: "\xff"
			});
		}

		if ('onlySomeReasons' in idp) {
			var c = 0;
			var c2 = 0;

			for (var l = 0; l < idp.onlySomeReasons.length; l++) {
				switch (idp.onlySomeReasons[l]) {
					case 'keyCompromise':			c |= 0x40; break;
					case 'cACompromise':			c |= 0x20; break;
					case 'affiliationChanged':		c |= 0x10; break;
					case 'superseded':				c |= 0x08; break;
					case 'cessationOfOperation':	c |= 0x04; break;
					case 'certificateHold':			c |= 0x02; break;
					case 'removeFromCRL':			c |= 0x01; break;
					case 'privilegeWithdrawn' :		c2 |= 0x80; break;
					case 'aACompromise': 			c2 |= 0x40; break;
				}
			}

			// get unused
			var unused = 0;
			var bit = 0x01;
			if (c2) {
				while (!(c2 & bit)) {
					if (bit >= 0x80) break;
					unused++;
					bit <<= 1;
				}
			} else if (c) {
				while (!(c & bit)) {
					if (bit >= 0x80) break;
					unused++;
					bit <<= 1;
				}
			}

			var reasons = {
				tagClass: jCastle.asn1.tagClassContextSpecific,
				type: 0x03,
				constructed: false,
				value: String.fromCharCode(unused) + String.fromCharCode(c) + (c2 ? String.fromCharCode(c2) : '')
			};

			v.push(reasons);
		}
						
		if ('indirectCRL' in idp && idp.indirectCRL) {
			v.push({
				tagClass: jCastle.asn1.tagClassContextSpecific,
				type: 0x04,
				constructed: false,
				value: "\xff"
			});
		}

		if ('onlyContainsAttributeCerts' in idp && idp.onlyContainsAttributeCerts) {
			v.push({
				tagClass: jCastle.asn1.tagClassContextSpecific,
				type: 0x05,
				constructed: false,
				value: "\xff"
			});
		}

		schema.items.push({
			type: jCastle.asn1.tagOctetString,
			value: {
				type: jCastle.asn1.tagSequence,
				items: v
			}
		});

		return schema;
	}
};

/*
Authority Info Access
---------------------

The authority information access extension gives details about
how to access certain information relating to the CA. 
Its syntax is accessOID;location where location has the same syntax
as subject alternative name (except that email:copy is not supported).
accessOID can be any valid OID but only certain values are meaningful,
for example OCSP and caIssuers.

Example:

	authorityInfoAccess = OCSP;URI:http://ocsp.my.host/
	authorityInfoAccess = caIssuers;URI:http://my.ca/ca.html
*/
jCastle.certificate.extensions["authorityInfoAccess"] = 
{
	parse: function(seq, config)
	{
			// PKIX - Private Key Infrastructure Extensions
/*
SEQUENCE(2 elem)
	OBJECT IDENTIFIER					1.3.6.1.5.5.7.1.1 -- authorityInfoAccess
	OCTET STRING(1 elem)
		SEQUENCE(1 elem)
			SEQUENCE(2 elem)
				OBJECT IDENTIFIER		1.3.6.1.5.5.7.48.1 -- ocsp
				[6]						http://ocsp.yessign.org:4612
*/
/*
 AuthorityInfoAccessSyntax  ::=
          SEQUENCE SIZE (1..MAX) OF AccessDescription

 AccessDescription  ::=  SEQUENCE {
          accessMethod          OBJECT IDENTIFIER,
          accessLocation        GeneralName  }
*/
		var idx = 1;
		var critical = false;
		var authorityInfoAccess = {};

		if (seq.items[idx].type == jCastle.asn1.tagBoolean) {
			critical = seq.items[idx].value ? true : false;
			idx++;
			if (critical) {
				authorityInfoAccess.critical = true;
			}
		}

		var accessDescription = jCastle.certificate.asn1.accessDescription.parse(seq.items[idx].value, critical);
		authorityInfoAccess.accessDescription = accessDescription;
		return authorityInfoAccess;
	},

	schema: function(authorityInfoAccess, ai_name, config)
	{
		var schema = {
			type: jCastle.asn1.tagSequence,
			items: [{
				type: jCastle.asn1.tagOID,
				value: jCastle.oid.getOID('authorityInfoAccess')
			}]
		};

		if ('critical' in authorityInfoAccess && authorityInfoAccess.critical) {
			schema.items.push({
				type: jCastle.asn1.tagBoolean,
				value: true
			});
		}
/*
		var v = [];

		for (var i = 0; i < authorityInfoAccess.accessDescription.length; i++) {
			var description = authorityInfoAccess.accessDescription[i];
			var d = {
				type: jCastle.asn1.tagSequence,
				items: [{
					type: jCastle.asn1.tagOID,
					value: jCastle.oid.getOID(description.accessMethod, null, config)
				}, jCastle.certificate.asn1.generalName.schema(description.accessLocation)
				]
			};
			v.push(d);
		}
*/
		schema.items.push({
			type: jCastle.asn1.tagOctetString,
//			value: {
//				type: jCastle.asn1.tagSequence,
//				items: v
//			}
			value: jCastle.certificate.asn1.accessDescription.schema(authorityInfoAccess.accessDescription, config)
		});

		return schema;
	}
};

/*
Extended Key Usage
------------------

This extensions consists of a list of usages indicating purposes 
for which the certificate public key can be used for,

These can either be object short names of the dotted numerical form of OIDs.
While any OID can be used only certain values make sense. 
In particular the following PKIX, NS and MS values are meaningful:

	Value                  Meaning
	-----                  -------
	serverAuth             SSL/TLS Web Server Authentication.
	clientAuth             SSL/TLS Web Client Authentication.
	codeSigning            Code signing.
	emailProtection        E-mail Protection (S/MIME).
	timeStamping           Trusted Timestamping
	msCodeInd              Microsoft Individual Code Signing (authenticode)
	msCodeCom              Microsoft Commercial Code Signing (authenticode)
	msCTLSign              Microsoft Trust List Signing
	msEFS                  Microsoft Encrypted File System

Examples:

	extendedKeyUsage=critical,codeSigning,1.2.3.4
	extendedKeyUsage=serverAuth,clientAuth
*/
jCastle.certificate.extensions["extKeyUsage"] = 
{
	parse: function(seq)
	{
/*
SEQUENCE(2 elem)
	OBJECT IDENTIFIER								2.5.29.37 -- extKeyUsage
	OCTET STRING(1 elem)
		SEQUENCE(4 elem)
			OBJECT IDENTIFIER						1.3.6.1.5.5.7.3.1 -- serverAuth
			OBJECT IDENTIFIER						1.3.6.1.5.5.7.3.2 -- clientAuth
			OBJECT IDENTIFIER						1.3.6.1.4.1.311.10.3.3 -- serverGatedCrypto (MS)
			OBJECT IDENTIFIER						2.16.840.1.113730.4.1 -- serverGatedCrypto (Netscape)
*/
/*
extKeyUsage EXTENSION ::= {
  SYNTAX         SEQUENCE SIZE (1..MAX) OF KeyPurposeId
  IDENTIFIED BY  id-ce-extKeyUsage
}

KeyPurposeId ::= OBJECT IDENTIFIER
*/
		var idx = 1;
		var critical = false;
		var extKeyUsage = {};

		if (seq.items[idx].type == jCastle.asn1.tagBoolean) {
			critical = seq.items[idx].value ? true : false;
			idx++;
			if (critical) {
				extKeyUsage.critical = true;
			}
		}

		var keyPurposeId = [];
		for (var j = 0; j < seq.items[idx].value.items.length; j++) {
			var obj = seq.items[idx].value.items[j];
			var kpid = jCastle.oid.getName(obj.value);
			if (!kpid) {
//				if (critical) {
//					throw jCastle.exception("UNSUPPORTED_EXTENSION", 'CRT060');
//				}
				keyPurposeId.push(obj.value);
			} else {
				keyPurposeId.push(kpid);
			}
		}

		extKeyUsage.keyPurposeId = keyPurposeId;

		return extKeyUsage;
	},

	schema: function(extKeyUsage)
	{
		var schema = {
			type: jCastle.asn1.tagSequence,
			items: [{
				type: jCastle.asn1.tagOID,
				value: jCastle.oid.getOID('extKeyUsage')
			}]
		};

		if ('critical' in extKeyUsage && extKeyUsage.critical) {
			schema.items.push({
				type: jCastle.asn1.tagBoolean,
				value: true
			});
		}

		var v = [];

		for (var i = 0; i < extKeyUsage.keyPurposeId.length; i++) {
			var kpid = extKeyUsage.keyPurposeId[i];
			var d = {
				type: jCastle.asn1.tagOID,
				value: jCastle.oid.getOID(kpid)
			};
			v.push(d);
		}

		schema.items.push({
			type: jCastle.asn1.tagOctetString,
			value: {
				type: jCastle.asn1.tagSequence,
				items: v
			}
		});

		return schema;
	}
};


/*
Inhibit Any Policy
------------------

This is a string extension whose value must be a non negative integer.

Example:

inhibitAnyPolicy = 2
*/
jCastle.certificate.extensions["inhibitAnyPolicy"] = 
{
	parse: function(seq)
	{
/*
4.2.1.14.  Inhibit anyPolicy

   The inhibit anyPolicy extension can be used in certificates issued to
   CAs.  The inhibit anyPolicy extension indicates that the special
   anyPolicy OID, with the value { 2 5 29 32 0 }, is not considered an
   explicit match for other certificate policies except when it appears
   in an intermediate self-issued CA certificate.  The value indicates
   the number of additional non-self-issued certificates that may appear
   in the path before anyPolicy is no longer permitted.  For example, a
   value of one indicates that anyPolicy may be processed in
   certificates issued by the subject of this certificate, but not in
   additional certificates in the path.

   Conforming CAs MUST mark this extension as critical.

   id-ce-inhibitAnyPolicy OBJECT IDENTIFIER ::=  { id-ce 54 }

   InhibitAnyPolicy ::= SkipCerts

   SkipCerts ::= INTEGER (0..MAX)
*/
		var idx = 1;
		var critical = false;
		var inhibitAnyPolicy = {};

		if (seq.items[idx].type == jCastle.asn1.tagBoolean) {
			critical = seq.items[idx].value ? true : false;
			idx++;
			if (critical) {
				inhibitAnyPolicy.critical = true;
			}
		}

		var skipCerts = seq.items[idx].value.intVal;

		inhibitAnyPolicy.skipCerts = skipCerts;

		return inhibitAnyPolicy;
	},

	schema: function(inhibitAnyPolicy)
	{
		var schema = {
			type: jCastle.asn1.tagSequence,
			items: [{
				type: jCastle.asn1.tagOID,
				value: jCastle.oid.getOID('inhibitAnyPolicy')
			}]
		};

		if ('critical' in inhibitAnyPolicy && inhibitAnyPolicy.critical) {
			schema.items.push({
				type: jCastle.asn1.tagBoolean,
				value: true
			});
		}

		schema.items.push({
			type: jCastle.asn1.tagOctetString,
			value: {
				type: jCastle.asn1.tagInteger,
				intVal: inhibitAnyPolicy.skipCerts
			}
		});

		return schema;
	}
};

/*
OCSP No Check
-------------

The OCSP No Check extension is a string extension but its value is ignored.

Example:

	noCheck = ignored
*/
jCastle.certificate.extensions["ocspNoCheck"] = 
{
/*
1.3.6.1.5.5.7.48.1.5 - id-pkix-ocsp-nocheck

OID value: 1.3.6.1.5.5.7.48.1.5

OID description:
4.2.2.2.1 Revocation Checking of an Authorized Responder 
Since an Authorized OCSP responder provides status information for one or more CAs,
OCSP clients need to know how to check that an authorized responder's certificate
has not been revoked. CAs may choose to deal with this problem in one of three ways:
- A CA may specify that an OCSP client can trust a responder for the lifetime 
of the responder's certificate. The CA does so by including the extension 
id-pkix-ocsp-nocheck. 

This SHOULD be a non-critical extension.
The value of the extension should be NULL. 

CAs issuing such a certificate should realized that a compromise of the responder's key,
is as serious as the compromise of a CA key used to sign CRLs, 
at least for the validity period of this certificate. CA's may choose 
to issue this type of certificate with a very short lifetime and renew it frequently. 
id-pkix-ocsp-nocheck OBJECT IDENTIFIER ::= { id-pkix-ocsp 5 }
*/
	parse: function(seq)
	{
/*
SEQUENCE(2 elem)
	OBJECT IDENTIFIER						1.3.6.1.5.5.7.48.1.5
	OCTET STRING(1 elem)
		NULL
*/
		var ocspNoCheck = "ignored";

		return ocspNoCheck;
	},

	schema: function(ocspNoCheck)
	{
		var schema = {
			type: jCastle.asn1.tagSequence,
			items: [{
				type: jCastle.asn1.tagOID,
				value: jCastle.oid.getOID('ocspNoCheck')
			}]
		};

		schema.items.push({
			type: jCastle.asn1.tagOctetString,
			value: {
				type: jCastle.asn1.tagNull,
				value: null
			}
		});

		return schema;
	}
};

/*
5.2.3.  CRL Number

   The CRL number is a non-critical CRL extension that conveys a
   monotonically increasing sequence number for a given CRL scope and
   CRL issuer.  This extension allows users to easily determine when a
   particular CRL supersedes another CRL.  CRL numbers also support the
   identification of complementary complete CRLs and delta CRLs.  CRL
   issuers conforming to this profile MUST include this extension in all
   CRLs and MUST mark this extension as non-critical.

   If a CRL issuer generates delta CRLs in addition to complete CRLs for
   a given scope, the complete CRLs and delta CRLs MUST share one
   numbering sequence.  If a delta CRL and a complete CRL that cover the
   same scope are issued at the same time, they MUST have the same CRL
   number and provide the same revocation information.  That is, the
   combination of the delta CRL and an acceptable complete CRL MUST
   provide the same revocation information as the simultaneously issued
   complete CRL.

   If a CRL issuer generates two CRLs (two complete CRLs, two delta
   CRLs, or a complete CRL and a delta CRL) for the same scope at
   different times, the two CRLs MUST NOT have the same CRL number.
   That is, if the this update field (Section 5.1.2.4) in the two CRLs
   are not identical, the CRL numbers MUST be different.

   Given the requirements above, CRL numbers can be expected to contain
   long integers.  CRL verifiers MUST be able to handle CRLNumber values
   up to 20 octets.  Conforming CRL issuers MUST NOT use CRLNumber
   values longer than 20 octets.

   id-ce-cRLNumber OBJECT IDENTIFIER ::= { id-ce 20 }

   CRLNumber ::= INTEGER (0..MAX)
*/
jCastle.certificate.extensions["cRLNumber"] = 
{
/*
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER					2.5.29.20 -- cRLNumber
					OCTET STRING(1 elem)
						INTEGER							3
*/
	parse: function(seq)
	{
		var cRLNumber = seq.items[1].value.intVal;

		return cRLNumber;
	},

	schema: function(ext, ext_name)
	{
		var schema = {
			type: jCastle.asn1.tagSequence,
			items: [{
				type: jCastle.asn1.tagOID,
				value: jCastle.oid.getOID('cRLNumber')
			}]
		};

		schema.items.push({
			type: jCastle.asn1.tagOctetString,
			value: {
				type: jCastle.asn1.tagInteger,
				intVal: ext
			}
		});

		return schema;
	}
};
/*
5.2.4.  Delta CRL Indicator

   The delta CRL indicator is a critical CRL extension that identifies a
   CRL as being a delta CRL.  Delta CRLs contain updates to revocation
   information previously distributed, rather than all the information
   that would appear in a complete CRL.  The use of delta CRLs can
   significantly reduce network load and processing time in some
   environments.  Delta CRLs are generally smaller than the CRLs they
   update, so applications that obtain delta CRLs consume less network
   bandwidth than applications that obtain the corresponding complete
   CRLs.  Applications that store revocation information in a format
   other than the CRL structure can add new revocation information to
   the local database without reprocessing information.

   The delta CRL indicator extension contains the single value of type
   BaseCRLNumber.  The CRL number identifies the CRL, complete for a
   given scope, that was used as the starting point in the generation of
   this delta CRL.  A conforming CRL issuer MUST publish the referenced
   base CRL as a complete CRL.  The delta CRL contains all updates to
   the revocation status for that same scope.  The combination of a
   delta CRL plus the referenced base CRL is equivalent to a complete
   CRL, for the applicable scope, at the time of publication of the
   delta CRL.

   When a conforming CRL issuer generates a delta CRL, the delta CRL
   MUST include a critical delta CRL indicator extension.

   When a delta CRL is issued, it MUST cover the same set of reasons and
   the same set of certificates that were covered by the base CRL it
   references.  That is, the scope of the delta CRL MUST be the same as
   the scope of the complete CRL referenced as the base.  The referenced
   base CRL and the delta CRL MUST omit the issuing distribution point
   extension or contain identical issuing distribution point extensions.
   Further, the CRL issuer MUST use the same private key to sign the
   delta CRL and any complete CRL that it can be used to update.

   An application that supports delta CRLs can construct a CRL that is
   complete for a given scope by combining a delta CRL for that scope
   with either an issued CRL that is complete for that scope or a
   locally constructed CRL that is complete for that scope.

   When a delta CRL is combined with a complete CRL or a locally
   constructed CRL, the resulting locally constructed CRL has the CRL
   number specified in the CRL number extension found in the delta CRL
   used in its construction.  In addition, the resulting locally
   constructed CRL has the thisUpdate and nextUpdate times specified in
   the corresponding fields of the delta CRL used in its construction.
   In addition, the locally constructed CRL inherits the issuing
   distribution point from the delta CRL.

   A complete CRL and a delta CRL MAY be combined if the following four
   conditions are satisfied:

      (a)  The complete CRL and delta CRL have the same issuer.

      (b)  The complete CRL and delta CRL have the same scope.  The two
           CRLs have the same scope if either of the following
           conditions are met:

         (1)  The issuingDistributionPoint extension is omitted from
              both the complete CRL and the delta CRL.

         (2)  The issuingDistributionPoint extension is present in both
              the complete CRL and the delta CRL, and the values for
              each of the fields in the extensions are the same in both
              CRLs.

      (c)  The CRL number of the complete CRL is equal to or greater
           than the BaseCRLNumber specified in the delta CRL.  That is,
           the complete CRL contains (at a minimum) all the revocation
           information held by the referenced base CRL.

      (d)  The CRL number of the complete CRL is less than the CRL
           number of the delta CRL.  That is, the delta CRL follows the
           complete CRL in the numbering sequence.

   CRL issuers MUST ensure that the combination of a delta CRL and any
   appropriate complete CRL accurately reflects the current revocation
   status.  The CRL issuer MUST include an entry in the delta CRL for
   each certificate within the scope of the delta CRL whose status has
   changed since the generation of the referenced base CRL:

      (a)  If the certificate is revoked for a reason included in the
           scope of the CRL, list the certificate as revoked.

      (b)  If the certificate is valid and was listed on the referenced
           base CRL or any subsequent CRL with reason code
           certificateHold, and the reason code certificateHold is
           included in the scope of the CRL, list the certificate with
           the reason code removeFromCRL.

      (c)  If the certificate is revoked for a reason outside the scope
           of the CRL, but the certificate was listed on the referenced
           base CRL or any subsequent CRL with a reason code included in
           the scope of this CRL, list the certificate as revoked but
           omit the reason code.

      (d)  If the certificate is revoked for a reason outside the scope
           of the CRL and the certificate was neither listed on the
           referenced base CRL nor any subsequent CRL with a reason code
           included in the scope of this CRL, do not list the
           certificate on this CRL.

   The status of a certificate is considered to have changed if it is
   revoked (for any revocation reason, including certificateHold), if it
   is released from hold, or if its revocation reason changes.

   It is appropriate to list a certificate with reason code
   removeFromCRL on a delta CRL even if the certificate was not on hold
   in the referenced base CRL.  If the certificate was placed on hold in
   any CRL issued after the base but before this delta CRL and then
   released from hold, it MUST be listed on the delta CRL with
   revocation reason removeFromCRL.

   A CRL issuer MAY optionally list a certificate on a delta CRL with
   reason code removeFromCRL if the notAfter time specified in the
   certificate precedes the thisUpdate time specified in the delta CRL
   and the certificate was listed on the referenced base CRL or in any
   CRL issued after the base but before this delta CRL.

   If a certificate revocation notice first appears on a delta CRL, then
   it is possible for the certificate validity period to expire before
   the next complete CRL for the same scope is issued.  In this case,
   the revocation notice MUST be included in all subsequent delta CRLs
   until the revocation notice is included on at least one explicitly
   issued complete CRL for this scope.

   An application that supports delta CRLs MUST be able to construct a
   current complete CRL by combining a previously issued complete CRL
   and the most current delta CRL.  An application that supports delta
   CRLs MAY also be able to construct a current complete CRL by
   combining a previously locally constructed complete CRL and the
   current delta CRL.  A delta CRL is considered to be the current one
   if the current time is between the times contained in the thisUpdate
   and nextUpdate fields.  Under some circumstances, the CRL issuer may
   publish one or more delta CRLs before the time indicated by the
   nextUpdate field.  If more than one current delta CRL for a given
   scope is encountered, the application SHOULD consider the one with
   the latest value in thisUpdate to be the most current one.

   id-ce-deltaCRLIndicator OBJECT IDENTIFIER ::= { id-ce 27 }

   BaseCRLNumber ::= CRLNumber
*/
jCastle.certificate.extensions["deltaCRLIndicator"] = 
{
	parse: function(seq)
	{
		var cRLNumber = seq.items[1].value.intVal;

		return cRLNumber;
	},

	schema: function(ext, ext_name)
	{
		var schema = {
			type: jCastle.asn1.tagSequence,
			items: [{
				type: jCastle.asn1.tagOID,
				value: jCastle.oid.getOID('deltaCRLIndicator')
			}]
		};

		schema.items.push({
			type: jCastle.asn1.tagOctetString,
			value: {
				type: jCastle.asn1.tagInteger,
				intVal: ext
			}
		});

		return schema;
	}
};




/*
DEPRECATED EXTENSIONS
=====================

The following extensions are non standard, Netscape specific 
and largely obsolete. Their use in new applications is discouraged.


Netscape String extensions
--------------------------

Netscape Comment (nsComment) is a string extension containing 
a comment which will be displayed when the certificate is viewed 
in some browsers.

Example:

	nsComment = "Some Random Comment"

Other supported extensions in this category are: nsBaseUrl,
nsRevocationUrl, nsCaRevocationUrl, nsRenewalUrl, nsCaPolicyUrl
and nsSslServerName.
*/
jCastle.certificate.extensions["netscape-comment"] = 
jCastle.certificate.extensions["netscape-base-url"] = 
jCastle.certificate.extensions["netscape-revocation-url"] = 
jCastle.certificate.extensions["netscape-ca-revocation-url"] = 
jCastle.certificate.extensions["netscape-cert-renewal-url"] = 
jCastle.certificate.extensions["netscape-ca-policy-url"] = 
jCastle.certificate.extensions["netscape-ssl-server-name"] = 
{
	parse: function(seq)
	{
/*
SEQUENCE(2 elem)
	OBJECT IDENTIFIER					2.16.840.1.113730.1.13
	OCTET STRING(1 elem)
		IA5String						Some Random Comment
*/
		var ext = {
			value: seq.items[1].value.value,
			type: seq.items[1].value.type
		};

		return ext;
	},

	schema: function(ext, ext_name)
	{
		var schema = {
			type: jCastle.asn1.tagSequence,
			items: [{
				type: jCastle.asn1.tagOID,
				value: jCastle.oid.getOID(ext_name)
			}]
		};

		schema.items.push({
			type: jCastle.asn1.tagOctetString,
			value: {
				type: ext.type ? ext.type : jCastle.asn1.tagIA5String,
				value: ext.value
			}
		});

		return schema;
	}
};
/*
jCastle.certificate.extensions["netscape-base-url"] = 
{
	parse: function(seq)
	{
		var comment = {
			value: seq.items[1].value.value,
			type: seq.items[1].value.type
		};

		return comment;
	},

	schema: function(comment)
	{
		var schema = {
			type: jCastle.asn1.tagSequence,
			items: [{
				type: jCastle.asn1.tagOID,
				value: jCastle.oid.getOID('netscape-base-url')
			}]
		};

		schema.items.push({
			type: jCastle.asn1.tagOctetString,
			value: {
				type: comment.type ? comment.type : jCastle.asn1.tagIA5String,
				value: comment.value
			}
		});

		return schema;
	}
};

jCastle.certificate.extensions["netscape-revocation-url"] = 
{
	parse: function(seq)
	{
		var comment = {
			value: seq.items[1].value.value,
			type: seq.items[1].value.type
		};

		return comment;
	},

	schema: function(comment)
	{
		var schema = {
			type: jCastle.asn1.tagSequence,
			items: [{
				type: jCastle.asn1.tagOID,
				value: jCastle.oid.getOID('netscape-revocation-url')
			}]
		};

		schema.items.push({
			type: jCastle.asn1.tagOctetString,
			value: {
				type: comment.type ? comment.type : jCastle.asn1.tagIA5String,
				value: comment.value
			}
		});

		return schema;
	}
};

jCastle.certificate.extensions["netscape-ca-revocation-url"] = 
{
	parse: function(seq)
	{
		var comment = {
			value: seq.items[1].value.value,
			type: seq.items[1].value.type
		};

		return comment;
	},

	schema: function(comment)
	{
		var schema = {
			type: jCastle.asn1.tagSequence,
			items: [{
				type: jCastle.asn1.tagOID,
				value: jCastle.oid.getOID('netscape-ca-revocation-url')
			}]
		};

		schema.items.push({
			type: jCastle.asn1.tagOctetString,
			value: {
				type: comment.type ? comment.type : jCastle.asn1.tagIA5String,
				value: comment.value
			}
		});

		return schema;
	}
};

jCastle.certificate.extensions["netscape-cert-renewal-url"] = 
{
	parse: function(seq)
	{
		var comment = {
			value: seq.items[1].value.value,
			type: seq.items[1].value.type
		};

		return comment;
	},

	schema: function(comment)
	{
		var schema = {
			type: jCastle.asn1.tagSequence,
			items: [{
				type: jCastle.asn1.tagOID,
				value: jCastle.oid.getOID('netscape-cert-renewal-url')
			}]
		};

		schema.items.push({
			type: jCastle.asn1.tagOctetString,
			value: {
				type: comment.type ? comment.type : jCastle.asn1.tagIA5String,
				value: comment.value
			}
		});

		return schema;
	}
};

jCastle.certificate.extensions["netscape-ca-policy-url"] = 
{
	parse: function(seq)
	{
		var comment = {
			value: seq.items[1].value.value,
			type: seq.items[1].value.type
		};

		return comment;
	},

	schema: function(comment)
	{
		var schema = {
			type: jCastle.asn1.tagSequence,
			items: [{
				type: jCastle.asn1.tagOID,
				value: jCastle.oid.getOID('netscape-ca-policy-url')
			}]
		};

		schema.items.push({
			type: jCastle.asn1.tagOctetString,
			value: {
				type: comment.type ? comment.type : jCastle.asn1.tagIA5String,
				value: comment.value
			}
		});

		return schema;
	}
};

jCastle.certificate.extensions["netscape-ssl-server-name"] = 
{
	parse: function(seq)
	{
		var comment = {
			value: seq.items[1].value.value,
			type: seq.items[1].value.type
		};

		return comment;
	},

	schema: function(comment)
	{
		var schema = {
			type: jCastle.asn1.tagSequence,
			items: [{
				type: jCastle.asn1.tagOID,
				value: jCastle.oid.getOID('netscape-ssl-server-name')
			}]
		};

		schema.items.push({
			type: jCastle.asn1.tagOctetString,
			value: {
				type: comment.type ? comment.type : jCastle.asn1.tagIA5String,
				value: comment.value
			}
		});

		return schema;
	}
};
*/

/*
Netscape Certificate Type
-------------------------

This is a multi-valued extensions which consists of a list of flags
to be included. It was used to indicate the purposes 
for which a certificate could be used. The basicConstraints,
keyUsage and extended key usage extensions are now used instead.

Acceptable values for nsCertType are: client, server, email,
objsign, reserved, sslCA, emailCA, objCA.
*/
/*
This class implements the NetscapeCertType Extension.
Each Netscape certificate extension is associated with 
a specific certificateExtension object identifier, derived from:

 netscape OBJECT IDENTIFIER ::= { 2 16 840 1 113730 }
 netscape-cert-extension OBJECT IDENTIFIER :: = { netscape 1 }
 
The object identifier for the NetscapeCertType extension is defined as:

netscape-cert-type OBJECT IDENTIFIER ::= { netscape-cert-extension 1 }

which corresponds to the OID string "2.16.840.1.113730.1.1".

The Netscape Certificate Specification specifies the NetscapeCertType extension
for limting the applications for a certificate. If the extension exists
in a certificate, it will limit the uses of the certificate to those specified.
If the extension is not present, the certificate can be used for all applications 
except Object Signing.

The value is a bit-string, where the individual bit positions are defined as:

bit-0 SSL client - this cert is certified for SSL client authentication use
bit-1 SSL server - this cert is certified for SSL server authentication use
bit-2 S/MIME - this cert is certified for use by clients (New in PR3)
bit-3 Object Signing - this cert is certified for signing objects 
      such as Java applets and plugins(New in PR3)
bit-4 Reserved - this bit is reserved for future use
bit-5 SSL CA - this cert is certified for issuing certs for SSL use
bit-6 S/MIME CA - this cert is certified for issuing certs for S/MIME use (New in PR3)
bit-7 Object Signing CA - this cert is certified for issuing certs 
      for Object Signing (New in PR3)
*/
jCastle.certificate.extensions["netscape-cert-type"] = 
{
	parse: function(seq)
	{
/*
SEQUENCE(2 elem)
	OBJECT IDENTIFIER								2.16.840.1.113730.1.1 -- netscape-cert-type
	OCTET STRING(1 elem)
		BIT STRING(8 bit)							00000001
*/
		var netscapeCertType = {};
		var idx = 1;
		netscapeCertType.value = [];
		netscapeCertType.critical = false; // default

		if (seq.items[idx].type == jCastle.asn1.tagBoolean) {
			netscapeCertType.critical = seq.items[idx].value ? true : false;
			idx++;
		}

		//var bits = parseInt(jCastle.encoding.hex.encode(seq.items[idx].value.value), 16);
		var c = seq.items[idx].value.value.charCodeAt(0);

		if (c & 0x80) netscapeCertType.value.push('SSL client');		// 1000 0000
		if (c & 0x40) netscapeCertType.value.push('SSL server');		// 0100 0000
		if (c & 0x20) netscapeCertType.value.push('S/MIME');			// 0010 0000
		if (c & 0x10) netscapeCertType.value.push('Object Signing');	// 0001 0000
		if (c & 0x08) netscapeCertType.value.push('Reserved');			// 0000 1000
		if (c & 0x04) netscapeCertType.value.push('SSL CA');			// 0000 0100
		if (c & 0x02) netscapeCertType.value.push('S/MIME CA');			// 0000 0010
		if (c & 0x01) netscapeCertType.value.push('Object Signing CA');	// 0000 0001

		return netscapeCertType;
	},

	schema: function(netscapeCertType)
	{
		var c = 0;

		for (var i = 0; i < netscapeCertType.value.length; i++) {
			switch (netscapeCertType.value[i]) {
				case 'SSL client':
				case 'client':			c |= 0x80; break; // openssl's value
				case 'SSL server':
				case 'server':			c |= 0x40; break; // openssl's value
				case 'S/MIME':
				case 'email':			c |= 0x20; break; // openssl's value
				case 'Object Signing':
				case 'objsign':			c |= 0x10; break; // openssl's value
				case 'Reserved':
				case 'reserved':		c |= 0x08; break; // openssl's value
				case 'SSL CA':
				case 'sslCA':			c |= 0x04; break; // openssl's value
				case 'S/MIME CA':
				case 'emailCA':			c |= 0x02; break; // openssl's value
				case 'Object Signing CA':
				case 'objCA':			c |= 0x01; break; // openssl's value				
			}
		}

		// get unused
		var unused = 0;
		var bit = 0x01;
		if (c) {
			while (!(c & bit)) {
				if (bit >= 0x80) break;
				unused++;
				bit <<= 1;
			}
		}

		var certTypeSchema = {
			type: jCastle.asn1.tagSequence,
			items: [{
				type: jCastle.asn1.tagOID,
				value: jCastle.oid.getOID('netscape-cert-type')
			}]
		};

		if ('critical' in netscapeCertType && netscapeCertType.critical) {
			certTypeSchema.items.push({
				type: jCastle.asn1.tagBoolean,
				value: true
			});
		}			

		certTypeSchema.items.push({
			type: jCastle.asn1.tagOctetString,
			value: {
				type: jCastle.asn1.tagBitString,
				value: String.fromCharCode(c),
				unused: unused
			}
		});

		return certTypeSchema;
	}
};

/*
SEQUENCE(2 elem)
	OBJECT IDENTIFIER					1.2.840.113533.7.65.0 -- entrustVersInfo
	OCTET STRING(1 elem)
		SEQUENCE(2 elem)
			GeneralString
			BIT STRING(8 bit)			10000001
*/
/*
OID value: 1.2.840.113533.7.65.0

OID description:
certificate extension for entrust version

entrustVersInfo EXTENSION ::= {
	SYNTAX EntrustVersInfoSyntax
	IDENTIFIED BY { id-nsn-ext 0}
}

EntrustVersInfoSyntax ::= OCTET STRING
*/
jCastle.certificate.extensions["entrustVersInfo"] = 
{
	parse: function(seq)
	{
		var entrustVersInfo = {};
		var idx = 1;
		entrustVersInfo.critical = false; // default

		if (seq.items[idx].type == jCastle.asn1.tagBoolean) {
			entrustVersInfo.critical = seq.items[idx].value ? true : false;
			idx++;
		}

		// I don't know exactly...
		entrustVersInfo.versionInfo = seq.items[idx].value.items[0].value;
		entrustVersInfo.versionBits = seq.items[idx].value.items[1].value;

		return entrustVersInfo;
	},

	schema: function(entrustVersInfo)
	{
		var schema = {
			type: jCastle.asn1.tagSequence,
			items: [{
				type: jCastle.asn1.tagOID,
				value: jCastle.oid.getOID('entrustVersInfo')
			}]
		};

		if ('critical' in entrustVersInfo && entrustVersInfo.critical) {
			schema.items.push({
				type: jCastle.asn1.tagBoolean,
				value: true
			});
		}			

		schema.items.push({
			type: jCastle.asn1.tagOctetString,
			value: {
				type: jCastle.asn1.tagSequence,
				items: [{
					type: jCastle.asn1.tagGeneralString,
					value: entrustVersInfo.versionInfo
				}, {
					type: jCastle.asn1.tagBitString,
					value: entrustVersInfo.versionBits
				}]
			}
		});

		return schema;
	}
};





/******************
 * OtherNameRules *
 ******************/

/*
SEQUENCE(2 elem)
	OBJECT IDENTIFIER											2.5.29.17 -- subjectAltName
	OCTET STRING(1 elem)
		SEQUENCE(1 elem)
			[0](2 elem)  -- otherName
				OBJECT IDENTIFIER								1.2.410.200004.10.1.1 -- npkiIdentifyData
				[0](1 elem)
					SEQUENCE(2 elem)
						UTF8String								이준오
						SEQUENCE(1 elem)
							SEQUENCE(2 elem)
								OBJECT IDENTIFIER				1.2.410.200004.10.1.1.1 -- npkiVID
								SEQUENCE(2 elem)
									SEQUENCE(1 elem)
										OBJECT IDENTIFIER		2.16.840.1.101.3.4.2.1 -- sha-256
									[0](1 elem)
										OCTET STRING(32 byte)	49800B859C322622E0F3A27F8E77463EF60663ACC773953AA6D640BF166C738E
*/
/*
SEQUENCE(2 elem)
	OBJECT IDENTIFIER						2.5.29.17 -- subjectAltName
	OCTET STRING(1 elem)
		SEQUENCE(1 elem)
			[0](2 elem)
				OBJECT IDENTIFIER			1.2.410.200004.10.1.1 -- npkiIdentifyData
				[0](1 elem)
					SEQUENCE(1 elem)
						UTF8String			한국전자인증
*/
jCastle.certificate.otherNameRules['npkiIdentifyData'] = 
{ 
	parse: function(otherName, explicit)
	{
		var name = {
			value: explicit.items[0].items[0].value,
			type:  explicit.items[0].items[0].type
		};

		var v = {
			name: name
		};

		if (typeof explicit.items[0].items[1] != 'undefined' &&
			explicit.items[0].items[1].type == jCastle.asn1.tagSequence
		) {
			var seq = explicit.items[0].items[1].items[0];
			var d = {};
			d.identifier = jCastle.oid.getName(seq.items[0].value);
			if (!d.identifier) d.identifier = seq.items[0].value;

			switch(d.identifier) {
				case 'npkiVID':
					d.hashAlgo = jCastle.oid.getName(seq.items[1].items[0].items[0].value);
					d.data = Buffer.from(seq.items[1].items[1].items[0].value, 'latin1');
					break;
				default:
					throw jCastle.exception("UNSUPPORTED_EXTENSION", 'CRT063');
			}

			v.identifyData = d;
		}

		var res = {
			name: otherName,
			value: v
		};

		return res;
	},

	schema: function(obj)
	{
		var schema = [];
		schema.push({
			type: jCastle.asn1.tagOID,
			value: jCastle.oid.getOID('npkiIdentifyData')
		});

		var valueSchema = {
			type: jCastle.asn1.tagSequence,
			items: [{
				type: 'type' in obj.value.name ? obj.value.name.type : jCastle.asn1.tagUTF8String,
				value: obj.value.name.value
			}]
		};

		if ('identifyData' in obj.value) {
			var npkiVIDSchema = {
				type: jCastle.asn1.tagSequence,
				items: [{
					type: jCastle.asn1.tagSequence,
					items: [{
						type: jCastle.asn1.tagOID,
						value: jCastle.oid.getOID(obj.value.identifyData.identifier) // should be npkiVID
					}, {
						type: jCastle.asn1.tagSequence,
						items: [{
							type: jCastle.asn1.tagSequence,
							items: [{
								type: jCastle.asn1.tagOID,
								value: jCastle.digest.getOID(obj.value.identifyData.hashAlgo)
							}]
						}, {
							tagClass: jCastle.asn1.tagClassContextSpecific,
							type: 0x00,
							constructed: true,
							items: [{
								type: jCastle.asn1.tagOctetString,
								value: obj.value.identifyData.data
							}]
						}]
					}]
				}]
			};

			valueSchema.items.push(npkiVIDSchema);
		}

		schema.push({
			tagClass: jCastle.asn1.tagClassContextSpecific,
			type: 0x00,
			constructed: true,
			items: [
				valueSchema
			]
		});

		return schema;
	}
};

/*
jCastle.certificate.registerOtherNameRule(
	'npkiIdentifyData', 
	function(otherName, explicit) // parse function
	{
		var name = {
			value: explicit.items[0].items[0].value,
			type:  explicit.items[0].items[0].type
		};

		var v = {
			name: name
		};

		if (typeof explicit.items[0].items[1] != 'undefined' &&
			explicit.items[0].items[1].type == jCastle.asn1.tagSequence
		) {
	//		var identifyData = [];

	//		for (var i = 0; i < explicit.items[0].items[1].items.length; i++) {
	//			var seq = explicit.items[0].items[1].items[i];
				var seq = explicit.items[0].items[1].items[0];
				var d = {};
				d.identifier = jCastle.oid.getName(seq.items[0].value);
				if (!d.identifier) d.identifier = seq.items[0].value;

				switch(d.identifier) {
					case 'npkiVID':
						d.hashAlgo = jCastle.oid.getName(seq.items[1].items[0].items[0].value);
						d.data = seq.items[1].items[1].items[0].value;
						break;
					default:
						throw jCastle.exception("UNSUPPORTED_EXTENSION", 'CRT063');
				}

	//			identifyData.push(d);
	//		}

	//		v.identifyData = identifyData;
			v.identifyData = d;
		}

		var res = {
			name: otherName,
			value: v
		};

		return res;
	},
	function(obj) // schema function
	{
		var schema = [];
		schema.push({
			type: jCastle.asn1.tagOID,
			value: jCastle.oid.getOID('npkiIdentifyData')
		});

		var valueSchema = {
			type: jCastle.asn1.tagSequence,
			items: [{
				type: 'type' in obj.value.name ? obj.value.name.type : jCastle.asn1.tagUTF8String,
				value: obj.value.name.value
			}]
		};

		if ('identifyData' in obj.value) {
			var npkiVIDSchema = {
				type: jCastle.asn1.tagSequence,
				items: [{
					type: jCastle.asn1.tagSequence,
					items: [{
						type: jCastle.asn1.tagOID,
						value: jCastle.oid.getOID(obj.value.identifyData.identifier) // should be npkiVID
					}, {
						type: jCastle.asn1.tagSequence,
						items: [{
							type: jCastle.asn1.tagSequence,
							items: [{
								type: jCastle.asn1.tagOID,
								value: jCastle.digest.getOID(obj.value.identifyData.hashAlgo)
							}]
						}, {
							tagClass: jCastle.asn1.tagClassContextSpecific,
							type: 0x00,
							constructed: true,
							items: [{
								type: jCastle.asn1.tagOctetString,
								value: obj.value.identifyData.data
							}]
						}]
					}]
				}]
			};

			valueSchema.items.push(npkiVIDSchema);
		}

		schema.push({
			tagClass: jCastle.asn1.tagClassContextSpecific,
			type: 0x00,
			constructed: true,
			items: [
				valueSchema
			]
		});

		return schema;
	}
);
*/

/* Rasterizing function */
jCastle.certificate.rasterize = 
jCastle.certificate.rasterizeSchema =
jCastle.certificate.rasterizeCertInfo = function(cert_info)
{
	if (jCastle.util.isString(cert_info)) {
		try {
			cert_info = new jCastle.certificate().parse(cert_info);
		} catch (e) {
			throw jCastle.exception('UNSUPPORTED_PEM_FORMAT', 'CRT064');
		}
	}

	var res = jCastle.util.clone(cert_info);

	if ('type' in res) {
		switch (res.type) {
			case 1: res.type = 'CRT(Certificate)'; break;
			case 2: res.type = 'CSR(Certificate Signing Request)'; break;
			case 3: res.type = 'CRL(Certificate Revocation List)'; break;
		}
	}

	if ('signature' in res) {
		res.signature = Buffer.isBuffer(res.signature) ? res.sigature.toString('hex') : Buffer.from(res.signature, 'latin1').toString('hex');
	}

	if ('tbs' in res) {
		for(var item in res.tbs) {
			switch (item) {
				// case 'der':
				// 	res.tbs.der = Buffer.from(res.tbs.der, 'latin1').toString('hex');
					// break;
				case 'serialNumber':
					res.tbs.serialNumber = res.tbs.serialNumber.toString();
					break;
				case 'subjectPublicKeyInfo':
					if (res.tbs.subjectPublicKeyInfo.algo == 'RSA') {
						res.tbs.subjectPublicKeyInfo.publicKey.n = res.tbs.subjectPublicKeyInfo.publicKey.n.toString(16);
						res.tbs.subjectPublicKeyInfo.publicKey.e = res.tbs.subjectPublicKeyInfo.publicKey.e;
					} else if (res.tbs.subjectPublicKeyInfo.algo == 'ECDSA' || res.tbs.subjectPublicKeyInfo.algo == 'ECKCDSA') {
						res.tbs.subjectPublicKeyInfo.publicKey = res.tbs.subjectPublicKeyInfo.publicKey.toString('hex'); // buffer
					} else {
						res.tbs.subjectPublicKeyInfo.publicKey = res.tbs.subjectPublicKeyInfo.publicKey.toString(16);
					}
					res.tbs.subjectPublicKeyInfo.type = 'public';
					break;
				case 'issuer':
				case 'subject':
					jCastle.certificate._rasterizeNameType(res.tbs[item]);
					break;
				case 'revokedCertificates':
					for (var i = 0; i < res.tbs.revokedCertificates.length; i++) {
						var revoked = res.tbs.revokedCertificates[i];
						if ('userCertificate' in revoked) revoked.userCertificate = revoked.userCertificate.toString();
					}
					break;
				case 'extensions':
				case 'extensionRequest':
				case 'crlExtensions':
					for (var it in res.tbs[item]) {
						switch (it) {
							case 'subjectKeyIdentifier':
								if (res.tbs[item][it] != "hash") {
									res.tbs[item][it] = Buffer.isBuffer(res.tbs[item][it]) ? res.tbs[item][it].toString('hex') : Buffer.from(res.tbs[item][it], 'latin1').toString('hex');
								}
								break;
							case 'authorityKeyIdentifier':
								if ('keyIdentifier' in res.tbs[item][it]) {
									if (res.tbs[item][it].keyIdentifier != "always") {
										res.tbs[item][it].keyIdentifier = Buffer.isBuffer(res.tbs[item][it].keyIdentifier) ? res.tbs[item][it].keyIdentifier.toString('hex') : Buffer.from(res.tbs[item][it].keyIdentifier, 'latin1').toString('hex');
									}
								}
								if ('authorityCertIssuer' in res.tbs[item][it]) {
									if (res.tbs[item][it].authorityCertIssuer != "always") {
										//if (res.tbs[item][it].authorityCertIssuer.name == 'directoryName') {
											jCastle.certificate._rasterizeNameType(res.tbs[item][it].authorityCertIssuer.value);
										//}
									}
								}
								if ('authorityCertSerialNumber' in res.tbs[item][it]) {
									res.tbs[item][it].authorityCertSerialNumber = res.tbs[item][it].authorityCertSerialNumber.toString(16);
								}
								break;
							case 'issuerAltName':
							case 'subjectAltName':
								jCastle.certificate._rasterizeNameType(res.tbs[item][it]);
								break;
							case 'issuingDistributionPoint':
								if ('distributionPoint' in res.tbs[item].issuingDistributionPoint) {
									jCastle.certificate._rasterizeNameType(res.tbs[item].issuingDistributionPoint.distributionPoint);
								}
								break;
							case 'authorityInfoAccess':
								for (var j = 0; j < res.tbs[item].authorityInfoAccess.accessDescription.length; j++) {
									if ('accessLocation' in res.tbs[item].authorityInfoAccess.accessDescription[j]) {
										jCastle.certificate._rasterizeNameType(res.tbs[item].authorityInfoAccess.accessDescription[j].accessLocation);
									}
								}
								break;
							case 'cRLDistributionPoints':
								for (var j = 0; j < res.tbs[item].cRLDistributionPoints.distributionPoints.length; j++) {
									if ('distributionPoint' in res.tbs[item].cRLDistributionPoints.distributionPoints[j]) {
										jCastle.certificate._rasterizeNameType(res.tbs[item].cRLDistributionPoints.distributionPoints[j].distributionPoint);
									}
									if ('cRLIssuer' in res.tbs[item].cRLDistributionPoints.distributionPoints[j]) {
										for (var k = 0; k < res.tbs[item].cRLDistributionPoints.distributionPoints[j].cRLIssuer.length; k++) {
											jCastle.certificate._rasterizeNameType(res.tbs[item].cRLDistributionPoints.distributionPoints[j].cRLIssuer[k].value);
										}
									}
								}
								break;
							case 'nameConstraints':
								if ('permittedSubtrees' in res.tbs[item].nameConstraints) {
									for (var j = 0; j < res.tbs[item].nameConstraints.permittedSubtrees.length; j++) {
										jCastle.certificate._rasterizeNameType(res.tbs[item].nameConstraints.permittedSubtrees[j].base);
									}
								}
								if ('excludedSubtrees' in res.tbs[item].nameConstraints) {
									for (var j = 0; j < res.tbs[item].nameConstraints.excludedSubtrees.length; j++) {
										jCastle.certificate._rasterizeNameType(res.tbs[item].nameConstraints.excludedSubtrees[j].base);
									}
								}
								break;
							case 'certificatePolicies':
								for (var j = 0; j < res.tbs[item][it].policyInformation.length; j++) {
									var information = res.tbs[item][it].policyInformation[j];
									if ('policyQualifiers' in information) {
										for (var q = 0; q < information.policyQualifiers.length; q++) {
											var policyQualifier = information.policyQualifiers[q];
											if ('explicitText' in policyQualifier.qualifier) {
												jCastle.certificate._rasterizeNameType(policyQualifier.qualifier.explicitText);
											} else {
												jCastle.certificate._rasterizeNameType(policyQualifier.qualifier);
											}
										}
									}
								}
								break;
							case 'netscape-comment':
							case 'netscape-base-url':
							case 'netscape-ca-revocation-url':
							case 'netscape-revocation-url':
							case 'netscape-cert-renewal-url':
							case 'netscape-ca-policy-url':
							case 'netscape-ssl-server-name':
								jCastle.certificate._rasterizeNameType(res.tbs[item][it]);
								break;
						}
					}
					break;
			}
		}
	}

	return res;
};

jCastle.certificate._rasterizeNameType = function(obj)
{
	if (jCastle.util.isArray(obj)) {
		for (var i = 0; i < obj.length; i++) {
			if ('type' in obj[i]) {
				obj[i].type = jCastle.certificate._rasterizeStringType(obj[i].type);
			}
			if (obj[i].name == 'otherName' && typeof obj[i].value == 'object' && 'name' in obj[i].value && obj[i].value.name == 'npkiIdentifyData') {
				if (typeof obj[i].value.value == 'object' && 'identifyData' in obj[i].value.value && obj[i].value.value.identifyData.identifier == 'npkiVID') {
					//obj[i].value.value.identifyData.data = jCastle.encoding.hex.encode(obj[i].value.value.identifyData.data);
					obj[i].value.value.identifyData.data = Buffer.from(obj[i].value.value.identifyData.data, 'latin1').toString('hex');
				} else if (typeof obj[i].value.value == 'object' && 'name' in obj[i].value.value) {
					obj[i].value.value.name.type = jCastle.certificate._rasterizeStringType(obj[i].value.value.name.type);
				}
			} else if (obj[i].name == 'directoryName' && typeof obj[i].value == 'object') {
				jCastle.certificate._rasterizeNameType(obj[i].value);
			}

		}
	} else {
		if ('type' in obj) {
			obj.type = jCastle.certificate._rasterizeStringType(obj.type);
		}
		if (obj.name == 'otherName' && typeof obj.value == 'object' && 'name' in obj.value && obj.value.name == 'npkiIdentifyData') {
			if (typeof obj.value.value == 'object' && 'identifyData' in obj.value.value && obj.value.value.identifyData.identifier == 'npkiVID') {
				//obj.value.value.identifyData.data = jCastle.encoding.hex.encode(obj.value.value.identifyData.data);
				obj.value.value.identifyData.data = Buffer.from(obj.value.value.identifyData.data, 'latin1').toString('hex');
			}  else if (typeof obj.value.value == 'object' && 'name' in obj.value.value) {
				obj.value.value.name.type = jCastle.certificate._rasterizeStringType(obj.value.value.name.type);
			}
		} else if (obj.name == 'directoryName' && typeof obj.value == 'object') {
			jCastle.certificate._rasterizeNameType(obj.value);
		}
	}
};

jCastle.certificate._rasterizeStringType = function(type)
{
	switch (type) {
		case 12: return 'UTF8 String';
		case 19: return 'Printable String';
		case 20: return 'Teletex String';
		case 22: return 'IA5 String';
		case 26: return 'Visible String';
		case 27: return 'General String';
		case 28: return 'Universal String';
		case 30: return 'BMP String';
	}
	return type;
};

jCastle.Certificate = jCastle.x509Cert = jCastle.x509Certificate = jCastle.certificate;

module.exports = jCastle.certificate;

/*
-----BEGIN X509 CRL-----
MIIDFDCCAfwCAQEwDQYJKoZIhvcNAQEFBQAwXzEjMCEGA1UEChMaU2FtcGxlIFNp
Z25lciBPcmdhbml6YXRpb24xGzAZBgNVBAsTElNhbXBsZSBTaWduZXIgVW5pdDEb
MBkGA1UEAxMSU2FtcGxlIFNpZ25lciBDZXJ0Fw0xMzAyMTgxMDMyMDBaFw0xMzAy
MTgxMDQyMDBaMIIBNjA8AgMUeUcXDTEzMDIxODEwMjIxMlowJjAKBgNVHRUEAwoB
AzAYBgNVHRgEERgPMjAxMzAyMTgxMDIyMDBaMDwCAxR5SBcNMTMwMjE4MTAyMjIy
WjAmMAoGA1UdFQQDCgEGMBgGA1UdGAQRGA8yMDEzMDIxODEwMjIwMFowPAIDFHlJ
Fw0xMzAyMTgxMDIyMzJaMCYwCgYDVR0VBAMKAQQwGAYDVR0YBBEYDzIwMTMwMjE4
MTAyMjAwWjA8AgMUeUoXDTEzMDIxODEwMjI0MlowJjAKBgNVHRUEAwoBATAYBgNV
HRgEERgPMjAxMzAyMTgxMDIyMDBaMDwCAxR5SxcNMTMwMjE4MTAyMjUxWjAmMAoG
A1UdFQQDCgEFMBgGA1UdGAQRGA8yMDEzMDIxODEwMjIwMFqgLzAtMB8GA1UdIwQY
MBaAFL4SAcyq6hGA2i6tsurHtfuf+a00MAoGA1UdFAQDAgEDMA0GCSqGSIb3DQEB
BQUAA4IBAQBCIb6B8cN5dmZbziETimiotDy+FsOvS93LeDWSkNjXTG/+bGgnrm3a
QpgB7heT8L2o7s2QtjX2DaTOSYL3nZ/Ibn/R8S0g+EbNQxdk5/la6CERxiRp+E2T
UG8LDb14YVMhRGKvCguSIyUG0MwGW6waqVtd6K71u7vhIU/Tidf6ZSdsTMhpPPFu
PUid4j29U3q10SGFF6cCt1DzjvUcCwHGhHA02Men70EgZFADPLWmLg0HglKUh1iZ
WcBGtev/8VsUijyjsM072C6Ut5TwNyrrthb952+eKlmxLNgT0o5hVYxjXhtwLQsL
7QZhrypAM1DLYqQjkiDI7hlvt7QuDGTJ
-----END X509 CRL-----

SEQUENCE(3 elem)
	SEQUENCE(7 elem)
		INTEGER											1
		SEQUENCE(2 elem)
			OBJECT IDENTIFIER							1.2.840.113549.1.1.5 -- sha1WithRSAEncryption
			NULL
		SEQUENCE(3 elem)
			SET(1 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER					2.5.4.10
					PrintableString						Sample Signer Organization
			SET(1 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER					2.5.4.11
					PrintableString						Sample Signer Unit
			SET(1 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER					2.5.4.3
					PrintableString						Sample Signer Cert
		UTCTime											2013-02-18 10:32:00 UTC
		UTCTime											2013-02-18 10:42:00 UTC
		SEQUENCE(5 elem)
			SEQUENCE(3 elem)
				INTEGER									1341767
				UTCTime									2013-02-18 10:22:12 UTC
				SEQUENCE(2 elem)
					SEQUENCE(2 elem)
						OBJECT IDENTIFIER				2.5.29.21 -- cRLReason
						OCTET STRING(1 elem)
							ENUMERATED
					SEQUENCE(2 elem)
						OBJECT IDENTIFIER				2.5.29.24 -- invalidityDate
						OCTET STRING(1 elem)
							GeneralizedTime				2013-02-18 10:22:00 UTC
			SEQUENCE(3 elem)
				INTEGER									1341768
				UTCTime									2013-02-18 10:22:22 UTC
				SEQUENCE(2 elem)
					SEQUENCE(2 elem)
						OBJECT IDENTIFIER				2.5.29.21
						OCTET STRING(1 elem)
							ENUMERATED
					SEQUENCE(2 elem)
						OBJECT IDENTIFIER				2.5.29.24
						OCTET STRING(1 elem)
							GeneralizedTime				2013-02-18 10:22:00 UTC
			SEQUENCE(3 elem)
				INTEGER									1341769
				UTCTime									2013-02-18 10:22:32 UTC
				SEQUENCE(2 elem)
					SEQUENCE(2 elem)
						OBJECT IDENTIFIER				2.5.29.21
						OCTET STRING(1 elem)
							ENUMERATED
					SEQUENCE(2 elem)
						OBJECT IDENTIFIER				2.5.29.24
						OCTET STRING(1 elem)
							GeneralizedTime				2013-02-18 10:22:00 UTC
			SEQUENCE(3 elem)
				INTEGER									1341770
				UTCTime									2013-02-18 10:22:42 UTC
				SEQUENCE(2 elem)
					SEQUENCE(2 elem)
						OBJECT IDENTIFIER				2.5.29.21
						OCTET STRING(1 elem)
							ENUMERATED
					SEQUENCE(2 elem)
						OBJECT IDENTIFIER				2.5.29.24
						OCTET STRING(1 elem)
							GeneralizedTime				2013-02-18 10:22:00 UTC
			SEQUENCE(3 elem)
				INTEGER									1341771
				UTCTime									2013-02-18 10:22:51 UTC
				SEQUENCE(2 elem)
					SEQUENCE(2 elem)
						OBJECT IDENTIFIER				2.5.29.21
						OCTET STRING(1 elem)
							ENUMERATED
					SEQUENCE(2 elem)
						OBJECT IDENTIFIER				2.5.29.24
						OCTET STRING(1 elem)
							GeneralizedTime				2013-02-18 10:22:00 UTC
		[0](1 elem)
			SEQUENCE(2 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER					2.5.29.35 -- authorityKeyIdentifier
					OCTET STRING(1 elem)
						SEQUENCE(1 elem)
							[0](20 byte)				BE1201CCAAEA1180DA2EADB2EAC7B5FB9FF9AD34
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER					2.5.29.20 -- cRLNumber
					OCTET STRING(1 elem)
						INTEGER							3
	SEQUENCE(2 elem)
		OBJECT IDENTIFIER								1.2.840.113549.1.1.5 -- sha1WithRSAEncryption
		NULL
	BIT STRING(2048 bit)								010000100010000110111110100000011111000111000011011110010111011001100…

*/


/*
Certificate with OAEP public key example:

This does not mean that the certificate should be verified with oaep.
https://code.google.com/p/chromium/issues/detail?id=477181

-----BEGIN CERTIFICATE----- 
MIIFyzCCA7OgAwIBAgIDMaTyMA0GCSqGSIb3DQEBBAUAMG0xETAPBgNVBAMTCFN0YW0gSXNo
MRQwEgYDVQQHEwtQZXRhaCBUaWt2YTEPMA0GA1UECBMGSXNyYWVsMQwwCgYDVQQKEwNBUlgx
FjAUBgNVBAsTDVByaXZhdGVTZXJ2ZXIxCzAJBgNVBAYTAklMMB4XDTAwMDEwMTEwMDAwMFoX
DTk5MTAxMzIxNTYxNVowbTERMA8GA1UEAxMIU3RhbSBJc2gxFDASBgNVBAcTC1BldGFoIFRp
a3ZhMQ8wDQYDVQQIEwZJc3JhZWwxDDAKBgNVBAoTA0FSWDEWMBQGA1UECxMNUHJpdmF0ZVNl
cnZlcjELMAkGA1UEBhMCSUwwggJnMFIGCSqGSIb3DQEBBzBFoA8wDQYJYIZIAWUDBAIBBQCh
HDAaBgkqhkiG9w0BAQgwDQYJYIZIAWUDBAIBBQCiFDASBgkqhkiG9w0BAQkEBVRDUEEAA4IC
DwAwggIKAoICAQCizEvm86uS4/f8e7EC81OqNK+fIoCWOYJdc7iDNEbI+7l9C/zD//KiETMD
x1V4WgBXvhokc05a0oLdJ8MlcTFUGsmrX8mxesGnY87wVeJBJ+jPQipZ+ZoA16U9d4xOQU8b
erXUf+w6VFwoL4M3jLyL2lspHiMJPagsukxjzh1Dj/xA6tIVsSnJkffDyRC9l267pP1mXi2u
vAT4zhSX1FLtoO3XkJ0pJarIyJeTnBLMQ5ga1gnDmUFve4tI/cLbb9fxeTF7zA+XNrTTdYrY
9zkiMXBvnT7h0ZpGhfvobC7ULbmO/XyR3tVmuMoTu9mwNgjwCgp5f5Jt7cZbUJNbBateglcv
+Gb9FjFjneCRU4adN87GpyAMfclq5MIO+KCoRWSDRbL/6exYMf0sE3g4ARSru/7Wm82xITNA
fRn2qDErR421SiiuwkIlh97eiyfYeEb+n5eSOr1Qscr+tXOpEuArBDPzg0g5fo0dgomAVZvK
hwfOS+URUmobRPuUN5ecB4dALBJkkN02qaGkCXZmzWicnheXmhTYe3og0fQpajFXUwgwguXl
CDfy91Tn9PBYdRs0G0/gkiRABTP3sZvG3ru9I20W9tdfvN3NssBb+2AadRhSvpgP1wkHIVmZ
/VOQN893TdmaS+WQOiocxh2LxJv7QeC8j8fi9k8LTeM4JCqJ0wIDAQABoy8wLTArBgNVHRAE
JDAigA8xOTk4MDEwMTA4MDAwMFqBDzIwMDAwMTAxMDgwMDAyWjANBgkqhkiG9w0BAQQFAAOC
AgEAODPOHhl4J519jEExA2TIwSWLC23lloBQQPJysE0gelbyTv3xGVmJJZF+JAGvxrkvYado
UMPc9pBF57RsB7tznhCHpcYpSRcEIEArZoxfiVkevheLsm9/gyd5RA/oD6xx8WZBFFjHW+fs
urdJPEfR0lBHGmOKBKTa9aeqwJ5Bfi6Rm6/OvbalWBgZh2+5KYhdtMZH7JnsCCR6ZrJzLp8D
uo5M0iIQ/J6D9pDsPBmYK3/P/c7mVhLhjUBtqelkRGO690VzoBykf9MsWE3IT58gq1Av3dGe
J1LSgijha65s/A+l7zEC0fL7UFSXUnNCghEz+PkpcO14wFeg9UIypM0R85IOO0PBg4FVLACT
hmBmFFJCDOCgMwO+xMQZE+eG5gOEUgESHaQfEUoU7JxPHYB/9Xxl2G69nHr2Fx0KuLrjnrym
SgrFubQ3d+XuSTLxr/Lr7gl7EZP68uEsPcw2CXXdpsq4pvmVbrNspfHGn9SimFkEA8qmPqkt
4wiUPCwLkvY+qZ55JnmtPWoeaekJDx7iox0TtiHlQH6Y+/Rl18zU0lITePKPbc5thPZjiwIl
rR5O1PYzlIzE9m/7mFNitIAR2CixJRNiykgz5Q2gjYu4itmb2aHE1UuzK2mORny2gYnG7mdr
dD2y8hDouRCuxND/kkfdDyspGSRQcnqnmpkt7nQ=
-----END CERTIFICATE-----


SEQUENCE(3 elem)
	SEQUENCE(8 elem)
		[0](1 elem)
			INTEGER									2								-- version
		INTEGER										3253490							-- serial
		SEQUENCE(2 elem)
			OBJECT IDENTIFIER						1.2.840.113549.1.1.4			-- md5WithRSAEncryption
			NULL
		SEQUENCE(6 elem)
			SET(1 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER				2.5.4.3
					PrintableString					Stam Ish
			SET(1 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER				2.5.4.7
					PrintableString					Petah Tikva
			SET(1 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER				2.5.4.8
					PrintableString					Israel
			SET(1 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER				2.5.4.10
					PrintableString					ARX
			SET(1 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER				2.5.4.11
					PrintableString					PrivateServer
			SET(1 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER				2.5.4.6
					PrintableString					IL
		SEQUENCE(2 elem)
			UTCTime									2000-01-01 10:00:00 UTC
			UTCTime									1999-10-13 21:56:15 UTC
		SEQUENCE(6 elem)
			SET(1 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER				2.5.4.3
					PrintableString					Stam Ish
			SET(1 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER				2.5.4.7
					PrintableString					Petah Tikva
			SET(1 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER				2.5.4.8
					PrintableString					Israel
			SET(1 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER				2.5.4.10
					PrintableString					ARX
			SET(1 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER				2.5.4.11
					PrintableString					PrivateServer
			SET(1 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER				2.5.4.6
					PrintableString					IL
		SEQUENCE(2 elem)
			SEQUENCE(2 elem)
				OBJECT IDENTIFIER					1.2.840.113549.1.1.7			-- rsaOAEP
				SEQUENCE(3 elem)
					[0](1 elem)
						SEQUENCE(2 elem)
							OBJECT IDENTIFIER		2.16.840.1.101.3.4.2.1			-- sha-256
							NULL
					[1](1 elem)
						SEQUENCE(2 elem)
							OBJECT IDENTIFIER		1.2.840.113549.1.1.8			-- pkcs1-MGF
							SEQUENCE(2 elem)
								OBJECT IDENTIFIER	2.16.840.1.101.3.4.2.1			-- sha-256
								NULL
					[2](1 elem)
						SEQUENCE(2 elem)
							OBJECT IDENTIFIER		1.2.840.113549.1.1.9			-- rsaOAEP-pSpecified
							OCTET STRING(5 byte)	5443504100
			BIT STRING(1 elem)
				SEQUENCE(2 elem)
					INTEGER(4096 bit)				664158030327658656011019037255739017511931322784390718439712888538135…
					INTEGER							65537
		[3](1 elem)
			SEQUENCE(1 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER				2.5.29.16						-- privateKeyUsagePeriod
					OCTET STRING(1 elem)
						SEQUENCE(2 elem)
							[0]						19980101080000Z
							[1]						20000101080002Z
	SEQUENCE(2 elem)
		OBJECT IDENTIFIER							1.2.840.113549.1.1.4			-- md5WithRSAEncryption
		NULL
	BIT STRING(4096 bit)							001110000011001111001110000111100001100101111000001001111001110101111…

*/

/*
This class specifies the set of parameters used with OAEP Padding, 
as defined in the PKCS #1 standard. Its ASN.1 definition in PKCS#1 standard is described below:

 RSAES-OAEP-params ::= SEQUENCE {
   hashAlgorithm      [0] OAEP-PSSDigestAlgorithms     DEFAULT sha1,
   maskGenAlgorithm   [1] PKCS1MGFAlgorithms  DEFAULT mgf1SHA1,
   pSourceAlgorithm   [2] PKCS1PSourceAlgorithms  DEFAULT pSpecifiedEmpty
 }
 

where

 OAEP-PSSDigestAlgorithms    ALGORITHM-IDENTIFIER ::= {
   { OID id-sha1 PARAMETERS NULL   }|
   { OID id-sha256 PARAMETERS NULL }|
   { OID id-sha384 PARAMETERS NULL }|
   { OID id-sha512 PARAMETERS NULL },
   ...  -- Allows for future expansion --
 }
 PKCS1MGFAlgorithms    ALGORITHM-IDENTIFIER ::= {
   { OID id-mgf1 PARAMETERS OAEP-PSSDigestAlgorithms },
   ...  -- Allows for future expansion --
 }
 PKCS1PSourceAlgorithms    ALGORITHM-IDENTIFIER ::= {
   { OID id-pSpecified PARAMETERS OCTET STRING },
   ...  -- Allows for future expansion --
 }

 Note: the OAEPParameterSpec.DEFAULT uses the following: 
 message digest -- "SHA-1" 
 mask generation function (mgf) -- "MGF1"
 parameters for mgf -- MGF1ParameterSpec.SHA1 
 source of encoding input -- PSource.PSpecified.DEFAULT

*/

/*

self-signed signature example

-----BEGIN CERTIFICATE-----
MIIDLjCCAeKgAwIBAgIBATBBBgkqhkiG9w0BAQowNKAPMA0GCWCGSAFlAwQCAQUA
oRwwGgYJKoZIhvcNAQEIMA0GCWCGSAFlAwQCAQUAogMCASAwHjEcMAkGA1UEBhMC
UlUwDwYDVQQDHggAVABlAHMAdDAeFw0xMzAyMDEwMDAwMDBaFw0xNjAyMDEwMDAw
MDBaMB4xHDAJBgNVBAYTAlJVMA8GA1UEAx4IAFQAZQBzAHQwggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQC0b5GWY4oMjNs2j4k+DLPr1ribN5rbRJNKxqqP
+KH8C+TG0/AyFxtnZsAqRiYDDVnXhB/Yl48OXvGJbFLMihT369K3SZwgjGeFFkns
7L9RgnT1yPliQSNPy0rjDpDH5S/Wi7fNKDhfSWFUi3D/pfBVDBUclVgbmKQfyTVy
FmGXV81yzLccdGN/DMyASGHik/NJBqHKEXJVoyLPKK7wSf90aWB8+sEaMvtFOfJT
osfkCJ4zD6I6+1Na3J6W86MYuIrXYgH0wbBZ+9AEFQkOTQ8Gkh1ZQJup3BC0UdB7
P9ad5wiVaHc1tHlojsBU3BntmxPtMQW8USBWxSc5GGc/yJDHAgMBAAGjDzANMAsG
A1UdDwQEAwIAAjBBBgkqhkiG9w0BAQowNKAPMA0GCWCGSAFlAwQCAQUAoRwwGgYJ
KoZIhvcNAQEIMA0GCWCGSAFlAwQCAQUAogMCASADggEBAK/ORKd/RDQS23VZIziG
lVh5l0jAcHZh8uo4qBOg7HJ2LnCv8466oIkzSCPFa+g+6DqlUEPBGwUgzp7jTKiE
mX24ZGeR215b9gKLuyMKAeWwlmwzYH1FpWmrkiyFS/LFZC/y3JwU9Z51Ge5J5mea
YZ4QQ2ZK35Cfa/CiBW/EQjwtEtxYHc2jd4x0Cgportuot4Axxa5v/6sz7uVHeIvH
d7zIwv/McOEAsAUMQsPtXf9roRUleCzfxkx7HEBH43eoV/a/aAJ/a2lKwCdnZpnp
sOnWjPwgFqTvDmSZMvVa3QLtOeDwmznR8Cjew/NqxpsJ12CBSlltTx/BaanfKr/7
d0A=
-----END CERTIFICATE-----


Parsing result:

SEQUENCE(3 elem)
	SEQUENCE(8 elem)
		[0](1 elem)
			INTEGER								2
		INTEGER									1
		SEQUENCE(2 elem)
			OBJECT IDENTIFIER					1.2.840.113549.1.1.10
			SEQUENCE(3 elem)
				[0](1 elem)
					SEQUENCE(2 elem)
						OBJECT IDENTIFIER		2.16.840.1.101.3.4.2.1
						NULL
				[1](1 elem)
					SEQUENCE(2 elem)
						OBJECT IDENTIFIER		1.2.840.113549.1.1.8
						SEQUENCE(2 elem)
							OBJECT IDENTIFIER	2.16.840.1.101.3.4.2.1
							NULL
				[2](1 elem)
					INTEGER						32
		SEQUENCE(1 elem)
			SET(2 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER			2.5.4.6
					PrintableString				RU
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER			2.5.4.3
					BMPString					Test
		SEQUENCE(2 elem)
			UTCTime								2013-02-01 00:00:00 UTC
			UTCTime								2016-02-01 00:00:00 UTC
		SEQUENCE(1 elem)
			SET(2 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER			2.5.4.6
					PrintableString				RU
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER			2.5.4.3
					BMPString					Test
		SEQUENCE(2 elem)
			SEQUENCE(2 elem)
				OBJECT IDENTIFIER				1.2.840.113549.1.1.1
				NULL
			BIT STRING(1 elem)
				SEQUENCE(2 elem)
					INTEGER(2048 bit) 			227779114708502272098325245002574518989245659902413298145007125468342…
					INTEGER						65537
		[3](1 elem)
			SEQUENCE(1 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER			2.5.29.15
					OCTET STRING(1 elem)
						BIT STRING(8 bit) 		01000000
	SEQUENCE(2 elem)
		OBJECT IDENTIFIER						1.2.840.113549.1.1.10
		SEQUENCE(3 elem)
			[0](1 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER			2.16.840.1.101.3.4.2.1
					NULL
			[1](1 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER			1.2.840.113549.1.1.8
					SEQUENCE(2 elem)
						OBJECT IDENTIFIER		2.16.840.1.101.3.4.2.1
						NULL
			[2](1 elem)
				INTEGER							32
	BIT STRING(2048 bit)						000000101110111011011111111111010101010011111011100101011001011010000…






-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC0b5GWY4oMjNs2
j4k+DLPr1ribN5rbRJNKxqqP+KH8C+TG0/AyFxtnZsAqRiYDDVnXhB/Yl48OXvGJ
bFLMihT369K3SZwgjGeFFkns7L9RgnT1yPliQSNPy0rjDpDH5S/Wi7fNKDhfSWFU
i3D/pfBVDBUclVgbmKQfyTVyFmGXV81yzLccdGN/DMyASGHik/NJBqHKEXJVoyLP
KK7wSf90aWB8+sEaMvtFOfJTosfkCJ4zD6I6+1Na3J6W86MYuIrXYgH0wbBZ+9AE
FQkOTQ8Gkh1ZQJup3BC0UdB7P9ad5wiVaHc1tHlojsBU3BntmxPtMQW8USBWxSc5
GGc/yJDHAgMBAAECggEBAIt6t1s+xQdgl1B88oWRwj+r83ahLEcVopqqKk0y0N0K
wKXmTYYbEKcE6cWEBnxThMCxtQB0YDSmtiYaI4NTtlPT60aeU19hyeA6U5kfheFX
bFxXKFiIq+hR6SjOKKMtiqZZyRKBZdpa2i9Fv2sP9lF4DpXS6JIkk7KykmsH3Bbl
jahZ8Ks78wO5zwF2mV+HKyvtWjH9idUSlMHU4liMBlbnRyksgqJ9AzPCr1Qfb9OJ
86DO+A2pFw8uOcTrRetKQkTKtFIwTNdDrAz6N3RcPQYwVXaCl/9CpERVi0XgViWx
Kp5xJXgOScsX3WWdLEQauHBGrc3bE/JeptQ+ZulFKqkCgYEA7odvj/zP21FL3KNQ
CSI1mDtZBwKhZM2oyUrSo68sWFnHxEB3rxUiDUk4L64NfNGkpme3vXLMmIUkTYpV
sAu7BQWd2feS6E+iNiA2Od0vrkd552Hjb6B96J+zJha7OY2BIS07XKbvtcY5tBiw
krvdlYQsYwxZxg+iPX2QFLxTi3UCgYEAwabZgHVL23Efr44H86gTOzfCLjwSZyGg
3lfayRXrUs/gUKndZbIYLCPOcdZJfZGM3iASg5SedmSaTQVqfQz6tI0VVIdF+wEN
+TCsK0iQKhV43ClhVVJrK8JnvUTutdhD/Dz6Q5QZ2HtO4BfLU3FvkhzXL8evv/YK
Jr7Q4BXkr8sCgYAPnhiE4fWuE3WXHa5I2s+Nhx0+I0Lz+a86dsax5u9NXZuB0wLD
GOwg2JFwNcI2UPep2ZKjOdgBiH4nAY64txvoqUR7mAUrZsNlLdi/EydjDtUBfFxK
28RCreop7UUW8Jfq1y5S069QRIlUrGUrRlesyXmqho1+NVnXEtiTMv15XQKBgGSP
MAL05h9d7wZKyvZMITBvE/bOWwATBmZvWL1zFHA8Yk+A5ecZRFQng9y5WhBKtMvj
+7k4Q9FXDIlSdqnZQ5bebGUomb5uHcN48u7HD5XK8KfjFRgpZF2k5hny4cKsOyGQ
yKSvE3zHC35y3LLIBRfqwhOdrjYQndTg4bZ7p/VhAoGBAOHG79zo+PdKYXd73PAb
y0D/QO0qGinhY/2oEzmF96caDa5xrR0yYgbOpTd96zxH7YGBwcfjfKN0TeMIFiYm
qsbHe1+c24seSGWlmiBj7WSdwhr4YXssALQk/bB22ZaJ5tQlFtltlgJSM86vMLzF
GxtiVdr8OO/6ESQidTuJOD3N
-----END PRIVATE KEY-----

*/


/*
self-signed ECDSA signature:
============================


-----BEGIN CERTIFICATE-----
MIIBOTCB4KADAgECAgEBMAoGCCqGSM49BAMCMB4xHDAJBgNVBAYTAlJVMA8GA1UE
Ax4IAFQAZQBzAHQwHhcNMTMwMjAxMDAwMDAwWhcNMTYwMjAxMDAwMDAwWjAeMRww
CQYDVQQGEwJSVTAPBgNVBAMeCABUAGUAcwB0MFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAE7kM0cycsMDqJklaHEJIJQjgsT8J5Bbb9lEdVAJd8wozsLz8TlLAKHjUu
de+bAFr1NHW9YgBc55KP2D+12LH1IqMPMA0wCwYDVR0PBAQDAgACMAoGCCqGSM49
BAMCA0gAMEUCICm4AR4qHakFXmTk74lezPZ8Ab1PdgjSGDUePwXskQo6AiEAigW4
bOJDAJDn0lzw81CgI2eD+VWV7nj0n3xSFHKNK1g=
-----END CERTIFICATE-----


SEQUENCE(3 elem)
	SEQUENCE(8 elem)
		[0](1 elem)
			INTEGER									2
		INTEGER										1
		SEQUENCE(1 elem)
			OBJECT IDENTIFIER						1.2.840.10045.4.3.2
		SEQUENCE(1 elem)
			SET(2 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER				2.5.4.6
					PrintableString					RU
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER				2.5.4.3
					BMPString						Test
		SEQUENCE(2 elem)
			UTCTime									2013-02-01 00:00:00 UTC
			UTCTime									2016-02-01 00:00:00 UTC
		SEQUENCE(1 elem)
			SET(2 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER				2.5.4.6
					PrintableString					RU
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER				2.5.4.3
					BMPString						Test
		SEQUENCE(2 elem)
			SEQUENCE(2 elem)
				OBJECT IDENTIFIER					1.2.840.10045.2.1
				OBJECT IDENTIFIER					1.2.840.10045.3.1.7
			BIT STRING(520 bit) 					0100010010101111100011010001101110101101111111000001101111110001010010…
		[3](1 elem)
			SEQUENCE(1 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER				2.5.29.15
					OCTET STRING(1 elem)
						BIT STRING(8 bit) 			01000000
	SEQUENCE(1 elem)
		OBJECT IDENTIFIER							1.2.840.10045.4.3.2
	BIT STRING(1 elem)
		SEQUENCE(2 elem)
			INTEGER(254 bit) 						1886993436681320920938210465971224929770732669952011886037913429000807…
			INTEGER(256 bit) 						6242928019664484406118859299993365642874681948091725605744730581673206…

*/

/*
self-signed RSASSA-PSS example:

-----BEGIN CERTIFICATE-----
MIIDLjCCAeKgAwIBAgIBATBBBgkqhkiG9w0BAQowNKAPMA0GCWCGSAFlAwQCAQUA
oRwwGgYJKoZIhvcNAQEIMA0GCWCGSAFlAwQCAQUAogMCASAwHjEcMAkGA1UEBhMC
UlUwDwYDVQQDHggAVABlAHMAdDAeFw0xMzAyMDEwMDAwMDBaFw0xNjAyMDEwMDAw
MDBaMB4xHDAJBgNVBAYTAlJVMA8GA1UEAx4IAFQAZQBzAHQwggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQC0b5GWY4oMjNs2j4k+DLPr1ribN5rbRJNKxqqP
+KH8C+TG0/AyFxtnZsAqRiYDDVnXhB/Yl48OXvGJbFLMihT369K3SZwgjGeFFkns
7L9RgnT1yPliQSNPy0rjDpDH5S/Wi7fNKDhfSWFUi3D/pfBVDBUclVgbmKQfyTVy
FmGXV81yzLccdGN/DMyASGHik/NJBqHKEXJVoyLPKK7wSf90aWB8+sEaMvtFOfJT
osfkCJ4zD6I6+1Na3J6W86MYuIrXYgH0wbBZ+9AEFQkOTQ8Gkh1ZQJup3BC0UdB7
P9ad5wiVaHc1tHlojsBU3BntmxPtMQW8USBWxSc5GGc/yJDHAgMBAAGjDzANMAsG
A1UdDwQEAwIAAjBBBgkqhkiG9w0BAQowNKAPMA0GCWCGSAFlAwQCAQUAoRwwGgYJ
KoZIhvcNAQEIMA0GCWCGSAFlAwQCAQUAogMCASADggEBAK/ORKd/RDQS23VZIziG
lVh5l0jAcHZh8uo4qBOg7HJ2LnCv8466oIkzSCPFa+g+6DqlUEPBGwUgzp7jTKiE
mX24ZGeR215b9gKLuyMKAeWwlmwzYH1FpWmrkiyFS/LFZC/y3JwU9Z51Ge5J5mea
YZ4QQ2ZK35Cfa/CiBW/EQjwtEtxYHc2jd4x0Cgportuot4Axxa5v/6sz7uVHeIvH
d7zIwv/McOEAsAUMQsPtXf9roRUleCzfxkx7HEBH43eoV/a/aAJ/a2lKwCdnZpnp
sOnWjPwgFqTvDmSZMvVa3QLtOeDwmznR8Cjew/NqxpsJ12CBSlltTx/BaanfKr/7
d0A=
-----END CERTIFICATE-----


SEQUENCE(3 elem)
	SEQUENCE(8 elem)
		[0](1 elem)
			INTEGER								2										-- version
		INTEGER									1										-- serial
		SEQUENCE(2 elem)
			OBJECT IDENTIFIER					1.2.840.113549.1.1.10					-- rsaPSS
			SEQUENCE(3 elem)
				[0](1 elem)
					SEQUENCE(2 elem)
						OBJECT IDENTIFIER		2.16.840.1.101.3.4.2.1					-- sha-256
						NULL
				[1](1 elem)
					SEQUENCE(2 elem)
						OBJECT IDENTIFIER		1.2.840.113549.1.1.8					-- pkcs1-MGF
						SEQUENCE(2 elem)
							OBJECT IDENTIFIER	2.16.840.1.101.3.4.2.1					-- sha-256
							NULL
				[2](1 elem)
					INTEGER						32										-- salt length
		SEQUENCE(1 elem)
			SET(2 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER			2.5.4.6
					PrintableString				RU
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER			2.5.4.3
					BMPString					Test
		SEQUENCE(2 elem)
			UTCTime								2013-02-01 00:00:00 UTC
			UTCTime								2016-02-01 00:00:00 UTC
		SEQUENCE(1 elem)
			SET(2 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER			2.5.4.6
					PrintableString				RU
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER			2.5.4.3
					BMPString					Test
		SEQUENCE(2 elem)
			SEQUENCE(2 elem)
				OBJECT IDENTIFIER				1.2.840.113549.1.1.1					-- rsaEncryption
				NULL
			BIT STRING(1 elem)
				SEQUENCE(2 elem)
					INTEGER(2048 bit)			227779114708502272098325245002574518989245659902413298145007125468342…
					INTEGER						65537
		[3](1 elem)
			SEQUENCE(1 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER			2.5.29.15								-- keyUsage
					OCTET STRING(1 elem)
						BIT STRING(8 bit)		00000010
	SEQUENCE(2 elem)
		OBJECT IDENTIFIER						1.2.840.113549.1.1.10					-- rsaPSS
		SEQUENCE(3 elem)
			[0](1 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER			2.16.840.1.101.3.4.2.1					-- sha-256
					NULL
			[1](1 elem)
			SEQUENCE(2 elem)
				OBJECT IDENTIFIER				1.2.840.113549.1.1.8					-- pkcs1-MGF
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER			2.16.840.1.101.3.4.2.1					-- sha-256
					NULL
			[2](1 elem)
				INTEGER							32										-- salt length
	BIT STRING(2048 bit)						101011111100111001000100101001110111111101000100001101000001001011011…

*/

/*
-----BEGIN CERTIFICATE REQUEST-----
MIICzDCCAbQCAQAwgYYxCzAJBgNVBAYTAkVOMQ0wCwYDVQQIDARub25lMQ0wCwYD
VQQHDARub25lMRIwEAYDVQQKDAlXaWtpcGVkaWExDTALBgNVBAsMBG5vbmUxGDAW
BgNVBAMMDyoud2lraXBlZGlhLm9yZzEcMBoGCSqGSIb3DQEJARYNbm9uZUBub25l
LmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMP/U8RlcCD6E8AL
PT8LLUR9ygyygPCaSmIEC8zXGJung3ykElXFRz/Jc/bu0hxCxi2YDz5IjxBBOpB/
kieG83HsSmZZtR+drZIQ6vOsr/ucvpnB9z4XzKuabNGZ5ZiTSQ9L7Mx8FzvUTq5y
/ArIuM+FBeuno/IV8zvwAe/VRa8i0QjFXT9vBBp35aeatdnJ2ds50yKCsHHcjvtr
9/8zPVqqmhl2XFS3Qdqlsprzbgksom67OobJGjaV+fNHNQ0o/rzP//Pl3i7vvaEG
7Ff8tQhEwR9nJUR1T6Z7ln7S6cOr23YozgWVkEJ/dSr6LAopb+cZ88FzW5NszU6i
57HhA7ECAwEAAaAAMA0GCSqGSIb3DQEBBAUAA4IBAQBn8OCVOIx+n0AS6WbEmYDR
SspR9xOCoOwYfamB+2Bpmt82R01zJ/kaqzUtZUjaGvQvAaz5lUwoMdaO0X7I5Xfl
sllMFDaYoGD4Rru4s8gz2qG/QHWA8uPXzJVAj6X0olbIdLTEqTKsnBj4Zr1AJCNy
/YcG4ouLJr140o26MhwBpoCRpPjAgdYMH60BYfnc4/DILxMVqR9xqK1s98d6Ob/+
3wHFK+S7BRWrJQXcM8veAexXuk9lHQ+FgGfD0eSYGz0kyP26Qa2pLTwumjt+nBPl
rfJxaLHwTQ/1988G0H35ED0f9Md5fzoKi5evU1wG5WRxdEUPyt3QUXxdQ69i0C+7
-----END CERTIFICATE REQUEST-----

SEQUENCE(3 elem)
	SEQUENCE(4 elem)
		INTEGER								0
		SEQUENCE(7 elem)
			SET(1 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER		2.5.4.6
					PrintableString			EN
			SET(1 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER		2.5.4.8
					UTF8String				none
			SET(1 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER		2.5.4.7
					UTF8String				none
			SET(1 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER		2.5.4.10
					UTF8String				Wikipedia
			SET(1 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER		2.5.4.11
					UTF8String				none
			SET(1 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER		2.5.4.3
					UTF8String				*.wikipedia.org
			SET(1 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER		1.2.840.113549.1.9.1
					IA5String				none@none.com
		SEQUENCE(2 elem)
			SEQUENCE(2 elem)
				OBJECT IDENTIFIER			1.2.840.113549.1.1.1
				NULL
			BIT STRING(1 elem)
				SEQUENCE(2 elem)
					INTEGER(2048 bit)		247423760109548725137075531536764195259463976641104303270337074470866…
					INTEGER					65537
		[0](0 elem)
	SEQUENCE(2 elem)
		OBJECT IDENTIFIER					1.2.840.113549.1.1.4
		NULL
	BIT STRING(2048 bit)					011001111111000011100000100101010011100010001100011111101001111101000…
*/

/* 
-----BEGIN CERTIFICATE REQUEST-----
MIIC4jCCAcoCAQAwbTELMAkGA1UEBhMCQ1oxDTALBgNVBAgTBEJybm8xDTALBgNV
BAcTBEJybm8xEDAOBgNVBAoTB1JlZCBIYXQxEDAOBgNVBAsTB1JlZCBIYXQxHDAa
BgNVBAMTE2NsaWVudDEuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQDrt1Jf2SrC5tM0ETtHhCvq84+V1maDY6TFYIb+jVS1EZi90Wf9
FxtutKOllwPbMSyP1yFXXRXIHhh1X4ONCYksZ1QwGdClwP51tBxr/Rzs4Bji4wAu
SN5Z6nlKH+L32rQmLu6Oib1p2WKckkWkoLEplhKUNnVm4f0tVlZ0annYNwcEnFfw
z6V5xfTt6RzPrslA5Az/zx7nhoB6QkeEmW+HpWV+kwP7xmRF+wWjxAmDqKPbvlIh
KVKaNJuJGHXdkAPajGfaa209sApzmphAnnbmJF82VkRrg8rG8HpUuS7YtRSBP9gG
0J3G7oZbCvhYBPGTcT/A56Oki8QbIKI9OZkxAgMBAAGgMDAuBgkqhkiG9w0BCQ4x
ITAfMB0GA1UdEQQWMBSCEmNsaWVudC5leGFtcGxlLmNvbTANBgkqhkiG9w0BAQUF
AAOCAQEAJC8byzLDAk7lX8kg6kWWMPfmpMEU+ACAVzQL8DJNlVCLUB+IWQPdHI+K
HZDsB4NPY6vaqiujibNwcl4n4196Rsxbnc1Q0xIvJ3JViEiI/2oxW+bdgWCmjuLf
JEqp/KMIcDdtvJ+U9JA6IplexAns/tkRJ3FVbPYtZpKw5FOFixH1WeHjF8J0wOCv
7RNHI4E+7LeeLv5w8+QB9fc4xk0LYLz9ajoQf/4em5bhaidRDAyp6rh88zNdWM5u
ZpWOyngW0yt6r8xMBCM8CJAql+lrUT1I/IuhnyjK1PKgI6qr/2a/qlo7KJpAjwxU
85gGMt/+QPtaKfMJSUkyjXidXU5eeA==
-----END CERTIFICATE REQUEST-----


SEQUENCE(3 elem)
	SEQUENCE(4 elem)
		INTEGER									0
		SEQUENCE(6 elem)
			SET(1 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER2.5.4.6
					PrintableStringCZ
			SET(1 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER			2.5.4.8
					PrintableString				Brno
			SET(1 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER			2.5.4.7
					PrintableString				Brno
			SET(1 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER			2.5.4.10
					PrintableString				Red Hat
			SET(1 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER			2.5.4.11
					PrintableString				Red Hat
			SET(1 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER			2.5.4.3
					PrintableString				client1.example.com
		SEQUENCE(2 elem)
			SEQUENCE(2 elem)
				OBJECT IDENTIFIER				1.2.840.113549.1.1.1
				NULL
			BIT STRING(1 elem)
				SEQUENCE(2 elem)
					INTEGER(2048 bit)			297564010035200491720488096030820652830611794214018659727148613700060…
					INTEGER						65537
		[0](1 elem)
			SEQUENCE(2 elem)
				OBJECT IDENTIFIER				1.2.840.113549.1.9.14
				SET(1 elem)
					SEQUENCE(1 elem)
						SEQUENCE(2 elem)
							OBJECT IDENTIFIER	2.5.29.17
							OCTET STRING(1 elem)
								SEQUENCE(1 elem)
									[2]			client.example.com
	SEQUENCE(2 elem)
		OBJECT IDENTIFIER						1.2.840.113549.1.1.5
		NULL
	BIT STRING(2048 bit)						001001000010111100011011110010110011001011000011000000100100111011100…
*/

/*
Unknown structures:


SEQUENCE(2 elem)
	OBJECT IDENTIFIER								2.16.840.1.113730.1.1 -- netscape-cert-type
	OCTET STRING(1 elem)
		BIT STRING(8 bit)							00000001

*/
/*
SEQUENCE(2 elem)
	OBJECT IDENTIFIER					1.2.840.113533.7.65.0 -- entrustVersInfo
	OCTET STRING(1 elem)
		SEQUENCE(2 elem)
			GeneralString
			BIT STRING(8 bit)			10000001
*/
/*
OID value: 1.2.840.113533.7.65.0

OID description:
certificate extension for entrust version

entrustVersInfo EXTENSION ::= {
	SYNTAX EntrustVersInfoSyntax
	IDENTIFIED BY { id-nsn-ext 0}
}

EntrustVersInfoSyntax ::= OCTET STRING
*/

/*

-----BEGIN CERTIFICATE REQUEST-----
MIIByjCCATMCAQAwgYkxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlh
MRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRMwEQYDVQQKEwpHb29nbGUgSW5jMR8w
HQYDVQQLExZJbmZvcm1hdGlvbiBUZWNobm9sb2d5MRcwFQYDVQQDEw53d3cuZ29v
Z2xlLmNvbTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEApZtYJCHJ4VpVXHfV
IlstQTlO4qC03hjX+ZkPyvdYd1Q4+qbAeTwXmCUKYHThVRd5aXSqlPzyIBwieMZr
WFlRQddZ1IzXAlVRDWwAo60KecqeAXnnUK+5fXoTI/UgWshre8tJ+x/TMHaQKR/J
cIWPhqaQhsJuzZbvAdGA80BLxdMCAwEAAaAAMA0GCSqGSIb3DQEBBQUAA4GBAIhl
4PvFq+e7ipARgI5ZM+GZx6mpCz44DTo0JkwfRDf+BtrsaC0q68eTf2XhYOsq4fkH
Q0uA0aVog3f5iJxCa3Hp5gxbJQ6zV6kJ0TEsuaaOhEko9sdpCoPOnRBm2i/XRD2D
6iNh8f8z0ShGsFqjDgFHyF3o+lUyj+UC6H1QW7bn
-----END CERTIFICATE REQUEST-----


SEQUENCE(3 elem)
	SEQUENCE(4 elem)
		INTEGER 						0
		SEQUENCE(6 elem)
			SET(1 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER 	2.5.4.6
					PrintableString 	US
			SET(1 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER 	2.5.4.8
					PrintableString 	California
			SET(1 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER 	2.5.4.7
					PrintableString 	Mountain View
			SET(1 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER 	2.5.4.10
					PrintableString 	Google Inc
			SET(1 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER 	2.5.4.11
					PrintableString 	Information Technology
			SET(1 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER 	2.5.4.3
					PrintableString 	www.google.com
		SEQUENCE(2 elem)
			SEQUENCE(2 elem)
				OBJECT IDENTIFIER 		1.2.840.113549.1.1.1 -- RSAEncryption
				NULL
			BIT STRING(1 elem)
				SEQUENCE(2 elem)
					INTEGER(1024 bit)  	116293059388161928152556433331639234989906985824917952487098931770978…
					INTEGER 			65537
		[0](0 elem)
	SEQUENCE(2 elem)
		OBJECT IDENTIFIER 				1.2.840.113549.1.1.5 -- sha1WithRSAEncryption
		NULL
	BIT STRING(1024 bit)  				100010000110010111100000111110111100010110101011111001111011101110001…





attributes([0] in here) can be like:

		[0](1 elem)
			SEQUENCE(2 elem)
				OBJECT IDENTIFIER		1.2.840.113549.1.9.7
				SET(1 elem)
					UTF8String			password
*/

/*
Creating Self signed certificate with keyUsage extensions:

You could try using openssl (available in most linux/unix environments) It supports the keyUsage extensions.

e.g. to create a self signed cert, you could use something similar to the following steps:
#Locate and edit your openssl configuration /etc/ssl/openssl.cnf, make sure it contains the following lines uncommented:
req_extensions = v3_req # The extensions to add to a certificate request
keyUsage = nonRepudiation, digitalSignature, keyEncipherment, dataEncipherment

Add whatever key usage extensions you need if not already there.

#Create private key
openssl genrsa -des3 -out mytest.key 2048

#remove pass phrase - optional
openssl rsa -in mytest.key -out mytest.nopass.key

#create cert signing request for your key
openssl req -new -key mytest.nopass.key -out mytest.csr -config /etc/ssl/openssl.cnf

#Confirm that your requested extensions are in the cert request
openssl req -text -noout -in mytest.csr

#Generate Self signed cert
openssl x509 -req -days 3650 -in mytest.csr -signkey mytest.nopass.key -out mytest.crt -extensions v3_req -extfile /etc/ssl/openssl.cnf

#convert to p12 for browser
openssl pkcs12 -export -in mytest.crt -inkey mytest.nopass.key -out mytest.p12

#import into browser and check the details…

*/

/*
https://wiki.mozilla.org/SecurityEngineering/x509Certs

Running your Own CA
===================

If you are going to have your own CA, we recommend building 3 certificates: a long term root cert, a medium term intermediate cert, and a short term end-entity cert. This type of hierarchy allows for a relatively simple long term root to be distributed to clients, and some flexibility on the intermediate cert so that you can change parameters based on best practices and security research.

Generate your CA Root
---------------------

Update *.example.com and *.example.net below to match your domains.

Assumptions:

	- You are the domain owner of *.example.com and *.example.net.
	- Your computer is not connected to the internet.

Steps to generate your CA root certificate:

1. Generate key

	- "openssl genpkey -algorithm RSA -out rootkey.pem -pkeyopt rsa_keygen_bits: 4096"
	- 4096 is considered secure for the next 15 years. 

2. Generate csr

	- "openssl req -new -key rootkey.pem -days 5480 -extensions v3_ca -batch -out root.csr - utf8 -subj '/C=US/O=Orgname/OU=SomeInternalName'
	- Make a new Certificate Signing Request (CSR) that will be valid for 15 years.

3. Write extensions File (openssl.root.cnf)

	- basicConstraints = critical, CA:TRUE
	- keyUsage = keyCertSign, cRLSign
	- subjectKeyIdentifier = hash
	- nameConstraints = permitted;DNS:example.com,permitted;DNS:example.net

4. Self-sign csr (using SHA256) and append the extensions described in the file

	- "openssl x509 -req -sha256 -days 3650 -in root.csr -signkey rootkey.pem -set-serial $ANY_SMALL_INTEGER -extfile openssl.root.cnf -out root.pem"

Now you have CA pem file with its associated key.

Generate your Intermediate cert
-------------------------------

The following steps create an intermediate cert that is valid for 8 years.

1. Generate key

	- "openssl genpkey -algorithm RSA -out r=intkey.pem -pkeyopt rsa_keygen_bits: 3072"
	- A 3072 bit key is considered secure for the next 8 years.

2. Generate csr

	- "openssl req -new -key intkey.pem -days 2922 -extensions v3_ca -batch -out int.csr - utf8 -subj '/C=US/O=Orgname/OU=SomeInternalName2'
	- Make a new Certificate Signing Request (CSR) that will be valid for 8 years.

3. Write extensions File (openssl.int.cnf)

	- basicConstraints = critical, CA:TRUE
	- authorityKeyIdentifier = keyid, issuer
	- subjectKeyIdentifier = hash
	- keyUsage = keyCertSign, cRLSign
	- extendedKeyUsage =serverAuth
	- authorityInfoAccess = OCSP;URI:http://ocsp.example.com:8888/

4. Sign the intermediate csr with the root key and the intermediate extensions

	- "openssl x509 -req -sha256 -days 2922 -in int.csr -CAkey rootkey.pem -CA root.pem -set_serial $SOME_LARGE_INTEGER -out int.pem -extfile openssl.int.cnf"

Generate the end entity certificate
-----------------------------------

Update www.example.com below to match your domain.

1. Generate key

	- "openssl genpkey -algorithm RSA -out eekey.pem -pkeyopt rsa_keygen_bits: 2048"
	- 2048 is considered secure for the next 4 years.

2. Generate csr

	- "openssl req -new -key key.pem -days 1096 -extensions v3_ca -batch -out example.csr - utf8 -subj '/CN=www.example.com'
	- Make a new Certificate Signing Request (CSR) that will be valid for 3 years.

3. Write extensions file (make a new file with name openssl.ss.cnf with the following contents)

	- basicConstraints = CA:FALSE
	- subjectAltName =DNS:www.example.com
	- extendedKeyUsage =serverAuth<
	- authorityInfoAccess = OCSP;URI:http://ocsp.example.com:80/

4. Intermediate sings the csr (using SHA256) and appends the extensions described in the file

	- "openssl x509 -req -sha256 -days 1096 -in example.csr -CAkey intkey.pem -CA int.pem -set_serial $SOME_LARGE_INTEGER -out www.example.com.pem -extfile openssl.int.cnf"
*/

/*
DN Field Definition
Whole Field The entire DN.
Country (C)						The two-letter country abbreviation. These codes conform to ISO 3166
								country abbreviations.
Common Name (CN)				The name of a person, system, or other entity. This is the lowest (most
								specific) level in the identification hierarchy.
DN Qualifier (DNQ)				A specific DN attribute.
E-mail Address (EA)				The e-mail address of the person, system or entity that owns the certificate.
Generational Qualifier
(GENQ)
								A generational qualifier such as Jr., Sr., or III.
Given Name (GN)					The first name of the certificate owner.
Initials (I)					The first letters of each part of the certificate owner’s name.
Locality (L)					The city or town where the organization is located.
Name (N)						The name of the certificate owner.
Organization (O)				The name of the company, institution, agency, association, or other entity.
Organizational Unit
(OU)
								The subgroup within the organization.
Serial Number (SER)				The serial number of the certificate.
Surname (SN)					The family name or last name of the certificate owner.
State/Province (S/P)			The state or province where the organization is located.
Title (T)						The title of the certificate owner, such as Dr.
User ID (UID)					The identification number of the certificate owner.
*/