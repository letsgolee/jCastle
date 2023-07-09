/**
 * A Javascript implemenation of Abstract Syntax Notation Number On(ASN1) Parser
 * 
 * @author Jacob Lee
 * 
 * Copyright (C) 2015-2022 Jacob Lee. All rights reserved.
 */

const jCastle = require('./jCastle');

require('./bigint-extend');
require('./util');
require('./lang/en');
require('./error');
require('./oid');

/* http://lapo.it/asn1js */

/* Refer to A Layman's Guide to a Subset of ASN.1, BER, and DER */

jCastle.asn1 = class
{
	/**
	 * Create a new ASN1 object.
	 * 
	 * @public
	 * 
	 * @returns the asn1 object.
	 */
    constructor()
    {
        this.data = null;
        this.pos = 0;
        this.eocLevel = 0;
        this.berEncoding = false;
        this.linebreak = 1024;
        this.ignoreLength = false;
    }

	// not used function.
	// experimental.
	ignoreLengthError()
	{
		this.ignoreLength = true;
	}

	/**
	 * checks whether the pos pointer reaches the end of the data.
	 * 
	 * @public
	 * 
	 * @returns true if pos pointer reaches the end of the data.
	 */
	isFinish()
	{
		return this.pos == this.data.length;
	}

	/**
	 * parses the buffer or string data and builds a asn1 structured object.
	 * 
	 * @public
	 * 
	 * @param {Buffer} data the buffer or string data to be parsed.
	 * @param {boolean} parsing_sub boolean flag for sub data.
	 * 
	 * @returns the parsed asn1 data object.
	 */
	parse(data, parsing_sub = false)
	{
		if (!data || !data.length) return null;

		this.data = Buffer.from(data, 'latin1');
		this.pos = 0;
		this.start_pos = 0;

/*
3. Basic Encoding Rules

The Basic Encoding Rules for ASN.1, abbreviated BER, give one or more ways 
to represent any ASN.1 value as an octet string. (There are certainly 
other ways to represent ASN.1 values, but BER is the standard for 
interchanging such values in OSI.)

There are three methods to encode an ASN.1 value under BER, the choice of
which depends on the type of value and whether the length of the value is
known. The three methods are primitive, definite-length encoding; 
constructed, definite- length encoding; and constructed, indefinite-length 
encoding. Simple non-string types employ the primitive, definite-length 
method; structured types employ either of the constructed methods; and 
simple string types employ any of the methods, depending on whether 
the length of the value is known. Types derived by implicit tagging employ 
the method of the underlying type and types derived by explicit tagging 
employ the constructed methods.

In each method, the BER encoding has three or four parts:

    Identifier octets. These identify the class and tag number of the ASN.1 
	value, and indicate whether the method is primitive or constructed.

    Length octets. For the definite-length methods, these give the number 
	of contents octets. For the constructed, indefinite-length method, 
	these indicate that the length is indefinite.

    Contents octets. For the primitive, definite-length method, these give 
	a concrete representation of the value. For the constructed methods,
	these give the concatenation of the BER encodings of the components 
	of the value.

    End-of-contents octets. For the constructed, indefinite- length method,
	these denote the end of the contents. For the other methods, these are
	absent.
*/

/*
https://en.wikipedia.org/wiki/X.690

Encoding structure
==================

The encoding of data does generally consist of four components which appear
in the following order:

+-------------------+---------------+-----------------+------------------------+
| Identifier octets | Length octets | Contents octets |                        |
|        Type       |      Length   |       Value     | End-of-contents octets |
+-------------------+---------------+-----------------+------------------------+

The End-of-contents octets are optional and only used if the indefinite length
form is used. The Contents octet may also be omitted if there is no content to
encode like in the NULL type.
*/
		var tag_octet = this.data[this.pos++];
/*
https://en.wikipedia.org/wiki/X.690

Encoding
========

The identifier octets encode the element type as an ASN.1 tag, consisting of
the class and number, and whether the contents octets represent a constructed 
or primitive value. Note that some types can have values with either primitive
or constructed encodings. It is encoded as 1 or more octets.

+-------------------------------------+--------------------------------+
|              Octet 1                |        Octet 2 onwards         |
+-----+-----+-----+---+---+---+---+---+----+---+---+---+---+---+---+---+
|  8  |  7  |  6  | 5 | 4 | 3 | 2 | 1 | 8  | 7 | 6 | 5 | 4 | 3 | 2 | 1 |
+-----+-----+-----+---+---+---+---+---+----+---+---+---+---+---+---+---+
|           |     | Tag number (0–30) |              N/A               |
| Tag Class | P/C +-------------------+----+---------------------------+
|           |     |         31        |More| Tag number                |
+-----------+-----+-------------------+----+---------------------------+

In the initial octet, bit 6 encodes whether the type is primitive or constructed,
bit 7–8 encode the class of the type, and bits 1–5 encode the tag number. The 
following values are possible:

+------------------+-------+-------------------------------------------------------------+
|      Class       | Value |                       Description                           |
+------------------+-------+-------------------------------------------------------------+
| Universal        |   0   | The type is native to ASN.1                                 |
+------------------+-------+-------------------------------------------------------------+
| Application      |   1   | The type is only valid for one specific application         |
+------------------+-------+-------------------------------------------------------------+
| Context-specific |   2   | Meaning of this type depends on the context                 |
|                  |       | (such as within a sequence, set or choice)                  |
+------------------+-------+-------------------------------------------------------------+
| Private          |   3   | Defined in private specifications                           |
+------------------+-------+-------------------------------------------------------------+

+------------------+-------+-------------------------------------------------------------+
|       P/C        | Value |                        Description                          |
+------------------+-------+-------------------------------------------------------------+
| Primitive (P)    |   0   | The contents octets directly encode the element value.      |
+------------------+-------+-------------------------------------------------------------+
| Constructed (C)  |   1   | The contents octets contain 0, 1, or more element encodings.|
+------------------+-------+-------------------------------------------------------------+
*/
		var tagClass = tag_octet >>> 6;
		var tagType = tag_octet & 0x1f; // 0x1f & 0x20 for constructed
		var constructed = tag_octet & 0x20;
		var length = this._parseTagLength(parsing_sub);
		constructed = constructed == 0x20 ? true : false;
		var indefinite_length = false;
		// console.log('tag octet: ', tag_octet.toString(16));
		// console.log('tagClass: ', tagClass.toString(16));
        // console.log('tagType: ', tagType.toString(16));
        // console.log('constructed: ', constructed);
		// console.log('length: ', length);


		if (tag_octet == 0x00 && length == 0) { // End-Of-Contents octets
			return null;
		}

		// length will be -1 when indefinite length flag is on.
		// In this case, the tag should be constructed tag.
		if (length == -1) {
			indefinite_length = true;
/*
3.3 Constructed, indefinite-length method

This method applies to simple string types, structured types, types derived
simple string types and structured types by implicit tagging, and types
derived from anything by explicit tagging. It does not require that the 
length of the value be known in advance. The parts of the BER encoding are 
as follows:

    Identifier octets. As described in Section 3.2.

    Length octets. One octet, 80.

    Contents octets. As described in Section 3.2.

    End-of-contents octets. Two octets, 00 00.

Since the end-of-contents octets appear where an ordinary BER encoding might 
be expected (e.g., in the contents octets of a sequence value), the 00 and 00
appear as identifier and length octets, respectively. Thus the end-of-contents
octets is really the primitive, definite-length encoding of a value with 
universal class, tag number 0, and length 0.
*/
			if (!constructed) {
				throw jCastle.exception("INVALID_DATA_LENGTH", 'ASN001');
			}

			this.eocLevel++;
			length = this.data.length - this.pos;
			// console.log('eocLevel: ', this.eocLevel);
			// console.log('changed data size: ', length);
		} else {
			if (length == null || length > (this.data.length - this.pos)) {
			// console.log('remained data size: ' , this.data.length - this.pos);
			// console.log('length: ', length);
			// console.log('eocLevel: ', this.eocLevel);
				if (parsing_sub) return null;
				else {
					if (!this.ignoreLength) throw jCastle.exception("INVALID_DATA_LENGTH", 'ASN002');
					length = this.data.length - this.pos;
					// console.log('ignoring the legnth & changed length: ', length);
				}
			}
		}

		switch (tagClass) {
			case jCastle.asn1.tagClassContextSpecific:
			case jCastle.asn1.tagClassPrivate:
			case jCastle.asn1.tagClassApplication:
/*
2.3 Implicitly and explicitly tagged types

Tagging is useful to distinguish types within an application; it is also commonly
used to distinguish component types within a structured type. For instance,
optional components of a SET or SEQUENCE type are typically given distinct
context-specific tags to avoid ambiguity.

There are two ways to tag a type: implicitly and explicitly.

Implicitly tagged types are derived from other types by changing the tag of the
underlying type. Implicit tagging is denoted by the ASN.1 keywords [class
number] IMPLICIT (see Section 5.1).

Explicitly tagged types are derived from other types by adding an outer tag to
the underlying type. In effect, explicitly tagged types are structured types
consisting of one component, the underlying type. Explicit tagging is denoted by
the ASN.1 keywords [class number] EXPLICIT (see Section 5.2).

The keyword [class number] alone is the same as explicit tagging, except when
the "module" in which the ASN.1 type is defined has implicit tagging by default.
("Modules" are among the advanced features not described in this note.)

For purposes of encoding, an implicitly tagged type is considered the same as
the underlying type, except that the tag is different. An explicitly tagged type is
considered like a structured type with one component, the underlying type.
Implicit tags result in shorter encodings, but explicit tags may be necessary to
avoid ambiguity if the tag of the underlying type is indeterminate (e.g., the
underlying type is CHOICE or ANY).
*/
				if (constructed) {
					if (length == 0) {
						return {
							tagClass: tagClass,
							type: tagType,
							constructed: true,
							explicit: true,
							items: [],
							_isAsn1: true,
							buffer: Buffer.from([tag_octet, 0x00]),
							// der: String.fromCharCode(tag_octet) + '\x00'
						};
					}
					
					var asn1 = new jCastle.asn1();
					if (this.ignoreLength) asn1.ignoreLength = true;
					var items = [];
					var start = this.pos;
					var end = this.pos + length;

					while (start < end) {
						var data = this.data.slice(start, end);
						var tagValue = asn1.parse(data);
						start += asn1.pos;
						if (tagValue == null) {
							// console.log('eocLevel: '+this.eocLevel);
							if (this.eocLevel) {
								this.eocLevel--;
								if (this.eocLevel == 0) break;
							} else {
								throw jCastle.exception("UNKNOWN_TAG_TYPE", 'ASN003');
							}
						} else {
							items.push(tagValue);
						}
					}

					// get real length
					if (end > start) {
						length = length - (end - start);
					}

					var buf;
					
					if (indefinite_length) {
						// console.log(length);
						buf = Buffer.concat([
							Buffer.from([tag_octet, 0x80]),
							this.data.slice(this.pos, this.pos + length), 
							Buffer.from([0x00, 0x00])]);
						// var der = String.fromCharCode(tag_octet) + '\x80' + this.data.slice(this.pos, this.pos + length).toString('latin1') + '\x00\x00';
					} else {
						var length_der = this._getLengthDER(length);
						buf = Buffer.concat([
							Buffer.from([tag_octet]),
							Buffer.from(length_der, 'latin1'),
							this.data.slice(this.pos, this.pos + length)]);
						// var der = String.fromCharCode(tag_octet) + length_der + this.data.slice(this.pos, this.pos + length).toString('latin1');
					}
					this.pos += length;

					return {
						tagClass: tagClass,
						type: tagType,
						items: items,
						constructed: true,
						explicit: true,
						_isAsn1: true,
						buffer: buf,
						// der: der,
						indefiniteLength: indefinite_length
					};
				} else {
					var start = this.pos;
					this.pos += length;

					return {
						tagClass: tagClass,
						type: tagType,
						constructed: false,
						_isAsn1: true,
						buffer: Buffer.slice(this.data, start, start + length),
						value: this.data.slice(start, start + length).toString('latin1')
					};
				}
			case jCastle.asn1.tagClassUniversal:
				var tagValue = this._parseTagValue(tagClass, tagType, length, indefinite_length, constructed);

				return tagValue;
			default: 
				if (parsing_sub) return null;
				else throw jCastle.exception("UNKNOWN_TAG_CLASS", 'ASN004');
		}
	}

/*
4. Distinguished Encoding Rules

The Distinguished Encoding Rules for ASN.1, abbreviated DER, are a subset of BER, 
and give exactly one way to represent any ASN.1 value as an octet string. DER is 
intended for applications in which a unique octet string encoding is needed, as 
is the case when a digital signature is computed on an ASN.1 value. DER is defined
in Section 8.7 of X.509.

DER adds the following restrictions to the rules given in Section 3:

    1. When the length is between 0 and 127, the short form of length must be used

    2. When the length is 128 or greater, the long form of length must be used, 
	and the length must be encoded in the minimum number of octets.

    3. For simple string types and implicitly tagged types derived from simple string
	types, the primitive, definite-length method must be employed.

    4. For structured types, implicitly tagged types derived from structured types, 
	and explicitly tagged types derived from anything, the constructed, 
	definite-length method must be employed. 
*/
/*
https://en.wikipedia.org/wiki/X.690

Length octets
=============

There are two forms of the length octets: The definite form and the indefinite form.

                          First length octet
+-----------------+-----------------------------------------------+
|                 |                      Bits                     |
|      Form       +-----+-----+-----+-----+-----+-----+-----+-----+
|                 |  8  |  7  |  6  |  5  |  4  |  3  |  2  |  1  |
+-----------------+-----+-----+-----+-----+-----+-----+-----+-----+
| Definite, short |  0  | Length (0–127)                          |
+-----------------+---+-------------------------------------------+
| Indefinite      |  1  | 0                                       |
+-----------------+---+-------------------------------------------+
| Definite, long  |  1  | Number of following octets (1–126)      |
+-----------------+---+-------------------------------------------+
| Reserved        |  1  | 127                                     |
+-----------------+-----+-----------------------------------------+

Definite form
=============

This encodes the number of content octets and is always used if the type is primitive
or constructed and data are immediately available. There is a short form and a long 
form, which can encode different ranges of lengths. Numeric data is encoded as 
unsigned integers with the least significant bit always first (to the right).
The short form consists of a single octet in which bit 8 is 0, and bits 1–7 encode 
the length (which may be 0) as a number of octets.
The long form consist of 1 initial octet followed by 1 or more subsequent octets, 
containing the length. In the initial octet, bit 8 is 1, and bits 1–7 (excluding the
values 0 and 127) encode the number of octets that follow.[1] The following octets 
encode, as big-endian, the length (which may be 0) as a number of octets.

                        Long form example, length 435
+---------------------------------------+-------------------------------+-------------------------------+
|                Octet 1                |            Octet 2            |            Octet 3            |
+-----------+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
|     1     | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 1 | 0 | 1 | 1 | 0 | 0 | 1 | 1 |
+-----------+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
| Long form |      2 length octets      |                        435 content octets                     |
+-----------+---------------------------+---------------------------------------------------------------+
*/
	/**
	 * parses length tag
	 * 
	 * @private
	 * 
	 * @param {boolean} parsing_sub boolean flag for sub data.
	 * 
	 * @returns {integer} length size.
	 */
	_parseTagLength(parsing_sub = false)
	{
		if (this.pos >= this.data.length) {
			if (parsing_sub) return null;
			else throw jCastle.exception("EOC_REACHED", 'ASN005');
		}

		var len = this.data[this.pos++];

		if (len & 0x80) {
			var size = len & 0x7F;


			// 2016.07.05
			// when size is 0 then the length is undefined.
			// der has more restrict rule, but ber is a little loosed.
			// and cms(cryptographic message syntax) allows ber-rule.
			if (size == 0) return -1;

			// if size is greater than 4 then the data is too big for javascript's handling.
			if (size > 4) {
				// console.log('len: ', len.toString(16));
				// console.log('size: ', size.toString(16));
				if (parsing_sub) return null;
				else throw jCastle.exception("TOO_BIG_TAG_LENGTH", 'ASN006');
			}

			var length = parseInt(this.data.slice(this.pos, this.pos + size).toString('hex'), 16);
			if (length < 0) throw jCastle.exception("TOO_BIG_TAG_LENGTH", 'ASN007');
			this.pos += size;

			return length;
		}

		return len;
	}

/*
A BER encoded "tag" is made up of several bit fields:

+---+---+---+---+---+---+---+---+
| 8 | 7 | 6 | 5 | 4 | 3 | 2 | 1 |
+---+---+---+---+---+---+---+---+
| Class |P/C|    Tag Number     |
+-------+---+-------------------+
The tag number for a Sequence(in the Universal Class) is 0x10.
A sequence is a Constructed type, making the P/C bit 1
Universal Class is 0

If the tag number is 0x10 then this makes the entire octet 0x30.
*/
/*
tagValue := {
	tagClass: jCastle.asn1.tagClassUniversal | 
			  jCastle.asn1.tagClassApplication | 
			  jCastle.asn1.tagClassContextSpecific | 
			  Castle.ASN1.tagClassPrivate,
	type: jCastle.asn1.tagBoolean ~ jCastle.asn1.tagGeneralizedTime,
	value: tag value,
	constructed: true | false, when tagClass is not jCastle.asn1.tagClassUniversal
}
*/
	/**
	 * parses the value of the tag.
	 * 
	 * @private
	 * 
	 * @param {integer} tagClass value.
	 * @param {integer} tag value.
	 * @param {integer} length of the data. 
	 * @param {boolean} indefinite_length boolean flag for indefinite length.
	 * @param {boolean} constructed boolean flag for constructed data type.
	 * 
	 * @returns the parsed data of the tag.
	 */
	_parseTagValue(tagClass, tag, length, indefinite_length, constructed = false)
	{
		switch (tag) {
			case jCastle.asn1.tagSequence:
			case jCastle.asn1.tagSet:
				var items = [];
				var start = this.pos;
				var end = this.pos + length;
				var buf;
				// var der;
				
				while (start < end) {
					var data = this.data.slice(start, end);
					var asn1 = new jCastle.asn1();
					if (this.ignoreLength) asn1.ignoreLength = true;
					var tagValue = asn1.parse(data);
					start += asn1.pos;
					if (tagValue == null) {
						// console.log('eocLevel: ', this.eocLevel);
						if (this.eocLevel) {
							this.eocLevel--;
							if (this.eocLevel == 0) break;
						} else {
							throw jCastle.exception("UNKNOWN_TAG_TYPE", 'ASN008');
						}
					} else {
						items.push(tagValue);
					}
				}

				// get real length
				if (end > start) {
					length = length - (end - start);
				}

				if (indefinite_length) {
					buf = Buffer.concat([
						Buffer.from([tag | 0x20, 0x80]),
						this.data.slice(this.pos, this.pos + length),
						Buffer.from([0x00, 0x00])]);
					// der = String.fromCharCode(tag | 0x20) + '\x80' + this.data.slice(this.pos, this.pos + length).toString('latin1') + '\x00\x00';
				} else {
					var length_der = this._getLengthDER(length);
					buf = Buffer.concat([
						Buffer.from([tag | 0x20]),
						Buffer.from(length_der, 'latin1'),
						this.data.slice(this.pos, this.pos + length)]);
					// der = String.fromCharCode(tag | 0x20) + length_der + this.data.slice(this.pos, this.pos + length).toString('latin1');
				}
				this.pos += length;

				return {
					tagClass: tagClass,
					type: tag,
					items: items,
					_isAsn1: true,
					buffer: buf,
					// der: der,
					indefiniteLength: indefinite_length
				};

			case jCastle.asn1.tagBoolean: // 0x01
				var data = this.data[this.pos++];

				return {
					tagClass: tagClass,
					type: tag,
					_isAsn1: true,
					value: data ? true : false
				};

			case jCastle.asn1.tagEnumerated: // 0x0a
/*
Type ENUMERATED is similar to the INTEGER type, but names specific values only. For example,

   ColorType ::= ENUMERATED
       {
          red      (0)
          white    (1)
          blue     (2)
       }
has the same interpretation as in the type INTEGER example near the beginning of this section, 
except that ColorType can take only the values specifically in the list; that is, 
no other values than 0 for ``red", 1 for ``white", or 2 for ``blue".



http://security.stackexchange.com/questions/22586/asn-1-enumerated-vs-integer

QUESTION:

From the X.509 specs:

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
...and...

Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
Why isn't Version an ENUMERATED type? And similarly, why isn't CRLReason an INTEGER?

ANSWER:

ENUMERATED and INTEGER are almost identical (they just use distinct tags). The generic idea 
is that ENUMERATED is for a choice within a bounded set of possible values, whereas INTEGER
is for values which could, at least theoretically, raise indefinitely.

Here, the use of ENUMERATED for CRLReasons is a hint which says that "there shall be no 
other reason in the future", whereas there may well be other protocol versions (possibly
many others).

Now that's just a declaration of intent, which will not be enforced in any way. Remember
that the justification of most of ASN.1 is: "it looked like a good idea at that time". Do not
try to read too much in it. After all, ASN.1 succeeded in defining, well into the 1980s, 
a format for dates which has only two digits for the year -- a glaring Y2K issue, which did
not deter the standardization committee... so just accept the ENUMERATED/INTEGER duality as
one of the numerous quirks of ASN.1 (it's not the worse).
*/
			case jCastle.asn1.tagInteger: // 0x02
/*
5.7 INTEGER

The INTEGER type denotes an arbitrary integer. INTEGER values can be positive, negative, or
zero, and can have any magnitude.
The INTEGER type is used for version numbers throughout PKCS, cryptographic values such as 
modulus, exponent, and primes in PKCS #1's RSAPublicKey and RSAPrivateKey types and PKCS #3's
DHParameter type, a message-digest iteration count in PKCS #5's PBEParameter type, and 
version numbers and serial numbers in X.509's Certificate type.

ASN.1 notation:

INTEGER [{ identifier1(value1) ... identifiern(valuen) }]

where identifier1, ..., identifiern are optional distinct identifiers and value1, ..., valuen
are optional integer values. The identifiers, when present, are associated with values of the
type.

Example: X.509's Version type is an INTEGER type with identified values:

Version ::= INTEGER { v1988(0) }

The identifier v1988 is associated with the value 0. X.509's Certificate type uses the identifier
v1988 to give a default value of 0 for the version component:

Certificate ::= ...
  version Version DEFAULT v1988,
...

BER encoding. Primitive. Contents octets give the value of the integer, base 256, in two's 
complement form, most significant digit first, with the minimum number of octets. The value 0
is encoded as a single 00 octet.

Some example BER encodings (which also happen to be DER encodings) are given in Table 3.

Integer value       BER encoding
--------------------------------
0	                02 01 00
127	                02 01 7F
128	                02 02 00 80
256	                02 02 01 00
-128                02 01 80
-129                02 02 FF 7F

Table 3. Example BER encodings of INTEGER values.

DER encoding. Primitive. Contents octets are as for a primitive BER encoding.
*/
                var data = this.data.slice(this.pos, this.pos + length);
				var intVal = BigInt.fromBuffer(data);

				if (jCastle.util.isSafeInt(intVal)) {
					//intVal = parseInt(intVal.toString());
					intVal = Number(intVal);
				}
				this.pos += length;

				return {
					tagClass: tagClass,
					type: tag,
					_isAsn1: true,
					value: data.toString('latin1'),
					intVal: intVal,
					buffer: Buffer.slice(data)
				};

			case jCastle.asn1.tagBitString: // 0x03
/*
5.4 BIT STRING

The BIT STRING type denotes an arbitrary string of bits (ones and zeroes). A BIT STRING 
value can have any length, including zero. This type is a string type.
The BIT STRING type is used for digital signatures on extended certificates in PKCS #6's
ExtendedCertificate type, for digital signatures on certificates in X.509's Certificate
type, and for public keys in certificates in X.509's SubjectPublicKeyInfo type.

ASN.1 notation:

BIT STRING

Example: X.509's SubjectPublicKeyInfo type has a component of type BIT STRING:

SubjectPublicKeyInfo ::= SEQUENCE {
  algorithm AlgorithmIdentifier,
  publicKey BIT STRING }

BER encoding. Primitive or constructed. In a primitive encoding, the first contents octet
gives the number of bits by which the length of the bit string is less than the next 
multiple of eight (this is called the "number of unused bits"). The second and following
contents octets give the value of the bit string, converted to an octet string. The
conversion process is as follows:

The bit string is padded after the last bit with zero to seven bits of any value to make
the length of the bit string a multiple of eight. If the length of the bit string is a
multiple of eight already, no padding is done.
The padded bit string is divided into octets. The first eight bits of the padded bit
string become the first octet, bit 8 to bit 1, and so on through the last eight bits of
the padded bit string.
In a constructed encoding, the contents octets give the concatenation of the BER encodings
of consecutive substrings of the bit string, where each substring except the last has a 
length that is a multiple of eight bits.

Example: The BER encoding of the BIT STRING value "011011100101110111" can be any of the 
following, among others, depending on the choice of padding bits, the form of length
octets, and whether the encoding is primitive or constructed:

03 04 06 6e 5d c0                                     DER encoding
03 04 06 6e 5d e0                                     padded with "100000"
03 81 04 06 6e 5d c0                                  long form of length octets
23 09        
   03 03 00 6e 5d
   03 02 06 c0                                        constructed encoding:
                                                      "0110111001011101" + "11"

DER encoding. Primitive. The contents octects are as for a primitive BER encoding, except
that the bit string is padded with zero-valued bits.

Example: The DER encoding of the BIT STRING value "011011100101110111" is

03 04 06 6e 5d c0
*/
				var unused = 0, skip, data;
				var bitString = '';
				var encapsulated = false;
				var sub = null;

				if (constructed) {
                    data = this.data.slice(this.pos, this.pos + length);
					return this._parseConstructedValue(tagClass, tag, data);
				} else {
					unused = this.data[this.pos++];
					data = this.data.slice(this.pos, this.pos + length - 1);

					// 2016-11-10 if unused is greater than 0 then sub parsing is no need.
					if (!unused) {
						try {
							var asn1 = new jCastle.asn1();
							sub = asn1.parse(data, true);
							if (sub && !asn1.isFinish()) sub = null;
						} catch(e) {
							sub = null;
						}
					}

					if (!sub) {
						sub = data.toString('latin1');
						skip = 0;

						for (var i = 0; i <= data.length - 1; i++) {
							var b = data[i];
							if (i == data.length - 1) skip = unused;
							for (var j = 7; j >= skip; j--) {
								bitString += (b >>> j) & 1 ? "1" : "0";
							}
						}
					} else {
						encapsulated = true;
					}
				}

				this.pos += length - 1;

				var tagValue = {
					tagClass: tagClass,
					type: tag,
					_isAsn1: true,
					unused: unused,
					encapsulated: encapsulated,
					constructed: constructed,
					value: sub
				};

				if (!encapsulated) {
					tagValue.bitString = bitString;
				}

				if (encapsulated) tagValue.buffer = Buffer.slice(data);

				return tagValue;

			case jCastle.asn1.tagOctetString: // 0x04
/*
5.10 OCTET STRING

The OCTET STRING type denotes an arbitrary string of octets (eight-bit values). An OCTET
STRING value can have any length, including zero. This type is a string type.
The OCTET STRING type is used for salt values in PKCS #5's PBEParameter type, for message
digests, encrypted message digests, and encrypted content in PKCS #7, and for private keys
and encrypted private keys in PKCS #8.

ASN.1 notation:

OCTET STRING [SIZE ({size | size1..size2})]

where size, size1, and size2 are optional size constraints. In the OCTET STRING SIZE (size)
form, the octet string must have size octets. In the OCTET STRING SIZE (size1..size2) form,
the octet string must have between size1 and size2 octets. In the OCTET STRING form, the 
octet string can have any size.

Example: PKCS #5's PBEParameter type has a component of type OCTET STRING:

PBEParameter ::= SEQUENCE {
  salt OCTET STRING SIZE(8),
  iterationCount INTEGER }

Here the size of the salt component is always eight octets.

BER encoding. Primitive or constructed. In a primitive encoding, the contents octets give the
value of the octet string, first octet to last octet. In a constructed encoding, the contents
octets give the concatenation of the BER encodings of substrings of the OCTET STRING value.

Example: The BER encoding of the OCTET STRING value 01 23 45 67 89 ab cd ef can be any of the
following, among others, depending on the form of length octets and whether the encoding is
primitive or constructed:

04 08 01 23 45 67 89 ab cd ef                              DER encoding
04 81 08 01 23 45 67 89 ab cd ef                           long form of length octets
24 0c
   04 04 01 23 45 67
   04 04 89 ab cd ef                                       constructed encoding:
                                                           01 ... 67 + 89 ... ef

DER encoding. Primitive. Contents octets are as for a primitive BER encoding.

Example: The BER encoding of the OCTET STRING value 01 23 45 67 89 ab cd ef is

04 08 01 23 45 67 89 ab cd ef
*/
				var data = this.data.slice(this.pos, this.pos + length);
				var sub;
				var encapsulated = false;

				if (constructed) {
					return this._parseConstructedValue(tagClass, tag, data);
				} else {
					try {
						var asn1 = new jCastle.asn1();
						sub = asn1.parse(data, true);
						if (sub && !asn1.isFinish()) sub = null;
					} catch(e) {
						// console.log('have no sub structures');
						sub = null;
					}
					if (!sub) {
						sub = data.toString('latin1');
					} else {
						encapsulated = true;
					}
				}

				this.pos += length;

				var tagValue = {
					tagClass: tagClass,
					type: tag,
					_isAsn1: true,
					encapsulated: encapsulated,
					constructed: constructed,
					value: sub
				};

				if (encapsulated) tagValue.buffer = Buffer.slice(data);

				return tagValue;

			case jCastle.asn1.tagNull: // 0x05
/*
5.8 NULL

The NULL type denotes a null value.
The NULL type is used for algorithm parameters in several places in PKCS.

ASN.1 notation:

NULL

BER encoding. Primitive. Contents octets are empty.

Example: The BER encoding of a NULL value can be either of the following, as well as others, 
depending on the form of the length octets:

05 00

05 81 00

DER encoding. Primitive. Contents octets are empty; the DER encoding of a NULL value 
is always 05 00.
*/
				return {
					tagClass: tagClass,
					type: tag,
					_isAsn1: true,
					value: null
				};

			case jCastle.asn1.tagOID: //0x06
/*
5.9 OBJECT IDENTIFIER

The OBJECT IDENTIFIER type denotes an object identifier, a sequence of integer components
that identifies an object such as an algorithm, an attribute type, or perhaps a 
registration authority that defines other object identifiers. An OBJECT IDENTIFIER value
can have any number of components, and components can generally have any nonnegative value.
This type is a non-string type.

OBJECT IDENTIFIER values are given meanings by registration authorities. Each registration
authority is responsible for all sequences of components beginning with a given sequence.
A registration authority typically delegates responsibility for subsets of the sequences
in its domain to other registration authorities, or for particular types of object. There
are always at least two components.

The OBJECT IDENTIFIER type is used to identify content in PKCS #7's ContentInfo type, to
identify algorithms in X.509's AlgorithmIdentifier type, and to identify attributes in 
X.501's Attribute and AttributeValueAssertion types. The Attribute type is used by PKCS
#6, #7, #8, #9, and #10, and the AttributeValueAssertion type is used in X.501
distinguished names. OBJECT IDENTIFIER values are defined throughout PKCS.

ASN.1 notation:

OBJECT IDENTIFIER

The ASN.1 notation for values of the OBJECT IDENTIFIER type is

{ [identifier] component1 ... componentn }

componenti = identifieri | identifieri (valuei) | valuei

where identifier, identifier1, ..., identifiern are identifiers, and value1, ..., valuen
are optional integer values.

The form without identifier is the "complete" value with all its components; the form with 
identifier abbreviates the beginning components with another object identifier value. The 
identifiers identifier1, ..., identifiern are intended primarily for documentation, but 
they must correspond to the integer value when both are present. These identifiers can 
appear without integer values only if they are among a small set of identifiers defined in
X.208.

Example: The following values both refer to the object identifier assigned to RSA Data 
Security, Inc.:

{ iso(1) member-body(2) 840 113549 }
{ 1 2 840 113549 }
(In this example, which gives ASN.1 value notation, the object identifier values are decimal,
not hexadecimal.) Table 4 gives some other object identifier values and their meanings.

Object identifier value	Meaning
{ 1 2 }                                       ISO member bodies
{ 1 2 840 }                                   US (ANSI)
{ 1 2 840 113549 }                            RSA Data Security, Inc.
{ 1 2 840 113549 1 }                          RSA Data Security, Inc. PKCS
{ 2 5 }                                       directory services (X.500)
{ 2 5 8 }                                     directory services-algorithms

Table 4. Some object identifier values and their meanings.

BER encoding. Primitive. Contents octets are as follows, where value1, ..., valuen denote the
integer values of the components in the complete object identifier:

The first octet has value 40 * value1 + value2. (This is unambiguous, since value1 is limited
to values 0, 1, and 2; value2 is limited to the range 0 to 39 when value1 is 0 or 1; and, 
according to X.208, n is always at least 2.)

The following octets, if any, encode value3, ..., valuen. Each value is encoded base 128, most
significant digit first, with as few digits as possible, and the most significant bit of each 
octet except the last in the value's encoding set to "1."
Example: The first octet of the BER encoding of RSA Data Security, Inc.'s object identifier is
40 * 1 + 2 = 42 = 2a16. The encoding of 840 = 6 * 128 + 4816 is 86 48 and the encoding of 
113549 = 6 * 1282 + 7716 * 128 + d16 is 86 f7 0d. This leads to the following BER encoding:

06 06 2a 86 48 86 f7 0d

DER encoding. Primitive. Contents octets are as for a primitive BER encoding.
*/
				var oid = jCastle.asn1.fn.parseOID(this.data.slice(this.pos, this.pos + length).toString('latin1'));
				this.pos += length;

				return {
					tagClass: tagClass,
					type: tag,
					_isAsn1: true,
					value: oid
				};

			case jCastle.asn1.tagUTF8String: // 0x0c
                var data = this.data.slice(this.pos, this.pos + length);
                this.pos += length;

                if (constructed) {
                    return this._parseConstructedValue(tagClass, tag, data);
                }

                var tagValue = {
                    tagClass: tagClass,
                    type: tag,
                    _isAsn1: true,
                    constructed: constructed,
                    value: data.toString()
                };

                return tagValue;

			case jCastle.asn1.tagNumericString: // 0x12
			case jCastle.asn1.tagPrintableString: // 0x13
/*
5.11 PrintableString

The PrintableString type denotes an arbitrary string of printable characters from the
following character set:

A, B, ..., Z
a, b, ..., z
0, 1, ..., 9
(space) ' ( ) + , - . / : = ?

This type is a string type.

The PrintableString type is used in PKCS #9's challenge- password and unstructured-address
attributes, and in several X.521 distinguished names attributes.

ASN.1 notation:

PrintableString

BER encoding. Primitive or constructed. In a primitive encoding, the contents octets give 
the characters in the printable string, encoded in ASCII. In a constructed encoding, the 
contents octets give the concatenation of the BER encodings of consecutive substrings of
the string.

Example: The BER encoding of the PrintableString value "Test User 1" can be any of the 
following, among others, depending on the form of length octets and whether the encoding 
is primitive or constructed:

13 0b 54 65 73 74 20 55 73 65 72 20 31              DER encoding

13 81 0b
54 65 73 74 20 55 73 65 72 20 31                    long form of length octets

33 0f
   13 05 54 65 73 74 20
   13 06 55 73 65 72 20 31                          constructed encoding: "Test " + "User 1"

DER encoding. Primitive. Contents octets are as for a primitive BER encoding.

Example: The DER encoding of the PrintableString value "Test User 1" is

13 0b 54 65 73 74 20 55 73 65 72 20 31
*/
			case jCastle.asn1.tagT61String: // 0x14
/*
5.16 T61String

The T61String type denotes an arbtrary string of T.61 characters. T.61 is an eight-bit 
extension to the ASCII character set. Special "escape" sequences specify the interpretation
of subsequent character values as, for example, Japanese; the initial interpretation is 
Latin. The character set includes non-printing control characters. The T61String type allows
only the Latin and Japanese character interepretations, and implementors' agreements for 
directory names exclude control characters [NIST92]. A T61String value can have any length,
including zero. This type is a string type.
The T61String type is used in PKCS #9's unstructured-address and challenge-password 
attributes, and in several X.521 attributes.

ASN.1 notation:

T61String

BER encoding. Primitive or constructed. In a primitive encoding, the contents octets give the
characters in the T.61 string, encoded in ASCII. In a constructed encoding, the contents
octets give the concatenation of the BER encodings of consecutive substrings of the T.61 string.

Example: The BER encoding of the T61String value "cl'es publiques" (French for "public keys")
can be any of the following, among others, depending on the form of length octets and whether 
the encoding is primitive or constructed:

14 0f
   63 6c c2 65 73 20 70 75 62 6c 69 71 75 65 73                   DER encoding
14 81 0f
   63 6c c2 65 73 20 70 75 62 6c 69 71 75 65 73                   long form of length octets
34 15
   14 05 63 6c c2 65 73
   14 01 20
   14 09 70 75 62 6c 69 71 75 65 73                               constructed encoding: 
                                                                  "cl'es" + " " + "publiques"

The eight-bit character c2 is a T.61 prefix that adds an acute accent (') to the next character.

DER encoding. Primitive. Contents octets are as for a primitive BER encoding.

Example: The DER encoding of the T61String value "cl'es publiques" is

14 0f 63 6c c2 65 73 20 70 75 62 6c 69 71 75 65 73
*/
			case jCastle.asn1.tagIA5String: // 0x16
/*
5.6 IA5String

The IA5String type denotes an arbtrary string of IA5 characters. IA5 stands for International
Alphabet 5, which is the same as ASCII. The character set includes non- printing control 
characters. An IA5String value can have any length, including zero. This type is a string type.
The IA5String type is used in PKCS #9's electronic-mail address, unstructured-name, and
unstructured-address attributes.

ASN.1 notation:

IA5String

BER encoding. Primitive or constructed. In a primitive encoding, the contents octets give the 
characters in the IA5 string, encoded in ASCII. In a constructed encoding, the contents octets
give the concatenation of the BER encodings of consecutive substrings of the IA5 string.

Example: The BER encoding of the IA5String value "test1@rsa.com" can be any of the following,
among others, depending on the form of length octets and whether the encoding is primitive or 
constructed:

16 0d 74 65 73 74 31 40 72 73 61 2e 63 6f 6d                        DER encoding
16 81 0d
   74 65 73 74 31 40 72 73 61 2e 63 6f 6d                           long form of length octets
36 13
   16 05 74 65 73 74 31
   16 01 40
   16 07 72 73 61 2e 63 6f 6d                                       constructed encoding:
                                                                    "test1" + "@" + "rsa.com"

DER encoding. Primitive. Contents octets are as for a primitive BER encoding.

Example: The DER encoding of the IA5String value "test1@rsa.com" is

16 0d 74 65 73 74 31 40 72 73 61 2e 63 6f 6d
*/
			case jCastle.asn1.tagGraphicString: // 0x19
			case jCastle.asn1.tagVisibleString: // 0x1a
			case jCastle.asn1.tagGeneralString: // 0x1b
			case jCastle.asn1.tagUniversalString: // 0x1c
				var data = this.data.slice(this.pos, this.pos + length);
				this.pos += length;

				if (constructed) {
					return this._parseConstructedValue(tagClass, tag, data);
				}

				var tagValue = {
					tagClass: tagClass,
					type: tag,
					_isAsn1: true,
					constructed: constructed,
					value: data.toString('latin1')
				};

				return tagValue;

			case jCastle.asn1.tagBMPString: // 0x1e
				var data = this.data.slice(this.pos, this.pos + length);
				this.pos += length;

				if (constructed) {
					return this._parseConstructedValue(tagClass, tag, data);
				}

                var str = '';
                for (var i = 0; i < data.length; i += 2) {
                    str += String.fromCharCode((data[i] << 8) | data[i+1]);
                }

				var tagValue = {
					tagClass: tagClass,
					type: tag,
					_isAsn1: true,
					constructed: constructed,
                    value: str
				};

				return tagValue;

			case jCastle.asn1.tagUTCTime: // 0x17
			case jCastle.asn1.tagGeneralizedTime: // 0x18
/*
5.17 UTCTime

The UTCTime type denotes a "coordinated universal time" or Greenwich Mean Time (GMT) value.
A UTCTime value includes the local time precise to either minutes or seconds, and an offset
from GMT in hours and minutes. It takes any of the following forms:

YYMMDDhhmmZ
YYMMDDhhmm+hh'mm'
YYMMDDhhmm-hh'mm'
YYMMDDhhmmssZ
YYMMDDhhmmss+hh'mm'
YYMMDDhhmmss-hh'mm'

where:

YY is the least significant two digits of the year
MM is the month (01 to 12)

DD is the day (01 to 31)

hh is the hour (00 to 23)

mm are the minutes (00 to 59)

ss are the seconds (00 to 59)

Z indicates that local time is GMT, + indicates that local time is later than GMT, and - 
indicates that local time is earlier than GMT

hh' is the absolute value of the offset from GMT in hours

mm' is the absolute value of the offset from GMT in minutes

This type is a string type.

The UTCTime type is used for signing times in PKCS #9's signing-time attribute and for
certificate validity periods in X.509's Validity type.

ASN.1 notation:

UTCTime

BER encoding. Primitive or constructed. In a primitive encoding, the contents octets give 
the characters in the string, encoded in ASCII. In a constructed encoding, the contents 
octets give the concatenation of the BER encodings of consecutive substrings of the string.
(The constructed encoding is not particularly interesting, since UTCTime values are so 
short, but the constructed encoding is permitted.)

Example: The time this sentence was originally written was 4:45:40 p.m. Pacific Daylight 
Time on May 6, 1991, which can be represented with either of the following UTCTime values, 
among others:

"910506164540-0700"

"910506234540Z"

These values have the following BER encodings, among others:

17 0d 39 31 30 35 30 36 32 33 34 35 34 30 5a

17 11 39 31 30 35 30 36 31 36 34 35 34 30 2D 30 37 30 30

DER encoding. Primitive. Contents octets are as for a primitive BER encoding.
*/
				var data = this.data.slice(this.pos, this.pos + length).toString('latin1');
				var time = jCastle.asn1.fn.parseDateTime(tag, data);
				if (!time) return null;
				this.pos += length;

				return {
					tagClass: tagClass,
					type: tag,
					_isAsn1: true,
					value: time
				};

			case jCastle.asn1.tagReal: // 0x09
/*
Type REAL takes values that are the machine representation of a real number, namely the 
triplet (m, b, e), where m is the mantissa (a signed number), b the base (2 or 10), and
e the exponent (a signed number). For example, the representation of the value 3.14 for
the variable Pi, declared as Pi ::= REAL, can be (314, 10, -2). Three special values, 
PLUS-INFINITY, 0, and MINUS-INFINITY, are also allowed.
*/

			default:
				// console.log('tagClass: ', tagClass, ', tag: ', tag, ', length: ', length);
				throw jCastle.exception("UNKNOWN_TAG_TYPE", 'ASN009');
		}
	}
	/**
	 * get the asn1 DER buffer value from the given asn1 structured object.
	 * 
	 * @public
	 * 
	 * @param {object} obj a asn1 structured object. 
	 * @param {boolean} ber_encoding boolean flag for BER encoding.
	 * @returns the asn1 DER buffer value.
	 */
	getBuffer(obj, ber_encoding = false)
	{
		var der = this.getDER(obj, ber_encoding);
		return Buffer.from(der, 'latin1');
	}

	/**
	 * get the asn1 BER string value from the given asn1 structured object. 
	 * 
	 * @public
	 * 
	 * @param {object} obj a asn1 structured object.
	 * @returns the asn1 BER string value.
	 */
	getBER(obj)
	{
		return this.getDER(obj, true);
	}

	/**
	 * get the asn1 DER string value from the given asn1 structured object. 
	 * 
	 * @public
	 * 
	 * @param {object} obj a asn1 structured object.
	 * @returns the asn1 DER string value.
	 */
	getDER(obj, ber_encoding = false)
	{
		// if obj is der string or buffer then nothing to do. just return...
		if (jCastle.util.isString(obj)) return obj;
		if (Buffer.isBuffer(obj)) return obj.toString('latin1');

		var der;

		// normally obj has no tagClass. if no tagClass, then it is tagClassUniversal.
		// if it is not tagClassUniversal:
		if ('tagClass' in obj && obj.tagClass != jCastle.asn1.tagClassUniversal) {
			var tag = obj.type;
			tag |= obj.tagClass << 6;
			der = '';
			if (obj.constructed || obj.explicit) {
				tag |= 0x20;

				for (var i = 0; i < obj.items.length; i++) {
					der += this.getDER(obj.items[i], ber_encoding);
				}
			} else { // implicit
				if (typeof obj.value == 'number' || BigInt.is(obj.value)) {
					var intVal = BigInt(obj.value);
					der = Buffer.from(intVal.toBuffer()).toString('latin1');
				} else if (Buffer.isBuffer(obj.value)) {
					der = obj.value.toString('latin1');
				} else if (typeof obj.value == 'object' && '_isAsn1' in obj.value && obj.value._isAsn1) {
/*
https://ask.wireshark.org/questions/8277/difference-between-implicit-and-explicit-tags-asn1

When using BER (BASIC ENCODING RULES) or DER (DISTINGUISHED ENCODING RULES), data for types
are encoding using a Type-Length-Value format. Each primitive ASN.1 Type such as INTEGER has
a UNIVERSAL TAG assigned by the ASN.1 standard. If you have just

A ::= INTEGER

This has a tag of UNIVERSAL 2, so an encoding of the interger value 5 in BER would be in hex
02 01 05.

B ::= [2] IMPLICIT INTEGER

For B, with an implicit tag, this says to replace the existing tag on INTEGER with [2], so 
the encoding in BER of the value 5 would be in hex 
82 01 05.

C ::= [2] EXPLICIT INTEGER

For C, with an explicit tag, this says to add [2] in front of the existing tag, so the encoding
in BER of the value 5 would be in hex 
A2 03 02 01 05.

There is a free ASN.1 book you can download from 
http://www.oss.com/asn1/resources/books-whitepapers-pubs/asn1-books.html 
which explains tagging in much more detail.
*/
					/*
					var obj = {
						tagClass: jCastl.ASN1.tagClassContextSpecific,
						tag: 0x01,
						constructed: false,
						value: {
							tag: jCastle.asn1.tagOctetString,
							value: 'mail@to'
						}
					};
					*/
					der = this.getDER(obj.value, ber_encoding);
					var replace_tag = der.slice(0, 1);
					der = der.slice(1);

					return String.fromCharCode(tag) + der;					
				} else {
					der = Buffer.isBuffer(obj.value) ? obj.value.toString('latin1') : obj.value;
				} 
			}

			// BER in-definite length
			if ((obj.constructed || obj.explicit) && (ber_encoding || 'indefiniteLength' in obj && obj.indefiniteLength)) {
				return String.fromCharCode(tag) + '\x80' + der + '\x00\x00';
			}

			return String.fromCharCode(tag) + this._getLengthDER(der.length) + der;
		}

		// else: obj.tagClass is undefined or jCastle.asn1.tagClassUniversal

		switch (obj.type) {
			case jCastle.asn1.tagSequence:
			case jCastle.asn1.tagSet:
				der = '';
				for (var i = 0; i < obj.items.length; i++) {
					der += this.getDER(obj.items[i], ber_encoding);
				}

				if (ber_encoding || ('indefiniteLength' in obj && obj.indefiniteLength)) {
					return String.fromCharCode(obj.type | 0x20) + '\x80' + der + '\x00\x00';
				}

				return String.fromCharCode(obj.type | 0x20) + this._getLengthDER(der.length) + der;
				
			case jCastle.asn1.tagBoolean:
				return String.fromCharCode(obj.type) + this._getLengthDER(1) + (obj.value ? "\xff" : "\x00");

			case jCastle.asn1.tagEnumerated:
			case jCastle.asn1.tagInteger:
				var is_minus = false;
				var h;

				var value = 'intVal' in obj ? obj.intVal : obj.value;

/*
http://www.dreamincode.net/forums/topic/122557-how-to-convert-signed-decimal-to-hex/

Subject: How To Convert Signed Decimal To Hex?

Q:
It says to take the bits, reverse them and than add one. 

Such as if im given the decimal: -32
How do I get that to hex? 

A:
1. Represent 32 in binary, 00100000
2. Reverse the bits, 11011111
3. Add 1, 11100000
4. Represent the resulting binary in hex, E0

Edit: Just a sidenote, this procedure should only be performed on negative numbers. 
Positive numbers can be converted straight to hex without steps 2 and 3. This 
particular procedure is called two's complement. Other methods for representation 
of signed integers exist. 

A:
The actual way to Convert Signed Decimal to Hex is to convert the absolute value of
the Decimal to Hex then take the Twos Compliment of the Hex. If the MSB of the Hex 
is greater then 8 the the number is negative. I will explain how its done:

32/16 = Qoutient of 2 and Remainer of 0 (LSB)
2/16 = Qoutient of 0 and Remainer of 2 (MSB)
32 DEC = 20 HEX

Now we calulate the Two's Compliment be inversing each bit (subtract from 15) then ADD 1
F-2 = D, F-0 = F, DF + 1 = E0 
*/

/*
http://mathforum.org/library/drmath/view/55998.html

Converting Negative Decimals to Hexadecimal

Q:
I'm trying to find out the formula for converting a negative decimal 
number to a hexadecimal number.

Using calculators I can get any of the conversions like - 16 = F0, but 
what I really need to know is HOW to get to F0 from - .16

A:

That way of representing signed number is called "sixteen's 
complement" (the hexadecimal equivalent of two's complement in 
binary). Generally, sixteen's complement hexadecimal is used as a 
"shorthand notation" for two's complement signed binary numbers, 
therefore I think it is easier to understand when taken in two steps.

To find the sixteen's complement hexadecimal value, you would first 
convert the number to two's complement signed binary, then convert 
that binary value to hexadecimal.

To learn about two's complement, check out:

   Two's Complement
   http://mathforum.org/dr.math/problems/corbin.07.13.99.html   

   Negative Numbers in Binary
   http://mathforum.org/dr.math/problems/akella.8.19.99.html   

To learn about converting binary to hexadecimal, check out:

   Binary to Hexadecimal
   http://mathforum.org/dr.math/problems/hamilton12.8.98.html   

   Binary Conversion
   http://mathforum.org/dr.math/problems/stirling1.7.98.html   

   Converting Bases (bottom of the page)
   http://mathforum.org/dr.math/problems/reinhardt12.21.97.html   

all from our Ask Dr. Math archives.

Let's do an example. Suppose we want to find the hexadecimal 
representation of -53 (base 10). First, we convert 53 to binary:

                       1 1 0 1 0 1
                      / / / / / /
          0  r 1  ---+ / / / / /
        ----          / / / / /
      2 ) 1  r 1  ---+ / / / /
        ----          / / / /
      2 ) 3  r 0  ---+ / / /
        ----          / / /
      2 ) 6  r 1  ---+ / /
       -----          / /
     2 ) 13  r 0  ---+ /
       -----          /
     2 ) 26  r 1  ---+
       -----
     2 ) 53
        
So 53 (base 10) = 110101 (base 2). Next, we take the two's complement. 
We'll use 8-bit values (as in your example), so we have to fill the 
value to 8 bits by adding 2 leading zeroes on the left. Then invert 
the bits and add 1. We then have:

       00110101   (positive value)
           |
           v
       11001010   (invert)
     +        1   (add 1)
      ----------
       11001011   (two's complement negative result)

This is how -53 is represented in two's complement signed binary. The 
final step is to convert the binary to hexadecimal. We simply group 
the bits into groups of four, then convert each group to its 
hexadecimal equivalent, like so:

     1100 1011
     \__/ \__/
      12   11
       C    B

So -53 (base 10) = CB (signed hexadecimal using complements).
*/				

				if (typeof value == 'number' || BigInt.is(value)) {
					value = BigInt(value);

					h = value.toBuffer().toString('latin1');
				} else if (Buffer.isBuffer(value)) {
					h = value.toString('latin1');
				} else { // string
					if (/^[0-9A-Z]+$/i.test(value)) h = Buffer.from(value, 'hex').toString('latin1');
					else h = value;
				}
				
				return String.fromCharCode(obj.type) + this._getLengthDER(h.length) + h;

			case jCastle.asn1.tagBitString:
				if (obj.constructed) {
					return this._getConstructedStringDER(obj);
				}

				if (jCastle.util.isString(obj.value)) {
					der = obj.value;
				} else if (Buffer.isBuffer(obj.value)) {
					der = obj.value.toString('latin1');
				} else {
					der = this.getDER(obj.value, ber_encoding);
				}
				return String.fromCharCode(obj.type) + this._getLengthDER(der.length + 1) + 
					(typeof obj.unused == 'undefined' ? "\x00" : String.fromCharCode(obj.unused)) + der;

			case jCastle.asn1.tagOctetString:
				if (obj.constructed) {
					return this._getConstructedStringDER(obj);
				}

				if (jCastle.util.isString(obj.value)) {
					der = obj.value;
				} else if (Buffer.isBuffer(obj.value)) {
					der = obj.value.toString('latin1');
				} else {
					der = this.getDER(obj.value, ber_encoding);
				}
				return String.fromCharCode(obj.type) + this._getLengthDER(der.length) + der;

			case jCastle.asn1.tagNull:
				return String.fromCharCode(obj.type) + "\x00";

			case jCastle.asn1.tagOID:
				der = jCastle.asn1.fn.getOIDDER(obj.value);
				return String.fromCharCode(obj.type) + this._getLengthDER(der.length) + der;

			case jCastle.asn1.tagUTF8String:
				if (obj.constructed) {
					return this._getConstructedStringDER(obj);
				}

				if (jCastle.util.isString(obj.value)) {
                	der = Buffer.from(obj.value, 'utf8').toString('latin1');
				} else if (Buffer.isBuffer(obj.value)) {
					der = obj.value.toString('latin1');
				}
				return String.fromCharCode(obj.type) + this._getLengthDER(der.length) + der;

			case jCastle.asn1.tagNumericString:
			case jCastle.asn1.tagPrintableString:
			case jCastle.asn1.tagT61String:
			case jCastle.asn1.tagIA5String:
			case jCastle.asn1.tagGraphicString:
			case jCastle.asn1.tagVisibleString:
			case jCastle.asn1.tagGeneralString:
			case jCastle.asn1.tagUniversalString:
				if (obj.constructed) {
					return this._getConstructedStringDER(obj);
				}

				if (jCastle.util.isString(obj.value)) {
					der = Buffer.from(obj.value, 'latin1').toString('latin1');
				} else if (Buffer.isBuffer(obj.value)) {
					der = obj.value.toString('latin1');
				}
				return String.fromCharCode(obj.type) + this._getLengthDER(der.length) + der;

			case jCastle.asn1.tagBMPString:
				if (obj.constructed) {
					return this._getConstructedStringDER(obj);
				}

				var str;
				if (Buffer.isBuffer(obj.value)) {
					str = obj.value.toString();
				} else {
					str = obj.value;
				}

				der = '';
				for (var i = 0; i < str.length; i++) {
					var c = str.charCodeAt(i);
					der += String.fromCharCode((c >>> 8) & 0xff, c & 0xff);
				}

				return String.fromCharCode(obj.type) + this._getLengthDER(der.length) + der;

			case jCastle.asn1.tagUTCTime:
			case jCastle.asn1.tagGeneralizedTime:
				if (obj.value instanceof Date || !obj.value.match(/^[0-9]+Z/g)) {
					der = jCastle.asn1.fn.formatDateTime(obj.value, obj.type);
				} else {
					der = obj.value;
				}
				return String.fromCharCode(obj.type) + this._getLengthDER(der.length) + der;

			case jCastle.asn1.tagEOC: // end-of-content
				return '\x00';

			case jCastle.asn1.tagReal:
/*
http://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf

8.5 Encoding of a real value
============================

8.5.1 The encoding of a real value shall be primitive.

8.5.2 If the real value is the value zero, there shall be no contents octets in the encoding.

8.5.3 For a non-zero real value, if the base of the abstract value is 10, then the base of
      the encoded value shall be 10, and if the base of the abstract value is 2 the base of the 
      encoded value shall be 2, 8 or 16 as a sender's option.

8.5.4 If the real value is non-zero, then the base used for the encoding shall be B' as
      specified in 8.5.3. If B' is 2, 8 or 16, a binary encoding, specified in 8.5.6, shall be
      used. If B' is 10, a character encoding, specified in 8.5.7, shall be used.

8.5.5 Bit 8 of the first contents octet shall be set as follows:

      a) if bit 8 = 1, then the binary encoding specified in 8.5.6 applies;
      b) if bit 8 = 0 and bit 7 = 0, then the decimal encoding specified in 8.5.7 applies;
      c) if bit 8 = 0 and bit 7 = 1, then a "SpecialRealValue" 
         (see ITU-T Rec. X.680 | ISO/IEC 8824-1) is encoded as specified in 8.5.8.

8.5.6 When binary encoding is used (bit 8 = 1), then if the mantissa M is non-zero, it shall
      be represented by a sign S, a positive integer value N and a binary scaling factor F, 
	  such that:

      M = S × N × 2^F
      0 ≤ F < 4
      S = +1 or –1

NOTE – The binary scaling factor F is required under certain circumstances in order to align 
       the implied point of the mantissa to the position required by the encoding rules of 
	   this subclause. This alignment cannot always be achieved by modification of the
       exponent E. If the base B' used for encoding is 8 or 16, the implied point can only 
	   be moved in steps of 3 or 4 bits, respectively, by changing the component E. 
	   Therefore, values of the binary scaling factor F other than zero may be required 
	   in order to move the implied point to the required position.

8.5.6.1 Bit 7 of the first contents octets shall be 1 if S is –1 and 0 otherwise.

8.5.6.2 Bits 6 to 5 of the first contents octets shall encode the value of the base B' as 
        follows:

        Bits 6 to 5       Base
		-----------       ----
        00                base 2
        01                base 8
        10                base 16
        11                Reserved for further editions of this Recommendation | International 
		                  Standard. 

8.5.6.3 Bits 4 to 3 of the first contents octet shall encode the value of the binary scaling 
        factor F as an unsigned binary integer.

8.5.6.4 Bits 2 to 1 of the first contents octet shall encode the format of the exponent as 
        follows:

        a) if bits 2 to 1 are 00, then the second contents octet encodes the value of the 
		   exponent as a two's complement binary number;
        b) if bits 2 to 1 are 01, then the second and third contents octets encode the value
		   of the exponent as a two's complement binary number;
        c) if bits 2 to 1 are 10, then the second, third and fourth contents octets encode 
		   the value of the exponent as a two's complement binary number;
        d) if bits 2 to 1 are 11, then the second contents octet encodes the number of octets,
		   X say, (as an unsigned binary number) used to encode the value of the exponent, 
		   and the third up to the (X plus 3)th (inclusive) contents octets encode the value 
		   of the exponent as a two's complement binary number; the value of X shall be at least
		   one; the first nine bits of the transmitted exponent shall not be all zeros or 
		   all ones.

8.5.6.5 The remaining contents octets encode the value of the integer N (see 8.5.6) as 
        an unsigned binary number.

NOTE 1 – For non-canonical BER there is no requirement for floating point normalization of 
         the mantissa. This allows an implementor to transmit octets containing the mantissa 
		 without performing shift functions on the mantissa in memory. In the Canonical Encoding
		 Rules and the Distinguished Encoding Rules normalization is specified and the mantissa
		 (unless it is 0) needs to be repeatedly shifted until the least significant bit is a 1.

NOTE 2 – This representation of real numbers is very different from the formats normally used in
         floating point hardware, but has been designed to be easily converted to and from such 
		 formats (see Annex C).

8.5.7 When decimal encoding is used (bits 8 to 7 = 00), all the contents octets following 
      the first contents octet form a field, as the term is used in ISO 6093, of a length 
	  chosen by the sender, and encoded according to ISO 6093. The choice of ISO 6093 number
	  representation is specified by bits 6 to 1 of the first contents octet as follows:

      Bits 6 to 1         Number representation
	  -----------         ---------------------
      00 0001             ISO 6093 NR1 form
      00 0010             ISO 6093 NR2 form
      00 0011             ISO 6093 NR3 form

      The remaining values of bits 6 to 1 are reserved for further edition of this Recommendation
	  | International Standard. There shall be no use of scaling factors specified in accompanying 
      documentation (see ISO 6093).

NOTE 1 – The recommendations in ISO 6093 concerning the use of at least one digit to the left of
         the decimal mark are also recommended in this Recommendation | International Standard, 
		 but are not mandatory.

NOTE 2 – Use of the normalized form (see ISO 6093) is a sender's option, and has no significance.

8.5.8 When "SpecialRealValues" are to be encoded (bits 8 to 7 = 01), there shall be only one 
      contents octet, with values as follows:

      01000000            Value is PLUS-INFINITY
      01000001            Value is MINUS-INFINITY

      All other values having bits 8 and 7 equal to 0 and 1 respectively are reserved for addenda 
	  to this Recommendation | International Standard. 
*/
			default:
				// console.log(obj);
				throw jCastle.exception("UNKNOWN_TAG_TYPE", 'ASN010');
		}
	}

	/**
	 * gets DER string value of the length.
	 * @private
	 * 
	 * @param {integer} length the langth value input.
	 * 
	 * @returns the length DER string.
	 */
	_getLengthDER(length)
	{
		if (length <= 0x7f) return String.fromCharCode(length);

		var res = '', size = 0;

		while (length) {
			res = String.fromCharCode(length & 0xff) + res;
			length >>>= 8;
			size++;
		}

		return String.fromCharCode(size | 0x80) + res;
	}

	/**
	 * parses the constructed data.
	 * 
	 * @param {integer} tagClass tagClass value.
	 * @param {integer} tag tag value.
	 * @param {buffer} data data buffer.
	 * 
	 * @returns the asn1 structrued object.
	 */
	_parseConstructedValue(tagClass, tag, data)
	{
			var asn1 = new jCastle.asn1();
			var obj;
			var value = '', linebreak = 0;
			var finish = false;
			var unused = 0;
			var bitString = '';

		try {
			while (!finish) {
				obj = asn1.parse(data);
				value += obj.value;

				if (!linebreak) {
					switch (tag) {
						case jCastle.asn1.tagBitString:
						case jCastle.asn1.tagOctetString:
							linebreak = obj.value.length;
							break;
						case jCastle.asn1.tagUTF8String:
							linebreak = Buffer.from(obj.valuea).length;
							break;
						case jCastle.asn1.tagBMPString:
							linebreak = obj.value.length * 2;
							break;
						default:
							linebreak = Buffer.from(obj.value).length;
							break;
					}
				}
				data = data.slice(asn1.pos);
				finish = asn1.isFinish();

				if (tag == jCastle.asn1.tagBitString) {
					if (obj.unused) unused = obj.unused;
					bitString += obj.bitString;
				}
			}
		} catch(e) {
			// console.log(e.message);
			throw jCastle.exception('INVALID_ASN1', 'ASN011');
		}

		if (tag == jCastle.asn1.tagBMPString) {
			var str = '';
			for (var i = 0; i < value.length; i += 2) {
				str += String.fromCharCode((value.charCodeAt(i) << 8) | value.charCodeAt(i+1));
			}
			value = str;
		}

		var tagValue = {
			tagClass: tagClass,
			type: tag,
			constructed: true,
			value: value,
			_isAsn1: true,
			linebreak: linebreak
		};

		if (tag == jCastle.asn1.tagBitString) {
			tagValue.unused = unused;
			tagValue.bitString = bitString;
		}

		return tagValue;
	}

	/**
	 * get constructed DER from the asn1 structured object.
	 * 
	 * @private
	 * 
	 * @param {object} obj asn1 structured object.
	 * 
	 * @returns the constructed DER string.
	 */
	_getConstructedStringDER(obj)
	{
		var data, length;
		//var linebreak = obj.linebreak ? obj.linebreak : 1024;
		var linebreak = obj.linebreak ? obj.linebreak : this.linebreak;
		var der = '', skip = 0, tmp;

		switch (obj.type) {
			case jCastle.asn1.tagBitString:
			case jCastle.asn1.tagOctetString:
				data = obj.value;
				break;
			case jCastle.asn1.tagUTF8String:
				data = Buffer.from(obj.value).toString('latin1');
				break;
			case jCastle.asn1.tagBMPString:
				data = Buffer.toBmpString(Buffer.from(obj.value), 'latin1');
				break;
			default:
				data = Buffer.from(obj.value).toString('latin1');
				break;
		}

		length = data.length;

		while (length) {
			if (obj.type == jCastle.asn1.tagBitString) {
				if (length <= linebreak) skip = 'unused' in obj ? obj.unused : 0;
				tmp = String.fromCharCode(skip) + data.slice(0, linebreak);
			} else {
				tmp = data.slice(0, linebreak);
			}
			der += String.fromCharCode(obj.type) + this._getLengthDER(tmp.length) + tmp;

			data = data.slice(linebreak);
			length = data.length;
		}

		return String.fromCharCode(0x20 | obj.type) + this._getLengthDER(der.length) + der;
	}
};

/**
 * create a new asn1 objet.
 * 
 * @public
 * 
 * @returns a new asn1 object.
 */
jCastle.asn1.create = function()
{
	return new jCastle.asn1();
};

/**
 * parse the buffer data.
 * 
 * @public
 * 
 * @param {buffer} data DER buffer or string.
 * 
 * @returns the asn1 structured object.
 */
jCastle.asn1.parse = function(data)
{
	return new jCastle.asn1().parse(data);
};

/**
 * get DER string from schema (asn1 structured object).
 * 
 * @public
 * 
 * @param {object} schema asn1 structured object
 * 
 * @returns the DER string.
 */
jCastle.asn1.getDER = function(schema)
{
	return new jCastle.asn1().getDER(schema);
};

/**
 * checks object whether it is asn1 sequence object.
 * 
 * @public
 * 
 * @param {object} obj asn1 strucured object 
 * 
 * @returns true if it is asn1 sequence object.
 */
jCastle.asn1.isSequence = function(obj)
{
	if (typeof obj == 'object' &&
	 '_isAsn1' in obj &&
	  'type' in obj && obj.type === jCastle.asn1.tagSequence)
		return true;
	return false;
};

/*
// simple checker
jCastle.asn1.isAsn1Format = function(data)
{
	var cdata;

	if (Buffer.isBuffer(data)) {
		cdata = data;
	} else {
		cdata = Buffer.from(data, 'latin1');
	}

	var pos = 0;

	var tag_octet = cdata[pos++];
	var len = cdata[pos++];
	var size;
	var indefinite_length = false;

	if (len & 0x80) {
		var size = len & 0x7F;

		if (size == 0) {
			len = -1;
			indefinite_length = true;

		// if size is greater than 4 then the data is too big for javascript's handling.
		} else if (size > 4) {
			return false;
		} else {
			if (typeof cdata[pos+size-1] == 'undefined') return false;
			var length = parseInt(cdata.slice(pos, pos + size).toString('hex'), 16);
			if (length < 0) return false;
			pos += size;

			len = length;
		}
	}

	if (indefinite_length == false && len == cdata.length - pos) return true;
	if (indefinite_length === true && cdata[cdata.length-1] == 0x00 && cdata[cdata.length-2] == 0x00) return true;

	return false;
};
*/

/**
 * simple parser for asn1 DER string or not.
 * 
 * @public
 * 
 * @param {buffer} data data to be parsed.
 * @param {integer} cur_pos indicator of the current position.
 * @param {integer} eoc_level eoc level. default value is 0.
 * 
 * @returns true if it is asn1 DER string or buffer.
 */
jCastle.asn1.isAsn1Format = function(data, cur_pos = 0, eoc_level = 0)
{
    if (!Buffer.isBuffer(data)) data = Buffer.from(data, 'latin1');

    if (data.length == 0) return 0;

    var data_len = data.length;

    var tag_octet = data[cur_pos++];
    var len = data[cur_pos++];
    var size;
    var indefinite_length = false;
    var tagClass = tag_octet >>> 6;
    var tagType = tag_octet & 0x1f; // 0x1f & 0x20 for constructed
    var constructed = tag_octet & 0x20;

    // get length
    if (len & 0x80) {
        var size = len & 0x7F;

        if (size == 0) {
            len = -1;
            indefinite_length = true;

        // if size is greater than 4 then the data is too big for javascript's handling.
        } else if (size > 4) {
            return 0;
        } else {
            if (typeof data[cur_pos+size-1] == 'undefined') return 0;
            var length = parseInt(data.slice(cur_pos, cur_pos + size).toString('hex'), 16);
            if (length < 0) return 0;
            cur_pos += size;

            len = length;
        }
    }

    var end_pos = indefinite_length ? data_len : cur_pos + len;

    if (constructed) {
        while (cur_pos < end_pos) {
            cur_pos = jCastle.asn1.isAsn1Format(data, cur_pos, eoc_level+1);
            if (cur_pos == 0) return 0;
    
            if (indefinite_length) {
                if (data[cur_pos] == 0x00 && data[cur_pos+1] == 0x00) {
                    cur_pos += 2;
                    break;    
                }
            }
        }

        if (eoc_level) {
            if (indefinite_length) {
                return cur_pos;
            } else {
                if (cur_pos != end_pos) return 0;
                return end_pos;
            }
        } else {
            if (cur_pos !== data_len) return 0;
            return data_len;
        }
    } else {
        if (indefinite_length) return 0;

        if (eoc_level) {
            return cur_pos + len;
        } else {
            if (cur_pos + len == data_len) return data_len;
            else return 0;
        }
    }
};

/*
http://luca.ntop.org/Teaching/Appunti/asn1.html

Abstract Syntax Notation One, abbreviated ASN.1, is a notation for describing
abstract types and values. In ASN.1, a type is a set of values. For some types,
there are a finite number of values, and for other types there are an infinite 
number. A value of a given ASN.1 type is an element of the type's set. 
ASN.1 has four kinds of type: simple types, which are "atomic" and have no
components; structured types, which have components; tagged types, which are
derived from other types; and other types, which include the CHOICE type and 
the ANY type. Types and values can be given names with the ASN.1 assignment
operator (::=) , and those names can be used in defining other types and values.

Every ASN.1 type other than CHOICE and ANY has a tag, which consists of a class
and a nonnegative tag number. ASN.1 types are abstractly the same if and only if
their tag numbers are the same. In other words, the name of an ASN.1 type does 
not affect its abstract meaning, only the tag does. There are four classes of tag:

    1. Universal, for types whose meaning is the same in all applications;
	   these types are only defined in X.208.

    2. Application, for types whose meaning is specific to an application, such
	   as X.500 directory services; types in two different applications may have
	   the same application-specific tag and different meanings.

    3. Private, for types whose meaning is specific to a given enterprise.

    4. Context-specific, for types whose meaning is specific to a given structured
	   type; context-specific tags are used to distinguish between component types 
	   with the same underlying tag within the context of a given structured type, 
	   and component types in two different structured types may have the same tag
	   and different meanings.

The types with universal tags are defined in X.208, which also gives the types'
universal tag numbers. Types with other tags are defined in many places, and are 
always obtained by implicit or explicit tagging (see Section 2.3). 
Table 1 lists some ASN.1 types and their universal-class tags.

+--------------------+-------------+---------------+
|       Type         | Tag number  | Tag number    |
|                    | (decimal)   | (hexadecimal) |
+--------------------+-------------+---------------+
| INTEGER            | 2           | 02            |
+--------------------+-------------+---------------+
| BIT STRING         | 3           | 03            |
+--------------------+-------------+---------------+
| OCTET STRING       | 4           | 04            |
+--------------------+-------------+---------------+
| NULL               | 5           | 05            |
+--------------------+-------------+---------------+
| OBJECT IDENTIFIER  | 6           | 06            |
+--------------------+-------------+---------------+
| UTF8String         | 12          | 0C            |
+--------------------+-------------+---------------+
| SEQUENCE and       |             |               |
| SEQUENCE OF        | 16          | 10            |
+--------------------+-------------+---------------+
| SET and            |             |               |
| SET OF             | 17          | 11            |
+--------------------+-------------+---------------+
| PrintableString    | 19          | 13            |
+--------------------+-------------+---------------+
| T61String          | 20          | 14            |
+--------------------+-------------+---------------+
| IA5String          | 22          | 16            |
+--------------------+-------------+---------------+
| UTCTime            | 23          | 17            |
+--------------------+-------------+---------------+
| VisibleString      | 26          | la            |
+--------------------+-------------+---------------+
| GeneralString      | 27          | 1b            |
+--------------------+-------------+---------------+
| UniversalString    | 28          | 1c            |
+--------------------+-------------+---------------+
| BMPString          | 30          | 1e            |
+--------------------+-------------+---------------+
*/

// class
jCastle.asn1.tagClassUniversal			= 0x00;			// 0000 0000  -- 0x00
jCastle.asn1.tagClassApplication		= 0x01;			// 0100 0000  -- 0x40
jCastle.asn1.tagClassContextSpecific	= 0x02;			// 1000 0000  -- 0x80
jCastle.asn1.tagClassPrivate			= 0x03;			// 1100 0000  -- 0xc0

// primitive
jCastle.asn1.tagEOC						= 0x00; // end-of-content
jCastle.asn1.tagBoolean					= 0x01;
jCastle.asn1.tagInteger					= 0x02;
jCastle.asn1.tagBitString				= 0x03;
jCastle.asn1.tagOctetString				= 0x04;
jCastle.asn1.tagNull					= 0x05;
jCastle.asn1.tagOID						= 0x06;
jCastle.asn1.tagReal					= 0x09;
jCastle.asn1.tagEnumerated				= 0x0a;
jCastle.asn1.tagUTF8String				= 0x0c;
jCastle.asn1.tagSequence				= 0x10; // constructed
jCastle.asn1.tagSet						= 0x11; // constructed
jCastle.asn1.tagNumericString			= 0x12;
jCastle.asn1.tagPrintableString			= 0x13;
jCastle.asn1.tagT61String				= 0x14; // TeletexString
jCastle.asn1.tagIA5String				= 0x16; // same with ASCII
jCastle.asn1.tagGraphicString			= 0x19;
jCastle.asn1.tagVisibleString			= 0x1a; // ASCII subset
jCastle.asn1.tagGeneralString			= 0x1b;
jCastle.asn1.tagUniversalString			= 0x1c;
jCastle.asn1.tagBMPString				= 0x1e;
jCastle.asn1.tagUTCTime					= 0x17;
jCastle.asn1.tagGeneralizedTime			= 0x18;

jCastle.asn1.tagDer						= 0xFF;

jCastle.asn1.fn = {};


jCastle.asn1.fn.shortTimeRegex =     /^(\d\d)(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])([01]\d|2[0-3])(?:([0-5]\d)(?:([0-5]\d)(?:[.,](\d{1,3}))?)?)?(Z|[-+](?:[0]\d|1[0-2])([0-5]\d)?)?$/;

jCastle.asn1.fn.longTimeRegex = /^(\d\d\d\d)(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])([01]\d|2[0-3])(?:([0-5]\d)(?:([0-5]\d)(?:[.,](\d{1,3}))?)?)?(Z|[-+](?:[0]\d|1[0-2])([0-5]\d)?)?$/;

jCastle.asn1.fn.formatTimeRegex = /^(\d\d\d\d)\-(0[1-9]|1[0-2])\-(0[1-9]|[12]\d|3[01])(?:[ ]([01]\d|2[0-3])\:([0-5]\d)\:([0-5]\d)(?:[ ](UTC|GMT))?)?$/;

jCastle.asn1.fn.getOIDDER = function(oid)
{
	var tmp = oid.split('.');
				
	if (tmp.length < 2 || tmp[0] > 6 || tmp[1] >= 40) {
		throw jCastle.exception("INVALID_OID", 'ASN012');
	}

	var der = [parseInt(tmp[0])*40 + parseInt(tmp[1])];
	for (var i = 2; i < tmp.length; i++) {
		var x = parseInt(tmp[i]);
		if (x == 0) {
			der.push(0);
		} else {
			var octets = [];
			while (x != 0) {
				var v = x & 0x7f;
				if (octets.length > 0) {
					v |= 0x80;
				}
				octets.push(v);
				x >>>= 7;
			}
			octets.reverse();
			der = der.concat(octets);
		}
	}

	return Buffer.from(der).toString('latin1');
};

jCastle.asn1.fn.parseOID = function(data)
{
	var res = [];
	var d0 = data.charCodeAt(0);
//	var d0 = data[0];
	res.push(Math.floor(d0 / 40));
	res.push(d0 - res[0] * 40);
	var stack = [];
	var powNum = 0;

	for(var i = 1; i < data.length; i++) {
		var token = data.charCodeAt(i);
//		var token = data[i];

		stack.push(token & 127);
		if ( token & 128 ) {
			powNum++;
		} else {
			var sum = 0, j;

			for(var j = 0; j < stack.length; j++) {
				sum += stack[j] * Math.pow(128, powNum--);
			}
			res.push(sum);
			powNum = 0;
			stack = [];
		}
	}
		
	return res.join(".");
};

jCastle.asn1.fn.parseDateTime = function(tag, timestamp)
{
	var s, m = (tag == jCastle.asn1.tagUTCTime ? jCastle.asn1.fn.shortTimeRegex : jCastle.asn1.fn.longTimeRegex).exec(timestamp);
	if (!m) {
		throw jCastle.exception("UNRECOGIZED_TIME", 'ASN013');
	}
	if (tag == jCastle.asn1.tagUTCTime) { // short year
		// to avoid querying the timer, use the fixed range [1970, 2069]
		// it will conform with ITU X.400 [-10, +40] sliding window until 2030
		//m[1] = +m[1];
		m[1] = parseInt(m[1]);
		m[1] += (m[1] < 70) ? 2000 : 1900;
	}
	s = m[1] + "-" + m[2] + "-" + m[3] + " " + m[4];
	if (m[5]) {
		s += ":" + m[5];
		if (m[6]) {
			s += ":" + m[6];
			if (m[7])
				s += "." + m[7];
		}
	}
	if (m[8]) {
		s += " UTC";
		if (m[8] != 'Z') {
			s += m[8];
			if (m[9])
				s += ":" + m[9];
		}
	}
	return s;
};

jCastle.asn1.fn.str2date = function(str)
{
	var year, month, day, hour, minute, second, d;
	var m = jCastle.asn1.fn.formatTimeRegex.exec(str);

	if (!m) {
		d = new Date(str);
	} else {
		year = m[1];
		month = m[2];
		day = m[3];
		if (m[4]) {
			hour = m[4];
			minute = m[5];
			second = m[6];
		} else {
			hour = minute = second = 0;
		}
		if (m[7]) {
			d = new Date(Date.UTC(year, month-1, day, hour, minute, second));
		} else {
			d = new Date(year, month-1, day, hour, minute, second);
		}
	}
	return d;
};

jCastle.asn1.fn.formatDateTime = function(year, month, day, hour, minute, second, type)
{
	// change normal date and time to utc cercificate time format
	// YYYYMMDDHHMMSSZ
	var d;

	try {
		if (typeof second != 'undefined') {
			d = new Date(year, month, day, hour, minute, second);
			type = type || jCastle.asn1.tagGeneralizedTime;
		} else if (year instanceof Date) {
			d = year;
			type = month || jCastle.asn1.tagGeneralizedTime;
		} else {
/*
Date(): With this you call a function called Date(). It accepts date in format "yyyy-mm-dd hh:mm:ss"
new Date(): With this you're creating a new instance of Date.

You can use only the following constructors:

    new Date() // current date and time
    new Date(milliseconds) //milliseconds since 1970/01/01
    new Date(dateString)
    new Date(year, month, day, hours, minutes, seconds, milliseconds)

So, use 2010-08-17 12:09:36 as parameter to constructor is not allowed.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

See w3schools.

new Date(dateString) uses one of these formats:

    "October 13, 1975 11:13:00"
    "October 13, 1975 11:13"
    "October 13, 1975"
*/
			type = month || jCastle.asn1.tagGeneralizedTime;
			d = jCastle.asn1.fn.str2date(year);
		}
	// console.log(d);
	} catch (e) {
		throw e;
	}

	year = (type == jCastle.asn1.tagGeneralizedTime) ?
		d.getUTCFullYear().toString() : d.getUTCFullYear().toString().substr(2,2);

	month = (d.getUTCMonth() + 1).toString(); // getMonth : 0~11
	month = month.length == 1 ? '0' + month : month;

	day = d.getUTCDate().toString();
	day = day.length == 1 ? '0' + day : day;

	hour = d.getUTCHours().toString();
	hour = hour.length == 1 ? '0' + hour : hour;

	minute = d.getUTCMinutes().toString();
	minute = minute.length == 1 ? '0' + minute : minute;

	second = d.getUTCSeconds().toString();
	second = second.length == 1 ? '0' + second : second;

	return year + month + day + hour + minute + second + 'Z';
};

jCastle.asn1.rasterize =
jCastle.asn1.rasterizeSchema = function(schema)
{
	if (jCastle.util.isString(schema)) {
		try {
			schema = new jCastle.asn1().parse(schema);
		} catch (e) {
			throw jCastle.exception('INVALID_ASN1', 'ASN014');
		}
	}

	//var result = Object.assign({}, schema);
    var result = jCastle.util.clone(schema);

	if ('der' in result) result.der = Buffer.from(result.der, 'latin1').toString('hex');

	switch (result.tagClass) {
		case jCastle.asn1.tagClassUniversal:
			switch (result.type) {
				case jCastle.asn1.tagBoolean:
					result.type = 'BOOLEAN';
					break;
				case jCastle.asn1.tagInteger: 
					result.value = result.intVal;
					result.type = 'INTEGER';
					if ('buffer' in result) result.buffer = result.buffer.toString('hex');
					break;

				case jCastle.asn1.tagBitString:
					if (jCastle.asn1.isSequence(result.value)) {
						result.value = jCastle.asn1.rasterizeSchema(result.value);
					} else {
						result.value = Buffer.from(result.value, 'latin1').toString('hex');
					}
					result.type = 'BIT STRING';
					break;
				case jCastle.asn1.tagOctetString:
					if (jCastle.asn1.isSequence(result.value)) {
						result.value = jCastle.asn1.rasterizeSchema(result.value);
					}
					result.type = 'OCTET STRING';
					break;
				case jCastle.asn1.tagNull:
					result.type = 'NULL';
					break;
				case jCastle.asn1.tagOID:
					result.type = 'OID';
					var name = jCastle.OID.getName(result.value);
					if (name) result.value += '(' + name + ')';
					break;
				case jCastle.asn1.tagReal:
					result.value = Buffer.from(result.value, 'latin1').toString('hex');
					result.type = 'REAL';
					break;
				case jCastle.asn1.tagEnumerated:
					result.value = result.intVal;
					result.type = 'ENUMERATED';
					if ('buffer' in result) result.buffer = result.buffer.toString('hex');
					break;					
				case jCastle.asn1.tagUTF8String:
					result.type = 'UTF8 STRING';
					break;
				case jCastle.asn1.tagNumericString:
					result.type = 'NUMERIC STRING';
					break;
				case jCastle.asn1.tagPrintableString:
					result.type = 'PRINTABLE STRING';
					break;
				case jCastle.asn1.tagT61String:
					result.type = 'T61 STRING';
					break;
				case jCastle.asn1.tagIA5String:
					result.type = 'IA5 STRING';
					break;
				case jCastle.asn1.tagGraphicString:
					result.type = 'GRAPHIC STRING';
					break;
				case jCastle.asn1.tagVisibleString:
					result.type = 'VISIBLE STRING';
					break;
				case jCastle.asn1.tagGeneralString:
					result.type = 'GENERAL STRING';
					break;
				case jCastle.asn1.tagUniversalString:
					result.type = 'UNIVERSAL STRING';
					break;
				case jCastle.asn1.tagBMPString:
					result.type = 'BMP STRING';
					break;
				case jCastle.asn1.tagUTCTime:
					result.type = 'UTC TIME';
					break;
				case jCastle.asn1.tagGeneralizedTime:
					result.type = 'GENERALIZED TIME';
					break;
				case jCastle.asn1.tagSequence:
					result.type = 'SEQUENCE';
					result.items = jCastle.asn1._rasterizeItemSchema(result.items);
					if ('buffer' in result) result.buffer = result.buffer.toString('hex');
					break;
				case jCastle.asn1.tagSet:
					result.type = 'SET';
					result.items = jCastle.asn1._rasterizeItemSchema(result.items);
					if ('buffer' in result) result.buffer = result.buffer.toString('hex');
					break;
			}
			result.tagClass = 'Universal';
			break;
		case jCastle.asn1.tagClassApplication:
			result.value = Buffer.from(result.value, 'latin1').toString('hex');
			result.tagClass = 'Application';
			if ('buffer' in result) result.buffer = result.buffer.toString('hex');
			break;
		case jCastle.asn1.tagClassContextSpecific:
			if (result.constructed) {
				result.items = jCastle.asn1._rasterizeItemSchema(result.items);
			} else {
				result.value = Buffer.from(result.value, 'latin1').toString('hex');
			}
			result.tagClass = 'Context Specific';
			if ('buffer' in result) result.buffer = result.buffer.toString('hex');
			break;
		case jCastle.asn1.tagClassPrivate:
			result.value = Buffer.from(result.value, 'latin1').toString('hex');
			result.tagClass = 'Private';
			if ('buffer' in result) result.buffer = result.buffer.toString('hex');
			break;
		default:
			throw "Unknown tag class";

	}

	return result;
};

jCastle.asn1._rasterizeItemSchema = function(arr)
{
	//var result = Object.assign({}, arr);
    var result = jCastle.util.clone(arr);

	for (var i = 0; i < result.length; i++) {
		result[i] = jCastle.asn1.rasterizeSchema(result[i]);
	}

	return result;
};

jCastle.ASN1 = jCastle.asn1;

module.exports = jCastle.asn1;

/*
PEM Sample:

http://fm4dd.com/openssl/certexamples.htm
http://csrc.nist.gov/groups/ST/crypto_apps_infra/documents/pkixtools/

/*

Certificate:
============

-----BEGIN CERTIFICATE-----
MIICVjCCAb8CAg37MA0GCSqGSIb3DQEBBQUAMIGbMQswCQYDVQQGEwJKUDEOMAwG
A1UECBMFVG9reW8xEDAOBgNVBAcTB0NodW8ta3UxETAPBgNVBAoTCEZyYW5rNERE
MRgwFgYDVQQLEw9XZWJDZXJ0IFN1cHBvcnQxGDAWBgNVBAMTD0ZyYW5rNEREIFdl
YiBDQTEjMCEGCSqGSIb3DQEJARYUc3VwcG9ydEBmcmFuazRkZC5jb20wHhcNMTIw
ODIyMDUyNzIzWhcNMTcwODIxMDUyNzIzWjBKMQswCQYDVQQGEwJKUDEOMAwGA1UE
CAwFVG9reW8xETAPBgNVBAoMCEZyYW5rNEREMRgwFgYDVQQDDA93d3cuZXhhbXBs
ZS5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMYBBrx5PlP0WNI/ZdzD
+6Pktmurn+F2kQYbtc7XQh8/LTBvCo+P6iZoLEmUA9e7EXLRxgU1CVqeAi7QcAn9
MwBlc8ksFJHB0rtf9pmf8Oza9E0Bynlq/4/Kb1x+d+AyhL7oK9tQwB24uHOueHi1
C/iVv8CSWKiYe6hzN1txYe8rAgMBAAEwDQYJKoZIhvcNAQEFBQADgYEAASPdjigJ
kXCqKWpnZ/Oc75EUcMi6HztaW8abUMlYXPIgkV2F7YanHOB7K4f7OOLjiz8DTPFf
jC9UeuErhaA/zzWi8ewMTFZW/WshOrm3fNvcMrMLKtH534JKvcdMg6qIdjTFINIr
evnAhf0cwULaebn+lMs8Pdl7y37+sfluVok=
-----END CERTIFICATE-----



SEQUENCE(3 elem)
	SEQUENCE(6 elem)
		INTEGER3579
		SEQUENCE(2 elem)
			OBJECT IDENTIFIER					1.2.840.113549.1.1.5
			NULL
		SEQUENCE(7 elem)
			SET(1 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER			2.5.4.6
					PrintableString				JP
			SET(1 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER			2.5.4.8
					PrintableString				Tokyo
			SET(1 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER			2.5.4.7
					PrintableString				Chuo-ku
			SET(1 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER			2.5.4.10
					PrintableString				Frank4DD
			SET(1 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER			2.5.4.11
					PrintableString				WebCert Support
			SET(1 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER			2.5.4.3
					PrintableString				Frank4DD Web CA
			SET(1 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER			1.2.840.113549.1.9.1
					IA5String					support@frank4dd.com
		SEQUENCE(2 elem)
			UTCTime								2012-08-22 05:27:23 UTC
			UTCTime								2017-08-21 05:27:23 UTC
		SEQUENCE(4 elem)
			SET(1 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER			2.5.4.6
					PrintableString				JP
			SET(1 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER			2.5.4.8
					UTF8String					Tokyo
			SET(1 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER			2.5.4.10
					UTF8String					Frank4DD
			SET(1 elem)
				SEQUENCE(2 elem)
					OBJECT IDENTIFIER			2.5.4.3
					UTF8String					www.example.com
		SEQUENCE(2 elem)
			SEQUENCE(2 elem)
				OBJECT IDENTIFIER				1.2.840.113549.1.1.1
				NULL
			BIT STRING(1 elem)
				SEQUENCE(2 elem)
					INTEGER(1024 bit)			139043143640772622771388283044214826965667264427324172021986332943067…
					INTEGER						65537
	SEQUENCE(2 elem)
		OBJECT IDENTIFIER						1.2.840.113549.1.1.5
		NULL
	BIT STRING(1024 bit)						000000010010001111011101100011100010100000001001100100010111000010101…





public PEM:
===========

-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQBm5yRpE8xVXV8SSVDNISkkzToY
MmPDulNbTsHawtTMOeHkNR2klYw23rzDAwzVB0JtpOfyJXVw7WYEh6kqwXfW4lB7
f3Oye/bXOh0XVryvIVrnQwRouxYYcd64uha/CVnG4y/tM7DbG64JTd4tJVbYkrmO
pjsBPNoJbhKjTnb0/QIDAQAB
-----END PUBLIC KEY-----

SEQUENCE(2 elem)
	SEQUENCE(2 elem)
		OBJECT IDENTIFIER			1.2.840.113549.1.1.1				-- rsaEncryption
		NULL
	BIT STRING(1 elem)
		SEQUENCE(2 elem)
			INTEGER(1023 bit)		722608733133111661585229270073948506509109752292816595953562525256298…
			INTEGER					65537



-----BEGIN EC PUBLIC KEY-----
RUNTMzAAAABMrWvMrqah61dhnjTXm8YYZzgE2TtVO8d5DCHak7wjrJ21VIvl/BouL7Hyp/aHiDReIs+nGT7VsNp+CPaGt3Ek5V8DMmNxb5jl2mlgVq/Fvwu/Ktuhso49/Vc582SH1gg=
-----END EC PUBLIC KEY-----

Application 5(67 byte)				5333300000004CAD6BCCAEA6A1EB57619E34D79BC618673804D93B553BC7790C21DA93…


-----BEGIN EC PRIVATE KEY-----
RUNTNDAAAABMrWvMrqah61dhnjTXm8YYZzgE2TtVO8d5DCHak7wjrJ21VIvl/BouL7Hyp/aHiDReIs+nGT7VsNp+CPaGt3Ek5V8DMmNxb5jl2mlgVq/Fvwu/Ktuhso49/Vc582SH1ggkTg5HnE3IaucuTV/Rtdub4JktPk2fb3vIJgGiTsLeAuE6KvBfXTGXRoZsNRSriqg=
-----END EC PRIVATE KEY-----

Application 5(67 byte)				5334300000004CAD6BCCAEA6A1EB57619E34D79BC618673804D93B553BC7790C21DA93…

*/