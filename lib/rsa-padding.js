/**
 * A Javascript implemenation of PKI Paddings
 * 
 * @author Jacob Lee
 *
 * Copyright (C) 2015-2022 Jacob Lee.
 */

var jCastle = require('./jCastle');
require('./rsa');

// if (typeof jCastle.pki.rsa == 'undefined') {
// 	throw jCastle.exception('RSA_REQUIRED', 'RSAPAD001');
// }

jCastle.pki.rsa.padding = {};

jCastle.pki.rsa.PKCS1_PADDING_SIZE = 11;

/**
 * gets padding object.
 * 
 * @public
 * @param {string} padding padding type.
 * @returns padding object.
 */
jCastle.pki.rsa.padding.create = function(padding)
{
	return jCastle.pki.rsa.padding[padding.toLowerCase()];
};

// do not use it for encrypting
// do not use it with bit value as 0x00 for signing.
//
// http://www.di-mgt.com.au/rsa_alg.html#pkcs1schemes

/*
https://www.ibm.com/docs/en/zos/2.2.0?topic=cryptography-pkcs-1-formats

PKCS #1 Formats
===============

Version 2.0 of the PKCS #1 standard1 defines methods for formatting keys and hashes 
prior to RSA encryption of the resulting data structures. The lower versions of the 
PKCS #1 standard defined block types 0, 1, and 2, but in the current standard that 
terminology is dropped.

ICSF implemented these processes using the terminology of the Version 2.0 standard:

- For formatting keys for secured transport (CSNDSYX, CSNDSYG, CSNDSYI):

  * RSAES-OAEP, the preferred method for key-encipherment2 when exchanging DATA keys 
    between systems. Keyword PKCSOAEP is used to invoke this formatting technique. 
    The P parameter described in the standard is not used and its length is set to zero.

  * RSAES-PKCS1-v1_5, is an older method for formatting keys. Keyword PKCS-1.2 is used 
    to invoke this formatting technique.
    
- For formatting hashes for digital signatures (CSNDDSG and CSNDDSV):

  * RSASSA-PKCS1-v1_5, the newer name for the block-type 1 format. Keyword PKCS-1.1 is 
    used to invoke this formatting technique.

  * The PKCS #1 specification no longer discusses use of block-type 0. Keyword PKCS-1.0 
    is used to invoke this formatting technique. Use of block-type 0 is discouraged.

Using the terminology from older versions of the PKCS #1 standard, block types 0 and 1 
are used to format a hash and block type 2 is used to format a DES key. 
The blocks consist of (|| means concatenation): X'00' || BT || PS || X'00' D where:

- BT is the block type, X'00', X'01', X'02'.
- PS is the padding of as many bytes as required to make the block the same length 
  as the modulus of the RSA key, and is bytes of X'00' for block type 0, X'01' 
  for block type 1, and random and non-X'00' for block type 2. The length of PS must be
  at least 8 bytes.
- D is the key, or the concatenation of the BER-encoded hash identifier and the hash.

You can create the ASN.1 BER encoding of an MD5, SHA-1, SHA-224, SHA-256, SHA-384, 
or SHA-512 value by prepending a string to the hash value, as shown:

  MD5      X’3020300C 06082A86 4886F70D 02050500 0410’   || 16-byte hash value
  SHA-1    X'30213009 06052B0E 03021A05 000414’          || 20-byte hash value
  SHA-224  X’302D300D 06096086 48016503 04020405 00041C’ || 28-byte hash value
  SHA-256  X’3031300D 06096086 48016503 04020105 000420’ || 32-byte hash value
  SHA-384  X’3041300D 06096086 48016503 04020205 000430’ || 48-byte hash value
  SHA-512  X’3051300D 06096086 48016503 04020305 000440’ || 64-byte hash value
*/

/*
rfc 2313

8. Encryption process

   This section describes the RSA encryption process.

   The encryption process consists of four steps: encryption- block
   formatting, octet-string-to-integer conversion, RSA computation, and
   integer-to-octet-string conversion. The input to the encryption
   process shall be an octet string D, the data; an integer n, the
   modulus; and an integer c, the exponent. For a public-key operation,
   the integer c shall be an entity's public exponent e; for a private-
   key operation, it shall be an entity's private exponent d. The output
   from the encryption process shall be an octet string ED, the
   encrypted data.

   The length of the data D shall not be more than k-11 octets, which is
   positive since the length k of the modulus is at least 12 octets.
   This limitation guarantees that the length of the padding string PS
   is at least eight octets, which is a security condition.

   Notes.

        1.   In typical applications of this document to
             encrypt content-encryption keys and message digests, one
             would have ||D|| <= 30. Thus the length of the RSA modulus
             will need to be at least 328 bits (41 octets), which is
             reasonable and consistent with security recommendations.

        2.   The encryption process does not provide an
             explicit integrity check to facilitate error detection
             should the encrypted data be corrupted in transmission.
             However, the structure of the encryption block guarantees
             that the probability that corruption is undetected is less
             than 2-16, which is an upper bound on the probability that
             a random encryption block looks like block type 02.

        3.   Application of private-key operations as defined
             here to data other than an octet string containing a
             message digest is not recommended and is subject to further
             study.

        4.   This document may be extended to handle data of
             length more than k-11 octets.

8.1 Encryption-block formatting

   A block type BT, a padding string PS, and the data D shall be
   formatted into an octet string EB, the encryption block.

              EB = 00 || BT || PS || 00 || D .           (1)

   The block type BT shall be a single octet indicating the structure of
   the encryption block. For this version of the document it shall have
   value 00, 01, or 02. For a private- key operation, the block type
   shall be 00 or 01. For a public-key operation, it shall be 02.

   The padding string PS shall consist of k-3-||D|| octets. For block
   type 00, the octets shall have value 00; for block type 01, they
   shall have value FF; and for block type 02, they shall be
   pseudorandomly generated and nonzero. This makes the length of the
   encryption block EB equal to k.

   Notes.

        1.   The leading 00 octet ensures that the encryption
             block, converted to an integer, is less than the modulus.

        2.   For block type 00, the data D must begin with a
             nonzero octet or have known length so that the encryption
             block can be parsed unambiguously. For block types 01 and
             02, the encryption block can be parsed unambiguously since
             the padding string PS contains no octets with value 00 and
             the padding string is separated from the data D by an octet
             with value 00.

        3.   Block type 01 is recommended for private-key
             operations. Block type 01 has the property that the
             encryption block, converted to an integer, is guaranteed to
             be large, which prevents certain attacks of the kind
             proposed by Desmedt and Odlyzko [DO86].

        4.   Block types 01 and 02 are compatible with PEM RSA
             encryption of content-encryption keys and message digests
             as described in RFC 1423.

        5.   For block type 02, it is recommended that the
             pseudorandom octets be generated independently for each
             encryption process, especially if the same data is input to
             more than one encryption process.  Hastad's results [Has88]
             motivate this recommendation.

        6.   For block type 02, the padding string is at least
             eight octets long, which is a security condition for
             public-key operations that prevents an attacker from
             recoving data by trying all possible encryption blocks. For
             simplicity, the minimum length is the same for block type
             01.

        7.   This document may be extended in the future to
             include other block types.

*/
jCastle.pki.rsa.padding['pkcs1_type_1'] = {

   name: "PKCS1 Type 1 Padding",

	pad: function(input, bitlen, blockType = 0x01)
	{
      var ba = Buffer.from(input);
      var n = (bitlen + 7) >>> 3;

		if(n < ba.length + jCastle.pki.rsa.PKCS1_PADDING_SIZE) {
			throw jCastle.exception("MSG_TOO_LONG", 'RSAPAD001');
		}

		// EB = 00 || BT || PS || 00 || D

      if (blockType !== 0x00 && blockType !== 0x01 && blockType !== 0x02)
         throw jCastle.exception("INVALID_BLOCK_TYPE", 'RSAPAD002');

		var res = Buffer.alloc(n);

		var len = ba.length;
		res[0] = 0x00;
		res[1] = blockType;

      var i = 2;

      if (blockType == 0x00 || blockType == 0x01) {
         var pad = blockType == 0x00 ? 0x00 : 0xff;
         while (i < n - len - 1) {
            res[i++] = pad;
         }
      } else {
         var padding = new jCastle.prng.nextBytes(n - len - 1, true, true);
         padding.copy(res, 2);
         i = n - len - 1;
      }
      

      res[i++] = 0x00;

      res.set(ba, i);

      return res;
	},

	unpad: function(input, bitlen, bt = 0x02)
	{
		var i = 0;
      var ba = Buffer.from(input);
      var n = (bitlen + 7) >>> 3;

		if (bt == 0x00) {
			while (ba[i] == 0x00 && i < ba.length) i++;
		} else {
			if (ba[i] == 0x00) i++;
			if (ba[i++] !== bt) return null;
			while (ba[i] !== 0x00 && i < ba.length) i++;
			if (ba[i++] != 0x00) {
				return null;
			}
		}
      var res = Buffer.slice(ba, i);

		if(n < res.length + jCastle.pki.rsa.PKCS1_PADDING_SIZE) {
			throw jCastle.exception("MSG_TOO_LONG", 'RSAPAD003');
		}

		return res;
	}
};


/*
rfc3447

   RSAES-PKCS1-V1_5-ENCRYPT ((n, e), M)

   Input:
   (n, e)   recipient's RSA public key (k denotes the length in octets
            of the modulus n)
   M        message to be encrypted, an octet string of length mLen,
            where mLen <= k - 11

   Output:
   C        ciphertext, an octet string of length k

   Error: "message too long"

   Steps:

   1. Length checking: If mLen > k - 11, output "message too long" and
      stop.

   2. EME-PKCS1-v1_5 encoding:

      a. Generate an octet string PS of length k - mLen - 3 consisting
         of pseudo-randomly generated nonzero octets.  The length of PS
         will be at least eight octets.

      b. Concatenate PS, the message M, and other padding to form an
         encoded message EM of length k octets as

            EM = 0x00 || 0x02 || PS || 0x00 || M.

   3. RSA encryption:

      a. Convert the encoded message EM to an integer message
         representative m (see Section 4.2):

            m = OS2IP (EM).

      b. Apply the RSAEP encryption primitive (Section 5.1.1) to the RSA
         public key (n, e) and the message representative m to produce
         an integer ciphertext representative c:

            c = RSAEP ((n, e), m).

      c. Convert the ciphertext representative c to a ciphertext C of
         length k octets (see Section 4.1):

               C = I2OSP (c, k).

   4. Output the ciphertext C.
*/
// PKCS#1 v1.5 (type 2, random) pad input string s to n bytes, and return a bigint
// EME-PKCS1-v1_5 padding (See {@link http://tools.ietf.org/html/rfc4880#section-13.1.1|RFC 4880 13.1.1})
jCastle.pki.rsa.padding['rsaes-pkcs1-v1_5'] = 
jCastle.pki.rsa.padding['pkcs1_type_2'] = {

	name: "PKCS1 Type 2 Padding",

	pad: function(input, bitlen, blockType = 0x02)
	{
      var ba = Buffer.from(input);
      var n = (bitlen + 7) >>> 3;

		// random pads should be at least 8
		if (n < ba.length + jCastle.pki.rsa.PKCS1_PADDING_SIZE) {
			throw jCastle.exception("MSG_TOO_LONG", 'RSAPAD004');
		}

		// EB = 00 || 02 || PS || 00 || D

		var len = ba.length;
		var res = Buffer.alloc(n);
		res[0] = 0x00;
		res[1] = 0x02;

		var rng = new jCastle.prng();
      var i = 2;
      var pad = null;

      if (blockType == 0x00) pad = 0x00;
      else if (blockType == 0x01) pad = 0xff;

      while ( i < n - len - 1) {
         res[i++] = blockType == 0x02 ? rng.nextByte(true) : pad;
      }
      res[i++] = 0x00;

      res.set(ba, i);

      return res;
	},

/*
rfc3447

   RSAES-PKCS1-V1_5-DECRYPT (K, C)

   Input:
   K        recipient's RSA private key
   C        ciphertext to be decrypted, an octet string of length k,
            where k is the length in octets of the RSA modulus n

   Output:
   M        message, an octet string of length at most k - 11

   Error: "decryption error"

   Steps:

   1. Length checking: If the length of the ciphertext C is not k octets
      (or if k < 11), output "decryption error" and stop.

   2. RSA decryption:

      a. Convert the ciphertext C to an integer ciphertext
         representative c (see Section 4.2):

            c = OS2IP (C).

      b. Apply the RSADP decryption primitive (Section 5.1.2) to the RSA
         private key (n, d) and the ciphertext representative c to
         produce an integer message representative m:

            m = RSADP ((n, d), c).

         If RSADP outputs "ciphertext representative out of range"
         (meaning that c >= n), output "decryption error" and stop.

      c. Convert the message representative m to an encoded message EM
         of length k octets (see Section 4.1):

            EM = I2OSP (m, k).

   3. EME-PKCS1-v1_5 decoding: Separate the encoded message EM into an
      octet string PS consisting of nonzero octets and a message M as

         EM = 0x00 || 0x02 || PS || 0x00 || M.

      If the first octet of EM does not have hexadecimal value 0x00, if
      the second octet of EM does not have hexadecimal value 0x02, if
      there is no octet with hexadecimal value 0x00 to separate PS from
      M, or if the length of PS is less than 8 octets, output
      "decryption error" and stop.  (See the note below.)

   4. Output M.

   Note.  Care shall be taken to ensure that an opponent cannot
   distinguish the different error conditions in Step 3, whether by
   error message or timing.  Otherwise an opponent may be able to obtain
   useful information about the decryption of the ciphertext C, leading
   to a strengthened version of Bleichenbacher's attack [6]; compare to
   Manger's attack [36].
*/
// Undo PKCS#1 (type 2, random) padding and, if valid, return the plaintext
	unpad: function(input, bitlen, blockType)
	{
		var i = 0;
      var ba = Buffer.from(input);
      var n = (bitlen + 7) >>> 3;

		if (ba[i] == 0x00) i++;
		if (ba[i] != 0x02) return null;
		while (ba[i] != 0x00 && i < ba.length) i++;
		if (ba.length == i) return null;
		i++; // 0x00

      var res = Buffer.slice(ba, i);

      if(n < res.length + jCastle.pki.rsa.PKCS1_PADDING_SIZE) {
			throw jCastle.exception("MSG_TOO_LONG", 'RSAPAD005');
		}

		return res;
	}
};

jCastle.pki.rsa.padding['sslv23'] = {

	name: "SSLv23 Padding",

   pad: function(input, bitlen)
	{
      var ba = Buffer.from(input);
      var n = (bitlen + 7) >>> 3;

		// random pads should be at least 8
		if (n < ba.length + jCastle.pki.rsa.PKCS1_PADDING_SIZE) {
			throw jCastle.exception("MSG_TOO_LONG", 'RSAPAD006');
		}

		var len = ba.length;
		var res = Buffer.alloc(n);
		res[0] = 0x00;
		res[1] = 0x02;

		var rng = new jCastle.prng();
      var i = 2;
      while ( i < n - len - 8 - 1) {
         res[i++] = rng.nextByte(true);
      }
      res.fill(0x03, i, i + 8);
      i += 8;
      res[i++] = 0x00;

      res.set(ba, i);
		return res
	},

	// Undo PKCS#1 (type 2, random) padding and, if valid, return the plaintext
	unpad: function(input, bitlen)
	{
		var i = 0;
      var ba = Buffer.from(input);
      var n = (bitlen + 7) >>> 3;

		if (ba[i] == 0x00) i++;
		if (ba[i++] != 0x02) return null;
		while (ba[i] != 0x00 && i < ba.length) i++;
		if (i == ba.length) return null;

		// ba[i] is 0x00
		for (var j = i - 8; j < i; j++) {
			if (ba[j] != 0x03) return null;
		}

		var res = Buffer.slice(ba, i);

		if(n < res.length + jCastle.pki.rsa.PKCS1_PADDING_SIZE) {
			throw jCastle.exception("MSG_TOO_LONG", 'RSAPAD007');
		}

		return res;
	}
};


/*
rfc3447
http://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding



			<m>							000						r
size		m.length = (n - k0 - k1)	k1						k0
            |                           |                       |
			+------------+--------------+                       |
			             |                                      |
						 +---------------- G <------------------+
						 |                                      |
						 |                                      |
						 +---------------> H ------------------>|
						 |                                      |
						 X                                      Y



In the diagram,

n is the number of bits in the RSA modulus.
k0 and k1 are integers fixed by the protocol.
m is the plaintext message, an (n − k0 − k1 )-bit string
G and H are typically some cryptographic hash functions fixed by the protocol.

To encode,

messages are padded with k1 zeros to be n − k0 bits in length.
r is a random k0-bit string
G expands the k0 bits of r to n − k0 bits.
X = m00..0 ⊕ G(r)
H reduces the n − k0 bits of X to k0 bits.
Y = r ⊕ H(X)
The output is X || Y where X is shown in the diagram as the leftmost block and Y as the rightmost block.

To decode,

recover the random string as r = Y ⊕ H(X)
recover the message as m00..0 = X ⊕ G(r)

*/

/*
https://www.ietf.org/rfc/rfc3447.txt

   __________________________________________________________________

                             +----------+---------+-------+
                        DB = |  lHash   |    PS   |   M   |
                             +----------+---------+-------+
                                            |
                  +----------+              V
                  |   seed   |--> MGF ---> xor
                  +----------+              |
                        |                   |
               +--+     V                   |
               |00|    xor <----- MGF <-----|
               +--+     |                   |
                 |      |                   |
                 V      V                   V
               +--+----------+----------------------------+
         EM =  |00|maskedSeed|          maskedDB          |
               +--+----------+----------------------------+
   __________________________________________________________________

Figure 1: EME-OAEP encoding operation.  lHash is the hash of the
   optional label L.  Decoding operation follows reverse steps to
   recover M and verify lHash and PS.

*/

// PKCS#1 (OAEP) mask generation function
jCastle.pki.rsa.padding['rsaes-oaep_mgf1'] = 
jCastle.pki.rsa.padding['pkcs1_oaep_mgf1'] = {

	name: "PKCS1 OAEP MGF1 Padding",

   mgf1: function(seed, len, hash_name)
	{

		var mask = Buffer.alloc(0), i = 0;
		var md = new jCastle.digest(hash_name);

      while (mask.length < len) {
         var t = md.start()
                     .update(seed)
                     .update(Buffer.from([(i >>> 24) & 0xff, (i >>> 16) & 0xff, (i >>> 8) & 0xff, i & 0xff]))
                     .finalize();
         mask = Buffer.concat([mask, t]);
         i++;
      }

		return mask.slice(0, len);
	},

/*
https://www.ipa.go.jp/security/rfc/RFC4055EN.html

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

	  ...
	  pSourceFunc

         The pSourceFunc field identifies the source (and possibly the
         value) of the encoding parameters, commonly called P.
         Implementations MUST represent P by an algorithm identifier,
         id-pSpecified, indicating that P is explicitly provided as an
         OCTET STRING in the parameters.  The default value for P is an
         empty string.  In this case, pHash in EME-OAEP contains the
         hash of a zero length string.
*/

/*
rfc3447

   RSAES-OAEP-ENCRYPT ((n, e), M, L)

   Options:
   Hash     hash function (hLen denotes the length in octets of the hash
            function output)
   MGF      mask generation function

   Input:
   (n, e)   recipient's RSA public key (k denotes the length in octets
            of the RSA modulus n)
   M        message to be encrypted, an octet string of length mLen,
            where mLen <= k - 2hLen - 2
   L        optional label to be associated with the message; the
            default value for L, if L is not provided, is the empty
            string

   Output:
   C        ciphertext, an octet string of length k

   Errors:  "message too long"; "label too long"

   Assumption: RSA public key (n, e) is valid

   Steps:

   1. Length checking:

      a. If the length of L is greater than the input limitation for the
         hash function (2^61 - 1 octets for SHA-1), output "label too
         long" and stop.

      b. If mLen > k - 2hLen - 2, output "message too long" and stop.

   2. EME-OAEP encoding (see Figure 1 below):

      a. If the label L is not provided, let L be the empty string. Let
         lHash = Hash(L), an octet string of length hLen (see the note
         below).

      b. Generate an octet string PS consisting of k - mLen - 2hLen - 2
         zero octets.  The length of PS may be zero.

      c. Concatenate lHash, PS, a single octet with hexadecimal value
         0x01, and the message M to form a data block DB of length k -
         hLen - 1 octets as

            DB = lHash || PS || 0x01 || M.

      d. Generate a random octet string seed of length hLen.

      e. Let dbMask = MGF(seed, k - hLen - 1).

      f. Let maskedDB = DB \xor dbMask.

      g. Let seedMask = MGF(maskedDB, hLen).

      h. Let maskedSeed = seed \xor seedMask.

      i. Concatenate a single octet with hexadecimal value 0x00,
         maskedSeed, and maskedDB to form an encoded message EM of
         length k octets as

            EM = 0x00 || maskedSeed || maskedDB.

   3. RSA encryption:

      a. Convert the encoded message EM to an integer message
         representative m (see Section 4.2):

            m = OS2IP (EM).

      b. Apply the RSAEP encryption primitive (Section 5.1.1) to the RSA
         public key (n, e) and the message representative m to produce
         an integer ciphertext representative c:

            c = RSAEP ((n, e), m).

      c. Convert the ciphertext representative c to a ciphertext C of
         length k octets (see Section 4.1):

            C = I2OSP (c, k).

   4. Output the ciphertext C.

   Note.  If L is the empty string, the corresponding hash value lHash
   has the following hexadecimal representation for different choices of
   Hash:

   SHA-1:   (0x)da39a3ee 5e6b4b0d 3255bfef 95601890 afd80709
   SHA-256: (0x)e3b0c442 98fc1c14 9afbf4c8 996fb924 27ae41e4 649b934c
                a495991b 7852b855
   SHA-384: (0x)38b060a7 51ac9638 4cd9327e b1b1e36a 21fdb711 14be0743
                4c0cc7bf 63f6e1da 274edebf e76f65fb d51ad2f1 4898b95b
   SHA-512: (0x)cf83e135 7eefb8bd f1542850 d66d8007 d620e405 0b5715dc
                83f4a921 d36ce9ce 47d0d13c 5d85f2b0 ff8318d2 877eec2f
                63b931bd 47417a81 a538327a f927da3e

   __________________________________________________________________

                             +----------+---------+-------+
                        DB = |  lHash   |    PS   |   M   |
                             +----------+---------+-------+
                                            |
                  +----------+              V
                  |   seed   |--> MGF ---> xor
                  +----------+              |
                        |                   |
               +--+     V                   |
               |00|    xor <----- MGF <-----|
               +--+     |                   |
                 |      |                   |
                 V      V                   V
               +--+----------+----------------------------+
         EM =  |00|maskedSeed|          maskedDB          |
               +--+----------+----------------------------+
   __________________________________________________________________

   Figure 1: EME-OAEP encoding operation.  lHash is the hash of the
   optional label L.  Decoding operation follows reverse steps to
   recover M and verify lHash and PS.
*/
// RSAES-OAEP
// PKCS#1 (OAEP) pad input string s to n bytes, and return a bigint
	pad: function(input, bitlen, hash_name = 'sha-1', label = '', seed = null)
	{
      var ba = Buffer.from(input);
      var n = (bitlen + 7) >>> 3;
      var mLen = ba.length;
      var hLen = jCastle.digest.getDigestLength(hash_name);

      if (n < mLen + (hLen * 2) + 2) {
			throw jCastle.exception("MSG_TOO_LONG", 'RSAPAD008');
		}

      var PS = Buffer.alloc(n - mLen - (hLen * 2) - 2, 0x00);
		var label_hash = new jCastle.digest(hash_name).digest(label);
      var DB = Buffer.concat([label_hash, PS, Buffer.alloc(1, 0x01), ba]);
      if (seed) {
         seed = Buffer.from(seed);
      } else {
   		seed = new jCastle.prng().nextBytes(hLen, true);
      }
		var dbMask = this.mgf1(seed, DB.length, hash_name);
      var maskedDB = Buffer.xor(DB, dbMask);
		var seedMask = this.mgf1(maskedDB, seed.length, hash_name);
      var maskedSeed = Buffer.xor(seed, seedMask);
      var EM = Buffer.concat([Buffer.alloc(1, 0x00), maskedSeed, maskedDB]);

      return EM;
	},


/*
rfc3447

   RSAES-OAEP-DECRYPT (K, C, L)

   Options:
   Hash     hash function (hLen denotes the length in octets of the hash
            function output)
   MGF      mask generation function

   Input:
   K        recipient's RSA private key (k denotes the length in octets
            of the RSA modulus n)
   C        ciphertext to be decrypted, an octet string of length k,
            where k = 2hLen + 2
   L        optional label whose association with the message is to be
            verified; the default value for L, if L is not provided, is
            the empty string

   Output:
   M        message, an octet string of length mLen, where mLen <= k -
            2hLen - 2

   Error: "decryption error"

   Steps:

   1. Length checking:

      a. If the length of L is greater than the input limitation for the
         hash function (2^61 - 1 octets for SHA-1), output "decryption
         error" and stop.

      b. If the length of the ciphertext C is not k octets, output
         "decryption error" and stop.

      c. If k < 2hLen + 2, output "decryption error" and stop.

   2.    RSA decryption:

      a. Convert the ciphertext C to an integer ciphertext
         representative c (see Section 4.2):

            c = OS2IP (C).

         b. Apply the RSADP decryption primitive (Section 5.1.2) to the
         RSA private key K and the ciphertext representative c to
         produce an integer message representative m:

            m = RSADP (K, c).

         If RSADP outputs "ciphertext representative out of range"
         (meaning that c >= n), output "decryption error" and stop.

      c. Convert the message representative m to an encoded message EM
         of length k octets (see Section 4.1):

            EM = I2OSP (m, k).

   3. EME-OAEP decoding:

      a. If the label L is not provided, let L be the empty string. Let
         lHash = Hash(L), an octet string of length hLen (see the note
         in Section 7.1.1).

      b. Separate the encoded message EM into a single octet Y, an octet
         string maskedSeed of length hLen, and an octet string maskedDB
         of length k - hLen - 1 as

            EM = Y || maskedSeed || maskedDB.

      c. Let seedMask = MGF(maskedDB, hLen).

      d. Let seed = maskedSeed \xor seedMask.

      e. Let dbMask = MGF(seed, k - hLen - 1).

      f. Let DB = maskedDB \xor dbMask.

      g. Separate DB into an octet string lHash' of length hLen, a
         (possibly empty) padding string PS consisting of octets with
         hexadecimal value 0x00, and a message M as

            DB = lHash' || PS || 0x01 || M.

         If there is no octet with hexadecimal value 0x01 to separate PS
         from M, if lHash does not equal lHash', or if Y is nonzero,
         output "decryption error" and stop.  (See the note below.)

   4. Output the message M.

   Note.  Care must be taken to ensure that an opponent cannot
   distinguish the different error conditions in Step 3.g, whether by
   error message or timing, or, more generally, learn partial
   information about the encoded message EM.  Otherwise an opponent may
   be able to obtain useful information about the decryption of the
   ciphertext C, leading to a chosen-ciphertext attack such as the one
   observed by Manger [36].
*/
// Undo PKCS#1 (OAEP) padding and, if valid, return the plaintext
	unpad: function(input, bitlen, hash_name = 'sha-1', label = '')
	{
      var ba = Buffer.from(input);
      var n = (bitlen + 7) >>> 3;
      var hLen = jCastle.digest.getDigestLength(hash_name);

		if (ba.length < (hLen * 2) + 2) {
			throw jCastle.exception("CIPHERTEXT_TOO_SHORT", 'RSAPAD009');
		}

      if (ba.length < n) {
         ba = Buffer.concat([Buffer.alloc(n - ba.length, 0x00), ba]);
      }

		var maskedSeed = ba.slice(1, hLen + 1);
		var maskedDB = ba.slice(hLen + 1);
		var seedMask = this.mgf1(maskedDB, hLen, hash_name);
		// var seed = Buffer.alloc(maskedSeed.length);
		// for (var i = 0; i < maskedSeed.length; i++) {
		// 	seed[i] = maskedSeed[i] ^ seedMask[i];
		// }
      var seed = Buffer.xor(maskedSeed, seedMask);

		var dbMask = this.mgf1(seed, ba.length - hLen, hash_name);
		// var DB = Buffer.alloc(maskedDB.length);
		// for (var i = 0; i < maskedDB.length; i++) {
		// 	DB[i] = maskedDB[i] ^ dbMask[i];
		// }
      var DB = Buffer.xor(maskedDB, dbMask);

		var label_hash = new jCastle.digest(hash_name).digest(label);
		var hash_arr = DB.slice(0, hLen);
      if (!hash_arr.equals(label_hash)) {
			throw jCastle.exception("HASH_MISMATCH", 'RSAPAD010');
		}

		var i = hLen;
		while (DB[i] == 0x00) i++;

		if (DB[i++] != 0x01) {
			throw jCastle.exception("MALFORMED_DATA", 'RSAPAD011');
		}

		return Buffer.slice(DB, i);

	}
};

/*
rfc3447

   Figure 2 illustrates the encoding operation.

   __________________________________________________________________

                                  +-----------+
                                  |     M     |
                                  +-----------+
                                        |
                                        V
                                      Hash
                                        |
                                        V
                          +--------+----------+----------+
                     M' = |Padding1|  mHash   |   salt   |
                          +--------+----------+----------+
                                         |
               +--------+----------+     V
         DB =  |Padding2|maskedseed|   Hash
               +--------+----------+     |
                         |               |
                         V               |    +--+
                        xor <--- MGF <---|    |bc|
                         |               |    +--+
                         |               |      |
                         V               V      V
               +-------------------+----------+--+
         EM =  |    maskedDB       |maskedseed|bc|
               +-------------------+----------+--+
   __________________________________________________________________

   Figure 2: EMSA-PSS encoding operation.  Verification operation
   follows reverse steps to recover salt, then forward steps to
   recompute and compare H.

   Notes.

   1. The encoding method defined here differs from the one in Bellare
      and Rogaway's submission to IEEE P1363a [5] in three respects:

      *  It applies a hash function rather than a mask generation
         function to the message.  Even though the mask generation
         function is based on a hash function, it seems more natural to
         apply a hash function directly.

      *  The value that is hashed together with the salt value is the
         string (0x)00 00 00 00 00 00 00 00 || mHash rather than the
         message M itself.  Here, mHash is the hash of M.  Note that the
         hash function is the same in both steps.  See Note 3 below for
         further discussion.  (Also, the name "salt" is used instead of
         "seed", as it is more reflective of the value's role.)

      *  The encoded message in EMSA-PSS has nine fixed bits; the first
         bit is 0 and the last eight bits form a "trailer field", the
         octet 0xbc.  In the original scheme, only the first bit is
         fixed.  The rationale for the trailer field is for
         compatibility with the Rabin-Williams IFSP-RW signature
         primitive in IEEE Std 1363-2000 [26] and the corresponding
         primitive in the draft ISO/IEC 9796-2 [29].

   2. Assuming that the mask generation function is based on a hash
      function, it is recommended that the hash function be the same as
      the one that is applied to the message; see Section 8.1 for
      further discussion.

   3. Without compromising the security proof for RSASSA-PSS, one may
      perform steps 1 and 2 of EMSA-PSS-ENCODE and EMSA-PSS-VERIFY (the
      application of the hash function to the message) outside the
      module that computes the rest of the signature operation, so that
      mHash rather than the message M itself is input to the module.  In
      other words, the security proof for RSASSA-PSS still holds even if
      an opponent can control the value of mHash.  This is convenient if
      the module has limited I/O bandwidth, e.g., a smart card.  Note
      that previous versions of PSS [4][5] did not have this property.
      Of course, it may be desirable for other security reasons to have
      the module process the full message.  For instance, the module may
      need to "see" what it is signing if it does not trust the
      component that computes the hash value.

   4. Typical salt lengths in octets are hLen (the length of the output
      of the hash function Hash) and 0.  In both cases the security of
      RSASSA-PSS can be closely related to the hardness of inverting
      RSAVP1.  Bellare and Rogaway [4] give a tight lower bound for the
      security of the original RSA-PSS scheme, which corresponds roughly
      to the former case, while Coron [12] gives a lower bound for the
      related Full Domain Hashing scheme, which corresponds roughly to
      the latter case.  In [13] Coron provides a general treatment with
      various salt lengths ranging from 0 to hLen; see [27] for
      discussion.  See also [31], which adapts the security proofs in
      [4][13] to address the differences between the original and the
      present version of RSA-PSS as listed in Note 1 above.

   5. As noted in IEEE P1363a [27], the use of randomization in
      signature schemes - such as the salt value in EMSA-PSS - may
      provide a "covert channel" for transmitting information other than
      the message being signed.  For more on covert channels, see [50].

   -------------------------------------------------------------------------

   EMSA-PSS-ENCODE (M, emBits)

   Options:

   Hash     hash function (hLen denotes the length in octets of the hash
            function output)
   MGF      mask generation function
   sLen     intended length in octets of the salt

   Input:
   M        message to be encoded, an octet string
   emBits   maximal bit length of the integer OS2IP (EM) (see Section
            4.2), at least 8hLen + 8sLen + 9

   Output:
   EM       encoded message, an octet string of length emLen = \ceil
            (emBits/8)

   Errors:  "encoding error"; "message too long"

   Steps:

   1.  If the length of M is greater than the input limitation for the
       hash function (2^61 - 1 octets for SHA-1), output "message too
       long" and stop.

   2.  Let mHash = Hash(M), an octet string of length hLen.

   3.  If emLen < hLen + sLen + 2, output "encoding error" and stop.

   4.  Generate a random octet string salt of length sLen; if sLen = 0,
       then salt is the empty string.

   5.  Let
         M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt;

       M' is an octet string of length 8 + hLen + sLen with eight
       initial zero octets.

   6.  Let H = Hash(M'), an octet string of length hLen.

   7.  Generate an octet string PS consisting of emLen - sLen - hLen - 2
       zero octets.  The length of PS may be 0.

   8.  Let DB = PS || 0x01 || salt; DB is an octet string of length
       emLen - hLen - 1.

   9.  Let dbMask = MGF(H, emLen - hLen - 1).

   10. Let maskedDB = DB xor dbMask.

   11. Set the leftmost 8emLen - emBits bits of the leftmost octet in
       maskedDB to zero.

   12. Let EM = maskedDB || H || 0xbc.

   13. Output EM.
*/
jCastle.pki.rsa.padding['emsa-pss_mgf1'] =
jCastle.pki.rsa.padding['pkcs1_pss_mgf1'] = {

	name: "PKCS1 PSS MGF1 Padding for signing",

   mgf1: jCastle.pki.rsa.padding['rsaes-oaep_mgf1'].mgf1, // pkcs1_oaep_mgf1

	pad: function(input, bitlen, hash_name, salt_len = -1, salt = null)
	{
      var ba = Buffer.from(input);
      var embits = bitlen - 1;
      var len = (embits + 7) >>> 3;
		var msg_hash = new jCastle.digest(hash_name).digest(ba);

		//
		// Negative sLen has special meanings:
		//      -1      sLen == hLen
		//      -2      salt length is maximized
		//      -N      reserved
		//
		if (salt_len == -1) {
			salt_len = msg_hash.length;
		} else if (salt_len == -2) {
			salt_len = len - msg_hash.length -2; // maximum permissible value. OpenSSL's default value.
		} else if (salt_len < -2) {
			throw jCastle.exception("INVALID_SALT_LENGTH", 'RSAPAD012');
		} else if (salt_len === 0 && !salt) {
         salt = Buffer.alloc(0);
      }

		if (salt_len > 0 && !salt) {
			salt = new jCastle.prng().nextBytes(salt_len, true); // true means no zero byte first
		}

		var seed = new jCastle.digest(hash_name).start()
                     .update(Buffer.alloc(8, 0x00))
                     .update(msg_hash)
                     .update(salt)
                     .finalize();
		
		var ps_len = len - salt_len - msg_hash.length - 2;
      var PS = Buffer.alloc(ps_len, 0x00);

      var DB = Buffer.concat([PS, Buffer.alloc(1, 0x01), salt]);
		var dbMask = this.mgf1(seed, DB.length, hash_name);
		var maskedDB = Buffer.alloc(DB.length);

      // for(i = 0; i < DB.length; i++) {
      // 	maskedDB[i] = DB[i] ^ dbMask[i];
      // }
      maskedDB = Buffer.xor(DB, dbMask);

      // maskedDB = Buffer.xor(DB, dbMask);
      // maskedDB[0] &= 0x7f;
      var mask = 0xff >>> ((len * 8) - embits);
      maskedDB[0] &= mask;

      return Buffer.concat([maskedDB, seed, Buffer.alloc(1, 0xbc)]);
	},

/*
rfc3447

   EMSA-PSS-VERIFY (M, EM, emBits)

   Options:
   Hash     hash function (hLen denotes the length in octets of the hash
            function output)
   MGF      mask generation function
   sLen     intended length in octets of the salt

   Input:
   M        message to be verified, an octet string
   EM       encoded message, an octet string of length emLen = \ceil
            (emBits/8)
   emBits   maximal bit length of the integer OS2IP (EM) (see Section
            4.2), at least 8hLen + 8sLen + 9

   Output:
   "consistent" or "inconsistent"

   Steps:

   1.  If the length of M is greater than the input limitation for the
       hash function (2^61 - 1 octets for SHA-1), output "inconsistent"
       and stop.

   2.  Let mHash = Hash(M), an octet string of length hLen.

   3.  If emLen < hLen + sLen + 2, output "inconsistent" and stop.

   4.  If the rightmost octet of EM does not have hexadecimal value
       0xbc, output "inconsistent" and stop.

   5.  Let maskedDB be the leftmost emLen - hLen - 1 octets of EM, and
       let H be the next hLen octets.

   6.  If the leftmost 8emLen - emBits bits of the leftmost octet in
       maskedDB are not all equal to zero, output "inconsistent" and
       stop.

   7.  Let dbMask = MGF(H, emLen - hLen - 1).

   8.  Let DB = maskedDB \xor dbMask.

   9.  Set the leftmost 8emLen - emBits bits of the leftmost octet in DB
       to zero.

   10. If the emLen - hLen - sLen - 2 leftmost octets of DB are not zero
       or if the octet at position emLen - hLen - sLen - 1 (the leftmost
       position is "position 1") does not have hexadecimal value 0x01,
       output "inconsistent" and stop.

   11.  Let salt be the last sLen octets of DB.

   12.  Let
            M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt ;

       M' is an octet string of length 8 + hLen + sLen with eight
       initial zero octets.

   13. Let H' = Hash(M'), an octet string of length hLen.

   14. If H = H', output "consistent." Otherwise, output "inconsistent."
*/
	verify: function(input, bitlen, enc_msg, hash_name, salt_len)
	{
      var ba = Buffer.from(input);
      var embits = bitlen - 1;
      var len = (embits + 7) >>> 3;
      var EM = Buffer.from(enc_msg);
		var msg_hash = new jCastle.digest(hash_name).digest(ba);
      var mlen = msg_hash.length;

      //
		// Negative sLen has special meanings:
		//      -1      sLen == hLen
		//      -2      salt length is maximized
		//      -N      reserved
		//
		if (salt_len == -1) {
			salt_len = mlen;
		} else if (salt_len == -2) {
			salt_len = len - mlen -2; // maximum permissible value. OpenSSL's default value.
		} else if (salt_len < -2) {
			throw jCastle.exception("INVALID_SALT_LENGTH", 'RSAPAD015');
      }

      if (EM.length < len) {
         EM = Buffer.concat([Buffer.alloc(len - EM.length, 0x00), EM]);
      }
      if (EM.length > len) {
         EM = EM.slice(EM.length - len);
      }

		if (EM[len-1] != 0xbc) {
			//throw jCastle.exception("MALFORMED_DATA", 'RSAPAD014');
         console.log('0xbc cannot be found');
			return false;
		}

		var maskedDB = EM.slice(0, len - mlen - 1);
		var seed = EM.slice(maskedDB.length, maskedDB.length + mlen);
		var dbMask = this.mgf1(seed, maskedDB.length, hash_name);
		var DB = Buffer.alloc(maskedDB.length);

		// for (var i = 0; i < maskedDB.length; i++) {
		// 	DB[i] = maskedDB[i] ^ dbMask[i];
		// }
      DB = Buffer.xor(maskedDB, dbMask);

      var mask = 0xff >>> ((len * 8) - embits);
      DB[0] &= mask;
		// DB[0] &= 0x7f;

      // when we don't know the salt length.
      // var pos = 0;
      // for (; pos < DB.length; pos++) {
      //    if (DB[pos] == 0x01) break;
      // }
      // pos++;
      // if (pos >= DB.length) {
		// 	return false;
      // }
      // var salt = DB.slice(pos);

      var ps_len = len - salt_len - mlen - 2;

		for (i = 0; i < ps_len; i++) {
			if (DB[i] != 0x00) {
				//throw jCastle.exception("MALFORMED_DATA", 'RSAENC016');
				return false;
			}
		}

		if (DB[ps_len] != 0x01) {
			//throw jCastle.exception("MALFORMED_DATA", 'RSAENC017');
			return false;
		}
		var salt = DB.slice(DB.length - salt_len);


		var ck_seed = new jCastle.digest(hash_name).start()
                        .update(Buffer.alloc(8, 0x00))
                        .update(msg_hash)
                        .update(salt)
                        .finalize();

      return seed.equals(ck_seed);
	}
};


/*
rfc3447

   EMSA-PKCS1-v1_5-ENCODE (M, emLen)

   Option:
   Hash     hash function (hLen denotes the length in octets of the hash
            function output)

   Input:
   M        message to be encoded
   emLen    intended length in octets of the encoded message, at least
            tLen + 11, where tLen is the octet length of the DER
            encoding T of a certain value computed during the encoding
            operation

   Output:
   EM       encoded message, an octet string of length emLen

   Errors:
   "message too long"; "intended encoded message length too short"

   Steps:

   1. Apply the hash function to the message M to produce a hash value
      H:

         H = Hash(M).

      If the hash function outputs "message too long," output "message
      too long" and stop.

   2. Encode the algorithm ID for the hash function and the hash value
      into an ASN.1 value of type DigestInfo (see Appendix A.2.4) with
      the Distinguished Encoding Rules (DER), where the type DigestInfo
      has the syntax

      DigestInfo ::= SEQUENCE {
          digestAlgorithm AlgorithmIdentifier,
          digest OCTET STRING
      }

      The first field identifies the hash function and the second
      contains the hash value.  Let T be the DER encoding of the
      DigestInfo value (see the notes below) and let tLen be the length
      in octets of T.

   3. If emLen < tLen + 11, output "intended encoded message length too
      short" and stop.

   4. Generate an octet string PS consisting of emLen - tLen - 3 octets
      with hexadecimal value 0xff.  The length of PS will be at least 8
      octets.

   5. Concatenate PS, the DER encoding T, and other padding to form the
      encoded message EM as

         EM = 0x00 || 0x01 || PS || 0x00 || T.

   6. Output EM.

 Notes.

   1. For the six hash functions mentioned in Appendix B.1, the DER
      encoding T of the DigestInfo value is equal to the following:

      MD2:     (0x)30 20 30 0c 06 08 2a 86 48 86 f7 0d 02 02 05 00 04
                   10 || H.
      MD5:     (0x)30 20 30 0c 06 08 2a 86 48 86 f7 0d 02 05 05 00 04
                   10 || H.
      SHA-1:   (0x)30 21 30 09 06 05 2b 0e 03 02 1a 05 00 04 14 || H.
      SHA-256: (0x)30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00
                   04 20 || H.
      SHA-384: (0x)30 41 30 0d 06 09 60 86 48 01 65 03 04 02 02 05 00
                   04 30 || H.
      SHA-512: (0x)30 51 30 0d 06 09 60 86 48 01 65 03 04 02 03 05 00
                      04 40 || H.

   2. In version 1.5 of this document, T was defined as the BER
      encoding, rather than the DER encoding, of the DigestInfo value.
      In particular, it is possible - at least in theory - that the
      verification operation defined in this document (as well as in
      version 2.0) rejects a signature that is valid with respect to the
      specification given in PKCS #1 v1.5.  This occurs if other rules
      than DER are applied to DigestInfo (e.g., an indefinite length
      encoding of the underlying SEQUENCE type).  While this is unlikely
      to be a concern in practice, a cautious implementer may choose to
      employ a verification operation based on a BER decoding operation
      as specified in PKCS #1 v1.5.  In this manner, compatibility with
      any valid implementation based on PKCS #1 v1.5 is obtained.  Such
      a verification operation should indicate whether the underlying
      BER encoding is a DER encoding and hence whether the signature is
      valid with respect to the specification given in this document.
*/
jCastle.pki.rsa.padding['emsa-pkcs1-v1_5'] = 
jCastle.pki.rsa.padding['pkcs1_emsa'] = {

	name: "EMSA-PKCS1-v1_5-ENCODE for signing",

   pad: function(input, bitlen, hash_name = 'sha-1')
	{
      var ba = Buffer.from(input);
      var n = (bitlen + 7) >>> 3;

		//var H = new jCastle.digest(hash_name).digest(ba).toString('latin1');
      var H = new jCastle.digest(hash_name).digest(ba);
		var oid = jCastle.digest.getOID(hash_name);

		var T = new jCastle.asn1().getDER({
			type: jCastle.asn1.tagSequence,
			items: [{
				type: jCastle.asn1.tagSequence,
				items: [{
					type: jCastle.asn1.tagOID,
					value: oid
				}, {
					type: jCastle.asn1.tagNull
				}]
			}, {
				type: jCastle.asn1.tagOctetString,
				value: H
			}]
		});

		// random pads should be at least 8
		if (n < T.length + jCastle.pki.rsa.PKCS1_PADDING_SIZE) {
			throw jCastle.exception("MSG_TOO_LONG", 'RSAPAD018');
		}

		//T = jCastle.fn.str2byteArray(T);
		T = Buffer.from(T, 'latin1');

		// EM = 0x00 || 0x01 || PS || 0x00 || T.
		//var EM = [];
		var EM = Buffer.alloc(n);
      EM[0] = 0x00;
      EM[1] = 0x01;

      var i = 2;
		while (i < n - 1 - T.length) {
			EM[i++] = 0xff;
		}

		EM[i++] = 0x00;

		EM.set(T, i);

		return EM;
	}
};

/*
http://www.di-mgt.com.au/rsa_alg.html#pkcs1schemes

ANSI standard X9.31 [AX931] requires using strong primes derived in a way 
to avoid particular attacks that are probably no longer relevant.
X9.31 uses a method of encoding the message digest specific to the hash algorithm.
It expects a key with length an exact multiple of 256 bits.
The same algorithm is also specified in P1363 [P1363] where it is called IFSP-RSA2.
The scheme allows for the public exponent to be an even value, 
but we do not consider that case here; all our values of e are assumed to be odd.
The message digest hash, H, is encapsulated to form a byte string as follows

EB = 06 || PS || 0xBA || H || 0x33 || 0xCC

where PS is a string of bytes all of value 0xBB of length such that |EB|=|n|,
and 0x33 is the ISO/IEC 10118 part number† for SHA-1. 
The byte string, EB, is converted to an integer value, the message representative, f.

ISO/IEC 10118 part numbers for other hash functions are:
SHA-1=0x33, SHA-256=0x34, SHA-384=0x36, SHA-512=0x35, RIPEMD=0x31. 
*/
jCastle.pki.rsa.padding['ansi_x931'] = {
   name: 'ANSI X931 Padding for RSA Signing',

   pad: function(input, bitlen, hash_algo = 'sha-1')
   {
      var ba = Buffer.from(input);
      var n = (bitlen + 7) >>> 3;

		hash_algo = jCastle.digest.getValidAlgoName(hash_algo);

		var hash_id;
		switch (hash_algo) {
			case 'sha-1':		hash_id = 0x33; break;
			case 'sha-256':		hash_id = 0x34; break;
			case 'sha-384':		hash_id = 0x36; break;
			case 'sha-512':		hash_id = 0x35; break;
			case 'ripemd-160':	hash_id = 0x31; break;
			case 'ripemd-128':	hash_id = 0x32; break;
			case 'whirlpool':	hash_id = 0x37; break;
			default:
				throw jCastle.exception("UNSUPPORTED_HASHER", 'RSAPAD019');
		}

		var pad_ba = Buffer.alloc(n);

		pad_ba[0] = 0x6b;

		var hash = new jCastle.digest(hash_algo).digest(ba);

		ps_len = n - hash.length - 4;

		var j = 1;
		for (var i = 0; i < ps_len; i++) {
			pad_ba[j++] = 0xbb;
		}
		pad_ba[j++] = 0xba;
		
		pad_ba.set(hash, j);
      j += hash.length;
		pad_ba[j++] = hash_id;
		pad_ba[j] = 0xcc;

      return pad_ba;
   },

   verify: function(input, bitlen, enc_msg)
   {
      var ba = Buffer.from(input);
      var n = (bitlen + 7) >>> 3;
      var em = Buffer.from(enc_msg);

      var i = 0;
      
		while (em[i] == 0x00) {
			i++;
		}

		if (em[i++] != 0x6b) {
			return false;
		}

		while (em[i] == 0xbb) {
			i++;
		}

		if (em[i++] != 0xba) {
			return false;
		}

      if (em[em.length - 1] != 0xcc) {
			return false;
		}

		var hash_id = em[em.length - 2];
		var hash_algo = '';

		switch (hash_id) {
			case 0x33: hash_algo =  'sha-1'; break;
			case 0x34: hash_algo = 'sha-256'; break;
			case 0x36: hash_algo = 'sha-384'; break;
			case 0x35: hash_algo = 'sha-512'; break;
			case 0x31: hash_algo = 'ripemd-160'; break;
			case 0x32: hash_algo = 'ripemd-128'; break;
			case 0x37: hash_algo = 'whirlpool'; break;
			default:
				//throw jCastle.exception("UNSUPPORTED_HASHER", 'RSA019');
				return false;
		}

      var hLen = jCastle.digest.getDigestLength(hash_algo);

      var ck_hash = em.slice(i, i + hLen);
		
		var hash = new jCastle.digest(hash_algo).digest(ba);

		return hash.equals(ck_hash);
   }
};

jCastle.pki.rsa.Padding = jCastle.pki.rsa.padding;

module.exports = jCastle.pki.rsa.padding;
