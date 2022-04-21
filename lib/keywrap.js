/**
 * jCastle - KeyWrap: Javascript Key Data Wrapping Engine 
 * 
 * @author Jacob Lee
 *
 * Copyright (C) 2015-2022 Jacob Lee.
 */

const jCastle = require('./jCastle');
require('./util');

/*
http://www.ietf.org/rfc/rfc3394.txt


1. Introduction

   NOTE: Most of the following text is taken from [AES-WRAP], and the
   assertions regarding the security of the AES Key Wrap algorithm are
   made by the US Government, not by the authors of this document.

   This specification is intended to satisfy the National Institute of
   Standards and Technology (NIST) Key Wrap requirement to:  Design a
   cryptographic algorithm called a Key Wrap that uses the Advanced
   Encryption Standard (AES) as a primitive to securely encrypt
   plaintext key(s) with any associated integrity information and data,
   such that the combination could be longer than the width of the AES
   block size (128-bits).  Each ciphertext bit should be a highly non-
   linear function of each plaintext bit, and (when unwrapping) each
   plaintext bit should be a highly non-linear function of each
   ciphertext bit.  It is sufficient to approximate an ideal
   pseudorandom permutation to the degree that exploitation of
   undesirable phenomena is as unlikely as guessing the AES engine key.

   This key wrap algorithm needs to provide ample security to protect
   keys in the context of prudently designed key management
   architecture.

   Throughout this document, any data being wrapped will be referred to
   as the key data.  It makes no difference to the algorithm whether the
   data being wrapped is a key; in fact there is often good reason to
   include other data with the key, to wrap multiple keys together, or
   to wrap data that isn't strictly a key.  So, the term "key data" is
   used broadly to mean any data being wrapped, but particularly keys,
   since this is primarily a key wrap algorithm.  The key used to do the
   wrapping will be referred to as the key-encryption key (KEK).

   In this document a KEK can be any valid key supported by the AES
   codebook.  That is, a KEK can be a 128-bit key, a 192-bit key, or a
   256-bit key.
*/
jCastle.keywrap = class
{
    /**
     * KeyWrap: Javascript Key Data Wrapping Engine
     * 
     * @param {string} algo_name algorithm name
     * @constructor
     */
    constructor(algo_name)
    {
/*
http://www.ietf.org/rfc/rfc3394.txt

2.2 Algorithms

   The specification of the key wrap algorithm requires the use of the
   AES codebook [AES].  The next three sections will describe the key
   wrap algorithm, the key unwrap algorithm, and the inherent data
   integrity check.
*/
        this._algorithm = null;
        this._algoName = 'aes-128';

        this._default = {
            wrappingKey: null,
    //		iv: null,
    //		blockSize: 0,
    //		format: 'bytes',
            isEncryption: true
        };

        this._options = {};

        this._keydata = Buffer.alloc(0);

        if (algo_name) {
            this._algoName = jCastle.mcrypt.getValidAlgoName(algo_name);
        }
/*
http://www.ietf.org/rfc/rfc3394.txt

3. Object Identifiers

   NIST has assigned the following object identifiers to identify the
   key wrap algorithm with the default initial value specified in
   2.2.3.1.  One object identifier is assigned for use with each of the
   KEK AES key sizes.

       aes  OBJECT IDENTIFIER  ::=  { joint-iso-itu-t(2) country(16)

          us(840) organization(1) gov(101) csor(3) nistAlgorithm(4) 1 }

       id-aes128-wrap  OBJECT IDENTIFIER  ::=  { aes 5 }
       id-aes192-wrap  OBJECT IDENTIFIER  ::=  { aes 25 }
       id-aes256-wrap  OBJECT IDENTIFIER  ::=  { aes 45 }
*/
    }

    /**
     * resets internal variables except algoName.
     * 
     * @public
     * @returns this class instance.
     */
	reset()
	{
		this._algorithm = null;
//		this._algoName = 'aes-128';
		this._keydata = Buffer.alloc(0);
        this._options = {};

		return this;
	}

    /**
     * wrap key data.
     * 
     * @public
     * @param {buffer} keydata key data to be wrapped.
     * @param {object} options options object
     * @returns wrapped keydata.
     */
	wrap(keydata, options = {})
	{
		if ('direction' in options) {
			delete options.direction;
		}
		options.isEncryption = true;
		
		return this.start(options).update(keydata).finalize();
	}

    /**
     * unwrap the encrypted key data.
     * 
     * @public
     * @param {buffer} keydata wrapped key data.
     * @param {object} options options object.
     * @returns unwrapped key data.
     */
	unwrap(keydata, options = {})
	{
		if ('direction' in options) {
			delete options.direction;
		}
		options.isEncryption = false;

		return this.start(options).update(keydata).finalize();
	}

/*
http://www.ietf.org/rfc/rfc3394.txt

2.2.1 Key Wrap

   The inputs to the key wrapping process are the KEK and the plaintext
   to be wrapped.  The plaintext consists of n 64-bit blocks, containing
   the key data being wrapped.  The key wrapping process is described
   below.

   Inputs:      Plaintext, n 64-bit values {P1, P2, ..., Pn}, and
                Key, K (the KEK).
   Outputs:     Ciphertext, (n+1) 64-bit values {C0, C1, ..., Cn}.

   1) Initialize variables.

       Set A0 to an initial value (see 2.2.3)
       For i = 1 to n
            R[0][i] = P[i]

   2) Calculate intermediate values.

       For t = 1 to s, where s = 6n
           A[t] = MSB(64, AES(K, A[t-1] | R[t-1][1])) ^ t
           For i = 1 to n-1
               R[t][i] = R[t-1][i+1]
           R[t][n] = LSB(64, AES(K, A[t-1] | R[t-1][1]))

   3) Output the results.

       Set C[0] = A[t]
       For i = 1 to n
           C[i] = R[t][i]

   An alternative description of the key wrap algorithm involves
   indexing rather than shifting.  This approach allows one to calculate
   the wrapped key in place, avoiding the rotation in the previous
   description.  This produces identical results and is more easily
   implemented in software.

   Inputs:  Plaintext, n 64-bit values {P1, P2, ..., Pn}, and
            Key, K (the KEK).
   Outputs: Ciphertext, (n+1) 64-bit values {C0, C1, ..., Cn}.

   1) Initialize variables.

       Set A = IV, an initial value (see 2.2.3)
       For i = 1 to n
           R[i] = P[i]

   2) Calculate intermediate values.

       For j = 0 to 5
           For i=1 to n
               B = AES(K, A | R[i])
               A = MSB(64, B) ^ t where t = (n*j)+i
               R[i] = LSB(64, B)

   3) Output the results.

       Set C[0] = A
       For i = 1 to n
           C[i] = R[i]
*/
    /**
     * start the process.
     * 
     * @public
     * @param {object} options options object.
     *                 {buffer} wrappingKey key for wrapping/unwrapping process.
     *                 {string} algoName algorithm name.
     *                 {boolean} isEncryption flag for wrapping or unwrapping.
     *                 {boolean} direction alias for isEncryption
     * @returns this class instance.
     */
	start(options = {})
	{
		this._options = {};

		// for (var i in options) {
		// 	this._options[i] = options[i];
		// }

        this._options = Object.assign(this._options, options);

		for (var i in this._default) {
			if (!(i in this._options)) {
				this._options[i] = this._default[i];
			}
		}
		
		if ('wrappingKey' in this._options && !Buffer.isBuffer(this._options.wrappingKey))
			this._options.wrappingKey = Buffer.from(options.wrappingKey, 'latin1');

		if ('algoName' in options) {
			this._algoName = jCastle.mcrypt.getValidAlgoName(options.algoName);
		}

		// direction
		if ('direction' in this._options) {
			if (this._options.direction === true || 
				(jCastle.util.isString(this._options.direction) && /^enc(rypt(ion)?)?$/ig.test(this._options.direction))) {
				this._options.isEncryption = true;
			} else if (this._options.direction === false || 
				(jCastle.util.isString(this._options.direction) && /^dec(rypt(ion)?)?$/ig.test(this._options.direction))) {
				this._options.isEncryption = false;
			} else {
				throw jCastle.exception('INVALID_DIRECTION', 'WRP009');
			}
		}

		this._keydata = Buffer.alloc(0);

		return this;
	}

    /**
	 * updates the process with the keydata
	 * 
	 * @public
	 * @param {buffer} keydata keydata to be updated.
	 * @returns this class instance.
	 */
	update(keydata)
	{
		var input;
		
		if (keydata && keydata.length) {
            input = Buffer.from(keydata);
			this._keydata = Buffer.concat([this._keydata, input]);
        }

		return this;
	}

    /**
	 * finalize the process and returns the result.
	 * 
	 * @public
	 * @param {buffer} keydata key data 
	 * @returns the wrapping result in buffer
	 */
	finalize(keydata)
	{
        var output;

		if (keydata && keydata.length) {
            if (Buffer.isBuffer(keydata)) {
                input = keydata;
            } else {
                input = Buffer.from(keydata, 'latin1');
            }
			this._keydata = Buffer.concat([this._keydata, input]);
        }

		switch (this._algoName)
		{
			case 'gost': // not yet implemented
				// https://tools.ietf.org/rfc/rfc4490
				// https://tools.ietf.org/html/rfc4357
				throw jCastle.exception('UNSUPPORTED_ALGO', 'KWR009');
			case 'des-ede2':
				if (this._options.wrappingKey.length == 16) 
					this._options.wrappingKey = Buffer.concat([this._options.wrappingKey, this._options.wrappingKey.slice(0, 8)]);
			case '3des':
			case 'des3':
			case 'des-ede3':
			case 'tripledes':
				output = this._des3Wrapper();
                break;
			case 'rc2':
				output = this._rc2Wrapper();
                break;
//			case 'seed':
//			case 'seed-128':
/*
https://tools.ietf.org/html/rfc4010

3.  Key Wrap Algorithm

   SEED key wrapping and unwrapping is done in conformance with the AES
   key wrap algorithm [RFC3394].
*/
			default:
				output = this._defaultWrapper();
                break;
		}

        if ('encoding' in this._options) {
			output = output.toString(this._options.encoding);
		}

        this.reset();

        return output;
	}

	_defaultWrapper()
	{
		var iv, output;

		if (this._options.isEncryption) {

/*
http://www.ietf.org/rfc/rfc3394.txt

2.2.3.1 Default Initial Value

   The default initial value (IV) is defined to be the hexadecimal
   constant:

       A[0] = IV = A6A6A6A6A6A6A6A6

   The use of a constant as the IV supports a strong integrity check on
   the key data during the period that it is wrapped.  If unwrapping
   produces A[0] = A6A6A6A6A6A6A6A6, then the chance that the key data
   is corrupt is 2^-64.  If unwrapping produces A[0] any other value,
   then the unwrap must return an error and not return any key data.

2.2.3.2 Alternative Initial Values

   When the key wrap is used as part of a larger key management protocol
   or system, the desired scope for data integrity may be more than just
   the key data or the desired duration for more than just the period
   that it is wrapped.  Also, if the key data is not just an AES key, it
   may not always be a multiple of 64 bits.  Alternative definitions of
   the initial value can be used to address such problems.  NIST will
   define alternative initial values in future key management
   publications as needed.  In order to accommodate a set of
   alternatives that may evolve over time, key wrap implementations that
   are not application-specific will require some flexibility in the way
   that the initial value is set and tested.
*/
			var block_size = 8;

			if (!this._keydata.length) {
				throw jCastle.exception("DATA_TOO_SHORT", 'KWR001');
			}

/*
http://www.rfc-base.org/txt/rfc-5649.txt

3.  Alternative Initial Value

   The Alternative Initial Value (AIV) required by this specification is
   a 32-bit constant concatenated to a 32-bit MLI.  The constant is (in
   hexadecimal) A65959A6 and occupies the high-order half of the AIV.
   Note that this differs from the high order 32 bits of the default IV
   in Section 2.2.3.1 of [AES-KW1], so there is no ambiguity between the
   two.  The 32-bit MLI, which occupies the low-order half of the AIV,
   is an unsigned binary integer equal to the octet length of the
   plaintext key data, in network order -- that is, with the most
   significant octet first.  When the MLI is not a multiple of 8, the
   key data is padded on the right with the least number of octets
   sufficient to make the resulting octet length a multiple of 8.  The
   value of each padding octet shall be 0 (eight binary zeros).

   Notice that for a given number of 64-bit plaintext blocks, there are
   only eight values of MLI that can have that outcome.  For example,
   the only MLI values that are valid with four 64-bit plaintext blocks
   are 32 (with no padding octets), 31 (with one padding octet), 30, 29,
   28, 27, 26, and 25 (with seven padding octets).  When the unwrapping
   process specified below yields n 64-bit blocks of output data and an
   AIV, the eight valid values for the MLI are 8*n, (8*n)-1, ..., and
   (8*n)-7.  Therefore, integrity checking of the AIV, which is
   contained in a 64-bit register called A, requires the following
   steps:

   1) Check that MSB(32,A) = A65959A6.

   2) Check that 8*(n-1) < LSB(32,A) <= 8*n.  If so, let
      MLI = LSB(32,A).

   3) Let b = (8*n)-MLI, and then check that the rightmost b octets of
      the output data are zero.

   If all three checks pass, then the AIV is valid.  If any of the
   checks fail, then the AIV is invalid and the unwrapping operation
   must return an error.
*/
			var padding = this._keydata.length % block_size ? block_size - (this._keydata.length % block_size) : 0;

			if (padding) {
				var MLI = Buffer.alloc(4);
				MLI.writeInt32BE(this._keydata.length, 0, true);
				iv = Buffer.concat([Buffer.from('A65959A6', 'hex'), MLI]);
			} else {
				iv = Buffer.from('A6A6A6A6A6A6A6A6', 'hex');
			}

			// padding key data
			if (padding) 
				this._keydata = Buffer.concat([this._keydata, Buffer.alloc(padding)]);

			this._algorithm = new jCastle.algorithm[jCastle._algorithmInfo[this._algoName].object_name](this._algoName);
			this._algorithm.keySchedule(this._options.wrappingKey, true);

			var n = Math.ceil(this._keydata.length / block_size);
			var blocks = [];
			for (var i = 0; i < n; i++) {
				blocks[i] = this._keydata.slice(i * block_size, i * block_size + block_size);
			}

			if (n == 1) {
/*
http://www.rfc-base.org/txt/rfc-5649.txt

4.1.  Extended Key Wrapping Process

   The inputs to the extended key wrapping process are the KEK and the
   plaintext to be wrapped.  The plaintext consists of between one and
   2^32 octets, containing the key data being wrapped.  The key wrapping
   process is described below.

   Inputs:  Plaintext, m octets {Q[1], Q[2], ..., Q[m]}, and
            Key, K (the KEK).
   Outputs: Ciphertext, (n+1) 64-bit values {C[0], C[1], ..., C[n]}.

   1) Append padding

      If m is not a multiple of 8, pad the plaintext octet string on the
      right with octets {Q[m+1], ..., Q[r]} of zeros, where r is the
      smallest multiple of 8 that is greater than m.  If m is a multiple
      of 8, then there is no padding, and r = m.

      Set n = r/8, which is the same as CEILING(m/8).

      For i = 1, ..., n
         j = 8*(i-1)
         P[i] = Q[j+1] | Q[j+2] | ... | Q[j+8].

   2) Wrapping

      If the padded plaintext contains exactly eight octets, then
      prepend the AIV as defined in Section 3 above to P[1] and encrypt
      the resulting 128-bit block using AES in ECB mode [Modes] with key
      K (the KEK).  In this case, the output is two 64-bit blocks C[0]
      and C[1]:

         C[0] | C[1] = ENC(K, A | P[1]).

      Otherwise, apply the wrapping process specified in Section 2.2.1
      of [AES-KW2] to the padded plaintext {P[1], ..., P[n]} with K (the
      KEK) and the AIV as defined in Section 3 above as the initial
      value.  The result is n+1 64-bit blocks {C[0], C[1], ..., C[n]}.
*/
				// later output is returned. iv is encrypted also.
				output = this._algorithm.encryptBlock(Buffer.concat([iv, blocks[0]]));
			} else {
				for (var i = 0; i <= 5; i++) {
					for (var j = 0; j < n; j++) {
						var block = blocks[j];
						var b = this._algorithm.encryptBlock(Buffer.concat([iv, block]));
						var cnt = n * i + j + 1;
						var cnt_block = Buffer.alloc(block_size);
						// cnt should be saved as int64.
						// however, javascript does not support int64.
						// cnt is saved as big-endian array.
						cnt_block.writeInt32BE(cnt, 4, true);
						iv = Buffer.xor(b.slice(0, block_size), cnt_block);
						blocks[j] = Buffer.slice(b, b.length - block_size);
					}
				}

				output = Buffer.alloc(block_size * blocks.length);
				var pos = 0;
				for (var i = 0; i < blocks.length; i++) {
					output.set(blocks[i], pos);
					pos += block_size;
				}
				
				// concat iv before the output.
				output = Buffer.concat([iv, output]);
			}
			
			return output;
		} 
		else { // decryption
/*
http://www.ietf.org/rfc/rfc3394.txt

2.2.2 Key Unwrap

   The inputs to the unwrap process are the KEK and (n+1) 64-bit blocks
   of ciphertext consisting of previously wrapped key.  It returns n
   blocks of plaintext consisting of the n 64-bit blocks of the
   decrypted key data.

   Inputs:  Ciphertext, (n+1) 64-bit values {C0, C1, ..., Cn}, and
           Key, K (the KEK).
   Outputs: Plaintext, n 64-bit values {P1, P2, ..., Pn}.

   1) Initialize variables.

       Set A[s] = C[0] where s = 6n
       For i = 1 to n
           R[s][i] = C[i]

   2) Calculate the intermediate values.

       For t = s to 1
           A[t-1] = MSB(64, AES-1(K, ((A[t] ^ t) | R[t][n]))
           R[t-1][1] = LSB(64, AES-1(K, ((A[t]^t) | R[t][n]))
           For i = 2 to n
               R[t-1][i] = R[t][i-1]

   3) Output the results.

       If A[0] is an appropriate initial value (see 2.2.3),
       Then
           For i = 1 to n
               P[i] = R[0][i]
       Else
           Return an error

   The unwrap algorithm can also be specified as an index based
   operation, allowing the calculations to be carried out in place.
   Again, this produces the same results as the register shifting
   approach.

   Inputs:  Ciphertext, (n+1) 64-bit values {C0, C1, ..., Cn}, and
            Key, K (the KEK).
   Outputs: Plaintext, n 64-bit values {P0, P1, K, Pn}.

   1) Initialize variables.

       Set A = C[0]
       For i = 1 to n
           R[i] = C[i]

   2) Compute intermediate values.

       For j = 5 to 0
           For i = n to 1
               B = AES-1(K, (A ^ t) | R[i]) where t = n*j+i
               A = MSB(64, B)
               R[i] = LSB(64, B)

   3) Output results.

   If A is an appropriate initial value (see 2.2.3),
   Then
       For i = 1 to n
           P[i] = R[i]
   Else
       Return an error
*/
			var block_size = 8;

			if (!this._keydata.length || this._keydata.length % block_size) {
				throw jCastle.exception("INVALID_INPUT_SIZE", 'KWR002');
			}

			this._algorithm = new jCastle.algorithm[jCastle._algorithmInfo[this._algoName].object_name](this._algoName);
			this._algorithm.keySchedule(this._options.wrappingKey, false);

			var n = Math.ceil(this._keydata.length / block_size);
			var blocks = [];
			for (var i = 0; i < n; i++) {
				blocks[i] = this._keydata.slice(i * block_size, i * block_size + block_size);
			}
			
			var iv = blocks[0];

			if (n == 2) {
/*
http://www.rfc-base.org/txt/rfc-5649.txt

4.2.  Extended Key Unwrapping Process

   The inputs to the extended key unwrapping process are the KEK and
   (n+1) 64-bit ciphertext blocks consisting of a previously wrapped
   key.  If the ciphertext is a validly wrapped key, then the unwrapping
   process returns n 64-bit blocks of padded plaintext, which are then
   mapped in this extension to m octets of decrypted key data, as
   indicated by the MLI embedded in the AIV.

   Inputs:  Ciphertext, (n+1) 64-bit blocks {C[0], C[1], ..., C[n]}, and
            Key, K (the KEK).
   Outputs: Plaintext, m octets {Q[1], Q[2], ..., Q[m]}, or an error.

   1) Key unwrapping

      When n is one (n=1), the ciphertext contains exactly two 64-bit
      blocks (C[0] and C[1]), and they are decrypted as a single AES
      block using AES in ECB mode [Modes] with K (the KEK) to recover
      the AIV and the padded plaintext key:

         A | P[1] = DEC(K, C[0] | C[1]).

      Otherwise, apply Steps 1 and 2 of the unwrapping process specified
      in Section 2.2.2 of [AES-KW2] to the n+1 64-bit ciphertext blocks,
      {C[0], C[1], ..., C[n]}, and to the KEK, K.  Define the padded
      plaintext blocks, {P[1], ..., P[n]}, as specified in Step 3 of
      that process, with A[0] as the A value.  Note that checking "If
      A[0] is an appropriate value" is slightly delayed to Step 2 below
      since the padded plaintext is needed to perform this verification
      when the AIV is used.

   2) AIV verification

      Perform the three checks described in Section 3 above on the
      padded plaintext and the A value.  If any of the checks fail, then
      return an error.

   3) Remove padding

      Let m = the MLI value extracted from A.

      Let P = P[1] | P[2] | ... | P[n].

      For i = 1, ... , m
       Q[i] = LSB(8, MSB(8*i, P))
*/
				var b = this._algorithm.decryptBlock(Buffer.concat([iv, blocks[1]]));
				iv = b.slice(0, 8);
				output = Buffer.slice(b, 8);
			} else {
				for (var i = 5; i >= 0; i--) {
					for (var j = n - 1; j > 0; j--) {
						var cnt = (n - 1) * i + j;
						var cnt_block = Buffer.alloc(block_size);
						// cnt is saved as int64. here the lower part is only saved.
						cnt_block.writeInt32BE(cnt, 4);
						iv = Buffer.xor(iv, cnt_block);
						var block = blocks[j];
						var b = this._algorithm.decryptBlock(Buffer.concat([iv, block]));
						
						iv = b.slice(0, block_size);
						blocks[j] = Buffer.slice(b, -block_size);
					}
				}

				output = Buffer.alloc(block_size * (blocks.length - 1));
				var pos = 0;
				for (var i = 1; i < blocks.length; i++) {
					output.set(blocks[i], pos);
					pos += block_size;
				}
			}

/*
http://www.ietf.org/rfc/rfc3394.txt

2.2.3 Key Data Integrity -- the Initial Value

   The initial value (IV) refers to the value assigned to A[0] in the
   first step of the wrapping process.  This value is used to obtain an
   integrity check on the key data.  In the final step of the unwrapping
   process, the recovered value of A[0] is compared to the expected
   value of A[0].  If there is a match, the key is accepted as valid,
   and the unwrapping algorithm returns it.  If there is not a match,
   then the key is rejected, and the unwrapping algorithm returns an
   error.

   The exact properties achieved by this integrity check depend on the
   definition of the initial value.  Different applications may call for
   somewhat different properties; for example, whether there is need to
   determine the integrity of key data throughout its lifecycle or just
   when it is unwrapped.  This specification defines a default initial
   value that supports integrity of the key data during the period it is
   wrapped (2.2.3.1).  Provision is also made to support alternative
   initial values (in 2.2.3.2).
*/

//console.log(iv.toHex());

			if (!iv.equals(Buffer.from('A6A6A6A6A6A6A6A6', 'hex'))) {
				if (iv.slice(0, 4).equals(Buffer.from('A65959A6', 'hex'))) {
					var length = iv.readInt32BE(4);
					var padding = block_size - (length % block_size);
                    // console.log(padding);
					if (padding >= output.length) {
						throw jCastle.exception("IV_CHECK_FAIL", 'KWR003');
					}

					output = Buffer.slice(output, 0, output.length - padding);
				} else {
					throw jCastle.exception("IV_CHECK_FAIL", 'KWR004');
				}
			}


			return output;
		}
	}

	_des3Wrapper()
	{
		if (this._options.isEncryption) {

/*
https://tools.ietf.org/html/rfc3217

2  Key Checksum

   The key checksum algorithm is used to provide a key integrity check
   value.  The algorithm is:

   1. Compute a 20 octet SHA-1 [SHA1] message digest on the key that is
      to be wrapped.
   2. Use the most significant (first) eight octets of the message
      digest value as the checksum value.

3  Triple-DES Key Wrapping and Unwrapping

   This section specifies the algorithms for wrapping and unwrapping one
   Triple-DES key with another Triple-DES key [3DES].

   The same key wrap algorithm is used for both Two-key Triple-DES and
   Three-key Triple-DES keys.  When a Two-key Triple-DES key is to be
   wrapped, a third DES key with the same value as the first DES key is
   created.  Thus, all wrapped Triple-DES keys include three DES keys.
   However, a Two-key Triple-DES key MUST NOT be used to wrap a Three-
   key Triple-DES key that is comprised of three unique DES keys.

3.1  Triple-DES Key Wrap

   The Triple-DES key wrap algorithm encrypts a Triple-DES key with a
   Triple-DES key-encryption key.  The Triple-DES key wrap algorithm is:

   1. Set odd parity for each of the DES key octets comprising the
      Three-Key Triple-DES key that is to be wrapped, call the result
      CEK.
   2. Compute an 8 octet key checksum value on CEK as described above in
      Section 2, call the result ICV.
   3. Let CEKICV = CEK || ICV.
   4. Generate 8 octets at random, call the result IV.
   5. Encrypt CEKICV in CBC mode using the key-encryption key.  Use the
      random value generated in the previous step as the initialization
      vector (IV).  Call the ciphertext TEMP1.
   6. Let TEMP2 = IV || TEMP1.
   7. Reverse the order of the octets in TEMP2.  That is, the most
      significant (first) octet is swapped with the least significant
      (last) octet, and so on.  Call the result TEMP3.
   8. Encrypt TEMP3 in CBC mode using the key-encryption key.  Use an
      initialization vector (IV) of 0x4adda22c79e82105.  The ciphertext
      is 40 octets long.

   Note:  When the same Three-Key Triple-DES key is wrapped in different
   key-encryption keys, a fresh initialization vector (IV) must be
   generated for each invocation of the key wrap algorithm.
*/
			var cek = this._keydata;
			var icv = jCastle.digest.create('sha-1').digest(cek).slice(0, 8);
			var cekicv = Buffer.concat([cek, icv]);
            var iv;
			if (this._options.iv) iv = Buffer.from(this._options.iv);
			else {
				var prng = jCastle.prng.create();
				iv = prng.nextBytes(8);
			}

			var crypto = jCastle.mcrypt.create(this._algoName);
			var params = {
				key: this._options.wrappingKey,
				iv: iv,
				mode: 'cbc',
				isEncryption: true,
				padding: 'zeros'
			};
			var temp1 = crypto.start(params).update(cekicv).finalize();
			var temp2 = Buffer.concat([iv, temp1]);
			temp2.reverse();

			params.iv = Buffer.from('4adda22c79e82105', 'hex');
			var output = crypto.start(params).update(temp2).finalize();

			return output;
		} else {
/*
https://tools.ietf.org/html/rfc3217

3.2  Triple-DES Key Unwrap

   The Triple-DES key unwrap algorithm decrypts a Triple-DES key using a
   Triple-DES key-encryption key.  The Triple-DES key unwrap algorithm
   is:

   1. If the wrapped key is not 40 octets, then error.
   2. Decrypt the wrapped key in CBC mode using the key-encryption key.
      Use an initialization vector (IV) of 0x4adda22c79e82105.  Call the
      output TEMP3.
   3. Reverse the order of the octets in TEMP3.  That is, the most
      significant (first) octet is swapped with the least significant
      (last) octet, and so on.  Call the result TEMP2.
   4. Decompose TEMP2 into IV and TEMP1.  IV is the most significant
      (first) 8 octets, and TEMP1 is the least significant (last) 32
      octets.
   5. Decrypt TEMP1 in CBC mode using the key-encryption key.  Use the
      IV value from the previous step as the initialization vector.
      Call the ciphertext CEKICV.
   6. Decompose CEKICV into CEK and ICV.  CEK is the most significant
      (first) 24 octets, and ICV is the least significant (last) 8
      octets.
   7. Compute an 8 octet key checksum value on CEK as described above in
      Section 2.  If the computed key checksum value does not match the
      decrypted key checksum value, ICV, then error.
   8. Check for odd parity each of the DES key octets comprising CEK.
      If parity is incorrect, then error.
   9. Use CEK as a Triple-DES key.
*/
			jCastle.assert(this._keydata.length, 40, 'INVALID_WRAPPED_KEYSIZE', 'KWR005');

			var params = {
				key: this._options.wrappingKey,
				iv: Buffer.from('4adda22c79e82105', 'hex'),
				mode: 'cbc',
				isEncryption: false,
				padding: 'zeros'
			};

			var crypto = jCastle.mcrypt.create(this._algoName);
			var temp2 = crypto.start(params).update(this._keydata).finalize();
			temp2.reverse();
			var iv = temp2.slice(0, 8);
			var temp1 = temp2.slice(8);
			
			params.iv = iv;
			var cekicv = crypto.start(params).update(temp1).finalize();
			var cek = Buffer.slice(cekicv, 0, 24);
			var icv = cekicv.slice(24);
			var icv_chk = jCastle.digest.create('sha-1').digest(cek).slice(0, 8);

			if (!icv.equals(icv_chk)) throw jCastle.exception("ICV_CHECK_FAIL", 'KWR006');

			return cek;
		}
	}

	_rc2Wrapper()
	{
		// SHA1 digest and the following Ciphers in CBC mode - DESede cipher and
		// RC2 Cipher with 40-bit effective key length as defined by PKCS #12 version 1.0 standard.
		var ekb = 40; // effectiveKeyBits
		if ('effectiveKeyBits' in this._options) ekb = this._options.effectiveKeyBits;

		if (this._options.isEncryption) {
/*
https://tools.ietf.org/html/rfc3217

4  RC2 Key Wrapping and Unwrapping

   This section specifies the algorithms for wrapping and unwrapping one
   RC2 key with another RC2 key [RC2].

   RC2 supports variable length keys.  RC2 128-bit keys MUST be used as
   key-encryption keys; however, the wrapped RC2 key MAY be of any size.

4.1  RC2 Key Wrap

   The RC2 key wrap algorithm encrypts a RC2 key with a RC2 key-
   encryption key.  The RC2 key wrap algorithm is:

   1.  Let the RC2 key be called CEK, and let the length of CEK in
       octets be called LENGTH.  LENGTH is a single octet.
   2.  Let LCEK = LENGTH || CEK.
   3.  Let LCEKPAD = LCEK || PAD.  If the length of LCEK is a multiple
       of 8, the PAD has a length of zero.  If the length of LCEK is not
       a multiple of 8, then PAD contains the fewest number of random
       octets to make the length of LCEKPAD a multiple of 8.
   4.  Compute an 8 octet key checksum value on LCEKPAD as described
       above in Section 2, call the result ICV.
   5.  Let LCEKPADICV = LCEKPAD || ICV.
   6.  Generate 8 octets at random, call the result IV.
   7.  Encrypt LCEKPADICV in CBC mode using the key-encryption key.  Use
       the random value generated in the previous step as the
       initialization vector (IV).  Call the ciphertext TEMP1.
   8.  Let TEMP2 = IV || TEMP1.
   9.  Reverse the order of the octets in TEMP2.  That is, the most
       significant (first) octet is swapped with the least significant
       (last) octet, and so on.  Call the result TEMP3.
   10. Encrypt TEMP3 in CBC mode using the key-encryption key.  Use an
       initialization vector (IV) of 0x4adda22c79e82105.

   Note:  When the same RC2 key is wrapped in different key-encryption
   keys, a fresh initialization vector (IV) must be generated for each
   invocation of the key wrap algorithm.
*/
			var prng = jCastle.prng.create();
			var block_size = jCastle._algorithmInfo[this._algoName].block_size;
			
			var cek = this._keydata;
			var len = cek.length;
			var lcek_len = 1 + len;
			while (lcek_len % 8) lcek_len++;
			var lcek = Buffer.alloc(lcek_len);
			lcek[0] = len;
			lcek.set(cek, 1);
			
			var pads = lcek_len - 1 - len;

/*
// for test. 
// see keywrap_test.html

			if (pads) {
				if ('customPaddingForTest' in this._options) {
					var test_padding = Buffer.from(this._options.customPaddingForTest);
					if (test_padding.length != pads)
						throw jCastle.exception("INVALID_PADDING", 'KWR009');
					lcek.set(test_padding, 1 + len);
				} else {
					lcek.set(prng.nextBytes(pads), 1 + len);
				}
			}
*/			
			if (pads) lcek.set(prng.nextBytes(pads), 1 + len);

			var icv = jCastle.digest.create('sha-1').digest(lcek).slice(0, 8);
			var lcekicv = Buffer.concat([lcek, icv]);
            var iv;

			if (this._options.iv) iv = Buffer.from(this._options.iv);
			else {
				iv = prng.nextBytes(block_size);
			}
			
			var crypto = jCastle.mcrypt.create(this._algoName);
			var params = {
				key: this._options.wrappingKey,
				effectiveKeyBits: ekb,
				iv: iv,
				mode: 'cbc',
				isEncryption: true,
				padding: 'zeros'
			};

			var temp1 = crypto.start(params).update(lcekicv).finalize();
			var temp2 = Buffer.concat([iv, temp1]);
			temp2.reverse();

			params.iv = Buffer.from('4adda22c79e82105', 'hex');
			var output = crypto.start(params).update(temp2).finalize();

			return output;

		} else {
/*
https://tools.ietf.org/html/rfc3217

4.2  RC2 Key Unwrap

   The RC2 key unwrap algorithm decrypts a RC2 key using a RC2 key-
   encryption key.  The RC2 key unwrap algorithm is:

   1.  If the wrapped key is not a multiple of 8 octets, then error.
   2.  Decrypt the wrapped key in CBC mode using the key-encryption key.
       Use an initialization vector (IV) of 0x4adda22c79e82105.  Call
       the output TEMP3.
   3.  Reverse the order of the octets in TEMP3.  That is, the most
       significant (first) octet is swapped with the least significant
       (last) octet, and so on.  Call the result TEMP2.
   4.  Decompose the TEMP2 into IV and TEMP1.  IV is the most
       significant (first) 8 octets, and TEMP1 is the remaining octets.
   5.  Decrypt TEMP1 in CBC mode using the key-encryption key.  Use the
       IV value from the previous step as the initialization vector.
       Call the plaintext LCEKPADICV.
   6.  Decompose the LCEKPADICV into LCEKPAD, and ICV.  ICV is the least
       significant (last) octet 8 octets.  LCEKPAD is the remaining
       octets.
   7.  Compute an 8 octet key checksum value on LCEKPAD as described
       above in Section 2.  If the computed key checksum value does not
       match the decrypted key checksum value, ICV, then error.
   8.  Decompose the LCEKPAD into LENGTH, CEK, and PAD.  LENGTH is the
       most significant (first) octet.  CEK is the following LENGTH
       octets.  PAD is the remaining octets, if any.
   9.  If the length of PAD is more than 7 octets, then error.
   10. Use CEK as an RC2 key.
*/
			jCastle.assert(this._keydata.length % 8, 0, 'INVALID_WRAPPED_KEYSIZE', 'KWR007');

			var params = {
				key: this._options.wrappingKey,
				effectiveKeyBits: ekb,
				iv: Buffer.from('4adda22c79e82105', 'hex'),
				mode: 'cbc',
				isEncryption: false,
				padding: 'zeros'
			};

			var block_size = jCastle._algorithmInfo[this._algoName].block_size;
			var crypto = jCastle.mcrypt.create(this._algoName);
			var temp2 = crypto.start(params).update(this._keydata).finalize();
			temp2.reverse();
			var iv = temp2.slice(0, block_size);
			var temp1 = temp2.slice(block_size);
			
			params.iv = iv;
			var lcekicv = crypto.start(params).update(temp1).finalize();
			var lcek = lcekicv.slice(0, lcekicv.length - 8);
			var icv = lcekicv.slice(lcekicv.length - 8);
			var icv_chk = jCastle.digest.create('sha-1').digest(lcek).slice(0, 8);

			if (!icv.equals(icv_chk)) throw jCastle.exception("ICV_CHECK_FAIL", 'KWR008');

			// lcek[0] is the length of cek.
			var cek = Buffer.slice(lcek, 1, lcek[0] + 1);

			return cek;
		}
	}

};

/**
 * creates a new class instance.
 * 
 * @public
 * @param {string} algo_name algorithm name
 * @returns this class instance.
 */
jCastle.keywrap.create = function(algo_name)
{
	return new jCastle.keywrap(algo_name);
};

/**
 * creates a new class instance and start the wrapping process.
 * 
 * @public
 * @param {object} options options object.
 * @returns this class instance.
 */
jCastle.keywrap.start = function(options)
{
    return new jCastle.keywrap().start(options);
};

/**
 * gets the object id of the wrap algorithm.
 * 
 * @public
 * @param {string} algo algorithm name
 * @returns the object id of the wrap algorithm.
 */
jCastle.keywrap.getOID = function(algo)
{
	algo = jCastle.mcrypt.getValidAlgoName(algo);

	switch(algo) {
		case 'aes-128': return "2.16.840.1.101.3.4.1.5"; // aes-128-wrap
		case 'aes-192': return "2.16.840.1.101.3.4.1.25";
		case 'aes-256': return "2.16.840.1.101.3.4.1.45";
		case 'seed':
		case 'seed-128': return "1.2.410.200004.7.1.1.1"; // npkiCmsSEEDwrap
		case 'aria-128': return "1.2.410.200046.1.1.40"; // aria-128-keywrap
		case 'aria-192': return "1.2.410.200046.1.1.41";
		case 'aria-256': return "1.2.410.200046.1.1.42";
		case '3des':
		case 'des3':
		case 'des-ede3':
        case '3des-ede':
		case 'tripledes': return "1.2.840.113549.1.9.16.3.6"; // cms3DESwrap
        case 'rc2-128':
		case 'rc2': return "1.2.840.113549.1.9.16.3.7"; // cmsRC2wrap
		case 'gost': return "1.2.643.2.2.13.0"; // gostwrap
	}

	return null;
};

/**
 * gets the wrap algorithm name.
 * 
 * @public
 * @param {string} algo algorithm name
 * @returns the wrap algorithm name.
 */
jCastle.keywrap.getWrapName = function(algo)
{
	algo = jCastle.mcrypt.getValidAlgoName(algo);

	switch(algo) {
		case 'aes-128':
		case 'aes-192':
		case 'aes-256': return algo + '-wrap';
		case 'seed':
		case 'seed-128': return "npkiCmsSEEDwrap";
		case 'aria-128':
		case 'aria-192':
		case 'aria-256': return algo + '-keywrap';
		case '3des':
		case 'des3':
		case 'des-ede3':
		case 'tripledes': return "cms3DESwrap";
		case 'rc2': return "cmsRC2wrap";
		case 'gost': return "gostwrap";
	}

	return null;
};

/**
 * gets the base algorithm name from the wrap algorithm.
 * 
 * @public
 * @param {string} wrap_algo wrap algorithm name.
 * @returns the algorithm name.
 */
jCastle.keywrap.getAlgoName = function(wrap_algo)
{
	var m = /(npki)?(cms)?([a-z0-9]+([\-]{0,1}[0-9]+)?)(\-)?(key)?wrap/i.exec(wrap_algo); // cms3DESwrap, npkiCmsSEEDwrap, aes-128-wrap
//console.log(m);
	return jCastle.mcrypt.getValidAlgoName(m[3]);
};

jCastle.KeyWrap = jCastle.keyWrap = jCastle.keywrap;

module.exports = jCastle.keywrap;