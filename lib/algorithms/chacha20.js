/**
 * Javascript jCastle Mcrypt Module - Chacha20
 * 
 * @author Jacob Lee
 *
 * Copyright (C) 2015-2022 Jacob Lee.
 */

/*
https://tools.ietf.org/html/draft-irtf-cfrg-chacha20-poly1305-01
*/
var jCastle = require('../jCastle');
require('../util');

jCastle.algorithm.chacha20 = class
{
	/**
	 * creates the algorithm instance.
	 * 
	 * @param {string} algo_name algorithm name
	 * @param {object} options options object
	 * @constructor
	 */
    constructor(algo_name, options = {})
    {
        this.algoName = algo_name;
        this.masterKey = null;
        this.roundKey = null;
        this.useInitialVector = false;
        this.initialVector = null;
        this.rounds = 20;
        this.counter = 0;

/*
The inputs to ChaCha20 are:
o  A 256-bit key, treated as a concatenation of 8 32-bit little-
	endian integers.
o  A 96-bit nonce, treated as a concatenation of 3 32-bit little-
	endian integers.
o  A 32-bit block count parameter, treated as a 32-bit little-endian
	integer.
*/
        if ('counter' in options) this.counter = options.counter;
        if ('rounds' in options) this.rounds = options.rounds;
    }

	/**
	 * validate the key size.
	 * 
	 * @public
	 * @param {buffer} key 
	 * @returns true if the key size is valid.
	 */
	isValidKeySize(key)
	{
		if (jCastle._algorithmInfo[this.algoName].min_key_size == jCastle._algorithmInfo[this.algoName].max_key_size) {
			if (key.length != jCastle._algorithmInfo[this.algoName].key_size) {
				return false;
			}
		} else {
			if (key.length > jCastle._algorithmInfo[this.algoName].max_key_size) {
				return false;
			}
			if (key.length < jCastle._algorithmInfo[this.algoName].min_key_size) {
				return false;
			}
			if (typeof jCastle._algorithmInfo[this.algoName].key_sizes != 'undefined' &&
            !jCastle._algorithmInfo[this.algoName].key_sizes.includes(key.length)
			) {
				return false;			
			}
		}
		return true;
	}

	/**
	 * resets internal variables except algoName.
	 * 
	 *  @public
	 */
	reset()
	{
		this.masterKey = null;
		this.roundKey = null;
		this.useInitialVector = false;
		this.initialVector = null;
		this.rounds = 20;
		this.counter = 0;

		return this;
	}

	/**
	 * get the key.
	 * 
	 * @public
	 * @returns the masterKey.
	 */
    getKey()
	{
		return this.masterKey;
	}

	/**
	 * get the block size.
	 * 
	 * @public
	 * @returns the block size.
	 */
	getBlockSize()
	{
		return jCastle._algorithmInfo[this.algoName].block_size;
	}

	/**
	 * sets the initial vector.
	 * 
	 * @public
	 * @param {buffer} IV initial vector.
	 * @returns this class instance.
	 */
	setInitialVector(IV)
	{
		var iv = Buffer.from(IV, 'latin1');

		if (iv.length != jCastle._algorithmInfo[this.algoName].stream_iv_size) { // 12
			throw jCastle.exception("INVALID_IV", 'CHA001');
		}

		this.initialVector = iv;
		this.useInitialVector = true;

		return this;
	}

	/**
	 * alias for setInitialVector()
	 * 
	 * @public
	 * @param {buffer} IV initial vector.
	 * @returns this class instance.
	 */
	setNonce(IV)
	{
		return this.setInitialVector(IV);
	}

	/**
	 * sets the number of rounds
	 * 
	 * @public
	 * @param {number} rounds 
	 * @returns this class instance.
	 */
	setRounds(rounds)
	{
		if (jCastle.util.isInteger(rounds) && rounds > 0) {
			this.rounds = rounds;
		} else {
			throw jCastle.exception("INVALID_ROUNDS", 'CHA002');
		}

		return this;
	}

	/**
	 * sets the number of the counter.
	 * 
	 * @public
	 * @param {number} counter counter number
	 * @returns this class instance.
	 */
	setCounter(counter)
	{
		if (jCastle.util.isInteger(counter)) {
			this.counter = counter;
		} else {
			throw jCastle.exception("INVALID_COUNTER", 'CHA003');
		}

		return this;
	}

	/**
	 * makes round key for encryption/decryption.
	 *
	 * @public
	 * @param {buffer} key encryption/decryption key.
	 * @param {boolean} isEncryption if encryption then true, otherwise false.
	 */
	keySchedule(key, isEncryption)
	{
		this.masterKey = Buffer.from(key, 'latin1');
		
		this.expandKey(this.masterKey);

		return this;
	}

	/**
	 * encrypts a block.
	 * 
	 * @public
	 * @param {buffer} input input data to be encrypted.
	 * @returns encrypted block in buffer.
	 */
	encryptBlock(input)
	{
		return this.cryptBlock(input);
	}

	/**
	 * decrypts a block.
	 * 
	 * @public
	 * @param {buffer} input input data to be decrypted.
	 * @returns the decrypted block in buffer.
	 */
	decryptBlock(input)
	{
		return this.cryptBlock(input);
	}

	/**
	 * crypt the input data. this is the stream cipher function.
	 * 
	 * @public
	 * @param {buffer} input input data to be crypted.
	 * @returns crypted data in buffer.
	 */
	crypt(input)
	{
		var blockSize = jCastle._algorithmInfo[this.algoName].stream_block_size;
		var len = input.length;
		var output = Buffer.alloc(len);

		for (var i = 0; i < len; i += blockSize) {
			output.set(this.cryptBlock(input.slice(i, i + blockSize)), i);
		}
		
		return output;
	}

/*
   The ChaCha20 state is initialized as follows:
   o  The first 4 words (0-3) are constants: 0x61707865, 0x3320646e,
      0x79622d32, 0x6b206574.
   o  The next 8 words (4-11) are taken from the 256-bit key by reading
      the bytes in little-endian order, in 4-byte chunks.
   o  Word 12 is a block counter.  Since each block is 64-byte, a 32-bit
      word is enough for 256 Gigabytes of data.
   o  Words 13-15 are a nonce, which should not be repeated for the same
      key.  The 13th word is the first 32 bits of the input nonce taken
      as a little-endian integer, while the 15th word is the last 32
      bits.

       cccccccc  cccccccc  cccccccc  cccccccc
       kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
       kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
       bbbbbbbb  nnnnnnnn  nnnnnnnn  nnnnnnnn

   c=constant k=key b=blockcount n=nonce
*/
	/**
	 * Calculate the necessary round keys.
	 * The number of calculations depends on key size and block size.
	 * 
	 * @private
	 * @param {buffer} key key for encryption/decryption.
	 * @param {boolean} isEncryption true if it is encryption, otherwise false.
	 */
	expandKey(key, isEncryption)
	{
		// check iv
		if (!this.useInitialVector ||this.initialVector.length != 12) {
			throw jCastle.exception("INVALID_IV");
		}

		// 0 .. 3
		this.roundKey = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

		// 4 .. 11
		for (var i = 0; i < key.length; i += 4) {
			this.roundKey.push(key.readInt32LE(i));
		}

		// 12
		this.roundKey.push(this.counter);

		// 13 .. 15
		for (var i = 0; i < this.initialVector.length; i += 4) {
			this.roundKey.push(this.initialVector.readInt32LE(i));
		}
	}

/*
   The basic operation of the ChaCha algorithm is the quarter round.  It
   operates on four 32-bit unsigned integers, denoted a, b, c, and d.
   The operation is as follows (in C-like notation):
   o  a += b; d ^= a; d <<<= 16;
   o  c += d; b ^= c; b <<<= 12;
   o  a += b; d ^= a; d <<<= 8;
   o  c += d; b ^= c; b <<<= 7;
   Where "+" denotes integer addition modulo 2^32, "^" denotes a bitwise
   XOR, and "<<< n" denotes an n-bit left rotation (towards the high
   bits).
*/
	quarterRound(x, a, b, c, d)
	{
		var safeAdd = jCastle.util.safeAdd32;
		var rotl = jCastle.util.rotl32;

		x[a] = safeAdd(x[a], x[b]); 
		x[d] = rotl(x[d] ^ x[a], 16);
		x[c] = safeAdd(x[c], x[d]);
		x[b] = rotl(x[b] ^ x[c], 12);
		x[a] = safeAdd(x[a], x[b]);
		x[d] = rotl(x[d] ^ x[a],  8);
		x[c] = safeAdd(x[c], x[d]);
		x[b] = rotl(x[b] ^ x[c],  7);
	}


/*
   ChaCha20 runs 20 rounds, alternating between "column" and "diagonal"
   rounds.  Each round is 4 quarter-rounds, and they are run as follows.
   Quarter-rounds 1-4 are part of a "column" round, while 5-8 are part
   of a "diagonal" round:
   1.  QUARTERROUND ( 0, 4, 8,12)
   2.  QUARTERROUND ( 1, 5, 9,13)
   3.  QUARTERROUND ( 2, 6,10,14)
   4.  QUARTERROUND ( 3, 7,11,15)
   5.  QUARTERROUND ( 0, 5,10,15)
   6.  QUARTERROUND ( 1, 6,11,12)
   7.  QUARTERROUND ( 2, 7, 8,13)
   8.  QUARTERROUND ( 3, 4, 9,14)

   At the end of 20 rounds, we add the original input words to the
   output words, and serialize the result by sequencing the words one-
   by-one in little-endian order.

   Note: "addition" in the above paragraph is done modulo 2^32.  In some
   machine languages this is called carryless addition on a 32-bit word.
*/
	/**
	 * crypt the block sized data. chacha20 has a stream block size.
	 * 
	 * @public
	 * @param {buffer} input input data to be crypted.
	 * @returns the crypted data in buffer.
	 */
	cryptBlock(input)
	{
		// the input size is will be 64 bytes or under.
		// Chacha20 has 64 bytes stream block(16 blocks of 32-bit integers).
		var safeAdd = jCastle.util.safeAdd32;
		var x = this.roundKey.slice(0);

		for (var r = 0; r < this.rounds; r += 2) {
			this.quarterRound(x, 0, 4, 8, 12);
			this.quarterRound(x, 1, 5, 9, 13);
			this.quarterRound(x, 2, 6,10, 14);
			this.quarterRound(x, 3, 7,11, 15);
			this.quarterRound(x, 0, 5,10, 15);
			this.quarterRound(x, 1, 6,11, 12);
			this.quarterRound(x, 2, 7, 8, 13);
			this.quarterRound(x, 3, 4, 9, 14);
		}

		for (var i = 0; i < x.length; i++) {
			x[i] += this.roundKey[i];
		}

		var x_block = Buffer.alloc(x.length * 4);
		for (var i = 0, j = 0; i < x_block.length; i += 4) {
			x_block.writeInt32LE(x[j++] & 0xffffffff, i);
		}


		// counter block
		this.roundKey[12] = safeAdd(this.roundKey[12], 1);
		if (this.roundKey[12] === 0) {
			this.roundKey[13] += 1;
		}

		var output = Buffer.alloc(input.length);;

		for (var i = 0; i < input.length; i++) {
			output[i] = (input[i] ^ x_block[i]) & 0xff;
		}

		return output;
	}
}


jCastle._algorithmInfo['chacha20'] = {
	algorithm_type: 'crypt',
	block_size: 1,
	stream_block_size: 64,
	stream_iv_size: 12,
	key_size: 32,
	min_key_size: 32,
	max_key_size: 32,
	padding: 'zeros',
	object_name: 'chacha20'
};


/*
https://tools.ietf.org/html/rfc7539

2.6.1.  Poly1305 Key Generation in Pseudocode

      poly1305_key_gen(key,nonce):
         counter = 0
         block = chacha20_block(key,counter,nonce)
         return block[0..31]
         end

2.6.2.  Poly1305 Key Generation Test Vector

   For this example, we'll set:

  Key:
  000  80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f  ................
  016  90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f  ................

   Nonce:
   000  00 00 00 00 00 01 02 03 04 05 06 07              ............

   The ChaCha state setup with key, nonce, and block counter zero:
         61707865  3320646e  79622d32  6b206574
         83828180  87868584  8b8a8988  8f8e8d8c
         93929190  97969594  9b9a9998  9f9e9d9c
         00000000  00000000  03020100  07060504

   The ChaCha state after 20 rounds:
         8ba0d58a  cc815f90  27405081  7194b24a
         37b633a8  a50dfde3  e2b8db08  46a6d1fd
         7da03782  9183a233  148ad271  b46773d1
         3cc1875a  8607def1  ca5c3086  7085eb87

  Output bytes:
  000  8a d5 a0 8b 90 5f 81 cc 81 50 40 27 4a b2 94 71  ....._...P@'J..q
  016  a8 33 b6 37 e3 fd 0d a5 08 db b8 e2 fd d1 a6 46  .3.7...........F

   And that output is also the 32-byte one-time key used for Poly1305.

2.7.  A Pseudorandom Function for Crypto Suites based on ChaCha/Poly1305

   Some protocols, such as IKEv2 ([RFC7296]), require a Pseudorandom
   Function (PRF), mostly for key derivation.  In the IKEv2 definition,
   a PRF is a function that accepts a variable-length key and a
   variable-length input, and returns a fixed-length output.  Most
   commonly, Hashed MAC (HMAC) constructions are used for this purpose,
   and often the same function is used for both message authentication
   and PRF.

   Poly1305 is not a suitable choice for a PRF.  Poly1305 prohibits
   using the same key twice, whereas the PRF in IKEv2 is used multiple
   times with the same key.  Additionally, unlike HMAC, Poly1305 is
   biased, so using it for key derivation would reduce the security of
   the symmetric encryption.

   Chacha20 could be used as a key-derivation function, by generating an
   arbitrarily long keystream.  However, that is not what protocols such
   as IKEv2 require.

   For this reason, this document does not specify a PRF and recommends
   that crypto suites use some other PRF such as PRF_HMAC_SHA2_256 (see
   Section 2.1.2 of [RFC4868]).

*/

jCastle.algorithm.chacha20.poly1305GenerateKey = function(key, nonce)
{
	var algorithm = new jCastle.algorithm.chacha20('chacha20');
	algorithm.setInitialVector(nonce);
	algorithm.keySchedule(key, true);
	var block = algorithm.cryptBlock(Buffer.alloc(64));

	return Buffer.slice(block, 0, 32);
};

module.exports = jCastle.algorithm.chacha20;