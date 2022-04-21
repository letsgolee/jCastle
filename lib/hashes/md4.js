/**
 * A Javascript implemenation of MD4
 * 
 * @author Jacob Lee
 * 
 * Copyright (C) 2015-2022 Jacob Lee.
 */

var jCastle = require('../jCastle');
require('../util');

jCastle.algorithm.md4 = class
{
	/**
	 * creates the hash algorithm instance.
	 * 
	 * @param {string} hash_name hash algorithm name
	 * @constructor
	 */
    constructor(hash_name)
    {
        this.algoName = hash_name;
        this._state = null;
    }

	/**
	 * get the block size in bits.
	 * 
	 * @public
	 * @returns the block size in bits.
	 */
	getBlockSize()
	{
		return jCastle._algorithmInfo[this.algoName].block_size; // bits
	}

	/**
	 * get the bytes length of the hash algorithm
	 * 
	 * @public
	 * @returns the hash bytes length.
	 */
	getDigestLength()
	{
		return jCastle._algorithmInfo[this.algoName].digest_size; // bytes
	}

	/**
	 * initialize the hash algorithm and sets state with initial value.
	 * 
	 * @public
	 * @param {object} options options object
	 */
	init(options = {})
	{
		this._state = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];
	}

	/**
	 * processes digesting.
	 * 
	 * @public
	 * @param {buffer} input input data to be digested.
	 */
	process(input)
	{
		var safeAdd = jCastle.util.safeAdd32;
		var rotl = jCastle.util.rotl32;
		var H = this._state;

		function FF(a, b, c, d, x, s) {
			a = safeAdd(a, safeAdd(d ^ (b & (c ^ d)), x));
			a = rotl(a, s);
			return a;
		}
		function GG(a, b, c, d, x, s) {
			a = safeAdd(a, safeAdd(safeAdd((b & c) | (d & (b | c)), x), 0x5a827999));
			a = rotl(a, s);
			return a;
		}
		function HH(a, b, c, d, x, s) {
			a = safeAdd(a, safeAdd(safeAdd(b ^ c ^ d, x), 0x6ed9eba1));
			a = rotl(a, s);
			return a;
		}


		var a, b, c, d;

		var block = [];
		var block_size = jCastle._algorithmInfo[this.algoName].block_size;
		for (var i = 0; i < block_size / 4; i++) {
			block[i] = input.readInt32LE(i * 4);
		}

		/* copy state */
		a = H[0];
		b = H[1];
		c = H[2];
		d = H[3];
	 
		/* Round 1 */ 
		a = FF(a, b, c, d, block[ 0], 3); /* 1 */ 
		d = FF(d, a, b, c, block[ 1], 7); /* 2 */ 
		c = FF(c, d, a, b, block[ 2], 11); /* 3 */ 
		b = FF(b, c, d, a, block[ 3], 19); /* 4 */ 
		a = FF(a, b, c, d, block[ 4], 3); /* 5 */ 
		d = FF(d, a, b, c, block[ 5], 7); /* 6 */ 
		c = FF(c, d, a, b, block[ 6], 11); /* 7 */ 
		b = FF(b, c, d, a, block[ 7], 19); /* 8 */ 
		a = FF(a, b, c, d, block[ 8], 3); /* 9 */ 
		d = FF(d, a, b, c, block[ 9], 7); /* 10 */
		c = FF(c, d, a, b, block[10], 11); /* 11 */ 
		b = FF(b, c, d, a, block[11], 19); /* 12 */
		a = FF(a, b, c, d, block[12], 3); /* 13 */
		d = FF(d, a, b, c, block[13], 7); /* 14 */ 
		c = FF(c, d, a, b, block[14], 11); /* 15 */ 
		b = FF(b, c, d, a, block[15], 19); /* 16 */ 
		
		/* Round 2 */ 
		a = GG(a, b, c, d, block[ 0], 3); /* 17 */ 
		d = GG(d, a, b, c, block[ 4], 5); /* 18 */ 
		c = GG(c, d, a, b, block[ 8], 9); /* 19 */ 
		b = GG(b, c, d, a, block[12], 13); /* 20 */ 
		a = GG(a, b, c, d, block[ 1], 3); /* 21 */ 
		d = GG(d, a, b, c, block[ 5], 5); /* 22 */ 
		c = GG(c, d, a, b, block[ 9], 9); /* 23 */ 
		b = GG(b, c, d, a, block[13], 13); /* 24 */ 
		a = GG(a, b, c, d, block[ 2], 3); /* 25 */ 
		d = GG(d, a, b, c, block[ 6], 5); /* 26 */ 
		c = GG(c, d, a, b, block[10], 9); /* 27 */ 
		b = GG(b, c, d, a, block[14], 13); /* 28 */ 
		a = GG(a, b, c, d, block[ 3], 3); /* 29 */ 
		d = GG(d, a, b, c, block[ 7], 5); /* 30 */ 
		c = GG(c, d, a, b, block[11], 9); /* 31 */ 
		b = GG(b, c, d, a, block[15], 13); /* 32 */ 
			
		/* Round 3 */
		a = HH(a, b, c, d, block[ 0], 3); /* 33 */ 
		d = HH(d, a, b, c, block[ 8], 9); /* 34 */ 
		c = HH(c, d, a, b, block[ 4], 11); /* 35 */ 
		b = HH(b, c, d, a, block[12], 15); /* 36 */ 
		a = HH(a, b, c, d, block[ 2], 3); /* 37 */ 
		d = HH(d, a, b, c, block[10], 9); /* 38 */ 
		c = HH(c, d, a, b, block[ 6], 11); /* 39 */ 
		b = HH(b, c, d, a, block[14], 15); /* 40 */ 
		a = HH(a, b, c, d, block[ 1], 3); /* 41 */ 
		d = HH(d, a, b, c, block[ 9], 9); /* 42 */ 
		c = HH(c, d, a, b, block[ 5], 11); /* 43 */ 
		b = HH(b, c, d, a, block[13], 15); /* 44 */ 
		a = HH(a, b, c, d, block[ 3], 3); /* 45 */ 
		d = HH(d, a, b, c, block[11], 9); /* 46 */ 
		c = HH(c, d, a, b, block[ 7], 11); /* 47 */ 
		b = HH(b, c, d, a, block[15], 15); /* 48 */ 

		/* Update our state */
		H[0] = H[0] + a;
		H[1] = H[1] + b;
		H[2] = H[2] + c;
		H[3] = H[3] + d;

		this._state = H;
	}

	/**
	 * pads the data.
	 * 
	 * @public
	 * @param {buffer} input input data to be padded.
	 * @param {number} pos position number.
	 * @returns the padded input.
	 */
	pad(input, pos)
	{
		var input_len = input.length;
		var index = input_len - pos;
		var pads = 0;

		// append the '1' bit
		pads++; index++;

		// if the length is currently above 56 bytes we append zeros
		// then compress.  Then we can fall back to padding zeros and length
		// encoding like normal.
		if (index > 56) {
			while (index < 64) {
				pads++; index++;
			}
			index = 0;
			pos += 64;
		}

		// pad upto 56 bytes of zeroes 
		while (index < 56) {
			pads++; index++;
		}
		
		var length_pos = pads;
		pads += 8;
		
		var padding = Buffer.alloc(pads);
		
		padding[0] = 0x80;
		padding.writeInt32LE(input_len * 8, length_pos, true);
		
		return Buffer.concat([input, padding]);
	}

	/**
	 * finishes digesting process and returns the result.
	 * 
	 * @public
	 * @returns the digested data.
	 */
	finish()
	{
		var digest_size = jCastle._algorithmInfo[this.algoName].digest_size;
		var output = Buffer.alloc(digest_size);

		for (var i = 0; i < digest_size / 4; i++) {
			output.writeInt32LE(this._state[i] & 0xffffffff, i * 4, true);
		}
		this._state = null;
		
		return output;
	}
};

jCastle.algorithm.MD4 = jCastle.algorithm.md4;

jCastle._algorithmInfo['md4'] = {
	algorithm_type: 'hash',
	object_name: 'md4',
	block_size: 64,
	digest_size: 16,
	oid: "1.2.840.113549.2.4"
};

module.exports = jCastle.algorithm.md4;