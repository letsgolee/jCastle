/**
 * A Javascript implemenation of HAS-160
 * 
 * @author Jacob Lee
 * 
 * Copyright (C) 2015-2022 Jacob Lee.
 */

var jCastle = require('../jCastle');
require('../util');

jCastle.algorithm.has160 = class
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
		this._state = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];
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

		//	step operations
		function FF(a, b, c, d, e, x, s) {
			e = safeAdd(safeAdd(safeAdd(e, rotl(a, s)), d ^ (b & (c ^ d))), x);
			b = rotl(b, 10);
			return [b, e];
		}

		function GG(a, b, c, d, e, x, s) {
			e = safeAdd(safeAdd(safeAdd(safeAdd(e, rotl(a, s)), b ^ c ^ d), x), 0x5A827999);
			b = rotl(b, 17);
			return [b, e];
		}

		function HH(a, b, c, d, e, x, s) {
			e = safeAdd(safeAdd(safeAdd(safeAdd(e, rotl(a, s)), c ^ (b | ~d)), x), 0x6ED9EBA1);
			b = rotl(b, 25);
			return [b, e];
		}

		function II(a, b, c, d, e, x, s) {
			e = safeAdd(safeAdd(safeAdd(safeAdd(e, rotl(a, s)), b ^ c ^ d), x), 0x8F1BBCDC);
			b = rotl(b, 30);
			return [b, e];
		}

		var a, b, c, d, e, T = new Array(16), K, t;
		var H = this._state;

		var block = [];
		var block_size = jCastle._algorithmInfo[this.algoName].block_size;
		for (var i = 0; i < block_size / 4; i++) {
			block[i] = input.readInt32LE(i * 4);
		}

		a = H[0];
		b = H[1];
		c = H[2];
		d = H[3];
		e = H[4];

		T[ 0] = block[ 8] ^ block[ 9] ^ block[10] ^ block[11];
		T[ 1] = block[12] ^ block[13] ^ block[14] ^ block[15];
		T[ 2] = block[ 0] ^ block[ 1] ^ block[ 2] ^ block[ 3];
		T[ 3] = block[ 4] ^ block[ 5] ^ block[ 6] ^ block[ 7];

		T[ 4] = block[11] ^ block[14] ^ block[ 1] ^ block[ 4];
		T[ 5] = block[ 7] ^ block[10] ^ block[13] ^ block[ 0];
		T[ 6] = block[ 3] ^ block[ 6] ^ block[ 9] ^ block[12];
		T[ 7] = block[15] ^ block[ 2] ^ block[ 5] ^ block[ 8];

		T[ 8] = block[ 4] ^ block[13] ^ block[ 6] ^ block[15];
		T[ 9] = block[ 8] ^ block[ 1] ^ block[10] ^ block[ 3];
		T[10] = block[12] ^ block[ 5] ^ block[14] ^ block[ 7];
		T[11] = block[ 0] ^ block[ 9] ^ block[ 2] ^ block[11];

		T[12] = block[15] ^ block[10] ^ block[ 5] ^ block[ 0];
		T[13] = block[11] ^ block[ 6] ^ block[ 1] ^ block[12];
		T[14] = block[ 7] ^ block[ 2] ^ block[13] ^ block[ 8];
		T[15] = block[ 3] ^ block[14] ^ block[ 9] ^ block[ 4];

		//	round 1
		t = FF(a, b, c, d, e, T[ 0],  5); b = t[0]; e = t[1];
		t = FF(e, a, b, c, d, block[ 0], 11); a = t[0]; d = t[1];
		t = FF(d, e, a, b, c, block[ 1],  7); e = t[0]; c = t[1];
		t = FF(c, d, e, a, b, block[ 2], 15); d = t[0]; b = t[1];
		t = FF(b, c, d, e, a, block[ 3],  6); c = t[0]; a = t[1];
		t = FF(a, b, c, d, e, T[ 1], 13); b = t[0]; e = t[1];
		t = FF(e, a, b, c, d, block[ 4],  8); a = t[0]; d = t[1];
		t = FF(d, e, a, b, c, block[ 5], 14); e = t[0]; c = t[1];
		t = FF(c, d, e, a, b, block[ 6],  7); d = t[0]; b = t[1];
		t = FF(b, c, d, e, a, block[ 7], 12); c = t[0]; a = t[1];
		t = FF(a, b, c, d, e, T[ 2],  9); b = t[0]; e = t[1];
		t = FF(e, a, b, c, d, block[ 8], 11); a = t[0]; d = t[1];
		t = FF(d, e, a, b, c, block[ 9],  8); e = t[0]; c = t[1];
		t = FF(c, d, e, a, b, block[10], 15); d = t[0]; b = t[1];
		t = FF(b, c, d, e, a, block[11],  6); c = t[0]; a = t[1];
		t = FF(a, b, c, d, e, T[ 3], 12); b = t[0]; e = t[1];
		t = FF(e, a, b, c, d, block[12],  9); a = t[0]; d = t[1];
		t = FF(d, e, a, b, c, block[13], 14); e = t[0]; c = t[1];
		t = FF(c, d, e, a, b, block[14],  5); d = t[0]; b = t[1];
		t = FF(b, c, d, e, a, block[15], 13); c = t[0]; a = t[1];

		//	round 2
		t = GG(a, b, c, d, e, T[ 4],  5); b = t[0]; e = t[1];
		t = GG(e, a, b, c, d, block[ 3], 11); a = t[0]; d = t[1];
		t = GG(d, e, a, b, c, block[ 6],  7); e = t[0]; c = t[1];
		t = GG(c, d, e, a, b, block[ 9], 15); d = t[0]; b = t[1];
		t = GG(b, c, d, e, a, block[12],  6); c = t[0]; a = t[1];
		t = GG(a, b, c, d, e, T[ 5], 13); b = t[0]; e = t[1];
		t = GG(e, a, b, c, d, block[15],  8); a = t[0]; d = t[1];
		t = GG(d, e, a, b, c, block[ 2], 14); e = t[0]; c = t[1];
		t = GG(c, d, e, a, b, block[ 5],  7); d = t[0]; b = t[1];
		t = GG(b, c, d, e, a, block[ 8], 12); c = t[0]; a = t[1];
		t = GG(a, b, c, d, e, T[ 6],  9); b = t[0]; e = t[1];
		t = GG(e, a, b, c, d, block[11], 11); a = t[0]; d = t[1];
		t = GG(d, e, a, b, c, block[14],  8); e = t[0]; c = t[1];
		t = GG(c, d, e, a, b, block[ 1], 15); d = t[0]; b = t[1];
		t = GG(b, c, d, e, a, block[ 4],  6); c = t[0]; a = t[1];
		t = GG(a, b, c, d, e, T[ 7], 12); b = t[0]; e = t[1];
		t = GG(e, a, b, c, d, block[ 7],  9); a = t[0]; d = t[1];
		t = GG(d, e, a, b, c, block[10], 14); e = t[0]; c = t[1];
		t = GG(c, d, e, a, b, block[13],  5); d = t[0]; b = t[1];
		t = GG(b, c, d, e, a, block[ 0], 13); c = t[0]; a = t[1];

		//	round 3
		t = HH(a, b, c, d, e, T[ 8],  5); b = t[0]; e = t[1];
		t = HH(e, a, b, c, d, block[12], 11); a = t[0]; d = t[1];
		t = HH(d, e, a, b, c, block[ 5],  7); e = t[0]; c = t[1];
		t = HH(c, d, e, a, b, block[14], 15); d = t[0]; b = t[1];
		t = HH(b, c, d, e, a, block[ 7],  6); c = t[0]; a = t[1];
		t = HH(a, b, c, d, e, T[ 9], 13); b = t[0]; e = t[1];
		t = HH(e, a, b, c, d, block[ 0],  8); a = t[0]; d = t[1];
		t = HH(d, e, a, b, c, block[ 9], 14); e = t[0]; c = t[1];
		t = HH(c, d, e, a, b, block[ 2],  7); d = t[0]; b = t[1];
		t = HH(b, c, d, e, a, block[11], 12); c = t[0]; a = t[1];
		t = HH(a, b, c, d, e, T[10],  9); b = t[0]; e = t[1];
		t = HH(e, a, b, c, d, block[ 4], 11); a = t[0]; d = t[1];
		t = HH(d, e, a, b, c, block[13],  8); e = t[0]; c = t[1];
		t = HH(c, d, e, a, b, block[ 6], 15); d = t[0]; b = t[1];
		t = HH(b, c, d, e, a, block[15],  6); c = t[0]; a = t[1];
		t = HH(a, b, c, d, e, T[11], 12); b = t[0]; e = t[1];
		t = HH(e, a, b, c, d, block[ 8],  9); a = t[0]; d = t[1];
		t = HH(d, e, a, b, c, block[ 1], 14); e = t[0]; c = t[1];
		t = HH(c, d, e, a, b, block[10],  5); d = t[0]; b = t[1];
		t = HH(b, c, d, e, a, block[ 3], 13); c = t[0]; a = t[1];

		//	round 4
		t = II(a, b, c, d, e, T[12],  5); b = t[0]; e = t[1];
		t = II(e, a, b, c, d, block[ 7], 11); a = t[0]; d = t[1];
		t = II(d, e, a, b, c, block[ 2],  7); e = t[0]; c = t[1];
		t = II(c, d, e, a, b, block[13], 15); d = t[0]; b = t[1];
		t = II(b, c, d, e, a, block[ 8],  6); c = t[0]; a = t[1];
		t = II(a, b, c, d, e, T[13], 13); b = t[0]; e = t[1];
		t = II(e, a, b, c, d, block[ 3],  8); a = t[0]; d = t[1];
		t = II(d, e, a, b, c, block[14], 14); e = t[0]; c = t[1];
		t = II(c, d, e, a, b, block[ 9],  7); d = t[0]; b = t[1];
		t = II(b, c, d, e, a, block[ 4], 12); c = t[0]; a = t[1];
		t = II(a, b, c, d, e, T[14],  9); b = t[0]; e = t[1];
		t = II(e, a, b, c, d, block[15], 11); a = t[0]; d = t[1];
		t = II(d, e, a, b, c, block[10],  8); e = t[0]; c = t[1];
		t = II(c, d, e, a, b, block[ 5], 15); d = t[0]; b = t[1];
		t = II(b, c, d, e, a, block[ 0],  6); c = t[0]; a = t[1];
		t = II(a, b, c, d, e, T[15], 12); b = t[0]; e = t[1];
		t = II(e, a, b, c, d, block[11],  9); a = t[0]; d = t[1];
		t = II(d, e, a, b, c, block[ 6], 14); e = t[0]; c = t[1];
		t = II(c, d, e, a, b, block[ 1],  5); d = t[0]; b = t[1];
		t = II(b, c, d, e, a, block[12], 13); c = t[0]; a = t[1];

		//	chaining variables update
		H[0] = safeAdd(H[0], a);
		H[1] = safeAdd(H[1], b);
		H[2] = safeAdd(H[2], c);
		H[3] = safeAdd(H[3], d);
		H[4] = safeAdd(H[4], e);

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
			output.writeInt32LE(this._state[i], i * 4, true);
		}
		this._state = null;
		
		return output;
	}
}

jCastle.algorithm.HAS160 = jCastle.algorithm.has160;

jCastle._algorithmInfo['has160'] =
jCastle._algorithmInfo['has-160'] = {
	algorithm_type: 'hash',
	object_name: 'has160',
	block_size: 64,
	digest_size: 20,
	oid: "1.2.410.200004.1.2"
};

module.exports = jCastle.algorithm.has160;