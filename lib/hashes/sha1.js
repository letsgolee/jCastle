/**
 * A Javascript implemenation of SHA-1
 * 
 * @author Jacob Lee
 * 
 * Copyright (C) 2015-2022 Jacob Lee.
 */

var jCastle = require('../jCastle');
require('../util');

jCastle.algorithm.sha1 = class
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
        this._rounds = 80;
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
		var a, b, c, d, e;
		var T;
		var rotl = jCastle.util.rotl32, safeAdd = jCastle.util.safeAdd32;
		var H = this._state, W = [];

		var block = [];
		var block_size = jCastle._algorithmInfo[this.algoName].block_size;
		for (var i = 0; i < block_size / 4; i++) {
			block[i] = input.readInt32BE(i * 4);
		}

		a = H[0];
		b = H[1];
		c = H[2];
		d = H[3];
		e = H[4];

		for (var t = 0; t < this._rounds; t++) {
			if (t < 16) {
				W[t] = block[t];
			} else {
				W[t] = rotl(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1);
			}

			if (t < 20) {
				T = safeAdd(safeAdd(safeAdd(safeAdd(rotl(a, 5), this.ch(b, c, d)), e), jCastle.algorithm.sha1.K[t]), W[t]);
			} else if (t < 40) {
				T = safeAdd(safeAdd(safeAdd(safeAdd(rotl(a, 5), this.parity(b, c, d)), e), jCastle.algorithm.sha1.K[t]), W[t]);
			} else if (t < 60) {
				T = safeAdd(safeAdd(safeAdd(safeAdd(rotl(a, 5), this.maj(b, c, d)), e), jCastle.algorithm.sha1.K[t]), W[t]);
			} else {
				T = safeAdd(safeAdd(safeAdd(safeAdd(rotl(a, 5), this.parity(b, c, d)), e), jCastle.algorithm.sha1.K[t]), W[t]);
			}

			e = d;
			d = c;
			c = rotl(b, 30);
			b = a;
			a = T;
		}

		H[0] = safeAdd(a, H[0]);
		H[1] = safeAdd(b, H[1]);
		H[2] = safeAdd(c, H[2]);
		H[3] = safeAdd(d, H[3]);
		H[4] = safeAdd(e, H[4]);

		this._state = H;
	}

	pad(input, pos)
	{
		var input_len = input.length;
		var index = input_len - pos;
		var pads = 0;
		
		// append the '1' bit
		index++; pads++;
		
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
		
		// length block
		var length_pos = pads;
		pads += 8;
		
		var padding = Buffer.alloc(pads);
		padding[0] = 0x80;
		
		// input length should be saved as int64.
		// but javascript does not support int64.
		// input length will be saved as int32
		padding.writeInt32BE(input_len * 8, length_pos + 4, true);
		
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
			output.writeInt32BE(this._state[i] & 0xffffffff, i * 4, true);
		}
		this._state = null;

		return output;	
	}

	parity(x, y, z)
	{
		return x ^ y ^ z;
	}

	ch(x, y, z)
	{
		return (x & y) ^ (~x & z);
	}

	maj(x, y, z)
	{
		return (x & y) ^ (x & z) ^ (y & z);
	}


}



jCastle.algorithm.sha1.K = [
	0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999,
	0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999,
	0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999,
	0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999,
	0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999,
	0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1,
	0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1,
	0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1,
	0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1,
	0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1,
	0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc,
	0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc,
	0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc,
	0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc,
	0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc,
	0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6,
	0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6,
	0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6,
	0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6,
	0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6
];

jCastle.algorithm.SHA1 = jCastle.algorithm.sha1;

jCastle._algorithmInfo['sha1'] = 
jCastle._algorithmInfo['sha-1'] = {
	algorithm_type: 'hash',
	object_name: 'sha1',
	block_size: 64,
	digest_size: 20,
	oid: "1.3.14.3.2.26"
};

module.exports = jCastle.algorithm.sha1;