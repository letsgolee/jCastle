/**
 * A Javascript implemenation of Whirlpool
 * 
 * @author Jacob Lee
 * 
 * Copyright (C) 2015-2022 Jacob Lee.
 */

var jCastle = require('../jCastle');
require('../util');
var INT64 = require('../int64');

jCastle.algorithm.whirlpool = class
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

        // if (typeof INT64 == 'undefined') {
        // 	throw jCastle.exception("INT64_REQUIRED");
        // }
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

	/*
	 * int's are used to prevent sign extension.  The values that are really being used are
	 * actually just 0..255
	 */
	_maskPolynomial(input)
	{
		var rv = input;
		if (rv >= 0x100) { // high bit set
			rv ^= jCastle.algorithm.whirlpool.REDUCTION_POLYNOMIAL; // reduced by the polynomial
		}
		return rv;
	}

	/**
	 * initialize the hash algorithm and sets state with initial value.
	 * 
	 * @public
	 * @param {object} options options object
	 */
	init(options = {})
	{
		this._C = [];

		for (var t = 0; t < 8; t++) this._C[t] = [];

		this._rc = new Array(jCastle.algorithm.whirlpool.ROUNDS + 1);

		for (var i = 0; i < 256; i++) {
			var v1 = jCastle.algorithm.whirlpool.SBOX[i];
			var v2 = this._maskPolynomial(v1 << 1);
			var v4 = this._maskPolynomial(v2 << 1);
			var v5 = v4 ^ v1;
			var v8 = this._maskPolynomial(v4 << 1);
			var v9 = v8 ^ v1;


			this._C[0][i] = new INT64(0, 0);
			this._C[0][i].msint = (v1 << 24) | (v1 << 16) | (v4 <<  8) | (v1);
			this._C[0][i].lsint = (v8 << 24) | (v5 << 16) | (v2 <<  8) | (v9);

			// Build the remaining circulant tables C[t][x] = C[0][x] rotr t
			for (var t = 1; t < 8; t++) {
				this._C[t][i] = new INT64(0, 0);
				this._C[t][i].msint = (this._C[t - 1][i].msint >>> 8) | ((this._C[t - 1][i].lsint << 24));
				this._C[t][i].lsint  = (this._C[t - 1][i].lsint >>> 8)  | ((this._C[t - 1][i].msint << 24));
			}
		}
			
		this._rc[0] = new INT64(0, 0);

		for (var r = 1; r <= jCastle.algorithm.whirlpool.ROUNDS; r++) {
			var i = 8 * (r - 1);
			this._rc[r] = new INT64(0, 0);
			this._rc[r].msint = 
				(this._C[0][i    ].msint & 0xff000000) ^
				(this._C[1][i + 1].msint & 0x00ff0000) ^
				(this._C[2][i + 2].msint & 0x0000ff00) ^
				(this._C[3][i + 3].msint & 0x000000ff);
			this._rc[r].lsint = 
				(this._C[4][i + 4].lsint & 0xff000000) ^
				(this._C[5][i + 5].lsint & 0x00ff0000) ^
				(this._C[6][i + 6].lsint & 0x0000ff00) ^
				(this._C[7][i + 7].lsint & 0x000000ff);
		}

		this._state = [];
		for (var i = 0; i < 8; i++) {
			this._state[i] = new INT64(0, 0);
		}
	}

	/**
	 * processes digesting.
	 * 
	 * @public
	 * @param {buffer} input input data to be digested.
	 */
	process(input)
	{
		// buffer contents have been transferred to the _block[] array via
		var block = [];
		var block_size = jCastle._algorithmInfo[this.algoName].block_size;
		for (var i = 0; i < block_size / 8; i++) {
			block[i] = new INT64(
				input.readInt32BE(i * 8),
				input.readInt32BE(i * 8 + 4)
			);
		}

		var K = []; // the round key
		var L = [];
		var S = [];
			
		// compute and apply K^0 to the cipher state:
		for (var i = 0; i < 8; i++) {
			S[i] = new INT64(0, 0); K[i] = new INT64(0, 0);
			S[i].msint = (block[i].msint ^ (K[i].msint = this._state[i].msint)) & 0xffffffff;
			S[i].lsint = (block[i].lsint ^ (K[i].lsint = this._state[i].lsint)) & 0xffffffff;
		}

		// iterate over all rounds:
		for (var r = 1; r <= jCastle.algorithm.whirlpool.ROUNDS; r++) {
			// compute K^r from K^{r-1}:
			for (i = 0; i < 8; i++) {
				L[i] = new INT64(0,0);
				for (var t = 0, s = 56, j = 0; t < 8; t++,s -= 8) {
					if (s >= 32) {
						L[i].msint ^= this._C[t][(K[(i - t) & 7].msint >>> (s % 32)) & 0xff].msint;
						L[i].lsint ^= this._C[t][(K[(i - t) & 7].msint >>> (s % 32)) & 0xff].lsint;
					} else {
						L[i].msint ^= this._C[t][(K[(i - t) & 7].lsint >>> (s % 32)) & 0xff].msint;
						L[i].lsint ^= this._C[t][(K[(i - t) & 7].lsint >>> (s % 32)) & 0xff].lsint;
					}
				}
			}

			for (var i = 0; i < 8; i++) {
				K[i].msint = L[i].msint;
				K[i].lsint = L[i].lsint;
			}

			K[0].msint ^= this._rc[r].msint;
			K[0].lsint ^= this._rc[r].lsint;

			// apply the r-th round transformation:
			for (var i = 0; i < 8; i++) {
				L[i].msint = K[i].msint;
				L[i].lsint = K[i].lsint;
				for (t = 0, s = 56, j = 0; t < 8; t++, s -= 8) {
					if (s >= 32) {
						L[i].msint ^= this._C[t][(S[(i - t) & 7].msint >>> (s % 32)) & 0xff].msint;
						L[i].lsint ^= this._C[t][(S[(i - t) & 7].msint >>> (s % 32)) & 0xff].lsint;
					} else {
						L[i].msint ^= this._C[t][(S[(i - t) & 7].lsint >>> (s % 32)) & 0xff].msint;
						L[i].lsint ^= this._C[t][(S[(i - t) & 7].lsint >>> (s % 32)) & 0xff].lsint;
					}
				}
			}
			for (var i = 0; i < 8; i++) {
				S[i].msint = L[i].msint;
				S[i].lsint = L[i].lsint;
			}
		}

		// apply the Miyaguchi-Preneel compression function:
		for (var i = 0; i < 8; i++) {
			this._state[i].msint ^= S[i].msint ^ block[i].msint;
			this._state[i].lsint ^= S[i].lsint ^ block[i].lsint;
		}
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

		// if the length is currently above 32 bytes we append zeros
		// then compress.  Then we can fall back to padding zeros and length
		// encoding like normal.
		if (index > 32) {
			while (index < 64) {
				pads++; index++;
			}
			index = 0;
			pos += 64;
		}

		// pad upto 56 bytes of zeroes (should be 32 but we only support 64-bit lengths) 
		while (index < 56) {
			pads++; index++;
		}
		
		var length_pos = pads;
		pads += 8;
		
		var padding = Buffer.alloc(pads);
		
		padding[0] = 0x80;
		padding.writeInt32BE(input_len * 8, length_pos + 4);
		
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
		var output = Buffer.alloc(this._state.length * 8);
		
		for (var i = 0; i < this._state.length; i++) {
			output.writeInt32BE(this._state[i].msint, i * 8, true);
			output.writeInt32BE(this._state[i].lsint, i * 8 + 4, true);
		}
		this._C = null;
		this._rc = null;
		this._state = null;

		return output;
	}
}



jCastle.algorithm.whirlpool.ROUNDS = 10;

jCastle.algorithm.whirlpool.REDUCTION_POLYNOMIAL = 0x011d; // 2^8 + 2^4 + 2^3 + 2 + 1;

jCastle.algorithm.whirlpool.SBOX = [
	0x18, 0x23, 0xc6, 0xe8, 0x87, 0xb8, 0x01, 0x4f, 0x36, 0xa6, 0xd2, 0xf5, 0x79, 0x6f, 0x91, 0x52,
	0x60, 0xbc, 0x9b, 0x8e, 0xa3, 0x0c, 0x7b, 0x35, 0x1d, 0xe0, 0xd7, 0xc2, 0x2e, 0x4b, 0xfe, 0x57,
	0x15, 0x77, 0x37, 0xe5, 0x9f, 0xf0, 0x4a, 0xda, 0x58, 0xc9, 0x29, 0x0a, 0xb1, 0xa0, 0x6b, 0x85,
	0xbd, 0x5d, 0x10, 0xf4, 0xcb, 0x3e, 0x05, 0x67, 0xe4, 0x27, 0x41, 0x8b, 0xa7, 0x7d, 0x95, 0xd8,
	0xfb, 0xee, 0x7c, 0x66, 0xdd, 0x17, 0x47, 0x9e, 0xca, 0x2d, 0xbf, 0x07, 0xad, 0x5a, 0x83, 0x33,
	0x63, 0x02, 0xaa, 0x71, 0xc8, 0x19, 0x49, 0xd9, 0xf2, 0xe3, 0x5b, 0x88, 0x9a, 0x26, 0x32, 0xb0,
	0xe9, 0x0f, 0xd5, 0x80, 0xbe, 0xcd, 0x34, 0x48, 0xff, 0x7a, 0x90, 0x5f, 0x20, 0x68, 0x1a, 0xae,
	0xb4, 0x54, 0x93, 0x22, 0x64, 0xf1, 0x73, 0x12, 0x40, 0x08, 0xc3, 0xec, 0xdb, 0xa1, 0x8d, 0x3d,
	0x97, 0x00, 0xcf, 0x2b, 0x76, 0x82, 0xd6, 0x1b, 0xb5, 0xaf, 0x6a, 0x50, 0x45, 0xf3, 0x30, 0xef,
	0x3f, 0x55, 0xa2, 0xea, 0x65, 0xba, 0x2f, 0xc0, 0xde, 0x1c, 0xfd, 0x4d, 0x92, 0x75, 0x06, 0x8a,
	0xb2, 0xe6, 0x0e, 0x1f, 0x62, 0xd4, 0xa8, 0x96, 0xf9, 0xc5, 0x25, 0x59, 0x84, 0x72, 0x39, 0x4c,
	0x5e, 0x78, 0x38, 0x8c, 0xd1, 0xa5, 0xe2, 0x61, 0xb3, 0x21, 0x9c, 0x1e, 0x43, 0xc7, 0xfc, 0x04,
	0x51, 0x99, 0x6d, 0x0d, 0xfa, 0xdf, 0x7e, 0x24, 0x3b, 0xab, 0xce, 0x11, 0x8f, 0x4e, 0xb7, 0xeb,
	0x3c, 0x81, 0x94, 0xf7, 0xb9, 0x13, 0x2c, 0xd3, 0xe7, 0x6e, 0xc4, 0x03, 0x56, 0x44, 0x7f, 0xa9,
	0x2a, 0xbb, 0xc1, 0x53, 0xdc, 0x0b, 0x9d, 0x6c, 0x31, 0x74, 0xf6, 0x46, 0xac, 0x89, 0x14, 0xe1,
	0x16, 0x3a, 0x69, 0x09, 0x70, 0xb6, 0xd0, 0xed, 0xcc, 0x42, 0x98, 0xa4, 0x28, 0x5c, 0xf8, 0x86
];

jCastle.algorithm.Whirlpool = jCastle.algorithm.whirlpool;

jCastle._algorithmInfo['whirlpool'] = {
	algorithm_type: 'hash',
	object_name: 'whirlpool',
	block_size: 64,
	digest_size: 64,
	oid: "1.0.10118.3.0.55"
};

module.exports = jCastle.algorithm.whirlpool;