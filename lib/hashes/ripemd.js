/**
 * A Javascript implemenation of RIPEMD Family
 * 
 * @author Jacob Lee
 * 
 * Copyright (C) 2015-2022 Jacob Lee.
 */

var jCastle = require('../jCastle');
require('../util');

jCastle.algorithm.ripemd128 = class
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
		this.type = 1;
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
		var aa, bb, cc, dd, aaa, bbb, ccc, ddd, tmp;

		var block = [];
		var block_size = jCastle._algorithmInfo[this.algoName].block_size;
		for (var i = 0; i < block_size / 4; i++) {
			block[i] = input.readInt32LE(i * 4);
		}


		/* the eight basic operations FF() through III() */
		function FF(a, b, c, d, x, s)
		{
			a = safeAdd(a, safeAdd(b ^ c ^ d, x));
			a = rotl(a, s);
			return a;
		}

		function GG(a, b, c, d, x, s)
		{
			a = safeAdd(a, safeAdd(safeAdd((b & c) | (~b & d), x), 0x5a827999));
			a = rotl(a, s);
			return a;
		}

		function HH(a, b, c, d, x, s)
		{
			a = safeAdd(a, safeAdd(safeAdd((b | ~c) ^ d, x), 0x6ed9eba1));
			a = rotl(a, s);
			return a;
		}

		function II(a, b, c, d, x, s)
		{
			a = safeAdd(a, safeAdd(safeAdd((b & d) | (c & ~d), x), 0x8f1bbcdc));
			a = rotl(a, s);
			return a;
		}

		function FFF(a, b, c, d, x, s)
		{
			a = safeAdd(a, safeAdd(b ^ c ^ d, x));
			a = rotl(a, s);
			return a;
		}

		function GGG(a, b, c, d, x, s)
		{
			a = safeAdd(a, safeAdd(safeAdd((b & c) | (~b & d), x), 0x6d703ef3));
			a = rotl(a, s);
			return a;
		}

		function HHH(a, b, c, d, x, s)
		{
			a = safeAdd(a, safeAdd(safeAdd((b | ~c) ^ d, x), 0x5c4dd124));
			a = rotl(a, s);
			return a;
		}

		function III(a, b, c, d, x, s) 
		{
			a = safeAdd(a, safeAdd(safeAdd((b & d) | (c & ~d), x), 0x50a28be6));
			a = rotl(a, s);
			return a;
		}

		/* load state */
		switch (this.type) {
			case 1: // ripemd-128
				aa = aaa = H[0];
				bb = bbb = H[1];
				cc = ccc = H[2];
				dd = ddd = H[3];
				break;
			case 2: // ripemd-256
				aa = H[0];
				bb = H[1];
				cc = H[2];
				dd = H[3];
				aaa = H[4];
				bbb = H[5];
				ccc = H[6];
				ddd = H[7];
				break;
		}

		// round 1 
		aa = FF(aa, bb, cc, dd, block[ 0], 11);
		dd = FF(dd, aa, bb, cc, block[ 1], 14);
		cc = FF(cc, dd, aa, bb, block[ 2], 15);
		bb = FF(bb, cc, dd, aa, block[ 3], 12);
		aa = FF(aa, bb, cc, dd, block[ 4],  5);
		dd = FF(dd, aa, bb, cc, block[ 5],  8);
		cc = FF(cc, dd, aa, bb, block[ 6],  7);
		bb = FF(bb, cc, dd, aa, block[ 7],  9);
		aa = FF(aa, bb, cc, dd, block[ 8], 11);
		dd = FF(dd, aa, bb, cc, block[ 9], 13);
		cc = FF(cc, dd, aa, bb, block[10], 14);
		bb = FF(bb, cc, dd, aa, block[11], 15);
		aa = FF(aa, bb, cc, dd, block[12],  6);
		dd = FF(dd, aa, bb, cc, block[13],  7);
		cc = FF(cc, dd, aa, bb, block[14],  9);
		bb = FF(bb, cc, dd, aa, block[15],  8);

		// parallel round 1 
		aaa = III(aaa, bbb, ccc, ddd, block[ 5],  8);
		ddd = III(ddd, aaa, bbb, ccc, block[14],  9);
		ccc = III(ccc, ddd, aaa, bbb, block[ 7],  9);
		bbb = III(bbb, ccc, ddd, aaa, block[ 0], 11);
		aaa = III(aaa, bbb, ccc, ddd, block[ 9], 13);
		ddd = III(ddd, aaa, bbb, ccc, block[ 2], 15);
		ccc = III(ccc, ddd, aaa, bbb, block[11], 15);
		bbb = III(bbb, ccc, ddd, aaa, block[ 4],  5);
		aaa = III(aaa, bbb, ccc, ddd, block[13],  7);
		ddd = III(ddd, aaa, bbb, ccc, block[ 6],  7);
		ccc = III(ccc, ddd, aaa, bbb, block[15],  8);
		bbb = III(bbb, ccc, ddd, aaa, block[ 8], 11);
		aaa = III(aaa, bbb, ccc, ddd, block[ 1], 14);
		ddd = III(ddd, aaa, bbb, ccc, block[10], 14);
		ccc = III(ccc, ddd, aaa, bbb, block[ 3], 12);
		bbb = III(bbb, ccc, ddd, aaa, block[12],  6);

		if (this.type == 2) {
			tmp = aa; aa = aaa; aaa = tmp;
		}

		// round 2
		aa = GG(aa, bb, cc, dd, block[ 7],  7);
		dd = GG(dd, aa, bb, cc, block[ 4],  6);
		cc = GG(cc, dd, aa, bb, block[13],  8);
		bb = GG(bb, cc, dd, aa, block[ 1], 13);
		aa = GG(aa, bb, cc, dd, block[10], 11);
		dd = GG(dd, aa, bb, cc, block[ 6],  9);
		cc = GG(cc, dd, aa, bb, block[15],  7);
		bb = GG(bb, cc, dd, aa, block[ 3], 15);
		aa = GG(aa, bb, cc, dd, block[12],  7);
		dd = GG(dd, aa, bb, cc, block[ 0], 12);
		cc = GG(cc, dd, aa, bb, block[ 9], 15);
		bb = GG(bb, cc, dd, aa, block[ 5],  9);
		aa = GG(aa, bb, cc, dd, block[ 2], 11);
		dd = GG(dd, aa, bb, cc, block[14],  7);
		cc = GG(cc, dd, aa, bb, block[11], 13);
		bb = GG(bb, cc, dd, aa, block[ 8], 12);

		// parallel round 2
		aaa = HHH(aaa, bbb, ccc, ddd, block[ 6],  9);
		ddd = HHH(ddd, aaa, bbb, ccc, block[11], 13);
		ccc = HHH(ccc, ddd, aaa, bbb, block[ 3], 15);
		bbb = HHH(bbb, ccc, ddd, aaa, block[ 7],  7);
		aaa = HHH(aaa, bbb, ccc, ddd, block[ 0], 12);
		ddd = HHH(ddd, aaa, bbb, ccc, block[13],  8);
		ccc = HHH(ccc, ddd, aaa, bbb, block[ 5],  9);
		bbb = HHH(bbb, ccc, ddd, aaa, block[10], 11);
		aaa = HHH(aaa, bbb, ccc, ddd, block[14],  7);
		ddd = HHH(ddd, aaa, bbb, ccc, block[15],  7);
		ccc = HHH(ccc, ddd, aaa, bbb, block[ 8], 12);
		bbb = HHH(bbb, ccc, ddd, aaa, block[12],  7);
		aaa = HHH(aaa, bbb, ccc, ddd, block[ 4],  6);
		ddd = HHH(ddd, aaa, bbb, ccc, block[ 9], 15);
		ccc = HHH(ccc, ddd, aaa, bbb, block[ 1], 13);
		bbb = HHH(bbb, ccc, ddd, aaa, block[ 2], 11);

		if (this.type == 2) {
			tmp = bb; bb = bbb; bbb = tmp;
		}

		// round 3
		aa = HH(aa, bb, cc, dd, block[ 3], 11);
		dd = HH(dd, aa, bb, cc, block[10], 13);
		cc = HH(cc, dd, aa, bb, block[14],  6);
		bb = HH(bb, cc, dd, aa, block[ 4],  7);
		aa = HH(aa, bb, cc, dd, block[ 9], 14);
		dd = HH(dd, aa, bb, cc, block[15],  9);
		cc = HH(cc, dd, aa, bb, block[ 8], 13);
		bb = HH(bb, cc, dd, aa, block[ 1], 15);
		aa = HH(aa, bb, cc, dd, block[ 2], 14);
		dd = HH(dd, aa, bb, cc, block[ 7],  8);
		cc = HH(cc, dd, aa, bb, block[ 0], 13);
		bb = HH(bb, cc, dd, aa, block[ 6],  6);
		aa = HH(aa, bb, cc, dd, block[13],  5);
		dd = HH(dd, aa, bb, cc, block[11], 12);
		cc = HH(cc, dd, aa, bb, block[ 5],  7);
		bb = HH(bb, cc, dd, aa, block[12],  5);

		// parallel round 3
		aaa = GGG(aaa, bbb, ccc, ddd, block[15],  9);
		ddd = GGG(ddd, aaa, bbb, ccc, block[ 5],  7);
		ccc = GGG(ccc, ddd, aaa, bbb, block[ 1], 15);
		bbb = GGG(bbb, ccc, ddd, aaa, block[ 3], 11);
		aaa = GGG(aaa, bbb, ccc, ddd, block[ 7],  8);
		ddd = GGG(ddd, aaa, bbb, ccc, block[14],  6);
		ccc = GGG(ccc, ddd, aaa, bbb, block[ 6],  6);
		bbb = GGG(bbb, ccc, ddd, aaa, block[ 9], 14);
		aaa = GGG(aaa, bbb, ccc, ddd, block[11], 12);
		ddd = GGG(ddd, aaa, bbb, ccc, block[ 8], 13);
		ccc = GGG(ccc, ddd, aaa, bbb, block[12],  5);
		bbb = GGG(bbb, ccc, ddd, aaa, block[ 2], 14);
		aaa = GGG(aaa, bbb, ccc, ddd, block[10], 13);
		ddd = GGG(ddd, aaa, bbb, ccc, block[ 0], 13);
		ccc = GGG(ccc, ddd, aaa, bbb, block[ 4],  7);
		bbb = GGG(bbb, ccc, ddd, aaa, block[13],  5);

		if (this.type == 2) {
			tmp = cc; cc = ccc; ccc = tmp;
		}

		// round 4
		aa = II(aa, bb, cc, dd, block[ 1], 11);
		dd = II(dd, aa, bb, cc, block[ 9], 12);
		cc = II(cc, dd, aa, bb, block[11], 14);
		bb = II(bb, cc, dd, aa, block[10], 15);
		aa = II(aa, bb, cc, dd, block[ 0], 14);
		dd = II(dd, aa, bb, cc, block[ 8], 15);
		cc = II(cc, dd, aa, bb, block[12],  9);
		bb = II(bb, cc, dd, aa, block[ 4],  8);
		aa = II(aa, bb, cc, dd, block[13],  9);
		dd = II(dd, aa, bb, cc, block[ 3], 14);
		cc = II(cc, dd, aa, bb, block[ 7],  5);
		bb = II(bb, cc, dd, aa, block[15],  6);
		aa = II(aa, bb, cc, dd, block[14],  8);
		dd = II(dd, aa, bb, cc, block[ 5],  6);
		cc = II(cc, dd, aa, bb, block[ 6],  5);
		bb = II(bb, cc, dd, aa, block[ 2], 12);

		// parallel round 4
		aaa = FFF(aaa, bbb, ccc, ddd, block[ 8], 15);
		ddd = FFF(ddd, aaa, bbb, ccc, block[ 6],  5);
		ccc = FFF(ccc, ddd, aaa, bbb, block[ 4],  8);
		bbb = FFF(bbb, ccc, ddd, aaa, block[ 1], 11);
		aaa = FFF(aaa, bbb, ccc, ddd, block[ 3], 14);
		ddd = FFF(ddd, aaa, bbb, ccc, block[11], 14);
		ccc = FFF(ccc, ddd, aaa, bbb, block[15],  6);
		bbb = FFF(bbb, ccc, ddd, aaa, block[ 0], 14);
		aaa = FFF(aaa, bbb, ccc, ddd, block[ 5],  6);
		ddd = FFF(ddd, aaa, bbb, ccc, block[12],  9);
		ccc = FFF(ccc, ddd, aaa, bbb, block[ 2], 12);
		bbb = FFF(bbb, ccc, ddd, aaa, block[13],  9);
		aaa = FFF(aaa, bbb, ccc, ddd, block[ 9], 12);
		ddd = FFF(ddd, aaa, bbb, ccc, block[ 7],  5);
		ccc = FFF(ccc, ddd, aaa, bbb, block[10], 15);
		bbb = FFF(bbb, ccc, ddd, aaa, block[14],  8);

		if (this.type == 2) {
			tmp = dd; dd = ddd; ddd = tmp;
		}

		/* combine results */
		switch (this.type) {
			case 1: // ripemd-128
				ddd = safeAdd(ddd, safeAdd(cc, H[1]));               /* final result for MDbuf[0] */
				H[1] = safeAdd(H[2], safeAdd(dd, aaa));
				H[2] = safeAdd(H[3], safeAdd(aa, bbb));
				H[3] = safeAdd(H[0], safeAdd(bb, ccc));
				H[0] = ddd;
				break;
			case 2: // ripemd-256
				H[0] += aa;
				H[1] += bb;
				H[2] += cc;
				H[3] += dd;
				H[4] += aaa;
				H[5] += bbb;
				H[6] += ccc;
				H[7] += ddd;
				break;
		}

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
}

jCastle.algorithm.RIPEMD128 = jCastle.algorithm.ripemd128;

/* Implementation of RIPEMD-128 based on the source by Antoon Bosselaers, ESAT-COSIC
 */
jCastle._algorithmInfo['ripemd-128'] = {
	algorithm_type: 'hash',
	object_name: 'ripemd128',
	block_size: 64,
	digest_size: 16,
	oid: "1.0.10118.3.0.50"
};

jCastle.algorithm.ripemd256 = class extends jCastle.algorithm.ripemd128
{
	/**
	 * creates the hash algorithm instance.
	 * 
	 * @param {string} hash_name hash algorithm name
	 * @constructor
	 */
    constructor(hash_name)
    {
        super(hash_name);

        this.algoName = hash_name;
        this._state = null;
    }

	/**
	 * initialize the hash algorithm and sets state with initial value.
	 * 
	 * @public
	 * @param {object} options options object
	 */
	init(options = {})
	{
		this._state = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0x76543210, 0xfedcba98, 0x89abcdef, 0x01234567];
		this.type = 2;
	}
}

jCastle.algorithm.RIPEMD256 = jCastle.algorithm.ripemd256;

jCastle._algorithmInfo['ripemd-256'] = {
	algorithm_type: 'hash',
	object_name: 'ripemd256',
	block_size: 64,
	digest_size: 32,
	oid: "1.3.36.3.2.3"
};

/************************************************************/

jCastle.algorithm.ripemd160 = class
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
		this.type = 1;
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
		var aa, bb, cc, dd, ee, aaa, bbb, ccc, ddd, eee, tmp, t;

		var block = [];
		var block_size = jCastle._algorithmInfo[this.algoName].block_size;
		for (var i = 0; i < block_size / 4; i++) {
			block[i] = input.readInt32LE(i * 4);
		}


		/* the ten basic operations FF() through III() */
		function FF(a, b, c, d, e, x, s) {
			a = safeAdd(a, safeAdd(b ^ c ^ d, x));
			a = safeAdd(rotl(a, s), e);
			c = rotl(c, 10);
			return [a, c];
		}

		function GG(a, b, c, d, e, x, s) {
			a = safeAdd(a, safeAdd(safeAdd((b & c) | (~b & d), x), 0x5a827999));
			a = safeAdd(rotl(a, s), e);
			c = rotl(c, 10);
			return [a, c];
		}

		function HH(a, b, c, d, e, x, s) {
			a = safeAdd(a, safeAdd(safeAdd((b | ~c) ^ d, x), 0x6ed9eba1));
			a = safeAdd(rotl(a, s), e);
			c = rotl(c, 10);
			return [a, c];
		}

		function II(a, b, c, d, e, x, s) {
			a = safeAdd(a, safeAdd(safeAdd((b & d) | (c & ~d), x), 0x8f1bbcdc));
			a = safeAdd(rotl(a, s), e);
			c = rotl(c, 10);
			return [a, c];
		}

		function JJ(a, b, c, d, e, x, s) {
			a = safeAdd(a, safeAdd(safeAdd(b ^ (c | ~d), x), 0xa953fd4e));
			a = safeAdd(rotl(a, s), e);
			c = rotl(c, 10);
			return [a, c];
		}

		function FFF(a, b, c, d, e, x, s) {
			a = safeAdd(a, safeAdd(b ^ c ^ d, x));
			a = safeAdd(rotl(a, s), e);
			c = rotl(c, 10);
			return [a, c];
		}

		function GGG(a, b, c, d, e, x, s) {
			a = safeAdd(a, safeAdd(safeAdd((b & c) | (~b & d), x), 0x7a6d76e9));
			a = safeAdd(rotl(a, s), e);
			c = rotl(c, 10);
			return [a, c];
		}

		function HHH(a, b, c, d, e, x, s) {
			a = safeAdd(a, safeAdd(safeAdd((b | ~c) ^ d, x), 0x6d703ef3));
			a = safeAdd(rotl(a, s), e);
			c = rotl(c, 10);
			return [a, c];
		}

		function III(a, b, c, d, e, x, s) {
			a = safeAdd(a, safeAdd(safeAdd((b & d) | (c & ~d), x), 0x5c4dd124));
			a = safeAdd(rotl(a, s), e);
			c = rotl(c, 10);
			return [a, c];
		}

		function JJJ(a, b, c, d, e, x, s) {
			a = safeAdd(a, safeAdd(safeAdd(b ^ (c | ~d), x), 0x50a28be6));
			a = safeAdd(rotl(a, s), e);
			c = rotl(c, 10);
			return [a, c];
		}

		/* load state */
		switch (this.type) {
			case 1: // ripemd-160
				aa = aaa = H[0];
				bb = bbb = H[1];
				cc = ccc = H[2];
				dd = ddd = H[3];
				ee = eee = H[4];
				break;
			case 2: // ripemd-320
				aa = H[0];
				bb = H[1];
				cc = H[2];
				dd = H[3];
				ee = H[4];
				aaa = H[5];
				bbb = H[6];
				ccc = H[7];
				ddd = H[8];
				eee = H[9];
				break;
		}

		/* round 1 */
		t = FF(aa, bb, cc, dd, ee, block[ 0], 11); aa = t[0]; cc = t[1];
		t = FF(ee, aa, bb, cc, dd, block[ 1], 14); ee = t[0]; bb = t[1];
		t = FF(dd, ee, aa, bb, cc, block[ 2], 15); dd = t[0]; aa = t[1];
		t = FF(cc, dd, ee, aa, bb, block[ 3], 12); cc = t[0]; ee = t[1];
		t = FF(bb, cc, dd, ee, aa, block[ 4],  5); bb = t[0]; dd = t[1];
		t = FF(aa, bb, cc, dd, ee, block[ 5],  8); aa = t[0]; cc = t[1];
		t = FF(ee, aa, bb, cc, dd, block[ 6],  7); ee = t[0]; bb = t[1];
		t = FF(dd, ee, aa, bb, cc, block[ 7],  9); dd = t[0]; aa = t[1];
		t = FF(cc, dd, ee, aa, bb, block[ 8], 11); cc = t[0]; ee = t[1];
		t = FF(bb, cc, dd, ee, aa, block[ 9], 13); bb = t[0]; dd = t[1];
		t = FF(aa, bb, cc, dd, ee, block[10], 14); aa = t[0]; cc = t[1];
		t = FF(ee, aa, bb, cc, dd, block[11], 15); ee = t[0]; bb = t[1];
		t = FF(dd, ee, aa, bb, cc, block[12],  6); dd = t[0]; aa = t[1];
		t = FF(cc, dd, ee, aa, bb, block[13],  7); cc = t[0]; ee = t[1];
		t = FF(bb, cc, dd, ee, aa, block[14],  9); bb = t[0]; dd = t[1];
		t = FF(aa, bb, cc, dd, ee, block[15],  8); aa = t[0]; cc = t[1];

		/* parallel round 1 */
		t = JJJ(aaa, bbb, ccc, ddd, eee, block[ 5],  8); aaa = t[0]; ccc = t[1];
		t = JJJ(eee, aaa, bbb, ccc, ddd, block[14],  9); eee = t[0]; bbb = t[1];
		t = JJJ(ddd, eee, aaa, bbb, ccc, block[ 7],  9); ddd = t[0]; aaa = t[1];
		t = JJJ(ccc, ddd, eee, aaa, bbb, block[ 0], 11); ccc = t[0]; eee = t[1];
		t = JJJ(bbb, ccc, ddd, eee, aaa, block[ 9], 13); bbb = t[0]; ddd = t[1];
		t = JJJ(aaa, bbb, ccc, ddd, eee, block[ 2], 15); aaa = t[0]; ccc = t[1];
		t = JJJ(eee, aaa, bbb, ccc, ddd, block[11], 15); eee = t[0]; bbb = t[1];
		t = JJJ(ddd, eee, aaa, bbb, ccc, block[ 4],  5); ddd = t[0]; aaa = t[1];
		t = JJJ(ccc, ddd, eee, aaa, bbb, block[13],  7); ccc = t[0]; eee = t[1];
		t = JJJ(bbb, ccc, ddd, eee, aaa, block[ 6],  7); bbb = t[0]; ddd = t[1];
		t = JJJ(aaa, bbb, ccc, ddd, eee, block[15],  8); aaa = t[0]; ccc = t[1];
		t = JJJ(eee, aaa, bbb, ccc, ddd, block[ 8], 11); eee = t[0]; bbb = t[1];
		t = JJJ(ddd, eee, aaa, bbb, ccc, block[ 1], 14); ddd = t[0]; aaa = t[1];
		t = JJJ(ccc, ddd, eee, aaa, bbb, block[10], 14); ccc = t[0]; eee = t[1];
		t = JJJ(bbb, ccc, ddd, eee, aaa, block[ 3], 12); bbb = t[0]; ddd = t[1];
		t = JJJ(aaa, bbb, ccc, ddd, eee, block[12],  6); aaa = t[0]; ccc = t[1];

		if (this.type == 2) {
			tmp = aa; aa = aaa; aaa = tmp;
		}

		/* round 2 */
		t = GG(ee, aa, bb, cc, dd, block[ 7],  7); ee = t[0]; bb = t[1];
		t = GG(dd, ee, aa, bb, cc, block[ 4],  6); dd = t[0]; aa = t[1];
		t = GG(cc, dd, ee, aa, bb, block[13],  8); cc = t[0]; ee = t[1];
		t = GG(bb, cc, dd, ee, aa, block[ 1], 13); bb = t[0]; dd = t[1];
		t = GG(aa, bb, cc, dd, ee, block[10], 11); aa = t[0]; cc = t[1];
		t = GG(ee, aa, bb, cc, dd, block[ 6],  9); ee = t[0]; bb = t[1];
		t = GG(dd, ee, aa, bb, cc, block[15],  7); dd = t[0]; aa = t[1];
		t = GG(cc, dd, ee, aa, bb, block[ 3], 15); cc = t[0]; ee = t[1];
		t = GG(bb, cc, dd, ee, aa, block[12],  7); bb = t[0]; dd = t[1];
		t = GG(aa, bb, cc, dd, ee, block[ 0], 12); aa = t[0]; cc = t[1];
		t = GG(ee, aa, bb, cc, dd, block[ 9], 15); ee = t[0]; bb = t[1];
		t = GG(dd, ee, aa, bb, cc, block[ 5],  9); dd = t[0]; aa = t[1];
		t = GG(cc, dd, ee, aa, bb, block[ 2], 11); cc = t[0]; ee = t[1];
		t = GG(bb, cc, dd, ee, aa, block[14],  7); bb = t[0]; dd = t[1];
		t = GG(aa, bb, cc, dd, ee, block[11], 13); aa = t[0]; cc = t[1];
		t = GG(ee, aa, bb, cc, dd, block[ 8], 12); ee = t[0]; bb = t[1];

		/* parallel round 2 */
		t = III(eee, aaa, bbb, ccc, ddd, block[ 6],  9); eee = t[0]; bbb = t[1];
		t = III(ddd, eee, aaa, bbb, ccc, block[11], 13); ddd = t[0]; aaa = t[1];
		t = III(ccc, ddd, eee, aaa, bbb, block[ 3], 15); ccc = t[0]; eee = t[1];
		t = III(bbb, ccc, ddd, eee, aaa, block[ 7],  7); bbb = t[0]; ddd = t[1];
		t = III(aaa, bbb, ccc, ddd, eee, block[ 0], 12); aaa = t[0]; ccc = t[1];
		t = III(eee, aaa, bbb, ccc, ddd, block[13],  8); eee = t[0]; bbb = t[1];
		t = III(ddd, eee, aaa, bbb, ccc, block[ 5],  9); ddd = t[0]; aaa = t[1];
		t = III(ccc, ddd, eee, aaa, bbb, block[10], 11); ccc = t[0]; eee = t[1];
		t = III(bbb, ccc, ddd, eee, aaa, block[14],  7); bbb = t[0]; ddd = t[1];
		t = III(aaa, bbb, ccc, ddd, eee, block[15],  7); aaa = t[0]; ccc = t[1];
		t = III(eee, aaa, bbb, ccc, ddd, block[ 8], 12); eee = t[0]; bbb = t[1];
		t = III(ddd, eee, aaa, bbb, ccc, block[12],  7); ddd = t[0]; aaa = t[1];
		t = III(ccc, ddd, eee, aaa, bbb, block[ 4],  6); ccc = t[0]; eee = t[1];
		t = III(bbb, ccc, ddd, eee, aaa, block[ 9], 15); bbb = t[0]; ddd = t[1];
		t = III(aaa, bbb, ccc, ddd, eee, block[ 1], 13); aaa = t[0]; ccc = t[1];
		t = III(eee, aaa, bbb, ccc, ddd, block[ 2], 11); eee = t[0]; bbb = t[1];

		if (this.type == 2) {
			tmp = bb; bb = bbb; bbb = tmp;
		}

		/* round 3 */
		t = HH(dd, ee, aa, bb, cc, block[ 3], 11); dd = t[0]; aa = t[1];
		t = HH(cc, dd, ee, aa, bb, block[10], 13); cc = t[0]; ee = t[1];
		t = HH(bb, cc, dd, ee, aa, block[14],  6); bb = t[0]; dd = t[1];
		t = HH(aa, bb, cc, dd, ee, block[ 4],  7); aa = t[0]; cc = t[1];
		t = HH(ee, aa, bb, cc, dd, block[ 9], 14); ee = t[0]; bb = t[1];
		t = HH(dd, ee, aa, bb, cc, block[15],  9); dd = t[0]; aa = t[1];
		t = HH(cc, dd, ee, aa, bb, block[ 8], 13); cc = t[0]; ee = t[1];
		t = HH(bb, cc, dd, ee, aa, block[ 1], 15); bb = t[0]; dd = t[1];
		t = HH(aa, bb, cc, dd, ee, block[ 2], 14); aa = t[0]; cc = t[1];
		t = HH(ee, aa, bb, cc, dd, block[ 7],  8); ee = t[0]; bb = t[1];
		t = HH(dd, ee, aa, bb, cc, block[ 0], 13); dd = t[0]; aa = t[1];
		t = HH(cc, dd, ee, aa, bb, block[ 6],  6); cc = t[0]; ee = t[1];
		t = HH(bb, cc, dd, ee, aa, block[13],  5); bb = t[0]; dd = t[1];
		t = HH(aa, bb, cc, dd, ee, block[11], 12); aa = t[0]; cc = t[1];
		t = HH(ee, aa, bb, cc, dd, block[ 5],  7); ee = t[0]; bb = t[1];
		t = HH(dd, ee, aa, bb, cc, block[12],  5); dd = t[0]; aa = t[1];

		/* parallel round 3 */
		t = HHH(ddd, eee, aaa, bbb, ccc, block[15],  9); ddd = t[0]; aaa = t[1];
		t = HHH(ccc, ddd, eee, aaa, bbb, block[ 5],  7); ccc = t[0]; eee = t[1];
		t = HHH(bbb, ccc, ddd, eee, aaa, block[ 1], 15); bbb = t[0]; ddd = t[1];
		t = HHH(aaa, bbb, ccc, ddd, eee, block[ 3], 11); aaa = t[0]; ccc = t[1];
		t = HHH(eee, aaa, bbb, ccc, ddd, block[ 7],  8); eee = t[0]; bbb = t[1];
		t = HHH(ddd, eee, aaa, bbb, ccc, block[14],  6); ddd = t[0]; aaa = t[1];
		t = HHH(ccc, ddd, eee, aaa, bbb, block[ 6],  6); ccc = t[0]; eee = t[1];
		t = HHH(bbb, ccc, ddd, eee, aaa, block[ 9], 14); bbb = t[0]; ddd = t[1];
		t = HHH(aaa, bbb, ccc, ddd, eee, block[11], 12); aaa = t[0]; ccc = t[1];
		t = HHH(eee, aaa, bbb, ccc, ddd, block[ 8], 13); eee = t[0]; bbb = t[1];
		t = HHH(ddd, eee, aaa, bbb, ccc, block[12],  5); ddd = t[0]; aaa = t[1];
		t = HHH(ccc, ddd, eee, aaa, bbb, block[ 2], 14); ccc = t[0]; eee = t[1];
		t = HHH(bbb, ccc, ddd, eee, aaa, block[10], 13); bbb = t[0]; ddd = t[1];
		t = HHH(aaa, bbb, ccc, ddd, eee, block[ 0], 13); aaa = t[0]; ccc = t[1];
		t = HHH(eee, aaa, bbb, ccc, ddd, block[ 4],  7); eee = t[0]; bbb = t[1];
		t = HHH(ddd, eee, aaa, bbb, ccc, block[13],  5); ddd = t[0]; aaa = t[1];

		if (this.type == 2) {
			tmp = cc; cc = ccc; ccc = tmp;
		}

		/* round 4 */
		t = II(cc, dd, ee, aa, bb, block[ 1], 11); cc = t[0]; ee = t[1];
		t = II(bb, cc, dd, ee, aa, block[ 9], 12); bb = t[0]; dd = t[1];
		t = II(aa, bb, cc, dd, ee, block[11], 14); aa = t[0]; cc = t[1];
		t = II(ee, aa, bb, cc, dd, block[10], 15); ee = t[0]; bb = t[1];
		t = II(dd, ee, aa, bb, cc, block[ 0], 14); dd = t[0]; aa = t[1];
		t = II(cc, dd, ee, aa, bb, block[ 8], 15); cc = t[0]; ee = t[1];
		t = II(bb, cc, dd, ee, aa, block[12],  9); bb = t[0]; dd = t[1];
		t = II(aa, bb, cc, dd, ee, block[ 4],  8); aa = t[0]; cc = t[1];
		t = II(ee, aa, bb, cc, dd, block[13],  9); ee = t[0]; bb = t[1];
		t = II(dd, ee, aa, bb, cc, block[ 3], 14); dd = t[0]; aa = t[1];
		t = II(cc, dd, ee, aa, bb, block[ 7],  5); cc = t[0]; ee = t[1];
		t = II(bb, cc, dd, ee, aa, block[15],  6); bb = t[0]; dd = t[1];
		t = II(aa, bb, cc, dd, ee, block[14],  8); aa = t[0]; cc = t[1];
		t = II(ee, aa, bb, cc, dd, block[ 5],  6); ee = t[0]; bb = t[1];
		t = II(dd, ee, aa, bb, cc, block[ 6],  5); dd = t[0]; aa = t[1];
		t = II(cc, dd, ee, aa, bb, block[ 2], 12); cc = t[0]; ee = t[1];

		/* parallel round 4 */
		t = GGG(ccc, ddd, eee, aaa, bbb, block[ 8], 15); ccc = t[0]; eee = t[1];
		t = GGG(bbb, ccc, ddd, eee, aaa, block[ 6],  5); bbb = t[0]; ddd = t[1];
		t = GGG(aaa, bbb, ccc, ddd, eee, block[ 4],  8); aaa = t[0]; ccc = t[1];
		t = GGG(eee, aaa, bbb, ccc, ddd, block[ 1], 11); eee = t[0]; bbb = t[1];
		t = GGG(ddd, eee, aaa, bbb, ccc, block[ 3], 14); ddd = t[0]; aaa = t[1];
		t = GGG(ccc, ddd, eee, aaa, bbb, block[11], 14); ccc = t[0]; eee = t[1];
		t = GGG(bbb, ccc, ddd, eee, aaa, block[15],  6); bbb = t[0]; ddd = t[1];
		t = GGG(aaa, bbb, ccc, ddd, eee, block[ 0], 14); aaa = t[0]; ccc = t[1];
		t = GGG(eee, aaa, bbb, ccc, ddd, block[ 5],  6); eee = t[0]; bbb = t[1];
		t = GGG(ddd, eee, aaa, bbb, ccc, block[12],  9); ddd = t[0]; aaa = t[1];
		t = GGG(ccc, ddd, eee, aaa, bbb, block[ 2], 12); ccc = t[0]; eee = t[1];
		t = GGG(bbb, ccc, ddd, eee, aaa, block[13],  9); bbb = t[0]; ddd = t[1];
		t = GGG(aaa, bbb, ccc, ddd, eee, block[ 9], 12); aaa = t[0]; ccc = t[1];
		t = GGG(eee, aaa, bbb, ccc, ddd, block[ 7],  5); eee = t[0]; bbb = t[1];
		t = GGG(ddd, eee, aaa, bbb, ccc, block[10], 15); ddd = t[0]; aaa = t[1];
		t = GGG(ccc, ddd, eee, aaa, bbb, block[14],  8); ccc = t[0]; eee = t[1];

		if (this.type == 2) {
			tmp = dd; dd = ddd; ddd = tmp;
		}

		/* round 5 */
		t = JJ(bb, cc, dd, ee, aa, block[ 4],  9); bb = t[0]; dd = t[1];
		t = JJ(aa, bb, cc, dd, ee, block[ 0], 15); aa = t[0]; cc = t[1];
		t = JJ(ee, aa, bb, cc, dd, block[ 5],  5); ee = t[0]; bb = t[1];
		t = JJ(dd, ee, aa, bb, cc, block[ 9], 11); dd = t[0]; aa = t[1];
		t = JJ(cc, dd, ee, aa, bb, block[ 7],  6); cc = t[0]; ee = t[1];
		t = JJ(bb, cc, dd, ee, aa, block[12],  8); bb = t[0]; dd = t[1];
		t = JJ(aa, bb, cc, dd, ee, block[ 2], 13); aa = t[0]; cc = t[1];
		t = JJ(ee, aa, bb, cc, dd, block[10], 12); ee = t[0]; bb = t[1];
		t = JJ(dd, ee, aa, bb, cc, block[14],  5); dd = t[0]; aa = t[1];
		t = JJ(cc, dd, ee, aa, bb, block[ 1], 12); cc = t[0]; ee = t[1];
		t = JJ(bb, cc, dd, ee, aa, block[ 3], 13); bb = t[0]; dd = t[1];
		t = JJ(aa, bb, cc, dd, ee, block[ 8], 14); aa = t[0]; cc = t[1];
		t = JJ(ee, aa, bb, cc, dd, block[11], 11); ee = t[0]; bb = t[1];
		t = JJ(dd, ee, aa, bb, cc, block[ 6],  8); dd = t[0]; aa = t[1];
		t = JJ(cc, dd, ee, aa, bb, block[15],  5); cc = t[0]; ee = t[1];
		t = JJ(bb, cc, dd, ee, aa, block[13],  6); bb = t[0]; dd = t[1];

		/* parallel round 5 */
		t = FFF(bbb, ccc, ddd, eee, aaa, block[12] ,  8); bbb = t[0]; ddd = t[1];
		t = FFF(aaa, bbb, ccc, ddd, eee, block[15] ,  5); aaa = t[0]; ccc = t[1];
		t = FFF(eee, aaa, bbb, ccc, ddd, block[10] , 12); eee = t[0]; bbb = t[1];
		t = FFF(ddd, eee, aaa, bbb, ccc, block[ 4] ,  9); ddd = t[0]; aaa = t[1];
		t = FFF(ccc, ddd, eee, aaa, bbb, block[ 1] , 12); ccc = t[0]; eee = t[1];
		t = FFF(bbb, ccc, ddd, eee, aaa, block[ 5] ,  5); bbb = t[0]; ddd = t[1];
		t = FFF(aaa, bbb, ccc, ddd, eee, block[ 8] , 14); aaa = t[0]; ccc = t[1];
		t = FFF(eee, aaa, bbb, ccc, ddd, block[ 7] ,  6); eee = t[0]; bbb = t[1];
		t = FFF(ddd, eee, aaa, bbb, ccc, block[ 6] ,  8); ddd = t[0]; aaa = t[1];
		t = FFF(ccc, ddd, eee, aaa, bbb, block[ 2] , 13); ccc = t[0]; eee = t[1];
		t = FFF(bbb, ccc, ddd, eee, aaa, block[13] ,  6); bbb = t[0]; ddd = t[1];
		t = FFF(aaa, bbb, ccc, ddd, eee, block[14] ,  5); aaa = t[0]; ccc = t[1];
		t = FFF(eee, aaa, bbb, ccc, ddd, block[ 0] , 15); eee = t[0]; bbb = t[1];
		t = FFF(ddd, eee, aaa, bbb, ccc, block[ 3] , 13); ddd = t[0]; aaa = t[1];
		t = FFF(ccc, ddd, eee, aaa, bbb, block[ 9] , 11); ccc = t[0]; eee = t[1];
		t = FFF(bbb, ccc, ddd, eee, aaa, block[11] , 11); bbb = t[0]; ddd = t[1];

		if (this.type == 2) {
			tmp = ee; ee = eee; eee = tmp;
		}

		/* combine results */
		switch (this.type) {
			case 1:
				ddd = safeAdd(ddd, safeAdd(cc, H[1]));               /* final result for H[0] */
				H[1] = safeAdd(H[2], safeAdd(dd, eee));
				H[2] = safeAdd(H[3], safeAdd(ee, aaa));
				H[3] = safeAdd(H[4], safeAdd(aa, bbb));
				H[4] = safeAdd(H[0], safeAdd(bb, ccc));
				H[0] = ddd;
				break;
			case 2:
				H[0] += aa;
				H[1] += bb;
				H[2] += cc;
				H[3] += dd;
				H[4] += ee;
				H[5] += aaa;
				H[6] += bbb;
				H[7] += ccc;
				H[8] += ddd;
				H[9] += eee;
				break;
		}

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
}

jCastle.algorithm.RIPEMD160 = jCastle.algorithm.ripemd160;

/* Implementation of RIPEMD-128 based on the source by Antoon Bosselaers, ESAT-COSIC
 */
jCastle._algorithmInfo['ripemd-160'] = {
	algorithm_type: 'hash',
	object_name: 'ripemd160',
	block_size: 64,
	digest_size: 20,
	oid: "1.3.36.3.2.1"
};

jCastle.algorithm.ripemd320 = class extends jCastle.algorithm.ripemd160
{
	/**
	 * creates the hash algorithm instance.
	 * 
	 * @param {string} hash_name hash algorithm name
	 * @constructor
	 */
    constructor(hash_name)
    {
        super(hash_name);

        this.algoName = hash_name;
        this._state = null;
    }

	/**
	 * initialize the hash algorithm and sets state with initial value.
	 * 
	 * @public
	 * @param {object} options options object
	 */
	init(options = {})
	{
		this._state = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0, 0x76543210, 0xfedcba98, 0x89abcdef, 0x01234567, 0x3c2d1e0f];
		this.type = 2;
	}
}

jCastle.algorithm.RIPEMD320 = jCastle.algorithm.ripemd320;

jCastle._algorithmInfo['ripemd-320'] = {
	algorithm_type: 'hash',
	object_name: 'ripemd320',
	block_size: 64,
	digest_size: 40,
	oid: null
};

module.exports = {
    ripemd128: jCastle.algorithm.ripemd128,
    ripemd256: jCastle.algorithm.ripemd256,
    ripemd160: jCastle.algorithm.ripemd160,
    ripemd320: jCastle.algorithm.ripemd320
};