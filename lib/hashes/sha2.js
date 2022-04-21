/**
 * A Javascript implemenation of SHA2 Family
 * 
 * @author Jacob Lee
 * Copyright (C) 2015-2022 Jacob Lee.
 */

var jCastle = require('../jCastle');
require('../util');
var INT64 = require('../int64');

jCastle.algorithm.sha224 = class
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
        this._rounds = 64;
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
		this._state = [
			0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
			0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
		];
	}

	/**
	 * processes digesting.
	 * 
	 * @public
	 * @param {buffer} input input data to be digested.
	 */
	process(input)
	{
		var W = [];
		var a, b, c, d, e, f, g, h;
		var T1, T2;
		var H;
		var safeAdd = jCastle.util.safeAdd32;

		var block = [];
		var block_size = jCastle._algorithmInfo[this.algoName].block_size;
		for (var i = 0; i < block_size / 4; i++) {
			block[i] = input.readInt32BE(i * 4);
		}

		H = this._state;

		a = H[0];
		b = H[1];
		c = H[2];
		d = H[3];
		e = H[4];
		f = H[5];
		g = H[6];
		h = H[7];

		for (var t = 0; t < this._rounds; t++) {
			if (t < 16) {
				W[t] = block[t];
			} else {
				W[t] = safeAdd(safeAdd(safeAdd(this.gamma1(W[t - 2]), W[t - 7]), this.gamma0(W[t - 15])), W[t - 16]);
			}

			T1 = safeAdd(safeAdd(safeAdd(safeAdd(h, this.sigma1(e)), this.ch(e, f, g)), jCastle.algorithm.sha224.K[t]), W[t]);
			T2 = safeAdd(this.sigma0(a), this.maj(a, b, c));
			h = g;
			g = f;
			f = e;
			e = safeAdd(d, T1);
			d = c;
			c = b;
			b = a;
			a = safeAdd(T1, T2);
		}

		H[0] = safeAdd(a, H[0]);
		H[1] = safeAdd(b, H[1]);
		H[2] = safeAdd(c, H[2]);
		H[3] = safeAdd(d, H[3]);
		H[4] = safeAdd(e, H[4]);
		H[5] = safeAdd(f, H[5]);
		H[6] = safeAdd(g, H[6]);
		H[7] = safeAdd(h, H[7]);

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
		
		// length will be saved as int64.
		// but javascript only can save as int32
		var length_pos = pads;
		pads += 8;
		var padding = Buffer.alloc(pads);
		
		padding[0] = 0x80;
		
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
		this._state.pop();
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

	sigma0(x)
	{
		var rotr32 = jCastle.util.rotr32;
		return rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22);
	}

	sigma1(x)
	{
		var rotr32 = jCastle.util.rotr32;
		return rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25);
	}

	gamma0(x)
	{
		var rotr32 = jCastle.util.rotr32;
		return rotr32(x, 7) ^ rotr32(x, 18) ^ jCastle.util.shr32(x, 3);
	}

	gamma1(x)
	{
		var rotr32 = jCastle.util.rotr32;
		return rotr32(x, 17) ^ rotr32(x, 19) ^ jCastle.util.shr32(x, 10);
	}
};

jCastle.algorithm.SHA224 = jCastle.algorithm.sha224;

jCastle._algorithmInfo['sha-224'] = {
	algorithm_type: 'hash',
	object_name: 'sha224',
	block_size: 64,
	digest_size: 28,
	oid: "2.16.840.1.101.3.4.2.4"
};

jCastle.algorithm.sha224.K = [
	0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
	0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
	0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
	0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
	0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
	0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
	0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
	0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
	0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
	0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
	0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
	0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
	0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
	0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
	0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
	0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
];


jCastle.algorithm.sha256 = class extends jCastle.algorithm.sha224
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
        this._rounds = 64;
    }

	/**
	 * initialize the hash algorithm and sets state with initial value.
	 * 
	 * @public
	 * @param {object} options options object
	 */
	init(options = {})
	{
		this._state = [
			0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
			0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
		];
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
};

jCastle.algorithm.SHA256 = jCastle.algorithm.sha256;

jCastle._algorithmInfo['sha-256'] = {
	algorithm_type: 'hash',
	object_name: 'sha256',
	block_size: 64,
	digest_size: 32,
	oid: "2.16.840.1.101.3.4.2.1"
};



jCastle.algorithm.sha384 = class
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

        // if (typeof INT64 == 'undefined') {
        //     throw jCastle.exception("INT64_REQUIRED");
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

	/**
	 * initialize the hash algorithm and sets state with initial value.
	 * 
	 * @public
	 * @param {object} options options object
	 */
	init(options = {})
	{
		this._state = [
			new INT64(0xcbbb9d5d, 0xc1059ed8), new INT64(0x0629a292a, 0x367cd507), new INT64(0x9159015a, 0x3070dd17), new INT64(0x152fecd8, 0xf70e5939),
			new INT64(0x67332667, 0xffc00b31), new INT64(0x98eb44a87, 0x68581511), new INT64(0xdb0c2e0d, 0x64f98fa7), new INT64(0x47b5481d, 0xbefa4fa4)
		];
	}

	/**
	 * processes digesting.
	 * 
	 * @public
	 * @param {buffer} input input data to be digested.
	 */
	process(input)
	{
		var W = [];
		var a, b, c, d, e, f, g, h;
		var T1, T2;
		var H;

		var block = [];
		var block_size = jCastle._algorithmInfo[this.algoName].block_size;
		for (var i = 0; i < block_size / 4; i++) {
			block[i] = input.readInt32BE(i * 4);
		}

		H = this._state;

		a = H[0];
		b = H[1];
		c = H[2];
		d = H[3];
		e = H[4];
		f = H[5];
		g = H[6];
		h = H[7];

		for (var t = 0; t < this._rounds; t++) {
			if (t < 16) {
				W[t] = new INT64(block[t * 2], block[t * 2 + 1]);
			} else {
				W[t] = this.gamma1(W[t - 2]).add(W[t - 7]).add(this.gamma0(W[t - 15])).add(W[t - 16]);
			}
			T1 = h.add(this.sigma1(e)).add(this.ch(e, f, g)).add(jCastle.algorithm.sha384.K[t]).add(W[t]);
			T2 = this.sigma0(a).add(this.maj(a, b, c));
			h = g;
			g = f;
			f = e;
			e = d.add(T1);
			d = c;
			c = b;
			b = a;
			a = T1.add(T2);
		}

		H[0] = a.add(H[0]);
		H[1] = b.add(H[1]);
		H[2] = c.add(H[2]);
		H[3] = d.add(H[3]);
		H[4] = e.add(H[4]);
		H[5] = f.add(H[5]);
		H[6] = g.add(H[6]);
		H[7] = h.add(H[7]);

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

		// if the length is currently above 112 bytes we append zeros
		// then compress.  Then we can fall back to padding zeros and length
		// encoding like normal.
		if (index > 112) {
			while (index < 128) {
				pads++; index++;
			}
			index = 0;
			pos += 128;
		}

		// pad upto 120 bytes of zeroes 
		// note: that from 112 to 120 is the 64 MSB of the length.  We assume that you won't hash
		//  > 2^64 bits of data... :-)
		while (index < 120) {
			pads++; index++;
		}
		
		// length size is saved as int64.
		// however javascript only can save as int32.
		var length_pos = pads;
		pads += 8;
		
		var padding = Buffer.alloc(pads);
		padding[0] = 0x80;
		
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
		var H = this._state;
		this._state = [
			H[0].msint, H[0].lsint,
			H[1].msint, H[1].lsint,
			H[2].msint, H[2].lsint,
			H[3].msint, H[3].lsint,
			H[4].msint, H[4].lsint,
			H[5].msint, H[5].lsint
		];
		var digest_size = jCastle._algorithmInfo[this.algoName].digest_size;
		var output = Buffer.alloc(digest_size);

		for (var i = 0; i < digest_size / 4; i++) {
			output.writeInt32BE(this._state[i], i * 4, true);
		}
		this._state = null;

		return output;
	}

	ch(x, y, z)
	{
		return new INT64(
			(x.msint & y.msint) ^ (~x.msint & z.msint),
			(x.lsint & y.lsint) ^ (~x.lsint & z.lsint)
		);
	}

	maj(x, y, z)
	{
		return new INT64(
			(x.msint & y.msint) ^ (x.msint & z.msint) ^ (y.msint & z.msint),
			(x.lsint & y.lsint) ^ (x.lsint & z.lsint) ^ (y.lsint & z.lsint)
		);
	}

	sigma0(x)
	{
		var rotr28 = x.rotr(28);
		var rotr34 = x.rotr(34);
		var rotr39 = x.rotr(39);

		return new INT64(
			rotr28.msint ^ rotr34.msint ^ rotr39.msint,
			rotr28.lsint ^ rotr34.lsint ^ rotr39.lsint
		);
	}

	sigma1(x)
	{
		var rotr14 = x.rotr(14);
		var rotr18 = x.rotr(18);
		var rotr41 = x.rotr(41);

		return new INT64(
			rotr14.msint ^ rotr18.msint ^ rotr41.msint,
			rotr14.lsint ^ rotr18.lsint ^ rotr41.lsint
		);
	}

	gamma0(x)
	{
		var rotr1 = x.rotr(1);
		var rotr8 = x.rotr(8);
		//var shr7 = x.shr(7);
		var shr7 = x.shiftRightUnsigned(7); // important! for INT64

		return new INT64(
			rotr1.msint ^ rotr8.msint ^ shr7.msint,
			rotr1.lsint ^ rotr8.lsint ^ shr7.lsint
		);
	}

	gamma1(x)
	{
		var rotr19 = x.rotr(19);
		var rotr61 = x.rotr(61);
		//var shr6 = x.shr(6);
		var shr6 = x.shiftRightUnsigned(6); // important! for INT64

		return new INT64(
			rotr19.msint ^ rotr61.msint ^ shr6.msint,
			rotr19.lsint ^ rotr61.lsint ^ shr6.lsint
		);
	}
};

jCastle.algorithm.SHA384 = jCastle.algorithm.sha384;

jCastle._algorithmInfo['sha-384'] = {
	algorithm_type: 'hash',
	object_name: 'sha384',
	block_size: 128,
	digest_size: 48,
	oid: "2.16.840.1.101.3.4.2.2"
};

jCastle.algorithm.sha384.K = [
	new INT64(0x428a2f98, 0xd728ae22), new INT64(0x71374491, 0x23ef65cd), new INT64(0xb5c0fbcf, 0xec4d3b2f), new INT64(0xe9b5dba5, 0x8189dbbc),
	new INT64(0x3956c25b, 0xf348b538), new INT64(0x59f111f1, 0xb605d019), new INT64(0x923f82a4, 0xaf194f9b), new INT64(0xab1c5ed5, 0xda6d8118),
	new INT64(0xd807aa98, 0xa3030242), new INT64(0x12835b01, 0x45706fbe), new INT64(0x243185be, 0x4ee4b28c), new INT64(0x550c7dc3, 0xd5ffb4e2),
	new INT64(0x72be5d74, 0xf27b896f), new INT64(0x80deb1fe, 0x3b1696b1), new INT64(0x9bdc06a7, 0x25c71235), new INT64(0xc19bf174, 0xcf692694),
	new INT64(0xe49b69c1, 0x9ef14ad2), new INT64(0xefbe4786, 0x384f25e3), new INT64(0x0fc19dc6, 0x8b8cd5b5), new INT64(0x240ca1cc, 0x77ac9c65),
	new INT64(0x2de92c6f, 0x592b0275), new INT64(0x4a7484aa, 0x6ea6e483), new INT64(0x5cb0a9dc, 0xbd41fbd4), new INT64(0x76f988da, 0x831153b5),
	new INT64(0x983e5152, 0xee66dfab), new INT64(0xa831c66d, 0x2db43210), new INT64(0xb00327c8, 0x98fb213f), new INT64(0xbf597fc7, 0xbeef0ee4),
	new INT64(0xc6e00bf3, 0x3da88fc2), new INT64(0xd5a79147, 0x930aa725), new INT64(0x06ca6351, 0xe003826f), new INT64(0x14292967, 0x0a0e6e70),
	new INT64(0x27b70a85, 0x46d22ffc), new INT64(0x2e1b2138, 0x5c26c926), new INT64(0x4d2c6dfc, 0x5ac42aed), new INT64(0x53380d13, 0x9d95b3df),
	new INT64(0x650a7354, 0x8baf63de), new INT64(0x766a0abb, 0x3c77b2a8), new INT64(0x81c2c92e, 0x47edaee6), new INT64(0x92722c85, 0x1482353b),
	new INT64(0xa2bfe8a1, 0x4cf10364), new INT64(0xa81a664b, 0xbc423001), new INT64(0xc24b8b70, 0xd0f89791), new INT64(0xc76c51a3, 0x0654be30),
	new INT64(0xd192e819, 0xd6ef5218), new INT64(0xd6990624, 0x5565a910), new INT64(0xf40e3585, 0x5771202a), new INT64(0x106aa070, 0x32bbd1b8),
	new INT64(0x19a4c116, 0xb8d2d0c8), new INT64(0x1e376c08, 0x5141ab53), new INT64(0x2748774c, 0xdf8eeb99), new INT64(0x34b0bcb5, 0xe19b48a8),
	new INT64(0x391c0cb3, 0xc5c95a63), new INT64(0x4ed8aa4a, 0xe3418acb), new INT64(0x5b9cca4f, 0x7763e373), new INT64(0x682e6ff3, 0xd6b2b8a3),
	new INT64(0x748f82ee, 0x5defb2fc), new INT64(0x78a5636f, 0x43172f60), new INT64(0x84c87814, 0xa1f0ab72), new INT64(0x8cc70208, 0x1a6439ec),
	new INT64(0x90befffa, 0x23631e28), new INT64(0xa4506ceb, 0xde82bde9), new INT64(0xbef9a3f7, 0xb2c67915), new INT64(0xc67178f2, 0xe372532b),
	new INT64(0xca273ece, 0xea26619c), new INT64(0xd186b8c7, 0x21c0c207), new INT64(0xeada7dd6, 0xcde0eb1e), new INT64(0xf57d4f7f, 0xee6ed178),
	new INT64(0x06f067aa, 0x72176fba), new INT64(0x0a637dc5, 0xa2c898a6), new INT64(0x113f9804, 0xbef90dae), new INT64(0x1b710b35, 0x131c471b),
	new INT64(0x28db77f5, 0x23047d84), new INT64(0x32caab7b, 0x40c72493), new INT64(0x3c9ebe0a, 0x15c9bebc), new INT64(0x431d67c4, 0x9c100d4c),
	new INT64(0x4cc5d4be, 0xcb3e42b6), new INT64(0x597f299c, 0xfc657e2a), new INT64(0x5fcb6fab, 0x3ad6faec), new INT64(0x6c44198c, 0x4a475817)
];


jCastle.algorithm.sha512 = class extends jCastle.algorithm.sha384
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
        this._rounds = 80;

        // if (typeof INT64 == 'undefined') {
        //     throw jCastle.throwException("INT64_REQUIRED");
        // }
    }

	/**
	 * initialize the hash algorithm and sets state with initial value.
	 * 
	 * @public
	 * @param {object} options options object
	 */
	init(options = {})
	{
		//switch (this.algoName) {
		switch (jCastle._algorithmInfo[this.algoName].digest_size) {
			//case 'sha-512/224':
			case 28:
				this._state = [
					new INT64(0x8C3D37C8, 0x19544DA2), new INT64(0x73E19966, 0x89DCD4D6), new INT64(0x1DFAB7AE, 0x32FF9C82), new INT64(0x679DD514, 0x582F9FCF),
					new INT64(0x0F6D2B69, 0x7BD44DA8), new INT64(0x77E36F73, 0x04C48942), new INT64(0x3F9D85A8, 0x6A1D36C8), new INT64(0x1112E6AD, 0x91D692A1)
				];
				break;
			//case 'sha-512/256':
			case 32:
				this._state = [
					new INT64(0x22312194, 0xFC2BF72C), new INT64(0x9F555FA3, 0xC84C64C2), new INT64(0x2393B86B, 0x6F53B151), new INT64(0x96387719, 0x5940EABD),
					new INT64(0x96283EE2, 0xA88EFFE3), new INT64(0xBE5E1E25, 0x53863992), new INT64(0x2B0199FC, 0x2C85B8AA), new INT64(0x0EB72DDC, 0x81C52CA2)
				];
				break; 
			default:
				this._state = [
					new INT64(0x6a09e667, 0xf3bcc908), new INT64(0xbb67ae85, 0x84caa73b), new INT64(0x3c6ef372, 0xfe94f82b), new INT64(0xa54ff53a, 0x5f1d36f1),
					new INT64(0x510e527f, 0xade682d1), new INT64(0x9b05688c, 0x2b3e6c1f), new INT64(0x1f83d9ab, 0xfb41bd6b), new INT64(0x5be0cd19, 0x137e2179)
				];
				break;
		}
	}

	/**
	 * finishes digesting process and returns the result.
	 * 
	 * @public
	 * @returns the digested data.
	 */
	finish()
	{
		var H = this._state;
		var digest_size = jCastle._algorithmInfo[this.algoName].digest_size;

		//switch (this.algoName) {
		switch (digest_size) {
			//case 'sha-512/224':
			case 28:
				this._state = [
					H[0].msint, H[0].lsint,
					H[1].msint, H[1].lsint,
					H[2].msint, H[2].lsint,
					H[3].msint
				];
				break;
			//case 'sha-512/256':
			case 32:
				this._state = [
					H[0].msint, H[0].lsint,
					H[1].msint, H[1].lsint,
					H[2].msint, H[2].lsint,
					H[3].msint, H[3].lsint
				];
				break;
			default:
				this._state = [
					H[0].msint, H[0].lsint,
					H[1].msint, H[1].lsint,
					H[2].msint, H[2].lsint,
					H[3].msint, H[3].lsint,
					H[4].msint, H[4].lsint,
					H[5].msint, H[5].lsint,
					H[6].msint, H[6].lsint,
					H[7].msint, H[7].lsint
				];
				break;
		}
		
		var output = Buffer.alloc(digest_size);

		for (var i = 0; i < digest_size / 4; i++) {
			output.writeInt32BE(this._state[i], i * 4, true);
		}
		this._state = null;

		return output;
	}
};

jCastle.algorithm.SHA512 = jCastle.algorithm.sha512;

jCastle._algorithmInfo['sha-512'] = {
	algorithm_type: 'hash',
	object_name: 'sha512',
	block_size: 128,
	digest_size: 64,
	oid: "2.16.840.1.101.3.4.2.3"
};

jCastle._algorithmInfo['sha-512/224'] = {
	algorithm_type: 'hash',
	object_name: 'sha512',
	block_size: 128,
	digest_size: 28,
	oid: "2.16.840.1.101.3.4.2.5"
};

jCastle._algorithmInfo['sha-512/256'] = {
	algorithm_type: 'hash',
	object_name: 'sha512',
	block_size: 128,
	digest_size: 32,
	oid: "2.16.840.1.101.3.4.2.6"
};

module.exports = {
    sha224: jCastle.algorithm.sha224,
    sha256: jCastle.algorithm.sha256,
    sha384: jCastle.algorithm.sha384,
    sha512: jCastle.algorithm.sha512
};