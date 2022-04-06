/**
 * A Javascript implemenation of MD5
 * 
 * @author Jacob Lee
 * 
 * Copyright (C) 2015-2022 Jacob Lee.
 */

var jCastle = require('../jCastle');
require('../util');

jCastle.algorithm.md5 = class
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
		this._state = [1732584193, -271733879, -1732584194, 271733878];
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

		var block = [];
		var block_size = jCastle._algorithmInfo[this.algoName].block_size;
		for (var i = 0; i < block_size / 4; i++) {
			block[i] = input.readInt32LE(i * 4);
		}

		var H = this._state;

		var a = H[0];
		var b = H[1];
		var c = H[2];
		var d = H[3];

		//
		// These functions implement the four basic operations the algorithm uses.
		//
		function md5_cmn(q, a, b, x, s, t)
		{
		  return safeAdd(jCastle.util.rotl32(safeAdd(safeAdd(a, q), safeAdd(x, t)), s),b);
		}
		function FF(a, b, c, d, x, s, t)
		{
		  return md5_cmn((b & c) | ((~b) & d), a, b, x, s, t);
		}
		function GG(a, b, c, d, x, s, t)
		{
		  return md5_cmn((b & d) | (c & (~d)), a, b, x, s, t);
		}
		function HH(a, b, c, d, x, s, t)
		{
		  return md5_cmn(b ^ c ^ d, a, b, x, s, t);
		}
		function II(a, b, c, d, x, s, t)
		{
		  return md5_cmn(c ^ (b | (~d)), a, b, x, s, t);
		}

		var olda = a;
		var oldb = b;
		var oldc = c;
		var oldd = d;

		a = FF(a, b, c, d, block[ 0], 7 , -680876936);
		d = FF(d, a, b, c, block[ 1], 12, -389564586);
		c = FF(c, d, a, b, block[ 2], 17,  606105819);
		b = FF(b, c, d, a, block[ 3], 22, -1044525330);
		a = FF(a, b, c, d, block[ 4], 7 , -176418897);
		d = FF(d, a, b, c, block[ 5], 12,  1200080426);
		c = FF(c, d, a, b, block[ 6], 17, -1473231341);
		b = FF(b, c, d, a, block[ 7], 22, -45705983);
		a = FF(a, b, c, d, block[ 8], 7 ,  1770035416);
		d = FF(d, a, b, c, block[ 9], 12, -1958414417);
		c = FF(c, d, a, b, block[10], 17, -42063);
		b = FF(b, c, d, a, block[11], 22, -1990404162);
		a = FF(a, b, c, d, block[12], 7 ,  1804603682);
		d = FF(d, a, b, c, block[13], 12, -40341101);
		c = FF(c, d, a, b, block[14], 17, -1502002290);
		b = FF(b, c, d, a, block[15], 22,  1236535329);

		a = GG(a, b, c, d, block[ 1], 5 , -165796510);
		d = GG(d, a, b, c, block[ 6], 9 , -1069501632);
		c = GG(c, d, a, b, block[11], 14,  643717713);
		b = GG(b, c, d, a, block[ 0], 20, -373897302);
		a = GG(a, b, c, d, block[ 5], 5 , -701558691);
		d = GG(d, a, b, c, block[10], 9 ,  38016083);
		c = GG(c, d, a, b, block[15], 14, -660478335);
		b = GG(b, c, d, a, block[ 4], 20, -405537848);
		a = GG(a, b, c, d, block[ 9], 5 ,  568446438);
		d = GG(d, a, b, c, block[14], 9 , -1019803690);
		c = GG(c, d, a, b, block[ 3], 14, -187363961);
		b = GG(b, c, d, a, block[ 8], 20,  1163531501);
		a = GG(a, b, c, d, block[13], 5 , -1444681467);
		d = GG(d, a, b, c, block[ 2], 9 , -51403784);
		c = GG(c, d, a, b, block[ 7], 14,  1735328473);
		b = GG(b, c, d, a, block[12], 20, -1926607734);

		a = HH(a, b, c, d, block[ 5], 4 , -378558);
		d = HH(d, a, b, c, block[ 8], 11, -2022574463);
		c = HH(c, d, a, b, block[11], 16,  1839030562);
		b = HH(b, c, d, a, block[14], 23, -35309556);
		a = HH(a, b, c, d, block[ 1], 4 , -1530992060);
		d = HH(d, a, b, c, block[ 4], 11,  1272893353);
		c = HH(c, d, a, b, block[ 7], 16, -155497632);
		b = HH(b, c, d, a, block[10], 23, -1094730640);
		a = HH(a, b, c, d, block[13], 4 ,  681279174);
		d = HH(d, a, b, c, block[ 0], 11, -358537222);
		c = HH(c, d, a, b, block[ 3], 16, -722521979);
		b = HH(b, c, d, a, block[ 6], 23,  76029189);
		a = HH(a, b, c, d, block[ 9], 4 , -640364487);
		d = HH(d, a, b, c, block[12], 11, -421815835);
		c = HH(c, d, a, b, block[15], 16,  530742520);
		b = HH(b, c, d, a, block[ 2], 23, -995338651);

		a = II(a, b, c, d, block[ 0], 6 , -198630844);
		d = II(d, a, b, c, block[ 7], 10,  1126891415);
		c = II(c, d, a, b, block[14], 15, -1416354905);
		b = II(b, c, d, a, block[ 5], 21, -57434055);
		a = II(a, b, c, d, block[12], 6 ,  1700485571);
		d = II(d, a, b, c, block[ 3], 10, -1894986606);
		c = II(c, d, a, b, block[10], 15, -1051523);
		b = II(b, c, d, a, block[ 1], 21, -2054922799);
		a = II(a, b, c, d, block[ 8], 6 ,  1873313359);
		d = II(d, a, b, c, block[15], 10, -30611744);
		c = II(c, d, a, b, block[ 6], 15, -1560198380);
		b = II(b, c, d, a, block[13], 21,  1309151649);
		a = II(a, b, c, d, block[ 4], 6 , -145523070);
		d = II(d, a, b, c, block[11], 10, -1120210379);
		c = II(c, d, a, b, block[ 2], 15,  718787259);
		b = II(b, c, d, a, block[ 9], 21, -343485551);

		a = safeAdd(a, olda);
		b = safeAdd(b, oldb);
		c = safeAdd(c, oldc);
		d = safeAdd(d, oldd);

		this._state = [a, b, c, d];
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

jCastle.algorithm.MD5 = jCastle.algorithm.md5;

jCastle._algorithmInfo['md5'] = {
	algorithm_type: 'hash',
	object_name: 'md5',
	block_size: 64,
	digest_size: 16,
	oid: "1.2.840.113549.2.5"
};

module.exports = jCastle.algorithm.md5;