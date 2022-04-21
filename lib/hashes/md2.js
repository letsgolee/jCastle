/**
 * A Javascript implemenation of MD2
 * 
 * @author Jacob Lee
 * 
 * Copyright (C) 2015-2022 Jacob Lee.
 */
var jCastle = require('../jCastle');
require('../util');

jCastle.algorithm.md2 = class
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
		this._state = new Array(48);
		this._chksum = new Array(16);
	}

	_compress(buf)
	{
		var j, k, t;
	   
		/* copy block */
		for (j = 0; j < 16; j++) {
			this._state[16+j] = buf[j];
			this._state[32+j] = this._state[j] ^ this._state[16+j];
		}

		t = 0x00;

		/* do 18 rounds */
		for (j = 0; j < 18; j++) {
			for (k = 0; k < 48; k++) {
				this._state[k] ^= jCastle.algorithm.md2.PI_SUBST[t];
				t = this._state[k] & 255;
			}
			t = (t + j) & 255;
		}
	}

	_updateChksum(buf)
	{
		var j, L;

		L = this._chksum[15];
			
		for (j = 0; j < 16; j++) {
			/* caution, the RFC says its "C[j] = S[M[i*16+j] xor L]" but the reference source code [and test vectors] say 
			   otherwise.
			*/
			this._chksum[j] ^= jCastle.algorithm.md2.PI_SUBST[(buf[j] ^ L) & 255] & 255;
			L =this._chksum[j];
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
		this._compress(input);
		this._updateChksum(input);
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
		var block_size = jCastle._algorithmInfo[this.algoName].block_size;
		var index = input.length % block_size;
		var k = block_size - index;
		var padding = Buffer.alloc(k, k);
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
		this._compress(this._chksum);
		var output = Buffer.from(this._state.slice(0, 16));
		this._state = null;
		this._chksum = null;

		return output;
	}
};

jCastle.algorithm.MD2 = jCastle.algorithm.md2;

jCastle._algorithmInfo['md2'] = {
	algorithm_type: 'hash',
	object_name: 'md2',
	block_size: 16,
	digest_size: 16,
	oid: "1.2.840.113549.2.2"
};
	

jCastle.algorithm.md2.PI_SUBST = [
	41, 46, 67, 201, 162, 216, 124, 1, 61, 54, 84, 161, 236, 240, 6,
	19, 98, 167, 5, 243, 192, 199, 115, 140, 152, 147, 43, 217, 188,
	76, 130, 202, 30, 155, 87, 60, 253, 212, 224, 22, 103, 66, 111, 24,
	138, 23, 229, 18, 190, 78, 196, 214, 218, 158, 222, 73, 160, 251,
	245, 142, 187, 47, 238, 122, 169, 104, 121, 145, 21, 178, 7, 63,
	148, 194, 16, 137, 11, 34, 95, 33, 128, 127, 93, 154, 90, 144, 50,
	39, 53, 62, 204, 231, 191, 247, 151, 3, 255, 25, 48, 179, 72, 165,
	181, 209, 215, 94, 146, 42, 172, 86, 170, 198, 79, 184, 56, 210,
	150, 164, 125, 182, 118, 252, 107, 226, 156, 116, 4, 241, 69, 157,
	112, 89, 100, 113, 135, 32, 134, 91, 207, 101, 230, 45, 168, 2, 27,
	96, 37, 173, 174, 176, 185, 246, 28, 70, 97, 105, 52, 64, 126, 15,
	85, 71, 163, 35, 221, 81, 175, 58, 195, 92, 249, 206, 186, 197,
	234, 38, 44, 83, 13, 110, 133, 40, 132, 9, 211, 223, 205, 244, 65,
	129, 77, 82, 106, 220, 55, 200, 108, 193, 171, 250, 36, 225, 123,
	8, 12, 189, 177, 74, 120, 136, 149, 139, 227, 99, 232, 109, 233,
	203, 213, 254, 59, 0, 29, 57, 242, 239, 183, 14, 102, 88, 208, 228,
	166, 119, 114, 248, 235, 117, 75, 10, 49, 68, 80, 180, 143, 237,
	31, 26, 219, 153, 141, 51, 159, 17, 131, 20
];

module.exports = jCastle.algorithm.md2;