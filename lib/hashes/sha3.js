/**
 * A Javascript implemenation of SHA3 Family & SHAKE-128/256
 * 
 * @author Jacob Lee
 * 
 * Copyright (C) 2015-2022 Jacob Lee.
 */

var jCastle = require('../jCastle');
require('../util');
var INT64 = require('../int64');

/*
SHAKE's digest length is arbitrary:
You can set it in options.

for instance, new jCastle.digest('shake-128').digest(data, {outputBits: 256});
or new jCastle.digest('shake-128/256');

*/
jCastle.algorithm.sha3 = class
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

        this.bit_length = 0;

        // if (typeof INT64 == 'undefined') {
        //     throw jCastle.exception("INT64_REQUIRED", 'SHA3001');
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
		if ('outputSize' in options) options.outputLength = options.outputSize;
		
		this._state = new Array(1600 / 8); // 200

		if ('outputLength' in options && /^shake-/.test(this.algoName)) {
			this.bit_length = options.outputLength * 8;

			if (this.algoName == 'shake-128') {
				var min_length = 128;
			} else {
				var min_length = 256;
			}
/*
			if (this.bit_length % 8) {
				throw "The bit_length of the output should be a muliple of 8."
			}
*/
			if (this.bit_length < min_length) {
				throw jCastle.throwException("OUTPUT_BITS_TOO_SMALL", 'SHA3002');
			}
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
		for (var i = 0; i < input.length; i++) {
			this._state[i] ^= input[i];
		}

		this._permutate();
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

		// append a bit
		// SHA3 : 0x06
		// Keccak: 0x01
		// Shake: 0x1f
		var extra = 0x06; // default
		if (/^shake-/.test(this.algoName)) extra = 0x1f;
		else if (/^keccak-/.test(this.algoName)) extra = 0x01; // deesn't support keccak hashers, but for the possibility
		pads++; index++;

		// fill with 0x00 
		while (index < jCastle._algorithmInfo[this.algoName].block_size - 1) {
			pads++; index++;
		}

		// add 0x80 to the end 
		pads++;
		
		var padding = Buffer.alloc(pads);
		padding[0] = extra;
		padding[pads - 1] = 0x80;
		
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
		var rate = jCastle._algorithmInfo[this.algoName].rate;
		var output = [];
		// shake's output is of obitrary bit length.
		var bit_length = this.bit_length > 0 ? this.bit_length : jCastle._algorithmInfo[this.algoName].digest_size * 8;
		var i = 0;

		if (rate == 1024) {
			var queue = this.state.slice(0, 128);
			var available = 1024;
		} else {
			var queue = this._state.slice(0, rate / 8);
			var available = rate;
		}

		while (i < bit_length) {
			if (!available) {
				this._permutate();

				if (rate == 1024) {
					queue = this.state.slice(0, 128);
					available = 1024;
				} else {
					queue = this.state.slice(0, rate / 8);
					available = rate;
				}
			}

			var partial = available;
			if (partial > bit_length - i) {
				partial = bit_length - i;
			}

			var start = (rate - available) / 8;
			var end = start + partial / 8;
			output = output.concat(queue.slice(start, end));
			available -= partial;
			i += partial;
		}

		this._state = null;
		this.bit_length = 0;

		return Buffer.from(output);
	}

	_permutate()
	{
		var s = [];

		// change to int64 array
		for (var i = 0; i < 25; i++) {
			s[i] = new INT64(jCastle.util.load32(this._state, i * 8 + 4), jCastle.util.load32(this._state, i * 8));
		}

		for (var round = 0; round < 24; round++) {
			this._theta(s);
			this._rho(s);
			this._pi(s);
			this._chi(s);
			this._iota(s, round);
		}

		// change to byte array
		for (var i = 0; i < 25; i++) {
			jCastle.util.store32(this._state, i * 8, s[i].lsint);
			jCastle.util.store32(this._state, i * 8 + 4, s[i].msint);
		}
	}

	_theta(s)
	{
		var C = new Array(5);

		for (var x = 0; x < 5; x++) {
			C[x] = new INT64();
			for (var y = 0; y < 5; y++) {
				C[x] = C[x].xor(s[x + 5 * y]);
			}
		}

		for (var x = 0; x < 5; x++) {
			var dX = C[(x + 1) % 5].shiftLeft(1).xor(C[(x + 1) % 5].shiftRightUnsigned(63)).xor(C[(x + 4) % 5]);
			for (var y = 0; y < 5; y++) {
				s[x + 5 * y] = s[x + 5 * y].xor(dX);
			}
		}
	}

	_rho(s)
	{
		var rho_offset = jCastle.algorithm.sha3.RHO_OFFSET;
		for (var x = 0; x < 5; x++) {
			for (var y = 0; y < 5; y++) {
				var idx = x + 5 * y;
				s[idx] = rho_offset[idx] != 0 ? (
					s[idx].shiftLeft(rho_offset[idx]).xor(s[idx].shiftRightUnsigned(64 - rho_offset[idx]))
					) : s[idx];
			}
		}
	}

	_pi(s)
	{
		var temp = s.slice(0);

		for (var x = 0; x < 5; x++) {
			for (var y = 0; y < 5; y++) {
				s[y + 5 * ((2 * x + 3 * y) % 5)] = temp[x +  5 * y];
			}
		}
	}

	_chi(s)
	{
		var chiC = new Array(5);

		for (var y = 0; y < 5; y++) {
			for (var x = 0; x < 5; x++) {
				chiC[x] = s[x + 5 * y].xor(s[((x + 1) % 5) + 5 * y].not().and(s[((x + 2) % 5) + 5 * y]));
			}
			for (var x = 0; x < 5; x++) {
				s[x + 5 * y] = chiC[x];
			};
		}
	}

	_iota(s, round)
	{
		s[0] = s[0].xor(jCastle.algorithm.sha3.ROUND_CONST[round]);
	}
}

jCastle.algorithm.sha3.ROUND_CONST = [
	new INT64(0x00000000, 0x00000001), new INT64(0x00000000, 0x00008082), new INT64(0x80000000, 0x0000808A),
	new INT64(0x80000000, 0x80008000), new INT64(0x00000000, 0x0000808B), new INT64(0x00000000, 0x80000001),
	new INT64(0x80000000, 0x80008081), new INT64(0x80000000, 0x00008009), new INT64(0x00000000, 0x0000008A),
	new INT64(0x00000000, 0x00000088), new INT64(0x00000000, 0x80008009), new INT64(0x00000000, 0x8000000A),
	new INT64(0x00000000, 0x8000808B), new INT64(0x80000000, 0x0000008B), new INT64(0x80000000, 0x00008089),
	new INT64(0x80000000, 0x00008003), new INT64(0x80000000, 0x00008002), new INT64(0x80000000, 0x00000080),
	new INT64(0x00000000, 0x0000800A), new INT64(0x80000000, 0x8000000A), new INT64(0x80000000, 0x80008081),
	new INT64(0x80000000, 0x00008080), new INT64(0x00000000, 0x80000001), new INT64(0x80000000, 0x80008008)
];

jCastle.algorithm.sha3.RHO_OFFSET = [
	0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14
];

jCastle.algorithm.SHA3 = jCastle.algorithm.sha3;

// rate + capacity = 1600
// block_size = rate / 8

jCastle._algorithmInfo['sha3-224'] = {
	algorithm_type: 'hash',
	object_name: 'sha3',
	//bit_length: 224,
	rate: 1152,
	//capacity: 448,
	block_size: 144,
	digest_size: 28,
	oid: "2.16.840.1.101.3.4.2.7"
};

jCastle._algorithmInfo['sha3-256'] = {
	algorithm_type: 'hash',
	object_name: 'sha3',
	//bit_length: 256,
	rate: 1088,
	//capacity: 512,
	block_size: 136,
	digest_size: 32,
	oid: "2.16.840.1.101.3.4.2.8"
};

jCastle._algorithmInfo['sha3-288'] = {
	algorithm_type: 'hash',
	object_name: 'sha3',
	//bit_length: 288,
	rate: 1024,
	//capacity: 576,
	block_size: 128,
	digest_size: 36,
	oid: null
};

jCastle._algorithmInfo['sha3-384'] = {
	algorithm_type: 'hash',
	object_name: 'sha3',
	//bit_length: 384,
	rate: 832,
	//capacity: 768,
	block_size: 104,
	digest_size: 48,
	oid: "2.16.840.1.101.3.4.2.9"
};

jCastle._algorithmInfo['sha3-512'] = {
	algorithm_type: 'hash',
	object_name: 'sha3',
	//bit_length: 512,
	rate: 576,
	//capacity: 1024,
	block_size: 72,
	digest_size: 64,
	oid: "2.16.840.1.101.3.4.2.10"
};

jCastle._algorithmInfo['shake-128'] = 
jCastle._algorithmInfo['shake-128/128'] = {
	algorithm_type: 'hash',
	object_name: 'sha3',
	//bit_length: 128,
	rate: 1344,
	//capacity: 256,
	block_size: 168,
	digest_size: 16,
	oid: "2.16.840.1.101.3.4.2.11"
};

jCastle._algorithmInfo['shake-128/256'] = {
	algorithm_type: 'hash',
	object_name: 'sha3',
	//bit_length: 128,
	rate: 1344,
	//capacity: 256,
	block_size: 168,
	digest_size: 32,
	oid: null
};

jCastle._algorithmInfo['shake-128/384'] = {
	algorithm_type: 'hash',
	object_name: 'sha3',
	//bit_length: 128,
	rate: 1344,
	//capacity: 256,
	block_size: 168,
	digest_size: 48,
	oid: null
};

jCastle._algorithmInfo['shake-128/512'] = {
	algorithm_type: 'hash',
	object_name: 'sha3',
	//bit_length: 128,
	rate: 1344,
	//capacity: 256,
	block_size: 168,
	digest_size: 64,
	oid: null
};


jCastle._algorithmInfo['shake-256'] = 
jCastle._algorithmInfo['shake-256/256'] = {
	algorithm_type: 'hash',
	object_name: 'sha3',
	//bit_length: 256,
	rate: 1088,
	//capacity: 512,
	block_size: 136,
	digest_size: 32,
	oid: "2.16.840.1.101.3.4.2.12"
};

jCastle._algorithmInfo['shake-256/384'] = {
	algorithm_type: 'hash',
	object_name: 'sha3',
	//bit_length: 256,
	rate: 1088,
	//capacity: 512,
	block_size: 136,
	digest_size: 48,
	oid: null
};

jCastle._algorithmInfo['shake-256/512'] = {
	algorithm_type: 'hash',
	object_name: 'sha3',
	//bit_length: 256,
	rate: 1088,
	//capacity: 512,
	block_size: 136,
	digest_size: 64,
	oid: null
};


module.exports = jCastle.algorithm.sha3;