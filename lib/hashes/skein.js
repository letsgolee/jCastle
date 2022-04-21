/**
 * A Javascript implemenation of Skein-256/512/1024
 * 
 * @author Jacob Lee
 * Copyright (C) 2015-2022 Jacob Lee.
 */

var jCastle = require('../jCastle');
require('../util');
var INT64 = require('../int64');

// if the hash output length that you want is not in the list of _algorithmInfo
// then set output_size or output_bits in options.
// for instance, new Hasher('skein-256').digest('', {outputBits: 1024});
// or new Hasher('skein-256').digest('', {outputSize: 128});

jCastle.algorithm.skein = class
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
        this._threefish = null;

        // if (typeof INT64 == 'undefined') {
        //     throw jCastle.exception("INT64_REQUIRED", 'SKEIN001');
        // }

        this.output_size = 0;

        this.tweak_type_key = 0;
        this.tweak_type_config = 4;
        this.tweak_type_message = 48;
        this.tweak_type_output = 63;
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
		var block_size = jCastle._algorithmInfo[this.algoName].block_size;
		var algo_name = 'threefish-' + (block_size * 8);

		if (typeof jCastle._algorithmInfo == 'undefined' || !(algo_name in jCastle._algorithmInfo)) {
			throw jCastle.exception("TRHREEFISH_REQUIRED", 'SKEIN002');
		}

		this._threefish = new jCastle.algorithm[jCastle._algorithmInfo[algo_name].object_name](algo_name);

		this.key = Buffer.alloc(block_size);

		if ('hmacKey' in options) { // this will be used in hash mac
			var hmac_key = Buffer.from(options.hmacKey);
			
			if (hmac_key.length < 16) {
				throw jCastle.exception("INVALID_KEYSIZE", 'SKEIN003');
			}
			
			var last_length = hmac_key.length % block_size ? hmac_key.length % block_size : (hmac_key.length ? block_size : 0);
			
			if (hmac_key.length % block_size) {
				hmac_key = jCastle.mcrypt.padding['zeros'].pad(hmac_key, block_size);
			}

			var block_count = Math.ceil(hmac_key.length / block_size);
			var tweak = this._setFirst(true, 
							this._setType(this.tweak_type_key, [new INT64(), new INT64()])
						);
			
			for (var j = 0; j < block_count; j++) {
				if (j == (block_count - 1)) {
					tweak = this._setLast(true, tweak);
					tweak = this._addBytes(last_length, tweak);
				} else {
					tweak = this._addBytes(block_size, tweak);
				}

				this._threefish.keySchedule(this.key, true);
				this._threefish.expandTweak(tweak);

				this._state = this._threefish.encryptBlock(hmac_key.slice(j * block_size, j * block_size + block_size));
				this.key = Buffer.xor(this._state, hmac_key.slice(j * block_size, j * block_size + block_size));
				tweak = this._setFirst(false, tweak);
			}
		}

		var config = Buffer.alloc(block_size);

		// SHA3
		config[0] = 'S'.charCodeAt(0);
		config[1] = 'H'.charCodeAt(0);
		config[2] = 'A'.charCodeAt(0);
		config[3] = '3'.charCodeAt(0);

		// Version number in LSB order
		config[4] = 1;
		config[5] = 0;

		// 8 .. 15
		if ('outputLength' in options) this.output_size = options.outputLength;

		config.writeInt32LE(this.output_size ? this.output_size * 8 : jCastle._algorithmInfo[this.algoName].digest_size * 8, 8, true);

		var tweak = this._addBytes(32, 
							this._setLast(true, 
								this._setFirst(true, 
									this._setType(this.tweak_type_config, [new INT64(), new INT64()])
								)
							)
						);

		this._threefish.keySchedule(this.key, true);
		this._threefish.expandTweak(tweak);

		this._state = this._threefish.encryptBlock(config);
		this.key = Buffer.xor(this._state, config);

		// tweak
		// tweak is always 128 bits or 2 blocks of 64-bit
		this.tweak = this._setFirst(true, 
							this._setType(this.tweak_type_message, [new INT64(), new INT64()])
					); 

		this.save_block = Buffer.alloc(0);
		this.last_size = 0;
	}

	/**
	 * processes digesting.
	 * 
	 * @public
	 * @param {buffer} input input data to be digested.
	 */
	process(input)
	{
		// if the input size is total times of block_size then we don't know which will be the last.
		// so we have to save one block.
		if (!this.save_block.length) {
			this.save_block = input.slice(0);
		} else {
			this._threefish.keySchedule(this.key, true);
			this.tweak = this._addBytes(jCastle._algorithmInfo[this.algoName].block_size, this.tweak);
			this._threefish.expandTweak(this.tweak);
			this._state = this._threefish.encryptBlock(this.save_block);
			this.key = Buffer.xor(this.save_block, this._state);
			this.tweak = this._setFirst(false, this.tweak);

			this.save_block = input.slice(0);
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
		var block_size = jCastle._algorithmInfo[this.algoName].block_size;
		var index = input.length - pos;

		if (index == 0 && input.length) {
			index = block_size;
		}

		this.last_size = index;

		return Buffer.concat([input, Buffer.alloc(block_size - index)]);
	}

	/**
	 * finishes digesting process and returns the result.
	 * 
	 * @public
	 * @returns the digested data.
	 */
	finish()
	{
		// last block
		var output = Buffer.alloc(0);

		this._threefish.keySchedule(this.key, true);	
		this.tweak = this._addBytes(this.last_size, this._setLast(true, this.tweak));
		this._threefish.expandTweak(this.tweak);
		this._state = this._threefish.encryptBlock(this.save_block);

		var output_size = this.output_size ? this.output_size : jCastle._algorithmInfo[this.algoName].digest_size;
		var block_size = jCastle._algorithmInfo[this.algoName].block_size;

		// output
		var key = Buffer.xor(this.save_block, this._state);

		var tweak = this._addBytes(8, // sequence block is always 64-bit word
						this._setLast(true, 
							this._setFirst(true, 
								this._setType(this.tweak_type_output, [new INT64(), new INT64()])
							)
						)
					);

		this._threefish.keySchedule(key, true);
		this._threefish.expandTweak(tweak);

		var block_count = Math.ceil(output_size / block_size);

		for (var i = 0; i < block_count; i++) {
			var seq_block = Buffer.alloc(block_size);
			this._threefish.storeInt64(seq_block, 0, INT64.valueOf(i));
			this._state = this._threefish.encryptBlock(seq_block);

			output = Buffer.concat([output, Buffer.xor(this._state, seq_block)]);
		}

		this._state = null;
		this._threefish = null;

		output = output.slice(0, output_size);
		return output;
	}

	_setFirst(is_first, tw)
	{
		if (is_first) {
			tw[1].msint = tw[1].msint | (1 << 30);
		} else {
			tw[1].msint = tw[1].msint & ~(1 << 30);
		}

		return tw;
	}

	_setLast(is_first, tw)
	{
		if (is_first) {
			tw[1].msint = tw[1].msint | (1 << 31);
		} else {
			tw[1].msint = tw[1].msint & ~(1 << 31);
		}

		return tw;

	}

	_addBytes(bytes, tw)
	{
		tw[0] = tw[0].add(bytes);
		return tw;
	}

	_setType(type, tw)
	{
		tw[1].msint = (tw[1].msint & ~(63 << 24)) | (type << 24);
		return tw;
	}

/*
	_setFirst(is_first, tw)
	{
		if (is_first) {
			tw[1] = tw[1].or(jCastle.algorithm.skein.T1_FIRST);
		} else {
			tw[1] = tw[1].and(jCastle.algorithm.skein.T1_FIRST.not());
		}

		return tw;
	}

	_setLast(is_first, tw)
	{
		if (is_first) {
			tw[1] = tw[1].or(jCastle.algorithm.skein.T1_FINAL);
		} else {
			tw[1] = tw[1].and(jCastle.algorithm.skein.T1_FINAL.not());
		}

		return tw;

	}

	_addBytes(bytes, tw)
	{
		tw[0] = tw[0].add(bytes);

		return tw;
	}

	_setType(type, tw)
	{
		tw[1] = tw[1].and(INT64.fromBits(0xFFFFFFC0, 0)).or(INT64.valueOf(type & 0x3F).shiftLeft(56));

		return tw;
	}
*/
};

jCastle.algorithm.Skein = jCastle.algorithm.skein;

jCastle._algorithmInfo['skein-256/128'] = {
	algorithm_type: 'hash',
	object_name: 'skein',
	block_size: 32,
	digest_size: 16,
	oid: null
};

jCastle._algorithmInfo['skein-256/160'] = {
	algorithm_type: 'hash',
	object_name: 'skein',
	block_size: 32,
	digest_size: 20,
	oid: null
};

jCastle._algorithmInfo['skein-256/224'] = {
	algorithm_type: 'hash',
	object_name: 'skein',
	block_size: 32,
	digest_size: 28,
	oid: null
};

jCastle._algorithmInfo['skein-256'] =
jCastle._algorithmInfo['skein-256/256'] = {
	algorithm_type: 'hash',
	object_name: 'skein',
	block_size: 32,
	digest_size: 32,
	oid: null
};

jCastle._algorithmInfo['skein-512/128'] = {
	algorithm_type: 'hash',
	object_name: 'skein',
	block_size: 64,
	digest_size: 16,
	oid: null
};

jCastle._algorithmInfo['skein-512/160'] = {
	algorithm_type: 'hash',
	object_name: 'skein',
	block_size: 64,
	digest_size: 20,
	oid: null
};

jCastle._algorithmInfo['skein-512/224'] = {
	algorithm_type: 'hash',
	object_name: 'skein',
	block_size: 64,
	digest_size: 28,
	oid: null
};

jCastle._algorithmInfo['skein-512/256'] = {
	algorithm_type: 'hash',
	object_name: 'skein',
	block_size: 64,
	digest_size: 32,
	oid: null
};

jCastle._algorithmInfo['skein-512/384'] = {
	algorithm_type: 'hash',
	object_name: 'skein',
	block_size: 64,
	digest_size: 48,
	oid: null
};

jCastle._algorithmInfo['skein-512'] =
jCastle._algorithmInfo['skein-512/512'] = {
	algorithm_type: 'hash',
	object_name: 'skein',
	block_size: 64,
	digest_size: 64,
	oid: null
};

jCastle._algorithmInfo['skein-1024/256'] = {
	algorithm_type: 'hash',
	object_name: 'skein',
	block_size: 128,
	digest_size: 32,
	oid: null
};

jCastle._algorithmInfo['skein-1024/384'] = {
	algorithm_type: 'hash',
	object_name: 'skein',
	block_size: 128,
	digest_size: 48,
	oid: null
};

jCastle._algorithmInfo['skein-1024/512'] = {
	algorithm_type: 'hash',
	object_name: 'skein',
	block_size: 128,
	digest_size: 64,
	oid: null
};

jCastle._algorithmInfo['skein-1024'] =
jCastle._algorithmInfo['skein-1024/1024'] = {
	algorithm_type: 'hash',
	object_name: 'skein',
	block_size: 128,
	digest_size: 128,
	oid: null
};

/*
jCastle.algorithm.skein.T1_FIRST = INT64.valueOf(1).shiftLeft(62);
jCastle.algorithm.skein.T1_FINAL = INT64.valueOf(1).shiftLeft(63);
*/

module.exports = jCastle.algorithm.skein;