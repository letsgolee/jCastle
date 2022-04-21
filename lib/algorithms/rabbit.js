/**
 * Javascript jCastle Mcrypt Module - Rabbit
 * 
 * @author Jacob Lee
 *
 * Copyright (C) 2015-2021 Jacob Lee.
 */

var jCastle = require('../jCastle');
require('../util');

jCastle.algorithm.rabbit = class
{
	/**
	 * creates the algorithm instance.
	 * 
	 * @param {string} algo_name algorithm name
	 * @constructor
	 */
    constructor(algo_name)
    {
        this.algoName = algo_name;
        this.masterKey = null;
        this.roundKey = null;
        this.state = null;
        this.counter = null;
        this.carry = 0;
        this.useInitialVector = false;
        this.initialVector = null;
    }

    /**
	 * validate the key size.
	 * 
	 * @public
	 * @param {buffer} key 
	 * @returns true if the key size is valid.
	 */
	isValidKeySize(key)
	{
		if (jCastle._algorithmInfo[this.algoName].min_key_size == jCastle._algorithmInfo[this.algoName].max_key_size) {
			if (key.length != jCastle._algorithmInfo[this.algoName].key_size) {
				return false;
			}
		} else {
			if (key.length > jCastle._algorithmInfo[this.algoName].max_key_size) {
				return false;
			}
			if (key.length < jCastle._algorithmInfo[this.algoName].min_key_size) {
				return false;
			}
			if (typeof jCastle._algorithmInfo[this.algoName].key_sizes != 'undefined' &&
            !jCastle._algorithmInfo[this.algoName].key_sizes.includes(key.length)
			) {
				return false;			
			}
		}
		return true;
	}

	/**
	 * resets internal variables except algoName.
	 * 
	 *  @public
	 */
	reset()
	{
		this.masterKey = null;
		this.roundKey = null;
		this.state = null;
		this.counter = null;
		this.carry = 0;
		this.useInitialVector = false;
		this.initialVector = null;
		return this;
	}

	/**
	 * get the key.
	 * 
	 * @public
	 * @returns the masterKey.
	 */
    getKey()
    {
        return this.masterKey;
    }

	/**
	 * get the block size.
	 * 
	 * @public
	 * @returns the block size.
	 */
	getBlockSize()
	{
		return jCastle._algorithmInfo[this.algoName].block_size;
	}

	/**
	 * sets the initial vector.
	 * 
	 * @public
	 * @param {buffer} IV initial vector.
	 * @returns this class instance.
	 */
	setInitialVector(IV)
	{
		var iv = Buffer.from(IV, 'latin1');

		if (iv.length != jCastle._algorithmInfo[this.algoName].stream_iv_size) { // iv length is 8
			throw jCastle.exception("INVALID_IV", 'RABBIT001');
		}

		this.initialVector = iv;
		this.useInitialVector = true;

		return this;
	}

	/**
	 * makes round key for encryption/decryption.
	 *
	 * @public
	 * @param {buffer} key encryption/decryption key.
	 * @param {boolean} isEncryption if encryption then true, otherwise false.
	 */
	keySchedule(key, isEncryption)
	{
		this.masterKey = Buffer.from(key, 'latin1');

		this.expandKey(this.masterKey);
		return this;
	}

	/**
	 * encrypts a block.
	 * 
	 * @public
	 * @param {buffer} input input data to be encrypted.
	 * @returns encrypted block in buffer.
	 */
	encryptBlock(input)
	{
		return this.cryptBlock(input);
	}

	/**
	 * decrypts a block.
	 * 
	 * @public
	 * @param {buffer} input input data to be decrypted.
	 * @returns the decrypted block in buffer.
	 */
	decryptBlock(input)
	{
		return this.cryptBlock(input);
	}

	/**
	 * crypt the input data. this is the stream cipher function.
	 * 
	 * @public
	 * @param {buffer} input input data to be crypted.
	 * @returns crypted data in buffer.
	 */
	crypt(input)
	{
		var blockSize = jCastle._algorithmInfo[this.algoName].stream_block_size;
		var len = input.length;
		var output = Buffer.alloc(len);

		for (var i = 0; i < len; i += blockSize) {
			output.set(this.cryptBlock(input.slice(i, i + blockSize)), i);
		}

		return output;
	}

	/**
	 * Calculate the necessary round keys.
	 * The number of calculations depends on key size and block size.
	 * 
	 * @private
	 * @param {buffer} key key for encryption/decryption.
	 * @param {boolean} isEncryption true if it is encryption, otherwise false.
	 */
	expandKey(key, isEncryption)
	{
		var k0, k1, k2, k3, i, rotl = jCastle.util.rotl32;

		// Generate four subkeys
		k0 = key.readInt32LE(0);
		k1 = key.readInt32LE(4);
		k2 = key.readInt32LE(8);
		k3 = key.readInt32LE(12);

		this.state = new Array(8);

		// Generate initial state variables
		this.state[0] = k0;
		this.state[2] = k1;
		this.state[4] = k2;
		this.state[6] = k3;
		this.state[1] = (k3 << 16) | (k2 >>> 16);
		this.state[3] = (k0 << 16) | (k3 >>> 16);
		this.state[5] = (k1 << 16) | (k0 >>> 16);
		this.state[7] = (k2 << 16) | (k1 >>> 16);

		this.counter = new Array(8);

		// Generate initial counter values
		this.counter[0] = rotl(k2, 16);
		this.counter[2] = rotl(k3, 16);
		this.counter[4] = rotl(k0, 16);
		this.counter[6] = rotl(k1, 16);
		this.counter[1] = (k0 & 0xFFFF0000) | (k1 & 0xFFFF);
		this.counter[3] = (k1 & 0xFFFF0000) | (k2 & 0xFFFF);
		this.counter[5] = (k2 & 0xFFFF0000) | (k3 & 0xFFFF);
		this.counter[7] = (k3 & 0xFFFF0000) | (k0 & 0xFFFF);

		// Reset carry flag
		this.carry = 0;

		// Iterate the system four times
		for (i = 0; i < 4; i++)
			this.nextState();

		// Modify the counters
		for (i = 0; i < 8; i++)
			this.counter[(i + 4) & 0x7] ^= this.state[i];

		if (this.useInitialVector) {
			var i0, i1, i2, i3;

			i0 = this.initialVector.readInt32BE(0);
			i1 = this.initialVector.readInt32BE(4);

			// Generate four subvectors
			i0 = (((i0 << 8) | (i0 >>> 24)) & 0x00ff00ff) | (((i0 << 24) | (i0 >>> 8)) & 0xff00ff00);
			i2 = (((i1 << 8) | (i1 >>> 24)) & 0x00ff00ff) | (((i1 << 24) | (i1 >>> 8)) & 0xff00ff00);
			i1 = (i0 >>> 16) | (i2 & 0xffff0000);
			i3 = (i2 << 16)  | (i0 & 0x0000ffff);

			// Modify counter values
			this.counter[0] ^= i0;
			this.counter[1] ^= i1;
			this.counter[2] ^= i2;
			this.counter[3] ^= i3;
			this.counter[4] ^= i0;
			this.counter[5] ^= i1;
			this.counter[6] ^= i2;
			this.counter[7] ^= i3;

			// Iterate the system four times
			for (i = 0; i < 4; i++)
				this.nextState();
		}

	}

	// Calculate the next internal state
	// variables are uint32
	nextState()
	{
		var g = [], old = [], i, rotl = jCastle.util.rotl32;

		// Save old counter values
		for (i = 0; i < 8; i++)
			old[i] = this.counter[i] >>> 0;

		// Calculate new counter values

		this.counter[0] = (old[0] + 0x4d34d34d +  this.carry) | 0; // make it uint32
		this.counter[1] = (old[1] + 0xd34d34d3 + (this.counter[0] >>> 0 < old[0] ? 1 : 0)) | 0;
		this.counter[2] = (old[2] + 0x34d34d34 + (this.counter[1] >>> 0 < old[1] ? 1 : 0)) | 0;
		this.counter[3] = (old[3] + 0x4d34d34d + (this.counter[2] >>> 0 < old[2] ? 1 : 0)) | 0;
		this.counter[4] = (old[4] + 0xd34d34d3 + (this.counter[3] >>> 0 < old[3] ? 1 : 0)) | 0;
		this.counter[5] = (old[5] + 0x34d34d34 + (this.counter[4] >>> 0 < old[4] ? 1 : 0)) | 0;
		this.counter[6] = (old[6] + 0x4d34d34d + (this.counter[5] >>> 0 < old[5] ? 1 : 0)) | 0;
		this.counter[7] = (old[7] + 0xd34d34d3 + (this.counter[6] >>> 0 < old[6] ? 1 : 0)) | 0;

		this.carry = this.counter[7] >>> 0 < old[7] ? 1 : 0;

		// Calculate the g-functions
		for (i = 0; i < 8; i++)
			g[i] = this.gFunc(this.state[i] + this.counter[i]);

		// Calculate new state values
		this.state[0] = (g[0] + rotl(g[7], 16) + rotl(g[6], 16)) | 0;
		this.state[1] = (g[1] + rotl(g[0],  8) + g[7]) | 0;
		this.state[2] = (g[2] + rotl(g[1], 16) + rotl(g[0], 16)) | 0;
		this.state[3] = (g[3] + rotl(g[2],  8) + g[1]) | 0;
		this.state[4] = (g[4] + rotl(g[3], 16) + rotl(g[2], 16)) | 0;
		this.state[5] = (g[5] + rotl(g[4],  8) + g[3]) | 0;
		this.state[6] = (g[6] + rotl(g[5], 16) + rotl(g[4], 16)) | 0;
		this.state[7] = (g[7] + rotl(g[6],  8) + g[5]) | 0;
	}

	gFunc(x)
	{
		// Construct high and low argument for squaring
		var a = x & 0xffff;
		var b = x >>> 16;

		// Calculate high and low result of squaring
		var h = ((((a * a) >>> 17) + (a * b)) >>> 15) + (b * b);
//		var l = (x * x) | 0;
		var l = (((x & 0xffff0000) * x) | 0) + (((x & 0x0000ffff) * x) | 0);

		// Return high XOR low
		return h ^ l;
	}

	/**
	 * crypt the block sized data. chacha20 has a stream block size.
	 * 
	 * @public
	 * @param {buffer} input input data to be crypted.
	 * @returns the crypted data in buffer.
	 */
	cryptBlock(input)
	{
		var blockSize = jCastle._algorithmInfo[this.algoName].stream_block_size;
		var output = Buffer.alloc(blockSize);
		var len = input.length;
		var data = input;

		if (len < blockSize) {
			data = Buffer.concat([data, Buffer.alloc(blockSize - len)]);
		}

		var a0 = input.readInt32LE(0);
		var a1 = input.readInt32LE(4);
		var a2 = input.readInt32LE(8);
		var a3 = input.readInt32LE(12);

		// Rabbit works with 16 bytes block

		this.nextState();  // Iterate the system

		// Encrypt 16 bytes of data
		a0 ^= (this.state[0]) ^ (this.state[5] >>> 16) ^ (this.state[3] << 16);
		a1 ^= (this.state[2]) ^ (this.state[7] >>> 16) ^ (this.state[5] << 16);
		a2 ^= (this.state[4]) ^ (this.state[1] >>> 16) ^ (this.state[7] << 16);
		a3 ^= (this.state[6]) ^ (this.state[3] >>> 16) ^ (this.state[1] << 16);

		output.writeInt32LE(a0, 0, true);
		output.writeInt32LE(a1, 4, true);
		output.writeInt32LE(a2, 8, true);
		output.writeInt32LE(a3, 12, true);

		return output.slice(0, len);
	}
};


jCastle._algorithmInfo['rabbit'] = {
	algorithm_type: 'crypt',
	block_size: 1, // stream cipher
	stream_block_size: 16,
	stream_iv_size: 8,
	key_size: 16,
	min_key_size: 16,
	max_key_size: 16,
	padding: 'zeros',
	object_name: 'rabbit'
};

module.exports = jCastle.algorithm.rabbit;