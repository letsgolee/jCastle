/**
 * Javascript jCastle Mcrypt Module - XTea 
 * 
 * @author Jacob Lee
 *
 * Copyright (C) 2015-2022 Jacob Lee.
 */

var jCastle = require('../jCastle');
require('../util');

jCastle.algorithm.xtea = class
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
        this.rounds = 32;
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
		this.rounds = 32;
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
		var output = Buffer.alloc(input.length);

		var y = input.readInt32BE(0),
			z = input.readInt32BE(4);
		var bswap32 = jCastle.util.bswap32;

		var limit, sum = 0;
		var N = this.rounds;

		limit = jCastle.algorithm.xtea.delta * N;

		while (sum != limit) {
			y += (((z << 4) ^ (z >>> 5)) + z) ^ (sum + bswap32(this.roundKey[sum & 3]));
			sum += jCastle.algorithm.xtea.delta;
			z += (((y << 4) ^ (y >>> 5)) + y) ^ (sum + bswap32(this.roundKey[(sum >>> 11) & 3]));
		}

		y &= 0xffffffff;
		z &= 0xffffffff;

		output.writeInt32BE(y, 0);
		output.writeInt32BE(z, 4);
		
		return output;
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
		var output = Buffer.alloc(input.length);

		var y = input.readInt32BE(0),
			z = input.readInt32BE(4);
		var bswap32 = jCastle.util.bswap32;
			
		var limit, sum = 0;
		var N = (-this.rounds);

		limit = jCastle.algorithm.xtea.delta * N;
		sum = jCastle.algorithm.xtea.delta * (-N);
			
		while (sum) {
			z -= (((y << 4) ^ (y >>> 5)) + y) ^ (sum + bswap32(this.roundKey[(sum >>> 11) & 3]));
			sum -= jCastle.algorithm.xtea.delta;
			y -= (((z << 4) ^ (z >>> 5)) + z) ^ (sum + bswap32(this.roundKey[sum & 3]));
		}

		y &= 0xffffffff;
		z &= 0xffffffff;

		output.writeInt32BE(y, 0);
		output.writeInt32BE(z, 4);
		
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
		this.roundKey = [
			key.readInt32LE(0),
			key.readInt32LE(4),
			key.readInt32LE(8),
			key.readInt32LE(12)
		];
	}
};



/*
 * ---------
 * Constants
 * ---------
 */

jCastle.algorithm.xtea.delta = 0x9e3779b9;	/* sqr(5)-1 * 2^31 */

jCastle._algorithmInfo['xtea'] = {
	algorithm_type: 'crypt',
	block_size: 8,
	key_size: 16,
	min_key_size: 16,
	max_key_size: 16,
	padding: 'zeros',
	object_name: 'xtea'
};

module.exports = jCastle.algorithm.xtea;