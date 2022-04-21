/**
 * Javascript jCastle Mcrypt Module - Skipjack
 * 
 * @author Jacob Lee
 *
 * Copyright (C) 2015-2022 Jacob Lee.
 */

var jCastle = require('../jCastle');
require('../util');

jCastle.algorithm.skipjack = class
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
        this.roundKey = null; // 10
        this.masterKey = null;
        this.rounds = null;
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
		this.roundKey = null;
		this.masterKey = null;
		this.rounds = null;
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


	// In-place encryption of 64-bit block 
	/**
	 * encrypts a block.
	 * 
	 * @public
	 * @param {buffer} input input data to be encrypted.
	 * @returns encrypted block in buffer.
	 */
	encryptBlock(input)
	{
		// load block 
		var w1 = input.readUInt16BE(0);
		var w2 = input.readUInt16BE(2);
		var w3 = input.readUInt16BE(4);
		var w4 = input.readUInt16BE(6);
		
		var kp = 0;

		for (var t = 0; t < 2; t++) {

			for (var i = 0; i < 8; i++) {
				var tmp = w4;
				w4 = w3;
				w3 = w2;
				w2 = this.g_func(w1, kp);
				w1 = w2 ^ tmp ^ (kp + 1);
				kp++;
			}

			for (var i = 0; i < 8; i++) {
				var tmp = w4;
				w4 = w3;
				w3 = w1 ^ w2 ^ (kp + 1);
				w2 = this.g_func(w1, kp);
				w1 = tmp;			
				kp++;
			}
		}

		var output = Buffer.alloc(input.length);
		
		output.writeUInt16BE(w1, 0);
		output.writeUInt16BE(w2, 2);
		output.writeUInt16BE(w3, 4);
		output.writeUInt16BE(w4, 6);

		return output;
	}

	/**
	 * decrypts a block.
	 * 
	 * @public
	 * @param {buffer} input input data to be decrypted.
	 * @returns the decrypted block in buffer.
	 */
	decryptBlock(input) // TRIPLEDES_KEY * key, char *block
	{
		var w2 = input.readUInt16BE(0);
		var w1 = input.readUInt16BE(2);
		var w4 = input.readUInt16BE(4);
		var w3 = input.readUInt16BE(6);
		
		var kp = 31;

		for (var t = 0; t < 2; t++) {

			for (var i = 0; i < 8; i++) {
				var tmp = w4;
				w4 = w3;
				w3 = w2;
				w2 = this.ig_func(w1, kp);
				w1 = w2 ^ tmp ^ (kp + 1);
				kp--;
			}

			for (var i = 0; i < 8; i++) {
				var tmp = w4;
				w4 = w3;
				w3 = w1 ^ w2 ^ (kp + 1);
				w2 = this.ig_func(w1, kp);
				w1 = tmp;			
				kp--;
			}
		}

		var output = Buffer.alloc(input.length);
		
		output.writeUInt16BE(w2, 0);
		output.writeUInt16BE(w1, 2);
		output.writeUInt16BE(w4, 4);
		output.writeUInt16BE(w3, 6);

		return output;
	}


/*
 * -----------------
 * Private functions
 * -----------------
 */


	/*
	this takes as input a 64 bit key (even though only 56 bits are used)
	as an array of 2 integers, and returns 16 48 bit keys
	*/
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
		if (key.length != 10) {
			throw jCastle.exception("INVALID_KEYSIZE");
		}
		
		this.rounds = 32;
		this.roundKey = [[], [], [], []];

		for (var i = 0; i < 32; i++) {
			this.roundKey[0][i] = key[(i * 4    ) % 10] & 0xff;
			this.roundKey[1][i] = key[(i * 4 + 1) % 10] & 0xff;
			this.roundKey[2][i] = key[(i * 4 + 2) % 10] & 0xff;
			this.roundKey[3][i] = key[(i * 4 + 3) % 10] & 0xff;
		}
	}

	g_func(w, kp)
	{
		var g1 = (w >>> 8) & 0xff, g2 = w & 0xff;

		g1 ^= jCastle.algorithm.skipjack.sbox[(g2 ^ this.roundKey[0][kp]) & 0xff];
		g2 ^= jCastle.algorithm.skipjack.sbox[(g1 ^ this.roundKey[1][kp]) & 0xff];
		g1 ^= jCastle.algorithm.skipjack.sbox[(g2 ^ this.roundKey[2][kp]) & 0xff];
		g2 ^= jCastle.algorithm.skipjack.sbox[(g1 ^ this.roundKey[3][kp]) & 0xff];

		return ((g1 & 0xff) << 8) | (g2 & 0xff);
	}

	ig_func(w, kp)
	{
		var g2 = (w >>> 8) & 0xff, g1 = w & 0xff;

		g1 ^= jCastle.algorithm.skipjack.sbox[(g2 ^ this.roundKey[3][kp]) & 0xff];
		g2 ^= jCastle.algorithm.skipjack.sbox[(g1 ^ this.roundKey[2][kp]) & 0xff];
		g1 ^= jCastle.algorithm.skipjack.sbox[(g2 ^ this.roundKey[1][kp]) & 0xff];
		g2 ^= jCastle.algorithm.skipjack.sbox[(g1 ^ this.roundKey[0][kp]) & 0xff];

		return ((g2 & 0xff) << 8) | (g1 & 0xff);
	}
};



/*
 * ---------
 * Constants
 * ---------
 */

jCastle.algorithm.skipjack.sbox = [
	0xa3, 0xd7, 0x09, 0x83, 0xf8, 0x48, 0xf6, 0xf4, 0xb3, 0x21, 0x15, 0x78, 0x99, 0xb1, 0xaf, 0xf9, 
	0xe7, 0x2d, 0x4d, 0x8a, 0xce, 0x4c, 0xca, 0x2e, 0x52, 0x95, 0xd9, 0x1e, 0x4e, 0x38, 0x44, 0x28, 
	0x0a, 0xdf, 0x02, 0xa0, 0x17, 0xf1, 0x60, 0x68, 0x12, 0xb7, 0x7a, 0xc3, 0xe9, 0xfa, 0x3d, 0x53, 
	0x96, 0x84, 0x6b, 0xba, 0xf2, 0x63, 0x9a, 0x19, 0x7c, 0xae, 0xe5, 0xf5, 0xf7, 0x16, 0x6a, 0xa2, 
	0x39, 0xb6, 0x7b, 0x0f, 0xc1, 0x93, 0x81, 0x1b, 0xee, 0xb4, 0x1a, 0xea, 0xd0, 0x91, 0x2f, 0xb8, 
	0x55, 0xb9, 0xda, 0x85, 0x3f, 0x41, 0xbf, 0xe0, 0x5a, 0x58, 0x80, 0x5f, 0x66, 0x0b, 0xd8, 0x90, 
	0x35, 0xd5, 0xc0, 0xa7, 0x33, 0x06, 0x65, 0x69, 0x45, 0x00, 0x94, 0x56, 0x6d, 0x98, 0x9b, 0x76, 
	0x97, 0xfc, 0xb2, 0xc2, 0xb0, 0xfe, 0xdb, 0x20, 0xe1, 0xeb, 0xd6, 0xe4, 0xdd, 0x47, 0x4a, 0x1d, 
	0x42, 0xed, 0x9e, 0x6e, 0x49, 0x3c, 0xcd, 0x43, 0x27, 0xd2, 0x07, 0xd4, 0xde, 0xc7, 0x67, 0x18, 
	0x89, 0xcb, 0x30, 0x1f, 0x8d, 0xc6, 0x8f, 0xaa, 0xc8, 0x74, 0xdc, 0xc9, 0x5d, 0x5c, 0x31, 0xa4, 
	0x70, 0x88, 0x61, 0x2c, 0x9f, 0x0d, 0x2b, 0x87, 0x50, 0x82, 0x54, 0x64, 0x26, 0x7d, 0x03, 0x40, 
	0x34, 0x4b, 0x1c, 0x73, 0xd1, 0xc4, 0xfd, 0x3b, 0xcc, 0xfb, 0x7f, 0xab, 0xe6, 0x3e, 0x5b, 0xa5, 
	0xad, 0x04, 0x23, 0x9c, 0x14, 0x51, 0x22, 0xf0, 0x29, 0x79, 0x71, 0x7e, 0xff, 0x8c, 0x0e, 0xe2, 
	0x0c, 0xef, 0xbc, 0x72, 0x75, 0x6f, 0x37, 0xa1, 0xec, 0xd3, 0x8e, 0x62, 0x8b, 0x86, 0x10, 0xe8, 
	0x08, 0x77, 0x11, 0xbe, 0x92, 0x4f, 0x24, 0xc5, 0x32, 0x36, 0x9d, 0xcf, 0xf3, 0xa6, 0xbb, 0xac, 
	0x5e, 0x6c, 0xa9, 0x13, 0x57, 0x25, 0xb5, 0xe3, 0xbd, 0xa8, 0x3a, 0x01, 0x05, 0x59, 0x2a, 0x46
];


jCastle._algorithmInfo['skipjack'] = {
	algorithm_type: 'crypt',
	block_size: 8,
	key_size: 10,
	min_key_size: 10,
	max_key_size: 10,
	padding: 'zeros',
	object_name: 'skipjack'
};

module.exports = jCastle.algorithm.skipjack;