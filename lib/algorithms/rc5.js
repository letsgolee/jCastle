/**
 * Javascript jCastle Mcrypt Module - RC5
 * 
 * @author Jacob Lee
 *
 * Copyright (C) 2015-2021 Jacob Lee.
 */

var jCastle = require('../jCastle');
require('../util');
var UINT32 = require('../uint32');

jCastle.algorithm.rc5 = class
{
	/**
	 * creates the algorithm instance.
	 * 
	 * @param {string} algo_name algorithm name
	 * @param {object} options options object
	 * @constructor
	 */
    constructor(algo_name, options = {})
    {
        this.algoName = algo_name;
        this.masterKey = null;
        this.roundKey = null;
        this.rounds = 12;

    //	if (typeof UINT32 == 'undefined') {
    //		throw jCastle.exception("UINT32_REQUIRED", 'RC5001');
    //	}

        if ('rounds' in options) this.rounds = options.rounds; // 0 .. 255
        if ('version' in options) this.version = options.version; // v1-0
        if ('blockSizeInBits' in options) this.blockSizeInBits = options.blockSizeInBits; // 64 | 128
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
		return this.cryptBlock(true, input);
	}

	/**
	 * crypt the input data. this is the stream cipher function.
	 * 
	 * @public
	 * @param {buffer} input input data to be crypted.
	 * @returns crypted data in buffer.
	 */
	decryptBlock(input)
	{
		return this.cryptBlock(false, input);
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
		var A, B, i, j, v, s, t, L;
		var keylen = key.length;
		var c = key.length / 4;

// according to RFC 2898
// RC5 has a variable number of "rounds" in the encryption
// operation, from 8 to 127.
//		if (this.rounds < 12 || this.rounds > 24) { 
		if (this.rounds < 8 || this.rounds > 127) {
		   throw jCastle.throwException("INVALID_ROUNDS");
		}

		// key must be between 64 and 1024 bits
		if (keylen < 8 || keylen > 128) {
		   throw jCastle.throwException("INVALID_KEYSIZE");
		}
		
		// copy the key into the L array 
		L = new Array(c);

		for(var i = 0; i < c; i++) {
			L[i] = UINT32.valueOf(key.readInt32LE(i * 4));
		}

		// setup the S array
		t = 2 * (this.rounds + 1);
		this.roundKey = new Array(t);
		for (var i = 0; i < t; i++) {
			this.roundKey[i] = UINT32.valueOf(jCastle.algorithm.rc5.stab[i]);
		}

		// mix buffer
		s = 3 * Math.max(t, c);

		A = UINT32.valueOf(0); B = UINT32.valueOf(0);
		
		for (i = j = v = 0; v < s; v++) { 
			this.roundKey[i] = this.roundKey[i].add(A).add(B).rotl(3);
			A = this.roundKey[i].clone();
			L[j] = L[j].add(A).add(B).rotl(A.add(B).div(UINT32.valueOf(32)).remainder.toNumber());
			B = L[j].clone();
			i = (i + 1) % t;
			j = (j + 1) % c;
		}
	}

	/**
	 * crypt the block sized data. chacha20 has a stream block size.
	 * 
	 * @public
	 * @param {boolean} direction true if it is encryption, otherwise false.
	 * @param {buffer} input input data to be crypted.
	 * @returns the crypted data in buffer.
	 */
	cryptBlock(direction, input)
	{
		var A = UINT32.valueOf(input.readUInt32LE(0));
		var B = UINT32.valueOf(input.readUInt32LE(4));
		
		var i, r;

		if (direction) {
			i = 0;
			A = A.add(this.roundKey[i++]);
			B = B.add(this.roundKey[i++]);
	  
			for (r = 0; r < this.rounds; r++) {
				A = A.xor(B).rotl(B.div(UINT32.valueOf(32)).remainder.toNumber()).add(this.roundKey[i++]);
				B = B.xor(A).rotl(A.div(UINT32.valueOf(32)).remainder.toNumber()).add(this.roundKey[i++]);
			}
		} else {
			i = this.rounds * 2 + 1;
			for (r = this.rounds - 1; r >= 0; r--) {
				B = B.subtract(this.roundKey[i--]).rotr(A.div(UINT32.valueOf(32)).remainder.toNumber()).xor(A);
				A = A.subtract(this.roundKey[i--]).rotr(B.div(UINT32.valueOf(32)).remainder.toNumber()).xor(B);
			}
			B = B.subtract(this.roundKey[i--]);
			A = A.subtract(this.roundKey[i]);
		}

		var output = Buffer.alloc(input.length);
		
		output.writeUInt32LE(A.toNumber(), 0);
		output.writeUInt32LE(B.toNumber(), 4);

		return output;
	}
}


jCastle._algorithmInfo['rc5'] = {
	algorithm_type: 'crypt',
	block_size: 8,
	key_size: 16,
	min_key_size: 8,
	max_key_size: 128,
	padding: 'zeros',
	object_name: 'rc5'
};

// Constants
//...........................................................................

jCastle.algorithm.rc5.stab = [
0xb7e15163, 0x5618cb1c, 0xf45044d5, 0x9287be8e, 0x30bf3847, 0xcef6b200, 0x6d2e2bb9, 0x0b65a572,
0xa99d1f2b, 0x47d498e4, 0xe60c129d, 0x84438c56, 0x227b060f, 0xc0b27fc8, 0x5ee9f981, 0xfd21733a,
0x9b58ecf3, 0x399066ac, 0xd7c7e065, 0x75ff5a1e, 0x1436d3d7, 0xb26e4d90, 0x50a5c749, 0xeedd4102,
0x8d14babb, 0x2b4c3474, 0xc983ae2d, 0x67bb27e6, 0x05f2a19f, 0xa42a1b58, 0x42619511, 0xe0990eca,
0x7ed08883, 0x1d08023c, 0xbb3f7bf5, 0x5976f5ae, 0xf7ae6f67, 0x95e5e920, 0x341d62d9, 0xd254dc92,
0x708c564b, 0x0ec3d004, 0xacfb49bd, 0x4b32c376, 0xe96a3d2f, 0x87a1b6e8, 0x25d930a1, 0xc410aa5a,
0x62482413, 0x007f9dcc
];

module.exports = jCastle.algorithm.rc5;