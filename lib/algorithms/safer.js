/**
 * Javascript jCastle Mcrypt Module - Safer(Safer-K64/SK64/K128/SK128)
 * 
 * @author Jacbo Lee
 *
 * Copyright (C) 2015-2022 Jacob Lee.
 */

var jCastle = require('../jCastle');
require('../util');

jCastle.algorithm.safer = class
{
	/**
	 * creates the algorithm instance.
	 * 
	 * @param {string} algo_name algorithm name
	 * @param {object} options options object.
	 * @constructor
	 */
    constructor(algo_name, options = {})
    {
        this.algoName = algo_name;
        this.roundKey = null;
        this.masterKey = null;
        this.rounds = 0;
        this.strengthened = true;
            
        // safer-sk64 & safer-sk128 : set strengthened := 1
        // safer-k64 & safer-k128 : set strengthened := 0
        // By default set strengthend := 1
        if (this.algoName == 'safer-k64' || this.algoName == 'safer-k128') {
            this.strengthened = false;
        }

        if ('rounds' in options) {
            this.rounds = options.rounds;
        }
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
		this.rounds = 0;
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
		var a, b, c, d, e, f, g, h, t;
		var round;
		var i= 0;
		var output = Buffer.alloc(input.length);

		a = input[0];
		b = input[1];
		c = input[2];
		d = input[3];
		e = input[4];
		f = input[5];
		g = input[6];
		h = input[7];
		
		if (jCastle.algorithm.safer.MAX_ROUNDS < (round = this.roundKey[i])) {
			round = jCastle.algorithm.safer.MAX_ROUNDS;
		}
		
		while (round--) {
			a ^= this.roundKey[++i];
			b += this.roundKey[++i];
			c += this.roundKey[++i];
			d ^= this.roundKey[++i];
			e ^= this.roundKey[++i];
			f += this.roundKey[++i];
			g += this.roundKey[++i];
			h ^= this.roundKey[++i];
			a = this.EXP(a) + this.roundKey[++i];
			b = this.LOG(b) ^ this.roundKey[++i];
			c = this.LOG(c) ^ this.roundKey[++i];
			d = this.EXP(d) + this.roundKey[++i];
			e = this.EXP(e) + this.roundKey[++i];
			f = this.LOG(f) ^ this.roundKey[++i];
			g = this.LOG(g) ^ this.roundKey[++i];
			h = this.EXP(h) + this.roundKey[++i];
			b += a; a += b;
			d += c; c += d;
			f += e; e += f;
			h += g; g += h;
			c += a; a += c;
			g += e; e += g;
			d += b; b += d;
			h += f; f += h;
			e += a; a += e;
			f += b; b += f;
			g += c; c += g;
			h += d; d += h;
			t = b;
			b = e;
			e = c;
			c = t;
			t = d;
			d = f;
			f = g;
			g = t;
		}

		a ^= this.roundKey[++i];
		b += this.roundKey[++i];
		c += this.roundKey[++i];
		d ^= this.roundKey[++i];
		e ^= this.roundKey[++i];
		f += this.roundKey[++i];
		g += this.roundKey[++i];
		h ^= this.roundKey[++i];

		output[0] = a & 0xFF;
		output[1] = b & 0xFF;
		output[2] = c & 0xFF;
		output[3] = d & 0xFF;
		output[4] = e & 0xFF;
		output[5] = f & 0xFF;
		output[6] = g & 0xFF;
		output[7] = h & 0xFF;
		
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
		var a, b, c, d, e, f, g, h, t;
		var round;
		var i= 0;
		var output = Buffer.alloc(input.length);
		
		a = input[0];
		b = input[1];
		c = input[2];
		d = input[3];
		e = input[4];
		f = input[5];
		g = input[6];
		h = input[7];
		
		if (jCastle.algorithm.safer.MAX_ROUNDS < (round = this.roundKey[0])) {
			round = jCastle.algorithm.safer.MAX_ROUNDS;
		}
		
		i += jCastle.algorithm.safer.BLOCK_SIZE * (1 + 2 * round);
		
		h ^= this.roundKey[i];
		g -= this.roundKey[--i];
		f -= this.roundKey[--i];
		e ^= this.roundKey[--i];
		d ^= this.roundKey[--i];
		c -= this.roundKey[--i];
		b -= this.roundKey[--i];
		a ^= this.roundKey[--i];
		
		while (round--) {
			t = e;
			e = b;
			b = c;
			c = t;
			t = f;
			f = d;
			d = g;
			g = t;
			a -= e; e -= a;
			b -= f; f -= b;
			c -= g; g -= c;
			d -= h; h -= d;
			a -= c; c -= a;
			e -= g; g -= e;
			b -= d; d -= b;
			f -= h; h -= f;
			a -= b; b -= a;
			c -= d; d -= c;
			e -= f; f -= e;
			g -= h; h -= g;
			h -= this.roundKey[--i];
			g ^= this.roundKey[--i];
			f ^= this.roundKey[--i];
			e -= this.roundKey[--i];
			d -= this.roundKey[--i];
			c ^= this.roundKey[--i];
			b ^= this.roundKey[--i];
			a -= this.roundKey[--i];
			h = this.LOG(h) ^ this.roundKey[--i];
			g = this.EXP(g) - this.roundKey[--i];
			f = this.EXP(f) - this.roundKey[--i];
			e = this.LOG(e) ^ this.roundKey[--i];
			d = this.LOG(d) ^ this.roundKey[--i];
			c = this.EXP(c) - this.roundKey[--i];
			b = this.EXP(b) - this.roundKey[--i];
			a = this.LOG(a) ^ this.roundKey[--i];
		}

		output[0] = a & 0xFF;
		output[1] = b & 0xFF;
		output[2] = c & 0xFF;
		output[3] = d & 0xFF;
		output[4] = e & 0xFF;
		output[5] = f & 0xFF;
		output[6] = g & 0xFF;
		output[7] = h & 0xFF;
		
		return output;
	}



/*
 * -----------------
 * Private functions
 * -----------------
 */



	EXP(x)
	{
		return jCastle.algorithm.safer.exp_tab[x & 0xFF];
	}

	LOG(x)
	{
		return jCastle.algorithm.safer.log_tab[x & 0xFF];
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
		var i, j;
		var block_size = jCastle.algorithm.safer.BLOCK_SIZE;
		var ka = new Array(block_size + 1);
		var kb = new Array(block_size + 1);
		var bits = key.length * 8;
		var nof_rounds;
		
		// safer-sk64 & safer-sk128 : set strengthened := 1
		// safer-k64 & safer-k128 : set strengthened := 0
		var strengthened = this.strengthened;
		
		var userkey_1 = [];
		var userkey_2 = [];
		
		switch (bits) {
			case 128:
				nof_rounds = strengthened ? jCastle.algorithm.safer.SK128_DEFAUT_ROUNDS : jCastle.algorithm.safer.K128_DEFAUT_ROUNDS;
				for(var i = 0; i < 8; i++) {
					userkey_1[i] = key[i];
					userkey_2[i] = key[i+8];
				}
				break;
			case 64:
				nof_rounds = strengthened ? jCastle.algorithm.safer.SK64_DEFAUT_ROUNDS : jCastle.algorithm.safer.K64_DEFAUT_ROUNDS;
				for(var i = 0; i < 8; i++) {
					userkey_1[i] = key[i];
					userkey_2[i] = key[i];
				}
				break;
			default:
				throw jCastle.exception("INVALID_KEYSIZE");
		}
		
		if (!this.rounds) {
			this.rounds = nof_rounds;
		}
		if (jCastle.algorithm.safer.MAX_ROUNDS < this.rounds) {
			this.rounds = jCastle.algorithm.safer.MAX_ROUNDS;
		}

		this.roundKey = [];
		
		var key_offset = 0;
		
		this.roundKey[key_offset++] = this.rounds & 0xFF;
		
		ka[block_size] = 0;
		kb[block_size] = 0;
		
		for (j = 0; j < block_size; j++) {
			ka[j] = jCastle.util.rotl8(userkey_1[j], 5);
			ka[block_size] ^= ka[j];
			kb[j] = this.roundKey[key_offset++] = userkey_2[j];
			kb[block_size] ^= kb[j];
		}
		for (i = 1; i <= this.rounds; i++) {
			for (j = 0; j < block_size + 1; j++) {
				ka[j] = jCastle.util.rotl8(ka[j], 6);
				kb[j] = jCastle.util.rotl8(kb[j], 6);
			}
			for (j = 0; j < block_size; j++)
				if (strengthened) {
					this.roundKey[key_offset++] = 
						(ka[(j + 2 * i - 1) % (block_size + 1)] +
						 jCastle.algorithm.safer.exp_tab[jCastle.algorithm.safer.exp_tab[18 * i + j + 1]]) & 0xFF;
				} else {
					this.roundKey[key_offset++] = 
						(ka[j] + jCastle.algorithm.safer.exp_tab[jCastle.algorithm.safer.exp_tab[18 * i + j + 1]]) & 0xFF;
				}
			for (j = 0; j < block_size; j++) {
				if (strengthened) {
					this.roundKey[key_offset++] = 
						(kb[(j + 2 * i) % (block_size + 1)] +
						 jCastle.algorithm.safer.exp_tab[jCastle.algorithm.safer.exp_tab[18 * i + j + 10]]) & 0xFF;
				} else {
					this.roundKey[key_offset++] = 
						(kb[j] + jCastle.algorithm.safer.exp_tab[jCastle.algorithm.safer.exp_tab[18 * i + j + 10]]) & 0xFF;
				}
			}
		}
	}

};



/*
 * ---------
 * Constants
 * ---------
 */

jCastle.algorithm.safer.K64_DEFAUT_ROUNDS = 6;
jCastle.algorithm.safer.K128_DEFAUT_ROUNDS = 10;
jCastle.algorithm.safer.SK64_DEFAUT_ROUNDS  = 8;
jCastle.algorithm.safer.SK128_DEFAUT_ROUNDS = 10;
jCastle.algorithm.safer.MAX_ROUNDS =          13;
jCastle.algorithm.safer.BLOCK_SIZE =           8;
//var jCastle.algorithm.safer.keyLength =    (1 + jCastle.algorithm.safer.BLOCK_SIZE * (1 + 2 * jCastle.algorithm.safer.MAX_ROUNDS));

jCastle.algorithm.safer.exp_tab = [
	0x01, 0x2d, 0xe2, 0x93, 0xbe, 0x45, 0x15, 0xae, 0x78, 0x03, 
	0x87, 0xa4, 0xb8, 0x38, 0xcf, 0x3f, 0x08, 0x67, 0x09, 0x94, 
	0xeb, 0x26, 0xa8, 0x6b, 0xbd, 0x18, 0x34, 0x1b, 0xbb, 0xbf, 
	0x72, 0xf7, 0x40, 0x35, 0x48, 0x9c, 0x51, 0x2f, 0x3b, 0x55, 
	0xe3, 0xc0, 0x9f, 0xd8, 0xd3, 0xf3, 0x8d, 0xb1, 0xff, 0xa7, 
	0x3e, 0xdc, 0x86, 0x77, 0xd7, 0xa6, 0x11, 0xfb, 0xf4, 0xba, 
	0x92, 0x91, 0x64, 0x83, 0xf1, 0x33, 0xef, 0xda, 0x2c, 0xb5, 
	0xb2, 0x2b, 0x88, 0xd1, 0x99, 0xcb, 0x8c, 0x84, 0x1d, 0x14, 
	0x81, 0x97, 0x71, 0xca, 0x5f, 0xa3, 0x8b, 0x57, 0x3c, 0x82, 
	0xc4, 0x52, 0x5c, 0x1c, 0xe8, 0xa0, 0x04, 0xb4, 0x85, 0x4a, 
	0xf6, 0x13, 0x54, 0xb6, 0xdf, 0x0c, 0x1a, 0x8e, 0xde, 0xe0, 
	0x39, 0xfc, 0x20, 0x9b, 0x24, 0x4e, 0xa9, 0x98, 0x9e, 0xab, 
	0xf2, 0x60, 0xd0, 0x6c, 0xea, 0xfa, 0xc7, 0xd9, 0x00, 0xd4, 
	0x1f, 0x6e, 0x43, 0xbc, 0xec, 0x53, 0x89, 0xfe, 0x7a, 0x5d, 
	0x49, 0xc9, 0x32, 0xc2, 0xf9, 0x9a, 0xf8, 0x6d, 0x16, 0xdb, 
	0x59, 0x96, 0x44, 0xe9, 0xcd, 0xe6, 0x46, 0x42, 0x8f, 0x0a, 
	0xc1, 0xcc, 0xb9, 0x65, 0xb0, 0xd2, 0xc6, 0xac, 0x1e, 0x41, 
	0x62, 0x29, 0x2e, 0x0e, 0x74, 0x50, 0x02, 0x5a, 0xc3, 0x25, 
	0x7b, 0x8a, 0x2a, 0x5b, 0xf0, 0x06, 0x0d, 0x47, 0x6f, 0x70, 
	0x9d, 0x7e, 0x10, 0xce, 0x12, 0x27, 0xd5, 0x4c, 0x4f, 0xd6, 
	0x79, 0x30, 0x68, 0x36, 0x75, 0x7d, 0xe4, 0xed, 0x80, 0x6a, 
	0x90, 0x37, 0xa2, 0x5e, 0x76, 0xaa, 0xc5, 0x7f, 0x3d, 0xaf, 
	0xa5, 0xe5, 0x19, 0x61, 0xfd, 0x4d, 0x7c, 0xb7, 0x0b, 0xee, 
	0xad, 0x4b, 0x22, 0xf5, 0xe7, 0x73, 0x23, 0x21, 0xc8, 0x05, 
	0xe1, 0x66, 0xdd, 0xb3, 0x58, 0x69, 0x63, 0x56, 0x0f, 0xa1, 
	0x31, 0x95, 0x17, 0x07, 0x3a, 0x28
];

jCastle.algorithm.safer.log_tab = [
	0x80, 0x00, 0xb0, 0x09, 0x60, 0xef, 0xb9, 0xfd, 0x10, 0x12, 
	0x9f, 0xe4, 0x69, 0xba, 0xad, 0xf8, 0xc0, 0x38, 0xc2, 0x65, 
	0x4f, 0x06, 0x94, 0xfc, 0x19, 0xde, 0x6a, 0x1b, 0x5d, 0x4e, 
	0xa8, 0x82, 0x70, 0xed, 0xe8, 0xec, 0x72, 0xb3, 0x15, 0xc3, 
	0xff, 0xab, 0xb6, 0x47, 0x44, 0x01, 0xac, 0x25, 0xc9, 0xfa, 
	0x8e, 0x41, 0x1a, 0x21, 0xcb, 0xd3, 0x0d, 0x6e, 0xfe, 0x26, 
	0x58, 0xda, 0x32, 0x0f, 0x20, 0xa9, 0x9d, 0x84, 0x98, 0x05, 
	0x9c, 0xbb, 0x22, 0x8c, 0x63, 0xe7, 0xc5, 0xe1, 0x73, 0xc6, 
	0xaf, 0x24, 0x5b, 0x87, 0x66, 0x27, 0xf7, 0x57, 0xf4, 0x96, 
	0xb1, 0xb7, 0x5c, 0x8b, 0xd5, 0x54, 0x79, 0xdf, 0xaa, 0xf6, 
	0x3e, 0xa3, 0xf1, 0x11, 0xca, 0xf5, 0xd1, 0x17, 0x7b, 0x93, 
	0x83, 0xbc, 0xbd, 0x52, 0x1e, 0xeb, 0xae, 0xcc, 0xd6, 0x35, 
	0x08, 0xc8, 0x8a, 0xb4, 0xe2, 0xcd, 0xbf, 0xd9, 0xd0, 0x50, 
	0x59, 0x3f, 0x4d, 0x62, 0x34, 0x0a, 0x48, 0x88, 0xb5, 0x56, 
	0x4c, 0x2e, 0x6b, 0x9e, 0xd2, 0x3d, 0x3c, 0x03, 0x13, 0xfb, 
	0x97, 0x51, 0x75, 0x4a, 0x91, 0x71, 0x23, 0xbe, 0x76, 0x2a, 
	0x5f, 0xf9, 0xd4, 0x55, 0x0b, 0xdc, 0x37, 0x31, 0x16, 0x74, 
	0xd7, 0x77, 0xa7, 0xe6, 0x07, 0xdb, 0xa4, 0x2f, 0x46, 0xf3, 
	0x61, 0x45, 0x67, 0xe3, 0x0c, 0xa2, 0x3b, 0x1c, 0x85, 0x18, 
	0x04, 0x1d, 0x29, 0xa0, 0x8f, 0xb2, 0x5a, 0xd8, 0xa6, 0x7e, 
	0xee, 0x8d, 0x53, 0x4b, 0xa1, 0x9a, 0xc1, 0x0e, 0x7a, 0x49, 
	0xa5, 0x2c, 0x81, 0xc4, 0xc7, 0x36, 0x2b, 0x7f, 0x43, 0x95, 
	0x33, 0xf2, 0x6c, 0x68, 0x6d, 0xf0, 0x02, 0x28, 0xce, 0xdd, 
	0x9b, 0xea, 0x5e, 0x99, 0x7c, 0x14, 0x86, 0xcf, 0xe5, 0x42, 
	0xb8, 0x40, 0x78, 0x2d, 0x3a, 0xe9, 0x64, 0x1f, 0x92, 0x90, 
	0x7d, 0x39, 0x6f, 0xe0, 0x89, 0x30
];


jCastle._algorithmInfo['safer-sk64'] = {
	algorithm_type: 'crypt',
	block_size: 8,
	key_size: 8,
	min_key_size: 8,
	max_key_size: 8,
	padding: 'zeros',
	object_name: 'safer'
};

jCastle._algorithmInfo['safer-k64'] = {
	algorithm_type: 'crypt',
	block_size: 8,
	key_size: 8,
	min_key_size: 8,
	max_key_size: 8,
	padding: 'zeros',
	object_name: 'safer'
};

jCastle._algorithmInfo['safer-sk128'] = {
	algorithm_type: 'crypt',
	block_size: 8,
	key_size: 16,
	min_key_size: 16,
	max_key_size: 16,
	padding: 'zeros',
	object_name: 'safer'
};

jCastle._algorithmInfo['safer-k128'] = {
	algorithm_type: 'crypt',
	block_size: 8,
	key_size: 16,
	min_key_size: 16,
	max_key_size: 16,
	padding: 'zeros',
	object_name: 'safer'
};

module.exports = jCastle.algorithm.safer;