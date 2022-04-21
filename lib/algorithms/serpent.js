/**
 * Javascript jCastle Mcrypt Module - Serpent 
 * 
 * @author Jacob Lee
 *
 * Copyright (C) 2015-2022 Jacob Lee.
 */

var jCastle = require('../jCastle');
require('../util');

jCastle.algorithm.serpent = class
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
		var r = [
			input.readInt32LE(0),
			input.readInt32LE(4),
			input.readInt32LE(8),
			input.readInt32LE(12)
		];

		this.xorRoundKey(r, 0, 1, 2, 3, 0);
		var n = 0, m = jCastle.algorithm.serpent.ec[n];
		while (
			jCastle.algorithm.serpent.sboxesFunc[n % 8](r, m % 5, m % 7, m % 11, m % 13, m % 17),
			n < (this.rounds - 1)
		) { 
			m = jCastle.algorithm.serpent.ec[++n];
			this.encXorRound(r, m%5, m%7, m%11, m%13, m%17, n);
		}
		this.xorRoundKey(r, 0, 1, 2, 3, this.rounds);

		output.writeInt32LE(r[0], 0, true);
		output.writeInt32LE(r[1], 4, true);
		output.writeInt32LE(r[2], 8, true);
		output.writeInt32LE(r[3], 12, true);

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
		var r = [
			input.readInt32LE(0),
			input.readInt32LE(4),
			input.readInt32LE(8),
			input.readInt32LE(12)
		];

		this.xorRoundKey(r, 0, 1, 2, 3, this.rounds);
		var n = 0, m = jCastle.algorithm.serpent.dc[n];
		while (
			jCastle.algorithm.serpent.sboxesFunc_inverse[7-n%8](r, m%5, m%7, m%11, m%13, m%17),
			n < (this.rounds-1)
		) { 
			m = jCastle.algorithm.serpent.dc[++n];
			this.decXorRound(r, m%5, m%7, m%11, m%13, m%17, this.rounds-n);
		}
		this.xorRoundKey(r,2,3,1,4,0);

		output.writeInt32LE(r[2], 0, true);
		output.writeInt32LE(r[3], 4, true);
		output.writeInt32LE(r[1], 8, true);
		output.writeInt32LE(r[4], 12, true);

		return output;
	}


/*
 * -----------------
 * Private functions
 * -----------------
 */

	xorRoundKey(r, a, b, c, d, i)
	{
		r[a] ^= this.roundKey[4*i];
		r[b] ^= this.roundKey[4*i+1];
		r[c] ^= this.roundKey[4*i+2]; 
		r[d] ^= this.roundKey[4*i+3];
	}

	encXorRound(r, a, b, c, d, e, i)
	{
		r[a] = jCastle.util.rotl32(r[a], 13);
		r[c] = jCastle.util.rotl32(r[c], 3);
		r[b] ^= r[a];
		r[e] = (r[a]<<3) & 0xFFFFFFFF;
		r[d] ^= r[c];
		r[b] ^= r[c];
		r[b] = jCastle.util.rotl32(r[b],1);
		r[d] ^= r[e];
		r[d] = jCastle.util.rotl32(r[d],7);
		r[e] = r[b];
		r[a] ^= r[b];
		r[e] = (r[e]<<7) & 0xFFFFFFFF;
		r[c] ^= r[d];
		r[a] ^= r[d];
		r[c] ^= r[e];
		r[d] ^= this.roundKey[4 * i + 3];
		r[b] ^= this.roundKey[4 * i + 1];
		r[a] = jCastle.util.rotl32(r[a], 5);
		r[c] = jCastle.util.rotl32(r[c], 22);
		r[a] ^= this.roundKey[4 * i];
		r[c] ^= this.roundKey[4 * i + 2];
	}

	decXorRound(r, a, b, c, d, e, i)
	{
		r[a] ^= this.roundKey[4 * i];
		r[b] ^= this.roundKey[4 * i + 1];
		r[c] ^= this.roundKey[4 * i + 2];
		r[d] ^= this.roundKey[4 * i + 3];
		r[a] = jCastle.util.rotl32(r[a], 27);
		r[c] = jCastle.util.rotl32(r[c], 10);
		r[e] = r[b];
		r[c] ^= r[d];
		r[a] ^= r[d];
		r[e] = (r[e]<<7) & 0xFFFFFFFF;
		r[a] ^= r[b];
		r[b] = jCastle.util.rotl32(r[b], 31);
		r[c] ^= r[e];
		r[d] = jCastle.util.rotl32(r[d], 25);
		r[e] = (r[a]<<3) & 0xFFFFFFFF;
		r[b] ^= r[a];
		r[d] ^= r[e];
		r[a] = jCastle.util.rotl32(r[a], 19);
		r[b] ^= r[c];
		r[d] ^= r[c];
		r[c] = jCastle.util.rotl32(r[c], 29);
	}

	setRndKey(r, a, b, c, d, i)
	{
		r[b] = jCastle.util.rotl32(this.roundKey[a] ^ r[b] ^ r[c] ^ r[d] ^ 0x9e3779b9 ^ i, 11);
		this.roundKey[i] = r[b];
	}

	loadRndKey(r, a, b, c, d, i)
	{
		r[a] = this.roundKey[i];
		r[b] = this.roundKey[i + 1];
		r[c] = this.roundKey[i + 2];
		r[d] = this.roundKey[i + 3];
	}

	storeRndKey(r, a, b, c, d, i)
	{
		this.roundKey[i]     = r[a]; 
		this.roundKey[i + 1] = r[b];
		this.roundKey[i + 2] = r[c];
		this.roundKey[i + 3] = r[d];
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
		var i, j, m, n;
		
		this.roundKey = [];
		
		var keylen = key.length;
		
		var enckey = Buffer.alloc(32);
		enckey.set(key, 0);

		if(keylen < 32) {
			enckey[keylen] = 1;
		}

		for (i = 0; i < 8; i++) {
			//this.roundKey[i] = (key[4*i+0] & 0xff) | (key[4*i+1] & 0xff) << 8 | (key[4*i+2] & 0xff) << 16 | (key[4*i+3] & 0xff) << 24;
			//this.roundKey[i] = jCastle.util.load32(enckey, i * 4);
			this.roundKey[i] = enckey.readInt32LE(i * 4);
		}

		var r = [this.roundKey[3], this.roundKey[4], this.roundKey[5], this.roundKey[6], this.roundKey[7]];

		i = 0; j = 0;
		while (
			this.setRndKey(r, j++, 0, 4, 2, i++),
			this.setRndKey(r, j++, 1, 0, 3, i++),
			i < 132
		) {
			this.setRndKey(r, j++, 2, 1, 4, i++);
			if (i == 8) {
				j = 0;
			}
			this.setRndKey(r, j++, 3, 2, 0, i++);
			this.setRndKey(r, j++, 4, 3, 1, i++);
		}

		i = 128; j = 3; n = 0;
		
		while (
			m = jCastle.algorithm.serpent.kc[n++],
			jCastle.algorithm.serpent.sboxesFunc[j++ % 8](r, m % 5, m % 7, m % 11, m % 13, m % 17),
			m = jCastle.algorithm.serpent.kc[n],
			this.storeRndKey(r, m % 5, m % 7, m % 11, m % 13, i),
			i > 0
		) {
			i -= 4;
			this.loadRndKey(r, m % 5, m % 7, m % 11, m % 13, i);
		}
	}
};





/*
 * --------------------------
 * Constants & sbox functions
 * --------------------------
 */

jCastle.algorithm.serpent.sboxesFunc = [
	function(r, x0, x1, x2, x3, x4)
	{
		r[x4] =  r[x3]; 
		r[x3] |= r[x0]; r[x0] ^= r[x4]; r[x4] ^= r[x2]; r[x4] =~ r[x4];
		r[x3] ^= r[x1]; r[x1] &= r[x0]; r[x1] ^= r[x4]; r[x2] ^= r[x0];
		r[x0] ^= r[x3]; r[x4] |= r[x0]; r[x0] ^= r[x2]; r[x2] &= r[x1];
		r[x3] ^= r[x2]; r[x1] =~ r[x1]; r[x2] ^= r[x4]; r[x1] ^= r[x2];
	},
	function(r, x0, x1, x2, x3, x4)
	{
		r[x4] =  r[x1];
		r[x1] ^= r[x0]; r[x0] ^= r[x3]; r[x3] =~ r[x3]; r[x4] &= r[x1];
		r[x0] |= r[x1]; r[x3] ^= r[x2]; r[x0] ^= r[x3]; r[x1] ^= r[x3];
		r[x3] ^= r[x4]; r[x1] |= r[x4]; r[x4] ^= r[x2]; r[x2] &= r[x0];
		r[x2] ^= r[x1]; r[x1] |= r[x0]; r[x0] =~ r[x0]; r[x0] ^= r[x2];
		r[x4] ^= r[x1];
	},
	function(r, x0, x1, x2, x3, x4)
	{
		r[x3] =~ r[x3]; r[x1]^=r[x0]; r[x4]=r[x0]; r[x0]&=r[x2]; r[x0]^=r[x3];
		r[x3] |= r[x4]; r[x2]^=r[x1]; r[x3]^=r[x1]; r[x1]&=r[x0]; r[x0]^=r[x2];
		r[x2] &= r[x3]; r[x3]|=r[x1]; r[x0]=~r[x0]; r[x3]^=r[x0]; r[x4]^=r[x0];
		r[x0] ^= r[x2]; r[x1]|=r[x2];
	},
	function(r, x0, x1, x2, x3, x4)
	{
		r[x4] =  r[x1]; r[x1]^=r[x3]; r[x3]|=r[x0]; r[x4]&=r[x0]; r[x0]^=r[x2];
		r[x2] ^= r[x1]; r[x1]&=r[x3]; r[x2]^=r[x3]; r[x0]|=r[x4]; r[x4]^=r[x3];
		r[x1] ^= r[x0]; r[x0]&=r[x3]; r[x3]&=r[x4]; r[x3]^=r[x2]; r[x4]|=r[x1];
		r[x2] &= r[x1]; r[x4]^=r[x3]; r[x0]^=r[x3]; r[x3]^=r[x2];
	},
	function(r, x0, x1, x2, x3, x4)
	{
		r[x4] =  r[x3];r[x3]&=r[x0];r[x0]^=r[x4];r[x3]^=r[x2];r[x2]|=r[x4];r[x0]^=r[x1];
		r[x4] ^= r[x3];r[x2]|=r[x0];r[x2]^=r[x1];r[x1]&=r[x0];r[x1]^=r[x4];r[x4]&=r[x2];
		r[x2] ^= r[x3];r[x4]^=r[x0];r[x3]|=r[x1];r[x1]=~r[x1];r[x3]^=r[x0];
	},
	function(r, x0, x1, x2, x3, x4)
	{
		r[x4] =  r[x1]; r[x1]|=r[x0]; r[x2]^=r[x1]; r[x3]=~r[x3]; r[x4]^=r[x0]; r[x0]^=r[x2];
		r[x1] &= r[x4]; r[x4]|=r[x3]; r[x4]^=r[x0]; r[x0]&=r[x3]; r[x1]^=r[x3]; r[x3]^=r[x2];
		r[x0] ^= r[x1]; r[x2]&=r[x4]; r[x1]^=r[x2]; r[x2]&=r[x0]; r[x3]^=r[x2];
	},
	function(r, x0, x1, x2, x3, x4)
	{
		r[x4] =  r[x1]; r[x3]^=r[x0]; r[x1]^=r[x2]; r[x2]^=r[x0]; r[x0]&=r[x3]; r[x1]|=r[x3];
		r[x4] = ~r[x4]; r[x0]^=r[x1]; r[x1]^=r[x2]; r[x3]^=r[x4]; r[x4]^=r[x0]; r[x2]&=r[x0];
		r[x4] ^= r[x1]; r[x2]^=r[x3]; r[x3]&=r[x1]; r[x3]^=r[x0]; r[x1]^=r[x2]; 
	},
	function(r, x0, x1, x2, x3, x4)
	{
		r[x1] = ~r[x1]; r[x4]=r[x1]; r[x0]=~r[x0]; r[x1]&=r[x2]; r[x1]^=r[x3]; r[x3]|=r[x4];
		r[x4] ^= r[x2]; r[x2]^=r[x3]; r[x3]^=r[x0]; r[x0]|=r[x1]; r[x2]&=r[x0]; r[x0]^=r[x4];
		r[x4] ^= r[x3]; r[x3]&=r[x0]; r[x4]^=r[x1]; r[x2]^=r[x4]; r[x3]^=r[x1]; r[x4]|=r[x0];
		r[x4] ^= r[x1];
	}
];

jCastle.algorithm.serpent.sboxesFunc_inverse = [
	function(r,x0,x1,x2,x3,x4){
		r[x4]=r[x3]; r[x1]^=r[x0]; r[x3]|=r[x1]; r[x4]^=r[x1]; r[x0]=~r[x0]; r[x2]^=r[x3];
		r[x3]^=r[x0]; r[x0]&=r[x1]; r[x0]^=r[x2]; r[x2]&=r[x3]; r[x3]^=r[x4]; r[x2]^=r[x3];
		r[x1]^=r[x3]; r[x3]&=r[x0]; r[x1]^=r[x0]; r[x0]^=r[x2]; r[x4]^=r[x3];
	},
	function(r,x0,x1,x2,x3,x4){
		r[x1]^=r[x3];r[x4]=r[x0];r[x0]^=r[x2];r[x2]=~r[x2];r[x4]|=r[x1];r[x4]^=r[x3];
		r[x3]&=r[x1];r[x1]^=r[x2];r[x2]&=r[x4];r[x4]^=r[x1];r[x1]|=r[x3];r[x3]^=r[x0];
		r[x2]^=r[x0];r[x0]|=r[x4];r[x2]^=r[x4];r[x1]^=r[x0];r[x4]^=r[x1];
	},
	function(r,x0,x1,x2,x3,x4){
		r[x2]^=r[x1];r[x4]=r[x3];r[x3]=~r[x3];r[x3]|=r[x2];r[x2]^=r[x4];r[x4]^=r[x0];
		r[x3]^=r[x1];r[x1]|=r[x2];r[x2]^=r[x0];r[x1]^=r[x4];r[x4]|=r[x3];r[x2]^=r[x3];
		r[x4]^=r[x2];r[x2]&=r[x1];r[x2]^=r[x3];r[x3]^=r[x4];r[x4]^=r[x0];
	},
	function(r,x0,x1,x2,x3,x4){
		r[x2]^=r[x1];r[x4]=r[x1];r[x1]&=r[x2];r[x1]^=r[x0];r[x0]|=r[x4];r[x4]^=r[x3];
		r[x0]^=r[x3];r[x3]|=r[x1];r[x1]^=r[x2];r[x1]^=r[x3];r[x0]^=r[x2];r[x2]^=r[x3];
		r[x3]&=r[x1];r[x1]^=r[x0];r[x0]&=r[x2];r[x4]^=r[x3];r[x3]^=r[x0];r[x0]^=r[x1];
	},
	function(r,x0,x1,x2,x3,x4){
		r[x2]^=r[x3];r[x4]=r[x0];r[x0]&=r[x1];r[x0]^=r[x2];r[x2]|=r[x3];r[x4]=~r[x4];
		r[x1]^=r[x0];r[x0]^=r[x2];r[x2]&=r[x4];r[x2]^=r[x0];r[x0]|=r[x4];r[x0]^=r[x3];
		r[x3]&=r[x2];r[x4]^=r[x3];r[x3]^=r[x1];r[x1]&=r[x0];r[x4]^=r[x1];r[x0]^=r[x3];
	},
	function(r,x0,x1,x2,x3,x4){
		r[x4]=r[x1];r[x1]|=r[x2];r[x2]^=r[x4];r[x1]^=r[x3];r[x3]&=r[x4];r[x2]^=r[x3];r[x3]|=r[x0];
		r[x0]=~r[x0];r[x3]^=r[x2];r[x2]|=r[x0];r[x4]^=r[x1];r[x2]^=r[x4];r[x4]&=r[x0];r[x0]^=r[x1];
		r[x1]^=r[x3];r[x0]&=r[x2];r[x2]^=r[x3];r[x0]^=r[x2];r[x2]^=r[x4];r[x4]^=r[x3];
	},
	function(r,x0,x1,x2,x3,x4){
		r[x0]^=r[x2];r[x4]=r[x0];r[x0]&=r[x3];r[x2]^=r[x3];r[x0]^=r[x2];r[x3]^=r[x1];
		r[x2]|=r[x4];r[x2]^=r[x3];r[x3]&=r[x0];r[x0]=~r[x0];r[x3]^=r[x1];r[x1]&=r[x2];
		r[x4]^=r[x0];r[x3]^=r[x4];r[x4]^=r[x2];r[x0]^=r[x1];r[x2]^=r[x0];
	},
	function(r,x0,x1,x2,x3,x4){
		r[x4]=r[x3];r[x3]&=r[x0];r[x0]^=r[x2];r[x2]|=r[x4];r[x4]^=r[x1];r[x0]=~r[x0];r[x1]|=r[x3];
		r[x4]^=r[x0];r[x0]&=r[x2];r[x0]^=r[x1];r[x1]&=r[x2];r[x3]^=r[x2];r[x4]^=r[x3];
		r[x2]&=r[x3];r[x3]|=r[x0];r[x1]^=r[x4];r[x3]^=r[x4];r[x4]&=r[x0];r[x4]^=r[x2];
	}
];

jCastle.algorithm.serpent.kc = [
	 7788, 63716, 84032,  7891, 78949, 25146, 28835, 67288, 84032, 40055,
	 7361,  1940, 77639, 27525, 24193, 75702,  7361, 35413, 83150, 82383,
	58619, 48468, 18242, 66861, 83150, 69667,  7788, 31552, 40054, 23222,
	52496, 57565,  7788, 63716];

jCastle.algorithm.serpent.ec = [
	44255, 61867, 45034, 52496, 73087, 56255, 43827, 41448, 18242,  1939,
	18581, 56255, 64584, 31097, 26469, 77728, 77639,  4216, 64585, 31097,
	66861, 78949, 58006, 59943, 49676, 78950,  5512, 78949, 27525, 52496,
	18670, 76143
];
jCastle.algorithm.serpent.dc = [
	44255, 60896, 28835,  1837,  1057,  4216, 18242, 77301, 47399, 53992,
	 1939,  1940, 66420, 39172, 78950, 45917, 82383,  7450, 67288, 26469,
	83149, 57565, 66419, 47400, 58006, 44254, 18581, 18228, 33048, 45034,
	66508,  7449
];



jCastle._algorithmInfo['serpent'] = {
	algorithm_type: 'crypt',
	block_size: 16,
	key_size: 32,
	min_key_size: 16,
	max_key_size: 32,
	key_sizes: [16, 24, 32],
	padding: 'zeros',
	object_name: 'serpent'
};

jCastle._algorithmInfo['serpent-128'] = {
	algorithm_type: 'crypt',
	block_size: 16,
	key_size: 16,
	min_key_size: 16,
	max_key_size: 16,
	padding: 'zeros',
	object_name: 'serpent'
};

jCastle._algorithmInfo['serpent-192'] = {
	algorithm_type: 'crypt',
	block_size: 16,
	key_size: 24,
	min_key_size: 24,
	max_key_size: 24,
	padding: 'zeros',
	object_name: 'serpent'
};

jCastle._algorithmInfo['serpent-256'] = {
	algorithm_type: 'crypt',
	block_size: 16,
	key_size: 32,
	min_key_size: 32,
	max_key_size: 32,
	padding: 'zeros',
	object_name: 'serpent'
};

module.exports = jCastle.algorithm.serpent;