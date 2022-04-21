/**
 * Javascript jCastle Mcrypt Module - Lea
 * 
 * @author Jacob Lee
 *
 * Copyright (C) 2015-2022 Jacob Lee.
 */

var jCastle = require('../jCastle');
require('../util');

jCastle.algorithm.lea = class
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
        this.roundKeys = null;
        this.rounds = null;
        this.keyBytes = null;
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
		this.roundKeys = null;
		this.rounds = null;
		this.keyBytes = null;
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
		
		this.keyBytes = this.masterKey.length;
		
		switch(this.keyBytes * 8) {
			case 128:
				this.rounds = 24; break;
			case 192:
				this.rounds = 28; break;
			case 256:
				this.rounds = 32; break;
		}
		
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
		var X0,X1,X2,X3;
		var temp;
		var roundKeys = this.roundKeys;
		var output = Buffer.alloc(input.length);

		X0 = input.readInt32LE(0);
		X1 = input.readInt32LE(4);
		X2 = input.readInt32LE(8);
		X3 = input.readInt32LE(12);

		
		for(var i = 0; i < this.rounds; i++) {
			X3 = jCastle.util.rotr32((X2 ^ roundKeys[i][4]) + (X3 ^ roundKeys[i][5]), 3);
			X2 = jCastle.util.rotr32((X1 ^ roundKeys[i][2]) + (X2 ^ roundKeys[i][3]), 5);
			X1 = jCastle.util.rotl32((X0 ^ roundKeys[i][0]) + (X1 ^ roundKeys[i][1]), 9);
			temp = X0;
			X0 = X1; X1 = X2; X2 = X3; X3 = temp;
		}

		output.writeInt32LE(X0, 0, true);
		output.writeInt32LE(X1, 4, true);
		output.writeInt32LE(X2, 8, true);
		output.writeInt32LE(X3, 12, true);
		
		return output;
	}

	/**
	 * decrypts a block.
	 * 
	 * @public
	 * @param {buffer} input input data to be decrypted.
	 * @returns the decrypted block in buffer.
	 */
	decryptBlock (input)
	{
		var X0,X1,X2,X3;
		var temp;
		var roundKeys = this.roundKeys;
		var output = Buffer.alloc(input.length);

		X0 = input.readInt32LE(0);
		X1 = input.readInt32LE(4);
		X2 = input.readInt32LE(8);
		X3 = input.readInt32LE(12);
		
		for(var i = 0; i < this.rounds; i++) {
			temp = X3;
			X3 = X2;
			X2 = X1;
			X1 = X0;
			X0 = temp;

			X1 = (jCastle.util.rotr32(X1,9) - (X0 ^ roundKeys[this.rounds-1-i][0])) ^ roundKeys[this.rounds-1-i][1];
			X2 = (jCastle.util.rotl32(X2,5) - (X1 ^ roundKeys[this.rounds-1-i][2])) ^ roundKeys[this.rounds-1-i][3];
			X3 = (jCastle.util.rotl32(X3,3) - (X2 ^ roundKeys[this.rounds-1-i][4])) ^ roundKeys[this.rounds-1-i][5];
		}

		output.writeInt32LE(X0, 0, true);
		output.writeInt32LE(X1, 4, true);
		output.writeInt32LE(X2, 8, true);
		output.writeInt32LE(X3, 12, true);
		
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
	expandKey(pbKey)
	{
		var roundKeys = [];
		var rotl32 = jCastle.util.rotl32;
		
		for (var i = 0; i < this.rounds; i++) {
			roundKeys[i] = [];
			for (var j = 0; j < jCastle.algorithm.lea.roundKeyWordLength; j++) {
				roundKeys[i][j] = 0;
			}
		}

		if (this.keyBytes == 16) {
			var delta = [0xc3efe9db, 0x44626b02, 0x79e27c8a, 0x78df30ec];
			var T = new Array(4);

			T[0] = pbKey.readInt32LE(0);
			T[1] = pbKey.readInt32LE(4);
			T[2] = pbKey.readInt32LE(8);
			T[3] = pbKey.readInt32LE(12);
			
			for(var i = 0; i < this.rounds; i++) {
				T[0] = rotl32(T[0] + rotl32(delta[i&3], i), 1);
				T[1] = rotl32(T[1] + rotl32(delta[i&3], i+1), 3);
				T[2] = rotl32(T[2] + rotl32(delta[i&3], i+2), 6);
				T[3] = rotl32(T[3] + rotl32(delta[i&3], i+3), 11);

				roundKeys[i][0] = T[0];
				roundKeys[i][1] = T[1];
				roundKeys[i][2] = T[2];
				roundKeys[i][3] = T[1];
				roundKeys[i][4] = T[3];
				roundKeys[i][5] = T[1];
			}
		} else if (this.keyBytes == 24) {
			var  delta = [ 0xc3efe9db, 0x44626b02, 0x79e27c8a, 0x78df30ec, 0x715ea49e, 0xc785da0a];
			var T = new Array(6);

			T[0] = pbKey.readInt32LE(0);
			T[1] = pbKey.readInt32LE(4);
			T[2] = pbKey.readInt32LE(8);
			T[3] = pbKey.readInt32LE(12);
			T[4] = pbKey.readInt32LE(16);
			T[5] = pbKey.readInt32LE(20);
			
			for(var i = 0; i < this.rounds; i++) {
				T[0] = rotl32(T[0] + rotl32(delta[i%6], i&0x1f), 1);
				T[1] = rotl32(T[1] + rotl32(delta[i%6], (i+1)&0x1f), 3);
				T[2] = rotl32(T[2] + rotl32(delta[i%6], (i+2)&0x1f), 6);
				T[3] = rotl32(T[3] + rotl32(delta[i%6], (i+3)&0x1f), 11);
				T[4] = rotl32(T[4] + rotl32(delta[i%6], (i+4)&0x1f), 13);
				T[5] = rotl32(T[5] + rotl32(delta[i%6], (i+5)&0x1f), 17);

				roundKeys[i][0] = T[0];
				roundKeys[i][1] = T[1];
				roundKeys[i][2] = T[2];
				roundKeys[i][3] = T[3];
				roundKeys[i][4] = T[4];
				roundKeys[i][5] = T[5];
			}

		} else if (this.keyBytes == 32) {
			var delta = [0xc3efe9db, 0x44626b02, 0x79e27c8a, 0x78df30ec, 0x715ea49e, 0xc785da0a, 0xe04ef22a, 0xe5c40957];
			var T = new Array(8);

			T[0] = pbKey.readInt32LE(0);
			T[1] = pbKey.readInt32LE(4);
			T[2] = pbKey.readInt32LE(8);
			T[3] = pbKey.readInt32LE(12);
			T[4] = pbKey.readInt32LE(16);
			T[5] = pbKey.readInt32LE(20);
			T[6] = pbKey.readInt32LE(24);
			T[7] = pbKey.readInt32LE(28);
			
				
			for(var i = 0; i < this.rounds; i++) {
				T[(6*i    )&7] = rotl32(T[(6*i    )&7] + rotl32(delta[i&7], i&0x1f), 1);
				T[(6*i + 1)&7] = rotl32(T[(6*i + 1)&7] + rotl32(delta[i&7], (i+1)&0x1f), 3);
				T[(6*i + 2)&7] = rotl32(T[(6*i + 2)&7] + rotl32(delta[i&7], (i+2)&0x1f), 6);
				T[(6*i + 3)&7] = rotl32(T[(6*i + 3)&7] + rotl32(delta[i&7], (i+3)&0x1f), 11);
				T[(6*i + 4)&7] = rotl32(T[(6*i + 4)&7] + rotl32(delta[i&7], (i+4)&0x1f), 13);
				T[(6*i + 5)&7] = rotl32(T[(6*i + 5)&7] + rotl32(delta[i&7], (i+5)&0x1f), 17);

				roundKeys[i][0] = T[(6*i)&7];
				roundKeys[i][1] = T[(6*i+1)&7];
				roundKeys[i][2] = T[(6*i+2)&7];
				roundKeys[i][3] = T[(6*i+3)&7];
				roundKeys[i][4] = T[(6*i+4)&7];
				roundKeys[i][5] = T[(6*i+5)&7];
			}
		}
		
		this.roundKeys = roundKeys;
	}
};



/*
 * ---------
 * Constants
 * ---------
 */

jCastle.algorithm.lea.roundKeyWordLength = 6;


jCastle._algorithmInfo['lea'] = {
	algorithm_type: 'crypt',
	block_size: 16,
	key_size: 32,
	min_key_size: 16,
	max_key_size: 32,
	key_sizes: [16, 24, 32],
	padding: 'zeros',
	object_name: 'lea'
};

jCastle._algorithmInfo['lea-128'] = {
	algorithm_type: 'crypt',
	block_size: 16,
	key_size: 16,
	min_key_size: 16,
	max_key_size: 16,
	padding: 'zeros',
	object_name: 'lea'
};

jCastle._algorithmInfo['lea-192'] = {
	algorithm_type: 'crypt',
	block_size: 16,
	key_size: 24,
	min_key_size: 24,
	max_key_size: 24,
	padding: 'zeros',
	object_name: 'lea'
};

jCastle._algorithmInfo['lea-256'] = {
	algorithm_type: 'crypt',
	block_size: 16,
	key_size: 32,
	min_key_size: 32,
	max_key_size: 32,
	padding: 'zeros',
	object_name: 'lea'
};

module.exports = jCastle.algorithm.lea;