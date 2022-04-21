/**
 * Javascript jCastle Module - RC6
 * 
 * @author Jacob Lee
 *
 * Copyright (C) 2015-2022 Jacob Lee.
 */

var jCastle = require('../jCastle');
require('../util');
var UINT32 = require('../uint32');

jCastle.algorithm.rc6 = class
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
        this.roundKey = null; // 2 * RC6_rounds + 4

    //	if (typeof UINT32 == 'undefined') {
    //		throw jCastle.exception("UINT32_REQUIRED", 'RC6001');
    //	}
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
				!jCastle.util.inArray(key.length, jCastle._algorithmInfo[this.algoName].key_sizes)
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
		this.rounds = 20;
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
		
		this.rounds = 20;

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
	 * decrypts a block.
	 * 
	 * @public
	 * @param {buffer} input input data to be decrypted.
	 * @returns the decrypted block in buffer.
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
		var c = key.length / 4, t = 2 * this.rounds + 4;

		this.roundKey = new Array(t);

		var L = new Array(c);

		for(var i = 0; i < c; i++) {
			L[i] = UINT32.valueOf(key.readInt32LE(i * 4));
		}

		this.roundKey[0] = UINT32.valueOf(jCastle.algorithm.rc6.P);
		for(var i = 1; i < t; i++) {
			this.roundKey[i] = this.roundKey[i-1].add(jCastle.algorithm.rc6.Q);
		}

		var A = UINT32.valueOf(0), B = UINT32.valueOf(0), i = 0, j = 0, v = 3 * t;
		for(var s = 1; s <= v; s++) {
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
		var C = UINT32.valueOf(input.readUInt32LE(8));
		var D = UINT32.valueOf(input.readUInt32LE(12));

		var t, u, tmp;

		if (direction) {
			B = B.add(this.roundKey[0]);
			D = D.add(this.roundKey[1]);
			for(var i = 1; i <= 2 * this.rounds; ) {
				t = B.multiply(2).add(1).multiply(B).rotl(5);
				u = D.multiply(2).add(1).multiply(D).rotl(5);
				A = A.xor(t).rotl(u.div(UINT32.valueOf(32)).remainder.toNumber()).add(this.roundKey[++i]);
				C = C.xor(u).rotl(t.div(UINT32.valueOf(32)).remainder.toNumber()).add(this.roundKey[++i]);
				tmp = A; A=B; B=C; C=D; D=tmp;
			}
			A = A.add(this.roundKey[2*this.rounds+2]);
			C = C.add(this.roundKey[2*this.rounds+3]);
		} else {
			C = C.subtract(this.roundKey[2*this.rounds+3]);
			A = A.subtract(this.roundKey[2*this.rounds+2]);
			for(var i = 2 * this.rounds + 2; i > 2; ) {
				tmp = D; D = C; C = B; B = A; A = tmp;
				u = D.multiply(2).add(1).multiply(D).rotl(5);
				t = B.multiply(2).add(1).multiply(B).rotl(5);
				C = C.subtract(this.roundKey[--i]).rotr(t.div(UINT32.valueOf(32)).remainder.toNumber()).xor(u);
				A = A.subtract(this.roundKey[--i]).rotr(u.div(UINT32.valueOf(32)).remainder.toNumber()).xor(t);
			}
			D = D.subtract(this.roundKey[1]);
			B = B.subtract(this.roundKey[0]);
		}

		var output = Buffer.alloc(input.length);
		output.writeUInt32LE(A.toNumber(), 0);
		output.writeUInt32LE(B.toNumber(), 4);
		output.writeUInt32LE(C.toNumber(), 8);
		output.writeUInt32LE(D.toNumber(), 12);
		
		return output;
	}
};


// Constants
//...........................................................................

// Magic constants
jCastle.algorithm.rc6.P = 0xB7E15163;
jCastle.algorithm.rc6.Q = 0x9E3779B9;

jCastle._algorithmInfo['rc6'] = {
	algorithm_type: 'crypt',
	block_size: 16,
	key_size: 32,
	min_key_size: 16,
	max_key_size: 32,
	key_sizes: [16, 24, 32],
	padding: 'zeros',
	object_name: 'rc6'
};

module.exports = jCastle.algorithm.rc6;