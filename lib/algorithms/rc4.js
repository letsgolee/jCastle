/**
 * Javascript jCastle Mcrypt Module - RC4
 * 
 * @author Jacob Lee
 *
 * Copyright (C) 2015-2022 Jacob Lee.
 */
var jCastle = require('../jCastle');
require('../util');

jCastle.algorithm.rc4 = class
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
        this._ivSet = false;
        this._iv = null;
        this.i = 0;
        this.y = 0;
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
		this._ivSet = false;
		this._iv = null;
		this.x = 0;
		this.y = 0;
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

		this._iv = iv;
		this._ivSet = true;
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
		return this.cryptBlock(input);
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
		var iv_idx = 0;
		this.roundKey = new Uint8Array(256).fill(0);
		this.x = 0;
		this.y = 0;
		
		for (var i = 0; i < 256; i++) {
			this.roundKey[i] = i;
		}
		
		for (var i = 0, j = 0; i < 256; i++) {
			j = (j + this.roundKey[i] + key[i % key.length]) & 0xff;
			if (this._ivSet) {
				j = (j + this._iv[iv_idx]) & 0xff;
			}

			this.arraySwap(this.roundKey, i, j);

			if (this._ivSet) {
				iv_idx = (iv_idx + 1) % this._iv.length;
			}
		}
	}

	arraySwap(a, x, y)
	{
		var t;
		t = a[x]; a[x] = a[y]; a[y] = t;
	}

	/**
	 * crypt the block sized data.
	 * 
	 * @public
	 * @param {buffer} input input data to be crypted.
	 * @returns the crypted data in buffer.
	 */
	cryptBlock(input)
	{
		var output = Buffer.alloc(input.length);;
		
		for (var c = 0; c < input.length; c++) {
			this.x = (this.x + 1) & 0xff;
			this.y = (this.y + this.roundKey[this.x]) & 0xff;
			this.arraySwap(this.roundKey, this.x, this.y);
			output[c] = (input[c] ^ this.roundKey[(this.roundKey[this.x] + this.roundKey[this.y]) & 0xff]) & 0xff;
		}
		return output;

	}

	cryptByte(input)
	{
		this.x = (this.x + 1) & 0xff;
		this.y = (this.y + this.roundKey[this.x]) & 0xff;
		this.arraySwap(this.roundKey, this.x, this.y);
		return (input ^ this.roundKey[(this.roundKey[this.x] + this.roundKey[this.y]) & 0xff]) & 0xff;

	}
};


jCastle._algorithmInfo['arcfour'] =
jCastle._algorithmInfo['rc4'] = {
	algorithm_type: 'crypt',
	block_size: 1,
	key_size: 32,
	min_key_size: 1,
	max_key_size: 256,
	padding: 'zeros',
	object_name: 'rc4',
	//stream_block_size: 32 // for convenience
};

jCastle._algorithmInfo['rc4-40'] = {
	algorithm_type: 'crypt',
	block_size: 1,
	key_size: 5,
	min_key_size: 1,
	max_key_size: 256,
	padding: 'zeros',
	object_name: 'rc4',
	//stream_block_size: 5 // for convenience
};

jCastle._algorithmInfo['rc4-56'] = {
	algorithm_type: 'crypt',
	block_size: 1,
	key_size: 7,
	min_key_size: 1,
	max_key_size: 256,
	padding: 'zeros',
	object_name: 'rc4',
	//stream_block_size: 7 // for convenience
};

jCastle._algorithmInfo['rc4-64'] = {
	algorithm_type: 'crypt',
	block_size: 1,
	key_size: 8,
	min_key_size: 1,
	max_key_size: 256,
	padding: 'zeros',
	object_name: 'rc4',
	//stream_block_size: 8 // for convenience
};

jCastle._algorithmInfo['rc4-80'] = {
	algorithm_type: 'crypt',
	block_size: 1,
	key_size: 10,
	min_key_size: 1,
	max_key_size: 256,
	padding: 'zeros',
	object_name: 'rc4',
	//stream_block_size: 10 // for convenience
};

jCastle._algorithmInfo['rc4-128'] = {
	algorithm_type: 'crypt',
	block_size: 1,
	key_size: 16,
	min_key_size: 1,
	max_key_size: 256,
	padding: 'zeros',
	object_name: 'rc4',
	//stream_block_size: 16 // for convenience
};

jCastle._algorithmInfo['rc4-196'] = {
	algorithm_type: 'crypt',
	block_size: 1,
	key_size: 24,
	min_key_size: 1,
	max_key_size: 256,
	padding: 'zeros',
	object_name: 'rc4',
	//stream_block_size: 24 // for convenience
};

jCastle._algorithmInfo['rc4-256'] = {
	algorithm_type: 'crypt',
	block_size: 1,
	key_size: 32,
	min_key_size: 1,
	max_key_size: 256,
	padding: 'zeros',
	object_name: 'rc4',
	//stream_block_size: 32 // for convenience
};

module.exports = jCastle.algorithm.rc4;