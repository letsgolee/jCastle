/**
 * Javascript jCastle Mcrypt Module - Idea 
 * 
 * @author Jacob Lee
 *
 * Copyright (C) 2015-2022 Jacob Lee.
 */
var jCastle = require('../jCastle');
require('../util');

jCastle.algorithm.idea = class
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
        this.encryptKey = null;
        this.decryptKey = null;
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
		this.encryptKey = null;
		this.decryptKey = null;
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



/*
 * -----------------
 * Private functions
 * -----------------
 */

/*
	expandKey(key)
	{
		var i;
		this.encryptKey = new Uint16Array(52);
		this.decryptKey = new Uint16Array(52);

		//First, the 128-bit key is partitioned into eight 16-bit sub-blocks
		for(i = 0; i < 8; i++)
			this.encryptKey[i] = jCastle.util.load16b(key, i * 2);

		//Expand encryption subkeys
		for(i = 8; i < 52; i++) {
			if((i % 8) == 6)
				this.encryptKey[i] = ((this.encryptKey[i - 7] << 9) | (this.encryptKey[i - 14] >>> 7)) & 0xffff;
			else if((i % 8) == 7)
				this.encryptKey[i] = ((this.encryptKey[i - 15] << 9) | (this.encryptKey[i - 14] >>> 7)) & 0xffff;
			else
				this.encryptKey[i] = ((this.encryptKey[i - 7] << 9) | (this.encryptKey[i - 6] >>> 7)) & 0xffff;
		}

		//Generate subkeys for decryption

		for(i = 0; i < 52; i += 6) {
			this.decryptKey[i] = this.ideaMulInv(this.encryptKey[48 - i]);

			if(i == 0 || i == 48) {
				this.decryptKey[i + 1] = -this.encryptKey[49 - i];
				this.decryptKey[i + 2] = -this.encryptKey[50 - i];
			} else {
				this.decryptKey[i + 1] = -this.encryptKey[50 - i];
				this.decryptKey[i + 2] = -this.encryptKey[49 - i];
			}

			this.decryptKey[i + 3] = this.ideaMulInv(this.encryptKey[51 - i]);

			if(i < 48) {
				this.decryptKey[i + 4] = this.encryptKey[46 - i];
				this.decryptKey[i + 5] = this.encryptKey[47 - i];
			}
		}
	}
*/
	/**
	 * Calculate the necessary round keys.
	 * The number of calculations depends on key size and block size.
	 * 
	 * @private
	 * @param {buffer} key key for encryption/decryption.
	 * @param {boolean} isEncryption true if it is encryption, otherwise false.
	 */
	expandKey(key)
	{
		var i;
		this.encryptKey = new Array(52);
		this.decryptKey = new Array(52);

		function toUint16(x) {
			return x - Math.floor(x / 65536) * 65536;
		}


		//First, the 128-bit key is partitioned into eight 16-bit sub-blocks
		for(i = 0; i < 8; i++)
			this.encryptKey[i] = key.readUInt16BE(i * 2);

		//Expand encryption subkeys
		for(i = 8; i < 52; i++) {
			if((i % 8) == 6)
				this.encryptKey[i] = ((this.encryptKey[i - 7] << 9) | (this.encryptKey[i - 14] >>> 7)) & 0xffff;
			else if((i % 8) == 7)
				this.encryptKey[i] = ((this.encryptKey[i - 15] << 9) | (this.encryptKey[i - 14] >>> 7)) & 0xffff;
			else
				this.encryptKey[i] = ((this.encryptKey[i - 7] << 9) | (this.encryptKey[i - 6] >>> 7)) & 0xffff;
		}

		//Generate subkeys for decryption

		for(i = 0; i < 52; i += 6) {
			this.decryptKey[i] = this.ideaMulInv(this.encryptKey[48 - i]);

			if(i == 0 || i == 48) {
				this.decryptKey[i + 1] = toUint16(-this.encryptKey[49 - i]);
				this.decryptKey[i + 2] = toUint16(-this.encryptKey[50 - i]);
			} else {
				this.decryptKey[i + 1] = toUint16(-this.encryptKey[50 - i]);
				this.decryptKey[i + 2] = toUint16(-this.encryptKey[49 - i]);
			}

			this.decryptKey[i + 3] = this.ideaMulInv(this.encryptKey[51 - i]);

			if(i < 48) {
				this.decryptKey[i + 4] = this.encryptKey[46 - i];
				this.decryptKey[i + 5] = this.encryptKey[47 - i];
			}
		}
	}

	ideaMul(a, b) // uint16_t a, uint16_t b
	{
		var c = a * b;

		if(c) {
			c = (jCastle.util.rotl32(c, 16) - c) >>> 16;
			return (c + 1) & 0xFFFF;
		} else {
			return (1 - a - b) & 0xFFFF;
		}
	}

	ideaMulInv(a) // uint16_t a
	{
		var b, q, r, t, u, v;

		b = 0x10001;
		u = 0;
		v = 1;

		while(a > 0) {
			q = ~~(b / a);
			r = b % a;

			b = a;
			a = r & 0xffff;

			t = v;
			v = u - q * v;
			u = t;
		}

		if(u < 0)
			u += 0x10001;

		return u & 0xffff;
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
		var k = 0, e, f, key;
		var safeAdd = jCastle.util.safeAdd16;

		//The plaintext is divided into four 16-bit registers
		var a = input.readUInt16BE(0);
		var b = input.readUInt16BE(2);
		var c = input.readUInt16BE(4);
		var d = input.readUInt16BE(6);
		

		//Point to the key schedule
		key = direction ? this.encryptKey : this.decryptKey;

		//The process consists of eight identical encryption steps
		for(var i = 0; i < 8; i++) {
			//Apply a round
			a = this.ideaMul(a & 0xffff, key[k++]);
//			b += key[k++];
//			c += key[k++];
			b = safeAdd(b, key[k++]);
			c = safeAdd(c, key[k++]);
			d = this.ideaMul(d & 0xffff, key[k++]);

			e = a ^ c;
			f = b ^ d;

			e = this.ideaMul(e & 0xffff, key[k++]);
//			f += e;
			f = safeAdd(f, e);
			f = this.ideaMul(f & 0xffff, key[k++]);
//			e += f;
			e = safeAdd(e, f);

			a ^= f;
			d ^= e;
			e ^= b;
			f ^= c;

			b = f;
			c = e;
		}

		//The four 16-bit values produced at the end of the 8th encryption
		//round are combined with the last four of the 52 key sub-blocks
		a = this.ideaMul(a & 0xffff, key[k++]);
//		c += key[k++];
//		b += key[k++];
		c = safeAdd(c, key[k++]);
		b = safeAdd(b, key[k++]);
		d = this.ideaMul(d & 0xffff, key[k++]);

	   //The resulting value is the ciphertext
	   var output = Buffer.alloc(input.length);
	   
		output.writeUInt16BE(a & 0xffff, 0, true);
		output.writeUInt16BE(c & 0xffff, 2, true);
		output.writeUInt16BE(b & 0xffff, 4, true);
		output.writeUInt16BE(d & 0xffff, 6, true);

	   return output;
	}
}

jCastle._algorithmInfo['idea'] = {
	algorithm_type: 'crypt',
	block_size: 8,
	key_size: 16,
	min_key_size: 16,
	max_key_size: 16,
	padding: 'zeros',
	object_name: 'idea'
};

module.exports = jCastle.algorithm.idea;