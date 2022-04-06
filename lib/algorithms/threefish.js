/**
 * Javascript jCastle Mcrypt Module - Threefish
 * 
 * @author Jacob Lee
 *
 * Copyright (C) 2015-2022 Jacob Lee.
 */

var jCastle = require('../jCastle');
require('../util');
var INT64 = require('../int64');


// if (typeof INT64 == 'undefined') {
// 	throw jCastle.exception("INT64_REQUIRED");
// }

jCastle.algorithm.threefish = class
{
	/**
	 * creates the algorithm instance.
	 * 
	 * @param {string} algo_name algorithm name
	 * @param {object} options options object
	 * @constructor
	 */
    constructor(algo_name, options)
    {
        options = options || {};

        this.algoName = algo_name;
        this.masterKey = null;
        this.roundKey = null;
        this.rawTweak = null;

        if ('tweak' in options) {
            this.setTweak(options.tweak);
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
		var keylen = key.length;
		
		if (Array.isArray(this._options.key) && key[0] instanceof INT64) {
			keylen = keylen * 8;
		}
		
		if (jCastle._algorithmInfo[this.algoName].min_key_size == jCastle._algorithmInfo[this.algoName].max_key_size) {
			if (keylen != jCastle._algorithmInfo[this.algoName].key_size) {
				return false;
			}
		} else {
			if (keylen > jCastle._algorithmInfo[this.algoName].max_key_size) {
				return false;
			}
			if (keylen < jCastle._algorithmInfo[this.algoName].min_key_size) {
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
		this.rawTweak = null;

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
	 * sets tweak value. if tweat should be set, this function must be executed before keySchedule().
	 * 
	 * @public
	 * @param {mixed} tweak tweak value. array of INT64 or buffer
	 * @returns this class instance.
	 */
	setTweak(tweak)
	{
		if (Array.isArray(tweak) && tweak[0] instanceof INT64) {
			this.rawTweak = tweak;
		} else {
			this.rawTweak = Buffer.from(tweak, 'latin1');
		}

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
		if (Array.isArray(key) && key[0] instanceof INT64) {
			this.masterKey = key;
		} else {			
			this.masterKey = Buffer.from(key, 'latin1');
		}
		
		this.expandKey(this.masterKey);
		this.rounds = jCastle._algorithmInfo[this.algoName].rounds;
		this.tweak = new Array(5); // empty default tweak

		if (this.rawTweak) {
			this.expandTweak();
		}

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
		var block_size = jCastle._algorithmInfo[this.algoName].block_size;

		switch (block_size) {
			case 32: return this.encryptBlock_256(input);
			case 64: return this.encryptBlock_512(input);
			case 128: return this.encryptBlock_1024(input);
		}
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
		var block_size = jCastle._algorithmInfo[this.algoName].block_size;

		switch (block_size) {
			case 32: return this.decryptBlock_256(input);
			case 64: return this.decryptBlock_512(input);
			case 128: return this.decryptBlock_1024(input);
		}
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
		var block_size = jCastle._algorithmInfo[this.algoName].block_size;

		this.roundKey = [];

		// key can be INT64 array. This will happen within Skein Hash.
		if (Array.isArray(key) && key[0] instanceof INT64) {
			if (key.length !== (jCastle._algorithmInfo[this.algoName].block_size / 8))
				throw jCastle.exception("INVALID_KEYSIZE", 'THREEFISH001');
			this.roundKey = key.slice(0);
		} else {
			// 64 bit word from input in LSB first order
			for (var i = 0, j = 0; i < block_size; i += 8) {
				this.roundKey[j++] = this.loadInt64(key, i);
			}
		}

		var parity = jCastle.algorithm.threefish.SCHEDULE_CONST;

		for (var i = 0; i < this.roundKey.length; i++) {
			parity = parity.xor(this.roundKey[i]);
		}
		this.roundKey.push(parity);

		for (var i = 0; i < block_size / 8; i++) {
			this.roundKey.push(this.roundKey[i].clone());
		}

		return this;
	}

	// Tweak bytes (2 byte t1,t2, calculated t3 and repeat of t1,t2 for modulo free lookup
	expandTweak(tweak)
	{
		if (!tweak && this.rawTweak)
			tweak = this.rawTweak;
		
		if (Array.isArray(tweak) && tweak[0] instanceof INT64) {  // This will happen within Skein Hash.
			if (tweak.length != 2) throw jCastle.exception("INVALID_TWEAK_SIZE", 'THREEFISH002');
			this.tweak = tweak.slice(0);
		} else {
			if (tweak.length != jCastle.algorithm.threefish.TWEAK_SIZE) {
				//throw "Invalid tweak size. It should be " + jCastle.algorithm.threefish.TWEAK_SIZE;
				throw jCastle.exception("INVALID_TWEAK_SIZE", 'THREEFISH003');
			}

			this.tweak = []; // 5

			// 64 bit word from input in LSB first order
//			for (var i = 0, j = 0; i < jCastle.algorithm.threefish.TWEAK_SIZE; i += 8) {
//				this.tweak[j++] = this.loadInt64(tweak, i);
//			}
			this.tweak[0] = this.loadInt64(tweak, 0);
			this.tweak[1] = this.loadInt64(tweak, 8);
		}

		this.tweak[2] = this.tweak[0].xor(this.tweak[1]);
		this.tweak[3] = this.tweak[0].clone();
		this.tweak[4] = this.tweak[1].clone();

		return this;
	}

	loadInt64(a, i)
	{
		return new INT64(a.readInt32LE(i + 4), a.readInt32LE(i));
	}

	storeInt64(a, i, i64)
	{
		a.writeInt32LE(i64.lsint, i, true);
		a.writeInt32LE(i64.msint, i + 4, true);
	}

	encryptBlock_256(input)
	{
		// 256 bits; 32 bytes to 4 64bit words of little endian order
		var b0 = this.loadInt64(input, 0);
		var b1 = this.loadInt64(input, 8);
		var b2 = this.loadInt64(input, 16);
		var b3 = this.loadInt64(input, 24);

		// First subkey injection.
		b0 = b0.add(this.roundKey[0]);
		b1 = b1.add(this.roundKey[1].add(this.tweak[0]));
		b2 = b2.add(this.roundKey[2].add(this.tweak[1]));
		b3 = b3.add(this.roundKey[3]);

		// this.round / 4 = 72 / 4 = 18, starting from 2, so the end is + 2.
		for(var r = 2; r < this.rounds / 4 + 2; r += 2) {
			b0 = b0.add(b1); b1 = b1.rotateLeft(14).xor(b0);
			b2 = b2.add(b3); b3 = b3.rotateLeft(16).xor(b2);
			b0 = b0.add(b3); b3 = b3.rotateLeft(52).xor(b0);
			b2 = b2.add(b1); b1 = b1.rotateLeft(57).xor(b2);
			b0 = b0.add(b1); b1 = b1.rotateLeft(23).xor(b0);
			b2 = b2.add(b3); b3 = b3.rotateLeft(40).xor(b2);
			b0 = b0.add(b3); b3 = b3.rotateLeft( 5).xor(b0);
			b2 = b2.add(b1); b1 = b1.rotateLeft(37).xor(b2);

			b0 = b0.add(this.roundKey[(r-1) % 5]);
			b1 = b1.add(this.roundKey[r % 5]).add(this.tweak[(r-1) % 3]);
			b2 = b2.add(this.roundKey[(r+1) % 5]).add(this.tweak[r % 3]);
			b3 = b3.add(this.roundKey[(r+2) % 5]).add(r-1);

			b0 = b0.add(b1); b1 = b1.rotateLeft(25).xor(b0);
			b2 = b2.add(b3); b3 = b3.rotateLeft(33).xor(b2);
			b0 = b0.add(b3); b3 = b3.rotateLeft(46).xor(b0);
			b2 = b2.add(b1); b1 = b1.rotateLeft(12).xor(b2);
			b0 = b0.add(b1); b1 = b1.rotateLeft(58).xor(b0);
			b2 = b2.add(b3); b3 = b3.rotateLeft(22).xor(b2);
			b0 = b0.add(b3); b3 = b3.rotateLeft(32).xor(b0);
			b2 = b2.add(b1); b1 = b1.rotateLeft(32).xor(b2);

			b0 = b0.add(this.roundKey[r % 5]);
			b1 = b1.add(this.roundKey[(r+1) % 5]).add(this.tweak[r % 3]);
			b2 = b2.add(this.roundKey[(r+2) % 5]).add(this.tweak[(r+1) % 3]);
			b3 = b3.add(this.roundKey[(r+3) % 5]).add(r);
		}

		var output = Buffer.alloc(input.length);

		this.storeInt64(output, 0, b0);
		this.storeInt64(output, 8, b1);
		this.storeInt64(output, 16, b2);
		this.storeInt64(output, 24, b3);

		return output;
	}

	decryptBlock_256(input)
	{
		// 256 bits; 32 bytes to 4 64bit words of little endian order
		var b0 = this.loadInt64(input, 0);
		var b1 = this.loadInt64(input, 8);
		var b2 = this.loadInt64(input, 16);
		var b3 = this.loadInt64(input, 24);

		for(var r = this.rounds / 4; r >= 2; r -= 2) {
			b0 = b0.subtract(this.roundKey[r % 5]);
			b1 = b1.subtract(this.roundKey[(r+1) % 5].add(this.tweak[r % 3]));
			b2 = b2.subtract(this.roundKey[(r+2) % 5].add(this.tweak[(r+1) % 3]));
			b3 = b3.subtract(this.roundKey[(r+3) % 5].add(r));

			b3 = b3.xor(b0).rotateRight(32); b0 = b0.subtract(b3);
			b1 = b1.xor(b2).rotateRight(32); b2 = b2.subtract(b1);
			b1 = b1.xor(b0).rotateRight(58); b0 = b0.subtract(b1);
			b3 = b3.xor(b2).rotateRight(22); b2 = b2.subtract(b3);
			b3 = b3.xor(b0).rotateRight(46); b0 = b0.subtract(b3);
			b1 = b1.xor(b2).rotateRight(12); b2 = b2.subtract(b1);
			b1 = b1.xor(b0).rotateRight(25); b0 = b0.subtract(b1);
			b3 = b3.xor(b2).rotateRight(33); b2 = b2.subtract(b3);

			b0 = b0.subtract(this.roundKey[(r-1) % 5]);
			b1 = b1.subtract(this.roundKey[r % 5].add(this.tweak[(r-1) % 3]));
			b2 = b2.subtract(this.roundKey[(r+1) % 5].add(this.tweak[r % 3]));
			b3 = b3.subtract(this.roundKey[(r+2) % 5].add(r-1));

			b3 = b3.xor(b0).rotateRight( 5); b0 = b0.subtract(b3);
			b1 = b1.xor(b2).rotateRight(37); b2 = b2.subtract(b1);
			b1 = b1.xor(b0).rotateRight(23); b0 = b0.subtract(b1);
			b3 = b3.xor(b2).rotateRight(40); b2 = b2.subtract(b3);
			b3 = b3.xor(b0).rotateRight(52); b0 = b0.subtract(b3);
			b1 = b1.xor(b2).rotateRight(57); b2 = b2.subtract(b1);
			b1 = b1.xor(b0).rotateRight(14); b0 = b0.subtract(b1);
			b3 = b3.xor(b2).rotateRight(16); b2 = b2.subtract(b3);
		}

		// First subkey uninjection.
		b0 = b0.subtract(this.roundKey[0]);
		b1 = b1.subtract(this.roundKey[1].add(this.tweak[0]));
		b2 = b2.subtract(this.roundKey[2].add(this.tweak[1]));
		b3 = b3.subtract(this.roundKey[3]);

		var output = Buffer.alloc(input.length);

		this.storeInt64(output, 0, b0);
		this.storeInt64(output, 8, b1);
		this.storeInt64(output, 16, b2);
		this.storeInt64(output, 24, b3);

		return output;
	}

	encryptBlock_512(input)
	{
		// 256 bits; 64 bytes to 8 64bit-words of little endian order
		var b0 = this.loadInt64(input, 0);
		var b1 = this.loadInt64(input, 8);
		var b2 = this.loadInt64(input, 16);
		var b3 = this.loadInt64(input, 24);
		var b4 = this.loadInt64(input, 32);
		var b5 = this.loadInt64(input, 40);
		var b6 = this.loadInt64(input, 48);
		var b7 = this.loadInt64(input, 56);

		b0 = b0.add(this.roundKey[0]);
		b1 = b1.add(this.roundKey[1]);
		b2 = b2.add(this.roundKey[2]);
		b3 = b3.add(this.roundKey[3]);
		b4 = b4.add(this.roundKey[4]);
		b5 = b5.add(this.roundKey[5].add(this.tweak[0]));
		b6 = b6.add(this.roundKey[6].add(this.tweak[1]));
		b7 = b7.add(this.roundKey[7]);

		for(var r = 2; r < this.rounds / 4 + 2; r += 2) {
			b0 = b0.add(b1); b1 = b1.rotateLeft(46).xor(b0);
			b2 = b2.add(b3); b3 = b3.rotateLeft(36).xor(b2);
			b4 = b4.add(b5); b5 = b5.rotateLeft(19).xor(b4);
			b6 = b6.add(b7); b7 = b7.rotateLeft(37).xor(b6);
			b2 = b2.add(b1); b1 = b1.rotateLeft(33).xor(b2);
			b4 = b4.add(b7); b7 = b7.rotateLeft(27).xor(b4);
			b6 = b6.add(b5); b5 = b5.rotateLeft(14).xor(b6);
			b0 = b0.add(b3); b3 = b3.rotateLeft(42).xor(b0);
			b4 = b4.add(b1); b1 = b1.rotateLeft(17).xor(b4);
			b6 = b6.add(b3); b3 = b3.rotateLeft(49).xor(b6);
			b0 = b0.add(b5); b5 = b5.rotateLeft(36).xor(b0);
			b2 = b2.add(b7); b7 = b7.rotateLeft(39).xor(b2);
			b6 = b6.add(b1); b1 = b1.rotateLeft(44).xor(b6);
			b0 = b0.add(b7); b7 = b7.rotateLeft(9).xor(b0);
			b2 = b2.add(b5); b5 = b5.rotateLeft(54).xor(b2);
			b4 = b4.add(b3); b3 = b3.rotateLeft(56).xor(b4);

			b0 = b0.add(this.roundKey[(r - 1) % 9]);
			b1 = b1.add(this.roundKey[r % 9]);
			b2 = b2.add(this.roundKey[(r + 1) % 9]);
			b3 = b3.add(this.roundKey[(r + 2) % 9]);
			b4 = b4.add(this.roundKey[(r + 3) % 9]);
			b5 = b5.add(this.roundKey[(r + 4) % 9].add(this.tweak[(r - 1) % 3]));
			b6 = b6.add(this.roundKey[(r + 5) % 9].add(this.tweak[r % 3]));
			b7 = b7.add(this.roundKey[(r + 6) % 9].add(r - 1));

			b0 = b0.add(b1); b1 = b1.rotateLeft(39).xor(b0);
			b2 = b2.add(b3); b3 = b3.rotateLeft(30).xor(b2);
			b4 = b4.add(b5); b5 = b5.rotateLeft(34).xor(b4);
			b6 = b6.add(b7); b7 = b7.rotateLeft(24).xor(b6);
			b2 = b2.add(b1); b1 = b1.rotateLeft(13).xor(b2);
			b4 = b4.add(b7); b7 = b7.rotateLeft(50).xor(b4);
			b6 = b6.add(b5); b5 = b5.rotateLeft(10).xor(b6);
			b0 = b0.add(b3); b3 = b3.rotateLeft(17).xor(b0);
			b4 = b4.add(b1); b1 = b1.rotateLeft(25).xor(b4);
			b6 = b6.add(b3); b3 = b3.rotateLeft(29).xor(b6);
			b0 = b0.add(b5); b5 = b5.rotateLeft(39).xor(b0);
			b2 = b2.add(b7); b7 = b7.rotateLeft(43).xor(b2);
			b6 = b6.add(b1); b1 = b1.rotateLeft(8).xor(b6);
			b0 = b0.add(b7); b7 = b7.rotateLeft(35).xor(b0);
			b2 = b2.add(b5); b5 = b5.rotateLeft(56).xor(b2);
			b4 = b4.add(b3); b3 = b3.rotateLeft(22).xor(b4);

			b0 = b0.add(this.roundKey[r % 9]);
			b1 = b1.add(this.roundKey[(r + 1) % 9]);
			b2 = b2.add(this.roundKey[(r + 2) % 9]);
			b3 = b3.add(this.roundKey[(r + 3) % 9]);
			b4 = b4.add(this.roundKey[(r + 4) % 9]);
			b5 = b5.add(this.roundKey[(r + 5) % 9].add(this.tweak[r % 3]));
			b6 = b6.add(this.roundKey[(r + 6) % 9].add(this.tweak[(r + 1) % 3]));
			b7 = b7.add(this.roundKey[(r + 7) % 9].add(r));
		}

		var output = Buffer.alloc(input.length);

		this.storeInt64(output, 0, b0);
		this.storeInt64(output, 8, b1);
		this.storeInt64(output, 16, b2);
		this.storeInt64(output, 24, b3);
		this.storeInt64(output, 32, b4);
		this.storeInt64(output, 40, b5);
		this.storeInt64(output, 48, b6);
		this.storeInt64(output, 56, b7);

		return output;
	}

	decryptBlock_512(input)
	{
		// 256 bits; 64 bytes to 8 64bit-words of little endian order
		var b0 = this.loadInt64(input, 0);
		var b1 = this.loadInt64(input, 8);
		var b2 = this.loadInt64(input, 16);
		var b3 = this.loadInt64(input, 24);
		var b4 = this.loadInt64(input, 32);
		var b5 = this.loadInt64(input, 40);
		var b6 = this.loadInt64(input, 48);
		var b7 = this.loadInt64(input, 56);

		for(var r = this.rounds / 4; r >= 2; r -= 2) {
			// Reverse key injection for second 4 rounds
			b0 = b0.subtract(this.roundKey[r % 9]);
			b1 = b1.subtract(this.roundKey[(r + 1) % 9]);
			b2 = b2.subtract(this.roundKey[(r + 2) % 9]);
			b3 = b3.subtract(this.roundKey[(r + 3) % 9]);
			b4 = b4.subtract(this.roundKey[(r + 4) % 9]);
			b5 = b5.subtract(this.roundKey[(r + 5) % 9].add(this.tweak[r % 3]));
			b6 = b6.subtract(this.roundKey[(r + 6) % 9].add(this.tweak[(r + 1) % 3]));
			b7 = b7.subtract(this.roundKey[(r + 7) % 9].add(r));

			// Reverse second 4 mix/permute rounds
			b1 = b1.xor(b6).rotateRight(8); b6 = b6.subtract(b1);
			b7 = b7.xor(b0).rotateRight(35); b0 = b0.subtract(b7);
			b5 = b5.xor(b2).rotateRight(56); b2 = b2.subtract(b5);
			b3 = b3.xor(b4).rotateRight(22); b4 = b4.subtract(b3);
			b1 = b1.xor(b4).rotateRight(25); b4 = b4.subtract(b1);
			b3 = b3.xor(b6).rotateRight(29); b6 = b6.subtract(b3);
			b5 = b5.xor(b0).rotateRight(39); b0 = b0.subtract(b5);
			b7 = b7.xor(b2).rotateRight(43); b2 = b2.subtract(b7);
			b1 = b1.xor(b2).rotateRight(13); b2 = b2.subtract(b1);
			b7 = b7.xor(b4).rotateRight(50); b4 = b4.subtract(b7);
			b5 = b5.xor(b6).rotateRight(10); b6 = b6.subtract(b5);
			b3 = b3.xor(b0).rotateRight(17); b0 = b0.subtract(b3);
			b1 = b1.xor(b0).rotateRight(39); b0 = b0.subtract(b1);
			b3 = b3.xor(b2).rotateRight(30); b2 = b2.subtract(b3);
			b5 = b5.xor(b4).rotateRight(34); b4 = b4.subtract(b5);
			b7 = b7.xor(b6).rotateRight(24); b6 = b6.subtract(b7);

			// Reverse key injection for first 4 rounds
			b0 = b0.subtract(this.roundKey[(r - 1) % 9]);
			b1 = b1.subtract(this.roundKey[r % 9]);
			b2 = b2.subtract(this.roundKey[(r + 1) % 9]);
			b3 = b3.subtract(this.roundKey[(r + 2) % 9]);
			b4 = b4.subtract(this.roundKey[(r + 3) % 9]);
			b5 = b5.subtract(this.roundKey[(r + 4) % 9].add(this.tweak[(r - 1) % 3]));
			b6 = b6.subtract(this.roundKey[(r + 5) % 9].add(this.tweak[r % 3]));
			b7 = b7.subtract(this.roundKey[(r + 6) % 9].add(r - 1));

			// Reverse first 4 mix/permute rounds 
			b1 = b1.xor(b6).rotateRight(44); b6 = b6.subtract(b1);
			b7 = b7.xor(b0).rotateRight(9); b0 = b0.subtract(b7);
			b5 = b5.xor(b2).rotateRight(54); b2 = b2.subtract(b5);
			b3 = b3.xor(b4).rotateRight(56); b4 = b4.subtract(b3);
			b1 = b1.xor(b4).rotateRight(17); b4 = b4.subtract(b1);
			b3 = b3.xor(b6).rotateRight(49); b6 = b6.subtract(b3);
			b5 = b5.xor(b0).rotateRight(36); b0 = b0.subtract(b5);
			b7 = b7.xor(b2).rotateRight(39); b2 = b2.subtract(b7);
			b1 = b1.xor(b2).rotateRight(33); b2 = b2.subtract(b1);
			b7 = b7.xor(b4).rotateRight(27); b4 = b4.subtract(b7);
			b5 = b5.xor(b6).rotateRight(14); b6 = b6.subtract(b5);
			b3 = b3.xor(b0).rotateRight(42); b0 = b0.subtract(b3);
			b1 = b1.xor(b0).rotateRight(46); b0 = b0.subtract(b1);
			b3 = b3.xor(b2).rotateRight(36); b2 = b2.subtract(b3);
			b5 = b5.xor(b4).rotateRight(19); b4 = b4.subtract(b5);
			b7 = b7.xor(b6).rotateRight(37); b6 = b6.subtract(b7);
		}

		b0 = b0.subtract(this.roundKey[0]);
		b1 = b1.subtract(this.roundKey[1]);
		b2 = b2.subtract(this.roundKey[2]);
		b3 = b3.subtract(this.roundKey[3]);
		b4 = b4.subtract(this.roundKey[4]);
		b5 = b5.subtract(this.roundKey[5].add(this.tweak[0]));
		b6 = b6.subtract(this.roundKey[6].add(this.tweak[1]));
		b7 = b7.subtract(this.roundKey[7]);

		var output = Buffer.alloc(input.length);

		this.storeInt64(output, 0, b0);
		this.storeInt64(output, 8, b1);
		this.storeInt64(output, 16, b2);
		this.storeInt64(output, 24, b3);
		this.storeInt64(output, 32, b4);
		this.storeInt64(output, 40, b5);
		this.storeInt64(output, 48, b6);
		this.storeInt64(output, 56, b7);

		return output;
	}

	encryptBlock_1024(input)
	{
		// 256 bits; 64 bytes to 8 64bit-words of little endian order
		var b0 = this.loadInt64(input, 0);
		var b1 = this.loadInt64(input, 8);
		var b2 = this.loadInt64(input, 16);
		var b3 = this.loadInt64(input, 24);
		var b4 = this.loadInt64(input, 32);
		var b5 = this.loadInt64(input, 40);
		var b6 = this.loadInt64(input, 48);
		var b7 = this.loadInt64(input, 56);
		var b8 = this.loadInt64(input, 64);
		var b9 = this.loadInt64(input, 72);
		var b10 = this.loadInt64(input, 80);
		var b11 = this.loadInt64(input, 88);
		var b12 = this.loadInt64(input, 96);
		var b13 = this.loadInt64(input, 104);
		var b14 = this.loadInt64(input, 112);
		var b15 = this.loadInt64(input, 120);

		b0 = b0.add(this.roundKey[0]);
		b1 = b1.add(this.roundKey[1]);
		b2 = b2.add(this.roundKey[2]);
		b3 = b3.add(this.roundKey[3]);
		b4 = b4.add(this.roundKey[4]);
		b5 = b5.add(this.roundKey[5]);
		b6 = b6.add(this.roundKey[6]);
		b7 = b7.add(this.roundKey[7]);
		b8 = b8.add(this.roundKey[8]);
		b9 = b9.add(this.roundKey[9]);
		b10 = b10.add(this.roundKey[10]);
		b11 = b11.add(this.roundKey[11]);
		b12 = b12.add(this.roundKey[12]);
		b13 = b13.add(this.roundKey[13].add(this.tweak[0]));
		b14 = b14.add(this.roundKey[14].add(this.tweak[1]));
		b15 = b15.add(this.roundKey[15]);

		for(var r = 2; r < this.rounds / 4 + 2; r += 2) {
			b0 = b0.add(b1); b1 = b1.rotateLeft(24).xor(b0);
			b2 = b2.add(b3); b3 = b3.rotateLeft(13).xor(b2);
			b4 = b4.add(b5); b5 = b5.rotateLeft(8).xor(b4);
			b6 = b6.add(b7); b7 = b7.rotateLeft(47).xor(b6);
			b8 = b8.add(b9); b9 = b9.rotateLeft(8).xor(b8);
			b10 = b10.add(b11); b11 = b11.rotateLeft(17).xor(b10);
			b12 = b12.add(b13); b13 = b13.rotateLeft(22).xor(b12);
			b14 = b14.add(b15); b15 = b15.rotateLeft(37).xor(b14);
			b0 = b0.add(b9); b9 = b9.rotateLeft(38).xor(b0);
			b2 = b2.add(b13); b13 = b13.rotateLeft(19).xor(b2);
			b6 = b6.add(b11); b11 = b11.rotateLeft(10).xor(b6);
			b4 = b4.add(b15); b15 = b15.rotateLeft(55).xor(b4);
			b10 = b10.add(b7); b7 = b7.rotateLeft(49).xor(b10);
			b12 = b12.add(b3); b3 = b3.rotateLeft(18).xor(b12);
			b14 = b14.add(b5); b5 = b5.rotateLeft(23).xor(b14);
			b8 = b8.add(b1); b1 = b1.rotateLeft(52).xor(b8);
			b0 = b0.add(b7); b7 = b7.rotateLeft(33).xor(b0);
			b2 = b2.add(b5); b5 = b5.rotateLeft(4).xor(b2);
			b4 = b4.add(b3); b3 = b3.rotateLeft(51).xor(b4);
			b6 = b6.add(b1); b1 = b1.rotateLeft(13).xor(b6);
			b12 = b12.add(b15); b15 = b15.rotateLeft(34).xor(b12);
			b14 = b14.add(b13); b13 = b13.rotateLeft(41).xor(b14);
			b8 = b8.add(b11); b11 = b11.rotateLeft(59).xor(b8);
			b10 = b10.add(b9); b9 = b9.rotateLeft(17).xor(b10);
			b0 = b0.add(b15); b15 = b15.rotateLeft(5).xor(b0);
			b2 = b2.add(b11); b11 = b11.rotateLeft(20).xor(b2);
			b6 = b6.add(b13); b13 = b13.rotateLeft(48).xor(b6);
			b4 = b4.add(b9); b9 = b9.rotateLeft(41).xor(b4);
			b14 = b14.add(b1); b1 = b1.rotateLeft(47).xor(b14);
			b8 = b8.add(b5); b5 = b5.rotateLeft(28).xor(b8);
			b10 = b10.add(b3); b3 = b3.rotateLeft(16).xor(b10);
			b12 = b12.add(b7); b7 = b7.rotateLeft(25).xor(b12);

			b0 = b0.add(this.roundKey[(r - 1) % 17]);
			b1 = b1.add(this.roundKey[r % 17]);
			b2 = b2.add(this.roundKey[(r + 1) % 17]);
			b3 = b3.add(this.roundKey[(r + 2) % 17]);
			b4 = b4.add(this.roundKey[(r + 3) % 17]);
			b5 = b5.add(this.roundKey[(r + 4) % 17]);
			b6 = b6.add(this.roundKey[(r + 5) % 17]);
			b7 = b7.add(this.roundKey[(r + 6) % 17]);
			b8 = b8.add(this.roundKey[(r + 7) % 17]);
			b9 = b9.add(this.roundKey[(r + 8) % 17]);
			b10 = b10.add(this.roundKey[(r + 9) % 17]);
			b11 = b11.add(this.roundKey[(r + 10) % 17]);
			b12 = b12.add(this.roundKey[(r + 11) % 17]);
			b13 = b13.add(this.roundKey[(r + 12) % 17].add(this.tweak[(r - 1) % 3]));
			b14 = b14.add(this.roundKey[(r + 13) % 17].add(this.tweak[r % 3]));
			b15 = b15.add(this.roundKey[(r + 14) % 17].add(r - 1));

			b0 = b0.add(b1); b1 = b1.rotateLeft(41).xor(b0);
			b2 = b2.add(b3); b3 = b3.rotateLeft(9).xor(b2);
			b4 = b4.add(b5); b5 = b5.rotateLeft(37).xor(b4);
			b6 = b6.add(b7); b7 = b7.rotateLeft(31).xor(b6);
			b8 = b8.add(b9); b9 = b9.rotateLeft(12).xor(b8);
			b10 = b10.add(b11); b11 = b11.rotateLeft(47).xor(b10);
			b12 = b12.add(b13); b13 = b13.rotateLeft(44).xor(b12);
			b14 = b14.add(b15); b15 = b15.rotateLeft(30).xor(b14);
			b0 = b0.add(b9); b9 = b9.rotateLeft(16).xor(b0);
			b2 = b2.add(b13); b13 = b13.rotateLeft(34).xor(b2);
			b6 = b6.add(b11); b11 = b11.rotateLeft(56).xor(b6);
			b4 = b4.add(b15); b15 = b15.rotateLeft(51).xor(b4);
			b10 = b10.add(b7); b7 = b7.rotateLeft(4).xor(b10);
			b12 = b12.add(b3); b3 = b3.rotateLeft(53).xor(b12);
			b14 = b14.add(b5); b5 = b5.rotateLeft(42).xor(b14);
			b8 = b8.add(b1); b1 = b1.rotateLeft(41).xor(b8);
			b0 = b0.add(b7); b7 = b7.rotateLeft(31).xor(b0);
			b2 = b2.add(b5); b5 = b5.rotateLeft(44).xor(b2);
			b4 = b4.add(b3); b3 = b3.rotateLeft(47).xor(b4);
			b6 = b6.add(b1); b1 = b1.rotateLeft(46).xor(b6);
			b12 = b12.add(b15); b15 = b15.rotateLeft(19).xor(b12);
			b14 = b14.add(b13); b13 = b13.rotateLeft(42).xor(b14);
			b8 = b8.add(b11); b11 = b11.rotateLeft(44).xor(b8);
			b10 = b10.add(b9); b9 = b9.rotateLeft(25).xor(b10);
			b0 = b0.add(b15); b15 = b15.rotateLeft(9).xor(b0);
			b2 = b2.add(b11); b11 = b11.rotateLeft(48).xor(b2);
			b6 = b6.add(b13); b13 = b13.rotateLeft(35).xor(b6);
			b4 = b4.add(b9); b9 = b9.rotateLeft(52).xor(b4);
			b14 = b14.add(b1); b1 = b1.rotateLeft(23).xor(b14);
			b8 = b8.add(b5); b5 = b5.rotateLeft(31).xor(b8);
			b10 = b10.add(b3); b3 = b3.rotateLeft(37).xor(b10);
			b12 = b12.add(b7); b7 = b7.rotateLeft(20).xor(b12);

			b0 = b0.add(this.roundKey[r % 17]);
			b1 = b1.add(this.roundKey[(r + 1) % 17]);
			b2 = b2.add(this.roundKey[(r + 2) % 17]);
			b3 = b3.add(this.roundKey[(r + 3) % 17]);
			b4 = b4.add(this.roundKey[(r + 4) % 17]);
			b5 = b5.add(this.roundKey[(r + 5) % 17]);
			b6 = b6.add(this.roundKey[(r + 6) % 17]);
			b7 = b7.add(this.roundKey[(r + 7) % 17]);
			b8 = b8.add(this.roundKey[(r + 8) % 17]);
			b9 = b9.add(this.roundKey[(r + 9) % 17]);
			b10 = b10.add(this.roundKey[(r + 10) % 17]);
			b11 = b11.add(this.roundKey[(r + 11) % 17]);
			b12 = b12.add(this.roundKey[(r + 12) % 17]);
			b13 = b13.add(this.roundKey[(r + 13) % 17].add(this.tweak[r % 3]));
			b14 = b14.add(this.roundKey[(r + 14) % 17].add(this.tweak[(r + 1) % 3]));
			b15 = b15.add(this.roundKey[(r + 15) % 17].add(r));
		}

		var output = Buffer.alloc(input.length);

		this.storeInt64(output, 0, b0);
		this.storeInt64(output, 8, b1);
		this.storeInt64(output, 16, b2);
		this.storeInt64(output, 24, b3);
		this.storeInt64(output, 32, b4);
		this.storeInt64(output, 40, b5);
		this.storeInt64(output, 48, b6);
		this.storeInt64(output, 56, b7);
		this.storeInt64(output, 64, b8);
		this.storeInt64(output, 72, b9);
		this.storeInt64(output, 80, b10);
		this.storeInt64(output, 88, b11);
		this.storeInt64(output, 96, b12);
		this.storeInt64(output, 104, b13);
		this.storeInt64(output, 112, b14);
		this.storeInt64(output, 120, b15);

		return output;
	}

	decryptBlock_1024(input)
	{
		// 256 bits; 64 bytes to 8 64bit-words of little endian order
		var b0 = this.loadInt64(input, 0);
		var b1 = this.loadInt64(input, 8);
		var b2 = this.loadInt64(input, 16);
		var b3 = this.loadInt64(input, 24);
		var b4 = this.loadInt64(input, 32);
		var b5 = this.loadInt64(input, 40);
		var b6 = this.loadInt64(input, 48);
		var b7 = this.loadInt64(input, 56);
		var b8 = this.loadInt64(input, 64);
		var b9 = this.loadInt64(input, 72);
		var b10 = this.loadInt64(input, 80);
		var b11 = this.loadInt64(input, 88);
		var b12 = this.loadInt64(input, 96);
		var b13 = this.loadInt64(input, 104);
		var b14 = this.loadInt64(input, 112);
		var b15 = this.loadInt64(input, 120);

		for(var r = this.rounds / 4; r >= 2; r -= 2) {
			b0 = b0.subtract(this.roundKey[r % 17]);
			b1 = b1.subtract(this.roundKey[(r + 1) % 17]);
			b2 = b2.subtract(this.roundKey[(r + 2) % 17]);
			b3 = b3.subtract(this.roundKey[(r + 3) % 17]);
			b4 = b4.subtract(this.roundKey[(r + 4) % 17]);
			b5 = b5.subtract(this.roundKey[(r + 5) % 17]);
			b6 = b6.subtract(this.roundKey[(r + 6) % 17]);
			b7 = b7.subtract(this.roundKey[(r + 7) % 17]);
			b8 = b8.subtract(this.roundKey[(r + 8) % 17]);
			b9 = b9.subtract(this.roundKey[(r + 9) % 17]);
			b10 = b10.subtract(this.roundKey[(r + 10) % 17]);
			b11 = b11.subtract(this.roundKey[(r + 11) % 17]);
			b12 = b12.subtract(this.roundKey[(r + 12) % 17]);
			b13 = b13.subtract(this.roundKey[(r + 13) % 17].add(this.tweak[r % 3]));
			b14 = b14.subtract(this.roundKey[(r + 14) % 17].add(this.tweak[(r + 1) % 3]));
			b15 = b15.subtract(this.roundKey[(r + 15) % 17].add(r));

			b15 = b15.xor(b0).rotateRight(9); b0 = b0.subtract(b15);
			b11 = b11.xor(b2).rotateRight(48); b2 = b2.subtract(b11);
			b13 = b13.xor(b6).rotateRight(35); b6 = b6.subtract(b13);
			b9 = b9.xor(b4).rotateRight(52); b4 = b4.subtract(b9);
			b1 = b1.xor(b14).rotateRight(23); b14 = b14.subtract(b1);
			b5 = b5.xor(b8).rotateRight(31); b8 = b8.subtract(b5);
			b3 = b3.xor(b10).rotateRight(37); b10 = b10.subtract(b3);
			b7 = b7.xor(b12).rotateRight(20); b12 = b12.subtract(b7);
			b7 = b7.xor(b0).rotateRight(31); b0 = b0.subtract(b7);
			b5 = b5.xor(b2).rotateRight(44); b2 = b2.subtract(b5);
			b3 = b3.xor(b4).rotateRight(47); b4 = b4.subtract(b3);
			b1 = b1.xor(b6).rotateRight(46); b6 = b6.subtract(b1);
			b15 = b15.xor(b12).rotateRight(19); b12 = b12.subtract(b15);
			b13 = b13.xor(b14).rotateRight(42); b14 = b14.subtract(b13);
			b11 = b11.xor(b8).rotateRight(44); b8 = b8.subtract(b11);
			b9 = b9.xor(b10).rotateRight(25); b10 = b10.subtract(b9);
			b9 = b9.xor(b0).rotateRight(16); b0 = b0.subtract(b9);
			b13 = b13.xor(b2).rotateRight(34); b2 = b2.subtract(b13);
			b11 = b11.xor(b6).rotateRight(56); b6 = b6.subtract(b11);
			b15 = b15.xor(b4).rotateRight(51); b4 = b4.subtract(b15);
			b7 = b7.xor(b10).rotateRight(4); b10 = b10.subtract(b7);
			b3 = b3.xor(b12).rotateRight(53); b12 = b12.subtract(b3);
			b5 = b5.xor(b14).rotateRight(42); b14 = b14.subtract(b5);
			b1 = b1.xor(b8).rotateRight(41); b8 = b8.subtract(b1);
			b1 = b1.xor(b0).rotateRight(41); b0 = b0.subtract(b1);
			b3 = b3.xor(b2).rotateRight(9); b2 = b2.subtract(b3);
			b5 = b5.xor(b4).rotateRight(37); b4 = b4.subtract(b5);
			b7 = b7.xor(b6).rotateRight(31); b6 = b6.subtract(b7);
			b9 = b9.xor(b8).rotateRight(12); b8 = b8.subtract(b9);
			b11 = b11.xor(b10).rotateRight(47); b10 = b10.subtract(b11);
			b13 = b13.xor(b12).rotateRight(44); b12 = b12.subtract(b13);
			b15 = b15.xor(b14).rotateRight(30); b14 = b14.subtract(b15);

			b0 = b0.subtract(this.roundKey[(r - 1) % 17]);
			b1 = b1.subtract(this.roundKey[r % 17]);
			b2 = b2.subtract(this.roundKey[(r + 1) % 17]);
			b3 = b3.subtract(this.roundKey[(r + 2) % 17]);
			b4 = b4.subtract(this.roundKey[(r + 3) % 17]);
			b5 = b5.subtract(this.roundKey[(r + 4) % 17]);
			b6 = b6.subtract(this.roundKey[(r + 5) % 17]);
			b7 = b7.subtract(this.roundKey[(r + 6) % 17]);
			b8 = b8.subtract(this.roundKey[(r + 7) % 17]);
			b9 = b9.subtract(this.roundKey[(r + 8) % 17]);
			b10 = b10.subtract(this.roundKey[(r + 9) % 17]);
			b11 = b11.subtract(this.roundKey[(r + 10) % 17]);
			b12 = b12.subtract(this.roundKey[(r + 11) % 17]);
			b13 = b13.subtract(this.roundKey[(r + 12) % 17].add(this.tweak[(r - 1) % 3]));
			b14 = b14.subtract(this.roundKey[(r + 13) % 17].add(this.tweak[r % 3]));
			b15 = b15.subtract(this.roundKey[(r + 14) % 17].add(r - 1));

			b15 = b15.xor(b0).rotateRight(5); b0 = b0.subtract(b15);
			b11 = b11.xor(b2).rotateRight(20); b2 = b2.subtract(b11);
			b13 = b13.xor(b6).rotateRight(48); b6 = b6.subtract(b13);
			b9 = b9.xor(b4).rotateRight(41); b4 = b4.subtract(b9);
			b1 = b1.xor(b14).rotateRight(47); b14 = b14.subtract(b1);
			b5 = b5.xor(b8).rotateRight(28); b8 = b8.subtract(b5);
			b3 = b3.xor(b10).rotateRight(16); b10 = b10.subtract(b3);
			b7 = b7.xor(b12).rotateRight(25); b12 = b12.subtract(b7);
			b7 = b7.xor(b0).rotateRight(33); b0 = b0.subtract(b7);
			b5 = b5.xor(b2).rotateRight(4); b2 = b2.subtract(b5);
			b3 = b3.xor(b4).rotateRight(51); b4 = b4.subtract(b3);
			b1 = b1.xor(b6).rotateRight(13); b6 = b6.subtract(b1);
			b15 = b15.xor(b12).rotateRight(34); b12 = b12.subtract(b15);
			b13 = b13.xor(b14).rotateRight(41); b14 = b14.subtract(b13);
			b11 = b11.xor(b8).rotateRight(59); b8 = b8.subtract(b11);
			b9 = b9.xor(b10).rotateRight(17); b10 = b10.subtract(b9);
			b9 = b9.xor(b0).rotateRight(38); b0 = b0.subtract(b9);
			b13 = b13.xor(b2).rotateRight(19); b2 = b2.subtract(b13);
			b11 = b11.xor(b6).rotateRight(10); b6 = b6.subtract(b11);
			b15 = b15.xor(b4).rotateRight(55); b4 = b4.subtract(b15);
			b7 = b7.xor(b10).rotateRight(49); b10 = b10.subtract(b7);
			b3 = b3.xor(b12).rotateRight(18); b12 = b12.subtract(b3);
			b5 = b5.xor(b14).rotateRight(23); b14 = b14.subtract(b5);
			b1 = b1.xor(b8).rotateRight(52); b8 = b8.subtract(b1);
			b1 = b1.xor(b0).rotateRight(24); b0 = b0.subtract(b1);
			b3 = b3.xor(b2).rotateRight(13); b2 = b2.subtract(b3);
			b5 = b5.xor(b4).rotateRight(8); b4 = b4.subtract(b5);
			b7 = b7.xor(b6).rotateRight(47); b6 = b6.subtract(b7);
			b9 = b9.xor(b8).rotateRight(8); b8 = b8.subtract(b9);
			b11 = b11.xor(b10).rotateRight(17); b10 = b10.subtract(b11);
			b13 = b13.xor(b12).rotateRight(22); b12 = b12.subtract(b13);
			b15 = b15.xor(b14).rotateRight(37); b14 = b14.subtract(b15);
		}

		b0 = b0.subtract(this.roundKey[0]);
		b1 = b1.subtract(this.roundKey[1]);
		b2 = b2.subtract(this.roundKey[2]);
		b3 = b3.subtract(this.roundKey[3]);
		b4 = b4.subtract(this.roundKey[4]);
		b5 = b5.subtract(this.roundKey[5]);
		b6 = b6.subtract(this.roundKey[6]);
		b7 = b7.subtract(this.roundKey[7]);
		b8 = b8.subtract(this.roundKey[8]);
		b9 = b9.subtract(this.roundKey[9]);
		b10 = b10.subtract(this.roundKey[10]);
		b11 = b11.subtract(this.roundKey[11]);
		b12 = b12.subtract(this.roundKey[12]);
		b13 = b13.subtract(this.roundKey[13].add(this.tweak[0]));
		b14 = b14.subtract(this.roundKey[14].add(this.tweak[1]));
		b15 = b15.subtract(this.roundKey[15]);

		var output = Buffer.alloc(input.length);

		this.storeInt64(output, 0, b0);
		this.storeInt64(output, 8, b1);
		this.storeInt64(output, 16, b2);
		this.storeInt64(output, 24, b3);
		this.storeInt64(output, 32, b4);
		this.storeInt64(output, 40, b5);
		this.storeInt64(output, 48, b6);
		this.storeInt64(output, 56, b7);
		this.storeInt64(output, 64, b8);
		this.storeInt64(output, 72, b9);
		this.storeInt64(output, 80, b10);
		this.storeInt64(output, 88, b11);
		this.storeInt64(output, 96, b12);
		this.storeInt64(output, 104, b13);
		this.storeInt64(output, 112, b14);
		this.storeInt64(output, 120, b15);

		return output;
	}
}



/*
 * ---------
 * Constants
 * ---------
 */

jCastle.algorithm.threefish.SCHEDULE_CONST = new INT64(0x1BD11BDA, 0xA9FC1A22);
jCastle.algorithm.threefish.MAX_ROUNDS = 80;
jCastle.algorithm.threefish.TWEAK_SIZE = 16;



jCastle._algorithmInfo['threefish-256'] = {
	algorithm_type: 'crypt',
	block_size: 32,
	key_size: 32,
	min_key_size: 32,
	max_key_size: 32,
	padding: 'zeros',
	object_name: 'threefish',
	rounds: 72
};

jCastle._algorithmInfo['threefish-512'] = {
	algorithm_type: 'crypt',
	block_size: 64,
	key_size: 64,
	min_key_size: 64,
	max_key_size: 64,
	padding: 'zeros',
	object_name: 'threefish',
	rounds: 72
};

jCastle._algorithmInfo['threefish-1024'] = {
	algorithm_type: 'crypt',
	block_size: 128,
	key_size: 128,
	min_key_size: 128,
	max_key_size: 128,
	padding: 'zeros',
	object_name: 'threefish',
	rounds: 80
};

module.exports = jCastle.algorithm.threefish;