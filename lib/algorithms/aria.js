/**
 * Javascript jCastle Mcrypt Module - Aria 
 * 
 * @author Jacob Lee
 *
 * Copyright (C) 2015-2021 Jacob Lee.
 */

var jCastle = require('../jCastle');
require('../util');

// https://tools.ietf.org/html/draft-ietf-avtcore-aria-srtp-02
// https://datatracker.ietf.org/doc/html/rfc5794

jCastle.algorithm.aria = class
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
        this.keyBits = 0;
        this.rounds = 0;
        this.masterKey = null;
        this.encRoundKeys = null;
        this.decRoundKeys = null;
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
	 * @public
	 * @returns this class instance.
	 */
	reset()
	{
		this.keyBits = 0;
		this.rounds = 0;
		this.masterKey = null;
		this.encRoundKeys = null;
		this.decRoundKeys = null;

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
	 * @returns this class instance.
	 */
	keySchedule(key, isEncryption)
	{
		this.masterKey = Buffer.from(key, 'latin1');

		var size = this.masterKey.length * 8;
		
		if (size <= 128) {
			this.setKeyBits(128);
		} else if (size <=192) {
			this.setKeyBits(192);
		} else {
			this.setKeyBits(256);
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
	 * sets key bits and the number of rounds.
	 * 
	 * @private
	 * @param {number} keyBits bits number of the key
	 */
	setKeyBits(keyBits)
	{
		if (keyBits != 128 && keyBits != 192 && keyBits != 256) {
			throw jCastle.exception("INVALID_KEYSIZE", 'ARIA001');
		}
		this.keyBits = keyBits;
		
		switch (keyBits) {
			case 128:
				this.rounds = 12;
				break;
			case 192:
				this.rounds = 14;
				break;
			case 256:
				this.rounds = 16;
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
		this.encRoundKeys = new Array(4 * (this.rounds + 1));
		this.setupEncRoundKeys(key);	
		
		this.decRoundKeys = this.encRoundKeys.slice(0);
		this.setupDecRoundKeys(key);
	}

	/**
	 * crypt the block sized data.
	 * 
	 * @public
	 * @param {boolean} direction true if it is encryption, otherwise false.
	 * @param {buffer} input input data to be crypted.
	 * @returns the crypted data in buffer.
	 */
	cryptBlock(direction, input)
	{
		var rk = direction ? this.encRoundKeys : this.decRoundKeys;
		var t0, t1, t2, t3, j = 0;
		var rounds = this.rounds;
		var byte = jCastle.util.byte;
		var output = Buffer.alloc(input.length);
		
		var ts1 = jCastle.algorithm.aria.ts1;
		var ts2 = jCastle.algorithm.aria.ts2;
		var tx1 = jCastle.algorithm.aria.tx1;
		var tx2 = jCastle.algorithm.aria.tx2;
		var x1 = jCastle.algorithm.aria.x1;
		var x2 = jCastle.algorithm.aria.x2;
		var s1 = jCastle.algorithm.aria.s1;
		var s2 = jCastle.algorithm.aria.s2;

		t0 = input.readInt32BE(0);
		t1 = input.readInt32BE(4);
		t2 = input.readInt32BE(8);
		t3 = input.readInt32BE(12);

		for (var r = 1; r < rounds / 2; r++) { // 2 rounds
			t0 ^= rk[j++]; t1 ^= rk[j++]; t2 ^= rk[j++]; t3 ^= rk[j++];
			t0 = ts1[byte(t0, 3)] ^ ts2[byte(t0, 2)] ^ tx1[byte(t0, 1)] ^ tx2[byte(t0, 0)];
			t1 = ts1[byte(t1, 3)] ^ ts2[byte(t1, 2)] ^ tx1[byte(t1, 1)] ^ tx2[byte(t1, 0)];
			t2 = ts1[byte(t2, 3)] ^ ts2[byte(t2, 2)] ^ tx1[byte(t2, 1)] ^ tx2[byte(t2, 0)];
			t3 = ts1[byte(t3, 3)] ^ ts2[byte(t3, 2)] ^ tx1[byte(t3, 1)] ^ tx2[byte(t3, 0)];         
			t1 ^= t2; t2 ^= t3; t0 ^= t1; t3 ^= t1; t2 ^= t0; t1 ^= t2;
			t1 = this.badc(t1); t2 = this.cdab(t2); t3 = this.dcba(t3);
			t1 ^= t2; t2 ^= t3; t0 ^= t1; t3 ^= t1; t2 ^= t0; t1 ^= t2;
			
			t0 ^= rk[j++]; t1 ^= rk[j++]; t2 ^= rk[j++]; t3 ^= rk[j++];
			t0 = tx1[byte(t0, 3)] ^ tx2[byte(t0, 2)] ^ ts1[byte(t0, 1)] ^ ts2[byte(t0, 0)];
			t1 = tx1[byte(t1, 3)] ^ tx2[byte(t1, 2)] ^ ts1[byte(t1, 1)] ^ ts2[byte(t1, 0)];
			t2 = tx1[byte(t2, 3)] ^ tx2[byte(t2, 2)] ^ ts1[byte(t2, 1)] ^ ts2[byte(t2, 0)];
			t3 = tx1[byte(t3, 3)] ^ tx2[byte(t3, 2)] ^ ts1[byte(t3, 1)] ^ ts2[byte(t3, 0)];  
			t1 ^= t2; t2 ^= t3; t0 ^= t1; t3 ^= t1; t2 ^= t0; t1 ^= t2;
			t3 = this.badc(t3); t0 = this.cdab(t0); t1 = this.dcba(t1);        
			t1 ^= t2; t2 ^= t3; t0 ^= t1; t3 ^= t1; t2 ^= t0; t1 ^= t2;
		}
		t0 ^= rk[j++]; t1 ^= rk[j++]; t2 ^= rk[j++]; t3 ^= rk[j++];
		t0 = ts1[byte(t0, 3)] ^ ts2[byte(t0, 2)] ^ tx1[byte(t0, 1)] ^ tx2[byte(t0, 0)];
		t1 = ts1[byte(t1, 3)] ^ ts2[byte(t1, 2)] ^ tx1[byte(t1, 1)] ^ tx2[byte(t1, 0)];
		t2 = ts1[byte(t2, 3)] ^ ts2[byte(t2, 2)] ^ tx1[byte(t2, 1)] ^ tx2[byte(t2, 0)];
		t3 = ts1[byte(t3, 3)] ^ ts2[byte(t3, 2)] ^ tx1[byte(t3, 1)] ^ tx2[byte(t3, 0)];
		t1 ^= t2; t2 ^= t3; t0 ^= t1; t3 ^= t1; t2 ^= t0; t1 ^= t2;
		t1 = this.badc(t1); t2 = this.cdab(t2); t3 = this.dcba(t3);
		t1 ^= t2; t2 ^= t3; t0 ^= t1; t3 ^= t1; t2 ^= t0; t1 ^= t2;
		
		// last round
		t0 ^= rk[j++]; t1 ^= rk[j++]; t2 ^= rk[j++]; t3 ^= rk[j++];
		output[ 0] = (x1[0xff & (t0 >>> 24)] ^ (rk[j  ] >>> 24)) & 0xFF;
		output[ 1] = (x2[0xff & (t0 >>> 16)] ^ (rk[j  ] >>> 16)) & 0xFF;
		output[ 2] = (s1[0xff & (t0 >>>  8)] ^ (rk[j  ] >>>  8)) & 0xFF;
		output[ 3] = (s2[0xff & (t0       )] ^ (rk[j  ]       )) & 0xFF;
		output[ 4] = (x1[0xff & (t1 >>> 24)] ^ (rk[j+1] >>> 24)) & 0xFF;
		output[ 5] = (x2[0xff & (t1 >>> 16)] ^ (rk[j+1] >>> 16)) & 0xFF;
		output[ 6] = (s1[0xff & (t1 >>>  8)] ^ (rk[j+1] >>>  8)) & 0xFF;
		output[ 7] = (s2[0xff & (t1       )] ^ (rk[j+1]       )) & 0xFF;
		output[ 8] = (x1[0xff & (t2 >>> 24)] ^ (rk[j+2] >>> 24)) & 0xFF;
		output[ 9] = (x2[0xff & (t2 >>> 16)] ^ (rk[j+2] >>> 16)) & 0xFF;
		output[10] = (s1[0xff & (t2 >>>  8)] ^ (rk[j+2] >>>  8)) & 0xFF;
		output[11] = (s2[0xff & (t2       )] ^ (rk[j+2]       )) & 0xFF;
		output[12] = (x1[0xff & (t3 >>> 24)] ^ (rk[j+3] >>> 24)) & 0xFF;
		output[13] = (x2[0xff & (t3 >>> 16)] ^ (rk[j+3] >>> 16)) & 0xFF;
		output[14] = (s1[0xff & (t3 >>>  8)] ^ (rk[j+3] >>>  8)) & 0xFF;
		output[15] = (s2[0xff & (t3       )] ^ (rk[j+3]       )) & 0xFF;
		
		return output;
	}


	setupEncRoundKeys(key)
	{
		var keyBits = this.keyBits, byte = jCastle.util.byte;	
		var t0, t1, t2, t3, q, j=0;
		var w0 = new Array(4);
		var w1 = new Array(4);
		var w2 = new Array(4);
		var w3 = new Array(4);
		
		var ts1 = jCastle.algorithm.aria.ts1;
		var ts2 = jCastle.algorithm.aria.ts2;
		var tx1 = jCastle.algorithm.aria.tx1;
		var tx2 = jCastle.algorithm.aria.tx2;
		var krk = jCastle.algorithm.aria.krk;

		for (var i = 0; i < 4; i++) {
			w0[i] = key.readInt32BE(i * 4);
		}

		q = (keyBits - 128) / 64;
		t0 = w0[0] ^ krk[q][0];
		t1 = w0[1] ^ krk[q][1];
		t2 = w0[2] ^ krk[q][2];
		t3 = w0[3] ^ krk[q][3];  
		t0 = ts1[byte(t0, 3)] ^ ts2[byte(t0, 2)] ^ tx1[byte(t0, 1)] ^ tx2[byte(t0, 0)];
		t1 = ts1[byte(t1, 3)] ^ ts2[byte(t1, 2)] ^ tx1[byte(t1, 1)] ^ tx2[byte(t1, 0)];
		t2 = ts1[byte(t2, 3)] ^ ts2[byte(t2, 2)] ^ tx1[byte(t2, 1)] ^ tx2[byte(t2, 0)];
		t3 = ts1[byte(t3, 3)] ^ ts2[byte(t3, 2)] ^ tx1[byte(t3, 1)] ^ tx2[byte(t3, 0)];   
		t1 ^= t2; t2 ^= t3; t0 ^= t1; t3 ^= t1; t2 ^= t0; t1 ^= t2;
		t1 = this.badc(t1); t2 = this.cdab(t2); t3 = this.dcba(t3);
		t1 ^= t2; t2 ^= t3; t0 ^= t1; t3 ^= t1; t2 ^= t0; t1 ^= t2;
		
		if (keyBits > 128) {
			w1[0] = key.readInt32BE(16);
			w1[1] = key.readInt32BE(20);
			if (keyBits > 192) {
				w1[2] = key.readInt32BE(24);
				w1[3] = key.readInt32BE(28);
			} else {
				w1[2] = w1[3] = 0;
			}
		} else {
			w1[0] = w1[1] = w1[2] = w1[3] = 0;
		}
		w1[0] ^= t0; w1[1] ^= t1; w1[2] ^= t2; w1[3] ^= t3;
		t0 = w1[0];  t1 = w1[1];  t2 = w1[2];  t3 = w1[3];
		
		q = (q == 2 )? 0 : (q + 1);
		t0 ^= krk[q][0]; t1 ^= krk[q][1]; t2 ^= krk[q][2]; t3 ^= krk[q][3];
		t0 = tx1[byte(t0, 3)] ^ tx2[byte(t0, 2)] ^ ts1[byte(t0, 1)] ^ ts2[byte(t0, 0)];
		t1 = tx1[byte(t1, 3)] ^ tx2[byte(t1, 2)] ^ ts1[byte(t1, 1)] ^ ts2[byte(t1, 0)];
		t2 = tx1[byte(t2, 3)] ^ tx2[byte(t2, 2)] ^ ts1[byte(t2, 1)] ^ ts2[byte(t2, 0)];
		t3 = tx1[byte(t3, 3)] ^ tx2[byte(t3, 2)] ^ ts1[byte(t3, 1)] ^ ts2[byte(t3, 0)]; 
		t1 ^= t2; t2 ^= t3; t0 ^= t1; t3 ^= t1; t2 ^= t0; t1 ^= t2;
		t3 = this.badc(t3); t0 = this.cdab(t0); t1 = this.dcba(t1);        
		t1 ^= t2; t2 ^= t3; t0 ^= t1; t3 ^= t1; t2 ^= t0; t1 ^= t2;
		t0 ^= w0[0]; t1 ^= w0[1]; t2 ^= w0[2]; t3 ^= w0[3];
		w2[0] = t0; w2[1] = t1; w2[2] = t2; w2[3] = t3;
		
		q = (q == 2)? 0 : (q + 1);
		t0 ^= krk[q][0]; t1 ^= krk[q][1]; t2 ^= krk[q][2]; t3 ^= krk[q][3];
		t0 = ts1[byte(t0, 3)] ^ ts2[byte(t0, 2)] ^ tx1[byte(t0, 1)] ^ tx2[byte(t0, 0)];
		t1 = ts1[byte(t1, 3)] ^ ts2[byte(t1, 2)] ^ tx1[byte(t1, 1)] ^ tx2[byte(t1, 0)];
		t2 = ts1[byte(t2, 3)] ^ ts2[byte(t2, 2)] ^ tx1[byte(t2, 1)] ^ tx2[byte(t2, 0)];
		t3 = ts1[byte(t3, 3)] ^ ts2[byte(t3, 2)] ^ tx1[byte(t3, 1)] ^ tx2[byte(t3, 0)];   
		t1 ^= t2; t2 ^= t3; t0 ^= t1; t3 ^= t1; t2 ^= t0; t1 ^= t2;
		t1 = this.badc(t1); t2 = this.cdab(t2); t3 = this.dcba(t3);
		t1 ^= t2; t2 ^= t3; t0 ^= t1; t3 ^= t1; t2 ^= t0; t1 ^= t2;
		w3[0] = t0 ^ w1[0]; w3[1] = t1 ^ w1[1]; w3[2] = t2 ^ w1[2]; w3[3] = t3 ^ w1[3];
		
		this.gsrk(w0, w1, 19,this.encRoundKeys, j); j += 4;
		this.gsrk(w1, w2, 19,this.encRoundKeys, j); j += 4;
		this.gsrk(w2, w3, 19,this.encRoundKeys, j); j += 4;
		this.gsrk(w3, w0, 19,this.encRoundKeys, j); j += 4;
		this.gsrk(w0, w1, 31,this.encRoundKeys, j); j += 4;
		this.gsrk(w1, w2, 31,this.encRoundKeys, j); j += 4;
		this.gsrk(w2, w3, 31,this.encRoundKeys, j); j += 4;
		this.gsrk(w3, w0, 31,this.encRoundKeys, j); j += 4;
		this.gsrk(w0, w1, 67,this.encRoundKeys, j); j += 4;
		this.gsrk(w1, w2, 67,this.encRoundKeys, j); j += 4;
		this.gsrk(w2, w3, 67,this.encRoundKeys, j); j += 4;
		this.gsrk(w3, w0, 67,this.encRoundKeys, j); j += 4;
		this.gsrk(w0, w1, 97,this.encRoundKeys, j); j += 4;
		if (keyBits > 128) {  
			this.gsrk(w1, w2, 97,this.encRoundKeys, j); j += 4;
			this.gsrk(w2, w3, 97,this.encRoundKeys, j); j += 4;
		}
		if (keyBits > 192) {
			this.gsrk(w3, w0,  97,this.encRoundKeys, j); j += 4;
			this.gsrk(w0, w1, 109,this.encRoundKeys, j);
		}
	}
	  

	setupDecRoundKeys(key)
	{
		var keyBits = this.keyBits;
		var a = 0, z;
		var t = new Array(4);
		
		z = 32 + keyBits / 8;
		this.swapBlocks(this.decRoundKeys, 0, z);
		a += 4;
		z -= 4;
		
		for ( ; a < z; a += 4, z -= 4) {
			this.swapAndDiffuse(this.decRoundKeys, a, z, t);
		}
		this.diffuse(this.decRoundKeys, a, t, 0);
		this.decRoundKeys[a] = t[0];
		this.decRoundKeys[a+1] = t[1];
		this.decRoundKeys[a+2] = t[2];
		this.decRoundKeys[a+3] = t[3];
	}	  

	matrix(t)
	{
		return 0x00010101 * ((t >>> 24) & 0xff) ^ 0x01000101 * ((t >>> 16) & 0xff) ^ 0x01010001 * ((t >>> 8) & 0xff) ^ 0x01010100 * (t & 0xff);
	}
	  
	badc(t)
	{
		return ((t << 8) & 0xff00ff00) | ((t >>> 8) & 0x00ff00ff);
	}
	  
	cdab(t)
	{
		return ((t << 16) & 0xffff0000) | ((t >>> 16) & 0x0000ffff);
	}
	  
	dcba(t)
	{
		return (t & 0x000000ff) << 24 | (t & 0x0000ff00) << 8 | (t & 0x00ff0000) >>> 8 | (t & 0xff000000) >>> 24;
	}
	  
	gsrk(x, y, rot, rk, offset)
	{
		var q = 4 - Math.floor(rot / 32), r = rot % 32, s = 32 - r;
		
		rk[offset]   = x[0] ^ y[(q  )%4] >>> r ^ y[(q+3)%4] << s;
		rk[offset+1] = x[1] ^ y[(q+1)%4] >>> r ^ y[(q  )%4] << s;
		rk[offset+2] = x[2] ^ y[(q+2)%4] >>> r ^ y[(q+1)%4] << s;
		rk[offset+3] = x[3] ^ y[(q+3)%4] >>> r ^ y[(q+2)%4] << s;
	}
	  
	diffuse(i, offset1, o, offset2)
	{
		var t0, t1, t2, t3;
		  
		t0 = this.matrix(i[offset1]); t1 = this.matrix(i[offset1+1]); t2 = this.matrix(i[offset1+2]); t3 = this.matrix(i[offset1+3]);         
		t1 ^= t2; t2 ^= t3; t0 ^= t1; t3 ^= t1; t2 ^= t0; t1 ^= t2;
		t1 = this.badc(t1); t2 = this.cdab(t2); t3 = this.dcba(t3);
		t1 ^= t2; t2 ^= t3; t0 ^= t1; t3 ^= t1; t2 ^= t0; t1 ^= t2;
		o[offset2] = t0; o[offset2+1] = t1; o[offset2+2] = t2; o[offset2+3] = t3;
	}
	  
	swapBlocks(arr, offset1, offset2)
	{
		var t;
		
		for (var i = 0; i < 4; i++) {
			t = arr[offset1+i];
			arr[offset1+i] = arr[offset2+i];
			arr[offset2+i] = t;
		}
	}
	  
	swapAndDiffuse(arr, offset1, offset2, tmp)
	{
		this.diffuse(arr, offset1, tmp, 0);
		this.diffuse(arr, offset2, arr, offset1);
		arr[offset2] = tmp[0]; arr[offset2+1] = tmp[1]; 
		arr[offset2+2] = tmp[2]; arr[offset2+3] = tmp[3];
	}
}




/*
 * ---------
 * Constants
 * ---------
 */

jCastle.algorithm.aria.krk = [
	[0x517cc1b7, 0x27220a94, 0xfe13abe8, 0xfa9a6ee0],
	[0x6db14acc, 0x9e21c820, 0xff28b1d5, 0xef5de2b0],
	[0xdb92371d, 0x2126e970, 0x03249775, 0x04e8c90e]
];



// S-box type 1
jCastle.algorithm.aria.s1 = [
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16];

// S-box type 2
jCastle.algorithm.aria.s2 = [
  0xe2, 0x4e, 0x54, 0xfc, 0x94, 0xc2, 0x4a, 0xcc, 0x62, 0x0d, 0x6a, 0x46, 0x3c, 0x4d, 0x8b, 0xd1,
  0x5e, 0xfa, 0x64, 0xcb, 0xb4, 0x97, 0xbe, 0x2b, 0xbc, 0x77, 0x2e, 0x03, 0xd3, 0x19, 0x59, 0xc1,
  0x1d, 0x06, 0x41, 0x6b, 0x55, 0xf0, 0x99, 0x69, 0xea, 0x9c, 0x18, 0xae, 0x63, 0xdf, 0xe7, 0xbb,
  0x00, 0x73, 0x66, 0xfb, 0x96, 0x4c, 0x85, 0xe4, 0x3a, 0x09, 0x45, 0xaa, 0x0f, 0xee, 0x10, 0xeb,
  0x2d, 0x7f, 0xf4, 0x29, 0xac, 0xcf, 0xad, 0x91, 0x8d, 0x78, 0xc8, 0x95, 0xf9, 0x2f, 0xce, 0xcd,
  0x08, 0x7a, 0x88, 0x38, 0x5c, 0x83, 0x2a, 0x28, 0x47, 0xdb, 0xb8, 0xc7, 0x93, 0xa4, 0x12, 0x53,
  0xff, 0x87, 0x0e, 0x31, 0x36, 0x21, 0x58, 0x48, 0x01, 0x8e, 0x37, 0x74, 0x32, 0xca, 0xe9, 0xb1,
  0xb7, 0xab, 0x0c, 0xd7, 0xc4, 0x56, 0x42, 0x26, 0x07, 0x98, 0x60, 0xd9, 0xb6, 0xb9, 0x11, 0x40,
  0xec, 0x20, 0x8c, 0xbd, 0xa0, 0xc9, 0x84, 0x04, 0x49, 0x23, 0xf1, 0x4f, 0x50, 0x1f, 0x13, 0xdc,
  0xd8, 0xc0, 0x9e, 0x57, 0xe3, 0xc3, 0x7b, 0x65, 0x3b, 0x02, 0x8f, 0x3e, 0xe8, 0x25, 0x92, 0xe5,
  0x15, 0xdd, 0xfd, 0x17, 0xa9, 0xbf, 0xd4, 0x9a, 0x7e, 0xc5, 0x39, 0x67, 0xfe, 0x76, 0x9d, 0x43,
  0xa7, 0xe1, 0xd0, 0xf5, 0x68, 0xf2, 0x1b, 0x34, 0x70, 0x05, 0xa3, 0x8a, 0xd5, 0x79, 0x86, 0xa8,
  0x30, 0xc6, 0x51, 0x4b, 0x1e, 0xa6, 0x27, 0xf6, 0x35, 0xd2, 0x6e, 0x24, 0x16, 0x82, 0x5f, 0xda,
  0xe6, 0x75, 0xa2, 0xef, 0x2c, 0xb2, 0x1c, 0x9f, 0x5d, 0x6f, 0x80, 0x0a, 0x72, 0x44, 0x9b, 0x6c,
  0x90, 0x0b, 0x5b, 0x33, 0x7d, 0x5a, 0x52, 0xf3, 0x61, 0xa1, 0xf7, 0xb0, 0xd6, 0x3f, 0x7c, 0x6d,
  0xed, 0x14, 0xe0, 0xa5, 0x3d, 0x22, 0xb3, 0xf8, 0x89, 0xde, 0x71, 0x1a, 0xaf, 0xba, 0xb5, 0x81];

// inverse of S-box type 1
jCastle.algorithm.aria.x1 = [
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d];

// inverse of S-box type 2
jCastle.algorithm.aria.x2 = [
  0x30, 0x68, 0x99, 0x1b, 0x87, 0xb9, 0x21, 0x78, 0x50, 0x39, 0xdb, 0xe1, 0x72, 0x09, 0x62, 0x3c,
  0x3e, 0x7e, 0x5e, 0x8e, 0xf1, 0xa0, 0xcc, 0xa3, 0x2a, 0x1d, 0xfb, 0xb6, 0xd6, 0x20, 0xc4, 0x8d,
  0x81, 0x65, 0xf5, 0x89, 0xcb, 0x9d, 0x77, 0xc6, 0x57, 0x43, 0x56, 0x17, 0xd4, 0x40, 0x1a, 0x4d,
  0xc0, 0x63, 0x6c, 0xe3, 0xb7, 0xc8, 0x64, 0x6a, 0x53, 0xaa, 0x38, 0x98, 0x0c, 0xf4, 0x9b, 0xed,
  0x7f, 0x22, 0x76, 0xaf, 0xdd, 0x3a, 0x0b, 0x58, 0x67, 0x88, 0x06, 0xc3, 0x35, 0x0d, 0x01, 0x8b,
  0x8c, 0xc2, 0xe6, 0x5f, 0x02, 0x24, 0x75, 0x93, 0x66, 0x1e, 0xe5, 0xe2, 0x54, 0xd8, 0x10, 0xce,
  0x7a, 0xe8, 0x08, 0x2c, 0x12, 0x97, 0x32, 0xab, 0xb4, 0x27, 0x0a, 0x23, 0xdf, 0xef, 0xca, 0xd9,
  0xb8, 0xfa, 0xdc, 0x31, 0x6b, 0xd1, 0xad, 0x19, 0x49, 0xbd, 0x51, 0x96, 0xee, 0xe4, 0xa8, 0x41,
  0xda, 0xff, 0xcd, 0x55, 0x86, 0x36, 0xbe, 0x61, 0x52, 0xf8, 0xbb, 0x0e, 0x82, 0x48, 0x69, 0x9a,
  0xe0, 0x47, 0x9e, 0x5c, 0x04, 0x4b, 0x34, 0x15, 0x79, 0x26, 0xa7, 0xde, 0x29, 0xae, 0x92, 0xd7,
  0x84, 0xe9, 0xd2, 0xba, 0x5d, 0xf3, 0xc5, 0xb0, 0xbf, 0xa4, 0x3b, 0x71, 0x44, 0x46, 0x2b, 0xfc,
  0xeb, 0x6f, 0xd5, 0xf6, 0x14, 0xfe, 0x7c, 0x70, 0x5a, 0x7d, 0xfd, 0x2f, 0x18, 0x83, 0x16, 0xa5,
  0x91, 0x1f, 0x05, 0x95, 0x74, 0xa9, 0xc1, 0x5b, 0x4a, 0x85, 0x6d, 0x13, 0x07, 0x4f, 0x4e, 0x45,
  0xb2, 0x0f, 0xc9, 0x1c, 0xa6, 0xbc, 0xec, 0x73, 0x90, 0x7b, 0xcf, 0x59, 0x8f, 0xa1, 0xf9, 0x2d,
  0xf2, 0xb1, 0x00, 0x94, 0x37, 0x9f, 0xd0, 0x2e, 0x9c, 0x6e, 0x28, 0x3f, 0x80, 0xf0, 0x3d, 0xd3,
  0x25, 0x8a, 0xb5, 0xe7, 0x42, 0xb3, 0xc7, 0xea, 0xf7, 0x4c, 0x11, 0x33, 0x03, 0xa2, 0xac, 0x60];


jCastle.algorithm.aria.ts1 = new Array(256);
jCastle.algorithm.aria.ts2 = new Array(256);
jCastle.algorithm.aria.tx1 = new Array(256);
jCastle.algorithm.aria.tx2 = new Array(256);

for (var i = 0; i < 256; i++) {
	jCastle.algorithm.aria.ts1[i] = 0x00010101 * (jCastle.algorithm.aria.s1[i] & 0xff);
	jCastle.algorithm.aria.ts2[i] = 0x01000101 * (jCastle.algorithm.aria.s2[i] & 0xff);
	jCastle.algorithm.aria.tx1[i] = 0x01010001 * (jCastle.algorithm.aria.x1[i] & 0xff);
	jCastle.algorithm.aria.tx2[i] = 0x01010100 * (jCastle.algorithm.aria.x2[i] & 0xff);
}


jCastle._algorithmInfo['aria'] = {
	algorithm_type: 'crypt',
	block_size: 16,
	key_size: 32,
	min_key_size: 16,
	max_key_size: 32,
	key_sizes: [16, 24, 32],
	padding: 'ansix923',
	object_name: 'aria'
};

jCastle._algorithmInfo['aria-128'] = {
	algorithm_type: 'crypt',
	block_size: 16,
	key_size: 16,
	min_key_size: 16,
	max_key_size: 16,
	key_sizes: 16,
	padding: 'ansix923',
	object_name: 'aria'
};

jCastle._algorithmInfo['aria-192'] = {
	algorithm_type: 'crypt',
	block_size: 16,
	key_size: 24,
	min_key_size: 24,
	max_key_size: 24,
	key_sizes: 24,
	padding: 'ansix923',
	object_name: 'aria'
};

jCastle._algorithmInfo['aria-256'] = {
	algorithm_type: 'crypt',
	block_size: 16,
	key_size: 32,
	min_key_size: 32,
	max_key_size: 32,
	key_sizes: 32,
	padding: 'ansix923',
	object_name: 'aria'
};

module.exports = jCastle.algorithm.aria;