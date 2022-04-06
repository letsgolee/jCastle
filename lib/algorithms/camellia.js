/**
 * Javascript jCastle Mcrypt Module - Camellia 
 * 
 * @author Jacob Lee
 *
 * Copyright (C) 2015-2021 Jacob Lee.
 */

var jCastle = require('../jCastle');
require('../util');

jCastle.algorithm.camellia = class
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
        this.keyBits = null;
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
		this.masterKey = null;
		this.roundKey = null;
		this.keyBits = null;
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
		var i;
		var output = Buffer.alloc(input.length);
		var keyBits = this.keyBits;

		this.xorBlock(input, 0, this.roundKey, 0, output , 0);

		for (i = 0; i < 3; i++) {
			this.feistel(output, 0, this.roundKey, 16 + (i << 4), output, 8);
			this.feistel(output, 8, this.roundKey, 24 + (i << 4), output, 0);
		}

		this.fLayer(output, this.roundKey, 64, this.roundKey, 72);

		for (i = 0; i < 3; i++) {
			this.feistel(output, 0, this.roundKey, 80 + (i << 4), output, 8);
			this.feistel(output, 8, this.roundKey, 88 + (i << 4), output, 0);
		}

		this.fLayer(output, this.roundKey, 128, this.roundKey, 136);

		for (i = 0; i < 3; i++) {
			this.feistel(output, 0, this.roundKey, 144 + (i << 4), output, 8);
			this.feistel(output, 8, this.roundKey, 152 + (i << 4), output, 0);
		}

		if (keyBits == 128) {
			this.swapHalf(output );
			this.xorBlock(output, 0, this.roundKey, 192, output, 0);
		} else {
			this.fLayer(output, this.roundKey, 192, this.roundKey, 200);

			for (i = 0; i < 3; i++) {
				this.feistel(output, 0, this.roundKey, 208 + (i << 4), output, 8);
				this.feistel(output, 8, this.roundKey, 216 + (i << 4), output, 0);
			}

			this.swapHalf(output);
			this.xorBlock(output, 0, this.roundKey, 256, output, 0);
		}
		
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
		var i;
		var output = Buffer.alloc(input.length);
		var keyBits = this.keyBits;

		if(keyBits == 128) {
			this.xorBlock(input, 0,  this.roundKey, 192, output, 0);
		} else {
			this.xorBlock(input, 0, this.roundKey, 256, output, 0);

			for( i = 2; i >= 0; i--) {
				this.feistel(output, 0, this.roundKey, 216 + (i << 4), output, 8);
				this.feistel(output, 8, this.roundKey, 208 + (i << 4), output, 0);
			}

			this.fLayer(output, this.roundKey, 200, this.roundKey, 192 );
		}

		for(i = 2; i >= 0; i--) {
			this.feistel(output, 0, this.roundKey, 152 + (i << 4), output, 8);
			this.feistel(output, 8, this.roundKey, 144 + (i << 4), output, 0);
		}

		this.fLayer(output, this.roundKey, 136, this.roundKey, 128);

		for(i = 2; i >= 0; i--) {
			this.feistel(output, 0, this.roundKey, 88 + (i << 4), output, 8);
			this.feistel(output, 8, this.roundKey, 80 + (i << 4), output, 0);
		}

		this.fLayer(output, this.roundKey, 72, this.roundKey, 64);

		for(i = 2; i >= 0; i--) {
			this.feistel(output, 0, this.roundKey, 24 + (i << 4), output, 8);
			this.feistel(output, 8, this.roundKey, 16 + (i << 4), output, 0);
		}

		this.swapHalf(output);
		this.xorBlock(output, 0, this.roundKey, 0, output, 0);
		
		return output;
	}




/*
 * -----------------
 * Private functions
 * -----------------
 */


	sbox1(n)
	{
		return jCastle.algorithm.camellia.sbox[n];
	}

	sbox2(n)
	{
		return ((jCastle.algorithm.camellia.sbox[n] >>> 7) ^ jCastle.algorithm.camellia.sbox[n] << 1) & 0xff;
	}

	sbox3(n)
	{
		return ((jCastle.algorithm.camellia.sbox[n] >>> 1) ^ jCastle.algorithm.camellia.sbox[n] << 7) & 0xff;
	}

	sbox4(n)
	{
		return jCastle.algorithm.camellia.sbox[((n << 1) ^ (n >>> 7)) & 0xff];
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
		var t = new Array(64); // byte array
		var u = new Array(20); // word array
		var i;
		
		this.roundKey = [];
		
		var keyBits = key.length * 8;
		
		var sigma = jCastle.algorithm.camellia.sigma;

		if (keyBits == 128) {
			for (i = 0 ; i < 16; i++) t[i] = key[i];
			for (i = 16; i < 32; i++) t[i] = 0;
		} else if (keyBits == 192) {
			for (i = 0 ; i < 24; i++) t[i] = key[i];
			for (i = 24; i < 32; i++) t[i] = key[i - 8] ^ 0xff;
		} else if (keyBits == 256) {
			for (i = 0 ; i < 32; i++ ) t[i] = key[i];
		}

		this.xorBlock(t, 0, t, 16, t, 32);
		
		this.feistel(t, 32, sigma, 0, t, 40);
		
		this.feistel(t ,40, sigma ,8, t, 32);

		this.xorBlock( t, 32, t, 0, t, 32 );

		this.feistel(t, 32, sigma, 16, t, 40);
		this.feistel(t ,40, sigma, 24, t, 32);
		
		this.bytesToWord(t, 0, u, 0);
		this.bytesToWord(t, 32, u, 4);

		if (keyBits == 128) {
			for (i = 0; i < 26; i += 2) {
				this.rotBlock(u, jCastle.algorithm.camellia.kidx1[i + 0], jCastle.algorithm.camellia.ksft1[i + 0], u, 16);
				this.rotBlock(u, jCastle.algorithm.camellia.kidx1[i + 1], jCastle.algorithm.camellia.ksft1[i + 1], u, 18);
				this.wordToBytes(u, 16, this.roundKey, i << 3);
			}

		} else {
			this.xorBlock(t, 32, t, 16, t, 48);

			this.feistel( t, 48, sigma, 32, t, 56);
			this.feistel( t, 56, sigma, 40, t, 48);

			this.bytesToWord( t, 16, u, 8  );
			this.bytesToWord( t, 48, u, 12 );

			for( i = 0; i < 34; i += 2 ){
				this.rotBlock(u, jCastle.algorithm.camellia.kidx2[i + 0], jCastle.algorithm.camellia.ksft2[i + 0], u, 16);
				this.rotBlock(u, jCastle.algorithm.camellia.kidx2[i + 1], jCastle.algorithm.camellia.ksft2[i + 1], u, 18);
				this.wordToBytes(u, 16, this.roundKey, i << 3);
			}
		}

		this.keyBits = keyBits;
	}

	feistel(x, _x, k, _k, y, _y)
	{
		var t = new Array(8);

		t[0] = this.sbox1(x[_x + 0] ^ k[_k + 0]);
		t[1] = this.sbox2(x[_x + 1] ^ k[_k + 1]);
		t[2] = this.sbox3(x[_x + 2] ^ k[_k + 2]);
		t[3] = this.sbox4(x[_x + 3] ^ k[_k + 3]);
		t[4] = this.sbox2(x[_x + 4] ^ k[_k + 4]);
		t[5] = this.sbox3(x[_x + 5] ^ k[_k + 5]);
		t[6] = this.sbox4(x[_x + 6] ^ k[_k + 6]);
		t[7] = this.sbox1(x[_x + 7] ^ k[_k + 7]);

		y[_y+0] ^= t[0] ^ t[2] ^ t[3] ^ t[5] ^ t[6] ^ t[7];
		y[_y+1] ^= t[0] ^ t[1] ^ t[3] ^ t[4] ^ t[6] ^ t[7];
		y[_y+2] ^= t[0] ^ t[1] ^ t[2] ^ t[4] ^ t[5] ^ t[7];
		y[_y+3] ^= t[1] ^ t[2] ^ t[3] ^ t[4] ^ t[5] ^ t[6];
		y[_y+4] ^= t[0] ^ t[1] ^ t[5] ^ t[6] ^ t[7];
		y[_y+5] ^= t[1] ^ t[2] ^ t[4] ^ t[6] ^ t[7];
		y[_y+6] ^= t[2] ^ t[3] ^ t[4] ^ t[5] ^ t[7];
		y[_y+7] ^= t[0] ^ t[3] ^ t[4] ^ t[5] ^ t[6];
	}

	fLayer(x, kl, _kl, kr, _kr)
	{
		var t = new Array(4), u = new Array(4), v = new Array(4);

		this.bytesToWord( x, 0, t, 0);
		this.bytesToWord( kl, _kl, u, 0);
		this.bytesToWord( kr, _kr, v, 0);

		t[1] ^= (t[0] & u[0]) << 1 ^ (t[0] & u[0]) >>> 31;
		t[0] ^= t[1] | u[1];
		t[2] ^= t[3] | v[1];
		t[3] ^= (t[2] & v[0]) << 1 ^ (t[2] & v[0]) >>> 31;

		this.wordToBytes(t, 0, x, 0);
	}

	bytesToWord(x, _x, y, _y)
	{
		for (var i = 0; i < 4; i++) {
			y[_y + i] = jCastle.util.load32b(x, _x + (i << 2));
		}
	}

	wordToBytes(x, _x, y, _y)
	{
		for (var i = 0; i < 4; i++ ) {
			jCastle.util.store32b(y, _y + (i << 2), x[_x + i]);
		}
	}

	rotBlock(x, _x, n, y, _y)
	{
		var r;
		
		if ( r = (n & 31) ) {
			y[_y + 0] = x[_x + (((n >>> 5) + 0) & 3)] << r ^ x[_x + (((n >>> 5) + 1) & 3)] >>> (32 - r);
			y[_y + 1] = x[_x + (((n >>> 5) + 1) & 3)] << r ^ x[_x + (((n >>> 5) + 2) & 3)] >>> (32 - r);
		} else {
			y[_y + 0] = x[_x + (((n >>> 5) + 0) & 3)];
			y[_y + 1] = x[_x + (((n >>> 5) + 1) & 3)];
		}
	}

	swapHalf(x)
	{
		var t;

		for(var i = 0; i < 8; i++) {
			t = x[i];
			x[i] = x[8 + i];
			x[8 + i] = t;
		}
	}

	xorBlock(x, _x, y, _y, z, _z)
	{
		for(var i = 0; i < 16; i++) {
			z[_z + i] = x[_x + i] ^ y[_y + i];
		}
	}
}



/*
 * ---------
 * Constants
 * ---------
 */

jCastle.algorithm.camellia.sigma = [
	0xa0, 0x9e, 0x66, 0x7f, 0x3b, 0xcc, 0x90, 0x8b, 0xb6, 0x7a,
	0xe8, 0x58, 0x4c, 0xaa, 0x73, 0xb2, 0xc6, 0xef, 0x37, 0x2f,
	0xe9, 0x4f, 0x82, 0xbe, 0x54, 0xff, 0x53, 0xa5, 0xf1, 0xd3,
	0x6f, 0x1c, 0x10, 0xe5, 0x27, 0xfa, 0xde, 0x68, 0x2d, 0x1d,
	0xb0, 0x56, 0x88, 0xc2, 0xb3, 0xe6, 0xc1, 0xfd
];

jCastle.algorithm.camellia.ksft1 = [
	0x00, 0x40, 0x00, 0x40, 0x0f, 0x4f, 0x0f, 0x4f, 0x1e, 0x5e, 
	0x2d, 0x6d, 0x2d, 0x7c, 0x3c, 0x7c, 0x4d, 0x0d, 0x5e, 0x1e, 
	0x5e, 0x1e, 0x6f, 0x2f, 0x6f, 0x2f
];

jCastle.algorithm.camellia.kidx1 = [
	0x00, 0x00, 0x04, 0x04, 0x00, 0x00, 0x04, 0x04, 0x04, 0x04, 
	0x00, 0x00, 0x04, 0x00, 0x04, 0x04, 0x00, 0x00, 0x00, 0x00, 
	0x04, 0x04, 0x00, 0x00, 0x04, 0x04
];

jCastle.algorithm.camellia.ksft2 = [
	0x00, 0x40, 0x00, 0x40, 0x0f, 0x4f, 0x0f, 0x4f, 0x1e, 0x5e, 
	0x1e, 0x5e, 0x2d, 0x6d, 0x2d, 0x6d, 0x3c, 0x7c, 0x3c, 0x7c, 
	0x3c, 0x7c, 0x4d, 0x0d, 0x4d, 0x0d, 0x5e, 0x1e, 0x5e, 0x1e, 
	0x6f, 0x2f, 0x6f, 0x2f
];

jCastle.algorithm.camellia.kidx2 = [
	0x00, 0x00, 0x0c, 0x0c, 0x08, 0x08, 0x04, 0x04, 0x08, 0x08, 
	0x0c, 0x0c, 0x00, 0x00, 0x04, 0x04, 0x00, 0x00, 0x08, 0x08, 
	0x0c, 0x0c, 0x00, 0x00, 0x04, 0x04, 0x08, 0x08, 0x04, 0x04, 
	0x00, 0x00, 0x0c, 0x0c
];

jCastle.algorithm.camellia.sbox = [
	0x70, 0x82, 0x2c, 0xec, 0xb3, 0x27, 0xc0, 0xe5, 0xe4, 0x85, 
	0x57, 0x35, 0xea, 0x0c, 0xae, 0x41, 0x23, 0xef, 0x6b, 0x93, 
	0x45, 0x19, 0xa5, 0x21, 0xed, 0x0e, 0x4f, 0x4e, 0x1d, 0x65, 
	0x92, 0xbd, 0x86, 0xb8, 0xaf, 0x8f, 0x7c, 0xeb, 0x1f, 0xce, 
	0x3e, 0x30, 0xdc, 0x5f, 0x5e, 0xc5, 0x0b, 0x1a, 0xa6, 0xe1, 
	0x39, 0xca, 0xd5, 0x47, 0x5d, 0x3d, 0xd9, 0x01, 0x5a, 0xd6, 
	0x51, 0x56, 0x6c, 0x4d, 0x8b, 0x0d, 0x9a, 0x66, 0xfb, 0xcc, 
	0xb0, 0x2d, 0x74, 0x12, 0x2b, 0x20, 0xf0, 0xb1, 0x84, 0x99, 
	0xdf, 0x4c, 0xcb, 0xc2, 0x34, 0x7e, 0x76, 0x05, 0x6d, 0xb7, 
	0xa9, 0x31, 0xd1, 0x17, 0x04, 0xd7, 0x14, 0x58, 0x3a, 0x61, 
	0xde, 0x1b, 0x11, 0x1c, 0x32, 0x0f, 0x9c, 0x16, 0x53, 0x18, 
	0xf2, 0x22, 0xfe, 0x44, 0xcf, 0xb2, 0xc3, 0xb5, 0x7a, 0x91, 
	0x24, 0x08, 0xe8, 0xa8, 0x60, 0xfc, 0x69, 0x50, 0xaa, 0xd0, 
	0xa0, 0x7d, 0xa1, 0x89, 0x62, 0x97, 0x54, 0x5b, 0x1e, 0x95, 
	0xe0, 0xff, 0x64, 0xd2, 0x10, 0xc4, 0x00, 0x48, 0xa3, 0xf7, 
	0x75, 0xdb, 0x8a, 0x03, 0xe6, 0xda, 0x09, 0x3f, 0xdd, 0x94, 
	0x87, 0x5c, 0x83, 0x02, 0xcd, 0x4a, 0x90, 0x33, 0x73, 0x67, 
	0xf6, 0xf3, 0x9d, 0x7f, 0xbf, 0xe2, 0x52, 0x9b, 0xd8, 0x26, 
	0xc8, 0x37, 0xc6, 0x3b, 0x81, 0x96, 0x6f, 0x4b, 0x13, 0xbe, 
	0x63, 0x2e, 0xe9, 0x79, 0xa7, 0x8c, 0x9f, 0x6e, 0xbc, 0x8e, 
	0x29, 0xf5, 0xf9, 0xb6, 0x2f, 0xfd, 0xb4, 0x59, 0x78, 0x98, 
	0x06, 0x6a, 0xe7, 0x46, 0x71, 0xba, 0xd4, 0x25, 0xab, 0x42, 
	0x88, 0xa2, 0x8d, 0xfa, 0x72, 0x07, 0xb9, 0x55, 0xf8, 0xee, 
	0xac, 0x0a, 0x36, 0x49, 0x2a, 0x68, 0x3c, 0x38, 0xf1, 0xa4, 
	0x40, 0x28, 0xd3, 0x7b, 0xbb, 0xc9, 0x43, 0xc1, 0x15, 0xe3, 
	0xad, 0xf4, 0x77, 0xc7, 0x80, 0x9e
];


jCastle._algorithmInfo['camellia'] = {
	algorithm_type: 'crypt',
	block_size: 16,
	key_size: 32,
	min_key_size: 16,
	max_key_size: 32,
	key_sizes: [16, 24, 32],
	padding: 'zeros',
	object_name: 'camellia'
};

jCastle._algorithmInfo['camellia-128'] = {
	algorithm_type: 'crypt',
	block_size: 16,
	key_size: 16,
	min_key_size: 16,
	max_key_size: 16,
	padding: 'zeros',
	object_name: 'camellia'
};

jCastle._algorithmInfo['camellia-192'] = {
	algorithm_type: 'crypt',
	block_size: 16,
	key_size: 24,
	min_key_size: 24,
	max_key_size: 24,
	padding: 'zeros',
	object_name: 'camellia'
};

jCastle._algorithmInfo['camellia-256'] = {
	algorithm_type: 'crypt',
	block_size: 16,
	key_size: 32,
	min_key_size: 32,
	max_key_size: 32,
	padding: 'zeros',
	object_name: 'camellia'
};

module.exports = jCastle.algorithm.camellia;