/**
 * A Javascript implemenation of GOST3411-94 Hash
 * 
 * @author Jacob Lee
 * 
 * Copyright (C) 2015-2022 Jacob Lee.
 */

var jCastle = require('../jCastle');
require('../util');

jCastle.algorithm.gost3411 = class
{
	/**
	 * creates the hash algorithm instance.
	 * 
	 * @param {string} hash_name hash algorithm name
	 * @constructor
	 */
    constructor(hash_name)
    {
        this.algoName = hash_name;
        this.sbox_type = '';
        this._state = null;
        this.block_state = null;
        this.roundKey = null; // for gost encrytion
        this.input_length = 0;
        this._gost = null;

        // if (typeof jCastle._algorithmInfo == 'undefined' || !('gost28147' in jCastle._algorithmInfo)) {
        //     throw jCastle.exception("GOST28147_REQUIRED", 'GST3411001');
        // }
    }

	/**
	 * get the block size in bits.
	 * 
	 * @public
	 * @returns the block size in bits.
	 */
	getBlockSize()
	{
		return jCastle._algorithmInfo[this.algoName].block_size; // bits
	}

	/**
	 * get the bytes length of the hash algorithm
	 * 
	 * @public
	 * @returns the hash bytes length.
	 */
	getDigestLength()
	{
		return jCastle._algorithmInfo[this.algoName].digest_size; // bytes
	}

	/**
	 * initialize the hash algorithm and sets state with initial value.
	 * 
	 * @public
	 * @param {object} options options object
	 */
	init(options = {})
	{
		this.sbox_type = jCastle._algorithmInfo[this.algoName].sbox_type;

		// initialize;
		this._state = Buffer.alloc(32);
		this.block_state = Buffer.alloc(32);

		this.input_length = 0;

		this._gost = new jCastle.algorithm.gost('gost28147');
		this._gost.setSbox(this.sbox_type);
	}

	/**
	 * processes digesting.
	 * 
	 * @public
	 * @param {buffer} input input data to be digested.
	 */
	process(input)
	{
		this.hash_step(input);
		this.add_blocks(input);
	}

	/**
	 * pads the data.
	 * 
	 * @public
	 * @param {buffer} input input data to be padded.
	 * @param {number} pos position number.
	 * @returns the padded input.
	 */
	pad(input, pos)
	{
		var input_len = input.length;
		var index = input_len - pos; // same with input_len % jCastle._algorithmInfo[this.algoName].block_size
		this.input_length = input_len;
		var pads = 0;

		if (index) {
			while (index < jCastle._algorithmInfo[this.algoName].block_size) {
				pads++;
				index++;
			}
		}
		
		return pads ? Buffer.concat([input, Buffer.alloc(pads)]) : input;		
	}

	/**
	 * finishes digesting process and returns the result.
	 * 
	 * @public
	 * @returns the digested data.
	 */
	finish()
	{
		var len_block = Buffer.alloc(32);
		var len = this.input_length * 8;
		var j = 0;
		while (len > 0) {
			len_block[j++] = len & 0xff;
			len >>>= 8;
		}

		this.hash_step(len_block);
		this.hash_step(this.block_state);

		var output = Buffer.slice(this._state);

		this._state = null;
		this.block_state = null;
		this.input_length = 0;
		this.roundKey = null;
		this._gost = null;
		
		return output;
	}

	// Following functions are various bit meshing routines used in
	// GOST R 34.11-94 algorithms
	swap_bytes(w, k)
	{
		for (var i = 0; i < 4; i++)	{
			for (var j = 0; j < 8; j++) {
				k[i + 4 * j] = w[8 * i + j] & 0xff;
			}
		}
	}

	// was A_A
	circle_xor8(w, k)
	{
		var buf = Buffer.slice(w, 0, 8);

		k.set(w.slice(8, 8 + 24), 0);
		for(var i = 0; i < 8; i++) {
			k[i + 24] = buf[i] ^ k[i];
		}
	}

	// was R_R
	transform_3(data)
	{
		var acc;
		acc = (data[0] ^ data[2] ^ data[4] ^ data[6] ^ data[24] ^ data[30]) |
			((data[1] ^ data[3] ^ data[5] ^ data[7] ^ data[25] ^ data[31]) << 8);
		
		data.set(data.slice(2, 2 + 30), 0);

		data[30] = acc & 0xff;
		data[31] = (acc >>> 8) & 0xff;
	}

	// Adds blocks of N bytes modulo 2**(8*n). Returns carry
	add_blocks(block)
	{
		var carry = 0;
		var sum;

		for (var i = 0; i < 32; i++) {
			sum = this.block_state[i] + block[i] + carry;
			this.block_state[i] = sum & 0xff;
			carry = sum >>> 8;
		}
		return carry;
	}

	// Calculate H(i+1) = Hash(Hi,Mi) 
	// Where H and M are 32 bytes long
	hash_step(M)
	{
		var U = Buffer.alloc(32), V = Buffer.alloc(32), S = Buffer.alloc(32), key = Buffer.alloc(32), W;
		var H = this._state;

		// Compute first key
		W = Buffer.xor(H, M);
		this.swap_bytes(W, key);

		// Encrypt first 8 bytes of H with first key
		this._gost.keySchedule(key, true);
		S.set(this._gost.encryptBlock(H.slice(0, 8)), 0);

		// Compute second key
		this.circle_xor8(H, U);
		this.circle_xor8(M, V);
		this.circle_xor8(V, V);
		W = Buffer.xor(U, V);
		this.swap_bytes(W, key);

		// encrypt second 8 bytes of H with second key
		this._gost.keySchedule(key, true);
		S.set(this._gost.encryptBlock(H.slice(8, 16)), 8);

		// compute third key
		this.circle_xor8(U, U);

		U[31] = ~U[31]; U[29] = ~U[29]; U[28] = ~U[28]; U[24] = ~U[24];
		U[23] = ~U[23]; U[20] = ~U[20]; U[18] = ~U[18]; U[17] = ~U[17];
		U[14] = ~U[14]; U[12] = ~U[12]; U[10] = ~U[10]; U[ 8] = ~U[ 8];
		U[ 7] = ~U[ 7]; U[ 5] = ~U[ 5]; U[ 3] = ~U[ 3]; U[ 1] = ~U[ 1];

		this.circle_xor8(V, V);
		this.circle_xor8(V, V);
		W = Buffer.xor(U, V);
		this.swap_bytes(W, key);

		// encrypt third 8 bytes of H with third key
		this._gost.keySchedule(key, true);
		S.set(this._gost.encryptBlock(H.slice(16, 24)), 16);

		// Compute fourth key
		this.circle_xor8(U, U);
		this.circle_xor8(V, V);
		this.circle_xor8(V, V);
		W = Buffer.xor(U, V);
		this.swap_bytes(W, key);
		
		// Encrypt last 8 bytes with fourth key
		this._gost.keySchedule(key, true);
		S.set(this._gost.encryptBlock(H.slice(24, 32)), 24);
		
		for (var i = 0; i < 12; i++)  {
			this.transform_3(S);
		}
		
		S = Buffer.xor(S, M);
		this.transform_3(S);
		
		S = Buffer.xor(S, H);
		for (var i = 0; i < 61; i++) {
			this.transform_3(S);
		}

		this._state = Buffer.slice(S);
	}
};

jCastle.algorithm.GOST3411 = jCastle.algorithm.gost3411;


jCastle._algorithmInfo['gost3411'] = {
	algorithm_type: 'hash',
	version: '94',
	object_name: 'gost3411',
	block_size: 32,
	digest_size: 32,
	sbox_type: 'GostR3411_94_TestParamSet',
	oid: "1.2.643.2.2.9",
	sbox_oid: "1.2.643.2.2.30.0"
};

// gost-crypto was added in php 5.6
jCastle._algorithmInfo['gost3411-crypto'] = {
	algorithm_type: 'hash',
	version: '94',
	object_name: 'gost3411',
	block_size: 32,
	digest_size: 32,
	sbox_type: 'GostR3411_94_CryptoProParamSet',
	oid: "1.2.643.2.2.9",
	sbox_oid: "1.2.643.2.2.30.1"
};

module.exports = jCastle.algorithm.gost3411;