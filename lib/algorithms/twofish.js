/**
 * Javascript jCastle Mcrypt Module - Twofish 
 *
 * @author Jacob Lee
 *
 * Copyright (C) 2015-2022 Jacob Lee.
 */

var jCastle = require('../jCastle');
require('../util');

jCastle.algorithm.twofish = class
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
        this.whitenKey = null;
        this.roundKeys = null;
        this.rounds = 8;
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
		this.whitenKey = null;
		this.roundKeys = null;
		this.rounds = 8;
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
			input.readInt32LE(0) ^ this.whitenKey[0],
			input.readInt32LE(4) ^ this.whitenKey[1],
			input.readInt32LE(8) ^ this.whitenKey[2],
			input.readInt32LE(12) ^ this.whitenKey[3]
		];
		
		for (var j = 0;j < this.rounds; j++) {
			r = this.f_rnd(j, r);
		}
		
		output.writeInt32LE(r[2] ^ this.whitenKey[4], 0, true);
		output.writeInt32LE(r[3] ^ this.whitenKey[5], 4, true);
		output.writeInt32LE(r[0] ^ this.whitenKey[6], 8, true);
		output.writeInt32LE(r[1] ^ this.whitenKey[7], 12, true);

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
		var r=[
			input.readInt32LE(0) ^ this.whitenKey[4],
			input.readInt32LE(4) ^ this.whitenKey[5],
			input.readInt32LE(8) ^ this.whitenKey[6],
			input.readInt32LE(12) ^ this.whitenKey[7]
		];

		for (var j = (this.rounds-1); j >= 0; j--) {
			r = this.i_rnd(j, r);
		}
		
		output.writeInt32LE(r[2] ^ this.whitenKey[0], 0, true);
		output.writeInt32LE(r[3] ^ this.whitenKey[1], 4, true);
		output.writeInt32LE(r[0] ^ this.whitenKey[2], 8, true);
		output.writeInt32LE(r[1] ^ this.whitenKey[3], 12, true);
		
		return output;
	}


/*
 * -----------------
 * Private functions
 * -----------------
 */


	g0_fun(x)
	{
		var byte = jCastle.util.byte;
		
		return this.roundKeys[0][byte(x, 0)] ^ this.roundKeys[1][byte(x, 1)] ^ 
			this.roundKeys[2][byte(x, 2)] ^ this.roundKeys[3][byte(x, 3)]; 
	}

	g1_fun(x)
	{
		var byte = jCastle.util.byte;
		
		return this.roundKeys[0][byte(x, 3)] ^ this.roundKeys[1][byte(x, 0)] ^
			this.roundKeys[2][byte(x, 1)] ^ this.roundKeys[3][byte(x, 2)]; 
	}

	f_rnd(i, block)
	{
		var t1 = this.g1_fun(block[1]);
		var t0 = this.g0_fun(block[0]);
		var rotl32 = jCastle.util.rotl32;
		
		block[2] = rotl32(block[2] ^ (t0 + t1 + this.whitenKey[4 * i + 8]) & 0xffffffff, 31);
		block[3] = rotl32(block[3], 1) ^ (t0 + 2 * t1 + this.whitenKey[4 * i + 9]) & 0xffffffff;
		
		t1 = this.g1_fun(block[3]);
		t0 = this.g0_fun(block[2]);
		
		block[0] = rotl32(block[0] ^ (t0 + t1 + this.whitenKey[4 * i + 10]) & 0xffffffff, 31);
		block[1] = rotl32(block[1], 1) ^ (t0 + 2 * t1 + this.whitenKey[4 * i + 11]) & 0xffffffff;
		
		return block;
	}

	i_rnd(i, block)
	{
		var t1 = this.g1_fun(block[1]);
		var t0 = this.g0_fun(block[0]);
		var rotl32 = jCastle.util.rotl32;
		
		block[2] = rotl32(block[2], 1) ^ (t0 + t1 + this.whitenKey[4 * i + 10]) & 0xffffffff;
		block[3] = rotl32(block[3] ^ (t0 + 2 * t1 + this.whitenKey[4 * i + 11]) & 0xffffffff, 31);
		
		t1 = this.g1_fun(block[3]);
		t0 = this.g0_fun(block[2]);
		
		block[0] = rotl32(block[0], 1) ^ (t0 + t1 + this.whitenKey[4 * i + 8]) & 0xffffffff;
		block[1] = rotl32(block[1] ^ (t0 + 2 * t1 + this.whitenKey[4 * i + 9]) & 0xffffffff, 31);
		
		return block;
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
		var  i, a, b, c, d, me_key = [], mo_key = [], int32Key = [];
		var k_len, len = key.length;
		var s_key = [];
		var enckey = key.slice(0);
		
		this.roundKeys = [[],[],[],[]];
		this.whitenKey = [];
		
		while (len != 16 && len != 24 && len != 32) {
//			key[len++] = 0;
			len++;
		}
		
		if (len != enckey.length) {
			enckey = Buffer.concat([enckey, Buffer.alloc(len - enckey.length)]);
		}
		

		for (i = 0; i < enckey.length; i += 4) {
//			int32Key[i >> 2] = jCastle.util.load32(key, i);
			int32Key[i >>> 2] = enckey.readInt32LE(i);
		}

		var q_tab = this.create_qtab();
		var m_tab = this.create_mtab(q_tab);

		k_len = int32Key.length / 2; /* shoud 2, 3 or 4 */
		for (i = 0; i < k_len; i++) {
			a = int32Key[i + i];
			me_key[i] = a;
			b = int32Key[i + i + 1];
			mo_key[i] = b;
			s_key[k_len - i - 1] = this.mds_rem(a, b);
		}
		
		for (i = 0; i < 40; i += 2) {
			a = 0x1010101 * i;
			b = a + 0x1010101;
			a = this.h_fun(k_len, a, me_key, q_tab, m_tab);
			b = jCastle.util.rotl32(this.h_fun(k_len, b, mo_key, q_tab, m_tab), 8);
			this.whitenKey[i] = (a + b) & 0xffffffff;
			this.whitenKey[i + 1] = jCastle.util.rotl32(a + 2 * b, 9);
		}
		
		this.roundKeys = this.create_roundKeys(k_len, s_key, m_tab, q_tab);
	}

	mds_rem(p0, p1)
	{
		var t, u;
			
		for (var i = 0; i < 8; i++) {
			t = p1 >>> 24;
			p1 = ((p1 << 8) & 0xffffffff) | p0 >>> 24;
			p0 = (p0 << 8) & 0xffffffff;
			u = t << 1;
			if (t & 0x80) {
				u ^= jCastle.algorithm.twofish.G_MOD;
			}
			p1 ^= t ^ (u << 16);
			u ^= t >>> 1;
			if (t & 0x01) {
				u ^= jCastle.algorithm.twofish.G_MOD >> 1;
			}
			p1 ^= (u << 24) | (u << 8);
		}
		return p1;
	}


	h_fun(k_len, x, key, q_tab, m_tab)
	{
		var byte = jCastle.util.byte;
			
		var b0 = byte(x,0),
			b1 = byte(x,1),
			b2 = byte(x,2),
			b3 = byte(x,3);
			
		switch(k_len) {
			case 4:
				b0 = q_tab[1][b0] ^ byte(key[3],0);
				b1 = q_tab[0][b1] ^ byte(key[3],1);
				b2 = q_tab[0][b2] ^ byte(key[3],2);
				b3 = q_tab[1][b3] ^ byte(key[3],3);
			case 3:
				b0 = q_tab[1][b0] ^ byte(key[2],0);
				b1 = q_tab[1][b1] ^ byte(key[2],1);
				b2 = q_tab[0][b2] ^ byte(key[2],2);
				b3 = q_tab[0][b3] ^ byte(key[2],3);
			case 2:
				b0 = q_tab[0][q_tab[0][b0] ^ byte(key[1],0)] ^ byte(key[0],0);
				b1 = q_tab[0][q_tab[1][b1] ^ byte(key[1],1)] ^ byte(key[0],1);
				b2 = q_tab[1][q_tab[0][b2] ^ byte(key[1],2)] ^ byte(key[0],2);
				b3 = q_tab[1][q_tab[1][b3] ^ byte(key[1],3)] ^ byte(key[0],3);
		}
		return m_tab[0][b0] ^ m_tab[1][b1] ^ m_tab[2][b2] ^ m_tab[3][b3];
	}

	create_qtab()
	{
		function qp(n, x)
		{		
			var a, b, c, d;
			a = x >>> 4;
			b = x & 15;
			c = jCastle.algorithm.twofish.qtab0[n][a^b];
			d = jCastle.algorithm.twofish.qtab1[n][jCastle.algorithm.twofish.ror4[b] ^ jCastle.algorithm.twofish.ashx[a]];
			return (jCastle.algorithm.twofish.qtab3[n][jCastle.algorithm.twofish.ror4[d] ^ jCastle.algorithm.twofish.ashx[c]] << 4) | 
					jCastle.algorithm.twofish.qtab2[n][c^d];
		};

		var q_tab = [[],[]];
			
		for (var i = 0; i < 256; i++) {
			q_tab[0][i] = qp(0, i);
			q_tab[1][i] = qp(1, i);
		}
			
		return q_tab;
	}
		
	create_mtab(q_tab)
	{
		var G_M  = 0x0169;
		var tab_5b = [ 0, G_M >>> 2, G_M >>> 1, (G_M >>> 1) ^ (G_M >>> 2) ];
		var tab_ef = [ 0, (G_M >>> 1) ^ (G_M >>> 2), G_M >>> 1, G_M >>> 2 ];
	 
		function ffm_5b(x)
		{
			return x ^ (x >>> 2) ^ tab_5b[x & 3];
		};
		
		function ffm_ef(x)
		{
			return x ^ (x >>> 1) ^ (x >>> 2) ^ tab_ef[x & 3];
		};
		
		var m_tab = [[],[],[],[]];
		var f01, f5b, fef;
			
		for (var i = 0; i < 256; i++) {
			f01 = q_tab[1][i];
			f5b = ffm_5b(f01);
			fef = ffm_ef(f01);
			m_tab[0][i] = f01 + (f5b << 8) + (fef << 16) + (fef << 24);
			m_tab[2][i] = f5b + (fef << 8) + (f01 << 16) + (fef << 24);
			f01 = q_tab[0][i];
			f5b = ffm_5b(f01);
			fef = ffm_ef(f01);
			m_tab[1][i] = fef + (fef << 8) + (f5b << 16) + (f01 << 24);
			m_tab[3][i] = f5b + (f01 << 8) + (fef << 16) + (f5b << 24);
		}
			
		return m_tab;
	}
		
	create_roundKeys(k_len, s_key, m_tab, q_tab)
	{
		var roundKeys = [[],[],[],[]];
		var byte = jCastle.util.byte;
		var a, b, c, d;
			
		for (var i = 0; i < 256; i++) {
			a = b = c = d = i;
			switch(k_len) {
				case 4:
					a = q_tab[1][a] ^ byte(s_key[3],0);
					b = q_tab[0][b] ^ byte(s_key[3],1);
					c = q_tab[0][c] ^ byte(s_key[3],2);
					d = q_tab[1][d] ^ byte(s_key[3],3);
				case 3:
					a = q_tab[1][a] ^ byte(s_key[2],0);
					b = q_tab[1][b] ^ byte(s_key[2],1);
					c = q_tab[0][c] ^ byte(s_key[2],2);
					d = q_tab[0][d] ^ byte(s_key[2],3);
				case 2:
					roundKeys[0][i] = m_tab[0][q_tab[0][q_tab[0][a] ^ byte(s_key[1],0)] ^ byte(s_key[0],0)];
					roundKeys[1][i] = m_tab[1][q_tab[0][q_tab[1][b] ^ byte(s_key[1],1)] ^ byte(s_key[0],1)];
					roundKeys[2][i] = m_tab[2][q_tab[1][q_tab[0][c] ^ byte(s_key[1],2)] ^ byte(s_key[0],2)];
					roundKeys[3][i] = m_tab[3][q_tab[1][q_tab[1][d] ^ byte(s_key[1],3)] ^ byte(s_key[0],3)];
			}
		}
		return roundKeys;
	}
}


/*
 * ---------
 * Constants
 * ---------
 */

jCastle.algorithm.twofish.qtab0 = [
	[8, 1, 7, 13, 6, 15, 3, 2, 0, 11, 5, 9, 14, 12, 10, 4],
	[2, 8, 11, 13, 15, 7, 6, 14, 3, 1, 9, 4, 0, 10, 12, 5]
];

jCastle.algorithm.twofish.qtab1 = [
	[14, 12, 11, 8, 1, 2, 3, 5, 15, 4, 10, 6, 7, 0, 9, 13],
	[1, 14, 2, 11, 4, 12, 3, 7, 6, 13, 10, 5, 15, 9, 0, 8]
];

jCastle.algorithm.twofish.qtab2 = [
	[11, 10, 5, 14, 6, 13, 9, 0, 12, 8, 15, 3, 2, 4, 7, 1],
	[4, 12, 7, 5, 1, 6, 9, 10, 0, 14, 13, 8, 2, 11, 3, 15]
];

jCastle.algorithm.twofish.qtab3 = [
	[13, 7, 15, 4, 1, 2, 6, 14, 9, 11, 3, 0, 8, 5, 12, 10],
	[11, 9, 5, 1, 12, 3, 13, 14, 6, 4, 7, 15, 2, 0, 8, 10]
];

jCastle.algorithm.twofish.G_MOD = 0x0000014d;
jCastle.algorithm.twofish.ror4 = [0, 8, 1, 9, 2, 10, 3, 11, 4, 12, 5, 13, 6, 14, 7, 15];
jCastle.algorithm.twofish.ashx = [0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 5, 14, 7];


jCastle._algorithmInfo['twofish'] = {
	algorithm_type: 'crypt',
	block_size: 16,
	key_size: 32,
	min_key_size: 16,
	max_key_size: 32,
	key_sizes: [16, 24, 32],
	padding: 'zeros',
	object_name: 'twofish'
};

module.exports = jCastle.algorithm.twofish;