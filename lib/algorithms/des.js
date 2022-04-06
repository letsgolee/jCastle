/**
 * Javascript jCastle Mcrypt Module - DES3 & DES
 *
 * @author Jacob Lee
 *
 * Copyright (C) 2015-2022 Jacob Lee.
 */

var jCastle = require('../jCastle');
require('../util');

jCastle.algorithm.des = class
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
        this.kn = null;
        this.sp = null;
        this.iperm = null;
        this.fperm = null;
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
		this.kn = null;
		this.sp = null;
		this.iperm = null;
		this.fperm = null;

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
		
		var enckey = Buffer.slice(this.masterKey);
		
		if (this.algoName == 'des-ede2' && enckey.length == 16) {
			enckey = Buffer.concat([enckey, enckey.slice(0, 8)]);
		}
		
		this.expandKey(enckey);
		return this;
	}

	/**
	 * encrypts a block.
	 * 
	 * @public
	 * @param {buffer} input input data to be encrypted.
	 * @returns encrypted block in buffer.
	 */
	encryptBlock(block)
	{
		var left, right;
		var work;

	/* DES 1 */
		work = this.permute(block, this.iperm);	/* Initial Permutation */

		left = work.readInt32BE(0);
		right = work.readInt32BE(4);

		/* Do the 16 rounds.
		 * The rounds are numbered from 0 to 15. On even rounds
		 * the right half is fed to f() and the result exclusive-ORs
		 * the left half; on odd rounds the reverse is done.
		 */
		for (var i = 0; i < 16; i += 2) {
			left ^= this.f(0, right, this.kn[0][i]);
			right ^= this.f(0, left, this.kn[0][i+1]);
		}

		if (jCastle._algorithmInfo[this.algoName].key_size > 8) {

	/* DES 2 */

			/* Do the 16 rounds in reverse order.
			 * The rounds are numbered from 15 to 0. On even rounds
			 * the right half is fed to f() and the result exclusive-ORs
			 * the left half; on odd rounds the reverse is done.
			 */
			for (var i = 15; i > 0; i -= 2) {
				right ^= this.f(1, left, this.kn[1][i]);
				left ^= this.f(1, right, this.kn[1][i-1]);
			}

			/* Do the 16 rounds.
			 * The rounds are numbered from 0 to 15. On even rounds
			 * the right half is fed to f() and the result exclusive-ORs
			 * the left half; on odd rounds the reverse is done.
			 */
			for (var i = 0; i < 16; i += 2) {
				left ^= this.f(2, right, this.kn[2][i]);
				right ^= this.f(2, left, this.kn[2][i+1]);
			}
		}

		/* Left/right half swap, plus byte swap if little-endian */
		work.writeInt32BE(right, 0);
		work.writeInt32BE(left, 4);

		return this.permute(work, this.fperm);	/* Inverse initial permutation */
	}

	/**
	 * decrypts a block.
	 * 
	 * @public
	 * @param {buffer} input input data to be decrypted.
	 * @returns the decrypted block in buffer.
	 */
	decryptBlock(block) 
	{
		var left, right;
		var work;

		work = this.permute(block, this.iperm);	/* Initial permutation */

		/* Left/right half swap, plus byte swap if little-endian */
		right = work.readInt32BE(0);
		left = work.readInt32BE(4);

		if (jCastle._algorithmInfo[this.algoName].key_size > 8) {
			
	/* DES 3 */

			/* Do the 16 rounds in reverse order.
			 * The rounds are numbered from 15 to 0. On even rounds
			 * the right half is fed to f() and the result exclusive-ORs
			 * the left half; on odd rounds the reverse is done.
			 */
			for (var i = 15; i > 0; i -= 2) {
				right ^= this.f(2, left, this.kn[2][i]);
				left ^= this.f(2, right, this.kn[2][i-1]);
			}


		/* DES 2*/
			/* Do the 16 rounds.
			 * The rounds are numbered from 0 to 15. On even rounds
			 * the right half is fed to f() and the result exclusive-ORs
			 * the left half; on odd rounds the reverse is done.
			 */
			for (var i = 0; i < 16; i += 2) {
				left ^= this.f(1, right, this.kn[1][i]);
				right ^= this.f(1, left, this.kn[1][i+1]);
			}
		}

	/* DES 1 */
		/* Do the 16 rounds in reverse order.
		 * The rounds are numbered from 15 to 0. On even rounds
		 * the right half is fed to f() and the result exclusive-ORs
		 * the left half; on odd rounds the reverse is done.
		 */
		for (var i = 15; i > 0; i -= 2) {
			right ^= this.f(0, left, this.kn[0][i]);
			left ^= this.f(0, right, this.kn[0][i-1]);
		}

		work.writeInt32BE(left, 0);
		work.writeInt32BE(right, 4);

		return this.permute(work, this.fperm);	/* Inverse initial permutation */
	}


/*
 * -----------------
 * Private functions
 * -----------------
 */


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
		var pc1m = new Array(56);		/* place to modify pc1 into */
		var pcr = new Array(56);		/* place to rotate pc1 into */
		var i, j, l, m;

		var is_ede = (jCastle._algorithmInfo[this.algoName].key_size > 8) ? true : false;

		var key_length = is_ede ? 3 : 1;
		var user_key = new Array(key_length);
		for (var i = 0; i < key_length; i++) {
			user_key[i] = new Array(8);
		}

		for (var i = 0; i < 8; i++) {
			user_key[0][i] = key[i];
			if (is_ede) {
				user_key[1][i] = key[i + 8];
				user_key[2][i] = key[i + 16];
			}
		}
		
		
		// initialize sp
		// sp[3][8][64]
		this.sp = [];
		for (var i = 0; i < key_length; i++) {
			this.sp[i] = [];
			for (var j = 0; j < 8; j++) {
				this.sp[i][j] = new Array(64);
			}
		}
		
		// initialize iperm
		// initialize fperm
		this.iperm = [];
		this.fperm = [];
		for (var i = 0; i < 16; i++) {
			this.iperm[i] = [];
			this.fperm[i] = [];
			for (var j = 0; j < 16; j++) {
				this.iperm[i][j] = [0, 0, 0, 0, 0, 0, 0, 0];
				this.fperm[i][j] = [0, 0, 0, 0, 0, 0, 0, 0];
			}
		}
			
		this.init(key_length);

		/* Clear key schedule */
		// kn: [3][16][8]
		this.kn = [];
		for (var i = 0; i < key_length; i++) {
			this.kn[i] = [];
			for (var j = 0; j < 16; j++) {
				this.kn[i][j] = [0, 0, 0, 0, 0, 0, 0, 0];
			}
		}

		for (var k = 0; k < key_length; k++) {
			for (j = 0; j < 56; j++) {	/* convert pc1 to bits of key */
				l = jCastle.algorithm.des.pc1[j] - 1;	/* integer bit location  */
				m = l & 0x07;	/* find bit              */
				pc1m[j] = (user_key[k][(l >>> 3) & 0xf] &	/* find which key byte l is in */
					   jCastle.algorithm.des.bytebit[m])	/* and which bit of that byte */
					? 1 : 0;	/* and store 1-bit result */

			}
			for (i = 0; i < 16; i++) {	/* key chunk for each iteration */
				for (j = 0; j < 56; j++) {	/* rotate pc1 the right amount */
					pcr[j] =
						pc1m[(l = j + jCastle.algorithm.des.totrot[i]) <
						 (j < 28 ? 28 : 56) ? l : l - 28];
				}
				/* rotate left and right halves independently */
				for (j = 0; j < 48; j++) {	/* select bits individually */
					/* check bit that goes to kn[j] */
					if (pcr[jCastle.algorithm.des.pc2[j] - 1]) {
						/* mask it in if it's there */
						l = j % 6;
						this.kn[k][i][Math.floor(j / 6)] |= jCastle.algorithm.des.bytebit[l] >>> 2;
					}
				}
			}
		}
	}


	/* Allocate space and initialize DES lookup arrays
	 * mode == 0: standard Data Encryption Algorithm
	 */
	init(key_length)
	{
		for (var i = 0; i < key_length; i++) {
			this.spinit(i);
		}
		
		this.perminit(this.iperm, jCastle.algorithm.des.ip);
		this.perminit(this.fperm, jCastle.algorithm.des.fp);
	}


	/* Permute inblock with perm */
	permute(inblock, perm)
	{
		if (typeof perm == 'undefined' || perm == null) {
			/* No permutation, just copy */
			return Buffer.slice(inblock);
		}

		/* Clear output block */
		var outblock = Buffer.alloc(8);

		for (var j = 0, i = 0; j < 16; j += 2, i++) {	/* for each input nibble */
			var p = perm[j][(inblock[i] >>> 4) & 0xf];
			var q = perm[j + 1][inblock[i] & 0xf];
			/* and each output byte, OR the masks together */
			for (var k = 0; k < 8; k++) {
				outblock[k] |= p[k] | q[k];
			}
		}

		return outblock;
	}

	/* The nonlinear function f(r,k), the heart of DES */
	f(pos, r, subkey)
	{
		var spp;
		var rval, rt;
		var er;

		/* Run E(R) ^ K through the combined S & P boxes.
		 * This code takes advantage of a convenient regularity in
		 * E, namely that each group of 6 bits in E(R) feeding
		 * a single S-box is a contiguous segment of R.
		 */

		var i = 7;
		var j = 7;

		// sp[3][8][64]

		/* Compute E(R) for each block of 6 bits, and run thru boxes */
		er = (r << 1) | ((r & 0x80000000) ? 1 : 0);
		rval = this.sp[pos][j--][(er ^ subkey[i--]) & 0x3f];

		rt = r >>> 3;
		rval |= this.sp[pos][j--][(rt ^ subkey[i--]) & 0x3f];

		rt >>>= 4;
		rval |= this.sp[pos][j--][(rt ^ subkey[i--]) & 0x3f];

		rt >>>= 4;
		rval |= this.sp[pos][j--][(rt ^ subkey[i--]) & 0x3f];

		rt >>>= 4;
		rval |= this.sp[pos][j--][(rt ^ subkey[i--]) & 0x3f];

		rt >>>= 4;
		rval |= this.sp[pos][j--][(rt ^ subkey[i--]) & 0x3f];

		rt >>>= 4;
		rval |= this.sp[pos][j--][(rt ^ subkey[i--]) & 0x3f];

		rt >>>= 4;
		rt |= (r & 1) << 5;
		rval |= this.sp[pos][j][(rt ^ subkey[i]) & 0x3f];

		return rval;
	}

	/* initialize a perm array */
	perminit(perm, p)
	{
		var l, j, k;
		var i, m;

		for (i = 0; i < 16; i++) {	/* each input nibble position */
			for (j = 0; j < 16; j++) {	/* each possible input nibble */
				for (k = 0; k < 64; k++) {	/* each output bit position */
					l = p[k] - 1;	/* where does this bit come from */
					if ((l >>> 2) != i) {	/* does it come from input posn? */
						continue;	/* if not, bit k is 0    */
					}
					if (!(j & jCastle.algorithm.des.nibblebit[l & 3])) {
						continue;	/* any such bit in input? */
					}
					m = k & 0x07/*07*/;	/* which bit is this in the byte */
					perm[i][j][k >>> 3] |= jCastle.algorithm.des.bytebit[m];
				}
			}
		}
	}

	/* Initialize the lookup table for the combined S and P boxes */
	spinit(pos)
	{
		var pbox = new Array(32);
		var p, i, s, j, rowcol;
		var val;

		/* Compute pbox, the inverse of p32i.
		 * This is easier to work with
		 */
		for (p = 0; p < 32; p++) {
			for (i = 0; i < 32; i++) {
				if (jCastle.algorithm.des.p32i[i] - 1 == p) {
					pbox[p] = i;
					break;
				}
			}
		}
		
		for (s = 0; s < 8; s++) {	/* For each S-box */
			for (i = 0; i < 64; i++) {	/* For each possible input */
				val = 0;
				/* The row number is formed from the first and last
				 * bits; the column number is from the middle 4
				 */
				rowcol =
					(i & 32) | ((i & 1) ? 16 : 0) | ((i >>> 1) &
									 0xf);
				for (j = 0; j < 4; j++) {	/* For each output bit */
					if (jCastle.algorithm.des.si[s][rowcol] & (8 >>> j)) {
						val |=
							1 << (31 - pbox[4 * s + j]);
					}
				}
				this.sp[pos][s][i] = val;
			}
		}
	}
}



/* Tables defined in the Data Encryption Standard documents */

/* initial permutation IP */
jCastle.algorithm.des.ip = [
	58, 50, 42, 34, 26, 18, 10, 2,
	60, 52, 44, 36, 28, 20, 12, 4,
	62, 54, 46, 38, 30, 22, 14, 6,
	64, 56, 48, 40, 32, 24, 16, 8,
	57, 49, 41, 33, 25, 17, 9, 1,
	59, 51, 43, 35, 27, 19, 11, 3,
	61, 53, 45, 37, 29, 21, 13, 5,
	63, 55, 47, 39, 31, 23, 15, 7
];

/* final permutation IP^-1 */
jCastle.algorithm.des.fp = [
	40, 8, 48, 16, 56, 24, 64, 32,
	39, 7, 47, 15, 55, 23, 63, 31,
	38, 6, 46, 14, 54, 22, 62, 30,
	37, 5, 45, 13, 53, 21, 61, 29,
	36, 4, 44, 12, 52, 20, 60, 28,
	35, 3, 43, 11, 51, 19, 59, 27,
	34, 2, 42, 10, 50, 18, 58, 26,
	33, 1, 41, 9, 49, 17, 57, 25
];

/* expansion operation matrix
 * This is for reference only; it is unused in the code
 * as the f() function performs it implicitly for speed
 */

jCastle.algorithm.des.ei = [
	32, 1, 2, 3, 4, 5,
	4, 5, 6, 7, 8, 9,
	8, 9, 10, 11, 12, 13,
	12, 13, 14, 15, 16, 17,
	16, 17, 18, 19, 20, 21,
	20, 21, 22, 23, 24, 25,
	24, 25, 26, 27, 28, 29,
	28, 29, 30, 31, 32, 1
];


/* permuted choice table (key) */
jCastle.algorithm.des.pc1 = [
	57, 49, 41, 33, 25, 17, 9,
	1, 58, 50, 42, 34, 26, 18,
	10, 2, 59, 51, 43, 35, 27,
	19, 11, 3, 60, 52, 44, 36,

	63, 55, 47, 39, 31, 23, 15,
	7, 62, 54, 46, 38, 30, 22,
	14, 6, 61, 53, 45, 37, 29,
	21, 13, 5, 28, 20, 12, 4
];

/* number left rotations of pc1 */
jCastle.algorithm.des.totrot = [
	1, 2, 4, 6, 8, 10, 12, 14, 15, 17, 19, 21, 23, 25, 27, 28
];

/* permuted choice key (table) */
jCastle.algorithm.des.pc2 = [
	14, 17, 11, 24, 1, 5,
	3, 28, 15, 6, 21, 10,
	23, 19, 12, 4, 26, 8,
	16, 7, 27, 20, 13, 2,
	41, 52, 31, 37, 47, 55,
	30, 40, 51, 45, 33, 48,
	44, 49, 39, 56, 34, 53,
	46, 42, 50, 36, 29, 32
];

/* The (in)famous S-boxes */
jCastle.algorithm.des.si = [ // [8][64]
	/* S1 */
	[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
	 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
	 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
	 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],

	/* S2 */
	[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
	 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
	 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
	 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],

	/* S3 */
	[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
	 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
	 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
	 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],

	/* S4 */
	[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
	 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
	 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
	 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],

	/* S5 */
	[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
	 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
	 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
	 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],

	/* S6 */
	[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
	 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
	 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
	 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],

	/* S7 */
	[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
	 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
	 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
	 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],

	/* S8 */
	[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
	 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
	 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
	 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],

];

/* 32-bit permutation function P used on the output of the S-boxes */
jCastle.algorithm.des.p32i = [
	16, 7, 20, 21,
	29, 12, 28, 17,
	1, 15, 23, 26,
	5, 18, 31, 10,
	2, 8, 24, 14,
	32, 27, 3, 9,
	19, 13, 30, 6,
	22, 11, 4, 25
];

/* End of DES-defined tables */

/* Lookup tables initialized once only at startup by desinit() */

/* bit 0 is left-most in byte */
jCastle.algorithm.des.bytebit = [
	//0200, 0100, 040, 020, 010, 04, 02, 01
	0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01

];

jCastle.algorithm.des.nibblebit = [
	//010, 04, 02, 01
	0x08, 0x04, 0x02, 0x01
];


jCastle._algorithmInfo['des'] = {
	algorithm_type: 'crypt',
	block_size: 8,
	key_size: 8,
	min_key_size: 8,
	max_key_size: 8,
	padding: 'zeros',
	object_name: 'des'
};

jCastle._algorithmInfo['des-ede2'] = {
	algorithm_type: 'crypt',
	block_size: 8,
	key_size: 16,
	min_key_size: 16,
	max_key_size: 16,
	padding: 'zeros',
	object_name: 'des'
};

jCastle._algorithmInfo['3des'] = 
jCastle._algorithmInfo['des3'] = 
jCastle._algorithmInfo['des-ede3'] = 
jCastle._algorithmInfo['3des-ede'] =
jCastle._algorithmInfo['tripledes'] = {
	algorithm_type: 'crypt',
	block_size: 8,
	key_size: 24,
	min_key_size: 24,
	max_key_size: 24,
	padding: 'zeros',
	object_name: 'des'
};

module.exports = jCastle.algorithm.des;