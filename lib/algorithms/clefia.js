/**
 * Javascript jCastle Mcrypt Module - Clefia
 * 
 * @author Jacob Lee
 *
 * Copyright (C) 2015-2022 Jacob Lee.
 */

var jCastle = require('../jCastle');
require('../util');

jCastle.algorithm.clefia = class
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
        this.roundKey = null;
        this.masterKey = null;
        this.keyBits = null;
        this.rounds = null;
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
		var rin = Buffer.slice(input), rout = Buffer.alloc(16);
		var rk_offset = 0;
		var r = this.rounds;

		//jCastle.util.arrayCopy(rin, 0,  input, 0,  16);

		jCastle.util.byteXor(rin, 4,  rin, 4,  this.roundKey, rk_offset, 4); /* initial key whitening */
		jCastle.util.byteXor(rin, 12, rin, 12, this.roundKey, rk_offset+4, 4);
		rk_offset += 8;

		this.Gfn4(rout, rin, this.roundKey, rk_offset, r); /* GFN_{4,r} */

		//jCastle.util.arrayCopy(output, 0, rout, 0, 16);

		jCastle.util.byteXor(rout, 4,  rout, 4,  this.roundKey, rk_offset + r * 8 + 0, 4); /* final key whitening */
		jCastle.util.byteXor(rout, 12, rout, 12, this.roundKey, rk_offset + r * 8 + 4, 4);
		
		return rout;
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
		var rin = Buffer.slice(input), rout = Buffer.alloc(16);
		var rk_offset = 0;
		var r = this.rounds;

		//jCastle.util.arrayCopy(rin, 0, input, 0, 16);

		jCastle.util.byteXor(rin, 4,  rin, 4,  this.roundKey, rk_offset + r * 8 + 8,  4); /* initial key whitening */
		jCastle.util.byteXor(rin, 12, rin, 12, this.roundKey, rk_offset + r * 8 + 12, 4);
		rk_offset += 8;

		this.Gfn4Inv(rout, rin, this.roundKey, rk_offset, r); /* GFN^{-1}_{4,r} */

		//jCastle.util.arrayCopy(output, 0, rout, 0, 16);

		jCastle.util.byteXor(rout, 4,  rout, 4,  this.roundKey, rk_offset - 8, 4); /* final key whitening */
		jCastle.util.byteXor(rout, 12, rout, 12, this.roundKey, rk_offset - 4, 4);
		
		return rout;
	}



/*
 * -----------------
 * Private functions
 * -----------------
 */



/*
	byteCopy(dst, _dst, src, _src, bytelen)
	{
		while(bytelen-- > 0) {
			dst[_dst++] = src[_src++];
		}
	}

	byteXor(dst, _dst, a, _a, b, _b, bytelen)
	{
		while(bytelen-- > 0) {
			dst[_dst++] = (a[_a++] ^ b[_b++]) & 0xff;
		}
	}
*/

	Mul2(x)
	{
	  /* multiplication over GF(2^8) (p(x) = '11d') */
		if(x & 0x80) {
			x ^= 0x0e;
		}
		return ((x << 1) | (x >>> 7)) & 0xff;
	}

	Mul4(_x)
	{
		return this.Mul2(this.Mul2(_x));
	}

	Mul6(_x)
	{
		return this.Mul2(_x) ^ this.Mul4(_x);
	}

	Mul8(_x)
	{
		return this.Mul2(this.Mul4(_x));
	}

	MulA(_x)
	{
		return this.Mul2(_x) ^ this.Mul8(_x);
	}

	F0Xor(dst, _dst, src, _src, rk, _rk)
	{
		var x = Buffer.alloc(4), y = Buffer.alloc(4), z = Buffer.alloc(4);

		/* F0 */
		/* Key addition */
		jCastle.util.byteXor(x, 0, src, _src, rk, _rk, 4);
		/* Substitution layer */
		z[0] = jCastle.algorithm.clefia.s0[x[0]];
		z[1] = jCastle.algorithm.clefia.s1[x[1]];
		z[2] = jCastle.algorithm.clefia.s0[x[2]];
		z[3] = jCastle.algorithm.clefia.s1[x[3]];
		/* Diffusion layer (M0) */
		y[0] = (           z[0]  ^ this.Mul2(z[1]) ^ this.Mul4(z[2]) ^ this.Mul6(z[3])) & 0xFF;
		y[1] = (this.Mul2(z[0]) ^            z[1]  ^ this.Mul6(z[2]) ^ this.Mul4(z[3])) & 0xFF;
		y[2] = (this.Mul4(z[0]) ^ this.Mul6(z[1]) ^            z[2]  ^ this.Mul2(z[3])) & 0xFF;
		y[3] = (this.Mul6(z[0]) ^ this.Mul4(z[1]) ^ this.Mul2(z[2]) ^            z[3] ) & 0xFF;

		/* Xoring after F0 */
		jCastle.util.arrayCopy(dst, _dst, src, _src, 4);
		jCastle.util.byteXor(dst, _dst+4, src, _src+4, y, 0, 4);
	}

	F1Xor(dst, _dst, src, _src, rk, _rk) 
	{
		var x = Buffer.alloc(4), y = Buffer.alloc(4), z = Buffer.alloc(4);

		/* F1 */
		/* Key addition */
		jCastle.util.byteXor(x, 0, src, _src, rk, _rk, 4);
		/* Substitution layer */
		z[0] = jCastle.algorithm.clefia.s1[x[0]];
		z[1] = jCastle.algorithm.clefia.s0[x[1]];
		z[2] = jCastle.algorithm.clefia.s1[x[2]];
		z[3] = jCastle.algorithm.clefia.s0[x[3]];
		/* Diffusion layer (M1) */
		y[0] = (           z[0]  ^ this.Mul8(z[1]) ^ this.Mul2(z[2]) ^ this.MulA(z[3])) & 0xFF;
		y[1] = (this.Mul8(z[0]) ^            z[1]  ^ this.MulA(z[2]) ^ this.Mul2(z[3])) & 0xFF;
		y[2] = (this.Mul2(z[0]) ^ this.MulA(z[1]) ^            z[2]  ^ this.Mul8(z[3])) & 0xFF;
		y[3] = (this.MulA(z[0]) ^ this.Mul2(z[1]) ^ this.Mul8(z[2]) ^            z[3] ) & 0xFF;

		/* Xoring after F1 */
		jCastle.util.arrayCopy(dst, _dst, src, _src, 4);
		jCastle.util.byteXor(dst, _dst+4, src, _src+4, y, 0, 4);
	}

	Gfn4(y, x, rk, _rk, r) 
	{
		var fin= Buffer.alloc(16), fout = Buffer.alloc(16);
		
		var rk_offset = _rk;

		jCastle.util.arrayCopy(fin, 0, x, 0, 16);
		while(r-- > 0){
			this.F0Xor(fout, 0, fin, 0, rk, rk_offset + 0);
			this.F1Xor(fout, 8, fin, 8, rk, rk_offset + 4);
			rk_offset += 8;
			if(r){ /* swapping for encryption */
				jCastle.util.arrayCopy(fin, 0,  fout, 4, 12);
				jCastle.util.arrayCopy(fin, 12, fout, 0, 4);
			}
		}
		jCastle.util.arrayCopy(y, 0, fout, 0, 16);
	}

	Gfn8(y, x, rk, _rk, r) 
	{
		var fin = Buffer.alloc(32), fout = Buffer.alloc(32);
		var rk_offset = _rk;

		jCastle.util.arrayCopy(fin , 0, x, 0, 32);
		while(r-- > 0){
			this.F0Xor(fout, 0,  fin, 0,  rk, rk_offset + 0);
			this.F1Xor(fout, 8,  fin, 8,  rk, rk_offset + 4);
			this.F0Xor(fout, 16, fin, 16, rk, rk_offset + 8);
			this.F1Xor(fout, 24, fin, 24, rk, rk_offset + 12);
			rk_offset += 16;
			if(r){ /* swapping for encryption */
				jCastle.util.arrayCopy(fin, 0,  fout, 4, 28);
				jCastle.util.arrayCopy(fin, 28, fout, 0, 4);
			}
		}
		jCastle.util.arrayCopy(y, 0, fout, 0, 32);
	}

	Gfn4Inv(y, x, rk, _rk, r)
	{
		var fin = Buffer.alloc(16), fout = Buffer.alloc(16);
		var rk_offset = _rk;

		rk_offset += (r - 1) * 8;
		jCastle.util.arrayCopy(fin, 0, x, 0, 16);
		while(r-- > 0) {
			this.F0Xor(fout, 0, fin, 0, rk, rk_offset + 0);
			this.F1Xor(fout, 8, fin, 8, rk, rk_offset + 4);
			rk_offset -= 8;
			if(r){ /* swapping for decryption */
				jCastle.util.arrayCopy(fin, 0, fout, 12, 4);
				jCastle.util.arrayCopy(fin, 4, fout, 0,  12);
			}
		}
		jCastle.util.arrayCopy(y, 0, fout, 0, 16);
	}

	doubleSwap(lk, _lk)
	{
		var t = Buffer.alloc(16);
		var out = lk.slice(0);

		t[0]  = ((lk[_lk+0] << 7) | (lk[_lk+1]  >>> 1)) & 0xFF;
		t[1]  = ((lk[_lk+1] << 7) | (lk[_lk+2]  >>> 1)) & 0xFF;
		t[2]  = ((lk[_lk+2] << 7) | (lk[_lk+3]  >>> 1)) & 0xFF;
		t[3]  = ((lk[_lk+3] << 7) | (lk[_lk+4]  >>> 1)) & 0xFF;
		t[4]  = ((lk[_lk+4] << 7) | (lk[_lk+5]  >>> 1)) & 0xFF;
		t[5]  = ((lk[_lk+5] << 7) | (lk[_lk+6]  >>> 1)) & 0xFF;
		t[6]  = ((lk[_lk+6] << 7) | (lk[_lk+7]  >>> 1)) & 0xFF;
		t[7]  = ((lk[_lk+7] << 7) | (lk[_lk+15] & 0x7f)) & 0xFF;

		t[8]  = ((lk[_lk+8]  >>> 7) | (lk[_lk+0]  & 0xfe)) & 0xFF;
		t[9]  = ((lk[_lk+9]  >>> 7) | (lk[_lk+8]  << 1)) & 0xFF;
		t[10] = ((lk[_lk+10] >>> 7) | (lk[_lk+9]  << 1)) & 0xFF;
		t[11] = ((lk[_lk+11] >>> 7) | (lk[_lk+10] << 1)) & 0xFF;
		t[12] = ((lk[_lk+12] >>> 7) | (lk[_lk+11] << 1)) & 0xFF;
		t[13] = ((lk[_lk+13] >>> 7) | (lk[_lk+12] << 1)) & 0xFF;
		t[14] = ((lk[_lk+14] >>> 7) | (lk[_lk+13] << 1)) & 0xFF;
		t[15] = ((lk[_lk+15] >>> 7) | (lk[_lk+14] << 1)) & 0xFF;
		
		//jCastle.util.arrayCopy(lk, _lk, t, 0, 16);
		for (var i = 0; i < 16; i++) {
			out[_lk+i] = t[i];
		}
		return out;
	}

	setCON(con, iv, lk) 
	{
		var t = Buffer.alloc(2);
		var tmp;
		var con_offset = 0;

		jCastle.util.arrayCopy(t, 0, iv, 0, 2);
		//t = iv.slice(0);
		
		while(lk-- > 0){
			con[con_offset + 0] = (t[0] ^ 0xb7) & 0xff; /* P_16 = 0xb7e1 (natural logarithm) */
			con[con_offset + 1] = (t[1] ^ 0xe1) & 0xff;
			con[con_offset + 2] = (~((t[0] << 1) | (t[1] >>> 7))) & 0xFF;
			con[con_offset + 3] = (~((t[1] << 1) | (t[0] >>> 7))) & 0xFF;
			con[con_offset + 4] = (~t[0] ^ 0x24) & 0xFF; /* Q_16 = 0x243f (circle ratio) */
			con[con_offset + 5] = (~t[1] ^ 0x3f) & 0xFF;
			con[con_offset + 6] = t[1];
			con[con_offset + 7] = t[0];
			con_offset += 8;

			/* updating T */
			if(t[1] & 0x01){
				t[0] = (t[0] ^ 0xa8)  & 0xff;
				t[1] = (t[1] ^ 0x30)  & 0xff;
			}
			tmp = t[0] << 7;
			t[0] = ((t[0] >>> 1) | (t[1] << 7)) & 0xFF;
			t[1] = ((t[1] >>> 1) | tmp) & 0xFF;
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
	expandKey128(key) 
	{
		var iv = Buffer.from([0x42, 0x8a]); /* cubic root of 2 */
		var lk = Buffer.alloc(16);
		var con128 = Buffer.alloc(4 * 60);
		var i;
		var rk_offset = 0;

		/* generating CONi^(128) (0 <= i < 60, lk = 30) */
		this.setCON(con128, iv, 30);
		/* GFN_{4,12} (generating L from K) */
		this.Gfn4(lk, key, con128, 0, 12);

		jCastle.util.arrayCopy(this.roundKey, rk_offset, key, 0, 8); /* initial whitening key (WK0, WK1) */
		rk_offset += 8;
		for(i = 0; i < 9; i++) { /* round key (RKi (0 <= i < 36)) */
			jCastle.util.byteXor(this.roundKey, rk_offset, lk, 0, con128, i * 16 + (4 * 24), 16);
			if(i % 2){
				jCastle.util.byteXor(this.roundKey, rk_offset, this.roundKey, rk_offset, key, 0, 16); /* Xoring K */
			}
			lk = this.doubleSwap(lk, 0); /* Updating L (DoubleSwap function) */
			rk_offset += 16;
		}
		jCastle.util.arrayCopy(this.roundKey, rk_offset, key, 8, 8); /* final whitening key (WK2, WK3) */
	}

	/**
	 * Calculate the necessary round keys.
	 * The number of calculations depends on key size and block size.
	 * 
	 * @private
	 * @param {buffer} key key for encryption/decryption.
	 * @param {boolean} isEncryption true if it is encryption, otherwise false.
	 */
	expandKey192(key)
	{
		var iv = Buffer.from([0x71, 0x37]); /* cubic root of 3 */
		var key256 = Buffer.alloc(32);
		var lk = Buffer.alloc(32);
		var con192 = Buffer.alloc(4 * 84); // 336
		var i;
		var rk_offset = 0;

		jCastle.util.arrayCopy(key256, 0, key, 0, 24);
		for(i = 0; i < 8; i++){
			key256[i + 24] = (~key[i]) & 0xff;
		}

		/* generating CONi^(192) (0 <= i < 84, lk = 42) */
		this.setCON(con192, iv, 42);
		/* GFN_{8,10} (generating L from K) */
		this.Gfn8(lk, key256, con192, 0, 10);
		jCastle.util.byteXor(this.roundKey, rk_offset, key256, 0, key256, 16, 8); /* initial whitening key (WK0, WK1) */
		
		rk_offset += 8;
		for(i = 0; i < 11; i++){ /* round key (RKi (0 <= i < 44)) */
			/* the original source has a bug....
			   refer the clefia specification pdf */
			switch (i % 4) { 
				case 2: /* if i mod 4 = 2 or 3 */
				case 3:
					jCastle.util.byteXor(this.roundKey , rk_offset, lk, 16, con192, i * 16 + (4 * 40), 16); /* LR */
					if(i % 2){ /* if i is odd */
						jCastle.util.byteXor(this.roundKey, rk_offset, this.roundKey , rk_offset, key256, 0,  16); /* Xoring KL */
					}
					lk = this.doubleSwap(lk, 16); /* updating LR */
				break;
				case 0: /* if i mod 4 = 0 or 1 */
				case 1:
					jCastle.util.byteXor(this.roundKey, rk_offset, lk, 0,  con192, i * 16 + (4 * 40), 16); /* LL */
					if(i % 2){ /* if i is odd */
						jCastle.util.byteXor(this.roundKey, rk_offset, this.roundKey, rk_offset, key256, 16, 16); /* Xoring KR */
					}
					lk = this.doubleSwap(lk, 0);  /* updating LL */
					break;
			}
			rk_offset += 16;
		}
		jCastle.util.byteXor(this.roundKey, rk_offset, key256, 8, key256, 24, 8); /* final whitening key (WK2, WK3) */
	}

	/**
	 * Calculate the necessary round keys.
	 * The number of calculations depends on key size and block size.
	 * 
	 * @private
	 * @param {buffer} key key for encryption/decryption.
	 * @param {boolean} isEncryption true if it is encryption, otherwise false.
	 */
	expandKey256(key)
	{
		var iv = Buffer.from([0xb5, 0xc0]); /* cubic root of 5 */
		var lk = Buffer.alloc(32);
		var con256 = Buffer.alloc(4 * 92);
		var i;
		var rk_offset = 0;
		
		/* generating CONi^(256) (0 <= i < 92, lk = 46) */
		this.setCON(con256, iv, 46);
		/* GFN_{8,10} (generating L from K) */
		this.Gfn8(lk, key, con256, 0, 10);
		jCastle.util.byteXor(this.roundKey, rk_offset, key, 0, key, 16, 8); /* initial whitening key (WK0, WK1) */

		rk_offset += 8;
		for(i = 0; i < 13; i++){ /* round key (RKi (0 <= i < 52)) */
			/* the original source has a bug....
			   refer the clefia specification pdf */
			switch (i % 4) { 
				case 2: /* if i mod 4 = 2 or 3 */
				case 3:
					jCastle.util.byteXor(this.roundKey, rk_offset, lk, 16, con256, i * 16 + (4 * 40), 16); /* LR */
					if(i % 2){ /* if i is odd */
						jCastle.util.byteXor(this.roundKey, rk_offset, this.roundKey, rk_offset, key, 0,  16); /* Xoring KL */
					}
					lk = this.doubleSwap(lk, 16); /* updating LR */
					break;
				case 0: /* if i mod 4 = 0 or 1 */
				case 1:
					jCastle.util.byteXor(this.roundKey, rk_offset, lk, 0,  con256, i * 16 + (4 * 40), 16); /* LL */
					if(i % 2){ /* if i is odd */
						jCastle.util.byteXor(this.roundKey, rk_offset, this.roundKey, rk_offset, key, 16, 16); /* Xoring KR */
					}
					lk = this.doubleSwap(lk, 0);  /* updating LL */
					break;
			}
			rk_offset += 16;
		}
		jCastle.util.byteXor(this.roundKey, rk_offset, key, 8, key, 24, 8); /* final whitening key (WK2, WK3) */
	}

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
		this.masterKey = key;
		this.keyBits = key.length * 8;
		this.roundKey = Buffer.alloc(8 * 26 + 16);
		
		switch (this.keyBits) {
			case 128:
				this.expandKey128(key);
				this.rounds = 18;
				break;
			case 192:
				this.expandKey192(key);
				this.rounds = 22;
				break;
			case 256:
				this.expandKey256(key);
				this.rounds = 26;
				break;
		}
	}
}



/*
 * ---------
 * Constants
 * ---------
 */


/* S0 (8-bit S-box based on four 4-bit S-boxes) */
jCastle.algorithm.clefia.s0 = [
	0x57, 0x49, 0xd1, 0xc6, 0x2f, 0x33, 0x74, 0xfb,
	0x95, 0x6d, 0x82, 0xea, 0x0e, 0xb0, 0xa8, 0x1c,
	0x28, 0xd0, 0x4b, 0x92, 0x5c, 0xee, 0x85, 0xb1,
	0xc4, 0x0a, 0x76, 0x3d, 0x63, 0xf9, 0x17, 0xaf,
	0xbf, 0xa1, 0x19, 0x65, 0xf7, 0x7a, 0x32, 0x20,
	0x06, 0xce, 0xe4, 0x83, 0x9d, 0x5b, 0x4c, 0xd8,
	0x42, 0x5d, 0x2e, 0xe8, 0xd4, 0x9b, 0x0f, 0x13,
	0x3c, 0x89, 0x67, 0xc0, 0x71, 0xaa, 0xb6, 0xf5,
	0xa4, 0xbe, 0xfd, 0x8c, 0x12, 0x00, 0x97, 0xda,
	0x78, 0xe1, 0xcf, 0x6b, 0x39, 0x43, 0x55, 0x26,
	0x30, 0x98, 0xcc, 0xdd, 0xeb, 0x54, 0xb3, 0x8f,
	0x4e, 0x16, 0xfa, 0x22, 0xa5, 0x77, 0x09, 0x61,
	0xd6, 0x2a, 0x53, 0x37, 0x45, 0xc1, 0x6c, 0xae,
	0xef, 0x70, 0x08, 0x99, 0x8b, 0x1d, 0xf2, 0xb4,
	0xe9, 0xc7, 0x9f, 0x4a, 0x31, 0x25, 0xfe, 0x7c,
	0xd3, 0xa2, 0xbd, 0x56, 0x14, 0x88, 0x60, 0x0b,
	0xcd, 0xe2, 0x34, 0x50, 0x9e, 0xdc, 0x11, 0x05,
	0x2b, 0xb7, 0xa9, 0x48, 0xff, 0x66, 0x8a, 0x73,
	0x03, 0x75, 0x86, 0xf1, 0x6a, 0xa7, 0x40, 0xc2,
	0xb9, 0x2c, 0xdb, 0x1f, 0x58, 0x94, 0x3e, 0xed,
	0xfc, 0x1b, 0xa0, 0x04, 0xb8, 0x8d, 0xe6, 0x59,
	0x62, 0x93, 0x35, 0x7e, 0xca, 0x21, 0xdf, 0x47,
	0x15, 0xf3, 0xba, 0x7f, 0xa6, 0x69, 0xc8, 0x4d,
	0x87, 0x3b, 0x9c, 0x01, 0xe0, 0xde, 0x24, 0x52,
	0x7b, 0x0c, 0x68, 0x1e, 0x80, 0xb2, 0x5a, 0xe7,
	0xad, 0xd5, 0x23, 0xf4, 0x46, 0x3f, 0x91, 0xc9,
	0x6e, 0x84, 0x72, 0xbb, 0x0d, 0x18, 0xd9, 0x96,
	0xf0, 0x5f, 0x41, 0xac, 0x27, 0xc5, 0xe3, 0x3a,
	0x81, 0x6f, 0x07, 0xa3, 0x79, 0xf6, 0x2d, 0x38,
	0x1a, 0x44, 0x5e, 0xb5, 0xd2, 0xec, 0xcb, 0x90,
	0x9a, 0x36, 0xe5, 0x29, 0xc3, 0x4f, 0xab, 0x64,
	0x51, 0xf8, 0x10, 0xd7, 0xbc, 0x02, 0x7d, 0x8e
];

/* S1 (8-bit S-box based on inverse function) */
jCastle.algorithm.clefia.s1 = [
	0x6c, 0xda, 0xc3, 0xe9, 0x4e, 0x9d, 0x0a, 0x3d,
	0xb8, 0x36, 0xb4, 0x38, 0x13, 0x34, 0x0c, 0xd9,
	0xbf, 0x74, 0x94, 0x8f, 0xb7, 0x9c, 0xe5, 0xdc,
	0x9e, 0x07, 0x49, 0x4f, 0x98, 0x2c, 0xb0, 0x93,
	0x12, 0xeb, 0xcd, 0xb3, 0x92, 0xe7, 0x41, 0x60,
	0xe3, 0x21, 0x27, 0x3b, 0xe6, 0x19, 0xd2, 0x0e,
	0x91, 0x11, 0xc7, 0x3f, 0x2a, 0x8e, 0xa1, 0xbc,
	0x2b, 0xc8, 0xc5, 0x0f, 0x5b, 0xf3, 0x87, 0x8b,
	0xfb, 0xf5, 0xde, 0x20, 0xc6, 0xa7, 0x84, 0xce,
	0xd8, 0x65, 0x51, 0xc9, 0xa4, 0xef, 0x43, 0x53,
	0x25, 0x5d, 0x9b, 0x31, 0xe8, 0x3e, 0x0d, 0xd7,
	0x80, 0xff, 0x69, 0x8a, 0xba, 0x0b, 0x73, 0x5c,
	0x6e, 0x54, 0x15, 0x62, 0xf6, 0x35, 0x30, 0x52,
	0xa3, 0x16, 0xd3, 0x28, 0x32, 0xfa, 0xaa, 0x5e,
	0xcf, 0xea, 0xed, 0x78, 0x33, 0x58, 0x09, 0x7b,
	0x63, 0xc0, 0xc1, 0x46, 0x1e, 0xdf, 0xa9, 0x99,
	0x55, 0x04, 0xc4, 0x86, 0x39, 0x77, 0x82, 0xec,
	0x40, 0x18, 0x90, 0x97, 0x59, 0xdd, 0x83, 0x1f,
	0x9a, 0x37, 0x06, 0x24, 0x64, 0x7c, 0xa5, 0x56,
	0x48, 0x08, 0x85, 0xd0, 0x61, 0x26, 0xca, 0x6f,
	0x7e, 0x6a, 0xb6, 0x71, 0xa0, 0x70, 0x05, 0xd1,
	0x45, 0x8c, 0x23, 0x1c, 0xf0, 0xee, 0x89, 0xad,
	0x7a, 0x4b, 0xc2, 0x2f, 0xdb, 0x5a, 0x4d, 0x76,
	0x67, 0x17, 0x2d, 0xf4, 0xcb, 0xb1, 0x4a, 0xa8,
	0xb5, 0x22, 0x47, 0x3a, 0xd5, 0x10, 0x4c, 0x72,
	0xcc, 0x00, 0xf9, 0xe0, 0xfd, 0xe2, 0xfe, 0xae,
	0xf8, 0x5f, 0xab, 0xf1, 0x1b, 0x42, 0x81, 0xd6,
	0xbe, 0x44, 0x29, 0xa6, 0x57, 0xb9, 0xaf, 0xf2,
	0xd4, 0x75, 0x66, 0xbb, 0x68, 0x9f, 0x50, 0x02,
	0x01, 0x3c, 0x7f, 0x8d, 0x1a, 0x88, 0xbd, 0xac,
	0xf7, 0xe4, 0x79, 0x96, 0xa2, 0xfc, 0x6d, 0xb2,
	0x6b, 0x03, 0xe1, 0x2e, 0x7d, 0x14, 0x95, 0x1d
];


jCastle._algorithmInfo['clefia'] = {
	algorithm_type: 'crypt',
	block_size: 16,
	key_size: 32,
	min_key_size: 16,
	max_key_size: 32,
	key_sizes: [16, 24, 32],
	padding: 'zeros',
	object_name: 'clefia'
};

jCastle._algorithmInfo['clefia-128'] = {
	algorithm_type: 'crypt',
	block_size: 16,
	key_size: 16,
	min_key_size: 16,
	max_key_size: 16,
	padding: 'zeros',
	object_name: 'clefia'
};

jCastle._algorithmInfo['clefia-192'] = {
	algorithm_type: 'crypt',
	block_size: 16,
	key_size: 24,
	min_key_size: 24,
	max_key_size: 24,
	padding: 'zeros',
	object_name: 'clefia'
};

jCastle._algorithmInfo['clefia-256'] = {
	algorithm_type: 'crypt',
	block_size: 16,
	key_size: 32,
	min_key_size: 32,
	max_key_size: 32,
	padding: 'zeros',
	object_name: 'clefia'
};

module.exports = jCastle.algorithm.clefia;