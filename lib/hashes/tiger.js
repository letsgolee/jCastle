/**
 * A Javascript implemenation of Tiger
 *
 * @author Jacob Lee
 * 
 * Copyright (C) 2015-2022 Jacob Lee.
 */

// if (typeof UINT64 == 'undefined') {
// 	throw jCastle.exception("UINT64_REQUIRED", 'TIGER001');
// }

var jCastle = require('../jCastle');
require('../util');
var UINT64 = require('../uint64');

/*
There is a bug in under PHP 5.3.8 and you will have different results.

Reference:

1) https://bugs.php.net/bug.php?id=60221
According to the bug report, Tiger should be little endian, but php's order is big endian.
You can expect the perl's order is little endian.

http://stackoverflow.com/questions/16943297/tiger192-4-php-hash-generating-differente-values-in-different-php-versions
php 5.4.9-4 and php 5.3.10 result in different hash values!!!

I've tested php 5.3.8 and it gives wrong hashes.
php 5.4.10 gives a right one.
*/

jCastle.algorithm.tiger = class
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
        this._state = null;
        this._rounds = 3;
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
		this._state = [
			new UINT64(0x01234567, 0x89ABCDEF),
			new UINT64(0xFEDCBA98, 0x76543210),
			new UINT64(0xF096A5B4, 0xC3B2E187)
		];

		// tiger has two round types: 3, 4
		this._rounds = 'rounds' in options ? options.rounds : 3;

		switch (this._rounds) {
			case 3:
			case 4:
				break;
			default: 
				throw jCastle.throwException("INVALID_ROUNDS");
		}
	}

	/* one round of the hash function */
	tiger_round(a, b, c, x, mul)
	{
		var tmp;

		function byte64(x, n) {
			x = x.clone().shiftRight(8 * n).toNumber();
			return x & 255;
		}

		c = c.clone().xor(x);
		tmp = c.clone();
		a = a.clone().subtract(
		   jCastle.algorithm.tiger.t1[byte64(tmp, 0)].clone().xor(jCastle.algorithm.tiger.t2[byte64(tmp, 2)]).xor(jCastle.algorithm.tiger.t3[byte64(tmp, 4)]).xor(jCastle.algorithm.tiger.t4[byte64(tmp, 6)])
		);
		b = b.clone().add(
			jCastle.algorithm.tiger.t4[byte64(tmp, 1)].clone().xor(jCastle.algorithm.tiger.t3[byte64(tmp, 3)]).xor(jCastle.algorithm.tiger.t2[byte64(tmp,5)]).xor(jCastle.algorithm.tiger.t1[byte64(tmp,7)])
		);

		tmp = b.clone();
		switch (mul) {
			case 5:  b = tmp.clone().shiftLeft(2).add(tmp); break;
			case 7:  b = tmp.clone().shiftLeft(3).subtract(tmp); break;
			case 9:  b = tmp.clone().shiftLeft(3).add(tmp); break;
		}
		// b = b.multiply(mul);

		return [a, b, c];
	}

	/* one complete pass */
	pass(a, b, c, x, mul)
	{
		var tmp;

		tmp = this.tiger_round(a, b, c, x[0], mul); a = tmp[0]; b = tmp[1]; c = tmp[2]; 
		tmp = this.tiger_round(b, c, a, x[1], mul); b = tmp[0]; c = tmp[1]; a = tmp[2]; 
		tmp = this.tiger_round(c, a, b, x[2], mul); c = tmp[0]; a = tmp[1]; b = tmp[2]; 
		tmp = this.tiger_round(a, b, c, x[3], mul); a = tmp[0]; b = tmp[1]; c = tmp[2]; 
		tmp = this.tiger_round(b, c, a, x[4], mul); b = tmp[0]; c = tmp[1]; a = tmp[2]; 
		tmp = this.tiger_round(c, a, b, x[5], mul); c = tmp[0]; a = tmp[1]; b = tmp[2]; 
		tmp = this.tiger_round(a, b, c, x[6], mul); a = tmp[0]; b = tmp[1]; c = tmp[2]; 
		tmp = this.tiger_round(b, c, a, x[7], mul); b = tmp[0]; c = tmp[1]; a = tmp[2];
		return [a, b, c];
	}

	/* The key mixing schedule */
	key_schedule(x)
	{
		x[0] = x[0].clone().subtract(x[7].clone().xor(new UINT64(0xA5A5A5A5, 0xA5A5A5A5))); 
		x[1] = x[1].clone().xor(x[0]);
		x[2] = x[2].clone().add(x[1]);
		x[3] = x[3].clone().subtract(x[2].clone().xor(x[1].clone().not().shiftLeft(19)));
		x[4] = x[4].clone().xor(x[3]); 
		x[5] = x[5].clone().add(x[4]);
		x[6] = x[6].clone().subtract(x[5].clone().xor(x[4].clone().not().shiftRight(23)));
		x[7] = x[7].clone().xor(x[6]);
		x[0] = x[0].clone().add(x[7]);
		x[1] = x[1].clone().subtract(x[0].clone().xor(x[7].clone().not().shiftLeft(19)));
		x[2] = x[2].clone().xor(x[1]);
		x[3] = x[3].clone().add(x[2]);
		x[4] = x[4].clone().subtract(x[3].clone().xor(x[2].clone().not().shiftRight(23)));
		x[5] = x[5].clone().xor(x[4]);
		x[6] = x[6].clone().add(x[5]);
		x[7] = x[7].clone().subtract(x[6].clone().xor(new UINT64(0x01234567, 0x89ABCDEF)));
	}

	/**
	 * processes digesting.
	 * 
	 * @public
	 * @param {buffer} input input data to be digested.
	 */
	process(input)
	{
		var a, b, c;
		var i;
		var H = this._state;
		var tmp;
		var passes = this._rounds - 3;

		/* load words */
		// buffer contents have been transferred to the _block[] array via
		var block = [];
		var block_size = jCastle._algorithmInfo[this.algoName].block_size;
		for (var i = 0; i < block_size / 8; i++) {
			block[i] = new UINT64(
				input.readInt32LE(i * 8 + 4),
				input.readInt32LE(i * 8)
			);
		}
		a = H[0];
		b = H[1];
		c = H[2];

		tmp = this.pass(a, b, c, block, 5); a = tmp[0]; b = tmp[1]; c = tmp[2];
		this.key_schedule(block);
		tmp = this.pass(c, a, b, block, 7); c = tmp[0]; a = tmp[1]; b = tmp[2];
		this.key_schedule(block);
		tmp = this.pass(b, c, a, block, 9); b = tmp[0]; c = tmp[1]; a = tmp[2];

		for (var no = 0; no < passes; no++) {
			this.key_schedule(block);
			tmp = this.pass(a, b, c, block, 9); a = tmp[0]; b = tmp[1]; c = tmp[2];
			var tmpa = a; a = c; c = b; b = tmpa;
		}

		/* store state */
		H[0] = a.xor(H[0]);
		H[1] = b.subtract(H[1]);
		H[2] = c.add(H[2]);

		this._state = H;
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
		var index = input_len - pos;
		var pads = 0;

		// append the '1' bit
		pads++; index++;

		// if the length is currently above 56 bytes we append zeros
		// then compress.  Then we can fall back to padding zeros and length
		// encoding like normal.
		if (index > 56) {
			while (index < 64) {
				pads++; index++;
			}
			index = 0;
			pos += 64;
		}

		// pad upto 56 bytes of zeroes 
		while (index < 56) {
			pads++; index++;
		}
		
		var length_pos = pads;
		pads += 8;
		
		var padding = Buffer.alloc(pads);
		
		padding[0] = 0x01;
		padding.writeInt32LE(input_len * 8, length_pos, true);
		
		return Buffer.concat([input, padding]);
	}

	/**
	 * finishes digesting process and returns the result.
	 * 
	 * @public
	 * @returns the digested data.
	 */
	finish()
	{
		var output = Buffer.alloc(this._state.length * 8);
		for (var i = 0; i < this._state.length; i++) {
			output.writeInt32LE((this._state[i]._a00 & 0xffff) | ((this._state[i]._a16 & 0xffff) << 16), i * 8, true);
			output.writeInt32LE((this._state[i]._a32 & 0xffff) | ((this._state[i]._a48 & 0xffff) << 16), i * 8 + 4, true);
		}
		this._state = null;

		output = output.slice(0, jCastle._algorithmInfo[this.algoName].digest_size);
		return output;
	}
};

jCastle.algorithm.tiger.t1 = [
	new UINT64(0x02AAB17C, 0xF7E90C5E) /*    0 */, new UINT64(0xAC424B03, 0xE243A8EC) /*    1 */,
	new UINT64(0x72CD5BE3, 0x0DD5FCD3) /*    2 */, new UINT64(0x6D019B93, 0xF6F97F3A) /*    3 */,
	new UINT64(0xCD9978FF, 0xD21F9193) /*    4 */, new UINT64(0x7573A1C9, 0x708029E2) /*    5 */,
	new UINT64(0xB164326B, 0x922A83C3) /*    6 */, new UINT64(0x46883EEE, 0x04915870) /*    7 */,
	new UINT64(0xEAACE305, 0x7103ECE6) /*    8 */, new UINT64(0xC54169B8, 0x08A3535C) /*    9 */,
	new UINT64(0x4CE75491, 0x8DDEC47C) /*   10 */, new UINT64(0x0AA2F4DF, 0xDC0DF40C) /*   11 */,
	new UINT64(0x10B76F18, 0xA74DBEFA) /*   12 */, new UINT64(0xC6CCB623, 0x5AD1AB6A) /*   13 */,
	new UINT64(0x13726121, 0x572FE2FF) /*   14 */, new UINT64(0x1A488C6F, 0x199D921E) /*   15 */,
	new UINT64(0x4BC9F9F4, 0xDA0007CA) /*   16 */, new UINT64(0x26F5E6F6, 0xE85241C7) /*   17 */,
	new UINT64(0x859079DB, 0xEA5947B6) /*   18 */, new UINT64(0x4F1885C5, 0xC99E8C92) /*   19 */,
	new UINT64(0xD78E761E, 0xA96F864B) /*   20 */, new UINT64(0x8E36428C, 0x52B5C17D) /*   21 */,
	new UINT64(0x69CF6827, 0x373063C1) /*   22 */, new UINT64(0xB607C93D, 0x9BB4C56E) /*   23 */,
	new UINT64(0x7D820E76, 0x0E76B5EA) /*   24 */, new UINT64(0x645C9CC6, 0xF07FDC42) /*   25 */,
	new UINT64(0xBF38A078, 0x243342E0) /*   26 */, new UINT64(0x5F6B343C, 0x9D2E7D04) /*   27 */,
	new UINT64(0xF2C28AEB, 0x600B0EC6) /*   28 */, new UINT64(0x6C0ED85F, 0x7254BCAC) /*   29 */,
	new UINT64(0x71592281, 0xA4DB4FE5) /*   30 */, new UINT64(0x1967FA69, 0xCE0FED9F) /*   31 */,
	new UINT64(0xFD5293F8, 0xB96545DB) /*   32 */, new UINT64(0xC879E9D7, 0xF2A7600B) /*   33 */,
	new UINT64(0x86024892, 0x0193194E) /*   34 */, new UINT64(0xA4F9533B, 0x2D9CC0B3) /*   35 */,
	new UINT64(0x9053836C, 0x15957613) /*   36 */, new UINT64(0xDB6DCF8A, 0xFC357BF1) /*   37 */,
	new UINT64(0x18BEEA7A, 0x7A370F57) /*   38 */, new UINT64(0x037117CA, 0x50B99066) /*   39 */,
	new UINT64(0x6AB30A97, 0x74424A35) /*   40 */, new UINT64(0xF4E92F02, 0xE325249B) /*   41 */,
	new UINT64(0x7739DB07, 0x061CCAE1) /*   42 */, new UINT64(0xD8F3B49C, 0xECA42A05) /*   43 */,
	new UINT64(0xBD56BE3F, 0x51382F73) /*   44 */, new UINT64(0x45FAED58, 0x43B0BB28) /*   45 */,
	new UINT64(0x1C813D5C, 0x11BF1F83) /*   46 */, new UINT64(0x8AF0E4B6, 0xD75FA169) /*   47 */,
	new UINT64(0x33EE18A4, 0x87AD9999) /*   48 */, new UINT64(0x3C26E8EA, 0xB1C94410) /*   49 */,
	new UINT64(0xB510102B, 0xC0A822F9) /*   50 */, new UINT64(0x141EEF31, 0x0CE6123B) /*   51 */,
	new UINT64(0xFC65B900, 0x59DDB154) /*   52 */, new UINT64(0xE0158640, 0xC5E0E607) /*   53 */,
	new UINT64(0x884E0798, 0x26C3A3CF) /*   54 */, new UINT64(0x930D0D95, 0x23C535FD) /*   55 */,
	new UINT64(0x35638D75, 0x4E9A2B00) /*   56 */, new UINT64(0x4085FCCF, 0x40469DD5) /*   57 */,
	new UINT64(0xC4B17AD2, 0x8BE23A4C) /*   58 */, new UINT64(0xCAB2F0FC, 0x6A3E6A2E) /*   59 */,
	new UINT64(0x2860971A, 0x6B943FCD) /*   60 */, new UINT64(0x3DDE6EE2, 0x12E30446) /*   61 */,
	new UINT64(0x6222F32A, 0xE01765AE) /*   62 */, new UINT64(0x5D550BB5, 0x478308FE) /*   63 */,
	new UINT64(0xA9EFA98D, 0xA0EDA22A) /*   64 */, new UINT64(0xC351A716, 0x86C40DA7) /*   65 */,
	new UINT64(0x1105586D, 0x9C867C84) /*   66 */, new UINT64(0xDCFFEE85, 0xFDA22853) /*   67 */,
	new UINT64(0xCCFBD026, 0x2C5EEF76) /*   68 */, new UINT64(0xBAF294CB, 0x8990D201) /*   69 */,
	new UINT64(0xE69464F5, 0x2AFAD975) /*   70 */, new UINT64(0x94B013AF, 0xDF133E14) /*   71 */,
	new UINT64(0x06A7D1A3, 0x2823C958) /*   72 */, new UINT64(0x6F95FE51, 0x30F61119) /*   73 */,
	new UINT64(0xD92AB34E, 0x462C06C0) /*   74 */, new UINT64(0xED7BDE33, 0x887C71D2) /*   75 */,
	new UINT64(0x79746D6E, 0x6518393E) /*   76 */, new UINT64(0x5BA41938, 0x5D713329) /*   77 */,
	new UINT64(0x7C1BA6B9, 0x48A97564) /*   78 */, new UINT64(0x31987C19, 0x7BFDAC67) /*   79 */,
	new UINT64(0xDE6C23C4, 0x4B053D02) /*   80 */, new UINT64(0x581C49FE, 0xD002D64D) /*   81 */,
	new UINT64(0xDD474D63, 0x38261571) /*   82 */, new UINT64(0xAA4546C3, 0xE473D062) /*   83 */,
	new UINT64(0x928FCE34, 0x9455F860) /*   84 */, new UINT64(0x48161BBA, 0xCAAB94D9) /*   85 */,
	new UINT64(0x63912430, 0x770E6F68) /*   86 */, new UINT64(0x6EC8A5E6, 0x02C6641C) /*   87 */,
	new UINT64(0x87282515, 0x337DDD2B) /*   88 */, new UINT64(0x2CDA6B42, 0x034B701B) /*   89 */,
	new UINT64(0xB03D37C1, 0x81CB096D) /*   90 */, new UINT64(0xE1084382, 0x66C71C6F) /*   91 */,
	new UINT64(0x2B3180C7, 0xEB51B255) /*   92 */, new UINT64(0xDF92B82F, 0x96C08BBC) /*   93 */,
	new UINT64(0x5C68C8C0, 0xA632F3BA) /*   94 */, new UINT64(0x5504CC86, 0x1C3D0556) /*   95 */,
	new UINT64(0xABBFA4E5, 0x5FB26B8F) /*   96 */, new UINT64(0x41848B0A, 0xB3BACEB4) /*   97 */,
	new UINT64(0xB334A273, 0xAA445D32) /*   98 */, new UINT64(0xBCA696F0, 0xA85AD881) /*   99 */,
	new UINT64(0x24F6EC65, 0xB528D56C) /*  100 */, new UINT64(0x0CE1512E, 0x90F4524A) /*  101 */,
	new UINT64(0x4E9DD79D, 0x5506D35A) /*  102 */, new UINT64(0x258905FA, 0xC6CE9779) /*  103 */,
	new UINT64(0x2019295B, 0x3E109B33) /*  104 */, new UINT64(0xF8A9478B, 0x73A054CC) /*  105 */,
	new UINT64(0x2924F2F9, 0x34417EB0) /*  106 */, new UINT64(0x3993357D, 0x536D1BC4) /*  107 */,
	new UINT64(0x38A81AC2, 0x1DB6FF8B) /*  108 */, new UINT64(0x47C4FBF1, 0x7D6016BF) /*  109 */,
	new UINT64(0x1E0FAADD, 0x7667E3F5) /*  110 */, new UINT64(0x7ABCFF62, 0x938BEB96) /*  111 */,
	new UINT64(0xA78DAD94, 0x8FC179C9) /*  112 */, new UINT64(0x8F1F98B7, 0x2911E50D) /*  113 */,
	new UINT64(0x61E48EAE, 0x27121A91) /*  114 */, new UINT64(0x4D62F7AD, 0x31859808) /*  115 */,
	new UINT64(0xECEBA345, 0xEF5CEAEB) /*  116 */, new UINT64(0xF5CEB25E, 0xBC9684CE) /*  117 */,
	new UINT64(0xF633E20C, 0xB7F76221) /*  118 */, new UINT64(0xA32CDF06, 0xAB8293E4) /*  119 */,
	new UINT64(0x985A202C, 0xA5EE2CA4) /*  120 */, new UINT64(0xCF0B8447, 0xCC8A8FB1) /*  121 */,
	new UINT64(0x9F765244, 0x979859A3) /*  122 */, new UINT64(0xA8D516B1, 0xA1240017) /*  123 */,
	new UINT64(0x0BD7BA3E, 0xBB5DC726) /*  124 */, new UINT64(0xE54BCA55, 0xB86ADB39) /*  125 */,
	new UINT64(0x1D7A3AFD, 0x6C478063) /*  126 */, new UINT64(0x519EC608, 0xE7669EDD) /*  127 */,
	new UINT64(0x0E5715A2, 0xD149AA23) /*  128 */, new UINT64(0x177D4571, 0x848FF194) /*  129 */,
	new UINT64(0xEEB55F32, 0x41014C22) /*  130 */, new UINT64(0x0F5E5CA1, 0x3A6E2EC2) /*  131 */,
	new UINT64(0x8029927B, 0x75F5C361) /*  132 */, new UINT64(0xAD139FAB, 0xC3D6E436) /*  133 */,
	new UINT64(0x0D5DF1A9, 0x4CCF402F) /*  134 */, new UINT64(0x3E8BD948, 0xBEA5DFC8) /*  135 */,
	new UINT64(0xA5A0D357, 0xBD3FF77E) /*  136 */, new UINT64(0xA2D12E25, 0x1F74F645) /*  137 */,
	new UINT64(0x66FD9E52, 0x5E81A082) /*  138 */, new UINT64(0x2E0C90CE, 0x7F687A49) /*  139 */,
	new UINT64(0xC2E8BCBE, 0xBA973BC5) /*  140 */, new UINT64(0x000001BC, 0xE509745F) /*  141 */,
	new UINT64(0x423777BB, 0xE6DAB3D6) /*  142 */, new UINT64(0xD1661C7E, 0xAEF06EB5) /*  143 */,
	new UINT64(0xA1781F35, 0x4DAACFD8) /*  144 */, new UINT64(0x2D11284A, 0x2B16AFFC) /*  145 */,
	new UINT64(0xF1FC4F67, 0xFA891D1F) /*  146 */, new UINT64(0x73ECC25D, 0xCB920ADA) /*  147 */,
	new UINT64(0xAE610C22, 0xC2A12651) /*  148 */, new UINT64(0x96E0A810, 0xD356B78A) /*  149 */,
	new UINT64(0x5A9A381F, 0x2FE7870F) /*  150 */, new UINT64(0xD5AD62ED, 0xE94E5530) /*  151 */,
	new UINT64(0xD225E5E8, 0x368D1427) /*  152 */, new UINT64(0x65977B70, 0xC7AF4631) /*  153 */,
	new UINT64(0x99F889B2, 0xDE39D74F) /*  154 */, new UINT64(0x233F30BF, 0x54E1D143) /*  155 */,
	new UINT64(0x9A9675D3, 0xD9A63C97) /*  156 */, new UINT64(0x5470554F, 0xF334F9A8) /*  157 */,
	new UINT64(0x166ACB74, 0x4A4F5688) /*  158 */, new UINT64(0x70C74CAA, 0xB2E4AEAD) /*  159 */,
	new UINT64(0xF0D09164, 0x6F294D12) /*  160 */, new UINT64(0x57B82A89, 0x684031D1) /*  161 */,
	new UINT64(0xEFD95A5A, 0x61BE0B6B) /*  162 */, new UINT64(0x2FBD12E9, 0x69F2F29A) /*  163 */,
	new UINT64(0x9BD37013, 0xFEFF9FE8) /*  164 */, new UINT64(0x3F9B0404, 0xD6085A06) /*  165 */,
	new UINT64(0x4940C1F3, 0x166CFE15) /*  166 */, new UINT64(0x09542C4D, 0xCDF3DEFB) /*  167 */,
	new UINT64(0xB4C52183, 0x85CD5CE3) /*  168 */, new UINT64(0xC935B7DC, 0x4462A641) /*  169 */,
	new UINT64(0x3417F8A6, 0x8ED3B63F) /*  170 */, new UINT64(0xB8095929, 0x5B215B40) /*  171 */,
	new UINT64(0xF99CDAEF, 0x3B8C8572) /*  172 */, new UINT64(0x018C0614, 0xF8FCB95D) /*  173 */,
	new UINT64(0x1B14ACCD, 0x1A3ACDF3) /*  174 */, new UINT64(0x84D471F2, 0x00BB732D) /*  175 */,
	new UINT64(0xC1A3110E, 0x95E8DA16) /*  176 */, new UINT64(0x430A7220, 0xBF1A82B8) /*  177 */,
	new UINT64(0xB77E090D, 0x39DF210E) /*  178 */, new UINT64(0x5EF4BD9F, 0x3CD05E9D) /*  179 */,
	new UINT64(0x9D4FF6DA, 0x7E57A444) /*  180 */, new UINT64(0xDA1D60E1, 0x83D4A5F8) /*  181 */,
	new UINT64(0xB287C384, 0x17998E47) /*  182 */, new UINT64(0xFE3EDC12, 0x1BB31886) /*  183 */,
	new UINT64(0xC7FE3CCC, 0x980CCBEF) /*  184 */, new UINT64(0xE46FB590, 0x189BFD03) /*  185 */,
	new UINT64(0x3732FD46, 0x9A4C57DC) /*  186 */, new UINT64(0x7EF700A0, 0x7CF1AD65) /*  187 */,
	new UINT64(0x59C64468, 0xA31D8859) /*  188 */, new UINT64(0x762FB0B4, 0xD45B61F6) /*  189 */,
	new UINT64(0x155BAED0, 0x99047718) /*  190 */, new UINT64(0x68755E4C, 0x3D50BAA6) /*  191 */,
	new UINT64(0xE9214E7F, 0x22D8B4DF) /*  192 */, new UINT64(0x2ADDBF53, 0x2EAC95F4) /*  193 */,
	new UINT64(0x32AE3909, 0xB4BD0109) /*  194 */, new UINT64(0x834DF537, 0xB08E3450) /*  195 */,
	new UINT64(0xFA209DA8, 0x4220728D) /*  196 */, new UINT64(0x9E691D9B, 0x9EFE23F7) /*  197 */,
	new UINT64(0x0446D288, 0xC4AE8D7F) /*  198 */, new UINT64(0x7B4CC524, 0xE169785B) /*  199 */,
	new UINT64(0x21D87F01, 0x35CA1385) /*  200 */, new UINT64(0xCEBB400F, 0x137B8AA5) /*  201 */,
	new UINT64(0x272E2B66, 0x580796BE) /*  202 */, new UINT64(0x36122641, 0x25C2B0DE) /*  203 */,
	new UINT64(0x057702BD, 0xAD1EFBB2) /*  204 */, new UINT64(0xD4BABB8E, 0xACF84BE9) /*  205 */,
	new UINT64(0x91583139, 0x641BC67B) /*  206 */, new UINT64(0x8BDC2DE0, 0x8036E024) /*  207 */,
	new UINT64(0x603C8156, 0xF49F68ED) /*  208 */, new UINT64(0xF7D236F7, 0xDBEF5111) /*  209 */,
	new UINT64(0x9727C459, 0x8AD21E80) /*  210 */, new UINT64(0xA08A0896, 0x670A5FD7) /*  211 */,
	new UINT64(0xCB4A8F43, 0x09EBA9CB) /*  212 */, new UINT64(0x81AF564B, 0x0F7036A1) /*  213 */,
	new UINT64(0xC0B99AA7, 0x78199ABD) /*  214 */, new UINT64(0x959F1EC8, 0x3FC8E952) /*  215 */,
	new UINT64(0x8C505077, 0x794A81B9) /*  216 */, new UINT64(0x3ACAAF8F, 0x056338F0) /*  217 */,
	new UINT64(0x07B43F50, 0x627A6778) /*  218 */, new UINT64(0x4A44AB49, 0xF5ECCC77) /*  219 */,
	new UINT64(0x3BC3D6E4, 0xB679EE98) /*  220 */, new UINT64(0x9CC0D4D1, 0xCF14108C) /*  221 */,
	new UINT64(0x4406C00B, 0x206BC8A0) /*  222 */, new UINT64(0x82A18854, 0xC8D72D89) /*  223 */,
	new UINT64(0x67E366B3, 0x5C3C432C) /*  224 */, new UINT64(0xB923DD61, 0x102B37F2) /*  225 */,
	new UINT64(0x56AB2779, 0xD884271D) /*  226 */, new UINT64(0xBE83E1B0, 0xFF1525AF) /*  227 */,
	new UINT64(0xFB7C65D4, 0x217E49A9) /*  228 */, new UINT64(0x6BDBE0E7, 0x6D48E7D4) /*  229 */,
	new UINT64(0x08DF8287, 0x45D9179E) /*  230 */, new UINT64(0x22EA6A9A, 0xDD53BD34) /*  231 */,
	new UINT64(0xE36E141C, 0x5622200A) /*  232 */, new UINT64(0x7F805D1B, 0x8CB750EE) /*  233 */,
	new UINT64(0xAFE5C7A5, 0x9F58E837) /*  234 */, new UINT64(0xE27F996A, 0x4FB1C23C) /*  235 */,
	new UINT64(0xD3867DFB, 0x0775F0D0) /*  236 */, new UINT64(0xD0E673DE, 0x6E88891A) /*  237 */,
	new UINT64(0x123AEB9E, 0xAFB86C25) /*  238 */, new UINT64(0x30F1D5D5, 0xC145B895) /*  239 */,
	new UINT64(0xBB434A2D, 0xEE7269E7) /*  240 */, new UINT64(0x78CB67EC, 0xF931FA38) /*  241 */,
	new UINT64(0xF33B0372, 0x323BBF9C) /*  242 */, new UINT64(0x52D66336, 0xFB279C74) /*  243 */,
	new UINT64(0x505F33AC, 0x0AFB4EAA) /*  244 */, new UINT64(0xE8A5CD99, 0xA2CCE187) /*  245 */,
	new UINT64(0x53497480, 0x1E2D30BB) /*  246 */, new UINT64(0x8D2D5711, 0xD5876D90) /*  247 */,
	new UINT64(0x1F1A4128, 0x91BC038E) /*  248 */, new UINT64(0xD6E2E71D, 0x82E56648) /*  249 */,
	new UINT64(0x74036C3A, 0x497732B7) /*  250 */, new UINT64(0x89B67ED9, 0x6361F5AB) /*  251 */,
	new UINT64(0xFFED95D8, 0xF1EA02A2) /*  252 */, new UINT64(0xE72B3BD6, 0x1464D43D) /*  253 */,
	new UINT64(0xA6300F17, 0x0BDC4820) /*  254 */, new UINT64(0xEBC18760, 0xED78A77A) /*  255 */
];

jCastle.algorithm.tiger.t2 = [
	new UINT64(0xE6A6BE5A, 0x05A12138) /*  256 */, new UINT64(0xB5A122A5, 0xB4F87C98) /*  257 */,
	new UINT64(0x563C6089, 0x140B6990) /*  258 */, new UINT64(0x4C46CB2E, 0x391F5DD5) /*  259 */,
	new UINT64(0xD932ADDB, 0xC9B79434) /*  260 */, new UINT64(0x08EA70E4, 0x2015AFF5) /*  261 */,
	new UINT64(0xD765A667, 0x3E478CF1) /*  262 */, new UINT64(0xC4FB757E, 0xAB278D99) /*  263 */,
	new UINT64(0xDF11C686, 0x2D6E0692) /*  264 */, new UINT64(0xDDEB84F1, 0x0D7F3B16) /*  265 */,
	new UINT64(0x6F2EF604, 0xA665EA04) /*  266 */, new UINT64(0x4A8E0F0F, 0xF0E0DFB3) /*  267 */,
	new UINT64(0xA5EDEEF8, 0x3DBCBA51) /*  268 */, new UINT64(0xFC4F0A2A, 0x0EA4371E) /*  269 */,
	new UINT64(0xE83E1DA8, 0x5CB38429) /*  270 */, new UINT64(0xDC8FF882, 0xBA1B1CE2) /*  271 */,
	new UINT64(0xCD45505E, 0x8353E80D) /*  272 */, new UINT64(0x18D19A00, 0xD4DB0717) /*  273 */,
	new UINT64(0x34A0CFED, 0xA5F38101) /*  274 */, new UINT64(0x0BE77E51, 0x8887CAF2) /*  275 */,
	new UINT64(0x1E341438, 0xB3C45136) /*  276 */, new UINT64(0xE05797F4, 0x9089CCF9) /*  277 */,
	new UINT64(0xFFD23F9D, 0xF2591D14) /*  278 */, new UINT64(0x543DDA22, 0x8595C5CD) /*  279 */,
	new UINT64(0x661F81FD, 0x99052A33) /*  280 */, new UINT64(0x8736E641, 0xDB0F7B76) /*  281 */,
	new UINT64(0x15227725, 0x418E5307) /*  282 */, new UINT64(0xE25F7F46, 0x162EB2FA) /*  283 */,
	new UINT64(0x48A8B212, 0x6C13D9FE) /*  284 */, new UINT64(0xAFDC5417, 0x92E76EEA) /*  285 */,
	new UINT64(0x03D912BF, 0xC6D1898F) /*  286 */, new UINT64(0x31B1AAFA, 0x1B83F51B) /*  287 */,
	new UINT64(0xF1AC2796, 0xE42AB7D9) /*  288 */, new UINT64(0x40A3A7D7, 0xFCD2EBAC) /*  289 */,
	new UINT64(0x1056136D, 0x0AFBBCC5) /*  290 */, new UINT64(0x7889E1DD, 0x9A6D0C85) /*  291 */,
	new UINT64(0xD3352578, 0x2A7974AA) /*  292 */, new UINT64(0xA7E25D09, 0x078AC09B) /*  293 */,
	new UINT64(0xBD4138B3, 0xEAC6EDD0) /*  294 */, new UINT64(0x920ABFBE, 0x71EB9E70) /*  295 */,
	new UINT64(0xA2A5D0F5, 0x4FC2625C) /*  296 */, new UINT64(0xC054E36B, 0x0B1290A3) /*  297 */,
	new UINT64(0xF6DD59FF, 0x62FE932B) /*  298 */, new UINT64(0x35373545, 0x11A8AC7D) /*  299 */,
	new UINT64(0xCA845E91, 0x72FADCD4) /*  300 */, new UINT64(0x84F82B60, 0x329D20DC) /*  301 */,
	new UINT64(0x79C62CE1, 0xCD672F18) /*  302 */, new UINT64(0x8B09A2AD, 0xD124642C) /*  303 */,
	new UINT64(0xD0C1E96A, 0x19D9E726) /*  304 */, new UINT64(0x5A786A9B, 0x4BA9500C) /*  305 */,
	new UINT64(0x0E020336, 0x634C43F3) /*  306 */, new UINT64(0xC17B474A, 0xEB66D822) /*  307 */,
	new UINT64(0x6A731AE3, 0xEC9BAAC2) /*  308 */, new UINT64(0x8226667A, 0xE0840258) /*  309 */,
	new UINT64(0x67D45676, 0x91CAECA5) /*  310 */, new UINT64(0x1D94155C, 0x4875ADB5) /*  311 */,
	new UINT64(0x6D00FD98, 0x5B813FDF) /*  312 */, new UINT64(0x51286EFC, 0xB774CD06) /*  313 */,
	new UINT64(0x5E883447, 0x1FA744AF) /*  314 */, new UINT64(0xF72CA0AE, 0xE761AE2E) /*  315 */,
	new UINT64(0xBE40E4CD, 0xAEE8E09A) /*  316 */, new UINT64(0xE9970BBB, 0x5118F665) /*  317 */,
	new UINT64(0x726E4BEB, 0x33DF1964) /*  318 */, new UINT64(0x703B0007, 0x29199762) /*  319 */,
	new UINT64(0x4631D816, 0xF5EF30A7) /*  320 */, new UINT64(0xB880B5B5, 0x1504A6BE) /*  321 */,
	new UINT64(0x641793C3, 0x7ED84B6C) /*  322 */, new UINT64(0x7B21ED77, 0xF6E97D96) /*  323 */,
	new UINT64(0x77630631, 0x2EF96B73) /*  324 */, new UINT64(0xAE528948, 0xE86FF3F4) /*  325 */,
	new UINT64(0x53DBD7F2, 0x86A3F8F8) /*  326 */, new UINT64(0x16CADCE7, 0x4CFC1063) /*  327 */,
	new UINT64(0x005C19BD, 0xFA52C6DD) /*  328 */, new UINT64(0x68868F5D, 0x64D46AD3) /*  329 */,
	new UINT64(0x3A9D512C, 0xCF1E186A) /*  330 */, new UINT64(0x367E62C2, 0x385660AE) /*  331 */,
	new UINT64(0xE359E7EA, 0x77DCB1D7) /*  332 */, new UINT64(0x526C0773, 0x749ABE6E) /*  333 */,
	new UINT64(0x735AE5F9, 0xD09F734B) /*  334 */, new UINT64(0x493FC7CC, 0x8A558BA8) /*  335 */,
	new UINT64(0xB0B9C153, 0x3041AB45) /*  336 */, new UINT64(0x321958BA, 0x470A59BD) /*  337 */,
	new UINT64(0x852DB00B, 0x5F46C393) /*  338 */, new UINT64(0x91209B2B, 0xD336B0E5) /*  339 */,
	new UINT64(0x6E604F7D, 0x659EF19F) /*  340 */, new UINT64(0xB99A8AE2, 0x782CCB24) /*  341 */,
	new UINT64(0xCCF52AB6, 0xC814C4C7) /*  342 */, new UINT64(0x4727D9AF, 0xBE11727B) /*  343 */,
	new UINT64(0x7E950D0C, 0x0121B34D) /*  344 */, new UINT64(0x756F4356, 0x70AD471F) /*  345 */,
	new UINT64(0xF5ADD442, 0x615A6849) /*  346 */, new UINT64(0x4E87E099, 0x80B9957A) /*  347 */,
	new UINT64(0x2ACFA1DF, 0x50AEE355) /*  348 */, new UINT64(0xD898263A, 0xFD2FD556) /*  349 */,
	new UINT64(0xC8F4924D, 0xD80C8FD6) /*  350 */, new UINT64(0xCF99CA3D, 0x754A173A) /*  351 */,
	new UINT64(0xFE477BAC, 0xAF91BF3C) /*  352 */, new UINT64(0xED5371F6, 0xD690C12D) /*  353 */,
	new UINT64(0x831A5C28, 0x5E687094) /*  354 */, new UINT64(0xC5D3C90A, 0x3708A0A4) /*  355 */,
	new UINT64(0x0F7F9037, 0x17D06580) /*  356 */, new UINT64(0x19F9BB13, 0xB8FDF27F) /*  357 */,
	new UINT64(0xB1BD6F1B, 0x4D502843) /*  358 */, new UINT64(0x1C761BA3, 0x8FFF4012) /*  359 */,
	new UINT64(0x0D1530C4, 0xE2E21F3B) /*  360 */, new UINT64(0x8943CE69, 0xA7372C8A) /*  361 */,
	new UINT64(0xE5184E11, 0xFEB5CE66) /*  362 */, new UINT64(0x618BDB80, 0xBD736621) /*  363 */,
	new UINT64(0x7D29BAD6, 0x8B574D0B) /*  364 */, new UINT64(0x81BB613E, 0x25E6FE5B) /*  365 */,
	new UINT64(0x071C9C10, 0xBC07913F) /*  366 */, new UINT64(0xC7BEEB79, 0x09AC2D97) /*  367 */,
	new UINT64(0xC3E58D35, 0x3BC5D757) /*  368 */, new UINT64(0xEB017892, 0xF38F61E8) /*  369 */,
	new UINT64(0xD4EFFB9C, 0x9B1CC21A) /*  370 */, new UINT64(0x99727D26, 0xF494F7AB) /*  371 */,
	new UINT64(0xA3E063A2, 0x956B3E03) /*  372 */, new UINT64(0x9D4A8B9A, 0x4AA09C30) /*  373 */,
	new UINT64(0x3F6AB7D5, 0x00090FB4) /*  374 */, new UINT64(0x9CC0F2A0, 0x57268AC0) /*  375 */,
	new UINT64(0x3DEE9D2D, 0xEDBF42D1) /*  376 */, new UINT64(0x330F49C8, 0x7960A972) /*  377 */,
	new UINT64(0xC6B27202, 0x87421B41) /*  378 */, new UINT64(0x0AC59EC0, 0x7C00369C) /*  379 */,
	new UINT64(0xEF4EAC49, 0xCB353425) /*  380 */, new UINT64(0xF450244E, 0xEF0129D8) /*  381 */,
	new UINT64(0x8ACC46E5, 0xCAF4DEB6) /*  382 */, new UINT64(0x2FFEAB63, 0x989263F7) /*  383 */,
	new UINT64(0x8F7CB9FE, 0x5D7A4578) /*  384 */, new UINT64(0x5BD8F764, 0x4E634635) /*  385 */,
	new UINT64(0x427A7315, 0xBF2DC900) /*  386 */, new UINT64(0x17D0C4AA, 0x2125261C) /*  387 */,
	new UINT64(0x3992486C, 0x93518E50) /*  388 */, new UINT64(0xB4CBFEE0, 0xA2D7D4C3) /*  389 */,
	new UINT64(0x7C75D620, 0x2C5DDD8D) /*  390 */, new UINT64(0xDBC295D8, 0xE35B6C61) /*  391 */,
	new UINT64(0x60B369D3, 0x02032B19) /*  392 */, new UINT64(0xCE42685F, 0xDCE44132) /*  393 */,
	new UINT64(0x06F3DDB9, 0xDDF65610) /*  394 */, new UINT64(0x8EA4D21D, 0xB5E148F0) /*  395 */,
	new UINT64(0x20B0FCE6, 0x2FCD496F) /*  396 */, new UINT64(0x2C1B9123, 0x58B0EE31) /*  397 */,
	new UINT64(0xB28317B8, 0x18F5A308) /*  398 */, new UINT64(0xA89C1E18, 0x9CA6D2CF) /*  399 */,
	new UINT64(0x0C6B1857, 0x6AAADBC8) /*  400 */, new UINT64(0xB65DEAA9, 0x1299FAE3) /*  401 */,
	new UINT64(0xFB2B794B, 0x7F1027E7) /*  402 */, new UINT64(0x04E4317F, 0x443B5BEB) /*  403 */,
	new UINT64(0x4B852D32, 0x5939D0A6) /*  404 */, new UINT64(0xD5AE6BEE, 0xFB207FFC) /*  405 */,
	new UINT64(0x309682B2, 0x81C7D374) /*  406 */, new UINT64(0xBAE309A1, 0x94C3B475) /*  407 */,
	new UINT64(0x8CC3F97B, 0x13B49F05) /*  408 */, new UINT64(0x98A9422F, 0xF8293967) /*  409 */,
	new UINT64(0x244B16B0, 0x1076FF7C) /*  410 */, new UINT64(0xF8BF571C, 0x663D67EE) /*  411 */,
	new UINT64(0x1F0D6758, 0xEEE30DA1) /*  412 */, new UINT64(0xC9B611D9, 0x7ADEB9B7) /*  413 */,
	new UINT64(0xB7AFD588, 0x7B6C57A2) /*  414 */, new UINT64(0x6290AE84, 0x6B984FE1) /*  415 */,
	new UINT64(0x94DF4CDE, 0xACC1A5FD) /*  416 */, new UINT64(0x058A5BD1, 0xC5483AFF) /*  417 */,
	new UINT64(0x63166CC1, 0x42BA3C37) /*  418 */, new UINT64(0x8DB8526E, 0xB2F76F40) /*  419 */,
	new UINT64(0xE1088003, 0x6F0D6D4E) /*  420 */, new UINT64(0x9E0523C9, 0x971D311D) /*  421 */,
	new UINT64(0x45EC2824, 0xCC7CD691) /*  422 */, new UINT64(0x575B8359, 0xE62382C9) /*  423 */,
	new UINT64(0xFA9E400D, 0xC4889995) /*  424 */, new UINT64(0xD1823ECB, 0x45721568) /*  425 */,
	new UINT64(0xDAFD983B, 0x8206082F) /*  426 */, new UINT64(0xAA7D2908, 0x2386A8CB) /*  427 */,
	new UINT64(0x269FCD44, 0x03B87588) /*  428 */, new UINT64(0x1B91F5F7, 0x28BDD1E0) /*  429 */,
	new UINT64(0xE4669F39, 0x040201F6) /*  430 */, new UINT64(0x7A1D7C21, 0x8CF04ADE) /*  431 */,
	new UINT64(0x65623C29, 0xD79CE5CE) /*  432 */, new UINT64(0x23684490, 0x96C00BB1) /*  433 */,
	new UINT64(0xAB9BF187, 0x9DA503BA) /*  434 */, new UINT64(0xBC23ECB1, 0xA458058E) /*  435 */,
	new UINT64(0x9A58DF01, 0xBB401ECC) /*  436 */, new UINT64(0xA070E868, 0xA85F143D) /*  437 */,
	new UINT64(0x4FF18830, 0x7DF2239E) /*  438 */, new UINT64(0x14D565B4, 0x1A641183) /*  439 */,
	new UINT64(0xEE133374, 0x52701602) /*  440 */, new UINT64(0x950E3DCF, 0x3F285E09) /*  441 */,
	new UINT64(0x59930254, 0xB9C80953) /*  442 */, new UINT64(0x3BF29940, 0x8930DA6D) /*  443 */,
	new UINT64(0xA955943F, 0x53691387) /*  444 */, new UINT64(0xA15EDECA, 0xA9CB8784) /*  445 */,
	new UINT64(0x29142127, 0x352BE9A0) /*  446 */, new UINT64(0x76F0371F, 0xFF4E7AFB) /*  447 */,
	new UINT64(0x0239F450, 0x274F2228) /*  448 */, new UINT64(0xBB073AF0, 0x1D5E868B) /*  449 */,
	new UINT64(0xBFC80571, 0xC10E96C1) /*  450 */, new UINT64(0xD2670885, 0x68222E23) /*  451 */,
	new UINT64(0x9671A3D4, 0x8E80B5B0) /*  452 */, new UINT64(0x55B5D38A, 0xE193BB81) /*  453 */,
	new UINT64(0x693AE2D0, 0xA18B04B8) /*  454 */, new UINT64(0x5C48B4EC, 0xADD5335F) /*  455 */,
	new UINT64(0xFD743B19, 0x4916A1CA) /*  456 */, new UINT64(0x25770181, 0x34BE98C4) /*  457 */,
	new UINT64(0xE77987E8, 0x3C54A4AD) /*  458 */, new UINT64(0x28E11014, 0xDA33E1B9) /*  459 */,
	new UINT64(0x270CC59E, 0x226AA213) /*  460 */, new UINT64(0x71495F75, 0x6D1A5F60) /*  461 */,
	new UINT64(0x9BE853FB, 0x60AFEF77) /*  462 */, new UINT64(0xADC786A7, 0xF7443DBF) /*  463 */,
	new UINT64(0x09044561, 0x73B29A82) /*  464 */, new UINT64(0x58BC7A66, 0xC232BD5E) /*  465 */,
	new UINT64(0xF306558C, 0x673AC8B2) /*  466 */, new UINT64(0x41F639C6, 0xB6C9772A) /*  467 */,
	new UINT64(0x216DEFE9, 0x9FDA35DA) /*  468 */, new UINT64(0x11640CC7, 0x1C7BE615) /*  469 */,
	new UINT64(0x93C43694, 0x565C5527) /*  470 */, new UINT64(0xEA038E62, 0x46777839) /*  471 */,
	new UINT64(0xF9ABF3CE, 0x5A3E2469) /*  472 */, new UINT64(0x741E768D, 0x0FD312D2) /*  473 */,
	new UINT64(0x0144B883, 0xCED652C6) /*  474 */, new UINT64(0xC20B5A5B, 0xA33F8552) /*  475 */,
	new UINT64(0x1AE69633, 0xC3435A9D) /*  476 */, new UINT64(0x97A28CA4, 0x088CFDEC) /*  477 */,
	new UINT64(0x8824A43C, 0x1E96F420) /*  478 */, new UINT64(0x37612FA6, 0x6EEEA746) /*  479 */,
	new UINT64(0x6B4CB165, 0xF9CF0E5A) /*  480 */, new UINT64(0x43AA1C06, 0xA0ABFB4A) /*  481 */,
	new UINT64(0x7F4DC26F, 0xF162796B) /*  482 */, new UINT64(0x6CBACC8E, 0x54ED9B0F) /*  483 */,
	new UINT64(0xA6B7FFEF, 0xD2BB253E) /*  484 */, new UINT64(0x2E25BC95, 0xB0A29D4F) /*  485 */,
	new UINT64(0x86D6A58B, 0xDEF1388C) /*  486 */, new UINT64(0xDED74AC5, 0x76B6F054) /*  487 */,
	new UINT64(0x8030BDBC, 0x2B45805D) /*  488 */, new UINT64(0x3C81AF70, 0xE94D9289) /*  489 */,
	new UINT64(0x3EFF6DDA, 0x9E3100DB) /*  490 */, new UINT64(0xB38DC39F, 0xDFCC8847) /*  491 */,
	new UINT64(0x12388552, 0x8D17B87E) /*  492 */, new UINT64(0xF2DA0ED2, 0x40B1B642) /*  493 */,
	new UINT64(0x44CEFADC, 0xD54BF9A9) /*  494 */, new UINT64(0x1312200E, 0x433C7EE6) /*  495 */,
	new UINT64(0x9FFCC84F, 0x3A78C748) /*  496 */, new UINT64(0xF0CD1F72, 0x248576BB) /*  497 */,
	new UINT64(0xEC697405, 0x3638CFE4) /*  498 */, new UINT64(0x2BA7B67C, 0x0CEC4E4C) /*  499 */,
	new UINT64(0xAC2F4DF3, 0xE5CE32ED) /*  500 */, new UINT64(0xCB33D143, 0x26EA4C11) /*  501 */,
	new UINT64(0xA4E9044C, 0xC77E58BC) /*  502 */, new UINT64(0x5F513293, 0xD934FCEF) /*  503 */,
	new UINT64(0x5DC96455, 0x06E55444) /*  504 */, new UINT64(0x50DE418F, 0x317DE40A) /*  505 */,
	new UINT64(0x388CB31A, 0x69DDE259) /*  506 */, new UINT64(0x2DB4A834, 0x55820A86) /*  507 */,
	new UINT64(0x9010A91E, 0x84711AE9) /*  508 */, new UINT64(0x4DF7F0B7, 0xB1498371) /*  509 */,
	new UINT64(0xD62A2EAB, 0xC0977179) /*  510 */, new UINT64(0x22FAC097, 0xAA8D5C0E) /*  511 */
];

jCastle.algorithm.tiger.t3 = [
	new UINT64(0xF49FCC2F, 0xF1DAF39B) /*  512 */, new UINT64(0x487FD5C6, 0x6FF29281) /*  513 */,
	new UINT64(0xE8A30667, 0xFCDCA83F) /*  514 */, new UINT64(0x2C9B4BE3, 0xD2FCCE63) /*  515 */,
	new UINT64(0xDA3FF74B, 0x93FBBBC2) /*  516 */, new UINT64(0x2FA165D2, 0xFE70BA66) /*  517 */,
	new UINT64(0xA103E279, 0x970E93D4) /*  518 */, new UINT64(0xBECDEC77, 0xB0E45E71) /*  519 */,
	new UINT64(0xCFB41E72, 0x3985E497) /*  520 */, new UINT64(0xB70AAA02, 0x5EF75017) /*  521 */,
	new UINT64(0xD42309F0, 0x3840B8E0) /*  522 */, new UINT64(0x8EFC1AD0, 0x35898579) /*  523 */,
	new UINT64(0x96C6920B, 0xE2B2ABC5) /*  524 */, new UINT64(0x66AF4163, 0x375A9172) /*  525 */,
	new UINT64(0x2174ABDC, 0xCA7127FB) /*  526 */, new UINT64(0xB33CCEA6, 0x4A72FF41) /*  527 */,
	new UINT64(0xF04A4933, 0x083066A5) /*  528 */, new UINT64(0x8D970ACD, 0xD7289AF5) /*  529 */,
	new UINT64(0x8F96E8E0, 0x31C8C25E) /*  530 */, new UINT64(0xF3FEC022, 0x76875D47) /*  531 */,
	new UINT64(0xEC7BF310, 0x056190DD) /*  532 */, new UINT64(0xF5ADB0AE, 0xBB0F1491) /*  533 */,
	new UINT64(0x9B50F885, 0x0FD58892) /*  534 */, new UINT64(0x49754883, 0x58B74DE8) /*  535 */,
	new UINT64(0xA3354FF6, 0x91531C61) /*  536 */, new UINT64(0x0702BBE4, 0x81D2C6EE) /*  537 */,
	new UINT64(0x89FB2405, 0x7DEDED98) /*  538 */, new UINT64(0xAC307513, 0x8596E902) /*  539 */,
	new UINT64(0x1D2D3580, 0x172772ED) /*  540 */, new UINT64(0xEB738FC2, 0x8E6BC30D) /*  541 */,
	new UINT64(0x5854EF8F, 0x63044326) /*  542 */, new UINT64(0x9E5C5232, 0x5ADD3BBE) /*  543 */,
	new UINT64(0x90AA53CF, 0x325C4623) /*  544 */, new UINT64(0xC1D24D51, 0x349DD067) /*  545 */,
	new UINT64(0x2051CFEE, 0xA69EA624) /*  546 */, new UINT64(0x13220F0A, 0x862E7E4F) /*  547 */,
	new UINT64(0xCE393994, 0x04E04864) /*  548 */, new UINT64(0xD9C42CA4, 0x7086FCB7) /*  549 */,
	new UINT64(0x685AD223, 0x8A03E7CC) /*  550 */, new UINT64(0x066484B2, 0xAB2FF1DB) /*  551 */,
	new UINT64(0xFE9D5D70, 0xEFBF79EC) /*  552 */, new UINT64(0x5B13B9DD, 0x9C481854) /*  553 */,
	new UINT64(0x15F0D475, 0xED1509AD) /*  554 */, new UINT64(0x0BEBCD06, 0x0EC79851) /*  555 */,
	new UINT64(0xD58C6791, 0x183AB7F8) /*  556 */, new UINT64(0xD1187C50, 0x52F3EEE4) /*  557 */,
	new UINT64(0xC95D1192, 0xE54E82FF) /*  558 */, new UINT64(0x86EEA14C, 0xB9AC6CA2) /*  559 */,
	new UINT64(0x3485BEB1, 0x53677D5D) /*  560 */, new UINT64(0xDD191D78, 0x1F8C492A) /*  561 */,
	new UINT64(0xF60866BA, 0xA784EBF9) /*  562 */, new UINT64(0x518F643B, 0xA2D08C74) /*  563 */,
	new UINT64(0x8852E956, 0xE1087C22) /*  564 */, new UINT64(0xA768CB8D, 0xC410AE8D) /*  565 */,
	new UINT64(0x38047726, 0xBFEC8E1A) /*  566 */, new UINT64(0xA67738B4, 0xCD3B45AA) /*  567 */,
	new UINT64(0xAD16691C, 0xEC0DDE19) /*  568 */, new UINT64(0xC6D43193, 0x80462E07) /*  569 */,
	new UINT64(0xC5A5876D, 0x0BA61938) /*  570 */, new UINT64(0x16B9FA1F, 0xA58FD840) /*  571 */,
	new UINT64(0x188AB117, 0x3CA74F18) /*  572 */, new UINT64(0xABDA2F98, 0xC99C021F) /*  573 */,
	new UINT64(0x3E0580AB, 0x134AE816) /*  574 */, new UINT64(0x5F3B05B7, 0x73645ABB) /*  575 */,
	new UINT64(0x2501A2BE, 0x5575F2F6) /*  576 */, new UINT64(0x1B2F7400, 0x4E7E8BA9) /*  577 */,
	new UINT64(0x1CD75803, 0x71E8D953) /*  578 */, new UINT64(0x7F6ED895, 0x62764E30) /*  579 */,
	new UINT64(0xB15926FF, 0x596F003D) /*  580 */, new UINT64(0x9F65293D, 0xA8C5D6B9) /*  581 */,
	new UINT64(0x6ECEF04D, 0xD690F84C) /*  582 */, new UINT64(0x4782275F, 0xFF33AF88) /*  583 */,
	new UINT64(0xE4143308, 0x3F820801) /*  584 */, new UINT64(0xFD0DFE40, 0x9A1AF9B5) /*  585 */,
	new UINT64(0x4325A334, 0x2CDB396B) /*  586 */, new UINT64(0x8AE77E62, 0xB301B252) /*  587 */,
	new UINT64(0xC36F9E9F, 0x6655615A) /*  588 */, new UINT64(0x85455A2D, 0x92D32C09) /*  589 */,
	new UINT64(0xF2C7DEA9, 0x49477485) /*  590 */, new UINT64(0x63CFB4C1, 0x33A39EBA) /*  591 */,
	new UINT64(0x83B040CC, 0x6EBC5462) /*  592 */, new UINT64(0x3B9454C8, 0xFDB326B0) /*  593 */,
	new UINT64(0x56F56A9E, 0x87FFD78C) /*  594 */, new UINT64(0x2DC2940D, 0x99F42BC6) /*  595 */,
	new UINT64(0x98F7DF09, 0x6B096E2D) /*  596 */, new UINT64(0x19A6E01E, 0x3AD852BF) /*  597 */,
	new UINT64(0x42A99CCB, 0xDBD4B40B) /*  598 */, new UINT64(0xA59998AF, 0x45E9C559) /*  599 */,
	new UINT64(0x366295E8, 0x07D93186) /*  600 */, new UINT64(0x6B48181B, 0xFAA1F773) /*  601 */,
	new UINT64(0x1FEC57E2, 0x157A0A1D) /*  602 */, new UINT64(0x4667446A, 0xF6201AD5) /*  603 */,
	new UINT64(0xE615EBCA, 0xCFB0F075) /*  604 */, new UINT64(0xB8F31F4F, 0x68290778) /*  605 */,
	new UINT64(0x22713ED6, 0xCE22D11E) /*  606 */, new UINT64(0x3057C1A7, 0x2EC3C93B) /*  607 */,
	new UINT64(0xCB46ACC3, 0x7C3F1F2F) /*  608 */, new UINT64(0xDBB893FD, 0x02AAF50E) /*  609 */,
	new UINT64(0x331FD92E, 0x600B9FCF) /*  610 */, new UINT64(0xA498F961, 0x48EA3AD6) /*  611 */,
	new UINT64(0xA8D8426E, 0x8B6A83EA) /*  612 */, new UINT64(0xA089B274, 0xB7735CDC) /*  613 */,
	new UINT64(0x87F6B373, 0x1E524A11) /*  614 */, new UINT64(0x118808E5, 0xCBC96749) /*  615 */,
	new UINT64(0x9906E4C7, 0xB19BD394) /*  616 */, new UINT64(0xAFED7F7E, 0x9B24A20C) /*  617 */,
	new UINT64(0x6509EADE, 0xEB3644A7) /*  618 */, new UINT64(0x6C1EF1D3, 0xE8EF0EDE) /*  619 */,
	new UINT64(0xB9C97D43, 0xE9798FB4) /*  620 */, new UINT64(0xA2F2D784, 0x740C28A3) /*  621 */,
	new UINT64(0x7B849647, 0x6197566F) /*  622 */, new UINT64(0x7A5BE3E6, 0xB65F069D) /*  623 */,
	new UINT64(0xF96330ED, 0x78BE6F10) /*  624 */, new UINT64(0xEEE60DE7, 0x7A076A15) /*  625 */,
	new UINT64(0x2B4BEE4A, 0xA08B9BD0) /*  626 */, new UINT64(0x6A56A63E, 0xC7B8894E) /*  627 */,
	new UINT64(0x02121359, 0xBA34FEF4) /*  628 */, new UINT64(0x4CBF99F8, 0x283703FC) /*  629 */,
	new UINT64(0x39807135, 0x0CAF30C8) /*  630 */, new UINT64(0xD0A77A89, 0xF017687A) /*  631 */,
	new UINT64(0xF1C1A9EB, 0x9E423569) /*  632 */, new UINT64(0x8C797628, 0x2DEE8199) /*  633 */,
	new UINT64(0x5D1737A5, 0xDD1F7ABD) /*  634 */, new UINT64(0x4F53433C, 0x09A9FA80) /*  635 */,
	new UINT64(0xFA8B0C53, 0xDF7CA1D9) /*  636 */, new UINT64(0x3FD9DCBC, 0x886CCB77) /*  637 */,
	new UINT64(0xC040917C, 0xA91B4720) /*  638 */, new UINT64(0x7DD00142, 0xF9D1DCDF) /*  639 */,
	new UINT64(0x8476FC1D, 0x4F387B58) /*  640 */, new UINT64(0x23F8E7C5, 0xF3316503) /*  641 */,
	new UINT64(0x032A2244, 0xE7E37339) /*  642 */, new UINT64(0x5C87A5D7, 0x50F5A74B) /*  643 */,
	new UINT64(0x082B4CC4, 0x3698992E) /*  644 */, new UINT64(0xDF917BEC, 0xB858F63C) /*  645 */,
	new UINT64(0x3270B8FC, 0x5BF86DDA) /*  646 */, new UINT64(0x10AE72BB, 0x29B5DD76) /*  647 */,
	new UINT64(0x576AC94E, 0x7700362B) /*  648 */, new UINT64(0x1AD112DA, 0xC61EFB8F) /*  649 */,
	new UINT64(0x691BC30E, 0xC5FAA427) /*  650 */, new UINT64(0xFF246311, 0xCC327143) /*  651 */,
	new UINT64(0x3142368E, 0x30E53206) /*  652 */, new UINT64(0x71380E31, 0xE02CA396) /*  653 */,
	new UINT64(0x958D5C96, 0x0AAD76F1) /*  654 */, new UINT64(0xF8D6F430, 0xC16DA536) /*  655 */,
	new UINT64(0xC8FFD13F, 0x1BE7E1D2) /*  656 */, new UINT64(0x7578AE66, 0x004DDBE1) /*  657 */,
	new UINT64(0x05833F01, 0x067BE646) /*  658 */, new UINT64(0xBB34B5AD, 0x3BFE586D) /*  659 */,
	new UINT64(0x095F34C9, 0xA12B97F0) /*  660 */, new UINT64(0x247AB645, 0x25D60CA8) /*  661 */,
	new UINT64(0xDCDBC6F3, 0x017477D1) /*  662 */, new UINT64(0x4A2E14D4, 0xDECAD24D) /*  663 */,
	new UINT64(0xBDB5E6D9, 0xBE0A1EEB) /*  664 */, new UINT64(0x2A7E70F7, 0x794301AB) /*  665 */,
	new UINT64(0xDEF42D8A, 0x270540FD) /*  666 */, new UINT64(0x01078EC0, 0xA34C22C1) /*  667 */,
	new UINT64(0xE5DE511A, 0xF4C16387) /*  668 */, new UINT64(0x7EBB3A52, 0xBD9A330A) /*  669 */,
	new UINT64(0x77697857, 0xAA7D6435) /*  670 */, new UINT64(0x004E8316, 0x03AE4C32) /*  671 */,
	new UINT64(0xE7A21020, 0xAD78E312) /*  672 */, new UINT64(0x9D41A70C, 0x6AB420F2) /*  673 */,
	new UINT64(0x28E06C18, 0xEA1141E6) /*  674 */, new UINT64(0xD2B28CBD, 0x984F6B28) /*  675 */,
	new UINT64(0x26B75F6C, 0x446E9D83) /*  676 */, new UINT64(0xBA47568C, 0x4D418D7F) /*  677 */,
	new UINT64(0xD80BADBF, 0xE6183D8E) /*  678 */, new UINT64(0x0E206D7F, 0x5F166044) /*  679 */,
	new UINT64(0xE258A439, 0x11CBCA3E) /*  680 */, new UINT64(0x723A1746, 0xB21DC0BC) /*  681 */,
	new UINT64(0xC7CAA854, 0xF5D7CDD3) /*  682 */, new UINT64(0x7CAC3288, 0x3D261D9C) /*  683 */,
	new UINT64(0x7690C264, 0x23BA942C) /*  684 */, new UINT64(0x17E55524, 0x478042B8) /*  685 */,
	new UINT64(0xE0BE4776, 0x56A2389F) /*  686 */, new UINT64(0x4D289B5E, 0x67AB2DA0) /*  687 */,
	new UINT64(0x44862B9C, 0x8FBBFD31) /*  688 */, new UINT64(0xB47CC804, 0x9D141365) /*  689 */,
	new UINT64(0x822C1B36, 0x2B91C793) /*  690 */, new UINT64(0x4EB14655, 0xFB13DFD8) /*  691 */,
	new UINT64(0x1ECBBA07, 0x14E2A97B) /*  692 */, new UINT64(0x6143459D, 0x5CDE5F14) /*  693 */,
	new UINT64(0x53A8FBF1, 0xD5F0AC89) /*  694 */, new UINT64(0x97EA04D8, 0x1C5E5B00) /*  695 */,
	new UINT64(0x622181A8, 0xD4FDB3F3) /*  696 */, new UINT64(0xE9BCD341, 0x572A1208) /*  697 */,
	new UINT64(0x14112586, 0x43CCE58A) /*  698 */, new UINT64(0x9144C5FE, 0xA4C6E0A4) /*  699 */,
	new UINT64(0x0D33D065, 0x65CF620F) /*  700 */, new UINT64(0x54A48D48, 0x9F219CA1) /*  701 */,
	new UINT64(0xC43E5EAC, 0x6D63C821) /*  702 */, new UINT64(0xA9728B3A, 0x72770DAF) /*  703 */,
	new UINT64(0xD7934E7B, 0x20DF87EF) /*  704 */, new UINT64(0xE35503B6, 0x1A3E86E5) /*  705 */,
	new UINT64(0xCAE321FB, 0xC819D504) /*  706 */, new UINT64(0x129A50B3, 0xAC60BFA6) /*  707 */,
	new UINT64(0xCD5E68EA, 0x7E9FB6C3) /*  708 */, new UINT64(0xB01C9019, 0x9483B1C7) /*  709 */,
	new UINT64(0x3DE93CD5, 0xC295376C) /*  710 */, new UINT64(0xAED52EDF, 0x2AB9AD13) /*  711 */,
	new UINT64(0x2E60F512, 0xC0A07884) /*  712 */, new UINT64(0xBC3D86A3, 0xE36210C9) /*  713 */,
	new UINT64(0x35269D9B, 0x163951CE) /*  714 */, new UINT64(0x0C7D6E2A, 0xD0CDB5FA) /*  715 */,
	new UINT64(0x59E86297, 0xD87F5733) /*  716 */, new UINT64(0x298EF221, 0x898DB0E7) /*  717 */,
	new UINT64(0x55000029, 0xD1A5AA7E) /*  718 */, new UINT64(0x8BC08AE1, 0xB5061B45) /*  719 */,
	new UINT64(0xC2C31C2B, 0x6C92703A) /*  720 */, new UINT64(0x94CC596B, 0xAF25EF42) /*  721 */,
	new UINT64(0x0A1D73DB, 0x22540456) /*  722 */, new UINT64(0x04B6A0F9, 0xD9C4179A) /*  723 */,
	new UINT64(0xEFFDAFA2, 0xAE3D3C60) /*  724 */, new UINT64(0xF7C8075B, 0xB49496C4) /*  725 */,
	new UINT64(0x9CC5C714, 0x1D1CD4E3) /*  726 */, new UINT64(0x78BD1638, 0x218E5534) /*  727 */,
	new UINT64(0xB2F11568, 0xF850246A) /*  728 */, new UINT64(0xEDFABCFA, 0x9502BC29) /*  729 */,
	new UINT64(0x796CE5F2, 0xDA23051B) /*  730 */, new UINT64(0xAAE128B0, 0xDC93537C) /*  731 */,
	new UINT64(0x3A493DA0, 0xEE4B29AE) /*  732 */, new UINT64(0xB5DF6B2C, 0x416895D7) /*  733 */,
	new UINT64(0xFCABBD25, 0x122D7F37) /*  734 */, new UINT64(0x70810B58, 0x105DC4B1) /*  735 */,
	new UINT64(0xE10FDD37, 0xF7882A90) /*  736 */, new UINT64(0x524DCAB5, 0x518A3F5C) /*  737 */,
	new UINT64(0x3C9E8587, 0x8451255B) /*  738 */, new UINT64(0x40298281, 0x19BD34E2) /*  739 */,
	new UINT64(0x74A05B6F, 0x5D3CECCB) /*  740 */, new UINT64(0xB6100215, 0x42E13ECA) /*  741 */,
	new UINT64(0x0FF979D1, 0x2F59E2AC) /*  742 */, new UINT64(0x6037DA27, 0xE4F9CC50) /*  743 */,
	new UINT64(0x5E92975A, 0x0DF1847D) /*  744 */, new UINT64(0xD66DE190, 0xD3E623FE) /*  745 */,
	new UINT64(0x5032D6B8, 0x7B568048) /*  746 */, new UINT64(0x9A36B7CE, 0x8235216E) /*  747 */,
	new UINT64(0x80272A7A, 0x24F64B4A) /*  748 */, new UINT64(0x93EFED8B, 0x8C6916F7) /*  749 */,
	new UINT64(0x37DDBFF4, 0x4CCE1555) /*  750 */, new UINT64(0x4B95DB5D, 0x4B99BD25) /*  751 */,
	new UINT64(0x92D3FDA1, 0x69812FC0) /*  752 */, new UINT64(0xFB1A4A9A, 0x90660BB6) /*  753 */,
	new UINT64(0x730C1969, 0x46A4B9B2) /*  754 */, new UINT64(0x81E289AA, 0x7F49DA68) /*  755 */,
	new UINT64(0x64669A0F, 0x83B1A05F) /*  756 */, new UINT64(0x27B3FF7D, 0x9644F48B) /*  757 */,
	new UINT64(0xCC6B615C, 0x8DB675B3) /*  758 */, new UINT64(0x674F20B9, 0xBCEBBE95) /*  759 */,
	new UINT64(0x6F312382, 0x75655982) /*  760 */, new UINT64(0x5AE48871, 0x3E45CF05) /*  761 */,
	new UINT64(0xBF619F99, 0x54C21157) /*  762 */, new UINT64(0xEABAC460, 0x40A8EAE9) /*  763 */,
	new UINT64(0x454C6FE9, 0xF2C0C1CD) /*  764 */, new UINT64(0x419CF649, 0x6412691C) /*  765 */,
	new UINT64(0xD3DC3BEF, 0x265B0F70) /*  766 */, new UINT64(0x6D0E60F5, 0xC3578A9E) /*  767 */
];
jCastle.algorithm.tiger.t4 = [
	new UINT64(0x5B0E6085, 0x26323C55) /*  768 */, new UINT64(0x1A46C1A9, 0xFA1B59F5) /*  769 */,
	new UINT64(0xA9E245A1, 0x7C4C8FFA) /*  770 */, new UINT64(0x65CA5159, 0xDB2955D7) /*  771 */,
	new UINT64(0x05DB0A76, 0xCE35AFC2) /*  772 */, new UINT64(0x81EAC77E, 0xA9113D45) /*  773 */,
	new UINT64(0x528EF88A, 0xB6AC0A0D) /*  774 */, new UINT64(0xA09EA253, 0x597BE3FF) /*  775 */,
	new UINT64(0x430DDFB3, 0xAC48CD56) /*  776 */, new UINT64(0xC4B3A67A, 0xF45CE46F) /*  777 */,
	new UINT64(0x4ECECFD8, 0xFBE2D05E) /*  778 */, new UINT64(0x3EF56F10, 0xB39935F0) /*  779 */,
	new UINT64(0x0B22D682, 0x9CD619C6) /*  780 */, new UINT64(0x17FD460A, 0x74DF2069) /*  781 */,
	new UINT64(0x6CF8CC8E, 0x8510ED40) /*  782 */, new UINT64(0xD6C824BF, 0x3A6ECAA7) /*  783 */,
	new UINT64(0x61243D58, 0x1A817049) /*  784 */, new UINT64(0x048BACB6, 0xBBC163A2) /*  785 */,
	new UINT64(0xD9A38AC2, 0x7D44CC32) /*  786 */, new UINT64(0x7FDDFF5B, 0xAAF410AB) /*  787 */,
	new UINT64(0xAD6D495A, 0xA804824B) /*  788 */, new UINT64(0xE1A6A74F, 0x2D8C9F94) /*  789 */,
	new UINT64(0xD4F78512, 0x35DEE8E3) /*  790 */, new UINT64(0xFD4B7F88, 0x6540D893) /*  791 */,
	new UINT64(0x247C2004, 0x2AA4BFDA) /*  792 */, new UINT64(0x096EA1C5, 0x17D1327C) /*  793 */,
	new UINT64(0xD56966B4, 0x361A6685) /*  794 */, new UINT64(0x277DA5C3, 0x1221057D) /*  795 */,
	new UINT64(0x94D59893, 0xA43ACFF7) /*  796 */, new UINT64(0x64F0C51C, 0xCDC02281) /*  797 */,
	new UINT64(0x3D33BCC4, 0xFF6189DB) /*  798 */, new UINT64(0xE005CB18, 0x4CE66AF1) /*  799 */,
	new UINT64(0xFF5CCD1D, 0x1DB99BEA) /*  800 */, new UINT64(0xB0B854A7, 0xFE42980F) /*  801 */,
	new UINT64(0x7BD46A6A, 0x718D4B9F) /*  802 */, new UINT64(0xD10FA8CC, 0x22A5FD8C) /*  803 */,
	new UINT64(0xD3148495, 0x2BE4BD31) /*  804 */, new UINT64(0xC7FA975F, 0xCB243847) /*  805 */,
	new UINT64(0x4886ED1E, 0x5846C407) /*  806 */, new UINT64(0x28CDDB79, 0x1EB70B04) /*  807 */,
	new UINT64(0xC2B00BE2, 0xF573417F) /*  808 */, new UINT64(0x5C959045, 0x2180F877) /*  809 */,
	new UINT64(0x7A6BDDFF, 0xF370EB00) /*  810 */, new UINT64(0xCE509E38, 0xD6D9D6A4) /*  811 */,
	new UINT64(0xEBEB0F00, 0x647FA702) /*  812 */, new UINT64(0x1DCC06CF, 0x76606F06) /*  813 */,
	new UINT64(0xE4D9F28B, 0xA286FF0A) /*  814 */, new UINT64(0xD85A305D, 0xC918C262) /*  815 */,
	new UINT64(0x475B1D87, 0x32225F54) /*  816 */, new UINT64(0x2D4FB516, 0x68CCB5FE) /*  817 */,
	new UINT64(0xA679B9D9, 0xD72BBA20) /*  818 */, new UINT64(0x53841C0D, 0x912D43A5) /*  819 */,
	new UINT64(0x3B7EAA48, 0xBF12A4E8) /*  820 */, new UINT64(0x781E0E47, 0xF22F1DDF) /*  821 */,
	new UINT64(0xEFF20CE6, 0x0AB50973) /*  822 */, new UINT64(0x20D261D1, 0x9DFFB742) /*  823 */,
	new UINT64(0x16A12B03, 0x062A2E39) /*  824 */, new UINT64(0x1960EB22, 0x39650495) /*  825 */,
	new UINT64(0x251C16FE, 0xD50EB8B8) /*  826 */, new UINT64(0x9AC0C330, 0xF826016E) /*  827 */,
	new UINT64(0xED152665, 0x953E7671) /*  828 */, new UINT64(0x02D63194, 0xA6369570) /*  829 */,
	new UINT64(0x5074F083, 0x94B1C987) /*  830 */, new UINT64(0x70BA598C, 0x90B25CE1) /*  831 */,
	new UINT64(0x794A1581, 0x0B9742F6) /*  832 */, new UINT64(0x0D5925E9, 0xFCAF8C6C) /*  833 */,
	new UINT64(0x3067716C, 0xD868744E) /*  834 */, new UINT64(0x910AB077, 0xE8D7731B) /*  835 */,
	new UINT64(0x6A61BBDB, 0x5AC42F61) /*  836 */, new UINT64(0x93513EFB, 0xF0851567) /*  837 */,
	new UINT64(0xF494724B, 0x9E83E9D5) /*  838 */, new UINT64(0xE887E198, 0x5C09648D) /*  839 */,
	new UINT64(0x34B1D3C6, 0x75370CFD) /*  840 */, new UINT64(0xDC35E433, 0xBC0D255D) /*  841 */,
	new UINT64(0xD0AAB842, 0x34131BE0) /*  842 */, new UINT64(0x08042A50, 0xB48B7EAF) /*  843 */,
	new UINT64(0x9997C4EE, 0x44A3AB35) /*  844 */, new UINT64(0x829A7B49, 0x201799D0) /*  845 */,
	new UINT64(0x263B8307, 0xB7C54441) /*  846 */, new UINT64(0x752F95F4, 0xFD6A6CA6) /*  847 */,
	new UINT64(0x92721740, 0x2C08C6E5) /*  848 */, new UINT64(0x2A8AB754, 0xA795D9EE) /*  849 */,
	new UINT64(0xA442F755, 0x2F72943D) /*  850 */, new UINT64(0x2C31334E, 0x19781208) /*  851 */,
	new UINT64(0x4FA98D7C, 0xEAEE6291) /*  852 */, new UINT64(0x55C3862F, 0x665DB309) /*  853 */,
	new UINT64(0xBD061017, 0x5D53B1F3) /*  854 */, new UINT64(0x46FE6CB8, 0x40413F27) /*  855 */,
	new UINT64(0x3FE03792, 0xDF0CFA59) /*  856 */, new UINT64(0xCFE70037, 0x2EB85E8F) /*  857 */,
	new UINT64(0xA7BE29E7, 0xADBCE118) /*  858 */, new UINT64(0xE544EE5C, 0xDE8431DD) /*  859 */,
	new UINT64(0x8A781B1B, 0x41F1873E) /*  860 */, new UINT64(0xA5C94C78, 0xA0D2F0E7) /*  861 */,
	new UINT64(0x39412E28, 0x77B60728) /*  862 */, new UINT64(0xA1265EF3, 0xAFC9A62C) /*  863 */,
	new UINT64(0xBCC2770C, 0x6A2506C5) /*  864 */, new UINT64(0x3AB66DD5, 0xDCE1CE12) /*  865 */,
	new UINT64(0xE65499D0, 0x4A675B37) /*  866 */, new UINT64(0x7D8F5234, 0x81BFD216) /*  867 */,
	new UINT64(0x0F6F64FC, 0xEC15F389) /*  868 */, new UINT64(0x74EFBE61, 0x8B5B13C8) /*  869 */,
	new UINT64(0xACDC82B7, 0x14273E1D) /*  870 */, new UINT64(0xDD40BFE0, 0x03199D17) /*  871 */,
	new UINT64(0x37E99257, 0xE7E061F8) /*  872 */, new UINT64(0xFA526269, 0x04775AAA) /*  873 */,
	new UINT64(0x8BBBF63A, 0x463D56F9) /*  874 */, new UINT64(0xF0013F15, 0x43A26E64) /*  875 */,
	new UINT64(0xA8307E9F, 0x879EC898) /*  876 */, new UINT64(0xCC4C27A4, 0x150177CC) /*  877 */,
	new UINT64(0x1B432F2C, 0xCA1D3348) /*  878 */, new UINT64(0xDE1D1F8F, 0x9F6FA013) /*  879 */,
	new UINT64(0x606602A0, 0x47A7DDD6) /*  880 */, new UINT64(0xD237AB64, 0xCC1CB2C7) /*  881 */,
	new UINT64(0x9B938E72, 0x25FCD1D3) /*  882 */, new UINT64(0xEC4E0370, 0x8E0FF476) /*  883 */,
	new UINT64(0xFEB2FBDA, 0x3D03C12D) /*  884 */, new UINT64(0xAE0BCED2, 0xEE43889A) /*  885 */,
	new UINT64(0x22CB8923, 0xEBFB4F43) /*  886 */, new UINT64(0x69360D01, 0x3CF7396D) /*  887 */,
	new UINT64(0x855E3602, 0xD2D4E022) /*  888 */, new UINT64(0x073805BA, 0xD01F784C) /*  889 */,
	new UINT64(0x33E17A13, 0x3852F546) /*  890 */, new UINT64(0xDF487405, 0x8AC7B638) /*  891 */,
	new UINT64(0xBA92B29C, 0x678AA14A) /*  892 */, new UINT64(0x0CE89FC7, 0x6CFAADCD) /*  893 */,
	new UINT64(0x5F9D4E09, 0x08339E34) /*  894 */, new UINT64(0xF1AFE929, 0x1F5923B9) /*  895 */,
	new UINT64(0x6E3480F6, 0x0F4A265F) /*  896 */, new UINT64(0xEEBF3A2A, 0xB29B841C) /*  897 */,
	new UINT64(0xE21938A8, 0x8F91B4AD) /*  898 */, new UINT64(0x57DFEFF8, 0x45C6D3C3) /*  899 */,
	new UINT64(0x2F006B0B, 0xF62CAAF2) /*  900 */, new UINT64(0x62F479EF, 0x6F75EE78) /*  901 */,
	new UINT64(0x11A55AD4, 0x1C8916A9) /*  902 */, new UINT64(0xF229D290, 0x84FED453) /*  903 */,
	new UINT64(0x42F1C27B, 0x16B000E6) /*  904 */, new UINT64(0x2B1F7674, 0x9823C074) /*  905 */,
	new UINT64(0x4B76ECA3, 0xC2745360) /*  906 */, new UINT64(0x8C98F463, 0xB91691BD) /*  907 */,
	new UINT64(0x14BCC93C, 0xF1ADE66A) /*  908 */, new UINT64(0x8885213E, 0x6D458397) /*  909 */,
	new UINT64(0x8E177DF0, 0x274D4711) /*  910 */, new UINT64(0xB49B73B5, 0x503F2951) /*  911 */,
	new UINT64(0x10168168, 0xC3F96B6B) /*  912 */, new UINT64(0x0E3D963B, 0x63CAB0AE) /*  913 */,
	new UINT64(0x8DFC4B56, 0x55A1DB14) /*  914 */, new UINT64(0xF789F135, 0x6E14DE5C) /*  915 */,
	new UINT64(0x683E68AF, 0x4E51DAC1) /*  916 */, new UINT64(0xC9A84F9D, 0x8D4B0FD9) /*  917 */,
	new UINT64(0x3691E03F, 0x52A0F9D1) /*  918 */, new UINT64(0x5ED86E46, 0xE1878E80) /*  919 */,
	new UINT64(0x3C711A0E, 0x99D07150) /*  920 */, new UINT64(0x5A0865B2, 0x0C4E9310) /*  921 */,
	new UINT64(0x56FBFC1F, 0xE4F0682E) /*  922 */, new UINT64(0xEA8D5DE3, 0x105EDF9B) /*  923 */,
	new UINT64(0x71ABFDB1, 0x2379187A) /*  924 */, new UINT64(0x2EB99DE1, 0xBEE77B9C) /*  925 */,
	new UINT64(0x21ECC0EA, 0x33CF4523) /*  926 */, new UINT64(0x59A4D752, 0x1805C7A1) /*  927 */,
	new UINT64(0x3896F5EB, 0x56AE7C72) /*  928 */, new UINT64(0xAA638F3D, 0xB18F75DC) /*  929 */,
	new UINT64(0x9F39358D, 0xABE9808E) /*  930 */, new UINT64(0xB7DEFA91, 0xC00B72AC) /*  931 */,
	new UINT64(0x6B5541FD, 0x62492D92) /*  932 */, new UINT64(0x6DC6DEE8, 0xF92E4D5B) /*  933 */,
	new UINT64(0x353F57AB, 0xC4BEEA7E) /*  934 */, new UINT64(0x735769D6, 0xDA5690CE) /*  935 */,
	new UINT64(0x0A234AA6, 0x42391484) /*  936 */, new UINT64(0xF6F95080, 0x28F80D9D) /*  937 */,
	new UINT64(0xB8E319A2, 0x7AB3F215) /*  938 */, new UINT64(0x31AD9C11, 0x51341A4D) /*  939 */,
	new UINT64(0x773C22A5, 0x7BEF5805) /*  940 */, new UINT64(0x45C7561A, 0x07968633) /*  941 */,
	new UINT64(0xF913DA9E, 0x249DBE36) /*  942 */, new UINT64(0xDA652D9B, 0x78A64C68) /*  943 */,
	new UINT64(0x4C27A97F, 0x3BC334EF) /*  944 */, new UINT64(0x76621220, 0xE66B17F4) /*  945 */,
	new UINT64(0x96774389, 0x9ACD7D0B) /*  946 */, new UINT64(0xF3EE5BCA, 0xE0ED6782) /*  947 */,
	new UINT64(0x409F7536, 0x00C879FC) /*  948 */, new UINT64(0x06D09A39, 0xB5926DB6) /*  949 */,
	new UINT64(0x6F83AEB0, 0x317AC588) /*  950 */, new UINT64(0x01E6CA4A, 0x86381F21) /*  951 */,
	new UINT64(0x66FF3462, 0xD19F3025) /*  952 */, new UINT64(0x72207C24, 0xDDFD3BFB) /*  953 */,
	new UINT64(0x4AF6B6D3, 0xE2ECE2EB) /*  954 */, new UINT64(0x9C994DBE, 0xC7EA08DE) /*  955 */,
	new UINT64(0x49ACE597, 0xB09A8BC4) /*  956 */, new UINT64(0xB38C4766, 0xCF0797BA) /*  957 */,
	new UINT64(0x131B9373, 0xC57C2A75) /*  958 */, new UINT64(0xB1822CCE, 0x61931E58) /*  959 */,
	new UINT64(0x9D7555B9, 0x09BA1C0C) /*  960 */, new UINT64(0x127FAFDD, 0x937D11D2) /*  961 */,
	new UINT64(0x29DA3BAD, 0xC66D92E4) /*  962 */, new UINT64(0xA2C1D571, 0x54C2ECBC) /*  963 */,
	new UINT64(0x58C5134D, 0x82F6FE24) /*  964 */, new UINT64(0x1C3AE351, 0x5B62274F) /*  965 */,
	new UINT64(0xE907C82E, 0x01CB8126) /*  966 */, new UINT64(0xF8ED0919, 0x13E37FCB) /*  967 */,
	new UINT64(0x3249D8F9, 0xC80046C9) /*  968 */, new UINT64(0x80CF9BED, 0xE388FB63) /*  969 */,
	new UINT64(0x1881539A, 0x116CF19E) /*  970 */, new UINT64(0x5103F3F7, 0x6BD52457) /*  971 */,
	new UINT64(0x15B7E6F5, 0xAE47F7A8) /*  972 */, new UINT64(0xDBD7C6DE, 0xD47E9CCF) /*  973 */,
	new UINT64(0x44E55C41, 0x0228BB1A) /*  974 */, new UINT64(0xB647D425, 0x5EDB4E99) /*  975 */,
	new UINT64(0x5D11882B, 0xB8AAFC30) /*  976 */, new UINT64(0xF5098BBB, 0x29D3212A) /*  977 */,
	new UINT64(0x8FB5EA14, 0xE90296B3) /*  978 */, new UINT64(0x677B9421, 0x57DD025A) /*  979 */,
	new UINT64(0xFB58E7C0, 0xA390ACB5) /*  980 */, new UINT64(0x89D3674C, 0x83BD4A01) /*  981 */,
	new UINT64(0x9E2DA4DF, 0x4BF3B93B) /*  982 */, new UINT64(0xFCC41E32, 0x8CAB4829) /*  983 */,
	new UINT64(0x03F38C96, 0xBA582C52) /*  984 */, new UINT64(0xCAD1BDBD, 0x7FD85DB2) /*  985 */,
	new UINT64(0xBBB442C1, 0x6082AE83) /*  986 */, new UINT64(0xB95FE86B, 0xA5DA9AB0) /*  987 */,
	new UINT64(0xB22E0467, 0x3771A93F) /*  988 */, new UINT64(0x845358C9, 0x493152D8) /*  989 */,
	new UINT64(0xBE2A4886, 0x97B4541E) /*  990 */, new UINT64(0x95A2DC2D, 0xD38E6966) /*  991 */,
	new UINT64(0xC02C11AC, 0x923C852B) /*  992 */, new UINT64(0x2388B199, 0x0DF2A87B) /*  993 */,
	new UINT64(0x7C8008FA, 0x1B4F37BE) /*  994 */, new UINT64(0x1F70D0C8, 0x4D54E503) /*  995 */,
	new UINT64(0x5490ADEC, 0x7ECE57D4) /*  996 */, new UINT64(0x002B3C27, 0xD9063A3A) /*  997 */,
	new UINT64(0x7EAEA384, 0x8030A2BF) /*  998 */, new UINT64(0xC602326D, 0xED2003C0) /*  999 */,
	new UINT64(0x83A7287D, 0x69A94086) /* 1000 */, new UINT64(0xC57A5FCB, 0x30F57A8A) /* 1001 */,
	new UINT64(0xB56844E4, 0x79EBE779) /* 1002 */, new UINT64(0xA373B40F, 0x05DCBCE9) /* 1003 */,
	new UINT64(0xD71A786E, 0x88570EE2) /* 1004 */, new UINT64(0x879CBACD, 0xBDE8F6A0) /* 1005 */,
	new UINT64(0x976AD1BC, 0xC164A32F) /* 1006 */, new UINT64(0xAB21E25E, 0x9666D78B) /* 1007 */,
	new UINT64(0x901063AA, 0xE5E5C33C) /* 1008 */, new UINT64(0x9818B344, 0x48698D90) /* 1009 */,
	new UINT64(0xE36487AE, 0x3E1E8ABB) /* 1010 */, new UINT64(0xAFBDF931, 0x893BDCB4) /* 1011 */,
	new UINT64(0x6345A0DC, 0x5FBBD519) /* 1012 */, new UINT64(0x8628FE26, 0x9B9465CA) /* 1013 */,
	new UINT64(0x1E5D0160, 0x3F9C51EC) /* 1014 */, new UINT64(0x4DE44006, 0xA15049B7) /* 1015 */,
	new UINT64(0xBF6C70E5, 0xF776CBB1) /* 1016 */, new UINT64(0x411218F2, 0xEF552BED) /* 1017 */,
	new UINT64(0xCB0C0708, 0x705A36A3) /* 1018 */, new UINT64(0xE74D1475, 0x4F986044) /* 1019 */,
	new UINT64(0xCD56D943, 0x0EA8280E) /* 1020 */, new UINT64(0xC12591D7, 0x535F5065) /* 1021 */,
	new UINT64(0xC83223F1, 0x720AEF96) /* 1022 */, new UINT64(0xC3A0396F, 0x7363A51F) /* 1023 */
];

jCastle.algorithm.Tiger = jCastle.algorithm.tiger;

jCastle._algorithmInfo['tiger'] = {//tiger-192
	algorithm_type: 'hash',
	object_name: 'tiger',
	block_size: 64,
	digest_size: 24,
	oid: "1.3.6.1.4.1.11591.12.2"
};

jCastle._algorithmInfo['tiger-128'] = {
	algorithm_type: 'hash',
	object_name: 'tiger',
	block_size: 64,
	digest_size: 16
	//oid: "1.3.6.1.4.1.11591.12.2"
};

jCastle._algorithmInfo['tiger-160'] = {
	algorithm_type: 'hash',
	object_name: 'tiger',
	block_size: 64,
	digest_size: 20
	//oid: "1.3.6.1.4.1.11591.12.2"
};

jCastle._algorithmInfo['tiger-192'] = {
	algorithm_type: 'hash',
	object_name: 'tiger',
	block_size: 64,
	digest_size: 24,
	oid: "1.3.6.1.4.1.11591.12.2"
};

module.exports = jCastle.algorithm.tiger;