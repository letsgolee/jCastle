/**
 * A Javascript implemenation of HAVAL
 * 
 * @author Jacob Lee
 * 
 * Copyright (C) 2015-2022 Jacob Lee.
 */

var jCastle = require('../jCastle');
require('../util');

jCastle.algorithm.haval = class
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
        this._rounds = 3; // defualt
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
		this._state = [0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344, 0xA4093822, 0x299F31D0, 0x082EFA98, 0xEC4E6C89];

		// haval has three round types: 3, 4, 5
		this._rounds = 'rounds' in options ? options.rounds : 3;

		switch (this._rounds) {
			case 3:
			case 4:
			case 5:
				break;
			default: 
				throw jCastle.exception("INVALID_ROUNDS", 'HAVAL001');
		}
	}

	/**
	 * processes digesting.
	 * 
	 * @public
	 * @param {buffer} input input data to be digested.
	 */
	process(input)
	{
		var H = this._state;
		var rounds = this._rounds;
		//if (rounds < 3) rounds = 3;

		var block = [];
		var block_size = jCastle._algorithmInfo[this.algoName].block_size;
		for (var i = 0; i < block_size / 4; i++) {
			block[i] = input.readInt32LE(i * 4);
		}
		

		var t0 = H[0], t1 = H[1], t2 = H[2], t3 = H[3], t4 = H[4], t5 = H[5], t6 = H[6], t7 = H[7];

		// Pass 1
		t7 = this.FF1(t7, t6, t5, t4, t3, t2, t1, t0, block[0]);
		t6 = this.FF1(t6, t5, t4, t3, t2, t1, t0, t7, block[1]);
		t5 = this.FF1(t5, t4, t3, t2, t1, t0, t7, t6, block[2]);
		t4 = this.FF1(t4, t3, t2, t1, t0, t7, t6, t5, block[3]);
		t3 = this.FF1(t3, t2, t1, t0, t7, t6, t5, t4, block[4]);
		t2 = this.FF1(t2, t1, t0, t7, t6, t5, t4, t3, block[5]);
		t1 = this.FF1(t1, t0, t7, t6, t5, t4, t3, t2, block[6]);
		t0 = this.FF1(t0, t7, t6, t5, t4, t3, t2, t1, block[7]);

		t7 = this.FF1(t7, t6, t5, t4, t3, t2, t1, t0, block[8] );
		t6 = this.FF1(t6, t5, t4, t3, t2, t1, t0, t7, block[9] );
		t5 = this.FF1(t5, t4, t3, t2, t1, t0, t7, t6, block[10]);
		t4 = this.FF1(t4, t3, t2, t1, t0, t7, t6, t5, block[11]);
		t3 = this.FF1(t3, t2, t1, t0, t7, t6, t5, t4, block[12]);
		t2 = this.FF1(t2, t1, t0, t7, t6, t5, t4, t3, block[13]);
		t1 = this.FF1(t1, t0, t7, t6, t5, t4, t3, t2, block[14]);
		t0 = this.FF1(t0, t7, t6, t5, t4, t3, t2, t1, block[15]);

		t7 = this.FF1(t7, t6, t5, t4, t3, t2, t1, t0, block[16]);
		t6 = this.FF1(t6, t5, t4, t3, t2, t1, t0, t7, block[17]);
		t5 = this.FF1(t5, t4, t3, t2, t1, t0, t7, t6, block[18]);
		t4 = this.FF1(t4, t3, t2, t1, t0, t7, t6, t5, block[19]);
		t3 = this.FF1(t3, t2, t1, t0, t7, t6, t5, t4, block[20]);
		t2 = this.FF1(t2, t1, t0, t7, t6, t5, t4, t3, block[21]);
		t1 = this.FF1(t1, t0, t7, t6, t5, t4, t3, t2, block[22]);
		t0 = this.FF1(t0, t7, t6, t5, t4, t3, t2, t1, block[23]);

		t7 = this.FF1(t7, t6, t5, t4, t3, t2, t1, t0, block[24]);
		t6 = this.FF1(t6, t5, t4, t3, t2, t1, t0, t7, block[25]);
		t5 = this.FF1(t5, t4, t3, t2, t1, t0, t7, t6, block[26]);
		t4 = this.FF1(t4, t3, t2, t1, t0, t7, t6, t5, block[27]);
		t3 = this.FF1(t3, t2, t1, t0, t7, t6, t5, t4, block[28]);
		t2 = this.FF1(t2, t1, t0, t7, t6, t5, t4, t3, block[29]);
		t1 = this.FF1(t1, t0, t7, t6, t5, t4, t3, t2, block[30]);
		t0 = this.FF1(t0, t7, t6, t5, t4, t3, t2, t1, block[31]);

		// Pass 2
		t7 = this.FF2(t7, t6, t5, t4, t3, t2, t1, t0, block[5] , 0x452821E6);
		t6 = this.FF2(t6, t5, t4, t3, t2, t1, t0, t7, block[14], 0x38D01377);
		t5 = this.FF2(t5, t4, t3, t2, t1, t0, t7, t6, block[26], 0xBE5466CF);
		t4 = this.FF2(t4, t3, t2, t1, t0, t7, t6, t5, block[18], 0x34E90C6C);
		t3 = this.FF2(t3, t2, t1, t0, t7, t6, t5, t4, block[11], 0xC0AC29B7);
		t2 = this.FF2(t2, t1, t0, t7, t6, t5, t4, t3, block[28], 0xC97C50DD);
		t1 = this.FF2(t1, t0, t7, t6, t5, t4, t3, t2, block[7] , 0x3F84D5B5);
		t0 = this.FF2(t0, t7, t6, t5, t4, t3, t2, t1, block[16], 0xB5470917);

		t7 = this.FF2(t7, t6, t5, t4, t3, t2, t1, t0, block[0] , 0x9216D5D9);
		t6 = this.FF2(t6, t5, t4, t3, t2, t1, t0, t7, block[23], 0x8979FB1B);
		t5 = this.FF2(t5, t4, t3, t2, t1, t0, t7, t6, block[20], 0xD1310BA6);
		t4 = this.FF2(t4, t3, t2, t1, t0, t7, t6, t5, block[22], 0x98DFB5AC);
		t3 = this.FF2(t3, t2, t1, t0, t7, t6, t5, t4, block[1] , 0x2FFD72DB);
		t2 = this.FF2(t2, t1, t0, t7, t6, t5, t4, t3, block[10], 0xD01ADFB7);
		t1 = this.FF2(t1, t0, t7, t6, t5, t4, t3, t2, block[4] , 0xB8E1AFED);
		t0 = this.FF2(t0, t7, t6, t5, t4, t3, t2, t1, block[8] , 0x6A267E96);

		t7 = this.FF2(t7, t6, t5, t4, t3, t2, t1, t0, block[30], 0xBA7C9045);
		t6 = this.FF2(t6, t5, t4, t3, t2, t1, t0, t7, block[3] , 0xF12C7F99);
		t5 = this.FF2(t5, t4, t3, t2, t1, t0, t7, t6, block[21], 0x24A19947);
		t4 = this.FF2(t4, t3, t2, t1, t0, t7, t6, t5, block[9] , 0xB3916CF7);
		t3 = this.FF2(t3, t2, t1, t0, t7, t6, t5, t4, block[17], 0x0801F2E2);
		t2 = this.FF2(t2, t1, t0, t7, t6, t5, t4, t3, block[24], 0x858EFC16);
		t1 = this.FF2(t1, t0, t7, t6, t5, t4, t3, t2, block[29], 0x636920D8);
		t0 = this.FF2(t0, t7, t6, t5, t4, t3, t2, t1, block[6] , 0x71574E69);

		t7 = this.FF2(t7, t6, t5, t4, t3, t2, t1, t0, block[19], 0xA458FEA3);
		t6 = this.FF2(t6, t5, t4, t3, t2, t1, t0, t7, block[12], 0xF4933D7E);
		t5 = this.FF2(t5, t4, t3, t2, t1, t0, t7, t6, block[15], 0x0D95748F);
		t4 = this.FF2(t4, t3, t2, t1, t0, t7, t6, t5, block[13], 0x728EB658);
		t3 = this.FF2(t3, t2, t1, t0, t7, t6, t5, t4, block[2] , 0x718BCD58);
		t2 = this.FF2(t2, t1, t0, t7, t6, t5, t4, t3, block[25], 0x82154AEE);
		t1 = this.FF2(t1, t0, t7, t6, t5, t4, t3, t2, block[31], 0x7B54A41D);
		t0 = this.FF2(t0, t7, t6, t5, t4, t3, t2, t1, block[27], 0xC25A59B5);

		// Pass 3
		t7 = this.FF3(t7, t6, t5, t4, t3, t2, t1, t0, block[19], 0x9C30D539);
		t6 = this.FF3(t6, t5, t4, t3, t2, t1, t0, t7, block[9] , 0x2AF26013);
		t5 = this.FF3(t5, t4, t3, t2, t1, t0, t7, t6, block[4] , 0xC5D1B023);
		t4 = this.FF3(t4, t3, t2, t1, t0, t7, t6, t5, block[20], 0x286085F0);
		t3 = this.FF3(t3, t2, t1, t0, t7, t6, t5, t4, block[28], 0xCA417918);
		t2 = this.FF3(t2, t1, t0, t7, t6, t5, t4, t3, block[17], 0xB8DB38EF);
		t1 = this.FF3(t1, t0, t7, t6, t5, t4, t3, t2, block[8] , 0x8E79DCB0);
		t0 = this.FF3(t0, t7, t6, t5, t4, t3, t2, t1, block[22], 0x603A180E);

		t7 = this.FF3(t7, t6, t5, t4, t3, t2, t1, t0, block[29], 0x6C9E0E8B);
		t6 = this.FF3(t6, t5, t4, t3, t2, t1, t0, t7, block[14], 0xB01E8A3E);
		t5 = this.FF3(t5, t4, t3, t2, t1, t0, t7, t6, block[25], 0xD71577C1);
		t4 = this.FF3(t4, t3, t2, t1, t0, t7, t6, t5, block[12], 0xBD314B27);
		t3 = this.FF3(t3, t2, t1, t0, t7, t6, t5, t4, block[24], 0x78AF2FDA);
		t2 = this.FF3(t2, t1, t0, t7, t6, t5, t4, t3, block[30], 0x55605C60);
		t1 = this.FF3(t1, t0, t7, t6, t5, t4, t3, t2, block[16], 0xE65525F3);
		t0 = this.FF3(t0, t7, t6, t5, t4, t3, t2, t1, block[26], 0xAA55AB94);

		t7 = this.FF3(t7, t6, t5, t4, t3, t2, t1, t0, block[31], 0x57489862);
		t6 = this.FF3(t6, t5, t4, t3, t2, t1, t0, t7, block[15], 0x63E81440);
		t5 = this.FF3(t5, t4, t3, t2, t1, t0, t7, t6, block[7] , 0x55CA396A);
		t4 = this.FF3(t4, t3, t2, t1, t0, t7, t6, t5, block[3] , 0x2AAB10B6);
		t3 = this.FF3(t3, t2, t1, t0, t7, t6, t5, t4, block[1] , 0xB4CC5C34);
		t2 = this.FF3(t2, t1, t0, t7, t6, t5, t4, t3, block[0] , 0x1141E8CE);
		t1 = this.FF3(t1, t0, t7, t6, t5, t4, t3, t2, block[18], 0xA15486AF);
		t0 = this.FF3(t0, t7, t6, t5, t4, t3, t2, t1, block[27], 0x7C72E993);

		t7 = this.FF3(t7, t6, t5, t4, t3, t2, t1, t0, block[13], 0xB3EE1411);
		t6 = this.FF3(t6, t5, t4, t3, t2, t1, t0, t7, block[6] , 0x636FBC2A);
		t5 = this.FF3(t5, t4, t3, t2, t1, t0, t7, t6, block[21], 0x2BA9C55D);
		t4 = this.FF3(t4, t3, t2, t1, t0, t7, t6, t5, block[10], 0x741831F6);
		t3 = this.FF3(t3, t2, t1, t0, t7, t6, t5, t4, block[23], 0xCE5C3E16);
		t2 = this.FF3(t2, t1, t0, t7, t6, t5, t4, t3, block[11], 0x9B87931E);
		t1 = this.FF3(t1, t0, t7, t6, t5, t4, t3, t2, block[5] , 0xAFD6BA33);
		t0 = this.FF3(t0, t7, t6, t5, t4, t3, t2, t1, block[2] , 0x6C24CF5C);

		if (rounds >= 4) {
			t7 = this.FF4(t7, t6, t5, t4, t3, t2, t1, t0, block[24], 0x7A325381);
			t6 = this.FF4(t6, t5, t4, t3, t2, t1, t0, t7, block[4] , 0x28958677);
			t5 = this.FF4(t5, t4, t3, t2, t1, t0, t7, t6, block[0] , 0x3B8F4898);
			t4 = this.FF4(t4, t3, t2, t1, t0, t7, t6, t5, block[14], 0x6B4BB9AF);
			t3 = this.FF4(t3, t2, t1, t0, t7, t6, t5, t4, block[2] , 0xC4BFE81B);
			t2 = this.FF4(t2, t1, t0, t7, t6, t5, t4, t3, block[7] , 0x66282193);
			t1 = this.FF4(t1, t0, t7, t6, t5, t4, t3, t2, block[28], 0x61D809CC);
			t0 = this.FF4(t0, t7, t6, t5, t4, t3, t2, t1, block[23], 0xFB21A991);
			t7 = this.FF4(t7, t6, t5, t4, t3, t2, t1, t0, block[26], 0x487CAC60);
			t6 = this.FF4(t6, t5, t4, t3, t2, t1, t0, t7, block[6] , 0x5DEC8032);
			t5 = this.FF4(t5, t4, t3, t2, t1, t0, t7, t6, block[30], 0xEF845D5D);
			t4 = this.FF4(t4, t3, t2, t1, t0, t7, t6, t5, block[20], 0xE98575B1);
			t3 = this.FF4(t3, t2, t1, t0, t7, t6, t5, t4, block[18], 0xDC262302);
			t2 = this.FF4(t2, t1, t0, t7, t6, t5, t4, t3, block[25], 0xEB651B88);
			t1 = this.FF4(t1, t0, t7, t6, t5, t4, t3, t2, block[19], 0x23893E81);
			t0 = this.FF4(t0, t7, t6, t5, t4, t3, t2, t1, block[3] , 0xD396ACC5);

			t7 = this.FF4(t7, t6, t5, t4, t3, t2, t1, t0, block[22], 0x0F6D6FF3);
			t6 = this.FF4(t6, t5, t4, t3, t2, t1, t0, t7, block[11], 0x83F44239);
			t5 = this.FF4(t5, t4, t3, t2, t1, t0, t7, t6, block[31], 0x2E0B4482);
			t4 = this.FF4(t4, t3, t2, t1, t0, t7, t6, t5, block[21], 0xA4842004);
			t3 = this.FF4(t3, t2, t1, t0, t7, t6, t5, t4, block[8] , 0x69C8F04A);
			t2 = this.FF4(t2, t1, t0, t7, t6, t5, t4, t3, block[27], 0x9E1F9B5E);
			t1 = this.FF4(t1, t0, t7, t6, t5, t4, t3, t2, block[12], 0x21C66842);
			t0 = this.FF4(t0, t7, t6, t5, t4, t3, t2, t1, block[9] , 0xF6E96C9A);
			t7 = this.FF4(t7, t6, t5, t4, t3, t2, t1, t0, block[1] , 0x670C9C61);
			t6 = this.FF4(t6, t5, t4, t3, t2, t1, t0, t7, block[29], 0xABD388F0);
			t5 = this.FF4(t5, t4, t3, t2, t1, t0, t7, t6, block[5] , 0x6A51A0D2);
			t4 = this.FF4(t4, t3, t2, t1, t0, t7, t6, t5, block[15], 0xD8542F68);
			t3 = this.FF4(t3, t2, t1, t0, t7, t6, t5, t4, block[17], 0x960FA728);
			t2 = this.FF4(t2, t1, t0, t7, t6, t5, t4, t3, block[10], 0xAB5133A3);
			t1 = this.FF4(t1, t0, t7, t6, t5, t4, t3, t2, block[16], 0x6EEF0B6C);
			t0 = this.FF4(t0, t7, t6, t5, t4, t3, t2, t1, block[13], 0x137A3BE4);

			if (rounds == 5) {
				t7 = this.FF5(t7, t6, t5, t4, t3, t2, t1, t0, block[27], 0xBA3BF050);
				t6 = this.FF5(t6, t5, t4, t3, t2, t1, t0, t7, block[3] , 0x7EFB2A98);
				t5 = this.FF5(t5, t4, t3, t2, t1, t0, t7, t6, block[21], 0xA1F1651D);
				t4 = this.FF5(t4, t3, t2, t1, t0, t7, t6, t5, block[26], 0x39AF0176);
				t3 = this.FF5(t3, t2, t1, t0, t7, t6, t5, t4, block[17], 0x66CA593E);
				t2 = this.FF5(t2, t1, t0, t7, t6, t5, t4, t3, block[11], 0x82430E88);
				t1 = this.FF5(t1, t0, t7, t6, t5, t4, t3, t2, block[20], 0x8CEE8619);
				t0 = this.FF5(t0, t7, t6, t5, t4, t3, t2, t1, block[29], 0x456F9FB4);

				t7 = this.FF5(t7, t6, t5, t4, t3, t2, t1, t0, block[19], 0x7D84A5C3);
				t6 = this.FF5(t6, t5, t4, t3, t2, t1, t0, t7, block[0] , 0x3B8B5EBE);
				t5 = this.FF5(t5, t4, t3, t2, t1, t0, t7, t6, block[12], 0xE06F75D8);
				t4 = this.FF5(t4, t3, t2, t1, t0, t7, t6, t5, block[7] , 0x85C12073);
				t3 = this.FF5(t3, t2, t1, t0, t7, t6, t5, t4, block[13], 0x401A449F);
				t2 = this.FF5(t2, t1, t0, t7, t6, t5, t4, t3, block[8] , 0x56C16AA6);
				t1 = this.FF5(t1, t0, t7, t6, t5, t4, t3, t2, block[31], 0x4ED3AA62);
				t0 = this.FF5(t0, t7, t6, t5, t4, t3, t2, t1, block[10], 0x363F7706);

				t7 = this.FF5(t7, t6, t5, t4, t3, t2, t1, t0, block[5] , 0x1BFEDF72);
				t6 = this.FF5(t6, t5, t4, t3, t2, t1, t0, t7, block[9] , 0x429B023D);
				t5 = this.FF5(t5, t4, t3, t2, t1, t0, t7, t6, block[14], 0x37D0D724);
				t4 = this.FF5(t4, t3, t2, t1, t0, t7, t6, t5, block[30], 0xD00A1248);
				t3 = this.FF5(t3, t2, t1, t0, t7, t6, t5, t4, block[18], 0xDB0FEAD3);
				t2 = this.FF5(t2, t1, t0, t7, t6, t5, t4, t3, block[6] , 0x49F1C09B);
				t1 = this.FF5(t1, t0, t7, t6, t5, t4, t3, t2, block[28], 0x075372C9);
				t0 = this.FF5(t0, t7, t6, t5, t4, t3, t2, t1, block[24], 0x80991B7B);

				t7 = this.FF5(t7, t6, t5, t4, t3, t2, t1, t0, block[2] , 0x25D479D8);
				t6 = this.FF5(t6, t5, t4, t3, t2, t1, t0, t7, block[23], 0xF6E8DEF7);
				t5 = this.FF5(t5, t4, t3, t2, t1, t0, t7, t6, block[16], 0xE3FE501A);
				t4 = this.FF5(t4, t3, t2, t1, t0, t7, t6, t5, block[22], 0xB6794C3B);
				t3 = this.FF5(t3, t2, t1, t0, t7, t6, t5, t4, block[4] , 0x976CE0BD);
				t2 = this.FF5(t2, t1, t0, t7, t6, t5, t4, t3, block[1] , 0x04C006BA);
				t1 = this.FF5(t1, t0, t7, t6, t5, t4, t3, t2, block[25], 0xC1A94FB6);
				t0 = this.FF5(t0, t7, t6, t5, t4, t3, t2, t1, block[15], 0x409F60C4);
			}
		}

		H[7] += t7;
		H[6] += t6;
		H[5] += t5;
		H[4] += t4;
		H[3] += t3;
		H[2] += t2;
		H[1] += t1;
		H[0] += t0;

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
		var pad_len = index < 118 ? (118 - index) : (246 - index);

		// save the version number (LSB 3), the number of rounds (3 bits in the
		// middle), the fingerprint length (MSB 2 bits and next byte) and the
		// number of bits in the unpadded message.
		var bits_length = jCastle._algorithmInfo[this.algoName].digest_size * 8;
		var bits_pos = pad_len;
		pad_len += 2;
		
		var length_pos = pad_len;
		pad_len += 8;
		
		var padding = Buffer.alloc(pad_len);
		padding[0] = 0x01;
		padding[bits_pos] = (((bits_length & 0x03) << 6) | ((this._rounds & 0x07) << 3) | (jCastle.algorithm.haval.VERSION & 0x07)) & 0xFF;
		padding[bits_pos+1] = (bits_length >>> 2) & 0xFF;
		
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
		this.haval_final();

		var digest_size = jCastle._algorithmInfo[this.algoName].digest_size;
		var output = Buffer.alloc(digest_size);

		for (var i = 0; i < digest_size / 4; i++) {
			output.writeInt32LE(this._state[i] & 0xffffffff, i * 4, true);
		}
		this._state = null;
		
		return output;
	}


	haval_final()
	{
		var t;
		var H = this._state;

		switch (jCastle._algorithmInfo[this.algoName].digest_size) {
		case 16:
			t = (H[7] & 0x000000FF) | (H[6] & 0xFF000000) | (H[5] & 0x00FF0000) | (H[4] & 0x0000FF00);
			H[0] += t >>> 8 | t << 24;
			t = (H[7] & 0x0000FF00) | (H[6] & 0x000000FF) | (H[5] & 0xFF000000) | (H[4] & 0x00FF0000);
			H[1] += t >>> 16 | t << 16;
			t = (H[7] & 0x00FF0000) | (H[6] & 0x0000FF00) | (H[5] & 0x000000FF) | (H[4] & 0xFF000000);
			H[2] += t >>> 24 | t << 8;
			t = (H[7] & 0xFF000000) | (H[6] & 0x00FF0000) | (H[5] & 0x0000FF00) | (H[4] & 0x000000FF);
			H[3] += t;
			break;
		case 20:
			t = (H[7] & 0x3F) | (H[6] & (0x7F << 25)) | (H[5] & (0x3F << 19));
			H[0] += t >>> 19 | t << 13;
			t = (H[7] & (0x3F << 6)) | (H[6] & 0x3F) | (H[5] & (0x7F << 25));
			H[1] += t >>> 25 | t << 7;
			t = (H[7] & (0x7F << 12)) | (H[6] & (0x3F << 6)) | (H[5] & 0x3F);
			H[2] += t;
			t = (H[7] & (0x3F << 19)) | (H[6] & (0x7F << 12)) | (H[5] & (0x3F << 6));
			H[3] += (t >>> 6);
			t = (H[7] & (0x7F << 25)) | (H[6] & (0x3F << 19)) | (H[5] & (0x7F << 12));
			H[4] += (t >>> 12);
			break;
		case 24:
			t = (H[7] & 0x1F) | (H[6] & (0x3F << 26));
			H[0] += t >>> 26 | t << 6;
			t = (H[7] & (0x1F <<  5)) | (H[6] & 0x1F);
			H[1] += t;
			t = (H[7] & (0x3F << 10)) | (H[6] & (0x1F <<  5));
			H[2] += (t >>> 5);
			t = (H[7] & (0x1F << 16)) | (H[6] & (0x3F << 10));
			H[3] += (t >>> 10);
			t = (H[7] & (0x1F << 21)) | (H[6] & (0x1F << 16));
			H[4] += (t >>> 16);
			t = (H[7] & (0x3F << 26)) | (H[6] & (0x1F << 21));
			H[5] += (t >>> 21);
			break;
		case 28:
			H[0] += ((H[7] >>> 27) & 0x1F);
			H[1] += ((H[7] >>> 22) & 0x1F);
			H[2] += ((H[7] >>> 18) & 0x0F);
			H[3] += ((H[7] >>> 13) & 0x1F);
			H[4] += ((H[7] >>>  9) & 0x0F);
			H[5] += ((H[7] >>>  4) & 0x1F);
			H[6] += ( H[7]		   & 0x0F);
		}

		this._state = H;
	}


/**
 * Permutations phi_{i,j}, i=3,4,5, j=1,...,i.
 *
 * rounds = 3:   6 5 4 3 2 1 0
 *			| | | | | | | (replaced by)
 *  phi_{3,1}:   1 0 3 5 6 2 4
 *  phi_{3,2}:   4 2 1 0 5 3 6
 *  phi_{3,3}:   6 1 2 3 4 5 0
 *
 * rounds = 4:   6 5 4 3 2 1 0
 *			| | | | | | | (replaced by)
 *  phi_{4,1}:   2 6 1 4 5 3 0
 *  phi_{4,2}:   3 5 2 0 1 6 4
 *  phi_{4,3}:   1 4 3 6 0 2 5
 *  phi_{4,4}:   6 4 0 5 2 1 3
 *
 * rounds = 5:   6 5 4 3 2 1 0
 *			| | | | | | | (replaced by)
 *  phi_{5,1}:   3 4 1 0 5 2 6
 *  phi_{5,2}:   6 2 1 0 3 4 5
 *  phi_{5,3}:   2 6 0 4 3 1 5
 *  phi_{5,4}:   1 5 3 2 0 4 6
 *  phi_{5,5}:   2 5 0 6 4 3 1
 */

	FF1(x7, x6, x5, x4, x3, x2, x1, x0, w)
	{
		var t;
		switch (this._rounds) {
			case 3:  t = this.f1(x1, x0, x3, x5, x6, x2, x4); break;
			case 4:  t = this.f1(x2, x6, x1, x4, x5, x3, x0); break;
			default: t = this.f1(x3, x4, x1, x0, x5, x2, x6);
		}
		return (t >>> 7 | t << 25) + (x7 >>> 11 | x7 << 21) + w;
	}

	FF2(x7, x6, x5, x4, x3, x2, x1, x0, w, c)
	{
		var t;
		switch (this._rounds) {
			case 3:  t = this.f2(x4, x2, x1, x0, x5, x3, x6); break;
			case 4:  t = this.f2(x3, x5, x2, x0, x1, x6, x4); break;
			default: t = this.f2(x6, x2, x1, x0, x3, x4, x5);
		}
		return (t >>> 7 | t << 25) + (x7 >>> 11 | x7 << 21) + w + c;
	}

	FF3(x7, x6, x5, x4, x3, x2, x1, x0, w, c)
	{
		var t;
		switch (this._rounds) {
			case 3:  t = this.f3(x6, x1, x2, x3, x4, x5, x0); break;
			case 4:  t = this.f3(x1, x4, x3, x6, x0, x2, x5); break;
			default: t = this.f3(x2, x6, x0, x4, x3, x1, x5);
		}
		return (t >>> 7 | t << 25) + (x7 >>> 11 | x7 << 21) + w + c;
	}

	FF4(x7, x6, x5, x4, x3, x2, x1, x0, w, c)
	{
		var t;
		switch (this._rounds) {
			case 4:  t = this.f4(x6, x4, x0, x5, x2, x1, x3); break;
			default: t = this.f4(x1, x5, x3, x2, x0, x4, x6);
		}
		return (t >>> 7 | t << 25) + (x7 >>> 11 | x7 << 21) + w + c;
	}

	FF5(x7, x6, x5, x4, x3, x2, x1, x0, w, c)
	{
		var t = this.f5(x2, x5, x0, x6, x4, x3, x1);
		return (t >>> 7 | t << 25) + (x7 >>> 11 | x7 << 21) + w + c;
	}

	f1(x6, x5, x4, x3, x2, x1, x0)
	{
		return x1 & (x0 ^ x4) ^ x2 & x5 ^ x3 & x6 ^ x0;
	}

	f2(x6, x5, x4, x3, x2, x1, x0)
	{
		return x2 & (x1 & ~x3 ^ x4 & x5 ^ x6 ^ x0) ^ x4 & (x1 ^ x5) ^ x3 & x5 ^ x0;
	}

	f3(x6, x5, x4, x3, x2, x1, x0)
	{
		return x3 & (x1 & x2 ^ x6 ^ x0) ^ x1 & x4 ^ x2 & x5 ^ x0;
	}

	f4(x6, x5, x4, x3, x2, x1, x0)
	{
		return x4 & (x5 & ~x2 ^ x3 & ~x6 ^ x1 ^ x6 ^ x0) ^ x3 & (x1 & x2 ^ x5 ^ x6) ^ x2 & x6 ^ x0;
	}

	f5(x6, x5, x4, x3, x2, x1, x0)
	{
		return x0 & (x1 & x2 & x3 ^ ~x5) ^ x1 & x4 ^ x2 & x5 ^ x3 & x6;
	}
}


jCastle.algorithm.haval.VERSION = 0x01;

jCastle.algorithm.Haval = jCastle.algorithm.haval;

jCastle._algorithmInfo['haval'] = { // haval-256
	algorithm_type: 'hash',
	object_name: 'haval',
	block_size: 128,
	digest_size: 32
	// oid: ""
};

jCastle._algorithmInfo['haval-128'] = {
	algorithm_type: 'hash',
	object_name: 'haval',
	block_size: 128,
	digest_size: 16
	// oid: ""
};

jCastle._algorithmInfo['haval-160'] = {
	algorithm_type: 'hash',
	object_name: 'haval',
	block_size: 128,
	digest_size: 20
	// oid: ""
};

jCastle._algorithmInfo['haval-192'] = {
	algorithm_type: 'hash',
	object_name: 'haval',
	block_size: 128,
	digest_size: 24
	// oid: ""
};

jCastle._algorithmInfo['haval-224'] = {
	algorithm_type: 'hash',
	object_name: 'haval',
	block_size: 128,
	digest_size: 28
	// oid: ""
};

jCastle._algorithmInfo['haval-256'] = {
	algorithm_type: 'hash',
	object_name: 'haval',
	block_size: 128,
	digest_size: 32
	// oid: ""
};

module.exports = jCastle.algorithm.haval;