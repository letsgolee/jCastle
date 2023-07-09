/**
 * Mcrypt: Javascript Cypher Modes 
 * 
 * @author Jacob Lee
 *
 * Copyright (C) 2015-2022 Jacob Lee.
 */

var jCastle = require('./jCastle');
require('./mcrypt');
require('./mac');

jCastle.mcrypt.mode = {};

/**
 * gets the list of mcrypt modes.
 * 
 * @public
 * @returns the arrays of mcrypt modes.
 */
jCastle.mcrypt.mode.listModes = function()
{
	var l = [
		'ecb', 'cbc', 'pcbc', 'cfb', 'ofb', 'ncfb', 'nofb', 'ctr', 
		'gctr', //'gofb', 
		'gcfb', 'cts', // 'cts-cbc',
		'cts-ebc', 'xts', 'eax', 
		'ccm', 'gcm', 'cwc', 
		'poly1305', //'poly1305-aead',
		'wrap'];

	return l;
};

/**
 * checks if the mode accepts Authenticated Additional Data(AAD).
 * 
 * @public
 * @param {string} mode mode name
 * @returns true if the mode accepts AAD.
 */
jCastle.mcrypt.mode.aadAcceptable = function(mode)
{
	var aad_acceptable = ['eax', 'ccm', 'gcm', 'cwc', 'poly1305'];
	return aad_acceptable.includes(mode.toLowerCase());
};

/**
 * checks if the mode returns a mac tag.
 * 
 * @public
 * @param {string} mode mode name
 * @returns true if the mode returns a mac tag.
 */
jCastle.mcrypt.mode.hasMacTag = function(mode)
{
	var has_tag = ['eax', 'ccm', 'gcm', 'cwc', 'poly1305'];
	return has_tag.includes(mode.toLowerCase());
};

/**
 * checks if the mode needs a padding.
 * 
 * @public
 * @param {string} mode mode name
 * @returns true if the mode needs a padding.
 */
jCastle.mcrypt.mode.needsPadding = function(mode)
{
	var needs_padding = ['ecb', 'cbc', 'pcbc'];
	return needs_padding.includes(mode.toLowerCase());
};

/**
 * creates a new mcrypt-mode class.
 * 
 * @public
 * @param {string} mode mcrypt-mode name.
 * @returns the mcrypt-mode class
 */
jCastle.mcrypt.mode.create = function(mode)
{
	return new jCastle.mcrypt.mode[mode.toLowerCase()]();
};

jCastle.mcrypt.mode['ecb'] = class
{
    constructor()
    {
        this.algorithm = null;
        this.state = null;
        this.isEncryption = true;
        this.blockSize = 0;
    }

	init(algorithm, options)
	{
		this.algorithm = algorithm;
		this.state = null;
		this.isEncryption = options.isEncryption;
		this.blockSize = options.blockSize;
	}

	process(input)
	{
		var output = this.isEncryption ? this.algorithm.encryptBlock(input) : this.algorithm.decryptBlock(input);
		return output;
	}

	finish()
	{
		this.state = null;
		this.isEncryption = null;
		this.blockSize = null;
		
		if (typeof this.algorithm.reset === 'function') {
			this.algorithm.reset();
		}
	}
};

jCastle.mcrypt.mode['stream'] = class
{
    constructor()
    {
        this.algorithm = null;
        this.state = null;
        this.isEncryption = true;
        this.blockSize = 1;
    }

	init(algorithm, options)
	{
		this.algorithm = algorithm;
		this.isEncryption = options.isEncryption;

		// stream block size is 1
		// but some ciphers have their own stream_block_size.
	}

	process(input)
	{
		var output = this.isEncryption ? this.algorithm.encryptBlock(input) : this.algorithm.decryptBlock(input);
		return output;
	}

	finish()
	{
		this.isEncryption = null;
		
		if (typeof this.algorithm.reset === 'function') {
			this.algorithm.reset();
		}
	}
};

jCastle.mcrypt.mode['cbc'] = class
{
    constructor()
    {
        this.algorithm = null;
        this.state = null;
        this.isEncryption = true;
        this.blockSize = 0;
    }

	init(algorithm, options)
	{
		this.algorithm = algorithm;
		this.isEncryption = options.isEncryption;
		this.blockSize = options.blockSize;

		var iv = Buffer.from(options.iv, 'latin1');

		if(iv.length != this.blockSize) {
			throw jCastle.exception('INVALID_IV', 'MOD001');
		}
		// For block chain modes, initial vector is THE first block

		this.state = iv.slice(0);
	}

	process(input)
	{
		if(this.isEncryption) {
			var block = Buffer.xor(input, this.state);
			this.state = this.algorithm.encryptBlock(block);
			return Buffer.slice(this.state);
		} else {
			var temp = Buffer.slice(this.state);
			this.state = Buffer.slice(input);
			var block = this.algorithm.decryptBlock(this.state);
			return Buffer.xor(temp, block);
		}
	}

	finish()
	{
		this.state = null;
		this.isEncryption = null;
		this.blockSize = null;

		if (typeof this.algorithm.reset === 'function') {
			this.algorithm.reset();
		}
	}
};

jCastle.mcrypt.mode['pcbc'] = class
{
    constructor()
    {
        this.algorithm = null;
        this.state = null;
        this.isEncryption = true;
        this.blockSize = 0;
    }

	init(algorithm, options)
	{
		this.algorithm = algorithm;
		this.isEncryption = options.isEncryption;
		this.blockSize = options.blockSize;

		var iv = Buffer.from(options.iv, 'latin1');

		if(iv.length != this.blockSize) {
			throw jCastle.exception('INVALID_IV', 'MOD002');
		}
		// For block chain modes, initial vector is THE first block

		this.state = Buffer.slice(iv);
	}

	process(input)
	{
		if(this.isEncryption) {
			var temp = Buffer.xor(input, this.state);
			this.state = this.algorithm.encryptBlock(temp);
			var output = Buffer.slice(this.state);
			this.state = Buffer.xor(this.state, input);
			return output;
		} else {
			var temp = this.state.subarray();
			var dec_block = this.algorithm.decryptBlock(input);
			dec_block = Buffer.xor(temp, dec_block);
			this.state = Buffer.xor(dec_block, input);
			return dec_block;
		}
	}

	finish() 
	{
		this.state = null;
		this.isEncryption = null;
		this.blockSize = null;

		if (typeof this.algorithm.reset === 'function') {
			this.algorithm.reset();
		}
	}
};

/*
http://stackoverflow.com/questions/4574245/what-are-ncfb-and-nofb-modes-for
http://stackoverflow.com/questions/29670856/what-is-the-java-equivalent-of-mcrypt-ncfb-mode
http://mcrypt.hellug.gr/lib/mcrypt.3.html

Note that CFB and OFB in the rest of the document represent the "8bit CFB or OFB" mode. 
nOFB and nCFB modes represents a n-bit OFB/CFB mode, 
n is used to represent the algorithm's block size.

...

nOFB: The Output-Feedback Mode (in nbit). n Is the size of the block of the algorithm.
This is a synchronous stream cipher implemented from a block cipher. 
It is intended for use in noisy lines, 
because corrupted ciphertext blocks do not corrupt the plaintext blocks that follow. 
This mode operates in streams.

nCFB: The Cipher-Feedback Mode (in nbit). n Is the size of the block of the algorithm. 
This is a self synchronizing stream cipher implemented from a block cipher. 
This mode operates in streams.

Be careful!
The CFB and OFB in bouncycastle of Java are the same with nCFB and nOFB.
*/
jCastle.mcrypt.mode['cfb'] = class
{
    constructor()
    {
        this.algorithm = null;
        this.state = null;
        this.isEncryption = true;
        this.blockSize = 0;
    }

	init(algorithm, options)
	{
		// CFB always one way keyscheduling.
		this.algorithm = algorithm;
		this.isEncryption = options.isEncryption;
		this.blockSize = options.blockSize;
		
		if (!this.isEncryption) this.algorithm.keySchedule(algorithm.masterKey, true);

		var iv = Buffer.from(options.iv, 'latin1');

		if(iv.length != this.blockSize) {
			throw jCastle.exception('INVALID_IV', 'MOD003');
		}

		// For block chain modes, initial vector is THE first block
		this.state = Buffer.slice(iv);
	}

	process(input)
	{
		var output = Buffer.alloc(input.length);

		for (var i = 0; i < input.length; i++) {
			var temp = this.algorithm.encryptBlock(this.state);
			var rv = (temp[0] ^ input[i]) & 0xff;
//			for (var j = 1; j < this.state.length; j++)
//				this.state[j - 1] = this.state[j];
			this.state.set(this.state.slice(1), 0);
			this.state[this.state.length - 1] = this.isEncryption ? rv : input[i];
			output[i] = rv;
		}

		return output;
	}

	finish() 
	{
		this.state = null;
		this.isEncryption = null;
		this.blockSize = null;

		if (typeof this.algorithm.reset === 'function') {
			this.algorithm.reset();
		}
	}
};

jCastle.mcrypt.mode['ofb'] = class
{
    constructor()
    {
        this.algorithm = null;
        this.state = null;
        this.isEncryption = true;
        this.blockSize = 0;
    }

	init(algorithm, options)
	{
		// OFB always one way keyscheduling.
		this.algorithm = algorithm;
		this.isEncryption = options.isEncryption;
		this.blockSize = options.blockSize;
		
		if (!this.isEncryption) this.algorithm.keySchedule(algorithm.masterKey, true);

		var iv = Buffer.from(options.iv, 'latin1');

		if(iv.length != this.blockSize) {
			throw jCastle.exception('INVALID_IV', 'MOD004');
		}

		// For block chain modes, initial vector is THE first block
		this.state = Buffer.slice(iv);
	}

	process(input)
	{
		var output = Buffer.alloc(input.length);

		for (var i = 0; i < input.length; i++) {
			var temp = this.algorithm.encryptBlock(this.state);
			output[i] = (temp[0] ^ input[i]) & 0xff;
//			for (var j = 1; j < this.state.length; j++)
//				this.state[j - 1] = this.state[j];
			this.state.set(this.state.slice(1), 0);
			this.state[this.state.length - 1] = temp[0];
		}

		return output;
	}

	finish() 
	{
		this.state = null;
		this.isEncryption = null;
		this.blockSize = null;

		if (typeof this.algorithm.reset === 'function') {
			this.algorithm.reset();
		}
	}
};

jCastle.mcrypt.mode['ncfb'] = class
{
    constructor()
    {
        this.algorithm = null;
        this.state = null;
        this.isEncryption = true;
        this.blockSize = 0;
    }

	init(algorithm, options)
	{
		// NCFB always one way keyscheduling.
		this.algorithm = algorithm;
		this.isEncryption = options.isEncryption;
		this.blockSize = options.blockSize;
		
		if (!this.isEncryption) this.algorithm.keySchedule(algorithm.masterKey, true);

		var iv = Buffer.from(options.iv, 'latin1');

		if(iv.length != this.blockSize) {
			throw jCastle.exception('INVALID_IV', 'MOD005');
		}

		// For block chain modes, initial vector is THE first block
		this.state = Buffer.slice(iv);
	}

	process(input)
	{
		var output = Buffer.alloc(input.length);
		var temp = this.algorithm.encryptBlock(this.state);

		// input can be less than block size
		// so xorBlock function should not be used.
		for (var i = 0; i < input.length; i++) {
			var rv = (temp[i] ^ input[i]) & 0xff;
//			for (var j = 1; j < this.state.length; j++)
//				this.state[j - 1] = this.state[j];
			this.state.set(this.state.slice(1), 0);
			this.state[this.state.length - 1] = this.isEncryption ? rv : input[i];
			output[i] = rv;
		}

		return output;
	}

	finish() 
	{
		this.state = null;
		this.isEncryption = null;
		this.blockSize = null;

		if (typeof this.algorithm.reset === 'function') {
			this.algorithm.reset();
		}
	}
};

jCastle.mcrypt.mode['nofb'] = class
{
    constructor()
    {
        this.algorithm = null;
        this.state = null;
        this.isEncryption = true;
        this.blockSize = 0;
    }

	init(algorithm, options)
	{
		// NOFB always one way keyscheduling.
		this.algorithm = algorithm;
		this.isEncryption = options.isEncryption;
		this.blockSize = options.blockSize;
		
		if (!this.isEncryption) this.algorithm.keySchedule(algorithm.masterKey, true);

		var iv = Buffer.from(options.iv, 'latin1');

		if(iv.length != this.blockSize) {
			throw jCastle.exception('INVALID_IV', 'MOD006');
		}

		// For block chain modes, initial vector is THE first block
		this.state = Buffer.slice(iv);
	}

	process(input)
	{
		var output = Buffer.alloc(input.length);
		var temp = this.algorithm.encryptBlock(this.state);

		// input can be less than block size
		// so xorBlock function should not be used.
		for (var i = 0; i < input.length; i++) {
			output[i] = temp[i] ^ input[i];
//			for (var j = 1; j < this.state.length; j++)
//				this.state[j - 1] = this.state[j];
			this.state.set(this.state.slice(1), 0);
			this.state[this.state.length - 1] = temp[i];
		}

		return output;
	}

	finish() 
	{
		this.state = null;
		this.isEncryption = null;
		this.blockSize = null;

		if (typeof this.algorithm.reset === 'function') {
			this.algorithm.reset();
		}
	}
};

jCastle.mcrypt.mode['ctr'] = class
{
    constructor()
    {
        this.algorithm = null;
        this.state = null;
        this.isEncryption = true;
        this.blockSize = 0;
    }

    // Segmented Integer Counter (SIC) mode known as ctr
	init(algorithm, options)
	{
		// CTR always one way keyscheduling.
		this.algorithm = algorithm;
		this.isEncryption = options.isEncryption;
		this.blockSize = options.blockSize;
		
		if (!this.isEncryption) this.algorithm.keySchedule(algorithm.masterKey, true);

		var iv = Buffer.from(options.iv, 'latin1');

		if(iv.length != this.blockSize) {
			throw jCastle.exception('INVALID_IV', 'MOD007');
		}
		// For block chain modes, initial vector is THE first block
		// iv works as counter.

		this.state = Buffer.slice(iv);
	}

	process(input)
	{
		var output = Buffer.alloc(input.length);
		var temp = this.algorithm.encryptBlock(this.state);

		for (var i = 0; i < input.length; i++) {
			output[i] = input[i] ^ temp[i];
		}

		this.increaseCounter();

		return output;
	}

	finish() 
	{
		this.state = null;
		this.isEncryption = null;
		this.blockSize = null;

		if (typeof this.algorithm.reset === 'function') {
			this.algorithm.reset();
		}
	}

	increaseCounter()
	{
		var carry = 1;
		var j = this.blockSize;

		while (j-- && carry) {
			var x = this.state[j] + carry;
			carry = x > 0xff ? 1 : 0;
			this.state[j] = x & 0xff;
		}
	}
};

jCastle.mcrypt.mode['gofb'] = class
{
    constructor()
    {
        this.algorithm = null;
        this.state = null;
        this.isEncryption = true;
        this.blockSize = 0;
    }

    // GOST 28147 OFB counter mode
	init(algorithm, options)
	{
		this.algorithm = algorithm;
		this.isEncryption = options.isEncryption;
		this.blockSize = options.blockSize;
		
		if (!this.isEncryption) this.algorithm.keySchedule(algorithm.masterKey, true);

		var iv = Buffer.from(options.iv, 'latin1');

		// let's allow other cipher if its block size is the same with gost.
/*
		if (this.algorithm.algoName != 'gost') {
			throw jCastle.exception('GCTR_NOT_GOST', 'MOD008');
		}
*/
		if (this.blockSize != 8) {
			throw jCastle.exception('INVALID_BLOCKSIZE', 'MOD009');
		}

		this.state = Buffer.alloc(this.blockSize);
		this.state.set(iv, 0);		

		this.C1 = 0x1010104; // 16843012;
		this.C2 = 0x1010101; // 16843009;

		var temp = this.algorithm.encryptBlock(this.state);
		this.N3 = temp.readInt32LE(0);
		this.N4 = temp.readInt32LE(4);

	}

	process(input)
	{
//		var output = Buffer.alloc(input.length);

		this.N3 += this.C2;
		this.N4 += this.C1;

		this.state.writeInt32LE(this.N3 & 0xffffffff, 0);
		this.state.writeInt32LE(this.N4 & 0xffffffff, 4);
		this.state = this.algorithm.encryptBlock(this.state);

//		for (var i = 0; i < input.length; i++) {
//			output[i] = this.state[i] ^ input[i];
//		}
		var output = Buffer.xor(input, this.state);

		return output;
	}

	finish()
	{
		this.state = null;
		this.isEncryption = null;
		this.blockSize = null;

		if (typeof this.algorithm.reset === 'function') {
			this.algorithm.reset();
		}
	}
};

jCastle.mcrypt.mode['gctr'] = jCastle.mcrypt.mode['gofb'];

/*
https://tools.ietf.org/html/rfc4357

2.3.2.  CryptoPro Key Meshing

   The CryptoPro key meshing algorithm transforms the key and
   initialization vector every 1024 octets (8192 bits, or 256 64-bit
   blocks) of plaintext data.

   This algorithm has the same drawback as OFB cipher mode: it is
   impossible to re-establish crypto synch while decrypting a ciphertext
   if parts of encrypted data are corrupted, lost, or processed out of
   order.  Furthermore, it is impossible to re-synch even if an IV for
   each data packet is provided explicitly.  Use of this algorithm in
   protocols such as IPsec ESP requires special care.

   The identifier for this algorithm is:

       id-Gost28147-89-CryptoPro-KeyMeshing  OBJECT IDENTIFIER ::=
           { iso(1) member-body(2) ru(643) rans(2) cryptopro(2)
               keyMeshing(14) cryptoPro(1) }

   There are no meaningful parameters to this algorithm.  If present,
   AlgorithmIdentifier.parameters MUST contain NULL.

   GOST 28147-89, in encrypt, decrypt, or MAC mode, starts with key K[0]
   =  K, IV0[0] = IV, i = 0.  Let IVn[0] be the value of the
   initialization vector after processing the first 1024 octets of data.

   Processing of the next 1024 octets will start with K[1] and IV0[1],
   which are calculated using the following formula:

       K[i+1] = decryptECB (K[i], C);
       IV0[i+1] = encryptECB (K[i+1],IVn[i])

   Where C = {0x69, 0x00, 0x72, 0x22,   0x64, 0xC9, 0x04, 0x23,
              0x8D, 0x3A, 0xDB, 0x96,   0x46, 0xE9, 0x2A, 0xC4,
              0x18, 0xFE, 0xAC, 0x94,   0x00, 0xED, 0x07, 0x12,
              0xC0, 0x86, 0xDC, 0xC2,   0xEF, 0x4C, 0xA9, 0x2B};

   After processing each 1024 octets of data:
    * the resulting initialization vector is stored as IVn[i];
    * K[i+1] and IV0[i+1] are calculated;
    * i is incremented;
    * Encryption or decryption of next 1024 bytes starts, using
      the new key and IV;
   The process is repeated until all the data has been processed.
*/
jCastle.mcrypt.mode['gcfb'] = class
{
    // GOST CFB mode with CryptoPro key meshing as described in RFC 4357
	// sad to say, there is no test vectors.

    cbox = Buffer.from([
		0x69, 0x00, 0x72, 0x22, 0x64, 0xC9, 0x04, 0x23,
		0x8D, 0x3A, 0xDB, 0x96, 0x46, 0xE9, 0x2A, 0xC4,
		0x18, 0xFE, 0xAC, 0x94, 0x00, 0xED, 0x07, 0x12,
		0xC0, 0x86, 0xDC, 0xC2, 0xEF, 0x4C, 0xA9, 0x2B
	]);

    constructor()
    {
        this.algorithm = null;
        this.state = null;
        this.isEncryption = true;
        this.blockSize = 0;
    }

	init(algorithm, options)
	{
		this.algorithm = algorithm;
		this.state = new ByteBuffer;
		this.isEncryption = options.isEncryption;
		this.blockSize = options.blockSize;

		var iv = Buffer.from(options.iv, 'latin1');

		if (this.blockSize % 8) {
			throw jCastle.exception("MODE_INVALID_BLOCKSIZE", 'MOD010');
		}

		if (jCastle._algorithmInfo[this.algorithm.algoName].key_size != 32) {
			throw jCastle.exception("INVALID_KEYSIZE", 'MOD011');
		}

		this.counter = 0; // long
		this.iv = Buffer.slice(iv);
		this.cfbMode = jCastle.mcrypt.mode.create('cfb');
		this.cfbMode.init(this.algorithm, options);
	}

	process(input)
	{
		if (this.counter && this.counter % 1024 == 0) {
			var algorithm = this.cfbMode.algorithm;

			var key = Buffer.alloc(32);
			key.set(algorithm.decryptBlock(this.cbox.slice(0, 8)), 0);
			key.set(algorithm.decryptBlock(this.cbox.slice(8, 16)), 8);
			key.set(algorithm.decryptBlock(this.cbox.slice(16, 24)), 16);
			key.set(algorithm.decryptBlock(this.cbox.slice(24)), 24);

			algorithm.keySchedule(key, true);

			this.iv = algorithm.encryptBlock(this.iv);

			this.cfbMode.init(algorithm, {
				iv: this.iv, 
				blockSize: this.blockSize,
				isEncryption: this.isEncryption});
		}

		this.counter += input.length;

		var output = this.cfbMode.process(input);

		return output;
	}

	finish()
	{
		this.state = null;
		this.isEncryption = null;
		this.blockSize = null;
		this.cfbMode.finish();
		this.cfbMode = null;

		if (typeof this.algorithm.reset === 'function') {
			this.algorithm.reset();
		}
	}
};

// Cipher Text Stealing(CTS) mode
// https://en.wikipedia.org/wiki/Ciphertext_stealing
jCastle.mcrypt.mode['cts'] = class
{
    constructor()
    {
        this.algorithm = null;
        this.state = null;
        this.isEncryption = true;
        this.blockSize = 0;
    }

	init(algorithm, options)
	{
		this.algorithm = algorithm;
		this.state = Buffer.alloc(0);
		this.isEncryption = options.isEncryption;
		this.blockSize = options.blockSize;

/*
Ciphertext format:
------------------
There are several different ways to arrange the ciphertext for transmission. 
The ciphertext bits are the same in all cases, just transmitted in a 
different order, so the choice has no security implications; it is purely 
one of implementation convenience.

The numbering here is taken from Dworkin, who describes them all. The third
is the most popular, and described by Daemen and Schneier; Meyer describes a
related, but incompatible scheme (with respect to bit ordering and key use).

CS1:
Arguably the most obvious way to arrange the ciphertext is to transmit the 
truncated penultimate block, followed by the full final block. This is not 
convenient for the receiver for two reasons:

    - The receiver must decrypt the final block first in any case, and
    - This results in the final block not being aligned on a natural boundary, 
	complicating hardware implementations.
    - This does have the advantage that, if the final plaintext block happens 
	to be a multiple of the block size, the ciphertext is identical to that
	of the original mode of operation without ciphertext stealing.

CS2:
It is often more convenient to swap the final two ciphertext blocks, so the
ciphertext ends with the full final block, followed by the truncated 
penultimate block. This results in naturally aligned ciphertext blocks.

In order to maintain compatibility with the non-stealing modes, option CS2
performs this swap only if the amount of stolen ciphertext is non-zero, 
i.e. the original message was not a multiple of the block size.

This maintains natural alignment, and compatibility with the non-stealing
modes, but requires treating the cases of aligned and unaligned message size
differently.

CS3:
The most popular alternative swaps the final two ciphertext blocks 
unconditionally. This is the ordering used in the descriptions below.
*/
		this.type = ('ctsType' in options && options.ctsType.length) ? options.ctsType.toUpperCase() : 'CS3';

		switch (this.type) {
			case "CS1":
			case "CS2":
			case "CS3":
				break;
			default:
				//console.log(this.type);
				throw jCastle.exception("INVALID_CTS_TYPE", 'MOD012');
		}

		this.cbcMode = jCastle.mcrypt.mode.create('cbc');
		this.cbcMode.init(this.algorithm, options);
		this.lastBlock = Buffer.alloc(0);
	}

	process(input)
	{
		var output = Buffer.alloc(0);

		if (this.lastBlock.length) {
			if (this.state.length) {
				output = this.cbcMode.process(this.state);
			}
			this.state = this.lastBlock.slice(0);
		}
		this.lastBlock = Buffer.slice(input);

		return output;
	}

	finish() 
	{
		var block, lastBlock, lastLength = this.lastBlock.length;
		var output;

		if (!lastLength) {
			throw jCastle.exception('DATA_TOO_SHORT_FOR_MODE', 'MOD013');
		}

		if (this.isEncryption) {
/*
CBC ciphertext stealing encryption(CS3 type) using a standard CBC interface:
	1. Pad the last partial plaintext block with 0.
	2. Encrypt the whole padded plaintext using the standard CBC mode.
	3. Swap the last two ciphertext blocks.
	4. Truncate the ciphertext to the length of the original plaintext.


                                              (second to the last)                   (the last block)
           plaintext block                      plaintext block                       plaintext block
           ################                     ################                      ###########-----(zero paded)
                  |                                    |                                    |
                  |                                    |                                    |
   IV----------->XOR           +--------------------->XOR           +--------------------->XOR							 
                  |            |                       |            |                       |							 
                  |            |                       |            |                       |
                  |            |                       |            |                       |
               ENC(Key)        |                    ENC(Key)        |                    ENC(Key)
                  |            |                       |            |                       |
                  |            |                       |            |                       |
                  +------------+                       +------------+                       |
                  |                                    |                                    |
                  |                                    |                                    |
                  |                             ###########~~~~~                            |
                  |                                 |                                       |
                  |                                 |  +------------------------------------+
                  |                                 |  |                                        
                  |                                 +---------------------------------------+
                  |                                    |                                    |
                  |                                    |                                    |
                  V                                    V                                    V
           ################                     ################                      ###########
           ciphertext block                     ciphertext block                      last ciphertext block
                                             partly encrypted twice
*/
			if (lastLength == this.blockSize) {
				block = this.cbcMode.process(this.state);
				lastBlock = this.cbcMode.process(this.lastBlock);

				output = this.type == 'CS3' ? Buffer.concat([lastBlock, block]) : Buffer.concat([block, lastBlock]);
			} else {
				if (this.lastBlock.length != this.blockSize) {
					var size = this.blockSize - this.lastBlock.length;
					this.lastBlock = Buffer.concat([this.lastBlock, Buffer.alloc(size)]);
				}
				block = this.cbcMode.process(this.state);
				lastBlock = this.cbcMode.process(this.lastBlock);

				if (this.type == 'CS2' || this.type == 'CS3') {
					output = Buffer.concat([lastBlock, block.slice(0, lastLength)]);
				} else {
					output = Buffer.concat([block.slice(0, lastLength), lastBlock]);
				}				
			}
		} else {
/*
CBC ciphertext stealing decryption(CS3 type) using a standard CBC interface:
	1. Dn = Decrypt (K, Cn−1). Decrypt the second to last ciphertext block.
	2. Cn = Cn || Tail (Dn, B−M). Pad the ciphertext to the nearest multiple 
	   of the block size using the last B−M bits of block cipher decryption 
	   of the second-to-last ciphertext block.
	3. Swap the last two ciphertext blocks.
	4. Decrypt the (modified) ciphertext using the standard CBC mode.
	5. Truncate the plaintext to the length of the original ciphertext.


                                             partly encrypted twice                      
           ciphertext block                     ciphertext block                      last ciphertext block
           ################                     ################                      ###########
                  |                                 |                                       |
                  |                                 |  +------------------------------------+
                  |                                 |  |                                     
                  |                                 +---------------------------------------+
                  |                                    |                                    |
                  |                                    V                                    |
                  |                             ###########@@@@@ <--------------------------|--------------+
                  |                                    |                                    |              |
                  |                                    |                                    |              |
                  +------------+                       +------------+                       |              |
                  |            |                       |            |                       |              |
                  |            |                       |            |                       |              |
                  |            |                       |            |                       V              |
               DEC(Key)        |                    DEC(Key)        |                    DEC(Key)          |
                  |            |                       |            |                       |              |
                  |            |                       |            |                       |              |
                  |            |                       |            |                ###########@@@@@      |
                  |            |                       |            |                       |   --+--      |
                  |            |                       |            |                       |     |        |
                  |            |                       |            |                       |     +--------+
   IV----------->XOR           +--------------------->XOR           +--------------------->XOR							 
				  |                                    |                                    |
                  |                                    |                                    |
                  V                                    V                                    V
           ################                     ################                      ###########
           plaintext block                      plaintext block                       last plaintext block
*/
			if (lastLength == this.blockSize) {
				if (this.type == 'CS3') {
					// last block should be first processed because of IV
					// in cbc mode, processing will change the IV.
					lastBlock = this.cbcMode.process(this.lastBlock);
					block = this.cbcMode.process(this.state);
				} else {
					block = this.cbcMode.process(this.state);
					lastBlock = this.cbcMode.process(this.lastBlock);
				}

				output = this.type == 'CS3' ? Buffer.concat([lastBlock, block]) : Buffer.concat([block, lastBlock]);
			} else {
				if (this.type == 'CS2' || this.type == 'CS3') {
					lastBlock = this.algorithm.decryptBlock(this.state);
					var temp = Buffer.concat([this.lastBlock, lastBlock.slice(lastLength)]);
					block = this.cbcMode.process(temp);
					lastBlock = Buffer.xor(lastBlock, temp);
					output = Buffer.concat([block, lastBlock.slice(0, lastLength)]);
				} else {
					lastBlock = this.algorithm.decryptBlock(Buffer.concat([this.state.slice(lastLength), this.lastBlock]));
					block = this.cbcMode.process(Buffer.concat([this.state.slice(0, lastLength), lastBlock.slice(lastLength)]));
					lastBlock = Buffer.xor(lastBlock, this.state);
					output = Buffer.concat([block, lastBlock.slice(0, lastLength)]);
				}
			}
		}

		this.state = null;
		this.lastBlock = null;
		this.isEncryption = null;
		this.blockSize = null;

		if (typeof this.algorithm.reset === 'function') {
			this.algorithm.reset();
		}

		return output;
	}
};

jCastle.mcrypt.mode['cts-cbc'] = jCastle.mcrypt.mode['cts'];

// Cipher Text Stealing(CTS) mode
// https://en.wikipedia.org/wiki/Ciphertext_stealing
jCastle.mcrypt.mode['cts-ecb'] = class
{
    constructor()
    {
        this.algorithm = null;
        this.state = null;
        this.isEncryption = true;
        this.blockSize = 0;
    }

	init(algorithm, options)
	{
		this.algorithm = algorithm;
		this.state = Buffer.alloc(0);
		this.isEncryption = options.isEncryption;
		this.blockSize = options.blockSize;

		this.type = 'ctsType' in options ? this.type = options.ctsType.toUpperCase() : 'CS3';

		switch (this.type) {
			case "CS1":
			case "CS2":
			case "CS3":
				break;
			default:
				throw jCastle.exception("INVALID_CTS_TYPE", 'MOD014');
		}

		this.ecbMode = jCastle.mcrypt.mode.create('ecb');
		this.ecbMode.init(this.algorithm, options);
		this.lastBlock = Buffer.alloc(0);
	}

	process(input)
	{
		var output;

		if (this.lastBlock.length) {
			if (this.state.length) {
				output = this.ecbMode.process(this.state);
			}
			this.state = this.lastBlock.subarray();
		}
		this.lastBlock = Buffer.slice(input);

		return output;
	}

	finish() 
	{
		var block, lastBlock, lastLength = this.lastBlock.length;
		var output;

		if (!lastLength) {
			throw jCastle.exception('DATA_TOO_SHORT_FOR_MODE', 'MOD015');
		}

/*
when CTS is working with ECB mode then,
the decryption process is the same with the encryption process.

Encryption with CTS-ECB(CS3):
-----------------------------

    plaintext block                last plaintext block
    ################               ###########
          |                               |
          |                               |
       ENC(Key)                           |
          |                               |
          |                               |
    ###########@@@@@               ###########@@@@@ <-----+
      |       --+--                       |               |
      |         |                         |               |
      |         +-------------------------|---------------+
      |                                   |
      |                                   |
      |                                ENC(Key)
      |                                   |
      |                                   |
      |   +-------------------------------+
      |   |                               
      +---|-------------------------------+
          |                               |
          |                               |
          V                               V
    ################               ###########
	ciphertext block               last ciphertext block


Decryption with CTS-ECB(CS3):
-----------------------------

    ciphertext block               last ciphertext block
    ################               ###########
          |                               |
          |                               |
       DEC(Key)                           |
          |                               |
          |                               |
    ###########@@@@@               ###########@@@@@ <-----+
      |       --+--                       |               |
      |         |                         |               |
      |         +-------------------------|---------------+
      |                                   |
      |                                   |
      |                                DEC(Key)
      |                                   |
      |                                   |
      |   +-------------------------------+
      |   |                               
      +---|-------------------------------+
          |                               |
          |                               |
          V                               V
    ################               ###########
	plaintext block                last plaintext block

*/
		if (lastLength == this.blockSize) {
			block = this.ecbMode.process(this.state);
			lastBlock = this.ecbMode.process(this.lastBlock);

			output = this.type == 'CS3' ? Buffer.concat([lastBlock, block]) : Buffer.concat([block, lastBlock]);
		} else {
			block = this.ecbMode.process(this.state);
			lastBlock = this.ecbMode.process(Buffer.concat([this.lastBlock, block.slice(lastLength)]));
			if (this.type == 'CS2' || this.type == 'CS3') {
				output = Buffer.concat([lastBlock, block.slice(0, lastLength)]);
			} else {
				output = Buffer.concat([block.slice(0, lastLength), lastBlock]);
			}
		}

		this.state = null;
		this.lastBlock = null;
		this.isEncryption = null;
		this.blockSize = null;

		if (typeof this.algorithm.reset === 'function') {
			this.algorithm.reset();
		}

		return output;
	}
};

// XOR Encrypt XOR Tweakable Block Cipher Text Stealing(XTS) mode
//
// XTS-AES mode was designed for the cryptographic protection of data on storage devices 
// that use of fixed length "data units".
// because of that it need a data unit(dataUnit) as one of input data.
// dataUnit does not necessarily correspond to a physical block on the storage device.
//
// reference:
// http://libeccio.di.unisa.it/Crypto14/Lab/p1619.pdf
// http://grouper.ieee.org/groups/1619/email/pdf00086.pdf
//
// http://www.gladman.me.uk/AES
// https://github.com/heisencoder/XTS-AES
// http://web.cs.ucdavis.edu/~rogaway/papers/modes.pdf
// https://en.wikipedia.org/wiki/Disk_encryption_theory#XTS
//
// test vectors can be found:
// https://github.com/coruus/nist-testvectors/tree/master/csrc.nist.gov/groups/STM/cavp/documents/aes
jCastle.mcrypt.mode['xts'] = class
{
    constructor()
    {
        this.algorithm = null;
        this.state = null;
        this.isEncryption = true;
        this.blockSize = 0;
    }

	init(algorithm, options)
	{
		this.algorithm = algorithm;
		this.state = Buffer.alloc(0);
		this.isEncryption = options.isEncryption;
		this.blockSize = options.blockSize;

		if (this.blockSize != 16) {
			throw jCastle.exception("INVALID_BLOCKSIZE", 'MOD016');
		}

		if (!('tweakKey' in options)) {
			throw jCastle.exception("XTS_TWEAKKEY_NOT_GIVEN", 'MOD017');
		}
		this.tweakKey = options.tweakKey;
		if (!Buffer.isBuffer(this.tweakKey))
			this.tweakKey = Buffer.from(this.tweakKey, 'latin1');

/*
http://grouper.ieee.org/groups/1619/email/pdf00086.pdf
http://libeccio.di.unisa.it/Crypto14/Lab/p1619.pdf

5.1 Data units and tweaks

This standard applies to encryption of data stream divided into consecutive equal-size 
data units, where the data stream refers to the information that has to be encrypted 
and stored on the storage device. Information that is not to be encrypted is considered
to be outside of the data stream.
 
The data unit size shall be at least 128 bits. The number of 128-bit blocks in the data
unit shall not exceed 2^128 - 2. The number of 128-bit blocks should not exceed 2^20. 
Each data unit is assigned a tweak value which is a non-negative integer. The tweak 
values are assigned consecutively, starting from an arbitrary non-negative integer. 
When encrypting tweak value using AES, the tweak is first converted into a little-endian
byte array. For example, tweak value 123456789A(16) corresponds to byte array 
9a(16),78(16),56(16),34(16),12(16).

The mapping between the data unit and the transfer, placement and composition of data on
the storage device is beyond the scope of this standard. Devices compliant with this 
standard should include documentation describing this mapping. In particular, single data
unit does not necessarily correspond to a single logical block on the storage device. For 
example, several logical blocks might correspond to a single data unit. Data stream, as 
used in this standard, does not necessarily refer to all of the bits sent to be stored
in the storage device. In particular, if only part of a logical block is encrypted, only
the encrypted bytes are viewed as the data stream, i.e. input to the encryption algorithm
in this standard. 
*/
		this.tweak = Buffer.alloc(0);

		// data unit value should be 64 bits and it will be stored with little-endian order.

		if ('tweak' in options && options.tweak) {
			this.tweak = options.tweak;
			if (!Buffer.isBuffer(this.tweak))
				this.tweak = Buffer.from(this.tweak, 'latin1');

			if (this.tweak.length != this.blockSize) {
				throw jCastle.exception('INVALID_TWEAK_SIZE', 'MOD018');
			}
		} else {
			if (!('dataUnitSerial' in options)) {
				throw jCastle.exception("XTS_DATAUNIT_NOT_GIVEN", 'MOD019');
			}

			var dataUnitSerial = options.dataUnitSerial;

			// avoid [object String]
			if (jCastle.util.isString(dataUnitSerial)) dataUnitSerial = String(dataUnitSerial);
			switch (typeof dataUnitSerial) {
				case 'number':
					// in javascript any numbers that exceed 2^32 cannot be used for bit-wise function.
					dataUnitSerial = dataUnitSerial.toString(16);
					if (dataUnitSerial.length % 2) dataUnitSerial = '0' + dataUnitSerial;
					this.tweak = Buffer.from(dataUnitSerial, 'hex');
					break;
				case 'string':
					if (/^[0-9A-F]+$/i.test(dataUnitSerial)) {
						if (dataUnitSerial.length % 2) dataUnitSerial = '0' + dataUnitSerial;
						this.tweak = Buffer.from(dataUnitSerial, 'hex');
						break;
					}
					this.tweak = Buffer.from(dataUnitSerial, 'latin1');
					break;
				default:
					try {
						this.tweak = Buffer.from(dataUnitSerial, 'latin1');
					} catch (ex) {
						throw jCastle.exception("INVALID_DATAUNIT_SERIAL", 'MOD020');
					}
					break;
			}

			if (this.tweak.length > this.blockSize) {
				this.tweak = Buffer.slice(this.weak, 0, this.blockSize);
			} else if (this.tweak.length < this.blockSize) {
				var size = this.blockSize - this.tweak.length;
				this.tweak = Buffer.concat([this.tweak, Buffer.alloc(size)]);
			}
		}

		this.dataUnitLength = ('dataUnitLength' in options && typeof options.dataUnitLength == 'number') ? options.dataUnitLength : 0;
		if (this.dataUnitLength && this.dataUnitLength < this.blockSize * 8) {
			throw jCastle.exception("INVALID_DATAUNIT_LENGTH", 'MOD021');
		}

		this.bitsLength = 0;

		this.tweakAlgo = jCastle.mcrypt.getAlgorithm(this.algorithm.algoName);
		this.tweakAlgo.keySchedule(this.tweakKey, true);
		this.tweak = this.tweakAlgo.encryptBlock(this.tweak);

		this.lastBlock = Buffer.alloc(0);
	}

/*
    dataUnitSerial
          |
          |                       tweak                          tweak                    
    ENC(tweakKey)----+-------------MUL--------------+-------------MUL--------------+     
                     |                              |                              |     
                     |       plaintext block        |       plaintext block        |       plaintext block        
                     |       ################       |       ################       |       ###########@@@@@       
                     |              |               |              |               |              |   --+--       
                     |              |               |              |               |              |     |         
                     +------------>XOR              +------------>XOR              +------------>XOR    |
                     |              |               |              |               |              |     |
                     |              |               |              |               |              |     |
                     |           ENC(key)           |           ENC(key)           |           ENC(key) |
                     |              |               |              |               |              |     |
                     |              |               |              |               |              |     |
                     +------------>XOR              +------------>XOR              +------------>XOR    |
                                    |                              |                              |     |
                                    |                              |                              |     |
                                    |                       ###########@@@@@                      |     |
                                    |                              |   --+--        +-------------+     |
                                    |                              |     |          |                   |
                                    |                              |     +----------|-------------------+
                                    |                              |                |                  
                                    |                              +------------------------------+
                                    |                                               |             |
                                    |                                               |             |
                                    |                              +----------------+             |
                                    |                              |                              |
                                    |                              |                              |
                                    V                              V                              V
                             ################               ################              ###########
                             ciphertext block               ciphertext block              ciphertext block
*/

	process(input)
	{
		var output = Buffer.alloc(0);

		if (this.lastBlock.length) {
			if (this.state.length) {
				output = Buffer.xor(this.state, this.tweak);
				output = this.isEncryption ? this.algorithm.encryptBlock(output) : this.algorithm.decryptBlock(output);
				output = Buffer.xor(output, this.tweak);
				this.multiplyTweak();
				this.bitsLength += input.length * 8;
			}
			this.state = this.lastBlock.subarray();
		}
		this.lastBlock = Buffer.slice(input);

		return output;
	}

/*
D.5 Sector-size that is not a multiple of 128 bits

The generic XEX transform as described in [XEX04] immediately implies a method for 
encrypting sectors that consist of an integral number of 128-bit blocks: apply the 
transform individually to each 128-bit block, but use the block number in the sector
as part of the tweak value when encrypting that block. This method is applicable to 
the most common sector sizes (such as 512 bytes or 4096 bytes). However, it does not
directly apply to sector sizes that are not an integer multiple of 128-bit blocks 
(e.g., 520-byte sectors).

To encrypt a sector which length is not an integral number of 128-bit blocks, the 
standard uses the “ciphertext-stealing” technique similar to the one used for ECB 
mode (see [MM82, Fig. 2-22]). Namely, both XTS-AES-128 and XTS-AES-256 encrypt all
the full blocks except the last full block (with different tweak values for each 
block), and then encrypt the last full block together with the remaining partial block
using two application of the XTS-AES-blockEnc procedure described in 5.3.1 with two 
different tweak values, as described in 5.3.2. 
*/
	finish() 
	{

		var output, lastLength = this.lastBlock.length;
		var prevBlock, lastBlock;
		var bits;

		// xts mode need at least one 128 bit block.
		if (!this.state.length && lastLength != this.blockSize) {
			throw jCastle.exception('DATA_TOO_SHORT_FOR_MODE', 'MOD022');
		}

		if (!this.state.length) {
			// when only one block is given.
			output = Buffer.xor(this.lastBlock, this.tweak);
			output = this.isEncryption ? this.algorithm.encryptBlock(output) : this.algorithm.decryptBlock(output);
			output = Buffer.xor(output, this.tweak);
		} else if (this.isEncryption) {

/*
the last byte of the last block can be of incomplete bits according to the test vectors of nist.

	example:
	{
		count: 201,
		dataUnitLength: 130,
		key: "258a0e54b33347abb36fa24d28cae61902d514172df1a83756ae3932b9353f56",
		tweak: "720438c7211b6df569b40867b71d7989",
		pt: "b556cac9983f337345f81587f55a482a40",
		ct: "4a48e2cf351572e2708ca9ad05a3ee2580"
	}

	pt's bytes length is 17, but dataUnitLength is 130 not 136(8 * 17)!

         ################                                   #---------------
         second to last block                               last block
         +                                                  +
         |                                                  | <----------------------------+
         |                                                  |                              |
    6 bits and other 15 bytes should be                     the last byte                  |
    stealed from here and added to                          6 bits of it are empty         |
    the last block                                                                         |
         |                                                                                 |
         |                                                                                 |
         +---------------------------------------------------------------------------------+

      data length: 128 bits(16 bytes) + 2 bits(incomplete one byte) = 130 bits(17 bytes)

if dataUnitLength is not multiple of 8 like 130 then the last byte of the last block is incomplete.
	
if dataUnitLength is 130 then 6 bits of the last byte are empty.
then, the 6 bits from the same positioned byte and other 15 bytes should be stealed
from the block that is second to last.

*/
			this.bitsLength += this.state.length * 8 + this.lastBlock.length * 8;
			var stealBits = false;

			if (this.dataUnitLength) {
				bits = this.bitsLength - this.dataUnitLength;
				if (bits < 0) {
					throw jCastle.exception('INVALID_DATAUNIT_LENGTH_2', 'MOD023');
				}

				if (bits > 7) {
					throw jCastle.exception('INVALID_DATAUNIT_LENGTH_3', 'MOD024');
				}
				if (bits) stealBits = true;
			}				

			prevBlock = Buffer.xor(this.state, this.tweak);
			prevBlock = this.algorithm.encryptBlock(prevBlock);
			prevBlock = Buffer.xor(prevBlock, this.tweak);
			this.multiplyTweak();

			if (lastLength == this.blockSize) {
				if (!stealBits) {
					lastBlock = Buffer.xor(this.lastBlock, this.tweak);
					lastBlock = this.algorithm.encryptBlock(lastBlock);
					lastBlock = Buffer.xor(lastBlock, this.tweak);
					output = Buffer.concat([prevBlock, lastBlock]);
				} else {
					// there must be stealing
					lastBlock = Buffer.slice(this.lastBlock);
					var stealBits = this.stealBits(prevBlock, lastLength - 1, bits);
					lastBlock[lastLength - 1] |= stealBits;

					lastBlock = Buffer.xor(lastBlock, this.tweak);
					lastBlock = this.algorithm.encryptBlock(lastBlock);
					lastBlock = Buffer.xor(lastBlock, this.tweak);
					output = Buffer.concat([lastBlock, prevBlock]);
				}
			} else {
				lastBlock = Buffer.slice(prevBlock, 0, lastLength);
				var block = Buffer.concat([this.lastBlock, prevBlock.slice(lastLength)]);

				if (stealBits) {
					var stealedBits = this.stealBits(lastBlock, lastLength - 1, bits);
					block[lastLength - 1] |= stealedBits;
				}

				block = Buffer.xor(block, this.tweak);
				block = this.algorithm.encryptBlock(block);
				block = Buffer.xor(block, this.tweak);
				output = Buffer.concat([block, lastBlock]);
			}
		} else { // decryption
			this.bitsLength += this.state.length * 8 + this.lastBlock.length * 8;
			var stealBits = false;

			if (this.dataUnitLength) {
				bits = this.bitsLength - this.dataUnitLength;
				if (bits < 0) {
					throw jCastle.exception('INVALID_DATAUNIT_LENGTH_2', 'MOD025');
				}

				if (bits > 7) {
					throw jCastle.exception('INVALID_DATAUNIT_LENGTH_3', 'MOD026');
				}
				if (bits) stealBits = true;
			}				

			if (lastLength == this.blockSize) {
				if (!stealBits) { // two blocks of full 128 bits
					prevBlock = Buffer.xor(this.state, this.tweak);
					prevBlock = this.algorithm.decryptBlock(prevBlock);
					prevBlock = Buffer.xor(prevBlock, this.tweak);
					this.multiplyTweak();

					lastBlock = Buffer.xor(this.lastBlock, this.tweak);
					lastBlock = this.algorithm.decryptBlock(lastBlock);
					lastBlock = Buffer.xor(lastBlock, this.tweak);
					output = Buffer.concat([prevBlock, lastBlock]);
				} else {
					var tweak = Buffer.slice(this.tweak);
					this.multiplyTweak();

					prevBlock = Buffer.xor(this.state, this.tweak);
					prevBlock = this.algorithm.decryptBlock(prevBlock);
					prevBlock = Buffer.xor(prevBlock, this.tweak);

					lastBlock = Buffer.slice(this.lastBlock);
					var stealedBits = this.stealBits(lastBlock, lastLength - 1, bits);
					lastBlock[lastLength - 1] |= stealedBits;

					lastBlock = Buffer.xor(lastBlock, tweak);
					lastBlock = this.algorithm.decryptBlock(lastBlock);
					lastBlock = Buffer.xor(lastBlock, tweak);
					output = Buffer.concat([lastBlock, prevBlock]);
				}
			} else {
				// this.state should be xored by the next tweak,
				// for it has come from the last plaintext block.
				var tweak = Buffer.slice(this.tweak);
				this.multiplyTweak();

				prevBlock = Buffer.xor(this.state, this.tweak);
				prevBlock = this.algorithm.decryptBlock(prevBlock);
				prevBlock = Buffer.xor(prevBlock, this.tweak);
				lastBlock = Buffer.slice(prevBlock, 0, lastLength);
					
				prevBlock = Buffer.concat([this.lastBlock, prevBlock.slice(lastLength)]);

				if (stealBits) {
					var stealedBits = this.stealBits(lastBlock, lastLength - 1, bits);
					prevBlock[lastLength - 1] |= stealedBits;
				}

				prevBlock = Buffer.xor(prevBlock, tweak);
				prevBlock = this.algorithm.decryptBlock(prevBlock);
				prevBlock = Buffer.xor(prevBlock, tweak);
				output = Buffer.concat([prevBlock, lastBlock]);
			}
		}

		this.state = null;
		this.isEncryption = null;
		this.blockSize = null;
		this.tweak = null;

		if (typeof this.algorithm.reset === 'function') {
			this.algorithm.reset();
			if (this.tweakAlgo) this.tweakAlgo.reset();
		}

		this.tweakAlgo = null;
		
		return output;
	}

	stealBits(block, pos, bitSize)
	{
		var x = block[pos];
		x = (x << (8 - bitSize)) & 0xFF; // important! not use this: x <<= (8 - bitSize);
		x >>>= (8 - bitSize);

		// block[pos] should be extracted.
		block[pos] >>>= bitSize;
		block[pos] <<= bitSize;
		block[pos] &= 0xFF;
		return x & 0xFF;		
	}

/*
5.2 Multiplication by a primitive element α

The encryption and decryption procedures described in the following section use multiplication of a 16-
byte value (the result of AES encryption or decryption) by j-th power of α, a primitive element of GF(2^128).
The input value is first converted into a byte array a_0[k], k = 0,1,...,15. In particular, the 16-byte result of
AES encryption or decryption is treated as a byte array, where a_0[0] is the first byte of the AES block.

This multiplication is defined by the following procedure.

Input:  j is the power of α
        byte array a_0[k], k = 0,1,...,15
Output: byte array a_j[k], k = 0,1,...,15

The output array is defined recursively by the following formulas where i is iterated from 0 to j:

a_i+1[0] ← (2 (a_i[0] mod 128)) XOR (135 └ ai[15]/128 ┘)
a_i+1[k] ← (2 (a_i[k] mod 128)) XOR └ ai[k-1]/128┘, k = 1,2,…,15

Note - Conceptually, the operation is a left shift of each byte by one bit with carry propagating from one
byte to the next one. Also, if the 15th 32 (last) byte shift results in a carry, a special value (decimal 135) is xor-
ed into the first byte. This value is derived from the modulus of the Galois Field (polynomial
x^128 + x^7 + x^2 + x + 1). See Annex C for an alternative way to implement the multiplication by α^j. 
*/
	multiplyTweak()
	{
/*
// method 1.

		var a0 = this.tweak.readInt32LE(12);
		var a1 = this.tweak.readInt32LE(8);
		var a2 = this.tweak.readInt32LE(4);
		var a3 = this.tweak.readInt32LE(0);

		// Multiplication of two polynomials over the binary field.
		// GF(2) modulo x^128 + x^7 + x^2 + x + 1, where GF stands for Galois Field.
		var carry = (a0 & 0x80000000) == 0 ? 0 : 135;    // 135 = 0x87 = 10000111(2)

		a0 = a0 << 1 | a1 >>> 31;
		a1 = a1 << 1 | a2 >>> 31;
		a2 = a2 << 1 | a3 >>> 31;
		a3 = (a3 << 1) ^ carry;

		this.tweak.writeInt32LE(a0, 12);
		this.tweak.writeInt32LE(a1, 8);
		this.tweak.writeInt32LE(a2, 4);
		this.tweak.writeInt32LE(a3, 0);
*/

// method 2.

		var i = this.blockSize;
		var t = this.tweak[this.blockSize - 1];
		while (--i != 0) {
			this.tweak[i] = ((this.tweak[i] << 1) | ((this.tweak[i - 1] & 0x80) != 0 ? 1 : 0)) & 0xFF;
		}
		this.tweak[0] = ((this.tweak[0] << 1) ^ ((t & 0x80) != 0 ? 0x87 : 0x00)) & 0xFF;




/*
// method 3.

		var Cin = 0, Cout, GF_128_FDBK = 0x87;
		for (var i = 0; i < this.tweak.length; i++) {
			Cout = (this.tweak[i] >>> 7) & 0x01;
			this.tweak[i] = ((this.tweak[i] << 1) + Cin) & 0xFF;
			Cin = Cout;
		}

		if (Cout) this.tweak[0] = (this.tweak[0] ^ GF_128_FDBK) & 0xFF;
*/
	}
};

jCastle.mcrypt.mode['eax'] = class
{
    constructor()
    {
        this.algorithm = null;
        this.state = null;
        this.isEncryption = true;
        this.blockSize = 0;
    }

    // EAX is an AEAD scheme based on CTR and OMAC1/CMAC, that uses a single block
	// cipher to encrypt and authenticate data. It's on-line (the length of a
	// message isn't needed to begin processing it), has good performances, it's
	// simple and provably secure (provided the underlying block cipher is secure).
	// Of course, this implementation is NOT thread-safe.
	init(algorithm, options)
	{
		this.algorithm = algorithm;
		this.state = Buffer.alloc(0);
		this.isEncryption = options.isEncryption;
		this.blockSize = options.blockSize;

//		if (typeof jCastle.mac == 'undefined') {
//			throw jCastle.exception("MAC_REQUIRED", 'MOD027');
//		}

		// There is no limitation of the length of nonce in EAX mode

		this.nonce = Buffer.from(options.nonce, 'latin1');

		this.tagSize = this.blockSize;
		if ('tagSize' in options) {
			this.tagSize = options.tagSize;
		}

		// additional authenticated data
		this.additionalData = Buffer.alloc(0);
		if ('additionalData' in options) {
			//this.additionalData = Buffer.from(options.additionalData, 'latin1');
			this.additionalData = Buffer.from(options.additionalData);
		}

		var algo_name = this.algorithm.algoName;
		//var key = this.algorithm.masterKey;
		var key = options.key;
		var algo = new jCastle.algorithm[jCastle._algorithmInfo[algo_name].object_name](algo_name);
		algo.keySchedule(key, true);

		var tag = Buffer.alloc(this.blockSize);
		//tag.fill(0);
		tag[this.blockSize - 1] = 0x01;

		var cMac_options = {
			key: key,
			blockSize: this.blockSize
		};

		this.cMac = jCastle.mac.mode.create('cmac');
		this.cMac.init(algo, cMac_options);

		this.cMac.process(tag);
		this.cMac.process(this.additionalData);
		this.additionalDataMac = this.cMac.finish();

		tag[this.blockSize - 1] = 0x00;
		this.cMac.init(algo, cMac_options);
		this.cMac.process(tag);
		this.cMac.process(this.nonce);
		this.nonceMac = this.cMac.finish();

		tag[this.blockSize - 1] = 0x02;
		this.cMac.init(algorithm, cMac_options);
		this.cMac.process(tag);

		this.ctrMode = jCastle.mcrypt.mode.create('ctr');
		this.ctrMode.init(this.algorithm, {
			iv: this.nonceMac,
			blockSize: this.blockSize,
			isEncryption: this.isEncryption});

	}

/*
EAX Encryption Routine:

    +---------+             +-----------+              +----------------------------+
    |  Nonce  |             |  Message  |              |  Header (Associated Data)  |
	+----+----+             +-----+-----+              +--------------+-------------+
	     |                        |                                   |
+--------+--------+               |                          +--------+--------+
| CMac(0x00, Key) |               |                          | CMac(0x01, Key) |
+--------+--------+               |                          +--------+--------+
	     |                        |                                   |
      +--+--+               +-----+-----+                          +--+--+
      |  N` |-------------> | CTR(Key)  |                          |  H` |
      +--+--+               +-----+-----+                          +--+--+
         |                        |                                   |
	     |          +-------------+-------------+                     |
	     |          |      C - Ciphertext       |                     |
	     |          +-------------+-------------+                     |
	     |                        |                                   |
	     |              +---------+----------+                        |
	     |              |  cMac(0x02, Key)   |                        |
	     |              +---------+----------+                        |
	     |                        |                                   |
	     |                     +--+--+                                |
         |                     |  C` |                                |
	     |                     +--+--+                                |
	     |                        |                                   |
	     |                    +---+---+                               |
	     +------------------> | (xor) | <-----------------------------+
                              +---+---+                
                                  |
	                       +------+------+                
                           |  T - Tag    |
	                       +-------------+                

Output : C + T.
*/

	process(input)
	{
		var output = Buffer.alloc(0);

		if (this.state.length) {
			if (this.isEncryption) {
				output = this.ctrMode.process(this.state);
				this.cMac.process(output);
				this.state = input;
			} else {
				if (input.length == this.blockSize) {
					this.cMac.process(this.state);
					output = this.ctrMode.process(this.state);
					this.state = Buffer.slice(input);
				} else {
					// tag is both in input and state.
					this.state = Buffer.concat([this.state, input]);
					var len = this.state.length - this.blockSize;

					if (this.state.length > this.blockSize) {
						this.cMac.process(this.state.slice(0, len));
						output = this.ctrMode.process(this.state.slice(0, len));
						this.state = Buffer.slice(this.state, len);
					}
				}				
			}
		} else {
			this.state = Buffer.slice(input);
		}

		return output;
	}

	finish()
	{
		var output = Buffer.alloc(0);

		if (this.isEncryption) {
			if (this.state.length) {
				output = this.ctrMode.process(this.state);
				this.cMac.process(output);
			}

			var mac = this.calculateMac();
			output = Buffer.concat([output, mac.slice(0, this.tagSize)]);
		} else {
			// the only tag is remained.
			var v_mac = this.calculateMac();
//			var v_mac_trimed = Buffer.slice(v_mac, 0, this.tagSize);
//			if (!v_mac_trimed.equals(this.state)) {
			if (!v_mac.slice(0, this.tagSize).equals(this.state)) {
				throw jCastle.exception("MAC_CHECK_FAIL", 'MOD028');
			}
		}

		this.state = null;
		this.isEncryption = null;
		this.blockSize = null;
		this.state = null;

        if (typeof this.algorithm.reset === 'function') {
			this.algorithm.reset();
		}

		this.ctrMode.finish();

		return output;
	}

	calculateMac()
	{
		var mac = this.cMac.finish();

		for (var i = 0; i < this.blockSize; i++) {
			mac[i] ^= this.nonceMac[i] ^ this.additionalDataMac[i];
		}

		return mac;
	}
};

jCastle.mcrypt.mode['ccm'] = class
{
    constructor()
    {
        this.algorithm = null;
        this.state = null;
        this.isEncryption = true;
        this.blockSize = 0;
        this.iv = null;
        this.nonce = null;
    }

	// https://tools.ietf.org/html/rfc3610
	// Implements the Counter with Cipher Block Chaining mode (CCM) detailed in
	// NIST Special Publication 800-38C.
	// http://csrc.nist.gov/publications/nistpubs/800-38C/SP800-38C.pdf
	init(algorithm, options)
	{
		this.algorithm = algorithm;
		this.state = Buffer.alloc(0);
		this.isEncryption = options.isEncryption;
		this.blockSize = options.blockSize;

		this.nonce = Buffer.from(options.nonce, 'latin1');

		if (this.blockSize != 16) {
			throw jCastle.exception("MODE_INVALID_BLOCKSIZE", 'MOD029');
		}

		// { 7, 8, 9, 10, 11, 12, 13 }
		if (this.nonce.length < 7 || this.nonce.length > 13) {
			throw jCastle.exception("INVALID_NONCE", 'MOD030');
		}

/*
RFC 5084          Using AES-CCM and AES-GCM in the CMS

   With all three AES-CCM algorithm identifiers, the AlgorithmIdentifier
   parameters field MUST be present, and the parameters field must
   contain a CCMParameter:

      CCMParameters ::= SEQUENCE {
        aes-nonce         OCTET STRING (SIZE(7..13)),
        aes-ICVlen        AES-CCM-ICVlen DEFAULT 12 }

      AES-CCM-ICVlen ::= INTEGER (4 | 6 | 8 | 10 | 12 | 14 | 16)

   The aes-nonce parameter field contains 15-L octets, where L is the
   size of the length field.  With the CMS, the normal situation is for
   the content-authenticated-encryption key to be used for a single
   content; therefore, L=8 is RECOMMENDED.  See [CCM] for a discussion
   of the trade-off between the maximum content size and the size of the
   nonce.  Within the scope of any content-authenticated-encryption key,
   the nonce value MUST be unique.  That is, the set of nonce values
   used with any given key MUST NOT contain any duplicate values.

   The aes-ICVlen parameter field tells the size of the message
   authentication code.  It MUST match the size in octets of the value
   in the AuthEnvelopedData mac field.  A length of 12 octets is
   RECOMMENDED.
*/
		// { 4, 6, 8, 10, 12, 14, 16 }
		this.tagSize = 12;
		if ('tagSize' in options) {
			if (options.tagSize % 2 || options.tagSize < 4 || options.tagSize > 16) {
				throw jCastle.exception("MODE_INVALID_TAGSIZE", 'MOD031');
			}
			this.tagSize = options.tagSize;
		}
/*
the counter generation function in this section is equivalent to 
a formating of the counter index i into a complete data block.
The counter blocks Ctr-i are formatted as shown in Table 3 below.

        Table 3: Formatting of Ctr-i

-------------+---------+----------------+--------------
octet number |     0   |   1 ... 15-q   | 16-q ... 15
-------------+---------+----------------+--------------
contents     | flags   |       N        |     [i]8q
-------------+---------+----------------+--------------

Withn each block Ctr-i, the flags field is formatted as shown in table 4 below.

        Table 4: Formattig of the Flags Field in Ctr-i

-----------+----------+----------+-----+-----+-----+-----+-----+-----+------
bit number |    7     |    6     |  5  |  4  |  4  |  3  |  2  |  1  |  0
-----------+----------+----------+-----+-----+-----+-----+-----+-----+------
contents   | reserved | reserved |  0  |  0  |  0  |  0  |      [q-1]3 
-----------+----------+----------+-----+-----+-----+-----+-----+-----+------

*/
		var q = 15 - this.nonce.length;
		
		this.iv = Buffer.alloc(this.blockSize);
		this.iv[0] = (q - 1) & 0x07;
		this.iv.set(this.nonce, 1);
		
		// additional authenticated data
		this.additionalData = Buffer.alloc(0);
		if ('additionalData' in options) {
			this.additionalData = Buffer.from(options.additionalData);
		}

		// CCM mode is alike stream mode.
		// calculating mac requires us to save all inputs.
		this.data = Buffer.alloc(0);
	}

	process(input)
	{
		// there is nothing to do exept saving the input.
		// when decryption, the mac data should be calculated first using ctrMode,
		// we cannot process anything here.

		this.data = Buffer.concat([this.data, input]);
	}

	finish()
	{
		var data = this.data;
		var ctrMode = jCastle.mcrypt.mode.create('ctr');

		ctrMode.init(this.algorithm, {
			iv: this.iv,
			blockSize: this.blockSize,
			isEncryption: this.isEncryption});

		var blockSize = this.blockSize;
		var output = Buffer.alloc(0);

		if (this.isEncryption) {
			var mac = this.calculateMac(data);
			mac = ctrMode.process(mac);

			for (var i = 0; i < data.length; i += blockSize) {
				output = Buffer.concat([output, ctrMode.process(data.slice(i, i + blockSize))]);
			}

			output = Buffer.concat([output, mac]);
		} else {
			var mac = Buffer.slice(data, data.length - this.tagSize);
			var input = Buffer.slice(data, 0, data.length - this.tagSize);
			
			mac = ctrMode.process(mac);

			for (var i = 0; i < input.length; i += blockSize) {
				output = Buffer.concat([output, ctrMode.process(input.slice(i, i + blockSize))]);
			}
			
			var v_mac = this.calculateMac(output);

			if (!v_mac.slice(0, this.tagSize).equals(mac)) {
				throw jCastle.exception("MAC_CHECK_FAIL", 'MOD032');
			}
		}

		ctrMode.finish();

		this.reset();

		return output;
	}

	reset()
	{
		this.state = null;
		this.isEncryption = null;
		this.blockSize = null;
		this.iv = null;
		this.nonce = null;
		this.tagSize = null;

		if (typeof this.algorithm.reset === 'function') {
			this.algorithm.reset();
		}
	}

	calculateMac(data)
	{
		// we will caculate CBC-MAC with CBC mode.
		var cbcMode = jCastle.mcrypt.mode.create('cbc');

		// CBC-MAC has 0 initial vector
		// CBC-MAC always encrypts the data
		var algo_name = this.algorithm.algoName;
		var key = this.algorithm.masterKey;
		var algorithm = new jCastle.algorithm[jCastle._algorithmInfo[algo_name].object_name](algo_name);
		algorithm.keySchedule(key, true);

		cbcMode.init(algorithm, {
			iv: Buffer.alloc(this.blockSize),
			blockSize: this.blockSize,
			isEncryption: true});

		// build b0
		var b0 = Buffer.alloc(16);

/*

n is nonce octet length, a is additional text's octet length and p is data's octet length.
t is octet length of the tag, and p is represented within the first block of the formatted
data(b0) as an octet string denoted Q. q is the octet length of Q.

t is an element of {4, 6, 8, 10, 12, 14, 16};
q is an element of {2, 3, 4, 5, 6, 7, 8};
n is an element of {7, 8, 9, 10, 11, 12, 13};
n + q = 15;
a < 2**64;

           Table 1: Formatting of the Flags Octet in B0

-----------+----------+-------+-------+-------+-------+-------+-------+--------
bit number |    7     |   6   |   5   |   4   |   3   |   2   |   1   |   0
-----------+----------+-------+-------+-------+-------+-------+-------+--------
contents   | reserved | adata |     (t - 2) / 2       |         q - 1
-----------+----------+-------+-------+-------+-------+-------+-------+--------

The remaining 15 octets of the first block of the formatting are devoted to the nonce and the 
binary representation of the message length in q octets, as given in table 2.

           Table 2: Formatting of B0

-------------+-------+------------+--------------
octet number |   0   | 1 ... 15-q | 16-q ... 15
-------------+-------+------------+--------------
contents     | flags |     N      |      Q
-------------+-------+------------+--------------

*/
		if (this.additionalData.length) {
			b0[0] |= 0x40; // 0100 0000
		}

		var q = 15 - this.nonce.length;

		b0[0] |= (((this.tagSize - 2) / 2) & 0x07) << 3;
		b0[0] |= (q - 1) & 0x07;

		b0.set(this.nonce, 1);

		var p = data.length;
		for (var i = this.blockSize - 1; i >= (16 - q); i--) {
			b0[i] = p & 0xff;
			p >>>= 8;
		}

		var size;
		var b = Buffer.slice(b0);

/*
if a > 0, then a is encoded as described below, and the encoding of a is concatednated with
the associated data A, followed by the minimum number of '0' bits, possibly none, 
such that the resulting string can be partitioned into 16-octet blocks.

The value a is encoded according to the following three cases:

if 0 < a < 2**16 - 2**8, then a is encoded as [a]16, i.e., two octets.
if 2**16 - 2**8 <= a < 2**32, then a is encoded as 0xff || 0xfe || [a]32, i.e., six octets.
if 2*32 <= a < 2**64, then a is encode as 0xff || 0xff || [a]64, i.e., ten octets.

Do not forget that the javascript's safe maximum number is 2**32(0xFFFFFFFF). 
*/
		// process associated text or additional text
		if (this.additionalData.length) {
			var alen = this.additionalData.length;
			
			var l = [];

			if (alen >= (65536 - 256)) { // (1<<16 - 1<<8
				l.push(0xff);
				l.push(0xfe);
				l.push((alen >>> 24) & 0xff);
				l.push((alen >>> 16) & 0xff);

			}

			l.push((alen >>> 8) & 0xff);
			l.push(alen & 0xff);

			b = Buffer.concat([b, Buffer.from(l), this.additionalData]);

			size = b.length % this.blockSize;
			if (size) {
				b = Buffer.concat([b, Buffer.alloc(this.blockSize - size)]);
			}
		}

/*
The associated data blocks, if any, are followed in the sequence of formatted blocks
by the payload blocks. the payload is concatednated with the minimum number of '0' bits,
possibly none, such that the result can be partitioned into 16-octet blocks.
*/

		b = Buffer.concat([b, data]);
		// zero padding
		size = b.length % this.blockSize;
		if (size) {
			b = Buffer.concat([b, Buffer.alloc(this.blockSize - size)]);
		}

		var mac;
		
		for (var i = 0; i < b.length; i += this.blockSize) {
			mac = cbcMode.process(b.slice(i, i + this.blockSize));
		}

		cbcMode.finish();

		return Buffer.slice(mac, 0, this.tagSize);
	}
};

jCastle.mcrypt.mode['gcm'] = class
{
    constructor()
    {
        this.algorithm = null;
        this.state = null;
        this.isEncryption = true;
        this.blockSize = 0;
    }

	// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
	// http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf
	// http://www.ieee802.org/1/files/public/docs2011/bn-randall-test-vectors-0511-v1.pdf
	init(algorithm, options)
	{
		this.algorithm = algorithm;
		this.state = Buffer.alloc(0);
		this.isEncryption = options.isEncryption;
		this.blockSize = options.blockSize;
		
		// with GCM cipher mode, the algorithm is always used in forward mode
		if (!this.isEncryption) this.algorithm.keySchedule(algorithm.masterKey, true);

		this.nonce = Buffer.from(options.nonce, 'latin1');

		if (this.blockSize != 16) {
			throw jCastle.exception("MODE_INVALID_BLOCKSIZE", 'MOD033');
		}

		// For GCM mode, 1 <= len(IV) <= power(2, 64)-1
		if (!this.nonce || !this.nonce.length) {
			throw jCastle.exception("INVALID_NONCE", 'MOD034');
		}

		// The constant within the algorithm for the block multiplication operation
		// this.R = BigInt("0b11100001") << 120n;
		// we don't need to calculte all. Just the last block will be used.
		this.galoisR = 0xe1;

/*
RFC 5084          Using AES-CCM and AES-GCM in the CMS

   With all three AES-GCM algorithm identifiers, the AlgorithmIdentifier
   parameters field MUST be present, and the parameters field must
   contain a GCMParameter:

      GCMParameters ::= SEQUENCE {
        aes-nonce        OCTET STRING, -- recommended size is 12 octets
        aes-ICVlen       AES-GCM-ICVlen DEFAULT 12 }

      AES-GCM-ICVlen ::= INTEGER (12 | 13 | 14 | 15 | 16)

   The aes-nonce is the AES-GCM initialization vector.  The algorithm
   specification permits the nonce to have any number of bits between 1
   and 2^64.  However, the use of OCTET STRING within GCMParameters
   requires the nonce to be a multiple of 8 bits.  Within the scope of
   any content-authenticated-encryption key, the nonce value MUST be
   unique, but need not have equal lengths.  A nonce value of 12 octets
   can be processed more efficiently, so that length is RECOMMENDED.

   The aes-ICVlen parameter field tells the size of the message
   authentication code.  It MUST match the size in octets of the value
   in the AuthEnvelopedData mac field.  A length of 12 octets is
   RECOMMENDED.
*/
		this.tagSize = 12;
		if ('tagSize' in options) {
			if (options.tagSize < 11 || options.tagSize > 16) {
				throw jCastle.exception('MODE_INVALID_TAGSIZE', 'MOD057');
			}

			this.tagSize = options.tagSize;
		}

		// additional authenticated data
		this.additionalData = Buffer.alloc(0);
		if ('additionalData' in options) {
			this.additionalData = Buffer.from(options.additionalData);
		}

		// the hash subkey
		this.galoisH = this.algorithm.encryptBlock(Buffer.alloc(this.blockSize));
		this.S0 = this.galoisHash(this.galoisH, Buffer.alloc(this.blockSize), this.additionalData);

		// ICB - initial counter block
		// For IVs, it is recommended that implementations restrict support to the length of 96 bits, 
		// to promote interoperability, efficiency, and simplicity of design.
		if (this.nonce.length == 12) {
			this.J0 = Buffer.alloc(this.blockSize);
			this.J0.set(this.nonce, 0);
			this.J0[this.J0.length - 1] = 0x01;
		} else {
			this.J0 = this.galoisHash(this.galoisH, Buffer.alloc(this.blockSize), this.nonce);
			var L = Buffer.alloc(this.blockSize);

			// we don't need 64-bit length because javascript doesn't support that length integer.
			// we will reduce it to 32-bit integer.
			L.writeInt32BE(this.nonce.length * 8, 12);
			this.J0 = this.galoisHash(this.galoisH, this.J0, L);
        }
		
		this.counter = Buffer.slice(this.J0);
		this.dataLength = 0;
	}

	process(input)
	{
		var temp, output;

		if (this.isEncryption) {
			var size = input.length;
			if (size == this.blockSize) temp = input;
			else {
				temp = Buffer.alloc(this.blockSize);
				temp.set(input, 0);
			}
			output = this.galoisCTR(temp, size);
			this.dataLength += input.length;
			return output;
		} else {
			if (!this.state.length) { // first time
				if (input.length < this.blockSize) {
					throw jCastle.exception("DATA_TOO_SHORT", 'MOD035');
				}
				this.state = Buffer.slice(input);
				return Buffer.alloc(0);
			}
			if (input.length < this.blockSize) {
				// input length is less than block size
				// it means the input has parts of mac block and cipher.state has also.
				
				temp = Buffer.alloc(this.blockSize);
				temp.set(this.state.slice(0, input.length), 0);
				output = this.galoisCTR(temp, input.length);
				this.state = Buffer.concat([this.state.slice(input.length), input]);
				this.dataLength += output.length;
				return output;
			}
			// normall
			output = this.galoisCTR(this.state, input.length);
			this.state = Buffer.slice(input);
			this.dataLength += output.length;
			return output;
		}
	}

	finish()
	{
		// Final ghash
		var X = Buffer.alloc(this.blockSize);
		// the biggest length in javascript is 4Gi
		X.writeInt32BE(this.additionalData.length * 8, 4);
		X.writeInt32BE(this.dataLength * 8, 12);

		this.S0 = this.galoisHash(this.galoisH, this.S0, X);
		// T - The authentication tag
		var J = this.algorithm.encryptBlock(this.J0);
		var tag = Buffer.xor(this.S0, J);

		if (this.isEncryption) {
			this.reset();
			return tag;
		} else {
			if (!tag.equals(this.state)) {
				// console.log('tag: ' + tag.toString('hex'));
				// console.log('state: ' + this.state.toString('hex'));
				throw jCastle.exception("MAC_CHECK_FAIL", 'MOD036');
			}
			this.reset();
			return;
		}
	}

	reset()
	{
		this.S0 = null;
		this.counter = null;
		this.J0 = null;
		this.additionalData = null;
		this.state = null;
		this.dataLength = 0;

		if (typeof this.algorithm.reset === 'function') {
			this.algorithm.reset();
		}
	}

	galoisHash(H, Y0, data)
	{
		var Yi = Buffer.slice(Y0);
	
		for (var i = 0; i < data.length; i += this.blockSize) {
			Yi = Buffer.xor(Yi, data.slice(i, i + this.blockSize));
			Yi = this.galoisMultiply(Yi, H);
		}

		return Yi;
	}

	galoisMultiply(x, y)
	{
		var Zi = Buffer.alloc(this.blockSize);
		var Vi = Buffer.slice(y);
		var Xi;

		// Block size is 128bits, run 128 times to get Z_128
		for (var i = 0; i < 128; i++) {
			Xi = (x[Math.floor(i / 8)] & (1 << (7 - i % 8))) !== 0;

			if (Xi) {
				Zi = Buffer.xor(Zi, Vi);
			}

			// Store the value of LSB(V_i)
			var lsb = (Vi[15] & 1) !== 0;

			// V_i+1 = V_i >> 1
			for (var j = 15; j > 0; j--) {
				Vi[j] = (Vi[j] >>> 1) | ((Vi[j - 1] & 1) << 7);
			}
			Vi[0] = Vi[0] >>> 1;

			// If LSB(V_i) is 1, V_i+1 = (V_i >> 1) ^ R
			if (lsb) {
				Vi[0] ^= this.galoisR;
			}
		}

		return Zi;
	}

	galoisCTR(block, size)
	{
		var output = Buffer.alloc(size);
		this.increaseCounter();
		var tmp = this.algorithm.encryptBlock(this.counter);

		if (this.isEncryption) {
			for (var i = size; i < this.blockSize; i++) {
				tmp[i] = 0x00;
			}
			for (var l = size-1; l >= 0; l--) {
				tmp[l] ^= block[l];
				output[l] = tmp[l];
			}
			this.S0 = this.galoisHash(this.galoisH, this.S0, tmp);
		} else {
			for (var l = size-1; l >= 0; l--) {
				tmp[l] ^= block[l];
				output[l] = tmp[l];
			}
			this.S0 = this.galoisHash(this.galoisH, this.S0, block);
		}
		return output;
	}

	increaseCounter()
	{
		for (var p = 15; p >= 12; p--) {
			var b = (this.counter[p] + 1) & 0xff;
			this.counter[p] = b & 0xff;
			if (b != 0) break;
		}
	}
};

/*
jCastle.mcrypt.mode['gcm'] = class
{
    constructor()
    {
        this.algorithm = null;
        this.state = null;
        this.isEncryption = true;
        this.blockSize = 0;
    }

	init(algorithm, options)
	{
		this.algorithm = algorithm;
		this.isEncryption = options.isEncryption;
		this.blockSize = options.blockSize;

		this.nonce = Buffer.from(options.nonce);

		if (this.blockSize != 16) {
			throw jCastle.exception("MODE_INVALID_BLOCKSIZE", 'MOD038');
		}

		// For GCM mode, 1 <= len(IV) <= power(2, 64)-1
		if (this.nonce.length == 0) {
			throw jCastle.exception("INVALID_NONCE", 'MOD039');
		}

		this.state = Buffer.slice(this.nonce);

		// The constant within the algorithm for the block multiplication operation
		this.R = BigInt("0b11100001") << 120n;

		this.tagSize = this.blockSize;

		// additional authenticated data
		this.additionalData = Buffer.alloc(0);
		if ('additionalData' in options) {
			this.additionalData = Buffer.from(options.additionalData);
		}

		// the hash subkey
		this.ZERO_BLOCK = Buffer.alloc(this.blockSize);
		h = this.algorithm.encryptBlock(this.ZERO_BLOCK);
		this.H = BigInt.fromBuffer(h);

		// ghash function needs this.H
		this.S = this.ghash(this.additionalData, false);

		// ICB - initial counter block
		// For IVs, it is recommended that implementations restrict support to the length of 96 bits, 
		// to promote interoperability, efficiency, and simplicity of design.
		if (this.state.length == 12) {
			this.J0 = Buffer.alloc(this.blockSize);
			this.J0.set(this.state, 0);
			this.J0[15] = 0x01;
		} else {
			var N = this.ghash(this.state, true);
			var X = BigInt(this.state.length * 8);
			N = this.gmultiply(N.xor(X), this.H);
			this.J0 = this.BigIntToBuffer(N, this.blockSize);
        }
		
		this.counter = Buffer.slice(this.J0);

		this.state = Buffer.alloc(0);
		this.dataLength = 0;
	}

	process(input)
	{
		this.dataLength += input.length;

		if (this.isEncryption) {
			var temp, size = input.length;
			if (size < this._blockSize) {
				temp = Buffer.alloc(this.blockSize);
				temp.set(input, 0);
			} else {
				temp = input;
			}
			var output = this.gctr(input, size);
			return output;
		} else {
			if (!this.state.length) { // first time
				if (input.length < this.blockSize) {
					throw jCastle.exception('DATA_TOO_SHORT', 'MOD040');
				}
				this.state = Buffer.slice(input);
				return Buffer.alloc(0);
			}
			if (input.length < this.blockSize) {
				// input length is less than block size
				// it means the input has parts of mac block and cipher.state has also.
				
				var temp = Buffer.alloc(this.blockSize);
				temp.set(input, 0);
				
				var output = this.gctr(temp, input.length);
				this.state = Buffer.concat([this.state.slice(input.length), input]);
				return output;
			}
			// normall
			var output = this.gctr(this.state, input.length);
			this.state = Buffer.slice(input);
			return output;
		}
	}

	finish()
	{
		// Final ghash
		var data_length = this.isEncryption ? this.dataLength : this.dataLength - this.tagSize;

		var X = BigInt(this.additionalData.length * 8).shiftLeft(64).add(BigInt(data_length * 8));
		//this.S = this.gmultiply(this.S.xor(X), this.H);
		this.ghashBlock(X);

		// T - The authentication tag
		// T = MSBt(GCTRk(J0, S))
		var tBytes = this.algorithm.encryptBlock(this.J0);
		var T = this.S.xor(BigInt(tBytes));
		var tag = this.BigIntToBuffer(T, this.blockSize);

		if (this.isEncryption) {
			this.reset();
			return tag;
		} else {
			if (!tag.equals(this.state)) {
				throw jCastle.exception("MAC_CHECK_FAIL", 'MOD041');
			}
			this.reset();
			return 0;
		}
	}

	reset()
	{
		this.S = null
		this.counter = null;
		this.J0 = null;
		this.additional = null;
		this.state = null;
		this.data = null;
	}

	ghash(b, nonce)
	{
		var Y = 0n;
		for (var pos = 0; pos < b.length; pos += 16) {
			var x = Buffer.alloc(16);
            var num = Math.min(b.length - pos, 16);
			x.set(b.slice(pos, pos * num), 0);
            var X = BigInt(x);
            Y = this.gmultiply(Y.xor(X), this.H);
        }

        return Y;
	}

	gmultiply(X, Y)
	{
		var Z = 0n;
		var V = X;

		for (var i = 0; i < 128; ++i) {
			if (Y.testBit(127 - i)) {
				Z = Z.xor(V);
			}
			var lsb = V.testBit(0);
			V = V.shiftRight(1);
			if (lsb) {
				V = V.xor(this.R);
			}
		}

		return Z;
	}

	BigIntToBuffer(bi, size)
	{
		var b = bi.toBuffer();
        if (b.length < 16) {
			while (b.length < 16) {
				b = Buffer.concat([Buffer.alloc(0), b]);
			}
        }
		while (b.length > size) {
			//b.shift();
			b = b.slice(1);
		}

        //return Buffer.from(b);
		return b;
    }

	gctr(block, size)
	{
		var output = Buffer.alloc(size);
		this.increaseCounter();
		var tmp = this.algorithm.encryptBlock(this.counter);

		if (this.isEncryption) {
			for (var i = size; i < this.blockSize; i++) tmp[i] = 0x00;
			for (var l = size-1; l >= 0; l--) {
				tmp[l] ^= block[l];
				output[l] = tmp[l];
			}
			this.ghashBlock(tmp);
		} else {
			for (var l = size-1; l >= 0; l--) {
				tmp[l] ^= block[l];
				output[l] = tmp[l];
			}
			this.ghashBlock(block);
		}
		return output;
	}

	increaseCounter()
	{
		for (var p = 15; p >= 12; p--) {
			var b = (this.counter[p] + 1) & 0xff;
			this.counter[p] = b & 0xff;
			if (b != 0) break;
		}
	}

	ghashBlock(block)
	{
		var X = BigInt.is(block) ? block : BigInt(block);
		this.S = this.gmultiply(this.S.xor(X), this.H);
	}
};
*/

// https://tools.ietf.org/pdf/draft-irtf-cfrg-cwc-00.pdf
jCastle.mcrypt.mode['cwc'] = class
{
    constructor()
    {
        this.algorithm = null;
        this.state = null;
        this.isEncryption = true;
        this.blockSize = 0;
    }

	init(algorithm, options)
	{
		this.algorithm = algorithm;
		this.state = Buffer.alloc(0);
		this.isEncryption = options.isEncryption;
		this.blockSize = options.blockSize;

		this.nonce = Buffer.from(options.nonce, 'latin1');

		this.counter = 1;

		if (this.blockSize != 16) {
			throw jCastle.exception("MODE_INVALID_BLOCKSIZE", 'MOD042');
		}

		/*
		N, a nonce, 11 octets in length. Each value of N MUST NOT be used
        more than once for any given key K.  The layout of the nonce is
		unspecified, but we recommend using part of the nonce for a
		salt of at least 4 octets that is randomly chosen at key setup
		time and using the rest for a message counter.
		*/ 
		if (this.nonce.length < 4) {
			throw jCastle.exception("INVALID_NONCE", 'MOD043');
		}

		while (this.nonce.length < 11) {
			this.nonce = Buffer.concat([this.nonce, Buffer.alloc(11 - this.nonce.length)]);
		}

		if (this.nonce.length > 11) {
			this.nonce = Buffer.slice(this.nonce, 0, 11);
		}

		// { 4, 6, 8, 10, 12, 14, 16 }
		this.tagSize = 16;
		if ('tagSize' in options && options.tagSize > 0) {
			if (options.tagSize % 2 || options.tagSize < 4 || options.tagSize > 16) {
				throw jCastle.exception("MODE_INVALID_TAGSIZE", 'MOD044');
			}
			this.tagSize = options.tagSize;
		}
/*
   This use of counter mode uses a layout for plaintexts that is
   compatible with the draft specification of Integer Counter Mode
   presented in [ICM].
   The first two bits of the block being encrypted are used to
   distinguish the different types of AES encryption. In the context of
   the counter mode encryption, the first bit will always be 1, and the
   second will always be 0. The next 6 bits are reserved, and must
   always be zero. The next 11 octets consist of the nonce, and the 
   final 4 octets encode a counter in big endian format that indicates
   which block of keystream is being produced by the current AES
   operation.

   Here’s a visual representation of the octets in the counter plaintext
   blocks:
            0       1      2        3       4       5       6       7
		+-------+-------+-------+-------+-------+-------+-------+-------+
		| 0x80  |                        Nonce    
		+-------+-------+-------+-------+-------+-------+-------+-------+
		        Nonce (continued)       |            Counter            |    
		+-------+-------+-------+-------+-------+-------+-------+-------+
		    8       9      10      11      12      13      14      15
 
*/
		this.T = Buffer.alloc(16);
		this.T[0] = 0x80;
		this.T.set(this.nonce, 1);
		this.T.writeInt32BE(this.counter, 12);

		this.algorithm.keySchedule(options.key, true);
		//this.algorithm.keySchedule(this.algorithm.masterKey, true);

		// additional authenticated data
		this.additionalData = Buffer.alloc(0);
		if ('additionalData' in options) {
			this.additionalData = Buffer.from(options.additionalData);
		}

		this.data = Buffer.alloc(0);
	}

/*
2.2. The CWC-ENCRYPT operation

   CWC-ENCRYPT takes the following inputs:

     K, a key that is Y octets in length.

     A, a string of arbitrary length consisting of data to be
        authenticated, but not encrypted.  The length of A MUST NOT
        exceed 2^36-16 octets.

     M, a string of arbitrary length consisting of the plaintext
        message.  This message will be both encrypted and
        authenticated.  The length of M MUST NOT exceed 2^36-16 octets.

     N, a nonce, 11 octets in length. Each value of N MUST NOT be used
        more than once for any given key K.  The layout of the nonce is
        unspecified, but we recommend using part of the nonce for a
        salt of at least 4 octets that is randomly chosen at key setup
        time and using the rest for a message counter.

   Note that the length restrictions on A and M are an implementation-
   level decision specific to CWC-AES.  Please see [CWC] for a
   discussion of the considerations.

   CWC-ENCRYPT is computed as follows:

     1) C      = CWC-CTR(K, N, M)
     2) T      = CWC-MAC(K, A, N, C)
     3) OUTPUT = C || T

2.3. The CWC-DECRYPT operation

   CWC-DECRYPT takes the following inputs:

     K, a key that is Y octets in length.

     A, a string of arbitrary length up to 2^36-16 octets, consisting of
        data to be authenticated.

     C, a string of arbitrary length up to 2^36-16+Z octets, consisting
   of
        ciphertext to be decrypted and authenticated.

     N, a nonce of 11 octets in length, corresponding to the nonce for
        encryption.

     Note that if either A or C is longer than specified above,
     authentication will fail, as no messages may be that long.
     Implementations MAY explicitly check for overlong inputs and
     reject them up front.

   CWC-DECRYPT is computed as follows:

     1) IF LEN(C) < Z THEN FAIL
     2) C'     = C[0 : LEN(C)-Z]
     3) T'     = C[LEN(C)-Z : LEN(C)]
     4) T      = CWC-MAC(K, A, N, C')
     6) IF T <> T' THEN FAIL
     7) OUTPUT = CWC-CTR(K, N, C')

2.4. The CWC-CTR operation

   This use of counter mode uses a layout for plaintexts that is
   compatible with the draft specification of Integer Counter Mode
   presented in [ICM].

   The first two bits of the block being encrypted are used to
   distinguish the different types of AES encryption.  In the context of
   the counter mode encryption, the first bit will always be 1, and the
   second will always be 0.  The next 6 bits are reserved, and must
   always be zero.  The next 11 octets consist of the nonce, and the
   final 4 octets encode a counter in big endian format that indicates
   which block of keystream is being produced by the current AES
   operation.

   Here's a visual representation of the octets in the counter plaintext
   blocks:

        0       1      2        3       4       5       6       7
    +-------+-------+-------+-------+-------+-------+-------+-------+
    | 0x80  |                        Nonce
    +-------+-------+-------+-------+-------+-------+-------+-------+
            Nonce (continued)       |            Counter            |
    +-------+-------+-------+-------+-------+-------+-------+-------+
        8       9      10      11      12      13      14      15

   CWC-CTR(K, N, M):

     1) J = CEILING(LEN(M)/16)
     2) S = ""
     3) FOR I in 1 TO J:   S = S || AES_K(0x80 || N || I)
     4) OUTPUT = S[0:LEN(M)] XOR M

   Note that, in step 3, the number I is represented as a string in big
   endian format, and MUST be exactly 4 octets in length.
*/
	process(input)
	{
		// there is nothing to do exept saving the input.
		// when decryption, the mac data should be calculated first using ctrMode,
		// we cannot process anything here.

		var output = Buffer.alloc(0);

		if (this.isEncryption) {
			var T = this.algorithm.encryptBlock(this.T);

			if (input.length != this.blockSize) {
				T = Buffer.slice(T, 0, input.length);
			}
			output = Buffer.xor(T, input);
			this.data = Buffer.concat([this.data, output]);

			this.T.writeInt32BE(++this.counter, 12);
		} else {
			if (!this.state.length) {
				this.state = Buffer.slice(input);
			} else {
				var T = this.algorithm.encryptBlock(this.T);

				if (input.length == this.blockSize) {
					this.data = Buffer.concat([this.data, this.state]);
					output = Buffer.xor(this.state, T);
					this.state = Buffer.slice(input);
				} else {
					// input length is less than block size
					// it means the input has parts of mac block and cipher.state has also.
					var l = input.length;
					var temp = Buffer.slice(this.state, 0, l);
					this.data = Buffer.concat([this.data, temp]);
					output = Buffer.xor(temp, T);
					this.state = Buffer.concat([this.state.slice(l), input]); // mac
				}

				this.T.writeInt32BE(++this.counter, 12);
			}
		}

		return output;
	}

	finish()
	{
		var output = Buffer.alloc(0);

		if (this.isEncryption) {
			var mac = this.calculateMac();

			output = mac;
		} else {
			var mac = this.state;

			if (mac.length != this.tagSize) {
				throw jCastle.exception("MODE_INVALID_TAGSIZE", 'MOD045');
			}

			var v_mac = this.calculateMac();

			if (!v_mac.equals(mac)) {
				throw jCastle.exception("MAC_CHECK_FAIL", 'MOD046');
			}
		}

		this.reset();

		return output;
	}

	reset()
	{
		this.state = null;
		this.isEncryption = null;
		this.blockSize = null;
		this.nonce = null;
		this.tagSize = null;

		if (typeof this.algorithm.reset === 'function') {
			this.algorithm.reset();
		}
	}

/*
2.5. The CWC-MAC operation

   The CWC-MAC operation takes the results of CWC-HASH and then performs
   two post-processing AES operations.  The first operation directly
   encrypts the hash result.  Note that, in a correct implementation,
   the first bit of that plaintext will always be zero.  The second AES
   operation is identical to the operation in 2.4., with the counter
   value set to 0.

   CWC-MAC(K, A, N, C):

     1) R = AES_K(CWC-HASH(K, A, C))
     2) OUTPUT = (AES_K(0x80||N||0x00000000) XOR R)[0:Z]

2.6. The CWC-HASH operation

   This hash function is the traditional Carter-Wegman polynomial hash,
   with a field of GF(2^127-1).  In practice, this means that, for each
   12 octets of the message (where those octets are treated like a
   number in big endian notation), we add the message block to the
   ongoing result, modulo 2^127-1.  We then multiply by the hash key
   (itself treated as a number), again modulo 2^127-1.

   The result is the ongoing result, represented as a 16-octet big
   endian value.  The most significant bit will always be 0.

   CWC-HASH(K, A, C):

     1) Z = AES_K(0xC0000000000000000000000000000000) &
                  0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
     2) X  = CWC-HPAD(A) || CWC-HPAD(C)
     3) B = LEN(X) / 12
     4) OUTPUT = 0
     5) FOR I FROM 0 TO B-1:
        a) OUTPUT = OUTPUT + X[12*I : 12*I+12] MOD 2^127-1
        b) OUTPUT = OUTPUT * Z MOD 2^127-1
     6) OUTPUT = OUTPUT + (LEN(C) + 2^64*LEN(A)) MOD 2^127-1

   Note that most implementations will want to compute Z at key setup
   time, instead of recomputing it for each message.

2.7. The CWC-HPAD operation

   The input to the hash function needs to be a multiple of 96 bits.

   CWC-HPAD(STR):

     1) OUTPUT = STR
     2) WHILE LEN(OUTPUT) MOD 12: OUTPUT = OUTPUT + 0x00
*/
	calculateMac()
	{
//		var algo_name = this.algorithm.algoName;
//		var key = this.algorithm.masterKey;
//		var algorithm = new jCastle.algorithm[jCastle._algorithmInfo[algo_name].object_name](algo_name);
//		algorithm.keySchedule(key, true);

		var hashkey = this.algorithm.encryptBlock(Buffer.from('C0000000000000000000000000000000', 'hex'));
		//hashkey = Buffer.xor(hashkey, Buffer.from('7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF', 'hex'));
		hashkey[0] = hashkey[0] & 0x7F;

		var hash = this.cwcHash(hashkey, this.additionalData, this.data);
		var R = this.algorithm.encryptBlock(hash);

		var T = Buffer.alloc(16);
		T[0] = 0x80;
		T.set(this.nonce, 1);

		var temp = this.algorithm.encryptBlock(T);
		var mac = Buffer.xor(temp, R);

		return Buffer.slice(mac, 0, this.tagSize);
	}

/*
	cwcHash(hashkey, additionalData, ciphertext)
	{
		var z = BigInt.fromBuffer(hashkey); // 34ae6a6fe9517894acccbb9ebae7208c
		//var m = 2n ** 127n - 1n; // 2^127 - 1
		var m = BigInt('170141183460469231731687303715884105727');
		//var n = 2n ** 64n; // 2^64
		var n = BigInt('18446744073709551616');

		var x = Buffer.slice(additionalData);
		if (x.length % 12) {
			x = Buffer.concat([x, Buffer.alloc(12 - x.length % 12)]);
		}
		x = Buffer.concat([x, ciphertext]);
		if (x.length % 12) {
			x = Buffer.concat([x, Buffer.alloc(12 - x.length % 12)]);
		}
		
		var output = 0n;
		var t, p = 0;

		while (p < x.length) {
			t = BigInt.fromBufferUnsigned(x.slice(p, p + 12));
			output = output.add(t).mod(m);
			output = output.multiply(z).mod(m);
			p += 12;
		}

		t = BigInt(ciphertext.length);
		t = t.add(n.multiply(BigInt(additionalData.length)));

		output = output.add(t).mod(m);

		return output.toBuffer();
	}
*/
	cwcHash(hashkey, additionalData, ciphertext)
	{
		var res = Buffer.alloc(16);
		var x = Buffer.slice(additionalData);
		
		if (x.length % 12) {
			x = Buffer.concat([x, Buffer.alloc(12 - x.length % 12)]);
		}

		x = Buffer.concat([x, ciphertext]);
		if (x.length % 12) {
			x = Buffer.concat([x, Buffer.alloc(12 - x.length % 12)]);
		}

		var t, p = 0;
		while (p < x.length) {
			t = Buffer.alloc(16);
			var s = x.slice(p, p + 12);
			t.set(s, 16 - s.length);
			
			res = this.cwcModAdd(t, res);
			res = this.cwcModMultiply(hashkey, res);
			p += 12;
		}

		t = Buffer.alloc(16);
		t.writeInt32BE(additionalData.length, 4);
		t.writeInt32BE(ciphertext.length, 12);

		return this.cwcModAdd(t, res);
	}

	cwcModAdd(a, b)
	{
		var carry = new Array(16).fill(0), res = Array.prototype.slice.call(b, 0);

		for (var i = 0; i < 16; i++) {
			res[i] += a[i];
			var t = res[i] >>> 8;
			if (t) {
				carry[i - 1] = t;
				res[i] &= 0xff;
			}
			if (res[0] & 0x80) {
				carry[15] = 1;
				res[0] &= 0x7f;
			}
		}

		var i = 16;
		while (i--) {
			if (carry[i]) {
				res[i] += carry[i];
				t = res[i] >>> 8;
				if (t) {
					carry[i - 1] += t;
					res[i] &= 0xff;
				}
			}
		}

		return Buffer.from(res);
	}

	cwcModMultiply(a, b)
	{
		var c = new Array(32).fill(0);
		var upper, lower, carry = new Array(32).fill(0);
		var tmp, t;

		for (var i = 0; i < 16; i++) {
			for (var j = 0; j < 16; j++) {
				tmp = a[i] * b[j];
				upper = tmp >>> 8;
				lower = tmp & 0xff;
				c[i + j] += upper;
				t = c[i + j] >>> 8;
				if (t) {
					carry[i + j - 1] += t;
					c[i + j] &= 0xff;
				}
				c[i + j + 1] += lower;
				t = c[i + j + 1] >>> 8;
				if (t) {
					carry[i + j] += t;
					c[i + j + 1] &= 0xff;
				}
			}
		}
		var i = 32;
		while (i--) {
			c[i] += carry[i];
			t = c[i] >>> 8;
			if (t) {
				carry[i - 1] += t;
				c[i] &= 0xff;
			}
		}

		for (var i = 0; i < 16; i++) {
			c[i] <<= 1;
			c[i] &= 0xff;
			c[i] |= c[i + 1] >>> 7;
		}
		c[16] &= 0x7f;
		
		var res = Buffer.from(c);
		
		return this.cwcModAdd(res.slice(0, 16), res.slice(16));
	}
};

// https://datatracker.ietf.org/doc/html/rfc7539
jCastle.mcrypt.mode['poly1305'] = class
{
    constructor()
    {
        this.algorithm = null;
        this.state = null;
        this.isEncryption = true;
        this.blockSize = 0;
    }

	init(algorithm, options)
	{
		this.algorithm = algorithm;
		this.isEncryption = options.isEncryption;
		this.blockSize = options.blockSize;
		
		this.cdata = Buffer.alloc(0);
		
		if (algorithm.algoName != 'chacha20') {
			throw jCastle.exception("POLY1305_NOT_CHACHA20", 'MOD048');
		}

//		if (typeof jCastle.mac == 'undefined') {
//			throw jCastle.exception("MAC_REQUIRED", 'MOD049');
//		}

		// additional authenticated data
		this.additionalData = Buffer.alloc(0);
		if ('additionalData' in options) {
			this.additionalData = Buffer.from(options.additionalData);
		}

		this.polyKey = this.algorithm.encryptBlock(Buffer.alloc(64)); // important!
		this.polyKey = Buffer.slice(this.polyKey, 0, 32);

		this.state = Buffer.alloc(0);
	}

	process(input)
	{
		var output;

		if (this.isEncryption) {
			output = this.algorithm.encryptBlock(Buffer.alloc(input.length));
			output = Buffer.xor(input, output);
			this.cdata = Buffer.concat([this.cdata, output]);
		} else {
			if (!this.state.length) {
				this.state = Buffer.slice(input);

				return Buffer.alloc(0);
			}

			//if (input.length != jCastle._algorithmInfo[this.algorithm.algoName].stream_block_size) {
			if (input.length != this.blockSize) {
				// last time and the size is short
				this.state = Buffer.concat([this.state, input]);
				return Buffer.alloc(0);
			}

			output = this.algorithm.decryptBlock(Buffer.alloc(this.state.length));
			output = Buffer.xor(this.state, output);
			this.cdata = Buffer.concat([this.cdata, this.state]);
			this.state = Buffer.slice(input);
		}

		return output;
	}

	finish()
	{
		var mac, output;

		if (this.isEncryption) {
			mac = this.calculateMac(this.polyKey, this.additionalData, this.cdata);

			this.reset();
			return mac;
		} else {
			if (!this.state.length) {
				throw jCastle.exception("MAC_NOT_FOUND", 'MOD050');
			}

			mac = Buffer.slice(this.state, this.state.length - 16);
			var data = this.state.slice(0, this.state.length - 16);

			if (mac.length != 16) {
				throw jCastle.exception("MAC_NOT_FOUND", 'MOD051');
			}

			var len = data.length;
			output = Buffer.alloc(0);
			
			for (var i = 0; i < len; i += 64) {
				var input = data.slice(i, i + 64 < len ? i + 64 : len);
				var out =  this.algorithm.decryptBlock(Buffer.alloc(input.length));
				out = Buffer.xor(input, out);
				output = Buffer.concat([output, out]);
				this.cdata = Buffer.concat([this.cdata, input]);
			}

			var v_mac = this.calculateMac(this.polyKey, this.additionalData, this.cdata);

			if (!v_mac.equals(mac)) {
				throw jCastle.exception("MAC_CHECK_FAIL", 'MOD052');
			}

			return output;
		}
	}

	reset()
	{
		this.state = null;
		this.cdata = null;
		this.polyKey = null;

		if (typeof this.algorithm.reset === 'function') {
			this.algorithm.reset();
		}

		this.algorithm = null;
	}

	calculateMac(key, adata, cdata)
	{
		var apad = 16 - (adata.length % 16);
		var cpad = 16 - (cdata.length % 16);
		
		var bl = Buffer.alloc(16);
		bl.writeInt32LE(adata.length, 0);
		bl.writeInt32LE(cdata.length, 8);
		
		var len = adata.length + apad + cdata.length + cpad;
		
		var total = Buffer.alloc(len + 16);
		total.set(adata, 0);
		total.set(cdata, adata.length + apad);
		total.set(bl, len);
		

		var polyMac = new jCastle.mac('poly1305-Mac');
		polyMac.start({ key: key });
		polyMac.update(total);

		return polyMac.finalize();
	}		
};

jCastle.mcrypt.mode['poly1305-aead'] = jCastle.mcrypt.mode['poly1305'];

jCastle.mcrypt.mode['wrap'] = class
{
    constructor()
    {
        this.algorithm = null;
        this.state = null;
        this.isEncryption = true;
        this.blockSize = 0;
		this.wrapper = null;
    }

	init(algorithm, options)
	{
		this.algorithm = algorithm;

		var algo_name = this.algorithm.algoName;

		this.wrapper = new jCastle.keyWrap(algo_name);
		var params = {
			wrappingKey: this.algorithm.masterKey,
			isEncryption: options.isEncryption
		};
		this.wrapper.start(params);
	}

	process(input)
	{
		this.wrapper.update(input);
	}

	finish()
	{
		var output = this.wrapper.finalize();

		return output;
	}

	reset()
	{
		if (typeof this.algorithm.reset === 'function') {
			this.algorithm.reset();
		}

		this.algorithm = null;
		this.state = null;
		this.wrapper = null;
	}
};

module.exports = jCastle.mcrypt.mode;
