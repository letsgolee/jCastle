/**
 * Mcrypt: Javascript Message Crypt Engine 
 * 
 * @author Jacob Lee
 *
 * Copyright (C) 2015-2022 Jacob Lee.
 */

const jCastle = require('./jCastle');
const INT64 = require('./int64');
require('./util');

jCastle.mcrypt = class
{
	/**
	 * An implementation of Message Crypt
	 * 
	 * @param {string} algo_name message crypt algorithm name
	 * @constructor
	 */
    constructor (algo_name)
    {
        this.algoName = '';
		this.algorithm = null;

        this._default = {
            key: null,
            mode: 'cbc',
        //	initialVector: null,
        //	iv: null,
        //	nonce: null,
            padding: 'zeros',
            blockSize: 0,
        //	additionalData: null,
            tagSize: 0,
        //	sbox: null,
        //	rounds: 0,
        //	counter: 0,
        //	tweak: null,
            ctsType: '',
        //	dataUnit: 0,
        //	tweakKey: null,
        //	effectiveKeyBits: null, // rc2

    // bug patched - 2017.05.16
    // must commented
    //		direction: true,

            isEncryption: true
        };

        this._algoFunc = {
            'sbox': 'setSbox',
            'round': 'setRound',
            'tweak': 'setTweak',
            'counter': 'setCounter'
        };

        this._options = {};
        this._input = null;
        this._pos = 0;
        this._blockSize = 0;
        this._output = null;
        this._cipherMode = null;
        this._initialized = false;

        if (jCastle.util.isString(algo_name)) {
            this.algoName = jCastle.mcrypt.getValidAlgoName(algo_name);
        } else if (typeof algo_name == 'object') {
            var obj = algo_name;
            for (var i in obj) {
                if (obj.hasOwnProperty(i)) {
                    this[i] = obj[i];
                }
            }
        }
    }

	/**
	 * encrypts a message.
	 * 
	 * @public
	 * @param {buffer} message message to be encrypted
	 * @param {object} options options object
	 * @returns encrypted message.
	 */
	encrypt(message, options = {})
	{
		if ('direction' in options) {
			delete options.direction;
		}
		options.isEncryption = true;
		
		return this.start(options).update(message).finalize();
	}

	/**
	 * decrypts a ciphertext.
	 * 
	 * @public
	 * @param {buffer} message message to be decrypted
	 * @param {object} options options object
	 * @returns decrypted message.
	 */
	decrypt(message, options = {})
	{
		if ('direction' in options) {
			delete options.direction;
		}
		options.isEncryption = false;

		return this.start(options).update(message).finalize();
	}

	/**
	 * resets internal variables.
	 * 
	 * @public
	 * @returns this class instance.
	 */
	reset()
	{
		this._input = null;
		this._pos = 0;
		this._blockSize = 0;
		this._output = null;
		this._options = {};
		this._cipherMode = null;
		this._initialized = false;
	}

	/**
	 * starts crypto process.
	 * 
	 * @public
	 * @param {object} options options object for crypto process.
	 *                 {string} algoName crypto algorithm name.
	 *                 {buffer} key key used to crypt process.
	 *                 {boolean} isEncryption flag for direction of crypto.
	 *                 {string} mode mode name for crypto.
	 *                 {string} padding padding name if padding is needed.
	 *                 {number} blockSize if any blockSize is needed.
	 *                 {buffer} nonce nonce for crypt process.
	 *                 {buffer} additionalData additional data for AEAD.
	 *                 {buffer} tweakKey tweakKey for xts mode.
	 *                 {number} dataUnit data block size for XTS mode.
	 *                 {string} sbox sbox type  for "gost" algorithm.
	 *                 {string} ctsType cts type for CTS mode.
	 * @returns this class instance for function chaining.
	 */
	start(options = {})
	{
		this._options = {};
		this._options = Object.assign(this._options, options);

		for (var i in this._default) {
			if (!(i in this._options)) {
				this._options[i] = this._default[i];
			}
		}


/*
to do:
allow set algorithm object as a parameter

*/
		// algo_name
		if ('algoName' in this._options) {
			this._setAlgorithm(this._options.algoName);
		} else {
			if (this.algoName.length == 0) {
				throw jCastle.exception('ALGORITHM_NOT_SET', 'MCR001');
			}
		}

		// iv
		// gcm, ccm, eax requires nonce. It is almost the same with iv.
		if (options.initialVector) this._options.iv = options.initialVector;
		if (this._options.iv && !Buffer.isBuffer(this._options.iv))
			this._options.iv = Buffer.from(this._options.iv, 'latin1');

		if (!('key' in this._options)) {
			throw jCastle.exception("KEY_NOT_SET", 'MCR002');
		}
		if (!(Array.isArray(this._options.key) && key[0] instanceof INT64)) {
			if (!Buffer.isBuffer(this._options.key))
				this._options.key = Buffer.from(this._options.key, 'latin1');
		}

		// direction
		if ('direction' in this._options) {
			if (this._options.direction === true || 
				(jCastle.util.isString(this._options.direction) && /^enc(rypt(ion)?)?$/ig.test(this._options.direction))) {
				this._options.isEncryption = true;
			} else if (this._options.direction === false || 
				(jCastle.util.isString(this._options.direction) && /^dec(rypt(ion)?)?$/ig.test(this._options.direction))) {
				this._options.isEncryption = false;
			} else {
				throw jCastle.exception('INVALID_DIRECTION', 'MCR003');
			}
		}

//console.log(this._options.isEncryption);

		// mode
		var mode;
		if ('mode' in this._options) {
			mode = this._options.mode.toLowerCase();
			if (!(mode in jCastle.mcrypt.mode)) {
				throw jCastle.exception('UNSUPPORTED_MODE', 'MCR004');
			}
			this._options.mode = mode;
		}

		var nonce_mode = ['eax', 'ccm', 'gcm', 'cwc'];

		if (nonce_mode.includes(mode) && !('nonce' in this._options) && 'iv' in this._options) {
			this._options.nonce = this._options.iv;
		}

		// padding
		if ('padding' in this._options) {
			var padding = this._options.padding.toLowerCase();
			if (!(padding in jCastle.mcrypt.padding) && padding.length) {
				throw jCastle.exception('INVALID_PADDING_METHOD', 'MCR005');
			}

			this._options.padding = padding;
		}

		// if not set then use the algorithm's default padding.
		if (!this._options.padding || this._options.padding.length == 0) {
			this._options.padding = jCastle._algorithmInfo[this.algoName].padding;
		}

		if ('blockSize' in this._options) {
			if ('block_sizes' in jCastle._algorithmInfo[this.algoName] &&
			jCastle._algorithmInfo[this.algoName].block_sizes.includes(this._options.blockSize)) {
				this._blockSize = this._options.blockSize;
			}
		}

		// xts
		if (this._options.mode == 'xts' && !('tweakKey' in this._options)) {
			var keylen = this._options.key.length;
			this._options.tweakKey = Buffer.slice(this._options.key, keylen / 2);
			this._options.key = Buffer.slice(this._options.key, 0, keylen / 2);
		}
		
		this._input = Buffer.alloc(0);
		this._output = Buffer.alloc(0);

		this._initialize();

		return this;
	}

	// this one does not work properly. for start() performs _initialize().
	// to work properly _initialize() should be modified.
	//
	// // aadUpdate should come between start() and update().
	// aadUpdate(aad)
	// {
	// 	var input;

	// 	if (aad && aad.length) {
	// 		input = Buffer.from(aad);

	// 		if (!('additionalData' in this._options)) this._options.additionalData = input;
	// 		else this._options.additionalData = Buffer.concat([this._options.additionalData, input]);
	// 	}

	// 	return this;
	// }
	/**
	 * updates the process with the message
	 * 
	 * @public
	 * @param {buffer} message message to be updated.
	 * @returns this class instance.
	 */
	update(message)
	{
		var input;

		if (message && message.length) {
			input = Buffer.from(message);
			this._input = Buffer.concat([this._input, input]);
		}

		while (this._pos + this._blockSize <= this._input.length) {
			var output = this._cipherMode.process(this._input.slice(this._pos, this._pos + this._blockSize));
			if (output && output.length) this._output = Buffer.concat([this._output, output]);
			this._pos += this._blockSize;
		}

		return this;
	}

	/**
	 * finalize the process and returns the result.
	 * 
	 * @public
	 * @param {buffer} message 
	 * @returns the crypted message in buffer
	 */
	finalize(message)
	{
		var output;

		if (message && message.length) {
			this.update(message);
		}

		if (this._options.isEncryption) this._pad();

		while (this._pos < this._input.length) {
			output = this._cipherMode.process(this._input.slice(this._pos, this._pos + this._blockSize));
			if (output && output.length) this._output = Buffer.concat([this._output, output]);
			this._pos += this._blockSize;
		}

		output = this._cipherMode.finish();
		if (output && output.length) this._output = Buffer.concat([this._output, output]);

		if (!this._options.isEncryption) this._unpad();

		output = Buffer.from(this._output);

		if ('encoding' in this._options) {
			output = output.toString(this._options.encoding);
		}

		this.reset();

		return output;
	}

	/**
	 * Gets the block size of the algorithm
	 * 
	 * @public
	 * @param {string} mode mode name
	 * @returns algorithm's blockSize
	 */
	getBlockSize(mode)
	{
		if (this.algoName.length) {
			return jCastle._algorithmInfo[this.algoName].block_size;
		}
		return null;
	}

	/**
	 * Gets the name of the algorithm after checking this application supports
	 * 
	 * @public
	 * @returns algorithm name.
	 */
	getAlgorithmName()
	{
		if (this.algoName.length) {
			return this.algoName;
		}
		return null;
	}

	/**
	 * Returns the size of the IV belonging to a algorithm/mode combination
	 * 
	 * @public
	 * @param {string} mode mode name.
	 * @returns the size of the IV.
	 */
	getInitialVectorSize(mode)
	{
		if (!this.algoName) throw jCastle.exception('ALGORITHM_NOT_SET', 'MCR006');

		return jCastle.mcrypt.getInitialVectorSize(this.algoName, mode);
	}

	/**
	 * alias for getInitialVectorSize()
	 * 
	 * @public
	 * @param {string} mode mode name
	 * @returns the size of the IV.
	 */
	getIVSize(mode)
	{
		if (!this.algoName) throw jCastle.exception('ALGORITHM_NOT_SET', 'MCR007');

		return jCastle.mcrypt.getInitialVectorSize(this.algoName, mode);
	}

	/**
	 * Creates an IV with the given size
	 * 
	 * @public
	 * @param {number} size size of the IV.
	 * @returns IV with the given size.
	 */
	createInitialVector(size)
	{
		return jCastle.mcrypt.createInitialVector(size);
	}

	/**
	 * alias for createInitialVector()
	 * 
	 * @public
	 * @param {number} size size of the IV.
	 * @returns IV with the given size.
	 */
	createIV(size)
	{
		return jCastle.mcrypt.createInitialVector(size);
	}

	/**
	 * Gets the key size of the algorithm
	 * 
	 * @public
	 * @returns the key size of the algorithm.
	 */
	getKeySize()
	{
		if (this.algoName.length) {
			return jCastle._algorithmInfo[this.algoName].key_size;
		}
		return false;
	}

	/**
	 * Creates a random key.
	 * 
	 * @public
	 * @param {number} size size of a key
	 * @returns a new key with a given size.
	 */
	createKey(size)
	{
		return jCastle.mcrypt.createKey(size);
	}



	/**
	 * creates a algorithm object.
	 * 
	 * @private
	 * @param {string} algo_name 
	 * @param {object} options options for creating algorithm object.
	 * @returns the created algorithm object.
	 */
	getAlgorithm(algo_name, options)
	{
		if (typeof algo_name == 'object' && !jCastle.util.isString(algo_name) && 'algoName' in algo_name &&
			algo_name instanceof jCastle[jCastle._algorithmInfo[algo_name.algoName].object_name]) {
			// this.algoName = algo_name.algoName;
			return algo_name;
		}

		algo_name = jCastle.mcrypt.getValidAlgoName(algo_name);

		return new jCastle.algorithm[jCastle._algorithmInfo[algo_name].object_name](algo_name, options);
	}

	_setAlgorithm(algo_name)
	{
		this.algoName = jCastle.mcrypt.getValidAlgoName(algo_name);
		return this;
	}

	_initialize()
	{
		var algorithm = this.getAlgorithm(this.algoName, this._options);

		// check the key size.
		// some algorithms fill paddings to the key for a proper size,
		// but this is not good. Also PHP now gives error after 5.6.0.
		if (typeof algorithm.isValidKeySize == 'function' && !algorithm.isValidKeySize(this._options.key)) {
			throw jCastle.exception('INVALID_KEYSIZE', 'MCR008');
		}
		
		if (!this._blockSize) {
			this._blockSize = jCastle._algorithmInfo[this.algoName].block_size;
		}
		
		// steam cipher has no block size
		// therefore the text will be encrypt/decrypt without any mode & padding.
		if (this._blockSize == 1) {

			// chacha20 has 64 bytes stream block.
			if ('stream_block_size' in jCastle._algorithmInfo[this.algoName]) {
				this._blockSize = jCastle._algorithmInfo[this.algoName].stream_block_size;
			}

			// when mode is stream setting of iv should be before calling keySchedule.
			if ((this._options.iv || this._options.nonce) && typeof algorithm.setInitialVector == 'function') {
				algorithm.setInitialVector(this._options.iv ? this._options.iv : this._options.nonce);
			}
		}

		// user functions
		for (var p in this._algoFunc) {
			if (p in this._options && typeof algorithm[this._algoFunc[p]] == 'function') {
				algorithm[this._algoFunc[p]](this._options[p]);
			}
		}

		if (!this._options.blockSize) this._options.blockSize = this._blockSize;

		// key scheduling
		algorithm.keySchedule(this._options.key, this._options.isEncryption);

		this._cipherMode = jCastle.mcrypt.mode.create(this._options.mode);
		this._cipherMode.init(algorithm, this._options);
		
		this._initialized = true;
	}

	_pad()
	{
		switch (this._options.mode) {
			case 'ecb':
			case 'cbc':
			case 'pcbc':
				this._input = jCastle.mcrypt.padding[this._options.padding].pad(this._input, this._blockSize);
				break;
			default:
				return;
		}
	}

	_unpad()
	{
		switch (this._options.mode) {
			case 'ecb':
			case 'cbc':
			case 'pcbc':
				try {
					this._output = jCastle.mcrypt.padding[this._options.padding].unpad(this._output, this._blockSize);
				} catch (e) {
					throw jCastle.exception("INVALID_PADDING", 'MCR009');
				}
				break;
			default:
				return;
		}
	}
};


Object.assign(jCastle.mcrypt,
{
	/**
	 * creates a new class instance.
	 * 
	 * @public
	 * @param {string} algo_name crypto algorithm name
	 * @returns the new class instance.
	 */
	create: function(algo_name)
	{
		return new jCastle.mcrypt(algo_name);
	},

	/**
	 * creates a new class instance and start a crypto process.
	 * 
	 * @public
	 * @param {object} options options object for the process.
	 * @returns the class instance.
	 */
	start: function(options)
	{
		return new jCastle.mcrypt().start(options);
	},

	/**
	 * gets list of supported algorithms
	 * 
	 * @public
	 * @returns arrays of supported algorithms.
	 */
	listAlgorithms: function()
	{
		var l = [];
		for (var i in jCastle._algorithmInfo) {
			l.push(i);
		}
		return l;
	},
		
	/**
	 * gets the valid algorithm name.
	 * 
	 * @public
	 * @param {string} algo_name algorithm name
	 * @returns the valid algorithm name
	 */
	getValidAlgoName: function(algo_name)
	{
		algo_name = algo_name.toLowerCase();

		var name_reg = /^([a-z]+)(128|192|256|384|512|1024)$/;
		var m = name_reg.exec(algo_name);
		if (m) {
			algo_name = m[1] + '-' + m[2];
		}

		// alias
		switch (algo_name) {
			case 'arcfour':
				algo_name = 'rc4';
				break;
	//		case 'rc2-128':
	//			algo_name = 'rc2';
	//			break;
		}

		if (!(algo_name in jCastle._algorithmInfo)) {
			throw jCastle.exception('UNKNOWN_ALGORITHM', 'MCR010');
		}
		return algo_name;
	},

	/**
	 * gets params object whose properties are supported by mcrypt.
	 * 
	 * @public
	 * @param {object} options options object.
	 * @returns params object.
	 */
	getAlgoParameters: function(options)
	{
		var params = {};
		var param_names = ['key', 'mode', 'iv', 'nonce', 'padding', 'blockSize', 
//			'format',
			'additionalData', 'tagSize', 'sbox', 'rounds', 'counter',
			'tweak', 'ctsType', 'dataUnit', 'tweakKey', 'direction', 'isEncryption',
			'effectiveKeyBits', 'version', 'blockSizeInBits'];

		for (var i in options) {
			if (param_names.includes(i)) {
				params[i] = options[i];
			}
		}

		return params;
	},

	/**
	 * check the parameters with the mode and if there is no IV given, create it.
	 * 
	 * @public
	 * @param {object} params parameters object
	 * @param {string} algo_name algorithm name
	 * @param {string} mode mode name
	 * @param {object} prng psudo random generator.
	 */
	checkAlgoParameters: function(params, algo_name, mode, prng)
	{
	//	params = jCastle.mcrypt.getAlgoParameters(params);

		if (!prng || !(prng instanceof jCastle.prng)) prng = new jCastle.prng();

		var algo_info = jCastle._algorithmInfo[jCastle.mcrypt.getValidAlgoName(algo_name)];
		var block_size = algo_info.block_size;

		if (!('mode' in params)) params.mode = mode;

		switch (mode) {
			case 'ecb':
			case 'stream':
			case 'wrap':
				break;
			case 'gcm':
			case 'ccm':
			case 'eax':
			case 'cwc':
			case 'poly1305-aead':
				if (!params.nonce || !params.nonce.length) {
					params.nonce = prng.nextBytes(block_size);
				}
				break;
			default:
				if (!params.iv || !params.iv.length) {
					params.iv = prng.nextBytes(block_size);
				}
		}
	},

	/**
	 * get the algorithm information object.
	 * 
	 * @public
	 * @param {string} algo_name algorithm name
	 * @returns algorithm information object
	 */
	getAlgorithmInfo: function(algo_name)
	{
		algo_name = jCastle.mcrypt.getValidAlgoName(algo_name);

		var algo_info = jCastle._algorithmInfo[algo_name];

		var info = {
			algo: algo_name,
			keySize: algo_info.key_size,
			blockSize: algo_info.block_size
		};
		if ('min_key_size' in algo_info) info.minKeySize = algo_info.min_key_size;
		if ('max_key_size' in algo_info) info.maxKeySize = algo_info.max_key_size;
		if ('key_sizes' in algo_info) info.keySizes = algo_info.key_sizes;
		if ('stream_block_size' in algo_info) info.streamBlockSize = algo_info.stream_block_size;

		return info;
	},

	/**
	 * encrypt the message.
	 * 
	 * @public
	 * @param {buffer} message message to be encrypted.
	 * @param {object} options options object
	 * @returns encrypted message.
	 */
	encrypt: function(message, options)
	{
		return new jCastle.mcrypt().encrypt(message, options);
	},

	/**
	 * decrypt the ciphertext.
	 * 
	 * @public
	 * @param {buffer} message message to be decrypted.
	 * @param {object} options options object.
	 * @returns decrypted message.
	 */
	decrypt: function(message, options)
	{
		return new jCastle.mcrypt().decrypt(message, options);
	},

	/**
	 * Gets the block size of the algorithm
	 * 
	 * @public
	 * @param {string} mode mode name
	 * @returns algorithm's blockSize
	 */
	getBlockSize: function(algo_name, mode)
	{
		algo_name = jCastle.mcrypt.getValidAlgoName(algo_name);

		if (!jCastle._algorithmInfo.hasOwnProperty(algo_name)) {
			throw jCastle.exception('UNKNOWN_ALGORITHM', 'MCR011');
		}

		return jCastle._algorithmInfo[algo_name].block_size;
	},

	/**
	 * Returns the size of the IV belonging to a algorithm/mode combination
	 * 
	 * @public
	 * @param {string} mode mode name.
	 * @returns the size of the IV.
	 */
	getInitialVectorSize: function(algo_name, mode)
	{
		mode = mode || 'cbc';
		mode = mode.toLowerCase();

		if (mode == 'ecb' || mode == 'stream') {
			return 0;
		}
		if (mode == 'gcm') return 12;

		algo_name = jCastle.mcrypt.getValidAlgoName(algo_name);

		if (!jCastle._algorithmInfo.hasOwnProperty(algo_name)) {
			throw jCastle.exception('UNKNOWN_ALGORITHM', 'MCR012');
		}
		if (typeof jCastle._algorithmInfo[algo_name].iv_size != 'undefined') {
			return jCastle._algorithmInfo[algo_name].iv_size;
		}

		// stream cipher - We don't know what to do...
		if (jCastle._algorithmInfo[algo_name].block_size == 1) {
			if ('stream_iv_size' in jCastle._algorithmInfo[algo_name]) return jCastle._algorithmInfo[algo_name].stream_iv_size;
			if ('stream_block_size' in jCastle._algorithmInfo[algo_name]) return jCastle._algorithmInfo[algo_name].stream_block_size;
			return jCastle._algorithmInfo[algo_name].key_size;
		}

		return jCastle._algorithmInfo[algo_name].block_size;
	},

	/**
	 * alias for getInitialVectorSize()
	 * 
	 * @public
	 * @param {string} mode mode name.
	 * @returns the size of the IV.
	 */
    getIVSize: function(algo_name, mode)
    {
        return jCastle.mcrypt.getInitialVectorSize(algo_name, mode);
    },


	/**
	 * Creates an IV with the given size
	 * 
	 * @public
	 * @param {number} size size of the IV.
	 * @returns IV with the given size.
	 */
	createInitialVector: function(size)
	{
		return new jCastle.prng().nextBytes(size, true, true);
	},

	/**
	 * alias for createInitialVector()
	 * 
	 * @public
	 * @param {number} size size of the IV.
	 * @returns IV with the given size.
	 */
    createIV: function(size)
    {
        return jCastle.mcrypt.createInitialVector(size);
    },


	/**
	 * Gets the key size of the algorithm
	 * 
	 * @public
	 * @returns the key size of the algorithm.
	 */
	getKeySize: function(algo_name, mode)
	{
		algo_name = jCastle.mcrypt.getValidAlgoName(algo_name);

		if (!jCastle._algorithmInfo.hasOwnProperty(algo_name)) {
			throw jCastle.exception('UNKNOWN_ALGORITHM', 'MCR013');
		}

		return jCastle._algorithmInfo[algo_name].key_size;
	},

	/**
	 * Creates a random key.
	 * 
	 * @public
	 * @param {number} size size of a key
	 * @returns a new key with a given size.
	 */
	createKey: function(size)
	{
		return new jCastle.prng().nextBytes(size);
	},

	/**
	 * creates a algorithm object.
	 * 
	 * @private
	 * @param {string} algo_name 
	 * @param {object} options options for creating algorithm object.
	 * @returns the created algorithm object.
	 */
	getAlgorithm: function(algo_name, options)
	{
		algo_name = jCastle.mcrypt.getValidAlgoName(algo_name);

		return new jCastle.algorithm[jCastle._algorithmInfo[algo_name].object_name](algo_name, options);
	}
});

jCastle.Mcrypt = jCastle.mcrypt;

module.exports = jCastle.mcrypt;