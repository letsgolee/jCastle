/**
 * Digest: A Javascript implemenation of diverse hash algorithms
 * 
 * @author Jacob Lee
 * Copyright (C) 2015-2022 Jacob Lee.
 */

var jCastle = require('./jCastle');
require('./util');
require('./lang/en');
require('./error');


jCastle.digest = class
{
	/**
	 * implementation of hash algorithms.
	 * 
	 * @param {string} hash_name hash algorithm name for digest.
	 * @constructor
	 */
    constructor(hash_name)
    {
        this.algoName = '';
        this._md = null;

        this._default = {
    //		encoding: 'hex',
    //		outputLength: 0,
    //		rounds: 0,
    //		initialValue: 0 // for crc32
        };

        this._options = {};
        this._pos = 0;
        this._input = null;
        this._state = null;
        this._initialized = false;

        if (jCastle.util.isString(hash_name)) {
            var pos = hash_name.indexOf(',');
            if (pos != -1) {
                this._options.rounds = parseInt(hash_name.substring(pos+1));
                hash_name = hash_name.substring(0, pos);
            }

            this.algoName = jCastle.digest.getValidAlgoName(hash_name);
        }
    }

	/* Public functions */

	/**
	 * resets internal variables.
	 * 
	 * @public
	 * @returns this class instance.
	 */
	reset()
	{
		this._pos = 0;
		this._input = null;
		this._initialized = false;
		this._options = {};
		this._md = null;

		return this;
	}

	/**
	 * gets the block length in bits of the set algorithm.
	 * 
	 * @public
	 * @returns the block length in bits of the hash algorithm.
	 */
	getBlockSize()
	{
		return this.algoName in jCastle._algorithmInfo ? jCastle._algorithmInfo[this.algoName].block_size : 0; // bits
	}

	/**
	 * get the bytes length of the hash algorithm
	 * 
	 * @public
	 * @returns the hash bytes length.
	 */
	getDigestLength()
	{
		return this.algoName in jCastle._algorithmInfo ? jCastle._algorithmInfo[this.algoName].digest_size : 0; // bytes
	}

	/**
	 * starts digest process.
	 * 
	 * @public
	 * @param {object} options options object for digest process.
	 *                 {number} outputSize if set, the final digest buffer will be reduced by it.
	 *                 {number} outputBits if set, the final digest buffer will be reduced by it. 
	 *                          the value should be multiple of 8.
	 *                 {string} algoName hash algorithm name.
	 *                 {string} encoding if given final digest buffer value will be stringed to the encoding.
	 * @returns this class instance for function chaining.
	 */
	start(options = {})
	{

		// for (var i in options) {
		// 		this._options[i] = options[i];
		// }

		if (jCastle.util.isString(options)) {
			options = {
				encoding: options
			};
		}

		this._options = Object.assign(this._options, options);

		for (var i in this._default) {
			if (!(i in this._options)) {
				this._options[i] = this._default[i];
			}
		}

		if ('outputSize' in this._options) {
			this._options.outputLength = this._options.outputSize;
		}
		
		if ('outputBits' in this._options) {
			if (this._options.outputBits % 8) {
				throw jCastle.exception('INVALID_OUTPUT_BITS', 'DST001');
			}
			this._options.outputLength = this._options.outputBits / 8;
		}

		if ('algoName' in this._options) {
			this._setAlgorithm(this._options.algoName);
		}

		if (this._md == null && !this.algoName.length) {
			throw jCastle.exception('NOT_INITIALIZED', 'DST002');
		}

		if (this._md == null) {
			this._md = new jCastle.algorithm[jCastle._algorithmInfo[this.algoName].object_name](this.algoName);
		}
		
		this._input = Buffer.alloc(0);

		this._md.init(this._options);
		this._initialized = true;

		return this;
	}

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

		var block_size = jCastle._algorithmInfo[this.algoName].block_size;

		while (this._pos + block_size <= this._input.length) {
			this._md.process(this._input.slice(this._pos, this._pos + block_size));
			this._pos += block_size;
		}

		return this;
	}

	/**
	 * finalize the process and returns the hash result.
	 * 
	 * @public
	 * @param {buffer} message message to be updated.
	 * @returns the digest hash in buffer
	 */
	finalize(message)
	{
		if (message && message.length) {
			this.update(message);
		}

		if (!this._initialized) {
			throw jCastle.exception('NOT_INITIALIZED', 'DST003');
		}

		this._input = this._md.pad(this._input, this._pos);

		var block_size = jCastle._algorithmInfo[this.algoName].block_size;

		while (this._pos < this._input.length) {
			this._md.process(this._input.slice(this._pos, this._pos + block_size));
			this._pos += block_size;
		}

		var output = this._md.finish();

		if ('encoding' in this._options) {
			output = output.toString(this._options.encoding);
		}

		this.reset();

		return output;
	}

	/**
	 * digest the message.
	 * 
	 * @public
	 * @param {buffer} message message to be hashed.
	 * @param {object} options options object for digest process.
	 * @returns the buffer of the digested hash bytes.
	 */
	digest(message, options)
	{
		return this.start(options).update(message).finalize();
	}

	/* Private functions */

	_setAlgorithm(hash_name)
	{
		if (jCastle.util.isString(hash_name)) {
			var pos = hash_name.indexOf(',');
			if (pos != -1) {
				this._options.rounds = parseInt(hash_name.substring(pos+1));
				hash_name = hash_name.substring(0, pos);
			}

			this.algoName = jCastle.digest.getValidAlgoName(hash_name);
		}

		return this;
	}
}

Object.assign(jCastle.digest, 
{
	/**
	 * creates a new class instance.
	 * 
	 * @public
	 * @param {string} hash_name hash algorithm name
	 * @returns the new class instance.
	 */
	create: function(hash_name)
	{
		return new jCastle.digest(hash_name);
	},

	/**
	 * creates a new class instance and start a digest process.
	 * 
	 * @public
	 * @param {object} options options object for digest process.
	 * @returns the class instance.
	 */
	start: function(options)
	{
		return new jCastle.digest().start(options);
	},
	
	/**
	 * gets all the hash algorithm names supported.
	 * 
	 * @public
	 * @returns array of hash algorithm names.
	 */
	listHashes: function()
	{
		var l = [];
		for (var i in jCastle._algorithmInfo) {
				l.push(i);
		}
		return l;
	},

	/**
	 * digest the message.
	 * 
	 * @public
	 * @param {buffer} message message to be digested.
	 * @param {object} options options object for the process.
	 * @returns the buffer of the digested hash in buffer.
	 */
	digest: function(message, options)
	{
		return new jCastle.digest().start(options).update(message).finalize();
	},

	/**
	 * gets the valid hash algorithm name.
	 * 
	 * @public
	 * @param {string} hash_name hash algorithm name
	 * @returns the valid hash algorithm name.
	 */
	getValidAlgoName: function(hash_name)
	{
		hash_name = hash_name.toLowerCase().trim();
		// alias
		switch (hash_name) {
			case "sha1":
				hash_name = "sha-1"; break;
			default: 
				var m = /^([a-z]+)(128|160|192|224|256|320|384|512|1024)((\/|\-)(128|160|192|224|256|384|512|1024))?$/g.exec(hash_name);
				if (m != null) {
					hash_name = (m[1] == 'rmd' ? 'ripemd' : m[1]) + '-' + m[2];
					if (m[3]) hash_name += m[3];
				}
				break;
		}

		if (!(hash_name in jCastle._algorithmInfo)) {
			throw jCastle.exception('UNSUPPORTED_HASHER', 'DST004');
		}

		return hash_name;
	},

	/**
	 * gets digest length in bytes
	 *  
	 * @public
	 * @param {string} hash_name hash algorithm name
	 * @returns the digest length of the algorithm.
	 */
	getDigestLength: function(hash_name)
	{
		return jCastle._algorithmInfo[jCastle.digest.getValidAlgoName(hash_name)].digest_size;
	},

	/**
	 * gets the block length in bits 
	 * 
	 * @public
	 * @param {string} hash_name hash algorithm name
	 * @returns the block length in bits.
	 */
	getBlockSize: function(hash_name)
	{
		return jCastle._algorithmInfo[jCastle.digest.getValidAlgoName(hash_name)].block_size;
	},

	/**
	 * gets the digest length in bits.
	 * 
	 * @public
	 * @param {string} hash_name hash algorithm name
	 * @returns the digest length in bits.
	 */
	getBitLength: function(hash_name)
	{
		return jCastle.digest.getDigestLength(hash_name) * 8;
	},

	/**
	 * gets the information data of the hash algorithm.
	 * 
	 * @public
	 * @param {string} hash_name hash algorithm name
	 * @returns the information data object.
	 */
	getAlgorithmInfo: function(hash_name)
	{
		hash_name = jCastle.digest.getValidAlgoName(hash_name);

		var algo_info = jCastle._algorithmInfo[hash_name];

		var info = {
			algo: hash_name,
			blockSize: algo_info.block_size,
			bitLength: algo_info.digest_size * 8,
			digestSize: algo_info.digest_size,
			oid: algo_info.oid
		};

		return info;
	},

	/**
	 * gets an object id of the hash name
	 * 
	 * @public
	 * @param {string} hash_name hash algorithm name
	 * @returns the object id of the hash algorithm if exists
	 */
	getOID: function(hash_name)
	{
		return jCastle._algorithmInfo[jCastle.digest.getValidAlgoName(hash_name)].oid;
	},

	/**
	 * gets hash algorithm name using the oid.
	 * 
	 * @public
	 * @param {string} oid object id
	 * @returns the hash algorithm name if exists.
	 */
	getHashNameByOID: function(oid)
	{
		for (var i in jCastle._algorithmInfo) {
			if (jCastle._algorithmInfo[i].oid == oid) {
				return i;
			}
		}
		return false;
	}
});

jCastle.Digest = jCastle.digest;

module.exports = jCastle.digest;
