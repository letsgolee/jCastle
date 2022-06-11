/**
 * A Javascript implemenation of HMac
 * 
 * @author Jacob Lee
 * 
 * Copyright (C) 2015-2022 Jacob Lee.
 */

var jCastle = require('./jCastle');
require('./util');
require('./digest');

jCastle.hmac = class
{
	/**
	 * An implementation of Hash Mac
	 * 
	 * @param {string} hash_name hash algorithm name
	 * @constructor
	 */
    constructor(hash_name)
    {
        this.algoName = hash_name || '';
        this._md = null;

        this._default = {
    //		format: 'bytes',
    //		outputLength: 0,
    //		rounds: 0
        };

        this._options = {};
        this._pos = 0;
        this._input = null;
        this._initialized = false;

        this._skein = false; // skein has different hash mechanism.

        this._hmac = false;
        this._hmacKey = null;
        if (this.algoName.length) {
            var pos = this.algoName.indexOf(',');
            if (pos != -1) {
                this._options.rounds = parseInt(this.algoName.substring(pos+1));
                this.algoName = this.algoName.substring(0, pos);
            }

            this.algoName = jCastle.Digest.getValidAlgoName(this.algoName);

            if (/^skein-/.test(this.algoName)) this._skein = true;
        }
    }

	/**
	 * resets internal variables.
	 * 
	 * @public
	 * @returns this class object.
	 */
	reset()
	{
		this._pos = 0;
		this._input = null;
		this._initialized = false;
		this._hmac = false;
		this._hmacKey = null;
		this._options = {};
		this._md = null;
		this._skein = false;
	}

	/**
	 * starts mac process.
	 * 
	 * @public
	 * @param {object} options options object for mac process.
	 *                 {number} outputSize if set, the final digest buffer will be reduced by it.
	 *                 {number} outputBits if set, the final digest buffer will be reduced by it. 
	 *                          the value should be multiple of 8.
	 *                 {string} algoName hash algorithm name.
	 *                 {buffer} key key used to mac process.
	 *                 {buffer} macKey alias to 'key'.
	 *                 {string} encoding if given final digest buffer value will be stringed to the encoding.
	 * @returns this class object for function chaining.
	 */
	start(options = {})
	{
		// for (var i in options) {
		// 		this._options[i] = options[i];
		// }

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
				throw jCastle.exception('INVALID_OUTPUT_BITS', 'HMC001');
			}
			this._options.outputLength = this._options.outputBits / 8;
		}

		if ('algoName' in this._options) {
			this._setAlgorithm(this._options.algoName);
		}

		if ('key' in this._options || 'hmacKey' in this._options) {
			this._hmacKey = this._options.key || this._options.hmacKey;
			if (!Buffer.isBuffer(this._hmacKey))
				this._hmacKey = Buffer.from(this._options.key, 'latin1');
		}

		if (!this._hmacKey) {
			throw jCastle.exception('INVALID_KEYSIZE', 'HMC002');
		}

		if (/^skein-/.test(this.algoName)) this._skein = true;
		else this._skein = false;

		if (this._md == null) {
			if (this.algoName.length == 0) {
				throw jCastle.exception('NOT_INITIALIZED', 'HMC003');
			}
			this._md = new jCastle.algorithm[jCastle._algorithmInfo[this.algoName].object_name](this.algoName);
		}

		// skein will use the original key
		// other hmac needs a key of block size
		if (!this._skein) {
			var opt = {};
			if (this._options.outputLength) opt.outputSize = this._options.outputLength;

			if (this._hmacKey.length > jCastle._algorithmInfo[this.algoName].block_size) {
				this._hmacKey = new jCastle.digest(
					this._options.rounds > 0 ? this.algoName + ',' + this._options.rounds : this.algoName
				).digest(this._hmacKey, opt);
			}

			if (this._hmacKey.length < jCastle._algorithmInfo[this.algoName].block_size) {
				this._hmacKey = Buffer.concat([this._hmacKey, Buffer.alloc(jCastle._algorithmInfo[this.algoName].block_size - this._hmacKey.length)]);
			}
		}
		
		this._input = Buffer.alloc(0);

		this._md.init({
			rounds: this._options.rounds, 
			outputLength: this._options.outputLength,
			hmacKey: this._hmacKey});

		return this;
	}

	/**
	 * updates the process with the message
	 * 
	 * @public
	 * @param {buffer} message message to be updated.
	 * @returns this class object.
	 */
	update(message)
	{
		var input;

		var block_size = jCastle._algorithmInfo[this.algoName].block_size;
		
		if (!this._initialized) {
			this._initialized = true;

			if (!this._skein) {
				var ipad = Buffer.alloc(block_size);
				for (var i = 0; i < block_size; i++) {
					ipad[i] = (this._hmacKey[i] ^ 0x36) & 0xff;
				}
				this.update(ipad);
			}
		}

		if (message && message.length) {
			input = Buffer.from(message);
			this._input = Buffer.concat([this._input, input]);
		}

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
	 * @param {buffer} message 
	 * @returns the hash mac in buffer
	 */
	finalize(message)
	{
		// if (message) {
		// 	var input = Buffer.from(message);
		// 	this._input = Buffer.concat([this._input, input]);
		// }
		if (message && message.length) {
			this.update(message);
		}

		if (!this._initialized) {
			throw jCastle.exception('NOT_INITIALIZED', 'HMC004');
		}

		this._input = this._md.pad(this._input, this._pos);

		var block_size = jCastle._algorithmInfo[this.algoName].block_size;

		while (this._pos < this._input.length) {
			this._md.process(this._input.slice(this._pos, this._pos + block_size));
			this._pos += block_size;
		}

		var output = this._md.finish();

		if (!this._skein) {
			var opad = Buffer.alloc(block_size);
			for (var i = 0; i < block_size; i++) {
				opad[i] = (this._hmacKey[i] ^ 0x5c) & 0xff;
			}

			var opt = {};
			if (this._options.outputLength) opt.outputSize = this._options.outputLength;
			
			output = new jCastle.digest(this._options.rounds > 0 ? this.algoName + ',' + this._options.rounds : this.algoName)
				.start(opt)
				.update(opad)
				.update(output)
				.finalize();
		}

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

			this.algoName = jCastle.Digest.getValidAlgoName(hash_name);
		}

		return this;
	}

};

Object.assign(jCastle.hmac,
{
	/**
	 * creates a new class object.
	 * 
	 * @public
	 * @param {string} hash_name hash algorithm name
	 * @returns the new class object.
	 */
	create: function(hash_name)
	{
		return new jCastle.hmac(hash_name);
	},

	/**
	 * creates a new class object and start a hash mac process.
	 * 
	 * @public
	 * @param {object} options options object for mac process.
	 * @returns the class object.
	 */
	start: function(options)
	{
		return new jCastle.hmac().start(options);
	},

	/**
	 * digest the message.
	 * 
	 * @public
	 * @param {buffer} message message to be digested.
	 * @param {object} options options object for the process.
	 * @returns the digested hash in buffer.
	 */
	digest: function(message, options)
	{
		return new jCastle.hmac().start(options).update(message).finalize();
	},

	/**
	 * gets an object id of the hash mac name
	 * 
	 * @public
	 * @param {string} hash_name hash algorithm name
	 * @returns the object id of the hash algorithm if exists
	 */
	getOID: function(algo)
	{
		algo = jCastle.digest.getValidAlgoName(algo);

		switch (algo) {
			case 'gost': 
			case 'gost3411': return "1.2.643.2.2.10"; // hmacGost
			case 'sha-1': return "1.2.840.113549.2.7"; // hmacWithSHA1
			case 'sha-224': return "1.2.840.113549.2.8"; // hmacWithSHA224
			case 'sha-256': return "1.2.840.113549.2.9"; // hmacWithSHA256
			case 'sha-384': return "1.2.840.113549.2.10"; // hmacWithSHA384
			case 'sha-512': return "1.2.840.113549.2.11"; // hmacWithSHA512
			case 'md5': return "1.3.6.1.5.5.8.1.1"; // hmacMD5
			//case 'sha-1': return "1.3.6.1.5.5.8.1.2"; // hmacSHA
			case 'tiger': return "1.3.6.1.5.5.8.1.3"; // hmacTiger
		}

		return null;
	},

	/**
	 * get a registered hash mac algorithm name.
	 * 
	 * @public
	 * @param {string} algo hash algorithm name
	 * @returns the hash mac algorithm name registered with OID.
	 */
	getMacName: function(algo)
	{
		algo = jCastle.digest.getValidAlgoName(algo);

		switch (algo) {
			case 'gost': 
			case 'gost3411': return 'hmacGost';
			case 'sha-1': return 'hmacWithSHA1';
			case 'sha-224': return 'hmacWithSHA224';
			case 'sha-256': return 'hmacWithSHA256';
			case 'sha-384': return 'hmacWithSHA384';
			case 'sha-512': return 'hmacWithSHA512';
			case 'md5': return 'hmacMD5';
			case 'tiger': return 'hmacTiger';
		}

		return null;
	},

	/**
	 * gets the base hash algorithm name.
	 * 
	 * @public
	 * @param {string} hmac_algo hash mac algorithm name
	 * @returns hash algorithm name
	 */
	getAlgoName: function(hmac_algo)
	{
		var m = /hmac(With)?([a-z0-9]+)/i.exec(hmac_algo);

		return jCastle.digest.getValidAlgoName(m[2]);
	}
});

jCastle.HMac = jCastle.hmac;

module.exports = jCastle.hmac;
