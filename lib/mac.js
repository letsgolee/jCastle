/**
 * Mac: Javascript Message Authentication Code Engine 
 * 
 * @author Jacob Lee
 *
 * Copyright (C) 2015-2022 Jacob Lee.
 */

var jCastle = require('./jCastle');
require('./mcrypt');
require('./mcrypt-mode');

jCastle.mac = class
{
	/**
	 * creates a mac algorithm object.
	 * 
	 * @param {string} mac_name mac algorithm name
	 * @constructor
	 */
    constructor(mac_name)
    {
        this._blockSize = 0;
        this._macMode = null;

        this._default = {
            key: null,
            iv: null,
            algoName: '',
    //		macSize: 0
        };

        this._options = {};
        this._input = null;
        this._pos = 0;
        this._algorithm = null;
        this.macName = '';

        if (mac_name && mac_name.length) {
            this.macName = mac_name.toLowerCase();
        }
    }

	_setAlgorithm(algo)
	{
		if (jCastle.util.isString(algo)) {
			algo = algo.toLowerCase();
			if (!(algo in jCastle._algorithmInfo)) {
				throw jCastle.exception('ALGORITHM_NOT_SET', 'MAC001');
			}
			this._options.algoName = algo;
		} else if (algo && typeof algo == 'object' && 'algoName' in algo && 'masterKey' in algo) {
			this._algorithm = algo;
		}

		return this;
	}

	/**
	 * resets internal variables.
	 * 
	 * @public
	 * @returns this class instance.
	 */
	reset()
	{
		this._options = {};
		this._macMode = null;
		this._blockSize = 0;
		this._input = null;
		this._pos = 0;
		this._algorithm = null;
		this.macName = '';
	}

	/**
	 * starts mac process.
	 * 
	 * @public
	 * @param {object} options options object for mac process. each mac algorithm requires iv or noce.
	 *                 {string} macName mac algorithm name.
	 *                 {buffer} key key used to mac process.
	 *                 {buffer} macKey alias for 'key'.
	 *                 {string} encoding if given final digest buffer value will be stringed to the encoding.
	 * @returns this class instance for function chaining.
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

		// mac name
		if ('macName' in this._options) {
			this.macName = mac_name.toLowerCase();
		}

		if (!this.macName.length || !(this.macName in jCastle.mac.mode)) {
			throw jCastle.exception('UNSUPPORTED_MAC', 'MAC002');
		}

		if ('macKey' in this._options && !('key' in this._options))
			this._options.key = this._options.macKey;

		// key
		if ('key' in this._options) {

			if (!Buffer.isBuffer(this._options.key))
				this._options.key = Buffer.from(this._options.key, 'latin1');
		}

		// keyScheduling will be done in each mac init.
		if ('algorithm' in this._options && this._options.algorithm) {
			this._setAlgorithm(this._options.algorithm);
		}

		if (!this._algorithm && 'algoName' in this._options && this._options.algoName.length) {
			this._algorithm = jCastle.mcrypt.getAlgorithm(this._options.algoName);
		}

		// nonce or iv
//		if (this._options.iv || this._options.nonce) {
//			this._options.initialVector = (this._options.nonce) ? this._options.nonce : this._options.iv;
//			this._options.initialVector = ByteBuffer.parse(this._options.initialVector);
//		}

		this._macMode = jCastle.mac.mode.create(this.macName);

		if (this._algorithm) {
			this._blockSize = jCastle._algorithmInfo[this._algorithm.algoName].block_size;
		} else {
			// we need to set block size or it will be in the loop continually.
			// these are the cases the algo name is not given.
			this._blockSize = this._macMode.blockSize;
		}

		if (!this._options.blockSize) this._options.blockSize = this._blockSize;
		
		this._input = Buffer.alloc(0);

		this._macMode.init(this._algorithm, this._options);

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

		while (this._pos + this._blockSize <= this._input.length) {
			this._mac = this._macMode.process(this._input.slice(this._pos, this._pos + this._blockSize));
			this._pos += this._blockSize;
		}

		return this;
	}

	/**
	 * finalize the process and returns the hash result.
	 * 
	 * @public
	 * @param {buffer} message 
	 * @returns the mac in buffer
	 */
	finalize(message)
	{
		if (message && message.length) {
			this.update(message);
		}

		while (this._pos < this._input.length) {
			this._mac = this._macMode.process(this._input.slice(this._pos, this._pos + this._blockSize));
			this._pos += this._blockSize;
		}

		this._mac = this._macMode.finish();

		var mac = Buffer.slice(this._mac);

		if ('encoding' in this._options) {
			mac = mac.toString(this._options.encoding);
		}

		this.reset();

		return mac;
	}

	/**
	 * digest the message to get mac.
	 * 
	 * @public
	 * @param {buffer} message message to be digested.
	 * @param {object} options options object for digest process.
	 * @returns the mac in buffer.
	 */
	digest(message, options)
	{
		return this.start(options).update(message).finalize();
	}
}

Object.assign(jCastle.mac, 
{
	/**
	 * creates a new class instance.
	 * 
	 * @public
	 * @param {string} mac_name mac algorithm name
	 * @returns the new class instance.
	 */
	create: function(mac_name)
	{
		return new jCastle.mac(mac_name);
	},

	/**
	 * creates a new class instance and start a hash mac process.
	 * 
	 * @public
	 * @param {object} options options object for mac process.
	 * @returns the class instance.
	 */
	start: function(options)
	{
		return new jCastle.mac().start(options);
	},

	/**
	 * digest the message to get mac.
	 * 
	 * @public
	 * @param {buffer} message message to be digested.
	 * @param {object} options options object for the process.
	 * @returns mac in buffer.
	 */
	digest: function(message, options)
	{
		return new jCastle.mac().start(options).update(message).finalize();
	},

	/**
	 * gets an object id of the mac name
	 * 
	 * @public
	 * @param {string} algo mac algorithm name
	 * @returns the object id of the mac algorithm if exists
	 */
	getOID: function(algo)
	{
		algo = jCastle.mcrypt.getValidAlgoName(algo);

		switch (algo) {
			case 'des': return "1.3.14.3.2.10"; // desMAC
			case 'seed':
			case 'seed-128': return "1.2.410.200004.1.7"; // seed-MAC
			case 'aria-128': return "1.2.410.200046.1.1.21"; // aria-128-MAC
			case 'aria-192': return "1.2.410.200046.1.1.22"; // aria-192-MAC
			case 'aria-256': return "1.2.410.200046.1.1.23"; // aria-256-MAC
			case 'cast5': return "1.2.840.113533.7.66.11"; // cast5-MAC
			case 'rc4': return "1.2.840.113549.3.5"; // rc4WithMAC
		}

		return null;
	},

	/**
	 * get a registered mac algorithm name.
	 * 
	 * @public
	 * @param {string} algo mac algorithm name
	 * @returns the mac algorithm name registered with OID.
	 */
	getMacName: function(algo)
	{
		algo = jCastle.mcrypt.getValidAlgoName(algo);

		switch (algo) {
			case 'des': return 'desMAC';
			case 'seed':
			case 'seed-128': return 'seed-MAC';
			case 'aria-128':
			case 'aria-192':
			case 'aria-256':
			case 'cast5':
				return algo + '-MAC';
			case 'rc4': return 'rc4WithMAC';
		}

		return null;
	},

	/**
	 * gets the base algorithm name.
	 * 
	 * @public
	 * @param {string} mac_algo mac algorithm name
	 * @returns algorithm name
	 */
	getAlgoName: function(mac_algo)
	{
		var m = /([a-z0-9\-]+)(WithMAC|\-MAC)/i.exec(mac_algo);

		return jCastle.mcrypt.getValidAlgoName(m[1]);
	}
});

module.exports = jCastle.mac;
