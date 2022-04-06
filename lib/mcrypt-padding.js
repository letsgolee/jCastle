/**
 * A Javascript implemenation of Mcrypt Paddings 
 * 
 * @author Jacob Lee
 *
 * Copyright (C) 2015-2022 Jacob Lee.
 */

var jCastle = require('./jCastle');
require('./util');
require('./mcrypt');

jCastle.mcrypt.padding = {};

/**
 * gets a padding object.
 * 
 * @public
 * @param {string} padname padding name.
 * @returns the padding object.
 */
jCastle.mcrypt.padding.create = function(padname)
{
	if (padname in jCastle.mcrypt.padding)
		return jCastle.mcrypt.padding[padname];
	
	throw jCastle.exception("INVALID_PADDING", 'PAD007');
};

jCastle.mcrypt.padding['zeros'] = 
{
	name: 'Zero Byte Padding',

	pad: function(input, block_size)
	{
		var pads = block_size - input.length % block_size;
		var output;

		// if input size is 0 then it needs padding...
		if (pads != block_size || input.length == 0) {
			output = Buffer.concat([input, Buffer.alloc(pads)]);
		} else {
			output = input;
		}

		return output;
	},

	unpad: function(input, block_size)
	{
		var cnt = 0;
		var pos = input.length -1;
		
		while (input[pos--] == 0x00) {
			cnt++;
		}
		if (cnt > block_size) {
			throw jCastle.exception("INVALID_PADDING", 'PAD001');
		}
		
		// buffer.slice() returns a new Buffer that references the same memory as the original.
		// buffer.slice() does as buffer.subarray().
		var output = Buffer.slice(input, 0, input.length - cnt);

		return output;
	}
};

jCastle.mcrypt.padding['pkcs7'] =
{
	name: 'PKCS#7 Padding',

	pad: function(input, block_size)
	{
		var pads = block_size - input.length % block_size;
		var output = Buffer.concat([input, Buffer.alloc(pads, pads)]);
		return output;
	}, 

	unpad: function(input, block_size)
	{
		var pads = input[input.length - 1] & 0xFF;

		if (pads > block_size) {
			throw jCastle.exception("INVALID_PADDING", 'PAD002');
		}

		var l = input.length - pads;

		for (var i = l; i < input.length; i++) {
			if (input[i] != pads) throw jCastle.exception("INVALID_PADDING", 'PAD005');
		}

		var output = Buffer.slice(input, 0, l);

		return output;
	}
};

jCastle.mcrypt.padding['pkcs5'] = 
{
	name: 'PKCS#5 Padding',

	pad: jCastle.mcrypt.padding['pkcs7'].pad,

	unpad: jCastle.mcrypt.padding['pkcs7'].unpad

};

jCastle.mcrypt.padding['ansix923'] = 
{
	name: 'ANSI X.923 Padding',

	pad: function(input, block_size)
	{
		var pads = block_size - input.length % block_size;
		var output;

		// if input size is 0 then it needs padding...
		if (pads != block_size || input.length == 0) {
			var padding = Buffer.alloc(pads);
			padding[padding.length - 1] = pads;
			output = Buffer.concat([input, padding]);
		} else {
			output = input;
		}

		return output;
	},

	unpad: function(input, block_size)
	{
		var pads = input[input.length - 1] & 0xFF;

		if (pads > block_size) {
			throw jCastle.exception("INVALID_PADDING", 'PAD006');
		}

		var l = input.length - pads;

		var output = Buffer.slice(input, 0, l);

		return output;
	}
};

jCastle.mcrypt.padding['iso10126'] = 
{
	name: 'ISO 10126 Padding',

	pad: function(input, block_size)
	{
		var pads = block_size - input.length % block_size;
		var padding = new jCastle.prng().nextBytes(pads-1);

		padding[padding.length - 1] = pads;

		var output = Buffer.concat([input, padding]);

		return output;
	},

	unpad: jCastle.mcrypt.padding['ansix923'].unpad
};

// bit padding
jCastle.mcrypt.padding['iso7816'] = 
{
	name: 'ISO/IEC 7816-4 Padding',

	pad: function(input, block_size)
	{
		var pads = block_size - input.length % block_size;

		var padding = Buffer.alloc(pads);
		padding[0] = 0x80;

		var output = Buffer.concat([input, padding]);

		return output;
	},

	unpad: function(input, block_size)
	{
		var cnt = 0;
		while (input[input.length - 1 - cnt] == 0x00) {
			cnt++;
		}
		if (cnt >= block_size) {
			throw jCastle.exception("INVALID_PADDING", 'PAD003');
		}
		var b = input[input.length - 1 - cnt] & 0xff;
		if (b != 0x80) {
			throw jCastle.exception("INVALID_PADDING", 'PAD004');
		}
		cnt++;

		var output = Buffer.slice(input, 0, input.length - cnt);

		return output;
	}
};

jCastle.mcrypt.padding['iso9797-1'] = jCastle.mcrypt.padding['iso7816'];

jCastle.mcrypt.padding['none'] = 
{
	name: 'No Padding',

	pad: function(input)
	{
		return input;
	},

	unpad: function(input)
	{
		return input;
	}
};

module.exports = jCastle.mcrypt.padding;
