/**
 * Unsigned 32 bits integers in Javascript
 *
 * Copyright (C) 2015-2021 Jacob Lee <letsgolee@naver.com>
 * MIT license
 * 
 * Original: https://github.com/pierrec/js-cuint
 *	Copyright (C) 2013, Pierre Curto
 *	MIT license
 */

 const UINT32 = (function() {

	function UINT32 (high, low)
	{
		this._low = low | 0;
		this._high = high | 0;

		this.remainder = null;

		if (typeof low == 'undefined') {
			this._high = 0;
			this._low = high;
		}
	};

	UINT32.prototype = {
        toNumber: function()
        {
            //return (this._high << 16) | this._low;
            return (this._high * 65536) + this._low;
        },
	
		toString: function(radix)
		{
/*
			radix = radix || 10;
			var radixUint = new UINT32(radix);

			if (!this.gt(radixUint)) return this.toNumber().toString(radix);

			var self = this.clone();
			var res = new Array(32);
			for (var i = 31; i >= 0; i--) {
				self = self.div(radixUint); // fix bug. 2021.10.19
				res[i] = self.remainder.toNumber().toString(radix);
				if (!self.gt(radixUint)) break;
			}
			res[i-1] = self.toNumber().toString(radix);

			return res.join('');
*/
            return this.toNumber().toString(radix || 10);
		},


		add: function(other)
		{
			if (!(other instanceof UINT32)) other = UINT32.valueOf(other);

			var a00 = this._low + other._low;
			var a16 = a00 >>> 16;

			a16 += this._high + other._high;

			var low = a00 & 0xFFFF;
			var high = a16 & 0xFFFF;

			return UINT32.fromBits(high, low);
		},


		subtract: function(other)
		{
			if (!(other instanceof UINT32)) other = UINT32.valueOf(other);

			return this.add(other.negate());
		},


		multiply: function(other)
		{
			if (!(other instanceof UINT32)) other = UINT32.valueOf(other);

			/*
				a = a00 + a16
				b = b00 + b16
				a*b = (a00 + a16)(b00 + b16)
					= a00b00 + a00b16 + a16b00 + a16b16

				a16b16 overflows the 32bits
			 */
			var a16 = this._high;
			var a00 = this._low;
			var b16 = other._high;
			var b00 = other._low;

		/* Removed to increase speed under normal circumstances (i.e. not multiplying by 0 or 1)
				// this == 0 or other == 1: nothing to do
				if ((a00 == 0 && a16 == 0) || (b00 == 1 && b16 == 0)) return this

				// other == 0 or this == 1: this = other
				if ((b00 == 0 && b16 == 0) || (a00 == 1 && a16 == 0)) {
					this._low = other._low
					this._high = other._high
					return this
				}
		*/

			var c16, c00;
			c00 = a00 * b00;
			c16 = c00 >>> 16;

			c16 += a16 * b00;
			c16 &= 0xFFFF;		// Not required but improves performance
			c16 += a00 * b16;

			var low = c00 & 0xFFFF;
			var high = c16 & 0xFFFF;

			return UINT32.fromBits(high, low);
		},


		div: function(other)
		{
			if (!(other instanceof UINT32)) other = UINT32.valueOf(other);

			if ( (other._low == 0) && (other._high == 0) ) throw Error('division by zero');

			// other == 1
			if (other._high == 0 && other._low == 1) {
				var res = this.clone();
				res.remainder = UINT32.valueOf(0);
				return res;
			}

			// other > this: 0
			if ( other.gt(this) ) {
				var res = UINT32.valueOf(0);
				res.remainder = UINT32.valueOf(0);
				return res;
			}

			// other == this: 1
			if (this.eq(other)) {
				var res = UINT32.valueOf(1);
				res.remainder = UINT32.valueOf(0);
				return res;
			}

			// Shift the divisor left until it is higher than the dividend
			var _other = other.clone();
			var i = -1;
			var result = UINT32.valueOf(0);

			while ( !this.lt(_other) ) {
				// High bit can overflow the default 16bits
				// Its ok since we right shift after this loop
				// The overflown bit must be kept though
				_other = _other.shiftLeft(1, true);
				i++;
			}

			// Set the remainder
			result.remainder = this.clone();
			// Initialize the current result to 0
			//result._low = 0;
			//result._high = 0;
			for (; i >= 0; i--) {
				_other = _other.shiftRight(1);
				// If shifted divisor is smaller than the dividend
				// then subtract it from the dividend
				if ( !result.remainder.lt(_other) ) {
					result.remainder = result.remainder.subtract(_other);
					// Update the current result
					if (i >= 16) {
						result._high |= 1 << (i - 16);
					} else {
						result._low |= 1 << i;
					}
				}
			}

			return result;
		},


		modulo: function(other)
		{
			var result = this.div(other);

			return result.remainder;
		},


		negate: function()
		{
			var v = ( ~this._low & 0xFFFF ) + 1;
			var low = v & 0xFFFF;
			var high = (~this._high + (v >>> 16)) & 0xFFFF;

			return UINT32.fromBits(high, low);
		},


		eq: function(other)
		{
			if (!(other instanceof UINT32)) other = UINT32.valueOf(other);

			return (this._low == other._low) && (this._high == other._high);
		},


		gt: function(other)
		{
			if (!(other instanceof UINT32)) other = UINT32.valueOf(other);

			if (this._high > other._high) return true;
			if (this._high < other._high) return false;
			return this._low > other._low;
		},


		lt: function(other)
		{
			if (!(other instanceof UINT32)) other = UINT32.valueOf(other);

			if (this._high < other._high) return true;
			if (this._high > other._high) return false;
			return this._low < other._low;
		},


		compareTo: function(other)
		{
			if (!(other instanceof UINT32)) other = UINT32.valueOf(other);

			if (this._high > other._high) return 1;
			if (this._high < other._high) return -1;
			if (this._low > other._low) return 1;
			
			return this._low == other._low ? 0 : -1;
		},


		or: function(other)
		{
			if (!(other instanceof UINT32)) other = UINT32.valueOf(other);

			return UINT32.fromBits(this._high | other._high, this._low | other._low);
		},


		and: function(other)
		{
			if (!(other instanceof UINT32)) other = UINT32.valueOf(other);

			return UINT32.fromBits(this._high & other._high, this._low & other._low);
		},


		not: function()
		{
			return UINT32.fromBits(~this._high & 0xFFFF, ~this._low & 0xFFFF);
		},


		xor: function(other)
		{
			if (!(other instanceof UINT32)) other = UINT32.valueOf(other);

			return UINT32.fromBits(this._high ^ other._high, this._low ^ other._low);
		},


		shiftr: function(n)
		{
			var high, low;

			if (n > 16) {
				low = this._high >> (n - 16);
				high = 0;
			} else if (n == 16) {
				low = this._high;
				high = 0;
			} else {
				low = (this._low >>> n) | ( (this._high << (16-n)) & 0xFFFF );
				high = this._high >>> n;
			}

			return UINT32.fromBits(high, low);
		},


		shiftl: function(n, allowOverflow)
		{
			var high, low;

			if (n > 16) {
				high = this._low << (n - 16);
				low = 0;
				if (!allowOverflow) {
					high &= 0xFFFF;
				}
			} else if (n == 16) {
				high = this._low;
				low = 0;
			} else {
				high = (this._high << n) | (this._low >> (16-n));
				low = (this._low << n) & 0xFFFF;
				if (!allowOverflow) {
					// Overflow only allowed on the high bits...
					high &= 0xFFFF;
				}
			}

			return UINT32.fromBits(high, low);
		},


		rotl: function(n)
		{
			var v = (this._high << 16) | this._low;
			v = (v << n) | (v >>> (32 - n));
			var low = v & 0xFFFF;
			var high = v >>> 16;

			return UINT32.fromBits(high, low);
		},


		rotr: function(n)
		{
			var v = (this._high << 16) | this._low;
			v = (v >>> n) | (v << (32 - n));
			var low = v & 0xFFFF;
			var high = v >>> 16;

			return UINT32.fromBits(high, low);
		},


		clone: function()
		{
			return UINT32.fromBits(this._high, this._low);
		}
	
	};

	UINT32.prototype.mod = UINT32.prototype.modulo;
	UINT32.prototype.equals = UINT32.prototype.eq;
	UINT32.prototype.greaterThan = UINT32.prototype.gt;
	UINT32.prototype.lessThan = UINT32.prototype.lt;
	UINT32.prototype.compare = UINT32.prototype.compareTo;
	UINT32.prototype.shiftRight = UINT32.prototype.shiftr;
	UINT32.prototype.shiftLeft = UINT32.prototype.shiftl;
	UINT32.prototype.rotateLeft = UINT32.prototype.rotl;
	UINT32.prototype.rotateRight = UINT32.prototype.rotr;


	UINT32.fromBits = function(highBits, lowBits)
	{
		return new UINT32(highBits, lowBits);
	};


	UINT32.valueOf =
	UINT32.fromNumber = function(value)
	{
		return new UINT32(value >>> 16, value & 0xFFFF);
	};


	UINT32.fromString = function(s, radix)
	{
		var value = parseInt(s, radix || 10);

		return new UINT32(value >>> 16, value & 0xFFFF);
	};


	if ("undefined" !== typeof exports) { // Node Support
		if (("undefined" !== typeof module) && module.exports) {
			module.exports = exports = UINT32;
		} else {
			exports = UINT32;
		}
	} else { // Browsers and Web Workers
		if (!global.UINT32) global.UINT32 = UINT32;
	}

	return UINT32;
})();

module.exports = UINT32;