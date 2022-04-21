/**
 * Unsigned 64 bits integers in Javascript
 *
 * Copyright (C) 2015-2021 Jacob Lee <letsgolee@naver.com>
 * MIT license
 * 
 * Original: https://github.com/pierrec/js-cuint
 *	Copyright (C) 2013, Pierre Curto
 *	MIT license
 */

 const UINT64 = (function() {

	/**
	 *	Represents an unsigned 64 bits integer
	 * @constructor
	 * @param {Number} first high bits (8)
	 * @param {Number} second high bits (8)
	 * @param {Number} first low bits (8)
	 * @param {Number} second low bits (8)
	 * or
	 * @param {Number} low bits (32)
	 * @param {Number} high bits (32)
	 * or
	 * @param {String|Number} integer as a string 		 | integer as a number
	 * @param {Number|Undefined} radix (optional, default=10)
	 * @return 
	 */
	function UINT64(a48, a32, a16, a00)
	{
		this._a00 = a00 | 0;
		this._a16 = a16 | 0;
		this._a32 = a32 | 0;
		this._a48 = a48 | 0;

		this.remainder = null;

		if (typeof a32 == 'undefined') {
			// UINT64(lowBits)
			this._a00 = a48 & 0xFFFF;
			this._a16 = a48 >>> 16;
			this._a32 = 0;
			this._a48 = 0;
		} else if (typeof a16 == 'undefined') {
			// UINT64(highBits, lowBits)
			this._a00 = a32 & 0xFFFF;
			this._a16 = a32 >>> 16;
			this._a32 = a48 & 0xFFFF;
			this._a48 = a48 >>> 16;
		}
	};


	UINT64.prototype = {
		toNumber: function()
		{
			//return (this._a16 << 16) | this._a00;
            return (this._a16 * 65536) + this._a00;
		},


		toString: function(radix)
		{
			radix = radix || 10;
			var radixUint = UINT64.valueOf(radix);

			if (!this.gt(radixUint)) return this.toNumber().toString(radix);

			var self = this.clone();
			var res = new Array(64);
			for (var i = 63; i >= 0; i--) {
				self = self.div(radixUint); // fix bug. 2021.10.19
				res[i] = self.remainder.toNumber().toString(radix);
				if (!self.gt(radixUint)) break;
			}
			res[i-1] = self.toNumber().toString(radix);

			return res.join('');
		},


		add: function(other)
		{
			if (!(other instanceof UINT64)) other = UINT64.valueOf(other);

			var a00 = this._a00 + other._a00;

			var a16 = a00 >>> 16;
			a16 += this._a16 + other._a16;

			var a32 = a16 >>> 16;
			a32 += this._a32 + other._a32;

			var a48 = a32 >>> 16;
			a48 += this._a48 + other._a48;

			return new UINT64(a48 & 0xFFFF, a32 & 0xFFFF, a16 &0xFFFF, a00 & 0xFFFF);
		},


		subtract: function(other)
		{
			if (!(other instanceof UINT64)) other = UINT64.valueOf(other);

			return this.add(other.negate());
		},


		multiply: function(other)
		{
			if (!(other instanceof UINT64)) other = UINT64.valueOf(other);

			/*
				a = a00 + a16 + a32 + a48
				b = b00 + b16 + b32 + b48
				a*b = (a00 + a16 + a32 + a48)(b00 + b16 + b32 + b48)
					= a00b00 + a00b16 + a00b32 + a00b48
					+ a16b00 + a16b16 + a16b32 + a16b48
					+ a32b00 + a32b16 + a32b32 + a32b48
					+ a48b00 + a48b16 + a48b32 + a48b48

				a16b48, a32b32, a48b16, a48b32 and a48b48 overflow the 64 bits
				so it comes down to:
				a*b	= a00b00 + a00b16 + a00b32 + a00b48
					+ a16b00 + a16b16 + a16b32
					+ a32b00 + a32b16
					+ a48b00
					= a00b00
					+ a00b16 + a16b00
					+ a00b32 + a16b16 + a32b00
					+ a00b48 + a16b32 + a32b16 + a48b00
			 */
			var a00 = this._a00;
			var a16 = this._a16;
			var a32 = this._a32;
			var a48 = this._a48;
			var b00 = other._a00;
			var b16 = other._a16;
			var b32 = other._a32;
			var b48 = other._a48;

			var c00 = a00 * b00;

			var c16 = c00 >>> 16;
			c16 += a00 * b16;
			var c32 = c16 >>> 16;
			c16 &= 0xFFFF;
			c16 += a16 * b00;

			c32 += c16 >>> 16;
			c32 += a00 * b32;
			var c48 = c32 >>> 16;
			c32 &= 0xFFFF;
			c32 += a16 * b16;
			c48 += c32 >>> 16;
			c32 &= 0xFFFF;
			c32 += a32 * b00;

			c48 += c32 >>> 16;
			c48 += a00 * b48;
			c48 &= 0xFFFF;
			c48 += a16 * b32;
			c48 &= 0xFFFF;
			c48 += a32 * b16;
			c48 &= 0xFFFF;
			c48 += a48 * b00;

			return new UINT64(c48 & 0xFFFF, c32 & 0xFFFF, c16 &0xFFFF, c00 & 0xFFFF);
		},


		div: function(other)
		{
			if (!(other instanceof UINT64)) other = UINT64.valueOf(other);

			if ((other._a16 == 0) && (other._a32 == 0) && (other._a48 == 0)) {
				if (other._a00 == 0) throw Error('division by zero');

				// other == 1: this
				if (other._a00 == 1) {
					var result = this.clone();
					result.remainder = UINT64.valueOf(0);
					return result;
				}
			}

			// other > this: 0
			if (other.gt(this)) {
				var result = UINT64.valueOf(0);
				result.remainder = UINT64.valueOf(0);
				return result;
			}
			// other == this: 1
			if (this.eq(other)) {
				var result = UINT64.valueOf(1);
				result.remainder = new UINT64(0);
				return result;
			}

			// Shift the divisor left until it is higher than the dividend
			var _other = other.clone();
			var i = -1;
			var result = UINT64.valueOf(0);

			while (!this.lt(_other)) {
				// High bit can overflow the default 16bits
				// Its ok since we right shift after this loop
				// The overflown bit must be kept though
				_other = _other.shiftLeft(1, true);
				i++;
			}

			// Set the remainder
			result.remainder = this.clone();
			// Initialize the current result to 0
			for (; i >= 0; i--) {
				_other = _other.shiftRight(1);
				// If shifted divisor is smaller than the dividend
				// then subtract it from the dividend
				if (!result.remainder.lt(_other)) {
					result.remainder = result.remainder.subtract(_other);
					// Update the current result
					if (i >= 48) {
						result._a48 |= 1 << (i - 48);
					} else if (i >= 32) {
						result._a32 |= 1 << (i - 32);
					} else if (i >= 16) {
						result._a16 |= 1 << (i - 16);
					} else {
						result._a00 |= 1 << i;
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
			var v = (~this._a00 & 0xFFFF) + 1;
			var a00 = v & 0xFFFF;
			v = (~this._a16 & 0xFFFF) + (v >>> 16);
			var a16 = v & 0xFFFF;
			v = (~this._a32 & 0xFFFF) + (v >>> 16);
			var a32 = v & 0xFFFF;
			var a48 = (~this._a48 + (v >>> 16)) & 0xFFFF;

			return new UINT64(a48, a32, a16, a00);
		},


		equals: function(other)
		{
			if (!(other instanceof UINT64)) other = UINT64.valueOf(other);

			return (this._a48 == other._a48) && (this._a00 == other._a00)
				 && (this._a32 == other._a32) && (this._a16 == other._a16);
		},


		gt: function(other)
		{
			if (!(other instanceof UINT64)) other = UINT64.valueOf(other);

			if (this._a48 > other._a48) return true;
			if (this._a48 < other._a48) return false;
			if (this._a32 > other._a32) return true;
			if (this._a32 < other._a32) return false;
			if (this._a16 > other._a16) return true;
			if (this._a16 < other._a16) return false;
			return this._a00 > other._a00;
		},


		lt: function(other)
		{
			if (!(other instanceof UINT64)) other = UINT64.valueOf(other);

			if (this._a48 < other._a48) return true;
			if (this._a48 > other._a48) return false;
			if (this._a32 < other._a32) return true;
			if (this._a32 > other._a32) return false;
			if (this._a16 < other._a16) return true;
			if (this._a16 > other._a16) return false;
			return this._a00 < other._a00;
		},

		compareTo: function(other)
		{
			if (!(other instanceof UINT64)) other = UINT64.valueOf(other);

			if (this._a48 > other._a48) return 1;
			if (this._a48 < other._a48) return -1;
			if (this._a32 > other._a32) return 1;
			if (this._a32 < other._a32) return -1;
			if (this._a16 > other._a16) return 1;
			if (this._a16 < other._a16) return -1;
			if (this._a00 > other._a00) return 1;
			return this._a00 == other._a00 ? 0 : -1;
		},


		or: function (other)
		{
			if (!(other instanceof UINT64)) other = UINT64.valueOf(other);

			return new UINT64(this._a48 | other._a48, this._a32 | other._a32, this._a16 | other._a16, this._a00 | other._a00);
		},


		and: function (other)
		{
			if (!(other instanceof UINT64)) other = UINT64.valueOf(other);

			return new UINT64(this._a48 & other._a48, this._a32 & other._a32, this._a16 & other._a16, this._a00 & other._a00);
		},


		xor: function (other)
		{
			if (!(other instanceof UINT64)) other = UINT64.valueOf(other);

			return new UINT64(this._a48 ^ other._a48, this._a32 ^ other._a32, this._a16 ^ other._a16, this._a00 ^ other._a00);
		},


		not: function()
		{
			return new UINT64(~this._a48 & 0xFFFF, ~this._a32 & 0xFFFF, ~this._a16 & 0xFFFF, ~this._a00 & 0xFFFF);
		},


		shiftr: function (n)
		{
			var a48, a32, a16, a00;
			n %= 64;

			if (n >= 48) {
				a00 = this._a48 >> (n - 48);
				a16 = 0;
				a32 = 0;
				a48 = 0;
			} else if (n >= 32) {
				n -= 32;
				a00 = ( (this._a32 >> n) | (this._a48 << (16-n)) ) & 0xFFFF;
				a16 = (this._a48 >> n) & 0xFFFF;
				a32 = 0;
				a48 = 0;
			} else if (n >= 16) {
				n -= 16;
				a00 = ( (this._a16 >> n) | (this._a32 << (16-n)) ) & 0xFFFF;
				a16 = ( (this._a32 >> n) | (this._a48 << (16-n)) ) & 0xFFFF;
				a32 = (this._a48 >> n) & 0xFFFF;
				a48 = 0;
			} else {
				a00 = ( (this._a00 >> n) | (this._a16 << (16-n)) ) & 0xFFFF;
				a16 = ( (this._a16 >> n) | (this._a32 << (16-n)) ) & 0xFFFF;
				a32 = ( (this._a32 >> n) | (this._a48 << (16-n)) ) & 0xFFFF;
				a48 = (this._a48 >> n) & 0xFFFF;
			}

			return new UINT64(a48, a32, a16, a00);
		},


		shiftl: function (n, allowOverflow)
		{
			var a48, a32, a16, a00;
			n %= 64;

			if (n >= 48) {
				a48 = this._a00 << (n - 48);
				a32 = 0;
				a16 = 0;
				a00 = 0;
			} else if (n >= 32) {
				n -= 32;
				a48 = (this._a16 << n) | (this._a00 >> (16-n));
				a32 = (this._a00 << n) & 0xFFFF;
				a16 = 0;
				a00 = 0;
			} else if (n >= 16) {
				n -= 16;
				a48 = (this._a32 << n) | (this._a16 >> (16-n));
				a32 = ( (this._a16 << n) | (this._a00 >> (16-n)) ) & 0xFFFF;
				a16 = (this._a00 << n) & 0xFFFF;
				a00 = 0;
			} else {
				a48 = (this._a48 << n) | (this._a32 >> (16-n));
				a32 = ( (this._a32 << n) | (this._a16 >> (16-n)) ) & 0xFFFF;
				a16 = ( (this._a16 << n) | (this._a00 >> (16-n)) ) & 0xFFFF;
				a00 = (this._a00 << n) & 0xFFFF;
			}
			if (!allowOverflow) {
				a48 &= 0xFFFF;
			}

			return new UINT64(a48, a32, a16, a00);
		},


		rotl: function (n)
		{
			var a48, a32, a16, a00;
			n %= 64;

			if (n == 0) return this.clone();

			a48 = this._a48; a32 = this._a32; a16 = this._a16; a00 = this._a00;

			if (n >= 32) {
				// A.B.C.D
				// B.C.D.A rotl(16)
				// C.D.A.B rotl(32)
				var v = a00;
				a00 = a32;
				a32 = v;
				v = a48;
				a48 = a16;
				a16 = v;
				if (n == 32) return new UINT64(a48, a32, a16, a00);
				n -= 32;
			}

			var high = (a48 << 16) | a32;
			var low = (a16 << 16) | a00;

			var _high = (high << n) | (low >>> (32 - n));
			var _low = (low << n) | (high >>> (32 - n));

			return new UINT64(_high >>> 16, _high & 0xFFFF, _low >>> 16, _low & 0xFFFF);
		},


		rotr: function (n)
		{
			var a48, a32, a16, a00;
			n %= 64;

			if (n == 0) return this.clone();

			a48 = this._a48; a32 = this._a32; a16 = this._a16; a00 = this._a00;
			
			if (n >= 32) {
				// A.B.C.D
				// D.A.B.C rotr(16)
				// C.D.A.B rotr(32)
				var v = a00;
				a00 = a32;
				a32 = v;
				v = a48;
				a48 = _a16;
				a16 = v;
				if (n == 32) return this;
				n -= 32;
			}

			var high = (a48 << 16) | a32;
			var low = (a16 << 16) | a00;

			var _high = (high >>> n) | (low << (32 - n));
			var _low = (low >>> n) | (high << (32 - n));

			return new UINT64(_high >>> 16, _high & 0xFFFF, _low >>> 16, _low & 0xFFFF);
		},

			/**
			 * Clone the current _UINT64_
			 * @method clone
			 * @return {Object} cloned UINT64
			 */
		clone: function ()
		{
			return new UINT64(this._a48, this._a32, this._a16, this._a00);
		}
	};

	UINT64.prototype.mod = UINT64.prototype.modulo;
	UINT64.prototype.eq = UINT64.prototype.equals;
	UINT64.prototype.greaterThan = UINT64.prototype.gt;
	UINT64.prototype.lessThan = UINT64.prototype.lt;
	UINT64.prototype.compare = UINT64.prototype.compareTo;
	UINT64.prototype.shiftRight = UINT64.prototype.shiftr;
	UINT64.prototype.shiftLeft = UINT64.prototype.shiftl;
	UINT64.prototype.rotateLeft = UINT64.prototype.rotl;
	UINT64.prototype.rotateRight = UINT64.prototype.rotr;


	UINT64.fromBits = function(a48, a32, a16, a00)
	{
		if (typeof a16 == 'undefined') {
			return new UINT64(a48 >>> 16, a48 & 0xFFFF, a32 >>> 16, a32 & 0xFFFF);
		}

		return new UINT64(a48, a32, a16, a00);
	};


	UINT64.valueOf =
	UINT64.fromNumber = function(value)
	{
		return new UINT64(0, 0, value >>> 16, value & 0xFFFF);
	};



	UINT64.fromString = function(s, radix)
	{
		radix = radix || 10;

		var i64 = new UINT64();

		/*
			In Javascript, bitwise operators only operate on the first 32 bits 
			of a number, even though parseInt() encodes numbers with a 53 bits 
			mantissa.
			Therefore UINT64(<Number>) can only work on 32 bits.
			The radix maximum value is 36 (as per ECMA specs) (26 letters + 10 digits)
			maximum input value is m = 32bits as 1 = 2^32 - 1
			So the maximum substring length n is:
			36^(n+1) - 1 = 2^32 - 1
			36^(n+1) = 2^32
			(n+1)ln(36) = 32ln(2)
			n = 32ln(2)/ln(36) - 1
			n = 5.189644915687692
			n = 5
		 */
		var radixUint = UINT64.valueOf(Math.pow(radix, 5));

		for (var i = 0, len = s.length; i < len; i += 5) {
			var size = Math.min(5, len - i);
			var value = parseInt(s.slice(i, i + size), radix);
			i64.multiply(
				size < 5
					? UINT64.valueOf(Math.pow(radix, size))
					: radixUint
			)
			.add(UINT64.valueOf(value));
		}

		return i64;
	};


	if ("undefined" !== typeof exports) { // Node Support
		if (("undefined" !== typeof module) && module.exports) {
			module.exports = exports = UINT64;
		} else {
			exports = UINT64;
		}
	} else { // Browsers and Web Workers
		if (window && !window.UINT64) window.UINT64 = UINT64;
	}

	return UINT64;
})();

// module.exports = UINT64;