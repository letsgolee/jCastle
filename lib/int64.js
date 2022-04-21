/*
 * Copyright 2015-2021 jacob lee. All Rights Reserved.
 * The license is the same with the original.
 * the names and orders of lowBits and highBits are changed for my own purpose.
 *
 * Copyright 2009 The Closure Library Authors. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS-IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @fileoverview Defines a Long class for representing a 64-bit two's-complement
 * integer value, which faithfully simulates the behavior of a Java "long". This
 * implementation is derived from LongLib in GWT.
 *
 */

//goog.provide('goog.math.Long');

const INT64 = (function() {

	function INT64(msint, lsint)
	{
		this.lsint = lsint | 0;  // force into 32 signed bits.
		this.msint = msint | 0;  // force into 32 signed bits.

		if (typeof lsint == 'undefined') {
			this.msint = 0;
			this.lsint = msint | 0;
		}
	};

	INT64.prototype = {

		toBytes: function()
		{
			var b0 = (this.msint >>> 24) & 0xFF;
			var b1 = (this.msint >>> 16) & 0xFF;
			var b2 = (this.msint >>> 8) & 0xFF;
			var b3 = (this.msint >>> 0) & 0xFF;
			var b4 = (this.lsint >>> 24) & 0xFF;
			var b5 = (this.lsint >>> 16) & 0xFF;
			var b6 = (this.lsint >>> 8) & 0xFF;
			var b7 = (this.lsint >>> 0) & 0xFF;
			
			return [b0, b1, b2, b3, b4, b5, b6, b7];
		},

		clone: function()
		{
			return INT64.fromBits(this.msint, this.lsint);
		},

		toInt: function()
		{
			return this.lsint;
		},

		toNumber: function()
		{
			return this.msint * INT64.TWO_PWR_32_DBL +
				 this.getLowBitsUnsigned();
		},

		toString: function(opt_radix)
		{
			var radix = opt_radix || 10;
			if (radix < 2 || 36 < radix) {
				throw Error('radix out of range: ' + radix);
			}

			if (this.isZero()) {
				return '0';
			}

			if (this.isNegative()) {
				if (this.equals(INT64.MIN_VALUE)) {
					// We need to change the Long value before it can be negated, so we remove
					// the bottom-most digit in this base and then recurse to do the rest.
					var radixLong = INT64.fromNumber(radix);
					var div = this.div(radixLong);
					var rem = div.multiply(radixLong).subtract(this);
					return div.toString(radix) + rem.toInt().toString(radix);
				} else {
					return '-' + this.negate().toString(radix);
				}
			}

			// Do several (6) digits each time through the loop, so as to
			// minimize the calls to the very expensive emulated div.
			var radixToPower = INT64.fromNumber(Math.pow(radix, 6));

			var rem = this;
			var result = '';
			while (true) {
				var remDiv = rem.div(radixToPower);
				var intval = rem.subtract(remDiv.multiply(radixToPower)).toInt();
				var digits = intval.toString(radix);

				rem = remDiv;
				if (rem.isZero()) {
					return digits + result;
				} else {
					while (digits.length < 6) {
						digits = '0' + digits;
					}
					result = '' + digits + result;
				}
			}
		},

		getHighBits: function()
		{
			return this.msint;
		},

		getLowBits: function()
		{
			return this.lsint;
		},

		getLowBitsUnsigned: function()
		{
			return (this.lsint >= 0) ?
				this.lsint : INT64.TWO_PWR_32_DBL + this.lsint;
		},

		getNumBitsAbs: function()
		{
			if (this.isNegative()) {
				if (this.equals(INT64.MIN_VALUE)) {
					return 64;
				} else {
					return this.negate().getNumBitsAbs();
				}
			} else {
				var val = this.msint != 0 ? this.msint : this.lsint;
				for (var bit = 31; bit > 0; bit--) {
					if ((val & (1 << bit)) != 0) {
						break;
					}
				}
				return this.msint != 0 ? bit + 33 : bit + 1;
			}
		},


		isZero: function()
		{
			return this.msint == 0 && this.lsint == 0;
		},


		isNegative: function()
		{
			return this.msint < 0;
		},


		isOdd: function()
		{
			return (this.lsint & 1) == 1;
		},

		equals: function(other)
		{
			if (!(other instanceof INT64)) {
				other = INT64.valueOf(other);
			}

			return (this.msint == other.msint) && (this.lsint == other.lsint);
		},

		notEquals: function(other)
		{
			if (!(other instanceof INT64)) {
				other = INT64.valueOf(other);
			}

			return (this.msint != other.msint) || (this.lsint != other.lsint);
		},

		lessThan: function(other)
		{
			return this.compare(other) < 0;
		},

		lessThanOrEqual: function(other)
		{
			return this.compare(other) <= 0;
		},

		greaterThan: function(other)
		{
			return this.compare(other) > 0;
		},

		greaterThanOrEqual: function(other)
		{
			return this.compare(other) >= 0;
		},

		compareTo: function(other)
		{
			if (!(other instanceof INT64)) {
				other = INT64.valueOf(other);
			}

			if (this.equals(other)) {
				return 0;
			}

			var thisNeg = this.isNegative();
			var otherNeg = other.isNegative();
			if (thisNeg && !otherNeg) {
				return -1;
			}
			if (!thisNeg && otherNeg) {
				return 1;
			}

			// at this point, the signs are the same, so subtraction will not overflow
			if (this.subtract(other).isNegative()) {
				return -1;
			} else {
				return 1;
			}
		},

		negate: function()
		{
			if (this.equals(INT64.MIN_VALUE)) {
				return INT64.MIN_VALUE;
			} else {
				return this.not().add(INT64.ONE);
			}
		},


		add: function(other)
		{
			if (!(other instanceof INT64)) {
				other = INT64.valueOf(other);
			}
		/*
			// Divide each number into 4 chunks of 16 bits, and then sum the chunks.

			var a48 = this.msint >>> 16;
			var a32 = this.msint & 0xFFFF;
			var a16 = this.lsint >>> 16;
			var a00 = this.lsint & 0xFFFF;

			var b48 = other.msint >>> 16;
			var b32 = other.msint & 0xFFFF;
			var b16 = other.lsint >>> 16;
			var b00 = other.lsint & 0xFFFF;

			var c48 = 0, c32 = 0, c16 = 0, c00 = 0;
			c00 += a00 + b00;
			c16 += c00 >>> 16;
			c00 &= 0xFFFF;
			c16 += a16 + b16;
			c32 += c16 >>> 16;
			c16 &= 0xFFFF;
			c32 += a32 + b32;
			c48 += c32 >>> 16;
			c32 &= 0xFFFF;
			c48 += a48 + b48;
			c48 &= 0xFFFF;

			return INT64.fromBits((c48 << 16) | c32, (c16 << 16) | c00);
		*/
			var lsw = (this.lsint & 0xFFFF) + (other.lsint & 0xFFFF);
			var msw = (this.lsint >>> 16) + (other.lsint >>> 16) + (lsw >>> 16);
			var lsint = ((msw & 0xFFFF) << 16) | (lsw & 0xFFFF);

			lsw = (this.msint & 0xFFFF) + (other.msint & 0xFFFF) + (msw >>> 16);
			msw = (this.msint >>> 16) + (other.msint >>> 16) + (lsw >>> 16);
			var msint = ((msw & 0xFFFF) << 16) | (lsw & 0xFFFF);

			return new INT64(msint, lsint);
		},

		subtract: function(other)
		{
			if (!(other instanceof INT64)) {
				other = INT64.valueOf(other);
			}

			return this.add(other.negate());
		},


		multiply: function(other)
		{
			if (!(other instanceof INT64)) {
				other = INT64.valueOf(other);
			}

			if (this.isZero()) {
				return INT64.ZERO;
			} else if (other.isZero()) {
				return INT64.ZERO;
			}

			if (this.equals(INT64.MIN_VALUE)) {
				return other.isOdd() ? INT64.MIN_VALUE : INT64.ZERO;
			} else if (other.equals(INT64.MIN_VALUE)) {
				return this.isOdd() ? INT64.MIN_VALUE : INT64.ZERO;
			}

			if (this.isNegative()) {
				if (other.isNegative()) {
					return this.negate().multiply(other.negate());
				} else {
					return this.negate().multiply(other).negate();
				}
			} else if (other.isNegative()) {
				return this.multiply(other.negate()).negate();
			}

			// If both longs are small, use float multiplication
			if (this.lessThan(INT64.TWO_PWR_24_) &&
				other.lessThan(INT64.TWO_PWR_24_)
			) {
				return INT64.fromNumber(this.toNumber() * other.toNumber());
			}

			// Divide each long into 4 chunks of 16 bits, and then add up 4x4 products.
			// We can skip products that would overflow.

			var a48 = this.msint >>> 16;
			var a32 = this.msint & 0xFFFF;
			var a16 = this.lsint >>> 16;
			var a00 = this.lsint & 0xFFFF;

			var b48 = other.msint >>> 16;
			var b32 = other.msint & 0xFFFF;
			var b16 = other.lsint >>> 16;
			var b00 = other.lsint & 0xFFFF;

			var c48 = 0, c32 = 0, c16 = 0, c00 = 0;
			c00 += a00 * b00;
			c16 += c00 >>> 16;
			c00 &= 0xFFFF;
			c16 += a16 * b00;
			c32 += c16 >>> 16;
			c16 &= 0xFFFF;
			c16 += a00 * b16;
			c32 += c16 >>> 16;
			c16 &= 0xFFFF;
			c32 += a32 * b00;
			c48 += c32 >>> 16;
			c32 &= 0xFFFF;
			c32 += a16 * b16;
			c48 += c32 >>> 16;
			c32 &= 0xFFFF;
			c32 += a00 * b32;
			c48 += c32 >>> 16;
			c32 &= 0xFFFF;
			c48 += a48 * b00 + a32 * b16 + a16 * b32 + a00 * b48;
			c48 &= 0xFFFF;

			return INT64.fromBits((c48 << 16) | c32, (c16 << 16) | c00);
		},


		div: function(other)
		{
			if (!(other instanceof INT64)) {
				other = INT64.valueOf(other);
			}

			if (other.isZero()) {
				throw Error('division by zero');
			} else if (this.isZero()) {
				return INT64.ZERO;
			}

			if (this.equals(INT64.MIN_VALUE)) {
				if (other.equals(INT64.ONE) ||
					other.equals(INT64.NEG_ONE)
				) {
					return INT64.MIN_VALUE;  // recall that -MIN_VALUE == MIN_VALUE
				} else if (other.equals(INT64.MIN_VALUE)) {
					return INT64.ONE;
				} else {
					// At this point, we have |other| >= 2, so |this/other| < |MIN_VALUE|.
					var halfThis = this.shiftRight(1);
					var approx = halfThis.div(other).shiftLeft(1);
					if (approx.equals(INT64.ZERO)) {
						return other.isNegative() ? INT64.ONE : INT64.NEG_ONE;
					} else {
						var rem = this.subtract(other.multiply(approx));
						var result = approx.add(rem.div(other));
						return result;
					}
				}
			} else if (other.equals(INT64.MIN_VALUE)) {
				return INT64.ZERO;
			}

			if (this.isNegative()) {
				if (other.isNegative()) {
					return this.negate().div(other.negate());
				} else {
					return this.negate().div(other).negate();
				}
			} else if (other.isNegative()) {
				return this.div(other.negate()).negate();
			}

			// Repeat the following until the remainder is less than other:  find a
			// floating-point that approximates remainder / other *from below*, add this
			// into the result, and subtract it from the remainder.  It is critical that
			// the approximate value is less than or equal to the real value so that the
			// remainder never becomes negative.
			var res = INT64.ZERO;
			var rem = this.clone();
			while (rem.greaterThanOrEqual(other)) {
				// Approximate the result of division. This may be a little greater or
				// smaller than the actual value.
				var approx = Math.max(1, Math.floor(rem.toNumber() / other.toNumber()));

				// We will tweak the approximate result by changing it in the 48-th digit or
				// the smallest non-fractional digit, whichever is larger.
				var log2 = Math.ceil(Math.log(approx) / Math.LN2);
				var delta = (log2 <= 48) ? 1 : Math.pow(2, log2 - 48);

				// Decrease the approximation until it is smaller than the remainder.  Note
				// that if it is too large, the product overflows and is negative.
				var approxRes = INT64.fromNumber(approx);
				var approxRem = approxRes.multiply(other);
				while (approxRem.isNegative() || approxRem.greaterThan(rem)) {
					approx -= delta;
					approxRes = INT64.fromNumber(approx);
					approxRem = approxRes.multiply(other);
				}

				// We know the answer can't be zero... and actually, zero would cause
				// infinite recursion since we would make no progress.
				if (approxRes.isZero()) {
					approxRes = INT64.ONE;
				}

				res = res.add(approxRes);
				rem = rem.subtract(approxRem);
			}

			return res;
		},


		modulo: function(other)
		{
			if (!(other instanceof INT64)) {
				other = INT64.valueOf(other);
			}

			return this.subtract(this.div(other).multiply(other));
		},


		not: function()
		{
			return INT64.fromBits(~this.msint, ~this.lsint);
		},


		and: function(other)
		{
			if (!(other instanceof INT64)) {
				other = INT64.valueOf(other);
			}

			return INT64.fromBits(
				this.msint & other.msint, 
				this.lsint & other.lsint
			);
		},


		or: function(other)
		{
			if (!(other instanceof INT64)) {
				other = INT64.valueOf(other);
			}

			return INT64.fromBits(
				this.msint | other.msint,
				this.lsint | other.lsint
			);
		},

		xor: function(other)
		{
			if (!(other instanceof INT64)) {
				other = INT64.valueOf(other);
			}

			return INT64.fromBits(
				this.msint ^ other.msint,
				this.lsint ^ other.lsint
			);
		},

		shiftLeft: function(numBits)
		{
		/*
			numBits &= 63;
			if (numBits == 0) {
				return this;
			} else {
				var lsint = this.lsint;
				if (numBits < 32) {
					var msint = this.msint;

					return INT64.fromBits(
						(msint << numBits) | (lsint >>> (32 - numBits)),
						lsint << numBits
					);
				} else {
					return INT64.fromBits(lsint << (numBits - 32), 0);
				}
			}
		*/
			numBits &= 63;
			if (numBits == 0) {
				return this.clone();
			}

			if (numBits < 32) {
				return new INT64(
					this.msint << numBits | this.lsint >>> (32 - numBits),
					this.lsint << numBits
				);
			} else if (numBits === 32) {
				return new INT64(this.lsint, 0);
			} else {
				return this.shiftLeft(32).shiftLeft(numBits - 32);
			}
		},


		shiftRight: function(numBits)
		{
			numBits &= 63;
			if (numBits == 0) {
				return this.clone();
			} else {
				var msint = this.msint;
				if (numBits < 32) {
					var lsint = this.lsint;

					return INT64.fromBits(
						msint >> numBits,
						(lsint >>> numBits) | (msint << (32 - numBits))
					);
				} else {
					return INT64.fromBits(
						msint >= 0 ? 0 : -1,
						msint >> (numBits - 32)
					);
				}
			}
		},


		shiftRightUnsigned: function(numBits)
		{
			numBits &= 63;
			if (numBits == 0) {
				return this.clone();
			}
			
			var msint = this.msint;
			if (numBits < 32) {
				var lsint = this.lsint;

				return INT64.fromBits(
					msint >>> numBits,
					(lsint >>> numBits | (msint << (32 - numBits)))
				);
			} else if (numBits == 32) {
				return INT64.fromBits(0, msint);
			} else {
				return INT64.fromBits(0, msint >>> (numBits - 32));
			}
		},


		rotr: function(numBits)
		{
			if (numBits < 32) {
				return new INT64(
					(this.msint >>> numBits) | (this.lsint << (32 - numBits)),
					(this.lsint >>> numBits) | (this.msint << (32 - numBits))
				);
			} else if (numBits === 32) { // Apparently in JS, shifting a 32-bit value by 32 yields original value
				return new INT64(this.lsint, this.msint);
			} else {
				return this.rotr(32).rotr(numBits - 32);
			}
		},


		rotl: function(numBits)
		{
			if (numBits < 32) {
				return new INT64(
					(this.msint << numBits) | (this.lsint >>> (32 - numBits)),
					(this.lsint << numBits) | (this.msint >>> (32 - numBits))
				);
			} else if (numBits === 32) { // Apparently in JS, shifting a 32-bit value by 32 yields original value
				return new INT64(this.lsint, this.msint);
			} else {
				return this.rotl(32).rotl(numBits - 32);
			}
		}

	};

	INT64.prototype.lt = INT64.prototype.lessThan;
	INT64.prototype.lte = INT64.prototype.lessThanOrEqual;
	INT64.prototype.gt =  INT64.prototype.greaterThan;
	INT64.prototype.gte = INT64.prototype.greaterThanOrEqual;
	INT64.prototype.compare = INT64.prototype.compareTo;
	INT64.prototype.mod = INT64.prototype.modulo;
	INT64.prototype.shl = INT64.prototype.shiftLeft;
	INT64.prototype.shr = INT64.prototype.shiftRight;
	INT64.prototype.rotateRight = INT64.prototype.rotr;
	INT64.prototype.rotateLeft = INT64.prototype.rotl;


	INT64.fromBytes = function(b0, b1, b2, b3, b4, b5, b6, b7)
	{
		if (Object.prototype.toString.call(b0) === '[object Array]') {
			var a = b0;
		} else  {
			var a = [b0, b1, b2, b3, b4, b5, b6, b7];
		}

		return new INT64(
			((a[0] & 0xFF) << 24) | ((a[1] & 0xFF) << 16) | ((a[2] & 0xFF) << 8) | (a[3] & 0xFF),
			((a[4] & 0xFF) << 24) | ((a[5] & 0xFF) << 16) | ((a[6] & 0xFF) << 8) | (a[7] & 0xFF)
		);
	};


	INT64.valueOf =
	INT64.fromInt = function(value)
	{
		return new INT64(value < 0 ? -1 : 0, value | 0);
	};


	INT64.fromNumber = function(value)
	{
		if (isNaN(value) || !isFinite(value)) {
			return INT64.ZERO;
		} else if (value <= -INT64.TWO_PWR_63_DBL) {
			return INT64.MIN_VALUE;
		} else if (value + 1 >= INT64.TWO_PWR_63_DBL) {
			return INT64.MAX_VALUE;
		} else if (value < 0) {
			return INT64.fromNumber(-value).negate();
		} else {
			return new INT64(
				(value / INT64.TWO_PWR_32_DBL) | 0,
				(value % INT64.TWO_PWR_32_DBL) | 0
			);
		}
	};


	INT64.fromBits = function(highBits, lowBits)
	{
		return new INT64(highBits, lowBits);
	};


	INT64.fromString = function(str, opt_radix)
	{
		if (str.length == 0) {
			throw Error('number format error: empty string');
		}

		var radix = opt_radix || 10;
		if (radix < 2 || 36 < radix) {
			throw Error('radix out of range: ' + radix);
		}

		if (str.charAt(0) == '-') {
			return INT64.fromString(str.substring(1), radix).negate();
		} else if (str.indexOf('-') >= 0) {
			throw Error('number format error: interior "-" character: ' + str);
		}

		// Do several (8) digits each time through the loop, so as to
		// minimize the calls to the very expensive emulated div.
		var radixToPower = INT64.fromNumber(Math.pow(radix, 8));

		var result = INT64.ZERO;
		for (var i = 0; i < str.length; i += 8) {
			var size = Math.min(8, str.length - i);
			var value = parseInt(str.substring(i, i + size), radix);
			if (size < 8) {
				var power = INT64.fromNumber(Math.pow(radix, size));
				result = result.multiply(power).add(INT64.fromNumber(value));
			} else {
				result = result.multiply(radixToPower);
				result = result.add(INT64.fromNumber(value));
			}
		}
		return result;
	};


	/**
	 * Number used repeated below in calculations.  This must appear before the
	 * first call to any from* function below.
	 * @type {number}
	 * @private
	 */
	INT64.TWO_PWR_16_DBL = 1 << 16;


	/**
	 * @type {number}
	 * @private
	 */
	INT64.TWO_PWR_24_DBL = 1 << 24;


	/**
	 * @type {number}
	 * @private
	 */
	INT64.TWO_PWR_32_DBL =
		INT64.TWO_PWR_16_DBL * INT64.TWO_PWR_16_DBL;


	/**
	 * @type {number}
	 * @private
	 */
	INT64.TWO_PWR_31_DBL =
		INT64.TWO_PWR_32_DBL / 2;


	/**
	 * @type {number}
	 * @private
	 */
	INT64.TWO_PWR_48_DBL =
		INT64.TWO_PWR_32_DBL * INT64.TWO_PWR_16_DBL;


	/**
	 * @type {number}
	 * @private
	 */
	INT64.TWO_PWR_64_DBL =
		INT64.TWO_PWR_32_DBL * INT64.TWO_PWR_32_DBL;


	/**
	 * @type {number}
	 * @private
	 */
	INT64.TWO_PWR_63_DBL =
		INT64.TWO_PWR_64_DBL / 2;


	/** @type {!INT64} */
	INT64.ZERO = INT64.fromInt(0);


	/** @type {!INT64} */
	INT64.ONE = INT64.fromInt(1);


	/** @type {!INT64} */
	INT64.NEG_ONE = INT64.fromInt(-1);


	/** @type {!INT64} */
	INT64.MAX_VALUE =
		INT64.fromBits(0x7FFFFFFF | 0, 0xFFFFFFFF | 0);


	/** @type {!INT64} */
	INT64.MIN_VALUE = INT64.fromBits(0x80000000 | 0, 0);


	/**
	 * @type {!INT64}
	 * @private
	 */
	INT64.TWO_PWR_24_ = INT64.fromInt(1 << 24);


	if ("undefined" !== typeof exports) { // Node Support
		if (("undefined" !== typeof module) && module.exports) {
			module.exports = exports = INT64;
		} else {
			exports = INT64;
		}
	} else { // Browsers and Web Workers
		if (window && !window.INT64) window.INT64 = INT64;
	}

	return INT64;
})();

// module.exports = INT64;