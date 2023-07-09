/**
* BigInt Extention Library
* 
* @author Jacob Lee
* 
* This program is free software; you can redistribute it and/or
* modify it under the terms of the GNU General Public License as
* published by the Free Software Foundation; either version 2 of the
* License, or (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	See the GNU
* General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
* 02111-1307 USA or check at http://www.gnu.org/licenses/gpl.html
*/
(function() {

	//const MAX_INT = 9007199254740992;

	function isSafeInt(n) {
        return Number.MIN_SAFE_INTEGER < n && n < Number.MAX_SAFE_INTEGER;
    }

	// hex to bigInt. usefull when hex is negative number
	// https://coolaj86.com/articles/convert-hex-to-decimal-with-js-bigints/
	function hexToBn(hex) {
		if (hex.length % 2) {
			hex = '0' + hex;
		}

		let highbyte = parseInt(hex.slice(0, 2), 16);
		let bn = BigInt('0x' + hex);

		if (0x80 & highbyte) {
			// bn = ~bn; WRONG in JS (would work in other languages)

			// manually perform two's compliment (flip bits, add one)
			// (because JS binary operators are incorrect for negatives)
			bn = BigInt('0b' + bn.toString(2).split('').map(function (i) {
				return '0' === i ? 1 : 0
			}).join('')) + BigInt(1);
			// add the sign character to output string (bytes are unaffected)
			bn = -bn;
		}

		return bn;
	}


	// https://coolaj86.com/articles/convert-decimal-to-hex-with-js-bigints/
	function bnToHex(bn) {
		bn = BigInt(bn);

		let pos = true;
		if (bn < 0) {
			pos = false;
			bn = bitnot(bn);
		}

		let hex = bn.toString(16);
		if (hex.length % 2) { hex = '0' + hex; }

		if (pos && (0x80 & parseInt(hex.slice(0, 2), 16))) {
			hex = '00' + hex;
		}

		return hex;
	}

	function bitnot(bn) {
		bn = -bn;
		let bin = (bn).toString(2);
		let prefix = '';
		while (bin.length % 8) { bin = '0' + bin; }
		if ('1' === bin[0] && -1 !== bin.slice(1).indexOf('1')) {
			prefix = '11111111';
		}
		bin = bin.split('').map(function (i) {
			return '0' === i ? '1' : '0';
		}).join('');
		return BigInt('0b' + prefix + bin) + BigInt(1);
	}

	// https://coolaj86.com/articles/convert-js-bigints-to-typedarrays/
	function bnToBuf(bn) {
		let hex = BigInt(bn).toString(16);
		if (hex.length % 2) { hex = '0' + hex; }

		let len = hex.length / 2;
		//let u8 = new Uint8Array(len);
		let u8 = Buffer.alloc(len);

		let i = 0;
		let j = 0;
		while (i < len) {
			u8[i] = parseInt(hex.slice(j, j+2), 16);
			i += 1;
			j += 2;
		}

		if (bn > 0n && u8[0] & 0x80) {
			//let t = new Uint8Array(len + 1);
			let t = Buffer.alloc(len + 1);
			t.set([0x00]);
			t.set(u8, 1);
			return t;
		}

		return u8;
	}

	function bufToBn(buf, unsigned=true) {
		let hex = [];
		u8 = Uint8Array.from(buf);

		u8.forEach(function (i) {
			let h = i.toString(16);
			if (h.length % 2) { h = '0' + h; }
			hex.push(h);
		});

		// always positive number.
		if (unsigned) {
			hex.unshift('00');
		}

		return BigInt('0x' + hex.join(''));
	}


	// https://coolaj86.com/articles/bigints-and-base64-in-javascript/
	function b64ToBn(b64) {
		let bin = atob(b64);
		let hex = [];

		bin.split('').forEach(function (ch) {
			let h = ch.charCodeAt(0).toString(16);
			if (h.length % 2) { h = '0' + h; }
			hex.push(h);
		});

		return BigInt('0x' + hex.join(''));
	}

	// ASCII (base64) to Binary string
	function atob(b64) {
		return Buffer.from(b64, 'base64').toString('binary');
	}

	function bnToB64(bn) {
		let hex = BigInt(bn).toString(16);
		if (hex.length % 2) { hex = '0' + hex; }

		let bin = [];
		let i = 0;
		let d;
		let b;
		while (i < hex.length) {
			d = parseInt(hex.slice(i, i + 2), 16);
			b = String.fromCharCode(d);
			bin.push(b);
			i += 2;
		}

		return btoa(bin.join(''));
	}

	function base64ToUrlBase64(str) {
		return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
	}

	function urlBase64ToBase64(str) {
		let r = str % 4;
		if (2 === r) {
			str += '==';
		} else if (3 === r) {
			str += '=';
		}
		return str.replace(/-/g, '+').replace(/_/g, '/');
	}

	function randBufArr(len) {
		const chars = "0123456789abcdef";
		let hex = '', c1, c2;
		for (var i = 0; i < len; i++) {
			// Generate two random integers from 0 to 15
			c1 = chars[Math.floor(Math.random() * 16)];
			c2 = chars[Math.floor(Math.random() * 16)];

			// Append the characters to the string
			hex += c1 + c2;
		}
		return Buffer.from(hex, 'hex');
	}

	///////////////////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////////////////

	// BigInt.PLUS_MAXINT = BigInt("9007199254740991"); // pow(2, 53)
	// BigInt.MINUS_MAXINT = BigInt("-9007199254740992");
	
	BigInt.fromBuffer = function(buf) {
		return bufToBn(buf);
	};

	BigInt.fromBufferUnsigned = function(buf) {
		// BigInt expects a DER integer conformant byte array
		if (buf[0] & 0x80) {
			return bufToBn(Buffer.concat([Buffer.alloc(1, 0x00), buf]));
		}
		return bufToBn(buf);
	};

	BigInt.fromHexSigned = function(hex) {
		return hexToBn(hex);
	};

	BigInt.max = function(...values) {
        if (values.length === 0) {
            return null;
        }

        if (values.length === 1) {
            return values[0];
        }

        let x = values[0];
        for (let i = 1; i < values.length; i++) {
            if (values[i] > x) {
                x = values[i];
            }
        }
        return x;
    };

    BigInt.min = function(...values) {
        if (values.length === 0) {
            return null;
        }

        if (values.length === 1) {
            return values[0];
        }

        let x = values[0];
        for (let i = 1; i < values.length; i++) {
            if (values[i] < x) {
                x = values[i];
            }
        }
        return x;
    };

	// extended Euclid.
	// returns an object {gcd, x, y} such that ax + by = gcd.
	BigInt.extendedEuclid = function(a, b) {
		var x = 0n;
		var last_x = 1n;
		var y = 1n;
		var last_y = 0n;

		while (b != 0n) {
			var quotientAndRemainder = a.divideAndRemainder(b);
			var quotient = quotientAndRemainder.quotient;

			var temp = a;
			a = b;
			b = quotientAndRemainder.remainder;

			temp = x;
			x = last_x - (quotient * x);
			last_x = temp;

			temp = y;
			y = last_y - (quotient * y);
			last_y = temp;
		}

		var result = {
			x: last_x,
			y: last_y,
			gcd: a
		};

		return result;		
	};

	BigInt.eGcd = BigInt.extendedEuclid;


	BigInt.gcd = function(a, b) {
		if (a < 0n) a = -a;
		if (b < 0n) b = -b;

		return b === 0 ? a : BigInt.gcd(b, a % b);
	};

/*
	BigInt.gcd = function (a, b) {
		a = a.abs();
		b = b.abs();
		
		if (b > a) {var temp = a; a = b; b = temp;}
		while (true) {
			if (b == 0) return a;
			a %= b;
			if (a == 0) return b;
			b %= a;
		}
	};
*/
	BigInt.is = function(x) {
		return typeof x === "bigint";
	};

	BigInt.lucasLehmerSequence = function(d, k, n) { // int z, BigInt k, BigInt n
		var u = 1n, u2;
		var v = 1n, v2;

		for (var i = k.bitLength() - 2; i >= 0; i--) {
			u2 = (u * v) % n;

			v2 = (v.square() + (d * u.square())) % n;
			if (v2.testBit(0)) {
				v2 = n - v2;
				v2 = -v2;
			}
			v2 = v2 >> 1n;

			u = u2; v = v2;
			if (k.testBit(i)) {
				u2 = (u + v) % n;
				if (u2.testBit(0)) {
					u2 = n - u2;
					u2 = -u2;
				}
				u2 = u2 >> 1n;

				v2 = (v + d * u) % n;
				if (v2.testBit(0)) {
					v2 = n - v2;
					v2 = -v2;
				}
				v2 = v2 >> 1n;

				u = u2; v = v2;
			}
		}
		return u;
	};

	BigInt._jacobiTable = [0, 1, 0, -1, 0, -1, 0, 1];

	// rng.nextBytes() should return buffer array
	BigInt.random = function(bit, rng, rand_bits=false) {
		var x, t = bit & 7;
		var len = (bit >>> 3);
		if (t) len++;

		// example:
        // if bit = 62, then t = 6.
        // two things should be done for making 62 bits length integer:
        //     x[0] & 0011 1111  -> this will remove upper bits. 0011 1111 = 0100 0000 - 1
        //     x[0] | 0010 0000  -> force 1 to the 5th. 
		x = rng && typeof rng.nextBytes === 'function' ? rng.nextBytes(len) : randBufArr(len);

		// return a random number with the exact bitlength.
		// if rand_bits is true, then it allows 00 byte at first.
		if (!rand_bits || x[0] != 0x00) {
			if (t > 0) {
				x[0] &= ((1 << t) - 1);
				x[0] |= 1 << (t - 1);
			}
			else x[0] |= 0x80;
		}

		// for safty reason to get a positive integer, add zero at first position.
		return BigInt.fromBufferUnsigned(x);
	};

	BigInt.randomInRange = function(a, b, rng) {
		var min = a, max = b;

		// min and max is same
		if (min == max) return min;

		if (max < min) {
			var t = min;
			min = max;
			max = t;
		}

		var min_bits = Math.floor(min.bitLength() + 7 / 8);
		var max_bits = Math.floor(max.bitLength() + 7 / 8);
		var range = max - min;
		var bits = Math.floor(Math.random() * (max_bits - min_bits + 1)) + min_bits;
		var r = BigInt.random(bits, rng, true);
		if (r > range) r = r % range;	

		return min + r;
	};

	BigInt.probablePrime = function(bit, rng, repeat=1, use_lucasLehmerCheck=false) {
		// $repeat is repeat times for accuracy of the test
		// http://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test

		var x = BigInt.random(bit, rng);

		// if (!x.testBit(bit - 1)) { // force MSB set
		// 	//x |= 1n << BigInt(bit - 1);
		// 	x = x.setBit(bit - 1);
		// }

		if (x.isEven()) x += 1n; // force odd
		while (!x.isProbablePrime(repeat) || (use_lucasLehmerCheck && !x.isLucasLehmerPrime())) {
			x += 2n;
			if (x.bitLength() > bit) x -= 1n << BigInt(bit -1);
		}
		return x;
	};

	BigInt.probablePrimeInRange = function(a, b, rng, repeat=1, use_lucasLehmerCheck=false)
	{
		var min = a, max = b;

		// min and max is same
		if (min == max) {
			if (min.isProbablePrime(repeat)) return min;
			else return null;
		}

		if (max < min) {
			var t = min;
			min = max;
			max = t;
		}

		var x, bit;
		for (x = BigInt.randomInRange(min, max, rng);;) {
			bit = x.bitLength();
			if (!x.testBit(bit - 1))	// force MSB set
				x = x.setBit(bit - 1);
			if (x.isEven()) x += 1n; // force odd
			while (!x.isProbablePrime(repeat) || (use_lucasLehmerCheck && !x.isLucasLehmerPrime())) {
				x += 2n;
				if (x.bitLength() > bit) x -= 1n << (bit - 1);
			}
			if (x <= max && x >= min) return x;
		}
	};

	Object.assign(BigInt.prototype, {
		
		intValue: function() {
			return Number(this);
		},

		toHex: function() {
			return bnToHex(this);
		},

		toBuffer: function() {
			return bnToBuf(this);
		},

		toBufferUnsigned: function() {
			var r = bnToBuf(this);
			return (r[0] == 0) ? r.slice(1) : r;
		},

		clone: function() {
			return BigInt(this);	
		},

		negate: function() {
			return -this;
		},

		compareTo: function(a) {
			var r = this - a;

			return r > 0 ? 1 : (r < 0 ? -1 : 0);
		},

		toJSON: function() {
			return this.toString();
		},

		add: function(a) {
			return this + a;
		},

		subtract: function(a) {
			return this - a;
		},

		multiply: function(a) {
			return this * a;
		},

		divide: function(a) {
			return this / a;
		},

		mod: function(a) {
			// return this % a;
			var r = this.abs() % a;
			if (this < 0n && r > 0n) r = a - r;
			if (r < 0n) r = r + a;
			return r;
		},

		pow: function(a) {
			return this ** BigInt(a);
		},

		isPowerOf2: function() {
			// Exercise for reader: confirm that n is an integer
			return (this !== 0n) && (this & (this - 1n)) === 0n;
		},

		modPow: function(e, n) {
			let r = 1n;
			let b = this;
			e = BigInt(e);
			let inv = e < 0n;
			e = e.abs();

			while (e > 0n) {
				//if ((e % 2n) === 1n) {
				if (e.testBit(0)) {
					r = r * b % n;
				}
				//e = e / 2n;
				e >>= 1n;
				b = b ** 2n % n;
			}
			return inv ? r.modInverse(n) : r;
		},
/*
		//Fast modular exponentiation for base ^ e mod n
		modPow: function(e, n) {
			e = BigInt(e);
			var inverse = e < 0n;
			e = e.abs();
			var result = 1n;
			var x = this % n;
			while (e > 0n) {
				var leastSignificantBit = e % 2n;
				e = e / 2n;
				if (leastSignificantBit == 1n) {
					result = result * x;
					result = result % n;
				}
				x = x * x;
				x = x % n;
			}
			if (inverse) return result.modInverse(n);
			return result;
		},
*/
		signum: function() {
			return this > 0n ? 1 : (this < 0n ? -1 : 0);
		},

		abs: function() {
			return this < 0n ? -this : this;
		},

/*
		// https://stackoverflow.com/questions/53683995/javascript-big-integer-square-root/58863398#58863398
		rootNth: function(k=2n) {
			if (this < 0n) {
				throw 'negative number is not supported'
			}

			let o = 0n;
			let x = this;
			let limit = 100;

			while (x ** k !== k && x !== o && --limit) {
				o = x;
				x = ((k - 1n) * x + this / x ** (k - 1n)) / k;
			}

			return x;
		},

		sqrt: function() {
			return this.rootNth();
		},
*/

		sqrt: function() {
			var r = 0n;
			var o, n;
			var m = this;

			n = m >> BigInt(m.bitLength() / 2);

			do {
				o = n;
				n = (((o ** 2n) + m) / o) / 2n;
			} while ((n - o).abs() > 2n);

			return n;
		},

/*
		sqrt: function() {
			var c, medium;
			var high = this;
			var low = 1n;

			do {
				medium = (high + low) / 2n;
				c = (medium ** 2) == this;
				if (c > 0) high = medium;
				if (c < 0) low = medium;
				if (c == 0)
					return medium;
			} while ((high - low) > 1n);

			if ((high ** 2) == this) {
				return high;
			} else {
				return low;
			}
		},
*/

/*
		gcd: function(b) {
			return BigInt.gcd(this, b);
		},
*/
		
		gcd: function(b) {
			let a = BigInt(this);

			if (a < 0n) a = -a;
			if (b < 0n) b = -b;

			if (a === 0n) {
				return b;
			}
			else if (b === 0n) {
				return a;
			}
			let shift = 0n;
			while (((a | b) & 1n) === 0n) {
				a >>= 1n;
				b >>= 1n;
				shift++;
			}
			while ((a & 1n) === 0n)
				a >>= 1n;
			do {
				while ((b & 1n) === 0n)
					b >>= 1n;
				if (a > b) {
					let x = a;
					a = b;
					b = x;
				}
				b -= a;
			} while (b !== 0n);
			return a << shift;
		},

		// return b.multiply(this).abs().divide(b.gcd(this));
		lcm: function(b) {
			let a = this;
			if (a === 0n && b === 0n)
				return 0n;
			return ((a / a.gcd(b)) * b).abs();
		},

		modInverse: function(m) {
			let ac = m.isEven();
			if ((this.isEven() && ac) || m == 0n) return 0n;
			var u = m, v = this;
			var a = 1n, b = 0n, c = 0n, d = 1n;
			while (u.signum() != 0) {
				while (u.isEven()) {
					u >>= 1n;
					if (ac) {
						if (!a.isEven() || !b.isEven()) { a += this; b -= m; }
						a >>= 1n;
					}
					else if (!b.isEven()) b -= m;
					b >>= 1n;
				}
				while (v.isEven()) {
					v >>= 1n;
					if (ac) {
						if (!c.isEven() || !d.isEven()) { c += this; d -= m; }
						c >>= 1n;
					}
					else if (!d.isEven()) d -= m;
					d >>= 1n;
				}
				if (u >= v) {
					u -= v;
					if (ac) a -= c;
					b -= d;
				}
				else {
					v -= u;
					if (ac) c -= a;
					d -= b;
				}
			}
			if (v != 1n) return 0n; // it gives an error when using '==='.
			if (d >= m) return d - m;
			if (d < 0n) d += m; else return d;
			if (d < 0n) return d + m; else return d;
		},
/*
		modInverse: function(n) {
			if (n <= 0n) {
				throw new RangeError('n must be > 0')
			}
			
			let d = this % n;
			if (d < 0n) d += n;

			let ed = BigInt.eGcd(d, n);

			if (ed.gcd != 1n) throw new Error('modular inverse does not exist');

			let m = ed.x % n;
			return m < 0n ? m + n : m;
		},
*/
		// https://stackoverflow.com/questions/70382306/logarithm-of-a-bigint
		log10: function() {
			const n = this.toString(10).length;
			return this > 0n ? BigInt(n - 1) : null;
		},
/*
		// https://stackoverflow.com/questions/55355184/optimized-integer-logarithm-base2-for-bigint
		log2: function() {
			if (this <= 0n) throw 'negative number is not supported';

			let n = this;
			const C1 = BigInt(1);
			const C2 = BigInt(2);
			for(var count = 0; n > C1; count++)  n = n/C2;
			return count;
		},

		log2_str:= function() { // 2*faster!
			return this.toString(2).length - 1;
		},
*/
		log2: function() {
			let value = this;
			let result = 0n, i, v;
			for (i = 1n; value >> (1n << i); i <<= 1n);
			while (value > 1n) {
				v = 1n << --i;
				if (value >> v) {
					result += v;
					value >>= v;
				}
			}
			return result;
		},

		// https://math.stackexchange.com/questions/1416606/how-to-find-the-amount-of-binary-digits-in-a-decimal-number/1416817#1416817
		bitLength: function() {
			if (this == 0n) {
				return 0;
			}
			let n = this;

			if (n < 0n) {
				n = -n;
				n -= 1n;
			}

			return Number(this.log2() + 1n);
		},

		// testBit
		// https://www.geeksforgeeks.org/biginteger-testbit-method-in-java/
		testBit: function(pos) {
			return (this & (1n << BigInt(pos))) !== 0n;
		},

		// https://www.geeksforgeeks.org/biginteger-setbit-method-in-java/
		setBit: function(pos) {
			return this | (1n << BigInt(pos));
		},

		// https://www.geeksforgeeks.org/biginteger-clearbit-method-in-java/
		clearBit: function(pos) {
			return this & ~(1n << BigInt(pos));
		},

		// https://www.geeksforgeeks.org/biginteger-flipbit-method-in-java/
		flipBit: function(pos) {
			return this ^ (1n << BigInt(pos));
		},

		// https://www.geeksforgeeks.org/biginteger-bitcount-method-in-java/
		bitCount: function() {
			let count = 0;
			let bn = this;
			while (bn) {
				if ((bn & 1n) == 1n) {
					count++;
				}
				bn >>= 1n;
			}
			return count;
		},

		// https://www.geeksforgeeks.org/biginteger-getlowestsetbit-method-in-java/
		getLowestSetBit: function() {
			return this == 0n ? -1n : (this & -this).log2();
		},

		square: function() {
			return this ** 2n;
		},

		shiftLeft: function(n) {
			return this << BigInt(n);
		},

		shiftRight: function(n) {
			return this >> BigInt(n);
		},

		isEven: function() {
			return (this & 1n) === 0n;
		},

		isOdd: function() {
			return !this.isEven();
		},
/*
		modPowInt: function(e, n) {
			return this.modPow(BigInt(e), n);
		},
*/
		nextProbablePrime: function(repeat=1, use_lucasLehmerCheck=false) {
			if (this == 1n || this == 0n) return 2n;

			var x = this + 1n;
			if (x.isEven()) x += 1n;
			while (!x.isProbablePrime(repeat) || (use_lucasLehmerCheck && !x.isLucasLehmerPrime())) {
				x += 2n;
			}
			return x;
		},

		equals: function(a) {
			return this == a;
		},

		notEquals: function(a) {
			return this != a;
		},

		lesser: function(a) {
			return this < a;
		},

		greater: function(a) {
			return this > a;
		},

		lesserOrEquals: function(a) {
			return this <= a;
		},

		greaterOrEquals: function(a) {
			return this >= a;
		},

		min: function(a) {
			return this > a ? a : this;
		},

		max: function(a) {
			return this < a ? a : this;
		},

		and: function(a) {
			return this & a;
		},

		or: function(a) {
			return this | a;
		},

		xor: function(a) {
			return this ^ a;
		},

		// this & ~a
		andNot: function(a) {
			return this & ~a;
		},

		not: function(a) {
			return ~this;
		},

		remainder: function(a) {
			return this % a;
		},

		divideAndRemainder: function(a) {
			return {
				quotient: this / a,
				remainder: this % a
			};
		},

		// (public) this^(BigInt e)
		// http://stackoverflow.com/questions/4582277/biginteger-powbiginteger
		bigPow: function(exp) {
			var base = this;
			var r = 1n;
			while (exp > 0n) {
				if (exp.testBit(0)) r = r * base;
				base = base * base;
				exp >>= 1n;
			}
			return r;
		},

		// (public) test primality with certainty >= 1-.5^t
		isProbablePrime: function(t) {
			var i, x = this.abs();
			if (x.isEven()) return false;
				
			if (x <= BigInt.lowPrimes[BigInt.lowPrimes.length - 1]) {
				for (i = 0; i < BigInt.lowPrimes.length; ++i)
					if (x == BigInt.lowPrimes[i]) return true;
				return false;
			}
				
			i = 1;
			while (i < BigInt.lowPrimes.length) {
				var m = BigInt.lowPrimes[i], j = i + 1;
				while (j < BigInt.lowPrimes.length && m < BigInt.lplim) m *= BigInt.lowPrimes[j++];
				m = x % m;
				while (i < j) if (m % BigInt.lowPrimes[i++] == 0n) return false;
			}
			return x.isMillerRabinPrime(t);
		},

		/*
		Input #1: n > 2, an odd integer to be tested for primality
		Input #2: k, the number of rounds of testing to perform
		Output: “composite” if n is found to be composite, “probably prime” otherwise

		let s > 0 and d odd > 0 such that n − 1 = 2sd  # by factoring out powers of 2 from n − 1
		repeat k times:
			a ← random(2, n − 2)  # n is always a probable prime to base 1 and n − 1
			x ← ad mod n
			repeat s times:
				y ← x2 mod n
				if y = 1 and x ≠ 1 and x ≠ n − 1 then # nontrivial square root of 1 modulo n
					return “composite”
				x ← y
			if y ≠ 1 then
				return “composite”
		return “probably prime”
		*/
		/*
		// (protected) true if probably prime (HAC 4.24, Miller-Rabin)
		isMillerRabinPrime: function(t) {
			var n1 = this - 1n;
			var k = n1.getLowestSetBit();
			if (k <= 0n) return false;
			var r = n1 >> k;
			t = (t + 1) >> 1;
			if (t > BigInt.lowPrimes.length) t = BigInt.lowPrimes.length;
			var a = 0n;
			for (var i = 0; i < t; ++i) {
				//Pick bases at random, instead of starting at 2
				a = BigInt.lowPrimes[Math.floor(Math.random() * BigInt.lowPrimes.length)];
				var y = a.modPow(r, this);
				if (y != 1n && y != n1) {
					var j = 1;
					while (j++ < k && y != n1) {
						y = y.modPow(2n, this);
						if (y == 1n) return false;
					}
					if (y != n1) return false;
				}
			}
			return true;
		},
		*/
		isMillerRabinPrime: function(t) {
			let n = this;
			let s = n - 1n;
			let n1 = n - 1n;

			// base case
			if (n == 0n || n == 1n)
				return false;
			// base case - 2 is prime
			if (n == 2n)
				return true;
			// an even number other than 2 is composite
			//if (n % 2n == 0n)
			if ((n & 1n) == 0n)
				return false;
			
			while (s % 2n == 0n)
				s /= 2n;
	 
			for (let i = 0; i < t; i++) {
				let r = BigInt.lowPrimes[Math.floor(Math.random() * BigInt.lowPrimes.length)];         
				let a = (r % n1) + 1n;
				let temp = s;
				let m = a.modPow(temp, n);
				while (temp != n1 && m != 1n && m != n1) {
					m = (m * m) % n;
					temp *= 2n;
				}
				if (m != n1 && temp % 2n == 0n)
					return false;
			}
			return true;        
		},

		isZero: function() {
			return this == 0n;
		},

		isOne: function() {
			// do not use ===. it will give you error sometimes!!!
			return this == 1n;
		},

		isSquare: function() {
			var a = this.sqrt();
			return this % a == 0n; // (a ** 2) == this;
		},

		/**
		* Returns true if this BigInt is a Lucas-Lehmer probable prime.
		*
		* The following assumptions are made:
		* This BigInt is a positive, odd number.
		*/
		isLucasLehmerPrime: function() {
			var a = this;
			var a1 = a + 1n;

			// Step 1
			var d = 5n;
			while (d.jacobi(a) != -1) {
			// 5, -7, 9, -11, ...
			//		d = (d < 0) ? Math.abs(d) + 2 : -(d + 2);
				d = d < 0n ? (d.abs() + 2n) : -(d + 2n);
			}

			// Step 2
			var u = BigInt.lucasLehmerSequence(d, a1, a);

			// Step 3
			return u.mod(a) == 0n;
		},

		/**
		 * Computes the value of the Jacobi symbol (A|B). The following properties
		 * hold for the Jacobi symbol which makes it a very efficient way to
		 * evaluate the Legendre symbol
		 * 
		 * (A|B) = 0 IF gcd(A,B) > 1
		 * (-1|B) = 1 IF n = 1 (mod 1)
		 * (-1|B) = -1 IF n = 3 (mod 4)
		 * (A|B) (C|B) = (AC|B)
		 * (A|B) (A|C) = (A|CB)
		 * (A|B) = (C|B) IF A = C (mod B)
		 * (2|B) = 1 IF N = 1 OR 7 (mod 8)
		 * (2|B) = 1 IF N = 3 OR 5 (mod 8)
		 *
		 * @param A integer value
		 * @param B integer value
		 * @return value of the jacobi symbol (A|B)
		 */
		jacobi: function(B) {
			var A = this;
			var a, b, v;
			var k = 1;

			// test trivial cases
			if (B == 0n) {
				a = A.abs();
				return a == 1n ? 1 : 0;
			}

			if (!A.testBit(0) && !B.testBit(0)) {
				return 0;
			}

			a = A;
			b = B;

			if (b < 0n) {
				b = -b;
				if (a < 0n) {
					k = -1;
				}
			}

			v = 0;
			while (!b.testBit(0)) {
				// v = v + 1
				v++;
				// b = b/2
				b >>= 1n;
			}

			// if (v % 2 != 0) {
			if (v & 1) {
				k = k * BigInt._jacobiTable[Number(a) & 7];
			}

			if (a < 0n) {
				if (b.testBit(1)) {
					k = -k;
				}
				a = -a;
			}

			// main loop
			while (a != 0n) {
				v = 0;
				while (!a.testBit(0)) { // a is even
					v++;
					a >>= 1n;
				}
				// if (v % 2 != 0) {
				if (v & 1) {
					k = k * BigInt._jacobiTable[Number(b) & 7];
				}

				if (a < b) {
					// swap and correct intermediate result
					var x = a;
					a = b;
					b = x;
					if (a.testBit(1) && b.testBit(1)) {
						k = -k;
					}
				}
				a -= b;
			}

			return b == 1n ? k : 0;
		},

		// x ^ 2 = n (mod p)
		// where n is a quadratic residue (mod p), and p is an odd prime.
		// 
		// returns square root of this modulo p if it exists,
		// 0 otherwise.
		// example:
		// the square root of 2 mod 113 = 62.
		// for 62 ^ 2 = 3844 = 2 + 34 * 113 = 2 (mod 113)
		modSqrt: function(p) {
			var a = this;

			if (a == 0n) return 0n;
			if (a == 1n) return 1n;

			if (p == 2n) return a;

			var s = 0;
			var q = p - 1n;
			var r;
			var p1 = p - 1n;

			// p = 3 mod 4 or (3 mod 8 or 7 mod 8)
			if (p.testBit(0) && p.testBit(1)) {
				if (a.jacobi(p) == 1) { // a quadr. residue mod p
					v = p + 1n;
					v >>= 2n; // v = v/4n
					return a.modPow(v, p); // return a^v mod p
					// return --> a^((p+1)/4) mod p
				}
				return 0n;
			}

			while (!q.testBit(0)) {
				q >>= 1n;
				++s;
			}

			// Find the first quadratic non-residue z by brute-force search
			var z = 1n;
			do {
				z += 1n;
			} while (z.jacobi(p) == 1);

			var c = z.modPow(q, p);
			//	r = a.modPow((q + 1n) / 2n, p);
			var d = q + 1n;
			d >>= 1n;
			r = a.modPow(d, p);
			var t = a.modPow(q, p);
			var m = s;

			var tt, i, b, b2;
			while (t != 1n) {
				tt = t;
				i = 0;
				while (tt != 1n) {
					tt = tt.square() % p;
					++i;
					if (i == m) return 0n;
				}
					
				// b = c.modPow(2n.modPow(BigInt(m - i - 1), p1), p);
				b = 2n;
				b = c.modPow(b.modPow(BigInt(m - i - 1), p1), p);
				b2 = b.square() % p;
				r = (r * b) % p;
				t = (t * b2) % p;
				c = b2;
				m = i;
			}

			//	if (r.multiply(r).mod(p).equals(a)) return r;
			if (r.square() % p == a) return r;
			return 0n;
		} /*,

//
		// Tonelli Shanks algorithm
		// get modular square root.
		// same with modSqrt
		tonelliShanks: function(p) {
			var a = this;

			if (a == 0n) return 0n;
			if (a == 1n) return 1n;

			var s = 0;
			var q = p - 1n;
			var r;
			var p1 = p - 1n;

			while (q % 2n == 0n) {
				q /= 2n;
				++s;
			}

			if (s == 1) {
				// a^((p+1)/4) mod p
				r = a.modPow((p + 1) / 4n, p);
				if (r.square() % p == a) return r;
				return 0n;
			}

			// Find the first quadratic non-residue z by brute-force search
			var z = 1n;
			var zz;
			do {
				z += 1n;
				zz = z.modPow(p1 / 2n, p);
			} while (zz != p1);

			var c = z.modPow(q, p);
			r = a.modPow((q + 1n) / 2n, p);
			var t = a.modPow(q, p);
			var m = s;

			var tt, i, b, b2;
			while (t != 1n) {
				tt = t;
				i = 0;
				while (tt != 1n) {
					tt = tt.square() % p;
					++i;
					if (i == m) return 0n;
				}
					
				b = c.modPow((2n).modPow(BigInt(m - i - 1), p1), p);
				b2 = b.square() % p;
				r = (r * b) % p;
				t = (t * b2) % p;
				c = b2;
				m = i;
			}

			if (r.square() % p == a) return r;
			return 0n;
		}
*/
	});

	BigInt.prototype.gt = BigInt.prototype.greater;
	BigInt.prototype.lt = BigInt.prototype.lesser;
	BigInt.prototype.eq = BigInt.prototype.equals;
	BigInt.prototype.neq = BigInt.prototype.notEquals;
	BigInt.prototype.leq = BigInt.prototype.lesserOrEquals;
	BigInt.prototype.geq = BigInt.prototype.greaterOrEquals;
	BigInt.prototype.shl = BigInt.prototype.ShiftLeft;
	BigInt.prototype.shr = BigInt.prototype.ShiftRight;
	BigInt.prototype.modInv = BigInt.prototype.modInverse;


	BigInt.lowPrimes = [
		2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n, 41n, 43n, 47n, 53n, 59n, 61n, 67n, 71n,
		73n, 79n, 83n, 89n, 97n, 101n, 103n, 107n, 109n, 113n, 127n, 131n, 137n, 139n, 149n, 151n,
		157n, 163n, 167n, 173n, 179n, 181n, 191n, 193n, 197n, 199n, 211n, 223n, 227n, 229n, 233n,
		239n, 241n, 251n, 257n, 263n, 269n, 271n, 277n, 281n, 283n, 293n, 307n, 311n, 313n, 317n,
		331n, 337n, 347n, 349n, 353n, 359n, 367n, 373n, 379n, 383n, 389n, 397n, 401n, 409n, 419n,
		421n, 431n, 433n, 439n, 443n, 449n, 457n, 461n, 463n, 467n, 479n, 487n, 491n, 499n, 503n,
		509n, 521n, 523n, 541n, 547n, 557n, 563n, 569n, 571n, 577n, 587n, 593n, 599n, 601n, 607n,
		613n, 617n, 619n, 631n, 641n, 643n, 647n, 653n, 659n, 661n, 673n, 677n, 683n, 691n, 701n,
		709n, 719n, 727n, 733n, 739n, 743n, 751n, 757n, 761n, 769n, 773n, 787n, 797n, 809n, 811n,
		821n, 823n, 827n, 829n, 839n, 853n, 857n, 859n, 863n, 877n, 881n, 883n, 887n, 907n, 911n,
		919n, 929n, 937n, 941n, 947n, 953n, 967n, 971n, 977n, 983n, 991n, 997n,
//
		1009n, 1013n, 1019n, 1021n, 1031n, 1033n, 1039n, 1049n, 1051n, 1061n, 1063n, 1069n, 1087n,
		1091n, 1093n, 1097n, 1103n, 1109n, 1117n, 1123n, 1129n, 1151n, 1153n, 1163n, 1171n, 1181n,
		1187n, 1193n, 1201n, 1213n, 1217n, 1223n, 1229n, 1231n, 1237n, 1249n, 1259n, 1277n, 1279n,
		1283n, 1289n, 1291n, 1297n, 1301n, 1303n, 1307n, 1319n, 1321n, 1327n, 1361n, 1367n, 1373n,
		1381n, 1399n, 1409n, 1423n, 1427n, 1429n, 1433n, 1439n, 1447n, 1451n, 1453n, 1459n, 1471n,
		1481n, 1483n, 1487n, 1489n, 1493n, 1499n, 1511n, 1523n, 1531n, 1543n, 1549n, 1553n, 1559n,
		1567n, 1571n, 1579n, 1583n, 1597n, 1601n, 1607n, 1609n, 1613n, 1619n, 1621n, 1627n, 1637n,
		1657n, 1663n, 1667n, 1669n, 1693n, 1697n, 1699n, 1709n, 1721n, 1723n, 1733n, 1741n, 1747n,
		1753n, 1759n, 1777n, 1783n, 1787n, 1789n, 1801n, 1811n, 1823n, 1831n, 1847n, 1861n, 1867n,
		1871n, 1873n, 1877n, 1879n, 1889n, 1901n, 1907n, 1913n, 1931n, 1933n, 1949n, 1951n, 1973n,
		1979n, 1987n, 1993n, 1997n, 1999n, 
			
		2003n, 2011n, 2017n, 2027n, 2029n, 2039n, 2053n, 2063n, 2069n, 2081n, 2083n, 2087n, 2089n,
		2099n, 2111n, 2113n, 2129n, 2131n, 2137n, 2141n, 2143n, 2153n, 2161n, 2179n, 2203n, 2207n,
		2213n, 2221n, 2237n, 2239n, 2243n, 2251n, 2267n, 2269n, 2273n, 2281n, 2287n, 2293n, 2297n,
		2309n, 2311n, 2333n, 2339n, 2341n, 2347n, 2351n, 2357n, 2371n, 2377n, 2381n, 2383n, 2389n,
		2393n, 2399n, 2411n, 2417n, 2423n, 2437n, 2441n, 2447n, 2459n, 2467n, 2473n, 2477n, 2503n,
		2521n, 2531n, 2539n, 2543n, 2549n, 2551n, 2557n, 2579n, 2591n, 2593n, 2609n, 2617n, 2621n,
		2633n, 2647n, 2657n, 2659n, 2663n, 2671n, 2677n, 2683n, 2687n, 2689n, 2693n, 2699n, 2707n,
		2711n, 2713n, 2719n, 2729n, 2731n, 2741n, 2749n, 2753n, 2767n, 2777n, 2789n, 2791n, 2797n,
		2801n, 2803n, 2819n, 2833n, 2837n, 2843n, 2851n, 2857n, 2861n, 2879n, 2887n, 2897n, 2903n,
		2909n, 2917n, 2927n, 2939n, 2953n, 2957n, 2963n, 2969n, 2971n, 2999n,
			
		3001n, 3011n, 3019n, 3023n, 3037n, 3041n, 3049n, 3061n, 3067n, 3079n, 3083n, 3089n, 3109n,
		3119n, 3121n, 3137n, 3163n, 3167n, 3169n, 3181n, 3187n, 3191n, 3203n, 3209n, 3217n, 3221n,
		3229n, 3251n, 3253n, 3257n, 3259n, 3271n, 3299n, 3301n, 3307n, 3313n, 3319n, 3323n, 3329n,
		3331n, 3343n, 3347n, 3359n, 3361n, 3371n, 3373n, 3389n, 3391n, 3407n, 3413n, 3433n, 3449n,
		3457n, 3461n, 3463n, 3467n, 3469n, 3491n, 3499n, 3511n, 3517n, 3527n, 3529n, 3533n, 3539n,
		3541n, 3547n, 3557n, 3559n, 3571n, 3581n, 3583n, 3593n, 3607n, 3613n, 3617n, 3623n, 3631n,
		3637n, 3643n, 3659n, 3671n, 3673n, 3677n, 3691n, 3697n, 3701n, 3709n, 3719n, 3727n, 3733n,
		3739n, 3761n, 3767n, 3769n, 3779n, 3793n, 3797n, 3803n, 3821n, 3823n, 3833n, 3847n, 3851n,
		3853n, 3863n, 3877n, 3881n, 3889n, 3907n, 3911n, 3917n, 3919n, 3923n, 3929n, 3931n, 3943n,
		3947n, 3967n, 3989n,
			
		4001n, 4003n, 4007n, 4013n, 4019n, 4021n, 4027n, 4049n, 4051n, 4057n, 4073n, 4079n, 4091n,
		4093n, 4099n, 4111n, 4127n, 4129n, 4133n, 4139n, 4153n, 4157n, 4159n, 4177n, 4201n, 4211n,
		4217n, 4219n, 4229n, 4231n, 4241n, 4243n, 4253n, 4259n, 4261n, 4271n, 4273n, 4283n, 4289n,
		4297n, 4327n, 4337n, 4339n, 4349n, 4357n, 4363n, 4373n, 4391n, 4397n, 4409n, 4421n, 4423n,
		4441n, 4447n, 4451n, 4457n, 4463n, 4481n, 4483n, 4493n, 4507n, 4513n, 4517n, 4519n, 4523n,
		4547n, 4549n, 4561n, 4567n, 4583n, 4591n, 4597n, 4603n, 4621n, 4637n, 4639n, 4643n, 4649n,
		4651n, 4657n, 4663n, 4673n, 4679n, 4691n, 4703n, 4721n, 4723n, 4729n, 4733n, 4751n, 4759n,
		4783n, 4787n, 4789n, 4793n, 4799n, 4801n, 4813n, 4817n, 4831n, 4861n, 4871n, 4877n, 4889n,
		4903n, 4909n, 4919n, 4931n, 4933n, 4937n, 4943n, 4951n, 4957n, 4967n, 4969n, 4973n, 4987n,
		4993n, 4999n,
			
		5003n, 5009n, 5011n, 5021n, 5023n, 5039n, 5051n, 5059n, 5077n, 5081n, 5087n, 5099n, 5101n,
		5107n, 5113n, 5119n, 5147n, 5153n, 5167n, 5171n, 5179n, 5189n, 5197n, 5209n, 5227n, 5231n, 
		5233n, 5237n, 5261n, 5273n, 5279n, 5281n, 5297n, 5303n, 5309n, 5323n, 5333n, 5347n, 5351n,
		5381n, 5387n, 5393n, 5399n, 5407n, 5413n, 5417n, 5419n, 5431n, 5437n, 5441n, 5443n, 5449n,
		5471n, 5477n, 5479n, 5483n, 5501n, 5503n, 5507n, 5519n, 5521n, 5527n, 5531n, 5557n, 5563n,
		5569n, 5573n, 5581n, 5591n, 5623n, 5639n, 5641n, 5647n, 5651n, 5653n, 5657n, 5659n, 5669n,
		5683n, 5689n, 5693n, 5701n, 5711n, 5717n, 5737n, 5741n, 5743n, 5749n, 5779n, 5783n, 5791n,
		5801n, 5807n, 5813n, 5821n, 5827n, 5839n, 5843n, 5849n, 5851n, 5857n, 5861n, 5867n, 5869n,
		5879n, 5881n, 5897n, 5903n, 5923n, 5927n, 5939n, 5953n, 5981n, 5987n, 6007n, 6011n, 6029n,
		6037n, 6043n, 6047n, 6053n, 6067n, 6073n, 6079n, 6089n, 6091n, 6101n, 6113n, 6121n, 6131n,
		6133n, 6143n, 6151n, 6163n, 6173n, 6197n, 6199n, 6203n, 6211n, 6217n, 6221n, 6229n, 6247n,
		6257n, 6263n, 6269n, 6271n, 6277n, 6287n, 6299n, 6301n, 6311n, 6317n, 6323n, 6329n, 6337n,
		6343n, 6353n, 6359n, 6361n, 6367n, 6373n, 6379n, 6389n, 6397n, 6421n, 6427n, 6449n, 6451n,
		6469n, 6473n, 6481n, 6491n, 6521n, 6529n, 6547n, 6551n, 6553n, 6563n, 6569n, 6571n, 6577n,
		6581n, 6599n, 6607n, 6619n, 6637n, 6653n, 6659n, 6661n, 6673n, 6679n, 6689n, 6691n, 6701n,
		6703n, 6709n, 6719n, 6733n, 6737n, 6761n, 6763n, 6779n, 6781n, 6791n, 6793n, 6803n, 6823n,
		6827n, 6829n, 6833n, 6841n, 6857n, 6863n, 6869n, 6871n, 6883n, 6899n, 6907n, 6911n, 6917n,
		6947n, 6949n, 6959n, 6961n, 6967n, 6971n, 6977n, 6983n, 6991n, 6997n, 7001n, 7013n, 7019n,
		7027n, 7039n, 7043n, 7057n, 7069n, 7079n, 7103n, 7109n, 7121n, 7127n, 7129n, 7151n, 7159n,
		7177n, 7187n, 7193n, 7207n, 7211n, 7213n, 7219n, 7229n, 7237n, 7243n, 7247n, 7253n, 7283n,
		7297n, 7307n, 7309n, 7321n, 7331n, 7333n, 7349n, 7351n, 7369n, 7393n, 7411n, 7417n, 7433n,
		7451n, 7457n, 7459n, 7477n, 7481n, 7487n, 7489n, 7499n, 7507n, 7517n, 7523n, 7529n, 7537n,
		7541n, 7547n, 7549n, 7559n, 7561n, 7573n, 7577n, 7583n, 7589n, 7591n, 7603n, 7607n, 7621n,
		7639n, 7643n, 7649n, 7669n, 7673n, 7681n, 7687n, 7691n, 7699n, 7703n, 7717n, 7723n, 7727n,
		7741n, 7753n, 7757n, 7759n, 7789n, 7793n, 7817n, 7823n, 7829n, 7841n, 7853n, 7867n, 7873n,
		7877n, 7879n, 7883n, 7901n, 7907n, 7919n, 7927n, 7933n, 7937n, 7949n, 7951n, 7963n, 7993n,
		8009n, 8011n, 8017n, 8039n, 8053n, 8059n, 8069n, 8081n, 8087n, 8089n, 8093n, 8101n, 8111n,
		8117n, 8123n, 8147n, 8161n, 8167n, 8171n, 8179n, 8191n, 8209n, 8219n, 8221n, 8231n, 8233n,
		8237n, 8243n, 8263n, 8269n, 8273n, 8287n, 8291n, 8293n, 8297n, 8311n, 8317n, 8329n, 8353n,
		8363n, 8369n, 8377n, 8387n, 8389n, 8419n, 8423n, 8429n, 8431n, 8443n, 8447n, 8461n, 8467n,
		8501n, 8513n, 8521n, 8527n, 8537n, 8539n, 8543n, 8563n, 8573n, 8581n, 8597n, 8599n, 8609n,
		8623n, 8627n, 8629n, 8641n, 8647n, 8663n, 8669n, 8677n, 8681n, 8689n, 8693n, 8699n, 8707n,
		8713n, 8719n, 8731n, 8737n, 8741n, 8747n, 8753n, 8761n, 8779n, 8783n, 8803n, 8807n, 8819n,
		8821n, 8831n, 8837n, 8839n, 8849n, 8861n, 8863n, 8867n, 8887n, 8893n, 8923n, 8929n, 8933n,
		8941n, 8951n, 8963n, 8969n, 8971n, 8999n, 9001n, 9007n, 9011n, 9013n, 9029n, 9041n, 9043n,
		9049n, 9059n, 9067n, 9091n, 9103n, 9109n, 9127n, 9133n, 9137n, 9151n, 9157n, 9161n, 9173n,
		9181n, 9187n, 9199n, 9203n, 9209n, 9221n, 9227n, 9239n, 9241n, 9257n, 9277n, 9281n, 9283n,
		9293n, 9311n, 9319n, 9323n, 9337n, 9341n, 9343n, 9349n, 9371n, 9377n, 9391n, 9397n, 9403n,
		9413n, 9419n, 9421n, 9431n, 9433n, 9437n, 9439n, 9461n, 9463n, 9467n, 9473n, 9479n, 9491n,
		9497n, 9511n, 9521n, 9533n, 9539n, 9547n, 9551n, 9587n, 9601n, 9613n, 9619n, 9623n, 9629n,
		9631n, 9643n, 9649n, 9661n, 9677n, 9679n, 9689n, 9697n, 9719n, 9721n, 9733n, 9739n, 9743n,
		9749n, 9767n, 9769n, 9781n, 9787n, 9791n, 9803n, 9811n, 9817n, 9829n, 9833n, 9839n, 9851n,
		9857n, 9859n, 9871n, 9883n, 9887n, 9901n, 9907n, 9923n, 9929n, 9931n, 9941n, 9949n, 9967n,
		9973n, 
/*
		10007n, 10009n, 10037n, 10039n, 10061n, 10067n, 10069n, 10079n, 10091n, 10093n, 10099n,
		10103n, 10111n, 10133n, 10139n, 10141n, 10151n, 10159n, 10163n, 10169n, 10177n, 10181n,
		10193n, 10211n, 10223n, 10243n, 10247n, 10253n, 10259n, 10267n, 10271n, 10273n, 10289n,
		10301n, 10303n, 10313n, 10321n, 10331n, 10333n, 10337n, 10343n, 10357n, 10369n, 10391n,
		10399n, 10427n, 10429n, 10433n, 10453n, 10457n, 10459n, 10463n, 10477n, 10487n, 10499n,
		10501n, 10513n, 10529n, 10531n, 10559n, 10567n, 10589n, 10597n, 10601n, 10607n, 10613n,
		10627n, 10631n, 10639n, 10651n, 10657n, 10663n, 10667n, 10687n, 10691n, 10709n, 10711n,
		10723n, 10729n, 10733n, 10739n, 10753n, 10771n, 10781n, 10789n, 10799n, 10831n, 10837n,
		10847n, 10853n, 10859n, 10861n, 10867n, 10883n, 10889n, 10891n, 10903n, 10909n, 10937n,
		10939n, 10949n, 10957n, 10973n, 10979n, 10987n, 10993n, 11003n, 11027n, 11047n, 11057n,
		11059n, 11069n, 11071n, 11083n, 11087n, 11093n, 11113n, 11117n, 11119n, 11131n, 11149n,
		11159n, 11161n, 11171n, 11173n, 11177n, 11197n, 11213n, 11239n, 11243n, 11251n, 11257n,
		11261n, 11273n, 11279n, 11287n, 11299n, 11311n, 11317n, 11321n, 11329n, 11351n, 11353n,
		11369n, 11383n, 11393n, 11399n, 11411n, 11423n, 11437n, 11443n, 11447n, 11467n, 11471n,
		11483n, 11489n, 11491n, 11497n, 11503n, 11519n, 11527n, 11549n, 11551n, 11579n, 11587n,
		11593n, 11597n, 11617n, 11621n, 11633n, 11657n, 11677n, 11681n, 11689n, 11699n, 11701n,
		11717n, 11719n, 11731n, 11743n, 11777n, 11779n, 11783n, 11789n, 11801n, 11807n, 11813n,
		11821n, 11827n, 11831n, 11833n, 11839n, 11863n, 11867n, 11887n, 11897n, 11903n, 11909n,
		11923n, 11927n, 11933n, 11939n, 11941n, 11953n, 11959n, 11969n, 11971n, 11981n, 11987n,
		12007n, 12011n, 12037n, 12041n, 12043n, 12049n, 12071n, 12073n, 12097n, 12101n, 12107n,
		12109n, 12113n, 12119n, 12143n, 12149n, 12157n, 12161n, 12163n, 12197n, 12203n, 12211n,
		12227n, 12239n, 12241n, 12251n, 12253n, 12263n, 12269n, 12277n, 12281n, 12289n, 12301n,
		12323n, 12329n, 12343n, 12347n, 12373n, 12377n, 12379n, 12391n, 12401n, 12409n, 12413n,
		12421n, 12433n, 12437n, 12451n, 12457n, 12473n, 12479n, 12487n, 12491n, 12497n, 12503n,
		12511n, 12517n, 12527n, 12539n, 12541n, 12547n, 12553n, 12569n, 12577n, 12583n, 12589n,
		12601n, 12611n, 12613n, 12619n, 12637n, 12641n, 12647n, 12653n, 12659n, 12671n, 12689n,
		12697n, 12703n, 12713n, 12721n, 12739n, 12743n, 12757n, 12763n, 12781n, 12791n, 12799n,
		12809n, 12821n, 12823n, 12829n, 12841n, 12853n, 12889n, 12893n, 12899n, 12907n, 12911n,
		12917n, 12919n, 12923n, 12941n, 12953n, 12959n, 12967n, 12973n, 12979n, 12983n, 13001n,
		13003n, 13007n, 13009n, 13033n, 13037n, 13043n, 13049n, 13063n, 13093n, 13099n, 13103n,
		13109n, 13121n, 13127n, 13147n, 13151n, 13159n, 13163n, 13171n, 13177n, 13183n, 13187n,
		13217n, 13219n, 13229n, 13241n, 13249n, 13259n, 13267n, 13291n, 13297n, 13309n, 13313n,
		13327n, 13331n, 13337n, 13339n, 13367n, 13381n, 13397n, 13399n, 13411n, 13417n, 13421n,
		13441n, 13451n, 13457n, 13463n, 13469n, 13477n, 13487n, 13499n, 13513n, 13523n, 13537n,
		13553n, 13567n, 13577n, 13591n, 13597n, 13613n, 13619n, 13627n, 13633n, 13649n, 13669n,
		13679n, 13681n, 13687n, 13691n, 13693n, 13697n, 13709n, 13711n, 13721n, 13723n, 13729n,
		13751n, 13757n, 13759n, 13763n, 13781n, 13789n, 13799n, 13807n, 13829n, 13831n, 13841n,
		13859n, 13873n, 13877n, 13879n, 13883n, 13901n, 13903n, 13907n, 13913n, 13921n, 13931n,
		13933n, 13963n, 13967n, 13997n, 13999n, 14009n, 14011n, 14029n, 14033n, 14051n, 14057n,
		14071n, 14081n, 14083n, 14087n, 14107n, 14143n, 14149n, 14153n, 14159n, 14173n, 14177n,
		14197n, 14207n, 14221n, 14243n, 14249n, 14251n, 14281n, 14293n, 14303n, 14321n, 14323n,
		14327n, 14341n, 14347n, 14369n, 14387n, 14389n, 14401n, 14407n, 14411n, 14419n, 14423n,
		14431n, 14437n, 14447n, 14449n, 14461n, 14479n, 14489n, 14503n, 14519n, 14533n, 14537n,
		14543n, 14549n, 14551n, 14557n, 14561n, 14563n, 14591n, 14593n, 14621n, 14627n, 14629n,
		14633n, 14639n, 14653n, 14657n, 14669n, 14683n, 14699n, 14713n, 14717n, 14723n, 14731n,
		14737n, 14741n, 14747n, 14753n, 14759n, 14767n, 14771n, 14779n, 14783n, 14797n, 14813n,
		14821n, 14827n, 14831n, 14843n, 14851n, 14867n, 14869n, 14879n, 14887n, 14891n, 14897n,
		14923n, 14929n, 14939n, 14947n, 14951n, 14957n, 14969n, 14983n, 15013n, 15017n, 15031n,
		15053n, 15061n, 15073n, 15077n, 15083n, 15091n, 15101n, 15107n, 15121n, 15131n, 15137n,
		15139n, 15149n, 15161n, 15173n, 15187n, 15193n, 15199n, 15217n, 15227n, 15233n, 15241n, 
		15259n, 15263n, 15269n, 15271n, 15277n, 15287n, 15289n, 15299n, 15307n, 15313n, 15319n,
		15329n, 15331n, 15349n, 15359n, 15361n, 15373n, 15377n, 15383n, 15391n, 15401n, 15413n,
		15427n, 15439n, 15443n, 15451n, 15461n, 15467n, 15473n, 15493n, 15497n, 15511n, 15527n,
		15541n, 15551n, 15559n, 15569n, 15581n, 15583n, 15601n, 15607n, 15619n, 15629n, 15641n,
		15643n, 15647n, 15649n, 15661n, 15667n, 15671n, 15679n, 15683n, 15727n, 15731n, 15733n,
		15737n, 15739n, 15749n, 15761n, 15767n, 15773n, 15787n, 15791n, 15797n, 15803n, 15809n,
		15817n, 15823n, 15859n, 15877n, 15881n, 15887n, 15889n, 15901n, 15907n, 15913n, 15919n,
		15923n, 15937n, 15959n, 15971n, 15973n, 15991n, 16001n, 16007n, 16033n, 16057n, 16061n,
		16063n, 16067n, 16069n, 16073n, 16087n, 16091n, 16097n, 16103n, 16111n, 16127n, 16139n,
		16141n, 16183n, 16187n, 16189n, 16193n, 16217n, 16223n, 16229n, 16231n, 16249n, 16253n,
		16267n, 16273n, 16301n, 16319n, 16333n, 16339n, 16349n, 16361n, 16363n, 16369n, 16381n,
		16411n, 16417n, 16421n, 16427n, 16433n, 16447n, 16451n, 16453n, 16477n, 16481n, 16487n,
		16493n, 16519n, 16529n, 16547n, 16553n, 16561n, 16567n, 16573n, 16603n, 16607n, 16619n,
		16631n, 16633n, 16649n, 16651n, 16657n, 16661n, 16673n, 16691n, 16693n, 16699n, 16703n,
		16729n, 16741n, 16747n, 16759n, 16763n, 16787n, 16811n, 16823n, 16829n, 16831n, 16843n,
		16871n, 16879n, 16883n, 16889n, 16901n, 16903n, 16921n, 16927n, 16931n, 16937n, 16943n,
		16963n, 16979n, 16981n, 16987n, 16993n, 17011n, 17021n, 17027n, 17029n, 17033n, 17041n,
		17047n, 17053n, 17077n, 17093n, 17099n, 17107n, 17117n, 17123n, 17137n, 17159n, 17167n,
		17183n, 17189n, 17191n, 17203n, 17207n, 17209n, 17231n, 17239n, 17257n, 17291n, 17293n,
		17299n, 17317n, 17321n, 17327n, 17333n, 17341n, 17351n, 17359n, 17377n, 17383n, 17387n,
		17389n, 17393n, 17401n, 17417n, 17419n, 17431n, 17443n, 17449n, 17467n, 17471n, 17477n,
		17483n, 17489n, 17491n, 17497n, 17509n, 17519n, 17539n, 17551n, 17569n, 17573n, 17579n,
		17581n, 17597n, 17599n, 17609n, 17623n, 17627n, 17657n, 17659n, 17669n, 17681n, 17683n,
		17707n, 17713n, 17729n, 17737n, 17747n, 17749n, 17761n, 17783n, 17789n, 17791n, 17807n,
		17827n, 17837n, 17839n, 17851n, 17863n, 17881n, 17891n, 17903n, 17909n, 17911n, 17921n,
		17923n, 17929n, 17939n, 17957n, 17959n, 17971n, 17977n, 17981n, 17987n, 17989n, 18013n,
		18041n, 18043n, 18047n, 18049n, 18059n, 18061n, 18077n, 18089n, 18097n, 18119n, 18121n,
		18127n, 18131n, 18133n, 18143n, 18149n, 18169n, 18181n, 18191n, 18199n, 18211n, 18217n,
		18223n, 18229n, 18233n, 18251n, 18253n, 18257n, 18269n, 18287n, 18289n, 18301n, 18307n,
		18311n, 18313n, 18329n, 18341n, 18353n, 18367n, 18371n, 18379n, 18397n, 18401n, 18413n,
		18427n, 18433n, 18439n, 18443n, 18451n, 18457n, 18461n, 18481n, 18493n, 18503n, 18517n,
		18521n, 18523n, 18539n, 18541n, 18553n, 18583n, 18587n, 18593n, 18617n, 18637n, 18661n,
		18671n, 18679n, 18691n, 18701n, 18713n, 18719n, 18731n, 18743n, 18749n, 18757n, 18773n,
		18787n, 18793n, 18797n, 18803n, 18839n, 18859n, 18869n, 18899n, 18911n, 18913n, 18917n,
		18919n, 18947n, 18959n, 18973n, 18979n, 19001n, 19009n, 19013n, 19031n, 19037n, 19051n,
		19069n, 19073n, 19079n, 19081n, 19087n, 19121n, 19139n, 19141n, 19157n, 19163n, 19181n,
		19183n, 19207n, 19211n, 19213n, 19219n, 19231n, 19237n, 19249n, 19259n, 19267n, 19273n,
		19289n, 19301n, 19309n, 19319n, 19333n, 19373n, 19379n, 19381n, 19387n, 19391n, 19403n,
		19417n, 19421n, 19423n, 19427n, 19429n, 19433n, 19441n, 19447n, 19457n, 19463n, 19469n,
		19471n, 19477n, 19483n, 19489n, 19501n, 19507n, 19531n, 19541n, 19543n, 19553n, 19559n,
		19571n, 19577n, 19583n, 19597n, 19603n, 19609n, 19661n, 19681n, 19687n, 19697n, 19699n,
		19709n, 19717n, 19727n, 19739n, 19751n, 19753n, 19759n, 19763n, 19777n, 19793n, 19801n,
		19813n, 19819n, 19841n, 19843n, 19853n, 19861n, 19867n, 19889n, 19891n, 19913n, 19919n,
		19927n, 19937n, 19949n, 19961n, 19963n, 19973n, 19979n, 19991n, 19993n, 19997n, 

		20011n, 20021n, 20023n, 20029n, 20047n, 20051n, 20063n, 20071n, 20089n, 20101n, 20107n,
		20113n, 20117n, 20123n, 20129n, 20143n, 20147n, 20149n, 20161n, 20173n, 20177n, 20183n,
		20201n, 20219n, 20231n, 20233n, 20249n, 20261n, 20269n, 20287n, 20297n, 20323n, 20327n,
		20333n, 20341n, 20347n, 20353n, 20357n, 20359n, 20369n, 20389n, 20393n, 20399n, 20407n,
		20411n, 20431n, 20441n, 20443n, 20477n, 20479n, 20483n, 20507n, 20509n, 20521n, 20533n,
		20543n, 20549n, 20551n, 20563n, 20593n, 20599n, 20611n, 20627n, 20639n, 20641n, 20663n,
		20681n, 20693n, 20707n, 20717n, 20719n, 20731n, 20743n, 20747n, 20749n, 20753n, 20759n,
		20771n, 20773n, 20789n, 20807n, 20809n, 20849n, 20857n, 20873n, 20879n, 20887n, 20897n,
		20899n, 20903n, 20921n, 20929n, 20939n, 20947n, 20959n, 20963n, 20981n, 20983n, 21001n,
		21011n, 21013n, 21017n, 21019n, 21023n, 21031n, 21059n, 21061n, 21067n, 21089n, 21101n,
		21107n, 21121n, 21139n, 21143n, 21149n, 21157n, 21163n, 21169n, 21179n, 21187n, 21191n,
		21193n, 21211n, 21221n, 21227n, 21247n, 21269n, 21277n, 21283n, 21313n, 21317n, 21319n,
		21323n, 21341n, 21347n, 21377n, 21379n, 21383n, 21391n, 21397n, 21401n, 21407n, 21419n,
		21433n, 21467n, 21481n, 21487n, 21491n, 21493n, 21499n, 21503n, 21517n, 21521n, 21523n,
		21529n, 21557n, 21559n, 21563n, 21569n, 21577n, 21587n, 21589n, 21599n, 21601n, 21611n,
		21613n, 21617n, 21647n, 21649n, 21661n, 21673n, 21683n, 21701n, 21713n, 21727n, 21737n,
		21739n, 21751n, 21757n, 21767n, 21773n, 21787n, 21799n, 21803n, 21817n, 21821n, 21839n,
		21841n, 21851n, 21859n, 21863n, 21871n, 21881n, 21893n, 21911n, 21929n, 21937n, 21943n,
		21961n, 21977n, 21991n, 21997n, 22003n, 22013n, 22027n, 22031n, 22037n, 22039n, 22051n,
		22063n, 22067n, 22073n, 22079n, 22091n, 22093n, 22109n, 22111n, 22123n, 22129n, 22133n,
		22147n, 22153n, 22157n, 22159n, 22171n, 22189n, 22193n, 22229n, 22247n, 22259n, 22271n,
		22273n, 22277n, 22279n, 22283n, 22291n, 22303n, 22307n, 22343n, 22349n, 22367n, 22369n,
		22381n, 22391n, 22397n, 22409n, 22433n, 22441n, 22447n, 22453n, 22469n, 22481n, 22483n,
		22501n, 22511n, 22531n, 22541n, 22543n, 22549n, 22567n, 22571n, 22573n, 22613n, 22619n,
		22621n, 22637n, 22639n, 22643n, 22651n, 22669n, 22679n, 22691n, 22697n, 22699n, 22709n,
		22717n, 22721n, 22727n, 22739n, 22741n, 22751n, 22769n, 22777n, 22783n, 22787n, 22807n,
		22811n, 22817n, 22853n, 22859n, 22861n, 22871n, 22877n, 22901n, 22907n, 22921n, 22937n,
		22943n, 22961n, 22963n, 22973n, 22993n, 23003n, 23011n, 23017n, 23021n, 23027n, 23029n,
		23039n, 23041n, 23053n, 23057n, 23059n, 23063n, 23071n, 23081n, 23087n, 23099n, 23117n,
		23131n, 23143n, 23159n, 23167n, 23173n, 23189n, 23197n, 23201n, 23203n, 23209n, 23227n,
		23251n, 23269n, 23279n, 23291n, 23293n, 23297n, 23311n, 23321n, 23327n, 23333n, 23339n,
		23357n, 23369n, 23371n, 23399n, 23417n, 23431n, 23447n, 23459n, 23473n, 23497n, 23509n,
		23531n, 23537n, 23539n, 23549n, 23557n, 23561n, 23563n, 23567n, 23581n, 23593n, 23599n,
		23603n, 23609n, 23623n, 23627n, 23629n, 23633n, 23663n, 23669n, 23671n, 23677n, 23687n,
		23689n, 23719n, 23741n, 23743n, 23747n, 23753n, 23761n, 23767n, 23773n, 23789n, 23801n,
		23813n, 23819n, 23827n, 23831n, 23833n, 23857n, 23869n, 23873n, 23879n, 23887n, 23893n,
		23899n, 23909n, 23911n, 23917n, 23929n, 23957n, 23971n, 23977n, 23981n, 23993n, 24001n,
		24007n, 24019n, 24023n, 24029n, 24043n, 24049n, 24061n, 24071n, 24077n, 24083n, 24091n,
		24097n, 24103n, 24107n, 24109n, 24113n, 24121n, 24133n, 24137n, 24151n, 24169n, 24179n,
		24181n, 24197n, 24203n, 24223n, 24229n, 24239n, 24247n, 24251n, 24281n, 24317n, 24329n,
		24337n, 24359n, 24371n, 24373n, 24379n, 24391n, 24407n, 24413n, 24419n, 24421n, 24439n,
		24443n, 24469n, 24473n, 24481n, 24499n, 24509n, 24517n, 24527n, 24533n, 24547n, 24551n,
		24571n, 24593n, 24611n, 24623n, 24631n, 24659n, 24671n, 24677n, 24683n, 24691n, 24697n,
		24709n, 24733n, 24749n, 24763n, 24767n, 24781n, 24793n, 24799n, 24809n, 24821n, 24841n,
		24847n, 24851n, 24859n, 24877n, 24889n, 24907n, 24917n, 24919n, 24923n, 24943n, 24953n,
		24967n, 24971n, 24977n, 24979n, 24989n, 25013n, 25031n, 25033n, 25037n, 25057n, 25073n,
		25087n, 25097n, 25111n, 25117n, 25121n, 25127n, 25147n, 25153n, 25163n, 25169n, 25171n,
		25183n, 25189n, 25219n, 25229n, 25237n, 25243n, 25247n, 25253n, 25261n, 25301n, 25303n,
		25307n, 25309n, 25321n, 25339n, 25343n, 25349n, 25357n, 25367n, 25373n, 25391n, 25409n,
		25411n, 25423n, 25439n, 25447n, 25453n, 25457n, 25463n, 25469n, 25471n, 25523n, 25537n,
		25541n, 25561n, 25577n, 25579n, 25583n, 25589n, 25601n, 25603n, 25609n, 25621n, 25633n,
		25639n, 25643n, 25657n, 25667n, 25673n, 25679n, 25693n, 25703n, 25717n, 25733n, 25741n,
		25747n, 25759n, 25763n, 25771n, 25793n, 25799n, 25801n, 25819n, 25841n, 25847n, 25849n,
		25867n, 25873n, 25889n, 25903n, 25913n, 25919n, 25931n, 25933n, 25939n, 25943n, 25951n,
		25969n, 25981n, 25997n, 25999n, 26003n, 26017n, 26021n, 26029n, 26041n, 26053n, 26083n,
		26099n, 26107n, 26111n, 26113n, 26119n, 26141n, 26153n, 26161n, 26171n, 26177n, 26183n,
		26189n, 26203n, 26209n, 26227n, 26237n, 26249n, 26251n, 26261n, 26263n, 26267n, 26293n,
		26297n, 26309n, 26317n, 26321n, 26339n, 26347n, 26357n, 26371n, 26387n, 26393n, 26399n,
		26407n, 26417n, 26423n, 26431n, 26437n, 26449n, 26459n, 26479n, 26489n, 26497n, 26501n,
		26513n, 26539n, 26557n, 26561n, 26573n, 26591n, 26597n, 26627n, 26633n, 26641n, 26647n,
		26669n, 26681n, 26683n, 26687n, 26693n, 26699n, 26701n, 26711n, 26713n, 26717n, 26723n,
		26729n, 26731n, 26737n, 26759n, 26777n, 26783n, 26801n, 26813n, 26821n, 26833n, 26839n,
		26849n, 26861n, 26863n, 26879n, 26881n, 26891n, 26893n, 26903n, 26921n, 26927n, 26947n,
		26951n, 26953n, 26959n, 26981n, 26987n, 26993n, 27011n, 27017n, 27031n, 27043n, 27059n,
		27061n, 27067n, 27073n, 27077n, 27091n, 27103n, 27107n, 27109n, 27127n, 27143n, 27179n,
		27191n, 27197n, 27211n, 27239n, 27241n, 27253n, 27259n, 27271n, 27277n, 27281n, 27283n,
		27299n, 27329n, 27337n, 27361n, 27367n, 27397n, 27407n, 27409n, 27427n, 27431n, 27437n,
		27449n, 27457n, 27479n, 27481n, 27487n, 27509n, 27527n, 27529n, 27539n, 27541n, 27551n,
		27581n, 27583n, 27611n, 27617n, 27631n, 27647n, 27653n, 27673n, 27689n, 27691n, 27697n,
		27701n, 27733n, 27737n, 27739n, 27743n, 27749n, 27751n, 27763n, 27767n, 27773n, 27779n,
		27791n, 27793n, 27799n, 27803n, 27809n, 27817n, 27823n, 27827n, 27847n, 27851n, 27883n,
		27893n, 27901n, 27917n, 27919n, 27941n, 27943n, 27947n, 27953n, 27961n, 27967n, 27983n,
		27997n, 28001n, 28019n, 28027n, 28031n, 28051n, 28057n, 28069n, 28081n, 28087n, 28097n,
		28099n, 28109n, 28111n, 28123n, 28151n, 28163n, 28181n, 28183n, 28201n, 28211n, 28219n,
		28229n, 28277n, 28279n, 28283n, 28289n, 28297n, 28307n, 28309n, 28319n, 28349n, 28351n,
		28387n, 28393n, 28403n, 28409n, 28411n, 28429n, 28433n, 28439n, 28447n, 28463n, 28477n,
		28493n, 28499n, 28513n, 28517n, 28537n, 28541n, 28547n, 28549n, 28559n, 28571n, 28573n,
		28579n, 28591n, 28597n, 28603n, 28607n, 28619n, 28621n, 28627n, 28631n, 28643n, 28649n,
		28657n, 28661n, 28663n, 28669n, 28687n, 28697n, 28703n, 28711n, 28723n, 28729n, 28751n,
		28753n, 28759n, 28771n, 28789n, 28793n, 28807n, 28813n, 28817n, 28837n, 28843n, 28859n,
		28867n, 28871n, 28879n, 28901n, 28909n, 28921n, 28927n, 28933n, 28949n, 28961n, 28979n,
		29009n, 29017n, 29021n, 29023n, 29027n, 29033n, 29059n, 29063n, 29077n, 29101n, 29123n,
		29129n, 29131n, 29137n, 29147n, 29153n, 29167n, 29173n, 29179n, 29191n, 29201n, 29207n,
		29209n, 29221n, 29231n, 29243n, 29251n, 29269n, 29287n, 29297n, 29303n, 29311n, 29327n,
		29333n, 29339n, 29347n, 29363n, 29383n, 29387n, 29389n, 29399n, 29401n, 29411n, 29423n,
		29429n, 29437n, 29443n, 29453n, 29473n, 29483n, 29501n, 29527n, 29531n, 29537n, 29567n,
		29569n, 29573n, 29581n, 29587n, 29599n, 29611n, 29629n, 29633n, 29641n, 29663n, 29669n,
		29671n, 29683n, 29717n, 29723n, 29741n, 29753n, 29759n, 29761n, 29789n, 29803n, 29819n,
		29833n, 29837n, 29851n, 29863n, 29867n, 29873n, 29879n, 29881n, 29917n, 29921n, 29927n,
		29947n, 29959n, 29983n, 29989n,
		
		30011n, 30013n, 30029n, 30047n, 30059n, 30071n, 30089n, 30091n,
		30097n, 30103n, 30109n, 30113n, 30119n, 30133n, 30137n, 30139n, 30161n, 30169n, 30181n,
		30187n, 30197n, 30203n, 30211n, 30223n, 30241n, 30253n, 30259n, 30269n, 30271n, 30293n,
		30307n, 30313n, 30319n, 30323n, 30341n, 30347n, 30367n, 30389n, 30391n, 30403n, 30427n,
		30431n, 30449n, 30467n, 30469n, 30491n, 30493n, 30497n, 30509n, 30517n, 30529n, 30539n,
		30553n, 30557n, 30559n, 30577n, 30593n, 30631n, 30637n, 30643n, 30649n, 30661n, 30671n,
		30677n, 30689n, 30697n, 30703n, 30707n, 30713n, 30727n, 30757n, 30763n, 30773n, 30781n,
		30803n, 30809n, 30817n, 30829n, 30839n, 30841n, 30851n, 30853n, 30859n, 30869n, 30871n,
		30881n, 30893n, 30911n, 30931n, 30937n, 30941n, 30949n, 30971n, 30977n, 30983n, 31013n,
		31019n, 31033n, 31039n, 31051n, 31063n, 31069n, 31079n, 31081n, 31091n, 31121n, 31123n,
		31139n, 31147n, 31151n, 31153n, 31159n, 31177n, 31181n, 31183n, 31189n, 31193n, 31219n,
		31223n, 31231n, 31237n, 31247n, 31249n, 31253n, 31259n, 31267n, 31271n, 31277n, 31307n,
		31319n, 31321n, 31327n, 31333n, 31337n, 31357n, 31379n, 31387n, 31391n, 31393n, 31397n,
		31469n, 31477n, 31481n, 31489n, 31511n, 31513n, 31517n, 31531n, 31541n, 31543n, 31547n,
		31567n, 31573n, 31583n, 31601n, 31607n, 31627n, 31643n, 31649n, 31657n, 31663n, 31667n,
		31687n, 31699n, 31721n, 31723n, 31727n, 31729n, 31741n, 31751n, 31769n, 31771n, 31793n,
		31799n, 31817n, 31847n, 31849n, 31859n, 31873n, 31883n, 31891n, 31907n, 31957n, 31963n,
		31973n, 31981n, 31991n, 32003n, 32009n, 32027n, 32029n, 32051n, 32057n, 32059n, 32063n,
		32069n, 32077n, 32083n, 32089n, 32099n, 32117n, 32119n, 32141n, 32143n, 32159n, 32173n,
		32183n, 32189n, 32191n, 32203n, 32213n, 32233n, 32237n, 32251n, 32257n, 32261n, 32297n,
		32299n, 32303n, 32309n, 32321n, 32323n, 32327n, 32341n, 32353n, 32359n, 32363n, 32369n,
		32371n, 32377n, 32381n, 32401n, 32411n, 32413n, 32423n, 32429n, 32441n, 32443n, 32467n,
		32479n, 32491n, 32497n, 32503n, 32507n, 32531n, 32533n, 32537n, 32561n, 32563n, 32569n,
		32573n, 32579n, 32587n, 32603n, 32609n, 32611n, 32621n, 32633n, 32647n, 32653n, 32687n,
		32693n, 32707n, 32713n, 32717n, 32719n, 32749n, 32771n, 32779n, 32783n, 32789n, 32797n,
		32801n, 32803n, 32831n, 32833n, 32839n, 32843n, 32869n, 32887n, 32909n, 32911n, 32917n,
		32933n, 32939n, 32941n, 32957n, 32969n, 32971n, 32983n, 32987n, 32993n, 32999n, 33013n,
		33023n, 33029n, 33037n, 33049n, 33053n, 33071n, 33073n, 33083n, 33091n, 33107n, 33113n,
		33119n, 33149n, 33151n, 33161n, 33179n, 33181n, 33191n, 33199n, 33203n, 33211n, 33223n,
		33247n, 33287n, 33289n, 33301n, 33311n, 33317n, 33329n, 33331n, 33343n, 33347n, 33349n,
		33353n, 33359n, 33377n, 33391n, 33403n, 33409n, 33413n, 33427n, 33457n, 33461n, 33469n,
		33479n, 33487n, 33493n, 33503n, 33521n, 33529n, 33533n, 33547n, 33563n, 33569n, 33577n,
		33581n, 33587n, 33589n, 33599n, 33601n, 33613n, 33617n, 33619n, 33623n, 33629n, 33637n,
		33641n, 33647n, 33679n, 33703n, 33713n, 33721n, 33739n, 33749n, 33751n, 33757n, 33767n,
		33769n, 33773n, 33791n, 33797n, 33809n, 33811n, 33827n, 33829n, 33851n, 33857n, 33863n,
		33871n, 33889n, 33893n, 33911n, 33923n, 33931n, 33937n, 33941n, 33961n, 33967n, 33997n,
		34019n, 34031n, 34033n, 34039n, 34057n, 34061n, 34123n, 34127n, 34129n, 34141n, 34147n, 
		34157n, 34159n, 34171n, 34183n, 34211n, 34213n, 34217n, 34231n, 34253n, 34259n, 34261n, 
		34267n, 34273n, 34283n, 34297n, 34301n, 34303n, 34313n, 34319n, 34327n, 34337n, 34351n, 
		34361n, 34367n, 34369n, 34381n, 34403n, 34421n, 34429n, 34439n, 34457n, 34469n, 34471n, 
		34483n, 34487n, 34499n, 34501n, 34511n, 34513n, 34519n, 34537n, 34543n, 34549n, 34583n, 
		34589n, 34591n, 34603n, 34607n, 34613n, 34631n, 34649n, 34651n, 34667n, 34673n, 34679n, 
		34687n, 34693n, 34703n, 34721n, 34729n, 34739n, 34747n, 34757n, 34759n, 34763n, 34781n, 
		34807n, 34819n, 34841n, 34843n, 34847n, 34849n, 34871n, 34877n, 34883n, 34897n, 34913n, 
		34919n, 34939n, 34949n, 34961n, 34963n, 34981n, 35023n, 35027n, 35051n, 35053n, 35059n, 
		35069n, 35081n, 35083n, 35089n, 35099n, 35107n, 35111n, 35117n, 35129n, 35141n, 35149n, 
		35153n, 35159n, 35171n, 35201n, 35221n, 35227n, 35251n, 35257n, 35267n, 35279n, 35281n, 
		35291n, 35311n, 35317n, 35323n, 35327n, 35339n, 35353n, 35363n, 35381n, 35393n, 35401n, 
		35407n, 35419n, 35423n, 35437n, 35447n, 35449n, 35461n, 35491n, 35507n, 35509n, 35521n, 
		35527n, 35531n, 35533n, 35537n, 35543n, 35569n, 35573n, 35591n, 35593n, 35597n, 35603n, 
		35617n, 35671n, 35677n, 35729n, 35731n, 35747n, 35753n, 35759n, 35771n, 35797n, 35801n, 
		35803n, 35809n, 35831n, 35837n, 35839n, 35851n, 35863n, 35869n, 35879n, 35897n, 35899n, 
		35911n, 35923n, 35933n, 35951n, 35963n, 35969n, 35977n, 35983n, 35993n, 35999n, 36007n, 
		36011n, 36013n, 36017n, 36037n, 36061n, 36067n, 36073n, 36083n, 36097n, 36107n, 36109n, 
		36131n, 36137n, 36151n, 36161n, 36187n, 36191n, 36209n, 36217n, 36229n, 36241n, 36251n, 
		36263n, 36269n, 36277n, 36293n, 36299n, 36307n, 36313n, 36319n, 36341n, 36343n, 36353n, 
		36373n, 36383n, 36389n, 36433n, 36451n, 36457n, 36467n, 36469n, 36473n, 36479n, 36493n, 
		36497n, 36523n, 36527n, 36529n, 36541n, 36551n, 36559n, 36563n, 36571n, 36583n, 36587n, 
		36599n, 36607n, 36629n, 36637n, 36643n, 36653n, 36671n, 36677n, 36683n, 36691n, 36697n, 
		36709n, 36713n, 36721n, 36739n, 36749n, 36761n, 36767n, 36779n, 36781n, 36787n, 36791n, 
		36793n, 36809n, 36821n, 36833n, 36847n, 36857n, 36871n, 36877n, 36887n, 36899n, 36901n, 
		36913n, 36919n, 36923n, 36929n, 36931n, 36943n, 36947n, 36973n, 36979n, 36997n, 37003n, 
		37013n, 37019n, 37021n, 37039n, 37049n, 37057n, 37061n, 37087n, 37097n, 37117n, 37123n, 
		37139n, 37159n, 37171n, 37181n, 37189n, 37199n, 37201n, 37217n, 37223n, 37243n, 37253n, 
		37273n, 37277n, 37307n, 37309n, 37313n, 37321n, 37337n, 37339n, 37357n, 37361n, 37363n, 
		37369n, 37379n, 37397n, 37409n, 37423n, 37441n, 37447n, 37463n, 37483n, 37489n, 37493n, 
		37501n, 37507n, 37511n, 37517n, 37529n, 37537n, 37547n, 37549n, 37561n, 37567n, 37571n, 
		37573n, 37579n, 37589n, 37591n, 37607n, 37619n, 37633n, 37643n, 37649n, 37657n, 37663n, 
		37691n, 37693n, 37699n, 37717n, 37747n, 37781n, 37783n, 37799n, 37811n, 37813n, 37831n, 
		37847n, 37853n, 37861n, 37871n, 37879n, 37889n, 37897n, 37907n, 37951n, 37957n, 37963n, 
		37967n, 37987n, 37991n, 37993n, 37997n, 38011n, 38039n, 38047n, 38053n, 38069n, 38083n, 
		38113n, 38119n, 38149n, 38153n, 38167n, 38177n, 38183n, 38189n, 38197n, 38201n, 38219n, 
		38231n, 38237n, 38239n, 38261n, 38273n, 38281n, 38287n, 38299n, 38303n, 38317n, 38321n, 
		38327n, 38329n, 38333n, 38351n, 38371n, 38377n, 38393n, 38431n, 38447n, 38449n, 38453n, 
		38459n, 38461n, 38501n, 38543n, 38557n, 38561n, 38567n, 38569n, 38593n, 38603n, 38609n, 
		38611n, 38629n, 38639n, 38651n, 38653n, 38669n, 38671n, 38677n, 38693n, 38699n, 38707n, 
		38711n, 38713n, 38723n, 38729n, 38737n, 38747n, 38749n, 38767n, 38783n, 38791n, 38803n, 
		38821n, 38833n, 38839n, 38851n, 38861n, 38867n, 38873n, 38891n, 38903n, 38917n, 38921n, 
		38923n, 38933n, 38953n, 38959n, 38971n, 38977n, 38993n, 39019n, 39023n, 39041n, 39043n, 
		39047n, 39079n, 39089n, 39097n, 39103n, 39107n, 39113n, 39119n, 39133n, 39139n, 39157n, 
		39161n, 39163n, 39181n, 39191n, 39199n, 39209n, 39217n, 39227n, 39229n, 39233n, 39239n, 
		39241n, 39251n, 39293n, 39301n, 39313n, 39317n, 39323n, 39341n, 39343n, 39359n, 39367n, 
		39371n, 39373n, 39383n, 39397n, 39409n, 39419n, 39439n, 39443n, 39451n, 39461n, 39499n, 
		39503n, 39509n, 39511n, 39521n, 39541n, 39551n, 39563n, 39569n, 39581n, 39607n, 39619n, 
		39623n, 39631n, 39659n, 39667n, 39671n, 39679n, 39703n, 39709n, 39719n, 39727n, 39733n, 
		39749n, 39761n, 39769n, 39779n, 39791n, 39799n, 39821n, 39827n, 39829n, 39839n, 39841n, 
		39847n, 39857n, 39863n, 39869n, 39877n, 39883n, 39887n, 39901n, 39929n, 39937n, 39953n, 
		39971n, 39979n, 39983n, 39989n, 
		
		40009n, 40013n, 40031n, 40037n, 40039n, 40063n, 40087n, 
		40093n, 40099n, 40111n, 40123n, 40127n, 40129n, 40151n, 40153n, 40163n, 40169n, 40177n, 
		40189n, 40193n, 40213n, 40231n, 40237n, 40241n, 40253n, 40277n, 40283n, 40289n, 40343n, 
		40351n, 40357n, 40361n, 40387n, 40423n, 40427n, 40429n, 40433n, 40459n, 40471n, 40483n, 
		40487n, 40493n, 40499n, 40507n, 40519n, 40529n, 40531n, 40543n, 40559n, 40577n, 40583n, 
		40591n, 40597n, 40609n, 40627n, 40637n, 40639n, 40693n, 40697n, 40699n, 40709n, 40739n, 
		40751n, 40759n, 40763n, 40771n, 40787n, 40801n, 40813n, 40819n, 40823n, 40829n, 40841n, 
		40847n, 40849n, 40853n, 40867n, 40879n, 40883n, 40897n, 40903n, 40927n, 40933n, 40939n, 
		40949n, 40961n, 40973n, 40993n, 41011n, 41017n, 41023n, 41039n, 41047n, 41051n, 41057n, 
		41077n, 41081n, 41113n, 41117n, 41131n, 41141n, 41143n, 41149n, 41161n, 41177n, 41179n, 
		41183n, 41189n, 41201n, 41203n, 41213n, 41221n, 41227n, 41231n, 41233n, 41243n, 41257n, 
		41263n, 41269n, 41281n, 41299n, 41333n, 41341n, 41351n, 41357n, 41381n, 41387n, 41389n, 
		41399n, 41411n, 41413n, 41443n, 41453n, 41467n, 41479n, 41491n, 41507n, 41513n, 41519n, 
		41521n, 41539n, 41543n, 41549n, 41579n, 41593n, 41597n, 41603n, 41609n, 41611n, 41617n, 
		41621n, 41627n, 41641n, 41647n, 41651n, 41659n, 41669n, 41681n, 41687n, 41719n, 41729n, 
		41737n, 41759n, 41761n, 41771n, 41777n, 41801n, 41809n, 41813n, 41843n, 41849n, 41851n, 
		41863n, 41879n, 41887n, 41893n, 41897n, 41903n, 41911n, 41927n, 41941n, 41947n, 41953n, 
		41957n, 41959n, 41969n, 41981n, 41983n, 41999n, 42013n, 42017n, 42019n, 42023n, 42043n, 
		42061n, 42071n, 42073n, 42083n, 42089n, 42101n, 42131n, 42139n, 42157n, 42169n, 42179n, 
		42181n, 42187n, 42193n, 42197n, 42209n, 42221n, 42223n, 42227n, 42239n, 42257n, 42281n, 
		42283n, 42293n, 42299n, 42307n, 42323n, 42331n, 42337n, 42349n, 42359n, 42373n, 42379n, 
		42391n, 42397n, 42403n, 42407n, 42409n, 42433n, 42437n, 42443n, 42451n, 42457n, 42461n, 
		42463n, 42467n, 42473n, 42487n, 42491n, 42499n, 42509n, 42533n, 42557n, 42569n, 42571n, 
		42577n, 42589n, 42611n, 42641n, 42643n, 42649n, 42667n, 42677n, 42683n, 42689n, 42697n, 
		42701n, 42703n, 42709n, 42719n, 42727n, 42737n, 42743n, 42751n, 42767n, 42773n, 42787n, 
		42793n, 42797n, 42821n, 42829n, 42839n, 42841n, 42853n, 42859n, 42863n, 42899n, 42901n, 
		42923n, 42929n, 42937n, 42943n, 42953n, 42961n, 42967n, 42979n, 42989n, 43003n, 43013n, 
		43019n, 43037n, 43049n, 43051n, 43063n, 43067n, 43093n, 43103n, 43117n, 43133n, 43151n, 
		43159n, 43177n, 43189n, 43201n, 43207n, 43223n, 43237n, 43261n, 43271n, 43283n, 43291n, 
		43313n, 43319n, 43321n, 43331n, 43391n, 43397n, 43399n, 43403n, 43411n, 43427n, 43441n, 
		43451n, 43457n, 43481n, 43487n, 43499n, 43517n, 43541n, 43543n, 43573n, 43577n, 43579n, 
		43591n, 43597n, 43607n, 43609n, 43613n, 43627n, 43633n, 43649n, 43651n, 43661n, 43669n, 
		43691n, 43711n, 43717n, 43721n, 43753n, 43759n, 43777n, 43781n, 43783n, 43787n, 43789n, 
		43793n, 43801n, 43853n, 43867n, 43889n, 43891n, 43913n, 43933n, 43943n, 43951n, 43961n, 
		43963n, 43969n, 43973n, 43987n, 43991n, 43997n, 44017n, 44021n, 44027n, 44029n, 44041n, 
		44053n, 44059n, 44071n, 44087n, 44089n, 44101n, 44111n, 44119n, 44123n, 44129n, 44131n, 
		44159n, 44171n, 44179n, 44189n, 44201n, 44203n, 44207n, 44221n, 44249n, 44257n, 44263n, 
		44267n, 44269n, 44273n, 44279n, 44281n, 44293n, 44351n, 44357n, 44371n, 44381n, 44383n, 
		44389n, 44417n, 44449n, 44453n, 44483n, 44491n, 44497n, 44501n, 44507n, 44519n, 44531n, 
		44533n, 44537n, 44543n, 44549n, 44563n, 44579n, 44587n, 44617n, 44621n, 44623n, 44633n, 
		44641n, 44647n, 44651n, 44657n, 44683n, 44687n, 44699n, 44701n, 44711n, 44729n, 44741n, 
		44753n, 44771n, 44773n, 44777n, 44789n, 44797n, 44809n, 44819n, 44839n, 44843n, 44851n, 
		44867n, 44879n, 44887n, 44893n, 44909n, 44917n, 44927n, 44939n, 44953n, 44959n, 44963n, 
		44971n, 44983n, 44987n, 45007n, 45013n, 45053n, 45061n, 45077n, 45083n, 45119n, 45121n, 
		45127n, 45131n, 45137n, 45139n, 45161n, 45179n, 45181n, 45191n, 45197n, 45233n, 45247n, 
		45259n, 45263n, 45281n, 45289n, 45293n, 45307n, 45317n, 45319n, 45329n, 45337n, 45341n, 
		45343n, 45361n, 45377n, 45389n, 45403n, 45413n, 45427n, 45433n, 45439n, 45481n, 45491n, 
		45497n, 45503n, 45523n, 45533n, 45541n, 45553n, 45557n, 45569n, 45587n, 45589n, 45599n, 
		45613n, 45631n, 45641n, 45659n, 45667n, 45673n, 45677n, 45691n, 45697n, 45707n, 45737n, 
		45751n, 45757n, 45763n, 45767n, 45779n, 45817n, 45821n, 45823n, 45827n, 45833n, 45841n, 
		45853n, 45863n, 45869n, 45887n, 45893n, 45943n, 45949n, 45953n, 45959n, 45971n, 45979n, 
		45989n, 46021n, 46027n, 46049n, 46051n, 46061n, 46073n, 46091n, 46093n, 46099n, 46103n, 
		46133n, 46141n, 46147n, 46153n, 46171n, 46181n, 46183n, 46187n, 46199n, 46219n, 46229n, 
		46237n, 46261n, 46271n, 46273n, 46279n, 46301n, 46307n, 46309n, 46327n, 46337n, 46349n, 
		46351n, 46381n, 46399n, 46411n, 46439n, 46441n, 46447n, 46451n, 46457n, 46471n, 46477n, 
		46489n, 46499n, 46507n, 46511n, 46523n, 46549n, 46559n, 46567n, 46573n, 46589n, 46591n, 
		46601n, 46619n, 46633n, 46639n, 46643n, 46649n, 46663n, 46679n, 46681n, 46687n, 46691n, 
		46703n, 46723n, 46727n, 46747n, 46751n, 46757n, 46769n, 46771n, 46807n, 46811n, 46817n, 
		46819n, 46829n, 46831n, 46853n, 46861n, 46867n, 46877n, 46889n, 46901n, 46919n, 46933n, 
		46957n, 46993n, 46997n, 47017n, 47041n, 47051n, 47057n, 47059n, 47087n, 47093n, 47111n, 
		47119n, 47123n, 47129n, 47137n, 47143n, 47147n, 47149n, 47161n, 47189n, 47207n, 47221n, 
		47237n, 47251n, 47269n, 47279n, 47287n, 47293n, 47297n, 47303n, 47309n, 47317n, 47339n, 
		47351n, 47353n, 47363n, 47381n, 47387n, 47389n, 47407n, 47417n, 47419n, 47431n, 47441n, 
		47459n, 47491n, 47497n, 47501n, 47507n, 47513n, 47521n, 47527n, 47533n, 47543n, 47563n, 
		47569n, 47581n, 47591n, 47599n, 47609n, 47623n, 47629n, 47639n, 47653n, 47657n, 47659n, 
		47681n, 47699n, 47701n, 47711n, 47713n, 47717n, 47737n, 47741n, 47743n, 47777n, 47779n, 
		47791n, 47797n, 47807n, 47809n, 47819n, 47837n, 47843n, 47857n, 47869n, 47881n, 47903n, 
		47911n, 47917n, 47933n, 47939n, 47947n, 47951n, 47963n, 47969n, 47977n, 47981n, 48017n, 
		48023n, 48029n, 48049n, 48073n, 48079n, 48091n, 48109n, 48119n, 48121n, 48131n, 48157n, 
		48163n, 48179n, 48187n, 48193n, 48197n, 48221n, 48239n, 48247n, 48259n, 48271n, 48281n, 
		48299n, 48311n, 48313n, 48337n, 48341n, 48353n, 48371n, 48383n, 48397n, 48407n, 48409n, 
		48413n, 48437n, 48449n, 48463n, 48473n, 48479n, 48481n, 48487n, 48491n, 48497n, 48523n, 
		48527n, 48533n, 48539n, 48541n, 48563n, 48571n, 48589n, 48593n, 48611n, 48619n, 48623n, 
		48647n, 48649n, 48661n, 48673n, 48677n, 48679n, 48731n, 48733n, 48751n, 48757n, 48761n, 
		48767n, 48779n, 48781n, 48787n, 48799n, 48809n, 48817n, 48821n, 48823n, 48847n, 48857n, 
		48859n, 48869n, 48871n, 48883n, 48889n, 48907n, 48947n, 48953n, 48973n, 48989n, 48991n, 
		49003n, 49009n, 49019n, 49031n, 49033n, 49037n, 49043n, 49057n, 49069n, 49081n, 49103n, 
		49109n, 49117n, 49121n, 49123n, 49139n, 49157n, 49169n, 49171n, 49177n, 49193n, 49199n, 
		49201n, 49207n, 49211n, 49223n, 49253n, 49261n, 49277n, 49279n, 49297n, 49307n, 49331n, 
		49333n, 49339n, 49363n, 49367n, 49369n, 49391n, 49393n, 49409n, 49411n, 49417n, 49429n, 
		49433n, 49451n, 49459n, 49463n, 49477n, 49481n, 49499n, 49523n, 49529n, 49531n, 49537n, 
		49547n, 49549n, 49559n, 49597n, 49603n, 49613n, 49627n, 49633n, 49639n, 49663n, 49667n, 
		49669n, 49681n, 49697n, 49711n, 49727n, 49739n, 49741n, 49747n, 49757n, 49783n, 49787n, 
		49789n, 49801n, 49807n, 49811n, 49823n, 49831n, 49843n, 49853n, 49871n, 49877n, 49891n, 
		49919n, 49921n, 49927n, 49937n, 49939n, 49943n, 49957n, 49991n, 49993n, 49999n, 
		
		50021n, 
		50023n, 50033n, 50047n, 50051n, 50053n, 50069n, 50077n, 50087n, 50093n, 50101n, 50111n, 
		50119n, 50123n, 50129n, 50131n, 50147n, 50153n, 50159n, 50177n, 50207n, 50221n, 50227n, 
		50231n, 50261n, 50263n, 50273n, 50287n, 50291n, 50311n, 50321n, 50329n, 50333n, 50341n, 
		50359n, 50363n, 50377n, 50383n, 50387n, 50411n, 50417n, 50423n, 50441n, 50459n, 50461n, 
		50497n, 50503n, 50513n, 50527n, 50539n, 50543n, 50549n, 50551n, 50581n, 50587n, 50591n, 
		50593n, 50599n, 50627n, 50647n, 50651n, 50671n, 50683n, 50707n, 50723n, 50741n, 50753n, 
		50767n, 50773n, 50777n, 50789n, 50821n, 50833n, 50839n, 50849n, 50857n, 50867n, 50873n, 
		50891n, 50893n, 50909n, 50923n, 50929n, 50951n, 50957n, 50969n, 50971n, 50989n, 50993n, 
		51001n, 51031n, 51043n, 51047n, 51059n, 51061n, 51071n, 51109n, 51131n, 51133n, 51137n, 
		51151n, 51157n, 51169n, 51193n, 51197n, 51199n, 51203n, 51217n, 51229n, 51239n, 51241n, 
		51257n, 51263n, 51283n, 51287n, 51307n, 51329n, 51341n, 51343n, 51347n, 51349n, 51361n, 
		51383n, 51407n, 51413n, 51419n, 51421n, 51427n, 51431n, 51437n, 51439n, 51449n, 51461n, 
		51473n, 51479n, 51481n, 51487n, 51503n, 51511n, 51517n, 51521n, 51539n, 51551n, 51563n, 
		51577n, 51581n, 51593n, 51599n, 51607n, 51613n, 51631n, 51637n, 51647n, 51659n, 51673n, 
		51679n, 51683n, 51691n, 51713n, 51719n, 51721n, 51749n, 51767n, 51769n, 51787n, 51797n, 
		51803n, 51817n, 51827n, 51829n, 51839n, 51853n, 51859n, 51869n, 51871n, 51893n, 51899n, 
		51907n, 51913n, 51929n, 51941n, 51949n, 51971n, 51973n, 51977n, 51991n, 52009n, 52021n, 
		52027n, 52051n, 52057n, 52067n, 52069n, 52081n, 52103n, 52121n, 52127n, 52147n, 52153n, 
		52163n, 52177n, 52181n, 52183n, 52189n, 52201n, 52223n, 52237n, 52249n, 52253n, 52259n, 
		52267n, 52289n, 52291n, 52301n, 52313n, 52321n, 52361n, 52363n, 52369n, 52379n, 52387n, 
		52391n, 52433n, 52453n, 52457n, 52489n, 52501n, 52511n, 52517n, 52529n, 52541n, 52543n, 
		52553n, 52561n, 52567n, 52571n, 52579n, 52583n, 52609n, 52627n, 52631n, 52639n, 52667n, 
		52673n, 52691n, 52697n, 52709n, 52711n, 52721n, 52727n, 52733n, 52747n, 52757n, 52769n, 
		52783n, 52807n, 52813n, 52817n, 52837n, 52859n, 52861n, 52879n, 52883n, 52889n, 52901n, 
		52903n, 52919n, 52937n, 52951n, 52957n, 52963n, 52967n, 52973n, 52981n, 52999n, 53003n, 
		53017n, 53047n, 53051n, 53069n, 53077n, 53087n, 53089n, 53093n, 53101n, 53113n, 53117n, 
		53129n, 53147n, 53149n, 53161n, 53171n, 53173n, 53189n, 53197n, 53201n, 53231n, 53233n, 
		53239n, 53267n, 53269n, 53279n, 53281n, 53299n, 53309n, 53323n, 53327n, 53353n, 53359n, 
		53377n, 53381n, 53401n, 53407n, 53411n, 53419n, 53437n, 53441n, 53453n, 53479n, 53503n, 
		53507n, 53527n, 53549n, 53551n, 53569n, 53591n, 53593n, 53597n, 53609n, 53611n, 53617n, 
		53623n, 53629n, 53633n, 53639n, 53653n, 53657n, 53681n, 53693n, 53699n, 53717n, 53719n, 
		53731n, 53759n, 53773n, 53777n, 53783n, 53791n, 53813n, 53819n, 53831n, 53849n, 53857n, 
		53861n, 53881n, 53887n, 53891n, 53897n, 53899n, 53917n, 53923n, 53927n, 53939n, 53951n, 
		53959n, 53987n, 53993n, 54001n, 54011n, 54013n, 54037n, 54049n, 54059n, 54083n, 54091n, 
		54101n, 54121n, 54133n, 54139n, 54151n, 54163n, 54167n, 54181n, 54193n, 54217n, 54251n, 
		54269n, 54277n, 54287n, 54293n, 54311n, 54319n, 54323n, 54331n, 54347n, 54361n, 54367n, 
		54371n, 54377n, 54401n, 54403n, 54409n, 54413n, 54419n, 54421n, 54437n, 54443n, 54449n, 
		54469n, 54493n, 54497n, 54499n, 54503n, 54517n, 54521n, 54539n, 54541n, 54547n, 54559n, 
		54563n, 54577n, 54581n, 54583n, 54601n, 54617n, 54623n, 54629n, 54631n, 54647n, 54667n, 
		54673n, 54679n, 54709n, 54713n, 54721n, 54727n, 54751n, 54767n, 54773n, 54779n, 54787n, 
		54799n, 54829n, 54833n, 54851n, 54869n, 54877n, 54881n, 54907n, 54917n, 54919n, 54941n, 
		54949n, 54959n, 54973n, 54979n, 54983n, 55001n, 55009n, 55021n, 55049n, 55051n, 55057n, 
		55061n, 55073n, 55079n, 55103n, 55109n, 55117n, 55127n, 55147n, 55163n, 55171n, 55201n, 
		55207n, 55213n, 55217n, 55219n, 55229n, 55243n, 55249n, 55259n, 55291n, 55313n, 55331n, 
		55333n, 55337n, 55339n, 55343n, 55351n, 55373n, 55381n, 55399n, 55411n, 55439n, 55441n, 
		55457n, 55469n, 55487n, 55501n, 55511n, 55529n, 55541n, 55547n, 55579n, 55589n, 55603n, 
		55609n, 55619n, 55621n, 55631n, 55633n, 55639n, 55661n, 55663n, 55667n, 55673n, 55681n, 
		55691n, 55697n, 55711n, 55717n, 55721n, 55733n, 55763n, 55787n, 55793n, 55799n, 55807n, 
		55813n, 55817n, 55819n, 55823n, 55829n, 55837n, 55843n, 55849n, 55871n, 55889n, 55897n, 
		55901n, 55903n, 55921n, 55927n, 55931n, 55933n, 55949n, 55967n, 55987n, 55997n, 56003n, 
		56009n, 56039n, 56041n, 56053n, 56081n, 56087n, 56093n, 56099n, 56101n, 56113n, 56123n, 
		56131n, 56149n, 56167n, 56171n, 56179n, 56197n, 56207n, 56209n, 56237n, 56239n, 56249n, 
		56263n, 56267n, 56269n, 56299n, 56311n, 56333n, 56359n, 56369n, 56377n, 56383n, 56393n, 
		56401n, 56417n, 56431n, 56437n, 56443n, 56453n, 56467n, 56473n, 56477n, 56479n, 56489n, 
		56501n, 56503n, 56509n, 56519n, 56527n, 56531n, 56533n, 56543n, 56569n, 56591n, 56597n, 
		56599n, 56611n, 56629n, 56633n, 56659n, 56663n, 56671n, 56681n, 56687n, 56701n, 56711n, 
		56713n, 56731n, 56737n, 56747n, 56767n, 56773n, 56779n, 56783n, 56807n, 56809n, 56813n, 
		56821n, 56827n, 56843n, 56857n, 56873n, 56891n, 56893n, 56897n, 56909n, 56911n, 56921n, 
		56923n, 56929n, 56941n, 56951n, 56957n, 56963n, 56983n, 56989n, 56993n, 56999n, 57037n, 
		57041n, 57047n, 57059n, 57073n, 57077n, 57089n, 57097n, 57107n, 57119n, 57131n, 57139n, 
		57143n, 57149n, 57163n, 57173n, 57179n, 57191n, 57193n, 57203n, 57221n, 57223n, 57241n, 
		57251n, 57259n, 57269n, 57271n, 57283n, 57287n, 57301n, 57329n, 57331n, 57347n, 57349n, 
		57367n, 57373n, 57383n, 57389n, 57397n, 57413n, 57427n, 57457n, 57467n, 57487n, 57493n, 
		57503n, 57527n, 57529n, 57557n, 57559n, 57571n, 57587n, 57593n, 57601n, 57637n, 57641n, 
		57649n, 57653n, 57667n, 57679n, 57689n, 57697n, 57709n, 57713n, 57719n, 57727n, 57731n, 
		57737n, 57751n, 57773n, 57781n, 57787n, 57791n, 57793n, 57803n, 57809n, 57829n, 57839n, 
		57847n, 57853n, 57859n, 57881n, 57899n, 57901n, 57917n, 57923n, 57943n, 57947n, 57973n, 
		57977n, 57991n, 58013n, 58027n, 58031n, 58043n, 58049n, 58057n, 58061n, 58067n, 58073n, 
		58099n, 58109n, 58111n, 58129n, 58147n, 58151n, 58153n, 58169n, 58171n, 58189n, 58193n, 
		58199n, 58207n, 58211n, 58217n, 58229n, 58231n, 58237n, 58243n, 58271n, 58309n, 58313n, 
		58321n, 58337n, 58363n, 58367n, 58369n, 58379n, 58391n, 58393n, 58403n, 58411n, 58417n, 
		58427n, 58439n, 58441n, 58451n, 58453n, 58477n, 58481n, 58511n, 58537n, 58543n, 58549n, 
		58567n, 58573n, 58579n, 58601n, 58603n, 58613n, 58631n, 58657n, 58661n, 58679n, 58687n, 
		58693n, 58699n, 58711n, 58727n, 58733n, 58741n, 58757n, 58763n, 58771n, 58787n, 58789n, 
		58831n, 58889n, 58897n, 58901n, 58907n, 58909n, 58913n, 58921n, 58937n, 58943n, 58963n, 
		58967n, 58979n, 58991n, 58997n, 59009n, 59011n, 59021n, 59023n, 59029n, 59051n, 59053n, 
		59063n, 59069n, 59077n, 59083n, 59093n, 59107n, 59113n, 59119n, 59123n, 59141n, 59149n, 
		59159n, 59167n, 59183n, 59197n, 59207n, 59209n, 59219n, 59221n, 59233n, 59239n, 59243n, 
		59263n, 59273n, 59281n, 59333n, 59341n, 59351n, 59357n, 59359n, 59369n, 59377n, 59387n, 
		59393n, 59399n, 59407n, 59417n, 59419n, 59441n, 59443n, 59447n, 59453n, 59467n, 59471n, 
		59473n, 59497n, 59509n, 59513n, 59539n, 59557n, 59561n, 59567n, 59581n, 59611n, 59617n, 
		59621n, 59627n, 59629n, 59651n, 59659n, 59663n, 59669n, 59671n, 59693n, 59699n, 59707n, 
		59723n, 59729n, 59743n, 59747n, 59753n, 59771n, 59779n, 59791n, 59797n, 59809n, 59833n, 
		59863n, 59879n, 59887n, 59921n, 59929n, 59951n, 59957n, 59971n, 59981n, 59999n, 
		
		60013n, 
		60017n, 60029n, 60037n, 60041n, 60077n, 60083n, 60089n, 60091n, 60101n, 60103n, 60107n, 
		60127n, 60133n, 60139n, 60149n, 60161n, 60167n, 60169n, 60209n, 60217n, 60223n, 60251n, 
		60257n, 60259n, 60271n, 60289n, 60293n, 60317n, 60331n, 60337n, 60343n, 60353n, 60373n, 
		60383n, 60397n, 60413n, 60427n, 60443n, 60449n, 60457n, 60493n, 60497n, 60509n, 60521n, 
		60527n, 60539n, 60589n, 60601n, 60607n, 60611n, 60617n, 60623n, 60631n, 60637n, 60647n, 
		60649n, 60659n, 60661n, 60679n, 60689n, 60703n, 60719n, 60727n, 60733n, 60737n, 60757n, 
		60761n, 60763n, 60773n, 60779n, 60793n, 60811n, 60821n, 60859n, 60869n, 60887n, 60889n, 
		60899n, 60901n, 60913n, 60917n, 60919n, 60923n, 60937n, 60943n, 60953n, 60961n, 61001n, 
		61007n, 61027n, 61031n, 61043n, 61051n, 61057n, 61091n, 61099n, 61121n, 61129n, 61141n, 
		61151n, 61153n, 61169n, 61211n, 61223n, 61231n, 61253n, 61261n, 61283n, 61291n, 61297n, 
		61331n, 61333n, 61339n, 61343n, 61357n, 61363n, 61379n, 61381n, 61403n, 61409n, 61417n, 
		61441n, 61463n, 61469n, 61471n, 61483n, 61487n, 61493n, 61507n, 61511n, 61519n, 61543n, 
		61547n, 61553n, 61559n, 61561n, 61583n, 61603n, 61609n, 61613n, 61627n, 61631n, 61637n, 
		61643n, 61651n, 61657n, 61667n, 61673n, 61681n, 61687n, 61703n, 61717n, 61723n, 61729n, 
		61751n, 61757n, 61781n, 61813n, 61819n, 61837n, 61843n, 61861n, 61871n, 61879n, 61909n, 
		61927n, 61933n, 61949n, 61961n, 61967n, 61979n, 61981n, 61987n, 61991n, 62003n, 62011n, 
		62017n, 62039n, 62047n, 62053n, 62057n, 62071n, 62081n, 62099n, 62119n, 62129n, 62131n, 
		62137n, 62141n, 62143n, 62171n, 62189n, 62191n, 62201n, 62207n, 62213n, 62219n, 62233n, 
		62273n, 62297n, 62299n, 62303n, 62311n, 62323n, 62327n, 62347n, 62351n, 62383n, 62401n, 
		62417n, 62423n, 62459n, 62467n, 62473n, 62477n, 62483n, 62497n, 62501n, 62507n, 62533n, 
		62539n, 62549n, 62563n, 62581n, 62591n, 62597n, 62603n, 62617n, 62627n, 62633n, 62639n, 
		62653n, 62659n, 62683n, 62687n, 62701n, 62723n, 62731n, 62743n, 62753n, 62761n, 62773n, 
		62791n, 62801n, 62819n, 62827n, 62851n, 62861n, 62869n, 62873n, 62897n, 62903n, 62921n, 
		62927n, 62929n, 62939n, 62969n, 62971n, 62981n, 62983n, 62987n, 62989n, 63029n, 63031n, 
		63059n, 63067n, 63073n, 63079n, 63097n, 63103n, 63113n, 63127n, 63131n, 63149n, 63179n, 
		63197n, 63199n, 63211n, 63241n, 63247n, 63277n, 63281n, 63299n, 63311n, 63313n, 63317n, 
		63331n, 63337n, 63347n, 63353n, 63361n, 63367n, 63377n, 63389n, 63391n, 63397n, 63409n, 
		63419n, 63421n, 63439n, 63443n, 63463n, 63467n, 63473n, 63487n, 63493n, 63499n, 63521n, 
		63527n, 63533n, 63541n, 63559n, 63577n, 63587n, 63589n, 63599n, 63601n, 63607n, 63611n, 
		63617n, 63629n, 63647n, 63649n, 63659n, 63667n, 63671n, 63689n, 63691n, 63697n, 63703n, 
		63709n, 63719n, 63727n, 63737n, 63743n, 63761n, 63773n, 63781n, 63793n, 63799n, 63803n, 
		63809n, 63823n, 63839n, 63841n, 63853n, 63857n, 63863n, 63901n, 63907n, 63913n, 63929n, 
		63949n, 63977n, 63997n, 64007n, 64013n, 64019n, 64033n, 64037n, 64063n, 64067n, 64081n, 
		64091n, 64109n, 64123n, 64151n, 64153n, 64157n, 64171n, 64187n, 64189n, 64217n, 64223n, 
		64231n, 64237n, 64271n, 64279n, 64283n, 64301n, 64303n, 64319n, 64327n, 64333n, 64373n, 
		64381n, 64399n, 64403n, 64433n, 64439n, 64451n, 64453n, 64483n, 64489n, 64499n, 64513n, 
		64553n, 64567n, 64577n, 64579n, 64591n, 64601n, 64609n, 64613n, 64621n, 64627n, 64633n, 
		64661n, 64663n, 64667n, 64679n, 64693n, 64709n, 64717n, 64747n, 64763n, 64781n, 64783n, 
		64793n, 64811n, 64817n, 64849n, 64853n, 64871n, 64877n, 64879n, 64891n, 64901n, 64919n, 
		64921n, 64927n, 64937n, 64951n, 64969n, 64997n, 65003n, 65011n, 65027n, 65029n, 65033n, 
		65053n, 65063n, 65071n, 65089n, 65099n, 65101n, 65111n, 65119n, 65123n, 65129n, 65141n, 
		65147n, 65167n, 65171n, 65173n, 65179n, 65183n, 65203n, 65213n, 65239n, 65257n, 65267n, 
		65269n, 65287n, 65293n, 65309n, 65323n, 65327n, 65353n, 65357n, 65371n, 65381n, 65393n, 
		65407n, 65413n, 65419n, 65423n, 65437n, 65447n, 65449n, 65479n, 65497n, 65519n, 65521n, 
		65537n, 65539n, 65543n, 65551n, 65557n, 65563n, 65579n, 65581n, 65587n, 65599n, 65609n, 
		65617n, 65629n, 65633n, 65647n, 65651n, 65657n, 65677n, 65687n, 65699n, 65701n, 65707n, 
		65713n, 65717n, 65719n, 65729n, 65731n, 65761n, 65777n, 65789n, 65809n, 65827n, 65831n, 
		65837n, 65839n, 65843n, 65851n, 65867n, 65881n, 65899n, 65921n, 65927n, 65929n, 65951n, 
		65957n, 65963n, 65981n, 65983n, 65993n, 66029n, 66037n, 66041n, 66047n, 66067n, 66071n, 
		66083n, 66089n, 66103n, 66107n, 66109n, 66137n, 66161n, 66169n, 66173n, 66179n, 66191n, 
		66221n, 66239n, 66271n, 66293n, 66301n, 66337n, 66343n, 66347n, 66359n, 66361n, 66373n, 
		66377n, 66383n, 66403n, 66413n, 66431n, 66449n, 66457n, 66463n, 66467n, 66491n, 66499n, 
		66509n, 66523n, 66529n, 66533n, 66541n, 66553n, 66569n, 66571n, 66587n, 66593n, 66601n, 
		66617n, 66629n, 66643n, 66653n, 66683n, 66697n, 66701n, 66713n, 66721n, 66733n, 66739n, 
		66749n, 66751n, 66763n, 66791n, 66797n, 66809n, 66821n, 66841n, 66851n, 66853n, 66863n, 
		66877n, 66883n, 66889n, 66919n, 66923n, 66931n, 66943n, 66947n, 66949n, 66959n, 66973n, 
		66977n, 67003n, 67021n, 67033n, 67043n, 67049n, 67057n, 67061n, 67073n, 67079n, 67103n, 
		67121n, 67129n, 67139n, 67141n, 67153n, 67157n, 67169n, 67181n, 67187n, 67189n, 67211n, 
		67213n, 67217n, 67219n, 67231n, 67247n, 67261n, 67271n, 67273n, 67289n, 67307n, 67339n, 
		67343n, 67349n, 67369n, 67391n, 67399n, 67409n, 67411n, 67421n, 67427n, 67429n, 67433n, 
		67447n, 67453n, 67477n, 67481n, 67489n, 67493n, 67499n, 67511n, 67523n, 67531n, 67537n, 
		67547n, 67559n, 67567n, 67577n, 67579n, 67589n, 67601n, 67607n, 67619n, 67631n, 67651n, 
		67679n, 67699n, 67709n, 67723n, 67733n, 67741n, 67751n, 67757n, 67759n, 67763n, 67777n, 
		67783n, 67789n, 67801n, 67807n, 67819n, 67829n, 67843n, 67853n, 67867n, 67883n, 67891n, 
		67901n, 67927n, 67931n, 67933n, 67939n, 67943n, 67957n, 67961n, 67967n, 67979n, 67987n, 
		67993n, 68023n, 68041n, 68053n, 68059n, 68071n, 68087n, 68099n, 68111n, 68113n, 68141n, 
		68147n, 68161n, 68171n, 68207n, 68209n, 68213n, 68219n, 68227n, 68239n, 68261n, 68279n, 
		68281n, 68311n, 68329n, 68351n, 68371n, 68389n, 68399n, 68437n, 68443n, 68447n, 68449n, 
		68473n, 68477n, 68483n, 68489n, 68491n, 68501n, 68507n, 68521n, 68531n, 68539n, 68543n, 
		68567n, 68581n, 68597n, 68611n, 68633n, 68639n, 68659n, 68669n, 68683n, 68687n, 68699n, 
		68711n, 68713n, 68729n, 68737n, 68743n, 68749n, 68767n, 68771n, 68777n, 68791n, 68813n, 
		68819n, 68821n, 68863n, 68879n, 68881n, 68891n, 68897n, 68899n, 68903n, 68909n, 68917n, 
		68927n, 68947n, 68963n, 68993n, 69001n, 69011n, 69019n, 69029n, 69031n, 69061n, 69067n, 
		69073n, 69109n, 69119n, 69127n, 69143n, 69149n, 69151n, 69163n, 69191n, 69193n, 69197n, 
		69203n, 69221n, 69233n, 69239n, 69247n, 69257n, 69259n, 69263n, 69313n, 69317n, 69337n, 
		69341n, 69371n, 69379n, 69383n, 69389n, 69401n, 69403n, 69427n, 69431n, 69439n, 69457n, 
		69463n, 69467n, 69473n, 69481n, 69491n, 69493n, 69497n, 69499n, 69539n, 69557n, 69593n, 
		69623n, 69653n, 69661n, 69677n, 69691n, 69697n, 69709n, 69737n, 69739n, 69761n, 69763n, 
		69767n, 69779n, 69809n, 69821n, 69827n, 69829n, 69833n, 69847n, 69857n, 69859n, 69877n, 
		69899n, 69911n, 69929n, 69931n, 69941n, 69959n, 69991n, 69997n, 
		
		70001n, 70003n, 70009n, 
		70019n, 70039n, 70051n, 70061n, 70067n, 70079n, 70099n, 70111n, 70117n, 70121n, 70123n, 
		70139n, 70141n, 70157n, 70163n, 70177n, 70181n, 70183n, 70199n, 70201n, 70207n, 70223n, 
		70229n, 70237n, 70241n, 70249n, 70271n, 70289n, 70297n, 70309n, 70313n, 70321n, 70327n, 
		70351n, 70373n, 70379n, 70381n, 70393n, 70423n, 70429n, 70439n, 70451n, 70457n, 70459n, 
		70481n, 70487n, 70489n, 70501n, 70507n, 70529n, 70537n, 70549n, 70571n, 70573n, 70583n, 
		70589n, 70607n, 70619n, 70621n, 70627n, 70639n, 70657n, 70663n, 70667n, 70687n, 70709n, 
		70717n, 70729n, 70753n, 70769n, 70783n, 70793n, 70823n, 70841n, 70843n, 70849n, 70853n, 
		70867n, 70877n, 70879n, 70891n, 70901n, 70913n, 70919n, 70921n, 70937n, 70949n, 70951n, 
		70957n, 70969n, 70979n, 70981n, 70991n, 70997n, 70999n, 71011n, 71023n, 71039n, 71059n, 
		71069n, 71081n, 71089n, 71119n, 71129n, 71143n, 71147n, 71153n, 71161n, 71167n, 71171n, 
		71191n, 71209n, 71233n, 71237n, 71249n, 71257n, 71261n, 71263n, 71287n, 71293n, 71317n, 
		71327n, 71329n, 71333n, 71339n, 71341n, 71347n, 71353n, 71359n, 71363n, 71387n, 71389n, 
		71399n, 71411n, 71413n, 71419n, 71429n, 71437n, 71443n, 71453n, 71471n, 71473n, 71479n, 
		71483n, 71503n, 71527n, 71537n, 71549n, 71551n, 71563n, 71569n, 71593n, 71597n, 71633n, 
		71647n, 71663n, 71671n, 71693n, 71699n, 71707n, 71711n, 71713n, 71719n, 71741n, 71761n, 
		71777n, 71789n, 71807n, 71809n, 71821n, 71837n, 71843n, 71849n, 71861n, 71867n, 71879n, 
		71881n, 71887n, 71899n, 71909n, 71917n, 71933n, 71941n, 71947n, 71963n, 71971n, 71983n, 
		71987n, 71993n, 71999n, 72019n, 72031n, 72043n, 72047n, 72053n, 72073n, 72077n, 72089n, 
		72091n, 72101n, 72103n, 72109n, 72139n, 72161n, 72167n, 72169n, 72173n, 72211n, 72221n, 
		72223n, 72227n, 72229n, 72251n, 72253n, 72269n, 72271n, 72277n, 72287n, 72307n, 72313n, 
		72337n, 72341n, 72353n, 72367n, 72379n, 72383n, 72421n, 72431n, 72461n, 72467n, 72469n, 
		72481n, 72493n, 72497n, 72503n, 72533n, 72547n, 72551n, 72559n, 72577n, 72613n, 72617n, 
		72623n, 72643n, 72647n, 72649n, 72661n, 72671n, 72673n, 72679n, 72689n, 72701n, 72707n, 
		72719n, 72727n, 72733n, 72739n, 72763n, 72767n, 72797n, 72817n, 72823n, 72859n, 72869n, 
		72871n, 72883n, 72889n, 72893n, 72901n, 72907n, 72911n, 72923n, 72931n, 72937n, 72949n, 
		72953n, 72959n, 72973n, 72977n, 72997n, 73009n, 73013n, 73019n, 73037n, 73039n, 73043n, 
		73061n, 73063n, 73079n, 73091n, 73121n, 73127n, 73133n, 73141n, 73181n, 73189n, 73237n, 
		73243n, 73259n, 73277n, 73291n, 73303n, 73309n, 73327n, 73331n, 73351n, 73361n, 73363n, 
		73369n, 73379n, 73387n, 73417n, 73421n, 73433n, 73453n, 73459n, 73471n, 73477n, 73483n, 
		73517n, 73523n, 73529n, 73547n, 73553n, 73561n, 73571n, 73583n, 73589n, 73597n, 73607n, 
		73609n, 73613n, 73637n, 73643n, 73651n, 73673n, 73679n, 73681n, 73693n, 73699n, 73709n, 
		73721n, 73727n, 73751n, 73757n, 73771n, 73783n, 73819n, 73823n, 73847n, 73849n, 73859n, 
		73867n, 73877n, 73883n, 73897n, 73907n, 73939n, 73943n, 73951n, 73961n, 73973n, 73999n, 
		74017n, 74021n, 74027n, 74047n, 74051n, 74071n, 74077n, 74093n, 74099n, 74101n, 74131n, 
		74143n, 74149n, 74159n, 74161n, 74167n, 74177n, 74189n, 74197n, 74201n, 74203n, 74209n, 
		74219n, 74231n, 74257n, 74279n, 74287n, 74293n, 74297n, 74311n, 74317n, 74323n, 74353n, 
		74357n, 74363n, 74377n, 74381n, 74383n, 74411n, 74413n, 74419n, 74441n, 74449n, 74453n, 
		74471n, 74489n, 74507n, 74509n, 74521n, 74527n, 74531n, 74551n, 74561n, 74567n, 74573n, 
		74587n, 74597n, 74609n, 74611n, 74623n, 74653n, 74687n, 74699n, 74707n, 74713n, 74717n, 
		74719n, 74729n, 74731n, 74747n, 74759n, 74761n, 74771n, 74779n, 74797n, 74821n, 74827n, 
		74831n, 74843n, 74857n, 74861n, 74869n, 74873n, 74887n, 74891n, 74897n, 74903n, 74923n, 
		74929n, 74933n, 74941n, 74959n, 75011n, 75013n, 75017n, 75029n, 75037n, 75041n, 75079n, 
		75083n, 75109n, 75133n, 75149n, 75161n, 75167n, 75169n, 75181n, 75193n, 75209n, 75211n, 
		75217n, 75223n, 75227n, 75239n, 75253n, 75269n, 75277n, 75289n, 75307n, 75323n, 75329n, 
		75337n, 75347n, 75353n, 75367n, 75377n, 75389n, 75391n, 75401n, 75403n, 75407n, 75431n, 
		75437n, 75479n, 75503n, 75511n, 75521n, 75527n, 75533n, 75539n, 75541n, 75553n, 75557n, 
		75571n, 75577n, 75583n, 75611n, 75617n, 75619n, 75629n, 75641n, 75653n, 75659n, 75679n, 
		75683n, 75689n, 75703n, 75707n, 75709n, 75721n, 75731n, 75743n, 75767n, 75773n, 75781n, 
		75787n, 75793n, 75797n, 75821n, 75833n, 75853n, 75869n, 75883n, 75913n, 75931n, 75937n, 
		75941n, 75967n, 75979n, 75983n, 75989n, 75991n, 75997n, 76001n, 76003n, 76031n, 76039n, 
		76079n, 76081n, 76091n, 76099n, 76103n, 76123n, 76129n, 76147n, 76157n, 76159n, 76163n, 
		76207n, 76213n, 76231n, 76243n, 76249n, 76253n, 76259n, 76261n, 76283n, 76289n, 76303n, 
		76333n, 76343n, 76367n, 76369n, 76379n, 76387n, 76403n, 76421n, 76423n, 76441n, 76463n, 
		76471n, 76481n, 76487n, 76493n, 76507n, 76511n, 76519n, 76537n, 76541n, 76543n, 76561n, 
		76579n, 76597n, 76603n, 76607n, 76631n, 76649n, 76651n, 76667n, 76673n, 76679n, 76697n, 
		76717n, 76733n, 76753n, 76757n, 76771n, 76777n, 76781n, 76801n, 76819n, 76829n, 76831n, 
		76837n, 76847n, 76871n, 76873n, 76883n, 76907n, 76913n, 76919n, 76943n, 76949n, 76961n, 
		76963n, 76991n, 77003n, 77017n, 77023n, 77029n, 77041n, 77047n, 77069n, 77081n, 77093n, 
		77101n, 77137n, 77141n, 77153n, 77167n, 77171n, 77191n, 77201n, 77213n, 77237n, 77239n, 
		77243n, 77249n, 77261n, 77263n, 77267n, 77269n, 77279n, 77291n, 77317n, 77323n, 77339n, 
		77347n, 77351n, 77359n, 77369n, 77377n, 77383n, 77417n, 77419n, 77431n, 77447n, 77471n, 
		77477n, 77479n, 77489n, 77491n, 77509n, 77513n, 77521n, 77527n, 77543n, 77549n, 77551n, 
		77557n, 77563n, 77569n, 77573n, 77587n, 77591n, 77611n, 77617n, 77621n, 77641n, 77647n, 
		77659n, 77681n, 77687n, 77689n, 77699n, 77711n, 77713n, 77719n, 77723n, 77731n, 77743n, 
		77747n, 77761n, 77773n, 77783n, 77797n, 77801n, 77813n, 77839n, 77849n, 77863n, 77867n, 
		77893n, 77899n, 77929n, 77933n, 77951n, 77969n, 77977n, 77983n, 77999n, 78007n, 78017n, 
		78031n, 78041n, 78049n, 78059n, 78079n, 78101n, 78121n, 78137n, 78139n, 78157n, 78163n, 
		78167n, 78173n, 78179n, 78191n, 78193n, 78203n, 78229n, 78233n, 78241n, 78259n, 78277n, 
		78283n, 78301n, 78307n, 78311n, 78317n, 78341n, 78347n, 78367n, 78401n, 78427n, 78437n, 
		78439n, 78467n, 78479n, 78487n, 78497n, 78509n, 78511n, 78517n, 78539n, 78541n, 78553n, 
		78569n, 78571n, 78577n, 78583n, 78593n, 78607n, 78623n, 78643n, 78649n, 78653n, 78691n, 
		78697n, 78707n, 78713n, 78721n, 78737n, 78779n, 78781n, 78787n, 78791n, 78797n, 78803n, 
		78809n, 78823n, 78839n, 78853n, 78857n, 78877n, 78887n, 78889n, 78893n, 78901n, 78919n, 
		78929n, 78941n, 78977n, 78979n, 78989n, 79031n, 79039n, 79043n, 79063n, 79087n, 79103n, 
		79111n, 79133n, 79139n, 79147n, 79151n, 79153n, 79159n, 79181n, 79187n, 79193n, 79201n, 
		79229n, 79231n, 79241n, 79259n, 79273n, 79279n, 79283n, 79301n, 79309n, 79319n, 79333n, 
		79337n, 79349n, 79357n, 79367n, 79379n, 79393n, 79397n, 79399n, 79411n, 79423n, 79427n, 
		79433n, 79451n, 79481n, 79493n, 79531n, 79537n, 79549n, 79559n, 79561n, 79579n, 79589n, 
		79601n, 79609n, 79613n, 79621n, 79627n, 79631n, 79633n, 79657n, 79669n, 79687n, 79691n, 
		79693n, 79697n, 79699n, 79757n, 79769n, 79777n, 79801n, 79811n, 79813n, 79817n, 79823n, 
		79829n, 79841n, 79843n, 79847n, 79861n, 79867n, 79873n, 79889n, 79901n, 79903n, 79907n, 
		79939n, 79943n, 79967n, 79973n, 79979n, 79987n, 79997n, 79999n, 
		
		80021n, 80039n, 80051n, 
		80071n, 80077n, 80107n, 80111n, 80141n, 80147n, 80149n, 80153n, 80167n, 80173n, 80177n, 
		80191n, 80207n, 80209n, 80221n, 80231n, 80233n, 80239n, 80251n, 80263n, 80273n, 80279n, 
		80287n, 80309n, 80317n, 80329n, 80341n, 80347n, 80363n, 80369n, 80387n, 80407n, 80429n, 
		80447n, 80449n, 80471n, 80473n, 80489n, 80491n, 80513n, 80527n, 80537n, 80557n, 80567n, 
		80599n, 80603n, 80611n, 80621n, 80627n, 80629n, 80651n, 80657n, 80669n, 80671n, 80677n, 
		80681n, 80683n, 80687n, 80701n, 80713n, 80737n, 80747n, 80749n, 80761n, 80777n, 80779n, 
		80783n, 80789n, 80803n, 80809n, 80819n, 80831n, 80833n, 80849n, 80863n, 80897n, 80909n, 
		80911n, 80917n, 80923n, 80929n, 80933n, 80953n, 80963n, 80989n, 81001n, 81013n, 81017n, 
		81019n, 81023n, 81031n, 81041n, 81043n, 81047n, 81049n, 81071n, 81077n, 81083n, 81097n, 
		81101n, 81119n, 81131n, 81157n, 81163n, 81173n, 81181n, 81197n, 81199n, 81203n, 81223n, 
		81233n, 81239n, 81281n, 81283n, 81293n, 81299n, 81307n, 81331n, 81343n, 81349n, 81353n, 
		81359n, 81371n, 81373n, 81401n, 81409n, 81421n, 81439n, 81457n, 81463n, 81509n, 81517n, 
		81527n, 81533n, 81547n, 81551n, 81553n, 81559n, 81563n, 81569n, 81611n, 81619n, 81629n, 
		81637n, 81647n, 81649n, 81667n, 81671n, 81677n, 81689n, 81701n, 81703n, 81707n, 81727n, 
		81737n, 81749n, 81761n, 81769n, 81773n, 81799n, 81817n, 81839n, 81847n, 81853n, 81869n, 
		81883n, 81899n, 81901n, 81919n, 81929n, 81931n, 81937n, 81943n, 81953n, 81967n, 81971n, 
		81973n, 82003n, 82007n, 82009n, 82013n, 82021n, 82031n, 82037n, 82039n, 82051n, 82067n, 
		82073n, 82129n, 82139n, 82141n, 82153n, 82163n, 82171n, 82183n, 82189n, 82193n, 82207n, 
		82217n, 82219n, 82223n, 82231n, 82237n, 82241n, 82261n, 82267n, 82279n, 82301n, 82307n, 
		82339n, 82349n, 82351n, 82361n, 82373n, 82387n, 82393n, 82421n, 82457n, 82463n, 82469n, 
		82471n, 82483n, 82487n, 82493n, 82499n, 82507n, 82529n, 82531n, 82549n, 82559n, 82561n, 
		82567n, 82571n, 82591n, 82601n, 82609n, 82613n, 82619n, 82633n, 82651n, 82657n, 82699n, 
		82721n, 82723n, 82727n, 82729n, 82757n, 82759n, 82763n, 82781n, 82787n, 82793n, 82799n, 
		82811n, 82813n, 82837n, 82847n, 82883n, 82889n, 82891n, 82903n, 82913n, 82939n, 82963n, 
		82981n, 82997n, 83003n, 83009n, 83023n, 83047n, 83059n, 83063n, 83071n, 83077n, 83089n, 
		83093n, 83101n, 83117n, 83137n, 83177n, 83203n, 83207n, 83219n, 83221n, 83227n, 83231n, 
		83233n, 83243n, 83257n, 83267n, 83269n, 83273n, 83299n, 83311n, 83339n, 83341n, 83357n, 
		83383n, 83389n, 83399n, 83401n, 83407n, 83417n, 83423n, 83431n, 83437n, 83443n, 83449n, 
		83459n, 83471n, 83477n, 83497n, 83537n, 83557n, 83561n, 83563n, 83579n, 83591n, 83597n, 
		83609n, 83617n, 83621n, 83639n, 83641n, 83653n, 83663n, 83689n, 83701n, 83717n, 83719n, 
		83737n, 83761n, 83773n, 83777n, 83791n, 83813n, 83833n, 83843n, 83857n, 83869n, 83873n, 
		83891n, 83903n, 83911n, 83921n, 83933n, 83939n, 83969n, 83983n, 83987n, 84011n, 84017n, 
		84047n, 84053n, 84059n, 84061n, 84067n, 84089n, 84121n, 84127n, 84131n, 84137n, 84143n, 
		84163n, 84179n, 84181n, 84191n, 84199n, 84211n, 84221n, 84223n, 84229n, 84239n, 84247n, 
		84263n, 84299n, 84307n, 84313n, 84317n, 84319n, 84347n, 84349n, 84377n, 84389n, 84391n, 
		84401n, 84407n, 84421n, 84431n, 84437n, 84443n, 84449n, 84457n, 84463n, 84467n, 84481n, 
		84499n, 84503n, 84509n, 84521n, 84523n, 84533n, 84551n, 84559n, 84589n, 84629n, 84631n, 
		84649n, 84653n, 84659n, 84673n, 84691n, 84697n, 84701n, 84713n, 84719n, 84731n, 84737n, 
		84751n, 84761n, 84787n, 84793n, 84809n, 84811n, 84827n, 84857n, 84859n, 84869n, 84871n, 
		84913n, 84919n, 84947n, 84961n, 84967n, 84977n, 84979n, 84991n, 85009n, 85021n, 85027n, 
		85037n, 85049n, 85061n, 85081n, 85087n, 85091n, 85093n, 85103n, 85109n, 85121n, 85133n, 
		85147n, 85159n, 85193n, 85199n, 85201n, 85213n, 85223n, 85229n, 85237n, 85243n, 85247n, 
		85259n, 85297n, 85303n, 85313n, 85331n, 85333n, 85361n, 85363n, 85369n, 85381n, 85411n, 
		85427n, 85429n, 85439n, 85447n, 85451n, 85453n, 85469n, 85487n, 85513n, 85517n, 85523n, 
		85531n, 85549n, 85571n, 85577n, 85597n, 85601n, 85607n, 85619n, 85621n, 85627n, 85639n, 
		85643n, 85661n, 85667n, 85669n, 85691n, 85703n, 85711n, 85717n, 85733n, 85751n, 85781n, 
		85793n, 85817n, 85819n, 85829n, 85831n, 85837n, 85843n, 85847n, 85853n, 85889n, 85903n, 
		85909n, 85931n, 85933n, 85991n, 85999n, 86011n, 86017n, 86027n, 86029n, 86069n, 86077n, 
		86083n, 86111n, 86113n, 86117n, 86131n, 86137n, 86143n, 86161n, 86171n, 86179n, 86183n, 
		86197n, 86201n, 86209n, 86239n, 86243n, 86249n, 86257n, 86263n, 86269n, 86287n, 86291n, 
		86293n, 86297n, 86311n, 86323n, 86341n, 86351n, 86353n, 86357n, 86369n, 86371n, 86381n, 
		86389n, 86399n, 86413n, 86423n, 86441n, 86453n, 86461n, 86467n, 86477n, 86491n, 86501n, 
		86509n, 86531n, 86533n, 86539n, 86561n, 86573n, 86579n, 86587n, 86599n, 86627n, 86629n, 
		86677n, 86689n, 86693n, 86711n, 86719n, 86729n, 86743n, 86753n, 86767n, 86771n, 86783n, 
		86813n, 86837n, 86843n, 86851n, 86857n, 86861n, 86869n, 86923n, 86927n, 86929n, 86939n, 
		86951n, 86959n, 86969n, 86981n, 86993n, 87011n, 87013n, 87037n, 87041n, 87049n, 87071n, 
		87083n, 87103n, 87107n, 87119n, 87121n, 87133n, 87149n, 87151n, 87179n, 87181n, 87187n, 
		87211n, 87221n, 87223n, 87251n, 87253n, 87257n, 87277n, 87281n, 87293n, 87299n, 87313n, 
		87317n, 87323n, 87337n, 87359n, 87383n, 87403n, 87407n, 87421n, 87427n, 87433n, 87443n, 
		87473n, 87481n, 87491n, 87509n, 87511n, 87517n, 87523n, 87539n, 87541n, 87547n, 87553n, 
		87557n, 87559n, 87583n, 87587n, 87589n, 87613n, 87623n, 87629n, 87631n, 87641n, 87643n, 
		87649n, 87671n, 87679n, 87683n, 87691n, 87697n, 87701n, 87719n, 87721n, 87739n, 87743n, 
		87751n, 87767n, 87793n, 87797n, 87803n, 87811n, 87833n, 87853n, 87869n, 87877n, 87881n, 
		87887n, 87911n, 87917n, 87931n, 87943n, 87959n, 87961n, 87973n, 87977n, 87991n, 88001n, 
		88003n, 88007n, 88019n, 88037n, 88069n, 88079n, 88093n, 88117n, 88129n, 88169n, 88177n, 
		88211n, 88223n, 88237n, 88241n, 88259n, 88261n, 88289n, 88301n, 88321n, 88327n, 88337n, 
		88339n, 88379n, 88397n, 88411n, 88423n, 88427n, 88463n, 88469n, 88471n, 88493n, 88499n, 
		88513n, 88523n, 88547n, 88589n, 88591n, 88607n, 88609n, 88643n, 88651n, 88657n, 88661n, 
		88663n, 88667n, 88681n, 88721n, 88729n, 88741n, 88747n, 88771n, 88789n, 88793n, 88799n, 
		88801n, 88807n, 88811n, 88813n, 88817n, 88819n, 88843n, 88853n, 88861n, 88867n, 88873n, 
		88883n, 88897n, 88903n, 88919n, 88937n, 88951n, 88969n, 88993n, 88997n, 89003n, 89009n, 
		89017n, 89021n, 89041n, 89051n, 89057n, 89069n, 89071n, 89083n, 89087n, 89101n, 89107n, 
		89113n, 89119n, 89123n, 89137n, 89153n, 89189n, 89203n, 89209n, 89213n, 89227n, 89231n, 
		89237n, 89261n, 89269n, 89273n, 89293n, 89303n, 89317n, 89329n, 89363n, 89371n, 89381n, 
		89387n, 89393n, 89399n, 89413n, 89417n, 89431n, 89443n, 89449n, 89459n, 89477n, 89491n, 
		89501n, 89513n, 89519n, 89521n, 89527n, 89533n, 89561n, 89563n, 89567n, 89591n, 89597n, 
		89599n, 89603n, 89611n, 89627n, 89633n, 89653n, 89657n, 89659n, 89669n, 89671n, 89681n, 
		89689n, 89753n, 89759n, 89767n, 89779n, 89783n, 89797n, 89809n, 89819n, 89821n, 89833n, 
		89839n, 89849n, 89867n, 89891n, 89897n, 89899n, 89909n, 89917n, 89923n, 89939n, 89959n, 
		89963n, 89977n, 89983n, 89989n, 
		
		90001n, 90007n, 90011n, 90017n, 90019n, 90023n, 90031n, 
		90053n, 90059n, 90067n, 90071n, 90073n, 90089n, 90107n, 90121n, 90127n, 90149n, 90163n, 
		90173n, 90187n, 90191n, 90197n, 90199n, 90203n, 90217n, 90227n, 90239n, 90247n, 90263n, 
		90271n, 90281n, 90289n, 90313n, 90353n, 90359n, 90371n, 90373n, 90379n, 90397n, 90401n, 
		90403n, 90407n, 90437n, 90439n, 90469n, 90473n, 90481n, 90499n, 90511n, 90523n, 90527n, 
		90529n, 90533n, 90547n, 90583n, 90599n, 90617n, 90619n, 90631n, 90641n, 90647n, 90659n, 
		90677n, 90679n, 90697n, 90703n, 90709n, 90731n, 90749n, 90787n, 90793n, 90803n, 90821n, 
		90823n, 90833n, 90841n, 90847n, 90863n, 90887n, 90901n, 90907n, 90911n, 90917n, 90931n, 
		90947n, 90971n, 90977n, 90989n, 90997n, 91009n, 91019n, 91033n, 91079n, 91081n, 91097n, 
		91099n, 91121n, 91127n, 91129n, 91139n, 91141n, 91151n, 91153n, 91159n, 91163n, 91183n, 
		91193n, 91199n, 91229n, 91237n, 91243n, 91249n, 91253n, 91283n, 91291n, 91297n, 91303n, 
		91309n, 91331n, 91367n, 91369n, 91373n, 91381n, 91387n, 91393n, 91397n, 91411n, 91423n, 
		91433n, 91453n, 91457n, 91459n, 91463n, 91493n, 91499n, 91513n, 91529n, 91541n, 91571n, 
		91573n, 91577n, 91583n, 91591n, 91621n, 91631n, 91639n, 91673n, 91691n, 91703n, 91711n, 
		91733n, 91753n, 91757n, 91771n, 91781n, 91801n, 91807n, 91811n, 91813n, 91823n, 91837n, 
		91841n, 91867n, 91873n, 91909n, 91921n, 91939n, 91943n, 91951n, 91957n, 91961n, 91967n, 
		91969n, 91997n, 92003n, 92009n, 92033n, 92041n, 92051n, 92077n, 92083n, 92107n, 92111n, 
		92119n, 92143n, 92153n, 92173n, 92177n, 92179n, 92189n, 92203n, 92219n, 92221n, 92227n, 
		92233n, 92237n, 92243n, 92251n, 92269n, 92297n, 92311n, 92317n, 92333n, 92347n, 92353n, 
		92357n, 92363n, 92369n, 92377n, 92381n, 92383n, 92387n, 92399n, 92401n, 92413n, 92419n, 
		92431n, 92459n, 92461n, 92467n, 92479n, 92489n, 92503n, 92507n, 92551n, 92557n, 92567n, 
		92569n, 92581n, 92593n, 92623n, 92627n, 92639n, 92641n, 92647n, 92657n, 92669n, 92671n, 
		92681n, 92683n, 92693n, 92699n, 92707n, 92717n, 92723n, 92737n, 92753n, 92761n, 92767n, 
		92779n, 92789n, 92791n, 92801n, 92809n, 92821n, 92831n, 92849n, 92857n, 92861n, 92863n, 
		92867n, 92893n, 92899n, 92921n, 92927n, 92941n, 92951n, 92957n, 92959n, 92987n, 92993n, 
		93001n, 93047n, 93053n, 93059n, 93077n, 93083n, 93089n, 93097n, 93103n, 93113n, 93131n, 
		93133n, 93139n, 93151n, 93169n, 93179n, 93187n, 93199n, 93229n, 93239n, 93241n, 93251n, 
		93253n, 93257n, 93263n, 93281n, 93283n, 93287n, 93307n, 93319n, 93323n, 93329n, 93337n, 
		93371n, 93377n, 93383n, 93407n, 93419n, 93427n, 93463n, 93479n, 93481n, 93487n, 93491n, 
		93493n, 93497n, 93503n, 93523n, 93529n, 93553n, 93557n, 93559n, 93563n, 93581n, 93601n, 
		93607n, 93629n, 93637n, 93683n, 93701n, 93703n, 93719n, 93739n, 93761n, 93763n, 93787n, 
		93809n, 93811n, 93827n, 93851n, 93871n, 93887n, 93889n, 93893n, 93901n, 93911n, 93913n, 
		93923n, 93937n, 93941n, 93949n, 93967n, 93971n, 93979n, 93983n, 93997n, 94007n, 94009n, 
		94033n, 94049n, 94057n, 94063n, 94079n, 94099n, 94109n, 94111n, 94117n, 94121n, 94151n, 
		94153n, 94169n, 94201n, 94207n, 94219n, 94229n, 94253n, 94261n, 94273n, 94291n, 94307n, 
		94309n, 94321n, 94327n, 94331n, 94343n, 94349n, 94351n, 94379n, 94397n, 94399n, 94421n, 
		94427n, 94433n, 94439n, 94441n, 94447n, 94463n, 94477n, 94483n, 94513n, 94529n, 94531n, 
		94541n, 94543n, 94547n, 94559n, 94561n, 94573n, 94583n, 94597n, 94603n, 94613n, 94621n, 
		94649n, 94651n, 94687n, 94693n, 94709n, 94723n, 94727n, 94747n, 94771n, 94777n, 94781n, 
		94789n, 94793n, 94811n, 94819n, 94823n, 94837n, 94841n, 94847n, 94849n, 94873n, 94889n, 
		94903n, 94907n, 94933n, 94949n, 94951n, 94961n, 94993n, 94999n, 95003n, 95009n, 95021n, 
		95027n, 95063n, 95071n, 95083n, 95087n, 95089n, 95093n, 95101n, 95107n, 95111n, 95131n, 
		95143n, 95153n, 95177n, 95189n, 95191n, 95203n, 95213n, 95219n, 95231n, 95233n, 95239n, 
		95257n, 95261n, 95267n, 95273n, 95279n, 95287n, 95311n, 95317n, 95327n, 95339n, 95369n, 
		95383n, 95393n, 95401n, 95413n, 95419n, 95429n, 95441n, 95443n, 95461n, 95467n, 95471n, 
		95479n, 95483n, 95507n, 95527n, 95531n, 95539n, 95549n, 95561n, 95569n, 95581n, 95597n, 
		95603n, 95617n, 95621n, 95629n, 95633n, 95651n, 95701n, 95707n, 95713n, 95717n, 95723n, 
		95731n, 95737n, 95747n, 95773n, 95783n, 95789n, 95791n, 95801n, 95803n, 95813n, 95819n, 
		95857n, 95869n, 95873n, 95881n, 95891n, 95911n, 95917n, 95923n, 95929n, 95947n, 95957n, 
		95959n, 95971n, 95987n, 95989n, 96001n, 96013n, 96017n, 96043n, 96053n, 96059n, 96079n, 
		96097n, 96137n, 96149n, 96157n, 96167n, 96179n, 96181n, 96199n, 96211n, 96221n, 96223n, 
		96233n, 96259n, 96263n, 96269n, 96281n, 96289n, 96293n, 96323n, 96329n, 96331n, 96337n, 
		96353n, 96377n, 96401n, 96419n, 96431n, 96443n, 96451n, 96457n, 96461n, 96469n, 96479n, 
		96487n, 96493n, 96497n, 96517n, 96527n, 96553n, 96557n, 96581n, 96587n, 96589n, 96601n, 
		96643n, 96661n, 96667n, 96671n, 96697n, 96703n, 96731n, 96737n, 96739n, 96749n, 96757n, 
		96763n, 96769n, 96779n, 96787n, 96797n, 96799n, 96821n, 96823n, 96827n, 96847n, 96851n, 
		96857n, 96893n, 96907n, 96911n, 96931n, 96953n, 96959n, 96973n, 96979n, 96989n, 96997n, 
		97001n, 97003n, 97007n, 97021n, 97039n, 97073n, 97081n, 97103n, 97117n, 97127n, 97151n, 
		97157n, 97159n, 97169n, 97171n, 97177n, 97187n, 97213n, 97231n, 97241n, 97259n, 97283n, 
		97301n, 97303n, 97327n, 97367n, 97369n, 97373n, 97379n, 97381n, 97387n, 97397n, 97423n, 
		97429n, 97441n, 97453n, 97459n, 97463n, 97499n, 97501n, 97511n, 97523n, 97547n, 97549n, 
		97553n, 97561n, 97571n, 97577n, 97579n, 97583n, 97607n, 97609n, 97613n, 97649n, 97651n, 
		97673n, 97687n, 97711n, 97729n, 97771n, 97777n, 97787n, 97789n, 97813n, 97829n, 97841n, 
		97843n, 97847n, 97849n, 97859n, 97861n, 97871n, 97879n, 97883n, 97919n, 97927n, 97931n, 
		97943n, 97961n, 97967n, 97973n, 97987n, 98009n, 98011n, 98017n, 98041n, 98047n, 98057n, 
		98081n, 98101n, 98123n, 98129n, 98143n, 98179n, 98207n, 98213n, 98221n, 98227n, 98251n, 
		98257n, 98269n, 98297n, 98299n, 98317n, 98321n, 98323n, 98327n, 98347n, 98369n, 98377n, 
		98387n, 98389n, 98407n, 98411n, 98419n, 98429n, 98443n, 98453n, 98459n, 98467n, 98473n, 
		98479n, 98491n, 98507n, 98519n, 98533n, 98543n, 98561n, 98563n, 98573n, 98597n, 98621n, 
		98627n, 98639n, 98641n, 98663n, 98669n, 98689n, 98711n, 98713n, 98717n, 98729n, 98731n, 
		98737n, 98773n, 98779n, 98801n, 98807n, 98809n, 98837n, 98849n, 98867n, 98869n, 98873n, 
		98887n, 98893n, 98897n, 98899n, 98909n, 98911n, 98927n, 98929n, 98939n, 98947n, 98953n, 
		98963n, 98981n, 98993n, 98999n, 99013n, 99017n, 99023n, 99041n, 99053n, 99079n, 99083n, 
		99089n, 99103n, 99109n, 99119n, 99131n, 99133n, 99137n, 99139n, 99149n, 99173n, 99181n, 
		99191n, 99223n, 99233n, 99241n, 99251n, 99257n, 99259n, 99277n, 99289n, 99317n, 99347n, 
		99349n, 99367n, 99371n, 99377n, 99391n, 99397n, 99401n, 99409n, 99431n, 99439n, 99469n, 
		99487n, 99497n, 99523n, 99527n, 99529n, 99551n, 99559n, 99563n, 99571n, 99577n, 99581n, 
		99607n, 99611n, 99623n, 99643n, 99661n, 99667n, 99679n, 99689n, 99707n, 99709n, 99713n, 
		99719n, 99721n, 99733n, 99761n, 99767n, 99787n, 99793n, 99809n, 99817n, 99823n, 99829n, 
		99833n, 99839n, 99859n, 99871n, 99877n, 99881n, 99901n, 99907n, 99923n, 99929n, 99961n, 
		99971n, 99989n, 99991n, 

		100003n, 100019n, 100043n, 100049n, 100057n, 100069n, 100103n, 100109n, 100129n, 100151n,
		100153n, 100169n, 100183n, 100189n, 100193n, 100207n, 100213n, 100237n, 100267n, 100271n, 
		100279n, 100291n, 100297n, 100313n, 100333n, 100343n, 100357n, 100361n, 100363n, 100379n, 
		100391n, 100393n, 100403n, 100411n, 100417n, 100447n, 100459n, 100469n, 100483n, 100493n, 
		100501n, 100511n, 100517n, 100519n, 100523n, 100537n, 100547n, 100549n, 100559n, 100591n, 
		100609n, 100613n, 100621n, 100649n, 100669n, 100673n, 100693n, 100699n, 100703n, 100733n, 
		100741n, 100747n, 100769n, 100787n, 100799n, 100801n, 100811n, 100823n, 100829n, 100847n, 
		100853n, 100907n, 100913n, 100927n, 100931n, 100937n, 100943n, 100957n, 100981n, 100987n, 
		100999n, 101009n, 101021n, 101027n, 101051n, 101063n, 101081n, 101089n, 101107n, 101111n, 
		101113n, 101117n, 101119n, 101141n, 101149n, 101159n, 101161n, 101173n, 101183n, 101197n, 
		101203n, 101207n, 101209n, 101221n, 101267n, 101273n, 101279n, 101281n, 101287n, 101293n, 
		101323n, 101333n, 101341n, 101347n, 101359n, 101363n, 101377n, 101383n, 101399n, 101411n, 
		101419n, 101429n, 101449n, 101467n, 101477n, 101483n, 101489n, 101501n, 101503n, 101513n, 
		101527n, 101531n, 101533n, 101537n, 101561n, 101573n, 101581n, 101599n, 101603n, 101611n, 
		101627n, 101641n, 101653n, 101663n, 101681n, 101693n, 101701n, 101719n, 101723n, 101737n, 
		101741n, 101747n, 101749n, 101771n, 101789n, 101797n, 101807n, 101833n, 101837n, 101839n, 
		101863n, 101869n, 101873n, 101879n, 101891n, 101917n, 101921n, 101929n, 101939n, 101957n, 
		101963n, 101977n, 101987n, 101999n, 102001n, 102013n, 102019n, 102023n, 102031n, 102043n, 
		102059n, 102061n, 102071n, 102077n, 102079n, 102101n, 102103n, 102107n, 102121n, 102139n, 
		102149n, 102161n, 102181n, 102191n, 102197n, 102199n, 102203n, 102217n, 102229n, 102233n, 
		102241n, 102251n, 102253n, 102259n, 102293n, 102299n, 102301n, 102317n, 102329n, 102337n, 
		102359n, 102367n, 102397n, 102407n, 102409n, 102433n, 102437n, 102451n, 102461n, 102481n, 
		102497n, 102499n, 102503n, 102523n, 102533n, 102539n, 102547n, 102551n, 102559n, 102563n, 
		102587n, 102593n, 102607n, 102611n, 102643n, 102647n, 102653n, 102667n, 102673n, 102677n, 
		102679n, 102701n, 102761n, 102763n, 102769n, 102793n, 102797n, 102811n, 102829n, 102841n, 
		102859n, 102871n, 102877n, 102881n, 102911n, 102913n, 102929n, 102931n, 102953n, 102967n, 
		102983n, 103001n, 103007n, 103043n, 103049n, 103067n, 103069n, 103079n, 103087n, 103091n, 
		103093n, 103099n, 103123n, 103141n, 103171n, 103177n, 103183n, 103217n, 103231n, 103237n, 
		103289n, 103291n, 103307n, 103319n, 103333n, 103349n, 103357n, 103387n, 103391n, 103393n, 
		103399n, 103409n, 103421n, 103423n, 103451n, 103457n, 103471n, 103483n, 103511n, 103529n, 
		103549n, 103553n, 103561n, 103567n, 103573n, 103577n, 103583n, 103591n, 103613n, 103619n, 
		103643n, 103651n, 103657n, 103669n, 103681n, 103687n, 103699n, 103703n, 103723n, 103769n, 
		103787n, 103801n, 103811n, 103813n, 103837n, 103841n, 103843n, 103867n, 103889n, 103903n, 
		103913n, 103919n, 103951n, 103963n, 103967n, 103969n, 103979n, 103981n, 103991n, 103993n, 
		103997n, 104003n, 104009n, 104021n, 104033n, 104047n, 104053n, 104059n, 104087n, 104089n, 
		104107n, 104113n, 104119n, 104123n, 104147n, 104149n, 104161n, 104173n, 104179n, 104183n, 
		104207n, 104231n, 104233n, 104239n, 104243n, 104281n, 104287n, 104297n, 104309n, 104311n, 
		104323n, 104327n, 104347n, 104369n, 104381n, 104383n, 104393n, 104399n, 104417n, 104459n, 
		104471n, 104473n, 104479n, 104491n, 104513n, 104527n, 104537n, 104543n, 104549n, 104551n, 
		104561n, 104579n, 104593n, 104597n, 104623n, 104639n, 104651n, 104659n, 104677n, 104681n, 
		104683n, 104693n, 104701n, 104707n, 104711n, 104717n, 104723n, 104729n
*/
	];

	BigInt.lplim = (1n << 26n) / BigInt.lowPrimes[BigInt.lowPrimes.length - 1];

	// https://eprint.iacr.org/2014/040.pdf
	// https://www.nayuki.io/page/barrett-reduction-algorithm
	BigInt.Barrett = function(m) {
		// setup Barrett
		this.q3 = 0n;
		this.shft = 2n * BigInt(m.bitLength());
		this.r2 = 1n << (this.shft);
		this.mu = this.r2.divide(m);
		this.m = m;
	};

	BigInt.Barrett.prototype = {
		convert: function(x) {
			if (x < 0n || x.bitLength() > this.m.bitLength()) return x.mod(this.m);
			else if (x.compareTo(this.m) < 0) return x;
			else { 
				var r = x;
				return this.reduce(r);
			}
		},

		revert: function(x) {
			return x;
		},

		// x = x mod m (HAC 14.42)
		reduce: function(x) {
			//assert x.signum() >= 0 && x.compareTo(this.m.pow(2)) < 0;
			var t = x.subtract(x.multiply(this.mu).shiftRight(this.shft).multiply(this.m));
			while (t.compareTo(this.m) >= 0) t -= this.m;
			return t;
		},

		// r = x^2 mod m; x != r
		square: function(x) {
			var r = x.square();
			return this.reduce(r);
		},

		// r = x*y mod m; x,y != r
		multiply: function(x, y) {
			var r = x.multiply(y);
			return this.reduce(r);
		}
	};

	// Montgomery reduction
	BigInt.Montgomery = function(m) {
		if (!m.testBit(0) || m.compareTo(1n) <= 0n)
			throw new Error('Modulus must be an odd number at least 3n');
		this.m = m;
		this.rBits = (m.bitLength() / 8 + 1) * 8;
		this.r = 1n << BigInt(this.rBits); // reducer
		this.mk = this.r - 1n; // mask
		this.rp = this.r.modInverse(this.m); // reciprocal
		this.mu = this.r.multiply(this.rp).subtract(1n).divide(this.m); // factor
	};

	// xR mod m
	BigInt.Montgomery.prototype = {
		convert: function(x) {
			return x.abs().shiftLeft(this.rBits).mod(this.m);
		},

		revert: function(x) {
			//return this.reduce(x);
			return x.multiply(this.rp).mod(this.m);
		},

		// x = x/R mod m (HAC 14.32)
		reduce: function(x) {
			var t = x.and(this.mk).multiply(this.mu).and(this.mk);
			var r = x.add(t.multiply(this.m)).shiftRight(this.rBits);
			if (r.compareTo(this.m) >= 0) r = r.subtract(this.m);
			return r;
		},

		// r = "x^2/R mod m"; x != r
		square: function(x) {
			var r = x.square();
			return this.reduce(r);
		},

		// r = "xy/R mod m"; x,y != r
		multiply: function(x, y) {
			var r = x.multiply(y);
			return this.reduce(r);
		},

		pow: function(x, y) {
			if (y.signum() == -1) throw new Error("Negative exponent");

			var z = this.r.mod(this.m);
			for (var i = 0, len = y.bitLength(); i < len; i++) {
				if (y.testBit(i))
					z = this.multiply(z, x);
				x = this.square(x);
			}
			return z;
		}
	};

})();
