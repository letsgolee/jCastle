/**
 * jCastle - Utility functions collection
 * 
 * @author Jacob Lee
 * 
 * Copyright (c) 2015-2022 Jacob Lee
 */

var jCastle = require('./jCastle');
var BigInteger = require('./biginteger');

require('./lang/en');
require('./lang/ko');
require('./error');

if (typeof global === "undefined") var global = window;

Object.defineProperty(global, '__stack', {
	get: function() {
		var orig = Error.prepareStackTrace;
		Error.prepareStackTrace = function(_, stack){ return stack; };
		var err = new Error;
		Error.captureStackTrace(err, arguments.callee);
		var stack = err.stack;
		Error.prepareStackTrace = orig;
		return stack;
	}
});
  
 Object.defineProperty(global, '__line', {
	get: function() {
		return __stack[1].getLineNumber();
	}
});


/*
Buffer.xor = (x, y, fill_method) => {
	fill_method = fill_method || "right";

	var yy = Array.prototype.slice.call(y, 0), z = Buffer.alloc(x.length);

	switch (fill_method.toLowerCase()) {
		case "left": while (yy.length < x.length) yy.unshift(0x00); break;
		case "right": while (yy.length < x.length) yy.push(0x00); break;
	}

	for (var i = 0; i < x.length; i++) {
		z[i] = (x[i] ^ yy[i]) & 0xFF;
	}
	return z;
};
*/
Buffer.xor = (x, y) => {
    var z = Buffer.alloc(x.length);

    for (var i = 0; i < x.length; i++) {
        z[i] = (x[i] ^ y[i]) & 0xff;
    }

    return z;
};

// In web browser Uint8Array.prototype.slice.call() returns a Uint8Array object 
// not a buffer object.
Buffer.slice = (buf, start, end) => {
	var sub = buf.slice(start, end);
	var copy = Buffer.alloc(sub.length);
	copy.set(sub, 0);
	return copy;
};

/*
// node의 스트링은 utf16le라는 인코딩으로 되어 있는 것처럼 보인다.

> let a = '한글';
> console.log(a)
한글
> let b = Buffer.from(a, 'utf16le')
> console.log(a)
한글
> console.log(b);
<Buffer 5c d5 00 ae>
> let c = Buffer.from(a, 'utf8')
> console.log(c)
<Buffer ed 95 9c ea b8 80>
> console.log(b.toString('utf16le'))
한글
> console.log(c.toString('utf8'))
한글
> let d = ''; for(let i = 0; i < a.length; i++) {d += a.charCodeAt(i) + ','}console.log(d);
54620,44544,
> console.log(54620..toString(16))
d55c
> console.log(44544..toString(16))
ae00
*/

Buffer.toBmpString = (buf, encoding = 'latin1') => {
	var str = buf.toString(encoding);
	var bmp_str = '';
	for (var i = 0; i < str.length; i++) {
		var c = str.charCodeAt(i);
		bmp_str += String.fromCharCode((c >>> 8) & 0xFF) + String.fromCharCode(c & 0xFF);
	}
	bmp_str += String.fromCharCode(0, 0); // null terminate
	return bmp_str;
};

Buffer.fromBmpString = (bmpstr, encoding = 'latin1') => {
	var str = '';

	for (var i = 0; i < bmpstr; i += 2) {
		str += (bmpstr.charCodeAt(i) << 8) | (bmpstr.charCodeAt(i+1));
	}
	// remove null string
	return Buffer.from(str.substring(0, str.length - 1), encoding);
};

/*
 * Utility functions for jCastle
 */
jCastle.util = {
	isUint8Array: function(u8)
	{
		return Object.prototype.toString.call(u8) === '[object Uint8Array]';
	},

	// rotate a byte to the left
	rotl8: function(x, n)
	{
		return (x << n | x >>> (8 - n)) & 0xFF;
	},

	// rotate a word to the left
	rotl32: function(w, n)
	{
		if (n < 32) {
			return (w <<  n) | (w >>> (32 - n));
		} else {
			return x;
		}
	},

	// rotate a word to the right
	rotr32: function(w, n)
	{
		if (n < 32) {
			return (w >>> n | w << (32 - n)) & 0xffffffff;
		}
		return w;
	},

	// The 32-bit implementation of shift right
	shr32: function(x, n)
	{
		if (n < 32) {
			return x >>> n;
		} else {
			return 0;
		}
	},

	// swap bytes for endian change
	bswap32: function(val)
	{
		return ((val & 0xFF) << 24)
			   | ((val & 0xFF00) << 8)
			   | ((val >>> 8) & 0xFF00)
			   | ((val >>> 24) & 0xFF);
	},

	bswap16: function(val)
	{
		return ((val & 0xFF) << 8)
			   | ((val >> 8) & 0xFF);
	},

	// get a litten-endian word from a byte array
	load32: function(a, i)
	{
		return a[i] | a[i+1] << 8 | a[i+2] << 16 | a[i+3] << 24;
	},

	// get a big-endian word from a byte array
	load32b: function(a, i)
	{
		//return a[i] << 24 | a[i+1] << 16 | a[i+2] << 8 | a[i+3];
		return ((0x0ff&a[i]) << 24) | ((0x0ff&a[i+1]) << 16) | ((0x0ff&a[i+2]) << 8) | ((0x0ff&a[i+3]));
	},

	// set a little-endian word to an byte array
	store32: function(a, i, w)
	{
		if (jCastle.util.isUint8Array(a)) {
			a.set([w & 0xFF, (w >>> 8) & 0xFF, (w >>> 16) & 0xFF, (w >>> 24) & 0xFF], i);
		} else {
			a.splice(i, 4, w & 0xFF, (w >>> 8) & 0xFF, (w >>> 16) & 0xFF, (w >>> 24) & 0xFF);
		}
	},

	// set a big-endian word to an byte array
	store32b: function(a, i, w)
	{
		if (jCastle.util.isUint8Array(a)) {
			a.set([(w >>> 24) & 0xFF, (w >>> 16) & 0xFF, (w >>> 8) & 0xFF, w & 0xFF], i);
		} else {
			a.splice(i, 4, (w >>> 24) & 0xFF, (w >>> 16) & 0xFF, (w >>> 8) & 0xFF, w & 0xFF);
		}
	},

	// get a litten-endian int16 from a byte array
	load16: function(a, i)
	{
		return (a[i] & 0xff) | (a[i + 1] & 0xff) << 8;
	},

	// get a big-endian int16 from a byte array
	load16b: function(a, i)
	{
		//return a[i] << 24 | a[i+1] << 16 | a[i+2] << 8 | a[i+3];
		return ((0x0ff & a[i]) << 8) | ((0x0ff & a[i + 1]));
	},

	// set a little-endian int16 to an byte array
	store16: function(a, i, w)
	{
		a.splice(i, 2, w & 0xFF, (w >>> 8) & 0xFF);
	},

	// set a big-endian word to an byte array
	store16b: function(a, i, w)
	{
		a.splice(i, 2, (w >>> 8) & 0xFF, w & 0xFF);
	},

	store64: function(a, i, hi, lo)
	{
		a.splice(i, 4, lo & 0xFF, (lo >>> 8) & 0xFF, (lo >>> 16) & 0xFF, (lo >>> 24) & 0xFF);
		a.splice(i + 4, 4, hi & 0xFF, (hi >>> 8) & 0xFF, (hi >>> 16) & 0xFF, (hi >>> 24) & 0xFF);
	},

	store64b: function(a, i, hi, lo)
	{
		a.splice(i, 4, (hi >>> 24) & 0xFF, (hi >>> 16) & 0xFF, (hi >>> 8) & 0xFF, hi & 0xFF);
		a.splice(i + 4, 4, (lo >>> 24) & 0xFF, (lo >>> 16) & 0xFF, (lo >>> 8) & 0xFF, lo & 0xFF);
	},
/*
	loadINT64: function(a, i)
	{
		return new INT64(jCastle.util.load32(a, i+4), jCastle..util.load32(a, i));
	},
*/

	// get a byte from a word
	byte: function(x, n)
	{
		return (x >>> (8 * n)) & 0xFF;
	},

	/*
	// little-endian
	toInt32: function(b0, b1, b2, b3)
	{
		return (b0 & 0xff) | (b1 & 0xff) << 8 | (b2 & 0xff) << 16 | (b3 & 0xff) << 24;
	},

	// big-endian
	toInt32b: function(b0, b1, b2, b3)
	{
		return (b0 & 0xff) << 24 | (b1 & 0xff) << 16 | (b2 & 0xff) << 8 | (b3 & 0xff);
	},
	*/

	byteArray2hex: function(input, is_upper)
	{
		var hex_tab = is_upper ? "0123456789ABCDEF" : "0123456789abcdef";
		if(!input || !input.length) return '';
		var output = "";
		var k;
		var i = 0;

		do {
			k = input[i++];
			output += hex_tab.charAt((k >> 4) & 0xf) + hex_tab.charAt(k & 0xf);
		} while (i < input.length);

		return output;
	},

	hex2byteArray: function(h)
	{
		var res = [];
		if (h.length % 2) h = "0" + h;
		for (var i = 0; i < h.length; i += 2) {
			var c = h.substr(i, 2);
			res.push(parseInt(c, 16));
		}
		return res;
	},

	byte2hex: function(b)
	{
		if(b < 0x10)
			return "0" + b.toString(16);
		else
			return b.toString(16);
	},

	byteXor: function(dst, _dst, a, _a, b, _b, bytelen)
	{
		while(bytelen-- > 0) {
			dst[_dst++] = (a[_a++] ^ b[_b++]) & 0xff;
		}
	},

	xorBlock: function(x, y, fill_method)
	{
		fill_method = fill_method || "no";

		var yy = y.slice(0);

		switch (fill_method.toLowerCase()) {
			case "left": while (yy.length != x.length) yy.unshift(0x00); break;
			case "right": while (yy.length != x.length) yy.push(0x00); break;
		}

		var z = [];
		for (var i = 0; i < x.length; i++) {
			z[i] = x[i] ^ yy[i];
		}
		return z;
	},

	lineBreak: function(s, n = 64)
	{
		var ret = "";
		var i = 0;
		while(i + n < s.length) {
			ret += s.substring(i,i+n) + "\n";
			i += n;
		}
		return ret + s.substring(i,s.length);
	},

	strReverse: function(s)
	{
		for (var i = s.length - 1, o = ''; i >= 0; o += s[i--]) { }
		return o;
	},


	clone: function(obj)
	{
		var copy;

		// Handle the 3 simple types, and null or undefined
		if (null == obj || "object" != typeof obj) return obj;

		// Handle Date
		if (obj instanceof Date) {
			copy = new Date();
			copy.setTime(obj.getTime());
			return copy;
		}

		// Handle Array
		if (obj instanceof Array) {
			copy = [];
			for (var i = 0, len = obj.length; i < len; i++) {
				copy[i] = jCastle.util.clone(obj[i]);
			}

			return copy;
		}

		if (typeof Uint8Array!= 'undefined' && obj instanceof Uint8Array) {
			return obj.slice(0);
		}

		if (obj instanceof BigInteger) {
			copy = obj.clone();
			return copy;
		}

		// Handle Object
		if (obj instanceof Object) {
			if (typeof obj.clone == 'function') {
				copy = obj.clone();
			} else {
				copy = {};
				//for (var attr in obj) {
				//	if (obj.hasOwnProperty(attr)) copy[attr] = jCastle.util.clone(obj[attr]);
				//}
                Object.assign(copy, obj);
			}
			return copy;
		}

		throw jCastle.exception('OBJ_CANNOT_COPY', 'UTL001');
	},

	equals: function(o1, o2)
	{	
		var type1 = typeof o1, type2 = typeof o2;
			
		if (type1 !== type2) return false;
		if ('undefined' === type1 || 'undefined' === type2) {
			return (o1 === o2);
		}
		if (o1 === null || o2 === null) {
			return (o1 === o2);
		}
		if (('number' === type1 && isNaN(o1)) && ('number' === type2 && isNaN(o2)) ) {
			return (isNaN(o1) && isNaN(o2));
		}
			
		// Check whether arguments are not objects
		var primitives = {number: '', string: '', boolean: ''};

		if (type1 in primitives) {
			return o1 === o2;
		} 
			
		if ('function' === type1) {
			return o1.toString() === o2.toString();
		}

		for (var p in o1) {
			if (o1.hasOwnProperty(p)) {
				if ('undefined' === typeof o2[p] && 'undefined' !== typeof o1[p]) return false;
				if (!o2[p] && o1[p]) return false; // <!-- null --> 

				switch (typeof o1[p]) {
					case 'function':
						if (o1[p].toString() !== o2[p].toString()) return false;
					default:
						if (!jCastle.util.equals(o1[p], o2[p])) return false; 
				}
			} 
		}
		  
		// Check whether o2 has extra properties
		// TODO: improve, some properties have already been checked!
		for (p in o2) {
			if (o2.hasOwnProperty(p)) {
				if ('undefined' === typeof o1[p] && 'undefined' !== typeof o2[p]) return false;
				if (!o1[p] && o2[p]) return false; // <!-- null --> 
			}
		}

		return true;
	},

	arrayCopy: function(dst, _dst, src, _src, bytelen)
	{
		while(bytelen-- > 0) {
			dst[_dst++] = src[_src++];
		}
	},

	fillArray: function(a, what)
	{
		for (var i = 0; i < a.length; i++) {
			a[i] = what;
		}
	},

	arrayRemove: function(needle, haystack)
	{
		var i = haystack.indexOf(needle);

		if (i >= 0) {
			haystack.splice(i, 1);
		}
	},

	safeAdd32: function(x, y) 
	{
		var lsw = (x & 0xFFFF) + (y & 0xFFFF);
		var msw = (x >>> 16) + (y >>> 16) + (lsw >>> 16);

		return ((msw & 0xFFFF) << 16) | (lsw & 0xFFFF);
	},

	safeAdd16: function(x, y) 
	{
		var lsw = (x & 0xFF) + (y & 0xFF);
		var msw = (x >>> 8) + (y >>> 8) + (lsw >>> 8);

		return ((msw & 0xFF) << 8) | (lsw & 0xFF);
	},

    // In web browser Uint8Array.prototype.slice.call() returns a Uint8Array object 
    // not a buffer object.
    sliceBuffer: (buf, start, end) => {
        var sub = buf.slice(start, end);
        var copy = Buffer.alloc(sub.length);
        copy.set(sub, 0);
        return copy;
    },

	randomString: function(length, chars)
	{
		var mask = '';
		if (chars.indexOf('a') > -1) mask += 'abcdefghijklmnopqrstuvwxyz';
		if (chars.indexOf('A') > -1) mask += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
		if (chars.indexOf('#') > -1) mask += '0123456789';
		if (chars.indexOf('!') > -1) mask += '~`!@#$%^&*()_+-={}[]:";\'<>?,./|\\';
		var result = '';
		for (var i = length; i > 0; --i) result += mask[Math.round(Math.random() * (mask.length - 1))];
		return result;
	},

	isString: function(input)
	{
		return typeof input == 'string' || Object.prototype.toString.call(input) == '[object String]';
	},

	// be careful when you try to turn a string to a BigInteger number.
	//
	// if you try to turn a string to byte array and then make a BigInteger using the byte array,
	// then you might have a wrong result when the number of BigInteger starts with 8 or bigger.
	// it might be that it is treated as a minus number.
	//
	// but if the byte array is turned to hex string and then it will be no problem.
	// 
	// so if you need a bigInteger use toBigInteger function!
	toBigInteger: function(input, encoding = 'latin1')
	{
		var buf;

		if (input instanceof BigInteger) {
			return input.clone();
		}

		if (typeof input == 'number') {
			return new BigInteger(input.toString(16), 16);
		}

		if (jCastle.util.isString(input) && /^[0-9A-F]+$/i.test(input)) {
			buf = Buffer.from(input, 'hex');
		} else {
			buf = Buffer.from(input, encoding);
		}

		return BigInteger.fromByteArrayUnsigned(buf);
	},

	formatBigInteger: function(bi, format = 'latin1')
	{
		switch (format.toLowerCase()) {
			case 'bytearray':
				return bi.toByteArray();
			case 'uint8':
			case 'uint8array':
				return new Uint8Array(bi.toByteArray());
			case 'int':
			case 'integer':
				return bi.intValue();
			case 'object':
			case 'biginteger':
				return bi.clone();
			default:
				var buf = Buffer.from(bi.toByteArray());
				if (format == 'buffer') return buf;
				return buf.toString(format);
		}
	},

	// check salt whether it has asn1 structure...
	avoidAsn1Format: function(salt_bytes)
	{
		var len = salt_bytes.length - 2;
		if (salt_bytes[1] == len)
			salt_bytes[1] = (salt_bytes[1] + 1) & 0xff;
	},
	
	seekPemFormat: function(input)
	{
		// string - pem
		// string - hex
		// string - base64
		// string - der
		// object - asn1 object
		// buffer - der
		if (jCastle.util.isString(input)) {
			// javascript doesn't support multiline flag(s).
			// the good news is using \s\S is ok.

			// der might have \x00 as BER's in-definite length style.
			// trim() function will remove it and asn1 parser gets error.
			//input = input.trim();

			if (/-----BEGIN ([A-Z0-9 ]+)-----/i.test(input) &&
				/-----END ([A-Z0-9 ]+)-----/i.test(input)) return 'pem';
			input = input.trim();
			input = input.replace(/[\n\r\s]/g, '');
			if (/^[0-9A-F]+$/i.test(input)) return 'hex';
			if (/^[a-z0-9\+\=\/]+$/i.test(input)) return 'base64';
			return 'der';
		}
		if (Buffer.isBuffer(input)) return 'buffer';
		if (typeof input == 'object' && 
			'type' in input && input.type == jCastle.asn1.tagSequence && 'items' in input) {
				// most of cases asn1 format starts with sequence tag.
				// if the object is created by asn1 parser then it has _isAsn1 property,
				// but we have to be careful for a user can make asn1 object by himself.
				return 'asn1';
			}

		return 'unknown';
	},

	toAsn1Object: function(input, options = {})
	{
		format = 'format' in options ? options.format.toLowerCase() : 'auto';
		if (format == 'auto') format = jCastle.util.seekPemFormat(input);

		var buf, output = {};

		switch (format) {
			case 'pem':
				if ('match' in options) {
					// pkcs#5 match: "-----BEGIN ([A-Z]+) PRIVATE KEY-----"
					var regex = new RegExp(options.match, 'g');
					var matches = regex.exec(input);
					if (!matches) throw jCastle.exception("INVALID_PEM_FORMAT", 'UTL004');
					output.matches = matches;
				}

				// public key in pkcs#5 format
				if (input.indexOf("Proc-Type: 4,ENCRYPTED") != -1) {

					//console.log('encrypted');

					// encrypted
					output.encrypted = true;
						
					input = input.replace("Proc-Type: 4,ENCRYPTED", '');
					var algo_info = /DEK-Info: ([^,]+),([0-9A-F]+)/ig.exec(input);
					input = input.replace(/DEK-Info: ([^,]+),([0-9A-F]+)/ig, '');
						
					var iv = Buffer.from(algo_info[2], 'hex');
					var algo = algo_info[1].toLowerCase();
					var pos = algo.lastIndexOf('-');
					if (pos == -1) {
						throw jCastle.exception("INVALID_ENCRYPTION_METHOD", 'UTL005');
					}
					var algo_name = algo.slice(0, pos);
					var algo_mode = algo.slice(pos+1);

					output.encryptedInfo = {
						algo: algo_name,
						iv: iv,
						mode: algo_mode
					}
				}

				var p = new RegExp("-----(BEGIN|END) ([A-Z0-9 ]+)-----", "g");
				input = input.replace(p, '').replace(/[\r\n]/g, '');
			case 'base64':
				buf = Buffer.from(input, 'base64');
				break;				
			case 'hex':
				buf = Buffer.from(input, 'hex');
				break;
			case 'buffer':
				buf = input;
				break;
			case 'der':
				buf = Buffer.from(input, 'latin1');
				break;
			case 'asn1':
				output.asn1 = input;
				return output;
			default:
				throw jCastle.exception('UNKNOWN_FORMAT', 'UTL006');
		}

		output.buffer = buf;

		if (!('encrypted' in output) || !output.encrypted) {
			var asn1 = new jCastle.asn1();
			//asn1.ignoreLengthError();
			output.asn1 = asn1.parse(buf);
		}

		return output;
	},

	int2hex: function(n)
	{
		n = n.toString(16);
		if (n.length % 2 !== 0) {
			n = '0' + n;
		}
		return n;
	},

	isInteger: function(value)
	{
		var x;
		return isNaN(value) ? !1 : (x = parseFloat(value), (0 | x) === x);
	},

	str2date: function(str)
	{
		var year, month, day, hour, minute, second, d;
		var m = /^(\d\d\d\d)\-(0[1-9]|1[0-2])\-(0[1-9]|[12]\d|3[01])(?:[ ]([01]\d|2[0-3])\:([0-5]\d)\:([0-5]\d)(?:[ ](UTC|GMT))?)?$/.exec(str);

		if (!m) {
			d = new Date(str);
		} else {
			year = m[1];
			month = m[2];
			day = m[3];
			if (m[4]) {
				hour = m[4];
				minute = m[5];
				second = m[6];
			} else {
				hour = minute = second = 0;
			}
			if (m[7]) {
				d = new Date(Date.UTC(year, month-1, day, hour, minute, second));
			} else {
				d = new Date(year, month-1, day, hour, minute, second);
			}
		}
		return d;
	},

	str2int: function(str)
	{
		if (typeof str === 'number') return str;
		
		var v = new BigInteger(Buffer.from(str, 'latin1').toString('hex'), 16);

		if (v.gt(BigInteger.MAXINT)) return v.toString(10);
		if (v.gt(BigInteger.SAFE_MAXINT)) return parseInt(v.toString(10));
		return v.intValue();
	},

	loadIPv4: function(v)
	{
		var ip = v.charCodeAt(0) + '.' + v.charCodeAt(1) + '.' + v.charCodeAt(2) + '.' + v.charCodeAt(3);
		
		if (v.length == 4) {
			return ip;
		}

		ip += '/' + v.charCodeAt(4) + '.' + v.charCodeAt(5) + '.' + v.charCodeAt(6) + '.' + v.charCodeAt(7);
		return ip;
	},

	storeIPv4: function(ip)
	{
		if (ip.indexOf('/') === -1) {
			var s = ip.split('.');

			return String.fromCharCode(parseInt(s[0])) + String.fromCharCode(parseInt(s[1])) +
				String.fromCharCode(parseInt(s[2])) + String.fromCharCode(parseInt(s[3]));
		}

		var s = ip.split('/');
		var res = '';
		
		for (var i = 0; i < s.length; i++) {
			var s1 = s[i].split('.');

			res += String.fromCharCode(parseInt(s1[0])) + String.fromCharCode(parseInt(s1[1])) +
				String.fromCharCode(parseInt(s1[2])) + String.fromCharCode(parseInt(s1[3]));
		}

		return res;
	},

	loadIPv6: function(v)
	{
		var ip = '';
		
		for (var i = 0; i < v.length; i += 2) {
			var s1 = v.charCodeAt(i);
			var s2 = v.charCodeAt(i + 1);

			ip += (!s1) ? '' : s1.toString(16);
			ip += s1 ? jCastle.util.int2hex(s2) : s2.toString(16);
			if (i != v.length - 2) ip += ':';
		}

		if (ip.substr(-1, 1) == ':') ip = ip.substr(0, ip.length - 1);

		// reduce
		var m = /(0\:0(\:0(\:0(\:0(\:0(\:0(\:0)?)?)?)?)?)?)/.exec(ip);
		if (m) {
			ip = ip.replace(m[1], '::');
			ip = ip.replace(/\:\:(\:(\:)?)?/, '::');
		}

		return ip;
	},

	storeIPv6: function(ip)
	{
		var d = [];
		if (/\:\:/.test(ip)) {
			var cnt = 0;
			// restore
			var s = ip.split(/\:\:/);
			var s1 = s[0].split(':');
			var s2 = s[1].split(':');

			if (s1.length > 1 || s1[0] != '') {
				cnt += s1.length;
				d = d.concat(s1);
			}
			cnt += s2.length;
			for (var i = 8 - cnt; i > 0; i--) {
				d.push('00');
			}
			d = d.concat(s2);
		} else {
			d = ip.split(':');
		}

	//	console.log(d);

		var res = '';

		for (var i = 0; i < d.length; i++) {
			var s = jCastle.encoding.hex.decode(d[i]);
			if (s.length == 1) {
				res += "\x00" + s;
			} else {
				res += s;
			}
		}

		return res;
	}
};

