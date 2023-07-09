/**
* Buffer Extention Library
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