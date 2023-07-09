/**
 * A Javascript implemenation of Math - EC
 * 
 * @author Jacob Lee
 *
 * BSD Copyright (C) 2015-2022 Jacob Lee.
 * 
 * Inspired by Java's BouncyCastle.
 */
// https://www.secg.org/sec1-v2.pdf

const jCastle = require('./jCastle');

require('./bigint-extend');
require('./util');
require('./lang/en');
require('./error');
require('./prng');

jCastle.math.ec = {};

// -----------------------------------------------------------------------------
// jCastle.math.ec.fieldElement
// -----------------------------------------------------------------------------

jCastle.math.ec.fieldElement = {};


jCastle.math.ec.fieldElement.fp = class
{
    constructor(q, x)
    {
        this.x = x;
		
// if uncomment here then we will get an error with secp521r1
//
        if (x.compareTo(q) >= 0) {
            throw jCastle.exception('X_VALUE_TOO_LARGE', 'EC001');
        }
//
// or x can be moded by q
//	if (x.compareTo(q) >= 0) {
//		this.x = x.mod(q);
//	}
//

        this.q = q;
    }

	equals(other)
	{
		if(other == this) return true;

		return this.q.equals(other.q) && this.x.equals(other.x);
	}

	toBigInt()
	{
		return this.x;
	}

	clone()
	{
		return new jCastle.math.ec.fieldElement.fp(this.q, this.x.clone());
	}

	isZero()
	{
		return this.toBigInt().equals(0n);
	}

	negate()
	{
		return new jCastle.math.ec.fieldElement.fp(
			this.q,
			this.x.negate().mod(this.q)
		);
	}

	add(b)
	{
		return new jCastle.math.ec.fieldElement.fp(
			this.q,
			this.x.add(b.toBigInt()).mod(this.q)
		);
	}

	subtract(b)
	{
		return new jCastle.math.ec.fieldElement.fp(
			this.q,
			this.x.subtract(b.toBigInt()).mod(this.q)
		);
	}

	multiply(b)
	{
		return new jCastle.math.ec.fieldElement.fp(
			this.q,
			this.x.multiply(b.toBigInt()).mod(this.q)
		);
	}

	square()
	{
		return new jCastle.math.ec.fieldElement.fp(
			this.q,
			this.x.square().mod(this.q)
		);
	}

	pow(n)
	{
		var x = this;
		var one = new jCastle.math.ec.fieldElement.fp(this.q, 1n);
		var R = one;
		var bitlen = n.toString(2).length;

		for (var i = 0; i < bitlen; i++) {
			if (n & (1 << i)) {
				R = R.multiply(x);
			}
			x = x.square();
		}

		return R;
	}

	divide(b)
	{
		return new jCastle.math.ec.fieldElement.fp(
			this.q,
			this.x.multiply(b.toBigInt().modInverse(this.q)).mod(this.q)
		);
	}

	invert()
	{
		return new jCastle.math.ec.fieldElement.fp(this.q, x.modInverse(this.q));
	}

	sqrt()
	{
		if (!this.q.testBit(0)) {
			throw jCastle.exception("NOT_DONE_YET", 'EC002');
		}

		// p mod 4 == 3
		if (this.q.testBit(1)) {
			// z = g^(u+1) + p, p = 4u + 3
			var z = new jCastle.math.ec.fieldElement.fp(
				this.q,
				this.x.modPow(this.q.shiftRight(2n).add(1n), this.q)
			);

			return z.square().equals(this) ? z : null;
		}

		// p mod 4 == 1
		var qMinusOne = this.q.subtract(1n);

		var legendreExponent = qMinusOne.shiftRight(1n);
		if (!(this.x.modPow(legendreExponent, this.q).equals(1n))) {
			return null;
		}

		var u = qMinusOne.shiftRight(2n);
		var k = u.shiftLeft(1n).add(1n);

		var Q = this.x.clone();
		var fourQ = Q.shiftLeft(2n).mod(this.q);

		var U, V;
		var rng = new jCastle.prng();
		do {
			var P;
			do {
                P = BigInt.random(this.q.bitLength(), rng);
			}
			while (P.compareTo(this.q) >= 0
				|| !(P.multiply(P).subtract(fourQ).modPow(legendreExponent, this.q).equals(qMinusOne)));

			var result = this.lucasSequence(this.q, P, Q, k);
			U = result[0];
			V = result[1];

			if (V.multiply(V).mod(this.q).equals(fourQ)) {
				// Integer division by 2, mod q
				if (V.testBit(0)) {
					V = V.add(this.q);
				}

				V = V.shiftRight(1n);

				//assert V.multiply(V).mod(q).equals(x);

				return new jCastle.math.ec.fieldElement.fp(this.q, V);
			}
		}
		while (U.equals(1n) || U.equals(qMinusOne));

		return null;
	}

	lucasSequence(p, P, Q, k)
	{
		var n = k.bitLength();
		var s = Number(k.getLowestSetBit());

		var Uh = 1n;
		var Vl = 2n;
		var Vh = P;
		var Ql = 1n;
		var Qh = 1n;

		for (var j = n - 1; j >= s + 1; --j) {
			Ql = Ql.multiply(Qh).mod(p);

			if (k.testBit(j)) {
				Qh = Ql.multiply(Q).mod(p);
				Uh = Uh.multiply(Vh).mod(p);
				Vl = Vh.multiply(Vl).subtract(P.multiply(Ql)).mod(p);
				Vh = Vh.multiply(Vh).subtract(Qh.shiftLeft(1n)).mod(p);
			} else {
				Qh = Ql;
				Uh = Uh.multiply(Vl).subtract(Ql).mod(p);
				Vh = Vh.multiply(Vl).subtract(P.multiply(Ql)).mod(p);
				Vl = Vl.multiply(Vl).subtract(Ql.shiftLeft(1n)).mod(p);
			}
		}

		Ql = Ql.multiply(Qh).mod(p);
		Qh = Ql.multiply(Q).mod(p);
		Uh = Uh.multiply(Vl).subtract(Ql).mod(p);
		Vl = Vh.multiply(Vl).subtract(P.multiply(Ql)).mod(p);
		Ql = Ql.multiply(Qh).mod(p);

		for (var j = 1; j <= s; ++j) {
			Uh = Uh.multiply(Vl).mod(p);
			Vl = Vl.multiply(Vl).subtract(Ql.shiftLeft(1n)).mod(p);
			Ql = Ql.multiply(Ql).mod(p);
		}

		return [Uh, Vl];
	}

	getByteLength ()
	{
		return (this.toBigInt().bitLength() + 7) >>> 3;
	}
};

jCastle.math.ec = jCastle.math.ec;
jCastle.math.ec.FieldElement = jCastle.math.ec.fieldElement;
jCastle.math.ec.fieldElement.Fp = jCastle.math.ec.fieldElement.fp;

jCastle.math.ec.fieldElement.fp.create = function(q, x)
{
    return new jCastle.math.ec.fieldElement.fp(q, x);
};

// ported from java bouncycastle's
jCastle.math.ec.fieldElement.f2m = class
{
    constructor(m, k1, k2, k3, x)
    {
        this.representation = 0;

        // t = m / 32 rounded up to the next integer
        this.t = (m + 1) >>> 5;

        if (BigInt.is(k2) && typeof k3 == 'undefined') {
            this.representation = 'TBP'; // 2
            x = k2;
            k2 = 0;
            k3 = 0;
        } else if (k2 == 0 && k3 == 0) {
            this.representation = 'TBP'; // 2
        } else {
            if (k2 >= k3) {
                throw jCastle.exception("INVALID_F2M_PARAMS", 'EC003');// new Error("k2 must be smaller than k3");
            }
            if (k2 <= 0) {
                throw jCastle.exception("INVALID_F2M_PARAMS", 'EC004');// new Error("k2 must be larger than 0");
            }
            this.representation = 'PPB'; // 3
        }

        // if (x.compareTo(0n) < 0) {
        //	throw new Error("x value cannot be negative");
        //}

        this.m = m;
        this.k1 = k1;
        this.k2 = k2;
        this.k3 = k3;
        this.x = x;
    }

	toBigInt()
	{
		return this.x;
	}

	clone()
	{
		return new jCastle.math.ec.fieldElement.f2m(this.m, this.k1, this.k2, this.k3, this.x.clone());
	}

	getFieldSize()
	{
		return this.m;
	}

	// computes z * a(z) mod f(z), where f(z) is the reduction polynomial of this.
	multZModF(a)
	{
		// left-shift of a(z)
		var az = a.shiftLeft(1n);

		if (az.testBit(this.m)) {
			// If the coefficient of z^m in a(z) equals 1, reduction
			// modulo f(z) is performed: Add f(z) to to a(z):
			// Step 1: Unset mth coeffient of a(z)
			az = az.clearBit(this.m);

			// Step 2: Add r(z) to a(z), where r(z) is defined as
			// f(z) = z^m + r(z), and k1, k2, k3 are the positions of
			// the non-zero coefficients in r(z)
			az = az.flipBit(0);
			az = az.flipBit(this.k1);
			if (this.representation == 'PPB') {
				az = az.flipBit(this.k2);
				az = az.flipBit(this.k3);
			}
		}

		return az;
	}

	add(b)
	{
		// No check performed here for performance reasons. Instead the
		// elements involved are checked in ECPoint.F2m
		// checkFieldElements(this, b);
		if (b.toBigInt().signum() == 0) {
			return this;
		}

		return new jCastle.math.ec.fieldElement.f2m(
			this.m,
			this.k1,
			this.k2,
			this.k3,
			this.x.xor(b.toBigInt())
		);
	}

	subtract(b)
	{
		// addition and subtraction are the same in F2m
		return this.add(b);
	}


	multiply(b)
	{
		// Left-to-right shift-and-add field multiplication in F2m
		// Input: Binary polynomials a(z) and b(z) of degree at most m-1
		// Output: c(z) = a(z) * b(z) mod f(z)

		// No check performed here for performance reasons. Instead the
		// elements involved are checked in EC.Point.F2m
		// jCastle.math.ec.fieldElement.f2m.checkFieldElements(this, b);
		var az = this.toBigInt();
		var bz = b.toBigInt();
		var cz;

		// Compute c(z) = a(z) * b(z) mod f(z)
		if (az.testBit(0)) {
			cz = bz;
		} else {
			cz = 0n;
		}

		for (var i = 1; i < this.m; i++) {
			// b(z) := z * b(z) mod f(z)
			bz = this.multZModF(bz);

			if (az.testBit(i)) {
				// If the coefficient of x^i in a(z) equals 1, b(z) is added to c(z)
				cz = cz.xor(bz);
			}
		}

		return new jCastle.math.ec.fieldElement.f2m(
			this.m,
			this.k1,
			this.k2,
			this.k3,
			cz
		);
	}

	divide(b)
	{
		var bInv = b.invert();
		return this.multiply(bInv);
	}

	negate()
	{
		// -x ==x holds for all x in F2m
		return this;
	}

	square()
	{
		return this.multiply(this);
	}

	invert()
	{
		// Inversion in F2m using the extended Euclidean algorithm
		// Input: A nonzero polynomial a(z) of degree at most m-1
		// Output: a(z)^(-1) mod f(z)

		// u(z) := a(z)
		var uz = this.x.clone();
		if (uz.signum() <= 0) {
			throw jCastle.exception("NEGATIVE_VALUE", 'EC005'); // new Error("x is zero or negative, inversion is impossible");
		}

		// v(z) := f(z)
		var vz = 0n.setBit(this.m);
		vz = vz.setBit(0);
		vz = vz.setBit(this.k1);
		if (this.representation == 'PPB') {
			vz = vz.setBit(this.k2);
			vz = vz.setBit(this.k3);
		}

		// g1(z) := 1, g2(z) := 0
		var g1z = 1n;
		var g2z = 0n;

		// while u != 1
		while (!(uz.equals(0n))) {
			// j := deg(u(z)) - deg(v(z))
			var j = uz.bitLength() - vz.bitLength();

			// If j < 0 then: u(z) <-> v(z), g1(z) <-> g2(z), j := -j
			if (j < 0) {
				var uzCopy = uz.clone();
				uz = vz;
				vz = uzCopy;

				var g1zCopy = g1z.clone();
				g1z = g2z;
				g2z = g1zCopy;

				j = -j;
			}

			// u(z) := u(z) + z^j * v(z)
			// Note, that no reduction modulo f(z) is required, because
			// deg(u(z) + z^j * v(z)) <= max(deg(u(z)), j + deg(v(z)))
			// = max(deg(u(z)), deg(u(z)) - deg(v(z)) + deg(v(z))
			// = deg(u(z))
			uz = uz.xor(vz.shiftLeft(j));

			// g1(z) := g1(z) + z^j * g2(z)
			g1z = g1z.xor(g2z.shiftLeft(j));

	//		if (g1z.bitLength() > this.m) {
	//			throw new Error("deg(g1z) >= m, g1z = " + g1z.toString(2));
	//		}
		}

		return new jCastle.math.ec.fieldElement.f2m(
			this.m,
			this.k1,
			this.k2,
			this.k3,
			g2z
		);
	}

	pow(n)
	{
		var x = this;
		var one = new jCastle.math.ec.fieldElement.f2m(this.m, this.k1, this.k2, this.k3, 1n);
		var R = one;
		var bitlen = n.toString(2).length;

		for (var i = 0; i < bitlen; i++) {
			if (n & (1 << i)) {
				R = R.multiply(x);
			}
			x = x.square();
		}

		return R;
	}

	sqrt()
	{
	// http://cs.ucsb.edu/~koc/ecc/docx/GuideEllipticCurveCryptography.pdf
	// or http://math.boisestate.edu/~liljanab/MATH508/GuideEllipticCurveCryptography.PDF
	// look at page 136
	//
	// http://math.ucalgary.ca/ecc/files/ecc/u5/Lopez_ECC2009.pdf

	// in binary field, c.pow(2.pow(m)) = c
	// thus sqrt(c) = c.pow(2.pow(m-1))

	// now we haven't implemented yet!
	// this function is only used for decompressing any encoded point,
	// so it's not urgent.

		var x = this;
		
		for (var i = 0; i < this.m - 1; i++) {
			x = x.square();
		}

		return x;
	}

	isZero()
	{
		return this.toBigInt().equals(0n);
	}

	getRepresentation()
	{
		return this.representation;
	}


	// the degree m of the reduction polynomial f(z)
	getM()
	{
		return this.m;
	}

	getK1()
	{
		return this.k1;
	}

	getK2()
	{
		return this.k2;
	}

	getK3()
	{
		return this.k3;
	}

	equals(other)
	{
		if (other == this) return true;

		if (!(other instanceof jCastle.math.ec.fieldElement.f2m)) return false;

		return this.m == other.m &&
			this.k1 == other.k1 &&
			this.k2 == other.k2 &&
			this.k3 == other.k3 && 
			this.x.equals(other.x);
	}

	getByteLength ()
	{
		return (this.toBigInt().bitLength() + 7) >>> 3;
	}
};

jCastle.math.ec.fieldElement.F2m = jCastle.math.ec.fieldElement.f2m;

jCastle.math.ec.fieldElement.f2m.create = function(m, k1, k2, k3, x)
{
    return new jCastle.math.ec.fieldElement.f2m(m, k1, k2, k3, x);
};

// checks, if the ECFieldElements a and b are elements of the same field F2m
// (having the same prepresentation).
jCastle.math.ec.fieldElement.f2m.checkFieldElements = function(a, b)
{
	if (!(a instanceof jCastle.math.ec.fieldElement.f2m) || !(b instanceof jCastle.math.ec.fieldElement.f2m)) {
		throw jCastle.exception("NOT_FIELDELEMENT", 'EC006'); // new Error("Field elements are not both instances of ECElement.F2m");
	}

	if (a.x.signum() < 0 || b.x.signum() < 0) {
		throw jCastle.exception("NEGATIVE_VALUE", 'EC007'); // new Error("x value may not be negative");
	}
	
	if (a.m != b.m || a.k1 != b.k1 || a.k2 != b.k2 || a.k3 != b.k3) {
		throw jCastle.exception("NOT_SAME_CURVE", 'EC008'); // new Error("Field elements are not elements of the same field F2m");
	}
	
	if (a.representation != b.representation) {
		throw jCastle.exception("DIFFERENT_REPRESENTATION", 'EC009'); // new Error("One of the field elements has incorrect representation");
	}
};


// -----------------------------------------------------------------------------
// jCastle.math.ec.point
// -----------------------------------------------------------------------------

jCastle.math.ec.point = {};

/*
Double-and-Add Algorithm for Point Multiplication

Input: elliptic curve E, an elliptic curve point P and a scalar d with bits d_i
Output: T = dP

Initalization:

T = P

Algorithm:

FOR i = t-1 DOWNTO 0
    T = T + T mod n
	IF d_i = 1
	    T = T + P mod n
RETURN (T)

Example: 26P = (11010)P

Step
#0				P = 1P										initial setting
#1a				P + P = 2P = (10)P							DOUBLE
#lb				2p + P = 3P = (10)P + (1)P					ADD
#2a				3P + 3P = 6P = 2(11)P = (110)P				DOUBLE
#2b															no ADD
#3a				6P + 6P = 12P = 2(110)P = (1100)P			DOUBLE
#3b				12P + P = 13P = (1100)P + (1)P = (1101)P	ADD
#4a				13P + 13P = 26P = 2(1101)P = (11010)P		DOUBLE
#4b															no ADD
*/
// there are diverse methods of multiplication of a point on the elliptic curve.
// https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication
//
// speed test
// (z-signed-digit, double-add) > montgomery-ladder > classic-double-add
// sometimes double-add method is faster than z-signed-digit,
// in average, z-signed-digit seems to be faster a little.
// anyway, default one is double-add
jCastle.math.ec.point.multiplyPositive = function(point, k, method)
{
	switch (method) {
		case 'montgomery-ladder':
			var R = [point.curve.getInfinity(), point];
			var n = k.bitLength();
			var i = n;
			var b, bp;

			while (--i >= 0) {
				b = k.testBit(i) ? 1 : 0;
				bp = 1 - b;
				R[bp] = R[bp].add(R[b]);
				R[b] = R[b].twice();
			}

			return R[0];

		case 'z-signed-digit':
			var neg = point.negate();
			var R = point;
			var n = k.bitLength();
			var s = k.getLowestSetBit();
			var i = n;

			while (--i > s) {
				R = R.twice().add(k.testBit(i) ? point : neg);
			}

			R = R.timesPow2(s);

			return R;

		case 'classic-double-add':
			var h = k.multiply(3n);
			var neg = point.negate();
			var R = point;
			var hBit, kBit;

			for (var i = h.bitLength() - 2; i > 0; --i) {
				R = R.twice();

				hBit = h.testBit(i);
				kBit = k.testBit(i);

				if (hBit != kBit) {
					R = R.add(hBit ? point : neg);
				}
			}

			return R;

		case 'double-add':
		default:
			var R = [point.curve.getInfinity(), point];
			var n = k.bitLength();
			var b, bp;

			for (var i = 0; i < n; i++) {
				b = k.testBit(i) ? 1 : 0;
				bp = 1 - b;
				R[bp] = R[bp].twice().add(R[b]);
			}

			return R[0];

	}
};

jCastle.math.ec.point.fp = class
{
    constructor(curve, x, y, compressed)
    {
        this.curve = curve;
        this.x = x;
        this.y = y;

        this.compressed = compressed ? compressed : false;

        if ((this.x != null && y == null) || (this.x == null && this.y != null)) {
            throw jCastle.exception("ONE_IS_NULL", 'EC010'); // new Error("Exactly one of the field element is null");
        }
    }

	getCurve()
	{
		return this.curve;
	}

	getX()
	{
		return this.x;
	}

	getY()
	{
		return this.y;
	}

	clone()
	{
		return new jCastle.math.ec.point.fp(this.curve, this.x.clone(), this.y.clone(), this.compressed);
	}

	equals(other)
	{
		if(other == this) return true;
		if(this.isInfinity()) return other.isInfinity();
		if(other.isInfinity()) return this.isInfinity();

		return this.x.equals(other.x) && this.y.equals(other.y);
	}

	isInfinity()
	{
		return (this.x == null) && (this.y == null);
	}

	negate()
	{
		return new jCastle.math.ec.point.fp(
			this.curve,
			this.x,
			this.y.negate(),
			this.compressed
		);
	}

	/*
	Elliptic Curve Point Addition and Doubling Formulas:

	R.x = gamma^2 - P.x - Q.x mod p and
	R.y = gamma * (P.x - R.x) - P.y mod p

	where

	if P != Q : (point addtion)
	gamma = (Q.y - P.y) / (Q.x - P.x) mod p

	if P == Q : (point doubling)
	gamma = (3 * P.x^2 + curve.a) / (2 * P.y) mod p
	*/
	add(b)
	{
		if(this.isInfinity()) return b;
		if(b.isInfinity()) return this;

		// check if b == this or b == -this
		if (this.x.equals(b.x)) {
			if (this.y.equals(b.y)) {
				// this = b, i.e. this must be doubled
				return this.twice();
			}
			// this = -b, i.e. the result is the point at infinity
			return this.curve.getInfinity();
		}

		// point addtion
		// gamma = (Q.y - P.y) / (Q.x - P.x) mod p
		var gamma = b.y.subtract(this.y).divide(b.x.subtract(this.x));
		var x3 = gamma.square().subtract(this.x).subtract(b.x);
		//var y3 = gamma.multiply(this.x.subtract(x3)).subtract(this.y);
		var y3 = this.x.subtract(x3).multiply(gamma).subtract(this.y);

		return new jCastle.math.ec.point.fp(this.curve, x3, y3);
	}

	twice()
	{
		if (this.isInfinity()) {
			return this;
		}
		if (this.y.toBigInt().signum() == 0) {
			// if y1 == 0, then (x1, y1) == (x1, -y1)
			// and hence this = -this and thus 2(x1, y1) == infinity
			return this.curve.getInfinity();
		}

		// point doubling
		// gamma = (3 * P.x^2 + curve.a) / (2 * P.y) mod p
		var TWO = this.curve.fromBigInt(2n);
		var THREE = this.curve.fromBigInt(3n);
		var gamma = this.x.square().multiply(THREE).add(this.curve.a).divide(this.y.multiply(TWO));

		var x3 = gamma.square().subtract(this.x.multiply(TWO));
		//var y3 = gamma.multiply(this.x.subtract(x3)).subtract(this.y);
		var y3 = this.x.subtract(x3).multiply(gamma).subtract(this.y);

		return new jCastle.math.ec.point.fp(this.curve, x3, y3, this.compressed);
	}

	multiply(k, method = 'double-add') // the fastest one
	{
		var sign = k.signum();

		if (sign == 0 || this.isInfinity()) {
			return this.curve.getInfinity();
		}

		var positive = jCastle.math.ec.point.multiplyPositive(this, k.abs(), method);

		return sign > 0 ? positive : positive.negate();
	}

	threeTimes()
	{
		return this.twice().add(this);
	}

	timesPow2(e)
	{
		if (e < 0) throw new Error("e cannot be negative");

		var p = this;

		while (--e >= 0) {
			p = p.twice();
		}

		return p;
	}

	// Compute this*j + x*k (simultaneous multiplication)
	multiplyTwo(j, x, k)
	{
		var i;
		if(j.bitLength() > k.bitLength()) {
			i = j.bitLength() - 1;
		} else {
			i = k.bitLength() - 1;
		}

		var R = this.curve.getInfinity();
		var both = this.add(x);
		while(i >= 0) {
			R = R.twice();
			if(j.testBit(i)) {
				if(k.testBit(i)) {
					R = R.add(both);
				} else {
					R = R.add(this);
				}
			} else {
				if(k.testBit(i)) {
					R = R.add(x);
				}
			}
			--i;
		}

		return R;
	}

	subtract(b)
	{
		if (b.isInfinity()) return this;

		// Add -b
		return this.add(b.negate());
	}

	encodePoint(compressed = false)
	{
		//var len = this.getCurve().getQ().toBufferUnsigned().length;
		var len = (this.getCurve().getN().bitLength + 7) >>> 3;
		var x = this.getX().toBigInt();
		var y = this.getY().toBigInt();
		var enc = x.toBufferUnsigned();

		if (enc.length < len) {
			enc = Buffer.concat([Buffer.alloc(len - enc.length, 0x00), enc]);
		}

		if(compressed) {
			if (y.isEven()) {
				// Compressed even pubkey
				// M = 02 || X
				enc = Buffer.concat([Buffer.from([0x02]), enc]);
			} else {
				// Compressed uneven pubkey
				// M = 03 || X
				enc = Buffer.concat([Buffer.from([0x03]), enc]);
			}
		} else {
			// Uncompressed pubkey
			// M = 04 || X || Y
			enc = Buffer.concat([Buffer.from([0x04]), enc]);

			var encY = y.toBufferUnsigned();

			while (encY.length < len) {
				encY = Buffer.concat([Buffer.from([0x00]), encY]);
			}
			enc = Buffer.concat([enc, encY]);
		}

		return enc;
	}

	toString(base, compressed = false)
	{
		//var len = this.getCurve().getQ().toBuffer().length;
        //var len = this.getCurve().getQ().toString(base).length;
		var len = (this.getCurve().getQ().bitLength + 7) >>> 3;
		var x = this.getX().toBigInt();
		var y = this.getY().toBigInt();
		var res = '';
		var y_is_even = y.isEven();

		x = x.toString(base);
		y = y.toString(base);

		while (x.length < len) {
			x = '0' + x;
		}
		while (y.length < len) {
			y = '0' + y;
		}

		res += x;

		if (compressed) {
			if (y_is_even) {
				res = '02' + res;
			} else {
				res = '03' + res;
			}
		} else {
			res = '04' + res;
			res += y;
		}

		return res;
	}

	// do not use it. rather use curve.decodePoint() for safty
	decodePoint(curve, s)
	{
		var enc = s;
		if (!Buffer.isBuffer(enc)) enc = Buffer.from(enc, 'hex');

		var type = enc[0];
		var len = enc.length - 1;
        var x, y, xBa, yBa;
        var a = this.curve.getA();
		var b = this.curve.getB();

        if (type === 0x04) {
            // Extract x and y as byte arrays
            xBa = enc.slice(1, 1 + len / 2);
            //var yBa = enc.slice(1 + len / 2, 1 + len);
            yBa = enc.slice(1 + len / 2);

            // Prepend zero byte to prevent interpretation as negative integer
            // Convert to BigInt
            x = BigInt.fromBufferUnsigned(xBa);
            y = BigInt.fromBufferUnsigned(yBa);

            // Return point
            return new jCastle.math.ec.point.fp(
                curve,
                curve.fromBigInt(x),
                curve.fromBigInt(y)
            );
        } else {
            xBa = enc.slice(1);
            x = BigInt.fromBufferUnsigned(xBa);
            // since y^2 = x^3 + ax + b
            var y2 = x.square().add(a).multiply(x).add(b);
            y = y2.sqrt();

            // if we can't find a sqrt we haven't got a point on the curve.
			if (y == null) {
				//throw new Error("Invalid point compression");
				throw jCastle.exception("INVALID_ENCODING", 'EC021');
			}

			var bit0 = y.toBigInt().testBit(0) ? 1 : 0;
            var p;

			if (bit0 == ytilde) {
				p = new jCastle.math.ec.point.fp(
					this,
					x,
					y,
	//				null,
					true
				);
			} else {
				p = new jCastle.math.ec.point.fp(
					this,
					x,
	//				new jCastle.math.ec.fieldElement.fp(this.q, this.q.subtract(y.toBigInt())),
					y.negate(),
	//				null,
					true
				);
			}
            return p;
        }
	}

	isOnCurve()
	{
		var x = this.getX();
		var y = this.getY();
		var a = this.curve.getA();
		var b = this.curve.getB();

		// y^2 = x^3 + ax + b
		var lhs = y.square();
		var rhs = x.square().add(a).multiply(x).add(b);

		return lhs.equals(rhs);
	}

	validate()
	{
		var q = this.curve.getQ();

		// Check Q != O
		if (this.isInfinity()) {
			//throw new Error("Point is at infinity.");
			return false;
		}

		// Check coordinate bounds
		var x = this.getX().toBigInt();
		var y = this.getY().toBigInt();

		if (x.compareTo(1n) < 0 ||
			x.compareTo(q.subtract(1n)) > 0
		) {
			//throw new Error('x coordinate out of bounds');
			return false;
		}
		if (y.compareTo(1n) < 0 ||
			y.compareTo(q.subtract(1n)) > 0
		) {
			//throw new Error('y coordinate out of bounds');
			return false;
		}

		// Check y^2 = x^3 + ax + b (mod n)
		if (!this.isOnCurve()) {
			//throw new Error("Point is not on the curve.");
			return false;
		}

	// commented. for if the point is not the base point then it is invalid
	//
	//	// Check nQ = 0 (Q is a scalar multiple of G)
	//	if (this.multiply(n).isInfinity()) {
	//		// TODO: This check doesn't work - fix.
	//		//throw new Error("Point is not a scalar multiple of G.");
	//		return false;
	//	}
	//
		return true;
	}
};

jCastle.math.ec.Point = jCastle.math.ec.point;
jCastle.math.ec.point.Fp = jCastle.math.ec.point.fp;

jCastle.math.ec.point.fp.create = function(curve, x, y, compressed)
{
    return new jCastle.math.ec.point.fp(curve, x, y, compressed);
};

jCastle.math.ec.point.f2m = class
{
    constructor(curve, x, y)
    {
        this.curve = curve;
        this.x = x;
        this.y = y;

        if ((x != null && y == null) || (x == null && y != null)) {
            throw jCastle.exception("ONE_IS_NULL", 'EC011'); // new Error("Exactly one of the field elements is null");
        }
                    
        if (x != null) {
            // Check if x and y are elements of the same field
            jCastle.math.ec.fieldElement.f2m.checkFieldElements(this.x, this.y);
            
            // Check if x and a are elements of the same field
            if (curve != null) {
                jCastle.math.ec.fieldElement.f2m.checkFieldElements(this.x, this.curve.getA());
            }
        }
    }

	getX()
	{
		return this.x;
	}

	getY()
	{
		return this.y;
	}

	getCurve()
	{
		return this.curve;
	}

	clone()
	{
		return new jCastle.math.ec.point.f2m(this.curve, this.x.clone(), this.y.clone());
	}

	equals(other)
	{
		if(other == this) return true;
		if(this.isInfinity()) return other.isInfinity();
		if(other.isInfinity()) return this.isInfinity();

		return this.x.equals(other.x) && this.y.equals(other.y);
	}

	encodePoint(compressed)
	{
		if (this.isInfinity()) {
            return Buffer.alloc(1, 0x00);
		}

		var X = this.getX().toBigInt().toBufferUnsigned();
		var Y = this.getY().toBigInt().toBufferUnsigned();
		//var length = (this.getCurve().getN().bitLength() + 7) >>> 3;
		var length = (this.getCurve().getM() + 7) >>> 3; // important!

		if (X.length < length)
			X = Buffer.concat([Buffer.alloc(length - X.length, 0x00), X]);

		var PO;

		if (compressed) {
			// See X9.62 4.3.6 and 4.2.2
			PO = Buffer.alloc(1, 0x02);

			// X9.62 4.2.2 and 4.3.6:
			// if x = 0 then ypTilde := 0, else ypTilde is the rightmost
			// bit of y * x^(-1)
			// if ypTilde = 0, then PC := 02, else PC := 03
			// Note: PC === PO[0]
			if (!(this.getX().toBigInt().equals(0n))) {
				if (this.getY().multiply(this.getX().invert()).toBigInt().testBit(0)) {
					// ypTilde = 1, hence PC = 03
					PO[0] = 0x03;
				}
			}

			//PO = PO.concat(X);
			PO = Buffer.concat([PO, X]);
		} else {
			if (Y.length < length)
				Y = Buffer.concat([Buffer.alloc(length - Y.length, 0x00), Y]);
		
			PO = Buffer.alloc(1, 0x04);
			PO = Buffer.concat([PO, X, Y]);
		}

		return PO;
	}


	checkPoints(a, b)
	{
		// Check, if points are on the same curve
		if (!(a.curve.equals(b.curve))) {
			throw jCastle.exception("NOT_SAME_CURVE", 'EC012'); // new Error("Only points on the same curve can be added or subtracted");
		}

	//	jCastle.math.ec.fieldElement.f2m.checkFieldElements(a.x, b.x);
	}

	add(b, do_check)
	{
		if (typeof do_check == 'undefined' || do_check) {
			this.checkPoints(this, b);
		}

		if (this.isInfinity()) return b;

		if (b.isInfinity()) return this;

		var x2 = b.getX();
		var y2 = b.getY();

		// Check if other = this or other = -this
		if (this.x.equals(x2)) {
			if (this.y.equals(y2)) {
				// this = other, i.e. this must be doubled
				return this.twice();
			}

			// this = -other, i.e. the result is the point at infinity
			return this.curve.getInfinity();
		}

		var lambda = (this.y.add(y2)).divide(this.x.add(x2));
		var x3 = lambda.square().add(lambda).add(this.x).add(x2).add(this.curve.getA());
		//var y3 = lambda.multiply(this.x.add(x3)).add(x3).add(this.y);
		var y3 = this.x.add(x3).multiply(lambda).add(x3).add(this.y);

		return new jCastle.math.ec.point.f2m(this.curve, x3, y3);
	}

	subtract(b)
	{
		this.checkPoints(this, b);
		
		if (b.isInfinity()) {
			return this;
		}

		// Add -b
		return this.add(b.negate(), false);
	}

	twice()
	{
		if (this.isInfinity()) {
			// Twice identity element (point at infinity) is identity
			return this;
		}

		if (this.x.toBigInt().signum() == 0) {
			// if x1 == 0, then (x1, y1) == (x1, x1 + y1)
			// and hence this = -this and thus 2(x1, y1) == infinity
			return this.curve.getInfinity();
		}

		//var lambda = this.x.add(this.y.divide(this.x));
		var lambda = this.y.divide(this.x).add(this.x);
		var x3 = lambda.square().add(lambda).add(this.curve.getA());
		var ONE = this.curve.fromBigInt(1n);
		var y3 = this.x.square().add(x3.multiply(lambda.add(ONE)));

		return new jCastle.math.ec.point.f2m(this.curve, x3, y3);
	}

	multiply(k, method)
	{
		method = method || 'double-add'; // the fastest one

		var sign = k.signum();

		if (sign == 0 || this.isInfinity()) {
			return this.curve.getInfinity();
		}

		var positive = jCastle.math.ec.point.multiplyPositive(this, k.abs(), method);

		return sign > 0 ? positive : positive.negate();
	}

	threeTimes()
	{
		return this.twice().add(this);
	}

	timesPow2(e)
	{
		if (e < 0) throw new Error("e cannot be negative");

		var p = this;

		while (--e >= 0) {
			p = p.twice();
		}

		return p;
	}

	negate()
	{
		return new jCastle.math.ec.point.f2m(
			this.curve,
			this.getX(),
			this.getY().add(this.getX())
		);
	}

	// Compute this*j + x*k (simultaneous multiplication)
	multiplyTwo(j, x, k)
	{
		var i;
		if(j.bitLength() > k.bitLength()) {
			i = j.bitLength() - 1;
		} else {
			i = k.bitLength() - 1;
		}

		var R = this.curve.getInfinity();
		var both = this.add(x);
		while(i >= 0) {
			R = R.twice();
			if(j.testBit(i)) {
				if(k.testBit(i)) {
					R = R.add(both);
				} else {
					R = R.add(this);
				}
			} else {
				if(k.testBit(i)) {
					R = R.add(x);
				}
			}
			--i;
		}

		return R;
	}

	isInfinity()
	{
		return  this.x == null && this.y == null;
	}


	// it doesn't support any compression...
	decodePoint(curve, s)
	{
		var enc = s;
		if (!Buffer.isBuffer(enc)) enc = Buffer.from(enc, 'hex');

		var type = enc[0];
		var len = enc.length - 1;

		// Extract x and y as byte arrays
		var xBa = enc.slice(1, 1 + len / 2);
		//var yBa = enc.slice(1 + len / 2, 1 + len);
        var yBa = enc.slice(1 + len / 2);

		// Prepend zero byte to prevent interpretation as negative integer
		// Convert to BigInt
		var x = BigInt.fromBufferUnsigned(xBa);
		var y = BigInt.fromBufferUnsigned(yBa);

		// Return point
		return new jCastle.math.ec.point.f2m(
			curve,
			curve.fromBigInt(x),
			curve.fromBigInt(y)
		);
	}

	isOnCurve()
	{
		var x = this.getX();
		var y = this.getY();
		var a = this.curve.getA();
		var b = this.curve.getB();

		// y^2 + xy = x^3 + ax + b
		var lhs = y.add(x).multiply(y);
		var rhs = x.add(a).multiply(x.square()).add(b);

		return lhs.equals(rhs);
	}

	validate()
	{
	//	var q = this.curve.getQ();

		// Check Q != O
		if (this.isInfinity()) {
			//throw new Error("Point is at infinity.");
			return false;
	//		return true;
		}

		// Check coordinate bounds
	//	var x = this.getX().toBigInt();
	//	var y = this.getY().toBigInt();
	//
	//	if (x.compareTo(1n) < 0 ||
	//		x.compareTo(q.subtract(1n)) > 0
	//	) {
	//		//throw new Error('x coordinate out of bounds');
	//		return false;
	//	}
	//	if (y.compareTo(1n) < 0 ||
	//		y.compareTo(q.subtract(1n)) > 0
	//	) {
	//		//throw new Error('y coordinate out of bounds');
	//		return false;
	//	}

		// Check y^2 = x^3 + ax + b (mod n)
		if (!this.isOnCurve()) {
			//throw new Error("Point is not on the curve.");
			return false;
		}

	// commented. for if the point is not the base point then it is invalid
	//
	//	// Check nQ = 0 (Q is a scalar multiple of G)
	//	if (this.multiply(n).isInfinity()) {
	//		// TODO: This check doesn't work - fix.
	//		//throw new Error("Point is not a scalar multiple of G.");
	//		return false;
	//	}
	//
		return true;
	}
};

jCastle.math.ec.point.F2m = jCastle.math.ec.point.f2m;

// -----------------------------------------------------------------------------
// jCastle.math.ec.curve
// -----------------------------------------------------------------------------

jCastle.math.ec.curve = {};

jCastle.math.ec.curve.fp = class
{
    constructor(q, a, b , n, h)
    {
        this.q = q;
        this.a = this.fromBigInt(a);
        this.b = this.fromBigInt(b);
        this.infinity = new jCastle.math.ec.point.fp(this, null, null);
        this.reducer = new BigInt.Barrett(this.q); // this.s
        this.n = n; // order of q
        this.h = h;
    }

	getQ()
	{
		return this.q;
	}

	getA()
	{
		return this.a;
	}

	getB()
	{
		return this.b;
	}

	getN()
	{
		return this.n;
	}

	getH()
	{
		return this.h;
	}

	getCofactor()
	{
		return this.h;
	}

	equals(other)
	{
		if(other == this) return true;

		return this.q.equals(other.q) &&
			this.a.equals(other.a) &&
			this.b.equals(other.b);
	}

	createPoint(x, y, compressed)
	{
		return new jCastle.math.ec.point.fp(this, this.fromBigInt(x), this.fromBigInt(y), compressed);
	}

	getInfinity()
	{
		return this.infinity;
	}

	fromBigInt(x)
	{
		return new jCastle.math.ec.fieldElement.fp(this.q, x);
	}

	reduce(x)
	{
		return this.reducer.reduce(x);
	}

	encodePoint(p)
	{
		if (typeof p == 'undefined' || p == null) p = this;

		if (p.isInfinity()) {
            return Buffer.alloc(1, 0x00);
        }

		var x = p.getX().toBigInt().toBufferUnsigned();
		var y = p.getY().toBigInt().toBufferUnsigned();
		var len = (this.getN().bitLength + 7) >>> 3;

		if (x.length < len) {
			x = Buffer.concat([Buffer.alloc(len - x.length, 0x00), x]);
		}

		if (y.length < len) {
			y = Buffer.concat([Buffer.alloc(len - y.length, 0x00), y]);
		}

		return Buffer.concat([Buffer.alloc(1, 0x04), x, y])
	}

	decodePoint(enc)
	{
		var p = null;
		var s = enc;
		if (!Buffer.isBuffer(s)) s = Buffer.from(s, 'hex');

		switch (s[0]) {
			// infinity
			case 0x00:
				p = this.getInfinity();
				break;
			// compressed
			case 0x02:
			case 0x03:
				var ytilde = s[0];
				ytilde &= 1;

                var x = new jCastle.math.ec.fieldElement.fp(this.q, BigInt.fromBufferUnsigned(s.slice(1)));
				// y^2 = x^3 + a * x + b
				// y^2 = x * (x^2 + a) + b
				//var y2 = x.multiply(x.square().add(this.a)).add(this.b);
				var y2 = x.square().add(this.a).multiply(x).add(this.b);
				var y = y2.sqrt();

				// if we can't find a sqrt we haven't got a point on the curve.
				if (y == null) {
					//throw new Error("Invalid point compression");
					throw jCastle.exception("INVALID_ENCODING", 'EC020');
				}

				var bit0 = y.toBigInt().testBit(0) ? 1 : 0;

				if (bit0 == ytilde) {
					p = new jCastle.math.ec.point.fp(
						this,
						x,
						y,
	//					null,
						true
					);
				} else {
					p = new jCastle.math.ec.point.fp(
						this,
						x,
	//					new jCastle.math.ec.fieldElement.fp(this.q, this.q.subtract(y)),
						y.negate(),
	//					null,
						true
					);
				}
				break;
			// uncompressed
			case 0x04:
			// hybrid
			case 0x06:
			case 0x07:
				var s1 = s.slice(1);
				var x = s1.slice(0, s1.length / 2);
				var y = s1.slice(s1.length / 2);

				p = new jCastle.math.ec.point.fp(this,
						this.fromBigInt(BigInt.fromBufferUnsigned(x)),
						this.fromBigInt(BigInt.fromBufferUnsigned(y))
					);
				break;

			default:
				throw jCastle.exception("INVALID_ENCODING", 'EC013'); // new Error("Invalid point encoding 0x" + s.charCodeAt(0).toString(16));
		}

		return p;
	}
};

jCastle.math.ec.Curve = jCastle.math.ec.curve;
jCastle.math.ec.curve.Fp = jCastle.math.ec.curve.fp;


//
//Trinomial Polynomial Basis (TPB):
//
//	m - The exponent m of F 2^m.
//	k1 - The integer k where x^m + x^k1 + 1 represents the reduction polynomial f(z).
//	a - The coefficient a in the Weierstrass equation for non-supersingular elliptic curves over F2m.
//	b - The coefficient b in the Weierstrass equation for non-supersingular elliptic curves over F2m.
//	k2 and k3 should be always 0.
//
//Pentanomial Polynomial Basis (PPB):
//
//	m - The exponent m of F 2^m.
//	k1 - The integer k1 where x^m + x^k3 + x^k2 + x^k1 + 1 represents the reduction polynomial f(z).
//	k2 - The integer k2 where xm + x^k3 + x^k2 + x^k1 + 1 represents the reduction polynomial f(z).
//	k3 - The integer k3 where xm + x^k3 + x6k2 + x^k1 + 1 represents the reduction polynomial f(z).
//	a - The coefficient a in the Weierstrass equation for non-supersingular elliptic curves over F2m.
//	b - The coefficient b in the Weierstrass equation for non-supersingular elliptic curves over F2m.
//

jCastle.math.ec.curve.f2m = class
{
    constructor(m, k1, k2, k3, a, b, n, h)
    {
        this.m = m;

        this.k1 = k1;
        this.k2 = k2;
        this.k3 = k3;

        this.n = n;
        this.h = h;

        if (k1 == 0) {
            throw jCastle.exception("INVALID_F2M_PARAMS", 'EC014'); // new Error("k1 must be > 0");
        }

        if (k2 == 0) {
            if (k3 != 0) {
                throw jCastle.exception("INVALID_F2M_PARAMS", 'EC015'); // new Error("k3 must be 0 if k2 == 0");
            }
        } else {
            if (k2 <= k1) {
                throw jCastle.exception("INVALID_F2M_PARAMS", 'EC016'); // new Error("k2 must be > k1");
            }

            if (k3 <= k2) {
                throw jCastle.exception("INVALID_F2M_PARAMS", 'EC017'); // new Error("k3 must be > k2");
            }
        }

        this.a = this.fromBigInt(a);
        this.b = this.fromBigInt(b);
        this.infinity = new jCastle.math.ec.point.f2m(this, null, null);

    //	this.mu = 0;
    //	this.si = null;
    }

	getA()
	{
		return this.a;
	}

	getB()
	{
		return this.b;
	}

	getM()
	{
		return this.m;
	}

	getK1()
	{
		return this.k1;
	}

	getK2()
	{
		return this.k2;
	}

	getK3()
	{
		return this.k3;
	}

	getN()
	{
		return this.n;
	}

	getH()
	{
		return this.h;
	}

	getCofactor()
	{
		return this.h;
	}

	// Return true if curve uses a Trinomial basis.
	isTrinomial()
	{
		return this.k2 == 0 && this.k3 == 0;
	}

	getFieldSize()
	{
		return this.m;
	}

	getInfinity()
	{
		return this.infinity;
	}

	fromBigInt(x)
	{
		return new jCastle.math.ec.fieldElement.f2m(
			this.m,
			this.k1,
			this.k2,
			this.k3,
			x
		);
	}

	createPoint(x, y)
	{
		return new jCastle.math.ec.point.f2m(
			this,
			this.fromBigInt(x),
			this.fromBigInt(y)
		);
	}

//	equals(other)
//	{
//		if(other == this) return true;
//
//		if (this.isInfinity()) return other.isInfinity();
//
//		return this.a.equals(other.a) && this.b.equals(other.b);
//	}

	encodePoint(p)
	{
		if (typeof p == 'undefined' || p == null) p = this;

		if (p.isInfinity()) {
            return Buffer.alloc(1, 0x00);
        }

		var x = p.getX().toBigInt().toBufferUnsigned();
		var y = p.getY().toBigInt().toBufferUnsigned();
		var len = (this.getM().bitLength + 7) >>> 3; // important!

		if (x.length < len) {
			x = Buffer.concat([Buffer.alloc(len - x.length, 0x00), x]);
		}

		if (y.length < len) {
			y = Buffer.concat([Buffer.alloc(len - y.length, 0x00), y]);
		}

		return Buffer.concat([Buffer.alloc(1, 0x04), x, y]);
	}

	decodePoint(enc)
	{
		var p = null;
		var s = enc;
		if (!Buffer.isBuffer(s)) s = Buffer.from(s, 'hex');

		switch (s[0]) {
			// infinity
			case 0x00:
				p = this.getInfinity();
				break;
			// compressed
			case 0x02:
			case 0x03:
				var type = s[0];
				p = this.decompressPoint(s.slice(1), type == 0x02 ? 0 : 1);
				break;
			// uncompressed
			case 0x04:
			// hybrid
			case 0x06:
			case 0x07:
				var s1 = s.slice(1);
				var x = s1.slice(0, s1.length / 2);
				var y = s1.slice(s1.length / 2);


				p = new jCastle.math.ec.point.f2m(this,
						this.fromBigInt(BigInt.fromBufferUnsigned(x)),
						this.fromBigInt(BigInt.fromBufferUnsigned(y))
					);
				break;

			default:
				throw jCastle.exception("INVALID_ENCODING", 'EC018');// new Error("Invalid point encoding 0x" + s.charCodeat(0).toString(16));
		}

		return p;
	}

	getInfinity()
	{
		return this.infinity;
	}

	// Returns true if this is a Koblitz curve (ABC curve).
	isKoblitz()
	{
	//
	//	return (this.n != null) && (this.h != null) &&
	//		(this.a.toBigInt().equals(0n) || this.a.toBigInt().equals(1n)) &&
	//		this.b.toBigInt().equals(1n);
	//
		return (this.a.toBigInt().equals(0n) || this.a.toBigInt().equals(1n)) &&
			this.b.toBigInt().equals(1n);
	}

	//* Decompresses a compressed point P = (xp, yp) (X9.62 s 4.2.2).
	decompressPoint(s, yBit) // byte[], int
	{
		var x = this.fromBigInt(BigInt.fromBufferUnsigned(s));
		var y = null;
		var one = this.fromBigInt(1n);

		if (x.isZero()) {
			// when x is zero then
			// y^2 = b

	//		y = this.b;
	//		for (var i = 0; i < this.m - 1; i++) {
	//			y = y.square();
	//		}
			y = this.b.sqrt();
		} else {
			//var beta = x.add(this.a).add(this.b.multiply(x.square().invert()));
			var beta = x.square().invert().multiply(this.b).add(this.a).add(x);
			var z = this.solveQuadraticEquation(beta);

			if (z == null) {
				throw jCastle.exception("INVALID_COMPRESSION", 'EC019'); // new Error("Invalid point compression");
			}

			var zBit = z.toBigInt().testBit(0) ? 1 : 0;

			if (zBit != yBit) {
				z = z.add(one);
			}

			y = x.multiply(z);
		}
				
		return new jCastle.math.ec.point.f2m(this, x, y);
	}
			
	// Solves a quadratic equation z^2 + z = beta (X9.62 D.1.6) The other solution is z + 1.
	solveQuadraticEquation(beta)
	{
		var zeroElement = this.fromBigInt(0n);

		if (beta.isZero()) {
			return zero;
		}

		var z = null;
		var gamma = null;
		var rng = new jCastle.prng();

		do {
			var t = this.fromBigInt(BigInt.random(this.m, rng));
			z = zeroElement;
			var w = beta;
			for (var i = 1; i < this.m; i++) {
				var w2 = w.square();
				z = z.square().add(w2.multiply(t));
				w = w2.add(beta);
			}
			if (!w.isZero()) {
				return null;
			}
			gamma = z.square().add(z);
		} 
		while (gamma.isZero());

		return z;
	}
			
	equals(other)
	{
		if (other == this) {
			return true;
		}

		if (!(other instanceof jCastle.math.ec.curve.f2m)) {
			return false;
		}

		return (this.m == other.m) && (this.k1 == other.k1)
			&& (this.k2 == other.k2) && (this.k3 == other.k3)
			&& this.a.equals(other.a) && this.b.equals(other.b);
	}

/*
	// Returns the parameter mu of the elliptic curve.
	// Error if the given ECCurve is not a Koblitz curve.
	getMu()
	{
		if (this.mu == 0) {
			this.mu = jCastle.math.ec.curve.f2m.tnaf.getMu(this);
	    }
		return this.mu;
	}

	// return the auxiliary values s0 and s1 used for partial modular reduction for Koblitz curves.
	getSi()
	{
		if (this.si == null) {
			this.si = jCastle.math.ec.curve.f2m.tnaf.getSi(this);
		}
		return this.si;
	}
*/

};

jCastle.math.ec.curve.F2m = jCastle.math.ec.curve.f2m;

/*
jCastle.math.ec.curve.f2m.tnaf = {

	getMu: function(curve)
	{
		if (typeof curve == 'number') {
			return curve == 0 ? -1 : 1;
		}

		if (!curve.isKoblitz()) {
			throw new Error("No Koblitz curve (ABC), TNAF multiplication not possible");
		}

		if (curve.getA().isZero()) {
			return -1;
		}

		return 1;
	},

	// Calculates the Lucas Sequence elements U^(k-1) and U^k or V^k-1 and V^k.
	getLucas: function(mu, k, doV) // byte, int, boolean
	{
		if (!((mu == 1) || (mu == -1))) {
			throw new Error("mu must be 1 or -1");
		}

		var u0;
		var u1;
		var u2;

		if (doV) {
			u0 = 2n;
			u1 = BigInt(mu);
		} else {
			u0 = 0n;
			u1 = 1n;
		}

		for (var i = 1; i < k; i++) {
			// u2 = mu*u1 - 2*u0;
			var s = null;
			if (mu == 1) {
				s = u1;
			} else {
				// mu == -1
				s = u1.negate();
			}
				
			u2 = s.subtract(u0.shiftLeft(1));
			u0 = u1;
			u1 = u2;
		}

		var retVal = [u0, u1];

		return retVal;
	},



	// Computes the auxiliary values s0 and s1 used for partial modular reduction. 
	getSi: function(fieldSize, curve, cofactor)
	{
		if (typeof curve == 'undefined') {
			curve = fieldSize;

			if (!curve.isKoblitz()) {
				throw new Error("si is defined for Koblitz curves only");
			}

			var m = curve.getFieldSize();
			var a = Number(curve.getA().toBigInt());
			var mu = jCastle.math.ec.curve.f2m.tnaf.getMu(a);
			var shifts = jCastle.math.ec.curve.f2m.tnaf.getShiftsForCofactor(curve.getCofactor());
			var index = m + 3 - a;
			var ui = getLucas(mu, index, false);
			if (mu == 1) {
				ui[0] = ui[0].negate();
				ui[1] = ui[1].negate();
			}

			var dividend0 = 1n.add(ui[1]).shiftRight(shifts);
			var dividend1 = 1n.add(ui[0]).shiftRight(shifts).negate();

			return [dividend0, dividend1];

		} else {
			var mu = jCastle.math.ec.curve.f2m.tnaf.getMu(curveA);
			var shifts = jCastle.math.ec.curve.f2m.tnaf.getShiftsForCofactor(cofactor);
			var index = fieldSize + 3 - curveA;
			var ui = getLucas(mu, index, false);
			if (mu == 1) {
				ui[0] = ui[0].negate();
				ui[1] = ui[1].negate();
			}

			var dividend0 = 1n.add(ui[1]).shiftRight(shifts);
			var dividend1 = 1n.add(ui[0]).shiftRight(shifts).negate();

			return [dividend0, dividend1];
		}
	},

	getShiftsForCofactor: function(h)
	{
		if (h != null) {
			if (h.equals(2n)) {
				return 1;
			}
			if (h.equals(4n)) {
				return 2;
			}
		}

		throw new Error("h (Cofactor) must be 2 or 4");
	}
};

jCastle.math.ec.curve.f2m.Tnaf = jCastle.math.ec.curve.f2m.tnaf;
*/


/*
"Shamir's Trick", originally due to E. G. Straus
(Addition chains of vectors. American Mathematical Monthly,
71(7):806-808, Aug./Sept. 1964)

Input: The points P, Q, scalar k = (km?, ... , k1, k0)
and scalar l = (lm?, ... , l1, l0).
Output: R = k * P + l * Q.

1: Z <- P + Q
2: R <- O
3: for i from m-1 down to 0 do
4:        R <- R + R        {point doubling}
5:        if (ki = 1) and (li = 0) then R <- R + P end if
6:        if (ki = 0) and (li = 1) then R <- R + Q end if
7:        if (ki = 1) and (li = 1) then R <- R + Z end if
8: end for
9: return R
*/
jCastle.math.ec.implementShamirsTrick = function(P, k, Q, l)
{
	var m = Math.max(k.bitLength(), l.bitLength());
	var Z = P.add(Q);
	var R = P.getCurve().getInfinity();

	for (var i = m - 1; i >= 0; --i) {
		R = R.twice();

		if (k.testBit(i)) {
			if (l.testBit(i)) R = R.add(Z);
			else R = R.add(P);
		} else {
			if (l.testBit(i)) R = R.add(Q);
		}
	}
	
	return R;
};


module.exports = jCastle.math.ec;