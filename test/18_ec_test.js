const jCastle = require('../lib/index');
const BigInteger = require('../lib/biginteger');
const QUnit = require('qunit');

QUnit.module('EC');
QUnit.test("Fp Test", function(assert) {


	// Fp Test

	var q = BigInteger.valueOf(29);
	var a = BigInteger.valueOf(4);
	var b = BigInteger.valueOf(20);
	var n = BigInteger.valueOf(38);
	var h = BigInteger.ONE;

	var curve = new jCastle.math.ec.curve.fp(q, a, b, n, h);
	var infinity = curve.getInfinity();
	var pointSource = [5, 22, 16, 27, 13, 6, 14, 6];
	//var p = new Array(pointSource.length /2);
	var p = [];

	for (var i = 0; i < pointSource.length / 2; i++) {
		p[i] = curve.createPoint(
			BigInteger.valueOf(pointSource[2 * i]),
			BigInteger.valueOf(pointSource[2 * i + 1])
		);
	}

	// add
	assert.ok(p[0].add(p[1]).equals(p[2]), "Add 1st Test");
	assert.ok(p[1].add(p[0]).equals(p[2]), "Add 2nd Test");

	for (var i = 0; i < p.length; i++) {
		assert.ok(p[i].equals(p[i].add(infinity)), "Add Infinity Test "+ (i + 1));
	}

	// twice
	assert.ok(p[3].equals(p[0].twice()), "Twice Test");
	assert.ok(p[3].equals(p[0].add(p[0])), "Twice check Test");

	// three times
	assert.ok(p[0].add(p[0]).add(p[0]).equals(p[0].twice().add(p[0])), "three times Test");

	// infinity test
	var adder = infinity;
	var multiplier = infinity;
	var iter = BigInteger.ONE;

	// old-double-add test
	var before = new Date();

	do {
		adder = adder.add(p[0]);
		multiplier = p[0].multiply(iter);
		
		assert.ok(adder.equals(multiplier), "Add & multiply Test " + iter.toString());

		iter = iter.add(BigInteger.ONE);
	} while (!(adder.equals(infinity)));

	var after = new Date();

	// console.log('old-double-add method time: ' + (after - before) + ' ms');

    var adder = infinity;
	var multiplier1 = infinity;
	var iter = BigInteger.ONE;

	// double-add
	var before = new Date();

	do {
		adder = adder.add(p[0]);
		multiplier1 = p[0].multiply(iter, 'double-add');
		
		assert.ok(adder.equals(multiplier1), "Add & multiply(double-add) Test " + iter.toString());

		iter = iter.add(BigInteger.ONE);
	} while (!(adder.equals(infinity)));

	var after = new Date();

	// console.log('double-add method time: ' + (after - before) + ' ms');

	var adder = infinity;
	var multiplier2 = infinity;
	var iter = BigInteger.ONE;
	
	// montgomery-ladder'
	var before = new Date();

	do {
		adder = adder.add(p[0]);
		multiplier2 = p[0].multiply(iter, 'montgomery-ladder');
		
		assert.ok(adder.equals(multiplier2), "Add & multiply(montgomery-ladder) Test " + iter.toString());

		iter = iter.add(BigInteger.ONE);
	} while (!(adder.equals(infinity)));

	var after = new Date();

	// console.log('montgomery-ladder method time: ' + (after - before) + ' ms');

	var adder = infinity;
	var multiplier3 = infinity;
	var iter = BigInteger.ONE;

	// z-signed-digit
	var before = new Date();

	do {
		adder = adder.add(p[0]);
		multiplier3 = p[0].multiply(iter, 'z-signed-digit');
		
		assert.ok(adder.equals(multiplier3), "Add & multiply(z-signed-digit) Test " + iter.toString());

		iter = iter.add(BigInteger.ONE);
	} while (!(adder.equals(infinity)));

	var after = new Date();

	// console.log('z-signed-digit method time: ' + (after - before) + ' ms');


	// subtract test
	var p4 = p[0].twice().twice();
	var q4 = p[0].add(p[0]).add(p[0]).add(p[0]);
	assert.ok(p4.equals(q4), "4 Times adding Test");
	var p1 = p4.subtract(p[0]).subtract(p[0]).subtract(p[0]);
	assert.ok(p1.equals(p[0]), "sutraction test");


	// isOnCurve test

	for (var i = 0; i < p.length; i++) {
		assert.ok(p[i].isOnCurve(), "isOnCurve test - "+(i+1));
	}

	// encode & decode test

	var encoded = p[0].encodePoint();
	assert.ok(curve.decodePoint(encoded).equals(p[0]), "Encode & Decode with no compression test");

	encoded = p[0].encodePoint(true);
	assert.ok(curve.decodePoint(encoded).equals(p[0]), "Encode & Decode with compression test");


//	var pptable = prettyPrint(cert_info);
//	document.getElementById('printarea').appendChild(pptable);

});


QUnit.test("ECC F2m Test", function(assert) {

	var m = 4;
	var k1 = 1;
	// a = z^3
	var a = new BigInteger("1000", 2);
	// b = z^3 + 1
	var b = new BigInteger("1001", 2);
	var n = BigInteger.valueOf(23);
	var h = BigInteger.ONE;

	var curve = new jCastle.math.ec.curve.f2m(m, k1, 0, 0, a, b, n ,h);

	var infinity = curve.getInfinity();
	var pointSource = ["0010", "1111", "1100", "1100", "0001", "0001", "1011", "0010"];
	var p = [];

	for (var i = 0; i < pointSource.length / 2; i++) {
		p[i] = curve.createPoint(
			new BigInteger(pointSource[2 * i], 2),
			new BigInteger(pointSource[2 * i + 1], 2)
		);
	}

	// add
	assert.ok(p[0].add(p[1]).equals(p[2]), "Add 1st Test");
	assert.ok(p[1].add(p[0]).equals(p[2]), "Add 2nd Test");

	for (var i = 0; i < p.length; i++) {
		assert.ok(p[i].equals(p[i].add(infinity)), "Add Infinity Test "+ (i + 1));
	}

	// twice
	assert.ok(p[3].equals(p[0].twice()), "Twice Test");
	assert.ok(p[3].equals(p[0].add(p[0])), "Twice check Test");

	// three times
	assert.ok(p[0].add(p[0]).add(p[0]).equals(p[0].twice().add(p[0])), "three times Test");

	// infinity test
	var adder = infinity;
	var multiplier = infinity;
	var iter = BigInteger.ONE;

	// old-double-add test
	var before = new Date();

	do {
		adder = adder.add(p[0]);
		multiplier = p[0].multiply(iter);
		
		assert.ok(adder.equals(multiplier), "Add & multiply Test " + iter.toString());

		iter = iter.add(BigInteger.ONE);
	} while (!(adder.equals(infinity)));

	var after = new Date();

	// console.log('old-double-add method time: ' + (after - before) + ' ms');

    var adder = infinity;
	var multiplier1 = infinity;
	var iter = BigInteger.ONE;

	// double-add
	var before = new Date();

	do {
		adder = adder.add(p[0]);
		multiplier1 = p[0].multiply(iter, 'double-add');
		
		assert.ok(adder.equals(multiplier1), "Add & multiply(double-add) Test " + iter.toString());

		iter = iter.add(BigInteger.ONE);
	} while (!(adder.equals(infinity)));

	var after = new Date();

	// console.log('double-add method time: ' + (after - before) + ' ms');

	var adder = infinity;
	var multiplier2 = infinity;
	var iter = BigInteger.ONE;
	
	// montgomery-ladder'
	var before = new Date();

	do {
		adder = adder.add(p[0]);
		multiplier2 = p[0].multiply(iter, 'montgomery-ladder');
		
		assert.ok(adder.equals(multiplier2), "Add & multiply(montgomery-ladder) Test " + iter.toString());

		iter = iter.add(BigInteger.ONE);
	} while (!(adder.equals(infinity)));

	var after = new Date();

	// console.log('montgomery-ladder method time: ' + (after - before) + ' ms');

	var adder = infinity;
	var multiplier3 = infinity;
	var iter = BigInteger.ONE;

	// z-signed-digit
	var before = new Date();

	do {
		adder = adder.add(p[0]);
		multiplier3 = p[0].multiply(iter, 'z-signed-digit');
		
		assert.ok(adder.equals(multiplier3), "Add & multiply(z-signed-digit) Test " + iter.toString());

		iter = iter.add(BigInteger.ONE);
	} while (!(adder.equals(infinity)));

	var after = new Date();

	// console.log('z-signed-digit method time: ' + (after - before) + ' ms');


	// subtract test
	var p4 = p[0].twice().twice();
	var q4 = p[0].add(p[0]).add(p[0]).add(p[0]);
	assert.ok(p4.equals(q4), "4 Times adding Test");
	var p1 = p4.subtract(p[0]).subtract(p[0]).subtract(p[0]);
	assert.ok(p1.equals(p[0]), "sutraction test");


	// isOnCurve test

	for (var i = 0; i < p.length; i++) {
		assert.ok(p[i].isOnCurve(), "isOnCurve test - "+(i+1));
	}

	// encode & decode test

	var encoded = p[0].encodePoint();
	var ep = curve.decodePoint(encoded);

	assert.ok(ep.equals(p[0]), "Encode & Decode with no compression test");

	encoded = p[0].encodePoint(true);
	ep = curve.decodePoint(encoded);

	assert.ok(ep.equals(p[0]), "Encode & Decode with compression test");
});

QUnit.test("ECC F2m Test 2", function(assert) {

	var curve_name = "sect113r1";

	var pki = new jCastle.pki('ECDSA');
	pki.setParameters(curve_name);

	var curve = pki.pkiObject.ecInfo.curve;
	//var curve = pki.getCurve();
	var G = pki.pkiObject.ecInfo.G;

	var x = curve.fromBigInteger(G.getX().toBigInteger());

	assert.ok(x.multiply(x).multiply(x).multiply(x).multiply(x).multiply(x).equals(x.pow(6)), "pow Test");

	// sqrt test

	// y^2 + x * y = x^3 + a * x + b
	// when x is zero, then y = b

	// in binary field, c.pow(2.pow(m)) = c
	// thus sqrt(c) = c.pow(2.pow(m-1))

	var x = curve.fromBigInteger(BigInteger.ZERO);

	var before = new Date();
	var y = curve.getB();
	for (var i = 0; i < curve.m - 1; i++) {
		y = y.square();
	}
	var after = new Date();

	// console.log("Computing sqrt with squaring m-1 times: "+(after - before) + " ms");
	// console.log(y.toBigInteger().toString(16));

	// another test
	var before = new Date();
	var y2 = curve.getB();
	y2 = y2.sqrt();
	var after = new Date();

	// console.log("Computing sqrt with given function: "+(after - before) + " ms");

	assert.ok(y.equals(y2), "ECC on F2m sqrt Test");
	// console.log(y2.toBigInteger().toString(16));

});