const jCastle = require('../lib/index');
const QUnit = require('qunit');

QUnit.module('EC Curve');
QUnit.test("ECC named curve - isOnCurve Test", function(assert) {

	var curve_name = "secp256k1";

	var ecdsa = new jCastle.pki.ecdsa();
	ecdsa.setParameters(curve_name);

	var curve = ecdsa.ecInfo.curve;
	var infinity = curve.getInfinity();
	var n = ecdsa.ecInfo.n;
	var G = ecdsa.ecInfo.G;

	assert.ok(G.isOnCurve(), "G point should be on curve");
	assert.ok(G.multiply(1000n).isOnCurve(), "multiplied G also should be on curve");

});

// var data = [];
// var trace = {
// 	x: [],
// 	y: [],
// 	mode: 'lines+markers',
// 	type: 'scatter'
// };

QUnit.test("ECC custom curve Test", function(assert) {

	/* custom curve */

	var q = 29n;
	var a = 4n;
	var b = 20n;
	var n = 37n;
	var h = 1n;

	var curve = new jCastle.math.ec.curve.fp(q, a, b, n, h);
	var infinity = curve.getInfinity();
	var G = curve.createPoint(
		5n,
		22n
	);

	var p = G;
	var i = 1;

	while (!p.isInfinity()) {
		assert.ok(p.isOnCurve(), i + " - point should be on curve");

		var x = p.getX().toBigInt().toString();
		var y = p.getY().toBigInt().toString();
		// console.log(i + " ==> (" + x + ", " + y + ")");

		// put x and y into trace for plotly
		// trace.x.push(parseInt(x));
		// trace.y.push(parseInt(y));

		p = p.add(G);
		i++;
	}

	p = p.add(G);

	var x = p.getX().toBigInt().toString();
	var y = p.getY().toBigInt().toString();
//	console.log(38 + " ==> (" + x + ", " + y + ")");

/*
y^2 = x^3 + 4*x + 20 mod 29
---------------------------
1 ==> (5, 22)
2 ==> (14, 6)
3 ==> (6, 12)
4 ==> (2, 6)
5 ==> (15, 2)
6 ==> (13, 23)
7 ==> (16, 2)
8 ==> (1, 5)
9 ==> (3, 1)
10 ==> (8, 19)
11 ==> (17, 19)
12 ==> (27, 27)
13 ==> (20, 26)
14 ==> (10, 25)
15 ==> (19, 16)
16 ==> (4, 19)
17 ==> (0, 22)
18 ==> (24, 7)
19 ==> (24, 22)
20 ==> (0, 7)
21 ==> (4, 10)
22 ==> (19, 13)
23 ==> (10, 4)
24 ==> (20, 3)
25 ==> (27, 2)
26 ==> (17, 10)
27 ==> (8, 10)
28 ==> (3, 28)
29 ==> (1, 24)
30 ==> (16, 27)
31 ==> (13, 6)
32 ==> (15, 27)
33 ==> (2, 23)
34 ==> (6, 17)
35 ==> (14, 23)
36 ==> (5, 7)
*/
});


QUnit.test("ECC custom curve Test2", function(assert) {

	/* custom curve */

	var q = 17n;
	var a = 2n;
	var b = 2n;
	var n = 19n;
	var h = 1n;

	var curve = new jCastle.math.ec.curve.fp(q, a, b, n, h);
	var infinity = curve.getInfinity();
	var G = curve.createPoint(
		5n,
		1n
	);

	var p = G;
	var i = 1;

	while (!p.isInfinity()) {
		assert.ok(p.isOnCurve(), i + " - point should be on curve");

		var x = p.getX().toBigInt().toString();
		var y = p.getY().toBigInt().toString();
		// console.log(i + " ==> (" + x + ", " + y + ")");

		p = p.add(G);
		i++;
	}
/*
y^2 = x^3 + 2*x + 2 mod 17
--------------------------
1 ==> (5, 1)
2 ==> (6, 3)
3 ==> (10, 6)
4 ==> (3, 1)
5 ==> (9, 16)
6 ==> (16, 13)
7 ==> (0, 6)
8 ==> (13, 7)
9 ==> (7, 6)
10 ==> (7, 11)
11 ==> (13, 10)
12 ==> (0, 11)
13 ==> (16, 4)
14 ==> (9, 1)
15 ==> (3, 16)
16 ==> (10, 11)
17 ==> (6, 14)
18 ==> (5, 16)
*/
});


// data.push(trace);

// var layout = {
// 	title:'Line and Scatter Plot',
// 	height: 800,
// 	width: 800
// };

// setTimeout(function() {
// 	Plotly.newPlot('plotly_div', data, layout);
// }, 2000);



/*

example:

E: y^2 = x^3 + 2*x + 2 mod 17
G: (5, 1)

then

2G = G + G = (5, 1) + (5, 1) = (x3, y3)


gamma = (3*x1^2 + a)/2*y1 = (x1.square().multiply(3n).add(a).divide(y1.multiply(2n));

*/