const jCastle = require('../lib/index');
const QUnit = require('qunit');

QUnit.module('PRNG');
QUnit.test("generating random numbers test", function(assert) {
    // default algorithm - arc4.
    // same seed should give the same result.
    
    var seed = "jCastle.net Jacob Lee 2022.04.14 pure javascript crypto library!";

    var prng1 = new jCastle.prng(seed);
    var prng2 = jCastle.prng.create(seed);
    var prng3 = jCastle.prng.create(seed+'!'); // this one should not give the same result.

    var a, b, c;

    for (var i = 0; i < 100; i++) {
        a = prng1.nextBytes(16);
        b = prng2.nextBytes(16);
        c = prng3.nextBytes(16);

        assert.ok(a.equals(b), 'prng with the same seed test');
        assert.ok(!a.equals(c), 'prng with different seed test');
    }

});

QUnit.test("generating test 2", function(assert) {
    // no seed given, then seed will be generated internally.
    // sha-1 algorithm is used.
    var prng = new jCastle.prng(null, 'sha-1');
    var t;

    for (var i = 0; i < 10000; i++) {
        t = prng.nextBytes(64, true, true); // first boolean - no zero first byte, second boolean - allows no zero at all.
    }
    for (var i = 0; i < t.length; i++) {
        assert.ok(t[i] != 0x00, "prng no zero test");
    }
});