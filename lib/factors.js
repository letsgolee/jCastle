var jCastle = require('./jCastle');
var BigInteger = require('./biginteger');

var PollardRho = class
{
    constructor(rng, method)
    {
        this._factors = [];
        this._rng = null;
        this._method = 'rho';

        if (rng) this._rng = rng;
        else this._rng = new jCastle.prng();

        if (method && method.length && method.toLowerCase() == 'brent') this._method = 'brent';
    }

    reset()
    {
        this._factors = [];
        this._method = 'rho';
        return this;
    }

    rho()
    {
        this._method = 'rho';
        return this;
    }

    brent()
    {
        this._method = 'brent';
        return this;
    }

    _rho(n)
    {
        var zero = BigInteger.valueOf(0);
        var one = BigInteger.valueOf(1);
        var two = BigInteger.valueOf(2);

        // check if divided by 2
        if (n.mod(two).compareTo(zero) == 0) return two;

        var divisor;
        var c = BigInteger.random(n.bitLength()-1, this._rng);
        var x = BigInteger.random(n.bitLength()-1, this._rng);
        var y = x;

        do {
            x = x.multiply(x).mod(n).add(c).mod(n);
            y = y.multiply(y).mod(n).add(c).mod(n);
            y = y.multiply(y).mod(n).add(c).mod(n);
            divisor = x.subtract(y).abs().gcd(n);
        } while (divisor.compareTo(one) == 0);

        return divisor;
    }

    // not work!
    _brent(n)
    {
        var zero = BigInteger.valueOf(0);
        var one = BigInteger.valueOf(1);
        var two = BigInteger.valueOf(2);

        // check if divided by 2
        if (n.mod(two).compareTo(zero) == 0) return two;

        var x0 = BigInteger.valueOf(2);
        var m = BigInteger.valueOf(25);
        var cst = BigInteger.proablePrime(n.bitLength()-1, this._rng, 10);
        var c = cst;
        var y = x0;
        var r = BigInteger.valueOf(1);
        var x, y2, k, bound, q, divisor, prod, out;
        do {
            x = y;
            for (var i = zero; i.lt(r); i = i.add(one)) {
                y2 = y.square().mod(n);
                y = y.add(c).mod(n);
            }
            k = zero;
            do {
                bound = BigInteger.min(m, r.subtract(k));
                q = one;
                for (var i = BigInteger.valueOf(-3); i.lt(bound); i = i.add(one)) { //start at -3 to ensure we enter this loop at least 3 times
                    y2 = y.square().mod(n);
                    y = y.add(c).mod(n);
                    divisor = x.subtract(y).abs();
                    if (divisor.isZero()) {
                        c = c.add(cst);
                        k = m.negate();
                        y = x0;
                        r = one;
                        break;
                    }
                    prod = divisor.multiply(q);
                    q = prod.mod(n);
                    if (q.isZero()) {
                        return divisor.abs().gcd(n);
                    }
                }
                out = q.abs().gcd(n);
                if (out.compareTo(one) !== 0) {
                    return out;
                }
                k = k.add(m);
            } while (k.lt(r));
            r = two.multiply(r);
        } while (true);
    }

    _getFactors(n)
    {
        var divisor;

        if (n.compareTo(BigInteger.ONE) == 0) return;

        if (n.isProbablePrime(10)) {
            this._factors.push(n);
            return;
        }

        divisor = this._method == 'rho' ? this._rho(n) : this._brent(n);

        this._getFactors(divisor);
        this._getFactors(n.divide(divisor));
    }

    factor(n)
    {
        this._getFactors(n);

        // sort
        this._factors.sort(function(a, b) {
            var result = a.compareTo(b);
            if (result > 0) return 1;
            if (result < 0) return -1;
            return 0;
        });

        return this._factors;
    }
}

PollardRho.factor = function(n, rng, method)
{
    return new PollardRho(rng, method).factor(n);
};


module.exports = {
    pollardRho: PollardRho
};