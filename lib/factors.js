require('./bigint-extend');

var jCastle = require('./jCastle');


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
        // check if divided by 2
        if (n.mod(2n).compareTo(0n) == 0) return two;

        var divisor;
        var c = BigInt.random(n.bitLength()-1, this._rng);
        var x = BigInt.random(n.bitLength()-1, this._rng);
        var y = x;

        do {
            x = x.multiply(x).mod(n).add(c).mod(n);
            y = y.multiply(y).mod(n).add(c).mod(n);
            y = y.multiply(y).mod(n).add(c).mod(n);
            divisor = x.subtract(y).abs().gcd(n);
        } while (divisor.compareTo(1n) == 0);

        return divisor;
    }

    // not work!
    _brent(n)
    {
        // check if divided by 2
        if (n.mod(2n).compareTo(0n) == 0) return two;

        var x0 = 2n;
        var m = 25n;
        var cst = BigInt.proablePrime(n.bitLength()-1, this._rng, 10);
        var c = cst;
        var y = x0;
        var r = 1n;
        var x, y2, k, bound, q, divisor, prod, out;
        do {
            x = y;
            for (var i = 0n; i < r; i += 1n) {
                y2 = y.square().mod(n);
                y = y.add(c).mod(n);
            }
            k = zero;
            do {
                bound = BigInt.min(m, r.subtract(k));
                q = 1n;
                for (var i = -3n; i < bound; i += 1n) { //start at -3 to ensure we enter this loop at least 3 times
                    y2 = y.square().mod(n);
                    y = y.add(c).mod(n);
                    divisor = x.subtract(y).abs();
                    if (divisor.isZero()) {
                        c = c.add(cst);
                        k = m.negate();
                        y = x0;
                        r = 1n;
                        break;
                    }
                    prod = divisor.multiply(q);
                    q = prod.mod(n);
                    if (q.isZero()) {
                        return divisor.abs().gcd(n);
                    }
                }
                out = q.abs().gcd(n);
                if (out.compareTo(1n) !== 0) {
                    return out;
                }
                k = k.add(m);
            } while (k.lt(r));
            r = 2n.multiply(r);
        } while (true);
    }

    _getFactors(n)
    {
        var divisor;

        if (n.compareTo(1n) == 0) return;

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