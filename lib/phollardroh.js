

(function() {

	const PollardRho = class 
	{
		constructor(rng, method = 'rho') {
			this._method = method || 'rho';
			this._factors = [];
			this._rng = rng;
		}

		setRandomGenerator(rng) {
			this._rng = rng;
		}

		_rho(n) {
			// check if divided by 2
			if (n % 2n == 0n) return 2n;

			var divisor;
			var c = (BigInt.random(n.bitLength(), this._rng)) % n;
			var x = (BigInt.random(n.bitLength(), this._rng)) % n;
			var y = x;
			var save, save_f = true;

			do {
				if (save_f) {
					save = x;
					save_f = false;
				}

				x = (((x ** 2n) % n) + c) % n;
				y = (((y ** 2n) % n) + c) % n;
				y = (((y ** 2n) % n) + c) % n;
				divisor = (x - y).gcd(n);

				if (divisor == 1n && x == save) {
					// f(x) function cycle repeats
//console.log('f(x) function cycle repeats');
					c = (BigInt.random(n.bitLength(), this._rng)) % n;
					save_f = true;
				}
			} while (divisor == 1n);

			return divisor;
		}

		_brent(n) {
			var k = 1n;
			var r = 1n;
			var i = 1n;
			var m = 10n;
			var iter = 0n;
			var z = 0n;
			var x = 1n;
			var y = 0n;
			var q = 1n;
			var ys = 1n;

			do {
				x = y;
				for (i = 1n; i <= r; i += 1n) y = (y ** 2n + 3n) % n;
				k = 0n;
				do {
					iter += 1n;
					ys = y;
					for (i = 1n; i <= m.min(r-k); i += 1n) {
						y = (y ** 2n + 3n) % n;
						q = ((y - x) * q) % n;
					}
					z = n.gcd(q);
					k += m;
				} while (k < r && z == 1n);

				r = r * 2n;
			} while (z == 1n && iter < 1000n);

			if (z == n) {
				do {
					ys = (y ** 2n + 3n) % n;
					z = n.gcd(ys - x);
				} while (z == 1n);
			}

			return z;
		}

		_getFactors(n) {
			var divisor;

			if (n == 1n) return [];

			if (n.isProbablePrime(20) && n.isLucasLehmerPrime()) {
				this._factors.push(n);
				return this._factors;
			}

//			divisor = this._method.toLowerCase == 'brent' ? this._brent(n) : this._rho(n);
			divisor = this._rho(n);

			this._getFactors(divisor);
			this._getFactors(n / divisor);
		}

		factor(n) {
			if (!this._rng) 
				throw new Error("Pollard Rho Factorization requires a random number generator(RNG)");

			this._getFactors(n);

			// sort
			this._factors.sort(function(a, b) {
				var result = a.compareTo(b);
				if (a > b) return 1;
				if (a < b) return -1;
				return 0;
			});
			return this._factors;
		}

	};

	module.exports = PollardRho;

})();