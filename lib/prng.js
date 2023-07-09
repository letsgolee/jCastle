/**
 * A Javascript implemenation of PRNG(Psudo Random Number Generator) 
 * or SecureRandom
 * 
 * @author Jacob Lee
 * 
 * Copyright (C) 2015-2022 Jacob Lee.
 */

/* Some functions got from https://github.com/skeeto/rng-js */

var jCastle = require('./jCastle');
require('./util');
require('./digest');
require('./hashes/md2');
require('./hashes/md4');
require('./hashes/md5');
require('./hashes/crc32');
require('./hashes/sha1');
require('./hashes/sha2');
require('./hashes/sha3');
require('./hashes/has-160');
require('./hashes/ripemd');
require('./hashes/haval');
require('./hashes/skein');
require('./hashes/gost3411');
require('./hashes/tiger');
require('./hashes/whirlpool');

jCastle.prng = class
{
    /**
     * Create a new random number generator with optional seed. If the
     * provided seed is a function (i.e. Math.random) it will be used as
     * the uniform number generator.
     * 
     * @param {mixed} seed data used to seed the generator.
     * @param {string} hashAlgo hash algorithm name.
     * @constructor
     */
    constructor(seed, hashAlgo)
    {
        var seed_data;
        
        this._algorithm = null;
    
        if (!seed) {
            seed_data = (Math.floor(Math.random() * Math.pow(2, 42) + 1) + Date.now()).toString();
            if ('undefined' !== typeof window && window.navigator && window.navigator.userAgent) 
                seed_data += window.navigator.userAgent;
            //else if ('undefined' !== typeof os && os.cpus && os.networkInterfaces) { // node.js
            else if ('undefined' !== typeof os && os.cpus) {
                seed_data += os.hostname();
                seed_data += JSON.stringify(os.cpus());
                //seed_data += JSON.stringify(os.networkInterfaces());
            }
        } else if (typeof seed === "function") {
            // Use it as a uniform number generator
    		// this.uniform = seed;
    		// this.nextByte = function() {
    		// 	return ~~(this.uniform() * 256);
    		// };
            this.nextByte = seed;
            seed_data = null;
        } else {
            seed_data = seed;
        }
        //console.log(seed_data);
    
        this._normal = null;
        
        if (seed_data) this.init(seed_data, hashAlgo);
    }
 
    /**
     * initialize prng generator.
     * 
     * @public
     * @param {mixed} seed seed data used to seed the generator.
     * @param {string} hashAlgo hash algorithm name.
     * @returns this class instance.
     */
    init(seed, hashAlgo)
    {
        var algorithm;
        if (seed) seed = Buffer.from(seed, 'latin1');
        if (!hashAlgo) hashAlgo = 'arc4';
		if (hashAlgo == 'default') hashAlgo = 'arc4';
        hashAlgo = hashAlgo.toLowerCase();
         
        if (hashAlgo !== 'vmpc' && hashAlgo !== 'arc4') {
            hashAlgo = jCastle.digest.getValidAlgoName(hashAlgo);
 
            if (!(hashAlgo in jCastle._algorithmInfo))
                throw new Error('The hash algorithm(' + hashAlgo + ') is not loaded');
        }

        switch (hashAlgo) {
            case 'arc4':
                algorithm = new jCastle.prng.algorithm.arc4();
                break;
            case 'vmpc':
                algorithm = new jCastle.prng.algorithm.vmpc();
                break;
            default:
                algorithm = new jCastle.prng.algorithm.digest(hashAlgo);
                break;
        }
 
        this._algorithm = algorithm;
        this._algorithm.init(seed);

        return this;
    }
 
    /**
     * get a byte number.
     * 
     * @public
     * @param {boolean} nozero if true 0x00 is not allowed.
     * @returns random number between 0 and 255.
     */
    nextByte(nozero = false)
    {
        //nozero = !!nozero;
        var c = this._algorithm.next();
        if (!nozero) return c;
        while (c == 0x00) c = this._algorithm.next();
        return c;
    }
 
    /**
     * get bytes.
     * 
     * @public     * 
     * @param {number} size the amount number of bytes array.
     * @param {boolean} nozero_first if true 0x00 is not allowed at first position.
     * @param {boolean} nozero if true 0x00 is not allowed at all.
     * @returns the buffer allocated by random bytes.
     */
    nextBytes(size, nozero_first = false, nozero = false)
    {
        //nozero_first = !!nozero_first;
        if ('nextBytes' in this._algorithm && typeof this._algorithm.nextBytes == 'function')
            return this._algorithm.nextBytes(size, nozero_first, nozero);
 
        var c, pos = 0, out = Buffer.alloc(size);
 
        while (pos < size) {
            c = this.nextByte();
            if (nozero && c === 0x00) continue;
            out[pos++] = c;
        }
 
        if (nozero_first && out[0] === 0x00) {
            do {
                c = this.nextByte();
                out[0] = c;
            } while (c === 0x00);
        }
 
        return out;
    }

    /**
     * alias function of nextBytes().
     * 
     * @public
     * @param {number} size the amount number of bytes array.
     * @param {boolean} nozero_first if true 0x00 is not allowed at first position.
     * @param {boolean} nozero if true 0x00 is not allowed at all.
     * @returns the buffer allocated by random bytes.
     */
    randomBytes(size, nozero_first = false, nozero = false)
    {
        return this.nextBytes(size, nozero_first, nozero);
    }
 
    /**
     * @returns a random number between 0 and 1.
     */
    uniform()
    {
        var BYTES = 7; // 56 bits to make a 53-bit double
        var output = 0;
        for (var i = 0; i < BYTES; i++) {
            output *= 256;
            output += this.nextByte();
        }
        return output / (Math.pow(2, BYTES * 8) - 1);
    }
 
    /**
     * produce a random integer within [n, m].
     * 
     * @param {number} [n=0]
     * @param {number} m
     *
     */
    random(n, m)
    {
        if (n == null) {
            return this.uniform();
        } else if (m == null) {
            m = n;
            n = 0;
        }
        return n + Math.floor(this.uniform() * (m - n));
    }
 
    /**
     * Generates numbers using this.uniform() with the Box-Muller transform.
     * 
     * @returns {number} Normally-distributed random number of mean 0, variance 1.
     */
    normal()
    {
        if (this._normal !== null) {
            var n = this._normal;
            this._normal = null;
            return n;
        } else {
            var x = this.uniform() || Math.pow(2, -53); // can't be exactly 0
            var y = this.uniform();
            this._normal = Math.sqrt(-2 * Math.log(x)) * Math.sin(2 * Math.PI * y);
            return Math.sqrt(-2 * Math.log(x)) * Math.cos(2 * Math.PI * y);
        }
    }
 
    /**
     * Generates numbers using this.uniform().
     * 
     * @returns {number} Number from the exponential distribution, lambda = 1.
     */
    exponential()
    {
        return -Math.log(this.uniform() || Math.pow(2, -53));
    }
 
    /**
     * Generates numbers using this.uniform() and Knuth's method.
     * 
     * @param {number} [mean=1]
     * @returns {number} Number from the Poisson distribution.
     */
    poisson(mean)
    {
        var L = Math.exp(-(mean || 1));
        var k = 0, p = 1;
        do {
            k++;
            p *= this.uniform();
        } while (p > L);
        return k - 1;
    }
 
    /**
     * Generates numbers using this.uniform(), this.normal(),
     * this.exponential(), and the Marsaglia-Tsang method.
     * 
     * @param {number} a
     * @returns {number} Number from the gamma distribution.
     */
    gamma(a)
    {
        var d = (a < 1 ? 1 + a : a) - 1 / 3;
        var c = 1 / Math.sqrt(9 * d);
        do {
            do {
                var x = this.normal();
                var v = Math.pow(c * x + 1, 3);
            } while (v <= 0);
            var u = this.uniform();
            var x2 = Math.pow(x, 2);
        } while (u >= 1 - 0.0331 * x2 * x2 &&
            Math.log(u) >= 0.5 * x2 + d * (1 - v + Math.log(v)));
        if (a < 1) {
            return d * v * Math.exp(this.exponential() / -a);
        } else {
            return d * v;
        }
    }
};
 
jCastle.prng.algorithm = {};

jCastle.prng.algorithm.arc4 = class {

    init(seed)
    {
        this.state = new Uint8Array(256);
        this.i = 0;
        this.j = 0;
        for (var i = 0; i < 256; i++) {
            this.state[i] = i;
        }
        if (seed) {
            this.mix(seed);
        }
    }

    mix(seed) 
    {
        for (var i = 0, j = 0; i < this.state.length; i++) {
            j += this.state[i] + seed[i % seed.length];
            j &= 0xFF;
            this.swap(i, j);
        }
    }

    swap(i, j)
    {
        var tmp = this.state[i];
        this.state[i] = this.state[j];
        this.state[j] = tmp;
    }

    next()
    {
        this.i = (this.i + 1) & 0xFF;
        this.j = (this.j + this.state[this.i]) & 0xFF;
        this.swap(this.i, this.j);
        return this.state[(this.state[this.i] + this.state[this.j]) & 0xFF];
    }
};

jCastle.prng.algorithm.vmpc = class {
// vmpc
// this implication is not vmpc-r. its alogrithm is similar with vmpc cipher function.
// 
    init(seed)
    {
        var n, i, j = 2;

        this.state = new Uint8Array(256);
        this.s = 0;
        this.n = 0;

        for (i = 0; i < 256; i++)
            this.state[i] = i;
        
        while (j--)
            for (i = 0;i < 768; i++) {
                n = i & 0xFF;
                this.s = this.state[(this.s + this.state[n] + seed[i % seed.length]) & 0xFF];
                this.swap(n, this.s);
            }
    }

    swap(x, y)
    {
        var z;
        z = this.state[x];
        this.state[x] = this.state[y];
        this.state[y] = z;
    }

    next()
    {
        var c;

        this.s = this.state[(this.s + this.state[this.n]) & 0xFF];
        c = this.state[(this.state[this.state[this.s]] + 1) & 0xFF];
        this.swap(this.s, this.n);
        this.n = (this.n + 1) & 0xFF;

        return c;
    }
};

jCastle.prng.algorithm.digest = class {

    constructor(hashAlgo)
    {
        this.md = new jCastle.digest(hashAlgo);
        this.pos = 0;
        this.count = 0;
        this.seed = null;
    }

    init(seed) 
    {
        this.pos = 0;
        this.count = 0;
        this.seed = seed;

        this.update();
    }

    update() 
    {
        var cb = Buffer.alloc(4);
		cb.writeInt32BE(this.count, 0);

        this.md.start();
        this.md.update(this.seed);
        this.md.update(cb);
        this.state = this.md.finalize();
        this.count++;
    }

    next() 
    {
        if (this.pos >= this.state.length) {
            this.pos = 0;
            this.update();
        }
        return this.state[this.pos++];
    }
};
 
jCastle.prng.create = function(seed, hashAlgo)
{
    return new jCastle.prng(seed, hashAlgo);
};
 
jCastle.prng.randomBytes = function(size, seed, hashAlgo)
{
    return new jCastle.prng(seed, hashAlgo).nextBytes(size);
};
 
jCastle.secureRandom = function(seed, hashAlgo)
{
    hashAlgo = hashAlgo || 'sha-1';
    return new jCastle.prng(seed, hashAlgo);
};
 
jCastle.secureRandom.create = function(seed, hashAlgo)
{
    return new jCastle.secureRandom(seed, hashAlgo);
};

jCastle.PRNG = jCastle.prng;
 
module.exports = jCastle.prng; 


/*
 VMPC-R
 ======
 Psdo-random number generator using VMPC
 ---------------------------------------
 
 http://www.vmpcfunction.com/vmpcr.htm
 
 2. VMPC-R algorithm: 
 
      N	 :  word size; in most practical applications N=256
      P, S	 :  N-element tables storing permutations of integers {0,1,...,N-1}
      a, b, c, d, e, f, n	 :  integer variables
      L	 :  number of pseudorandom integers to generate
      +	    denotes addition modulo N
 
 
 Table 1. VMPC-R CSPRNG pseudo code
 repeat steps 1-10 L times:
 
    1. a = P[a + c + S[n]]
    2. b = P[b + a]
    3. c = P[c + b] 
 
    4. d = S[d + f + P[n]]
    5. e = S[e + d]
    6. f = S[f + e] 
 
    7. output S[S[S[c + d]] + 1] 
 
    8. swap P[n] with P[f]
    9. swap S[n] with S[a] 
 
   10. n = n + 1
 
 
 3. VMPC-R Key Scheduling Algorithm
 
 The VMPC-R Key Scheduling Algorithm transforms the seed (which could be a 
 cryptographic key and an Initialization Vector) into the algorithm's internal 
 state. 
 
 Notation: as in section 2, with: 
 
      a, b, c, d, e, f, n	 
      k	 :  length of the seed or cryptographic key; k ∈ {1,2,...,N}
      K	 :  k-element table storing the seed or cryptographic key
      v	 :  length of the Initialization Vector; v ∈ {1,2,...,N}
      V	 :  v-element table storing the Initialization Vector
      i	 :  temporary integer variable
       R	 =  N * Ceiling(k2/(6N))
      +	    denotes addition modulo N
 
 Table 2. VMPC-R Key Scheduling Algorithm pseudo code
 0. a = b = c = d = e = f = n = 0
    P[i] = S[i] = i for i ∈ {0,1,...,N-1}
 
 1. KSARound(K, k)
 2. KSARound(V, v)
 3. KSARound(K, k)
 4. n = S[S[S[c + d]] + 1]
 5. generate N outputs with VMPC-R CSPRNG (for L=N)
 
 
 Function KSARound(M, m) definition:
   6. i = 0
   7. repeat steps 8-18 R times:
        8. a = P[a + f + M[i]] + i;   i = (i + 1) mod m
        9. b = S[b + a + M[i]] + i;   i = (i + 1) mod m
       10. c = P[c + b + M[i]] + i;   i = (i + 1) mod m
       11. d = S[d + c + M[i]] + i;   i = (i + 1) mod m
       12. e = P[e + d + M[i]] + i;   i = (i + 1) mod m
       13. f = S[f + e + M[i]] + i;   i = (i + 1) mod m
 
       14. swap P[n] with P[b]
       15. swap S[n] with S[e]
       16. swap P[d] with P[f]
       17. swap S[a] with S[c]
 
       18. n = n + 1
 
 
 The KSARound function performs R = N * Ceiling(k2/(6N)) iterations. This value 
 ensures that each word of a k-word key updates the internal state at least k
 times. For N = 256 and key sizes k ∈ {2,3,...,39} (keys up to 312 bits) R = N.
 For N = 256 and key sizes k ∈ {40,41,...,55} (keys from 320 to 440 bits) R = 2N.
 And so on.
 */		