/**
 * Javascript jCastle Mcrypt Module - VMPC
 * 
 * @author Jacob Lee
 *
 * Copyright (C) 2015-2022 Jacob Lee.
 */

var jCastle = require('../jCastle');
require('../util');

jCastle.algorithm.vmpc = class
{
	/**
	 * creates the algorithm instance.
	 * 
	 * @param {string} algo_name algorithm name
	 * @constructor
	 */
    constructor(algo_name)
    {
        this.algoName = algo_name;
        this.masterKey = null;
        this.roundKey = null;
        this.useInitialVector = false;
        this.initialVector = null;
            
        this.s = 0;
        this.n = 0;
    }

	/**
	 * validate the key size.
	 * 
	 * @public
	 * @param {buffer} key 
	 * @returns true if the key size is valid.
	 */
	isValidKeySize(key)
	{
		if (jCastle._algorithmInfo[this.algoName].min_key_size == jCastle._algorithmInfo[this.algoName].max_key_size) {
			if (key.length != jCastle._algorithmInfo[this.algoName].key_size) {
				return false;
			}
		} else {
			if (key.length > jCastle._algorithmInfo[this.algoName].max_key_size) {
				return false;
			}
			if (key.length < jCastle._algorithmInfo[this.algoName].min_key_size) {
				return false;
			}
			if (typeof jCastle._algorithmInfo[this.algoName].key_sizes != 'undefined' &&
            !jCastle._algorithmInfo[this.algoName].key_sizes.includes(key.length)
			) {
				return false;			
			}
		}
		return true;
	}

	/**
	 * resets internal variables except algoName.
	 * 
	 *  @public
	 */
	reset()
	{
		this.masterKey = null;
		this.roundKey = null;
		this.useInitialVector = false;
		this.initialVector = null;
		this.n = 0;
		this.s = 0;
		return this;
	}

	/**
	 * get the key.
	 * 
	 * @public
	 * @returns the masterKey.
	 */
    getKey()
    {
        return this.masterKey;
    }

	/**
	 * get the block size.
	 * 
	 * @public
	 * @returns the block size.
	 */
	getBlockSize()
	{
		return jCastle._algorithmInfo[this.algoName].block_size;
	}

	/**
	 * sets the initial vector.
	 * 
	 * @public
	 * @param {buffer} IV initial vector.
	 * @returns this class instance.
	 */
	setInitialVector(IV)
	{
		var iv = Buffer.from(IV, 'latin1');

		this.initialVector = iv;
		this.useInitialVector = true;
		return this;
	}

	/**
	 * makes round key for encryption/decryption.
	 *
	 * @public
	 * @param {buffer} key encryption/decryption key.
	 * @param {boolean} isEncryption if encryption then true, otherwise false.
	 */
	keySchedule(key, isEncryption)
	{
		this.masterKey = Buffer.from(key, 'latin1');

		this.expandKey(this.masterKey);
		return this;
	}

	/**
	 * encrypts a block.
	 * 
	 * @public
	 * @param {buffer} input input data to be encrypted.
	 * @returns encrypted block in buffer.
	 */
	encryptBlock(input)
	{
		return this.cryptBlock(input);
	}

	/**
	 * decrypts a block.
	 * 
	 * @public
	 * @param {buffer} input input data to be decrypted.
	 * @returns the decrypted block in buffer.
	 */
	decryptBlock(input)
	{
		return this.cryptBlock(input);
	}

	/**
	 * crypt the input data. this is the stream cipher function.
	 * 
	 * @public
	 * @param {buffer} input input data to be crypted.
	 * @returns crypted data in buffer.
	 */
	crypt(input)
	{
		return this.cryptBlock(input);
	}

/*
 * -----------------
 * Private functions
 * -----------------
 */

/*
https://www.iacr.org/archive/fse2004/30170209/30170209.pdf

Variables:

c: fixed length of the cryptographic key in bytes, 16 <= c <= 64
K: c-element table storing the cryptographic key
z: fixed length of the Initialization Vector in bytes, 16 <= z <= 64
V: z-element table storing the Initialization Vector
m: 16-bit variable


		1. s = 0
		2. for n from 0 to 255: P[n] = n

		3. for m from 0 to 767: execute steps 4-6:
			4. n = m modulo 256
			5. s = P[(s + P[n] + K[m modulo c]) modulo 256 ]
			6. Temp = P[n]
			   P[n] = P[s]
			   P[s] = Temp

		7. If Initialization Vector is used: execute step 8:

		8. for m from 0 to 767: execute steps 9-11:
			9. n = m modulo 256
			10. s = P[(s + P[n] + V[m modulo z]) modulo 256 ]
			11. Temp = P[n]
				P[n] = P[s]
				P[s] = Temp
*/
	/**
	 * Calculate the necessary round keys.
	 * The number of calculations depends on key size and block size.
	 * 
	 * @private
	 * @param {buffer} key key for encryption/decryption.
	 * @param {boolean} isEncryption true if it is encryption, otherwise false.
	 */
	expandKey(key, isEncryption)
	{
		// check iv
		if (this.useInitialVector && (this.initialVector.length < 16 || this.initialVector.length > 64)) {
			throw jCastle.exception("INVALID_IV");
		}

		var n;

		this.roundKey = new Uint8Array(256);
		this.s = 0;

		for (var i = 0; i < 256; i++) {
			this.roundKey[i] = i;
		}

		for (var m = 0; m < 768; m++) {
			n = m & 0xff;
			this.s = this.roundKey[(this.s + this.roundKey[n] + key[m % key.length]) & 0xff];
			this.swap(n, this.s);
		}

		if (this.useInitialVector) {
			for (var m = 0; m < 768; m++) {
				n = m & 0xff;
				this.s = this.roundKey[(this.s + this.roundKey[n] + this.initialVector[m % this.initialVector.length]) & 0xff];
				this.swap(n, this.s);
			}
		}

		if (this.algoName == 'vmpc-ksa3') {
			for (var m = 0; m < 768; m++) {
				n = m & 0xff;
				this.s = this.roundKey[(this.s + this.roundKey[n] + key[m % key.length]) & 0xff];
				this.swap(n, this.s);
			}
		}
	}

	swap(x, y)
	{
		var t;
		t = this.roundKey[x]; this.roundKey[x] = this.roundKey[y]; this.roundKey[y] = t;
	}


	/*
	Variables:

	P: 256-byte table storing a permutation initialized by the VMPC KSA
	s: 8-bit variable initialized by the VMPC KSA
	n: 8-bit variable
	L: desired length of the keystream in bytes


			1. n = 0

			2. Repeat steps 3-6 L times:
				3. s = P[s + P[n] modulo 256]
				4. Output P[(P[P[s]] + 1) modulo 256]
				5.  Temp = P[s]
					P[n] = P[s]
					P[s] = Temp
				6. n = (n + 1) modulo 256

	*/
	/**
	 * crypt the block sized data.
	 * 
	 * @public
	 * @param {buffer} input input data to be crypted.
	 * @returns the crypted data in buffer.
	 */
	cryptBlock(input)
	{
		var output = Buffer.alloc(input.length);
		
		for (var c = 0; c < input.length; c++) {
			this.s = this.roundKey[(this.s + this.roundKey[this.n]) & 0xff];
			var z = (input[c] ^ this.roundKey[(this.roundKey[this.roundKey[this.s]] + 1) & 0xff]) & 0xff;
			this.swap(this.s, this.n);
			this.n = (this.n + 1) & 0xff;

			//output.push(z);
			output[c] = z;
		}
			
		return output;

	}
};


jCastle._algorithmInfo['vmpc'] = {
	algorithm_type: 'crypt',
	block_size: 1, // stream cipher
	key_size: 32,
	min_key_size: 16,
	max_key_size: 64,
	padding: 'zeros',
	stream_block_size: 64,
	object_name: 'vmpc'
};

jCastle._algorithmInfo['vmpc-ksa3'] = {
	algorithm_type: 'crypt',
	block_size: 1,
	key_size: 32,
	min_key_size: 16,
	max_key_size: 64,
	padding: 'zeros',
	stream_block_size: 64,
	object_name: 'vmpc'
};

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

module.exports = jCastle.algorithm.vmpc;