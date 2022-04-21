/**
 * Javascript jCastle Mcrypt Module - VMPC-R
 * 
 * @author Jacob Lee
 *
 * Copyright (C) 2015-2021 Jacob Lee.
 */

var jCastle = require('../jCastle');
require('../util');

jCastle.algorithm.vmpcr = class
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
        
        this.a = 0;
        this.b = 0;
        this.c = 0;
        this.d = 0;
        this.e = 0;
        this.f = 0;
        this.n = 0;
        
        this.P = null;
        this.S = null;
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
		
		this.a = 0;
		this.b = 0;
		this.c = 0;
		this.d = 0;
		this.e = 0;
		this.f = 0;
		this.n = 0;
		
		this.P = null;
		this.S = null;
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
	
	prngGetBytes(len) 
	{
		var t;
		var output = Buffer.alloc(len);
		
		for (var x = 0; x < len; x++)  {
			this.a = this.P[ (this.a + this.c + this.S[this.n]) & 255 ];
			this.b = this.P[ (this.b + this.a) & 255 ];
			this.c = this.P[ (this.c + this.b) & 255 ];
			this.d = this.S[ (this.d + this.f + this.P[this.n]) & 255 ];
			this.e = this.S[ (this.e + this.d) & 255 ];
			this.f = this.S[ (this.f + this.e) & 255 ];

			output[x] = this.S[(this.S[this.S[ (this.c + this.d) & 255 ]] + 1) & 255];      //pseudo-random number generation /**/
			//output[x] ^= this.S[(this.S[this.S[ (this.c + this.d) & 255 ]] + 1) & 255];   //encryption / decryption         /**/

			t = this.P[this.n];  this.P[this.n] = this.P[this.f];  this.P[this.f] = t;
			t = this.S[this.n];  this.S[this.n] = this.S[this.a];  this.S[this.a] = t;

			this.n++;
			this.n &= 0xff;
		}
		
		return output;
	}

/*
 * -----------------
 * Private functions
 * -----------------
 */

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
		if (!this.useInitialVector || this.initialVector.length < 1 || this.initialVector.length > 256) {
			throw jCastle.exception("INVALID_IV");
		}
		var iv = this.initialVector;
		
		this.P = Uint8Array.from(jCastle.algorithm.vmpcr.permut123);
		this.S = Uint8Array.from(jCastle.algorithm.vmpcr.permut123);
		this.a = 0; this.b = 0; this.c = 0; this.d = 0; this.e = 0; this.f = 0; this.n = 0;

		this.initKeyRound(key);
		this.initKeyRound(iv);
		this.initKeyRound(key);
		this.n = this.S[(this.S[this.S[ (this.c + this.d) & 255 ]] + 1) & 255];
		
		
//		this.initKeyFinalize();

		var t;
		
		for (var x = 0; x < 256; x++) {   
			this.a = this.P[ (this.a + this.c + this.S[this.n]) & 255 ];
			this.b = this.P[ (this.b + this.a) & 255 ];
			this.c = this.P[ (this.c + this.b) & 255 ];
			this.d = this.S[ (this.d + this.f + this.P[this.n]) & 255 ];
			this.e = this.S[ (this.e + this.d) & 255 ];
			this.f = this.S[ (this.f + this.e) & 255 ];
			t = this.P[this.n];  this.P[this.n] = this.P[this.f];  this.P[this.f] = t;
			t = this.S[this.n];  this.S[this.n] = this.S[this.a];  this.S[this.a] = t;
			this.n++;
			this.n &= 0xff;
		}
	}

	initKeyRound(data) 
	//data: key or initialization vector
	{
		var len = data.length;
		var i = 0, t;

		for (var r = 1; r <= jCastle.algorithm.vmpcr.initKeyRounds[len-1]; r++) {  //InitKeyRounds[len-1] = Math.ceil(len*len / (6*256))
			for (var x = 0; x < 256; x++)  {                //x will take on the same values as n in the algorithm's specification
				this.a = (this.P[ (this.a + this.f + data[i]) & 255 ] + i) & 255;   i++; if (i == len) i = 0;
				this.b = (this.S[ (this.b + this.a + data[i]) & 255 ] + i) & 255;   i++; if (i == len) i = 0;
				this.c = (this.P[ (this.c + this.b + data[i]) & 255 ] + i) & 255;   i++; if (i == len) i = 0;
				this.d = (this.S[ (this.d + this.c + data[i]) & 255 ] + i) & 255;   i++; if (i == len) i = 0;
				this.e = (this.P[ (this.e + this.d + data[i]) & 255 ] + i) & 255;   i++; if (i == len) i = 0;
				this.f = (this.S[ (this.f + this.e + data[i]) & 255 ] + i) & 255;   i++; if (i == len) i = 0;
				t = this.P[x];  this.P[x] = this.P[this.b];  this.P[this.b] = t;
				t = this.S[x];  this.S[x] = this.S[this.e];  this.S[this.e] = t;
				t = this.P[this.d];  this.P[this.d] = this.P[this.f];  this.P[this.f] = t;
				t = this.S[this.a];  this.S[this.a] = this.S[this.c];  this.S[this.c] = t;
			}
		}
	}
/*
	initKeyFinalize()
	{
		var t;
		
		for (var x = 0; x < 256; x++) {   
			this.a = this.P[ (this.a + this.c + this.S[this.n]) & 255 ];
			this.b = this.P[ (this.b + this.a) & 255 ];
			this.c = this.P[ (this.c + this.b) & 255 ];
			this.d = this.S[ (this.d + this.f + this.P[this.n]) & 255 ];
			this.e = this.S[ (this.e + this.d) & 255 ];
			this.f = this.S[ (this.f + this.e) & 255 ];
			t = this.P[this.n];  this.P[this.n] = this.P[this.f];  this.P[this.f] = t;
			t = this.S[this.n];  this.S[this.n] = this.S[this.a];  this.S[this.a] = t;
			this.n++;
			this.n &= 0xff;
		}
	}
*/

	/*
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
		var t;
		var len = input.length;
		var output = Buffer.alloc(len);
		
		for (var x = 0; x < len; x++)  {
			this.a = this.P[ (this.a + this.c + this.S[this.n]) & 255 ];
			this.b = this.P[ (this.b + this.a) & 255 ];
			this.c = this.P[ (this.c + this.b) & 255 ];
			this.d = this.S[ (this.d + this.f + this.P[this.n]) & 255 ];
			this.e = this.S[ (this.e + this.d) & 255 ];
			this.f = this.S[ (this.f + this.e) & 255 ];

			//output[x] = this.S[(this.S[this.S[ (this.c + this.d) & 255 ]] + 1) & 255];      //pseudo-random number generation /**/
			//output[x] ^= this.S[(this.S[this.S[ (this.c + this.d) & 255 ]] + 1) & 255];   //encryption / decryption         /**/
			
			output[x] = input[x] ^ this.S[(this.S[this.S[ (this.c + this.d) & 255 ]] + 1) & 255];

			t = this.P[this.n];  this.P[this.n] = this.P[this.f];  this.P[this.f] = t;
			t = this.S[this.n];  this.S[this.n] = this.S[this.a];  this.S[this.a] = t;

			this.n++;
			this.n &= 0xff;
		}
		
		return output;

	}
};

jCastle.algorithm.vmpcr.permut123 = [  //Permut123[x]=x
	 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,
	32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,
	72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,96,97,98,99,100,101,102,103,104,105,106,107,108,
	109,110,111,112,113,114,115,116,117,118,119,120,121,122,123,124,125,126,127,128,129,130,131,132,133,134,135,136,137,138,
	139,140,141,142,143,144,145,146,147,148,149,150,151,152,153,154,155,156,157,158,159,160,161,162,163,164,165,166,167,168,
	169,170,171,172,173,174,175,176,177,178,179,180,181,182,183,184,185,186,187,188,189,190,191,192,193,194,195,196,197,198,
	199,200,201,202,203,204,205,206,207,208,209,210,211,212,213,214,215,216,217,218,219,220,221,222,223,224,225,226,227,
	228,229,230,231,232,233,234,235,236,237,238,239,240,241,242,243,244,245,246,247,248,249,250,251,252,253,254,255
]; // 256

jCastle.algorithm.vmpcr.initKeyRounds = [ //InitKeyRounds[x]=Ceiling((x+1)*(x+1) / (6*256))
	 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
	5, 5, 5, 5, 5, 5, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 6, 6, 7, 7, 7, 7, 7, 7, 7, 8, 8, 8, 8, 8, 8, 8, 9, 9, 9, 9, 9, 9, 9,
	10, 10, 10, 10, 10, 10, 11, 11, 11, 11, 11, 11, 12, 12, 12, 12, 12, 12, 13, 13, 13, 13, 13, 13, 14, 14, 14, 14, 14,
	15, 15, 15, 15, 15, 16, 16, 16, 16, 16, 17, 17, 17, 17, 17, 18, 18, 18, 18, 18, 19, 19, 19, 19, 20, 20, 20, 20, 20,
	21, 21, 21, 21, 22, 22, 22, 22, 23, 23, 23, 23, 24, 24, 24, 24, 24, 25, 25, 25, 26, 26, 26, 26, 27, 27, 27, 27,
	28, 28, 28, 28, 29, 29, 29, 29, 30, 30, 30, 31, 31, 31, 31, 32, 32, 32, 33, 33, 33, 33, 34, 34, 34, 35, 35, 35,
	36, 36, 36, 36, 37, 37, 37, 38, 38, 38, 39, 39, 39, 40, 40, 40, 41, 41, 41, 42, 42, 42, 43, 43, 43
]; // 256


jCastle._algorithmInfo['vmpcr'] = {
	algorithm_type: 'crypt',
	block_size: 1, // stream cipher
	key_size: 32,
	min_key_size: 16,
	max_key_size: 64,
	padding: 'zeros',
	stream_block_size: 64,
	object_name: 'vmpcr'
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

module.exports = jCastle.algorithm.vmpcr;