/**
 * A Javascript implemenation of PKI - KCDSA
 * 
 * @author Jacob Lee
 * 
 * Copyright (C) 2015-2022 Jacob Lee. 
 */

var jCastle = require('./jCastle');
var BigInteger = require('./biginteger');
require('./util');

jCastle.pki.kcdsa = class
{
	/**
	 * An implementation of KC-DSA.
	 * 
	 * @constructor
	 */
	constructor()
	{
		this.OID = "1.2.410.200004.1.1";
		//this.OID = "1.2.410.200004.1.21"; // KCDSA1
		this.pkiName = 'KCDSA';
		this.blockLength = 0;
		this.bitLength = 0;
		this.hasPrivKey = false;
		this.hasPubKey = false;

		this.params = {};
		this.publicKey = null;
		this.privateKey = null;

		this._pkiClass = true;
	}

	/**
	 * resets internal variables.
	 * 
	 * @public
	 * @returns this class instance.
	 */
	reset()
	{
		this.params = {};
		this.publicKey = null;
		this.privateKey = null;

		this.blockLength = 0;
		this.bitLength = 0;

		this.hasPrivKey = false;
		this.hasPubKey = false;

		return this;
	}

	/**
	 * gets block length of parameter p in bytes.
	 * 
	 * @public
	 * @returns block length in bytes.
	 */
	getBlockLength()
	{
		return this.blockLength;
	}

	/**
	 * gets block length of parameter p in bits.
	 * 
	 * @public
	 * @returns block length in bits.
	 */
	getBitLength()
	{
		return this.bitLength;
	}

	/**
	 * sets publicKey.
	 * 
	 * @public
	 * @param {mixed} y publicKey object or buffer.
	 * @param {object} params parameters object.
	 * @returns this class instance.
	 */
	setPublicKey(y, params)
	{
		if (!params && typeof y == 'object' && 'kty' in y && y.kty == 'KCDSA') {
			params = {
				p: Buffer.from(y.p.replace(/[ \t\r\n]/g, ''), 'base64url').toString('hex'),
				q: Buffer.from(y.q.replace(/[ \t\r\n]/g, ''), 'base64url').toString('hex'),
				g: Buffer.from(y.g.replace(/[ \t\r\n]/g, ''), 'base64url').toString('hex')
			};
			
			var yy = BigInteger.fromByteArrayUnsigned(Buffer.from(y.y.replace(/[ \t\r\n]/g, ''), 'base64url'));

			return this.setPublicKey(yy, params);
		}

		if (params) {
			this.setParameters(params);
		}

		if (!this.params || !this.params.p) {
			throw jCastle.exception("PARAMETERS_NOT_SET", 'KCD001');
		}

		if (!y && this.privateKey) {
			// pkcs8 pem format doesn't give you 'y'.
			y = this.params.g.modPow(this.privateKey.modInverse(this.params.q), this.params.p);
		}

		this.publicKey = jCastle.util.toBigInteger(y);

	//	if (!z) {
	//		z = this.publicKey.mod(BigInteger.ONE.shiftLeft(this.params.l));
	//	}
	//	this.z = jCastle.util.toBigInteger(z);

		this.blockLength = (this.params.p.bitLength() + 7) >>> 3;
		this.bitLength = this.params.p.bitLength();

		this.hasPubKey = true;

		return this;
	}

	/**
	 * gets publicKey.
	 * 
	 * @public
	 * @param {string} format format string.
	 * @returns publicKey in format.
	 */
	getPublicKey(format = 'object')
	{
		if (this.hasPubKey) {
			if (format.toLowerCase() == 'jwt') {
				var params = this.getParameters('hex');

				return {
					kty: 'KCDSA',
					p: Buffer.from(params.p, 'hex').toString('base64url'),
					q: Buffer.from(params.q, 'hex').toString('base64url'),
					g: Buffer.from(params.g, 'hex').toString('base64url'),
					y: Buffer.from(this.publicKey.toString(16), 'hex').toString('base64url')
				};
			}

			return jCastle.util.formatBigInteger(this.publicKey, format);
		}

		return null;
	}

	/**
	 * gets privateKey.
	 * 
	 * @public
	 * @param {string} format format string
	 * @returns privateKey in format.
	 */
	getPrivateKey(format = 'object')
	{
		if (this.hasPrivKey) {
			if (format.toLowerCase() == 'jwt') {
				var params = this.getParameters('hex');

				return {
					kty: 'KCDSA',
					p: Buffer.from(params.p, 'hex').toString('base64url'),
					q: Buffer.from(params.q, 'hex').toString('base64url'),
					g: Buffer.from(params.g, 'hex').toString('base64url'),
					x: Buffer.from(this.privateKey.toString(16), 'hex').toString('base64url'),
					y: Buffer.from(this.publicKey.toString(16), 'hex').toString('base64url')
				};
			}

			return jCastle.util.formatBigInteger(this.privateKey, format);
		}

		return null;
	}

	/**
	 * sets privateKey and publicKey. publicKey will be computed if it does not exist.
	 * 
	 * @public
	 * @param {mixed} x privateKey object or buffer.
	 * @param {mixed} y publicKey object or buffer.
	 * @param {object} params parameters object.
	 * @returns this class instance.
	 */
	setPrivateKey(x, y, params)
	{
		if (typeof y == 'undefined' && typeof x == 'object' && 'kty' in x && x.kty == 'KCDSA') {
			params = {
				p: Buffer.from(x.p.replace(/[ \t\r\n]/g, ''), 'base64url').toString('hex'),
				q: Buffer.from(x.q.replace(/[ \t\r\n]/g, ''), 'base64url').toString('hex'),
				g: Buffer.from(x.g.replace(/[ \t\r\n]/g, ''), 'base64url').toString('hex')
			};
			
			var xx = BigInteger.fromByteArrayUnsigned(Buffer.from(x.x.replace(/[ \t\r\n]/g, ''), 'base64url'));
			var yy = BigInteger.fromByteArrayUnsigned(Buffer.from(x.y.replace(/[ \t\r\n]/g, ''), 'base64url'));

			return this.setPublicKey(xx, yy, params);
		}

		if (params) {
			this.setParameters(params);
		}

		if (!this.params || !this.params.p) {
			throw jCastle.exception("PARAMETERS_NOT_SET", 'KCD002');
		}

		this.privateKey = jCastle.util.toBigInteger(x);

		if (!y && this.privateKey) {
			// pkcs8 pem format doesn't give you 'y'.
			y = this.params.g.modPow(this.privateKey.modInverse(this.params.q), this.params.p);
		}

		this.setPublicKey(y);
		
		this.hasPrivKey = true;

		return this;
	}

	/**
	 * gets publicKey information object.
	 * 
	 * @public
	 * @param {string} format publicKey format string
	 * @param {string} param_format parameters format string
	 * @returns publicKey information object in format.
	 */
	getPublicKeyInfo(format = 'object', param_format = 'hex')
	{
		var pubkey_info = {};
		pubkey_info.type = 'public';
		pubkey_info.algo = this.pkiName;
		pubkey_info.parameters = this.getParameters(param_format);
		pubkey_info.publicKey = this.getPublicKey(format);

		return pubkey_info;	
	}

	/**
	 * gets privateKey information object.
	 * 
	 * @public
	 * @param {string} format privateKey format string
	 * @param {string} param_format parameters format string
	 * @returns privateKey information object in format.
	 */
	getPrivateKeyInfo(format = 'object', param_format = 'hex')
	{
		var privkey_info = {};
		privkey_info.type = 'private';
		privkey_info.algo = this.pkiName;
		privkey_info.parameters = this.getParameters(param_format);
		privkey_info.privateKey = this.getPrivateKey(format);

		return privkey_info;	
	}

	/**
	 * checks if the pubkey is the same with the publicKey of the class instance.
	 * 
	 * @public
	 * @param {object} pubkey publicKey object or buffer.
	 * @returns true if the pubkey is the same with the publicKey of this class instance.
	 */
	publicKeyEquals(pubkey)
	{
		if (!this.hasPubKey) return false;

		var p = jCastle.util.toBigInteger(pubkey);
		if (this.publicKey.equals(p)) return true;
		return false;
	}

	/**
	 * checks if publicKey is set.
	 * 
	 * @public
	 * @returns true if publicKey is set.
	 */
	hasPublicKey()
	{
		return this.hasPubKey;
	}

	/**
	 * checks if privateKey is set.
	 * 
	 * @public
	 * @returns true if privateKey is set.
	 */
	hasPrivateKey()
	{
		return this.hasPrivKey;
	}


	/**
	 * sets parameter values.
	 * 
	 * @public
	 * @param {mixed} p parameter p object or buffer
	 * @param {mixed} q parameter q object or buffer
	 * @param {mixed} g parameter g object or buffer
	 * @returns this class instance.
	 */
	setParameters(p, q, g)
	{
		if (typeof q == 'undefined' && typeof p == 'object') {
			var params = p;
			p = params.p;
			q = params.q;
			g = params.g;
	//		if ('l' in params) {
	//			l = params.l;
	//		}
		}

		this.params = {
			p: jCastle.util.toBigInteger(p),
			q: jCastle.util.toBigInteger(q),
			g: jCastle.util.toBigInteger(g)
		};

	//	if (l) {
	//		this.params.l = l;
	//	} else {
	//		this.params.l = 512; // default;
	//	}

		return this;
	}

	/**
	 * gets KC-DSA parameters.
	 * 
	 * @public
	 * @param {string} format parameters format string
	 * @returns parameters in format
	 */
	getParameters(format = 'hex')
	{
		return jCastle.pki.kcdsa.formatParameters(this.params, format);
	}

/*
KCDSA1 Specification:
=====================
! caution. It's not the old KCDSA.

- p : a large prime such that |p| = 1024 + 256 * i (0 <= i <= 4). That is, the bit-length
      of p can vary from 1024 bits to 2048 bits with increment byamultiple of 256 bits.

- q : a prime factor of p - 1 such that |q| = 160 + 32 * j (0 <= j <= 3). That is, the
      bit-length of q can vary from 160 bits to 256 bits with increment by a multiple of 32
      bits. Further, it is required that (p - 1) / 2q should be a prime or at least all of its
      prime factors should be greater than q.

- g : a base element of order q in GF(p), i.e., g != 1 and g^q = 1 mod p.

- x : signer's private signature key such that 1 <= x <= q.

- y : signer's public verification key computed by y = g^(x`) mod p, 
      where x` = x^(-1) mod q.

- z : a hash-value of Cert Data, i.e., z = h(Cert Data). Here Cert Data denotes
      the signer's certification data, which should contain at least signer's distinguished
      identifier, public key y and the domain parameters {p, q, g}.

	  signer-specific message prefix obtained by taking the lower B bits of
	  the public key y (i.e., computed by z = y mod 2^B), where B denotes 
	  the internal processing unit (block size in bits) of the hash function used
	  ( A tipical value of B is 512 for most existing hash functions, 
	  including SHA-1, RMD-160, and HAS-160. )

	  e.g, z = Y mod 2^512 :: 64bytes

*/
	/**
	 * generates KC-DSA parameters
	 * 
	 * @public
	 * @param {number} pbits p bits in number
	 * @param {number} qbits q bits in number
	 * @param {string} hash_algo hash algorithm name
	 * @params {buffer} seed seed value
	 * @returns this class instance.
	 */
	generateParameters(pbits, qbits, hash_algo, seed)
	{
		var params = jCastle.pki.kcdsa.generateParameters(pbits, qbits, hash_algo, seed, 'object');

	//	this.params = {
	//		p: new BigInteger(params.p, 16),
	//		q: new BigInteger(params.q, 16),
	//		g: new BigInteger(params.g, 16)
	//	};
		this.params = params;

		return this;
	}

	/**
	 * generates privateKey and publicKey.
	 * 
	 * @public
	 * @param {object} parameters parameters object. DSA parameters must be set if it is not given.
	 * @returns this class instance.
	 */
	generateKeypair(params, hash_algo)
	{
		if (typeof params == 'undefined' && (!this.params || !this.params.p)) {
			throw jCastle.exception("PARAMETERS_NOT_SET", 'KCD003');
		}

		if (typeof params != 'undefined') {
			this.setParameters(params, hash_algo);
		}

		// Choose an integer, such that 0 < x < q.
		var rng = new jCastle.prng();
		var x;
		var certainty = 10;

		do {
//			x = BigInteger.probablePrime(this.params.q.bitLength(), rng, certainty);
//			if (!x.isLucasLehmerPrime()) continue;
			x = BigInteger.random(this.params.q.bitLength(), rng);
		} while (x.compareTo(BigInteger.ZERO) <= 0 || x.compareTo(this.params.q) >= 0);

		this.privateKey = x; // private key
		this.hasPrivKey = true;

		// Compute y as g^(x`) mod p,  where x` is x^(-1) mod q.
		this.publicKey = this.params.g.modPow(this.privateKey.modInverse(this.params.q), this.params.p);

		this.hasPubKey = true;

	//	if (!this.l) this.l = 512; // block size of the hash function. normally 512.

	////if (this.l) {
	//		this.z = this.y.mod(BigInteger.ONE.shiftLeft(this.l));
	////}

		this.blockLength = (this.params.p.bitLength() + 7) >>> 3;
		this.bitLength = this.params.p.bitLength();

		return this;
	}

	/*
	http://cseric.or.kr/new_Cseric/yungoostep/content.asp?idx=397&startpage_view=395&startpage=405&page=34

	KCDSA (Korea Certification-based Digital Signature Algorithm)는 이산대수 문제의 어려움에
	기반을 둔 전자서명 알고리즘으로서, 한국통신정보보호학회의 주관 하에 우리 나라의 
	주요 암호학자들이 주축이 되어 1996년 11월에 개발하였으며, 
	이후 지속적인 수정 및 보완 작업을 거쳐 1998년 10월 TTA에서 단체 표준으로 제정되었다.
	KCDSA는 임의의 길이를 갖는 메시지에 대해 인증서 기반 부가형 전자서명의 생성과 검증을 위한 알고리즘이다.
	KCDSA 표준에 규정되어 있는 사항들은 이 표준을 사용하거나 이해함에 도움을 주기 위해 기술된 것으로 
	준수 사항은 아니다.

	◆ 서명 생성 과정

	서명 생성 과정에서는 메시지 M 을 입력으로 받아 다음 단계를 거쳐 계산된, 
	비트 열 R과 정수 S 의 쌍으로 구성된 S = {R, S}를 서명으로 출력한다.

	단계 0. (선택 사항) 도메인 변수 P, Q, G 와 공개 검증키 Y가 올바른지 검증한다.
	단계 1. 난수 값 K 를 {1, × × × , Q - 1}에서 랜덤하게 선택한다.
	단계 2. 증거 값 W = GK mod P 를 계산한다.
	단계 3. 서명의 첫 부분 R = h(W)를 계산한다.
	단계 4. Z =Y mod 2^l을 계산해서, 해쉬 코드 H = h(Z || M)을 계산한다. l은 해쉬함수의 블럭 비트
	단계 5. 중간 값 E = (R ⊕ H) mod Q 를 계산한다.
	단계 6. 서명의 두 번째 값 S = X(K - E) mod Q 를 계산한다. 만약 S=0 이면 단계 1로 간다.
	단계 7. 비트 열 R 과 정수 S 의 쌍, S = {R, S}를 서명으로 출력한다.

	단계 0 은 최초에 한 번만 수행하고 그 후 서명생성시 마다 사용할 수 있도록 
	P, Q, G 및 Y를 안전하게 보관할 수 있다. 단계 1부터 단계 3까지의 과정은 서명할 메시지와 관계가 없으므로
	사전에 계산해 둘 수도 있다. 즉 K 와 R 을 미리 계산해서 안전하게 보관하고 있다가 
	서명할 메시지가 들어오면 단계 4부터 실시간 계산을 할 수 있다. 이런 사전 계산 방식은 
	다수의 서명을 실시간으로 계산할 필요가 있을 때 유용하게 사용될 수 있으며, 
	이를 위해서는 사전 계산된 {K, R} 을 저장할 여분의 안전한 메모리를 갖추어야 한다. 
	*/
	/*
	Signature Generation 

	Signature Generation: The signer can generate a signature r||s for a message m as 
	follows:

	1. randomly picks an integer k in Zq* and computes w = g^k mod p, 
	2. computes the first part r of the signature as r = h(w), 
	3. computes z = Y mod 2^l (l = 512 : block size of hash function, likely SHA1, HAS-160, Y : public key)  
	4. computes e = r ⊕ h(z||m) mod q, 
	5. computes the second part s of the signature as s = x(k - e)mod q 
	6. if s=0, then repeats the above process. 


	The computation of w is the most time-consuming operation in the signing process. 
	However, since the first two steps can be performed independent of specific message 
	to be signed. we may pre-compute and securely store the pair r, k for fast on-line sig-
	nature generation. The above signing process can be described in brief by the follow-
	ing two equations: 
	r = h(g^k  mod p) wite k ∈r  Z*q, 
	s = x(k - (r ⊕ h(z || m))) mod q. 

	*/
	/**
	 * gets a signature of the message.
	 * 
	 * @public
	 * @param {buffer} str buffer or string to be signed
	 * @param {object} options options object.
	 *                 {string} hashAlgo hash algorithm name. (default: 'has-160')
	 *                 {string} returnType return type string. 'concat' | 'object' | 'asn1'. (default: 'asn1')
	 *                 {buffer} kRandom random K value for generating signature. this is for test mode.
	 * @returns the signature in return type.
	 */
	sign(str, options = {})
	{
		var hash_algo = 'hashAlgo' in options ? options.hashAlgo : 'has-160';
		var ret_type = 'returnType' in options ? options.returnType.toLowerCase() : 'asn1';
		var random_k = 'kRandom' in options ? options.kRandom : null;
		var ba;

		if (!this.hasPrivKey) throw jCastle.exception("PRIVKEY_NOT_SET", 'KCD004');

		if (Buffer.isBuffer(str)) ba = str;
		else ba = Buffer.from(str, 'latin1');

		// M: message to be signed
		// H: = h(z || M)
		// K: 0 < K < Q
		// W: W = G^K mod P
		// R: R = h(W)
		// E: E = (R ⊕ H) mod Q
		// S: S = X(K - E) mod Q

		hash_algo = jCastle.digest.getValidAlgoName(hash_algo);
		if (!hash_algo || jCastle._algorithmInfo[hash_algo].oid == null) {
			throw jCastle.exception("UNSUPPORTED_HASHER", 'KCD005');
		}

		if (random_k){
			if (!Buffer.isBuffer(random_k)) {
				if (/^[0-9A-F]+$/i.test(random_k)) random_k = Buffer.from(random_k, 'hex');
				else random_k = Buffer.from(random_k, 'latin1');
			}
		}

		var zero = BigInteger.valueOf(0);
		var one = BigInteger.valueOf(1);

		var l = jCastle.digest.getBlockSize(hash_algo) * 8;
		var z = this.publicKey.mod(one.shiftLeft(l)).toByteArrayUnsigned();
		// var l = jCastle.digest.getBlockSize(hash_algo);
		// var z = Buffer.alloc(l);
		// var y = Buffer.from(this.publicKey.toByteArray());
		// y.copy(z, 0, y.length - l);
		var h = jCastle.digest.create(hash_algo).start().update(z).update(ba).finalize();
		var h_bi = BigInteger.fromByteArrayUnsigned(h);

		// Generate a random number k, such that 0 < k < q.
		var rng = new jCastle.prng();
		var k, w, r, e, s, r_bi, res;
		var counter = 0;

		for (;;) {
			if (random_k) {
				if (counter) {
					throw  jCastle.exception("INVALID_SALT", 'KCD020');
				}
				k = BigInteger.fromByteArrayUnsigned(random_k);
			} else {
				do {
					k = BigInteger.random(this.params.q.bitLength(), rng);
				} while (k.compareTo(zero) <= 0 || k.compareTo(this.params.q) >= 0);
			}

			// w = g^k mod p
			w = this.params.g.modPow(k, this.params.p);
			r = new jCastle.digest(hash_algo).digest(w.toByteArrayUnsigned());
			r_bi = BigInteger.fromByteArrayUnsigned(r);

			// e = r ⊕ h(z||m) mod q
			e = r_bi.xor(h_bi).mod(this.params.q);

			// computes the second part s of the signature as s = x(k - e)mod q
			s = this.privateKey.multiply(k.subtract(e)).mod(this.params.q);

			if (s.compareTo(zero) > 0) break;

			counter++;
		}

		var bl = this.blockLength;
		var s_ba = Buffer.from(s.toByteArray());

		if (s_ba.length < bl) 
			s_ba = Buffer.concat([Buffer.alloc(bl - s_ba.length, 0x00), s_ba]);
		if (s_ba.length > bl)
			s_ba = s_ba.slice(s_ba.length - bl);

		switch (ret_type) {
			case 'concat':
				// r size is the hash size
				res = Buffer.concat([r, s_ba]);
				break;
			case 'object':
				res = {
					r: r,
					s: s_ba
				};
                break;
			case 'asn1':
			default:
				// Package the digital signature as {r,s}.
				res = new jCastle.asn1().getDER({
					type: jCastle.asn1.tagSequence,
					items:[{
						type: jCastle.asn1.tagOctetString,
						value: r
					}, {
						type: jCastle.asn1.tagInteger,
						intVal: s
					}]
				});
                res = Buffer.from(res, 'latin1');
				break;
		}

        if ('encoding' in options) {
            if (ret_type === 'object') {
                res.r = res.r.toString(options.encoding);
                res.s = res.s.toString(options.encoding);
            } else {
            	res = res.toString(options.encoding);
			}
        }
		return res;
	}

	/*
	Signature Verification 

	On receiving{m || r || s}, the verifier can check the validity of the signature as follows: 

	1. checks the size of r and s : 0 <= r < 2|q| , 0 < s < q, 
	2. computes z = Y mod 2^l (l : block size of hash function, Y : public key)  
	3. computes e = r ⊕ h(z || m) mod q, 
	4. computes w' = (y^s)(g^e) mod p 
	5. finally checks if  r = h(w'). 

	The pair {r||s} is a valid signature for m only if all the checks succeed. The above 
	verifying process can be described in brief by the following equations: 
	e = r ⊕ h(z || m) mod q, 
	r = h(y^s ∙ g^e  mod p)?  

	◆ 서명 검증 과정

	먼저 서명을 검증하기 전에 검증자는 서명자의 공개 검증키 Y 와 도메인 변수 P, Q, G등에 대한 
	올바른 값들을 얻어야 한다. 이를 위해 신뢰할 수 있는 인증기관에서 발행한 서명자의 인증서를 확인하고 
	이로부터 추출된 도메인 변수 P, Q, G와 공개 검증키 Y를 얻어 내는 방법을 사용 할 수 있다.

	단계 0. (선택 사항) 서명자의 인증서를 확인하고, 서명검증에 필요한 도메인 변수 P, Q, G와 공개 검증키 Y 를 추출한다.
	단계 1. 수신된 서명 ∑’ = {R’, S’}에 대해 비트열 R’이 해쉬 함수의 출력길이와 같은지 확인하고, 0 < S’ < Q 임을 확인한다.
	단계 2. Z=Y mod 2l 을 계산해서 검증할 메시지 M’에 대한 해쉬 코드 H’ = h(Z || M’)을 계산한다.
	단계 3. 중간 값 E’ = (R’ ⊕ H’) mod Q 을 계산한다.
	단계 4. 서명자의 공개 검증키 Y를 이용하여 증거 값 W’ =YS’GE’ mod P를 계산한다.
	단계 5. h(W’) = R’이 성립하는지 확인한다.

	검증 과정이 모두 통과되면 서명 ∑’는 수신 메시지 M’에 대하여 공개 검증키 Y에 대응하는 
	비공개 서명키 X로 서명하였음이 검증된 것이다. 위 검증 단계에서 하나라도 그 검증이 실패하면 
	메시지 M’에 대하여 불법적인 방법으로 서명이 되었거나 메시지가 변경된 것이므로 
	다음 단계로 넘어갈 필요 없이 M’에 대한 서명이 거짓임이 밝혀진 것이다. 

	자세한 알고리즘은 TTA의 KCDSA 표준문서를 참조하기 바란다.
	*/
	/**
	 * checks if the signature is right.
	 * 
	 * @public
	 * @param {buffer} str buffer or string to be signed
	 * @param {mixed} signature signature value.
	 * @param {object} options options object.
	 *                 {string} hashAlgo hash algorithm name. (default: 'has-160')
	 * @returns true if the signature is right.
	 */
	verify(str, signature, options = {})
	{
		if (!this.hasPubKey) throw jCastle.exception("PUBKEY_NOT_SET", 'KCD006');

		var hash_algo = 'hashAlgo' in options ? options.hashAlgo : 'has-160';
		var ba, r, s;

		if (Buffer.isBuffer(str)) ba = str;
		else ba = Buffer.from(str, 'latin1');

		hash_algo = jCastle.digest.getValidAlgoName(hash_algo);
		if (!hash_algo || jCastle._algorithmInfo[hash_algo].oid == null) {
			throw jCastle.exception("UNSUPPORTED_HASHER", 'KCD007');
		}

		var hash_size = jCastle.digest.getDigestLength(hash_algo);

		if (typeof signature === 'object' && 'r' in signature && 's' in signature) {
			// object {r, s}
            if (!Buffer.isBuffer(signature.r)) {
				if (/^[0-9A-F]+$/i.test(signature.r)) {
					r = Buffer.from(signature.r, 'hex');
					s = Buffer.from(signature.s, 'hex');
				} else {
					r = Buffer.from(signature.r, 'latin1');
					s = Buffer.from(signature.s, 'latin1');
				}
			} else {
				r = Buffer.from(signature.r);
				s = Buffer.from(signature.s);
			}
			r = BigInteger.fromByteArrayUnsigned(r);
			s = BigInteger.fromByteArrayUnsigned(s);
		} else {
			if (!Buffer.isBuffer(signature)) {
				if (/^[0-9A-F]+$/i.test(signature)) signature = Buffer.from(signature, 'hex');
				else signature = Buffer.from(signature, 'latin1');
			}

			if (jCastle.asn1.isAsn1Format(signature)) {
				try {
					// asn1
					var sequence = new jCastle.asn1().parse(signature);

					if (!jCastle.asn1.isSequence(sequence)) return false;

					r = BigInteger.fromByteArrayUnsigned(Buffer.from(sequence.items[0].value, 'latin1'));
					s = sequence.items[1].intVal;
				} catch (ex) {
					// concat
					r = BigInteger.fromByteArrayUnsigned(signature.slice(0, hash_size));
					s = BigInteger.fromByteArrayUnsigned(signature.slice(hash_size));
				}
			} else {
				// concat
				r = BigInteger.fromByteArrayUnsigned(signature.slice(0, hash_size));
				s = BigInteger.fromByteArrayUnsigned(signature.slice(hash_size));
			}
		}
		
		var zero = BigInteger.valueOf(0);
		var one = BigInteger.valueOf(1);
		var two = BigInteger.valueOf(2);

		var l = jCastle.digest.getBlockSize(hash_algo) * 8;
		var z = this.publicKey.mod(one.shiftLeft(l)).toByteArrayUnsigned();
		// var l = jCastle.digest.getBlockSize(hash_algo);
		// var z = Buffer.alloc(l);
		// var y = Buffer.from(this.publicKey.toByteArray());
		// y.copy(z, 0, y.length - l);
		var h = jCastle.digest.create(hash_algo).start().update(z).update(ba).finalize();
		var h_bi = BigInteger.fromByteArrayUnsigned(h);

		if (r.compareTo(zero) <= 0 || r.compareTo(this.params.q.multiply(two)) >= 0 ||
			s.compareTo(zero) <= 0 || s.compareTo(this.params.q) >= 0
		) {
			return false;
		}

		// computes e = r ⊕ h(z || m) mod q, 
		var e = r.xor(h_bi).mod(this.params.q);

		// w' = (y^s)(g^e) mod p 
		//var w = this.y.modPow(s, this.p).multiply(this.g.modPow(e, this.p)).mod(this.p);
		var u1 = this.publicKey.modPow(s, this.params.p);
		var u2 = this.params.g.modPow(e, this.params.p);
		var w = u1.multiply(u2).mod(this.params.p);

		// finally checks if  r = h(w'). 
		var v = new jCastle.digest(hash_algo).digest(w.toByteArrayUnsigned());
		v = BigInteger.fromByteArrayUnsigned(v);
				
		// If v == r, the digital signature is valid.
		return v.compareTo(r) == 0;
	}
}

/**
 * creates a new KC-DSA pki object.
 * 
 * @public
 * @returns the new KC-DSA pki object.
 */
jCastle.pki.kcdsa.create = function()
{
	return new jCastle.pki.kcdsa();
};

jCastle.pki.kcdsa._PPGF = function(md, seed, hash_len, bits)
{
	var len = Math.ceil(((bits + 7) & 0xFFFFFFF8) / 8);
	var tmp;
	var result = Buffer.alloc(len);

	for (var count = 0;; count++) {
		md.start();
		md.update(seed);
		md.update(Buffer.alloc(1, count & 0xff));
		tmp = md.finalize();

		if (len >= hash_len) {
			len -= hash_len;
			tmp.copy(result, len, 0, tmp.length);
			if (len === 0) break;
		} else {
			tmp.copy(result, 0, hash_len - len, hash_len);
			break;
		}
	}

	len = bits & 0x07;
	if (len !== 0) result[0] &= (1 << len) - 1;

	return result;
};
/*
- p : a large prime such that |p| = 1024 + 256 * i (0 <= i <= 4). That is, the bit-length
      of p can vary from 1024 bits to 2048 bits with increment byamultiple of 256 bits.

- q : a prime factor of p - 1 such that |q| = 160 + 32 * j (0 <= j <= 3). That is, the
      bit-length of q can vary from 160 bits to 256 bits with increment byamultiple of 32
      bits. Further, it is required that (p - 1) / 2q should be a prime or at least all of its
      prime factors should be greater than q.

- g : a base element of order q in GF(p), i.e., g != 1 and g^q = 1 mod p.

Remember just 4 principles:

1. P - 1 = 2JQ
   P and Q are primes.
   2JQ + 1 = P

2. J = (p - 1) / 2Q
   J should be also a prime number.

3. 1 < U < P

4. G = U^2J mod P
*/

// KISA_KCDSA_GenerateParameters 
// only acceps sha-224 and sha-256 for hash algorithm.
// hash_len: 28 or 32
// KISA had suggested (1024, 160), (2048, 224), (2048, 256), (3072, 256) in 2011.
/**
 * generates KC-DSA parameters.
 * 
 * @public
 * @param {object} options options object.
 *                 {number} pBits bits length for parameter p. (default: 2048)
 *                 {number} qBits bits length for parameter q. (default: 256)
 *                 {string} hashAlgo hash algorithm name. (default: 'sha-256')
 *                 {string} format format string.
 *                 {buffer} seed seed buffer
 *                 {number} certainty certainty for generating random. (default: 10)
 *                 {buffer} gHash gHash value for test.
 * @returns generated parameters object.
 */
jCastle.pki.kcdsa.generateParameters = function(options = {})
{
	

	var certainty = 'certainty' in options ? options.certainty : 10;
	var qBits = 'qBits' in options ? options.qBits : 256;
	var seed = 'seed' in options ? options.seed : null;
	var pBits = 'pBits' in options ? options.pBits : 2048;
	var hash_algo = 'hashAlgo' in options ? options.hashAlgo : 'sha-256';
	var hash_len = jCastle.digest.getDigestLength(hash_algo);
	var format = 'format' in options ? options.format : 'hex';
	var g_hash = 'gHash' in options ? options.gHash : null;
	var seed_len = qBits >>> 3;

	if (seed && !Buffer.isBuffer(seed)) seed = Buffer.from(seed);
	if (g_hash && !Buffer.isBuffer(g_hash)) g_hash = Buffer.from(g_hash);


	if (seed && seed.length !== seed_len) {
		throw jCastle.exception("INVALID_SEED", 'KCD012');
	}

	if (pBits < 2048 || pBits > 3072 || pBits % 256) {
		throw jCastle.exception("INVALID_BITLENGTH", 'KCD013'); // "Invalid parameter p bits";
	}

	if (qBits < 224 || qBits > 256 || qBits % 32) {
		throw jCastle.exception("INVALID_BITLENGTH", 'KCD014'); // "Invalid parameter q bits";
	}

	var rng = new jCastle.prng();
	var md = new jCastle.digest(hash_algo);
	var seed_provided = seed ? true : false;
	var U, J, p, q, g;
	var counter = 0;
	var limit = 1 << 24;

	do {
		//	Step 1. |Q| 비트 크기의 임의의 비트열 Seed를 선택한다.
		if (counter && seed_provided) {
			// seed 값이 주어졌으나 생성된 BigInteger J가 소수가 되지 못함.
			// 루프문을 빠져나갈 수 없으므로 throw error한다.
			throw jCastle.exception("INVALID_BITLENGTH", 'KCD015');
		}
		if (!seed_provided) seed = rng.nextBytes(seed_len);

		//	Step 2. U = PRNG(Seed, |P|-|Q|-4)
		U = jCastle.pki.kcdsa._PPGF(md, seed, hash_len, pBits - qBits - 4);

		U[0] |= 0x80;
        U[U.length - 1] |= 0x01;

		J = BigInteger.fromByteArrayUnsigned(U);

		//	Step 3. J = 2|P|-|Q|-1 XOR U XOR 1
		// sometimes setBit() makes negative number.
		// J = J.setBit(pBits - qBits - 1);
		// J = J.setBit(0);

		//	Step 4. J가 소수가 아니면 단계 1로 간다.
		counter++;
	}
	while (!J.isProbablePrime(certainty));

	//	Step 5. Count를 0으로 둔다.
	counter = 0;

	for (counter = 1; counter < limit; counter++) {
		//	Step 6. Count를 1증가시킨다.
		//	Step 7. Count > 2^24이면 단계 2로 간다.

		//	Step 8. U = PRNG(Seed || Count, |Q|)
		var cb = Buffer.alloc(4);
		cb.writeInt32BE(counter, 0);
		//cb[0] = 0x00;

		U = jCastle.pki.kcdsa._PPGF(md, Buffer.concat([seed, cb]), hash_len, qBits);

		U[0] |= 0x80;
        U[U.length - 1] |= 0x01;

		q = BigInteger.fromByteArrayUnsigned(U);

		//	Step 9. Q = 2^(|Q|-1) XOR U XOR 1
		// sometimes setBit() makes negative number.
		// q = q.setBit(qBits - 1);
		// q = q.setBit(0);

		p = q.multiply(J);

		//	Step 10. P = 2JQ+1의 비트수가 |P|보다 크면 단계 6으로 간다.
		if (p.testBit(pBits - 1)) continue;

		p = p.shiftLeft(1);

		//p = p.add(BigInteger.ONE);
		p = p.setBit(0);

		//	Step 11. 강한 소수 판정 알고리즘으로 Q를 판정하여 소수가 아니면 단계 6으로 간다.
		//	Step 12. 강한 소수 판정 알고리즘으로 P를 판정하여 소수가 아니면 단계 6으로 간다.
		if (!q.isProbablePrime(certainty)) continue;
		if (p.isProbablePrime(certainty)) break;
	}

	if (counter == limit) throw jCastle.exception("FATAL_ERROR", 'KCD016');

	//	Step 1. P보다 작은 임의의 수 U를 발생시킨다.

	var g_counter = 0;
//	var TWO = BigInteger.valueOf(2);

	J = J.shiftLeft(1); // 2*J

	for (;;) {
		if (g_hash) {
			if (g_counter) throw jCastle.exception("FATAL_ERROR", 'KCD017');
			U = BigInteger.fromByteArrayUnsigned(g_hash);
			g_counter++;
		} else {
			U = BigInteger.random(pBits, rng);
			if (U.compareTo(BigInteger.ONE) <= 0 || U.compareTo(p.subtract(BigInteger.ONE) >= 0)) {
				continue;
			}
		}
		
		//	Step 2. G = U^2J mod P를 계산한다.
		//g = U.modPow(J.multiply(TWO), p);
		g = U.modPow(J, p);
		if (g.compareTo(BigInteger.ONE) <= 0) {
			continue;
		}
		break;
	}

	var params = {
		p: p,
		q: q,
		g: g
	};

	params.validity = {};
	params.validity.counter = counter;
	params.validity.seed = seed.toString('hex');

	//return params;
	return jCastle.pki.kcdsa.formatParameters(params, format);
};

// this one takes too much time...
jCastle.pki.kcdsa.generateParametersExt = function(options = {})
{
	var certainty = 'certainty' in options ? options.certainty : 10;
	var qBits = 'qBits' in options ? options.qBits : 160; // 256
	var seed = 'seed' in options ? options.seed : null;
	var pBits = 'pBits' in options ? options.pBits : 1024; // 2048
	var hash_algo = 'hashAlgo' in options ? options.hashAlgo : 'has-160'; // sha-256
	var hash_len = jCastle.digest.getDigestLength(hash_algo);
	var format = 'format' in options ? options.format : 'hex';
	var seed_len = qBits >>> 3;

	if (pBits < 1024 || pBits > 4096 || pBits % 8) {
		throw jCastle.exception("INVALID_BITLENGTH", 'KCD008'); // "Invalid parameter p bits";
	}

	if (qBits < 160 || qBits > 256 || qBits % 32) {
		throw jCastle.exception("INVALID_BITLENGTH", 'KCD009'); // "Invalid parameter q bits";
	}

	if (pBits >= 2048 && qBits < 224) {
		throw jCastle.exception("INVALID_BITLENGTH", 'KCD010'); // "Small qbits";
	}

	// if (pBits >=2048 && hash_algo == 'has-160') {
	// 	throw jCastle.exception("UNFIT_HASH", 'KCD011'); // "HAS-160 is not fit for the bits. You might not specify the hash name.";
	// }

	if (seed && !Buffer.isBuffer(seed)) seed = Buffer.from(seed);
	if (!seed) seed = Buffer.from(Date.now().toString());

	var rng = new jCastle.prng(seed, hash_algo);
	var one = BigInteger.valueOf(1);
	var two = BigInteger.valueOf(2);
	var counter = 0;
	var p, q, g, j, h;

	do {
		// Choose a prime number q, which is called the prime divisor.
		j = BigInteger.probablePrime(pBits - qBits - 4, rng, certainty);
		q = BigInteger.probablePrime(qBits, rng, certainty);

		p = q.multiply(j);

		if (p.testBit(pBits - 1)) {
			continue;
		}

		//p = p.multiply(two).add(one);
		p = p.shiftLeft(1);
		p = p.setBit(0);

		counter++;
	} while (!p.testBit(pBits - 1) || !p.isProbablePrime(certainty));

	// Choose an integer g, such that 1 < g < p, g**q mod p = 1 and g = h**((p–1)/q) mod p. 
	// q is also called g's multiplicative order modulo p.
	j = j.multiply(two); // j*2

	do {
		h = BigInteger.random(pBits, rng);
		if (h.compareTo(p.subtract(one)) >= 0 || h.compareTo(one) <= 0) {
			continue;
		}

		g = h.modPow(j, p);
	} while (!g || g.compareTo(one) <= 0);	// sometimes g is undefined...

	var params = {
		p: p,
		q: q,
		g: g
	};

	params.validity = {
		counter: counter,
		seed: seed.toString('hex')
	};


	return jCastle.pki.kcdsa.formatParameters(params, format);
};


jCastle.pki.kcdsa.formatParameters = function(params, format = 'hex')
{
	switch (format) {
		case 'hex':
			var pp = {
				p: params.p.toString(16),
				q: params.q.toString(16),
				g: params.g.toString(16)
	//			l: params.l
			};
			break;
	// 	case 'raw':
	// 	case 'utf8':
	// 		var pp = {
	// 			p: jCastle.encoding.hex.decode(params.p.toString(16)),
	// 			q: jCastle.encoding.hex.decode(params.q.toString(16)),
	// 			g: jCastle.encoding.hex.decode(params.g.toString(16))
	// //		l: params.l
	// 		};
	// 		break;
		case 'object':
			var pp = {
				p: params.p.clone(),
				q: params.q.clone(),
				g: params.g.clone()
	//			l: params.l
			};
			break;
		default:
			var pp = {
				p: Buffer.from(params.p.toByteArray()),
				q: Buffer.from(params.q.toByteArray()),
				g: Buffer.from(params.g.toByteArray())
			};
			if (format !== 'buffer') {
				pp.p = pp.p.toString(format);
				pp.q = pp.q.toString(format);
				pp.g = pp.g.toString(format);
			}
			break;
	}

	if ('validity' in params) {
		pp.validity = {};
		pp.validity.counter = params.validity.counter;
		pp.validity.seed = params.validity.seed;
	}

	return pp;
};

jCastle._pkiInfo['kcdsa'] = {
	pki_name: 'KCDSA',
	object_name: 'kcdsa',
	oid: "1.2.410.200004.1.1"
};

jCastle.pki.KCDSA = jCastle.pki.kcdsa;

module.exports = jCastle.pki.kcdsa;

