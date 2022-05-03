# jCastle

A native implementation of cryptographic library in JavaScript.

## Introduction

jCastle is a native implementation of cryptographic library in JavaScript. It supports most of algorithms. The merit of jCastle comes from its ability of analysis. You can see with examples.

## Installation

Currently npm install is not supported.

<!--
If you use **Node.js** then it is available through `npm`:
Installation:

    npm install jCastle

You can then use jCastle as a regular module:

```js
var jCastle = require("jCastle");
```

The npm package includes pre-built `jCastle.min.js` and you will need `buffer.js` to use in the web browser. `buffer.js` is uploaded in the top directory.
-->

The pre-built `jCastle.min.js` file is inside `dist` folder and it includes `buffer.js` for to use with the web browser.

## Testing

jCastle includes many testing codes and it is time consuming.

### Running automated tests with Node.js

jCastle natively runs in a Node.js environment:

    npm test

## API

### mcrypt

`jCastle.mcrypt` module encrypts/decrypts a message. The input should be `buffer` or it is converted as `buffer` value. The output comes in `buffer`.

```js
var message = "This is the message";
var crypto = new jCastle.mcrypt();
var ciphertext = crypto
  .start({
    algoName: "AES-256",
    key: key,
    nonce: nonce,
    mode: "GCM",
    isEncryption: true,
    additionalData: adata,
  })
  .update(message)
  .finalize();
```

`jCastle.mcrypt` processes with `jCastle.algorithm` and `jCastle.mcrypt.mode` and the first code can be re-written like:

```js
var message = "This is the message";
var is_encryption =  true;
var block_size = jCastle.mcrypt.getBlockSize("aes-256");
var algo = new jCastle.algorithm.seed("aes-256");
algo.keySchedule(key, is_encryption);
var gcmMode = jCastle.mcrypt.mode.create("gcm");
gcmMode.init({
    algorithm: algo,
    nonce: nonce,
    blockSize: block_size,
    isEncryption: is_encryption,
    additionalData: adata
});
var ciphertext = Buffer.alloc(0);
message = Buffer.from(message);
for (var i = 0; i < message.length; i += 16) {
    ciphertext = Buffer.concat([
        ciphertext,
        gcmMode.process(message.slice(i, i+16)
    ]);
ciphertext = Buffer.concat([
    ciphertext,
    cbcMode.finish() // for the tag.
]);
```

The supported `algorithm` list:

    AES, Anubis, Aria, Blowfish, Camellia, Cast-128(Cast5), Cast-256(Cast6),
    Chacha20, Clefia, DES , DES-EDE3, GOST28147-89, Hight, Idea, Lea,
    RC2, RC4, RC5, RC6, Safer-k64/sk64/k128/sk128, Safer+, Seed-128,
    Serpent, Skipjack,  Threefish, Twofish, VMPC, VMPCR, XTea

The supported `mode` list:

    ECB, CBC, PCBC, CFB, OFB, NCFB, NOFB, CTR, GCTR(GOFB), GCFB,
    CTS(CBC/ECB), XTS, EAX, CCM, GCM, CWC, Poly1305-AEAD(for Chacha20 only),
    wrap(keywrap)

### mac

`jCastle.mac` is the implementation of message authentication code(mac) and the supported algorithms are:

    CBC-Mac, CMac, GMac, VMPC-Mac, Poly1305-Mac, GOST28147-Mac,
    ISO9797Alg3-Mac(DES-EDE-Mac), CFB-Mac

example:

```js
var  macName = ‘cmac’;
var  mac = jCastle.mac.create(macName);
mac.start({
    //macName: macName,
    algoName: 'aes-128',
    key: key
}).update("The quick fox jumps over the lazy dog!");
var macCode = mac.finalize();
```

This code can be re-written like this:

```js
var message = "The quick fox jumps over the lazy dog!";
var macMode = jCastle.mac.mode.create('cmac');
var algo = jCastle.mcrypt.getAlgorithm('aes-128');
macMode.init(algo, {
    key: key
});
message = Buffer.from(message);
for (var i = 0; i < message.length; i += 16) {
    macMode.process(message.slice(i, i+16);
}
var macCode = macMode.finalize();
```

### digest

`jCastle.digest` is the implementation of message digest algorithm. Supported algorithms are:

    MD2, MD4, MD5, SHA-1, SHA-224|256|384|512, SHA-512/224, SHA-512/256,
    HAS-160, RIPEMD-128|160|256|320, Tiger, Whirlpool, Haval, Gost3411,
    SHA3-224|256|384|512, Shake-128/(128/256/384/512)|256/(256/384/512),
    Skein-256/512/1024, CRC

Basic usage is like this example:

```js
var  hashName = ‘sha-512’;
var  md = jCastle.digest.create(hashName);
md.start(
// { algoName: hashName }
);
md.update("The quick fox jumps over the lazy dog!");
var hash = md.finalize();
```

### hmac

`jCastle.hmac` is the implementation of hash message authentication code and the basic usage is like:

```js
var  hmac = jCastle.hmac.create(‘skein-1024’);
hmac.start({
    key: key,
    encoding: ‘hex’,
    outputBits: 512 // or outputLength: 64
});
hmac.update("The quick fox jumps over the lazy dog!");
var code = hmac.finalize(); // hex string code.
```

### kdf

`jCastle.kdf` is the implemenation of key derivation function and `jCastle.kdf` supports `pbkdf1`, `pbkdf2`, `pkcs5DeriveKey`, `ansX963DeriveKey`, `singlestepKDF`(or `concatKDF`) and `pkcs12DeriveKey`.

### keywrap

`jCastle.keywrap` is the implementation of keywrap algorithm and the basic usage is like:

```js
var kw = new jCastle.KeyWrap();
var keydata = Buffer.from(
  `00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F`,
  "hex"
);
var wrapping_key = Buffer.from(
  `000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F`,
  "hex"
);
var expected = Buffer.from(
  `28C9F404C4B810F4 CBCCB35CFB87F826 3F5786E2D80ED326 CBC7F0E71A99F43B FB988B9B7A02DD21`.replace(
    / /g,
    ""
  ),
  "hex"
);
var ct = kw.wrap({
  wrappingKey: wrapping_key,
  keyData: keydata,
});
console.log(ct.equals(expected));

var pt = kw.unwrap({
  wrappingKey: wrapping_key,
  keyData: ct,
});
console.log(pt.equals(keydata));
```

### pki

`jCastle.pki` is the implementation of public key infrastructure and `jCastle.pki` supports `RSA`, `DSA`, `ECDSA`, `ElGamal`, `KCDSA` and `EC-KCDSA`.
`jCastle.pki` parses publicKey and privateKey `PEM` or `buffer` data and builds `PKCS#5` and `PKCS#8` format `PEM`.
Examples:

```js
var enc_private_key = `
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,584BBCF38BE41D90AB16740EE5D2E24C
k5m1gaYDbX+EYPcv/+wvSsYOkBpOxFYXbzMYY8Z2d39mfQ8Y+WzOJnWWYT2tj2d8
LodWRu2PD93or3z8wI0Y5huCs6VikZLtjxKawPwm5wosXud978k3dVw+VG/M8JDh
J6dIAbcmNxaHv1UX5gmdnRcRqSGt0WHXYbXgUlSNLwhrTU9osd7A/eLZf5MZ5hTB
5CQ/Tb9jCZxSyP8YiPvOuR9gCK5L3Ooq820mwZ0oL9r18uby4ElSmFuM+nipThyu
4SinV3MIN5bOMvsb34DDbQ9wbbtvDA1V7iJRItLo9+1v5d7O876BTSwX9Qd12P0C
WqiKUAt/T/ZB/NJC3bw2v9bRL+VifvfLmOigvw7r2NAokpRHb8Elv80S5ZtcZGmp
tQ7wCkO8kz/JFX/UXqqkSSBsegtGm+CwenEvyQ5dtUUu1ETo7vOMp9c+AZyKCNgu
MDC5nhLBm1H93t1Wko45yn/Az7RVw6yzUEp6WrADajjGtLwVbLC5eDd7+9utHp/x
UB/5H+vI+nbYP5KBc/Zqe/IjSrVKFBtoD2MowVtkWg42mGgQ1VNKYhKELLFFtWxd
HuYlHVYYiOHXbMLsofMkqxxJQatS7WtKBWBgmYbqhHxNpZ11QKxzk+Wo+J9ixLbs
ADBhAak4t7eHFZtbKonP+hEGanZGK04Wz8+leo+BL+7J5d4d9WZPFH9q47kM5/Wc
qUkJIZPzwKAlb5ot/9XQmqnECip2yRhyJYcOBqfg4EXfCbDqz3YCFS8HpPOVQqMs
ZGvRA9LrZfsy6V9NCWFZbBtiYjO2gOtYASoDKyo615vdma42L8P+h2UPtk8e0ziM
OpuZiR37HsahyWAcGgomprs+hmV5yFnzIs5O5P6J0uf2TCrUR8cZBuYoPVp9pErc
l/U5m0G+ENTwzs8Dd6ySyDpKlADRnjQYPxulbT4VpT9c9kUg3sxRHWRv5C0FLVPq
M0atErcFtKIlLPsEDKHwfx3kyRrsEopU8f9kTpcTKcHEdrp7zKJFCmKZa9K53/JZ
Y9Z8DQY7e36l7UOuVIMqzBxADZIUJsyw8AmUu2/pwjgNfAjRD11p3k9rz0cMMp0X
5Np2VfSdVSkHFsDqLw7B6AKO+3fXtzqMPD40b+vIDhrpDJNgrwMCKVlkw2J1A6VG
Ec4oSDc3gIXLzA7O/42xSAObA9hZldEqrimMCFlW+qkkWyUh9mWhiUyJyZ5MgPk2
LW80PS+3q3G7ALEnP69cNxJ3CE7nfYUNmcv8cYkJU0Y2SXXYdN75ejVEDLo6TfJT
mxZV476I23gsBnAAk+G5RYSzx/lZ0VEV/8Z0B/X1UV/Oc5bm38chLKLFxYzVr400
KzEb3m0LgwtR+N9kkMLTEkFeCFqublZ9qcJm/GP3+7BNcXaDBq950fZRKz5ET0So
QbDopxjjW8CBPTSj8f1zlRqp1mAiwHdliNjUL5xhqNjKwR5XVpntSqy5KS1QXD2e
hfjciNo1DcBMpSs+X6GqYuqybpU/El/XX7o9+Qb5Dy5zY+5MfOl2/O/4ToYWGc+/
KmpQTLFiCqXrWNRQVbvvmCpuq/dHJL2aeE9Y/JcOH+yt9YEPB7hPZyXM15AVxVfL
-----END RSA PRIVATE KEY-----`;
var password = Buffer.from("password");
var pki = new jCastle.pki("RSA");
pki.parsePrivateKey(enc_private_key, password);

// 1. export public key
var pem = pki.exportPublicKey();
var pki1 = new jCastle.pki("RSA");
pki1.parsePublicKey(pem);

var privkey1 = pki.getPrivateKey();
var pubkey2 = pki1.getPublicKey();
assert.ok(privkey1.n.equals(pubkey2.n), "parse public key");

// 2. no encryption pkcs#5
var pem3 = pki.exportPrivateKeyPKCS5();
console.log(pem3);

// 3. pkcs#5 encrypted with des-ede3-CBC
var pem3 = pki.exportPrivateKeyPKCS5({ password: password, algo: "des-ede3" });
console.log(pem3);

// pkcs#5 encrypted with camellia-256
var pem3 = pki.exportPrivateKeyPKCS5({
  password: password,
  algo: "camellia-256",
});
console.log(pem3);

// pkcs#8 no encryption
var pem3 = pki.exportPrivateKey();
console.log(pem3);

// pkcs#8 encryption pkcs5 v1.5 / default pbeWithMD5AndDES-CBC
var pem3 = pki.exportPrivateKey({ password: password });
console.log(pem3);

// pkcs#8 encryption pkcs5 v1.5 / pbeWithSHAAnd40BitRC2-CBC
var pem3 = pki.exportPrivateKey({
  password: password,
  algo: "pbeWithSHAAnd40BitRC2-CBC",
});
console.log(pem3);

// pkcs#8 encryption pkcs5 v1.5 / pbeWithSHAAnd64BitRC2-CBC
var pem3 = pki.exportPrivateKey({
  password: password,
  algo: "pbeWithSHAAnd64BitRC2-CBC",
});
console.log(pem3);

// pkcs#8 encryption pkcs12 / pbeWithSHAAnd128BitRC4
var pem3 = pki.exportPrivateKey({
  password: password,
  algo: "pbeWithSHAAnd128BitRC4",
});
console.log(pem3);

// pkcs#8 encryption pkcs12 / pbeWithSHAAnd2-KeyTripleDES-CBC
var pem3 = pki.exportPrivateKey({
  password: password,
  algo: "pbeWithSHAAnd2-KeyTripleDES-CBC",
});
console.log(pem3);

// pkcs#8 encryption pkcs12 / PBE-SHA1-SEED
var pem3 = pki.exportPrivateKey({ password: password, algo: "PBE-SHA1-SEED" });
console.log(pem3);

// pkcs#8 encryptions pkcs5 v2.0 / seed-cbc / default prf hmacWithSHA
var pem3 = pki.exportPrivateKey({ password: password, algo: "seed-cbc" });
console.log(pem3);

// pkcs#8 encryptions pkcs5 v2.0 / idea-cbc / default prf hmacWithSHA384
var pem3 = pki.exportPrivateKey({
  password: password,
  algo: "ideacbc",
  prf: "hmacWithSHA256",
});
console.log(pem3);
```

### dh/ecdh

`jCastle.dh` is the implementation of Diffie-Hellman key exchange algorithm and and `jCastle.ecdh` is the implementation of ECDH(Elliptic Curve Diffie-Hellman key exchange algorithm. The code following is the `jCastle.ecdh`'s example:

```js
var brainpoolP512t1_pem = `-----BEGIN EC PARAMETERS-----
MIIBogIBATBMBgcqhkjOPQEBAkEAqt2duNvpxIs/1OauM8n8B8swjbOzydIO1mOc
ynAzCHF9TZsAm8ZoQq7NoSrmo4DmKIH/Ly2CxoUoqmBWWDpI8zCBhARAqt2duNvp
xIs/1OauM8n8B8swjbOzydIO1mOcynAzCHF9TZsAm8ZoQq7NoSrmo4DmKIH/Ly2C
xoUoqmBWWDpI8ARAfLu8+UQc+rduGJDkaITq4yH3DAvLSYFSeJdQS+w+NqYrzfoj
BJdlQPZFAIXy2uFFwiVTtGV2NokYDqJXGGdCPgSBgQRkDs5cEniHF7nBugbLwqb+
uoWEJFjFbd6dsXWNOcAxPYK6UXNc2z6kmap3p9aUOmT3o/Jf4m8GtRuqJpb6kDXa
W1NL1ZX1rw+iyJI3bISs4btOMBm3FjTAETEVnK4DzunZkyGEvu8ha9cd8trfhqYn
MG7P+W27i6zhmLYeAPizMgJBAKrdnbjb6cSLP9TmrjPJ/AfLMI2zs8nSDtZjnMpw
MwhwVT5cQUypJhlBhmEZf6wQRx2x04EIXdrdtYeWgpypAGkCAQE=
-----END EC PARAMETERS-----`;
var alice = new jCastle.pki("ECDSA");
var bob = new jCastle.pki("ECDSA");
alice.parseParameters(brainpoolP512t1_pem);
bob.parseParameters(brainpoolP512t1_pem);

// Now allice and Bob both has the same parameters. now generate public & private key...
alice.generateKeypair();
bob.generateKeypair();

// get public keys...
var alice_pubkey = alice.getPublicKey().encodePoint();
var bob_pubkey = bob.getPublicKey().encodePoint();

// Compute secret...
var alice_ecdh = new jCastle.ecdh().init(alice);
var bob_ecdh = new jCastle.ecdh().init(bob);
var alice_secret = alice_ecdh.computeSecret(bob_pubkey);
var bob_secret = bob_ecdh.computeSecret(alice_pubkey);

// Both secrets should be equal
console.log(
  "DiffieHellman Key Agreement with ECDSA Parameters(ECDH) Test: ",
  alice_secret.equals(bob_secret)
);

// creating ephemeral private key
var prng = jCastle.prng.create();
var alice_ephemeral_privkey = BigInteger.random(alice.getBitLength(), prng);
var bob_ephemeral_privkey = BigInteger.random(bob.getBitLength(), prng);

// creating ephemeral public key
var alice_ephemeral_pubkey = alice.getEphemeralPublicKey(
  alice_ephemeral_privkey
);
var bob_ephemeral_pubkey = bob.getEphemeralPublicKey(bob_ephemeral_privkey);

var alice_ecdh = jCastle.ecdh.create().init(alice);
var bob_ecdh = jCastle.ecdh.create().init(bob);
var zz = alice_ecdh.calculateMQVAgreement(
  alice_ephemeral_privkey,
  bob_pubkey,
  bob_ephemeral_pubkey
);
var zz1 = bob_ecdh.calculateMQVAgreement(
  bob_ephemeral_privkey,
  alice_pubkey,
  alice_ephemeral_pubkey
);

console.log("MQV Key Agreement with ECDSA Test: ", zz1.equals(zz));
```

### asn1

`jCastle.asn1` is the implementation of Abstract Syntax Notation Number On(ASN1) parser and it accepts `der` string or `buffer` and returns the asn1 structured object as the result. The following code is the basic example:

```js
var asn1 = new jCastle.asn1();
var obj = asn1.parse(signed_cert);
console.log(obj);
```

The parsed object's structure is much like: (Tag numbers are stringified.)

```js
{
  tagClass: 'Universal',
  type: 'SEQUENCE',
  items: [
    {
      tagClass: 'Universal',
      type: 'SEQUENCE',
      items: [Array],
      _isAsn1: true,
      buffer: <Buffer 30 82 04 83 a0 03 02 01 02 02 ... 06 13 02 6b 72 31 10 30 0e 06 ... 1109 more bytes>,
      indefiniteLength: false
    },
    {
      tagClass: 'Universal',
      type: 'SEQUENCE',
      items: [Array],
      _isAsn1: true,
      buffer: <Buffer 30 0d 06 09 ... 01 01 0b 05 00>,
      indefiniteLength: false
    },
    {
      tagClass: 'Universal',
      type: 'BIT STRING',
      _isAsn1: true,
      unused: 0,
      encapsulated: false,
      constructed: false,
      value: 'c1aa6a65594f ... c4a6221ade4d2c199ae5000b',
      bitString: '1100000110101010011...11001010000000000001011'
    }
  ],
  _isAsn1: true,
  buffer: <Buffer 30 82 05 9b 30 82 04 83 ... 31 0b 30 09 06 03 55 04 06 13 02 6b 72 31 ... 1389 more bytes>,
  indefiniteLength: false
}
```

### certificate

`jCastle.certificate` is the implementation of X.509 Certificate parser and builder. It can accepts `CSR` and issues `CRT` and builds `CRL` with revoked certificate information. This is the demo:

```js
// DEMO
// JISCO - jCastle Internet & Security Company
//
var jisco_priv_pem = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAHe+YHFvjkxmqH0v
UtyTSd3WH7CkGcmRtYNFZhYE4dS/hH8D50h9YlINwpQRXStRT70Jj0GmjH58t9/Y
OGXmJJJwYO4muldITFZMD4Y8cFjGOp7+PczqQf8saHLoHO0uDn2K1XEYktb9UQS8
LhMbwyzpn9o5OjThcsK3b2YuGkzQ6+CEnB2XN4qNpJqjzukrxoZwAtRRCGvo92Wt
oucTA5ThTLKsYOLNLZON3+HfKPQfdNk/5X8Df6J1qasgoLfW39JiFlsyvHIxoNL2
583DXyDxesBAcoJds6r2xEhhak/Bu7CS45JmXne0fw9yGTA4NcHenf2dsyep+Us0
ZHE1WFECAwEAAQKCAQANV+qZWWwK+XmXEZnzOHqHvN+lKHQzMQiAC1C37W1Y7sqN
+NpiCo7VQ/FF3LV8KUBweUs8bpnDUpSO3iJSwJWct+clQq2LImRXTXyBYeTHD7fi
lcQ/PG+ERueQvmrSx0oYFUt5odpjGLFZjLq5qGNUcug8QhpJYEIQjq5cPZDytEFz
PiVvtzhmmzsz+gW2jS3hlwwgoZCSPA+/5eT/ber4B2lK62GDDRO+J667Agp/E9L/
OLKShumcgNItZ8nQdzJj+Rg82XBLX44KTE5IyTM7UlLCWix0NbjObOfGSFTUv7nX
3Ef+qNz5qmJ0EFpvaD3Sj3Reetn25k6cxYgvW23tAoGBANY7pyhJM3xgJgmgkGge
pzQRwK/AuVnS4JpGUbVUTZ1DUj9Vd6+FfW8Ij0lROPfj21jXbiCaPD0cX2+RptVv
uGcq4er56dv+do/UeoFevlql7k2rw4gkIvjbwDbm2icF/cAOUXeUxI87rfE4XUIA
GVigHTrUn/7Mus5BygTZT7uTAoGBAI8WxRnivR1tpr6Vo0828aUuyh2hXK3Mb1Fz
bme5uBmoO/Z2UOVwkhLo9adC+jLY3o4bR4XkwuiGfgiGbND8k7t2IKPB+aZE1Wmd
sIFRIvP8n3q8eDCjWZOmGtFGLrZVNW6pKCclh1JIfgOkJ5O3na5yXr9jxN3DR98/
QOfsLjMLAoGActD9wYWZ5mrReA9p1aO4ERwCnS85J37xiT1uxTQtdL+D8RWpU5TD
qSJ5SN4THigsguzSxP5kkowGShFRzMpXllNRSVIvmAxFFsjV70gL1SFhGpeX7/sO
EzoTRllrScbYPHpwBxrgTbO6gbGnqZvL+ce2YrVaGoE3DRwNXZPqO6kCgYEAipZA
MtEj38PbM04VTVzm8Nj/k3E9JWwTCS2m6jm7sMX7xbtUoNTF9iDCBM1fLS5VaAfN
30Xw7WuN2E3ySPvJTlCcTl9KoBqdJN1BHg7qrqun/yVZt6oO0W2ZHcY+6gRfax3V
MQ0tIqnpuzcbyfuWcmZ9lBtaintgOj62a6qaGH8CgYEAnZXFzL8+UQp4zogUH3uY
o5K3y8/dzvuQlUQNShOqySCYZq138TB4GRapbjEtybj5H8ir1lApM1xzcJcisT+f
QClpPUxq1KitZqZPj1PtH6Yn+vP4CWq9D6a+6lt9DhH7rwqyOmcTskmIeGJWerP4
YTdgkw8sWi3fZ9kH06PUPKs=
-----END PRIVATE KEY-----`;
jisco_pki = new jCastle.pki("RSA");
jisco_pki.parse(jisco_priv_pem);

console.log("JISCO - jCastle Internet & Security Company");
console.log("JISCO ROOT PEM: ");
console.log(jisco_pki.exportPrivateKey());

// 2. create server private key
console.log("Creating server private key...");

var srv_pki = new jCastle.pki("RSA");
srv_pki.generateKeypair({
  bits: 2048,
  exponent: 0x10001 /* 65537 */,
});
console.log("Server Private Key PEM: ");
console.log(srv_pki.exportPrivateKey());

// 3. create server CSR
console.log("Creating server CSR...");
var srv_subject = [
  {
    name: "C",
    value: "kr",
  },
  {
    name: "O",
    value: "demosign",
  },
  {
    name: "OU",
    value: "demoCA",
  },
  {
    name: "CN",
    value: "demoCA Class 1",
  },
];
var srv_algo = {
  signAlgo: "RSASSA-PKCS1-V1_5",
  signHash: "sha-256",
};
var srv_extensions = {
  basicConstraints: {
    cA: true,
  },
  keyUsage: {
    critical: true,
    list: ["nonRepudiation", "digitalSignature"],
  },
};
var srv_cert = new jCastle.certificate().setSignKey(srv_pki);
var srv_csr_pem = srv_cert.request({
  subject: srv_subject,
  algo: srv_algo,
  extensions: srv_extensions,
});
console.log("Server CSR PEM: ");
console.log(srv_csr_pem);
console.log("csr verify test: ", srv_cert.verify(srv_csr_pem, srv_pki));

// 4. create server certificate
console.log("Creating server Certificate...");

var jisco_cert = new jCastle.certificate().setSignKey(jisco_pki);
var jisco_issuer = [
  {
    name: "C",
    value: "KR",
  },
  {
    name: "O",
    value: "JISCO",
  },
  {
    name: "OU",
    value: "Demo Certificate Authority Central",
  },
  {
    name: "CN",
    value: "JISCO RootCA 1",
  },
];
var serial = new jCastle.prng().nextBytes(4);
serial = parseInt("00" + serial.toString("hex"), 16);
var srv_cert_pem = jisco_cert.issue(srv_csr_pem, {
  serialNumber: serial,
  issuer: jisco_issuer,
  algo: {
    signAlgo: "RSASSA-PKCS1-V1_5",
    hashAlgo: "sha-256",
  },
  extensions: {
    subjectKeyIdentifier: "hash",
    // authorityKeyIdentifier: {
    // keyIdentifier: "always",
    // authorityCertIssuer: "always"
    // }
  },
});

console.log("Server Certificate PEM:");
console.log(srv_cert_pem);

var cert_info = new jCastle.Certificate().parse(srv_cert_pem);
console.log(cert_info);
```

### certConfig

`jCastle.certConfig` parses OpenSSL's `cnf` file content and returns structured object. Basic example:

```js
var parser = jCastle.certConfig.create();
var config = parser.parse(openssl_inf);
console.log(config);
```

When creating certificates `jCastle.certificate` can use OpenSSL's `cnf` content using `jCastle.certificate.setConfig()`.

```js
var cert_builder = new jCastle.certficate();
cert_builder.setConfig(openssl_inf);
cert_builder.setSignKey(sign_key);
...
```

### pfx

`jCastle.pfx` is the implementation of PFX-Personal Information Exchange(PFX). `jCastle.pfx` only creates OpenSSL style pfx now.

Example:

```js
var enc_priv_key_pem = `
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFLDBWBgkqhkiG9w0BBQ0wSTApBgkqhkiG9w0BBQwwHAQICOOtqCPzODkCAggA
MAwGCCqGSIb3DQIJBQAwHAYIKoMajJpEAQQEEJ7IEWELxKhpmbtUKJu63rYEggTQ
oquhw9Jlj9lqWzl7FHp/wmC5WagTChuhfT6KOvFk0Fcz1G4Zy0osvOnvsUA3zw+V
3zyTHEHT/ajrojScZgc6D2vCYH+NjiQKRHCxBEUI5KdZbz9+epS2jHyTwPlJzJP4
hCOb6oXo2fPL/nc9U7Cyb5oqr5mGIE19BNKJdJWwbTt1kjN753cqGWLM6GaP3eKx
m0axdNZ6fgZJ9scdvb3rnnKw5OjiCp3b+8zSHCaq5W1LqF1kABt1sWCZBnxKwY8y
B2IfiK3JnUG5DLdvUtZotfNHeGNweu0LDgH4ZH8c/i3yB/TwBYbK4VNPiYkxoXT7
1YUGQqbQwFQ6EwWpfGFxnUPTTDjG3GkWFYrs8Tm6EDWkoi8Bqd8CMLelNs+suF7g
KWZ33j+E4Fp45d39IowNWdf2R4kaGsvW3FCkNaa1E+o4zZHTWv9+69K3dZV5Pt4/
JMneSbfuumvgOSPsJmD0KWVfqOVJs59wyVLrYHieQ34xKx1A3qWpdzTJHwdPyK7q
Ra5fPR7j4bT7ncYqML5KQb5Uqz9BZLGZD5fqFzVgjwyALDdYNxoHQccb6NhOq1e5
yKCGhZ9guRfp6Hy6F8LMJV2e9rHHI4gPCUvZkMk/SjXV2Vy9xxKvdAWAcInN4dEp
/yiLqy8zpy0q85hydOU/ItaCEhv0a5ttHQV0yXVWvf5WcF+snzW/4y0WboRB/IRC
LN/WpGSaVr8uqYE3NLRa80nLZF2Xvnmu3BEccKtsF3C71qlNi31Ksqq3pv0gTL+7
vWhOhwYlVfpvH5e0OINYhpvXHdqzeCbueUJ6u1T2vT5p4Q7E59jK6myNTEE0VeLf
SgwnLBThXiZM53NtWcS6gPJ8y+QZyosBwOLcsM9ojnkNrfa4tZet4vMutzMONoQq
nnIR5sHd9T4m96/032CSPePsknViIer7JiCq0bNFXpgWMjDJQZuVjmomOepT3aob
yQcPcYgKeG5l9TWaVb0sm4pYjQv+aqzmYo8ZJGfnwUUOmW9BdbZPEdIx8lE1yir6
1FRDPLz3B94NXS9G8u2DzxvnKJ87pZDI9yeU4zGUd6pW5biMe4GeCJDxrvoizwIA
qcqtejJu816SBQGQ4yyJa39EX2wUOJI23oSqRFSQ0mdxfds5BC6y9i4+2ZekbU9b
tToWFMMqiOgFcrzgy4N5olQxbiM+wYAAZdN0fN/mXDYRTzZxlfoo9oHRpKyAm105
Z7sDG5DSD60SUnCYkg2iVHTk+5OV1nW8pfAcrWYSbi+g4rXl2bNBB/fShzKLOSMh
zoZ6C+5ZkuFPl5C57g5xZyy4sK4tU2nAQutF73zNTCipx2O4jl4pGpqwiDrcuD6O
p7KVQbVe/P5jHC4s9cNb1Hb2J6bVvnH2oXU2tta5FPAVah9936fEn6I97nZi9+7S
UKTG0US9Im87pIzt4gfJqMxCPZgulHvV8pBNzZFAY/F424hV1EHizaInhaoUDSj0
crXvZpIAUZzO3HpuI/ysMywqOd2NqxWRQNVYobo2ur2FVOTCNO/RQarr9BvYT1GX
85cefe+APXCbzOUL+7JAzVNDLYkqDsMykz8QrtksUmOdyG/fznH/3gyDfzi3Lson
PPHRqlwvjJwaoX356aZBx+majfTWvPLRsmUhQdTwldE=
-----END ENCRYPTED PRIVATE KEY-----`;

var cert_pem = `
-----BEGIN CERTIFICATE-----
MIID6zCCAtOgAwIBAgIBATANBgkqhkiG9w0BAQsFADBKMQswCQYDVQQGEwJrcjER
MA8GA1UEChMIZGVtb3NpZ24xDzANBgNVBAsTBmRlbW9DQTEXMBUGA1UEAxMOZGVt
b0NBIENsYXNzIDEwHhcNMTkxMjExMTQwMTI0WhcNMjAxMjExMTQwMTI0WjB/MQsw
CQYDVQQGEwJrcjERMA8GA1UECgwIZGVtb3NpZ24xFDASBgNVBAsMC3BlcnNvbmFs
NElTMREwDwYDVQQLDAhEZW1vQmFuazE0MDIGA1UEAwwrw63CmcKNw6rCuMK4w6vC
j8KZKCkwMDk5MDMzMjAxOTEyMTExMTA0MTE4MDCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBANNX9DPTDRpp/QBx4O6h7k6YrSAqys4d8nE7BrtqYTsyiPg4
0u+wPYYqZdYzLHyt4FhoT5u64XmvTgf98e67LjX2VUvZzK5r6kocSqa978t7Ievf
uww4Hq6qr1rNdzfmNIcOdwj6Npn8Lz7sDef6UIXZPj8/Ary6kugmEE+otrU7zmQl
yrZugGTjOAOutq3qA6Z7FWHfYIrBMGc7JMouehvOFSu+EB7PVhwKUcaxbRS4x3+e
UB4JMG9+5f0z5DLMf6SdckxDQtzkCOYjq8zd7ufhANxeOtSbjKKojnJfovAQqj4W
vvyv6tBJrg9MF+ZZhQWzBi4rbppwtJ0gTfMOsr8CAwEAAaOBpjCBozAMBgNVHRME
BTADAQEAMB0GA1UdDgQWBBQ5wMqSqxM/Bxrssawz73W+7FJEgzB0BgNVHSMEbTBr
oWWkYzBhMQswCQYDVQQGEwJLUjENMAsGA1UECgwERElTQTErMCkGA1UECwwiRGVt
byBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgQ2VudHJhbDEWMBQGA1UEAwwNRElTQSBS
b290Q0EgMYICEAMwDQYJKoZIhvcNAQELBQADggEBAGn4j78ZNBoUYrTOrpRPuRRE
px/wqULne4mrYEB5RUe1B6KEI1W78kD8cFGvsPc2JJi0fo0aTeW7BUPM6Oh6vKtf
fpbW9wxzT5VB/3w4klwoug0qaBYguskd1AZsxrxHg1zAUDdtgzWKRIKj6hp1VN9w
7lQE5nIrBYwR78eGBeTIRqxc/zaviVYNTdnZFAoBCTBYJI5wmZaMmSoYzNnO/UQY
ZccHTjW4TkJb0GuDuX7hRI7y0g45mbasuzpD2u5N2VYZH38kHc0eFMDLJOcRl5MV
tcB1Tuc/oM+1QS6ZfFePQfNpKSx3+wQPc5CKfRE6zGhM58LMJ6TqjXON7Ebe+PI=
-----END CERTIFICATE-----`;
var password = "1111aaaa!!!!";

var pfx = new jCastle.pfx.create();
pfx_der = pfx.exportCertificateAndPrivateKey({
  certificate: cert_pem,
  privateKey: enc_priv_key_pem,
  password: password,
});

var pfx_info = pfx.parse(pfx_der, {
  password: password,
});
console.log("pfx_info: ", pfx_info);
```

### cms

`jCastle.cms` is the implementation of Cryptographic Message Syntax(CMS). The supported types are `AuthenticatedData`, ` AuthEnvelopedData`, `DigestedData`, `EncryptedData`, `EnvelopedData`, `SignedData`.

The following code is the example of `EncryptedData` type.

```js
var encryptKey = Buffer.from("000102030405060708090a0b0c0d0e0f", "hex");
var encrypteddata_pem = `
-----BEGIN CMS-----
MIAGCSqGSIb3DQEHBqCAMIACAQAwgAYJKoZIhvcNAQcBMB0GCWCGSAFlAwQBAgQQ
rNaWW2F+b+pR/3t732H3QKCABBAuNuLZg/4euGW8ZL1Ko4tzAAAAAAAAAAAAAA==
-----END CMS-----`;
var plaintext = "hello world";

var cms = jCastle.cms.create();
var cms_info = cms.parse(encrypteddata_pem, {
  encryptKey: encryptKey,
});
console.log("cms_info: ", cms_info);

var cms_info2 = {
  contentType: "encryptedData",
  content: {
    encryptedContentInfo: {
      type: "data",
      contentEncryptionAlgorithm: {
        algo: "aes-128-CBC",
      }, //,
      // content: plaintext
    },
  },
};

var cms_data = cms.exportCMS(cms_info2, {
  format: "base64",
  content: plaintext,
  encryptKey: encryptKey,
});
console.log(jCastle.util.lineBreak(cms_data, 64));

var cms_info3 = cms.parse(cms_data, {
  encryptKey: encryptKey,
});
console.log("cms_info3: ", cms_info3);
```

`AuthenticatedData` type example:

```js
var bits = 1024;
var password = "password";
var privkey_pem = `
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDOBZhK/11578ky
wgY+TFIFPlceyA4vZgQmHY/k+lzxW/z3bCJtZCydaskMnkUvGMJXk20tWLCitOfl
EdZGJndMFQhJzPQic+uYI/6eevHN5T/eBFbS41tGdHtC8ZBbNuzZdvK8Aheo7n8p
a3jO1wnqLrA72eurZZZjiQgH7JdczfAV4CV6GZFgCqtmWJv3ZFTYb8DoxqcLay99
6DGovaOytuIcE1D6lTdNAJyK9OsPK5K3JK/YeHKJoE54XwhKqY0WA0NyN7M8TkH6
rA9oXEaYmG9O13OkT/MV4j1lCdqzC5HKloeARpQwfHFfLEqyUsG6szgnT9RFGQCe
+e/kLowPAgMBAAECggEAUd/9VwjHYFdAEVD0ZDu2eOj+fHgq0wFq8q7a6bfpye2x
ya6KvAiMhn7SqZYYjo/7ZAxt3hCaGf9lDS8ahcRxsqXFJncyKqMA5PShEuBvSlEq
IZR94M+EDarq9X7EzMs2M3JHIxp9xqAJny9b0m+5O/0UAqUnOHVl3+asb2HCAZoK
rhcStW7plMKCX0GB7wiuFmtH2fgDHGDOU/qtZsUdx/uv7JeD53cEskIUKydH9OBm
I8WbKc5xOyk45BaX4kjGAXMKntc1PvjZhYX1HP8jwIfqggBD1TFCfRiDi1xCPO95
mm9RP/Qx9w+BfQX+1Sjw8O6ZQB7qLXSK0nU2JFICSQKBgQD+NToGqENyAiHWl+tA
m/AjAqBF8vjbqsBsxWT/eFEd/g13raR0LDcF3Ubhtgqa9SdanyT2VpC4UyeELEGP
9cgAJDVtV+52Aznhy3bMdx3dqVHwpm930x7C9CGrUOYIwLFs3kanFbOb9jg0S5Fj
TayciIkI7NgilXGRqPkd98r1UwKBgQDPeWfxdomIoV2yz0YO3xHkaPqE+8L9zp3b
nDliofIGrseDdCEwEai0zNlYkUbLUXWMiMLnDTetYTvl7w7QqE3p/CnbJ/DBoStU
7SbJZ8znyvW/e1oEoSBxOgzChJZVY9APJIGJW1+2IknlD62y2FSVA3YS0KpAlB2T
tkzaNEIa1QKBgQCCJJ3gaqSc6ZqJUp2OJkd6pQ2IwivFylVZWnWqlN5yjG44px1a
nIhO6EoxpBEp4/iR3If/1bGhrHC+qimmmh4adG8l266pnF01zAS2CQWxRc49dff7
UIqfJH1YR8J9GKm9Is7pG6MoZZXAsC9ut4V3Xi9J8nd0vS23dNqVDRdLIQKBgBbu
yHp8K7+adozpNEk4hvXEVMyWN3tudyxrHDy2wdXTQ+JX18NEcG1rpyqPBFA89M1P
4JtBbsIPWVuVDQIrWFFgug+rXoVIl02P2RWyD4gfewJrVAvm83sQe5CUrzlJCxph
YqAYJYAwUhKrpPt7xf2ioE58GhWBSbOmFuCXnibxAoGAUkVYcVwtNd3YbWolIjh2
h1cLyIOkKdvqcRxAl1z/I+wCe7klSSwJCEqcif/Ueh+CqcywsC3Itwg/znhHITaM
ZbuGLJrFuuc9t5hofd5Ht9tkWTQEpI3SNVsou/SbP1Xb+PL6ndPNsSVUPoXvIRdM
wOwbyIdR5BgbRsDIgBbYTLo=
-----END PRIVATE KEY-----`;

/* root */

var root = new jCastle.pki();
root.parsePrivateKey(privkey_pem);
var issuer = [
  {
    name: "countryName",
    value: "KR",
    type: jCastle.asn1.tagPrintableString,
  },
  {
    name: "stateOrProvinceName",
    value: "Chungcheongbuk-do",
    // type: jCastle.asn1.tagUTF8String // default
  },
  {
    name: "localityName",
    value: "Cheongju",
  },
  {
    name: "organizationName",
    value: "jCastle Corp",
  },
  {
    name: "organizationalUnitName",
    value: "WebCert Support",
  },
  {
    name: "commonName",
    value: "jCastle Web CA",
  },
  {
    name: "emailAddress",
    value: "support@jcastle.net",
  },
];

/* alice */

var alice = jCastle.pki.create("RSA");
alice.generateKeypair({
  bits: bits,
  exponent: 0x10001,
});
alice.setPadding("rsaes-oaep");
console.log("alice rsa key generated.");

var alice_privkey_pem = alice.exportPrivateKey({ password: password });
console.log("alice private key pem with password: ");
console.log(alice_privkey_pem);

var alice_subject = [
  {
    name: "countryName",
    value: "KR",
    type: jCastle.asn1.tagPrintableString,
  },
  {
    name: "stateOrProvinceName",
    value: "Seoul",
    // type: jCastle.asn1.tagUTF8String // default
  },
  {
    name: "organizationName",
    value: "DACOCHE",
  },
  {
    name: "commonName",
    value: "Dacoche Web Flatform",
  },
];

var alice_cert_info = {
  type: jCastle.certificate.typeCRT,
  tbs: {
    serial: 750365,
    issuer: issuer,
    subject: alice_subject,
    subjectPublicKeyInfo: alice.getPublicKeyInfo(),
    extensions: {
      keyUsage: {
        list: ["keyEncipherment", "digitalSignature"],
        critical: true,
      },
    },
  },
  algo: {
    signHash: "SHA-256",
    signAlgo: "RSASSA-PKCS1-V1_5", // 'RSASSA-PSS', 'EC', 'DSA'
  },
};
var alice_cert = jCastle.certificate.create();
var alice_cert_pem = alice_cert
  .setSignKey(root)
  .exportCertificate(alice_cert_info);
console.log("alice certificate pem: ");
console.log(alice_cert_pem);

/* bob */

var bob = jCastle.pki.create("RSA");
bob.generateKeypair({
  bits: bits,
  exponent: 0x10001,
});
console.log("bob rsa key generated.");

var bob_privkey_pem = bob.exportPrivateKey({ password: password });
console.log("bob private key pem with password: ");
console.log(bob_privkey_pem);

var bob_subject = [
  {
    name: "countryName",
    value: "KR",
    type: jCastle.asn1.tagPrintableString,
  },
  {
    name: "stateOrProvinceName",
    value: "Seoul",
    // type: jCastle.asn1.tagUTF8String // default
  },
  {
    name: "organizationName",
    value: "Hareem",
  },
  {
    name: "commonName",
    value: "Hareem Food",
  },
];

var bob_cert_info = {
  type: jCastle.certificate.typeCRT,
  tbs: {
    serial: 6649112,
    issuer: issuer,
    subject: bob_subject,
    subjectPublicKeyInfo: bob.getPublicKeyInfo(),
    extensions: {
      keyUsage: {
        list: ["keyEncipherment", "digitalSignature"],
        critical: true,
      },
    },
  },
  algo: {
    signHash: "SHA-256",
    signAlgo: "RSASSA-PKCS1-V1_5", // 'RSASSA-PSS', 'EC', 'DSA'
  },
};
var bob_cert = jCastle.certificate.create();
var bob_cert_pem = bob_cert.setSignKey(root).exportCertificate(bob_cert_info);
console.log("bob certificate pem: ");
console.log(bob_cert_pem);

/* alice exports cms with authenticatedData - ktri */
console.log("alice exports cms with authenticatedData - ktri");

var cms_info = {
  contentType: "authenticatedData",
  content: {
    recipientInfos: [
      {
        type: "keyTransRecipientInfo",
        keyEncryptionAlgorithm: {
          algo: "RSA",
          padding: {
            mode: "RSAES-OAEP", // PKCS1_OAEP
            hashAlgo: "sha-1",
            mgf: "mgf1",
            label: "",
          },
        },
      },
    ],
    macAlgorithm: {
      algorithm: "hmacWithSHA256",
    },
  },
};

var plaintext = "Hello world!";
var cms = jCastle.cms.create();
var options = {
  cmsKey: {
    privateKey: alice_privkey_pem,
    password: password,
    certificate: alice_cert_pem,
    recipient: {
      certificate: bob_cert_pem,
    },
  },
  content: plaintext,
};

var cms_pem = cms.exportCMS(cms_info, options);
console.log("alice cms_pem: ");
console.log(cms_pem);

/* bob parses cms pem */
console.log("bob parses cms pem.");

var cmsKey = {
  privateKey: bob_privkey_pem,
  password: password,
};
var options = {
  cmsKey: cmsKey,
};
var cms_info = cms.parse(cms_pem, options);
console.log("cms_info: ");
console.log(cms_info);
```

`AuthEnvelopedData` example:

```js
/* alice exports cms with authEnvelopedData - ktri */
console.log("alice exports cms with authEnvelopedData - ktri");

var cms_info = {
  contentType: "authEnvelopedData",
  content: {
    recipientInfos: [
      {
        type: "keyTransRecipientInfo",
        //"identifierType": "subjectKeyIdentifier",
        // identifierType: 'issuerAndSerialNumber', // default
        keyEncryptionAlgorithm: {
          algo: "RSA",
          padding: {
            mode: "RSAES-OAEP", // PKCS1_OAEP
            hashAlgo: "sha-1",
            mgf: "mgf1",
            label: "",
          },
        },
      },
    ],
    authEncryptedContentInfo: {
      contentEncryptionAlgorithm: {
        algo: "aes-128-GCM",
      },
    },
  },
};
var plaintext = Buffer.from("Hello world!");
var cms = jCastle.cms.create();
var options = {
  cmsKey: {
    privateKey: alice_privkey_pem,
    password: password,
    certificate: alice_cert_pem,
    recipient: {
      certificate: bob_cert_pem,
    },
  },
  content: plaintext,
};

var cms_pem = cms.exportCMS(cms_info, options);
console.log("cms_pem: ", cms_pem);
var options = {
  cmsKey: {
    privateKey: bob_privkey_pem,
    password: password,
  },
};
var cms_info = cms.parse(cms_pem, options);
console.log("cms_info: ", cms_info);
```

`SignedData` type example:

```js
/* alice exports cms with signedData */

var content = Buffer.from("alice the queen!");
var cms_info = {
  contentType: "signedData",
  content: {
    digestAlgorithms: ["sha-256"],
    signerInfos: [
      {
        digestAlgorithm: "sha-256",
        signatureAlgorithm: {
          algo: "RSA",
          padding: {
            mode: "RSAES-PKCS-V1_5", // PKCS1_Type_2
          },
        },
      },
    ],
  },
};
var cms = jCastle.cms.create();
var cms_signed_data_pem = cms.exportCMS(cms_info, {
  format: "pem",
  cmsKey: {
    privateKey: alice_privkey_pem,
    password: password,
    certificate: alice_cert_pem,
  },
  certificates: [alice_cert_pem],
  // crls: [
  // alice_crl_pem
  // ],
  content: content,
});
console.log("alice create signed data:");
console.log(cms_signed_data_pem);

/* bob parses cms pem and verifies it */

var cms_info = cms.parse(cms_signed_data_pem);
console.log("cms_info: ", cms_info);
```

`DigestedData` type Example:

```js
var cms_data = `
MGkGCSqGSIb3DQEHBaBcMFoCAQAwBwYFKw4DAhowNgYJKoZIhvcNAQcBoCkEJ0Nv
bnRlbnQtVHlwZTogdGV4dC9wbGFpbg0KDQpoZWxsbyB3b3JsZAQUz8wdr3rAtyPE
1SSbbjxk17TFHyY=`;
var cms = new jCastle.cms();
var cms_info = cms.parse(cms_data);
console.log("cms_info: ", cms_info);

console.log(
  "CMS DigestedData Verification 1: ",
  jCastle.CMS.verifyDigestedData(cms_info)
);

var cms_info2 = {
  contentType: "digestedData",
  content: {
    digestAlgorithm: "sha-1",
    encapContentInfo: {
      type: "data",
      content: "hello world",
    },
  },
};
var cms_data2 = cms.exportCMS(cms_info2, {
  content: "Hello world from jCastle.net\n Jacob Lee greets you!",
  format: "base64",
});
console.log(jCastle.util.lineBreak(cms_data2, 64));

var cms_info3 = cms.parse(cms_data2);
console.log("cms_info3: ", cms_info3);
```

`EnvelopedData` type example:

```js
var cms_pem = `
-----BEGIN CMS-----
MIHtBgkqhkiG9w0BBwOggd8wgdwCAQIxgZKjgY8CAQCgYQYJKoZIhvcNAQUMMFQE
QNwYPo2QkGIoljsJY765zgL/X9DV8Vt84FkndCGrNteJIqt3wmdqdXbOsu+TUgy5
Fr/mYbND5vWnspJuYkzdV30CAggAMAwGCCqGSIb3DQILBQAwDQYJYIZIAWUDBAEt
BQAEGKgbc5C/25urkAsAhTcNPJreqhE0hR+lcjCABgkqhkiG9w0BBwEwHQYJYIZI
AWUDBAECBBBIsUH2oxzBLKY/AuyrnJhJoIAEEKXwYlW4M2qrp3drmZBTznQAAAAA
-----END CMS-----`;
var password = "password";
var plaintext = "hello world";
var algo_expected = "aes-128";
var mode_expected = "cbc";
var cms = new jCastle.cms();
var cms_info = cms.parse(cms_pem, {
  cmsKey: {
    password: password,
  },
});
console.log("cms_info: ", cms_info);

var cms_info = {
  contentType: "envelopedData",
  content: {
    version: 2,
    recipientInfos: [
      {
        type: "passwordRecipientInfo",
        keyDerivationAlgorithm: {
          prfHash: "sha-512",
        },
        keyEncryptionAlgorithm: "aes-256",
      },
    ],
    encryptedContentInfo: {
      contentEncryptionAlgorithm: {
        algo: "aes-128-CBC",
      },
    },
  },
};
var cms_data = cms.exportCMS(cms_info, {
  format: "pem",
  cmsKey: {
    password: password,
  },
  content: plaintext,
});
console.log("cms_data: ", cms_data);

var cms_info2 = cms.parse(cms_data, {
  cmsKey: {
    password: password,
  },
});
console.log("cms_info2: ", cms_info2);
```

### jose

`jCastle.jose` is the implementation of Javascript Object Signing & Encryption. It includes `JWS` (JSON Web Signature) and `JWE`(JSON Web Encryption).

For `JWS` , simple usage is like:

```js
var jws = new jCastle.jose();
var jwt = jws.sign(...);
var v = jws.verify(...);
```

or you can use `jCastle.jose.jws.sign()` and `jCastle.jose.jws.verify()`.

`JWS` Example:

```js
var rsa_pub_jwk = {
  kty: "RSA",
  kid: "bilbo.baggins@hobbiton.example",
  use: "sig",
  n: `n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT
		-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqV
		wGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-
		oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde
		3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuC
		LqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5g
		HdrNP5zw`,
  e: "AQAB",
};
var rsa_priv_jwk = {
  kty: "RSA",
  kid: "bilbo.baggins@hobbiton.example",
  use: "sig",
  n: `n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT
		-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqV
		wGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-
		oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde
		3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuC
		LqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5g
		HdrNP5zw`,
  e: "AQAB",
  d: `bWUC9B-EFRIo8kpGfh0ZuyGPvMNKvYWNtB_ikiH9k20eT-O1q_I78e
		iZkpXxXQ0UTEs2LsNRS-8uJbvQ-A1irkwMSMkK1J3XTGgdrhCku9gRld
		Y7sNA_AKZGh-Q661_42rINLRCe8W-nZ34ui_qOfkLnK9QWDDqpaIsA-b
		MwWWSDFu2MUBYwkHTMEzLYGqOe04noqeq1hExBTHBOBdkMXiuFhUq1BU
		6l-DqEiWxqg82sXt2h-LMnT3046AOYJoRioz75tSUQfGCshWTBnP5uDj
		d18kKhyv07lhfSJdrPdM5Plyl21hsFf4L_mHCuoFau7gdsPfHPxxjVOc
		OpBrQzwQ`,
  p: `3Slxg_DwTXJcb6095RoXygQCAZ5RnAvZlno1yhHtnUex_fp7AZ_9nR
		aO7HX_-SFfGQeutao2TDjDAWU4Vupk8rw9JR0AzZ0N2fvuIAmr_WCsmG
		peNqQnev1T7IyEsnh8UMt-n5CafhkikzhEsrmndH6LxOrvRJlsPp6Zv8
		bUq0k`,
  q: `uKE2dh-cTf6ERF4k4e_jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT
		8bR_cu0Dm1MZwWmtdqDyI95HrUeq3MP15vMMON8lHTeZu2lmKvwqW7an
		V5UzhM1iZ7z4yMkuUwFWoBvyY898EXvRD-hdqRxHlSqAZ192zB3pVFJ0
		s7pFc`,
  dp: `B8PVvXkvJrj2L-GYQ7v3y9r6Kw5g9SahXBwsWUzp19TVlgI-YV85q
		1NIb1rxQtD-IsXXR3-TanevuRPRt5OBOdiMGQp8pbt26gljYfKU_E9xn
		-RULHz0-ed9E9gXLKD4VGngpz-PfQ_q29pk5xWHoJp009Qf1HvChixRX
		59ehik`,
  dq: `CLDmDGduhylc9o7r84rEUVn7pzQ6PF83Y-iBZx5NT-TpnOZKF1pEr
		AMVeKzFEl41DlHHqqBLSM0W1sOFbwTxYWZDm6sI6og5iTbwQGIC3gnJK
		bi_7k_vJgGHwHxgPaX2PnvP-zyEkDERuf-ry4c_Z11Cq9AqC2yeL6kdK
		T1cYF8`,
  qi: `3PiqvXQN0zwMeE-sBvZgi289XP9XCQF3VWqPzMKnIgQp7_Tugo6-N
		ZBKCQsMf3HaEGBjTVJs_jcK8-TRXvaKe-7ZMaQj8VfBdYkssbu0NKDDh
		jJ-GtiseaDVWt7dcH0cfwxgFUHpQh7FoCrjFJ6h6ZEpMF6xmujs4qMpP
		z8aaI4`,
};

var payload_b64u = `
SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IH
lvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBk
b24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcm
UgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4`.replace(/[ \t\r\n]/g, "");
var payload = Buffer.from(payload_b64u, "base64url");

// compact mode
var compact_jwt = jCastle.jose.jws.sign(
  payload,
  {
    algoName: "RS256",
    key: rsa_priv_jwk,
    protectHeader: true,
  },
  {
    serialize: "compact",
  }
);
console.log("compact jwt: ");
console.log(compact_jwt);

var v = jCastle.jose.jws.verify(compact_jwt, {
  key: rsa_pub_jwk,
});
console.log(v);

// geneneral mode
var jwt = jCastle.jose.jws.sign(
  payload,
  {
    algoName: "RS256",
    key: rsa_priv_jwk,
    protectHeader: true,
  },
  {
    serialize: "general",
  }
);
console.log(jwt);

var v = jCastle.jose.jws.verify(jwt, {
  key: rsa_pub_jwk,
});
```

For `JWE` , a similiar syntax is used lik `JWS`.

```js
var jwe = new jCastle.jose();
var jwt = jwe.encrypt(...);
var pt = jwt.decrypt(...);
```

You can use `jCastle.jose.jwe.encrypt()` and `jCastle.jose.jwe.decrypt()` also.

`JWE` Example:

```js
var plaintext = `You can trust us to stick with you through thick and
thin–to the bitter end. And you can trust us to
keep any secret of yours–closer than you keep it
yourself. But you cannot trust us to let you face trouble
alone, and go off without a word. We are your friends, Frodo.`.replace(
  /\n/g,
  " "
);
var rsa_priv_jwk = {
  kty: "RSA",
  kid: "frodo.baggins@hobbiton.example",
  use: "enc",
  n: `maxhbsmBtdQ3CNrKvprUE6n9lYcregDMLYNeTAWcLj8NnPU9XIYegT
		HVHQjxKDSHP2l-F5jS7sppG1wgdAqZyhnWvXhYNvcM7RfgKxqNx_xAHx
		6f3yy7s-M9PSNCwPC2lh6UAkR4I00EhV9lrypM9Pi4lBUop9t5fS9W5U
		NwaAllhrd-osQGPjIeI1deHTwx-ZTHu3C60Pu_LJIl6hKn9wbwaUmA4c
		R5Bd2pgbaY7ASgsjCUbtYJaNIHSoHXprUdJZKUMAzV0WOKPfA6OPI4oy
		pBadjvMZ4ZAj3BnXaSYsEZhaueTXvZB4eZOAjIyh2e_VOIKVMsnDrJYA
		VotGlvMQ`,
  e: "AQAB",
  d: `Kn9tgoHfiTVi8uPu5b9TnwyHwG5dK6RE0uFdlpCGnJN7ZEi963R7wy
		bQ1PLAHmpIbNTztfrheoAniRV1NCIqXaW_qS461xiDTp4ntEPnqcKsyO
		5jMAji7-CL8vhpYYowNFvIesgMoVaPRYMYT9TW63hNM0aWs7USZ_hLg6
		Oe1mY0vHTI3FucjSM86Nff4oIENt43r2fspgEPGRrdE6fpLc9Oaq-qeP
		1GFULimrRdndm-P8q8kvN3KHlNAtEgrQAgTTgz80S-3VD0FgWfgnb1PN
		miuPUxO8OpI9KDIfu_acc6fg14nsNaJqXe6RESvhGPH2afjHqSy_Fd2v
		pzj85bQQ`,
  p: `2DwQmZ43FoTnQ8IkUj3BmKRf5Eh2mizZA5xEJ2MinUE3sdTYKSLtaE
		oekX9vbBZuWxHdVhM6UnKCJ_2iNk8Z0ayLYHL0_G21aXf9-unynEpUsH
		7HHTklLpYAzOOx1ZgVljoxAdWNn3hiEFrjZLZGS7lOH-a3QQlDDQoJOJ
		2VFmU`,
  q: `te8LY4-W7IyaqH1ExujjMqkTAlTeRbv0VLQnfLY2xINnrWdwiQ93_V
		F099aP1ESeLja2nw-6iKIe-qT7mtCPozKfVtUYfz5HrJ_XY2kfexJINb
		9lhZHMv5p1skZpeIS-GPHCC6gRlKo1q-idn_qxyusfWv7WAxlSVfQfk8
		d6Et0`,
  dp: `UfYKcL_or492vVc0PzwLSplbg4L3-Z5wL48mwiswbpzOyIgd2xHTH
		QmjJpFAIZ8q-zf9RmgJXkDrFs9rkdxPtAsL1WYdeCT5c125Fkdg317JV
		RDo1inX7x2Kdh8ERCreW8_4zXItuTl_KiXZNU5lvMQjWbIw2eTx1lpsf
		lo0rYU`,
  dq: `iEgcO-QfpepdH8FWd7mUFyrXdnOkXJBCogChY6YKuIHGc_p8Le9Mb
		pFKESzEaLlN1Ehf3B6oGBl5Iz_ayUlZj2IoQZ82znoUrpa9fVYNot87A
		CfzIG7q9Mv7RiPAderZi03tkVXAdaBau_9vs5rS-7HMtxkVrxSUvJY14
		TkXlHE`,
  qi: `kC-lzZOqoFaZCr5l0tOVtREKoVqaAYhQiqIRGL-MzS4sCmRkxm5vZ
		lXYx6RtE1n_AagjqajlkjieGlxTTThHD8Iga6foGBMaAr5uR1hGQpSc7
		Gl7CF1DZkBJMTQN6EshYzZfxW08mIO8M6Rzuh0beL6fG9mkDcIyPrBXx
		2bQ_mM`,
};
var cek_b64u = "3qyTVhIWt5juqZUCpfRqpvauwB956MEJL2Rt-8qXKSo";
var iv_b64u = "bbd5sTkYwhAIqfHsx8DayA";

// compact mode
var compact_jwe = jCastle.jose.jwe.encrypt(
  plaintext,
  {
    algoName: "RSA1_5",
    key: rsa_priv_jwk,
  },
  {
    algoName: "A128CBC-HS256",
    key: Buffer.from(cek_b64u, "base64url"),
    iv: Buffer.from(iv_b64u, "base64url"),
  },
  {
    serialize: "compact",
  }
);
console.log(compact_jwe);

var v = jCastle.jose.jwe.decrypt(compact_jwe, {
  algoName: "RSA1_5",
  key: rsa_priv_jwk,
});
console.log(v.toString() == plaintext);

var jwe = `
eyJhbGciOiJSU0ExXzUiLCJraWQiOiJmcm9kby5iYWdnaW5zQGhvYmJpdG9uLm
V4YW1wbGUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0
.
laLxI0j-nLH-_BgLOXMozKxmy9gffy2gTdvqzfTihJBuuzxg0V7yk1WClnQePF
vG2K-pvSlWc9BRIazDrn50RcRai__3TDON395H3c62tIouJJ4XaRvYHFjZTZ2G
Xfz8YAImcc91Tfk0WXC2F5Xbb71ClQ1DDH151tlpH77f2ff7xiSxh9oSewYrcG
TSLUeeCt36r1Kt3OSj7EyBQXoZlN7IxbyhMAfgIe7Mv1rOTOI5I8NQqeXXW8Vl
zNmoxaGMny3YnGir5Wf6Qt2nBq4qDaPdnaAuuGUGEecelIO1wx1BpyIfgvfjOh
MBs9M8XL223Fg47xlGsMXdfuY-4jaqVw
.
bbd5sTkYwhAIqfHsx8DayA
.
0fys_TY_na7f8dwSfXLiYdHaA2DxUjD67ieF7fcVbIR62JhJvGZ4_FNVSiGc_r
aa0HnLQ6s1P2sv3Xzl1p1l_o5wR_RsSzrS8Z-wnI3Jvo0mkpEEnlDmZvDu_k8O
WzJv7eZVEqiWKdyVzFhPpiyQU28GLOpRc2VbVbK4dQKPdNTjPPEmRqcaGeTWZV
yeSUvf5k59yJZxRuSvWFf6KrNtmRdZ8R4mDOjHSrM_s8uwIFcqt4r5GX8TKaI0
zT5CbL5Qlw3sRc7u_hg0yKVOiRytEAEs3vZkcfLkP6nbXdC_PkMdNS-ohP78T2
O6_7uInMGhFeX4ctHG7VelHGiT93JfWDEQi5_V9UN1rhXNrYu-0fVMkZAKX3VW
i7lzA6BP430m
.
kvKuFBXHe5mQr4lqgobAUg`.replace(/[ \t\r\n]/g, "");
var v = jCastle.jose.jwe.decrypt(jwe, {
  algoName: "RSA1_5",
  key: rsa_priv_jwk,
});
console.log(v.toString() == plaintext);

// general mode
var general_jwe = jCastle.jose.jwe.encrypt(
  plaintext,
  {
    algoName: "RSA1_5",
    key: rsa_priv_jwk,
  },
  {
    algoName: "A128CBC-HS256",
    key: Buffer.from(cek_b64u, "base64url"),
    iv: Buffer.from(iv_b64u, "base64url"),
  },
  {
    serialize: "general",
    protectHeader: true,
  }
);
console.log(general_jwe);
```

### prng/secureRandom

`jCastle.prng` is the Psudo Random Number Generator(PRNG), `jCastle.secureRandom` is the alias for `jCastle.prng` with `sha-1` hash algorithm used. It acceps `seed` and `hashAlgo` and generates random byte(s). Default `hashAlgo` is `ARC4`. It returns byte(s) in `buffer`.

```js
var bytes = jCastle.prng().nextBytes(16);
var bytes2 = jCastle.prng(Date.now(), "sha-1");
```

## Contact

- Webpage: http://jCastle.net
- Email: letsgolee@naver.com

## Donations & Licenses Purchasing

Financial support is always welcome and helps contribute to futher development.
