/**
 * jCastle, The Pure Javascript Crypto Library 
 * 
 * @author Jacob Lee
 *
 * Copyright (C) 2015-2022 Jacob Lee.
 */

const jCastle = require('./jCastle');
const BigInteger = require('./biginteger');
const UINT64 = require('./uint64');
const UINT32 = require('./uint32');
const INT64 = require('./int64');

require('./util');

require('./lang/en');
require('./lang/ko');
require('./error');

require('./prng');

require('./algorithms/aes-fast');
require('./algorithms/seed-openssl');
require('./algorithms/rijndael');
require('./algorithms/chacha20');
require('./algorithms/gost');
require('./algorithms/blowfish');
require('./algorithms/vmpc');
require('./algorithms/vmpcr');
require('./algorithms/cast');
require('./algorithms/rc2');
require('./algorithms/rc4');
require('./algorithms/rc5');
require('./algorithms/rc6');
require('./algorithms/twofish');
require('./algorithms/threefish');
require('./algorithms/des');
require('./algorithms/serpent');
require('./algorithms/skipjack');
require('./algorithms/clefia');
require('./algorithms/hight');
require('./algorithms/idea');
require('./algorithms/safer');
require('./algorithms/saferplus');
require('./algorithms/rabbit');
require('./algorithms/lea');
require('./algorithms/xtea');
require('./algorithms/anubis');
require('./algorithms/aria');
require('./algorithms/camellia');

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


require('./mcrypt');
require('./mcrypt-mode');
require('./mcrypt-padding');
require('./mac');
require('./mac-mode');

require('./digest');
require('./hmac');

require('./keywrap');
require('./kdf');

require('./asn1');
require('./oid');
require('./oid-kr');


require('./pbe');
require('./pki');
require('./rsa');
require('./rsa-padding');
require('./dsa');
require('./dsa-parameters');
require('./dsa-nist-parameters');
require('./ec');
require('./ecdsa');
require('./ec-parameters');
require('./kcdsa');
require('./kcdsa-parameters');
require('./kcdsa-kisa-parameters');
require('./eckcdsa');
require('./elgamal');

require('./dh');
require('./ecdh');

require('./cert-config');
require('./certificate');

require('./jose');
require('./pfx');
require('./cms');

jCastle.math.bigInteger = BigInteger;
jCastle.math.uint32 = UINT32;
jCastle.math.uint64 = UINT64;
jCastle.math.int64 = INT64;

module.exports = jCastle;