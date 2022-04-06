
const QUnit = require('qunit');
const jCastle = require('../lib/index');


//
// ECB, CBC, CFB, OFB, CTR test vectors got from here:
// http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
//


QUnit.module('AES-ECB');
QUnit.test("Vector Test", function(assert) {

    //
    //ECB-AES-128. Encrypt / Decrypt
    //
        var key = "2b7e151628aed2a6abf7158809cf4f3c";
        var testVectors = [
            [
                "6bc1bee22e409f96e93d7e117393172a",
                "3ad77bb40d7a3660a89ecaf32466ef97"
            ],
            [
                "ae2d8a571e03ac9c9eb76fac45af8e51",
                "f5d3d58503b9699de785895a96fdbaaf"
            ],
            [
                "30c81c46a35ce411e5fbc1191a0a52ef",
                "43b1cd7f598ece23881b00e3ed030688"
            ],
            [	
                "f69f2445df4f9b17ad2b417be66c3710",
                "7b0c785e27e8ad3f8223207104725dd4"
            ]
        ];
    
        key = Buffer.from(key, 'hex');
    
        var algorithm = new jCastle.algorithm.rijndael('rijndael');
        
        var is_enc = true;
        
        var encrypted = [];
        
        algorithm.keySchedule(key, is_enc);
    
        var ecbMode = jCastle.mcrypt.mode.create('ecb');
    
        // encrypt
    
        ecbMode.init(algorithm, {
            blockSize: 16,
            isEncryption: is_enc
        });
    
        for (var i = 0; i < testVectors.length; i++) {
            var vector = testVectors[i];
            var pt = Buffer.from(vector[0], 'hex');
            var ct = ecbMode.process(pt);
            var expected = Buffer.from(vector[1], 'hex');
    
            assert.ok(ct.equals(expected) , "Encryption passed!");
        }
    
        // decrypt and check
    
        is_enc = false;
        algorithm.keySchedule(key, is_enc);
    
        ecbMode.init(algorithm, {
            blockSize: 16,
            isEncryption: is_enc
        });
    
        for (var i = 0; i < testVectors.length; i++) {
            var vector = testVectors[i];
            var expected = Buffer.from(vector[0], 'hex');
            var ct = Buffer.from(vector[1], 'hex');
    
            var dt = ecbMode.process(ct);
    
            assert.ok(dt.equals(expected), "Decryption passed!");
        }
    
    //
    // ECB-AES-192. Encrypt / Decrypt
    //
        var key = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
        var testVectors = [
            [
                "6bc1bee22e409f96e93d7e117393172a",
                "bd334f1d6e45f25ff712a214571fa5cc"
            ],
            [
                "ae2d8a571e03ac9c9eb76fac45af8e51",
                "974104846d0ad3ad7734ecb3ecee4eef"
            ],
            [
                "30c81c46a35ce411e5fbc1191a0a52ef",
                "ef7afd2270e2e60adce0ba2face6444e"
            ],
            [
                "f69f2445df4f9b17ad2b417be66c3710",
                "9a4b41ba738d6c72fb16691603c18e0e"
            ]
        ];
                
        key = Buffer.from(key, 'hex');
    
        var algorithm = new jCastle.algorithm.rijndael('rijndael');
        
        var is_enc = true;
        
        algorithm.keySchedule(key, is_enc);
    
        var ecbMode = jCastle.mcrypt.mode.create('ecb');
    
        // encrypt
    
        ecbMode.init(algorithm, {
            blockSize: 16,
            isEncryption: is_enc
        });
    
        for (var i = 0; i < testVectors.length; i++) {
            var vector = testVectors[i];
            var pt = Buffer.from(vector[0], 'hex');
            var ct = ecbMode.process(pt);
            var expected = Buffer.from(vector[1], 'hex');
    
            assert.ok(ct.equals(expected) , "Encryption passed!");
        }
    
        // decrypt and check
    
        is_enc = false;
        algorithm.keySchedule(key, is_enc);
    
        ecbMode.init(algorithm, {
            blockSize: 16,
            isEncryption: is_enc
        });
    
        for (var i = 0; i < testVectors.length; i++) {
            var vector = testVectors[i];
            var expected = Buffer.from(vector[0], 'hex');
            var ct = Buffer.from(vector[1], 'hex');
    
            var dt = ecbMode.process(ct);
    
            assert.ok(dt.equals(expected), "Decryption passed!");
        }
    
    //
    // ECB-AES-256. Encrypt / Decrypt
    //
        var key = "603deb1015ca71be2b73aef0857d7781"+
                  "1f352c073b6108d72d9810a30914dff4";
        var testVectors = [
            [
                "6bc1bee22e409f96e93d7e117393172a",
                "f3eed1bdb5d2a03c064b5a7e3db181f8"
            ],
            [
                "ae2d8a571e03ac9c9eb76fac45af8e51",
                "591ccb10d410ed26dc5ba74a31362870"
            ],
            [
                "30c81c46a35ce411e5fbc1191a0a52ef",
                "b6ed21b99ca6f4f9f153e7b1beafed1d"
            ],
            [
                "f69f2445df4f9b17ad2b417be66c3710",
                "23304b7a39f9f3ff067d8d8f9e24ecc7"
            ]
        ];
    
        key = Buffer.from(key, 'hex');
    
        var algorithm = new jCastle.algorithm.rijndael('rijndael');
        
        var is_enc = true;
    
        var ecbMode = jCastle.mcrypt.mode.create('ecb');
    
        // encrypt
    
        algorithm.keySchedule(key, is_enc);
        
        ecbMode.init(algorithm, {
            blockSize: 16,
            isEncryption: is_enc
        });
    
        for (var i = 0; i < testVectors.length; i++) {
            var vector = testVectors[i];
            var pt = Buffer.from(vector[0], 'hex');
            var ct = ecbMode.process(pt);
            var expected = Buffer.from(vector[1], 'hex');
    
            assert.ok(ct.equals(expected) , "Encryption passed!");
        }
    
        // decrypt and check
        
        is_enc = false;
        
        algorithm.keySchedule(key, is_enc);
    
        ecbMode.init(algorithm, {
            blockSize: 16,
            isEncryption: is_enc
        });
    
        for (var i = 0; i < testVectors.length; i++) {
            var vector = testVectors[i];
            var expected = Buffer.from(vector[0], 'hex');
            var ct = Buffer.from(vector[1], 'hex');
    
            var dt = ecbMode.process(ct);
    
            assert.ok(dt.equals(expected), "Decryption passed!");
        }
    });

    QUnit.module('AES-CBC');        
    QUnit.test("Vector Test", function(assert) {
    //
    // CBC-AES-128. Encrypt / Decrypt
    //
        var key = "2b7e151628aed2a6abf7158809cf4f3c";
        var iv = "000102030405060708090a0b0c0d0e0f";
        var testVectors = [
            [
                "6bc1bee22e409f96e93d7e117393172a", // pt
                "7649abac8119b246cee98e9b12e9197d"  // ct
            ],
            [
                "ae2d8a571e03ac9c9eb76fac45af8e51",
                "5086cb9b507219ee95db113a917678b2"
            ],
            [
                "30c81c46a35ce411e5fbc1191a0a52ef",
                "73bed6b8e3c1743b7116e69e22229516"
            ],
            [
                "f69f2445df4f9b17ad2b417be66c3710",
                "3ff1caa1681fac09120eca307586e1a7"
            ]
        ];
    
        key = Buffer.from(key, 'hex');
        iv = Buffer.from(iv, 'hex');
    
        var algorithm = new jCastle.algorithm.rijndael('rijndael');
        
        var is_enc = true;
        algorithm.keySchedule(key, is_enc);
    
        var cbcMode = jCastle.mcrypt.mode.create('cbc');
    
        encrypted = [];
        
        // encrypt
    
        cbcMode.init(algorithm, {
            iv: iv,
            blockSize: 16,
            isEncryption: is_enc
        });
    
        for (var i = 0; i < testVectors.length; i++) {
            var vector = testVectors[i];
            var pt = Buffer.from(vector[0], 'hex');
    
            var ct = cbcMode.process(pt);
    
            encrypted.push(ct);
        }
    
        // decrypt and check
        
        is_enc = false;
        algorithm.keySchedule(key, is_enc);
    
        cbcMode.init(algorithm, {
            iv: iv,
            blockSize: 16,
            isEncryption: is_enc
        });
    
        for (var i = 0; i < testVectors.length; i++) {
            var vector = testVectors[i];
            var pt = Buffer.from(vector[0], 'hex');
            var ct = Buffer.from(vector[1], 'hex');
    
            // check encrypted...
            assert.ok(encrypted[i].equals(ct) , "Encryption passed!");
    
            var dt = cbcMode.process(ct);
    
            assert.ok(dt.equals(pt), "Decryption passed!");
        }
    
    
    //
    // CBC-AES-192. Encrypt / Decrypt
    //
        var key = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
        var iv = "000102030405060708090a0b0c0d0e0f";
        var testVectors = [
            [
                "6bc1bee22e409f96e93d7e117393172a",
                "4f021db243bc633d7178183a9fa071e8"
            ],
            [
                "ae2d8a571e03ac9c9eb76fac45af8e51",
                "b4d9ada9ad7dedf4e5e738763f69145a"
            ],
            [
                "30c81c46a35ce411e5fbc1191a0a52ef",
                "571b242012fb7ae07fa9baac3df102e0"
            ],
            [
                "f69f2445df4f9b17ad2b417be66c3710",
                "08b0e27988598881d920a9e64f5615cd"
            ]
        ];
    
        key = Buffer.from(key, 'hex');
        iv = Buffer.from(iv, 'hex');
    
        var algorithm = new jCastle.algorithm.rijndael('rijndael');
        
        var is_enc = true;
        algorithm.keySchedule(key, is_enc);
    
        var cbcMode = jCastle.mcrypt.mode.create('cbc');
    
        encrypted = [];
        
        // encrypt
    
        cbcMode.init(algorithm, {
            iv: iv,
            blockSize: 16,
            isEncryption: is_enc
        });
    
        for (var i = 0; i < testVectors.length; i++) {
            var vector = testVectors[i];
            var pt = Buffer.from(vector[0], 'hex');
    
            var ct = cbcMode.process(pt);
    
            encrypted.push(ct);
        }
    
        // decrypt and check
        
        is_enc = false;
        algorithm.keySchedule(key, is_enc);
    
        cbcMode.init(algorithm, {
            iv: iv,
            blockSize: 16,
            isEncryption: is_enc
        });
    
        for (var i = 0; i < testVectors.length; i++) {
            var vector = testVectors[i];
            var pt = Buffer.from(vector[0], 'hex');
            var ct = Buffer.from(vector[1], 'hex');
    
            // check encrypted...
            assert.ok(encrypted[i].equals(ct) , "Encryption passed!");
    
            var dt = cbcMode.process(ct);
    
            assert.ok(dt.equals(pt), "Decryption passed!");
        }
        
    //
    // CBC-AES-256. Encrypt / Decrypt
    //
        var key = "603deb1015ca71be2b73aef0857d7781"+
                  "1f352c073b6108d72d9810a30914dff4";
        var iv = "000102030405060708090a0b0c0d0e0f";
        var testVectors = [
            [
                "6bc1bee22e409f96e93d7e117393172a",
                "f58c4c04d6e5f1ba779eabfb5f7bfbd6"
            ],
            [
                "ae2d8a571e03ac9c9eb76fac45af8e51",
                "9cfc4e967edb808d679f777bc6702c7d"
            ],
            [	"30c81c46a35ce411e5fbc1191a0a52ef",
                "39f23369a9d9bacfa530e26304231461"
            ],
            [
                "f69f2445df4f9b17ad2b417be66c3710",
                "b2eb05e2c39be9fcda6c19078c6a9d1b"
            ]
        ];
    
        key = Buffer.from(key, 'hex');
        iv = Buffer.from(iv, 'hex');
    
        //var algorithm = new jCastle.algorithm.rijndael('rijndael');
        var algorithm = new jCastle.algorithm.aes('aes-128');
        
        var is_enc = true;
        algorithm.keySchedule(key, is_enc);
    
        var cbcMode = jCastle.mcrypt.mode.create('cbc');
    
        encrypted = [];
        
        // encrypt
    
        cbcMode.init(algorithm, {
            iv: iv,
            blockSize: 16,
            isEncryption: is_enc
        });
    
        for (var i = 0; i < testVectors.length; i++) {
            var vector = testVectors[i];
            var pt = Buffer.from(vector[0], 'hex');
    
            var ct = cbcMode.process(pt);
    
            encrypted.push(ct);
        }
    
        // decrypt and check
        
        is_enc = false;
        algorithm.keySchedule(key, is_enc);
    
        cbcMode.init(algorithm, {
            iv: iv,
            blockSize: 16,
            isEncryption: is_enc
        });
    
        for (var i = 0; i < testVectors.length; i++) {
            var vector = testVectors[i];
            var pt = Buffer.from(vector[0], 'hex');
            var ct = Buffer.from(vector[1], 'hex');
    
            // check encrypted...
            assert.ok(encrypted[i].equals(ct) , "Encryption passed!");
    
            var dt = cbcMode.process(ct);
    
            assert.ok(dt.equals(pt), "Decryption passed!");
        }
    });
    
    QUnit.module('AES-CFB');
    QUnit.test("Vector Test", function(assert) {
    
        var key = "2b7e151628aed2a6abf7158809cf4f3c";
        var iv = "000102030405060708090a0b0c0d0e0f";
    
        var testVectors = [
            [
                "6bc1bee22e409f96e93d7e117393172a",
                "3b79424c9c0dd436bace9e0ed4586a4f"
            ],
            [
                "ae2d8a571e03ac9c9eb76fac45af8e51",
                "fed65b2a0a203b682640f5ca09a2d410"
            ],
            [
                "30c81c46a35ce411e5fbc1191a0a52ef",
                "60dc808f45cee759327f8ff1b899f29b"
            ],
            [
                "f69f2445df4f9b17ad2b417be66c3710",
                "a628b00b5c630691a08a992332765451"
            ]
        ];
    
        key = Buffer.from(key, 'hex');
        iv = Buffer.from(iv, 'hex');
    
        //var algorithm = new jCastle.algorithm.rijndael('rijndael');
        var algorithm = new jCastle.algorithm.aes('aes-128');
    
        var cfbMode = jCastle.mcrypt.mode.create('cfb');
    
        for (var i = 0; i < testVectors.length; i++) {
            var vector = testVectors[i];
    
            // encrypt
            algorithm.keySchedule(key, true);
            
            cfbMode.init(algorithm, {
                iv: iv,
                blockSize: 16,
                isEncryption: true
            });
            var pt = Buffer.from(vector[0], 'hex');
            var expected = Buffer.from(vector[1], 'hex');
            var ct = cfbMode.process(pt);
            
            algorithm.keySchedule(key, false);
    
            // decrypt
            cfbMode.init(algorithm, {
                iv: iv,
                blockSize: 16,
                isEncryption: false
            });
            var dt = cfbMode.process(ct);
    
            assert.ok(ct.equals(expected), 'Encryptions Passed!');
    
            assert.ok(dt.equals(pt), 'Decryption Passed!');
        }
    
    });
    
    QUnit.module('AES-OFB');
    QUnit.test("Vector Test", function(assert) {
    
        var key = "2b7e151628aed2a6abf7158809cf4f3c";
        var iv = "000102030405060708090a0b0c0d0e0f";
    
        var testVectors = [
            [
                "6bc1bee22e409f96e93d7e117393172a",
                "3b95b11c62c9b759f605bbce1812c67c"
            ],
            [
                "ae2d8a571e03ac9c9eb76fac45af8e51",
                "fe7985a9528a8453818faa732e2e5f07"
            ],
            [
                "30c81c46a35ce411e5fbc1191a0a52ef",
                "609c13b8efd5ccdefac304c6718b83b9"
            ],
            [
                "f69f2445df4f9b17ad2b417be66c3710",
                "a6cb2bbb93c6b3d8b21384a48dede646"
            ]
        ];
    
        key = Buffer.from(key, 'hex');
        iv = Buffer.from(iv, 'hex');
    
        //var algorithm = new jCastle.algorithm.rijndael('rijndael');
        var algorithm = new jCastle.algorithm.aes('aes-128');
        
    
        var ofbMode = jCastle.mcrypt.mode.create('ofb');
    
        for (var i = 0; i < testVectors.length; i++) {
            var vector = testVectors[i];
    
            // encrypt
            algorithm.keySchedule(key, true);
            
            ofbMode.init(algorithm, {
                iv: iv,
                blockSize: 16,
                isEncryption: true
            });
            var pt = Buffer.from(vector[0], 'hex');
            var expected = Buffer.from(vector[1], 'hex');
            var ct = ofbMode.process(pt);
            
            algorithm.keySchedule(key, false);
    
            // decrypt
            ofbMode.init(algorithm, {
                iv: iv,
                blockSize: 16,
                isEncryption: false
            });
            var dt = ofbMode.process(ct);
    
            assert.ok(ct.equals(expected), 'Encryptions Passed!');
    
            assert.ok(dt.equals(pt), 'Decryption Passed!');
        }
    
    });
    
    QUnit.module('AES-nCFB');
    QUnit.test("Vector Test", function(assert) {
    
    //
    // CFB1-AES-128.Encrypt / Decrypt
    //
        var key = "2b7e151628aed2a6abf7158809cf4f3c";
        var iv = "000102030405060708090a0b0c0d0e0f";
        var testVectors = [
            [
                "6b",
                "3b"
            ],
            [
                "c1",
                "79"
            ],
            [
                "be",
                "42"
            ],
            [
                "e2",
                "4c"
            ],
            [
                "2e",
                "9c"
            ],
            [
                "40",
                "0d"
            ],
            [
                "9f",
                "d4"
            ],
            [
                "96",
                "36"
            ],
            [
                "e9",
                "ba"
            ],
            [
                "3d",
                "ce"
            ],
            [
                "7e",
                "9e"
            ],
            [
                "11",
                "0e"
            ],
            [
                "73",
                "d4"
            ],
            [
                "93",
                "58"
            ],
            [
                "17",
                "6a"
            ],
            [
                "2a",
                "4f"
            ],
            [
                "ae",
                "32"
            ],
            [
                "2d",
                "b9"
            ]
        ];
    
        key = Buffer.from(key, 'hex');
        iv = Buffer.from(iv, 'hex');
    
        //var algorithm = new jCastle.algorithm.rijndael('rijnadel');
        var algorithm = new jCastle.algorithm.aes('aes-128');
        algorithm.keySchedule(key, true);
    
        var ncfbMode = jCastle.mcrypt.mode.create('ncfb');
        
        var encrypted = [];
    
        // encrypt
    
        ncfbMode.init(algorithm, {
            iv: iv,
            blockSize: 16,
            isEncryption: true
        });
    
        for (var i = 0; i < testVectors.length; i++) {
            var vector = testVectors[i];
            var pt = Buffer.from(vector[0], 'hex');
            var ct = ncfbMode.process(pt);
            encrypted.push(ct);
        }
    
        // decrypt and check
        
        algorithm.keySchedule(key, false);
    
        ncfbMode.init(algorithm, {
            iv: iv,
            blockSize: 16,
            isEncryption: false
        });
    
        for (var i = 0; i < testVectors.length; i++) {
            var vector = testVectors[i];
            var pt = Buffer.from(vector[0], 'hex');
            var ct = Buffer.from(vector[1], 'hex');
    
            // check encrypted...
            assert.ok(encrypted[i].equals(ct) , "Encryption passed!");
    
            var dt = ncfbMode.process(ct);
    
            assert.ok(dt.equals(pt), "Decryption passed!");
        }
    //
    // nCFB128-AES-128.Encrypt / Decrypt
    //
    
        var key = "2b7e151628aed2a6abf7158809cf4f3c";
        var iv = "000102030405060708090a0b0c0d0e0f";
        var testVectors = [
            [
                "6bc1bee22e409f96e93d7e117393172a",
                "3b3fd92eb72dad20333449f8e83cfb4a"
            ],
            [
                "ae2d8a571e03ac9c9eb76fac45af8e51",
                "c8a64537a0b3a93fcde3cdad9f1ce58b"
            ],
            [
                "30c81c46a35ce411e5fbc1191a0a52ef",
                "26751f67a3cbb140b1808cf187a4f4df"
            ],
            [
                "f69f2445df4f9b17ad2b417be66c3710",
                "c04b05357c5d1c0eeac4c66f9ff7f2e6"
            ]
        ];
    
        key = Buffer.from(key, 'hex');
        iv = Buffer.from(iv, 'hex');
    
        //var algorithm = new jCastle.algorithm.rijndael('rijndael');
        var algorithm = new jCastle.algorithm.aes('aes-128');
        algorithm.keySchedule(key, true);
    
        var ncfbMode = jCastle.mcrypt.mode.create('ncfb');
        
        var encrypted = [];
    
        // encrypt
    
        ncfbMode.init(algorithm, {
            iv: iv,
            blockSize: 16,
            isEncryption: true
        });
    
        for (var i = 0; i < testVectors.length; i++) {
            var vector = testVectors[i];
            var pt = Buffer.from(vector[0], 'hex');
            var ct = ncfbMode.process(pt);
            encrypted.push(ct);
        }
    
        // decrypt and check
        
        algorithm.keySchedule(key, false);
    
        ncfbMode.init(algorithm, {
            iv: iv,
            blockSize: 16,
            isEncryption: false
        });
    
        for (var i = 0; i < testVectors.length; i++) {
            var vector = testVectors[i];
            var pt = Buffer.from(vector[0], 'hex');
            var ct = Buffer.from(vector[1], 'hex');
    
            // check encrypted...
            assert.ok(encrypted[i].equals(ct) , "Encryption passed!");
    
            var dt = ncfbMode.process(ct);
    
            assert.ok(dt.equals(pt), "Decryption passed!");
        }
    
    //
    // nCFB128-AES-192.Encrypt / Decrypt
    //
        var key = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
        var iv = "000102030405060708090a0b0c0d0e0f";
        var testVectors = [
            [
                "6bc1bee22e409f96e93d7e117393172a",
                "cdc80d6fddf18cab34c25909c99a4174"
            ],
            [
                "ae2d8a571e03ac9c9eb76fac45af8e51",
                "67ce7f7f81173621961a2b70171d3d7a"
            ],
            [
                "30c81c46a35ce411e5fbc1191a0a52ef",
                "2e1e8a1dd59b88b1c8e60fed1efac4c9"
            ],
            [
                "f69f2445df4f9b17ad2b417be66c3710",
                "c05f9f9ca9834fa042ae8fba584b09ff"
            ]
        ];
    
        key = Buffer.from(key, 'hex');
        iv = Buffer.from(iv, 'hex');
    
        var algorithm = new jCastle.algorithm.rijndael('rijndael');
        algorithm.keySchedule(key, true);
    
        var ncfbMode = jCastle.mcrypt.mode.create('ncfb');
        
        var encrypted = [];
    
        // encrypt
    
        ncfbMode.init(algorithm, {
            iv: iv,
            blockSize: 16,
            isEncryption: true
        });
    
        for (var i = 0; i < testVectors.length; i++) {
            var vector = testVectors[i];
            var pt = Buffer.from(vector[0], 'hex');
            var ct = ncfbMode.process(pt);
            encrypted.push(ct);
        }
    
        // decrypt and check
        
        algorithm.keySchedule(key, false);
    
        ncfbMode.init(algorithm, {
            iv: iv,
            blockSize: 16,
            isEncryption: false
        });
    
        for (var i = 0; i < testVectors.length; i++) {
            var vector = testVectors[i];
            var pt = Buffer.from(vector[0], 'hex');
            var ct = Buffer.from(vector[1], 'hex');
    
            // check encrypted...
            assert.ok(encrypted[i].equals(ct) , "Encryption passed!");
    
            var dt = ncfbMode.process(ct);
    
            assert.ok(dt.equals(pt), "Decryption passed!");
        }
    
    //
    // nCFB128-AES-256.Encrypt / Decrypt
    //
        var key = "603deb1015ca71be2b73aef0857d7781"+
                  "1f352c073b6108d72d9810a30914dff4";
        var iv = "000102030405060708090a0b0c0d0e0f";
        var testVectors = [
            [
                "6bc1bee22e409f96e93d7e117393172a",
                "dc7e84bfda79164b7ecd8486985d3860"
            ],
            [
                "ae2d8a571e03ac9c9eb76fac45af8e51",
                "39ffed143b28b1c832113c6331e5407b"
            ],
            [
                "30c81c46a35ce411e5fbc1191a0a52ef",
                "df10132415e54b92a13ed0a8267ae2f9"
            ],
            [
                "f69f2445df4f9b17ad2b417be66c3710",
                "75a385741ab9cef82031623d55b1e471"
            ]
        ];
    
        key = Buffer.from(key, 'hex');
        iv = Buffer.from(iv, 'hex');
    
        var algorithm = new jCastle.algorithm.rijndael('rijndael');
        algorithm.keySchedule(key, true);
    
        var ncfbMode = jCastle.mcrypt.mode.create('ncfb');
        
        var encrypted = [];
    
        // encrypt
    
        ncfbMode.init(algorithm, {
            iv: iv,
            blockSize: 16,
            isEncryption: true
        });
    
        for (var i = 0; i < testVectors.length; i++) {
            var vector = testVectors[i];
            var pt = Buffer.from(vector[0], 'hex');
            var ct = ncfbMode.process(pt);
            encrypted.push(ct);
        }
    
        // decrypt and check
        
        algorithm.keySchedule(key, false);
    
        ncfbMode.init(algorithm, {
            iv: iv,
            blockSize: 16,
            isEncryption: false
        });
    
        for (var i = 0; i < testVectors.length; i++) {
            var vector = testVectors[i];
            var pt = Buffer.from(vector[0], 'hex');
            var ct = Buffer.from(vector[1], 'hex');
    
            // check encrypted...
            assert.ok(encrypted[i].equals(ct) , "Encryption passed!");
    
            var dt = ncfbMode.process(ct);
    
            assert.ok(dt.equals(pt), "Decryption passed!");
        }
    
    });
    
    QUnit.module('AES-nOFB');
    QUnit.test("Vector Test", function(assert) {
    
    //
    // nOFB-AES-128.Encrypt / Decrypt
    //
        var key = "2b7e151628aed2a6abf7158809cf4f3c";
        var iv = "000102030405060708090a0b0c0d0e0f";
        var testVectors = [
            [
                "6bc1bee22e409f96e93d7e117393172a",
                "3b3fd92eb72dad20333449f8e83cfb4a"
            ],
            [
                "ae2d8a571e03ac9c9eb76fac45af8e51",
                "7789508d16918f03f53c52dac54ed825"
            ],
            [
                "30c81c46a35ce411e5fbc1191a0a52ef",
                "9740051e9c5fecf64344f7a82260edcc"
            ],
            [
                "f69f2445df4f9b17ad2b417be66c3710",
                "304c6528f659c77866a510d9c1d6ae5e"
            ]
        ];
    
        key = Buffer.from(key, 'hex');
        iv = Buffer.from(iv, 'hex');
    
        //var algorithm = new jCastle.algorithm.rijndael('rijndael');
        var algorithm = new jCastle.algorithm.aes('aes-128');
        
        algorithm.keySchedule(key, true);
    
        var nofbMode = jCastle.mcrypt.mode.create('nofb');
        
        var encrypted = [];
    
        // encrypt
    
        nofbMode.init(algorithm, {
            iv: iv,
            blockSize: 16,
            isEncryption: true
        });
    
        for (var i = 0; i < testVectors.length; i++) {
            var vector = testVectors[i];
            var pt = Buffer.from(vector[0], 'hex');
            var ct = nofbMode.process(pt);
    
            encrypted.push(ct);
        }
    
        // decrypt and check
        
        algorithm.keySchedule(key, false);
    
        nofbMode.init(algorithm, {
            iv: iv,
            blockSize: 16,
            isEncryption: false
        });
    
        for (var i = 0; i < testVectors.length; i++) {
            var vector = testVectors[i];
            var pt = Buffer.from(vector[0], 'hex');
            var ct = Buffer.from(vector[1], 'hex');
    
            // check encrypted...
            assert.ok(encrypted[i].equals(ct) , "Encryption passed!");
    
            var dt = nofbMode.process(ct);
    
            assert.ok(dt.equals(pt), "Decryption passed!");
        }
    
    
    //
    // nOFB-AES-192.Encrypt / Decrypt
    //
    
        var key = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
        var iv = "000102030405060708090a0b0c0d0e0f";
        var testVectors = [
            [
                "6bc1bee22e409f96e93d7e117393172a",
                "cdc80d6fddf18cab34c25909c99a4174"
            ],
            [
                "ae2d8a571e03ac9c9eb76fac45af8e51",
                "fcc28b8d4c63837c09e81700c1100401"
            ],
            [
                "30c81c46a35ce411e5fbc1191a0a52ef",
                "8d9a9aeac0f6596f559c6d4daf59a5f2"
            ],
            [
                "f69f2445df4f9b17ad2b417be66c3710",
                "6d9f200857ca6c3e9cac524bd9acc92a"
            ]
        ];
    
        key = Buffer.from(key, 'hex');
        iv = Buffer.from(iv, 'hex');
    
        //var algorithm = new jCastle.algorithm.rijndael('rijndael');
        var algorithm = new jCastle.algorithm.aes('aes-128');
        
        algorithm.keySchedule(key, true);
    
        var nofbMode = jCastle.mcrypt.mode.create('nofb');
        
        var encrypted = [];
    
        // encrypt
    
        nofbMode.init(algorithm, {
            iv: iv,
            blockSize: 16,
            isEncryption: true
        });
    
        for (var i = 0; i < testVectors.length; i++) {
            var vector = testVectors[i];
            var pt = Buffer.from(vector[0], 'hex');
            var ct = nofbMode.process(pt);
    
            encrypted.push(ct);
        }
    
        // decrypt and check
        
        algorithm.keySchedule(key, false);
    
        nofbMode.init(algorithm, {
            iv: iv,
            blockSize: 16,
            isEncryption: false
        });
    
        for (var i = 0; i < testVectors.length; i++) {
            var vector = testVectors[i];
            var pt = Buffer.from(vector[0], 'hex');
            var ct = Buffer.from(vector[1], 'hex');
    
            // check encrypted...
            assert.ok(encrypted[i].equals(ct) , "Encryption passed!");
    
            var dt = nofbMode.process(ct);
    
            assert.ok(dt.equals(pt), "Decryption passed!");
        }
    
    //
    // nOFB-AES-256.Encrypt / Decrypt
    //
        var key = "603deb1015ca71be2b73aef0857d7781"+
                  "1f352c073b6108d72d9810a30914dff4";
        var iv = "000102030405060708090a0b0c0d0e0f";
        var testVectors = [
            [
                "6bc1bee22e409f96e93d7e117393172a",
                "dc7e84bfda79164b7ecd8486985d3860"
            ],
            [
                "ae2d8a571e03ac9c9eb76fac45af8e51",
                "4febdc6740d20b3ac88f6ad82a4fb08d"
            ],
            [
                "30c81c46a35ce411e5fbc1191a0a52ef",
                "71ab47a086e86eedf39d1c5bba97c408"
            ],
            [
                "f69f2445df4f9b17ad2b417be66c3710",
                "0126141d67f37be8538f5a8be740e484"
            ]
        ];
    
        key = Buffer.from(key, 'hex');
        iv = Buffer.from(iv, 'hex');
    
        //var algorithm = new jCastle.algorithm.rijndael('rijndael');
        var algorithm = new jCastle.algorithm.aes('aes-128');
        
        algorithm.keySchedule(key, true);
    
        var nofbMode = jCastle.mcrypt.mode.create('nofb');
        
        var encrypted = [];
    
        // encrypt
    
        nofbMode.init(algorithm, {
            iv: iv,
            blockSize: 16,
            isEncryption: true
        });
    
        for (var i = 0; i < testVectors.length; i++) {
            var vector = testVectors[i];
            var pt = Buffer.from(vector[0], 'hex');
            var ct = nofbMode.process(pt);
    
            encrypted.push(ct);
        }
    
        // decrypt and check
        
        algorithm.keySchedule(key, false);
    
        nofbMode.init(algorithm, {
            iv: iv,
            blockSize: 16,
            isEncryption: false
        });
    
        for (var i = 0; i < testVectors.length; i++) {
            var vector = testVectors[i];
            var pt = Buffer.from(vector[0], 'hex');
            var ct = Buffer.from(vector[1], 'hex');
    
            // check encrypted...
            assert.ok(encrypted[i].equals(ct) , "Encryption passed!");
    
            var dt = nofbMode.process(ct);
    
            assert.ok(dt.equals(pt), "Decryption passed!");
        }
    
    });
    
    
    QUnit.module('AES-CTR');
    QUnit.test("Vector Test", function(assert) {
    
    //
    // CTR-AES-128.Encrypt / Decrypt
    //
        var key = "2b7e151628aed2a6abf7158809cf4f3c";
        var iv = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"; // initial counter
    
        var testVectors = [
            [
                "6bc1bee22e409f96e93d7e117393172a",
                "874d6191b620e3261bef6864990db6ce"
            ],
            [
                "ae2d8a571e03ac9c9eb76fac45af8e51",
                "9806f66b7970fdff8617187bb9fffdff"
            ],
            [
                "30c81c46a35ce411e5fbc1191a0a52ef",
                "5ae4df3edbd5d35e5b4f09020db03eab"
            ],
            [
                "f69f2445df4f9b17ad2b417be66c3710",
                "1e031dda2fbe03d1792170a0f3009cee"
            ]
        ];
        
        //
        // Caution!!!
        //
        // CTR always uses encryption direction when ekyScheduling.
        // 
    
        key = Buffer.from(key, 'hex');
        iv = Buffer.from(iv, 'hex');
    
        //var algorithm = new jCastle.algorithm.rijndael('rijnadel');
        var algorithm = new jCastle.algorithm.aes('aes-128');
        algorithm.keySchedule(key, true);
    
        var ctrMode = jCastle.mcrypt.mode.create('ctr');
        
        var encrypted = [];
    
        // encrypt
    
        ctrMode.init(algorithm, {
            iv: iv,
            blockSize: 16,
            isEncryption: true
        });
    
        for (var i = 0; i < testVectors.length; i++) {
            var vector = testVectors[i];
            var pt = Buffer.from(vector[0], 'hex');
            var ct = ctrMode.process(pt);
    
            encrypted.push(ct);
        }
    
        // decrypt and check
        
        algorithm.keySchedule(key, false);
    
        ctrMode.init(algorithm, {
            iv: iv,
            blockSize: 16,
            isEncryption: false
        });
    
        for (var i = 0; i < testVectors.length; i++) {
            var vector = testVectors[i];
            var pt = Buffer.from(vector[0], 'hex');
            var ct = Buffer.from(vector[1], 'hex');
    
            // check encrypted...
            assert.ok(encrypted[i].equals(ct) , "Encryption passed!");
    
            var dt = ctrMode.process(ct);
    
            assert.ok(dt.equals(pt), "Decryption passed!");
        }
    
    //
    // CTR-AES-192.Encrypt / Decrypt
    //
        var key = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
        var iv = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
    
        var testVectors = [
            [
                "6bc1bee22e409f96e93d7e117393172a",
                "1abc932417521ca24f2b0459fe7e6e0b"
            ],
            [
                "ae2d8a571e03ac9c9eb76fac45af8e51",
                "090339ec0aa6faefd5ccc2c6f4ce8e94"
            ],
            [
                "30c81c46a35ce411e5fbc1191a0a52ef",
                "1e36b26bd1ebc670d1bd1d665620abf7"
            ],
            [
                "f69f2445df4f9b17ad2b417be66c3710",
                "4f78a7f6d29809585a97daec58c6b050"
            ]
        ];
    
        key = Buffer.from(key, 'hex');
        iv = Buffer.from(iv, 'hex');
    
        var algorithm = new jCastle.algorithm.rijndael('rijndael');
        algorithm.keySchedule(key, true);
    
        var ctrMode = jCastle.mcrypt.mode.create('ctr');
        
        var encrypted = [];
    
        // encrypt
    
        ctrMode.init(algorithm, {
            iv: iv,
            blockSize: 16,
            isEncryption: true
        });
    
        for (var i = 0; i < testVectors.length; i++) {
            var vector = testVectors[i];
            var pt = Buffer.from(vector[0], 'hex');
            var ct = ctrMode.process(pt);
    
            encrypted.push(ct);
        }
    
        // decrypt and check
        
        algorithm.keySchedule(key, false);
    
        ctrMode.init(algorithm, {
            iv: iv,
            blockSize: 16,
            isEncryption: false
        });
    
        for (var i = 0; i < testVectors.length; i++) {
            var vector = testVectors[i];
            var pt = Buffer.from(vector[0], 'hex');
            var ct = Buffer.from(vector[1], 'hex');
    
            // check encrypted...
            assert.ok(encrypted[i].equals(ct) , "Encryption passed!");
    
            var dt = ctrMode.process(ct);
    
            assert.ok(dt.equals(pt), "Decryption passed!");
        }
    
    //
    // CTR-AES-256.Encrypt
    //
        var key = "603deb1015ca71be2b73aef0857d7781"+
                  "1f352c073b6108d72d9810a30914dff4";
        var iv = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
    
        var testVectors = [
            [
                "6bc1bee22e409f96e93d7e117393172a",
                "601ec313775789a5b7a7f504bbf3d228"
            ],
            [
                "ae2d8a571e03ac9c9eb76fac45af8e51",
                "f443e3ca4d62b59aca84e990cacaf5c5"
            ],
            [
                "30c81c46a35ce411e5fbc1191a0a52ef",
                "2b0930daa23de94ce87017ba2d84988d"
            ],
            [
                "f69f2445df4f9b17ad2b417be66c3710",
                "dfc9c58db67aada613c2dd08457941a6"
            ]
        ];
    
        key = Buffer.from(key, 'hex');
        iv = Buffer.from(iv, 'hex');
    
        var algorithm = new jCastle.algorithm.rijndael('rijndael');
        algorithm.keySchedule(key, true);
    
        var ctrMode = jCastle.mcrypt.mode.create('ctr');
        
        var encrypted = [];
    
        // encrypt
    
        ctrMode.init(algorithm, {
            iv: iv,
            blockSize: 16,
            isEncryption: true
        });
    
        for (var i = 0; i < testVectors.length; i++) {
            var vector = testVectors[i];
            var pt = Buffer.from(vector[0], 'hex');
            var ct = ctrMode.process(pt);
    
            encrypted.push(ct);
        }
    
        // decrypt and check
        
        algorithm.keySchedule(key, false);
    
        ctrMode.init(algorithm, {
            iv: iv,
            blockSize: 16,
            isEncryption: false
        });
    
        for (var i = 0; i < testVectors.length; i++) {
            var vector = testVectors[i];
            var pt = Buffer.from(vector[0], 'hex');
            var ct = Buffer.from(vector[1], 'hex');
    
            // check encrypted...
            assert.ok(encrypted[i].equals(ct) , "Encryption passed!");
    
            var dt = ctrMode.process(ct);
    
            assert.ok(dt.equals(pt), "Decryption passed!");
        }
    
    });
    
    QUnit.module('AES-EAX');
    QUnit.test("Vector Test", function(assert) {
    
        // aes_type, key, nonce, authdata, repeat, cleartext, ciphertext
        // tagSize is 16
        var testVectors = [
            [
                128, 
                "233952DEE4D5ED5F9B9C6D6FF80FF478",
                "62EC67F9C3A4A407FCB2A8C49031A8B3",
                "6BFB914FD07EAE6B", 1,
                "",
                "E037830E8389F27B025A2D6527E79D01"
            ],
            [
                128,
                "91945D3F4DCBEE0BF45EF52255F095A4",
                "BECAF043B0A23D843194BA972C66DEBD",
                "FA3BFD4806EB53FA", 1,
                "F7FB",
                "19DD5C4C9331049D0BDAB0277408F67967E5"
            ],
            [
                128,
                "01F74AD64077F2E704C0F60ADA3DD523",
                "70C3DB4F0D26368400A10ED05D2BFF5E",
                "234A3463C1264AC6", 1,
                "1A47CB4933",
                "D851D5BAE03A59F238A23E39199DC9266626C40F80"
            ],
            [
                128,
                "D07CF6CBB7F313BDDE66B727AFD3C5E8",
                "8408DFFF3C1A2B1292DC199E46B7D617",
                "33CCE2EABFF5A79D", 1,
                "481C9E39B1",
                "632A9D131AD4C168A4225D8E1FF755939974A7BEDE"
            ],
            [
                128,
                "35B6D0580005BBC12B0587124557D2C2",
                "FDB6B06676EEDC5C61D74276E1F8E816",
                "AEB96EAEBE2970E9", 1,
                "40D0C07DA5E4",
                "071DFE16C675CB0677E536F73AFE6A14B74EE49844DD"
            ],
            [
                128,
                "BD8E6E11475E60B268784C38C62FEB22",
                "6EAC5C93072D8E8513F750935E46DA1B",
                "D4482D1CA78DCE0F", 1,
                "4DE3B35C3FC039245BD1FB7D",
                "835BB4F15D743E350E728414ABB8644FD6CCB86947C5E10590210A4F"
            ],
            [
                128,
                "7C77D6E813BED5AC98BAA417477A2E7D",
                "1A8C98DCD73D38393B2BF1569DEEFC19",
                "65D2017990D62528", 1,
                "8B0A79306C9CE7ED99DAE4F87F8DD61636",
                "02083E3979DA014812F59F11D52630DA30137327D10649B0AA6E1C181DB617D7F2"
            ],
            [
                128,
                "5FFF20CAFAB119CA2FC73549E20F5B0D",
                "DDE59B97D722156D4D9AFF2BC7559826",
                "54B9F04E6A09189A", 1,
                "1BDA122BCE8A8DBAF1877D962B8592DD2D56",
                "2EC47B2C4954A489AFC7BA4897EDCDAE8CC33B60450599BD02C96382902AEF7F832A"
            ],
            [
                128,
                "A4A4782BCFFD3EC5E7EF6D8C34A56123",
                "B781FCF2F75FA5A8DE97A9CA48E522EC",
                "899A175897561D7E", 1,
                "6CF36720872B8513F6EAB1A8A44438D5EF11",
                "0DE18FD0FDD91E7AF19F1D8EE8733938B1E8E7F6D2231618102FDB7FE55FF1991700"
            ],
            [
                128,
                "8395FCF1E95BEBD697BD010BC766AAC3",
                "22E7ADD93CFC6393C57EC0B3C17D6B44",
                "126735FCC320D25A", 1,
                "CA40D7446E545FFAED3BD12A740A659FFBBB3CEAB7",
                "CB8920F87A6C75CFF39627B56E3ED197C552D295A7CFC46AFC253B4652B1AF3795B124AB6E"
            ]
        ];
    
        // aes_type, key, nonce, authdata, repeat, cleartext, ciphertext
        for (var i = 0; i < testVectors.length; i++) {
            var vector = testVectors[i];
    
            var key = Buffer.from(vector[1], 'hex');
            var nonce = Buffer.from(vector[2], 'hex');
            var authdata = Buffer.from(vector[3], 'hex');
            var repeat = vector[4];
            var pt = Buffer.from(vector[5], 'hex');
            var expected = Buffer.from(vector[6], 'hex');
    
            var tagSize = 16;
            var algo_name = 'aes-128';
            
            var adata = Buffer.slice(authdata);
    
            if (repeat > 1) {
                for (var j = 1; j < repeat; j++) {
                    adata = Buffer.concat([adata, authdata]);
                }
                console.log(adata.length);
            }
            
    
            var cipher = new jCastle.mcrypt(algo_name);
            cipher.start({
                key: key,
                nonce: nonce,
                mode: 'eax',
                direction: true,
                additionalData: adata,
                tagSize: tagSize
            });
    
            var ct = cipher.update(pt).finalize();
            
            assert.ok(ct.equals(expected), 'Encryption Passed!');
    
    
            var cipher = new jCastle.mcrypt(algo_name);
            cipher.start({
                key: key,
                nonce: nonce,
                mode: 'eax',
                direction: false,
                additionalData: adata,
                tagSize: tagSize
            });
    
            var dt = cipher.update(ct).finalize();
    
            assert.ok(dt.equals(pt), 'Decryption Passed!');
        }
    });
    
    QUnit.module('AES-CCM');
    QUnit.test("Vector Test", function(assert) {
    
        var authdata_sample = "00010203 04050607 08090a0b 0c0d0e0f";
        var authdata_hex1 = 
            "00010203 04050607 08090a0b 0c0d0e0f" + 
            "10111213 14151617 18191a1b 1c1d1e1f" + 
            "20212223 24252627 28292a2b 2c2d2e2f" + 
            "30313233 34353637 38393a3b 3c3d3e3f" + 
            "40414243 44454647 48494a4b 4c4d4e4f" + 
            "50515253 54555657 58595a5b 5c5d5e5f" + 
            "60616263 64656667 68696a6b 6c6d6e6f" + 
            "70717273 74757677 78797a7b 7c7d7e7f" + 
            "80818283 84858687 88898a8b 8c8d8e8f" + 
            "90919293 94959697 98999a9b 9c9d9e9f" + 
            "a0a1a2a3 a4a5a6a7 a8a9aaab acadaeaf" + 
            "b0b1b2b3 b4b5b6b7 b8b9babb bcbdbebf" + 
            "c0c1c2c3 c4c5c6c7 c8c9cacb cccdcecf" + 
            "d0d1d2d3 d4d5d6d7 d8d9dadb dcdddedf" + 
            "e0e1e2e3 e4e5e6e7 e8e9eaeb ecedeeef" + 
            "f0f1f2f3 f4f5f6f7 f8f9fafb fcfdfeff";
    
    
        var testVectors = [
            // From NIST spec 800-38C on AES modes.
            // keysize, key, nonce, authdata, repeat, plaintext, ciphertext, tagsize
            [
                '128',
                "404142434445464748494a4b4c4d4e4f",
                "10111213141516",
                "0001020304050607", 1,
                "20212223",
                "7162015b"+
                "4dac255d", 4],
            [
                '128',
              "404142434445464748494a4b4c4d4e4f",
              "1011121314151617",
              "000102030405060708090a0b0c0d0e0f", 1,
              "202122232425262728292a2b2c2d2e2f",
              "d2a1f0e051ea5f62081a7792073d593d"+
                  "1fc64fbfaccd", 6],
            [
                '128',
              "404142434445464748494a4b4c4d4e4f",
              "101112131415161718191a1b",
              "000102030405060708090a0b0c0d0e0f"+
                  "10111213", 1,
              "202122232425262728292a2b2c2d2e2f"+
                   "3031323334353637",
              "e3b201a9f5b71a7a9b1ceaeccd97e70b"+
                   "6176aad9a4428aa5 484392fbc1b09951", 8],
            [
                '128',
              "404142434445464748494a4b4c4d4e4f",
              "101112131415161718191a1b1c",
              authdata_hex1, 256,
              "202122232425262728292a2b2c2d2e2f"+
                   "303132333435363738393a3b3c3d3e3f",
              "69915dad1e84c6376a68c2967e4dab61"+
                   "5ae0fd1faec44cc484828529463ccf72"+
                   "b4ac6bec93e8598e7f0dadbcea5b", 14],
            [
                '128',
              "C0 C1 C2 C3  C4 C5 C6 C7  C8 C9 CA CB  CC CD CE CF",
              "00 00 00 03  02 01 00 A0  A1 A2 A3 A4  A5",
              "00 01 02 03  04 05 06 07", 1,
              "08 09 0A 0B  0C 0D 0E 0F  10 11 12 13  14 15 16 17  18 19 1A 1B  1C 1D 1E",
              "58 8C 97 9A  61 C6 63 D2  F0 66 D0 C2  C0 F9 89 80  6D 5F 6B 61  DA C3 84"+
                   "17 E8 D1 2C  FD F9 26 E0"],
            [
                '128',
              "C0 C1 C2 C3  C4 C5 C6 C7  C8 C9 CA CB  CC CD CE CF",
              "00 00 00 04  03 02 01 A0  A1 A2 A3 A4  A5",
              "00 01 02 03  04 05 06 07", 1,
              "08 09 0A 0B  0C 0D 0E 0F  10 11 12 13  14 15 16 17  18 19 1A 1B  1C 1D 1E 1F",
              "72 C9 1A 36  E1 35 F8 CF  29 1C A8 94  08 5C 87 E3  CC 15 C4 39  C9 E4 3A 3B"+
                   "A0 91 D5 6E  10 40 09 16"],
            [
                '128',
              "C0 C1 C2 C3  C4 C5 C6 C7  C8 C9 CA CB  CC CD CE CF",
              "00 00 00 05  04 03 02 A0  A1 A2 A3 A4  A5",
              "00 01 02 03  04 05 06 07", 1,
              "08 09 0A 0B  0C 0D 0E 0F  10 11 12 13  14 15 16 17  18 19 1A 1B  1C 1D 1E 1F  20",
              "51 B1 E5 F4  4A 19 7D 1D  A4 6B 0F 8E  2D 28 2A E8  71 E8 38 BB  64 DA 85 96  57"+
                   "4A DA A7 6F  BD 9F B0 C5"],
            [
                '128',
              "C0 C1 C2 C3  C4 C5 C6 C7  C8 C9 CA CB  CC CD CE CF",
              "00 00 00 06  05 04 03 A0  A1 A2 A3 A4  A5",
              "00 01 02 03  04 05 06 07  08 09 0A 0B", 1,
              "0C 0D 0E 0F  10 11 12 13  14 15 16 17  18 19 1A 1B  1C 1D 1E",
              "A2 8C 68 65  93 9A 9A 79  FA AA 5C 4C  2A 9D 4A 91  CD AC 8C"+
                   "96 C8 61 B9  C9 E6 1E F1"],
            [
                '128',
              "C0 C1 C2 C3  C4 C5 C6 C7  C8 C9 CA CB  CC CD CE CF",
              "00 00 00 07  06 05 04 A0  A1 A2 A3 A4  A5",
              "00 01 02 03  04 05 06 07  08 09 0A 0B", 1,
              "0C 0D 0E 0F  10 11 12 13  14 15 16 17  18 19 1A 1B  1C 1D 1E 1F",
              "DC F1 FB 7B  5D 9E 23 FB  9D 4E 13 12  53 65 8A D8  6E BD CA 3E"+
                   "51 E8 3F 07  7D 9C 2D 93"],
            [
                '128',
              "C0 C1 C2 C3  C4 C5 C6 C7  C8 C9 CA CB  CC CD CE CF",
              "00 00 00 08  07 06 05 A0  A1 A2 A3 A4  A5",
              "00 01 02 03  04 05 06 07  08 09 0A 0B", 1,
              "0C 0D 0E 0F  10 11 12 13  14 15 16 17  18 19 1A 1B  1C 1D 1E 1F  20",
              "6F C1 B0 11  F0 06 56 8B  51 71 A4 2D  95 3D 46 9B  25 70 A4 BD  87"+
                   "40 5A 04 43  AC 91 CB 94"],
            [
                '128',
              "C0 C1 C2 C3  C4 C5 C6 C7  C8 C9 CA CB  CC CD CE CF",
              "00 00 00 09  08 07 06 A0  A1 A2 A3 A4  A5",
              "00 01 02 03  04 05 06 07", 1,
              "08 09 0A 0B  0C 0D 0E 0F  10 11 12 13  14 15 16 17  18 19 1A 1B  1C 1D 1E",
              "01 35 D1 B2  C9 5F 41 D5  D1 D4 FE C1  85 D1 66 B8  09 4E 99 9D  FE D9 6C"+
                   "04 8C 56 60  2C 97 AC BB  74 90", 10],
            [
                '128',
              "C0 C1 C2 C3  C4 C5 C6 C7  C8 C9 CA CB  CC CD CE CF",
              "00 00 00 0A  09 08 07 A0  A1 A2 A3 A4  A5",
              "00 01 02 03  04 05 06 07", 1,
              "08 09 0A 0B  0C 0D 0E 0F  10 11 12 13  14 15 16 17  18 19 1A 1B  1C 1D 1E 1F",
              "7B 75 39 9A  C0 83 1D D2  F0 BB D7 58  79 A2 FD 8F  6C AE 6B 6C  D9 B7 DB 24"+
                   "C1 7B 44 33  F4 34 96 3F  34 B4", 10],
            [
                '128',
              "C0 C1 C2 C3  C4 C5 C6 C7  C8 C9 CA CB  CC CD CE CF",
              "00 00 00 0B  0A 09 08 A0  A1 A2 A3 A4  A5",
              "00 01 02 03  04 05 06 07", 1,
              "08 09 0A 0B  0C 0D 0E 0F  10 11 12 13  14 15 16 17  18 19 1A 1B  1C 1D 1E 1F  20",
              "82 53 1A 60  CC 24 94 5A  4B 82 79 18  1A B5 C8 4D  F2 1C E7 F9  B7 3F 42 E1  97"+
                   "EA 9C 07 E5  6B 5E B1 7E  5F 4E", 10],
            [
                '128',
              "C0 C1 C2 C3  C4 C5 C6 C7  C8 C9 CA CB  CC CD CE CF",
              "00 00 00 0C  0B 0A 09 A0  A1 A2 A3 A4  A5",
              "00 01 02 03  04 05 06 07  08 09 0A 0B", 1,
              "0C 0D 0E 0F  10 11 12 13  14 15 16 17  18 19 1A 1B  1C 1D 1E",
              "07 34 25 94  15 77 85 15  2B 07 40 98  33 0A BB 14  1B 94 7B"+
                   "56 6A A9 40  6B 4D 99 99  88 DD", 10],
            [
                '128',
              "C0 C1 C2 C3  C4 C5 C6 C7  C8 C9 CA CB  CC CD CE CF",
              "00 00 00 0D  0C 0B 0A A0  A1 A2 A3 A4  A5",
              "00 01 02 03  04 05 06 07  08 09 0A 0B", 1,
              "0C 0D 0E 0F  10 11 12 13  14 15 16 17  18 19 1A 1B  1C 1D 1E 1F",
              "67 6B B2 03  80 B0 E3 01  E8 AB 79 59  0A 39 6D A7  8B 83 49 34"+
                   "F5 3A A2 E9  10 7A 8B 6C  02 2C", 10],
            [
                '128',
              "C0 C1 C2 C3  C4 C5 C6 C7  C8 C9 CA CB  CC CD CE CF",
              "00 00 00 0E  0D 0C 0B A0  A1 A2 A3 A4  A5",
              "00 01 02 03  04 05 06 07  08 09 0A 0B", 1,
              "0C 0D 0E 0F  10 11 12 13  14 15 16 17  18 19 1A 1B  1C 1D 1E 1F  20",
              "C0 FF A0 D6  F0 5B DB 67  F2 4D 43 A4  33 8D 2A A4  BE D7 B2 0E  43"+
                   "CD 1A A3 16  62 E7 AD 65  D6 DB", 10],
            [
                '128',
              "D7 82 8D 13  B2 B0 BD C3  25 A7 62 36  DF 93 CC 6B",
              "00 41 2B 4E  A9 CD BE 3C  96 96 76 6C  FA",
              "0B E1 A8 8B  AC E0 18 B1", 1,
              "08 E8 CF 97  D8 20 EA 25  84 60 E9 6A  D9 CF 52 89  05 4D 89 5C  EA C4 7C",
              "4C B9 7F 86  A2 A4 68 9A  87 79 47 AB  80 91 EF 53  86 A6 FF BD  D0 80 F8"+
                   "E7 8C F7 CB  0C DD D7 B3"],
            [
                '128',
              "D7 82 8D 13  B2 B0 BD C3  25 A7 62 36  DF 93 CC 6B",
              "00 33 56 8E  F7 B2 63 3C  96 96 76 6C  FA",
              "63 01 8F 76  DC 8A 1B CB", 1,
              "90 20 EA 6F  91 BD D8 5A  FA 00 39 BA  4B AF F9 BF  B7 9C 70 28  94 9C D0 EC",
              "4C CB 1E 7C  A9 81 BE FA  A0 72 6C 55  D3 78 06 12  98 C8 5C 92  81 4A BC 33"+
                   "C5 2E E8 1D  7D 77 C0 8A"],
            [
                '128',
              "D7 82 8D 13  B2 B0 BD C3  25 A7 62 36  DF 93 CC 6B",
              "00 10 3F E4  13 36 71 3C  96 96 76 6C  FA",
              "AA 6C FA 36  CA E8 6B 40", 1,
              "B9 16 E0 EA  CC 1C 00 D7  DC EC 68 EC  0B 3B BB 1A  02 DE 8A 2D  1A A3 46 13  2E",
              "B1 D2 3A 22  20 DD C0 AC  90 0D 9A A0  3C 61 FC F4  A5 59 A4 41  77 67 08 97  08"+
                   "A7 76 79 6E  DB 72 35 06"],
            [
                '128',
              "D7 82 8D 13  B2 B0 BD C3  25 A7 62 36  DF 93 CC 6B",
              "00 76 4C 63  B8 05 8E 3C  96 96 76 6C  FA",
              "D0 D0 73 5C  53 1E 1B EC  F0 49 C2 44", 1,
              "12 DA AC 56  30 EF A5 39  6F 77 0C E1  A6 6B 21 F7  B2 10 1C",
              "14 D2 53 C3  96 7B 70 60  9B 7C BB 7C  49 91 60 28  32 45 26"+
                   "9A 6F 49 97  5B CA DE AF"],
            [
                '128',
              "D7 82 8D 13  B2 B0 BD C3  25 A7 62 36  DF 93 CC 6B",
              "00 F8 B6 78  09 4E 3B 3C  96 96 76 6C  FA",
              "77 B6 0F 01  1C 03 E1 52  58 99 BC AE", 1,
              "E8 8B 6A 46  C7 8D 63 E5  2E B8 C5 46  EF B5 DE 6F  75 E9 CC 0D",
              "55 45 FF 1A  08 5E E2 EF  BF 52 B2 E0  4B EE 1E 23  36 C7 3E 3F"+
                   "76 2C 0C 77  44 FE 7E 3C"],
            [
                '128',
              "D7 82 8D 13  B2 B0 BD C3  25 A7 62 36  DF 93 CC 6B",
              "00 D5 60 91  2D 3F 70 3C  96 96 76 6C  FA",
              "CD 90 44 D2  B7 1F DB 81  20 EA 60 C0", 1,
              "64 35 AC BA  FB 11 A8 2E  2F 07 1D 7C  A4 A5 EB D9  3A 80 3B A8  7F",
              "00 97 69 EC  AB DF 48 62  55 94 C5 92  51 E6 03 57  22 67 5E 04  C8"+
                   "47 09 9E 5A  E0 70 45 51"],
            [
                '128',
              "D7 82 8D 13  B2 B0 BD C3  25 A7 62 36  DF 93 CC 6B",
              "00 42 FF F8  F1 95 1C 3C  96 96 76 6C  FA",
              "D8 5B C7 E6  9F 94 4F B8", 1,
              "8A 19 B9 50  BC F7 1A 01  8E 5E 67 01  C9 17 87 65  98 09 D6 7D  BE DD 18",
              "BC 21 8D AA  94 74 27 B6  DB 38 6A 99  AC 1A EF 23  AD E0 B5 29  39 CB 6A"+
                   "63 7C F9 BE  C2 40 88 97  C6 BA", 10],
            [
                '128',
              "D7 82 8D 13  B2 B0 BD C3  25 A7 62 36  DF 93 CC 6B",
              "00 92 0F 40  E5 6C DC 3C  96 96 76 6C  FA",
              "74 A0 EB C9  06 9F 5B 37", 1,
              "17 61 43 3C  37 C5 A3 5F  C1 F3 9F 40  63 02 EB 90  7C 61 63 BE  38 C9 84 37",
              "58 10 E6 FD  25 87 40 22  E8 03 61 A4  78 E3 E9 CF  48 4A B0 4F  44 7E FF F6"+
                   "F0 A4 77 CC  2F C9 BF 54  89 44", 10],
            [
                '128',
              "D7 82 8D 13  B2 B0 BD C3  25 A7 62 36  DF 93 CC 6B",
              "00 27 CA 0C  71 20 BC 3C  96 96 76 6C  FA",
              "44 A3 AA 3A  AE 64 75 CA", 1,
              "A4 34 A8 E5  85 00 C6 E4  15 30 53 88  62 D6 86 EA  9E 81 30 1B  5A E4 22 6B  FA",
              "F2 BE ED 7B  C5 09 8E 83  FE B5 B3 16  08 F8 E2 9C  38 81 9A 89  C8 E7 76 F1  54"+
                   "4D 41 51 A4  ED 3A 8B 87  B9 CE", 10],
            [
                '128',
              "D7 82 8D 13  B2 B0 BD C3  25 A7 62 36  DF 93 CC 6B",
              "00 5B 8C CB  CD 9A F8 3C  96 96 76 6C  FA",
              "EC 46 BB 63  B0 25 20 C3  3C 49 FD 70", 1,
              "B9 6B 49 E2  1D 62 17 41  63 28 75 DB  7F 6C 92 43  D2 D7 C2",
              "31 D7 50 A0  9D A3 ED 7F  DD D4 9A 20  32 AA BF 17  EC 8E BF"+
                   "7D 22 C8 08  8C 66 6B E5  C1 97", 10],
            [
                '128',
              "D7 82 8D 13  B2 B0 BD C3  25 A7 62 36  DF 93 CC 6B",
              "00 3E BE 94  04 4B 9A 3C  96 96 76 6C  FA",
              "47 A6 5A C7  8B 3D 59 42  27 E8 5E 71", 1,
              "E2 FC FB B8 80 44 2C 73  1B F9 51 67  C8 FF D7 89  5E 33 70 76",
              "E8 82 F1 DB D3 8C E3 ED  A7 C2 3F 04  DD 65 07 1E  B4 13 42 AC"+
                   "DF 7E 00 DC  CE C7 AE 52  98 7D", 10],
            [
                '128',
              "D7 82 8D 13  B2 B0 BD C3  25 A7 62 36  DF 93 CC 6B",
              "00 8D 49 3B  30 AE 8B 3C  96 96 76 6C  FA",
              "6E 37 A6 EF  54 6D 95 5D  34 AB 60 59", 1,
              "AB F2 1C 0B  02 FE B8 8F  85 6D F4 A3  73 81 BC E3  CC 12 85 17  D4",
              "F3 29 05 B8  8A 64 1B 04  B9 C9 FF B5  8C C3 90 90  0F 3D A1 2A  B1"+
              "6D CE 9E 82  EF A1 6D A6  20 59", 10],
    
            // IEEE 802.15.4-2011
            [
                '128',
              "C0 C1 C2 C3 C4 C5 C6 C7 C8 C9 CA CB CC CD CE CF",
              "AC DE 48 00 00 00 00 01 00 00 00 05 02",
              "08 D0 84 21 43 01 00 00 00 00 48 DE AC 02 05 00 00 00 55 CF 00 00 51 52 53 54", 1,
              "",
              "22 3B C1 EC 84 1A B5 53"],
            // tag size 0 is not allowed. refer the RFC 5084 document.
            /*[
                '128',
              "C0 C1 C2 C3 C4 C5 C6 C7 C8 C9 CA CB CC CD CE CF",
              "AC DE 48 00 00 00 00 01 00 00 00 05 04",
              "69 DC 84 21 43 02 00 00 00 00 48 DE AC 01 00 00 00 00 48 DE AC 04 05 00 00 00", 1,
              "61 62 63 64",
              "D4 3E 02 2B", 0], // tagSize: 0 */
            [
                '128',
              "C0 C1 C2 C3 C4 C5 C6 C7 C8 C9 CA CB CC CD CE CF",
              "AC DE 48 00 00 00 00 01 00 00 00 05 06",
              "2B DC 84 21 43 02 00 0000 00 48 DE AC FF FF 01 00 00 00 00 48 DE AC 06 05 00 00 00 01", 1,
              "CE",
              "D8 4F DE 52 90 61 F9 C6 F1"],
    
            // From IEEE P1619.1/D22 July 2007 (draft version)
            [
                '256',
              "0000000000000000000000000000000000000000000000000000000000000000",
              "000000000000000000000000",
              "", 0,
              "00000000000000000000000000000000",
              "c1944044c8e7aa95d2de9513c7f3dd8c"+
                   "4b0a3e5e51f151eb0ffae7c43d010fdb", 16],
            [
                '256',
              "0000000000000000000000000000000000000000000000000000000000000000",
              "000000000000000000000000",
              "00000000000000000000000000000000", 1,
              "",
              "904704e89fb216443cb9d584911fc3c2", 16],
            [
                '256',
              "0000000000000000000000000000000000000000000000000000000000000000",
              "000000000000000000000000",
              "00000000000000000000000000000000", 1,
              "00000000000000000000000000000000",
              "c1944044c8e7aa95d2de9513c7f3dd8c"+
                   "87314e9c1fa01abe6a6415943dc38521", 16],
            [
                '256',
              "fb7615b23d80891dd470980bc79584c8b2fb64ce60978f4d17fce45a49e830b7",
              "dbd1a3636024b7b402da7d6f",
              "", 0,
              "a845348ec8c5b5f126f50e76fefd1b1e",
              "cc881261c6a7fa72b96a1739176b277f"+
                   "3472e1145f2c0cbe146349062cf0e423", 16],
            [
                '256',
              "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
              "101112131415161718191a1b",
              "000102030405060708090a0b0c0d0e0f10111213", 1,
              "202122232425262728292a2b2c2d2e2f3031323334353637",
              "04f883aeb3bd0730eaf50bb6de4fa2212034e4e41b0e75e5"+
                   "9bba3f3a107f3239bd63902923f80371", 16],
            [
                '256',
              "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
              "101112131415161718191a1b",
              authdata_hex1, 256,
              "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
              "04f883aeb3bd0730eaf50bb6de4fa2212034e4e41b0e75e577f6bf2422c0f6d2"+
                   "3376d2cf256ef613c56454cbb5265834", 16],
            [
                '256',
              "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
              "101112131415161718191a1b",
              "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f", 1,
              "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"+
                   "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"+
                   "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"+
                   "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"+
                   "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"+
                   "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"+
                   "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf"+
                   "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
              "24d8a38e939d2710cad52b96fe6f82010014c4c43b2e55c557d69f0402e0d6f2"+
                   "06c53d6cbd3f1c3c6de5dcdcad9fb74f25741dea741149fe4278a0cc24741e86"+
                   "58cc0523b8d7838c60fb1de4b7c3941f5b26dea9322aa29656ec37ac18a9b108"+
                   "a6f38b7917f5a9c398838b22afbd17252e96694a9e6237964a0eae21c0a6e152"+
                   "15a0e82022926be97268249599e456e05029c3ebc07d78fc5b4a0862e04e68c2"+
                   "9514c7bdafc4b52e04833bf30622e4eb42504a44a9dcbc774752de7bb82891ad"+
                   "1eba9dc3281422a8aba8654268d3d9c81705f4c5a531ef856df5609a159af738"+
                   "eb753423ed2001b8f20c23725f2bef18c409f7e52132341f27cb8f0e79894dd9"+
                   "ebb1fa9d28ccfe21bdfea7e6d91e0bab", 16],
            [
                '256',
              "fb7615b23d80891dd470980bc79584c8b2fb64ce6097878d17fce45a49e830b7",
              "dbd1a3636024b7b402da7d6f",
              "36", 1,
              "a9",
              "9d3261b1cf931431e99a32806738ecbd2a", 16],
            [
                '256',
              "f8d476cfd646ea6c2384cb1c27d6195dfef1a9f37b9c8d21a79c21f8cb90d289",
              "dbd1a3636024b7b402da7d6f",
              "7bd859a247961a21823b380e9fe8b65082ba61d3", 1,
              "90ae61cf7baebd4cade494c54a29ae70269aec71",
              "6c05313e45dc8ec10bea6c670bd94f31569386a6"+
                   "8f3829e8e76ee23c04f566189e63c686", 16]
        ];
    
        // aes_type, key, nonce, authdata, repeat, cleartext, ciphertext, tagSize
    
        for (var i = 0; i < testVectors.length; i++) {
            var vector = testVectors[i];
    
            var key = Buffer.from(vector[1].replace(/[ \:]/g, ''), 'hex');
            var nonce = Buffer.from(vector[2].replace(/[ \:]/g, ''), 'hex');
            var authdata = Buffer.from(vector[3].replace(/[ \:]/g, ''), 'hex');
            var repeat = vector[4];
            var pt = Buffer.from(vector[5].replace(/[ \:]/g, ''), 'hex');
            var expected = Buffer.from(vector[6].replace(/[ \:]/g, ''), 'hex');
            var tagSize = typeof vector[7] != 'undefined' ? vector[7] : 8;
            
            var adata = Buffer.slice(authdata);
    
            if (repeat > 1) {
                for (var j = 1; j < repeat; j++) {
                    adata = Buffer.concat([adata, authdata]);
                }
                //console.log(adata.length);
            }
    
            var algo_name = 'aes-128';
    
            var cipher = new jCastle.mcrypt(algo_name);
            cipher.start({
                key: key,
                nonce: nonce,
                mode: 'ccm',
                direction: true,
                additionalData: adata,
                tagSize: tagSize
            });
    
            var ct = cipher.update(pt).finalize();
    
            assert.ok(ct.equals(expected), 'Encryption Passed!');
    
    
            var cipher = new jCastle.mcrypt(algo_name);
            cipher.start({
                key: key,
                nonce: nonce,
                mode: 'ccm',
                direction: false,
                additionalData: adata,
                tagSize: tagSize
            });
    
            var dt = cipher.update(ct).finalize();
    
            assert.ok(dt.equals(pt), 'Decryption Passed!');
        }
    });
    
    QUnit.module('AES-GCM');
    QUnit.test("Vector Test", function(assert) {
        // keysize, key, nonce, authdata, repeat, pt, ct, tag, tagsize
        var testVectors = [
            [
                128,
                '00000000000000000000000000000000',
                '000000000000000000000000',
                '', 1,
                '',
                '',
                '58e2fccefa7e3061367f1d57a4e7455a'],
            [
                128,
                '00000000000000000000000000000000',
                '000000000000000000000000',
                '', 1,
                '00000000000000000000000000000000',
                '0388dace60b6a392f328c2b971b2fe78',
                'ab6e47d42cec13bdf53a67b21257bddf'],
            [
                128,
                'feffe9928665731c6d6a8f9467308308',
                'cafebabefacedbaddecaf888',
                '', 1,
                'd9313225f88406e5a55909c5aff5269a'+
                '86a7a9531534f7da2e4c303d8a318a72'+
                '1c3c0c95956809532fcf0e2449a6b525'+
                'b16aedf5aa0de657ba637b391aafd255',
                '42831ec2217774244b7221b784d0d49c'+
                'e3aa212f2c02a4e035c17e2329aca12e'+
                '21d514b25466931c7d8f6a5aac84aa05'+
                '1ba30b396a0aac973d58e091473f5985',
                '4d5c2af327cd64a62cf35abd2ba6fab4'],
            [
                128,
                'feffe9928665731c6d6a8f9467308308',
                'cafebabefacedbaddecaf888',
                'feedfacedeadbeeffeedfacedeadbeef'+
                'abaddad2', 1,
                'd9313225f88406e5a55909c5aff5269a'+
                '86a7a9531534f7da2e4c303d8a318a72'+
                '1c3c0c95956809532fcf0e2449a6b525'+
                'b16aedf5aa0de657ba637b39',
                '42831ec2217774244b7221b784d0d49c'+
                'e3aa212f2c02a4e035c17e2329aca12e'+
                '21d514b25466931c7d8f6a5aac84aa05'+
                '1ba30b396a0aac973d58e091',
                '5bc94fbc3221a5db94fae95ae7121a47'],
            [
                128,
                'feffe9928665731c6d6a8f9467308308',
                'cafebabefacedbad',
                'feedfacedeadbeeffeedfacedeadbeef'+
                'abaddad2', 1,
                'd9313225f88406e5a55909c5aff5269a'+
                '86a7a9531534f7da2e4c303d8a318a72'+
                '1c3c0c95956809532fcf0e2449a6b525'+
                'b16aedf5aa0de657ba637b39',
                '61353b4c2806934a777ff51fa22a4755'+
                '699b2a714fcdc6f83766e5f97b6c7423'+
                '73806900e49f24b22b097544d4896b42'+
                '4989b5e1ebac0f07c23f4598',
                '3612d2e79e3b0785561be14aaca2fccb'],
            [
                128,
                'feffe9928665731c6d6a8f9467308308',
                '9313225df88406e555909c5aff5269aa'+
                '6a7a9538534f7da1e4c303d2a318a728'+
                'c3c0c95156809539fcf0e2429a6b5254'+
                '16aedbf5a0de6a57a637b39b',
                'feedfacedeadbeeffeedfacedeadbeef'+
                'abaddad2', 1,
                'd9313225f88406e5a55909c5aff5269a'+
                '86a7a9531534f7da2e4c303d8a318a72'+
                '1c3c0c95956809532fcf0e2449a6b525'+
                'b16aedf5aa0de657ba637b39',
                '8ce24998625615b603a033aca13fb894'+
                'be9112a5c3a211a8ba262a3cca7e2ca7'+
                '01e4a9a4fba43c90ccdcb281d48c7c6f'+
                'd62875d2aca417034c34aee5',
                '619cc5aefffe0bfa462af43c1699d050'],
            [
                192,
                '00000000000000000000000000000000'+
                '0000000000000000',
                '000000000000000000000000',
                '', 1,
                '',
                '',
                'cd33b28ac773f74ba00ed1f312572435'],
            [
                192,
                '00000000000000000000000000000000'+
                '0000000000000000',
                '000000000000000000000000',
                '', 1,
                '00000000000000000000000000000000',
                '98e7247c07f0fe411c267e4384b0f600',
                '2ff58d80033927ab8ef4d4587514f0fb'],
            [
                192,
                'feffe9928665731c6d6a8f9467308308'+
                'feffe9928665731c',
                'cafebabefacedbaddecaf888',
                '', 1,
                'd9313225f88406e5a55909c5aff5269a'+
                '86a7a9531534f7da2e4c303d8a318a72'+
                '1c3c0c95956809532fcf0e2449a6b525'+
                'b16aedf5aa0de657ba637b391aafd255',
                '3980ca0b3c00e841eb06fac4872a2757'+
                '859e1ceaa6efd984628593b40ca1e19c'+
                '7d773d00c144c525ac619d18c84a3f47'+
                '18e2448b2fe324d9ccda2710acade256',
                '9924a7c8587336bfb118024db8674a14'],
            [
                192,
                'feffe9928665731c6d6a8f9467308308'+
                'feffe9928665731c',
                'cafebabefacedbaddecaf888',
                'feedfacedeadbeeffeedfacedeadbeef'+
                'abaddad2', 1,
                'd9313225f88406e5a55909c5aff5269a'+
                '86a7a9531534f7da2e4c303d8a318a72'+
                '1c3c0c95956809532fcf0e2449a6b525'+
                'b16aedf5aa0de657ba637b39',
                '3980ca0b3c00e841eb06fac4872a2757'+
                '859e1ceaa6efd984628593b40ca1e19c'+
                '7d773d00c144c525ac619d18c84a3f47'+
                '18e2448b2fe324d9ccda2710',
                '2519498e80f1478f37ba55bd6d27618c'],
            [
                192,
                'feffe9928665731c6d6a8f9467308308'+
                'feffe9928665731c',
                'cafebabefacedbad',
                'feedfacedeadbeeffeedfacedeadbeef'+
                'abaddad2', 1,
                'd9313225f88406e5a55909c5aff5269a'+
                '86a7a9531534f7da2e4c303d8a318a72'+
                '1c3c0c95956809532fcf0e2449a6b525'+
                'b16aedf5aa0de657ba637b39',
                '0f10f599ae14a154ed24b36e25324db8'+
                'c566632ef2bbb34f8347280fc4507057'+
                'fddc29df9a471f75c66541d4d4dad1c9'+
                'e93a19a58e8b473fa0f062f7',
                '65dcc57fcf623a24094fcca40d3533f8'],
            [
                192,
                'feffe9928665731c6d6a8f9467308308'+
                'feffe9928665731c',
                '9313225df88406e555909c5aff5269aa'+
                '6a7a9538534f7da1e4c303d2a318a728'+
                'c3c0c95156809539fcf0e2429a6b5254'+
                '16aedbf5a0de6a57a637b39b',
                'feedfacedeadbeeffeedfacedeadbeef'+
                'abaddad2', 1,
                'd9313225f88406e5a55909c5aff5269a'+
                '86a7a9531534f7da2e4c303d8a318a72'+
                '1c3c0c95956809532fcf0e2449a6b525'+
                'b16aedf5aa0de657ba637b39',
                'd27e88681ce3243c4830165a8fdcf9ff'+
                '1de9a1d8e6b447ef6ef7b79828666e45'+
                '81e79012af34ddd9e2f037589b292db3'+
                'e67c036745fa22e7e9b7373b',
                'dcf566ff291c25bbb8568fc3d376a6d9'],
            [
                256,
                '00000000000000000000000000000000'+
                '00000000000000000000000000000000',
                '000000000000000000000000',
                '', 1,
                '',
                '',
                '530f8afbc74536b9a963b4f1c4cb738b'],
            [
                256,
                '00000000000000000000000000000000'+
                '00000000000000000000000000000000',
                '000000000000000000000000',
                '', 1,
                '00000000000000000000000000000000',
                'cea7403d4d606b6e074ec5d3baf39d18',
                'd0d1c8a799996bf0265b98b5d48ab919'],
            [
                256,
                'feffe9928665731c6d6a8f9467308308'+
                'feffe9928665731c6d6a8f9467308308',
                'cafebabefacedbaddecaf888',
                '', 1,
                'd9313225f88406e5a55909c5aff5269a'+
                '86a7a9531534f7da2e4c303d8a318a72'+
                '1c3c0c95956809532fcf0e2449a6b525'+
                'b16aedf5aa0de657ba637b391aafd255',
                '522dc1f099567d07f47f37a32a84427d'+
                '643a8cdcbfe5c0c97598a2bd2555d1aa'+
                '8cb08e48590dbb3da7b08b1056828838'+
                'c5f61e6393ba7a0abcc9f662898015ad',
                'b094dac5d93471bdec1a502270e3cc6c'],
            [
                256,
                'feffe9928665731c6d6a8f9467308308'+
                'feffe9928665731c6d6a8f9467308308',
                'cafebabefacedbaddecaf888',
                'feedfacedeadbeeffeedfacedeadbeef'+
                'abaddad2', 1,
                'd9313225f88406e5a55909c5aff5269a'+
                '86a7a9531534f7da2e4c303d8a318a72'+
                '1c3c0c95956809532fcf0e2449a6b525'+
                'b16aedf5aa0de657ba637b39',
                '522dc1f099567d07f47f37a32a84427d'+
                '643a8cdcbfe5c0c97598a2bd2555d1aa'+
                '8cb08e48590dbb3da7b08b1056828838'+
                'c5f61e6393ba7a0abcc9f662',
                '76fc6ece0f4e1768cddf8853bb2d551b'],
            [
                256,
                'feffe9928665731c6d6a8f9467308308'+
                'feffe9928665731c6d6a8f9467308308',
                'cafebabefacedbad',
                'feedfacedeadbeeffeedfacedeadbeef'+
                'abaddad2', 1,
                'd9313225f88406e5a55909c5aff5269a'+
                '86a7a9531534f7da2e4c303d8a318a72'+
                '1c3c0c95956809532fcf0e2449a6b525'+
                'b16aedf5aa0de657ba637b39',
                'c3762df1ca787d32ae47c13bf19844cb'+
                'af1ae14d0b976afac52ff7d79bba9de0'+
                'feb582d33934a4f0954cc2363bc73f78'+
                '62ac430e64abe499f47c9b1f',
                '3a337dbf46a792c45e454913fe2ea8f2'],
            [
                256,
                'feffe9928665731c6d6a8f9467308308'+
                'feffe9928665731c6d6a8f9467308308',
                '9313225df88406e555909c5aff5269aa'+
                '6a7a9538534f7da1e4c303d2a318a728'+
                'c3c0c95156809539fcf0e2429a6b5254'+
                '16aedbf5a0de6a57a637b39b',
                'feedfacedeadbeeffeedfacedeadbeef'+
                'abaddad2', 1,
                'd9313225f88406e5a55909c5aff5269a'+
                '86a7a9531534f7da2e4c303d8a318a72'+
                '1c3c0c95956809532fcf0e2449a6b525'+
                'b16aedf5aa0de657ba637b39',
                '5a8def2f0c9e53f1f75d7853659e2a20'+
                'eeb2b22aafde6419a058ab4f6f746bf4'+
                '0fc0c3b780f244452da3ebf1c5d82cde'+
                'a2418997200ef82e44ae7e3f',
                'a44a8266ee1c8eb0c8b5d4cf5ae9f19a'],
            [
                128,
                '2fb45e5b8f993a2bfebc4b15b533e0b4',
                '5b05755f984d2b90f94b8027',
                'e85491b2202caf1d7dce03b97e09331c'+
                '32473941', 1,
                '',
                '',
                'c75b7832b2a2d9bd827412b6ef5769db'],
            [
                128,
                '99e3e8793e686e571d8285c564f75e2b',
                'c2dd0ab868da6aa8ad9c0d23',
                'b668e42d4e444ca8b23cfdd95a9fedd5'+
                '178aa521144890b093733cf5cf22526c'+
                '5917ee476541809ac6867a8c399309fc', 1,
                '',
                '',
                '3f4fba100eaf1f34b0baadaae9995d85']
        ];
    
        // aes_type, key, nonce, authdata, repeat, cleartext, ciphertext, tag, tagSize
    
        for (var i = 0; i < testVectors.length; i++) {
            var vector = testVectors[i];
    
            var key = Buffer.from(vector[1].replace(/[ \:]/g, ''), 'hex');
            var nonce = Buffer.from(vector[2].replace(/[ \:]/g, ''), 'hex');
            var authdata = Buffer.from(vector[3].replace(/[ \:]/g, ''), 'hex');
            var repeat = vector[4];
            var pt = Buffer.from(vector[5].replace(/[ \:]/g, ''), 'hex');
            var ct_expected = Buffer.from(vector[6].replace(/[ \:]/g, ''), 'hex');
            var tag = Buffer.from(vector[7].replace(/[ \:]/g, ''), 'hex');
            var tagSize = typeof vector[8] != 'undefined' ? vector[8] : tag.length;
    
            var expected = Buffer.concat([ct_expected, tag]);
    
            var algo_name = 'aes-128';
            //var algo_name = 'rijndael-128';
    
            var block_size = jCastle._algorithmInfo[algo_name].block_size;
            
            var adata = Buffer.slice(authdata);
    
            if (repeat > 1) {
                for (var j = 1; j < repeat; j++) {
                    adata = Buffer.concat([adata, authdata]);
                }
                console.log(adata.length);
            }
    
            var cipher = new jCastle.mcrypt(algo_name);
            cipher.start({
                key: key,
                nonce: nonce,
                mode: 'gcm',
                direction: true,
                additionalData: adata,
                tagSize: tagSize ? tagSize : block_size
            });
    
            var ct = cipher.update(pt).finalize();
    
            assert.ok(ct.equals(expected), 'Encryption Passed!');
    
    
            var cipher = new jCastle.mcrypt(algo_name);
            cipher.start({
                key: key,
                nonce: nonce,
                mode: 'gcm',
                direction: false,
                additionalData: adata,
                tagSize: tagSize ? tagSize : block_size
            });
    
            var dt = cipher.update(ct).finalize();
    
            assert.ok(dt.equals(pt), 'Decryption Passed!');
        }
    });
    
    
    QUnit.module('Chacha20-Poly1305');
    QUnit.test("Vector Test", function(assert) {
    
        var testVectors = [
            {
                key:		'80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f'+
                            '90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f',
                nonce:		'07 00 00 00 40 41 42 43 44 45 46 47',
                plaintext:	'4c 61 64 69 65 73 20 61 6e 64 20 47 65 6e 74 6c'+
                            '65 6d 65 6e 20 6f 66 20 74 68 65 20 63 6c 61 73'+
                            '73 20 6f 66 20 27 39 39 3a 20 49 66 20 49 20 63'+
                            '6f 75 6c 64 20 6f 66 66 65 72 20 79 6f 75 20 6f'+
                            '6e 6c 79 20 6f 6e 65 20 74 69 70 20 66 6f 72 20'+
                            '74 68 65 20 66 75 74 75 72 65 2c 20 73 75 6e 73'+
                            '63 72 65 65 6e 20 77 6f 75 6c 64 20 62 65 20 69'+
                            '74 2e',
                aad:		'50 51 52 53 c0 c1 c2 c3 c4 c5 c6 c7',
                ciphertext:	'd3 1a 8d 34 64 8e 60 db 7b 86 af bc 53 ef 7e c2'+
                            'a4 ad ed 51 29 6e 08 fe a9 e2 b5 a7 36 ee 62 d6'+
                            '3d be a4 5e 8c a9 67 12 82 fa fb 69 da 92 72 8b'+
                            '1a 71 de 0a 9e 06 0b 29 05 d6 a5 b6 7e cd 3b 36'+
                            '92 dd bd 7f 2d 77 8b 8c 98 03 ae e3 28 09 1b 58'+
                            'fa b3 24 e4 fa d6 75 94 55 85 80 8b 48 31 d7 bc'+
                            '3f f4 de f0 8e 4b 7a 9d e5 76 d2 65 86 ce c6 4b'+
                            '61 16',
                tag:		'1a:e1:0b:59:4f:09:e2:6a:7e:90:2e:cb:d0:60:06:91'
            },
            {
                key:		'1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0'+
                            '47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0',
                nonce:      '00 00 00 00 01 02 03 04 05 06 07 08',
                plaintext:  'Internet-Drafts are draft documents valid for a maximum of '+
                            'six months and may be updated, replaced, or obsoleted by other '+
                            'documents at any time. It is inappropriate to use Internet-Drafts '+
                            'as reference material or to cite them other than as /“work in progress./”',
                aad:        'f3 33 88 86 00 00 00 00 00 00 4e 91',
                ciphertext: '64 a0 86 15 75 86 1a f4 60 f0 62 c7 9b e6 43 bd'+
                            '5e 80 5c fd 34 5c f3 89 f1 08 67 0a c7 6c 8c b2'+
                            '4c 6c fc 18 75 5d 43 ee a0 9e e9 4e 38 2d 26 b0'+
                            'bd b7 b7 3c 32 1b 01 00 d4 f0 3b 7f 35 58 94 cf'+
                            '33 2f 83 0e 71 0b 97 ce 98 c8 a8 4a bd 0b 94 81'+
                            '14 ad 17 6e 00 8d 33 bd 60 f9 82 b1 ff 37 c8 55'+
                            '97 97 a0 6e f4 f0 ef 61 c1 86 32 4e 2b 35 06 38'+
                            '36 06 90 7b 6a 7c 02 b0 f9 f6 15 7b 53 c8 67 e4'+
                            'b9 16 6c 76 7b 80 4d 46 a5 9b 52 16 cd e7 a4 e9'+
                            '90 40 c5 a4 04 33 22 5e e2 82 a1 b0 a0 6c 52 3e'+
                            'af 45 34 d7 f8 3f a1 15 5b 00 47 71 8c bc 54 6a'+
                            '0d 07 2b 04 b3 56 4e ea 1b 42 22 73 f5 48 27 1a'+
                            '0b b2 31 60 53 fa 76 99 19 55 eb d6 31 59 43 4e'+
                            'ce bb 4e 46 6d ae 5a 10 73 a6 72 76 27 09 7a 10'+
                            '49 e6 17 d9 1d 36 10 94 fa 68 f0 ff 77 98 71 30'+
                            '30 5b ea ba 2e da 04 df 99 7b 71 4d 6c 6f 2c 29'+
                            'a6 ad 5c b4 02 2b 02 70 9b',
                tag:        'ee ad 9d 67 89 0c bb 22 39 23 36 fe a1 85 1f 38',
                pt_is_text: true
            }
        ];
    
    
        for (var i = 0; i < testVectors.length; i++) {
            var vector = testVectors[i];
    
            var key = Buffer.from(vector.key.replace(/[ \:]/g, ''), 'hex');
            var nonce = Buffer.from(vector.nonce.replace(/[ \:]/g, ''), 'hex');
            var authdata = Buffer.from(vector.aad.replace(/[ \:]/g, ''), 'hex');
            if (vector.pt_is_text) {
                var pt = Buffer.from(vector.plaintext); // important!
            } else {
                var pt = Buffer.from(vector.plaintext.replace(/[ \:]/g, ''), 'hex');
            }
            var ct_expected = Buffer.from(vector.ciphertext.replace(/[ \:]/g, ''), 'hex');
            var tag = Buffer.from(vector.tag.replace(/[ \:]/g, ''), 'hex');
    
            var expected = Buffer.concat([ct_expected, tag]);
    
            var algo_name = 'chacha20';
    
            var cipher = new jCastle.mcrypt(algo_name);
            cipher.start({
                key: key,
                nonce: nonce,
                mode: 'poly1305',
                isEncryption: true,
                additionalData: authdata
            });
    
            var ct = cipher.update(pt).finalize();
    
            assert.ok(ct.equals(expected), 'Encryption Passed!');
    
            var cipher = new jCastle.mcrypt(algo_name);
            cipher.start({
                key: key,
                nonce: nonce,
                mode: 'poly1305',
                isEncryption: false,
                additionalData: authdata
            });
    
            var dt = cipher.update(ct).finalize();
    
            assert.ok(dt.equals(pt), 'Decryption Passed!');
        }
    });
    
    QUnit.module('GCTR with GOST');
    QUnit.test("Vector Test", function(assert) {
    
        var vector = {
            key: "0011223344556677889900112233445566778899001122334455667788990011",
            iv: "1234567890abcdef",
            pt: "bc350e71aa11345709acde",
            expected: "8824c124c4fd14301fb1e8"
            };
    
        var key = Buffer.from(vector.key.replace(/[ \:]/g, ''), 'hex');
        var iv = Buffer.from(vector.iv.replace(/[ \:]/g, ''), 'hex');
        var pt = Buffer.from(vector.pt.replace(/[ \:]/g, ''), 'hex');
        var expected = Buffer.from(vector.expected.replace(/[ \:]/g, ''), 'hex');
    
        var algo_name = 'gost';
    
        var cipher = new jCastle.mcrypt(algo_name);
        cipher.start({
            key: key,
            iv: iv,
            mode: 'gctr',
            direction: true
        });
    
        var ct = cipher.update(pt).finalize();
    
        assert.ok(ct.equals(expected), 'Encryption Passed!');
    
        var cipher = new jCastle.mcrypt(algo_name);
        cipher.start({
            key: key,
            iv: iv,
            mode: 'gctr',
            direction: false
        });
    
        var dt = cipher.update(ct).finalize();
    
        assert.ok(dt.equals(pt), 'Decryption Passed!');
    
        //
        // second test with SBOX 'E-A'
        //
    
        var vector = {
            key: "4ef72b778f0b0bebeef4f077551cb74a927b470ad7d7f2513454569a247e989d",
            iv: "1234567890abcdef",
            pt: "bc350e71aa11345709acde",
            expected: "1bcc2282707c676fb656dc"
            };
    
        var key = Buffer.from(vector.key.replace(/[ \:]/g, ''), 'hex');
        var iv = Buffer.from(vector.iv.replace(/[ \:]/g, ''), 'hex');
        var pt = Buffer.from(vector.pt.replace(/[ \:]/g, ''), 'hex');
        var expected = Buffer.from(vector.expected.replace(/[ \:]/g, ''), 'hex');
    
        var algo_name = 'gost';
    
        var cipher = new jCastle.mcrypt(algo_name);
        cipher.start({
            key: key,
            iv: iv,
            mode: 'gctr',
            direction: true,
            sbox: 'E-A' // important!
        });
    
        var ct = cipher.update(pt).finalize();
    
        assert.ok(ct.equals(expected), 'Encryption Passed!');
    
        var cipher = new jCastle.mcrypt(algo_name);
        cipher.start({
            key: key,
            iv: iv,
            mode: 'gctr',
            direction: false,
            sbox: 'E-A' // important!
        });
    
        var dt = cipher.update(ct).finalize();
    
        assert.ok(dt.equals(pt), 'Decryption Passed!');
    });
    
    
    //
    // there is no test vectors for gcfb mode.
    //