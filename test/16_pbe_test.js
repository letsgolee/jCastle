
const jCastle = require('../lib/index');
const QUnit = require('qunit');

QUnit.module('PBE');
QUnit.test("Encryption/Decryption test", function(assert) {

    //
    // jCastle.pbe.encrypt
    //

    var data = "jCastle.net";
    var password = 'qwer1234##';

    var ct = jCastle.pbe.encrypt(data, {
        password,
        saltLength: 8
    });
    //console.log(ct);

    var pt = jCastle.pbe.decrypt(ct.encrypted, {
        password: 'qwer1234##',
        salt: ct.salt
    });
    //console.log(pt.toString() === data);
    assert.equal(data, pt.toString(), 'pbe test 1');


    //
    // jCastle.pbe.pbes1.encrypt
    //

    var ct = jCastle.pbe.pbes1.encrypt({
        algoInfo: 'pbeWithSHA1AndSEED-CBC',
        kdfInfo: {
            iterations: 1024
        }
    }, password, data);
    //console.log(ct);
    var pt = jCastle.pbe.pbes1.decrypt({
        algoInfo: 'pbeWithSHA1AndSEED-CBC',
        kdfInfo: {
            salt: ct.salt,
            iterations: ct.iterations
        }
    }, password, ct.encrypted);
    //console.log(pt.toString() === data);
    assert.equal(data, pt.toString(), 'pbe test 2');


    //
    // jCastle.pbe.pbes2.encrypt
    //

    var ct = jCastle.pbe.pbes2.encrypt({
        algoInfo: 'aes-128-cbc',
        kdfInfo: {
            iterations: 1024
        }
    }, password, data);
    //console.log(ct);
    var pt = jCastle.pbe.pbes2.decrypt({
        algoInfo: 'aes-128-cbc',
        kdfInfo: {
            salt: ct.salt,
            iterations: ct.iterations
        },
        params: {
            iv: ct.iv
        }
    }, password, ct.encrypted);
    //console.log(pt.toString() === data);
    assert.equal(data, pt.toString(), 'pbe test 3');


    //
    // jCastle.pbe.pkcs12pbes.encrypt
    //

    var ct = jCastle.pbe.pkcs12pbes.encrypt({
        //algoInfo: 'PBE-SHA1-SEED',
        algoInfo: 'pbeWithSHAAnd2-KeyTripleDES-CBC',
        kdfInfo: {
            iterations: 1024
        }
    }, password, data);
    //console.log(ct);
    var pt = jCastle.pbe.pkcs12pbes.decrypt({
        //algoInfo: 'PBE-SHA1-SEED',
        algoInfo: 'pbeWithSHAAnd2-KeyTripleDES-CBC',
        kdfInfo: {
            salt: ct.salt,
            iterations: ct.iterations
        }
    }, password, ct.encrypted);
    //console.log(pt.toString() === data);
    assert.equal(data, pt.toString(), 'pbe test 4');


    //
    // jCastle.pbe.asn1.encrypt
    //

    // PKCS#5 v1.5 or PKCS#12 Password Based Encryption
    var der = jCastle.pbe.asn1.encrypt(data, {
        password
    });
    //console.log(Buffer.from(der, 'latin1'));
    var sequence = jCastle.asn1.create().parse(der);
    var pt = jCastle.pbe.asn1.decrypt(sequence, password);
    //console.log(pt.toString() === data);
    assert.equal(data, pt.toString(), 'pbe test 5');

    // pkcs#5 v2.0 algorithm
    var der = jCastle.pbe.asn1.encrypt(data, {
        algo: 'aes-128-cbc',
        password
    });
    //console.log(Buffer.from(der, 'latin1'));
    var sequence = jCastle.asn1.create().parse(der);
    var pt = jCastle.pbe.asn1.decrypt(sequence, password);
    //console.log(pt.toString() === data);
    assert.equal(data, pt.toString(), 'pbe test 5');


    // jCastle.pbe.asn1.pbkdf2.parse
    // jCastle.pbe.asn1.pbkdf2.schema


    // jCastle.pbe.asn1.encAlgoInfo.parse
    // jCastle.pbe.asn1.encAlgoInfo.schema


    // jCastle.pbe.asn1.pbeInfo.parse
    // jCastle.pbe.asn1.pbeInfo.schema


    // jCastle.pbe.asn1.macAlgorithm.parse
    // jCastle.pbe.asn1.macAlgorithm.schema


    // jCastle.pbe.asn1.macAlgoParameters.parse
    // jCastle.pbe.asn1.macAlgoParameters.schema



});