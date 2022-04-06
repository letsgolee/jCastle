const jCastle = require('../lib/index');
const QUnit = require('qunit');

QUnit.module("CMS");
QUnit.test("CMS Parsing Test", function(assert) {


    // openssl cms -EncryptedData_encrypt -in message.txt -outform PEM -aes128 -secretkey 000102030405060708090a0b0c0d0e0f -stream -out cms_encryptedData_aes128.pem
    // message.txt has "hello world" text.
    
    /*
    -----BEGIN CMS-----
    MIAGCSqGSIb3DQEHBqCAMIACAQAwgAYJKoZIhvcNAQcBMB0GCWCGSAFlAwQBAgQQ
    rNaWW2F+b+pR/3t732H3QKCABBAuNuLZg/4euGW8ZL1Ko4tzAAAAAAAAAAAAAA==
    -----END CMS-----
    
    
    
    SEQUENCE (2 elem)
      OBJECT IDENTIFIER 1.2.840.113549.1.7.6 encryptedData (PKCS #7)
      [0] (1 elem)
        SEQUENCE (2 elem)
          INTEGER 0
          SEQUENCE (3 elem)
            OBJECT IDENTIFIER 1.2.840.113549.1.7.1 data (PKCS #7)
            SEQUENCE (2 elem)
              OBJECT IDENTIFIER 2.16.840.1.101.3.4.1.2 aes128-CBC (NIST Algorithm)
              OCTET STRING (16 byte) ACD6965B617E6FEA51FF7B7BDF61F740
            [0] (1 elem)
              OCTET STRING (16 byte) 2E36E2D983FE1EB865BC64BD4AA38B73
    */
    
    var encryptKey = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex');
    var encrypteddata_pem = `
    -----BEGIN CMS-----
    MIAGCSqGSIb3DQEHBqCAMIACAQAwgAYJKoZIhvcNAQcBMB0GCWCGSAFlAwQBAgQQ
    rNaWW2F+b+pR/3t732H3QKCABBAuNuLZg/4euGW8ZL1Ko4tzAAAAAAAAAAAAAA==
    -----END CMS-----`;

    var plaintext = "hello world";
    
    var cms = jCastle.cms.create();
    var cms_info = cms.parse(encrypteddata_pem, {
        encryptKey: encryptKey
    });

    // console.log('cms_info: ', cms_info);

    // var pptable = prettyPrint(cms_info);
    // document.getElementById('printarea').appendChild(pptable);
    
    var cms_info2 = {
        contentType: "encryptedData",
        content: {
            encryptedContentInfo: {
                type: "data",
                contentEncryptionAlgorithm: {
                    "algo": "aes-128-CBC"
                }//,
    //          content: plaintext
            }
        }
    };
    
    var cms_data = cms.exportCMS(cms_info2, {
        format: 'base64',
        content: plaintext,
        encryptKey: encryptKey
    });

    // console.log('cms_data: ');
    // console.log(jCastle.util.lineBreak(cms_data, 64));
    
    var cms_info3 = cms.parse(cms_data, {
        encryptKey: encryptKey
    });
    
    // var pptable2 = prettyPrint(cms_info3);
    // document.getElementById('printarea1').appendChild(pptable2);
    
    assert.equal(plaintext, cms_info3.content.encryptedContentInfo.content.toString(), "CMS EncryptedData Test");
    // console.log("CMS EncryptedData Test: ", plaintext == cms_info3.content.encryptedContentInfo.content.toString());
    
});

QUnit.test('encryptedData - password based encryption test', function (assert) {

    var plaintext = "hello world";

    var password = "password";

    var cms = jCastle.cms.create();

    var cms_info = {
        contentType: "encryptedData",
        content: {
            encryptedContentInfo: {
                type: "data",
                contentEncryptionAlgorithm: {
                    "algo": "pbeWithSHAAnd40BitRC2-CBC"
                }//,
    //          content: plaintext
            }
        }
    };

    var cms_data = cms.exportCMS(cms_info, {
        format: 'base64',
        content: plaintext,
        password: password
    });

    // console.log('cms_data: ');
    // console.log(jCastle.util.lineBreak(cms_data, 64));
    
    var cms_info2 = cms.parse(cms_data, {
        password: password
    });

    // console.log('cms_info2: ', cms_info2);
    
    // var pptable2 = prettyPrint(cms_info2);
    // document.getElementById('printarea1').appendChild(pptable2);
    
    assert.equal(plaintext, cms_info2.content.encryptedContentInfo.content.toString(), "CMS EncryptedData Test");
    // console.log("CMS EncryptedData Test: ", plaintext == cms_info2.content.encryptedContentInfo.content.toString());

});