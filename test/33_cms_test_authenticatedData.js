const jCastle = require('../lib/index');
const QUnit = require('qunit');

QUnit.module("CMS");
QUnit.test("CMS AuthenticatedData - KeyTransRecipientInfo export / parse Step Test", function(assert) {

    var bits = 1024;

    var password = 'password';

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
    
    var issuer = [{
        name: 'countryName',
        value: 'KR',
        type: jCastle.asn1.tagPrintableString
    }, {
        name: 'stateOrProvinceName',
        value: 'Chungcheongbuk-do'
        // type: jCastle.asn1.tagUTF8String // default
    }, {
        name: 'localityName',
        value: 'Cheongju'
    }, {
        name: 'organizationName',
        value: 'jCastle Corp'
    }, {
        name: 'organizationalUnitName',
        value: 'WebCert Support'
    }, {
        name: 'commonName',
        value: 'jCastle Web CA'
    }, {
        name: 'emailAddress',
        value: 'support@jcastle.net'
    }];
    
    /* alice */
    
    var alice = jCastle.pki.create('RSA');
    alice.generateKeypair({
        bits: bits, 
        exponent: 0x10001
    });

    alice.setPadding('rsaes-oaep');

    // console.log('alice rsa key generated.');

    var alice_privkey_pem = alice.exportPrivateKey({ password: password });

    // console.log('alice private key pem with password: ');
    // console.log(alice_privkey_pem);
    
    var alice_subject = [{
        name: 'countryName',
        value: 'KR',
        type: jCastle.asn1.tagPrintableString
    }, {
        name: 'stateOrProvinceName',
        value: 'Seoul'
        // type: jCastle.asn1.tagUTF8String // default
    }, {
        name: 'organizationName',
        value: 'DACOCHE'
    }, {
        name: 'commonName',
        value: 'Dacoche Web Flatform'
    }];
    
    var alice_cert_info = {
        type: jCastle.certificate.typeCRT,
        tbs: {
            serial: 750365,
            issuer: issuer,
            subject: alice_subject,
            subjectPublicKeyInfo: alice.getPublicKeyInfo(),
            extensions: {
                keyUsage: {
                    list: ['keyEncipherment', 'digitalSignature'],
                    critical: true
                }
            }
        },
        algo: {
            signHash: 'SHA-256',
            signAlgo: 'RSASSA-PKCS1-V1_5' // 'RSASSA-PSS', 'EC', 'DSA'
        }
    };
    
    var alice_cert = jCastle.certificate.create();
    var alice_cert_pem = alice_cert.setSignKey(root).exportCertificate(alice_cert_info);

    // console.log('alice certificate pem: ');
    // console.log(alice_cert_pem);
    
    /* bob */
    
    var bob = jCastle.pki.create('RSA');
    bob.generateKeypair({
        bits: bits, 
        exponent: 0x10001
    });

    // console.log('bob rsa key generated.');

    var bob_privkey_pem = bob.exportPrivateKey({ password: password });

    // console.log('bob private key pem with password: ');
    // console.log(bob_privkey_pem);
    
    var bob_subject = [{
        name: 'countryName',
        value: 'KR',
        type: jCastle.asn1.tagPrintableString
    }, {
        name: 'stateOrProvinceName',
        value: 'Seoul'
        // type: jCastle.asn1.tagUTF8String // default
    }, {
        name: 'organizationName',
        value: 'Hareem'
    }, {
        name: 'commonName',
        value: 'Hareem Food'
    }];
    
    var bob_cert_info = {
        type: jCastle.certificate.typeCRT,
        tbs: {
            serial: 6649112,
            issuer: issuer,
            subject: bob_subject,
            subjectPublicKeyInfo: bob.getPublicKeyInfo(),
            extensions: {
                keyUsage: {
                    list: ['keyEncipherment', 'digitalSignature'],
                    critical: true
                }
            }
        },
        algo: {
            signHash: 'SHA-256',
            signAlgo: 'RSASSA-PKCS1-V1_5' // 'RSASSA-PSS', 'EC', 'DSA'
        }
    };
    
    var bob_cert = jCastle.certificate.create();
    var bob_cert_pem = bob_cert.setSignKey(root).exportCertificate(bob_cert_info);

    // console.log('bob certificate pem: ');
    // console.log(bob_cert_pem);
    
    /* alice exports cms with authenticatedData - ktri */

    // console.log('alice exports cms with authenticatedData - ktri');
    
    var cms_info = {
        "contentType": "authenticatedData",
        "content": {
            "recipientInfos": [
                {
                    "type": "keyTransRecipientInfo",
                    "keyEncryptionAlgorithm": {
                        "algo": "RSA",
                        "padding": {
                            "mode": "RSAES-OAEP", // PKCS1_OAEP
                            "hashAlgo": "sha-1",
                            "mgf": "mgf1",
                            "label": ""
                        }
                    }
                }
            ],
            "macAlgorithm": {
                "algorithm": "hmacWithSHA256"
            }
        }
    };
    
    var plaintext = "Hello world!";
    
    var cms = jCastle.cms.create();
    var options = {
        cmsKey: {
            privateKey: alice_privkey_pem,
            password: password,
            certificate: alice_cert_pem,
            recipient: {
                certificate: bob_cert_pem
            }
        },
        content: plaintext
    };
    var cms_pem = cms.exportCMS(cms_info, options);
    
    // console.log('alice cms_pem: ');
    // console.log(cms_pem);
    
    /* bob parses cms pem */

    // console.log('bob parses cms pem.');
    
    var cmsKey = {
        privateKey: bob_privkey_pem,
        password: password
    };
    
    var options = {
        cmsKey: cmsKey
    };
    
    var cms_info = cms.parse(cms_pem, options);

    // console.log('cms_info: ');
    // console.log(cms_info);
    // console.log(cms_info.content.recipientInfos);
    // console.log(cms_info.content.recipientInfos[0].recipientIdentifier.serialNumber);
    // if (BigInt.is(cms_info.content.recipientInfos[0].recipientIdentifier.serialNumber))
    //     console.log(cms_info.content.recipientInfos[0].recipientIdentifier.serialNumber.intValue());
    // console.log(cms_info.content.macAlgorithm.macInfo);
    
    assert.ok(jCastle.cms.verifyAuthenticatedData(cms_info, cmsKey), "AuthenticatedData-ktri verification");
    // console.log("AuthenticatedData-ktri verification: ", jCastle.cms.verifyAuthenticatedData(cms_info, cmsKey));
     
    // var pptable = prettyPrint(cms_info);
    // document.getElementById('printarea2').appendChild(pptable);
    
     
});