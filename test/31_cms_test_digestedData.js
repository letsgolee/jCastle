const jCastle = require('../lib/index');
const QUnit = require('qunit');

QUnit.module("CMS");
QUnit.test("CMS Parsing Test", function(assert) {

    // cms digested-data sample
    // plaintext: hello world
    // openssl cms -digest_create -in message.txt -text -out cms_digestedData_sample_1.msg
    
    /*
    MGkGCSqGSIb3DQEHBaBcMFoCAQAwBwYFKw4DAhowNgYJKoZIhvcNAQcBoCkEJ0Nv
    bnRlbnQtVHlwZTogdGV4dC9wbGFpbg0KDQpoZWxsbyB3b3JsZAQUz8wdr3rAtyPE
    1SSbbjxk17TFHyY=
    
    
    SEQUENCE (2 elem)
        OBJECT IDENTIFIER 1.2.840.113549.1.7.5 digestedData (PKCS #7)
        [0] (1 elem)
            SEQUENCE (4 elem)
                INTEGER 0
                SEQUENCE (1 elem)
                    OBJECT IDENTIFIER 1.3.14.3.2.26 sha1 (OIW)
                SEQUENCE (2 elem)
                    OBJECT IDENTIFIER 1.2.840.113549.1.7.1 data (PKCS #7)
                    [0] (1 elem)
                        OCTET STRING (39 byte) 436F6E74656E742D547970653A20746578742F706C61696E0D0A0D0A68656C6C6F2077…     
                                               Content-Type: text/plain hello world
                OCTET STRING (20 byte) CFCC1DAF7AC0B723C4D5249B6E3C64D7B4C51F26
    
    */
    
    var cms_data = `
        MGkGCSqGSIb3DQEHBaBcMFoCAQAwBwYFKw4DAhowNgYJKoZIhvcNAQcBoCkEJ0Nv
        bnRlbnQtVHlwZTogdGV4dC9wbGFpbg0KDQpoZWxsbyB3b3JsZAQUz8wdr3rAtyPE
        1SSbbjxk17TFHyY=`;
    
    var cms = new jCastle.cms();
    
    var cms_info = cms.parse(cms_data);
    
    // console.log('cms_info: ', cms_info);
    // console.log('content: ', cms_info.content.encapContentInfo.content.toString());
    
    // var pptable = prettyPrint(cms_info);
    // document.getElementById('printarea').appendChild(pptable);
    
    assert.ok(jCastle.CMS.verifyDigestedData(cms_info), "CMS DigestedData Verification 1");
    // console.log("CMS DigestedData Verification 1: ", jCastle.CMS.verifyDigestedData(cms_info));
    
    var cms_info2 = {
        contentType: "digestedData",
        content: {
            digestAlgorithm: "sha-1",
            encapContentInfo: {
                type: "data",
                content: "hello world"
            }
        }
    };
    
    var cms_data2 = cms.exportCMS(cms_info2, {
        content: "Hello world from jCastle.net\n Jacob Lee greets you!",
        format: 'base64'
    });
    
    // console.log('cms_data2: ');
    // console.log(jCastle.util.lineBreak(cms_data2, 64));
    
    var cms_info3 = cms.parse(cms_data2);
    
    // var pptable2 = prettyPrint(cms_info3);
    // document.getElementById('printarea1').appendChild(pptable2);

    // console.log('cms_info3: ', cms_info3);
    
    assert.ok(jCastle.CMS.verifyDigestedData(cms_info3), "CMS DigestedData Verification 2");	  
    // console.log("CMS DigestedData Verification 2: ", jCastle.CMS.verifyDigestedData(cms_info3));	
});