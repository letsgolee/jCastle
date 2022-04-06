const QUnit = require('qunit');
const jCastle = require('../lib/index');


// http://vmpcfunction.com/vmpcr.htm
QUnit.module('VMPC-R');
QUnit.test("Vector Test", function(assert) {

    //----------------- Test data: -----------------
    var testOutPSIdx = Buffer.from([0, 1, 2, 3, 252, 253, 254, 255]);
    var testOutIdx   = [0, 1, 2, 3, 254, 255, 256, 257,1000,1001,10000,10001,100000,100001,1000000,1000001];
    
    var testKey      = Buffer.from([11,22,33,144,155,166,233,244,255]);
    var testIV   = Buffer.from([255,250,200,150,100,50,5,1]);
    
    var testKey32    =    Buffer.from([104, 9, 46, 231, 132, 149, 234, 147, 224, 97, 230, 127, 124, 109, 34, 171,
                                       88, 185, 158, 23, 116, 69, 90, 195, 208, 17, 86, 175, 108, 29, 146, 219]);
                                      //RND=123; repeat 32 times:{RND=RND*134775813+1; output=(RND & 255)}
    
    var testIV32 =    Buffer.from([149, 234, 147, 224, 97, 230, 127, 124, 109, 34, 171, 88, 185, 158, 23, 116,
                                       69, 90, 195, 208, 17, 86, 175, 108, 29, 146, 219, 72, 105, 14, 71, 100]);
                                      //RND=132; repeat 32 times:{RND=RND*134775813+1; output=(RND & 255)}
    
    var testKey256   =    Buffer.from([147, 224, 97, 230, 127, 124, 109, 34, 171, 88, 185, 158, 23, 116, 69, 90, 195, 208, 17, 86, 175,
                                       108, 29, 146, 219, 72, 105, 14, 71, 100, 245, 202, 243, 192, 193, 198, 223, 92, 205, 2, 11, 56,
                                       25, 126, 119, 84, 165, 58, 35, 176, 113, 54, 15, 76, 125, 114, 59, 40, 201, 238, 167, 68, 85, 170,
                                       83, 160, 33, 166, 63, 60, 45, 226, 107, 24, 121, 94, 215, 52, 5, 26, 131, 144, 209, 22, 111, 44,
                                       221, 82, 155, 8, 41, 206, 7, 36, 181, 138, 179, 128, 129, 134, 159, 28, 141, 194, 203, 248, 217,
                                       62, 55, 20, 101, 250, 227, 112, 49, 246, 207, 12, 61, 50, 251, 232, 137, 174, 103, 4, 21, 106, 19,
                                       96, 225, 102, 255, 252, 237, 162, 43, 216, 57, 30, 151, 244, 197, 218, 67, 80, 145, 214, 47, 236,
                                       157, 18, 91, 200, 233, 142, 199, 228, 117, 74, 115, 64, 65, 70, 95, 220, 77, 130, 139, 184, 153,
                                       254, 247, 212, 37, 186, 163, 48, 241, 182, 143, 204, 253, 242, 187, 168, 73, 110, 39, 196, 213,
                                       42, 211, 32, 161, 38, 191, 188, 173, 98, 235, 152, 249, 222, 87, 180, 133, 154, 3, 16, 81, 150,
                                       239, 172, 93, 210, 27, 136, 169, 78, 135, 164, 53, 10, 51, 0, 1, 6, 31, 156, 13, 66, 75, 120, 89,
                                       190, 183, 148, 229, 122, 99, 240, 177, 118, 79, 140, 189, 178, 123, 104, 9, 46, 231, 132, 149, 234]);
                                      //RND=234; repeat 256 times:{RND=RND*134775813+1; output=(RND & 255)}
    
    var testOutP       = Buffer.from([97,218,106,125,139,86,36,126]);
    var testOutS       = Buffer.from([152,143,19,154,92,25,24,157]);
    var testOut        = Buffer.from([49,161,79,69,85,237,96,243,181,184,136,99,67,27,253,231]);
    
    //-------------------------------------------------------------------------------------------------------------
    
        var z = 1;
        var vmpcr = new jCastle.algorithm.vmpcr('vmpcr');
        
        vmpcr.setInitialVector(testIV);
        vmpcr.keySchedule(testKey, true);
        
        for (var x = 0; x < testOutPSIdx.length; x++) {
            assert.equal(vmpcr.P[testOutPSIdx[x]], testOutP[x], "P Test " + (z++));
            assert.equal(vmpcr.S[testOutPSIdx[x]], testOutS[x], "S Test " + (z++));
        }
        
        var bytes =vmpcr.prngGetBytes(1000002);
            
        for (var x = 0; x < testOutIdx.length; x++) {
            assert.equal(bytes[testOutIdx[x]], testOut[x], "Pseudo-Random Generation Test " + (z++));
        }
    
    //-------------------------------------------------------------------------------------------------------------
    
    var testOutP32     = Buffer.from([76, 44, 167, 7, 250, 147, 240, 51]);
    var testOutS32     = Buffer.from([239, 59, 110, 207, 98, 23, 178, 227]);
    var testOut32      = Buffer.from([219, 178, 157, 119, 2, 155, 62, 20, 3, 239, 236, 81, 195, 11, 186, 127]);
        
        
        vmpcr.setInitialVector(testIV32);
        vmpcr.keySchedule(testKey32, true);
        
        for (var x = 0; x < testOutPSIdx.length; x++) {
            assert.equal(vmpcr.P[testOutPSIdx[x]], testOutP32[x], "P Test " + (z++));
            assert.equal(vmpcr.S[testOutPSIdx[x]], testOutS32[x], "S Test " + (z++));
        }
        var bytes =vmpcr.prngGetBytes(1000002);
            
        for (var x = 0; x < testOutIdx.length; x++) {
            assert.equal(bytes[testOutIdx[x]], testOut32[x], "Pseudo-Random Generation Test " + (z++));
        }
    
    //-------------------------------------------------------------------------------------------------------------
    
    var testOutP256    = Buffer.from([10, 34, 13, 239, 209, 9, 154, 220]);
    var testOutS256    = Buffer.from([253, 106, 200, 178, 75, 251, 129, 209]);
    var testOut256     = Buffer.from([201, 85, 155, 17, 187, 48, 55, 198, 110, 179, 189, 210, 4, 15, 253, 83]);
    
        vmpcr.setInitialVector(testIV);
        vmpcr.keySchedule(testKey256, true);
    
        for (var x = 0; x < testOutPSIdx.length; x++) {
            assert.equal(vmpcr.P[testOutPSIdx[x]], testOutP256[x], "P Test " + (z++));
            assert.equal(vmpcr.S[testOutPSIdx[x]], testOutS256[x], "S Test " + (z++));
        }
        var bytes =vmpcr.prngGetBytes(1000002);
            
        for (var x = 0; x < testOutIdx.length; x++) {
            assert.equal(bytes[testOutIdx[x]], testOut256[x], "Pseudo-Random Generation Test " + (z++));
        }
    
    });