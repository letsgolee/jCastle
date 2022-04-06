const QUnit = require('qunit');
const jCastle = require('../lib/index');

//
// XTS mode
//

QUnit.module('AES-XTS');
QUnit.test("Vector Test", function(assert) {

    //
    //XTS-AES Encrypt / Decrypt
    //
    
    /*
    http://libeccio.di.unisa.it/Crypto14/Lab/p1619.pdf
    */
    
        var testVectors = [
    
        // XTS-AES applied for a data unit of 32 bytes, 32 bytes key material. 
    
    ///{{{  
            {
                count: 1,
                key1: "00000000000000000000000000000000",
                key2: "00000000000000000000000000000000",
                dataUnitSerial: "0",
                pt: "0000000000000000000000000000000000000000000000000000000000000000",
    //			tweak: "66e94bd4ef8a2c3b884cfa59ca342b2eccd297a8df1559761099f4b39469565c",
                expected: "917cf69ebd68b2ec9b9fe9a3eadda692cd43d2f59598ed858c02c2652fbf922e",
            },
    
            {
                count: 2,
                key1: "11111111111111111111111111111111",
                key2: "22222222222222222222222222222222",
                dataUnitSerial: "3333333333",
                pt: "4444444444444444444444444444444444444444444444444444444444444444",
    //			tweak: "3f803bcd0d7fd2b37558419f59d5cda6f900779a1bfea467ebb0823eb3aa9b4d",
                expected: "c454185e6a16936e39334038acef838bfb186fff7480adc4289382ecd6d394f0",
            },
            
            {
                count: 3,
                key1: "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0",
                key2: "22222222222222222222222222222222",
                dataUnitSerial: "3333333333",
                pt: "4444444444444444444444444444444444444444444444444444444444444444",
    //			tweak: "3f803bcd0d7fd2b37558419f59d5cda6f900779a1bfea467ebb0823eb3aa9b4d",
                expected: "af85336b597afc1a900b2eb21ec949d292df4c047e0b21532186a5971a227a89",
            },
    ///}}}
    
        // XTS-AES-128 applied for a data unit of 512 bytes
    
            {
                count: 4,
                key1: "27182818284590452353602874713526",
                key2: "31415926535897932384626433832795",
                dataUnitSerial: "0",
                pt:
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" + 
                "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" + 
                "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f" + 
                "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f" + 
                "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f" + 
                "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf" + 
                "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf" + 
                "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff" + 
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" + 
                "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" +  
                "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f" + 
                "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f" + 
                "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f" + 
                "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf" + 
                "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf" + 
                "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
                expected:
                "27a7479befa1d476489f308cd4cfa6e2a96e4bbe3208ff25287dd3819616e89c" + 
                "c78cf7f5e543445f8333d8fa7f56000005279fa5d8b5e4ad40e736ddb4d35412" + 
                "328063fd2aab53e5ea1e0a9f332500a5df9487d07a5c92cc512c8866c7e860ce" + 
                "93fdf166a24912b422976146ae20ce846bb7dc9ba94a767aaef20c0d61ad0265" + 
                "5ea92dc4c4e41a8952c651d33174be51a10c421110e6d81588ede82103a252d8" + 
                "a750e8768defffed9122810aaeb99f9172af82b604dc4b8e51bcb08235a6f434" + 
                "1332e4ca60482a4ba1a03b3e65008fc5da76b70bf1690db4eae29c5f1badd03c" + 
                "5ccf2a55d705ddcd86d449511ceb7ec30bf12b1fa35b913f9f747a8afd1b130e" + 
                "94bff94effd01a91735ca1726acd0b197c4e5b03393697e126826fb6bbde8ecc" + 
                "1e08298516e2c9ed03ff3c1b7860f6de76d4cecd94c8119855ef5297ca67e9f3" + 
                "e7ff72b1e99785ca0a7e7720c5b36dc6d72cac9574c8cbbc2f801e23e56fd344" + 
                "b07f22154beba0f08ce8891e643ed995c94d9a69c9f1b5f499027a78572aeebd" + 
                "74d20cc39881c213ee770b1010e4bea718846977ae119f7a023ab58cca0ad752" + 
                "afe656bb3c17256a9f6e9bf19fdd5a38fc82bbe872c5539edb609ef4f79c203e" + 
                "bb140f2e583cb2ad15b4aa5b655016a8449277dbd477ef2c8d6c017db738b18d" + 
                "eb4a427d1923ce3ff262735779a418f20a282df920147beabe421ee5319d0568"
            },
    
            {
                count: 5,
                key1: "27182818284590452353602874713526",
                key2: "31415926535897932384626433832795",
                dataUnitSerial: "01",
                pt:
                "27a7479befa1d476489f308cd4cfa6e2a96e4bbe3208ff25287dd3819616e89c" + 
                "c78cf7f5e543445f8333d8fa7f56000005279fa5d8b5e4ad40e736ddb4d35412" + 
                "328063fd2aab53e5ea1e0a9f332500a5df9487d07a5c92cc512c8866c7e860ce" + 
                "93fdf166a24912b422976146ae20ce846bb7dc9ba94a767aaef20c0d61ad0265" + 
                "5ea92dc4c4e41a8952c651d33174be51a10c421110e6d81588ede82103a252d8" + 
                "a750e8768defffed9122810aaeb99f9172af82b604dc4b8e51bcb08235a6f434" + 
                "1332e4ca60482a4ba1a03b3e65008fc5da76b70bf1690db4eae29c5f1badd03c" + 
                "5ccf2a55d705ddcd86d449511ceb7ec30bf12b1fa35b913f9f747a8afd1b130e" + 
                "94bff94effd01a91735ca1726acd0b197c4e5b03393697e126826fb6bbde8ecc" + 
                "1e08298516e2c9ed03ff3c1b7860f6de76d4cecd94c8119855ef5297ca67e9f3" + 
                "e7ff72b1e99785ca0a7e7720c5b36dc6d72cac9574c8cbbc2f801e23e56fd344" + 
                "b07f22154beba0f08ce8891e643ed995c94d9a69c9f1b5f499027a78572aeebd" + 
                "74d20cc39881c213ee770b1010e4bea718846977ae119f7a023ab58cca0ad752" + 
                "afe656bb3c17256a9f6e9bf19fdd5a38fc82bbe872c5539edb609ef4f79c203e" + 
                "bb140f2e583cb2ad15b4aa5b655016a8449277dbd477ef2c8d6c017db738b18d" + 
                "eb4a427d1923ce3ff262735779a418f20a282df920147beabe421ee5319d0568",
                expected:
                "264d3ca8512194fec312c8c9891f279fefdd608d0c027b60483a3fa811d65ee5" + 
                "9d52d9e40ec5672d81532b38b6b089ce951f0f9c35590b8b978d175213f329bb" + 
                "1c2fd30f2f7f30492a61a532a79f51d36f5e31a7c9a12c286082ff7d2394d18f" + 
                "783e1a8e72c722caaaa52d8f065657d2631fd25bfd8e5baad6e527d763517501" + 
                "c68c5edc3cdd55435c532d7125c8614deed9adaa3acade5888b87bef641c4c99" + 
                "4c8091b5bcd387f3963fb5bc37aa922fbfe3df4e5b915e6eb514717bdd2a7407" + 
                "9a5073f5c4bfd46adf7d282e7a393a52579d11a028da4d9cd9c77124f9648ee3" + 
                "83b1ac763930e7162a8d37f350b2f74b8472cf09902063c6b32e8c2d9290cefb" + 
                "d7346d1c779a0df50edcde4531da07b099c638e83a755944df2aef1aa31752fd" + 
                "323dcb710fb4bfbb9d22b925bc3577e1b8949e729a90bbafeacf7f7879e7b114" + 
                "7e28ba0bae940db795a61b15ecf4df8db07b824bb062802cc98a9545bb2aaeed" + 
                "77cb3fc6db15dcd7d80d7d5bc406c4970a3478ada8899b329198eb61c193fb62" + 
                "75aa8ca340344a75a862aebe92eee1ce032fd950b47d7704a3876923b4ad6284" + 
                "4bf4a09c4dbe8b4397184b7471360c9564880aedddb9baa4af2e75394b08cd32" + 
                "ff479c57a07d3eab5d54de5f9738b8d27f27a9f0ab11799d7b7ffefb2704c95c" + 
                "6ad12c39f1e867a4b7b1d7818a4b753dfd2a89ccb45e001a03a867b187f225dd"
            },
    
            {
                count: 6,
                key1: "27182818284590452353602874713526",
                key2: "31415926535897932384626433832795", 
                dataUnitSerial: "02",
                pt:
                "264d3ca8512194fec312c8c9891f279fefdd608d0c027b60483a3fa811d65ee5" + 
                "9d52d9e40ec5672d81532b38b6b089ce951f0f9c35590b8b978d175213f329bb" + 
                "1c2fd30f2f7f30492a61a532a79f51d36f5e31a7c9a12c286082ff7d2394d18f" + 
                "783e1a8e72c722caaaa52d8f065657d2631fd25bfd8e5baad6e527d763517501" + 
                "c68c5edc3cdd55435c532d7125c8614deed9adaa3acade5888b87bef641c4c99" + 
                "4c8091b5bcd387f3963fb5bc37aa922fbfe3df4e5b915e6eb514717bdd2a7407" + 
                "9a5073f5c4bfd46adf7d282e7a393a52579d11a028da4d9cd9c77124f9648ee3" + 
                "83b1ac763930e7162a8d37f350b2f74b8472cf09902063c6b32e8c2d9290cefb" + 
                "d7346d1c779a0df50edcde4531da07b099c638e83a755944df2aef1aa31752fd" + 
                "323dcb710fb4bfbb9d22b925bc3577e1b8949e729a90bbafeacf7f7879e7b114" + 
                "7e28ba0bae940db795a61b15ecf4df8db07b824bb062802cc98a9545bb2aaeed" + 
                "77cb3fc6db15dcd7d80d7d5bc406c4970a3478ada8899b329198eb61c193fb62" + 
                "75aa8ca340344a75a862aebe92eee1ce032fd950b47d7704a3876923b4ad6284" + 
                "4bf4a09c4dbe8b4397184b7471360c9564880aedddb9baa4af2e75394b08cd32" + 
                "ff479c57a07d3eab5d54de5f9738b8d27f27a9f0ab11799d7b7ffefb2704c95c" + 
                "6ad12c39f1e867a4b7b1d7818a4b753dfd2a89ccb45e001a03a867b187f225dd",
                expected:
                "fa762a3680b76007928ed4a4f49a9456031b704782e65e16cecb54ed7d017b5e" + 
                "18abd67b338e81078f21edb7868d901ebe9c731a7c18b5e6dec1d6a72e078ac9" + 
                "a4262f860beefa14f4e821018272e411a951502b6e79066e84252c3346f3aa62" + 
                "344351a291d4bedc7a07618bdea2af63145cc7a4b8d4070691ae890cd65733e7" + 
                "946e9021a1dffc4c59f159425ee6d50ca9b135fa6162cea18a939838dc000fb3" + 
                "86fad086acce5ac07cb2ece7fd580b00cfa5e98589631dc25e8e2a3daf2ffdec" + 
                "26531659912c9d8f7a15e5865ea8fb5816d6207052bd7128cd743c12c8118791" + 
                "a4736811935eb982a532349e31dd401e0b660a568cb1a4711f552f55ded59f1f" + 
                "15bf7196b3ca12a91e488ef59d64f3a02bf45239499ac6176ae321c4a211ec54" + 
                "5365971c5d3f4f09d4eb139bfdf2073d33180b21002b65cc9865e76cb24cd92c" + 
                "874c24c18350399a936ab3637079295d76c417776b94efce3a0ef7206b151105" + 
                "19655c956cbd8b2489405ee2b09a6b6eebe0c53790a12a8998378b33a5b71159" + 
                "625f4ba49d2a2fdba59fbf0897bc7aabd8d707dc140a80f0f309f835d3da54ab" + 
                "584e501dfa0ee977fec543f74186a802b9a37adb3e8291eca04d66520d229e60" + 
                "401e7282bef486ae059aa70696e0e305d777140a7a883ecdcb69b9ff938e8a42" + 
                "31864c69ca2c2043bed007ff3e605e014bcf518138dc3a25c5e236171a2d01d6"
            },
    
            {
                count: 7,
                key1: "27182818284590452353602874713526",
                key2: "31415926535897932384626433832795",
                dataUnitSerial: "fd",
                pt:
                "8e41b78c390b5af9d758bb214a67e9f6bf7727b09ac6124084c37611398fa45d" + 
                "aad94868600ed391fb1acd4857a95b466e62ef9f4b377244d1c152e7b30d731a" + 
                "ad30c716d214b707aed99eb5b5e580b3e887cf7497465651d4b60e6042051da3" + 
                "693c3b78c14489543be8b6ad0ba629565bba202313ba7b0d0c94a3252b676f46" + 
                "cc02ce0f8a7d34c0ed229129673c1f61aed579d08a9203a25aac3a77e9db6026" + 
                "7996db38df637356d9dcd1632e369939f2a29d89345c66e05066f1a3677aef18" + 
                "dea4113faeb629e46721a66d0a7e785d3e29af2594eb67dfa982affe0aac058f" + 
                "6e15864269b135418261fc3afb089472cf68c45dd7f231c6249ba0255e1e0338" + 
                "33fc4d00a3fe02132d7bc3873614b8aee34273581ea0325c81f0270affa13641" + 
                "d052d36f0757d484014354d02d6883ca15c24d8c3956b1bd027bcf41f151fd80" + 
                "23c5340e5606f37e90fdb87c86fb4fa634b3718a30bace06a66eaf8f63c4aa3b" + 
                "637826a87fe8cfa44282e92cb1615af3a28e53bc74c7cba1a0977be9065d0c1a" + 
                "5dec6c54ae38d37f37aa35283e048e5530a85c4e7a29d7b92ec0c3169cdf2a80" + 
                "5c7604bce60049b9fb7b8eaac10f51ae23794ceba68bb58112e293b9b692ca72" + 
                "1b37c662f8574ed4dba6f88e170881c82cddc1034a0ca7e284bf0962b6b26292" + 
                "d836fa9f73c1ac770eef0f2d3a1eaf61d3e03555fd424eedd67e18a18094f888",
                expected:
                "d55f684f81f4426e9fde92a5ff02df2ac896af63962888a97910c1379e20b0a3" + 
                "b1db613fb7fe2e07004329ea5c22bfd33e3dbe4cf58cc608c2c26c19a2e2fe22" + 
                "f98732c2b5cb844cc6c0702d91e1d50fc4382a7eba5635cd602432a2306ac4ce" + 
                "82f8d70c8d9bc15f918fe71e74c622d5cf71178bf6e0b9cc9f2b41dd8dbe441c" + 
                "41cd0c73a6dc47a348f6702f9d0e9b1b1431e948e299b9ec2272ab2c5f0c7be8" + 
                "6affa5dec87a0bee81d3d50007edaa2bcfccb35605155ff36ed8edd4a40dcd4b" + 
                "243acd11b2b987bdbfaf91a7cac27e9c5aea525ee53de7b2d3332c8644402b82" + 
                "3e94a7db26276d2d23aa07180f76b4fd29b9c0823099c9d62c519880aee7e969" +  
                "7617c1497d47bf3e571950311421b6b734d38b0db91eb85331b91ea9f61530f5" + 
                "4512a5a52a4bad589eb69781d537f23297bb459bdad2948a29e1550bf4787e0b" + 
                "e95bb173cf5fab17dab7a13a052a63453d97ccec1a321954886b7a1299faaeec" + 
                "ae35c6eaaca753b041b5e5f093bf83397fd21dd6b3012066fcc058cc32c3b09d" + 
                "7562dee29509b5839392c9ff05f51f3166aaac4ac5f238038a3045e6f72e48ef" + 
                "0fe8bc675e82c318a268e43970271bf119b81bf6a982746554f84e72b9f00280" + 
                "a320a08142923c23c883423ff949827f29bbacdc1ccdb04938ce6098c95ba6b3" + 
                "2528f4ef78eed778b2e122ddfd1cbdd11d1c0a6783e011fc536d63d053260637"
            },
    
            {
                count: 8,
                key1: "27182818284590452353602874713526",
                key2: "31415926535897932384626433832795",
                dataUnitSerial: "fe",
                pt:
                "d55f684f81f4426e9fde92a5ff02df2ac896af63962888a97910c1379e20b0a3" + 
                "b1db613fb7fe2e07004329ea5c22bfd33e3dbe4cf58cc608c2c26c19a2e2fe22" + 
                "f98732c2b5cb844cc6c0702d91e1d50fc4382a7eba5635cd602432a2306ac4ce" + 
                "82f8d70c8d9bc15f918fe71e74c622d5cf71178bf6e0b9cc9f2b41dd8dbe441c" + 
                "41cd0c73a6dc47a348f6702f9d0e9b1b1431e948e299b9ec2272ab2c5f0c7be8" + 
                "6affa5dec87a0bee81d3d50007edaa2bcfccb35605155ff36ed8edd4a40dcd4b" + 
                "243acd11b2b987bdbfaf91a7cac27e9c5aea525ee53de7b2d3332c8644402b82" + 
                "3e94a7db26276d2d23aa07180f76b4fd29b9c0823099c9d62c519880aee7e969" + 
                "7617c1497d47bf3e571950311421b6b734d38b0db91eb85331b91ea9f61530f5" + 
                "4512a5a52a4bad589eb69781d537f23297bb459bdad2948a29e1550bf4787e0b" + 
                "e95bb173cf5fab17dab7a13a052a63453d97ccec1a321954886b7a1299faaeec" + 
                "ae35c6eaaca753b041b5e5f093bf83397fd21dd6b3012066fcc058cc32c3b09d" + 
                "7562dee29509b5839392c9ff05f51f3166aaac4ac5f238038a3045e6f72e48ef" + 
                "0fe8bc675e82c318a268e43970271bf119b81bf6a982746554f84e72b9f00280" + 
                "a320a08142923c23c883423ff949827f29bbacdc1ccdb04938ce6098c95ba6b3" + 
                "2528f4ef78eed778b2e122ddfd1cbdd11d1c0a6783e011fc536d63d053260637",
                expected:
                "72efc1ebfe1ee25975a6eb3aa8589dda2b261f1c85bdab442a9e5b2dd1d7c395" + 
                "7a16fc08e526d4b1223f1b1232a11af274c3d70dac57f83e0983c498f1a6f1ae" + 
                "cb021c3e70085a1e527f1ce41ee5911a82020161529cd82773762daf5459de94" + 
                "a0a82adae7e1703c808543c29ed6fb32d9e004327c1355180c995a07741493a0" + 
                "9c21ba01a387882da4f62534b87bb15d60d197201c0fd3bf30c1500a3ecfecdd" + 
                "66d8721f90bcc4c17ee925c61b0a03727a9c0d5f5ca462fbfa0af1c2513a9d9d" + 
                "4b5345bd27a5f6e653f751693e6b6a2b8ead57d511e00e58c45b7b8d005af792" + 
                "88f5c7c22fd4f1bf7a898b03a5634c6a1ae3f9fae5de4f296a2896b23e7ed43e" + 
                "d14fa5a2803f4d28f0d3ffcf24757677aebdb47bb388378708948a8d4126ed18" + 
                "39e0da29a537a8c198b3c66ab00712dd261674bf45a73d67f76914f830ca014b" + 
                "65596f27e4cf62de66125a5566df9975155628b400fbfb3a29040ed50faffdbb" + 
                "18aece7c5c44693260aab386c0a37b11b114f1c415aebb653be468179428d43a" + 
                "4d8bc3ec38813eca30a13cf1bb18d524f1992d44d8b1a42ea30b22e6c95b199d" + 
                "8d182f8840b09d059585c31ad691fa0619ff038aca2c39a943421157361717c4" + 
                "9d322028a74648113bd8c9d7ec77cf3c89c1ec8718ceff8516d96b34c3c614f1" + 
                "0699c9abc4ed0411506223bea16af35c883accdbe1104eef0cfdb54e12fb230a"
            },
    
            {
                count: 9,
                key1: "27182818284590452353602874713526",
                key2: "31415926535897932384626433832795",
                dataUnitSerial: "ff",
                pt:
                "72efc1ebfe1ee25975a6eb3aa8589dda2b261f1c85bdab442a9e5b2dd1d7c395" + 
                "7a16fc08e526d4b1223f1b1232a11af274c3d70dac57f83e0983c498f1a6f1ae" + 
                "cb021c3e70085a1e527f1ce41ee5911a82020161529cd82773762daf5459de94" + 
                "a0a82adae7e1703c808543c29ed6fb32d9e004327c1355180c995a07741493a0" + 
                "9c21ba01a387882da4f62534b87bb15d60d197201c0fd3bf30c1500a3ecfecdd" + 
                "66d8721f90bcc4c17ee925c61b0a03727a9c0d5f5ca462fbfa0af1c2513a9d9d" + 
                "4b5345bd27a5f6e653f751693e6b6a2b8ead57d511e00e58c45b7b8d005af792" + 
                "88f5c7c22fd4f1bf7a898b03a5634c6a1ae3f9fae5de4f296a2896b23e7ed43e" + 
                "d14fa5a2803f4d28f0d3ffcf24757677aebdb47bb388378708948a8d4126ed18" + 
                "39e0da29a537a8c198b3c66ab00712dd261674bf45a73d67f76914f830ca014b" + 
                "65596f27e4cf62de66125a5566df9975155628b400fbfb3a29040ed50faffdbb" + 
                "18aece7c5c44693260aab386c0a37b11b114f1c415aebb653be468179428d43a" +  
                "4d8bc3ec38813eca30a13cf1bb18d524f1992d44d8b1a42ea30b22e6c95b199d" + 
                "8d182f8840b09d059585c31ad691fa0619ff038aca2c39a943421157361717c4" + 
                "9d322028a74648113bd8c9d7ec77cf3c89c1ec8718ceff8516d96b34c3c614f1" + 
                "0699c9abc4ed0411506223bea16af35c883accdbe1104eef0cfdb54e12fb230a",
                expected:
                "3260ae8dad1f4a32c5cafe3ab0eb95549d461a67ceb9e5aa2d3afb62dece0553" + 
                "193ba50c75be251e08d1d08f1088576c7efdfaaf3f459559571e12511753b07a" + 
                "f073f35da06af0ce0bbf6b8f5ccc5cea500ec1b211bd51f63b606bf6528796ca" + 
                "12173ba39b8935ee44ccce646f90a45bf9ccc567f0ace13dc2d53ebeedc81f58" + 
                "b2e41179dddf0d5a5c42f5d8506c1a5d2f8f59f3ea873cbcd0eec19acbf32542" + 
                "3bd3dcb8c2b1bf1d1eaed0eba7f0698e4314fbeb2f1566d1b9253008cbccf45a" + 
                "2b0d9c5c9c21474f4076e02be26050b99dee4fd68a4cf890e496e4fcae7b70f9" + 
                "4ea5a9062da0daeba1993d2ccd1dd3c244b8428801495a58b216547e7e847c46" + 
                "d1d756377b6242d2e5fb83bf752b54e0df71e889f3a2bb0f4c10805bf3c59037" + 
                "6e3c24e22ff57f7fa965577375325cea5d920db94b9c336b455f6e894c01866f" + 
                "e9fbb8c8d3f70a2957285f6dfb5dcd8cbf54782f8fe7766d4723819913ac7734" + 
                "21e3a31095866bad22c86a6036b2518b2059b4229d18c8c2ccbdf906c6cc6e82" + 
                "464ee57bddb0bebcb1dc645325bfb3e665ef7251082c88ebb1cf203bd779fdd3" + 
                "8675713c8daadd17e1cabee432b09787b6ddf3304e38b731b45df5df51b78fcf" + 
                "b3d32466028d0ba36555e7e11ab0ee0666061d1645d962444bc47a38188930a8" + 
                "4b4d561395c73c087021927ca638b7afc8a8679ccb84c26555440ec7f10445cd"
            },
    
        // XTS-AES-256 applied for a data unit of 512 bytes
    
            {
                count: 10,
                key1: "2718281828459045235360287471352662497757247093699959574966967627",
                key2: "3141592653589793238462643383279502884197169399375105820974944592",
                dataUnitSerial: "ff",
                pt:
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" + 
                "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" + 
                "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f" + 
                "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f" + 
                "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f" + 
                "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf" + 
                "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf" + 
                "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff" + 
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" + 
                "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" + 
                "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f" + 
                "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f" + 
                "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f" + 
                "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf" + 
                "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf" + 
                "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
                expected:
                "1c3b3a102f770386e4836c99e370cf9bea00803f5e482357a4ae12d414a3e63b" + 
                "5d31e276f8fe4a8d66b317f9ac683f44680a86ac35adfc3345befecb4bb188fd" + 
                "5776926c49a3095eb108fd1098baec70aaa66999a72a82f27d848b21d4a741b0" + 
                "c5cd4d5fff9dac89aeba122961d03a757123e9870f8acf1000020887891429ca" + 
                "2a3e7a7d7df7b10355165c8b9a6d0a7de8b062c4500dc4cd120c0f7418dae3d0" + 
                "b5781c34803fa75421c790dfe1de1834f280d7667b327f6c8cd7557e12ac3a0f" + 
                "93ec05c52e0493ef31a12d3d9260f79a289d6a379bc70c50841473d1a8cc81ec" + 
                "583e9645e07b8d9670655ba5bbcfecc6dc3966380ad8fecb17b6ba02469a020a" + 
                "84e18e8f84252070c13e9f1f289be54fbc481457778f616015e1327a02b140f1" + 
                "505eb309326d68378f8374595c849d84f4c333ec4423885143cb47bd71c5edae" + 
                "9be69a2ffeceb1bec9de244fbe15992b11b77c040f12bd8f6a975a44a0f90c29" + 
                "a9abc3d4d893927284c58754cce294529f8614dcd2aba991925fedc4ae74ffac" + 
                "6e333b93eb4aff0479da9a410e4450e0dd7ae4c6e2910900575da401fc07059f" + 
                "645e8b7e9bfdef33943054ff84011493c27b3429eaedb4ed5376441a77ed4385" + 
                "1ad77f16f541dfd269d50d6a5f14fb0aab1cbb4c1550be97f7ab4066193c4caa" + 
                "773dad38014bd2092fa755c824bb5e54c4f36ffda9fcea70b9c6e693e148c151"
            },
    
            {
                count: 11,
                key1: "2718281828459045235360287471352662497757247093699959574966967627",
                key2: "3141592653589793238462643383279502884197169399375105820974944592",
                dataUnitSerial: "ffff",
                pt:
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" + 
                "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" + 
                "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f" + 
                "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f" + 
                "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f" + 
                "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf" + 
                "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf" + 
                "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff" + 
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" + 
                "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" + 
                "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f" + 
                "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f" + 
                "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f" + 
                "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf" + 
                "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf" + 
                "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
                expected:
                "77a31251618a15e6b92d1d66dffe7b50b50bad552305ba0217a610688eff7e11" + 
                "e1d0225438e093242d6db274fde801d4cae06f2092c728b2478559df58e837c2" + 
                "469ee4a4fa794e4bbc7f39bc026e3cb72c33b0888f25b4acf56a2a9804f1ce6d" + 
                "3d6e1dc6ca181d4b546179d55544aa7760c40d06741539c7e3cd9d2f6650b201" + 
                "3fd0eeb8c2b8e3d8d240ccae2d4c98320a7442e1c8d75a42d6e6cfa4c2eca179" + 
                "8d158c7aecdf82490f24bb9b38e108bcda12c3faf9a21141c3613b58367f922a" + 
                "aa26cd22f23d708dae699ad7cb40a8ad0b6e2784973dcb605684c08b8d6998c6" + 
                "9aac049921871ebb65301a4619ca80ecb485a31d744223ce8ddc2394828d6a80" + 
                "470c092f5ba413c3378fa6054255c6f9df4495862bbb3287681f931b687c888a" + 
                "bf844dfc8fc28331e579928cd12bd2390ae123cf03818d14dedde5c0c24c8ab0" + 
                "18bfca75ca096f2d531f3d1619e785f1ada437cab92e980558b3dce1474afb75" + 
                "bfedbf8ff54cb2618e0244c9ac0d3c66fb51598cd2db11f9be39791abe447c63" + 
                "094f7c453b7ff87cb5bb36b7c79efb0872d17058b83b15ab0866ad8a58656c5a" + 
                "7e20dbdf308b2461d97c0ec0024a2715055249cf3b478ddd4740de654f75ca68" + 
                "6e0d7345c69ed50cdc2a8b332b1f8824108ac937eb050585608ee734097fc090" + 
                "54fbff89eeaeea791f4a7ab1f9868294a4f9e27b42af8100cb9d59cef9645803"
            },
    
            {
                count: 12,
                key1: "2718281828459045235360287471352662497757247093699959574966967627",
                key2: "3141592653589793238462643383279502884197169399375105820974944592",
                dataUnitSerial: "ffffff",
                pt:
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" + 
                "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" + 
                "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f" + 
                "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f" + 
                "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f" + 
                "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf" + 
                "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf" + 
                "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff" + 
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" + 
                "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" + 
                "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f" + 
                "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f" + 
                "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f" + 
                "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf" + 
                "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf" + 
                "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
                expected:
                "e387aaa58ba483afa7e8eb469778317ecf4cf573aa9d4eac23f2cdf914e4e200" + 
                "a8b490e42ee646802dc6ee2b471b278195d60918ececb44bf79966f83faba049" + 
                "9298ebc699c0c8634715a320bb4f075d622e74c8c932004f25b41e361025b5a8" + 
                "7815391f6108fc4afa6a05d9303c6ba68a128a55705d415985832fdeaae6c8e1" + 
                "9110e84d1b1f199a2692119edc96132658f09da7c623efcec712537a3d94c0bf" +  
                "5d7e352ec94ae5797fdb377dc1551150721adf15bd26a8efc2fcaad56881fa9e" + 
                "62462c28f30ae1ceaca93c345cf243b73f542e2074a705bd2643bb9f7cc79bb6" + 
                "e7091ea6e232df0f9ad0d6cf502327876d82207abf2115cdacf6d5a48f6c1879" + 
                "a65b115f0f8b3cb3c59d15dd8c769bc014795a1837f3901b5845eb491adfefe0" + 
                "97b1fa30a12fc1f65ba22905031539971a10f2f36c321bb51331cdefb39e3964" + 
                "c7ef079994f5b69b2edd83a71ef549971ee93f44eac3938fcdd61d01fa71799d" + 
                "a3a8091c4c48aa9ed263ff0749df95d44fef6a0bb578ec69456aa5408ae32c7a" + 
                "f08ad7ba8921287e3bbee31b767be06a0e705c864a769137df28292283ea81a2" + 
                "480241b44d9921cdbec1bc28dc1fda114bd8e5217ac9d8ebafa720e9da4f9ace" + 
                "231cc949e5b96fe76ffc21063fddc83a6b8679c00d35e09576a875305bed5f36" + 
                "ed242c8900dd1fa965bc950dfce09b132263a1eef52dd6888c309f5a7d712826"
            },
    
            {
                count: 13,
                key1: "2718281828459045235360287471352662497757247093699959574966967627",
                key2: "3141592653589793238462643383279502884197169399375105820974944592",
                dataUnitSerial: "ffffffff",
                pt:
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" + 
                "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" + 
                "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f" + 
                "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f" + 
                "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f" + 
                "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf" + 
                "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf" + 
                "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff" + 
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" + 
                "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" + 
                "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f" + 
                "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f" + 
                "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f" + 
                "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf" + 
                "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf" + 
                "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
                expected:
                "bf53d2dade78e822a4d949a9bc6766b01b06a8ef70d26748c6a7fc36d80ae4c5" + 
                "520f7c4ab0ac8544424fa405162fef5a6b7f229498063618d39f0003cb5fb8d1" + 
                "c86b643497da1ff945c8d3bedeca4f479702a7a735f043ddb1d6aaade3c4a0ac" + 
                "7ca7f3fa5279bef56f82cd7a2f38672e824814e10700300a055e1630b8f1cb0e" + 
                "919f5e942010a416e2bf48cb46993d3cb6a51c19bacf864785a00bc2ecff15d3" + 
                "50875b246ed53e68be6f55bd7e05cfc2b2ed6432198a6444b6d8c247fab941f5" + 
                "69768b5c429366f1d3f00f0345b96123d56204c01c63b22ce78baf116e525ed9" + 
                "0fdea39fa469494d3866c31e05f295ff21fea8d4e6e13d67e47ce722e9698a1c" + 
                "1048d68ebcde76b86fcf976eab8aa9790268b7068e017a8b9b749409514f1053" + 
                "027fd16c3786ea1bac5f15cb79711ee2abe82f5cf8b13ae73030ef5b9e4457e7" + 
                "5d1304f988d62dd6fc4b94ed38ba831da4b7634971b6cd8ec325d9c61c00f1df" + 
                "73627ed3745a5e8489f3a95c69639c32cd6e1d537a85f75cc844726e8a72fc00" + 
                "77ad22000f1d5078f6b866318c668f1ad03d5a5fced5219f2eabbd0aa5c0f460" + 
                "d183f04404a0d6f469558e81fab24a167905ab4c7878502ad3e38fdbe62a4155" + 
                "6cec37325759533ce8f25f367c87bb5578d667ae93f9e2fd99bcbc5f2fbba88c" + 
                "f6516139420fcff3b7361d86322c4bd84c82f335abb152c4a93411373aaa8220"
            },
    
            {
                count: 14,
                key1: "2718281828459045235360287471352662497757247093699959574966967627",
                key2: "3141592653589793238462643383279502884197169399375105820974944592",
                dataUnitSerial: "ffffffffff",
                pt:
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" + 
                "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" + 
                "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f" + 
                "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f" + 
                "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f" + 
                "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf" + 
                "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf" + 
                "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff" + 
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +  
                "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" + 
                "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f" + 
                "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f" + 
                "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f" + 
                "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf" + 
                "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf" + 
                "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
                expected:
                "64497e5a831e4a932c09be3e5393376daa599548b816031d224bbf50a818ed23" + 
                "50eae7e96087c8a0db51ad290bd00c1ac1620857635bf246c176ab463be30b80" + 
                "8da548081ac847b158e1264be25bb0910bbc92647108089415d45fab1b3d2604" + 
                "e8a8eff1ae4020cfa39936b66827b23f371b92200be90251e6d73c5f86de5fd4" + 
                "a950781933d79a28272b782a2ec313efdfcc0628f43d744c2dc2ff3dcb66999b" + 
                "50c7ca895b0c64791eeaa5f29499fb1c026f84ce5b5c72ba1083cddb5ce45434" + 
                "631665c333b60b11593fb253c5179a2c8db813782a004856a1653011e93fb6d8" + 
                "76c18366dd8683f53412c0c180f9c848592d593f8609ca736317d356e13e2bff" + 
                "3a9f59cd9aeb19cd482593d8c46128bb32423b37a9adfb482b99453fbe25a41b" + 
                "f6feb4aa0bef5ed24bf73c762978025482c13115e4015aac992e5613a3b5c2f6" + 
                "85b84795cb6e9b2656d8c88157e52c42f978d8634c43d06fea928f2822e465aa" + 
                "6576e9bf419384506cc3ce3c54ac1a6f67dc66f3b30191e698380bc999b05abc" + 
                "e19dc0c6dcc2dd001ec535ba18deb2df1a101023108318c75dc98611a09dc48a" + 
                "0acdec676fabdf222f07e026f059b672b56e5cbc8e1d21bbd867dd9272120546" + 
                "81d70ea737134cdfce93b6f82ae22423274e58a0821cc5502e2d0ab4585e94de" + 
                "6975be5e0b4efce51cd3e70c25a1fbbbd609d273ad5b0d59631c531f6a0a57b9"
            },
    
        // XTS-AES-128 applied for a data unit that is not a multiple of 16 bytes
    
            {
                count: 15,
                key1: "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0",
                key2: "bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0",
                dataUnitSerial: "9a78563412",
                pt:       "000102030405060708090a0b0c0d0e0f10",
                expected: "6c1625db4671522d3d7599601de7ca09ed"
            },
    
            {
                count: 16,
                key1: "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0",
                key2: "bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0",
                dataUnitSerial: "9a78563412",
                pt:       "000102030405060708090a0b0c0d0e0f1011",
                expected: "d069444b7a7e0cab09e24447d24deb1fedbf"
            },
    
            {
                count: 17,
                key1: "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0",
                key2: "bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0",
                dataUnitSerial: "9a78563412",
                pt:       "000102030405060708090a0b0c0d0e0f101112",
                expected: "e5df1351c0544ba1350b3363cd8ef4beedbf9d"
            },
    
            {
                count: 18,
                key1: "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0",
                key2: "bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0",
                dataUnitSerial: "9a78563412",
                pt:       "000102030405060708090a0b0c0d0e0f10111213",
                expected: "9d84c813f719aa2c7be3f66171c7c5c2edbf9dac"
            },
    
            {
                count: 19,
                key1: "e0e1e2e3e4e5e6e7e8e9eaebecedeeef",
                key2: "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf",
                dataUnitSerial: "21436587a9",
                pt:
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +  
                "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" + 
                "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f" + 
                "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f" + 
                "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f" + 
                "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf" + 
                "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf" + 
                "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff" + 
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" + 
                "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" + 
                "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f" + 
                "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f" + 
                "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f" + 
                "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf" + 
                "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf" + 
                "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
                expected:
                "38b45812ef43a05bd957e545907e223b954ab4aaf088303ad910eadf14b42be6" + 
                "8b2461149d8c8ba85f992be970bc621f1b06573f63e867bf5875acafa04e42cc" + 
                "bd7bd3c2a0fb1fff791ec5ec36c66ae4ac1e806d81fbf709dbe29e471fad3854" + 
                "9c8e66f5345d7c1eb94f405d1ec785cc6f6a68f6254dd8339f9d84057e01a177" + 
                "41990482999516b5611a38f41bb6478e6f173f320805dd71b1932fc333cb9ee3" + 
                "9936beea9ad96fa10fb4112b901734ddad40bc1878995f8e11aee7d141a2f5d4" + 
                "8b7a4e1e7f0b2c04830e69a4fd1378411c2f287edf48c6c4e5c247a19680f7fe" + 
                "41cefbd49b582106e3616cbbe4dfb2344b2ae9519391f3e0fb4922254b1d6d2d" + 
                "19c6d4d537b3a26f3bcc51588b32f3eca0829b6a5ac72578fb814fb43cf80d64" + 
                "a233e3f997a3f02683342f2b33d25b492536b93becb2f5e1a8b82f5b88334272" + 
                "9e8ae09d16938841a21a97fb543eea3bbff59f13c1a18449e398701c1ad51648" + 
                "346cbc04c27bb2da3b93a1372ccae548fb53bee476f9e9c91773b1bb19828394" + 
                "d55d3e1a20ed69113a860b6829ffa847224604435070221b257e8dff783615d2" + 
                "cae4803a93aa4334ab482a0afac9c0aeda70b45a481df5dec5df8cc0f423c77a" + 
                "5fd46cd312021d4b438862419a791be03bb4d97c0e59578542531ba466a83baf" + 
                "92cefc151b5cc1611a167893819b63fb8a6b18e86de60290fa72b797b0ce59f3"
            }
    
        ];
    
        for (var i = 0; i < testVectors.length; i++) {
            var vector = testVectors[i];
    
            key = Buffer.from(vector.key1, 'hex');
            tweakKey = Buffer.from(vector.key2, 'hex');
    
            var expected = Buffer.from(vector.expected, 'hex');
            var pt = Buffer.from(vector.pt, 'hex');
            var dataUnitSerial = vector.dataUnitSerial;
            var count = vector.count;
    //		var tweak = null;
            
            var algo_name = 'aes-128';
    
            var cipher = new jCastle.mcrypt(algo_name);
            cipher.start({
                key: key,
                tweakKey: tweakKey,
                dataUnitSerial: dataUnitSerial,
                mode: 'xts',
    //			tweak: tweak,
                direction: true
            });
    
            var ct = cipher.update(pt).finalize();
    
            var v = ct.equals(expected);
    
            assert.ok(v, count + ' - Encryption Passed!');
    
            var cipher = new jCastle.mcrypt(algo_name);
            cipher.start({
                key: key,
                tweakKey: tweakKey,
                dataUnitSerial: dataUnitSerial,
                mode: 'xts',
    //			tweak: tweak,
                direction: false
            });
    
            var dt = cipher.update(ct).finalize();
    
            v = dt.equals(pt);
            assert.ok(v, count + ' - Decryption Passed!');
        }
    
        // 
        // Test when dataUnitSerial is a number.
        //
    
        var key = "2718281828459045235360287471352662497757247093699959574966967627";
        var tweakKey = "3141592653589793238462643383279502884197169399375105820974944592";
        var dataUnitSerial = "00000000000000ff";
        var plainText = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                      + "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
                      + "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
                      + "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
                      + "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
                      + "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
                      + "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
                      + "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
                      + "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                      + "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
                      + "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
                      + "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
                      + "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
                      + "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
                      + "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
                      + "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
        var cipherText = "1c3b3a102f770386e4836c99e370cf9bea00803f5e482357a4ae12d414a3e63b"
                       + "5d31e276f8fe4a8d66b317f9ac683f44680a86ac35adfc3345befecb4bb188fd"
                       + "5776926c49a3095eb108fd1098baec70aaa66999a72a82f27d848b21d4a741b0"
                       + "c5cd4d5fff9dac89aeba122961d03a757123e9870f8acf1000020887891429ca"
                       + "2a3e7a7d7df7b10355165c8b9a6d0a7de8b062c4500dc4cd120c0f7418dae3d0"
                       + "b5781c34803fa75421c790dfe1de1834f280d7667b327f6c8cd7557e12ac3a0f"
                       + "93ec05c52e0493ef31a12d3d9260f79a289d6a379bc70c50841473d1a8cc81ec"
                       + "583e9645e07b8d9670655ba5bbcfecc6dc3966380ad8fecb17b6ba02469a020a"
                       + "84e18e8f84252070c13e9f1f289be54fbc481457778f616015e1327a02b140f1"
                       + "505eb309326d68378f8374595c849d84f4c333ec4423885143cb47bd71c5edae"
                       + "9be69a2ffeceb1bec9de244fbe15992b11b77c040f12bd8f6a975a44a0f90c29"
                       + "a9abc3d4d893927284c58754cce294529f8614dcd2aba991925fedc4ae74ffac"
                       + "6e333b93eb4aff0479da9a410e4450e0dd7ae4c6e2910900575da401fc07059f"
                       + "645e8b7e9bfdef33943054ff84011493c27b3429eaedb4ed5376441a77ed4385"
                       + "1ad77f16f541dfd269d50d6a5f14fb0aab1cbb4c1550be97f7ab4066193c4caa"
                       + "773dad38014bd2092fa755c824bb5e54c4f36ffda9fcea70b9c6e693e148c151";
    
        key = Buffer.from(key, 'hex');
        tweakKey = Buffer.from(tweakKey, 'hex');
    
        var expected = Buffer.from(cipherText, 'hex');
        var pt = Buffer.from(plainText, 'hex');
        
        var algo_name = 'aes-128';
        
        //
        // IMPORTANT!
        //
        // when dataUnitSerial is untouched and is given, 
        // then returned output will be different.
        // it need to be converted to a number.
        //
        dataUnitSerial = parseInt(dataUnitSerial, 16);
    
        var cipher = new jCastle.mcrypt(algo_name);
        cipher.start({
            key: key,
            tweakKey: tweakKey,
            dataUnitSerial: dataUnitSerial,
            mode: 'xts',
            direction: true
        });
    
        var ct = cipher.update(pt).finalize();
    
        assert.ok(ct.equals(expected), 'Encryption Passed!');
    
        
        var cipher = new jCastle.mcrypt(algo_name);
        cipher.start({
            key: key,
            tweakKey: tweakKey,
            dataUnitSerial: dataUnitSerial,
            mode: 'xts',
            direction: false
        });
    
        var dt = cipher.update(ct).finalize();
    
        assert.ok(dt.equals(pt), 'Decryption Passed!');
    
    });
    
    
    //
    // CTS mode
    //
    
    QUnit.module('AES-CTS');
    QUnit.test("Vector Test", function(assert) {
    
    //
    //CTS-AES Encrypt / Decrypt
    //
    /*
    https://tools.ietf.org/html/rfc3962
    
       Some test vectors for CBC with ciphertext stealing, using an initial
       vector of all-zero.
    */
    
        var key = '63 68 69 63 6b 65 6e 20 74 65 72 69 79 61 6b 69';
        var iv = '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00';
    
        var testVectors = [
            [
                '49 20 77 6f 75 6c 64 20 6c 69 6b 65 20 74 68 65' +
                '20',
                'c6 35 35 68 f2 bf 8c b4 d8 a5 80 36 2d a7 ff 7f' + 
                '97'
            ],
            [
                '49 20 77 6f 75 6c 64 20 6c 69 6b 65 20 74 68 65' + 
                '20 47 65 6e 65 72 61 6c 20 47 61 75 27 73 20',
                'fc 00 78 3e 0e fd b2 c1 d4 45 d4 c8 ef f7 ed 22' + 
                '97 68 72 68 d6 ec cc c0 c0 7b 25 e2 5e cf e5'
            ],
            [
                '49 20 77 6f 75 6c 64 20 6c 69 6b 65 20 74 68 65' + 
                '20 47 65 6e 65 72 61 6c 20 47 61 75 27 73 20 43',
                '39 31 25 23 a7 86 62 d5 be 7f cb cc 98 eb f5 a8' + 
                '97 68 72 68 d6 ec cc c0 c0 7b 25 e2 5e cf e5 84'
            ],
            [
                '49 20 77 6f 75 6c 64 20 6c 69 6b 65 20 74 68 65' + 
                '20 47 65 6e 65 72 61 6c 20 47 61 75 27 73 20 43' + 
                '68 69 63 6b 65 6e 2c 20 70 6c 65 61 73 65 2c',
                '97 68 72 68 d6 ec cc c0 c0 7b 25 e2 5e cf e5 84' + 
                'b3 ff fd 94 0c 16 a1 8c 1b 55 49 d2 f8 38 02 9e' + 
                '39 31 25 23 a7 86 62 d5 be 7f cb cc 98 eb f5'
            ],
            [
                '49 20 77 6f 75 6c 64 20 6c 69 6b 65 20 74 68 65' + 
                '20 47 65 6e 65 72 61 6c 20 47 61 75 27 73 20 43' + 
                '68 69 63 6b 65 6e 2c 20 70 6c 65 61 73 65 2c 20',
                '97 68 72 68 d6 ec cc c0 c0 7b 25 e2 5e cf e5 84' + 
                '9d ad 8b bb 96 c4 cd c0 3b c1 03 e1 a1 94 bb d8' + 
                '39 31 25 23 a7 86 62 d5 be 7f cb cc 98 eb f5 a8'
            ],
            [
                '49 20 77 6f 75 6c 64 20 6c 69 6b 65 20 74 68 65' +
                '20 47 65 6e 65 72 61 6c 20 47 61 75 27 73 20 43' + 
                '68 69 63 6b 65 6e 2c 20 70 6c 65 61 73 65 2c 20' + 
                '61 6e 64 20 77 6f 6e 74 6f 6e 20 73 6f 75 70 2e',
                '97 68 72 68 d6 ec cc c0 c0 7b 25 e2 5e cf e5 84' + 
                '39 31 25 23 a7 86 62 d5 be 7f cb cc 98 eb f5 a8' + 
                '48 07 ef e8 36 ee 89 a5 26 73 0d bc 2f 7b c8 40' + 
                '9d ad 8b bb 96 c4 cd c0 3b c1 03 e1 a1 94 bb d8'
            ]
        ];
    
        var algo_name = 'aes-128';
        var key = Buffer.from(key.replace(/[ \:]/g, ''), 'hex');
        var iv = Buffer.from(iv.replace(/[ \:]/g, ''), 'hex');
    
        for (var i = 0; i < testVectors.length; i++) {
            var vector = testVectors[i];
            var pt = Buffer.from(vector[0].replace(/[ \:]/g, ''), 'hex');
            var expected = Buffer.from(vector[1].replace(/[ \:]/g, ''), 'hex');
    
            var cipher = new jCastle.mcrypt(algo_name);
    
            cipher.start({
                key: key,
                iv: iv,
                mode: 'cts',
                direction: true
            });
    
            var ct = cipher.update(pt).finalize();
    
            assert.ok(ct.equals(expected), 'Encryption Passed!');
    
            var cipher = new jCastle.mcrypt(algo_name);
            cipher.start({
                key: key,
                iv: iv,
                mode: 'cts',
                direction: false
            });
    
            var dt = cipher.update(ct).finalize();
    
            assert.ok(dt.equals(pt), 'Decryption Passed!');
        }
    
    });

//
// CWC mode
//
QUnit.module('AES-CWC');
QUnit.test("Vector Test", function(assert) {

    //
    //CWC-AES Encrypt / Decrypt
    //
    
        // from test vectors
        // https://tools.ietf.org/id/draft-irtf-cfrg-cwc-00.txt
    
        var testVectors = [
            // Vector #1:  CWC-AES-16
            {
                key:   '00 01 02 03  04 05 06 07  08 09 0A 0B  0C 0D 0E 0F',
                pt:    '00 01 02 03  04 05 06 07',
                aad:   '',
                nonce: 'FF EE DD CC  BB AA 99 88  77 66 55',
                //--------------------------------------------------------------
                //HASH KEY:   34 AE 6A 6F  E9 51 78 94  AC CC BB 9E  BA E7 20 8C
                //HASH VALUE: 2B 9E AE BE  67 3F AE 03  6B 16 EA 31  DC A7 AE 6B
                //AES(HVAL):  FC DC 06 4C  CD CA FE E3  DE 7A A3 CF  5C 5D B9 7B
                //MAC CTR PT: 80 FF EE DD  CC BB AA 99  88 77 66 55  00 00 00 00
                //AES(MCPT):  AB 89 DD E9  C4 55 C1 FE  BE 7E E7 58  82 D4 8A D2
                ct:    '88 B8 DF 06  28 FD 51 CC  57 55 DB A5  09 9F 3F 1D' +
                       '60 04 44 97  DE 89 33 A9'
            },
    
            // Vector #2:  CWC-AES-24
            {
                key:   '00 01 02 03  04 05 06 07  08 09 0A 0B  0C 0D 0E 0F' + 
                       'F0 E0 D0 C0  B0 A0 90 80',
                pt:    '00 01 02 03  04 05 06 07',
                aad:   '',
                nonce: 'FF EE DD CC  BB AA 99 88  77 66 55',
                //--------------------------------------------------------------
                //HASH KEY:   4F A8 88 AF  06 83 60 0C  AB 35 75 EF  0A E6 01 A5
                //HASH VALUE: 40 E6 24 83  4B 27 9A 7B  15 42 C7 FE  29 EB 29 A3
                //AES(HVAL):  69 CC 0E 3D  96 98 EB 75  1F 06 A5 90  9B C2 4F 5A
                //MAC CTR PT: 80 FF EE DD  CC BB AA 99  88 77 66 55  00 00 00 00
                //AES(MCPT):  C6 B6 F4 33  F9 12 39 4F  6A 8C B9 D3  F2 7B 0C 72
                ct:    'F0 DB A9 74  12 30 01 B0  AF 7A FA 0E  6F 8A D2 3A' + 
                       '75 8A 1C 43  69 B9 43 28'
            },
    
            // Vector #3:  CWC-AES-32
            {
                key:   '00 01 02 03  04 05 06 07  08 09 0A 0B  0C 0D 0E 0F' +
                       'F0 E0 D0 C0  B0 A0 90 80  70 60 50 40  30 20 10 00',
                pt:    '00 01 02 03  04 05 06 07',
                aad:   '',
                nonce: 'FF EE DD CC  BB AA 99 88  77 66 55',
                //--------------------------------------------------------------
                //HASH KEY:   35 8F 2B 0C  FF E9 84 BE  F9 EE EE 55  85 36 BC E5
                //HASH VALUE: 18 99 E1 A6  1E 6E 37 65  C6 3A 41 99  56 8C D1 BF
                //AES(HVAL):  1C 56 65 0A  22 BC B5 94  AC F3 CA 24  46 03 B8 5E
                //MAC CTR PT: 80 FF EE DD  CC BB AA 99  88 77 66 55  00 00 00 00
                //AES(MCPT):  92 0A 3B 46  82 25 16 F1  5A A3 1B AE  8D EB 72 A0
                ct:    '7B CF 73 BE  46 9C 46 0B  8E 5C 5E 4C  A0 99 A3 65' +
                       'F6 50 D1 8A  CB E8 CA FE'
            },
    
            // Vector #4:  CWC-AES-16
            {
                key:   '00 01 02 03  04 05 06 07  08 09 0A 0B  0C 0D 0E 0F',
                pt:    '00 01 02 03  04 05 06 07',
                aad:   '54 68 69 73  20 69 73 20  61 20 70 6C  61 69 6E 74' +
                       '65 78 74 20  68 65 61 64  65 72 2E 00',
                nonce: 'FF EE DD CC  BB AA 99 88  77 66 55',
                //--------------------------------------------------------------
                //HASH KEY:   34 AE 6A 6F  E9 51 78 94  AC CC BB 9E  BA E7 20 8C
                //HASH VALUE: 2E A9 2A A5  28 B1 1C 08  1C C8 2F 24  9B E4 19 8D
                //AES(HVAL):  EA 54 F8 3D  56 7F 53 05  88 B1 EA 96  36 79 CD AC
                //MAC CTR PT: 80 FF EE DD  CC BB AA 99  88 77 66 55  00 00 00 00
                //AES(MCPT):  AB 89 DD E9  C4 55 C1 FE  BE 7E E7 58  82 D4 8A D2
                ct:    '88 B8 DF 06  28 FD 51 CC  41 DD 25 D4  92 2A 92 FB' +
                       '36 CF 0D CE  B4 AD 47 7E'
            },
    
            // Vector #5:  CWC-AES-24
            {
                key:   '00 01 02 03  04 05 06 07  08 09 0A 0B  0C 0D 0E 0F' +
                       'F0 E0 D0 C0  B0 A0 90 80',
                pt:    '00 01 02 03  04 05 06 07',
                aad:   '54 68 69 73  20 69 73 20  61 20 70 6C  61 69 6E 74' +
                       '65 78 74 20  68 65 61 64  65 72 2E 00',
                nonce: 'FF EE DD CC  BB AA 99 88  77 66 55',
                //--------------------------------------------------------------
                //HASH KEY:   4F A8 88 AF  06 83 60 0C  AB 35 75 EF  0A E6 01 A5
                //HASH VALUE: 60 3F FC 24  71 64 2E D9  57 E1 B1 EA  F2 F8 B0 34
                //AES(HVAL):  D8 39 86 2A  33 5A 54 68  C8 16 DA 47  69 A2 10 EB
                //MAC CTR PT: 80 FF EE DD  CC BB AA 99  88 77 66 55  00 00 00 00
                //AES(MCPT):  C6 B6 F4 33  F9 12 39 4F  6A 8C B9 D3  F2 7B 0C 72
                ct:    'F0 DB A9 74  12 30 01 B0  1E 8F 72 19  CA 48 6D 27' +
                       'A2 9A 63 94  9B D9 1C 99'
            },
    
            // Vector #6:  CWC-AES-32
            {
                key:   '00 01 02 03  04 05 06 07  08 09 0A 0B  0C 0D 0E 0F' +
                       'F0 E0 D0 C0  B0 A0 90 80  70 60 50 40  30 20 10 00',
                pt:    '00 01 02 03  04 05 06 07',
                aad:   '54 68 69 73  20 69 73 20  61 20 70 6C  61 69 6E 74' +
                       '65 78 74 20  68 65 61 64  65 72 2E 00',
                nonce: 'FF EE DD CC  BB AA 99 88  77 66 55',
                //--------------------------------------------------------------
                //HASH KEY:   35 8F 2B 0C  FF E9 84 BE  F9 EE EE 55  85 36 BC E5
                //HASH VALUE: 0A C6 B1 39  57 7F 26 DA  94 16 42 E1  6D 73 EC B5
                //AES(HVAL):  4B A5 AD 1E  74 A2 C5 BE  AB D0 DA 4D  F4 29 83 0C
                //MAC CTR PT: 80 FF EE DD  CC BB AA 99  88 77 66 55  00 00 00 00
                //AES(MCPT):  92 0A 3B 46  82 25 16 F1  5A A3 1B AE  8D EB 72 A0
                ct:    '7B CF 73 BE  46 9C 46 0B  D9 AF 96 58  F6 87 D3 4F' +
                       'F1 73 C1 E3  79 C2 F1 AC'
            },
    
            // Vector #7:  CWC-AES-16
            {
                key:   '00 01 02 03  04 05 06 07  08 09 0A 0B  0C 0D 0E 0F',
                pt:    '00 01 02 03  04 05 06 07  08 09 0A 0B  0C 0D 0E',
                aad:   '',
                nonce: 'FF EE DD CC  BB AA 99 88  77 66 55',
                //--------------------------------------------------------------
                //HASH KEY:   34 AE 6A 6F  E9 51 78 94  AC CC BB 9E  BA E7 20 8C
                //HASH VALUE: 79 00 74 72  E1 C8 36 96  ED 7A B1 F9  03 6E 94 8B
                //AES(HVAL):  2B 0F 24 69  B1 2B BE 39  C9 40 67 BA  F1 25 E2 5B
                //MAC CTR PT: 80 FF EE DD  CC BB AA 99  88 77 66 55  00 00 00 00
                //AES(MCPT):  AB 89 DD E9  C4 55 C1 FE  BE 7E E7 58  82 D4 8A D2
                ct:    '88 B8 DF 06  28 FD 51 CC  31 E6 6E 57  0B 0F 77 80' +
                       '86 F9 80 75  7E 7F C7 77  3E 80 E2 73  F1 68 89'
            },
    
            // Vector #8:  CWC-AES-24
            {
                key:   '00 01 02 03  04 05 06 07  08 09 0A 0B  0C 0D 0E 0F' +
                       'F0 E0 D0 C0  B0 A0 90 80',
                pt:    '00 01 02 03  04 05 06 07  08 09 0A 0B  0C 0D 0E',
                aad:   '',
                nonce: 'FF EE DD CC  BB AA 99 88  77 66 55',
                //--------------------------------------------------------------
                //HASH KEY:   4F A8 88 AF  06 83 60 0C  AB 35 75 EF  0A E6 01 A5
                //HASH VALUE: 2C 5E 3A A4  37 1C 27 D6  E8 6B 76 DC  3D 93 BC 87
                //AES(HVAL):  48 6E 9C E5  C3 16 3E A6  9C D4 D7 E2  7C 9D 92 D2
                //MAC CTR PT: 80 FF EE DD  CC BB AA 99  88 77 66 55  00 00 00 00
                //AES(MCPT):  C6 B6 F4 33  F9 12 39 4F  6A 8C B9 D3  F2 7B 0C 72
                ct:    'F0 DB A9 74  12 30 01 B0  E1 42 B7 58  87 C9 00 8E' +
                       'D8 68 D6 3A  04 07 E9 F6  58 6E 31 8E  E6 9E A0'
            },
    
            // Vector #9:  CWC-AES-32
            {
                key:   '00 01 02 03  04 05 06 07  08 09 0A 0B  0C 0D 0E 0F' +
                       'F0 E0 D0 C0  B0 A0 90 80  70 60 50 40  30 20 10 00',
                pt:    '00 01 02 03  04 05 06 07  08 09 0A 0B  0C 0D 0E',
                aad:   '',
                nonce: 'FF EE DD CC  BB AA 99 88  77 66 55',
                //--------------------------------------------------------------
                //HASH KEY:   35 8F 2B 0C  FF E9 84 BE  F9 EE EE 55  85 36 BC E5
                //HASH VALUE: 4A 70 29 CC  58 25 52 CB  75 AD C9 60  FF B3 F7 55
                //AES(HVAL):  2B 64 0E 02  CE 51 DE 22  B2 0F 2A 8D  C4 23 CD C0
                //MAC CTR PT: 80 FF EE DD  CC BB AA 99  88 77 66 55  00 00 00 00
                //AES(MCPT):  92 0A 3B 46  82 25 16 F1  5A A3 1B AE  8D EB 72 A0
                ct:    '7B CF 73 BE  46 9C 46 0B  9B C6 2D DE  26 DD 47 B9' +
                       '6E 35 44 4C  74 C8 D3 E8  AC 31 23 49  C8 BF 60'
            },
    
            // Vector #10: CWC-AES-16
            {
                key:   '00 01 02 03  04 05 06 07  08 09 0A 0B  0C 0D 0E 0F',
                pt:    '00 01 02 03  04 05 06 07  08 09 0A 0B  0C 0D 0E',
                aad:   '54 68 69 73  20 69 73 20  61 20 70 6C  61 69 6E 74' +
                       '65 78 74 20  68 65 61 64  65 72 2E 00',
                nonce: 'FF EE DD CC  BB AA 99 88  77 66 55',
                //--------------------------------------------------------------
                //HASH KEY:   34 AE 6A 6F  E9 51 78 94  AC CC BB 9E  BA E7 20 8C
                //HASH VALUE: 51 AE 9D 7E  86 BD E0 B2  AA 18 2C 91  87 0A 9C A5
                //AES(HVAL):  DF 48 30 BD  1D DC E0 59  B1 C2 0B 29  01 4F 80 10
                //MAC CTR PT: 80 FF EE DD  CC BB AA 99  88 77 66 55  00 00 00 00
                //AES(MCPT):  AB 89 DD E9  C4 55 C1 FE  BE 7E E7 58  82 D4 8A D2
                ct:   '88 B8 DF 06  28 FD 51 CC  31 E6 6E 57  0B 0F 77 74' +
                      'C1 ED 54 D9  89 21 A7 0F  BC EC 71 83  9B 0A C2'
            },
    
            // Vector #11: CWC-AES-24
            {
                key:   '00 01 02 03  04 05 06 07  08 09 0A 0B  0C 0D 0E 0F' +
                       'F0 E0 D0 C0  B0 A0 90 80',
                pt:    '00 01 02 03  04 05 06 07  08 09 0A 0B  0C 0D 0E',
                aad:   '54 68 69 73  20 69 73 20  61 20 70 6C  61 69 6E 74' +
                       '65 78 74 20  68 65 61 64  65 72 2E 00',
                nonce: 'FF EE DD CC  BB AA 99 88  77 66 55',
                //--------------------------------------------------------------
                //HASH KEY:   4F A8 88 AF  06 83 60 0C  AB 35 75 EF  0A E6 01 A5
                //HASH VALUE: 51 60 E7 81  DC 64 F9 CD  54 BA 02 40  A2 E8 EE 99
                //AES(HVAL):  A0 30 58 13  22 B6 80 53  64 B0 3E 52  41 D2 2D 0A
                //MAC CTR PT: 80 FF EE DD  CC BB AA 99  88 77 66 55  00 00 00 00
                //AES(MCPT):  C6 B6 F4 33  F9 12 39 4F  6A 8C B9 D3  F2 7B 0C 72
                ct:    'F0 DB A9 74  12 30 01 B0  E1 42 B7 58  87 C9 00 66' + 
                       '86 AC 20 DB  A4 B9 1C 0E  3C 87 81 B3  A9 21 78'
            },
    
            //Vector #12: CWC-AES-32
            {
                key:   '00 01 02 03  04 05 06 07  08 09 0A 0B  0C 0D 0E 0F' +
                       'F0 E0 D0 C0  B0 A0 90 80  70 60 50 40  30 20 10 00',
                pt:    '00 01 02 03  04 05 06 07  08 09 0A 0B  0C 0D 0E',
                aad:   '54 68 69 73  20 69 73 20  61 20 70 6C  61 69 6E 74' +
                       '65 78 74 20  68 65 61 64  65 72 2E 00',
                nonce: 'FF EE DD CC  BB AA 99 88  77 66 55',
                //--------------------------------------------------------------
                //HASH KEY:   35 8F 2B 0C  FF E9 84 BE  F9 EE EE 55  85 36 BC E5
                //HASH VALUE: 3F F5 0C 60  E6 01 7A 3C  A1 BB B3 54  65 02 85 7C
                //AES(HVAL):  3E EF A2 E4  97 91 82 86  73 0C F6 E9  46 2C CA 15
                //MAC CTR PT: 80 FF EE DD  CC BB AA 99  88 77 66 55  00 00 00 00
                //AES(MCPT):  92 0A 3B 46  82 25 16 F1  5A A3 1B AE  8D EB 72 A0
                ct:    '7B CF 73 BE  46 9C 46 0B  9B C6 2D DE  26 DD 47 AC' + 
                       'E5 99 A2 15  B4 94 77 29  AF ED 47 CB  C7 B8 B5'
            },
    
            // Vector #13: CWC-AES-16
            {
                key:   '00 01 02 03  04 05 06 07  08 09 0A 0B  0C 0D 0E 0F',
                pt:    '00 01 02 03  04 05 06 07  08 09 0A 0B  0C 0D 0E 0F' +
                       '80 81 82 83  84 85 86 87  88 89 8A 8B  8C 8D 8E 8F',
                aad:   '',
                nonce: 'FF EE DD CC  BB AA 99 88  77 66 55',
                //--------------------------------------------------------------
                //HASH KEY:   34 AE 6A 6F  E9 51 78 94  AC CC BB 9E  BA E7 20 8C
                //HASH VALUE: 58 D5 28 89  4F 1F 6A 52  A6 44 FA 69  65 C0 73 A6
                //AES(HVAL):  A3 9E F3 6F  67 1F FA F8  71 0C 83 BB  49 A6 6E BC
                //MAC CTR PT: 80 FF EE DD  CC BB AA 99  88 77 66 55  00 00 00 00
                //AES(MCPT):  AB 89 DD E9  C4 55 C1 FE  BE 7E E7 58  82 D4 8A D2
                ct:    '88 B8 DF 06  28 FD 51 CC  31 E6 6E 57  0B 0F 77 0F' +
                       '48 5B 82 64  6E CF B9 F9  A0 B0 75 4F  D5 94 36 5A' +
                       '08 17 2E 86  A3 4A 3B 06  CF 72 64 E3  CB 72 E4 6E'
            },
    
            // Vector #14:  CWC-AES-24
            {
                key:   '00 01 02 03  04 05 06 07  08 09 0A 0B  0C 0D 0E 0F' +
                       'F0 E0 D0 C0  B0 A0 90 80',
                pt:    '00 01 02 03  04 05 06 07  08 09 0A 0B  0C 0D 0E 0F' +
                       '80 81 82 83  84 85 86 87  88 89 8A 8B  8C 8D 8E 8F',
                aad:   '',
                nonce: 'FF EE DD CC  BB AA 99 88  77 66 55',
                //--------------------------------------------------------------
                //HASH KEY:   4F A8 88 AF  06 83 60 0C  AB 35 75 EF  0A E6 01 A5
                //HASH VALUE: 0D 0A D2 78  1E 8F E8 47  00 85 31 28  B1 E3 49 3A
                //AES(HVAL):  5A 05 AA 45  88 06 A9 C1  DC 5A F6 AF  6F 8F EC F6
                //MAC CTR PT: 80 FF EE DD  CC BB AA 99  88 77 66 55  00 00 00 00
                //AES(MCPT):  C6 B6 F4 33  F9 12 39 4F  6A 8C B9 D3  F2 7B 0C 72
                ct:    'F0 DB A9 74  12 30 01 B0  E1 42 B7 58  87 C9 00 A3' +
                       'A4 C4 70 6D  40 41 F4 F9  58 E1 3F D0  D7 60 4D 1E' +
                       '9C B3 5E 76  71 14 90 8E  B6 D6 4F 7C  9D F4 E0 84'
            },
    
            // Vector #15: CWC-AES-32
            {
                key:   '00 01 02 03  04 05 06 07  08 09 0A 0B  0C 0D 0E 0F' +
                       'F0 E0 D0 C0  B0 A0 90 80  70 60 50 40  30 20 10 00',
                pt:    '00 01 02 03  04 05 06 07  08 09 0A 0B  0C 0D 0E 0F' +
                       '80 81 82 83  84 85 86 87  88 89 8A 8B  8C 8D 8E 8F',
                aad:   '',
                nonce: 'FF EE DD CC  BB AA 99 88  77 66 55',
                //--------------------------------------------------------------
                //HASH KEY:   35 8F 2B 0C  FF E9 84 BE  F9 EE EE 55  85 36 BC E5
                //HASH VALUE: 02 F2 DA E9  83 72 0E BC  DC 77 89 3B  67 CB 3D B7
                //AES(HVAL):  B7 F6 AE DE  A3 95 35 FE  03 93 08 DF  E0 C7 F1 78
                //MAC CTR PT: 80 FF EE DD  CC BB AA 99  88 77 66 55  00 00 00 00
                //AES(MCPT):  92 0A 3B 46  82 25 16 F1  5A A3 1B AE  8D EB 72 A0
                ct:    '7B CF 73 BE  46 9C 46 0B  9B C6 2D DE  26 DD 47 B5' +
                       'D2 41 06 CA  5D EB 80 A7  B5 71 0A 38  A4 39 8D BA' +
                       '25 FC 95 98  21 B0 23 0F  59 30 13 71  6D 2C 83 D8'
            },
    
            // Vector #16: CWC-AES-16
            {
                key:   '00 01 02 03  04 05 06 07  08 09 0A 0B  0C 0D 0E 0F',
                pt:    '00 01 02 03  04 05 06 07  08 09 0A 0B  0C 0D 0E 0F' +
                       '80 81 82 83  84 85 86 87  88 89 8A 8B  8C 8D 8E 8F',
                aad:   '54 68 69 73  20 69 73 20  61 20 70 6C  61 69 6E 74' +
                       '65 78 74 20  68 65 61 64  65 72 2E 00',
                nonce: 'FF EE DD CC  BB AA 99 88  77 66 55',
                //--------------------------------------------------------------
                //HASH KEY:   34 AE 6A 6F  E9 51 78 94  AC CC BB 9E  BA E7 20 8C
                //HASH VALUE: 05 EE B6 CB  DF A6 E5 B8  4C 65 DD F4  8C C8 25 23
                //AES(HVAL):  62 E5 23 FE  48 8F BC 14  E3 77 15 6C  4D 0F D0 8B
                //MAC CTR PT: 80 FF EE DD  CC BB AA 99  88 77 66 55  00 00 00 00
                //AES(MCPT):  AB 89 DD E9  C4 55 C1 FE  BE 7E E7 58  82 D4 8A D2
                ct:    '88 B8 DF 06  28 FD 51 CC  31 E6 6E 57  0B 0F 77 0F' +
                       '48 5B 82 64  6E CF B9 F9  A0 B0 75 4F  D5 94 36 5A' +
                       'C9 6C FE 17  8C DA 7D EA  5D 09 F2 34  CF DB 5A 59'
            },
    
            // Vector #17: CWC-AES-24
            {
                key:   '00 01 02 03  04 05 06 07  08 09 0A 0B  0C 0D 0E 0F' +
                       'F0 E0 D0 C0  B0 A0 90 80',
                pt:    '00 01 02 03  04 05 06 07  08 09 0A 0B  0C 0D 0E 0F' +
                       '80 81 82 83  84 85 86 87  88 89 8A 8B  8C 8D 8E 8F',
                aad:   '54 68 69 73  20 69 73 20  61 20 70 6C  61 69 6E 74' +
                       '65 78 74 20  68 65 61 64  65 72 2E 00',
                nonce: 'FF EE DD CC  BB AA 99 88  77 66 55',
                //--------------------------------------------------------------
                //HASH KEY:   4F A8 88 AF  06 83 60 0C  AB 35 75 EF  0A E6 01 A5
                //HASH VALUE: 10 E1 48 E2  D0 68 39 EC  C4 0A 6C A3  D6 8B 47 54
                //AES(HVAL):  23 0A 37 C3  48 7C 9F 76  05 B9 5D 1A  21 D5 D5 FD
                //MAC CTR PT: 80 FF EE DD  CC BB AA 99  88 77 66 55  00 00 00 00
                //AES(MCPT):  C6 B6 F4 33  F9 12 39 4F  6A 8C B9 D3  F2 7B 0C 72
                ct:    'F0 DB A9 74  12 30 01 B0  E1 42 B7 58  87 C9 00 A3' +
                       'A4 C4 70 6D  40 41 F4 F9  58 E1 3F D0  D7 60 4D 1E' +
                       'E5 BC C3 F0  B1 6E A6 39  6F 35 E4 C9  D3 AE D9 8F'
            },
    
            // Vector #18: CWC-AES-32
            {
                key:   '00 01 02 03  04 05 06 07  08 09 0A 0B  0C 0D 0E 0F' +
                       'F0 E0 D0 C0  B0 A0 90 80  70 60 50 40  30 20 10 00',
                pt:    '00 01 02 03  04 05 06 07  08 09 0A 0B  0C 0D 0E 0F' +
                       '80 81 82 83  84 85 86 87  88 89 8A 8B  8C 8D 8E 8F',
                aad:   '54 68 69 73  20 69 73 20  61 20 70 6C  61 69 6E 74' +
                       '65 78 74 20  68 65 61 64  65 72 2E 00',
                nonce: 'FF EE DD CC  BB AA 99 88  77 66 55',
                //--------------------------------------------------------------
                //HASH KEY:   35 8F 2B 0C  FF E9 84 BE  F9 EE EE 55  85 36 BC E5
                //HASH VALUE: 09 4D C5 21  94 79 E0 58  4E E9 C1 2C  29 6A E3 A4
                //AES(HVAL):  E9 69 49 47  09 07 62 3B  A9 8D AD 51  9F D5 D1 F7
                //MAC CTR PT: 80 FF EE DD  CC BB AA 99  88 77 66 55  00 00 00 00
                //AES(MCPT):  92 0A 3B 46  82 25 16 F1  5A A3 1B AE  8D EB 72 A0
                ct:    '7B CF 73 BE  46 9C 46 0B  9B C6 2D DE  26 DD 47 B5' +
                       'D2 41 06 CA  5D EB 80 A7  B5 71 0A 38  A4 39 8D BA' +
                       '7B 63 72 01  8B 22 74 CA  F3 2E B6 FF  12 3E A3 57'
            }
        ];
    
        for (var i = 0, count = 1; i < testVectors.length; i++, count++) {
            var vector = testVectors[i];
    
    
            var key = Buffer.from(vector.key.replace(/[ \:]/g, ''), 'hex');
            var expected = Buffer.from(vector.ct.replace(/[ \:]/g, ''), 'hex');
            var pt = Buffer.from(vector.pt.replace(/[ \:]/g, ''), 'hex');
            var nonce = Buffer.from(vector.nonce.replace(/[ \:]/g, ''), 'hex');
            var aad = Buffer.from(vector.aad.replace(/[ \:]/g, ''), 'hex');
    
            var algo_name = 'aes-' + (key.length * 8);
    
            var cipher = new jCastle.mcrypt(algo_name);
            cipher.start({
                key: key,
                mode: 'cwc',
                direction: true,
                nonce: nonce,
                additionalData: aad
            });
    
            var ct = cipher.update(pt).finalize();
            var v = ct.equals(expected);
    
            assert.ok(v, count + ' - Encryption Passed!');
    
    if (!v) {
        console.log('ciphertext: ' + ct.toString('hex'));
        console.log('expected:   ' + expected.toString('hex'));
    }
    
            var cipher = new jCastle.mcrypt(algo_name);
            cipher.start({
                key: key,
                mode: 'cwc',
                direction: false,
                nonce: nonce,
                additionalData: aad,
            });
    
            var dt = cipher.update(ct).finalize();
            v = dt.equals(pt);
    
            assert.ok(v, count + ' - Decryption Passed!');
    
    
        }
    
    });    