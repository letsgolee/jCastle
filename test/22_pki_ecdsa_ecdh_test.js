const jCastle = require('../lib/index');
const BigInteger = require('../lib/biginteger');
const QUnit = require('qunit');


QUnit.module('ECDH');
QUnit.test("Key Agreement Test", function(assert) {
    
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
    
    
    var alice = new jCastle.pki('ECDSA');
    var bob = new jCastle.pki('ECDSA');
    
    alice.parseParameters(brainpoolP512t1_pem);
    bob.parseParameters(brainpoolP512t1_pem);
    
    // Now allice and Bob both has the same parameters. now generate public & private key...

    alice.generateKeypair();
    bob.generateKeypair();
    
    // get public keys...
    
    var alice_pubkey = alice.getPublicKey().encodePoint();
    var bob_pubkey = bob.getPublicKey().encodePoint();

    //----------------------------------------------------------------------------------------------------
    
    
    // Compute secret...
    
    var alice_ecdh = new jCastle.ecdh().init(alice);
    var bob_ecdh = new jCastle.ecdh().init(bob);
    
    var alice_secret = alice_ecdh.computeSecret(bob_pubkey);
    var bob_secret = bob_ecdh.computeSecret(alice_pubkey);

    // Both secrets should be equal
    
    assert.ok(alice_secret.equals(bob_secret), "DiffieHellman Key Agreement with ECDSA Parameters(ECDH) Test");
   

    //----------------------------------------------------------------------------------------------------
    
    // creating ephemeral private key
    var prng = jCastle.prng.create();
    var alice_ephemeral_privkey = BigInteger.random(alice.getBitLength(), prng);
    var bob_ephemeral_privkey = BigInteger.random(bob.getBitLength(), prng);

    // creating ephemeral public key
    // var alice_ephemeral_pubkey = alice.pkiObject.ecInfo.G.multiply(alice_ephemeral_privkey);
    // var bob_ephemeral_pubkey = bob.pkiObject.ecInfo.G.multiply(bob_ephemeral_privkey);
    var alice_ephemeral_pubkey = alice.getEphemeralPublicKey(alice_ephemeral_privkey);
    var bob_ephemeral_pubkey = bob.getEphemeralPublicKey(bob_ephemeral_privkey);

    var alice_ecdh = jCastle.ecdh.create().init(alice);
    var bob_ecdh = jCastle.ecdh.create().init(bob);
    
    var zz = alice_ecdh.calculateMQVAgreement(alice_ephemeral_privkey, bob_pubkey, bob_ephemeral_pubkey);
    var zz1 = bob_ecdh.calculateMQVAgreement(bob_ephemeral_privkey, alice_pubkey, alice_ephemeral_pubkey);
    
    assert.ok(zz1.equals(zz), 'MQV Key Agreement with ECDSA Test');
   
});