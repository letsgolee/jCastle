const jCastle = require('../lib/index');
const QUnit = require('qunit');

QUnit.module('DSA');
QUnit.test("DH Test", function(assert) {
    //----------------------------------------------------------------------------------------------------
    
    
    var params = jCastle.pki.dsa.getPredefinedParameters(4096);
    
    var alice = new jCastle.pki('DSA');
    var bob = new jCastle.pki('DSA');

    alice.setParameters(params);
    bob.setParameters(params);

    // Now allice and Bob both has the same parameters. now generate public & private key...

    alice.generateKeypair();
    bob.generateKeypair();

    // Exchange public keys...

    var alice_pubkey = alice.getPublicKey();
    var bob_pubkey = bob.getPublicKey();

    // Compute secret...

    var alice_dh = new jCastle.dh().init(alice);
    var bob_dh = new jCastle.dh().init(bob);

    var alice_secret = alice_dh.computeSecret(bob_pubkey).toString('hex');
    var bob_secret = bob_dh.computeSecret(alice_pubkey).toString('hex');

    // Both secrets should be equal

    assert.equal(alice_secret , bob_secret, "DiffieHellman Key Agreement with DSA Parameters Test");
});    