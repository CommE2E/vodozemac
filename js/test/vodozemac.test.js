// @flow

const { Account, Session, OlmMessage } = require('../wasm/node/vodozemac.js');

// Tests inspired by olm.spec.js in CommE2E/olm repo to make sure
// Vodozemac API is the same.
// This test does not include the sequential decrypt feature, which is not
// used anymore.

describe("vodozemac", function () {
  var aliceAccount = new Account(), bobAccount = new Account();
  var aliceSession = new Session(), bobSession = new Session();

  beforeEach(function () {
    aliceAccount = new Account();
    bobAccount = new Account();


    bobAccount.generate_prekey();
    bobAccount.mark_prekey_as_published();
    bobAccount.generate_prekey();
    bobAccount.mark_prekey_as_published();
    bobAccount.forget_old_prekey();
  });

  afterEach(function () {
    if (aliceAccount !== undefined) {
      aliceAccount.free();
    }

    if (bobAccount !== undefined) {
      bobAccount.free();
    }

    if (aliceSession !== undefined) {
      aliceSession.free();
    }

    if (bobSession !== undefined) {
      bobSession.free();
    }
  });

  function testPickleAndRestore() {
    var alicePickleKey = new TextEncoder().encode('SomeSecretAliceSomeSecretAliceSomeSecretAlice').slice(0, 32);
    var bobPickleKey = new TextEncoder().encode('SomeSecretBobSomeSecretBobSomeSecretBob').slice(0, 32);
    var aliceSessionPickled = aliceSession.pickle(alicePickleKey);
    var bobSessionPickled = bobSession.pickle(bobPickleKey);

    aliceSession.free();
    bobSession.free();

    aliceSession = Session.from_pickle(aliceSessionPickled, alicePickleKey);
    bobSession = Session.from_pickle(bobSessionPickled, bobPickleKey);
  }

  function testEncryptDecrypt() {
    var TEST_TEXT = 'têst1';
    var encrypted = aliceSession.encrypt(TEST_TEXT);
    expect(encrypted.message_type).toEqual(0);

    const result = bobAccount.create_inbound_session(aliceAccount.curve25519_key, encrypted);
    var decrypted = result.plaintext;
    bobSession = result.into_session();
    // Removing OTKs is now done as part of create_inbound_session.
    console.log(TEST_TEXT, "->", decrypted);
    expect(decrypted).toEqual(TEST_TEXT);

    TEST_TEXT = 'hot beverage: ☕';
    encrypted = bobSession.encrypt(TEST_TEXT);
    expect(encrypted.message_type).toEqual(1);
    decrypted = aliceSession.decrypt(encrypted);

    console.log(TEST_TEXT, "->", decrypted);
    expect(decrypted).toEqual(TEST_TEXT);

    testPickleAndRestore();

    TEST_TEXT = 'some emoji: ☕ 123 // after pickling';
    encrypted = bobSession.encrypt(TEST_TEXT);
    expect(encrypted.message_type).toEqual(1);
    decrypted = aliceSession.decrypt(encrypted);

    console.log(TEST_TEXT, "->", decrypted);
    expect(decrypted).toEqual(TEST_TEXT);
  }

  it('should encrypt and decrypt with session created with OTK', function () {
    bobAccount.generate_one_time_keys(1);
    const [oneTimeKey] = Array.from(bobAccount.one_time_keys().values());
    bobAccount.mark_keys_as_published();

    var bobIdKey = bobAccount.curve25519_key;
    var bobSigningKey = bobAccount.ed25519_key;

    var bobPrekey = bobAccount.prekey();
    var bobPreKeySignature = bobAccount.prekey_signature();
    if (!bobPrekey) throw new Error('prekey is required');
    if (!bobPreKeySignature) throw new Error('prekey_signature is required');

    aliceSession = aliceAccount.create_outbound_session(
      bobIdKey, bobSigningKey, oneTimeKey, bobPrekey, bobPreKeySignature, false
    );

    testEncryptDecrypt();
  });


  it('should encrypt and decrypt with session created without OTK', function () {
    var bobIdKey = bobAccount.curve25519_key;
    var bobSigningKey = bobAccount.ed25519_key;

    var bobPrekey = bobAccount.prekey();
    var bobPreKeySignature = bobAccount.prekey_signature();
    if (!bobPrekey) throw new Error('prekey is required');
    if (!bobPreKeySignature) throw new Error('prekey_signature is required');

    aliceSession = aliceAccount.create_outbound_session(
      bobIdKey, bobSigningKey, null, bobPrekey, bobPreKeySignature, false
    );

    testEncryptDecrypt();
  });


  it('should handle sender chain initialization and received_message flag setting', function () {
    bobAccount.generate_one_time_keys(1);
    const [oneTimeKey] = Array.from(bobAccount.one_time_keys().values());
    bobAccount.mark_keys_as_published();


    var bobIdKey = bobAccount.curve25519_key;
    var bobSigningKey = bobAccount.ed25519_key;

    var bobPrekey = bobAccount.prekey();
    var bobPreKeySignature = bobAccount.prekey_signature();
    if (!bobPrekey) throw new Error('prekey is required');
    if (!bobPreKeySignature) throw new Error('prekey_signature is required');

    aliceSession = aliceAccount.create_outbound_session(
      bobIdKey, bobSigningKey, oneTimeKey, bobPrekey, bobPreKeySignature, false
    );
    expect(aliceSession.is_sender_chain_empty()).toEqual(false);
    expect(aliceSession.has_received_message()).toEqual(false);

    var TEST_TEXT = 'têst1';
    var encrypted = aliceSession.encrypt(TEST_TEXT);
    expect(encrypted.message_type).toEqual(0);
    let result = bobAccount.create_inbound_session(aliceAccount.curve25519_key, encrypted);
    var decrypted = result.plaintext;
    bobSession = result.into_session();
    expect(decrypted).toEqual(TEST_TEXT);

    expect(bobSession.is_sender_chain_empty()).toEqual(true);
    expect(bobSession.has_received_message()).toEqual(true);

    TEST_TEXT = 'hot beverage: ☕';
    encrypted = bobSession.encrypt(TEST_TEXT);
    expect(encrypted.message_type).toEqual(1);
    decrypted = aliceSession.decrypt(encrypted);

    expect(decrypted).toEqual(TEST_TEXT);

    expect(bobSession.is_sender_chain_empty()).toEqual(false);
    expect(aliceSession.has_received_message()).toEqual(true);
  });
});