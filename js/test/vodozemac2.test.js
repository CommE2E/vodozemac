// @flow


const { Account, Session, OlmMessage } = require('../wasm/node/vodozemac.js');

// Tests inspired by [link to Olm tests]

describe("vodozemac2", function () {
    var aliceAccount = new Account(), bobAccount = new Account();
    var aliceSession: Session, bobSession: Session;

    beforeEach(function () {
        // This should really be in a beforeAll, but jasmine-node
        // doesn't support that

        aliceAccount = new Account();
        bobAccount = new Account();
        aliceSession = new Session();
        bobSession = new Session();

        bobAccount.generate_prekey();
        bobAccount.mark_prekey_as_published();
        bobAccount.generate_prekey();
        bobAccount.mark_prekey_as_published();
        bobAccount.forget_old_prekey();
    });

    afterEach(function () {
        if (aliceAccount !== undefined) {
            aliceAccount.free();
            aliceAccount = undefined;
        }

        if (bobAccount !== undefined) {
            bobAccount.free();
            bobAccount = undefined;
        }

        if (aliceSession !== undefined) {
            aliceSession.free();
            aliceSession = undefined;
        }

        if (bobSession !== undefined) {
            bobSession.free();
            bobSession = undefined;
        }
    });

    function testPickleAndRestore() {
        var alicePickleKey = new TextEncoder().encode('DEFAULT_PICKLE_KEY_1234567890___').slice(0, 32);
        var bobPickleKey = new TextEncoder().encode('DEFAULT_PICKLE_KEY_1234567890___').slice(0, 32);
        var aliceSessionPickled = aliceSession.pickle(alicePickleKey);
        var bobSessionPickled = bobSession.pickle(bobPickleKey);

        aliceSession.free();
        aliceSession = undefined;

        bobSession.free();
        bobSession = undefined;

        aliceSession = new Session();
        bobSession = new Session();

        aliceSession = Session.from_pickle(aliceSessionPickled, alicePickleKey);
        bobSession = Session.from_pickle(bobSessionPickled, bobPickleKey);
    }

    function testEncryptDecrypt() {
        var TEST_TEXT = 'têst1';
        var encrypted = aliceSession.encrypt(TEST_TEXT);
        expect(encrypted.message_type).toEqual(0);

        const { plaintext, session: bob_session } =
            bobAccount.create_inbound_session(aliceAccount.curve25519_key, encrypted);

        bobSession = bob_session
        //done automatically
        //bobAccount.remove_one_time_keys(bobSession);
        var decrypted = new TextDecoder().decode(plaintext);
        console.log(TEST_TEXT, "->", decrypted);
        expect(decrypted).toEqual(TEST_TEXT);

        TEST_TEXT = 'hot beverage: ☕';
        encrypted = bobSession.encrypt(TEST_TEXT);
        expect(encrypted.message_type).toEqual(1);
        decrypted = aliceSession.decrypt(encrypted);
        decrypted = new TextDecoder().decode(decrypted);
        console.log(TEST_TEXT, "->", decrypted);
        expect(decrypted).toEqual(TEST_TEXT);

        testPickleAndRestore();

        TEST_TEXT = 'some emoji: ☕ 123 // after pickling';
        encrypted = bobSession.encrypt(TEST_TEXT);
        expect(encrypted.message_type).toEqual(1);
        decrypted = aliceSession.decrypt(encrypted);
        decrypted = new TextDecoder().decode(decrypted);
        console.log(TEST_TEXT, "->", decrypted);
        expect(decrypted).toEqual(TEST_TEXT);
    }

    it('should encrypt and decrypt with session created with OTK', function () {
        bobAccount.generate_one_time_keys(1);
        const [oneTimeKey] = Array.from(bobAccount.one_time_keys.values());
        bobAccount.mark_keys_as_published();

        var bobIdKey = bobAccount.curve25519_key;
        var bobSigningKey = bobAccount.ed25519_key;

        var bobPrekey = bobAccount.prekey() ?? '';
        var bobPreKeySignature = bobAccount.prekey_signature() ?? '';


        aliceSession = aliceAccount.create_outbound_session(
            bobIdKey, bobSigningKey, oneTimeKey, bobPrekey, bobPreKeySignature
        );

        testEncryptDecrypt();
    });


    it('should encrypt and decrypt with session created without OTK', function () {
        var bobIdKey = bobAccount.curve25519_key;
        var bobSigningKey = bobAccount.ed25519_key;

        var bobPrekey = bobAccount.prekey() ?? '';
        var bobPreKeySignature = bobAccount.prekey_signature() ?? '';

        aliceSession = aliceAccount.create_outbound_session(
            bobIdKey, bobSigningKey, null, bobPrekey, bobPreKeySignature
        );

        testEncryptDecrypt();
    });


    it('should handle sender chain initialization and received_message flag setting', function () {
        bobAccount.generate_one_time_keys(1);
        const [oneTimeKey] = Array.from(bobAccount.one_time_keys.values());
        bobAccount.mark_keys_as_published();

        var bobIdKey = bobAccount.curve25519_key;
        var bobSigningKey = bobAccount.ed25519_key;

        var bobPrekey = bobAccount.prekey() ?? '';
        var bobPreKeySignature = bobAccount.prekey_signature() ?? '';

        expect(aliceSession.is_sender_chain_empty()).toEqual(true);
        aliceSession = aliceAccount.create_outbound_session(
            bobIdKey, bobSigningKey, oneTimeKey, bobPrekey, bobPreKeySignature
        );
        expect(aliceSession.is_sender_chain_empty()).toEqual(false);
        expect(aliceSession.has_received_message()).toEqual(false);

        var TEST_TEXT = 'têst1';
        var encrypted = aliceSession.encrypt(TEST_TEXT);
        expect(encrypted.message_type).toEqual(0);
        bobSession = bobAccount.create_inbound_session(aliceAccount.curve25519_key, encrypted).session;
        //done automatically
        //bobAccount.remove_one_time_keys(bobSession);
        var decrypted = bobSession.decrypt(encrypted);
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