// @flow

const Olm = require('@commapp/olm');
const { Account: VodozemacAccount, Session: VodozemacSession } = require('../wasm/node/vodozemac.js');

const key = 'DEFAULT_PICKLE_KEY_1234567890___';
const fullKeyBytes = new TextEncoder().encode(key);
const PICKLE_KEY = fullKeyBytes.slice(0, 32);

describe('libolm to vodozemac migration', () => {
    beforeAll(async () => {
        await Olm.init();
    });

    describe('Account migration', () => {
        it('should migrate basic account with no keys', () => {
            const olmAccount = new Olm.Account();
            olmAccount.create();
            const pickle = olmAccount.pickle(key);

            const vodozemacAccount = VodozemacAccount.from_libolm_pickle(pickle, PICKLE_KEY);

            const olmIdentityKeys = JSON.parse(olmAccount.identity_keys());
            expect(vodozemacAccount.ed25519_key).toBe(olmIdentityKeys.ed25519);
            expect(vodozemacAccount.curve25519_key).toBe(olmIdentityKeys.curve25519);
            expect(vodozemacAccount.max_number_of_one_time_keys).toBe(olmAccount.max_number_of_one_time_keys());

            olmAccount.free();
            vodozemacAccount.free();
        });

        it('should migrate account with unpublished one-time keys', () => {
            const olmAccount = new Olm.Account();
            olmAccount.create();
            olmAccount.generate_one_time_keys(10);

            const olmOTKs = JSON.parse(olmAccount.one_time_keys());
            const pickle = olmAccount.pickle(key);

            const vodozemacAccount = VodozemacAccount.from_libolm_pickle(pickle, PICKLE_KEY);

            expect(vodozemacAccount.one_time_keys.size).toBe(10);

            // Verify keys match
            const vodozemacOTKs = Object.fromEntries(vodozemacAccount.one_time_keys);
            expect(vodozemacOTKs).toEqual(olmOTKs.curve25519);

            olmAccount.free();
            vodozemacAccount.free();
        });

        it('should migrate account with published one-time keys', () => {
            const olmAccount = new Olm.Account();
            olmAccount.create();
            olmAccount.generate_one_time_keys(15);
            olmAccount.mark_keys_as_published();

            const pickle = olmAccount.pickle(key);
            const vodozemacAccount = VodozemacAccount.from_libolm_pickle(pickle, PICKLE_KEY);

            // After marking as published, one_time_keys should be empty
            expect(vodozemacAccount.one_time_keys.size).toBe(0);

            olmAccount.free();
            vodozemacAccount.free();
        });

        it('should migrate account with mixed published and unpublished keys', () => {
            const olmAccount = new Olm.Account();
            olmAccount.create();

            // Generate and publish first batch
            olmAccount.generate_one_time_keys(10);
            olmAccount.mark_keys_as_published();

            // Generate second batch (unpublished)
            olmAccount.generate_one_time_keys(5);

            const pickle = olmAccount.pickle(key);
            const vodozemacAccount = VodozemacAccount.from_libolm_pickle(pickle, PICKLE_KEY);

            // Should only have the unpublished keys
            expect(vodozemacAccount.one_time_keys.size).toBe(5);

            olmAccount.free();
            vodozemacAccount.free();
        });

        it('should preserve identity keys across migration', () => {
            const olmAccount = new Olm.Account();
            olmAccount.create();

            const olmIdentityKeys = JSON.parse(olmAccount.identity_keys());
            const olmEd25519 = olmIdentityKeys.ed25519;
            const olmCurve25519 = olmIdentityKeys.curve25519;

            const pickle = olmAccount.pickle(key);
            const vodozemacAccount = VodozemacAccount.from_libolm_pickle(pickle, PICKLE_KEY);

            expect(vodozemacAccount.ed25519_key).toBe(olmEd25519);
            expect(vodozemacAccount.curve25519_key).toBe(olmCurve25519);

            olmAccount.free();
            vodozemacAccount.free();
        });

        it('should sign messages identically after migration', () => {
            const olmAccount = new Olm.Account();
            olmAccount.create();
            const message = 'test message to sign';

            const olmSignature = olmAccount.sign(message);

            const pickle = olmAccount.pickle(key);
            const vodozemacAccount = VodozemacAccount.from_libolm_pickle(pickle, PICKLE_KEY);

            const vodozemacSignature = vodozemacAccount.sign(message);

            // Signatures should be identical (same keys produce same signatures)
            expect(vodozemacSignature).toBe(olmSignature);

            olmAccount.free();
            vodozemacAccount.free();
        });
    });

    describe('Session migration', () => {
        function createOlmSession() {
            const aliceAccount = new Olm.Account();
            aliceAccount.create();
            const bobAccount = new Olm.Account();
            bobAccount.create();

            bobAccount.generate_one_time_keys(1);
            bobAccount.generate_prekey();

            const bobOTKs = JSON.parse(bobAccount.one_time_keys());
            const bobOTKId = Object.keys(bobOTKs.curve25519)[0];
            const bobOTK = bobOTKs.curve25519[bobOTKId];

            const bobIdentityKeys = JSON.parse(bobAccount.identity_keys());
            const bobPrekey = JSON.parse(bobAccount.prekey());
            const bobPrekeyValue = String(Object.values(bobPrekey.curve25519)[0]);
            const bobPrekeySignature = bobAccount.prekey_signature();

            const aliceSession = new Olm.Session();
            aliceSession.create_outbound(
                aliceAccount,
                bobIdentityKeys.curve25519,
                bobIdentityKeys.ed25519,
                bobPrekeyValue,
                bobPrekeySignature,
                bobOTK,
            );

            return { aliceAccount, bobAccount, aliceSession };
        }

        it('should migrate fresh session', () => {
            const { aliceAccount, bobAccount, aliceSession } = createOlmSession();

            const olmSessionId = aliceSession.session_id();
            const pickle = aliceSession.pickle(key);

            const vodozemacSession = VodozemacSession.from_pickle(pickle, PICKLE_KEY);

            expect(vodozemacSession.session_id).toBe(olmSessionId);

            aliceAccount.free();
            bobAccount.free();
            aliceSession.free();
            vodozemacSession.free();
        });

        it('should migrate session and continue encryption/decryption', () => {
            const { aliceAccount, bobAccount, aliceSession } = createOlmSession();

            const plaintext = "Test message before migration";
            const encrypted = aliceSession.encrypt(plaintext);

            // Pickle the session
            const pickle = aliceSession.pickle(key);
            const vodozemacSession = VodozemacSession.from_pickle(pickle, PICKLE_KEY);

            // Create Bob's inbound session
            const bobSession = new Olm.Session();
            bobSession.create_inbound(bobAccount, encrypted.body);

            // Bob decrypts with olm
            const decrypted = bobSession.decrypt(encrypted.type, encrypted.body);
            expect(decrypted).toBe(plaintext);

            // Now encrypt with vodozemac
            const plaintext2 = "Message after migration";
            const encrypted2 = vodozemacSession.encrypt(plaintext2);

            // Bob should be able to decrypt
            const decrypted2 = bobSession.decrypt(encrypted2.message_type, new TextDecoder().decode(encrypted2.ciphertext));
            expect(decrypted2).toBe(plaintext2);

            aliceAccount.free();
            bobAccount.free();
            aliceSession.free();
            bobSession.free();
            vodozemacSession.free();
        });

        it('should migrate session after multiple messages', () => {
            const { aliceAccount, bobAccount, aliceSession } = createOlmSession();

            // Exchange several messages
            const plaintext1 = "First message";
            const encrypted1 = aliceSession.encrypt(plaintext1);

            const bobSession = new Olm.Session();
            bobSession.create_inbound(bobAccount, encrypted1.body);
            bobSession.decrypt(encrypted1.type, encrypted1.body);

            // Exchange more messages
            for (let i = 0; i < 5; i++) {
                const msg = `Message ${i}`;
                const enc = aliceSession.encrypt(msg);
                bobSession.decrypt(enc.type, enc.body);

                const reply = `Reply ${i}`;
                const replyEnc = bobSession.encrypt(reply);
                aliceSession.decrypt(replyEnc.type, replyEnc.body);
            }

            // Now pickle and migrate
            const pickle = aliceSession.pickle(key);
            const vodozemacSession = VodozemacSession.from_pickle(pickle, PICKLE_KEY);

            // Should still be able to communicate
            const testMsg = "After migration";
            const encAfter = vodozemacSession.encrypt(testMsg);
            const decAfter = bobSession.decrypt(encAfter.message_type, new TextDecoder().decode(encAfter.ciphertext));
            expect(decAfter).toBe(testMsg);

            aliceAccount.free();
            bobAccount.free();
            aliceSession.free();
            bobSession.free();
            vodozemacSession.free();
        });

        it('should preserve has_received_message status', () => {
            const { aliceAccount, bobAccount, aliceSession } = createOlmSession();

            // Fresh session - hasn't received anything yet
            const olmHasReceived1 = aliceSession.has_received_message();
            const pickle1 = aliceSession.pickle(key);
            const vodozemacSession1 = VodozemacSession.from_libolm_pickle(pickle1, PICKLE_KEY);

            expect(vodozemacSession1.has_received_message()).toBe(olmHasReceived1);
            vodozemacSession1.free();

            // Send a message and create inbound session
            const encrypted = aliceSession.encrypt("Test");
            const bobSession = new Olm.Session();
            bobSession.create_inbound(bobAccount, encrypted.body);
            bobSession.decrypt(encrypted.type, encrypted.body);

            // Bob sends reply, Alice receives
            const reply = bobSession.encrypt("Reply");
            aliceSession.decrypt(reply.type, reply.body);

            // Now Alice has received a message
            const olmHasReceived2 = aliceSession.has_received_message();
            const pickle2 = aliceSession.pickle(key);
            const vodozemacSession2 = VodozemacSession.from_libolm_pickle(pickle2, PICKLE_KEY);

            expect(vodozemacSession2.has_received_message()).toBe(olmHasReceived2);
            expect(olmHasReceived2).toBe(true);

            aliceAccount.free();
            bobAccount.free();
            aliceSession.free();
            bobSession.free();
            vodozemacSession2.free();
        });

        it('should preserve is_sender_chain_empty status', () => {
            const { aliceAccount, bobAccount, aliceSession } = createOlmSession();

            // Check initial state
            const olmIsEmpty1 = aliceSession.is_sender_chain_empty();
            const pickle1 = aliceSession.pickle(key);
            const vodozemacSession1 = VodozemacSession.from_libolm_pickle(pickle1, PICKLE_KEY);

            expect(vodozemacSession1.is_sender_chain_empty()).toBe(olmIsEmpty1);
            vodozemacSession1.free();

            // After sending a message
            const encrypted = aliceSession.encrypt("First message");
            const bobSession = new Olm.Session();
            bobSession.create_inbound(bobAccount, encrypted.body);
            bobSession.decrypt(encrypted.type, encrypted.body);

            const olmIsEmpty2 = aliceSession.is_sender_chain_empty();
            const pickle2 = aliceSession.pickle(key);
            const vodozemacSession2 = VodozemacSession.from_libolm_pickle(pickle2, PICKLE_KEY);

            expect(vodozemacSession2.is_sender_chain_empty()).toBe(olmIsEmpty2);

            aliceAccount.free();
            bobAccount.free();
            aliceSession.free();
            bobSession.free();
            vodozemacSession2.free();
        });
    });
});
