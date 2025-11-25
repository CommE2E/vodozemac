// @flow

import Olm from '@commapp/olm';
import vodozemacInit, {Account as VodozemacAccount, Session as VodozemacSession, OlmMessage} from 'vodozemac';

const key = 'abcdef0123456789ABCDEF0123456789';
const PICKLE_KEY = new TextEncoder().encode(key);


describe('Session migration', () => {
  beforeAll(async () => {
    await Olm.init();
    await vodozemacInit();
  });

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
    if (!bobPrekeySignature) throw new Error('prekey_signature is required');

    const aliceSession = new Olm.Session();
    aliceSession.create_outbound(
      aliceAccount,
      bobIdentityKeys.curve25519,
      bobIdentityKeys.ed25519,
      bobPrekeyValue,
      bobPrekeySignature,
      bobOTK
    );

    return { aliceAccount, bobAccount, aliceSession };
  }


  it('should migrate session and continue encryption/decryption', () => {
    const { aliceAccount, bobAccount, aliceSession } = createOlmSession();

    const plaintext = "Test message before migration";
    const encrypted = aliceSession.encrypt(plaintext);

    // Pickle the session
    const pickle = aliceSession.pickle(key);
    const vodozemacSession = VodozemacSession.from_libolm_pickle(pickle, PICKLE_KEY);

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
    const decrypted2 = bobSession.decrypt(encrypted2.message_type, encrypted2.ciphertext);
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
    const vodozemacSession = VodozemacSession.from_libolm_pickle(pickle, PICKLE_KEY);

    // Should still be able to communicate
    const testMsg = "After migration";
    const encAfter = vodozemacSession.encrypt(testMsg);
    const decAfter = bobSession.decrypt(encAfter.message_type, encAfter.ciphertext);
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

  it('should migrate inbound session', () => {
    const { aliceAccount, bobAccount, aliceSession } = createOlmSession();

    // Alice sends a message
    const plaintext = "Hello Bob";
    const encrypted = aliceSession.encrypt(plaintext);

    // Bob creates inbound session and receives the message
    const bobSession = new Olm.Session();
    bobSession.create_inbound(bobAccount, encrypted.body);
    const decrypted1 = bobSession.decrypt(encrypted.type, encrypted.body);
    expect(decrypted1).toBe(plaintext);

    // Migrate Bob's INBOUND session
    const bobPickle = bobSession.pickle(key);
    const vodozemacBobSession = VodozemacSession.from_libolm_pickle(bobPickle, PICKLE_KEY);

    // Verify Bob's migrated session has correct state
    expect(vodozemacBobSession.has_received_message()).toBe(true);
    expect(vodozemacBobSession.is_sender_chain_empty()).toBe(true);

    // Alice sends another message
    const plaintext2 = "Second message";
    const encrypted2 = aliceSession.encrypt(plaintext2);

    // Bob's migrated session should be able to decrypt it
    const message = new OlmMessage(encrypted2.type, encrypted2.body);
    const decrypted2 = vodozemacBobSession.decrypt(message);
    expect(decrypted2).toBe(plaintext2);

    // Bob can now send a reply
    const reply = "Hello Alice";
    const replyEnc = vodozemacBobSession.encrypt(reply);
    const replyDecrypted = aliceSession.decrypt(replyEnc.message_type, replyEnc.ciphertext);
    expect(replyDecrypted).toBe(reply);

    aliceAccount.free();
    bobAccount.free();
    aliceSession.free();
    bobSession.free();
    vodozemacBobSession.free();
  });

  it('should migrate session created without one-time key', () => {
    const aliceAccount = new Olm.Account();
    aliceAccount.create();
    const bobAccount = new Olm.Account();
    bobAccount.create();

    bobAccount.generate_prekey();

    const bobIdentityKeys = JSON.parse(bobAccount.identity_keys());
    const bobPrekey = JSON.parse(bobAccount.prekey());
    const bobPrekeyValue = String(Object.values(bobPrekey.curve25519)[0]);
    const bobPrekeySignature = bobAccount.prekey_signature();
    if (!bobPrekey) throw new Error('prekey is required');
    if (!bobPrekeySignature) throw new Error('prekey_signature is required');

    // Create session WITHOUT one-time key (null OTK)
    const aliceSession = new Olm.Session();
    aliceSession.create_outbound_without_otk(
      aliceAccount,
      bobIdentityKeys.curve25519,
      bobIdentityKeys.ed25519,
      bobPrekeyValue,
      bobPrekeySignature
    );

    const olmSessionId = aliceSession.session_id();
    const pickle = aliceSession.pickle(key);

    const vodozemacSession = VodozemacSession.from_libolm_pickle(pickle, PICKLE_KEY);

    // Verify it can encrypt/decrypt
    const plaintext = "Test without OTK";
    const encrypted = vodozemacSession.encrypt(plaintext);

    const bobSession = new Olm.Session();
    bobSession.create_inbound(bobAccount, encrypted.ciphertext);
    const decrypted = bobSession.decrypt(encrypted.message_type, encrypted.ciphertext);
    expect(decrypted).toBe(plaintext);

    aliceAccount.free();
    bobAccount.free();
    aliceSession.free();
    bobSession.free();
    vodozemacSession.free();
  });

  it('should handle bidirectional migration', () => {
    const { aliceAccount, bobAccount, aliceSession } = createOlmSession();

    // Establish communication
    const msg1 = aliceSession.encrypt("Alice to Bob");
    const bobSession = new Olm.Session();
    bobSession.create_inbound(bobAccount, msg1.body);
    bobSession.decrypt(msg1.type, msg1.body);

    const reply1 = bobSession.encrypt("Bob to Alice");
    aliceSession.decrypt(reply1.type, reply1.body);

    // Now BOTH migrate
    const alicePickle = aliceSession.pickle(key);
    const bobPickle = bobSession.pickle(key);

    const vodozemacAlice = VodozemacSession.from_libolm_pickle(alicePickle, PICKLE_KEY);
    const vodozemacBob = VodozemacSession.from_libolm_pickle(bobPickle, PICKLE_KEY);

    // Continue bidirectional communication after migration
    const msg2 = "After migration - Alice";
    const enc2 = vodozemacAlice.encrypt(msg2);
    const dec2 = vodozemacBob.decrypt(enc2);
    expect(dec2).toBe(msg2);

    const msg3 = "After migration - Bob";
    const enc3 = vodozemacBob.encrypt(msg3);
    const dec3 = vodozemacAlice.decrypt(enc3);
    expect(dec3).toBe(msg3);

    aliceAccount.free();
    bobAccount.free();
    aliceSession.free();
    bobSession.free();
    vodozemacAlice.free();
    vodozemacBob.free();
  });
});
