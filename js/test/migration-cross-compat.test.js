// @flow

import Olm from '@commapp/olm';
import vodozemacInit, {Account as VodozemacAccount, Session as VodozemacSession, OlmMessage} from 'vodozemac';

const PICKLE_KEY_STR = 'abcdef0123456789ABCDEF0123456789';
const PICKLE_KEY = new TextEncoder().encode(PICKLE_KEY_STR);

describe('Cross-compatibility: Olm <-> Vodozemac Migration', () => {
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
      bobOTK,
    );

    return { aliceAccount, bobAccount, aliceSession };
  }

  /**
   * MIGRATION TEST 1: Outbound session migrated BEFORE receiving acknowledgment
   *
   * - OUTBOUND: Alice (Olm) → creates session, sends PreKey messages
   * - INBOUND: Bob (Olm) → receives PreKey messages
   * - MIGRATION: Alice migrates to Vodozemac BEFORE Bob replies
   * - RESULT: Alice continues sending PreKey messages until Bob replies, then switches to Normal
   */
  it('should migrate session BEFORE receiving ack (PreKey mode)', () => {
    const { aliceAccount, bobAccount, aliceSession } = createOlmSession();

    // Alice sends PreKey message
    const preKeyMsg1 = aliceSession.encrypt("PreKey message 1");
    expect(preKeyMsg1.type).toBe(0); // PreKey message

    // Bob receives it
    const bobSession = new Olm.Session();
    bobSession.create_inbound(bobAccount, preKeyMsg1.body);
    const decrypted1 = bobSession.decrypt(preKeyMsg1.type, preKeyMsg1.body);
    expect(decrypted1).toBe("PreKey message 1");

    // Alice sends another message - STILL PreKey because no ack yet
    const preKeyMsg2 = aliceSession.encrypt("PreKey message 2");
    expect(preKeyMsg2.type).toBe(0); // Still PreKey - no ack received
    bobSession.decrypt(preKeyMsg2.type, preKeyMsg2.body);

    // NOW migrate Alice's session BEFORE receiving ack
    const alicePickle = aliceSession.pickle(PICKLE_KEY_STR);
    const vodozemacAlice = VodozemacSession.from_libolm_pickle(alicePickle, PICKLE_KEY);

    // Verify migrated session still hasn't received message
    expect(vodozemacAlice.has_received_message()).toBe(false);

    // After migration, should STILL send PreKey messages (no ack yet)
    const afterMigration1 = vodozemacAlice.encrypt("After migration - still PreKey");
    expect(afterMigration1.message_type).toBe(0); // Still PreKey
    const dec3 = bobSession.decrypt(afterMigration1.message_type, afterMigration1.ciphertext);
    expect(dec3).toBe("After migration - still PreKey");

    // Bob finally replies
    const bobReply = bobSession.encrypt("Bob's ack");
    const message = new OlmMessage(bobReply.type, bobReply.body);
    const aliceDecrypted = vodozemacAlice.decrypt(message);
    expect(aliceDecrypted).toBe("Bob's ack");

    // NOW Alice has received message, should send Normal messages
    expect(vodozemacAlice.has_received_message()).toBe(true);
    const normalMsg = vodozemacAlice.encrypt("Now Normal");
    expect(normalMsg.message_type).toBe(1); // Normal message now
    bobSession.decrypt(normalMsg.message_type, normalMsg.ciphertext);

    aliceAccount.free();
    bobAccount.free();
    aliceSession.free();
    bobSession.free();
    vodozemacAlice.free();
  });

  /**
   * MIGRATION TEST 2: Outbound session migrated AFTER receiving acknowledgment
   *
   * - OUTBOUND: Alice (Olm) → creates session, sends PreKey then Normal messages
   * - INBOUND: Bob (Olm) → receives and replies
   * - MIGRATION: Alice migrates to Vodozemac AFTER Bob replies (already in Normal mode)
   * - RESULT: Alice continues sending Normal messages after migration
   */
  it('should migrate session AFTER receiving ack (Normal mode)', () => {
    const { aliceAccount, bobAccount, aliceSession } = createOlmSession();

    // Alice sends PreKey message
    const preKeyMsg = aliceSession.encrypt("PreKey message");
    expect(preKeyMsg.type).toBe(0); // PreKey message

    // Bob receives it
    const bobSession = new Olm.Session();
    bobSession.create_inbound(bobAccount, preKeyMsg.body);
    const decrypted1 = bobSession.decrypt(preKeyMsg.type, preKeyMsg.body);
    expect(decrypted1).toBe("PreKey message");

    // Bob replies - Alice receives ack
    const bobReply = bobSession.encrypt("Ack");
    aliceSession.decrypt(bobReply.type, bobReply.body);

    // NOW Alice sends Normal messages (session established)
    const normalMsg1 = aliceSession.encrypt("Normal message 1");
    expect(normalMsg1.type).toBe(1); // Normal message
    bobSession.decrypt(normalMsg1.type, normalMsg1.body);

    const normalMsg2 = aliceSession.encrypt("Normal message 2");
    expect(normalMsg2.type).toBe(1); // Normal message
    bobSession.decrypt(normalMsg2.type, normalMsg2.body);

    // NOW migrate Alice's session AFTER receiving ack
    const alicePickle = aliceSession.pickle(PICKLE_KEY_STR);
    const vodozemacAlice = VodozemacSession.from_libolm_pickle(alicePickle, PICKLE_KEY);

    // Verify migrated session has received message
    expect(vodozemacAlice.has_received_message()).toBe(true);

    // After migration, should continue sending Normal messages
    const afterMigration1 = vodozemacAlice.encrypt("After migration 1");
    expect(afterMigration1.message_type).toBe(1); // Normal message
    const dec3 = bobSession.decrypt(afterMigration1.message_type, afterMigration1.ciphertext);
    expect(dec3).toBe("After migration 1");

    const afterMigration2 = vodozemacAlice.encrypt("After migration 2");
    expect(afterMigration2.message_type).toBe(1); // Normal message
    const dec4 = bobSession.decrypt(afterMigration2.message_type, afterMigration2.ciphertext);
    expect(dec4).toBe("After migration 2");

    // Bob can still reply
    const bobReply2 = bobSession.encrypt("Bob's reply");
    const message = new OlmMessage(bobReply2.type, bobReply2.body);
    const aliceDecrypted = vodozemacAlice.decrypt(message);
    expect(aliceDecrypted).toBe("Bob's reply");

    aliceAccount.free();
    bobAccount.free();
    aliceSession.free();
    bobSession.free();
    vodozemacAlice.free();
  });

  /**
   * MIGRATION TEST 3: Inbound session migrated mid-conversation
   *
   * - OUTBOUND: Alice (Olm) → creates session
   * - INBOUND: Bob (Olm) → receives, then MIGRATES to Vodozemac
   * - MIGRATION: Bob migrates AFTER receiving and exchanging messages
   * - RESULT: Non-migrated Alice can continue communicating with migrated Bob
   */
  it('should migrate inbound session and continue with non-migrated peer', () => {
    const { aliceAccount, bobAccount, aliceSession } = createOlmSession();

    // Alice sends PreKey message
    const preKeyMsg = aliceSession.encrypt("Initial message");
    expect(preKeyMsg.type).toBe(0); // PreKey message

    // Bob creates inbound session
    const bobSession = new Olm.Session();
    bobSession.create_inbound(bobAccount, preKeyMsg.body);
    bobSession.decrypt(preKeyMsg.type, preKeyMsg.body);

    // Exchange a few messages before migration
    const msg1 = aliceSession.encrypt("Message 1");
    bobSession.decrypt(msg1.type, msg1.body);

    const reply1 = bobSession.encrypt("Reply 1");
    aliceSession.decrypt(reply1.type, reply1.body);

    // NOW migrate Bob's inbound session
    const bobPickle = bobSession.pickle(PICKLE_KEY_STR);
    const vodozemacBob = VodozemacSession.from_libolm_pickle(bobPickle, PICKLE_KEY);

    // Non-migrated Alice continues sending to migrated Bob
    const msg2 = aliceSession.encrypt("After Bob migrated");
    const dec1 = vodozemacBob.decrypt(new OlmMessage(msg2.type, msg2.body));
    expect(dec1).toBe("After Bob migrated");

    // Migrated Bob can reply
    const bobReply = vodozemacBob.encrypt("Bob's reply after migration");
    const aliceDecrypted = aliceSession.decrypt(bobReply.message_type, bobReply.ciphertext);
    expect(aliceDecrypted).toBe("Bob's reply after migration");

    // Continue exchange
    const msg3 = aliceSession.encrypt("One more");
    const dec2 = vodozemacBob.decrypt(new OlmMessage(msg3.type, msg3.body));
    expect(dec2).toBe("One more");

    aliceAccount.free();
    bobAccount.free();
    aliceSession.free();
    bobSession.free();
    vodozemacBob.free();
  });
});
