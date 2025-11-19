// @flow

const Olm = require('@commapp/olm');
const { Account: VodozemacAccount, Session: VodozemacSession } = require('../wasm/node/vodozemac.js');
const { OlmMessage } = require("../wasm/node/vodozemac.js");

const PICKLE_KEY_STR = 'abcdef0123456789ABCDEF0123456789';
const PICKLE_KEY = new TextEncoder().encode(PICKLE_KEY_STR);

describe('Cross-compatibility: Olm <-> Vodozemac Migration', () => {
  beforeAll(async () => {
    await Olm.init();
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

  /**
   * MIGRATION TEST 4: Account migrated BEFORE creating outbound session
   *
   * - OUTBOUND: Alice account migrated to Vodozemac FIRST, then creates session
   * - INBOUND: Bob (Olm) → receives from fresh Vodozemac session
   * - MIGRATION: Alice account migrated before session creation
   * - RESULT: Fresh Vodozemac session works correctly with Olm peer
   */
  it('should handle PreKey message after migration', () => {
    const aliceAccount = new Olm.Account();
    aliceAccount.create();

    const bobAccount = new Olm.Account();
    bobAccount.create();
    bobAccount.generate_one_time_keys(1);
    bobAccount.generate_prekey();

    // Migrate Alice's account BEFORE creating session
    const alicePickle = aliceAccount.pickle(PICKLE_KEY_STR);
    const vodozemacAlice = VodozemacAccount.from_libolm_pickle(alicePickle, PICKLE_KEY);

    // Create session from migrated account
    const bobOTKs = JSON.parse(bobAccount.one_time_keys());
    const bobOTK = Object.values(bobOTKs.curve25519)[0];
    const bobIdentityKeys = JSON.parse(bobAccount.identity_keys());
    const bobPrekey = JSON.parse(bobAccount.prekey());
    const bobPrekeyValue = String(Object.values(bobPrekey.curve25519)[0]);
    const bobPrekeySignature = bobAccount.prekey_signature();
    if (!bobPrekeySignature) throw new Error('prekey_signature is required');

    const aliceSession = vodozemacAlice.create_outbound_session(
      bobIdentityKeys.curve25519,
      bobIdentityKeys.ed25519,
      bobOTK,
      bobPrekeyValue,
      bobPrekeySignature,
      true
    );

    // First message should be PreKey message
    const preKeyMsg = aliceSession.encrypt("First PreKey message");
    expect(preKeyMsg.message_type).toBe(0); // PreKey message type

    // Bob receives PreKey message
    const bobSession = new Olm.Session();
    bobSession.create_inbound(bobAccount, preKeyMsg.ciphertext);
    const decrypted = bobSession.decrypt(preKeyMsg.message_type, preKeyMsg.ciphertext);
    expect(decrypted).toBe("First PreKey message");

    // Bob replies (needed for Alice to switch to Normal messages)
    const bobReply = bobSession.encrypt("Bob's reply");
    const aliceDecrypted = aliceSession.decrypt(new OlmMessage(bobReply.type, bobReply.body));
    expect(aliceDecrypted).toBe("Bob's reply");

    // Now Alice has received a message, subsequent messages should be Normal
    const normalMsg = aliceSession.encrypt("Normal message");
    expect(normalMsg.message_type).toBe(1); // Normal message type
    const dec2 = bobSession.decrypt(normalMsg.message_type, normalMsg.ciphertext);
    expect(dec2).toBe("Normal message");

    aliceAccount.free();
    bobAccount.free();
    bobSession.free();
    vodozemacAlice.free();
    aliceSession.free();
  });


  /**
   * INTEROP TEST 1: Bidirectional communication between Fresh Vodozemac and Olm
   *
   * Tests TWO separate session pairs:
   * - Direction 1: Vodozemac (Alice) outbound → Olm (Bob) inbound
   * - Direction 2: Olm (Carol) outbound → Vodozemac (Dave) inbound
   * - NO MIGRATION: All sessions fresh from the start
   * - RESULT: PreKey and Normal messages work in both directions
   */
  it('should verify PreKey and Normal messages work in BOTH directions', () => {
    // Setup: Two separate session pairs to test both directions

    // === Direction 1: Vodozemac (Alice) → Olm (Bob) ===
    const aliceAccount = new VodozemacAccount();
    const bobAccount = new Olm.Account();
    bobAccount.create();
    bobAccount.generate_one_time_keys(1);
    bobAccount.generate_prekey();

    const bobOTKs = JSON.parse(bobAccount.one_time_keys());
    const bobOTK = Object.values(bobOTKs.curve25519)[0];
    const bobIdentityKeys = JSON.parse(bobAccount.identity_keys());
    const bobPrekey = JSON.parse(bobAccount.prekey());
    const bobPrekeyValue = String(Object.values(bobPrekey.curve25519)[0]);
    const bobPrekeySignature = bobAccount.prekey_signature();
    if (!bobPrekeySignature) throw new Error('prekey_signature is required');

    const aliceSession = aliceAccount.create_outbound_session(
      bobIdentityKeys.curve25519,
      bobIdentityKeys.ed25519,
      bobOTK,
      bobPrekeyValue,
      bobPrekeySignature,
      true
    );

    // Test 1: Vodozemac sends PreKey → Olm receives
    const vPreKeyMsg = aliceSession.encrypt("Vodozemac PreKey message");
    expect(vPreKeyMsg.message_type).toBe(0); // PreKey type

    const bobSession = new Olm.Session();
    bobSession.create_inbound(bobAccount, vPreKeyMsg.ciphertext);
    const vPreKeyDecrypted = bobSession.decrypt(vPreKeyMsg.message_type, vPreKeyMsg.ciphertext);
    expect(vPreKeyDecrypted).toBe("Vodozemac PreKey message");
    console.log("✓ PreKey: Vodozemac → Olm works");

    // Setup for Normal messages (need Bob to reply first so Alice has received)
    const bobReply = bobSession.encrypt("Setup reply");
    aliceSession.decrypt(new OlmMessage(bobReply.type, bobReply.body));

    // Test 2: Vodozemac sends Normal → Olm receives
    const vNormalMsg = aliceSession.encrypt("Vodozemac Normal message");
    expect(vNormalMsg.message_type).toBe(1); // Normal type
    const vNormalDecrypted = bobSession.decrypt(vNormalMsg.message_type, vNormalMsg.ciphertext);
    expect(vNormalDecrypted).toBe("Vodozemac Normal message");
    console.log("✓ Normal: Vodozemac → Olm works");

    // Test 3: Olm sends Normal → Vodozemac receives
    const olmNormalMsg = bobSession.encrypt("Olm Normal message");
    expect(olmNormalMsg.type).toBe(1); // Normal type
    const olmNormalDecrypted = aliceSession.decrypt(new OlmMessage(olmNormalMsg.type, olmNormalMsg.body));
    expect(olmNormalDecrypted).toBe("Olm Normal message");
    console.log("✓ Normal: Olm → Vodozemac works");

    // === Direction 2: Olm (Carol) → Vodozemac (Dave) ===
    const carolAccount = new Olm.Account();
    carolAccount.create();

    const daveAccount = new VodozemacAccount();
    daveAccount.generate_one_time_keys(1);
    daveAccount.generate_prekey();

    const daveOTK = Array.from(daveAccount.one_time_keys().values())[0];
    const daveIdKey = daveAccount.curve25519_key;
    const daveSigningKey = daveAccount.ed25519_key;
    const davePrekey = daveAccount.prekey();
    const davePrekeySignature = daveAccount.prekey_signature();
    if (!davePrekey) throw new Error('prekey is required');
    if (!davePrekeySignature) throw new Error('prekey_signature is required');

    const carolSession = new Olm.Session();
    carolSession.create_outbound(
      carolAccount,
      daveIdKey,
      daveSigningKey,
      davePrekey,
      davePrekeySignature,
      daveOTK
    );

    // Test 4: Olm sends PreKey → Vodozemac receives
    const olmPreKeyMsg = carolSession.encrypt("Olm PreKey message");
    expect(olmPreKeyMsg.type).toBe(0); // PreKey type

    const carolIdentityKeys = JSON.parse(carolAccount.identity_keys());
    const message = new OlmMessage(olmPreKeyMsg.type, olmPreKeyMsg.body);
    const result = daveAccount.create_inbound_session(
      carolIdentityKeys.curve25519,
      message
    );
    const olmPreKeyDecrypted = result.plaintext;
    const daveSession = result.into_session();
    expect(olmPreKeyDecrypted).toBe("Olm PreKey message");
    console.log("✓ PreKey: Olm → Vodozemac works");

    // Test 5: Vodozemac sends reply → Olm receives (needed for Carol to switch to Normal)
    const vReply = daveSession.encrypt("Vodozemac reply");
    expect(vReply.message_type).toBe(1); // Normal type
    const carolDecrypted = carolSession.decrypt(vReply.message_type, vReply.ciphertext);
    expect(carolDecrypted).toBe("Vodozemac reply");
    console.log("✓ Normal: Vodozemac → Olm works");

    // Test 6: Olm sends Normal → Vodozemac receives (after receiving reply)
    const olmNormalMsg2 = carolSession.encrypt("Olm Normal message 2");
    expect(olmNormalMsg2.type).toBe(1); // Normal type
    const olmNormalDecrypted2 = daveSession.decrypt(new OlmMessage(olmNormalMsg2.type, olmNormalMsg2.body));
    expect(olmNormalDecrypted2).toBe("Olm Normal message 2");
    console.log("✓ Normal: Olm → Vodozemac works (reversed)");

    // Cleanup
    aliceAccount.free();
    bobAccount.free();
    carolAccount.free();
    daveAccount.free();
    aliceSession.free();
    bobSession.free();
    carolSession.free();
    daveSession.free();
  });

  /**
   * INTEROP TEST 2: Fresh Vodozemac outbound, Olm inbound, then Olm migrates
   *
   * - OUTBOUND: Alice (Fresh Vodozemac) → creates session
   * - INBOUND: Bob (Olm) → receives
   * - MIGRATION: Bob migrates from Olm to Vodozemac AFTER exchanges
   * - RESULT: Both peers end up on Vodozemac, continue communicating
   */
  it('should work: fresh Vodozemac outbound → Olm inbound, then migrate Olm', () => {
    // Fresh Vodozemac account
    const aliceAccount = new VodozemacAccount();

    // Fresh Olm account
    const bobAccount = new Olm.Account();
    bobAccount.create();
    bobAccount.generate_one_time_keys(1);
    bobAccount.generate_prekey();

    const bobOTKs = JSON.parse(bobAccount.one_time_keys());
    const bobOTK = Object.values(bobOTKs.curve25519)[0];
    const bobIdentityKeys = JSON.parse(bobAccount.identity_keys());
    const bobPrekey = JSON.parse(bobAccount.prekey());
    const bobPrekeyValue = String(Object.values(bobPrekey.curve25519)[0]);
    const bobPrekeySignature = bobAccount.prekey_signature();
    if (!bobPrekeySignature) throw new Error('prekey_signature is required');

    // Vodozemac Alice creates outbound session to Olm Bob
    const aliceSession = aliceAccount.create_outbound_session(
      bobIdentityKeys.curve25519,
      bobIdentityKeys.ed25519,
      bobOTK,
      bobPrekeyValue,
      bobPrekeySignature,
      true
    );

    // === Phase 1: Fresh Vodozemac → Fresh Olm ===

    // Alice sends PreKey message
    const msg1 = aliceSession.encrypt("Hello from Vodozemac!");
    expect(msg1.message_type).toBe(0); // PreKey

    // Bob receives with Olm
    const bobSession = new Olm.Session();
    bobSession.create_inbound(bobAccount, msg1.ciphertext);
    const dec1 = bobSession.decrypt(msg1.message_type, msg1.ciphertext);
    expect(dec1).toBe("Hello from Vodozemac!");

    // Bob replies
    const reply1 = bobSession.encrypt("Hello from Olm!");
    const dec2 = aliceSession.decrypt(new OlmMessage(reply1.type, reply1.body));
    expect(dec2).toBe("Hello from Olm!");

    // Continue exchange (normal messages now)
    const msg2 = aliceSession.encrypt("How are you?");
    expect(msg2.message_type).toBe(1); // Normal message
    const dec3 = bobSession.decrypt(msg2.message_type, msg2.ciphertext);
    expect(dec3).toBe("How are you?");

    const reply2 = bobSession.encrypt("I'm good!");
    const dec4 = aliceSession.decrypt(new OlmMessage(reply2.type, reply2.body));
    expect(dec4).toBe("I'm good!");

    // === Phase 2: Migrate Olm Bob → Vodozemac ===

    const bobPickle = bobSession.pickle(PICKLE_KEY_STR);
    const vodozemacBob = VodozemacSession.from_libolm_pickle(bobPickle, PICKLE_KEY);

    // Continue communication after Bob migrates
    const msg3 = aliceSession.encrypt("Still working?");
    const dec5 = vodozemacBob.decrypt(new OlmMessage(msg3.message_type, msg3.ciphertext));
    expect(dec5).toBe("Still working?");

    const reply3 = vodozemacBob.encrypt("Yes, perfect!");
    const dec6 = aliceSession.decrypt(new OlmMessage(reply3.message_type, reply3.ciphertext));
    expect(dec6).toBe("Yes, perfect!");

    // Final exchange - both Vodozemac now
    const msg4 = aliceSession.encrypt("Both Vodozemac now!");
    const dec7 = vodozemacBob.decrypt(new OlmMessage(msg4.message_type, msg4.ciphertext));
    expect(dec7).toBe("Both Vodozemac now!");

    aliceAccount.free();
    bobAccount.free();
    aliceSession.free();
    bobSession.free();
    vodozemacBob.free();
  });

  /**
   * INTEROP TEST 3: Olm outbound, Fresh Vodozemac inbound, then Olm migrates
   *
   * - OUTBOUND: Alice (Olm) → creates session
   * - INBOUND: Bob (Fresh Vodozemac) → receives
   * - MIGRATION: Alice migrates from Olm to Vodozemac AFTER exchanges
   * - RESULT: Both peers end up on Vodozemac, continue communicating
   */
  it('should work: Olm outbound → fresh Vodozemac inbound, then migrate Olm', () => {
    // Fresh Olm account
    const aliceAccount = new Olm.Account();
    aliceAccount.create();

    // Fresh Vodozemac account
    const bobAccount = new VodozemacAccount();
    bobAccount.generate_one_time_keys(1);
    bobAccount.generate_prekey();

    const bobOTK = Array.from(bobAccount.one_time_keys().values())[0];
    const bobIdKey = bobAccount.curve25519_key;
    const bobSigningKey = bobAccount.ed25519_key;
    const bobPrekey = bobAccount.prekey();
    const bobPrekeySignature = bobAccount.prekey_signature();
    if (!bobPrekey) throw new Error('prekey is required');
    if (!bobPrekeySignature) throw new Error('prekey_signature is required');

    // Olm Alice creates outbound session to Vodozemac Bob
    const aliceSession = new Olm.Session();
    aliceSession.create_outbound(
      aliceAccount,
      bobIdKey,
      bobSigningKey,
      bobPrekey,
      bobPrekeySignature,
      bobOTK
    );

    // === Phase 1: Fresh Olm → Fresh Vodozemac ===

    // Alice sends PreKey message
    const msg1 = aliceSession.encrypt("Hello from Olm!");
    expect(msg1.type).toBe(0); // PreKey

    // Bob receives with Vodozemac
    const aliceIdentityKeys = JSON.parse(aliceAccount.identity_keys());
    const result = bobAccount.create_inbound_session(
      aliceIdentityKeys.curve25519,
      new OlmMessage(msg1.type, msg1.body)
    );
    const plaintext1 = result.plaintext;
    const bobSession = result.into_session();
    expect(plaintext1).toBe("Hello from Olm!");

    // Bob replies
    const reply1 = bobSession.encrypt("Hello from Vodozemac!");
    const dec2 = aliceSession.decrypt(reply1.message_type, reply1.ciphertext);
    expect(dec2).toBe("Hello from Vodozemac!");

    // Continue exchange
    const msg2 = aliceSession.encrypt("Nice to meet you!");
    const dec3 = bobSession.decrypt(new OlmMessage(msg2.type, msg2.body));
    expect(dec3).toBe("Nice to meet you!");

    const reply2 = bobSession.encrypt("You too!");
    const dec4 = aliceSession.decrypt(reply2.message_type, reply2.ciphertext);
    expect(dec4).toBe("You too!");

    // === Phase 2: Migrate Olm Alice → Vodozemac ===

    const alicePickle = aliceSession.pickle(PICKLE_KEY_STR);
    const vodozemacAlice = VodozemacSession.from_libolm_pickle(alicePickle, PICKLE_KEY);

    // Continue communication after Alice migrates
    const msg3 = vodozemacAlice.encrypt("I migrated!");
    const dec5 = bobSession.decrypt(new OlmMessage(msg3.message_type, msg3.ciphertext));
    expect(dec5).toBe("I migrated!");

    const reply3 = bobSession.encrypt("Welcome to Vodozemac!");
    const dec6 = vodozemacAlice.decrypt(new OlmMessage(reply3.message_type, reply3.ciphertext));
    expect(dec6).toBe("Welcome to Vodozemac!");

    // Final exchange - both Vodozemac now
    const msg4 = vodozemacAlice.encrypt("We're all Vodozemac!");
    const dec7 = bobSession.decrypt(new OlmMessage(msg4.message_type, msg4.ciphertext));
    expect(dec7).toBe("We're all Vodozemac!");

    const reply4 = bobSession.encrypt("Perfect!");
    const dec8 = vodozemacAlice.decrypt(new OlmMessage(reply4.message_type, reply4.ciphertext));
    expect(dec8).toBe("Perfect!");

    aliceAccount.free();
    bobAccount.free();
    aliceSession.free();
    bobSession.free();
    vodozemacAlice.free();
  });
});
