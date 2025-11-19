// @flow

const Olm = require('@commapp/olm');
const { Account } = require('../wasm/node/vodozemac.js');

describe('Olm/Vodozemac is_sender_chain_empty behavior', () => {

  beforeAll(async () => {
    await Olm.init();
  });

  it('should match ratchet_counts test expectations for Olm', () => {
    // Create Alice and Bob accounts
    const aliceAccount = new Olm.Account();
    const bobAccount = new Olm.Account();
    aliceAccount.create();
    bobAccount.create();

    bobAccount.generate_one_time_keys(1);
    bobAccount.generate_prekey();

    const bobOneTimeKeys = JSON.parse(bobAccount.one_time_keys()).curve25519;
    const bobOneTimeKey = Object.values(bobOneTimeKeys)[0];
    const bobIdentityKeys = JSON.parse(bobAccount.identity_keys());
    const bobPrekey = JSON.parse(bobAccount.prekey());
    const bobPrekeyValue = String(Object.values(bobPrekey.curve25519)[0]);
    const bobPrekeySignature = bobAccount.prekey_signature();
    if (!bobPrekeySignature) throw new Error('prekey_signature is required');

    // Alice creates outbound session
    const aliceSession = new Olm.Session();
    expect(aliceSession.is_sender_chain_empty()).toBe(true); // Alice is active
    aliceSession.create_outbound(
      aliceAccount,
      bobIdentityKeys.curve25519,
      bobIdentityKeys.ed25519,
      bobPrekeyValue,
      bobPrekeySignature,
      bobOneTimeKey
    );

    // Initial state - Both ratchets should start with empty sender chains
    expect(aliceSession.is_sender_chain_empty()).toBe(false); // Alice is active

    // Alice sends first message
    const firstMessage = aliceSession.encrypt("Hello");

    // Bob creates inbound session
    const bobSession = new Olm.Session();
    bobSession.create_inbound(bobAccount, firstMessage.body);
    bobSession.decrypt(firstMessage.type, firstMessage.body);

    expect(bobSession.is_sender_chain_empty()).toBe(true); // Bob never sent

    // Bob replies
    const bobReply = bobSession.encrypt("Hi Alice");

    expect(bobSession.is_sender_chain_empty()).toBe(false); // Bob just encrypted

    // Alice receives Bob's reply
    aliceSession.decrypt(bobReply.type, bobReply.body);

    expect(aliceSession.is_sender_chain_empty()).toBe(true); // Alice is inactive after receiving

    // Alice replies again
    const aliceReply = aliceSession.encrypt("Hello again");

    expect(aliceSession.is_sender_chain_empty()).toBe(false); // Alice is active, just encrypted

    // Bob receives Alice's reply
    bobSession.decrypt(aliceReply.type, aliceReply.body);

    expect(bobSession.is_sender_chain_empty()).toBe(true); // Bob is inactive after receiving

    // Cleanup
    aliceSession.free();
    bobSession.free();
    aliceAccount.free();
    bobAccount.free();
  });

  it('should match ratchet_counts test expectations for Vodozemac', () => {
    // Create Alice and Bob accounts
    const aliceAccount = new Account();
    const bobAccount = new Account();

    bobAccount.generate_one_time_keys(1);
    bobAccount.generate_prekey();

    const bobOneTimeKeys = bobAccount.one_time_keys();
    const bobOneTimeKey = Array.from(bobOneTimeKeys.values())[0];
    const bobPrekey = bobAccount.prekey();
    const bobPrekeySignature = bobAccount.prekey_signature();
    if (!bobPrekey) throw new Error('prekey is required');
    if (!bobPrekeySignature) throw new Error('prekey_signature is required');

    // Alice creates outbound session
    const aliceSession = aliceAccount.create_outbound_session(
      bobAccount.curve25519_key,
      bobAccount.ed25519_key,
      bobOneTimeKey,
      bobPrekey,
      bobPrekeySignature,
      false
    );

    // Initial state - Both ratchets should start with empty sender chains
    expect(aliceSession.is_sender_chain_empty()).toBe(false); // Alice is active

    // Alice sends first message
    const firstMessage = aliceSession.encrypt("Hello");

    // Bob creates inbound session
    const result = bobAccount.create_inbound_session(aliceAccount.curve25519_key, firstMessage);
    const bobSession = result.into_session();

    expect(bobSession.is_sender_chain_empty()).toBe(true); // Bob never sent

    // Bob replies
    const bobReply = bobSession.encrypt("Hi Alice");

    expect(bobSession.is_sender_chain_empty()).toBe(false); // Bob just encrypted

    // Alice receives Bob's reply
    aliceSession.decrypt(bobReply);

    expect(aliceSession.is_sender_chain_empty()).toBe(true); // Alice is inactive after receiving

    // Alice replies again
    const aliceReply = aliceSession.encrypt("Hello again");

    expect(aliceSession.is_sender_chain_empty()).toBe(false); // Alice is active, just encrypted

    // Bob receives Alice's reply
    bobSession.decrypt(aliceReply);

    expect(bobSession.is_sender_chain_empty()).toBe(true); // Bob is inactive after receiving

    // Cleanup
    aliceSession.free();
    bobSession.free();
    aliceAccount.free();
    bobAccount.free();
  });
});
