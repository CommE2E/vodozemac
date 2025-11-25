// @flow

import vodozemacInit, {Account, Session, OlmMessage} from 'vodozemac';

const PICKLE_KEY = new TextEncoder().encode('abcdef0123456789ABCDEF0123456789');

// The set of tests was developed when implementing bindings.

function create_session() {
  const alice = new Account();
  const bob = new Account();

  bob.generate_one_time_keys(1);
  const [otk] = Array.from(bob.one_time_keys().values());
  bob.mark_prekey_as_published();

  const session = alice.create_outbound_session(
    bob.curve25519_key,
    bob.ed25519_key,
    otk,
    bob.prekey() ?? '',
    bob.prekey_signature() ?? '',
  );

  return { alice, bob, session };
}

describe('Vodozemac Session', function () {
  beforeAll(async () => {
    await vodozemacInit();
  });

  it('should be created successfully', function () {
    const { session } = create_session();
    expect(session.session_id).toBeTruthy();
  });

  it('should create unique session id', function () {
    const { session: a } = create_session();
    const { session: b } = create_session();

    expect(a.session_id).not.toEqual(b.session_id);
  });

  it('should pickle and unpickle session', function () {
    const { session } = create_session();
    const pickled = session.pickle(PICKLE_KEY);
    const unpickled = Session.from_pickle(pickled, PICKLE_KEY);
    expect(session.session_id).toEqual(unpickled.session_id);
  });

  it('should throw an exception if the pickle/key is not valid', function () {
    expect(() => Session.from_pickle('pickle problem', PICKLE_KEY)).toThrow();
    const { session } = create_session();
    const pickled = session.pickle(PICKLE_KEY);
    expect(() => Session.from_pickle(pickled, new Uint8Array([]))).toThrow();
  });

  it('should encrypt and decrypt messages', function () {
    const plaintext = "secret message";
    const { alice, bob, session } = create_session();

    const message = session.encrypt(plaintext);
    expect(message.message_type).toBe(0);

    const result = bob.create_inbound_session(alice.curve25519_key, message);
    const decrypted = result.plaintext;
    const bob_session = result.into_session();

    expect(decrypted).toEqual(plaintext);
    expect(session.session_id).toEqual(bob_session.session_id);
  });


  it('should throw an exception if the message is not valid', function () {
    const { session } = create_session();
    const message = new OlmMessage(0, "");
    expect(() => session.decrypt(message)).toThrow();
  });

  it('should encrypt and decrypt multiple messages', function () {
    let plaintext = "secret message";
    const { alice, bob, session } = create_session();

    let message = session.encrypt(plaintext);
    expect(message.message_type).toBe(0);

    let result = bob.create_inbound_session(alice.curve25519_key, message);
    let decrypted = result.plaintext;
    let bob_session = result.into_session();

    expect(decrypted).toEqual(plaintext);
    expect(session.session_id).toEqual(bob_session.session_id);

    plaintext = 'another one';
    message = bob_session.encrypt(plaintext);
    decrypted = session.decrypt(message);

    expect(decrypted).toEqual(plaintext);
  });

  it('should throw an exception if keys invalid', function () {
    const { alice, bob } = create_session();

    expect(() => alice.create_outbound_session('a', 'b', 'c', 'd', 'e')).toThrow();

    const message = new OlmMessage(0, "");
    expect(() =>
      bob.create_inbound_session(alice.curve25519_key, message),
    ).toThrow();
  });

  it('should check if a pre-key message matches a session', function () {
    let plaintext = "secret message";
    const { alice, bob, session } = create_session();
    let message = session.encrypt(plaintext);
    const result = bob.create_inbound_session(alice.curve25519_key, message);
    const bob_session = result.into_session();

    plaintext = 'another one';
    message = session.encrypt(plaintext);

    expect(bob_session.session_matches(message)).toBeTruthy();
  });

  it("should check if a pre-key message doesn't match a session", function () {
    let message = new OlmMessage(0, "");
    const { session } = create_session();
    expect(session.session_matches(message)).toBeFalsy()
  });

});
