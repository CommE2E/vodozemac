// @flow

import vodozemacInit, {Account, Session, OlmMessage} from 'vodozemac';

// Tests inspired by olm-utils.test.js in CommE2E/comm repo to make sure
// Vodozemac API is the same.
// This test does not include the sequential decrypt feature, which is not
// used anymore.

describe('vodozemac utils', () => {
  beforeAll(async () => {
    await vodozemacInit();
  });

  const alphabet =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 ';

  const randomString = (length: number) =>
    Array.from(
      { length },
      () => alphabet[Math.floor(Math.random() * alphabet.length)],
    ).join('');

  const initAccount = (mark_prekey_published: boolean = true) => {
    const account = new Account();
    account.generate_prekey();
    account.generate_one_time_keys(1);
    if (mark_prekey_published) {
      account.mark_prekey_as_published();
    }
    return account;
  };

  // In the original version, this function was getting an empty session and
  // filling the object. In Vodozemac, a session is the result of calling
  // a method on the Account object.
  function createSession(
    aliceAccount: Account,
    bobAccount: Account,
    regen: boolean = false,
    forget: boolean = false,
    invalid_sign: boolean = false,
  ): ?Session {
    const bobOneTimeKeys = bobAccount.one_time_keys().entries();
    bobAccount.mark_keys_as_published();
    const otk_id = Object.keys(bobOneTimeKeys)[0];

    if (regen) {
      bobAccount.generate_prekey();
      if (forget) {
        bobAccount.forget_old_prekey();
      }
    }

    if (invalid_sign) {
      try {
        aliceAccount.create_outbound_session(
          bobAccount.curve25519_key,
          bobAccount.ed25519_key,
          bobOneTimeKeys[otk_id],
          bobAccount.prekey() ?? '',
          bobAccount.sign(randomString(32)),
          false
        );
      } catch (error) {
        expect(error.message).toContain('The signature was invalid');
        return null;
      }

      try {
        aliceAccount.create_outbound_session(
          bobAccount.curve25519_key,
          bobAccount.ed25519_key,
          bobOneTimeKeys[otk_id],
          bobAccount.prekey() ?? '',
          randomString(43),
          false,
        );
      } catch (error) {
        expect(error.message).toContain('The signature couldn\'t be decoded');
        return null;
      }
    }

    const session = aliceAccount.create_outbound_session(
      bobAccount.curve25519_key,
      bobAccount.ed25519_key,
      bobOneTimeKeys[otk_id],
      bobAccount.prekey() ?? '',
      String(bobAccount.prekey_signature()),
      false
    );

    return session;
  }

  const createSessionWithoutOTK = (
    aliceAccount: Account,
    bobAccount: Account,
  ) => {
    const session = aliceAccount.create_outbound_session(
      bobAccount.curve25519_key,
      bobAccount.ed25519_key,
      null,
      bobAccount.prekey() ?? '',
      String(bobAccount.prekey_signature()),
      false
    );

    return session;
  };

  const testRatchet = (
    aliceSession: Session,
    aliceAccount: Account,
    bobAccount: Account,
    num_msg: number = 1,
  ) => {
    let test_text = randomString(40);
    let encrypted = aliceSession.encrypt(test_text);
    expect(encrypted.message_type).toEqual(0);

    let result;

    try {
      result = bobAccount.create_inbound_session(aliceAccount.curve25519_key, encrypted);
    } catch (error) {
      expect(error.message).toContain('The pre-key message contained an unknown one-time key');
      return false;
    }

    // Removing OTKs is now done as part of create_inbound_session.
    // There is no need for additional decryption.

    let decrypted = result.plaintext;
    expect(decrypted).toEqual(test_text);

    let bobSession = result.into_session();

    test_text = randomString(40);
    encrypted = bobSession.encrypt(test_text);
    expect(encrypted.message_type).toEqual(1);
    decrypted = aliceSession.decrypt(encrypted);

    expect(decrypted).toEqual(test_text);

    const aliceEncrypted = aliceSession.encrypt(test_text);
    expect(() =>
      aliceSession.decrypt(aliceEncrypted),
    ).toThrow('Failed decrypting Olm message, invalid MAC: MAC tag mismatch');

    for (let index = 1; index < num_msg; index++) {
      test_text = randomString(40);
      encrypted = aliceSession.encrypt(test_text);
      expect(encrypted.message_type).toEqual(1);
      decrypted = bobSession.decrypt(encrypted);

      expect(decrypted).toEqual(test_text);

      test_text = randomString(40);
      encrypted = bobSession.encrypt(test_text);
      expect(encrypted.message_type).toEqual(1);
      decrypted = aliceSession.decrypt(encrypted);

      expect(decrypted).toEqual(test_text);
    }

    expect(() =>
      aliceSession.decrypt(encrypted),
    ).toThrow('The message key with the given key can\'t be created');

    return true;
  };


  it('should generate, regenerate, forget, and publish prekey', async () => {
    const account = initAccount(false);

    expect(Number(account.last_prekey_publish_time())).toEqual(0);
    expect(account.prekey()).toBeDefined();
    expect(account.unpublished_prekey()).toBeDefined();
    account.mark_prekey_as_published();
    const last_published = account.last_prekey_publish_time();
    expect(Number(last_published)).toBeGreaterThan(0);

    // TThis condition is updated; in the original test file, it was incorrect.
    expect(account.unpublished_prekey()).toBeUndefined();
    account.forget_old_prekey();

    account.generate_prekey();
    expect(account.prekey()).toBeDefined();
    expect(account.unpublished_prekey()).toBeDefined();

    expect(account.last_prekey_publish_time()).toEqual(last_published);
    account.mark_prekey_as_published();
    expect(Number(account.last_prekey_publish_time())).toBeGreaterThanOrEqual(
      Number(last_published),
    );
    account.forget_old_prekey();
  });

  it('should encrypt and decrypt', async () => {
    const aliceAccount = initAccount();
    const bobAccount = initAccount();

    const aliceSession = createSession(aliceAccount, bobAccount);
    if (!aliceSession) {
      throw new Error('Failed to create session');
    }
    expect(testRatchet(aliceSession, aliceAccount, bobAccount)).toBeTrue;
  });

  it('should encrypt and decrypt, even after a prekey is rotated', async () => {
    const aliceAccount = initAccount();
    const bobAccount = initAccount();

    const aliceSession = createSession(aliceAccount, bobAccount, true);
    if (!aliceSession) {
      throw new Error('Failed to create session');
    }
    expect(testRatchet(aliceSession, aliceAccount, bobAccount)).toBeTrue;
  });

  it('should not encrypt and decrypt, after the old prekey is forgotten', async () => {
    const aliceAccount = initAccount();
    const bobAccount = initAccount();

    const aliceSession = createSession(aliceAccount, bobAccount, true, true);
    if (!aliceSession) {
      throw new Error('Failed to create session');
    }
    expect(testRatchet(aliceSession, aliceAccount, bobAccount)).toBeFalse;
  });

  it('should encrypt and decrypt repeatedly', async () => {
    const aliceAccount = initAccount();
    const bobAccount = initAccount();

    const aliceSession = createSession(aliceAccount, bobAccount, false, false);
    if (!aliceSession) {
      throw new Error('Failed to create session');
    }
    expect(testRatchet(aliceSession, aliceAccount, bobAccount, 100)).toBeTrue;
  });

  it('should not encrypt and decrypt if prekey is not signed correctly', async () => {
    const aliceAccount = initAccount();
    const bobAccount = initAccount();

    expect(
      createSession(aliceAccount, bobAccount, false, false, true),
    ).toBeFalse;
  });

  it('should create session without one-time key', async () => {
    const aliceAccount = initAccount();
    const bobAccount = initAccount();

    const aliceSession = createSessionWithoutOTK(aliceAccount, bobAccount);
    if (!aliceSession) {
      throw new Error('Failed to create session');
    }
    expect(testRatchet(aliceSession, aliceAccount, bobAccount, 100)).toBeTrue;
  });
});
