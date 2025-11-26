// @flow

import Olm from '@commapp/olm';
import vodozemacInit, {Account as VodozemacAccount, Session as VodozemacSession, OlmMessage} from 'vodozemac';


const key = 'DEFAULT_PICKLE_KEY_1234567890___';
const fullKeyBytes = new TextEncoder().encode(key);
const PICKLE_KEY = fullKeyBytes;


describe('Account migration', () => {
  beforeAll(async () => {
    await Olm.init();
    await vodozemacInit();
  });


  it('should migrate basic account with no keys', () => {
    const olmAccount = new Olm.Account();

    olmAccount.create();
    const pickle = olmAccount.pickle(key);

    const vodozemacAccount = VodozemacAccount.from_libolm_pickle(pickle, PICKLE_KEY);

    const olmIdentityKeys = JSON.parse(olmAccount.identity_keys());
    expect(vodozemacAccount.ed25519_key).toBe(olmIdentityKeys.ed25519);
    expect(vodozemacAccount.curve25519_key).toBe(olmIdentityKeys.curve25519);
    expect(vodozemacAccount.max_number_of_one_time_keys()).toBe(olmAccount.max_number_of_one_time_keys());

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

    expect(vodozemacAccount.one_time_keys().size).toBe(10);

    // Note: Key IDs will differ between libolm and vodozemac:
    // - libolm encodes key IDs as 4-byte (u32) base64 strings (e.g., "AAAAAQ")
    // - vodozemac encodes key IDs as 8-byte (u64) base64 strings (e.g., "AAAAAAAAAAE")
    // This is expected and doesn't affect functionality - only the key VALUES matter.
    // Verify that the key values match (order should be preserved)
    const vodozemacOTKs = Object.fromEntries(vodozemacAccount.one_time_keys());
    const vodozemacValues = Object.values(vodozemacOTKs).sort();
    const olmValues = Object.values(olmOTKs.curve25519).sort();
    expect(vodozemacValues).toEqual(olmValues);

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
    expect(vodozemacAccount.one_time_keys().size).toBe(0);

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
    expect(vodozemacAccount.one_time_keys().size).toBe(5);

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

  it('should migrate account with one unpublished prekey', () => {
    const olmAccount = new Olm.Account();
    olmAccount.create();
    olmAccount.generate_prekey();

    const olmPrekey = JSON.parse(olmAccount.prekey());
    const olmPrekeyValue = String(Object.values(olmPrekey.curve25519)[0]);
    const olmPrekeySignature = olmAccount.prekey_signature();
    if (!olmPrekeySignature) throw new Error('prekey_signature is required');

    const pickle = olmAccount.pickle(key);
    const vodozemacAccount = VodozemacAccount.from_libolm_pickle(pickle, PICKLE_KEY);

    expect(vodozemacAccount.prekey()).toBe(olmPrekeyValue);
    expect(vodozemacAccount.prekey_signature()).toBe(olmPrekeySignature);
    expect(vodozemacAccount.unpublished_prekey()).toBe(olmPrekeyValue);

    olmAccount.free();
    vodozemacAccount.free();
  });

  it('should migrate account with one published prekey', () => {
    const olmAccount = new Olm.Account();
    olmAccount.create();
    olmAccount.generate_prekey();
    olmAccount.mark_prekey_as_published();

    // After marking as published, unpublished_prekey should be null
    expect(olmAccount.unpublished_prekey()).toBeNull()

    const olmPrekey = JSON.parse(olmAccount.prekey());
    const olmPrekeyValue = String(Object.values(olmPrekey.curve25519)[0]);
    const olmPrekeySignature = olmAccount.prekey_signature();
    if (!olmPrekeySignature) throw new Error('prekey_signature is required');

    const pickle = olmAccount.pickle(key);
    const vodozemacAccount = VodozemacAccount.from_libolm_pickle(pickle, PICKLE_KEY);

    expect(vodozemacAccount.prekey()).toBe(olmPrekeyValue);
    expect(vodozemacAccount.prekey_signature()).toBe(olmPrekeySignature);
    // After marking as published, unpublished_prekey should be null
    expect(vodozemacAccount.unpublished_prekey()).toBeUndefined()

    olmAccount.free();
    vodozemacAccount.free();
  });

  it('should migrate account with two prekeys (current and old)', () => {
    const olmAccount = new Olm.Account();
    olmAccount.create();

    // Generate and publish first prekey
    olmAccount.generate_prekey();
    const firstPrekey = JSON.parse(olmAccount.prekey());
    const firstPrekeyValue = String(Object.values(firstPrekey.curve25519)[0]);
    olmAccount.mark_prekey_as_published();

    // Generate second prekey (unpublished)
    olmAccount.generate_prekey();
    const secondPrekey = JSON.parse(olmAccount.prekey());
    const secondPrekeyValue = String(Object.values(secondPrekey.curve25519)[0]);

    const pickle = olmAccount.pickle(key);
    const vodozemacAccount = VodozemacAccount.from_libolm_pickle(pickle, PICKLE_KEY);

    // Current prekey should be the second one
    expect(vodozemacAccount.prekey()).toBe(secondPrekeyValue);
    expect(vodozemacAccount.unpublished_prekey()).toBe(secondPrekeyValue);
    // Both prekeys should be preserved (old one still usable for incoming sessions)
    expect(vodozemacAccount.prekey()).not.toBe(firstPrekeyValue);

    olmAccount.free();
    vodozemacAccount.free();
  });

  it('should migrate account after forgetting old prekey', () => {
    const olmAccount = new Olm.Account();
    olmAccount.create();

    // Generate and publish first prekey
    olmAccount.generate_prekey();
    olmAccount.mark_prekey_as_published();

    // Generate second prekey
    olmAccount.generate_prekey();
    olmAccount.mark_prekey_as_published();

    // Forget the old prekey
    olmAccount.forget_old_prekey();

    const currentPrekey = JSON.parse(olmAccount.prekey());
    const currentPrekeyValue = String(Object.values(currentPrekey.curve25519)[0]);

    const pickle = olmAccount.pickle(key);
    const vodozemacAccount = VodozemacAccount.from_libolm_pickle(pickle, PICKLE_KEY);

    expect(vodozemacAccount.prekey()).toBe(currentPrekeyValue);

    olmAccount.free();
    vodozemacAccount.free();
  });

  it('should preserve prekey timestamp after migration', () => {
    const olmAccount = new Olm.Account();
    olmAccount.create();
    olmAccount.generate_prekey();
    olmAccount.mark_prekey_as_published();

    const olmTimestamp = olmAccount.last_prekey_publish_time();

    const pickle = olmAccount.pickle(key);
    const vodozemacAccount = VodozemacAccount.from_libolm_pickle(pickle, PICKLE_KEY);

    expect(Number(vodozemacAccount.last_prekey_publish_time())).toBe(olmTimestamp);
    expect(olmTimestamp).toBeGreaterThan(0);

    olmAccount.free();
    vodozemacAccount.free();
  });

  it('should generate new keys after migration', () => {
    const olmAccount = new Olm.Account();
    olmAccount.create();
    olmAccount.generate_one_time_keys(5);

    const pickle = olmAccount.pickle(key);
    const vodozemacAccount = VodozemacAccount.from_libolm_pickle(pickle, PICKLE_KEY);

    expect(vodozemacAccount.one_time_keys().size).toBe(5);
    
    const keysBefore = Object.keys(Object.fromEntries(vodozemacAccount.one_time_keys())).sort();
    vodozemacAccount.generate_one_time_keys(3);
    const keysAfter = Object.keys(Object.fromEntries(vodozemacAccount.one_time_keys())).sort();

    // Expected 8 (5+3)
    expect(vodozemacAccount.one_time_keys().size).toBe(8);

    // Mark as published and verify
    vodozemacAccount.mark_keys_as_published();
    expect(vodozemacAccount.one_time_keys().size).toBe(0);

    olmAccount.free();
    vodozemacAccount.free();
  });

  it('should generate new prekeys after migration', () => {
    const olmAccount = new Olm.Account();
    olmAccount.create();
    olmAccount.generate_prekey();

    const pickle = olmAccount.pickle(key);
    const vodozemacAccount = VodozemacAccount.from_libolm_pickle(pickle, PICKLE_KEY);

    const oldPrekey = vodozemacAccount.prekey();

    // Generate new prekey
    vodozemacAccount.generate_prekey();
    const newPrekey = vodozemacAccount.prekey();

    expect(newPrekey).not.toBe(oldPrekey);
    expect(newPrekey).toBeTruthy();

    olmAccount.free();
    vodozemacAccount.free();
  });

  it('should handle account with maximum one-time keys', () => {
    const olmAccount = new Olm.Account();
    olmAccount.create();

    const maxKeys = olmAccount.max_number_of_one_time_keys();
    olmAccount.generate_one_time_keys(maxKeys);

    const pickle = olmAccount.pickle(key);
    const vodozemacAccount = VodozemacAccount.from_libolm_pickle(pickle, PICKLE_KEY);

    expect(vodozemacAccount.one_time_keys().size).toBe(maxKeys);

    olmAccount.free();
    vodozemacAccount.free();
  });
});

