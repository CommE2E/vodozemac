// @flow

import {Account} from 'vodozemac';

const PICKLE_KEY = new TextEncoder().encode('abcdef0123456789ABCDEF0123456789');

// The set of tests was developed when implementing bindings.

describe('Vodozemac Account', function () {
  it('should be created successfully with identity keys', function () {
    const account = new Account();
    expect(account.ed25519_key).toBeDefined();
    expect(account.curve25519_key).toBeDefined();
  });

  it('should generate prekeys', function () {
    const account = new Account();
    expect(account.prekey()).toBeDefined();
    expect(account.unpublished_prekey()).toBeDefined()
    expect(account.mark_prekey_as_published()).toBeTruthy();
    expect(account.mark_prekey_as_published()).toBeFalsy();
    expect(account.prekey()).toBeDefined();
    expect(account.unpublished_prekey()).toBeUndefined()
  });

  it('should generate one-time keys', function () {
    const account = new Account();
    expect(account.one_time_keys().size).toBe(0);
    account.generate_one_time_keys(10);
    expect(account.one_time_keys().size).toBe(10);
    account.mark_keys_as_published();
    expect(account.one_time_keys().size).toBe(0);
  });


  it('should return maximum number of one-time keys', function () {
    const account = new Account();
    expect(account.max_number_of_one_time_keys()).toBe(100)
  });

  it('should pickle and unpickle the account', function () {
    const account = new Account();
    const pickled = account.pickle(PICKLE_KEY);
    const unpickled = Account.from_pickle(pickled, PICKLE_KEY);
    expect(account.ed25519_key).toEqual(unpickled.ed25519_key);
    expect(account.curve25519_key).toEqual(unpickled.curve25519_key);
    expect(account.prekey()).toEqual(unpickled.prekey());
    expect(Account.from_pickle(pickled, PICKLE_KEY))
  });


  it('should throw an exception if the pickle/key is not valid', function () {
    expect(() => Account.from_pickle('pickle problem', PICKLE_KEY)).toThrow();
    const account = new Account();
    const pickled = account.pickle(PICKLE_KEY);
    expect(() => Account.from_pickle(pickled, new Uint8Array([]))).toThrow();
  });
});
