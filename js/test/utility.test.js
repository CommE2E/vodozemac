// @flow

const { Account, Utility } = require('../wasm/node/vodozemac.js');
const Olm = require('@commapp/olm');

describe('Vodozemac Utility', function () {
  let utility;
  let olmUtility;

  beforeEach(async function () {
    utility = new Utility();
    await Olm.init();
    olmUtility = new Olm.Utility();
  });

  it('should compute SHA256 hash of a string', function () {
    const input = 'Hello, World!';
    const hash = utility.sha256(input);

    expect(hash).toBeDefined();
    expect(typeof hash).toBe('string');
    expect(hash.length).toBeGreaterThan(0);
  });

  it('should compute SHA256 hash of a Uint8Array', function () {
    const input = new TextEncoder().encode('Hello, World!');
    const hash = utility.sha256(input);

    expect(hash).toBeDefined();
    expect(typeof hash).toBe('string');
    expect(hash.length).toBeGreaterThan(0);
  });

  it('should produce the same hash for string and Uint8Array with same content', function () {
    const message = 'Test message';
    const hashFromString = utility.sha256(message);
    const hashFromBytes = utility.sha256(new TextEncoder().encode(message));

    expect(hashFromString).toEqual(hashFromBytes);
  });

  it('should produce different hashes for different inputs', function () {
    const hash1 = utility.sha256('message1');
    const hash2 = utility.sha256('message2');

    expect(hash1).not.toEqual(hash2);
  });

  it('should handle empty string', function () {
    const hash = utility.sha256('');

    expect(hash).toBeDefined();
    expect(typeof hash).toBe('string');
  });

  it('should handle empty Uint8Array', function () {
    const hash = utility.sha256(new Uint8Array(0));

    expect(hash).toBeDefined();
    expect(typeof hash).toBe('string');
  });

  it('should verify a valid signature from Account.sign()', function () {
    const account = new Account();
    const message = 'Test message to sign';
    const signature = account.sign(message);
    const publicKey = account.ed25519_key;

    expect(() => {
      utility.ed25519_verify(publicKey, message, signature);
    }).not.toThrow();
  });

  it('should verify a valid signature with Uint8Array message', function () {
    const account = new Account();
    const message = 'Test message to sign';
    const signature = account.sign(message);
    const publicKey = account.ed25519_key;
    const messageBytes = new TextEncoder().encode(message);

    expect(() => {
      utility.ed25519_verify(publicKey, messageBytes, signature);
    }).not.toThrow();
  });

  it('should throw error for invalid signature', function () {
    const account = new Account();
    const message = 'Test message';
    const signature = account.sign(message);
    const publicKey = account.ed25519_key;
    const wrongMessage = 'Wrong message';

    expect(() => {
      utility.ed25519_verify(publicKey, wrongMessage, signature);
    }).toThrow();
  });

  it('should throw error for wrong public key', function () {
    const account1 = new Account();
    const account2 = new Account();
    const message = 'Test message';
    const signature = account1.sign(message);
    const wrongPublicKey = account2.ed25519_key;

    expect(() => {
      utility.ed25519_verify(wrongPublicKey, message, signature);
    }).toThrow();
  });

  it('should throw error for malformed signature', function () {
    const account = new Account();
    const message = 'Test message';
    const publicKey = account.ed25519_key;
    const invalidSignature = 'not-a-valid-signature';

    expect(() => {
      utility.ed25519_verify(publicKey, message, invalidSignature);
    }).toThrow();
  });

  it('should throw error for malformed public key', function () {
    const account = new Account();
    const message = 'Test message';
    const signature = account.sign(message);
    const invalidPublicKey = 'not-a-valid-key';

    expect(() => {
      utility.ed25519_verify(invalidPublicKey, message, signature);
    }).toThrow();
  });

  it('should verify signature for empty message', function () {
    const account = new Account();
    const message = '';
    const signature = account.sign(message);
    const publicKey = account.ed25519_key;

    expect(() => {
      utility.ed25519_verify(publicKey, message, signature);
    }).not.toThrow();
  });


  it('should produce same hash as Olm for string input', function () {
    const message = 'Test message for hashing';
    const vodozemacHash = utility.sha256(message);
    const olmHash = olmUtility.sha256(message);

    expect(vodozemacHash).toEqual(olmHash);
  });

  it('should produce same hash as Olm for Uint8Array input', function () {
    const messageBytes = new TextEncoder().encode('Binary test message');
    const vodozemacHash = utility.sha256(messageBytes);
    const olmHash = olmUtility.sha256(messageBytes);

    expect(vodozemacHash).toEqual(olmHash);
  });

  it('should produce same hash as Olm for long messages', function () {
    const longMessage = 'x'.repeat(10000);
    const vodozemacHash = utility.sha256(longMessage);
    const olmHash = olmUtility.sha256(longMessage);

    expect(vodozemacHash).toEqual(olmHash);
  });

  it('should verify Olm signature with vodozemac Utility', function () {
    const olmAccount = new Olm.Account();
    olmAccount.create();

    const identityKeys = JSON.parse(olmAccount.identity_keys());
    const ed25519Key = identityKeys.ed25519;

    const message = 'Cross-compatibility test message';
    const olmSignature = olmAccount.sign(message);

    // Vodozemac should be able to verify Olm's signature
    expect(() => {
      utility.ed25519_verify(ed25519Key, message, olmSignature);
    }).not.toThrow();

    olmAccount.free();
  });

  it('should verify vodozemac signature with Olm Utility', function () {
    const vodozemacAccount = new Account();
    const message = 'Cross-compatibility test message';
    const vodozemacSignature = vodozemacAccount.sign(message);
    const ed25519Key = vodozemacAccount.ed25519_key;

    // Olm should be able to verify vodozemac's signature
    expect(() => {
      olmUtility.ed25519_verify(ed25519Key, message, vodozemacSignature);
    }).not.toThrow();
  });

  it('should verify vodozemac signature with Uint8Array message in Olm', function () {
    const vodozemacAccount = new Account();
    const messageBytes = new TextEncoder().encode('Binary message test');
    const message = new TextDecoder().decode(messageBytes);
    const vodozemacSignature = vodozemacAccount.sign(message);
    const ed25519Key = vodozemacAccount.ed25519_key;

    // Olm should verify vodozemac's signature on binary data
    expect(() => {
      olmUtility.ed25519_verify(ed25519Key, messageBytes, vodozemacSignature);
    }).not.toThrow();
  });

  it('should verify Olm signature with Uint8Array message', function () {
    const olmAccount = new Olm.Account();
    olmAccount.create();

    const identityKeys = JSON.parse(olmAccount.identity_keys());
    const ed25519Key = identityKeys.ed25519;

    const messageBytes = new TextEncoder().encode('Binary message test');
    const olmSignature = olmAccount.sign(messageBytes);

    //TODO: this fails
    // Vodozemac should verify Olm's signature on binary data
    expect(() => {
      utility.ed25519_verify(ed25519Key, messageBytes, olmSignature);
    }).not.toThrow();

    olmAccount.free();
  });

  it('should demonstrate Olm Uint8Array signing quirk', function () {
    // This test documents a quirk in Olm's implementation:
    // Olm's sign() method converts Uint8Array to string internally,
    // so it doesn't actually sign the raw bytes.
    const olmAccount = new Olm.Account();
    olmAccount.create();

    const identityKeys = JSON.parse(olmAccount.identity_keys());
    const ed25519Key = identityKeys.ed25519;

    const message = 'Binary message test';
    const messageBytes = new TextEncoder().encode(message);

    // Sign both string and Uint8Array with Olm
    const stringSignature = olmAccount.sign(message);
    const uint8ArraySignature = olmAccount.sign(messageBytes);

    // Olm produces identical signatures for both!
    expect(stringSignature).toEqual(uint8ArraySignature);

    // Verification with string works in both Olm and vodozemac
    expect(() => {
      olmUtility.ed25519_verify(ed25519Key, message, stringSignature);
    }).not.toThrow();

    expect(() => {
      utility.ed25519_verify(ed25519Key, message, stringSignature);
    }).not.toThrow();

    // But verification with Uint8Array fails in BOTH Olm and vodozemac!
    expect(() => {
      olmUtility.ed25519_verify(ed25519Key, messageBytes, uint8ArraySignature);
    }).toThrow(/BAD_MESSAGE_MAC/);

    expect(() => {
      utility.ed25519_verify(ed25519Key, messageBytes, uint8ArraySignature);
    }).toThrow(/signature was invalid/);

    olmAccount.free();
  });

  it('should detect invalid Olm signature in vodozemac', function () {
    const olmAccount = new Olm.Account();
    olmAccount.create();

    const identityKeys = JSON.parse(olmAccount.identity_keys());
    const ed25519Key = identityKeys.ed25519;

    const message = 'Original message';
    const olmSignature = olmAccount.sign(message);

    // Vodozemac should reject signature for wrong message
    expect(() => {
      utility.ed25519_verify(ed25519Key, 'Wrong message', olmSignature);
    }).toThrow();

    olmAccount.free();
  });

  it('should detect invalid vodozemac signature in Olm', function () {
    const vodozemacAccount = new Account();
    const message = 'Original message';
    const vodozemacSignature = vodozemacAccount.sign(message);
    const ed25519Key = vodozemacAccount.ed25519_key;

    // Olm should reject signature for wrong message
    expect(() => {
      olmUtility.ed25519_verify(ed25519Key, 'Wrong message', vodozemacSignature);
    }).toThrow();
  });
});

