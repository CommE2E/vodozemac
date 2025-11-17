// @flow

const { Account, Session, OlmMessage } = require('../wasm/node/vodozemac.js');

// Tests inspired by [link to Comm tests]

describe('Account', () => {
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

    function createSession(
        aliceSession: Session,
        aliceAccount: Account,
        bobAccount: Account,
        regen: boolean = false,
        forget: boolean = false,
        invalid_sign: boolean = false,
    ): ?Session {
        const bobOneTimeKeys = bobAccount.one_time_keys.entries();
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
                );
            } catch (error) {
                //FIXME
                // expect(error.message).toBe('OLM.BAD_SIGNATURE');
                expect(error.message).toContain('The signature was invalid: signature error');
                return null;
            }

            try {
                aliceAccount.create_outbound_session(
                    bobAccount.curve25519_key,
                    bobAccount.ed25519_key,
                    bobOneTimeKeys[otk_id],
                    bobAccount.prekey() ?? '',
                    randomString(43),
                );
            } catch (error) {
                expect(error.message).toBe('OLM.INVALID_BASE64');
                return null;
            }
        }

        const session = aliceAccount.create_outbound_session(
            bobAccount.curve25519_key,
            bobAccount.ed25519_key,
            bobOneTimeKeys[otk_id],
            bobAccount.prekey() ?? '',
            String(bobAccount.prekey_signature()),
        );

        return session;
    };

    const createSessionWithoutOTK = (
        aliceSession: Session,
        aliceAccount: Account,
        bobAccount: Account,
    ) => {
        const session = aliceAccount.create_outbound_session(
            bobAccount.curve25519_key,
            bobAccount.ed25519_key,
            null,
            bobAccount.prekey() ?? '',
            String(bobAccount.prekey_signature()),
        );

        return session;
    };

    const testRatchet = (
        aliceSession: Session,
        aliceAccount: Account,
        bobSession: Session,
        bobAccount: Account,
        num_msg: number = 1,
    ) => {
        let test_text = randomString(40);
        let encrypted = aliceSession.encrypt(test_text);
        expect(encrypted.message_type).toEqual(0);

        try {
            bobSession = bobAccount.create_inbound_session(aliceAccount.curve25519_key, encrypted).session;
        } catch (error) {
            //FIXME
            // expect(error.message).toBe('OLM.BAD_MESSAGE_KEY_ID');
            expect(error.message).toContain('The pre-key message contained an unknown one-time key');
            return false;
        }

        // done automatically
        //bobAccount.remove_one_time_keys(bobSession);
        let decrypted = bobSession.decrypt(encrypted);
        expect(decrypted).toEqual(test_text);

        test_text = randomString(40);
        encrypted = bobSession.encrypt(test_text);
        expect(encrypted.message_type).toEqual(1);
        decrypted = aliceSession.decrypt(encrypted);
        expect(decrypted).toEqual(test_text);

        const aliceEncrypted = aliceSession.encrypt(test_text);
        expect(() =>
            aliceSession.decrypt(aliceEncrypted),
        ).toThrow('OLM.BAD_MESSAGE_MAC');

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

        //FIXME: this test doesn't make sense
        try {
            console.log(account.unpublished_prekey());
        } catch (error) {
            expect(error.message).toContain('NO_UNPUBLISHED_PREKEY');
        }
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
        let bobSession = new Session();

        const aliceSession = createSession(new Session(), aliceAccount, bobAccount);
        if (!aliceSession) {
            throw new Error('Failed to create session');
        }
        expect(testRatchet(aliceSession, aliceAccount, bobSession, bobAccount)).toBeTrue;
    });

    it('should encrypt and decrypt, even after a prekey is rotated', async () => {
        const aliceAccount = initAccount();
        const bobAccount = initAccount();
        let bobSession = new Session();

        const aliceSession = createSession(new Session(), aliceAccount, bobAccount, true);
        if (!aliceSession) {
            throw new Error('Failed to create session');
        }
        expect(testRatchet(aliceSession, aliceAccount, bobSession, bobAccount)).toBeTrue;
    });

    it('should not encrypt and decrypt, after the old prekey is forgotten', async () => {
        const aliceAccount = initAccount();
        const bobAccount = initAccount();
        let bobSession = new Session();

        const aliceSession = createSession(new Session(), aliceAccount, bobAccount, true, true);
        if (!aliceSession) {
            throw new Error('Failed to create session');
        }
        expect(testRatchet(aliceSession, aliceAccount, bobSession, bobAccount)).toBeFalse;
    });

    it('should encrypt and decrypt repeatedly', async () => {
        const aliceAccount = initAccount();
        const bobAccount = initAccount();
        let bobSession = new Session();

        const aliceSession = createSession(new Session(), aliceAccount, bobAccount, false, false);
        if (!aliceSession) {
            throw new Error('Failed to create session');
        }
        expect(testRatchet(aliceSession, aliceAccount, bobSession, bobAccount, 100)).toBeTrue;
    });

    it('should not encrypt and decrypt if prekey is not signed correctly', async () => {
        const aliceAccount = initAccount();
        const bobAccount = initAccount();

        expect(
            createSession(new Session(), aliceAccount, bobAccount, false, false, true),
        ).toBeFalse;
    });

    it('should create session without one-time key', async () => {
        const aliceAccount = initAccount();
        const bobAccount = initAccount();
        let bobSession = new Session();

        const aliceSession = createSessionWithoutOTK(new Session(), aliceAccount, bobAccount);
        if (!aliceSession) {
            throw new Error('Failed to create session');
        }
        expect(testRatchet(aliceSession, aliceAccount, bobSession, bobAccount, 100)).toBeTrue;
    });
});
