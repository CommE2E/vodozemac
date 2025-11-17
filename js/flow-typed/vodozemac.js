// @flow

declare module '../wasm/node/vodozemac.js' {
    declare export class Account {
        constructor(): Account;
        free(): void;

        static from_pickle(pickle: string, pickle_key: Uint8Array): Account;
        static from_libolm_pickle(pickle: string, pickle_key: Uint8Array): Account;

        pickle(pickle_key: Uint8Array): string;

        +ed25519_key: string;
        +curve25519_key: string;

        sign(message: string): string;

        +max_number_of_one_time_keys: number;
        +one_time_keys: Map<string, string>;

        generate_one_time_keys(count: number): void;

        +fallback_key: Map<string, string>;

        generate_fallback_key(): void;

        mark_keys_as_published(): void;
        forget_old_prekey(): void;

        mark_prekey_as_published(): boolean;

        generate_prekey(): boolean;

        last_prekey_publish_time(): bigint;

        prekey(): ?string;

        unpublished_prekey(): ?string;

        create_outbound_session(
            identity_key: string,
            signing_key: string,
            one_time_key: ?string,
            pre_key: string,
            pre_key_signature: string,
        ): Session;

        create_inbound_session(
            identity_key: string,
            message: OlmMessage,
        ): InboundCreationResult;

        prekey_signature(): ?string;
    }

    declare export class Session {
        free(): void;

        static from_pickle(pickle: string, pickle_key: Uint8Array): Session;

        pickle(pickle_key: Uint8Array): string;

        +session_id: string;

        session_matches(message: OlmMessage): boolean;

        encrypt(plaintext: string): OlmMessage;

        decrypt(message: OlmMessage): Uint8Array;

        has_received_message(): boolean;

        is_sender_chain_empty(): boolean;
    }

    declare export class OlmMessage {
        constructor(message_type: number, ciphertext: Uint8Array): OlmMessage;

        ciphertext: Uint8Array;
        message_type: number;
    }

    declare export class InboundCreationResult {
        +session: Session;
        +plaintext: Uint8Array;
    }

    declare export class SessionConfig {
    }
}
