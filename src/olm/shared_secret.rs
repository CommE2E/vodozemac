// Copyright 2021 Damir Jelić
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! A 3DH implementation following the Olm [spec].
//!
//! The setup takes four Curve25519 inputs: Identity keys for Alice and Bob,
//! (Ia, Ib), and one-time keys for Alice and Bob (Ea, Eb).
//!
//! A shared secret S is generated via Triple Diffie-Hellman using the above
//! inputs. The initial 256-bit root key R0 and a 256-bit chain key C0,0 are
//! derived from the shared secret using an HMAC-based Key Derivation Function
//! with SHA-256 as the hash function (HKDF-SHA-256), the default salt and
//! "OLM_ROOT" as the info.
//!
//! ```text
//!     S = ECDH(Ia, Eb) || ECDH(Ea, Ib) || ECDH (Ea, Eb)
//!
//!     R0, C0,0 = HKDF(0, S, "OLM_ROOT", 64)
//! ```
//!
//! [spec]: https://gitlab.matrix.org/matrix-org/olm/-/blob/master/docs/olm.md#initial-setup

use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{ReusableSecret, SharedSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Curve25519PublicKey as PublicKey, types::Curve25519SecretKey as StaticSecret};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SharedX3DHSecret {
    secret: Box<[u8; 128]>,
    secret_length: usize,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RemoteSharedX3DHSecret {
    secret: Box<[u8; 128]>,
    secret_length: usize,
}

fn expand(shared_secret: &[u8; 128], secret_length: usize) -> (Box<[u8; 32]>, Box<[u8; 32]>) {
    // COMPATIBILITY: Comm/olm has a bug where it only uses 3 or 4 bytes
    // of the shared secret for HKDF instead of the full 96 or 128 bytes.
    // Temporary replicate this bug for compatibility.
    let hkdf: Hkdf<Sha256> = Hkdf::new(Some(&[0]), &shared_secret[..secret_length]);
    let mut root_key = Box::new([0u8; 32]);
    let mut chain_key = Box::new([0u8; 32]);

    let mut expanded_keys = [0u8; 64];

    #[allow(clippy::expect_used)]
    hkdf.expand(b"OLM_ROOT", &mut expanded_keys)
        .expect("We should be able to expand the shared 3DH secret into the Olm root");

    root_key.copy_from_slice(&expanded_keys[0..32]);
    chain_key.copy_from_slice(&expanded_keys[32..64]);

    expanded_keys.zeroize();

    (root_key, chain_key)
}

fn merge_secrets(
    first_secret: SharedSecret,
    second_secret: SharedSecret,
    third_secret: SharedSecret,
    fourth_secret: Option<SharedSecret>,
) -> Box<[u8; 128]> {
    let mut secret = Box::new([0u8; 128]);

    secret[0..32].copy_from_slice(first_secret.as_bytes());
    secret[32..64].copy_from_slice(second_secret.as_bytes());
    secret[64..96].copy_from_slice(third_secret.as_bytes());
    if let Some(fourth_secret) = fourth_secret {
        secret[96..].copy_from_slice(fourth_secret.as_bytes());
    }

    secret
}

impl RemoteSharedX3DHSecret {
    pub(crate) fn new(
        identity_key: &StaticSecret,
        one_time_key: &StaticSecret,
        remote_identity_key: &PublicKey,
        remote_one_time_key: &PublicKey,
        pre_key_secret: &StaticSecret,
        olm_compatibility_mode: bool,
    ) -> Self {
        // Check if the sender used prekey as OTK by comparing their bytes.
        // If OTK == prekey, the sender didn't have an OTK available and used
        // the prekey as OTK instead.
        // This is for compatibility with our Olm fork.
        let using_prekey_as_otk =
            PublicKey::from(one_time_key).to_bytes() == PublicKey::from(pre_key_secret).to_bytes();

        let first_secret = one_time_key.diffie_hellman(remote_identity_key);
        let second_secret = identity_key.diffie_hellman(remote_one_time_key);
        let third_secret = one_time_key.diffie_hellman(remote_one_time_key);

        let fourth_secret = match using_prekey_as_otk {
            true => None,
            false => pre_key_secret.diffie_hellman(remote_one_time_key).into(),
        };

        let secret = merge_secrets(first_secret, second_secret, third_secret, fourth_secret);

        // COMPATIBILITY: Comm/olm has a bug where it only uses 3 or 4 bytes
        // of the shared secret for HKDF instead of the full 96 or 128 bytes.
        // Temporary replicate this bug for compatibility.
        let secret_length = if olm_compatibility_mode {
            if using_prekey_as_otk { 3 } else { 4 }
        } else if using_prekey_as_otk {
            96
        } else {
            128
        };

        Self { secret, secret_length }
    }

    pub fn expand(self) -> (Box<[u8; 32]>, Box<[u8; 32]>) {
        expand(&self.secret, self.secret_length)
    }
}

impl SharedX3DHSecret {
    pub(crate) fn new(
        identity_key: &StaticSecret,
        one_time_key: &ReusableSecret,
        remote_identity_key: &PublicKey,
        remote_one_time_key: &Option<PublicKey>,
        remote_prekey: &PublicKey,
        olm_compatibility_mode: bool,
    ) -> Self {
        let unwrapped_remote_one_time_key = remote_one_time_key.unwrap_or_else(|| *remote_prekey);
        let first_secret = identity_key.diffie_hellman(&unwrapped_remote_one_time_key);
        let second_secret = one_time_key.diffie_hellman(&remote_identity_key.inner);
        let third_secret = one_time_key.diffie_hellman(&unwrapped_remote_one_time_key.inner);
        let fourth_secret = match remote_one_time_key {
            None => None,
            Some(_) => one_time_key.diffie_hellman(&remote_prekey.inner).into(),
        };

        let secret = merge_secrets(first_secret, second_secret, third_secret, fourth_secret);

        // COMPATIBILITY: Comm/olm has a bug where it only uses 3 or 4 bytes
        // of the shared secret for HKDF instead of the full 96 or 128 bytes.
        // Temporary replicate this bug for compatibility.
        let secret_length = if olm_compatibility_mode {
            if remote_one_time_key.is_some() { 4 } else { 3 }
        } else if remote_one_time_key.is_some() {
            128
        } else {
            96
        };

        Self { secret, secret_length }
    }

    pub fn expand(self) -> (Box<[u8; 32]>, Box<[u8; 32]>) {
        expand(&self.secret, self.secret_length)
    }
}

#[cfg(test)]
mod test {
    use rand::thread_rng;
    use x25519_dalek::ReusableSecret;

    use super::{RemoteSharedX3DHSecret, SharedX3DHSecret};
    use crate::{Curve25519PublicKey as PublicKey, types::Curve25519SecretKey as StaticSecret};

    #[test]
    fn triple_diffie_hellman() {
        let rng = thread_rng();

        let alice_identity = StaticSecret::new();
        let alice_one_time = ReusableSecret::random_from_rng(rng);

        let bob_identity = StaticSecret::new();
        let bob_one_time = StaticSecret::new();

        let bob_prekey = StaticSecret::new();

        let alice_secret = SharedX3DHSecret::new(
            &alice_identity,
            &alice_one_time,
            &PublicKey::from(&bob_identity),
            &PublicKey::from(&bob_one_time).into(),
            &PublicKey::from(&bob_prekey),
            false,
        );

        let bob_secret = RemoteSharedX3DHSecret::new(
            &bob_identity,
            &bob_one_time,
            &PublicKey::from(&alice_identity),
            &PublicKey::from(&alice_one_time),
            &bob_prekey,
            false,
        );

        assert_eq!(alice_secret.secret, bob_secret.secret);
        assert_eq!(alice_secret.secret_length, bob_secret.secret_length);

        let alice_result = alice_secret.expand();
        let bob_result = bob_secret.expand();

        assert_eq!(alice_result, bob_result);
    }

    #[test]
    fn triple_diffie_hellman_olm_compatibility() {
        let rng = thread_rng();

        let alice_identity = StaticSecret::new();
        let alice_one_time = ReusableSecret::random_from_rng(rng);

        let bob_identity = StaticSecret::new();
        let bob_one_time = StaticSecret::new();

        let bob_prekey = StaticSecret::new();

        let alice_secret = SharedX3DHSecret::new(
            &alice_identity,
            &alice_one_time,
            &PublicKey::from(&bob_identity),
            &PublicKey::from(&bob_one_time).into(),
            &PublicKey::from(&bob_prekey),
            true,
        );

        let bob_secret = RemoteSharedX3DHSecret::new(
            &bob_identity,
            &bob_one_time,
            &PublicKey::from(&alice_identity),
            &PublicKey::from(&alice_one_time),
            &bob_prekey,
            true,
        );

        assert_eq!(alice_secret.secret, bob_secret.secret);
        assert_eq!(alice_secret.secret_length, bob_secret.secret_length);

        let alice_result = alice_secret.expand();
        let bob_result = bob_secret.expand();

        assert_eq!(alice_result, bob_result);
    }
}
