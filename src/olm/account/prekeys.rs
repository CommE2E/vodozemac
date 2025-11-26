use crate::{Curve25519PublicKey, Ed25519Keypair, Ed25519Signature, types::Curve25519SecretKey};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(feature = "js")]
use js_sys;

#[derive(Serialize, Deserialize, Clone)]
pub(super) struct PreKey {
    pub key_id: u32,
    pub published: bool,
    pub key: Curve25519SecretKey,
    #[serde(with = "serde_bytes")]
    pub signature: [u8; Ed25519Signature::LENGTH],
}

impl PreKey {
    fn new(key_id: u32, signing_key: Ed25519Keypair) -> Self {
        let key = Curve25519SecretKey::new();

        let message = Curve25519PublicKey::from(&key).to_bytes();
        let signature = signing_key.sign(&message).to_bytes();

        Self { key_id, key, published: false, signature }
    }

    pub fn public_key(&self) -> Curve25519PublicKey {
        Curve25519PublicKey::from(&self.key)
    }

    pub const fn secret_key(&self) -> &Curve25519SecretKey {
        &self.key
    }

    pub fn mark_as_published(&mut self) {
        self.published = true;
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub(super) struct PreKeys {
    pub current_prekey: Option<PreKey>,
    pub prev_prekey: Option<PreKey>,
    pub num_prekeys: u8,
    pub next_prekey_id: u32,
    pub last_prekey_publish_time: u64,
}

impl PreKeys {
    pub fn new(signing_key: Ed25519Keypair) -> Self {
        let mut prekeys = Self {
            current_prekey: None,
            prev_prekey: None,
            num_prekeys: 0,
            next_prekey_id: 0,
            last_prekey_publish_time: 0,
        };
        prekeys.generate_prekey(signing_key);
        prekeys
    }

    pub fn mark_as_published(&mut self) -> bool {
        if let Some(f) = self.current_prekey.as_mut() {
            if f.published {
                return false;
            }
            #[cfg(feature = "js")]
            let timestamp = (js_sys::Date::now() / 1000.0) as u64;

            #[cfg(not(feature = "js"))]
            let timestamp =
                SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();

            self.last_prekey_publish_time = timestamp;
            f.mark_as_published();
            true
        } else {
            false
        }
    }

    pub fn forget_old_prekey(&mut self) {
        if self.num_prekeys == 2 {
            self.prev_prekey.take();
            self.num_prekeys -= 1;
        }
    }

    pub fn get_last_prekey_publish_time(&self) -> u64 {
        self.last_prekey_publish_time
    }

    pub fn generate_prekey(&mut self, signing_key: Ed25519Keypair) {
        if self.num_prekeys < 2 {
            self.num_prekeys += 1;
        }

        self.prev_prekey = self.current_prekey.take();
        self.next_prekey_id += 1;
        self.current_prekey = Some(PreKey::new(self.next_prekey_id, signing_key));
    }

    pub fn current_prekey(&self) -> Option<&PreKey> {
        self.current_prekey.as_ref()
    }

    pub fn get_prekey_signature(&self) -> Option<String> {
        self.current_prekey.as_ref().and_then(|prekey| {
            Ed25519Signature::from_slice(&prekey.signature).ok().map(|sig| sig.to_base64())
        })
    }

    pub fn get_secret_key(&self, public_key: &Curve25519PublicKey) -> Option<&Curve25519SecretKey> {
        self.current_prekey
            .as_ref()
            .filter(|f| f.public_key() == *public_key)
            .or_else(|| self.prev_prekey.as_ref().filter(|f| f.public_key() == *public_key))
            .map(|f| f.secret_key())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prekey_initialization() {
        // Test that new PreKeys creates initial prekey
        let signing_key = Ed25519Keypair::new();
        let prekeys = PreKeys::new(signing_key);

        assert!(prekeys.current_prekey.is_some());
        assert!(prekeys.prev_prekey.is_none());
        assert_eq!(prekeys.num_prekeys, 1);
        assert_eq!(prekeys.next_prekey_id, 1);
    }

    #[test]
    fn test_prekey_rotation() {
        // Test that generating new prekey rotates current to prev
        let signing_key = Ed25519Keypair::new();
        let mut prekeys = PreKeys::new(signing_key.clone());

        let first_key_id = prekeys.current_prekey.as_ref().unwrap().key_id;
        prekeys.generate_prekey(signing_key);

        assert_eq!(prekeys.num_prekeys, 2);
        assert_eq!(prekeys.prev_prekey.as_ref().unwrap().key_id, first_key_id);
        assert_eq!(prekeys.current_prekey.as_ref().unwrap().key_id, 2);
    }

    #[test]
    fn test_mark_as_published() {
        // Test marking prekey as published updates state
        let signing_key = Ed25519Keypair::new();
        let mut prekeys = PreKeys::new(signing_key);

        assert!(!prekeys.current_prekey.as_ref().unwrap().published);
        assert!(prekeys.mark_as_published());
        assert!(prekeys.current_prekey.as_ref().unwrap().published);

        // Second call should return false
        assert!(!prekeys.mark_as_published());
    }

    #[test]
    fn test_get_secret_key() {
        // Test retrieving secret key by public key
        let signing_key = Ed25519Keypair::new();
        let mut prekeys = PreKeys::new(signing_key.clone());

        let public_key = prekeys.current_prekey.as_ref().unwrap().public_key();
        assert!(prekeys.get_secret_key(&public_key).is_some());

        // Generate new key, old one should still be findable
        prekeys.generate_prekey(signing_key);
        assert!(prekeys.get_secret_key(&public_key).is_some());
    }

    #[test]
    fn test_forget_old_prekey() {
        // Test that forget_old_prekey removes prev_prekey
        let signing_key = Ed25519Keypair::new();
        let mut prekeys = PreKeys::new(signing_key.clone());
        prekeys.generate_prekey(signing_key);

        assert_eq!(prekeys.num_prekeys, 2);
        prekeys.forget_old_prekey();
        assert_eq!(prekeys.num_prekeys, 1);
        assert!(prekeys.prev_prekey.is_none());
    }

    #[test]
    fn test_prekey_signature_verification() {
        // Test that signature can be recovered and is valid
        let signing_key = Ed25519Keypair::new();
        let prekeys = PreKeys::new(signing_key.clone());

        let prekey = prekeys.current_prekey.as_ref().unwrap();
        let curve_public_key = prekey.public_key();
        let signature = Ed25519Signature::from_slice(&prekey.signature).unwrap();

        // Verify signature matches the Curve25519 public key
        let ed_public_key = signing_key.public_key();
        assert!(ed_public_key.verify(&curve_public_key.to_bytes(), &signature).is_ok());
    }
}
