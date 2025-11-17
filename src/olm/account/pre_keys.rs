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
    //FIXME: this should be Box<>
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
        prekeys.generate_pre_key(signing_key);
        prekeys
    }

    pub fn mark_as_published(&mut self) -> bool {
        println!("mark_as_published");
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
            self.num_prekeys = self.num_prekeys - 1;
        }
    }

    pub fn get_last_prekey_publish_time(&self) -> u64 {
        self.last_prekey_publish_time
    }

    pub fn generate_pre_key(&mut self, signing_key: Ed25519Keypair) -> bool {
        if self.num_prekeys < 2 {
            self.num_prekeys += 1;
        }

        self.prev_prekey = self.current_prekey.take();
        self.next_prekey_id += 1;
        self.current_prekey = Some(PreKey::new(self.next_prekey_id, signing_key));
        true
    }

    pub fn current_pre_key(&self) -> Option<&PreKey> {
        //FIXME: should we return only not published key?
        // self.current_prekey.as_ref().filter(|f| !f.published())
        self.current_prekey.as_ref()
    }

    pub fn get_prekey_signature(&self) -> Option<String> {
        let signature =
            Ed25519Signature::from_slice(self.current_prekey.clone().unwrap().signature.as_ref());
        match signature {
            Ok(signature) => signature.to_base64().into(),
            Err(_) => None,
        }
    }

    pub fn get_secret_key(&self, public_key: &Curve25519PublicKey) -> Option<&Curve25519SecretKey> {
        self.current_prekey
            .as_ref()
            .filter(|f| f.public_key() == *public_key)
            .or_else(|| self.prev_prekey.as_ref().filter(|f| f.public_key() == *public_key))
            .map(|f| f.secret_key())
    }
}

//TODO: implement tests
