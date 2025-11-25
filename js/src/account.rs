use std::collections::HashMap;

use crate::error_to_js;
use vodozemac::olm;
use wasm_bindgen::prelude::*;

use super::{session::Session, OlmMessage};

#[wasm_bindgen]
pub struct Account {
    inner: olm::Account,
}

#[wasm_bindgen]
pub struct InboundCreationResult {
    session: Session,
    plaintext: String,
}

#[wasm_bindgen]
impl InboundCreationResult {
    #[wasm_bindgen(getter)]
    pub fn plaintext(&self) -> String {
        self.plaintext.clone()
    }
    pub fn into_session(self) -> Session {
        self.session
    }
}

impl From<vodozemac::olm::InboundCreationResult> for InboundCreationResult {
    fn from(result: vodozemac::olm::InboundCreationResult) -> Self {
        let plaintext =
            String::from_utf8(result.plaintext).unwrap_or_else(|_| String::from("[Invalid UTF-8]"));
        Self { session: Session { inner: result.session }, plaintext }
    }
}

#[wasm_bindgen]
impl Account {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self { inner: vodozemac::olm::Account::new() }
    }

    pub fn pickle(&self, pickle_key: &[u8]) -> Result<String, JsValue> {
        let pickle_key: &[u8; 32] = pickle_key.try_into().map_err(error_to_js)?;
        Ok(self.inner.pickle().encrypt(pickle_key))
    }

    pub fn from_pickle(pickle: &str, pickle_key: &[u8]) -> Result<Account, JsValue> {
        let pickle_key: &[u8; 32] = pickle_key.try_into().map_err(error_to_js)?;
        let pickle = vodozemac::olm::AccountPickle::from_encrypted(pickle, pickle_key)
            .map_err(error_to_js)?;

        let inner = vodozemac::olm::Account::from_pickle(pickle);
        Ok(Self { inner })
    }

    pub fn from_libolm_pickle(pickle: &str, pickle_key: &[u8]) -> Result<Account, JsValue> {
        let inner =
            vodozemac::olm::Account::from_libolm_pickle(pickle, pickle_key).map_err(error_to_js)?;
        Ok(Self { inner })
    }

    #[wasm_bindgen(method, getter)]
    pub fn ed25519_key(&self) -> String {
        self.inner.ed25519_key().to_base64()
    }

    #[wasm_bindgen(method, getter)]
    pub fn curve25519_key(&self) -> String {
        self.inner.curve25519_key().to_base64()
    }

    pub fn sign(&self, message: &str) -> String {
        self.inner.sign(message).to_base64()
    }

    pub fn max_number_of_one_time_keys(&self) -> usize {
        self.inner.max_number_of_one_time_keys()
    }

    pub fn one_time_keys(&self) -> Result<JsValue, JsValue> {
        let keys: HashMap<_, _> = self
            .inner
            .one_time_keys()
            .into_iter()
            .map(|(k, v)| (k.to_base64(), v.to_base64()))
            .collect();

        Ok(serde_wasm_bindgen::to_value(&keys)?)
    }

    pub fn generate_one_time_keys(&mut self, count: usize) {
        self.inner.generate_one_time_keys(count);
    }

    pub fn mark_keys_as_published(&mut self) {
        self.inner.mark_keys_as_published()
    }

    pub fn mark_prekey_as_published(&mut self) -> bool {
        self.inner.mark_prekey_as_published()
    }

    pub fn generate_prekey(&mut self) {
        self.inner.generate_prekey()
    }

    pub fn forget_old_prekey(&mut self) {
        self.inner.forget_old_prekey()
    }

    pub fn last_prekey_publish_time(&mut self) -> u64 {
        self.inner.get_last_prekey_publish_time()
    }

    pub fn prekey(&self) -> Option<String> {
        if let Some(key) = self.inner.prekey() {
            Some(key.to_base64())
        } else {
            None
        }
    }

    pub fn unpublished_prekey(&self) -> Option<String> {
        if let Some(key) = self.inner.unpublished_prekey() {
            Some(key.to_base64())
        } else {
            None
        }
    }

    pub fn prekey_signature(&self) -> Option<String> {
        self.inner.get_prekey_signature()
    }

    pub fn create_outbound_session(
        &self,
        identity_key: &str,
        signing_key: &str,
        one_time_key: Option<String>,
        pre_key: &str,
        pre_key_signature: &str,
        olm_compatibility_mode: bool,
    ) -> Result<Session, JsValue> {
        let session_config = vodozemac::olm::SessionConfig::version_1();
        let identity_key =
            vodozemac::Curve25519PublicKey::from_base64(identity_key).map_err(error_to_js)?;
        let signing_key =
            vodozemac::Ed25519PublicKey::from_base64(signing_key).map_err(error_to_js)?;
        let one_time_key = match one_time_key {
            None => None,
            Some(key) => Some(
                vodozemac::Curve25519PublicKey::from_base64(key.as_ref()).map_err(error_to_js)?,
            ),
        };
        let pre_key = vodozemac::Curve25519PublicKey::from_base64(pre_key).map_err(error_to_js)?;

        let session = self
            .inner
            .create_outbound_session(
                session_config,
                identity_key,
                signing_key,
                one_time_key,
                pre_key,
                pre_key_signature.to_string(),
                olm_compatibility_mode,
            )
            .map_err(error_to_js)?;

        Ok(Session { inner: session })
    }

    pub fn create_inbound_session(
        &mut self,
        identity_key: &str,
        message: &OlmMessage,
    ) -> Result<InboundCreationResult, JsValue> {
        let identity_key =
            vodozemac::Curve25519PublicKey::from_base64(identity_key).map_err(error_to_js)?;
        let olm_message: olm::OlmMessage = message.try_into().map_err(JsValue::from)?;

        if let olm::OlmMessage::PreKey(message) = olm_message {
            Ok(self
                .inner
                .create_inbound_session(identity_key, &message)
                .map_err(error_to_js)?
                .into())
        } else {
            Err(JsError::new("Invalid message type, expected a pre-key message").into())
        }
    }
}
