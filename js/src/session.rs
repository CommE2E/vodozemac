use vodozemac::olm;
use vodozemac::olm::MessageType;
use wasm_bindgen::prelude::*;

use crate::error_to_js;

use super::OlmMessage;

#[wasm_bindgen]
pub struct Session {
    pub(super) inner: vodozemac::olm::Session,
}

#[wasm_bindgen]
impl Session {
    pub fn pickle(&self, pickle_key: &[u8]) -> Result<String, JsValue> {
        let pickle_key: &[u8; 32] = pickle_key.try_into().map_err(error_to_js)?;
        Ok(self.inner.pickle().encrypt(pickle_key))
    }

    pub fn from_pickle(pickle: &str, pickle_key: &[u8]) -> Result<Session, JsValue> {
        let pickle_key: &[u8; 32] = pickle_key.try_into().map_err(error_to_js)?;
        let pickle = vodozemac::olm::SessionPickle::from_encrypted(pickle, pickle_key)
            .map_err(error_to_js)?;

        let session = olm::Session::from_pickle(pickle);
        Ok(Self { inner: session })
    }

    pub fn from_libolm_pickle(pickle: &str, pickle_key: &[u8]) -> Result<Session, JsValue> {
        let session =
            vodozemac::olm::Session::from_libolm_pickle(pickle, pickle_key).map_err(error_to_js)?;
        Ok(Self { inner: session })
    }

    #[wasm_bindgen(getter)]
    pub fn session_id(&self) -> String {
        self.inner.session_id()
    }

    pub fn session_matches(&self, message: &OlmMessage) -> bool {
        match message.try_into() {
            Ok(olm::OlmMessage::PreKey(m)) => self.inner.session_keys() == m.session_keys(),
            _ => false,
        }
    }

    pub fn encrypt(&mut self, plaintext: &str) -> OlmMessage {
        let message = self.inner.encrypt(plaintext);
        let (message_type, encrypted_message) = match message {
            olm::OlmMessage::PreKey(msg) => (0, msg.to_base64()),
            olm::OlmMessage::Normal(msg) => (1, msg.to_base64()),
        };

        OlmMessage { ciphertext: encrypted_message, message_type }
    }

    pub fn decrypt(&mut self, message: &OlmMessage) -> Result<String, JsValue> {
        let olm_message: olm::OlmMessage = message.try_into().map_err(JsValue::from)?;
        let plaintext = self.inner.decrypt(&olm_message).map_err(error_to_js)?;
        String::from_utf8(plaintext).map_err(|e| JsValue::from(e.to_string()))
    }

    pub fn has_received_message(&self) -> bool {
        self.inner.has_received_message()
    }

    pub fn is_sender_chain_empty(&self) -> bool {
        self.inner.is_sender_chain_empty()
    }
}
