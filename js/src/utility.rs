use crate::error_to_js;
use sha2::{Digest, Sha256};
use vodozemac::{Curve25519PublicKey, Ed25519PublicKey, Ed25519Signature};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct Utility {}

#[wasm_bindgen]
impl Utility {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {}
    }

    /// Calculate the SHA-256 hash of the input and return it as base64.
    pub fn sha256(&self, input: &JsValue) -> Result<String, JsValue> {
        let bytes = if input.is_string() {
            input.as_string().unwrap().as_bytes().to_vec()
        } else {
            let uint8_array = js_sys::Uint8Array::new(input);
            uint8_array.to_vec()
        };

        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let hash = hasher.finalize();

        Ok(vodozemac::base64_encode(hash))
    }

    /// Verify an Ed25519 signature.
    pub fn ed25519_verify(
        &self,
        key: &str,
        message: &JsValue,
        signature: &str,
    ) -> Result<(), JsValue> {
        let public_key = Ed25519PublicKey::from_base64(key).map_err(error_to_js)?;
        let signature = Ed25519Signature::from_base64(signature).map_err(error_to_js)?;

        let message_bytes = if message.is_string() {
            message.as_string().unwrap().as_bytes().to_vec()
        } else {
            let uint8_array = js_sys::Uint8Array::new(message);
            uint8_array.to_vec()
        };

        public_key.verify(&message_bytes, &signature).map_err(error_to_js)?;

        Ok(())
    }
}
