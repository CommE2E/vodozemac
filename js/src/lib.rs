mod account;

mod session;

pub use account::Account;
pub use session::Session;

use wasm_bindgen::prelude::*;

fn error_to_js(error: impl std::error::Error) -> JsError {
    JsError::new(&error.to_string())
}

#[wasm_bindgen(getter_with_clone, setter)]
pub struct OlmMessage {
    pub ciphertext: String,
    pub message_type: usize,
}

#[wasm_bindgen]
impl OlmMessage {
    #[wasm_bindgen(constructor)]
    pub fn new(message_type: usize, ciphertext: String) -> Self {
        Self { ciphertext, message_type }
    }
}

impl TryFrom<&OlmMessage> for vodozemac::olm::OlmMessage {
    type Error = String;

    fn try_from(message: &OlmMessage) -> Result<Self, Self::Error> {
        use vodozemac::olm;

        match message.message_type {
            0 => {
                let prekey = olm::PreKeyMessage::from_base64(&message.ciphertext)
                    .map_err(|e| e.to_string())?;
                Ok(prekey.into())
            }
            1 => {
                let msg =
                    olm::Message::from_base64(&message.ciphertext).map_err(|e| e.to_string())?;
                Ok(msg.into())
            }
            _ => Err(format!("Invalid message type: {}", message.message_type)),
        }
    }
}
