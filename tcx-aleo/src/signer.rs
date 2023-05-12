use crate::privatekey::AleoPrivateKey;
use crate::request::AleoProgramRequest;
use crate::CurrentNetwork;
use snarkvm_console::account::{Field, Signature};
use std::str::FromStr;
use wasm_bindgen::prelude::*;
use wasm_bindgen::{JsError, JsValue};

#[wasm_bindgen]
impl AleoPrivateKey {
    /// Returns a singed program request and a signed fee request if it has
    #[wasm_bindgen]
    pub async fn sign_program_request(
        &self,
        aleo_request: String,
    ) -> std::result::Result<JsValue, JsError> {
        let aleo_request = serde_json::from_str::<AleoProgramRequest>(&aleo_request)
            .map_err(|e| JsError::new(&e.to_string()))?;
        let signed = aleo_request
            .sign(self)
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;
        serde_wasm_bindgen::to_value(&signed).map_err(|e| JsError::new(&e.to_string()))
    }

    /// Returns a signature for the given message (as field elements) using the private key.
    #[wasm_bindgen]
    pub fn sign(&self, message: String) -> std::result::Result<String, JsError> {
        let rng = &mut rand::thread_rng();

        let message = serde_json::from_str::<Vec<String>>(&message)
            .map_err(|e| JsError::new(&e.to_string()))?;

        let mut msgs = Vec::with_capacity(message.len());
        for msg in message {
            let f = Field::<CurrentNetwork>::from_str(&msg)
                .map_err(|e| JsError::new(&e.to_string()))?;
            msgs.push(f)
        }

        let signature = Signature::<CurrentNetwork>::sign(
            &self.raw().map_err(|e| JsError::new(&e.to_string()))?,
            msgs.as_slice(),
            rng,
        )
        .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(signature.to_string())
    }

    /// Returns a signature for the given message (as bytes) using the private key.
    #[wasm_bindgen]
    pub fn sign_bytes(&self, message: &[u8]) -> std::result::Result<String, JsError> {
        let rng = &mut rand::thread_rng();
        let signature = Signature::<CurrentNetwork>::sign_bytes(
            &self.raw().map_err(|e| JsError::new(&e.to_string()))?,
            message,
            rng,
        )
        .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(signature.to_string())
    }

    /// Returns a signature for the given message (as bits) using the private key.
    #[wasm_bindgen]
    pub fn sign_bits(&self, message: JsValue) -> std::result::Result<String, JsError> {
        let message: Vec<bool> = serde_wasm_bindgen::from_value(message)?;
        let rng = &mut rand::thread_rng();
        let signature = Signature::<CurrentNetwork>::sign_bits(
            &self.raw().map_err(|e| JsError::new(&e.to_string()))?,
            message.as_slice(),
            rng,
        )
        .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(signature.to_string())
    }
}

#[cfg(test)]
mod tests {
    use crate::request::AleoProgramRequest;
    use crate::{utils, CurrentNetwork};
    use snarkvm_console::account::{Signature, TestRng, Uniform};
    use snarkvm_console::program::{Plaintext, Record, Request};
    use snarkvm_console::types::Field;
    use std::str::FromStr;
    use wasm_bindgen::JsValue;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    const ITERATIONS: u64 = 100;

    #[test]
    fn test_sign_and_verify() {
        let rng = &mut TestRng::default();

        for i in 0..ITERATIONS {
            // Sample an address and a private key.
            let (private_key, _view_key, address) = utils::helpers::generate_account().unwrap();
            let address_raw = &address.raw().unwrap();
            // Check that the signature is valid for the message.
            let message: Vec<_> = (0..i)
                .map(|_| Uniform::rand(rng))
                .collect::<Vec<Field<CurrentNetwork>>>()
                .into_iter()
                .map(|msg| msg.to_string())
                .collect();
            let message_s = serde_json::to_string(&message).unwrap();
            let signature = private_key
                .sign(message_s)
                .map_err(|e| JsValue::from(e))
                .unwrap();
            let message = message
                .into_iter()
                .map(|msg| Field::<CurrentNetwork>::from_str(&msg).unwrap())
                .collect::<Vec<Field<CurrentNetwork>>>();
            let signature = Signature::<CurrentNetwork>::from_str(&signature).unwrap();
            assert!(signature.verify(address_raw, message.as_slice()));

            // Check that the signature is invalid for an incorrect message.
            let failure_message: Vec<_> = (0..i).map(|_| Uniform::rand(rng)).collect();
            if message != failure_message {
                assert!(!signature.verify(address_raw, &failure_message));
            }
        }
    }

    // #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen_test]
    async fn test_sign_request() {
        let (private_key, _view_key, address) = utils::helpers::generate_account().unwrap();

        let query = "https://vm.aleo.org/api".to_string();

        let inputs1 = vec![address.address(), "10000u64".to_string()];
        let aleo_program_request = AleoProgramRequest::new(
            "credits.aleo".to_string(),
            "mint".to_string(),
            serde_json::to_string(&inputs1).unwrap(),
            query.clone(),
        );

        let res1 = private_key
            .sign_program_request(aleo_program_request.to_string())
            .await
            .map_err(|e| JsValue::from(e))
            .unwrap();
        console_log!("res1: {:?}", res1);
        let program_signed_1 =
            &serde_wasm_bindgen::from_value::<Request<CurrentNetwork>>(res1).unwrap();

        assert_eq!(
            program_signed_1.program_id().to_string(),
            aleo_program_request.program_id()
        );
        assert_eq!(program_signed_1.inputs().len(), inputs1.len());
        assert_eq!(
            program_signed_1.function_name().to_string(),
            aleo_program_request.function_name()
        );

        let fee_record = Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::from_str(&format!(
            "{{
  owner: {}.private,
  microcredits: 50000000u64.private,
  _nonce: 6284621587203125875149547889323796299059507753986233073895647656902474803214group.public
}}",
            address.address()
        ))
        .unwrap();

        let inputs2 = vec![fee_record.to_string(), "1000u64".to_string()];
        let fee_request = AleoProgramRequest::new(
            "credits.aleo".to_string(),
            "fee".to_string(),
            serde_json::to_string(&inputs2).unwrap(),
            query.clone(),
        );

        let res2 = private_key
            .sign_program_request(fee_request.to_string())
            .await
            .map_err(|e| JsValue::from(e))
            .unwrap();
        console_log!("res2: {:?}", res2);
        let program_signed_2 =
            &serde_wasm_bindgen::from_value::<Request<CurrentNetwork>>(res2).unwrap();

        assert_eq!(
            program_signed_2.program_id().to_string(),
            fee_request.program_id()
        );
        assert_eq!(program_signed_2.inputs().len(), inputs2.len());
        assert_eq!(
            program_signed_2.function_name().to_string(),
            fee_request.function_name()
        );
    }

    #[test]
    fn test_sign_and_verify_bytes() {
        let rng = &mut TestRng::default();

        for i in 0..ITERATIONS {
            // Sample an address and a private key.
            let (private_key, _view_key, address) = utils::helpers::generate_account().unwrap();
            let address_raw = &address.raw().unwrap();
            // Check that the signature is valid for the message.
            let message: Vec<_> = (0..i).map(|_| Uniform::rand(rng)).collect();
            let signature = private_key
                .sign_bytes(&message)
                .map_err(|e| JsValue::from(e))
                .unwrap();
            let signature = Signature::<CurrentNetwork>::from_str(&signature).unwrap();
            assert!(signature.verify_bytes(address_raw, &message));

            // Check that the signature is invalid for an incorrect message.
            let failure_message: Vec<_> = (0..i).map(|_| Uniform::rand(rng)).collect();
            if message != failure_message {
                assert!(!signature.verify_bytes(address_raw, &failure_message));
            }
        }
    }

    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen_test]
    fn test_sign_and_verify_bits() {
        let rng = &mut TestRng::default();

        for i in 0..ITERATIONS {
            // Sample an address and a private key.
            let (private_key, _view_key, address) = utils::helpers::generate_account().unwrap();
            let address_raw = &address.raw().unwrap();
            // Check that the signature is valid for the message.
            let message: Vec<_> = (0..i).map(|_| Uniform::rand(rng)).collect();
            let message_js = serde_wasm_bindgen::to_value(&message).unwrap();
            let signature = private_key
                .sign_bits(message_js)
                .map_err(|e| JsValue::from(e))
                .unwrap();
            let signature = Signature::<CurrentNetwork>::from_str(&signature).unwrap();
            assert!(signature.verify_bits(address_raw, &message));

            // Check that the signature is invalid for an incorrect message.
            let failure_message: Vec<_> = (0..i).map(|_| Uniform::rand(rng)).collect();
            if message != failure_message {
                assert!(!signature.verify_bits(address_raw, &failure_message));
            }
        }
    }
}