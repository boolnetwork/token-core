use crate::{CurrentNetwork, Error};
use serde::{Deserialize, Serialize};
use snarkvm_console::account::PrivateKey;
use std::fmt::{Display, Formatter};
use std::str::FromStr;
use tcx_constants::Result;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsError;

#[wasm_bindgen]
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct AleoPrivateKey(String);

#[wasm_bindgen]
impl AleoPrivateKey {
    #[wasm_bindgen(constructor)]
    pub fn new(key: String) -> std::result::Result<AleoPrivateKey, JsError> {
        let key = Self::from_str(&key).map_err(|e| JsError::new(&e.to_string()))?;
        Ok(key)
    }

    #[wasm_bindgen(getter)]
    pub fn key(&self) -> String {
        self.0.clone()
    }

    #[wasm_bindgen(setter)]
    pub fn set_key(&mut self, key: String) -> std::result::Result<(), JsError> {
        let key = Self::from_str(&key).map_err(|e| JsError::new(&e.to_string()))?;
        self.0 = key.0;
        Ok(())
    }
}

impl AleoPrivateKey {
    pub(crate) fn raw(&self) -> Result<PrivateKey<CurrentNetwork>> {
        let sk = PrivateKey::<CurrentNetwork>::from_str(&self.0)
            .map_err(|_| Error::InvalidPrivateKey)?;
        Ok(sk)
    }
}

impl Display for AleoPrivateKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.0, f)
    }
}

impl FromStr for AleoPrivateKey {
    type Err = failure::Error;

    fn from_str(s: &str) -> Result<Self> {
        let key = PrivateKey::<CurrentNetwork>::from_str(s)
            .map_err(|_| Error::InvalidPrivateKey)?
            .to_string();
        Ok(AleoPrivateKey(key))
    }
}

#[cfg(test)]
mod tests {
    use crate::privatekey::AleoPrivateKey;
    use crate::{utils, CurrentNetwork};
    use snarkvm_console::account::{PrivateKey, TestRng};
    use std::str::FromStr;
    use wasm_bindgen::JsValue;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    const ITERATIONS: u64 = 1000;

    #[test]
    fn test_display() {
        let mut rng = TestRng::default();
        for _ in 0..ITERATIONS {
            let private_key = PrivateKey::<CurrentNetwork>::new(&mut rng).unwrap();
            let s = private_key.to_string();
            let ask = AleoPrivateKey::from_str(&s).unwrap();
            assert_eq!(s, ask.to_string())
        }
    }

    //todo test wasm methods
    #[test]
    fn test_new_private_key() {
        for _ in 0..ITERATIONS {
            let (private_key, _view_key, _address) = utils::helpers::generate_account().unwrap();
            let new_private_key = AleoPrivateKey::new(private_key.to_string())
                .map_err(|e| JsValue::from(e))
                .unwrap();
            assert_eq!(private_key, new_private_key)
        }
    }

    #[test]
    fn test_get_private_key() {
        for _ in 0..ITERATIONS {
            let (private_key, _view_key, _address) = utils::helpers::generate_account().unwrap();
            let private_key_s = private_key.key();
            assert_eq!(private_key.to_string(), private_key_s)
        }
    }

    #[test]
    fn test_set_private_key() {
        for _ in 0..ITERATIONS {
            let (mut private_key1, _view_key1, _address1) =
                utils::helpers::generate_account().unwrap();
            let (private_key2, _view_key2, _address2) = utils::helpers::generate_account().unwrap();
            private_key1
                .set_key(private_key2.key())
                .map_err(|e| JsValue::from(e))
                .unwrap();
            assert_eq!(private_key1.key(), private_key2.key())
        }
    }

    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen_test]
    fn test_private_key_wasm() {
        let (mut private_key1, _view_key1, _address1) = utils::helpers::generate_account().unwrap();
        console_log!("private_key1: {}", private_key1);
        console_log!("key in private_key1: {}", private_key1.key());
        let (private_key2, _view_key2, _address2) = utils::helpers::generate_account().unwrap();
        console_log!("key in private_key2: {}", private_key2.key());
        private_key1
            .set_key(private_key2.key())
            .map_err(|e| JsValue::from(e))
            .unwrap();
        assert_eq!(private_key1.key(), private_key2.key());
        console_log!("key in private_key1 after set: {}", private_key1.key());
    }
}
