use crate::{CurrentNetwork, Error};
use snarkvm_console::account::PrivateKey;
use std::fmt::{Display, Formatter};
use std::str::FromStr;
use tcx_constants::Result;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsError;

#[wasm_bindgen]
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
    use crate::CurrentNetwork;
    use snarkvm_console::account::{PrivateKey, TestRng};
    use std::str::FromStr;

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
}
