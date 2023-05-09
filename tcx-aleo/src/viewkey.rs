use crate::address::AleoAddress;
use crate::privatekey::AleoPrivateKey;
use crate::Error::CustomError;
use crate::{CurrentNetwork, Error};
use snarkvm_console::account::{ComputeKey, PrivateKey, ViewKey};
use std::fmt::{Display, Formatter};
use std::str::FromStr;
use tcx_constants::Result;
use wasm_bindgen::prelude::*;
use wasm_bindgen::{JsError, JsValue};

#[wasm_bindgen]
#[derive(Debug, PartialEq)]
pub struct AleoViewKey(String);

#[wasm_bindgen]
impl AleoViewKey {
    #[wasm_bindgen(constructor)]
    pub fn new(view_key: String) -> std::result::Result<AleoViewKey, JsError> {
        match Self::from_str(&view_key) {
            Ok(vk) => Ok(vk),
            Err(e) => Err(JsError::new(&e.to_string())),
        }
    }

    #[wasm_bindgen(getter)]
    pub fn key(&self) -> String {
        self.0.clone()
    }

    #[wasm_bindgen(setter)]
    pub fn set_key(&mut self, view_key: String) -> std::result::Result<(), JsError> {
        let key = Self::from_str(&view_key).map_err(|e| JsError::new(&e.to_string()))?;
        self.0 = key.0;
        Ok(())
    }

    //todo decrypt record
}

impl AleoViewKey {
    pub(crate) fn from_private_key(private_key: &AleoPrivateKey) -> Result<AleoViewKey> {
        let sk = PrivateKey::<CurrentNetwork>::from_str(&private_key.key())
            .map_err(|_| Error::InvalidPrivateKey)?;
        // Derive the compute key.
        let compute_key =
            ComputeKey::<CurrentNetwork>::try_from(sk).map_err(|e| CustomError(e.to_string()))?;
        Ok(AleoViewKey(
            ViewKey::<CurrentNetwork>::from_scalar(sk.sk_sig() + sk.r_sig() + compute_key.sk_prf())
                .to_string(),
        ))
    }

    pub(crate) fn to_address(&self) -> Result<AleoAddress> {
        let vk = ViewKey::<CurrentNetwork>::from_str(&self.0).map_err(|_| Error::InvalidViewKey)?;
        let addr = AleoAddress::new(vk.to_address().to_string())
            .map_err(|e| CustomError(JsValue::from(e).as_string().unwrap_or_default()))?;
        Ok(addr)
    }
}

impl FromStr for AleoViewKey {
    type Err = failure::Error;

    fn from_str(s: &str) -> Result<Self> {
        let vk = ViewKey::<CurrentNetwork>::from_str(s)
            .map_err(|_| Error::InvalidViewKey)?
            .to_string();
        Ok(AleoViewKey(vk))
    }
}

impl Display for AleoViewKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.0, f)
    }
}

#[cfg(test)]
mod tests {
    use crate::privatekey::AleoPrivateKey;
    use crate::viewkey::AleoViewKey;
    use crate::{utils, CurrentNetwork};
    use snarkvm_console::account::{PrivateKey, Rng, TestRng, ViewKey};
    use std::str::FromStr;
    use wasm_bindgen::JsValue;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    const ITERATIONS: u64 = 1000;

    #[test]
    fn test_from_str() {
        let mut rng = TestRng::default();
        for _ in 0..ITERATIONS {
            let sk = PrivateKey::<CurrentNetwork>::new(&mut rng).unwrap();
            let vk_s = ViewKey::try_from(&sk).unwrap().to_string();
            let mut vk_s_wrong = vk_s.clone();
            if let Some(c) = vk_s_wrong.pop() {
                loop {
                    let t: u32 = rng.gen_range(0..10);
                    if let Ok(new) = char::try_from(t) {
                        if new != c {
                            vk_s_wrong.push(new);
                            break;
                        }
                    }
                }
            }
            assert!(AleoViewKey::from_str(&vk_s).is_ok());
            assert!(AleoViewKey::from_str(&vk_s_wrong).is_err());
        }
    }

    #[test]
    fn test_from_private_key() {
        for _ in 0..ITERATIONS {
            let (private_key, view_key, _address) = utils::helpers::generate_account().unwrap();

            let expected_raw = ViewKey::try_from(private_key.raw().unwrap()).unwrap();
            let expected = expected_raw.to_string();

            let vk = AleoViewKey::from_private_key(&private_key).unwrap();
            assert_eq!(vk.to_string(), expected);

            assert_eq!(vk, AleoViewKey(expected));
            assert_eq!(vk, view_key)
        }
    }

    #[test]
    fn test_new_view_key() {
        for _ in 0..ITERATIONS {
            let (_private_key, view_key, _address) = utils::helpers::generate_account().unwrap();
            let new_view_key = AleoViewKey::new(view_key.to_string())
                .map_err(|e| JsValue::from(e))
                .unwrap();
            assert_eq!(view_key, new_view_key)
        }
    }

    #[test]
    fn test_get_view_key() {
        for _ in 0..ITERATIONS {
            let (_private_key, view_key, _address) = utils::helpers::generate_account().unwrap();
            let view_key_s = view_key.key();
            assert_eq!(view_key.to_string(), view_key_s)
        }
    }

    #[test]
    fn test_set_view_key() {
        for _ in 0..ITERATIONS {
            let (_private_key1, mut view_key1, _address1) =
                utils::helpers::generate_account().unwrap();
            let (_private_key2, view_key2, _address2) = utils::helpers::generate_account().unwrap();
            view_key1
                .set_key(view_key2.key())
                .map_err(|e| JsValue::from(e))
                .unwrap();
            assert_eq!(view_key1.key(), view_key2.key())
        }
    }

    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen_test]
    fn test_view_key_wasm() {
        let (_private_key1, mut view_key1, _address1) = utils::helpers::generate_account().unwrap();
        let new_view_key = AleoViewKey::new(view_key1.to_string())
            .map_err(|e| JsValue::from(e))
            .unwrap();
        console_log!("view_key1: {}", view_key1);
        console_log!("key in view_key1: {}", view_key1.key());
        let (_private_key2, view_key2, _address2) = utils::helpers::generate_account().unwrap();
        console_log!("key in view_key2: {}", view_key2.key());
        view_key1
            .set_key(view_key2.key())
            .map_err(|e| JsValue::from(e))
            .unwrap();
        assert_eq!(view_key1.key(), view_key2.key());
        console_log!("key in view_key1 after set: {}", view_key1.key());
    }
}
