use crate::privatekey::AleoPrivateKey;
use crate::viewkey::AleoViewKey;
use crate::CurrentNetwork;
use crate::Error::InvalidAddress;
use serde::{Deserialize, Serialize};
use snarkvm_console::account::Address;
use std::fmt::{Debug, Display, Formatter};
use std::str::FromStr;
use tcx_constants::Result;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct AleoAddress(String);

#[wasm_bindgen]
impl AleoAddress {
    #[wasm_bindgen(constructor)]
    pub fn new(address: String) -> std::result::Result<AleoAddress, JsError> {
        match Self::from_str(&address) {
            Ok(addr) => Ok(addr),
            Err(e) => Err(JsError::new(&e.to_string())),
        }
    }

    #[wasm_bindgen(getter)]
    pub fn address(&self) -> String {
        self.0.clone()
    }

    #[wasm_bindgen(setter)]
    pub fn set_address(&mut self, addr: String) -> std::result::Result<(), JsError> {
        let addr = Self::from_str(&addr).map_err(|e| JsError::new(&e.to_string()))?;
        self.0 = addr.0;
        Ok(())
    }

    pub fn from_private_key(private_key: String) -> std::result::Result<String, JsError> {
        let sk =
            AleoPrivateKey::from_str(&private_key).map_err(|e| JsError::new(&e.to_string()))?;
        let address =
            Self::from_private_key_internal(&sk).map_err(|e| JsError::new(&e.to_string()))?;
        Ok(address.to_string())
    }
}

impl AleoAddress {
    pub fn raw(&self) -> Result<Address<CurrentNetwork>> {
        let addr = Address::<CurrentNetwork>::from_str(&self.0).map_err(|_| InvalidAddress)?;
        Ok(addr)
    }

    pub(crate) fn from_private_key_internal(private_key: &AleoPrivateKey) -> Result<AleoAddress> {
        let vk = AleoViewKey::from_private_key_internal(private_key)?;
        vk.to_address()
    }
}

impl Display for AleoAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.0, f)
    }
}

impl FromStr for AleoAddress {
    type Err = failure::Error;

    fn from_str(s: &str) -> Result<Self> {
        let addr = Address::<CurrentNetwork>::from_str(s)
            .map_err(|_| InvalidAddress)?
            .to_string();
        Ok(AleoAddress(addr))
    }
}

#[cfg(test)]
mod tests {
    use crate::address::AleoAddress;
    use crate::utils;
    use std::str::FromStr;
    use wasm_bindgen::JsValue;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    const ITERATIONS: u64 = 1000;

    #[test]
    fn test_from_str() {
        for _ in 0..ITERATIONS {
            let (_private_key, _view_key, expected_address) =
                utils::helpers::generate_account().unwrap();
            assert_eq!(
                expected_address,
                AleoAddress::from_str(&expected_address.to_string()).unwrap()
            )
        }
    }

    #[test]
    fn test_new_address() {
        for _ in 0..ITERATIONS {
            let (_private_key, _view_key, address) = utils::helpers::generate_account().unwrap();
            let new_address = AleoAddress::new(address.to_string())
                .map_err(|e| JsValue::from(e))
                .unwrap();
            assert_eq!(address, new_address)
        }
    }

    #[test]
    fn test_get_address() {
        for _ in 0..ITERATIONS {
            let (_private_key, _view_key, address) = utils::helpers::generate_account().unwrap();
            let address_s = address.address();
            assert_eq!(address.to_string(), address_s)
        }
    }

    #[test]
    fn test_set_address() {
        for _ in 0..ITERATIONS {
            let (_private_key1, _view_key1, mut address1) =
                utils::helpers::generate_account().unwrap();
            let (_private_key2, _view_key2, address2) = utils::helpers::generate_account().unwrap();
            address1
                .set_address(address2.address())
                .map_err(|e| JsValue::from(e))
                .unwrap();
            assert_eq!(address1.address(), address2.address())
        }
    }

    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen_test]
    fn test_address_wasm() {
        let (_private_key1, _view_key1, mut address1) = utils::helpers::generate_account().unwrap();
        console_log!("address1: {}", address1);
        console_log!("address in address1: {}", address1.address());
        let (_private_key2, _view_key2, address2) = utils::helpers::generate_account().unwrap();
        console_log!("address in address2: {}", address2.address());
        address1
            .set_address(address2.address())
            .map_err(|e| JsValue::from(e))
            .unwrap();
        assert_eq!(address1, address2);
        console_log!("address in address1 after set: {}", address1.address());
    }

    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen_test]
    fn test_from_private_key() {
        let (private_key, _view_key, address_expected) =
            utils::helpers::generate_account().unwrap();
        let address = AleoAddress::from_private_key(private_key.key())
            .map_err(|e| JsValue::from(e))
            .unwrap();
        assert_eq!(address_expected.address(), address);
        console_log!("test address from_private_key: {}", address)
    }
}
