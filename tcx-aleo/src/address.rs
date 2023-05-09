use crate::privatekey::AleoPrivateKey;
use crate::viewkey::AleoViewKey;
use crate::CurrentNetwork;
use crate::Error::{InvalidAddress, InvalidPrivateKey};
use serde::{Deserialize, Serialize};
use snarkvm_console::account::Address;
use snarkvm_console::network::Network;
use std::fmt::{Debug, Display, Formatter};
use std::str::FromStr;
use tcx_constants::Result;
use wasm_bindgen::convert::ReturnWasmAbi;
use wasm_bindgen::describe::WasmDescribe;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsValue;

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

    #[wasm_bindgen(constructor)]
    pub fn from_private_key(
        private_key: &AleoPrivateKey,
    ) -> std::result::Result<AleoAddress, JsError> {
        match AleoViewKey::from_private_key(private_key) {
            Ok(vk) => vk.to_address(),
            Err(_) => {}
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
}

impl AleoAddress {
    pub(crate) fn raw(&self) -> Result<Address<CurrentNetwork>> {
        let addr = Address::<CurrentNetwork>::from_str(&self.0).map_err(|e| InvalidAddress)?;
        Ok(addr)
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
    use crate::privatekey::AleoPrivateKey;
    use crate::viewkey::AleoViewKey;
    use crate::{utils, CurrentNetwork};
    use snarkvm_console::account::TestRng;
    use std::str::FromStr;
    use wasm_bindgen::prelude::wasm_bindgen;

    const ITERATIONS: u64 = 1000;

    #[test]
    fn test_from_str() {
        let mut rng = TestRng::default();
        for _ in 0..ITERATIONS {
            let (_private_key, _view_key, expected_address) = utils::helpers::generate_account()?;
            assert_eq!(
                expected_address,
                AleoAddress::from_str(&expected_address.to_string()).unwrap()
            )
        }
    }
}
