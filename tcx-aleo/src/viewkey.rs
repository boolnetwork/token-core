use crate::address::AleoAddress;
use crate::privatekey::AleoPrivateKey;
use crate::Error::CustomError;
use crate::{CurrentNetwork, Error};
use snarkvm_console::account::{ComputeKey, PrivateKey, ViewKey};
use std::fmt::{Display, Formatter};
use std::str::FromStr;
use tcx_constants::Result;
use wasm_bindgen::{JsError, JsValue};

#[derive(Debug, PartialEq)]
pub struct AleoViewKey(String);

impl AleoViewKey {
    pub fn from_private_key(private_key: &AleoPrivateKey) -> Result<AleoViewKey> {
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

    pub fn to_address(&self) -> Result<AleoAddress> {
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
    use crate::CurrentNetwork;
    use snarkvm_console::account::{PrivateKey, Rng, TestRng, ViewKey};
    use std::str::FromStr;

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
        let mut rng = TestRng::default();
        for _ in 0..ITERATIONS {
            let sk_raw = PrivateKey::<CurrentNetwork>::new(&mut rng).unwrap();
            let sk = AleoPrivateKey::from_str(&sk_raw.to_string()).unwrap();
            let expected_raw = ViewKey::try_from(sk_raw).unwrap();
            let expected = expected_raw.to_string();

            let vk = AleoViewKey::from_private_key(&sk).unwrap();
            assert_eq!(vk.to_string(), expected);

            assert_eq!(vk, AleoViewKey(expected))
        }
    }
}
