use crate::address::AleoAddress;
use crate::privatekey::AleoPrivateKey;
use crate::Error;
use crate::Error::CustomError;
use snarkvm_console::account::{ComputeKey, ViewKey};
use snarkvm_console::network::Network;
use std::fmt::{Display, Formatter};
use std::str::FromStr;
use tcx_constants::Result;

#[derive(Debug, PartialEq)]
pub struct AleoViewKey<N: Network>(ViewKey<N>);

impl<N: Network> AleoViewKey<N> {
    pub fn from_private_key(private_key: &AleoPrivateKey<N>) -> Result<AleoViewKey<N>> {
        // Derive the compute key.
        let compute_key =
            ComputeKey::<N>::try_from(private_key.0).map_err(|e| CustomError(e.to_string()))?;
        Ok(AleoViewKey(ViewKey::<N>::from_scalar(
            private_key.0.sk_sig() + private_key.0.r_sig() + compute_key.sk_prf(),
        )))
    }

    pub fn to_address(&self) -> AleoAddress<N> {
        AleoAddress::<N>::new(self.0.to_address())
    }
}

impl<N: Network> FromStr for AleoViewKey<N> {
    type Err = failure::Error;

    fn from_str(s: &str) -> Result<Self> {
        let vk = ViewKey::<N>::from_str(s).map_err(|_| Error::InvalidViewKey)?;
        Ok(AleoViewKey(vk))
    }
}

impl<N: Network> Display for AleoViewKey<N> {
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
        for i in 0..ITERATIONS {
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
            assert!(AleoViewKey::<CurrentNetwork>::from_str(&vk_s).is_ok());
            assert!(AleoViewKey::<CurrentNetwork>::from_str(&vk_s_wrong).is_err());
        }
    }

    #[test]
    fn test_from_private_key() {
        let mut rng = TestRng::default();
        for i in 0..ITERATIONS {
            let sk_raw = PrivateKey::<CurrentNetwork>::new(&mut rng).unwrap();
            let sk = AleoPrivateKey::<CurrentNetwork>::from_str(&sk_raw.to_string()).unwrap();
            let expected_raw = ViewKey::try_from(sk_raw).unwrap();
            let expected = expected_raw.to_string();

            let vk = AleoViewKey::from_private_key(&sk).unwrap();
            assert_eq!(vk.to_string(), expected);

            assert_eq!(vk, AleoViewKey(expected_raw))
        }
    }
}
