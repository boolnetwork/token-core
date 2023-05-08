use crate::Error;
use crate::Error::CustomError;
use snarkvm_console::account::{CryptoRng, PrivateKey, Rng};
use snarkvm_console::network::Network;
use std::fmt::{Display, Formatter};
use std::str::FromStr;
use tcx_constants::Result;

pub struct AleoPrivateKey<N: Network>(pub PrivateKey<N>);

impl<N: Network> AleoPrivateKey<N> {
    pub fn new<R: Rng + CryptoRng>(rng: &mut R) -> Result<AleoPrivateKey<N>> {
        let key = PrivateKey::<N>::new(rng).map_err(|e| CustomError(e.to_string()))?;
        Ok(Self(key))
    }
}

impl<N: Network> Display for AleoPrivateKey<N> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.0, f)
    }
}

impl<N: Network> FromStr for AleoPrivateKey<N> {
    type Err = failure::Error;

    fn from_str(s: &str) -> Result<Self> {
        let key = PrivateKey::<N>::from_str(s).map_err(|_| Error::InvalidPrivateKey)?;
        Ok(AleoPrivateKey(key))
    }
}

#[cfg(test)]
mod tests {
    use crate::privatekey::AleoPrivateKey;
    use crate::viewkey::AleoViewKey;
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
            let ask = AleoPrivateKey::<CurrentNetwork>::from_str(&s).unwrap();
            assert_eq!(s, ask.to_string())
        }
    }
}
