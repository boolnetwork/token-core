use crate::Error::InvalidAddress;
use snarkvm_console::account::Address;
use snarkvm_console::network::Network;
use std::fmt::{Debug, Display, Formatter};
use std::str::FromStr;
use tcx_constants::Result;

#[derive(Debug, PartialEq)]
pub struct AleoAddress<N: Network>(pub Address<N>);

impl<N: Network> AleoAddress<N> {
    pub const fn new(address: Address<N>) -> Self {
        Self(address)
    }
}

impl<N: Network> Display for AleoAddress<N> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.0, f)
    }
}

impl<N: Network> FromStr for AleoAddress<N> {
    type Err = failure::Error;

    fn from_str(s: &str) -> Result<Self> {
        let addr = Address::<N>::from_str(s).map_err(|_| InvalidAddress)?;
        Ok(AleoAddress(addr))
    }
}

#[cfg(test)]
mod tests {
    use crate::address::AleoAddress;
    use crate::privatekey::AleoPrivateKey;
    use crate::viewkey::AleoViewKey;
    use crate::CurrentNetwork;
    use snarkvm_console::account::{Address, PrivateKey, TestRng, ViewKey};
    use std::str::FromStr;

    const ITERATIONS: u64 = 1000;

    #[test]
    fn test_from_str() {
        let mut rng = TestRng::default();
        for _ in 0..ITERATIONS {
            let private_key = AleoPrivateKey::<CurrentNetwork>::new(&mut rng).unwrap();
            let view_key = AleoViewKey::<CurrentNetwork>::from_private_key(&private_key).unwrap();
            let expected = view_key.to_address();
            assert_eq!(
                expected,
                AleoAddress::<CurrentNetwork>::from_str(&expected.to_string()).unwrap()
            )
        }
    }
}
