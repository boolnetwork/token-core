use crate::viewkey::AleoViewKey;
use crate::Error;
use crate::Error::InvalidAddress;
use snarkvm_console::account::{Address, Group, ViewKey};
use snarkvm_console::network::Network;
use std::fmt::{Debug, Display, Formatter};
use std::marker::PhantomData;
use std::str::FromStr;
use tcx_constants::Result;

#[derive(Debug, PartialEq)]
pub struct AleoAddress<N: Network>(Address<N>);

impl<N: Network> AleoAddress<N> {
    pub const fn new(address: Address<N>) -> Self {
        Self(address)
    }

    fn from_view_key(view_key: &AleoViewKey<N>) -> AleoAddress<N> {
        view_key.to_address()
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
    use crate::viewkey::AleoViewKey;
    use crate::CurrentNetwork;
    use std::str::FromStr;

    #[test]
    fn test_from_str() {
        let expected = "aleo1nrnwjp5u4lmkf98lymj6rh6u8aa3pnpjg422qhehtvnxre2fvvpq9pxyl2";
        let address = AleoAddress::<CurrentNetwork>::from_str(expected).unwrap();
        assert_eq!(address.to_string(), expected)
    }

    #[test]
    fn test_from_view_key() {
        let v_s = "AViewKey1tya3YUZSMd2LotPBYd9CPyrpQoaSz3BDKiVp8UwjHqPf";
        let expected = "aleo1nrnwjp5u4lmkf98lymj6rh6u8aa3pnpjg422qhehtvnxre2fvvpq9pxyl2";

        let vk = AleoViewKey::<CurrentNetwork>::from_str(v_s).unwrap();
        let address_1 = AleoAddress::<CurrentNetwork>::from_view_key(&vk);
        assert_eq!(address_1.to_string(), expected);
        let address_2 = AleoAddress::<CurrentNetwork>::from_str(expected).unwrap();
        assert_eq!(address_1, address_2)
    }
}
