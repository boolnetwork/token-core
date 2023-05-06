use crate::privatekey::AleoPrivateKey;
use crate::Error;
use snarkvm_console::account::{ComputeKey, ViewKey};
use snarkvm_console::network::Network;
use std::marker::PhantomData;
use std::str::FromStr;

pub struct AleoViewKey<N: Network>(ViewKey<N>);

impl<N: Network> AleoViewKey<N> {
    fn from_private_key(private_key: AleoPrivateKey<N>) -> AleoViewKey<N> {
        // Derive the compute key.
        let compute_key = ComputeKey::<N>::try_from(private_key)?;
    }
}

impl<N: Network> FromStr for AleoViewKey<N> {
    type Err = failure::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let vk = ViewKey::<N>::from_str(s).map_err(|_| Error::InvalidViewKey)?;
        Ok(AleoViewKey(vk))
    }
}

impl<N: Network> ToString for AleoViewKey<N> {
    fn to_string(&self) -> String {
        self.0.to_string()
    }
}

#[cfg(test)]
mod tests {
    use crate::viewkey::AleoViewKey;
    use crate::CurrentNetwork;
    use std::str::FromStr;

    #[test]
    fn test_from_str() {
        let v_s = "AViewKey1tya3YUZSMd2LotPBYd9CPyrpQoaSz3BDKiVp8UwjHqPf";
        let v_s_inc = "asdaweatya3YUZSMd2LotPBYd9CPyrpQoaSz3BDKiVp8UwjHqPf";
        assert!(AleoViewKey::<CurrentNetwork>::from_str(v_s).is_ok());
        assert!(AleoViewKey::<CurrentNetwork>::from_str(v_s_inc).is_err());
    }
}
