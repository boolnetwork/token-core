use snarkvm_console::account::ViewKey;
use snarkvm_console::network::Network;
use std::str::FromStr;

pub struct AleoViewKey<N: Network>(pub String);

impl<N: Network> AleoViewKey<N> {}

impl<N: Network> FromStr for AleoViewKey<N> {
    type Err = failure::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let vk = ViewKey::<N>::from_str(s).map_err(|err| failure::Error::from(err));
        Ok(AleoViewKey(vk.to_string()))
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
