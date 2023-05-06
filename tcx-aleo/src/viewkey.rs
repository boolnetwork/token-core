use crate::privatekey::AleoPrivateKey;
use crate::Error;
use snarkvm_console::account::{ComputeKey, ViewKey};
use snarkvm_console::network::Network;
use std::fmt::{Display, Formatter};
use std::marker::PhantomData;
use std::str::FromStr;
use tcx_constants::Result;

#[derive(Debug, PartialEq)]
pub struct AleoViewKey<N: Network>(ViewKey<N>);

impl<N: Network> AleoViewKey<N> {
    fn from_private_key(private_key: AleoPrivateKey<N>) -> Result<AleoViewKey<N>> {
        // Derive the compute key.
        let compute_key = private_key.to_compute_key()?;
        Ok(AleoViewKey(ViewKey::<N>::from_scalar(
            private_key.sk_sig() + private_key.r_sig() + compute_key.sk_prf(),
        )))
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
        self.0.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use crate::privatekey::AleoPrivateKey;
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

    #[test]
    fn test_from_private_key() {
        let expected = "AViewKey1tya3YUZSMd2LotPBYd9CPyrpQoaSz3BDKiVp8UwjHqPf";
        let sk = "APrivateKey1zkp3Z5SRjW9BomVUqP1Gd9P4vYi6coW1MPfe3HZc7MmMMSk";
        let a_sk = AleoPrivateKey::<CurrentNetwork>::from_str(sk).unwrap();
        let a_vk_1 = AleoViewKey::<CurrentNetwork>::from_private_key(a_sk).unwrap();
        println!("{}", a_vk_1);
        assert_eq!(a_vk_1.to_string(), expected);
        let a_vk_2 = AleoViewKey::<CurrentNetwork>::from_str(expected).unwrap();
        assert_eq!(a_vk_1, a_vk_2);
    }
}
