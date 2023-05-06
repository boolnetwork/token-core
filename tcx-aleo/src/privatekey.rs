use crate::computekey::AleoComputeKey;
use crate::Error;
use snarkvm_console::account::{ComputeKey, PrivateKey, Scalar};
use snarkvm_console::network::Network;
use std::marker::PhantomData;
use std::str::FromStr;
use tcx_constants::Result;

pub struct AleoPrivateKey<N: Network>(PrivateKey<N>);

impl<N: Network> AleoPrivateKey<N> {
    /// Returns the signature secret key.
    pub const fn sk_sig(&self) -> Scalar<N> {
        self.0.sk_sig()
    }

    /// Returns the signature randomizer.
    pub const fn r_sig(&self) -> Scalar<N> {
        self.0.r_sig()
    }

    pub fn to_compute_key(&self) -> Result<AleoComputeKey<N>> {
        AleoComputeKey::<N>::from_private_key(self)
    }
}

impl<N: Network> FromStr for AleoPrivateKey<N> {
    type Err = failure::Error;

    fn from_str(s: &str) -> Result<Self> {
        let key = PrivateKey::<N>::from_str(s).map_err(|_| Error::InvalidPrivateKey)?;
        Ok(AleoPrivateKey(key))
    }
}
