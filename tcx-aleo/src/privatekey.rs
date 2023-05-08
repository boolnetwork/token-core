use crate::computekey::AleoComputeKey;
use crate::Error;
use crate::Error::CustomError;
use snarkvm_console::account::{ComputeKey, CryptoRng, Field, PrivateKey, Rng, Scalar, Signature};
use snarkvm_console::network::Network;
use std::marker::PhantomData;
use std::str::FromStr;
use tcx_constants::Result;

pub struct AleoPrivateKey<N: Network>(pub PrivateKey<N>);

impl<N: Network> AleoPrivateKey<N> {
    pub fn new<R: Rng + CryptoRng>(rng: &mut R) -> Result<AleoPrivateKey<N>> {
        let key = PrivateKey::<N>::new(rng).map_err(|e| CustomError(e.to_string()))?;
        Ok(Self(key))
    }

    /// Returns the signature secret key.
    pub const fn sk_sig(&self) -> Scalar<N> {
        self.0.sk_sig()
    }

    /// Returns the signature randomizer.
    pub const fn r_sig(&self) -> Scalar<N> {
        self.0.r_sig()
    }
}

impl<N: Network> FromStr for AleoPrivateKey<N> {
    type Err = failure::Error;

    fn from_str(s: &str) -> Result<Self> {
        let key = PrivateKey::<N>::from_str(s).map_err(|_| Error::InvalidPrivateKey)?;
        Ok(AleoPrivateKey(key))
    }
}
