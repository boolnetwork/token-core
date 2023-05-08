use crate::privatekey::AleoPrivateKey;
use crate::Error::CustomError;
use snarkvm_console::account::{CryptoRng, Field, Rng, Signature};
use snarkvm_console::network::Network;
use tcx_constants::Result;

impl<N: Network> AleoPrivateKey<N> {
    /// Returns a signature for the given message (as field elements) using the private key.
    pub fn sign<R: Rng + CryptoRng>(
        &self,
        message: &[Field<N>],
        rng: &mut R,
    ) -> Result<Signature<N>> {
        Signature::sign(&self.0, message, rng)
            .map_err(|e| failure::Error::from(CustomError(e.to_string())))
    }

    /// Returns a signature for the given message (as bytes) using the private key.
    pub fn sign_bytes<R: Rng + CryptoRng>(
        &self,
        message: &[u8],
        rng: &mut R,
    ) -> Result<Signature<N>> {
        Signature::sign_bytes(&self.0, message, rng)
            .map_err(|e| failure::Error::from(CustomError(e.to_string())))
    }

    /// Returns a signature for the given message (as bits) using the private key.
    pub fn sign_bits<R: Rng + CryptoRng>(
        &self,
        message: &[bool],
        rng: &mut R,
    ) -> Result<Signature<N>> {
        Signature::sign_bits(&self.0, message, rng)
            .map_err(|e| failure::Error::from(CustomError(e.to_string())))
    }
}
