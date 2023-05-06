use crate::privatekey::AleoPrivateKey;
use crate::Error::InvalidPrivateKey;
use snarkvm_console::account::{ComputeKey, Group, Scalar};
use snarkvm_console::network::Network;
use tcx_constants::Result;

pub struct AleoComputeKey<N: Network>(ComputeKey<N>);

impl<N: Network> AleoComputeKey<N> {
    pub fn from_private_key(private_key: &AleoPrivateKey<N>) -> Result<AleoComputeKey<N>> {
        // Compute pk_sig := G^sk_sig.
        let pk_sig = N::g_scalar_multiply(&private_key.sk_sig());
        // Compute pr_sig := G^r_sig.
        let pr_sig = N::g_scalar_multiply(&private_key.r_sig());
        // Output the compute key.
        let cp = ComputeKey::<N>::try_from((pk_sig, pr_sig)).map_err(|_| InvalidPrivateKey)?;
        Ok(AleoComputeKey(cp))
    }

    /// Returns the signature public key.
    pub const fn pk_sig(&self) -> Group<N> {
        self.0.pk_sig()
    }

    /// Returns the signature public randomizer.
    pub const fn pr_sig(&self) -> Group<N> {
        self.0.pr_sig()
    }

    /// Returns a reference to the PRF secret key.
    pub const fn sk_prf(&self) -> Scalar<N> {
        self.0.sk_prf()
    }
}
