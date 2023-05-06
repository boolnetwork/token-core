use crate::privatekey::AleoPrivateKey;
use crate::Error::InvalidPrivateKey;
use snarkvm_console::account::ComputeKey;
use snarkvm_console::network::Network;
use tcx_constants::Result;

pub struct AleoComputeKey<N: Network>(ComputeKey<N>);

impl<N: Network> AleoComputeKey<N> {
    fn from_private_key(private_key: AleoPrivateKey<N>) -> Result<AleoComputeKey<N>> {
        // Compute pk_sig := G^sk_sig.
        let pk_sig = N::g_scalar_multiply(&private_key.sk_sig());
        // Compute pr_sig := G^r_sig.
        let pr_sig = N::g_scalar_multiply(&private_key.r_sig());
        // Output the compute key.
        let cp = ComputeKey::<N>::try_from((pk_sig, pr_sig)).map_err(|_| InvalidPrivateKey)?;
        Ok(AleoComputeKey(cp))
    }
}
