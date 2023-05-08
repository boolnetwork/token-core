use crate::address::AleoAddress;
use crate::privatekey::AleoPrivateKey;
use crate::Error::{CustomError, InvalidComputeKey, InvalidPrivateKey};
use snarkvm_console::account::{Address, ComputeKey, Group, Scalar};
use snarkvm_console::network::Network;
use tcx_constants::Result;

#[derive(Debug, PartialEq)]
pub struct AleoComputeKey<N: Network>(pub ComputeKey<N>);

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

    pub fn to_address(&self) -> AleoAddress<N> {
        // Compute pk_prf := G^sk_prf.
        let pk_prf = N::g_scalar_multiply(&self.sk_prf());
        // Compute the address := pk_sig + pr_sig + pk_prf.
        AleoAddress::new(Address::new(self.pk_sig() + self.pr_sig() + pk_prf))
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

impl<N: Network> TryFrom<(Group<N>, Group<N>)> for AleoComputeKey<N> {
    type Error = failure::Error;

    /// Derives the account compute key from a tuple `(pk_sig, pr_sig)`.
    fn try_from((pk_sig, pr_sig): (Group<N>, Group<N>)) -> Result<Self> {
        let key =
            ComputeKey::<N>::try_from((pk_sig, pr_sig)).map_err(|e| CustomError(e.to_string()))?;
        Ok(Self(key))
    }
}

#[cfg(test)]
mod tests {
    use crate::computekey::AleoComputeKey;
    use crate::privatekey::AleoPrivateKey;
    use crate::CurrentNetwork;
    use crate::Error::CustomError;
    use snarkvm_console::account::{ComputeKey, PrivateKey, TestRng};
    use snarkvm_console::network::Network;
    use tcx_constants::Result;

    const ITERATIONS: u64 = 1000;

    #[test]
    fn test_from_private_key() -> Result<()> {
        let mut rng = TestRng::default();
        for _ in 0..ITERATIONS {
            let private_key = AleoPrivateKey::<CurrentNetwork>::new(&mut rng)?;
            let candidate = AleoComputeKey::<CurrentNetwork>::from_private_key(&private_key)?;
            // Check that sk_prf matches.
            // Compute sk_prf := HashToScalar(pk_sig || pr_sig).
            let candidate_sk_prf = CurrentNetwork::hash_to_scalar_psd4(&[
                candidate.pk_sig().to_x_coordinate(),
                candidate.pr_sig().to_x_coordinate(),
            ])
            .map_err(|e| CustomError(e.to_string()))?;
            assert_eq!(candidate.sk_prf(), candidate_sk_prf);

            // Check that compute key is derived correctly from the tuple `(pk_sig, pr_sig)`.
            assert_eq!(
                candidate,
                AleoComputeKey::try_from((candidate.pk_sig(), candidate.pr_sig()))
                    .map_err(|e| CustomError(e.to_string()))?
            );
        }
        Ok(())
    }
}
