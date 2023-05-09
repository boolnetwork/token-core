use crate::Error::InvalidAleoRequest;
use reqwest::Response;
use tcx_constants::Result;

pub(crate) async fn query_get(query_url: String) -> Result<Response> {
    let client = reqwest::Client::new();
    client
        .get(query_url)
        .send()
        .await
        .map_err(|e| failure::Error::from(InvalidAleoRequest(e.to_string())))
}

#[cfg(test)]
pub(crate) mod helpers {
    use snarkvm_console::account::{PrivateKey, TestRng};

    use crate::address::AleoAddress;
    use crate::privatekey::AleoPrivateKey;
    use crate::viewkey::AleoViewKey;
    use crate::CurrentNetwork;
    use crate::Error::CustomError;
    use tcx_constants::Result;

    #[allow(clippy::type_complexity)]
    pub(crate) fn generate_account() -> Result<(AleoPrivateKey, AleoViewKey, AleoAddress)> {
        // Sample a random private key.
        let sk = PrivateKey::<CurrentNetwork>::new(&mut TestRng::default())
            .map_err(|e| CustomError(e.to_string()))?;
        let private_key = AleoPrivateKey::new(sk.to_string())?;

        // Derive the compute key, view key, and address.
        let view_key = AleoViewKey::from_private_key(&private_key)?;
        let address = AleoAddress::from_private_key(&private_key)?;

        // Return the private key and compute key components.
        Ok((private_key, view_key, address))
    }
}
