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
    use snarkvm_console::account::TestRng;

    use crate::address::AleoAddress;
    use crate::privatekey::AleoPrivateKey;
    use crate::viewkey::AleoViewKey;
    use crate::CurrentNetwork;
    use tcx_constants::Result;

    #[allow(clippy::type_complexity)]
    pub(crate) fn generate_account() -> Result<(
        AleoPrivateKey<CurrentNetwork>,
        AleoViewKey<CurrentNetwork>,
        AleoAddress<CurrentNetwork>,
    )> {
        // Sample a random private key.
        let private_key = AleoPrivateKey::<CurrentNetwork>::new(&mut TestRng::default())?;

        // Derive the compute key, view key, and address.
        let view_key = AleoViewKey::<CurrentNetwork>::from_private_key(&private_key)?;
        let address = AleoAddress::<CurrentNetwork>::from_private_key(&private_key)?;

        // Return the private key and compute key components.
        Ok((private_key, view_key, address))
    }
}
