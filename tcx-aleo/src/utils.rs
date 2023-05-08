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
