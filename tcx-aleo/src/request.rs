use serde::{Deserialize, Serialize};
use snarkvm_console::network::Network;
use snarkvm_console::program::{Plaintext, Record, Request};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct AleoRequest<N: Network> {
    /// program request
    request: Request<N>,
    /// fee request, record and fee_in_microcredits
    fee: Option<(Request<N>, Record<N, Plaintext<N>>, u64)>,
}
