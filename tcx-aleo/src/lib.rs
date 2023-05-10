use failure::Fail;
use snarkvm_console::network::Testnet3;

mod address;
mod privatekey;
mod request;
mod signer;
mod transfer;
mod utils;
mod viewkey;

pub use crate::address::AleoAddress;
pub use crate::privatekey::AleoPrivateKey;
pub use crate::request::AleoRequest;
pub use crate::viewkey::AleoViewKey;
#[macro_use]
extern crate failure;

type CurrentNetwork = Testnet3;

static CURRENT_NETWORK_WORDS: &str = "testnet3";

#[derive(Fail, Debug, PartialEq)]
pub enum Error {
    #[fail(display = "invalid_address")]
    InvalidAddress,

    #[fail(display = "invalid_view_key")]
    InvalidViewKey,

    #[fail(display = "invalid_private_key")]
    InvalidPrivateKey,

    #[fail(display = "custom error: {}", 0)]
    CustomError(String),

    #[fail(display = "invalid_aleo_request: {}", 0)]
    InvalidAleoRequest(String),

    #[fail(display = "fee_record_missed")]
    FeeRecordMissed,
}
