use failure::Fail;
use snarkvm_console::network::Testnet3;

mod address;
mod privatekey;
mod request;
mod signer;
mod utils;
mod viewkey;

type CurrentNetwork = Testnet3;

extern crate failure;

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
}
