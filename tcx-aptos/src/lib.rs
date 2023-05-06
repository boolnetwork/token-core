mod address;
mod signer;
mod transaction;
mod vec_bytes;

pub use crate::address::AptosAddress;
pub use crate::transaction::{aptos_tx_in::AptosTxType, AptosTxIn, AptosTxOut, NewTransfer};
#[macro_use]
extern crate failure;
#[derive(Fail, Debug, PartialEq)]
pub enum Error {
    #[fail(display = "account address parse error")]
    AccountAddressParseError,
    #[fail(display = "empty aptos tx")]
    EmptyAptosTx,
    #[fail(display = "hex decode failed")]
    HexDecodeFailed,
    #[fail(display = "bcs decode failed")]
    BcsDecodeFailed,
    #[fail(display = "bcs encode failed")]
    BcsEncodeFailed,
}
