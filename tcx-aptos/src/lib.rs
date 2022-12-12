mod address;
mod signer;
mod transaction;
mod vec_bytes;

pub use crate::address::AptosAddress;
pub use crate::transaction::{AptosTxIn, AptosTxOut};
#[macro_use]
extern crate failure;
#[derive(Fail, Debug, PartialEq)]
pub enum Error {
    #[fail(display = "account address parse error")]
    AccountAddressParseError,
}
