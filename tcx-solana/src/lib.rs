mod address;
mod construct_transaction;
mod signer;
mod transaction;

pub use crate::address::SolanaAddress;
pub use crate::transaction::{SolanaTxIn, SolanaTxOut};
#[macro_use]
extern crate failure;
#[derive(Fail, Debug, PartialEq)]
pub enum Error {
    #[fail(display = "invalid signal")]
    InvalidSignal,
}
