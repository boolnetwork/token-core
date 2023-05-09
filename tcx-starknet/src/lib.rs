mod address;
mod signer;
mod transaction;

pub use address::StarknetAddress;
pub use transaction::{starknet_tx_in::StarknetTxType, NewTransfer, StarknetTxIn, StarknetTxOut};

#[macro_use]
extern crate failure;
#[derive(Fail, Debug, PartialEq)]
pub enum Error {
    #[fail(display = "sui address parse error")]
    AddressParseError,
    #[fail(display = "tx must be 'raw' or 'transfer'")]
    EmptyTxType,
    #[fail(display = "starknet curve type is invalid")]
    InvalidStarknetCurveType,
}
