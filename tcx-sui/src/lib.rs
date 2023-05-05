mod address;
mod signer;
mod sui_serde;
mod transaction;

pub use crate::{
    address::SuiAddress,
    transaction::{
        NewTransfer, ProstObjectRef, RawTx, SuiTransfer, SuiTxInput, SuiTxOuput, SuiTxType,
        SuiUnsignedMessage, TransferType,
    },
};

#[macro_use]
extern crate failure;
#[derive(Fail, Debug, PartialEq)]
pub enum Error {
    #[fail(display = "sui address parse error")]
    AddressParseError,
    #[fail(display = "sui tx intent base64 parse error")]
    IntentBs64ParseError,
    #[fail(display = "sui tx intent bcs parse error")]
    IntentBcsParseError,
    #[fail(display = "sui tx data base64 parse error")]
    TxDataBase64ParseError,
    #[fail(display = "sui tx data bcs parse error")]
    TxDataBcsParseError,
    #[fail(display = "sui account not found")]
    CannotFoundSuiAccount,
    #[fail(display = "sui curve type is invalid")]
    InvalidSuiCurveType,
    #[fail(display = "bcs serialize failed")]
    BcsSerializeFailed,
    #[fail(display = "invalid object id length")]
    InvalidObjectID,
    #[fail(display = "invalid object digest length")]
    InvalidObjectDigest,
    #[fail(display = "tx must be 'raw' or 'transfer'")]
    EmptyTxType,
    #[fail(display = "transfer type must be 'sui' or 'object'")]
    EmptyTransferType,
}
