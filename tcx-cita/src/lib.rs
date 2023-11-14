pub mod address;
pub mod signer;
pub mod transaction;

pub use address::CitaAddress;
pub use transaction::*;

use failure::Fail;

#[derive(Fail, Debug, PartialEq)]
pub enum Error {
    #[fail(display = "cannot_found_account")]
    CannotFoundAccount,

    #[fail(display = "cannot_get_private_key")]
    CannotGetPrivateKey,

    #[fail(display = "invalid_public_key")]
    InvalidPubkey,

    #[fail(display = "invalid_to")]
    InvalidTo,

    #[fail(display = "invalid_nonce")]
    InvalidNonce,

    #[fail(display = "invalid_quota")]
    InvalidQuota,

    #[fail(display = "invalid_valid_until_block")]
    InvalidValidUntilBlock,

    #[fail(display = "invalid_data")]
    InvalidData,

    #[fail(display = "invalid_value")]
    InvalidValue,

    #[fail(display = "invalid_chain_id")]
    InvalidChainId,

    #[fail(display = "invalid_version")]
    InvalidVersion,

    #[fail(display = "invalid_to_v1")]
    InvalidToV1,

    #[fail(display = "invalid_chain_id_v1")]
    InvalidChainIdV1,

    #[fail(display = "decode_transaction_error")]
    DecodeTransactionError,

    #[fail(display = "proto_buff_error")]
    ProtoBuffError,

    #[fail(display = "serialize_error")]
    SerializeError,

    #[fail(display = "sign_error")]
    SignError,
}
