#![allow(deprecated)]
use crate::transaction::{Crypto, SignedTransaction, Transaction, UnverifiedTransaction};
use crate::Error;
use prost::Message;
use sha3::Digest;
use tcx_chain::{Keystore, Result, TransactionSigner};
use tcx_primitive::PrivateKey;

impl TransactionSigner<Transaction, SignedTransaction> for Keystore {
    fn sign_transaction(
        &mut self,
        symbol: &str,
        address: &str,
        tx: &Transaction,
    ) -> Result<SignedTransaction> {
        let account = self.account(symbol, address);
        if account.is_none() {
            return Err(Error::CannotFoundAccount.into());
        }
        let private_key = self
            .find_private_key(&symbol, &address)
            .map_err(|_| Error::CannotGetPrivateKey)?;
        let private_key = private_key
            .as_secp256k1()
            .map_err(|_| Error::CannotGetPrivateKey)?;

        let mut tx_bytes = vec![];
        Message::encode(tx, &mut tx_bytes).map_err(|_| Error::SerializeError)?;
        let hash = sha3::Keccak256::digest(&tx_bytes).to_vec();
        let signature = private_key
            .sign_recoverable(&hash)
            .map_err(|_| Error::SignError)?;

        let unverified_tx = UnverifiedTransaction {
            transaction: Some(tx.clone()),
            signature,
            crypto: Crypto::Default as i32,
        };
        let mut unverified_tx_bytes: Vec<u8> = vec![];
        Message::encode(&unverified_tx, &mut unverified_tx_bytes).unwrap();

        let signed_tx = SignedTransaction {
            transaction_with_sig: Some(unverified_tx),
            tx_hash: sha3::Keccak256::digest(&unverified_tx_bytes).to_vec(),
            signer: private_key.public_key().to_uncompressed()[1..].to_vec(),
        };

        Ok(signed_tx)
    }
}

#[test]
fn test_cita_encode() {
    use protobuf::Message as ProtoMessage;

    let transaction = Transaction {
        nonce: "0".to_string(),
        quota: 0,
        to: "132D1eA7EF895b6834D25911656a434d7167091C".to_string(),
        value: 0u32.to_be_bytes().to_vec(),
        chain_id: 1,
        version: 0,
        to_v1: vec![],
        data: "7f7465737432000000000000000000000000000000000000000000000000000000600057"
            .as_bytes()
            .to_vec(),
        valid_until_block: 1000,
        chain_id_v1: vec![],
    };
    let mut bytes1 = vec![];
    Message::encode(&transaction, &mut bytes1).unwrap();

    let transaction1 = libproto::Transaction {
        nonce: "0".to_string(),
        quota: 0,
        to: "132D1eA7EF895b6834D25911656a434d7167091C".to_string(),
        value: 0u32.to_be_bytes().to_vec(),
        chain_id: 1,
        version: 0,
        to_v1: vec![],
        data: "7f7465737432000000000000000000000000000000000000000000000000000000600057"
            .as_bytes()
            .to_vec(),
        valid_until_block: 1000,
        chain_id_v1: vec![],
        unknown_fields: Default::default(),
        cached_size: Default::default(),
    };
    let mut bytes2 = vec![];
    transaction1.write_to_vec(&mut bytes2).unwrap();
    assert_eq!(bytes1, bytes2);
}
