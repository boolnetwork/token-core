#![allow(deprecated)]
use crate::transaction::{SignedTransaction, Transaction};
use crate::Error;
use cita_crypto::PrivKey;
use libproto::Transaction as ProtoTx;
use prost::Message;
use protobuf::Message as ProtoMessage;
use tcx_chain::{Keystore, Result, TransactionSigner};

impl From<Transaction> for ProtoTx {
    fn from(value: Transaction) -> Self {
        let mut tx = ProtoTx::new();
        tx.set_to(value.to.clone());
        tx.set_nonce(value.nonce.clone());
        tx.set_quota(value.quota);
        tx.set_valid_until_block(value.valid_until_block);
        tx.set_data(value.data.clone());
        tx.set_value(value.value.clone());
        tx.set_chain_id(value.chain_id);
        tx.set_version(value.version);
        tx.set_to_v1(value.to_v1.clone());
        tx.set_chain_id_v1(value.chain_id_v1.clone());
        tx
    }
}

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
        let sk = PrivKey::from_slice(&private_key.to_bytes());
        let proto_tx: ProtoTx = tx.clone().into();
        let signed_tx = proto_tx.sign(sk);
        let mut signed_tx_bytes = vec![];
        signed_tx
            .write_to_vec(&mut signed_tx_bytes)
            .map_err(|_| Error::SerializeError)?;
        SignedTransaction::decode(signed_tx_bytes.as_slice())
            .map_err(|_| Error::DecodeTransactionError.into())
    }
}

#[test]
fn test_cita_encode() {
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
