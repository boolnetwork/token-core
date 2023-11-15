#![allow(deprecated)]
use crate::transaction::{SignedTransaction, Transaction, UnverifiedTransaction};
use crate::Error;
use cita_crypto::{PrivKey, Sign};
use cita_sm2::Signature;
use hashable::Hashable;
use prost::Message;
use tcx_chain::{Keystore, Result, TransactionSigner};

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
        let mut tx_bytes = vec![];
        Message::encode(tx, &mut tx_bytes).map_err(|_| Error::SerializeError)?;
        let hash = tx_bytes.crypt_hash();
        let signature = Signature::sign(&sk, &hash).map_err(|_| Error::SignError)?;
        let unverified_tx = UnverifiedTransaction {
            transaction: Some(tx.clone()),
            signature: signature.to_vec(),
            crypto: 0,
        };
        let mut unverified_tx_bytes = vec![];
        Message::encode(&unverified_tx, &mut unverified_tx_bytes)
            .map_err(|_| Error::SerializeError)?;
        Ok(SignedTransaction {
            transaction_with_sig: Some(unverified_tx),
            tx_hash: unverified_tx_bytes.crypt_hash().to_vec(),
            signer: private_key.public_key().to_bytes(),
        })
    }
}

#[test]
fn test_cita_encode() {
    use protobuf::Message;

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
