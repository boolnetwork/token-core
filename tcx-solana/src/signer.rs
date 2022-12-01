use crate::construct_transaction::{
    associated_token_account_instruction, message_from_instructions, transfer_instruction,
    transfer_token_instruction, Pubkey, Signature, SolanaTransaction,
};
use crate::transaction::{SolanaTxIn, SolanaTxOut};
use crate::Error;
use bincode::serialize;
use sp_core::bytes::from_hex;
use std::convert::TryFrom;
use tcx_chain::Result;
use tcx_chain::{Keystore, TransactionSigner};

impl TransactionSigner<SolanaTxIn, SolanaTxOut> for Keystore {
    fn sign_transaction(
        &mut self,
        symbol: &str,
        address: &str,
        tx: &SolanaTxIn,
    ) -> Result<SolanaTxOut> {
        let payer_pubkey = Pubkey(<[u8; 32]>::try_from(from_hex(address)?.as_slice())?);
        let to_pubkey = Pubkey(<[u8; 32]>::try_from(tx.to.as_slice())?);
        let instruction = match tx.signal {
            0 => transfer_instruction(&payer_pubkey, &to_pubkey, tx.amount),
            1 => transfer_token_instruction(
                &Pubkey(<[u8; 32]>::try_from(tx.param.as_slice())?),
                &to_pubkey,
                &payer_pubkey,
                tx.amount,
            ),
            2 => associated_token_account_instruction(
                &payer_pubkey,
                &to_pubkey,
                &Pubkey(<[u8; 32]>::try_from(tx.param.as_slice())?),
            ),
            _ => return Err(Error::InvalidSignal.into()),
        };
        let message = message_from_instructions(
            &[instruction],
            &payer_pubkey,
            <[u8; 32]>::try_from(tx.recent_blockhash.as_slice())?,
        );
        let serialized_message = bincode::serialize(&message)?;
        let sk = self.find_private_key(symbol, address)?;
        let sig = sk.sign(&*serialized_message)?;
        let tx = SolanaTransaction {
            signatures: vec![Signature::new(sig.as_slice())],
            message,
        };
        let serialized_tx = bs58::encode(serialize(&tx)?).into_string();
        Ok(SolanaTxOut { tx: serialized_tx })
    }
}
