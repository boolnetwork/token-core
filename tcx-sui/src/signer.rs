use crate::address::{DEFAULT_HASH_SIZE, ED25519_FLAG, SECP256K1_FLAG};
use crate::primitives::SuiUnsignedMessage;
use crate::transaction::{sui_tx_input::SuiTxType, SuiTxInput, SuiTxOuput};
use crate::Error;
use sha2::{Digest, Sha256};
use tcx_chain::{Keystore, TransactionSigner};
use tcx_primitive::TypedPrivateKey;

impl TransactionSigner<SuiTxInput, SuiTxOuput> for Keystore {
    fn sign_transaction(
        &mut self,
        symbol: &str,
        address: &str,
        tx: &SuiTxInput,
    ) -> tcx_chain::Result<SuiTxOuput> {
        let unsigned_tx = SuiUnsignedMessage::try_from(tx)?;
        let msg_to_sign = bcs::to_bytes(&unsigned_tx)
            .map_err(|_| failure::Error::from(Error::BcsSerializeFailed))?;
        // hash data use blake2b-256
        let mut result = [0u8; 32];
        let mut hasher = blake2b_rs::Blake2bBuilder::new(DEFAULT_HASH_SIZE).build();
        hasher.update(&msg_to_sign);
        hasher.finalize(&mut result);
        let sk = self.find_private_key(symbol, address)?;

        // full signature contains (flag, sig, pk)
        let mut signature = Vec::new();
        match sk {
            TypedPrivateKey::Ed25519(_) => {
                let mut sig = sk.sign_recoverable(&result)?;
                signature.push(ED25519_FLAG);
                signature.append(&mut sig);
            }
            TypedPrivateKey::Secp256k1(_) => {
                // must hash data again use sha2-256
                let mut hasher = Sha256::new();
                hasher.update(result);
                result = hasher.finalize().into();
                let sig = sk.sign_recoverable(&result)?;
                signature.push(SECP256K1_FLAG);
                signature.append(&mut sig[..64].to_vec());
            }
            _ => return Err(failure::Error::from(Error::InvalidSuiCurveType)),
        };
        signature.append(&mut sk.public_key().to_bytes());
        let tx_data = match &tx.sui_tx_type.as_ref().ok_or(crate::Error::EmptyTxType)? {
            SuiTxType::RawTx(tx) => tx.tx_data.clone(),
            SuiTxType::Transfer(_) => base64::encode(
                &bcs::to_bytes(&unsigned_tx.value).map_err(|_| Error::BcsSerializeFailed)?,
            ),
        };
        Ok(SuiTxOuput {
            tx_data,
            signature: base64::encode(&signature),
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::transaction::{RawTx, SuiTxInput};
    use crate::{SuiAddress, SuiTxType};
    use tcx_chain::{Keystore, Metadata, TransactionSigner};
    use tcx_constants::{CoinInfo, CurveType};

    #[test]
    fn test_sui_sign_ed25519() {
        let mut ks = Keystore::from_private_key(
            "5bf718a81770f55ad59766eb5ebf792df379b1da81b40a47530ce32ea059f2cc",
            "Password",
            Metadata::default(),
            "",
        );
        ks.unlock_by_password("Password").unwrap();
        let coin_info = CoinInfo {
            coin: "SUI".to_string(),
            derivation_path: "".to_string(),
            curve: CurveType::ED25519,
            network: "MAINNET".to_string(),
            seg_wit: "".to_string(),
        };
        let account = ks.derive_coin::<SuiAddress>(&coin_info).unwrap().clone();
        println!("account: {:?}", account);
        let tx_input = SuiTxInput {
            sui_tx_type: Some(SuiTxType::RawTx(
                RawTx {
                    intent: "AAAA".to_string(),
                    tx_data: "AAACACDcuwu46vFiu6uRqbhDa0O608vjolaFH0xH2XMreJluiAAIAIeTAwAAAAACAgABAQEAAQECAAABAACwRH97irYX05VgpnSB8BPYs38y0l5nWwPa5YeIHGeY/wEHm6Y05TyCQsujP5F94Q6hJ5pwpXszRteML2MRXG2gHE5NKAAAAAAAIPBhCNlgeWQXkO2bJZJLJYPgkB4q8//5R9UHFiLTiPmmsER/e4q2F9OVYKZ0gfAT2LN/MtJeZ1sD2uWHiBxnmP/nAwAAAAAAAICWmAAAAAAAAA==".to_string(),
                }
            ))
        };
        let output = ks
            .sign_transaction("SUI", &account.address, &tx_input)
            .unwrap();
        println!("output: {:?}", output);
        let sig = "ALrW17ATAG4uGcER3rJuxaJ5hClV+nyFIFydSty1jU/V3A/xclIkA/UM7s7j776MFcZbC/Tcaxbdx0DDApfjwgnSMo758Mo+FlkS7gz+o/PNe5nVbgOOsRREJnQTcf8Q4g==".to_string();
        assert_eq!(sig, output.signature)
    }

    #[test]
    fn test_sui_sign_spec256k1() {
        let mut ks = Keystore::from_private_key(
            "d22d0f6cf72a51d304a1ada52b04eaa03cf8130a3a3a6a153495219b502dc119",
            "Password",
            Metadata::default(),
            "",
        );
        ks.unlock_by_password("Password").unwrap();
        let coin_info = CoinInfo {
            coin: "SUI".to_string(),
            derivation_path: "".to_string(),
            curve: CurveType::SECP256k1,
            network: "MAINNET".to_string(),
            seg_wit: "".to_string(),
        };
        let account = ks.derive_coin::<SuiAddress>(&coin_info).unwrap().clone();
        println!("account: {:?}", account);
        let intent = "AAAA".to_string();
        let tx_data = "AAACACDcuwu46vFiu6uRqbhDa0O608vjolaFH0xH2XMreJluiAAIAIeTAwAAAAACAgABAQEAAQECAAABAABpPUv4DWejudfZjyhwRb30r93w6ejRwWWhqlxG9w7TxAHcuogjoTmy/mKCvhYfF5V/vKfRTW4Ko0fFgZgvRUFekU5NKAAAAAAAIHf09gz7lrd9KKelJ79D2KPkvMJ3jF8WLWvMTCuXdD0EaT1L+A1no7nX2Y8ocEW99K/d8Ono0cFloapcRvcO08ToAwAAAAAAAICWmAAAAAAAAA==".to_string();
        let tx_input = SuiTxInput {
            sui_tx_type: Some(SuiTxType::RawTx(RawTx { intent, tx_data })),
        };
        let output = ks
            .sign_transaction("SUI", &account.address, &tx_input)
            .unwrap();
        println!("output: {:?}", output);
        assert_eq!(output.signature, "AU3Leyt5EKAYVGWhHQQD3gnyrvTiunynu0VU/wky7vYvE1LWI8dnvt0IwRu8dh5UKizUejU89JXoCKI/z/2oRNMC9uKMHAGame2Juz0DN+uBgBbDj/ZGQwU/rPs5ColiDHY=");
    }
}
