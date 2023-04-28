use crate::address::{DEFAULT_HASH_SIZE, ED25519_FALG, SECP256K1_FALG};
use crate::transaction::{SuiTxInput, SuiTxOuput, SuiUnsignedMessage};
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
                signature.push(ED25519_FALG);
                signature.append(&mut sig);
            }
            TypedPrivateKey::Secp256k1(_) => {
                // must hash data again use sha2-256
                let mut hasher = Sha256::new();
                hasher.update(&result);
                result = hasher.finalize().into();
                let sig = sk.sign_recoverable(&result)?;
                signature.push(SECP256K1_FALG);
                signature.append(&mut sig[..64].to_vec());
            }
            _ => return Err(failure::Error::from(Error::InvalidSuiCurveType)),
        };
        signature.append(&mut sk.public_key().to_bytes());

        Ok(SuiTxOuput {
            tx_data: tx.tx_data.clone(),
            signatures: base64::encode(&signature),
            response_options: tx.response_options.clone(),
            r#type: tx.r#type,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::transaction::{SuiTransactionBlockResponseOptions, SuiTxInput};
    use crate::SuiAddress;
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
        let intent = "AAAA".to_string();
        let tx_data = "AAACACDcuwu46vFiu6uRqbhDa0O608vjolaFH0xH2XMreJluiAAIAIeTAwAAAAACAgABAQEAAQECAAABAACwRH97irYX05VgpnSB8BPYs38y0l5nWwPa5YeIHGeY/wEHm6Y05TyCQsujP5F94Q6hJ5pwpXszRteML2MRXG2gHNQUFQAAAAAAIJXoZBHHdSW8FSdK+4HU4sqJ76kNNuqPjZtr4gzLaUNjsER/e4q2F9OVYKZ0gfAT2LN/MtJeZ1sD2uWHiBxnmP/oAwAAAAAAAICWmAAAAAAAAA==".to_string();
        let tx_input = SuiTxInput {
            intent,
            tx_data,
            response_options: SuiTransactionBlockResponseOptions {
                show_input: false,
                show_raw_input: false,
                show_effects: false,
                show_events: false,
                show_object_changes: false,
                show_balance_changes: false,
            },
            r#type: 0,
        };
        let output = ks
            .sign_transaction("SUI", &account.address, &tx_input)
            .unwrap();
        println!("output: {:?}", output);
        let sig = base64::encode([
            0, 129, 43, 62, 99, 221, 63, 227, 0, 74, 51, 107, 36, 236, 174, 161, 101, 211, 74, 162,
            227, 109, 172, 92, 195, 62, 62, 243, 46, 224, 64, 219, 160, 156, 45, 49, 171, 193, 0,
            150, 109, 39, 241, 170, 226, 45, 34, 108, 245, 152, 178, 45, 28, 141, 156, 151, 56, 42,
            194, 31, 209, 221, 236, 39, 11, 210, 50, 142, 249, 240, 202, 62, 22, 89, 18, 238, 12,
            254, 163, 243, 205, 123, 153, 213, 110, 3, 142, 177, 20, 68, 38, 116, 19, 113, 255, 16,
            226,
        ]);
        assert_eq!(sig, output.signatures)
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
            intent,
            tx_data,
            response_options: SuiTransactionBlockResponseOptions {
                show_input: false,
                show_raw_input: false,
                show_effects: false,
                show_events: false,
                show_object_changes: false,
                show_balance_changes: false,
            },
            r#type: 0,
        };
        let output = ks
            .sign_transaction("SUI", &account.address, &tx_input)
            .unwrap();
        println!("output: {:?}", output);
        assert_eq!(output.signatures, "AU3Leyt5EKAYVGWhHQQD3gnyrvTiunynu0VU/wky7vYvE1LWI8dnvt0IwRu8dh5UKizUejU89JXoCKI/z/2oRNMC9uKMHAGame2Juz0DN+uBgBbDj/ZGQwU/rPs5ColiDHY=");
    }
}
