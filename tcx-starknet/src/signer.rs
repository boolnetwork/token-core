use crate::{StarknetTxIn, StarknetTxOut, StarknetTxType};
use serde::{Deserialize, Serialize};
use starknet_accounts::{Call, RawExecution};
use starknet_core::types::FieldElement;
use std::str::FromStr;
use tcx_chain::{Keystore, TransactionSigner};
use tcx_primitive::{PrivateKey, TypedPrivateKey};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct ProtoRawTx {
    pub sender: String,
    pub calls: Vec<ProtoCall>,
    pub nonce: u64,
    pub chain_id: String,
    pub max_fee: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProtoCall {
    pub to: String,
    pub selector: String,
    pub call_data: Vec<String>,
}

#[derive(Debug)]
pub struct UnsignedTx {
    pub sender: FieldElement,
    pub chain_id: FieldElement,
    pub raw_tx: RawExecution,
}

impl TryFrom<&ProtoRawTx> for RawExecution {
    type Error = failure::Error;

    fn try_from(raw: &ProtoRawTx) -> Result<RawExecution, Self::Error> {
        let mut calls = Vec::new();
        for call in &raw.calls {
            let to = FieldElement::from_str(&call.to)?;
            let selector = FieldElement::from_str(&call.selector)?;
            let mut call_data = Vec::new();
            for data in &call.call_data {
                call_data.push(FieldElement::from_str(&data)?)
            }
            calls.push(Call {
                to,
                selector,
                calldata: call_data,
            })
        }
        Ok(RawExecution {
            calls,
            nonce: FieldElement::from(raw.nonce),
            max_fee: FieldElement::from_str(&raw.max_fee)?,
        })
    }
}

impl TryFrom<&StarknetTxIn> for UnsignedTx {
    type Error = failure::Error;

    fn try_from(tx_in: &StarknetTxIn) -> Result<UnsignedTx, Self::Error> {
        let unsigned_tx = match tx_in
            .starknet_tx_type
            .as_ref()
            .ok_or(crate::Error::EmptyTxType)?
        {
            StarknetTxType::RawTx(data) => {
                let proto_raw: ProtoRawTx = serde_json::from_str(data)?;
                let raw_tx = RawExecution::try_from(&proto_raw)?;
                UnsignedTx {
                    sender: FieldElement::from_str(&proto_raw.sender)?,
                    chain_id: FieldElement::from_str(&proto_raw.chain_id)?,
                    raw_tx,
                }
            }
            StarknetTxType::Transfer(tx) => {
                let call = Call {
                    to: transfer_eth_token_contract(),
                    selector: transfer_eth_token_selector(),
                    calldata: vec![
                        FieldElement::from_str(&tx.to)?,
                        FieldElement::from_str(&tx.amount)?,
                    ],
                };
                println!("Call: {:?}", call);

                UnsignedTx {
                    sender: FieldElement::from_str(&tx.sender)?,
                    chain_id: FieldElement::from_str(&tx.chain_id)?,
                    raw_tx: RawExecution {
                        calls: vec![call],
                        nonce: FieldElement::from(tx.nonce),
                        max_fee: FieldElement::from_str(&tx.max_fee)?,
                    },
                }
            }
        };
        Ok(unsigned_tx)
    }
}

impl TransactionSigner<StarknetTxIn, StarknetTxOut> for Keystore {
    fn sign_transaction(
        &mut self,
        symbol: &str,
        address: &str,
        tx: &StarknetTxIn,
    ) -> tcx_chain::Result<StarknetTxOut> {
        println!("111111111");

        let sk = self.find_private_key(symbol, address)?;
        let unsigned_tx = UnsignedTx::try_from(tx)?;
        println!("unsigned_tx: {:?}", unsigned_tx);

        let sig = match sk {
            TypedPrivateKey::Starknet(sk) => {
                let msg_to_sign = unsigned_tx
                    .raw_tx
                    .transaction_hash(unsigned_tx.chain_id, unsigned_tx.sender);
                sk.sign(&msg_to_sign.to_bytes_be())?
            }
            _ => return Err(failure::Error::from(crate::Error::InvalidStarknetCurveType)),
        };
        println!("sig: {:?}", sig);
        let call_data = unsigned_tx
            .raw_tx
            .raw_calldata()
            .iter()
            .map(|data| data.inner_to_hex())
            .collect();
        Ok(StarknetTxOut {
            contract_address: unsigned_tx.sender.inner_to_hex(),
            call_data,
            signature: hex::encode(&sig),
            max_fee: unsigned_tx.raw_tx.max_fee.inner_to_hex(),
            nonce: unsigned_tx.raw_tx.nonce.inner_to_hex(),
        })
    }
}

trait ToHex {
    fn inner_to_hex(&self) -> String;
}

impl ToHex for FieldElement {
    fn inner_to_hex(&self) -> String {
        "0x".to_string() + &hex::encode(&self.to_bytes_be())
    }
}

fn transfer_eth_token_contract() -> FieldElement {
    FieldElement::from_str("0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7")
        .unwrap()
}

fn transfer_eth_token_selector() -> FieldElement {
    FieldElement::from_str("0x83afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e")
        .unwrap()
}

#[cfg(test)]
mod tests {
    use crate::address::StarknetAddress;
    use crate::signer::{ProtoCall, ProtoRawTx, ToHex};
    use crate::StarknetTxType::RawTx;
    use crate::{NewTransfer, StarknetTxIn, StarknetTxType};
    use starknet_core::types::FieldElement;
    use std::str::FromStr;
    use tcx_chain::TransactionSigner;
    use tcx_chain::{Keystore, Metadata};
    use tcx_constants::{CoinInfo, CurveType};

    #[test]
    fn test_starknet_sign_transfer() {
        // sk from decimal num
        let sk = FieldElement::from_dec_str(
            "1680276612603002181718147419160781730358142667709908871467878829425628458003",
        )
        .unwrap()
        .to_bytes_be();
        let mut ks =
            Keystore::from_private_key(&hex::encode(sk), "Password", Metadata::default(), "");
        ks.unlock_by_password("Password").unwrap();
        let coin_info = CoinInfo {
            coin: "STARKNET".to_string(),
            derivation_path: "".to_string(),
            curve: CurveType::StarknetCurve,
            network: "MAINNET".to_string(),
            seg_wit: "".to_string(),
        };
        let account = ks
            .derive_coin::<StarknetAddress>(&coin_info)
            .unwrap()
            .clone();
        println!("account: {:?}", account);
        let tx_input = StarknetTxIn {
            starknet_tx_type: Some(StarknetTxType::Transfer(NewTransfer {
                sender: "0x0133f10fa30f0b6a98a82d514db2b970db0b43e2bd120a76a17911d58bcd01ff"
                    .to_string(),
                nonce: 10,
                to: "0x04c15e9de9b0583417ec528435bee789f71137d98a4826abf0f31588d64fe53d"
                    .to_string(),
                amount: FieldElement::from(1000000000000000000u64).inner_to_hex(),
                max_fee: FieldElement::from(0u8).inner_to_hex(),
                chain_id: "0x0000000000000000000000000000000000000000000000534e5f474f45524c49"
                    .to_string(),
            })),
        };
        let output = ks
            .sign_transaction("SUI", &account.address, &tx_input)
            .unwrap();
        println!("output: {:?}", output);
        assert_eq!(output.signature, "02900d61c17093c18f01a874a1acf4ff1b7d648562cd03aa816efd30d8b96fbd07f73855bafd4996445956f58ae09f72fd17b5ea5107d41f8c8613deb93f355f".to_string())
    }

    #[test]
    fn test_starknet_sign_raw() {
        let sk = FieldElement::from_str(
            "0x03b700bb76966cf556bcbd41528da8dcfa7086b2b8db7aca3f5cd26df68aac13",
        )
        .unwrap()
        .to_bytes_be();
        let mut ks =
            Keystore::from_private_key(&hex::encode(sk), "Password", Metadata::default(), "");
        ks.unlock_by_password("Password").unwrap();
        let coin_info = CoinInfo {
            coin: "STARKNET".to_string(),
            derivation_path: "".to_string(),
            curve: CurveType::StarknetCurve,
            network: "MAINNET".to_string(),
            seg_wit: "".to_string(),
        };
        let account = ks
            .derive_coin::<StarknetAddress>(&coin_info)
            .unwrap()
            .clone();
        println!("account: {:?}", account);
        let proto_raw = ProtoRawTx {
            sender: "0x0133f10fa30f0b6a98a82d514db2b970db0b43e2bd120a76a17911d58bcd01ff"
                .to_string(),
            calls: vec![ProtoCall {
                to: "0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7"
                    .to_string(),
                selector: "0x0083afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e"
                    .to_string(),
                call_data: vec![
                    "0x04c15e9de9b0583417ec528435bee789f71137d98a4826abf0f31588d64fe53d"
                        .to_string(),
                    "0x0000000000000000000000000000000000000000000000000de0b6b3a7640000"
                        .to_string(),
                ],
            }],
            nonce: 10,
            chain_id: "0x0000000000000000000000000000000000000000000000534e5f474f45524c49"
                .to_string(),
            max_fee: "0x0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
        };
        let tx_input = StarknetTxIn {
            starknet_tx_type: Some(RawTx(serde_json::to_string(&proto_raw).unwrap())),
        };

        let a = "{\"sender\":\"0x0133f10fa30f0b6a98a82d514db2b970db0b43e2bd120a76a17911d58bcd01ff\",\"calls\":[{\"to\":\"0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7\",\"selector\":\"0x0083afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e\",\"call_data\":[\"0x04c15e9de9b0583417ec528435bee789f71137d98a4826abf0f31588d64fe53d\",\"0x0000000000000000000000000000000000000000000000000de0b6b3a7640000\"]}],\"nonce\":10,\"chain_id\":\"0x0000000000000000000000000000000000000000000000534e5f474f45524c49\",\"max_fee\":\"0x0000000000000000000000000000000000000000000000000000000000000000\"}";
        let b: ProtoRawTx = serde_json::from_str(a).unwrap();
        assert_eq!(b, proto_raw);

        println!(
            "ser string: {:?}",
            serde_json::to_string(&proto_raw).unwrap()
        );
        let output = ks
            .sign_transaction("SUI", &account.address, &tx_input)
            .unwrap();
        println!("output: {:?}", output);
        assert_eq!(output.signature, "02900d61c17093c18f01a874a1acf4ff1b7d648562cd03aa816efd30d8b96fbd07f73855bafd4996445956f58ae09f72fd17b5ea5107d41f8c8613deb93f355f".to_string())
    }
}
