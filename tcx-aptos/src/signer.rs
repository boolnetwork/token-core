#![allow(dead_code)]
use crate::transaction::aptos_tx_in::AptosTxType;
use crate::Error;
use crate::{vec_bytes, AptosTxIn, AptosTxOut};
use hex::FromHex;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use tcx_chain::{Keystore, Result, TransactionSigner};

const TRANSACTION_PREFIX: &str = "APTOS::RawTransaction";

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct SignedTransaction {
    pub raw_tx: RawTransaction,
    pub authenticator: TransactionAuthenticator,
}
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct RawTransaction {
    sender: AccountAddress,
    sequence_number: u64,
    payload: TransactionPayload,
    max_gas_amount: u64,
    gas_unit_price: u64,
    expiration_timestamp_secs: u64,
    chain_id: u8,
}

impl TryFrom<&AptosTxIn> for RawTransaction {
    type Error = crate::Error;

    fn try_from(input: &AptosTxIn) -> core::result::Result<RawTransaction, self::Error> {
        let unsigned_tx = match input.aptos_tx_type.as_ref().ok_or(Error::EmptyAptosTx)? {
            AptosTxType::RawTx(data) => {
                let data = data.strip_prefix("0x").unwrap_or(&data);
                let tx: RawTransaction =
                    bcs::from_bytes(&hex::decode(data).map_err(|_| Error::HexDecodeFailed.into())?)
                        .map_err(|_| Error::BcsDecodeFailed.into())?;
                tx
            }
            AptosTxType::Transfer(transfer) => {
                let entry_fun =
                    EntryFunction::transfer_aptos_coin(transfer.to.clone(), transfer.amount)?;
                RawTransaction {
                    sender: AccountAddress::from_hex_literal(&transfer.sender)?,
                    sequence_number: transfer.sequence_number,
                    payload: TransactionPayload::EntryFunction(entry_fun),
                    max_gas_amount: transfer.max_gas_amount,
                    gas_unit_price: transfer.gas_unit_price,
                    expiration_timestamp_secs: transfer.expiration_timestamp_secs,
                    chain_id: transfer.chain_id as u8,
                }
            }
        };
        Ok(unsigned_tx)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountAddress([u8; 32]);
impl AccountAddress {
    pub const fn new(address: [u8; 32]) -> Self {
        Self(address)
    }
    pub fn from_hex_literal(literal: &str) -> core::result::Result<Self, crate::Error> {
        if !literal.starts_with("0x") {
            return Err(Error::AccountAddressParseError.into());
        }

        let hex_len = literal.len() - 2;

        // If the string is too short, pad it
        if hex_len < 64 {
            let mut hex_str = String::with_capacity(64);
            for _ in 0..64 - hex_len {
                hex_str.push('0');
            }
            hex_str.push_str(&literal[2..]);
            AccountAddress::from_hex(hex_str)
        } else {
            AccountAddress::from_hex(&literal[2..])
        }
    }
    pub fn from_hex<T: AsRef<[u8]>>(hex: T) -> core::result::Result<Self, crate::Error> {
        <[u8; 32]>::from_hex(hex)
            .map_err(|_| Error::AccountAddressParseError.into())
            .map(Self)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TransactionPayload {
    Script(),
    ModuleBundle(),
    EntryFunction(EntryFunction),
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EntryFunction {
    module: ModuleId,
    function: String,
    ty_args: Vec<TypeTag>,
    #[serde(with = "vec_bytes")]
    args: Vec<Vec<u8>>,
}
impl EntryFunction {
    pub fn new(
        module: ModuleId,
        function: String,
        ty_args: Vec<TypeTag>,
        args: Vec<Vec<u8>>,
    ) -> Self {
        EntryFunction {
            module,
            function,
            ty_args,
            args,
        }
    }

    fn transfer_aptos_coin(to: String, amount: u64) -> core::result::Result<Self, self::Error> {
        let module = ModuleId::new(AccountAddress::from_hex_literal("0x1")?, "coin".to_string());
        let coin = StructTag {
            address: AccountAddress::from_hex_literal("0x1")?,
            module: "aptos_coin".to_string(),
            name: "AptosCoin".to_string(),
            type_params: vec![],
        };
        let receiver = AccountAddress::from_hex_literal(&to)?;
        let entry_fun = Self {
            module,
            function: "transfer".to_string(),
            ty_args: vec![TypeTag::Struct(coin)],
            args: vec![
                bcs::to_bytes(&receiver).map_err(|_| Error::BcsEncodeFailed)?,
                bcs::to_bytes(&amount).map_err(|_| Error::BcsEncodeFailed)?,
            ],
        };
        Ok(entry_fun)
    }
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ModuleId {
    address: AccountAddress,
    name: String,
}
impl ModuleId {
    pub fn new(address: AccountAddress, name: String) -> Self {
        ModuleId { address, name }
    }
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum TypeTag {
    Bool,
    U8,
    U64,
    U128,
    Address,
    Signer,
    Vector(Box<TypeTag>),
    Struct(StructTag),
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StructTag {
    pub address: AccountAddress,
    pub module: String,
    pub name: String,
    pub type_params: Vec<TypeTag>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum TransactionAuthenticator {
    /// Single signature
    Ed25519 {
        public_key: Vec<u8>,
        signature: Vec<u8>,
    },
    /// K-of-N multisignature
    MultiEd25519 {},
    /// Multi-agent transaction.
    MultiAgent {},
}

impl TransactionSigner<AptosTxIn, AptosTxOut> for Keystore {
    fn sign_transaction(
        &mut self,
        symbol: &str,
        address: &str,
        tx: &AptosTxIn,
    ) -> Result<AptosTxOut> {
        let raw_tx = RawTransaction::try_from(tx)?;
        // note: msg_to_sign = prefix_bytes | bcs_bytes_of_raw_transaction.
        let mut msg_to_sign = tx_prefix_hash();
        bcs::serialize_into(&mut msg_to_sign, &raw_tx)?;
        let sk = self.find_private_key(symbol, address)?;
        let sig = sk.sign(&msg_to_sign)?;
        let pk = sk.public_key().to_bytes();
        let signed_tx = SignedTransaction {
            raw_tx,
            authenticator: TransactionAuthenticator::Ed25519 {
                public_key: pk,
                signature: sig,
            },
        };
        let serialized_tx = bcs::to_bytes(&signed_tx)?;
        Ok(AptosTxOut { tx: serialized_tx })
    }
}

fn tx_prefix_hash() -> Vec<u8> {
    let mut hasher = Sha3_256::new();
    hasher.update(TRANSACTION_PREFIX.as_bytes());
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use crate::signer::{
        AccountAddress, RawTransaction, SignedTransaction, TransactionAuthenticator,
    };
    use crate::transaction::aptos_tx_in::AptosTxType;
    use crate::{AptosAddress, AptosTxIn, NewTransfer};
    use sha3::{Digest, Sha3_256};
    use tcx_chain::{Keystore, Metadata, TransactionSigner};
    use tcx_constants::{CoinInfo, CurveType};

    #[test]
    fn test_transfer_input_convert_to_raw_tx() {
        let input = AptosTxIn {
            aptos_tx_type: Some(AptosTxType::Transfer(NewTransfer {
                sender: "0x7bb8598a93089b57b0db07303d4dfe8604c3c8d40d6ef0b6c2358baa5fd3933f"
                    .to_string(),
                sequence_number: 7,
                args: vec![],
                to: "0x90521ddc8cc3a6ee04953fdd2bbc0b4cf2899da8c3733f1870cee8e6999726e7"
                    .to_string(),
                amount: 10000000u64,
                max_gas_amount: 5000,
                gas_unit_price: 1000,
                expiration_timestamp_secs: 1979382887679336,
                chain_id: 2,
            })),
        };
        let raw_tx = RawTransaction::try_from(&input).unwrap();
        println!("raw_tx: {:?}", raw_tx);
        let valid_tx = [
            123, 184, 89, 138, 147, 8, 155, 87, 176, 219, 7, 48, 61, 77, 254, 134, 4, 195, 200,
            212, 13, 110, 240, 182, 194, 53, 139, 170, 95, 211, 147, 63, 7, 0, 0, 0, 0, 0, 0, 0, 2,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1, 4, 99, 111, 105, 110, 8, 116, 114, 97, 110, 115, 102, 101, 114, 1, 7, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            10, 97, 112, 116, 111, 115, 95, 99, 111, 105, 110, 9, 65, 112, 116, 111, 115, 67, 111,
            105, 110, 0, 2, 32, 144, 82, 29, 220, 140, 195, 166, 238, 4, 149, 63, 221, 43, 188, 11,
            76, 242, 137, 157, 168, 195, 115, 63, 24, 112, 206, 232, 230, 153, 151, 38, 231, 8,
            128, 150, 152, 0, 0, 0, 0, 0, 136, 19, 0, 0, 0, 0, 0, 0, 232, 3, 0, 0, 0, 0, 0, 0, 104,
            5, 229, 253, 60, 8, 7, 0, 2,
        ];
        println!("hex: {:?}", hex::encode(&valid_tx));
        assert_eq!(bcs::to_bytes(&raw_tx).unwrap(), valid_tx.to_vec());
    }

    #[test]
    fn test_raw_msg_input_convert_to_raw_tx() {
        let input = AptosTxIn {
            aptos_tx_type: Some(AptosTxType::RawTx(
                "7bb8598a93089b57b0db07303d4dfe8604c3c8d40d6ef0b6c2358baa5fd3933f070000000000000002000000000000000000000000000000000000000000000000000000000000000104636f696e087472616e73666572010700000000000000000000000000000000000000000000000000000000000000010a6170746f735f636f696e094170746f73436f696e00022090521ddc8cc3a6ee04953fdd2bbc0b4cf2899da8c3733f1870cee8e6999726e70880969800000000008813000000000000e8030000000000006805e5fd3c08070002".to_string()
            ))
        };
        RawTransaction::try_from(&input).unwrap();
    }
    #[test]
    fn test_sign_aptos_raw_tx() {
        let mut ks = Keystore::from_private_key(
            "6E26EBB57A01EE47158050E6980DC639E66129335ACE114ABBF9FD5D939049D6",
            "Password",
            Metadata::default(),
            "",
        );
        ks.unlock_by_password("Password").unwrap();
        let coin_info = CoinInfo {
            coin: "APTOS".to_string(),
            derivation_path: "".to_string(),
            curve: CurveType::ED25519,
            network: "MAINNET".to_string(),
            seg_wit: "".to_string(),
        };
        let account = ks.derive_coin::<AptosAddress>(&coin_info).unwrap().clone();
        println!("account: {:?}", account);

        let tx_input = AptosTxIn {
            aptos_tx_type: Some(AptosTxType::RawTx(
                "7bb8598a93089b57b0db07303d4dfe8604c3c8d40d6ef0b6c2358baa5fd3933f070000000000000002000000000000000000000000000000000000000000000000000000000000000104636f696e087472616e73666572010700000000000000000000000000000000000000000000000000000000000000010a6170746f735f636f696e094170746f73436f696e00022090521ddc8cc3a6ee04953fdd2bbc0b4cf2899da8c3733f1870cee8e6999726e70880969800000000008813000000000000e8030000000000006805e5fd3c08070002".to_string()
            ))
        };
        println!("input: {:?}", tx_input);

        let output = ks
            .sign_transaction("APTOS", &account.address, &tx_input)
            .unwrap();
        println!("output: {:?}", output);

        let signed_tx: SignedTransaction = bcs::from_bytes(&output.tx).unwrap();
        let valid_signature = TransactionAuthenticator::Ed25519 {
            public_key: vec![
                79, 175, 249, 168, 47, 87, 208, 99, 222, 47, 184, 22, 217, 86, 17, 163, 219, 210,
                20, 67, 49, 111, 195, 153, 16, 102, 112, 117, 187, 24, 145, 189,
            ],
            signature: vec![
                16, 85, 118, 133, 210, 232, 234, 125, 209, 178, 6, 79, 251, 34, 178, 158, 178, 224,
                18, 172, 211, 157, 29, 210, 111, 214, 19, 87, 152, 247, 116, 140, 26, 112, 163,
                108, 171, 47, 163, 156, 244, 173, 61, 63, 148, 195, 232, 189, 15, 18, 255, 76, 5,
                41, 85, 29, 90, 195, 71, 182, 184, 176, 68, 5,
            ],
        };
        assert_eq!(signed_tx.authenticator, valid_signature);
    }
}
