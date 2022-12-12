use crate::Error;
use crate::{vec_bytes, AptosTxIn, AptosTxOut};
use hex::FromHex;
use serde::{Deserialize, Serialize};
use tcx_chain::{Keystore, Result, TransactionSigner};
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct SignedTransaction {
    pub raw_txn: RawTransaction,
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
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountAddress([u8; 32]);
impl AccountAddress {
    pub const fn new(address: [u8; 32]) -> Self {
        Self(address)
    }
    pub fn from_hex_literal(literal: &str) -> Result<Self> {
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
    pub fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self> {
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
#[derive(Clone, Debug, Serialize, Deserialize)]
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
        let str: Vec<&str> = tx.coin_type.split("::").collect();
        let coin = StructTag {
            address: AccountAddress::from_hex_literal(str[0])?,
            module: str[1].to_string(),
            name: str[2].to_string(),
            type_params: vec![],
        };
        let mut account_one = [0u8; 32];
        account_one[31] = 1;
        let payload = TransactionPayload::EntryFunction(EntryFunction::new(
            ModuleId::new(AccountAddress::new(account_one), "coin".to_string()),
            "transfer".to_string(),
            vec![TypeTag::Struct(coin)],
            vec![tx.to.to_vec(), bcs::to_bytes(&tx.amount)?],
        ));
        let raw_tx = RawTransaction {
            sender: AccountAddress(<[u8; 32]>::try_from(tx.sender.as_slice())?),
            sequence_number: tx.sequence_number.clone(),
            payload,
            max_gas_amount: tx.max_gas_amount.clone(),
            gas_unit_price: tx.gas_unit_price.clone(),
            expiration_timestamp_secs: tx.expiration_timestamp_secs.clone(),
            chain_id: tx.chain_id.clone() as u8,
        };
        //hash seed of raw transaction
        let mut bytes: Vec<u8> = [
            181, 233, 125, 176, 127, 160, 189, 14, 85, 152, 170, 54, 67, 169, 188, 111, 102, 147,
            189, 220, 26, 159, 236, 158, 103, 74, 70, 30, 170, 0, 177, 147,
        ]
        .to_vec();
        bcs::serialize_into(&mut bytes, &raw_tx)?;
        let sk = self.find_private_key(symbol, address)?;
        let sig = sk.sign(&bytes)?;
        let pk = sk.public_key().to_bytes();
        let signed_tx = SignedTransaction {
            raw_txn: raw_tx,
            authenticator: TransactionAuthenticator::Ed25519 {
                public_key: pk,
                signature: sig,
            },
        };
        let serialized_tx = bcs::to_bytes(&signed_tx)?;
        Ok(AptosTxOut { tx: serialized_tx })
    }
}
