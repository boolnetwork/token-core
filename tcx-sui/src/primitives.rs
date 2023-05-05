use super::sui_serde::{Base58, Hex, HexAccountAddress, Readable};
use crate::sui_serde::decode_bytes_hex;
use crate::{NewTransfer, ProstObjectRef, SuiTxInput, SuiTxType, TransferType};
use hex::FromHex;
use move_core_types::{identifier::Identifier, language_storage::TypeTag};
use schemars::JsonSchema;
use serde::de::Error;
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use serde_with::{serde_as, Bytes};
use sp_core::serde::{Deserializer, Serializer};
use std::fmt;
use std::str::FromStr;

pub type ObjectRef = (ObjectID, SequenceNumber, ObjectDigest);

impl TryFrom<&NewTransfer> for ProgrammableTransaction {
    type Error = crate::Error;

    fn try_from(transfer: &NewTransfer) -> Result<ProgrammableTransaction, Self::Error> {
        let programmable_tx = match transfer
            .transfer_type
            .as_ref()
            .ok_or(crate::Error::EmptyTransferType)?
        {
            TransferType::Sui(tx) => {
                let mut inputs = Vec::new();
                let receiver = Address::from_str(&transfer.recipient)?;
                let rec_arg = Argument::Input(0);
                inputs.push(CallArg::Pure(
                    bcs::to_bytes(&receiver).map_err(|_| crate::Error::BcsSerializeFailed)?,
                ));
                let mut commands = Vec::new();
                let coin_arg = {
                    let amt_arg = Argument::Input(1);
                    commands.push(Command::SplitCoins(Argument::GasCoin, vec![amt_arg]));
                    inputs.push(CallArg::Pure(
                        bcs::to_bytes(&tx.amount).map_err(|_| crate::Error::BcsSerializeFailed)?,
                    ));
                    Argument::Result(0)
                };
                commands.push(Command::TransferObjects(vec![coin_arg], rec_arg));
                ProgrammableTransaction { inputs, commands }
            }
            TransferType::Object(object) => {
                let mut inputs = Vec::new();
                let receiver = Address::from_str(&transfer.recipient)?;
                let rec_arg = Argument::Input(0);
                inputs.push(CallArg::Pure(
                    bcs::to_bytes(&receiver).map_err(|_| crate::Error::BcsSerializeFailed)?,
                ));
                let object = ObjectRef::try_from(object)?;
                let obj_arg = Argument::Input(1);
                inputs.push(CallArg::Object(ObjectArg::ImmOrOwnedObject(object)));
                ProgrammableTransaction {
                    inputs,
                    commands: vec![Command::TransferObjects(vec![obj_arg], rec_arg)],
                }
            }
        };
        Ok(programmable_tx)
    }
}

impl TryFrom<&ProstObjectRef> for ObjectRef {
    type Error = crate::Error;

    fn try_from(message: &ProstObjectRef) -> Result<ObjectRef, Self::Error> {
        if message.object_id.len() != 32 {
            return Err(crate::Error::InvalidObjectID);
        }
        if message.object_digest.len() != 32 {
            return Err(crate::Error::InvalidObjectDigest);
        }
        let mut object_id = [0u8; 32];
        object_id.copy_from_slice(&message.object_id);
        let mut object_digest = [0u8; 32];
        object_digest.copy_from_slice(&message.object_digest);
        Ok((
            ObjectID(AccountAddress(object_id)),
            SequenceNumber(message.seq_num),
            ObjectDigest(Digest(object_digest)),
        ))
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Clone, Hash, Deserialize)]
pub struct SuiUnsignedMessage {
    pub intent: Intent,
    pub value: SuiRawTx,
}

impl TryFrom<&SuiTxInput> for SuiUnsignedMessage {
    type Error = crate::Error;

    fn try_from(message: &SuiTxInput) -> Result<SuiUnsignedMessage, Self::Error> {
        let unsigned_msg = match message
            .sui_tx_type
            .clone()
            .ok_or(crate::Error::EmptyTxType)?
        {
            SuiTxType::RawTx(tx) => {
                let intent = bcs::from_bytes::<Intent>(
                    &base64::decode(&tx.intent).map_err(|_| Self::Error::IntentBs64ParseError)?,
                )
                .map_err(|_| Self::Error::IntentBcsParseError)?;
                let raw_tx = bcs::from_bytes::<SuiRawTx>(
                    &base64::decode(&tx.tx_data)
                        .map_err(|_| Self::Error::TxDataBase64ParseError)?,
                )
                .map_err(|_| Self::Error::TxDataBcsParseError)?;
                SuiUnsignedMessage {
                    intent,
                    value: raw_tx,
                }
            }
            SuiTxType::Transfer(transfer) => {
                let programmable_tx = ProgrammableTransaction::try_from(&transfer)?;
                let sender = Address::from_str(&transfer.sender)?;
                let payment = ObjectRef::try_from(
                    &transfer.gas_payment.ok_or(crate::Error::EmptyObjectRef)?,
                )?;
                let value = SuiRawTx::V1(TransactionDataV1 {
                    kind: TransactionKind::ProgrammableTransaction(programmable_tx),
                    sender,
                    gas_data: GasData {
                        price: transfer.gas_price,
                        owner: sender,
                        payment: vec![payment],
                        budget: transfer.gas_budget,
                    },
                    expiration: TransactionExpiration::None,
                });
                let intent = Intent {
                    scope: IntentScope::TransactionData,
                    version: IntentVersion::V0,
                    app_id: AppId::Sui,
                };
                SuiUnsignedMessage { intent, value }
            }
        };
        Ok(unsigned_msg)
    }
}

/// An intent is a compact struct serves as the domain separator for a message that a signature commits to.
/// It consists of three parts: [enum IntentScope] (what the type of the message is), [enum IntentVersion], [enum AppId] (what application that the signature refers to).
/// It is used to construct [struct IntentMessage] that what a signature commits to.
///
/// The serialization of an Intent is a 3-byte array where each field is represented by a byte.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone, Hash)]
pub struct Intent {
    pub scope: IntentScope,
    pub version: IntentVersion,
    pub app_id: AppId,
}

#[derive(Serialize_repr, Deserialize_repr, Copy, Clone, PartialEq, Eq, Debug, Hash)]
#[repr(u8)]
pub enum IntentVersion {
    V0 = 0,
}

impl IntentVersion {
    pub fn from_u32(value: u32) -> Option<IntentVersion> {
        let version = match value {
            0 => Self::V0,
            _ => return None,
        };
        Some(version)
    }
}

/// This enums specifies the application ID. Two intents in two different applications
/// (i.e., Narwhal, Sui, Ethereum etc) should never collide, so that even when a signing
/// key is reused, nobody can take a signature designated for app_1 and present it as a
/// valid signature for an (any) intent in app_2.
#[derive(Serialize_repr, Deserialize_repr, Copy, Clone, PartialEq, Eq, Debug, Hash)]
#[repr(u8)]
pub enum AppId {
    Sui = 0,
    Narwhal = 1,
}

impl AppId {
    pub fn from_u32(value: u32) -> Option<AppId> {
        let app_id = match value {
            0 => Self::Sui,
            1 => Self::Narwhal,
            _ => return None,
        };
        Some(app_id)
    }
}

#[derive(Serialize_repr, Deserialize_repr, Copy, Clone, PartialEq, Eq, Debug, Hash)]
#[repr(u8)]
pub enum IntentScope {
    TransactionData = 0,         // Used for a user signature on a transaction data.
    TransactionEffects = 1,      // Used for an authority signature on transaction effects.
    CheckpointSummary = 2,       // Used for an authority signature on a checkpoint summary.
    PersonalMessage = 3,         // Used for a user signature on a personal message.
    SenderSignedTransaction = 4, // Used for an authority signature on a user signed transaction.
    ProofOfPossession = 5, // Used as a signature representing an authority's proof of possession of its authority protocol key.
    HeaderDigest = 6,      // Used for narwhal authority signature on header digest.
}

impl IntentScope {
    pub fn from_u32(value: u32) -> Option<IntentScope> {
        let scope = match value {
            0 => Self::TransactionData,
            1 => Self::TransactionEffects,
            2 => Self::CheckpointSummary,
            3 => Self::PersonalMessage,
            4 => Self::SenderSignedTransaction,
            5 => Self::ProofOfPossession,
            6 => Self::HeaderDigest,
            _ => return None,
        };
        Some(scope)
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
pub enum SuiRawTx {
    V1(TransactionDataV1),
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
pub struct TransactionDataV1 {
    pub kind: TransactionKind,
    pub sender: Address,
    pub gas_data: GasData,
    pub expiration: TransactionExpiration,
}

#[serde_as]
#[derive(
    Eq, Default, PartialEq, Ord, PartialOrd, Copy, Clone, Hash, Serialize, Deserialize, JsonSchema,
)]
pub struct Address(
    #[schemars(with = "Hex")]
    #[serde_as(as = "Readable<Hex, _>")]
    [u8; 32],
);

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", Hex::encode(self.0))
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "0x{}", Hex::encode(self.0))
    }
}

impl TryFrom<&[u8]> for Address {
    type Error = crate::Error;

    /// Tries to convert the provided byte array into a SuiAddress.
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        <[u8; 32]>::try_from(bytes)
            .map_err(|_| Self::Error::AddressParseError)
            .map(Address)
    }
}

impl FromStr for Address {
    type Err = crate::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        decode_bytes_hex(s).map_err(|_| crate::Error::AddressParseError)
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
pub struct GasData {
    pub payment: Vec<ObjectRef>,
    pub owner: Address,
    pub price: u64,
    pub budget: u64,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy, Serialize, Deserialize)]
pub enum TransactionExpiration {
    /// The transaction has no expiration
    None,
    /// Validators wont sign a transaction unless the expiration Epoch
    /// is greater than or equal to the current epoch
    Epoch(u64),
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
pub enum TransactionKind {
    /// A transaction that allows the interleaving of native commands and Move calls
    ProgrammableTransaction(ProgrammableTransaction),
}

/// A series of commands where the results of one command can be used in future
/// commands
#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
pub struct ProgrammableTransaction {
    /// Input objects or primitive values
    pub inputs: Vec<CallArg>,
    /// The commands to be executed sequentially. A failure in any command will
    /// result in the failure of the entire transaction.
    pub commands: Vec<Command>,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
pub enum CallArg {
    // contains no structs or objects
    Pure(Vec<u8>),
    // an object
    Object(ObjectArg),
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy, Serialize, Deserialize)]
pub enum ObjectArg {
    // A Move object, either immutable, or owned mutable.
    ImmOrOwnedObject(ObjectRef),
    // A Move object that's shared.
    // SharedObject::mutable controls whether caller asks for a mutable reference to shared object.
    SharedObject {
        id: ObjectID,
        initial_shared_version: SequenceNumber,
        mutable: bool,
    },
}

#[serde_as]
#[derive(Eq, PartialEq, Clone, Copy, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema)]
pub struct ObjectID(
    #[schemars(with = "Hex")]
    #[serde_as(as = "Readable<HexAccountAddress, _>")]
    AccountAddress,
);

impl AsRef<[u8]> for AccountAddress {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for ObjectID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

#[derive(Ord, PartialOrd, Eq, PartialEq, Hash, Clone, Copy)]
pub struct AccountAddress([u8; 32]);

impl AccountAddress {
    pub const fn new(address: [u8; 32]) -> Self {
        Self(address)
    }

    pub fn from_hex_literal(literal: &str) -> Result<Self, AccountAddressParseError> {
        if !literal.starts_with("0x") {
            return Err(AccountAddressParseError);
        }

        let hex_len = literal.len() - 2;

        // If the string is too short, pad it
        if hex_len < 32 * 2 {
            let mut hex_str = String::with_capacity(32 * 2);
            for _ in 0..32 * 2 - hex_len {
                hex_str.push('0');
            }
            hex_str.push_str(&literal[2..]);
            AccountAddress::from_hex(hex_str)
        } else {
            AccountAddress::from_hex(&literal[2..])
        }
    }

    pub fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, AccountAddressParseError> {
        <[u8; 32]>::from_hex(hex)
            .map_err(|_| AccountAddressParseError)
            .map(Self)
    }

    pub fn encode_to_hex(&self) -> String {
        format!("{:?}", hex::encode(self.0).to_lowercase())
    }
}
impl FromStr for AccountAddress {
    type Err = AccountAddressParseError;

    fn from_str(s: &str) -> Result<Self, AccountAddressParseError> {
        // Accept 0xADDRESS or ADDRESS
        if let Ok(address) = AccountAddress::from_hex_literal(s) {
            Ok(address)
        } else {
            Self::from_hex(s)
        }
    }
}

impl<'de> Deserialize<'de> for AccountAddress {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = <String>::deserialize(deserializer)?;
            AccountAddress::from_str(&s).map_err(D::Error::custom)
        } else {
            // In order to preserve the Serde data model and help analysis tools,
            // make sure to wrap our value in a container with the same name
            // as the original type.
            #[derive(::serde::Deserialize)]
            #[serde(rename = "AccountAddress")]
            struct Value([u8; 32]);

            let value = Value::deserialize(deserializer)?;
            Ok(AccountAddress::new(value.0))
        }
    }
}

impl Serialize for AccountAddress {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            self.encode_to_hex().serialize(serializer)
        } else {
            // See comment in deserialize.
            serializer.serialize_newtype_struct("AccountAddress", &self.0)
        }
    }
}

#[derive(
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Copy,
    Clone,
    Hash,
    Default,
    Debug,
    Serialize,
    Deserialize,
    JsonSchema,
)]
pub struct SequenceNumber(u64);

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema)]
pub struct ObjectDigest(Digest);

impl fmt::Debug for ObjectDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "o#{}", self.0)
    }
}

#[serde_as]
#[derive(
    Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
pub struct Digest(
    #[schemars(with = "Base58")]
    #[serde_as(as = "Readable<Base58, Bytes>")]
    [u8; 32],
);

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&bs58::encode(self.0).into_string())
    }
}

/// A single command in a programmable transaction.
#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
pub enum Command {
    /// A call to either an entry or a public Move function
    MoveCall(Box<ProgrammableMoveCall>),
    /// `(Vec<forall T:key+store. T>, address)`
    /// It sends n-objects to the specified address. These objects must have store
    /// (public transfer) and either the previous owner must be an address or the object must
    /// be newly created.
    TransferObjects(Vec<Argument>, Argument),
    /// `(&mut Coin<T>, Vec<u64>)` -> `Vec<Coin<T>>`
    /// It splits off some amounts into a new coins with those amounts
    SplitCoins(Argument, Vec<Argument>),
    /// `(&mut Coin<T>, Vec<Coin<T>>)`
    /// It merges n-coins into the first coin
    MergeCoins(Argument, Vec<Argument>),
    /// Publishes a Move package. It takes the package bytes and a list of the package's transitive
    /// dependencies to link against on-chain.
    Publish(Vec<Vec<u8>>, Vec<ObjectID>),
    /// `forall T: Vec<T> -> vector<T>`
    /// Given n-values of the same type, it constructs a vector. For non objects or an empty vector,
    /// the type tag must be specified.
    MakeMoveVec(Option<TypeTag>, Vec<Argument>),
    /// Upgrades a Move package
    /// Takes (in order):
    /// 1. A vector of serialized modules for the package.
    /// 2. A vector of object ids for the transitive dependencies of the new package.
    /// 3. The object ID of the package being upgraded.
    /// 4. An argument holding the `UpgradeTicket` that must have been produced from an earlier command in the same
    ///    programmable transaction.
    Upgrade(Vec<Vec<u8>>, Vec<ObjectID>, ObjectID, Argument),
}

/// The command for calling a Move function, either an entry function or a public
/// function (which cannot return references).
#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
pub struct ProgrammableMoveCall {
    /// The package containing the module and function.
    pub package: ObjectID,
    /// The specific module in the package containing the function.
    pub module: Identifier,
    /// The function to be called.
    pub function: Identifier,
    /// The type arguments to the function.
    pub type_arguments: Vec<TypeTag>,
    /// The arguments to the function.
    pub arguments: Vec<Argument>,
}

/// An argument to a programmable transaction command
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy, Serialize, Deserialize)]
pub enum Argument {
    /// The gas coin. The gas coin can only be used by-ref, except for with
    /// `TransferObjects`, which can use it by-value.
    GasCoin,
    /// One of the input objects or primitive values (from
    /// `ProgrammableTransaction` inputs)
    Input(u16),
    /// The result of another command (from `ProgrammableTransaction` commands)
    Result(u16),
    /// Like a `Result` but it accesses a nested result. Currently, the only usage
    /// of this is to access a value from a Move call with multiple return values.
    NestedResult(u16, u16),
}

#[derive(Clone, Copy, Debug)]
pub struct AccountAddressParseError;

impl fmt::Display for AccountAddressParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Unable to parse AccountAddress (must be hex string of length {})",
            32
        )
    }
}

impl std::error::Error for AccountAddressParseError {}

#[cfg(test)]
mod tests {
    use crate::primitives::{
        AccountAddress, Address, AppId, Argument, CallArg, Command, Digest, GasData, Intent,
        IntentScope, IntentVersion, NewTransfer, ObjectDigest, ObjectID, ProgrammableTransaction,
        ProstObjectRef, SequenceNumber, SuiRawTx, SuiTxType, TransactionDataV1,
        TransactionExpiration, TransactionKind, TransferType,
    };
    use crate::transaction::SuiTxInput;
    use crate::{RawTx, SuiTransfer, SuiUnsignedMessage};

    #[test]
    fn test_raw_tx_data() {
        let input = SuiTxInput {
            sui_tx_type: Some(SuiTxType::RawTx(
                RawTx {
                    intent: "AAAA".to_string(),
                    tx_data: "AAACACDcuwu46vFiu6uRqbhDa0O608vjolaFH0xH2XMreJluiAAIAIeTAwAAAAACAgABAQEAAQECAAABAACwRH97irYX05VgpnSB8BPYs38y0l5nWwPa5YeIHGeY/wEHm6Y05TyCQsujP5F94Q6hJ5pwpXszRteML2MRXG2gHNQUFQAAAAAAIJXoZBHHdSW8FSdK+4HU4sqJ76kNNuqPjZtr4gzLaUNjsER/e4q2F9OVYKZ0gfAT2LN/MtJeZ1sD2uWHiBxnmP/oAwAAAAAAAICWmAAAAAAAAA==".to_string(),
                }
            ))
        };
        let tx = SuiUnsignedMessage {
            intent: Intent {
                scope: IntentScope::TransactionData,
                version: IntentVersion::V0,
                app_id: AppId::Sui,
            },
            value: SuiRawTx::V1(TransactionDataV1 {
                kind: TransactionKind::ProgrammableTransaction(ProgrammableTransaction {
                    inputs: vec![
                        CallArg::Pure(
                            [
                                220, 187, 11, 184, 234, 241, 98, 187, 171, 145, 169, 184, 67, 107, 67,
                                186, 211, 203, 227, 162, 86, 133, 31, 76, 71, 217, 115, 43, 120, 153,
                                110, 136,
                            ]
                                .to_vec(),
                        ),
                        CallArg::Pure([0, 135, 147, 3, 0, 0, 0, 0].to_vec()),
                    ],
                    commands: vec![
                        Command::SplitCoins(Argument::GasCoin, vec![Argument::Input(1)]),
                        Command::TransferObjects(vec![Argument::Result(0)], Argument::Input(0)),
                    ],
                }),
                sender: Address([
                    176u8, 68, 127, 123, 138, 182, 23, 211, 149, 96, 166, 116, 129, 240, 19, 216, 179,
                    127, 50, 210, 94, 103, 91, 3, 218, 229, 135, 136, 28, 103, 152, 255,
                ]),
                gas_data: GasData {
                    payment: vec![(
                        ObjectID(
                            AccountAddress::from_hex_literal(
                                "0x079ba634e53c8242cba33f917de10ea1279a70a57b3346d78c2f63115c6da01c",
                            )
                                .unwrap(),
                        ),
                        SequenceNumber(1381588),
                        ObjectDigest(Digest([
                            149, 232, 100, 17, 199, 117, 37, 188, 21, 39, 74, 251, 129, 212, 226, 202,
                            137, 239, 169, 13, 54, 234, 143, 141, 155, 107, 226, 12, 203, 105, 67, 99,
                        ])),
                    )],
                    owner: Address([
                        176u8, 68, 127, 123, 138, 182, 23, 211, 149, 96, 166, 116, 129, 240, 19, 216,
                        179, 127, 50, 210, 94, 103, 91, 3, 218, 229, 135, 136, 28, 103, 152, 255,
                    ]),
                    price: 1000,
                    budget: 10000000,
                },
                expiration: TransactionExpiration::None,
            }),
        };

        assert_eq!(SuiUnsignedMessage::try_from(&input).unwrap(), tx);

        let bytes1 = bcs::to_bytes(&tx.intent).unwrap();
        println!("bytes1: {:?}", bytes1);
        println!(
            "intent base64: {:?}",
            base64::encode(&bcs::to_bytes(&tx.intent).unwrap())
        );

        assert_eq!(
            bcs::from_bytes::<Intent>(&base64::decode("AAAA").unwrap()).unwrap(),
            tx.intent
        );

        let tx_data_base64 = base64::encode(&bcs::to_bytes(&tx.value).unwrap());
        assert_eq!(tx_data_base64, "AAACACDcuwu46vFiu6uRqbhDa0O608vjolaFH0xH2XMreJluiAAIAIeTAwAAAAACAgABAQEAAQECAAABAACwRH97irYX05VgpnSB8BPYs38y0l5nWwPa5YeIHGeY/wEHm6Y05TyCQsujP5F94Q6hJ5pwpXszRteML2MRXG2gHNQUFQAAAAAAIJXoZBHHdSW8FSdK+4HU4sqJ76kNNuqPjZtr4gzLaUNjsER/e4q2F9OVYKZ0gfAT2LN/MtJeZ1sD2uWHiBxnmP/oAwAAAAAAAICWmAAAAAAAAA==");
        let de_tx: SuiRawTx = bcs::from_bytes(&base64::decode(tx_data_base64).unwrap()).unwrap();
        assert_eq!(de_tx, tx.value);
    }

    #[test]
    fn test_transfer_sui_tx_data() {
        let sui_transfer = SuiTransfer { amount: 60000000 };
        let transfer = NewTransfer {
            transfer_type: Some(TransferType::Sui(sui_transfer)),
            recipient: "0xdcbb0bb8eaf162bbab91a9b8436b43bad3cbe3a256851f4c47d9732b78996e88"
                .to_string(),
            sender: "0xb0447f7b8ab617d39560a67481f013d8b37f32d25e675b03dae587881c6798ff"
                .to_string(),
            gas_payment: Some(ProstObjectRef {
                object_id: hex::decode(
                    "079ba634e53c8242cba33f917de10ea1279a70a57b3346d78c2f63115c6da01c",
                )
                .unwrap(),
                seq_num: 2641230,
                object_digest: bs58::decode("HBLfbA1EqRUAWWMeVZa5bgKyXv3VS1GnCZcKCZYLtGLu")
                    .into_vec()
                    .unwrap(),
            }),
            gas_budget: 10000000,
            gas_price: 999,
        };
        let input = SuiTxInput {
            sui_tx_type: Some(SuiTxType::Transfer(transfer)),
        };
        let unsigned_tx = SuiUnsignedMessage::try_from(&input).unwrap();
        println!("unsigned_tx: {:?}", unsigned_tx);
        let tx_data_base64 = base64::encode(&bcs::to_bytes(&unsigned_tx.value).unwrap());
        assert_eq!(tx_data_base64, "AAACACDcuwu46vFiu6uRqbhDa0O608vjolaFH0xH2XMreJluiAAIAIeTAwAAAAACAgABAQEAAQECAAABAACwRH97irYX05VgpnSB8BPYs38y0l5nWwPa5YeIHGeY/wEHm6Y05TyCQsujP5F94Q6hJ5pwpXszRteML2MRXG2gHE5NKAAAAAAAIPBhCNlgeWQXkO2bJZJLJYPgkB4q8//5R9UHFiLTiPmmsER/e4q2F9OVYKZ0gfAT2LN/MtJeZ1sD2uWHiBxnmP/nAwAAAAAAAICWmAAAAAAAAA==")
    }

    #[test]
    fn test_transfer_object_tx_data() {
        let obj_transfer = ProstObjectRef {
            object_id: hex::decode(
                "079ba634e53c8242cba33f917de10ea1279a70a57b3346d78c2f63115c6da01c",
            )
            .unwrap(),
            seq_num: 2641230,
            object_digest: bs58::decode("HBLfbA1EqRUAWWMeVZa5bgKyXv3VS1GnCZcKCZYLtGLu")
                .into_vec()
                .unwrap(),
        };
        let transfer = NewTransfer {
            transfer_type: Some(TransferType::Object(obj_transfer)),
            recipient: "0xdcbb0bb8eaf162bbab91a9b8436b43bad3cbe3a256851f4c47d9732b78996e88"
                .to_string(),
            sender: "0xb0447f7b8ab617d39560a67481f013d8b37f32d25e675b03dae587881c6798ff"
                .to_string(),
            gas_payment: Some(ProstObjectRef {
                object_id: hex::decode(
                    "079ba634e53c8242cba33f917de10ea1279a70a57b3346d78c2f63115c6da01c",
                )
                .unwrap(),
                seq_num: 2641230,
                object_digest: bs58::decode("HBLfbA1EqRUAWWMeVZa5bgKyXv3VS1GnCZcKCZYLtGLu")
                    .into_vec()
                    .unwrap(),
            }),
            gas_budget: 10000000,
            gas_price: 998,
        };
        let input = SuiTxInput {
            sui_tx_type: Some(SuiTxType::Transfer(transfer)),
        };
        let unsigned_tx = SuiUnsignedMessage::try_from(&input).unwrap();
        println!("unsigned_tx: {:?}", unsigned_tx);
        let tx_data_base64 = base64::encode(&bcs::to_bytes(&unsigned_tx.value).unwrap());
        assert_eq!(tx_data_base64, "AAACACDcuwu46vFiu6uRqbhDa0O608vjolaFH0xH2XMreJluiAEAB5umNOU8gkLLoz+RfeEOoSeacKV7M0bXjC9jEVxtoBxOTSgAAAAAACDwYQjZYHlkF5DtmyWSSyWD4JAeKvP/+UfVBxYi04j5pgEBAQEBAAEAALBEf3uKthfTlWCmdIHwE9izfzLSXmdbA9rlh4gcZ5j/AQebpjTlPIJCy6M/kX3hDqEnmnClezNG14wvYxFcbaAcTk0oAAAAAAAg8GEI2WB5ZBeQ7Zslkkslg+CQHirz//lH1QcWItOI+aawRH97irYX05VgpnSB8BPYs38y0l5nWwPa5YeIHGeY/+YDAAAAAAAAgJaYAAAAAAAA".to_string());
    }
}
