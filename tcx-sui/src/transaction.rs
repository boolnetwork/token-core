use super::sui_serde::{Base58, Hex, HexAccountAddress, Readable};
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

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SuiTxInput {
    #[prost(string, tag = "1")]
    pub intent: String,
    #[prost(string, tag = "2")]
    pub tx_data: String,
    #[prost(message, required, tag = "3")]
    pub response_options: SuiTransactionBlockResponseOptions,
    #[prost(enumeration = "ExecuteTransactionRequestType", tag = "4")]
    pub r#type: i32,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SuiTxOuput {
    #[prost(string, tag = "1")]
    pub tx_data: String,
    #[prost(string, tag = "2")]
    pub signatures: String,
    #[prost(message, required, tag = "3")]
    pub response_options: SuiTransactionBlockResponseOptions,
    #[prost(enumeration = "ExecuteTransactionRequestType", tag = "4")]
    pub r#type: i32,
}

#[derive(Debug, PartialEq, Eq, Serialize, Clone, Hash, Deserialize)]
pub struct SuiUnsignedMessage {
    pub intent: Intent,
    pub value: SuiRawTx,
}

impl TryFrom<&SuiTxInput> for SuiUnsignedMessage {
    type Error = crate::Error;

    fn try_from(message: &SuiTxInput) -> Result<SuiUnsignedMessage, Self::Error> {
        let intent = bcs::from_bytes::<Intent>(
            &base64::decode(&message.intent).map_err(|_| Self::Error::IntentBs64ParseError)?,
        )
        .map_err(|_| Self::Error::IntentBcsParseError)?;
        let raw_tx = bcs::from_bytes::<SuiRawTx>(
            &base64::decode(&message.tx_data).map_err(|_| Self::Error::TxDataBase64ParseError)?,
        )
        .map_err(|_| Self::Error::TxDataBcsParseError)?;
        Ok(SuiUnsignedMessage {
            intent,
            value: raw_tx,
        })
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
    Debug,
    Eq,
    Default,
    PartialEq,
    Ord,
    PartialOrd,
    Copy,
    Clone,
    Hash,
    Serialize,
    Deserialize,
    JsonSchema,
)]
pub struct Address(
    #[schemars(with = "Hex")]
    #[serde_as(as = "Readable<Hex, _>")]
    [u8; 32],
);

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

    pub fn to_hex(&self) -> String {
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
            self.to_hex().serialize(serializer)
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

#[derive(Clone, Deserialize, Serialize, JsonSchema, Eq, PartialEq, ::prost::Message)]
#[serde(
    rename_all = "camelCase",
    rename = "TransactionBlockResponseOptions",
    default
)]
pub struct SuiTransactionBlockResponseOptions {
    /// Whether to show transaction input data. Default to be False
    #[prost(bool, tag = "1")]
    pub show_input: bool,
    /// Whether to show bcs-encoded transaction input data
    #[prost(bool, tag = "2")]
    pub show_raw_input: bool,
    /// Whether to show transaction effects. Default to be False
    #[prost(bool, tag = "3")]
    pub show_effects: bool,
    /// Whether to show transaction events. Default to be False
    #[prost(bool, tag = "4")]
    pub show_events: bool,
    /// Whether to show object_changes. Default to be False
    #[prost(bool, tag = "5")]
    pub show_object_changes: bool,
    /// Whether to show balance_changes. Default to be False
    #[prost(bool, tag = "6")]
    pub show_balance_changes: bool,
}

#[derive(
    Serialize, Deserialize, Clone, Debug, schemars::JsonSchema, PartialEq, ::prost::Enumeration,
)]
#[repr(i32)]
pub enum ExecuteTransactionRequestType {
    WaitForEffectsCert = 0,
    WaitForLocalExecution = 1,
}

#[test]
fn test_tx_data() {
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
