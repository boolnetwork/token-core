#![allow(dead_code)]
use crate::primitives::AccountAddress;
use eyre::eyre;
use schemars::JsonSchema;
use serde::{de::Error, Deserialize, Serialize};
use serde_with::{DeserializeAs, SerializeAs};
use sp_core::serde::{Deserializer, Serializer};
use std::fmt::Debug;
use std::marker::PhantomData;
/// Use with serde_as to control serde for human-readable serialization and deserialization
/// `H` : serde_as SerializeAs/DeserializeAs delegation for human readable in/output
/// `R` : serde_as SerializeAs/DeserializeAs delegation for non-human readable in/output
///
/// # Example:
///
/// ```text
/// #[serde_as]
/// #[derive(Deserialize, Serialize)]
/// struct Example(#[serde_as(as = "Readable<DisplayFromStr, _>")] [u8; 20]);
/// ```
///
/// The above example will delegate human-readable serde to `DisplayFromStr`
/// and array tuple (default) for non-human-readable serializer.
pub struct Readable<H, R> {
    human_readable: PhantomData<H>,
    non_human_readable: PhantomData<R>,
}

impl<T: ?Sized, H, R> SerializeAs<T> for Readable<H, R>
where
    H: SerializeAs<T>,
    R: SerializeAs<T>,
{
    fn serialize_as<S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            H::serialize_as(value, serializer)
        } else {
            R::serialize_as(value, serializer)
        }
    }
}

impl<'de, R, H, T> DeserializeAs<'de, T> for Readable<H, R>
where
    H: DeserializeAs<'de, T>,
    R: DeserializeAs<'de, T>,
{
    fn deserialize_as<D>(deserializer: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            H::deserialize_as(deserializer)
        } else {
            R::deserialize_as(deserializer)
        }
    }
}

#[derive(Serialize, Deserialize, Debug, JsonSchema, Clone)]
pub struct Hex(String);

/// Decodes a hex string to bytes. Both upper and lower case characters are allowed in the hex string.
pub fn decode_bytes_hex<T: for<'a> TryFrom<&'a [u8]>>(s: &str) -> Result<T, eyre::Report> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let value = hex::decode(s)?;
    T::try_from(&value[..]).map_err(|_| eyre!("byte deserialization failed"))
}

impl Hex {
    pub fn decode(s: &str) -> Result<Vec<u8>, eyre::Report> {
        decode_bytes_hex(s)
    }

    pub fn encode<T: AsRef<[u8]>>(data: T) -> String {
        hex::encode(data.as_ref())
    }
}

impl<'de> DeserializeAs<'de, Vec<u8>> for Hex {
    fn deserialize_as<D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::decode(&s).map_err(to_custom_error::<'de, D, _>)
    }
}

impl<'de, const N: usize> DeserializeAs<'de, [u8; N]> for Hex {
    fn deserialize_as<D>(deserializer: D) -> Result<[u8; N], D::Error>
    where
        D: Deserializer<'de>,
    {
        let value: Vec<u8> = Hex::deserialize_as(deserializer)?;
        if value.len() != N {
            return Err(serde::de::Error::custom(format!(
                "invalid array length {}, expecting {}",
                value.len(),
                N
            )));
        }
        let mut array = [0u8; N];
        array.copy_from_slice(&value[..N]);
        Ok(array)
    }
}

/// Encodes bytes as a 0x prefixed hex string using lower case characters.
pub fn encode_with_format<B: AsRef<[u8]>>(bytes: B) -> String {
    format!("0x{}", hex::encode(bytes.as_ref()))
}

impl<T> SerializeAs<T> for Hex
where
    T: AsRef<[u8]>,
{
    fn serialize_as<S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        encode_with_format(value).serialize(serializer)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq, JsonSchema)]
#[serde(try_from = "String")]
pub struct Base58(String);

impl Base58 {
    fn decode(s: &str) -> Result<Vec<u8>, eyre::Report> {
        bs58::decode(s).into_vec().map_err(|e| eyre::eyre!(e))
    }

    fn encode<T: AsRef<[u8]>>(data: T) -> String {
        bs58::encode(data).into_string()
    }
}

impl TryFrom<String> for Base58 {
    type Error = eyre::Report;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        // Make sure the value is valid base58 string.
        bs58::decode(&value).into_vec()?;
        Ok(Self(value))
    }
}

impl<'de> DeserializeAs<'de, Vec<u8>> for Base58 {
    fn deserialize_as<D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::decode(&s).map_err(to_custom_error::<'de, D, _>)
    }
}

impl<T> SerializeAs<T> for Base58
where
    T: AsRef<[u8]>,
{
    fn serialize_as<S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        Self::encode(value).serialize(serializer)
    }
}

impl<'de, const N: usize> DeserializeAs<'de, [u8; N]> for Base58 {
    fn deserialize_as<D>(deserializer: D) -> Result<[u8; N], D::Error>
    where
        D: Deserializer<'de>,
    {
        let value: Vec<u8> = Base58::deserialize_as(deserializer)?;
        if value.len() != N {
            return Err(Error::custom(format!(
                "invalid array length {}, expecting {}",
                value.len(),
                N
            )));
        }
        let mut array = [0u8; N];
        array.copy_from_slice(&value[..N]);
        Ok(array)
    }
}

/// custom serde for AccountAddress
pub struct HexAccountAddress;

impl SerializeAs<AccountAddress> for HexAccountAddress {
    fn serialize_as<S>(value: &AccountAddress, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        Hex::serialize_as(value, serializer)
    }
}

impl<'de> DeserializeAs<'de, AccountAddress> for HexAccountAddress {
    fn deserialize_as<D>(deserializer: D) -> Result<AccountAddress, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        if s.starts_with("0x") {
            AccountAddress::from_hex_literal(&s)
        } else {
            AccountAddress::from_hex(&s)
        }
        .map_err(to_custom_error::<'de, D, _>)
    }
}

#[inline]
fn to_custom_error<'de, D, E>(e: E) -> D::Error
where
    E: Debug,
    D: Deserializer<'de>,
{
    serde::de::Error::custom(format!("byte deserialization failed, cause by: {e:?}"))
}
