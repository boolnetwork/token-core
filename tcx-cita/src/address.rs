use tcx_chain::Address;
use tcx_constants::{CoinInfo, Result};
use tcx_primitive::TypedPublicKey;

pub struct CitaAddress;

impl Address for CitaAddress {
    fn from_public_key(public_key: &TypedPublicKey, _coin: &CoinInfo) -> Result<String> {
        let address = match public_key {
            TypedPublicKey::Sm2(pk) => hex::encode(cita_sm2::pubkey_to_address(&pk.0).0),
            _ => return Err(crate::Error::InvalidPubkey.into()),
        };
        Ok("0x".to_string() + &address)
    }

    fn is_valid(address: &str, _coin: &CoinInfo) -> bool {
        if address.is_empty() {
            return false;
        };
        let address = address.strip_prefix("0x").unwrap_or(address);
        if address.len() != 64 {
            return false;
        }
        true
    }
}
