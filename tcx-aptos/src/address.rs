use sp_core::bytes::to_hex;
use tcx_chain::Address;
use tcx_constants::{CoinInfo, Result};
use tcx_primitive::{Ed25519PublicKey, PublicKey, TypedPublicKey};

pub struct AptosAddress(String);

impl Address for AptosAddress {
    fn from_public_key(public_key: &TypedPublicKey, _coin: &CoinInfo) -> Result<String> {
        let address = to_hex(public_key.to_bytes().as_slice(), false);
        Ok(address)
    }

    fn is_valid(address: &str, _coin: &CoinInfo) -> bool {
        match Ed25519PublicKey::from_slice(address.as_bytes()) {
            Ok(..) => true,
            _ => false,
        }
    }
}
