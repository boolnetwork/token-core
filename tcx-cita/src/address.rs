use sha3::Digest;
use tcx_chain::Address;
use tcx_constants::{CoinInfo, Result};
use tcx_primitive::TypedPublicKey;

pub struct CitaAddress;

impl Address for CitaAddress {
    fn from_public_key(public_key: &TypedPublicKey, _coin: &CoinInfo) -> Result<String> {
        let pk = public_key.as_secp256k1()?.to_uncompressed();
        let hash = sha3::Keccak256::digest(&pk[1..]).to_vec().split_off(12);
        let address = hex::encode(hash);
        Ok("0x".to_string() + &hex::encode::<&[u8]>(address.as_ref()))
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
