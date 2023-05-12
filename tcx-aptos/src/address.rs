#![allow(dead_code)]
use sha3::{Digest, Sha3_256};
use sp_core::bytes::to_hex;
use tcx_chain::Address;
use tcx_constants::{CoinInfo, Result};
use tcx_primitive::TypedPublicKey;

pub const ED25519_FLAG: u8 = 0;
pub const MULTIED25519_FLAG: u8 = 1;

pub struct AptosAddress(String);

impl Address for AptosAddress {
    fn from_public_key(public_key: &TypedPublicKey, _coin: &CoinInfo) -> Result<String> {
        let mut pk = public_key.to_bytes();
        let flag = match public_key {
            TypedPublicKey::Ed25519(_) => ED25519_FLAG,
            _ => return Err(crate::Error::AccountAddressParseError.into()),
        };
        pk.push(flag);
        let mut hasher = Sha3_256::new();
        hasher.update(&pk);
        let result = hasher.finalize();
        let address = to_hex(&result, false);
        Ok(address)
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

#[cfg(test)]
mod tests {
    use crate::AptosAddress;
    use tcx_chain::Address;
    use tcx_constants::{CoinInfo, CurveType};
    use tcx_primitive::{Ed25519PublicKey, PublicKey, TypedPublicKey};

    #[test]
    fn test_address_from_pk() {
        let ed25519_pk = TypedPublicKey::Ed25519(
            Ed25519PublicKey::from_slice(
                &hex::decode("D2328EF9F0CA3E165912EE0CFEA3F3CD7B99D56E038EB1144426741371FF10E2")
                    .unwrap(),
            )
            .unwrap(),
        );
        let coin_info = CoinInfo {
            coin: "SUI".to_string(),
            derivation_path: "".to_string(),
            curve: CurveType::ED25519,
            network: "TESTNET".to_string(),
            seg_wit: "".to_string(),
        };
        let addr1 = AptosAddress::from_public_key(&ed25519_pk, &coin_info).unwrap();
        assert_eq!(
            addr1,
            "0xe4f2b6319b3f872b854aba308c616f832111f77d08598cd3c06deaf072ba0a6b"
        );
    }

    #[test]
    fn test_address_valid() {
        let coin_info = CoinInfo {
            coin: "APTOS".to_string(),
            derivation_path: "".to_string(),
            curve: CurveType::ED25519,
            network: "TESTNET".to_string(),
            seg_wit: "".to_string(),
        };
        assert!(AptosAddress::is_valid(
            "0xe4f2b6319b3f872b854aba308c616f832111f77d08598cd3c06deaf072ba0a6b",
            &coin_info
        ));
    }
}
