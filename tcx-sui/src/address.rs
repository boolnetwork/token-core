use crate::Error;
use sp_core::bytes::to_hex;
use tcx_chain::Address;
use tcx_constants::{CoinInfo, Result};
use tcx_primitive::TypedPublicKey;

pub const DEFAULT_HASH_SIZE: usize = 32;
pub const ED25519_FALG: u8 = 0;
pub const SECP256K1_FALG: u8 = 1;

pub struct SuiAddress();

impl Address for SuiAddress {
    fn from_public_key(public_key: &TypedPublicKey, _coin: &CoinInfo) -> Result<String> {
        let flag = match public_key {
            TypedPublicKey::Ed25519(_) => ED25519_FALG,
            TypedPublicKey::Secp256k1(_) => SECP256K1_FALG,
            _ => return Err(Error::AddressParseError.into()),
        };
        let mut result = [0u8; 32];
        let pk = public_key.to_bytes();
        let mut hasher = blake2b_rs::Blake2bBuilder::new(DEFAULT_HASH_SIZE).build();
        hasher.update(&[flag]);
        hasher.update(&pk);
        hasher.finalize(&mut result);
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
    use crate::SuiAddress;
    use tcx_chain::Address;
    use tcx_constants::{CoinInfo, CurveType};
    use tcx_primitive::{Ed25519PublicKey, PublicKey, Secp256k1PublicKey, TypedPublicKey};

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
        let addr1 = SuiAddress::from_public_key(&ed25519_pk, &coin_info).unwrap();
        assert_eq!(
            addr1,
            "0xb0447f7b8ab617d39560a67481f013d8b37f32d25e675b03dae587881c6798ff"
        );

        let ecdsa_pk = TypedPublicKey::Secp256k1(
            Secp256k1PublicKey::from_slice(
                &hex::decode("02f6e28c1c019a99ed89bb3d0337eb818016c38ff64643053facfb390a89620c76")
                    .unwrap(),
            )
            .unwrap(),
        );
        let coin_info = CoinInfo {
            coin: "SUI".to_string(),
            derivation_path: "".to_string(),
            curve: CurveType::SECP256k1,
            network: "TESTNET".to_string(),
            seg_wit: "".to_string(),
        };
        let addr2 = SuiAddress::from_public_key(&ecdsa_pk, &coin_info).unwrap();
        assert_eq!(
            addr2,
            "0x693d4bf80d67a3b9d7d98f287045bdf4afddf0e9e8d1c165a1aa5c46f70ed3c4"
        );
    }

    #[test]
    fn test_address_valid() {
        let coin_info = CoinInfo {
            coin: "SUI".to_string(),
            derivation_path: "".to_string(),
            curve: CurveType::ED25519,
            network: "TESTNET".to_string(),
            seg_wit: "".to_string(),
        };
        assert!(SuiAddress::is_valid(
            "0xb0447f7b8ab617d39560a67481f013d8b37f32d25e675b03dae587881c6798ff",
            &coin_info
        ));
        assert!(!SuiAddress::is_valid(
            "0xb0447f7b8ab617d39560a67481f013d8b37f32d25e675b03dae587881c6798",
            &coin_info
        ));
    }
}
