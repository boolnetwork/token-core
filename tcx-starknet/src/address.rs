use starknet_core::crypto::compute_hash_on_elements;
use starknet_core::types::FieldElement;
use std::str::FromStr;
use tcx_chain::{Address, Result};
use tcx_constants::CoinInfo;
use tcx_primitive::TypedPublicKey;

const ADDR_BOUND: FieldElement = FieldElement::from_mont([
    18446743986131443745,
    160989183,
    18446744073709255680,
    576459263475590224,
]);

/// Cairo string for "STARKNET_CONTRACT_ADDRESS"
const PREFIX_CONTRACT_ADDRESS: FieldElement = FieldElement::from_mont([
    3829237882463328880,
    17289941567720117366,
    8635008616843941496,
    533439743893157637,
]);

const SELECTOR_INITIALIZE: FieldElement = FieldElement::from_mont([
    14382173896205878522,
    7380089477680411368,
    4404362358337226556,
    132905214994424316,
]);

fn account_contract_class_hash() -> FieldElement {
    FieldElement::from_str("0x025ec026985a3bf9d0cc1fe17326b245dfdc3ff89b8fde106542a3ea56c5a918")
        .unwrap()
}

fn account_contract_impl_hash() -> FieldElement {
    FieldElement::from_str("0x033434ad846cdd5f23eb73ff09fe6fddd568284a0fb7d1be20ee482f044dabe2")
        .unwrap()
}

// // TODO: Salt constant
// fn account_contract_salt() -> FieldElement {
//     FieldElement::from_str("0x3a4dcd2cf32025819059d8b6c6506274b0c1aa1ee38c96e026d33daecd85443").unwrap()
// }

pub struct StarknetAddress;

impl Address for StarknetAddress {
    fn from_public_key(public_key: &TypedPublicKey, _coin: &CoinInfo) -> Result<String> {
        let pk = FieldElement::from_byte_slice_be(&public_key.to_bytes())?;
        let addr = compute_hash_on_elements(&[
            PREFIX_CONTRACT_ADDRESS,
            FieldElement::ZERO,
            // salt
            pk,
            // class hash
            account_contract_class_hash(),
            // call_data: open_zeppelin([pk]) or argent([impl_class_hash, SELECTOR_INITIALIZE, FieldElement::TWO, pk, guardian_public_key
            compute_hash_on_elements(&[
                account_contract_impl_hash(),
                SELECTOR_INITIALIZE,
                FieldElement::TWO,
                pk,
                FieldElement::ZERO,
            ]),
        ]) % ADDR_BOUND;

        Ok("0x".to_string() + &hex::encode(&addr.to_bytes_be()))
    }

    fn is_valid(address: &str, _coin: &CoinInfo) -> bool {
        if let Err(_) = FieldElement::from_str(address) {
            return false;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use crate::address::StarknetAddress;
    use tcx_chain::Address;
    use tcx_constants::{CoinInfo, CurveType};
    use tcx_primitive::{PublicKey, StarknetPublicKey, TypedPublicKey};

    #[test]
    fn test_address_from_pk() {
        let pk = TypedPublicKey::Starknet(
            StarknetPublicKey::from_slice(
                &hex::decode("032d5d80285b9a8079c136f2e98676699f339f65eb04fa79112a313580cf2e54")
                    .unwrap(),
            )
            .unwrap(),
        );
        let coin_info = CoinInfo {
            coin: "STARKNET".to_string(),
            derivation_path: "".to_string(),
            curve: CurveType::StarknetCurve,
            network: "TESTNET".to_string(),
            seg_wit: "".to_string(),
        };
        let addr1 = StarknetAddress::from_public_key(&pk, &coin_info).unwrap();
        assert_eq!(
            addr1,
            "0x0133f10fa30f0b6a98a82d514db2b970db0b43e2bd120a76a17911d58bcd01ff"
        );
    }

    #[test]
    fn test_address_is_valid() {
        let coin_info = CoinInfo {
            coin: "STARKNET".to_string(),
            derivation_path: "".to_string(),
            curve: CurveType::StarknetCurve,
            network: "TESTNET".to_string(),
            seg_wit: "".to_string(),
        };
        assert_eq!(
            StarknetAddress::is_valid(
                "0x0133f10fa30f0b6a98a82d514db2b970db0b43e2bd120a76a17911d58bcd01ff",
                &coin_info
            ),
            true
        );
        assert_eq!(
            StarknetAddress::is_valid(
                "0x0133f10fa30f0b6a98a82d514db2b970db0b43e2bd120a76a17911d58bcd01ff01",
                &coin_info
            ),
            false
        );
    }
}
