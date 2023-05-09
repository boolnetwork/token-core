use crate::ecc::{PrivateKey as TraitPrivateKey, PublicKey as TraitPublicKey};
use crate::Result;
use starknet_crypto::FieldElement;
use starknet_signers::SigningKey;

#[derive(Clone)]
pub struct StarknetPublicKey(pub FieldElement);

#[derive(Clone)]
pub struct StarknetPrivateKey(pub SigningKey);

impl From<FieldElement> for StarknetPublicKey {
    fn from(pk: FieldElement) -> Self {
        StarknetPublicKey(pk)
    }
}

impl From<SigningKey> for StarknetPrivateKey {
    fn from(sk: SigningKey) -> Self {
        StarknetPrivateKey(sk)
    }
}

impl TraitPrivateKey for StarknetPrivateKey {
    type PublicKey = StarknetPublicKey;

    fn from_slice(data: &[u8]) -> Result<Self> {
        let sk = FieldElement::from_byte_slice_be(data)?;
        Ok(StarknetPrivateKey(SigningKey::from_secret_scalar(sk)))
    }

    fn public_key(&self) -> Self::PublicKey {
        StarknetPublicKey(self.0.verifying_key().scalar())
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        let msg = FieldElement::from_byte_slice_be(data)?;
        let sign = self.0.sign(&msg)?;
        let mut ser_sign = Vec::new();
        ser_sign.append(&mut sign.r.to_bytes_be().to_vec());
        ser_sign.append(&mut sign.s.to_bytes_be().to_vec());
        Ok(ser_sign)
    }

    fn sign_recoverable(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.sign(data)
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.0.secret_scalar().to_bytes_be().to_vec()
    }
}

impl TraitPublicKey for StarknetPublicKey {
    fn from_slice(data: &[u8]) -> Result<Self> {
        Ok(StarknetPublicKey(FieldElement::from_byte_slice_be(data)?))
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes_be().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use crate::{PrivateKey, PublicKey, StarknetPrivateKey, StarknetPublicKey};
    use starknet_crypto::{FieldElement, Signature};
    use starknet_signers::SigningKey;

    #[test]
    fn test_sn_key() {
        let sk1 = StarknetPrivateKey::from_slice(
            &hex::decode(
                "1680276612603002181718147419160781730358142667709908871467878829425628458003",
            )
            .unwrap(),
        )
        .unwrap();

        let sk2 = StarknetPrivateKey::from(SigningKey::from_secret_scalar(
            FieldElement::from_dec_str(
                "1680276612603002181718147419160781730358142667709908871467878829425628458003",
            )
            .unwrap(),
        ));
        assert_eq!(sk1.to_bytes(), sk2.to_bytes());
        assert_eq!(
            sk1.public_key().0,
            StarknetPublicKey::from_slice(
                &hex::decode("032d5d80285b9a8079c136f2e98676699f339f65eb04fa79112a313580cf2e54")
                    .unwrap()
            )
            .unwrap()
            .0
        )
    }

    #[test]
    fn test_sn_key_sign_and_verify() {
        let msg = FieldElement::ONE;
        let sk = StarknetPrivateKey::from_slice(
            &hex::decode(
                "1680276612603002181718147419160781730358142667709908871467878829425628458003",
            )
            .unwrap(),
        )
        .unwrap();
        let sig = sk.sign(&msg.to_bytes_be()).unwrap();
        println!("sig: {:?}", sig);
        let expect_sig = vec![
            5, 18, 188, 14, 235, 129, 6, 237, 9, 120, 179, 22, 213, 14, 156, 143, 18, 79, 200, 6,
            5, 26, 47, 14, 81, 236, 99, 88, 62, 172, 157, 217, 4, 192, 161, 149, 64, 164, 132, 200,
            237, 227, 27, 83, 125, 199, 105, 85, 133, 154, 37, 82, 1, 58, 169, 79, 137, 206, 17,
            165, 138, 164, 3, 97,
        ];
        assert_eq!(sig, expect_sig);
        let pk = sk.0.verifying_key();
        assert_eq!(
            pk.verify(
                &msg,
                &Signature {
                    r: FieldElement::from_byte_slice_be(&sig[..32]).unwrap(),
                    s: FieldElement::from_byte_slice_be(&sig[32..]).unwrap(),
                }
            )
            .unwrap(),
            true
        );
    }
}
