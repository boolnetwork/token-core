#![allow(deprecated)]
use crate::ecc::{KeyError, PrivateKey as TraitPrivateKey, PublicKey as TraitPublicKey};
use crate::{FromHex, Result, ToHex};
use cita_crypto_trait::{CreateKey, Sign};
use cita_sm2::{KeyPair, Message, PrivKey, PubKey, Signature};

#[derive(Clone)]
pub struct Sm2PublicKey(pub PubKey);

#[derive(Clone)]
pub struct Sm2PrivateKey(pub PrivKey);

impl From<PubKey> for Sm2PublicKey {
    fn from(pk: PubKey) -> Self {
        Sm2PublicKey(pk)
    }
}

impl From<PrivKey> for Sm2PrivateKey {
    fn from(sk: PrivKey) -> Self {
        Sm2PrivateKey(sk)
    }
}

impl TraitPrivateKey for Sm2PrivateKey {
    type PublicKey = Sm2PublicKey;

    fn from_slice(data: &[u8]) -> Result<Self> {
        if data.len() != 32 {
            return Err(KeyError::InvalidSm2Key.into());
        }
        Ok(Sm2PrivateKey(PrivKey::from_slice(&data)))
    }

    fn public_key(&self) -> Self::PublicKey {
        let keypair = KeyPair::from_privkey(self.0.clone()).unwrap();
        Sm2PublicKey(keypair.pubkey().clone())
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() != 32 {
            return Err(KeyError::InvalidMessage.into());
        }
        let signature = Signature::sign(&self.0, &Message::from_slice(data))
            .map_err(|_| KeyError::InvalidRecoveryId)?;
        Ok(signature.as_slice().to_vec())
    }

    fn sign_recoverable(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.sign(data)
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl std::fmt::Display for Sm2PublicKey {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        self.0.fmt(f)
    }
}

impl TraitPublicKey for Sm2PublicKey {
    fn from_slice(data: &[u8]) -> Result<Self> {
        Ok(Sm2PublicKey(PubKey::from_slice(data)))
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl ToHex for Sm2PublicKey {
    fn to_hex(&self) -> String {
        hex::encode(self.0.to_vec())
    }
}

impl FromHex for Sm2PublicKey {
    fn from_hex(hex: &str) -> Result<Self> {
        let bytes = hex::decode(hex)?;
        let pk = Sm2PublicKey::from_slice(bytes.as_slice())?;
        Ok(pk)
    }
}
