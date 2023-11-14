use super::Result;
use crate::ecc::{DeterministicPrivateKey, DeterministicPublicKey, KeyError, PrivateKey};
use crate::{Derive, FromHex, PublicKey, Sm2PrivateKey, Sm2PublicKey, Ss58Codec, ToHex};
use bip39::{Language, Mnemonic};
use bitcoin::util::base58;
use bitcoin::util::base58::Error::InvalidLength;
use bitcoin::util::bip32::{ChainCode, ChildNumber, Error as Bip32Error, Fingerprint};
use bitcoin::XpubIdentifier;
use bitcoin_hashes::{sha512, Hash, HashEngine, Hmac, HmacEngine};
use byteorder::BigEndian;
use byteorder::ByteOrder;
use cita_crypto_trait::CreateKey;
use libsm::sm2::{
    ecc::EccCtx,
    field::{FieldCtx, FieldElem},
};
use std::fmt::Debug;

#[derive(Copy, Clone, Debug)]
pub struct Sm2ExtendedPrivKey {
    /// How many derivations this key is from the master (which is 0)
    pub depth: u8,
    /// Fingerprint of the parent key (0 for master)
    pub parent_fingerprint: Fingerprint,
    /// Child number of the key used to derive from parent (0 for master)
    pub child_number: ChildNumber,
    /// Private key
    pub private_key: Sm2PrivateKey,
    /// Chain code
    pub chain_code: ChainCode,
}

impl Sm2ExtendedPrivKey {
    pub fn derive_priv<P: AsRef<[ChildNumber]>>(&self, path: &P) -> Result<Sm2ExtendedPrivKey> {
        let mut sk: Sm2ExtendedPrivKey = *self;
        for cnum in path.as_ref() {
            sk = sk.ckd_priv(*cnum)?;
        }
        Ok(sk)
    }

    /// Private->Private child key derivation
    pub fn ckd_priv(&self, i: ChildNumber) -> Result<Sm2ExtendedPrivKey> {
        let mut hmac_engine: HmacEngine<sha512::Hash> = HmacEngine::new(&self.chain_code[..]);
        match i {
            ChildNumber::Normal { .. } => {
                // Non-hardened key: compute public data and use that
                let keypair = cita_sm2::KeyPair::from_privkey(self.private_key.0.clone())
                    .map_err(|_| KeyError::InvalidSm2Key)?;
                hmac_engine.input(&keypair.pubkey().0);
            }
            ChildNumber::Hardened { .. } => {
                // Hardened key: use only secret data to prevent public derivation
                hmac_engine.input(&[0u8]);
                hmac_engine.input(&self.private_key.to_bytes());
            }
        }

        hmac_engine.input(&u32::from(i).to_be_bytes());
        let hmac_result: Hmac<sha512::Hash> = Hmac::from_engine(hmac_engine);
        let mut sk =
            Sm2PrivateKey::from_slice(&hmac_result[..32]).map_err(|_| KeyError::InvalidSm2Key)?;
        let scalar = FieldCtx::new().add(
            &FieldElem::from_bytes(&sk.to_bytes()),
            &FieldElem::from_bytes(&self.private_key.to_bytes()),
        );
        sk = Sm2PrivateKey::from_slice(&scalar.to_bytes()).map_err(|_| KeyError::InvalidSm2Key)?;

        Ok(Sm2ExtendedPrivKey {
            depth: self.depth + 1,
            parent_fingerprint: self.fingerprint(),
            child_number: i,
            private_key: sk,
            chain_code: ChainCode::from(&hmac_result[32..]),
        })
    }

    /// Returns the HASH160 of the public key belonging to the xpriv
    pub fn identifier(&self) -> XpubIdentifier {
        Sm2ExtendedPubKey::from_private(self).identifier()
    }

    /// Returns the first four bytes of the identifier
    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::from(&self.identifier()[0..4])
    }
}

#[derive(Copy, Clone, Debug)]
pub struct Sm2ExtendedPubKey {
    /// How many derivations this key is from the master (which is 0)
    pub depth: u8,
    /// Fingerprint of the parent key
    pub parent_fingerprint: Fingerprint,
    /// Child number of the key used to derive from parent (0 for master)
    pub child_number: ChildNumber,
    /// Public key
    pub public_key: Sm2PublicKey,
    /// Chain code
    pub chain_code: ChainCode,
}

impl Sm2ExtendedPubKey {
    pub fn from_private(sk: &Sm2ExtendedPrivKey) -> Sm2ExtendedPubKey {
        Sm2ExtendedPubKey {
            depth: sk.depth,
            parent_fingerprint: sk.parent_fingerprint,
            child_number: sk.child_number,
            public_key: sk.private_key.public_key(),
            chain_code: sk.chain_code,
        }
    }
    pub fn derive_pub<P: AsRef<[ChildNumber]>>(&self, path: &P) -> Result<Sm2ExtendedPubKey> {
        let mut pk: Sm2ExtendedPubKey = *self;
        for cnum in path.as_ref() {
            pk = pk.ckd_pub(*cnum)?
        }
        Ok(pk)
    }

    pub fn ckd_pub_tweak(&self, i: ChildNumber) -> Result<(Sm2PrivateKey, ChainCode)> {
        match i {
            ChildNumber::Hardened { .. } => Err(KeyError::CannotDeriveFromHardenedKey.into()),
            ChildNumber::Normal { index: n } => {
                let mut hmac_engine: HmacEngine<sha512::Hash> =
                    HmacEngine::new(&self.chain_code[..]);
                hmac_engine.input(&self.public_key.to_bytes());
                hmac_engine.input(&n.to_be_bytes());

                let hmac_result: Hmac<sha512::Hash> = Hmac::from_engine(hmac_engine);

                let private_key = Sm2PrivateKey::from_slice(&hmac_result[..32])
                    .map_err(|_| KeyError::InvalidSm2Key)?;
                let chain_code = ChainCode::from(&hmac_result[32..]);
                Ok((private_key, chain_code))
            }
        }
    }

    pub fn ckd_pub(&self, i: ChildNumber) -> Result<Sm2ExtendedPubKey> {
        let (sk, chain_code) = self.ckd_pub_tweak(i)?;
        let curve = EccCtx::new();
        let mut pk_bytes = self.public_key.to_bytes();
        pk_bytes.insert(0, 0x04);
        let point = curve
            .bytes_to_point(&pk_bytes)
            .map_err(|_| KeyError::InvalidSm2Key)?;
        let point1 = curve.mul_raw(
            &FieldElem::from_bytes(&sk.to_bytes()).value,
            &curve.generator(),
        );
        let final_point = curve.add(&point, &point1);
        let pk = Sm2PublicKey::from_slice(&curve.point_to_bytes(&final_point, false)[1..])
            .map_err(|_| KeyError::InvalidSm2Key)?;

        Ok(Sm2ExtendedPubKey {
            depth: self.depth + 1,
            parent_fingerprint: self.fingerprint(),
            child_number: i,
            public_key: pk,
            chain_code,
        })
    }

    pub fn identifier(&self) -> XpubIdentifier {
        let mut engine = XpubIdentifier::engine();
        engine.input(&self.public_key.to_bytes());
        XpubIdentifier::from_engine(engine)
    }

    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::from(&self.identifier()[0..4])
    }
}

pub struct Bip32Sm2DeterministicPrivateKey(Sm2ExtendedPrivKey);

pub struct Bip32Sm2DeterministicPublicKey(Sm2ExtendedPubKey);

impl Bip32Sm2DeterministicPrivateKey {
    /// Construct a new master key from a seed value
    pub fn from_seed(seed: &[u8]) -> Result<Self> {
        let mut hmac_engine: HmacEngine<sha512::Hash> = HmacEngine::new(b"Cita seed");
        hmac_engine.input(seed);
        let hmac_result: Hmac<sha512::Hash> = Hmac::from_engine(hmac_engine);
        Ok(Bip32Sm2DeterministicPrivateKey(Sm2ExtendedPrivKey {
            depth: 0,
            parent_fingerprint: Default::default(),
            child_number: ChildNumber::from_normal_idx(0)?,
            private_key: Sm2PrivateKey::from_slice(&hmac_result[..32])
                .map_err(|_| KeyError::InvalidSm2Key)?,
            chain_code: ChainCode::from(&hmac_result[32..]),
        }))
    }

    pub fn from_mnemonic(mnemonic: &str) -> Result<Self> {
        let mn = Mnemonic::from_phrase(mnemonic, Language::English)?;
        let seed = bip39::Seed::new(&mn, "");
        Bip32Sm2DeterministicPrivateKey::from_seed(seed.as_ref())
    }
}

impl Derive for Bip32Sm2DeterministicPrivateKey {
    fn derive(&self, path: &str) -> Result<Self> {
        let extended_key = self.0.clone();

        let mut parts = path.split('/').peekable();
        if *parts.peek().unwrap() == "m" {
            parts.next();
        }

        let children_nums = parts
            .map(str::parse)
            .collect::<std::result::Result<Vec<ChildNumber>, Bip32Error>>()?;
        let child_key = extended_key.derive_priv(&children_nums)?;

        Ok(Bip32Sm2DeterministicPrivateKey(child_key))
    }
}

impl Derive for Bip32Sm2DeterministicPublicKey {
    fn derive(&self, path: &str) -> Result<Self> {
        let extended_key = self.0.clone();

        let mut parts = path.split('/').peekable();
        if *parts.peek().unwrap() == "m" {
            parts.next();
        }

        let children_nums = parts
            .map(str::parse)
            .collect::<std::result::Result<Vec<ChildNumber>, Bip32Error>>()?;
        let child_key = extended_key.derive_pub(&children_nums)?;

        Ok(Bip32Sm2DeterministicPublicKey(child_key))
    }
}

impl DeterministicPrivateKey for Bip32Sm2DeterministicPrivateKey {
    type DeterministicPublicKey = Bip32Sm2DeterministicPublicKey;
    type PrivateKey = Sm2PrivateKey;

    fn from_seed(seed: &[u8]) -> Result<Self> {
        Bip32Sm2DeterministicPrivateKey::from_seed(seed)
    }

    fn from_mnemonic(mnemonic: &str) -> Result<Self> {
        Bip32Sm2DeterministicPrivateKey::from_mnemonic(mnemonic)
    }

    fn private_key(&self) -> Self::PrivateKey {
        self.0.private_key.clone()
    }

    fn deterministic_public_key(&self) -> Self::DeterministicPublicKey {
        let pk = Sm2ExtendedPubKey::from_private(&self.0);
        Bip32Sm2DeterministicPublicKey(pk)
    }
}

impl DeterministicPublicKey for Bip32Sm2DeterministicPublicKey {
    type PublicKey = Sm2PublicKey;

    fn public_key(&self) -> Self::PublicKey {
        self.0.public_key.clone()
    }
}

impl std::fmt::Display for Bip32Sm2DeterministicPublicKey {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        self.0.fmt(f)
    }
}

impl ToHex for Bip32Sm2DeterministicPublicKey {
    fn to_hex(&self) -> String {
        let mut ret = [0; 105];
        let extended_key = self.0;
        ret[0] = extended_key.depth as u8;
        ret[1..5].copy_from_slice(&extended_key.parent_fingerprint[..]);

        BigEndian::write_u32(&mut ret[5..9], u32::from(extended_key.child_number));

        ret[9..41].copy_from_slice(&extended_key.chain_code[..]);
        ret[41..105].copy_from_slice(&extended_key.public_key.to_bytes());
        hex::encode(ret.to_vec())
    }
}

impl FromHex for Bip32Sm2DeterministicPublicKey {
    fn from_hex(hex: &str) -> Result<Self> {
        let data = hex::decode(hex)?;

        if data.len() != 105 {
            return Err(KeyError::InvalidBase58.into());
        }
        let cn_int: u32 = BigEndian::read_u32(&data[5..9]);
        let child_number: ChildNumber = ChildNumber::from(cn_int);

        let epk = Sm2ExtendedPubKey {
            depth: data[0],
            parent_fingerprint: Fingerprint::from(&data[1..5]),
            child_number,
            chain_code: ChainCode::from(&data[9..41]),
            public_key: Sm2PublicKey::from_slice(&data[41..105])
                .map_err(|_| KeyError::InvalidSm2Key)?,
        };
        Ok(Bip32Sm2DeterministicPublicKey(epk))
    }
}

impl Ss58Codec for Bip32Sm2DeterministicPublicKey {
    fn from_ss58check_with_version(s: &str) -> Result<(Self, Vec<u8>)> {
        let data = base58::from_check(s)?;

        if data.len() != 109 {
            return Err(KeyError::InvalidBase58.into());
        }
        let cn_int: u32 = BigEndian::read_u32(&data[9..13]);
        let child_number: ChildNumber = ChildNumber::from(cn_int);

        let epk = Sm2ExtendedPubKey {
            depth: data[4],
            parent_fingerprint: Fingerprint::from(&data[5..9]),
            child_number,
            chain_code: ChainCode::from(&data[13..45]),
            public_key: Sm2PublicKey::from_slice(&data[45..109])
                .map_err(|_| KeyError::InvalidSm2Key)?,
        };

        let mut network = [0; 4];
        network.copy_from_slice(&data[0..4]);
        Ok((Bip32Sm2DeterministicPublicKey(epk), network.to_vec()))
    }

    fn to_ss58check_with_version(&self, version: &[u8]) -> String {
        let mut ret = [0; 109];
        let extended_key = self.0;
        ret[0..4].copy_from_slice(&version[..]);
        ret[4] = extended_key.depth as u8;
        ret[5..9].copy_from_slice(&extended_key.parent_fingerprint[..]);

        BigEndian::write_u32(&mut ret[9..13], u32::from(extended_key.child_number));

        ret[13..45].copy_from_slice(&extended_key.chain_code[..]);
        ret[45..109].copy_from_slice(&extended_key.public_key.to_bytes());
        base58::check_encode_slice(&ret[..])
    }
}

impl Ss58Codec for Bip32Sm2DeterministicPrivateKey {
    fn from_ss58check_with_version(s: &str) -> Result<(Self, Vec<u8>)> {
        let data = base58::from_check(s)?;

        if data.len() != 78 {
            return Err(InvalidLength(data.len()).into());
        }

        let cn_int: u32 = BigEndian::read_u32(&data[9..13]);
        let child_number: ChildNumber = ChildNumber::from(cn_int);

        let epk = Sm2ExtendedPrivKey {
            depth: data[4],
            parent_fingerprint: Fingerprint::from(&data[5..9]),
            child_number,
            chain_code: ChainCode::from(&data[13..45]),
            private_key: Sm2PrivateKey::from_slice(&data[46..78])
                .map_err(|_| KeyError::InvalidSm2Key)?,
        };
        let mut network = [0; 4];
        network.copy_from_slice(&data[0..4]);
        Ok((Bip32Sm2DeterministicPrivateKey(epk), network.to_vec()))
    }

    fn to_ss58check_with_version(&self, version: &[u8]) -> String {
        let mut ret = [0; 78];
        let extended_key = &self.0;

        ret[0..4].copy_from_slice(&version[..]);
        ret[4] = extended_key.depth;
        ret[5..9].copy_from_slice(&extended_key.parent_fingerprint[..]);

        BigEndian::write_u32(&mut ret[9..13], u32::from(extended_key.child_number));

        ret[13..45].copy_from_slice(&extended_key.chain_code[..]);
        ret[45] = 0;
        ret[46..78].copy_from_slice(&extended_key.private_key.to_bytes());
        base58::check_encode_slice(&ret[..])
    }
}

#[cfg(test)]
mod tests {
    use crate::PublicKey;
    use crate::{Bip32Sm2DeterministicPrivateKey, Derive, DeterministicPrivateKey, PrivateKey};
    use bip39::{Language, Mnemonic, Seed};

    fn default_seed() -> Seed {
        let mn = Mnemonic::from_phrase(
            "inject kidney empty canal shadow pact comfort wife crush horse wife sketch",
            Language::English,
        )
        .unwrap();
        Seed::new(&mn, "")
    }

    #[test]
    fn derive_public_sm2_keys() {
        let seed = default_seed();
        let paths = vec![
            "m/44'/0'/0'/0/0",
            "m/44'/0'/0'/0/1",
            "m/44'/0'/0'/1/0",
            "m/44'/0'/0'/1/1",
        ];
        let esk = Bip32Sm2DeterministicPrivateKey::from_seed(seed.as_bytes()).unwrap();
        let pub_keys = paths
            .iter()
            .map(|path| {
                hex::encode(
                    esk.derive(path)
                        .unwrap()
                        .private_key()
                        .public_key()
                        .to_bytes(),
                )
            })
            .collect::<Vec<String>>();
        let expected_pub_keys = vec![
            "ef7f4d9fa39d197efaacab722dd35397940b70e40a0777dfcd5baf1e33359043cc41a6e86f513a92fad74167513ebfb7096c27e3521aac748226debdd1e86894",
            "244f34c99b9f9c8adcef24ecab8f4c5c628033162f2e8318c5bd147bc9017341621ee552c678177d0b926661046f0d3aa64e590cd06d0664d046ffc44e342c31",
            "d34e0bd95305d14d196d365a85274a8c0525a6f31d7a18ba6ab7452099e1f8649cd6b38a4934215de7628cf10bc2a508dcf80dcec99090f38c7cd1d2ad4d7069",
            "8423426816c06421a44393ddc6852d48d3d2f16f941e9b836e21025f7e509978977ff19d2fed8ade27becae2aae3d98c6257e29638bbea421a11f12a96d5edea",
        ];
        assert_eq!(pub_keys, expected_pub_keys);
    }
}
