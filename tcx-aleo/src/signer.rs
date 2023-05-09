use crate::privatekey::AleoPrivateKey;
use crate::request::AleoRequest;
use crate::Error::CustomError;
use snarkvm_console::account::{CryptoRng, Field, Rng, Signature};
use snarkvm_console::network::Network;
use snarkvm_console::program::Request;
use tcx_constants::Result;

impl<N: Network> AleoPrivateKey<N> {
    /// Returns a singed program request and a signed fee request if it has
    pub async fn sign_request(
        &self,
        aleo_request: AleoRequest<N>,
    ) -> Result<(Request<N>, Option<Request<N>>)> {
        aleo_request.sign(self).await
    }

    /// Returns a signature for the given message (as field elements) using the private key.
    pub fn sign<R: Rng + CryptoRng>(
        &self,
        message: &[Field<N>],
        rng: &mut R,
    ) -> Result<Signature<N>> {
        Signature::sign(&self.0, message, rng)
            .map_err(|e| failure::Error::from(CustomError(e.to_string())))
    }

    /// Returns a signature for the given message (as bytes) using the private key.
    pub fn sign_bytes<R: Rng + CryptoRng>(
        &self,
        message: &[u8],
        rng: &mut R,
    ) -> Result<Signature<N>> {
        Signature::sign_bytes(&self.0, message, rng)
            .map_err(|e| failure::Error::from(CustomError(e.to_string())))
    }

    /// Returns a signature for the given message (as bits) using the private key.
    pub fn sign_bits<R: Rng + CryptoRng>(
        &self,
        message: &[bool],
        rng: &mut R,
    ) -> Result<Signature<N>> {
        Signature::sign_bits(&self.0, message, rng)
            .map_err(|e| failure::Error::from(CustomError(e.to_string())))
    }
}

#[cfg(test)]
mod tests {
    use crate::address::AleoAddress;
    use crate::privatekey::AleoPrivateKey;
    use crate::request::{AleoProgramRequest, AleoRequest};
    use crate::CurrentNetwork;
    use snarkvm_console::program::{Plaintext, Record};
    use std::str::FromStr;

    #[tokio::test]
    async fn test_sign_request() {
        let rng = &mut rand::thread_rng();
        let ask = AleoPrivateKey::<CurrentNetwork>::new(rng).unwrap();
        let query = "https://vm.aleo.org/api".to_string();
        let addr = AleoAddress::<CurrentNetwork>::from_private_key(&ask).unwrap();

        let aleo_program_request = AleoProgramRequest::<CurrentNetwork>::new(
            "credits.aleo".to_string(),
            "mint".to_string(),
            vec![addr.to_string(), "10000u64".to_string()],
        );

        let fee_record = Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::from_str(&format!(
            "{{
  owner: {}.private,
  microcredits: 50000000u64.private,
  _nonce: 6284621587203125875149547889323796299059507753986233073895647656902474803214group.public
}}",
            addr.to_string()
        ))
        .unwrap();

        let fee_request = AleoProgramRequest::<CurrentNetwork>::new(
            "credits.aleo".to_string(),
            "fee".to_string(),
            vec![fee_record.to_string(), "1000u64".to_string()],
        );

        let aleo_request_no_fee = AleoRequest {
            request: aleo_program_request.clone(),
            fee: None,
            query: query.clone(),
        };

        let (program_signed_1, no_fee_signed) =
            ask.sign_request(aleo_request_no_fee).await.unwrap();
        assert!(no_fee_signed.is_none());
        assert_eq!(
            program_signed_1.program_id().to_string(),
            aleo_program_request.program_id
        );
        assert_eq!(
            program_signed_1.inputs().len(),
            aleo_program_request.inputs.len()
        );
        assert_eq!(
            program_signed_1.function_name().to_string(),
            aleo_program_request.function_name
        );

        let aleo_request_fee = AleoRequest {
            request: aleo_program_request.clone(),
            fee: Some(fee_request.clone()),
            query,
        };
        let (program_signed_2, fee_signed) = ask.sign_request(aleo_request_fee).await.unwrap();
        assert!(fee_signed.is_some());
        assert_eq!(
            program_signed_2.program_id().to_string(),
            aleo_program_request.program_id
        );
        assert_eq!(
            program_signed_2.inputs().len(),
            aleo_program_request.inputs.len()
        );
        assert_eq!(
            program_signed_2.function_name().to_string(),
            aleo_program_request.function_name
        );
        let fee_signed = fee_signed.unwrap();
        assert_eq!(fee_signed.program_id().to_string(), fee_request.program_id);
        assert_eq!(fee_signed.inputs().len(), fee_request.inputs.len());
        assert_eq!(
            fee_signed.function_name().to_string(),
            fee_request.function_name
        );
    }
}
