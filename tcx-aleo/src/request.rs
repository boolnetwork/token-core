use crate::privatekey::AleoPrivateKey;
use crate::Error::InvalidAleoRequest;
use crate::{utils, CurrentNetwork, CURRENT_NETWORK_WORDS};
use serde::{ser, Deserialize, Serialize};
use snarkvm_console::program::{Identifier, ProgramID, Request, Value};
use snarkvm_synthesizer::Program;
use std::fmt::{Display, Formatter};
use std::str;
use std::str::FromStr;
use tcx_constants::Result;
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(bound = "")]
pub struct AleoRequest {
    /// program request
    request: String,
    /// fee request, record and fee_in_microcredits
    fee: Option<String>,
    /// The endpoint to query node state from
    query: String,
}

#[wasm_bindgen]
impl AleoRequest {
    #[wasm_bindgen(constructor)]
    pub fn new(request: String, fee: Option<String>, query: String) -> AleoRequest {
        AleoRequest {
            request,
            fee,
            query,
        }
    }

    #[wasm_bindgen(getter)]
    pub fn request(&self) -> String {
        self.request.clone()
    }

    #[wasm_bindgen(setter)]
    pub fn set_request(&mut self, request: String) {
        self.request = request
    }

    #[wasm_bindgen(getter)]
    pub fn fee(&self) -> Option<String> {
        self.fee.clone()
    }

    #[wasm_bindgen(setter)]
    pub fn set_fee(&mut self, fee: Option<String>) {
        self.fee = fee
    }

    #[wasm_bindgen(getter)]
    pub fn query(&self) -> String {
        self.query.clone()
    }

    #[wasm_bindgen(setter)]
    pub fn set_query(&mut self, query: String) {
        self.query = query
    }
}

impl AleoRequest {
    pub(crate) async fn sign(
        &self,
        private_key: &AleoPrivateKey,
    ) -> Result<(Request<CurrentNetwork>, Option<Request<CurrentNetwork>>)> {
        let program_request = serde_json::from_str::<AleoProgramRequest>(&self.request)
            .map_err(|e| InvalidAleoRequest(e.to_string()))?;

        let request = program_request
            .sign(self.query.clone(), private_key)
            .await?;
        if let Some(fee) = &self.fee {
            let fee = serde_json::from_str::<AleoProgramRequest>(&fee)
                .map_err(|e| InvalidAleoRequest(e.to_string()))?;
            let fee_request = fee.sign(self.query.clone(), private_key).await?;
            Ok((request, Some(fee_request)))
        } else {
            Ok((request, None))
        }
    }
}

impl Display for AleoRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            serde_json::to_string(self).map_err::<std::fmt::Error, _>(ser::Error::custom)?
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(bound = "")]
pub(crate) struct AleoProgramRequest {
    pub program_id: String,
    pub function_name: String,
    pub inputs: Vec<String>,
}

impl AleoProgramRequest {
    pub(crate) fn new(program_id: String, function_name: String, inputs: Vec<String>) -> Self {
        AleoProgramRequest {
            program_id,
            function_name,
            inputs,
        }
    }

    async fn sign(
        &self,
        query: String,
        private_key: &AleoPrivateKey,
    ) -> Result<Request<CurrentNetwork>> {
        let rng = &mut rand::thread_rng();

        // get program_id
        let program_id = ProgramID::<CurrentNetwork>::try_from(&self.program_id)
            .map_err(|e| InvalidAleoRequest(e.to_string()))?;

        // get program function_name
        let function_name = Identifier::<CurrentNetwork>::from_str(&self.function_name)
            .map_err(|e| InvalidAleoRequest(e.to_string()))?;

        // request node to get program info
        let response = utils::query_get(format!(
            "{query}/{CURRENT_NETWORK_WORDS}/program/{}",
            self.program_id
        ))
        .await?;
        let text = response
            .text()
            .await
            .map_err(|e| InvalidAleoRequest(e.to_string()))?;
        let program = serde_json::from_str::<Program<CurrentNetwork>>(&text)
            .map_err(|e| InvalidAleoRequest(e.to_string()))?;
        // Retrieve the function.
        let function = program
            .get_function(&function_name)
            .map_err(|e| InvalidAleoRequest(e.to_string()))?;
        // Retrieve the input types.
        let input_types = function.input_types();
        // Ensure the number of inputs matches the number of input types.
        if function.inputs().len() != input_types.len() {
            return Err(failure::Error::from(InvalidAleoRequest(
                format!("Function '{function_name}' in program '{}' expects {} inputs, but {} types were found.",
                        self.program_id,
                        function.inputs().len(),
                        input_types.len())
            )));
        };

        // Prepare the inputs.
        let mut inputs = Vec::with_capacity(self.inputs.len());
        let req_inputs = self.inputs.clone();
        for (index, input) in req_inputs.into_iter().enumerate() {
            let value = Value::<CurrentNetwork>::from_str(&input).map_err(|e| {
                InvalidAleoRequest(format!(
                    "Failed to parse input #{index} for '{program_id}/{function_name}: {e}'"
                ))
            })?;
            inputs.push(value)
        }

        let request = Request::sign(
            &private_key.raw()?,
            program_id,
            function_name,
            inputs.iter(),
            &input_types,
            rng,
        )
        .map_err(|e| InvalidAleoRequest(e.to_string()))?;
        Ok(request)
    }
}

impl Display for AleoProgramRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            serde_json::to_string(self).map_err::<std::fmt::Error, _>(ser::Error::custom)?
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::request::{AleoProgramRequest, AleoRequest};
    use crate::Error::CustomError;
    use crate::{utils, CurrentNetwork};
    use snarkvm_console::program::{Plaintext, Record};
    use snarkvm_synthesizer::Program;
    use std::str::FromStr;

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn test_query_program() {
        let response =
            utils::query_get("https://vm.aleo.org/api/testnet3/program/OldDuck.aleo".to_string())
                .await
                .unwrap();
        let text = response
            .text()
            .await
            .map_err(|e| CustomError(e.to_string()))
            .unwrap();
        let program = serde_json::from_str::<Program<CurrentNetwork>>(&text)
            .map_err(|e| CustomError(e.to_string()))
            .unwrap();
        assert_eq!("OldDuck.aleo", program.id().to_string())
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn test_sign() {
        let (private_key, _view_key, address) = utils::helpers::generate_account().unwrap();

        let query = "https://vm.aleo.org/api".to_string();
        let aleo_program_request = AleoProgramRequest {
            program_id: "credits.aleo".to_string(),
            function_name: "mint".to_string(),
            inputs: vec![address.address(), "10000u64".to_string()],
        };

        let req = aleo_program_request
            .sign(query, &private_key)
            .await
            .unwrap();
        println!("{}", req);
        assert_eq!(req.inputs().len(), aleo_program_request.inputs.len())
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn test_aleo_req_sign() {
        let (private_key, _view_key, address) = utils::helpers::generate_account().unwrap();

        let query = "https://vm.aleo.org/api".to_string();
        let aleo_program_request = AleoProgramRequest {
            program_id: "credits.aleo".to_string(),
            function_name: "mint".to_string(),
            inputs: vec![address.address(), "10000u64".to_string()],
        };

        let fee_record = Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::from_str(&format!(
            "{{
  owner: {}.private,
  microcredits: 50000000u64.private,
  _nonce: 6284621587203125875149547889323796299059507753986233073895647656902474803214group.public
}}",
            address.address()
        ))
        .unwrap();

        let fee_request = AleoProgramRequest {
            program_id: "credits.aleo".to_string(),
            function_name: "fee".to_string(),

            inputs: vec![fee_record.to_string(), "1000u64".to_string()],
        };

        let aleo_request = AleoRequest {
            request: aleo_program_request.to_string(),
            fee: Some(fee_request.to_string()),
            query,
        };

        let req = aleo_request.sign(&private_key).await.unwrap();
        println!("{}", req.0);
        println!("{:?}", req.1);
        assert_eq!(req.0.inputs().len(), aleo_program_request.inputs.len());
        assert!(req.1.is_some());
        assert_eq!(req.1.unwrap().inputs().len(), fee_request.inputs.len())
    }

    #[test]
    fn test_serde() {
        let (_private_key, _view_key, address) = utils::helpers::generate_account().unwrap();
        let query = "https://vm.aleo.org/api".to_string();
        let aleo_program_request = AleoProgramRequest {
            program_id: "credits.aleo".to_string(),
            function_name: "mint".to_string(),
            inputs: vec![address.address(), "10000u64".to_string()],
        };

        let fee_record = Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::from_str(&format!(
            "{{
  owner: {}.private,
  microcredits: 50000000u64.private,
  _nonce: 6284621587203125875149547889323796299059507753986233073895647656902474803214group.public
}}",
            address.address()
        ))
        .unwrap();

        let fee_request = AleoProgramRequest {
            program_id: "credits.aleo".to_string(),
            function_name: "fee".to_string(),

            inputs: vec![fee_record.to_string(), "1000u64".to_string()],
        };

        let aleo_request = AleoRequest {
            request: aleo_program_request.to_string(),
            fee: Some(fee_request.to_string()),
            query,
        };

        let s = serde_json::to_string(&aleo_request).unwrap();
        let s_r = serde_json::from_str::<AleoRequest>(&s).unwrap();
        assert_eq!(aleo_request, s_r)
    }
}
