use crate::privatekey::AleoPrivateKey;
use crate::utils;
use crate::Error::{CustomError, InvalidAleoRequest};
use serde::{Deserialize, Serialize};
use snarkvm_console::network::Network;
use snarkvm_console::program::{Identifier, Plaintext, ProgramID, Record, Request, Value};
use snarkvm_synthesizer::Program;
use std::marker::PhantomData;
use std::str::FromStr;
use tcx_constants::Result;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct AleoRequest<N: Network> {
    /// program request
    pub request: AleoProgramRequest<N>,
    /// fee request, record and fee_in_microcredits
    pub fee: Option<AleoProgramRequest<N>>,
    /// The endpoint to query node state from
    pub query: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct AleoProgramRequest<N: Network> {
    pub program_id: String,
    pub function_name: String,
    pub inputs: Vec<String>,
    _phantom: PhantomData<N>,
}

impl<N: Network> AleoProgramRequest<N> {
    pub async fn sign(&self, query: String, private_key: AleoPrivateKey<N>) -> Result<Request<N>> {
        let rng = &mut rand::thread_rng();

        // get program_id
        let program_id = ProgramID::<N>::try_from(&self.program_id)
            .map_err(|e| InvalidAleoRequest(e.to_string()))?;

        // get program function_name
        let function_name = Identifier::<N>::from_str(&self.function_name)
            .map_err(|e| InvalidAleoRequest(e.to_string()))?;

        // request node to get program info
        let response =
            utils::query_get(format!("{}/testnet3/program/{}", query, self.program_id)).await?;
        let text = response
            .text()
            .await
            .map_err(|e| InvalidAleoRequest(e.to_string()))?;
        let program = serde_json::from_str::<Program<N>>(&text)
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
            let value = Value::<N>::from_str(&input).map_err(|e| {
                InvalidAleoRequest(format!(
                    "Failed to parse input #{index} for '{program_id}/{function_name}: {e}'"
                ))
            })?;
            inputs.push(value)
        }

        let request = Request::sign(
            &private_key.0,
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

#[cfg(test)]
mod tests {
    use crate::privatekey::AleoPrivateKey;
    use crate::request::AleoProgramRequest;
    use crate::Error::CustomError;
    use crate::{utils, CurrentNetwork};
    use snarkvm_console::account::Address;
    use snarkvm_console::program::Value;
    use snarkvm_synthesizer::Program;
    use std::marker::PhantomData;
    use std::str::FromStr;

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

    #[tokio::test]
    async fn test_sign() {
        let rng = &mut rand::thread_rng();
        let ask = AleoPrivateKey::<CurrentNetwork>::new(rng).unwrap();
        let query = "https://vm.aleo.org/api".to_string();
        let aleo_program_request = AleoProgramRequest {
            program_id: "credits.aleo".to_string(),
            function_name: "mint".to_string(),
            inputs: vec![
                Address::<CurrentNetwork>::try_from(&ask.0)
                    .unwrap()
                    .to_string(),
                "10000u64".to_string(),
            ],
            _phantom: PhantomData,
        };

        let req = aleo_program_request.sign(query, ask).await.unwrap();
        println!("{}", req)
    }
}
