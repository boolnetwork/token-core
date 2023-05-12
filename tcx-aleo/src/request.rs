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
use wasm_bindgen::JsValue;

#[wasm_bindgen]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct AleoProgramRequest {
    program_id: String,
    function_name: String,
    /// json of Vec<String>
    inputs: String,
    query: String,
}

#[wasm_bindgen]
impl AleoProgramRequest {
    #[wasm_bindgen(constructor)]
    pub fn new(program_id: String, function_name: String, inputs: String, query: String) -> Self {
        AleoProgramRequest {
            program_id,
            function_name,
            inputs,
            query,
        }
    }

    #[wasm_bindgen(getter)]
    pub fn program_id(&self) -> String {
        self.program_id.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn function_name(&self) -> String {
        self.function_name.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn inputs(&self) -> String {
        self.inputs.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn query(&self) -> String {
        self.query.clone()
    }

    #[wasm_bindgen(setter)]
    pub fn set_program_id(&mut self, program_id: String) {
        self.program_id = program_id
    }

    #[wasm_bindgen(setter)]
    pub fn set_function_name(&mut self, function_name: String) {
        self.function_name = function_name
    }

    #[wasm_bindgen(setter)]
    pub fn set_inputs(&mut self, inputs: String) {
        self.inputs = inputs
    }

    #[wasm_bindgen(setter)]
    pub fn set_query(&mut self, query: String) {
        self.query = query
    }
}

impl AleoProgramRequest {
    pub(crate) fn inputs_raw(&self) -> Result<Vec<Value<CurrentNetwork>>> {
        let inputs_s = serde_json::from_str::<Vec<String>>(&self.inputs.clone())?;
        let mut inputs = Vec::with_capacity(inputs_s.len());
        for (index, input) in inputs_s.into_iter().enumerate() {
            let value = Value::<CurrentNetwork>::from_str(&input).map_err(|e| {
                InvalidAleoRequest(format!(
                    "Failed to convert to Value of aleo #{index} for '{}/{}: {e}'",
                    self.program_id, self.function_name
                ))
            })?;
            inputs.push(value)
        }
        Ok(inputs)
    }

    pub(crate) async fn sign(
        &self,
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
            "{}/{CURRENT_NETWORK_WORDS}/program/{}",
            self.query, self.program_id
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
        let inputs = self.inputs_raw()?;

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
    use crate::request::AleoProgramRequest;
    use crate::Error::CustomError;
    use crate::{utils, CurrentNetwork};
    use snarkvm_console::program::{Plaintext, Record};
    use snarkvm_synthesizer::Program;
    use std::str::FromStr;
    use wasm_bindgen::JsValue;

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn test_query_program() {
        let response =
            utils::query_get("https://vm.aleo.org/api/testnet3/program/credits.aleo".to_string())
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
        assert_eq!("credits.aleo", program.id().to_string())
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn test_sign() {
        let (private_key, _view_key, address) = utils::helpers::generate_account().unwrap();

        let query = "https://vm.aleo.org/api".to_string();
        let inputs = vec![address.address(), "10000u64".to_string()];
        let aleo_program_request = AleoProgramRequest {
            program_id: "credits.aleo".to_string(),
            function_name: "mint".to_string(),
            inputs: serde_json::to_string(&inputs).unwrap(),
            query,
        };

        let req = aleo_program_request.sign(&private_key).await.unwrap();
        println!("{}", req);
        assert_eq!(req.inputs().len(), inputs.len())
    }

    #[test]
    fn test_serde() {
        let (_private_key, _view_key, address) = utils::helpers::generate_account().unwrap();
        let query = "https://vm.aleo.org/api".to_string();
        let aleo_program_request = AleoProgramRequest {
            program_id: "credits.aleo".to_string(),
            function_name: "mint".to_string(),
            inputs: serde_json::to_string(&vec![address.address(), "10000u64".to_string()])
                .unwrap(),
            query: query.clone(),
        };

        let s = serde_json::to_string(&aleo_program_request).unwrap();
        let s_r = serde_json::from_str::<AleoProgramRequest>(&s).unwrap();
        assert_eq!(aleo_program_request, s_r)
    }
}
