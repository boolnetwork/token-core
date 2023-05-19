use crate::request::AleoProgramRequest;
use crate::CurrentNetwork;
use crate::Error::{CustomError, FeeRecordMissed, InvalidAleoRequest};
use snarkvm_console::program::{Plaintext, Record, Value, U64};
use snarkvm_synthesizer::Execution;
use std::str::FromStr;
use tcx_constants::Result;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsError;

#[wasm_bindgen]
#[derive(Debug)]
pub struct AleoTransfer {
    /// The input record used to craft the transfer.
    input_record: String,
    /// The recipient address.
    recipient: String,
    /// The number of gates to transfer.
    amount: u64,
    fee: Option<u64>,
    /// The record to spend the fee from.
    fee_record: Option<String>,
    query: String,
}

#[wasm_bindgen]
impl AleoTransfer {
    #[wasm_bindgen(constructor)]
    pub fn new(
        input_record: String,
        recipient: String,
        amount: u64,
        fee: Option<u64>,
        fee_record: Option<String>,
        query: String,
    ) -> Self {
        Self {
            input_record,
            recipient,
            amount,
            fee,
            fee_record,
            query,
        }
    }

    #[wasm_bindgen(getter)]
    pub fn input_record(&self) -> String {
        self.input_record.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn recipient(&self) -> String {
        self.recipient.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn amount(&self) -> u64 {
        self.amount
    }

    #[wasm_bindgen(getter)]
    pub fn fee(&self) -> Option<u64> {
        self.fee
    }

    #[wasm_bindgen(getter)]
    pub fn fee_record(&self) -> Option<String> {
        self.fee_record.clone()
    }

    #[wasm_bindgen(setter)]
    pub fn set_input_record(&mut self, input_record: String) {
        self.input_record = input_record
    }

    #[wasm_bindgen(setter)]
    pub fn set_recipient(&mut self, recipient: String) {
        self.recipient = recipient
    }

    #[wasm_bindgen(setter)]
    pub fn set_amount(&mut self, amount: u64) {
        self.amount = amount
    }

    #[wasm_bindgen(setter)]
    pub fn set_fee(&mut self, fee: Option<u64>) {
        self.fee = fee
    }

    #[wasm_bindgen(setter)]
    pub fn set_fee_record(&mut self, fee_record: Option<String>) {
        self.fee_record = fee_record
    }

    pub fn to_program_request(&self) -> std::result::Result<AleoProgramRequest, JsError> {
        self.to_program_request_internal()
            .map_err(|e| JsError::new(&e.to_string()))
    }

    pub fn to_fee_request(
        &self,
        program_execution: String,
    ) -> std::result::Result<AleoProgramRequest, JsError> {
        self.to_fee_request_internal(program_execution)
            .map_err(|e| JsError::new(&e.to_string()))
    }
}

impl AleoTransfer {
    pub fn to_program_request_internal(&self) -> Result<AleoProgramRequest> {
        let program_inputs_record =
            Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::from_str(&self.input_record)
                .map_err(|e| CustomError(e.to_string()))?;
        let program_inputs = serde_json::to_string(&vec![
            Value::<CurrentNetwork>::Record(program_inputs_record).to_string(),
            Value::<CurrentNetwork>::from_str(&format!("{}", self.recipient))
                .map_err(|e| CustomError(e.to_string()))?
                .to_string(),
            Value::<CurrentNetwork>::from_str(&format!("{}u64", self.amount))
                .map_err(|e| CustomError(e.to_string()))?
                .to_string(),
        ])?;

        Ok(AleoProgramRequest::new(
            "credits.aleo".to_string(),
            "transfer".to_string(),
            program_inputs,
            self.query.clone(),
        ))
    }

    pub fn to_fee_request_internal(&self, program_execution: String) -> Result<AleoProgramRequest> {
        let program_execution = Execution::<CurrentNetwork>::from_str(&program_execution)
            .map_err(|e| CustomError(e.to_string()))?;

        let fee = match self.fee {
            None => {
                return Err(failure::Error::from(CustomError(
                    "fee is none,not needed to_fee_request".to_string(),
                )));
            }
            Some(amount) => amount,
        };

        let fee_record = match self.fee_record.clone() {
            None => {
                return Err(failure::Error::from(CustomError(
                    "fee_record is none,not needed to_fee_request".to_string(),
                )));
            }
            Some(record) => record,
        };

        let fee_record = Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::from_str(&fee_record)
            .map_err(|e| CustomError(e.to_string()))?;

        let fee_in_microcredits = program_execution
            .size_in_bytes()
            .map_err(|e| CustomError(e.to_string()))?
            .checked_add(fee)
            .ok_or_else(|| {
                CustomError("Fee overflowed for an execution transaction".to_string())
            })?;

        let fee_inputs = serde_json::to_string(&vec![
            Value::<CurrentNetwork>::Record(fee_record).to_string(),
            Value::<CurrentNetwork>::from_str(&format!(
                "{}",
                U64::<CurrentNetwork>::new(fee_in_microcredits)
            ))
            .map_err(|e| CustomError(e.to_string()))?
            .to_string(),
        ])?;
        Ok(AleoProgramRequest::new(
            "credits.aleo".to_string(),
            "fee".to_string(),
            fee_inputs,
            self.query.clone(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use crate::request::AleoProgramRequest;
    use crate::{utils, AleoTransfer, CurrentNetwork};
    use reqwest::Client;
    use serde::{Deserialize, Serialize};
    use serde_json::{json, Value};
    use snarkvm_console::program::{Plaintext, Record, Request};
    use snarkvm_synthesizer::Execution;
    use std::str::FromStr;
    use wasm_bindgen::JsValue;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    const QUERY: &str = "https://vm.aleo.org/api";

    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen_test]
    fn test_transfer_new() {
        let (_private_key_owner, _view_key_owner, address_owner) =
            utils::helpers::generate_account().unwrap();

        let input_record = Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::from_str(&format!(
            "{{
  owner: {}.private,
  microcredits: 50000000u64.private,
  _nonce: 0group.public
}}",
            address_owner.address()
        ))
        .unwrap();

        let fee_record = Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::from_str(&format!(
            "{{
  owner: {}.private,
  microcredits: 10000u64.private,
  _nonce: 0group.public
}}",
            address_owner.address()
        ))
        .unwrap();

        let (_, _, address_recipient) = utils::helpers::generate_account().unwrap();

        let transfer = AleoTransfer::new(
            input_record.to_string(),
            address_recipient.address(),
            1000000,
            Some(200),
            Some(fee_record.to_string()),
            QUERY.to_string(),
        );
        assert_eq!(transfer.input_record(), input_record.to_string());
        assert_eq!(transfer.recipient(), address_recipient.address());
        assert_eq!(transfer.amount(), 1000000);
        assert_eq!(transfer.fee(), Some(200));
        assert_eq!(transfer.fee_record(), Some(fee_record.to_string()));
        console_log!("test_transfer_new: {:?}", transfer)
    }

    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen_test]
    fn test_transfer_set() {
        let (_private_key_owner, _view_key_owner, address_owner) =
            utils::helpers::generate_account().unwrap();

        let input_record = Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::from_str(&format!(
            "{{
      owner: {}.private,
      microcredits: 50000000u64.private,
      _nonce: 0group.public
    }}",
            address_owner.address()
        ))
        .unwrap();

        let fee_record = Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::from_str(&format!(
            "{{
      owner: {}.private,
      microcredits: 10000u64.private,
      _nonce: 0group.public
    }}",
            address_owner.address()
        ))
        .unwrap();

        let (_, _, address_recipient) = utils::helpers::generate_account().unwrap();

        let mut transfer = AleoTransfer::new(
            input_record.to_string(),
            address_recipient.address(),
            1000000,
            Some(200),
            Some(fee_record.to_string()),
            QUERY.to_string(),
        );
        assert_eq!(transfer.input_record(), input_record.to_string());
        assert_eq!(transfer.recipient(), address_recipient.address());
        assert_eq!(transfer.amount(), 1000000);
        assert_eq!(transfer.fee(), Some(200));
        assert_eq!(transfer.fee_record(), Some(fee_record.to_string()));

        let (_private_key_owner, _view_key_owner, address_owner_new) =
            utils::helpers::generate_account().unwrap();

        let input_record_new =
            Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::from_str(&format!(
                "{{
      owner: {}.private,
      microcredits: 10000000u64.private,
      _nonce: 0group.public
    }}",
                address_owner_new.address()
            ))
            .unwrap();

        let fee_record_new =
            Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::from_str(&format!(
                "{{
      owner: {}.private,
      microcredits: 20000u64.private,
      _nonce: 0group.public
    }}",
                address_owner_new.address()
            ))
            .unwrap();

        let (_, _, address_recipient_new) = utils::helpers::generate_account().unwrap();
        transfer.set_fee(Some(100));
        transfer.set_amount(20000000);
        transfer.set_recipient(address_recipient_new.address());
        transfer.set_fee_record(Some(fee_record_new.to_string()));
        transfer.set_input_record(input_record_new.to_string());
        assert_eq!(transfer.input_record(), input_record_new.to_string());
        assert_eq!(transfer.recipient(), address_recipient_new.address());
        assert_eq!(transfer.amount(), 20000000);
        assert_eq!(transfer.fee(), Some(100));
        assert_eq!(transfer.fee_record(), Some(fee_record_new.to_string()));
    }

    // #[cfg(target_arch = "wasm32")]
    // #[wasm_bindgen_test]
    // async fn test_to_aleo_request() {
    //     let (private_key_owner, _view_key_owner, address_owner) =
    //         utils::helpers::generate_account().unwrap();
    //
    //     let input_record = Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::from_str(&format!(
    //         "{{
    //   owner: {}.private,
    //   microcredits: 50000000u64.private,
    //   _nonce: 0group.public
    // }}",
    //         address_owner.address()
    //     ))
    //         .unwrap();
    //
    //     let fee_record = Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::from_str(&format!(
    //         "{{
    //   owner: {}.private,
    //   microcredits: 10000u64.private,
    //   _nonce: 0group.public
    // }}",
    //         address_owner.address()
    //     ))
    //         .unwrap();
    //
    //     let (private_key_recipient, _, address_recipient) =
    //         utils::helpers::generate_account().unwrap();
    //
    //     let transfer = AleoTransfer::new(
    //         input_record.to_string(),
    //         address_recipient.address(),
    //         1000000,
    //         Some(200),
    //         Some(fee_record.to_string()),
    //         QUERY.to_string(),
    //     );
    //
    //     #[derive(Debug, Serialize)]
    //     struct JsonRpcRequest<'a> {
    //         jsonrpc: &'a str,
    //         id: i32,
    //         method: &'a str,
    //         params: Value,
    //     }
    //
    //     #[derive(Debug, Deserialize)]
    //     struct JsonRpcResponse {
    //         jsonrpc: String,
    //         id: i32,
    //         result: Value,
    //     }
    //
    //     let url = "http://127.0.0.1:51234";
    //     let client = Client::new();
    //
    //
    //     let program_request = transfer.to_program_request().map_err(|e| JsValue::from(e)).unwrap();
    //     console_log!("program_request: {}", program_request.to_string());
    //
    //     let program_request_signed = private_key_owner.sign_program_request(program_request.to_string()).await.map_err(|e| JsValue::from(e)).unwrap();
    //     let request_data = JsonRpcRequest {
    //         jsonrpc: "2.0",
    //         id: 1,
    //         method: "execute_request",
    //         params: json!( program_request_signed),
    //     };
    //     let request = client.post(url).json(&request_data).build().unwrap();
    //     let response = client.execute(request).await.unwrap();
    //     // // let response_json: JsonRpcResponse = response.json().await.unwrap();
    //     // console_log!("5");
    //     //
    //     // console_log!("execute_request: {:?}",response)
    //
    //     // let fee_request = transfer.to_fee_request()
    // }
}
