use crate::request::AleoProgramRequest;
use crate::Error::{FeeRecordMissed, InvalidAleoRequest};
use crate::{AleoRequest, CurrentNetwork};
use snarkvm_console::program::{Plaintext, Record, Value, U64};
use std::str::FromStr;
use wasm_bindgen::JsError;

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
}

impl AleoTransfer {
    pub fn new(
        input_record: String,
        recipient: String,
        amount: u64,
        fee: Option<u64>,
        fee_record: Option<String>,
    ) -> Self {
        Self {
            input_record,
            recipient,
            amount,
            fee,
            fee_record,
        }
    }

    pub fn input_record(&self) -> String {
        self.input_record.clone()
    }

    pub fn recipient(&self) -> String {
        self.recipient.clone()
    }

    pub fn amount(&self) -> u64 {
        self.amount
    }

    pub fn fee(&self) -> Option<u64> {
        self.fee
    }

    pub fn fee_record(&self) -> Option<String> {
        self.fee_record.clone()
    }

    pub fn to_aleo_request(&self, query: String) -> std::result::Result<AleoRequest, JsError> {
        let program_inputs_record =
            Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::from_str(&self.input_record)
                .map_err(|e| JsError::new(&e.to_string()))?;
        let program_inputs = vec![
            Value::Record(program_inputs_record).to_string(),
            Value::from_str(&format!("{}", self.recipient))?.to_string(),
            Value::from_str(&format!("{}u64", self.amount))?.to_string(),
        ];
        let program_req = AleoProgramRequest::new(
            "credits.aleo".to_string(),
            "transfer".to_string(),
            program_inputs,
        )
        .to_string();

        // fee
        if let Some(fee) = self.fee {
            if let Some(fee_record) = self.fee_record.clone() {
                let fee_record =
                    Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::from_str(&fee_record)
                        .map_err(|e| JsError::new(&e.to_string()))?;
                let fee_inputs = vec![
                    Value::Record(fee_record).to_string(),
                    Value::from_str(&format!("{}", U64::<CurrentNetwork>::new(fee))).to_string(),
                ];

                let fee_req = AleoProgramRequest::new(
                    "credits.aleo".to_string(),
                    "fee".to_string(),
                    fee_inputs,
                )
                .to_string();

                Ok(AleoRequest::new(program_req, Some(fee_req), query))
            } else {
                Err(JsError::new(&FeeRecordMissed.to_string()))
            }
        } else {
            Ok(AleoRequest::new(program_req, None, query))
        }
    }
}
