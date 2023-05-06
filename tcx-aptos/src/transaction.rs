#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AptosTxIn {
    #[prost(oneof = "aptos_tx_in::AptosTxType", tags = "1, 2")]
    pub aptos_tx_type: ::std::option::Option<aptos_tx_in::AptosTxType>,
}
pub mod aptos_tx_in {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum AptosTxType {
        #[prost(string, tag = "1")]
        RawTx(std::string::String),
        #[prost(message, tag = "2")]
        Transfer(super::NewTransfer),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NewTransfer {
    #[prost(string, tag = "1")]
    pub sender: std::string::String,
    #[prost(uint64, tag = "2")]
    pub sequence_number: u64,
    #[prost(bytes, repeated, tag = "3")]
    pub args: ::std::vec::Vec<std::vec::Vec<u8>>,
    #[prost(string, tag = "4")]
    pub to: std::string::String,
    #[prost(uint64, tag = "5")]
    pub amount: u64,
    #[prost(uint64, tag = "6")]
    pub max_gas_amount: u64,
    #[prost(uint64, tag = "7")]
    pub gas_unit_price: u64,
    #[prost(uint64, tag = "8")]
    pub expiration_timestamp_secs: u64,
    #[prost(uint32, tag = "9")]
    pub chain_id: u32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AptosTxOut {
    #[prost(bytes, tag = "1")]
    pub tx: std::vec::Vec<u8>,
}
