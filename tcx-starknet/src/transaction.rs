#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StarknetTxIn {
    #[prost(oneof = "starknet_tx_in::StarknetTxType", tags = "1, 2")]
    pub starknet_tx_type: ::std::option::Option<starknet_tx_in::StarknetTxType>,
}
pub mod starknet_tx_in {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum StarknetTxType {
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
    pub nonce: u64,
    #[prost(string, tag = "3")]
    pub to: std::string::String,
    #[prost(string, tag = "4")]
    pub amount: std::string::String,
    #[prost(string, tag = "5")]
    pub max_fee: std::string::String,
    #[prost(string, tag = "6")]
    pub chain_id: std::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StarknetTxOut {
    #[prost(string, tag = "1")]
    pub contract_address: std::string::String,
    #[prost(string, repeated, tag = "2")]
    pub call_data: ::std::vec::Vec<std::string::String>,
    #[prost(string, tag = "3")]
    pub signature: std::string::String,
    #[prost(string, tag = "4")]
    pub max_fee: std::string::String,
    #[prost(string, tag = "5")]
    pub nonce: std::string::String,
}
