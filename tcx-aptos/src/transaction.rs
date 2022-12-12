#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AptosTxIn {
    #[prost(bytes, tag = "1")]
    pub sender: std::vec::Vec<u8>,
    #[prost(uint64, tag = "2")]
    pub sequence_number: u64,
    #[prost(string, tag = "3")]
    pub coin_type: std::string::String,
    #[prost(bytes, tag = "4")]
    pub to: std::vec::Vec<u8>,
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
