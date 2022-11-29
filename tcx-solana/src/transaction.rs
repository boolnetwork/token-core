#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SolanaTxIn {
    #[prost(bytes, tag = "1")]
    pub to: std::vec::Vec<u8>,
    #[prost(uint64, tag = "2")]
    pub amount: u64,
    #[prost(bytes, tag = "3")]
    pub recent_blockhash: std::vec::Vec<u8>,
    #[prost(uint32, tag = "4")]
    pub signal: u32,
    #[prost(bytes, tag = "5")]
    pub param: std::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SolanaTxOut {
    #[prost(string, tag = "1")]
    pub tx: std::string::String,
}
