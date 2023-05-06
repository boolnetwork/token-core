#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AptosTxIn {
    #[prost(bytes, tag = "1")]
    pub sender: std::vec::Vec<u8>,
    #[prost(uint64, tag = "2")]
    pub sequence_number: u64,
    #[prost(message, optional, tag = "3")]
    pub call_path: ::std::option::Option<ProtoEntryFunction>,
    #[prost(bytes, repeated, tag = "4")]
    pub args: ::std::vec::Vec<std::vec::Vec<u8>>,
    #[prost(uint64, tag = "5")]
    pub max_gas_amount: u64,
    #[prost(uint64, tag = "6")]
    pub gas_unit_price: u64,
    #[prost(uint64, tag = "7")]
    pub expiration_timestamp_secs: u64,
    #[prost(uint32, tag = "9")]
    pub chain_id: u32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AptosTxOut {
    #[prost(bytes, tag = "1")]
    pub tx: std::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ProtoEntryFunction {
    #[prost(string, tag = "1")]
    pub contract_addr: std::string::String,
    #[prost(string, tag = "2")]
    pub module: std::string::String,
    #[prost(string, tag = "3")]
    pub function: std::string::String,
    #[prost(message, repeated, tag = "4")]
    pub instance: ::std::vec::Vec<InstanceType>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InstanceType {
    #[prost(string, tag = "1")]
    pub contract_addr: std::string::String,
    #[prost(string, tag = "2")]
    pub module: std::string::String,
    #[prost(string, tag = "3")]
    pub name: std::string::String,
    #[prost(message, repeated, tag = "4")]
    pub type_params: ::std::vec::Vec<InstanceType>,
}
