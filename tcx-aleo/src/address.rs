use crate::viewkey::AleoViewKey;
use snarkvm_console::account::ViewKey;
use snarkvm_console::network::Network;
use std::str::FromStr;
use tcx_constants::Result;

pub struct AleoAddress<N: Network>;

impl<N: Network> AleoAddress<N> {
    fn from_view_key(view_key: AleoViewKey<N>) -> Result<String> {
        let vk = ViewKey::<N>::from_str(&view_key.0)?;
        Ok(vk.to_address().to_string())
    }
}
