use crate::viewkey::AleoViewKey;
use crate::Error;
use snarkvm_console::account::ViewKey;
use snarkvm_console::network::Network;
use std::marker::PhantomData;
use std::str::FromStr;
use tcx_constants::Result;

pub struct AleoAddress<N: Network>(PhantomData<N>);

impl<N: Network> AleoAddress<N> {
    fn from_view_key(view_key: AleoViewKey<N>) -> Result<String> {
        let vk =
            ViewKey::<N>::from_str(&view_key.to_string()).map_err(|_| Error::InvalidViewKey)?;
        Ok(vk.to_address().to_string())
    }
}
