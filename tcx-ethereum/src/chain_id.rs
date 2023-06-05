use failure::format_err;
use parking_lot::RwLock;

pub type Result<T> = std::result::Result<T, failure::Error>;

/// Ethereum chain info
#[derive(Clone)]
pub struct ChainInfo {
    pub network: String,
    pub network_id: i32,
    pub chain_id: u64,
}

lazy_static! {
    static ref CHAIN_INFOS: RwLock<Vec<ChainInfo>> = {
        let mut chain_infos = Vec::new();
        chain_infos.push(ChainInfo {
            network: "MAINNET".to_string(),
            network_id: 1,
            chain_id: 1,
        });
        chain_infos.push(ChainInfo {
            network: "ROPSTEN".to_string(),
            network_id: 3,
            chain_id: 3,
        });
        chain_infos.push(ChainInfo {
            network: "RINKEBY".to_string(),
            network_id: 4,
            chain_id: 4,
        });
        chain_infos.push(ChainInfo {
            network: "GOERLI".to_string(),
            network_id: 5,
            chain_id: 5,
        });
        chain_infos.push(ChainInfo {
            network: "KOVAN".to_string(),
            network_id: 42,
            chain_id: 42,
        });
        chain_infos.push(ChainInfo {
            network: "BSC".to_string(),
            network_id: 56,
            chain_id: 56,
        });
        chain_infos.push(ChainInfo {
            network: "BSC_TESTNET".to_string(),
            network_id: 97,
            chain_id: 97,
        });
        chain_infos.push(ChainInfo {
            network: "POLYGON".to_string(),
            network_id: 137,
            chain_id: 137,
        });
        chain_infos.push(ChainInfo {
            network: "MUMBAI".to_string(),
            network_id: 80001,
            chain_id: 80001,
        });
        chain_infos.push(ChainInfo {
            network: "BOOL".to_string(),
            network_id: 479,
            chain_id: 479,
        });
        chain_infos.push(ChainInfo {
            network: "BOOL_TESTNET".to_string(),
            network_id: 47,
            chain_id: 47,
        });
        chain_infos.push(ChainInfo {
            network: "BOOL_DEVNET".to_string(),
            network_id: 477,
            chain_id: 477,
        });
        chain_infos.push(ChainInfo {
            network: "ETHW".to_string(),
            network_id: 10001,
            chain_id: 10001,
        });
        chain_infos.push(ChainInfo {
            network: "FILECOIN_EVM".to_string(),
            network_id: 314,
            chain_id: 314,
        });
        chain_infos.push(ChainInfo {
            network: "FILECOIN_HYPERSPACE_EVM".to_string(),
            network_id: 3141,
            chain_id: 3141,
        });
        chain_infos.push(ChainInfo {
            network: "FILECOIN_CALIBRATION_EVM".to_string(),
            network_id: 314159,
            chain_id: 314159,
        });
        chain_infos.push(ChainInfo {
            network: "OPTIMISM".to_string(),
            network_id: 10,
            chain_id: 10,
        });
        chain_infos.push(ChainInfo {
            network: "OPTIMISM_GOERLI".to_string(),
            network_id: 420,
            chain_id: 420,
        });
        chain_infos.push(ChainInfo {
            network: "ARBITRUM".to_string(),
            network_id: 42161,
            chain_id: 42161,
        });
        chain_infos.push(ChainInfo {
            network: "ARBITRUM_GOERLI".to_string(),
            network_id: 421613,
            chain_id: 421613,
        });
        chain_infos.push(ChainInfo {
            network: "AVALANCHE".to_string(),
            network_id: 43114,
            chain_id: 43114,
        });
        chain_infos.push(ChainInfo {
            network: "AVALANCHE_FUJI".to_string(),
            network_id: 43113,
            chain_id: 43113,
        });
        chain_infos.push(ChainInfo {
            network: "FANTOM".to_string(),
            network_id: 250,
            chain_id: 250,
        });
        chain_infos.push(ChainInfo {
            network: "FANTOM_TESTNET".to_string(),
            network_id: 4002,
            chain_id: 4002,
        });
        chain_infos.push(ChainInfo {
            network: "CRONOS".to_string(),
            network_id: 25,
            chain_id: 25,
        });
        chain_infos.push(ChainInfo {
            network: "CRONOS_TESTNET".to_string(),
            network_id: 338,
            chain_id: 338,
        });
        chain_infos.push(ChainInfo {
            network: "ZKSYNC".to_string(),
            network_id: 324,
            chain_id: 324,
        });
        chain_infos.push(ChainInfo {
            network: "ZKSYNC_TESTNET".to_string(),
            network_id: 280,
            chain_id: 280,
        });
        chain_infos.push(ChainInfo {
            network: "CHAIN_SQL".to_string(),
            network_id: 7181,
            chain_id: 7181,
        });
        RwLock::new(chain_infos)
    };
}

pub fn chain_id_from_network(network: &str) -> Result<u64> {
    let chain_infos = CHAIN_INFOS.read();
    let mut res: Vec<u64> = chain_infos
        .iter()
        .filter(|x| x.network.as_str() == network)
        .map(|x| x.chain_id)
        .collect::<Vec<u64>>();
    if res.len() > 0 {
        Ok(res.pop().unwrap())
    } else {
        Err(format_err!("No chain id for network"))
    }
}
