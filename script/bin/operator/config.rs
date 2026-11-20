//! The chain configuration and the signer mode, read from a file or from the environment.

use alloy::primitives::Address;
use anyhow::{Context, Result};
use std::{env, str::FromStr};

#[derive(Debug)]
pub enum SignerMode {
    Kms,
    Local,
}

impl FromStr for SignerMode {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "kms" => Self::Kms,
            "local" => Self::Local,
            _ => return Err(anyhow::anyhow!("Invalid signer mode: {}", s)),
        })
    }
}

#[derive(Debug, serde::Deserialize)]
pub struct ChainConfig {
    pub rpc_url: String,
    pub vector_address: Address,
}

impl ChainConfig {
    /// Reads the file at `CHAINS_PATH`, or at the default path (`chains.json`) when the variable
    /// is not set.
    ///
    /// If the file is missing or cannot be read, it will try to use [`Self::from_env`].
    pub fn fetch() -> Result<Vec<Self>> {
        const DEFAULT_PATH: &str = "chains.json";

        let path = env::var("CHAINS_PATH").unwrap_or(DEFAULT_PATH.to_string());

        Self::from_file(&path).or_else(|e| {
            // The text of a JSON error can quote a value of the file, and the file holds RPC
            // URLs. So the log gets only the position of a JSON error.
            let reason = match e.downcast_ref::<serde_json::Error>() {
                Some(json_error) => format!(
                    "invalid JSON at line {} column {}",
                    json_error.line(),
                    json_error.column()
                ),
                None => e.to_string(),
            };
            tracing::info!("No usable chains file ({}), trying env.", reason);
            Self::from_env().map(|c| vec![c])
        })
    }

    /// Tries to read from the `CONTRACT_ADDRESS` and `RPC_URL` environment variables.
    pub fn from_env() -> Result<Self> {
        let address = env::var("CONTRACT_ADDRESS").context("CONTRACT_ADDRESS not set")?;
        let rpc_url = env::var("RPC_URL").context("RPC_URL not set")?;

        Ok(Self {
            rpc_url,
            vector_address: address.parse()?,
        })
    }

    pub fn from_file(path: &str) -> Result<Vec<Self>> {
        tracing::debug!("Reading chains from file: {}", path);

        let file = std::fs::read_to_string(path)?;

        Ok(serde_json::from_str(&file)?)
    }
}
