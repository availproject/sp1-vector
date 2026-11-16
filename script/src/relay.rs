use std::env;
use std::str::FromStr;
use std::time::Duration;

use alloy::network::Network;
use alloy::primitives::B256;
use alloy::providers::Provider;
use alloy::transports::http::Client;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::info;

/// Get the gas limit associated with the chain id. Note: These values have been found through
/// trial and error and can be configured.
pub fn get_gas_limit(chain_id: u64) -> u64 {
    if chain_id == 42161 || chain_id == 421614 {
        25_000_000
    } else {
        1_500_000
    }
}

/// Get the gas fee cap associated with the chain id, using the provider to get the gas price. Note:
/// These values have been found through trial and error and can be configured.
pub async fn get_fee_cap<P, N>(chain_id: u64, provider: &P) -> u128
where
    P: Provider<N>,
    N: Network,
{
    // Base percentage multiplier for the gas fee.
    let mut multiplier = 20;

    // Double the estimated gas fee cap for the testnets.
    if chain_id == 17000 || chain_id == 421614 || chain_id == 11155111 || chain_id == 84532 {
        multiplier = 100
    }

    // Get the gas price.
    let gas_price = provider.get_gas_price().await.unwrap();

    // Calculate the fee cap.
    (gas_price * (100 + multiplier)) / 100
}

#[derive(Serialize, Deserialize)]
pub enum KMSRelayStatus {
    Unknown = 0,
    Relayed = 1,
    PreflightError = 2,
    SimulationFailure = 3,
    RelayFailure = 4,
    InvalidAuthenticationToken = 5,
}

/// Relay request arguments for KMS relayer.
#[derive(Debug, Deserialize, Serialize)]
pub struct KMSRelayRequest {
    pub chain_id: u64,
    pub address: String,
    pub calldata: String,
    pub platform_request: bool,
}

/// Response from KMS relayer.
#[derive(Debug, Deserialize, Serialize)]
pub struct KMSRelayResponse {
    pub transaction_hash: Option<String>,
    pub message: Option<String>,
    pub status: u32,
}

/// Relay a transaction with KMS and return the transaction hash with retries.
/// Requires SECURE_RELAYER_ENDPOINT and SECURE_RELAYER_API_KEY to be set in the environment.
pub async fn relay_with_kms(args: &KMSRelayRequest, num_retries: u32) -> Result<B256> {
    for attempt in 1..=num_retries {
        let response = send_kms_relay_request(args).await?;
        match response.status {
            status if status == KMSRelayStatus::Relayed as u32 => {
                return Ok(B256::from_str(
                    &response
                        .transaction_hash
                        .ok_or_else(|| anyhow::anyhow!("Missing transaction hash"))?,
                )?);
            }
            _ => {
                let error_message = response
                    .message
                    .unwrap_or_else(|| format!("status {} without a message", response.status));
                tracing::warn!("KMS relay attempt {} failed: {}", attempt, error_message);
                if attempt == num_retries {
                    return Err(anyhow::anyhow!(
                        "Failed to relay transaction: {}",
                        error_message
                    ));
                }
            }
        }
    }
    unreachable!("Loop should have returned or thrown an error")
}

/// Send a KMS relay request and get the response.
/// Requires SECURE_RELAYER_ENDPOINT and SECURE_RELAYER_API_KEY to be set in the environment.
async fn send_kms_relay_request(args: &KMSRelayRequest) -> Result<KMSRelayResponse> {
    info!("Sending KMS relay request: {:?}", args);
    // Read relayer endpoint from env
    let relayer_endpoint =
        env::var("SECURE_RELAYER_ENDPOINT").context("SECURE_RELAYER_ENDPOINT must be set")?;
    let api_key =
        env::var("SECURE_RELAYER_API_KEY").context("SECURE_RELAYER_API_KEY must be set")?;

    let client = Client::new();
    let response = client
        .post(format!("{}/relay", relayer_endpoint))
        .bearer_auth(api_key)
        .json(&json!(args))
        .timeout(Duration::from_secs(90))
        .send()
        .await
        .map_err(|e| e.without_url())
        .context("The KMS relay request failed")?;
    let response_body = response
        .text()
        .await
        .map_err(|e| e.without_url())
        .context("Failed to read the KMS relay response")?;
    let response_json: KMSRelayResponse = serde_json::from_str(&response_body)?;
    Ok(response_json)
}
