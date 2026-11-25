//! Relay a transaction: through the KMS relayer, or directly, with the USD fee gate on chain 1.

use std::env;
use std::ops::{Div, Mul};
use std::time::Duration;

use alloy::network::{Network, ReceiptResponse, TransactionBuilder};
use alloy::primitives::utils::Unit;
use alloy::primitives::B256;
use alloy::providers::Provider;
use anyhow::{bail, Context, Result};
use services::input::fetch_usd_rate;
use sp1_vectorx_script::relay::{self};
use tokio::time::sleep;
use tracing::{debug, info, instrument, warn};

use crate::config::SignerMode;
use crate::operator::SP1VectorOperator;

// The number of confirmations that the receipt watcher is asked to wait for. alloy 0.14
// `get_receipt` also polls for the receipt and returns the first one it gets, so the wait ends
// after one confirmation.
const NUM_CONFIRMATIONS: u64 = 3;

// How long to wait for a sent transaction to get into a block.
const RELAY_TIMEOUT_SECONDS: u64 = 60;

// The number of times to retry a relay transaction.
const NUM_RELAY_RETRIES: u32 = 3;

impl<P, N> SP1VectorOperator<P, N>
where
    P: Provider<N>,
    N: Network,
{
    async fn submit_proof(
        &self,
        chain_id: u64,
        tx: N::TransactionRequest,
    ) -> Result<N::ReceiptResponse> {
        let contract = self
            .contracts
            .get(&chain_id)
            .expect("No contract for chain id");

        let receipt = contract
            .provider()
            .send_transaction(tx)
            .await?
            .with_required_confirmations(NUM_CONFIRMATIONS)
            .with_timeout(Some(Duration::from_secs(RELAY_TIMEOUT_SECONDS)))
            .get_receipt()
            .await?;

        if !receipt.status() {
            return Err(anyhow::anyhow!("Transaction reverted!"));
        }
        Ok(receipt)
    }

    async fn estimate_effective_usd_gas_fee(
        &self,
        chain_id: u64,
        tx: &N::TransactionRequest,
    ) -> Result<f64> {
        let contract = self
            .contracts
            .get(&chain_id)
            .expect("No contract for chain id");

        let wei: f64 = Unit::ETHER.wei_const().to::<u64>() as f64;
        let gas_estimate: f64 = contract.provider().estimate_gas(tx.clone()).await? as f64;

        let max_fee_per_gas = contract
            .provider()
            .estimate_eip1559_fees()
            .await?
            .max_fee_per_gas as f64;
        let effective_gas_estimate = gas_estimate.mul(max_fee_per_gas).div(wei);
        let usd_estimate = convert_to_usd_gas_fee(effective_gas_estimate).await?;
        info!(
            message = "Gas estimate",
            gas_estimate = gas_estimate,
            effective_gas_estimate = effective_gas_estimate,
            max_fee_per_gas = max_fee_per_gas,
            usd_estimate = round_to_decimals(usd_estimate, 2)
        );
        Ok(round_to_decimals(usd_estimate, 6))
    }

    /// Relay a transaction to the given chain id.
    ///
    /// NOTE: Assumes the provider has a wallet.
    #[instrument(skip(self, tx))]
    pub(crate) async fn relay_tx(&self, chain_id: u64, tx: N::TransactionRequest) -> Result<B256> {
        debug!("Relaying transaction to chain {}", chain_id);

        if matches!(self.signer_mode, SignerMode::Kms) {
            relay::relay_with_kms(
                &relay::KMSRelayRequest {
                    chain_id,
                    address: tx.to().expect("Transaction has no to address").to_string(),
                    calldata: tx.input().expect("Transaction has no input").to_string(),
                    platform_request: false,
                },
                NUM_RELAY_RETRIES,
            )
            .await
        } else if matches!(chain_id, 1) {
            let (
                max_estimate_retries,
                retry_sleep_interval,
                target_usd_fee_threshold,
                max_usd_fee_threshold,
            ) = get_retry_envs()?;

            let mut attempt: u8 = 0;
            let mut last_estimates: Vec<f64> = vec![];

            let tx_hash: B256 = loop {
                let effective_gas_estimate = self
                    .estimate_effective_usd_gas_fee(chain_id, &tx)
                    .await
                    .context("Failed to estimate USD gas fees")?;

                last_estimates.push(round_to_decimals(effective_gas_estimate, 2));

                // 1. If the price is acceptable let's just send it, no questions asked.
                if effective_gas_estimate <= target_usd_fee_threshold {
                    let tx_hash = self
                        .submit_proof_with_info(chain_id, &tx, last_estimates.last().cloned())
                        .await?;
                    break tx_hash;
                }

                info!(
                    message = "USD Gas fee too high!!",
                    usd_estimate = round_to_decimals(effective_gas_estimate, 2)
                );

                warn!(
                    message = "Failed to match send proof condition",
                    gas_estimate = effective_gas_estimate,
                    attempts = attempt
                );

                // 2. Otherwise let's wait and see if the price will go down later. Do this
                // for [`max_estimate_retries`] times
                if attempt < max_estimate_retries {
                    warn!(message = "Retrying...",);
                    sleep(Duration::from_secs(retry_sleep_interval)).await;
                    attempt += 1;
                    continue;
                }

                warn!(message = "Exhausted all retires. Checking one more time but this time with a higher threshold",);

                // 3. If we reached the maximum number of retires we should check one more time,
                // but this time with a higher threshold. If the higher threshold doesn't help
                // then we need to bail out. Sorry
                if effective_gas_estimate <= max_usd_fee_threshold {
                    let tx_hash = self
                        .submit_proof_with_info(chain_id, &tx, last_estimates.last().cloned())
                        .await?;
                    break tx_hash;
                }

                // If we are here it means that we have exhausted all the retires and everything.
                // There is nothing that we can do now. :(
                warn!(message = "Exhausted all options. Failed to submit proof. Exiting loop");
                bail!("Failed to match send proof condition");
            };

            return Ok(tx_hash);
        } else {
            let receipt = self.submit_proof(chain_id, tx).await?;
            Ok(receipt.transaction_hash())
        }
    }

    async fn submit_proof_with_info(
        &self,
        chain_id: u64,
        tx: &N::TransactionRequest,
        last_estimates: Option<f64>,
    ) -> Result<B256> {
        let receipt = self.submit_proof(chain_id, tx.clone()).await?;
        let wei = Unit::ETHER.wei_const().to::<u128>() as f64;
        let effective_gas_price: f64 = receipt.effective_gas_price() as f64;
        let effective_gas_used = effective_gas_price.mul(receipt.gas_used() as f64).div(wei);

        // The transaction is mined at this point. A failed price lookup must not turn the relay
        // into a failure, so the log line has no `usd_fee` in that case.
        match fetch_usd_rate().await {
            Ok(eth_to_usd_rate) => info!(
                message = "Transaction gas fee used",
                gas_fee = effective_gas_used,
                usd_fee = effective_gas_used.mul(eth_to_usd_rate.from_asset.to_asset),
                tx_hash = %receipt.transaction_hash(),
                last_usd_gas_estimates = ?last_estimates
            ),
            Err(e) => {
                warn!("Failed to fetch the USD rate for the fee log: {:?}", e);
                info!(
                    message = "Transaction gas fee used",
                    gas_fee = effective_gas_used,
                    tx_hash = %receipt.transaction_hash(),
                    last_usd_gas_estimates = ?last_estimates
                );
            }
        }

        Ok(receipt.transaction_hash())
    }
}

fn get_retry_envs() -> Result<(u8, u64, f64, f64)> {
    let max_estimate_retries: u8 = env::var("MAX_ESTIMATE_RETRIES")
        .unwrap_or("5".to_string())
        .parse()?;

    let retry_sleep_interval: u64 = env::var("RETRY_SLEEP_INTERVAL")
        .unwrap_or("60".to_string())
        .parse()?;

    let target_usd_fee_threshold: f64 = env::var("TARGET_USD_FEE_THRESHOLD")
        .unwrap_or("2.00".to_string())
        .parse()?;

    let max_usd_fee_threshold: f64 = env::var("MAX_USD_FEE_THRESHOLD")
        .unwrap_or("30.00".to_string())
        .parse()?;

    Ok((
        max_estimate_retries,
        retry_sleep_interval,
        target_usd_fee_threshold,
        max_usd_fee_threshold,
    ))
}

fn round_to_decimals(value: f64, decimals: u32) -> f64 {
    let factor = 10f64.powi(decimals as i32);
    (value * factor).round() / factor
}

async fn convert_to_usd_gas_fee(gas_fee: f64) -> Result<f64> {
    let eth_to_usd_rate = fetch_usd_rate().await?;
    Ok(gas_fee * eth_to_usd_rate.from_asset.to_asset)
}
