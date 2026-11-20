//! The SP1 Vector operator: prove a rotate and a header range, and relay them to every chain.
//! One start of the process does one run. A scheduler provides the loop.

mod config;
mod header_range;
mod logging;
mod operator;
mod relay_tx;
mod rotate;

use std::env;
use std::str::FromStr;
use std::time::Duration;

use alloy::signers::local::PrivateKeySigner;
use alloy::{
    network::Network,
    primitives::Address,
    providers::{Provider, ProviderBuilder},
};
use anyhow::{bail, Result};
use services::redact::Redactor;
use services::Timeout;
use tracing::level_filters::LevelFilter;
use tracing::{error, info};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use config::{ChainConfig, SignerMode};
use logging::{RedactingWriter, LOG_REDACTOR};
use operator::{SP1VectorOperator, RPC_TIMEOUT_SECS};

#[tokio::main]
async fn main() -> Result<()> {
    dotenv::dotenv().ok();
    let log_level = env::var("LOG_LEVEL").unwrap_or("info".to_string());

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_current_span(true)
                .with_line_number(true)
                .with_target(true)
                .with_writer(|| RedactingWriter(std::io::stdout())),
        )
        .with(LevelFilter::from_str(&log_level)?)
        .init();

    // The default panic hook writes the message to stderr as it is, and a panic message can hold
    // an RPC URL. Send panics through the log instead, where URLs are redacted.
    // `Backtrace::capture` honours `RUST_BACKTRACE`, as the default hook does.
    std::panic::set_hook(Box::new(|panic_info| {
        let backtrace = std::backtrace::Backtrace::capture();
        match backtrace.status() {
            std::backtrace::BacktraceStatus::Captured => {
                error!("Panic: {}\n{}", panic_info, backtrace)
            }
            _ => error!("Panic: {}", panic_info),
        }
    }));

    let signer_mode = env::var("SIGNER_MODE")
        .map(|v| v.parse().unwrap())
        .unwrap_or(SignerMode::Local);
    let config = ChainConfig::fetch().expect("Failed to fetch chain config");

    // From here on the log also removes the configured secret values themselves.
    let mut redactor = Redactor::default();
    for name in [
        "PRIVATE_KEY",
        "NETWORK_PRIVATE_KEY",
        "SECURE_RELAYER_API_KEY",
        "COINGEKO_API_KEY",
    ] {
        if let Ok(value) = env::var(name) {
            redactor.add_secret(&value);
        }
    }
    for name in [
        "AVAIL_URL",
        "RPC_URL",
        "SECURE_RELAYER_ENDPOINT",
        "DATABASE_URL",
        "VECTORX_QUERY_URL",
        "COINGEKO_URL",
    ] {
        if let Ok(value) = env::var(name) {
            redactor.add_url(&value);
        }
    }
    for chain in &config {
        redactor.add_url(&chain.rpc_url);
    }
    let _ = LOG_REDACTOR.set(redactor);

    let run_result = match signer_mode {
        SignerMode::Local => run_with_signer(config).await,
        SignerMode::Kms => run_with_kms(config).await,
    };

    run_result
}

async fn run_with_signer(config: Vec<ChainConfig>) -> Result<()> {
    let operator = SP1VectorOperator::new(SignerMode::Local).await;

    let signer: PrivateKeySigner = env::var("PRIVATE_KEY")
        .expect("PRIVATE_KEY must be set")
        .parse()
        .expect("Failed to parse PRIVATE_KEY");

    let chains = config
        .into_iter()
        .map(|c| {
            let provider = ProviderBuilder::new()
                .wallet(signer.clone())
                .on_http(c.rpc_url.parse().expect("Failed to parse RPC URL"));
            (provider, c.vector_address)
        })
        .collect();

    run_with_chains(operator, chains).await
}

async fn run_with_kms(config: Vec<ChainConfig>) -> Result<()> {
    let operator = SP1VectorOperator::new(SignerMode::Kms).await;

    let chains = config
        .into_iter()
        .map(|c| {
            let provider =
                ProviderBuilder::new().on_http(c.rpc_url.parse().expect("Failed to parse RPC URL"));
            (provider, c.vector_address)
        })
        .collect();

    run_with_chains(operator, chains).await
}

/// Register the chains and run the operator. A chain whose RPC fails at registration is skipped,
/// so that it does not stop the other chains. The run still ends with an error in that case.
async fn run_with_chains<P, N>(
    mut operator: SP1VectorOperator<P, N>,
    chains: Vec<(P, Address)>,
) -> Result<()>
where
    P: Provider<N>,
    N: Network,
{
    let mut skipped_chain = false;
    for (provider, address) in chains {
        let registration = operator
            .add_chain(provider, address)
            .timeout(Duration::from_secs(RPC_TIMEOUT_SECS))
            .await
            .unwrap_or_else(|_| Err(anyhow::anyhow!("The chain's RPC timed out")));
        if let Err(e) = registration {
            skipped_chain = true;
            error!("Skipping the contract {}: {:?}", address, e);
        }
    }

    let run_result = operator.run().await;
    if skipped_chain {
        bail!("At least one chain was skipped at startup");
    }
    run_result?;

    // Only here is it known that no chain was skipped and that no step failed.
    info!("The run finished without errors");
    Ok(())
}
