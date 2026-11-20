//! The operator type: its chains, the prover selection, and one run over all chains.

use std::collections::HashMap;
use std::env;
use std::future::Future;
use std::time::Duration;

use alloy::{network::Network, primitives::Address, providers::Provider, sol};
use anyhow::{Context, Result};
use futures::future::join_all;
use services::input::RpcDataFetcher;
use services::Timeout;
use sp1_sdk::env::{EnvProver, EnvProvingKey};
use sp1_sdk::network::FulfillmentStrategy;
use sp1_sdk::{
    Elf, HashableKey, ProveRequest, Prover, ProverClient, ProvingKey, SP1ProofWithPublicValues,
    SP1Stdin, SP1VerifyingKey,
};
use sp1_vectorx_script::SP1_VECTOR_ELF;
use tracing::{debug, error, info};

use crate::config::SignerMode;

// If the SP1 proof takes too long to respond, time out.
// timeout available only for sp1 network
const PROOF_TIMEOUT_SECS: u64 = 60 * 30;

// If the operator takes too long to run, time out.
const LOOP_TIMEOUT_MINS: u64 = 30;

// If the RPC takes too long to respond, time out.
pub(crate) const RPC_TIMEOUT_SECS: u64 = 60 * 2;

sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    contract SP1Vector {
        uint32 public latestBlock;
        uint64 public latestAuthoritySetId;
        mapping(uint64 => bytes32) public authoritySetIdToHash;
        uint32 public headerRangeCommitmentTreeSize;
        bytes32 public vectorXProgramVkey;

        function rotate(bytes calldata proof, bytes calldata publicValues) external;
        function commitHeaderRange(bytes calldata proof, bytes calldata publicValues) external;
    }
}

type SP1VectorInstance<P, N> = SP1Vector::SP1VectorInstance<P, N>;

pub(crate) struct SP1VectorOperator<P, N> {
    pk: EnvProvingKey,
    vk: SP1VerifyingKey,
    pub(crate) signer_mode: SignerMode,
    pub(crate) tree_size: Option<u32>,
    pub(crate) fetcher: RpcDataFetcher,
    prover: EnvProver,
    pub(crate) contracts: HashMap<u64, SP1VectorInstance<P, N>>,
}

impl<P, N> SP1VectorOperator<P, N>
where
    P: Provider<N>,
    N: Network,
{
    pub(crate) async fn new(signer_mode: SignerMode) -> Self {
        dotenv::dotenv().ok();

        let prover = ProverClient::from_env().await;
        let pk = prover
            .setup(Elf::Static(SP1_VECTOR_ELF))
            .await
            .expect("failed to setup prover");
        let vk = pk.verifying_key().clone();

        Self {
            fetcher: RpcDataFetcher::new().await,
            pk,
            vk,
            signer_mode,
            prover,
            contracts: HashMap::new(),
            tree_size: None,
        }
    }

    /// Register a new chain with the operator.
    ///
    /// Returns an error if the chain's RPC fails, so the caller can skip this chain and serve the
    /// others. This function will panic if the tree size doesnt match as expected.
    pub(crate) async fn add_chain(&mut self, provider: P, address: Address) -> Result<()> {
        let contract = SP1VectorInstance::new(address, provider);

        let tree_size = contract
            .headerRangeCommitmentTreeSize()
            .call()
            .await
            .context("Failed to get tree size")?;

        let chain_id = contract
            .provider()
            .get_chain_id()
            .await
            .context("Failed to get chain id")?;

        // Register the first tree size.
        match self.tree_size {
            None => self.tree_size = Some(tree_size),
            Some(existing) if existing != tree_size => {
                panic!(
                    "Tree size mismatch! Expected {}, got {} for chain id {}",
                    existing, tree_size, chain_id
                );
            }
            Some(_) => {}
        }

        self.contracts.insert(chain_id, contract);

        Ok(())
    }

    /// Prove `stdin` with the prover that the `SP1_PROVER` environment variable selects: `mock`,
    /// `network`, or else the client built from the environment. `purpose` completes the log
    /// line that says which prover is used.
    pub(crate) async fn prove(
        &self,
        stdin: SP1Stdin,
        purpose: &str,
    ) -> Result<SP1ProofWithPublicValues> {
        match env::var("SP1_PROVER")?.to_lowercase().as_str() {
            "mock" => {
                info!("Using mock proof to {}.", purpose);
                let prover_client = ProverClient::builder().mock().build().await;
                let mock_pk = prover_client
                    .setup(Elf::Static(SP1_VECTOR_ELF))
                    .await
                    .expect("failed to setup mock prover");
                Ok(prover_client.prove(&mock_pk, stdin).plonk().await?)
            }
            "network" => {
                info!("Using spn proof to {}.", purpose);

                let spn_client = ProverClient::builder().network().build().await;
                let balance = spn_client.get_balance().await?;
                info!(message = "Available balance", balance = balance.to_string());

                let network_pk = spn_client
                    .setup(Elf::Static(SP1_VECTOR_ELF))
                    .await
                    .expect("failed to setup network prover");
                spn_client
                    .prove(&network_pk, stdin)
                    .strategy(FulfillmentStrategy::Auction)
                    .min_auction_period(10)
                    .plonk()
                    .timeout(Duration::from_secs(PROOF_TIMEOUT_SECS))
                    .await
            }
            _ => {
                info!("Using env defined client to {}.", purpose);
                self.prover.prove(&self.pk, stdin).plonk().await
            }
        }
    }

    /// Run `f` for each chain, with a timeout per chain. A chain that fails is logged and left
    /// out, so it does not stop the other chains.
    ///
    /// Returns the values of the chains that succeeded, and whether any chain failed.
    pub(crate) async fn for_each_chain<T, F, Fut>(
        &self,
        chain_ids: &[u64],
        step: &str,
        f: F,
    ) -> (Vec<(u64, T)>, bool)
    where
        F: Fn(u64) -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        let results = join_all(chain_ids.iter().map(|&chain_id| {
            let fut = f(chain_id).timeout(Duration::from_secs(RPC_TIMEOUT_SECS));
            async move { (chain_id, fut.await) }
        }))
        .await;

        let mut values = Vec::with_capacity(results.len());
        let mut has_errors = false;
        for (chain_id, result) in results {
            match result {
                Ok(Ok(value)) => values.push((chain_id, value)),
                Ok(Err(e)) => {
                    has_errors = true;
                    error!("{} failed for chain {}: {:?}", step, chain_id, e);
                }
                Err(_) => {
                    has_errors = true;
                    error!(
                        "{} timed out for chain {} after {} seconds",
                        step, chain_id, RPC_TIMEOUT_SECS
                    );
                }
            }
        }
        (values, has_errors)
    }

    /// Check the verifying key in the contract matches the
    /// verifying key in the prover for the given `chain_id`.
    async fn check_vkey(&self, chain_id: u64) -> Result<()> {
        debug!("Checking verifying key for chain {}", chain_id);

        // Check that the verifying key in the contract matches the verifying key in the prover.
        let contract = self
            .contracts
            .get(&chain_id)
            .expect("No contract for chain id");

        let verifying_key = contract.vectorXProgramVkey().call().await?;

        if verifying_key.0.to_vec()
            != hex::decode(self.vk.bytes32().strip_prefix("0x").unwrap()).unwrap()
        {
            return Err(anyhow::anyhow!(
                "The verifying key in the operator does not match the verifying key in the contract!"
            ));
        }

        Ok(())
    }

    /// Run a single iteration of the operator.
    ///
    /// If any step of this function fails, it will return a generic error indicating a failure.
    async fn run_once(&self) -> Result<()> {
        debug!("Starting operator, run_once");
        let mut has_errors = false;

        // A chain whose vkey check fails is left out of this run. The other chains go on.
        let all_chain_ids: Vec<u64> = self.contracts.keys().copied().collect();
        let (checked, check_errors) = self
            .for_each_chain(&all_chain_ids, "Checking the verifying key", |id| {
                self.check_vkey(id)
            })
            .await;
        has_errors |= check_errors;
        let chain_ids: Vec<u64> = checked.into_iter().map(|(id, ())| id).collect();

        if let Err(e) = self.handle_rotate(&chain_ids).await {
            has_errors = true;
            error!("Error during `handle_rotate`: {:?}", e);
        }

        if let Err(e) = self.handle_header_range(&chain_ids).await {
            has_errors = true;
            error!("Error during `handle_header_range`: {:?}", e);
        }

        if has_errors {
            // By this point, any known errors have been logged.
            return Err(anyhow::anyhow!("At least one step of the run failed"));
        }

        Ok(())
    }

    // Run the operator once, with a timeout. The scheduler that starts the process provides the
    // loop.
    pub(crate) async fn run(self) -> Result<()> {
        tokio::select! {
            res = self.run_once() => {
                if let Err(e) = res {
                    error!("Error during `run_once`: {:?}", e);
                    return Err(anyhow::anyhow!("Error during `run_once`"));
                }
            },
            _ = tokio::time::sleep(Duration::from_secs(LOOP_TIMEOUT_MINS * 60)) => {
                return Err(anyhow::anyhow!("Timed out after {:?} minutes", LOOP_TIMEOUT_MINS));
            }
        }

        Ok(())
    }
}
