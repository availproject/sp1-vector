use alloy::network::{ReceiptResponse, TransactionBuilder};
use alloy::primitives::utils::Unit;
use alloy::signers::local::PrivateKeySigner;
use alloy::{
    network::Network,
    primitives::{Address, B256},
    providers::{Provider, ProviderBuilder},
    sol,
};
use futures::future::join_all;
use std::env;
use std::future::Future;
use std::io::Write;
use std::ops::{Div, Mul};
use std::str::FromStr;
use std::sync::OnceLock;
use std::time::Duration;
use std::{cmp::min, collections::HashMap};
use tokio::time::sleep;

use anyhow::{bail, Context, Result};
use services::input::{fetch_usd_rate, HeaderRangeRequestData, RpcDataFetcher};
use services::redact::{redact_urls, Redactor};
use services::Timeout;
use sp1_sdk::env::{EnvProver, EnvProvingKey};
use sp1_sdk::network::FulfillmentStrategy;
use sp1_sdk::{
    Elf, HashableKey, ProveRequest, Prover, ProverClient, ProvingKey, SP1ProofWithPublicValues,
    SP1Stdin, SP1VerifyingKey,
};
use sp1_vector_primitives::types::ProofType;
use sp1_vectorx_script::relay::{self};
use sp1_vectorx_script::SP1_VECTOR_ELF;
use tracing::level_filters::LevelFilter;
use tracing::{debug, error, info, instrument, warn};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use config::{ChainConfig, SignerMode};

////////////////////////////////////////////////////////////
// Constants
////////////////////////////////////////////////////////////

// If the SP1 proof takes too long to respond, time out.
// timeout available only for sp1 network
const PROOF_TIMEOUT_SECS: u64 = 60 * 30;

// If the operator takes too long to run, time out.
const LOOP_TIMEOUT_MINS: u64 = 30;

// If the RPC takes too long to respond, time out.
const RPC_TIMEOUT_SECS: u64 = 60 * 2;

// Wait for 3 required confirmations with a timeout of 60 seconds.
const NUM_CONFIRMATIONS: u64 = 3;

// If the relay takes too long to respond, time out.
const RELAY_TIMEOUT_SECONDS: u64 = 60;

// The number of times to retry a relay transaction.
const NUM_RELAY_RETRIES: u32 = 3;

////////////////////////////////////////////////////////////
// Type Definitions
////////////////////////////////////////////////////////////

sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    contract SP1Vector {
        bool public frozen;
        uint32 public latestBlock;
        uint64 public latestAuthoritySetId;
        mapping(uint64 => bytes32) public authoritySetIdToHash;
        uint32 public headerRangeCommitmentTreeSize;
        bytes32 public vectorXProgramVkey;
        address public verifier;

        function rotate(bytes calldata proof, bytes calldata publicValues) external;
        function commitHeaderRange(bytes calldata proof, bytes calldata publicValues) external;
    }
}

type SP1VectorInstance<P, N> = SP1Vector::SP1VectorInstance<P, N>;

struct SP1VectorOperator<P, N> {
    pk: EnvProvingKey,
    vk: SP1VerifyingKey,
    signer_mode: SignerMode,
    tree_size: Option<u32>,
    fetcher: RpcDataFetcher,
    prover: EnvProver,
    contracts: HashMap<u64, SP1VectorInstance<P, N>>,
}

#[derive(Debug)]
struct HeaderRangeContractData {
    vectorx_latest_block: u32,
    avail_current_block: u32,
    header_range_commitment_tree_size: u32,
    next_authority_set_hash_exists: bool,
}

#[derive(Debug)]
struct RotateContractData {
    current_block: u32,
    next_authority_set_hash_exists: bool,
}

////////////////////////////////////////////////////////////
// Constructor
////////////////////////////////////////////////////////////

impl<P, N> SP1VectorOperator<P, N>
where
    P: Provider<N>,
    N: Network,
{
    async fn new(signer_mode: SignerMode) -> Self {
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
    async fn add_chain(&mut self, provider: P, address: Address) -> Result<()> {
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
}

////////////////////////////////////////////////////////////
// Block Utilities
////////////////////////////////////////////////////////////

impl<P, N> SP1VectorOperator<P, N>
where
    P: Provider<N>,
    N: Network,
{
    async fn request_header_range(
        &self,
        tree_size: u32,
        header_range_request: HeaderRangeRequestData,
    ) -> Result<SP1ProofWithPublicValues> {
        let mut stdin: SP1Stdin = SP1Stdin::new();

        let proof_type = ProofType::HeaderRangeProof;
        let header_range_inputs = self
            .fetcher
            .get_header_range_inputs(header_range_request, Some(tree_size))
            .await
            .context("Failed to get the header range inputs")?;

        stdin.write(&proof_type);
        stdin.write(&header_range_inputs);

        info!(
            "Requesting header range proof from block {} to block {}.",
            header_range_request.trusted_block, header_range_request.target_block
        );

        // If the SP1_PROVER environment variable is set to "mock", use the mock prover.
        let mock = env::var("SP1_PROVER")?.to_lowercase() == "mock";
        let proof = if mock {
            info!("Using mock proof to insert header range proof.");
            let prover_client = ProverClient::builder().mock().build().await;
            let mock_pk = prover_client
                .setup(Elf::Static(SP1_VECTOR_ELF))
                .await
                .expect("failed to setup mock prover");
            let proof = prover_client.prove(&mock_pk, stdin).plonk().await?;
            Ok(proof)
        } else {
            let spn = env::var("SP1_PROVER")?.to_lowercase() == "network";
            return if spn {
                info!("Using spn proof to insert header range proof.");

                let spn_client = ProverClient::builder().network().build().await;
                let balance = spn_client.get_balance().await?;
                info!(message = "Available balance", balance = balance.to_string());

                let network_pk = spn_client
                    .setup(Elf::Static(SP1_VECTOR_ELF))
                    .await
                    .expect("failed to setup network prover");
                let proof = spn_client
                    .prove(&network_pk, stdin)
                    .strategy(FulfillmentStrategy::Auction)
                    .min_auction_period(10)
                    .plonk()
                    .timeout(Duration::from_secs(PROOF_TIMEOUT_SECS))
                    .await;
                proof
            } else {
                info!("Using env defined client insert header range proof.");
                let proof = self.prover.prove(&self.pk, stdin).plonk().await;
                proof
            };
        };
        proof
    }

    // Ideally, post a header range update every ideal_block_interval blocks. Returns Option<(latest_block, block_to_step_to)>.
    #[instrument(skip(self, ideal_block_interval))]
    async fn find_header_range(
        &self,
        chain_id: u64,
        ideal_block_interval: u32,
    ) -> Result<Option<HeaderRangeRequestData>> {
        let header_range_contract_data = self.get_contract_data_for_header_range(chain_id).await?;
        debug!(
            "header_range_contract_data: {:?}",
            header_range_contract_data
        );

        // The current authority set id is the authority set id of the block before the current block.
        let current_authority_set_id = self
            .fetcher
            .get_authority_set_id(header_range_contract_data.vectorx_latest_block - 1)
            .await?;

        info!("current_authority_set_id: {}", current_authority_set_id);
        // Get the last justified block by the current authority set id.
        let last_justified_block = self
            .fetcher
            .last_justified_block(current_authority_set_id)
            .await?;

        // If this is the last justified block, check for header range with next authority set.
        let mut request_authority_set_id = current_authority_set_id;
        info!("last_justified_block: {}", last_justified_block);
        info!(
            "vectorx_latest_block: {}",
            header_range_contract_data.vectorx_latest_block
        );
        if header_range_contract_data.vectorx_latest_block == last_justified_block {
            let next_authority_set_id = current_authority_set_id + 1;

            // Check if the next authority set id exists in the contract. If not, a rotate is needed.
            if !header_range_contract_data.next_authority_set_hash_exists {
                return Ok(None);
            }
            request_authority_set_id = next_authority_set_id;
        }

        // Find the block to step to. If no block is returned, either 1) there is no block satisfying
        // the conditions that is available to step to or 2) something has gone wrong with the indexer.
        let maybe_block_to_step_to = self
            .find_block_to_step_to(
                ideal_block_interval,
                header_range_contract_data.header_range_commitment_tree_size,
                header_range_contract_data.vectorx_latest_block,
                header_range_contract_data.avail_current_block,
                request_authority_set_id,
            )
            .await?;

        info!("Target Block: {:?}", maybe_block_to_step_to);

        if let Some((block_to_step_to, is_target_epoch_end_block)) = maybe_block_to_step_to {
            return Ok(Some(HeaderRangeRequestData {
                trusted_block: header_range_contract_data.vectorx_latest_block,
                target_block: block_to_step_to,
                is_target_epoch_end_block,
            }));
        }
        Ok(None)
    }

    // Current block, step_range_max and whether next authority set hash exists.
    async fn get_contract_data_for_header_range(
        &self,
        chain_id: u64,
    ) -> Result<HeaderRangeContractData> {
        let contract = self
            .contracts
            .get(&chain_id)
            .expect("No contract for chain id");

        let vectorx_latest_block = contract.latestBlock().call().await?;
        let header_range_commitment_tree_size =
            contract.headerRangeCommitmentTreeSize().call().await?;

        let avail_current_block = self.fetcher.get_head().await?.number;

        let vectorx_current_authority_set_id = self
            .fetcher
            .get_authority_set_id(vectorx_latest_block - 1)
            .await?;
        let next_authority_set_id = vectorx_current_authority_set_id + 1;

        let next_authority_set_hash = contract
            .authoritySetIdToHash(next_authority_set_id)
            .call()
            .await?;

        Ok(HeaderRangeContractData {
            vectorx_latest_block,
            avail_current_block,
            header_range_commitment_tree_size,
            next_authority_set_hash_exists: next_authority_set_hash != B256::ZERO,
        })
    }

    // The logic for finding the block to step to is as follows:
    // 1. If the current epoch in the contract is not the latest epoch, step to the last justified block
    // of the epoch.
    // 2. If the block has a valid justification, return the block number.
    // 3. If the block has no valid justification, return None.
    //
    // The returned flag is true when the block is the last justified block of `authority_set_id`.
    // The justification of such a block comes from `grandpa_proveFinality`.
    async fn find_block_to_step_to(
        &self,
        ideal_block_interval: u32,
        header_range_commitment_tree_size: u32,
        vectorx_current_block: u32,
        avail_current_block: u32,
        authority_set_id: u64,
    ) -> Result<Option<(u32, bool)>> {
        // Each search uses its own connection, so that the searches of several chains run in
        // parallel within the per-chain timeout.
        let fetcher = RpcDataFetcher::try_new().await?;
        let last_justified_block = fetcher.last_justified_block(authority_set_id).await?;

        // Step to the last justified block of the current epoch if it is in range. When the last
        // justified block is 0, the SP1Vector contract's latest epoch is the current epoch on the
        // Avail chain.
        if last_justified_block != 0
            && last_justified_block <= vectorx_current_block + header_range_commitment_tree_size
        {
            debug!("last_justified_block: {}", last_justified_block);
            return Ok(Some((last_justified_block, true)));
        }

        // The maximum valid block to step to is the either header_range_commitment_tree_size blocks
        // ahead of the current block in the contract or the latest block on Avail.
        let max_valid_block_to_step_to = min(
            vectorx_current_block + header_range_commitment_tree_size,
            avail_current_block,
        );

        info!("max_valid_block_to_step_to: {}", max_valid_block_to_step_to);
        info!("avail_current_block: {}", avail_current_block);
        info!("block interval: {}", ideal_block_interval);

        // Find the closest block to the maximum valid block to step to that is a multiple of
        // ideal_block_interval.
        let mut block_to_step_to =
            max_valid_block_to_step_to - (max_valid_block_to_step_to % ideal_block_interval);

        debug!("Block to step to: {}", block_to_step_to);

        // If block_to_step_to is <= to the current block, return None.
        if block_to_step_to <= vectorx_current_block {
            return Ok(None);
        }

        // Check that block_to_step_to has a valid justification. If not, iterate up until the maximum_vectorx_target_block
        // to find a valid justification. If we're unable to find a justification, something has gone
        // deeply wrong with the justification indexer.
        loop {
            if block_to_step_to > max_valid_block_to_step_to {
                error!(
                    "Unable to find any valid justifications after searching from block {} to block {}. This is likely caused by an issue with the justification indexer.",
                    vectorx_current_block + ideal_block_interval,
                    max_valid_block_to_step_to
                );
                return Ok(None);
            }

            // An error here means that the justification endpoint failed. Stop the search, because
            // every later block would fail the same way.
            if fetcher.get_justification(block_to_step_to).await?.is_some() {
                break;
            }
            block_to_step_to += 1;
        }

        Ok(Some((block_to_step_to, false)))
    }
}

////////////////////////////////////////////////////////////
// Rotate Utilities
////////////////////////////////////////////////////////////

impl<P, N> SP1VectorOperator<P, N>
where
    P: Provider<N>,
    N: Network,
{
    // Current block and whether next authority set hash exists.
    async fn get_contract_data_for_rotate(&self, chain_id: u64) -> Result<RotateContractData> {
        let contract = self
            .contracts
            .get(&chain_id)
            .expect("No contract for chain id");

        // Fetch the current block from the contract
        let vectorx_latest_block = contract.latestBlock().call().await?;

        // Fetch the current authority set id from the contract
        let vectorx_latest_authority_set_id = contract.latestAuthoritySetId().call().await?;

        // Check if the next authority set id exists in the contract
        let next_authority_set_id = vectorx_latest_authority_set_id + 1;
        let next_authority_set_hash = contract
            .authoritySetIdToHash(next_authority_set_id)
            .call()
            .await?;
        let next_authority_set_hash_exists = next_authority_set_hash != B256::ZERO;

        // Return the fetched data
        Ok(RotateContractData {
            current_block: vectorx_latest_block,
            next_authority_set_hash_exists,
        })
    }

    async fn request_rotate(
        &self,
        current_authority_set_id: u64,
    ) -> Result<SP1ProofWithPublicValues> {
        let mut stdin: SP1Stdin = SP1Stdin::new();

        let proof_type = ProofType::RotateProof;
        let fetcher = RpcDataFetcher::try_new().await?;
        let rotate_input = fetcher
            .get_rotate_inputs(current_authority_set_id)
            .await
            .context("Failed to get the rotate inputs")?;

        stdin.write(&proof_type);
        stdin.write(&rotate_input);

        info!(
            "Requesting rotate proof to add authority set {}.",
            current_authority_set_id + 1
        );

        // If the SP1_PROVER environment variable is set to "mock", use the mock prover.
        let mock = env::var("SP1_PROVER")?.to_lowercase() == "mock";
        let proof = if mock {
            info!(
                "Using mock proof to add authority set {}.",
                current_authority_set_id
            );
            let prover_client = ProverClient::builder().mock().build().await;
            let mock_pk = prover_client
                .setup(Elf::Static(SP1_VECTOR_ELF))
                .await
                .expect("failed to setup mock prover");
            let proof = prover_client.prove(&mock_pk, stdin).plonk().await?;
            Ok(proof)
        } else {
            let spn = env::var("SP1_PROVER")?.to_lowercase() == "network";
            return if spn {
                info!(
                    "Using spn proof to add authority set {}.",
                    current_authority_set_id
                );
                let spn_client = ProverClient::builder().network().build().await;
                let balance = spn_client.get_balance().await?;
                info!(message = "Available balance", balance = balance.to_string());

                let network_pk = spn_client
                    .setup(Elf::Static(SP1_VECTOR_ELF))
                    .await
                    .expect("failed to setup network prover");
                let proof = spn_client
                    .prove(&network_pk, stdin)
                    .strategy(FulfillmentStrategy::Auction)
                    .min_auction_period(10)
                    .plonk()
                    .timeout(Duration::from_secs(PROOF_TIMEOUT_SECS))
                    .await;
                proof
            } else {
                info!(
                    "Using env defined client to add authority set {}.",
                    current_authority_set_id
                );
                let proof = self.prover.prove(&self.pk, stdin).plonk().await;
                proof
            };
        };
        proof
    }

    // Determine if a rotate is needed and request the proof if so. Returns Option<current_authority_set_id>.
    #[instrument(skip(self))]
    async fn find_rotate(&self, chain_id: u64) -> Result<Option<u64>> {
        debug!("finding rotate for chain {}", chain_id);

        let rotate_contract_data = self.get_contract_data_for_rotate(chain_id).await?;
        debug!("rotate_contract_data: {:?}", rotate_contract_data);

        // Get the current block and authority set id from the Avail chain.
        let head_block = self.fetcher.get_head().await?.number;
        debug!("head_block: {}", head_block);

        let head_authority_set_id = self.fetcher.get_authority_set_id(head_block - 1).await?;
        debug!("head_authority_set_id: {}", head_authority_set_id);

        // The current authority set id is the authority set id of the block before the current block.
        let current_authority_set_id = self
            .fetcher
            .get_authority_set_id(rotate_contract_data.current_block - 1)
            .await?;
        debug!("current_authority_set_id: {}", current_authority_set_id);

        if current_authority_set_id < head_authority_set_id
            && !rotate_contract_data.next_authority_set_hash_exists
        {
            return Ok(Some(current_authority_set_id));
        }
        Ok(None)
    }
}

////////////////////////////////////////////////////////////
// Control Flow & SP1
////////////////////////////////////////////////////////////

impl<P, N> SP1VectorOperator<P, N>
where
    P: Provider<N>,
    N: Network,
{
    /// Run `f` for each chain, with a timeout per chain. A chain that fails is logged and left
    /// out, so it does not stop the other chains.
    ///
    /// Returns the values of the chains that succeeded, and whether any chain failed.
    async fn for_each_chain<T, F, Fut>(
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

    /// Create and relay a header range proof for each chain.
    ///
    /// If any step of this function fails, it will return a generic error indicating a failure.
    async fn handle_header_range(&self, chain_ids: &[u64]) -> Result<()> {
        let block_interval = get_block_update_interval();

        let (header_range_datas, mut has_errors) = self
            .for_each_chain(chain_ids, "Finding the header range", |id| {
                self.find_header_range(id, block_interval)
            })
            .await;

        // Batch the chains with the same header range request data.
        let mut header_range_data_to_chain_id: HashMap<_, Vec<u64>> = HashMap::new();
        header_range_datas
            .into_iter()
            .filter(|(_, header_range_data)| header_range_data.is_some())
            .for_each(|(id, header_range_data)| {
                header_range_data_to_chain_id
                    .entry(header_range_data.unwrap())
                    .or_default()
                    .push(id);
            });

        debug!(
            "header_range_data_to_chain_id: {:?}",
            header_range_data_to_chain_id
        );

        // Create a single proof for all the chain with the same header range request data, then relay to each chain.
        let results = join_all(header_range_data_to_chain_id.into_iter().map(
            |(header_range_data, chain_ids)| async move {
                let proof = self
                    .request_header_range(
                        self.tree_size.expect("Tree size not set"),
                        header_range_data,
                    )
                    .await?;

                info!(
                    "Created header range proof for chain {:?} of {:?}",
                    chain_ids, header_range_data
                );

                // Relay the transaction to all chains.
                let tx_hash_futs: Vec<_> = chain_ids
                    .into_iter()
                    .map(|chain_id| {
                        let contract = self
                            .contracts
                            .get(&chain_id)
                            .expect("No contract for chain id");

                        let tx = contract
                            .commitHeaderRange(
                                proof.bytes().into(),
                                proof.public_values.to_vec().into(),
                            )
                            .into_transaction_request();

                        async move {
                            match self
                                .relay_tx(chain_id, tx)
                                .await
                                .context(format!("Relaying proof for chain {chain_id} failed"))
                            {
                                Ok(tx_hash) => Ok((chain_id, tx_hash)),
                                Err(e) => Err(e),
                            }
                        }
                    })
                    .collect();

                Result::<_, anyhow::Error>::Ok(join_all(tx_hash_futs).await)
            },
        ))
        .await;

        // Check if any of the futures failed.
        // There are two cases where a future can fail here:
        // - Creating the header range proof failed.
        // - Relaying the transaction failed.
        //
        // In either case log it and indicate the failure to the caller.
        for batch_result in results {
            if let Err(e) = batch_result {
                has_errors = true;
                error!("Error creating header range proof: {:?}", e);
            } else {
                for relay_result in batch_result.unwrap() {
                    if let Ok((chain_id, tx_hash)) = relay_result {
                        info!(
                            "Posted next header range on chain {}\nTransaction hash: {}",
                            chain_id, tx_hash
                        );
                    } else {
                        has_errors = true;
                        error!(
                            "Error relaying header range proof: {:?}",
                            relay_result.unwrap_err()
                        );
                    }
                }
            }
        }

        if has_errors {
            return Err(anyhow::anyhow!("Error during `handle_header_range`!"));
        }

        Ok(())
    }

    /// Create and relay proof for each chain of an authority set rotation.
    ///
    /// If any step of this function fails, it will return a generic error indicating a failure.
    async fn handle_rotate(&self, chain_ids: &[u64]) -> Result<()> {
        debug!("Enter handle rotate");

        let (next_authority_set_ids, mut has_errors) = self
            .for_each_chain(chain_ids, "Finding the rotate", |id| self.find_rotate(id))
            .await;

        // "Batch" the chains by the next authority set id.
        let mut next_authority_set_to_chain_ids_map: HashMap<u64, Vec<u64>> =
            HashMap::with_capacity(next_authority_set_ids.len());

        // Populate the map with the next authority set ids.
        next_authority_set_ids
            .into_iter()
            .filter(|(_, next_authority_set_id)| next_authority_set_id.is_some())
            .for_each(|(chain_id, next_authority_set_id)| {
                next_authority_set_to_chain_ids_map
                    .entry(next_authority_set_id.unwrap())
                    .or_default()
                    .push(chain_id);
            });

        debug!(
            "next_authority_set_to_chain_ids_map: {:?}",
            next_authority_set_to_chain_ids_map
        );

        // Create and relay a proof for each back to all the chains concurrently.
        let results = join_all(next_authority_set_to_chain_ids_map.into_iter().map(
            |(next_auth_id, chain_ids)| async move {
                let proof = self.request_rotate(next_auth_id).await.context(format!(
                    "Failed to request rotate proof for chains {:?}",
                    chain_ids
                ))?;

                info!(
                    "Created rotate proof for authority set {} on chains {:?}",
                    next_auth_id, chain_ids
                );

                // Relay the transaction to all chains.
                let tx_hash_futs: Vec<_> = chain_ids
                    .into_iter()
                    .map(|chain_id| {
                        let contract = self
                            .contracts
                            .get(&chain_id)
                            .expect("No contract for chain id");

                        let tx = contract
                            .rotate(proof.bytes().into(), proof.public_values.to_vec().into())
                            .into_transaction_request();

                        async move {
                            match self
                                .relay_tx(chain_id, tx)
                                .await
                                .context(format!("Relaying proof for chain {chain_id} failed"))
                            {
                                Ok(tx_hash) => Ok((chain_id, tx_hash)),
                                Err(e) => Err(e),
                            }
                        }
                    })
                    .collect();

                Result::<_, anyhow::Error>::Ok(join_all(tx_hash_futs).await)
            },
        ))
        .await;

        // Check if any of the futures failed.
        // There are two cases where a future can fail here:
        // - Creating the rotate proof failed.
        // - Relaying the transaction failed.
        //
        // In either case log it and indicate the failure to the caller.
        for batch_result in results {
            if let Err(e) = batch_result {
                has_errors = true;
                error!("Error creating rotate proof: {:?}", e);
            } else {
                for relay_result in batch_result.unwrap() {
                    if let Ok((chain_id, tx_hash)) = relay_result {
                        info!(
                            "Posted next authority set on chain {}\nTransaction hash: {}",
                            chain_id, tx_hash
                        );
                    } else {
                        has_errors = true;
                        error!(
                            "Error relaying rotate proof: {:?}",
                            relay_result.unwrap_err()
                        );
                    }
                }
            }
        }

        if has_errors {
            Err(anyhow::anyhow!("Error during `handle_rotate`!"))
        } else {
            Ok(())
        }
    }

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
    async fn relay_tx(&self, chain_id: u64, tx: N::TransactionRequest) -> Result<B256> {
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
            return Err(anyhow::anyhow!(""));
        }

        Ok(())
    }

    // Run the operator, indefinitely.
    async fn run(self) -> Result<()> {
        let job_interval = Duration::from_secs(get_job_interval_mins() * 60);

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

        info!("Sleeping for {:?} minutes", job_interval.as_secs() / 60);
        Ok(())
    }
}

// returns the interval of the job that triggers the operator
fn get_job_interval_mins() -> u64 {
    let mut loop_interval_mins = 60;
    if let Ok(job_interval_mins_env) = env::var("LOOP_INTERVAL_MINS") {
        loop_interval_mins = job_interval_mins_env
            .parse::<u64>()
            .expect("invalid LOOP_INTERVAL_MINS");
    }
    loop_interval_mins
}

fn get_block_update_interval() -> u32 {
    let mut block_update_interval = 360;
    if let Ok(block_update_interval_env) = env::var("BLOCK_UPDATE_INTERVAL") {
        block_update_interval = block_update_interval_env
            .parse::<u32>()
            .expect("invalid BLOCK_UPDATE_INTERVAL");
    }
    block_update_interval
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
    run_result
}

/// The configured secret values. `main` sets it once the chain config is loaded.
static LOG_REDACTOR: OnceLock<Redactor> = OnceLock::new();

/// Writes log lines with the path and query of every URL redacted. RPC URLs carry API keys, and
/// errors from the HTTP and RPC libraries print the URL that failed. Once `LOG_REDACTOR` is set,
/// the configured secret values are removed as well.
///
/// The `tracing` fmt layer passes each event in one `write` call, so a URL is never split.
struct RedactingWriter<W>(W);

impl<W: Write> Write for RedactingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let text = String::from_utf8_lossy(buf);
        let line = match LOG_REDACTOR.get() {
            Some(redactor) => redactor.redact(&text),
            None => redact_urls(&text),
        };
        self.0.write_all(line.as_bytes())?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::RedactingWriter;
    use std::io::Write;
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::layer::SubscriberExt;

    #[derive(Clone, Default)]
    struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

    impl Write for SharedBuffer {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// An error with a key-bearing URL, logged the way the operator logs errors, must reach the
    /// output without the key. The JSON layer is the one `main` installs.
    #[test]
    fn log_lines_have_no_url_path() {
        let buffer = SharedBuffer::default();
        let writer = buffer.clone();
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_writer(move || RedactingWriter(writer.clone())),
        );

        tracing::subscriber::with_default(subscriber, || {
            let error = anyhow::anyhow!(
                r#"reqwest::Error {{ kind: Request, url: "https://rpc.example/v2/SECRET_KEY" }}"#
            )
            .context("error sending request for url (https://rpc.example/v2/SECRET_KEY)");
            tracing::error!("Error during `handle_rotate`: {:?}", error);
        });

        let output = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
        // The redacted line is still one valid JSON object.
        serde_json::from_str::<serde_json::Value>(&output).expect("log line is not valid JSON");
        assert!(output.contains("handle_rotate"), "{output}");
        assert!(
            output.contains("https://rpc.example/<redacted>"),
            "{output}"
        );
        assert!(!output.contains("SECRET_KEY"), "{output}");
    }
}

mod config {
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
        /// Tries to read from the `CHAINS_PATH` environment variable, then the default path (`../chains.json`).
        ///
        /// If neither are set, it will try to use [`Self::from_env`].
        pub fn fetch() -> Result<Vec<Self>> {
            const DEFAULT_PATH: &str = "chains.json";

            let path = env::var("CHAINS_PATH").unwrap_or(DEFAULT_PATH.to_string());

            Self::from_file(&path).or_else(|_| {
                tracing::info!("No chains file found, trying env.");
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
}
