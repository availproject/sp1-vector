use std::env;
use std::time::Duration;
use std::{cmp::min, collections::HashMap};

use alloy::network::{ReceiptResponse, TransactionBuilder};
use alloy::signers::local::PrivateKeySigner;
use alloy::{
    network::Network,
    primitives::{Address, B256},
    providers::{Provider, ProviderBuilder},
    sol,
};
use futures::future::{join_all, try_join_all};

use anyhow::{Context, Result};
use services::input::{HeaderRangeRequestData, RpcDataFetcher};
use sp1_sdk::NetworkProver;
use sp1_sdk::{
    network::FulfillmentStrategy, HashableKey, Prover, ProverClient, SP1ProofWithPublicValues,
    SP1ProvingKey, SP1Stdin, SP1VerifyingKey,
};

use tracing::{debug, error, info, instrument};
use tracing_subscriber::EnvFilter;

use services::Timeout;
use sp1_vector_primitives::types::ProofType;
use sp1_vectorx_script::relay::{self};
use sp1_vectorx_script::SP1_VECTOR_ELF;

use config::{ChainConfig, SignerMode};

////////////////////////////////////////////////////////////
// Constants
////////////////////////////////////////////////////////////

// If the SP1 proof takes too long to respond, time out.
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
    pk: SP1ProvingKey,
    vk: SP1VerifyingKey,
    signer_mode: SignerMode,
    tree_size: Option<u32>,
    fetcher: RpcDataFetcher,
    prover: NetworkProver,
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

        let prover = ProverClient::builder().network().build();
        let (pk, vk) = prover.setup(SP1_VECTOR_ELF);

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
    /// This function will panic if the tree size doesnt match as expected, or it fails to get the chain id.
    async fn with_chain(mut self, provider: P, address: Address) -> Self {
        let contract = SP1VectorInstance::new(address, provider);

        let tree_size = contract
            .headerRangeCommitmentTreeSize()
            .call()
            .await
            .expect("Failed to get tree size");

        let chain_id = contract
            .provider()
            .get_chain_id()
            .await
            .expect("Failed to get chain id");

        // Register the first tree size.
        if self.tree_size.is_none() {
            self.tree_size = Some(tree_size);
        } else if self.tree_size.unwrap() != tree_size {
            panic!(
                "Tree size mismatch! Expected {}, got {} for chain id {}",
                self.tree_size.unwrap(),
                tree_size,
                chain_id
            );
        }

        self.contracts.insert(chain_id, contract);

        self
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
            .await;

        stdin.write(&proof_type);
        stdin.write(&header_range_inputs);

        info!(
            "Requesting header range proof from block {} to block {}.",
            header_range_request.trusted_block, header_range_request.target_block
        );

        // If the SP1_PROVER environment variable is set to "mock", use the mock prover.
        if let Ok(prover_type) = env::var("SP1_PROVER") {
            if prover_type == "mock" {
                let prover_client = ProverClient::builder().mock().build();
                let proof = prover_client.prove(&self.pk, &stdin).plonk().run()?;
                return Ok(proof);
            }
        }

        self.prover
            .prove(&self.pk, &stdin)
            .strategy(FulfillmentStrategy::Reserved)
            .skip_simulation(true)
            .plonk()
            .timeout(Duration::from_secs(PROOF_TIMEOUT_SECS))
            .run_async()
            .await
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
            .await;

        info!("current_authority_set_id: {}", current_authority_set_id);
        // Get the last justified block by the current authority set id.
        let last_justified_block = self
            .fetcher
            .last_justified_block(current_authority_set_id)
            .await;

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
            .await;

        info!("Target Block: {:?}", maybe_block_to_step_to);

        if let Some(block_to_step_to) = maybe_block_to_step_to {
            return Ok(Some(HeaderRangeRequestData {
                trusted_block: header_range_contract_data.vectorx_latest_block,
                target_block: block_to_step_to,
                is_target_epoch_end_block: block_to_step_to == last_justified_block,
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

        let avail_current_block = self.fetcher.get_head().await.number;

        let vectorx_current_authority_set_id = self
            .fetcher
            .get_authority_set_id(vectorx_latest_block - 1)
            .await;
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
    async fn find_block_to_step_to(
        &self,
        ideal_block_interval: u32,
        header_range_commitment_tree_size: u32,
        vectorx_current_block: u32,
        avail_current_block: u32,
        authority_set_id: u64,
    ) -> Option<u32> {
        let fetcher = RpcDataFetcher::new().await;
        let last_justified_block = fetcher.last_justified_block(authority_set_id).await;

        // Step to the last justified block of the current epoch if it is in range. When the last
        // justified block is 0, the SP1Vector contract's latest epoch is the current epoch on the
        // Avail chain.
        if last_justified_block != 0
            && last_justified_block <= vectorx_current_block + header_range_commitment_tree_size
        {
            debug!("last_justified_block: {}", last_justified_block);
            return Some(last_justified_block);
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
            return None;
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
                return None;
            }

            if fetcher
                .get_justification_data_for_block(block_to_step_to, false)
                .await
                .is_some()
            {
                break;
            }
            block_to_step_to += 1;
        }

        Some(block_to_step_to)
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
        let fetcher = RpcDataFetcher::new().await;

        let mut stdin: SP1Stdin = SP1Stdin::new();

        let proof_type = ProofType::RotateProof;
        let rotate_input = fetcher.get_rotate_inputs(current_authority_set_id).await;

        stdin.write(&proof_type);
        stdin.write(&rotate_input);

        info!(
            "Requesting rotate proof to add authority set {}.",
            current_authority_set_id + 1
        );

        // If the SP1_PROVER environment variable is set to "mock", use the mock prover.
        if let Ok(prover_type) = env::var("SP1_PROVER") {
            if prover_type == "mock" {
                let prover_client = ProverClient::builder().mock().build();
                let proof = prover_client.prove(&self.pk, &stdin).plonk().run()?;
                return Ok(proof);
            }
        }

        self.prover
            .prove(&self.pk, &stdin)
            .strategy(FulfillmentStrategy::Reserved)
            .skip_simulation(true)
            .plonk()
            .timeout(Duration::from_secs(PROOF_TIMEOUT_SECS))
            .run_async()
            .await
    }

    // Determine if a rotate is needed and request the proof if so. Returns Option<current_authority_set_id>.
    #[instrument(skip(self))]
    async fn find_rotate(&self, chain_id: u64) -> Result<Option<u64>> {
        debug!("finding rotate for chain {}", chain_id);

        let rotate_contract_data = self.get_contract_data_for_rotate(chain_id).await?;
        debug!("rotate_contract_data: {:?}", rotate_contract_data);

        // Get the current block and authority set id from the Avail chain.
        let head_block = self.fetcher.get_head().await.number;
        debug!("head_block: {}", head_block);

        let head_authority_set_id = self.fetcher.get_authority_set_id(head_block - 1).await;
        debug!("head_authority_set_id: {}", head_authority_set_id);

        // The current authority set id is the authority set id of the block before the current block.
        let current_authority_set_id = self
            .fetcher
            .get_authority_set_id(rotate_contract_data.current_block - 1)
            .await;
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
    /// Create and relay a header range proof for each chain.
    ///
    /// If any step of this function fails, it will return a generic error indicating a failure.
    async fn handle_header_range(&self) -> Result<()> {
        let block_interval = get_block_update_interval();

        // NOTE: Fails fast if any of the futures fail.
        let header_range_datas =
            try_join_all(self.contracts.keys().copied().map(|id| async move {
                Result::<_, anyhow::Error>::Ok((
                    id,
                    self.find_header_range(id, block_interval).await?,
                ))
            }))
            .timeout(Duration::from_secs(RPC_TIMEOUT_SECS))
            .await??;

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
        // - Creating the rotate proof failed.
        // - Relaying the transaction failed.
        //
        // In either case log it and indicate the failure to the caller.
        let mut has_errors = false;
        for batch_result in results {
            if let Err(e) = batch_result {
                has_errors = true;
                error!("Error creating rotate proof: {:?}", e);
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
                            "Error relaying rotate proof: {:?}",
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
    async fn handle_rotate(&self) -> Result<()> {
        debug!("Enter handle rotate");

        let next_authority_set_ids = self.contracts.keys().copied().map(|id| async move {
            Result::<_, anyhow::Error>::Ok((id, self.find_rotate(id).await?))
        });

        // NOTE: Fails fast if any of the futures fail.
        let next_authority_set_ids = try_join_all(next_authority_set_ids)
            .timeout(Duration::from_secs(RPC_TIMEOUT_SECS))
            .await??;

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
        let mut has_errors = false;
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
        } else {
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

            Ok(receipt.transaction_hash())
        }
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

        // NOTE: Fails fast if any of the futures fail.
        try_join_all(self.contracts.keys().copied().map(|id| self.check_vkey(id))).await?;

        if let Err(e) = self.handle_rotate().await {
            has_errors = true;
            error!("Error during `handle_rotate`: {:?}", e);
        }

        if let Err(e) = self.handle_header_range().await {
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
    async fn run(self) {
        let loop_interval = Duration::from_secs(get_loop_interval_mins() * 60);
        let error_interval = Duration::from_secs(10);

        loop {
            tokio::select! {
                res = self.run_once() => {
                    if let Err(e) = res {
                        error!("Error during `run_once`: {:?}", e);
                        // Sleep for less time if theres an error.
                        tokio::time::sleep(error_interval).await;
                        continue;
                    }
                },
                _ = tokio::time::sleep(Duration::from_secs(LOOP_TIMEOUT_MINS * 60)) => {
                    continue;
                }
            }

            tracing::info!(
                "Operator ran successfully, sleeping for {} seconds",
                loop_interval.as_secs()
            );

            // Sleep for the loop interval.
            tokio::time::sleep(loop_interval).await;
        }
    }
}

fn get_loop_interval_mins() -> u64 {
    let loop_interval_mins_env = env::var("LOOP_INTERVAL_MINS");
    let mut loop_interval_mins = 60;
    if loop_interval_mins_env.is_ok() {
        loop_interval_mins = loop_interval_mins_env
            .unwrap()
            .parse::<u64>()
            .expect("invalid LOOP_INTERVAL_MINS");
    }
    loop_interval_mins
}

fn get_block_update_interval() -> u32 {
    let block_update_interval_env = env::var("BLOCK_UPDATE_INTERVAL");
    let mut block_update_interval = 360;
    if block_update_interval_env.is_ok() {
        block_update_interval = block_update_interval_env
            .unwrap()
            .parse::<u32>()
            .expect("invalid BLOCK_UPDATE_INTERVAL");
    }
    block_update_interval
}

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    tracing_subscriber::fmt::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::from_env("info")),
        )
        .init();

    let signer_mode = env::var("SIGNER_MODE")
        .map(|v| v.parse().unwrap())
        .unwrap_or(SignerMode::Local);
    let config = ChainConfig::fetch().expect("Failed to fetch chain config");

    match signer_mode {
        SignerMode::Local => run_with_signer(config).await,
        SignerMode::Kms => run_with_kms(config).await,
    }
}

async fn run_with_signer(config: Vec<ChainConfig>) {
    let mut operator = SP1VectorOperator::new(SignerMode::Local).await;

    let signer: PrivateKeySigner = env::var("PRIVATE_KEY")
        .expect("PRIVATE_KEY must be set")
        .parse()
        .expect("Failed to parse PRIVATE_KEY");

    for c in config {
        let provider = ProviderBuilder::new()
            .wallet(signer.clone())
            .on_http(c.rpc_url.parse().expect("Failed to parse RPC URL"));

        operator = operator.with_chain(provider, c.vector_address).await;
    }

    operator.run().await
}

async fn run_with_kms(config: Vec<ChainConfig>) {
    let mut operator = SP1VectorOperator::new(SignerMode::Kms).await;

    for c in config {
        let provider =
            ProviderBuilder::new().on_http(c.rpc_url.parse().expect("Failed to parse RPC URL"));

        operator = operator.with_chain(provider, c.vector_address).await;
    }

    operator.run().await
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
