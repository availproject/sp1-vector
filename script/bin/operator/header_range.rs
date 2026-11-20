//! Header range: find the block to step to, request the proof, and relay it to each chain.

use std::cmp::min;
use std::collections::HashMap;
use std::env;

use alloy::{network::Network, primitives::B256, providers::Provider};
use anyhow::{Context, Result};
use futures::future::join_all;
use services::input::{HeaderRangeRequestData, RpcDataFetcher};
use sp1_sdk::{SP1ProofWithPublicValues, SP1Stdin};
use sp1_vector_primitives::types::ProofType;
use tracing::{debug, error, info, instrument};

use crate::operator::SP1VectorOperator;

#[derive(Debug)]
struct HeaderRangeContractData {
    vectorx_latest_block: u32,
    avail_current_block: u32,
    header_range_commitment_tree_size: u32,
    next_authority_set_hash_exists: bool,
}

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

        self.prove(stdin, "insert header range proof").await
    }

    // Ideally, post a header range update every ideal_block_interval blocks. Returns the request
    // data (trusted block and target block), or None when no step is possible yet.
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

    // The contract's latest block and tree size, the Avail head, and whether the next authority
    // set hash exists.
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
    // 1. If the authority set that signs the target has ended and its last justified block is in
    // range, step to that block.
    // 2. Otherwise start at the highest multiple of ideal_block_interval that is in range, and
    // return the first block from there on that has a justification.
    // 3. If no block up to the maximum valid block has a justification, return None.
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

        // Check that block_to_step_to has a valid justification. If not, iterate up until max_valid_block_to_step_to
        // to find a valid justification. If we're unable to find a justification, something has gone
        // deeply wrong with the justification indexer.
        let first_block_searched = block_to_step_to;
        loop {
            if block_to_step_to > max_valid_block_to_step_to {
                error!(
                    "Unable to find any valid justifications after searching from block {} to block {}. This is likely caused by an issue with the justification indexer.",
                    first_block_searched,
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

    /// Create and relay a header range proof for each chain.
    ///
    /// If any step of this function fails, it will return a generic error indicating a failure.
    pub(crate) async fn handle_header_range(&self, chain_ids: &[u64]) -> Result<()> {
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
