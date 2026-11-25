//! Rotate: find a missing authority set, request the proof, and relay it to each chain.

use std::collections::HashMap;

use alloy::{network::Network, primitives::B256, providers::Provider};
use anyhow::{Context, Result};
use futures::future::join_all;
use services::input::RpcDataFetcher;
use sp1_sdk::{SP1ProofWithPublicValues, SP1Stdin};
use sp1_vector_primitives::types::ProofType;
use tracing::{debug, error, info, instrument};

use crate::operator::SP1VectorOperator;

#[derive(Debug)]
struct RotateContractData {
    current_block: u32,
    next_authority_set_hash_exists: bool,
}

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

        let next_authority_set_id = current_authority_set_id + 1;
        info!(
            "Requesting rotate proof to add authority set {}.",
            next_authority_set_id
        );

        self.prove(
            stdin,
            &format!("add authority set {}", next_authority_set_id),
        )
        .await
    }

    // Determine if a rotate is needed. Returns Option<current_authority_set_id>.
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

    /// Create and relay proof for each chain of an authority set rotation.
    ///
    /// If any step of this function fails, it will return a generic error indicating a failure.
    pub(crate) async fn handle_rotate(&self, chain_ids: &[u64]) -> Result<()> {
        debug!("Enter handle rotate");

        let (next_authority_set_ids, mut has_errors) = self
            .for_each_chain(chain_ids, "Finding the rotate", |id| self.find_rotate(id))
            .await;

        // "Batch" the chains by the authority set id that `find_rotate` returns. That is the
        // chain's current set id, and the rotate adds the set after it.
        let mut next_authority_set_to_chain_ids_map: HashMap<u64, Vec<u64>> =
            HashMap::with_capacity(next_authority_set_ids.len());

        // Populate the map with these current authority set ids.
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
}
