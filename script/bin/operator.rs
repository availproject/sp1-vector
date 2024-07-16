use std::cmp::min;
use std::env;

use alloy::sol_types::SolValue;
use alloy::{primitives::B256, sol};
use anyhow::Result;
use log::{error, info};
use nodekit_seq_sdk::client::jsonrpc_client;
use serde::{Deserialize, Serialize};
use services::input::RpcDataFetcher;
use sp1_recursion_gnark_ffi::PlonkBn254Proof;
use sp1_sdk::{ProverClient, SP1PlonkBn254Proof, SP1ProvingKey, SP1Stdin, SP1VerifyingKey};
use sp1_vector_primitives::types::ProofType;
use std::{fs::File, io::Write};

const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

sol! {

    struct CommitHeaderRangeAndRotateInput{
        bytes proof;
        bytes publicValues;
    }
}

struct VectorXOperator {
    client: ProverClient,
    pk: SP1ProvingKey,
    rpc_client: jsonrpc_client::JSONRPCClient,
    // contract address
    address: String,
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

#[derive(Serialize, Deserialize)]
struct HelperForJsonFileOutput {
    #[serde(rename = "proof")]
    proof: PlonkBn254Proof,
    #[serde(rename = "verifyingKey")]
    verification_key: SP1VerifyingKey,
}

impl VectorXOperator {
    async fn new() -> Self {
        dotenv::dotenv().ok();

        let client = ProverClient::new();
        let (pk, _) = client.setup(ELF);

        let rpc_client = jsonrpc_client::JSONRPCClient::new(
            env::var("RPC_URL").unwrap().as_str(),
            env::var("NETWORK_ID").unwrap().parse::<u32>().unwrap(),
            env::var("CHAIN_ID").unwrap(),
        )
        .unwrap();

        let address = env::var("ADDRESS").expect("ADDRESS not set");
        Self {
            client,
            pk,
            rpc_client,
            address,
        }
    }

    async fn request_header_range(
        &self,
        trusted_block: u32,
        target_block: u32,
    ) -> Result<SP1PlonkBn254Proof> {
        let mut stdin: SP1Stdin = SP1Stdin::new();

        let fetcher = RpcDataFetcher::new().await;

        let proof_type = ProofType::HeaderRangeProof;
        // Fetch the header range commitment tree size from the contract.

        let storage_slot = env::var("STORAGE_SLOT_HEADER_RANGE_COMMITMENT_TREE_SIZE")
            .unwrap()
            .parse::<u32>()
            .expect("STORAGE_SLOT_HEADER_RANGE_COMMITMENT_TREE_SIZE not set");
        let resp = self
            .rpc_client
            .get_storage_slot_data(self.address.clone(), storage_slot.to_be_bytes().into())
            .unwrap();

        let header_range_commitment_tree_size =
            u32::from_be_bytes(resp.data[0..4].try_into().unwrap());
        let header_range_inputs = fetcher
            .get_header_range_inputs(
                trusted_block,
                target_block,
                Some(header_range_commitment_tree_size),
            )
            .await;

        stdin.write(&proof_type);
        stdin.write(&header_range_inputs);

        info!(
            "Requesting header range proof from block {} to block {}.",
            trusted_block, target_block
        );

        let proof = self.client.prove_plonk(&self.pk, stdin).unwrap();
        let helper_output = HelperForJsonFileOutput {
            proof: proof.proof.clone(),
            verification_key: self.pk.vk.clone(),
        };
        let json_output = serde_json::to_string(&helper_output).unwrap();
        let file_name = format!("proof_{}_{}.json", trusted_block, target_block);
        // Create a file and write the data
        let mut file = File::create(file_name).expect("Unable to create file");
        file.write_all(json_output.as_bytes())
            .expect("Unable to write data");
        Ok(proof)
    }

    async fn request_rotate(&self, current_authority_set_id: u64) -> Result<SP1PlonkBn254Proof> {
        let fetcher = RpcDataFetcher::new().await;

        let mut stdin: SP1Stdin = SP1Stdin::new();

        let proof_type = ProofType::RotateProof;
        // fetcher inputs are indepedent of destination chain. dependent only on avail chain.
        let rotate_input = fetcher.get_rotate_inputs(current_authority_set_id).await;

        stdin.write(&proof_type);
        stdin.write(&rotate_input);

        info!(
            "Requesting rotate proof to add authority set {}.",
            current_authority_set_id + 1
        );

        let proof = self.client.prove_plonk(&self.pk, stdin).unwrap();
        let helper_output = HelperForJsonFileOutput {
            proof: proof.proof.clone(),
            verification_key: self.pk.vk.clone(),
        };
        let json_output = serde_json::to_string(&helper_output).unwrap();
        let file_name = format!("proof_{}.json", current_authority_set_id);
        // Create a file and write the data
        let mut file = File::create(file_name).expect("Unable to create file");
        file.write_all(json_output.as_bytes())
            .expect("Unable to write data");
        Ok(proof)
    }

    // Determine if a rotate is needed and request the proof if so. Returns Option<current_authority_set_id>.
    async fn find_rotate(&self) -> Result<Option<u64>> {
        let rotate_contract_data = self.get_contract_data_for_rotate().await?;

        let fetcher = RpcDataFetcher::new().await;
        let head = fetcher.get_head().await;
        let head_block = head.number;
        let head_authority_set_id = fetcher.get_authority_set_id(head_block - 1).await;

        // The current authority set id is the authority set id of the block before the current block.
        let current_authority_set_id = fetcher
            .get_authority_set_id(rotate_contract_data.current_block - 1)
            .await;

        if current_authority_set_id < head_authority_set_id
            && !rotate_contract_data.next_authority_set_hash_exists
        {
            return Ok(Some(current_authority_set_id));
        }
        Ok(None)
    }

    // Ideally, post a header range update every ideal_block_interval blocks. Returns Option<(latest_block, block_to_step_to)>.
    async fn find_header_range(&self, ideal_block_interval: u32) -> Result<Option<(u32, u32)>> {
        let header_range_contract_data = self.get_contract_data_for_header_range().await?;

        let fetcher = RpcDataFetcher::new().await;

        // The current authority set id is the authority set id of the block before the current block.
        let current_authority_set_id = fetcher
            .get_authority_set_id(header_range_contract_data.vectorx_latest_block - 1)
            .await;

        // Get the last justified block by the current authority set id.
        let last_justified_block = fetcher.last_justified_block(current_authority_set_id).await;

        // If this is the last justified block, check for header range with next authority set.
        let mut request_authority_set_id = current_authority_set_id;
        println!("last_justified_block: {}", last_justified_block);
        println!(
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
        let block_to_step_to = self
            .find_block_to_step_to(
                ideal_block_interval,
                header_range_contract_data.header_range_commitment_tree_size,
                header_range_contract_data.vectorx_latest_block,
                header_range_contract_data.avail_current_block,
                request_authority_set_id,
            )
            .await;

        println!("block_to_step_to: {:?}", block_to_step_to);

        if let Some(block_to_step_to) = block_to_step_to {
            return Ok(Some((
                header_range_contract_data.vectorx_latest_block,
                block_to_step_to,
            )));
        }
        Ok(None)
    }

    // Current block, step_range_max and whether next authority set hash exists.
    async fn get_contract_data_for_header_range(&self) -> Result<HeaderRangeContractData> {
        let fetcher = RpcDataFetcher::new().await;

        let storage_slot = env::var("STORAGE_SLOT_LATEST_BLOCK")
            .unwrap()
            .parse::<u32>()
            .expect("STORAGE_SLOT_LATEST_BLOCK not set");

        let resp = self
            .rpc_client
            .get_storage_slot_data(self.address.clone(), storage_slot.to_be_bytes().into())
            .unwrap();

        let vectorx_latest_block = u32::from_be_bytes(resp.data[0..4].try_into().unwrap());

        let storage_slot = env::var("STORAGE_SLOT_HEADER_RANGE_COMMITMENT_TREE_SIZE")
            .unwrap()
            .parse::<u32>()
            .expect("STORAGE_SLOT_HEADER_RANGE_COMMITMENT_TREE_SIZE not set");
        let resp = self
            .rpc_client
            .get_storage_slot_data(self.address.clone(), storage_slot.to_be_bytes().into())
            .unwrap();

        let header_range_commitment_tree_size =
            u32::from_be_bytes(resp.data[0..4].try_into().unwrap());

        let avail_current_block = fetcher.get_head().await.number;

        let vectorx_current_authority_set_id =
            fetcher.get_authority_set_id(vectorx_latest_block - 1).await;
        let next_authority_set_id = vectorx_current_authority_set_id + 1;

        let storage_slot_map_identifier =
            env::var("STORAGE_SLOT_MAPPING_AUTHORITY_SET_ID_TO_HASH_ID")
                .unwrap()
                .parse::<u32>()
                .expect("STORAGE_SLOT_MAPPING_AUTHORITY_SET_ID_TO_HASH_ID not set");

        let mut storage_slot = storage_slot_map_identifier.to_be_bytes().to_vec();
        storage_slot.append(&mut next_authority_set_id.to_be_bytes().to_vec());

        let resp = self
            .rpc_client
            .get_storage_slot_data(self.address.clone(), storage_slot)
            .unwrap();
        let next_authority_set_hash = B256::from_slice(&resp.data[0..32]);
        Ok(HeaderRangeContractData {
            vectorx_latest_block,
            avail_current_block,
            header_range_commitment_tree_size,
            next_authority_set_hash_exists: next_authority_set_hash != B256::ZERO,
        })
    }

    // Current block and whether next authority set hash exists.
    async fn get_contract_data_for_rotate(&self) -> Result<RotateContractData> {
        // Fetch the current block from the contract
        let storage_slot = env::var("STORAGE_SLOT_LATEST_BLOCK")
            .unwrap()
            .parse::<u32>()
            .expect("STORAGE_SLOT_LATEST_BLOCK not set");

        let resp = self
            .rpc_client
            .get_storage_slot_data(self.address.clone(), storage_slot.to_be_bytes().into())
            .unwrap();

        let vectorx_latest_block = u32::from_be_bytes(resp.data[0..4].try_into().unwrap());

        // Fetch the current authority set id from the contract
        let storage_slot = env::var("STORAGE_SLOT_LATEST_AUTHORITY_SET_ID")
            .unwrap()
            .parse::<u32>()
            .expect("STORAGE_SLOT_LATEST_AUTHORITY_SET_ID not set");

        let resp = self
            .rpc_client
            .get_storage_slot_data(self.address.clone(), storage_slot.to_be_bytes().into())
            .unwrap();

        let vectorx_latest_authority_set_id =
            u64::from_be_bytes(resp.data[0..8].try_into().unwrap());

        // Check if the next authority set id exists in the contract
        let next_authority_set_id = vectorx_latest_authority_set_id + 1;
        let storage_slot_map_identifier =
            env::var("STORAGE_SLOT_MAPPING_AUTHORITY_SET_ID_TO_HASH_ID")
                .unwrap()
                .parse::<u32>()
                .expect("STORAGE_SLOT_MAPPING_AUTHORITY_SET_ID_TO_HASH_ID not set");

        let mut storage_slot = storage_slot_map_identifier.to_be_bytes().to_vec();
        storage_slot.append(&mut next_authority_set_id.to_be_bytes().to_vec());

        let resp = self
            .rpc_client
            .get_storage_slot_data(self.address.clone(), storage_slot)
            .unwrap();
        let next_authority_set_hash = B256::from_slice(&resp.data[0..32]);

        let next_authority_set_hash_exists = next_authority_set_hash != B256::ZERO;

        // Return the fetched data
        Ok(RotateContractData {
            current_block: vectorx_latest_block,
            next_authority_set_hash_exists,
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
            return Some(last_justified_block);
        }

        // The maximum valid block to step to is the either header_range_commitment_tree_size blocks
        // ahead of the current block in the contract or the latest block on Avail.
        let max_valid_block_to_step_to = min(
            vectorx_current_block + header_range_commitment_tree_size,
            avail_current_block,
        );

        println!("max_valid_block_to_step_to: {}", max_valid_block_to_step_to);
        println!("avail_current_block: {}", avail_current_block);
        println!("block interval: {}", ideal_block_interval);

        // Find the closest block to the maximum valid block to step to that is a multiple of
        // ideal_block_interval.
        let mut block_to_step_to =
            max_valid_block_to_step_to - (max_valid_block_to_step_to % ideal_block_interval);

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
                .get_justification_data_for_block(block_to_step_to)
                .await
                .is_some()
            {
                break;
            }
            block_to_step_to += 1;
        }

        Some(block_to_step_to)
    }

    /// Relay a header range proof to the SP1 SP1Vector contract.
    async fn relay_header_range(&self, proof: SP1PlonkBn254Proof) -> Result<String> {
        let public_value_bytes = proof.public_values.to_vec();

        let input = CommitHeaderRangeAndRotateInput {
            // raw proof is used to verify the plonk proof in gnark.
            // solidity verifier uses encoded proof, packed by first 4 bytes with sp1 version identefier.
            proof: proof.proof.raw_proof.into(),
            // public value bytes are same as the public inputs accepted/used during proof generation.
            // public value bytes contain the proof type of header range or request.
            publicValues: public_value_bytes.into(),
        };

        let tx_reply = self
            .rpc_client
            .submit_transact_tx(
                String::from("commit_header_range"),
                self.address.clone(),
                input.abi_encode(),
            )
            .unwrap();
        Ok(tx_reply.tx_id)
    }

    /// Relay a rotate proof to the SP1 SP1Vector contract.
    async fn relay_rotate(&self, proof: SP1PlonkBn254Proof) -> Result<String> {
        let public_value_bytes = proof.public_values.to_vec();

        let input = CommitHeaderRangeAndRotateInput {
            // raw proof is used to verify the plonk proof in gnark.
            // solidity verifier uses encoded proof, packed by first 4 bytes with sp1 version identefier.
            proof: proof.proof.raw_proof.into(),
            // public value bytes are same as the public inputs accepted/used during proof generation.
            // public value bytes contain the proof type of header range or request.
            publicValues: public_value_bytes.into(),
        };

        let tx_reply = self
            .rpc_client
            .submit_transact_tx(
                String::from("rotate"),
                self.address.clone(),
                input.abi_encode(),
            )
            .unwrap();
        Ok(tx_reply.tx_id)
    }

    async fn run(&self) -> Result<()> {
        loop {
            let loop_interval_mins = get_loop_interval_mins();
            let block_interval = get_block_update_interval();

            // Check if there is a rotate available for the next authority set.
            let current_authority_set_id = self.find_rotate().await?;

            println!(
                "Current authority set id: {}",
                current_authority_set_id.unwrap_or(0)
            );

            // Request a rotate for the next authority set id.
            if let Some(current_authority_set_id) = current_authority_set_id {
                let proof = self.request_rotate(current_authority_set_id).await?;
                let tx_hash = self.relay_rotate(proof).await?;
                info!(
                    "Added authority set {}\nTransaction ID: {}",
                    current_authority_set_id + 1,
                    tx_hash
                );
            }

            println!("On the way for header range!");

            // Check if there is a header range request available.
            let header_range_request = self.find_header_range(block_interval).await?;

            println!("header_range_request: {:?}", header_range_request);

            if let Some(header_range_request) = header_range_request {
                // Request the header range proof to block_to_step_to.
                let proof = self
                    .request_header_range(header_range_request.0, header_range_request.1)
                    .await;
                match proof {
                    Ok(proof) => {
                        let tx_hash = self.relay_header_range(proof).await?;
                        info!(
                            "Posted data commitment from block {} to block {}\nTransaction ID: {}",
                            header_range_request.0, header_range_request.1, tx_hash
                        );
                    }
                    Err(e) => {
                        error!("Header range proof generation failed: {}", e);
                    }
                };
            }

            // Sleep for N minutes.
            info!("Sleeping for {} minutes.", loop_interval_mins);
            tokio::time::sleep(tokio::time::Duration::from_secs(60 * loop_interval_mins)).await;
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
    env_logger::init();

    let operator = VectorXOperator::new().await;

    loop {
        if let Err(e) = operator.run().await {
            error!("Error running operator: {}", e);
        }
    }
}
