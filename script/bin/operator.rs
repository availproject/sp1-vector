use std::cmp::min;
use std::env;
use std::time::Duration;

use alloy::{
    network::EthereumWallet,
    primitives::{Address, B256},
    providers::ProviderBuilder,
    signers::local::PrivateKeySigner,
    sol,
};
use reqwest::Url;

use anyhow::Result;
use log::{error, info};
use services::input::{HeaderRangeRequestData, RpcDataFetcher};
use sp1_sdk::{
    network::FulfillmentStrategy, HashableKey, Prover, ProverClient, SP1ProofWithPublicValues,
    SP1ProvingKey, SP1Stdin, SP1VerifyingKey,
};
use sp1_vector_primitives::types::ProofType;
use sp1_vectorx_script::relay::{self};
use sp1_vectorx_script::SP1_VECTOR_ELF;

// If the SP1 proof takes too long to respond, time out.
const PROOF_TIMEOUT_SECS: u64 = 60 * 30;

// Wait for 3 required confirmations with a timeout of 60 seconds.
const NUM_CONFIRMATIONS: u64 = 3;
const RELAY_TIMEOUT_SECONDS: u64 = 60;

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
struct VectorXOperator {
    pk: SP1ProvingKey,
    vk: SP1VerifyingKey,
    contract_address: Address,
    rpc_url: Url,
    chain_id: u64,
    use_kms_relayer: bool,
}

#[derive(Debug)]
struct HeaderRangeContractData {
    vectorx_latest_block: u32,
    avail_current_block: u32,
    header_range_commitment_tree_size: u32,
    next_authority_set_hash_exists: bool,
}

const NUM_RELAY_RETRIES: u32 = 3;

#[derive(Debug)]
struct RotateContractData {
    current_block: u32,
    next_authority_set_hash_exists: bool,
}

impl VectorXOperator {
    async fn new() -> Self {
        dotenv::dotenv().ok();

        let client = ProverClient::builder().mock().build();
        let (pk, vk) = client.setup(SP1_VECTOR_ELF);
        let use_kms_relayer: bool = env::var("USE_KMS_RELAYER")
            .unwrap_or("false".to_string())
            .parse()
            .unwrap();
        let chain_id: u64 = env::var("CHAIN_ID")
            .expect("CHAIN_ID not set")
            .parse()
            .unwrap();
        let rpc_url = env::var("RPC_URL")
            .expect("RPC_URL not set")
            .parse()
            .unwrap();

        let contract_address = env::var("CONTRACT_ADDRESS")
            .expect("CONTRACT_ADDRESS not set")
            .parse()
            .unwrap();

        Self {
            pk,
            vk,
            rpc_url,
            chain_id,
            contract_address,
            use_kms_relayer,
        }
    }

    async fn request_header_range(
        &self,
        header_range_request: HeaderRangeRequestData,
    ) -> Result<SP1ProofWithPublicValues> {
        let mut stdin: SP1Stdin = SP1Stdin::new();

        let fetcher = RpcDataFetcher::new().await;

        let proof_type = ProofType::HeaderRangeProof;
        let provider = ProviderBuilder::new().on_http(self.rpc_url.clone());
        // Fetch the header range commitment tree size from the contract.
        let contract = SP1Vector::new(self.contract_address, provider.clone());
        let output = contract
            .headerRangeCommitmentTreeSize()
            .call()
            .await
            .unwrap();
        let header_range_inputs = fetcher
            .get_header_range_inputs(
                header_range_request,
                Some(output.headerRangeCommitmentTreeSize),
            )
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

        let prover_client = ProverClient::builder().network().build();
        prover_client
            .prove(&self.pk, &stdin)
            .strategy(FulfillmentStrategy::Reserved)
            .skip_simulation(true)
            .plonk()
            .timeout(Duration::from_secs(PROOF_TIMEOUT_SECS))
            .run()
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

        let prover_client = ProverClient::builder().network().build();
        prover_client
            .prove(&self.pk, &stdin)
            .strategy(FulfillmentStrategy::Reserved)
            .skip_simulation(true)
            .plonk()
            .timeout(Duration::from_secs(PROOF_TIMEOUT_SECS))
            .run()
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
    async fn find_header_range(
        &self,
        ideal_block_interval: u32,
    ) -> Result<Option<HeaderRangeRequestData>> {
        let header_range_contract_data = self.get_contract_data_for_header_range().await?;

        let fetcher = RpcDataFetcher::new().await;

        // The current authority set id is the authority set id of the block before the current block.
        let current_authority_set_id = fetcher
            .get_authority_set_id(header_range_contract_data.vectorx_latest_block - 1)
            .await;

        info!("current_authority_set_id: {}", current_authority_set_id);
        // Get the last justified block by the current authority set id.
        let last_justified_block = fetcher.last_justified_block(current_authority_set_id).await;

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
        let block_to_step_to = self
            .find_block_to_step_to(
                ideal_block_interval,
                header_range_contract_data.header_range_commitment_tree_size,
                header_range_contract_data.vectorx_latest_block,
                header_range_contract_data.avail_current_block,
                request_authority_set_id,
            )
            .await;

        info!("block_to_step_to: {:?}", block_to_step_to);

        if let Some(block_to_step_to) = block_to_step_to {
            return Ok(Some(HeaderRangeRequestData {
                trusted_block: header_range_contract_data.vectorx_latest_block,
                target_block: block_to_step_to,
                is_target_epoch_end_block: block_to_step_to == last_justified_block,
            }));
        }
        Ok(None)
    }

    // Current block, step_range_max and whether next authority set hash exists.
    async fn get_contract_data_for_header_range(&self) -> Result<HeaderRangeContractData> {
        let fetcher = RpcDataFetcher::new().await;

        let provider = ProviderBuilder::new().on_http(self.rpc_url.clone());
        let contract = SP1Vector::new(self.contract_address, provider);

        let vectorx_latest_block = contract.latestBlock().call().await?.latestBlock;
        let header_range_commitment_tree_size = contract
            .headerRangeCommitmentTreeSize()
            .call()
            .await?
            .headerRangeCommitmentTreeSize;

        let avail_current_block = fetcher.get_head().await.number;

        let vectorx_current_authority_set_id =
            fetcher.get_authority_set_id(vectorx_latest_block - 1).await;
        let next_authority_set_id = vectorx_current_authority_set_id + 1;

        let next_authority_set_hash = contract
            .authoritySetIdToHash(next_authority_set_id)
            .call()
            .await?
            ._0;

        Ok(HeaderRangeContractData {
            vectorx_latest_block,
            avail_current_block,
            header_range_commitment_tree_size,
            next_authority_set_hash_exists: next_authority_set_hash != B256::ZERO,
        })
    }

    // Current block and whether next authority set hash exists.
    async fn get_contract_data_for_rotate(&self) -> Result<RotateContractData> {
        let provider = ProviderBuilder::new().on_http(self.rpc_url.clone());
        let contract = SP1Vector::new(self.contract_address, provider);

        // Fetch the current block from the contract
        let vectorx_latest_block = contract.latestBlock().call().await?.latestBlock;

        // Fetch the current authority set id from the contract
        let vectorx_latest_authority_set_id = contract
            .latestAuthoritySetId()
            .call()
            .await?
            .latestAuthoritySetId;

        // Check if the next authority set id exists in the contract
        let next_authority_set_id = vectorx_latest_authority_set_id + 1;
        let next_authority_set_hash = contract
            .authoritySetIdToHash(next_authority_set_id)
            .call()
            .await?
            ._0;
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

        info!("max_valid_block_to_step_to: {}", max_valid_block_to_step_to);
        info!("avail_current_block: {}", avail_current_block);
        info!("block interval: {}", ideal_block_interval);

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

    /// Relay a header range proof to the SP1 SP1Vector contract.
    async fn relay_header_range(&self, proof: SP1ProofWithPublicValues) -> Result<B256> {
        if self.use_kms_relayer {
            let provider = ProviderBuilder::new().on_http(self.rpc_url.clone());
            let contract = SP1Vector::new(self.contract_address, provider);
            let proof_bytes = proof.bytes().clone().into();
            let public_values = proof.public_values.to_vec().into();
            let commit_header_range = contract.commitHeaderRange(proof_bytes, public_values);
            relay::relay_with_kms(
                &relay::KMSRelayRequest {
                    chain_id: self.chain_id,
                    address: self.contract_address.to_checksum(None),
                    calldata: commit_header_range.calldata().to_string(),
                    platform_request: false,
                },
                NUM_RELAY_RETRIES,
            )
            .await
        } else {
            let private_key = env::var("PRIVATE_KEY").expect("PRIVATE_KEY not set");
            let signer: PrivateKeySigner =
                private_key.parse().expect("Failed to parse private key");
            let wallet = EthereumWallet::from(signer);
            let provider = ProviderBuilder::new()
                .with_recommended_fillers()
                .wallet(wallet)
                .on_http(self.rpc_url.clone());
            let contract = SP1Vector::new(self.contract_address, provider);

            let receipt = contract
                .commitHeaderRange(proof.bytes().into(), proof.public_values.to_vec().into())
                .send()
                .await?
                .with_required_confirmations(NUM_CONFIRMATIONS)
                .with_timeout(Some(Duration::from_secs(RELAY_TIMEOUT_SECONDS)))
                .get_receipt()
                .await?;

            log::debug!("Receipt: {:?}", receipt);

            // If status is false, it reverted.
            if !receipt.status() {
                return Err(anyhow::anyhow!("Transaction reverted!"));
            }

            Ok(receipt.transaction_hash)
        }
    }

    /// Relay a rotate proof to the SP1 SP1Vector contract.
    async fn relay_rotate(&self, proof: SP1ProofWithPublicValues) -> Result<B256> {
        if self.use_kms_relayer {
            let provider = ProviderBuilder::new().on_http(self.rpc_url.clone());
            let contract = SP1Vector::new(self.contract_address, provider);
            let proof_bytes = proof.bytes().clone().into();
            let public_values = proof.public_values.to_vec().into();
            let rotate = contract.rotate(proof_bytes, public_values);
            relay::relay_with_kms(
                &relay::KMSRelayRequest {
                    chain_id: self.chain_id,
                    address: self.contract_address.to_checksum(None),
                    calldata: rotate.calldata().to_string(),
                    platform_request: false,
                },
                NUM_RELAY_RETRIES,
            )
            .await
        } else {
            let private_key = env::var("PRIVATE_KEY").expect("PRIVATE_KEY not set");
            let signer: PrivateKeySigner =
                private_key.parse().expect("Failed to parse private key");
            let wallet = EthereumWallet::from(signer);
            let provider = ProviderBuilder::new()
                .with_recommended_fillers()
                .wallet(wallet)
                .on_http(self.rpc_url.clone());
            let contract = SP1Vector::new(self.contract_address, provider);
            let receipt = contract
                .rotate(proof.bytes().into(), proof.public_values.to_vec().into())
                .send()
                .await?
                .with_required_confirmations(NUM_CONFIRMATIONS)
                .with_timeout(Some(Duration::from_secs(RELAY_TIMEOUT_SECONDS)))
                .get_receipt()
                .await?;

            // If status is false, it reverted.
            if !receipt.status() {
                return Err(anyhow::anyhow!("Transaction reverted!"));
            }

            Ok(receipt.transaction_hash)
        }
    }

    /// Check the verifying key in the contract matches the verifying key in the prover.
    async fn check_vkey(&self) -> Result<()> {
        // Check that the verifying key in the contract matches the verifying key in the prover.
        let provider = ProviderBuilder::new().on_http(self.rpc_url.clone());
        let contract = SP1Vector::new(self.contract_address, provider);
        let verifying_key = contract
            .vectorXProgramVkey()
            .call()
            .await?
            .vectorXProgramVkey;

        if verifying_key.0.to_vec()
            != hex::decode(self.vk.bytes32().strip_prefix("0x").unwrap()).unwrap()
        {
            return Err(anyhow::anyhow!(
                "The verifying key in the operator does not match the verifying key in the contract!"
            ));
        }

        Ok(())
    }

    async fn run(&self) -> Result<()> {
        loop {
            info!("Starting loop!");
            let loop_interval_mins = get_loop_interval_mins();
            let block_interval = get_block_update_interval();

            // Check if there is a rotate available for the next authority set.
            // Note: There is a timeout here in case the Avail RPC fails to respond. Once there is
            // an easy way to configure the timeout on Avail RPC requests, this should be removed.
            let current_authority_set_id =
                tokio::time::timeout(tokio::time::Duration::from_secs(60), self.find_rotate())
                    .await??;

            info!(
                "Current authority set id: {}",
                current_authority_set_id.unwrap_or(0)
            );

            // Request a rotate for the next authority set id.
            if let Some(current_authority_set_id) = current_authority_set_id {
                let proof = self.request_rotate(current_authority_set_id).await?;
                let tx_hash = self.relay_rotate(proof).await?;
                info!(
                    "Added authority set {}\nTransaction hash: {}",
                    current_authority_set_id + 1,
                    tx_hash
                );
            }

            info!("On the way for header range!");

            // Check if there is a header range request available.
            // Note: There is a timeout here in case the Avail RPC fails to respond. Once there is
            // an easy way to configure the timeout on Avail RPC requests, this should be removed.
            let header_range_request = tokio::time::timeout(
                tokio::time::Duration::from_secs(60),
                self.find_header_range(block_interval),
            )
            .await??;

            info!("header_range_request: {:?}", header_range_request);

            if let Some(header_range_request) = header_range_request {
                // Request the header range proof to block_to_step_to.
                let proof = self.request_header_range(header_range_request).await;
                match proof {
                    Ok(proof) => {
                        let tx_hash = self.relay_header_range(proof).await?;
                        info!(
                            "Posted data commitment from block {} to block {}\nTransaction hash: {}",
                            header_range_request.trusted_block, header_range_request.target_block, tx_hash
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

    operator.check_vkey().await.unwrap();

    loop {
        if let Err(e) = operator.run().await {
            error!("Error running operator: {}", e);
        }
    }
}
