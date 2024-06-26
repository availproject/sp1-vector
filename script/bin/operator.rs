use std::env;
use std::time::Duration;
use std::{cmp::min, sync::Arc};

use alloy::{
    network::{Ethereum, EthereumWallet},
    primitives::{Address, B256},
    providers::{
        fillers::{ChainIdFiller, FillProvider, GasFiller, JoinFill, WalletFiller},
        Identity, Provider, ProviderBuilder, RootProvider,
    },
    signers::local::PrivateKeySigner,
    sol,
    transports::http::{Client, Http},
};

use anyhow::Result;
use log::{error, info};
use services::input::RpcDataFetcher;
use sp1_sdk::{ProverClient, SP1PlonkBn254Proof, SP1ProvingKey, SP1Stdin};
use sp1_vectorx_primitives::types::ProofType;
use sp1_vectorx_script::relay::{self};
const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    contract VectorX {
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

/// Alias the fill provider for the Ethereum network. Retrieved from the instantiation
/// of the ProviderBuilder. Recommended method for passing around a ProviderBuilder.
type EthereumFillProvider = FillProvider<
    JoinFill<JoinFill<JoinFill<Identity, GasFiller>, ChainIdFiller>, WalletFiller<EthereumWallet>>,
    RootProvider<Http<Client>>,
    Http<Client>,
    Ethereum,
>;

struct VectorXOperator {
    wallet_filler: Arc<EthereumFillProvider>,
    client: ProverClient,
    pk: SP1ProvingKey,
    contract_address: Address,
    relayer_address: Address,
    chain_id: u64,
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

impl VectorXOperator {
    async fn new() -> Self {
        dotenv::dotenv().ok();

        let client = ProverClient::new();
        let (pk, _) = client.setup(ELF);
        let chain_id: u64 = env::var("CHAIN_ID")
            .expect("CHAIN_ID not set")
            .parse()
            .unwrap();
        let rpc_url = env::var("RPC_URL")
            .expect("RPC_URL not set")
            .parse()
            .unwrap();

        let private_key = env::var("PRIVATE_KEY").expect("PRIVATE_KEY not set");
        let contract_address = env::var("CONTRACT_ADDRESS")
            .expect("CONTRACT_ADDRESS not set")
            .parse()
            .unwrap();
        let signer: PrivateKeySigner = private_key.parse().expect("Failed to parse private key");
        let relayer_address = signer.address();
        let wallet = EthereumWallet::from(signer);
        let provider = ProviderBuilder::new()
            .filler(GasFiller)
            .filler(ChainIdFiller::default())
            .wallet(wallet)
            .on_http(rpc_url);

        Self {
            client,
            pk,
            wallet_filler: Arc::new(provider),
            chain_id,
            contract_address,
            relayer_address,
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
        let header_range_inputs = fetcher
            .get_header_range_inputs(trusted_block, target_block)
            .await;

        let curr_authority_set_id = fetcher.get_authority_set_id(target_block - 1).await;
        let target_authority_set_id = fetcher.get_authority_set_id(target_block).await;

        let target_justification;
        // This is an epoch end block, fetch using the get_justification_data_for epoch end block
        if curr_authority_set_id == target_authority_set_id - 1 {
            target_justification = fetcher
                .get_justification_data_epoch_end_block(curr_authority_set_id)
                .await;
        } else {
            (target_justification, _) = fetcher
                .get_justification_data_for_block(target_block)
                .await
                .ok_or_else(|| anyhow::anyhow!("Failed to get justification data for block"))?;
        }

        stdin.write(&proof_type);
        stdin.write(&header_range_inputs);
        stdin.write(&target_justification);

        info!(
            "Requesting header range proof from block {} to block {}.",
            trusted_block, target_block
        );

        self.client.prove_plonk(&self.pk, stdin)
    }

    async fn request_rotate(&self, current_authority_set_id: u64) -> Result<SP1PlonkBn254Proof> {
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

        self.client.prove_plonk(&self.pk, stdin)
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

        let contract = VectorX::new(self.contract_address, self.wallet_filler.clone());

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
        let contract = VectorX::new(self.contract_address, self.wallet_filler.clone());

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
        // justified block is 0, the VectorX contract's latest epoch is the current epoch on the
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
            if block_to_step_to > vectorx_current_block + header_range_commitment_tree_size {
                error!(
                    "Unable to find any valid justifications after searching from block {} to block {}. This is likely caused by an issue with the justification indexer.",
                    vectorx_current_block + ideal_block_interval,
                    vectorx_current_block + header_range_commitment_tree_size
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

    /// Relay a header range proof to the SP1 VectorX contract.
    async fn relay_header_range(&self, proof: SP1PlonkBn254Proof) -> Result<B256> {
        let contract = VectorX::new(self.contract_address, self.wallet_filler.clone());

        let proof_as_bytes = hex::decode(&proof.proof.encoded_proof)?;

        let gas_limit = relay::get_gas_limit(self.chain_id);
        let max_fee_per_gas = relay::get_fee_cap(self.chain_id, self.wallet_filler.root()).await;

        // Wait for 3 required confirmations with a timeout of 60 seconds.
        const NUM_CONFIRMATIONS: u64 = 3;
        const TIMEOUT_SECONDS: u64 = 60;

        let current_nonce = self
            .wallet_filler
            .get_transaction_count(self.relayer_address)
            .await?;

        let receipt = contract
            .commitHeaderRange(proof_as_bytes.into(), proof.public_values.to_vec().into())
            .gas_price(max_fee_per_gas)
            .gas(gas_limit)
            .nonce(current_nonce)
            .send()
            .await?
            .with_required_confirmations(NUM_CONFIRMATIONS)
            .with_timeout(Some(Duration::from_secs(TIMEOUT_SECONDS)))
            .get_receipt()
            .await?;

        // If status is false, it reverted.
        if !receipt.status() {
            return Err(anyhow::anyhow!("Transaction reverted!"));
        }

        Ok(receipt.transaction_hash)
    }

    /// Relay a rotate proof to the SP1 VectorX contract.
    async fn relay_rotate(&self, proof: SP1PlonkBn254Proof) -> Result<B256> {
        let contract = VectorX::new(self.contract_address, self.wallet_filler.clone());

        let proof_as_bytes = hex::decode(&proof.proof.encoded_proof)?;

        let gas_limit = relay::get_gas_limit(self.chain_id);
        let max_fee_per_gas = relay::get_fee_cap(self.chain_id, self.wallet_filler.root()).await;

        // Wait for 3 required confirmations with a timeout of 60 seconds.
        const NUM_CONFIRMATIONS: u64 = 3;
        const TIMEOUT_SECONDS: u64 = 60;

        let current_nonce = self
            .wallet_filler
            .get_transaction_count(self.relayer_address)
            .await?;

        let receipt = contract
            .rotate(proof_as_bytes.into(), proof.public_values.to_vec().into())
            .gas_price(max_fee_per_gas)
            .gas(gas_limit)
            .nonce(current_nonce)
            .send()
            .await?
            .with_required_confirmations(NUM_CONFIRMATIONS)
            .with_timeout(Some(Duration::from_secs(TIMEOUT_SECONDS)))
            .get_receipt()
            .await?;

        // If status is false, it reverted.
        if !receipt.status() {
            return Err(anyhow::anyhow!("Transaction reverted!"));
        }

        Ok(receipt.transaction_hash)
    }

    async fn run(&self) -> Result<()> {
        loop {
            let loop_interval_mins = get_loop_interval_mins();
            let block_interval = get_block_update_interval();

            // Check if there is a rotate available for the next authority set.
            let current_authority_set_id = self.find_rotate().await?;

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

            // Check if there is a header range request available.
            let header_range_request = self.find_header_range(block_interval).await?;

            if let Some(header_range_request) = header_range_request {
                // Request the header range proof to block_to_step_to.
                let proof = self
                    .request_header_range(header_range_request.0, header_range_request.1)
                    .await;
                match proof {
                    Ok(proof) => {
                        let tx_hash = self.relay_header_range(proof).await?;
                        info!(
                            "Posted data commitment from block {} to block {}\nTransaction hash: {}",
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
