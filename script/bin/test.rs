//! A simple script to test the generation of proofs.

use alloy::sol_types::SolType;
use services::input::{HeaderRangeRequestData, RpcDataFetcher};
use sp1_sdk::{utils::setup_logger, ProverClient, SP1Stdin};
use sp1_vector_primitives::types::{ProofOutput, ProofType};
const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

// Requires the following environment variables to be set:
// - AVAIL_URL: The URL of the Avail RPC endpoint.
// - AVAIL_CHAIN_ID: The chain id of the Avail network.
// - VECTORX_QUERY_URL: The URL of the VectorX query service.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    setup_logger();

    // Supply an initial authority set id, trusted block, and target block.
    let authority_set_id = 64u64;
    let trusted_block = 305130;
    let target_block = 305160;

    let proof_type = ProofType::HeaderRangeProof;

    let fetcher = RpcDataFetcher::new().await;
    let mut stdin: SP1Stdin = SP1Stdin::new();

    // Fetch & write inputs to proof based on the proof type.
    match proof_type {
        ProofType::HeaderRangeProof => {
            let header_range_inputs = fetcher
                .get_header_range_inputs(HeaderRangeRequestData {
                    trusted_block,
                    target_block,
                    is_target_epoch_end_block: false,
                },
                Some(512))
                .await;

            stdin.write(&proof_type);
            stdin.write(&header_range_inputs);
        }
        ProofType::RotateProof => {
            let rotate_input = fetcher.get_rotate_inputs(authority_set_id).await;

            stdin.write(&proof_type);
            stdin.write(&rotate_input);
        }
    }

    let client = ProverClient::new();

    let (pv, report) = client.execute(ELF, stdin).run()?;

    let _ = ProofOutput::abi_decode(pv.as_slice(), true)?;

    println!("Exeuction Report: {:?}", report);
    println!("Total instructions: {}", report.total_instruction_count());

    Ok(())
}
