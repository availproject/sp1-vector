//! A simple script to test the generation of proofs.

use alloy::sol_types::SolType;
use clap::Parser;
use services::input::{HeaderRangeRequestData, RpcDataFetcher};
use sp1_sdk::{utils::setup_logger, ProverClient, SP1Stdin};
use sp1_vector_primitives::types::{ProofOutput, ProofType};
use sp1_vectorx_script::SP1_VECTOR_ELF;

// Requires the following environment variables to be set:
// - AVAIL_URL: The URL of the Avail RPC endpoint.
// - AVAIL_CHAIN_ID: The chain id of the Avail network.
// - VECTORX_QUERY_URL: The URL of the VectorX query service.

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct ScriptArgs {
    /// Trusted block.
    #[clap(long)]
    trusted_block: u32,

    /// Target block.
    #[clap(long, env)]
    target_block: u32,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    setup_logger();

    let args = ScriptArgs::parse();

    let trusted_block = args.trusted_block;
    let target_block = args.target_block;

    let authority_set_id = 282u64;
    let proof_type = ProofType::HeaderRangeProof;

    let fetcher = RpcDataFetcher::new().await;
    let mut stdin: SP1Stdin = SP1Stdin::new();

    // Fetch & write inputs to proof based on the proof type.
    match proof_type {
        ProofType::HeaderRangeProof => {
            let header_range_inputs = fetcher
                .get_header_range_inputs(
                    HeaderRangeRequestData {
                        trusted_block,
                        target_block,
                        is_target_epoch_end_block: false,
                    },
                    Some(512),
                )
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

    let client = ProverClient::from_env();

    let (pv, report) = client.execute(SP1_VECTOR_ELF, &stdin).run()?;

    let _ = ProofOutput::abi_decode(pv.as_slice())?;

    println!("Exeuction Report: {:?}", report);
    println!("Total instructions: {}", report.total_instruction_count());

    Ok(())
}
