//! To build the binary:
//!
//!     `cargo build --release --bin genesis`
//!
use avail_subxt::config::Header;
use clap::Parser;
use services::input::RpcDataFetcher;
use sp1_sdk::{HashableKey, ProverClient};
const VECTORX_ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

#[derive(Parser, Debug, Clone)]
#[command(about = "Get the genesis parameters from a block.")]
pub struct GenesisArgs {
    #[arg(long)]
    pub block: Option<u32>,
}

const HEADER_RANGE_COMMITMENT_TREE_SIZE: u32 = 1024;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let fetcher = RpcDataFetcher::new().await;
    let client = ProverClient::new();
    let (_pk, vk) = client.setup(VECTORX_ELF);

    let args = GenesisArgs::parse();

    let header;
    if let Some(block) = args.block {
        header = fetcher.get_header(block).await;
    } else {
        header = fetcher.get_head().await;
    }
    let header_hash = header.hash();
    let authority_set_id = fetcher.get_authority_set_id(header.number).await;
    let authority_set_hash = fetcher
        .compute_authority_set_hash_for_block(header.number)
        .await;

    struct GenesisOutput {
        genesis_height: u32,
        genesis_header: String,
        genesis_authority_set_id: u64,
        genesis_authority_set_hash: String,
        sp1_vector_program_vkey: String,
        header_range_commitment_tree_size: u32,
    }

    let output = GenesisOutput {
        genesis_height: header.number,
        genesis_header: format!("{:#x}", header_hash),
        genesis_authority_set_id: authority_set_id,
        genesis_authority_set_hash: format!("{:#x}", authority_set_hash),
        sp1_vector_program_vkey: vk.bytes32(),
        header_range_commitment_tree_size: HEADER_RANGE_COMMITMENT_TREE_SIZE,
    };

    println!("GENESIS_HEIGHT={}\nGENESIS_HEADER={}\nGENESIS_AUTHORITY_SET_ID={}\nGENESIS_AUTHORITY_SET_HASH={}\nSP1_VECTOR_PROGRAM_VKEY={}\nHEADER_RANGE_COMMITMENT_TREE_SIZE={}",
             output.genesis_height,
             output.genesis_header,
             output.genesis_authority_set_id,
             output.genesis_authority_set_hash,
             output.sp1_vector_program_vkey,
             output.header_range_commitment_tree_size,
    );

    Ok(())
}
