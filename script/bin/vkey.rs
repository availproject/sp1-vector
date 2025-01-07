use sp1_sdk::{HashableKey, Prover, ProverClient};
use sp1_vectorx_script::SP1_VECTOR_ELF;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let client = ProverClient::builder().mock().build();
    let (_pk, vk) = client.setup(SP1_VECTOR_ELF);

    println!("VK: {}", vk.bytes32());

    Ok(())
}
