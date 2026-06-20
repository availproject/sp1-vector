use sp1_sdk::{HashableKey, Prover, ProverClient, ProvingKey};
use sp1_vectorx_script::SP1_VECTOR_ELF;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let client = ProverClient::builder().mock().build().await;
    let pk = client.setup(SP1_VECTOR_ELF.into()).await?;
    let vk = pk.verifying_key();

    println!("VK: {}", vk.bytes32());

    Ok(())
}
