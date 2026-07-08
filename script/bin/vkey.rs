use sp1_sdk::{Elf, HashableKey, Prover, ProverClient, ProvingKey};
use sp1_vectorx_script::SP1_VECTOR_ELF;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let client = ProverClient::builder().mock().build().await;
    let pk = client
        .setup(Elf::Static(SP1_VECTOR_ELF))
        .await
        .expect("failed to setup prover");
    let vk = pk.verifying_key();

    println!("VK: {}", vk.bytes32());

    Ok(())
}
