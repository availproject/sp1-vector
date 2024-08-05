pub mod relay;

pub const SP1_VECTOR_DOCKER_ELF: &[u8] = include_bytes!("../../elf/sp1-vector-docker");
pub const SP1_VECTOR_ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use services::input::RpcDataFetcher;

    #[tokio::test]
    async fn test_get_justification_query_service() -> Result<()> {
        let client = RpcDataFetcher::new().await;
        let justification = client.get_justification(337281).await?;
        println!("Justification: {:?}", justification);
        Ok(())
    }
}
