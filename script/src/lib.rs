pub mod relay;

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
