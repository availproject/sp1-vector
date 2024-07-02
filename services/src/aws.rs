use aws_sdk_dynamodb::types::AttributeValue;
use aws_sdk_dynamodb::Client;

use anyhow::Result;
use log::info;
use serde_json::{from_str, to_string};
use std::collections::HashMap;

use crate::types::GrandpaJustification;

pub struct AWSClient {
    client: Client,
}

const JUSTIFICATION_TABLE: &str = "justifications-v2";

impl AWSClient {
    pub async fn new() -> Self {
        let shared_config = aws_config::load_from_env().await;
        let client = Client::new(&shared_config);
        AWSClient { client }
    }

    /// Add a justification to the AWS DynamoDB table.
    pub async fn add_justification(
        &self,
        avail_chain_id: &str,
        justification: GrandpaJustification,
    ) -> Result<()> {
        let json_data = to_string(&justification)?;

        let block_nb = justification.commit.target_number;
        let key = format!("{}-{}", avail_chain_id, block_nb).to_lowercase();

        let item = HashMap::from([
            ("id".to_string(), AttributeValue::S(key.to_string())),
            ("data".to_string(), AttributeValue::S(json_data.to_string())),
        ]);

        info!("Adding justification for block number: {:?}", block_nb);

        self.client
            .put_item()
            .table_name(JUSTIFICATION_TABLE)
            .set_item(Some(item))
            .send()
            .await?;
        Ok(())
    }

    /// Get a justification from the AWS DynamoDB table.
    pub async fn get_justification(
        &self,
        avail_chain_id: &str,
        block_number: u32,
    ) -> Result<GrandpaJustification> {
        let key = format!("{}-{}", avail_chain_id, block_number).to_lowercase();

        let resp = self
            .client
            .get_item()
            .table_name(JUSTIFICATION_TABLE)
            .key("id", AttributeValue::S(key.to_string()))
            .send()
            .await?;

        if let Some(item) = resp.item {
            if let Some(data_attr) = item.get("data") {
                if let Ok(data_json) = data_attr.as_s() {
                    let data: GrandpaJustification = from_str(data_json)?;
                    return Ok(data);
                }
            }
        }
        Err(anyhow::anyhow!("Justification not found"))
    }
}
