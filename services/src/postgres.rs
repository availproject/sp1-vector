use anyhow::Result;
use serde_json::{from_str, to_string};
use sqlx::{PgPool, Row};
use tracing::info;

use crate::types::GrandpaJustification;

pub struct PostgresClient {
    pool: PgPool,
}

impl PostgresClient {
    pub async fn new() -> Result<Self> {
        let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");

        let pool = PgPool::connect(&database_url).await?;

        // Test the connection
        sqlx::query("SELECT 1").execute(&pool).await?;

        Ok(PostgresClient { pool })
    }

    /// Add a justification to the PostgreSQL table.
    pub async fn add_justification(
        &self,
        avail_chain_id: &str,
        justification: GrandpaJustification,
    ) -> Result<()> {
        let json_data = to_string(&justification)?;
        let block_nb = justification.commit.target_number;
        let id = format!("{}-{}", avail_chain_id, block_nb).to_lowercase();

        info!(
            "Adding justification for chain: {} for block number: {:?}",
            avail_chain_id, block_nb
        );

        sqlx::query(
            "INSERT INTO justifications (id, avail_chain_id, block_number, data) 
             VALUES ($1, $2, $3, $4) 
             ON CONFLICT (avail_chain_id, block_number) 
             DO UPDATE SET data = $4, created_at = NOW()",
        )
        .bind(&id)
        .bind(avail_chain_id)
        .bind(block_nb as i32)
        .bind(&json_data)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get a justification from the PostgreSQL table.
    pub async fn get_justification(
        &self,
        avail_chain_id: &str,
        block_number: u32,
    ) -> Result<GrandpaJustification> {
        let row = sqlx::query(
            "SELECT data FROM justifications 
             WHERE avail_chain_id = $1 AND block_number = $2",
        )
        .bind(avail_chain_id)
        .bind(block_number as i32)
        .fetch_optional(&self.pool)
        .await?;

        if let Some(row) = row {
            let json_data: String = row.get("data");
            let data: GrandpaJustification = from_str(&json_data)?;
            Ok(data)
        } else {
            Err(anyhow::anyhow!("Justification not found"))
        }
    }

    /// Check if a justification exists for the given chain and block number.
    pub async fn justification_exists(
        &self,
        avail_chain_id: &str,
        block_number: u32,
    ) -> Result<bool> {
        let row = sqlx::query(
            "SELECT 1 FROM justifications 
             WHERE avail_chain_id = $1 AND block_number = $2",
        )
        .bind(avail_chain_id)
        .bind(block_number as i32)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.is_some())
    }

    /// Get the latest block number for a given chain.
    pub async fn get_latest_block_number(&self, avail_chain_id: &str) -> Result<Option<u32>> {
        let row = sqlx::query(
            "SELECT MAX(block_number) as latest_block 
             FROM justifications 
             WHERE avail_chain_id = $1",
        )
        .bind(avail_chain_id)
        .fetch_optional(&self.pool)
        .await?;

        if let Some(row) = row {
            let latest_block: Option<i32> = row.get("latest_block");
            Ok(latest_block.map(|b| b as u32))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Commit, GrandpaJustification, Precommit, SignedPrecommit};
    use sp_core::ed25519::{Public, Signature};
    use sp_core::{ByteArray, H256};

    #[tokio::test]
    #[ignore] // This test requires a PostgreSQL database
    async fn test_postgres_client() {
        dotenv::dotenv().ok();

        // Skip test if DATABASE_URL is not set
        if std::env::var("DATABASE_URL").is_err() {
            println!("Skipping test: DATABASE_URL not set");
            return;
        }

        let client = PostgresClient::new()
            .await
            .expect("Failed to create client");

        // Create a test justification
        let test_justification = GrandpaJustification {
            round: 1,
            commit: Commit {
                target_hash: H256::from_slice(&[1u8; 32]),
                target_number: 12345,
                precommits: vec![SignedPrecommit {
                    precommit: Precommit {
                        target_hash: H256::from_slice(&[1u8; 32]),
                        target_number: 12345,
                    },
                    signature: Signature::from_slice(&[1u8; 64]).unwrap(),
                    id: Public::from_slice(&[1u8; 32]).unwrap(),
                }],
            },
            votes_ancestries: vec![],
        };

        let chain_id = "test-chain";
        let block_number = 12345;

        // Test adding justification
        client
            .add_justification(chain_id, test_justification.clone())
            .await
            .expect("Failed to add justification");

        // Test checking if justification exists
        let exists = client
            .justification_exists(chain_id, block_number)
            .await
            .expect("Failed to check existence");
        assert!(exists);

        // Test retrieving justification
        let retrieved = client
            .get_justification(chain_id, block_number)
            .await
            .expect("Failed to get justification");
        assert_eq!(retrieved.round, test_justification.round);
        assert_eq!(
            retrieved.commit.target_number,
            test_justification.commit.target_number
        );

        // Test getting latest block number
        let latest = client
            .get_latest_block_number(chain_id)
            .await
            .expect("Failed to get latest block number");
        assert_eq!(latest, Some(block_number));
    }
}
