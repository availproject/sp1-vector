use avail_subxt::avail_rust_core::grandpa::GrandpaJustification;
use sqlx::{PgPool, Row};
use tracing::info;

pub enum DatabaseClient {
    Postgres(PostgresClient),
    InMemory(InMemoryClient),
}

impl DatabaseClient {
    pub async fn new() -> anyhow::Result<Self> {
        if (std::env::var("DEBUG").is_ok() || std::env::var("DATABASE_INMEMORY").is_ok())
            && std::env::var("DATABASE_URL").is_err()
        {
            return Self::new_in_memory();
        }

        let pg = PostgresClient::new().await?;
        Ok(Self::Postgres(pg))
    }

    pub fn new_in_memory() -> anyhow::Result<Self> {
        let c = InMemoryClient::new();
        Ok(Self::InMemory(c))
    }

    pub async fn add_justification(
        &mut self,
        avail_chain_id: &str,
        justification: &GrandpaJustification,
    ) -> anyhow::Result<()> {
        match self {
            Self::Postgres(c) => c.add_justification(avail_chain_id, justification).await,
            Self::InMemory(c) => {
                c.add_justification(avail_chain_id, justification.clone());
                Ok(())
            }
        }
    }

    pub async fn get_justification(
        &self,
        avail_chain_id: &str,
        block_number: u32,
    ) -> anyhow::Result<GrandpaJustification> {
        match self {
            Self::Postgres(c) => c.get_justification(avail_chain_id, block_number).await,
            Self::InMemory(c) => {
                let just = c.get_justification(avail_chain_id, block_number);
                just.ok_or(anyhow::anyhow!("Failed to find justification"))
            }
        }
    }

    /// Check if a justification exists for the given chain and block number.
    pub async fn justification_exists(
        &self,
        avail_chain_id: &str,
        block_number: u32,
    ) -> anyhow::Result<bool> {
        match self {
            Self::Postgres(c) => c.justification_exists(avail_chain_id, block_number).await,
            Self::InMemory(c) => Ok(c.justification_exists(avail_chain_id, block_number)),
        }
    }

    /// Get the latest block number for a given chain.
    pub async fn get_latest_block_number(
        &self,
        avail_chain_id: &str,
    ) -> anyhow::Result<Option<u32>> {
        match self {
            Self::Postgres(c) => c.get_latest_block_number(avail_chain_id).await,
            Self::InMemory(c) => Ok(c.get_latest_block_number(avail_chain_id)),
        }
    }
}

#[derive(Default)]
pub struct InMemoryClient {
    list: Vec<(String, String, u32, GrandpaJustification)>,
}

impl InMemoryClient {
    pub fn new() -> Self {
        Self { list: Vec::new() }
    }

    pub fn add_justification(&mut self, avail_chain_id: &str, justification: GrandpaJustification) {
        let block_height = justification.commit.target_number;
        let id = format!("{avail_chain_id}-{block_height}").to_lowercase();

        // Remove old justification if it exists
        self.remove_justification(avail_chain_id, block_height);

        self.list
            .push((id, avail_chain_id.to_owned(), block_height, justification));
    }

    pub fn get_justification(
        &self,
        avail_chain_id: &str,
        block_height: u32,
    ) -> Option<GrandpaJustification> {
        let id = format!("{avail_chain_id}-{block_height}").to_lowercase();
        self.list.iter().find(|x| x.0 == id).map(|x| x.3.clone())
    }

    pub fn justification_exists(&self, avail_chain_id: &str, block_height: u32) -> bool {
        let id = format!("{avail_chain_id}-{block_height}").to_lowercase();
        self.list.iter().any(|x| x.0 == id)
    }

    pub fn remove_justification(&mut self, avail_chain_id: &str, block_height: u32) {
        let id = format!("{avail_chain_id}-{block_height}").to_lowercase();
        let pos = self.list.iter().position(|x| x.0 == id);
        let Some(pos) = pos else {
            return;
        };
        self.list.remove(pos);
    }

    pub fn get_latest_block_number(&self, avail_chain_id: &str) -> Option<u32> {
        let mut block_height = None;
        for el in self.list.iter() {
            if el.1.as_str() != avail_chain_id {
                continue;
            }

            block_height = match &block_height {
                Some(x) => Some(el.2.max(*x)),
                None => Some(el.2),
            };
        }

        block_height
    }
}

pub struct PostgresClient {
    pool: PgPool,
}

impl PostgresClient {
    pub async fn new() -> anyhow::Result<Self> {
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
        justification: &GrandpaJustification,
    ) -> anyhow::Result<()> {
        let json_data = serde_json::to_value(justification)?;
        let block_nb = justification.commit.target_number;
        let id = format!("{avail_chain_id}-{block_nb}").to_lowercase();

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
    ) -> anyhow::Result<GrandpaJustification> {
        let row = sqlx::query(
            "SELECT data FROM justifications 
             WHERE avail_chain_id = $1 AND block_number = $2",
        )
        .bind(avail_chain_id)
        .bind(block_number as i32)
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else {
            return Err(anyhow::anyhow!("Justification not found"));
        };

        let json_data: String = row.get("data");
        let data: GrandpaJustification = serde_json::from_str(&json_data)?;
        Ok(data)
    }

    /// Check if a justification exists for the given chain and block number.
    pub async fn justification_exists(
        &self,
        avail_chain_id: &str,
        block_number: u32,
    ) -> anyhow::Result<bool> {
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
    pub async fn get_latest_block_number(
        &self,
        avail_chain_id: &str,
    ) -> anyhow::Result<Option<u32>> {
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
    use avail_subxt::ext::avail_rust_core::grandpa::{
        AuthorityId, Commit, Precommit, Signature, SignedPrecommit,
    };
    use avail_subxt::{AvailHeader, H256};

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
                    signature: Signature([1u8; 64]),
                    id: AuthorityId([1u8; 32]),
                }],
            },
            votes_ancestries: vec![],
        };

        let chain_id = "test-chain";
        let block_number = 12345;

        // Test adding justification
        client
            .add_justification(chain_id, &test_justification)
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
