# VectorX Services

This directory contains the VectorX services, including the justification indexer that has been migrated from DynamoDB to PostgreSQL.

## Components

### Indexer (`bin/indexer.rs`)
The main indexer service that listens for Avail justifications and stores them in PostgreSQL.


## Environment Variables

### Required
```bash
# Database connection
DATABASE_URL=postgresql://myuser:mypassword@localhost:5432/vectorx-indexer

# Avail configuration
AVAIL_URL=wss://...
AVAIL_CHAIN_ID=mainnet
```

## Setup

1. **Install dependencies**:
   ```bash
   cargo build
   ```

2. **Set up PostgreSQL database**:
   ```bash
   createdb vectorx-indexer
   psql -d vectorx-indexer -f migrations/001_create_justifications_table.sql
   ```
   
   OR
   
   ```
   DATABASE_URL="<PSQL_CONN_STRING>" sqlx migrate run
   ```

3. **Configure environment variables** (see above)

4. **Run the indexer**:
   ```bash
   cargo run --bin indexer
   ```

## Testing

Run the PostgreSQL tests (requires a database connection):

```bash
cargo test --package services --lib postgres::tests -- --ignored
```

## Architecture

- **PostgreSQL Client** (`src/postgres.rs`): Handles all database operations
- **RPC Data Fetcher** (`src/input.rs`): Fetches data from Avail and queries justifications
- **Indexer** (`bin/indexer.rs`): Main service that processes justifications

## Benefits of PostgreSQL Migration

1. **Better Performance**: Direct database access without HTTP overhead
2. **ACID Compliance**: Full transaction support
3. **Rich Querying**: SQL queries for complex data analysis
4. **Cost Effective**: No AWS DynamoDB costs
5. **Self-Hosted**: Full control over the database 