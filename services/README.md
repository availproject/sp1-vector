# VectorX Services

This directory contains the VectorX services, including the justification indexer that has been migrated from DynamoDB to PostgreSQL.

## Components

### Indexer (`bin/indexer.rs`)
The main indexer service that listens for Avail justifications and stores them in PostgreSQL.

### Migration Tool (`bin/migrate_dynamodb_to_postgres.rs`)
A utility to migrate existing data from DynamoDB to PostgreSQL.

## Database Migration

The services have been migrated from DynamoDB to PostgreSQL. See [DATABASE_MIGRATION.md](./DATABASE_MIGRATION.md) for detailed information.

## Environment Variables

### Required
```bash
# Database connection
DATABASE_URL=postgresql://myuser:mypassword@localhost:5432/vectorx-indexer

# Avail configuration
AVAIL_URL=wss://...
AVAIL_CHAIN_ID=mainnet
```

### Optional (for data migration)
```bash
# AWS (if migrating existing DynamoDB data)
AWS_REGION=us-east-1
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

3. **Configure environment variables** (see above)

4. **Run the indexer**:
   ```bash
   cargo run --bin indexer
   ```

## Data Migration

If you have existing DynamoDB data, use the migration tool:

```bash
cargo run --bin migrate_dynamodb_to_postgres
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