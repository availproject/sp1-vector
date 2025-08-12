# Database Setup

This project has been migrated from DynamoDB to PostgreSQL for storing justifications data.

## Environment Variables

Add the following environment variable to your `.env.local` file:

```bash
DATABASE_URL=postgresql://myuser:mypassword@localhost:5433/vectorx-indexer
```

## Database Schema

The justifications table has the following schema:

```sql
CREATE TABLE IF NOT EXISTS justifications (
    id VARCHAR(255) PRIMARY KEY,
    avail_chain_id VARCHAR(100) NOT NULL,
    block_number INTEGER NOT NULL,
    data JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(avail_chain_id, block_number)
);

CREATE INDEX IF NOT EXISTS idx_justifications_avail_chain_id ON justifications(avail_chain_id);
CREATE INDEX IF NOT EXISTS idx_justifications_block_number ON justifications(block_number);
CREATE INDEX IF NOT EXISTS idx_justifications_avail_chain_block ON justifications(avail_chain_id, block_number);
```

## Setup Instructions

Please Read Postgres instructions on [vectorx-benchmarks](https://github.com/availproject/vectorx-benchmarks) repo.

## Migration from DynamoDB

If you have existing data in DynamoDB, you'll need to migrate it to PostgreSQL. The data structure should be compatible, but you may need to write a migration script to transfer the data.

## API Changes

The `/api/justification` endpoint now uses PostgreSQL instead of DynamoDB. The API interface remains the same:

- **GET** `/api/justification?blockNumber=<number>&availChainId=<chain_id>`

The response format is unchanged:
```json
{
  "success": true,
  "justification": { /* justification data */ }
}
```

## Dependencies

The following dependencies have been updated:
- Removed: `@aws-sdk/client-dynamodb`
- Added: `pg`, `@types/pg`
