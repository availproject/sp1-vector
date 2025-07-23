# VectorX Query Service

This is a Next.js API service for querying VectorX data and justifications.

## Features

- Health status checking for VectorX light clients
- Block range queries
- Justification retrieval (migrated from DynamoDB to PostgreSQL)
- Data commitment proofs

## Database Migration

This service has been migrated from DynamoDB to PostgreSQL for storing justifications data. See [DATABASE_SETUP.md](./DATABASE_SETUP.md) for detailed setup instructions.

## Environment Variables

Required environment variables:

```bash
# Database
DATABASE_URL=postgresql://myuser:mypassword@localhost:5432/vectorx-indexer

# Avail WebSocket endpoints
AVAIL_WS_HEX=wss://...
AVAIL_WS_TURING=wss://...
AVAIL_WS_MAINNET=wss://...

# Ethereum RPC endpoints (for each chain ID)
RPC_1=https://...
RPC_324=https://...
RPC_84532=https://...
RPC_11155111=https://...
RPC_421614=https://...
RPC_300=https://...

```

## API Endpoints

### Health Check
```
GET /api/health?chainName=<chain>&contractChainId=<id>&contractAddress=<address>
```

### Block Range
```
GET /api/range?contractChainId=<id>&contractAddress=<address>
```

### Justification (PostgreSQL)
```
GET /api/justification?blockNumber=<number>&availChainId=<chain_id>
```

### Data Commitment Proof
```
GET /api?chainName=<chain>&contractChainId=<id>&contractAddress=<address>&blockNumber=<number>
```

## Development

```bash
# Install dependencies
npm install

# Set up database
# See DATABASE_SETUP.md for instructions

# Start development server
npm run dev
```

## Migration from DynamoDB

If you have existing DynamoDB data, you'll need to write a migration script to transfer the data to PostgreSQL. The data structure should be compatible, but the storage format has changed from DynamoDB's attribute-value format to PostgreSQL's JSONB format. 