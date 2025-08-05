-- Migration: Create justifications table for services
-- Run this migration to set up the PostgreSQL database schema

CREATE TABLE IF NOT EXISTS justifications (
    id VARCHAR(255) PRIMARY KEY,
    avail_chain_id VARCHAR(100) NOT NULL,
    block_number INTEGER NOT NULL,
    data JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(avail_chain_id, block_number)
);

-- Create indexes for better query performance
CREATE INDEX IF NOT EXISTS idx_justifications_avail_chain_id ON justifications(avail_chain_id);
CREATE INDEX IF NOT EXISTS idx_justifications_block_number ON justifications(block_number);
CREATE INDEX IF NOT EXISTS idx_justifications_avail_chain_block ON justifications(avail_chain_id, block_number);
