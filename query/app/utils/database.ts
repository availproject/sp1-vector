import { Pool, PoolClient } from 'pg';

// Create a connection pool
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

export interface JustificationData {
    id: string;
    avail_chain_id: string;
    block_number: number;
    data: any;
    created_at: Date;
}

export async function getJustification(availChainId: string, blockNumber: number): Promise<JustificationData | null> {
    const client = await pool.connect();
    try {
        const query = `
            SELECT id, avail_chain_id, block_number, data, created_at
            FROM justifications
            WHERE avail_chain_id = $1 AND block_number = $2
        `;
        
        const result = await client.query(query, [availChainId, blockNumber]);
        
        if (result.rows.length === 0) {
            return null;
        }
        
        return result.rows[0];
    } finally {
        client.release();
    }
}

export async function createJustification(
    availChainId: string, 
    blockNumber: number, 
    data: any
): Promise<void> {
    const client = await pool.connect();
    try {
        const query = `
            INSERT INTO justifications (id, avail_chain_id, block_number, data)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (avail_chain_id, block_number) 
            DO UPDATE SET data = $4, created_at = NOW()
        `;
        
        const id = `${availChainId}-${blockNumber}`.toLowerCase();
        await client.query(query, [id, availChainId, blockNumber, data]);
    } finally {
        client.release();
    }
}

// Graceful shutdown
process.on('SIGINT', async () => {
    await pool.end();
    process.exit(0);
});

process.on('SIGTERM', async () => {
    await pool.end();
    process.exit(0);
}); 
