import { createPublicClient, http } from 'viem';
import { mainnet, goerli, gnosis, sepolia, holesky, arbitrumSepolia, arbitrum, scrollSepolia, optimism, optimismGoerli, base, baseSepolia } from 'viem/chains';
import { AbiEvent } from 'abitype';

const CHAINS = [mainnet, goerli, gnosis, sepolia, holesky, arbitrumSepolia, arbitrum, scrollSepolia, optimism, optimismGoerli, base, baseSepolia];

export type HealthInfo = {
    blocksBehindHead: number;
    ethBlocksSinceLastLog: number;
    lastLogTimestamp: number;
    logEmitted: boolean;
};

export function currentUnixTimestamp() {
    return BigInt(Math.floor(Date.now() / 1000));
}

export function unixTimestampFromSlot(slot: bigint, genesisTime: bigint, secondsPerSlot: bigint) {
    return genesisTime + slot * secondsPerSlot;
}

// Gets the most recent block before a given timestamp.
export async function queryEthereumBlockByTimestamp(
    ethereumChainId: number,
    ethereumRpc: string,
    timestamp: number
) {
    let chainInfo = getChainInfo(ethereumChainId);
    const client = createPublicClient({
        chain: chainInfo,
        transport: http(ethereumRpc, {
            fetchOptions: { cache: 'no-store' }
        })
    });

    let high = Number(await client.getBlockNumber());
    let low = high;
    let mid;
    let found = false;

    // Search to find a block with a lower timestamp
    let searchFactor = 5;
    for (let i = 1; !found && low > 0; i++) {
        low = high - (i ** searchFactor);
        if (low < 0) {
            low = 0;
        }
        const block = await client.getBlock({ blockNumber: BigInt(low) });
        if (BigInt(block.timestamp) < BigInt(timestamp)) {
            found = true;
        }
    }

    if (!found) {
        throw new Error('No block found before the given timestamp');
    }

    // Binary search between low and high to find the most recent block before the given timestamp
    while (low <= high) {
        mid = low + Math.floor((high - low) / 2);
        const block = await client.getBlock({ blockNumber: BigInt(mid) });

        if (BigInt(block.timestamp) < timestamp) {
            if (mid === high || BigInt((await client.getBlock({ blockNumber: BigInt(mid + 1) })).timestamp) >= timestamp) {
                return block; // This is the most recent block before the given timestamp
            }
            low = mid + 1;
        } else {
            high = mid - 1;
        }
    }

    throw new Error('Failed to find the most recent block before the given timestamp');
}

export async function queryLogs(
    ethereumChainId: number,
    contractAddress: Uint8Array,
    fromBlock: number,
    toBlock: number,
    event: AbiEvent,
) {
    console.log('queryLogs', fromBlock, toBlock);
    if (process.env[`RPC_${ethereumChainId}`] == undefined) {
        throw new Error('Missing RPC URL for chain ' + ethereumChainId);
    }
    let ethereumRpc = process.env[`RPC_${ethereumChainId}`] as string;
    let chainInfo = getChainInfo(ethereumChainId);
    const client = createPublicClient({
        chain: chainInfo,
        transport: http(ethereumRpc, {
            fetchOptions: { cache: 'no-store' }
        })
    });
    let address = Buffer.from(contractAddress).toString('hex');
    let logs = await client.getLogs({
        address: `0x${address}`,
        event,
        fromBlock: BigInt(fromBlock),
        toBlock: BigInt(toBlock)
    });
    return logs;
}

// Query logs in batches of maxLogsPerQuery.
export async function queryLogsWithBatches(
    ethereumChainId: number,
    contractAddress: Uint8Array,
    fromBlock: number,
    toBlock: number,
    event: AbiEvent,
    maxLogsPerQuery: number,
) {
    let logs: any = [];
    let currentBlock = fromBlock;
    while (currentBlock < toBlock) {
        let batchEndBlock = currentBlock + maxLogsPerQuery;
        if (batchEndBlock > toBlock) {
            batchEndBlock = toBlock;
        }
        let newLogs = await queryLogs(ethereumChainId, contractAddress, currentBlock, batchEndBlock, event);
        logs = logs.concat(newLogs);
        currentBlock = batchEndBlock + 1;
    }
    return logs;
}

const SLOTS_PER_PERIOD = 8192n;
export function getSyncCommitteePeriod(slot: bigint): bigint {
    return slot / SLOTS_PER_PERIOD;
}

export function getConsensusRpc(chainId?: number) {
    if (!chainId) {
        const chainIdStr = process.env.CHAIN_ID;
        if (!chainIdStr) {
            throw new Error('Default CHAIN_ID env not set');
        }
        chainId = Number(chainIdStr);
    }
    switch (chainId) {
        case 1:
            return process.env.CONSENSUS_RPC_1;
        case 5:
            return process.env.CONSENSUS_RPC_5;
        case 17000:
            return process.env.CONSENSUS_RPC_17000;
        case 11155111:
            return process.env.CONSENSUS_RPC_11155111;
        default:
            throw new Error('Chain not supported');
    }
}

export function getChainInfo(chainId: number) {
    for (const chain of CHAINS) {
        if (chain.id === chainId) {
            return chain;
        }
    }
    throw new Error(`No chain found for chainId ${chainId}`);
}

// Returns the number of blocks since the last log and whether a log was emitted in the last 10 * maxDelaySeconds.
export async function getBlocksSinceLastLog(ethereumChainId: number, ethereumRpc: string, ethCurrentBlockTimestamp: bigint, maxDelaySeconds: bigint, contractAddress: Uint8Array, ethCurrentBlockNumber: bigint, event: AbiEvent): Promise<{ lastLogBlockNumber: number, logEmitted: boolean }> {
    let queryBlock = await queryEthereumBlockByTimestamp(ethereumChainId, ethereumRpc, Number(ethCurrentBlockTimestamp - maxDelaySeconds));

    let diffSeconds = Number(ethCurrentBlockTimestamp) - Number(queryBlock.timestamp);
    let diffBlocks = Number(ethCurrentBlockNumber) - Number(queryBlock.number);

    const headUpdateLogs = await queryLogsWithBatches(
        ethereumChainId,
        contractAddress,
        Number(ethCurrentBlockNumber) - (diffBlocks * 10),
        Number(ethCurrentBlockNumber),
        event,
        10000
    );

    // Sort headUpdateLogs by block number descending.
    headUpdateLogs.sort((a: any, b: any) => Number(b.blockNumber - a.blockNumber));
    let lastLogBlockNumber = Number(ethCurrentBlockNumber) - diffBlocks * 10;
    if (headUpdateLogs.length > 0) {
        lastLogBlockNumber = Number(headUpdateLogs[0].blockNumber);
    }

    return {
        lastLogBlockNumber,
        logEmitted: headUpdateLogs.length > 0
    }
}
