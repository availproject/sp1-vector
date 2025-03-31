import { VECTORX_ABI, VECTORX_DATA_COMMITMENT_EVENT, VECTORX_HEAD_UPDATE_EVENT, VECTORX_INITIALIZED_EVENT } from '@/app/utils/abi';
import { HealthInfo, getBlocksSinceLastLog, getChainInfo, queryEthereumBlockByTimestamp, queryLogs, queryLogsWithBatches } from '@/app/utils/shared';
import { disconnect, initialize } from 'avail-js-sdk';
import { createPublicClient, http } from 'viem';

type RangeInfo = {
    start: number;
    end: number;
};

// List of Avail chains.
export const CHAIN_TO_WS_ENDPOINT = new Map([
    ['hex', process.env.AVAIL_WS_HEX as string],
    ['turing', process.env.AVAIL_WS_TURING as string],
    ['mainnet', process.env.AVAIL_WS_MAINNET as string],
]);

import deploymentData from "./deployments.json";

export interface DeploymentConfig {
    deployments: {
        contractChainId: number;
        contractAddress: string;
        cursorStartBlock: number;
    }[];
}

function readDeploymentConfig(): DeploymentConfig {
    return deploymentData as DeploymentConfig;
}

const deploymentConfig = readDeploymentConfig();

export async function getHealthStatusAvail(
    contractAddress: Uint8Array,
    ethereumChainId: number,
    sourceChainName: string,
    maxDelaySeconds: bigint
): Promise<HealthInfo> {
    if (process.env[`RPC_${ethereumChainId}`] == undefined) {
        throw new Error('Missing RPC URL for chain ' + ethereumChainId);
    }
    let ethereumRpc = process.env[`RPC_${ethereumChainId}`] as string;
    if (process.env[`AVAIL_WS_${sourceChainName.toUpperCase()}`] == undefined) {
        throw new Error('Missing Avail WS URL for chain ' + sourceChainName);
    }
    let availRpc = process.env[`AVAIL_WS_${sourceChainName.toUpperCase()}`] as string;

    const api = await initialize(availRpc);
    const rpc: any = api.rpc;
    const finalizedHead = await rpc.chain.getFinalizedHead();
    const finalizedHeader = await api.rpc.chain.getHeader(finalizedHead);
    const availHeadBlockNb = finalizedHeader.number.toNumber();

    await disconnect();

    let chainInfo = getChainInfo(ethereumChainId);

    const client = createPublicClient({
        chain: chainInfo,
        transport: http(ethereumRpc, {
            fetchOptions: { cache: 'no-store' }
        })
    });

    const ethCurrentBlock = await client.getBlock();
    let ethCurrentBlockTimestamp = ethCurrentBlock.timestamp;
    let ethCurrentBlockNumber = ethCurrentBlock.number;

    // Get the number of blocks since the last log and whether a log was emitted in the last 10 * maxDelaySeconds.
    let logData = await getBlocksSinceLastLog(ethereumChainId, ethereumRpc, ethCurrentBlockTimestamp, maxDelaySeconds, contractAddress, ethCurrentBlockNumber, VECTORX_HEAD_UPDATE_EVENT);

    let address = Buffer.from(contractAddress).toString('hex');

    // Read data from chain.
    const latestVectorBlockNb: number = (await client.readContract({
        address: `0x${address}`,
        abi: VECTORX_ABI,
        functionName: 'latestBlock'
    })) as number;

    let lastLogBlock = await client.getBlock({ blockNumber: BigInt(logData.lastLogBlockNumber) });

    return {
        logEmitted: logData.logEmitted,
        ethBlocksSinceLastLog: Number(ethCurrentBlockNumber) - logData.lastLogBlockNumber,
        lastLogTimestamp: Number(lastLogBlock.timestamp),
        blocksBehindHead: availHeadBlockNb - latestVectorBlockNb
    };
}

// Contract address is a string with the format '0x' followed by the address.
export async function getBlockRangeAvail(contractAddress: Uint8Array, ethereumChainId: number): Promise<RangeInfo | undefined> {
    if (process.env[`RPC_${ethereumChainId}`] == undefined) {
        throw new Error('Missing RPC URL for chain ' + ethereumChainId);
    }
    let ethereumRpc = process.env[`RPC_${ethereumChainId}`] as string;

    // Query in batches of 10_000 blocks.
    const BATCH_SIZE = 10_000;

    let chainInfo = getChainInfo(ethereumChainId);
    const client = createPublicClient({
        chain: chainInfo,
        transport: http(ethereumRpc, {
            fetchOptions: { cache: 'no-store' }
        })
    });
    let latestBlock = await client.getBlockNumber();

    // Convert contract address to a 0x prefixed string.
    let hexPrefixContractAddress = `0x` + Buffer.from(contractAddress).toString('hex');
    console.log('Hex prefix contract address: ' + hexPrefixContractAddress);

    // Check if there is a matching deployment config for the given contract address and chain id.
    let deployment = deploymentConfig.deployments.find((deployment) => deployment.contractAddress.toLowerCase() === hexPrefixContractAddress.toLowerCase() && deployment.contractChainId === ethereumChainId);
    if (deployment == undefined) {
        throw new Error('Deployment config not found for contract address ' + hexPrefixContractAddress + ' on chain ' + ethereumChainId);
    }

    let contractRangeStartBlock = 0;
    let contractRangeEndBlock = 0;

    // Find the first data commitment log after the cursor start block.
    let firstDataCommitmentCursor = Number(deployment.cursorStartBlock);
    while (true) {
        let dataCommitmentLogs: any = await queryLogsWithBatches(ethereumChainId, contractAddress, firstDataCommitmentCursor, firstDataCommitmentCursor + BATCH_SIZE, VECTORX_DATA_COMMITMENT_EVENT, BATCH_SIZE);
        if (dataCommitmentLogs.length == 0) {
            firstDataCommitmentCursor += BATCH_SIZE;
            if (firstDataCommitmentCursor > latestBlock) {
                throw new Error('No data commitment logs found');
            }
            continue;
        }

        // The first data commitment log is the oldest one.
        // Note: The +1 is because the start block in Avail is one block ahead of the event start block.
        contractRangeStartBlock = dataCommitmentLogs[0].args.startBlock + 1;
        break;
    }

    let mostRecentDataCommitmentCursor = Number(latestBlock);
    while (true) {
        // Search for data commitment logs starting from the most recent block number.
        let dataCommitmentLogs: any = await queryLogsWithBatches(ethereumChainId, contractAddress, mostRecentDataCommitmentCursor - BATCH_SIZE, mostRecentDataCommitmentCursor, VECTORX_DATA_COMMITMENT_EVENT, BATCH_SIZE);
        if (dataCommitmentLogs.length == 0) {
            mostRecentDataCommitmentCursor -= BATCH_SIZE;
            if (mostRecentDataCommitmentCursor < contractRangeStartBlock) {
                throw new Error('No data commitment logs found');
            }
            continue;
        }

        // The last log is the most recent one.
        let greatestEndBlockSoFar = dataCommitmentLogs[dataCommitmentLogs.length - 1].args.endBlock;

        contractRangeEndBlock = greatestEndBlockSoFar;
        break;
    }

    return {
        start: contractRangeStartBlock,
        end: contractRangeEndBlock
    };
}
