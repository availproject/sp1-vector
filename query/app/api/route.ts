import { NextRequest, NextResponse } from 'next/server';
import assert from 'assert';
import { createHash } from 'crypto';
import { keccak256, encodeAbiParameters, createPublicClient, http } from 'viem';
import { ApiPromise, initialize, disconnect } from 'avail-js-sdk';
import { getChainInfo, queryLogs } from '@/app/utils/shared';
import { VECTORX_DATA_COMMITMENT_EVENT } from '@/app/utils/abi';
import { AbiEvent } from 'abitype';
import { CHAIN_TO_WS_ENDPOINT, getBlockRangeAvail } from '@/app/utils/avail';

type DataCommitmentRange = {
    startBlockNumber: number;
    endBlockNumber: number;
    dataCommitment: Uint8Array;
    stateCommitment: Uint8Array;
    commitmentTreeSize: number;
};

async function getBlockHash(blockNumber: number, chainName: string): Promise<String | undefined> {
    const api = await initialize(CHAIN_TO_WS_ENDPOINT.get(chainName.toLowerCase()) as string);
    const rpc: any = api.rpc;
    try {
        const blockHash = await rpc.chain.getBlockHash(blockNumber);
        await disconnect();
        return blockHash.toHex();
    } catch (error) {
        console.log(error);
    }
}

function isEqualUint8Array(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length != b.length) {
        return false;
    }
    for (let i = 0; i < a.length; i++) {
        if (a[i] != b[i]) {
            return false;
        }
    }
    return true;
}

async function getBlockNumber(blockHash: string, chainName: string): Promise<number | undefined> {
    const api = await initialize(CHAIN_TO_WS_ENDPOINT.get(chainName.toLowerCase()) as string);
    const rpc: any = api.rpc;
    try {
        const block = await rpc.chain.getBlock(blockHash);
        await disconnect();
        return block.block.header.number.toNumber();
    } catch (error) {
        console.log(error);
    }
}

//* Fetch the dataRoot of blockNb from the given RPC. */
const fetchDataRoot = async (api: ApiPromise, blockNb: number): Promise<Uint8Array> => {
    const blockHash = await api.rpc.chain.getBlockHash(blockNb);
    const header = await api.rpc.chain.getHeader(blockHash);
    const extension = header.toJSON().extension as {
        [version: string]: { commitment: { dataRoot: string } };
    };
    if (!extension || Object.keys(extension).length === 0) {
        throw new Error(`Extension not found for block ${blockNb}`);
    }

    // Resilient to future changes in the extension format. Ex. v3, v4, etc.
    let dataRoot = extension[Object.keys(extension)[0]].commitment?.dataRoot;
    if (!dataRoot) throw new Error(`Data root not found for block ${blockNb}`);
    if (dataRoot.startsWith('0x')) dataRoot = dataRoot.slice(2);
    return new Uint8Array(Buffer.from(dataRoot, 'hex'));
};

/** Fetch data roots for the range (startBlock, endBlock - 1) inclusive from the RPC. */
const fetchDataRootsForRange = async (
    startBlock: number,
    endBlock: number,
    chainName: string
): Promise<Uint8Array[]> => {
    const api = await initialize(CHAIN_TO_WS_ENDPOINT.get(chainName.toLowerCase()) as string);

    const blockNumbers = Array.from(
        { length: endBlock - startBlock },
        (_, i) => startBlock + i
    );

    const dataRoots = await Promise.all(blockNumbers.map(x => fetchDataRoot(api, x)));
    return dataRoots;
};

/** Compute the Merkle tree branch for the requested block number. */
function computeMerkleLayersAndBranch(commitmentTreeSize: number, dataRoots: Uint8Array[], index: number): Uint8Array[] {
    if (dataRoots.length != commitmentTreeSize) {
        console.log('Wrong number of leaves');

        throw new Error('Invalid number of leaves!');
    }

    let nodes = dataRoots;

    let branch: Uint8Array[] = [];

    let indexSoFar = index;

    while (nodes.length > 1) {
        let nextLevelNodes: Uint8Array[] = [];

        for (let i = 0; i < nodes.length; i += 2) {
            let leftChild = nodes[i];
            let rightChild = nodes[i + 1];
            // Append the left and right child and hash them together.
            const combinedArray = new Uint8Array(leftChild.length + rightChild.length);
            combinedArray.set(leftChild, 0);
            combinedArray.set(rightChild, leftChild.length);
            const hash = createHash('sha256').update(combinedArray).digest('hex');
            nextLevelNodes.push(new Uint8Array(Buffer.from(hash, 'hex')));

            // This is the index of the node in the next level.
            if (indexSoFar - (indexSoFar % 2) == i) {
                if (indexSoFar % 2 == 0) {
                    // If leftChild is the node we are looking for, then the right child is the sibling.
                    branch.push(rightChild);
                } else {
                    // If rightChild is the node we are looking for, then the left child is the sibling.
                    branch.push(leftChild);
                }
            }
        }
        indexSoFar = Math.floor(indexSoFar / 2);
        nodes = nextLevelNodes;
    }

    return branch; // The root of the Merkle tree
}

/** Parse a log retrieved from eth_getLogs. */
function parseLog(log: any): DataCommitmentRange {
    // Parse dataCommitment and stateCommitment which are 0x prefixed hex strings.
    let dataCommitment = new Uint8Array(Buffer.from(log.args.dataCommitment.substring(2), 'hex'));
    let stateCommitment = new Uint8Array(Buffer.from(log.args.stateCommitment.substring(2), 'hex'));
    return {
        startBlockNumber: log.args.startBlock,
        endBlockNumber: log.args.endBlock,
        dataCommitment: dataCommitment,
        stateCommitment: stateCommitment,
        commitmentTreeSize: log.args.headerRangeCommitmentTreeSize
    };
}

/** Binary search for the log that contains the target block. */
function binarySearchForLog(logs: any[], targetBlock: number): DataCommitmentRange {
    let left = 0;
    let right = logs.length - 1;
    while (left <= right) {
        let mid = Math.floor((left + right) / 2);
        let log = parseLog(logs[mid]);
        // Check if the targetBlock is contained within startBlock + 1 and endBlock of the log.
        if (targetBlock >= log.startBlockNumber + 1 && targetBlock <= log.endBlockNumber) {
            return log;
        }
        if (targetBlock < log.startBlockNumber + 1) {
            right = mid - 1;
        } else {
            left = mid + 1;
        }
    }
    // This should never happen.
    throw new Error('Log not found');
}

/** Find the data commitment range in the contract matching the requested block number. */
async function getDataCommitmentRangeForBlock(
    contractChainId: number,
    contractAddress: Uint8Array,
    targetBlock: number
): Promise<DataCommitmentRange | null> {
    if (process.env[`RPC_${contractChainId}`] == undefined) {
        throw new Error('Missing RPC URL for chain ' + contractChainId);
    }
    let ethereumRpc = process.env[`RPC_${contractChainId}`] as string;

    let chainInfo = getChainInfo(contractChainId);
    const client = createPublicClient({
        chain: chainInfo,
        transport: http(ethereumRpc, {
            fetchOptions: { cache: 'no-store' }
        })
    });
    let latestBlock = await client.getBlockNumber();

    // Query in batches of 10000 blocks.
    const BATCH_SIZE = 10_000;

    // TODO: Implement a more efficient search for the first log, based on a heuristic for the ETH
    // block corresponding to an Avail block.
    let currentBlock = Number(latestBlock);

    while (true) {
        let logs = await queryLogs(
            contractChainId,
            contractAddress,
            currentBlock - BATCH_SIZE,
            currentBlock,
            VECTORX_DATA_COMMITMENT_EVENT as AbiEvent,
        );

        if (logs.length > 0) {
            let startLog = parseLog(logs[0]);
            let lastLog = parseLog(logs[logs.length - 1]);
            // Check if the targetBlock is contained within startBlock + 1 and endBlock of the last log. If so,
            // binary search for which log contains the targetBlock.
            if (targetBlock >= startLog.startBlockNumber + 1 && targetBlock <= lastLog.endBlockNumber) {
                return binarySearchForLog(logs, targetBlock);
            }
        } else {
            console.log('No ranges found for block ' + currentBlock);
            return null;
        }

        currentBlock -= BATCH_SIZE;
    }

}

/** Get the range hash for the given range. */
function getRangeHash(startBlockNumber: number, endBlockNumber: number): Uint8Array {
    let encodedRange = encodeAbiParameters(
        [
            { name: 'startBlockNumber', type: 'uint32' },
            { name: 'endBlockNumber', type: 'uint32' }
        ],
        [startBlockNumber, endBlockNumber]
    );

    // Strip the 0x prefix.
    let encodedRangeStripped = encodedRange.substring(2);

    // Convert to bytes and hash with keccak256.
    let rangeHash = keccak256(new Uint8Array(Buffer.from(encodedRangeStripped, 'hex')));
    let rangeHashUint8 = new Uint8Array(Buffer.from(rangeHash.substring(2), 'hex'));
    return rangeHashUint8;
}

/** Verify that the merkle tree branch matches the data commitment. */
function verifyMerkleBranch(
    dataRoots: Uint8Array[],
    branch: Uint8Array[],
    index: number,
    dataCommitment: Uint8Array
) {
    // Verify the branch matches the data commitment.
    let currentHash = dataRoots[index];
    let indexSoFar = index;
    for (let i = 0; i < branch.length; i++) {
        let sibling = branch[i];
        if (indexSoFar % 2 == 0) {
            currentHash = createHash('sha256')
                .update(Buffer.concat([currentHash, sibling]))
                .digest();
        } else {
            currentHash = createHash('sha256')
                .update(Buffer.concat([sibling, currentHash]))
                .digest();
        }
        indexSoFar = Math.floor(indexSoFar / 2);
    }
    assert(
        isEqualUint8Array(currentHash, dataCommitment),
        'Data commitment does not match the root constructed from the Merkle tree branch! This means that the computed data commitment or the Merkle tree branch is incorrect.'
    );
}

// Compute the Merkle Root from the dataRoots after confirming it's a power of 2.
function computeDataCommitment(dataRoots: Uint8Array[], commitmentTreeSize: number): Uint8Array {
    if (dataRoots.length != commitmentTreeSize) {
        throw new Error('Data roots length must be a power of 2!');
    }
    let level = dataRoots;

    // Continue combining pairs until we get to the root
    while (level.length > 1) {
        const nextLevel: Uint8Array[] = [];

        for (let i = 0; i < level.length; i += 2) {
            let hashStr = createHash('sha256').update(Buffer.concat([level[i], level[i + 1]])).digest('hex');
            nextLevel.push(new Uint8Array(Buffer.from(hashStr, 'hex')));
        }

        level = nextLevel;
    }

    return level[0];
}

/**
 * Get the proof for a data commitment for a specific block number on Avail against the data commitments posted by the VectorX contract.
 * Required query parameters:
 *  - chainName: The name of the Avail chain to check.
 *  - contractChainId: The chain ID where the VectorX contract is deployed.
 *  - contractAddress: The address of the VectorX contract.
 *  - blockHash | blockNumber: The block hash/block number of the Avail block for which the proof is requested.
 */
export async function GET(req: NextRequest) {
    const url = new URL(req.url);

    const chainName = url.searchParams.get('chainName');
    const ethereumChainId = Number(url.searchParams.get('contractChainId'));
    let address = url.searchParams.get('contractAddress');
    const blockHash = url.searchParams.get('blockHash')
        ? url.searchParams.get('blockHash')
        : undefined;
    const blockNumber = url.searchParams.get('blockNumber')
        ? Number(url.searchParams.get('blockNumber'))
        : undefined;

    console.log('Avail Chain name: ' + chainName);
    console.log('Ethereum Chain ID: ' + ethereumChainId);
    console.log('Address: ' + address);
    console.log('Block hash: ' + blockHash);
    console.log('Block number: ' + blockNumber);

    let requestedBlock: number;

    if (chainName === undefined || ethereumChainId === undefined || address === undefined) {
        return NextResponse.json({
            success: false,
            error: 'Invalid parameters!'
        });
    }

    // Strip the 0x prefix from the address (if it exists) and convert it to lowercase then Uint8Array.
    address = address!.toLowerCase();
    if (address.startsWith('0x')) {
        address = address.slice(2);
    }
    const addressUint8 = new Uint8Array(Buffer.from(address!, 'hex'));

    try {
        if (blockHash === undefined) {
            if (blockNumber === undefined) {
                return NextResponse.json({
                    success: false,
                    error: 'No block hash or block number provided!'
                });
            }
            requestedBlock = blockNumber;
        } else {
            // Get the block number for the given block hash.
            let tempRequestedBlock = await getBlockNumber(blockHash!, chainName!);
            if (tempRequestedBlock == undefined) {
                return NextResponse.json({
                    success: false,
                    error: 'Invalid block hash!'
                });
            }
            requestedBlock = tempRequestedBlock;
        }
    } catch (error) {
        return NextResponse.json({
            success: false,
            error: 'Getting block number failed!'
        });
    }

    console.log('Requested block: ' + requestedBlock);

    let blockRange = await getBlockRangeAvail(addressUint8, ethereumChainId);
    if (blockRange === undefined) {
        return NextResponse.json({
            success: false,
            error: 'Getting the block range covered by the VectorX contract failed!'
        });
    }

    if (requestedBlock < blockRange.start || requestedBlock > blockRange.end) {
        return NextResponse.json({
            success: false,
            error: `Requested block ${requestedBlock} is not in the range of blocks [${blockRange.start}, ${blockRange.end}] contained in the VectorX contract.`
        });
    }

    try {
        let promises = [
            getBlockHash(requestedBlock, chainName!),
            // Get the data commitment range data for the requested block number.
            getDataCommitmentRangeForBlock(ethereumChainId, addressUint8, requestedBlock)
        ];

        let [requestedBlockHash, dataCommitmentRange] = await Promise.all(promises);

        if (dataCommitmentRange === null) {
            return NextResponse.json({
                success: false,
                error: 'Requested block is not in the range of blocks contained in the VectorX contract.'
            });
        }

        let { startBlockNumber, endBlockNumber, dataCommitment, stateCommitment, commitmentTreeSize } = dataCommitmentRange as DataCommitmentRange;

        // The Avail Merkle tree root is constructed from the data roots of blocks from the range [startBlockNumber + 1, endBlockNumber] inclusive.
        // Fetch all headers from the RPC.
        let dataRoots = await fetchDataRootsForRange(
            startBlockNumber + 1,
            endBlockNumber + 1,
            chainName!
        );

        // Extend the header array to commitmentTreeSize (fill with empty bytes).
        if (dataRoots.length < commitmentTreeSize) {
            const additionalRoots = new Array(commitmentTreeSize - dataRoots.length).fill(new Uint8Array(32));
            dataRoots = dataRoots.concat(additionalRoots);
        }

        // Get the merkle branch for the requested block number by computing the Merkle tree branch
        // of the tree constructed from the data roots.
        const index = requestedBlock - startBlockNumber - 1;
        let branch = computeMerkleLayersAndBranch(commitmentTreeSize, dataRoots, index);

        // Verify the Merkle tree branch against the data commitment.
        verifyMerkleBranch(dataRoots, branch, index, dataCommitment);

        const res = NextResponse.json({
            data: {
                blockNumber: blockNumber,
                rangeHash:
                    '0x' +
                    Buffer.from(getRangeHash(startBlockNumber, endBlockNumber)).toString('hex'),
                dataCommitment: '0x' + Buffer.from(dataCommitment).toString('hex'),
                merkleBranch: branch.map(
                    (node) => '0x' + Buffer.from(new Uint8Array(node)).toString('hex')
                ),
                index,
                totalLeaves: commitmentTreeSize,
                dataRoot: '0x' + Buffer.from(dataRoots[index]).toString('hex'),
                blockHash: requestedBlockHash as String
            }
        });

        // Cache for 24 hours.
        res.headers.set('CDN-Cache-Control', 'public, max-age=86400');

        return res;
    } catch (error) {
        console.log(error);
        // TODO: Better logging, come back to this when upgrading to mainnet.
        return NextResponse.json({
            success: false,
            error
        });
    }
}
