import { DynamoDBClient, QueryCommand } from '@aws-sdk/client-dynamodb';
import { NextRequest, NextResponse } from 'next/server';

const tableName = 'justifications-v2';

/** Get the justification for a given Avail block.
 * - blockNumber: The block number of the Avail block.
 * - availChainId: The chain ID where the Avail contract is deployed.
 */
export async function GET(req: NextRequest) {
    const url = new URL(req.url);

    let dynamoClient = new DynamoDBClient({ region: process.env.AWS_REGION });

    const blockNumber = Number(url.searchParams.get('blockNumber'));
    const availChainId = url.searchParams.get('availChainId');

    console.log(url.searchParams);

    console.log('Block Number: ' + blockNumber);
    console.log('Avail Chain ID: ' + availChainId);

    if (blockNumber === undefined || availChainId === undefined) {
        return NextResponse.json({
            success: false
        });
    }

    let justificationKey = (availChainId! + '-' + blockNumber.toString()).toLowerCase();

    const command = new QueryCommand({
        TableName: tableName,
        KeyConditionExpression: 'id = :id',
        ExpressionAttributeValues: {
            ':id': { S: justificationKey },
        },
    });

    const response = await dynamoClient.send(command);

    if (response.Items === undefined || response.Items.length === 0) {
        return NextResponse.json({
            success: false,
            error: 'No justification found'
        });
    }

    return NextResponse.json({
        success: true,
        justification: response.Items![0].data
    });
}