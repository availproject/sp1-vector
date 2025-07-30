import { NextRequest, NextResponse } from 'next/server';
import { getJustification } from '@/app/utils/database';

/** Get the justification for a given Avail block.
 * - blockNumber: The block number of the Avail block.
 * - availChainId: The chain ID where the Avail contract is deployed.
 */
export async function GET(req: NextRequest) {
    const url = new URL(req.url);

    const blockNumber = Number(url.searchParams.get('blockNumber'));
    const availChainId = url.searchParams.get('availChainId');

    console.log(url.searchParams);

    console.log('Block Number: ' + blockNumber);
    console.log('Avail Chain ID: ' + availChainId);

    if (blockNumber === undefined || availChainId === undefined) {
        return NextResponse.json({
            success: false,
            error: 'Missing required parameters: blockNumber and availChainId'
        });
    }

    try {
        const justification = await getJustification(availChainId!, blockNumber);

        if (!justification) {
            return NextResponse.json({
                success: false,
                error: 'No justification found'
            });
        }

        return NextResponse.json({
            success: true,
            justification: justification.data
        });
    } catch (error) {
        console.error('Database error:', error);
        return NextResponse.json({
            success: false,
            error: 'Database error occurred'
        });
    }
}