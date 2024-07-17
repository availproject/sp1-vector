use alloy_primitives::B256;
use alloy_sol_types::SolType;

use crate::consts::HEADER_OUTPUTS_LENGTH;
use crate::merkle::get_merkle_root_commitments;
use crate::types::{DecodedHeaderData, HeaderRangeInputs, HeaderRangeOutputs};
use crate::{decode_scale_compact_int, hash_encoded_header, verify_justification};

/// Verify the justification from the current authority set on target block and compute the
/// state and data root commitments over the range [trusted_block + 1, target_block] inclusive.
pub fn verify_header_range(header_range_inputs: HeaderRangeInputs) -> [u8; HEADER_OUTPUTS_LENGTH] {
    let encoded_headers = header_range_inputs.encoded_headers;

    // 1. Decode the headers using: https://github.com/succinctlabs/vectorx/blob/fb83641259aef1f5df33efa73c23d90973d64e24/circuits/builder/decoder.rs#L104-L157
    // 2. Verify the chain of headers is connected from the trusted block to the target block.
    // 3. Verify the justification is valid.
    // 4. Compute the simple merkle tree commitment for the headers.

    // Stage 1: Decode the headers.
    // Decode the headers.
    let decoded_headers_data: Vec<DecodedHeaderData> = encoded_headers
        .iter()
        .map(|header_bytes| decode_header(header_bytes.to_vec()))
        .collect();

    // Get the hashes of all of the headers.
    let header_hashes = encoded_headers
        .iter()
        .map(|e| hash_encoded_header(e.as_slice()))
        .collect::<Vec<_>>();

    // Assert the first header hash matches the trusted header hash.
    assert_eq!(header_hashes[0], header_range_inputs.trusted_header_hash);
    assert_eq!(
        decoded_headers_data[0].block_number,
        header_range_inputs.trusted_block
    );

    // Stage 2: Verify the chain of headers is connected from the trusted block to the target block
    // by verifying the parent hashes are linked and the block numbers are sequential.
    for i in 1..(header_range_inputs.target_block - header_range_inputs.trusted_block + 1) as usize
    {
        // Verify the headers are linked.
        assert_eq!(header_hashes[i - 1], decoded_headers_data[i].parent_hash);
        // Verify the block numbers are sequential.
        assert_eq!(
            decoded_headers_data[i - 1].block_number + 1,
            decoded_headers_data[i].block_number
        );
    }

    // Verify that the last header matches the target block.
    assert_eq!(
        decoded_headers_data[decoded_headers_data.len() - 1].block_number,
        header_range_inputs.target_block
    );

    // Stage 3: Verify the justification is valid.
    verify_justification(&header_range_inputs.target_justification);

    // Stage 4: Compute the simple Merkle tree commitment for the headers. Note: Does not include
    // the trusted header in the commitment.
    let (state_root_commitment, data_root_commitment) = get_merkle_root_commitments(
        &decoded_headers_data[1..],
        header_range_inputs.merkle_tree_size,
    );

    HeaderRangeOutputs::abi_encode(&(
        header_range_inputs.trusted_block,
        header_range_inputs.trusted_header_hash,
        header_range_inputs.target_justification.authority_set_id,
        header_range_inputs
            .target_justification
            .current_authority_set_hash,
        header_range_inputs.target_block,
        header_hashes[header_hashes.len() - 1],
        state_root_commitment,
        data_root_commitment,
        header_range_inputs.merkle_tree_size as u32,
    ))
    .try_into()
    .unwrap()
}

/// Decode the header into a DecodedHeaderData struct manually.
fn decode_header(header_bytes: Vec<u8>) -> DecodedHeaderData {
    // The first 32 bytes are the parent hash.
    let mut cursor: usize = 32;
    let parent_hash = B256::from_slice(&header_bytes[..cursor]);

    // The next section is the variable-length encoded block number.
    let (block_nb, num_bytes) = decode_scale_compact_int(header_bytes[cursor..cursor + 5].to_vec());
    cursor += num_bytes;

    // After the block number is the state root.
    let state_root = B256::from_slice(&header_bytes[cursor..cursor + 32]);

    // The last 32 bytes are the data root.
    let data_root = B256::from_slice(&header_bytes[header_bytes.len() - 32..header_bytes.len()]);

    DecodedHeaderData {
        block_number: block_nb as u32,
        parent_hash,
        state_root,
        data_root,
    }
}
