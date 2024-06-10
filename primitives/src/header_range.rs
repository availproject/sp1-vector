use alloy_primitives::B256;
use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;

use crate::consts::HEADER_OUTPUTS_LENGTH;
use crate::merkle::get_merkle_root_commitments;
use crate::types::{
    CircuitJustification, DecodedHeaderData, HeaderRangeInputs, HeaderRangeOutputs,
};
use crate::{decode_scale_compact_int, verify_simple_justification};
use alloy_sol_types::SolType;

/// Verify the justification from the current authority set on target block and compute the
/// {state, data}_root_commitments over the range [trusted_block + 1, target_block] inclusive.
pub fn verify_header_range(
    header_range_inputs: HeaderRangeInputs,
    target_justification: CircuitJustification,
) -> [u8; HEADER_OUTPUTS_LENGTH] {
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

    // Hash the headers.
    let mut header_hashes = Vec::new();
    const DIGEST_SIZE: usize = 32;
    for header_bytes in encoded_headers {
        let mut hasher = Blake2bVar::new(DIGEST_SIZE).unwrap();
        hasher.update(header_bytes.as_slice());

        let mut digest_bytes = [0u8; DIGEST_SIZE];
        let _ = hasher.finalize_variable(&mut digest_bytes);
        header_hashes.push(B256::from(digest_bytes));
    }

    // Assert the first header hash matches the trusted header hash.
    assert_eq!(header_hashes[0], header_range_inputs.trusted_header_hash);
    assert_eq!(
        decoded_headers_data[0].block_number,
        header_range_inputs.trusted_block
    );

    // Stage 2: Verify the chain of headers is connected from the trusted block to the target block.
    // Do this by checking the parent hashes are linked and the block numbers are sequential.
    for i in 1..(header_range_inputs.target_block - header_range_inputs.trusted_block + 1) as usize
    {
        // Check the parent hashes are linked.
        assert_eq!(header_hashes[i - 1], decoded_headers_data[i].parent_hash);
        // Check the block numbers are sequential.
        assert_eq!(
            decoded_headers_data[i - 1].block_number + 1,
            decoded_headers_data[i].block_number
        );
    }

    // Check that the last header matches the target block.
    assert_eq!(
        decoded_headers_data[decoded_headers_data.len() - 1].block_number,
        header_range_inputs.target_block
    );
  
    // Stage 3: Verify the justification is valid.
    verify_simple_justification(
        target_justification,
        header_range_inputs.authority_set_id,
        header_range_inputs.authority_set_hash,
    );

    // Stage 4: Compute the simple Merkle tree commitment for the headers.
    let (state_root_commitment, data_root_commitment) = get_merkle_root_commitments(
        &decoded_headers_data[1..],
        header_range_inputs.merkle_tree_size,
    );

    // Return the ABI encoded HeaderRangeOutputs.
    HeaderRangeOutputs::abi_encode(&(
        header_range_inputs.trusted_block,
        header_range_inputs.trusted_header_hash,
        header_range_inputs.authority_set_id,
        header_range_inputs.authority_set_hash,
        header_range_inputs.target_block,
        header_hashes[header_hashes.len()-1],
        state_root_commitment,
        data_root_commitment,
    ))
    .try_into()
    .unwrap()
}

/// Decode the header into a DecodedHeaderData struct.
pub fn decode_header(header_bytes: Vec<u8>) -> DecodedHeaderData {
    let mut cursor: usize = 32;
    let parent_hash = B256::from_slice(&header_bytes[..cursor]);

    let (block_nb, num_bytes) = decode_scale_compact_int(&header_bytes[cursor..cursor + 5]);
    cursor += num_bytes;

    let state_root = B256::from_slice(&header_bytes[cursor..cursor + 32]);

    let data_root = B256::from_slice(&header_bytes[header_bytes.len() - 32..header_bytes.len()]);

    DecodedHeaderData {
        block_number: block_nb as u32,
        parent_hash,
        state_root,
        data_root,
    }
}
