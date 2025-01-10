use alloy_primitives::B256;
use alloy_sol_types::SolType;

use crate::consts::HEADER_OUTPUTS_LENGTH;
use crate::merkle::get_merkle_root_commitments;
use crate::types::{DecodedHeaderData, HeaderRangeInputs, HeaderRangeOutputs};
use crate::{
    compute_authority_set_commitment, decode_scale_compact_int, hash_encoded_header,
    verify_justification,
};

/// Verify the justification from the current authority set on target block and compute the
/// state and data root commitments over the range [trusted_block + 1, target_block] inclusive.
pub fn verify_header_range(header_range_inputs: HeaderRangeInputs) -> [u8; HEADER_OUTPUTS_LENGTH] {
    // 1. Decode the headers using: https://github.com/availproject/avail-core/blob/main/core/src/header/mod.rs#L44-L66.
    // 2. Verify the chain of headers is connected from the trusted block to the target block.
    // 3. Compute the simple merkle tree commitment for the headers.
    // 4. Verify the justification is valid.
    // 5. Verify the justification is linked to the target block.
    // 6. Commit to the authority set hash used for the justification. This will be verified
    //    to match the current authority set hash in the SP1Vector contract when the proof is verified.

    // Stage 1: Decode and get the hashes of all of the headers.
    let header_data: Vec<DecodedHeaderData> = header_range_inputs
        .encoded_headers
        .iter()
        .map(|header_bytes| (decode_header(header_bytes.to_vec())))
        .collect();

    // Assert the first header hash matches the trusted header hash.
    assert_eq!(
        header_data[0].header_hash,
        header_range_inputs.trusted_header_hash
    );
    // Verify the first block number matches the trusted block.
    assert_eq!(
        header_data[0].block_number,
        header_range_inputs.trusted_block
    );
    // Verify that the last header matches the target block.
    assert_eq!(
        header_data[header_data.len() - 1].block_number,
        header_range_inputs.target_block
    );

    // Stage 2: Verify the chain of all headers is connected from the trusted block to the target block
    // by verifying the parent hashes are linked and the block numbers are sequential.
    for i in 1..header_data.len() {
        // Verify the headers are linked.
        assert_eq!(header_data[i - 1].header_hash, header_data[i].parent_hash);
        // Verify the block numbers are sequential.
        assert_eq!(
            header_data[i - 1].block_number + 1,
            header_data[i].block_number
        );
    }

    // Verify the number of headers is equal to the number of headers in the range. This is implicitly
    // covered by the assertions + loop above, but we add this assertion for clarity.
    assert!(
        (header_range_inputs.target_block - header_range_inputs.trusted_block) + 1
            == header_data.len() as u32
    );

    // Stage 3: Compute the simple Merkle tree commitment for the headers. Note: Does not include
    // the trusted header in the commitment.
    let (state_root_commitment, data_root_commitment) =
        get_merkle_root_commitments(&header_data[1..], header_range_inputs.merkle_tree_size);

    // Stage 4: Verify the justification is valid.
    verify_justification(&header_range_inputs.target_justification);

    // Stage 5. Compute the authority set hash for the justification. This is verified to match
    // the current authority set hash in the SP1Vector contract when the proof is verified.
    let current_authority_set_hash =
        compute_authority_set_commitment(&header_range_inputs.target_justification.valset_pubkeys);

    // Stage 6: Verify the block hash the justification is signed over matches the last header hash
    // in the header chain commitment.
    assert_eq!(
        header_range_inputs.target_justification.block_hash,
        header_data[header_data.len() - 1].header_hash
    );

    HeaderRangeOutputs::abi_encode(&(
        header_range_inputs.trusted_block,
        header_range_inputs.trusted_header_hash,
        header_range_inputs.target_justification.authority_set_id,
        current_authority_set_hash,
        header_range_inputs.target_block,
        // Target header hash.
        header_data[header_data.len() - 1].header_hash,
        state_root_commitment,
        data_root_commitment,
        header_range_inputs.merkle_tree_size as u32,
    ))
    .try_into()
    .unwrap()
}

/// Decode the header into a DecodedHeaderData struct manually and compute the header hash.
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

    // Get the header hash.
    let header_hash = hash_encoded_header(header_bytes.as_slice());

    DecodedHeaderData {
        block_number: block_nb as u32,
        parent_hash,
        state_root,
        data_root,
        header_hash,
    }
}
