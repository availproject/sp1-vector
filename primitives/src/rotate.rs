use crate::{
    compute_authority_set_commitment,
    consts::{PUBKEY_LENGTH, ROTATE_OUTPUTS_LENGTH, VALIDATOR_LENGTH},
    decode_scale_compact_int, hash_encoded_header,
    types::{RotateInputs, RotateOutputs},
    verify_justification,
};
use alloy_primitives::B256;
use alloy_sol_types::SolType;

/// Verify the justification from the current authority set on the epoch end header and return the next
/// authority set commitment.
pub fn verify_rotate(rotate_inputs: RotateInputs) -> [u8; ROTATE_OUTPUTS_LENGTH] {
    // Verify the provided justification is valid.
    verify_justification(&rotate_inputs.justification);

    let expected_block_hash = hash_encoded_header(&rotate_inputs.header_rotate_data.header_bytes);

    // The header hash should match the block hash signed by the justification.
    assert_eq!(expected_block_hash, rotate_inputs.justification.block_hash);

    // Extract the public keys of the next validator set from the epoch end header.
    let next_validator_pubkeys = get_next_validator_pubkeys_from_epoch_end_header(
        &rotate_inputs.header_rotate_data.header_bytes,
        rotate_inputs.header_rotate_data.consensus_log_position,
    );

    // Compute the current authority set hash from the public keys used in the justification.
    let current_authority_set_hash =
        compute_authority_set_commitment(&rotate_inputs.justification.valset_pubkeys);

    // Compute the next authority set hash from the public keys that are encoded in the epoch end header.
    let next_authority_set_hash = compute_authority_set_commitment(&next_validator_pubkeys);

    // Return the ABI encoded RotateOutputs.
    RotateOutputs::abi_encode(&(
        rotate_inputs.justification.authority_set_id,
        current_authority_set_hash,
        next_authority_set_hash,
    ))
    .try_into()
    .unwrap()
}

/// Extract the public keys of the next validator set from the epoch end header.
///
/// 1. Verify the epoch end header's consensus log is formatted correctly before the next authority set hash bytes.
/// 2. Extract the public keys from the epoch end header. All validator voting weights are 1. The public
///    keys are encoded as 40 bytes: 32 bytes for the pubkey and 8 bytes for the voting weight.
/// 3. Assert the delay is 0.
pub fn get_next_validator_pubkeys_from_epoch_end_header(
    header_bytes: &[u8],
    mut cursor: usize,
) -> Vec<B256> {
    // Verify consensus flag is 4.
    assert_eq!(header_bytes[cursor + 1], 4u8);

    // Verify the consensus engine ID: 0x46524e4b [70, 82, 78, 75]
    // Consensus Id: https://github.com/availproject/avail/blob/188c20d6a1577670da65e0c6e1c2a38bea8239bb/avail-subxt/examples/download_digest_items.rs#L41-L56
    assert_eq!(
        header_bytes[cursor + 2..cursor + 6],
        [70u8, 82u8, 78u8, 75u8]
    );

    // Move past the consensus engine ID.
    cursor += 6;

    // Decode the encoded scheduled change message length.
    let (_, decoded_byte_length) =
        decode_scale_compact_int(header_bytes[cursor..cursor + 5].to_vec());

    // Move past the encoded scheduled change message length.
    cursor += decoded_byte_length;

    // Verify the next byte after encoded scheduled change message is the ScheduledChange enum flag.
    assert_eq!(header_bytes[cursor], 1u8);

    // Move past the ScheduledChange enum flag.
    cursor += 1;

    // Decoded the encoded authority set size.
    let (authority_set_size, decoded_byte_length) =
        decode_scale_compact_int(header_bytes[cursor..cursor + 5].to_vec());

    // Move past the encoded authority set size.
    cursor += decoded_byte_length;

    // Extract the public keys from the epoch end header.
    let extracted_pubkeys: Vec<B256> = (0..authority_set_size as usize)
        .map(|i| {
            let start = cursor + (i * VALIDATOR_LENGTH);
            let pubkey = B256::from_slice(&header_bytes[start..start + PUBKEY_LENGTH]);

            // All validator voting weights in Avail are 1.
            assert_eq!(
                &header_bytes[start + PUBKEY_LENGTH..start + VALIDATOR_LENGTH],
                &[1u8, 0, 0, 0, 0, 0, 0, 0]
            );

            pubkey
        })
        .collect();

    // Assert the delay is 0.
    let delay_start = cursor + (authority_set_size as usize * VALIDATOR_LENGTH);
    assert_eq!(
        &header_bytes[delay_start..delay_start + 4],
        &[0u8, 0u8, 0u8, 0u8]
    );

    extracted_pubkeys
}
