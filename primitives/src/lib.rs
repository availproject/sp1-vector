use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use types::CircuitJustification;

pub mod merkle;
pub mod types;
use sha2::{Digest as Sha256Digest, Sha256};
pub mod consts;
pub mod rotate;
pub mod header_range;
use alloy_primitives::B256;
use consts::{PUBKEY_LENGTH, VALIDATOR_LENGTH};

/// This function is useful for verifying that a Ed25519 signature is valid, it will panic if the signature is not valid.
pub fn verify_signature(pubkey_bytes: &[u8; 32], signed_message: &[u8], signature: &[u8; 64]) {
    let pubkey: VerifyingKey = VerifyingKey::from_bytes(pubkey_bytes).unwrap();
    let verified = pubkey.verify(signed_message, &Signature::from_bytes(signature));
    if verified.is_err() {
        panic!("Signature is not valid");
    }
}

/// Verify a simple justification on a block from the specified authority set.
pub fn verify_simple_justification(
    justification: CircuitJustification,
    authority_set_id: u64,
    current_authority_set_hash: B256,
) {
    // 1. Verify the authority set commitment is valid.
    assert_eq!(
        justification.current_authority_set_hash,
        current_authority_set_hash
    );

    // 2. Check encoding of precommit mesage.
    // a) Decode precommit.
    // b) Check that values from the decoded precommit match the passed in block number, block hash and authority_set_id.
    let (signed_block_hash, signed_block_number, _, signed_authority_set_id) =
        decode_precommit(justification.signed_message.clone());
    assert_eq!(signed_block_hash, justification.block_hash);
    assert_eq!(signed_block_number, justification.block_number);
    assert_eq!(signed_authority_set_id, authority_set_id);

    // 3. Check that the signed message is signed by the correct authority.
    // Must have at least 2/3 of the signatures to verify the justification.
    let threshold = (justification.pubkeys.len() * 2).div_ceil(3);
    let mut verified_signatures = 0;

    for i in 0..justification.pubkeys.len() {
        if let Some(signature) = &justification.signatures[i] {
            let signature: [u8; 64] = signature.as_slice().try_into().unwrap();
            verify_signature(
                &justification.pubkeys[i],
                &justification.signed_message,
                &signature,
            );
            verified_signatures += 1;

            // Exit the loop early if more than 2/3 of signatures are verified.
            if verified_signatures > threshold {
                break;
            }
        }
    }

    assert!(
        verified_signatures > threshold,
        "Less than 2/3 of signatures are verified"
    );
}

/// Compute the new authority set hash.
/// Compute the new authority set hash.
pub fn compute_authority_set_commitment(pubkeys: &[B256]) -> B256 {
    let mut commitment_so_far = Sha256::digest(pubkeys[0]).to_vec();
    for pubkey in pubkeys.iter().skip(1) {
        let mut input_to_hash = Vec::new();
        input_to_hash.extend_from_slice(&commitment_so_far);
        input_to_hash.extend_from_slice(pubkey.as_slice());
        commitment_so_far = Sha256::digest(&input_to_hash).to_vec();
    }
    B256::from_slice(&commitment_so_far)
}

pub fn decode_precommit(precommit: Vec<u8>) -> ([u8; 32], u32, u64, u64) {
    // The first byte should be a 1.
    assert_eq!(precommit[0], 1);

    // The next 32 bytes are the block hash.
    let block_hash: [u8; 32] = precommit[1..33].try_into().unwrap();

    // The next 4 bytes are the block number.
    let block_number = &precommit[33..37];
    // Convert the block number to a u32.
    let block_number = u32::from_le_bytes(block_number.try_into().unwrap());

    // The next 8 bytes are the justification round.
    let round = &precommit[37..45];
    // Convert the round to a u64.
    let round = u64::from_le_bytes(round.try_into().unwrap());

    // The next 8 bytes are the authority set id.
    let authority_set_id = &precommit[45..53];
    // Convert the authority set id to a u64.
    let authority_set_id = u64::from_le_bytes(authority_set_id.try_into().unwrap());

    (block_hash, block_number, round, authority_set_id)
}

/// Decode a SCALE-encoded compact int.
pub fn decode_scale_compact_int(bytes: &[u8]) -> (u64, usize) {
    if bytes.is_empty() {
        panic!("Input bytes are empty");
    }

    let first_byte = bytes[0];
    let flag = first_byte & 0b11;

    match flag {
        0b00 => {
            // Single-byte mode
            (u64::from(first_byte >> 2), 1)
        }
        0b01 => {
            // Two-byte mode
            if bytes.len() < 2 {
                panic!("Not enough bytes for two-byte mode");
            }
            let value = (u64::from(first_byte) >> 2) | (u64::from(bytes[1]) << 6);
            (value, 2)
        }
        0b10 => {
            // Four-byte mode
            if bytes.len() < 4 {
                panic!("Not enough bytes for four-byte mode");
            }
            let value = (u64::from(first_byte) >> 2)
                | (u64::from(bytes[1]) << 6)
                | (u64::from(bytes[2]) << 14)
                | (u64::from(bytes[3]) << 22);
            (value, 4)
        }
        0b11 => {
            // Big integer mode
            let byte_count = ((first_byte >> 2) + 4) as usize;
            if bytes.len() < byte_count + 1 {
                panic!("Not enough bytes for big integer mode");
            }
            let mut value = 0u64;
            for i in 0..byte_count {
                value |= (u64::from(bytes[i + 1])) << (i * 8);
            }
            (value, byte_count + 1)
        }
        _ => unreachable!(),
    }
}

/// Verify that the encoded validators match the provided pubkeys, have the correct weight, and the delay is zero.
pub fn verify_encoded_validators(header_bytes: &[u8], start_cursor: usize, pubkeys: &Vec<B256>) {
    let mut cursor = start_cursor;
    for pubkey in pubkeys {
        let extracted_pubkey = B256::from_slice(&header_bytes[cursor..cursor + PUBKEY_LENGTH]);
        // Assert that the extracted pubkey matches the expected pubkey.
        assert_eq!(extracted_pubkey, *pubkey);
        let extracted_weight = &header_bytes[cursor + PUBKEY_LENGTH..cursor + VALIDATOR_LENGTH];
        // All validating voting weights in Avail are 1.
        assert_eq!(extracted_weight, &[1u8, 0, 0, 0, 0, 0, 0, 0]);
        cursor += VALIDATOR_LENGTH;
    }
    // Assert the delay is 0.
    assert_eq!(&header_bytes[cursor..cursor + 4], &[0u8, 0u8, 0u8, 0u8]);
}

#[cfg(test)]
mod tests {
    use codec::{Compact, Encode};

    use super::*;

    #[test]
    fn test_decode_scale_compact_int() {
        let nums = [
            u32::MIN,
            1u32,
            63u32,
            64u32,
            16383u32,
            16384u32,
            1073741823u32,
            1073741824u32,
            4294967295u32,
            u32::MAX,
        ];
        let encoded_nums: Vec<Vec<u8>> = nums.iter().map(|num| Compact(*num).encode()).collect();
        let zipped: Vec<(&Vec<u8>, &u32)> = encoded_nums.iter().zip(nums.iter()).collect();
        for (encoded_num, num) in zipped {
            let (value, _) = decode_scale_compact_int(encoded_num);
            assert_eq!(value, *num as u64);
        }
    }
}
