use alloy_primitives::B256;
use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use codec::{Compact, Decode, Encode};
use sha2::{Digest as Sha256Digest, Sha256};

use crate::consts::{PUBKEY_LENGTH, VALIDATOR_LENGTH};

pub mod consts;
pub mod header_range;
mod justification;
pub mod merkle;
pub mod rotate;
pub mod types;

pub use justification::verify_justification;

/// Blake2B hash of an encoded header. Note: This is a generic hash fn for any data.
pub(crate) fn hash_encoded_header(encoded_header: &[u8]) -> B256 {
    const DIGEST_SIZE: usize = 32;
    let mut hasher = Blake2bVar::new(DIGEST_SIZE).unwrap();
    hasher.update(encoded_header);

    let mut digest_bytes = [0u8; DIGEST_SIZE];
    let _ = hasher.finalize_variable(&mut digest_bytes);
    B256::from(digest_bytes)
}

/// Compute the new authority set hash from the encoded pubkeys.
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

/// Decode a SCALE-encoded compact int and get the value and the number of bytes it took to encode.
pub(crate) fn decode_scale_compact_int(bytes: Vec<u8>) -> (u64, usize) {
    let value = Compact::<u64>::decode(&mut bytes.as_slice())
        .expect("Failed to decode SCALE-encoded compact int.");
    (value.into(), value.encoded_size())
}

/// Verify that the encoded validators match the provided pubkeys, have the correct weight, and the
/// delay is set to zero starting from the supplied cursor.
pub fn verify_encoded_validators(header_bytes: &[u8], start_cursor: usize, pubkeys: &Vec<B256>) {
    let mut cursor = start_cursor;
    for pubkey in pubkeys {
        let extracted_pubkey = B256::from_slice(&header_bytes[cursor..cursor + PUBKEY_LENGTH]);
        // Assert that the extracted pubkey matches the expected pubkey.
        assert_eq!(extracted_pubkey, *pubkey);
        let extracted_weight = &header_bytes[cursor + PUBKEY_LENGTH..cursor + VALIDATOR_LENGTH];

        // All validator voting weights in Avail are 1.
        assert_eq!(extracted_weight, &[1u8, 0, 0, 0, 0, 0, 0, 0]);
        cursor += VALIDATOR_LENGTH;
    }
    // Assert the delay is 0.
    assert_eq!(&header_bytes[cursor..cursor + 4], &[0u8, 0u8, 0u8, 0u8]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use avail_subxt::api::runtime_types::avail_core::header::extension::v3::HeaderExtension;
    use avail_subxt::api::runtime_types::avail_core::header::extension::HeaderExtension::V3;
    use avail_subxt::config::substrate::Digest;
    use avail_subxt::primitives::Header as DaHeader;
    use codec::{Compact, Encode};
    use primitive_types::H256;

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
            let (value, _) = decode_scale_compact_int(encoded_num.to_vec());
            assert_eq!(value, *num as u64);
        }
    }

    #[test]
    fn test_header_parent_hash_extracting() {
        let hash = H256::random();
        let h = DaHeader {
            parent_hash: hash,
            number: 1,
            state_root: H256::zero(),
            extrinsics_root: H256::zero(),
            extension: V3(HeaderExtension {
                ..Default::default()
            }),
            digest: Digest {
                ..Default::default()
            },
        };

        let encoded = h.encode();

        let n: [u8; 32] = encoded[0..32].try_into().unwrap();
        let extracted_hash = H256::from(n);
        assert_eq!(extracted_hash, hash, "Hashes don't match")
    }
}
