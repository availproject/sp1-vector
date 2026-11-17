use crate::{
    compute_authority_set_commitment,
    consts::{HASH_SIZE, PUBKEY_LENGTH, ROTATE_OUTPUTS_LENGTH},
    hash_encoded_header,
    types::{RotateInputs, RotateOutputs},
    verify_justification,
};
use alloy_primitives::B256;
use alloy_sol_types::SolType;
use codec::{Compact, Decode, DecodeAll};

/// SCALE indices of the `DigestItem` variants.
const DIGEST_ITEM_OTHER: u8 = 0;
const DIGEST_ITEM_CONSENSUS: u8 = 4;
const DIGEST_ITEM_SEAL: u8 = 5;
const DIGEST_ITEM_PRE_RUNTIME: u8 = 6;
const DIGEST_ITEM_RUNTIME_ENVIRONMENT_UPDATED: u8 = 8;

/// Consensus Id: https://github.com/availproject/avail/blob/188c20d6a1577670da65e0c6e1c2a38bea8239bb/avail-subxt/examples/download_digest_items.rs#L41-L56
const GRANDPA_ENGINE_ID: [u8; 4] = *b"FRNK";

/// SCALE index of the `ScheduledChange` variant of the GRANDPA `ConsensusLog`.
const SCHEDULED_CHANGE: u8 = 1;

/// Verify the justification from the current authority set on the epoch end header and return the next
/// authority set commitment.
pub fn verify_rotate(rotate_inputs: RotateInputs) -> [u8; ROTATE_OUTPUTS_LENGTH] {
    // Only count precommits on the epoch end header itself.
    assert!(
        rotate_inputs.justification.ancestries_encoded.is_empty(),
        "The rotate justification must not contain ancestries."
    );

    // Verify the provided justification is valid.
    verify_justification(&rotate_inputs.justification);

    let expected_block_hash = hash_encoded_header(&rotate_inputs.header_rotate_data.header_bytes);

    // The header hash should match the block hash signed by the justification.
    assert_eq!(expected_block_hash, rotate_inputs.justification.block_hash);

    // Extract the public keys of the next validator set from the epoch end header.
    let next_validator_pubkeys = get_next_validator_pubkeys_from_epoch_end_header(
        &rotate_inputs.header_rotate_data.header_bytes,
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
/// 1. Find the GRANDPA consensus log with the ScheduledChange in the header's digest.
/// 2. Extract the public keys from the ScheduledChange. All validator voting weights are 1.
/// 3. Assert the delay is 0.
pub fn get_next_validator_pubkeys_from_epoch_end_header(header_bytes: &[u8]) -> Vec<B256> {
    let scheduled_change_log = get_scheduled_change_log(header_bytes);

    // Decode the authorities and the delay after the ScheduledChange enum flag. The log must hold
    // nothing else.
    let (authorities, delay) =
        <(Vec<([u8; PUBKEY_LENGTH], u64)>, u32)>::decode_all(&mut &scheduled_change_log[1..])
            .expect("Failed to decode the GRANDPA ScheduledChange.");

    // Assert the delay is 0.
    assert_eq!(delay, 0);

    authorities
        .into_iter()
        .map(|(pubkey, weight)| {
            // All validator voting weights in Avail are 1.
            assert_eq!(weight, 1);
            B256::from(pubkey)
        })
        .collect()
}

/// Decode the header from the start, and return the payload of the only GRANDPA consensus log in
/// the digest that holds a ScheduledChange. Digest items of other types are skipped, even when
/// their engine ID is the GRANDPA engine ID.
fn get_scheduled_change_log(header_bytes: &[u8]) -> Vec<u8> {
    let mut input = header_bytes;

    // Skip the parent hash, the block number, the state root and the extrinsics root.
    <(
        [u8; HASH_SIZE],
        Compact<u32>,
        [u8; HASH_SIZE],
        [u8; HASH_SIZE],
    )>::decode(&mut input)
    .expect("Failed to decode the header.");

    let num_digest_items = Compact::<u32>::decode(&mut input)
        .expect("Failed to decode the header digest.")
        .0;

    let mut scheduled_change_logs = Vec::new();
    for _ in 0..num_digest_items {
        let item_type = u8::decode(&mut input).expect("Failed to decode the header digest.");
        match item_type {
            DIGEST_ITEM_OTHER => {
                Vec::<u8>::decode(&mut input).expect("Failed to decode the header digest.");
            }
            DIGEST_ITEM_CONSENSUS | DIGEST_ITEM_SEAL | DIGEST_ITEM_PRE_RUNTIME => {
                let (engine_id, payload) = <([u8; 4], Vec<u8>)>::decode(&mut input)
                    .expect("Failed to decode the header digest.");
                if item_type == DIGEST_ITEM_CONSENSUS
                    && engine_id == GRANDPA_ENGINE_ID
                    && payload.first() == Some(&SCHEDULED_CHANGE)
                {
                    scheduled_change_logs.push(payload);
                }
            }
            DIGEST_ITEM_RUNTIME_ENVIRONMENT_UPDATED => {}
            _ => panic!("Unknown digest item type {item_type}."),
        }
    }

    assert!(
        scheduled_change_logs.len() <= 1,
        "More than one GRANDPA ScheduledChange in the header digest."
    );
    scheduled_change_logs
        .pop()
        .expect("No GRANDPA ScheduledChange in the header digest.")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{CircuitJustification, HeaderRotateData, Precommit};
    use alloy_primitives::{b256, B512};
    use avail_subxt::ext::avail_rust_core::header::{
        Digest, DigestItem, HeaderExtension, V3HeaderExtension,
    };
    use avail_subxt::{AvailHeader, CompactDataLookup, KateCommitment, H256};
    use codec::Encode;
    use ed25519_consensus::SigningKey;

    const SET_ID: u64 = 10;

    fn pubkey(key: &SigningKey) -> B256 {
        B256::from(key.verification_key().to_bytes())
    }

    /// Encode a GRANDPA ScheduledChange with weight 1 for each authority and delay 0.
    fn scheduled_change(authorities: &[B256]) -> Vec<u8> {
        let authorities: Vec<([u8; 32], u64)> = authorities.iter().map(|a| (a.0, 1)).collect();
        (1u8, authorities, 0u32).encode()
    }

    fn encode_header(
        number: u32,
        parent_hash: B256,
        logs: Vec<DigestItem>,
        commitment: Vec<u8>,
    ) -> Vec<u8> {
        AvailHeader {
            parent_hash: H256::from(parent_hash.0),
            number,
            state_root: H256::zero(),
            extrinsics_root: H256::zero(),
            extension: HeaderExtension::V3(V3HeaderExtension {
                app_lookup: CompactDataLookup {
                    size: 0,
                    index: Vec::default(),
                },
                commitment: KateCommitment {
                    rows: 0,
                    cols: 0,
                    commitment,
                    data_root: H256::zero(),
                },
            }),
            digest: Digest { logs },
        }
        .encode()
    }

    /// A justification in which `signer`, the only authority of the set, precommits on `target`.
    fn justification(
        signer: &SigningKey,
        target_number: u32,
        target: &[u8],
        block_hash: B256,
        ancestries_encoded: Vec<Vec<u8>>,
    ) -> CircuitJustification {
        let round = 1u64;
        let target_hash = hash_encoded_header(target);
        let signed_message = (1u8, target_hash.0, target_number, round, SET_ID).encode();
        CircuitJustification {
            round,
            authority_set_id: SET_ID,
            valset_pubkeys: vec![pubkey(signer)],
            precommits: vec![Precommit {
                target_number,
                target_hash,
                pubkey: pubkey(signer),
                signature: B512::from(signer.sign(&signed_message).to_bytes()),
            }],
            block_hash,
            ancestries_encoded,
        }
    }

    fn rotate_inputs(header_bytes: Vec<u8>, justification: CircuitJustification) -> RotateInputs {
        RotateInputs {
            justification,
            header_rotate_data: HeaderRotateData { header_bytes },
        }
    }

    #[test]
    fn test_rotate_epoch_end_header() {
        let current = SigningKey::from([1u8; 32]);
        let next = SigningKey::from([2u8; 32]);
        let log = DigestItem::Consensus(GRANDPA_ENGINE_ID, scheduled_change(&[pubkey(&next)]));
        let header = encode_header(100, B256::ZERO, vec![log], vec![]);
        let justification =
            justification(&current, 100, &header, hash_encoded_header(&header), vec![]);

        let outputs = verify_rotate(rotate_inputs(header, justification));

        let (set_id, current_hash, next_hash) = RotateOutputs::abi_decode(&outputs).unwrap();
        assert_eq!(set_id, SET_ID);
        assert_eq!(
            current_hash,
            compute_authority_set_commitment(&[pubkey(&current)])
        );
        assert_eq!(
            next_hash,
            compute_authority_set_commitment(&[pubkey(&next)])
        );
    }

    #[test]
    fn test_rotate_mainnet_epoch_end_header() {
        // The operator's inputs for the end of mainnet authority set 917.
        let file = std::fs::File::open("test_assets/rotate_mainnet_917.json").unwrap();
        let inputs: RotateInputs = serde_json::from_reader(file).unwrap();

        let outputs = verify_rotate(inputs);

        // The hashes of sets 917 and 918 stored in the SP1Vector contract on Ethereum mainnet.
        let (set_id, current_hash, next_hash) = RotateOutputs::abi_decode(&outputs).unwrap();
        assert_eq!(set_id, 917);
        assert_eq!(
            current_hash,
            b256!("4507dfa251f7cfff2c81430dd62238c817dd4c79fc5096fcf48f15eb71141d9f")
        );
        assert_eq!(
            next_hash,
            b256!("fee9cdef73891777c7f67a10d78c7f455d52a71f9b1cc4dc8bdc786dfa440e9f")
        );
    }

    #[test]
    #[should_panic(expected = "The rotate justification must not contain ancestries.")]
    fn test_rotate_rejects_justification_on_descendant() {
        let current = SigningKey::from([1u8; 32]);
        let log = DigestItem::Consensus(GRANDPA_ENGINE_ID, scheduled_change(&[pubkey(&current)]));
        let header = encode_header(100, B256::ZERO, vec![log], vec![]);
        let child = encode_header(101, hash_encoded_header(&header), vec![], vec![]);
        let justification = justification(
            &current,
            101,
            &child,
            hash_encoded_header(&header),
            vec![child.clone()],
        );

        verify_rotate(rotate_inputs(header, justification));
    }

    #[test]
    #[should_panic(expected = "No GRANDPA ScheduledChange in the header digest.")]
    fn test_rotate_ignores_log_bytes_outside_digest() {
        let current = SigningKey::from([1u8; 32]);
        let other = SigningKey::from([3u8; 32]);
        let log = DigestItem::Consensus(GRANDPA_ENGINE_ID, scheduled_change(&[pubkey(&other)]));
        let header = encode_header(100, B256::ZERO, vec![], log.encode());
        let justification =
            justification(&current, 100, &header, hash_encoded_header(&header), vec![]);

        verify_rotate(rotate_inputs(header, justification));
    }

    #[test]
    #[should_panic(expected = "No GRANDPA ScheduledChange in the header digest.")]
    fn test_rotate_ignores_log_bytes_inside_pre_runtime_item() {
        let current = SigningKey::from([1u8; 32]);
        let other = SigningKey::from([3u8; 32]);
        let log = DigestItem::Consensus(GRANDPA_ENGINE_ID, scheduled_change(&[pubkey(&other)]));
        let item = DigestItem::PreRuntime(*b"TEST", log.encode());
        let header = encode_header(100, B256::ZERO, vec![item], vec![]);
        let justification =
            justification(&current, 100, &header, hash_encoded_header(&header), vec![]);

        verify_rotate(rotate_inputs(header, justification));
    }

    #[test]
    #[should_panic(expected = "No GRANDPA ScheduledChange in the header digest.")]
    fn test_rotate_ignores_pre_runtime_grandpa_item() {
        let current = SigningKey::from([1u8; 32]);
        let other = SigningKey::from([3u8; 32]);
        let item = DigestItem::PreRuntime(GRANDPA_ENGINE_ID, scheduled_change(&[pubkey(&other)]));
        let header = encode_header(100, B256::ZERO, vec![item], vec![]);
        let justification =
            justification(&current, 100, &header, hash_encoded_header(&header), vec![]);

        verify_rotate(rotate_inputs(header, justification));
    }

    #[test]
    #[should_panic(expected = "Failed to decode the GRANDPA ScheduledChange.")]
    fn test_rotate_rejects_trailing_bytes_in_scheduled_change() {
        let current = SigningKey::from([1u8; 32]);
        let next = SigningKey::from([2u8; 32]);
        let payload = [scheduled_change(&[pubkey(&next)]), vec![0u8]].concat();
        let log = DigestItem::Consensus(GRANDPA_ENGINE_ID, payload);
        let header = encode_header(100, B256::ZERO, vec![log], vec![]);
        let justification =
            justification(&current, 100, &header, hash_encoded_header(&header), vec![]);

        verify_rotate(rotate_inputs(header, justification));
    }
}
