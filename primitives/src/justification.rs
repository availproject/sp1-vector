use crate::{hash_encoded_header, types::CircuitJustification};
use codec::Encode;
use ed25519_consensus::{Signature, VerificationKey};
use std::collections::HashMap;

use alloy_primitives::B256;

/// Verify that a Ed25519 signature is valid. Panics if the signature is not valid.
fn verify_signature(pubkey_bytes: [u8; 32], signed_message: &[u8], signature: [u8; 64]) {
    let pubkey: VerificationKey = VerificationKey::try_from(pubkey_bytes).unwrap();
    let verified = pubkey.verify(&Signature::from(signature), signed_message);
    if verified.is_err() {
        panic!("Failed to verify Ed25519 signature.");
    }
}

/// Confirm ancestry of a child block by traversing the ancestry_map until root_hash is reached.
/// Sourced from https://github.com/availproject/avail-light/blob/main/core/src/finality.rs with some
/// small refactors for readability.  
fn confirm_ancestry(
    child_hash: &B256,
    root_hash: &B256,
    ancestry_map: &HashMap<B256, B256>,
) -> bool {
    let mut current_hash = child_hash;

    while current_hash != root_hash {
        match ancestry_map.get(current_hash) {
            Some(parent_hash) => current_hash = parent_hash,
            None => return false,
        }
    }

    true
}

/// Determine if a supermajority is achieved.
fn is_signed_by_supermajority(num_signatures: usize, validator_set_size: usize) -> bool {
    num_signatures * 3 > validator_set_size * 2
}

/// Verify a justification on a block from the specified authority set. Confirms that a supermajority
/// of the validator set is achieved on the specific block. Sourced from
/// https://github.com/availproject/avail-light/blob/main/core/src/finality.rs with some minor
/// modifications to fit into SP1 Vector, and small refactors for readability.
pub fn verify_justification(justification: &CircuitJustification) {
    // 1. Form an ancestry map from votes_ancestries in the justification. This maps header hashes to their parents' hashes.
    // Since we only get encoded headers, ensure that the parent is contained in the encoded header, no need to decode it.
    let ancestry_map: HashMap<B256, B256> = justification
        .ancestries_encoded
        .iter()
        .map(|encoded_header| {
            let parent_hash_array: [u8; 32] = encoded_header[0..32].try_into().unwrap();
            let parent_hash = B256::from(parent_hash_array);
            let header_hash = hash_encoded_header(encoded_header);

            (header_hash, parent_hash.to_owned())
        })
        .collect();

    // 2. Get the signer addresses of the accounts with valid precommits for the justification.
    let signer_addresses: Vec<B256> = justification
        .precommits
        .iter()
        .filter_map(|p| {
            // Form the message which is signed in the Justification.
            // Combination of the precommit flag, block data, round number and set_id.
            let signed_message = Encode::encode(&(
                1u8,
                p.target_hash.0,
                p.target_number,
                &justification.round,
                &justification.authority_set_id,
            ));

            // Verify the signature is valid on the precommit, and panic if this is not the case.
            verify_signature(p.pubkey.0, &signed_message, p.signature.0);

            // Confirm the ancestry of the child block.
            let ancestry_confirmed =
                confirm_ancestry(&p.target_hash, &justification.block_hash, &ancestry_map);

            if ancestry_confirmed {
                Some(p.pubkey)
            } else {
                None
            }
        })
        .collect();

    // 3. Count the accounts which are in validator set of the justification.
    let num_matched_addresses = signer_addresses
        .iter()
        .filter(|x| justification.valset_pubkeys.iter().any(|e| e.0.eq(&x[..])))
        .count();

    // 4. Confirm that the supermajority of the validator set is achieved.
    assert!(
        is_signed_by_supermajority(num_matched_addresses, justification.valset_pubkeys.len()),
        "More than 2/3 of signatures are not verifie!"
    );
}
