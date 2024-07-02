//! A simple program to be proven inside the zkVM.

#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_sol_types::SolType;
use sp1_vector_primitives::{
    consts::HEADER_OUTPUTS_LENGTH,
    consts::ROTATE_OUTPUTS_LENGTH,
    header_range::verify_header_range,
    rotate::verify_rotate,
    types::{HeaderRangeInputs, ProofOutput, ProofType, RotateInputs},
};

/// Generate an SP1 Vector proof for a given proof type.
pub fn main() {
    // Read the proof type requested from the inputs.
    let proof_type: ProofType = sp1_zkvm::io::read::<ProofType>();

    let mut header_range_outputs = [0u8; HEADER_OUTPUTS_LENGTH];
    let mut rotate_outputs = [0u8; ROTATE_OUTPUTS_LENGTH];

    match proof_type {
        ProofType::HeaderRangeProof => {
            // Read the header range inputs from the inputs.
            let header_range_inputs = sp1_zkvm::io::read::<HeaderRangeInputs>();
            header_range_outputs = verify_header_range(header_range_inputs);
        }
        ProofType::RotateProof => {
            // Read the rotate inputs from the inputs.
            let rotate_inputs = sp1_zkvm::io::read::<RotateInputs>();
            rotate_outputs = verify_rotate(rotate_inputs);
        }
    }

    // Commit the proof outputs to the zkVM as an encoded slice.
    let output = ProofOutput::abi_encode(&(proof_type as u8, header_range_outputs, rotate_outputs));
    sp1_zkvm::io::commit_slice(&output);
}
