use alloy_primitives::{B256, B512};
use alloy_sol_types::sol;

use serde::{Deserialize, Serialize};

/// uint32 trusted_block;
/// bytes32 trusted_header_hash;
/// uint64 authority_set_id;
/// bytes32 authority_set_hash;
/// uint32 target_block;
/// bytes32 target_header_hash
/// bytes32 state_root_commitment;
/// bytes32 data_root_commitment;
pub type HeaderRangeOutputs = sol! {
    tuple(uint32, bytes32, uint64, bytes32, uint32, bytes32, bytes32, bytes32)
};

/// uint64 current_authority_set_id;
/// bytes32 current_authority_set_hash;
/// bytes32 new_authority_set_hash;
pub type RotateOutputs = sol! {
    tuple(uint64, bytes32, bytes32)
};

/// uint8 ProofType (0 = HeaderRangeProof, 1 = RotateProof)
/// bytes HeaderRangeOutputs
/// bytes RotateOutputs
pub type ProofOutput = sol! {
    tuple(uint8, bytes, bytes)
};

#[derive(Debug, Deserialize, Serialize)]
pub enum ProofType {
    HeaderRangeProof = 0,
    RotateProof = 1,
}

impl ProofType {
    pub fn from_uint(value: u8) -> Option<ProofType> {
        match value {
            0 => Some(ProofType::HeaderRangeProof),
            1 => Some(ProofType::RotateProof),
            _ => None,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RotateInputs {
    pub current_authority_set_id: u64,
    pub current_authority_set_hash: B256,
    /// Justification data for the current authority set.
    pub justification: CircuitJustification,
    /// Data for the next authority set rotation.
    pub header_rotate_data: HeaderRotateData,
}

#[derive(Debug, Deserialize, Serialize)]
/// Data for the next set of authorities.
pub struct HeaderRotateData {
    /// Encoded header bytes for the epoch end block.
    pub header_bytes: Vec<u8>,
    pub num_authorities: usize,
    pub new_authority_set_hash: B256,
    pub pubkeys: Vec<B256>,
    /// Index of the new authority set data in the header bytes.
    pub consensus_log_position: usize,
}

#[derive(Debug, Deserialize, Serialize)]
/// Justification data for an authority set.
pub struct CircuitJustification {
    pub authority_set_id: u64,
    /// Message signed by authority set.
    pub signed_message: Vec<u8>,
    pub pubkeys: Vec<B256>,
    pub signatures: Vec<Option<B512>>,
    pub num_authorities: usize,
    pub current_authority_set_hash: B256,
    /// Block number associated with the justification.
    pub block_number: u32,
    /// Hash of the block associated with the justification.
    pub block_hash: B256,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct HeaderRangeInputs {
    pub trusted_block: u32,
    pub trusted_header_hash: B256,
    pub authority_set_id: u64,
    pub authority_set_hash: B256,
    pub target_block: u32,
    pub merkle_tree_size: usize,
    pub encoded_headers: Vec<Vec<u8>>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DecodedHeaderData {
    /// Block number of the decoded header.
    pub block_number: u32,
    /// Hash of the parent block.
    pub parent_hash: B256,
    /// State root of the block.
    pub state_root: B256,
    /// Data root of the block.
    pub data_root: B256,
}
