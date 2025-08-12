use avail_subxt::avail_rust_core::grandpa::{GrandpaJustification, Precommit};
use avail_subxt::{AvailHeader, H256};
use codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

#[derive(Debug, Encode)]
pub enum SignerMessage {
    #[allow(dead_code)]
    DummyMessage(u32),
    PrecommitMessage(Precommit),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EncodedFinalityProof(pub Vec<u8>);

#[derive(Debug, Encode, Decode, Clone, Deserialize)]
pub struct FinalityProof {
    /// The hash of block F for which justification is provided.
    pub block: H256,
    /// Justification of the block F.
    pub justification: Vec<u8>,
    /// The set of headers in the range (B; F] that are unknown to the caller, ordered by block number.
    pub unknown_headers: Vec<AvailHeader>,
}

#[derive(Clone, Debug, Decode, Serialize, Deserialize)]
pub struct VectorXJustificationApiResponse {
    pub success: bool,
    pub justification: Option<GrandpaJustification>,
    pub error: Option<String>,
}
