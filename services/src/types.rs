use avail_subxt::primitives::Header;
use codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use sp_core::ed25519::{Public as EdPublic, Signature};
use sp_core::Bytes;
use sp_core::H256;

#[derive(Clone, Debug, Decode, Encode, Serialize, Deserialize)]
pub struct Precommit {
    pub target_hash: H256,
    /// The target block's number
    pub target_number: u32,
}

#[derive(Clone, Debug, Decode, Serialize, Deserialize)]
pub struct SignedPrecommit {
    pub precommit: Precommit,
    /// The signature on the message.
    pub signature: Signature,
    /// The Id of the signer.
    pub id: EdPublic,
}

#[derive(Clone, Debug, Decode, Serialize, Deserialize)]
pub struct Commit {
    pub target_hash: H256,
    #[allow(dead_code)]
    /// The target block's number.
    pub target_number: u32,
    /// Precommits for target block or any block after it that justify this commit.
    pub precommits: Vec<SignedPrecommit>,
}

#[derive(Clone, Debug, Decode, Serialize, Deserialize)]
pub struct GrandpaJustification {
    pub round: u64,
    pub commit: Commit,
    #[allow(dead_code)]
    pub votes_ancestries: Vec<Header>,
}

#[derive(Debug, Encode)]
pub enum SignerMessage {
    #[allow(dead_code)]
    DummyMessage(u32),
    PrecommitMessage(Precommit),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EncodedFinalityProof(pub Bytes);

#[derive(Debug, PartialEq, Encode, Decode, Clone, Deserialize)]
pub struct FinalityProof {
    /// The hash of block F for which justification is provided.
    pub block: H256,
    /// Justification of the block F.
    pub justification: Vec<u8>,
    /// The set of headers in the range (B; F] that are unknown to the caller, ordered by block number.
    pub unknown_headers: Vec<Header>,
}
