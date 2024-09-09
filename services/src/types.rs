use avail_subxt::primitives::Header;
use codec::{Decode, Encode};
use serde::de::Error;
use serde::{Deserialize, Serialize};
use sp_core::ed25519::{Public as EdPublic, Signature};
use sp_core::H256;
use sp_core::{bytes, Bytes};

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
    /// The target block's number.
    pub target_number: u32,
    /// Precommits for target block or any block after it that justify this commit.
    pub precommits: Vec<SignedPrecommit>,
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

/// The justification type that the Avail Subxt client returns for justifications. Needs a custom
/// deserializer, so we can't use the equivalent `AvailSubscriptionGrandpaJustification` type.
#[derive(Clone, Debug, Decode, Serialize)]
pub struct AvailSubscriptionGrandpaJustification {
    pub round: u64,
    pub commit: Commit,
    pub votes_ancestries: Vec<Header>,
}

impl<'de> Deserialize<'de> for AvailSubscriptionGrandpaJustification {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let encoded = bytes::deserialize(deserializer)?;
        Self::decode(&mut &encoded[..])
            .map_err(|codec_err| D::Error::custom(format!("Invalid decoding: {:?}", codec_err)))
    }
}
