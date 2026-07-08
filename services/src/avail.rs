use avail_subxt::config::substrate::Digest;
use codec::{Decode, Encode};
use serde::{de::Visitor, Deserialize, Deserializer, Serialize};
use sp_core::H256;
use std::fmt;

#[derive(Clone, Debug, Decode, Encode, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FriBlobCommitment {
    pub blob_hash: H256,
    pub size_bytes: u64,
    pub commitment: Vec<u8>,
}

#[derive(Clone, Debug, Default, Decode, Encode, PartialEq, Serialize, Deserialize)]
pub enum FriParamsVersion {
    #[default]
    V0,
}

#[derive(Clone, Debug, Default, Decode, Encode, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FriHeaderExtension {
    pub blobs: Vec<FriBlobCommitment>,
    pub params_version: FriParamsVersion,
    pub data_root: H256,
}

#[derive(Clone, Debug, Decode, Encode, PartialEq, Serialize, Deserialize)]
pub enum HeaderExtension {
    #[codec(index = 0)]
    V1(FriHeaderExtension),
}

impl HeaderExtension {
    pub fn data_root(&self) -> H256 {
        match self {
            HeaderExtension::V1(extension) => extension.data_root,
        }
    }
}

#[derive(Clone, Debug, Decode, Encode, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Header {
    pub parent_hash: H256,
    #[codec(compact)]
    #[serde(deserialize_with = "deserialize_block_number")]
    pub number: u32,
    pub state_root: H256,
    pub extrinsics_root: H256,
    pub digest: Digest,
    pub extension: HeaderExtension,
}

fn deserialize_block_number<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    struct BlockNumberVisitor;

    impl<'de> Visitor<'de> for BlockNumberVisitor {
        type Value = u32;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a u32 block number or hex-encoded block number")
        }

        fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            value
                .try_into()
                .map_err(|_| E::custom("block number exceeds u32"))
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            let value = value.strip_prefix("0x").unwrap_or(value);
            u32::from_str_radix(value, 16).map_err(E::custom)
        }
    }

    deserializer.deserialize_any(BlockNumberVisitor)
}

impl Header {
    pub fn hash(&self) -> H256 {
        H256::from(sp_core::blake2_256(&self.encode()))
    }
}
