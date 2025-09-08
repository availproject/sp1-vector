use avail_subxt::avail_rust_core::grandpa::{GrandpaJustification, Precommit};
use avail_subxt::{AvailHeader, H256};
use codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

pub use impl_serde::serialize as bytes;

#[derive(Debug, Encode)]
pub enum SignerMessage {
    #[allow(dead_code)]
    DummyMessage(u32),
    PrecommitMessage(Precommit),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EncodedFinalityProof(#[serde(with = "bytes")] pub Vec<u8>);

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

#[cfg(test)]
mod tests {
    use super::VectorXJustificationApiResponse;
    use alloy::hex;
    use avail_subxt::AccountId;
    use avail_subxt::H256;

    #[test]
    pub fn test_justification_rsp() {
        let rsp = r#"{
  "success": true,
  "justification": {
    "round": 5118,
    "commit": {
      "precommits": [
        {
          "id": "5CExo2wmED2c3genFUdY9kkeSBHsfAcUbDTBVDpTZ8M26xyg",
          "precommit": {
            "target_hash": "0xfe0652f4564fe2b55fcd41edac2846da7eec9aae335db8149f456a9b784141ab",
            "target_number": 2075796
          },
          "signature": "58b592617471b8857db9b5bca458a4574bb7103cc87a5777be19650551a9a76ea47b3034dc03b137c204e55864a7f13d490df85a65f99909c3fcba1ddb039401"
        },
        {
          "id": "5CX5q5xv6uiAwBD9tmzPg1zTtEi7KhvSWzNtMfXJFKN4woLK",
          "precommit": {
            "target_hash": "0xfe0652f4564fe2b55fcd41edac2846da7eec9aae335db8149f456a9b784141ab",
            "target_number": 2075796
          },
          "signature": "da13946cf5ed0ded1a0d385bcfa4ee2edda7dade7569dc9dff34fdf520f97b4468c2ea77cb7c6cdc5350a70b7d0a28d8512b62e3c20f392d80dad1f18fa67400"
        }
      ],
      "target_hash": "0xfe0652f4564fe2b55fcd41edac2846da7eec9aae335db8149f456a9b784141ab",
      "target_number": 2075796
    },
    "votes_ancestries": []
  }
}"#;

        let justification_rsp: VectorXJustificationApiResponse = serde_json::from_str(rsp).unwrap();
        assert_eq!(justification_rsp.success, true);

        let justification = justification_rsp.justification.unwrap();

        assert_eq!(justification.commit.target_number, 2075796);
        assert_eq!(
            justification.commit.target_hash,
            H256(hex!(
                "fe0652f4564fe2b55fcd41edac2846da7eec9aae335db8149f456a9b784141ab"
            ))
        );
        assert_eq!(justification.commit.precommits.len(), 2);
        assert_eq!(
            AccountId::from(justification.commit.precommits[0].id.0).to_string(),
            "5CExo2wmED2c3genFUdY9kkeSBHsfAcUbDTBVDpTZ8M26xyg"
        );
        assert_eq!(
            AccountId::from(justification.commit.precommits[1].id.0).to_string(),
            "5CX5q5xv6uiAwBD9tmzPg1zTtEi7KhvSWzNtMfXJFKN4woLK"
        );
        assert_eq!(
            justification.commit.precommits[1].precommit.target_number,
            2075796
        );
        assert_eq!(
            justification.commit.precommits[1].precommit.target_hash,
            H256(hex!(
                "fe0652f4564fe2b55fcd41edac2846da7eec9aae335db8149f456a9b784141ab"
            ))
        );
        assert_eq!(hex::encode(&justification.commit.precommits[1].signature.0), "da13946cf5ed0ded1a0d385bcfa4ee2edda7dade7569dc9dff34fdf520f97b4468c2ea77cb7c6cdc5350a70b7d0a28d8512b62e3c20f392d80dad1f18fa67400");
        assert_eq!(justification.votes_ancestries.len(), 0);
    }
}
