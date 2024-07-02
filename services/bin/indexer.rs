use avail_subxt::primitives::Header;
use avail_subxt::RpcParams;
use codec::Decode;
use log::debug;
use serde::de::Error;
use serde::Deserialize;
use services::aws::AWSClient;
use services::input::RpcDataFetcher;
use services::types::{Commit, GrandpaJustification};
use sp_core::bytes;
use subxt::backend::rpc::RpcSubscription;

/// The justification type that the Avail Subxt client returns for justifications. Needs a custom
/// deserializer, so we can't use the equivalent `GrandpaJustification` type.
#[derive(Clone, Debug, Decode)]
pub struct AvailSubscriptionGrandpaJustification {
    pub round: u64,
    pub commit: Commit,
    #[allow(dead_code)]
    pub votes_ancestries: Vec<Header>,
}

impl From<AvailSubscriptionGrandpaJustification> for GrandpaJustification {
    fn from(justification: AvailSubscriptionGrandpaJustification) -> GrandpaJustification {
        GrandpaJustification {
            round: justification.round,
            commit: justification.commit,
            votes_ancestries: justification.votes_ancestries,
        }
    }
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

async fn listen_for_justifications(fetcher: RpcDataFetcher, aws_client: AWSClient) {
    let sub: Result<RpcSubscription<AvailSubscriptionGrandpaJustification>, _> = fetcher
        .client
        .rpc()
        .subscribe(
            "grandpa_subscribeJustifications",
            RpcParams::new(),
            "grandpa_unsubscribeJustifications",
        )
        .await;
    let mut sub = sub.unwrap();

    // Wait for new justification.
    while let Some(Ok(justification)) = sub.next().await {
        debug!(
            "New justification from block {}",
            justification.commit.target_number
        );

        aws_client
            .add_justification(&fetcher.avail_chain_id, justification.into())
            .await
            .unwrap();
    }
}

#[tokio::main]
pub async fn main() {
    dotenv::dotenv().ok();
    env_logger::init();

    let fetcher = RpcDataFetcher::new().await;
    let aws_client = AWSClient::new().await;

    listen_for_justifications(fetcher, aws_client).await;
}
