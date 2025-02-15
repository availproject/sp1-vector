use avail_subxt::primitives::Header;
use avail_subxt::RpcParams;
use codec::Decode;
use log::{debug, error, info};
use serde::de::Error;
use serde::Deserialize;
use services::aws::AWSClient;
use services::input::RpcDataFetcher;
use services::types::{Commit, GrandpaJustification};
use sp_core::bytes;
use subxt::backend::rpc::RpcSubscription;

use timeout::Timeout;

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

/// When the subscription yields events, add them to the indexer DB. If the subscription fails,
/// exit so the outer loop can re-initialize it.
async fn handle_subscription(
    sub: &mut RpcSubscription<AvailSubscriptionGrandpaJustification>,
    aws_client: &AWSClient,
    fetcher: &RpcDataFetcher,
    timeout_duration: std::time::Duration,
) {
    loop {
        match sub.next().timeout(timeout_duration).await {
            Ok(Some(Ok(justification))) => {
                debug!(
                    "New justification from block {}",
                    justification.commit.target_number
                );
                if let Err(e) = aws_client
                    .add_justification(&fetcher.avail_chain_id, justification.into())
                    .await
                {
                    error!("Error adding justification to AWS: {:?}", e);
                }
            }
            Ok(None) => {
                error!("Subscription ended unexpectedly");
                return;
            }
            Ok(Some(Err(e))) => {
                error!("Error in subscription: {:?}", e);
                return;
            }
            Err(_) => {
                error!("Timeout reached. No event received in the last minute.");
                return;
            }
        }
    }
}

/// Initialize the subscription for the grandpa justification events.
async fn initialize_subscription(
    fetcher: &RpcDataFetcher,
) -> Result<RpcSubscription<AvailSubscriptionGrandpaJustification>, subxt::Error> {
    fetcher
        .client
        .rpc()
        .subscribe(
            "grandpa_subscribeJustifications",
            RpcParams::new(),
            "grandpa_unsubscribeJustifications",
        )
        .await
}

/// Listen for justifications. If the subscription fails to yield a justification within the timeout
/// or errors, it will re-initialize the subscription.
async fn listen_for_justifications() {
    // Avail's block time is 20 seconds, as long as this is greater than that, we should be fine.
    let timeout_duration = std::time::Duration::from_secs(60);
    // Time to wait before retrying the subscription.
    let retry_delay = std::time::Duration::from_secs(5);

    loop {
        info!("Initializing fetcher and subscription...");

        let Ok(fetcher) = RpcDataFetcher::new().timeout(timeout_duration).await else {
            error!("Failed to initialize fetcher after timeout");
            continue;
        };

        // Initialize the AWS client.
        let Ok(aws_client) = AWSClient::new().timeout(timeout_duration).await else {
            error!("Failed to initialize AWS client after timeout");
            continue;
        };

        match initialize_subscription(&fetcher).await {
            Ok(mut sub) => {
                debug!("Subscription initialized successfully");
                handle_subscription(&mut sub, &aws_client, &fetcher, timeout_duration).await;
            }
            Err(e) => {
                debug!("Failed to initialize subscription: {:?}", e);
            }
        }

        debug!("Retrying subscription in {} seconds", retry_delay.as_secs());
        tokio::time::sleep(retry_delay).await;
    }
}

#[tokio::main]
pub async fn main() {
    dotenv::dotenv().ok();
    env_logger::init();

    listen_for_justifications().await;
}

mod timeout {
    use std::future::Future;
    use std::time::Duration;
    use tokio::time::{timeout, Timeout as TimeoutFuture};

    pub trait Timeout: Sized {
        fn timeout(self, duration: Duration) -> TimeoutFuture<Self>;
    }

    impl<T: Future> Timeout for T {
        fn timeout(self, duration: Duration) -> TimeoutFuture<Self> {
            timeout(duration, self)
        }
    }
}
