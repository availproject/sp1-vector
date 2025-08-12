use avail_subxt::{
    avail_rust_core::grandpa::GrandpaJustification, Client as AvailClient, ClientError,
};
use services::input::RpcDataFetcher;
use services::postgres::DatabaseClient;
use std::time::Duration;
use tokio::sync::mpsc::{self, error::TryRecvError, Receiver, Sender};
use tracing::{info, warn};
use tracing_subscriber::util::SubscriberInitExt;

#[derive(Debug)]
pub enum ChannelMessage {
    Justification(GrandpaJustification),
    Error(ClientError),
}

async fn task_fetch_justifications(
    client: AvailClient,
    block_height: u32,
    channel: Sender<ChannelMessage>,
) {
    let mut sub = client.subscription_grandpa_justification(block_height, Duration::from_secs(10));
    loop {
        let result = sub.next().await;
        let justification = match result {
            Ok(x) => x,
            Err(err) => {
                _ = channel.send(ChannelMessage::Error(err.into())).await;
                return;
            }
        };
        let res = channel
            .send(ChannelMessage::Justification(justification))
            .await;

        // If the other side is closed then there is nothing to do so we just exit
        if res.is_err() {
            return;
        }
    }
}

async fn fetch_block_height(client: &AvailClient) -> u32 {
    loop {
        let Ok(block_height) = client.finalized_block_height().await else {
            warn!("Failed to fetch finalized block height. Trying again in 3 seconds.");
            tokio::time::sleep(Duration::from_secs(3)).await;
            continue;
        };

        return block_height;
    }
}

async fn spawn_task(client: AvailClient, block_height: u32) -> Receiver<ChannelMessage> {
    let (tx, rx) = mpsc::channel::<ChannelMessage>(10);
    _ = tokio::spawn(async move { task_fetch_justifications(client, block_height, tx).await });
    info!("Spawned Justification Task. Block Height: {}", block_height);

    rx
}

async fn retrieve_justifications(
    rx: &mut Receiver<ChannelMessage>,
) -> Result<GrandpaJustification, ()> {
    loop {
        let maybe_message = rx.try_recv();
        let message = match maybe_message {
            Ok(x) => x,
            Err(TryRecvError::Empty) => {
                // No new justification was generated. Sleeping for 5 sec...
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
            Err(TryRecvError::Disconnected) => {
                return Err(());
            }
        };

        let justification: GrandpaJustification = match message {
            ChannelMessage::Justification(x) => x,
            ChannelMessage::Error(err) => {
                warn!("Justification Task Error: {:?}", err);
                return Err(());
            }
        };

        return Ok(justification);
    }
}

async fn send_justifications(chain_id: &str, justification: &GrandpaJustification) {
    loop {
        //TODO
        let mut client = DatabaseClient::new().await.unwrap();
        let result = client.add_justification(chain_id, justification).await;
        match result {
            Ok(_) => return,
            Err(err) => {
                warn!("Error: {}", err.to_string());
            }
        }

        // AWS client failed to send our justification. We don't know why so we will wait 20s and retry it.
        warn!("Database client failed to store our justification. Waiting 20 seconds and trying again.");
        tokio::time::sleep(Duration::from_secs(20)).await;
    }
}

#[tokio::main]
pub async fn main() {
    dotenv::dotenv().ok();
    let tracing_builder = tracing_subscriber::fmt::SubscriberBuilder::default();
    tracing_builder.finish().init();

    let client = DatabaseClient::new().await.unwrap();
    let data_fetcher = RpcDataFetcher::new().await;
    let chain_id = &data_fetcher.avail_chain_id;
    let mut next_block_height = client
        .get_latest_block_number(chain_id)
        .await
        .unwrap()
        .unwrap_or_default();
    if next_block_height > 0 {
        next_block_height += 1;
    }
    let mut rx = spawn_task(data_fetcher.client.clone(), next_block_height).await;

    loop {
        let Ok(justification) = retrieve_justifications(&mut rx).await else {
            // We failed to retrieve justification. This most likely happened because we failed to communicate
            // with a node.
            warn!("Failed to retrieve justification. Waiting 20 seconds before restarting everything.");
            tokio::time::sleep(Duration::from_secs(20)).await;

            rx = spawn_task(data_fetcher.client.clone(), next_block_height).await;
            continue;
        };

        info!(
            "Receive Justification. Block Height: {}",
            justification.commit.target_number
        );
        send_justifications(chain_id, &justification).await;
        info!(
            "Successfully added Justification to Database. Block Height {}",
            justification.commit.target_number
        );

        next_block_height = justification.commit.target_number + 1
    }
}
