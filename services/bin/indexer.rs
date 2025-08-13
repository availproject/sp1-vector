use avail_subxt::{
    avail_rust_core::grandpa::GrandpaJustification, Client as AvailClient, ClientError,
};
use services::input::RpcDataFetcher;
use services::postgres::DatabaseClient;
use std::time::Duration;
use tokio::sync::mpsc::{self, Receiver, Sender};
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

async fn spawn_task(client: AvailClient, block_height: u32) -> Receiver<ChannelMessage> {
    let (tx, rx) = mpsc::channel::<ChannelMessage>(10);
    _ = tokio::spawn(async move { task_fetch_justifications(client, block_height, tx).await });
    info!("Spawned Justification Task. Block Height: {}", block_height);

    rx
}

async fn retrieve_justifications(
    rx: &mut Receiver<ChannelMessage>,
) -> Result<GrandpaJustification, ()> {
    let maybe_message = rx.recv().await;
    let message = match maybe_message {
        Some(x) => x,
        None => {
            warn!("Justification channel is closed. Returning Error.");
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

    Ok(justification)
}

async fn send_justification(
    chain_id: &str,
    justification: &GrandpaJustification,
) -> Result<(), String> {
    let mut client = DatabaseClient::new().await.map_err(|x| x.to_string())?;
    client
        .add_justification(chain_id, justification)
        .await
        .map_err(|x| x.to_string())
}

async fn send_justification_loop(chain_id: &str, justification: &GrandpaJustification) {
    let block_height = justification.commit.target_number;
    info!("Sending justification. Block Height: {}", block_height);

    loop {
        let result = send_justification(chain_id, justification).await;
        let err = match result {
            Ok(_) => return,
            Err(err) => err,
        };

        warn!("Failed to send justification with error: {}", err);
        warn!("Waiting 20 seconds and trying again.");
        tokio::time::sleep(Duration::from_secs(20)).await;
    }
}

async fn fetch_last_stored_block_height(chain_id: &str) -> Result<u32, String> {
    let client = DatabaseClient::new().await.map_err(|x| x.to_string())?;
    let block_height = client
        .get_latest_block_number(chain_id)
        .await
        .map_err(|x| x.to_string())?;

    info!("Block Height read from database: {:?}", block_height);
    let block_height = block_height.unwrap_or_default();

    Ok(block_height.saturating_sub(1))
}

// Run `DEBUG= cargo run --bin indexer` to use default debug env values
#[tokio::main]
pub async fn main() -> Result<(), String> {
    // Env and Tracing
    dotenv::dotenv().ok();
    let tracing_builder = tracing_subscriber::fmt::SubscriberBuilder::default();
    tracing_builder.finish().init();

    let data_fetcher = RpcDataFetcher::new().await;
    let chain_id = &data_fetcher.avail_chain_id;
    let mut next_block_height = fetch_last_stored_block_height(chain_id).await?;

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

        send_justification_loop(chain_id, &justification).await;

        let block_height = justification.commit.target_number;
        info!("Successfully added Justification to Database. Block Height: {block_height}");

        next_block_height = block_height + 1;
    }
}
