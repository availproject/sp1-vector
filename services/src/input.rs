use crate::redact::redact_urls;
use crate::types::{
    CoingekoApiResponse, EncodedFinalityProof, FinalityProof, VectorXJustificationApiResponse,
};
use alloy::primitives::{B256, B512};
use anyhow::{anyhow, bail, ensure, Context, Result};
use codec::{Decode, Encode};
use futures::future::try_join_all;
use sp1_vector_primitives::compute_authority_set_commitment;
use sp1_vector_primitives::rotate::get_next_validator_pubkeys_from_epoch_end_header;
use sp1_vector_primitives::types::{
    CircuitJustification, HeaderRangeInputs, HeaderRotateData, Precommit, RotateInputs,
};
use std::cmp::Ordering;
use std::env;
use std::time::Duration;

use avail_subxt::avail_rust_core::grandpa::{GrandpaJustification, Public};
use avail_subxt::subxt_rpcs::client::RpcParams;
use avail_subxt::StorageValue;
use avail_subxt::{AvailHeader, Client as AvailClient, H256};

/// In order to avoid errors from the RPC client, tasks should coordinate via this mutex to coordinate
/// large amounts of concurrent requests.
static CONCURRENCY_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// If the justification endpoint or CoinGecko takes too long to respond, time out.
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);

/// How many times to send a justification request before the failure is returned.
const JUSTIFICATION_REQUEST_ATTEMPTS: u32 = 3;

/// The error text of the justification endpoint for a block without a justification.
const NO_JUSTIFICATION_ERROR: &str = "No justification found";

/// Build an HTTP client with the request timeout. A client keeps its connections open, so reuse
/// one client for requests that follow each other.
fn http_client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder().timeout(HTTP_TIMEOUT).build()?)
}

/// An RPC data fetcher for fetching data for VectorX. The vectorx_query_url is only necessary when
/// querying justifications.
pub struct RpcDataFetcher {
    pub client: AvailClient,
    pub avail_chain_id: String,
    pub vectorx_query_url: Option<String>,
    /// The client for the justification endpoint. The block search sends many requests in a row,
    /// and they reuse its connection.
    http: reqwest::Client,
}

/// Data for the header range request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HeaderRangeRequestData {
    pub trusted_block: u32,
    pub target_block: u32,
    pub is_target_epoch_end_block: bool,
}

impl RpcDataFetcher {
    /// Connect to the Avail node. Panics if the configuration is missing or the connection fails.
    pub async fn new() -> Self {
        Self::try_new()
            .await
            .unwrap_or_else(|e| panic!("Failed to create the Avail data fetcher: {e:?}"))
    }

    /// Connect to the Avail node, and return an error if the configuration is missing or the
    /// connection fails.
    pub async fn try_new() -> Result<Self> {
        dotenv::dotenv().ok();

        let (url, avail_chain_id) = if std::env::var("DEBUG").is_ok() {
            (
                env::var("AVAIL_URL").unwrap_or_else(|_| "http://localhost:9944".to_owned()),
                env::var("AVAIL_CHAIN_ID").unwrap_or_else(|_| "avail_c".to_owned()),
            )
        } else {
            (
                env::var("AVAIL_URL").context("AVAIL_URL must be set")?,
                env::var("AVAIL_CHAIN_ID").context("AVAIL_CHAIN_ID must be set")?,
            )
        };

        // The client's error prints the node URL, which can carry an API key.
        let client = AvailClient::new(url.as_str())
            .await
            .map_err(avail_error)
            .context("Failed to connect to the Avail node")?;

        Ok(RpcDataFetcher {
            client,
            avail_chain_id,
            vectorx_query_url: env::var("VECTORX_QUERY_URL").ok(),
            http: http_client()?,
        })
    }

    /// Fetch the justification of a block from the justification endpoint. Returns `None` when
    /// the endpoint answers that it has no justification for the block. A failed request is an
    /// error, so the caller can tell an outage from a block without a justification.
    pub async fn get_justification(
        &self,
        block_number: u32,
    ) -> Result<Option<GrandpaJustification>> {
        let Some(query_url) = self.vectorx_query_url.as_ref() else {
            bail!("VECTORX_QUERY_URL must be set");
        };

        let request_url = format!(
            "{}/api/justification?availChainId={}&blockNumber={}",
            query_url, self.avail_chain_id, block_number
        );

        // Retry a failed request, so that one transient failure does not end the run.
        let mut attempt = 1;
        loop {
            match request_justification(&self.http, &request_url, block_number).await {
                Ok(justification) => return Ok(justification),
                Err(e) if attempt < JUSTIFICATION_REQUEST_ATTEMPTS => {
                    tracing::warn!(
                        "Justification request for block {} failed, attempt {}: {:?}",
                        block_number,
                        attempt,
                        e
                    );
                    attempt += 1;
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Get the inputs for a header range proof. Optionally pass in the header range commitment tree size.
    /// If not passed in, it will be set to the nearest power of 2.
    pub async fn get_header_range_inputs(
        &self,
        header_range_request_data: HeaderRangeRequestData,
        header_range_commitment_tree_size: Option<u32>,
    ) -> Result<HeaderRangeInputs> {
        // The trusted header is not a leaf: the tree commits to (trusted_block, target_block].
        let num_leaves =
            header_range_request_data.target_block - header_range_request_data.trusted_block;
        let merkle_tree_size = get_merkle_tree_size(num_leaves, header_range_commitment_tree_size);

        tracing::debug!(
            "Getting block headers range from {} to {}",
            header_range_request_data.trusted_block,
            header_range_request_data.target_block
        );

        let headers = self
            .get_block_headers_range(
                header_range_request_data.trusted_block,
                header_range_request_data.target_block,
            )
            .await?;
        let encoded_headers: Vec<Vec<u8>> = headers.iter().map(|header| header.encode()).collect();

        let target_justification = self
            .get_justification_data_for_block(
                header_range_request_data.target_block,
                header_range_request_data.is_target_epoch_end_block,
            )
            .await?
            .with_context(|| {
                format!(
                    "No justification for target block {}",
                    header_range_request_data.target_block
                )
            })?;

        Ok(HeaderRangeInputs {
            merkle_tree_size,
            encoded_headers,
            target_justification,
        })
    }

    pub async fn get_rotate_inputs(&self, authority_set_id: u64) -> Result<RotateInputs> {
        let epoch_end_block = self.last_justified_block(authority_set_id).await?;
        ensure!(
            epoch_end_block != 0,
            "Current authority set is still active!"
        );

        let justification = keep_precommits_on_target(
            self.get_justification_data_epoch_end_block(epoch_end_block)
                .await?,
        );

        let header_rotate_data = self.get_header_rotate(epoch_end_block).await?;

        Ok(RotateInputs {
            justification,
            header_rotate_data,
        })
    }

    // This function returns the last block justified by target_authority_set_id. This block
    // also specifies the new authority set, which starts justifying after this block.
    // Returns 0 if curr_authority_set_id <= target_authority_set_id.
    pub async fn last_justified_block(&self, target_authority_set_id: u64) -> Result<u32> {
        let mut low = 0;
        let head_block = self.get_head().await?;
        let mut high = head_block.number;
        let mut epoch_end_block_number = 0;

        while low <= high {
            let mid = (low + high) / 2;
            let mid_authority_set_id = self.get_authority_set_id(mid).await?;

            match mid_authority_set_id.cmp(&(target_authority_set_id + 1)) {
                Ordering::Equal => {
                    if mid == 0 {
                        // Special case: there is no block "mid - 1", just return the found block.
                        epoch_end_block_number = mid;
                        break;
                    }
                    let prev_authority_set_id = self.get_authority_set_id(mid - 1).await?;
                    if prev_authority_set_id == target_authority_set_id {
                        epoch_end_block_number = mid;
                        break;
                    } else {
                        high = mid - 1;
                    }
                }
                Ordering::Less => low = mid + 1,
                Ordering::Greater => high = mid - 1,
            }
        }
        Ok(epoch_end_block_number)
    }

    pub async fn get_block_hash(&self, block_number: u32) -> Result<B256> {
        let block_hash = self
            .client
            .block_hash_ext(block_number, true, false)
            .await
            .map_err(avail_error)?
            .with_context(|| format!("The Avail node has no hash for block {block_number}"))?;

        Ok(B256::from(block_hash.0))
    }

    /// This function returns a vector of headers for a given range of block numbers, inclusive of the start and end block numbers.
    pub async fn get_block_headers_range(
        &self,
        start_block_number: u32,
        end_block_number: u32,
    ) -> Result<Vec<AvailHeader>> {
        // Fetch the headers in batches of MAX_CONCURRENT_WS_REQUESTS. The WS connection will error if there
        // are too many concurrent requests with Rpc(ClientError(MaxSlotsExceeded)).
        const MAX_CONCURRENT_WS_REQUESTS: usize = 200;

        // Take the guard to coordinate concurrent requests.
        let _guard = CONCURRENCY_MUTEX.lock().await;

        let mut headers = Vec::new();
        let mut curr_block = start_block_number;
        while curr_block <= end_block_number {
            let end_block = std::cmp::min(
                curr_block + MAX_CONCURRENT_WS_REQUESTS as u32 - 1,
                end_block_number,
            );
            let header_futures: Vec<_> = (curr_block..end_block + 1)
                .map(|block_number| self.get_header(block_number))
                .collect();

            // Await all futures concurrently
            let headers_batch: Vec<AvailHeader> = try_join_all(header_futures).await?;

            headers.extend(headers_batch);
            curr_block += MAX_CONCURRENT_WS_REQUESTS as u32;
        }
        Ok(headers)
    }

    pub async fn get_header(&self, block_number: u32) -> Result<AvailHeader> {
        let block_hash = self.get_block_hash(block_number).await?;
        self.client
            .block_header(H256::from(block_hash.0))
            .await
            .map_err(avail_error)?
            .with_context(|| format!("The Avail node has no header for block {block_number}"))
    }

    pub async fn get_head(&self) -> Result<AvailHeader> {
        let head_block_hash = self
            .client
            .finalized_block_hash_ext(true)
            .await
            .map_err(avail_error)?;
        self.client
            .block_header(head_block_hash)
            .await
            .map_err(avail_error)?
            .context("The Avail node has no header for the finalized head")
    }

    pub async fn get_authority_set_id(&self, block_number: u32) -> Result<u64> {
        use avail_subxt::avail::grandpa::storage::CurrentSetId;
        let block_hash = self.get_block_hash(block_number).await?;

        let at = Some(H256::from(block_hash.0));
        let set_id = CurrentSetId::fetch(&self.client.rpc_client, at)
            .await
            .map_err(avail_error)?
            .with_context(|| format!("No GRANDPA set id in storage at block {block_number}"))?;
        // todo hacky way of using auth set for hex devnet
        if self.avail_chain_id == "hex" {
            return Ok(set_id - 1);
        }

        Ok(set_id)
    }

    // This function returns the authorities (as AffinePoint and public key bytes) for a given block number
    // by fetching the "authorities_bytes" from storage and decoding the bytes to a VersionedAuthorityList.
    // Note: The authorities returned by this function attest to block_number + 1.
    pub async fn get_authorities(&self, block_number: u32) -> Result<Vec<B256>> {
        let block_hash = self.get_block_hash(block_number).await?;

        let grandpa_authorities = self
            .client
            .runtime_api()
            .call::<Vec<(Public, u64)>>(
                "GrandpaApi_grandpa_authorities",
                &[],
                Some(H256::from(block_hash.0)),
            )
            .await
            .map_err(avail_error)?;

        let mut authorities: Vec<B256> = Vec::new();
        for (pub_key, weight) in grandpa_authorities {
            authorities.push(B256::from(pub_key.0));
            // The circuit requires that the weight of each validator is 1.
            ensure!(weight == 1, "The weight of the authority is not 1!");
        }

        Ok(authorities)
    }

    /// Computes the authority_set_hash for a given block number. Note: This is the authority set hash
    /// that validates the next block after the given block number.
    pub async fn compute_authority_set_hash_for_block(&self, block_number: u32) -> Result<B256> {
        let authorities = self.get_authorities(block_number).await?;
        Ok(compute_authority_set_commitment(authorities.as_slice()))
    }

    /// Get the justification data necessary for the circuit using GrandpaJustification and the block number.
    async fn compute_data_from_justification(
        &self,
        justification: GrandpaJustification,
        block_number: u32,
    ) -> Result<CircuitJustification> {
        // Get the authority set id that attested to block_number.
        let authority_set_id = self.get_authority_set_id(block_number - 1).await?;

        // Get the authority set for the block number.
        let authorities = self.get_authorities(block_number - 1).await?;

        Ok(convert_justification_and_valset_to_circuit(
            justification,
            authorities,
            authority_set_id,
        ))
    }

    /// Get the justification for a block: from `grandpa_proveFinality` for an epoch end block, and
    /// from the justification endpoint for every other block. Returns `None` when the source has
    /// no justification for the block, and an error when the source fails.
    pub async fn get_justification_data_for_block(
        &self,
        block_number: u32,
        is_epoch_end_block: bool,
    ) -> Result<Option<CircuitJustification>> {
        let grandpa_justification = match is_epoch_end_block {
            // If the node has no finality proof for this exact block, or the RPC fails, try the
            // endpoint.
            true => match self
                .get_justification_data_for_block_unsafe(block_number)
                .await
            {
                Ok(Some(justification)) => Some(justification),
                Ok(None) => self.get_justification(block_number).await?,
                Err(rpc_error) => {
                    tracing::warn!(
                        "grandpa_proveFinality failed for block {}, trying the justification endpoint: {:?}",
                        block_number,
                        rpc_error
                    );
                    match self.get_justification(block_number).await {
                        Ok(Some(justification)) => Some(justification),
                        _ => return Err(rpc_error),
                    }
                }
            },
            false => self.get_justification(block_number).await?,
        };

        let Some(grandpa_justification) = grandpa_justification else {
            return Ok(None);
        };

        // Convert the justification into a CircuitJustification.
        let circuit_justification = self
            .compute_data_from_justification(grandpa_justification, block_number)
            .await?;
        Ok(Some(circuit_justification))
    }

    /// Get the justification data for a block number. Unsafe, not guaranteed to be correct.
    /// Returns `None` when the node has no finality proof for the block.
    pub async fn get_justification_data_for_block_unsafe(
        &self,
        epoch_end_block: u32,
    ) -> Result<Option<GrandpaJustification>> {
        // If epoch end block, use grandpa_proveFinality to get the justification.
        let mut params = RpcParams::new();
        let _ = params.push(epoch_end_block);

        let encoded_finality_proof = self
            .client
            .rpc_api()
            .call::<Option<EncodedFinalityProof>>("grandpa_proveFinality", params)
            .await
            .map_err(avail_error)?;

        let Some(encoded_finality_proof) = encoded_finality_proof else {
            return Ok(None);
        };

        let finality_proof: FinalityProof =
            Decode::decode(&mut encoded_finality_proof.0.as_slice())
                .map_err(|e| anyhow!("Failed to decode the finality proof: {e}"))?;
        let justification: GrandpaJustification =
            Decode::decode(&mut finality_proof.justification.as_slice())
                .map_err(|e| anyhow!("Failed to decode the justification: {e}"))?;

        // `grandpa_proveFinality` answers with the justification that ends the authority set of
        // the block. That is another block when the requested block is not an epoch end.
        if justification.commit.target_number != epoch_end_block {
            tracing::warn!(
                "grandpa_proveFinality for block {} returned a justification for block {}",
                epoch_end_block,
                justification.commit.target_number
            );
            return Ok(None);
        }

        Ok(Some(justification))
    }

    /// Get the justification data for an epoch end block, the last block that an authority set justifies.
    /// Fetch the authority set and justification proof for the block. If the finality proof is a
    /// simple justification, return a CircuitJustification with the encoded precommit that all
    /// authorities sign, the validator signatures, and the authority set's pubkeys.
    ///
    /// `epoch_end_block` must not be 0. `get_rotate_inputs` checks that.
    async fn get_justification_data_epoch_end_block(
        &self,
        epoch_end_block: u32,
    ) -> Result<CircuitJustification> {
        let grandpa_justification = self
            .get_justification_data_for_block_unsafe(epoch_end_block)
            .await?
            .with_context(|| format!("No justification for epoch end block {epoch_end_block}"))?;
        self.compute_data_from_justification(grandpa_justification, epoch_end_block)
            .await
    }

    /// This function takes in the number of an epoch end block as input, and fetches the new authority
    /// set specified in that block. It returns the encoded epoch end header, which the circuit decodes
    /// to find the new authority set.
    ///
    /// `epoch_end_block` must not be 0. `get_rotate_inputs` checks that.
    async fn get_header_rotate(&self, epoch_end_block: u32) -> Result<HeaderRotateData> {
        let header = self.get_header(epoch_end_block).await?;

        let header_bytes = header.encode();

        // Fetch the new authority set specified in the epoch end block.
        let expected_new_authorities = self.get_authorities(epoch_end_block).await?;

        // Decode the header the same way the circuit does. The decoder panics if the header has no
        // GRANDPA ScheduledChange, for example when the set changed through a ForcedChange. The
        // circuit would panic on the same header, so no rotate proof exists for it.
        let extracted_new_authorities = std::panic::catch_unwind(|| {
            get_next_validator_pubkeys_from_epoch_end_header(&header_bytes)
        })
        .map_err(|_| {
            anyhow!("The header of epoch end block {epoch_end_block} has no valid ScheduledChange")
        })?;

        ensure!(
            extracted_new_authorities == expected_new_authorities,
            "The authorities in the header of block {epoch_end_block} differ from the authorities in storage"
        );

        Ok(HeaderRotateData { header_bytes })
    }
}

/// Send one request to the justification endpoint.
///
/// The endpoint answers HTTP 200 with `success: false` both for a block without a justification
/// and for its own failures, for example a database error. Only the error text tells them apart.
async fn request_justification(
    http: &reqwest::Client,
    request_url: &str,
    block_number: u32,
) -> Result<Option<GrandpaJustification>> {
    let body = http
        .get(request_url)
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(reqwest::Error::without_url)
        .context("The justification request failed")?
        .text()
        .await
        .map_err(reqwest::Error::without_url)
        .context("Failed to read the justification response")?;

    parse_justification_response(&body, block_number)
}

/// Read the answer of the justification endpoint: `Some` for a justification, `None` for a block
/// without one, and an error when the endpoint reports a failure.
fn parse_justification_response(
    body: &str,
    block_number: u32,
) -> Result<Option<GrandpaJustification>> {
    // A body that does not decode is a fault of this one block's record. Skip the block, so that
    // the caller can use the next one.
    let response: VectorXJustificationApiResponse = match serde_json::from_str(body) {
        Ok(response) => response,
        Err(e) => {
            tracing::warn!(
                "The justification response for block {} does not decode: {}",
                block_number,
                e
            );
            return Ok(None);
        }
    };

    if response.success {
        return match response.justification {
            Some(justification) => Ok(Some(justification)),
            None => bail!("The justification response has success = true and no justification"),
        };
    }

    match response.error.as_deref() {
        Some(NO_JUSTIFICATION_ERROR) | None => Ok(None),
        Some(error) => bail!("The justification endpoint failed for block {block_number}: {error}"),
    }
}

/// Convert an Avail client error into an error without the node URL. The client's error prints
/// the URL of the request that failed, and that URL can carry an API key.
fn avail_error(error: impl std::fmt::Debug) -> anyhow::Error {
    anyhow!("Avail RPC error: {}", redact_urls(&format!("{error:?}")))
}

/// Demo keys are only valid on the public host and pro keys on the pro-api host, each with its
/// own header name. A key under the wrong name is ignored and the request is treated as anonymous.
///
/// The key goes in a header and not in the query string, so that no error can print it with
/// the URL.
fn coingecko_api_key_header(base_url: &str) -> &'static str {
    if base_url.contains("pro-api") {
        "x-cg-pro-api-key"
    } else {
        "x-cg-demo-api-key"
    }
}

pub async fn fetch_usd_rate() -> Result<CoingekoApiResponse> {
    let from_token: String = env::var("ASSET_TO_USD_CONVERSION").unwrap_or("ethereum".to_string());
    let coingeko_url =
        env::var("COINGEKO_URL").unwrap_or("https://api.coingecko.com/api".to_string());
    let coingeko_api_key = env::var("COINGEKO_API_KEY").context("Missing COINGEKO_API_KEY env")?;

    let price_endpoint =
        format!("{coingeko_url}/v3/simple/price?ids={from_token}&vs_currencies=usd");
    let response = http_client()?
        .get(price_endpoint)
        .header(coingecko_api_key_header(&coingeko_url), coingeko_api_key)
        .send()
        .await
        .map_err(reqwest::Error::without_url)
        .context("The CoinGecko request failed")?;
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(reqwest::Error::without_url)
        .context("Failed to read the CoinGecko response")?;
    if !status.is_success() {
        bail!("CoinGecko returned {status}: {body}");
    }
    serde_json::from_str(&body)
        .with_context(|| format!("Unexpected CoinGecko response body: {body}"))
}

#[cfg(test)]
mod coingecko_tests {
    use super::coingecko_api_key_header;

    #[test]
    fn demo_key_header_on_public_host() {
        assert_eq!(
            coingecko_api_key_header("https://api.coingecko.com/api"),
            "x-cg-demo-api-key"
        );
    }

    #[test]
    fn pro_key_header_on_pro_host() {
        assert_eq!(
            coingecko_api_key_header("https://pro-api.coingecko.com/api"),
            "x-cg-pro-api-key"
        );
    }
}

/// Converts GrandpaJustification and validator set to CircuitJustification.
pub fn convert_justification_and_valset_to_circuit(
    justification: GrandpaJustification,
    validator_set: Vec<B256>,
    set_id: u64,
) -> CircuitJustification {
    let precommits = justification
        .commit
        .precommits
        .iter()
        .map(|e| Precommit {
            target_number: e.precommit.target_number,
            target_hash: B256::from(e.precommit.target_hash.0),
            pubkey: B256::from(e.id.0),
            signature: B512::from(e.signature.0),
        })
        .collect::<Vec<_>>();

    let ancestries_encoded = justification
        .votes_ancestries
        .iter()
        .map(Encode::encode)
        .collect::<Vec<_>>();

    CircuitJustification {
        round: justification.round,
        authority_set_id: set_id,
        valset_pubkeys: validator_set.clone(),
        precommits,
        block_hash: justification.commit.target_hash.0.into(),
        ancestries_encoded,
    }
}

/// Keep only the precommits on the justified block itself, and drop the ancestries.
///
/// A precommit can target a descendant of the justified block. The justification then carries the
/// headers that link the two, and the rotate circuit rejects every justification with ancestries.
/// The circuit still requires a supermajority, so the remaining precommits must reach it alone.
pub fn keep_precommits_on_target(mut justification: CircuitJustification) -> CircuitJustification {
    let block_hash = justification.block_hash;
    justification
        .precommits
        .retain(|precommit| precommit.target_hash == block_hash);
    justification.ancestries_encoded.clear();
    justification
}

/// Check the tree size against the number of leaves, mirroring the circuit's check in
/// `get_merkle_root_commitments`. Without a tree size, use the nearest power of 2.
fn get_merkle_tree_size(num_leaves: u32, header_range_commitment_tree_size: Option<u32>) -> usize {
    if let Some(header_range_commitment_tree_size) = header_range_commitment_tree_size {
        assert!(
            header_range_commitment_tree_size >= num_leaves
                && header_range_commitment_tree_size.is_power_of_two(),
            "Header range commitment tree size must be greater than or equal to the number of leaves and a power of two"
        );
        return header_range_commitment_tree_size as usize;
    }

    // NOTE: DANGEROUS. ONLY USED IN TESTING. IN PROD, FETCH FROM CONTRACT.
    let mut size = 1;
    while size < num_leaves {
        size *= 2;
    }
    size as usize
}

#[cfg(test)]
mod tests {
    use crate::types::SignerMessage;
    use avail_subxt::ext::avail_rust_core::grandpa::{Commit, Precommit};
    use avail_subxt::AvailHeader;
    use serde::{Deserialize, Serialize};
    use sp1_vector_primitives::types::Precommit as CircuitPrecommit;
    use sp1_vector_primitives::{
        rotate::get_next_validator_pubkeys_from_epoch_end_header, verify_justification,
    };
    use std::fs::File;
    use test_case::test_case;

    use super::*;

    #[test]
    fn test_parse_justification_response() {
        // The answers of the production endpoint, checked on 2026-11-16.
        let missing = r#"{"success":false,"error":"No justification found"}"#;
        assert!(parse_justification_response(missing, 1).unwrap().is_none());

        // A failure of the endpoint is an error, not a missing justification.
        let failure = r#"{"success":false,"error":"Database error occurred"}"#;
        assert!(parse_justification_response(failure, 1).is_err());

        // A record that does not decode is skipped.
        assert!(parse_justification_response("not json", 1)
            .unwrap()
            .is_none());

        let no_data = r#"{"success":true}"#;
        assert!(parse_justification_response(no_data, 1).is_err());
    }

    #[test]
    fn test_merkle_tree_size_accepts_full_range() {
        // A range of tree_size blocks after the trusted block fills the tree exactly.
        assert_eq!(get_merkle_tree_size(512, Some(512)), 512);
        assert_eq!(get_merkle_tree_size(511, Some(512)), 512);
    }

    #[test]
    #[should_panic(expected = "Header range commitment tree size")]
    fn test_merkle_tree_size_rejects_overfull_range() {
        get_merkle_tree_size(513, Some(512));
    }

    #[test]
    fn test_merkle_tree_size_defaults_to_next_power_of_two() {
        assert_eq!(get_merkle_tree_size(512, None), 512);
        assert_eq!(get_merkle_tree_size(513, None), 1024);
    }

    #[tokio::test]
    async fn test_get_simple_justification_change_authority_set() {
        let fetcher = RpcDataFetcher::new().await;

        // This is an block in the middle of an era.
        let block = 645570;

        let authority_set_id = fetcher.get_authority_set_id(block - 1).await.unwrap();
        let authority_set_hash = fetcher
            .compute_authority_set_hash_for_block(block - 1)
            .await
            .unwrap();
        let header = fetcher.get_header(block).await.unwrap();
        let header_hash = header.hash();

        println!("authority_set_id {:?}", authority_set_id);
        println!("authority_set_hash {:?}", hex::encode(authority_set_hash.0));
        println!("header_hash {:?}", hex::encode(header_hash.0));

        let epoch_end_block = fetcher
            .last_justified_block(authority_set_id)
            .await
            .unwrap();
        let _ = fetcher
            .get_justification_data_epoch_end_block(epoch_end_block)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_get_new_authority_set() {
        dotenv::dotenv().ok();
        env_logger::init();

        let fetcher = RpcDataFetcher::new().await;

        // A binary search given a target_authority_set_id, returns the last block justified by
        // target_authority_set_id. This block also specifies the new authority set,
        // target_authority_set_id + 1.
        let target_authority_set_id = 2;
        let epoch_end_block_number = fetcher
            .last_justified_block(target_authority_set_id)
            .await
            .unwrap();

        // Verify that this is an epoch end block.
        assert_ne!(epoch_end_block_number, 0);
        println!("epoch_end_block_number {:?}", epoch_end_block_number);

        let previous_authority_set_id = fetcher
            .get_authority_set_id(epoch_end_block_number - 1)
            .await
            .unwrap();
        let new_authority_set_id = fetcher
            .get_authority_set_id(epoch_end_block_number)
            .await
            .unwrap();

        let new_authorities = fetcher
            .get_authorities(epoch_end_block_number)
            .await
            .unwrap();
        let expected_new_authority_set_hash = compute_authority_set_commitment(&new_authorities);

        // Verify this is an epoch end block.
        assert_eq!(previous_authority_set_id + 1, new_authority_set_id);
        assert_eq!(previous_authority_set_id, target_authority_set_id);

        let rotate_data = fetcher
            .get_header_rotate(epoch_end_block_number)
            .await
            .unwrap();
        let new_authority_set_hash = compute_authority_set_commitment(
            &get_next_validator_pubkeys_from_epoch_end_header(&rotate_data.header_bytes),
        );
        assert_eq!(new_authority_set_hash, expected_new_authority_set_hash);
    }

    #[test]
    fn test_signed_message_encoding() {
        let h1 = H256::random();

        // Cannonical way of forming the signed message (taken from Substrate code)
        let msg1 = Encode::encode(&(
            &SignerMessage::PrecommitMessage(Precommit {
                target_hash: h1,
                target_number: 2,
            }),
            3u64,
            4u64,
        ));

        // Simplified encoding using none of the Substrate-specific structures
        let msg2 = Encode::encode(&(1u8, B256::from(h1.0).0, 2u32, 3u64, 4u64));
        assert_eq!(msg1, msg2, "Messages are not equal")
    }

    #[test]
    fn test_keep_precommits_on_target() {
        let target = B256::repeat_byte(1);
        let child = B256::repeat_byte(2);
        let precommit = |target_number, target_hash, signer: u8| CircuitPrecommit {
            target_number,
            target_hash,
            pubkey: B256::repeat_byte(signer),
            signature: B512::ZERO,
        };
        let justification = CircuitJustification {
            round: 1,
            authority_set_id: 10,
            valset_pubkeys: vec![],
            precommits: vec![
                precommit(100, target, 10),
                precommit(101, child, 11),
                precommit(100, target, 12),
            ],
            block_hash: target,
            ancestries_encoded: vec![vec![0u8; 32]],
        };

        let filtered = keep_precommits_on_target(justification);

        let signers: Vec<B256> = filtered.precommits.iter().map(|p| p.pubkey).collect();
        assert_eq!(signers, [B256::repeat_byte(10), B256::repeat_byte(12)]);
        assert!(filtered.ancestries_encoded.is_empty());
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct JsonGrandpaJustification {
        pub round: u64,
        pub commit: Commit,
        pub votes_ancestries: Vec<AvailHeader>,
    }

    impl From<GrandpaJustification> for JsonGrandpaJustification {
        fn from(value: GrandpaJustification) -> Self {
            Self {
                round: value.round,
                commit: value.commit,
                votes_ancestries: value.votes_ancestries,
            }
        }
    }

    impl From<JsonGrandpaJustification> for GrandpaJustification {
        fn from(value: JsonGrandpaJustification) -> Self {
            GrandpaJustification {
                round: value.round,
                commit: value.commit,
                votes_ancestries: value.votes_ancestries,
            }
        }
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct ValidatorSet {
        pub set_id: u64,
        pub validator_set: Vec<Public>,
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct ValidatorSetAndJustification {
        pub validator_set: ValidatorSet,
        pub justification: JsonGrandpaJustification,
    }

    #[test_case("test_assets/ancestry.json"; "Complex ancestry")]
    #[test_case("test_assets/ancestry_missing_link_no_majority.json" => panics "More than 2/3 of signatures are not verifie!"; "Missing ancestor negative case")]
    #[test_case("test_assets/ancestry_missing_link_works.json"; "Missing ancestor")]
    /// Tesing some complex justifications, serialized in JSON format (for readability)
    fn test_complex_justification(path: &str) {
        let test_case_file = File::open(path).unwrap();
        let validator_set_and_justification: ValidatorSetAndJustification =
            serde_json::from_reader(test_case_file).unwrap();

        let justification: GrandpaJustification =
            validator_set_and_justification.justification.into();
        let validator_set = validator_set_and_justification
            .validator_set
            .validator_set
            .iter()
            .map(|e| B256::from(e.0))
            .collect::<Vec<_>>();
        let circuit_justification = convert_justification_and_valset_to_circuit(
            justification,
            validator_set,
            validator_set_and_justification.validator_set.set_id,
        );

        verify_justification(&circuit_justification)
    }
}
