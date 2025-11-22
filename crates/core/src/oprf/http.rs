//! HTTP backend for OPRF client operations.
//!
//! This module provides the Tokio/reqwest-based HTTP implementation for
//! communicating with OPRF service peers.
//!
//! Key functions:
//! - [`init_sessions`] — kicks off OPRF sessions by `POSTing` to `/api/v1/init`
//!   until the configured threshold of valid responses is reached.
//! - [`finish_sessions`] — completes all stored sessions in parallel by `POSTing`
//!   to `/api/v1/finish`.
//!
//! Errors from individual peers are tolerated during init, as long as the
//! threshold can still be met.

use eyre::Context;
use oprf_types::api::v1::{ChallengeRequest, ChallengeResponse, OprfRequest, OprfResponse};
use tokio::task::JoinSet;
use world_id_primitives::oprf::OprfRequestAuthV1;

use super::session::OprfSessions;
use super::ProofError;

type Result<T> = std::result::Result<T, ProofError>;

/// Sends an `init` request to one OPRF peer.
///
/// Returns the peer's URL alongside the parsed [`OprfResponse`].
async fn oprf_request(
    client: reqwest::Client,
    service: String,
    req: OprfRequest<OprfRequestAuthV1>,
) -> Result<(String, OprfResponse)> {
    let response = client
        .post(format!("{service}/api/v1/init"))
        .json(&req)
        .send()
        .await?;
    if response.status().is_success() {
        let response = response.json::<OprfResponse>().await?;
        Ok((service, response))
    } else {
        let status = response.status();
        let message = response.text().await?;
        Err(ProofError::ApiError { status, message })
    }
}

/// Sends a `challenge` request to one OPRF service.
///
/// Returns the parsed [`ChallengeResponse`].
async fn oprf_challenge(
    client: reqwest::Client,
    service: String,
    req: ChallengeRequest,
) -> Result<ChallengeResponse> {
    let response = client
        .post(format!("{service}/api/v1/finish"))
        .json(&req)
        .send()
        .await?;
    if response.status().is_success() {
        let response = response.json::<ChallengeResponse>().await?;
        Ok(response)
    } else {
        let status = response.status();
        let message = response.text().await?;
        Err(ProofError::ApiError { status, message })
    }
}

/// Completes all OPRF sessions in parallel by calling `/api/v1/finish`
/// on every peer in the [`OprfSessions`].
///
/// **Important:**
/// - These must be the *same parties* that were used during the initial
///   `init_sessions` call.
/// - The order of the peers matters: we return responses in the order provided and they need
///   to match the original session list. This is crucial because Lagrange coefficients are
///   computed in the meantime, and they need to match the shares obtained earlier.
///
/// # Errors
/// Returns an error if any peer request fails or returns an invalid response.
pub async fn finish_sessions(
    client: &reqwest::Client,
    sessions: OprfSessions,
    req: ChallengeRequest,
) -> Result<Vec<ChallengeResponse>> {
    futures::future::try_join_all(
        sessions
            .services
            .iter()
            .map(|service| oprf_challenge(client.clone(), service.to_owned(), req.clone())),
    )
    .await
}

/// Initializes new OPRF sessions by calling `/api/v1/init`
/// on a list of peers, collecting responses until the
/// given `threshold` is met.
///
/// Peers are queried concurrently. Errors from some services
/// are logged and ignored, unless they prevent reaching the threshold.
///
/// # Errors
/// Returns an error if not enough valid responses are received to meet the threshold.
pub async fn init_sessions(
    client: &reqwest::Client,
    oprf_services: &[String],
    threshold: usize,
    req: OprfRequest<OprfRequestAuthV1>,
) -> Result<OprfSessions> {
    let mut requests = oprf_services
        .iter()
        .map(|service| oprf_request(client.clone(), service.to_owned(), req.clone()))
        .collect::<JoinSet<_>>();

    let mut sessions = OprfSessions::with_capacity(threshold);
    while let Some(response) = requests.join_next().await {
        match response.context("can't join responses")? {
            Ok((service, response)) => {
                sessions.push(service, response);
                if sessions.len() == threshold {
                    break;
                }
            }
            Err(err) => {
                eprintln!("Got error response: {err:?}");
            }
        }
    }

    if sessions.len() == threshold {
        Ok(sessions)
    } else {
        Err(ProofError::NotEnoughOprfResponses {
            n: sessions.len(),
            threshold,
        })
    }
}
