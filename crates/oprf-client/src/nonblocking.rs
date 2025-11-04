//! Tokio/reqwest backend for the sans-I/O OPRF client.
//!
//! It wires up the I/O-free core with HTTP calls against OPRF peers.
//!
//! Key pieces:
//! - [`init_sessions`] — kicks off OPRF sessions by POSTing to `/api/v1/init`
//!   until the configured threshold of valid responses is reached.
//! - [`finish_sessions`] — completes all stored sessions in parallel by POSTing
//!   to `/api/v1/finish`.
//!
//! Errors from individual peers are tolerated during init, as long as the
//! threshold can still be met. If too many services fail, the client bails
//! out with [`Error::NotEnoughOprfResponses`].
//!
//! Under the hood, requests use `reqwest::Client` and responses are deserialized
//! into the types defined in [`oprf_types::api::v1`].

use eyre::Context;
use oprf_types::api::v1::{ChallengeRequest, ChallengeResponse, OprfRequest, OprfResponse};
use oprf_world_types::api::v1::OprfRequestAuth;
use tokio::task::JoinSet;

use crate::{Error, OprfSessions};

/// Sends an `init` request to one OPRF peer.
///
/// Returns the peer's URL alongside the parsed [`OprfResponse`].
async fn oprf_request(
    client: reqwest::Client,
    service: String,
    req: OprfRequest<OprfRequestAuth>,
) -> super::Result<(String, OprfResponse)> {
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
        Err(Error::ApiError { status, message })
    }
}

/// Sends a `challenge` request to one OPRF service.
///
/// Returns the parsed [`ChallengeResponse`].
async fn oprf_challenge(
    client: reqwest::Client,
    service: String,
    req: ChallengeRequest,
) -> super::Result<ChallengeResponse> {
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
        Err(Error::ApiError { status, message })
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
/// Fails fast if any single request errors out.
pub async fn finish_sessions(
    client: &reqwest::Client,
    sessions: OprfSessions,
    req: ChallengeRequest,
) -> super::Result<Vec<ChallengeResponse>> {
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
/// Returns an [`OprfSessions`] ready to be finalized with [`finish_sessions`].
pub async fn init_sessions(
    client: &reqwest::Client,
    oprf_services: &[String],
    threshold: usize,
    req: OprfRequest<OprfRequestAuth>,
) -> super::Result<OprfSessions> {
    let mut requests = oprf_services
        .iter()
        .map(|service| oprf_request(client.clone(), service.to_owned(), req.to_owned()))
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
        Err(super::Error::NotEnoughOprfResponses {
            n: sessions.len(),
            threshold,
        })
    }
}
