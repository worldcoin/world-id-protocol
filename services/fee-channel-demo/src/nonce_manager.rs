//! The public nonce service from YABS §Nonce Management, option 2.
//!
//! The service hands out the next counter for a channel lane and stores the latest signed
//! request per lane. Two mechanisms matter:
//!
//! - `previous`: every lease returns the last request recorded on that lane. The RP verifies
//!   that signature, which is the spec's protection against a service inventing an arbitrarily
//!   high nonce. It does not prove the returned nonce is the latest.
//! - The lease: a lane is handed to one caller at a time and stays held until that caller
//!   records or releases it. The spec leaves concurrent allocation of the same nonce as "an
//!   open requirement"; the lease is this demo's answer to it.
//!
//! POC: leases never time out, so a client that dies holding one strands its lane.

// Every handler holds the state lock for its whole body on purpose: leasing, recording, and
// releasing must each be one atomic step against the lane table.
#![expect(
    clippy::significant_drop_tightening,
    reason = "handlers hold the lane table lock for their whole body by design"
)]

use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use alloy::primitives::B256;
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use eyre::Result;
use serde::{Deserialize, Serialize};
use tokio::{net::TcpListener, sync::Mutex, task::JoinHandle};
use world_id_fee_escrow::{ProofRequestV2, nonce::LaneNonce};

/// Per-lane allocator state.
#[derive(Debug, Default, Clone)]
pub struct LaneState {
    /// Highest counter recorded on this lane. Zero means nothing recorded yet.
    pub counter: u64,
    /// The request signed for `counter`, returned as `previous` on the next lease.
    pub latest: Option<ProofRequestV2>,
    /// Whether a caller currently holds this lane.
    pub leased: bool,
}

/// All lanes of one channel.
#[derive(Debug, Clone)]
pub struct ChannelLanes {
    /// `ChannelSettings.laneCount`.
    pub lane_count: u32,
    /// One entry per lane, indexed by lane id.
    pub lanes: Vec<LaneState>,
}

/// Shared service state.
pub type SharedState = Arc<Mutex<HashMap<B256, ChannelLanes>>>;

/// Creates empty service state.
#[must_use]
pub fn state() -> SharedState {
    Arc::new(Mutex::new(HashMap::new()))
}

/// Request body for channel registration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RegisterChannel {
    /// Channel to track.
    pub channel_id: B256,
    /// Number of lanes the channel was opened with.
    pub lane_count: u32,
}

/// Response to a lease request.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LeaseResponse {
    /// Lane the caller may use.
    pub lane: u32,
    /// Counter the caller must sign.
    pub counter: u64,
    /// The request recorded for `counter - 1`, for the caller to verify.
    pub previous: Option<ProofRequestV2>,
}

/// One lane in a status response.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LaneStatus {
    /// Lane id.
    pub lane: u32,
    /// Highest counter recorded.
    pub counter: u64,
    /// Whether the lane is currently leased.
    pub leased: bool,
    /// Hex `uint96` of the latest recorded nonce, if any.
    pub latest_nonce: Option<String>,
}

/// Channel status for assertions.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ChannelStatus {
    /// Number of lanes.
    pub lane_count: u32,
    /// One entry per lane, lane-ordered.
    pub lanes: Vec<LaneStatus>,
}

/// Error body returned with every non-2xx status.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Reason {
    /// Human-readable cause.
    pub reason: String,
}

fn fail(status: StatusCode, reason: impl Into<String>) -> Response {
    (
        status,
        Json(Reason {
            reason: reason.into(),
        }),
    )
        .into_response()
}

/// Routes for the nonce service.
pub fn router(state: SharedState) -> Router {
    Router::new()
        .route("/channels", post(register_channel))
        .route("/channels/{channel_id}", get(channel_status))
        .route("/channels/{channel_id}/next", post(lease_next))
        .route(
            "/channels/{channel_id}/lanes/{lane}",
            axum::routing::put(record),
        )
        .route(
            "/channels/{channel_id}/lanes/{lane}/lease",
            axum::routing::delete(release),
        )
        .with_state(state)
}

/// Serves `router` on `listener` until the returned handle is aborted.
pub fn serve(listener: TcpListener, state: SharedState) -> JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, router(state)).await {
            tracing::error!(error = %e, "nonce manager stopped");
        }
    })
}

/// Binds an ephemeral loopback port.
///
/// # Errors
/// Returns an error if the port cannot be bound.
pub async fn bind_ephemeral() -> Result<(SocketAddr, TcpListener)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    Ok((addr, listener))
}

async fn register_channel(
    State(state): State<SharedState>,
    Json(body): Json<RegisterChannel>,
) -> Response {
    if body.lane_count == 0 {
        return fail(StatusCode::BAD_REQUEST, "lane_count must be positive");
    }
    let mut channels = state.lock().await;
    match channels.get(&body.channel_id) {
        Some(existing) if existing.lane_count == body.lane_count => {
            StatusCode::CREATED.into_response()
        }
        Some(existing) => fail(
            StatusCode::CONFLICT,
            format!(
                "channel already registered with lane_count {}",
                existing.lane_count
            ),
        ),
        None => {
            channels.insert(
                body.channel_id,
                ChannelLanes {
                    lane_count: body.lane_count,
                    lanes: vec![LaneState::default(); body.lane_count as usize],
                },
            );
            StatusCode::CREATED.into_response()
        }
    }
}

async fn lease_next(State(state): State<SharedState>, Path(channel_id): Path<B256>) -> Response {
    let mut channels = state.lock().await;
    let Some(channel) = channels.get_mut(&channel_id) else {
        return fail(StatusCode::NOT_FOUND, "unknown channel");
    };

    // Lowest counter first so lanes stay balanced; ties go to the lowest lane id.
    let choice = channel
        .lanes
        .iter()
        .enumerate()
        .filter(|(_, lane)| !lane.leased)
        .min_by_key(|(id, lane)| (lane.counter, *id))
        .map(|(id, _)| id);

    let Some(index) = choice else {
        return fail(StatusCode::CONFLICT, "all lanes leased");
    };
    let Some(lane) = channel.lanes.get_mut(index) else {
        return fail(StatusCode::INTERNAL_SERVER_ERROR, "lane vanished");
    };
    lane.leased = true;

    let Ok(lane_id) = u32::try_from(index) else {
        return fail(StatusCode::INTERNAL_SERVER_ERROR, "lane id overflow");
    };
    Json(LeaseResponse {
        lane: lane_id,
        counter: lane.counter + 1,
        previous: lane.latest.clone(),
    })
    .into_response()
}

async fn record(
    State(state): State<SharedState>,
    Path((channel_id, lane_id)): Path<(B256, u32)>,
    Json(request): Json<ProofRequestV2>,
) -> Response {
    let mut channels = state.lock().await;
    let Some(channel) = channels.get_mut(&channel_id) else {
        return fail(StatusCode::NOT_FOUND, "unknown channel");
    };
    let Some(lane) = channel.lanes.get_mut(lane_id as usize) else {
        return fail(StatusCode::NOT_FOUND, "unknown lane");
    };
    if !lane.leased {
        return fail(StatusCode::CONFLICT, "lane is not leased");
    }
    let expected = LaneNonce::new(lane_id, lane.counter + 1);
    if request.channel_id != Some(channel_id) {
        return fail(StatusCode::CONFLICT, "request is for a different channel");
    }
    if request.channel_nonce != Some(expected) {
        return fail(
            StatusCode::CONFLICT,
            format!("request must carry nonce {}", expected.to_hex()),
        );
    }

    lane.counter += 1;
    lane.latest = Some(request);
    lane.leased = false;
    StatusCode::NO_CONTENT.into_response()
}

async fn release(
    State(state): State<SharedState>,
    Path((channel_id, lane_id)): Path<(B256, u32)>,
) -> Response {
    let mut channels = state.lock().await;
    let Some(channel) = channels.get_mut(&channel_id) else {
        return fail(StatusCode::NOT_FOUND, "unknown channel");
    };
    let Some(lane) = channel.lanes.get_mut(lane_id as usize) else {
        return fail(StatusCode::NOT_FOUND, "unknown lane");
    };
    lane.leased = false;
    StatusCode::NO_CONTENT.into_response()
}

async fn channel_status(
    State(state): State<SharedState>,
    Path(channel_id): Path<B256>,
) -> Response {
    let channels = state.lock().await;
    let Some(channel) = channels.get(&channel_id) else {
        return fail(StatusCode::NOT_FOUND, "unknown channel");
    };
    let lanes = channel
        .lanes
        .iter()
        .enumerate()
        .map(|(id, lane)| LaneStatus {
            lane: u32::try_from(id).unwrap_or(u32::MAX),
            counter: lane.counter,
            leased: lane.leased,
            latest_nonce: lane
                .latest
                .as_ref()
                .and_then(|r| r.channel_nonce)
                .map(LaneNonce::to_hex),
        })
        .collect();
    Json(ChannelStatus {
        lane_count: channel.lane_count,
        lanes,
    })
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::{primitives::b256, signers::local::PrivateKeySigner};
    use world_id_fee_escrow::typed_data;
    use world_id_primitives::{
        FieldElement, OprfKeyId, SessionRef,
        request::{ProofRequest, ProofType, RequestItem, RequestVersion},
        rp::RpId,
    };

    const CHANNEL: B256 =
        b256!("0x00000000000000000000000000000000000000000000000000000000000000aa");

    fn signed(signer: &PrivateKeySigner, nonce: LaneNonce) -> ProofRequestV2 {
        let inner = ProofRequest {
            id: "req_test".to_string(),
            version: RequestVersion::V2,
            proof_type: ProofType::Uniqueness,
            created_at: 1_700_000_000,
            expires_at: 1_700_000_300,
            rp_id: RpId::new(7),
            oprf_key_id: OprfKeyId::new(alloy::primitives::Uint::<160, 3>::from(1u64)),
            session_id: SessionRef::None,
            action: Some(FieldElement::from(42u64)),
            signature: alloy::signers::Signature::new(
                alloy::primitives::U256::ONE,
                alloy::primitives::U256::ONE,
                false,
            ),
            nonce: FieldElement::from(u64::from(nonce.lane) * 1000 + nonce.counter),
            requests: vec![RequestItem::new("face".to_string(), 1, None, None, None)],
            constraints: None,
        };
        let domain = typed_data::domain(
            31_337,
            alloy::primitives::address!("0x6666666666666666666666666666666666666666"),
        );
        ProofRequestV2::sign(inner, CHANNEL, nonce, signer, &domain).expect("signs")
    }

    async fn registered(lane_count: u32) -> SharedState {
        let state = state();
        let response = register_channel(
            State(state.clone()),
            Json(RegisterChannel {
                channel_id: CHANNEL,
                lane_count,
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        state
    }

    #[tokio::test]
    async fn registration_is_idempotent_but_rejects_a_different_lane_count() {
        let state = registered(2).await;

        let same = register_channel(
            State(state.clone()),
            Json(RegisterChannel {
                channel_id: CHANNEL,
                lane_count: 2,
            }),
        )
        .await;
        assert_eq!(same.status(), StatusCode::CREATED);

        let different = register_channel(
            State(state),
            Json(RegisterChannel {
                channel_id: CHANNEL,
                lane_count: 3,
            }),
        )
        .await;
        assert_eq!(different.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn leases_are_exclusive_until_recorded() {
        let state = registered(2).await;

        let first = lease_next(State(state.clone()), Path(CHANNEL)).await;
        assert_eq!(first.status(), StatusCode::OK);
        let second = lease_next(State(state.clone()), Path(CHANNEL)).await;
        assert_eq!(second.status(), StatusCode::OK);

        let third = lease_next(State(state.clone()), Path(CHANNEL)).await;
        assert_eq!(
            third.status(),
            StatusCode::CONFLICT,
            "both lanes are held, so there is nothing to hand out"
        );

        let signer = PrivateKeySigner::random();
        let recorded = record(
            State(state.clone()),
            Path((CHANNEL, 0)),
            Json(signed(&signer, LaneNonce::new(0, 1))),
        )
        .await;
        assert_eq!(recorded.status(), StatusCode::NO_CONTENT);

        let fourth = lease_next(State(state), Path(CHANNEL)).await;
        assert_eq!(
            fourth.status(),
            StatusCode::OK,
            "recording frees the lane again"
        );
    }

    #[tokio::test]
    async fn record_rejects_a_nonce_the_lane_did_not_issue() {
        let state = registered(1).await;
        let signer = PrivateKeySigner::random();
        assert_eq!(
            lease_next(State(state.clone()), Path(CHANNEL))
                .await
                .status(),
            StatusCode::OK
        );

        let skipped = record(
            State(state.clone()),
            Path((CHANNEL, 0)),
            Json(signed(&signer, LaneNonce::new(0, 7))),
        )
        .await;
        assert_eq!(skipped.status(), StatusCode::CONFLICT);

        let wrong_lane = record(
            State(state.clone()),
            Path((CHANNEL, 0)),
            Json(signed(&signer, LaneNonce::new(1, 1))),
        )
        .await;
        assert_eq!(wrong_lane.status(), StatusCode::CONFLICT);

        let unleased = record(
            State(state),
            Path((CHANNEL, 0)),
            Json(signed(&signer, LaneNonce::new(0, 1))),
        )
        .await;
        assert_eq!(
            unleased.status(),
            StatusCode::NO_CONTENT,
            "the correct nonce on a leased lane is accepted"
        );
    }

    #[tokio::test]
    async fn releasing_a_lease_keeps_the_counter() {
        let state = registered(1).await;
        assert_eq!(
            lease_next(State(state.clone()), Path(CHANNEL))
                .await
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            release(State(state.clone()), Path((CHANNEL, 0)))
                .await
                .status(),
            StatusCode::NO_CONTENT
        );

        let again = lease_next(State(state.clone()), Path(CHANNEL)).await;
        assert_eq!(again.status(), StatusCode::OK);

        let channels = state.lock().await;
        let lane = &channels[&CHANNEL].lanes[0];
        assert_eq!(lane.counter, 0, "a released lease records nothing");
        assert!(lane.leased);
    }

    #[tokio::test]
    async fn unknown_channel_is_not_found() {
        let state = state();
        assert_eq!(
            lease_next(State(state.clone()), Path(CHANNEL))
                .await
                .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            channel_status(State(state), Path(CHANNEL)).await.status(),
            StatusCode::NOT_FOUND
        );
    }
}
