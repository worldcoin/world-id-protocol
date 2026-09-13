//! The flamingo verifier host's wire types, and the transport that speaks them.
//!
//! Mirrored here rather than depended on: this repository does not build the flamingo
//! workspace, so the types are copied and pinned by the harness that exercises them. A rename
//! on either side shows up as a deserialisation failure in the local end-to-end run.

use alloy::primitives::{B256, FixedBytes, Signature};
use eyre::{Result, bail};
use reqwest::{StatusCode, Url};
use serde::{Deserialize, Serialize};
use world_id_fee_escrow::{IssuedNonce, LaneNonce, Payment};

use crate::rp::{Admitted, Refused};

/// Stand-in for a sealed match request. The mock enclave hashes whatever it is given.
const DUMMY_CIPHERTEXT: &str = "c2VhbGVk";

/// `POST /v1/channels/{channel_id}/nonces` request.
#[derive(Debug, Serialize)]
struct ReserveBody {
    epoch: u64,
    request_id: B256,
}

/// An authorisation without the channel and epoch the enclosing response already names.
#[derive(Debug, Deserialize)]
struct AuthorizationBody {
    channel_nonce: LaneNonce,
    signature: FixedBytes<65>,
}

/// `POST /v1/channels/{channel_id}/nonces` response.
#[derive(Debug, Deserialize)]
struct ReserveResponse {
    lane: u32,
    counter: u64,
    expires_by: u64,
    previous: Option<AuthorizationBody>,
}

/// `POST /v1/matches` request.
#[derive(Debug, Serialize)]
struct MatchBody<'a> {
    ciphertext: &'a str,
    payment: &'a Payment,
}

/// `POST /v1/matches` response.
#[derive(Debug, Deserialize)]
struct MatchResponse {
    response_ciphertext: String,
}

/// The host's error envelope. `allowRetry` is its one camelCase key.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApiError {
    allow_retry: bool,
    error: ErrorBody,
}

#[derive(Debug, Deserialize)]
struct ErrorBody {
    code: String,
    message: String,
    #[serde(default)]
    details: Option<ErrorDetails>,
}

/// What a capacity refusal proves about itself.
#[derive(Debug, Deserialize)]
struct ErrorDetails {
    admitted_units: u64,
    capacity: u64,
    authorizations: Vec<LaneAuthorization>,
}

#[derive(Debug, Deserialize)]
struct LaneAuthorization {
    channel_nonce: LaneNonce,
    signature: FixedBytes<65>,
}

/// Rebuilds a payment from the channel and epoch the response did not repeat.
fn payment_from(
    channel_id: B256,
    epoch: u64,
    channel_nonce: LaneNonce,
    signature: FixedBytes<65>,
) -> Result<Payment> {
    Ok(Payment {
        channel_id,
        epoch,
        channel_nonce: channel_nonce.pack(),
        signature: Signature::from_raw_array(&signature.0)?,
    })
}

impl ApiError {
    /// Converts the envelope into the RP's transport-independent refusal.
    fn into_refused(self, channel_id: B256, epoch: u64) -> Result<Refused> {
        let mut refused = Refused {
            code: self.error.code,
            message: self.error.message,
            allow_retry: self.allow_retry,
            proof: Vec::new(),
            admitted_units: None,
            capacity: None,
        };
        if let Some(details) = self.error.details {
            refused.admitted_units = Some(details.admitted_units);
            refused.capacity = Some(details.capacity);
            for lane in details.authorizations {
                refused.proof.push(payment_from(
                    channel_id,
                    epoch,
                    lane.channel_nonce,
                    lane.signature,
                )?);
            }
        }
        Ok(refused)
    }
}

/// Speaks the flamingo verifier host's API.
///
/// `base` is the versioned API root, `http://127.0.0.1:8000/v1`. The host has no early-return
/// route, so a payment is spent by presenting it for a match and in no other way.
#[derive(Debug, Clone)]
pub struct FlamingoTransport {
    http: reqwest::Client,
    base: Url,
}

impl FlamingoTransport {
    /// Creates a transport against the host's versioned API root.
    ///
    /// # Errors
    /// Returns an error if `base` cannot be used as a path prefix.
    pub fn new(base: Url) -> Result<Self> {
        // A base without a trailing slash makes `join` drop its last segment.
        let base = if base.as_str().ends_with('/') {
            base
        } else {
            format!("{base}/").parse()?
        };
        Ok(Self {
            http: reqwest::Client::new(),
            base,
        })
    }

    /// Reserves the next counter, or returns the host's refusal.
    ///
    /// # Errors
    /// Returns an error on transport failure or an unrecognised response.
    pub async fn reserve(
        &self,
        channel_id: B256,
        epoch: u64,
        request_id: B256,
    ) -> Result<std::result::Result<IssuedNonce, Refused>> {
        let url = self.base.join(&format!("channels/{channel_id}/nonces"))?;
        let response = self
            .http
            .post(url)
            .json(&ReserveBody { epoch, request_id })
            .send()
            .await?;

        if response.status() == StatusCode::OK {
            let body: ReserveResponse = response.json().await?;
            let previous = body
                .previous
                .map(|previous| {
                    payment_from(
                        channel_id,
                        epoch,
                        previous.channel_nonce,
                        previous.signature,
                    )
                })
                .transpose()?;
            return Ok(Ok(IssuedNonce {
                lane: body.lane,
                counter: body.counter,
                expires_by: body.expires_by,
                previous,
            }));
        }
        self.refusal(response, channel_id, epoch).await.map(Err)
    }

    /// Presents a payment for one match.
    ///
    /// # Errors
    /// Returns an error on transport failure or an unrecognised response.
    pub async fn present(
        &self,
        payment: &Payment,
    ) -> Result<std::result::Result<Admitted, Refused>> {
        let url = self.base.join("matches")?;
        let response = self
            .http
            .post(url)
            .json(&MatchBody {
                ciphertext: DUMMY_CIPHERTEXT,
                payment,
            })
            .send()
            .await?;

        if response.status() == StatusCode::OK {
            let body: MatchResponse = response.json().await?;
            let nonce = payment.lane_nonce()?;
            return Ok(Ok(Admitted {
                receipt: body.response_ciphertext,
                epoch: payment.epoch,
                lane: nonce.lane,
                counter: nonce.counter,
            }));
        }
        self.refusal(response, payment.channel_id, payment.epoch)
            .await
            .map(Err)
    }

    /// Reads the host's error envelope off a non-success response.
    async fn refusal(
        &self,
        response: reqwest::Response,
        channel_id: B256,
        epoch: u64,
    ) -> Result<Refused> {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        match serde_json::from_str::<ApiError>(&body) {
            Ok(envelope) => envelope.into_refused(channel_id, epoch),
            Err(_) => bail!("the host returned {status} outside its error envelope: {body}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins the shapes this crate copied from `flamingo-verifier-api-types`. A rename there
    /// breaks this test rather than the harness at run time.
    #[test]
    fn the_error_envelope_matches_the_hosts_wire_form() {
        let json = serde_json::json!({
            "allowRetry": false,
            "error": {
                "code": "capacity_exhausted",
                "message": "The channel has spent its capacity for this epoch",
                "details": {
                    "epoch": 7,
                    "admitted_units": 2,
                    "capacity": 2,
                    "authorizations": [
                        { "lane": 0, "channel_nonce": "0x1", "signature": format!("0x{}", "33".repeat(65)) },
                    ],
                },
            },
        });

        let envelope: ApiError = serde_json::from_value(json).expect("deserialises");
        assert_eq!(envelope.error.code, "capacity_exhausted");
        let details = envelope.error.details.as_ref().expect("carries a proof");
        assert_eq!((details.admitted_units, details.capacity), (2, 2));
        assert_eq!(
            details.authorizations[0].channel_nonce,
            LaneNonce::new(0, 1)
        );
    }

    #[test]
    fn a_reservation_response_matches_the_hosts_wire_form() {
        let json = serde_json::json!({
            "lane": 2,
            "counter": 5,
            "expires_by": 1_700_000_600u64,
            "previous": {
                "channel_nonce": "0x20000000000000004",
                "signature": format!("0x{}", "33".repeat(65)),
            },
        });

        let body: ReserveResponse = serde_json::from_value(json).expect("deserialises");
        assert_eq!((body.lane, body.counter), (2, 5));
        assert_eq!(
            body.previous.expect("carries a predecessor").channel_nonce,
            LaneNonce::new(2, 4)
        );
    }

    #[test]
    fn a_first_reservation_carries_a_null_previous() {
        let json = serde_json::json!({
            "lane": 0,
            "counter": 1,
            "expires_by": 600,
            "previous": serde_json::Value::Null,
        });
        let body: ReserveResponse = serde_json::from_value(json).expect("deserialises");
        assert!(body.previous.is_none());
    }

    /// The crate's own `Payment` must serialise to what the host's `Payment` deserialises.
    #[test]
    fn a_payment_serialises_to_the_hosts_wire_form() {
        use alloy::primitives::{U256, b256};

        let payment = Payment {
            channel_id: b256!("0x1111111111111111111111111111111111111111111111111111111111111111"),
            epoch: 7,
            channel_nonce: LaneNonce::new(3, 42).pack(),
            signature: Signature::new(U256::from(1), U256::from(2), false),
        };
        let json = serde_json::to_value(&payment).expect("serialises");

        assert_eq!(json["channel_id"], format!("0x{}", "11".repeat(32)));
        assert_eq!(json["epoch"], 7);
        assert_eq!(json["channel_nonce"], "0x3000000000000002a");
        assert_eq!(
            json["signature"].as_str().expect("hex").len(),
            132,
            "0x plus 65 bytes, the host's FixedBytes<65>"
        );
    }

    #[test]
    fn the_ciphertext_is_valid_base64() {
        use base64::Engine as _;
        assert!(
            base64::engine::general_purpose::STANDARD
                .decode(DUMMY_CIPHERTEXT)
                .is_ok()
        );
    }
}
