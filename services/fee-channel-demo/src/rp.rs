//! The relying party: stateless, one reservation and one signature per unit of work.
//!
//! The same RP drives either collector. Only [`Transport`] differs: the demo collector in this
//! crate, or the flamingo verifier host, which is the production collector.

use alloy::{primitives::B256, signers::local::PrivateKeySigner, sol_types::Eip712Domain};
use eyre::{Result, bail, eyre};
use rand::Rng as _;
use reqwest::{StatusCode, Url};
use serde::{Deserialize, Serialize};
use world_id_fee_escrow::{
    IssuedNonce, Payment,
    typed_data::{ChannelSettings, epoch_of},
    verify_predecessor,
};

use crate::{
    collector::{RecordRequest, ReserveRequest},
    flamingo::FlamingoTransport,
};

/// One unit of work the collector agreed to do.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Admitted {
    /// Stand-in for whatever the real service returns.
    pub receipt: String,
    /// Epoch the unit was billed to.
    pub epoch: u64,
    /// Lane the unit consumed.
    pub lane: u32,
    /// Counter the unit consumed.
    pub counter: u64,
}

/// A collector's refusal, in the form both transports reduce to.
#[derive(Debug, Clone, Default)]
pub struct Refused {
    /// Stable refusal class, for example `capacity_exhausted`.
    pub code: String,
    /// Human-readable detail.
    pub message: String,
    /// Whether the collector invited a retry.
    pub allow_retry: bool,
    /// The highest payment per lane, when the refusal carried a proof.
    pub proof: Vec<Payment>,
    /// Units the collector says it has served this epoch, when it said so.
    pub admitted_units: Option<u64>,
    /// Units the epoch was funded for, when the collector said so.
    pub capacity: Option<u64>,
}

/// What happened to one request for work.
#[derive(Debug, Clone)]
pub enum Outcome {
    /// The collector booked the unit and did the work.
    Admitted(Admitted),
    /// The collector refused, with its stated class and any proof.
    Refused(Refused),
}

impl Outcome {
    /// The refusal class, or `None` when the unit was admitted.
    #[must_use]
    pub fn refusal_class(&self) -> Option<&str> {
        match self {
            Self::Admitted(_) => None,
            Self::Refused(refused) => Some(&refused.code),
        }
    }
}

/// Where the RP sends its reservations and payments.
#[derive(Debug, Clone)]
pub enum Transport {
    /// The in-process collector in this crate.
    Demo(DemoTransport),
    /// The flamingo verifier host.
    Flamingo(FlamingoTransport),
}

impl Transport {
    /// Speaks to this crate's demo collector at `base`.
    #[must_use]
    pub fn demo(base: Url) -> Self {
        Self::Demo(DemoTransport {
            http: reqwest::Client::new(),
            base,
        })
    }

    /// Speaks to the flamingo verifier host at its versioned API root.
    ///
    /// # Errors
    /// Returns an error if `base` cannot be used as a path prefix.
    pub fn flamingo(base: Url) -> Result<Self> {
        Ok(Self::Flamingo(FlamingoTransport::new(base)?))
    }

    async fn reserve(
        &self,
        channel_id: B256,
        epoch: u64,
        request_id: B256,
    ) -> Result<std::result::Result<IssuedNonce, Refused>> {
        match self {
            Self::Demo(demo) => demo.reserve(channel_id, epoch, request_id).await,
            Self::Flamingo(host) => host.reserve(channel_id, epoch, request_id).await,
        }
    }

    async fn present(&self, payment: &Payment) -> Result<std::result::Result<Admitted, Refused>> {
        match self {
            Self::Demo(demo) => demo.present(payment).await,
            Self::Flamingo(host) => host.present(payment).await,
        }
    }

    /// Hands the signature back before the payment is presented, where the collector takes one.
    async fn return_early(&self, payment: &Payment, request_id: B256) -> Result<()> {
        match self {
            Self::Demo(demo) => demo.return_early(payment, request_id).await,
            Self::Flamingo(_) => bail!(
                "the flamingo host has no early-return route: a payment is spent by presenting \
                 it for a match and in no other way"
            ),
        }
    }
}

/// Speaks this crate's demo collector API.
#[derive(Debug, Clone)]
pub struct DemoTransport {
    http: reqwest::Client,
    base: Url,
}

/// The demo collector's refusal envelope.
#[derive(Debug, Deserialize)]
struct DemoRefusal {
    error: String,
    message: String,
    #[serde(default)]
    refusal_proof: Option<Vec<Payment>>,
}

impl From<DemoRefusal> for Refused {
    fn from(refusal: DemoRefusal) -> Self {
        Self {
            code: refusal.error,
            message: refusal.message,
            allow_retry: false,
            proof: refusal.refusal_proof.unwrap_or_default(),
            admitted_units: None,
            capacity: None,
        }
    }
}

impl DemoTransport {
    async fn reserve(
        &self,
        channel_id: B256,
        epoch: u64,
        request_id: B256,
    ) -> Result<std::result::Result<IssuedNonce, Refused>> {
        let url = self.base.join(&format!("/channels/{channel_id}/nonces"))?;
        let response = self
            .http
            .post(url)
            .json(&ReserveRequest {
                epoch,
                request_id: request_id.to_string(),
            })
            .send()
            .await?;

        match response.status() {
            StatusCode::OK => Ok(Ok(response.json().await?)),
            StatusCode::PAYMENT_REQUIRED | StatusCode::SERVICE_UNAVAILABLE => {
                Ok(Err(response.json::<DemoRefusal>().await?.into()))
            }
            status => bail!(
                "the collector refused a reservation: {status} {}",
                response.text().await.unwrap_or_default()
            ),
        }
    }

    async fn present(&self, payment: &Payment) -> Result<std::result::Result<Admitted, Refused>> {
        let response = self
            .http
            .post(self.base.join("/admit")?)
            .json(payment)
            .send()
            .await?;
        match response.status() {
            StatusCode::OK => Ok(Ok(response.json().await?)),
            StatusCode::PAYMENT_REQUIRED
            | StatusCode::CONFLICT
            | StatusCode::SERVICE_UNAVAILABLE
            | StatusCode::NOT_FOUND => Ok(Err(response.json::<DemoRefusal>().await?.into())),
            status => bail!(
                "the collector returned {status}: {}",
                response.text().await.unwrap_or_default()
            ),
        }
    }

    async fn return_early(&self, payment: &Payment, request_id: B256) -> Result<()> {
        let nonce = payment.lane_nonce()?;
        let url = self.base.join(&format!(
            "/channels/{}/nonces/{}/{}",
            payment.channel_id, nonce.lane, nonce.counter
        ))?;

        let response = self
            .http
            .put(url)
            .json(&RecordRequest {
                request_id: request_id.to_string(),
                payment: payment.clone(),
            })
            .send()
            .await?;
        if !response.status().is_success() {
            bail!(
                "the collector refused the early payment: {} {}",
                response.status(),
                response.text().await.unwrap_or_default()
            );
        }
        Ok(())
    }
}

/// An RP that pays for its work out of one channel.
///
/// It holds no nonce state between requests: every proposal the collector makes carries the
/// RP's own previous signature, which is all it needs to check the proposal.
#[derive(Debug, Clone)]
pub struct RpService {
    transport: Transport,
    signer: PrivateKeySigner,
    domain: Eip712Domain,
    settings: ChannelSettings,
    channel_id: B256,
    /// Whether to return the signature before the payment is presented.
    pub early_return: bool,
}

impl RpService {
    /// Creates an RP bound to one channel.
    #[must_use]
    pub fn new(
        transport: Transport,
        signer: PrivateKeySigner,
        domain: Eip712Domain,
        settings: ChannelSettings,
    ) -> Self {
        let channel_id = settings.channel_id(&domain);
        Self {
            transport,
            signer,
            domain,
            settings,
            channel_id,
            early_return: false,
        }
    }

    /// The channel this RP pays from.
    #[must_use]
    pub const fn channel_id(&self) -> B256 {
        self.channel_id
    }

    /// The epoch the RP's clock falls in.
    ///
    /// # Errors
    /// Returns an error if now is outside the channel's schedule.
    pub fn current_epoch(&self) -> Result<u64> {
        let now = crate::unix_now();
        epoch_of(now, &self.settings)
            .ok_or_else(|| eyre!("{now} is outside the channel's schedule"))
    }

    /// Runs one unit: reserve, check the predecessor, sign, then present the payment.
    ///
    /// # Errors
    /// Returns an error on transport failure or if the collector's proposal does not carry the
    /// RP's own signature on the counter below the one it offered.
    pub async fn one_request(&self) -> Result<Outcome> {
        let epoch = self.current_epoch()?;
        let request_id = B256::from(rand::thread_rng().r#gen::<[u8; 32]>());

        let issued = match self
            .transport
            .reserve(self.channel_id, epoch, request_id)
            .await?
        {
            Ok(issued) => issued,
            Err(refused) => return Ok(Outcome::Refused(refused)),
        };

        // The only check the RP makes, and the only reason it can be stateless.
        verify_predecessor(
            issued.previous.as_ref(),
            self.channel_id,
            epoch,
            issued.lane_nonce(),
            self.signer.address(),
            &self.domain,
        )?;

        let payment = Payment::sign(
            self.channel_id,
            epoch,
            issued.lane_nonce(),
            &self.signer,
            &self.domain,
        )?;

        // A payment is consumed by its first admission, so the early return and presenting it
        // for work are alternatives, not a sequence. Returning early books the unit at once and
        // frees the lane; the work is then owed out of band.
        if self.early_return {
            self.transport.return_early(&payment, request_id).await?;
            return Ok(Outcome::Admitted(Admitted {
                receipt: format!("early-{}-{}", issued.lane, issued.counter),
                epoch,
                lane: issued.lane,
                counter: issued.counter,
            }));
        }

        Ok(match self.transport.present(&payment).await? {
            Ok(admitted) => Outcome::Admitted(admitted),
            Err(refused) => Outcome::Refused(refused),
        })
    }

    /// Checks a capacity refusal and returns the units it proves.
    ///
    /// The proof is the highest payment per lane. Each one is the RP's own signature over a
    /// cumulative counter, so verifying the signatures and summing the counters gives the
    /// epoch's usage at a cost proportional to lanes, not to capacity.
    ///
    /// # Errors
    /// Returns an error if the refusal carries no proof or a payment does not recover to this
    /// RP's spend key.
    pub fn verify_refusal(&self, epoch: u64, refused: &Refused) -> Result<u64> {
        if refused.proof.is_empty() {
            bail!("refusal {:?} carries no proof", refused.code);
        }
        let mut units = 0u64;
        for payment in &refused.proof {
            let nonce =
                payment.verify(self.channel_id, epoch, self.signer.address(), &self.domain)?;
            units = units.saturating_add(nonce.counter);
        }
        Ok(units)
    }
}
