//! The relying party: leases a nonce, signs a request, sends it for work.

use std::collections::BTreeMap;

use alloy::{
    primitives::B256,
    signers::{Signature, local::PrivateKeySigner},
    sol_types::Eip712Domain,
};
use eyre::{Result, bail, eyre};
use rand::Rng as _;
use reqwest::{StatusCode, Url};
use tokio::task::JoinSet;
use world_id_fee_escrow::{ProofRequestV2, nonce::LaneNonce};
use world_id_primitives::{
    FieldElement, OprfKeyId, SessionRef,
    request::{ProofRequest, ProofType, RequestItem, RequestVersion},
    rp::RpId,
};

use crate::{
    collector::{WorkAccepted, WorkRejected},
    nonce_manager::LeaseResponse,
};

/// How long a signed request stays valid.
const REQUEST_TTL_SECS: u64 = 300;
/// Attempts to acquire a lane before giving up.
const LEASE_ATTEMPTS: usize = 40;

/// What happened to one request.
#[derive(Debug, Clone)]
pub enum Outcome {
    /// The collector accepted the request and did the work.
    Admitted {
        /// Lane the nonce came from.
        lane: u32,
        /// Counter the request carried.
        counter: u64,
    },
    /// The collector refused to do the work.
    Rejected {
        /// Lane the nonce came from.
        lane: u32,
        /// Counter the request carried.
        counter: u64,
        /// The collector's stated reason.
        reason: String,
    },
}

/// What the RP saw across a whole run.
#[derive(Debug, Clone, Default)]
pub struct RpReport {
    /// Requests the collector admitted.
    pub admitted: usize,
    /// Reasons for each refusal, in completion order.
    pub rejected: Vec<String>,
    /// Highest counter signed per lane.
    pub per_lane_signed: BTreeMap<u32, u64>,
}

/// An RP that signs payment-authorising proof requests.
#[derive(Debug, Clone)]
pub struct RpService {
    http: reqwest::Client,
    nonce_manager: Url,
    collector: Url,
    signer: PrivateKeySigner,
    domain: Eip712Domain,
    channel_id: B256,
    rp_id: RpId,
    oprf_key_id: OprfKeyId,
}

impl RpService {
    /// Creates an RP bound to one channel.
    #[must_use]
    pub fn new(
        nonce_manager: Url,
        collector: Url,
        signer: PrivateKeySigner,
        domain: Eip712Domain,
        channel_id: B256,
        rp_id: RpId,
        oprf_key_id: OprfKeyId,
    ) -> Self {
        Self {
            http: reqwest::Client::new(),
            nonce_manager,
            collector,
            signer,
            domain,
            channel_id,
            rp_id,
            oprf_key_id,
        }
    }

    /// Leases the next nonce, retrying while every lane is held.
    ///
    /// # Errors
    /// Returns an error if the service is unreachable or stays fully leased.
    pub async fn next_nonce(&self) -> Result<(LaneNonce, Option<ProofRequestV2>)> {
        let url = self
            .nonce_manager
            .join(&format!("/channels/{}/next", self.channel_id))?;

        for _ in 0..LEASE_ATTEMPTS {
            let response = self.http.post(url.clone()).send().await?;
            if response.status() == StatusCode::CONFLICT {
                let backoff = rand::thread_rng().gen_range(10..50);
                tokio::time::sleep(std::time::Duration::from_millis(backoff)).await;
                continue;
            }
            if !response.status().is_success() {
                bail!(
                    "nonce manager refused a lease: {} {}",
                    response.status(),
                    response.text().await.unwrap_or_default()
                );
            }
            let lease: LeaseResponse = response.json().await?;
            return Ok((LaneNonce::new(lease.lane, lease.counter), lease.previous));
        }
        bail!("every lane stayed leased after {LEASE_ATTEMPTS} attempts")
    }

    /// Checks the service handed back the genuine predecessor of `nonce`.
    ///
    /// This is the spec's protection: the previous request is signed by this RP's own key, so
    /// the service cannot invent an arbitrarily high nonce. It does not prove the returned
    /// nonce is the latest one, which the spec leaves open.
    ///
    /// # Errors
    /// Returns an error if the predecessor is missing, unexpected, or not self-signed.
    pub fn check_previous(
        &self,
        nonce: LaneNonce,
        previous: Option<&ProofRequestV2>,
    ) -> Result<()> {
        if nonce.counter == 1 {
            return match previous {
                None => Ok(()),
                Some(_) => Err(eyre!(
                    "nonce manager equivocation: lane {} counter 1 cannot have a predecessor",
                    nonce.lane
                )),
            };
        }
        let previous = previous.ok_or_else(|| {
            eyre!(
                "nonce manager equivocation: no predecessor for lane {} counter {}",
                nonce.lane,
                nonce.counter
            )
        })?;
        previous
            .verify(&self.domain, self.signer.address())
            .map_err(|e| eyre!("nonce manager equivocation: predecessor not self-signed: {e}"))?;
        let expected = LaneNonce::new(nonce.lane, nonce.counter - 1);
        if previous.channel_nonce != Some(expected) {
            bail!(
                "nonce manager equivocation: predecessor carries {:?}, expected {}",
                previous.channel_nonce,
                expected.to_hex()
            );
        }
        Ok(())
    }

    /// Builds the unsigned inner request. Content is arbitrary; only the digest is paid for.
    fn build_inner(&self) -> Result<ProofRequest> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        Ok(ProofRequest {
            id: format!("req_{}", uuid::Uuid::new_v4()),
            version: RequestVersion::V2,
            proof_type: ProofType::Uniqueness,
            created_at: now,
            expires_at: now + REQUEST_TTL_SECS,
            rp_id: self.rp_id,
            oprf_key_id: self.oprf_key_id,
            session_id: SessionRef::None,
            action: Some(FieldElement::from(42u64)),
            // Overwritten by `ProofRequestV2::sign`.
            signature: Signature::new(
                alloy::primitives::U256::ONE,
                alloy::primitives::U256::ONE,
                false,
            ),
            nonce: FieldElement::from(rand::thread_rng().r#gen::<u64>()),
            requests: vec![RequestItem::new("face".to_string(), 1, None, None, None)],
            constraints: None,
        })
    }

    /// Runs one full request: lease, sign, ask for work, record the nonce.
    ///
    /// The lease is held until the work call returns, then released by recording. Releasing it
    /// earlier would let two requests on the same lane reach the collector out of order, and
    /// the escrow's monotonic counter rule would reject the older one.
    ///
    /// # Errors
    /// Returns an error on transport failure or nonce-manager equivocation.
    pub async fn one_request(&self) -> Result<Outcome> {
        let (nonce, previous) = self.next_nonce().await?;
        if let Err(e) = self.check_previous(nonce, previous.as_ref()) {
            self.release(nonce.lane).await?;
            return Err(e);
        }

        let signed = match ProofRequestV2::sign(
            self.build_inner()?,
            self.channel_id,
            nonce,
            &self.signer,
            &self.domain,
        ) {
            Ok(signed) => signed,
            Err(e) => {
                self.release(nonce.lane).await?;
                return Err(eyre!("signing failed: {e}"));
            }
        };

        let work = match self.send_work(&signed).await {
            Ok(outcome) => outcome,
            Err(e) => {
                self.release(nonce.lane).await?;
                return Err(e);
            }
        };

        // Recorded whatever the collector decided: the nonce was spent either way, so the RP
        // must never reuse it.
        self.record(nonce, &signed).await?;
        Ok(work)
    }

    async fn send_work(&self, signed: &ProofRequestV2) -> Result<Outcome> {
        let Some(nonce) = signed.channel_nonce else {
            bail!("signed request lost its channel nonce");
        };
        let response = self
            .http
            .post(self.collector.join("/work")?)
            .json(signed)
            .send()
            .await?;

        match response.status() {
            StatusCode::OK => {
                let accepted: WorkAccepted = response.json().await?;
                Ok(Outcome::Admitted {
                    lane: accepted.lane,
                    counter: accepted.counter,
                })
            }
            StatusCode::PAYMENT_REQUIRED => {
                let rejected: WorkRejected = response.json().await?;
                Ok(Outcome::Rejected {
                    lane: nonce.lane,
                    counter: nonce.counter,
                    reason: rejected.reason,
                })
            }
            status => bail!(
                "collector returned {status}: {}",
                response.text().await.unwrap_or_default()
            ),
        }
    }

    async fn record(&self, nonce: LaneNonce, signed: &ProofRequestV2) -> Result<()> {
        let url = self.nonce_manager.join(&format!(
            "/channels/{}/lanes/{}",
            self.channel_id, nonce.lane
        ))?;
        let response = self.http.put(url).json(signed).send().await?;
        if !response.status().is_success() {
            bail!(
                "nonce manager refused the record: {} {}",
                response.status(),
                response.text().await.unwrap_or_default()
            );
        }
        Ok(())
    }

    async fn release(&self, lane: u32) -> Result<()> {
        let url = self
            .nonce_manager
            .join(&format!("/channels/{}/lanes/{lane}/lease", self.channel_id))?;
        self.http.delete(url).send().await?;
        Ok(())
    }

    /// Runs `workers` concurrent workers, each issuing `per_worker` requests.
    ///
    /// # Errors
    /// Returns an error if any worker hits a transport failure or equivocation.
    pub async fn run(&self, workers: usize, per_worker: usize) -> Result<RpReport> {
        let mut set = JoinSet::new();
        for worker in 0..workers {
            let rp = self.clone();
            set.spawn(async move {
                let mut outcomes = Vec::with_capacity(per_worker);
                for _ in 0..per_worker {
                    let outcome = rp.one_request().await?;
                    match &outcome {
                        Outcome::Admitted { lane, counter } => {
                            tracing::info!(worker, lane, counter, "request admitted");
                        }
                        Outcome::Rejected {
                            lane,
                            counter,
                            reason,
                        } => tracing::warn!(worker, lane, counter, %reason, "request rejected"),
                    }
                    outcomes.push(outcome);
                }
                Ok::<_, eyre::Report>(outcomes)
            });
        }

        let mut report = RpReport::default();
        while let Some(joined) = set.join_next().await {
            for outcome in joined?? {
                match outcome {
                    Outcome::Admitted { lane, counter } => {
                        report.admitted += 1;
                        bump(&mut report.per_lane_signed, lane, counter);
                    }
                    Outcome::Rejected {
                        lane,
                        counter,
                        reason,
                    } => {
                        report.rejected.push(reason);
                        bump(&mut report.per_lane_signed, lane, counter);
                    }
                }
            }
        }
        Ok(report)
    }
}

fn bump(per_lane: &mut BTreeMap<u32, u64>, lane: u32, counter: u64) {
    let entry = per_lane.entry(lane).or_default();
    *entry = (*entry).max(counter);
}
