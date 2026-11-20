# World ID RP Sidecar

A local HTTP service that verifies [WIP-202](../../docs/WIPs/wip-202.md) Proofs of Embedding Similarity for a Relying Party. It wraps [`world-id-rp`](../../crates/rp) so that services written in Node, Go or other languages can verify proofs without building Rust.

It runs next to the RP's service, as a sidecar container in its Kubernetes pod or ECS task, and listens on loopback only. It has no authentication, so it must not be reachable from outside its pod.

## What the caller must do

The sidecar is stateless. It checks a proof against the request the RP issued, but it does not know which requests the RP issued or which ones were already used. The caller must:

1. Store every `ProofRequest` it issues, keyed by its `id`, until the request's `expires_at`. Each request has its own single-use `nonce`.
2. When a proof arrives, look up the stored request by the response's `id`, and send that stored copy. Never send a request the client sent back.
3. On `200`, consume the stored request atomically, for example with Redis `GETDEL`, and accept the proof only if this call removed it. A request accepts at most one proof ([WIP-201 §4.7](../../docs/WIPs/wip-201.md#47-consuming-flamingo-tokens) check 4). A user can obtain several valid proofs for one request, so skipping this step lets one request be redeemed more than once.
4. Check that the challenge image behind `challenge_hash` is one the RP checked against the party it interacts with ([WIP-202 §4.8](../../docs/WIPs/wip-202.md#48-reference-verification) item 5).

## API

### `POST /v1/embedding-similarity/verify`

```json
{
  "request": { "...": "the ProofRequest the RP issued, from its own store" },
  "response": { "...": "the ProofResponse the Authenticator returned" }
}
```

`request` and `response` are the protocol's JSON encodings of `ProofRequest` and `ProofResponse`, the same objects the RP sends to and receives from the Authenticator.

Every answer carries a `result`. Only `200` means the proof was accepted:

| Status | `result` | Meaning | Retry? |
| --- | --- | --- | --- |
| `200` | `accepted` | The proof is valid for the request and the RP's policy. Consume the stored request now. | — |
| `400`, `413` | `invalid` | The body is not a verification of a valid WIP-202 request. | No |
| `422` | `rejected` | The proof does not satisfy the request or the policy. | No |
| `503` | `unavailable` | No verdict was reached: a registry was unreachable, every verification slot was busy, or the request timed out. Has `Retry-After`. | Yes, with backoff and jitter |
| `500` | `internal` | The sidecar failed. | No |

Answers other than `200` also carry a stable `code` and a `message`:

```json
{ "result": "rejected", "code": "stale_proof", "message": "the proof's time 1795167232 is not within 300s of 1795167900" }
```

| `code` | `result` |
| --- | --- |
| `invalid_body`, `body_too_large`, `not_embedding_similarity`, `invalid_request` | `invalid` |
| `response_mismatch`, `request_expired`, `attestation_not_accepted`, `attested_key_mismatch`, `engine_not_accepted`, `stale_proof`, `invalid_root`, `untrusted_issuer_key`, `aat_required`, `aat_not_accepted`, `invalid_proof` | `rejected` |
| `root_check_failed`, `issuer_check_failed`, `overloaded`, `timeout` | `unavailable` |
| `clock_error`, `proof_verifier_failed`, `verification_panicked` | `internal` |

### `GET /health`

Answers `200` once the sidecar serves. It checks no dependency. A registry outage answers verifications with `503` instead, so an outage does not take the caller's whole pod out of service.

## Configuration

| Variable | Default | Description |
| --- | --- | --- |
| `POLICY_PATH` | required | The RP's policy file, see below. |
| `RPC_URL` | required | World Chain JSON-RPC endpoints, comma-separated. Every call goes to all of them, and the first successful answer wins. |
| `WORLD_ID_REGISTRY_ADDRESS` | required | The `WorldIDRegistry` proxy. |
| `CREDENTIAL_SCHEMA_ISSUER_REGISTRY_ADDRESS` | required | The `CredentialSchemaIssuerRegistry` proxy. |
| `LISTEN_ADDR` | `127.0.0.1:9202` | Keep it on loopback. |
| `MAX_CONCURRENT_VERIFICATIONS` | available CPUs | Verifications that may run at once. Each runs on its own thread and holds its slot from the registry reads to the proof verification. Requests beyond this are answered `503 overloaded` at once; they are not queued. Keep it well below 512, the size of the blocking thread pool that DNS lookups share. |
| `REQUEST_TIMEOUT_SECS` | `30` | The deadline of one verification. At the deadline the registry reads are cancelled and the request is answered `503 timeout`. CPU-bound work already running keeps its slot until it finishes. |
| `MAX_BODY_BYTES` | `8388608` | The largest request body accepted. |
| `RPC_TIMEOUT_SECS` | `3` | The timeout of one JSON-RPC attempt. |
| `RPC_MAX_RETRIES` | `2` | Retries of a failed JSON-RPC call, with exponential backoff and jitter. |
| `RPC_INITIAL_BACKOFF_MS`, `RPC_MAX_BACKOFF_MS` | `100`, `1000` | The first and the longest backoff between retries. |

The registry addresses for each environment are in [`contracts/deployments/core`](../../contracts/deployments/core). Every verification reads both registries, one after the other, so a revoked root or a rotated Issuer key takes effect immediately. The RPC defaults let both reads finish within `REQUEST_TIMEOUT_SECS` even when every attempt times out. Keep that true when you change them, or registry outages show up as `timeout` instead of `root_check_failed` or `issuer_check_failed`.

An API key in an `RPC_URL` reaches neither responses nor logs at the default log level: errors name RPC endpoints by host only and redact their paths. The RPC transport's `debug` logs print full URLs.

Set the caller's own timeout a few seconds above `REQUEST_TIMEOUT_SECS`. A verification whose caller hangs up first is counted as `abandoned`, and its outcome is lost.

Telemetry is configured through [`telemetry-batteries`](https://crates.io/crates/telemetry-batteries):
- `TELEMETRY_PRESET`: for example `datadog`, which also needs `TELEMETRY_SERVICE_NAME`.
- `RUST_LOG`
- `TELEMETRY_METRICS_BACKEND`: `statsd` with `TELEMETRY_STATSD_HOST` and `TELEMETRY_STATSD_PORT`, or `prometheus`.

Metrics are off unless `TELEMETRY_METRICS_BACKEND` is set. The Prometheus exporter listens on `0.0.0.0:9090` unless `TELEMETRY_PROMETHEUS_LISTEN` says otherwise, so pick a port the pod or task leaves free. An invalid telemetry configuration stops the sidecar at startup.

### Policy

The policy file holds what the RP accepts beyond its own request ([WIP-202 §4.8](../../docs/WIPs/wip-202.md#48-reference-verification)). Each RP sets its own. See [`policy.example.json`](policy.example.json).

| Field | Description |
| --- | --- |
| `issuer_version` | The `issuer_version` of the Proof of Human Credential. |
| `flamingo_verifiers` | The PCR0–2 of each Flamingo Verifier enclave image accepted (WIP-201 §4.7 check 1), as hex. |
| `engine_config_hashes` | The Engine configurations accepted (WIP-201 §4.7 check 6), as field elements. |
| `aat.required` | Whether proofs without an Authenticator Assertion are rejected. |
| `aat.trust_anchor_key_hashes`, `aat.accepted_flags` | The AAT values accepted ([WIP-106 §4](../../docs/WIPs/wip-106.md)). Both must be empty, or both must be set. With both empty, only proofs without an AAT are accepted. |

The sidecar refuses to start with a policy that:
- has unknown fields
- has an all-zero PCR0
- accepts no Flamingo Verifier or no Engine configuration
- requires an AAT but accepts none

Keep these points in mind:
- **Engine hashes.** Each one is `engine_config_hash(release_hash, pipeline_id, match_strictness)` for a release manifest that was verified under an active key of the manifest's `iss`. The sidecar does not read manifests. Compute the hashes with `world_id_rp::embedding_similarity::accepted_engine_configs`, or take them from the publisher of the Engine release. Remove a release's hashes when its manifest or key is revoked.
- **AAT requirement.** `aat.required` decides whether an AAT is required, whatever the request's own `aat` says. An RP that asks for an AAT in its requests must also set it here.
- **Releases.** Each Flamingo Verifier or Engine release changes these values. Add a new release's values before Flamingo starts serving it, and remove the old values afterwards.

## Deployment

`build-docker.yml` publishes the image for `linux/amd64` to `ghcr.io/worldcoin/world-id-protocol/world-id-rp-sidecar`:
- Pushing the git tag `world-id-rp-sidecar-v<version>` publishes `v<version>`.
- Every push to `main` publishes `sha-<sha>`.
- Pushes to `main` and stable release tags also move `latest`.

Pin the digest.

The image embeds the verifier of one WIP-202 circuit version: the version of the `world-id-proof` it is built with. Proofs from Authenticators on another circuit version are rejected with `invalid_proof`. Pin an image built with the version the Authenticators prove with, and upgrade the two together.

Run the sidecar as a [native sidecar](https://kubernetes.io/docs/concepts/workloads/pods/sidecar-containers/), so that it starts before the app container and stops after it. The app can then finish verifications while it drains:

```yaml
initContainers:
  - name: world-id-rp-sidecar
    image: ghcr.io/worldcoin/world-id-protocol/world-id-rp-sidecar@sha256:<digest>
    restartPolicy: Always
    env:
      - name: POLICY_PATH
        value: /etc/world-id-rp-sidecar/policy.json
      - name: RPC_URL
        valueFrom:
          secretKeyRef: { name: world-chain-rpc, key: url }
      - name: WORLD_ID_REGISTRY_ADDRESS
        value: "<from contracts/deployments/core>"
      - name: CREDENTIAL_SCHEMA_ISSUER_REGISTRY_ADDRESS
        value: "<from contracts/deployments/core>"
    volumeMounts:
      - { name: world-id-rp-sidecar-policy, mountPath: /etc/world-id-rp-sidecar }
```

On ECS, add the sidecar to the app's task definition. Containers in an `awsvpc` task share `127.0.0.1`. Make the app container `dependsOn` the sidecar, so that the sidecar starts first and stops last.

Neither platform can probe the sidecar:
- A kubelet probe connects to the pod IP, not to loopback.
- The image has no shell for an ECS container health check.

So the app should retry connection errors and `503`s for the few seconds the sidecar needs to start.

Verification is CPU-bound:
- Size the container's CPU from `embedding_similarity.proof_verification_ms`.
- Set `MAX_CONCURRENT_VERIFICATIONS` from the verify route's `http.latency_ms`, since a slot is also held through the registry reads.

## Observability

| Metric | Description |
| --- | --- |
| `embedding_similarity.verifications{result,code}` | Every verification, by outcome. `code` is `accepted` for an accepted proof, and both are `abandoned` when the caller hung up before the answer. |
| `embedding_similarity.proof_verification_ms` | The duration of the zero-knowledge proof verification alone. |
| `http.latency_ms{route,method,status_class}` | Request latency. |
| `rpc.endpoint_requests`, `rpc.endpoint_latency_ms` | Registry reads per RPC endpoint host. |

`unavailable` outcomes other than `overloaded` are logged at `warn`, and `internal` outcomes at `error`. Rejections and shed requests are counted, not logged: the caller receives the reason for a rejection, and logging every shed request would add load during an overload.

## Development

`world-id-proof` compiles the Noir verifier with `nargo`, so build inside the repo's dev shell:

```sh
nix develop --command cargo test -p world-id-rp-sidecar
```

Run the sidecar in a release build to verify real proofs, for example `cargo run --release -p world-id-rp-sidecar`. In debug builds, ProveKit checks the prover's transcript pattern, which no proof carries after serialization, so every proof received over the API panics the verifier. The sidecar answers that with `500 verification_panicked` and keeps serving.
