# World ID RP Sidecar

A local HTTP service that verifies [WIP-202](../../docs/WIPs/wip-202.md) Proofs of Embedding Similarity for a Relying Party. It wraps [`world-id-rp`](../../crates/rp) so that services written in Node, Go or other languages can verify proofs without building Rust.

It runs next to the RP's service, for example as a Kubernetes sidecar container, and listens on loopback only. It has no authentication, so it must not be reachable from outside its pod.

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
| `200` | `accepted` | The proof is valid for the request and the RP's policy. Consume the nonce now. | — |
| `400`, `413` | `invalid` | The body is not a verification of a WIP-202 request. | No |
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
| `clock`, `proof_verifier`, `verification_panicked` | `internal` |

### `GET /health`

Answers `200` once the sidecar serves. It checks no dependency. A registry outage answers verifications with `503` instead, so an outage does not take the caller's whole pod out of service.

## Configuration

| Variable | Default | Description |
| --- | --- | --- |
| `POLICY_PATH` | required | The RP's policy file, see below. |
| `RPC_URL` | required | World Chain JSON-RPC endpoints, comma-separated, in priority order. |
| `WORLD_ID_REGISTRY_ADDRESS` | required | The `WorldIDRegistry` proxy. |
| `CREDENTIAL_SCHEMA_ISSUER_REGISTRY_ADDRESS` | required | The `CredentialSchemaIssuerRegistry` proxy. |
| `LISTEN_ADDR` | `127.0.0.1:9202` | Keep it on loopback. |
| `MAX_CONCURRENT_VERIFICATIONS` | available CPUs | Proof verifications that may run at once. Requests beyond this are answered `503 overloaded`; they are not queued. |
| `REQUEST_TIMEOUT_SECS` | `30` | The longest one request may take. |
| `MAX_BODY_BYTES` | `8388608` | The largest request body accepted. |
| `RPC_MAX_RETRIES`, `RPC_INITIAL_BACKOFF_MS`, `RPC_MAX_BACKOFF_MS`, `RPC_TIMEOUT_SECS` | see `world-id-services-common` | Bounded retries with backoff for the registry reads. |

The registry addresses for each environment are in [`contracts/deployments/core`](../../contracts/deployments/core). Every verification reads both registries, so a revoked root or a rotated Issuer key takes effect immediately.

### Policy

The policy file holds what the RP accepts beyond its own request ([WIP-202 §4.8](../../docs/WIPs/wip-202.md#48-reference-verification)). Each RP sets its own. See [`policy.example.json`](policy.example.json).

| Field | Description |
| --- | --- |
| `issuer_version` | The `issuer_version` of the PoH Credential. |
| `flamingo_verifiers` | The PCR0–2 of each Flamingo Verifier enclave image accepted (WIP-201 §4.7 check 1), as hex. |
| `engine_config_hashes` | The Engine configurations accepted (WIP-201 §4.7 check 6), as field elements. |
| `aat.required` | Whether proofs without an Authenticator Assertion are rejected. |
| `aat.trust_anchor_key_hashes`, `aat.accepted_flags` | The AAT values accepted ([WIP-106 §4](../../docs/WIPs/wip-106.md)). Both must be empty, or both must be set. With both empty, only proofs without an AAT are accepted. |

The sidecar refuses to start with a policy that has unknown fields, an all-zero PCR0, no Flamingo Verifier or no Engine configuration. Each Flamingo Verifier or Engine release changes these values. Add a new release's values before Flamingo starts serving it, and remove the old values afterwards.

## Deployment

Images are published to `ghcr.io/worldcoin/world-id-protocol/world-id-rp-sidecar`, tagged `world-id-rp-sidecar-v<version>`. Pin the digest.

The image embeds the verifier of one WIP-202 circuit version: that of the `world-id-proof` it is built with. Proofs from Authenticators on another circuit version are rejected with `invalid_proof`. Pin an image built with the version the Authenticators prove with, and upgrade it together with them.

Run the sidecar as a [native sidecar](https://kubernetes.io/docs/concepts/workloads/pods/sidecar-containers/) so that it starts before the app container and stops after it. The app can then finish verifications while it drains:

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
    startupProbe:
      httpGet: { path: /health, port: 9202 }
    volumeMounts:
      - { name: world-id-rp-sidecar-policy, mountPath: /etc/world-id-rp-sidecar }
```

On ECS, add the sidecar to the app's task definition. Containers in an `awsvpc` task share `127.0.0.1`. Make the app container `dependsOn` the sidecar, so the sidecar starts first and stops last. The image has no shell, so the task cannot run a container health check against it; until it can, the app should retry `503`s and connection errors during startup.

Proof verification is CPU-bound. Set the container's CPU and memory from a measured verification, and set `MAX_CONCURRENT_VERIFICATIONS` to match the CPU limit.

## Observability

| Metric | Description |
| --- | --- |
| `embedding_similarity.verifications{result,code}` | Every verification, by outcome. |
| `http.latency_ms` | Request latency per route and status. |
| `rpc.endpoint_requests`, `rpc.endpoint_latency_ms` | Registry reads per RPC endpoint. |

`unavailable` outcomes are logged at `warn` and `internal` outcomes at `error`. Rejections are counted but not logged, because the caller receives their reason.

## Development

`world-id-proof` compiles the Noir verifier with `nargo`, so build inside the repo's dev shell:

```sh
nix develop --command cargo test -p world-id-rp-sidecar
```

ProveKit checks a transcript pattern only in debug builds, and a forged proof without that pattern makes it panic. The sidecar runs each verification on its own blocking thread, so such a panic becomes a `500 verification_panicked` and does not take the sidecar down. Release builds compile that check out and reject the proof with `invalid_proof`.
