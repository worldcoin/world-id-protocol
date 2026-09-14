# Draft: typed proof integrity statements

Status: proposal for review. This document does not change an accepted wire format,
enable a rollout, or provide a production encoder. Version 3 below is proposed,
subject to confirming that the integrity-bundle version is available.

## Problem and objective

An integrity signature must associate app-attested claims with the proof accepted
by the verifier. Signing the request nonce and face score alone does not provide
that association. OPRF nonce consumption is replay protection, not a substitute
for this binding.

[iOS #7980](https://github.com/worldcoin/world-app-ios/pull/7980) adds the face
nullifier to a generic list of claims. Its `integrityClaims()` parses either a
uniqueness nullifier or a session nullifier as one field. A session nullifier is
two fields, `(nullifier, action)`, serialized with the `snil_` prefix. In the
observed device flow, proof generation consumed the nonce, local digest
construction failed, and retrying proof generation returned `duplicate_nonce`.
[Portal #2335](https://github.com/worldcoin/developer-portal/pull/2335) instead
selects only the first session field. These are not interchangeable encodings.

Replace this implicit convention with a typed statement. Keep proof bindings
separate from disclosed claims, and define the same bytes for native clients and
the verifier. Bind both session fields directly; neither truncation, modular
reduction, nor a separate nested hash is needed.

## Proposed model

```text
IntegrityStatement {
  rp_id: RpId,
  nonce: FieldElement,
  items: [IntegrityItem]
}

IntegrityItem {
  identifier: String,
  issuer_schema_id: u64,
  binding: ProofBinding,
  claims: [FieldElement]
}

ProofBinding = Uniqueness { nullifier: FieldElement }
             | Session { nullifier: FieldElement, action: FieldElement }
```

The request supplies the numeric protocol RP ID and nonce. The generated response
supplies each item's identifier, issuer, and binding. Include **every response
item**, in response order, including items with no disclosed claims. This avoids
a face-specific rule in the encoder. Bind identifiers explicitly so relabeling an
item cannot transfer its signed claims to another request item.

Claims follow the credential schema's defined disclosure order and encoding.
For the current face schema, the sole claim is `sybil_score`, encoded as its
nonnegative integer value, not its JSON text. Portal currently requires a safe
integer; preserve that validation. Other supported schemas with no app-attested
claims use an empty list. Adding a claim or changing its meaning requires an
explicit schema/version decision; do not accept arbitrary extra claim fields.

The adapter must reject missing or simultaneous nullifier variants, a variant
inconsistent with the verified proof type, invalid fields, duplicate identifiers,
and unsupported claim schemas. Construct a session binding through the protocol's
`SessionNullifier` validation, including the session-action prefix constraint.
Do not substitute zero, drop failed items, or infer a proof type from text prefixes
in application code.

## Canonical bytes

The proposed payload digest is SHA-256 of this concatenation:

| Order | Bytes |
| --- | --- |
| Domain | Exact ASCII `worldcoin/proof-integrity/statement/v3`, without a terminator |
| RP | `u64_be(rp_id)` |
| Request | `field32(nonce)` |
| Item count | `u32_be(items.length)` |
| Each item | The item encoding below, in response order |

Each item is:

```text
u32_be(identifier_utf8.length) || identifier_utf8
|| u64_be(issuer_schema_id)
|| u8(binding_tag)
|| field32(nullifier)
|| [field32(action) only for Session]
|| u32_be(claims.length)
|| field32(claim_0) || ... || field32(claim_n)
```

Tags are `0` for Uniqueness and `1` for Session. Reject other tags. `field32` is
the canonical, unsigned, 32-byte big-endian protocol field representation; reject
values outside the field, rather than reducing them. The field modulus is
`21888242871839275222246405745257275088548364400416034343698204186575808495617`.
Integer lengths must fit their widths, without wrapping. Identifiers use exact
UTF-8 bytes, without Unicode normalization, sorting, or case conversion. Apply
the existing request size limits before allocation or encoding.

No JSON serialization, string prefix, or platform integer formatting participates
in these bytes. `nil_`/`snil_` and Portal's array representation are transport
adapters to the same protocol types.

Keep the existing outer attestation construction and checks: timestamp, signature
format, attested key/token, audience, environment, and freshness validation. This
proposal replaces the payload digest only; `rp_id` also makes the payload's RP
context explicit. The numeric RP ID must agree with the request and attestation
audience mapping.

## Verification and the security boundary

The verifier reconstructs this statement from the request and response fields it
actually uses for proof verification. It must not accept a client-provided digest
or duplicate binding object as authoritative. Validate the request, match items
to it, reconstruct the statement, and require both a valid integrity signature
and valid protocol proofs before accepting claims. Implementations may order
these checks for efficiency, but none is optional.

This associates claims with a proof's nullifier binding; it is **not** a signature
over the full proof bytes. Proof bytes, Merkle roots, `expires_at_min`, uniqueness
action, and session ID remain validated by the protocol verifier against the
request. Changing any of those must still satisfy that verifier. This proposal
does not replace its checks, RP request authentication, or replay policy, and does
not claim that an attested client cannot be compromised.

For sessions, including both fields commits to the complete `SessionNullifier`
accepted by verification. The protocol already relates its action to the
nullifier. Explicitly binding the pair avoids relying on that relationship as an
undocumented shortcut in a separate integrity format.

## Ownership and proposed API

- `world-id-primitives`: own the statement types, validation, and canonical encoder
  once the format is approved. Keep the encoder independent of platform signing.
- WalletKit: derive bindings from its typed `ProofResponse`; expose a native API
  that associates typed disclosures by item identifier and returns the digest.
  App code must not choose or parse a nullifier separately from the response.
- Oxide / app integrity: retain attestation/signature support. Delegate canonical
  encoding to the shared implementation if a digest API remains here; avoid a
  second Rust implementation and avoid introducing a WalletKit dependency in Oxide.
- Portal: reconstruct from the verified request/response models. Prefer a shared
  Rust/WASM implementation; an independent TypeScript adapter must pass the same
  checked-in vectors and mutation cases.

Illustrative call (not an API added by this PR):

```text
response.integrity_digest(request_context, disclosures_by_item_identifier)
```

The API validates disclosure coverage and emits items in response order regardless
of map iteration order. Platform callers receive bytes and pass them to the
existing integrity signing path. There is no `[[SemaphoreField]]` escape hatch
for constructing proof bindings in Swift.

## Delivery and versioning

1. Review the binding scope, claim mapping, bytes, and version allocation with
   protocol, WalletKit, Portal, and mobile owners. Security review must explicitly
   approve the signed-byte and authorization changes before implementation ships.
2. Implement shared types/encoder and native adapters; publish required packages.
   Verify the synthetic vectors with independently implemented native and server
   encoders. The companion script is an executable specification, not that parity
   verification and not proof that protocol proofs are valid.
3. Add Portal support for the new version before emitting it from clients. Keep
   existing versions byte-for-byte unchanged. Apply an explicit server policy for
   which versions may attest which claims; compatibility must not allow a request
   requiring the new binding to fall back to a weaker version.
4. Switch clients and counterpart verifiers together behind the established
   rollout process. Do not silently reinterpret v2 or infer versions from length.
   If v2 is conclusively unshipped everywhere, owners may instead revise this
   allocation explicitly before approving the contract.
5. Verify live uniqueness, session creation, cached session continuation, and
   uncached continuation before rollout. This documentation does not resolve the
   existing iOS/Portal fix PRs or assert that either is deployed.

Separately, split proof generation from delivery: after successful generation,
retain the immutable proof and digest for the active flow and retry only delivery.
Do not regenerate OPRF material under the same signed request after a digest or
transport failure. A deterministic encoding failure is terminal, not a network
retry. If the prepared result is unavailable, obtain a fresh signed RP request.
Retention, sensitive-data handling, and ambiguous upload outcomes need their own
review; no new persistence or generic retry policy is proposed here.

## Review and validation checklist

- Confirm numeric RP mapping, identifier binding, all-item coverage, and claim
  schema interpretation; decide whether any additional public input must be signed.
- Confirm the version/domain with all consumers, including other mobile clients.
- Match native and Portal digests for uniqueness, sessions, and mixed issuers.
- Alter each RP/nonce/identifier/issuer/tag/nullifier/action/claim field and item
  order independently; require an integrity mismatch.
- Reject malformed variants, out-of-range fields, wrong session prefixes, unknown
  tags/schemas, and duplicate identifiers before signing or acceptance.
- Require valid protocol proofs even when the integrity signature matches.
- Verify delivery retries do not issue additional OPRF calls.

Run `python3 docs/integrity-statement/vectors.py` to check the synthetic byte
vectors. No device data, real proofs, tokens, or credentials are included.
