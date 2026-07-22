-- Stores RP (relying party) signatures over proof requests so they can be verified later.
CREATE TABLE IF NOT EXISTS rp_signatures (
    id BIGINT GENERATED ALWAYS AS identity PRIMARY KEY,
    rp_id BIGINT NOT NULL,
    -- version is currently always 1
    version SMALLINT NOT NULL DEFAULT 1,
    nonce BYTEA NOT NULL,
    -- Signed validity window (u64 unix seconds stored as bigint)
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    -- The request's action field; part of the signed message for Uniqueness Proof requests.
    action BYTEA NOT NULL,
    -- RP ECDSA (secp256k1) signature over the message (alloy Signature, 65 bytes)
    signature BYTEA,
    -- Auxiliary data passed to a WIP101 signer contract's `verifyRpRequest`; only present
    -- (and only meaningful) when `signature` is NULL, i.e. the RP is WIP101-backed.
    wip101_data BYTEA,
    -- Record insertion timestamp (bookkeeping)
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);