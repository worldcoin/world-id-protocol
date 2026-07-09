-- Stores RP (relying party) signatures over proof requests so they can be verified later.
CREATE TABLE IF NOT EXISTS rp_signatures (
    id BIGINT GENERATED ALWAYS AS identity PRIMARY KEY,
    rp_id BIGINT NOT NULL,
    epoch BIGINT NOT NULL,
    -- version is currently always 1
    version SMALLINT NOT NULL DEFAULT 1,
    nonce BYTEA NOT NULL,
    -- Signed validity window (u64 unix seconds stored as bigint)
    signed_created_at BIGINT NOT NULL,
    signed_expires_at BIGINT NOT NULL,
    -- RP ECDSA (secp256k1) signature over the message (alloy Signature, 65 bytes)
    signature BYTEA,
    -- Record insertion timestamp (bookkeeping)
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- A given nonce should be signed at most once per RP (replay protection)
    constraint uq_rp_signatures_rp_id_nonce unique (rp_id, nonce, epoch)
);

-- Singleton table holding the last epoch the accountant has fully processed (i.e. voted
-- on). `id` is pinned to `true` so there can only ever be one row. Seeded at -1 (no epoch
-- processed yet) so the first tick starts from epoch 0.
CREATE TABLE IF NOT EXISTS epoch_cursor (
    id BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id),
    epoch BIGINT NOT NULL
);

INSERT INTO epoch_cursor (epoch)
VALUES (-1);