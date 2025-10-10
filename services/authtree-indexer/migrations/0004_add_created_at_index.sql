-- Add index on created_at for efficient polling queries
CREATE INDEX IF NOT EXISTS idx_commitment_updates_created_at
ON commitment_update_events(created_at DESC);
