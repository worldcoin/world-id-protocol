# world-id-billing-follower

Follows the WIP-107 Billing Contract at the latest block and emits the billing state a TEE Verifier's host supplies to it (WIP-107 §4.8).

`BillingFollower::next` returns `BillingUpdate`s: the `BillingOp`s to apply to a copy of `world_id_primitives::billing::BillingState`, the block the state is current up to, and whether the follower has caught up. The follower:

- backfills `BilledRpUpdated` logs from the Contract's deployment and `Registered` logs from the start of the earliest active billing period, with `eth_getLogs` ranges that shrink when a provider rejects them;
- polls on the chain's block schedule, checks each new block's parent hash, and answers a reorganization within its window with the ops that undo it; a deeper fork restarts it from an empty state, flagged as `reset`;
- retries failed reads with exponential backoff and jitter, and moves to the next endpoint after a failure;
- reports `billing_follower.*` metrics through the `metrics` facade.

`ChainSource` abstracts the reads; `RpcSource` implements it over JSON-RPC.
