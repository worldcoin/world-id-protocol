# World ID Indexer

The World ID Indexer primarily indexes the Acccount Registry of the World ID Protocol and provides inclusion proofs for specific public keys.

The indexer will backfill `AccountCreated` events into Postgres tables defined under `services/indexer/migrations`, then optionally follow live via WS if `WS_URL` is set.

## Developing Locally

1. Set up your enviroment variables

```
    cp .env.example .env
```

2. Run Postgres (e.g. through Docker)

```
    docker compose -f indexer/docker-compose.tests.yml up
```
