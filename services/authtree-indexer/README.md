# World ID Indexer

The World ID Indexer primarily indexes the Acccount Registry of the World ID Protocol and provides inclusion proofs for specific public keys.

## Developing Locally

1. Set up your enviroment variables

```
    cp .env.example .env
```

2. Run Postgres (e.g. through Docker)

```
    docker run --name postgres -p 5432:5432
```
