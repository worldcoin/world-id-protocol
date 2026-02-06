# Faux Issuer Service

A simple mock issuer service for testing World ID credential issuance. This service provides an HTTP API to issue signed credentials for testing purposes.

## Overview

The faux-issuer is a lightweight Axum HTTP server that issues World ID credentials. It loads its signing key from environment variables, making it suitable for local development and testing only.

**⚠️ WARNING: This service is for testing only. Never use it in production!**

## Configuration

The service is configured through environment variables. Create a `.env` file in the service directory or set these variables in your environment:

### Required Environment Variables

- `SIGNING_KEY` - 32-byte signing key as a hex string (64 characters). This seed is used to derive both on-chain and off-chain signing keys for the issuer.

### Optional Environment Variables

- `ISSUER_SCHEMA_ID` - Default issuer schema ID to use when not specified in requests. Supports both decimal (e.g., `295`) and hex format (e.g., `0x127`). Defaults to `1`.

### Example Configuration

Copy `.env.example` to `.env`:

```bash
cp .env.example .env
```

Example `.env` file:
```bash
# Signing key (64 hex characters)
SIGNING_KEY=0000000000000000000000000000000000000000000000000000000000000001

# Default issuer schema ID (hex or decimal)
ISSUER_SCHEMA_ID=0x127
```

## Running the Service

```bash
cargo run -p world-id-faux-issuer
```

The service will start on `http://127.0.0.1:3000`.

## API Endpoints

### POST /issue

Issues a new credential for the provided subject.

**Request Body:**

```json
{
  "sub": "0x1234567890abcdef...",  // 64-char hex string (32 bytes) - Required
  "issuer_schema_id": 1,           // Optional, defaults to ISSUER_SCHEMA_ID env var
  "expires_at": 1735689600         // Optional, defaults to 1 year from now (unix timestamp)
}
```

**Response:**

```json
{
  "credential": {
    "id": 12345678901234567890,
    "version": "V1",
    "issuer_schema_id": 1,
    "sub": "0x...",
    "genesis_issued_at": 1704153600,
    "expires_at": 1735689600,
    "claims": [...],
    "associated_data_hash": "0x...",
    "signature": {...},
    "issuer": {...}
  }
}
```

**Example:**

```bash
curl -X POST http://127.0.0.1:3000/issue \
  -H "Content-Type: application/json" \
  -d '{
    "sub": "0000000000000000000000000000000000000000000000000000000000000001",
    "issuer_schema_id": 1
  }'
```

### GET /health

Health check endpoint.

**Response:** `OK`

## Implementation Details

- **Issuer Seed:** Loaded from `SIGNING_KEY` environment variable for deterministic key generation
- **Issuer Schema ID:** Loaded from `ISSUER_SCHEMA_ID` environment variable (supports hex with `0x` prefix or decimal)
- **Port:** 3000 (hardcoded)
- **Host:** 127.0.0.1 (localhost only)
- **Credential Expiration:** Defaults to 1 year from issuance if not specified
- **Genesis Issued At:** Set to current timestamp
