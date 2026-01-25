#!/bin/bash

set -e

GATEWAY_URL="${GATEWAY_URL:-http://localhost:8081}"

echo "🧪 Testing account creation..."
echo "Gateway URL: $GATEWAY_URL"
echo ""

# Generate random values for unique account
echo "🎲 Generating random account data..."
RANDOM_RECOVERY=$(openssl rand -hex 20 | sed 's/^/0x/')
RANDOM_AUTH=$(openssl rand -hex 20 | sed 's/^/0x/')
# Generate values less than SNARK scalar field (use 31 bytes to be safe)
RANDOM_PUBKEY=$(openssl rand -hex 31 | sed 's/^/0x/')
RANDOM_COMMITMENT=$(openssl rand -hex 31 | sed 's/^/0x/')

echo "Recovery address: $RANDOM_RECOVERY"
echo "Authenticator address: $RANDOM_AUTH"
echo "Commitment: $RANDOM_COMMITMENT"
echo ""

# Create account request
echo "📤 Sending create account request..."
RESPONSE=$(curl -s -X POST "$GATEWAY_URL/create-account" \
  -H "Content-Type: application/json" \
  -d "{
    \"recovery_address\": \"$RANDOM_RECOVERY\",
    \"authenticator_addresses\": [\"$RANDOM_AUTH\"],
    \"authenticator_pubkeys\": [\"$RANDOM_PUBKEY\"],
    \"offchain_signer_commitment\": \"$RANDOM_COMMITMENT\"
  }")

echo "Response:"
echo "$RESPONSE" | jq '.' 2>/dev/null || echo "$RESPONSE"
echo ""

# Extract request ID
REQUEST_ID=$(echo "$RESPONSE" | jq -r '.request_id' 2>/dev/null)

if [ "$REQUEST_ID" = "null" ] || [ -z "$REQUEST_ID" ]; then
  echo "❌ Failed to create account. No request_id in response."
  exit 1
fi

echo "✅ Account creation request submitted!"
echo "Request ID: $REQUEST_ID"
echo ""

# Poll for status
echo "⏳ Polling for request status..."
MAX_ATTEMPTS=30
ATTEMPT=0

while [ $ATTEMPT -lt $MAX_ATTEMPTS ]; do
  ATTEMPT=$((ATTEMPT + 1))
  
  STATUS_RESPONSE=$(curl -s "$GATEWAY_URL/status/$REQUEST_ID")
  STATE=$(echo "$STATUS_RESPONSE" | jq -r '.status.state' 2>/dev/null)
  
  echo "Attempt $ATTEMPT/$MAX_ATTEMPTS - Status: $STATE"
  
  if [ "$STATE" = "completed" ]; then
    echo ""
    echo "✅ Account created successfully!"
    echo "Full response:"
    echo "$STATUS_RESPONSE" | jq '.' 2>/dev/null || echo "$STATUS_RESPONSE"
    
    # Get transaction hash if available
    TX_HASH=$(echo "$STATUS_RESPONSE" | jq -r '.status.tx_hash // empty' 2>/dev/null)
    if [ -n "$TX_HASH" ] && [ "$TX_HASH" != "null" ]; then
      echo ""
      echo "Transaction hash: $TX_HASH"
    fi
    
    exit 0
  elif [ "$STATE" = "failed" ]; then
    echo ""
    echo "❌ Account creation failed!"
    echo "Full response:"
    echo "$STATUS_RESPONSE" | jq '.' 2>/dev/null || echo "$STATUS_RESPONSE"
    exit 1
  fi
  
  sleep 1
done

echo ""
echo "⏱️  Timeout waiting for account creation to complete"
echo "Final status:"
curl -s "$GATEWAY_URL/status/$REQUEST_ID" | jq '.' 2>/dev/null
exit 1
