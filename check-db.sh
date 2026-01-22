#!/bin/bash

# Database connection settings
DB_HOST="${DB_HOST:-localhost}"
DB_USER="${DB_USER:-postgres}"
DB_PASSWORD="${DB_PASSWORD:-postgres}"
DB_NAME="${DB_NAME:-world_id_indexer}"

echo "🔍 Checking database state..."
echo ""

echo "📊 Events table:"
PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -U $DB_USER -d $DB_NAME -c "
SELECT 
  id, 
  leaf_index, 
  event_type, 
  new_commitment, 
  block_number, 
  LEFT(tx_hash, 18) || '...' as tx_hash,
  created_at 
FROM world_id_events 
ORDER BY id DESC 
LIMIT 10;
"

echo ""
echo "👤 Accounts table:"
PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -U $DB_USER -d $DB_NAME -c "
SELECT 
  leaf_index,
  LEFT(recovery_address::text, 10) || '...' as recovery,
  authenticator_addresses,
  authenticator_pubkeys,
  offchain_signer_commitment,
  created_at
FROM accounts 
ORDER BY leaf_index DESC 
LIMIT 10;
"

echo ""
echo "📈 Summary:"
PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -U $DB_USER -d $DB_NAME -c "
SELECT 
  (SELECT COUNT(*) FROM accounts) as total_accounts,
  (SELECT COUNT(*) FROM world_id_events) as total_events,
  (SELECT MAX(leaf_index) FROM accounts) as max_leaf_index;
"

ls -lh /tmp/tree.mmap
cat /tmp/tree.mmap.meta| jq '.'