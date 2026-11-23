# MCP audit ingest v1 (Ticket 34)

POST /api/security-events/mcp is mounted with the existing OAuth route flag. Configure
MCP_AUDIT_INGEST_URL to this absolute endpoint and MCP_CLIENT_ID to the registered
confidential MCP service. Apply migration 005 in the target database before enabling it.

Send application/json with one property, events (1–32 records, 16 KiB total).
Use Authorization: Bearer followed by a short-lived service-signed private_key_jwt.
Its sole audience is MCP_AUDIT_INGEST_URL. Include body_sha256 as lowercase hex SHA-256
of the exact UTF-8 body bytes. Reuse the existing assertion verifier and replay store.
Each retry needs a fresh assertion/JTI and the same immutable event payload.

The v1 fields and accepted values are defined in services/mcpAuditEvents.js. See
test/mcpAuditIngest.test.js for a synthetic started/completion pair. A successful
response contains data.acknowledged, an array of event_id and phase pairs. The sender
must find the matching started acknowledgement before exchange or business dispatch.
Treat timeouts and missing/malformed acknowledgements as unconfirmed. An identical
retry succeeds, conflicting content under the same key returns 409, and a persistence
failure returns 503. Never log the assertion, request body, or raw tool inputs.

The migration restricts table and RPC access to the backend service role. Ingest
removes records older than 90 days on each successful transaction. If strict expiry
during idle periods is required, schedule the same retention delete independently.
The shared security-events reader exposes redacted metadata for each phase.

Local route tests: run npx mocha --require ./test/support/dummyEnv.js test/mcpAuditIngest.test.js
from a checkout with installed dependencies and no real .env. Backend delivery, applying
the migration, and wiring the MCP sender are separate milestones.
