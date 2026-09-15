-- =============================================================================
-- Migration 002: OAuth 2.1 authorization server tables
-- Ticket 35 — NutriHelp MCP integration
--
-- Gates:    ticket 9 (D1) approved 2026-09-05; ticket 12 decided 2026-09-05
--           (OAuth merges before the repository/database refactor).
--
-- ⚠️ THERE IS NO MIGRATION RUNNER IN THIS REPOSITORY.
--    Paste this file into the Supabase SQL editor and run it by hand.
--    Nobody will run it for you. Run section 10 afterwards and read its output.
--
-- ⚠️ SCHEMA IS APPLIED BEFORE ROUTE ACTIVATION, NEVER FROM STARTUP.
--    OAuth routes stay disabled until section 10 verifies clean, the client
--    smoke tests pass and the token lifecycle tests pass.
--
-- Idempotent: safe to run more than once. Every object uses IF NOT EXISTS, and
-- the constraint blocks are guarded by catalogue lookups.
--
-- Backout: section 11, commented out. Read it before you need it.
--
-- Not in this migration:
--   * mcp_audit_events — that is ticket 34's table and ships in its own
--     migration, so the two change sets stay independently reviewable and
--     revertible. This file is ticket 35 only.
--   * Any seed row. Client registration is entered at runtime through the
--     admin route; a committed INSERT carrying a real client_id and public key
--     is exactly the hard-coded value the Q16 decision forbids.
-- =============================================================================

-- =============================================================================
-- 1. EXTENSIONS
-- =============================================================================
-- btree_gist lets a GiST exclusion constraint use plain equality (`=`) on
-- scalar columns alongside a range operator. Section 3's key-window constraint
-- cannot be created without it. It is available on Supabase but is NOT enabled
-- by default, and because this file is pasted by hand there is no runner to
-- enable it for us — so it lives here, in the same file, rather than being
-- assumed present.
CREATE EXTENSION IF NOT EXISTS btree_gist;

-- gen_random_uuid() is built into PostgreSQL 13+; Supabase is well past that.
-- No pgcrypto dependency.

-- =============================================================================
-- 2. OAUTH CLIENTS
-- =============================================================================
-- Two kinds of client share this table because both are identified by an HTTPS
-- URL, so one column and one lookup serves both:
--
--   assistant_public      Claude, ChatGPT. Admitted by Client ID Metadata
--                         Document. PKCE is the only proof of possession.
--                         No key. This is the client_id that appears in
--                         mcp_client_grants and in the client_id claim.
--
--   service_confidential  The MCP server itself. Authenticates with
--                         private_key_jwt against a public key held in
--                         oauth_client_keys. NEVER appears in a grant row.
--                         This is the client_id that appears in the act claim.
--
-- Conflating the two is the case that is hard to unwind once this server holds
-- both, so sections 3 and 6 enforce the split in the schema rather than
-- trusting every future query to remember it.
CREATE TABLE IF NOT EXISTS oauth_clients (
  client_id                  TEXT        PRIMARY KEY,
  client_type                TEXT        NOT NULL
                                         CHECK (client_type IN ('assistant_public', 'service_confidential')),
  token_endpoint_auth_method TEXT        NOT NULL
                                         CHECK (token_endpoint_auth_method IN ('none', 'private_key_jwt')),
  display_name               TEXT        NOT NULL,
  allowed_origin             TEXT,
  redirect_uris              TEXT[],
  is_active                  BOOLEAN     NOT NULL DEFAULT TRUE,
  created_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  -- client_id is an HTTPS URL in both cases. Cleartext would put a client
  -- identifier that is also a fetchable document on an unprotected scheme.
  -- LIKE 'https://%' is too weak: it accepts 'https://' with no host at all.
  -- Require a non-empty host, and forbid query and fragment -- a client_id is
  -- compared byte for byte, so two spellings of one identifier is a bug source.
  CONSTRAINT oauth_clients_id_is_https
    CHECK (client_id ~ '^https://[^/?#[:space:]]+(/[^?#[:space:]]*)?$'),

  -- Q16: the confidential client id is an HTTPS URL with a NON-EMPTY PATH,
  -- which is what keeps it distinct from MCP_RESOURCE_IDENTIFIER. A bare
  -- origin, or a lone '/', would let the two collapse into each other -- the
  -- conflation the decision exists to prevent.
  CONSTRAINT oauth_clients_confidential_id_has_path
    CHECK (
      client_type <> 'service_confidential'
      OR client_id ~ '^https://[^/?#[:space:]]+/[^?#[:space:]]+$'
    ),

  -- The authentication method is determined by the client kind, in both
  -- directions. This is what makes "an assistant_public client can never
  -- successfully verify a private_key_jwt" a schema fact: there is no row
  -- shape in which that pairing exists.
  CONSTRAINT oauth_clients_auth_method_matches_type
    CHECK (
      (client_type = 'service_confidential' AND token_endpoint_auth_method = 'private_key_jwt')
      OR
      (client_type = 'assistant_public'     AND token_endpoint_auth_method = 'none')
    )
);

-- Redundant against the primary key, but required as the target of the
-- composite foreign keys in sections 3 and 6. A plain FK cannot see
-- client_type; a composite FK carrying it can, which keeps the client-kind
-- split declarative instead of trigger-based.
CREATE UNIQUE INDEX IF NOT EXISTS oauth_clients_id_type_key
  ON oauth_clients (client_id, client_type);

-- =============================================================================
-- 3. OAUTH CLIENT KEYS  (public keys for private_key_jwt)
-- =============================================================================
-- Ticket 40 requires two keys valid at once so a rotation needs no coordinated
-- deploy. The bound is on OVERLAPPING VALIDITY WINDOWS, not on a count of
-- active rows, and the distinction is the whole point:
--
--   The verifier iterates keys that are in window (not_before <= now() <
--   not_after) and active, capped at two. A count of currently-active rows
--   does not bind that. Insert a third key with not_before in the future and
--   every count-based check passes -- then its window opens, three keys are in
--   window, the verifier tries two, and an assertion signed by the third
--   silently fails to verify and presents as a client bug.
--
-- The correct invariant: no more than two key windows may overlap at any
-- instant, per client. Expressed as two slots, each internally non-overlapping.
--
-- A plain CHECK cannot express this -- CHECK is evaluated per row and cannot
-- see sibling rows, so "at most two active rows" written as a CHECK does not
-- compile as one and quietly becomes application code. An exclusion constraint
-- is the mechanism.
CREATE TABLE IF NOT EXISTS oauth_client_keys (
  id             BIGSERIAL   PRIMARY KEY,
  client_id      TEXT        NOT NULL,
  -- Carried so the composite FK below can pin the client kind. Frozen by its
  -- own CHECK: a key row can only ever belong to a confidential client.
  client_type    TEXT        NOT NULL DEFAULT 'service_confidential'
                             CHECK (client_type = 'service_confidential'),
  slot           SMALLINT    NOT NULL CHECK (slot IN (1, 2)),
  public_key_pem TEXT        NOT NULL,
  -- Nullable until the MCP side adds kid to the assertion header (Q16b).
  -- While it is null, key selection is by client_id and the verifier tries
  -- each in-window key, capped at two.
  kid            TEXT,
  alg            TEXT        NOT NULL CHECK (alg IN ('RS256', 'ES256', 'EdDSA')),
  not_before     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  -- NOT NULL so retirement is always an explicit date rather than an unbounded
  -- window nobody closes.
  not_after      TIMESTAMPTZ NOT NULL,
  -- Kill switch that can only SUBTRACT. The time window is the sole authority
  -- on validity: false always refuses, true never extends a row past
  -- not_after. An is_active = true row past its not_after does NOT verify.
  is_active      BOOLEAN     NOT NULL DEFAULT TRUE,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  CONSTRAINT oauth_client_keys_window_sane
    CHECK (not_after > not_before),

  CONSTRAINT oauth_client_keys_client_fk
    FOREIGN KEY (client_id, client_type)
    REFERENCES oauth_clients (client_id, client_type)
    ON DELETE CASCADE
);

-- A kid, when present, identifies exactly one key for a client.
CREATE UNIQUE INDEX IF NOT EXISTS oauth_client_keys_client_kid_key
  ON oauth_client_keys (client_id, kid)
  WHERE kid IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_oauth_client_keys_lookup
  ON oauth_client_keys (client_id, is_active, not_before, not_after);

-- The invariant. Two slots, no overlap permitted within a slot, therefore at
-- most two windows cover any instant. A rotation writes the replacement into
-- the OTHER slot; a third live key is a refused INSERT at rotation time, with
-- an operator looking at it, rather than a verification failure at request
-- time with nobody looking.
--
-- Deliberately ignores is_active: is_active can only subtract, so it can never
-- raise the overlap count above two. Constraining windows alone is both
-- sufficient and stable under an is_active flip.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'oauth_client_keys_two_overlapping_windows'
  ) THEN
    ALTER TABLE oauth_client_keys
      ADD CONSTRAINT oauth_client_keys_two_overlapping_windows
        EXCLUDE USING gist (
          client_id WITH =,
          slot      WITH =,
          tstzrange(not_before, not_after, '[)') WITH &&
        );
  END IF;
END
$$;

-- NOT ENFORCEABLE HERE, AND THEREFORE AN OPERATOR PROCEDURE:
-- the retirement window -- the interval between a replacement key's
-- not_before and the outgoing key's not_after -- must exceed 330 seconds
-- (300 s maximum assertion lifetime + 30 s clock skew). It is a cross-row
-- property of a rotation, so it belongs in ticket 40's rotation runbook with a
-- test, not in a constraint.

-- =============================================================================
-- 4. CLIENT ASSERTION REPLAY STORE
-- =============================================================================
-- RFC 7523 §3(7) requires the authorization server to reject a reused jti.
--
-- THE HIGHEST-WRITE TABLE IN THIS DESIGN: the MCP server introspects on every
-- single request, so every request inserts one row. A row is needed for about
-- 90 seconds (60 s assertion lifetime + 30 s skew), so the steady state is
-- negligible IF THE PURGE RUNS, and unbounded if it does not.
--
-- No foreign key to oauth_clients, deliberately. This is the hot path, the
-- rows are ephemeral, and the client_id has already been validated against a
-- key row before anything is inserted here -- so an FK would buy referential
-- tidiness on throwaway data at the cost of a lookup on every request.
CREATE TABLE IF NOT EXISTS oauth_client_assertion_jti (
  client_id  TEXT        NOT NULL,
  jti        TEXT        NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (client_id, jti)
);

CREATE INDEX IF NOT EXISTS idx_oauth_client_assertion_jti_expires
  ON oauth_client_assertion_jti (expires_at);

-- RETENTION / PURGE — THERE IS NO SCHEDULER AND NO pg_cron IN THIS PROJECT.
-- A purge that nobody invokes is not a purge. Two mechanisms, both application
-- code, following the archiveOldAlerts() precedent in
-- services/securityAlertService.js (see CT-004_create_alert_tables.sql:136-142):
--
--   1. A routine on an existing schedule.
--   2. A SAMPLED purge on the insert path -- 1-in-N inserts, not every insert.
--      The insert path is every MCP request, so an unconditional DELETE would
--      double writes on the hottest table and add lock contention to the
--      latency-critical path to reclaim rows that live 90 seconds. Bounded so a
--      backlog drains across many calls rather than one long transaction:
--
--        DELETE FROM oauth_client_assertion_jti
--         WHERE ctid IN (
--           SELECT ctid FROM oauth_client_assertion_jti
--            WHERE expires_at < now()
--            LIMIT 500
--         );
--
-- CALLER: to be wired by ticket 42 alongside the introspection endpoint.
-- This is a release gate: an introspection endpoint whose replay store grows
-- without bound is not shippable, however correct its verification is.

-- =============================================================================
-- 5. AUTHORIZATION TRANSACTIONS  (ticket 36)
-- =============================================================================
-- A login attempt in progress. The browser is redirected to the frontend
-- carrying ONLY an opaque identifier; this table stores its HASH, so a leaked
-- row does not yield a usable transaction reference.
--
-- ⚠️ NEVER store a platform bearer token in this table. The user's platform
-- token is presented to the approve endpoint and used there; it is not
-- persisted. There is no column for it and one must not be added.
CREATE TABLE IF NOT EXISTS oauth_authorization_transactions (
  id                    BIGSERIAL   PRIMARY KEY,
  transaction_hash      TEXT        NOT NULL UNIQUE,
  client_id             TEXT        NOT NULL,
  -- Frozen to the assistant kind, with the composite FK below. A plain FK to
  -- oauth_clients(client_id) would accept the MCP server's own confidential id
  -- here, and the wrong client kind would then travel all the way to grant
  -- creation before anything refused it. Reject it AT THE DOOR instead: an
  -- authorization transaction is only ever started by an assistant.
  client_type           TEXT        NOT NULL DEFAULT 'assistant_public'
                                    CHECK (client_type = 'assistant_public'),
  redirect_uri          TEXT        NOT NULL,
  resource              TEXT        NOT NULL,
  scopes                TEXT[]      NOT NULL,
  code_challenge        TEXT        NOT NULL,
  code_challenge_method TEXT        NOT NULL CHECK (code_challenge_method = 'S256'),
  state                 TEXT,
  csrf_token_hash       TEXT,
  -- Set atomically at approval, never before. Null means unbound.
  bound_user_id         BIGINT,
  consumed_at           TIMESTAMPTZ,
  decision              TEXT        CHECK (decision IN ('approved', 'denied')),
  expires_at            TIMESTAMPTZ NOT NULL,
  created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  -- A terminal decision and consumption happen together, atomically. Neither
  -- exists without the other.
  CONSTRAINT oauth_transactions_decision_implies_consumed
    CHECK ((decision IS NULL) = (consumed_at IS NULL)),

  -- An approval binds a user; a denial creates no grant and binds none.
  CONSTRAINT oauth_transactions_approved_implies_bound
    CHECK (decision IS DISTINCT FROM 'approved' OR bound_user_id IS NOT NULL),

  CONSTRAINT oauth_transactions_client_fk
    FOREIGN KEY (client_id, client_type)
    REFERENCES oauth_clients (client_id, client_type)
);

CREATE INDEX IF NOT EXISTS idx_oauth_transactions_expires
  ON oauth_authorization_transactions (expires_at);

-- =============================================================================
-- 6. MCP CLIENT GRANTS  (the authoritative connection)
-- =============================================================================
-- The thing a user disconnects. Revoking this row invalidates every MCP access
-- token and every refresh family carrying its grant_id.
--
-- grant_id is an OPAQUE uuid, not a sequence: it appears in URL paths
-- (DELETE /api/oauth/grants/:grantId) and must not be enumerable. Ownership is
-- still checked in application code on every access -- the opacity is defence
-- in depth, not the control.
--
-- Client URLs are stored as data and NEVER used as a grant key or a route
-- segment: a CIMD client_id is a URL, and percent-encoding plus embedded
-- slashes make it ambiguous to decode and possible to match the wrong record.
CREATE TABLE IF NOT EXISTS mcp_client_grants (
  grant_id      UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id       BIGINT      NOT NULL,
  client_id     TEXT        NOT NULL,
  -- Frozen to the assistant kind. With the composite FK below this makes
  -- "a service_confidential client id can never be written to a grant row" a
  -- schema fact rather than a sentence in a document.
  client_type   TEXT        NOT NULL DEFAULT 'assistant_public'
                            CHECK (client_type = 'assistant_public'),
  resource      TEXT        NOT NULL,
  scopes        TEXT[]      NOT NULL,
  status        TEXT        NOT NULL DEFAULT 'active'
                            CHECK (status IN ('active', 'revoked', 'replaced')),
  revoked_at    TIMESTAMPTZ,
  revoke_reason TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  CONSTRAINT mcp_client_grants_client_fk
    FOREIGN KEY (client_id, client_type)
    REFERENCES oauth_clients (client_id, client_type),

  CONSTRAINT mcp_client_grants_terminal_has_timestamp
    CHECK (status = 'active' OR revoked_at IS NOT NULL)
);

-- At most ONE active grant per user, client and resource. Partial, because
-- superseded and revoked rows are history and many may coexist. Disconnection
-- depends on there being exactly one thing to switch off.
CREATE UNIQUE INDEX IF NOT EXISTS mcp_client_grants_one_active
  ON mcp_client_grants (user_id, client_id, resource)
  WHERE status = 'active';

CREATE INDEX IF NOT EXISTS idx_mcp_client_grants_user
  ON mcp_client_grants (user_id, status);

-- =============================================================================
-- 7. AUTHORIZATION CODES  (ticket 39)
-- =============================================================================
-- Hashed, single use, 60-second expiry -- and the 60 seconds is enforced here
-- rather than left to the issuing code, because an expiry that is only a
-- constant in JavaScript drifts the first time someone "makes testing easier".
CREATE TABLE IF NOT EXISTS oauth_authorization_codes (
  id             BIGSERIAL   PRIMARY KEY,
  code_hash      TEXT        NOT NULL UNIQUE,
  grant_id       UUID        NOT NULL REFERENCES mcp_client_grants (grant_id),
  client_id      TEXT        NOT NULL,
  -- Same reasoning as the transactions table: frozen kind plus composite FK,
  -- so a confidential client id cannot reach a code either.
  client_type    TEXT        NOT NULL DEFAULT 'assistant_public'
                             CHECK (client_type = 'assistant_public'),
  user_id        BIGINT      NOT NULL,
  redirect_uri   TEXT        NOT NULL,
  resource       TEXT        NOT NULL,
  scopes         TEXT[]      NOT NULL,
  code_challenge TEXT        NOT NULL,
  consumed_at    TIMESTAMPTZ,
  expires_at     TIMESTAMPTZ NOT NULL,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  CONSTRAINT oauth_codes_sixty_second_expiry
    CHECK (expires_at <= created_at + INTERVAL '60 seconds'),

  CONSTRAINT oauth_codes_client_fk
    FOREIGN KEY (client_id, client_type)
    REFERENCES oauth_clients (client_id, client_type)
);

CREATE INDEX IF NOT EXISTS idx_oauth_codes_expires
  ON oauth_authorization_codes (expires_at);

-- =============================================================================
-- 8. REFRESH TOKENS  (ticket 39)
-- =============================================================================
-- Opaque, one-time, rotating. NEVER JWTs. Stored as a strong hash plus a short
-- lookup digest; the raw value exists only in the response body.
--
-- Every successful refresh is an atomic rotation: mark the presented token
-- used, insert one child in the same family, return the new pair only after
-- commit. Presenting a used, replaced or revoked token is REUSE: revoke the
-- entire family and its grant in one transaction.
--
-- The bindings below are immutable and are enforced against the PARENT row by
-- a self-referencing composite foreign key, so a child physically cannot carry
-- a different user, client, resource, family or grant than the token it
-- replaces. That is what "no cross-client or cross-resource replacement" means
-- as a schema rule rather than as a code review comment.
CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
  id             BIGSERIAL   PRIMARY KEY,
  token_hash     TEXT        NOT NULL,
  lookup_hash    TEXT        NOT NULL UNIQUE,
  grant_id       UUID        NOT NULL REFERENCES mcp_client_grants (grant_id),
  family_id      UUID        NOT NULL,
  parent_id      BIGINT,
  replaced_by_id BIGINT      REFERENCES oauth_refresh_tokens (id),
  user_id        BIGINT      NOT NULL,
  client_id      TEXT        NOT NULL,
  -- client_id had no foreign key at all, resting entirely on the grant
  -- binding. That is one indirection away from the rule it is meant to obey,
  -- so it now carries the same frozen kind and composite FK as every other
  -- table holding an assistant client id.
  client_type    TEXT        NOT NULL DEFAULT 'assistant_public'
                             CHECK (client_type = 'assistant_public'),
  resource       TEXT        NOT NULL,
  scopes         TEXT[]      NOT NULL,
  issued_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at     TIMESTAMPTZ NOT NULL,
  used_at        TIMESTAMPTZ,
  revoked_at     TIMESTAMPTZ,
  revoke_reason  TEXT,

  -- One parent: no two children may replace the same token. This is what makes
  -- a fork in a refresh family impossible rather than merely unexpected.
  CONSTRAINT oauth_refresh_tokens_one_child_per_parent UNIQUE (parent_id),
  CONSTRAINT oauth_refresh_tokens_one_replacement     UNIQUE (replaced_by_id),

  CONSTRAINT oauth_refresh_tokens_client_fk
    FOREIGN KEY (client_id, client_type)
    REFERENCES oauth_clients (client_id, client_type)
);

-- Target for the self-referencing composite FK below.
CREATE UNIQUE INDEX IF NOT EXISTS oauth_refresh_tokens_binding_key
  ON oauth_refresh_tokens (id, user_id, client_id, resource, family_id, grant_id);

-- ⚠️ DO NOT "TIDY" THIS TO MATCH FULL. It relies on MATCH SIMPLE, which is the
-- default: when ANY column of a composite foreign key is NULL, the constraint
-- is not checked. parent_id is the only nullable column in it, so a family ROOT
-- (parent_id NULL) is exempt and inserts freely, while every CHILD has all six
-- columns populated and is therefore fully bound to its parent's identity.
-- That is by construction, not by luck. MATCH FULL would require all six to be
-- non-null together and would reject every root insert -- i.e. it would break
-- the first refresh token of every grant.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'oauth_refresh_tokens_inherit_bindings'
  ) THEN
    ALTER TABLE oauth_refresh_tokens
      ADD CONSTRAINT oauth_refresh_tokens_inherit_bindings
        FOREIGN KEY (parent_id, user_id, client_id, resource, family_id, grant_id)
        REFERENCES oauth_refresh_tokens (id, user_id, client_id, resource, family_id, grant_id);
  END IF;
END
$$;

CREATE INDEX IF NOT EXISTS idx_oauth_refresh_tokens_family
  ON oauth_refresh_tokens (family_id);

CREATE INDEX IF NOT EXISTS idx_oauth_refresh_tokens_grant
  ON oauth_refresh_tokens (grant_id);

-- =============================================================================
-- 9. ROW LEVEL SECURITY — A BACKSTOP, NOT THE CONTROL
-- =============================================================================
-- ⚠️ RLS IS NOT AN AUTHORIZATION CONTROL IN THIS PROJECT. The runtime client is
-- built with SUPABASE_SERVICE_ROLE_KEY (dbConnection.js:189), which bypasses
-- RLS entirely. Application code enforces ownership before every query, and
-- that remains true for every table above.
--
-- RLS is still enabled here, with NO policies, because these tables hold
-- authorization state and hashed credentials and should be unreachable by the
-- anon and authenticated roles under any circumstance. Enabled with no policy
-- means those roles get nothing; the service role is unaffected. It costs
-- nothing and closes the direct-client exposure question for these tables.
ALTER TABLE oauth_clients                     ENABLE ROW LEVEL SECURITY;
ALTER TABLE oauth_client_keys                 ENABLE ROW LEVEL SECURITY;
ALTER TABLE oauth_client_assertion_jti        ENABLE ROW LEVEL SECURITY;
ALTER TABLE oauth_authorization_transactions  ENABLE ROW LEVEL SECURITY;
ALTER TABLE mcp_client_grants                 ENABLE ROW LEVEL SECURITY;
ALTER TABLE oauth_authorization_codes         ENABLE ROW LEVEL SECURITY;
ALTER TABLE oauth_refresh_tokens              ENABLE ROW LEVEL SECURITY;

-- Guarded: anon and authenticated always exist on Supabase, but not on a plain
-- PostgreSQL instance -- a local verification run, a staging clone. Unguarded,
-- a missing role aborts the file HERE, leaving a half-applied migration, which
-- is the scenario section 10 exists to report. Skipping the REVOKE off-Supabase
-- is correct: without those roles there is no unprivileged grantee to revoke
-- from, and RLS above is already enabled either way.
DO $$
DECLARE
  t TEXT;
  r TEXT;
BEGIN
  FOREACH r IN ARRAY ARRAY['anon', 'authenticated'] LOOP
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
      FOREACH t IN ARRAY ARRAY[
        'oauth_clients', 'oauth_client_keys', 'oauth_client_assertion_jti',
        'oauth_authorization_transactions', 'mcp_client_grants',
        'oauth_authorization_codes', 'oauth_refresh_tokens'
      ] LOOP
        EXECUTE format('REVOKE ALL ON public.%I FROM %I', t, r);
      END LOOP;
    ELSE
      RAISE NOTICE 'role % absent - skipping REVOKE (expected off Supabase)', r;
    END IF;
  END LOOP;
END
$$;

-- =============================================================================
-- 10. VERIFICATION — RUN THIS AND READ THE OUTPUT
-- =============================================================================
-- Do not enable OAuth routes until this returns a single 'PASS' row.
-- Each count is the checksum for one section above.
DO $$
DECLARE
  v_tables      INT;
  v_rls         INT;
  v_exclusions  INT;
  v_kind_fks    INT;
  v_problems    TEXT := '';
BEGIN
  SELECT count(*) INTO v_tables
    FROM information_schema.tables
   WHERE table_schema = 'public'
     AND table_name IN (
       'oauth_clients', 'oauth_client_keys', 'oauth_client_assertion_jti',
       'oauth_authorization_transactions', 'mcp_client_grants',
       'oauth_authorization_codes', 'oauth_refresh_tokens'
     );

  SELECT count(*) INTO v_rls
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
   WHERE n.nspname = 'public' AND c.relrowsecurity
     AND c.relname IN (
       'oauth_clients', 'oauth_client_keys', 'oauth_client_assertion_jti',
       'oauth_authorization_transactions', 'mcp_client_grants',
       'oauth_authorization_codes', 'oauth_refresh_tokens'
     );

  -- Scoped by conrelid. Counting by name alone across all of pg_constraint
  -- means a same-named constraint on any other table inflates the count, which
  -- turns this checksum into a false PASS -- the one failure mode a checksum
  -- must not have.
  --
  -- to_regclass(), not ::regclass. The cast RAISES on a missing relation, and
  -- these queries run before the table-count test below -- so on a PARTIALLY
  -- APPLIED migration, which is exactly what this section exists to catch and
  -- is entirely plausible when a hand-pasted script errors mid-way, the cast
  -- would report 'relation does not exist' instead of 'tables: expected 7,
  -- found 6'. to_regclass returns NULL, the IN test simply does not match, and
  -- the diagnostic below survives to say something useful.
  SELECT count(*) INTO v_exclusions
    FROM pg_constraint
   WHERE (conname, conrelid) IN (
     ('oauth_client_keys_two_overlapping_windows', to_regclass('public.oauth_client_keys')),
     ('oauth_refresh_tokens_inherit_bindings',     to_regclass('public.oauth_refresh_tokens'))
   );

  -- The client-kind split, enforced at every table that holds a client id.
  -- Grants alone is not enough: without these the authorize and consent
  -- endpoints accept the wrong client kind and fail late, at grant creation.
  SELECT count(*) INTO v_kind_fks
    FROM pg_constraint
   WHERE contype = 'f'
     AND (conname, conrelid) IN (
       ('mcp_client_grants_client_fk',    to_regclass('public.mcp_client_grants')),
       ('oauth_transactions_client_fk',   to_regclass('public.oauth_authorization_transactions')),
       ('oauth_codes_client_fk',          to_regclass('public.oauth_authorization_codes')),
       ('oauth_refresh_tokens_client_fk', to_regclass('public.oauth_refresh_tokens')),
       ('oauth_client_keys_client_fk',    to_regclass('public.oauth_client_keys'))
     );

  IF v_tables     <> 7 THEN v_problems := v_problems || format('tables: expected 7, found %s. ', v_tables); END IF;
  IF v_rls        <> 7 THEN v_problems := v_problems || format('RLS enabled: expected 7, found %s. ', v_rls); END IF;
  IF v_exclusions <> 2 THEN v_problems := v_problems || format('window/binding constraints: expected 2, found %s. ', v_exclusions); END IF;
  IF v_kind_fks   <> 5 THEN v_problems := v_problems || format('client-kind composite FKs: expected 5, found %s. ', v_kind_fks); END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'mcp_client_grants_one_active') THEN
    v_problems := v_problems || 'missing partial unique index mcp_client_grants_one_active. ';
  END IF;

  IF v_problems = '' THEN
    RAISE NOTICE 'PASS - migration 002 applied completely.';
  ELSE
    RAISE EXCEPTION 'FAIL - migration 002 incomplete: %', v_problems;
  END IF;
END
$$;

-- BEHAVIOURAL CHECKS -- each MUST be refused. If any succeeds, the constraint
-- it exercises is not doing its job: do not activate routes.
--
-- All were run 2026-09-05 against PostgreSQL 18.3 on an ephemeral cluster, and
-- all 12 distinct constraints were MUTATION-PROVED: each was dropped inside a
-- transaction, the refused insert re-run and confirmed to SUCCEED, then rolled
-- back (DDL is transactional, so the constraint restores itself). That is the
-- difference between "these tests pass" and "these tests can fail".
--
--   check                                          refused by
--   ---------------------------------------------- ---------------------------------------------
--   a  confidential client id in a grant row        mcp_client_grants_client_fk
--   b  public client with private_key_jwt           oauth_clients_auth_method_matches_type
--   c  third overlapping key window                 oauth_client_keys_two_overlapping_windows
--   c2 ...the same, FUTURE-DATED                    oauth_client_keys_two_overlapping_windows
--   d  second active grant, same user+client+res    mcp_client_grants_one_active
--   e  authorization code with a 90-second expiry   oauth_codes_sixty_second_expiry
--   f  http:// client id                            oauth_clients_id_is_https
--   g  confidential id into a transaction           oauth_transactions_client_fk
--   h  confidential id into a code                  oauth_codes_client_fk
--   i  confidential id on a refresh token           oauth_refresh_tokens_client_fk
--   j  'https://' with no host at all               oauth_clients_id_is_https
--   k  confidential id, bare origin, no path        oauth_clients_confidential_id_has_path
--   l  confidential id, lone '/' path               oauth_clients_confidential_id_has_path
--   m  cross-CLIENT replacement                     oauth_refresh_tokens_inherit_bindings
--   n  cross-RESOURCE replacement                   oauth_refresh_tokens_inherit_bindings
--   o  forked family: two children, one parent      oauth_refresh_tokens_one_child_per_parent
--
-- Positive controls also ran and MUST succeed: a legitimate rotation inserts, a
-- family root inserts, and a new active grant is permitted once the prior one
-- is revoked.
--
-- Notes on three of these, each recording a mistake already made once:
--
--   c2 is not a duplicate of c. A count of active rows admits a third key dated
--   in the future; its window then opens and the verifier, capped at two, stops
--   verifying assertions signed by it. That is why the bound is on overlapping
--   windows and not on a row count.
--
--   g, h and i exist because the client-kind split was originally enforced only
--   at mcp_client_grants, so the wrong client kind was accepted at the
--   authorize and consent endpoints and refused late, at grant creation. Plain
--   single-column foreign keys are not sufficient here.
--
--   m must use a SECOND ASSISTANT client, not the confidential one. Written the
--   obvious way it is refused by oauth_refresh_tokens_client_fk before
--   oauth_refresh_tokens_inherit_bindings is ever consulted, so dropping the
--   binding constraint leaves it refused and the check passes for the wrong
--   reason forever. Isolate the constraint under test: two constraints covering
--   one insert is defence in depth in production and a false negative in a
--   suite.
--
-- Supabase runs an earlier major version than 18. Nothing here is
-- version-sensitive -- btree_gist, tstzrange, EXCLUDE, partial unique indexes
-- and gen_random_uuid() are long-standing -- but section 10 is the authority on
-- the target database. Run it there and read the output rather than trusting
-- this note.

-- =============================================================================
-- 11. BACKOUT  (commented out — read before you need it)
-- =============================================================================
-- Drop order is reverse dependency order. This destroys every grant, code and
-- refresh token: every connected assistant is disconnected and every user must
-- reconnect. btree_gist is deliberately NOT dropped -- other work may adopt it,
-- and dropping an extension another migration depends on is a worse outage
-- than leaving one enabled.
--
-- DROP TABLE IF EXISTS oauth_refresh_tokens;
-- DROP TABLE IF EXISTS oauth_authorization_codes;
-- DROP TABLE IF EXISTS oauth_authorization_transactions;
-- DROP TABLE IF EXISTS mcp_client_grants;
-- DROP TABLE IF EXISTS oauth_client_assertion_jti;
-- DROP TABLE IF EXISTS oauth_client_keys;
-- DROP TABLE IF EXISTS oauth_clients;
