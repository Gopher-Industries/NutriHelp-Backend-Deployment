const crypto = require('crypto');

const supabase = require('../../dbConnection');

/**
 * Opaque rotating refresh tokens (ticket 39b).
 *
 * Raw token is 256-bit CSPRNG, response-only. Two domain-separated SHA-256
 * digests: lookup_hash (indexed find) and token_hash (constant-time verify).
 * Plain SHA-256 is correct here (full entropy, not a password).
 *
 * ⚠️ No multi-statement txn over PostgREST — ordered idempotent writes;
 * safety-critical write first (claim before child; grant revoke before sweep).
 *
 * Ticket 88: a failed write can strand a claim (used_at / consumed_at set, no
 * token issued), and the compensating write usually fails in the same outage.
 * So a retry that finds a stranded claim older than RETRY_LEASE_MS takes it
 * over (compare-and-set on the exact timestamp) instead of reading it as theft.
 *
 * RESIDUALS. The complete fix is one atomic Postgres function per grant type
 * (precedent: migration 004's approve_oauth_authorization); needs a migration.
 *   - Code path has NO fork backstop: a redemption hung past the lease whose
 *     root lands after a takeover's sweep leaves two live roots in one family.
 *     ACCEPTED; ticket 89 adds a partial unique index UNIQUE (family_id) WHERE
 *     parent_id IS NULL: the late root insert fails 23505, the probe finds the
 *     winner's root, nothing is released, 503. Needs a migration; gated before
 *     the OAuth routes are enabled.
 *   - Deploy window: codes consumed <= 60 s before deploy have random family
 *     ids, so an authentic replay of one takes over instead of revoking.
 *   - Ambiguous commit (insert commits, reports failure): the probe finds it,
 *     nothing is released, and the retry revokes. Fail-safe, on both paths.
 *   - In-lease signal loss: a thief presenting a used token inside the lease,
 *     before its child lands, gets 503 instead of a revoke; caught on the next
 *     presentation once the child and replaced_by_id exist.
 */

const REFRESH_TOKEN_BYTES = 32;
const REFRESH_TOKEN_LIFETIME_SECONDS = 30 * 24 * 60 * 60;

const LOOKUP_DOMAIN = 'nutrihelp.oauth.refresh.lookup:';
const VERIFY_DOMAIN = 'nutrihelp.oauth.refresh.verify:';

const UNIQUE_VIOLATION = '23505';

// A claim younger than this may belong to a rotation or redemption still in
// flight: 503, never revoke, never take over. Without a lease, a client's
// double-send would take over its own in-flight claim, fork, and revoke.
// Inserts take well under 1 s. For refresh, a hang past the lease falls back
// to UNIQUE(parent_id), which catches the fork; the code path has no such
// backstop (header). App clocks on both sides, so instance skew shifts it.
const RETRY_LEASE_MS = 10 * 1000;

const REUSE_REVOKE_REASON = 'refresh_reuse_detected';
const RECONSENT_REVOKE_REASON = 'superseded_by_reconsent';
const CODE_REPLAY_REVOKE_REASON = 'authorization_code_replayed';

const sha256Hex = (value) => crypto.createHash('sha256').update(value).digest('hex');

const lookupHash = (rawToken) => sha256Hex(LOOKUP_DOMAIN + rawToken);
const tokenHash = (rawToken) => sha256Hex(VERIFY_DOMAIN + rawToken);

const mintRawToken = () => crypto.randomBytes(REFRESH_TOKEN_BYTES).toString('hex');

/** Constant-time compare of two hex digests of equal length. */
const digestsMatch = (left, right) => {
  if (typeof left !== 'string' || typeof right !== 'string') return false;
  if (left.length !== right.length) return false;
  return crypto.timingSafeEqual(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
};

/** Fail closed: missing/unparseable expires_at → expired. */
const isExpired = (row, now = new Date()) => {
  if (!row.expires_at) return true;
  const expiry = new Date(row.expires_at).getTime();
  if (Number.isNaN(expiry)) return true;
  return expiry <= now.getTime();
};

/** Unparseable or future timestamps count as in flight: no takeover, no revoke. */
const isWithinLease = (claimedAt, now = Date.now()) => {
  const at = new Date(claimedAt).getTime();
  if (Number.isNaN(at)) return true;
  return now - at < RETRY_LEASE_MS;
};

const failed = (detail) => ({ ok: false, detail });

/** Find by lookup_hash; prove possession via token_hash. */
const findPresentedToken = async (rawToken, deps = {}) => {
  const db = deps.supabase || supabase;

  let row;
  try {
    const { data, error } = await db
      .from('oauth_refresh_tokens')
      .select(
        'id, token_hash, lookup_hash, grant_id, family_id, parent_id, replaced_by_id, ' +
          'user_id, client_id, resource, scopes, expires_at, used_at, revoked_at'
      )
      .eq('lookup_hash', lookupHash(rawToken))
      .maybeSingle();

    if (error) return failed('refresh_lookup_failed');
    row = data;
  } catch (err) {
    return failed('refresh_lookup_failed');
  }

  if (!row) return { ok: true, row: null };

  if (!digestsMatch(row.token_hash, tokenHash(rawToken))) {
    return { ok: true, row: null };
  }

  return { ok: true, row };
};

/**
 * Insert one refresh token. parent null opens a new family.
 * Child bindings must match parent (composite FK oauth_refresh_tokens_inherit_bindings).
 */
const insertRefreshToken = async (bindings, deps = {}) => {
  const db = deps.supabase || supabase;
  const rawToken = mintRawToken();

  const row = {
    token_hash: tokenHash(rawToken),
    lookup_hash: lookupHash(rawToken),
    grant_id: bindings.grantId,
    family_id: bindings.familyId,
    parent_id: bindings.parentId === undefined ? null : bindings.parentId,
    user_id: bindings.userId,
    client_id: bindings.clientId,
    resource: bindings.resource,
    scopes: bindings.scopes,
    issued_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + REFRESH_TOKEN_LIFETIME_SECONDS * 1000).toISOString(),
  };

  try {
    const { data, error } = await db.from('oauth_refresh_tokens').insert(row).select('id').single();

    if (error) {
      // 23505 + parent → one-child-per-parent fork. 23505 + root → lookup_hash collision.
      const detail =
        error.code === UNIQUE_VIOLATION
          ? row.parent_id === null
            ? 'refresh_lookup_hash_collision'
            : 'refresh_family_already_forked'
          : 'refresh_insert_failed';
      return failed(detail);
    }

    return { ok: true, id: data.id, rawToken, expiresAt: row.expires_at };
  } catch (err) {
    return failed('refresh_insert_failed');
  }
};

/**
 * Set used_at while NULL — or, with expectedUsedAt, take over a stranded claim
 * while used_at still holds exactly that value and nothing replaced or revoked
 * the row. claimed:false → concurrent presentation. claimedAt is the value
 * written, for a conditional release.
 */
const claimRefreshToken = async (tokenId, deps = {}, expectedUsedAt = null) => {
  const db = deps.supabase || supabase;
  const claimedAt = new Date().toISOString();

  try {
    let query = db.from('oauth_refresh_tokens').update({ used_at: claimedAt }).eq('id', tokenId);
    query =
      expectedUsedAt === null
        ? query.is('used_at', null)
        : query.eq('used_at', expectedUsedAt).is('replaced_by_id', null).is('revoked_at', null);
    const { data, error } = await query.select('id');

    if (error) return failed('refresh_claim_failed');
    return { ok: true, claimed: Array.isArray(data) && data.length === 1, claimedAt };
  } catch (err) {
    return failed('refresh_claim_failed');
  }
};

/** Child of a claimed parent, if one landed. */
const findChildOf = async (parentId, deps = {}) => {
  const db = deps.supabase || supabase;

  try {
    const { data, error } = await db
      .from('oauth_refresh_tokens')
      .select('id, parent_id')
      .eq('parent_id', parentId)
      .maybeSingle();

    if (error) return failed('refresh_child_probe_failed');
    return { ok: true, child: data || null };
  } catch (err) {
    return failed('refresh_child_probe_failed');
  }
};

/**
 * Compensate claim after a reported failed child insert — only if no child exists.
 *
 * ⚠️ A failed insert does not prove absence (timeout after commit). Blind
 * release resurrects a parent that already has a child → retry hits UNIQUE →
 * false theft revoke. Probe unconditionally; do not trust error shape.
 * If a child is found, link it; caller still fails (raw token unrecoverable).
 * Conditional on claimedAt, so it can only undo this request's own claim. Best
 * effort: if it fails, the retry recovers the stranded claim after the lease.
 */
const releaseClaimIfNoChild = async (tokenId, deps = {}, claimedAt) => {
  const db = deps.supabase || supabase;

  const probe = await findChildOf(tokenId, deps);
  if (!probe.ok) return { ok: false, released: false, detail: probe.detail };

  if (probe.child) {
    await linkReplacementInternal(db, tokenId, probe.child.id);
    return { ok: true, released: false, childFound: true };
  }

  try {
    const { error } = await db
      .from('oauth_refresh_tokens')
      .update({ used_at: null })
      .eq('id', tokenId)
      .eq('used_at', claimedAt);

    if (error) return { ok: false, released: false, detail: 'refresh_claim_release_failed' };
    return { ok: true, released: true };
  } catch (err) {
    return { ok: false, released: false, detail: 'refresh_claim_release_failed' };
  }
};

const linkReplacementInternal = async (db, parentId, childId) => {
  try {
    const { error } = await db
      .from('oauth_refresh_tokens')
      .update({ replaced_by_id: childId })
      .eq('id', parentId);
    return error ? { ok: false } : { ok: true };
  } catch (err) {
    return { ok: false };
  }
};

/**
 * Whether a family's root (parent_id NULL) exists, i.e. whether tokens were
 * issued. Callers treat ok:false as 503, never as "not found": that would
 * take over a code whose tokens may already exist and issue a second set.
 */
const findFamilyRoot = async (familyId, deps = {}) => {
  const db = deps.supabase || supabase;

  try {
    // Array, not maybeSingle: a second root must read as "found", not as an error.
    const { data, error } = await db
      .from('oauth_refresh_tokens')
      .select('id')
      .eq('family_id', familyId)
      .is('parent_id', null);

    if (error) return failed('refresh_root_probe_failed');
    return { ok: true, found: Array.isArray(data) && data.length > 0 };
  } catch (err) {
    return failed('refresh_root_probe_failed');
  }
};

/** Link claimed parent → child. Cleanup only. */
const linkReplacement = async (parentId, childId, deps = {}) => {
  const db = deps.supabase || supabase;
  const result = await linkReplacementInternal(db, parentId, childId);
  return result.ok ? { ok: true } : failed('refresh_link_failed');
};

/**
 * Revoke live refresh tokens under a grant; leave the grant active (re-consent).
 * Distinct from revokeGrantAndAllFamilies — housekeeping, not a security revoke.
 */
const revokePriorFamilies = async (grantId, deps = {}) => {
  const db = deps.supabase || supabase;

  try {
    const { error } = await db
      .from('oauth_refresh_tokens')
      .update({ revoked_at: new Date().toISOString(), revoke_reason: RECONSENT_REVOKE_REASON })
      .eq('grant_id', grantId)
      .is('revoked_at', null);

    if (error) return failed('prior_family_revoke_failed');
    return { ok: true };
  } catch (err) {
    return failed('prior_family_revoke_failed');
  }
};

/** Revoke grant first, then one family. */
const revokeFamilyAndGrant = async (familyId, grantId, reason, deps = {}) => {
  const db = deps.supabase || supabase;
  const nowIso = new Date().toISOString();

  try {
    const { error } = await db
      .from('mcp_client_grants')
      .update({ status: 'revoked', revoked_at: nowIso, revoke_reason: reason })
      .eq('grant_id', grantId);

    if (error) return failed('grant_revoke_failed');
  } catch (err) {
    return failed('grant_revoke_failed');
  }

  try {
    const { error } = await db
      .from('oauth_refresh_tokens')
      .update({ revoked_at: nowIso, revoke_reason: reason })
      .eq('family_id', familyId)
      .is('revoked_at', null);

    if (error) return failed('refresh_revoke_failed');
  } catch (err) {
    return failed('refresh_revoke_failed');
  }

  return { ok: true };
};

/** Code replay: revoke grant, then all its refresh tokens. */
const revokeGrantAndAllFamilies = async (grantId, reason, deps = {}) => {
  const db = deps.supabase || supabase;
  const nowIso = new Date().toISOString();

  try {
    const { error } = await db
      .from('mcp_client_grants')
      .update({ status: 'revoked', revoked_at: nowIso, revoke_reason: reason })
      .eq('grant_id', grantId);

    if (error) return failed('grant_revoke_failed');
  } catch (err) {
    return failed('grant_revoke_failed');
  }

  try {
    const { error } = await db
      .from('oauth_refresh_tokens')
      .update({ revoked_at: nowIso, revoke_reason: reason })
      .eq('grant_id', grantId)
      .is('revoked_at', null);

    if (error) return failed('refresh_revoke_failed');
  } catch (err) {
    return failed('refresh_revoke_failed');
  }

  return { ok: true };
};

module.exports = {
  findPresentedToken,
  insertRefreshToken,
  claimRefreshToken,
  releaseClaimIfNoChild,
  findChildOf,
  findFamilyRoot,
  revokePriorFamilies,
  linkReplacement,
  revokeFamilyAndGrant,
  revokeGrantAndAllFamilies,
  isExpired,
  isWithinLease,
  lookupHash,
  tokenHash,
  REFRESH_TOKEN_LIFETIME_SECONDS,
  RETRY_LEASE_MS,
  REUSE_REVOKE_REASON,
  RECONSENT_REVOKE_REASON,
  CODE_REPLAY_REVOKE_REASON,
};
