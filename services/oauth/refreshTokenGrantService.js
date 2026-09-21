const supabase = require('../../dbConnection');
const introspectionService = require('./introspectionService');
const mcpAccessTokenIssuer = require('./mcpAccessTokenIssuer');
const refreshTokenStore = require('./refreshTokenStore');

/**
 * grant_type=refresh_token — rotating, one-time; reuse kills the family (39b).
 *
 *   {outcome:'issued', ...} | {outcome:'refused', error, detail} |
 *   {outcome:'unavailable', detail}
 *
 * Successful refresh consumes the presented token and returns one child.
 * Reuse (revoked, replaced, or used with a child) revokes the family and grant —
 * intentional. Used with no child is a claim in flight or stranded (ticket 88).
 *
 * ⚠️ Expiry is not reuse: refuse only, do not sweep.
 * Grant-status guard required (see grantRevocationService).
 */

const GRANT_STATUS_ACTIVE = 'active';

const refuse = (error, detail) => ({ outcome: 'refused', error, detail });
const unavailable = (detail) => ({ outcome: 'unavailable', detail });

const isNonEmptyString = (value) => typeof value === 'string' && value.trim() !== '';

const rotateRefreshToken = async (body, deps = {}) => {
  const db = deps.supabase || supabase;
  const store = deps.refreshTokenStore || refreshTokenStore;
  const issuer = deps.mcpAccessTokenIssuer || mcpAccessTokenIssuer;
  const scopes = deps.introspectionService || introspectionService;

  const presented = body.refresh_token;
  const clientId = body.client_id;

  if (!isNonEmptyString(presented)) return refuse('invalid_request', 'refresh_token_absent');

  // Required (same as code grant). Opt-out "if present" is skipped by omitting
  // it, or by repeating it (urlencoded → Array, not a string).
  if (!isNonEmptyString(clientId)) return refuse('invalid_request', 'client_id_absent');

  const found = await store.findPresentedToken(presented, deps);
  if (!found.ok) return unavailable(found.detail);
  if (!found.row) return refuse('invalid_grant', 'refresh_token_not_found');

  const row = found.row;

  if (row.client_id !== clientId) {
    return refuse('invalid_grant', 'refresh_client_mismatch');
  }

  const reuse = async () => {
    const swept = await store.revokeFamilyAndGrant(
      row.family_id,
      row.grant_id,
      store.REUSE_REVOKE_REASON,
      deps
    );
    // Failed sweep → 503, not invalid_grant (stolen family may still be live).
    if (!swept.ok) return unavailable(swept.detail);
    return refuse('invalid_grant', 'refresh_reuse_detected');
  };

  // revoked_at counts on its own: a family sweep never sets used_at.
  if (row.revoked_at || row.replaced_by_id) return reuse();

  // Ticket 88: used_at alone is a rotation in flight or a claim stranded by a
  // failed insert whose release also failed. Only a child proves reuse.
  let strandedUsedAt = null;
  if (row.used_at) {
    const probe = await store.findChildOf(row.id, deps);
    if (!probe.ok) return unavailable(probe.detail);
    if (probe.child) {
      await store.linkReplacement(row.id, probe.child.id, deps);
      return reuse();
    }
    if (store.isWithinLease(row.used_at)) return unavailable('refresh_rotation_in_flight');
    strandedUsedAt = row.used_at;
  }

  if (store.isExpired(row)) return refuse('invalid_grant', 'refresh_token_expired');

  let grant;
  try {
    const { data, error } = await db
      .from('mcp_client_grants')
      .select('grant_id, user_id, client_id, resource, scopes, status')
      .eq('grant_id', row.grant_id)
      .maybeSingle();

    if (error) return unavailable('grant_lookup_failed');
    grant = data;
  } catch (err) {
    return unavailable('grant_lookup_failed');
  }

  if (!grant) return refuse('invalid_grant', 'grant_not_found');
  if (grant.status !== GRANT_STATUS_ACTIVE) {
    return refuse('invalid_grant', `grant_status:${grant.status}`);
  }

  if (
    String(grant.user_id) !== String(row.user_id) ||
    grant.client_id !== row.client_id ||
    grant.resource !== row.resource
  ) {
    return refuse('invalid_grant', 'grant_token_binding_mismatch');
  }

  // May narrow; never widen. Parent scopes ∩ grant scopes.
  const available = scopes.intersectScopes(
    scopes.parseScope(row.scopes),
    scopes.parseScope(grant.scopes)
  );

  // ⚠️ parseScope, not isNonEmptyString — repeated scope= becomes an Array.
  const requested = scopes.parseScope(body.scope);

  let granted = available;
  if (requested.length > 0) {
    const widened = requested.filter((scope) => !available.includes(scope));
    if (widened.length > 0) return refuse('invalid_scope', 'requested_scope_exceeds_token');
    granted = requested;
  }

  // Mint before any DB write — signing can fail alone; mint-after-claim would
  // strand used_at and turn a config blip into reuse-on-retry disconnect.
  const minted = issuer.issueMcpAccessToken(
    {
      userId: row.user_id,
      clientId: row.client_id,
      grantId: row.grant_id,
      resource: row.resource,
      scope: granted.join(' '),
    },
    deps
  );

  if (!minted.ok) return unavailable(minted.detail);

  // Claim before replacement, or take over the stranded claim (CAS on its exact
  // used_at). Zero rows: a concurrent presenter, so reuse — unlike the code path.
  const claim = await store.claimRefreshToken(row.id, deps, strandedUsedAt);
  if (!claim.ok) return unavailable(claim.detail);
  if (!claim.claimed) return reuse();

  const child = await store.insertRefreshToken(
    {
      grantId: row.grant_id,
      familyId: row.family_id,
      parentId: row.id,
      userId: row.user_id,
      clientId: row.client_id,
      resource: row.resource,
      scopes: granted,
    },
    deps
  );

  if (!child.ok) {
    // UNIQUE(parent_id) → family already forked.
    if (child.detail === 'refresh_family_already_forked') return reuse();

    // Ordinary outage: release only after proving no child landed; if that
    // fails too, the retry takes the stranded claim over after the lease.
    await store.releaseClaimIfNoChild(row.id, deps, claim.claimedAt);
    return unavailable(child.detail);
  }

  await store.linkReplacement(row.id, child.id, deps);

  return {
    outcome: 'issued',
    accessToken: minted.accessToken,
    expiresIn: minted.expiresIn,
    scope: granted.join(' '),
    refreshToken: child.rawToken,
  };
};

module.exports = { rotateRefreshToken };
