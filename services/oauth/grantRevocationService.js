const supabase = require('../../dbConnection');

/**
 * User-initiated disconnection: revoke one grant and everything carrying it.
 *
 * Cascade is application code, not schema. Mig 002:312 promises grant revoke
 * invalidates refresh families, but oauth_refresh_tokens.grant_id is plain
 * REFERENCES with no status cascade — flip the grant alone and live refresh
 * tokens survive.
 *
 * No multi-statement transaction via PostgREST. Two idempotent writes; order
 * is the safety: GRANT FIRST (introspection reads status every MCP request),
 * then refresh sweep as cleanup.
 *
 * Ticket 39 must refuse refresh when grant status ≠ 'active'. With that check,
 * orphaned refresh rows are inert and this sweep is hygiene. Without it, a
 * failed sweep is the only thing between revoke and a new access token.
 */

const GRANT_STATUS_ACTIVE = 'active';
const REVOKE_REASON = 'user_disconnect';

const notFound = () => ({ outcome: 'not_found' });
const failed = (detail) => ({ outcome: 'failed', detail });

/**
 * @returns {Promise<
 *   {outcome:'revoked', grant: object, alreadyRevoked: boolean} |
 *   {outcome:'not_found'} |
 *   {outcome:'failed', detail: string}
 * >}
 */
const revokeGrantForUser = async (grantId, userId, deps = {}) => {
  const db = deps.supabase || supabase;
  const nowIso = new Date().toISOString();

  // Filter IS the ownership check — no fetch-then-compare branch to forget.
  let grant;
  try {
    const { data, error } = await db
      .from('mcp_client_grants')
      .select('grant_id, user_id, client_id, resource, status')
      .eq('grant_id', grantId)
      .eq('user_id', userId)
      .maybeSingle();

    if (error) return failed('grant_lookup_failed');
    grant = data;
  } catch (err) {
    return failed('grant_lookup_failed');
  }

  if (!grant) return notFound();

  const alreadyRevoked = grant.status !== GRANT_STATUS_ACTIVE;

  // Skip when terminal so retries do not re-stamp revoked_at.
  if (!alreadyRevoked) {
    try {
      const { error } = await db
        .from('mcp_client_grants')
        .update({
          status: 'revoked',
          // terminal_has_timestamp CHECK requires revoked_at when non-active.
          revoked_at: nowIso,
          revoke_reason: REVOKE_REASON,
        })
        .eq('grant_id', grantId)
        .eq('user_id', userId);

      if (error) return failed('grant_revoke_failed');
    } catch (err) {
      return failed('grant_revoke_failed');
    }
  }

  // Always sweep — even if already revoked — so a prior failed sweep heals.
  try {
    const { error } = await db
      .from('oauth_refresh_tokens')
      .update({ revoked_at: nowIso, revoke_reason: REVOKE_REASON })
      .eq('grant_id', grantId)
      .eq('user_id', userId)
      .is('revoked_at', null);

    if (error) return failed('refresh_revoke_failed');
  } catch (err) {
    return failed('refresh_revoke_failed');
  }

  return { outcome: 'revoked', grant, alreadyRevoked };
};

module.exports = { revokeGrantForUser, REVOKE_REASON };
