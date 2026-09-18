const supabase = require('../../dbConnection');
const mcpAccessTokenVerifier = require('./mcpAccessTokenVerifier');

/**
 * RFC 7662 introspection over an MCP access token.
 *
 * active:false means verified and genuinely inactive only. A failed check is
 * `unavailable` → 503. Never caches positives.
 */

const GRANT_STATUS_ACTIVE = 'active';

const isNonEmptyString = (value) => typeof value === 'string' && value.trim() !== '';

/** RFC 6749 space-delimited scope. Absent means no scopes — never "all". */
const parseScope = (scope) => {
  if (Array.isArray(scope)) return scope.filter(isNonEmptyString);
  if (!isNonEmptyString(scope)) return [];
  return scope.trim().split(/\s+/).filter(Boolean);
};

/** Intersection of token scopes and current grant scopes — never widens. */
const intersectScopes = (tokenScopes, grantScopes) => {
  const granted = new Set(grantScopes);
  return tokenScopes.filter((scope) => granted.has(scope));
};

// notices travel with the answer and never alter it.
const inactive = (detail, userId = null, notices = []) => ({
  outcome: 'inactive',
  detail,
  userId,
  notices,
});
const unavailable = (detail) => ({ outcome: 'unavailable', detail, notices: [] });

/**
 * @returns {Promise<
 *   {outcome: 'active', body: object, grant: object} |
 *   {outcome: 'inactive', detail: string} |
 *   {outcome: 'unavailable', detail: string}
 * >}
 */
const introspect = async (tokenValue, deps = {}) => {
  const db = deps.supabase || supabase;
  const verifier = deps.mcpAccessTokenVerifier || mcpAccessTokenVerifier;

  const verification = verifier.verifyMcpAccessToken(tokenValue, deps);

  if (!verification.ok) {
    return verification.reason === 'unavailable'
      ? unavailable(verification.detail)
      : inactive(verification.detail);
  }

  const { claims } = verification;
  const notices = verification.notices || [];

  let grant;
  try {
    const { data, error } = await db
      .from('mcp_client_grants')
      .select('grant_id, user_id, client_id, resource, scopes, status')
      .eq('grant_id', claims.grant_id)
      .maybeSingle();

    if (error) return unavailable('grant_lookup_failed');
    grant = data;
  } catch (err) {
    return unavailable('grant_lookup_failed');
  }

  if (!grant) return inactive('grant_not_found', null, notices);
  if (grant.status !== GRANT_STATUS_ACTIVE) {
    return inactive(`grant_status:${grant.status}`, grant.user_id, notices);
  }

  // Signature proves issuance; these prove the token still describes this grant.
  const grantSubject = String(grant.user_id);
  if (claims.sub !== grantSubject) {
    return inactive('token_grant_subject_mismatch', grant.user_id, notices);
  }
  if (claims.client_id !== grant.client_id) {
    return inactive('token_grant_client_mismatch', grant.user_id, notices);
  }
  // Match this grant's resource (jwt.verify audience accepts any array element).
  if (claims.aud !== grant.resource) {
    return inactive('token_grant_resource_mismatch', grant.user_id, notices);
  }

  const scopes = intersectScopes(parseScope(claims.scope), parseScope(grant.scopes));

  return {
    outcome: 'active',
    grant,
    notices,
    body: {
      // Real JSON boolean — string/1/missing are treated as unestablished by MCP.
      active: true,
      grant_id: grant.grant_id,
      sub: grantSubject,
      client_id: grant.client_id,
      scope: scopes.join(' '),
      // Echo ACCESS TOKEN claims, not this endpoint's identifiers.
      aud: claims.aud,
      iss: claims.iss,
      exp: claims.exp,
      iat: claims.iat,
      jti: claims.jti,
    },
  };
};

module.exports = { introspect, intersectScopes, parseScope };
