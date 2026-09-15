const jwt = require('jsonwebtoken');

const asVerificationKeys = require('./asVerificationKeys');
const oauthConfig = require('./oauthConfig');

/**
 * Verifies the MCP access token in the introspection `token` parameter.
 *
 * Algorithm is pinned from the profile (RS256), never from the token header.
 *
 *   {ok: true,  claims}                verified
 *   {ok: false, reason: 'invalid'}     verified-not-valid → active:false
 *   {ok: false, reason: 'unavailable'} could not check → 503, never false
 *
 * Collapsing unavailable into invalid reports the whole platform as revoked
 * when a deploy misses a key env var.
 */

const MCP_ACCESS_TOKEN_ALGORITHM = 'RS256';
const CLOCK_LEEWAY_SECONDS = 30;

const REQUIRED_STRING_CLAIMS = ['grant_id', 'sub', 'client_id', 'jti'];

/**
 * jsonwebtoken only checks `exp` when present — a signed token without `exp`
 * verifies and would stay active forever. Require finite iat/exp separately:
 * putting them on the string list would reject every legitimate numeric claim.
 */
const REQUIRED_NUMERIC_CLAIMS = ['iat', 'exp'];

const isNonEmptyString = (value) => typeof value === 'string' && value.trim() !== '';

const verifyMcpAccessToken = (tokenValue, deps = {}) => {
  const keys = (deps.asVerificationKeys || asVerificationKeys).getVerificationKeys();
  const config = deps.oauthConfig || oauthConfig;

  const issuer = config.mcpAccessTokenIssuer();
  const audience = config.mcpResourceIdentifier();

  if (keys.length === 0 || !issuer || !audience) {
    return {
      ok: false,
      reason: 'unavailable',
      detail: 'mcp_access_token_verification_unconfigured',
    };
  }

  if (!isNonEmptyString(tokenValue)) {
    return { ok: false, reason: 'invalid', detail: 'token_absent' };
  }

  // Header decode selects kid only — never the algorithm.
  let headerKid = null;
  try {
    const decoded = jwt.decode(tokenValue, { complete: true });
    headerKid = decoded && decoded.header ? decoded.header.kid || null : null;
  } catch (err) {
    return { ok: false, reason: 'invalid', detail: 'token_undecodable' };
  }

  const candidates = headerKid ? keys.filter((key) => key.kid === headerKid) : keys;
  if (candidates.length === 0) {
    // No applicable key → unavailable, not invalid. Mis-set KEY_ID or a
    // rotation window must not mass-disconnect users via cached active:false.
    return { ok: false, reason: 'unavailable', detail: 'no_key_for_kid' };
  }

  let claims = null;
  for (const key of candidates) {
    try {
      claims = jwt.verify(tokenValue, key.publicKeyPem, {
        algorithms: [MCP_ACCESS_TOKEN_ALGORITHM],
        issuer,
        audience,
        clockTolerance: CLOCK_LEEWAY_SECONDS,
      });
      break;
    } catch (err) {
      claims = null;
    }
  }

  if (!claims) {
    return { ok: false, reason: 'invalid', detail: 'signature_or_claims_rejected' };
  }

  if (claims.type !== 'mcp_access') {
    return { ok: false, reason: 'invalid', detail: 'wrong_token_profile' };
  }

  const missing = [
    ...REQUIRED_STRING_CLAIMS.filter((claim) => !isNonEmptyString(claims[claim])),
    ...REQUIRED_NUMERIC_CLAIMS.filter((claim) => !Number.isFinite(claims[claim])),
  ];
  if (missing.length > 0) {
    return { ok: false, reason: 'invalid', detail: `missing_claims:${missing.join(',')}` };
  }

  // Missing scope is a diagnostic, not a refusal: requiring it would yield
  // active:false (looks like revocation). Empty string is a valid zero-scope grant.
  const notices =
    claims.scope === undefined || claims.scope === null ? ['token_missing_scope_claim'] : [];

  return { ok: true, claims, notices };
};

module.exports = {
  verifyMcpAccessToken,
  MCP_ACCESS_TOKEN_ALGORITHM,
  CLOCK_LEEWAY_SECONDS,
};
