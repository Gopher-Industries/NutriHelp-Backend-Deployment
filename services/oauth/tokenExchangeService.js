const oauthConfig = require('./oauthConfig');
const introspectionService = require('./introspectionService');
const mcpAccessTokenVerifier = require('./mcpAccessTokenVerifier');
const exchangeRoleResolver = require('./exchangeRoleResolver');
const upstreamCredentialIssuer = require('./upstreamCredentialIssuer');

/**
 * RFC 8693 token exchange (ticket 39a).
 *
 * Subject token = MCP access token, verified by this AS (not passthrough).
 * Errors: RFC 6749 §5.2 + invalid_target. Never insufficient_scope/403.
 *
 *   {outcome: 'issued', ...} | {outcome: 'refused', ...} | {outcome: 'unavailable', detail}
 *
 * subjectTokenVerified drives the anomaly log (our key verified, still refused).
 */

const ACCESS_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token';
const GRANT_TYPE_TOKEN_EXCHANGE = 'urn:ietf:params:oauth:grant-type:token-exchange';

const isNonEmptyString = (value) => typeof value === 'string' && value.trim() !== '';

const refuse = (error, detail, extra = {}) => ({
  outcome: 'refused',
  error,
  detail,
  subjectTokenVerified: false,
  userId: null,
  ...extra,
});

const unavailable = (detail) => ({ outcome: 'unavailable', detail });

/**
 * @param {object} params  parsed form body — attacker-controlled
 */
const exchange = async (params = {}, deps = {}) => {
  const config = deps.oauthConfig || oauthConfig;
  const introspection = deps.introspectionService || introspectionService;
  const baseVerifier = deps.mcpAccessTokenVerifier || mcpAccessTokenVerifier;
  const roleResolver = deps.exchangeRoleResolver || exchangeRoleResolver;
  const issuer = deps.upstreamCredentialIssuer || upstreamCredentialIssuer;

  const subjectToken = params.subject_token;
  if (!isNonEmptyString(subjectToken)) {
    return refuse('invalid_request', 'subject_token_absent');
  }
  if (params.subject_token_type !== ACCESS_TOKEN_TYPE) {
    return refuse('invalid_request', 'subject_token_type_unsupported');
  }
  if (
    params.requested_token_type !== undefined &&
    params.requested_token_type !== ACCESS_TOKEN_TYPE
  ) {
    return refuse('invalid_request', 'requested_token_type_unsupported');
  }

  const backendAudience = config.backendApiAudience();
  if (!backendAudience) return unavailable('backend_api_audience_unconfigured');

  for (const field of ['resource', 'audience']) {
    const requested = params[field];
    if (requested !== undefined && requested !== backendAudience) {
      return refuse('invalid_target', `${field}_not_issuable`);
    }
  }

  // Reuse introspection for verify + live grant + scope intersect.
  let subjectTokenVerified = false;
  const recordingVerifier = {
    verifyMcpAccessToken: (tokenValue, verifierDeps) => {
      const verification = baseVerifier.verifyMcpAccessToken(tokenValue, verifierDeps);
      if (verification.ok) subjectTokenVerified = true;
      return verification;
    },
  };

  const result = await introspection.introspect(subjectToken, {
    ...deps,
    mcpAccessTokenVerifier: recordingVerifier,
  });

  if (result.outcome === 'unavailable') return unavailable(result.detail);

  if (result.outcome === 'inactive') {
    return refuse('invalid_grant', result.detail, {
      subjectTokenVerified,
      userId: result.userId === undefined ? null : result.userId,
    });
  }

  const { grant } = result;
  const grantedScopes = introspectionService.parseScope(result.body.scope);

  // Shared parseScope — must handle array form from urlencoded repeated keys.
  const requestedScopes = introspectionService.parseScope(params.scope);
  if (requestedScopes.length > 0) {
    const granted = new Set(grantedScopes);
    const exceeded = requestedScopes.filter((scope) => !granted.has(scope));
    if (exceeded.length > 0) {
      return refuse('invalid_scope', 'requested_scope_exceeds_grant', {
        subjectTokenVerified,
        userId: grant.user_id,
      });
    }
  }
  const issuedScopes = requestedScopes.length > 0 ? requestedScopes : grantedScopes;

  const roleResolution = await roleResolver.resolveRole(grant.user_id, deps);

  if (roleResolution.outcome === 'unavailable') return unavailable(roleResolution.detail);
  if (roleResolution.outcome === 'refused') {
    return refuse('invalid_grant', roleResolution.detail, {
      subjectTokenVerified,
      userId: grant.user_id,
    });
  }

  const minted = issuer.issueUpstreamCredential(
    {
      userId: grant.user_id,
      role: roleResolution.role,
      scope: issuedScopes.join(' '),
      clientId: grant.client_id,
      grantId: grant.grant_id,
      actorClientId: deps.actorClientId,
    },
    deps
  );

  if (!minted.ok) return unavailable(minted.detail);

  return {
    outcome: 'issued',
    credential: minted.credential,
    expiresIn: minted.expiresIn,
    scope: issuedScopes.join(' '),
    role: roleResolution.role,
    grant,
    subjectTokenVerified,
  };
};

module.exports = {
  exchange,
  ACCESS_TOKEN_TYPE,
  GRANT_TYPE_TOKEN_EXCHANGE,
};
