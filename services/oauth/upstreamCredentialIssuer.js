const crypto = require('crypto');

const jwt = require('jsonwebtoken');

const asSigningKey = require('./asSigningKey');
const oauthConfig = require('./oauthConfig');

/**
 * Mints the exchanged upstream credential (mcp_upstream). Lifetime fixed at 120s.
 * Policy decisions happen before this is called.
 */

const UPSTREAM_CREDENTIAL_LIFETIME_SECONDS = 120;
const UPSTREAM_TOKEN_TYPE = 'mcp_upstream';
const SIGNING_ALGORITHM = 'RS256';

const isNonEmptyString = (value) => typeof value === 'string' && value.trim() !== '';

/**
 * @param {object} subject
 * @param {number|string} subject.userId    from the grant
 * @param {string} subject.role
 * @param {string} subject.scope
 * @param {string} subject.clientId         assistant client id
 * @param {string} subject.grantId
 * @param {string} subject.actorClientId    MCP server client id → act
 */
const issueUpstreamCredential = (subject, deps = {}) => {
  const config = deps.oauthConfig || oauthConfig;
  const signingKeys = deps.asSigningKey || asSigningKey;

  const issuer = config.mcpAccessTokenIssuer();
  if (!issuer) return { ok: false, detail: 'issuer_unconfigured' };

  const audience = config.backendApiAudience();
  if (!audience) return { ok: false, detail: 'backend_api_audience_unconfigured' };

  const loaded = signingKeys.getSigningKey(deps);
  if (!loaded.ok) return { ok: false, detail: loaded.detail };

  const { kid, privateKeyPem } = loaded.key;

  if (!isNonEmptyString(kid)) {
    return { ok: false, detail: 'signing_key_id_absent' };
  }

  if (!isNonEmptyString(subject.actorClientId)) {
    return { ok: false, detail: 'actor_client_id_absent' };
  }

  const issuedAt = Math.floor(Date.now() / 1000);
  const jti = crypto.randomUUID();

  const claims = {
    iss: issuer,
    aud: audience,
    sub: String(subject.userId),
    userId: subject.userId,
    role: subject.role,
    scope: subject.scope,
    client_id: subject.clientId,
    grant_id: subject.grantId,
    jti,
    type: UPSTREAM_TOKEN_TYPE,
    iat: issuedAt,
    exp: issuedAt + UPSTREAM_CREDENTIAL_LIFETIME_SECONDS,
    act: { sub: subject.actorClientId },
  };

  let credential;
  try {
    // iat/exp set in claims; do not use noTimestamp (it deletes payload.iat).
    credential = jwt.sign(claims, privateKeyPem, {
      algorithm: SIGNING_ALGORITHM,
      keyid: kid,
    });
  } catch (err) {
    return { ok: false, detail: 'credential_signing_failed' };
  }

  return {
    ok: true,
    credential,
    expiresIn: UPSTREAM_CREDENTIAL_LIFETIME_SECONDS,
    jti,
  };
};

module.exports = {
  issueUpstreamCredential,
  UPSTREAM_CREDENTIAL_LIFETIME_SECONDS,
  UPSTREAM_TOKEN_TYPE,
};
