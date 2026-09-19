const crypto = require('crypto');

const jwt = require('jsonwebtoken');

const asSigningKey = require('./asSigningKey');
const oauthConfig = require('./oauthConfig');

/**
 * Mints MCP access token (`type:'mcp_access'`) for introspection. Ticket 39b.
 *
 * Not upstreamCredentialIssuer (mcp_upstream, 120s, backend aud, act.sub).
 * Claims follow mcpAccessTokenVerifier; suites verify with the real verifier.
 *
 * ⚠️ aud from the code/token row resource, never oauthConfig.mcpResourceIdentifier().
 */

const MCP_ACCESS_TOKEN_LIFETIME_SECONDS = 300;
const MCP_ACCESS_TOKEN_TYPE = 'mcp_access';
const SIGNING_ALGORITHM = 'RS256';

const isNonEmptyString = (value) => typeof value === 'string' && value.trim() !== '';

/**
 * @param {object} subject
 * @param {number|string} subject.userId
 * @param {string} subject.clientId
 * @param {string} subject.grantId
 * @param {string} subject.resource → aud
 * @param {string} subject.scope space-delimited, already intersected
 * @returns {{ok:true, accessToken:string, expiresIn:number, jti:string} |
 *           {ok:false, detail:string}}
 */
const issueMcpAccessToken = (subject, deps = {}) => {
  const config = deps.oauthConfig || oauthConfig;
  const signingKeys = deps.asSigningKey || asSigningKey;

  const issuer = config.mcpAccessTokenIssuer();
  if (!issuer) return { ok: false, detail: 'issuer_unconfigured' };

  if (!isNonEmptyString(subject.resource)) {
    return { ok: false, detail: 'resource_absent' };
  }

  if (!isNonEmptyString(subject.grantId)) return { ok: false, detail: 'grant_id_absent' };
  if (!isNonEmptyString(subject.clientId)) return { ok: false, detail: 'client_id_absent' };

  const loaded = signingKeys.getSigningKey(deps);
  if (!loaded.ok) return { ok: false, detail: loaded.detail };

  const { kid, privateKeyPem } = loaded.key;
  if (!isNonEmptyString(kid)) return { ok: false, detail: 'signing_key_id_absent' };

  const issuedAt = Math.floor(Date.now() / 1000);
  const jti = crypto.randomUUID();

  const claims = {
    iss: issuer,
    aud: subject.resource,
    sub: String(subject.userId),
    scope: subject.scope,
    client_id: subject.clientId,
    grant_id: subject.grantId,
    jti,
    type: MCP_ACCESS_TOKEN_TYPE,
    iat: issuedAt,
    exp: issuedAt + MCP_ACCESS_TOKEN_LIFETIME_SECONDS,
  };

  let accessToken;
  try {
    // iat/exp in claims; noTimestamp would delete payload.iat.
    accessToken = jwt.sign(claims, privateKeyPem, {
      algorithm: SIGNING_ALGORITHM,
      keyid: kid,
    });
  } catch (err) {
    return { ok: false, detail: 'access_token_signing_failed' };
  }

  return {
    ok: true,
    accessToken,
    expiresIn: MCP_ACCESS_TOKEN_LIFETIME_SECONDS,
    jti,
  };
};

module.exports = {
  issueMcpAccessToken,
  MCP_ACCESS_TOKEN_LIFETIME_SECONDS,
  MCP_ACCESS_TOKEN_TYPE,
};
