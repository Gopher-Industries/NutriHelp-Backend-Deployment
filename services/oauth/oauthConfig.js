/**
 * OAuth AS config — from environment only, never from the request.
 *
 * Assertion aud (Q16a) must not be derived from Host / hostname; that lets the
 * caller choose the value under check. Unset → null → 503, never active:false.
 */

const readEnv = (name) => {
  const raw = process.env[name];
  if (typeof raw !== 'string') return null;
  const trimmed = raw.trim();
  return trimmed === '' ? null : trimmed;
};

/** Absolute endpoint URL, normalised as new URL(x).href (same as MCP). */
const absoluteEndpointUrl = (variable) => {
  const configured = readEnv(variable);
  if (!configured) return null;
  try {
    return new URL(configured).href;
  } catch (err) {
    return null;
  }
};

/** Absolute introspection URL, normalised as new URL(x).href (same as MCP). */
const introspectionAudience = () => absoluteEndpointUrl('MCP_INTROSPECTION_URL');

/** Q16a token-endpoint aud. No fallback to introspection URL. Unset → null → 503. */
const tokenEndpointAudience = () => absoluteEndpointUrl('MCP_TOKEN_ENDPOINT_URL');

/** Exchanged-credential aud (this API). Not MCP_RESOURCE_IDENTIFIER. */
const backendApiAudience = () => readEnv('MCP_BACKEND_API_AUDIENCE');

const mcpAccessTokenIssuer = () => readEnv('MCP_AS_ISSUER');

const mcpResourceIdentifier = () => readEnv('MCP_RESOURCE_IDENTIFIER');

/**
 * Exact Origin for user-facing OAuth routes. Literal string only — never a
 * *.vercel.app pattern (server.js CORS has that hole). Null → middleware
 * refuses; unset must never mean accept-anything.
 */
const frontendOrigin = () => readEnv('OAUTH_FRONTEND_ORIGIN');

module.exports = {
  introspectionAudience,
  tokenEndpointAudience,
  backendApiAudience,
  mcpAccessTokenIssuer,
  mcpResourceIdentifier,
  frontendOrigin,
};
