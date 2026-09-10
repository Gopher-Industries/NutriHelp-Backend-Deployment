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

/** Absolute introspection URL, normalised as new URL(x).href (same as MCP). */
const introspectionAudience = () => {
  const configured = readEnv('MCP_INTROSPECTION_URL');
  if (!configured) return null;
  try {
    return new URL(configured).href;
  } catch (err) {
    return null;
  }
};

const mcpAccessTokenIssuer = () => readEnv('MCP_AS_ISSUER');

const mcpResourceIdentifier = () => readEnv('MCP_RESOURCE_IDENTIFIER');

module.exports = {
  introspectionAudience,
  mcpAccessTokenIssuer,
  mcpResourceIdentifier,
};
