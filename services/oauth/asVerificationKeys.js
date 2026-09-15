/**
 * Ticket 40 replaces this file's body only.
 *
 * getVerificationKeys() -> [{ kid, alg, publicKeyPem }]
 *
 * Env-backed today; JWKS/rotation later. Public material only — never sign here
 * (issuance is ticket 39). Empty → unavailable → 503, never active:false.
 */

const readEnv = (name) => {
  const raw = process.env[name];
  if (typeof raw !== 'string') return null;
  const trimmed = raw.trim();
  return trimmed === '' ? null : trimmed;
};

/**
 * @returns {Array<{kid: string|null, alg: string, publicKeyPem: string}>}
 */
const getVerificationKeys = () => {
  // Env PEMs arrive with escaped \n.
  const pem = readEnv('MCP_AS_PUBLIC_KEY_PEM');
  if (!pem) return [];

  return [
    {
      kid: readEnv('MCP_AS_KEY_ID'),
      alg: 'RS256',
      publicKeyPem: pem.replace(/\\n/g, '\n'),
    },
  ];
};

module.exports = { getVerificationKeys };
