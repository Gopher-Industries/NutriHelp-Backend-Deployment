const crypto = require('crypto');

/**
 * AS private key (issuance half of asVerificationKeys.js).
 *
 * Public half is derived; if MCP_AS_PUBLIC_KEY_PEM is set it must match.
 * Fail closed on mismatch. Missing key → {ok:false} → 503.
 */

const SIGNING_ALGORITHM = 'RS256';
const REQUIRED_KEY_TYPE = 'rsa';

const readEnv = (env, name) => {
  const raw = env[name];
  if (typeof raw !== 'string') return null;
  const trimmed = raw.trim();
  if (trimmed === '') return null;
  return trimmed.replace(/\\n/g, '\n');
};

const fail = (detail) => ({ ok: false, detail });

/** Compare key material via SPKI DER (PEM text can differ for the same key). */
const keyFingerprint = (key) => {
  const keyObject = typeof key === 'string' ? crypto.createPublicKey(key) : key;
  return keyObject.export({ type: 'spki', format: 'der' });
};

/**
 * @param {{env?: object}} [deps]
 */
const getSigningKey = (deps = {}) => {
  const env = deps.env || process.env;

  const privatePem = readEnv(env, 'MCP_AS_PRIVATE_KEY_PEM');
  if (!privatePem) return fail('signing_key_unconfigured');

  let privateKey;
  try {
    privateKey = crypto.createPrivateKey(privatePem);
  } catch (err) {
    return fail('signing_key_unreadable');
  }

  if (privateKey.asymmetricKeyType !== REQUIRED_KEY_TYPE) {
    return fail(`signing_key_wrong_type:${privateKey.asymmetricKeyType}`);
  }

  let publicKey;
  try {
    publicKey = crypto.createPublicKey(privateKey);
  } catch (err) {
    return fail('signing_key_unreadable');
  }

  const configuredPublicPem = readEnv(env, 'MCP_AS_PUBLIC_KEY_PEM');
  if (configuredPublicPem) {
    try {
      if (!keyFingerprint(configuredPublicPem).equals(keyFingerprint(publicKey))) {
        return fail('signing_key_public_mismatch');
      }
    } catch (err) {
      return fail('signing_key_public_mismatch');
    }
  }

  const kid = readEnv(env, 'MCP_AS_KEY_ID');
  if (!kid) return fail('signing_key_id_unconfigured');

  return {
    ok: true,
    key: {
      kid,
      alg: SIGNING_ALGORITHM,
      privateKeyPem: privatePem,
      publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }),
    },
  };
};

module.exports = { getSigningKey, SIGNING_ALGORITHM };
