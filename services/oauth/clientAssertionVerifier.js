const jwt = require('jsonwebtoken');

const supabase = require('../../dbConnection');
const oauthConfig = require('./oauthConfig');

/**
 * private_key_jwt (RFC 7523) for the MCP server.
 *
 * Algorithm comes from the registered key row, never the assertion header.
 * jsonwebtoken accepts `none` and HS*; Q16c rejects both. If header.alg chose
 * the verify algorithm: `none` is unsigned auth; HS256 treats public_key_pem as
 * the HMAC secret (anyone with the public key forges assertions).
 *
 * Q16b multi-key trial (owned by ticket 40 rotation): while kid is absent, try
 * each in-window active key, capped at two. Schema exclusion guarantees ≤2
 * overlapping windows. Retires when MCP sends kid.
 */

const ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

/** Q16c allowlist. Narrowing is an amendment, not a refactor. */
const Q16C_ALGORITHM_ALLOWLIST = Object.freeze(['RS256', 'ES256', 'EdDSA']);

/** Subset we can verify today — jsonwebtoken/jwa has no EdDSA. */
const VERIFIABLE_ALGORITHMS = Object.freeze(['RS256', 'ES256']);

const CLOCK_LEEWAY_SECONDS = 30;
const MAX_ASSERTION_LIFETIME_SECONDS = 300;
const MAX_KEYS_TRIED = 2;

const JTI_PURGE_SAMPLE_RATE = 50;
const JTI_PURGE_BATCH_SIZE = 500;

const POSTGRES_UNIQUE_VIOLATION = '23505';

const isNonEmptyString = (value) => typeof value === 'string' && value.trim() !== '';

const fail = (httpStatus, reason, detail) => ({ ok: false, httpStatus, reason, detail });

/** Bound attacker-controlled alg before it reaches error_logs. */
const safeAlgLabel = (value) => {
  if (typeof value !== 'string') return typeof value;
  const cleaned = value.replace(/[^A-Za-z0-9_-]/g, '');
  return cleaned.slice(0, 16) || 'unprintable';
};

/**
 * Sampled, bounded purge of oauth_client_assertion_jti (release gate, mig 002).
 * Never fails the request. Filter on expires_at (lifetime+skew), not created_at.
 *
 * `.order('expires_at', { ascending: true })` is required: PostgREST 12
 * rejects DELETE+limit without order (PGRST109). Measured 2026-09-10 on live
 * 12.2.3 — unordered → 400 every call; ordered → 204. Ascending drains
 * oldest-expired first. expires_at need not be unique here (no pagination
 * cursor). Optional stronger path later: RPC with mig 002's ctid subquery.
 */
const purgeExpiredJtis = async (db, random = Math.random) => {
  if (random() >= 1 / JTI_PURGE_SAMPLE_RATE) return { purged: false, sampled: false };

  try {
    // supabase-js resolves on failure — must read `error`, not assume success.
    const { error } = await db
      .from('oauth_client_assertion_jti')
      .delete()
      .lt('expires_at', new Date().toISOString())
      // Required by PostgREST 12 whenever limit is applied to a DELETE.
      .order('expires_at', { ascending: true })
      .limit(JTI_PURGE_BATCH_SIZE);

    if (error) return { purged: false, sampled: true, error };
    return { purged: true, sampled: true };
  } catch (err) {
    return { purged: false, sampled: true, error: err };
  }
};

/**
 * @returns {Promise<{ok: true, clientId: string} | {ok: false, httpStatus: number, reason: string, detail: string}>}
 *
 * 400 malformed, 401 bad credential (only 401 this endpoint returns), 503 our fault.
 * Never {"active": false} — that is grant state, not client auth.
 */
const verifyClientAssertion = async (params = {}, deps = {}) => {
  const db = deps.supabase || supabase;
  const config = deps.oauthConfig || oauthConfig;
  const random = deps.random || Math.random;

  const { client_assertion: assertion, client_assertion_type: assertionType } = params;

  if (!isNonEmptyString(assertionType) || assertionType !== ASSERTION_TYPE) {
    return fail(400, 'invalid_request', 'client_assertion_type_invalid');
  }
  if (!isNonEmptyString(assertion)) {
    return fail(400, 'invalid_request', 'client_assertion_absent');
  }

  // Q16a: this endpoint's absolute URL only — never Host header / issuer / sibling.
  const expectedAudience = config.introspectionAudience();
  if (!expectedAudience) {
    return fail(503, 'server_error', 'introspection_audience_unconfigured');
  }

  let decoded;
  try {
    decoded = jwt.decode(assertion, { complete: true });
  } catch (err) {
    decoded = null;
  }
  if (!decoded || !decoded.header || !decoded.payload || typeof decoded.payload !== 'object') {
    return fail(401, 'invalid_client', 'assertion_undecodable');
  }

  const headerAlgorithm = decoded.header.alg;

  // Named refusal of none/HS* (also blocked by algorithms pin below).
  if (
    !isNonEmptyString(headerAlgorithm) ||
    headerAlgorithm === 'none' ||
    /^HS/i.test(headerAlgorithm)
  ) {
    return fail(401, 'invalid_client', `algorithm_not_allowed:${safeAlgLabel(headerAlgorithm)}`);
  }
  if (!Q16C_ALGORITHM_ALLOWLIST.includes(headerAlgorithm)) {
    return fail(401, 'invalid_client', `algorithm_not_allowed:${safeAlgLabel(headerAlgorithm)}`);
  }

  const claimedClientId = decoded.payload.iss;
  if (!isNonEmptyString(claimedClientId)) {
    return fail(401, 'invalid_client', 'assertion_iss_absent');
  }
  // RFC 7523: iss and sub are both the client id.
  if (decoded.payload.sub !== claimedClientId) {
    return fail(401, 'invalid_client', 'assertion_iss_sub_mismatch');
  }

  let clientRow;
  try {
    const { data, error } = await db
      .from('oauth_clients')
      .select('client_id, client_type, token_endpoint_auth_method, is_active')
      .eq('client_id', claimedClientId)
      .maybeSingle();
    if (error) return fail(503, 'server_error', 'client_lookup_failed');
    clientRow = data;
  } catch (err) {
    return fail(503, 'server_error', 'client_lookup_failed');
  }

  if (!clientRow || clientRow.is_active !== true) {
    return fail(401, 'invalid_client', 'client_unknown_or_inactive');
  }
  // Kind before method — assistant_public must never verify here.
  if (clientRow.client_type !== 'service_confidential') {
    return fail(401, 'invalid_client', 'client_not_confidential');
  }
  // Defence in depth; schema already forbids this pairing. Do not reorder above kind check.
  if (clientRow.token_endpoint_auth_method !== 'private_key_jwt') {
    return fail(401, 'invalid_client', 'client_auth_method_mismatch');
  }

  const nowIso = new Date().toISOString();
  let keyRows;
  try {
    let query = db
      .from('oauth_client_keys')
      .select('kid, alg, public_key_pem, slot')
      .eq('client_id', claimedClientId)
      .eq('is_active', true)
      // Window is sole validity authority; is_active only subtracts.
      .lte('not_before', nowIso)
      .gt('not_after', nowIso);

    const headerKid = decoded.header.kid;
    if (isNonEmptyString(headerKid)) {
      query = query.eq('kid', headerKid);
    }

    const { data, error } = await query.order('slot', { ascending: true }).limit(MAX_KEYS_TRIED);
    if (error) return fail(503, 'server_error', 'key_lookup_failed');
    keyRows = Array.isArray(data) ? data : [];
  } catch (err) {
    return fail(503, 'server_error', 'key_lookup_failed');
  }

  if (keyRows.length === 0) {
    return fail(401, 'invalid_client', 'no_key_in_window');
  }

  let verifiedPayload = null;
  const unsupportedAlgorithms = [];
  let keysTried = 0;

  for (const keyRow of keyRows.slice(0, MAX_KEYS_TRIED)) {
    const keyAlgorithm = keyRow.alg;
    keysTried += 1;

    if (!Q16C_ALGORITHM_ALLOWLIST.includes(keyAlgorithm)) {
      continue;
    }

    if (!VERIFIABLE_ALGORITHMS.includes(keyAlgorithm)) {
      // EdDSA is in Q16c but unverifiable here — refuse loudly, do not silently drop.
      unsupportedAlgorithms.push(keyAlgorithm);
      continue;
    }

    try {
      verifiedPayload = jwt.verify(assertion, keyRow.public_key_pem, {
        // From the KEY ROW — never decoded.header.alg.
        algorithms: [keyAlgorithm],
        audience: expectedAudience,
        issuer: claimedClientId,
        subject: claimedClientId,
        clockTolerance: CLOCK_LEEWAY_SECONDS,
      });
      break;
    } catch (err) {
      verifiedPayload = null;
    }
  }

  if (!verifiedPayload) {
    // 503 only if every tried key was unverifiable; forged cred with mixed keys → 401.
    if (unsupportedAlgorithms.length > 0 && unsupportedAlgorithms.length === keysTried) {
      return fail(
        503,
        'server_error',
        `unsupported_algorithm_q16c_gap:${unsupportedAlgorithms[0]}`
      );
    }
    return fail(401, 'invalid_client', 'assertion_signature_rejected');
  }

  // jwt.verify accepts any element of an aud array; Q16a requires sole exact URL.
  if (verifiedPayload.aud !== expectedAudience) {
    return fail(401, 'invalid_client', 'assertion_audience_not_sole');
  }

  const { iat, exp, jti } = verifiedPayload;

  // Number.isFinite: NaN/±Infinity are typeof number; Infinity breaks Date#toISOString.
  if (!Number.isFinite(iat) || !Number.isFinite(exp)) {
    return fail(401, 'invalid_client', 'assertion_missing_iat_or_exp');
  }

  const nowSeconds = Math.floor(Date.now() / 1000);

  // exp-iat alone is attacker-chosen and collapses at large magnitudes — also bound to now.
  if (exp - iat > MAX_ASSERTION_LIFETIME_SECONDS) {
    return fail(401, 'invalid_client', 'assertion_lifetime_too_long');
  }
  if (exp - nowSeconds > MAX_ASSERTION_LIFETIME_SECONDS + CLOCK_LEEWAY_SECONDS) {
    return fail(401, 'invalid_client', 'assertion_expiry_too_far_ahead');
  }
  if (iat - nowSeconds > CLOCK_LEEWAY_SECONDS) {
    return fail(401, 'invalid_client', 'assertion_issued_in_future');
  }

  if (!isNonEmptyString(jti)) {
    return fail(401, 'invalid_client', 'assertion_jti_absent');
  }

  // Replay store only after signature verifies.
  const retainUntil = new Date((exp + CLOCK_LEEWAY_SECONDS) * 1000).toISOString();
  try {
    const { error } = await db
      .from('oauth_client_assertion_jti')
      .insert([{ client_id: claimedClientId, jti, expires_at: retainUntil }]);

    if (error) {
      if (error.code === POSTGRES_UNIQUE_VIOLATION) {
        return fail(401, 'invalid_client', 'assertion_replayed');
      }
      return fail(503, 'server_error', 'replay_store_unavailable');
    }
  } catch (err) {
    return fail(503, 'server_error', 'replay_store_unavailable');
  }

  const purge = await purgeExpiredJtis(db, random);

  return { ok: true, clientId: claimedClientId, purge };
};

module.exports = {
  verifyClientAssertion,
  purgeExpiredJtis,
  ASSERTION_TYPE,
  Q16C_ALGORITHM_ALLOWLIST,
  VERIFIABLE_ALGORITHMS,
  CLOCK_LEEWAY_SECONDS,
  MAX_ASSERTION_LIFETIME_SECONDS,
  MAX_KEYS_TRIED,
  JTI_PURGE_SAMPLE_RATE,
  JTI_PURGE_BATCH_SIZE,
};
