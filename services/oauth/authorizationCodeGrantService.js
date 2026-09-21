const crypto = require('crypto');

const supabase = require('../../dbConnection');
const introspectionService = require('./introspectionService');
const mcpAccessTokenIssuer = require('./mcpAccessTokenIssuer');
const refreshTokenStore = require('./refreshTokenStore');

/**
 * grant_type=authorization_code with PKCE (ticket 39b).
 *
 *   {outcome:'issued', ...} | {outcome:'refused', error, detail} |
 *   {outcome:'unavailable', detail}
 *
 * No client auth: assistant is public (schema-frozen assistant_public).
 * PKCE + code bindings are the proof; client_id is checked against the code.
 *
 * ⚠️ S256 is hardcoded — codes have no code_challenge_method column; the
 * method is pinned on oauth_authorization_transactions (CHECK + authorize).
 */

const GRANT_STATUS_ACTIVE = 'active';

// RFC 7636 §4.1: 43–128 characters from the unreserved set.
const CODE_VERIFIER_PATTERN = /^[A-Za-z0-9\-._~]{43,128}$/;

const refuse = (error, detail) => ({ outcome: 'refused', error, detail });
const unavailable = (detail) => ({ outcome: 'unavailable', detail });

const isNonEmptyString = (value) => typeof value === 'string' && value.trim() !== '';

const sha256Hex = (value) => crypto.createHash('sha256').update(value).digest('hex');

const CODE_FAMILY_DOMAIN = 'nutrihelp.oauth.code-family:';

/**
 * The refresh family a code opens, derived from its code_hash (ticket 88), so
 * "did THIS redemption's root land?" is an exact lookup; a time window would
 * also match another code's redemption on the same upserted grant (mig 004).
 * Internal only. UUID v8 (custom), so it can never collide with a random v4.
 */
const codeFamilyId = (codeHash) => {
  const bytes = crypto
    .createHash('sha256')
    .update(CODE_FAMILY_DOMAIN + codeHash)
    .digest();
  bytes[6] = (bytes[6] & 0x0f) | 0x80;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.subarray(0, 16).toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
};

/** Fail closed: missing or unparseable expires_at → expired (NaN <= now is false). */
const isCodeExpired = (row) => {
  const expiry = new Date(row.expires_at).getTime();
  return !row.expires_at || Number.isNaN(expiry) || expiry <= Date.now();
};

/** S256: BASE64URL(SHA256(ASCII(code_verifier))), compared in constant time. */
const pkceMatches = (codeVerifier, storedChallenge) => {
  if (!isNonEmptyString(storedChallenge)) return false;
  const computed = crypto.createHash('sha256').update(codeVerifier).digest().toString('base64url');
  if (computed.length !== storedChallenge.length) return false;
  return crypto.timingSafeEqual(
    Buffer.from(computed, 'utf8'),
    Buffer.from(storedChallenge, 'utf8')
  );
};

const redeemAuthorizationCode = async (body, deps = {}) => {
  const db = deps.supabase || supabase;
  const store = deps.refreshTokenStore || refreshTokenStore;
  const issuer = deps.mcpAccessTokenIssuer || mcpAccessTokenIssuer;
  const scopes = deps.introspectionService || introspectionService;

  const code = body.code;
  const codeVerifier = body.code_verifier;
  const redirectUri = body.redirect_uri;
  const clientId = body.client_id;

  if (!isNonEmptyString(code)) return refuse('invalid_request', 'code_absent');
  if (!isNonEmptyString(codeVerifier)) return refuse('invalid_request', 'code_verifier_absent');
  if (!CODE_VERIFIER_PATTERN.test(codeVerifier)) {
    return refuse('invalid_request', 'code_verifier_malformed');
  }
  if (!isNonEmptyString(redirectUri)) return refuse('invalid_request', 'redirect_uri_absent');
  if (!isNonEmptyString(clientId)) return refuse('invalid_request', 'client_id_absent');

  let codeRow;
  try {
    const { data, error } = await db
      .from('oauth_authorization_codes')
      .select(
        'id, code_hash, grant_id, client_id, user_id, redirect_uri, resource, scopes, ' +
          'code_challenge, consumed_at, expires_at'
      )
      .eq('code_hash', sha256Hex(code))
      .maybeSingle();

    if (error) return unavailable('code_lookup_failed');
    codeRow = data;
  } catch (err) {
    return unavailable('code_lookup_failed');
  }

  if (!codeRow) return refuse('invalid_grant', 'code_not_found');

  const familyId = codeFamilyId(codeRow.code_hash);

  // RFC 6749 §4.1.2: authentic replay (client + redirect + PKCE) revokes what
  // the code issued. Unauthentic replay is noise — revoking on any replay is a
  // forced-disconnect primitive (codes leak via redirect URLs).
  //
  // Ticket 88: revoke only when this code's root exists (tokens WERE issued).
  // No root: the consume was stranded by a failed redemption, and past the
  // lease an authentic retry takes it over. Recovery runs only after the
  // authentic check, which needs the same proof as a first redemption, so it
  // opens nothing new; unauthentic replay writes nothing and never revokes.
  let strandedConsumedAt = null;
  if (codeRow.consumed_at) {
    const authentic =
      codeRow.client_id === clientId &&
      codeRow.redirect_uri === redirectUri &&
      pkceMatches(codeVerifier, codeRow.code_challenge);

    if (!authentic) return refuse('invalid_grant', 'code_replay_unauthentic');

    const root = await store.findFamilyRoot(familyId, deps);
    if (!root.ok) return unavailable(root.detail);

    if (root.found) {
      const swept = await store.revokeGrantAndAllFamilies(
        codeRow.grant_id,
        store.CODE_REPLAY_REVOKE_REASON,
        deps
      );

      // Failed revoke → 503, not invalid_grant (would claim security ran when it didn't).
      if (!swept.ok) return unavailable(swept.detail);
      return refuse('invalid_grant', 'code_already_consumed');
    }

    if (isCodeExpired(codeRow)) return refuse('invalid_grant', 'code_expired');
    if (store.isWithinLease(codeRow.consumed_at)) {
      return unavailable('code_redemption_in_flight');
    }
    strandedConsumedAt = codeRow.consumed_at;
  }

  if (isCodeExpired(codeRow)) return refuse('invalid_grant', 'code_expired');

  if (codeRow.client_id !== clientId) return refuse('invalid_grant', 'code_client_mismatch');
  if (codeRow.redirect_uri !== redirectUri) {
    return refuse('invalid_grant', 'code_redirect_uri_mismatch');
  }

  if (!pkceMatches(codeVerifier, codeRow.code_challenge)) {
    return refuse('invalid_grant', 'pkce_verification_failed');
  }

  let grant;
  try {
    const { data, error } = await db
      .from('mcp_client_grants')
      .select('grant_id, user_id, client_id, resource, scopes, status')
      .eq('grant_id', codeRow.grant_id)
      .maybeSingle();

    if (error) return unavailable('grant_lookup_failed');
    grant = data;
  } catch (err) {
    return unavailable('grant_lookup_failed');
  }

  if (!grant) return refuse('invalid_grant', 'grant_not_found');
  if (grant.status !== GRANT_STATUS_ACTIVE) {
    return refuse('invalid_grant', `grant_status:${grant.status}`);
  }

  // Schema does not bind code↔grant user/client/resource — compare here.
  if (
    String(grant.user_id) !== String(codeRow.user_id) ||
    grant.client_id !== codeRow.client_id ||
    grant.resource !== codeRow.resource
  ) {
    return refuse('invalid_grant', 'grant_code_binding_mismatch');
  }

  // Never widen: code scopes ∩ grant scopes.
  const granted = scopes.intersectScopes(
    scopes.parseScope(codeRow.scopes),
    scopes.parseScope(grant.scopes)
  );

  // Mint before any DB write, as on refresh: a signing blip must not strand
  // the consume.
  const minted = issuer.issueMcpAccessToken(
    {
      userId: codeRow.user_id,
      clientId: codeRow.client_id,
      grantId: codeRow.grant_id,
      resource: codeRow.resource,
      scope: granted.join(' '),
    },
    deps
  );

  if (!minted.ok) return unavailable(minted.detail);

  // Consume, or take over the stranded consume (CAS on its exact consumed_at).
  // Zero rows: another request got there first. Refuse WITHOUT revoking,
  // since nothing is proven issued (on refresh a lost CAS is reuse).
  const consumedAt = new Date().toISOString();
  let consumed;
  try {
    let query = db
      .from('oauth_authorization_codes')
      .update({ consumed_at: consumedAt })
      .eq('id', codeRow.id);
    query =
      strandedConsumedAt === null
        ? query.is('consumed_at', null)
        : query.eq('consumed_at', strandedConsumedAt);
    const { data, error } = await query.select('id');

    if (error) return unavailable('code_consume_failed');
    consumed = data;
  } catch (err) {
    return unavailable('code_consume_failed');
  }

  if (!Array.isArray(consumed) || consumed.length !== 1) {
    return refuse('invalid_grant', 'code_already_consumed');
  }

  // Best effort: release only after proving this redemption's root did not
  // land (a failed insert may have committed), and only while consumed_at is
  // still the value THIS request wrote, never another request's takeover.
  const failAfterConsume = async (detail) => {
    const root = await store.findFamilyRoot(familyId, deps);
    if (root.ok && !root.found) {
      // { error } deliberately not read: 503 either way, and a failed release
      // is recovered at retry time. The try only stops a throw escaping.
      try {
        await db
          .from('oauth_authorization_codes')
          .update({ consumed_at: null })
          .eq('id', codeRow.id)
          .eq('consumed_at', consumedAt);
      } catch (err) {
        // As above.
      }
    }
    return unavailable(detail);
  };

  // Re-consent (Backend Lead): mig 004 upserts the same grant, so sweep prior
  // families before inserting the new root — otherwise old refresh tokens stay live.
  // Fail closed: do not issue while old families survive.
  const sweptPrior = await store.revokePriorFamilies(codeRow.grant_id, deps);
  if (!sweptPrior.ok) return failAfterConsume(sweptPrior.detail);

  const refresh = await store.insertRefreshToken(
    {
      grantId: codeRow.grant_id,
      familyId,
      parentId: null,
      userId: codeRow.user_id,
      clientId: codeRow.client_id,
      resource: codeRow.resource,
      scopes: granted,
    },
    deps
  );

  if (!refresh.ok) return failAfterConsume(refresh.detail);

  return {
    outcome: 'issued',
    accessToken: minted.accessToken,
    expiresIn: minted.expiresIn,
    scope: granted.join(' '),
    refreshToken: refresh.rawToken,
  };
};

module.exports = { redeemAuthorizationCode, codeFamilyId, CODE_VERIFIER_PATTERN };
