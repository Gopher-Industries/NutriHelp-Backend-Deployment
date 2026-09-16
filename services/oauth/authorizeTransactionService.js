const crypto = require('crypto');

const supabase = require('../../dbConnection');
const clientMetadataServiceModule = require('./clientMetadataService');
const redirectUriMatcher = require('./redirectUriMatcher');
const introspectionService = require('./introspectionService');
const oauthConfig = require('./oauthConfig');

/**
 * Authorization request intake (ticket 36).
 *
 * No browser session / no user resolution — validate, persist a hashed opaque
 * reference, hand it to the frontend login page.
 *
 * Order is the security property:
 *   1. client-independent shape (incl. PKCE / response_type — no fetch yet)
 *   2. CIMD resolve (ticket 41)  <-- outbound fetch
 *   3. prove redirect_uri against that client's list
 *   --- past here EVERY failure redirects to redirect_uri, 503s included ---
 *   4. client-dependent checks, then persistence
 *
 * Redirect before step 3 = open redirector. Direct answer after step 3 =
 * strands the assistant. ⚠️ Never store a platform bearer (mig 002).
 */

/** From the contract's Scopes table. Coarse and per-capability, by design. */
const SUPPORTED_SCOPES = ['nutrition:read', 'mealplan:read', 'meallog:write'];

/** Spans a login; codes are 60s. Leaked refs should usually be dead already. */
const TRANSACTION_TTL_SECONDS = 600;

/** RFC 7636 §4.2: 43-128 unreserved. 43 = SHA-256. */
const CODE_CHALLENGE_PATTERN = /^[A-Za-z0-9\-._~]{43,128}$/;

/** Attacker-chosen and reflected; RFC sets no limit — this one is ours. */
const MAX_STATE_LENGTH = 512;

/** 32 bytes — the reference must not be cheaper to guess than the code. */
const REFERENCE_BYTES = 32;
const CSRF_TOKEN_BYTES = 32;

const AUTHORIZE_ENDPOINT = 'GET /api/oauth/authorize';
const AUTHORIZE_ERROR_PREFIX = 'oauth_authorize';

const isNonEmptyString = (value) => typeof value === 'string' && value.trim() !== '';

/** Direct refusal — redirect_uri not yet proven. Always 400; no status field. */
const refuseDirect = (error, reason) => ({
  ok: false,
  redirectable: false,
  error,
  reason,
});

/** Refusal the client gets at its own proven redirect_uri (RFC 6749 §4.1.2.1). */
const refuseRedirect = (error, reason, redirectUri, state) => ({
  ok: false,
  redirectable: true,
  error,
  reason,
  redirectUri,
  state,
});

const hashTransactionReference = (reference) =>
  crypto.createHash('sha256').update(reference).digest('hex');

const newTransactionReference = () => crypto.randomBytes(REFERENCE_BYTES).toString('base64url');
const newCsrfToken = () => crypto.randomBytes(CSRF_TOKEN_BYTES).toString('base64url');

/**
 * Single query value only — Express arrays on repeated keys; taking the first
 * would smuggle a second redirect_uri. `scope` is the exception (space- or
 * repeated-key list); every element still filters against SUPPORTED_SCOPES.
 */
const singleValue = (value) => {
  if (Array.isArray(value)) return undefined;
  return value;
};

/**
 * @param {object} query   req.query, untrusted
 * @returns {Promise<object>} one of the three result shapes above
 */
const startAuthorization = async (query = {}, deps = {}) => {
  const db = deps.supabase || supabase;
  const clientMetadataService = deps.clientMetadataService || clientMetadataServiceModule;

  // --- 1. client-independent shape -----------------------------------------
  const clientId = singleValue(query.client_id);
  if (!isNonEmptyString(clientId)) {
    return refuseDirect('invalid_request', 'client_id_absent');
  }

  const redirectUri = singleValue(query.redirect_uri);
  if (!isNonEmptyString(redirectUri)) {
    // No usable redirect_uri → cannot deliver to client (§4.1.2.1).
    return refuseDirect('invalid_request', 'redirect_uri_absent');
  }

  // ⚠️ DELIBERATE RFC 6749 DEVIATION — syntactic malformations (state length,
  // response_type, PKCE) answer 400 here, ABOVE the outbound fetch. Proving
  // redirect_uri first would fetch a stranger-chosen URL (ticket 45 amplifier).
  // Working-client errors (unsupported scope, wrong resource) stay below the
  // redirect boundary so the assistant can act on them.
  const rawState = singleValue(query.state);
  const state = isNonEmptyString(rawState) ? rawState : null;
  if (state !== null && state.length > MAX_STATE_LENGTH) {
    return refuseDirect('invalid_request', 'state_too_long');
  }

  // RFC 6749 §4.1.2.1: a MISSING required parameter is invalid_request;
  // unsupported_response_type is for a value this server will not honour.
  const responseType = singleValue(query.response_type);
  if (responseType === undefined || responseType === null || responseType === '') {
    return refuseDirect('invalid_request', 'response_type_absent');
  }
  if (responseType !== 'code') {
    return refuseDirect('unsupported_response_type', 'response_type_not_code');
  }

  const codeChallenge = singleValue(query.code_challenge);
  if (!isNonEmptyString(codeChallenge) || !CODE_CHALLENGE_PATTERN.test(codeChallenge)) {
    return refuseDirect('invalid_request', 'code_challenge_invalid');
  }

  // S256 only. Migration 002 CHECKs it too, but a downgrade must be refused
  // with an OAuth error rather than a constraint violation at insert time.
  if (singleValue(query.code_challenge_method) !== 'S256') {
    return refuseDirect('invalid_request', 'code_challenge_method_not_s256');
  }

  // --- 2. resolve the client (ticket 41 whole — do not fork a second fetcher)
  const resolved = await clientMetadataService.fetchAndValidateClientMetadata(clientId, deps);
  if (!resolved.ok) {
    // Authorize endpoint (§4.1.2.1): invalid_request — not token-endpoint
    // invalid_client (§5.2). Detail stays in the log.
    return refuseDirect('invalid_request', resolved.reason);
  }

  // --- 3. prove the redirect_uri (ticket 41 matcher; RFC 8252 loopback) ----
  if (!redirectUriMatcher.matchesAny(resolved.metadata.redirect_uris, redirectUri)) {
    return refuseDirect('invalid_request', 'redirect_uri_not_registered');
  }

  // --- everything past here IS redirected (incl. server_error) -------------
  const redirectFailure = (error, reason) => refuseRedirect(error, reason, redirectUri, state);

  const requestedScopes = introspectionService.parseScope(query.scope);
  if (requestedScopes.length === 0) {
    return redirectFailure('invalid_scope', 'scope_absent');
  }
  const unknownScope = requestedScopes.find((scope) => !SUPPORTED_SCOPES.includes(scope));
  if (unknownScope) {
    return redirectFailure('invalid_scope', 'scope_not_supported');
  }

  // Configured resource only — never from the request.
  const configuredResource = oauthConfig.mcpResourceIdentifier();
  if (!isNonEmptyString(configuredResource)) {
    return redirectFailure('server_error', 'resource_identifier_unset');
  }
  if (singleValue(query.resource) !== configuredResource) {
    return redirectFailure('invalid_target', 'resource_not_issuable');
  }

  // --- 4. persist -----------------------------------------------------------
  // CIMD validates and writes nothing; ticket 36 owns the row for the FK.
  //
  // ⚠️ NEVER unconditional upsert on client_id — that overwrites
  // service_confidential into assistant_public / auth none. CIMD's document
  // refusal does not protect the DB row.
  //
  //   UPDATE ... WHERE client_id = ? AND client_type = 'assistant_public'
  //   -> matched? done.  -> else INSERT.
  //   -> INSERT 23505? RE-RUN UPDATE ONCE (23505 = "a row exists", not whose).
  // Concurrent first-sight: both miss update, A inserts, B collides — retry
  // classifies; without it B false-positives into the security sink.
  // One retry, never a loop. Residual: DELETE between failed insert and retry
  // fails closed. ⚠️ empty .select() after update assumes RLS off (service role).
  const clientRow = {
    client_id: resolved.metadata.client_id,
    token_endpoint_auth_method: 'none',
    display_name: resolved.metadata.display_name,
    redirect_uris: resolved.metadata.redirect_uris,
    updated_at: new Date().toISOString(),
  };

  const updateAssistantRow = () =>
    db
      .from('oauth_clients')
      .update(clientRow)
      .eq('client_id', resolved.metadata.client_id)
      .eq('client_type', 'assistant_public')
      .select('client_id');

  const matchedARow = (data) => Array.isArray(data) && data.length > 0;

  try {
    const { data: updated, error: updateError } = await updateAssistantRow();
    if (updateError) return redirectFailure('server_error', 'client_write_failed');

    if (!matchedARow(updated)) {
      const { error: insertError } = await db
        .from('oauth_clients')
        .insert([{ ...clientRow, client_type: 'assistant_public' }]);

      if (insertError) {
        if (insertError.code !== '23505') {
          return redirectFailure('server_error', 'client_write_failed');
        }

        const { data: retried, error: retryError } = await updateAssistantRow();
        if (retryError) return redirectFailure('server_error', 'client_write_failed');

        // Retry still empty → occupant is not assistant_public.
        if (!matchedARow(retried)) {
          return redirectFailure('server_error', 'client_conflicts_with_non_assistant_row');
        }
      }
    }
  } catch (err) {
    return redirectFailure('server_error', 'client_write_failed');
  }

  const reference = newTransactionReference();
  const csrfToken = newCsrfToken();
  const expiresAt = new Date(Date.now() + TRANSACTION_TTL_SECONDS * 1000).toISOString();

  try {
    const { error } = await db.from('oauth_authorization_transactions').insert([
      {
        transaction_hash: hashTransactionReference(reference), // hash, never the ref
        client_id: resolved.metadata.client_id,
        client_type: 'assistant_public',
        redirect_uri: redirectUri,
        resource: configuredResource,
        scopes: requestedScopes,
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
        state,
        csrf_token_hash: hashTransactionReference(csrfToken),
        bound_user_id: null, // set atomically at approval with consumed/decision
        consumed_at: null,
        decision: null,
        expires_at: expiresAt,
      },
    ]);
    if (error) return redirectFailure('server_error', 'transaction_insert_failed');
  } catch (err) {
    return redirectFailure('server_error', 'transaction_insert_failed');
  }

  return {
    ok: true,
    transactionReference: reference,
    csrfToken,
    expiresAt,
    clientId: resolved.metadata.client_id,
    redirectUri,
    state,
    scopes: requestedScopes,
  };
};

module.exports = {
  startAuthorization,
  hashTransactionReference,
  SUPPORTED_SCOPES,
  TRANSACTION_TTL_SECONDS,
  CODE_CHALLENGE_PATTERN,
  MAX_STATE_LENGTH,
  REFERENCE_BYTES,
  AUTHORIZE_ENDPOINT,
  AUTHORIZE_ERROR_PREFIX,
};
