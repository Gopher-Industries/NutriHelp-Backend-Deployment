const crypto = require('crypto');

const supabase = require('../../dbConnection');
const clientMetadataServiceModule = require('./clientMetadataService');
const redirectUriMatcher = require('./redirectUriMatcher');
const introspectionService = require('./introspectionService');
const oauthConfig = require('./oauthConfig');

/**
 * Authorization request intake (ticket 36).
 *
 * The browser arrives here redirected from the assistant, carrying NOTHING
 * that identifies the user: the web app keeps its platform token in browser
 * storage and there is no login cookie. So this service never tries to resolve
 * a user. It validates the request, persists it, and hands back an opaque
 * reference for the frontend login page to carry.
 *
 * The ordering below is the security property, not a style choice:
 *
 *   1. every check that does not depend on the client — including PKCE and
 *      response_type, which sit here so a malformed request costs no fetch
 *   2. resolve the client through CIMD (ticket 41)   <-- the outbound fetch
 *   3. match redirect_uri against that client's registered list
 *   --- past here EVERY failure is redirected to redirect_uri, 503s included ---
 *   4. everything that needed a resolved client, then persistence
 *
 * A failure redirected before step 3 completes is an open redirector, and
 * hands the OAuth error response to whoever chose the URL. A failure answered
 * directly AFTER step 3 is the opposite mistake: the assistant is told nothing
 * and the user is stranded mid-flow. Both have been live bugs in this file.
 *
 * ⚠️ Never add a column for the platform bearer token. Migration 002 has none
 * and the table comment says why.
 */

/** From the contract's Scopes table. Coarse and per-capability, by design. */
const SUPPORTED_SCOPES = ['nutrition:read', 'mealplan:read', 'meallog:write'];

/**
 * Long enough for a human to find their password, short enough that a
 * reference leaked through browser history is usually already dead.
 * Authorization codes are 60s; this one has to span a login.
 */
const TRANSACTION_TTL_SECONDS = 600;

/** RFC 7636 §4.2: 43-128 chars of unreserved. 43 is the SHA-256 case. */
const CODE_CHALLENGE_PATTERN = /^[A-Za-z0-9\-._~]{43,128}$/;

/**
 * `state` is attacker-chosen, stored, and reflected into a redirect URL. RFC
 * 6749 sets no limit; this one is ours. Generous next to any real client's
 * nonce, small next to anything worth calling an amplifier.
 */
const MAX_STATE_LENGTH = 512;

/** 32 bytes — the reference must not be cheaper to guess than the code. */
const REFERENCE_BYTES = 32;

const AUTHORIZE_ENDPOINT = 'GET /api/oauth/authorize';
const AUTHORIZE_ERROR_PREFIX = 'oauth_authorize';

const isNonEmptyString = (value) => typeof value === 'string' && value.trim() !== '';

/**
 * Refusal the caller must answer directly — redirect_uri is not yet proven.
 *
 * Always 400, and the shape carries no status at all on purpose. It used to
 * take a status parameter so server-side failures could answer 503 from below
 * the redirect boundary; those all redirect now. Both the parameter AND the
 * field are gone: leaving an inert `httpStatus` behind would be worse than the
 * unreachable branch it fed, because someone setting it on a future variant
 * would see it silently ignored. The controller answers 400 for every direct
 * refusal, and there is nothing here for it to read.
 */
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

/**
 * Only a single query value is ever accepted. Express gives an array when a
 * key repeats; taking the first silently would let a caller smuggle a second
 * redirect_uri past a check that only read one of them.
 *
 * `scope` is the ONE deliberate exception and does not go through this: it is
 * a space-delimited list, so the repeated-key form is a legitimate spelling of
 * the same value. Accepting both cannot escalate — every element is still
 * filtered against SUPPORTED_SCOPES below, and a request can only ever narrow
 * to what the user later approves. Pinned by the "accepts the repeated-key
 * array form of scope" test.
 *
 * Precisely: parseScope splits a STRING on whitespace, and for an ARRAY takes
 * the elements as-is WITHOUT splitting them. So ?scope=a&scope=b works, while
 * the mixed ?scope=a+b&scope=c would yield the element "a b", which fails
 * SUPPORTED_SCOPES and refuses. That is fail-closed and fine; it is not a
 * merge, and describing it as one overstates what the helper does.
 * introspectionService.parseScope is shared with the token-exchange path, so
 * it is not changed from here.
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
    // RFC 6749 §4.1.2.1: with no usable redirect_uri the error cannot be
    // delivered to the client, so it is shown here instead.
    return refuseDirect('invalid_request', 'redirect_uri_absent');
  }

  // ⚠️ DELIBERATE RFC 6749 DEVIATION — the three checks below answer 400
  // DIRECTLY rather than redirecting to redirect_uri, and they sit here, ABOVE
  // the outbound fetch, on purpose.
  //
  // Delivering them as redirects would mean proving redirect_uri first, which
  // means dereferencing a stranger-chosen URL first. That is the amplifier
  // ticket 45 exists to contain: without this, a request with a garbage
  // response_type still costs a real outbound GET to a host the caller picked.
  // Rate limits bound that, but every request pays a fetch until a bucket
  // trips.
  //
  // The trade is narrow and it is only taken for SYNTACTICALLY malformed
  // requests. A client sending response_type != 'code', no PKCE challenge, or
  // a downgraded method is broken, not unlucky; a clear 400 serves it as well
  // as a redirect would. Refusing early creates no open redirect — refusing is
  // not redirecting.
  //
  // Errors a WORKING client can legitimately hit (unsupported scope, wrong
  // resource) stay below the redirect boundary, where they reach the assistant
  // and it can tell the user what happened.
  //
  // `state` is checked here for the same reason and one extra one: it is the
  // client's OWN nonce, so an over-long state is the client being broken about
  // its own value. Refusing it below the boundary would also have been futile
  // — the error could not carry the offending state back, and a client that
  // receives an error with no state cannot match it to a pending request and
  // must drop it. That is paying an outbound fetch to deliver something the
  // client is obliged to ignore.
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

  // --- 2. resolve the client ------------------------------------------------
  // Reuses ticket 41 whole: SSRF address guard, no redirects, size cap, one
  // deadline, and the service_confidential refusal. A second fetcher here
  // would be a second list to keep in step.
  const resolved = await clientMetadataService.fetchAndValidateClientMetadata(clientId, deps);
  if (!resolved.ok) {
    // `invalid_request`, not `invalid_client`. RFC 6749 §5.2's `invalid_client`
    // belongs to the TOKEN endpoint; the authorization endpoint's set (§4.1.2.1)
    // is invalid_request, unauthorized_client, access_denied,
    // unsupported_response_type, invalid_scope, server_error and
    // temporarily_unavailable. The specific reason is in the log either way.
    return refuseDirect('invalid_request', resolved.reason);
  }

  // --- 3. prove the redirect_uri -------------------------------------------
  // The single matcher, shared with ticket 41. Exact match, with only the
  // RFC 8252 loopback-port exception.
  if (!redirectUriMatcher.matchesAny(resolved.metadata.redirect_uris, redirectUri)) {
    return refuseDirect('invalid_request', 'redirect_uri_not_registered');
  }

  // --- everything past here IS redirected to the client --------------------
  // No exceptions below this line, including server-side failures. The comment
  // used to say "may be", and three 503s underneath it answered the browser
  // directly — which strands the user mid-flow with the assistant given no
  // OAuth error it can read. RFC 6749 §4.1.2.1 has `server_error` for exactly
  // this and expects it at the validated redirect_uri.
  const redirectFailure = (error, reason) => refuseRedirect(error, reason, redirectUri, state);

  const requestedScopes = introspectionService.parseScope(query.scope);
  if (requestedScopes.length === 0) {
    return redirectFailure('invalid_scope', 'scope_absent');
  }
  const unknownScope = requestedScopes.find((scope) => !SUPPORTED_SCOPES.includes(scope));
  if (unknownScope) {
    return redirectFailure('invalid_scope', 'scope_not_supported');
  }

  // Configured, never derived from the request — same rule as the assertion
  // audience in oauthConfig.
  const configuredResource = oauthConfig.mcpResourceIdentifier();
  if (!isNonEmptyString(configuredResource)) {
    // Our misconfiguration, but it is delivered to the client: the assistant
    // cannot act on a 503 it never sees.
    return redirectFailure('server_error', 'resource_identifier_unset');
  }
  if (singleValue(query.resource) !== configuredResource) {
    return redirectFailure('invalid_target', 'resource_not_issuable');
  }

  // --- 4. persist -----------------------------------------------------------
  // The client row must exist before the transaction's composite FK can
  // resolve. clientMetadataService validates and deliberately writes nothing;
  // ticket 36 owns this write.
  //
  // ⚠️ NEVER make this an unconditional upsert on client_id. It used to be, and
  // that would UPDATE an existing service_confidential row — the MCP server's
  // own client — into client_type 'assistant_public' with auth method 'none',
  // silently breaking private_key_jwt.
  //
  // The CIMD layer's confidential refusal does NOT defend this. That inspects
  // the fetched DOCUMENT; this writes a database ROW. Two different objects,
  // and nothing there constrains what is already stored under that key. It was
  // a check on one thing standing in for a check on another, with a TOCTOU
  // window between them that any concurrent admin insert lands in.
  //
  // So the write is conditional:
  //   UPDATE ... WHERE client_id = ? AND client_type = 'assistant_public'
  //   -> a row matched? done.
  //   -> no row matched? INSERT.
  //   -> INSERT hits the primary key (23505)? RE-RUN THE UPDATE ONCE, then
  //      decide.
  //
  // ⚠️ THAT RETRY IS NOT OPTIONAL, and the reason is a direction that is easy
  // to get backwards. It is true that the insert cannot SUCCEED against a row
  // the update would not have matched. The direction that matters is the
  // converse: the insert CAN FAIL against a row the update WOULD have matched,
  // because the row can be created between the two statements.
  //
  // Two concurrent first-sight requests for the same new assistant do exactly
  // that — both updates match nothing, A inserts, B collides. Without the
  // retry B is refused for a legitimate request AND, because this reason is
  // security-logged, a false record is written claiming B named a client id
  // belonging to something else. A false positive in the one sink that exists
  // to flag real attack shapes.
  //
  // So 23505 means only "a row now exists". The SECOND UPDATE is what
  // distinguishes whose it is: it matches, and we proceed, only if the row is
  // assistant_public.
  //
  // ONE retry, never a loop, and one is enough: 23505 proves a row exists, and
  // the second UPDATE classifies it, so a further retry could only re-ask a
  // question already answered. The accepted residual is the other way round —
  // if the row were DELETED between the failed insert and the retry, the retry
  // matches nothing and the request is refused as a conflict it is not. That
  // needs an insert and a delete inside microseconds, it fails CLOSED, and
  // looping to chase it would trade a rare false refusal for an unbounded one.
  //
  // ⚠️ `matched.length === 0` carries more weight than it looks like. If RLS
  // were ever enabled on oauth_clients with a policy that hides rows from
  // .select(), this select would return [] even after a successful update and
  // every request would fall into a permanent false conflict. RLS is off here
  // (the service-role key bypasses it), but that is the assumption this
  // depends on.
  const clientRow = {
    client_id: resolved.metadata.client_id,
    // The CHECK pairs this with assistant_public; ticket 41 already refused
    // any document declaring anything else.
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
        // 23505 = the client_id primary key is occupied. That is ALL it means;
        // it does not say by whom. See the note above.
        if (insertError.code !== '23505') {
          return redirectFailure('server_error', 'client_write_failed');
        }

        const { data: retried, error: retryError } = await updateAssistantRow();
        if (retryError) return redirectFailure('server_error', 'client_write_failed');

        // Still nothing to update, so the occupying row is not an assistant
        // client. Now the conflict is established rather than assumed.
        if (!matchedARow(retried)) {
          return redirectFailure('server_error', 'client_conflicts_with_non_assistant_row');
        }
        // Otherwise a concurrent first-sight insert won the race and the row
        // it created is one of ours. Carry on.
      }
    }
  } catch (err) {
    return redirectFailure('server_error', 'client_write_failed');
  }

  const reference = newTransactionReference();
  const expiresAt = new Date(Date.now() + TRANSACTION_TTL_SECONDS * 1000).toISOString();

  try {
    const { error } = await db.from('oauth_authorization_transactions').insert([
      {
        // The hash, never the reference. A dump of this table yields nothing
        // a browser could present.
        transaction_hash: hashTransactionReference(reference),
        client_id: resolved.metadata.client_id,
        client_type: 'assistant_public',
        redirect_uri: redirectUri,
        resource: configuredResource,
        scopes: requestedScopes,
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
        state,
        // Ticket 37 mints the CSRF token when it renders the consent summary.
        csrf_token_hash: null,
        // Set atomically at approval, never here: the two CHECK constraints in
        // migration 002 read these three together.
        bound_user_id: null,
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
