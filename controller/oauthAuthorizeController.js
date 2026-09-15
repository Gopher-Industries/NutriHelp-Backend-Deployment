const crypto = require('crypto');

const authorizeTransactionService = require('../services/oauth/authorizeTransactionService');
const introspectionLog = require('../services/oauth/introspectionLog');
const oauthConfig = require('../services/oauth/oauthConfig');

/**
 * GET /api/oauth/authorize — ticket 36.
 *
 * Infers no browser session and reads no credential. The browser is redirected
 * here from the assistant with nothing identifying the user, so the endpoint
 * persists the request and bounces to the frontend login page carrying only an
 * opaque reference.
 *
 *   302 -> frontend login   request accepted, reference in the query
 *   302 -> redirect_uri     OAuth error, only once that URI is proven — and
 *                           that includes OUR failures: a bad resource
 *                           identifier, a broken frontend config, a failed
 *                           write. Past the proof, the client is told.
 *   400                     malformed request, bad client, or unregistered
 *                           redirect_uri — everything refused BEFORE the proof
 *   503                     the issuer is unconfigured, or an unhandled
 *                           exception. Nothing else.
 *
 * ⚠️ NEVER put a NutriHelp token in any of these URLs. The frontend redirect
 * carries the transaction reference and nothing else — the contract's wording
 * is "only the opaque identifier", and a second parameter is how request
 * details start leaking through Referer and browser history.
 *
 * The RFC 9207 `iss` goes on client-directed responses, which at this endpoint
 * means the error redirects; correct clients reject an authorization response
 * that arrives without it. The frontend redirect is not a client-directed
 * authorization response and deliberately does not carry it.
 */

const AUTHORIZE_EVENT_TYPE = 'mcp_authorize_request_refused';
const DEFAULT_LOGIN_PATH = '/login';

/**
 * Refusal reasons that get a security-sink record, not just an operational
 * line — the ones where the caller named something that is not theirs.
 *
 * ⚠️ ONE LAYER OWNS EACH REASON. `client_type_not_dereferenceable` is
 * deliberately NOT here: clientMetadataService already raises its own
 * DEREFERENCE_REFUSED_EVENT for it, and listing it here too produced two
 * security records for one attempt. A sink that double-counts is a sink whose
 * numbers cannot be trusted, so the rule is: the layer that DISCOVERS a
 * refusal emits it. This controller discovers redirect_uri_not_registered and
 * the client-row conflict; the CIMD layer discovers everything about the
 * document. `client_inactive` stays here because that layer returns it without
 * logging, so removing it would lose the record entirely rather than
 * de-duplicate it.
 *
 * The redirected failures (bad scope, bad resource, malformed PKCE) are
 * ordinary protocol errors, not attack shapes, and stay operational-only.
 */
const SECURITY_EVENT_REASONS = new Set([
  'redirect_uri_not_registered',
  'client_inactive',
  'client_conflicts_with_non_assistant_row',
]);

/**
 * A configured path, never a URL and never a query.
 *
 * '//host' and 'https://host' both redirect off-origin. A '?' or '#' is a
 * quieter failure of the same kind: '/login?next=/x' would produce
 * '?next=/x&transaction=…', and the one property this redirect has to keep is
 * that it carries the opaque identifier and nothing else. Refused rather than
 * normalised — silently stripping an operator's query would be its own
 * surprise.
 */
const readLoginPath = () => {
  const raw = process.env.OAUTH_FRONTEND_LOGIN_PATH;
  if (typeof raw !== 'string' || raw.trim() === '') return DEFAULT_LOGIN_PATH;
  const trimmed = raw.trim();
  if (!trimmed.startsWith('/') || trimmed.startsWith('//')) return null;
  if (trimmed.includes('?') || trimmed.includes('#')) return null;
  return trimmed;
};

/**
 * Resolves where the browser is sent on success. Called only AFTER
 * redirect_uri is proven, so every failure it reports is deliverable to the
 * client rather than shown to a stranger's browser as a 503.
 *
 * @returns {{ok: true, url: URL} | {ok: false, reason: string}}
 */
const resolveFrontendBase = (config) => {
  const frontendOrigin = config.frontendOrigin();
  if (!frontendOrigin) return { ok: false, reason: 'frontend_origin_unset' };

  const loginPath = readLoginPath();
  if (loginPath === null) return { ok: false, reason: 'login_path_not_relative' };

  let url;
  try {
    url = new URL(loginPath, frontendOrigin);
  } catch (err) {
    return { ok: false, reason: 'frontend_origin_unparseable' };
  }

  // A control character in the path can make it protocol-relative once WHATWG
  // parsing strips the character, so compare the resulting origin rather than
  // trusting readLoginPath's string checks alone.
  let configuredOrigin;
  try {
    configuredOrigin = new URL(frontendOrigin).origin;
  } catch (err) {
    return { ok: false, reason: 'frontend_origin_unparseable' };
  }
  if (url.origin !== configuredOrigin) return { ok: false, reason: 'login_path_changes_origin' };

  return { ok: true, url };
};

/**
 * The one place a client-directed error response is built. RFC 6749 §3.1.2:
 * start from the registered URI so a query string it already carries survives.
 * RFC 9207: `iss` on every client-directed response.
 */
const redirectToClient = (res, redirectUri, error, state, issuer) => {
  const destination = new URL(redirectUri);
  destination.searchParams.set('error', error);
  if (state !== null && state !== undefined) destination.searchParams.set('state', state);
  destination.searchParams.set('iss', issuer);
  return res.redirect(302, destination.href);
};

const createAuthorizeController = (deps = {}) => {
  const service = deps.authorizeTransactionService || authorizeTransactionService;
  const log = deps.introspectionLog || introspectionLog;
  const config = deps.oauthConfig || oauthConfig;

  return async (req, res) => {
    const correlationId = req.get ? req.get('x-correlation-id') : undefined;
    const requestId = crypto.randomUUID();

    // The abused client_id is the single most useful field under the
    // amplification attack the rate buckets exist to bound, so it is recorded
    // on every line rather than only on success. Untrusted and unvalidated at
    // this point — it is evidence of what was attempted, not an assertion that
    // the client exists. Bounded so a huge query value cannot bloat the sink.
    const attemptedClientId =
      typeof req.query.client_id === 'string' ? req.query.client_id.slice(0, 512) : null;

    const logContext = {
      correlationId,
      requestId,
      clientId: attemptedClientId,
      endpoint: authorizeTransactionService.AUTHORIZE_ENDPOINT,
      errorPrefix: authorizeTransactionService.AUTHORIZE_ERROR_PREFIX,
      eventType: AUTHORIZE_EVENT_TYPE,
      resource: authorizeTransactionService.AUTHORIZE_ENDPOINT,
    };

    // correlationId/requestId must reach the CIMD layer too, or its
    // metadata_fetch_refused lines carry correlation_id: null and cannot be
    // joined to the authorize refusal that caused them.
    const serviceDeps = { ...deps, correlationId, requestId };

    /**
     * One operational line for every refusal, plus a security record when the
     * reason is attack-shaped.
     *
     * Both branches go through here because the attack shapes are no longer
     * all on one side: the client-row conflict is delivered as a REDIRECT
     * (blocker 2 — past the redirect_uri proof, even server errors reach the
     * client), while redirect_uri_not_registered is still answered directly.
     * Keying the security emit off the branch instead of the reason would
     * silently drop the conflict record.
     *
     * logOperational drops eventType and resource, so the security sink is
     * only reached by the explicit logGrantRefusal call.
     */
    const recordRefusal = async (outcome, reason, httpStatus) => {
      await log.logOperational({ ...logContext, outcome, detail: reason, httpStatus }, deps);
      if (SECURITY_EVENT_REASONS.has(reason)) {
        await log.logGrantRefusal({ ...logContext, userId: null, detail: reason }, deps);
      }
    };

    const unavailable = async (detail) => {
      await log.logOperational(
        { ...logContext, outcome: 'authorize_unavailable', detail, httpStatus: 503 },
        deps
      );
      return res.status(503).json({ error: 'server_error' });
    };

    try {
      // Redirects are cacheable by default and this one carries a credential-
      // shaped reference.
      res.set('Cache-Control', 'no-store');

      // ISSUER ONLY. This is the one config value that must be resolved before
      // the request is processed, because every client-directed error carries
      // RFC 9207 `iss` and a compliant client rejects an authorization
      // response that arrives without it. With no issuer there is no way to
      // produce a deliverable error at all, so 503 here is the honest answer.
      //
      // ⚠️ NOTHING ELSE BELONGS ABOVE THIS CALL. The frontend origin and login
      // path are needed only to build the SUCCESS redirect, and hoisting them
      // meant a misconfigured OAUTH_FRONTEND_ORIGIN turned every refusal —
      // including an ordinary invalid_scope from a correctly registered client
      // — into a JSON 503 the assistant could not read. That is the same
      // failure the service's own redirect boundary exists to prevent, so the
      // controller must not reintroduce it one layer up.
      const issuer = config.mcpAccessTokenIssuer();
      if (!issuer) return await unavailable('issuer_unset');

      const result = await service.startAuthorization(req.query, serviceDeps);

      if (result.ok) {
        // Resolved HERE, not earlier: by this point redirect_uri is proven, so
        // a configuration failure can still be delivered to the client.
        const base = resolveFrontendBase(config);
        if (!base.ok) {
          await recordRefusal('authorize_refused_redirect', base.reason, 302);
          return redirectToClient(res, result.redirectUri, 'server_error', result.state, issuer);
        }

        const destination = new URL(base.url.href);
        destination.searchParams.set('transaction', result.transactionReference);
        return res.redirect(302, destination.href);
      }

      if (result.redirectable) {
        await recordRefusal('authorize_refused_redirect', result.reason, 302);
        return redirectToClient(res, result.redirectUri, result.error, result.state, issuer);
      }

      // Every direct refusal is a 400. There used to be a `status === 503`
      // branch here for server-side failures the service answered directly;
      // those all redirect now, so the branch became unreachable and was
      // removed rather than left reading as though it still did something.
      await recordRefusal('authorize_refused_direct', result.reason, 400);
      // The reason stays in the log. The browser is a stranger's browser here
      // and the detail would describe our client registry back to them.
      return res.status(400).json({ error: result.error });
    } catch (err) {
      // Express 4 does not route rejected promises to the error handler.
      await log.logOperational(
        {
          ...logContext,
          outcome: 'unhandled_exception',
          detail: err && err.name ? String(err.name).slice(0, 64) : 'unknown',
          httpStatus: 503,
        },
        deps
      );
      if (res.headersSent) return undefined;
      return res.status(503).json({ error: 'server_error' });
    }
  };
};

module.exports = {
  createAuthorizeController,
  readLoginPath,
  AUTHORIZE_EVENT_TYPE,
  DEFAULT_LOGIN_PATH,
};
