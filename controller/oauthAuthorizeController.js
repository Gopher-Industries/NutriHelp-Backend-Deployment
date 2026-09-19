const crypto = require('crypto');

const authorizeTransactionService = require('../services/oauth/authorizeTransactionService');
const introspectionLog = require('../services/oauth/introspectionLog');
const oauthConfig = require('../services/oauth/oauthConfig');

/**
 * GET /api/oauth/authorize — ticket 36. No session / no credential.
 *
 *   302 frontend login   success — query = opaque transaction only
 *   302 redirect_uri     OAuth error once URI proven (incl. our server_error)
 *   400                  refused before proof (malformed / bad client / URI)
 *   503                  issuer unset, or unhandled exception
 *
 * ⚠️ Never put a NutriHelp token in any URL. RFC 9207 `iss` only on
 * client-directed error redirects — not on the frontend hop.
 */

const AUTHORIZE_EVENT_TYPE = 'mcp_authorize_request_refused';
const DEFAULT_LOGIN_PATH = '/login';

/**
 * Attack-shaped reasons → security sink. ⚠️ One layer owns each reason:
 * discovering layer emits. Not listed: client_type_not_dereferenceable (CIMD
 * already emits). Listed: client_inactive (CIMD returns it without logging),
 * redirect_uri_not_registered, client_conflicts_with_non_assistant_row.
 * Ordinary protocol errors stay operational-only.
 */
const SECURITY_EVENT_REASONS = new Set([
  'redirect_uri_not_registered',
  'client_inactive',
  'client_conflicts_with_non_assistant_row',
]);

/**
 * Same-origin path only — no '//', '?', '#'. Refused, not normalised.
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
 * Success redirect base — only after redirect_uri is proven (failures deliver
 * to the client, not JSON 503 to a stranger).
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

  // Control chars can become protocol-relative after WHATWG strip — compare origins.
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
 * Client-directed error: RFC 6749 §3.1.2 (preserve registered query) + RFC 9207 iss.
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

    // Attempted client_id (untrusted, bounded) — useful under amplification.
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

    // Join authorize refusals to CIMD metadata_fetch_refused lines.
    const serviceDeps = { ...deps, correlationId, requestId };

    // Operational always; security when reason is attack-shaped (incl. redirected conflicts).
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
      res.set('Cache-Control', 'no-store');

      // Issuer only above the request — needed for RFC 9207 iss on every
      // client-directed error. Frontend origin/login path resolve AFTER proof
      // so a bad OAUTH_FRONTEND_ORIGIN cannot turn invalid_scope into JSON 503.
      const issuer = config.mcpAccessTokenIssuer();
      if (!issuer) return await unavailable('issuer_unset');

      const result = await service.startAuthorization(req.query, serviceDeps);

      if (result.ok) {
        const base = resolveFrontendBase(config);
        if (!base.ok) {
          await recordRefusal('authorize_refused_redirect', base.reason, 302);
          return redirectToClient(res, result.redirectUri, 'server_error', result.state, issuer);
        }

        const destination = new URL(base.url.href);
        destination.searchParams.set('transaction', result.transactionReference);
        destination.searchParams.set('csrf_token', result.csrfToken);
        return res.redirect(302, destination.href);
      }

      if (result.redirectable) {
        await recordRefusal('authorize_refused_redirect', result.reason, 302);
        return redirectToClient(res, result.redirectUri, result.error, result.state, issuer);
      }

      await recordRefusal('authorize_refused_direct', result.reason, 400);
      // Reason stays in the log — do not describe the registry to the browser.
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
