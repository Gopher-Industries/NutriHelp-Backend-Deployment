const crypto = require('crypto');

const clientAssertionVerifier = require('../services/oauth/clientAssertionVerifier');
const tokenExchangeService = require('../services/oauth/tokenExchangeService');
const introspectionLog = require('../services/oauth/introspectionLog');

/**
 * POST /api/oauth/token.
 *
 * Inactive grant → 400 invalid_grant here (introspection answers 200 active:false).
 * Errors: RFC 6749 §5.2 + invalid_target. Never insufficient_scope/403.
 *
 * 39a: exchange only. 39b adds authorization_code / refresh_token beside it.
 * Unknown grant_type is refused before client auth (avoids consuming a jti).
 */

const EXCHANGE_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:token-exchange';
const ACCESS_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token';

const TOKEN_ENDPOINT = 'POST /api/oauth/token';
const TOKEN_ERROR_PREFIX = 'oauth_token';
const EXCHANGE_ANOMALY_EVENT = 'mcp_token_exchange_refused_after_verification';

const ERROR_STATUS = Object.freeze({
  invalid_request: 400,
  invalid_grant: 400,
  invalid_scope: 400,
  invalid_target: 400,
  unauthorized_client: 400,
  unsupported_grant_type: 400,
  invalid_client: 401,
});

const setNoStore = (res) => {
  res.set('Cache-Control', 'no-store');
  res.set('Pragma', 'no-cache');
};

const isNonEmptyString = (value) => typeof value === 'string' && value.trim() !== '';

const createTokenController = (deps = {}) => {
  const assertionVerifier = deps.clientAssertionVerifier || clientAssertionVerifier;
  const exchangeService = deps.tokenExchangeService || tokenExchangeService;
  const log = deps.introspectionLog || introspectionLog;

  const logOperational = (context) =>
    log.logOperational(
      { ...context, endpoint: TOKEN_ENDPOINT, errorPrefix: TOKEN_ERROR_PREFIX },
      deps
    );

  const sendError = async (res, context, error, detail, httpStatus) => {
    await logOperational({ ...context, outcome: error, detail, httpStatus });
    setNoStore(res);
    return res.status(httpStatus).json({ error });
  };

  const handleTokenExchange = async (req, res, context) => {
    const body = req.body || {};

    // Must pass AUDIENCE_TOKEN_ENDPOINT — shared verifier defaults to introspect.
    const authentication = await assertionVerifier.verifyClientAssertion(body, {
      ...deps,
      assertionAudience: clientAssertionVerifier.AUDIENCE_TOKEN_ENDPOINT,
    });

    if (!authentication.ok) {
      await logOperational({
        ...context,
        outcome: authentication.reason,
        detail: authentication.detail,
        httpStatus: authentication.httpStatus,
      });
      setNoStore(res);
      return res.status(authentication.httpStatus).json({ error: authentication.reason });
    }

    const clientId = authentication.clientId;
    const withClient = { ...context, clientId };

    if (authentication.purge && authentication.purge.error) {
      await logOperational({
        ...withClient,
        outcome: 'jti_purge_failed',
        detail: 'replay_store_purge_error',
        httpStatus: 200,
      });
    }

    const result = await exchangeService.exchange(body, {
      ...deps,
      actorClientId: clientId,
    });

    if (result.outcome === 'unavailable') {
      await logOperational({
        ...withClient,
        outcome: 'exchange_unavailable',
        detail: result.detail,
        httpStatus: 503,
      });
      setNoStore(res);
      return res.status(503).json({ error: 'server_error' });
    }

    if (result.outcome === 'refused') {
      const httpStatus = ERROR_STATUS[result.error] || 400;

      // Anomaly only when OUR key verified the subject token and we still refused.
      if (result.subjectTokenVerified) {
        try {
          await log.logGrantRefusal(
            {
              ...withClient,
              detail: result.detail,
              userId: result.userId === undefined ? null : result.userId,
              eventType: EXCHANGE_ANOMALY_EVENT,
              resource: TOKEN_ENDPOINT,
            },
            deps
          );
        } catch (err) {
          // Logging never fails the request.
        }
      }

      return sendError(res, withClient, result.error, result.detail, httpStatus);
    }

    setNoStore(res);
    return res.status(200).json({
      access_token: result.credential,
      issued_token_type: ACCESS_TOKEN_TYPE,
      token_type: 'Bearer',
      expires_in: result.expiresIn,
      scope: result.scope,
    });
  };

  const GRANT_HANDLERS = Object.freeze({
    [EXCHANGE_GRANT_TYPE]: handleTokenExchange,
  });

  return async (req, res) => {
    const correlationId = req.get ? req.get('x-correlation-id') : undefined;
    const requestId = crypto.randomUUID();
    const context = { correlationId, requestId };

    try {
      setNoStore(res);

      const grantType = (req.body || {}).grant_type;

      if (!isNonEmptyString(grantType)) {
        return await sendError(res, context, 'invalid_request', 'grant_type_absent', 400);
      }

      const handler = GRANT_HANDLERS[grantType];
      if (!handler) {
        return await sendError(
          res,
          context,
          'unsupported_grant_type',
          'grant_type_not_implemented',
          400
        );
      }

      return await handler(req, res, context);
    } catch (err) {
      await logOperational({
        ...context,
        outcome: 'unhandled_exception',
        detail: err && err.name ? String(err.name).slice(0, 64) : 'unknown',
        httpStatus: 503,
      });
      if (res.headersSent) return undefined;
      setNoStore(res);
      return res.status(503).json({ error: 'server_error' });
    }
  };
};

const defaultHandler = createTokenController();

const token = (req, res, deps) =>
  deps && Object.keys(deps).length > 0
    ? createTokenController(deps)(req, res)
    : defaultHandler(req, res);

module.exports = {
  token,
  createTokenController,
  EXCHANGE_GRANT_TYPE,
  TOKEN_ENDPOINT,
  TOKEN_ERROR_PREFIX,
  EXCHANGE_ANOMALY_EVENT,
};
