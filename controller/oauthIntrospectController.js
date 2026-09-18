const crypto = require('crypto');

const clientAssertionVerifier = require('../services/oauth/clientAssertionVerifier');
const introspectionService = require('../services/oauth/introspectionService');
const introspectionLog = require('../services/oauth/introspectionLog');

/**
 * POST /api/oauth/introspect — RFC 7662, private_key_jwt.
 *
 * Inactive → 200 {"active": false}, NEVER 401. MCP maps non-2xx to retryable
 * upstream_failure, so 401-on-inactive leaves a disconnected user still connected.
 * 401 means assertion auth failed only.
 *
 *   200  active or inactive
 *   400  malformed request
 *   401  private_key_jwt failed / replayed
 *   503  could not establish an answer (never active:false)
 *
 * Any authenticated service_confidential client may introspect any token
 * (RFC 7662). Safe with one confidential client; a second needs an explicit policy.
 */

const setNoStore = (res) => {
  res.set('Cache-Control', 'no-store');
  res.set('Pragma', 'no-cache');
};

/** Factory binds deps once so Express keeps `next` as the third handler arg. */
const createIntrospectController = (deps = {}) => {
  const assertionVerifier = deps.clientAssertionVerifier || clientAssertionVerifier;
  const service = deps.introspectionService || introspectionService;
  const log = deps.introspectionLog || introspectionLog;

  // Express 4 does not route rejected promises to the error handler — catch
  // everything and answer 503 rather than hanging the socket until timeout.
  return async (req, res) => {
    const correlationId = req.get ? req.get('x-correlation-id') : undefined;
    const requestId = crypto.randomUUID();
    const logContext = { correlationId, requestId };

    try {
      setNoStore(res);

      const body = req.body || {};

      const authentication = await assertionVerifier.verifyClientAssertion(body, deps);

      if (!authentication.ok) {
        await log.logOperational(
          {
            ...logContext,
            outcome: authentication.reason,
            detail: authentication.detail,
            httpStatus: authentication.httpStatus,
          },
          deps
        );
        return res.status(authentication.httpStatus).json({ error: authentication.reason });
      }

      const clientId = authentication.clientId;

      // Purge must not fail the request, but a failed release-gate purge must be visible.
      if (authentication.purge && authentication.purge.error) {
        await log.logOperational(
          {
            ...logContext,
            clientId,
            outcome: 'jti_purge_failed',
            detail: 'replay_store_purge_error',
            httpStatus: 200,
          },
          deps
        );
      }

      // RFC 7662: the access-token VALUE. A jti alone is not introspection.
      const token = body.token;
      if (typeof token !== 'string' || token.trim() === '') {
        await log.logOperational(
          {
            ...logContext,
            clientId,
            outcome: 'invalid_request',
            detail: 'token_parameter_absent',
            httpStatus: 400,
          },
          deps
        );
        return res.status(400).json({ error: 'invalid_request' });
      }

      const result = await service.introspect(token, deps);

      // Diagnostics only — must not change the answer.
      for (const notice of result.notices || []) {
        await log.logOperational(
          {
            ...logContext,
            clientId,
            outcome: notice,
            detail: 'token_diagnostic',
            httpStatus: 200,
          },
          deps
        );
      }

      if (result.outcome === 'unavailable') {
        await log.logOperational(
          {
            ...logContext,
            clientId,
            outcome: 'introspection_unavailable',
            detail: result.detail,
            httpStatus: 503,
          },
          deps
        );
        return res.status(503).json({ error: 'server_error' });
      }

      if (result.outcome === 'inactive') {
        await log.logGrantRefusal(
          {
            ...logContext,
            clientId,
            detail: result.detail,
            userId: result.userId === undefined ? null : result.userId,
          },
          deps
        );
        return res.status(200).json({ active: false });
      }

      return res.status(200).json(result.body);
    } catch (err) {
      await log.logOperational(
        {
          ...logContext,
          outcome: 'unhandled_exception',
          // Error messages can be caller-influenced; only the name travels.
          detail: err && err.name ? String(err.name).slice(0, 64) : 'unknown',
          httpStatus: 503,
        },
        deps
      );
      if (res.headersSent) return undefined;
      setNoStore(res);
      return res.status(503).json({ error: 'server_error' });
    }
  };
};

const defaultHandler = createIntrospectController();

const introspect = (req, res, deps) =>
  deps && Object.keys(deps).length > 0
    ? createIntrospectController(deps)(req, res)
    : defaultHandler(req, res);

module.exports = { introspect, createIntrospectController };
