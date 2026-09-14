const crypto = require('crypto');

const grantRevocationService = require('../services/oauth/grantRevocationService');
const introspectionLog = require('../services/oauth/introspectionLog');

/**
 * DELETE /api/oauth/grants/:grantId — user-initiated disconnection.
 *
 * Platform Bearer + exact Origin (not private_key_jwt). Path carries only the
 * opaque grant uuid — never a CIMD client URL. CSRF/action-binding gap and
 * OAUTH_ROUTES_ENABLED coupling: see routes/oauth.js.
 *
 *   204  disconnected (incl. already disconnected)
 *   404  missing or not yours (indistinguishable)
 *   403  Origin missing / "null" / wrong (middleware)
 *   401  no/invalid bearer (middleware)
 *   503  write failed — never 204 on a failed sweep
 */

// Shape only — keep malformed ids out of PostgREST; not a UUID-version check.
const UUID_SHAPE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// introspectionLog defaults to introspect identity; omit these and a disconnect
// is indexed as mcp_introspection_grant_inactive. Resource is the route
// template (literal ':grantId'), never the interpolated uuid.
const DISCONNECT_EVENT_TYPE = 'mcp_grant_user_disconnected';
const DISCONNECT_RESOURCE = 'DELETE /api/oauth/grants/:grantId';
const DISCONNECT_ERROR_PREFIX = 'oauth_disconnect';

const createDisconnectController = (deps = {}) => {
  const service = deps.grantRevocationService || grantRevocationService;
  const log = deps.introspectionLog || introspectionLog;

  return async (req, res) => {
    const correlationId = req.get ? req.get('x-correlation-id') : undefined;
    const requestId = crypto.randomUUID();
    const userId = req.user && req.user.userId;
    const logContext = {
      correlationId,
      requestId,
      // One object for both sinks; each ignores the keys it does not use.
      endpoint: DISCONNECT_RESOURCE,
      errorPrefix: DISCONNECT_ERROR_PREFIX,
      eventType: DISCONNECT_EVENT_TYPE,
      resource: DISCONNECT_RESOURCE,
    };

    try {
      res.set('Cache-Control', 'no-store');

      const grantId = req.params.grantId;

      // 404 not 400: malformed must match "not yours" (no enumeration leak).
      if (typeof grantId !== 'string' || !UUID_SHAPE.test(grantId)) {
        return res.status(404).json({ error: 'not_found' });
      }

      const result = await service.revokeGrantForUser(grantId, userId, deps);

      if (result.outcome === 'not_found') {
        return res.status(404).json({ error: 'not_found' });
      }

      if (result.outcome === 'failed') {
        // Grant may already be revoked; 503 keeps retry pressure on the sweep.
        // Wrong "failed" costs a retry; wrong "succeeded" leaves credentials live.
        await log.logOperational(
          {
            ...logContext,
            outcome: 'grant_disconnect_failed',
            detail: result.detail,
            httpStatus: 503,
          },
          deps
        );
        return res.status(503).json({ error: 'server_error' });
      }

      await log.logGrantRefusal(
        {
          ...logContext,
          clientId: result.grant.client_id,
          userId: result.grant.user_id,
          detail: result.alreadyRevoked ? 'user_disconnect_already_revoked' : 'user_disconnect',
        },
        deps
      );

      return res.status(204).send();
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
  createDisconnectController,
  UUID_SHAPE,
  DISCONNECT_EVENT_TYPE,
  DISCONNECT_RESOURCE,
  DISCONNECT_ERROR_PREFIX,
};
