const errorLogService = require('../errorLogService');
const securityEventService = require('../securityEventService');

/**
 * Two sinks: operational (transport/contract faults) vs security (verified
 * but inactive grant). Never log token or assertion values. Logging never
 * fails the request.
 */

const swallow = () => {};

/**
 * @param {object} context
 * @param {string} context.correlationId
 * @param {string} context.requestId
 */
const logOperational = async (context, deps = {}) => {
  const service = deps.errorLogService || errorLogService;
  const { correlationId, requestId, outcome, detail, httpStatus, clientId } = context;

  try {
    await service.logError({
      error: new Error(`oauth_introspect:${outcome}`),
      // Repo vocabulary is critical|warning|info|minor; only 'critical' alerts.
      category: httpStatus >= 500 ? 'critical' : 'warning',
      type: 'system',
      additionalContext: {
        endpoint: 'POST /api/oauth/introspect',
        correlation_id: correlationId || null,
        request_id: requestId,
        outcome,
        detail: detail || null,
        http_status: httpStatus,
        client_id: clientId || null,
      },
    });
  } catch (err) {
    swallow(err);
  }
};

const logGrantRefusal = async (context, deps = {}) => {
  const service = deps.securityEventService || securityEventService;
  const { correlationId, requestId, detail, clientId, userId } = context;

  try {
    await service.logSecurityEvent({
      event_type: 'mcp_introspection_grant_inactive',
      severity: 'medium',
      user_id: userId || null,
      resource: 'POST /api/oauth/introspect',
      metadata: {
        correlation_id: correlationId || null,
        request_id: requestId,
        detail: detail || null,
        client_id: clientId || null,
      },
    });
  } catch (err) {
    swallow(err);
  }
};

module.exports = { logOperational, logGrantRefusal };
