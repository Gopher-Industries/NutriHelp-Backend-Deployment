const errorLogService = require('../errorLogService');
const securityEventService = require('../securityEventService');

/**
 * Operational vs security sinks. Never log token/assertion values. Logging
 * never fails the request.
 *
 * Event identity is parameterized (defaults = introspection) so ticket 42
 * callers stay byte-identical. Disconnect MUST pass its own — auditors filter
 * on those fields; metadata.detail does not reach them.
 *
 * Never add a key to additionalContext: oauthIntrospect.endpoint.test.js pins
 * the exact key set (richer context is how `req`/credentials leak in).
 */

const INTROSPECT_ENDPOINT = 'POST /api/oauth/introspect';
const INTROSPECT_ERROR_PREFIX = 'oauth_introspect';
const GRANT_INACTIVE_EVENT = 'mcp_introspection_grant_inactive';

const swallow = () => {};

/**
 * @param {object} context
 * @param {string} context.correlationId
 * @param {string} context.requestId
 * @param {string} [context.endpoint]     defaults to the introspect endpoint
 * @param {string} [context.errorPrefix]  defaults to 'oauth_introspect'
 */
const logOperational = async (context, deps = {}) => {
  const service = deps.errorLogService || errorLogService;
  const {
    correlationId,
    requestId,
    outcome,
    detail,
    httpStatus,
    clientId,
    endpoint = INTROSPECT_ENDPOINT,
    errorPrefix = INTROSPECT_ERROR_PREFIX,
  } = context;

  try {
    await service.logError({
      error: new Error(`${errorPrefix}:${outcome}`),
      // Repo vocabulary is critical|warning|info|minor; only 'critical' alerts.
      category: httpStatus >= 500 ? 'critical' : 'warning',
      type: 'system',
      additionalContext: {
        endpoint,
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

/**
 * @param {object} context
 * @param {string} [context.eventType]  defaults to 'mcp_introspection_grant_inactive'
 * @param {string} [context.resource]   defaults to the introspect endpoint
 */
const logGrantRefusal = async (context, deps = {}) => {
  const service = deps.securityEventService || securityEventService;
  const {
    correlationId,
    requestId,
    detail,
    clientId,
    userId,
    eventType = GRANT_INACTIVE_EVENT,
    resource = INTROSPECT_ENDPOINT,
  } = context;

  try {
    await service.logSecurityEvent({
      event_type: eventType,
      severity: 'medium',
      user_id: userId || null,
      resource,
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

module.exports = {
  logOperational,
  logGrantRefusal,
  INTROSPECT_ENDPOINT,
  INTROSPECT_ERROR_PREFIX,
  GRANT_INACTIVE_EVENT,
};
