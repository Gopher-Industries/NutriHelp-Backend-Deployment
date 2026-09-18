const express = require('express');

const oauthIntrospectController = require('../controller/oauthIntrospectController');
const oauthGrantsController = require('../controller/oauthGrantsController');
const oauthTokenController = require('../controller/oauthTokenController');
const oauthAuthorizeController = require('../controller/oauthAuthorizeController');
const { authenticateToken } = require('../middleware/authenticateToken');
const { requireExactOrigin } = require('../middleware/requireExactOrigin');
const defaultOauthRateLimiters = require('../middleware/oauthRateLimiters');

/**
 * OAuth authorization-server routes. Middleware per route — never router-wide.
 *
 * No trailing-slash redirect: MCP uses redirect:'error', so any 3xx hard-fails.
 *
 * Local urlencoded({limit:'16kb'}) is a NO-OP in production: server.js parses
 * globally at 50mb first and sets req._body. Kept for standalone mounts;
 * tightening production means editing server.js. See composition test.
 */
const createOauthRouter = (deps = {}) => {
  const controller = deps.oauthIntrospectController || oauthIntrospectController;
  const limiters = deps.oauthRateLimiters || defaultOauthRateLimiters;
  const router = express.Router();

  // Ticket 36 + 45: anonymous; address + hostname buckets before CIMD fetch.
  const authorizeController = deps.oauthAuthorizeController || oauthAuthorizeController;

  router.get(
    '/authorize',
    limiters.authorizeAddressLimiter,
    limiters.metadataFetchClientLimiter,
    authorizeController.createAuthorizeController(deps)
  );

  // Bind once; do not pass deps as a third handler arg (that is Express `next`).
  const introspectHandler = controller.createIntrospectController
    ? controller.createIntrospectController(deps)
    : (req, res) => controller.introspect(req, res, deps);

  // MCP service rate limit lives in server.js (see oauthRateLimiters.MCP_SERVICE_PATHS).
  router.post(
    '/introspect',
    express.urlencoded({ extended: false, limit: '16kb' }),
    introspectHandler
  );

  // RFC 8693 exchange; grant_type dispatch is in the controller.
  const tokenController = deps.oauthTokenController || oauthTokenController;
  const tokenHandler = tokenController.createTokenController(deps);

  router.post('/token', express.urlencoded({ extended: false, limit: '16kb' }), tokenHandler);

  // Ticket 43 disconnect. Auth then Origin (Origin after Bearer so anonymous
  // callers learn nothing about configured origins). Path param is the opaque
  // grant uuid only — never a CIMD client URL.
  //
  // Contract wants Bearer + Origin + action-bound CSRF (issuer = ticket 79).
  // authenticateToken is Bearer-only, so a forged DELETE dies at 401. Gap
  // accepted until that issuer exists. OAUTH_ROUTES_ENABLED mounts this whole
  // router, so enabling MCP also goes this DELETE live — it is not dark.
  const authenticate = deps.authenticateToken || authenticateToken;
  const originGuard = (deps.requireExactOrigin || requireExactOrigin)(deps);
  const disconnectHandler = (
    deps.oauthGrantsController || oauthGrantsController
  ).createDisconnectController(deps);

  router.delete('/grants/:grantId', authenticate, originGuard, disconnectHandler);

  return router;
};

module.exports = createOauthRouter();
module.exports.createOauthRouter = createOauthRouter;
