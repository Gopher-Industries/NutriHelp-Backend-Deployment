const express = require('express');

const oauthIntrospectController = require('../controller/oauthIntrospectController');
const oauthGrantsController = require('../controller/oauthGrantsController');
const oauthTokenController = require('../controller/oauthTokenController');
const oauthAuthorizeController = require('../controller/oauthAuthorizeController');
const { authenticateToken } = require('../middleware/authenticateToken');
const { requireExactOrigin } = require('../middleware/requireExactOrigin');
const defaultOauthRateLimiters = require('../middleware/oauthRateLimiters');

/**
 * OAuth authorization-server routes.
 *
 * Middleware per route — never router-wide:
 *   GET  /authorize         anonymous; two rate buckets, no auth of any kind
 *   POST /introspect        private_key_jwt; no Origin
 *   POST /token             client auth is grant-specific: token-exchange needs
 *                           private_key_jwt; authorization_code and refresh_token
 *                           are public-client grants (PKCE + bindings, no client auth)
 *   DELETE /grants/:grantId platform Bearer + exact Origin
 *
 * No trailing-slash redirect: MCP uses redirect:'error', so any 3xx hard-fails.
 *
 * WARNING: this urlencoded({limit:'16kb'}) IS IN FORCE as of ticket 45, where it
 * used to be a no-op, so raising or removing it changes what the public /token
 * and /introspect endpoints accept from anonymous callers. server.js skips the
 * global parsers for this prefix; oauthRateLimiters.skipOauthRouter says why, and
 * the composition suite proves the skip is what does the work.
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

  // All three grants; grant_type dispatch and per-grant client auth are in the controller.
  const tokenController = deps.oauthTokenController || oauthTokenController;
  const tokenHandler = tokenController.createTokenController(deps);

  router.post('/token', express.urlencoded({ extended: false, limit: '16kb' }), tokenHandler);

  // Disconnect (revoke one grant). Auth then Origin (Origin after Bearer so
  // anonymous callers learn nothing about configured origins).
  //
  // Path param is the opaque grant uuid only — never a CIMD client URL: a URL
  // needs percent-encoding and contains slashes, so as a path segment it can
  // decode differently or match the wrong route.
  //
  // Contract wants Bearer + Origin + action-bound CSRF (a token minted by a
  // GET /api/oauth/grants issuer that does not exist yet). CSRF here means
  // single-use intent binding, not cross-site forgery: authenticateToken is
  // Bearer-only, so a forged DELETE arrives with no credential and dies at 401.
  // Gap accepted until that issuer exists. OAUTH_ROUTES_ENABLED mounts this
  // whole router, so enabling MCP also goes this DELETE live — it is not dark.
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
