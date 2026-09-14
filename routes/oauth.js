const express = require('express');

const oauthIntrospectController = require('../controller/oauthIntrospectController');
const oauthGrantsController = require('../controller/oauthGrantsController');
const { authenticateToken } = require('../middleware/authenticateToken');
const { requireExactOrigin } = require('../middleware/requireExactOrigin');

/**
 * OAuth authorization-server routes.
 *
 * Two credentials, middleware per route — never router-wide:
 *   POST /introspect        private_key_jwt in body; no Origin
 *   DELETE /grants/:grantId platform Bearer + exact Origin
 * Router-wide Origin would refuse MCP; router-wide authenticateToken would too.
 *
 * No trailing-slash redirect: MCP uses redirect:'error', so any 3xx hard-fails.
 *
 * Local urlencoded({limit:'16kb'}) is a NO-OP in production: server.js parses
 * globally at 50mb first and sets req._body. Kept for standalone mounts;
 * tightening production means editing server.js (out of ticket 42 scope).
 * See test/oauthIntrospect.composition.test.js.
 */
const createOauthRouter = (deps = {}) => {
  const controller = deps.oauthIntrospectController || oauthIntrospectController;
  const router = express.Router();

  // Bind once; do not pass deps as a third handler arg (that is Express `next`).
  const introspectHandler = controller.createIntrospectController
    ? controller.createIntrospectController(deps)
    : (req, res) => controller.introspect(req, res, deps);

  router.post(
    '/introspect',
    express.urlencoded({ extended: false, limit: '16kb' }),
    introspectHandler
  );

  // Ticket 43 disconnect. Auth then Origin (Origin after Bearer so anonymous
  // callers learn nothing about configured origins).
  //
  // Path param is the opaque grant uuid only — never a CIMD client URL
  // (mig 002 / mcp_client_grants: percent-encoding + slashes can match wrong).
  //
  // Contract wants Bearer + Origin + action-bound CSRF (minted by unassigned
  // GET /api/oauth/grants). CSRF here means single-use intent binding, not
  // cross-site forgery: authenticateToken is Bearer-only, so a forged DELETE
  // arrives with no credential and dies at 401. Gap accepted until that issuer
  // exists. OAUTH_ROUTES_ENABLED mounts this whole router (incl. /introspect),
  // so flipping the flag for MCP also goes this DELETE live — it is not dark.
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
