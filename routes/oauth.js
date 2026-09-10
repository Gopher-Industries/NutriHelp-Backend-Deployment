const express = require('express');

const oauthIntrospectController = require('../controller/oauthIntrospectController');

/**
 * OAuth authorization-server routes.
 *
 * No trailing-slash redirect: MCP uses redirect:'error', so any 3xx hard-fails.
 * No Origin/CORS here — introspection is server-to-server (no Origin); browser
 * Origin rules apply to authorize/consent, not this router.
 *
 * The local urlencoded({limit:'16kb'}) is a NO-OP in production: server.js
 * parses globally at 50mb first and sets req._body. Kept for standalone mounts;
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

  return router;
};

module.exports = createOauthRouter();
module.exports.createOauthRouter = createOauthRouter;
