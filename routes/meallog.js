const express = require('express');
const { ServiceError } = require('../services/serviceError');
const { validateMealLog } = require('../validators/mealLogValidator');
const { createMealLogController } = require('../controller/mealLogController');

// body-parser 1.20 / raw-body 2.5 refusals this json parser can raise. Omitted
// because they cannot arise here: parameters.too.many (urlencoded only) and
// entity.verify.failed (no verify option).
const BODY_PARSER_ERROR_TYPES = new Set([
  'entity.too.large',
  'entity.parse.failed',
  'charset.unsupported',
  'encoding.unsupported',
  'request.size.invalid',
  'request.aborted',
]);

function unavailableMcpAuth() {
  return (req, res) =>
    res.status(503).json({
      success: false,
      error: 'Meal logging is awaiting MCP authentication integration',
      code: 'MCP_AUTH_UNAVAILABLE',
    });
}

// Ticket 31 integration point: requireMcpAuth(scope) must verify the AI backend
// token, enforce the scope and set req.user.userId from verified app identity.
// Do not pass the website authenticateToken middleware here (separate token boundary).
function createMealLogRouter({ requireMcpAuth = unavailableMcpAuth, service } = {}) {
  const router = express.Router();
  const authenticate = requireMcpAuth('meallog:write');
  if (typeof authenticate !== 'function') throw new TypeError('MCP auth must return middleware');

  router.use((req, res, next) => {
    res.set('Cache-Control', 'no-store');
    next();
  });
  // The only parser for this body (server.js's 50mb parsers skip this router),
  // after authenticate so an unauthenticated body is never read. 16kb: a record
  // is <= ~2KB of JSON (food_name 200 + meal_type 50 chars at up to 6 bytes each,
  // 7 numbers, date, time); same limit as the oauth router.
  router.post(
    '/me',
    authenticate,
    express.json({ limit: '16kb' }),
    validateMealLog,
    createMealLogController(service)
  );
  router.use((error, req, res, next) => {
    if (res.headersSent) return next(error);
    // body-parser refusals (413/400/415) keep their status, with fixed messages.
    // Gated on error.type: an exposed 401/403/429 from ticket 31's auth must not
    // read "Invalid meal log request". It falls to the 503 below, so ticket 31
    // should answer auth failures with res.status(...), not next(err).
    if (error && BODY_PARSER_ERROR_TYPES.has(error.type)) {
      return res.status(error.status).json({
        success: false,
        error: error.status === 413 ? 'Meal log request is too large' : 'Invalid meal log request',
      });
    }
    // Database messages may include row contents or constraint details.
    const known = error instanceof ServiceError;
    return res.status(known ? error.statusCode : 503).json({
      success: false,
      error: known ? error.message : 'Meal log storage is unavailable',
    });
  });
  return router;
}

module.exports = createMealLogRouter();
module.exports.createMealLogRouter = createMealLogRouter;
