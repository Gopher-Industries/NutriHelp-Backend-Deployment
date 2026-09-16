const express = require('express');
const { ServiceError } = require('../services/serviceError');
const { validateMealLog } = require('../validators/mealLogValidator');
const { createMealLogController } = require('../controller/mealLogController');

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
  router.post('/me', authenticate, validateMealLog, createMealLogController(service));
  router.use((error, req, res, next) => {
    if (res.headersSent) return next(error);
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
