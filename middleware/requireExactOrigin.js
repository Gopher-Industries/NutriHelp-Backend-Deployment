const oauthConfig = require('../services/oauth/oauthConfig');

/**
 * Exact-Origin for user-facing OAuth routes. Mount per route, never on the
 * oauth router — POST /introspect sends no Origin and would 403 under this.
 *
 * Literal equality against OAUTH_FRONTEND_ORIGIN only. Never a *.vercel.app
 * pattern (server.js CORS has that hole; these routes must not). Unset → 503
 * (refuse), never "accept anything". Absent / "null" / mismatch → 403.
 */
const requireExactOrigin = (deps = {}) => {
  const config = deps.oauthConfig || oauthConfig;

  return (req, res, next) => {
    const allowed = config.frontendOrigin();

    if (!allowed) {
      return res.status(503).json({ error: 'server_error' });
    }

    const origin = req.get ? req.get('origin') : undefined;

    if (!origin) return res.status(403).json({ error: 'forbidden' });
    if (origin === 'null') return res.status(403).json({ error: 'forbidden' });
    if (origin !== allowed) return res.status(403).json({ error: 'forbidden' });

    return next();
  };
};

module.exports = { requireExactOrigin };
