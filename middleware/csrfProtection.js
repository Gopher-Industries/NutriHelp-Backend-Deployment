const crypto = require('crypto');

const COOKIE_NAME = 'nutrihelp_csrf';
const HEADER_NAME = 'x-csrf-token';

function getCookie(req, name) {
  const cookies = req.headers.cookie || '';
  const entry = cookies.split(';').map((value) => value.trim()).find((value) => value.startsWith(`${name}=`));
  return entry ? decodeURIComponent(entry.slice(name.length + 1)) : null;
}

function getFrontendOrigin() {
  return process.env.FRONTEND_ORIGIN || '';
}

function requireFrontendOrigin(req, res, next) {
  const expectedOrigin = getFrontendOrigin();
  const requestOrigin = req.headers.origin;

  if (process.env.NODE_ENV === 'production' && !expectedOrigin) {
    return res.status(503).json({ success: false, error: 'Frontend origin is not configured' });
  }

  if (process.env.NODE_ENV === 'production' && requestOrigin !== expectedOrigin) {
    return res.status(403).json({ success: false, error: 'Origin not allowed' });
  }

  if (requestOrigin && expectedOrigin && requestOrigin !== expectedOrigin) {
    return res.status(403).json({ success: false, error: 'Origin not allowed' });
  }

  next();
}

function issueCsrfToken(_req, res) {
  const token = crypto.randomBytes(32).toString('hex');
  res.cookie(COOKIE_NAME, token, {
    httpOnly: false,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    path: '/api/consent',
  });
  return res.json({ success: true });
}

function requireCsrfToken(req, res, next) {
  const headerToken = req.headers[HEADER_NAME];
  const cookieToken = getCookie(req, COOKIE_NAME);

  if (!headerToken || !cookieToken || headerToken.length !== cookieToken.length ||
      !crypto.timingSafeEqual(Buffer.from(headerToken), Buffer.from(cookieToken))) {
    return res.status(403).json({ success: false, error: 'CSRF token missing or invalid' });
  }

  next();
}

module.exports = {
  issueCsrfToken,
  requireCsrfToken,
  requireFrontendOrigin,
};