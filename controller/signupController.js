const signupService = require('../services/signupService');
const { isServiceError } = require('../services/serviceError');

function getRequestContext(req) {
  return {
    ip: req.headers['x-forwarded-for'] || req.socket?.remoteAddress || req.ip || '',
    userAgent: req.get('User-Agent') || ''
  };
}

function toValidationError(field, message) {
  return { success: false, code: 'VALIDATION_ERROR', errors: [{ field, message }] };
}

async function signup(req, res) {
  try {
    const result = await signupService.signup({
      name: req.body.name,
      email: req.body.email,
      password: req.body.password,
      contactNumber: req.body.contact_number,
      address: req.body.address,
      ...getRequestContext(req)
    });

    return res.status(result.statusCode).json(result.body);
  } catch (error) {
    if (isServiceError(error)) {
      const code = error.details?.code;

      if (code === 'EMAIL_EXISTS') {
        return res.status(400).json(toValidationError('email', 'Email is already registered'));
      }

      if (code === 'WEAK_PASSWORD') {
        return res.status(400).json(toValidationError('password', error.message));
      }

      return res.status(error.statusCode).json({ success: false, error: error.message });
    }

    console.error('Signup error:', error);
    return res.status(500).json({ success: false, error: 'Internal server error' });
  }
}

module.exports = { signup };
