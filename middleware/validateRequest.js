const { validationResult } = require('express-validator');

module.exports = (req, res, next) => {
  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      code: 'VALIDATION_ERROR',
      errors: errors.array().map(err => ({
        field: err.path ?? err.param,
        message: err.msg
      }))
    });
  }

  next();
};
