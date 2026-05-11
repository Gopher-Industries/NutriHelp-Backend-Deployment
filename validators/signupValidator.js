const { body } = require('express-validator');

const registerValidation = [
  body('name')
    .notEmpty().withMessage('Name is required')
    .isLength({ min: 2, max: 100 }).withMessage('Name must be 2–100 characters')
    .matches(/^[A-Za-z\s]+$/).withMessage('Name must contain letters and spaces only'),

  body('email')
    .notEmpty().withMessage('Email is required')
    .isEmail().withMessage('Please enter a valid email'),

  body('password')
    .notEmpty().withMessage('Password is required')
    .isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
    .matches(/[a-z]/).withMessage('Password needs a lowercase letter')
    .matches(/[A-Z]/).withMessage('Password needs an uppercase letter')
    .matches(/\d/).withMessage('Password needs a number')
    .matches(/[@$!%*?&]/).withMessage('Password needs a special character (@$!%*?&)'),

  body('contact_number')
    .notEmpty().withMessage('Contact number is required')
    .matches(/^\d{10}$/).withMessage('Contact number must be exactly 10 digits'),

  body('address')
    .notEmpty().withMessage('Address is required')
    .isLength({ min: 5, max: 200 }).withMessage('Address must be 5–200 characters'),
];

module.exports = { registerValidation };
