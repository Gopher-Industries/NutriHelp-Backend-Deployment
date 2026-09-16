const Joi = require('joi');
const { ServiceError } = require('../services/serviceError');

const nutrientFields = ['calories', 'protein', 'carbs', 'fat', 'fiber', 'sugar', 'sodium'];
const mealFields = ['date', 'meal_type', 'food_name', ...nutrientFields, 'time'];

const schema = Joi.object({
  date: Joi.string()
    .pattern(/^\d{4}-\d{2}-\d{2}$/)
    .custom((value, helpers) => {
      const date = new Date(`${value}T00:00:00Z`);
      return value.startsWith('0000') ||
        Number.isNaN(date.getTime()) ||
        date.toISOString().slice(0, 10) !== value
        ? helpers.error('any.invalid')
        : value;
    })
    .required(),
  meal_type: Joi.string().min(1).max(50).pattern(/\S/).required(),
  food_name: Joi.string().min(1).max(200).pattern(/\S/).required(),
  ...Object.fromEntries(
    nutrientFields.map((field) => [
      field,
      Joi.number().min(0).max(Number.MAX_SAFE_INTEGER).allow(null),
    ])
  ),
  time: Joi.string()
    .pattern(/^(?:[01]\d|2[0-3]):[0-5]\d(?::[0-5]\d)?$/)
    .allow(null),
})
  .unknown(false)
  .required();

function badRequest() {
  return new ServiceError(400, 'Invalid meal log request');
}

function validateMealLog(req, res, next) {
  // /me has no caller-selected identity or other query parameters.
  if (Object.keys(req.query).length || !req.is('application/json')) {
    return next(badRequest());
  }

  const key = req.get('Idempotency-Key');
  if (typeof key !== 'string' || !/^[0-9a-f]{64}$/.test(key)) {
    return next(badRequest());
  }

  const { error, value } = schema.validate(req.body, { convert: false });
  if (error) return next(badRequest());

  const meal = { ...value };
  for (const field of nutrientFields) meal[field] = value[field] ?? null;
  meal.time = value.time ? (value.time.length === 5 ? `${value.time}:00` : value.time) : null;
  // Ticket 48 sends the SHA-256 digest already. Never hash it a second time.
  req.mealLogInput = { meal, keyHash: key };
  return next();
}

module.exports = { validateMealLog, mealFields, nutrientFields };
