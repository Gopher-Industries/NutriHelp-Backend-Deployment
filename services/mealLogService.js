const { ServiceError } = require('./serviceError');
const { createMealLogRepository } = require('../repositories/mealLogRepository');
const { mealFields, nutrientFields } = require('../validators/mealLogValidator');

function appUserId(value) {
  if (typeof value === 'number' && !Number.isSafeInteger(value)) {
    throw new ServiceError(401, 'A verified app user is required');
  }
  if (
    !['number', 'string'].includes(typeof value) ||
    !/^[1-9][0-9]{0,18}$/.test(String(value)) ||
    BigInt(value) > 9223372036854775807n
  ) {
    throw new ServiceError(401, 'A verified app user is required');
  }
  return String(value);
}

function sameMeal(record, meal) {
  return mealFields.every((field) => {
    const saved = record[field] ?? null;
    const requested = meal[field] ?? null;
    if (saved === null || requested === null) return saved === requested;
    return nutrientFields.includes(field) ? Number(saved) === requested : saved === requested;
  });
}

function publicRecord(record) {
  // Neither the user identifier nor the confirmation digest belongs in the response.
  return Object.fromEntries(['id', ...mealFields].map((field) => [field, record[field] ?? null]));
}

function createMealLogService(repository = createMealLogRepository()) {
  return {
    async save(verifiedUserId, { keyHash, meal }) {
      const userId = appUserId(verifiedUserId);
      try {
        const record = await repository.insert(userId, keyHash, meal);
        if (!record) throw new ServiceError(503, 'Meal log storage is unavailable');
        return { created: true, record: publicRecord(record) };
      } catch (error) {
        if (error.code !== '23505') throw error;
        // The database constraint decides the winner, including simultaneous retries.
        // Never update an existing log to make a retry succeed.
        const record = await repository.findByKey(userId, keyHash);
        if (!record) throw new ServiceError(503, 'Meal log storage is unavailable');
        if (!sameMeal(record, meal)) {
          throw new ServiceError(409, 'Idempotency key was already used for different meal data');
        }
        return { created: false, record: publicRecord(record) };
      }
    },
  };
}

module.exports = { createMealLogService };
