const express = require('express');
const request = require('supertest');
const { createMealLogRouter } = require('../routes/meallog');
const { createMealLogService } = require('../services/mealLogService');
const { createMealLogRepository } = require('../repositories/mealLogRepository');

const key = 'a'.repeat(64);
const meal = { date: '2026-09-11', meal_type: 'breakfast', food_name: 'Porridge', time: '08:00' };
let repository;
let app;

// Test double for Ticket 31's contract, not a JWT verifier or production middleware.
function testAuth(scope) {
  expect(scope).toBe('meallog:write');
  return (req, res, next) => {
    if (req.get('Authorization') === 'Bearer wrong-scope') return res.sendStatus(403);
    if (req.get('Authorization') !== 'Bearer verified-ai-token') return res.sendStatus(401);
    req.user = { userId: '42' };
    next();
  };
}

function buildApp(options, presetUser) {
  const server = express();
  server.use(express.json());
  if (presetUser)
    server.use((req, res, next) => {
      req.user = presetUser;
      next();
    });
  server.use('/api/meallog', createMealLogRouter(options));
  return server;
}

function post(body = meal, hash = key, path = '/api/meallog/me') {
  const call = request(app).post(path).set('Authorization', 'Bearer verified-ai-token');
  if (hash !== null) call.set('Idempotency-Key', hash);
  return call.send(body);
}

beforeEach(() => {
  repository = {
    insert: jest.fn(async (userId, keyHash, row) => ({
      id: '9007199254740993',
      ...row,
      user_id: userId,
      idempotency_key_hash: keyHash,
    })),
    findByKey: jest.fn(),
  };
  app = buildApp({ requireMcpAuth: testAuth, service: createMealLogService(repository) });
});

test('creates one snapshot with trusted identity and returns only public fields', async () => {
  const response = await post({ ...meal, calories: 200, carbs: 30 }).expect(201);
  expect(repository.insert).toHaveBeenCalledWith('42', key, {
    ...meal,
    time: '08:00:00',
    calories: 200,
    protein: null,
    carbs: 30,
    fat: null,
    fiber: null,
    sugar: null,
    sodium: null,
  });
  expect(response.body.data.id).toBe('9007199254740993');
  expect(response.body.data).not.toHaveProperty('user_id');
  expect(response.body.data).not.toHaveProperty('idempotency_key_hash');
  expect(response.headers['cache-control']).toBe('no-store');
});

test.each([
  'user_id',
  'userId',
  'email',
  'identifier',
  'id',
  'idempotency_key_hash',
  'confirmation_token',
  'ingredients',
])('rejects an unsupported body field: %s', async (field) => {
  await post({ ...meal, [field]: 'caller-controlled' }).expect(400);
  expect(repository.insert).not.toHaveBeenCalled();
});

test.each(['user_id=99', 'userId=99', 'email=someone', 'anything=1'])(
  'rejects query parameters: %s',
  async (query) => {
    await post(meal, key, `/api/meallog/me?${query}`).expect(400);
    expect(repository.insert).not.toHaveBeenCalled();
  }
);

test('identity headers cannot select another user', async () => {
  await post().set('X-User-Id', '999').set('User-Id', '999').expect(201);
  expect(repository.insert.mock.calls[0][0]).toBe('42');
});

test.each([null, '', 'raw-confirmation-token', 'A'.repeat(64), 'a'.repeat(63), 'g'.repeat(64)])(
  'rejects a missing or malformed digest: %s',
  async (hash) => {
    await post(meal, hash).expect(400);
    expect(repository.insert).not.toHaveBeenCalled();
  }
);

test.each([
  {},
  [],
  { ...meal, date: '2026-02-30' },
  { ...meal, date: '2025-02-29' },
  { ...meal, date: '0000-01-01' },
  { ...meal, date: '2026-9-1' },
  { ...meal, calories: -1 },
  { ...meal, protein: '7' },
  { ...meal, calories: Number.MAX_SAFE_INTEGER + 1 },
  { ...meal, food_name: '   ' },
  { ...meal, food_name: 'x'.repeat(201) },
  { ...meal, meal_type: 'x'.repeat(51) },
  { ...meal, time: '24:00' },
  { ...meal, time: '08:60' },
  { ...meal, time: '08:00Z' },
])('rejects invalid meal input %#', async (body) => {
  await post(body).expect(400);
  expect(repository.insert).not.toHaveBeenCalled();
});

test('accepts a leap day, explicit null and zero without substituting nutrition', async () => {
  const response = await post({
    ...meal,
    date: '2028-02-29',
    calories: 0,
    protein: null,
    time: null,
  }).expect(201);
  expect(response.body.data).toMatchObject({ calories: 0, protein: null, carbs: null, time: null });
});

test('does not accept form encoded bodies', async () => {
  await request(app)
    .post('/api/meallog/me')
    .set('Authorization', 'Bearer verified-ai-token')
    .set('Idempotency-Key', key)
    .type('form')
    .send(meal)
    .expect(400);
  expect(repository.insert).not.toHaveBeenCalled();
});

test.each([undefined, 'Bearer website-token', 'Bearer unverified-token', 'Bearer wrong-scope'])(
  'does not write when the auth adapter refuses the request: %s',
  async (token) => {
    const call = request(app).post('/api/meallog/me').set('Idempotency-Key', key);
    if (token) call.set('Authorization', token);
    await call.send(meal).expect(token === 'Bearer wrong-scope' ? 403 : 401);
    expect(repository.insert).not.toHaveBeenCalled();
  }
);

test('default registration stays unavailable even if website middleware populated req.user', async () => {
  app = buildApp({ service: createMealLogService(repository) }, { userId: '42' });
  const response = await post().expect(503);
  expect(response.body.code).toBe('MCP_AUTH_UNAVAILABLE');
  expect(repository.insert).not.toHaveBeenCalled();
});

test.each([
  undefined,
  null,
  'uuid-from-supabase',
  '0',
  '-1',
  '9223372036854775808',
  9007199254740992,
])('refuses an invalid identity from an incorrectly configured adapter: %s', async (userId) => {
  app = buildApp({
    service: createMealLogService(repository),
    requireMcpAuth: () => (req, res, next) => {
      req.user = { userId };
      next();
    },
  });
  await post().expect(401);
  expect(repository.insert).not.toHaveBeenCalled();
});

test('does not expose a caller-id route or a write operation on GET', async () => {
  await post(meal, key, '/api/meallog/42').expect(404);
  await request(app).get('/api/meallog/me').expect(404);
  expect(repository.insert).not.toHaveBeenCalled();
});

test.each(['23503', '42501', '08006'])('sanitizes a database failure (%s)', async (code) => {
  repository.insert.mockRejectedValue({ code, message: `private row ${key}`, details: meal });
  const response = await post().expect(503);
  expect(response.body).toEqual({ success: false, error: 'Meal log storage is unavailable' });
  expect(repository.findByKey).not.toHaveBeenCalled();
});

test('a uniqueness failure without a matching owner/key record is not a successful retry', async () => {
  repository.insert.mockRejectedValue({ code: '23505' });
  repository.findByKey.mockResolvedValue(null);
  await post().expect(503);
  expect(repository.findByKey).toHaveBeenCalledWith('42', key);
});

test('a failed retry lookup is sanitized', async () => {
  repository.insert.mockRejectedValue({ code: '23505' });
  repository.findByKey.mockRejectedValue(new Error('private database failure'));
  const response = await post().expect(503);
  expect(response.text).not.toContain('private');
});

test('missing service-role configuration cannot fall back to a mock or anonymous client', async () => {
  const service = createMealLogService(createMealLogRepository(() => null));
  app = buildApp({ requireMcpAuth: testAuth, service });
  await post().expect(503);
});
