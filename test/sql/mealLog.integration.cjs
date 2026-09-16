const fs = require('fs');
const path = require('path');
const assert = require('node:assert/strict');
const { test, before, beforeEach, after } = require('node:test');
const express = require('express');
const request = require('supertest');
const { PGlite } = require('@electric-sql/pglite');
const { createClient } = require('@supabase/supabase-js');
const { createMealLogRouter } = require('../../routes/meallog');
const { createMealLogService } = require('../../services/mealLogService');
const { createMealLogRepository } = require('../../repositories/mealLogRepository');

const key = 'b'.repeat(64);
const meal = {
  date: '2026-09-11',
  meal_type: 'breakfast',
  food_name: 'Porridge',
  calories: 200.5,
  carbs: 30,
  time: '08:00',
};
const outputColumns = [
  'id',
  'date',
  'meal_type',
  'food_name',
  'calories',
  'protein',
  'carbs',
  'fat',
  'fiber',
  'sugar',
  'sodium',
  'time',
];
let db;
let app;
let loseNextInsertResponse;
let calls;

// Exercise the real Supabase SDK against an in-memory PostgreSQL engine.
// This small transport models only the PostgREST calls used by the repository;
// it is not a running PostgREST server or a multi-connection database test.
async function databaseFetch(input, options) {
  const url = new URL(input);
  assert.equal(url.pathname, '/rest/v1/nutrition_records');
  calls.push({ method: options.method, url });
  const selection = url.searchParams.get('select').split(',');
  assert.deepEqual(
    selection.map((column) => column.split('::')[0]),
    outputColumns
  );
  assert.ok(selection.includes('id::text'));
  const returning = selection.join(',');
  try {
    let result;
    if (options.method === 'POST') {
      assert.match(new Headers(options.headers).get('prefer'), /return=representation/);
      const row = JSON.parse(options.body);
      const fields = Object.keys(row);
      assert.deepEqual(
        fields.sort(),
        [...outputColumns.filter((c) => c !== 'id'), 'user_id', 'idempotency_key_hash'].sort()
      );
      result = await db.query(
        `INSERT INTO nutrition_records (${fields.join(',')})
        VALUES (${fields.map((_, i) => `$${i + 1}`).join(',')})
        RETURNING ${returning}`,
        fields.map((field) => row[field])
      );
      if (loseNextInsertResponse) {
        loseNextInsertResponse = false;
        throw new TypeError('Simulated lost response after a committed insert');
      }
    } else {
      assert.equal(options.method, 'GET');
      const owner = url.searchParams.get('user_id');
      const hash = url.searchParams.get('idempotency_key_hash');
      assert.match(owner, /^eq\.\d+$/);
      assert.match(hash, /^eq\.[0-9a-f]{64}$/);
      result = await db.query(
        `SELECT ${returning} FROM nutrition_records
        WHERE user_id = $1 AND idempotency_key_hash = $2`,
        [owner.slice(3), hash.slice(3)]
      );
    }
    // to_json has PostgREST's numeric JSON semantics (PGlite otherwise returns numeric strings).
    const rows = result.rows.map((row) =>
      Object.fromEntries(
        Object.entries(row).map(([field, value]) => [
          field,
          value !== null &&
          ['calories', 'protein', 'carbs', 'fat', 'fiber', 'sugar', 'sodium'].includes(field)
            ? Number(value)
            : value,
        ])
      )
    );
    return new Response(JSON.stringify(options.method === 'POST' ? rows[0] : rows), {
      status: options.method === 'POST' ? 201 : 200,
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (error) {
    if (!error.code) throw error;
    return new Response(JSON.stringify({ code: error.code, message: error.message }), {
      status: error.code === '23505' ? 409 : 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}

before(async () => {
  db = new PGlite();
  const sqlSuite = fs
    .readFileSync(path.join(__dirname, 'nutrition_records.test.sql'), 'utf8')
    .replace(/^\\set .*$/gm, '');
  const [fixture, assertions] = sqlSuite.split(
    '\\ir ../../database/migrations/003_alter_nutrition_records.sql'
  );
  assert.ok(assertions);
  await db.exec(fixture);
  await db.exec(
    fs.readFileSync(
      path.join(__dirname, '../../database/migrations/003_alter_nutrition_records.sql'),
      'utf8'
    )
  );
  // Re-run the unchanged Ticket 46 SQL assertions before exercising the endpoint.
  const results = await db.exec(assertions);
  assert.equal(
    results.at(-1).rows[0].result,
    'Ticket 46 nutrition_records regression checks passed'
  );
});

beforeEach(async () => {
  await db.exec(`RESET ROLE; DELETE FROM users;
    INSERT INTO users VALUES (1), (2), (9223372036854775807);
    SELECT setval('nutrition_records_id_seq', 9007199254740993, false);
    SET ROLE service_role;`);
  loseNextInsertResponse = false;
  calls = [];
  const client = createClient('https://database.test.invalid', 'test-service-key', {
    global: { fetch: databaseFetch },
    auth: { persistSession: false, autoRefreshToken: false },
  });
  const repository = createMealLogRepository(() => client);
  app = express();
  app.use(express.json());
  app.use(
    '/api/meallog',
    createMealLogRouter({
      service: createMealLogService(repository),
      // Only a test stand-in for verified identity; Ticket 31 supplies production auth.
      requireMcpAuth: () => (req, res, next) => {
        const identities = {
          'Bearer user-a': '1',
          'Bearer user-b': '2',
          'Bearer large-user': '9223372036854775807',
        };
        const userId = identities[req.get('Authorization')];
        if (!userId) return res.sendStatus(401);
        req.user = { userId };
        return next();
      },
    })
  );
});

after(async () => {
  if (db) await db.close();
});

function post(body = meal, token = 'user-a', hash = key) {
  return request(app)
    .post('/api/meallog/me')
    .set('Authorization', `Bearer ${token}`)
    .set('Idempotency-Key', hash)
    .send(body);
}

async function count() {
  return (await db.query('SELECT count(*)::int AS total FROM nutrition_records')).rows[0].total;
}

test('retry returns the original record, with exact bigint id and a single stored row', async () => {
  const first = await post().expect(201);
  const retry = await post().expect(200);
  assert.deepEqual(first.body, retry.body);
  assert.equal(first.body.data.id, '9007199254740993');
  assert.equal(await count(), 1);
  assert.equal(
    (await db.query('SELECT idempotency_key_hash FROM nutrition_records')).rows[0]
      .idempotency_key_hash,
    key
  );
});

test('a lost insert response can be retried without writing another row', async () => {
  loseNextInsertResponse = true;
  await post().expect(503);
  const retry = await post().expect(200);
  assert.equal(retry.body.data.food_name, meal.food_name);
  assert.equal(await count(), 1);
});

test('simultaneous HTTP retries converge on one record using the database constraint', async () => {
  const responses = await Promise.all(Array.from({ length: 8 }, () => post()));
  assert.deepEqual(responses.map((r) => r.status).sort(), [200, 200, 200, 200, 200, 200, 200, 201]);
  assert.equal(new Set(responses.map((r) => r.body.data.id)).size, 1);
  assert.equal(await count(), 1);
});

for (const field of ['food_name', 'date', 'meal_type', 'calories', 'carbs', 'time']) {
  test(`same key with different ${field} is rejected without overwriting the saved meal`, async () => {
    const first = await post().expect(201);
    const changes = {
      food_name: 'Soup',
      date: '2026-09-12',
      meal_type: 'dinner',
      calories: 300,
      carbs: 0,
      time: '09:00',
    };
    await post({ ...meal, [field]: changes[field] }).expect(409);
    const retry = await post().expect(200);
    assert.deepEqual(retry.body, first.body);
    assert.equal(await count(), 1);
  });
}

test('concurrent requests with different content cannot overwrite each other', async () => {
  const responses = await Promise.all([post(), post({ ...meal, food_name: 'Soup' })]);
  assert.deepEqual(responses.map((r) => r.status).sort(), [201, 409]);
  assert.equal(await count(), 1);
});

test('the same digest is independent for different verified users', async () => {
  const first = await post().expect(201);
  const second = await post({ ...meal, food_name: 'Soup' }, 'user-b').expect(201);
  assert.notEqual(second.body.data.id, first.body.data.id);
  assert.deepEqual((await post(meal, 'user-a').expect(200)).body, first.body);
  assert.deepEqual(
    (await post({ ...meal, food_name: 'Soup' }, 'user-b').expect(200)).body,
    second.body
  );
  assert.equal(await count(), 2);
});

test('a new confirmation key allows another record for identical meal data', async () => {
  await post().expect(201);
  await post(meal, 'user-a', 'c'.repeat(64)).expect(201);
  assert.equal(await count(), 2);
});

test('preserves a bigint app user without rounding through JavaScript number', async () => {
  await post(meal, 'large-user').expect(201);
  assert.equal(
    (await db.query('SELECT user_id::text FROM nutrition_records')).rows[0].user_id,
    '9223372036854775807'
  );
});

test('null remains distinct from zero and equivalent clock formats replay safely', async () => {
  const body = {
    date: meal.date,
    meal_type: meal.meal_type,
    food_name: meal.food_name,
    time: '08:00',
  };
  const first = await post(body).expect(201);
  assert.equal(first.body.data.calories, null);
  await post({ ...body, calories: null, time: '08:00:00' }).expect(200);
  await post({ ...body, calories: 0 }).expect(409);
});

test('no SQL call is made for invalid input or refused authentication', async () => {
  await post({ ...meal, user_id: '2' }).expect(400);
  await post(meal, 'website-token').expect(401);
  assert.equal(calls.length, 0);
  assert.equal(await count(), 0);
});
