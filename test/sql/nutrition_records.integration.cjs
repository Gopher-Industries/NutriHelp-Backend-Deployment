const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { PGlite } = require('@electric-sql/pglite');

// Each case owns a disposable in-memory database; no shared database is contacted.
// Expand the single psql include so both runners execute the same SQL assertions.
const migrationPath = '../../database/migrations/003_alter_nutrition_records.sql';
const migration = fs.readFileSync(path.join(__dirname, migrationPath), 'utf8');
const suite = fs
  .readFileSync(path.join(__dirname, 'nutrition_records.test.sql'), 'utf8')
  .replace(/^\\set .*$/gm, '');
const parts = suite.split(`\\ir ${migrationPath}`);
assert.equal(parts.length, 2, 'SQL suite must include migration 003 exactly once');
const [fixture, assertions] = parts;

function databaseTest(name, run) {
  test(name, async () => {
    const db = new PGlite();
    try {
      await db.exec(fixture);
      await run(db);
    } finally {
      await db.close();
    }
  });
}

async function rejectsMigration(db, code, message) {
  await assert.rejects(db.exec(migration), (error) => {
    assert.equal(error.code, code);
    if (message) assert.match(error.message, message);
    return true;
  });
  await db.exec('ROLLBACK');
}

async function originalSchema(db, expectedPolicies = 3) {
  const result = await db.query(`SELECT
    (SELECT atttypid::regtype::text FROM pg_attribute
      WHERE attrelid = 'public.nutrition_records'::regclass AND attname = 'user_id') AS user_type,
    (SELECT count(*)::int FROM pg_policy
      WHERE polrelid = 'public.nutrition_records'::regclass) AS policies,
    (SELECT count(*)::int FROM pg_attribute
      WHERE attrelid = 'public.nutrition_records'::regclass
      AND attname = 'idempotency_key_hash' AND NOT attisdropped) AS hash_columns,
    (SELECT confrelid::regclass::text FROM pg_constraint
      WHERE conrelid = 'public.nutrition_records'::regclass
      AND conname = 'nutrition_records_user_id_fkey') AS target`);
  assert.deepEqual(result.rows[0], {
    user_type: 'uuid',
    policies: expectedPolicies,
    hash_columns: 0,
    target: 'auth.users',
  });
}

databaseTest(
  'runs every SQL regression assertion and names all three removed policies',
  async (db) => {
    const notices = [];
    await db.exec(migration, { onNotice: (notice) => notices.push(notice.message) });
    assert.deepEqual(
      notices.filter((notice) => notice.startsWith('Removing policies')),
      [
        'Removing policies from public.nutrition_records: insert own nutrition, read own nutrition, update own nutrition',
      ]
    );
    const result = await db.exec(assertions);
    assert.equal(
      result.at(-1).rows[0].result,
      'Ticket 46 nutrition_records regression checks passed'
    );
  }
);

for (const count of [2, 4]) {
  databaseTest(`rejects ${count} legacy policies without changing the schema`, async (db) => {
    await db.exec(
      count === 2
        ? 'DROP POLICY "update own nutrition" ON public.nutrition_records'
        : 'CREATE POLICY "extra policy" ON public.nutrition_records USING (true)'
    );
    await rejectsMigration(db, 'P0001', /expected 3 nutrition_records policies/);
    await originalSchema(db, count);
  });
}

databaseTest(
  'chooses account-delete CASCADE even when the legacy foreign key used RESTRICT',
  async (db) => {
    await db.exec(`ALTER TABLE public.nutrition_records DROP CONSTRAINT nutrition_records_user_id_fkey;
    ALTER TABLE public.nutrition_records ADD CONSTRAINT nutrition_records_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES auth.users(id)
    ON DELETE RESTRICT ON UPDATE CASCADE DEFERRABLE INITIALLY DEFERRED;`);
    await db.exec(migration);
    const result = await db.query(`SELECT confdeltype, confupdtype, condeferrable, condeferred
    FROM pg_constraint WHERE conrelid = 'public.nutrition_records'::regclass
    AND conname = 'nutrition_records_user_id_fkey'`);
    assert.deepEqual(result.rows[0], {
      confdeltype: 'c',
      confupdtype: 'c',
      condeferrable: true,
      condeferred: true,
    });
    await db.exec(`INSERT INTO public.users VALUES (1), (2);
      INSERT INTO public.nutrition_records
        (user_id, date, meal_type, food_name, idempotency_key_hash)
      VALUES (1, '2026-09-10', 'lunch', 'Soup', repeat('a', 64)),
             (2, '2026-09-10', 'lunch', 'Rice', repeat('b', 64));
      DELETE FROM public.users WHERE user_id = 2;
      UPDATE public.users SET user_id = 3 WHERE user_id = 1;`);
    assert.deepEqual(
      (await db.query('SELECT user_id::text, food_name FROM public.nutrition_records')).rows,
      [{ user_id: '3', food_name: 'Soup' }]
    );
  }
);

databaseTest(
  'uses the same account-delete decision when no legacy foreign key exists',
  async (db) => {
    await db.exec(
      'ALTER TABLE public.nutrition_records DROP CONSTRAINT nutrition_records_user_id_fkey'
    );
    await db.exec(migration);
    await db.exec(assertions);
  }
);

databaseTest('refuses a populated legacy table without deleting data or policies', async (db) => {
  await db.exec(`INSERT INTO auth.users VALUES ('00000000-0000-0000-0000-000000000001');
    INSERT INTO public.nutrition_records (user_id, date, meal_type, food_name)
    VALUES ('00000000-0000-0000-0000-000000000001', '2026-09-10', 'lunch', 'Existing meal');`);
  await rejectsMigration(db, 'P0001', /not empty/);
  await originalSchema(db);
  assert.equal(
    (await db.query('SELECT food_name FROM public.nutrition_records')).rows[0].food_name,
    'Existing meal'
  );
});

databaseTest('refuses an unexpected column layout', async (db) => {
  await db.exec('ALTER TABLE public.nutrition_records DROP COLUMN time');
  await rejectsMigration(db, 'P0001', /missing a column/);
  await originalSchema(db);
});

databaseTest(
  'a late constraint failure rolls back the user type and removed policies',
  async (db) => {
    await db.exec(`ALTER TABLE public.nutrition_records
    ADD CONSTRAINT nutrition_records_idempotency_key_hash_format CHECK (true)`);
    await rejectsMigration(db, '42710');
    await originalSchema(db);
  }
);

databaseTest('refuses to run the one-time migration again', async (db) => {
  await db.exec(migration);
  await rejectsMigration(db, 'P0001', /expected nutrition_records.user_id to be uuid/);
  assert.equal(
    (
      await db.query(`SELECT atttypid::regtype::text AS type FROM pg_attribute
    WHERE attrelid = 'public.nutrition_records'::regclass AND attname = 'user_id'`)
    ).rows[0].type,
    'bigint'
  );
});
