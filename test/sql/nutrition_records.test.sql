\set ON_ERROR_STOP on
-- from the repository root: npm ci, then npm run test:nutrition-records.
-- the Node runner creates and closes a fresh in-memory PGlite database for each test;
-- no PostgreSQL server, Docker, credentials or shared database are needed.
-- npm test runs Jest only; use the dedicated command above for this SQL suite.
-- optional native psql execution, after creating an empty database called ticket46_test:
-- psql -X -v ON_ERROR_STOP=1 -d ticket46_test -f test/sql/nutrition_records.test.sql
-- run only in an empty, disposable postgres database as a role that can create roles.
-- the fixture models ticket 14's reported table; it is not a production schema dump.

DO $$
BEGIN
    IF to_regclass('public.users') IS NOT NULL
        OR to_regclass('public.nutrition_records') IS NOT NULL
        OR EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'auth') THEN
        RAISE EXCEPTION 'use an empty disposable database for this test';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
        CREATE ROLE anon NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
        CREATE ROLE authenticated NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN
        CREATE ROLE service_role NOLOGIN BYPASSRLS;
    END IF;
END;
$$;

CREATE SCHEMA auth;
CREATE TABLE auth.users (id UUID PRIMARY KEY);
CREATE FUNCTION auth.uid() RETURNS UUID LANGUAGE sql STABLE AS $$
    SELECT nullif(current_setting('request.jwt.claim.sub', true), '')::uuid
$$;
CREATE TABLE public.users (user_id BIGINT PRIMARY KEY);
CREATE TABLE public.ingredients (id BIGINT PRIMARY KEY, name TEXT NOT NULL);

CREATE TABLE public.nutrition_records (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID NOT NULL DEFAULT auth.uid() REFERENCES auth.users(id) ON DELETE CASCADE,
    date DATE NOT NULL,
    meal_type TEXT NOT NULL,
    food_name TEXT NOT NULL,
    calories NUMERIC,
    protein NUMERIC,
    carbs NUMERIC,
    fat NUMERIC,
    fiber NUMERIC,
    sugar NUMERIC,
    sodium NUMERIC,
    time TIME
);
ALTER TABLE public.nutrition_records ENABLE ROW LEVEL SECURITY;
CREATE POLICY "read own nutrition" ON public.nutrition_records
    FOR SELECT TO authenticated USING (auth.uid() = user_id);
CREATE POLICY "insert own nutrition" ON public.nutrition_records
    FOR INSERT TO authenticated WITH CHECK (auth.uid() = user_id);
CREATE POLICY "update own nutrition" ON public.nutrition_records
    FOR UPDATE TO authenticated USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);
GRANT USAGE ON SCHEMA public, auth TO anon, authenticated, service_role;
GRANT ALL ON public.nutrition_records TO PUBLIC, anon, authenticated, service_role;
GRANT ALL ON SEQUENCE public.nutrition_records_id_seq TO PUBLIC, anon, authenticated, service_role;

-- retain a snapshot so the tests can detect accidental changes to existing food fields.
CREATE TEMP TABLE original_nutrition_columns AS
SELECT attnum, attname, atttypid, atttypmod, attnotnull,
       pg_get_expr(d.adbin, d.adrelid) AS default_expression
FROM pg_attribute a
LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
WHERE a.attrelid = 'public.nutrition_records'::regclass
  AND a.attnum > 0 AND NOT a.attisdropped AND a.attname <> 'user_id';

CREATE FUNCTION pg_temp.assert_true(condition BOOLEAN, description TEXT)
RETURNS VOID LANGUAGE plpgsql AS $$
BEGIN
    IF condition IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'assertion failed: %', description;
    END IF;
END;
$$;

CREATE FUNCTION pg_temp.expect_error(statement TEXT, expected_state TEXT)
RETURNS VOID LANGUAGE plpgsql AS $$
DECLARE
    actual_state TEXT;
BEGIN
    BEGIN
        EXECUTE statement;
    EXCEPTION WHEN OTHERS THEN
        GET STACKED DIAGNOSTICS actual_state = RETURNED_SQLSTATE;
        IF actual_state <> expected_state THEN
            RAISE EXCEPTION 'expected SQLSTATE %, got % for %', expected_state, actual_state, statement;
        END IF;
        RETURN;
    END;
    RAISE EXCEPTION 'expected SQLSTATE % but statement succeeded: %', expected_state, statement;
END;
$$;

\ir ../../database/migrations/003_alter_nutrition_records.sql

SELECT pg_temp.assert_true(to_regclass('public.meal_logs') IS NULL, 'no new meal_logs table');
SELECT pg_temp.assert_true((SELECT relrowsecurity FROM pg_class
    WHERE oid = 'public.nutrition_records'::regclass), 'rls remains enabled');
SELECT pg_temp.assert_true((SELECT count(*) = 0 FROM pg_policy
    WHERE polrelid = 'public.nutrition_records'::regclass), 'all old policies removed');
SELECT pg_temp.assert_true((SELECT atttypid = 'bigint'::regtype AND attnotnull
    FROM pg_attribute WHERE attrelid = 'public.nutrition_records'::regclass
    AND attname = 'user_id'), 'app user id is a required bigint');
SELECT pg_temp.assert_true(NOT EXISTS (SELECT 1 FROM pg_attrdef d
    JOIN pg_attribute a ON a.attrelid = d.adrelid AND a.attnum = d.adnum
    WHERE a.attrelid = 'public.nutrition_records'::regclass AND a.attname = 'user_id'),
    'old auth.uid default removed');
SELECT pg_temp.assert_true((SELECT confrelid = 'public.users'::regclass AND confdeltype = 'c'
    FROM pg_constraint WHERE conrelid = 'public.nutrition_records'::regclass
    AND conname = 'nutrition_records_user_id_fkey'), 'app-user deletion intentionally cascades to meal history');
SELECT pg_temp.assert_true(NOT EXISTS (
    SELECT * FROM original_nutrition_columns
    EXCEPT
    SELECT a.attnum, a.attname, a.atttypid, a.atttypmod, a.attnotnull,
           pg_get_expr(d.adbin, d.adrelid)
    FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
    WHERE a.attrelid = 'public.nutrition_records'::regclass
      AND a.attnum > 0 AND NOT a.attisdropped
), 'existing food columns, types and defaults are unchanged');

INSERT INTO public.users VALUES (1), (2);
INSERT INTO public.ingredients VALUES (5, 'Porridge');

SET ROLE service_role;
INSERT INTO public.nutrition_records
    (user_id, date, meal_type, food_name, calories, protein, carbs, fat, fiber, sugar, sodium, time, idempotency_key_hash)
VALUES (1, '2026-09-10', 'breakfast', 'Porridge', 200, 7, 30, 5, 4, 2, 20, '08:00', repeat('a', 64));
SELECT pg_temp.expect_error($q$INSERT INTO public.nutrition_records
    (user_id, date, meal_type, food_name, idempotency_key_hash)
    VALUES (1, '2026-09-10', 'breakfast', 'Porridge', repeat('a', 64))$q$, '23505');
SELECT pg_temp.expect_error($q$INSERT INTO public.nutrition_records
    (user_id, date, meal_type, food_name, idempotency_key_hash)
    VALUES (1, '2026-09-10', 'dinner', 'Changed payload', repeat('a', 64))$q$, '23505');

-- a retry can be ignored at the constraint; ticket 47 must compare and return the original row.
INSERT INTO public.nutrition_records (user_id, date, meal_type, food_name, idempotency_key_hash)
VALUES (1, '2026-09-10', 'breakfast', 'Porridge', repeat('a', 64))
ON CONFLICT (user_id, idempotency_key_hash) DO NOTHING;
SELECT pg_temp.assert_true((SELECT count(*) = 1 FROM public.nutrition_records WHERE user_id = 1),
    'repeated request writes one row');
INSERT INTO public.nutrition_records (user_id, date, meal_type, food_name, idempotency_key_hash)
VALUES (2, '2026-09-10', 'breakfast', 'Porridge', repeat('a', 64));
SELECT pg_temp.assert_true((SELECT count(*) = 2 FROM public.nutrition_records), 'key uniqueness is per user');
SELECT pg_temp.assert_true((SELECT carbs = 30 AND protein = 7 AND food_name = 'Porridge'
    FROM public.nutrition_records WHERE user_id = 1), 'original payload preserved');
SELECT pg_temp.assert_true((SELECT calories IS NULL FROM public.nutrition_records WHERE user_id = 2),
    'missing nutrition is not invented');

SELECT pg_temp.expect_error($q$INSERT INTO public.nutrition_records
    (user_id, date, meal_type, food_name, idempotency_key_hash)
    VALUES (999, '2026-09-10', 'lunch', 'Soup', repeat('b', 64))$q$, '23503');
SELECT pg_temp.expect_error($q$INSERT INTO public.nutrition_records
    (user_id, date, meal_type, food_name, idempotency_key_hash)
    VALUES (NULL, '2026-09-10', 'lunch', 'Soup', repeat('b', 64))$q$, '23502');
SELECT pg_temp.expect_error($q$INSERT INTO public.nutrition_records
    (user_id, date, meal_type, food_name, idempotency_key_hash)
    VALUES (1, '2026-09-10', 'lunch', 'Soup', NULL)$q$, '23502');
SELECT pg_temp.expect_error($q$INSERT INTO public.nutrition_records
    (user_id, date, meal_type, food_name, idempotency_key_hash)
    VALUES (1, '2026-09-10', 'lunch', 'Soup', 'raw-confirmation-token')$q$, '23514');
SELECT pg_temp.expect_error('UPDATE public.nutrition_records SET calories = 0', '42501');
SELECT pg_temp.expect_error('DELETE FROM public.nutrition_records', '42501');
SELECT pg_temp.expect_error('TRUNCATE public.nutrition_records', '42501');
RESET ROLE;

SET ROLE anon;
SELECT pg_temp.expect_error('SELECT * FROM public.nutrition_records', '42501');
SELECT pg_temp.expect_error($q$SELECT nextval('public.nutrition_records_id_seq')$q$, '42501');
RESET ROLE;
SET ROLE authenticated;
SELECT pg_temp.expect_error('SELECT * FROM public.nutrition_records', '42501');
SELECT pg_temp.expect_error($q$INSERT INTO public.nutrition_records
    (user_id, date, meal_type, food_name, idempotency_key_hash)
    VALUES (1, '2026-09-10', 'lunch', 'Soup', repeat('b', 64))$q$, '42501');
RESET ROLE;

-- even accidental client grants must not override the zero-policy rls boundary.
GRANT SELECT, INSERT ON public.nutrition_records TO anon, authenticated;
GRANT USAGE ON SEQUENCE public.nutrition_records_id_seq TO anon, authenticated;
SET ROLE anon;
SELECT pg_temp.assert_true((SELECT count(*) = 0 FROM public.nutrition_records), 'rls hides rows from anon');
SELECT pg_temp.expect_error($q$INSERT INTO public.nutrition_records
    (user_id, date, meal_type, food_name, idempotency_key_hash)
    VALUES (1, '2026-09-10', 'lunch', 'Soup', repeat('b', 64))$q$, '42501');
RESET ROLE;
SET ROLE authenticated;
SELECT pg_temp.assert_true((SELECT count(*) = 0 FROM public.nutrition_records), 'rls hides rows from authenticated');
SELECT pg_temp.expect_error($q$INSERT INTO public.nutrition_records
    (user_id, date, meal_type, food_name, idempotency_key_hash)
    VALUES (1, '2026-09-10', 'lunch', 'Soup', repeat('b', 64))$q$, '42501');
RESET ROLE;
REVOKE ALL ON public.nutrition_records FROM anon, authenticated;
REVOKE ALL ON SEQUENCE public.nutrition_records_id_seq FROM anon, authenticated;

UPDATE public.ingredients SET name = 'Renamed ingredient' WHERE id = 5;
DELETE FROM public.ingredients WHERE id = 5;
SELECT pg_temp.assert_true((SELECT food_name = 'Porridge' FROM public.nutrition_records WHERE user_id = 1),
    'food_name snapshot survives ingredient changes');
DELETE FROM public.users WHERE user_id = 2;
SELECT pg_temp.assert_true((SELECT count(*) = 1 FROM public.nutrition_records),
    'account deletion removes its meal history and preserves the other user history');

SELECT 'Ticket 46 nutrition_records regression checks passed' AS result;
