-- ticket 46: reuse nutrition_records for the app's meal logging endpoint.
-- based on the proposed ticket 14 decision; final sign-off is still pending.
-- run manually as a database administrator after reviewing the target schema.
-- targets Supabase PostgreSQL: anon, authenticated and service_role must already exist.

BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL row_security = off;

-- prevent a concurrent insert between the empty-table check and the type change.
LOCK TABLE public.nutrition_records IN ACCESS EXCLUSIVE MODE;

DO $$
DECLARE
    user_column SMALLINT;
    existing_fk RECORD;
    existing_policy RECORD;
    policy_names TEXT[];
    fk_count INTEGER := 0;
    fk_name TEXT := 'nutrition_records_user_id_fkey';
    update_action TEXT := 'NO ACTION';
    deferral TEXT := 'NOT DEFERRABLE';
BEGIN
    IF EXISTS (SELECT 1 FROM public.nutrition_records) THEN
        RAISE EXCEPTION 'nutrition_records is not empty; review its existing user mapping before migrating';
    END IF;

    SELECT attnum INTO user_column
    FROM pg_attribute
    WHERE attrelid = 'public.nutrition_records'::regclass
      AND attname = 'user_id' AND atttypid = 'uuid'::regtype AND NOT attisdropped;
    IF user_column IS NULL THEN
        RAISE EXCEPTION 'expected nutrition_records.user_id to be uuid; inspect the current schema';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_attribute
        WHERE attrelid = 'public.users'::regclass AND attname = 'user_id'
          AND atttypid = 'bigint'::regtype AND NOT attisdropped
    ) THEN
        RAISE EXCEPTION 'expected public.users.user_id to be bigint';
    END IF;

    IF EXISTS (
        SELECT unnest(ARRAY['date', 'meal_type', 'food_name', 'calories', 'protein',
                            'carbs', 'fat', 'fiber', 'sugar', 'sodium', 'time'])
        EXCEPT
        SELECT attname::text FROM pg_attribute
        WHERE attrelid = 'public.nutrition_records'::regclass
          AND attnum > 0 AND NOT attisdropped
    ) THEN
        RAISE EXCEPTION 'nutrition_records is missing a column described in ticket 14';
    END IF;

    -- ticket 14 describes exactly three legacy policies. Stop on schema drift.
    SELECT array_agg(polname::text ORDER BY polname) INTO policy_names
    FROM pg_policy WHERE polrelid = 'public.nutrition_records'::regclass;
    IF coalesce(cardinality(policy_names), 0) <> 3 THEN
        RAISE EXCEPTION 'expected 3 nutrition_records policies, found %; review the target schema',
            coalesce(cardinality(policy_names), 0);
    END IF;
    -- retain this notice with the migration output; removals commit with the transaction.
    RAISE NOTICE 'Removing policies from public.nutrition_records: %',
        array_to_string(policy_names, ', ');

    -- policy expressions depend on the uuid column, so remove them before altering it.
    FOR existing_policy IN
        SELECT polname FROM pg_policy
        WHERE polrelid = 'public.nutrition_records'::regclass
    LOOP
        EXECUTE format('DROP POLICY %I ON public.nutrition_records', existing_policy.polname);
    END LOOP;

    -- replace only the user foreign key, preserving its name, update action and deferral.
    FOR existing_fk IN
        SELECT * FROM pg_constraint
        WHERE conrelid = 'public.nutrition_records'::regclass
          AND contype = 'f' AND user_column = ANY(conkey)
    LOOP
        fk_count := fk_count + 1;
        IF fk_count > 1 OR cardinality(existing_fk.conkey) <> 1 THEN
            RAISE EXCEPTION 'unexpected user_id foreign keys; review them before migrating';
        END IF;
        fk_name := existing_fk.conname;
        update_action := CASE existing_fk.confupdtype
            WHEN 'a' THEN 'NO ACTION' WHEN 'r' THEN 'RESTRICT' WHEN 'c' THEN 'CASCADE'
            WHEN 'n' THEN 'SET NULL' WHEN 'd' THEN 'SET DEFAULT' END;
        IF existing_fk.condeferrable THEN
            deferral := CASE WHEN existing_fk.condeferred
                THEN 'DEFERRABLE INITIALLY DEFERRED' ELSE 'DEFERRABLE INITIALLY IMMEDIATE' END;
        END IF;
        EXECUTE format('ALTER TABLE public.nutrition_records DROP CONSTRAINT %I', fk_name);
    END LOOP;

    -- there is no uuid-to-app-id conversion: the locked table must be empty.
    ALTER TABLE public.nutrition_records
        ALTER COLUMN user_id DROP DEFAULT,
        ALTER COLUMN user_id TYPE BIGINT USING NULL::BIGINT,
        ALTER COLUMN user_id SET NOT NULL;

    -- explicit account-lifecycle decision: meal history belongs to the app account.
    -- deleting that account removes its meal records instead of retaining personal data
    -- without an owner. CASCADE is chosen here, not inherited from the auth.users FK.
    EXECUTE format(
        'ALTER TABLE public.nutrition_records ADD CONSTRAINT %I FOREIGN KEY (user_id) '
        'REFERENCES public.users(user_id) ON DELETE CASCADE ON UPDATE %s %s',
        fk_name, update_action, deferral
    );
END;
$$;

-- ticket 47 supplies a sha-256 digest, never the raw confirmation token.
ALTER TABLE public.nutrition_records
    ADD COLUMN idempotency_key_hash TEXT NOT NULL,
    ADD CONSTRAINT nutrition_records_idempotency_key_hash_format
        CHECK (idempotency_key_hash ~ '^[0-9a-f]{64}$'),
    ADD CONSTRAINT nutrition_records_user_id_idempotency_key_hash_key
        UNIQUE (user_id, idempotency_key_hash);

-- zero policies deny client access; the service role bypasses rls.
-- ticket 47 must derive user_id from the verified app token and scope every query.
-- this release supports append-only meal logging: the service role can read/insert.
-- editing or deleting individual meals needs a reviewed endpoint, grant change and tests.
-- this is not a permanent retention policy; deleting the owning app account still cascades.
ALTER TABLE public.nutrition_records ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.nutrition_records FROM PUBLIC, anon, authenticated, service_role;
GRANT SELECT, INSERT ON TABLE public.nutrition_records TO service_role;

-- support existing serial/identity columns without changing their definitions.
DO $$
DECLARE
    owned_sequence TEXT;
BEGIN
    FOR owned_sequence IN
        SELECT pg_get_serial_sequence('public.nutrition_records', attname)
        FROM pg_attribute
        WHERE attrelid = 'public.nutrition_records'::regclass AND attnum > 0
          AND NOT attisdropped
          AND pg_get_serial_sequence('public.nutrition_records', attname) IS NOT NULL
    LOOP
        EXECUTE format('REVOKE ALL ON SEQUENCE %s FROM PUBLIC, anon, authenticated, service_role', owned_sequence);
        EXECUTE format('GRANT USAGE, SELECT ON SEQUENCE %s TO service_role', owned_sequence);
    END LOOP;
END;
$$;

COMMIT;
