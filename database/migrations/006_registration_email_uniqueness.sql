-- Registration inserts use ON CONFLICT (email) DO NOTHING so concurrent
-- retries cannot replace an existing password. Reuse any suitable unique index.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_index i
    JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = i.indkey[0]
    WHERE i.indrelid = 'public.users'::regclass AND a.attname = 'email'
      AND i.indisunique AND i.indisvalid AND i.indimmediate
      AND i.indnkeyatts = 1 AND i.indpred IS NULL
  ) THEN
    -- Duplicate emails need manual reconciliation; do not edit account data.
    CREATE UNIQUE INDEX users_registration_email_unique ON public.users (email);
  END IF;
END;
$$;
