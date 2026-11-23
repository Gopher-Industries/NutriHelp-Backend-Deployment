BEGIN;
CREATE TABLE public.mcp_audit_events (
  event_id uuid NOT NULL,
  phase text NOT NULL CHECK (phase IN ('started','completion')),
  envelope jsonb NOT NULL,
  received_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (event_id, phase)
);
CREATE INDEX mcp_audit_received ON public.mcp_audit_events(received_at);
ALTER TABLE public.mcp_audit_events ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.mcp_audit_events FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT, DELETE ON public.mcp_audit_events TO service_role;

-- One RPC is one transaction. A conflicting retry rolls the entire batch back.
CREATE FUNCTION public.ingest_mcp_audit_events(envelopes jsonb) RETURNS integer
LANGUAGE plpgsql SECURITY INVOKER SET search_path = '' AS $$
DECLARE
  item jsonb;
  saved jsonb;
BEGIN
  IF jsonb_typeof(envelopes) IS DISTINCT FROM 'array' OR jsonb_array_length(envelopes) NOT BETWEEN 1 AND 32 THEN
    RAISE EXCEPTION 'invalid audit batch';
  END IF;
  FOR item IN SELECT value FROM jsonb_array_elements(envelopes) LOOP
    INSERT INTO public.mcp_audit_events(event_id, phase, envelope)
      VALUES ((item->>'event_id')::uuid, item->>'phase', item)
      ON CONFLICT (event_id, phase) DO NOTHING;
    IF NOT FOUND THEN
      SELECT envelope INTO STRICT saved FROM public.mcp_audit_events
        WHERE event_id = (item->>'event_id')::uuid AND phase = item->>'phase';
      IF saved IS DISTINCT FROM item THEN
        RAISE EXCEPTION 'conflicting audit retry' USING ERRCODE = '23505';
      END IF;
    END IF;
  END LOOP;
  DELETE FROM public.mcp_audit_events WHERE received_at < now() - interval '90 days';
  RETURN jsonb_array_length(envelopes);
END;
$$;
REVOKE ALL ON FUNCTION public.ingest_mcp_audit_events(jsonb) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.ingest_mcp_audit_events(jsonb) TO service_role;
COMMIT;
