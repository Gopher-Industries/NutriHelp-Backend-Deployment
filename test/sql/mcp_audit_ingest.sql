-- Run in a disposable PostgreSQL database with migration 005 applied.
BEGIN;
SET LOCAL ROLE service_role;
DO $$
DECLARE
  first_event jsonb := '{"event_id":"20115f02-bbc0-4ad1-a6ab-84c5f8f93500","phase":"started","schema_version":1}';
  next_event jsonb := first_event || '{"phase":"completion"}';
  other_event jsonb := first_event || '{"event_id":"00000000-1111-4333-8444-555555555555"}';
BEGIN
  IF public.ingest_mcp_audit_events(jsonb_build_array(first_event)) <> 1 THEN RAISE EXCEPTION 'missing ack'; END IF;
  PERFORM public.ingest_mcp_audit_events(jsonb_build_array(first_event, next_event));
  IF (SELECT count(*) FROM public.mcp_audit_events WHERE event_id = (first_event->>'event_id')::uuid) <> 2 THEN
    RAISE EXCEPTION 'retry or phase persistence failed';
  END IF;
  BEGIN
    PERFORM public.ingest_mcp_audit_events(jsonb_build_array(other_event, first_event || '{"schema_version":2}'));
    RAISE EXCEPTION 'expected conflicting retry';
  EXCEPTION WHEN unique_violation THEN NULL;
  END;
  IF EXISTS (SELECT FROM public.mcp_audit_events WHERE event_id = (other_event->>'event_id')::uuid) THEN
    RAISE EXCEPTION 'partial batch persisted';
  END IF;
  IF has_function_privilege('authenticated','public.ingest_mcp_audit_events(jsonb)','execute')
     OR has_function_privilege('anon','public.ingest_mcp_audit_events(jsonb)','execute')
     OR has_table_privilege('authenticated','public.mcp_audit_events','select')
     OR has_table_privilege('anon','public.mcp_audit_events','insert') THEN
    RAISE EXCEPTION 'audit storage exposed';
  END IF;
END $$;
ROLLBACK;
