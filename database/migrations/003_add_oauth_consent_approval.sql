-- Ticket 37: atomic approval operation for the OAuth transaction created by ticket 36.
--
-- Ticket 35 owns the OAuth tables and ticket 36 owns transaction creation. This
-- migration deliberately does not create either dependency. Apply it only after
-- the ticket-35 migration has been applied and its column contract is confirmed.
-- The RPC is the integration boundary used by services/consentService.js.

create extension if not exists pgcrypto;

create or replace function public.approve_oauth_authorization(
  p_transaction_hash text,
  p_user_id bigint
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  authorization_transaction public.oauth_authorization_transactions%rowtype;
  authorization_code text;
  grant_identifier uuid;
begin
  select * into authorization_transaction
  from public.oauth_authorization_transactions
  where transaction_hash = p_transaction_hash
  for update;

  if not found then
    return jsonb_build_object('status', 'invalid');
  end if;

  if authorization_transaction.consumed_at is not null then
    return jsonb_build_object('status', 'already_used');
  end if;

  if authorization_transaction.expires_at <= now() then
    return jsonb_build_object('status', 'expired');
  end if;

  authorization_code := replace(gen_random_uuid()::text, '-', '') ||
                        replace(gen_random_uuid()::text, '-', '');

  insert into public.mcp_client_grants (
    user_id, client_id, resource, scopes
  ) values (
    p_user_id,
    authorization_transaction.client_id,
    authorization_transaction.resource,
    authorization_transaction.scopes
  )
  on conflict (user_id, client_id, resource) where status = 'active'
  do update set scopes = excluded.scopes
  returning grant_id into grant_identifier;

  insert into public.oauth_authorization_codes (
    code_hash,
    grant_id,
    client_id,
    redirect_uri,
    resource,
    scopes,
    user_id,
    code_challenge,
    expires_at
  ) values (
    encode(digest(authorization_code, 'sha256'), 'hex'),
    grant_identifier,
    authorization_transaction.client_id,
    authorization_transaction.redirect_uri,
    authorization_transaction.resource,
    authorization_transaction.scopes,
    p_user_id,
    authorization_transaction.code_challenge,
    now() + interval '60 seconds'
  );

  update public.oauth_authorization_transactions
  set bound_user_id = p_user_id, decision = 'approved', consumed_at = now()
  where id = authorization_transaction.id;

  return jsonb_build_object(
    'status', 'approved',
    'authorization_code', authorization_code,
    'transaction_id', authorization_transaction.id,
    'redirect_uri', authorization_transaction.redirect_uri,
    'state', authorization_transaction.state
  );
end;
$$;

revoke all on function public.approve_oauth_authorization(text, bigint) from public;
grant execute on function public.approve_oauth_authorization(text, bigint) to service_role;