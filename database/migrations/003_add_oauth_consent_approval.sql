-- Ticket 37: atomic approval operation for the OAuth transaction created by ticket 36.
--
-- Ticket 35 owns the OAuth tables and ticket 36 owns transaction creation. This
-- migration deliberately does not create either dependency. Apply it only after
-- the ticket-35 migration has been applied and its column contract is confirmed.
-- The RPC is the integration boundary used by services/consentService.js.

create or replace function public.approve_oauth_authorization(
  p_transaction_id uuid,
  p_user_id bigint,
  p_approval_token_hash text
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  authorization_transaction public.oauth_authorization_transactions%rowtype;
  authorization_code text;
begin
  select * into authorization_transaction
  from public.oauth_authorization_transactions
  where transaction_id = p_transaction_id
    and user_id = p_user_id
    and approval_token_hash = p_approval_token_hash
  for update;

  if not found then
    return jsonb_build_object('status', 'invalid');
  end if;

  if authorization_transaction.status <> 'pending' then
    return jsonb_build_object('status', 'already_used');
  end if;

  if authorization_transaction.expires_at <= now() then
    update public.oauth_authorization_transactions
    set status = 'expired'
    where transaction_id = p_transaction_id;
    return jsonb_build_object('status', 'expired');
  end if;

  authorization_code := encode(gen_random_bytes(32), 'hex');

  insert into public.oauth_authorization_codes (
    code_hash,
    transaction_id,
    user_id,
    client_id,
    redirect_uri,
    scope,
    code_challenge,
    code_challenge_method,
    expires_at
  ) values (
    encode(digest(authorization_code, 'sha256'), 'hex'),
    authorization_transaction.transaction_id,
    authorization_transaction.user_id,
    authorization_transaction.client_id,
    authorization_transaction.redirect_uri,
    authorization_transaction.scope,
    authorization_transaction.code_challenge,
    authorization_transaction.code_challenge_method,
    now() + interval '60 seconds'
  );

  update public.oauth_authorization_transactions
  set status = 'approved', approved_at = now()
  where transaction_id = p_transaction_id;

  return jsonb_build_object(
    'status', 'approved',
    'authorization_code', authorization_code,
    'transaction_id', authorization_transaction.transaction_id,
    'redirect_uri', authorization_transaction.redirect_uri,
    'state', authorization_transaction.state
  );
end;
$$;

revoke all on function public.approve_oauth_authorization(uuid, bigint, text) from public;
grant execute on function public.approve_oauth_authorization(uuid, bigint, text) to service_role;