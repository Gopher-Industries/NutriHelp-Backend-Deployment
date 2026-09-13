create table if not exists public.consent_transactions (
  transaction_id uuid primary key,
  user_id bigint not null references public.users(user_id) on delete cascade,
  approval_token_hash text not null,
  action_hash text not null,
  status text not null default 'pending' check (status in ('pending', 'approved', 'expired')),
  expires_at timestamptz not null,
  approved_at timestamptz,
  result jsonb,
  created_at timestamptz not null default now()
);

create unique index if not exists consent_transactions_token_hash_idx
  on public.consent_transactions (approval_token_hash);

create or replace function public.approve_consent_transaction(
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
  transaction_row public.consent_transactions%rowtype;
begin
  select * into transaction_row
  from public.consent_transactions
  where transaction_id = p_transaction_id
    and user_id = p_user_id
    and approval_token_hash = p_approval_token_hash
  for update;

  if not found then
    return jsonb_build_object('status', 'invalid');
  end if;

  if transaction_row.status <> 'pending' then
    return jsonb_build_object('status', 'already_used');
  end if;

  if transaction_row.expires_at <= now() then
    update public.consent_transactions
    set status = 'expired'
    where transaction_id = p_transaction_id;
    return jsonb_build_object('status', 'expired');
  end if;

  update public.consent_transactions
  set status = 'approved', approved_at = now()
  where transaction_id = p_transaction_id;

  return jsonb_build_object('status', 'approved', 'transaction_id', transaction_row.transaction_id);
end;
$$;

revoke all on function public.approve_consent_transaction(uuid, bigint, text) from public;
grant execute on function public.approve_consent_transaction(uuid, bigint, text) to service_role;