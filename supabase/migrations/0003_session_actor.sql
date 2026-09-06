-- Record who generated each key so an admin can supervise all checks.

alter table sessions add column if not exists created_by_label text;

create or replace function create_session (p_tenant uuid, p_case_label text, p_suspect_label text default null)
returns table (session_id uuid, key text, expires_at timestamptz)
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_token   text;
  v_hash    text;
  v_id      uuid;
  v_expires timestamptz := now() + interval '30 minutes';
  v_label   text;
begin
  if not is_tenant_member(p_tenant) then
    raise exception 'not a member of this tenant';
  end if;

  v_label := case
    when coalesce((auth.jwt() ->> 'is_anonymous')::boolean, false) then 'guest'
    else coalesce(auth.jwt() ->> 'email', 'staff')
  end;

  v_token := replace(replace(encode(extensions.gen_random_bytes(24), 'base64'), '+', '-'), '/', '_');
  v_token := rtrim(v_token, '=');
  v_hash  := encode(extensions.digest(v_token, 'sha256'), 'hex');

  insert into sessions (tenant_id, case_label, suspect_label, key_hash, key_prefix, created_by, created_by_label, expires_at)
  values (p_tenant, p_case_label, p_suspect_label, v_hash, left(v_token, 8), auth.uid(), v_label, v_expires)
  returning id into v_id;

  insert into audit_log (tenant_id, actor_user_id, action, target_type, target_id, meta)
  values (p_tenant, auth.uid(), 'session.create', 'session', v_id::text,
          jsonb_build_object('case_label', p_case_label, 'by', v_label));

  return query select v_id, v_token, v_expires;
end;
$$;
