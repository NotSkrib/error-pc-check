-- Shorten the one-time key so the download link and file name stay compact.
-- 12 random bytes -> 16 url-safe base64 chars (was 24 bytes / 32 chars).
-- Still 96 bits of entropy for a single-use token that expires in 30 minutes.
-- Body is otherwise identical to 0004 (keeps the guest / staff "by" label).

create or replace function create_session (p_tenant uuid, p_case_label text, p_suspect_label text default null)
returns table (session_id uuid, key text, expires_at timestamptz)
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_token   text;
  v_hash    text;
  v_id      uuid;
  v_expires timestamptz := now() + interval '30 minutes';
  v_label   text;
  v_name    text;
begin
  if not is_tenant_member(p_tenant) then
    raise exception 'not a member of this tenant';
  end if;

  if coalesce((auth.jwt() ->> 'is_anonymous')::boolean, false) then
    select raw_user_meta_data ->> 'display_name' into v_name from auth.users where id = auth.uid();
    v_label := coalesce(nullif(trim(v_name), ''), 'guest') || ' (guest)';
  else
    v_label := coalesce(auth.jwt() ->> 'email', 'staff');
  end if;

  v_token := replace(replace(encode(extensions.gen_random_bytes(12), 'base64'), '+', '-'), '/', '_');
  v_token := rtrim(v_token, '=');
  v_hash  := encode(extensions.digest(v_token, 'sha256'), 'hex');

  insert into sessions (tenant_id, case_label, suspect_label, key_hash, key_prefix, created_by, created_by_label, expires_at)
  values (p_tenant, p_case_label, p_suspect_label, v_hash, left(v_token, 6), auth.uid(), v_label, v_expires)
  returning id into v_id;

  insert into audit_log (tenant_id, actor_user_id, action, target_type, target_id, meta)
  values (p_tenant, auth.uid(), 'session.create', 'session', v_id::text,
          jsonb_build_object('case_label', p_case_label, 'by', v_label));

  return query select v_id, v_token, v_expires;
end;
$$;
