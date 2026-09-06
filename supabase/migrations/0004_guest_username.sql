-- Let a guest pick a display name; show "<name> (guest)" in the By column.

create or replace function join_as_guest (p_name text default null)
returns uuid
language plpgsql security definer set search_path = public
as $$
declare
  v_tenant uuid;
  v_role   member_role;
  v_anon   boolean := coalesce((auth.jwt() ->> 'is_anonymous')::boolean, false);
begin
  if auth.uid() is null then
    raise exception 'not authenticated';
  end if;

  select guest_tenant_id, guest_role into v_tenant, v_role from app_config where id = 1;
  if v_tenant is null then
    raise exception 'guest access is not configured';
  end if;

  if p_name is not null and length(trim(p_name)) > 0 then
    update auth.users
       set raw_user_meta_data = coalesce(raw_user_meta_data, '{}'::jsonb)
                                || jsonb_build_object('display_name', left(trim(p_name), 40))
     where id = auth.uid();
  end if;

  insert into memberships (tenant_id, user_id, role)
  values (v_tenant, auth.uid(), v_role)
  on conflict (tenant_id, user_id) do nothing;

  insert into audit_log (tenant_id, actor_user_id, action, meta)
  values (v_tenant, auth.uid(), 'guest.join',
          jsonb_build_object('is_anonymous', v_anon, 'name', p_name));

  return v_tenant;
end;
$$;
grant execute on function join_as_guest(text) to anon, authenticated;

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
