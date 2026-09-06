-- Admin-only deletion of past sessions (cascades to report / findings / events).

create or replace function delete_session (p_session uuid)
returns void
language plpgsql security definer set search_path = public
as $$
declare v_tenant uuid;
begin
  select tenant_id into v_tenant from sessions where id = p_session;
  if v_tenant is null then
    raise exception 'session not found';
  end if;
  if not is_tenant_admin(v_tenant) then
    raise exception 'admins only';
  end if;

  delete from sessions where id = p_session;

  insert into audit_log (tenant_id, actor_user_id, action, target_type, target_id)
  values (v_tenant, auth.uid(), 'session.delete', 'session', p_session::text);
end;
$$;
grant execute on function delete_session(uuid) to authenticated;

-- Bulk: drop every session that is no longer in flight (completed / expired /
-- revoked). Leaves 'pending' and 'consumed' keys alone.
create or replace function purge_finished_sessions (p_tenant uuid)
returns integer
language plpgsql security definer set search_path = public
as $$
declare v_count integer;
begin
  if not is_tenant_admin(p_tenant) then
    raise exception 'admins only';
  end if;

  with del as (
    delete from sessions
     where tenant_id = p_tenant
       and status in ('completed', 'expired', 'revoked')
    returning 1
  )
  select count(*) into v_count from del;

  insert into audit_log (tenant_id, actor_user_id, action, meta)
  values (p_tenant, auth.uid(), 'session.purge', jsonb_build_object('deleted', v_count));

  return v_count;
end;
$$;
grant execute on function purge_finished_sessions(uuid) to authenticated;
