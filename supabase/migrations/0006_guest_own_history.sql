-- Guests (checker role) see only the sessions they created + those reports.
-- Owners / admins still see everything for the tenant.

drop policy if exists sessions_select on sessions;
create policy sessions_select on sessions for select using (
  is_tenant_admin(tenant_id) or created_by = auth.uid()
);

drop policy if exists sessions_update on sessions;
create policy sessions_update on sessions for update
  using (is_tenant_admin(tenant_id) or created_by = auth.uid())
  with check (is_tenant_admin(tenant_id) or created_by = auth.uid());

drop policy if exists reports_select on reports;
create policy reports_select on reports for select using (
  is_tenant_admin(tenant_id)
  or exists (select 1 from sessions s where s.id = reports.session_id and s.created_by = auth.uid())
);

drop policy if exists reports_update_label on reports;
create policy reports_update_label on reports for update
  using (
    is_tenant_admin(tenant_id)
    or exists (select 1 from sessions s where s.id = reports.session_id and s.created_by = auth.uid())
  )
  with check (
    is_tenant_admin(tenant_id)
    or exists (select 1 from sessions s where s.id = reports.session_id and s.created_by = auth.uid())
  );

drop policy if exists findings_select on findings;
create policy findings_select on findings for select using (
  is_tenant_admin(tenant_id)
  or exists (
    select 1 from reports r join sessions s on s.id = r.session_id
    where r.id = findings.report_id and s.created_by = auth.uid()
  )
);

drop policy if exists report_events_select on report_events;
create policy report_events_select on report_events for select using (
  is_tenant_admin(tenant_id)
  or exists (
    select 1 from reports r join sessions s on s.id = r.session_id
    where r.id = report_events.report_id and s.created_by = auth.uid()
  )
);

-- A guest can only revoke their own key.
create or replace function revoke_session (p_session uuid)
returns void language plpgsql security definer set search_path = public as $$
declare v_tenant uuid; v_owner uuid;
begin
  select tenant_id, created_by into v_tenant, v_owner from sessions where id = p_session;
  if v_tenant is null then
    raise exception 'session not found';
  end if;
  if not (is_tenant_admin(v_tenant) or v_owner = auth.uid()) then
    raise exception 'not allowed';
  end if;
  update sessions set status = 'revoked'
   where id = p_session and status in ('pending', 'consumed');
  insert into audit_log (tenant_id, actor_user_id, action, target_type, target_id)
  values (v_tenant, auth.uid(), 'session.revoke', 'session', p_session::text);
end;
$$;
