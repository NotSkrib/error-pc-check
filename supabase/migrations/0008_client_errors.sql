-- Self-hosted crash reporting (a small stand-in for Sentry).
-- The client posts unhandled exceptions to the `client-error` Edge Function,
-- which writes them here with the service role. Staff read them in the panel.

create table if not exists client_errors (
  id             uuid primary key default gen_random_uuid(),
  tenant_id      uuid references tenants (id) on delete cascade,  -- null if the crash beat key resolution
  key_prefix     text,                                            -- first chars of the session key, if any
  phase          text not null default 'fatal',                   -- describe | start | scan | complete | fatal | thread-exception | ...
  client_version text,
  os_build       text,
  exception_type text,
  message        text,
  stack          text,
  created_at     timestamptz not null default now()
);

create index if not exists client_errors_tenant_time on client_errors (tenant_id, created_at desc);

alter table client_errors enable row level security;

-- admins / owners of a tenant see that tenant's crashes
create policy client_errors_tenant_read on client_errors for select
  using (tenant_id is not null and is_tenant_admin(tenant_id));

-- any owner also sees orphaned crashes (no tenant could be resolved)
create policy client_errors_orphan_read on client_errors for select
  using (
    tenant_id is null
    and exists (select 1 from memberships m where m.user_id = auth.uid() and m.role = 'owner')
  );

-- no insert / update / delete policies: only the Edge Function (service role) writes.

-- housekeeping: drop crash rows older than 90 days
create or replace function purge_old_client_errors ()
returns integer language plpgsql security definer set search_path = public as $$
declare n integer;
begin
  delete from client_errors where created_at < now() - interval '90 days';
  get diagnostics n = row_count;
  return n;
end;
$$;
