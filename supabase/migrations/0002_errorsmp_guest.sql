-- Single-tenant "Error SMP" mode + anonymous guest access.
--
-- Public sign-up is turned off in the auth server (config.toml). Staff either
-- have an account an admin provisioned, or click "Continue as guest" which does
-- an anonymous sign-in and calls join_as_guest() to attach to the Error SMP
-- tenant with a limited role.

-- ---------------------------------------------------------------------------
-- app_config: singleton pointing at the tenant guests join
-- ---------------------------------------------------------------------------
create table app_config (
  id              int primary key default 1 check (id = 1),
  guest_tenant_id uuid references tenants (id) on delete set null,
  guest_role      member_role not null default 'checker',
  updated_at      timestamptz not null default now()
);
insert into app_config (id) values (1) on conflict do nothing;

alter table app_config enable row level security;
-- readable by any signed-in visitor (incl. anonymous); writes are service-role only
create policy app_config_read on app_config for select
  using (auth.role() in ('authenticated', 'anon'));

-- ---------------------------------------------------------------------------
-- no self-serve tenant creation anymore — provisioning is service-role only
-- ---------------------------------------------------------------------------
drop policy if exists tenants_insert on tenants;
create policy tenants_insert on tenants for insert with check (false);

-- ---------------------------------------------------------------------------
-- join_as_guest(): attach the caller to the configured tenant + role
-- ---------------------------------------------------------------------------
create or replace function join_as_guest ()
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

  insert into memberships (tenant_id, user_id, role)
  values (v_tenant, auth.uid(), v_role)
  on conflict (tenant_id, user_id) do nothing;

  insert into audit_log (tenant_id, actor_user_id, action, meta)
  values (v_tenant, auth.uid(), 'guest.join', jsonb_build_object('is_anonymous', v_anon));

  return v_tenant;
end;
$$;

grant execute on function join_as_guest() to anon, authenticated;
