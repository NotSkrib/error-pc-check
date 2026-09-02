-- SSAC — Screenshare Anti-Cheat
-- Migration 0001: core multi-tenant schema, RLS, key-generation RPC.
--
-- Design references: docs/phase-0-design.md
--   §2.2 A4  keys are one-time, ~30 min TTL, hash-only storage, revocable
--   §2.2 A5  RLS on every table keyed by tenant_id; panel never uses service role
--   §3      severity rubric  (clean|info|low|medium|high|critical)
--   §6      retention: default 30 days, max 180, auto-purge

create extension if not exists pgcrypto with schema extensions;

-- ---------------------------------------------------------------------------
-- enums
-- ---------------------------------------------------------------------------
create type severity        as enum ('clean', 'info', 'low', 'medium', 'high', 'critical');
create type member_role     as enum ('owner', 'admin', 'checker');
create type session_status  as enum ('pending', 'consumed', 'expired', 'revoked', 'completed');
create type report_status   as enum ('running', 'complete', 'aborted', 'error');

-- ---------------------------------------------------------------------------
-- tenants  (one per customer / Minecraft server brand)
-- ---------------------------------------------------------------------------
create table tenants (
  id              uuid primary key default gen_random_uuid(),
  name            text not null check (char_length(name) between 2 and 60),
  slug            text not null unique check (slug ~ '^[a-z0-9][a-z0-9-]{1,38}[a-z0-9]$'),
  retention_days  int  not null default 30 check (retention_days between 1 and 180),
  plan            text not null default 'trial',
  created_by      uuid not null references auth.users (id),
  created_at      timestamptz not null default now()
);

-- ---------------------------------------------------------------------------
-- memberships  (auth user <-> tenant, with role)
-- ---------------------------------------------------------------------------
create table memberships (
  tenant_id  uuid not null references tenants (id) on delete cascade,
  user_id    uuid not null references auth.users (id) on delete cascade,
  role       member_role not null default 'checker',
  created_at timestamptz not null default now(),
  primary key (tenant_id, user_id)
);
create index memberships_user_idx on memberships (user_id);

-- ---------------------------------------------------------------------------
-- subscriptions  (billing stub — Stripe wiring is Phase 7)
-- ---------------------------------------------------------------------------
create table subscriptions (
  tenant_id             uuid primary key references tenants (id) on delete cascade,
  provider              text not null default 'stripe',
  status                text not null default 'trialing',
  current_period_end    timestamptz,
  stripe_customer_id     text,
  stripe_subscription_id text,
  updated_at            timestamptz not null default now()
);

-- ---------------------------------------------------------------------------
-- sessions  (a "key" / screenshare case; raw key is NEVER stored)
-- ---------------------------------------------------------------------------
create table sessions (
  id             uuid primary key default gen_random_uuid(),
  tenant_id      uuid not null references tenants (id) on delete cascade,
  case_label     text not null check (char_length(case_label) between 1 and 80),
  suspect_label  text check (char_length(suspect_label) <= 80),
  key_hash       text not null unique,          -- hex sha256 of the raw token
  key_prefix     text not null,                 -- first 8 chars, for display only
  status         session_status not null default 'pending',
  created_by     uuid not null references auth.users (id),
  expires_at     timestamptz not null,
  consumed_at    timestamptz,
  client_ip_hash text,                          -- salted hash, set by ingest fn
  created_at     timestamptz not null default now()
);
create index sessions_tenant_idx  on sessions (tenant_id, created_at desc);
create index sessions_status_idx  on sessions (status) where status = 'pending';

-- ---------------------------------------------------------------------------
-- reports  (one per session)
-- ---------------------------------------------------------------------------
create table reports (
  id                   uuid primary key default gen_random_uuid(),
  tenant_id            uuid not null references tenants (id) on delete cascade,
  session_id           uuid not null unique references sessions (id) on delete cascade,
  status               report_status not null default 'running',
  verdict_severity     severity not null default 'info',
  findings_count       jsonb not null default '{}'::jsonb,   -- {critical:0,high:1,...}
  consent              jsonb,                                -- {accepted,at,browser_history_optin,server_name_shown,case_label}
  environment          jsonb,                                -- {os_build,uptime_seconds,is_vm,debugger_present,client_hash_ok,elevated}
  signature_db_version text,
  client_version       text,
  started_at           timestamptz not null default now(),
  completed_at         timestamptz,
  created_at           timestamptz not null default now()
);
create index reports_tenant_idx on reports (tenant_id, created_at desc);

-- ---------------------------------------------------------------------------
-- findings
-- ---------------------------------------------------------------------------
create table findings (
  id          uuid primary key default gen_random_uuid(),
  report_id   uuid not null references reports (id) on delete cascade,
  tenant_id   uuid not null references tenants (id) on delete cascade,
  module      text not null,
  severity    severity not null,
  title       text not null,
  description text not null default '',
  evidence    jsonb not null default '{}'::jsonb,  -- snippets / hashes / metadata only, never whole files
  occurred_at timestamptz,                         -- e.g. file deletion time
  sort_key    int not null default 0,
  created_at  timestamptz not null default now()
);
create index findings_report_idx on findings (report_id, sort_key);

-- ---------------------------------------------------------------------------
-- report_events  (live progress stream; published to Realtime)
-- ---------------------------------------------------------------------------
create table report_events (
  id         bigint generated always as identity primary key,
  report_id  uuid not null references reports (id) on delete cascade,
  tenant_id  uuid not null references tenants (id) on delete cascade,
  kind       text not null,          -- module_start | module_done | progress | log
  module     text,
  message    text not null default '',
  pct        int  check (pct between 0 and 100),
  created_at timestamptz not null default now()
);
create index report_events_report_idx on report_events (report_id, id);

-- ---------------------------------------------------------------------------
-- audit_log
-- ---------------------------------------------------------------------------
create table audit_log (
  id            bigint generated always as identity primary key,
  tenant_id     uuid references tenants (id) on delete cascade,
  actor_user_id uuid references auth.users (id),
  action        text not null,
  target_type   text,
  target_id     text,
  meta          jsonb not null default '{}'::jsonb,
  ip_hash       text,
  created_at    timestamptz not null default now()
);
create index audit_log_tenant_idx on audit_log (tenant_id, created_at desc);

-- ---------------------------------------------------------------------------
-- helper functions (security definer; used by RLS policies)
-- ---------------------------------------------------------------------------
create or replace function is_tenant_member (p_tenant uuid)
returns boolean language sql stable security definer set search_path = public as $$
  select exists (
    select 1 from memberships
    where tenant_id = p_tenant and user_id = auth.uid()
  );
$$;

create or replace function is_tenant_admin (p_tenant uuid)
returns boolean language sql stable security definer set search_path = public as $$
  select exists (
    select 1 from memberships
    where tenant_id = p_tenant and user_id = auth.uid()
      and role in ('owner', 'admin')
  );
$$;

-- add creator as owner whenever a tenant is created
create or replace function tenants_add_owner ()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  insert into memberships (tenant_id, user_id, role)
  values (new.id, new.created_by, 'owner');
  insert into subscriptions (tenant_id) values (new.id);
  return new;
end;
$$;
create trigger tenants_add_owner_trg
  after insert on tenants
  for each row execute function tenants_add_owner ();

-- refuse to drop the last owner of a tenant
create or replace function memberships_guard_last_owner ()
returns trigger language plpgsql as $$
begin
  if (tg_op = 'DELETE' or (tg_op = 'UPDATE' and new.role <> 'owner'))
     and old.role = 'owner'
     and (select count(*) from memberships
          where tenant_id = old.tenant_id and role = 'owner') <= 1
  then
    raise exception 'cannot remove the last owner of a tenant';
  end if;
  return coalesce(new, old);
end;
$$;
create trigger memberships_guard_last_owner_trg
  before update or delete on memberships
  for each row execute function memberships_guard_last_owner ();

-- ---------------------------------------------------------------------------
-- key generation RPC — returns the raw token ONCE; DB keeps only the hash
-- ---------------------------------------------------------------------------
create or replace function create_session (p_tenant uuid, p_case_label text, p_suspect_label text default null)
returns table (session_id uuid, key text, expires_at timestamptz)
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_token   text;
  v_hash    text;
  v_id      uuid;
  v_expires timestamptz := now() + interval '30 minutes';
begin
  if not is_tenant_member(p_tenant) then
    raise exception 'not a member of this tenant';
  end if;

  -- url-safe random token, ~32 chars
  v_token := replace(replace(encode(extensions.gen_random_bytes(24), 'base64'), '+', '-'), '/', '_');
  v_token := rtrim(v_token, '=');
  v_hash  := encode(extensions.digest(v_token, 'sha256'), 'hex');

  insert into sessions (tenant_id, case_label, suspect_label, key_hash, key_prefix, created_by, expires_at)
  values (p_tenant, p_case_label, p_suspect_label, v_hash, left(v_token, 8), auth.uid(), v_expires)
  returning id into v_id;

  insert into audit_log (tenant_id, actor_user_id, action, target_type, target_id, meta)
  values (p_tenant, auth.uid(), 'session.create', 'session', v_id::text,
          jsonb_build_object('case_label', p_case_label));

  return query select v_id, v_token, v_expires;
end;
$$;

create or replace function revoke_session (p_session uuid)
returns void language plpgsql security definer set search_path = public as $$
declare v_tenant uuid;
begin
  select tenant_id into v_tenant from sessions where id = p_session;
  if v_tenant is null or not is_tenant_member(v_tenant) then
    raise exception 'session not found';
  end if;
  update sessions set status = 'revoked'
   where id = p_session and status in ('pending', 'consumed');
  insert into audit_log (tenant_id, actor_user_id, action, target_type, target_id)
  values (v_tenant, auth.uid(), 'session.revoke', 'session', p_session::text);
end;
$$;

-- mark stale pending sessions expired; purge reports past tenant retention
create or replace function expire_stale_sessions ()
returns void language sql security definer set search_path = public as $$
  update sessions set status = 'expired'
   where status = 'pending' and expires_at < now();
$$;

create or replace function purge_old_reports ()
returns void language plpgsql security definer set search_path = public as $$
begin
  delete from reports r
  using tenants t
  where r.tenant_id = t.id
    and r.created_at < now() - make_interval(days => t.retention_days);
end;
$$;

-- ---------------------------------------------------------------------------
-- RLS
-- ---------------------------------------------------------------------------
alter table tenants        enable row level security;
alter table memberships    enable row level security;
alter table subscriptions  enable row level security;
alter table sessions       enable row level security;
alter table reports        enable row level security;
alter table findings       enable row level security;
alter table report_events  enable row level security;
alter table audit_log      enable row level security;

-- tenants
create policy tenants_select on tenants for select using (is_tenant_member(id));
create policy tenants_insert on tenants for insert with check (created_by = auth.uid());
create policy tenants_update on tenants for update using (is_tenant_admin(id)) with check (is_tenant_admin(id));

-- memberships
create policy memberships_select on memberships for select using (is_tenant_member(tenant_id));
create policy memberships_write  on memberships for all
  using (is_tenant_admin(tenant_id)) with check (is_tenant_admin(tenant_id));

-- subscriptions (read-only to admins; writes come from service role / webhooks)
create policy subscriptions_select on subscriptions for select using (is_tenant_admin(tenant_id));

-- sessions
create policy sessions_select on sessions for select using (is_tenant_member(tenant_id));
create policy sessions_insert on sessions for insert with check (is_tenant_member(tenant_id) and created_by = auth.uid());
create policy sessions_update on sessions for update
  using (is_tenant_member(tenant_id))
  with check (is_tenant_member(tenant_id));

-- reports / findings / events: panel reads only; ingest Edge Function (service role) writes
create policy reports_select on reports for select using (is_tenant_member(tenant_id));
create policy reports_update_label on reports for update
  using (is_tenant_member(tenant_id)) with check (is_tenant_member(tenant_id));
create policy findings_select on findings for select using (is_tenant_member(tenant_id));
create policy report_events_select on report_events for select using (is_tenant_member(tenant_id));

-- audit log: admins read
create policy audit_select on audit_log for select using (is_tenant_admin(tenant_id));

-- ---------------------------------------------------------------------------
-- realtime
-- ---------------------------------------------------------------------------
alter publication supabase_realtime add table report_events;
alter publication supabase_realtime add table reports;

-- ---------------------------------------------------------------------------
-- scheduled maintenance (best-effort; requires pg_cron on the project)
-- ---------------------------------------------------------------------------
do $$
begin
  if exists (select 1 from pg_extension where extname = 'pg_cron') then
    perform cron.schedule('ssac-expire-sessions', '*/5 * * * *', 'select expire_stale_sessions();');
    perform cron.schedule('ssac-purge-reports',   '17 3 * * *',  'select purge_old_reports();');
  end if;
end;
$$;
