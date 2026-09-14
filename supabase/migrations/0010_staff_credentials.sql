-- Recoverable staff passwords for the panel's /staff page, at the owner's
-- explicit request (small trusted-staff tool — plaintext-recoverable
-- passwords are an accepted tradeoff here, not the default we'd pick for a
-- public-facing product). Written only by the admin-staff Edge Function
-- (service role) on create/reset; read only by that same function, which
-- re-checks the caller is an owner/admin of the tenant on every call. No
-- client-side RLS policies at all — this table is unreachable via postgREST
-- even for an authenticated owner, on purpose.

create table if not exists staff_credentials (
  tenant_id  uuid not null references tenants (id) on delete cascade,
  user_id    uuid not null references auth.users (id) on delete cascade,
  password   text not null,
  updated_at timestamptz not null default now(),
  primary key (tenant_id, user_id)
);

alter table staff_credentials enable row level security;
-- intentionally no policies: only the service role (Edge Function) touches this table.
