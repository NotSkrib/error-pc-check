-- 0011: tighten RLS and function grants after security review.
--
-- 1) expire_stale_sessions(): global, cross-tenant, and was PUBLIC-executable
--    (anyone with the anon key). Restrict to signed-in users; the panel's
--    expireStale() call still works because PostgREST runs RPCs as the
--    `authenticated` role.
-- 2) join_as_guest(): guest access was retired from the product; block all
--    roles from (re)joining as a guest so no anonymous membership path remains.
-- 3) sessions/reports UPDATE policies let any member rewrite arbitrary columns
--    (status, verdict_severity, findings_count, ...) on rows they could see.
--    The panel mutates only via RPCs / Edge Functions, so revoke direct
--    PostgREST UPDATE on the security-sensitive columns for non-privileged
--    roles. Display-label columns (case_label / suspect_label on sessions)
--    stay updatable through the existing row-level policies.

-- 1) expire_stale_sessions: anon/public revoked, authenticated kept
revoke execute on function expire_stale_sessions() from public, anon;
grant execute on function expire_stale_sessions() to authenticated;

-- 2) join_as_guest: fully retired (no re-grants in later migrations)
revoke execute on function join_as_guest() from public, anon, authenticated;
revoke execute on function join_as_guest(text) from public, anon, authenticated;

-- 3) sessions: non-privileged roles may only update case_label / suspect_label
revoke update (
  key_hash, key_prefix, status, created_by, expires_at, consumed_at,
  client_ip_hash, created_at
) on sessions from anon, authenticated;

--    reports: everything except created_at is service-role/ingest-owned
revoke update (
  status, verdict_severity, findings_count, consent, environment,
  signature_db_version, client_version, started_at, completed_at,
  created_at
) on reports from anon, authenticated;