// SSAC end-to-end check against a live Supabase project.
//
//   node scripts/e2e.mjs seed     -> creates a confirmed user + tenant + one-time key, prints KEY / SESSION
//   node scripts/e2e.mjs report <sessionId>  -> prints the stored report + findings
//
// Env: SUPA_URL, SUPA_ANON, SUPA_SERVICE  (service key used only to create a
// pre-confirmed test user so signup email confirmation doesn't block CI).

import { createClient } from "@supabase/supabase-js";

const URL = process.env.SUPA_URL;
const ANON = process.env.SUPA_ANON;
const SERVICE = process.env.SUPA_SERVICE;
if (!URL || !ANON || !SERVICE) {
  console.error("set SUPA_URL, SUPA_ANON, SUPA_SERVICE");
  process.exit(1);
}

const admin = createClient(URL, SERVICE, { auth: { persistSession: false } });
const cmd = process.argv[2];

if (cmd === "seed") {
  const stamp = Date.now();

  // Self-serve tenant creation is disabled (migration 0002). Use the real guest
  // path: anonymous sign-in -> join_as_guest -> create_session.
  const anon = createClient(URL, ANON, { auth: { persistSession: false } });
  const { data: sIn, error: sErr } = await anon.auth.signInAnonymously();
  if (sErr) throw new Error(`anonymous sign-in: ${sErr.message}`);
  const user = createClient(URL, ANON, {
    auth: { persistSession: false },
    global: { headers: { Authorization: `Bearer ${sIn.session.access_token}` } },
  });

  const { data: tenantId, error: jErr } = await user.rpc("join_as_guest");
  if (jErr) throw new Error(`join_as_guest: ${jErr.message}`);
  console.error(`guest joined tenant ${tenantId}`);

  const { data: rpc, error: rErr } = await user.rpc("create_session", {
    p_tenant: tenantId, p_case_label: `e2e-${stamp}`, p_suspect_label: "headless-demo",
  });
  if (rErr) throw new Error(`create_session: ${rErr.message}`);
  const row = Array.isArray(rpc) ? rpc[0] : rpc;

  console.log(JSON.stringify({
    tenant_id: tenantId,
    session_id: row.session_id,
    key: row.key,
    expires_at: row.expires_at,
  }, null, 2));
} else if (cmd === "report") {
  const sessionId = process.argv[3];
  if (!sessionId) { console.error("usage: report <sessionId>"); process.exit(1); }

  const { data: report, error: e1 } = await admin
    .from("reports").select("*").eq("session_id", sessionId).maybeSingle();
  if (e1) throw e1;
  if (!report) { console.log("no report yet"); process.exit(0); }

  const { data: findings } = await admin
    .from("findings").select("module,severity,title,description,occurred_at")
    .eq("report_id", report.id).order("sort_key");
  const { data: events } = await admin
    .from("report_events").select("kind,module,message,pct").eq("report_id", report.id).order("id");

  console.log("REPORT", JSON.stringify({
    status: report.status,
    verdict: report.verdict_severity,
    counts: report.findings_count,
    client: report.client_version,
    signature_db: report.signature_db_version,
    consent: report.consent,
    environment: report.environment,
    started_at: report.started_at,
    completed_at: report.completed_at,
  }, null, 2));
  console.log(`\nEVENTS: ${events?.length ?? 0}`);
  console.log(`\nFINDINGS: ${findings?.length ?? 0}`);
  for (const f of findings ?? [])
    console.log(`  [${f.severity.toUpperCase().padEnd(8)}] ${f.module.padEnd(16)} ${f.title}`);
} else {
  console.error("usage: node scripts/e2e.mjs seed | report <sessionId>");
  process.exit(1);
}
