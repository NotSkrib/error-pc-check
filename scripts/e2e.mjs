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
  const email = `ssac.e2e.${stamp}@ssacdemo.com`;
  const password = `E2e-${stamp}-Aa1!`;

  const { data: created, error: cErr } = await admin.auth.admin.createUser({
    email,
    password,
    email_confirm: true,
  });
  if (cErr) throw cErr;
  console.error(`user: ${email} (${created.user.id})`);

  // One client, real in-memory session — exactly how the panel behaves.
  const user = createClient(URL, ANON, { auth: { persistSession: false } });
  const { data: signIn, error: sErr } = await user.auth.signInWithPassword({ email, password });
  if (sErr) throw sErr;
  const claims = JSON.parse(Buffer.from(signIn.session.access_token.split(".")[1], "base64url").toString());
  console.error(`signed in — role=${claims.role} sub=${claims.sub}`);

  const slug = `e2e-demo-${stamp}`;
  const ins = await user.from("tenants").insert({ name: "E2E Demo Server", slug, created_by: created.user.id });
  if (ins.error) throw new Error(`tenants insert (RLS): ${ins.error.message}`);
  const { data: tenant, error: selErr } = await user
    .from("tenants").select("id,name").eq("slug", slug).single();
  if (selErr) throw selErr;
  console.error(`tenant (authed insert, RLS OK): ${tenant.name} (${tenant.id})`);

  const { data: rpc, error: rErr } = await user.rpc("create_session", {
    p_tenant: tenant.id, p_case_label: `e2e-${stamp}`, p_suspect_label: "headless-demo",
  });
  if (rErr) throw new Error(`create_session (RLS): ${rErr.message}`);
  console.error("create_session (authed RPC, RLS OK)");
  const row = Array.isArray(rpc) ? rpc[0] : rpc;

  console.log(JSON.stringify({
    email, password,
    tenant_id: tenant.id,
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
