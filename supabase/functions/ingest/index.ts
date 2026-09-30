// Error SMP Screenshare ingest Edge Function
//
// The client agent authenticates with its one-time session key (raw token) and
// signs every request body with HMAC-SHA256 using that same token as the shared
// secret (docs/phase-0-design.md §2.2 A3). This function is the ONLY writer of
// reports / findings / report_events; it runs with the service-role key so RLS
// does not apply here — every insert is explicitly scoped to the session tenant.
//
// Body: { action, ...payload }
//   start    -> { consent, environment, client_version, signature_db_version }
//   event    -> { kind, module?, message?, pct? }
//   finding  -> { module, severity, title, description?, evidence?, occurred_at?, sort_key? }
//   complete -> { verdict_severity, findings_count, status? }

import { createClient } from "jsr:@supabase/supabase-js@2";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SERVICE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
// Fail closed: IP hashing is only as good as the salt, and a predictable
// "dev-salt" fallback would let stored IP hashes be reversed. Deploys must
// set SSAC_IP_SALT explicitly; the handler refuses to run without it.
const IP_SALT = Deno.env.get("SSAC_IP_SALT");
// Optional Discord webhook. When set, every completed (or aborted) screenshare
// posts an embed: who checked, who got checked, the verdict, and a report link.
// Deploys without it silently skip the notification.
const DISCORD_WEBHOOK_URL = Deno.env.get("DISCORD_WEBHOOK_URL");
const PANEL_BASE = Deno.env.get("PANEL_BASE") ?? "https://ssac-panel.vercel.app";

const admin = createClient(SUPABASE_URL, SERVICE_KEY, { auth: { persistSession: false } });

const enc = new TextEncoder();
const SEVERITIES = ["clean", "info", "low", "medium", "high", "critical"] as const;

const VERDICT_COLORS: Record<string, number> = {
  clean: 0x37b26a,
  info: 0x3aa0d1,
  low: 0xd1a33a,
  medium: 0xe0803a,
  high: 0xe5484d,
  critical: 0xff5b6b,
};

const VERDICT_LABELS: Record<string, string> = {
  clean: "Clean",
  info: "Info",
  low: "Low",
  medium: "Medium",
  high: "High",
  critical: "Critical",
};

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

async function announceCompleted(
  sessionId: string,
  verdict: string,
  counts: unknown,
  aborted: boolean,
): Promise<void> {
  if (!DISCORD_WEBHOOK_URL) return;
  try {
    const { data: detail } = await admin
      .from("sessions")
      .select("case_label, suspect_label, created_by_label, tenants(name)")
      .eq("id", sessionId)
      .maybeSingle();
    const tenant = detail?.tenants as { name?: string } | null;
    const countsObj = counts && typeof counts === "object"
      ? (counts as Record<string, number>)
      : {};
    const countsText = Object.entries(countsObj)
      .filter(([, n]) => (n ?? 0) > 0)
      .map(([k, n]) => `${k}: ${n}`)
      .join("\n");
    const link = `${PANEL_BASE}/reports/${sessionId}`;
    const payload = {
      username: "Error SMP Screenshare",
      embeds: [{
        title: aborted ? "Screenshare aborted" : "Screenshare completed",
        description: tenant?.name ?? "Error SMP Screenshare",
        color: aborted ? 0x597086 : (VERDICT_COLORS[verdict] ?? 0x3aa0d1),
        url: link,
        fields: [
          { name: "Checked by", value: detail?.case_label ?? "—", inline: true },
          { name: "Suspect", value: detail?.suspect_label ?? "—", inline: true },
          { name: "Verdict", value: VERDICT_LABELS[verdict] ?? verdict, inline: true },
          { name: "Findings", value: countsText || "no findings", inline: true },
          { name: "Report", value: link, inline: false },
        ],
        footer: { text: aborted ? "report was aborted" : "evidence, not a verdict" },
        timestamp: new Date().toISOString(),
      }],
    };
    const res = await fetch(DISCORD_WEBHOOK_URL, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!res.ok) console.error(`discord webhook returned ${res.status}`);
  } catch (e) {
    console.error("discord webhook error", e);
  }
}

async function sha256Hex(s: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", enc.encode(s));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function hmacHex(key: string, msg: string): Promise<string> {
  const k = await crypto.subtle.importKey(
    "raw",
    enc.encode(key),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", k, enc.encode(msg));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let out = 0;
  for (let i = 0; i < a.length; i++) out |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return out === 0;
}

Deno.serve(async (req) => {
  if (!IP_SALT) return json({ error: "misconfigured: SSAC_IP_SALT not set" }, 500);
  if (req.method !== "POST") return json({ error: "POST only" }, 405);

  const auth = req.headers.get("authorization") ?? "";
  const rawKey = auth.toLowerCase().startsWith("bearer ") ? auth.slice(7).trim() : "";
  if (!rawKey) return json({ error: "missing key" }, 401);

  const rawBody = await req.text();
  const sig = req.headers.get("x-ssac-sig") ?? "";
  const expectSig = await hmacHex(rawKey, rawBody);
  if (!timingSafeEqual(sig, expectSig)) return json({ error: "bad signature" }, 401);

  let body: Record<string, unknown>;
  try {
    body = JSON.parse(rawBody);
  } catch {
    return json({ error: "bad json" }, 400);
  }
  const action = String(body.action ?? "");

  // resolve the session from the key hash
  const keyHash = await sha256Hex(rawKey);
  const { data: session } = await admin
    .from("sessions")
    .select("id, tenant_id, status, expires_at")
    .eq("key_hash", keyHash)
    .maybeSingle();

  if (!session) return json({ error: "unknown key" }, 401);
  if (session.status === "revoked") return json({ error: "key revoked" }, 403);
  if (session.status === "expired" || new Date(session.expires_at) < new Date()) {
    return json({ error: "key expired" }, 403);
  }

  const ipHash = await sha256Hex(
    IP_SALT + ":" + (req.headers.get("x-forwarded-for") ?? "").split(",")[0].trim(),
  );

  // ------- describe: key details for the consent screen; does NOT consume the key -------
  if (action === "describe") {
    const { data: meta } = await admin
      .from("sessions")
      .select("case_label, suspect_label, expires_at, tenants(name)")
      .eq("id", session.id)
      .single();
    return json({
      server_name: (meta?.tenants as { name?: string } | null)?.name ?? "Unknown server",
      case_label: meta?.case_label ?? "",
      suspect_label: meta?.suspect_label ?? null,
      expires_at: meta?.expires_at ?? session.expires_at,
      already_used: session.status !== "pending",
    });
  }

  // ------- start: consume the key, create the report -------
  if (action === "start") {
    if (session.status !== "pending") return json({ error: "key already used" }, 409);

    await admin
      .from("sessions")
      .update({ status: "consumed", consumed_at: new Date().toISOString(), client_ip_hash: ipHash })
      .eq("id", session.id);

    const { data: report, error } = await admin
      .from("reports")
      .insert({
        tenant_id: session.tenant_id,
        session_id: session.id,
        status: "running",
        consent: body.consent ?? null,
        environment: body.environment ?? null,
        client_version: body.client_version ?? null,
        signature_db_version: body.signature_db_version ?? null,
      })
      .select("id")
      .single();
    if (error) return json({ error: error.message }, 500);
    return json({ report_id: report.id });
  }

  // every other action needs the running report
  const { data: report } = await admin
    .from("reports")
    .select("id, status")
    .eq("session_id", session.id)
    .maybeSingle();
  if (!report) return json({ error: "call start first" }, 409);
  if (report.status !== "running") return json({ error: "report already finalised" }, 409);

  if (action === "event") {
    await admin.from("report_events").insert({
      report_id: report.id,
      tenant_id: session.tenant_id,
      kind: String(body.kind ?? "log"),
      module: body.module ?? null,
      message: String(body.message ?? ""),
      pct: typeof body.pct === "number" ? body.pct : null,
    });
    return json({ ok: true });
  }

  if (action === "finding") {
    const severity = String(body.severity ?? "");
    if (!SEVERITIES.includes(severity as typeof SEVERITIES[number])) {
      return json({ error: "bad severity" }, 400);
    }
    await admin.from("findings").insert({
      report_id: report.id,
      tenant_id: session.tenant_id,
      module: String(body.module ?? "unknown"),
      severity,
      title: String(body.title ?? "").slice(0, 300),
      description: String(body.description ?? "").slice(0, 4000),
      evidence: body.evidence ?? {},
      occurred_at: body.occurred_at ?? null,
      sort_key: typeof body.sort_key === "number" ? body.sort_key : 0,
    });
    return json({ ok: true });
  }

  if (action === "complete") {
    const verdict = String(body.verdict_severity ?? "info");
    const aborted = body.status === "aborted";
    await admin
      .from("reports")
      .update({
        status: aborted ? "aborted" : "complete",
        verdict_severity: SEVERITIES.includes(verdict as typeof SEVERITIES[number]) ? verdict : "info",
        findings_count: body.findings_count ?? {},
        completed_at: new Date().toISOString(),
      })
      .eq("id", report.id);
    await admin.from("sessions").update({ status: "completed" }).eq("id", session.id);
    await announceCompleted(session.id, verdict, body.findings_count, aborted);
    return json({ ok: true });
  }

  return json({ error: "unknown action" }, 400);
});
