// Client crash sink — a minimal self-hosted alternative to Sentry.
//
//   POST { key?, phase, client_version, os_build, exception_type, message, stack }
//
// No HMAC and no JWT: the client may be reporting *because* signing or JSON
// serialisation is what broke. If a valid session key is supplied we attach the
// tenant so the right staff can see it; otherwise it is stored as an orphan that
// only an owner can read. Always returns 200 — crash reporting must not itself
// fail loudly.

import { createClient } from "jsr:@supabase/supabase-js@2";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SERVICE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const admin = createClient(SUPABASE_URL, SERVICE_KEY, { auth: { persistSession: false } });
const enc = new TextEncoder();

async function sha256Hex(s: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", enc.encode(s));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

const clip = (v: unknown, n: number) => (v == null ? null : String(v).slice(0, n));

Deno.serve(async (req) => {
  if (req.method !== "POST") return new Response("POST only", { status: 405 });

  let body: Record<string, unknown> = {};
  try {
    const raw = await req.text();
    if (raw.length <= 64 * 1024) body = JSON.parse(raw);
  } catch {
    // keep going — we still record what little we have
  }

  let tenantId: string | null = null;
  let keyPrefix: string | null = null;
  const key = typeof body.key === "string" ? body.key.trim() : "";
  if (key) {
    keyPrefix = key.slice(0, 6);
    try {
      const { data: session } = await admin
        .from("sessions")
        .select("tenant_id")
        .eq("key_hash", await sha256Hex(key))
        .maybeSingle();
      tenantId = session?.tenant_id ?? null;
    } catch {
      // ignore — store as orphan
    }
  }

  try {
    await admin.from("client_errors").insert({
      tenant_id: tenantId,
      key_prefix: keyPrefix,
      phase: clip(body.phase, 40) ?? "fatal",
      client_version: clip(body.client_version, 40),
      os_build: clip(body.os_build, 120),
      exception_type: clip(body.exception_type, 200),
      message: clip(body.message, 2000),
      stack: clip(body.stack, 12000),
    });
  } catch {
    // swallow — nothing useful to return to a crashing client
  }

  return new Response(JSON.stringify({ ok: true }), {
    headers: { "content-type": "application/json" },
  });
});
