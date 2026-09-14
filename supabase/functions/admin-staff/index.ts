// SSAC admin-staff Edge Function
//
// Owner/admin-only staff account management for the panel: list, create,
// reset password, remove. Runs with the service-role key (auth.admin.* isn't
// reachable from the client), but every call is gated on the caller's own
// Supabase session actually being an owner/admin of the target tenant.
//
// Auth: Authorization: Bearer <caller's Supabase session JWT> (NOT a service key)
// Body: { action, tenant_id, ...payload }
//   list            -> {}
//   create          -> { username }
//   reset_password  -> { user_id }
//   remove          -> { user_id }

import { createClient } from "jsr:@supabase/supabase-js@2";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SERVICE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const EMAIL_DOMAIN = "errorsmp.panel";

const admin = createClient(SUPABASE_URL, SERVICE_KEY, { auth: { persistSession: false } });

// Called via fetch() from the panel's own browser origin, so (unlike the
// built-in GoTrue/PostgREST endpoints) this needs its own CORS handling —
// Edge Functions don't get default CORS headers.
const CORS_HEADERS = {
  "access-control-allow-origin": "*",
  "access-control-allow-headers": "authorization, content-type, apikey, x-client-info",
  "access-control-allow-methods": "POST, OPTIONS",
};

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...CORS_HEADERS },
  });
}

function emailFor(username: string): string {
  const local = username.toLowerCase().replace(/[^a-z0-9._-]/g, "");
  return `${local}@${EMAIL_DOMAIN}`;
}

function genPassword(): string {
  return btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(12))))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS_HEADERS });
  if (req.method !== "POST") return json({ error: "POST only" }, 405);

  const auth = req.headers.get("authorization") ?? "";
  const jwt = auth.toLowerCase().startsWith("bearer ") ? auth.slice(7).trim() : "";
  if (!jwt) return json({ error: "missing auth" }, 401);

  const { data: caller, error: callerErr } = await admin.auth.getUser(jwt);
  if (callerErr || !caller.user) return json({ error: "invalid session" }, 401);

  let body: Record<string, unknown>;
  try {
    body = await req.json();
  } catch {
    return json({ error: "bad json" }, 400);
  }
  const action = String(body.action ?? "");
  const tenantId = String(body.tenant_id ?? "");
  if (!tenantId) return json({ error: "tenant_id required" }, 400);

  const { data: membership } = await admin
    .from("memberships")
    .select("role")
    .eq("tenant_id", tenantId)
    .eq("user_id", caller.user.id)
    .maybeSingle();
  if (!membership || !["owner", "admin"].includes(membership.role)) {
    return json({ error: "not authorized for this tenant" }, 403);
  }

  if (action === "list") {
    const { data: members, error } = await admin
      .from("memberships")
      .select("user_id, role")
      .eq("tenant_id", tenantId);
    if (error) return json({ error: error.message }, 500);

    const { data: usersPage } = await admin.auth.admin.listUsers({ perPage: 200 });
    const byId = new Map(usersPage?.users.map((u) => [u.id, u]) ?? []);
    const { data: creds } = await admin
      .from("staff_credentials")
      .select("user_id, password")
      .eq("tenant_id", tenantId);
    const passwordById = new Map((creds ?? []).map((c) => [c.user_id, c.password]));
    // Historical guest ("Continue as guest") sign-ins also landed as checker
    // members of this tenant before guest access was removed — they aren't
    // staff accounts, so leave them out of this list.
    const accounts = (members ?? [])
      .filter((m) => !byId.get(m.user_id)?.is_anonymous)
      .map((m) => {
        const u = byId.get(m.user_id);
        return {
          user_id: m.user_id,
          role: m.role,
          email: u?.email ?? null,
          display_name: (u?.user_metadata?.display_name as string | undefined) ?? null,
          created_at: u?.created_at ?? null,
          last_sign_in_at: u?.last_sign_in_at ?? null,
          password: passwordById.get(m.user_id) ?? null,
        };
      });
    return json({ accounts });
  }

  if (action === "create") {
    const username = String(body.username ?? "").trim();
    if (!username) return json({ error: "username required" }, 400);
    const email = emailFor(username);
    const password = genPassword();
    const { data, error } = await admin.auth.admin.createUser({
      email,
      password,
      email_confirm: true,
      user_metadata: { display_name: username },
    });
    if (error) return json({ error: error.message }, 409);
    await admin.from("memberships").upsert({ tenant_id: tenantId, user_id: data.user.id, role: "checker" });
    await admin
      .from("staff_credentials")
      .upsert({ tenant_id: tenantId, user_id: data.user.id, password, updated_at: new Date().toISOString() });
    return json({ user_id: data.user.id, email, password });
  }

  if (action === "reset_password") {
    const userId = String(body.user_id ?? "");
    if (!userId) return json({ error: "user_id required" }, 400);
    const password = genPassword();
    const { error } = await admin.auth.admin.updateUserById(userId, { password });
    if (error) return json({ error: error.message }, 400);
    await admin
      .from("staff_credentials")
      .upsert({ tenant_id: tenantId, user_id: userId, password, updated_at: new Date().toISOString() });
    return json({ user_id: userId, password });
  }

  if (action === "remove") {
    const userId = String(body.user_id ?? "");
    if (!userId) return json({ error: "user_id required" }, 400);
    const { error } = await admin
      .from("memberships")
      .delete()
      .eq("tenant_id", tenantId)
      .eq("user_id", userId);
    if (error) return json({ error: error.message }, 400);
    await admin.from("staff_credentials").delete().eq("tenant_id", tenantId).eq("user_id", userId);
    return json({ ok: true });
  }

  return json({ error: "unknown action" }, 400);
});
