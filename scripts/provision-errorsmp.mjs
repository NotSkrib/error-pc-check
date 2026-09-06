// One-time: create the "Error SMP" tenant + an owner account, and point guest
// access at it. Idempotent-ish (skips creation if the tenant already exists).
//
//   SUPA_URL=... SUPA_SERVICE=... node scripts/provision-errorsmp.mjs <owner-email> <owner-password>

import { createClient } from "@supabase/supabase-js";

const URL = process.env.SUPA_URL;
const SERVICE = process.env.SUPA_SERVICE;
const email = process.argv[2];
const password = process.argv[3];
if (!URL || !SERVICE || !email || !password) {
  console.error("SUPA_URL, SUPA_SERVICE env + <owner-email> <owner-password> required");
  process.exit(1);
}

const admin = createClient(URL, SERVICE, { auth: { persistSession: false } });
const TENANT_NAME = "Error SMP";
const TENANT_SLUG = "error-smp";

// owner account
let ownerId;
{
  const { data, error } = await admin.auth.admin.createUser({ email, password, email_confirm: true });
  if (error && !/already been registered/i.test(error.message)) throw error;
  if (data?.user) {
    ownerId = data.user.id;
    console.error(`owner created: ${email} (${ownerId})`);
  } else {
    const { data: list } = await admin.auth.admin.listUsers();
    ownerId = list.users.find((u) => u.email === email)?.id;
    console.error(`owner already existed: ${email} (${ownerId})`);
  }
}

// tenant (service role bypasses the tenants_insert = false policy)
let tenantId;
{
  const { data: existing } = await admin.from("tenants").select("id").eq("slug", TENANT_SLUG).maybeSingle();
  if (existing) {
    tenantId = existing.id;
    console.error(`tenant already existed: ${TENANT_NAME} (${tenantId})`);
  } else {
    const { data, error } = await admin
      .from("tenants")
      .insert({ name: TENANT_NAME, slug: TENANT_SLUG, created_by: ownerId })
      .select("id")
      .single();
    if (error) throw error;
    tenantId = data.id;
    console.error(`tenant created: ${TENANT_NAME} (${tenantId})`);
  }
}

// make sure the owner is an owner-member even if the tenant pre-existed
await admin.from("memberships").upsert({ tenant_id: tenantId, user_id: ownerId, role: "owner" });

// point guest access at it
const { error: cfgErr } = await admin
  .from("app_config")
  .update({ guest_tenant_id: tenantId, guest_role: "checker", updated_at: new Date().toISOString() })
  .eq("id", 1);
if (cfgErr) throw cfgErr;

console.log(JSON.stringify({
  ok: true,
  owner_email: email,
  owner_password: password,
  tenant_id: tenantId,
  tenant_name: TENANT_NAME,
  guest_role: "checker",
}, null, 2));
