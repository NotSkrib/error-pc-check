// Bulk-create staff accounts on the "Error SMP" tenant as `checker` members.
// Idempotent: re-running skips usernames that already have an account.
//
//   SUPA_URL=... SUPA_SERVICE=... node scripts/provision-staff.mjs
//
// Prints created accounts (email + generated password) as JSON on stdout —
// save that output, it's the only time the passwords are shown.

import { createClient } from "@supabase/supabase-js";
import crypto from "node:crypto";

const URL = process.env.SUPA_URL;
const SERVICE = process.env.SUPA_SERVICE;
if (!URL || !SERVICE) {
  console.error("SUPA_URL, SUPA_SERVICE env required");
  process.exit(1);
}

const USERNAMES = [
  "quizyyx", "Kr", "Ziggyyy_", "Mogtivz", "Hvnter", "Omurice", "SuperMatus",
  "Vibindreamer", "WorstMain", "Eskiess", "krimalos", "Noxiiiiii12", "Kvrsd",
];
const TENANT_SLUG = "error-smp";
const EMAIL_DOMAIN = "errorsmp.panel";

function emailFor(username) {
  const local = username.toLowerCase().replace(/[^a-z0-9._-]/g, "");
  return `${local}@${EMAIL_DOMAIN}`;
}

function genPassword() {
  return crypto.randomBytes(12).toString("base64url");
}

const admin = createClient(URL, SERVICE, { auth: { persistSession: false } });

const { data: tenant, error: tenantErr } = await admin
  .from("tenants")
  .select("id")
  .eq("slug", TENANT_SLUG)
  .single();
if (tenantErr) throw tenantErr;
const tenantId = tenant.id;

const results = [];
for (const username of USERNAMES) {
  const email = emailFor(username);
  const password = genPassword();
  const { data, error } = await admin.auth.admin.createUser({
    email,
    password,
    email_confirm: true,
    user_metadata: { display_name: username },
  });
  if (error && !/already been registered/i.test(error.message)) throw error;

  let userId;
  let created;
  if (data?.user) {
    userId = data.user.id;
    created = true;
  } else {
    const { data: list } = await admin.auth.admin.listUsers();
    userId = list.users.find((u) => u.email === email)?.id;
    created = false;
  }

  await admin.from("memberships").upsert({ tenant_id: tenantId, user_id: userId, role: "checker" });
  results.push({ username, email, password: created ? password : "(unchanged — account already existed)", created });
}

console.log(JSON.stringify({ ok: true, tenant_id: tenantId, accounts: results }, null, 2));
