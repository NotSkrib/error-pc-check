// SSAC public signature-DB endpoint.
//
// The client agent GETs this at scan start and uses whichever of
// (embedded seed, this response) has the higher `version` string
// (docs/phase-0-design.md §7). No auth — the DB contains only public
// cheat names / package ids / log-banner regexes.
//
// Publish flow: upload signatures/ssac-signatures.json to the Storage
// bucket `ssac-assets` at key `signatures/ssac-signatures.json`.
// If Storage is unreachable this returns an empty DB so the client
// falls back to its embedded copy.

import { createClient } from "jsr:@supabase/supabase-js@2";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SERVICE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const BUCKET = "ssac-assets";
const KEY = "signatures/ssac-signatures.json";

const admin = createClient(SUPABASE_URL, SERVICE_KEY, { auth: { persistSession: false } });

const EMPTY = JSON.stringify({ version: "0", updated: "", signatures: [] });

Deno.serve(async (req) => {
  if (req.method !== "GET") {
    return new Response(JSON.stringify({ error: "GET only" }), {
      status: 405,
      headers: { "content-type": "application/json" },
    });
  }

  let body = EMPTY;
  try {
    const { data, error } = await admin.storage.from(BUCKET).download(KEY);
    if (!error && data) body = await data.text();
  } catch {
    // fall through to EMPTY
  }

  return new Response(body, {
    headers: {
      "content-type": "application/json",
      "cache-control": "public, max-age=900",
      "access-control-allow-origin": "*",
    },
  });
});
