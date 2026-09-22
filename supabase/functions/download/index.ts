// SSAC client download.
//
//   GET /download?key=<session key>
//
// Validates the one-time key (via Supabase Postgres — cheap, low-egress),
// then streams the self-contained client binary (stored in <=30 MB parts,
// kept in Cloudflare R2 so serving it costs no egress) reassembled, named
// plainly Error_PC_Check.exe. The key is not in the file name; the client
// recovers it from the download's Zone.Identifier (mark-of-the-web) URL, or
// prompts. No key -> friendly HTML page.

import { createClient } from "jsr:@supabase/supabase-js@2";
import { AwsClient } from "npm:aws4fetch@1.0.20";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SERVICE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const PARTS_DIR = "client/parts";

const R2_ACCOUNT_ID = Deno.env.get("R2_ACCOUNT_ID")!;
const R2_ACCESS_KEY_ID = Deno.env.get("R2_ACCESS_KEY_ID")!;
const R2_SECRET_ACCESS_KEY = Deno.env.get("R2_SECRET_ACCESS_KEY")!;
const R2_BUCKET = Deno.env.get("R2_BUCKET") ?? "ssac-assets";
const R2_ENDPOINT = `https://${R2_ACCOUNT_ID}.r2.cloudflarestorage.com/${R2_BUCKET}`;

const admin = createClient(SUPABASE_URL, SERVICE_KEY, { auth: { persistSession: false } });
const r2 = new AwsClient({ accessKeyId: R2_ACCESS_KEY_ID, secretAccessKey: R2_SECRET_ACCESS_KEY });
const enc = new TextEncoder();

function r2Get(key: string) {
  return r2.fetch(`${R2_ENDPOINT}/${key}`);
}

async function sha256Hex(s: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", enc.encode(s));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function page(title: string, body: string, status = 200) {
  return new Response(
    `<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
     <title>${title}</title>
     <div style="font:16px/1.5 system-ui;max-width:32rem;margin:12vh auto;padding:0 1.5rem;color:#e6edf3;background:#0b0f14">
       <h1 style="font-size:1.2rem">${title}</h1>${body}
     </div>`,
    { status, headers: { "content-type": "text/html; charset=utf-8" } },
  );
}

Deno.serve(async (req) => {
  const url = new URL(req.url);
  const key = (url.searchParams.get("key") ?? "").trim();
  if (!key) {
    return page("SSAC Screenshare Tool", "<p>This link is missing its key. Ask the staff member for the download link again.</p>", 400);
  }

  const { data: session } = await admin
    .from("sessions")
    .select("status, expires_at, tenants(name)")
    .eq("key_hash", await sha256Hex(key))
    .maybeSingle();

  if (!session) {
    return page("Link not recognised", "<p>This download link is not valid. Ask the staff member for a new one.</p>", 404);
  }
  if (session.status === "revoked") {
    return page("Link cancelled", "<p>A staff member cancelled this screenshare. Nothing to do.</p>", 410);
  }
  if (session.status === "completed") {
    return page("Already used", "<p>This screenshare has already been run. Ask for a new link if you need to run it again.</p>", 410);
  }
  if (session.status === "expired" || new Date(session.expires_at) < new Date()) {
    return page("Link expired", "<p>This link timed out. Ask the staff member to generate a fresh one.</p>", 410);
  }

  // read the manifest, then stream the parts back to back
  const man = await r2Get(`${PARTS_DIR}/manifest.json`);
  if (!man.ok) return page("Client unavailable", "<p>The client build is not published yet. Tell the staff member.</p>", 503);
  const manifest = JSON.parse(await man.text()) as { parts: string[]; bytes: number };

  // NOTE: do NOT append anything (e.g. a key overlay) to the end of the exe —
  // the .NET single-file host reads its bundle footer from the very end of the
  // file, so trailing bytes corrupt the bundle ("Failure processing application
  // bundle"). The key reaches the client via the `--key` argument in the
  // launcher script, or via the mark-of-the-web /d/<KEY>|?key=<KEY> URL for
  // plain browser downloads.

  const stream = new ReadableStream({
    async start(controller) {
      try {
        for (const part of manifest.parts) {
          const dl = await r2Get(`${PARTS_DIR}/${part}`);
          if (!dl.ok) throw new Error(`missing part ${part}`);
          controller.enqueue(new Uint8Array(await dl.arrayBuffer()));
        }
        controller.close();
      } catch (e) {
        controller.error(e);
      }
    },
  });

  const server = (session.tenants as { name?: string } | null)?.name ?? "server";
  return new Response(stream, {
    headers: {
      "content-type": "application/octet-stream",
      "content-length": String(manifest.bytes),
      "content-disposition": `attachment; filename="Error_PC_Check.exe"`,
      "x-content-type-options": "nosniff",
      "cache-control": "no-store",
      "x-ssac-server": server,
    },
  });
});
