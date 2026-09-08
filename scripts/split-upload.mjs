// Split the published client exe into <=30MB parts and upload them (plus
// manifest.json) to Supabase Storage `ssac-assets/client/parts/`, which the
// `download` Edge Function streams back reassembled.
//
//   SUPA_URL=https://<ref>.supabase.co SUPA_SERVICE=<service-role key> \
//     node scripts/split-upload.mjs <path-to-exe>
import fs from "node:fs";

const URL = process.env.SUPA_URL;
const SERVICE = process.env.SUPA_SERVICE;
const FILE = process.argv[2];
const PART = 30 * 1024 * 1024;
const DIR = "client/parts";
if (!URL || !SERVICE || !FILE) {
  console.error("need SUPA_URL, SUPA_SERVICE env + <exe path>");
  process.exit(1);
}

const buf = fs.readFileSync(FILE);
const parts = [];
for (let i = 0, n = 0; i < buf.length; i += PART, n++) {
  const name = `part${String(n).padStart(2, "0")}`;
  const chunk = buf.subarray(i, Math.min(i + PART, buf.length));
  const res = await fetch(`${URL}/storage/v1/object/ssac-assets/${DIR}/${name}`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${SERVICE}`,
      apikey: SERVICE,
      "x-upsert": "true",
      "content-type": "application/octet-stream",
    },
    body: chunk,
  });
  if (!res.ok) {
    console.error(`${name} failed: ${res.status} ${await res.text()}`);
    process.exit(1);
  }
  console.error(`${name}  ${(chunk.length / 1048576).toFixed(1)} MB  ok`);
  parts.push(name);
}

const manifest = JSON.stringify({ parts, bytes: buf.length });
const mres = await fetch(`${URL}/storage/v1/object/ssac-assets/${DIR}/manifest.json`, {
  method: "POST",
  headers: {
    authorization: `Bearer ${SERVICE}`,
    apikey: SERVICE,
    "x-upsert": "true",
    "content-type": "application/json",
  },
  body: manifest,
});
if (!mres.ok) {
  console.error(`manifest failed: ${mres.status} ${await mres.text()}`);
  process.exit(1);
}
console.error(`manifest ok  ${manifest}`);
