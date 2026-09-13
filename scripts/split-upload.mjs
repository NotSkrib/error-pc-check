// Split the published client exe into <=30MB parts and upload them (plus
// manifest.json) to Cloudflare R2 `<bucket>/client/parts/`, which the
// `download` Edge Function streams back reassembled.
//
//   R2_ACCOUNT_ID=<account id> R2_ACCESS_KEY_ID=<key id> \
//     R2_SECRET_ACCESS_KEY=<secret> R2_BUCKET=ssac-assets \
//     node scripts/split-upload.mjs <path-to-exe>
import fs from "node:fs";
import { AwsClient } from "aws4fetch";

const ACCOUNT_ID = process.env.R2_ACCOUNT_ID;
const ACCESS_KEY_ID = process.env.R2_ACCESS_KEY_ID;
const SECRET_ACCESS_KEY = process.env.R2_SECRET_ACCESS_KEY;
const BUCKET = process.env.R2_BUCKET ?? "ssac-assets";
const FILE = process.argv[2];
const PART = 30 * 1024 * 1024;
const DIR = "client/parts";
if (!ACCOUNT_ID || !ACCESS_KEY_ID || !SECRET_ACCESS_KEY || !FILE) {
  console.error("need R2_ACCOUNT_ID, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY env + <exe path>");
  process.exit(1);
}

const endpoint = `https://${ACCOUNT_ID}.r2.cloudflarestorage.com/${BUCKET}`;
const r2 = new AwsClient({ accessKeyId: ACCESS_KEY_ID, secretAccessKey: SECRET_ACCESS_KEY });

async function put(key, body, contentType) {
  const res = await r2.fetch(`${endpoint}/${key}`, {
    method: "PUT",
    headers: { "content-type": contentType },
    body,
  });
  if (!res.ok) {
    console.error(`${key} failed: ${res.status} ${await res.text()}`);
    process.exit(1);
  }
}

const buf = fs.readFileSync(FILE);
const parts = [];
for (let i = 0, n = 0; i < buf.length; i += PART, n++) {
  const name = `part${String(n).padStart(2, "0")}`;
  const chunk = buf.subarray(i, Math.min(i + PART, buf.length));
  await put(`${DIR}/${name}`, chunk, "application/octet-stream");
  console.error(`${name}  ${(chunk.length / 1048576).toFixed(1)} MB  ok`);
  parts.push(name);
}

const manifest = JSON.stringify({ parts, bytes: buf.length });
await put(`${DIR}/manifest.json`, manifest, "application/json");
console.error(`manifest ok  ${manifest}`);
