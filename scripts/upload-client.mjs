// Resumable (TUS) upload of the published client exe to Supabase Storage.
// Standard uploads are capped low on the free tier; the resumable endpoint
// takes larger files. Run after `dotnet publish -c Release -p:EnableCompressionInSingleFile=true`.
//
//   SUPA_URL=... SUPA_SERVICE=... node scripts/upload-client.mjs <path-to-exe> [objectKey]

import fs from "node:fs";
import * as tus from "tus-js-client";

const URL = process.env.SUPA_URL;
const SERVICE = process.env.SUPA_SERVICE;
const file = process.argv[2];
const key = process.argv[3] ?? "client/ssac-screenshare.exe";
if (!URL || !SERVICE || !file) {
  console.error("SUPA_URL, SUPA_SERVICE env + <exe path> required");
  process.exit(1);
}

const size = fs.statSync(file).size;
console.error(`uploading ${file} (${(size / 1048576).toFixed(1)} MB) -> ssac-assets/${key}`);

const upload = new tus.Upload(fs.createReadStream(file), {
  endpoint: `${URL}/storage/v1/upload/resumable`,
  retryDelays: [0, 1000, 3000, 5000],
  headers: {
    authorization: `Bearer ${SERVICE}`,
    apikey: SERVICE,
    "x-upsert": "true",
  },
  uploadDataDuringCreation: true,
  removeFingerprintOnSuccess: true,
  chunkSize: 6 * 1024 * 1024,
  uploadSize: size,
  metadata: {
    bucketName: "ssac-assets",
    objectName: key,
    contentType: "application/octet-stream",
    cacheControl: "3600",
  },
  onError: (e) => {
    console.error("upload failed:", e.message ?? e);
    process.exit(1);
  },
  onProgress: (sent, total) => {
    process.stderr.write(`\r${((sent / total) * 100).toFixed(0)}%   `);
  },
  onSuccess: () => {
    console.error(`\ndone. public url:\n${URL}/storage/v1/object/public/ssac-assets/${key}`);
  },
});

upload.findPreviousUploads().then((prev) => {
  if (prev.length) upload.resumeFromPreviousUpload(prev[0]);
  upload.start();
});
