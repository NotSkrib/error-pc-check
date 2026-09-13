// Minimal static file server replacing Vercel's rewrites/headers config,
// for deployment on Railway. No dependencies.
//
// Env vars:
//   PORT               - listen port (Railway sets this)
//   STATIC_SUBDIR       - subdir under this file to serve (default: ".")
//   NOINDEX             - "1" to send X-Robots-Tag: noindex, nofollow on every response
//   ENABLE_R_REDIRECT   - "1" to enable /r/:key -> /d/:key redirect
import http from "node:http";
import { createReadStream, existsSync, statSync } from "node:fs";
import { extname, join, normalize, sep } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const STATIC_DIR = normalize(join(__dirname, process.env.STATIC_SUBDIR ?? "."));
const PORT = process.env.PORT ?? 8080;
const NOINDEX = process.env.NOINDEX === "1";
const ENABLE_R_REDIRECT = process.env.ENABLE_R_REDIRECT === "1";
const DOWNLOAD_FN = "https://ugxzpmsotzfhoqraohvv.supabase.co/functions/v1/download";

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".ico": "image/x-icon",
  ".woff2": "font/woff2",
};

async function proxyDownload(key, res) {
  const upstream = await fetch(`${DOWNLOAD_FN}?key=${encodeURIComponent(key)}`);
  const headers = {};
  for (const h of ["content-type", "content-length", "content-disposition", "cache-control", "x-content-type-options"]) {
    const v = upstream.headers.get(h);
    if (v) headers[h] = v;
  }
  res.writeHead(upstream.status, headers);
  if (!upstream.body) return res.end();
  for await (const chunk of upstream.body) res.write(chunk);
  res.end();
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, "http://localhost");
  if (NOINDEX) res.setHeader("X-Robots-Tag", "noindex, nofollow");

  const dMatch = url.pathname.match(/^\/d\/([^/]+)$/);
  if (dMatch) {
    await proxyDownload(dMatch[1], res);
    return;
  }

  if (ENABLE_R_REDIRECT) {
    const rMatch = url.pathname.match(/^\/r\/([^/]+)$/);
    if (rMatch) {
      res.writeHead(307, { location: `/d/${rMatch[1]}` });
      res.end();
      return;
    }
  }

  let filePath = normalize(join(STATIC_DIR, url.pathname));
  if (!filePath.startsWith(STATIC_DIR) || !existsSync(filePath) || statSync(filePath).isDirectory()) {
    filePath = join(STATIC_DIR, "index.html");
  }
  const ext = extname(filePath);
  const headers = { "content-type": MIME[ext] ?? "application/octet-stream" };
  if (filePath.includes(`${sep}assets${sep}`)) {
    headers["cache-control"] = "public, max-age=31536000, immutable";
  }
  res.writeHead(200, headers);
  createReadStream(filePath).pipe(res);
});

server.listen(PORT, () => console.log(`listening on ${PORT}`));
