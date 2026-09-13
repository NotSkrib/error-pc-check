# Handoff: R2 migration for client downloads

## Why

Supabase sent a Fair Use warning: the `download` Edge Function was streaming
the full client `.exe` out of Supabase Storage on every screenshare link,
with `cache-control: no-store` (so nothing was ever cached) and a unique key
baked into each file (so no two downloads could ever share a cached copy).
Egress scaled linearly with download count, which is what tripped the quota.
Fair Use restrictions start **October 13, 2026**.

Fix: move the client binary to Cloudflare R2, which has no egress fees.
Supabase keeps just the `sessions` table lookup (tiny) and the signature DB
(`signatures/ssac-signatures.json`, tiny, unchanged).

## What's done (code, already committed + pushed)

Branch: `claude/case-suspect-field-mapping-2shdvg`, commit `4080807`.

- `supabase/functions/download/index.ts` — now fetches `manifest.json` and
  the binary parts from an R2 bucket (via `aws4fetch`, using
  `R2_ACCOUNT_ID` / `R2_ACCESS_KEY_ID` / `R2_SECRET_ACCESS_KEY` /
  `R2_BUCKET` env vars) instead of Supabase Storage. Session-key validation
  is unchanged — still Supabase Postgres.
- `scripts/split-upload.mjs` — rewritten to split the built exe into
  <=30 MB parts and PUT them (plus `manifest.json`) to R2 instead of
  Supabase Storage. Same env-var names as above.
- `package.json` / `package-lock.json` — added `aws4fetch` dependency.
- `.github/workflows/release-client.yml` — the "publish signed build" step
  now runs `npm ci` and calls the updated upload script with `R2_*`
  secrets/vars instead of `SUPA_URL`/`SUPA_SERVICE`.
- `docs/deploy.md` — rewritten the storage section: `ssac-assets` on
  Supabase Storage now only holds the signature DB; the client binary
  section documents the R2 bucket + token setup and the new upload command.

None of this touches the panel UI, the client binary itself, or the
session/key-validation logic — it's purely swapping where the `.exe` bytes
live and get read from.

## What's needed (manual, Cloudflare/Supabase/GitHub account setup)

**1. Cloudflare R2 bucket + token**
- Create bucket `ssac-assets` in R2.
- Create an **Account API token** (not User API token — account tokens
  keep working even if the creator leaves the org, which matters since this
  token lives long-term in CI/Supabase secrets), permission
  **Object Read & Write**, scoped to just `ssac-assets`.
- ⚠️ A token's Access Key ID / Secret Access Key were pasted into a chat
  session during setup — **that token must be rolled/deleted and
  recreated** before going live. Treat anything typed into a chat as
  compromised.
- Note the Account ID (visible in the R2 dashboard sidebar, or as the
  `<account-id>` in the token's S3 endpoint `https://<account-id>.r2.cloudflarestorage.com`).

**2. Supabase secrets + deploy**
```bash
npx supabase secrets set R2_ACCOUNT_ID=<account id> \
  R2_ACCESS_KEY_ID=<access key id> \
  R2_SECRET_ACCESS_KEY=<secret access key> \
  R2_BUCKET=ssac-assets
npx supabase functions deploy download
```

**3. GitHub Actions secrets/vars** (repo → Settings → Secrets and variables → Actions)
- Secrets: `R2_ACCOUNT_ID`, `R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY`
- Variable: `R2_BUCKET` = `ssac-assets`

**4. Publish the current build to R2** (one-time — the old parts are still
only on Supabase Storage, R2 is empty until this runs)
```bash
R2_ACCOUNT_ID=<account id> R2_ACCESS_KEY_ID=<key> R2_SECRET_ACCESS_KEY=<secret> \
  node scripts/split-upload.mjs <path to the built/signed exe>
```
Or just cut a new release tag — `release-client.yml` now does this step
automatically once the GitHub secrets from step 3 are set.

**5. Verify**
- Generate a screenshare key from the panel, hit the `/d/<key>` link, and
  confirm the `.exe` downloads correctly and still runs (the per-download
  key footer logic in `download/index.ts` is unchanged, only the source of
  the bytes changed).
- After confirming, the old parts under `ssac-assets/client/parts/*` in
  **Supabase** Storage can be deleted — nothing reads from there anymore.
  Leave `ssac-assets/signatures/ssac-signatures.json` alone, that one's
  still live.

## Not done / open questions

- The R2 token from step 1 has not yet been created/rotated to a clean one.
- Steps 2–4 have not been run yet — `download/index.ts` on the deployed
  Supabase project is still the **old** Storage-based version until
  `supabase functions deploy download` is run with the R2 secrets in place.
  Don't cut over panel traffic assuming it's already live.
