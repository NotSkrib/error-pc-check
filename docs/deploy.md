# Deploy / run against Supabase

The live project used for the first end-to-end run: **`ugxzpmsotzfhoqraohvv`** ("ssdetector").

## One-time setup (cloud)

```bash
npx supabase login
npx supabase link --project-ref <ref>
npx supabase db push                       # applies supabase/migrations/0001_init.sql
npx supabase functions deploy ingest signatures
npx supabase secrets set SSAC_IP_SALT=<32+ random hex>
```

`SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` are injected into Edge Functions
automatically — do not set them.

### Storage bucket `ssac-assets` (public)

Holds the client download + the signature DB. Create it public:

```bash
curl -X POST "$SUPA_URL/storage/v1/bucket" \
  -H "authorization: Bearer $SERVICE" -H "apikey: $SERVICE" -H "content-type: application/json" \
  -d '{"id":"ssac-assets","name":"ssac-assets","public":true}'
```

Upload:

- **Signature DB** — `signatures/ssac-signatures.json` → key `signatures/ssac-signatures.json`
  (POST to `$SUPA_URL/storage/v1/object/ssac-assets/signatures/ssac-signatures.json`).
  If missing, the `signatures` function returns an empty DB and the client uses its embedded copy.
- **Client binary** — `client/ssac-screenshare.exe`. Publish it first:

  ```bash
  dotnet publish client/SSAC.Client/SSAC.Client.csproj -c Release \
    --self-contained false -p:PublishSingleFile=true -p:PublishReadyToRun=false
  # ~0.6 MB, needs .NET 8 Desktop Runtime on the target machine
  ```

  Upload with `x-upsert: true` to `$SUPA_URL/storage/v1/object/ssac-assets/client/ssac-screenshare.exe`.

  > The self-contained single-file build (~63 MB, no runtime needed) exceeds the
  > free-tier 50 MB Storage limit. TODO: host that build on a CDN / GitHub
  > Release and point an Edge `download` function at it. For now the panel links
  > the framework-dependent build directly.

### The download link

The panel builds:
`$SUPA_URL/storage/v1/object/public/ssac-assets/client/ssac-screenshare.exe?download=ssac-screenshare-<KEY>.exe`

Supabase's `?download=` sets `Content-Disposition` so the browser saves the file
as `ssac-screenshare-<KEY>.exe`; the client reads its own filename to recover the
key (`Options.KeyFromOwnFilename`) and uses the baked-in `AppInfo.DefaultEndpoint`.
So the suspect just downloads and double-clicks.

## Panel

`panel/.env.local`:

```
VITE_SUPABASE_URL=https://<ref>.supabase.co
VITE_SUPABASE_ANON_KEY=<anon public key>
```

```bash
cd panel && npm install && npm run dev      # http://localhost:5173
```

Sign up, create a server (tenant), generate a key. If signup asks for email
confirmation, either click the link or turn **Authentication → Providers →
Email → Confirm email** off in the dashboard.

## Client

```bash
dotnet publish client/SSAC.Client/SSAC.Client.csproj -c Release
# -> client/SSAC.Client/bin/Release/net8.0-windows/win-x64/publish/ssac-screenshare.exe

ssac-screenshare --key <KEY> --endpoint https://<ref>.supabase.co/functions/v1
```

`--auto` runs it headless (no consent window; consent recorded as accepted +
headless) for E2E/CI. `--selftest` runs every module locally with no network.

## End-to-end check script

`scripts/e2e.mjs` needs `SUPA_URL`, `SUPA_ANON`, `SUPA_SERVICE` in the env
(service key only to create a pre-confirmed test user):

```bash
node scripts/e2e.mjs seed                   # -> JSON: { key, session_id, ... }
ssac-screenshare --auto --key <KEY> --endpoint https://<ref>.supabase.co/functions/v1
node scripts/e2e.mjs report <session_id>    # -> stored report + findings
```

### First run result (2026-09-02)

- `describe` → `start` → 16 modules → **57 findings + 82 progress events** uploaded
  via HMAC-signed POSTs to the deployed `ingest` function → `complete`,
  verdict `critical`, persisted in Postgres.
- Negatives verified: bad key → 401; valid key + bad HMAC → 401; `describe`
  does not consume the key; replay with a consumed key → client aborts.
- Session row after: `status=completed`, `consumed_at` set, `client_ip_hash`
  is a salted SHA-256 (no raw IP stored).
- RLS verified via the standard single-session client flow: authed `tenants`
  insert + owner trigger + `create_session` RPC all pass.
