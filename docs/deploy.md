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
- **Client binary** — self-contained (no runtime needed), split into <=30 MB
  parts because it exceeds the free-tier 50 MB Storage limit:

  ```bash
  ./scripts/build-client.sh
  # = dotnet build  ->  obfuscar (rename-only, client/SSAC.Client/obfuscar.xml)
  #   ->  dotnet publish --no-build   (bundles the obfuscated assembly)
  # ~145 MB. Do NOT add -p:EnableCompressionInSingleFile — a compressed
  # single-file bundle reads as "packed" to AV heuristics and picks up
  # false positives on VirusTotal. Obfuscar is rename-only (no string
  # encryption, no packing) for the same reason.
  F=client/SSAC.Client/bin/Release/net8.0-windows/win-x64/publish/ssac-screenshare.exe
  split -b 30m -d "$F" part                      # part00..partNN
  # upload each part -> ssac-assets/client/parts/partNN  (x-upsert: true)
  # write ssac-assets/client/parts/manifest.json = {"parts":[...],"bytes":N,"sha256":"..."}
  ```

### The download link

The `download` Edge Function validates the key, reads `parts/manifest.json`, and
streams the parts reassembled as a plain `Error_PC_Check.exe` (no key in the name).

The panel only ever hands out `https://ssac-panel.vercel.app/d/<KEY>`, which
`panel/vercel.json` proxies to `$SUPA_URL/functions/v1/download?key=<KEY>` — the
Supabase host never appears in the UI. (Localhost dev has no proxy, so it uses
the function URL directly there.)

The client recovers the key from the download's `Zone.Identifier` mark-of-the-web
stream (`HostUrl` = `.../d/<KEY>`), via `Options.KeyFromMarkOfTheWeb`. Order of
recovery: `--key` arg → keyed file name (`errorsmp-<KEY>.exe` /
`ssac-screenshare-<KEY>.exe`, for testing) → mark-of-the-web. There is no
paste-the-key dialog: if none of those yield a key the client shows a short
"re-download from the link" message and exits. It then uses the baked-in
`AppInfo.DefaultEndpoint`, so the suspect just downloads and double-clicks.

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
