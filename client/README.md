# SSAC client agent (Phase 2)

Windows, C# / .NET 8, WinForms. Single-file self-contained `.exe`.

The suspect runs this once. It: reads the key → `describe` (shows the real server
name on the consent screen without consuming the key) → consent screen
(`docs/phase-0-design.md §5`) → `start` (consumes the key, opens the report) →
runs scan modules, streaming progress + findings to the panel over an
HMAC-signed channel → `complete` → shows the suspect exactly what was sent →
exits and deletes `%TEMP%\ssac-*`.

## Build

```bash
dotnet build client/SSAC.Client.sln
dotnet test  client/SSAC.Client.sln
```

## Publish the single-file exe

```bash
dotnet publish client/SSAC.Client/SSAC.Client.csproj -c Release
# -> client/SSAC.Client/bin/Release/net8.0-windows/win-x64/publish/ssac-screenshare.exe
```

## Run against local Supabase (end-to-end check)

1. `cd supabase && supabase start` (needs Docker + the Supabase CLI).
2. Apply the migration and serve the function:
   `supabase db reset` then `supabase functions serve ingest --no-verify-jwt`.
3. In the panel, sign up, create a server, generate a key.
4. Run the client pointed at the local function:

   ```bash
   ssac-screenshare --key <KEY> --endpoint http://localhost:54321/functions/v1
   ```

5. Watch the report fill in live on the panel's report page.

## MVP scan modules (this phase)

| Module | Severity signals | Allowlist ref |
|---|---|---|
| `environment` | debugger attached, VM, uptime < 5 min | §4.1 |
| `processes` | known autoclicker process names, unsigned `javaw` | §4.1, T6 |
| `pipeline-check` | one `info` finding proving the channel works | — |

Phase 3+ replaces `pipeline-check` with the real forensic collectors (Prefetch,
BAM/DAM, USN journal, `$MFT`, Recycle Bin, `.minecraft` inspection, known-cheat
signature DB, and the anti-forensic correlation engine).

## Not done yet (later phases)

- SPKI cert pinning value is a `--pin` flag only; the baked-in production pin +
  rotation plan is Phase 7.
- `SelfIntegrity` hashes the running image but does not yet compare to a signed
  manifest (Phase 7).
- Code signing + published SHA-256 (Phase 7).
- Admin-only collectors + UAC elevation prompt (Phase 3).
