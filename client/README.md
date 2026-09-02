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

## Scan modules

Run `ssac-screenshare --selftest` to execute every module locally with no
network and print the findings (dev smoke test).

| Module | What it reads | Signals | Priv |
|---|---|---|---|
| `environment` | OS build, uptime, VM/debugger, elevation | debugger attached, VM, uptime < 5 min | user |
| `processes` | running process list + signatures | autoclicker names, unsigned `javaw` (T6) | user |
| `prefetch` | `C:\Windows\Prefetch\*.pf` names + mtimes | suspicious exe ran; folder empty/wiped (T7) | user\* |
| `bam` | `bam\State\UserSettings\<SID>` | suspicious exe ran + FILETIME | user\* |
| `userassist` | `Explorer\UserAssist\*\Count` (ROT13) | GUI-launched suspicious program + run count | user |
| `shimcache` | `AppCompatCache` blob (Win10/11 `10ts`) | suspicious path present | user |
| `registry` | RunMRU, TypedPaths, Run keys, MUICache | suspicious autostart / typed path / run | user |
| `recycle-bin` | `$Recycle.Bin\*\$I*` (v1 + v2) | deleted `.jar`/`.exe`/`.dll`, esp. from `mods\` (T7) | user |
| `powershell-history` | `PSReadLine\ConsoleHost_history.txt` | download / inject / Defender-tamper commands | user |
| `minecraft` | every instance's `mods/*.jar` (name + zip entries), `versions/*.json`, `logs/*.log(.gz)`, `launcher_profiles.json`, `config/` | **known-cheat signature DB** hits (Meteor/Wurst/LiquidBounce/RusherHack/…), `-javaagent` in a profile or version manifest, custom `mainClass`, cheaty config names (T1, T2) | user |
| `usn-journal` | NTFS `$J` via FSCTL | deleted `.pf`, deleted cheat files, bulk wipe (T7) | admin |
| `amcache` / `mft` | — | not implemented (offline hive / raw NTFS) — Phase 3b | admin |
| `eventlog` | Security 4688 | process-creation events naming cheats | admin |
| `correlation` | *(the others' output)* | exec-without-Prefetch on a tampered system; cheat name across ≥2 artifacts; Prefetch wiped but other history survives (**T7 headline**) | — |

\* needs elevation to read on most systems; degrades to a `module_unavailable`
info finding without it.

## Signature DB

`signatures/ssac-signatures.json` (repo root) is embedded in the client and also
served by the public `signatures` Edge Function (client uses the newer of the
two by `version` string; the version used is recorded in every report). Matchers:
`file_name_regex`, `log_regex`, `string` (jar entry / config / log substring),
`file_hash`. A signature fires when its matched matcher weights sum to
`min_confidence`. Seed carries 18 families; `file_hash` matchers are
community-contributed and empty in the seed.

Phase 3b: real Amcache.hve + `$MFT` parsers. Phase 5: in-instance JVM/native.
Phase 6: report/verdict polish + PDF export.

## Not done yet (later phases)

- SPKI cert pinning value is a `--pin` flag only; the baked-in production pin +
  rotation plan is Phase 7.
- `SelfIntegrity` hashes the running image but does not yet compare to a signed
  manifest (Phase 7).
- Code signing + published SHA-256 (Phase 7).
- Admin-only collectors + UAC elevation prompt (Phase 3).
