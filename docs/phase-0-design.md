# Phase 0 — Design, Threat Model & Policy

Status: **draft**. This document is the reference for Phases 1–6. No code depends on it at runtime; it governs design decisions and the copy shipped in the client and panel.

---

## 1. Product summary

SSAC is a forensic scanner a Minecraft server's staff run against a **consenting** suspect's Windows PC to find evidence of cheat use. It is **not** a real-time anti-cheat. It produces evidence + severity, and a human decides.

### Actors

| Actor | Description | Trust |
|---|---|---|
| Owner | Buys a tenant, manages billing + staff | Full tenant admin |
| Admin | Manages checkers, views all reports | Tenant admin |
| Checker | Generates keys, runs screenshares, views own reports | Scoped |
| Suspect | Runs the client agent on their PC, gives consent | Untrusted; controls the machine being scanned |
| SSAC backend | Supabase project (Postgres + Auth + Realtime + Storage) | Trusted service |

### Non-goals (v1)

- Bedrock / console / mobile.
- Linux / macOS suspect machines.
- Automated banning or punishment.
- Real-time / in-game detection.
- Deep in-instance JVM + native memory scanning — deferred to **Phase 5 (v2)**.

---

## 2. Threat model

### 2.1 What we are defending against (detection targets)

The suspect is trying to use cheats and hide it. Categories:

| # | Technique | On-disk / in-memory signal | Phase |
|---|---|---|---|
| T1 | Mod-based client (Fabric/Forge coremod) | Jar in `.minecraft/mods/`, launcher profile, `logs/latest.log` lines | 4 |
| T2 | `-javaagent` / `-agentpath` launch injection | Agent flag in `javaw.exe` cmdline; transformer registered | 4 (cmdline), 5 (transformer) |
| T3 | Attach-API runtime injection | Orphan classloader, classes with null code source, `InstrumentationImpl` present | 5 |
| T4 | Traceless native JVM injection (`JNI_GetCreatedJavaVMs` + `Unsafe.defineClass`) | Private `PAGE_EXECUTE` memory not module-backed; unknown thread start addresses | 5 |
| T5 | Native DLL injection / ejection (external "injection clients") | Unsigned / temp-path / no-disk-backing DLL in `javaw.exe`; unloaded-module record; IAT/inline hooks | 5 |
| T6 | External autoclicker / macro | Separate process with LL mouse/keyboard hook; AHK; `JNativeHook` import | 4 (known binaries), 5 (live hooks) |
| T7 | Anti-forensics (clear Prefetch, secure-delete jars, timestomp, reboot pre-SS) | Deleted `.pf` in USN journal; MFT records for deleted exe/jar; Amcache↔Prefetch mismatch; uptime < minutes | 3 |

**MVP (Phases 0–4 + 6) covers T1, T2 (cmdline), T6 (known binaries), and all of T7.** The anti-forensic correlation engine (T7) is the headline capability — it is the hardest signal for a cheater to defeat and does not depend on the game being open.

### 2.2 What we are defending the *product* against (abuse + attack)

| # | Risk | Mitigation | Phase |
|---|---|---|---|
| A1 | Tool repackaged / passed off as benign software to scan someone without consent | Unmistakable branding + purpose text on every screen; mandatory consent click logged into report; no silent/headless mode; no persistence | 2 |
| A2 | Client used as general spyware (read documents, photos, messages) | Hard allowlist of scan targets (§4); browser history opt-in and off by default; code review gate on any new collector | 2–4 |
| A3 | Forged / tampered report uploaded to make someone look guilty (or innocent) | Session token + HMAC-SHA256 over canonicalised payload; server rejects mismatches; client self-integrity check | 2, 6 |
| A4 | Stolen key reused | One-time use, ~30 min TTL, bound to one report row, revocable, single client run | 1 |
| A5 | Cross-tenant data access | Postgres RLS on every table keyed by `tenant_id`; no service-role key in the panel | 1 |
| A6 | Panel account takeover | Argon2id (Supabase default), mandatory TOTP 2FA for Owner/Admin, short session, audit log | 1, 7 |
| A7 | Backend holds sensitive PC forensic data → attractive target | Evidence encrypted at rest (libsodium sealed box, per-tenant key), retention purge job, IP truncated/hashed, pentest | 7 |
| A8 | AV flags the client | Code sign, publish SHA-256, submit to vendors, no obfuscation, no packing | 7 |
| A9 | Ingest endpoint abused (spam/DoS) | Rate limit per tenant + per IP; payload size cap; key must be valid+unused | 1, 7 |
| A10 | Suspect runs client in a VM / feeds fake data | Client reports VM/debugger/tamper indicators; report flags "environment not trustworthy"; staff sees it | 2, 6 |

### 2.3 Trust boundaries

```
[Panel SPA] --(Supabase Auth JWT, anon key, RLS)--> [Supabase Postgres/Realtime]
[Client .exe] --(session token + HMAC, TLS+pin)--> [Edge Function: ingest] --> [Postgres]
```

- The panel **never** holds the service-role key. All panel access goes through RLS with the user's JWT.
- The client **never** holds any long-lived secret — only the per-session token, valid once.
- Ingest is an **Edge Function** (not direct table writes) so HMAC + key validation + rate limiting happen server-side.

---

## 3. Severity rubric

Every finding carries exactly one severity. The report verdict is the **highest** severity present plus counts.

| Severity | Meaning | Example |
|---|---|---|
| `clean` | Checked, nothing notable | No files in `mods/`; Prefetch consistent with Amcache |
| `info` | Context for the reviewer, not itself suspicious | Minecraft last launched 3h ago; 2 legit mods present (Sodium, Lithium) |
| `low` | Minor anomaly, plausible innocent explanation | A `.pf` file is missing but Prefetch service is disabled system-wide |
| `medium` | Anomaly that needs an explanation from the suspect | Autoclicker binary present but not running; unknown jar in `mods/` matching no signature |
| `high` | Strong indicator, hard to explain innocently | `logs/latest.log` contains a known cheat client banner; jar hash matches a known cheat |
| `critical` | Direct evidence of cheat use or deliberate anti-forensics | Known cheat jar deleted from `mods/` 4 minutes ago (USN); Amcache entry for `doomsday.exe` with matching deleted `.pf` |

Rules:
- A collector that could not run (missing privilege, artifact absent) emits an `info` finding `module_unavailable` — never silently skipped.
- Correlation findings (T7) may be `critical` even when each individual artifact is only `low`.
- The report header always shows: **"Findings are evidence, not a verdict. A human must review. SSAC does not recommend or apply punishment."**

---

## 4. Scan-target allowlist (client agent)

The client may read **only** the following. Anything not listed requires a design change + code review.

### 4.1 Always (no elevation needed)

- Process list: name, pid, path, start time, signature status, command line, parent pid.
- `%APPDATA%\.minecraft\` — `mods/`, `versions/*/*.json` and `*.jar` (hash only), `config/`, `logs/*.log` and `logs/*.log.gz`, `launcher_profiles.json`, `launcher_accounts.json` (existence + count only, **no tokens**), `options.txt`.
- Other known launcher roots: `PrismLauncher/instances/*/`, `.lunarclient/`, `.feather/`, MultiMC, ATLauncher, GDLauncher (same file set).
- Recycle Bin `$I` index records (original path + delete time) system-wide; `$R` content only for `.jar`/`.exe`/`.dll` under a size cap.
- Registry (read-only): `...\bam\State\UserSettings\<SID>`, `...\Explorer\UserAssist`, `RecentDocs`, `RunMRU`, `MUICache`, `AppCompatCache`, Run keys, `.minecraft` file assoc.
- Registry (read-only): `HKLM\SYSTEM\CurrentControlSet\Services\*` — driver/service entries: name, `Type`, `ImagePath`, driver-image signature (general-cheat + BYOVD detection). `HKCU\Software\Cheat Engine` existence.
- `bcdedit /enum {current}` output — boot flags only (`testsigning`, `nointegritychecks`, `debug`); no modification.
- File **names only** (never contents) of `*.exe` / `*.dll` / `*.sys` / `*.ahk` under `Downloads`, `Desktop`, and `%TEMP%` (depth ≤ 2), matched against cheat-tool naming.
- `C:\Windows\Prefetch\*.pf` (metadata + referenced paths).
- Scheduled Tasks (name, action path, trigger).
- System info: uptime, boot time, OS build, whether running in a VM, whether a debugger is attached to the client.
- Client self: own file hash vs signed manifest.

### 4.2 With elevation (UAC prompt, explained; degrade gracefully if declined)

- `$MFT` parse (deleted-file records, MACB timestamps, timestomp detection).
- USN Journal `$Extend\$UsnJrnl:$J` (create/delete/rename history).
- `Amcache.hve` (program hashes, first-run times).
- Windows Event Log: Security 4688, `Microsoft-Windows-PowerShell/Operational`, Sysmon if installed.
- PowerShell console history file (`ConsoleHost_history.txt`).

### 4.3 Opt-in only (checkbox on consent screen, default OFF)

- Browser download history (Chrome/Edge/Firefox `History` DBs — **download rows only**, never browsing history or form data).

### 4.4 Never

- Document/media/message file contents. Email. Chat logs. Saved passwords / cookies / session tokens / auth DBs. Full-disk enumeration. Keystroke capture. Screenshots of the desktop. Webcam/mic. Network packet capture. Anything outside the above.

---

## 5. Consent screen copy (client agent)

> **SSAC Screenshare Tool — <SERVER NAME>**
>
> A staff member of **<SERVER NAME>** has asked you to run a screenshare check. This tool looks for evidence of Minecraft cheating on this PC and sends a report to that server's panel.
>
> **What it reads:**
> - Your list of running programs and when they started
> - Your Minecraft folders: mods, version files, logs, launcher settings (it does **not** read your account password or login token)
> - Windows records of which programs have run or been deleted recently
> - The Recycle Bin (only `.jar`, `.exe`, `.dll` files)
>
> **What it never touches:** your documents, photos, messages, browser history*, passwords, or anything unrelated to Minecraft.
> *unless you tick the optional box below.
>
> **What it does NOT do:** install anything, stay running after it finishes, start with Windows, or capture your screen or keystrokes. It deletes its own temporary files when it closes.
>
> `[ ]` Also check my browser's **download history** for cheat-client downloads (optional)
>
> This report will be linked to case **<CASE ID>** for **<SERVER NAME>**. By continuing you confirm you are doing this voluntarily.
>
> `[ Cancel ]`    `[ I consent — start the scan ]`

The consent result (accepted/declined, timestamp, opt-in box state, case id, server name shown) is the first record written into the report.

---

## 6. Terms of Service — key clauses (multi-tenant product)

Full ToS drafted by counsel before launch (Phase 7). Non-negotiable clauses:

1. **Consent required.** Tenants may only run a scan against a person who has been told what the tool does and agrees. Running it covertly, or misrepresenting the tool, is prohibited and terminates the account.
2. **No minors without guardian involvement** where local law requires it.
3. **Purpose limitation.** Reports may be used only to adjudicate cheating on the tenant's own Minecraft server(s). No resale, profiling, or cross-referencing individuals.
4. **Retention.** Reports auto-delete after the tenant's configured window (default 30 days, max 180).
5. **No punishment automation reliance.** Tenant acknowledges findings are probabilistic and require human review.
6. **Jurisdiction.** Tenant is responsible for compliance with computer-misuse and privacy law in their and the suspect's jurisdiction.
7. **Watermarking.** Every report and export is watermarked with tenant name + case id + timestamp; removing it is a breach.

Panel enforces: consent copy cannot be edited by tenants beyond the server name; retention slider bounded; export always watermarked.

---

## 7. Known-cheat signature database

- Format: JSON, one entry per cheat/version, fields: `id`, `name`, `family`, `type` (`mod|native|autoclicker`), `matchers[]` (`{kind: file_hash|file_name_regex|log_regex|string, value, weight}`), `min_confidence`, `references[]`, `added`, `severity_hint`.
- Ships embedded in the client **and** fetched fresh from an Edge Function at scan start (client uses newer of the two; records DB version in the report).
- Seed sources: public cheat-client sites and repos (Meteor, Wurst, LiquidBounce, Impact families are open-source; commercial ones — Vape, Doomsday, Prestige, Entropy, Rise, Novoline — fingerprinted from public samples/log banners). Never distribute the cheats themselves; store only hashes + regexes.
- Update cadence: community-maintained, reviewed before publish. Report always states "signature DB vN, YYYY-MM-DD — newer cheats may not be recognised."

---

## 8. Artifact → privilege → phase matrix

| Artifact / collector | Priv | Phase | Detects |
|---|---|---|---|
| Process list + signatures + cmdline | user | 3 | T2, T6, running cheats/loaders |
| `.minecraft` mods/versions/config (hash) | user | 4 | T1 |
| `.minecraft` logs (`latest.log`, `*.log.gz`) | user | 4 | T1, T2, cheat banners |
| `launcher_profiles.json` JVM args | user | 4 | T2 |
| Known-cheat signature match | user | 4 | T1, T6 |
| Recycle Bin `$I`/`$R` | user | 3 | T7 (deleted jars/exes) |
| Prefetch `.pf` | user | 3 | evidence of execution, T7 |
| BAM / DAM | user | 3 | execution + user attribution |
| UserAssist / RecentDocs / RunMRU / MUICache | user | 3 | execution, opened paths |
| AppCompatCache (ShimCache) | user | 3 | execution |
| Scheduled Tasks / Run keys | user | 3 | loader persistence |
| System uptime / boot time | user | 3 | T7 (reboot before SS) |
| VM / debugger / tamper check | user | 2 | A10 |
| `$MFT` deleted records + timestomp | admin | 3 | T7 |
| USN Journal `$J` | admin | 3 | T7 (deleted `.pf`, deleted jars, secure-delete) |
| Amcache.hve | admin | 3 | execution + hash, T7 correlation |
| Event Log 4688 / PowerShell Operational | admin | 3 | execution, script-based loaders |
| PowerShell history file | admin | 3 | manual loader commands |
| Browser download history | user (opt-in) | 3 | cheat downloads |
| **Correlation engine** (cross-artifact) | best-effort | 3 | **T7 — headline** |

---

## 9. Open items to close during Phase 1

- [ ] Confirm Supabase project region + plan (Realtime + Edge Functions + Storage needed).
- [ ] Decide billing provider (Stripe) — schema leaves a `subscriptions` table stub, integration is Phase 7.
- [ ] Cert-pinning strategy for the client (pin Supabase edge domain SPKI; plan for rotation).
- [ ] Per-tenant evidence encryption key custody (libsodium sealed box; key stored in Supabase Vault).
- [ ] Retention purge: `pg_cron` job vs scheduled Edge Function.
