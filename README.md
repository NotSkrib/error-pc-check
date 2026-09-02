# SSAC — Screenshare Anti-Cheat

A **consensual remote forensic screenshare tool** for Minecraft (Java, Windows) cheat detection.

Three parts:

| Component | Path | Stack | Status |
|---|---|---|---|
| Web panel | `panel/` | React + Vite + TS + Tailwind | Phase 1 |
| Backend | `supabase/` | Supabase (Postgres + Auth + RLS + Realtime) | Phase 1 |
| Client agent | `client/` | C# / .NET 8, single-file signed `.exe` | Phase 2 (needs .NET SDK) |

## Workflow

1. A staff member logs into the panel and generates a **one-time key** for a suspect (short TTL, single use, scoped to one report).
2. The suspect downloads the client agent and runs it with the key.
3. The client shows a **consent screen**, scans for Minecraft cheat artifacts + anti-forensic tampering, streams live progress, and uploads evidence to the backend over TLS.
4. The staff member sees a live view and a final **report with severity-ranked findings** — human review required, no automated punishment.

## Scope (v1)

- **OS:** Windows only
- **Game:** Minecraft Java Edition only
- **Build line:** MVP = Phases 0–4 + 6 (out-of-instance forensics, Minecraft file/signature checks, reporting). Deep in-instance JVM/native scanning (Phase 5) is v2.
- **Product model:** multi-tenant SaaS (per-server accounts, billing hooks, watermarked reports).

## Ethical guardrails (non-negotiable)

- Explicit consent screen, consent logged into the report.
- No install, no persistence, no autostart, no stealth mode. Self-deletes temp files on exit.
- Scans program-execution forensic artifacts and Minecraft processes only — not documents, media, messages, or browsing content. Browser download history is opt-in, off by default.
- Data minimisation: hashes + short snippets + artifact metadata, never whole files. Auto-purge after retention window.
- Client binary is code-signed with published SHA-256.

See [`docs/phase-0-design.md`](docs/phase-0-design.md) for the threat model, severity rubric, and consent/ToS copy.

## Development

```bash
# panel
cd panel && npm install && npm run dev

# backend (requires Supabase CLI + Docker)
cd supabase && supabase start
```
