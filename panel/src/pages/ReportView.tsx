import { useCallback, useEffect, useMemo, useState } from "react";
import { useParams } from "react-router-dom";
import { supabase } from "../lib/supabase";
import {
  SEVERITY_CLASS,
  SEVERITY_LABEL,
  SEVERITY_ORDER,
  isCoverageGap,
  moduleLabel,
  severityRank,
  worstSeverity,
  type Finding,
  type Report,
  type ReportEvent,
  type Severity,
  type SessionRow,
} from "../lib/types";

function Badge({ severity, big }: { severity: Severity; big?: boolean }) {
  return (
    <span className={`chip ${big ? "px-3 py-1 text-sm" : ""} ${SEVERITY_CLASS[severity]}`}>
      {SEVERITY_LABEL[severity]}
    </span>
  );
}

function EvidenceView({ evidence }: { evidence: Record<string, unknown> }) {
  const keys = Object.keys(evidence ?? {});
  if (keys.length === 0) return null;
  const shallow = keys.every(
    (k) => evidence[k] === null || ["string", "number", "boolean"].includes(typeof evidence[k]),
  );
  if (shallow) {
    return (
      <table className="mt-2 w-full text-xs">
        <tbody>
          {keys.map((k) => (
            <tr key={k} className="border-t border-ink-line/60">
              <td className="w-40 py-1.5 pr-3 align-top text-fg-dim">{k}</td>
              <td className="py-1.5 font-mono break-all text-fg-mut">{String(evidence[k])}</td>
            </tr>
          ))}
        </tbody>
      </table>
    );
  }
  return (
    <pre className="mt-2 overflow-x-auto rounded-lg border border-ink-line bg-ink-0/60 p-2.5 text-xs text-fg-mut">
      {JSON.stringify(evidence, null, 2)}
    </pre>
  );
}

function appContext(evidence: Record<string, unknown>) {
  const values = Object.values(evidence ?? {}).filter((value): value is string => typeof value === "string");
  const path = values.find((value) => /[\\/]/.test(value));
  const normalized = path?.replaceAll("/", "\\").toLowerCase() ?? "";
  if (normalized.includes("modrinth")) {
    return "This path is inside Modrinth's app or game-data folders. Launchers commonly keep cached game files and dependencies there, so the location alone is not evidence of cheating. Check the exact filename and what the scanner observed.";
  }
  if (normalized.includes("\\medal\\")) {
    return "This path is inside Medal's app data. Recording and clipping apps create temporary/cache files; that can explain the location, but it does not identify this specific file. Check the filename and whether Minecraft actually loaded it.";
  }
  if (normalized.includes("\\temp\\") || normalized.includes("\\tmp\\")) {
    return "This file is in a temporary folder. Windows apps often create short-lived files there, so the folder alone does not identify it as harmful. Check the filename, publisher, and whether Minecraft loaded or ran it.";
  }
  return null;
}

function coverageHelp(f: Finding) {
  switch (f.module) {
    case "prefetch":
      return "Windows keeps a list of some apps it has opened. The scanner could not read that list, so this part of the history is missing. Running the check as administrator may help.";
    case "bam":
      return "Windows did not provide app-activity history for this account. This can happen on a new account or when Windows has no records available; it is not a detection.";
    case "amcache":
      return "This scanner does not yet read this Windows program-history database. No conclusion can be drawn from this check.";
    case "eventlog":
      return "The scanner could not read Windows security records. Administrator access and Windows process-logging settings may be required.";
    case "usn-journal":
      return "This Windows file-change history could not be checked. Administrator access is usually needed to see recent file deletions.";
    case "mft":
      return "Reading the detailed NTFS file index is not implemented yet. This check did not examine deleted-file records.";
    case "java-crash-log":
      return "No Java game crash record was found. This only means there was no matching crash log; it does not confirm or rule out other activity.";
    default:
      return f.description || "This check did not return usable information. It is not a detection.";
  }
}

const ENVIRONMENT_LABEL: Record<string, string> = {
  os_build: "Windows version",
  uptime_seconds: "Time since Windows started (seconds)",
  is_vm: "Virtual machine detected",
  debugger_present: "Debugger attached to scan app",
  client_hash_ok: "Scan app file check passed",
  client_sha256: "Scan app file fingerprint",
  parent_process: "App that started the scan",
  elevated: "Ran as administrator",
};

export default function ReportView() {
  const { sessionId } = useParams<{ sessionId: string }>();
  const [session, setSession] = useState<SessionRow | null>(null);
  const [tenantName, setTenantName] = useState<string>("");
  const [report, setReport] = useState<Report | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [events, setEvents] = useState<ReportEvent[]>([]);
  const [notFound, setNotFound] = useState(false);
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({});

  const load = useCallback(async () => {
    if (!sessionId) return;
    const { data: s } = await supabase
      .from("sessions")
      .select(
        "id,tenant_id,case_label,suspect_label,key_prefix,status,created_by,expires_at,consumed_at,created_at,tenants(name)",
      )
      .eq("id", sessionId)
      .maybeSingle();
    if (!s) {
      setNotFound(true);
      return;
    }
    setSession(s as unknown as SessionRow);
    setTenantName((s as { tenants?: { name?: string } }).tenants?.name ?? "");
    const { data: r } = await supabase
      .from("reports")
      .select("*")
      .eq("session_id", sessionId)
      .maybeSingle();
    setReport(r);
    if (r) {
      const [{ data: f }, { data: e }] = await Promise.all([
        supabase.from("findings").select("*").eq("report_id", r.id).order("sort_key"),
        supabase.from("report_events").select("*").eq("report_id", r.id).order("id"),
      ]);
      setFindings(f ?? []);
      setEvents(e ?? []);
    }
  }, [sessionId]);

  useEffect(() => {
    // Data fetch hydration after a route change (no data-query layer yet).
    // oxlint-disable-next-line react/set-state-in-effect
    load();
  }, [sessionId, load]);

  const reportId = report?.id;
  const reportStatus = report?.status;

  useEffect(() => {
    if (!reportId || reportStatus !== "running") return;
    const ch = supabase
      .channel(`report-${reportId}`)
      .on(
        "postgres_changes",
        { event: "INSERT", schema: "public", table: "report_events", filter: `report_id=eq.${reportId}` },
        (p) => setEvents((prev) => [...prev, p.new as ReportEvent]),
      )
      .on(
        "postgres_changes",
        { event: "INSERT", schema: "public", table: "findings", filter: `report_id=eq.${reportId}` },
        (p) => setFindings((prev) => [...prev, p.new as Finding]),
      )
      .on(
        "postgres_changes",
        { event: "UPDATE", schema: "public", table: "reports", filter: `id=eq.${reportId}` },
        (p) => setReport(p.new as Report),
      )
      .subscribe();
    return () => {
      supabase.removeChannel(ch);
    };
    // Deps are the primitives `reportId`/`reportStatus`, not the `report`
    // object: keying on `report` would tear down and recreate the channel on
    // every report UPDATE we receive (the very events we subscribe to). The
    // derived consts keep this subscription stable while staying exhaustive.
  }, [reportId, reportStatus]);

  const real = useMemo(() => findings.filter((f) => !isCoverageGap(f)), [findings]);
  const gaps = useMemo(() => findings.filter(isCoverageGap), [findings]);

  const counts = useMemo(() => {
    const c: Partial<Record<Severity, number>> = {};
    for (const f of real) c[f.severity] = (c[f.severity] ?? 0) + 1;
    return c;
  }, [real]);

  const groups = useMemo(() => {
    const m = new Map<string, Finding[]>();
    for (const f of real) (m.get(f.module) ?? m.set(f.module, []).get(f.module)!).push(f);
    return [...m.entries()]
      .map(([module, fs]) => ({
        module,
        findings: [...fs].sort((a, b) => severityRank(b.severity) - severityRank(a.severity)),
        worst: worstSeverity(fs.map((x) => x.severity)),
      }))
      .sort((a, b) => severityRank(b.worst) - severityRank(a.worst));
  }, [real]);

  const verdict = report?.verdict_severity ?? worstSeverity(real.map((f) => f.severity));

  if (notFound) return <p className="text-sm opacity-60">Session not found.</p>;
  if (!session) return <div className="animate-pulse py-20 text-center text-sm text-fg-dim">Loading…</div>;

  const consent = report?.consent as
    | { accepted?: boolean; at?: string; browser_history_optin?: boolean }
    | null
    | undefined;
  const env = report?.environment as Record<string, unknown> | null | undefined;
  const lastPct = [...events].reverse().find((e) => e.pct != null)?.pct ?? null;

  return (
    <div className="report-print space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">{session.case_label}</h1>
          <p className="mt-1 text-sm text-fg-mut">
            {tenantName} · suspect{" "}
            <span className="text-fg">{session.suspect_label ?? "—"}</span> · session{" "}
            {session.status} · key <span className="font-mono text-fg-dim">{session.key_prefix}…</span>
          </p>
        </div>
        {report && (
          <button onClick={() => window.print()} className="no-print btn px-3">
            Export PDF
          </button>
        )}
      </div>

      <div className="rounded-lg border border-sev-medium/30 bg-sev-medium/[0.08] px-4 py-2.5 text-sm text-fg-mut">
        Findings are <span className="text-fg">clues for a person to review</span>, not proof or an automatic decision.
        Severity means how closely staff should review a match; it does not determine what happened.
      </div>

      {!report && (
        <div className="card p-6 text-sm text-fg-mut">
          No report yet — the suspect hasn't run the client with this key.
        </div>
      )}

      {report && (
        <>
          {/* verdict header */}
          <section className="card p-5">
            <div className="flex flex-wrap items-center gap-x-6 gap-y-3">
              <div>
                <div className="label">Highest finding severity</div>
                <div className="mt-1">
                  <Badge severity={verdict} big />
                </div>
              </div>
              <div className="flex flex-wrap gap-1.5">
                {SEVERITY_ORDER.slice()
                  .reverse()
                  .map((s) =>
                    counts[s] ? (
                      <span key={s} className={`chip ${SEVERITY_CLASS[s]}`}>
                        {counts[s]} {SEVERITY_LABEL[s]}
                      </span>
                    ) : null,
                  )}
                {real.length === 0 && <span className="text-xs text-fg-dim">no findings</span>}
              </div>
              <div className="ml-auto flex gap-6 text-sm">
                <div>
                  <div className="label">Status</div>
                  <div className="mt-0.5">
                    {report.status}
                    {report.status === "running" && lastPct != null ? ` · ${lastPct}%` : ""}
                  </div>
                  {report.status === "running" && lastPct != null && (
                    <div className="mt-1.5 h-1 w-28 overflow-hidden rounded-full bg-white/10">
                      <div
                        className="h-full rounded-full bg-sev-info transition-all"
                        style={{ width: `${Math.min(100, Math.max(0, lastPct))}%` }}
                      />
                    </div>
                  )}
                </div>
                <div>
                  <div className="label">Client</div>
                  <div className="mt-0.5 font-mono text-xs">{report.client_version ?? "—"}</div>
                </div>
                <div>
                  <div className="label">Signatures</div>
                  <div className="mt-0.5 font-mono text-xs">{report.signature_db_version ?? "—"}</div>
                </div>
              </div>
            </div>
          </section>

          {/* consent + environment side by side */}
          <div className="grid gap-4 md:grid-cols-2">
            <section className="card p-5 text-sm">
              <h2 className="label mb-2">Consent</h2>
              {consent ? (
                <p className="text-fg-mut">
                  {consent.accepted ? (
                    <span className="font-medium text-sev-clean">Accepted</span>
                  ) : (
                    <span className="font-medium text-sev-high">Declined</span>
                  )}
                  {consent.at && ` · ${new Date(consent.at).toLocaleString()}`}
                  {" · "}browser downloads: {consent.browser_history_optin ? "yes" : "no"}
                </p>
              ) : (
                <p className="text-fg-dim">not recorded</p>
              )}
            </section>

            {env && (
              <section className="card p-5 text-sm">
                <h2 className="label mb-2">Environment</h2>
                <table className="w-full text-xs">
                  <tbody>
                    {Object.entries(env).map(([k, v]) => {
                      const warn =
                        (k === "is_vm" && v === true) ||
                        (k === "debugger_present" && v === true) ||
                        (k === "client_hash_ok" && v === false);
                      return (
                        <tr key={k} className="border-t border-ink-line/60">
                          <td className="w-56 py-1.5 pr-3 text-fg-dim">{ENVIRONMENT_LABEL[k] ?? k.replaceAll("_", " ")}</td>
                          <td className={`py-1.5 font-mono ${warn ? "text-sev-high" : "text-fg-mut"}`}>
                            {String(v)}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </section>
            )}
          </div>

          {/* findings grouped by module */}
          <section>
            <h2 className="mb-2.5 text-sm font-semibold">
              Findings <span className="text-fg-dim">{real.length}</span>
            </h2>
            <div className="space-y-2.5">
              {groups.map((g) => {
                const isCollapsed = collapsed[g.module] ?? true;
                return (
                  <div key={g.module} className="border-t border-ink-line">
                    <button
                      className="flex w-full items-center gap-2.5 py-3 text-left transition-colors hover:bg-white/[0.025]"
                      onClick={() => setCollapsed((c) => ({ ...c, [g.module]: !isCollapsed }))}
                    >
                      <Badge severity={g.worst} />
                      <span className="text-sm font-medium">{moduleLabel(g.module)}</span>
                      <span className="text-xs text-fg-dim">{g.findings.length}</span>
                      <span className="no-print ml-auto text-xs text-fg-dim">
                        {isCollapsed ? "▸" : "▾"}
                      </span>
                    </button>
                    {!isCollapsed && (
                      <div className="divide-y divide-ink-line">
                        {g.findings.map((f) => {
                          const context = appContext(f.evidence ?? {});
                          return (
                            <details key={f.id} className="group/finding py-2.5">
                              <summary className="flex cursor-pointer list-none items-center gap-2 rounded-md py-1 text-left marker:hidden focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--accent)] [&::-webkit-details-marker]:hidden">
                                <span aria-hidden="true" className="w-3 text-xs text-fg-dim group-open/finding:rotate-90">▸</span>
                                <Badge severity={f.severity} />
                                <span className="text-sm font-medium">{f.title}</span>
                              </summary>
                              <div className="ml-5 mt-2 border-l border-ink-line pl-4">
                                {context && (
                                  <div className="mb-3 rounded-md border border-sev-info/25 bg-sev-info/[0.06] p-3">
                                    <p className="text-xs font-semibold text-sev-info">Possible app or cache context</p>
                                    <p className="mt-1 text-sm text-fg-mut">{context}</p>
                                  </div>
                                )}
                                {f.description && (
                                  <div>
                                    <p className="text-xs font-medium text-fg">Why it was flagged</p>
                                    <p className="mt-1 text-sm leading-relaxed text-fg-mut">{f.description}</p>
                                  </div>
                                )}
                                {f.occurred_at && (
                                  <p className="mt-2 text-xs text-fg-dim">
                                    Observed {new Date(f.occurred_at).toLocaleString()}
                                  </p>
                                )}
                                <details className="mt-3 rounded-md border border-ink-line/70 bg-ink-0/20 px-3 py-2">
                                  <summary className="cursor-pointer text-xs font-medium text-fg-mut">Technical evidence</summary>
                                  <EvidenceView evidence={f.evidence ?? {}} />
                                </details>
                              </div>
                            </details>
                          );
                        })}
                      </div>
                    )}
                  </div>
                );
              })}
              {real.length === 0 && (
                <p className="card p-5 text-sm text-fg-dim">No findings recorded.</p>
              )}
            </div>
          </section>

          {/* coverage gaps */}
          {gaps.length > 0 && (
            <details className="card p-5">
              <summary className="cursor-pointer text-sm font-semibold">Checks not completed · {gaps.length}</summary>
              <p className="mb-3 mt-2 text-sm leading-relaxed text-fg-mut">
                These are missing parts of the scan, not flags against the player. Some need administrator access, some had no history to show, and some are not implemented yet.
              </p>
              <ul className="divide-y divide-ink-line/70">
                {gaps.map((f) => (
                  <li key={f.id} className="py-3 first:pt-0 last:pb-0">
                    <p className="text-sm font-medium text-fg">{moduleLabel(f.module)}</p>
                    <p className="mt-1 text-sm text-fg-mut">{coverageHelp(f)}</p>
                  </li>
                ))}
              </ul>
            </details>
          )}

          {/* scan log */}
          <details className="no-print">
            <summary className="mb-2.5 cursor-pointer text-sm font-semibold">Scan log</summary>
            <div className="max-h-64 overflow-y-auto rounded-md border border-ink-line bg-ink-0/60 p-3 font-mono text-xs leading-relaxed text-fg-mut">
              {events.map((e) => (
                <div key={e.id}>
                  <span className="text-fg-dim">
                    {new Date(e.created_at).toLocaleTimeString()}{" "}
                  </span>
                  [{e.kind}] {e.module ? `${e.module}: ` : ""}
                  {e.message}
                  {e.pct != null ? ` (${e.pct}%)` : ""}
                </div>
              ))}
              {events.length === 0 && <span className="text-fg-dim">no events</span>}
            </div>
          </details>
        </>
      )}
    </div>
  );
}
