import { useEffect, useMemo, useState } from "react";
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

export default function ReportView() {
  const { sessionId } = useParams<{ sessionId: string }>();
  const [session, setSession] = useState<SessionRow | null>(null);
  const [tenantName, setTenantName] = useState<string>("");
  const [report, setReport] = useState<Report | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [events, setEvents] = useState<ReportEvent[]>([]);
  const [notFound, setNotFound] = useState(false);
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({});

  async function load() {
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
  }

  useEffect(() => {
    load();
  }, [sessionId]);

  useEffect(() => {
    if (!report || report.status !== "running") return;
    const ch = supabase
      .channel(`report-${report.id}`)
      .on(
        "postgres_changes",
        { event: "INSERT", schema: "public", table: "report_events", filter: `report_id=eq.${report.id}` },
        (p) => setEvents((prev) => [...prev, p.new as ReportEvent]),
      )
      .on(
        "postgres_changes",
        { event: "INSERT", schema: "public", table: "findings", filter: `report_id=eq.${report.id}` },
        (p) => setFindings((prev) => [...prev, p.new as Finding]),
      )
      .on(
        "postgres_changes",
        { event: "UPDATE", schema: "public", table: "reports", filter: `id=eq.${report.id}` },
        (p) => setReport(p.new as Report),
      )
      .subscribe();
    return () => {
      supabase.removeChannel(ch);
    };
  }, [report?.id, report?.status]);

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
  if (!session) return <div className="py-20 text-center text-sm text-fg-dim">Loading…</div>;

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
        Findings are <span className="text-fg">evidence, not a verdict</span>. A human must review.
        The tool does not recommend or apply punishment.
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
                <div className="label">Verdict</div>
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
                          <td className="w-44 py-1.5 pr-3 text-fg-dim">{k}</td>
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
                const isCollapsed = collapsed[g.module] ?? false;
                return (
                  <div key={g.module} className="card overflow-hidden">
                    <button
                      className="flex w-full items-center gap-2.5 px-4 py-2.5 text-left transition hover:bg-white/[0.02]"
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
                      <div className="space-y-2 border-t border-ink-line p-3">
                        {g.findings.map((f) => (
                          <div
                            key={f.id}
                            className="rounded-lg border border-ink-line bg-ink-1/50 p-3"
                          >
                            <div className="flex items-center gap-2">
                              <Badge severity={f.severity} />
                              <span className="text-sm font-medium">{f.title}</span>
                            </div>
                            {f.description && (
                              <p className="mt-1.5 text-sm text-fg-mut">{f.description}</p>
                            )}
                            {f.occurred_at && (
                              <p className="mt-1 text-xs text-fg-dim">
                                occurred {new Date(f.occurred_at).toLocaleString()}
                              </p>
                            )}
                            <EvidenceView evidence={f.evidence ?? {}} />
                          </div>
                        ))}
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
            <section className="card p-5">
              <h2 className="label mb-1.5">Coverage gaps · {gaps.length}</h2>
              <p className="mb-2.5 text-xs text-fg-dim">
                Modules that couldn't run — usually not run as admin, or the artifact was absent.
                Not detections.
              </p>
              <ul className="space-y-1 text-sm text-fg-mut">
                {gaps.map((f) => (
                  <li key={f.id}>
                    <span className="text-fg-dim">{moduleLabel(f.module)}:</span> {f.title}
                  </li>
                ))}
              </ul>
            </section>
          )}

          {/* scan log */}
          <section className="no-print">
            <h2 className="mb-2.5 text-sm font-semibold">Scan log</h2>
            <div className="max-h-64 overflow-y-auto rounded-xl border border-ink-line bg-ink-0/60 p-3 font-mono text-xs leading-relaxed text-fg-mut">
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
          </section>
        </>
      )}
    </div>
  );
}
