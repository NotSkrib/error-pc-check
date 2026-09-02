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
    <span
      className={`inline-block rounded border font-medium ${big ? "px-2 py-1 text-sm" : "px-1.5 py-0.5 text-xs"} ${SEVERITY_CLASS[severity]}`}
    >
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
            <tr key={k} className="border-t border-white/5">
              <td className="w-40 py-1 pr-3 align-top opacity-50">{k}</td>
              <td className="py-1 font-mono break-all">{String(evidence[k])}</td>
            </tr>
          ))}
        </tbody>
      </table>
    );
  }
  return (
    <pre className="mt-2 overflow-x-auto rounded bg-black/30 p-2 text-xs opacity-80">
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
  if (!session) return <p className="text-sm opacity-60">Loading…</p>;

  const consent = report?.consent as
    | { accepted?: boolean; at?: string; browser_history_optin?: boolean }
    | null
    | undefined;
  const env = report?.environment as Record<string, unknown> | null | undefined;
  const generatedAt = new Date().toLocaleString();
  const lastPct = [...events].reverse().find((e) => e.pct != null)?.pct ?? null;

  return (
    <div className="report-print space-y-6">
      <div className="report-watermark" aria-hidden>
        {tenantName} · {session.case_label} · {generatedAt}
      </div>

      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-lg font-semibold">{session.case_label}</h1>
          <p className="text-sm opacity-60">
            {tenantName} · suspect {session.suspect_label ?? "—"} · session {session.status} · key{" "}
            {session.key_prefix}…
          </p>
        </div>
        {report && (
          <button
            onClick={() => window.print()}
            className="no-print rounded border border-white/15 px-2 py-1 text-sm hover:bg-white/5"
          >
            Export PDF
          </button>
        )}
      </div>

      <div className="rounded border border-sev-medium/40 bg-sev-medium/10 p-3 text-sm">
        Findings are evidence, not a verdict. A human must review. SSAC does not recommend or apply
        punishment.
      </div>

      {!report && (
        <p className="text-sm opacity-60">
          No report yet — the suspect has not run the client with this key.
        </p>
      )}

      {report && (
        <>
          <section className="flex flex-wrap items-center gap-x-6 gap-y-3 rounded-lg border border-white/10 p-4">
            <div>
              <div className="text-xs opacity-50">Verdict</div>
              <Badge severity={verdict} big />
            </div>
            <div className="flex flex-wrap gap-1.5">
              {SEVERITY_ORDER.slice().reverse().map((s) =>
                counts[s] ? (
                  <span
                    key={s}
                    className={`rounded border px-1.5 py-0.5 text-xs ${SEVERITY_CLASS[s]}`}
                  >
                    {counts[s]} {SEVERITY_LABEL[s]}
                  </span>
                ) : null,
              )}
              {real.length === 0 && <span className="text-xs opacity-50">no findings</span>}
            </div>
            <div className="ml-auto flex gap-6 text-sm">
              <div>
                <div className="text-xs opacity-50">Status</div>
                {report.status}
                {report.status === "running" && lastPct != null ? ` · ${lastPct}%` : ""}
              </div>
              <div>
                <div className="text-xs opacity-50">Client</div>
                {report.client_version ?? "—"}
              </div>
              <div>
                <div className="text-xs opacity-50">Signatures</div>
                {report.signature_db_version ?? "—"}
              </div>
            </div>
          </section>

          {/* consent — the legal record */}
          <section className="rounded-lg border border-white/10 p-4 text-sm">
            <h2 className="mb-2 font-semibold">Consent</h2>
            {consent ? (
              <p>
                {consent.accepted ? (
                  <span className="text-sev-clean">Accepted</span>
                ) : (
                  <span className="text-sev-high">Declined</span>
                )}{" "}
                {consent.at && `at ${new Date(consent.at).toLocaleString()}`} · browser history opt-in:{" "}
                {consent.browser_history_optin ? "yes" : "no"}
              </p>
            ) : (
              <p className="opacity-50">not recorded</p>
            )}
          </section>

          {/* environment */}
          {env && (
            <section className="rounded-lg border border-white/10 p-4 text-sm">
              <h2 className="mb-2 font-semibold">Environment</h2>
              <table className="w-full text-xs">
                <tbody>
                  {Object.entries(env).map(([k, v]) => {
                    const warn =
                      (k === "is_vm" && v === true) ||
                      (k === "debugger_present" && v === true) ||
                      (k === "client_hash_ok" && v === false);
                    return (
                      <tr key={k} className="border-t border-white/5">
                        <td className="w-48 py-1 pr-3 opacity-50">{k}</td>
                        <td className={`py-1 font-mono ${warn ? "text-sev-high" : ""}`}>
                          {String(v)}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </section>
          )}

          {/* findings grouped by module */}
          <section>
            <h2 className="mb-2 font-semibold">Findings ({real.length})</h2>
            <div className="space-y-3">
              {groups.map((g) => {
                const isCollapsed = collapsed[g.module] ?? false;
                return (
                  <div key={g.module} className="rounded-lg border border-white/10">
                    <button
                      className="flex w-full items-center gap-2 px-3 py-2 text-left"
                      onClick={() =>
                        setCollapsed((c) => ({ ...c, [g.module]: !isCollapsed }))
                      }
                    >
                      <Badge severity={g.worst} />
                      <span className="font-medium">{moduleLabel(g.module)}</span>
                      <span className="text-xs opacity-40">{g.findings.length}</span>
                      <span className="no-print ml-auto text-xs opacity-40">
                        {isCollapsed ? "▸" : "▾"}
                      </span>
                    </button>
                    {!isCollapsed && (
                      <div className="space-y-2 border-t border-white/5 p-3">
                        {g.findings.map((f) => (
                          <div key={f.id} className="rounded border border-white/10 p-2">
                            <div className="flex items-center gap-2">
                              <Badge severity={f.severity} />
                              <span className="text-sm font-medium">{f.title}</span>
                            </div>
                            {f.description && (
                              <p className="mt-1 text-sm opacity-80">{f.description}</p>
                            )}
                            {f.occurred_at && (
                              <p className="mt-1 text-xs opacity-50">
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
              {real.length === 0 && <p className="text-sm opacity-50">No findings recorded.</p>}
            </div>
          </section>

          {/* coverage gaps */}
          {gaps.length > 0 && (
            <section className="rounded-lg border border-white/10 p-4">
              <h2 className="mb-2 font-semibold">Coverage gaps ({gaps.length})</h2>
              <p className="mb-2 text-xs opacity-50">
                Modules that could not run — usually because the client was not run as administrator,
                or the artifact was absent. Not detections.
              </p>
              <ul className="space-y-1 text-sm">
                {gaps.map((f) => (
                  <li key={f.id} className="opacity-80">
                    <span className="opacity-50">{moduleLabel(f.module)}:</span> {f.title}
                  </li>
                ))}
              </ul>
            </section>
          )}

          {/* scan log */}
          <section className="no-print">
            <h2 className="mb-2 font-semibold">Scan log</h2>
            <div className="max-h-64 overflow-y-auto rounded-lg border border-white/10 p-3 font-mono text-xs">
              {events.map((e) => (
                <div key={e.id} className="opacity-80">
                  <span className="opacity-40">
                    {new Date(e.created_at).toLocaleTimeString()}{" "}
                  </span>
                  [{e.kind}] {e.module ? `${e.module}: ` : ""}
                  {e.message}
                  {e.pct != null ? ` (${e.pct}%)` : ""}
                </div>
              ))}
              {events.length === 0 && <span className="opacity-40">no events</span>}
            </div>
          </section>
        </>
      )}
    </div>
  );
}
