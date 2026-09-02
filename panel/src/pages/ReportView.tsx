import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { supabase } from "../lib/supabase";
import {
  SEVERITY_CLASS,
  SEVERITY_LABEL,
  type Finding,
  type Report,
  type ReportEvent,
  type SessionRow,
} from "../lib/types";

function Badge({ severity }: { severity: Finding["severity"] }) {
  return (
    <span
      className={`inline-block rounded border px-1.5 py-0.5 text-xs font-medium ${SEVERITY_CLASS[severity]}`}
    >
      {SEVERITY_LABEL[severity]}
    </span>
  );
}

export default function ReportView() {
  const { sessionId } = useParams<{ sessionId: string }>();
  const [session, setSession] = useState<SessionRow | null>(null);
  const [report, setReport] = useState<Report | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [events, setEvents] = useState<ReportEvent[]>([]);
  const [notFound, setNotFound] = useState(false);

  async function load() {
    if (!sessionId) return;
    const { data: s } = await supabase
      .from("sessions")
      .select("id,tenant_id,case_label,suspect_label,key_prefix,status,created_by,expires_at,consumed_at,created_at")
      .eq("id", sessionId)
      .maybeSingle();
    if (!s) {
      setNotFound(true);
      return;
    }
    setSession(s);
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

  // live updates while a scan is running
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

  if (notFound) return <p className="text-sm opacity-60">Session not found.</p>;
  if (!session) return <p className="text-sm opacity-60">Loading…</p>;

  const lastPct = [...events].reverse().find((e) => e.pct != null)?.pct ?? null;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-lg font-semibold">{session.case_label}</h1>
        <p className="text-sm opacity-60">
          Suspect: {session.suspect_label ?? "—"} · session {session.status} · key{" "}
          {session.key_prefix}…
        </p>
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
          <section className="flex flex-wrap items-center gap-4 rounded-lg border border-white/10 p-4">
            <div>
              <div className="text-xs opacity-50">Verdict</div>
              <Badge severity={report.verdict_severity} />
            </div>
            <div>
              <div className="text-xs opacity-50">Status</div>
              <div className="text-sm">{report.status}</div>
            </div>
            <div>
              <div className="text-xs opacity-50">Client</div>
              <div className="text-sm">{report.client_version ?? "—"}</div>
            </div>
            <div>
              <div className="text-xs opacity-50">Signatures</div>
              <div className="text-sm">{report.signature_db_version ?? "—"}</div>
            </div>
            {report.status === "running" && lastPct != null && (
              <div className="min-w-[160px] flex-1">
                <div className="text-xs opacity-50">Progress</div>
                <div className="mt-1 h-2 w-full overflow-hidden rounded bg-white/10">
                  <div className="h-full bg-sev-info" style={{ width: `${lastPct}%` }} />
                </div>
              </div>
            )}
          </section>

          {report.environment && (
            <section className="rounded-lg border border-white/10 p-4 text-sm">
              <h2 className="mb-2 font-semibold">Environment</h2>
              <pre className="overflow-x-auto whitespace-pre-wrap text-xs opacity-80">
                {JSON.stringify(report.environment, null, 2)}
              </pre>
            </section>
          )}

          <section>
            <h2 className="mb-2 font-semibold">Findings ({findings.length})</h2>
            <div className="space-y-2">
              {findings.map((f) => (
                <div key={f.id} className="rounded-lg border border-white/10 p-3">
                  <div className="flex items-center gap-2">
                    <Badge severity={f.severity} />
                    <span className="font-medium">{f.title}</span>
                    <span className="ml-auto text-xs opacity-40">{f.module}</span>
                  </div>
                  {f.description && (
                    <p className="mt-1 text-sm opacity-80">{f.description}</p>
                  )}
                  {f.occurred_at && (
                    <p className="mt-1 text-xs opacity-50">
                      occurred {new Date(f.occurred_at).toLocaleString()}
                    </p>
                  )}
                  {Object.keys(f.evidence ?? {}).length > 0 && (
                    <pre className="mt-2 overflow-x-auto rounded bg-black/30 p-2 text-xs opacity-80">
                      {JSON.stringify(f.evidence, null, 2)}
                    </pre>
                  )}
                </div>
              ))}
              {findings.length === 0 && (
                <p className="text-sm opacity-50">No findings recorded.</p>
              )}
            </div>
          </section>

          <section>
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
