import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { supabase } from "../lib/supabase";
import { SEVERITY_CLASS, SEVERITY_LABEL, type Severity, type SessionRow, type Tenant } from "../lib/types";

interface ReportRow {
  session_id: string;
  status: string;
  verdict_severity: Severity;
}


/** The link staff hand out. It lives on a separate, bare host (the `error-pc-check`
 *  Vercel project) whose `/` is a neutral page — the recipient never sees the
 *  staff panel. `/d/:key` there proxies to the download Edge Function.
 *  Override with VITE_DOWNLOAD_BASE; on localhost dev, fall back to the
 *  function URL directly. */
const DOWNLOAD_BASE =
  (import.meta.env.VITE_DOWNLOAD_BASE as string | undefined) ?? "https://error-pc-check.vercel.app";

function downloadUrl(key: string) {
  const origin = typeof window !== "undefined" ? window.location.origin : "";
  if (origin.includes("localhost") || origin.includes("127.0.0.1")) {
    const base = import.meta.env.VITE_SUPABASE_URL as string;
    return `${base}/functions/v1/download?key=${encodeURIComponent(key)}`;
  }
  // /r/<key> is a small page that auto-starts the download and shows the
  // recipient the "More info -> Run anyway" step for the SmartScreen prompt.
  return `${DOWNLOAD_BASE}/r/${encodeURIComponent(key)}`;
}

export default function Dashboard() {
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [tenantId, setTenantId] = useState<string | null>(null);
  const [sessions, setSessions] = useState<SessionRow[]>([]);
  const [reports, setReports] = useState<Record<string, ReportRow>>({});
  const [loading, setLoading] = useState(true);
  const [caseLabel, setCaseLabel] = useState("");
  const [suspect, setSuspect] = useState("");
  const [issued, setIssued] = useState<{ key: string; expires_at: string } | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [isAdmin, setIsAdmin] = useState(false);

  const tenant = useMemo(() => tenants.find((t) => t.id === tenantId) ?? null, [tenants, tenantId]);

  async function loadRole(tid: string) {
    const { data: u } = await supabase.auth.getUser();
    if (!u.user) return;
    const { data } = await supabase
      .from("memberships")
      .select("role")
      .eq("tenant_id", tid)
      .eq("user_id", u.user.id)
      .maybeSingle();
    setIsAdmin(data?.role === "owner" || data?.role === "admin");
  }

  async function deleteSession(id: string) {
    if (!confirm("Delete this session and its report? This can't be undone.")) return;
    const { error } = await supabase.rpc("delete_session", { p_session: id });
    if (error) return setErr(error.message);
    if (tenantId) loadSessions(tenantId);
  }

  async function clearFinished() {
    if (!tenantId) return;
    if (!confirm("Delete every completed / expired / revoked session for this server?")) return;
    const { data, error } = await supabase.rpc("purge_finished_sessions", { p_tenant: tenantId });
    if (error) return setErr(error.message);
    setErr(null);
    alert(`Deleted ${data} session(s).`);
    loadSessions(tenantId);
  }

  async function loadTenants(triedGuestJoin = false) {
    const { data, error } = await supabase
      .from("tenants")
      .select("id,name,slug,retention_days,plan,created_at")
      .order("created_at");
    if (error) setErr(error.message);

    // A guest whose anonymous session resumed without a membership: self-heal.
    if ((data?.length ?? 0) === 0 && !triedGuestJoin) {
      const { data: u } = await supabase.auth.getUser();
      if (u.user?.is_anonymous) {
        await supabase.rpc("join_as_guest");
        return loadTenants(true);
      }
    }

    setTenants(data ?? []);
    setTenantId((prev) => prev ?? data?.[0]?.id ?? null);
    setLoading(false);
  }

  async function loadSessions(tid: string) {
    const { data } = await supabase
      .from("sessions")
      .select("id,tenant_id,case_label,suspect_label,key_prefix,status,created_by,created_by_label,expires_at,consumed_at,created_at")
      .eq("tenant_id", tid)
      .order("created_at", { ascending: false })
      .limit(50);
    setSessions(data ?? []);
    const ids = (data ?? []).map((s) => s.id);
    if (ids.length) {
      const { data: rs } = await supabase
        .from("reports")
        .select("session_id,status,verdict_severity")
        .in("session_id", ids);
      setReports(Object.fromEntries((rs ?? []).map((r) => [r.session_id, r as ReportRow])));
    } else {
      setReports({});
    }
  }

  useEffect(() => {
    loadTenants();
  }, []);
  useEffect(() => {
    if (tenantId) {
      loadSessions(tenantId);
      loadRole(tenantId);
    }
  }, [tenantId]);

  async function generateKey(e: React.FormEvent) {
    e.preventDefault();
    setErr(null);
    setIssued(null);
    if (!tenantId) return;
    const { data, error } = await supabase.rpc("create_session", {
      p_tenant: tenantId,
      p_case_label: caseLabel.trim(),
      p_suspect_label: suspect.trim() || null,
    });
    if (error) return setErr(error.message);
    const row = Array.isArray(data) ? data[0] : data;
    setIssued({ key: row.key, expires_at: row.expires_at });
    setCaseLabel("");
    setSuspect("");
    loadSessions(tenantId);
  }

  if (loading)
    return <div className="py-20 text-center text-sm text-fg-dim">Loading…</div>;

  if (tenants.length === 0)
    return (
      <div className="card mx-auto max-w-md p-6">
        <h2 className="text-base font-semibold">No access yet</h2>
        <p className="mt-1.5 text-sm text-fg-mut">
          This account isn't attached to Error SMP. Ask an admin to add you, or sign out and use{" "}
          <span className="text-fg">Continue as guest</span>.
        </p>
        {err && <p className="mt-3 text-sm text-brand">{err}</p>}
      </div>
    );

  const dl = issued ? downloadUrl(issued.key) : "";

  return (
    <div className="space-y-6">
      {/* context bar */}
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        {tenants.length > 1 ? (
          <select
            className="input w-auto py-1.5"
            value={tenantId ?? ""}
            onChange={(e) => setTenantId(e.target.value)}
          >
            {tenants.map((t) => (
              <option key={t.id} value={t.id} className="bg-ink-1">
                {t.name}
              </option>
            ))}
          </select>
        ) : (
          <h1 className="text-lg font-semibold tracking-tight">{tenant?.name}</h1>
        )}
        {tenant && (
          <div className="flex gap-1.5 text-[11px] text-fg-dim">
            <span className="chip border-ink-line">links expire in 2h</span>
            <span className="chip border-ink-line">reports kept {tenant.retention_days}d</span>
          </div>
        )}
      </div>

      {/* new key */}
      <section className="card overflow-hidden">
        <div className="border-b border-ink-line px-5 py-3">
          <h2 className="text-sm font-semibold">New screenshare</h2>
        </div>
        <div className="p-5">
          <form onSubmit={generateKey} className="flex flex-wrap items-end gap-3">
            <div className="min-w-[200px] flex-1">
              <label className="label">Case</label>
              <input
                className="input mt-1"
                placeholder="#cheat-report-412"
                value={caseLabel}
                onChange={(e) => setCaseLabel(e.target.value)}
                required
              />
            </div>
            <div className="min-w-[180px] flex-1">
              <label className="label">Suspect · optional</label>
              <input
                className="input mt-1"
                placeholder="MC username"
                value={suspect}
                onChange={(e) => setSuspect(e.target.value)}
              />
            </div>
            <button className="btn btn-primary h-[38px] px-4">Generate key</button>
          </form>
          {err && <p className="mt-3 text-sm text-brand">{err}</p>}

          {issued && (
            <div className="mt-5 rounded-xl border border-brand/25 bg-brand/[0.06] p-4 shadow-glow">
              <p className="text-sm text-fg-mut">
                Send this link to the person. It downloads <span className="text-fg">Error_PC_Check.exe</span>{" "}
                — they just run it, the key rides along with the download. Works once · expires{" "}
                <span className="text-fg">{new Date(issued.expires_at).toLocaleTimeString()}</span>.
              </p>

              <div className="mt-3">
                <label className="label">Download link</label>
                <div className="mt-1 flex gap-2">
                  <input
                    readOnly
                    className="input flex-1 font-mono text-xs"
                    value={dl}
                    onFocus={(e) => e.currentTarget.select()}
                  />
                  <button
                    type="button"
                    className="btn px-3"
                    onClick={() => navigator.clipboard?.writeText(dl)}
                  >
                    Copy
                  </button>
                  <a href={dl} className="btn px-3">
                    Test
                  </a>
                </div>
              </div>

              <div className="mt-3 rounded-lg border border-ink-line bg-ink-0/60 p-3 text-xs text-fg-mut">
                <span className="font-medium text-fg">Windows shows a blue “unrecognized app” box</span>{" "}
                — normal for a new tool. Click <em>More info → Run anyway</em>. Self-contained
                (~140&nbsp;MB), nothing installed, closes itself when done.
              </div>

              <details className="mt-2 text-xs text-fg-mut">
                <summary className="cursor-pointer select-none">Raw key</summary>
                <code className="mt-1 block break-all rounded-lg bg-ink-0/60 p-2 font-mono text-fg">
                  {issued.key}
                </code>
              </details>
            </div>
          )}
        </div>
      </section>

      {/* sessions */}
      <section className="card overflow-hidden">
        <div className="flex items-center justify-between border-b border-ink-line px-5 py-3">
          <h2 className="text-sm font-semibold">
            Sessions <span className="ml-1 text-fg-dim">{sessions.length}</span>
          </h2>
          {isAdmin && sessions.length > 0 && (
            <button onClick={clearFinished} className="btn btn-ghost px-2.5 py-1 text-xs">
              Clear finished
            </button>
          )}
        </div>

        {sessions.length === 0 ? (
          <div className="px-5 py-14 text-center text-sm text-fg-dim">
            No sessions yet — generate a key above.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-ink-line text-left text-[11px] uppercase tracking-[0.12em] text-fg-dim">
                  <th className="px-5 py-2.5 font-medium">Case</th>
                  <th className="px-3 py-2.5 font-medium">Suspect</th>
                  <th className="px-3 py-2.5 font-medium">By</th>
                  <th className="px-3 py-2.5 font-medium">Key</th>
                  <th className="px-3 py-2.5 font-medium">Status</th>
                  <th className="px-3 py-2.5 font-medium">Verdict</th>
                  <th className="px-3 py-2.5 font-medium">Created</th>
                  <th className="px-5 py-2.5" />
                </tr>
              </thead>
              <tbody>
                {sessions.map((s) => {
                  const r = reports[s.id];
                  return (
                    <tr
                      key={s.id}
                      className="group border-b border-ink-line/60 transition-colors last:border-0 hover:bg-white/[0.02]"
                    >
                      <td className="px-5 py-3 font-medium">{s.case_label}</td>
                      <td className="px-3 py-3 text-fg-mut">{s.suspect_label ?? "—"}</td>
                      <td className="px-3 py-3 text-xs text-fg-mut">{s.created_by_label ?? "—"}</td>
                      <td className="px-3 py-3 font-mono text-xs text-fg-dim">{s.key_prefix}…</td>
                      <td className="px-3 py-3">
                        <span className="inline-flex items-center gap-1.5 text-xs text-fg-mut">
                          <span
                            className={`h-1.5 w-1.5 rounded-full ${
                              s.status === "completed"
                                ? "bg-sev-clean"
                                : s.status === "pending" || s.status === "consumed"
                                  ? "bg-sev-info"
                                  : "bg-fg-dim"
                            }`}
                          />
                          {s.status}
                        </span>
                      </td>
                      <td className="px-3 py-3">
                        {r ? (
                          r.status === "running" ? (
                            <span className="text-xs text-fg-dim">running…</span>
                          ) : (
                            <span className={`chip ${SEVERITY_CLASS[r.verdict_severity]}`}>
                              {SEVERITY_LABEL[r.verdict_severity]}
                            </span>
                          )
                        ) : (
                          <span className="text-xs text-fg-dim">—</span>
                        )}
                      </td>
                      <td className="px-3 py-3 text-xs text-fg-dim">
                        {new Date(s.created_at).toLocaleString([], {
                          month: "short",
                          day: "numeric",
                          hour: "2-digit",
                          minute: "2-digit",
                        })}
                      </td>
                      <td className="px-5 py-3 text-right whitespace-nowrap">
                        <Link
                          className="text-xs font-medium text-fg-mut hover:text-fg"
                          to={`/reports/${s.id}`}
                        >
                          View
                        </Link>
                        {isAdmin && (
                          <button
                            onClick={() => deleteSession(s.id)}
                            className="ml-3 text-xs text-fg-dim opacity-0 transition hover:text-brand group-hover:opacity-100"
                          >
                            Delete
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
