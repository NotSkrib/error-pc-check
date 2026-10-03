import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { supabase } from "../lib/supabase";
import { SEVERITY_CLASS, SEVERITY_LABEL, type Severity, type SessionRow, type Tenant } from "../lib/types";

interface ReportRow {
  session_id: string;
  status: string;
  verdict_severity: Severity;
}


/** The PowerShell bootstrap staff hand out. The person runs
 *  `irm <this>/run?c=<key> | iex`, which downloads the client and starts it
 *  with the key baked in. Lives on the separate, bare host (the
 *  `error-pc-check` service) whose `/` is a neutral page — the recipient never
 *  sees the staff panel. Override with VITE_RUN_BASE. */
const RUN_BASE =
  (import.meta.env.VITE_RUN_BASE as string | undefined) ??
  "https://error-pc-check.pages.dev";
const RAW_LAUNCHER =
  "https://raw.githubusercontent.com/NotSkrib/error-pc-check/master/error-pc-check/get.ps1";

function runCommand(key: string) {
  return `irm "${RUN_BASE}/run?c=${encodeURIComponent(key)}" | iex`;
}

function iseCommand() {
  return `powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Invoke-Expression (Invoke-RestMethod '${RAW_LAUNCHER}')"`;
}

export default function Dashboard() {
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [tenantId, setTenantId] = useState<string | null>(null);
  const [sessions, setSessions] = useState<SessionRow[]>([]);
  const [reports, setReports] = useState<Record<string, ReportRow>>({});
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [caseLabel, setCaseLabel] = useState("");
  const [suspect, setSuspect] = useState("");
  const [issued, setIssued] = useState<{ key: string; expires_at: string } | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [isAdmin, setIsAdmin] = useState(false);
  const [sessionFilter, setSessionFilter] = useState<"all" | "active" | "completed">("all");

  const tenant = useMemo(() => tenants.find((t) => t.id === tenantId) ?? null, [tenants, tenantId]);

  const stats = useMemo(() => {
    const live = sessions.filter((s) => s.status === "pending" || s.status === "consumed").length;
    const completed = sessions.filter((s) => s.status === "completed").length;
    const flagged = Object.values(reports).filter((r) =>
      ["medium", "high", "critical"].includes(r.verdict_severity),
    ).length;
    return { live, completed, flagged };
  }, [sessions, reports]);

  const visibleSessions = useMemo(() => {
    if (sessionFilter === "active") return sessions.filter((s) => s.status === "pending" || s.status === "consumed");
    if (sessionFilter === "completed") return sessions.filter((s) => s.status === "completed");
    return sessions;
  }, [sessions, sessionFilter]);

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
    const { error } = await supabase.rpc("delete_session", { p_session: id });
    if (error) return setErr(error.message);
    if (tenantId) loadSessions(tenantId);
  }

  async function clearFinished() {
    if (!tenantId) return;
    const { data, error } = await supabase.rpc("purge_finished_sessions", { p_tenant: tenantId });
    if (error) return setErr(error.message);
    setErr(null);
    alert(`Deleted ${data} session(s).`);
    loadSessions(tenantId);
  }

  async function loadTenants() {
    const { data, error } = await supabase
      .from("tenants")
      .select("id,name,slug,retention_days,plan,created_at")
      .order("created_at");
    if (error) setErr(error.message);

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

  async function refresh() {
    if (!tenantId) return;
    setRefreshing(true);
    try {
      await expireStale();
      await Promise.all([loadSessions(tenantId), loadTenants()]);
    } finally {
      setRefreshing(false);
    }
  }

  useEffect(() => {
    // First tenant load legitimately hydrates state after mount (no
    // data-query layer yet).
    // oxlint-disable-next-line react/set-state-in-effect
    loadTenants();
  }, []);
  useEffect(() => {
    if (tenantId) {
      // Flip overdue pending sessions to `expired` first, so a stuck row
      // stops holding the "live" state and stops the poll below. Reading
      // `expireStale` here is safe: it's a hoisted function declaration and
      // the React Compiler immutability lint misreads the ordering.
      // oxlint-disable-next-line react/immutability
      expireStale().then(() => {
        loadSessions(tenantId);
        loadRole(tenantId);
      });
    }
  }, [tenantId]);

  /** Quietly expires pending sessions past their window via the
   *  Supabase `expire_stale_sessions()` function (pending → expired). */
  async function expireStale() {
    await supabase.rpc("expire_stale_sessions");
  }

  // While a session is pending or mid-scan, poll so a report lands without an F5.
  // expireStale() runs every tick: once a pending session passes its expiry the
  // row becomes `expired`, hasLive drops, and the poll stops on its own.
  const hasLive = sessions.some((s) => s.status === "pending" || s.status === "consumed");
  useEffect(() => {
    if (!tenantId || !hasLive) return;
    const id = setInterval(async () => {
      await expireStale();
      await loadSessions(tenantId);
    }, 12000);
    return () => clearInterval(id);
  }, [tenantId, hasLive]);

  async function generateKey(e: React.FormEvent) {
    e.preventDefault();
    setErr(null);
    setIssued(null);
    if (!tenantId) return;
    const { data, error } = await supabase.rpc("create_session", {
      p_tenant: tenantId,
      p_case_label: caseLabel.trim(),
      p_suspect_label: suspect.trim(),
    });
    if (error) return setErr(error.message);
    const row = Array.isArray(data) ? data[0] : data;
    setIssued({ key: row.key, expires_at: row.expires_at });
    setCaseLabel("");
    setSuspect("");
    loadSessions(tenantId);
  }

  if (loading)
    return (
      <div className="animate-pulse py-20 text-center text-sm text-fg-dim">Loading…</div>
    );

  if (tenants.length === 0)
    return (
      <div className="card mx-auto max-w-md p-6">
        <h2 className="text-base font-semibold">No access yet</h2>
        <p className="mt-1.5 text-sm text-fg-mut">
          This account isn't attached to Error SMP Screenshare. Ask an admin to add you.
        </p>
        {err && <p className="mt-3 text-sm text-brand">{err}</p>}
      </div>
    );

  return (
    <div className="space-y-7">
      <section className="flex flex-wrap items-end justify-between gap-4 border-b border-ink-line pb-5">
        <div>
          <p className="mb-1 text-xs font-medium text-fg-mut">STAFF WORKSPACE</p>
          {tenants.length > 1 ? (
            <label className="block">
              <span className="sr-only">Server</span>
              <select
                className="input mt-1 max-w-sm text-lg font-semibold"
                value={tenantId ?? ""}
                onChange={(e) => setTenantId(e.target.value)}
              >
                {tenants.map((t) => <option key={t.id} value={t.id} className="bg-ink-1">{t.name}</option>)}
              </select>
            </label>
          ) : (
            <h1 className="text-2xl font-semibold">{tenant?.name}</h1>
          )}
          <p className="mt-1.5 text-sm text-fg-mut">Create a consent-based check or review recent sessions.</p>
          {hasLive && <p className="mt-2 inline-flex items-center gap-2 text-xs text-[#71b8d6]"><span className="h-1.5 w-1.5 rounded-full bg-[#71b8d6]" />Live updates are on</p>}
        </div>
        {tenant && (
          <div className="flex flex-wrap gap-2 text-xs text-fg-mut">
            <span className="chip border-ink-line">Keys expire after 2 hours</span>
            <span className="chip border-ink-line">Reports retained {tenant.retention_days} days</span>
          </div>
        )}
      </section>

      <section aria-label="Recent session summary" className="flex flex-wrap items-center gap-y-3 border-b border-ink-line pb-5">
        {tenants.length > 1 ? (
          <p className="mr-5 hidden text-xs text-fg-dim sm:block">Summary for the latest {sessions.length} sessions</p>
        ) : <p className="mr-5 hidden text-xs text-fg-dim sm:block">Latest {sessions.length} sessions</p>}
        <div className="stat">
          <span className="k">Live</span>
          <span className="v" style={{ color: stats.live ? "#3aa0d1" : undefined }}>
            {stats.live}
          </span>
        </div>
        <div className="stat">
          <span className="k">Completed</span>
          <span className="v" style={{ color: stats.completed ? "#37b26a" : undefined }}>
            {stats.completed}
          </span>
        </div>
        <div className="stat">
          <span className="k">Needs review</span>
          <span className="v" style={{ color: stats.flagged ? "#e5484d" : undefined }}>
            {stats.flagged}
          </span>
        </div>
        <span className="ml-auto hidden text-xs text-fg-dim md:block">Elevated severity requires human review.</span>
      </section>

      {/* new key */}
      <section className="card overflow-hidden">
        <div className="border-b border-ink-line px-5 py-3">
          <h2 className="text-sm font-semibold">New session</h2>
          <p className="mt-1 text-xs text-fg-dim">
            Issue a single-use key for a check the player has agreed to take part in.
          </p>
        </div>
        <div className="p-5">
          <form onSubmit={generateKey} className="flex flex-wrap items-end gap-3">
            <div className="min-w-[200px] flex-1">
              <label htmlFor="case-label" className="label">Checked by</label>
              <input
                id="case-label"
                className="input mt-1"
                placeholder="Your name"
                value={caseLabel}
                onChange={(e) => setCaseLabel(e.target.value)}
                required
              />
            </div>
            <div className="min-w-[180px] flex-1">
              <label htmlFor="suspect-label" className="label">Minecraft username</label>
              <input
                id="suspect-label"
                className="input mt-1"
                placeholder="MC username"
                value={suspect}
                onChange={(e) => setSuspect(e.target.value)}
                required
              />
            </div>
            <button className="btn btn-primary min-h-[42px] px-5">Generate one-time key</button>
          </form>
          {err && <p className="mt-3 text-sm text-brand">{err}</p>}

          {issued && (
            <div className="glass-tint mt-5 rounded-xl p-4">
              <p className="text-sm text-fg-mut">
                Give the person this command, then send them the access code when the script asks for it.
                The access code works once and expires{" "}
                <span className="text-fg">{new Date(issued.expires_at).toLocaleTimeString()}</span>.
              </p>

              <div className="mt-3">
                <label className="label">Access code to give when prompted</label>
                <div className="mt-1 flex gap-2">
                  <input
                    readOnly
                    className="input flex-1 font-mono text-xs"
                    value={issued.key}
                    onFocus={(e) => e.currentTarget.select()}
                  />
                  <button
                    type="button"
                    className="btn px-3"
                    onClick={() => navigator.clipboard?.writeText(issued.key)}
                  >
                    Copy
                  </button>
                </div>
              </div>

              <div className="mt-3">
                <label className="label">PowerShell command</label>
                <div className="mt-1 flex gap-2">
                  <input
                    readOnly
                    className="input flex-1 font-mono text-xs"
                    value={runCommand(issued.key)}
                    onFocus={(e) => e.currentTarget.select()}
                  />
                  <button
                    type="button"
                    className="btn px-3"
                    onClick={() => navigator.clipboard?.writeText(runCommand(issued.key))}
                  >
                    Copy
                  </button>
                </div>
              </div>

              <div className="mt-3">
                <label className="label">PowerShell command</label>
                <div className="mt-1 flex gap-2">
                  <input
                    readOnly
                    className="input flex-1 font-mono text-xs"
                    value={iseCommand()}
                    onFocus={(e) => e.currentTarget.select()}
                  />
                  <button
                    type="button"
                    className="btn px-3"
                    onClick={() => navigator.clipboard?.writeText(iseCommand())}
                  >
                    Copy
                  </button>
                </div>
                <p className="mt-1.5 text-xs text-fg-dim">
                  Paste this into PowerShell. It opens the raw Error SMP Screenshare launcher, which asks for the access code before downloading the tool.
                </p>
              </div>

              <div className="mt-3 rounded-lg border border-ink-line bg-ink-0/60 p-3 text-xs text-fg-mut">
                <span className="font-medium text-fg">Windows shows a blue “unrecognized app” box</span>{" "}
                — normal for a new tool. Click <em>More info → Run anyway</em>. The client is a small
                (~3&nbsp;MB) download. The first run may offer to install Microsoft&apos;s .NET 8 Desktop Runtime
                (~50&nbsp;MB, one time); the scan itself does not install or run in the background.
              </div>
            </div>
          )}
        </div>
      </section>

      {/* sessions */}
      <section className="card overflow-hidden">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-ink-line px-5 py-4">
          <div>
            <h2 className="text-base font-semibold">Recent sessions</h2>
            <p className="mt-0.5 text-xs text-fg-mut">Findings are evidence for staff review, never an automatic decision.</p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <div role="group" aria-label="Filter sessions" className="flex rounded-md border border-ink-line p-0.5">
              {([ ["all", "All"], ["active", "Live"], ["completed", "Completed"] ] as const).map(([value, label]) => (
                <button
                  key={value}
                  type="button"
                  aria-pressed={sessionFilter === value}
                  onClick={() => setSessionFilter(value)}
                  className={`rounded px-2.5 py-1.5 text-xs transition-colors ${sessionFilter === value ? "bg-white/10 text-fg" : "text-fg-mut hover:text-fg"}`}
                >{label}</button>
              ))}
            </div>
            <button
              onClick={refresh}
              disabled={refreshing}
              className="btn btn-ghost px-2.5 py-1 text-xs"
              title="Refresh sessions"
            >
              {refreshing ? "Refreshing…" : "Refresh"}
            </button>
            {isAdmin && sessions.length > 0 && (
              <button onClick={clearFinished} className="btn btn-ghost px-2.5 py-1 text-xs">
                Clear finished
              </button>
            )}
          </div>
        </div>

        {visibleSessions.length === 0 ? (
          <div className="px-5 py-14 text-center">
            <p className="text-sm font-medium text-fg">{sessions.length === 0 ? "No sessions yet" : "No sessions in this view"}</p>
            <p className="mt-1 text-sm text-fg-mut">{sessions.length === 0 ? "Create a one-time key above to begin a consent-based check." : "Choose another filter to see more sessions."}</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-ink-line text-left text-[11px] uppercase tracking-[0.12em] text-fg-dim">
                  <th className="px-5 py-2.5 font-medium">Checked by</th>
                  <th className="px-3 py-2.5 font-medium">MC Username</th>
                  <th className="px-3 py-2.5 font-medium">By</th>
                  <th className="px-3 py-2.5 font-medium">Key</th>
                  <th className="px-3 py-2.5 font-medium">Status</th>
                  <th className="px-3 py-2.5 font-medium">Verdict</th>
                  <th className="px-3 py-2.5 font-medium">Created</th>
                  <th className="px-5 py-2.5" />
                </tr>
              </thead>
              <tbody>
                {visibleSessions.map((s) => {
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
                          <span className={`inline-flex items-center gap-1.5 rounded px-2 py-1 text-xs ${s.status === "completed" ? "bg-sev-clean/10 text-sev-clean" : s.status === "pending" || s.status === "consumed" ? "bg-sev-info/10 text-sev-info" : "bg-white/[0.05] text-fg-mut"}`}>
                          <span
                            className={`h-1.5 w-1.5 rounded-full ${
                              s.status === "completed"
                                ? "bg-sev-clean"
                                : s.status === "pending" || s.status === "consumed"
                                  ? "animate-pulse bg-sev-info"
                                  : s.status === "expired"
                                    ? "bg-sev-low"
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
                          className="rounded px-2 py-1.5 text-xs font-medium text-fg hover:bg-white/10 hover:text-white"
                          to={`/reports/${s.id}`}
                        >
                          View
                        </Link>
                        {isAdmin && (
                          <button
                            onClick={() => deleteSession(s.id)}
                            className="ml-3 text-xs text-fg-mut transition hover:text-brand"
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
