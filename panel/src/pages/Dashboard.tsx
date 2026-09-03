import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { supabase } from "../lib/supabase";
import { SEVERITY_CLASS, SEVERITY_LABEL, type Severity, type SessionRow, type Tenant } from "../lib/types";

interface ReportRow {
  session_id: string;
  status: string;
  verdict_severity: Severity;
}

function slugify(s: string) {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 40);
}

/** Client download — the download function validates the key and streams the
 *  self-contained build, saved as ssac-screenshare-<key>.exe. */
function downloadUrl(key: string) {
  const base = import.meta.env.VITE_SUPABASE_URL as string;
  return `${base}/functions/v1/download?key=${encodeURIComponent(key)}`;
}

export default function Dashboard() {
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [tenantId, setTenantId] = useState<string | null>(null);
  const [sessions, setSessions] = useState<SessionRow[]>([]);
  const [reports, setReports] = useState<Record<string, ReportRow>>({});
  const [loading, setLoading] = useState(true);
  const [newTenant, setNewTenant] = useState("");
  const [caseLabel, setCaseLabel] = useState("");
  const [suspect, setSuspect] = useState("");
  const [issued, setIssued] = useState<{ key: string; expires_at: string } | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const tenant = useMemo(() => tenants.find((t) => t.id === tenantId) ?? null, [tenants, tenantId]);

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
      .select("id,tenant_id,case_label,suspect_label,key_prefix,status,created_by,expires_at,consumed_at,created_at")
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
    if (tenantId) loadSessions(tenantId);
  }, [tenantId]);

  async function createTenant(e: React.FormEvent) {
    e.preventDefault();
    setErr(null);
    const { data: u } = await supabase.auth.getUser();
    const { error } = await supabase.from("tenants").insert({
      name: newTenant.trim(),
      slug: slugify(newTenant),
      created_by: u.user!.id,
    });
    if (error) return setErr(error.message);
    setNewTenant("");
    loadTenants();
  }

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

  if (loading) return <p className="text-sm opacity-60">Loading…</p>;

  return (
    <div className="space-y-8">
      {tenants.length === 0 ? (
        <form onSubmit={createTenant} className="max-w-md space-y-3">
          <h2 className="font-semibold">Create your first server</h2>
          <p className="text-sm opacity-60">
            The name is shown to suspects on the consent screen (e.g. your Minecraft server brand).
          </p>
          <input
            className="w-full rounded border border-white/15 bg-transparent px-3 py-2 text-sm"
            placeholder="Server name"
            value={newTenant}
            onChange={(e) => setNewTenant(e.target.value)}
            required
          />
          <button className="rounded bg-white/90 px-3 py-2 text-sm font-medium text-black">
            Create
          </button>
          {err && <p className="text-sm text-sev-high">{err}</p>}
        </form>
      ) : (
        <>
          <div className="flex items-center gap-3">
            <label className="text-sm opacity-60">Server</label>
            <select
              className="rounded border border-white/15 bg-transparent px-2 py-1 text-sm"
              value={tenantId ?? ""}
              onChange={(e) => setTenantId(e.target.value)}
            >
              {tenants.map((t) => (
                <option key={t.id} value={t.id} className="bg-black">
                  {t.name}
                </option>
              ))}
            </select>
            {tenant && (
              <span className="text-xs opacity-40">
                retention {tenant.retention_days}d · plan {tenant.plan}
              </span>
            )}
          </div>

          <section className="rounded-lg border border-white/10 p-4">
            <h2 className="font-semibold">New screenshare key</h2>
            <form onSubmit={generateKey} className="mt-3 flex flex-wrap items-end gap-3">
              <div>
                <label className="block text-xs opacity-60">Case label</label>
                <input
                  className="rounded border border-white/15 bg-transparent px-3 py-2 text-sm"
                  placeholder="e.g. #cheat-report-412"
                  value={caseLabel}
                  onChange={(e) => setCaseLabel(e.target.value)}
                  required
                />
              </div>
              <div>
                <label className="block text-xs opacity-60">Suspect (optional)</label>
                <input
                  className="rounded border border-white/15 bg-transparent px-3 py-2 text-sm"
                  placeholder="MC username"
                  value={suspect}
                  onChange={(e) => setSuspect(e.target.value)}
                />
              </div>
              <button className="rounded bg-white/90 px-3 py-2 text-sm font-medium text-black">
                Generate
              </button>
            </form>
            {err && <p className="mt-2 text-sm text-sev-high">{err}</p>}
            {issued && (
              <div className="mt-3 space-y-3 rounded border border-sev-info/40 bg-sev-info/10 p-3 text-sm">
                <p className="opacity-70">
                  Send this download link to the person. The file has the key built into its name —
                  they just download and run it. Works once, expires{" "}
                  {new Date(issued.expires_at).toLocaleTimeString()}.
                </p>

                <div>
                  <label className="block text-xs opacity-60">Download link</label>
                  <div className="mt-1 flex gap-2">
                    <input
                      readOnly
                      className="flex-1 rounded bg-black/40 px-2 py-1.5 font-mono text-xs"
                      value={downloadUrl(issued.key)}
                      onFocus={(e) => e.currentTarget.select()}
                    />
                    <button
                      type="button"
                      className="rounded border border-white/15 px-2 py-1 text-xs hover:bg-white/5"
                      onClick={() => navigator.clipboard?.writeText(downloadUrl(issued.key))}
                    >
                      Copy
                    </button>
                    <a
                      href={downloadUrl(issued.key)}
                      className="rounded border border-white/15 px-2 py-1 text-xs hover:bg-white/5"
                    >
                      Test
                    </a>
                  </div>
                </div>

                <div className="rounded border border-white/10 bg-black/20 p-2 text-xs opacity-70">
                  <p className="font-medium opacity-100">Windows will show a blue “unrecognized app” box.</p>
                  <p className="mt-1">
                    That is normal for a brand-new tool — click <em>More info</em>, then{" "}
                    <em>Run anyway</em>. It goes away once the app is code-signed.
                  </p>
                  <p className="mt-1 opacity-70">
                    Self-contained (~64&nbsp;MB), nothing installed, closes itself when done.
                  </p>
                </div>

                <details className="text-xs opacity-70">
                  <summary className="cursor-pointer">Manual / advanced</summary>
                  <p className="mt-1">Raw key (if the person runs the client themselves):</p>
                  <code className="mt-1 block break-all rounded bg-black/40 px-2 py-1 font-mono">
                    {issued.key}
                  </code>
                </details>
              </div>
            )}
          </section>

          <section>
            <h2 className="mb-2 font-semibold">Recent sessions</h2>
            <div className="overflow-hidden rounded-lg border border-white/10">
              <table className="w-full text-sm">
                <thead className="bg-white/5 text-left text-xs uppercase opacity-60">
                  <tr>
                    <th className="px-3 py-2">Case</th>
                    <th className="px-3 py-2">Suspect</th>
                    <th className="px-3 py-2">Key</th>
                    <th className="px-3 py-2">Status</th>
                    <th className="px-3 py-2">Verdict</th>
                    <th className="px-3 py-2">Created</th>
                    <th className="px-3 py-2"></th>
                  </tr>
                </thead>
                <tbody>
                  {sessions.map((s) => (
                    <tr key={s.id} className="border-t border-white/5">
                      <td className="px-3 py-2">{s.case_label}</td>
                      <td className="px-3 py-2 opacity-70">{s.suspect_label ?? "—"}</td>
                      <td className="px-3 py-2 font-mono text-xs opacity-60">{s.key_prefix}…</td>
                      <td className="px-3 py-2">{s.status}</td>
                      <td className="px-3 py-2">
                        {reports[s.id] ? (
                          reports[s.id].status === "running" ? (
                            <span className="text-xs opacity-60">running…</span>
                          ) : (
                            <span
                              className={`rounded border px-1.5 py-0.5 text-xs ${SEVERITY_CLASS[reports[s.id].verdict_severity]}`}
                            >
                              {SEVERITY_LABEL[reports[s.id].verdict_severity]}
                            </span>
                          )
                        ) : (
                          <span className="text-xs opacity-30">—</span>
                        )}
                      </td>
                      <td className="px-3 py-2 opacity-60">
                        {new Date(s.created_at).toLocaleString()}
                      </td>
                      <td className="px-3 py-2 text-right">
                        <Link className="underline opacity-80" to={`/reports/${s.id}`}>
                          view
                        </Link>
                      </td>
                    </tr>
                  ))}
                  {sessions.length === 0 && (
                    <tr>
                      <td className="px-3 py-6 text-center opacity-50" colSpan={7}>
                        No sessions yet.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </section>
        </>
      )}
    </div>
  );
}
