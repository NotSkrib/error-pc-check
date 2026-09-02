import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { supabase } from "../lib/supabase";
import type { SessionRow, Tenant } from "../lib/types";

function slugify(s: string) {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 40);
}

export default function Dashboard() {
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [tenantId, setTenantId] = useState<string | null>(null);
  const [sessions, setSessions] = useState<SessionRow[]>([]);
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
              <div className="mt-3 rounded border border-sev-info/40 bg-sev-info/10 p-3 text-sm">
                <p className="opacity-70">
                  Give this key to the suspect with the client download. It is shown once, works
                  once, and expires {new Date(issued.expires_at).toLocaleTimeString()}.
                </p>
                <code className="mt-2 block break-all rounded bg-black/40 px-2 py-1 font-mono text-base">
                  {issued.key}
                </code>
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
                      <td className="px-3 py-6 text-center opacity-50" colSpan={6}>
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
