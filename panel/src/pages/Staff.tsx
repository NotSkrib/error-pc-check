import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { supabase } from "../lib/supabase";
import type { MemberRole, Tenant } from "../lib/types";

interface StaffAccount {
  user_id: string;
  role: MemberRole;
  email: string | null;
  display_name: string | null;
  created_at: string | null;
}

function callAdminStaff<T>(body: Record<string, unknown>): Promise<{ data: T | null; error: string | null }> {
  return supabase.functions
    .invoke("admin-staff", { body })
    .then(({ data, error }) => {
      if (error) return { data: null, error: error.message };
      if (data?.error) return { data: null, error: String(data.error) };
      return { data: data as T, error: null };
    });
}

export default function Staff() {
  const [tenant, setTenant] = useState<Tenant | null>(null);
  const [accounts, setAccounts] = useState<StaffAccount[]>([]);
  const [loading, setLoading] = useState(true);
  const [authorized, setAuthorized] = useState(true);
  const [username, setUsername] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [issued, setIssued] = useState<{ label: string; email: string; password: string } | null>(null);

  async function load() {
    setLoading(true);
    const { data: tenants } = await supabase
      .from("tenants")
      .select("id,name,slug,retention_days,plan,created_at")
      .order("created_at")
      .limit(1);
    const t = tenants?.[0] ?? null;
    setTenant(t);
    if (!t) {
      setLoading(false);
      return;
    }
    const { data, error } = await callAdminStaff<{ accounts: StaffAccount[] }>({
      action: "list",
      tenant_id: t.id,
    });
    if (error) {
      setAuthorized(!/not authorized/i.test(error));
      setErr(error);
    } else {
      setAccounts(data?.accounts ?? []);
    }
    setLoading(false);
  }

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function createAccount(e: React.FormEvent) {
    e.preventDefault();
    if (!tenant) return;
    const name = username.trim();
    if (!name) return;
    setErr(null);
    setIssued(null);
    setBusy(true);
    const { data, error } = await callAdminStaff<{ email: string; password: string }>({
      action: "create",
      tenant_id: tenant.id,
      username: name,
    });
    setBusy(false);
    if (error) return setErr(error);
    if (data) setIssued({ label: name, email: data.email, password: data.password });
    setUsername("");
    load();
  }

  async function resetPassword(a: StaffAccount) {
    if (!tenant) return;
    if (!confirm(`Reset the password for ${a.display_name ?? a.email}?`)) return;
    setErr(null);
    setIssued(null);
    const { data, error } = await callAdminStaff<{ password: string }>({
      action: "reset_password",
      tenant_id: tenant.id,
      user_id: a.user_id,
    });
    if (error) return setErr(error);
    if (data) setIssued({ label: a.display_name ?? a.email ?? a.user_id, email: a.email ?? "", password: data.password });
  }

  async function removeAccount(a: StaffAccount) {
    if (!tenant) return;
    if (!confirm(`Revoke access for ${a.display_name ?? a.email}? This can't be undone from here.`)) return;
    setErr(null);
    const { error } = await callAdminStaff({ action: "remove", tenant_id: tenant.id, user_id: a.user_id });
    if (error) return setErr(error);
    load();
  }

  if (loading) return <div className="py-20 text-center text-sm text-fg-dim">Loading…</div>;

  if (!authorized) {
    return (
      <div className="card mx-auto max-w-md p-6">
        <h2 className="text-base font-semibold">Not authorized</h2>
        <p className="mt-1.5 text-sm text-fg-mut">Only owners/admins can manage staff accounts.</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <Link to="/" className="text-sm text-fg-mut hover:text-fg">
          ← Dashboard
        </Link>
        <h1 className="text-lg font-semibold tracking-tight">Staff accounts</h1>
        <span className="chip border-ink-line text-fg-dim">{accounts.length}</span>
      </div>

      <section className="card overflow-hidden">
        <div className="border-b border-ink-line px-5 py-3">
          <h2 className="text-sm font-semibold">Add staff</h2>
        </div>
        <div className="p-5">
          <form onSubmit={createAccount} className="flex flex-wrap items-end gap-3">
            <div className="min-w-[200px] flex-1">
              <label className="label">Username</label>
              <input
                className="input mt-1"
                placeholder="Discord name"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
              />
            </div>
            <button disabled={busy} className="btn btn-primary h-[38px] px-4">
              {busy ? "Creating…" : "Create account"}
            </button>
          </form>
          {err && <p className="mt-3 text-sm text-brand">{err}</p>}
          {issued && (
            <div className="mt-5 rounded-xl border border-brand/25 bg-brand/[0.06] p-4 shadow-glow">
              <p className="text-sm text-fg-mut">
                Credentials for <span className="text-fg">{issued.label}</span> — shown once, save them now.
              </p>
              <div className="mt-2 space-y-1 font-mono text-xs">
                <div>
                  email: <span className="text-fg">{issued.email}</span>
                </div>
                <div>
                  password: <span className="text-fg">{issued.password}</span>
                </div>
              </div>
            </div>
          )}
        </div>
      </section>

      <section className="card overflow-hidden">
        <div className="border-b border-ink-line px-5 py-3">
          <h2 className="text-sm font-semibold">Members</h2>
        </div>
        {accounts.length === 0 ? (
          <div className="px-5 py-14 text-center text-sm text-fg-dim">No staff accounts yet.</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-ink-line text-left text-[11px] uppercase tracking-[0.12em] text-fg-dim">
                  <th className="px-5 py-2.5 font-medium">Name</th>
                  <th className="px-3 py-2.5 font-medium">Email</th>
                  <th className="px-3 py-2.5 font-medium">Role</th>
                  <th className="px-5 py-2.5" />
                </tr>
              </thead>
              <tbody>
                {accounts.map((a) => (
                  <tr key={a.user_id} className="group border-b border-ink-line/60 last:border-0 hover:bg-white/[0.02]">
                    <td className="px-5 py-3 font-medium">{a.display_name ?? "—"}</td>
                    <td className="px-3 py-3 text-fg-mut">{a.email}</td>
                    <td className="px-3 py-3 text-xs text-fg-mut">{a.role}</td>
                    <td className="px-5 py-3 text-right whitespace-nowrap">
                      <button
                        onClick={() => resetPassword(a)}
                        className="text-xs font-medium text-fg-mut hover:text-fg"
                      >
                        Reset password
                      </button>
                      {a.role !== "owner" && (
                        <button
                          onClick={() => removeAccount(a)}
                          className="ml-3 text-xs text-fg-dim opacity-0 transition hover:text-brand group-hover:opacity-100"
                        >
                          Remove
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
