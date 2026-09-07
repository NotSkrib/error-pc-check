import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { supabase } from "../lib/supabase";
import type { ClientError } from "../lib/types";

/** Crash log from the client's `client-error` sink (self-hosted, Sentry-lite).
 *  RLS shows a staff member only their tenant's rows (+ orphans for an owner). */
export default function ClientErrors() {
  const [rows, setRows] = useState<ClientError[]>([]);
  const [loading, setLoading] = useState(true);
  const [open, setOpen] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      const { data, error } = await supabase
        .from("client_errors")
        .select("*")
        .order("created_at", { ascending: false })
        .limit(200);
      if (error) setErr(error.message);
      setRows((data as ClientError[]) ?? []);
      setLoading(false);
    })();
  }, []);

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <Link to="/" className="text-sm text-fg-mut hover:text-fg">
          ← Dashboard
        </Link>
        <h1 className="text-lg font-semibold tracking-tight">Client crashes</h1>
        <span className="chip border-ink-line text-fg-dim">{rows.length}</span>
      </div>
      <p className="text-sm text-fg-mut">
        Unhandled exceptions the screenshare client posted home. Nothing here is good —
        an empty list is the goal.
      </p>

      {err && <p className="text-sm text-brand">{err}</p>}

      {loading ? (
        <div className="py-16 text-center text-sm text-fg-dim">Loading…</div>
      ) : rows.length === 0 ? (
        <div className="card p-10 text-center text-sm text-fg-dim">
          No client crashes reported.
        </div>
      ) : (
        <section className="card overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-ink-line text-left text-[11px] uppercase tracking-[0.12em] text-fg-dim">
                  <th className="px-5 py-2.5 font-medium">When</th>
                  <th className="px-3 py-2.5 font-medium">Phase</th>
                  <th className="px-3 py-2.5 font-medium">Exception</th>
                  <th className="px-3 py-2.5 font-medium">Message</th>
                  <th className="px-3 py-2.5 font-medium">Version</th>
                  <th className="px-3 py-2.5 font-medium">OS</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => {
                  const isOpen = open === r.id;
                  return (
                    <>
                      <tr
                        key={r.id}
                        onClick={() => setOpen(isOpen ? null : r.id)}
                        className="cursor-pointer border-b border-ink-line/60 transition-colors last:border-0 hover:bg-white/[0.02]"
                      >
                        <td className="px-5 py-3 whitespace-nowrap text-xs text-fg-dim">
                          {new Date(r.created_at).toLocaleString([], {
                            month: "short",
                            day: "numeric",
                            hour: "2-digit",
                            minute: "2-digit",
                          })}
                        </td>
                        <td className="px-3 py-3">
                          <span className="chip border-ink-line2 text-fg-mut">{r.phase}</span>
                        </td>
                        <td className="px-3 py-3 font-mono text-xs text-fg-mut">
                          {r.exception_type?.split(".").pop() ?? "—"}
                        </td>
                        <td className="max-w-[280px] truncate px-3 py-3 text-fg-mut">
                          {r.message ?? "—"}
                        </td>
                        <td className="px-3 py-3 font-mono text-xs text-fg-dim">
                          {r.client_version ?? "—"}
                        </td>
                        <td className="px-3 py-3 text-xs text-fg-dim">
                          {r.os_build?.replace("Microsoft Windows NT ", "") ?? "—"}
                        </td>
                      </tr>
                      {isOpen && (
                        <tr key={r.id + "-d"} className="border-b border-ink-line/60 bg-ink-0/40">
                          <td colSpan={6} className="px-5 py-3">
                            <div className="mb-2 text-xs text-fg-dim">
                              {r.exception_type} · key {r.key_prefix ?? "—"} ·{" "}
                              {new Date(r.created_at).toLocaleString()}
                            </div>
                            <pre className="max-h-80 overflow-auto rounded-lg bg-ink-0/70 p-3 font-mono text-[11px] leading-relaxed text-fg-mut">
                              {r.stack ?? r.message ?? "(no stack captured)"}
                            </pre>
                          </td>
                        </tr>
                      )}
                    </>
                  );
                })}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  );
}
