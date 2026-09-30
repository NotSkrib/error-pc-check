import { Fragment, useEffect, useMemo, useState } from "react";
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
  const [query, setQuery] = useState("");
  const [phase, setPhase] = useState("all");

  const phases = useMemo(() => [...new Set(rows.map((row) => row.phase))].sort(), [rows]);
  const visibleRows = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return rows.filter((row) => {
      if (phase !== "all" && row.phase !== phase) return false;
      if (!needle) return true;
      return [row.phase, row.exception_type, row.message, row.client_version, row.os_build]
        .some((value) => value?.toLowerCase().includes(needle));
    });
  }, [phase, query, rows]);

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
      <div className="flex flex-wrap items-end justify-between gap-4 border-b border-ink-line pb-5">
        <div>
          <Link to="/" className="mb-3 inline-flex text-xs font-medium text-fg-mut transition hover:text-[var(--accent)]">
            ← Sessions
          </Link>
          <h1 className="text-2xl font-semibold tracking-tight">Client errors</h1>
          <p className="mt-1.5 max-w-2xl text-sm leading-relaxed text-fg-mut">
            Diagnostic reports from the screenshare client, including expired keys and connection failures.
          </p>
        </div>
        <div className="flex items-baseline gap-2 rounded-lg border border-[color-mix(in_oklch,var(--accent)_28%,transparent)] bg-[color-mix(in_oklch,var(--accent)_9%,transparent)] px-4 py-2.5">
          <span className="text-xl font-semibold tabular-nums text-[var(--accent)]">{rows.length}</span>
          <span className="text-xs text-fg-mut">reports</span>
        </div>
      </div>

      {err && <p className="text-sm text-brand">{err}</p>}

      {loading ? (
        <div className="animate-pulse py-16 text-center text-sm text-fg-dim">Loading…</div>
      ) : rows.length === 0 ? (
        <div className="card p-10 text-center">
          <p className="text-sm font-medium text-fg">No client reports</p>
          <p className="mt-1 text-xs text-fg-mut">Diagnostic events will appear here when received.</p>
        </div>
      ) : (
        <section className="space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex min-w-0 flex-1 flex-wrap gap-2">
              <label className="relative min-w-[220px] flex-1 sm:max-w-md">
                <span className="sr-only">Search client reports</span>
                <span aria-hidden="true" className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-sm text-[var(--accent)]">⌕</span>
                <input
                  className="input pl-9"
                  type="search"
                  placeholder="Search message, exception, version…"
                  value={query}
                  onChange={(event) => setQuery(event.target.value)}
                />
              </label>
              <label>
                <span className="sr-only">Filter by phase</span>
                <select className="input min-w-36" value={phase} onChange={(event) => setPhase(event.target.value)}>
                  <option value="all">All phases</option>
                  {phases.map((item) => <option key={item} value={item}>{item}</option>)}
                </select>
              </label>
            </div>
            <p aria-live="polite" className="text-xs tabular-nums text-fg-mut">
              {visibleRows.length === rows.length ? `${rows.length} reports` : `${visibleRows.length} of ${rows.length} reports`}
            </p>
          </div>
          {visibleRows.length === 0 ? (
            <div className="card px-5 py-12 text-center">
              <p className="text-sm font-medium text-fg">No matching reports</p>
              <p className="mt-1 text-sm text-fg-mut">Try another search or phase.</p>
            </div>
          ) : <div className="card overflow-hidden">
          <div className="overflow-x-auto">
            <table className="client-error-table w-full text-sm">
              <thead>
                <tr className="border-b border-ink-line text-left text-[11px] uppercase tracking-[0.12em] text-fg-dim">
                  <th className="px-5 py-2.5 font-medium">When</th>
                  <th className="px-3 py-2.5 font-medium">Phase</th>
                  <th className="px-3 py-2.5 font-medium">Exception</th>
                  <th className="px-3 py-2.5 font-medium">Message</th>
                  <th className="px-3 py-2.5 font-medium">Version</th>
                  <th className="px-3 py-2.5 font-medium">OS</th>
                  <th className="px-3 py-2.5" />
                </tr>
              </thead>
              <tbody>
                {visibleRows.map((r) => {
                  const isOpen = open === r.id;
                  return (
                    <Fragment key={r.id}>
                      <tr
                        role="button"
                        tabIndex={0}
                        aria-expanded={isOpen}
                        onClick={() => setOpen(isOpen ? null : r.id)}
                        onKeyDown={(e) => {
                          if (e.key === "Enter" || e.key === " ") {
                            e.preventDefault();
                            setOpen(isOpen ? null : r.id);
                          }
                        }}
                        className="client-error-row cursor-pointer border-b border-ink-line/60 transition-colors last:border-0"
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
                          <span className="chip border-[color-mix(in_oklch,var(--accent)_24%,transparent)] bg-[color-mix(in_oklch,var(--accent)_8%,transparent)] text-[var(--accent)]">{r.phase}</span>
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
                        <td className="px-5 py-3 text-right text-xs text-fg-dim">
                          {isOpen ? "▾" : "▸"}
                        </td>
                      </tr>
                      {isOpen && (
                        <tr className="border-b border-ink-line/60 bg-ink-0/40">
                          <td colSpan={7} className="px-5 py-3">
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
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
          </div>}
        </section>
      )}
    </div>
  );
}
