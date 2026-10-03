import { Link, NavLink, Navigate, Route, Routes, useNavigate } from "react-router-dom";
import { RequireAuth } from "./auth";
import { useAuth } from "./lib/useAuth";
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import ReportView from "./pages/ReportView";
import ClientErrors from "./pages/ClientErrors";
import Staff from "./pages/Staff";

const PANEL_VERSION = "v2.4";

function Shell({ children }: { children: React.ReactNode }) {
  const { session, signOut } = useAuth();
  const nav = useNavigate();
  const who = session?.user.email;

  return (
    <div className="min-h-full">
      <header className="app-header sticky top-0 z-30 border-b">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-x-6 gap-y-2 px-5 py-3">
          <Link to="/" className="group flex items-center gap-2.5">
            <span className="brandmark">E</span>
            <span className="text-sm font-semibold text-fg">
              Error SMP <span className="font-normal text-fg-mut">Screenshare</span>
            </span>
            <span className="hidden rounded border border-ink-line px-1.5 py-0.5 text-[10px] text-fg-dim sm:inline-flex">{PANEL_VERSION}</span>
          </Link>
          <nav aria-label="Main navigation" className="flex items-center gap-1">
            <NavLink to="/" className="navlink" end>Sessions</NavLink>
            <NavLink to="/errors" className="navlink" end>
              Client errors
            </NavLink>
            <NavLink to="/staff" className="navlink" end>
              Staff
            </NavLink>
          </nav>
          <div className="flex min-w-0 items-center gap-2">
            <span className="max-w-[180px] truncate text-xs text-fg-mut" title={who}>{who}</span>
            <button
              className="btn btn-ghost px-2.5 py-1.5 text-xs"
              onClick={async () => { await signOut(); nav("/login"); }}
            >Sign out</button>
          </div>
        </div>
      </header>
      <main className="mx-auto max-w-6xl px-5 py-8">{children}</main>
      <footer className="mx-auto max-w-6xl px-5 pb-8 pt-2 text-xs text-fg-dim">
        Error SMP Screenshare <span className="px-1.5 text-fg-dim">·</span> Evidence for human review
      </footer>
    </div>
  );
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route
        path="/"
        element={
          <RequireAuth>
            <Shell>
              <Dashboard />
            </Shell>
          </RequireAuth>
        }
      />
      <Route
        path="/reports/:sessionId"
        element={
          <RequireAuth>
            <Shell>
              <ReportView />
            </Shell>
          </RequireAuth>
        }
      />
      <Route
        path="/errors"
        element={
          <RequireAuth>
            <Shell>
              <ClientErrors />
            </Shell>
          </RequireAuth>
        }
      />
      <Route
        path="/staff"
        element={
          <RequireAuth>
            <Shell>
              <Staff />
            </Shell>
          </RequireAuth>
        }
      />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
