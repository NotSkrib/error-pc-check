import { Link, NavLink, Navigate, Route, Routes, useNavigate } from "react-router-dom";
import { RequireAuth } from "./auth";
import { useAuth } from "./lib/useAuth";
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import ReportView from "./pages/ReportView";
import ClientErrors from "./pages/ClientErrors";
import Staff from "./pages/Staff";

const PANEL_VERSION = "v2.2";

function Shell({ children }: { children: React.ReactNode }) {
  const { session, signOut } = useAuth();
  const nav = useNavigate();
  const who = session?.user.email;

  return (
    <div className="min-h-full">
      <div className="h-px bg-gradient-to-r from-transparent via-violet-500/80 to-transparent" />
      <header className="glass sticky top-0 z-30 border-0 border-b border-b-white/10">
        <div className="mx-auto flex max-w-5xl items-center justify-between px-5 py-3">
          <Link to="/" className="group flex items-center gap-2.5">
            <span className="brandmark">E</span>
            <span className="text-[15px] font-semibold tracking-tight text-fg">
              Error SMP <span className="font-normal text-fg-dim">/ Staff Console</span>
            </span>
            <span className="chip border-ink-line2 text-fg-mut">{PANEL_VERSION}</span>
          </Link>
          <div className="flex items-center gap-1.5 text-sm">
            <NavLink to="/errors" className="navlink" end>
              Crashes
            </NavLink>
            <NavLink to="/staff" className="navlink" end>
              Staff
            </NavLink>
            <span className="mx-1.5 h-4 w-px bg-white/10" />
            <span className="flex items-center gap-1.5 text-fg-mut">
              <span className="max-w-[200px] truncate">{who}</span>
            </span>
            <button
              className="btn btn-ghost px-2.5 py-1.5"
              onClick={async () => {
                await signOut();
                nav("/login");
              }}
            >
              Sign out
            </button>
          </div>
        </div>
      </header>
      <main className="mx-auto max-w-5xl px-5 py-8">{children}</main>
      <footer className="mx-auto max-w-5xl px-5 pb-10 pt-2 text-center text-[11px] text-fg-dim">
        Error SMP Screenshare · Staff Console {PANEL_VERSION} · evidence, not a verdict
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
