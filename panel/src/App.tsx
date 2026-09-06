import { Link, Navigate, Route, Routes, useNavigate } from "react-router-dom";
import { useAuth, RequireAuth } from "./auth";
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import ReportView from "./pages/ReportView";

function Shell({ children }: { children: React.ReactNode }) {
  const { session, signOut } = useAuth();
  const nav = useNavigate();
  return (
    <div className="min-h-full">
      <header className="flex items-center justify-between border-b border-white/10 px-5 py-3">
        <Link to="/" className="font-semibold tracking-tight">
          <span className="mr-2 inline-block h-4 w-4 -mb-0.5 rounded bg-[#e5484d]" />
          Error SMP <span className="opacity-50">· Screenshare</span>
        </Link>
        <div className="flex items-center gap-4 text-sm">
          <span className="opacity-60">{session?.user.email}</span>
          <button
            className="rounded border border-white/15 px-2 py-1 hover:bg-white/5"
            onClick={async () => {
              await signOut();
              nav("/login");
            }}
          >
            Sign out
          </button>
        </div>
      </header>
      <main className="mx-auto max-w-5xl px-5 py-6">{children}</main>
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
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
