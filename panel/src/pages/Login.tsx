import { useState } from "react";
import { Navigate, useNavigate } from "react-router-dom";
import { supabase } from "../lib/supabase";
import { useAuth } from "../lib/useAuth";

export default function Login() {
  const nav = useNavigate();
  const { session } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState<"none" | "signin">("none");

  if (session) return <Navigate to="/" replace />;

  async function signIn(e: React.FormEvent) {
    e.preventDefault();
    setErr(null);
    setBusy("signin");
    const { error } = await supabase.auth.signInWithPassword({ email, password });
    setBusy("none");
    if (error) return setErr(error.message);
    nav("/", { replace: true });
  }

  return (
    <div className="relative flex min-h-screen items-center justify-center px-5 py-12">
      <div className="w-full max-w-sm">
        <div className="mb-7 flex flex-col items-center text-center">
          <span className="brandmark h-11 w-11 rounded-lg text-xl">
            E
          </span>
          <div className="mt-3 leading-tight">
            <div className="text-base font-semibold">Error SMP Screenshare</div>
            <div className="mt-1 text-sm text-fg-mut">Staff sign in</div>
          </div>
        </div>

        <div className="card p-6">
          <form onSubmit={signIn} className="space-y-4">
            <div>
              <label htmlFor="staff-email" className="label">Email</label>
              <input
                id="staff-email"
                className="input mt-1.5"
                type="email"
                autoComplete="username"
                spellCheck={false}
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
              />
            </div>
            <div>
              <label htmlFor="staff-password" className="label">Password</label>
              <input
                id="staff-password"
                className="input mt-1.5"
                type="password"
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </div>
            <button className="btn btn-primary min-h-[42px] w-full" disabled={busy !== "none"}>
              {busy === "signin" ? "Signing in…" : "Sign in"}
            </button>
          </form>

          {err && (
            <p role="alert" className="mt-3 text-sm text-brand">
              {err}
            </p>
          )}
        </div>

        <p className="mt-4 text-center text-xs leading-relaxed text-fg-mut">
          No public sign-up — an admin provisions staff accounts.
        </p>
      </div>
    </div>
  );
}
