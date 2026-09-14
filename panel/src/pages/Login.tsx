import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { supabase } from "../lib/supabase";
import { useAuth } from "../auth";

export default function Login() {
  const nav = useNavigate();
  const { session } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState<"none" | "signin">("none");

  if (session) nav("/", { replace: true });

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
    <div className="relative flex min-h-full items-center justify-center px-5 py-16">
      <div className="w-full max-w-sm">
        <div className="mb-8 flex items-center gap-2.5">
          <span className="brandmark h-7 w-7 text-sm">E</span>
          <div className="leading-tight">
            <div className="text-[15px] font-semibold tracking-tight">Error SMP</div>
            <div className="text-xs text-fg-dim">Screenshare console</div>
          </div>
        </div>

        <div className="card p-5">
          <form onSubmit={signIn} className="space-y-2.5">
            <input
              className="input"
              type="email"
              placeholder="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
            />
            <input
              className="input"
              type="password"
              placeholder="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
            <button className="btn btn-primary w-full py-2.5" disabled={busy !== "none"}>
              {busy === "signin" ? "Signing in…" : "Sign in"}
            </button>
          </form>

          {err && <p className="mt-3 text-sm text-brand">{err}</p>}
        </div>

        <p className="mt-4 text-center text-xs text-fg-dim">
          No public sign-up — an admin provisions staff accounts.
        </p>
      </div>
    </div>
  );
}
