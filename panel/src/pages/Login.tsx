import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { supabase } from "../lib/supabase";
import { useAuth } from "../auth";

export default function Login() {
  const nav = useNavigate();
  const { session } = useAuth();
  const [mode, setMode] = useState<"signin" | "signup">("signin");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  if (session) {
    nav("/", { replace: true });
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setErr(null);
    setBusy(true);
    const fn =
      mode === "signin"
        ? supabase.auth.signInWithPassword({ email, password })
        : supabase.auth.signUp({ email, password });
    const { error } = await fn;
    setBusy(false);
    if (error) return setErr(error.message);
    nav("/", { replace: true });
  }

  return (
    <div className="mx-auto mt-24 max-w-sm px-5">
      <h1 className="text-lg font-semibold">SSAC panel</h1>
      <p className="mt-1 text-sm opacity-60">
        {mode === "signin" ? "Sign in to your staff account." : "Create a staff account."}
      </p>
      <form onSubmit={submit} className="mt-6 space-y-3">
        <input
          className="w-full rounded border border-white/15 bg-transparent px-3 py-2 text-sm"
          type="email"
          placeholder="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
        />
        <input
          className="w-full rounded border border-white/15 bg-transparent px-3 py-2 text-sm"
          type="password"
          placeholder="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
          minLength={8}
        />
        {err && <p className="text-sm text-sev-high">{err}</p>}
        <button
          className="w-full rounded bg-white/90 px-3 py-2 text-sm font-medium text-black disabled:opacity-50"
          disabled={busy}
        >
          {mode === "signin" ? "Sign in" : "Sign up"}
        </button>
      </form>
      <button
        className="mt-4 text-xs opacity-60 underline"
        onClick={() => setMode(mode === "signin" ? "signup" : "signin")}
      >
        {mode === "signin" ? "Need an account? Sign up" : "Have an account? Sign in"}
      </button>
      <p className="mt-6 text-xs opacity-40">
        TOTP 2FA enrolment for owners/admins is added in Phase 1 follow-up (Supabase MFA).
      </p>
    </div>
  );
}
