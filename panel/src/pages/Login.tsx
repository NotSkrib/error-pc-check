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
  const [busy, setBusy] = useState<"none" | "signin" | "guest">("none");

  if (session) {
    nav("/", { replace: true });
  }

  async function signIn(e: React.FormEvent) {
    e.preventDefault();
    setErr(null);
    setBusy("signin");
    const { error } = await supabase.auth.signInWithPassword({ email, password });
    setBusy("none");
    if (error) return setErr(error.message);
    nav("/", { replace: true });
  }

  async function continueAsGuest() {
    setErr(null);
    setBusy("guest");
    const { error } = await supabase.auth.signInAnonymously();
    if (error) {
      setBusy("none");
      return setErr(error.message);
    }
    // attach to the Error SMP tenant with the guest role
    const { error: joinErr } = await supabase.rpc("join_as_guest");
    setBusy("none");
    if (joinErr) return setErr(joinErr.message);
    nav("/", { replace: true });
  }

  return (
    <div className="mx-auto mt-24 max-w-sm px-5">
      <div className="mb-6 flex items-center gap-2">
        <span className="inline-block h-6 w-6 rounded bg-[#e5484d]" />
        <h1 className="text-lg font-semibold">
          Error SMP <span className="opacity-50">· Screenshare</span>
        </h1>
      </div>

      <button
        onClick={continueAsGuest}
        disabled={busy !== "none"}
        className="w-full rounded bg-[#e5484d] px-3 py-2.5 text-sm font-medium text-white disabled:opacity-50"
      >
        {busy === "guest" ? "Setting up…" : "Continue as guest"}
      </button>
      <p className="mt-2 text-xs opacity-50">
        Guests can generate screenshare keys and view reports. No account needed.
      </p>

      <div className="my-6 flex items-center gap-3 text-xs opacity-40">
        <span className="h-px flex-1 bg-white/15" /> staff login <span className="h-px flex-1 bg-white/15" />
      </div>

      <form onSubmit={signIn} className="space-y-3">
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
        />
        {err && <p className="text-sm text-sev-high">{err}</p>}
        <button
          className="w-full rounded border border-white/20 px-3 py-2 text-sm font-medium disabled:opacity-50"
          disabled={busy !== "none"}
        >
          {busy === "signin" ? "Signing in…" : "Sign in"}
        </button>
      </form>

      <p className="mt-6 text-xs opacity-40">
        No public sign-up. An admin provisions staff accounts.
      </p>
    </div>
  );
}
