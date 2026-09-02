import { createClient } from "@supabase/supabase-js";

const url = import.meta.env.VITE_SUPABASE_URL as string | undefined;
const anon = import.meta.env.VITE_SUPABASE_ANON_KEY as string | undefined;

if (!url || !anon) {
  // Surfaced early so a missing .env.local is obvious in dev.
  console.error("Missing VITE_SUPABASE_URL / VITE_SUPABASE_ANON_KEY — copy panel/.env.example");
}

export const supabase = createClient(url ?? "http://localhost:54321", anon ?? "anon", {
  auth: { persistSession: true, autoRefreshToken: true },
});
