import { runScript } from "../run-script.mjs";

export async function onRequestGet({ request }) {
  const url = new URL(request.url);
  const key = (url.searchParams.get("c") ?? "").trim();
  if (!key) {
    return new Response("missing ?c=<CODE>\n", {
      status: 400,
      headers: { "Content-Type": "text/plain; charset=utf-8" },
    });
  }
  return new Response(runScript(key), {
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Robots-Tag": "noindex, nofollow",
    },
  });
}