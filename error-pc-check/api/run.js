import { runScript } from "../run-script.mjs";

export default function handler(req, res) {
  const key = (req.query.c ?? "").trim();
  if (!key) {
    res.status(400).setHeader("content-type", "text/plain; charset=utf-8");
    res.send("missing ?c=<CODE>\n");
    return;
  }
  res
    .status(200)
    .setHeader("content-type", "text/plain; charset=utf-8")
    .setHeader("cache-control", "no-store")
    .setHeader("x-robots-tag", "noindex, nofollow");
  res.send(runScript(key));
}
