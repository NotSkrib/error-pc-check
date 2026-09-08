# Open-sourcing + free code signing (SignPath Foundation)

Goal: a public repo + **free** Authenticode signing so the client stops
tripping SmartScreen (once it has some download reputation).

## 1. Put it on GitHub

Nothing secret is committed — the only credentials the code touches are read from
env (`Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")` in the Edge Functions) and
`.env*` files are gitignored. The Supabase **anon** key and project ref are safe
to be public (RLS-protected, that's their purpose).

```bash
gh auth login
gh repo create errorsmp/error-pc-check --public --source=. --remote=origin --push
# or: create the repo in the GitHub UI, then
#   git remote add origin https://github.com/<you>/error-pc-check.git
#   git push -u origin master
```

`.github/workflows/ci.yml` runs on every push (builds panel + client).

## 2. Apply to SignPath Foundation

SignPath gives OSS projects a free OV code-signing certificate + cloud signing.

1. Sign in at <https://about.signpath.io/product/open-source> with the GitHub
   account that owns the repo and submit the project for review.
2. When approved you get a SignPath **organization** with your repo linked.
3. In SignPath: create a **Project** (slug e.g. `error-pc-check`), add a
   **Signing Policy** (slug e.g. `release-signing`) bound to the Foundation
   certificate, and an **Artifact Configuration** that signs `*.exe`.
4. Create a **CI user** and copy its **API token**.

## 3. Wire the release workflow

In the GitHub repo -> Settings -> Secrets and variables -> Actions:

| Kind | Name | Value |
|---|---|---|
| Secret | `SIGNPATH_API_TOKEN` | the SignPath CI user token |
| Variable | `SIGNPATH_ORGANIZATION_ID` | SignPath org id (GUID) |
| Variable | `SIGNPATH_PROJECT_SLUG` | `error-pc-check` |
| Variable | `SIGNPATH_SIGNING_POLICY_SLUG` | `release-signing` |
| Secret *(optional)* | `SUPABASE_URL` | `https://ugxzpmsotzfhoqraohvv.supabase.co` |
| Secret *(optional)* | `SUPABASE_SERVICE_ROLE_KEY` | Supabase service-role key |

Then:

```bash
git tag v0.4.1 && git push origin v0.4.1
```

`.github/workflows/release-client.yml` builds -> obfuscates -> publishes the
single-file exe -> SignPath signs it -> attaches `Error_PC_Check.exe` to a GitHub
Release. If the two optional Supabase secrets are set it also re-splits the
**signed** exe and uploads the parts, so the live download link immediately
serves the signed build.

## 4. Reality check on SmartScreen

A SignPath (OV) signature makes the prompt show the publisher name and then fade
as the file accrues download reputation — days to weeks, not instant. Only an
**EV** certificate removes it on day one. See `docs/signing.md`.
