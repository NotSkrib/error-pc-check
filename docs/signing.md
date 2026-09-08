# Code signing (removes the SmartScreen "unrecognized app" prompt)

Windows SmartScreen shows **"Windows protected your PC — unrecognized app"** for
any executable downloaded from the internet whose publisher it doesn't recognise.
**There is no build flag that removes it for an unsigned binary.** The exe must
carry a valid Authenticode signature from a CA that SmartScreen trusts.

The client is already sign-ready: it has an icon, a manifest, version + publisher
metadata (`SSAC.Client.csproj`). All that's missing is the signature.

## Which certificate

| Path | ~Cost | Prompt after signing |
|---|---|---|
| **Azure Trusted Signing** (Microsoft) | ~$10/month | Gone after your identity is validated (a few business days). Cheapest legit route. |
| **EV code-signing cert** (Sectigo / DigiCert / SSL.com — ships on a USB token or cloud HSM) | ~$300-600/yr | **Gone immediately**, day one. What commercial tools use. |
| **OV code-signing cert** (Certum "open source" is ~$100/yr) | ~$100-250/yr | Publisher name replaces "unknown publisher"; the full prompt fades after the file accrues download reputation (days-weeks). |

Self-signed certs do **not** work - SmartScreen ignores them.

**Free route:** open-source the repo and get an OV cert + cloud signing from
**SignPath Foundation** — see [`open-source.md`](open-source.md). Same reputation
wait as any OV cert, but $0. `.github/workflows/release-client.yml` already wires
it in.

## Sign the published exe

After `dotnet publish` (see `docs/deploy.md`), before splitting/uploading:

```powershell
# EV / OV cert in the Windows cert store or on a token:
signtool sign /fd SHA256 /tr http://timestamp.sectigo.com /td SHA256 /a `
  client\SSAC.Client\bin\Release\net8.0-windows\win-x64\publish\ssac-screenshare.exe

# Azure Trusted Signing (azuresigntool + the ATS dlib):
azuresigntool sign -kvu <vault-url> -kvc <cert-name> `
  -kvt <tenant> -kvi <client-id> -kvs <secret> `
  -tr http://timestamp.acs.microsoft.com -td SHA256 `
  client\...\publish\ssac-screenshare.exe

# verify
signtool verify /pa /v client\...\publish\ssac-screenshare.exe
```

Then run the split + upload steps from `docs/deploy.md` on the **signed** exe and
regenerate `manifest.json` with its new sha256.

## If antivirus *deletes* the file (different from the SmartScreen prompt)

The SmartScreen screen is reputation only - it doesn't mean "malware detected".
If Defender/other AV actually quarantines the exe:

1. Signing fixes most of it (signed binaries are trusted far more).
2. Drop `EnableCompressionInSingleFile` from the publish (compressed bundles look
   "packed" to heuristics) - the exe grows to ~145 MB / 5 parts.
3. Submit it for review: <https://www.microsoft.com/wdsi/filesubmission>
   (choose "software developer", "incorrectly detected as malware").
4. Keep serving over HTTPS from the same domain so URL/domain reputation builds.

## Interim

Until a cert is in place, the panel download box tells the person:
*"If Windows shows a blue 'unrecognized app' box, click **More info -> Run
anyway**."* That is expected and safe for a brand-new unsigned tool.
