#!/usr/bin/env bash
# Build the Error SMP Screenshare client: compile, obfuscate (rename-only,
# see client/SSAC.Client/obfuscar.xml), then publish the single-file exe with
# the obfuscated assembly bundled in.
#
#   ./scripts/build-client.sh
#
# Output: client/SSAC.Client/bin/Release/net8.0-windows/win-x64/publish/ssac-screenshare.exe
set -euo pipefail
cd "$(dirname "$0")/.."

PROJ=client/SSAC.Client/SSAC.Client.csproj
OUT=client/SSAC.Client/bin/Release/net8.0-windows/win-x64
DLL=ssac-screenshare.dll

echo "[1/3] build"
dotnet build "$PROJ" -c Release -p:PublishReadyToRun=false

echo "[2/3] obfuscate (rename-only)"
dotnet tool restore >/dev/null
( cd client/SSAC.Client && dotnet obfuscar.console obfuscar.xml )
cp "$OUT/obfuscated/$DLL" "$OUT/$DLL"

echo "[3/3] publish single-file (no rebuild, bundles the obfuscated dll)"
dotnet publish "$PROJ" -c Release -r win-x64 --no-build \
  -p:PublishReadyToRun=false -p:DebugType=none

echo "done: $OUT/publish/ssac-screenshare.exe"
sha256sum "$OUT/publish/ssac-screenshare.exe" || true
