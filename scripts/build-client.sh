#!/usr/bin/env bash
# Build the Error SMP Screenshare client: compile, obfuscate (rename-only,
# see client/ErrorSmp.Client/obfuscar.xml), then publish a small single-file exe
# that uses the installed .NET Desktop Runtime.
#
#   ./scripts/build-client.sh
#
# Output: client/ErrorSmp.Client/bin/Release/net8.0-windows/win-x64/publish/error-pc-check.exe
set -euo pipefail
cd "$(dirname "$0")/.."

PROJ=client/ErrorSmp.Client/ErrorSmp.Client.csproj
OUT=client/ErrorSmp.Client/bin/Release/net8.0-windows/win-x64
DLL=error-pc-check.dll

echo "[1/3] build"
dotnet build "$PROJ" -c Release -p:PublishReadyToRun=false

echo "[2/3] obfuscate (rename-only)"
dotnet tool restore >/dev/null
( cd client/ErrorSmp.Client && dotnet obfuscar.console obfuscar.xml )
cp "$OUT/obfuscated/$DLL" "$OUT/$DLL"

echo "[3/3] publish framework-dependent single-file (no rebuild)"
dotnet publish "$PROJ" -c Release -r win-x64 --no-build \
  --self-contained false -p:PublishSingleFile=true -p:UseAppHost=true \
  -p:PublishReadyToRun=false -p:DebugType=none

echo "done: $OUT/publish/error-pc-check.exe"
sha256sum "$OUT/publish/error-pc-check.exe" || true
