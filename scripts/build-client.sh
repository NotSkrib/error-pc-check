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
WPF_REF_DIR_WINDOWS="$(pwsh -NoProfile -Command '
$root = Join-Path $env:ProgramFiles "dotnet/packs/Microsoft.WindowsDesktop.App.Ref"
$pack = Get-ChildItem -LiteralPath $root -Directory |
  Where-Object { $_.Name -match "^8\.0\." } |
  Sort-Object { [version]$_.Name } -Descending |
  Select-Object -First 1
if (-not $pack) { throw "Microsoft.WindowsDesktop.App.Ref for .NET 8 was not found." }
Join-Path $pack.FullName "ref/net8.0"
')"
WPF_REF_DIR="$(cygpath -u "$WPF_REF_DIR_WINDOWS")"
test -f "$WPF_REF_DIR/PresentationFramework.dll"
(
  cd client/ErrorSmp.Client
  WPF_REF_DIR="$WPF_REF_DIR_WINDOWS" pwsh -NoProfile -Command '
    [xml]$config = Get-Content "obfuscar.xml" -Raw
    $searchPath = $config.CreateElement("AssemblySearchPath")
    $searchPath.SetAttribute("path", $env:WPF_REF_DIR)
    $null = $config.Obfuscator.AppendChild($searchPath)
    $config.Save((Join-Path (Get-Location).Path "obj/obfuscar.generated.xml"))
  '
  dotnet obfuscar.console obj/obfuscar.generated.xml
)
cp "$OUT/obfuscated/$DLL" "$OUT/$DLL"

echo "[3/3] publish framework-dependent single-file (no rebuild)"
dotnet publish "$PROJ" -c Release -r win-x64 --no-build \
  --self-contained false -p:PublishSingleFile=true -p:UseAppHost=true \
  -p:PublishReadyToRun=false -p:DebugType=none

echo "done: $OUT/publish/error-pc-check.exe"
sha256sum "$OUT/publish/error-pc-check.exe" || true
