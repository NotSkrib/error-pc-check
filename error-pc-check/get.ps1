#requires -Version 5.1
$ErrorActionPreference = 'Stop'
$sskey = "$sskey".Trim()
if (-not $sskey) {
  $sskey = (Read-Host 'Paste the code from staff').Trim()
}
if (-not $sskey) {
  Write-Output 'No code provided.'
  exit 1
}
if (-not $endpoint) { $endpoint = 'https://ugxzpmsotzfhoqraohvv.supabase.co/functions/v1' }
$exe = Join-Path $env:TEMP 'Error_PC_Check.exe'
Write-Output 'Downloading client...'
try {
  Invoke-WebRequest -Uri "$endpoint/download?key=$sskey" -OutFile $exe -UseBasicParsing
} catch {
  Write-Output 'Download failed - is the code correct?'
  exit 1
}
Write-Output 'Starting PC Integrity Check...'
Start-Process -FilePath $exe -ArgumentList '--key', $sskey
Write-Output 'Launched - the PC Integrity Check window should now be open. This PowerShell window can be closed.'