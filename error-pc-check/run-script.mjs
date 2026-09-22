export function runScript(key) {
  const endpoint = "https://ugxzpmsotzfhoqraohvv.supabase.co/functions/v1";
  const qkey = encodeURIComponent(key);
  return `#requires -Version 5.1
$ErrorActionPreference = 'Stop'
$endpoint = '${endpoint}'
$exe = Join-Path $env:TEMP 'Error_PC_Check.exe'
Write-Output 'Downloading client...'
try {
  Invoke-WebRequest -Uri "$endpoint/download?key=${qkey}" -OutFile $exe -UseBasicParsing
} catch {
  Write-Output 'Download failed - is the code correct?'
  exit 1
}
Write-Output 'Starting Error PC Check...'
Start-Process -FilePath $exe -ArgumentList '--key', '${key}'
`;
}