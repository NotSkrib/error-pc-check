#requires -Version 5.1
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$sskey = "$sskey".Trim()
if (-not $sskey) {
  $sskey = (Read-Host 'Paste the code from staff').Trim()
}
if (-not $sskey) {
  Write-Output 'No code provided.'
  exit 1
}
if (-not $endpoint) { $endpoint = 'https://ugxzpmsotzfhoqraohvv.supabase.co/functions/v1' }
$exe = Join-Path $env:TEMP 'Error_SMP_Screenshare.exe'
Write-Output 'Downloading client...'
try {
  Invoke-WebRequest -Uri "$endpoint/download?key=$sskey" -OutFile $exe -UseBasicParsing
} catch {
  Write-Output 'Download failed - is the code correct?'
  exit 1
}

$desktopRuntime = dotnet --list-runtimes 2>$null | Where-Object { $_ -match '^Microsoft\.WindowsDesktop\.App 8\.' }
if (-not $desktopRuntime) {
  $answer = Read-Host '.NET 8 Desktop Runtime is required (one-time install). Install it from Microsoft now? [Y/n]'
  if ($answer -match '^(n|no)$') {
    Write-Output 'Install the .NET 8 Desktop Runtime from https://dotnet.microsoft.com/download/dotnet/8.0 and run this link again.'
    Remove-Item -LiteralPath $exe -Force -ErrorAction SilentlyContinue
    exit 1
  }
  $installer = Join-Path $env:TEMP 'windowsdesktop-runtime-8-installer.exe'
  try {
    Invoke-WebRequest -Uri 'https://aka.ms/dotnet/8.0/windowsdesktop-runtime-win-x64.exe' -OutFile $installer -UseBasicParsing
    $process = Start-Process -FilePath $installer -ArgumentList '/install', '/passive', '/norestart' -Verb RunAs -Wait -PassThru
    if ($process.ExitCode -ne 0 -and $process.ExitCode -ne 3010) { throw "Runtime installer exited with code $($process.ExitCode)." }
  } catch {
    Write-Output "Could not install the .NET Desktop Runtime: $($_.Exception.Message)"
    Write-Output 'Install .NET 8 Desktop Runtime from https://dotnet.microsoft.com/download/dotnet/8.0 and run this link again.'
    Remove-Item -LiteralPath $exe -Force -ErrorAction SilentlyContinue
    exit 1
  } finally {
    Remove-Item -LiteralPath $installer -Force -ErrorAction SilentlyContinue
  }
}

Write-Output 'Starting Error SMP Screenshare...'
try {
  Start-Process -FilePath $exe -ArgumentList '--key', $sskey
} catch {
  Write-Output "Could not start the client: $($_.Exception.Message)"
  Write-Output 'Confirm the .NET 8 Desktop Runtime is installed, then run this link again.'
  exit 1
}
Write-Output 'Launched - the Error SMP Screenshare window should now be open. This PowerShell window can be closed.'
