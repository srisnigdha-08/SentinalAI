<#
.SYNOPSIS
  Restarts only the backend window of a running demo, for example after `git pull` brought in new backend code.
  The AI engine, frontend, Cowrie parser and MongoDB keep running; open dashboards reconnect by themselves.

.DESCRIPTION
  `node server.js` does not reload code. The frontend (Vite) does, so after a pull the dashboard can show a feature
  whose API route the old backend never registered, and the request fails with "Route not found" (404). Run this
  script after pulling backend changes.

  Uses the same command, bind address, demo database and backend\.env as scripts\demo\start-demo.ps1. Stops only the
  existing "SentinelAI-demo: Backend" window; anything else on port 5000 is reported, never killed. Secrets stay in
  backend\.env and never appear on a command line.

  After the restart it checks that the backend answers /health and that the API routes are registered: an
  unauthenticated request to /api/reports/security-summary must be refused (401), not reported missing (404).

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\demo\restart-backend.ps1
#>
param(
  [string]$DemoDb = "sentinel-demo",
  [string]$Distro = "Ubuntu"
)
$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path

$WinIp = ((wsl -d $Distro -- ip route show default) -split ' ')[2]
if (-not $WinIp) { throw "Could not query WSL ($Distro) for the Windows host address. Is it installed and running?" }

Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" |
  Where-Object { $_.CommandLine -like "*SentinelAI-demo: Backend*" } |
  ForEach-Object { taskkill /PID $_.ProcessId /T /F | Out-Null; "Stopped the old backend window (pid $($_.ProcessId))" }
Start-Sleep 1
$busy = Get-NetTCPConnection -LocalPort 5000 -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
if ($busy) {
  $p = Get-CimInstance Win32_Process -Filter "ProcessId=$($busy.OwningProcess)"
  throw "Port 5000 is still in use by $($p.Name) (pid $($p.ProcessId)): $($p.CommandLine). This script did not start it; stop it yourself first."
}

$command = "`$host.UI.RawUI.WindowTitle='SentinelAI-demo: Backend :5000 ($DemoDb)'; " +
  "`$env:HOST='$WinIp'; `$env:MONGO_URI='mongodb://127.0.0.1:27017/$DemoDb'; Set-Location '$Root\backend'; node server.js"
Start-Process powershell -ArgumentList '-NoExit', '-ExecutionPolicy', 'Bypass', '-Command', $command | Out-Null

$base = "http://${WinIp}:5000"
$deadline = (Get-Date).AddSeconds(60)
$up = $false
while ((Get-Date) -lt $deadline) {
  try { Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 "$base/health" | Out-Null; $up = $true; break } catch { Start-Sleep 2 }
}
if (-not $up) { "Backend    $base/health        NOT RESPONDING - check its window"; exit 1 }

# Route-registration check: no credentials are sent, so a registered route answers 401; a missing one answers 404.
$code = 0
try { Invoke-WebRequest -UseBasicParsing -TimeoutSec 5 "$base/api/reports/security-summary?days=1&format=csv" | Out-Null; $code = 200 }
catch { if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode } }
if ($code -eq 404) { "Backend    $base  UP, but /api/reports is NOT registered (404). Is this checkout up to date?"; exit 1 }
"Backend    $base/health        UP  (database $DemoDb; /api/reports registered, unauthenticated -> $code)"
