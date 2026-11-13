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

  After the restart it checks that the backend is live (/health/live), reports its readiness (/health/ready:
  database, AI engine, revocation) and that the API routes are registered: an unauthenticated request to
  /api/reports/security-summary must be refused (401), not reported missing (404). The strict /health is not used:
  it answers 503 whenever the AI engine is down, which made a running backend look dead.

  The backend listens only on the WSL gateway address, never on 127.0.0.1: http://localhost:5000 is refused by
  design. The dashboard is http://localhost:3000.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\demo\restart-backend.ps1
#>
param(
  [string]$DemoDb = "sentinel-demo",
  [string]$Distro = "Ubuntu"
)
$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
. (Join-Path $PSScriptRoot "demo-common.ps1")

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
  if ((Get-HttpCode "$base/health/live") -eq 200) { $up = $true; break }
  Start-Sleep 2
}
if (-not $up) {
  $window = Get-DemoWindows "Backend :5000" | Select-Object -First 1
  $node = if ($window) { Get-DemoChild $window "node.exe" }
  $why = if (-not $window) { "its window is gone" } elseif (-not $node) { "node exited - read the [Startup] / MongoDB error in the new 'Backend :5000' window" } else { "node is running (pid $($node.ProcessId)) but not answering - see its window" }
  "Backend    $base/health/live   NOT RESPONDING ($why)"
  exit 1
}

# Route-registration check: no credentials are sent, so a registered route answers 401; a missing one answers 404.
$code = Get-HttpCode "$base/api/reports/security-summary?days=1&format=csv" 5
if ($code -eq 404) { "Backend    $base  UP, but /api/reports is NOT registered (404). Is this checkout up to date?"; exit 1 }
$ready = Get-BackendReadiness $base
$deps = if ($ready.dependencies) { "database $($ready.dependencies.database), AI engine $($ready.dependencies.aiEngine)" } else { "readiness unknown" }
"Backend    $base   $(if ($ready.status) { $ready.status.ToUpper() } else { 'UP' })  ($deps; database $DemoDb; /api/reports registered, unauthenticated -> $code)"
"           $LocalhostNote"
if ($ready.status -eq 'unavailable') { exit 1 }
