<#
.SYNOPSIS
  Restarts only the AI engine window of a running demo (for example after showing the engine-outage behaviour in
  Demo C). The backend, frontend, parser and open dashboards keep running; the backend's circuit breaker notices
  the engine is back by itself.

.DESCRIPTION
  Uses the same command, demo Q-table and backend\.env as scripts\demo\start-demo.ps1. Stops an existing
  "SentinelAI-demo: AI engine" window first. Secrets stay in backend\.env and never appear on a command line.

.PARAMETER DeceptionV2
  Persona policy v2 mode for the engine (docs/PERSONA_POLICY_V2.md): off | shadow | active. Unset: the engine's
  default (shadow). "active" is the promotion step, only after ai-engine\evaluation\v2_readiness.py reports READY
  and the owner approves; "shadow" is the rollback.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\demo\restart-engine.ps1
#>
param(
  [ValidateSet("", "off", "shadow", "active")][string]$DeceptionV2 = ""
)
$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$StateDir = Join-Path $env:USERPROFILE ".sentinelai\demo"

Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" |
  Where-Object { $_.CommandLine -like "*SentinelAI-demo: AI engine*" } |
  ForEach-Object { taskkill /PID $_.ProcessId /T /F | Out-Null; "Stopped the old engine window (pid $($_.ProcessId))" }
Start-Sleep 1
if (Get-NetTCPConnection -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue) {
  throw "Port 8000 is still in use by a process this script did not start. Stop it first."
}

$v2 = if ($DeceptionV2) { "`$env:DECEPTION_V2='$DeceptionV2'; " } else { "" }
$command = "`$host.UI.RawUI.WindowTitle='SentinelAI-demo: AI engine :8000'; $v2`$env:Q_TABLE_PATH='$StateDir\q_table.json'; " +
  "Set-Location '$Root\ai-engine'; .\.venv\Scripts\python.exe -m uvicorn inference.main:app --host 127.0.0.1 --port 8000 --env-file ..\backend\.env"
Start-Process powershell -ArgumentList '-NoExit', '-ExecutionPolicy', 'Bypass', '-Command', $command | Out-Null

$deadline = (Get-Date).AddSeconds(60)
while ((Get-Date) -lt $deadline) {
  try { Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 http://127.0.0.1:8000/ready | Out-Null; "AI engine  http://127.0.0.1:8000/ready        UP  (persona policy v2: $(if ($DeceptionV2) { $DeceptionV2 } else { 'default (shadow)' }))"; exit 0 } catch { Start-Sleep 2 }
}
"AI engine  http://127.0.0.1:8000/ready        NOT RESPONDING - check its window"
exit 1
