<#
.SYNOPSIS
  Starts the SentinelAI demo stack on Windows: AI engine (:8000), backend (:5000), frontend (:3000) and the
  Cowrie log parser, each in its own PowerShell window. Cowrie itself runs in WSL (scripts/demo/cowrie-demo-mode.sh).

.DESCRIPTION
  - Uses a separate MongoDB database (default "sentinel-demo"), so sentinel-db is never written to.
  - Uses a separate Q-table (%USERPROFILE%\.sentinelai\demo\q_table.json), seeded from models/q_table.json.
  - Binds the backend to the Windows host address that WSL sees (the WSL default gateway), so the Cowrie
    blocker inside WSL can read the deny-list. The frontend proxies to that address.
  - Secrets are read from backend\.env inside each service window; they never appear on a command line.
  - Containment stays on the mock adapter: nothing here enables real firewall enforcement.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\demo\start-demo.ps1
#>
param(
  [string]$DemoDb = "sentinel-demo",
  [string]$Distro = "Ubuntu",
  # Persona policy v2 mode (docs/PERSONA_POLICY_V2.md); unset = engine default (shadow). Never "active" before READY.
  [ValidateSet("", "off", "shadow", "active")][string]$DeceptionV2 = ""
)
$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$EnvFile = Join-Path $Root "backend\.env"
if (-not (Test-Path $EnvFile)) { throw "backend\.env not found at $EnvFile" }

foreach ($port in 8000, 5000, 3000) {
  if (Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue) {
    throw "Port $port is already in use. Run scripts\demo\stop-demo.ps1 (or stop that service) first."
  }
}
if ((Get-Service MongoDB -ErrorAction SilentlyContinue).Status -ne "Running") { throw "MongoDB service is not running (Start-Service MongoDB)." }

$WinIp = ((wsl -d $Distro -- ip route show default) -split ' ')[2]
$WslIp = ((wsl -d $Distro -- hostname -I) -split ' ')[0]
$WslHome = (wsl -d $Distro -- wslpath -w '~').Trim()
if (-not $WinIp -or -not $WslHome) { throw "Could not query WSL ($Distro). Is it installed and running?" }
$CowrieLog = "$WslHome\sentinelai-cowrie-test\cowrie\var\log\cowrie\cowrie.json"
$CowrieCfg = "$WslHome\sentinelai-cowrie-test\cowrie\etc\cowrie.cfg"
$StateDir = Join-Path $env:USERPROFILE ".sentinelai\demo"
New-Item -ItemType Directory -Force $StateDir | Out-Null

# Reads one key from backend\.env inside the service window (keeps it off command lines and out of this console).
$ReadKey = "function K(`$n){ (Select-String -Path '$EnvFile' -Pattern ('^' + `$n + '=(.*)$') | Select-Object -First 1).Matches[0].Groups[1].Value.Trim() }"

function Start-Window($title, $command) {
  $full = "`$host.UI.RawUI.WindowTitle='SentinelAI-demo: $title'; $ReadKey; $command"
  Start-Process powershell -ArgumentList '-NoExit', '-ExecutionPolicy', 'Bypass', '-Command', $full | Out-Null
}

$V2Env = if ($DeceptionV2) { "`$env:DECEPTION_V2='$DeceptionV2'; " } else { "" }
Start-Window "AI engine :8000" "$V2Env`$env:Q_TABLE_PATH='$StateDir\q_table.json'; Set-Location '$Root\ai-engine'; .\.venv\Scripts\python.exe -m uvicorn inference.main:app --host 127.0.0.1 --port 8000 --env-file ..\backend\.env"
Start-Window "Backend :5000 ($DemoDb)" "`$env:HOST='$WinIp'; `$env:MONGO_URI='mongodb://127.0.0.1:27017/$DemoDb'; Set-Location '$Root\backend'; node server.js"
Start-Window "Frontend :3000" "`$env:SENTINEL_DEV_API_PROXY='http://${WinIp}:5000'; Set-Location '$Root\frontend'; npm run dev"
Start-Window "Cowrie parser" "`$env:HONEYPOT_API_KEY=(K 'HONEYPOT_API_KEY'); `$env:SENTINEL_API='http://${WinIp}:5000/api'; `$env:PARSER_STATE_DIR='$StateDir\parser-state'; `$env:COWRIE_CFG='$CowrieCfg'; & '$Root\ai-engine\.venv\Scripts\python.exe' '$Root\honeypot\parsers\log_parser.py' --live --log '$CowrieLog'"

Write-Host "Waiting for services (up to 90 s)..."
$checks = [ordered]@{
  "AI engine  http://127.0.0.1:8000/ready" = "http://127.0.0.1:8000/ready"
  "Backend    http://${WinIp}:5000/health" = "http://${WinIp}:5000/health"
  "Frontend   http://localhost:3000"      = "http://localhost:3000"
}
$deadline = (Get-Date).AddSeconds(90)
$status = @{}
while ((Get-Date) -lt $deadline -and $status.Count -lt $checks.Count) {
  foreach ($name in $checks.Keys) {
    if ($status.ContainsKey($name)) { continue }
    try { Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 $checks[$name] | Out-Null; $status[$name] = "UP" } catch { }
  }
  Start-Sleep 2
}
foreach ($name in $checks.Keys) { "{0,-45} {1}" -f $name, ($(if ($status[$name]) { "UP" } else { "NOT RESPONDING - check its window" })) }
# WSL addresses change after a reboot: write them where the demo console can load them (no secrets in here).
$EnvScript = Join-Path $StateDir "demo-env.ps1"
@"
# Written by scripts\demo\start-demo.ps1 at $(Get-Date -Format s). Load with:  . `$env:USERPROFILE\.sentinelai\demo\demo-env.ps1
`$env:SENTINEL_HONEYPOT_IP = '$WslIp'                    # Cowrie in WSL (after cowrie-demo-mode.sh on)
`$env:SENTINEL_BACKEND_URL = 'http://${WinIp}:5000'      # used by ai-engine\demo\replay_cicids.py --target backend
"SentinelAI demo: honeypot `$env:SENTINEL_HONEYPOT_IP, backend `$env:SENTINEL_BACKEND_URL"
"@ | Set-Content -Encoding utf8 $EnvScript

""
"Demo database : $DemoDb   (sentinel-db untouched)"
"Q-table       : $StateDir\q_table.json"
"Honeypot (WSL): $WslIp    Windows host as seen from WSL: $WinIp"
"Next, in WSL  : bash scripts/demo/cowrie-demo-mode.sh on"
"Demo console  : . `$env:USERPROFILE\.sentinelai\demo\demo-env.ps1   (sets SENTINEL_HONEYPOT_IP and SENTINEL_BACKEND_URL)"
"Dashboard     : http://localhost:3000/login"
