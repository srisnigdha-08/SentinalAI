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
  [ValidateSet("", "off", "shadow", "active")][string]$DeceptionV2 = "",
  # How long to wait for every service (the AI engine loads its models first; allow for a cold start)
  [int]$TimeoutSec = 120,
  # Q-table copy, parser state and demo-env.ps1 live here. Default: %USERPROFILE%\.sentinelai\demo. Point it at a
  # scratch folder (with -DemoDb <scratch db> and -NoParser) to rehearse the start-up without touching demo state.
  [string]$StateDir = "",
  # Do not start the live Cowrie log parser (it ingests the WSL Cowrie log into $DemoDb)
  [switch]$NoParser
)
$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
. (Join-Path $PSScriptRoot "demo-common.ps1")
$EnvFile = Join-Path $Root "backend\.env"
if (-not (Test-Path $EnvFile)) { throw "backend\.env not found at $EnvFile" }

# Demo windows from an earlier start that are still open (a service may have crashed and freed its port): starting
# again would open duplicates. Stop them first.
$stale = @(Get-DemoWindows)
# Live Cowrie (its deny-list blocker) and the deception rotator in WSL poll whatever answers on the WSL gateway
# address. A rehearsal backend on a scratch database would hand them its empty deny-list and its own persona
# decisions, so a non-default database or state folder is refused while they run.
if ($DemoDb -ne "sentinel-demo" -or $StateDir) {
  $live = (wsl -d $Distro -- bash -c "pgrep -af 'twistd|deception_rotator' | grep -v pgrep") 2>$null
  if ($live) {
    throw ("Cowrie and/or the deception rotator are running in WSL and poll http://<WSL gateway>:5000. A backend on " +
      "-DemoDb $DemoDb / -StateDir would serve them a scratch deny-list and persona decisions. Stop them first " +
      "(bash scripts/demo/cowrie-demo-mode.sh off, and stop the rotator), or start with the default demo database.")
  }
}
if ($stale.Count) {
  throw ("$($stale.Count) SentinelAI-demo window(s) from an earlier start are still open (pid " +
    (($stale | ForEach-Object ProcessId) -join ', ') + "). Run scripts\demo\status-demo.ps1 to see their state, " +
    "or scripts\demo\stop-demo.ps1 to close them, then start again.")
}

foreach ($port in 8000, 5000, 3000) {
  $c = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($c) {
    $p = Get-CimInstance Win32_Process -Filter "ProcessId=$($c.OwningProcess)"
    $since = if ($p.CreationDate) { " since $($p.CreationDate.ToString('s'))" } else { "" }
    throw ("Port $port is already in use by $($p.Name) (pid $($p.ProcessId))$since. A demo is probably still running. " +
      "After a git pull, restart just the backend with scripts\demo\restart-backend.ps1 (node does not reload code); " +
      "otherwise run scripts\demo\stop-demo.ps1 first.")
  }
}
if ((Get-Service MongoDB -ErrorAction SilentlyContinue).Status -ne "Running") { throw "MongoDB service is not running (Start-Service MongoDB)." }

$WinIp = ((wsl -d $Distro -- ip route show default) -split ' ')[2]
$WslIp = ((wsl -d $Distro -- hostname -I) -split ' ')[0]
$WslHome = (wsl -d $Distro -- wslpath -w '~').Trim()
if (-not $WinIp -or -not $WslHome) { throw "Could not query WSL ($Distro). Is it installed and running?" }
$CowrieLog = "$WslHome\sentinelai-cowrie-test\cowrie\var\log\cowrie\cowrie.json"
$CowrieCfg = "$WslHome\sentinelai-cowrie-test\cowrie\etc\cowrie.cfg"
if (-not $StateDir) { $StateDir = Join-Path $env:USERPROFILE ".sentinelai\demo" }
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
if (-not $NoParser) { Start-Window "Cowrie parser" "`$env:HONEYPOT_API_KEY=(K 'HONEYPOT_API_KEY'); `$env:SENTINEL_API='http://${WinIp}:5000/api'; `$env:PARSER_STATE_DIR='$StateDir\parser-state'; `$env:COWRIE_CFG='$CowrieCfg'; & '$Root\ai-engine\.venv\Scripts\python.exe' '$Root\honeypot\parsers\log_parser.py' --live --log '$CowrieLog'" }

$Backend = "http://${WinIp}:5000"
Write-Host "Waiting for services (up to $TimeoutSec s)..."
# Readiness, not just "something answers": the engine's /ready, the backend's /health/live then /health/ready
# (the strict /health answers 503 whenever the AI engine is down, which made a running backend look dead).
$deadline = (Get-Date).AddSeconds($TimeoutSec)
$engine = $false; $live = $false; $frontend = $false
while ((Get-Date) -lt $deadline -and -not ($engine -and $live -and $frontend)) {
  if (-not $engine) { $engine = (Get-HttpCode "http://127.0.0.1:8000/ready") -eq 200 }
  if (-not $live) { $live = (Get-HttpCode "$Backend/health/live") -eq 200 }
  if (-not $frontend) { $frontend = (Get-HttpCode "http://localhost:3000") -eq 200 }
  if (-not ($engine -and $live -and $frontend)) { Start-Sleep 2 }
}
$problems = 0
"{0,-44} {1}" -f "AI engine  http://127.0.0.1:8000/ready", $(if ($engine) { "UP" } else { $problems++; "NOT READY - see its window (models load first; a wrong venv or missing --env-file stops it)" })

if ($live) {
  # One more short wait for the engine-dependent part of readiness to settle
  $ready = Get-BackendReadiness $Backend
  $deps = if ($ready.dependencies) { "database $($ready.dependencies.database), AI engine $($ready.dependencies.aiEngine), revocation $($ready.dependencies.revocation)" } else { "readiness unknown" }
  $state = if ($ready.status) { $ready.status.ToUpper() } else { "UP" }
  if ($ready.status -eq 'unavailable') { $problems++ }
  "{0,-44} {1}" -f "Backend    $Backend/health/ready", "$state ($deps)"
} else {
  $problems++
  $window = Get-DemoWindows "Backend :5000" | Select-Object -First 1
  $node = if ($window) { Get-DemoChild $window "node.exe" }
  $why = if (-not $window) { "its window is gone" }
         elseif (-not $node) { "node exited - read the [Startup] / MongoDB error in the 'Backend :5000' window" }
         else { "node is running (pid $($node.ProcessId)) but not answering on $Backend - see its window" }
  "{0,-44} {1}" -f "Backend    $Backend/health/live", "NOT RESPONDING ($why)"
  $owners = @(Get-PortOwners 5000)
  if ($owners.Count) { $owners | ForEach-Object { "           port 5000 is held by $($_.Name) (pid $($_.Pid)) on $($_.Address)" } }
}
"{0,-44} {1}" -f "Frontend   http://localhost:3000", $(if ($frontend) { "UP" } else { $problems++; "NOT RESPONDING - see its window" })

# Route-registration check (no credentials sent): a registered route answers 401, a missing one 404.
$routeCode = if ($live) { Get-HttpCode "$Backend/api/reports/security-summary?days=1&format=csv" 5 } else { 0 }
if ($routeCode -eq 404) { $problems++ }
"{0,-44} {1}" -f "Backend API routes (/api/reports)", $(if ($routeCode -eq 404) { "MISSING (404) - is this checkout up to date?" } elseif ($routeCode) { "registered ($routeCode without a token)" } else { "not checked (backend not responding)" })
# WSL addresses change after a reboot: write them where the demo console can load them (no secrets in here).
$EnvScript = Join-Path $StateDir "demo-env.ps1"
@"
# Written by scripts\demo\start-demo.ps1 at $(Get-Date -Format s). Load with:  . `$env:USERPROFILE\.sentinelai\demo\demo-env.ps1
`$env:SENTINEL_HONEYPOT_IP = '$WslIp'                    # Cowrie in WSL (after cowrie-demo-mode.sh on)
`$env:SENTINEL_BACKEND_URL = 'http://${WinIp}:5000'      # used by ai-engine\demo\replay_cicids.py --target backend
"SentinelAI demo: honeypot `$env:SENTINEL_HONEYPOT_IP, backend `$env:SENTINEL_BACKEND_URL"
"@ | Set-Content -Encoding utf8 $EnvScript

""
"Dashboard     : http://localhost:3000/login     <- open this in the browser"
"Backend API   : $Backend   (health: $Backend/health/ready)"
"                $LocalhostNote"
"Demo database : $DemoDb   (sentinel-db untouched)"
"Q-table       : $StateDir\q_table.json"
"Honeypot (WSL): $WslIp    Windows host as seen from WSL: $WinIp"
"Next, in WSL  : bash scripts/demo/cowrie-demo-mode.sh on"
"Demo console  : . '$EnvScript'   (sets SENTINEL_HONEYPOT_IP and SENTINEL_BACKEND_URL)"
"Check later   : powershell -ExecutionPolicy Bypass -File scripts\demo\status-demo.ps1"
if ($problems) {
  ""
  "$problems service check(s) failed. The windows stay open so you can read their errors; close them with scripts\demo\stop-demo.ps1."
  exit 1
}
