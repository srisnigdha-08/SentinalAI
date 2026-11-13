<#
.SYNOPSIS
  Read-only status of the SentinelAI demo: which services answer, on which address, and why one does not.
  Starts, stops and changes nothing; sends no credentials.

.DESCRIPTION
  Checks, in order: MongoDB service, AI engine (http://127.0.0.1:8000/ready), backend liveness and readiness on the
  WSL gateway address (http://<gateway>:5000/health/live and /health/ready), frontend (http://localhost:3000),
  the demo windows start-demo.ps1 opened and whether their process is still running.

  Expected and NOT an error: http://localhost:5000 is refused. The demo backend listens only on the WSL gateway
  address so the Cowrie blocker inside WSL can reach it. Open the dashboard at http://localhost:3000.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\demo\status-demo.ps1
#>
param([string]$Distro = "Ubuntu")
$ErrorActionPreference = "Continue"
. (Join-Path $PSScriptRoot "demo-common.ps1")

$problems = 0
function Line($name, $state, $detail = "") { "{0,-12} {1,-14} {2}" -f $name, $state, $detail }

$mongo = (Get-Service MongoDB -ErrorAction SilentlyContinue).Status
if ($mongo -eq "Running") { Line "MongoDB" "RUNNING" "service MongoDB" } else { $problems++; Line "MongoDB" "NOT RUNNING" "Start-Service MongoDB (as administrator)" }

$WinIp = Get-DemoWinIp $Distro
$Backend = if ($WinIp) { "http://${WinIp}:5000" } else { $null }

$engineCode = Get-HttpCode "http://127.0.0.1:8000/ready"
if ($engineCode -eq 200) { Line "AI engine" "READY" "http://127.0.0.1:8000" }
else {
  $problems++
  $owner = @(Get-PortOwners 8000) | Select-Object -First 1
  Line "AI engine" $(if ($engineCode) { "HTTP $engineCode" } else { "DOWN" }) $(if ($owner) { "port 8000 held by $($owner.Name) pid $($owner.Pid)" } else { "nothing listens on 8000" })
}

if (-not $Backend) { $problems++; Line "Backend" "UNKNOWN" "could not determine the WSL gateway address (is WSL $Distro running?)" }
elseif ((Get-HttpCode "$Backend/health/live") -eq 200) {
  $ready = Get-BackendReadiness $Backend
  $deps = if ($ready.dependencies) { "database $($ready.dependencies.database), AI engine $($ready.dependencies.aiEngine), revocation $($ready.dependencies.revocation)" } else { "" }
  if ($ready.status -eq 'unavailable') { $problems++ }
  Line "Backend" $(if ($ready.status) { $ready.status.ToUpper() } else { "UP" }) "$Backend  ($deps)"
} else {
  $problems++
  $owners = @(Get-PortOwners 5000)
  $detail = if ($owners.Count) { "port 5000 is held by " + (($owners | ForEach-Object { "$($_.Name) pid $($_.Pid) on $($_.Address)" }) -join '; ') + " - not the demo address $WinIp?" } else { "nothing listens on port 5000" }
  Line "Backend" "DOWN" "$Backend  ($detail)"
}

if ((Get-HttpCode "http://localhost:3000") -eq 200) { Line "Frontend" "UP" "http://localhost:3000  (open this one)" } else { $problems++; Line "Frontend" "DOWN" "http://localhost:3000" }

""
$windows = @(Get-DemoWindows)
if (-not $windows.Count) { "Demo windows: none open (start with scripts\demo\start-demo.ps1)" }
foreach ($w in $windows) {
  $title = ([regex]::Match($w.CommandLine, "SentinelAI-demo: ([^']*)")).Groups[1].Value
  $childName = if ($title -like "Backend*") { "node.exe" } elseif ($title -like "AI engine*" -or $title -like "Cowrie*") { "python.exe" } else { $null }
  $state = if (-not $childName) { "open" } elseif (Get-DemoChild $w $childName) { "running" } else { "EXITED - read the error in this window" }
  "  window pid {0,-7} {1,-34} {2}" -f $w.ProcessId, $title, $state
}

""
$LocalhostNote
if ($problems) { exit 1 }
