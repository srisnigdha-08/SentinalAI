<#
.SYNOPSIS
  Stops the SentinelAI demo windows opened by start-demo.ps1 (engine, backend, frontend, parser).
  Anything else listening on 8000/5000/3000 is reported, not killed, unless -Force is given.
#>
param([switch]$Force)

$windows = Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" |
  Where-Object { $_.CommandLine -like "*SentinelAI-demo:*" }
foreach ($w in $windows) {
  taskkill /PID $w.ProcessId /T /F | Out-Null
  "Stopped demo window (pid $($w.ProcessId))"
}
Start-Sleep 2
foreach ($port in 8000, 5000, 3000) {
  $c = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
  if (-not $c) { continue }
  $p = Get-CimInstance Win32_Process -Filter "ProcessId=$($c.OwningProcess)"
  if ($Force) {
    taskkill /PID $p.ProcessId /T /F | Out-Null
    "Port $port was still in use by $($p.Name) (pid $($p.ProcessId)): stopped (-Force)"
  } else {
    "Port $port is still in use by $($p.Name) (pid $($p.ProcessId)), not started by start-demo.ps1. Stop it yourself or re-run with -Force."
  }
}
