# Samples CPU % and working-set memory of the given process IDs once per second until -Seconds elapse.
# Read-only (Get-Process). CPU % is normalised to the whole machine (all logical processors = 100 %).
# Usage: powershell -File metrics_report\scripts\sample_resources.ps1 -Pids 1234,5678 -Seconds 300 -Out metrics_report\raw\resources.csv
param([int[]]$Pids, [int]$Seconds = 300, [string]$Out = "metrics_report\raw\resources.csv")
$cores = [Environment]::ProcessorCount
"timestamp,pid,name,cpu_percent,working_set_mb,private_mb" | Set-Content -Encoding utf8 $Out
$prev = @{}
foreach ($id in $Pids) { $p = Get-Process -Id $id -ErrorAction SilentlyContinue; if ($p) { $prev[$id] = $p.TotalProcessorTime.TotalSeconds } }
$t0 = Get-Date
for ($i = 0; $i -lt $Seconds; $i++) {
  Start-Sleep -Seconds 1
  $now = Get-Date
  foreach ($id in $Pids) {
    $p = Get-Process -Id $id -ErrorAction SilentlyContinue
    if (-not $p) { continue }
    $cpu = $p.TotalProcessorTime.TotalSeconds
    $pct = [math]::Round((($cpu - $prev[$id]) / 1.0) / $cores * 100, 2)
    $prev[$id] = $cpu
    "{0},{1},{2},{3},{4},{5}" -f $now.ToString("o"), $id, $p.ProcessName, $pct, [math]::Round($p.WorkingSet64 / 1MB, 1), [math]::Round($p.PrivateMemorySize64 / 1MB, 1) | Add-Content -Encoding utf8 $Out
  }
}
