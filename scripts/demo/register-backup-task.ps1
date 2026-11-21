<#
.SYNOPSIS
  Registers (or removes) two Windows scheduled tasks for the local SentinelAI database:
    "SentinelAI daily backup"  every day at 02:00   -> backup-local-db.cjs backup --db <DemoDb> --keep <Keep>
    "SentinelAI restore drill" monthly, day 1 03:00  -> backup-local-db.cjs drill  --backup <newest backup>

.DESCRIPTION
  Runs as the current user, only when the user is logged on (no stored password), and never elevates.
  Output of each run is appended to %USERPROFILE%\.sentinelai\backups\backup.log.
  The drill restores into a throwaway database named sentinel-restore-check-<UTC>, compares it, and drops it.
  For the Compose replica set use scripts/deploy/db_backup.cjs (encrypted, oplog-consistent) from cron instead.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\demo\register-backup-task.ps1
  powershell -ExecutionPolicy Bypass -File scripts\demo\register-backup-task.ps1 -Remove
#>
param(
  [string]$DemoDb = "sentinel-demo",
  [ValidateRange(1, 365)][int]$Keep = 7,
  [string]$At = "02:00",
  [switch]$Remove
)
$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$Script = Join-Path $Root "scripts\demo\backup-local-db.cjs"
$Out = Join-Path $env:USERPROFILE ".sentinelai\backups"
$Log = Join-Path $Out "backup.log"
$Names = @("SentinelAI daily backup", "SentinelAI restore drill")

if ($Remove) {
  foreach ($n in $Names) {
    if (Get-ScheduledTask -TaskName $n -ErrorAction SilentlyContinue) { Unregister-ScheduledTask -TaskName $n -Confirm:$false; "Removed '$n'" }
  }
  return
}
if ($DemoDb -notmatch '^[A-Za-z0-9_-]{1,63}$') { throw "Invalid database name: $DemoDb" }
$node = (Get-Command node -ErrorAction Stop).Source
New-Item -ItemType Directory -Force $Out | Out-Null

$backupCmd = "& '$node' '$Script' backup --db '$DemoDb' --keep $Keep --out '$Out' *>> '$Log'"
$drillCmd = "`$b = Get-ChildItem '$Out' -Directory | Where-Object Name -match '^$DemoDb-\d{8}T\d{9}Z$' | Sort-Object Name | Select-Object -Last 1; " +
  "if (`$b) { & '$node' '$Script' drill --backup `$b.FullName *>> '$Log' } else { 'No backup to drill' *>> '$Log' }"

$principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 1) -DontStopIfGoingOnBatteries -AllowStartIfOnBatteries
$daily = New-ScheduledTaskTrigger -Daily -At $At
# Monthly triggers are not exposed by New-ScheduledTaskTrigger; a 4-weekly trigger on Sunday is the closest built-in.
$monthly = New-ScheduledTaskTrigger -Weekly -WeeksInterval 4 -DaysOfWeek Sunday -At "03:00"

foreach ($t in @(
    @{ Name = $Names[0]; Cmd = $backupCmd; Trigger = $daily },
    @{ Name = $Names[1]; Cmd = $drillCmd; Trigger = $monthly })) {
  $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument ("-NoProfile -ExecutionPolicy Bypass -Command `"" + $t.Cmd.Replace('"', '\"') + "`"")
  Register-ScheduledTask -TaskName $t.Name -Action $action -Trigger $t.Trigger -Principal $principal -Settings $settings -Force | Out-Null
  "Registered '$($t.Name)'"
}
"Backups: $Out (newest $Keep kept). Log: $Log"
"Run one now:  Start-ScheduledTask -TaskName '$($Names[0])'"
