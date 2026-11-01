<#
.SYNOPSIS
  Clears demo activity from the demo database so a rehearsal starts empty. Keeps users, login sessions and
  settings (auto-block stays as you left it). Refuses to touch sentinel-db.

.DESCRIPTION
  Deletes: threats, alerts, AI predictions, blocked IPs, containment actions, honeypot sessions, campaigns,
  training samples, audit logs. With -ResetQTable it also deletes the demo Q-table so the next score starts
  from the synthetic seed again. Run it while the backend is stopped or idle; the Cowrie blocker picks up the
  emptied deny-list within 2 seconds.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\demo\reset-demo-db.ps1
#>
param(
  [string]$DemoDb = "sentinel-demo",
  [switch]$ResetQTable
)
$ErrorActionPreference = "Stop"
if ($DemoDb -eq "sentinel-db") { throw "Refusing to reset sentinel-db (your real data). Use a demo database name." }

$collections = "threatlogs", "alerts", "aipredictions", "blockedips", "containmentactions", "honeypotsessions",
               "campaigns", "trainingsamples", "auditlogs"
$list = ($collections | ForEach-Object { "'$_'" }) -join ","
$js = "[$list].forEach(c => { const n = db.getCollection(c).deleteMany({}).deletedCount; print(c.padEnd(20) + ' removed ' + n) }); print('kept users: ' + db.users.countDocuments() + ', settings: ' + db.systemsettings.countDocuments())"
mongosh --quiet "mongodb://127.0.0.1:27017/$DemoDb" --eval $js

if ($ResetQTable) {
  $q = Join-Path $env:USERPROFILE ".sentinelai\demo\q_table.json"
  if (Test-Path $q) { Remove-Item $q; "Demo Q-table removed (restart the AI engine; it re-seeds on the next score)" }
}
