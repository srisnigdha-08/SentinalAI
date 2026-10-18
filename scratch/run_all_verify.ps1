param(
  [string]$OutputPath = ""
)

if (-not $OutputPath) {
  $ts = Get-Date -Format "yyyyMMdd_HHmmss"
  $OutputPath = Join-Path $PSScriptRoot "evidence\verify_run_$ts.txt"
}
$transcriptPath = $OutputPath
Start-Transcript -Path $transcriptPath -Force

$env:VERIFY_ADMIN_PASSWORD = "Admin@1234"
$env:VERIFY_ANALYST_PASSWORD = "Analyst@1234"
$env:VERIFY_VIEWER_PASSWORD = "Viewer@1234"
$env:HONEYPOT_API_KEY = "b09b49ab1eeff33d1b0fa5f7f721e6d5ea60b0a1c430fec8d00813f13b5ff94e"
$env:MONGO_URI = "mongodb://localhost:27017/sentinel-db"

Write-Host "`n========================================================"
Write-Host "RUNNING SCRIPT 1: scratch/verify_browser_rbac.mjs"
Write-Host "========================================================`n"
& node scratch/verify_browser_rbac.mjs 2>&1 | ForEach-Object { Write-Host $_ }
Write-Host "`n>>> SCRIPT 1 EXIT CODE: $LASTEXITCODE <<<`n"

Write-Host "`n========================================================"
Write-Host "RUNNING SCRIPT 2: scratch/verify_ui_controls.mjs"
Write-Host "========================================================`n"
& node scratch/verify_ui_controls.mjs 2>&1 | ForEach-Object { Write-Host $_ }
Write-Host "`n>>> SCRIPT 2 EXIT CODE: $LASTEXITCODE <<<`n"

Write-Host "`n========================================================"
Write-Host "RUNNING SCRIPT 3: scratch/verify_viewer_audit.mjs"
Write-Host "========================================================`n"
& node scratch/verify_viewer_audit.mjs 2>&1 | ForEach-Object { Write-Host $_ }
Write-Host "`n>>> SCRIPT 3 EXIT CODE: $LASTEXITCODE <<<`n"

Write-Host "`n========================================================"
Write-Host "RUNNING SCRIPT 4: scratch/verify_analyst_feed.mjs"
Write-Host "========================================================`n"
& node scratch/verify_analyst_feed.mjs 2>&1 | ForEach-Object { Write-Host $_ }
Write-Host "`n>>> SCRIPT 4 EXIT CODE: $LASTEXITCODE <<<`n"

Write-Host "`n========================================================"
Write-Host "RUNNING SCRIPT 5: scratch/verify_live_demotion.mjs"
Write-Host "========================================================`n"
& node scratch/verify_live_demotion.mjs 2>&1 | ForEach-Object { Write-Host $_ }
Write-Host "`n>>> SCRIPT 5 EXIT CODE: $LASTEXITCODE <<<`n"

Stop-Transcript
