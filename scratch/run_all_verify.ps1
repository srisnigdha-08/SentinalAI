param(
  [string]$OutputPath = ""
)

if (-not $OutputPath) {
  $ts = Get-Date -Format "yyyyMMdd_HHmmss"
  $OutputPath = Join-Path $PSScriptRoot "evidence\verify_run_$ts.txt"
}
$transcriptPath = $OutputPath
Start-Transcript -Path $transcriptPath -Force

# Credentials are never stored here: set VERIFY_ADMIN_PASSWORD, VERIFY_ANALYST_PASSWORD,
# VERIFY_VIEWER_PASSWORD and HONEYPOT_API_KEY in this shell before running.
foreach ($name in @("VERIFY_ADMIN_PASSWORD", "VERIFY_ANALYST_PASSWORD", "VERIFY_VIEWER_PASSWORD", "HONEYPOT_API_KEY")) {
  if (-not [Environment]::GetEnvironmentVariable($name)) {
    Write-Error "$name is not set; refusing to run."
    Stop-Transcript | Out-Null
    exit 1
  }
}
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
