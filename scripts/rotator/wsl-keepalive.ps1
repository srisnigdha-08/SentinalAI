<#
.SYNOPSIS
  Optional: keeps the WSL distro running so sentinel-rotator.service keeps rotating with no WSL window open.

.DESCRIPTION
  WSL stops a distro shortly after its last wsl.exe process exits. systemd user services inside it, including
  sentinel-rotator.service and the Cowrie it restarts, stop with it, and come back only when WSL next starts.
  This script starts one hidden `wsl.exe -d <distro> --exec sleep infinity` process, which keeps the distro
  running. It changes no Windows setting, scheduled task or startup entry. It writes only a PID file.

    powershell -ExecutionPolicy Bypass -File scripts\rotator\wsl-keepalive.ps1 start
    powershell -ExecutionPolicy Bypass -File scripts\rotator\wsl-keepalive.ps1 status
    powershell -ExecutionPolicy Bypass -File scripts\rotator\wsl-keepalive.ps1 stop

  It does not survive a Windows sign-out or reboot. To make it start at sign-in, you can register it yourself
  (see scripts/rotator/README.md, "Keeping WSL running"). This script never does that.
#>
param(
  [Parameter(Position = 0)][ValidateSet("start", "stop", "status")][string]$Action = "status",
  [string]$Distro = "Ubuntu"
)
$ErrorActionPreference = "Stop"
$StateDir = Join-Path $env:USERPROFILE ".sentinelai"
$PidFile = Join-Path $StateDir "wsl-keepalive.pid"

function Get-Keeper {
  if (-not (Test-Path $PidFile)) { return $null }
  $id = [int](Get-Content $PidFile -Raw).Trim()
  $p = Get-Process -Id $id -ErrorAction SilentlyContinue
  if ($p -and $p.ProcessName -eq "wsl") { return $p }
  return $null
}

function Get-DistroState {
  $raw = (wsl.exe -l -v) -join "`n"
  $line = (($raw -replace "`0", "") -split "`n") | Where-Object { $_ -match "\b$([regex]::Escape($Distro))\b" } | Select-Object -First 1
  if ($line) { return (($line -replace "^\*", "").Trim() -split "\s+")[1] }
  return "unknown"
}

switch ($Action) {
  "start" {
    $k = Get-Keeper
    if ($k) { "keep-alive already running (PID $($k.Id)); $Distro is $(Get-DistroState)"; break }
    New-Item -ItemType Directory -Force $StateDir | Out-Null
    $p = Start-Process -FilePath "wsl.exe" -ArgumentList "-d", $Distro, "--exec", "sleep", "infinity" -WindowStyle Hidden -PassThru
    Set-Content -Path $PidFile -Value $p.Id -Encoding ascii
    Start-Sleep -Seconds 3
    "keep-alive started (PID $($p.Id)); $Distro is $(Get-DistroState)"
  }
  "stop" {
    $k = Get-Keeper
    if ($k) { Stop-Process -Id $k.Id; "keep-alive stopped (PID $($k.Id)); WSL may now stop when idle" }
    else { "keep-alive not running" }
    Remove-Item $PidFile -ErrorAction SilentlyContinue
  }
  "status" {
    $k = Get-Keeper
    "keep-alive : $(if ($k) { "running (PID $($k.Id))" } else { 'not running' })"
    "$Distro     : $(Get-DistroState)"
  }
}
