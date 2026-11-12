<#
.SYNOPSIS
  Optional: keeps the WSL distro running so sentinel-rotator.service keeps rotating with no WSL window open,
  repairs the systemd user manager if a forced WSL restart left it failed, and (only if you ask) registers itself
  to run at your Windows sign-in.

.DESCRIPTION
  WSL stops a distro shortly after its last wsl.exe process exits; sentinel-rotator.service and the Cowrie it
  restarts stop with it. `start` launches one hidden `wsl.exe -d <distro> --exec sleep infinity` (PID file only),
  then checks the distro's systemd user manager: after a forced `wsl --terminate` it can be left failed
  ("Failed to spawn executor: Device or resource busy"), so no user unit starts. In that case it restarts
  user@<uid>.service as the distro's root (WSL-internal; no Windows administrator rights) and reports whether the
  rotator unit came back. It never starts, stops or enables the rotator itself.

    powershell -ExecutionPolicy Bypass -File scripts\rotator\wsl-keepalive.ps1 start
    powershell -ExecutionPolicy Bypass -File scripts\rotator\wsl-keepalive.ps1 status
    powershell -ExecutionPolicy Bypass -File scripts\rotator\wsl-keepalive.ps1 stop

  Sign-in startup (a per-user scheduled task, limited rights, no admin; nothing is registered unless you run it):
    ... wsl-keepalive.ps1 register -DryRun     # show exactly what would be registered
    ... wsl-keepalive.ps1 register             # run `start` at every sign-in of this user
    ... wsl-keepalive.ps1 registration         # is it registered?
    ... wsl-keepalive.ps1 unregister           # remove it (the running keep-alive is left alone; use stop)
#>
param(
  [Parameter(Position = 0)][ValidateSet("start", "stop", "status", "register", "unregister", "registration")][string]$Action = "status",
  [string]$Distro = "Ubuntu",
  [switch]$DryRun
)
$ErrorActionPreference = "Stop"
$StateDir = Join-Path $env:USERPROFILE ".sentinelai"
$PidFile = Join-Path $StateDir "wsl-keepalive.pid"
$TaskName = "SentinelAI WSL keep-alive"

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

function Invoke-Distro([string[]]$Cmd, [switch]$Root) {
  $wslArgs = @("-d", $Distro) + $(if ($Root) { @("-u", "root") } else { @() }) + @("--") + $Cmd
  $out = & wsl.exe @wslArgs 2>&1 | Out-String
  return ($out -replace "`0", "").Trim()
}

function Get-UserManager { Invoke-Distro @("systemctl", "--user", "is-system-running") }

function Show-Services {
  "user mgr   : $(Get-UserManager)"
  "rotator    : $(Invoke-Distro @('systemctl', '--user', 'is-enabled', 'sentinel-rotator')) / $(Invoke-Distro @('systemctl', '--user', 'is-active', 'sentinel-rotator'))"
  # [t]wistd: the pattern must not match this bash -c command line itself
  "cowrie     : $(Invoke-Distro @('bash', '-c', 'pgrep -fc ''[t]wistd.*cowrie'' || true')) process(es)"
}

function Repair-UserManager {
  $state = Get-UserManager
  if ($state -match "^(running|degraded)") { return "user manager $state; nothing to repair" }
  $uid = Invoke-Distro @("id", "-u")
  if ($uid -notmatch "^\d+$") { return "could not read the distro user id ($uid); not repairing" }
  # Root inside the WSL distro only (no Windows elevation): restart the user's systemd manager, then re-check.
  Invoke-Distro -Root @("systemctl", "reset-failed", "user@$uid.service") | Out-Null
  Invoke-Distro -Root @("systemctl", "restart", "user@$uid.service") | Out-Null
  Start-Sleep -Seconds 5
  return "user manager was '$state'; restarted user@$uid.service -> now '$(Get-UserManager)'"
}

switch ($Action) {
  "start" {
    $k = Get-Keeper
    if ($k) { "keep-alive already running (PID $($k.Id)); $Distro is $(Get-DistroState)" }
    else {
      New-Item -ItemType Directory -Force $StateDir | Out-Null
      $p = Start-Process -FilePath "wsl.exe" -ArgumentList "-d", $Distro, "--exec", "sleep", "infinity" -WindowStyle Hidden -PassThru
      Set-Content -Path $PidFile -Value $p.Id -Encoding ascii
      Start-Sleep -Seconds 3
      "keep-alive started (PID $($p.Id)); $Distro is $(Get-DistroState)"
    }
    Repair-UserManager
    Show-Services
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
    if ((Get-DistroState) -eq "Running") { Show-Services }
    "sign-in    : $(if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) { 'registered' } else { 'not registered' })"
  }
  "registration" {
    $t = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($t) { "registered: '$TaskName' ($($t.State)), runs as $($t.Principal.UserId), level $($t.Principal.RunLevel)" } else { "not registered" }
  }
  "register" {
    $script = $MyInvocation.MyCommand.Path
    $arg = "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$script`" start -Distro $Distro"
    $user = "$env:USERDOMAIN\$env:USERNAME"
    if ($DryRun) {
      "would register per-user task '$TaskName':"
      "  trigger  : at sign-in of $user"
      "  action   : powershell.exe $arg"
      "  principal: $user, Interactive logon, RunLevel Limited (no administrator rights)"
      "nothing registered (dry run)"
      break
    }
    $taskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $arg
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $user
    $principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
    Register-ScheduledTask -TaskName $TaskName -Action $taskAction -Trigger $trigger -Principal $principal -Settings $settings `
      -Description "SentinelAI: keep WSL running for sentinel-rotator.service (scripts/rotator/wsl-keepalive.ps1)" | Out-Null
    "registered '$TaskName' for $user (limited rights). Remove with: wsl-keepalive.ps1 unregister"
  }
  "unregister" {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
      Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false; "unregistered '$TaskName' (a running keep-alive is left alone; use stop)"
    } else { "not registered; nothing to do" }
  }
}
