<#
.SYNOPSIS
  Shared helpers for the demo scripts (dot-source: . "$PSScriptRoot\demo-common.ps1"). Read-only: nothing here
  starts, stops or changes anything.

  Why the backend URL is not http://localhost:5000: the demo backend listens only on the Windows host address
  that WSL sees (the WSL gateway, e.g. 172.29.32.1), so the Cowrie blocker inside WSL can reach its deny-list.
  Nothing listens on 127.0.0.1:5000, so a browser on http://localhost:5000 gets ERR_CONNECTION_REFUSED even
  while the backend is healthy. The dashboard is http://localhost:3000; it proxies /api to the backend.
#>

function Get-DemoWinIp([string]$Distro = "Ubuntu") {
  # The WSL gateway as seen from WSL (same value start-demo.ps1 passes to the backend as HOST)
  $ip = ((wsl -d $Distro -- ip route show default) -split ' ')[2]
  if (-not $ip) {
    # WSL not answering: fall back to the Windows side of the WSL adapter
    $ip = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.InterfaceAlias -like 'vEthernet (WSL*' } | Select-Object -First 1).IPAddress
  }
  return $ip
}

# HTTP status code of a GET (0 = no connection). Unlike Invoke-WebRequest, a 503 is a result, not "down".
function Get-HttpCode([string]$Url, [int]$TimeoutSec = 3) {
  try { return [int](Invoke-WebRequest -UseBasicParsing -TimeoutSec $TimeoutSec $Url).StatusCode }
  catch {
    if ($_.Exception.Response) { return [int]$_.Exception.Response.StatusCode }
    return 0
  }
}

# Body of /health/ready as an object, or $null (no connection / not JSON). 503 bodies are read too.
function Get-BackendReadiness([string]$Base) {
  try { return Invoke-RestMethod -TimeoutSec 4 "$Base/health/ready" }
  catch {
    $r = $_.Exception.Response
    if (-not $r) { return $null }
    try {
      $reader = New-Object System.IO.StreamReader($r.GetResponseStream())
      return ($reader.ReadToEnd() | ConvertFrom-Json)
    } catch { return $null }
  }
}

# Open demo windows (the PowerShell windows start-demo.ps1 opens), optionally only the ones whose title matches.
function Get-DemoWindows([string]$Like = "*") {
  Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" |
    Where-Object { $_.CommandLine -like "*SentinelAI-demo:*" -and $_.CommandLine -like "*$Like*" }
}

# The process that runs inside a demo window (node / python), or $null when it has exited (crashed or stopped).
function Get-DemoChild($Window, [string]$Name) {
  Get-CimInstance Win32_Process -Filter "ParentProcessId=$($Window.ProcessId) AND Name='$Name'" | Select-Object -First 1
}

# Who listens on a port, on which address (empty when nobody does).
function Get-PortOwners([int]$Port) {
  Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue | ForEach-Object {
    $p = Get-CimInstance Win32_Process -Filter "ProcessId=$($_.OwningProcess)"
    [pscustomobject]@{ Address = $_.LocalAddress; Pid = $_.OwningProcess; Name = $p.Name; Since = $p.CreationDate }
  }
}

$LocalhostNote = "http://localhost:5000 is NOT served (connection refused is expected): the demo backend listens only on the WSL gateway address. Use the dashboard at http://localhost:3000."
