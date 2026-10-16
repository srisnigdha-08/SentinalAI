<#
.SYNOPSIS
    SentinelAI Isolated Windows VM Firewall Verification Runner
.DESCRIPTION
    Runs real Windows Firewall adapter verification ONLY inside a dedicated, isolated Windows VM.
    Enforces fail-closed safety checks, target address restrictions (RFC 5737 TEST-NET-1),
    and pre/post rule inventory reconciliation.
.PARAMETER ConfirmExecution
    Switch parameter confirming that the operator explicitly authorizes netsh rule mutation in this VM.
#>

[CmdletBinding()]
param(
    [switch]$ConfirmExecution
)

$ErrorActionPreference = "Stop"

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  SentinelAI Isolated Real-Windows-Firewall Test Runner          " -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

# 1. Environment Detection & Fail-Closed Guard
$MarkerFile = "C:\sentinelai_vm_marker.txt"
$EnvMarker = $env:SENTINELAI_ISOLATED_TEST_VM

if ($EnvMarker -ne "true" -or (-not (Test-Path $MarkerFile))) {
    Write-Host "`n[FATAL ERROR] Real Windows Firewall tests are STRICTLY PROHIBITED on host workstations!" -ForegroundColor Red
    Write-Host "Precondition failed: SENTINELAI_ISOLATED_TEST_VM is not 'true' or $MarkerFile is missing." -ForegroundColor Yellow
    Write-Host "To execute in an isolated VM:" -ForegroundColor Yellow
    Write-Host "  1. Provision a dedicated disposable Windows 11 / Server VM." -ForegroundColor Yellow
    Write-Host "  2. Create marker file: New-Item -Path 'C:\sentinelai_vm_marker.txt' -ItemType File" -ForegroundColor Yellow
    Write-Host "  3. Set environment: `$env:SENTINELAI_ISOLATED_TEST_VM = 'true'" -ForegroundColor Yellow
    Write-Host "  4. Run this script as Administrator with -ConfirmExecution" -ForegroundColor Yellow
    exit 1
}

# 2. Administrative Privilege Check
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) {
    Write-Host "`n[FATAL ERROR] Elevated Administrator privileges are required to mutate Windows Firewall rules." -ForegroundColor Red
    exit 1
}

# 3. Explicit Operator Confirmation Gate
if (-not $ConfirmExecution) {
    Write-Host "`n[CONFIRMATION REQUIRED] Pass -ConfirmExecution to authorize test rule mutations." -ForegroundColor Yellow
    exit 2
}

Write-Host "`n[PASSED] Isolated VM environment and Administrator privileges verified." -ForegroundColor Green

# 4. Pre-Test Rule Inventory
$PreRules = Get-NetFirewallRule -DisplayName "SentinelAI-VMTest-*" -ErrorAction SilentlyContinue
$PreCount = @($PreRules).Count
$preColor = if ($PreCount -eq 0) { "Green" } else { "Yellow" }
Write-Host "Existing SentinelAI-VMTest rules: $PreCount" -ForegroundColor $preColor

if ($PreCount -gt 0) {
    Write-Host "Cleaning up leftover test rules before starting..." -ForegroundColor Yellow
    Get-NetFirewallRule -DisplayName "SentinelAI-VMTest-*" | Remove-NetFirewallRule
}

# 5. Execute Isolated Node.js Adapter Test
Write-Host "`n[Step 2] Executing WindowsFirewallAdapter against RFC 5737 TEST-NET-1 (192.0.2.100)..." -ForegroundColor White
$env:ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT = "true"

node -e "
const WindowsFirewallAdapter = require('./backend/services/containment/WindowsFirewallAdapter');
const { assertSafeTestTarget, SAFE_TEST_TARGET } = require('./backend/tests/helpers/vmFirewallHarness');

(async () => {
  try {
    assertSafeTestTarget(SAFE_TEST_TARGET);
    const adapter = new WindowsFirewallAdapter({ enabled: true });
    const ruleName = 'SentinelAI-VMTest-Verification-01';

    console.log('Applying test rule: ' + ruleName);
    const applyResult = await adapter.applyRule({
      containmentId: 'vm-verify-01',
      target: SAFE_TEST_TARGET,
      ruleName: ruleName
    });
    console.log('Apply Result:', applyResult.success);

    console.log('Verifying test rule exists...');
    const verifyResult = await adapter.verifyRule({ ruleName: ruleName });
    console.log('Verify Result:', verifyResult.exists);

    console.log('Removing test rule...');
    const removeResult = await adapter.removeRule({ ruleName: ruleName });
    console.log('Remove Result:', removeResult.success);

    process.exit(applyResult.success && verifyResult.exists && removeResult.success ? 0 : 1);
  } catch (err) {
    console.error('Test Execution Error:', err.message);
    process.exit(1);
  }
})();
"

$NodeExitCode = $LASTEXITCODE

# 6. Post-Test Rule Inventory Reconciliation & Teardown Verification
Write-Host "`n[Step 3] Verifying teardown and post-test rule inventory..." -ForegroundColor White
$PostRules = Get-NetFirewallRule -DisplayName "SentinelAI-VMTest-*" -ErrorAction SilentlyContinue
$PostCount = @($PostRules).Count

if ($PostCount -eq 0 -and $NodeExitCode -eq 0) {
    Write-Host "`n=================================================================" -ForegroundColor Green
    Write-Host "  ISOLATED VM TEST COMPLETED SUCCESSFULLY (Zero Leftover Rules)   " -ForegroundColor Green
    Write-Host "=================================================================" -ForegroundColor Green
    exit 0
} else {
    Write-Host "`n[WARNING] Post-test inventory found $PostCount leftover rules or test failed with exit code $NodeExitCode!" -ForegroundColor Red
    if ($PostCount -gt 0) {
        Write-Host "Performing emergency cleanup..." -ForegroundColor Yellow
        Get-NetFirewallRule -DisplayName "SentinelAI-VMTest-*" | Remove-NetFirewallRule
    }
    exit 1
}
