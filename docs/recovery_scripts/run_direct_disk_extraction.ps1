# =============================================================================
# SentinelAI Docker Recovery -- Direct-Disk Extraction Phase
# =============================================================================
# This script extracts MongoDB candidate datasets from docker_data_A3_working.vhdx
# using QEMU SystemRescue with an isolated secondary virtual scratch disk.
#
# Constraints observed:
# 1. Zero writes to source VHDX:
#    - QEMU attaches overlay.qcow2 (copy-on-write overlay)
#    - Backing file is docker_data_A3_working.vhdx (format: vhdx)
#    - Guest Linux mounts /dev/vda as: mount -o ro,noload /dev/vda /mnt/target
#    - Journal replay is explicitly prohibited by 'noload'
# 2. Network isolation: -net none
# 3. Destination: D:\MongoPreservation\
#    - Scratch disk: D:\MongoPreservation\scratch_transfer.raw (1.5 GiB)
#    - Direct block writing to /dev/vdb inside guest
#    - Host extraction via bsdtar (tar.exe)
# 4. Strict verification against source manifests:
#    - deployment_mongo_data_SOURCE.sha256.txt (181 files)
#    - deepguard-platform_mongo_data_SOURCE.sha256.txt (21 files)
# 5. Post-execution verification of working copy hash.
# =============================================================================

$ErrorActionPreference = "Stop"

$WORKING_COPY_PATH   = "D:\DockerInspection\A3\docker_data_A3_working.vhdx"
$BASELINE_SHA256     = "660D98A97461FE44D4B23C72D151F80985BA53010DDA67F03D2C887B82A269CC"
$OVERLAY_PATH        = "C:\RecoveryTools\overlay.qcow2"
$QEMU_EXE            = "C:\RecoveryTools\qemu\qemu-system-x86_64.exe"
$QEMU_IMG            = "C:\RecoveryTools\qemu\qemu-img.exe"
$VMLINUZ_PATH        = "C:\RecoveryTools\sysrescue_boot\vmlinuz"
$INITRD_PATH         = "C:\RecoveryTools\sysrescue_boot\sysresccd.img"
$ISO_PATH            = "C:\RecoveryTools\systemrescue-13.02-amd64.iso"
$PORT                = 4449

$DEST_ROOT           = "D:\MongoPreservation"
$SCRATCH_RAW         = "$DEST_ROOT\scratch_transfer.raw"
$MANIFEST_DIR        = "$DEST_ROOT\manifests"
$LOG_FILE            = "$MANIFEST_DIR\direct_disk_recovery.log"
$TEMP_EXTRACT        = "$DEST_ROOT\temp_extracted"

$PRIMARY_DEST        = "$DEST_ROOT\deployment_mongo_data"
$SECONDARY_DEST      = "$DEST_ROOT\deepguard-platform_mongo_data"

function Log([string]$msg) {
    $ts = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $line = "[$ts] $msg"
    Write-Output $line
    Add-Content -Path $LOG_FILE -Value $line -Encoding UTF8
}

function Halt([string]$msg) {
    Log "ERROR HALT: $msg"
    throw $msg
}

# -----------------------------------------------------------------------------
# Phase 0: Preflight Validations
# -----------------------------------------------------------------------------
Write-Output "============================================================"
Write-Output "PHASE 0: PREFLIGHT VALIDATIONS"
Write-Output "============================================================"

# Ensure destination directories exist
if (-not (Test-Path $MANIFEST_DIR))   { New-Item -ItemType Directory -Path $MANIFEST_DIR -Force | Out-Null }
if (-not (Test-Path $PRIMARY_DEST))   { New-Item -ItemType Directory -Path $PRIMARY_DEST -Force | Out-Null }
if (-not (Test-Path $SECONDARY_DEST)) { New-Item -ItemType Directory -Path $SECONDARY_DEST -Force | Out-Null }

Set-Content -Path $LOG_FILE -Value "=== Direct-Disk Recovery Log Started ===" -Encoding UTF8

# Check Docker processes
$dockerProcs = Get-Process -Name "*docker*" -ErrorAction SilentlyContinue
if ($dockerProcs) {
    Halt "Docker processes detected: $($dockerProcs.Name -join ', '). Stop all Docker processes before proceeding."
}
Log "Preflight: No Docker processes running."

# Check WSL running status
$wslOut = (wsl.exe --list --running 2>&1) | Out-String
if ($wslOut -match "ubuntu|docker") {
    Halt "WSL running distributions detected: $wslOut. Stop all WSL distributions before proceeding."
}
Log "Preflight: No WSL distributions running."

# Check free space on D:
$dDrive = Get-PSDrive D
if ($dDrive.Free -lt 5GB) {
    Halt "Insufficient space on drive D:. Free: $([math]::Round($dDrive.Free/1GB, 2)) GiB, required: >= 5 GiB"
}
Log "Preflight: Drive D: free space is $([math]::Round($dDrive.Free/1GB, 2)) GiB."

# Check required binaries
$requiredPaths = @($WORKING_COPY_PATH, $OVERLAY_PATH, $QEMU_EXE, $QEMU_IMG, $VMLINUZ_PATH, $INITRD_PATH, $ISO_PATH)
foreach ($p in $requiredPaths) {
    if (-not (Test-Path $p)) { Halt "Required file missing: $p" }
}
Log "Preflight: All QEMU binaries and boot images verified."

# Check source manifests exist
$primMan = "$MANIFEST_DIR\deployment_mongo_data_SOURCE.sha256.txt"
$scndMan = "$MANIFEST_DIR\deepguard-platform_mongo_data_SOURCE.sha256.txt"
if (-not (Test-Path $primMan)) { Halt "Primary source manifest missing: $primMan" }
if (-not (Test-Path $scndMan)) { Halt "Secondary source manifest missing: $scndMan" }
Log "Preflight: Existing source manifests confirmed present."

# Validate overlay backing relationship
$overlayInfo = & $QEMU_IMG info $OVERLAY_PATH | Out-String
if ($overlayInfo -notmatch "backing file: .*docker_data_A3_working\.vhdx") {
    Halt "Overlay backing file mismatch! Info: $overlayInfo"
}
Log "Preflight: Overlay backing relationship confirmed: docker_data_A3_working.vhdx (vhdx)."

# -----------------------------------------------------------------------------
# Phase 1: Create 1.5 GiB Raw Scratch Disk
# -----------------------------------------------------------------------------
Write-Output ""
Write-Output "============================================================"
Write-Output "PHASE 1: PREPARING RAW SCRATCH DISK"
Write-Output "============================================================"
Log "Creating scratch transfer file: $SCRATCH_RAW (1.5 GiB)..."
if (Test-Path $SCRATCH_RAW) { Remove-Item $SCRATCH_RAW -Force }

$scratchStream = [System.IO.File]::Create($SCRATCH_RAW)
$scratchStream.SetLength(1610612736) # Exactly 1.5 GiB
$scratchStream.Close()
Log "Scratch disk created successfully. Size: $((Get-Item $SCRATCH_RAW).Length) bytes."

# -----------------------------------------------------------------------------
# Phase 2: Launch QEMU with Dual Drives (Overlay + Scratch)
# -----------------------------------------------------------------------------
Write-Output ""
Write-Output "============================================================"
Write-Output "PHASE 2: BOOTING ISOLATED QEMU RECOVERY ENVIRONMENT"
Write-Output "============================================================"

$qemuArgs = "-m 2048 -smp 2 -kernel `"$VMLINUZ_PATH`" -initrd `"$INITRD_PATH`" -append `"archisobasedir=sysresccd archisolabel=RESCUE1302 nomdlvm console=ttyS0,115200n8`" -cdrom `"$ISO_PATH`" -drive file=`"$OVERLAY_PATH`",format=qcow2,if=virtio -drive file=`"$SCRATCH_RAW`",format=raw,if=virtio -net none -display none -serial tcp:127.0.0.1:${PORT},server=on,wait=off"

Log "Starting QEMU: $QEMU_EXE $qemuArgs"
$qemuProc = Start-Process -FilePath $QEMU_EXE -ArgumentList $qemuArgs -PassThru -NoNewWindow
Start-Sleep -Seconds 2
if ($qemuProc.HasExited) { Halt "QEMU failed to start. ExitCode: $($qemuProc.ExitCode)" }
Log "QEMU running with PID $($qemuProc.Id)."

# Connect to serial TCP socket
$client = [System.Net.Sockets.TcpClient]::new()
$connected = $false
for ($i = 1; $i -le 20; $i++) {
    try {
        $client.Connect("127.0.0.1", $PORT)
        $connected = $true
        break
    } catch {
        Start-Sleep -Seconds 2
    }
}
if (-not $connected) {
    Stop-Process -Id $qemuProc.Id -Force
    Halt "Could not connect to QEMU serial socket on port $PORT after 20 attempts."
}
Log "Connected to QEMU serial console."
$stream = $client.GetStream()
$buf = [byte[]]::new(8192)

function Exec-Guest([string]$cmdStr, [int]$timeoutSec = 180) {
    while ($stream.DataAvailable) { $null = $stream.Read($buf, 0, $buf.Length) }
    $token = "DONE_$(Get-Random -Maximum 999999)"
    $fullCmd = [System.Text.Encoding]::ASCII.GetBytes("$cmdStr; echo $token`n")
    $stream.Write($fullCmd, 0, $fullCmd.Length)
    $out = [System.Text.StringBuilder]::new()
    $dead = (Get-Date).AddSeconds($timeoutSec)
    while ((Get-Date) -lt $dead) {
        Start-Sleep -Milliseconds 200
        while ($stream.DataAvailable) {
            $n = $stream.Read($buf, 0, $buf.Length)
            $out.Append([System.Text.Encoding]::ASCII.GetString($buf, 0, $n)) | Out-Null
        }
        if ($out.ToString() -match [regex]::Escape($token)) { break }
    }
    return ($out.ToString() -replace [regex]::Escape($token), "").Trim()
}

# Wait for root prompt
Log "Awaiting SystemRescue shell prompt (up to 3 min)..."
$promptFound = $false
$dead = (Get-Date).AddMinutes(3)
$acc = [System.Text.StringBuilder]::new()
while ((Get-Date) -lt $dead) {
    Start-Sleep -Milliseconds 300
    while ($stream.DataAvailable) {
        $n = $stream.Read($buf, 0, $buf.Length)
        $acc.Append([System.Text.Encoding]::ASCII.GetString($buf, 0, $n)) | Out-Null
    }
    if ($acc.ToString() -match "root@sysrescue") {
        $promptFound = $true
        break
    }
}
if (-not $promptFound) {
    Stop-Process -Id $qemuProc.Id -Force
    Halt "Timed out waiting for root shell prompt."
}
Log "SystemRescue shell prompt detected."
$null = Exec-Guest "stty -echo" 10

# -----------------------------------------------------------------------------
# Phase 3: Guest Mount and Direct Block Device Writing
# -----------------------------------------------------------------------------
Write-Output ""
Write-Output "============================================================"
Write-Output "PHASE 3: GUEST READ-ONLY MOUNT & DIRECT DISK EXTRACTION"
Write-Output "============================================================"

# Check disks
$blkid = Exec-Guest "blkid" 20
Log "Guest blkid: $blkid"
if ($blkid -notmatch "f0faad04-92bb-4f31-a2f1-0e7a110c4a59") {
    $null = Exec-Guest "poweroff" 10
    Halt "Expected disk UUID not found in blkid."
}

# Verify /dev/vdb exists
$vdbCheck = Exec-Guest "lsblk /dev/vdb" 10
Log "Guest /dev/vdb status: $vdbCheck"

# Mount /dev/vda read-only (ro,noload)
$null = Exec-Guest "mkdir -p /mnt/target" 10
$mountOut = Exec-Guest "mount -o ro,noload /dev/vda /mnt/target" 20
$findmnt = Exec-Guest "findmnt /mnt/target" 10
Log "findmnt /mnt/target: $findmnt"
if ($findmnt -notmatch "\bro\b") {
    $null = Exec-Guest "poweroff" 10
    Halt "Mount verification failed: ro option missing from findmnt output!"
}
Log "Confirmed: /dev/vda mounted strictly read-only with journal replay disabled."

# Verify candidate directories
$chkDirs = Exec-Guest "ls -ld /mnt/target/data/docker/volumes/deployment_mongo_data/_data /mnt/target/data/docker/volumes/deepguard-platform_mongo_data/_data" 15
Log "Candidate directories in guest: $chkDirs"

# Write tar directly to raw block device /dev/vdb
Log "Writing direct tar stream from /mnt/target/data/docker/volumes to /dev/vdb..."
$tarStart = Get-Date
$tarCmd = "tar -cf /dev/vdb -C /mnt/target/data/docker/volumes deployment_mongo_data deepguard-platform_mongo_data"
$tarRes = Exec-Guest $tarCmd 300
Log "Tar command completed in $((Get-Date) - $tarStart). Output: $tarRes"

# Sync and unmount
Log "Flushing disk caches and unmounting /mnt/target..."
$null = Exec-Guest "sync" 30
$null = Exec-Guest "umount /mnt/target" 20
Log "Unmounted /mnt/target cleanly."

# Graceful poweroff
Log "Shutting down QEMU guest..."
$null = Exec-Guest "poweroff" 10
$client.Close()

# Wait for process exit
for ($i = 1; $i -le 30; $i++) {
    if ($qemuProc.HasExited) { break }
    Start-Sleep -Seconds 1
}
if (-not $qemuProc.HasExited) {
    Log "Stopping QEMU process..."
    Stop-Process -Id $qemuProc.Id -Force
}
Log "QEMU guest execution terminated."

# -----------------------------------------------------------------------------
# Phase 4: Host Extraction from Raw Scratch Disk
# -----------------------------------------------------------------------------
Write-Output ""
Write-Output "============================================================"
Write-Output "PHASE 4: EXTRACTING & VERIFYING FILES ON HOST"
Write-Output "============================================================"

if (Test-Path $TEMP_EXTRACT) { Remove-Item $TEMP_EXTRACT -Recurse -Force }
New-Item -ItemType Directory -Path $TEMP_EXTRACT -Force | Out-Null

Log "Extracting tar archive from $SCRATCH_RAW into $TEMP_EXTRACT..."
$extractStart = Get-Date
& "tar.exe" -xf $SCRATCH_RAW -C $TEMP_EXTRACT
Log "Host extraction completed in $((Get-Date) - $extractStart)."

# Move files to final destination directories
Log "Moving extracted candidate directories to final destination..."
$sourcePrim = "$TEMP_EXTRACT\deployment_mongo_data\_data"
$sourceScnd = "$TEMP_EXTRACT\deepguard-platform_mongo_data\_data"

if (-not (Test-Path $sourcePrim)) { Halt "Primary candidate directory not found in extracted tarball: $sourcePrim" }
if (-not (Test-Path $sourceScnd)) { Halt "Secondary candidate directory not found in extracted tarball: $sourceScnd" }

Get-ChildItem -Path $sourcePrim -Force | Copy-Item -Destination $PRIMARY_DEST -Recurse -Force
Get-ChildItem -Path $sourceScnd -Force | Copy-Item -Destination $SECONDARY_DEST -Recurse -Force
Log "Files copied to $PRIMARY_DEST and $SECONDARY_DEST."

# Clean up temp extracted directory and raw scratch file
Remove-Item -Path $TEMP_EXTRACT -Recurse -Force
Remove-Item -Path $SCRATCH_RAW -Force
Log "Removed scratch transfer disk ($SCRATCH_RAW) and temporary extraction directory."

# -----------------------------------------------------------------------------
# Phase 5: Cryptographic Hash Verification against Source Manifests
# -----------------------------------------------------------------------------
Write-Output ""
Write-Output "============================================================"
Write-Output "PHASE 5: MANIFEST HASH VERIFICATION"
Write-Output "============================================================"

function Verify-Manifest([string]$manifestFile, [string]$targetDir, [string]$label) {
    Log "Verifying $label against manifest: $manifestFile"
    $lines = Get-Content $manifestFile | Where-Object { $_ -match "^([0-9a-fA-F]{64})\s+\./(.*)$" }
    $total = $lines.Count
    $passed = 0
    $failed = 0
    $missing = 0

    foreach ($line in $lines) {
        if ($line -match "^([0-9a-fA-F]{64})\s+\./(.*)$") {
            $expectedHash = $matches[1].ToLower()
            $relPath      = $matches[2] -replace "/", "\"
            $fullPath     = Join-Path $targetDir $relPath

            if (-not (Test-Path $fullPath)) {
                Log "  [MISSING] $relPath"
                $missing++
                continue
            }

            $actualHash = (Get-FileHash -Path $fullPath -Algorithm SHA256).Hash.ToLower()
            if ($actualHash -eq $expectedHash) {
                $passed++
            } else {
                Log "  [MISMATCH] $relPath (Expected: $expectedHash, Got: $actualHash)"
                $failed++
            }
        }
    }

    $actualFiles = (Get-ChildItem -Path $targetDir -Recurse -File).Count
    Log "Result for ${label}:"
    Log "  Manifest expected files: $total"
    Log "  Actual files on disk   : $actualFiles"
    Log "  Passed hashes          : $passed"
    Log "  Failed hashes          : $failed"
    Log "  Missing files          : $missing"

    if ($failed -gt 0 -or $missing -gt 0 -or $passed -ne $total) {
        Halt "Verification failed for ${label}! (Failed: $failed, Missing: $missing)"
    }
    Log "Verification PASSED for ${label}: 100% hash and file count match."
}

Verify-Manifest $primMan $PRIMARY_DEST "Primary Candidate (deployment_mongo_data)"
Verify-Manifest $scndMan $SECONDARY_DEST "Secondary Candidate (deepguard-platform_mongo_data)"

# Check WiredTiger sentinels
$wtFiles = @("WiredTiger", "WiredTiger.wt", "WiredTiger.turtle", "_mdb_catalog.wt")
foreach ($wt in $wtFiles) {
    if (-not (Test-Path "$PRIMARY_DEST\$wt")) { Halt "Missing core WiredTiger sentinel in primary: $wt" }
    if (-not (Test-Path "$SECONDARY_DEST\$wt")) { Halt "Missing core WiredTiger sentinel in secondary: $wt" }
}
Log "All WiredTiger engine sentinels verified in both candidates."

# -----------------------------------------------------------------------------
# Phase 6: Post-Execution Working-Copy Baseline Hash Verification
# -----------------------------------------------------------------------------
Write-Output ""
Write-Output "============================================================"
Write-Output "PHASE 6: SOURCE DISK INTEGRITY VERIFICATION"
Write-Output "============================================================"
Log "Re-checking SHA-256 of $WORKING_COPY_PATH..."
$finalHash = (Get-FileHash -Path $WORKING_COPY_PATH -Algorithm SHA256).Hash
Log "Working copy final SHA-256: $finalHash"
if ($finalHash -ne $BASELINE_SHA256) {
    Halt "CRITICAL: Working copy SHA-256 mismatch after recovery! Baseline: $BASELINE_SHA256, Final: $finalHash"
}
Log "CONFIRMED: Working copy SHA-256 matches baseline exactly. Source disk was not modified."

Write-Output ""
Write-Output "============================================================"
Write-Output "RECOVERY & MANIFEST VERIFICATION COMPLETED SUCCESSFULLY"
Write-Output "============================================================"
Log "Direct-disk recovery and validation completed with 100% integrity."
