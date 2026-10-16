<#
.SYNOPSIS
    SentinelAI Docker Recovery -- MongoDB Preservation Phase
.DESCRIPTION
    Copies both MongoDB candidate directories from the read-only working-copy VHDX
    into D:\MongoPreservation\, verifying every file's SHA-256 against a source-side
    manifest generated inside the VM.

    Authorized decisions:
      - Staging archives : C:\RecoveryTools\staging\  (kept after extraction)
      - Overlay          : reuse C:\RecoveryTools\overlay.qcow2 after validation
      - Destination      : D:\MongoPreservation\

    Hard stops on:
      - Any working-copy hash mismatch (pre or post)
      - Overlay backing-file mismatch
      - D: free space < 1500 MiB
      - Docker / WSL distributions running
      - Archive truncation or extraction error
      - Per-file hash mismatch
      - File count mismatch
      - Any missing WiredTiger sentinel file

    NOT authorized: MongoDB start, fsck, journal replay, cache.db access,
                    deleting overlay or staging archives.
#>

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

# -- Constants ------------------------------------------------------------------
$WORKING_COPY_PATH    = "D:\DockerInspection\A3\docker_data_A3_working.vhdx"
$WORKING_COPY_SHA256  = "660D98A97461FE44D4B23C72D151F80985BA53010DDA67F03D2C887B82A269CC"
$OVERLAY_PATH         = "C:\RecoveryTools\overlay.qcow2"
$ISO_PATH             = "C:\RecoveryTools\systemrescue-13.02-amd64.iso"
$VMLINUZ_PATH         = "C:\RecoveryTools\sysrescue_boot\vmlinuz"
$INITRD_PATH          = "C:\RecoveryTools\sysrescue_boot\sysresccd.img"
$QEMU_EXE             = "C:\RecoveryTools\qemu\qemu-system-x86_64.exe"
$QEMU_IMG_EXE         = "C:\RecoveryTools\qemu\qemu-img.exe"
$SEVENZIP_EXE         = "C:\RecoveryTools\7zip-full\7z.exe"
$STAGING_DIR          = "C:\RecoveryTools\staging"
$DEST_ROOT            = "D:\MongoPreservation"
$MANIFEST_DIR         = "$DEST_ROOT\manifests"
$PORT                 = 4449
$MIN_FREE_MIB         = 1500

# Guest paths (inside the VM)
$GUEST_MOUNT          = "/mnt/target"
$GUEST_PRIMARY        = "/mnt/target/data/docker/volumes/deployment_mongo_data/_data"
$GUEST_SECONDARY      = "/mnt/target/data/docker/volumes/deepguard-platform_mongo_data/_data"

# Host destinations
$DEST_PRIMARY         = "$DEST_ROOT\deployment_mongo_data"
$DEST_SECONDARY       = "$DEST_ROOT\deepguard-platform_mongo_data"

# Expected file counts from inventory
$EXPECTED_COUNT_PRIMARY   = 182
$EXPECTED_COUNT_SECONDARY = 22

# WiredTiger sentinel files required in BOTH copies
$WIREDTIGER_SENTINELS = @(
    "WiredTiger",
    "WiredTiger.wt",
    "WiredTiger.turtle",
    "WiredTiger.lock",
    "storage.bson",
    "mongod.lock"
)

# Log file (initialized once manifest dir exists)
$LOG_FILE = "$DEST_ROOT\manifests\copy_log.txt"

# -- Helper: Stop immediately with message --------------------------------------
function Halt([string]$reason) {
    $msg = "[HALT] $(Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ') $reason"
    Write-Output $msg
    if (Test-Path $LOG_FILE) { Add-Content -Path $LOG_FILE -Value $msg -Encoding UTF8 }
    throw $msg
}

function Log([string]$msg) {
    $line = "[$(Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')] $msg"
    Write-Output $line
    if (Test-Path $LOG_FILE) { Add-Content -Path $LOG_FILE -Value $line -Encoding UTF8 }
}

# -----------------------------------------------------------------------------
# PHASE 0 -- Pre-flight checks
# -----------------------------------------------------------------------------
Write-Output "============================================================"
Write-Output "PHASE 0 -- PRE-FLIGHT CHECKS"
Write-Output "============================================================"

# 0a. Docker Desktop and WSL distributions
Write-Output "0a. Checking Docker Desktop and WSL distribution status..."
$dockerProcs = Get-Process -Name "com.docker.backend","dockerd","docker-desktop" -ErrorAction SilentlyContinue
if ($dockerProcs) {
    Halt "Docker Desktop processes are running: $($dockerProcs.Name -join ', '). Stop all Docker processes before running this script."
}
$wslOutput = (wsl --list --running 2>&1) | Out-String
if ($wslOutput -match "ubuntu|docker-desktop") {
    Halt "WSL distributions are running: $wslOutput. Stop them before running this script."
}
Write-Output "  -> Docker Desktop: STOPPED. WSL distributions: STOPPED."

# 0b. Verify working binaries and paths exist
Write-Output "0b. Verifying required binaries and paths..."
foreach ($exe in @($QEMU_EXE, $QEMU_IMG_EXE, $SEVENZIP_EXE, $ISO_PATH, $OVERLAY_PATH, $WORKING_COPY_PATH, $VMLINUZ_PATH, $INITRD_PATH)) {
    if (-not (Test-Path $exe)) { Halt "Required path not found: $exe" }
}
Write-Output "  -> All required paths found."

# 0c. Validate overlay backing relationship
Write-Output "0c. Validating overlay backing relationship..."
$overlayInfo = (& $QEMU_IMG_EXE info $OVERLAY_PATH 2>&1) | Out-String
Write-Output $overlayInfo.Trim()

$wcpNorm = $WORKING_COPY_PATH.Replace("\", "/")
if (-not ($overlayInfo -match [regex]::Escape($WORKING_COPY_PATH) -or $overlayInfo -match [regex]::Escape($wcpNorm))) {
    Halt "Overlay backing file does not match expected working copy path. See qemu-img info output above."
}
if ($overlayInfo -notmatch "backing file format: vhdx") {
    Halt "Overlay backing format is not 'vhdx'. See qemu-img info output above."
}
Write-Output "  -> Overlay backing file: CONFIRMED (working copy, format=vhdx)."

# 0d. D: free space
Write-Output "0d. Checking D: free space..."
$dDrive = Get-PSDrive D
$freeMiB = [math]::Floor($dDrive.Free / 1MB)
Write-Output "  -> D: free: $freeMiB MiB (minimum required: $MIN_FREE_MIB MiB)"
if ($freeMiB -lt $MIN_FREE_MIB) {
    Halt "Insufficient free space on D:. Available: $freeMiB MiB, Required: $MIN_FREE_MIB MiB."
}
Write-Output "  -> Space check: OK"

# 0e. C: staging space (need ~900 MiB for base64 + archives)
$cDrive = Get-PSDrive C
$cFreeMiB = [math]::Floor($cDrive.Free / 1MB)
Write-Output "  -> C: free: $cFreeMiB MiB"
if ($cFreeMiB -lt 1000) {
    Halt "Insufficient free space on C: for staging. Available: $cFreeMiB MiB, need >= 1000 MiB."
}

# 0f. Pre-copy baseline hash of working copy
Write-Output "0f. Calculating working-copy SHA-256 baseline (this takes ~60s)..."
$preCopyHash = (Get-FileHash $WORKING_COPY_PATH -Algorithm SHA256).Hash.ToUpperInvariant()
Write-Output "  -> SHA-256: $preCopyHash"
if ($preCopyHash -ne $WORKING_COPY_SHA256) {
    Halt "PRE-COPY WORKING COPY HASH MISMATCH.`n  Expected: $WORKING_COPY_SHA256`n  Got:      $preCopyHash"
}
Write-Output "  -> Pre-copy baseline hash: MATCH OK"

# 0g. Create destination directories
Write-Output "0g. Creating destination directories..."
foreach ($d in @($STAGING_DIR, $DEST_ROOT, $DEST_PRIMARY, $DEST_SECONDARY, $MANIFEST_DIR)) {
    if (-not (Test-Path $d)) {
        New-Item -ItemType Directory -Path $d -Force | Out-Null
        Write-Output "  -> Created: $d"
    } else {
        Write-Output "  -> Exists:  $d"
    }
}

# Initialize log
"[$(Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')] === MongoDB Preservation Log === Starting ===" |
    Set-Content $LOG_FILE -Encoding UTF8

Log "Pre-flight PASSED. Working copy pre-copy SHA-256: $preCopyHash  MATCH"
$overlayLogLine = "Overlay: $OVERLAY_PATH `(backing=$WORKING_COPY_PATH, format=vhdx, dirty=208KiB`)"
Log $overlayLogLine
Log "D: free: $freeMiB MiB  |  C: free: $cFreeMiB MiB"

# -----------------------------------------------------------------------------
# PHASE 1 -- Boot VM, mount read-only, generate source manifests, stream archives
# -----------------------------------------------------------------------------
Write-Output ""
Write-Output "============================================================"
Write-Output "PHASE 1 -- VM BOOT, READ-ONLY MOUNT, MANIFEST + STREAMING"
Write-Output "============================================================"

$qemuArgString = "-m 2048 -smp 2 -kernel `"$VMLINUZ_PATH`" -initrd `"$INITRD_PATH`" -append `"archisobasedir=sysresccd archisolabel=RESCUE1302 nomdlvm console=ttyS0,115200n8`" -cdrom `"$ISO_PATH`" -drive file=`"$OVERLAY_PATH`",format=qcow2,if=virtio -net none -display none -serial tcp:127.0.0.1:${PORT},server=on,wait=off"

Log "Starting QEMU: $QEMU_EXE $qemuArgString"
$qemuProc = Start-Process -FilePath $QEMU_EXE -ArgumentList $qemuArgString -PassThru -NoNewWindow
Start-Sleep -Seconds 2
if ($qemuProc.HasExited) { Halt "QEMU failed to start. ExitCode: $($qemuProc.ExitCode)" }
Log "QEMU PID: $($qemuProc.Id)"

# Connect to serial console
$client = [System.Net.Sockets.TcpClient]::new()
$connected = $false
for ($attempt = 1; $attempt -le 15; $attempt++) {
    try { $client.Connect("127.0.0.1", $PORT); $connected = $true; break }
    catch { Start-Sleep -Seconds 2 }
}
if (-not $connected) {
    Stop-Process -Id $qemuProc.Id -Force
    Halt "Failed to connect to QEMU serial socket on port $PORT after 15 attempts."
}
$stream = $client.GetStream()
$buf = [byte[]]::new(8192)
$acc = [System.Text.StringBuilder]::new()

# Wait for shell prompt
Log "Waiting for SystemRescue boot prompt (up to 3 min)..."
$deadline = (Get-Date).AddSeconds(180)
while ((Get-Date) -lt $deadline) {
    $nl = [System.Text.Encoding]::ASCII.GetBytes("`n")
    $stream.Write($nl, 0, $nl.Length)
    Start-Sleep -Seconds 3
    while ($stream.DataAvailable) {
        $n = $stream.Read($buf, 0, $buf.Length)
        $acc.Append([System.Text.Encoding]::ASCII.GetString($buf, 0, $n)) | Out-Null
    }
    if ($acc.ToString() -match "sysrescue.*#|root@sysrescue") { Log "Shell prompt detected."; break }
}
if (-not ($acc.ToString() -match "sysrescue.*#|root@sysrescue")) {
    Stop-Process -Id $qemuProc.Id -Force
    Halt "Timed out waiting for SystemRescue shell prompt."
}

# Disable echo and flush
$echoOff = [System.Text.Encoding]::ASCII.GetBytes("stty -echo`n")
$stream.Write($echoOff, 0, $echoOff.Length)
Start-Sleep -Seconds 1
while ($stream.DataAvailable) { $null = $stream.Read($buf, 0, $buf.Length) }

# -- Guest command executor -----------------------------------------------------
function Exec-Guest {
    param([string]$cmdStr, [int]$timeoutSec = 120)
    while ($stream.DataAvailable) { $null = $stream.Read($buf, 0, $buf.Length) }
    $token = "DONE_$(Get-Random -Maximum 999999)"
    $fullCmd = [System.Text.Encoding]::ASCII.GetBytes("$cmdStr; echo $token`n")
    $stream.Write($fullCmd, 0, $fullCmd.Length)
    $out = [System.Text.StringBuilder]::new()
    $dead = (Get-Date).AddSeconds($timeoutSec)
    while ((Get-Date) -lt $dead) {
        Start-Sleep -Milliseconds 300
        while ($stream.DataAvailable) {
            $n = $stream.Read($buf, 0, $buf.Length)
            $out.Append([System.Text.Encoding]::ASCII.GetString($buf, 0, $n)) | Out-Null
        }
        if ($out.ToString() -match [regex]::Escape($token)) { break }
    }
    $result = ($out.ToString() -replace [regex]::Escape($token), "").Trim()
    return $result
}

# -- Large base64 stream reader -------------------------------------------------
# Guest emits: echo START_SENTINEL; <base64 data>; echo END_SENTINEL
# Host accumulates base64 lines between sentinels and decodes to file.
function Stream-GuestBase64ToFile {
    param(
        [string]$guestCmd,
        [string]$startSentinel,
        [string]$endSentinel,
        [int]$timeoutSec,
        [string]$outputPath
    )
    # Flush any queued input
    while ($stream.DataAvailable) { $null = $stream.Read($buf, 0, $buf.Length) }

    $cmdBytes = [System.Text.Encoding]::ASCII.GetBytes("$guestCmd`n")
    $stream.Write($cmdBytes, 0, $cmdBytes.Length)

    $b64Lines    = [System.Collections.Generic.List[string]]::new()
    $capturing   = $false
    $done        = $false
    $dead        = (Get-Date).AddSeconds($timeoutSec)
    $lineCarry   = [System.Text.StringBuilder]::new()

    while (-not $done -and (Get-Date) -lt $dead) {
        Start-Sleep -Milliseconds 50
        while ($stream.DataAvailable) {
            $n = $stream.Read($buf, 0, $buf.Length)
            $lineCarry.Append([System.Text.Encoding]::ASCII.GetString($buf, 0, $n)) | Out-Null
        }

        # Split on newlines; keep last partial line in carry buffer
        $raw   = $lineCarry.ToString()
        $parts = $raw -split "(?<=\n)"      # split but keep the \n
        $lineCarry.Clear()
        # Last element may be partial (no trailing \n yet)
        $completedLines = @()
        for ($i = 0; $i -lt $parts.Count - 1; $i++) { $completedLines += $parts[$i] }
        $lineCarry.Append($parts[-1]) | Out-Null

        foreach ($raw_line in $completedLines) {
            $l = $raw_line.Trim("`r`n")
            if ($l -eq $startSentinel) { $capturing = $true;  continue }
            if ($l -eq $endSentinel)   { $done      = $true;  break    }
            if ($capturing -and $l.Length -gt 0) { $b64Lines.Add($l) }
        }
    }
    if (-not $done) {
        Halt "Timed out waiting for END sentinel '$endSentinel'. Archive stream incomplete."
    }

    # Decode base64 ? bytes ? file
    $combined = [string]::Join("", $b64Lines)
    $bytes = [System.Convert]::FromBase64String($combined)
    [System.IO.File]::WriteAllBytes($outputPath, $bytes)
    return $bytes.Length
}

# -- 1. Device identification -------------------------------------------------
Log "Step 1: Device identification"
$blkid = Exec-Guest "blkid" 20
Log "blkid: $blkid"
if ($blkid -notmatch "f0faad04-92bb-4f31-a2f1-0e7a110c4a59") {
    $null = Exec-Guest "poweroff" 10; $client.Close()
    Halt "Expected ext4 UUID (f0faad04-92bb-4f31-a2f1-0e7a110c4a59) not found in blkid. Wrong disk? Halt."
}
Log "Disk UUID confirmed: f0faad04-92bb-4f31-a2f1-0e7a110c4a59"

# -- 2. Read-only mount -------------------------------------------------------
Log "Step 2: Mounting /dev/vda read-only (ro,noload)"
$null = Exec-Guest "mkdir -p $GUEST_MOUNT" 10
$mountRes = Exec-Guest "mount -o ro,noload /dev/vda $GUEST_MOUNT" 20
Log "mount result: $mountRes"
$findmnt = Exec-Guest "findmnt $GUEST_MOUNT" 10
Log "findmnt: $findmnt"
if ($findmnt -notmatch "\bro\b") {
    $null = Exec-Guest "umount $GUEST_MOUNT" 10
    $null = Exec-Guest "poweroff" 10; $client.Close()
    Halt "Mount verification failed -- 'ro' not confirmed in findmnt output. Halt."
}
Log "Read-only mount confirmed."

# -- 3. Verify candidate directories exist ------------------------------------
Log "Step 3: Verifying candidate directories exist inside VM"
$chkP = Exec-Guest ('test -d ''' + $GUEST_PRIMARY   + ''' && echo DIR_OK || echo DIR_MISSING') 15
$chkS = Exec-Guest ('test -d ''' + $GUEST_SECONDARY + ''' && echo DIR_OK || echo DIR_MISSING') 15
if ($chkP -notmatch "DIR_OK") {
    $null = Exec-Guest "umount $GUEST_MOUNT" 10; $null = Exec-Guest "poweroff" 10; $client.Close()
    Halt "Primary candidate not found: $GUEST_PRIMARY"
}
if ($chkS -notmatch "DIR_OK") {
    $null = Exec-Guest "umount $GUEST_MOUNT" 10; $null = Exec-Guest "poweroff" 10; $client.Close()
    Halt "Secondary candidate not found: $GUEST_SECONDARY"
}
Log "Both candidate directories confirmed."

# -- 4. Source-side SHA-256 manifests -----------------------------------------
Log "Step 4: Generating source-side SHA-256 manifests inside VM (may take several minutes)..."

# Each sha256sum line: "<hash>  ./relative/path"
$primaryManifestRaw = Exec-Guest `
    "(cd '$GUEST_PRIMARY'   && find . -type f | LC_ALL=C sort | xargs -d '\n' sha256sum 2>&1)" `
    300
Log "Primary source manifest ($( ($primaryManifestRaw -split '\n').Count ) lines):`n$primaryManifestRaw"

$secondaryManifestRaw = Exec-Guest `
    "(cd '$GUEST_SECONDARY' && find . -type f | LC_ALL=C sort | xargs -d '\n' sha256sum 2>&1)" `
    180
Log "Secondary source manifest ($( ($secondaryManifestRaw -split '\n').Count ) lines):`n$secondaryManifestRaw"

# Parse manifest into hashtable: normalised-relative-path -> SHA256
function Parse-SourceManifest([string]$raw) {
    $ht = @{}
    foreach ($line in ($raw -split "`n")) {
        $l = $line.Trim()
        # sha256sum format: "<64 hex chars>  ./path/to/file"  (two spaces)
        if ($l -match "^([0-9a-fA-F]{64})\s+\./(.+)$") {
            $sha = $Matches[1].ToUpperInvariant()
            # Normalise path separators to Windows backslash
            $rel = $Matches[2].Replace("/", "\")
            $ht[$rel] = $sha
        }
    }
    return $ht
}

$primaryManifest   = Parse-SourceManifest $primaryManifestRaw
$secondaryManifest = Parse-SourceManifest $secondaryManifestRaw

Log "Parsed primary manifest  : $($primaryManifest.Count) files"
Log "Parsed secondary manifest: $($secondaryManifest.Count) files"

if ($primaryManifest.Count -eq 0) {
    $null = Exec-Guest "umount $GUEST_MOUNT" 10; $null = Exec-Guest "poweroff" 10; $client.Close()
    Halt "Primary manifest parsed 0 files -- sha256sum may have failed. Halt."
}
if ($secondaryManifest.Count -eq 0) {
    $null = Exec-Guest "umount $GUEST_MOUNT" 10; $null = Exec-Guest "poweroff" 10; $client.Close()
    Halt "Secondary manifest parsed 0 files -- sha256sum may have failed. Halt."
}

# Save source manifests to host immediately (before any streaming can fail)
$primaryManifestRaw   | Set-Content "$MANIFEST_DIR\deployment_mongo_data_SOURCE.sha256.txt"         -Encoding UTF8
$secondaryManifestRaw | Set-Content "$MANIFEST_DIR\deepguard-platform_mongo_data_SOURCE.sha256.txt" -Encoding UTF8
Log "Source manifests saved to $MANIFEST_DIR"

# -- 5. Stream PRIMARY tar.gz archive -----------------------------------------
$primaryArchive   = "$STAGING_DIR\deployment_mongo_data.tar.gz"
Log "Step 5a: Streaming PRIMARY archive (this will take several minutes)..."
$guestPrimCmd = "echo PRIM_START; tar -czf - -C '$GUEST_PRIMARY'   . | base64; echo PRIM_END"
$primBytes = Stream-GuestBase64ToFile `
    -guestCmd      $guestPrimCmd `
    -startSentinel "PRIM_START" `
    -endSentinel   "PRIM_END" `
    -timeoutSec    1200 `
    -outputPath    $primaryArchive
Log "PRIMARY archive received: $primBytes bytes  ->  $primaryArchive"

if ($primBytes -lt 100000) {
    $null = Exec-Guest "umount $GUEST_MOUNT" 10; $null = Exec-Guest "poweroff" 10; $client.Close()
    Halt "PRIMARY archive too small ($primBytes bytes) -- likely truncated. Halt."
}
$magic = [System.IO.File]::ReadAllBytes($primaryArchive)
if (-not ($magic[0] -eq 0x1f -and $magic[1] -eq 0x8b)) {
    $null = Exec-Guest "umount $GUEST_MOUNT" 10; $null = Exec-Guest "poweroff" 10; $client.Close()
    Halt "PRIMARY archive missing gzip magic bytes (1F 8B). File is corrupt. Halt."
}
Log "PRIMARY archive gzip magic: OK"

# -- 6. Stream SECONDARY tar.gz archive ---------------------------------------
$secondaryArchive = "$STAGING_DIR\deepguard-platform_mongo_data.tar.gz"
Log "Step 5b: Streaming SECONDARY archive..."
$guestScndCmd = "echo SCND_START; tar -czf - -C '$GUEST_SECONDARY' . | base64; echo SCND_END"
$scndBytes = Stream-GuestBase64ToFile `
    -guestCmd      $guestScndCmd `
    -startSentinel "SCND_START" `
    -endSentinel   "SCND_END" `
    -timeoutSec    900 `
    -outputPath    $secondaryArchive
Log "SECONDARY archive received: $scndBytes bytes  ->  $secondaryArchive"

if ($scndBytes -lt 100000) {
    $null = Exec-Guest "umount $GUEST_MOUNT" 10; $null = Exec-Guest "poweroff" 10; $client.Close()
    Halt "SECONDARY archive too small ($scndBytes bytes) -- likely truncated. Halt."
}
$magic2 = [System.IO.File]::ReadAllBytes($secondaryArchive)
if (-not ($magic2[0] -eq 0x1f -and $magic2[1] -eq 0x8b)) {
    $null = Exec-Guest "umount $GUEST_MOUNT" 10; $null = Exec-Guest "poweroff" 10; $client.Close()
    Halt "SECONDARY archive missing gzip magic bytes. File is corrupt. Halt."
}
Log "SECONDARY archive gzip magic: OK"

# -- 7. Clean unmount and shutdown --------------------------------------------
Log "Step 6: Unmounting filesystem..."
$umRes = Exec-Guest "umount $GUEST_MOUNT" 20
Log "umount: $umRes"
$umVerify = Exec-Guest ('findmnt ' + $GUEST_MOUNT + ' || echo UNMOUNT_CONFIRMED') 10
if ($umVerify -notmatch "UNMOUNT_CONFIRMED") {
    Log "WARNING: Unmount verification: $umVerify"
}
Log "Shutting down VM..."
$null = Exec-Guest 'sync && poweroff' 15
$client.Close()
Log "Waiting for QEMU process exit..."
$qemuProc.WaitForExit(60000)
Log "QEMU exited: $($qemuProc.HasExited) (ExitCode: $($qemuProc.ExitCode))"

# -----------------------------------------------------------------------------
# PHASE 2 -- Extract archives on host
# -----------------------------------------------------------------------------
Write-Output ""
Write-Output "============================================================"
Write-Output "PHASE 2 -- EXTRACT ARCHIVES"
Write-Output "============================================================"

function Extract-Archive {
    param([string]$archive, [string]$dest, [string]$label)
    Log "Extracting $label  :  $archive  ->  $dest"
    $out = (& $SEVENZIP_EXE x $archive "-o$dest" -y 2>&1) | Out-String
    Log "7-Zip output: $out"
    if ($LASTEXITCODE -ne 0) {
        Halt "7-Zip extraction failed for $label (exit code $LASTEXITCODE). Halt."
    }
    Log "$label extraction complete."
}

Extract-Archive $primaryArchive   $DEST_PRIMARY   "PRIMARY (deployment_mongo_data)"
Extract-Archive $secondaryArchive $DEST_SECONDARY "SECONDARY (deepguard-platform_mongo_data)"

# -----------------------------------------------------------------------------
# PHASE 3 -- Integrity Verification
# -----------------------------------------------------------------------------
Write-Output ""
Write-Output "============================================================"
Write-Output "PHASE 3 -- INTEGRITY VERIFICATION"
Write-Output "============================================================"

function Verify-Copy {
    param(
        [string]$destDir,
        [hashtable]$sourceManifest,
        [string]$label,
        [int]$expectedCount,
        [string]$manifestOutPath
    )
    Log "Verifying $label  in  $destDir ..."

    # 3a. File count
    $destFiles   = Get-ChildItem -Recurse -File $destDir
    $actualCount = $destFiles.Count
    Log "  File count: actual=$actualCount  source-manifest=$($sourceManifest.Count)  inventory-expected=$expectedCount"
    if ($actualCount -ne $sourceManifest.Count) {
        Halt "FILE COUNT MISMATCH for $label. Destination=$actualCount files; source manifest=$($sourceManifest.Count) files. Halt."
    }

    # 3b. WiredTiger sentinel files
    Log "  Checking WiredTiger sentinel files..."
    foreach ($sentinel in $WIREDTIGER_SENTINELS) {
        if (-not (Test-Path (Join-Path $destDir $sentinel))) {
            Halt "MISSING WiredTiger sentinel file in ${label}: $sentinel. Halt."
        }
    }
    if (-not (Test-Path "$destDir\journal")) {
        Halt "MISSING 'journal' subdirectory in ${label}. Halt."
    }
    Log "  WiredTiger sentinels + journal: ALL PRESENT"

    # 3c. Per-file SHA-256
    $fileCountMsg = "  Computing per-file SHA-256 hashes `($actualCount files`)..."
    Log $fileCountMsg
    $hostManifest = [System.Collections.Generic.List[string]]::new()
    $mismatches   = 0

    foreach ($file in $destFiles) {
        $relPath  = $file.FullName.Substring($destDir.Length).TrimStart("\")
        $hostHash = (Get-FileHash $file.FullName -Algorithm SHA256).Hash.ToUpperInvariant()
        $hostManifest.Add("$hostHash  $($relPath.Replace('\','/'))")

        $srcHash = $sourceManifest[$relPath]
        if ($null -eq $srcHash) {
            Log "  [WARN] No source manifest entry for: $relPath"
            $mismatches++
        } elseif ($hostHash -ne $srcHash) {
            Log "  [FAIL] HASH MISMATCH: $relPath`n         Source: $srcHash`n         Host:   $hostHash"
            $mismatches++
        }
    }

    # Check that every source entry has a destination file
    foreach ($rel in $sourceManifest.Keys) {
        if (-not (Test-Path (Join-Path $destDir $rel))) {
            Log "  [FAIL] Source manifest entry missing from destination: $rel"
            $mismatches++
        }
    }

    $hostManifest | Set-Content $manifestOutPath -Encoding UTF8
    Log "  Host manifest saved: $manifestOutPath"

    if ($mismatches -gt 0) {
        Halt "$mismatches hash/file mismatch(es) in ${label}. See log. Halt."
    }
    Log "  Per-file SHA-256: ALL $actualCount FILES VERIFIED. $label OK."
}

Verify-Copy `
    -destDir        $DEST_PRIMARY `
    -sourceManifest $primaryManifest `
    -label          "PRIMARY (deployment_mongo_data)" `
    -expectedCount  $EXPECTED_COUNT_PRIMARY `
    -manifestOutPath "$MANIFEST_DIR\deployment_mongo_data.sha256.txt"

Verify-Copy `
    -destDir        $DEST_SECONDARY `
    -sourceManifest $secondaryManifest `
    -label          "SECONDARY (deepguard-platform_mongo_data)" `
    -expectedCount  $EXPECTED_COUNT_SECONDARY `
    -manifestOutPath "$MANIFEST_DIR\deepguard-platform_mongo_data.sha256.txt"

# -----------------------------------------------------------------------------
# PHASE 4 -- Post-copy working-copy hash verification
# -----------------------------------------------------------------------------
Write-Output ""
Write-Output "============================================================"
Write-Output "PHASE 4 -- POST-COPY WORKING-COPY HASH VERIFICATION"
Write-Output "============================================================"

Log "Recalculating working-copy SHA-256 post-shutdown (~60s)..."
$postCopyHash = (Get-FileHash $WORKING_COPY_PATH -Algorithm SHA256).Hash.ToUpperInvariant()
Log "Post-copy SHA-256: $postCopyHash"
if ($postCopyHash -ne $WORKING_COPY_SHA256) {
    Halt "POST-COPY HASH MISMATCH. Expected: $WORKING_COPY_SHA256  Got: $postCopyHash`nThe working copy may have been modified!"
}
Log "Post-copy hash: MATCH OK -- working copy byte-identical to baseline."

# -----------------------------------------------------------------------------
# PHASE 5 -- Final summary
# -----------------------------------------------------------------------------
$dFreeAfter = [math]::Floor((Get-PSDrive D).Free / 1MB)

$summary = @(
    "",
    "=== MongoDB Preservation COMPLETE ===",
    "Timestamp           : $(Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')",
    "",
    "WORKING COPY",
    "  Path              : $WORKING_COPY_PATH",
    "  Pre-copy  SHA-256 : $preCopyHash  MATCH",
    "  Post-copy SHA-256 : $postCopyHash  MATCH",
    "",
    "PRIMARY COPY",
    "  Guest source      : $GUEST_PRIMARY",
    "  Host destination  : $DEST_PRIMARY",
    "  Files verified    : $($primaryManifest.Count)",
    "  Archive kept      : $primaryArchive ($primBytes bytes)",
    "  Host manifest     : $MANIFEST_DIR\deployment_mongo_data.sha256.txt",
    "",
    "SECONDARY COPY",
    "  Guest source      : $GUEST_SECONDARY",
    "  Host destination  : $DEST_SECONDARY",
    "  Files verified    : $($secondaryManifest.Count)",
    "  Archive kept      : $secondaryArchive ($scndBytes bytes)",
    "  Host manifest     : $MANIFEST_DIR\deepguard-platform_mongo_data.sha256.txt",
    "",
    "D: free after copy  : $dFreeAfter MiB",
    "",
    "NOT done (requires separate authorization):",
    "  - MongoDB start or repair",
    "  - Journal replay, fsck, or e2fsck",
    "  - cache.db access",
    "  - SentinelAI restoration",
    "  - Overlay or staging archive deletion",
    "",
    "=== STOPPING AS AUTHORIZED ==="
)

$summary | ForEach-Object { Write-Output $_ }
$summary | Add-Content $LOG_FILE -Encoding UTF8
