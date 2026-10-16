$ErrorActionPreference = "Stop"

$overlayPath = "C:\RecoveryTools\overlay.qcow2"
$isoPath = "C:\RecoveryTools\systemrescue-13.02-amd64.iso"
$vmlinuz = "C:\RecoveryTools\sysrescue_boot\vmlinuz"
$initrd = "C:\RecoveryTools\sysrescue_boot\sysresccd.img"
$qemuExe = "C:\RecoveryTools\qemu\qemu-system-x86_64.exe"
$port = 4446

$argString = "-m 2048 -smp 2 -kernel `"$vmlinuz`" -initrd `"$initrd`" -append `"archisobasedir=sysresccd archisolabel=RESCUE1302 nomdlvm console=ttyS0,115200n8`" -cdrom `"$isoPath`" -drive file=`"$overlayPath`",format=qcow2,if=virtio -net none -display none -serial tcp:127.0.0.1:$port,server=on,wait=off"

Write-Output "Starting QEMU process..."
$qemuProc = Start-Process -FilePath $qemuExe -ArgumentList $argString -PassThru -NoNewWindow
Start-Sleep -Seconds 2

if ($qemuProc.HasExited) {
    throw "QEMU failed to start. ExitCode: $($qemuProc.ExitCode)"
}

Write-Output "Connecting to serial console on 127.0.0.1:$port..."
$client = [System.Net.Sockets.TcpClient]::new()
$connected = $false
for ($attempt = 1; $attempt -le 10; $attempt++) {
    try {
        $client.Connect("127.0.0.1", $port)
        $connected = $true
        break
    } catch {
        Start-Sleep -Seconds 1
    }
}
if (-not $connected) {
    Stop-Process -Id $qemuProc.Id -Force
    throw "Failed to connect to QEMU serial socket on port $port"
}

$stream = $client.GetStream()
$buf = [byte[]]::new(4096)
$allOutput = [System.Text.StringBuilder]::new()

function Read-StreamData() {
    $readText = ""
    while ($stream.DataAvailable) {
        $n = $stream.Read($buf, 0, $buf.Length)
        if ($n -gt 0) {
            $chunk = [System.Text.Encoding]::ASCII.GetString($buf, 0, $n)
            $allOutput.Append($chunk) | Out-Null
            $readText += $chunk
        }
    }
    return $readText
}

function Send-Raw($str) {
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($str)
    $stream.Write($bytes, 0, $bytes.Length)
}

Write-Output "Waiting for SystemRescue to finish boot and reach root prompt (up to 120s)..."
$deadline = (Get-Date).AddSeconds(120)
$promptReady = $false

while ((Get-Date) -lt $deadline) {
    $chunk = Read-StreamData
    if ($allOutput.ToString() -match "root@sysresccd ~ #" -or $allOutput.ToString() -match "sysresccd.*#") {
        $promptReady = $true
        break
    }
    # Send a newline periodically after 30s to stimulate terminal
    if ((Get-Date).Second % 10 -eq 0) {
        Send-Raw "`n"
    }
    Start-Sleep -Milliseconds 300
}

if (-not $promptReady) {
    Write-Output "Boot did not complete within 120s. Sending emergency newlines..."
    Send-Raw "`n`n"
    Start-Sleep -Seconds 3
    $null = Read-StreamData
}

Write-Output "Shell connection established. Initializing command session..."

function Exec-Guest($cmd, $timeoutSec = 60) {
    # Drain stream first
    $null = Read-StreamData
    $startMarker = "===START_" + (Get-Random) + "==="
    $endMarker = "===END_" + (Get-Random) + "==="
    
    $wrapped = "echo $startMarker; $cmd; echo EXITCODE:`$?; echo $endMarker`n"
    Send-Raw $wrapped
    
    $cmdBuf = [System.Text.StringBuilder]::new()
    $cmdDeadline = (Get-Date).AddSeconds($timeoutSec)
    $done = $false
    
    while ((Get-Date) -lt $cmdDeadline) {
        while ($stream.DataAvailable) {
            $n = $stream.Read($buf, 0, $buf.Length)
            if ($n -gt 0) {
                $chunk = [System.Text.Encoding]::ASCII.GetString($buf, 0, $n)
                $cmdBuf.Append($chunk) | Out-Null
                if ($cmdBuf.ToString().Contains($endMarker)) {
                    $done = $true
                    break
                }
            }
        }
        if ($done) { break }
        Start-Sleep -Milliseconds 100
    }
    
    $full = $cmdBuf.ToString()
    $sIdx = $full.IndexOf($startMarker)
    $eIdx = $full.IndexOf($endMarker)
    if ($sIdx -ge 0 -and $eIdx -gt $sIdx) {
        $extracted = $full.Substring($sIdx + $startMarker.Length, $eIdx - ($sIdx + $startMarker.Length)).Trim()
        return $extracted
    }
    return $full
}

# 1. Device identification
Write-Output "`n=========================================="
Write-Output "1. DEVICE IDENTIFICATION & VERIFICATION"
Write-Output "=========================================="

$lsblk = Exec-Guest "lsblk -o NAME,SIZE,TYPE,FSTYPE,UUID,SERIAL" 20
Write-Output "--- lsblk output ---`n$lsblk"

$blkid = Exec-Guest "blkid" 20
Write-Output "--- blkid output ---`n$blkid"

# Find target device
$targetDev = $null
if ($blkid -match "(/dev/\w+):\s+.*UUID=`"f0faad04-92bb-4f31-a2f1-0e7a110c4a59`".*TYPE=`"ext4`"") {
    $targetDev = $matches[1]
    Write-Output "`n>>> MATCHED TARGET DEVICE: $targetDev"
} else {
    Write-Output "`n>>> ERROR: Target device with UUID f0faad04-92bb-4f31-a2f1-0e7a110c4a59 not found!"
}

if ($null -eq $targetDev) {
    Write-Output "CRITICAL: Ambiguous or missing device. Halting and shutting down VM."
    Send-Raw "poweroff`n"
    $client.Close()
    $qemuProc.WaitForExit(15000)
    exit 1
}

$fileDev = Exec-Guest "file -s $targetDev" 15
Write-Output "--- file -s output ---`n$fileDev"

# 2. Mount strictly ro,noload
Write-Output "`n=========================================="
Write-Output "2. READ-ONLY MOUNT (ro,noload)"
Write-Output "=========================================="

$mountResult = Exec-Guest "mkdir -p /mnt/target && mount -o ro,noload $targetDev /mnt/target" 25
Write-Output "--- mount execution ---`n$mountResult"

$mountCheck = Exec-Guest "findmnt /mnt/target" 15
Write-Output "--- findmnt check ---`n$mountCheck"

if ($mountCheck -notmatch "/mnt/target" -or $mountCheck -notmatch "ro") {
    Write-Output "CRITICAL: Mount verification failed or not read-only. Unmounting and halting."
    Exec-Guest "umount /mnt/target" 10 | Out-Null
    Send-Raw "poweroff`n"
    $client.Close()
    $qemuProc.WaitForExit(15000)
    exit 1
}

# 3. Discover and inventory MongoDB candidate locations
Write-Output "`n=========================================="
Write-Output "3. MONGODB CANDIDATE LOCATIONS INVENTORY"
Write-Output "=========================================="

$pythonInv = @'
python3 - << 'PYEOF'
import os
import sys

mount_pt = "/mnt/target"
candidates = []
seen = set()

sig_files = {"WiredTiger.wt", "WiredTiger", "storage.bson", "mongod.lock"}

for root, dirs, files in os.walk(mount_pt):
    if "cache.db" in files or "buildkit" in root:
        continue
    fset = set(files)
    if sig_files.intersection(fset):
        if root not in seen:
            seen.add(root)
            candidates.append(root)

print(f"TOTAL_CANDIDATES_DISCOVERED: {len(candidates)}")
for idx, c in enumerate(candidates, 1):
    print(f"\n==============================")
    print(f"CANDIDATE #{idx}: {c}")
    print(f"==============================")
    try:
        entries = os.listdir(c)
    except Exception as e:
        print(f"Directory list error: {e}")
        continue
    
    meta_present = [f for f in ["WiredTiger", "WiredTiger.wt", "storage.bson", "mongod.lock", "WiredTiger.turtle"] if f in entries]
    print(f"Core Metadata Files Present: {', '.join(meta_present)}")
    
    col_idx_files = [f for f in entries if f.startswith("collection-") or f.startswith("index-")]
    print(f"Collection/Index Files Count: {len(col_idx_files)}")
    
    has_journal = os.path.isdir(os.path.join(c, "journal"))
    print(f"Journal Directory Present: {has_journal}")
    
    total_size = 0
    total_files = 0
    has_err = False
    for r, d, flist in os.walk(c):
        for f in flist:
            fp = os.path.join(r, f)
            try:
                st = os.stat(fp)
                total_size += st.st_size
                total_files += 1
            except Exception as e:
                print(f"Stat error on {fp}: {e}")
                has_err = True
                
    print(f"Total Files in Candidate: {total_files}")
    print(f"Total Size Bytes: {total_size} ({total_size / (1024*1024):.2f} MB)")
    print(f"Measurement Errors: {has_err}")
PYEOF
'@

$invResult = Exec-Guest $pythonInv 60
Write-Output $invResult

# 4. Check Docker Volume Context
Write-Output "`n=========================================="
Write-Output "4. DOCKER VOLUME CONTEXT & METADATA"
Write-Output "=========================================="

$dockerVols = Exec-Guest "ls -la /mnt/target/var/lib/docker/volumes 2>/dev/null || ls -la /mnt/target/volumes 2>/dev/null" 20
Write-Output "--- Docker volumes listing ---`n$dockerVols"

# 5. Clean Unmount
Write-Output "`n=========================================="
Write-Output "5. CLEAN UNMOUNT"
Write-Output "=========================================="

$umountRes = Exec-Guest "umount /mnt/target" 15
Write-Output "--- umount result ---`n$umountRes"

$unmountVerify = Exec-Guest "findmnt /mnt/target || echo 'UNMOUNT_VERIFIED_CLEAN'" 10
Write-Output "--- unmount verification ---`n$unmountVerify"

# 6. Clean Shutdown
Write-Output "`n=========================================="
Write-Output "6. CLEAN SHUTDOWN (poweroff)"
Write-Output "=========================================="

Send-Raw "poweroff`n"
$client.Close()

Write-Output "Waiting for QEMU process to terminate cleanly..."
$qemuProc.WaitForExit(30000)
Write-Output "QEMU Process Terminated: $($qemuProc.HasExited) (ExitCode: $($qemuProc.ExitCode))"
