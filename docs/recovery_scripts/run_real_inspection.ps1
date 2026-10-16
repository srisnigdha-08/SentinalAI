$ErrorActionPreference = "Stop"

$overlayPath = "C:\RecoveryTools\overlay.qcow2"
$isoPath = "C:\RecoveryTools\systemrescue-13.02-amd64.iso"
$vmlinuz = "C:\RecoveryTools\sysrescue_boot\vmlinuz"
$initrd = "C:\RecoveryTools\sysrescue_boot\sysresccd.img"
$qemuExe = "C:\RecoveryTools\qemu\qemu-system-x86_64.exe"
$port = 4448

$argString = "-m 2048 -smp 2 -kernel `"$vmlinuz`" -initrd `"$initrd`" -append `"archisobasedir=sysresccd archisolabel=RESCUE1302 nomdlvm console=ttyS0,115200n8`" -cdrom `"$isoPath`" -drive file=`"$overlayPath`",format=qcow2,if=virtio -net none -display none -serial tcp:127.0.0.1:$port,server=on,wait=off"

Write-Output "Starting QEMU process with real overlay..."
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
$acc = [System.Text.StringBuilder]::new()
$deadline = (Get-Date).AddSeconds(120)

Write-Output "Waiting for SystemRescue boot and shell prompt..."
while ((Get-Date) -lt $deadline) {
    $nl = [System.Text.Encoding]::ASCII.GetBytes("`n")
    $stream.Write($nl, 0, $nl.Length)
    Start-Sleep -Seconds 2
    while ($stream.DataAvailable) {
        $n = $stream.Read($buf, 0, $buf.Length)
        $acc.Append([System.Text.Encoding]::ASCII.GetString($buf, 0, $n)) | Out-Null
    }
    if ($acc.ToString() -match "sysrescue.*#" -or $acc.ToString() -match "root@") {
        Write-Output "PROMPT DETECTED!"
        break
    }
}

# Disable terminal echo for clean script output
$cmd = [System.Text.Encoding]::ASCII.GetBytes("stty -echo`n")
$stream.Write($cmd, 0, $cmd.Length)
Start-Sleep -Seconds 1
while ($stream.DataAvailable) { $null = $stream.Read($buf, 0, $buf.Length) }

function Exec-GuestClean($cmdStr, $timeoutSec = 60) {
    while ($stream.DataAvailable) { $null = $stream.Read($buf, 0, $buf.Length) }
    $cmdBytes = [System.Text.Encoding]::ASCII.GetBytes("$cmdStr; echo EXIT_CODE_`$?`n")
    $stream.Write($cmdBytes, 0, $cmdBytes.Length)
    
    $outBuf = [System.Text.StringBuilder]::new()
    $cmdDead = (Get-Date).AddSeconds($timeoutSec)
    
    while ((Get-Date) -lt $cmdDead) {
        Start-Sleep -Milliseconds 200
        while ($stream.DataAvailable) {
            $n = $stream.Read($buf, 0, $buf.Length)
            $outBuf.Append([System.Text.Encoding]::ASCII.GetString($buf, 0, $n)) | Out-Null
        }
        if ($outBuf.ToString() -match "EXIT_CODE_\d+") {
            break
        }
    }
    return $outBuf.ToString().Trim()
}

# 1. Device Inspection
Write-Output "`n========================================================"
Write-Output "1. DEVICE IDENTIFICATION & VERIFICATION"
Write-Output "========================================================"

$lsblk = Exec-GuestClean "lsblk -o NAME,SIZE,TYPE,FSTYPE,UUID,SERIAL" 15
Write-Output "--- lsblk ---`n$lsblk"

$blkid = Exec-GuestClean "blkid" 15
Write-Output "--- blkid ---`n$blkid"

$targetDev = $null
if ($blkid -match "(/dev/\w+):\s+.*UUID=`"f0faad04-92bb-4f31-a2f1-0e7a110c4a59`".*TYPE=`"ext4`"") {
    $targetDev = $matches[1]
    Write-Output "`n>>> MATCHED TARGET DEVICE VIA BLKID: $targetDev"
} else {
    Write-Output "`n>>> ERROR: Device with UUID f0faad04-92bb-4f31-a2f1-0e7a110c4a59 not found!"
}

if ($null -eq $targetDev) {
    Write-Output "CRITICAL HALT: Device identity ambiguous. Powering off..."
    $null = Exec-GuestClean "poweroff" 10
    $client.Close()
    $qemuProc.WaitForExit(15000)
    exit 1
}

# Verify device capacity and file -s
$devSize = Exec-GuestClean "lsblk -bno SIZE $targetDev" 10
Write-Output "Target Device Capacity Bytes: $devSize (Expected 1099511627776 bytes / 1 TiB)"

$fileDev = Exec-GuestClean "file -s $targetDev" 15
Write-Output "--- file -s $targetDev ---`n$fileDev"

# 2. Mount strictly ro,noload
Write-Output "`n========================================================"
Write-Output "2. READ-ONLY MOUNT (ro,noload)"
Write-Output "========================================================"

$mountRun = Exec-GuestClean "mkdir -p /mnt/target && mount -o ro,noload $targetDev /mnt/target" 20
Write-Output "--- mount execution ---`n$mountRun"

$mountCheck = Exec-GuestClean "findmnt /mnt/target" 10
Write-Output "--- findmnt check ---`n$mountCheck"

if ($mountCheck -notmatch "/mnt/target" -or $mountCheck -notmatch "ro") {
    Write-Output "CRITICAL HALT: Mount is not read-only or failed. Powering off..."
    $null = Exec-GuestClean "umount /mnt/target" 10
    $null = Exec-GuestClean "poweroff" 10
    $client.Close()
    $qemuProc.WaitForExit(15000)
    exit 1
}

# 3. Discover and Inventory MongoDB Candidates
Write-Output "`n========================================================"
Write-Output "3. MONGODB CANDIDATE LOCATIONS INVENTORY"
Write-Output "========================================================"

$pyScript = @'
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

print(f"DISCOVERED_CANDIDATE_COUNT: {len(candidates)}")
for idx, c in enumerate(candidates, 1):
    print(f"\n==========================================")
    print(f"CANDIDATE #{idx}: {c}")
    print(f"==========================================")
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
    if has_journal:
        jfiles = os.listdir(os.path.join(c, "journal"))
        print(f"  Journal files count: {len(jfiles)}")
    
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
    print(f"Total Size: {total_size} bytes ({total_size / (1024*1024):.2f} MB)")
    print(f"Measurement Errors Encountered: {has_err}")
PYEOF
'@

$invResult = Exec-GuestClean $pyScript 60
Write-Output $invResult

# 4. Docker Volume Context & Surrounding Metadata
Write-Output "`n========================================================"
Write-Output "4. DOCKER VOLUME CONTEXT & SURROUNDING METADATA"
Write-Output "========================================================"

$dockerVols = Exec-GuestClean "ls -la /mnt/target/var/lib/docker/volumes 2>/dev/null || ls -la /mnt/target/volumes 2>/dev/null" 20
Write-Output "--- Docker Volumes Root ---`n$dockerVols"

# Also check for volume names in /var/lib/docker/volumes
$volDirs = Exec-GuestClean "find /mnt/target/var/lib/docker/volumes -maxdepth 2 -type d 2>/dev/null" 20
Write-Output "--- Volume Directories ---`n$volDirs"

# 5. Clean Unmount
Write-Output "`n========================================================"
Write-Output "5. CLEAN UNMOUNT"
Write-Output "========================================================"

$umountRes = Exec-GuestClean "umount /mnt/target" 15
Write-Output "--- umount result ---`n$umountRes"

$unmountVerify = Exec-GuestClean "findmnt /mnt/target || echo 'UNMOUNT_CONFIRMED_CLEAN'" 10
Write-Output "--- unmount verification ---`n$unmountVerify"

# 6. Clean Shutdown
Write-Output "`n========================================================"
Write-Output "6. CLEAN SHUTDOWN (poweroff)"
Write-Output "========================================================"

$null = Exec-GuestClean "poweroff" 10
$client.Close()

Write-Output "Waiting for QEMU process to terminate..."
$qemuProc.WaitForExit(30000)
Write-Output "QEMU Process Terminated: $($qemuProc.HasExited) (ExitCode: $($qemuProc.ExitCode))`n"
