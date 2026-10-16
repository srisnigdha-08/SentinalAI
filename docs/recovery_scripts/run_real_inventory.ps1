$ErrorActionPreference = "Stop"

$overlayPath = "C:\RecoveryTools\overlay.qcow2"
$isoPath = "C:\RecoveryTools\systemrescue-13.02-amd64.iso"
$vmlinuz = "C:\RecoveryTools\sysrescue_boot\vmlinuz"
$initrd = "C:\RecoveryTools\sysrescue_boot\sysresccd.img"
$qemuExe = "C:\RecoveryTools\qemu\qemu-system-x86_64.exe"
$port = 4449

$b64 = (Get-Content "C:\RecoveryTools\inventory_b64.txt" -Raw).Trim()

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

# Disable echo
$cmd = [System.Text.Encoding]::ASCII.GetBytes("stty -echo`n")
$stream.Write($cmd, 0, $cmd.Length)
Start-Sleep -Seconds 1
while ($stream.DataAvailable) { $null = $stream.Read($buf, 0, $buf.Length) }

function Exec-Guest($cmdStr, $timeoutSec = 90) {
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

Write-Output "`n========================================================"
Write-Output "1. DEVICE IDENTIFICATION & VERIFICATION"
Write-Output "========================================================"

$blkid = Exec-Guest "blkid" 15
Write-Output "--- blkid ---`n$blkid"

$lsblk = Exec-Guest "lsblk -o NAME,SIZE,TYPE,FSTYPE,UUID,SERIAL" 15
Write-Output "--- lsblk ---`n$lsblk"

$targetDev = "/dev/vda"
$fileDev = Exec-Guest "file -s $targetDev" 15
Write-Output "--- file -s $targetDev ---`n$fileDev"

Write-Output "`n========================================================"
Write-Output "2. READ-ONLY MOUNT (ro,noload)"
Write-Output "========================================================"

$mountRun = Exec-Guest "mkdir -p /mnt/target && mount -o ro,noload $targetDev /mnt/target" 20
Write-Output "--- mount execution ---`n$mountRun"

$mountCheck = Exec-Guest "findmnt /mnt/target" 10
Write-Output "--- findmnt check ---`n$mountCheck"

Write-Output "`n========================================================"
Write-Output "3. MONGODB CANDIDATE LOCATIONS INVENTORY"
Write-Output "========================================================"

$invCmd = "echo '$b64' | base64 -d | python3"
$invResult = Exec-Guest $invCmd 90
Write-Output "--- Inventory Results ---`n$invResult"

Write-Output "`n========================================================"
Write-Output "4. DOCKER VOLUME CONTEXT & SURROUNDING METADATA"
Write-Output "========================================================"

$dockerVols = Exec-Guest "ls -la /mnt/target/var/lib/docker/volumes 2>/dev/null" 15
Write-Output "--- Docker Volumes Directory ---`n$dockerVols"

$volList = Exec-Guest "find /mnt/target/var/lib/docker/volumes -maxdepth 2 -type d 2>/dev/null" 15
Write-Output "--- Volume Folders ---`n$volList"

Write-Output "`n========================================================"
Write-Output "5. CLEAN UNMOUNT"
Write-Output "========================================================"

$umountRes = Exec-Guest "umount /mnt/target" 15
Write-Output "--- umount result ---`n$umountRes"

$unmountVerify = Exec-Guest "findmnt /mnt/target || echo 'UNMOUNT_CONFIRMED_CLEAN'" 10
Write-Output "--- unmount verification ---`n$unmountVerify"

Write-Output "`n========================================================"
Write-Output "6. CLEAN SHUTDOWN (poweroff)"
Write-Output "========================================================"

$null = Exec-Guest "poweroff" 10
$client.Close()

Write-Output "Waiting for QEMU process to terminate..."
$qemuProc.WaitForExit(30000)
Write-Output "QEMU Process Terminated: $($qemuProc.HasExited) (ExitCode: $($qemuProc.ExitCode))`n"
