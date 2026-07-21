# Migrate Docker Desktop WSL data from D:\Docker to F:\Docker
# Prerequisites:
#   1) Quit Docker Desktop completely (whale icon -> Quit)
#   2) Run PowerShell as the same user (Admin optional but recommended)
#   3) F: free space > size of D:\Docker\data (currently ~65GB + margin)
#
# What it does:
#   - Shuts down WSL
#   - Creates F:\Docker\data and F:\Docker\hyper-v
#   - Robocopy D:\Docker\data -> F:\Docker\data
#   - Updates %APPDATA%\Docker\settings-store.json paths
#   - Does NOT auto-delete D:\ data until you verify Docker works on F:

$ErrorActionPreference = "Stop"

$SrcData = "D:\Docker\data"
$SrcHyperV = "D:\Docker\hyper-v"
$DstData = "F:\Docker\data"
$DstHyperV = "F:\Docker\hyper-v"
$Settings = Join-Path $env:APPDATA "Docker\settings-store.json"
$Log = "F:\wangyi_0\output\queue\docker_migrate_to_f.log"

function Log($msg) {
    $line = "[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $msg
    Write-Host $line
    Add-Content -Path $Log -Value $line -Encoding UTF8
}

New-Item -ItemType Directory -Force -Path (Split-Path $Log) | Out-Null
Log "=== Docker migrate D: -> F: start ==="

# Space check
$f = Get-PSDrive F
$freeGB = [math]::Round($f.Free / 1GB, 1)
Log "F: free GB = $freeGB"
if ($f.Free -lt 80GB) {
    throw "F: free space < 80GB; abort to avoid failed copy of ~65GB docker_data.vhdx"
}

# Docker process check
$dockerProcs = Get-Process -Name "Docker Desktop","com.docker.backend","com.docker.service" -ErrorAction SilentlyContinue
if ($dockerProcs) {
    Log "Docker processes still running: $($dockerProcs.Name -join ', ')"
    Log "Attempting graceful stop..."
    Get-Process -Name "Docker Desktop" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3
}

# Stop Windows service if present
$svc = Get-Service -Name "com.docker.service" -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq "Running") {
    Log "Stopping com.docker.service"
    Stop-Service -Name "com.docker.service" -Force -ErrorAction SilentlyContinue
}

Log "wsl --shutdown"
wsl --shutdown
Start-Sleep -Seconds 5

# Ensure source exists
if (-not (Test-Path $SrcData)) {
    throw "Source not found: $SrcData"
}

New-Item -ItemType Directory -Force -Path $DstData | Out-Null
New-Item -ItemType Directory -Force -Path $DstHyperV | Out-Null

Log "Robocopy $SrcData -> $DstData"
# /MIR mirrors; first run use /E copy. Prefer /E + /COPY:DAT /R:2 /W:5 /MT:8
$rc = Start-Process -FilePath "robocopy.exe" -ArgumentList @(
    $SrcData, $DstData, "/E", "/COPY:DAT", "/R:2", "/W:5", "/MT:8", "/NFL", "/NDL", "/NP"
) -Wait -PassThru
# robocopy exit codes 0-7 are success-ish
Log "robocopy data exit=$($rc.ExitCode)"
if ($rc.ExitCode -ge 8) {
    throw "robocopy data failed with code $($rc.ExitCode)"
}

if (Test-Path $SrcHyperV) {
    Log "Robocopy $SrcHyperV -> $DstHyperV"
    $rc2 = Start-Process -FilePath "robocopy.exe" -ArgumentList @(
        $SrcHyperV, $DstHyperV, "/E", "/COPY:DAT", "/R:2", "/W:5", "/MT:8", "/NFL", "/NDL", "/NP"
    ) -Wait -PassThru
    Log "robocopy hyper-v exit=$($rc2.ExitCode)"
    if ($rc2.ExitCode -ge 8) {
        throw "robocopy hyper-v failed with code $($rc2.ExitCode)"
    }
}

# Verify critical vhdx
$vhdx = Join-Path $DstData "disk\docker_data.vhdx"
if (-not (Test-Path $vhdx)) {
    throw "Missing critical file after copy: $vhdx"
}
$vhdxSize = (Get-Item $vhdx).Length
Log "dst docker_data.vhdx size bytes=$vhdxSize"

# Backup and update settings
if (-not (Test-Path $Settings)) {
    throw "Docker settings not found: $Settings"
}
$bak = "$Settings.bak_$(Get-Date -Format yyyyMMdd_HHmmss)"
Copy-Item $Settings $bak -Force
Log "settings backup: $bak"

$json = Get-Content $Settings -Raw -Encoding UTF8 | ConvertFrom-Json
$json.CustomWslDistroDir = $DstData
$json.DataFolder = $DstHyperV
($json | ConvertTo-Json -Depth 10) | Set-Content -Path $Settings -Encoding UTF8
Log "Updated CustomWslDistroDir=$DstData"
Log "Updated DataFolder=$DstHyperV"

Log "=== Copy+settings done ==="
Log "NEXT:"
Log "  1) Start Docker Desktop"
Log "  2) docker info  (should work)"
Log "  3) docker images | measure"
Log "  4) Only after OK, manually delete D:\Docker\data to free D: (do NOT delete until verified)"
Log "=== migrate script finished successfully ==="
