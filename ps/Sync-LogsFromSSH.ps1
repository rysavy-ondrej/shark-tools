<#
.SYNOPSIS
    Downloads files from a remote SSH server if they do not exist locally.

.PARAMETER RemoteHost
    SSH hostname or alias (as defined in ~/.ssh/config or as full ssh user@host).

.PARAMETER RemotePath
    Path on the remote server where files are stored.

.PARAMETER LocalPath
    Local path to store downloaded files.

.PARAMETER FilePattern
    (Optional) Pattern to match specific files (e.g., *.json). Defaults to all files.

.EXAMPLE
    .\Sync-LogsFromSSH.ps1 -RemoteHost bedrock -RemotePath "/home/rysavy/shark/data" -LocalPath "../data/net.ecf" -FilePattern "*.ndjson.gz"
#>

param(
    [Parameter(Mandatory)]
    [string]$RemoteHost,

    [Parameter(Mandatory)]
    [string]$RemotePath,

    [Parameter(Mandatory)]
    [string]$LocalPath,

    [string]$FilePattern = "*"
)

# Ensure local path exists
if (-not (Test-Path $LocalPath)) {
    Write-Host "Creating local directory: $LocalPath"
    New-Item -Path $LocalPath -ItemType Directory | Out-Null
}


$remoteCommand = "ls -1 $RemotePath/$FilePattern"
$remoteFileList = & ssh $RemoteHost $remoteCommand

if (-not $remoteFileList) {
    Write-Warning "${RemoteHost}:${RemotePath}: No files found on remote server matching pattern '$FilePattern'."
    exit
}

# Get remote file list using ssh
Write-Host "Sync-LogsFromSSH: Getting $($remoteFileList.Count) files from ${RemoteHost}:${RemotePath}..."

# Get list of local files
$localFiles = Get-ChildItem -Path $LocalPath -File | Select-Object -ExpandProperty Name
$localFilesSet = [System.Collections.Generic.HashSet[string]]::new()
foreach ($item in $localFiles) {
    $localFilesSet.Add($item) | Out-Null
}

# Compare and download missing files
foreach ($remoteFile in $remoteFileList) {
    $remoteFileName = Split-Path -Path $remoteFile -Leaf  
    if (-not $localFilesSet.Contains($remoteFileName)) {
        # Write-Host "Downloading $remoteFile..."
        $scpSource = "${RemoteHost}:${remoteFile}"
        $scpTarget = Join-Path $LocalPath $remoteFileName

# scp -o ConnectTimeout=10 -o ServerAliveInterval=30 -o ServerAliveCountMax=3 user@host:/remote/file.txt C:\local\
# These settings help detect broken SSH connections faster and avoid indefinite hanging.
        & scp $scpSource $scpTarget
    }
    else {
        Write-Host "$remoteFileName exists, skipping."  
    }
}

Write-Host "Sync-LogsFromSSH: Sync complete."