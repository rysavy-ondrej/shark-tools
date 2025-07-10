param (
    [Parameter(Mandatory = $true)]
    [string] $CaptureAgent,       # Name of the capture agent with SSH access

    [Parameter(Mandatory = $true)]
    [string] $RemoteRootFolder,   # Root folder of the remote data location

    [Parameter(Mandatory = $true)]
    [string] $DestinationFolder,  # Local path where to store the results

    [Parameter(Mandatory = $true)]
    [datetime] $StartDate,        # Date of the source logs
    
    [int] $Days = 1               # How many days to read from the start date
)

for ($i = 0; $i -lt $Days; $i++) {

    $readDate = $StartDate.AddDays($i)
    # Build remote subfolder path: yyyy/MM/dd
    $remoteSubFolder = "$($readDate.Year)/$($readDate.Month.ToString("D2"))/$($readDate.Day.ToString("D2"))"

    $remotePath = Join-Path $RemoteRootFolder $remoteSubFolder
    # Create temporary folders (not files)
    $ecfTempPath = New-Item -ItemType Directory -Path ([System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), [System.Guid]::NewGuid().ToString())) -Force
    $ctfTempPath = New-Item -ItemType Directory -Path ([System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), [System.Guid]::NewGuid().ToString())) -Force

    try {
        # Step 1: Download logs from remote via SSH
        & "$PSScriptRoot\Sync-LogsFromSSH.ps1" -RemoteHost $CaptureAgent -RemotePath "$remotePath" -LocalPath $ecfTempPath.FullName -FilePattern "*.ndjson.gz"

        # Step 2: Convert logs to CTF format
        & "$PSScriptRoot\ConvertTo-CtfFolder.ps1" -FileFilter "*.ndjson.gz" -Unzip -SourceFolder $ecfTempPath.FullName -DestinationFolder $ctfTempPath.FullName

        # Step 3: Split logs by source IP key
        & "$PSScriptRoot\Split-LogsByKey.ps1" `
            -FilePattern "*.ndjson" `
            -SourceFolder $ctfTempPath.FullName `
            -DestinationFolder $DestinationFolder `
            -SelectKeyScript { param($x) $x.sa } `
            -FilterScript    { param($x) $x.sa.StartsWith("192.168.") }
    }
    finally {
        # Clean up temporary folders
        if (Test-Path $ecfTempPath.FullName) {
            Remove-Item -Path $ecfTempPath.FullName -Recurse -Force -ErrorAction SilentlyContinue
        }
        if (Test-Path $ctfTempPath.FullName) {
            Remove-Item -Path $ctfTempPath.FullName -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}