<#
.SYNOPSIS
    Recursively converts NDJSON files in a folder structure using ConvertTo-Ctf.ps1,
    preserving the folder hierarchy and file names.

.PARAMETER SourceFolder
    Path to the root folder containing input NDJSON files.

.PARAMETER DestinationFolder
    Path to the destination root where converted files will be saved.


.PARAMETER FileFilter
    The filter of the files toread from the source folders.

.PARAMETER  Unzip
    Unzip the input files is needed before the conversion.

.EXAMPLE
    .\ConvertTo-CtfFolder.ps1 -SourceFolder "C:\Logs\EcfLogs" -DestinationFolder "C:\Logs\CtfLogs"

    This will read and convert all ECF logs from source folder and writes them to destination folder preserving subfolders.
#>

param (
    [Parameter(Mandatory = $true)]
    [string]$SourceFolder,
    [Parameter(Mandatory = $true)]
    [string]$DestinationFolder,
    [switch]$Unzip,
    [Parameter(Mandatory = $true)]
    [string]$FileFilter
)


if ($true -eq $Unzip) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
}

# Ensure destination root exists
if (!(Test-Path $DestinationFolder)) {
    Write-Host "ConvertTo-Ctf: Destination folder, does not exist. Creating."
    New-Item -ItemType Directory -Path $DestinationFolder | Out-Null
}

$SourceFolder = Resolve-Path -Path $SourceFolder
$DestinationFolder = Resolve-Path -Path $DestinationFolder

Write-Host "ConvertTo-Ctf: Reading log files from $SourceFolder"
if ($Unzip) {
    Write-Host "ConvertTo-Ctf: Input is Compressed."
}

# Get all .ndjson files recursively
$files = Get-ChildItem -Path $SourceFolder -Recurse -Filter "$FileFilter"
$total = $files.Count
$index = 0

foreach ($file in $files) {
    $index++
    $percent = [math]::Round(($index / $total) * 100)

    $relativePath = $file.FullName.Substring($SourceFolder.Length).TrimStart('\', '/')
    $destinationFile = Join-Path $DestinationFolder $relativePath
    $destinationFile = $destinationFile -replace "ndjson.gz", "ndjson" 
    $destinationPath = Split-Path $destinationFile

    # Ensure output folder exists
    if (!(Test-Path $destinationPath)) {
        New-Item -ItemType Directory -Path $destinationPath -Force | Out-Null
    }

    # Update progress bar
    Write-Progress -Activity "Converting (ECF->CTF) NDJSON files" `
                   -Status "$($file.Name) ($index of $total)"`
                   -PercentComplete $percent

    $filePath = $file.FullName

    if ($true -eq $Unzip) {
        # Open the original .gz file stream
        $inStream = [System.IO.File]::OpenRead($filePath)
        $gzStream = New-Object System.IO.Compression.GZipStream($inStream, [System.IO.Compression.CompressionMode]::Decompress)
        $reader = New-Object System.IO.StreamReader($gzStream)
        # Read decompressed lines and pipe them into the converter script
        $ctfArray = [System.Collections.Generic.List[object]]::new()
        while (-not $reader.EndOfStream) {
            $line = $reader.ReadLine()
            $ctfObj = $line | & "$PSScriptRoot\ConvertTo-Ctf.ps1" -MergeTls -CompleteTls
            $ctfArray.Add($ctfObj)
        }
        $ctfArray | Set-Content -Encoding UTF8 $destinationFile
        # Clean up
        $reader.Dispose()
        $gzStream.Dispose()
        $inStream.Dispose()
    } else {
        Get-Content $filePath | & "$PSScriptRoot\ConvertTo-Ctf.ps1" -MergeTls -CompleteTls | Set-Content -Encoding UTF8 $destinationFile
    }
}

# Complete the progress bar
Write-Progress -Activity "Converting (ECF->CTF) NDJSON files" -Completed -Status "Done."
Write-Host "ConvertTo-Ctf: Done. Converted $($files.Count) file(s). Output written to: $DestinationFolder"