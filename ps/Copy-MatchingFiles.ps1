<#
.SYNOPSIS
    Searches recursively for .ndjson files containing a specific string and copies them to an output folder with renamed filenames.

.PARAMETER InputFolder
    The root directory to search for .ndjson files.

.PARAMETER SearchString
    The string to search for within the .ndjson files.

.PARAMETER OutputFolder
    The destination directory for the matching files.

.EXAMPLE
    .\Copy-MatchingFiles.ps1 -InputFolder "C:\Data" -SearchString "malware" -OutputFolder "C:\Matched"

    This will search all .ndjson files under C:\Data for the string "malware" and copy any matching file to C:\Matched.
#>

param (
    [Parameter(Mandatory = $true)]
    [string]$InputFolder,

    [Parameter(Mandatory = $true)]
    [string]$SearchString,

    [Parameter(Mandatory = $true)]
    [string]$OutputFolder
)

# Ensure output folder exists
if (-not (Test-Path -Path $OutputFolder)) {
    New-Item -ItemType Directory -Path $OutputFolder | Out-Null
}

# Get all .ndjson files in subdirectories
$ndjsonFiles = Get-ChildItem -Path $InputFolder -Filter *.ndjson -Recurse -File

$totalFiles = $ndjsonFiles.Count
$currentIndex = 0

foreach ($file in $ndjsonFiles) {
    $currentIndex++
    $percentComplete = [math]::Round(($currentIndex / $totalFiles) * 100)

    $parentFolder = Split-Path -Path $file.DirectoryName -Leaf

    Write-Progress -Activity "Processing log files" -Status "$($parentFolder) $($file.Name)" -PercentComplete $percentComplete

    # Read file content as string
    $content = Get-Content -Path $file.FullName -Raw

    # Check if file contains the search string
    if ($content -like "*$SearchString*") {
        $newFileName = "$($file.BaseName)_$($parentFolder).ndjson"
        $destinationPath = Join-Path -Path $OutputFolder -ChildPath $newFileName

        Copy-Item -Path $file.FullName -Destination $destinationPath -Force
        Write-Host "Copied: $($file.FullName) -> $destinationPath"
    }
}
Write-Progress -Activity "Processing log files" -Completed -Status "All files processed"