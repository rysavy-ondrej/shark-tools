<#
.SYNOPSIS
    Reads ndjson or read and decompresses .ndjson.gz log files from the source folder and split them by the given key field into subfolders.


.DESCRIPTION
    This script recursively scans an input folder for all `.ndjson.gz` files, decompresses each one,
    parses each line as JSON, extracts the key field, and writes each JSON line into an output
    folder structure organized by the key values. Each key value gets its own subfolder, and log entries
    from each input file are saved into corresponding files named after the original `.ndjson.gz` base name.

    Because of using ScriptBlock as parameters the cmdlet can process any NDJSON log files.

.PARAMETER SourceFolder
    The path to the folder containing source ndjson files to be processed.

.PARAMETER DestinationFolder
    The path to the output directory where split files will be written.
    Output is organized into subfolders by the specified key values.

.EXAMPLE
    ./Split-LogsByKey.ps1 -Unzip -FilePattern "*.ndjson.gz" -SourceFolder ./tests/ecf/ -DestinationFolder ./tests/ecf.split/ -SelectKeyScript { param($x) $x.ip.src } -FilterScript { param($x) $x.ip.src.StartsWith("192.168.") }

    This will read and decompress all `.ndjson.gz` files from ./tests/ecf/ and create per-IP output folders under ./tests/ecf.split/. It includes only connection sources from 192.168 prefix.

    ./Split-LogsByKey.ps1 -FilePattern "*.ndjson" -SourceFolder ./tests/ecf/ -DestinationFolder ./tests/ecf.split/ -SelectKeyScript { param($x) $x.ip.src } -FilterScript { param($x) $x.ip.src.StartsWith("192.168.") }

    This will read all `.ndjson` files from ./tests/ecf/ and create per-IP output folders under ./tests/ecf.split/. It includes only connection sources from 192.168 prefix.

.OUTPUTS
    Writes `.ndjson` files to disk inside subfolders named after the key values.
#>

param(
    [string]$SourceFolder,
    [string]$DestinationFolder,
    [string]$FilePattern,
    [ScriptBlock]$SelectKeyScript,    
    [ScriptBlock]$FilterScript = { param($x) $true } 
)

$SourceFolder = (Get-Item $SourceFolder).FullName
$DestinationFolder = (Get-Item $DestinationFolder).FullName

Write-Host "Split-LogsByKey: Reading log files from $SourceFolder"

if (!(Test-Path $DestinationFolder)) {
    Write-Host "Split-LogsByKey: Destination folder, does not exist. Creating."
    New-Item -ItemType Directory -Path $DestinationFolder | Out-Null
}

# Get all .ndjson.gz files
$files = Get-ChildItem -Path $SourceFolder -Filter "$FilePattern"
$totalFiles = $files.Count
$currentIndex = 0

foreach ($file in $files) {
    $currentIndex++
    $percentComplete = [math]::Round(($currentIndex / $totalFiles) * 100)
    
    Write-Progress -Activity "Splitting log files" -Status "$($file.Name) ($currentIndex of $totalFiles)" -PercentComplete $percentComplete

    $filePath = $file.FullName  # this include the path and name
    $fileName = $file.Name  # eg. capture_20250508T2254.ndjson

    # Read and split lines by source IP
    Get-Content -Path $filePath | ForEach-Object {
        # sanity check, is it JSON line?
        if ($_ -match '^\s*\{.*\}\s*$') {
            $json = $_ | ConvertFrom-Json

            $key = & $SelectKeyScript $json
            $accept = & $FilterScript $json

            # Write-Host "Record: $($json.ip), Key=$key, Accept=$accept"
            if ($key -and $accept) {
                $targetKeyFolder = Join-Path $DestinationFolder $key
                if (!(Test-Path $targetKeyFolder)) {
                    New-Item -ItemType Directory -Path $targetKeyFolder | Out-Null
                }

                $outFile = Join-Path $targetKeyFolder "$fileName"
                Add-Content -Path $outFile -Value $_
            }
        }
    }

    if ($null -ne $tempPath)
    {
        Remove-Item $tempPath
    }
}

Write-Progress -Activity "Splitting log files" -Completed -Status "Done."
Write-Host "Split-LogsByKey: Done. Splitted $totalFiles file(s). Output written to $DestinationFolder."