<#
.SYNOPSIS
    Processes log input and writes it to rotated, optionally compressed files.

.DESCRIPTION
    This script reads a stream of log entries from pipeline input and writes them into newline-delimited JSON (.ndjson) files.
    Files are rotated based on a fixed time interval. Optional gzip compression and structured folder organization by date 
    (year/month/day) are supported.

.PARAMETER IntervalMinutes
    The duration in minutes after which the output file should be rotated. A new file is created when this interval elapses.

.PARAMETER OutputDirectory
    The root directory where the output files will be stored. Created if it does not exist.

.PARAMETER Compress
    Switch to enable GZip compression of output files. If specified, files are saved with the .ndjson.gz extension.

.PARAMETER Structured
    Switch to enable structured output directories. If specified, output files will be placed in subdirectories
    organized by year/month/day (e.g., 2025/07/10/).

.PARAMETER InputObject
    The input lines to be processed. Should be provided via the pipeline. Only non-empty lines that do not start
    with '{"event"' will be written to the output.

.EXAMPLE
    Rotate-Json.ps1 network_log.txt | .\log_writer.ps1 -IntervalMinutes 10 -OutputDirectory "C:\Logs\Netflow" -Compress -Structured

    Reads from 'network_log.txt', rotates the output every 10 minutes, compresses the files, and saves them in structured subfolders.

.OUTPUTS
    Creates .ndjson or .ndjson.gz files in the specified directory.

.NOTES
    - Timestamps are in UTC and follow the format: yyyyMMddTHHmm.
    - Compression is handled using System.IO.Compression.GzipStream.
    - Designed for use in log collection and machine learning data preparation pipelines.
    - The script ensures directory creation and handles file rotation gracefully.

#>

param(
    [Parameter(Mandatory = $true)]
    [int]$IntervalMinutes,

    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory,

    [Parameter(Mandatory = $false)]
    [switch]$Compress,

    [Parameter(Mandatory = $false)]
    [switch]$Structured,  # when set, it will use year/month/day subfolders in the output directory

    [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
    [string[]]$InputObject
)

begin {
    if (!(Test-Path $OutputDirectory)) {
        New-Item -ItemType Directory -Path $OutputDirectory | Out-Null
    }

    $OutputDirectory = (Resolve-Path $OutputDirectory).Path
    Write-Host "Output directory is: $OutputDirectory."

    $currentBucketStart = [datetime]::UtcNow
    $fileNameBase = "capture_" + $currentBucketStart.ToString("yyyyMMddTHHmm")
    
    if ($Structured) {
        $OutputDirectoryPath = Join-Path $OutputDirectory $currentBucketStart.ToString("yyyy/MM/dd")
        if (!(Test-Path $OutputDirectoryPath)) {
            New-Item -ItemType Directory -Path $OutputDirectoryPath | Out-Null
        }
    } else {
        $OutputDirectoryPath = $OutputDirectory
    }

    if ($Compress) {
        $outputFile = Join-Path $OutputDirectoryPath ($fileNameBase + ".ndjson.gz")
        $fileStream = [System.IO.File]::Create($outputFile)
        $gzipStream = New-Object System.IO.Compression.GzipStream($fileStream, [System.IO.Compression.CompressionMode]::Compress)
        $streamWriter = New-Object System.IO.StreamWriter($gzipStream)
    } else {
        $outputFile = Join-Path $OutputDirectoryPath ($fileNameBase + ".ndjson")
        $streamWriter = [System.IO.StreamWriter]::new($outputFile, $true)
    }
}

process {
    foreach ($line in $InputObject) {
        if ($null -ne $line -and $line.Trim().Length -gt 0 -and -not ($line -like '{"event"*')) {
            $now = [datetime]::UtcNow

            if ($now -ge $currentBucketStart.AddMinutes($IntervalMinutes)) {
                # Close current file
                if ($streamWriter) {
                    $streamWriter.Flush()
                    $streamWriter.Close()

                    if ($Compress) {
                        $gzipStream.Close()
                        $fileStream.Close()
                    }

                    Write-Host "Rotated file at $now."
                }

                # Create new file
                $currentBucketStart = $now.AddSeconds(-$now.Second).AddMilliseconds(-$now.Millisecond)
                $fileNameBase = "capture_" + $currentBucketStart.ToString("yyyyMMddTHHmm")

                if ($Structured) {
                    $OutputDirectoryPath = Join-Path $OutputDirectory $currentBucketStart.ToString("yyyy/MM/dd")
                    if (!(Test-Path $OutputDirectoryPath)) {
                        New-Item -ItemType Directory -Path $OutputDirectoryPath | Out-Null
                    }
                } else {
                    $OutputDirectoryPath = $OutputDirectory
                }
                
                if ($Compress) {
                    $outputFile = Join-Path $OutputDirectoryPath ($fileNameBase + ".ndjson.gz")
                    $fileStream = [System.IO.File]::Create($outputFile)
                    $gzipStream = New-Object System.IO.Compression.GzipStream($fileStream, [System.IO.Compression.CompressionMode]::Compress)
                    $streamWriter = New-Object System.IO.StreamWriter($gzipStream)
                } else {
                    $outputFile = Join-Path $OutputDirectoryPath ($fileNameBase + ".ndjson")
                    $streamWriter = [System.IO.StreamWriter]::new($outputFile, $true)
                }

                Write-Host "Started new file: $outputFile"
            }

            # Write line
            $streamWriter.WriteLine($line)
        }
    }
}

end {
    if ($streamWriter) {
        $streamWriter.Flush()
        $streamWriter.Close()

        if ($Compress) {
            $gzipStream.Close()
            $fileStream.Close()
        }

        Write-Host "Final output file closed."
    }

    Write-Host "Processing complete."
}