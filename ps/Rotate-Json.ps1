param(
    [Parameter(Mandatory = $true)]
    [int]$IntervalMinutes,

    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory,

    [Parameter(Mandatory = $false)]
    [bool]$Compress = $false,

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
    
    if ($Compress) {
        $outputFile = Join-Path $OutputDirectory ($fileNameBase + ".ndjson.gz")
        $fileStream = [System.IO.File]::Create($outputFile)
        $gzipStream = New-Object System.IO.Compression.GzipStream($fileStream, [System.IO.Compression.CompressionMode]::Compress)
        $streamWriter = New-Object System.IO.StreamWriter($gzipStream)
    } else {
        $outputFile = Join-Path $OutputDirectory ($fileNameBase + ".ndjson")
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
                
                if ($Compress) {
                    $outputFile = Join-Path $OutputDirectory ($fileNameBase + ".ndjson.gz")
                    $fileStream = [System.IO.File]::Create($outputFile)
                    $gzipStream = New-Object System.IO.Compression.GzipStream($fileStream, [System.IO.Compression.CompressionMode]::Compress)
                    $streamWriter = New-Object System.IO.StreamWriter($gzipStream)
                } else {
                    $outputFile = Join-Path $OutputDirectory ($fileNameBase + ".ndjson")
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