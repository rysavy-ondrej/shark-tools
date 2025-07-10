# Dataset Automation

The dataset consisting of TLS connection logs separated to individual hosts can be synthetized automaticallz by following the steps in this document.



```pwsh
param(
[string]
$CaptureAgent,       # name of the capture agent, with enable SSH access
[string]
$RemoteRootFolder,   # the root folder of the remote data location 
[string]       
$DestinationFolder,  # The Local path where to store the results
[datetime]
$SourceDate
)

$remoteSubFolder = $SourceDate.Date.ToString("yyyy/MM/dd")
$remotePath = Join-Path $RemotePath $DateSubfolder
$ecfTempPath = [System.IO.Path]::GetTempFileName()
$ctfTempPath = [System.IO.Path]::GetTempFileName()

Sync-LogsFromSSH.ps1 -RemoteHost $CaptureAgent -RemotePath $RemotePath -LocalPath $ecfTempPath -FilePattern "*.ndjson.gz"

ConvertTo-CtfFolder.ps1 -SourceFolder $ecfTempPath -DestinationFolder $ctfTempPath

Split-LogsByKey.ps1 -FilePattern "*.ndjson" -SourceFolder $ctfTempPath -DestinationFolder $DestinationFolder -SelectKeyScript { param($x) $x.sa } -FilterScript { param($x) $x.sa.StartsWith("192.168.") }

# TODO: remove temp directories


```