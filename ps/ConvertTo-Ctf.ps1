<#
.SYNOPSIS
    Converts and aggregates network connection records from EnjoyConnectionFormat (ECF) to Compact TLS Format (CTF).

.DESCRIPTION
    This script reads NDJSON input line by line, either from standard input or through a pipeline.
    It merges connection parts by "id" if multiple entries are received for the same connection,
    ensuring that fields such as TLS records and packet/byte counters are properly aggregated.

.PARAMETER OnlyTls
    If specified, the script will only process records that include TLS metadata.

.PARAMETER MergeTls
    If specified, the script will merge multiple parts of a TLS connection based on the "id" field.

.PARAMETER Sample
    An optional label to include in each output record under the 'sample' field.

.PARAMETER Line
    A single NDJSON input line (JSON object as string). Used when input is passed via pipeline.

.EXAMPLE
    Get-Content input.ndjson | .\ConvertTo-Ctf.ps1 -MergeTls > output.ndjson

.INPUTS
    System.String

.OUTPUTS
    System.String (NDJSON-formatted Compact TLS Connection record)

.NOTES
    Version: 2.0
    Date: 2025-06-04
#>

param (
    [switch]$CompleteTls = $false,
    [switch]$MergeTls = $false,
    [string]$Sample = "",
    [Parameter(ValueFromPipeline=$true)]
    [string]$Line
)

begin {
    if ($MergeTls) {
        $connectionMap = @{}
    }

    function Test-RemoveIp {
    param (
            [string]$DestinationAddress
        )
        # Connections blocked by OpenDNS:
        return @( "146.112.61.106", "146.112.196.4", "66.254.114.41" ) -contains $DestinationAddress
    }
}



process {



    if ([string]::IsNullOrWhiteSpace($Line)) { return }

    try {
        $entry = $Line | ConvertFrom-Json

        if ($null -eq $entry.tls) {
            return
        }

        $id = $entry.id

        # Original single-record mode
        if ($MergeTls) {
            if (-not $connectionMap.ContainsKey($id)) {
                  $connectionMap[$id] = [ordered]@{
                    pt = $entry.ip.proto
                    sa = $entry.ip.src
                    sp = $entry.tcp.srcport
                    da = $entry.ip.dst
                    dp = $entry.tcp.dstport
                    ps = 0; pr = 0; bs = 0; br = 0
                    ts = $entry.ts
                    te = $entry.ts + $entry.td
                    'tls.rec' = @()
                }
            }

            $out = $connectionMap[$id]
            $out.ps += $entry.ip.psent
            $out.pr += $entry.ip.precv
            $out.bs += $entry.ip.bsent
            $out.br += $entry.ip.brecv
            $out.ts = [math]::Round([Math]::Min($out.ts, $entry.ts),3)
            $out.te = [math]::Round([Math]::Max($out.te, $entry.ts + $entry.td),3)

            if ($entry.tls) {
                if ($entry.tls.recs) {
                    $out.'tls.rec' += $entry.tls.recs | ForEach-Object {
                        $len = $_.len
                        if ($_.dir -eq -1) { -1 * $len } else { $len }
                    }
                }

                if ($entry.tls.cver)      { $out.'tls.cver' = "0x$($entry.tls.cver)" }
                if ($entry.tls.sver)      { $out.'tls.sver' = "0x$($entry.tls.sver)" }
                if ($entry.tls.cciphers)  { $out.'tls.ccs'  = $entry.tls.cciphers }
                if ($entry.tls.cexts)     { $out.'tls.cext' = $entry.tls.cexts }
                if ($entry.tls.csigs)     { $out.'tls.csg'  = $entry.tls.csigs }
                if ($entry.tls.csvers)    { $out.'tls.csv'  = $entry.tls.csvers }
                if ($entry.tls.alpn)      { $out.'tls.alpn' = $entry.tls.alpn }
                if ($entry.tls.sni)       { $out.'tls.sni'  = $entry.tls.sni }
                if ($entry.tls.scipher)   { $out.'tls.scs'  = "0x$($entry.tls.scipher)" }
                if ($entry.tls.sexts)     { $out.'tls.sext' = $entry.tls.sexts }
                if ($entry.tls.ssvers)    { $out.'tls.ssv'  = $entry.tls.ssvers }
                if ($entry.tls.ja3)       { $out.'tls.ja3'  = $entry.tls.ja3 }
                if ($entry.tls.ja3s)      { $out.'tls.ja3s' = $entry.tls.ja3s }
            }
        }
        else {
            # Original single-record mode
            $out = [ordered]@{
                pt = $entry.ip.proto
                sa = $entry.ip.src
                sp = $entry.tcp.srcport
                da = $entry.ip.dst
                dp = $entry.tcp.dstport
                ps = $entry.ip.psent
                pr = $entry.ip.precv
                bs = $entry.ip.bsent
                br = $entry.ip.brecv
                ts = [math]::Round($entry.ts, 3)
                td = [math]::Round($entry.td, 3)
            }

            if ($entry.tls -and $entry.tls.recs) {
                $out.'tls.rec' = $entry.tls.recs | ForEach-Object {
                    $len = $_.len
                    if ($_.dir -eq -1) { -1 * $len } else { $len }
                }
            }

            if ($entry.tls) {
                if ($entry.tls.cver)      { $out.'tls.cver' = "0x$($entry.tls.cver)" }
                if ($entry.tls.sver)      { $out.'tls.sver' = "0x$($entry.tls.sver)" }
                if ($entry.tls.cciphers)  { $out.'tls.ccs'  = $entry.tls.cciphers }
                if ($entry.tls.cexts)     { $out.'tls.cext' = $entry.tls.cexts }
                if ($entry.tls.csigs)     { $out.'tls.csg'  = $entry.tls.csigs }
                if ($entry.tls.csvers)    { $out.'tls.csv'  = $entry.tls.csvers }
                if ($entry.tls.alpn)      { $out.'tls.alpn' = $entry.tls.alpn }
                if ($entry.tls.sni)       { $out.'tls.sni'  = $entry.tls.sni }
                if ($entry.tls.scipher)   { $out.'tls.scs'  = "0x$($entry.tls.scipher)" }
                if ($entry.tls.sexts)     { $out.'tls.sext' = $entry.tls.sexts }
                if ($entry.tls.ssvers)    { $out.'tls.ssv'  = $entry.tls.ssvers }
                if ($entry.tls.ja3)       { $out.'tls.ja3'  = $entry.tls.ja3 }
                if ($entry.tls.ja3s)      { $out.'tls.ja3s' = $entry.tls.ja3s }
            }

            if ($Sample -ne "") { $out.sample = $Sample }
            
            # export depending on the CompleteTls switch and record content:
            if (-not ($CompleteTls -and -not ($out.'tls.cver' -and $out.'tls.sver'))) {

                if (-not (Test-RemoveIp $out.da))
                {
                    $out | ConvertTo-Json -Depth 10 -Compress
                }
            }
        }
    }
    catch {
        Write-Warning "Could not parse or convert line: $_"
    }
}



end {
    if ($MergeTls) {
        foreach ($out in $connectionMap.Values) {
            if ($Sample -ne "") { $out.sample = $Sample }
            # export depending on the CompleteTls switch and record content:
            if (-not ($CompleteTls -and -not ($out.'tls.cver' -and $out.'tls.sver'))) {
                if (-not (Test-RemoveIp $out.da))
                {
                    $out | ConvertTo-Json -Depth 10 -Compress
                }
            }
        }
    }
}
