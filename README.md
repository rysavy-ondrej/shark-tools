# shark-tools

A collection of tools for packet/flow processing based on tshark.

## Enjoy Lua Tool

[Enjoy](lua/enjoy/README.md) is a lua module that extracts detailed connection (bidirectional flow) information from network packets.



## Rotate-Json PowerShell Tool

This script provides a way to rotate and optionally compress Newline Delimited JSON (NDJSON) output received from a pipeline (e.g., from tshark) into manageable file chunks.

It is intended for use in long-running capture sessions where:
* File size needs to stay reasonable,
* Data should be organized over time,
* Storage efficiency is important.

✨ Features
* File rotation: Create a new file every N minutes to control file size.
* On-the-fly compression: Optionally compress each output file immediately as it is written (.ndjson.gz).
* Stream processing: Handles live input efficiently via pipeline (|).
* Safe and atomic: Ensures all files are flushed and closed properly before switching to the next file.
* Flexible: Works with any NDJSON-producing tool, not just tshark.

### Usage

Capture NDJSON without compression

```shell
tshark -q -X lua_script:lua\enjoy\enjoy.lua -X lua_script1:flush=10 -i "Ethernet 2" |
    .\ps\Rotate-Json.ps1 -IntervalMinutes 1 -OutputDirectory .\examples\out\
```

* Rotates output files every 1 minute.
* Produces plain .ndjson files (no compression).
* Files are named based on the UTC start time, for example:
capture_20240501T1210.ndjson

Capture NDJSON with compression enabled

```shell
tshark -q -X lua_script:lua\enjoy\enjoy.lua -X lua_script1:flush=10 -i "Ethernet 2" |
    .\ps\Rotate-Json.ps1 -IntervalMinutes 1 -OutputDirectory .\examples\out\ -Compress $true
```

* Same behavior as above but compresses output on the fly.
* Creates .ndjson.gz compressed files directly, for example:
capture_20240501T1210.ndjson.gz
* Compression typically reduces file size by a factor of 10×.

#### Parameters


| Parameter | Description | 	Required |	Example |
| ---- | ---- | ---- | ---- |
| -IntervalMinutes |	How often to rotate files (in minutes). | 	✅ |	1, 5, 10 | 
| -OutputDirectory |	Target directory where output files are stored. |	✅ |	.\\examples\\out\\ |
| -Compress |	Whether to compress files using Gzip on-the-fly. |	Optional (default: $false) |	$true |

#### Notes
* The Lua script (enjoy.lua) is responsible for formatting tshark’s output as NDJSON.
* Rotation and compression are based on the system UTC clock, ensuring consistent file naming.
* If the output directory does not exist, it will be created automatically.
