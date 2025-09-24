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


## Install as a service

The scripts provided can be used to capture communication in the local network. To deploy them, follow these steps:

### Configure Router
* Set up port mirroring or a TAP at a suitable point in the network (typically the LAN gateway router). Below is an example configuration for a MikroTik router, mirroring all traffic from ether2 to ether5. This assumes the LAN is connected to ether2.

```
/interface ethernet switch set switch1 mirror-source=ether2 mirror-target=ether5
```

### Configure the Monitoring Host

1. **Prepare the monitoring interface**

   Choose a Linux host for monitoring the LAN traffic. Use a dedicated interface named `MONITOR` configured for passive monitoring (no IP address, no outgoing traffic).

   Create the Netplan configuration file `/etc/netplan/99-capture.yaml` with the following content:

   ```yaml
   network:
     version: 2
     ethernets:
       MONITOR:
         dhcp4: false
         dhcp6: false
         link-local: []
         accept-ra: false
         ipv6-privacy: false
         optional: true
         addresses: []
         wakeonlan: false
   ```

2. **Create the capture script**

   Create `/home/USERNAME/shark/capture-tap.ps1` with the following content:

   ```pwsh
   $scriptPath = $PSScriptRoot
   
   tshark -q -X lua_script:$scriptPath/shark-tools/lua/enjoy/enjoy.lua -X lua_script1:flush=60 -i "MONITOR" |
   & $scriptPath/shark-tools/ps/Rotate-Json.ps1 -IntervalMinutes 10 -OutputDirectory ./data -Compress -Structured
   ```

3. **Create capture termination script**
   Create `/home/USERNAME/shark/kill-tap.sh` with the following content:

    ```bash
    #!/bin/bash
    # Try to kill the process using pkill
    /usr/bin/pkill tshark
    rm /tmp/*.pcapng
    
    # Capture the exit code of the pkill command
    exit_code=$?
    
    # Check the exit code and handle accordingly
    if [ $exit_code -eq 0 ]; then
        echo "Process terminated successfully."
        exit 0  # Success
    elif [ $exit_code -eq 1 ]; then
        echo "No matching processes found."
        exit 0  # No process to kill, but still consider as success
    else
        echo "An error occurred with pkill."
        exit 1  # Error
    fi
    ```

5. **Create the systemd service**

   Create `/etc/systemd/system/capture-tap.service`:

   ```ini
   [Unit]
   Description=Capture TAP PowerShell Script
   After=network.target

   [Service]
   ExecStartPre=/home/USERNAME/shark/kill-tap.sh
   ExecStart=/snap/bin/pwsh -File /home/USERNAME/shark/capture-tap.ps1
   Restart=always
   RestartSec=10
   User=USERNAME
   WorkingDirectory=/home/USERNAME/shark
   StandardOutput=append:/var/log/capture-tap.out
   StandardError=append:/var/log/capture-tap.err

   [Install]
   WantedBy=multi-user.target
   ```

   **Notes:**

   * Replace `USERNAME` with your actual Linux username.
   * Confirm the correct path to PowerShell (`pwsh`) using `which pwsh` (e.g., `/usr/bin/pwsh` or `/snap/bin/pwsh`).
   * Logs will be written to `/var/log/capture-tap.out` and `/var/log/capture-tap.err`.

4. **Enable and start the service**

   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable capture-tap.service
   sudo systemctl start capture-tap.service
   ```

5. **Verify service status**

   ```bash
   sudo systemctl status capture-tap.service
   ```
