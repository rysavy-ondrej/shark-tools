<#
.SYNOPSIS
Installs and configures a network capturing agent as a systemd service on the local Linux machine.

.DESCRIPTION
This script automates the deployment of a tshark-based capture service, running via PowerShell and systemd. It performs the following:

1. Displays network interfaces.
2. Prompts for the monitoring interface name.
3. Clones the `shark-tools` repository.
4. Configures a static netplan entry for the selected interface.
5. Creates two scripts:
   - `capture-tap.ps1`: Captures network traffic via tshark and processes it.
   - `kill-tap.sh`: Ensures any existing capture process is terminated.
6. Defines a `capture-tap.service` systemd unit to manage the service.
7. Enables, starts, and checks the status of the service.

.EXAMPLE
Run directly from GitHub:

    iex (iwr "https://raw.githubusercontent.com/rysavy-ondrej/shark-tools/main/deploy/Deploy-AsService.ps1")

.PARAMETER MonitorInterfaceId
The name of the network interface to use for monitoring (e.g., `eth0`, `enp0s3`).

.OUTPUTS
- `capture-tap.ps1`: PowerShell capture script.
- `kill-tap.sh`: Shell script to terminate tshark.
- `/etc/systemd/system/capture-tap.service`: Systemd unit file.
- System logs: `/var/log/capture-tap.out` and `/var/log/capture-tap.err`.

.NOTES
- Requires PowerShell Core, git, tshark, and systemd.
- Must be run with sudo privileges or as a user with rights to write to `/etc` and manage services.
- Designed for Linux systems with `netplan`.

.LINK
https://github.com/rysavy-ondrej/shark-tools

#>

$banner = @"
===============================================================
 Shark Tools – Network Capturing Agent Deployment Script
===============================================================

This script will install and configure a tshark-based network
capturing agent as a systemd service on your local Linux machine.

It will perform the following actions:
  • Clone the shark-tools Git repository
  • Set up static configuration via netplan for monitoring interface
  • Create a capture script and a shutdown script
  • Register and start a persistent systemd capture service 

---------------------------------------------------------------
 Requirements:
  • PowerShell Core (pwsh)
  • Git
  • tshark
  • systemd
  • sudo privileges (to write to /etc and manage services)
===============================================================
"@

Write-Host $banner -ForegroundColor Cyan

Write-Host ""
Write-Host "Host interfaces:"

$UserName = $env:USER

& ip address

Write-Host ""
$MonitorInterfaceId = Read-Host "Enter monitoring interface name"

$EnjoyRootPath = Get-Location

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Write-Error "Git is not installed or not in PATH."
    exit 1
}

# get the location of powershell:
$pwshPath = & which pwsh

& git clone https://github.com/rysavy-ondrej/shark-tools.git

if ($LASTEXITCODE -ne 0) {
    Write-Error "Git clone failed."
    exit 1
}

$captureInterfaceConfig = @"
network:
  version: 2
  ethernets:
    ${MonitorInterfaceId}:
      dhcp4: false
      dhcp6: false
      link-local: []
      accept-ra: false
      ipv6-privacy: false
      optional: true
      addresses: []
      wakeonlan: false
"@

$captureInterfaceConfig | sudo tee /etc/netplan/99-capture.yaml



Write-Host "Reloading Netplan configuration..."
& sudo netplan apply
& sudo ip link set $MonitorInterfaceId up

$captureTapPs1 = '$MonitorInterface="'+ $MonitorInterfaceId + '"' + @'

& tshark -q -X lua_script:$PSScriptRoot/shark-tools/lua/enjoy/enjoy.lua -X lua_script1:flush=60 -i $MonitorInterface -b duration:600 -w $PSScriptRoot/raw/raw.pcapng |
& $PSScriptRoot/shark-tools/ps/Rotate-Json.ps1 -IntervalMinutes 10 -OutputDirectory $PSScriptRoot/log -Compress -Structured
'@

$captureTapPs1 | Set-Content -Path capture-tap.ps1

$killTapSh = @'
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
'@

$killTapSh | Set-Content -Path kill-tap.sh
& chmod a+x kill-tap.sh

$captureTapService = @"
[Unit]
Description=Capture TAP PowerShell Script
After=network.target

[Service]
ExecStartPre=$EnjoyRootPath/kill-tap.sh
ExecStart=$pwshPath -File $EnjoyRootPath/capture-tap.ps1
Restart=always
RestartSec=10
User=$UserName
WorkingDirectory=$EnjoyRootPath
StandardOutput=append:/var/log/capture-tap.out
StandardError=append:/var/log/capture-tap.err

[Install]
WantedBy=multi-user.target
"@

$captureTapService | sudo tee /etc/systemd/system/capture-tap.service

& sudo systemctl daemon-reload
& sudo systemctl enable capture-tap.service
& sudo systemctl start capture-tap.service
& sudo systemctl status capture-tap.service
