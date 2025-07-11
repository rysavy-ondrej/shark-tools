# Install the network capturing agent as a service at the local host:
#
# Run this command from the powershell on the target machine in the root folder:
#
# iex (iwr "https://raw.githubusercontent.com/rysavy-ondrej/shark-tools/main/deploy/Deploy-AsService.ps1")
#
# iwr "https://raw.githubusercontent.com/rysavy-ondrej/shark-tools/main/deploy/Deploy-AsService.ps1" -OutFile "install.ps1"; & .\install.ps1; rm .\install.ps1
# 


# iwr -useb "https://raw.githubusercontent.com/rysavy-ondrej/shark-tools/main/deploy/Deploy-AsService.ps1" | iex


Write-Host "Host interfaces:"

& ip address

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
    $MonitorInterfaceId:
      dhcp4: false
      dhcp6: false
      link-local: []
      accept-ra: false
      ipv6-privacy: false
      optional: true
      addresses: []
      wakeonlan: false
"@

$captureInterfaceConfig | Set-Content -Path /etc/netplan/99-capture.yaml

$captureTapPs1 = @'
$scriptPath = $PSScriptRoot
tshark -q -X lua_script:$scriptPath/shark-tools/lua/enjoy/enjoy.lua -X lua_script1:flush=1 -i "MONITOR" |
& $scriptPath/shark-tools/ps/Rotate-Json.ps1 -IntervalMinutes 10 -OutputDirectory ./data -Compress $true
'@

$captureTapPs1 | Set-Content -Path capture-tap.ps1

$killTapPs1 = @'
#!/bin/bash
# Try to kill the process using pkill
/usr/bin/pkill tshark

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

$killTapPs1 | Set-Content -Path kill-tap.ps1

$captureTapService = @"
[Unit]
Description=Capture TAP PowerShell Script
After=network.target

[Service]
ExecStartPre=$EnjoyRootPath/kill-tap.sh
ExecStart=$pwshPath -File $EnjoyRootPath/capture-tap.ps1
Restart=always
RestartSec=10
User=USERNAME
WorkingDirectory=$EnjoyRootPath
StandardOutput=append:/var/log/capture-tap.out
StandardError=append:/var/log/capture-tap.err

[Install]
WantedBy=multi-user.target
"@

<#

$captureTapService | Set-Content -Path /etc/systemd/system/capture-tap.service

& sudo systemctl daemon-reload
& sudo systemctl enable capture-tap.service
& sudo systemctl start capture-tap.service
& sudo systemctl status capture-tap.service

#>