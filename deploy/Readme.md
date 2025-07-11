# Deployment to Monitoring machine


## Prerequisities

Check that yoiu have PowerShell, Git and tshark installed.

Enable no root users to use dumpcap:

```bash
sudo usermod -a -G wireshark $USER
```
Need to login again aftet this command. 

Test that you can capture on the machine interface.


## Deployment using PowerShell Script

To automatically deploy to target system execute the following command in the PowerShell session 
and the folder in which the tooll should be deployed. 

Before the execution find the name of the interface used for monitoring:

```pwsh
ip address

iex (iwr "https://raw.githubusercontent.com/rysavy-ondrej/shark-tools/main/deploy/Deploy-AsService.ps1")
```