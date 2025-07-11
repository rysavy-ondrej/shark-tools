# Deployment to Monitoring machine

To automatically deploy to target system execute the following command in the PowerShell session 
and the folder in which the tooll should be deployed. 

Before the execution find the name of the interface used for monitoring:

```pwsh
ip address

iex (iwr "https://raw.githubusercontent.com/rysavy-ondrej/shark-tools/main/deploy/Deploy-AsService.ps1")
```