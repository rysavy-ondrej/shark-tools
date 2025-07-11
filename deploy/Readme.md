# Deployment to Monitoring Machine

This guide explains how to automatically deploy the **network capture agent** to a target monitoring machine.
Currently, only **Ubuntu Server** systems using **Netplan** are supported.

---

## Prerequisites

Before deploying, ensure the following tools are installed on the target machine:

* **PowerShell** (pwsh)
* **Git**
* **tshark**

To allow non-root users to capture packets, add your user to the `wireshark` group:

```bash
sudo usermod -a -G wireshark $USER
```

> **Note:** You must log out and log back in for this change to take effect.

Verify that packet capture works on the target interface before proceeding.

---

## Automated Deployment via PowerShell

To deploy the capture agent automatically, open a **PowerShell session** on the target machine in the directory where you want the tool installed, and run:

```pwsh
iex (iwr "https://raw.githubusercontent.com/rysavy-ondrej/shark-tools/main/deploy/Deploy-AsService.ps1")
```

> This script will:
>
> * Prompt for the capture interface
> * Clone the repository
> * Configure Netplan
> * Install and enable the capture agent as a systemd service

