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

## Possible Issues

### tshark has not permission to run Lua scripts

When executing tshark with lua script the following error occurs:

```“You don't have permission to read the file”```

Consider that this error occurs when you execute:

```bash
$ tshark -X lua_script:"a.lua"

tshark: You don't have permission to read the file "a.lua".
```

One possible reason can be that AppArmor is blocking TShark from reading arbitrary Lua files, which shows up as the misleading “You don't have permission to read the file” error—even if the file is 644.

Troubleshooting:

1. Confirm Lua is compiled in and enabled: 
```bash
tshark -v | grep -i lua        # should mention Lua
echo $WIRESHARK_ENABLE_LUA     # should print 1
```

2. Rule out simple FS perms / path
```
pwd
ls -l a.lua                     # expect -rw-r--r--
stat .                          # directory must have x (execute) bit
tshark -X lua_script:"$PWD/a.lua"
```

3. Check for AppArmor denials
```
sudo aa-status | grep -E 'tshark|wireshark'
   tshark//dumpcap
   tshark
```
4. Try to relax AppArmor for TShark
```
sudo aa-complain /usr/bin/tshark
# or (stronger) temporarily disable the profile
sudo aa-disable /usr/bin/tshark
sudo systemctl reload apparmor
```
5. Adjust AppArmor configuration for tshark
If the issue is caused by AppArmor, edit the configuration in the /etc/apparmor.d/local/usr.bin.tshark file by adding the trusted folders.
```
/path/to/other/folder/** r,
```
and then reload the module:
```
sudo apparmor_parser -r /etc/apparmor.d/usr.bin.tshark
sudo systemctl reload apparmor
```




