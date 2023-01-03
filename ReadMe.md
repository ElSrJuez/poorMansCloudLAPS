# simpleLAPS
## _a simple solution for CloudOnly environments_
### Based on and inspired from leanLAPS from LiebenConsulting: [leanLAPS](https://www.lieben.nu/liebensraum/2021/06/lightweight-laps-solution-for-intune-mde/)

## Features
- does not require/modify registry keys
- does not store the password locally
- automatically renames the local admin account
- can remove any other local admin accounts if desired
- can whitelist approved admins or groups from AzureAD or Active Directory
- stores passwords and the password history in a safe place
- does not need additional PowerShell modules

## Prerequirements:
- Source code from here
- Licenses to have intune and "proactive remediation"
- Microsoft Azure

## Creation of Azure KeyVault
1. Logon to Azure
2. Create RessourceGroup or use an existing
2. Create a KeyVault in a region of your choice
3. Create a simple [AzureAD Enterprise Application](https://learn.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app)
4. Set Permissions in your KeyVault using a [Vault access Policy](https://learn.microsoft.com/en-us/azure/key-vault/general/assign-access-policy?tabs=azure-portal)

## Modification of the Script
1. Download the [Script](https://github.com/TrueKillRob/slaps/blob/main/simpleLAPS.ps1) to your computer
2. Modify line 19, 20 and 21 to the IDs of your Azure Tenant, App ID and App Secret

## Installation of simpleLAPS.ps1
1. Open your intune environment and go to Home --> Reports --> Endpoint analytics
2. Create a new custom Script
3. Define a name and description etc
4. Upload the modified simpleLAPS.PS1 as detection and as remediation
5. Disable "Run this Script using logged-on-credentials"
6. Disable "Enforce script signature check"
7. Enable "Run script in 64-bit PowerShell"
8. Assign the script to the destination computers
