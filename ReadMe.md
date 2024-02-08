# poorMansCloudLAPS
## _a simple solution for Servers_
### It all started from leanLAPS from LiebenConsulting: [leanLAPS](https://www.lieben.nu/liebensraum/2021/06/lightweight-laps-solution-for-intune-mde/)
### Forked from simpleLAPS from TrueKillRob:https://github.com/TrueKillRob/slaps/tree/main

## Features
- Does not require/modify registry keys
- Does not store the password locally
- Can automatically renames the local admin account
    - Can remove any other local admin accounts if desired
    - Can whitelist approved admins or groups from AzureAD or Active Directory
- Stores passwords in Azure Key Vault
- Logs activites to a Log Analytics Workspace
- Soes not need additional PowerShell modules
- Soes not use/need Intune

## Prerequirements:
- Source code from here
- A method for deploy files and scheduled tasks to intended computers
- Microsoft Azure Key Vault
- Microsoft Azure Log Analytics

## Creation of Azure KeyVault and Log Analytics Workspace
1. Logon to Azure
2. Create RessourceGroup or use an existing
2. Create a KeyVault in a region of your choice
3. Create a simple [AzureAD Enterprise Application](https://learn.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app)
4. Set Permissions in your KeyVault using a [Vault access Policy](https://learn.microsoft.com/en-us/azure/key-vault/general/assign-access-policy?tabs=azure-portal)
5. Create a Log Analytics workspace [https://learn.microsoft.com/en-us/azure/azure-monitor/logs/quick-create-workspace?tabs=azure-portal]

## Creating a parameters file
1. Create a copy of the parameters xml file template
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
