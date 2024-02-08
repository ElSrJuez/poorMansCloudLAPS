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
2. Create Resource Group or use an existing
2. Create a KeyVault in a region of your choice
3. Create a simple [AzureAD Enterprise Application](https://learn.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app)
4. Set Permissions in your KeyVault using a [Vault access Policy](https://learn.microsoft.com/en-us/azure/key-vault/general/assign-access-policy?tabs=azure-portal)
5. Create a Log Analytics workspace [https://learn.microsoft.com/en-us/azure/azure-monitor/logs/quick-create-workspace?tabs=azure-portal]

## Creating a parameters file
1. Create a copy of the parameters xml file template
2. Modify line 19, 20 and 21 to the IDs of your Azure Tenant, App ID and App Secret

## Installation of simpleLAPS.ps1
1. On a test computer, create a folder like C:\Temp\CloudLAPS
2. Clone this repo or download the CloudLAPS.ps1 file
3. Copy the xml file using CloudLAPS.xml file name.
4. Open a powershell prompt, change to the folder and run the script.
5. Check the local log file for a succesful result
6. Check the Log Analytics workspace for activity
7. Check the Key Vault for the updated secret
9. If all works, create a Scheduled Task that runs this script as SYSTEM with the desired frequency.
