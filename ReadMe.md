# poorMans CloudLAPS
## _a simple solution for Servers_
### It all started from leanLAPS from LiebenConsulting: [leanLAPS](https://www.lieben.nu/liebensraum/2021/06/lightweight-laps-solution-for-intune-mde/)
### Forked from simpleLAPS from TrueKillRob:https://github.com/TrueKillRob/slaps/tree/main

## Features
- Does not require/modifying registry keys
- Does not store passwords locally
- Can automatically rename the local Administrator account
    - Can remove/cleanup any other local admin accounts
    - Administrators group Cleanup can be filtered by SID
- Stores passwords in Azure Key Vault using Computer Name
- Authentication using Azure App
- Maximum possible security - App only requires 'Set Secret' permission on key vault (Cannot read secrets)
- Logs activites to a Log Analytics Workspace **
- Does not need external PowerShell modules
- Does not use/need Intune
- Uses Windows Password expiration policy to establish password reset cadence

## Prerequirements:
- Source code from here
- A method for deploy files and scheduled tasks to intended computers
- Microsoft Azure Key Vault
- Microsoft Azure Log Analytics

## Creation of Azure KeyVault and Log Analytics Workspace
1. Logon to Azure
2. Create Resource Group or use an existing
2. Create a KeyVault in a region of your choice
4. Set Permissions in your KeyVault using [RBAC](https://learn.microsoft.com/en-gb/azure/key-vault/general/rbac-guide?tabs=azurepowershell)
    - Create a custom role with 'Microsoft.KeyVault/vaults/secrets/setSecret/action' permissions
    - Create an Entra ID App [Entra ID App Registration](https://learn.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app)
    - Assign the custom role, assign to principal: (https://learn.microsoft.com/en-us/entra/identity-platform/howto-create-service-principal-portal)
    - Create an [App Secret](https://learn.microsoft.com/en-us/entra/identity-platform/howto-create-service-principal-portal)
6. Create a Log Analytics workspace [https://learn.microsoft.com/en-us/azure/azure-monitor/logs/quick-create-workspace?tabs=azure-portal]

## Creating a parameters file
1. Create a copy of the parameters xml file template
2. Modify parameters as needed

## Installation of CloudLAPS.ps1
1. On a test computer, create a folder like C:\Temp\CloudLAPS
2. Clone this repo or download the CloudLAPS.ps1 file
3. Copy the xml file using CloudLAPS.xml file name into the same folder.
4. Open a powershell prompt, change to the folder and run the script.
5. Check the local Application log file for a succesful result
6. Check the Log Analytics workspace for activity **
7. Check the Key Vault for the updated secret
9. If all works, create a Scheduled Task that runs this script as SYSTEM with the desired frequency.
