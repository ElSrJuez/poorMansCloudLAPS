<#
    .DESCRIPTION
    CloudLAPS is a simple solution for Servers
    https://github.com/ElSrJuez/poorMansCloudLAPS
    This script will create a base configuration CloudLAPS-template.xml file
    
    Create a config file:
    1. Adjust values below
    2. Run script code
#>
$cloudLAPSConfig = New-Object PSObject
$cloudLAPSConfig | Add-Member -NotePropertyName Debug -NotePropertyValue $true
# If Enabled, the Password and Accounts will not be changed. KeyVault will be used
$cloudLAPSConfig | Add-Member -NotePropertyName WhatIf  -NotePropertyValue $true 
$cloudLAPSConfig | Add-Member -NotePropertyName minimumPasswordLength -NotePropertyValue 21
# password will be changed only if has less than days from Windows maximum password age policy
$cloudLAPSConfig | Add-Member -NotePropertyName PolicyGracePeriodDays -NotePropertyValue 15
# ID of Entra ID Tenant where AZKeyVault and Log Analytics Workspace are located
$cloudLAPSConfig | Add-Member -NotePropertyName tenantID -NotePropertyValue "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
# Entra ID App ID for Authentication
$cloudLAPSConfig | Add-Member -NotePropertyName AZAppID -NotePropertyValue "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy"
# Secret for AZAppID
$cloudLAPSConfig | Add-Member -NotePropertyName AZAppSecret -NotePropertyValue "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
# Azure Key Vault Name
$cloudLAPSConfig | Add-Member -NotePropertyName AZVaultName -NotePropertyValue "KeyVault-01"
# ID of Azure Log Analytics Workspace
$cloudLAPSConfig | Add-Member -NotePropertyName AzLAWorkspaceID -NotePropertyValue "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
# Secret of Azure Log Analytics Workspace
$cloudLAPSConfig | Add-Member -NotePropertyName AzLAWorkspaceSecret -NotePropertyValue "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
# Set to True if renaming the local Administrator account is needed. Specify new name with localAdminName 
$cloudLAPSConfig | Add-Member -NotePropertyName renameAdminAccount -NotePropertyValue $false
# Name of the local Administrator account. Needed for conformance and required if renameAdminAccount is set to $true
$cloudLAPSConfig | Add-Member -NotePropertyName localAdminName -NotePropertyValue "admin1"
# if set to True, will remove ALL other local admins, including those set through Entra ID device settings
$cloudLAPSConfig | Add-Member -NotePropertyName removeOtherLocalAdmins -NotePropertyValue $False
# _REQUIRED_: When changing password the account expiration tattoo will also be set! False enables expiration policy to control rotation cadence.
$cloudLAPSConfig | Add-Member -NotePropertyName PasswordNeverExpires -NotePropertyValue $False

# To be deprecated, this tool is mostly useful on servers!
# $cloudLAPSConfig | Add-Member -NotePropertyName doNotRunOnServers -NotePropertyValue $True
$approvedAdmins = @( #specify SID's for Azure groups such as Global Admins and Device Administrators or for local or domain users to not remove from local admins. These are specific to your tenant, you can get them on a device by running: ([ADSI]::new("WinNT://$($env:COMPUTERNAME)/$((New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")).Translate([System.Security.Principal.NTAccount]).Value.Split("\")[1]),Group")).Invoke('Members') | % {"$((New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList @([Byte[]](([ADSI]$_).properties.objectSid).Value, 0)).Value) <--- a.k.a: $(([ADSI]$_).Path.Split("/")[-1])"}
"S-1-12-1-2296310142-aaaaaaaaaa-aaaaaaaaa-aaaaaaaaaa"
"S-1-12-1-465010940-bbbbbbbbbb-bbbbbbbbbb-bbbbbbbbb"
)
$cloudLAPSConfig | Add-Member -NotePropertyName approvedAdmins -NotePropertyValue $approvedAdmins

$cloudLAPSConfig | Export-Clixml -Path CloudLAPS-template.xml