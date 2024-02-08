<#
    .DESCRIPTION
    CloudLAPS is a simple solution for Servers
    This script will create a base configuration CloudLAPS.xml file
    
    Create a config file:
    1. Adjust values below
    2. Run script code
#>
$cloudLAPSConfig = New-Object PSObject
$cloudLAPSConfig | Add-Member -NotePropertyName Debug -NotePropertyValue $true
# If Enabled, the Password and Accounts will not be changed. KeyVault will be used
$cloudLAPSConfig | Add-Member -NotePropertyName WhatIf  -NotePropertyValue $true 
$cloudLAPSConfig | Add-Member -NotePropertyName minimumPasswordLength  -NotePropertyValue 21
# ID of Azure where AZKeyVault and Log Analytics Workspace are located
$cloudLAPSConfig | Add-Member -NotePropertyName tenantID -NotePropertyValue "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
# Azure App which permissions to only set Secret
$cloudLAPSConfig | Add-Member -NotePropertyName AZAppID -NotePropertyValue "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy"
# Secret for AZAppID
$cloudLAPSConfig | Add-Member -NotePropertyName AZAppSecret -NotePropertyValue "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
# Azure Key Vault Name
$cloudLAPSConfig | Add-Member -NotePropertyName AZVaultName -NotePropertyValue "KeyVault-01"
# if set, lokal admin will be renamed
$cloudLAPSConfig | Add-Member -NotePropertyName localAdminName -NotePropertyValue "superman"
# if set to True, will remove ALL other local admins, including those set through AzureAD device settings
$cloudLAPSConfig | Add-Member -NotePropertyName removeOtherLocalAdmins -NotePropertyValue $False
# To be deprecated, this tool is mostly useful on servers!
$cloudLAPSConfig | Add-Member -NotePropertyName doNotRunOnServers -NotePropertyValue $True
$cloudLAPSConfig | Add-Member -NotePropertyName markerFile -NotePropertyValue "CloudLAPS.marker"
$approvedAdmins = @( #specify SID's for Azure groups such as Global Admins and Device Administrators or for local or domain users to not remove from local admins. These are specific to your tenant, you can get them on a device by running: ([ADSI]::new("WinNT://$($env:COMPUTERNAME)/$((New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")).Translate([System.Security.Principal.NTAccount]).Value.Split("\")[1]),Group")).Invoke('Members') | % {"$((New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList @([Byte[]](([ADSI]$_).properties.objectSid).Value, 0)).Value) <--- a.k.a: $(([ADSI]$_).Path.Split("/")[-1])"}
"S-1-12-1-2296310142-aaaaaaaaaa-aaaaaaaaa-aaaaaaaaaa"
"S-1-12-1-465010940-bbbbbbbbbb-bbbbbbbbbb-bbbbbbbbb"
)
$cloudLAPSConfig | Add-Member -NotePropertyName approvedAdmins -NotePropertyValue $approvedAdmins

$cloudLAPSConfig | Export-Clixml -Path CloudLAPS.xml