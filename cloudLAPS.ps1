<#
    .DESCRIPTION
    a simple solution for Servers
    It all started from leanLAPS from LiebenConsulting: leanLAPS
    Forked from simpleLAPS from TrueKillRob:https://github.com/TrueKillRob/slaps/tree/main
    
    Installation:
    Get General info here:
    https://github.com/ElSrJuez/poorMansCloudLAPS
#>

#===============================================================================
function Connect-AZKeyVault {
    param (
        [string]$tenantId,
        [string]$Secret,
        [string]$Client_ID
    )
    
    $requestBody = @{
        client_id = $Client_ID
        scope = "https://vault.azure.net/.default"
        client_secret = $Secret
        grant_type = 'client_credentials'
    }

    $auth = Invoke-WebRequest -Method Post -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -Body $requestBody -UseBasicParsing
    if ( $auth ) {
        return $( $auth | ConvertFrom-Json )
    }
    else {
        return $false
    }
}

#===============================================================================
function Write-AZKeyVaultSecret {
    param (
        [string]$VaultName,
        [string]$SecretName,
        [string]$UserName,
        [string]$Secret,
        [PSCustomObject]$Token
    )
    $requestHeader = @{
        "Authorization" = "$($token.token_type) $($token.access_token)"
        "Content-Type" = "application/json"
    }

    $BaseTime = Get-Date "1970-01-01"
#    $Expire = ([Math]::Round( $( $( Get-Date ).AddDays(7) - $BaseTime ).TotalSeconds )).ToString()
    $Now = ([Math]::Round( $( $( Get-Date ) - $BaseTime ).TotalSeconds )).ToString()

    $Body = @{
        "value" = "$Secret"
        "contentType" = "text/plain"
        "attributes" = @{
            "enabled" = "true"
#            "exp" = "$Expire"
            "nbf" = "$Now"
            "recoveryLevel" = "Purgeable"
        }
        "Tags" = @{
            "UserName" = "$UserName"
        }
    }
    if ($WhatIf) {
        $Body.Tags.WhatIf=$True
    }

    $Uri = "https://" + $VaultName + ".vault.azure.net/secrets/" + $SecretName + "?api-version=7.3" 
    $Return = Invoke-RestMethod -Method PUT -Headers $requestheader -Uri $Uri -Body $($Body | ConvertTo-Json)
    if ( $Return ) {
        return $True
    }
    return $False
}
#===============================================================================
function Get-RandomCharacters($length, $characters) { 
    $random = 1..$length | ForEach-Object { Get-Random -Maximum $characters.length } 
    $private:ofs="" 
    return [String]$characters[$random]
}
#===============================================================================
function Get-NewPassword($passwordLength){ #minimum 10 characters will always be returned
    $password = Get-RandomCharacters -length ([Math]::Max($passwordLength-6,4)) -characters 'abcdefghikmnoprstuvwxyz'
    $password += Get-RandomCharacters -length 2 -characters 'ABCDEFGHKLMNPRSTUVWXYZ'
    $password += Get-RandomCharacters -length 2 -characters '23456789'
    $password += Get-RandomCharacters -length 2 -characters '!_%&/()=?}][{#*+'
    $characterArray = $password.ToCharArray()   
    $scrambledStringArray = $characterArray | Get-Random -Count $characterArray.Length     
    $outputString = -join $scrambledStringArray
    return $outputString 
}
#===============================================================================
Function Write-CustomEventLog($Message){
    # Write to the event log
    $EventSource=".CloudLAPS"
    if ([System.Diagnostics.EventLog]::Exists('Application') -eq $False -or [System.Diagnostics.EventLog]::SourceExists($EventSource) -eq $False){
        New-EventLog -LogName Application -Source $EventSource  | Out-Null
    }
    Write-EventLog -LogName Application -Source $EventSource -EntryType Information -EventId 2024 -Message $Message | Out-Null
    # Also log to console if in debug mode
    if ($Config.Debug) {
        Write-Host "$EventSource ID:2024 Message: $Message"
    }
}

Remove-Variable identity, principal -ErrorAction SilentlyContinue
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal -ArgumentList $identity
if ($principal.IsInRole( [Security.Principal.WindowsBuiltInRole]::Administrator )) {
    Write-CustomEventLog "CloudLAPS starting on $($ENV:COMPUTERNAME) with Invocation Command '$($MyInvocation.MyCommand)' under Identity $($identity.name)."
}
else {
    write-host "Identity $($identity.name) was determined not to be Administrator, exiting."
    return
}

$Config = Import-Clixml CloudLAPS.xml
#$markerFile = Join-Path . -ChildPath $Config.markerfile
#$markerFileExists = (Test-Path $markerFile)

if (($Config.AZVaultName | Get-Member).TypeName -eq 'System.String' ) {
    Write-CustomEventLog "CloudLAPS read AZ Vault Name $($Config.AZVaultName) from configuration file."
}
else {
    Write-CustomEventLog "CloudLAPS got unexpected result for configuration value AZVaultName, exiting."
    return
}

$Error.Clear()

Remove-Variable localAdmin, BlackHole -ErrorAction SilentlyContinue
try{    
    $localAdmin = Get-LocalUser | Where-Object { $_.SID.Value.EndsWith("-500") }
    if ( $Config.localAdminName -and ($true -eq $Config.renameAdminAccount) -and $localAdmin.Name -ne $Config.localAdminName) {
        Write-CustomEventLog "Rename local Administrator from '$($localAdmin.Name)' to '$($Config.localAdminName)'"        
        $BlackHole = Get-LocalUser -Name $Config.localAdminName -ErrorAction:SilentlyContinue
        if ( $BlackHole ) {
            Write-CustomEventLog "Remove preexisting '$($localAdmin.Name)' '$($BlackHole.SID.Value)'"
            Remove-LocalUser -SID $BlackHole.SID.Value -Confirm:$False -WhatIf:$Config.WhatIf | Out-Null
        }
        Rename-LocalUser -SID $localAdmin.SID.Value -NewName $Config.localAdminName -Confirm:$false -WhatIf:$Config.WhatIf | Out-Null
        #$localAdmin = Get-LocalUser -SID $localAdmin.SID.Value
    }
    else {
        Write-CustomEventLog "With renameAdminAccount set to '$($Config.renameAdminAccount)', no need to rename local Administrator from '$($localAdmin.Name)' to '$($Config.localAdminName)'." 
    }

    if ( -not $localAdmin.Enabled ) {
        Write-CustomEventLog "Found local Administrator account disabled, attempting to Enable local '$($localAdmin.Name)'..."
        Enable-LocalUser -SID $localAdmin.SID.Value -WhatIf:$WhatIf | Out-Null
    }
    else {
        Write-CustomEventLog "With Enabled attribute already at '$($localAdmin.Enabled)', no need to enable local Administrator '$($localAdmin.Name)'." 
    }
    if(!$localAdmin){Throw}
}catch{
    Write-CustomEventLog "Something went wrong while renaming or activating $($Config.localAdminName) $($_)"
    Write-Host "Something went wrong while renaming or activating $($Config.localAdminName) $($_)"
    Exit 1
}

Remove-Variable administratorsGroupName, group, administrators,adminNames -ErrorAction SilentlyContinue
try{
    $administratorsGroupName = (New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")).Translate([System.Security.Principal.NTAccount]).Value.Split("\")[1]
    Write-CustomEventLog "Local Administrators group is called $administratorsGroupName"
    $group = [ADSI]::new("WinNT://$($env:COMPUTERNAME)/$($administratorsGroupName),Group")
    $administrators = $group.Invoke('Members') | ForEach-Object {(New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList @([Byte[]](([ADSI]$_).properties.objectSid).Value, 0)).Value}
    $adminNames = $administrators | 
        foreach {([System.Security.Principal.SecurityIdentifier]$_).translate([System.Security.Principal.NTAccount])}
    Write-CustomEventLog "There are $($administrators.count) readable accounts in $administratorsGroupName with values '$($adminNames.value)'."

    if(!$administrators -or $administrators -notcontains $localAdmin.SID.Value){
        Write-CustomEventLog "$($Config.localAdminName) is not a local administrator, adding..."
        Add-LocalGroupMember -Group $administratorsGroupName -Member $Config.localAdminName -Confirm:$False -ErrorAction Stop -WhatIf:$WhatIf | Out-Null
        Write-CustomEventLog "Added $($Config.localAdminName) to the local administrators group, WhatIf mode '$($Config.WhatIf)"
    }
    #remove other local admins if specified, only executes if adding the new local admin succeeded
    if($Config.removeOtherLocalAdmins){
        foreach($administrator in $administrators){
            if($administrator.EndsWith("-500")){
                Write-CustomEventLog "Not removing $($administrator) because it is a built-in account and cannot be removed"
                continue
            }
            if($administrator -ne $localAdmin.SID.Value -and $Config.approvedAdmins -notcontains $administrator){
                Write-CustomEventLog "removeOtherLocalAdmins set to True, removing $($administrator) from Local Administrators"
                Remove-LocalGroupMember -Group $administratorsGroupName -Member $administrator -Confirm:$False -WhatIf:$Config.WhatIf | Out-Null
                Write-CustomEventLog "Removed account '$administrator' from Local '$($administratorsGroupName)' group, WhatIf mode '$($Config.WhatIf)"
            }else{
                Write-CustomEventLog "Not removing $($administrator) because of whitelisting"
            }
        }
    }else{
        Write-CustomEventLog "removeOtherLocalAdmins set to False, not removing any other accounts from group."
    }
}catch{
    Write-CustomEventLog "Something went wrong while processing the local administrators group $($_)"
    Write-Host "Something went wrong while processing the local administrators group $($_)"
    Exit 1
}

Remove-Variable newPwd, newPwdSecStr, AZToken, WriteSecretSuccess,localAdminWMI, passwordExpires, passwordExpirationDate, myCurrentDate -ErrorAction SilentlyContinue
try{
    Write-CustomEventLog "Starting password rotation flow for '$($localAdmin.Name)', setting PasswordNeverExpires is '$($Config.PasswordNeverExpires)', setting WhatIf is '$($Config.WhatIf)'..."
    $newPwd = Get-NewPassword $Config.minimumPasswordLength
    $newPwdSecStr = ConvertTo-SecureString $newPwd -asplaintext -force    
    $AZToken = Connect-AZKeyVault -tenantId $Config.tenantID -Client_ID $Config.AZAppID -Secret $Config.AZAppSecret
    if ( -not $AZToken ) { 
        Write-CustomEventLog "Unexpected result connecting to azure on tenant '$($Config.tenantID)' with Client ID '$($Config.AZAppID)'."
        throw 
    }
    if ($false -eq $Config.PasswordNeverExpires) {
        $localAdminWMI = Get-WmiObject -Query "SELECT * FROM Win32_UserAccount WHERE SID='$($localAdmin.SID)'"
        [bool]$passwordExpires = $localAdminWMI.Properties | 
            where-Object {$_.Name -eq 'PasswordExpires'} |
                Select-Object -ExpandProperty Value
        if ([bool]($Config.PasswordNeverExpires) -eq $passwordExpires) {
            Write-CustomEventLog "Password Expiration setting for $($localAdminWMI.Name) should be '$($Config.PasswordNeverExpires)', found '$(PasswordNeverExpires)'."
            $localAdmin | Set-LocalUser -PasswordNeverExpires $Config.PasswordNeverExpires -WhatIf:$Config.WhatIf | Out-Null
            Write-CustomEventLog "Password Expiration for $($localAdminWMI.Name) set to '$($Config.PasswordNeverExpires)' with WhatIf mode set to '$($Config.WhatIf)'."
        }
    }
    $myCurrentDate = Get-Date
    [datetime]$passwordExpirationDate = Get-LocalUser $localAdmin |
        Select-Object -ExpandProperty PasswordExpires
    if ($myCurrentDate -gt $passwordExpirationDate) {
        $WriteSecretSuccess = Write-AZKeyVaultSecret -VaultName $Config.AZVaultName -SecretName $($env:COMPUTERNAME) -Token $AZToken -UserName $Config.localAdminName -Secret $newPwd
        if ( -not $WriteSecretSuccess ) { 
            Write-CustomEventLog "Unexpected result setting secret name '$($env:COMPUTERNAME)' to azure vault '$($Config.AZVaultName)' with User Name '$($Config.localAdminName)'."    
            throw
            }
        $localAdmin | Set-LocalUser -Password $newPwdSecStr -Confirm:$False -WhatIf:$Config.WhatIf | Out-Null
        Write-CustomEventLog "Password for $($localAdmin.Name) set to a new value, see AzureKeyVault '$($Config.AZVaultName)' with WhatIf mode set to '$($Config.WhatIf)'."
    }
    else
    {
        Write-CustomEventLog "Password for $($localAdmin.Name) did not need to be set, current date '$myCurrentDate' is greater than password expiration date '$($passwordExpirationDate)'."
    }
}catch{
    Write-CustomEventLog "Unexpected error returned trying to set new password for $($localAdmin.Name)"
    Write-Host "Failed to set password for $($localAdmin.Name) because of $($_)"
    # Exit 1
}

Write-Host "CloudLAPS ran successfully for '$($localAdmin.Name)' with WhatIf '$($Config.WhatIf)'."
Write-CustomEventLog "CloudLAPS ran successfully for '$($localAdmin.Name)' with WhatIf '$($Config.WhatIf)'."
#Set-Content -Path $markerFile -Value $Config.localAdminName -Force -Confirm:$False | Out-Null
# Exit 0
