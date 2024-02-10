<#
    .DESCRIPTION
    A simple Cloud-based LAPS solution for Servers
    It all started from leanLAPS from LiebenConsulting: leanLAPS
    Forked from simpleLAPS from TrueKillRob:https://github.com/TrueKillRob/slaps/tree/main
    
    Installation:
    Get General info here:
    https://github.com/ElSrJuez/poorMansCloudLAPS

    .NOTES
    Version:        0.1
    Author:         https://github.com/ElSrJuez/
    Creation Date:  8-Feb-2024
    Purpose/Change: Truly Azure Cloud-native LAPS solution that works on Servers
#>

Import-Module .\module\CloudLAPS-reqs.psm1

class clsScriptState
{
    # Optionally, add attributes to prevent invalid values
    [string]$State
    [ValidateNotNullOrEmpty()][string]$Stage = 'New'
    [string]$Result
    [ValidateNotNullOrEmpty()][bool]$Error = $False
    [string]$Description
    [ValidateNotNullOrEmpty()][int]$ReturnCode = 0
}

Remove-Variable LAPSState -ErrorAction SilentlyContinue
$LAPSState = [clsScriptState]@{
   State = "Started"
}

Remove-Variable identity, principal -ErrorAction SilentlyContinue
$LAPSState.Stage = 'AdminCheck'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal -ArgumentList $identity
if ($principal.IsInRole( [Security.Principal.WindowsBuiltInRole]::Administrator )) {
    Write-CustomEventLog "CloudLAPS starting on $($ENV:COMPUTERNAME) with Invocation Command '$($MyInvocation.MyCommand)' under Identity $($identity.name)."
}
else {
    $LAPSState.Description = "Identity $($identity.name) was determined not to be Administrator-elevated, exiting."
    Write-CustomEventLog $LAPSState.Description
    $LAPSState.State = 'Cancelled'    
    $LAPSState.Error = $true
    $LAPSState.ReturnCode = 1
}

if ($LAPSState.Error -eq $False) {
    $LAPSState.Stage = 'ConfigLoad'
    $Config = Import-Clixml CloudLAPS.xml
    if (($Config.AZVaultName | Get-Member).TypeName -eq 'System.String' ) {
        Write-CustomEventLog "CloudLAPS read AZ Vault Name $($Config.AZVaultName) from configuration file."
    }
    else {
        $LAPSState.Description = "CloudLAPS got unexpected result for configuration value AZVaultName, exiting."
        Write-CustomEventLog $LAPSState.Description
        $LAPSState.State = 'Cancelled'        
        $LAPSState.Error = $true
        $LAPSState.ReturnCode = 1    
    }
}
$Error.Clear()

if ($LAPSState.Error -eq $False) {
    Remove-Variable localAdmin, ExistingLocalAccount -ErrorAction SilentlyContinue
    try{    
        $localAdmin = Get-LocalUser | Where-Object { $_.SID.Value.EndsWith("-500") }
        $LAPSState.Stage = 'RenameLocalAdmin'
        if ( $Config.localAdminName -and ($true -eq $Config.renameAdminAccount) -and $localAdmin.Name -ne $Config.localAdminName) {
            Write-CustomEventLog "Rename local Administrator from '$($localAdmin.Name)' to '$($Config.localAdminName)'"        
            $ExistingLocalAccount = Get-LocalUser -Name $Config.localAdminName -ErrorAction:SilentlyContinue
            if ( $ExistingLocalAccount ) {
                Write-CustomEventLog "Remove preexisting '$($localAdmin.Name)' '$($ExistingLocalAccount.SID.Value)'"
                Remove-LocalUser -SID $ExistingLocalAccount.SID.Value -Confirm:$False -WhatIf:$Config.WhatIf | Out-Null
            }
            Rename-LocalUser -SID $localAdmin.SID.Value -NewName $Config.localAdminName -Confirm:$false -WhatIf:$Config.WhatIf | Out-Null
            #$localAdmin = Get-LocalUser -SID $localAdmin.SID.Value
        }
        else {
            Write-CustomEventLog "With renameAdminAccount set to '$($Config.renameAdminAccount)', no need to rename local Administrator from '$($localAdmin.Name)' to '$($Config.localAdminName)'." 
        }

        $LAPSState.Stage = 'EnableLocalAdmin'
        if ( -not $localAdmin.Enabled ) {
            Write-CustomEventLog "Found local Administrator account disabled, attempting to Enable local '$($localAdmin.Name)'..."
            Enable-LocalUser -SID $localAdmin.SID.Value -WhatIf:$WhatIf | Out-Null
        }
        else {
            Write-CustomEventLog "With Enabled attribute already at '$($localAdmin.Enabled)', no need to enable local Administrator '$($localAdmin.Name)'." 
        }
        if(!$localAdmin){Throw}
    }catch{
        $LAPSState.Description = "Something went wrong while renaming or activating $($Config.localAdminName) $($_)"
        Write-CustomEventLog $LAPSState.Description
        $LAPSState.State = 'Cancelled'
        $LAPSState.Error = $true
        $LAPSState.ReturnCode = 1    
    }
}

if ($LAPSState.Error -eq $False) {
    Remove-Variable administratorsGroupName, group, administrators,adminNames -ErrorAction SilentlyContinue
    $LAPSState.Stage = 'EnumerateLocalAdminGroup'
    try{
        $administratorsGroupName = (New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")).Translate([System.Security.Principal.NTAccount]).Value.Split("\")[1]
        Write-CustomEventLog "Local Administrators group is called $administratorsGroupName"
        $group = [ADSI]::new("WinNT://$($env:COMPUTERNAME)/$($administratorsGroupName),Group")
        $administrators = $group.Invoke('Members') | ForEach-Object {(New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList @([Byte[]](([ADSI]$_).properties.objectSid).Value, 0)).Value}
        $adminNames = $administrators | 
            foreach {([System.Security.Principal.SecurityIdentifier]$_).translate([System.Security.Principal.NTAccount])}
        Write-CustomEventLog "There are $($administrators.count) readable accounts in $administratorsGroupName with values '$($adminNames.value)'."

        
        if(!$administrators -or $administrators -notcontains $localAdmin.SID.Value){
            $LAPSState.Stage = 'AddToLocalAdmins'
            Write-CustomEventLog "$($Config.localAdminName) is not a local administrator, adding..."
            Add-LocalGroupMember -Group $administratorsGroupName -Member $Config.localAdminName -Confirm:$False -ErrorAction Stop -WhatIf:$WhatIf | Out-Null
            Write-CustomEventLog "Added $($Config.localAdminName) to the local administrators group, WhatIf mode '$($Config.WhatIf)"
        }
        
        #remove other local admins if specified, only executes if adding the new local admin succeeded        
        if($Config.removeOtherLocalAdmins){
            $LAPSState.Stage = 'CleanupLocalAdmins'
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
        $LAPSState.Description = "Something went wrong while processing the local administrators group $($_)"
        Write-CustomEventLog $LAPSState.Description
        $LAPSState.State = 'Cancelled'
        $LAPSState.Error = $true
        $LAPSState.ReturnCode = 1    
    }
}

if ($LAPSState.Error -eq $False) {
    Remove-Variable newPwd, newPwdSecStr, AZToken, WriteSecretSuccess,localAdminWMI, passwordExpires, passwordExpirationDate, myCurrentDate,azContext,pwExpDateCalc -ErrorAction SilentlyContinue
    $LAPSState.Stage = 'ConnectKeyVault'
    try{
        Write-CustomEventLog "Starting password rotation flow for '$($localAdmin.Name)', setting PasswordNeverExpires is '$($Config.PasswordNeverExpires)', setting WhatIf is '$($Config.WhatIf)'..."
        $newPwd = Get-NewPassword $Config.minimumPasswordLength
        $newPwdSecStr = ConvertTo-SecureString $newPwd -asplaintext -force    
        $AZToken = Connect-AZKeyVault -tenantId $Config.tenantID -Client_ID $Config.AZAppID -Secret $Config.AZAppSecret
        if ( -not $AZToken ) { 
            Write-CustomEventLog "Unexpected result connecting to azure on tenant '$($Config.tenantID)' with Client ID '$($Config.AZAppID)'."
            throw 
        } ELSE {        
            Write-CustomEventLog "Connected to Entra ID tenant '$($Config.tenantID)' with Client ID '$($Config.AZAppID)', token type '$($AZToken.token_type)', token expiration '$($AZToken.expires_in)'."
        }
        if ($false -eq $Config.PasswordNeverExpires) {
            $LAPSState.Stage = 'QueryAdminAccountPasswordExpiration'
            $localAdminWMI = Get-WmiObject -Query "SELECT * FROM Win32_UserAccount WHERE SID='$($localAdmin.SID.value)' AND LocalAccount='true'"
            [bool]$passwordExpires = $localAdminWMI.Properties | 
                where-Object {$_.Name -eq 'PasswordExpires'} |
                    Select-Object -ExpandProperty Value
            if ([bool]($Config.PasswordNeverExpires -eq $false) -and ($passwordExpires -eq $False)) {
                $LAPSState.Stage = 'SetAdminAccountPasswordExpiration'
                Write-CustomEventLog "PasswordNeverExpires mandates '$($Config.PasswordNeverExpires)', $($localAdminWMI.Name) expiration found '$($passwordExpires)'."
                $localAdmin | Set-LocalUser -PasswordNeverExpires $Config.PasswordNeverExpires -WhatIf:$Config.WhatIf | Out-Null
                Write-CustomEventLog "Password Expiration for $($localAdminWMI.Name) changed to '$($Config.PasswordNeverExpires)' with WhatIf mode set to '$($Config.WhatIf)'."
            } else
            {
                Write-CustomEventLog "PasswordNeverExpires for $($localAdminWMI.Name) already set to '$($Config.PasswordNeverExpires)' with WhatIf mode set to '$($Config.WhatIf)'."
            }
        } else {            
            $LAPSState.Result = "CloudLAPS is configured for PasswordNeverExpires to $($Config.PasswordNeverExpires), this prevents using normal password expiration policy to manage password reset cadence."
            Write-CustomEventLog $LAPSState.Result
        }

        $myCurrentDate = Get-Date
        $LAPSState.Stage = 'QueryAdminAccountPasswordExpirationDate'
        [datetime]$passwordExpirationDate = Get-LocalUser $localAdmin |
            Select-Object -ExpandProperty PasswordExpires
        [datetime]$pwExpDateCalc = $passwordExpirationDate.AddDays(-$Config.PolicyGracePeriodDays)
        if ($myCurrentDate -gt $pwExpDateCalc) {            
            $LAPSState.Stage = 'StoreNewPassword'
            $LAPSState.Result = "Password can be changed since '$pwExpDateCalc': Current date '$myCurrentDate', configured expiration grace period is '$($Config.PolicyGracePeriodDays)', Windows password expiration date is '$($passwordExpirationDate)'."
            Write-CustomEventLog $LAPSState.Result
            $WriteSecretSuccess = Write-AZKeyVaultSecret -VaultName $Config.AZVaultName -SecretName $($env:COMPUTERNAME) -Token $AZToken -UserName $Config.localAdminName -Secret $newPwd
            if ( -not $WriteSecretSuccess ) { 
                Write-CustomEventLog "Unexpected result setting secret name '$($env:COMPUTERNAME)' to azure vault '$($Config.AZVaultName)' with User Name '$($Config.localAdminName)'."    
                throw
                }
            $LAPSState.Stage = 'SetNewPassword'
            $localAdmin | Set-LocalUser -Password $newPwdSecStr -Confirm:$False -WhatIf:$Config.WhatIf | Out-Null
            Write-CustomEventLog "Password for $($localAdmin.Name) set to a new value, see AzureKeyVault '$($Config.AZVaultName)' with WhatIf mode set to '$($Config.WhatIf)'."
        }
        else
        {
            $LAPSState.Result = "Password should not be changed until '$pwExpDateCalc': Current date '$myCurrentDate', configured expiration grace period is '$($Config.PolicyGracePeriodDays)', Windows password expiration date is '$($passwordExpirationDate)'."
            Write-CustomEventLog $LAPSState.Result
        }
    }catch{
        $LAPSState.Description = "Unexpected error trying to set password for $($localAdmin.Name), '$($_)'."
        Write-CustomEventLog $LAPSState.Description
        $LAPSState.State = 'Cancelled'
        $LAPSState.Error = $true
        $LAPSState.ReturnCode = 1    
    }
}

if ($LAPSState.Error -eq $False) {
    $LAPSState.State = 'Finished'
    $LAPSState.Description = "CloudLAPS finished for '$($localAdmin.Name)', state '$($LAPSState.State)', error '$($LAPSState.Error)', return code '$($LAPSState.ReturnCode)'."    
    Write-CustomEventLog $LAPSState.Description   
}

# Sending the data to Log Analytics Workspace
Remove-Variable PayloadJSON, LAResponse -ErrorAction SilentlyContinue
$PayloadJSON = $LAPSState | ConvertTo-Json
Write-CustomEventLog "Starting upload to workspace '$($Config.AzLAWorkspaceID)' with payload size $($PayloadJSON.Length)..."

# Submit the data to the API endpoint
$LAResponse = Send-LogAnalyticsData -customerId $Config.AzLAWorkspaceID -sharedKey $config.AzLAWorkspaceSecret -body ([System.Text.Encoding]::UTF8.GetBytes($PayloadJSON)) -logType 'CloudLAPS'

Write-CustomEventLog "Exiting script with state '$($LAPSState.State)', stage '$($LAPSState.Stage)', error '$($LAPSState.Error)', return code '$($LAPSState.ReturnCode)', Log Analytics Response '$LAResponse'."
#exit $LAPSState.ReturnCode