<#
    .DESCRIPTION
    a simple solution for Servers
    It all started from leanLAPS from LiebenConsulting: leanLAPS
    Forked from simpleLAPS from TrueKillRob:https://github.com/TrueKillRob/slaps/tree/main
    
    Installation:
    Get General info here:
    https://github.com/ElSrJuez/poorMansCloudLAPS
#>

$Debug = $False
$WhatIf = $False                                             # If Enabled, the Password and Accounts will not be changed. KeyVault will be used
####CONFIG
$minimumPasswordLength = 21
$tenantID = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"          # ID of Azure where AZKeyVault is located
$AZAppID  = "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy"          # Azure App which permissions to only set Secret
$AZAppSecret = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"   # Secret for AZAppID
$AZVaultName = "KeyVault-01"                                # Name of AzureKeyVault
$localAdminName = "superman"                                # if set, lokal admin will be renamed
$removeOtherLocalAdmins = $False                            # if set to True, will remove ALL other local admins, including those set through AzureAD device settings
$doNotRunOnServers = $True                                  # buildin protection in case an admin accidentally assigns this script to e.g. a domain controller
$markerFile = Join-Path $Env:TEMP -ChildPath "simpleLAPS.marker"
$markerFileExists = (Test-Path $markerFile)
$approvedAdmins = @( #specify SID's for Azure groups such as Global Admins and Device Administrators or for local or domain users to not remove from local admins. These are specific to your tenant, you can get them on a device by running: ([ADSI]::new("WinNT://$($env:COMPUTERNAME)/$((New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")).Translate([System.Security.Principal.NTAccount]).Value.Split("\")[1]),Group")).Invoke('Members') | % {"$((New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList @([Byte[]](([ADSI]$_).properties.objectSid).Value, 0)).Value) <--- a.k.a: $(([ADSI]$_).Path.Split("/")[-1])"}
"S-1-12-1-2296310142-aaaaaaaaaa-aaaaaaaaa-aaaaaaaaaa"
"S-1-12-1-465010940-bbbbbbbbbb-bbbbbbbbbb-bbbbbbbbb"
)

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
    $EventSource=".simpleLAPS"
    if ( -not $Debug ) {
        if ([System.Diagnostics.EventLog]::Exists('Application') -eq $False -or [System.Diagnostics.EventLog]::SourceExists($EventSource) -eq $False){
            New-EventLog -LogName Application -Source $EventSource  | Out-Null
        }
        Write-EventLog -LogName Application -Source $EventSource -EntryType Information -EventId 1985 -Message $Message | Out-Null
    }
    else {
        Write-Output "$EventSource ID:1985 Message: $Message"
    }
}
#===============================================================================
Write-CustomEventLog "simpleLAPS starting on $($ENV:COMPUTERNAME) as $($MyInvocation.MyCommand.Name)"

if($doNotRunOnServers -and (Get-WmiObject -Class Win32_OperatingSystem).ProductType -ne 1){
    Write-CustomEventLog "Unsupported OS!"
    Write-Error "Unsupported OS!"
    Exit 0
}
#===============================================================================
#===============================================================================

$mode = $MyInvocation.MyCommand.Name.Split(".")[0]

#when in remediation mode, always exit successfully as we remediated during the detection phase
if($mode -ne "detect" -and -not $Debug ){
    Exit 0
}else{
    #check if marker file present, which means we're in the 2nd detection run where nothing should happen except posting the new password to Intune
    if($markerFileExists){
        Remove-Item -Path $markerFile -Force -Confirm:$False
        #ensure the plaintext password is removed from Intune log files and registry (which are written after a delay):
        $triggers = @((New-ScheduledTaskTrigger -At (get-date).AddMinutes(5) -Once),(New-ScheduledTaskTrigger -At (get-date).AddMinutes(10) -Once),(New-ScheduledTaskTrigger -At (get-date).AddMinutes(30) -Once))
        $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ex bypass -EncodedCommand RgB1AG4AYwB0AGkAbwBuACAAVwByAGkAdABlAC0AQwB1AHMAdABvAG0ARQB2AGUAbgB0AEwAbwBnACgAJABNAGUAcwBzAGEAZwBlACkAewANAAoAIAAgACAAIAAkAEUAdgBlAG4AdABTAG8AdQByAGMAZQA9ACIALgBzAGkAbQBwAGwAZQBMAEEAUABTACIADQAKACAAIAAgACAAaQBmACAAKABbAFMAeQBzAHQAZQBtAC4ARABpAGEAZwBuAG8AcwB0AGkAYwBzAC4ARQB2AGUAbgB0AEwAbwBnAF0AOgA6AEUAeABpAHMAdABzACgAJwBBAHAAcABsAGkAYwBhAHQAaQBvAG4AJwApACAALQBlAHEAIAAkAEYAYQBsAHMAZQAgAC0AbwByACAAWwBTAHkAcwB0AGUAbQAuAEQAaQBhAGcAbgBvAHMAdABpAGMAcwAuAEUAdgBlAG4AdABMAG8AZwBdADoAOgBTAG8AdQByAGMAZQBFAHgAaQBzAHQAcwAoACQARQB2AGUAbgB0AFMAbwB1AHIAYwBlACkAIAAtAGUAcQAgACQARgBhAGwAcwBlACkAewANAAoAIAAgACAAIAAgACAAIAAgAE4AZQB3AC0ARQB2AGUAbgB0AEwAbwBnACAALQBMAG8AZwBOAGEAbQBlACAAQQBwAHAAbABpAGMAYQB0AGkAbwBuACAALQBTAG8AdQByAGMAZQAgACQARQB2AGUAbgB0AFMAbwB1AHIAYwBlACAAfAAgAE8AdQB0AC0ATgB1AGwAbAANAAoAIAAgACAAIAB9AA0ACgAgACAAIAAgAFcAcgBpAHQAZQAtAEUAdgBlAG4AdABMAG8AZwAgAC0ATABvAGcATgBhAG0AZQAgAEEAcABwAGwAaQBjAGEAdABpAG8AbgAgAC0AUwBvAHUAcgBjAGUAIAAkAEUAdgBlAG4AdABTAG8AdQByAGMAZQAgAC0ARQBuAHQAcgB5AFQAeQBwAGUAIABJAG4AZgBvAHIAbQBhAHQAaQBvAG4AIAAtAEUAdgBlAG4AdABJAGQAIAAxADkAOAA1ACAALQBNAGUAcwBzAGEAZwBlACAAJABNAGUAcwBzAGEAZwBlACAAfAAgAE8AdQB0AC0ATgB1AGwAbAANAAoAfQANAAoADQAKACMAdwBpAHAAZQAgAHAAYQBzAHMAdwBvAHIAZAAgAGYAcgBvAG0AIABsAG8AZwBmAGkAbABlAHMADQAKAHQAcgB5AHsADQAKACAAIAAgACAAJABpAG4AdAB1AG4AZQBMAG8AZwAxACAAPQAgAEoAbwBpAG4ALQBQAGEAdABoACAAJABFAG4AdgA6AFAAcgBvAGcAcgBhAG0ARABhAHQAYQAgAC0AYwBoAGkAbABkAHAAYQB0AGgAIAAiAE0AaQBjAHIAbwBzAG8AZgB0AFwASQBuAHQAdQBuAGUATQBhAG4AYQBnAGUAbQBlAG4AdABFAHgAdABlAG4AcwBpAG8AbgBcAEwAbwBnAHMAXABBAGcAZQBuAHQARQB4AGUAYwB1AHQAbwByAC4AbABvAGcAIgANAAoAIAAgACAAIAAkAGkAbgB0AHUAbgBlAEwAbwBnADIAIAA9ACAASgBvAGkAbgAtAFAAYQB0AGgAIAAkAEUAbgB2ADoAUAByAG8AZwByAGEAbQBEAGEAdABhACAALQBjAGgAaQBsAGQAcABhAHQAaAAgACIATQBpAGMAcgBvAHMAbwBmAHQAXABJAG4AdAB1AG4AZQBNAGEAbgBhAGcAZQBtAGUAbgB0AEUAeAB0AGUAbgBzAGkAbwBuAFwATABvAGcAcwBcAEkAbgB0AHUAbgBlAE0AYQBuAGEAZwBlAG0AZQBuAHQARQB4AHQAZQBuAHMAaQBvAG4ALgBsAG8AZwAiAA0ACgAgACAAIAAgAGkAZgAgACgAIABUAGUAcwB0AC0AUABhAHQAaAAgAC0ATABpAHQAZQByAGEAbABQAGEAdABoACAAJABpAG4AdAB1AG4AZQBMAG8AZwAxACAALQBQAGEAdABoAFQAeQBwAGUAOgBMAGUAYQBmACAAKQAgAHsADQAKAAkAIAAgACAAIABTAGUAdAAtAEMAbwBuAHQAZQBuAHQAIAAtAEYAbwByAGMAZQAgAC0AQwBvAG4AZgBpAHIAbQA6ACQARgBhAGwAcwBlACAALQBQAGEAdABoACAAJABpAG4AdAB1AG4AZQBMAG8AZwAxACAALQBWAGEAbAB1AGUAIAAoAEcAZQB0AC0AQwBvAG4AdABlAG4AdAAgAC0AUABhAHQAaAAgACQAaQBuAHQAdQBuAGUATABvAGcAMQAgAHwAIABTAGUAbABlAGMAdAAtAFMAdAByAGkAbgBnACAALQBQAGEAdAB0AGUAcgBuACAAIgBQAGEAcwBzAHcAbwByAGQAIgAgAC0ATgBvAHQATQBhAHQAYwBoACkADQAKACAAIAAgACAAfQANAAoAIAAgACAAIABpAGYAIAAoACAAVABlAHMAdAAtAFAAYQB0AGgAIAAtAEwAaQB0AGUAcgBhAGwAUABhAHQAaAAgACQAaQBuAHQAdQBuAGUATABvAGcAMgAgAC0AUABhAHQAaABUAHkAcABlADoATABlAGEAZgAgACkAIAB7AA0ACgAgACAAIAAgACAAIAAgACAAUwBlAHQALQBDAG8AbgB0AGUAbgB0ACAALQBGAG8AcgBjAGUAIAAtAEMAbwBuAGYAaQByAG0AOgAkAEYAYQBsAHMAZQAgAC0AUABhAHQAaAAgACQAaQBuAHQAdQBuAGUATABvAGcAMgAgAC0AVgBhAGwAdQBlACAAKABHAGUAdAAtAEMAbwBuAHQAZQBuAHQAIAAtAFAAYQB0AGgAIAAkAGkAbgB0AHUAbgBlAEwAbwBnADIAIAB8ACAAUwBlAGwAZQBjAHQALQBTAHQAcgBpAG4AZwAgAC0AUABhAHQAdABlAHIAbgAgACIAUABhAHMAcwB3AG8AcgBkACIAIAAtAE4AbwB0AE0AYQB0AGMAaAApAA0ACgAgACAAIAAgAH0ADQAKAH0AYwBhAHQAYwBoAHsAJABOAHUAbABsAH0ADQAKAA0ACgAjAG8AbgBsAHkAIAB3AGkAcABlACAAcgBlAGcAaQBzAHQAcgB5ACAAZABhAHQAYQAgAGEAZgB0AGUAcgAgAGQAYQB0AGEAIABoAGEAcwAgAGIAZQBlAG4AIABzAGUAbgB0ACAAdABvACAATQBzAGYAdAANAAoAaQBmACAAKAAgACQAKABUAGUAcwB0AC0AUABhAHQAaAAgAC0ATABpAHQAZQByAGEAbABQAGEAdABoACAAJABpAG4AdAB1AG4AZQBMAG8AZwAyACAALQBQAGEAdABoAFQAeQBwAGUAOgBMAGUAYQBmACkAIAAtAGEAbgBkACAAJAAoAFQAZQBzAHQALQBQAGEAdABoACAALQBQAGEAdABoACAAIgBIAEsATABNADoAXABTAG8AZgB0AHcAYQByAGUAXABNAGkAYwByAG8AcwBvAGYAdABcAEkAbgB0AHUAbgBlAE0AYQBuAGEAZwBlAG0AZQBuAHQARQB4AHQAZQBuAHMAaQBvAG4AXABTAGkAZABlAEMAYQByAFAAbwBsAGkAYwBpAGUAcwBcAFMAYwByAGkAcAB0AHMAXABSAGUAcABvAHIAdABzACIAKQAgACkAIAB7AA0ACgAgACAAIAAgAGkAZgAoACgARwBlAHQALQBDAG8AbgB0AGUAbgB0ACAALQBQAGEAdABoACAAJABpAG4AdAB1AG4AZQBMAG8AZwAyACAAfAAgAFMAZQBsAGUAYwB0AC0AUwB0AHIAaQBuAGcAIAAtAFAAYQB0AHQAZQByAG4AIAAiAFAAbwBsAGkAYwB5ACAAcgBlAHMAdQBsAHQAcwAgAGEAcgBlACAAcwB1AGMAYwBlAHMAcwBmAHUAbABsAHkAIABzAGUAbgB0AC4AIgApACkAewANAAoAIAAgACAAIAAgACAAIAAgAFcAcgBpAHQAZQAtAEMAdQBzAHQAbwBtAEUAdgBlAG4AdABMAG8AZwAgACIASQBuAHQAdQBuAGUAIABsAG8AZwBmAGkAbABlACAAaQBuAGQAaQBjAGEAdABlAHMAIABzAGMAcgBpAHAAdAAgAHIAZQBzAHUAbAB0AHMAIABoAGEAdgBlACAAYgBlAGUAbgAgAHIAZQBwAG8AcgB0AGUAZAAgAHQAbwAgAE0AaQBjAHIAbwBzAG8AZgB0ACIADQAKACAAIAAgACAAIAAgACAAIABTAGUAdAAtAEMAbwBuAHQAZQBuAHQAIAAtAEYAbwByAGMAZQAgAC0AQwBvAG4AZgBpAHIAbQA6ACQARgBhAGwAcwBlACAALQBQAGEAdABoACAAJABpAG4AdAB1AG4AZQBMAG8AZwAyACAALQBWAGEAbAB1AGUAIAAoAEcAZQB0AC0AQwBvAG4AdABlAG4AdAAgAC0AUABhAHQAaAAgACQAaQBuAHQAdQBuAGUATABvAGcAMgAgAHwAIABTAGUAbABlAGMAdAAtAFMAdAByAGkAbgBnACAALQBQAGEAdAB0AGUAcgBuACAAIgBQAG8AbABpAGMAeQAgAHIAZQBzAHUAbAB0AHMAIABhAHIAZQAgAHMAdQBjAGMAZQBzAHMAZgB1AGwAbAB5ACAAcwBlAG4AdAAuACIAIAAtAE4AbwB0AE0AYQB0AGMAaAApAA0ACgAgACAAIAAgACAAIAAgACAAUwB0AGEAcgB0AC0AUwBsAGUAZQBwACAALQBzACAAOQAwAA0ACgAgACAAIAAgACAAIAAgACAAdAByAHkAewANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAZgBvAHIAZQBhAGMAaAAoACQAVABlAG4AYQBuAHQAIABpAG4AIAAoAEcAZQB0AC0AQwBoAGkAbABkAEkAdABlAG0AIAAiAEgASwBMAE0AOgBcAFMAbwBmAHQAdwBhAHIAZQBcAE0AaQBjAHIAbwBzAG8AZgB0AFwASQBuAHQAdQBuAGUATQBhAG4AYQBnAGUAbQBlAG4AdABFAHgAdABlAG4AcwBpAG8AbgBcAFMAaQBkAGUAQwBhAHIAUABvAGwAaQBjAGkAZQBzAFwAUwBjAHIAaQBwAHQAcwBcAFIAZQBwAG8AcgB0AHMAIgApACkAewANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIABmAG8AcgBlAGEAYwBoACgAJABzAGMAcgBpAHAAdAAgAGkAbgAgACgARwBlAHQALQBDAGgAaQBsAGQASQB0AGUAbQAgACQAVABlAG4AYQBuAHQALgBQAFMAUABhAHQAaAApACkAewANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACQAagBzAG8AbgAgAD0AIAAoACgARwBlAHQALQBJAHQAZQBtAFAAcgBvAHAAZQByAHQAeQAgAC0AUABhAHQAaAAgACgASgBvAGkAbgAtAFAAYQB0AGgAIAAkAHMAYwByAGkAcAB0AC4AUABTAFAAYQB0AGgAIAAtAEMAaABpAGwAZABQAGEAdABoACAAIgBSAGUAcwB1AGwAdAAiACkAIAAtAE4AYQBtAGUAIAAiAFIAZQBzAHUAbAB0ACIAKQAuAFIAZQBzAHUAbAB0ACAAfAAgAGMAbwBuAHYAZQByAHQAZgByAG8AbQAtAGoAcwBvAG4AKQANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAGkAZgAoACQAagBzAG8AbgAuAFAAbwBzAHQAUgBlAG0AZQBkAGkAYQB0AGkAbwBuAEQAZQB0AGUAYwB0AFMAYwByAGkAcAB0AE8AdQB0AHAAdQB0AC4AUwB0AGEAcgB0AHMAVwBpAHQAaAAoACIAcwBpAG0AcABsAGUATABBAFAAUwAiACkAKQB7AA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAkAGoAcwBvAG4ALgBQAG8AcwB0AFIAZQBtAGUAZABpAGEAdABpAG8AbgBEAGUAdABlAGMAdABTAGMAcgBpAHAAdABPAHUAdABwAHUAdAAgAD0AIAAiAFIARQBEAEEAQwBUAEUARAAiAA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIABTAGUAdAAtAEkAdABlAG0AUAByAG8AcABlAHIAdAB5ACAALQBQAGEAdABoACAAKABKAG8AaQBuAC0AUABhAHQAaAAgACQAcwBjAHIAaQBwAHQALgBQAFMAUABhAHQAaAAgAC0AQwBoAGkAbABkAFAAYQB0AGgAIAAiAFIAZQBzAHUAbAB0ACIAKQAgAC0ATgBhAG0AZQAgACIAUgBlAHMAdQBsAHQAIgAgAC0AVgBhAGwAdQBlACAAKAAkAGoAcwBvAG4AIAB8ACAAQwBvAG4AdgBlAHIAdABUAG8ALQBKAHMAbwBuACAALQBEAGUAcAB0AGgAIAAxADAAIAAtAEMAbwBtAHAAcgBlAHMAcwApACAALQBGAG8AcgBjAGUAIAAtAEMAbwBuAGYAaQByAG0AOgAkAEYAYQBsAHMAZQANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAVwByAGkAdABlAC0AQwB1AHMAdABvAG0ARQB2AGUAbgB0AEwAbwBnACAAIgByAGUAZABhAGMAdABlAGQAIABhAGwAbAAgAGwAbwBjAGEAbAAgAGQAYQB0AGEAIgANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAH0ADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAfQANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAfQANAAoAIAAgACAAIAAgACAAIAAgAH0AYwBhAHQAYwBoAHsAJABOAHUAbABsAH0ADQAKACAAIAAgACAAfQANAAoAfQA=" #base64 UTF16-LE encoded command https://www.base64encode.org/
        $Null = Register-ScheduledTask -TaskName "simpleLAPS_WL" -Trigger $triggers -User "SYSTEM" -Action $Action -Force

        Write-Host "simpleLAPS changed password for $($localAdminName) on $(Get-Date)"
        Exit 0
    }
}

$Error.Clear()

try{
    $localAdmin = $Null
    $localAdmin = Get-LocalUser | Where-Object { $_.SID.Value.EndsWith("-500") }
    if ( $localAdminName -and $localAdmin.Name -ne $localAdminName) {
        Write-CustomEventLog "Rename lokal Administrator from '$($localAdmin.Name)' to '$localAdminName'"
        $BlackHole = Get-LocalUser -Name $localAdminName -ErrorAction:SilentlyContinue
        if ( $BlackHole ) {
            Write-CustomEventLog "Remove preexisting '$($localAdmin.Name)' '$($BlackHole.SID.Value)'"
            Remove-LocalUser -SID $BlackHole.SID.Value -Confirm:$False -WhatIf:$WhatIf | Out-Null
        }
        Rename-LocalUser -SID $localAdmin.SID.Value -NewName $localAdminName -Confirm:$false -WhatIf:$WhatIf | Out-Null
        $localAdmin = Get-LocalUser -SID $localAdmin.SID.Value
    }
    if ( -not $localAdmin.Enabled ) {
        Write-CustomEventLog "Enable lokal Administrator."
        Enable-LocalUser -SID $localAdmin.SID.Value -WhatIf:$WhatIf | Out-Null
    }
    if(!$localAdmin){Throw}
}catch{
    Write-CustomEventLog "Something went wrong while renaming or activating $localAdminName $($_)"
    Write-Host "Something went wrong while renaming or activating $localAdminName $($_)"
    Exit 1
}

try{
    $administratorsGroupName = (New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")).Translate([System.Security.Principal.NTAccount]).Value.Split("\")[1]
    Write-CustomEventLog "local administrators group is called $administratorsGroupName"
    $group = [ADSI]::new("WinNT://$($env:COMPUTERNAME)/$($administratorsGroupName),Group")
    $administrators = $group.Invoke('Members') | ForEach-Object {(New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList @([Byte[]](([ADSI]$_).properties.objectSid).Value, 0)).Value}
    
    Write-CustomEventLog "There are $($administrators.count) readable accounts in $administratorsGroupName"

    if(!$administrators -or $administrators -notcontains $localAdmin.SID.Value){
        Write-CustomEventLog "$localAdminName is not a local administrator, adding..."
        Add-LocalGroupMember -Group $administratorsGroupName -Member $localAdminName -Confirm:$False -ErrorAction Stop -WhatIf:$WhatIf | Out-Null
        Write-CustomEventLog "Added $localAdminName to the local administrators group"
    }
    #remove other local admins if specified, only executes if adding the new local admin succeeded
    if($removeOtherLocalAdmins){
        foreach($administrator in $administrators){
            if($administrator.EndsWith("-500")){
                Write-CustomEventLog "Not removing $($administrator) because it is a built-in account and cannot be removed"
                continue
            }
            if($administrator -ne $localAdmin.SID.Value -and $approvedAdmins -notcontains $administrator){
                Write-CustomEventLog "removeOtherLocalAdmins set to True, removing $($administrator) from Local Administrators"
                Remove-LocalGroupMember -Group $administratorsGroupName -Member $administrator -Confirm:$False -WhatIf:$WhatIf | Out-Null
                Write-CustomEventLog "Removed $administrator from Local Administrators"
            }else{
                Write-CustomEventLog "Not removing $($administrator) because of whitelisting"
            }
        }
    }else{
        Write-CustomEventLog "removeOtherLocalAdmins set to False, not removing any administrator permissions"
    }
}catch{
    Write-CustomEventLog "Something went wrong while processing the local administrators group $($_)"
    Write-Host "Something went wrong while processing the local administrators group $($_)"
    Exit 1
}

try{
    Write-CustomEventLog "Setting password for $localAdminName ..."
    $newPwd = Get-NewPassword $minimumPasswordLength
    $newPwdSecStr = ConvertTo-SecureString $newPwd -asplaintext -force
    $AZToken = Connect-AZKeyVault -tenantId $tenantID -Client_ID $AZAppID -Secret $AZAppSecret
    if ( -not $AZToken ) { throw }
    $BlackHole = Write-AZKeyVaultSecret -VaultName $AZVaultName -SecretName $($env:COMPUTERNAME) -Token $AZToken -UserName $localAdminName -Secret $newPwd
    if ( -not $BlackHole ) { throw }
    $localAdmin | Set-LocalUser -Password $newPwdSecStr -Confirm:$False -AccountNeverExpires -PasswordNeverExpires $True -UserMayChangePassword $True -WhatIf:$WhatIf | Out-Null
    Write-CustomEventLog "Password for $localAdminName set to a new value, see AzureKeyVault $AZVaultName"
}catch{
    Write-CustomEventLog "Failed to set new password for $localAdminName"
    Write-Host "Failed to set password for $localAdminName because of $($_)"
    Exit 1
}

Write-Host "LeanLAPS ran successfully for $($localAdminName)"
Set-Content -Path $markerFile -Value $localAdminName -Force -Confirm:$False | Out-Null
Exit 0
