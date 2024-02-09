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
