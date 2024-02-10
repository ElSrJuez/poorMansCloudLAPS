#===============================================================================
function Connect-LogAnalyticsWorkSpace {
    param (
        [string]$tenantId,
        [string]$Secret,
        [string]$Client_ID
    )
    
    $requestBody = @{
        client_id = $Client_ID
        scope = "https://api.loganalytics.io"
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
