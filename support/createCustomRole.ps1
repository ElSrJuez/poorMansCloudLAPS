Connect-AzAccount -UseDeviceAuthentication

$roleDefinitionTemplate = @"
{ 
   "Name": "Update Secret Only", 
   "Description": "CloudLAPS Perform only the Update secret DataAction", 
    "Actions": [ 
    ], 
    "DataActions": [ 
        "Microsoft.KeyVault/vaults/secrets/getSecret/action" 
    ], 
    "NotDataActions": [ 
   ], 
    "AssignableScopes": ["/subscriptions/{SubId}"] 
}
"@

$roledefinition = $roleDefinitionTemplate -replace '{Subid}',(Get-AzContext).Subscription.id 

$roleDefinition | Out-File role.json

New-AzRoleDefinition -InputFile role.json -Verbose