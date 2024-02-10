<#
.Synopsis
   # Write an event to a Windows event log, create event source if needed
#>
function Write-CustomEventLog
{
    Param
    (
        # Param1 help description
        [Parameter(Mandatory=$true,
                   Position=0)]
        [string]$Message,
        [string]$EventType = 'Information',
        [string]$EventSource=".CloudLAPS",
        [string]$LogName = 'Application',
        [int]$EventID = 2024,
        [bool]$LogToHost = $true
    )    
    if ([System.Diagnostics.EventLog]::Exists($LogName) -eq $False -or [System.Diagnostics.EventLog]::SourceExists($EventSource) -eq $False) {
        New-EventLog -LogName $LogName -Source $EventSource  | Out-Null
    }
    Write-EventLog -LogName $LogName -Source $EventSource -EntryType $EventType -EventId $EventID -Message $Message | Out-Null
    # Also log to console if specified mode
    if ($LogToHost) {
        Write-Host "$EventSource ID:$EventID Message: $Message"
    }
}