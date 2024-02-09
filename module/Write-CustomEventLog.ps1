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