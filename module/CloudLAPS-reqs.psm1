#handle PS2
    if(-not $PSScriptRoot)
    {
        $PSScriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent
    }

#Get public and private function definition files.
    $Public  = Get-ChildItem $PSScriptRoot\*.ps1 -ErrorAction SilentlyContinue
    $Private = Get-ChildItem $PSScriptRoot\Private\*.ps1 -ErrorAction SilentlyContinue
    $External = Get-ChildItem $PSScriptRoot\External\*.ps1 -ErrorAction SilentlyContinue

#Dot source the files
    Foreach($import in $Private)
    {
        Try
        {
            #PS2 compatibility
            if($import.fullname)
            {
                . $import.fullname
            }
        }
        Catch
        {
            Write-Error "Failed to import function $($import.fullname)"
        }
    }
   
        Foreach($import in $External)
    {
        Try
        {
            #PS2 compatibility
            if($import.fullname)
            {
                . $import.fullname
            }
        }
        Catch
        {
            Write-Error "Failed to import function $($import.fullname)"
        }
    }

        Foreach($import in $Public)
    {
        Try
        {
            #PS2 compatibility
            if($import.fullname)
            {
                . $import.fullname
            }
        }
        Catch
        {
            Write-Error "Failed to import function $($import.fullname)"
        }
    }

#Create some aliases, export public functions
    Export-ModuleMember -Function $($External | Select -ExpandProperty BaseName) -Alias *
    Export-ModuleMember -Function $($Public | Select -ExpandProperty BaseName) -Alias *