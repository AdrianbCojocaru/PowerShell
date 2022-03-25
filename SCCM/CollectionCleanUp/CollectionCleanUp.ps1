<#

.SYNOPSIS
  Delete SCCM collections.

.DESCRIPTION
  Place the collections names that you want removed in <ScriptPath>\Data\CollectionNamesToBeCleaned.txt - each name on a new line
  The script will first look for and remove the relationships for each collection from SQL DB. Then it will delete the collection itself.
  SQL Data Base & Server access are required

  -Confirm switch will require you to confirm the removal if:
    - the collection is not empty
    - the collection has 5 or more relationships

.PARAMETER Confirm
  Will ask you to confirm the removal if:
    - the collection is not empty
    - the collection has 5 or more relationships

.INPUTS
  SCCM collection names to be removed

.OUTPUTS
  None

.NOTES
  Author:         Adrian
  Purpose/Change: Initial script development

.EXAMPLE
  Run the script, no params needed.

#>

#EndRegion ============================[Metadata]==============================

#Region ===============================[Parameters]============================

# https://4sysops.com/archives/powershell-advanced-functions-the-cmdletbinding-and-parameter-attribute/
param (
    [Parameter(Mandatory = $false)]
    [switch]$Confirm
)

#EndRegion ============================[Parameters]============================

#Region ===============================[Variables]=============================

#Region    === Template generic variables ===
# Change the global Error action to stop, so that any error will stop the script
$ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop
# Force script culture. This helps avoid issues with date/time.
# To use an invariant culture, replace 'en-US' with [System.Globalization.CultureInfo]::InvariantCulture
[System.Threading.Thread]::CurrentThread.CurrentUICulture = 'en-US'
[System.Threading.Thread]::CurrentThread.CurrentCulture = 'en-US'
# Get script name (without extension).
[string]$ScriptName = (Get-Item $MyInvocation.MyCommand.Definition).BaseName
# Generate a timestamp variable to be used for filenames.
[string]$FileNameTimestamp = Get-Date -UFormat "%Y%m%d%H%M%S"
# Define the log file name.
[string]$LogFileName = $ScriptName
# Log folder.
[string]$LogFolder = "$PSScriptRoot\Logs\$ScriptName"
# Full log file path.
[string]$LogFile = "$LogFolder\$FileNameTimestamp-$LogFileName.log"
# How many log files to keep? Anything over this number will be deleted, starting with the oldest files.
[int32]$LogsFilesToKeep = 30
# Output file name.
[string]$OutputFileName = $ScriptName
# Output folder.
[string]$OutputFolder = "$PSScriptRoot\Output\$ScriptName"
# Full output file path.
[string]$OutputFile = "$OutputFolder\$FileNameTimestamp-$OutputFileName.xlsx"
# How many log files to keep?
[int32]$OutputFilesToKeep = 30
# Data folder.
[string]$DataFolder = "$PSScriptRoot\Data"
# Define the global exit code.
[int32]$Global:ExitCode = 0
# Define the GlobalOutput variable. To be used when output needs to be controlled.
# Add any output data to this variable. It will be written to the output in the 'finally' block.
[array]$Global:Output = @()
# Define an array of external module names that need to be loaded for this script.
# Leave it empty if no external modules are required.
[array]$RequiredModules = @()
#EndRegion === Template generic variables ===

# =================================
# === Script specific variables ===
# =================================

[string]$SQLServer = 'SQL_Server_name'
[string]$SQLDataBase = 'SQL_Database_name'
[string]$SiteServer = 'Site_Server_addr'
[string]$SiteCode = 'SiteCode'
[string]$SiteNamespace = "root\SMS\site_$SiteCode"

#EndRegion ============================[Variables]=============================

#Region ===============================[Functions]=============================
function Write-Log {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string]
        $Message,
        [Parameter(Mandatory = $False, Position = 1)]
        [int32]
        $Severity = 1,
        [Parameter(Mandatory = $False, Position = 2)]
        [boolean]
        $WriteHost = $true
    )
    switch ($Severity) {
        1 { $Level = 'Info:' }
        2 { $Level = 'Warning:' }
        3 { $Level = 'Error:' }
        Default { $Level = '-----' }
    }
    $TimeStamp = (Get-Date).ToString("yyyy-MM-dd HH:mm K")
    if ($null -eq $LogFile) {
        [string]$ScriptName = [io.path]::GetFileNameWithoutExtension($MyInvocation.ScriptName)
        $LogFilePath = "$PsScriptRoot\$ScriptName.log"
    }
    else {
        $LogFilePath = $LogFile
    }
    $Entry = "$TimeStamp $Level $Message"
    if ($LogFilePath) {
        try {
            Add-Content $LogFilePath -Value $Entry -EA 'Stop'
        }
        catch {
            Write-Warning "Unable to access log file [$LogFilePath]"
        }
    }
    else {
        Write-Warning "Log file is missing."
    }
    # If the "$WriteHost" variable is set, output the log data to console also.
    if ($WriteHost) {
        # Only output using color options if running in a host which supports colors.
        If ($Host.UI.RawUI.ForegroundColor) {
            Switch ($Severity) {
                3 { Write-Host -Object $Entry -ForegroundColor 'Red' -BackgroundColor 'Black' }
                2 { Write-Host -Object $Entry -ForegroundColor 'Yellow' -BackgroundColor 'Black' }
                Default { Write-Host -Object $Entry }
            }
        }
        # If executing "powershell.exe -File <filename>.ps1 > log.txt",
        # then all the Write-Host calls are converted to Write-Output calls so that they are included in the text log.
        Else {
            Write-Output -InputObject $Entry
        }
    }
}
function Initialize-Script {
    # If log folder doesn't exist, create it.
    # Else, remove all but the newest "$LogsFilesToKeep" log files.
    If (!(Test-Path -Path $LogFolder)) {
        New-Item -Path $LogFolder -ItemType Directory -Force | Out-Null
    }
    else {
        Get-ChildItem -Path $LogFolder |
        Where-Object { !$_.PsIsContainer } |
        Sort-Object -Property 'CreationTime' -Descending |
        Select-Object -Skip $LogsFilesToKeep |
        Remove-Item -Force -EA 'SilentlyContinue'
    }
    # If Output folder doesn't exist, create it.
    # Else, remove all but the newest "$OutputFilesToKeep" output files.
    If (! (Test-Path -Path $OutputFolder)) {
        New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null
    }
    else {
        Get-ChildItem -Path $OutputFolder |
        Where-Object { !$_.PsIsContainer } |
        Sort-Object -Property 'CreationTime' -Descending |
        Select-Object -Skip $OutputFilesToKeep |
        Remove-Item -Force -EA 'SilentlyContinue'
    }
    # Make sure the data folder exists.
    if (!(Test-Path -Path $DataFolder)) {
        New-Item -Path $DataFolder -ItemType 'Directory' -Force | Out-Null
    }
}
function Initialize-ExternalModules {
    if ($IM -and ($RequiredModules.Count -gt 0)) {
        # Make sure the network connection uses TLS1.2. Required by PSGallery connection.
        Write-Log "Settings HTTPS security protocol to TLS 1.2."
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Write-Log "Installing / Upgrading NuGet."
        $null = Install-PackageProvider -Name 'NuGet' -Scope 'AllUsers' -Force
        Write-Log "Setting PSGallery as a trusted repository."
        $null = Set-PSRepository -Name 'PSGallery' -InstallationPolicy 'Trusted'
        Write-Log "Setting execution policy to 'Bypass' to be able to import modules."
        $null = Set-ExecutionPolicy -ExecutionPolicy 'Bypass' -Scope 'CurrentUser' -Force -Confirm:$false
        # Go through the list of required modules and try to install them if missing.
        foreach ($ModuleName in $RequiredModules) {
            try {
                Import-Module -Name $ModuleName -Force -EA 'Stop'
            }
            catch {
                Write-Log "Installing module '$ModuleName'."
                $null = Install-Module -Name $ModuleName -Scope 'AllUsers' -Force
                Write-Log "Importing module '$ModuleName'."
                $null = Import-Module -Name $ModuleName -Force
            }
        }
    }
    else {
        # Try to import each module to check if all is OK.
        foreach ($ModuleName in $RequiredModules) {
            try {
                Write-Log "Importing module '$ModuleName'."
                Import-Module -Name $ModuleName -Force -ErrorAction Stop
            }
            catch {
                Write-Log "Module '$ModuleName' is missing." 2
                Write-Log "Please restart this script with ADMIN privileges and the '-IM' parameter to install the missing module." 2
                exit 1
            }
        }
    }
}
Function Set-SCCMconnection {
    Write-Log "Set-SCCMconnection executing."
    # Site configuration
    #$SiteCode = "SiteCode" # Site code 
    $ProviderMachineName = "Site_Server_addr" # SMS Provider machine name
    Write-Log "Set-SCCM | $SiteCode | $ProviderMachineName."
    # Customizations
    $initParams = @{}
    #$initParams.Add("Verbose", $true) # Uncomment this line to enable verbose logging
    #$initParams.Add("ErrorAction", "Stop") # Uncomment this line to stop the script on any errors

    # Do not change anything below this line

    # Import the ConfigurationManager.psd1 module 
    if ((Get-Module ConfigurationManager) -eq $null) {
        Import-Module "$($ENV:SMS_ADMIN_UI_PATH)\..\ConfigurationManager.psd1" @initParams 
    }

    # Connect to the site's drive if it is not already present
    if ((Get-PSDrive -Name $SiteCode -PSProvider CMSite -ErrorAction SilentlyContinue) -eq $null) {
        New-PSDrive -Name $SiteCode -PSProvider CMSite -Root $ProviderMachineName @initParams
    }

    # Set the current location to be the site code.
    Set-Location "$($SiteCode):\" @initParams
}
function Get-CollectionRelationships {
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory = $true)]
        [string]$CollectionID,
        [parameter(Mandatory = $true)]
        [string]$DataBase,
        [parameter(Mandatory = $true)]
        [string]$Server
    )
    $CollectionID = "'" + $CollectionID + "'"
    $Var = "ColID = $CollectionID"

    Write-Log -Message 'Executing SQL Query to collect Collection Relationships'
    $CollectionRelationships = Invoke-Sqlcmd -query "select distinct v_Collection.name as 'CollectionName', v_Collection.Collectionid as RuleCollectionID, vSMS_CollectionDependencies.SourceCollectionID as 'SourceCollectionID', Case When vSMS_CollectionDependencies.relationshiptype = 1 then 'Limited' when vSMS_CollectionDependencies.relationshiptype = 2 then 'Include ' when vSMS_CollectionDependencies.relationshiptype = 3 then 'Exclude ' end as 'Relationship' from v_Collection join vSMS_CollectionDependencies on vSMS_CollectionDependencies.DependentCollectionID = v_Collection.CollectionID where vSMS_CollectionDependencies.SourceCollectionID = `$(ColID)" -ServerInstance $Server -Database $DataBase -Variable $Var
    $CollectionRelationships
}

function Remove-CollectionRules {
    #Accepts a PS object that is the result of Get-CollectionRelationships. Reads the object and will remove collection include/exclude dependencies. 
    [CmdletBinding()]
    param
    (
        [parameter(mandatory = $true)]
        [object]$CollectionRulesToEvaluate,
        [parameter(mandatory = $true)]
        [string]$SiteServer
    )

    ForEach ($Item in $CollectionRulesToEvaluate) {
        try {
            If ($Item.Relationship -match 'Include') {
                $SourceCollectionID = $Item.SourceCollectionID
                $RuleCollectionID = $Item.RuleCollectionID
                Write-Log "Removing the Include rule $SourceCollectionID from the collection $RuleCollectionID"
                Remove-CMDeviceCollectionIncludeMembershipRule -CollectionID $Item.RuleCollectionID -IncludeCollectionID $Item.SourceCollectionID -force
                #If the $Item is an include rule, it sets variables and removes the collection rule.
            }
            elseif ($Item.Relationship -match 'Exclude') {
                $SourceCollectionID = $Item.SourceCollectionID
                $RuleCollectionID = $Item.RuleCollectionID
                Write-Log "Removing the Exclude rule $SourceCollectionID from the collection $RuleCollectionID"
                Remove-CMDeviceCollectionExcludeMembershipRule -CollectionID $Item.RuleCollectionID -ExcludeCollectionID $Item.SourceCollectionID -force
                #If the $Item is an exclude rule it sets variables and removes the collection rule.
            }
        }
        catch {
            Write-Log "Error removing $($Item.Relationship) rule $SourceCollectionID from the collection $RuleCollectionID"
        }
    }
    # Set-Location $CurentDir -Verbose:$false
    #returns to source directory.
}
#EndRegion ============================[Functions]=============================

#Region ===============================[EXEC]==================================

try {
    # Clear the terminal.
    Clear-Host
    # Prepare the output folders.
    Initialize-Script
    # Call the 'Manage external modules" script block.
    Initialize-ExternalModules
    # Write Log header.
    Write-Log "================================================================" 0
    Write-Log "Starting Script [$ScriptName]."
    Write-Log "Hostname: $env:COMPUTERNAME"
    Write-Log "Powershell version: $($PSVersionTable.PSVersion -join ('.'))"
    Write-Log "Running as user: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"
    Write-Log "================================================================" 0

    $RemoveAnyway = if ($Confirm) { 'N' } else { 'y' }
    $RemoveAnywayRel = if ($Confirm) { 'N' } else { 'y' }
    Write-Log "Confirm = $Confirm | RemoveAnyway = $RemoveAnyway | RemoveAnywayRel = $RemoveAnywayRel"
    if (Test-Path "$DataFolder\CollectionNamesToBeCleaned.txt") {
        Set-SCCMconnection
        $collections = Get-Content -Path "$DataFolder\CollectionNamesToBeCleaned.txt"
        $collections | ForEach-Object {
            # a cumbersome confirm block
            $CurrCol = Get-CMCollection -name $_
            if ($CurrCol -ne $null) {
                Write-Log "CollectionID: $($CurrCol.CollectionID) | Name: $_ | Type: $($CurrCol.CollectionType) | MemberCount: $($CurrCol.MemberCount)"
                If (($CurrCol.MemberCount -ne 0) -and $Confirm ) {
                    $RemoveAnyway = 'N'
                    Write-Log -Message "Collection $_, ID: $($CurrCol.CollectionID) has $($CurrCol.MemberCount) members!" -Severity 2
                    Write-Log -Message "Press [y] to remove this collection anyway." -Severity 2
                    $RemoveAnyway = Read-Host
                }
                else {
                    $RemoveAnyway = 'y'
                    Write-Log -Message "Collection $_, ID: $($CurrCol.CollectionID) is empty." 
                }
                if ($RemoveAnyway -eq 'y') {
                    $Relationships = Get-CollectionRelationships -CollectionID $CurrCol.CollectionID -Server $SQLServer -DataBase $SQLDataBase
                    $Relationships | ForEach-Object {
                        Write-Log "CollectionName: `"$($_.CollectionName)`" | RuleCollectionID: $($_.RuleCollectionID) | SourceCollectionID: $($_.SourceCollectionID) | Relationship: $($_.Relationship)"
                    }
                    if ($Relationships -ne $null) {
                        if (($Relationships.count -ge 5) -and $Confirm ) {
                            $RemoveAnywayRel = 'N'
                            Write-Log "Collection $_ has $($Relationships.count) Relationships." -Severity 2
                            Write-Log "Press [y] to remove this collection anyway..." -Severity 2
                            $RemoveAnywayRel = Read-Host
                        }
                        else {
                            $RemoveAnywayRel = 'y'
                        }
                        if ($RemoveAnywayRel -eq 'y') {
                            Remove-CollectionRules -CollectionRulesToEvaluate $Relationships -SiteServer $SiteServer
                            try {
                                $CurrCol | Remove-CMCollection -Force
                                Write-Log "Collection `"$_`" was removed."
                            }
                            catch {
                                Write-Log "Could not remove collection `"$_`""
                            }
                        }
                        else {
                            Write-Log "Skipping relationship removal for `"$_`""
                        }
                    }
                    else {
                        Write-Log "No relationships found for `"$_`"" 
                        try {
                            $CurrCol | Remove-CMCollection -Force
                            Write-Log "Collection `"$_`" was removed."
                        }
                        catch {
                            Write-Log "Could not remove collection `"$_`""
                        }
                    }
                }
                else {
                    Write-Log "Skipping CollectionID: $($CurrCol.CollectionID) | Name: $_ | Type: $($CurrCol.CollectionType) | MemberCount: $($CurrCol.MemberCount)"
                }
            }
            else { Write-Log "Collection `"$_`" not found!" }
        }
    }
    else {
        Write-Log "$DataFolder\CollectionNamesToBeCleaned.txt not found. the script will now exit" -Severity 2
        Pause
    }
    #! === MAIN CODE END ===
}
catch {
    if ($Global:ExitCode -eq 0) {
        $Global:ExitCode = 99999
        $ErrorMessage = [string]$_.Exception.Message
        $ErrorPosition = [string]$_.InvocationInfo.PositionMessage
        Write-Log -Message "$ErrorMessage | $ErrorPosition" -Severity 3 -WriteHost $true
    }
}
finally {
    # Call the .NET garbage collector.
    [System.GC]::Collect()
    if ($Global:Output) {
        $OutputString = ($Global:Output | Format-List -Property * | Out-String).Trim()
        Write-Log "Script output:`n$OutputString"
        Write-Output $Global:Output
    }
    Write-Log "Global exit code: $Global:ExitCode"
    Write-Log "Script [$ScriptName] finished."
    Write-Log "================================================================" 0
    Exit $Global:ExitCode
}

#EndRegion ============================[EXEC]==================================
