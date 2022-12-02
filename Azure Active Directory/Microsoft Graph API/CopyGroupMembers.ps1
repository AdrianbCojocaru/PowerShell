
#Region ===============================[Metadata]==============================
<#PSScriptInfo

.VERSION 1.0

.GUID 31abe8bd-bf88-4723-981d-57075585332d

.Date 15-Nov-2022

.AUTHOR adrianbcojocaru@gmail.com

#>

<#

.SYNOPSIS
  As per today, Azure AD Group Writeback does not support writeback of nested group members from on-prem AD.
  This script will copy all members (direct & transitive) of a group to another group in Azure Active Directory.

.DESCRIPTION
  Copy all members of a group (SourceGroupId/SourceGroupName) to another group (DestinationGroupId/DestinationGroupName).
  If the destination group does not exists it will be created - only when you specify DestinationGroupName.
  By default the newly created Group will be a security group. This can be changed with the GroupType parameter.

.OUTPUTS
  A log file will be created under the Logs folder next to the script.

.PARAMETER <Parameter_Name>
  SourceGroupId [string] [optional]
  SourceGroupName [string] [optional]
  DestinationGroupId [string] [optional]
  DestinationGroupName [string] [optional]
  GroupType [string] [optional]

.EXAMPLE
  ### destination group already exists:
  CopyGroupMembers.ps1 -SourceGroupId '9xxxxx9-8294-43ff-958e-450ee4d039e1' -DestinationGroupId '2xxxxx2-c4e8-4e64-8629-450ee4d039e1'

.EXAMPLE
  ### Copy membership and create the destination group if it does not exists:
  CopyGroupMembers.ps1 -SourceGroupId '9xxxxx9-8294-43ff-958e-450ee4d039e1' -DestinationGroupName 'ACTestGroup3'
  CopyGroupMembers.ps1 -SourceGroupId '9xxxxx9-8294-43ff-958e-450ee4d039e1' -DestinationGroupName 'ACTestGroup3' -GroupType 'Microsoft365'

#>

#EndRegion ============================[Metadata]==============================

#Region ===============================[Parameters]============================

#   [Parameter(Mandatory = $false)]    
#   [switch]$CreateGroup = $true,
[CmdletBinding()]
Param (
    [Parameter(Mandatory = $false)]
    [string]$SourceGroupId = '',
    [Parameter(Mandatory = $false)]
    [string]$SourceGroupName = '',
    [Parameter(Mandatory = $false)]
    [string]$DestinationGroupId = '',
    [Parameter(Mandatory = $false)]
    [string]$DestinationGroupName = '',
    [Parameter(Mandatory = $false)]
    [ValidateSet('Security', 'Microsoft 365', 'Microsoft365', 'M365')]
    [string]$GroupType = 'Security'
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
[array]$RequiredModules = @('Microsoft.Graph', 'ImportExcel')
#EndRegion === Template generic variables ===

# =================================
# === Script specific variables ===
# =================================


#EndRegion ============================[Variables]=============================
$ClientID = 'c2164bc4-563d-4016-b1be-3247e31a6c3f'
$TenantID = '3162431e-45a1-4b12-9845-2719fc9a0fc7'
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
#EndRegion ============================[Functions]=============================

#Region ===============================[EXEC]==================================

try {
    # Clear the terminal.
    # Clear-Host
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

    #! === MAIN CODE START ===
    write-log "SourceGroupId: $SourceGroupId SourceGroupName: $SourceGroupName"
    write-log "DestinationGroupId: $DestinationGroupId DestinationGroupName: $DestinationGroupName GroupType: $GroupType"
    $CreateGroup = $true
    ##
    Connect-MgGraph -ClientID $ClientID -TenantId $TenantId
    if ($DestinationGroupId) {
        $DestinationGroup = Get-MgGroup -GroupId $DestinationGroupId -EA Stop
    }
    elseif ($DestinationGroupName) {
        $DestinationGroup = Get-MgGroup -Filter "DisplayName eq '$DestinationGroupName'"
    }
    else {
        Write-Log "Either DestinationGroupId or DestinationGroupName params must be specified." -Severity 2
        Write-Log "The script will now exit." -Severity 3
        throw
    }

    if ($SourceGroupId) {
        $SourceGroup = Get-MgGroup -GroupId $SourceGroupId -EA Stop
    }
    elseif ($SourceGroupName) {
        $SourceGroup = Get-MgGroup -Filter "DisplayName eq '$SourceGroupName'" -EA Stop
    }
    else {
        Write-Log "Either SourceGroupId or SourceGroupName params must be specified." -Severity 2
        Write-Log "The script will now exit." -Severity 3
        throw
    }
    ##
    if (-not $DestinationGroup) {
        Write-Log "Destination group does not exists. Creating it.."
        if ($GroupType -eq 'Security') {
            $NewGroupParams = @{
                DisplayName     = $DestinationGroupName
                MailNickname    = $DestinationGroupName
                MailEnabled     = $false
                SecurityEnabled = $true
            }
        }
        else {
            $NewGroupParams = @{
                DisplayName     = $DestinationGroupName
                MailNickname    = $DestinationGroupName
                MailEnabled     = $true
                SecurityEnabled = $false
                GroupTypes      = @(
                    "Unified"
                )
            }
        }
        $DestinationGroup = New-MgGroup -BodyParameter $NewGroupParams
        Write-Log "Newly created destination group name: $($DestinationGroup.DisplayName) Id: $($DestinationGroup.Id)"
    }
    else {
        Write-Log "A group with name '$($DestinationGroup.DisplayName)' and ID: '$($DestinationGroup.Id)' already exists." -Severity 2
        Write-Log "Press Enter to go ahead with copying the members to this existing group." -Severity 2
        Pause
    }
    $UsersToAdd = New-Object System.Collections.Generic.List[System.Object]
    $DestinationGroupMembers_before = Get-MgGroupTransitiveMember -GroupId $DestinationGroup.Id -All
    $ExportExcelParams = @{
        WorkSheetName = 'DestinationGroupMembers_before'
        TableName     = 'DestinationGroupMembers_before'
        TableStyle    = 'Medium13'
        Append        = $true
        Show          = $false
        AutoSize      = $true
        Path          = $OutputFile
    }
    $DestinationGroupMembers_before | Select-Object Id, { $_.AdditionalProperties.userPrincipalName } | Export-Excel @ExportExcelParams
    $SourceGroupMembers = Get-MgGroupTransitiveMember -GroupId $SourceGroup.Id -All
    $SourceGroupMembers | ForEach-Object {
        if ($_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.user') {
            Write-Log "Adding user '$($($_.AdditionalProperties).userPrincipalName)' ID: '$($_.Id)' to group $($DestinationGroup.DisplayName)"
            #$_ | Add-Member -NotePropertyName userPrincipalName -NotePropertyValue $_.AdditionalProperties.userPrincipalName
            $UsersToAdd.Add($_)
            $params = @{
                "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$($_.Id)"
            }
            New-MgGroupMemberByRef -GroupId $DestinationGroup.Id -BodyParameter $params -EA SilentlyContinue
        }
    }
    $DestinationGroupMembers_after = Get-MgGroupTransitiveMember -GroupId $DestinationGroup.Id -All
    $ExportExcelParams = @{
        WorkSheetName = 'DestinationGroupMembers_after'
        TableName     = 'DestinationGroupMembers_after'
        TableStyle    = 'Medium13'
        Append        = $true
        Show          = $false
        AutoSize      = $true
        Path          = $OutputFile
    }
    $DestinationGroupMembers_after | Select-Object Id, { $_.AdditionalProperties.userPrincipalName } | Export-Excel @ExportExcelParams
    $ExportExcelParams = @{
        WorkSheetName = 'UsersToAdd'
        TableName     = 'UsersToAdd'
        TableStyle    = 'Medium13'
        Append        = $true
        Show          = $false
        AutoSize      = $true
        Path          = $OutputFile
    }
    $UsersToAdd | Select-Object Id, { $_.AdditionalProperties.userPrincipalName } | Export-Excel @ExportExcelParams
    #! === MAIN CODE END ===

    # Open output folder if running interactive.
    if ([Environment]::UserInteractive) {
        Start-Process -FilePath $OutputFolder
    }
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
