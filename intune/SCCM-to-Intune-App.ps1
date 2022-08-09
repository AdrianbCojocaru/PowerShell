#Requires -version 5
#
#

#Region ===============================[Metadata]==============================
# !WARNING! An empty line is required between metadata elements.
# To check if metadata is correctly configured, use Test-ScriptFileInfo -Path <path_to_script>

<#

.SYNOPSIS
  SCCM to Intune app migration script

.DESCRIPTION
  This script takes an application and its metadata from SCCM and converts it to an Intune app using IntuneWinAppUtil.exe
  IntuneWinAppUtil.exe should be placed under "$PSScriptRoot\Data"

.PARAMETER <Parameter_Name>
  <Brief description of parameter input required. Repeat this attribute if required>

.INPUTS
  Applications names that will be migrated are read from the $PSScriptRoot\Data\AppList.txt file

.OUTPUTS
  A migration report gets created under the $PSScriptRoot folder

.NOTES
  Author:         Adrian
  Creation Date:  22-July-2022
  Purpose/Change: Initial script development

.EXAMPLE


#>

#EndRegion ============================[Metadata]==============================

#Region ===============================[Parameters]============================

# https://4sysops.com/archives/powershell-advanced-functions-the-cmdletbinding-and-parameter-attribute/
[CmdletBinding()]
Param (
    [Parameter(Mandatory = $false)]
    [switch]$IM
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
[array]$RequiredModules = @('Win32AppMigrationTool', 'IntuneWin32App'
)
#EndRegion === Template generic variables ===

# =================================
# === Script specific variables ===
# =================================
$AppList = Get-Content "$DataFolder\AppList.txt"
$AppFilePath = $OutputFolder
$IntuneWinAppUtil = "$DataFolder\IntuneWinAppUtil.exe"
$GTimeStamp = (Get-Date).ToString("yyyy-MM-dd HH:mm K")

#! NOTE: Redefine any template generic variables, if needed.

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
    $SiteCode = "XXX" # Site code 
    $ProviderMachineName = "XXX" # SMS Provider machine name
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

function Get-AppCommandLine {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        $CurrentApp
    )
    Write-Log "Get-AppCommandLine $AppName LocalizedDisplayName = $($CurrentApp.LocalizedDisplayName)"

    [xml]$CurrentAppSDMPackageXML = $CurrentApp.SDMPackageXML
    # install & uninstall command line
    $item = New-Object System.Object
    $item | Add-Member -MemberType NoteProperty -Name "InstallCommandLine" -Value $CurrentAppSDMPackageXML.AppMgmtDigest.DeploymentType.Installer.CustomData.InstallCommandLine
    Write-Log "InstallCommandLine = $($($($($($CurrentAppSDMPackageXML.AppMgmtDigest).DeploymentType).Installer).CustomData).InstallCommandLine)"
    $item | Add-Member -MemberType NoteProperty -Name "UninstallCommandLine" -Value $CurrentAppSDMPackageXML.AppMgmtDigest.DeploymentType.Installer.CustomData.UninstallCommandLine
    Write-Log "UninstallCommandLine = $($($($($($($CurrentAppSDMPackageXML).AppMgmtDigest).DeploymentType).Installer).CustomData).UninstallCommandLine)"
    $item | Add-Member -MemberType NoteProperty -Name "ProductCode" -Value $CurrentAppSDMPackageXML.AppMgmtDigest.DeploymentType.Installer.CustomData.ProductCode
    Write-Log "ProductCode $($($($($($($CurrentAppSDMPackageXML).AppMgmtDigest).DeploymentType).Installer).CustomData).ProductCode)"
    $item | Add-Member -MemberType NoteProperty -Name "ProductVersion" -Value $CurrentAppSDMPackageXML.AppMgmtDigest.DeploymentType.Installer.CustomData.ProductVersion
    Write-Log "ProductVersion $($($($($($($CurrentAppSDMPackageXML).AppMgmtDigest).DeploymentType).Installer).CustomData).ProductVersion)"
    if ($null -eq $item.UninstallCommandLine) { $item.UninstallCommandLine = 'N/A' }
    if ($null -eq $item.InstallCommandLine) { $item.InstallCommandLine = 'N/A' }
    return $item
}
Function Get-AppDetectionMethod {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        $CurrentApp
    )
    Write-Log "Get-AppDetectionMethod $AppName LocalizedDisplayName = $($CurrentApp.LocalizedDisplayName)"
    # get app metadata
    # $CurrentApp = Get-CMApplication -Name $AppName -DisableWildcardHandling
    [xml]$CurrentAppSDMPackageXML = $CurrentApp.SDMPackageXML

    # detection method
    $DetectionMethod = $CurrentAppSDMPackageXML.AppMgmtDigest.DeploymentType.Installer.CustomData.DetectionMethod
    Write-Log "$AppName Detection Method: $DetectionMethod"
    if ($DetectionMethod -eq 'Enhanced') {
        $DetectionMethodList = New-Object System.Collections.ArrayList
        # File
        if (Get-Member -inputobject $CurrentAppSDMPackageXML.AppMgmtDigest.DeploymentType.Installer.CustomData.EnhancedDetectionMethod.Settings -name "File" -Membertype Properties) {
            Write-Log "AppMgmtDigest.DeploymentType.Installer.CustomData.EnhancedDetectionMethod.Settings = File"

            # most apps have at least two detection methods
            if ($CurrentAppSDMPackageXML.AppMgmtDigest.DeploymentType.Installer.CustomData.EnhancedDetectionMethod.Settings.File.Count -ge 2) {
                #$CurrentAppSDMPackageXML.AppMgmtDigest.DeploymentType.Installer.CustomData.EnhancedDetectionMethod | ForEach-Object {
                for ($i = 0; $i -lt $CurrentAppSDMPackageXML.AppMgmtDigest.DeploymentType.Installer.CustomData.EnhancedDetectionMethod.Settings.File.Count; $i++) {
                    $item = New-Object System.Object
                    $item | Add-Member -MemberType NoteProperty -Name "LogicalName" -Value $CurrentAppSDMPackageXML.AppMgmtDigest.DeploymentType.Installer.CustomData.EnhancedDetectionMethod.Settings.File.LogicalName[$i]
                    Write-Log "Add-Member NoteProperty LogicalName = $($($($($($($($($($CurrentAppSDMPackageXML).AppMgmtDigest).DeploymentType).Installer).CustomData).EnhancedDetectionMethod).Settings).File).LogicalName[$i])"
                    $item | Add-Member -MemberType NoteProperty -Name "Path" -Value $CurrentAppSDMPackageXML.AppMgmtDigest.DeploymentType.Installer.CustomData.EnhancedDetectionMethod.Settings.File.Path[$i]
                    Write-Log "Add-Member NoteProperty Path = $($($($($($($($($($CurrentAppSDMPackageXML).AppMgmtDigest).DeploymentType).Installer).CustomData).EnhancedDetectionMethod).Settings).File).Path[$i])"
                    $item | Add-Member -MemberType NoteProperty -Name "Filter" -Value $CurrentAppSDMPackageXML.AppMgmtDigest.DeploymentType.Installer.CustomData.EnhancedDetectionMethod.Settings.File.Filter[$i]
                    Write-Log "Add-Member NoteProperty Filter = $($($($($($($($($($CurrentAppSDMPackageXML).AppMgmtDigest).DeploymentType).Installer).CustomData).EnhancedDetectionMethod).Settings).File).Filter[$i])"
                    $item | Add-Member -MemberType NoteProperty -Name "Operator" -Value $CurrentAppSDMPackageXML.AppMgmtDigest.DeploymentType.Installer.CustomData.EnhancedDetectionMethod.Rule.Expression.Operands.Expression.Operator[$i]
                    Write-Log "Add-Member NoteProperty Operator = $($($($($($($($($($($($CurrentAppSDMPackageXML).AppMgmtDigest).DeploymentType).Installer).CustomData).EnhancedDetectionMethod).Rule).Expression).Operands).Expression).Operator[$i])"
                    $item | Add-Member -MemberType NoteProperty -Name $CurrentAppSDMPackageXML.AppMgmtDigest.DeploymentType.Installer.CustomData.EnhancedDetectionMethod.Rule.Expression.Operands.Expression.Operands.ConstantValue.DataType[$i] -Value $CurrentAppSDMPackageXML.AppMgmtDigest.DeploymentType.Installer.CustomData.EnhancedDetectionMethod.Rule.Expression.Operands.Expression.Operands.ConstantValue.Value[$i]
                    Write-Log "Add-Member NoteProperty $($($($($($($($($($($($($($CurrentAppSDMPackageXML).AppMgmtDigest).DeploymentType).Installer).CustomData).EnhancedDetectionMethod).Rule).Expression).Operands).Expression).Operands).ConstantValue).DataType[$i]) = $($($($($($($($($($($($($($CurrentAppSDMPackageXML).AppMgmtDigest).DeploymentType).Installer).CustomData).EnhancedDetectionMethod).Rule).Expression).Operands).Expression).Operands).ConstantValue).Value[$i])"
                    # Get the logical operator between multiple conditions. Will always be the same. Got it this way to keep the structure
                    $item | Add-Member -MemberType NoteProperty -Name "MasterOperator" -Value $CurrentAppSDMPackageXML.AppMgmtDigest.DeploymentType.Installer.CustomData.EnhancedDetectionMethod.Rule.Expression.Operator
                    Write-Log "Add-Member NoteProperty MasterOperator = $($($($($($($($($($CurrentAppSDMPackageXML).AppMgmtDigest).DeploymentType).Installer).CustomData).EnhancedDetectionMethod).Rule).Expression).Operator)"
                    #$item | Add-Member -MemberType NoteProperty -Name "SettingType" -Value 'File'
                    $DetectionMethodList.Add($item) | Out-Null
                }
            }
            else {
                # 1 detection method
                $item = New-Object System.Object
                $item | Add-Member -MemberType NoteProperty -Name "LogicalName" -Value $CurrentAppSDMPackageXML.AppMgmtDigest.DeploymentType.Installer.CustomData.EnhancedDetectionMethod.Settings.File.LogicalName
                Write-Log "Add-Member NoteProperty LogicalName = $($($($($($($($($($CurrentAppSDMPackageXML).AppMgmtDigest).DeploymentType).Installer).CustomData).EnhancedDetectionMethod).Settings).File).LogicalName)"
                $item | Add-Member -MemberType NoteProperty -Name "Path" -Value $CurrentAppSDMPackageXML.AppMgmtDigest.DeploymentType.Installer.CustomData.EnhancedDetectionMethod.Settings.File.Path
                Write-Log "Add-Member NoteProperty Path = $($($($($($($($($($CurrentAppSDMPackageXML).AppMgmtDigest).DeploymentType).Installer).CustomData).EnhancedDetectionMethod).Settings).File).Path)"
                $item | Add-Member -MemberType NoteProperty -Name "Filter" -Value $CurrentAppSDMPackageXML.AppMgmtDigest.DeploymentType.Installer.CustomData.EnhancedDetectionMethod.Settings.File.Filter
                Write-Log "Add-Member NoteProperty Filter = $($($($($($($($($($CurrentAppSDMPackageXML).AppMgmtDigest).DeploymentType).Installer).CustomData).EnhancedDetectionMethod).Settings).File).Filter)"
                $item | Add-Member -MemberType NoteProperty -Name "Operator" -Value $CurrentAppSDMPackageXML.AppMgmtDigest.DeploymentType.Installer.CustomData.EnhancedDetectionMethod.Rule.Expression.Operator
                Write-Log "Add-Member NoteProperty Operator = $($($($($($($($($($($($CurrentAppSDMPackageXML).AppMgmtDigest).DeploymentType).Installer).CustomData).EnhancedDetectionMethod).Rule).Expression).Operands).Expression).Operator)"
                $item | Add-Member -MemberType NoteProperty -Name $CurrentAppSDMPackageXML.AppMgmtDigest.DeploymentType.Installer.CustomData.EnhancedDetectionMethod.Rule.Expression.Operands.ConstantValue.DataType -Value $CurrentAppSDMPackageXML.AppMgmtDigest.DeploymentType.Installer.CustomData.EnhancedDetectionMethod.Rule.Expression.Operands.ConstantValue.Value
                Write-Log "Add-Member NoteProperty $($($($($($($($($($($($CurrentAppSDMPackageXML).AppMgmtDigest).DeploymentType).Installer).CustomData).EnhancedDetectionMethod).Rule).Expression).Operands).ConstantValue).DataType) = $($($($($($($($($($CurrentAppSDMPackageXML).AppMgmtDigest).DeploymentType).Installer).CustomData).EnhancedDetectionMethod).Rule).ConstantValue).Value)"
                #$item | Add-Member -MemberType NoteProperty -Name "SettingType" -Value 'File'
                $DetectionMethodList.Add($item) | Out-Null
            }
        }
        # Folder exists
        if (Get-Member -inputobject $CurrentAppSDMPackageXML.AppMgmtDigest.DeploymentType.Installer.CustomData.EnhancedDetectionMethod.Settings -name "Folder" -Membertype Properties) {
            Write-Log "AppMgmtDigest.DeploymentType.Installer.CustomData.EnhancedDetectionMethod.Settings = Folder"
            $DetectionMethodList.Add($CurrentAppSDMPackageXML.AppMgmtDigest.DeploymentType.Installer.CustomData.EnhancedDetectionMethod.Settings.Folder) | Out-Null
            # don't care about the rest.... it will always be folder exists
            #$DetectionMethodList.Add($CurrentAppSDMPackageXML.AppMgmtDigest.DeploymentType.Installer.CustomData.EnhancedDetectionMethod.Rule.Expression.Operands.Expression) | Out-Null
        }
        # Registry value exists or reg value equal, greater etc tahn something
        if (Get-Member -inputobject $CurrentAppSDMPackageXML.AppMgmtDigest.DeploymentType.Installer.CustomData.EnhancedDetectionMethod.Settings -name "SimpleSetting" -Membertype Properties) {
            $EnhancedDetectionMethod = $CurrentAppSDMPackageXML.AppMgmtDigest.DeploymentType.Installer.CustomData.EnhancedDetectionMethod
            #Settings | ForEach-Object { 
            # adding data from the Rule node to the SimpleSetting.RegistryDiscoverySource object
            if ($EnhancedDetectionMethod.Settings.SimpleSetting.RegistryDiscoverySource.count -ge 2) {
                for ($i = 0; $i -lt $EnhancedDetectionMethod.Settings.SimpleSetting.RegistryDiscoverySource.count; $i++) {
                    Write-Log "EnhancedDetectionMethod.Settings.SimpleSetting.RegistryDiscoverySource.count = $($($($($($EnhancedDetectionMethod).Settings).SimpleSetting).RegistryDiscoverySource).count)"
                    $EnhancedDetectionMethod.Settings.SimpleSetting.RegistryDiscoverySource[$i] | Add-Member -MemberType NoteProperty -Name 'RegValue' -Value $EnhancedDetectionMethod.Rule.Expression.Operands.Expression.Operands.ConstantValue.Value[$i]
                    Write-Log "Add-Member to EnhancedDetectionMethod.Settings.SimpleSetting.RegistryDiscoverySource object RegValue = $($($($($($($($($EnhancedDetectionMethod).Rule).Expression).Operands).Expression).Operands).ConstantValue).Value[$i])"
                    $EnhancedDetectionMethod.Settings.SimpleSetting.RegistryDiscoverySource[$i] | Add-Member -MemberType NoteProperty -Name 'Operator' -Value $EnhancedDetectionMethod.Rule.Expression.Operands.Expression.Operator[$i]
                    Write-Log "Add-Member to EnhancedDetectionMethod.Settings.SimpleSetting.RegistryDiscoverySource object Operator = $($($($($($($EnhancedDetectionMethod).Rule).Expression).Operands).Expression).Operator[$i])"
                    $EnhancedDetectionMethod.Settings.SimpleSetting.RegistryDiscoverySource[$i] | Add-Member -MemberType NoteProperty -Name 'DataType' -Value $EnhancedDetectionMethod.Rule.Expression.Operands.Expression.Operands.ConstantValue.DataType[$i]
                    Write-Log "Add-Member to EnhancedDetectionMethod.Settings.SimpleSetting.RegistryDiscoverySource object DataType = $($($($($($($($($EnhancedDetectionMethod).Rule).Expression).Operands).Expression).Operands).ConstantValue).DataType[$i])"
                    # Get the logical operator between multiple conditions. Will always be the same. Got it this way to keep the structure
                    $EnhancedDetectionMethod.Settings.SimpleSetting.RegistryDiscoverySource[$i] | Add-Member -MemberType NoteProperty -Name "MasterOperator" -Value $EnhancedDetectionMethod.Rule.Expression.Operator
                    Write-Log "Add-Member NoteProperty MasterOperator = $($($($($EnhancedDetectionMethod).Rule).Expression).Operator)"
                    $DetectionMethodList.Add($EnhancedDetectionMethod.Settings.SimpleSetting.RegistryDiscoverySource[$i]) | Out-Null
                }
            }
            else {
                Write-Log "EnhancedDetectionMethod.Settings.SimpleSetting.RegistryDiscoverySource.count = 1"
                $EnhancedDetectionMethod.Settings.SimpleSetting.RegistryDiscoverySource | Add-Member -MemberType NoteProperty -Name 'RegValue' -Value $EnhancedDetectionMethod.Rule.Expression.Operands.ConstantValue.Value
                Write-Log "Add-Member to EnhancedDetectionMethod.Settings.SimpleSetting.RegistryDiscoverySource object RegValue = $($($($($($($EnhancedDetectionMethod).Rule).Expression).Operands).ConstantValue).Value)"
                $EnhancedDetectionMethod.Settings.SimpleSetting.RegistryDiscoverySource | Add-Member -MemberType NoteProperty -Name 'Operator' -Value $EnhancedDetectionMethod.Rule.Expression.Operator
                Write-Log "Add-Member to EnhancedDetectionMethod.Settings.SimpleSetting.RegistryDiscoverySource object Operator = $($($($($EnhancedDetectionMethod).Rule).Expression).Operator)"
                $EnhancedDetectionMethod.Settings.SimpleSetting.RegistryDiscoverySource | Add-Member -MemberType NoteProperty -Name 'DataType' -Value $EnhancedDetectionMethod.Rule.Expression.Operands.ConstantValue.DataType
                Write-Log "Add-Member to EnhancedDetectionMethod.Settings.SimpleSetting.RegistryDiscoverySource object DataType = $($($($($($($EnhancedDetectionMethod).Rule).Expression).Operands).ConstantValue).DataType)"
                $DetectionMethodList.Add($EnhancedDetectionMethod.Settings.SimpleSetting.RegistryDiscoverySource) | Out-Null
            }
            # $EnhancedDetectionMethod.Settings.SimpleSetting.RegistryDiscoverySource | foreach { $DetectionMethodList.Add($_) } # you need to create obj list instead of adding one big obj
            # $DetectionMethodList.Add($EnhancedDetectionMethod.Settings.SimpleSetting.RegistryDiscoverySource) | Out-Null
            # $DetectionMethodList.Add($EnhancedDetectionMethod.Rule.Expression.Operands.Expression) | Out-Null # adding Operator (Equals etc.)
            # $DetectionMethodList.Add($EnhancedDetectionMethod.Rule.Expression.Operands.Expression.Operands.ConstantValue) | Out-Null # adding Operands adica Value & DataType

            #}
        }

        # Registry Key exists
        if (Get-Member -inputobject $CurrentAppSDMPackageXML.AppMgmtDigest.DeploymentType.Installer.CustomData.EnhancedDetectionMethod.Settings -name "RegistryKey" -Membertype Properties) {
            $EnhancedDetectionMethod = $CurrentAppSDMPackageXML.AppMgmtDigest.DeploymentType.Installer.CustomData.EnhancedDetectionMethod
            #Settings | ForEach-Object { 
            # adding data from the Rule node to the SimpleSetting.RegistryDiscoverySource object
            if ($EnhancedDetectionMethod.Settings.RegistryKey.count -ge 2) {
                for ($i = 0; $i -lt $EnhancedDetectionMethod.Settings.RegistryKey.count; $i++) {
                    Write-Log "EnhancedDetectionMethod.Settings.RegistryKey.count = $($($($($EnhancedDetectionMethod).Settings).RegistryKey).count)"
                    $EnhancedDetectionMethod.Settings.RegistryKey[$i] | Add-Member -MemberType NoteProperty -Name 'RegKey' -Value $EnhancedDetectionMethod.Settings.RegistryKey.Key[$i]
                    Write-Log "Add-Member to EnhancedDetectionMethod.Settings.RegistryKey object RegKey = $($($($($EnhancedDetectionMethod).Settings).RegistryKey).Key[$i])"
                    $EnhancedDetectionMethod.Settings.RegistryKey[$i] | Add-Member -MemberType NoteProperty -Name 'DataType' -Value $EnhancedDetectionMethod.Rule.Expression.Operands.Expression.Operands.ConstantValue.DataType[$i]
                    Write-Log "Add-Member to EnhancedDetectionMethod.Settings.RegistryKey DataType = $($($($($($($($($EnhancedDetectionMethod).Rule).Expression).Operands).Expression).Operands).ConstantValue).DataType[$i])"
                    # Get the logical operator between multiple conditions. Will always be the same. Got it this way to keep the structure
                    $EnhancedDetectionMethod.Settings.RegistryKey[$i] | Add-Member -MemberType NoteProperty -Name "MasterOperator" -Value $EnhancedDetectionMethod.Rule.Expression.Operator
                    Write-Log "Add-Member NoteProperty MasterOperator = $($($($($EnhancedDetectionMethod).Rule).Expression).Operator)"
                    $DetectionMethodList.Add($EnhancedDetectionMethod.Settings.RegistryKey[$i]) | Out-Null
                }
            }
            else {
                Write-Log "EnhancedDetectionMethod.Settings.RegistryKey.count = 1"
                $EnhancedDetectionMethod.Settings.RegistryKey | Add-Member -MemberType NoteProperty -Name 'RegKey' -Value $EnhancedDetectionMethod.Settings.RegistryKey.Key
                Write-Log "Add-Member to EnhancedDetectionMethod.Settings.RegistryKey object RegKey = $($($($($EnhancedDetectionMethod).Settings).RegistryKey).Key)"
                $EnhancedDetectionMethod.Settings.RegistryKey | Add-Member -MemberType NoteProperty -Name 'DataType' -Value $EnhancedDetectionMethod.Rule.Expression.Operands.ConstantValue.DataType
                Write-Log "Add-Member to EnhancedDetectionMethod.Settings.RegistryKey object DataType = $($($($($($($EnhancedDetectionMethod).Rule).Expression).Operands).ConstantValue).DataType)"
                $DetectionMethodList.Add($EnhancedDetectionMethod.Settings.RegistryKey) | Out-Null
            }
        }
        
        # MSI version compare + exists
        if (Get-Member -inputobject $CurrentAppSDMPackageXML.AppMgmtDigest.DeploymentType.Installer.CustomData.EnhancedDetectionMethod.Settings -name "MSI" -Membertype Properties) {
            $EnhancedDetectionMethod = $CurrentAppSDMPackageXML.AppMgmtDigest.DeploymentType.Installer.CustomData.EnhancedDetectionMethod
            #Settings | ForEach-Object { 
            # adding data from the Rule node to the Settings.MSI object
            if ($EnhancedDetectionMethod.Settings.MSI.count -ge 2) {
                for ($i = 0; $i -lt $EnhancedDetectionMethod.Settings.MSI.count; $i++) {
                    Write-Log "EnhancedDetectionMethod.Settings.MSI.count = $($($($($EnhancedDetectionMethod).Settings).MSI).count)"
                    $EnhancedDetectionMethod.Settings.MSI[$i] | Add-Member -MemberType NoteProperty -Name 'MSIversion' -Value $EnhancedDetectionMethod.Rule.Expression.Operands.Expression.Operands.ConstantValue.Value[$i]
                    Write-Log "Add-Member to EnhancedDetectionMethod.Settings.MSI object RegValue = $($($($($($($($($EnhancedDetectionMethod).Rule).Expression).Operands).Expression).Operands).ConstantValue).Value[$i])"
                    $EnhancedDetectionMethod.Settings.MSI[$i] | Add-Member -MemberType NoteProperty -Name 'Operator' -Value $EnhancedDetectionMethod.Rule.Expression.Operands.Expression.Operator[$i]
                    Write-Log "Add-Member to EnhancedDetectionMethod.Settings.MSI object Operator = $($($($($($($EnhancedDetectionMethod).Rule).Expression).Operands).Expression).Operator[$i])"
                    $EnhancedDetectionMethod.Settings.MSI[$i] | Add-Member -MemberType NoteProperty -Name 'DataType' -Value $EnhancedDetectionMethod.Rule.Expression.Operands.Expression.Operands.ConstantValue.DataType[$i]
                    Write-Log "Add-Member to EnhancedDetectionMethod.Settings.MSI object DataType = $($($($($($($($($EnhancedDetectionMethod).Rule).Expression).Operands).Expression).Operands).ConstantValue).DataType[$i])"
                    # Get the logical operator between multiple conditions. Will always be the same. Got it this way to keep the structure
                    $EnhancedDetectionMethod.Settings.MSI[$i] | Add-Member -MemberType NoteProperty -Name "MasterOperator" -Value $EnhancedDetectionMethod.Rule.Expression.Operator
                    Write-Log "Add-Member NoteProperty MasterOperator = $($($($($EnhancedDetectionMethod).Rule).Expression).Operator)"
                    $DetectionMethodList.Add($EnhancedDetectionMethod.Settings.MSI[$i]) | Out-Null
                }
            }
            else {
                Write-Log "EnhancedDetectionMethod.Settings.MSI.count = 1"
                $EnhancedDetectionMethod.Settings.MSI | Add-Member -MemberType NoteProperty -Name 'MSIversion' -Value $EnhancedDetectionMethod.Rule.Expression.Operands.ConstantValue.Value
                Write-Log "Add-Member to EnhancedDetectionMethod.Settings.MSI object RegValue = $($($($($($($EnhancedDetectionMethod).Rule).Expression).Operands).ConstantValue).Value)"
                $EnhancedDetectionMethod.Settings.MSI | Add-Member -MemberType NoteProperty -Name 'Operator' -Value $EnhancedDetectionMethod.Rule.Expression.Operator
                Write-Log "Add-Member to EnhancedDetectionMethod.Settings.MSI object Operator = $($($($($EnhancedDetectionMethod).Rule).Expression).Operator)"
                $EnhancedDetectionMethod.Settings.MSI | Add-Member -MemberType NoteProperty -Name 'DataType' -Value $EnhancedDetectionMethod.Rule.Expression.Operands.ConstantValue.DataType
                Write-Log "Add-Member to EnhancedDetectionMethod.Settings.MSI object DataType = $($($($($($($EnhancedDetectionMethod).Rule).Expression).Operands).ConstantValue).DataType)"
                $DetectionMethodList.Add($EnhancedDetectionMethod.Settings.MSI) | Out-Null
            }
        }
        #else {
        #    Write-Log "AppMgmtDigest.DeploymentType.Installer.CustomData.EnhancedDetectionMethod.Settings = not supported"
        #}
    }
    else {
        Write-Log "Non-enhanced detection method"
    }
    return $DetectionMethodList
    
}

function Get-AppIcon {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        $CurrentApp
    )
    Write-Log "Get-AppIcon $AppName LocalizedDisplayName = $($CurrentApp.LocalizedDisplayName)"

    [xml]$CurrentAppSDMPackageXML = $CurrentApp.SDMPackageXML
    # install & uninstall command line
    # $item = New-Object System.Object
    $SupportFiles = $CurrentAppSDMPackageXML.AppMgmtDigest.DeploymentType.Installer.Contents.Content.Location + 'SupportFiles'
    if ([System.IO.Directory]::Exists($SupportFiles)) {
        Write-Log "$SupportFiles folder exists"
        $IconLocation = (Get-ChildItem "FileSystem::$SupportFiles" -Recurse | Where-Object { $_.name -like "*.ico" }).fullname
    }
    else { $IconLocation = 'None' }
    Write-Log "Icon location = $IconLocation"
    return $IconLocation
}

function Get-ExecutionContext {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        $CurrentApp
    )
    Write-Log "Get-ExecutionContext $AppName LocalizedDisplayName = $($CurrentApp.LocalizedDisplayName)"

    [xml]$CurrentAppSDMPackageXML = $CurrentApp.SDMPackageXML
    # install & uninstall command line
    # $item = New-Object System.Object
    $ExecContext = $CurrentAppSDMPackageXML.AppMgmtDigest.DeploymentType.Installer.ExecutionContext
    Write-Log "ExecutionContext = $ExecContext"
    
    return $ExecContext
}

function Get-AppInfo {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        $CurrentApp
    )
    Write-Log "Get-AppInfo $AppName LocalizedDisplayName = $($CurrentApp.LocalizedDisplayName)"

    [xml]$CurrentAppSDMPackageXML = $CurrentApp.SDMPackageXML
    # AppContent
    $AppContentFolderName = $CurrentAppSDMPackageXML.AppMgmtDigest.DeploymentType.Installer.Contents.Content
    $item = New-Object System.Object
    $item | Add-Member -MemberType NoteProperty -Name "AppContentFolderName" -Value $AppContentFolderName
    Write-Log "AppContentFolderName = $AppContentFolderName"
    $AppExecutionContext = $CurrentAppSDMPackageXML.AppMgmtDigest.DeploymentType.Installer.ExecutionContext
    $item | Add-Member -MemberType NoteProperty -Name "AppExecutionContext" -Value $AppExecutionContext
    Write-Log "AppExecutionContext = $AppExecutionContext"
    # app description
    $Description = $CurrentAppSDMPackageXML.AppMgmtDigest.Application.DisplayInfo.Info.Description
    #$Description = if ($Description -ne '') { 'N/A' }
    $item | Add-Member -MemberType NoteProperty -Name "Description" -Value $Description
    Write-Log "Description = $Description"   
    # app InfoUrl
    $InfoUrl = $CurrentAppSDMPackageXML.AppMgmtDigest.Application.DisplayInfo.Info.InfoUrl
    #$InfoUrl = if ($InfoUrl -ne '') { 'N/A' }
    $item | Add-Member -MemberType NoteProperty -Name "InfoUrl" -Value $InfoUrl
    Write-Log "InfoUrl = $InfoUrl"
    # icon
    $icon = $CurrentAppSDMPackageXML.AppMgmtDigest.Resources.icon.data
    $item | Add-Member -MemberType NoteProperty -Name "icon" -Value $icon
    Write-Log "icon = $icon"

    return $item
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

    #! === MAIN CODE START ===

    if ((Get-Location).Drive.Name -ne 'XXX') { Set-SCCMconnection }

    $AppList | ForEach-Object {
        $AppName = $_
        $AppNameNoWildcard = $AppName.replace('[', '_')
        $AppNameNoWildcard = $AppNameNoWildcard.replace(']', '_')
        $BadApp = $false
        $CurrentApp = Get-CMApplication -Name $AppName -DisableWildcardHandling
    
        # export app source files + config files
        Export-CMApplication -Name $AppName -Path "$AppFilePath\$AppNameNoWildcard.zip" -IgnoreRelated -Comment "$AppName export" -Force
        Expand-Archive -LiteralPath "$AppFilePath\$AppNameNoWildcard.zip" -DestinationPath "$AppFilePath\$AppNameNoWildcard" -Force
        ### $SourcesPath = Select-Xml -Path "`"$AppFilePath\$AppNameNoWildcard\document.xml`"" -XPath "//Content" | ForEach-Object { $_.Node.FullPath }
        $AppContent = (Get-ChildItem "$AppFilePath\${AppNameNoWildcard}_files").FullName

        if (-not (Test-Path $IntuneWinAppUtil) ) { Write-Warning "$IntuneWinAppUtil missing!" }
        $IntuneWinArgs = @(
            "-c `"$AppContent`""
            "-s Deploy-Application.exe"
            "-o `"$AppFilePath\${AppNameNoWildcard}intunewin`""
            "-q"
        )
        Start-Process $IntuneWinAppUtil -ArgumentList $IntuneWinArgs -Wait

        $OperatorHash = @{Equals = "equal"; NotEquals = "notEqual"; GreaterEquals = "greaterThanOrEqual"; GreaterThan = "greaterThan"; LessEquals = "lessThanOrEqual"; LessThan = "lessThan" }
        $ReturnCodeHash = @{ 0 = 'Success'; 1707 = 'Success'; 3010 = 'Soft reboot'; 1641 = 'Hard reboot'; 1618 = 'Retry' }
        $ReturnCode = New-IntuneWin32AppReturnCode -ReturnCode 0 -Type "Success"
    
        $AppCommandLineObj = Get-AppCommandLine $CurrentApp
        #$AppIcon = Get-AppIcon $CurrentApp
        $AppExecutionContext = Get-ExecutionContext $CurrentApp

        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Connect-MSIntuneGraph -TenantID "XXX"

        # collect detection rules
        $DetectionRuleList = New-Object System.Collections.ArrayList
        Write-Log "Parsing AppDetectionMethodObj..."
        try {
            $AppDetectionMethodObj = Get-AppDetectionMethod $CurrentApp
            $AppDetectionMethodObj | ForEach-Object {
                if ($_.LogicalName -match 'File') {
                    Write-Log "AppDetectionMethodObj.LogicalName match File"
                    #[bool]$FileVersionCheck = if (Get-Member -inputobject $_ -name "Version" -Membertype Properties) { $true } else {$false}
                    #$AppDetectionRuleArgs = @(
                    #    Version = $FileVersionCheck
                    #)
                    if (Get-Member -inputobject $_ -name "Version" -Membertype Properties) {
                        # has file version check
                        Write-Log "AppDetectionMethodObj has Version property -> File version compare"
                        $DetectionRule = New-IntuneWin32AppDetectionRuleFile -Version -Path $_.Path -FileOrFolder $_.Filter -VersionValue $_.Version -Operator $OperatorHash.($_.operator)
                    }
                    else {
                        # only has file exists check
                        Write-Log "AppDetectionMethodObj does not have Version property -> File exists"
                        $DetectionRule = New-IntuneWin32AppDetectionRuleFile -Existence -Path $_.Path -FileOrFolder $_.Filter -DetectionType 'exists'
                    }
                }
                # Folder exists
                elseif ($_.LogicalName -match 'Folder') {
                    Write-Log "AppDetectionMethodObj.LogicalName match Folder. For folder tehre is only folder exists."
                    $DetectionRule = New-IntuneWin32AppDetectionRuleFile -Existence -Path $_.Path -FileOrFolder $_.Filter -DetectionType 'exists'
                }
                #Reg Key exists
                elseif ($_.LogicalName -match 'RegKey') {
                    Write-Log "AppDetectionMethodObj.LogicalName match RegKey -> Reg Key exists"
                    $DetectionRule = New-IntuneWin32AppDetectionRuleRegistry -Existence -KeyPath "$($_.Hive)\$($_.RegKey)" -DetectionType 'exists'
                }
                #Reg Value exists
                elseif ($_.DataType -eq 'Boolean') {
                    Write-Log "AppDetectionMethodObj.DataType equals Boolean -> Reg Value exists"
                    $DetectionRule = New-IntuneWin32AppDetectionRuleRegistry -Existence -KeyPath "$($_.Hive)\$($_.Key)" -ValueName $_.ValueName -DetectionType 'exists'
                }
                #Reg Value
                elseif ((Get-Member -inputobject $_ -name "DataType" -Membertype Properties) -and ($_.DataType -ne 'Boolean')) {
                    Write-Log "AppDetectionMethodObj.DataType property exists and not equals to Boolean -> Reg Value compare"
                    $CurrObj = $_
                    $DetectionRule = switch ($_.DataType) {
                        'Int64' { New-IntuneWin32AppDetectionRuleRegistry -KeyPath "$($CurrObj.Hive)\$($CurrObj.Key)" -ValueName $CurrObj.ValueName -IntegerComparison -IntegerComparisonOperator $OperatorHash.($CurrObj.operator) -IntegerComparisonValue $CurrObj.RegValue }
                        'String' { New-IntuneWin32AppDetectionRuleRegistry -KeyPath "$($CurrObj.Hive)\$($CurrObj.Key)" -ValueName $CurrObj.ValueName -StringComparison -StringComparisonOperator $OperatorHash.($CurrObj.operator) -StringComparisonValue $CurrObj.RegValue }
                        'Version' { New-IntuneWin32AppDetectionRuleRegistry -KeyPath "$($CurrObj.Hive)\$($CurrObj.Key)" -ValueName $CurrObj.ValueName -VersionComparison -VersionComparisonOperator $OperatorHash.($CurrObj.operator) -VersionComparisonValue $CurrObj.RegValue }
                        Default {}
                    }
                }
                # MSI
                elseif ($_.LogicalName -match 'MSI') {
                    Write-Log "AppDetectionMethodObj.LogicalName match MSI"
                    if ($_.MSIversion -eq 0) {
                        Write-Log "AppDetectionMethodObj.MSIversion equals 0 -> MSI exists"
                        $DetectionRule = New-IntuneWin32AppDetectionRuleMSI -ProductCode $_.ProductCode
                    }
                    else {
                        Write-Log "AppDetectionMethodObj.MSIversion not equals 0 -> do MSI version check"
                        $DetectionRule = New-IntuneWin32AppDetectionRuleMSI -ProductCode $_.ProductCode -ProductVersionOperator $OperatorHash.($_.operator) -ProductVersion $_.MSIversion
                    }
                }
                # MSI


                $DetectionRuleList.Add($DetectionRule) | Out-Null
            }
        }
        catch {
            Write-Log "Detection rule for $AppName cannot be determined. Please check." -Severity 2
            $BadApp = $true
            $DetectionRule = New-IntuneWin32AppDetectionRuleFile -Existence -Path 'C:\Windows' -FileOrFolder 'system32' -DetectionType 'exists'
            $DetectionRuleList.Add($DetectionRule)
        }
        if ($BadApp) {
            "[$GTimeStamp] $AppName" | Out-File  "$OutputFolder\BadAppList.txt" -Append
        }
        else {
            "[$GTimeStamp] $AppName" | Out-File  "$OutputFolder\GoodAppList.txt" -Append
        }
        [int]$RequiredDiskSpaceMB = (Get-Item "$AppFilePath\${AppNameNoWildcard}intunewin\Deploy-Application.intunewin").Length / 1mb

        $AppRequirementRuleArguments = @{
            Architecture                    = 'All'
            MinimumSupportedOperatingSystem = "1607"
            MinimumFreeDiskSpaceInMB        = $RequiredDiskSpaceMB
        }
        $AppRequirementRule = New-IntuneWin32AppRequirementRule @AppRequirementRuleArguments

        $AppInfo = Get-AppInfo $CurrentApp
        $AddIntuneWin32AppArguments = @{
            FilePath             = "$AppFilePath\${AppNameNoWildcard}intunewin\Deploy-Application.intunewin"
            DisplayName          = "${AppName}abcdef"
            #InformationURL       = $CurrentApp.InformationURL
            #Description          = $CurrentApp.Description
            Publisher            = $CurrentApp.Manufacturer
            Developer            = $CurrentApp.CreatedBy
            AppVersion           = $CurrentApp.SoftwareVersion
            InstallExperience    = $AppInfo.AppExecutionContext
            #icon                 = $CurrentApp.icon
            RestartBehavior      = "basedOnReturnCode"
            DetectionRule        = $DetectionRuleList
            InstallCommandLine   = $AppCommandLineObj.InstallCommandLine 
            UninstallCommandLine = $AppCommandLineObj.UninstallCommandLine 
            RequirementRule      = $AppRequirementRule
            Verbose              = $true
        }
        if ($AppInfo.InfoUrl -ne $null) { $AddIntuneWin32AppArguments = $AddIntuneWin32AppArguments + @{InformationURL = $AppInfo.InfoUrl } }
        if ($AppInfo.Description -ne $null) {
            $AddIntuneWin32AppArguments = $AddIntuneWin32AppArguments + @{Description = $AppInfo.Description }
        }
        else {
            $AddIntuneWin32AppArguments = $AddIntuneWin32AppArguments + @{Description = 'N/A' }
        }
        if ($AppInfo.icon -ne $null) { $AddIntuneWin32AppArguments + @{Icon = $AppInfo.icon } }
        Add-IntuneWin32App @AddIntuneWin32AppArguments
    }
    #$Icon = New-IntuneWin32AppIcon -FilePath $AppIcon
    #$AppInfo = Get-AppInfo $CurrentApp
    # if (-not (Test-Path "$AppFilePath\${AppNameNoWildcard}intunewin")) { New-Item -ItemType Directory -Path "$AppFilePath\${AppNameNoWildcard}intunewin" }
    # New-IntuneWin32AppPackage -SourceFolder $AppContent -SetupFile "Deploy-Application.exe" -OutputFolder "$AppFilePath\${AppNameNoWildcard}intunewin" -Verbose
    #$DetectionRule = New-IntuneWin32AppDetectionRule

    #[xml]$xmldocument = Get-Content -LiteralPath "$AppFilePath\$AppNameNoWildcard\document.xml"
    #$xmldocument.LibraryDocument.Contents.Content.OriginalPath


    #!=== Script Execution goes here !===

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



