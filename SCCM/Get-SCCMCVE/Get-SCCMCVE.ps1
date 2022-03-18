<#

.SYNOPSIS
  Determines the Microsoft CVE Updates status in SCCM

.DESCRIPTION
  The script is expecting the *.xlsx CVE files under the „Data” folder
  For every KB in every XLS the following will be determined: „Out of support”, „ExistsInSCCM”, „IsDeployed”

.PARAMETER ShowAll
  ShowAll it will add the 3 above properties in the XLSX output

.INPUTS
  None

.OUTPUTS
  One XLSX file will be created in the Output folder

.NOTES
  Author:         Adrian
  Creation Date:  09-Mar-2020
  Purpose/Change: Initial script development

.EXAMPLE
  powershell.exe -ExecutionPolicy Bypass -File "<PathToThisScript.ps1>" -ShowAll

#>

#EndRegion ============================[Metadata]==============================

#Region ===============================[Parameters]============================

# https://4sysops.com/archives/powershell-advanced-functions-the-cmdletbinding-and-parameter-attribute/
#[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [switch]$ShowAll
)
#
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
#[array]$RequiredModules = @('ImportExcel')
#EndRegion === Template generic variables ===

# =================================
# === Script specific variables ===
# =================================
#! NOTE: Define HERE all script specific variables.
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
Function Get-WebCVEs {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$SourceHTML
    )
    Begin { }
    Process { }
    End {
        $html = New-Object -ComObject "HTMLFile"
        $html.IHTMLDocument2_write($(Get-Content $file -raw))
        $AllmsrcTags = $html.all.tags("A") | % innerText  | Where-Object { $_ -like "*msrc.microsoft.com/update-guide/vulnerability*" } # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-21990
        $strCVEs = $AllmsrcTags | Split-Path -Leaf # CVE-2022-21990
        $strCVEs | ForEach-Object {
            Invoke-WebRequest -UseBasicParsing -Uri "https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability/$_"
        }

    }
}

Function Set-SCCMconnection {
    Write-Log "Set-SCCMconnection executing."
    # Site configuration
    $SiteCode = "XXX" # Site code 
    $ProviderMachineName = "XXX.com" # SMS Provider machine name
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

Function Get-SCCMupdaateStatus {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        $GroupedUpdates
    )
    Begin { 
        Write-Log "Get-SCCMupdaateStatus start."
    }
    Process {
        # check if not Out Of Support
        if ($_.OutOfSupport -eq $false) {
            # Check if the KB hasn't already been looked up in SCCM
            $SCCMUpdCollection += (Get-CMSoftwareUpdate -ArticleId $_.Name -Fast)
        }
        
        else { Write-Log "OutOfSupport = True for $($_.Article) | Doing nothing" }
    }
    End {
        Write-Log "Get-SCCMupdaateStatus end."
        $SCCMUpdCollection
    }
}

Function Set-Update {
    # Do xls-sccm update match
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        $SCCMUpdates,
        [Parameter(Mandatory = $true, Position = 1)]
        $XLSUpdates
    )
    Begin { 
        Write-Log "Set-Update start."
    }
    Process {
        # check if not Out Of Support
        
        # Check if the KB hasn't already been looked up in SCCM
        # SCCM Updates - as input obj
        $_ | ForEach-Object {
            $SCCMKB = $_
            $arr | ForEach-Object {
                if ($_.OutOfSupport -eq '') { 
                    $DN = $_.DisplayName
                    if ($SCCMKB.LocalizedDisplayName -like "*$DN*") {
                        $_ | Add-Member -NotePropertyName ExistsInSCCM -NotePropertyValue True -Force
                        $SCCMKBIsDeployed = if ($SCCMKB.IsDeployed) { 'True' } else { 'False' }
                        $_ | Add-Member -NotePropertyName IsDeployed -NotePropertyValue $SCCMKBIsDeployed -Force
                        Write-Log "$($SCCMKB.LocalizedDisplayName) = $DN | IsDeployed = $($SCCMKB.IsDeployed)"            
                    }            
                }   
            }
        }
    }
    End {
        Write-Log "Set-Update end."
        return $XLSUpdates
    }
}

Function Remove-OutOfSupport {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        $Updateobj
    )
    Begin { 
        Write-Log "Remove-OutOfSupport start."
        $OutOfSupport = @('Office 2013', 'Windows 7', 'Windows RT 8.1', 'Windows 8.1', 'Windows Server 2008',
            'Version 1809', 'Version 1507', 'Version 1511', 'Version 1607', 'Version 1703',
            'Version 1709', 'Version 1803', 'Version 1809', 'Version 1903')
        $NotInProdEdition = @('ARM64', 'Server Core', 'for Mac')
    }
    Process {
        $_ | Add-Member -NotePropertyName OutOfSupport -NotePropertyValue '' -Force
        $_ | Add-Member -NotePropertyName NotInProdEdition -NotePropertyValue '' -Force
        Write-Log "Processing $($_.Article) $($_.Product)."
        ForEach ($OOS in $OutOfSupport) {
            if ($_.Product -match $OOS) {
                Write-Log "OutOfSupport = True."
                $_.OutOfSupport = 'True'
                break
            }
        }
        ForEach ($Dont in $NotInProdEdition) {
            if ($_.Product -match $Dont) {
                Write-Log "NotInProdEdition = True."
                $_.NotInProdEdition = 'True'
                break
            }
        }  
    }
    End {
        Write-Log "Remove-OutOfSupport end."
    }
}

#Get-CMSoftwareUpdate -ArticleId 5010403
if ((Get-Location).Drive.Name -ne 'ZZZ') { Set-SCCMconnection }
$Allxslx = Get-ChildItem -Path $DataFolder\* -Include *.xlsx
$Allxslx | ForEach-Object {
    Write-Log "Reading $($_.FullName)"
    $arr = $null
    $SCCMUpdCollection = @()
    $arr = Import-Excel $_.FullName
    $arr | Add-Member -NotePropertyName ExistsInSCCM -NotePropertyValue '' -Force
    $arr | Add-Member -NotePropertyName IsDeployed -NotePropertyValue '' -Force
    $arr | Add-Member -NotePropertyName OutOfSupport -NotePropertyValue '' -Force
    $arr | ForEach-Object { 
        $_ | Add-Member -NotePropertyName DisplayName -NotePropertyValue $_.Product -Force
        if ($_.DisplayName -like "*32-bit*") { $_.DisplayName = $_.DisplayName -replace '32-bit', 'x86-based' }
        if ($_.DisplayName -like "*Systems*") { $_.DisplayName = $_.DisplayName.Substring(0, $_.DisplayName.ToLower().IndexOf('systems')) }
        if ($_.DisplayName -like "*Service Pack*") { $_.DisplayName = $_.DisplayName.Substring(0, $_.DisplayName.ToLower().IndexOf('service pack')) }
        if ($_.DisplayName -like "*Cumulative Update*") { $_.DisplayName = $_.DisplayName -replace 'Cumulative Update ', 'CU' }
        if ($_.DisplayName -like "*Microsoft Exchange Server*") { $_.DisplayName = $_.DisplayName -replace 'Microsoft Exchange Server', 'Exchange Server' }
        # if ($_.DisplayName -like "*(64-bit edition)*") { $_.DisplayName = $_.DisplayName.Substring(0, $_.DisplayName.ToLower().IndexOf('(64-bit edition)')) }
    }

    #$arr = Import-Excel "C:\Tools\Security Updates 2022-03-11-093313a''x"
    $arrGrouped = $arr | Group-Object Article
    $arrGrouped | ForEach-Object { $SCCMUpdCollection += (Get-CMSoftwareUpdate -ArticleId $_.Name -Fast) }
    #$5010342SCCM = Get-CMSoftwareUpdate -ArticleID $arrGrouped[0].Name
    $arr | Remove-OutOfSupport
    $SCCMUpdCollection | Set-Update -XLSUpdates $arr
    
    # Building final object for EXcel
    $CVEName = $arr[0].Details
    $arr | Add-Member -MemberType AliasProperty -Name $CVEName -Value Product
    $arr | Add-Member -NotePropertyName Info -NotePropertyValue '' -Force

    # Adding Final Info property based on the OutOfSupport, ExistsInSCCM & IsDeployed values
    $re = $arr | Where-Object { $_.NotInProdEdition -eq '' } | Select-Object -Property $CVEName, Article, OutOfSupport, ExistsInSCCM, IsDeployed,
    @{Name = 'Info'; Expression = { if ($_.OutOfSupport) { "Out of support OS" }
            elseif ($_.ExistsInSCCM) {
                if ($_.IsDeployed -eq 'True') { 'Included to the current Software Update group' } else { 'Available in SCCM but not deployed' }
            }
            else { 'Not available in SCCM' } 
        } 
    }
    $OutPath = if ($ShowAll) { "$OutputFolder\Results-ShowAll.xlsx" } else { "$OutputFolder\Results.xlsx" }

    $ExportExcelParams = @{
        WorkSheetName = $CVEName
        TableName     = $CVEName
        TableStyle    = 'Medium13'
        Append        = $true
        Show          = $false
        AutoSize      = $true
        Path          = $OutPath
    }
    if ($ShowAll) {
        $re | Export-Excel @ExportExcelParams
    }
    else {
        $re |  Select-Object -Property $CVEName, Article, Info | Export-Excel @ExportExcelParams
    }

}
