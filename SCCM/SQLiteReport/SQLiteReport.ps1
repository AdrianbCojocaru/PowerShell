
<#

.SYNOPSIS
  Creates a database containing the Client Check results from GPO, Intune & Cortex .

.DESCRIPTION
  Gather 'ClientCheck' script run status from various sources and create a PSSQLite report.

.PARAMETER <Parameter_Name>
  None

.INPUTS
  None

.OUTPUTS
  "$PSScriptRoot\Data\ClientStatus.db"

.NOTES
  Author:         Adrian
  Purpose/Change: Initial script development

.EXAMPLE
  No parameters required

#>

#EndRegion =============================[Metadata]================================

#Region ================================[Parameters]================================

[CmdletBinding()]
Param (
    [switch]$IM
)

#EndRegion =============================[Parameters]================================

#Region ================================[Variables]=================================

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
[string]$Global:LogFile = "$LogFolder\$FileNameTimestamp-$LogFileName.log"
# How many log files to keep? Anything over this number will be deleted, starting with the oldest files.
[int32]$LogsFilesToKeep = 30
# Output file name.
[string]$OutputFileName = $ScriptName
# Output folder.
[string]$OutputFolder = "$PSScriptRoot\Output\$ScriptName"
# Full output file path.
[string]$Global:OutputFile = "$OutputFolder\$FileNameTimestamp-$OutputFileName.xlsx"
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
[array]$RequiredModules = @('PSSQLite'
    #    'ImportExcel'
)
#EndRegion === Template generic variables ===

# =================================
# === Script specific variables ===
# =================================
#! NOTE: Define HERE all script specific variables.
#! NOTE: Redefine any template generic variables, if needed.
[string]$GpoFiles = "Path"
#[string]$GpoFiles = "$PSScriptRoot\Data\ExitCode2"
[string]$IntuneFiles = "$PSScriptRoot\Data\IntuneData.csv"
#[string]$CortexIds = "$PSScriptRoot\Data\CortexActionIdList.txt"
[string]$CortexIds = "C:\Work\CortexActionIdList.txt"
[string]$HistoryDB = "$PSScriptRoot\Data\ClientStatus.db"
[string]$HistoryTableName = Get-Date -Format yyyyMMddTHHmmss
[string]$HistoryTableName = "A$HistoryTableName"
[string]$Results = "results"
$Conn = New-SQLiteConnection -DataSource $HistoryDB

#EndRegion =============================[Variables]=================================

#Region ================================[Functions]=================================
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
    $LogFilePath = $LogFile
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

function Invoke-CortexAPI {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $ReqBody
    )
    [string]$ApiKey = 'XXXXXXXXXXXXXXXXXXXXXX'
    [string]$ApiKeyID = '45'
    [string]$Url = 'https://api-XXXXXXXXXXXXXXXX.xdr.eu.paloaltonetworks.com/public_api/v1/scripts/get_script_execution_results/'
    Write-Log "Invoke-CortexAPI $Url"
    # Generate a 64 bytes random string:
    [string]$Nonce = ( -join ((0x30..0x39) + ( 0x41..0x5A) + ( 0x61..0x7A) + (0x30..0x39) | Get-Random -Count 64 | ForEach-Object { [char]$_ }) )
    # Write-Host ("Nonce: $Nonce")
    # Get the current timestamp as milliseconds:
    $EpochStartDate = ("01/01/1970" -as [DateTime])
    [string]$TimeStamp = [int]((New-TimeSpan -Start $EpochStartDate -End ([DateTime]::UtcNow)).TotalSeconds -as [string]) * 1000
    # Write-Host ("Timestamp: $TimeStamp")
    # Generate the auth key:
    $AuthKey = $ApiKey + $Nonce + $TimeStamp
    # Write-Host ("AuthKey: $AuthKey")
    # Convert to bytes object:
    $Encoder = [System.Text.Encoding]::UTF8
    $EncAuthKey = $Encoder.GetBytes($AuthKey)
    # Write-Host ("EncodedAuthKey: $EncAuthKey")
    # Calculate sha256:
    $Hasher = [System.Security.Cryptography.HashAlgorithm]::Create('sha256')
    $Hash = $Hasher.ComputeHash($EncAuthKey)
    $HashString = [System.BitConverter]::ToString($Hash)
    #Remove dashes:
    $ApiKeyHash = $HashString.Replace('-', '').ToLower()
    # Write-Host ("APIKeyHash:$ApiKeyHash")
    # Generate HTTP call headers:
    $Headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $Headers.Add("x-xdr-timestamp", $TimeStamp)
    $Headers.Add("x-xdr-Nonce", $Nonce)
    $Headers.Add("x-xdr-auth-id", $ApiKeyID)
    $Headers.Add("Authorization", $ApiKeyHash)
    # Make sure the TLS version used is 1.2 before invoking the REST API
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::TLS12
    # Invoke the method:
    $CortexData = Invoke-RestMethod -Uri $Url -Method 'Post' -Headers $Headers -Body $ReqBody
    Write-Log "Name: $($($CortexData.reply).script_name) Description: $($($CortexData.reply).script_description) Date Created: $($($CortexData.reply).date_created)"
    Write-Output $CortexData.reply
}
function Get-GPOScriptResults {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [System.IO.FileInfo]$FilePath
    )
    Begin {
        Write-Log "=========== Get-GPOScriptResults start. ==========="
        $ObjList = New-Object System.Collections.Generic.List[System.Object]
    }
    Process {
        Write-Log "Processing: $($FilePath.FullName)"
        $DomainComputerName = $FilePath.BaseName -split "+", 0, "simplematch"
        $ResultsObj = [PSCustomObject]@{
            DomainName = $DomainComputerName[0].ToLower()               # Data Type: String
            DeviceName = $DomainComputerName[1]                         # Data Type: String
            ExitCode   = [int](Get-Content -Path $FilePath.FullName)    # Data Type: Int32
            Timestamp  = [datetime]$FilePath.LastWriteTimeUtc           # Data Type: DateTime
        }
        $ObjList.Add($ResultsObj)
    }

    End {
        Write-Log "=========== Get-GPOScriptResults end. ==========="
        return $ObjList
    }
}
function Get-IntuneScriptResults {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [System.IO.FileInfo]$FilePath
    )
    Begin {
        Write-Log "=========== Get-IntuneScriptResults start. ==========="
        $ObjList1 = [System.Collections.ArrayList]::new()
    }
    Process {
        Write-Log "Processing: $($FilePath.FullName)"
        $csv = Import-Csv $FilePath.FullName | Select-Object -Property @{Name = 'DomainName'; Expression = { $_.DomainName.ToLower() } },
        'DeviceName',
        'ExitCode',
        'Timestamp'
        $ObjList += $csv
        # $ResultsObj = [PSCustomObject]@{
        #     DomainName = $csv.DomainName.ToLower()  # Data Type: String
        #     DeviceName = $csv.DeviceName            # Data Type: String
        #     ExitCode   = $csv.ExitCode              # Data Type: Int32
        #     Timestamp  = $csv.Timestamp             # Data Type: DateTime
        # }
        # $ObjList.Add($ResultsObj)
    }

    End {
        Write-Log "=========== Get-IntuneScriptResults end. ==========="
        return $ObjList
    }
}

function Get-CortexScriptResults {
    Param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string]$action_id
    )
    Begin {
        Write-Log "=========== Get-CortexScriptResults start. ==========="
        $ObjList = New-Object System.Collections.Generic.List[System.Object]
    }
    Process {
        Write-Log "action_id = $action_id"
        [string]$RequestBody = "
        {
            `"request_data`": {
                `"action_id`": $action_id
            }
        }
        "
        $RetData = Invoke-CortexAPI -ReqBody $RequestBody
        $RetData.results | Select-Object -Property 'endpoint_name',
        'endpoint_status',
        'domain',
        'endpoint_id',
        'execution_status',
        'standard_output',
        @{Name = 'endpoint_ip_address'; Expression = { $_.endpoint_ip_address -join (',') } },
        @{Name = 'DomainName'; Expression = { (($_.domain -split '.', 0, "simplematch")[0]).ToLower() } },
        @{Name = 'DeviceName'; Expression = { $_.endpoint_name } },
        @{Name = 'ExitCode'; Expression = { if ($_.standard_output -match "^\d+$") { $_.standard_output } else { '' } } },
        @{Name = 'TimeStamp'; Expression = { [datetime]$RetData.date_created } }

        $ObjList.Add($RetData.results)
    }

    End {
        Write-Log "=========== Get-CortexScriptResults end. ==========="
        return $ObjList
    }
}

function Write-SQLiteDB {
    # Creates a new [$Data] table.
    # Drops the oldest table from the database if the number of existing tables exceeds $MaxTables
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        $Data,
        [Parameter(Mandatory = $true, Position = 1)]
        $MaxTables
    )
    $CreateDataHistoryTableQuery = @"
CREATE TABLE IF NOT EXISTS [$HistoryTableName] (
	[DomainName] TEXT,
    [DeviceName] TEXT NOT NULL,
    [ExitCode] TEXT,
    [Timestamp] DATETIME,
    PRIMARY KEY (DeviceName)
)WITHOUT ROWID;
"@

    $TableQuery = @"
SELECT
    name
FROM
    sqlite_master
WHERE
    type ='table' AND
    name NOT LIKE 'sqlite_%';
"@
    #    if (-not (Test-Path $HistoryDB)) {
    #   Write-Log "Creating $HistoryDB"
    Write-Log "CREATE TABLE IF NOT EXISTS [$HistoryTableName]"
    Invoke-SqliteQuery -Query $CreateDataHistoryTableQuery -DataSource $HistoryDB
    #    }
    #   else { Write-Log "$HistoryDB already exists" }
    #Invoke-SqliteQuery -SQLiteConnection $Conn -Query "ALTER TABLE $Results RENAME TO new_table;"
    Write-Log "DROP TABLE IF EXISTS $Results"
    Invoke-SqliteQuery -Query "DROP TABLE IF EXISTS `"$Results`"" -DataSource $HistoryDB
    $TableNames = (Invoke-SqliteQuery -SQLiteConnection $Conn -Query $TableQuery).Name | Sort-Object
    $TableNames | ForEach-Object { Write-Log $_ }
    if ($TableNames.Count -gt $MaxTables) {
        $ToRemove = ($TableNames | Sort-Object)[0]
        Write-Log "Number of existing tables [$($TableNames.Count)] is greater than the max number of allowed tables [$MaxTables]."
        write-log "DROP TABLE $ToRemove"
        Invoke-SqliteQuery -Query "DROP TABLE `"$ToRemove`"" -DataSource $HistoryDB
    }

    Write-Log "Writing $($Data.count) entries to $HistoryDB"
    $DataTable = $Data | Out-DataTable
    Invoke-SQLiteBulkCopy -DataSource $HistoryDB -DataTable $DataTable -Table $HistoryTableName -ConflictClause 'Replace' -Force
    # Create table query
    Write-Log "Create query for table $Results"
    for ($i = 0; $i -lt $TableNames.Count; $i++) {
        $q1 += "$($TableNames[$i]).DeviceName,
        $($TableNames[$i]).DomainName,
        $($TableNames[$i]).ExitCode,`n"
        if ($i -eq $TableNames.Count - 1) {
            $q1 = $q1.Substring(0, $q1.Length - 2)
            $q1 += "`n"
        }
    }
    for ($i = 0; $i -lt $TableNames.Count; $i++) {
        $q3 = $null
        $q += "SELECT $q1"
        $q += "FROM $($TableNames[$i])`n"

        $TableNames | ForEach-Object {
            if ($TableNames[$i] -ne $_) {
                $q3 += "LEFT JOIN $_ USING(DeviceName)`n"
            }
        }

        if ($i -ne $TableNames.Count - 1) {
            $q3 += "UNION`n"
        }
        $q += $q3

    }
    $q = "CREATE TABLE IF NOT EXISTS results AS`n" + $q

    # join la results table + last table, dosen't work as expected
    <#
    $CreateResultsTableQuery = @"
    CREATE TABLE IF NOT EXISTS $Results AS
    SELECT $($TableNames[0]).DomainName,
        $($TableNames[0]).DeviceName,
        $($TableNames[0]).ExitCode,
        $($TableNames[1]).DomainName,
        $($TableNames[1]).DeviceName,
        $($TableNames[1]).ExitCode,
        $($TableNames[2]).DomainName,
        $($TableNames[2]).DeviceName,
        $($TableNames[2]).ExitCode
    FROM $($TableNames[0])
    LEFT JOIN $($TableNames[1]) USING(DeviceName)
    LEFT JOIN $($TableNames[2]) USING(DeviceName)
    UNION
    SELECT $($TableNames[0]).DomainName,
        $($TableNames[0]).DeviceName,
        $($TableNames[0]).ExitCode,
        $($TableNames[1]).DomainName,
        $($TableNames[1]).DeviceName,
        $($TableNames[1]).ExitCode,
        $($TableNames[2]).DomainName,
        $($TableNames[2]).DeviceName,
        $($TableNames[2]).ExitCode
    FROM $($TableNames[1])
    LEFT JOIN $($TableNames[0]) USING(DeviceName)
    LEFT JOIN $($TableNames[2]) USING(DeviceName)
    UNION
    SELECT $($TableNames[0]).DomainName,
        $($TableNames[0]).DeviceName,
        $($TableNames[0]).ExitCode,
        $($TableNames[1]).DomainName,
        $($TableNames[1]).DeviceName,
        $($TableNames[1]).ExitCode,
        $($TableNames[2]).DomainName,
        $($TableNames[2]).DeviceName,
        $($TableNames[2]).ExitCode
    FROM $($TableNames[2])
    LEFT JOIN $($TableNames[0]) USING(DeviceName)
    LEFT JOIN $($TableNames[1]) USING(DeviceName)
"@
    #>
    Write-Log "Creating $Results table"
    Invoke-SqliteQuery -SQLiteConnection $Conn -Query $q # asta e ok
    # Invoke-SqliteQuery -Query $CreateResultsTableQuery -DataSource $HistoryDB


    # Compress DB
    Invoke-SqliteQuery -DataSource $HistoryDB -Query "VACUUM"
    return $TableNames.Count
}

function Get-AllData {
    # Makes sure the data is unique
    # If duplicate check TimeStamp, keep the newst.
    Param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [int]$NrOfTables
    )
    Begin {
        Write-Log "===========  Get-AllData. ==========="
        Write-Log "$NrOfTables tables returned."
    }
    Process {
    }

    End {
        Write-Log "Invoke-SqliteQuery -SQLiteConnection $Conn -Query SELECT * FROM $Results"
        $ResultsTable = Invoke-SqliteQuery -SQLiteConnection $Conn -Query "SELECT * FROM $Results"
        $ResultsTableCustom = $ResultsTable | Select-Object -Property ExitCode*,
        @{Name = 'ComputerName'; Expression = { for ($i = 0; $i -le $NrOfTables; $i++) { if ($_."DeviceName:$i" -ne $null) { $_."DeviceName:$i"; break } } } }
        Write-Log "Invoke-SqliteQuery -DataSource $HistoryDB -Query VACUUM"
        Invoke-SqliteQuery -DataSource $HistoryDB -Query "VACUUM"

        $FinalObj = $ResultsTableCustom | Select-Object -Property ComputerName, ExitCode*
        Write-Log "=========== Get-CortexScriptResults end. ==========="
        # Compress DB

        return $FinalObj
    }
}
#EndRegion =============================[Functions]=================================

#Region ================================[EXEC]=====================================

try {
    # Clear the terminal.
    Clear-Host
    # Write Log header.
    Write-Log "================================================================" 0
    Write-Log "Starting Script [$ScriptName]."
    Write-Log "Powershell version: $($PSVersionTable.PSVersion -join ('.'))"
    Write-Log "Running as user: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"
    Write-Log "Hostname: $env:COMPUTERNAME"
    Write-Log "================================================================" 0
    # Prepare the output folders.
    Initialize-Script
    # Call the 'Manage external modules" script block.
    Initialize-ExternalModules

    #! === MAIN CODE START ===

    $ScriptResults_GPO = Get-ChildItem $GpoFiles | Get-GPOScriptResults | Select-Object DomainName, DeviceName, ExitCode, Timestamp
    $ScriptResults_Cortex = Get-Content $CortexIds | Get-CortexScriptResults # | Select-Object DomainName, DeviceName, ExitCode, Timestamp
    $ScriptResults_Intune = Get-ChildItem $IntuneFiles | Get-IntuneScriptResults | Select-Object DomainName, DeviceName, ExitCode, Timestamp

    # Remove empty elements
    $ScriptResults = New-Object System.Collections.Generic.List[System.Object]
    $ScriptResults_All = $ScriptResults_GPO + $ScriptResults_Cortex + $ScriptResults_Intune
    Write-Log "$($ScriptResults_All.Count) total results." 
    $ScriptResults_All | ForEach-Object { if ($_.DeviceName -ne $null) { $ScriptResults.Add($_) } }
    Write-Log "$($ScriptResults.Count) non-empty results."

    # Add sorted & unique results to the database
    $ScriptResults_Cleaned = $ScriptResults | Sort-Object -Property DeviceDomain, DeviceName, TimeStamp -Descending -Unique
    $ScriptResults_Cleaned = $ScriptResults_Cleaned | Group-Object DeviceName | ForEach-Object { $_.Group | Sort-Object -Property TimeStamp -Descending | Select-Object -First 1 }
    Write-Log "$($ScriptResults_Cleaned.Count) unique results."
    $NrOfTables = Write-SQLiteDB -Data $ScriptResults_Cleaned -MaxTables 30
    # $ResultsForEcel = Get-AllData $NrOfTables

    #rename previos XLSX
    if (Test-Path "$PSScriptRoot\Output\Results.xlsx") {
        $DateTime = Get-Date -Format "yyyy_MM_dd_HH_mm_ss"
        Rename-Item -Path "$PSScriptRoot\Output\Results.xlsx" -NewName $DateTime
    }

    $ExportExcelParams = @{
        WorkSheetName = "$($File1SelectKey.SelectedItem)_&_$($File2SelectKey.SelectedItem)"
        TableName     = 'Data'
        TableStyle    = 'Medium13'
        Show          = $true
        AutoSize      = $true
        ClearSheet    = $true
        Path          = "$PSScriptRoot\Output\Results.xlsx"
    }

    Get-AllData $NrOfTables | Export-Excel @ExportExcelParams

}

#! === MAIN CODE END ===

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
    Write-Log "Global exit code: $Global:ExitCode"
    Write-Log "Global output: $($Global:Output -join ', ')"
    Write-Log "================================================================" 0
    Write-Log "Script [$ScriptName] finished."
    Write-Output $Global:Output
    Exit $Global:ExitCode
}

#EndRegion =============================[EXEC]=====================================
