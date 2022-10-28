# diag_api.psm1
# by tdimli
# March 2020
# API/helper functions

# errors reported by these diagnostics won't be shown on screen to user
# only saved to xray_ISSUES-FOUND_*.txt report file
$Global:BETA_DIAGS = "
net_802dot1x_KB4556307,
net_firewall_KB4561854,
net_wlan_KB4557342,
net_dnscli_KB4562541,
net_dasrv_KB4504598,
net_netio_KB4563820,
net_srv_KB4562940,
net_hyphost_KB4562593,
net_vpn_KB4553295,
net_vpn_KB4550202,
net_proxy_KB4569506,
net_branchcache_KB4565457,
net_dnssrv_KB4561750,
net_dnssrv_KB4569509,
net_dnscli_KB4617560,
net_ncsi_KB4648334,
net_srv_KB4612362
"

# constants
# return codes
$Global:RETURNCODE_SUCCESS = 0
$Global:RETURNCODE_SKIPPED = 1
$Global:RETURNCODE_FAILED = 2
$Global:RETURNCODE_EXCEPTION = 3

# issue types
$Global:ISSUETYPE_INFO = 0
$Global:ISSUETYPE_WARNING = 1
$Global:ISSUETYPE_ERROR = 2

# value could not be retrieved
$Global:VALUE_NA = "<error!>"

# time format
$Global:TIME_FORMAT = "yyMMdd-HHmmss"

# xray registry path
$xrayRegistryPath = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\xray"

# wmi data
$Global:wmi_Win32_ComputerSystem
$Global:wmi_Win32_OperatingSystem

# poolmon data
$Global:poolmonData

# globals
$version

$startTime
$timestamp

$dataPath
$logFile
$infoFile
$issuesFile
$xmlRptFile

$currDiagFn

$xmlReport
$xmlNsMgr
$nodeXray
$xmlTechAreas
$xmlParameters
$xmlSystemInfo
$xmlDiagnostics

# counters
$Global:numDiagsRun = 0
$Global:numDiagsSuccess = 0
$Global:numDiagsSkipped = 0
$Global:numDiagsFailed = 0
$Global:numIssues = 0

$Global:issueShown = $false

# To report an issue if one was identified by a diagnostic function
# Diagnostic functions use this function to report the issue they have identified 
# $issueType: 0 (Info), 1 (Warning) or 2 (Error)
function ReportIssue 
{
    param(
            [Parameter(Mandatory=$true,
            Position=0)]
            [string]
            $issueMsg,

            [Parameter(Mandatory=$true,
            Position=1)]
            [Int]
            $issueType
        )

    $Global:numIssues++
    $onScreenMsg = $true

    # get caller/diagnostic details
    $loc = $VALUE_NA
    $diagFn = $VALUE_NA
    $callStack = Get-PSCallStack
    if ($callStack.Count -gt 1) {
        $loc = (Split-Path -Path $callStack[1].ScriptName -Leaf).ToString() + ":" +  $callStack[1].ScriptLineNumber
        $diagFn = $callStack[1].FunctionName
        if (($loc -eq "") -or ($loc -eq $null)) {
            $loc = $VALUE_NA
        }
        if (($diagFn -eq "") -or ($diagFn -eq $null)) {
            if ($Global:currDiagFn -ne $null) {
                $diagFn = $Global:currDiagFn
            }
            else {
                $diagFn = $loc
            }
            LogWrite "Diagnostic name uncertainty: No on screen message"
            $onScreenMsg = $false
        }
    }

    XmlDiagnosticUpdateIssue $diagFn $IssueType
    LogWrite "Issue (type:$issueType) reported by diagnostic $diagFn [$loc]"

    $outFile = $issuesFile

    # reported issue not an error
    if ($issueType -lt $ISSUETYPE_ERROR) {
        LogWrite "Issue type is not error: No on screen message, saving to info file instead"
        $outFile = $infoFile
        $onScreenMsg = $false
    }

    # diagnostic in beta, no on-screen message
    if ($BETA_DIAGS.Contains($diagFn)) {
        LogWrite "Diagnostic in beta: No on screen message"
        $onScreenMsg = $false
    }

    if(!(Test-Path -Path $outFile)){
        "xray by tdimli, v$version">$outFile
        "Diagnostic check run on $timestamp UTC`r`n">>$outFile
    }
    else {
        # add separator
        "`r`n* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *`r`n">>$outFile
    }
        
    "**">>$outFile
    "** Issue $numIssues`tFound a potential issue (reported by $diagFn):">>$outFile
    "**">>$outFile
    $issueMsg>>$outFile
    
    # show message on screen
    if ($onScreenMsg) {
        $Global:issueShown = $true
        Write-Host ("
**
** Issue $numIssues`tFound a potential issue (reported by $diagFn):
**") -ForegroundColor red
        IndentMsg $issueMsg
    }
}

# Wraps a filename with "xray_" prefix and timestamp & computername suffix for consistency
# Ensures all files created have the same name format, same run of xray script uses the same timestamp-suffix
# Also prepends $dataPath to ensure all files are created in the designated folder
function MakeFilename
{
    param(
            [Parameter(Mandatory=$true,
            Position=0)]
            [string]
            $name,

            [Parameter(Mandatory=$true,
            Position=1)]
            [string]
            $extension
        )

    $computer = hostname
    $filename = "xray_" + $name + "_" + $timestamp + "_" + $computer + "." + $extension
    return Join-Path -Path $dataPath -ChildPath $filename
}

# Logs to activity log with timestamp
function LogWrite
{
    param(
            [Parameter(Mandatory=$true,
            Position=0)]
            [string]
            $msg
        )

    $callStack = Get-PSCallStack
    $caller = $VALUE_NA
    if ($callStack.Count -gt 1) {
        $caller = $callStack[1].FunctionName + " " + (Split-Path -Path $callStack[1].ScriptName -Leaf).ToString() + ":" +  $callStack[1].ScriptLineNumber
    }
    $time = (Get-Date).ToUniversalTime().ToString("yyMMdd-HHmmss.fffffff")
    "$time [$caller] $msg" >> $logFile
}

# returns summary data from poolmon
# if multiple poolmon data sets are available one set for each will be returned
# each returned set will contain two list items with a string[7] in following format
# Example:
# For sample summary:
#  Memory:33356024K Avail:19399488K  PageFlts:400263915   InRam Krnl:12672K P:935188K
#  Commit:15680004K Limit:40433912K Peak:15917968K            Pool N:629240K P:1004712K
# it will return string array(s) containing:
#  Summary1,22/05/2020 22:35:55.53,33356024,19399488,400263915,12672,935188
#  Summary2,22/05/2020 22:35:55.53,15680004,40433912,15917968,629240,1004712
function GetPoolUsageSummary
{
    [System.Collections.Generic.List[string[]]] $poolmonInfo = New-Object "System.Collections.Generic.List[string[]]"

    foreach ($entry in $poolmonData) {
        if ($entry.Contains("Summary")) {
            $poolmonInfo.Add($entry -split ',')
        }
    }

    return $poolmonInfo
}

# returns pool usage info from poolmon for specified pool tag and type
# pooltag has to be 4 characters (case-sensitive), pooltype can be "Nonp" or "Paged" (case-sensitive)
# if multiple poolmon data sets are available all matching entries will be returned
# returns $null if no entry for specified item
# return data type is list of Int64 arrays
# Example:
# For sample entry:
#  Ntfx Nonp    1127072   1037111     89961 26955808        299        
# it will return an Int64 array containing:
#  1127072, 1037111, 89961, 26955808, 299
function GetPoolUsageByTag
{
    param(
            [Parameter(Mandatory=$true,
            Position=0)]
            [ValidatePattern(“.{4}”)]
            [string]
            $poolTag,

            [Parameter(Mandatory=$true,
            Position=1)]
            [ValidatePattern(“(Nonp|Paged)")]
            [string]
            $poolType
        )

    [System.Collections.Generic.List[Int64[]]] $poolmonInfo = New-Object "System.Collections.Generic.List[Int64[]]"

    foreach ($entry in $poolmonData) {
        if ($entry.Contains("$poolTag,$poolType")) {
            $pmEntry = $entry -split ','
            [Int[]] $intArr = New-Object Int[] 5
            for ($i =0; $i -lt 5; $i++) {
                $intArr[$i] = [Convert]::ToInt64($pmEntry[$i + 2])
            }

            $poolmonInfo.Add($intArr)
        }
    }

    return ,$poolmonInfo # unary operator comma is to force the output type to array
}

<#
 Checks if one of the required updates ($reqUpdates) or a later update is present
 Returns 
  true if a required update or later is installed (or if none of the required updates do 
  not apply to current OS version)
   or
  false if a required update is not present (and one of the required updates applies to 
  current OS version)
 $required has a list of updates that specifies the minimum required update for any OS versions 
 to be checked
#>
function HasRequiredUpdate
{
    param(
        [Parameter(Mandatory=$true,
        Position=0)]
        [string[]]
        $reqUpdates
    )

    $unknownUpdates = $true
    $knownUpdateSeen = $false

    foreach ($minReqUpd in $reqUpdates) {
        foreach($name in $updateLists) {
            $updateList = (Get-Variable -Name $name -ErrorVariable ErrorMsg -ErrorAction SilentlyContinue).Value
            $minReqIdx = $updateList.id.IndexOf($minReqUpd)
            if ($minReqIdx -ge 0) {
                $unknownUpdates = $false
                foreach($installedUpdate in $installedUpdates) {
                    # look for $minReqUpd or later update
                    $instIdx = $updateList.id.IndexOf($installedUpdate.HotFixID)
                    if ($instIdx -ge 0) {
                        $knownUpdateSeen = $true
                        if ($instIdx -le $minReqIdx) { # updates in $updateList are in reverse chronological order, with most recent at idx=0
                            return $true
                        }
                    }
                }
            }
        }
    }

    if ($unknownUpdates) {
        LogWrite "Required update(s) not known"
        throw
    }

    if ($knownUpdateSeen) {
        return $false
    }

    return $true
}

<#
 Checks if all available Windows updates are installed
 Returns n where
  n=0 latest available update is installed, system up-to-date
  n>0 number of missing updates, i.e. updates that are available but not installed
  n<0 update status cannot be determined
#>
function CheckUpdateStatus
{
    param(
        [Parameter(Mandatory=$true,
        Position=0)]
        [Boolean]
        $offline
    )

    $errMsg = @"
This system is missing many important updates. 

The last update installed on this system was:
  {0}

Following {1} update(s) have been released since then:
{2}
Resolution
Please install below update as a matter of urgency:
  {3}
"@
    $Global:NumMissingUpdates = -1
    Clear-Variable -Name MissingUpdates -Scope Global -ErrorVariable ErrorMsg -ErrorAction SilentlyContinue
    
    if($offline) {
        LogWrite "Cannot run offline, skipping"
        return $RETURNCODE_SKIPPED
    }

    # Look for missing updates
	try	{
        if ($installedUpdates.Count -eq 0) {
            LogWrite "installedUpdates empty!"
            return $RETURNCODE_FAILED
        }
        
        $updateFound = $false
        foreach ($installedUpdate in $installedUpdates) {
            LogWrite $installedUpdate.HotfixId
            foreach ($name in $updateLists) {
                $updateList = (Get-Variable -Name $name -ErrorVariable ErrorMsg -ErrorAction SilentlyContinue).Value
                $idxMRUI = $updateList.id.IndexOf($installedUpdate.HotfixId)
                if ($idxMRUI -ge 0) {
                    $updateFound = $true
                    $Global:NumMissingUpdates = $idxMRUI
                    if ($idxMRUI -gt 0) {
                        $Global:MissingUpdates = $updateList[0..($idxMRUI - 1)]
                    }
                    LogWrite "installedUpdates[$($installedUpdates.IndexOf($installedUpdate))] is a match for $name[$idxMRUI]"
                    break
                }
            }
            if ($updateFound) {
                break
            }
        }

        if ($NumMissingUpdates -lt 0) {
            # failure
            LogWrite "Error: None of the installed updates match update data, update status could not be determined."
            return $RETURNCODE_FAILED
        }
        elseif ($NumMissingUpdates -gt 2) {
            # missing too many updates
            foreach ($upd in $MissingUpdates.heading) {
                $mUpd += "  $upd`r`n"
            }
            $issueType = $ISSUETYPE_ERROR
            $issueMsg = [string]::Format($errMsg, $updateList[$NumMissingUpdates].heading, $NumMissingUpdates, $mUpd, $MissingUpdates[0].heading)
            ReportIssue $issueMsg $issueType
        }
	}
	catch {
		LogWrite "Failed - exiting! (Error: $_)"
        return $RETURNCODE_FAILED
    }

    return $RETURNCODE_SUCCESS
}

# Shows message on screen indented for readability
function IndentMsg
{
    param(
            [Parameter(Mandatory=$true,
            Position=0)]
            [string]
            $msg
        )

    $newMsg = $msg -split "`n"
    foreach ($line in $newMsg) {
        Write-Host "   $line"
    }
}

function InitGlobals
{
    param(
            [Parameter(Mandatory=$true,
            Position=0)]
            [string]
            $ver,

            [Parameter(Mandatory=$true,
            Position=1)]
            [string]
            $path
        )

    $Global:version = $ver
    $Global:dataPath = $path
    $Global:startTime = (Get-Date).ToUniversalTime()
    $Global:timestamp = $startTime.ToString($TIME_FORMAT)
    $Global:logFile = MakeFilename "log" "txt"
    $Global:infoFile = MakeFilename "INFO" "txt"
    $Global:issuesFile = MakeFilename "ISSUES-FOUND" "txt"
    $Global:xmlRptFile = MakeFilename "report" "xml"
    $Global:issueShown = $false

    # add and populate root node: nodeXray
    $Global:xmlReport = New-Object System.XML.XMLDocument
    $Global:nodeXray = $xmlReport.CreateElement("xray")
    [void] $xmlReport.appendChild($nodeXray)
    $nodeXray.SetAttribute("Version", $version)
    $nodeXray.SetAttribute("Complete", $false)
    $nodeXray.SetAttribute("StartTime", $timestamp)
    $nodeXray.SetAttribute("Complete", $false)
        
    # add nodes
    $Global:xmlTechAreas = $nodeXray.AppendChild($xmlReport.CreateElement("TechAreas"))
    $Global:xmlParameters = $nodeXray.AppendChild($xmlReport.CreateElement("Parameters"))
    $Global:xmlSystemInfo = $nodeXray.AppendChild($xmlReport.CreateElement("SystemInfo"))
    $Global:xmlDiagnostics = $nodeXray.AppendChild($xmlReport.CreateElement("Diagnostics"))

    # namespace manager
    $Global:xmlNsMgr = New-Object System.Xml.XmlNamespaceManager($xmlReport.NameTable)
    $xmlNsMgr.AddNamespace("xrayNS", $xmlReport.DocumentElement.NamespaceURI)
}

function AddSysInfo
{
    param(
            [Parameter(Mandatory=$true,
            Position=0)]
            [bool]
            $offline
        )

    if ($offline) {
        # if offline retrieve from data
        LogWrite "Offline system info collection not yet implemented"
        return
    }

    # PSVersionTable
    $PSVer = ($PSVersionTable)
    if ($PSVer -ne $null) {
        XmlAddSysInfo "PSVersionTable" "PSVersion" $PSVer.PSVersion
        XmlAddSysInfo "PSVersionTable" "WSManStackVersion" $PSVer.WSManStackVersion
        XmlAddSysInfo "PSVersionTable" "SerializationVersion" $PSVer.SerializationVersion
        XmlAddSysInfo "PSVersionTable" "CLRVersion" $PSVer.CLRVersion
        XmlAddSysInfo "PSVersionTable" "BuildVersion" $PSVer.BuildVersion
    }

    # installedUpdates
    $Global:installedUpdates = Get-HotFix | Sort-Object -Property InstalledOn -Descending -ErrorAction SilentlyContinue

    # Win32_ComputerSystem
    $Global:wmi_Win32_ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
    if ($wmi_Win32_ComputerSystem -ne $null) {
        XmlAddSysInfo "Win32_ComputerSystem" "BootupState" $wmi_Win32_ComputerSystem.BootupState
        XmlAddSysInfo "Win32_ComputerSystem" "PowerState" $wmi_Win32_ComputerSystem.PowerState
        XmlAddSysInfo "Win32_ComputerSystem" "DomainRole" $wmi_Win32_ComputerSystem.DomainRole
        XmlAddSysInfo "Win32_ComputerSystem" "Manufacturer" $wmi_Win32_ComputerSystem.Manufacturer
        XmlAddSysInfo "Win32_ComputerSystem" "Model" $wmi_Win32_ComputerSystem.Model
        XmlAddSysInfo "Win32_ComputerSystem" "NumberOfLogicalProcessors" $wmi_Win32_ComputerSystem.NumberOfLogicalProcessors
        XmlAddSysInfo "Win32_ComputerSystem" "NumberOfProcessors" $wmi_Win32_ComputerSystem.NumberOfProcessors
        XmlAddSysInfo "Win32_ComputerSystem" "OEMStringArray" $wmi_Win32_ComputerSystem.OEMStringArray
        XmlAddSysInfo "Win32_ComputerSystem" "PartOfDomain" $wmi_Win32_ComputerSystem.PartOfDomain
        XmlAddSysInfo "Win32_ComputerSystem" "PCSystemType" $wmi_Win32_ComputerSystem.PCSystemType
        XmlAddSysInfo "Win32_ComputerSystem" "SystemType" $wmi_Win32_ComputerSystem.SystemType
        XmlAddSysInfo "Win32_ComputerSystem" "TotalPhysicalMemory" $wmi_Win32_ComputerSystem.TotalPhysicalMemory
        XmlAddSysInfo "Win32_ComputerSystem" "HypervisorPresent" $wmi_Win32_ComputerSystem.HypervisorPresent
    }

    # Win32_OperatingSystem
    $Global:wmi_Win32_OperatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    if ($wmi_Win32_OperatingSystem -ne $null) {
        XmlAddSysInfo "Win32_OperatingSystem" "Caption" $wmi_Win32_OperatingSystem.Caption
        XmlAddSysInfo "Win32_OperatingSystem" "Version" $wmi_Win32_OperatingSystem.Version
        XmlAddSysInfo "Win32_OperatingSystem" "BuildType" $wmi_Win32_OperatingSystem.BuildType
        XmlAddSysInfo "Win32_OperatingSystem" "BuildNumber" $wmi_Win32_OperatingSystem.BuildNumber
        XmlAddSysInfo "Win32_OperatingSystem" "ProductType" $wmi_Win32_OperatingSystem.ProductType
        XmlAddSysInfo "Win32_OperatingSystem" "OperatingSystemSKU" $wmi_Win32_OperatingSystem.OperatingSystemSKU
        XmlAddSysInfo "Win32_OperatingSystem" "OSArchitecture" $wmi_Win32_OperatingSystem.OSArchitecture
        XmlAddSysInfo "Win32_OperatingSystem" "OSType" $wmi_Win32_OperatingSystem.OSType
        XmlAddSysInfo "Win32_OperatingSystem" "InstallDate" $wmi_Win32_OperatingSystem.InstallDate
        XmlAddSysInfo "Win32_OperatingSystem" "LocalDateTime" $wmi_Win32_OperatingSystem.LocalDateTime
        XmlAddSysInfo "Win32_OperatingSystem" "LastBootUpTime" $wmi_Win32_OperatingSystem.LastBootUpTime
    }
    
    XmlSave
} 

function XmlAddTechArea
{
    param(
        [Parameter(Mandatory=$true,
        Position=0)]
        [string]
        $name,

        [Parameter(Mandatory=$true,
        Position=1)]
        [string]
        $ver
    )

    [System.XML.XMLElement]$xmlTechArea = $xmlTechAreas.AppendChild($xmlReport.CreateElement("TechArea"))
    $xmlTechArea.SetAttribute("Name", $name)
    $xmlTechArea.SetAttribute("Version", $ver)
}

function XmlAddParameters
{
    param(
        [Parameter(Mandatory=$true,
        Position=0)]
        [AllowEmptyString()]
        [AllowNull()]
        [string[]]
        $areas,

        [Parameter(Mandatory=$true,
        Position=1)]
        [AllowEmptyString()]
        [AllowNull()]
        [string[]]
        $components,

        [Parameter(Mandatory=$true,
        Position=2)]
        [AllowEmptyString()]
        [AllowNull()]
        [string[]]
        $diagnostics,

        [Parameter(Mandatory=$true,
        Position=3)]
        [bool]
        $offline,

        [Parameter(Mandatory=$true,
        Position=4)]
        [bool]
        $waitBeforeClose,

        [Parameter(Mandatory=$true,
        Position=5)]
        [bool]
        $skipDiags,

        [Parameter(Mandatory=$true,
        Position=6)]
        [bool]
        $DevMode
    )

    foreach ($area in $areas) {
        [System.XML.XMLElement] $xmlArea = $xmlParameters.AppendChild($xmlReport.CreateElement("Area"))
        $xmlArea.SetAttribute("Name", $area)
    }
    foreach ($component in $components) {
        [System.XML.XMLElement] $xmlComponent = $xmlParameters.AppendChild($xmlReport.CreateElement("Component"))
        $xmlComponent.SetAttribute("Name", $component)
    }
    foreach ($diagnostic in $diagnostics) {
        [System.XML.XMLElement] $xmlComponent = $xmlParameters.AppendChild($xmlReport.CreateElement("Diagnostic"))
        $xmlComponent.SetAttribute("Name", $diagnostic)
    }
    [System.XML.XMLElement] $xmlOffline = $xmlParameters.AppendChild($xmlReport.CreateElement("Offline"))
    $xmlOffline.SetAttribute("Value", $offline)
    [System.XML.XMLElement] $xmlOffline = $xmlParameters.AppendChild($xmlReport.CreateElement("WaitBeforeClose"))
    $xmlOffline.SetAttribute("Value", $waitBeforeClose)
    [System.XML.XMLElement] $xmlOffline = $xmlParameters.AppendChild($xmlReport.CreateElement("SkipDiags"))
    $xmlOffline.SetAttribute("Value", $skipDiags)
    [System.XML.XMLElement] $xmlOffline = $xmlParameters.AppendChild($xmlReport.CreateElement("DevMode"))
    $xmlOffline.SetAttribute("Value", $DevMode)

    # save
    XmlSave
}

# to add a single attribute from a WMI class
function XmlAddSysInfo
{
    param(
        [Parameter(Mandatory=$true,
        Position=0)]
        [string]
        $valueName,

        [Parameter(Mandatory=$true,
        Position=1)]
        [string]
        $attribName,

        [Parameter(Mandatory=$true,
        Position=2)]
        [AllowNull()]
        [System.Object]
        $propertyValue
    )

    if ($propertyValue -ne $null) {

        [System.XML.XMLElement] $wmidata = $nodeXray.SelectSingleNode("/xray/SystemInfo/$valueName")
        if ((!$xmlSystemInfo.HasChildNodes) -or ($wmidata -eq $null)) {
            # doesn't exist, need to add
            $wmidata = $xmlSystemInfo.AppendChild($xmlReport.CreateElement($valueName))
        }
        $wmidata.SetAttribute($attribName, $propertyValue)
    }
}

# to add multiple/all attributes of a WMI class
function XmlAddSysInfoMulti
{
    param(
        [Parameter(Mandatory=$true,
        Position=0)]
        [string]
        $valueName,

        [Parameter(Mandatory=$true,
        Position=1)]
        [System.Object[]]
        $attributes
    )

    [System.XML.XMLElement] $wmidata = $nodeXray.SelectSingleNode("/xray/SystemInfo/$valueName")
    if ((!$xmlSystemInfo.HasChildNodes) -or ($wmidata -eq $null)) {
        # doesn't exist, need to add
        $wmidata = $xmlSystemInfo.AppendChild($xmlReport.CreateElement($valueName))
    }
    foreach($attribute in $attributes) {
        $wmidata.SetAttribute($attribute.Name, $attribute.Value)
    }
    XmlSave
}

function XmlAddDiagnostic
{
    param(
        [Parameter(Mandatory=$true,
        Position=0)]
        [string]
        $name)

    [System.XML.XMLElement] $xmlDiagnostic = $xmlDiagnostics.AppendChild($xmlReport.CreateElement("Diagnostic"))
    $xmlDiagnostic.SetAttribute("Name", $name)
    $xmlDiagnostic.SetAttribute("Result", -1)
    $xmlDiagnostic.SetAttribute("Duration", -1)
    XmlSave 
}

function XmlDiagnosticComplete
{
    param(
        [Parameter(Mandatory=$true,
        Position=0)]
        [string]
        $name,

        [Parameter(Mandatory=$true,
        Position=1)]
        [Int]
        $result,

        [Parameter(Mandatory=$true,
        Position=2)]
        [UInt64]
        $duration
    )

    $xmlDiagnostic = $xmlReport.SelectSingleNode("//xrayNS:Diagnostics/Diagnostic[@Name='$name']", $xmlNsMgr)

    if ($xmlDiagnostic -ne $null) {
        $xmlDiagnostic.SetAttribute("Result", $result)
        $xmlDiagnostic.SetAttribute("Duration", $duration)
        XmlSave 
    }
}

function XmlDiagnosticUpdateIssue
{
    param(
        [Parameter(Mandatory=$true,
        Position=0)]
        [string]
        $name,

        [Parameter(Mandatory=$true,
        Position=1)]
        [Int]
        $issueType
    )

    $xmlDiagnostic = $xmlReport.SelectSingleNode("//xrayNS:Diagnostic[@Name='$name']", $xmlNsMgr)

    if ($xmlDiagnostic -ne $null) {
        $xmlDiagnostic.SetAttribute("Reported", $issueType)
        XmlSave 
    }
}

function XmlMarkComplete
{
    $nodeXray.SetAttribute("Complete", $true)
    XmlSave 
}

function XmlSave
{
    $finishTime = (Get-Date).ToUniversalTime()
    $nodeXray.SetAttribute("EndTime", $finishTime.ToString($TIME_FORMAT))
    [UInt64] $timeTaken = ($finishTime - $startTime).TotalMilliseconds
    $nodeXray.SetAttribute("Duration", $timeTaken)
    $xmlReport.Save($xmlRptFile)
}

function InitPoolmonData
{
    param(
            [Parameter(Mandatory=$true,
            Position=0)]
            [bool]
            $offline
        )

    $file = Get-ChildItem -Path "$dataPath\*_poolmon.txt" -Name
    if ($file.Count -gt 1) {
        $file = $file[0]
    }

    if ($file -ne $null) {

        $Global:poolmonData = New-Object "System.Collections.Generic.List[string]"
        $pmTimestamp = $VALUE_NA

        $summary1 = "^\s+Memory:\s*(?<memory>[-0-9]+)K Avail:\s*(?<avail>[-0-9]+)K  PageFlts:\s*(?<pageflts>[-0-9]+)   InRam Krnl:\s*(?<inRamKrnl>[-0-9]+)K P:\s*(?<inRamP>[-0-9]+)K"
        $summary2 = "^\s+Commit:\s*(?<commit>[-0-9]+)K Limit:\s*(?<limit>[-0-9]+)K Peak:\s*(?<peak>[-0-9]+)K            Pool N:\s*(?<poolN>[-0-9]+)K P:\s*(?<poolP>[-0-9]+)K"
        $tagentry = "^\s+(?<tag>.{4})\s+(?<type>\w+)\s+(?<allocs>[-0-9]+)\s+(?<frees>[-0-9]+)\s+(?<diff>[-0-9]+)\s+(?<bytes>[-0-9]+)\s+(?<perAlloc>[-0-9]+)\s+$"
        $markerDT = "^\s*===== (?<datetime>(.){22}) ====="
        
        Get-Content "$dataPath\$file" |
        Select-String -Pattern $summary1, $summary2, $tagentry, $markerDT |
        Foreach-Object {

            if ($_.Matches[0].Groups['datetime'].Value -ne "") {
                $pmTimestamp =  $_.Matches[0].Groups['datetime'].Value
            }

            if ($_.Matches[0].Groups['memory'].Value -ne "") {
                #$memory, $avail, $pageflts, $inRamKrnl, $inRamP = $_.Matches[0].Groups['memory', 'avail', 'pageflts', 'inRamKrnl', 'inRamP'].Value
                $memory = $_.Matches[0].Groups['memory'].Value
                $avail = $_.Matches[0].Groups['avail'].Value
                $pageflts = $_.Matches[0].Groups['pageflts'].Value
                $inRamKrnl = $_.Matches[0].Groups['inRamKrnl'].Value
                $inRamP = $_.Matches[0].Groups['inRamP'].Value

                $poolmonData.Add("Summary1,$pmTimestamp,$memory,$avail,$pageflts,$inRamKrnl,$inRamP")
            }

            if ($_.Matches[0].Groups['commit'].Value -ne "") {
                #$commit, $limit, $peak, $poolN, $poolP = $_.Matches[0].Groups['commit', 'limit', 'peak', 'poolN', 'poolP'].Value
                $commit = $_.Matches[0].Groups['commit'].Value
                $limit = $_.Matches[0].Groups['limit'].Value
                $peak = $_.Matches[0].Groups['peak'].Value
                $poolN = $_.Matches[0].Groups['poolN'].Value
                $poolP = $_.Matches[0].Groups['poolP'].Value

                $poolmonData.Add("Summary2,$pmTimestamp,$commit,$limit,$peak,$poolN,$poolP")
                $pmTimestamp = $VALUE_NA
            }

            if ($_.Matches[0].Groups['tag'].Value -ne "") {
                #$tag, $type, $allocs, $frees, $diff, $bytes, $perAlloc = $_.Matches[0].Groups['tag', 'type', 'allocs', 'frees', 'diff', 'bytes', 'perAlloc'].Value
                $tag = $_.Matches[0].Groups['tag'].Value
                $type = $_.Matches[0].Groups['type'].Value
                $allocs = $_.Matches[0].Groups['allocs'].Value
                $frees = $_.Matches[0].Groups['frees'].Value
                $diff = $_.Matches[0].Groups['diff'].Value
                $bytes = $_.Matches[0].Groups['bytes'].Value
                $perAlloc = $_.Matches[0].Groups['perAlloc'].Value 

                $poolmonData.Add("$tag,$type,$allocs,$frees,$diff,$bytes,$perAlloc")
            }
        }
    }
    else {
        LogWrite "Poolmon data not found: $dataPath\*_poolmon.txt"
    }
}

Export-ModuleMember -Function * -Variable *
# SIG # Begin signature block
# MIInygYJKoZIhvcNAQcCoIInuzCCJ7cCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBjihgCp/6xRAyN
# 4n/PsLbVqG2Q0bwVnstVycrjKlmkaqCCDYEwggX/MIID56ADAgECAhMzAAACzI61
# lqa90clOAAAAAALMMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjIwNTEyMjA0NjAxWhcNMjMwNTExMjA0NjAxWjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQCiTbHs68bADvNud97NzcdP0zh0mRr4VpDv68KobjQFybVAuVgiINf9aG2zQtWK
# No6+2X2Ix65KGcBXuZyEi0oBUAAGnIe5O5q/Y0Ij0WwDyMWaVad2Te4r1Eic3HWH
# UfiiNjF0ETHKg3qa7DCyUqwsR9q5SaXuHlYCwM+m59Nl3jKnYnKLLfzhl13wImV9
# DF8N76ANkRyK6BYoc9I6hHF2MCTQYWbQ4fXgzKhgzj4zeabWgfu+ZJCiFLkogvc0
# RVb0x3DtyxMbl/3e45Eu+sn/x6EVwbJZVvtQYcmdGF1yAYht+JnNmWwAxL8MgHMz
# xEcoY1Q1JtstiY3+u3ulGMvhAgMBAAGjggF+MIIBejAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUiLhHjTKWzIqVIp+sM2rOHH11rfQw
# UAYDVR0RBEkwR6RFMEMxKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMRYwFAYDVQQFEw0yMzAwMTIrNDcwNTI5MB8GA1UdIwQYMBaAFEhu
# ZOVQBdOCqhc3NyK1bajKdQKVMFQGA1UdHwRNMEswSaBHoEWGQ2h0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY0NvZFNpZ1BDQTIwMTFfMjAxMS0w
# Ny0wOC5jcmwwYQYIKwYBBQUHAQEEVTBTMFEGCCsGAQUFBzAChkVodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY0NvZFNpZ1BDQTIwMTFfMjAx
# MS0wNy0wOC5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAeA8D
# sOAHS53MTIHYu8bbXrO6yQtRD6JfyMWeXaLu3Nc8PDnFc1efYq/F3MGx/aiwNbcs
# J2MU7BKNWTP5JQVBA2GNIeR3mScXqnOsv1XqXPvZeISDVWLaBQzceItdIwgo6B13
# vxlkkSYMvB0Dr3Yw7/W9U4Wk5K/RDOnIGvmKqKi3AwyxlV1mpefy729FKaWT7edB
# d3I4+hldMY8sdfDPjWRtJzjMjXZs41OUOwtHccPazjjC7KndzvZHx/0VWL8n0NT/
# 404vftnXKifMZkS4p2sB3oK+6kCcsyWsgS/3eYGw1Fe4MOnin1RhgrW1rHPODJTG
# AUOmW4wc3Q6KKr2zve7sMDZe9tfylonPwhk971rX8qGw6LkrGFv31IJeJSe/aUbG
# dUDPkbrABbVvPElgoj5eP3REqx5jdfkQw7tOdWkhn0jDUh2uQen9Atj3RkJyHuR0
# GUsJVMWFJdkIO/gFwzoOGlHNsmxvpANV86/1qgb1oZXdrURpzJp53MsDaBY/pxOc
# J0Cvg6uWs3kQWgKk5aBzvsX95BzdItHTpVMtVPW4q41XEvbFmUP1n6oL5rdNdrTM
# j/HXMRk1KCksax1Vxo3qv+13cCsZAaQNaIAvt5LvkshZkDZIP//0Hnq7NnWeYR3z
# 4oFiw9N2n3bb9baQWuWPswG0Dq9YT9kb+Cs4qIIwggd6MIIFYqADAgECAgphDpDS
# AAAAAAADMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0
# ZSBBdXRob3JpdHkgMjAxMTAeFw0xMTA3MDgyMDU5MDlaFw0yNjA3MDgyMTA5MDla
# MH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMT
# H01pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTEwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQCr8PpyEBwurdhuqoIQTTS68rZYIZ9CGypr6VpQqrgG
# OBoESbp/wwwe3TdrxhLYC/A4wpkGsMg51QEUMULTiQ15ZId+lGAkbK+eSZzpaF7S
# 35tTsgosw6/ZqSuuegmv15ZZymAaBelmdugyUiYSL+erCFDPs0S3XdjELgN1q2jz
# y23zOlyhFvRGuuA4ZKxuZDV4pqBjDy3TQJP4494HDdVceaVJKecNvqATd76UPe/7
# 4ytaEB9NViiienLgEjq3SV7Y7e1DkYPZe7J7hhvZPrGMXeiJT4Qa8qEvWeSQOy2u
# M1jFtz7+MtOzAz2xsq+SOH7SnYAs9U5WkSE1JcM5bmR/U7qcD60ZI4TL9LoDho33
# X/DQUr+MlIe8wCF0JV8YKLbMJyg4JZg5SjbPfLGSrhwjp6lm7GEfauEoSZ1fiOIl
# XdMhSz5SxLVXPyQD8NF6Wy/VI+NwXQ9RRnez+ADhvKwCgl/bwBWzvRvUVUvnOaEP
# 6SNJvBi4RHxF5MHDcnrgcuck379GmcXvwhxX24ON7E1JMKerjt/sW5+v/N2wZuLB
# l4F77dbtS+dJKacTKKanfWeA5opieF+yL4TXV5xcv3coKPHtbcMojyyPQDdPweGF
# RInECUzF1KVDL3SV9274eCBYLBNdYJWaPk8zhNqwiBfenk70lrC8RqBsmNLg1oiM
# CwIDAQABo4IB7TCCAekwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFEhuZOVQ
# BdOCqhc3NyK1bajKdQKVMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1Ud
# DwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFHItOgIxkEO5FAVO
# 4eqnxzHRI4k0MFoGA1UdHwRTMFEwT6BNoEuGSWh0dHA6Ly9jcmwubWljcm9zb2Z0
# LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcmwwXgYIKwYBBQUHAQEEUjBQME4GCCsGAQUFBzAChkJodHRwOi8vd3d3Lm1p
# Y3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcnQwgZ8GA1UdIASBlzCBlDCBkQYJKwYBBAGCNy4DMIGDMD8GCCsGAQUFBwIB
# FjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2RvY3MvcHJpbWFyeWNw
# cy5odG0wQAYIKwYBBQUHAgIwNB4yIB0ATABlAGcAYQBsAF8AcABvAGwAaQBjAHkA
# XwBzAHQAYQB0AGUAbQBlAG4AdAAuIB0wDQYJKoZIhvcNAQELBQADggIBAGfyhqWY
# 4FR5Gi7T2HRnIpsLlhHhY5KZQpZ90nkMkMFlXy4sPvjDctFtg/6+P+gKyju/R6mj
# 82nbY78iNaWXXWWEkH2LRlBV2AySfNIaSxzzPEKLUtCw/WvjPgcuKZvmPRul1LUd
# d5Q54ulkyUQ9eHoj8xN9ppB0g430yyYCRirCihC7pKkFDJvtaPpoLpWgKj8qa1hJ
# Yx8JaW5amJbkg/TAj/NGK978O9C9Ne9uJa7lryft0N3zDq+ZKJeYTQ49C/IIidYf
# wzIY4vDFLc5bnrRJOQrGCsLGra7lstnbFYhRRVg4MnEnGn+x9Cf43iw6IGmYslmJ
# aG5vp7d0w0AFBqYBKig+gj8TTWYLwLNN9eGPfxxvFX1Fp3blQCplo8NdUmKGwx1j
# NpeG39rz+PIWoZon4c2ll9DuXWNB41sHnIc+BncG0QaxdR8UvmFhtfDcxhsEvt9B
# xw4o7t5lL+yX9qFcltgA1qFGvVnzl6UJS0gQmYAf0AApxbGbpT9Fdx41xtKiop96
# eiL6SJUfq/tHI4D1nvi/a7dLl+LrdXga7Oo3mXkYS//WsyNodeav+vyL6wuA6mk7
# r/ww7QRMjt/fdW1jkT3RnVZOT7+AVyKheBEyIXrvQQqxP/uozKRdwaGIm1dxVk5I
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIZnzCCGZsCAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAsyOtZamvdHJTgAAAAACzDAN
# BglghkgBZQMEAgEFAKCBrjAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgc7PobtxC
# E0azcHphQRGgfGaUUdArxhpdc3vYnmDaVIAwQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQBpEi7bwhz9kG92cicfZqR2kgofku7PZ/yGb51eLnRz
# sDIoiCmp+ar/kys/e7XuPe9x9W1uei4/VNYMy75TXYEIqaRZvEae1CujIDQupBwu
# TLbFyJxK3COXXsElGzVoGTNoLOt5eMI+0YlaRZbdcIZc2ayiNYFFNuK001fzO5QK
# nVvRTuxuSWFwhwvy1MoE836qNX7jLDPMNlCR8XNPw5baqekjHtz3ylDOSSH2fzCp
# ry8GlTJCm+fVI6CzKvANk1XAozEum6O3LK3LaWAi2wwf6sYRon5MNmHoXymsLTRG
# ZZMsBJCgcCV7noKPDaTUxf+yoyCt8VFQ1TYlkUaDomU5oYIXKTCCFyUGCisGAQQB
# gjcDAwExghcVMIIXEQYJKoZIhvcNAQcCoIIXAjCCFv4CAQMxDzANBglghkgBZQME
# AgEFADCCAVkGCyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEIK0CzE7hpattyaaLiun2OupQUoSdx0eZlMDalxtu
# 4EdVAgZjUBtk/WQYEzIwMjIxMDI2MTQyOTUxLjA4M1owBIACAfSggdikgdUwgdIx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1p
# Y3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhh
# bGVzIFRTUyBFU046ODZERi00QkJDLTkzMzUxJTAjBgNVBAMTHE1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFNlcnZpY2WgghF4MIIHJzCCBQ+gAwIBAgITMwAAAbchJxoHoiqG
# RgABAAABtzANBgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0Eg
# MjAxMDAeFw0yMjA5MjAyMDIyMTRaFw0yMzEyMTQyMDIyMTRaMIHSMQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQg
# SXJlbGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1Mg
# RVNOOjg2REYtNEJCQy05MzM1MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFt
# cCBTZXJ2aWNlMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAx/3PV1A0
# E2RMGrcclyXKmNBwkiUMCCm+zDi8cl7TqfnfZEoaRyfRXunrk54DXA6g77w2yime
# M+lVnz7iz9GF0wIw09AlehZ2RY6n/em4gSzV/M8GBMmt2bN3JRjOsCWggJjHvbaC
# Z2ls1/c/TLlnaBE7jyxYhjJh40lhyH5l8nNeqq+6+rsbw2bwgxCLxlrK/H7l1IYE
# zlVgcHEISNcX0Q3pDDsDrRJpeMqOiNKlSalozgWZV5z3zk811KHyE54/a0vvzVIF
# qf3YNPX2180e/0fQUCYTYcZHCLMeQn/+YBl1LSzpuL9TA8ySwCJrlumcgME6hph1
# aRXSVUbms3T6W1HP3OOVof26F0ZMn5aI0o6vuZGeXNhADnd+1JIkGqwSlPMK/tzr
# vd92+W3HfLjw96vq9zpRHl7iRJmwfXjUiHGGZFHZKYRpu5go5N07tD++W8B9DG4S
# cn3c0vgthXUhbDw77E07qCWOsGkI5845NCBYkX4zr8g/K5ity/v0u7uVzrtL5T0w
# S7Z2iDQy4kihgIyK5VpdLn4WY4mLJ+IJmbRUmwnnvTL2T+0RB7ppBH0zENbWnYXc
# dZ5uiVeP2y7vOusSU2UcAS+kWFyCgyeLKU1OJNnMvBSPtMfzeCe6DDUUIRVWHlT2
# XA0w8vUga7P/dT5FP3BkIElgisUk93qTxS0CAwEAAaOCAUkwggFFMB0GA1UdDgQW
# BBSz8jk+DDQkBWEN1gHbI8gjyXi07DAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJl
# pxtTNRnpcjBfBgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAx
# MCgxKS5jcmwwbAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3Rh
# bXAlMjBQQ0ElMjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQM
# MAoGCCsGAQUFBwMIMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQsFAAOCAgEA
# DZ1kzJuFXFJdNsnMWC82IwJXn8DKflS7MlTj3lgO1x5+iV3R6FH1AEYGEeYAy3XR
# ZgIfPZZBTIzeZAPgiwd8QvUkTCAb20arvW5yf12ScsEcPfQm9tBGEgpy8VKe9EIK
# lWmKUzwX9hpZcL1WJtJ5/89TYZYD7XOzrhUXEmod67LwqqtDJ8XbRIKd3zNFmXhh
# gFyOH0bQaOEkdQ8BgTHSvyNJaPKLajZYAcPoKmkG2TCdlJ/sDrwMvg7DAGmYUHf6
# +5uOA3BogJL5+QZW9Gc/ZmCaV+doBqzwzHuKAmpyKqrRDoCf7SsePWTGKw10iJPM
# WW7kbDZ6FekuuXn2S+yY41UAkeGd2nHef/SvvpMf7dY1L1RP2NvFCQT63a2GJ/ow
# rmSsUyeQEgIJH8NVxXWrD2yDqwwSjTBZJeVBhe9xBYDrl5XNKSizKWEiUhlksvcY
# dkPUtC0COnYDkXsLcjDg23sLtoMJ+kXGibdm6VGcUmiWU8dve6eP2ED3G9GIqdYw
# AylLgxkCiJXg7b3NYpl1TPKCnuAPhaMorXXkoInSi8Rx/3YCfAwBcyc2zWjQsKzO
# D64OaJBmzl5HuPN0rNV8XXPtt8Ng08Am+bmlJB1vLfAg6w3+y1iMz4SRo+1TOvw7
# IzCsb6OkUxuwHhx83q28h4a2u2SUwkW2cXrwJxlnkgAwggdxMIIFWaADAgECAhMz
# AAAAFcXna54Cm0mZAAAAAAAVMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9v
# dCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0yMTA5MzAxODIyMjVaFw0z
# MDA5MzAxODMyMjVaMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
# MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
# b24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMIICIjAN
# BgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA5OGmTOe0ciELeaLL1yR5vQ7VgtP9
# 7pwHB9KpbE51yMo1V/YBf2xK4OK9uT4XYDP/XE/HZveVU3Fa4n5KWv64NmeFRiMM
# tY0Tz3cywBAY6GB9alKDRLemjkZrBxTzxXb1hlDcwUTIcVxRMTegCjhuje3XD9gm
# U3w5YQJ6xKr9cmmvHaus9ja+NSZk2pg7uhp7M62AW36MEBydUv626GIl3GoPz130
# /o5Tz9bshVZN7928jaTjkY+yOSxRnOlwaQ3KNi1wjjHINSi947SHJMPgyY9+tVSP
# 3PoFVZhtaDuaRr3tpK56KTesy+uDRedGbsoy1cCGMFxPLOJiss254o2I5JasAUq7
# vnGpF1tnYN74kpEeHT39IM9zfUGaRnXNxF803RKJ1v2lIH1+/NmeRd+2ci/bfV+A
# utuqfjbsNkz2K26oElHovwUDo9Fzpk03dJQcNIIP8BDyt0cY7afomXw/TNuvXsLz
# 1dhzPUNOwTM5TI4CvEJoLhDqhFFG4tG9ahhaYQFzymeiXtcodgLiMxhy16cg8ML6
# EgrXY28MyTZki1ugpoMhXV8wdJGUlNi5UPkLiWHzNgY1GIRH29wb0f2y1BzFa/Zc
# UlFdEtsluq9QBXpsxREdcu+N+VLEhReTwDwV2xo3xwgVGD94q0W29R6HXtqPnhZy
# acaue7e3PmriLq0CAwEAAaOCAd0wggHZMBIGCSsGAQQBgjcVAQQFAgMBAAEwIwYJ
# KwYBBAGCNxUCBBYEFCqnUv5kxJq+gpE8RjUpzxD/LwTuMB0GA1UdDgQWBBSfpxVd
# AF5iXYP05dJlpxtTNRnpcjBcBgNVHSAEVTBTMFEGDCsGAQQBgjdMg30BATBBMD8G
# CCsGAQUFBwIBFjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL0RvY3Mv
# UmVwb3NpdG9yeS5odG0wEwYDVR0lBAwwCgYIKwYBBQUHAwgwGQYJKwYBBAGCNxQC
# BAweCgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYD
# VR0jBBgwFoAU1fZWy4/oolxiaNE9lJBb186aGMQwVgYDVR0fBE8wTTBLoEmgR4ZF
# aHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljUm9v
# Q2VyQXV0XzIwMTAtMDYtMjMuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggrBgEFBQcw
# AoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNSb29DZXJB
# dXRfMjAxMC0wNi0yMy5jcnQwDQYJKoZIhvcNAQELBQADggIBAJ1VffwqreEsH2cB
# MSRb4Z5yS/ypb+pcFLY+TkdkeLEGk5c9MTO1OdfCcTY/2mRsfNB1OW27DzHkwo/7
# bNGhlBgi7ulmZzpTTd2YurYeeNg2LpypglYAA7AFvonoaeC6Ce5732pvvinLbtg/
# SHUB2RjebYIM9W0jVOR4U3UkV7ndn/OOPcbzaN9l9qRWqveVtihVJ9AkvUCgvxm2
# EhIRXT0n4ECWOKz3+SmJw7wXsFSFQrP8DJ6LGYnn8AtqgcKBGUIZUnWKNsIdw2Fz
# Lixre24/LAl4FOmRsqlb30mjdAy87JGA0j3mSj5mO0+7hvoyGtmW9I/2kQH2zsZ0
# /fZMcm8Qq3UwxTSwethQ/gpY3UA8x1RtnWN0SCyxTkctwRQEcb9k+SS+c23Kjgm9
# swFXSVRk2XPXfx5bRAGOWhmRaw2fpCjcZxkoJLo4S5pu+yFUa2pFEUep8beuyOiJ
# Xk+d0tBMdrVXVAmxaQFEfnyhYWxz/gq77EFmPWn9y8FBSX5+k77L+DvktxW/tM4+
# pTFRhLy/AsGConsXHRWJjXD+57XQKBqJC4822rpM+Zv/Cuk0+CQ1ZyvgDbjmjJnW
# 4SLq8CdCPSWU5nR0W2rRnj7tfqAxM328y+l7vzhwRNGQ8cirOoo6CGJ/2XBjU02N
# 7oJtpQUQwXEGahC0HVUzWLOhcGbyoYIC1DCCAj0CAQEwggEAoYHYpIHVMIHSMQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNy
# b3NvZnQgSXJlbGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxl
# cyBUU1MgRVNOOjg2REYtNEJCQy05MzM1MSUwIwYDVQQDExxNaWNyb3NvZnQgVGlt
# ZS1TdGFtcCBTZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQDIZ0EYw5s4OWwYFmZJRfah
# aB+pxqCBgzCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
# MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
# b24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqG
# SIb3DQEBBQUAAgUA5wMrTDAiGA8yMDIyMTAyNjExNDMwOFoYDzIwMjIxMDI3MTE0
# MzA4WjB0MDoGCisGAQQBhFkKBAExLDAqMAoCBQDnAytMAgEAMAcCAQACAgcfMAcC
# AQACAhHwMAoCBQDnBHzMAgEAMDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkK
# AwKgCjAIAgEAAgMHoSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQEFBQADgYEAzX36
# YMWN/QiT1qsiW76s1fGz3vfG/NZnOtalm+ZmQQepRZeo49KrlHDEIim6EGoNuiAo
# Swsx0NFx9Lh9t5O85fqQuk6+9LWukz+LCepFS9HVJdq675EUaiWy0Ijq/As7bO7F
# leIZ5AuOXRRkudSg9RHQLMI3X7VqYShfXm393tsxggQNMIIECQIBATCBkzB8MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNy
# b3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAbchJxoHoiqGRgABAAABtzAN
# BglghkgBZQMEAgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8G
# CSqGSIb3DQEJBDEiBCCh62r/UcduXV95A7i7r9w+2i+jI/x+DYypQFENZvfZ5jCB
# +gYLKoZIhvcNAQkQAi8xgeowgecwgeQwgb0EIGwneNOyHtovyE16JgYvn/wgGfzN
# R+vv9DuuQzyJzXBBMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIw
# MTACEzMAAAG3IScaB6IqhkYAAQAAAbcwIgQgGeMGQ/+po2xC2zA3wttEvPzv6E6o
# 088k1PA3zlISlhowDQYJKoZIhvcNAQELBQAEggIAEUvvDkkO1WC7cJ+7RYl4LqOU
# UZWc53vktfVTbIAq5GDqcdSoS+MwkUUdI0terVWrBzLu65axzZitLOkiOZ5ruD5i
# QZmOfFS3ZwO7G6+iUlY2e9d53UmeV2xc/pQoYewsv035srXqyPq+orPppyoWdVCE
# puYkSaV9QEcbG8W1lIvcb+xk/DbFilUFSV+jxQl4luhgHFfdMTkW2p4r/FDH5tpz
# akxqPc2/wf3ooQvTMbjOdHNJCWYbRXpjEsk7N4zcV7ka51OWQMiRDYQzstSIJRBi
# Fm71FuMfYxrCzd0l41VEXDNuSr0rrdGtw4bjMzhpC4LoqG/JAuwEcJsoVuOLxsJA
# NH3MX7CKIe3pMursdeAOTYCevVZdsCPoRy5uhR5L0MnP+gZgCLu4D3FtQUgpXheF
# cEfQsm7fwAKl5zhi32nd4EfvkVTOHY6aZxuZ3Zx25wPATLAX5TPc7QGG/9T6m9Te
# jG64/Ua9Un+TX3vmILTvmJIRLET6ppgP1ySuzoKI0fuZga6zg4b4UU2LTKNmxMZp
# XLpfDHUga6/pacvPJf3OKcb5NmbR8m43ZHEzDuqh58u67oF7NVKfVYOQdQ39/DCl
# jL5fwgjzzZvRi6QUmCGmZeNfknTuKo5pS6VlRga64W8RlCC4KkcAWJtyoMiLMFHh
# f69BSP+gHhq2qpTbu9I=
# SIG # End signature block
