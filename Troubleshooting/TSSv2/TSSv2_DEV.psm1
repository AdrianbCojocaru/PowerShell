<#
.SYNOPSIS
   DEV Components and Scenarios module for learning and demoing TSSv2 Framework usage.
   This is NOT related to any specific POD and not designed for learning and troubleshooting.

.DESCRIPTION
   DEV Components and Scenarios module for learning and demoing TSSv2 Framework usage.
   This is NOT related to any specific POD and not designed for learning and troubleshooting.

.NOTES  
   Authors     : Milan Milosavljevic (milanmil@microsoft.com)
   Requires   : PowerShell V4(Supported from Windows 8.1/Windows Server 2012 R2)
   Version    : see $global:TssVerDateDEV

.LINK
	TSSv2 https://internal.support.services.microsoft.com/en-us/help/4619187
#>

<# latest changes
  2022.01.05.0 [we] added FW function calls which were previously defined in _NET
  2021.11.10.0 [we] #_# replaced all 'Get-WmiObject' with 'Get-CimInstance' to be compatible with PowerShell v7
#>

$global:TssVerDateDEV= "2022.01.05.0"

#region Components
# Normal trace -> data will be collected in a single file
$DEV_TEST1Providers = @(
    '{CC85922F-DB41-11D2-9244-006008269001}' # LSA
    '{6B510852-3583-4E2D-AFFE-A67F9F223438}' # Kerberos
)

# Normal trace with multi etl files
# Syntax is: GUID!filename!flags!level 
# GUID is mandtory
# if filename is not provided TSSv2 will create etl using Providers name, i.e. dev_test2 
# if flags is not provided, TSSv2 defaults to 0xffffffff
# if level is not provided, TSSv2 defaults to 0xff
$DEV_TEST2Providers = @(
    '{98BF1CD3-583E-4926-95EE-A61BF3F46470}!CertCli!0xffffff!0x05'
    '{6A71D062-9AFE-4F35-AD08-52134F85DFB9}!CertificationAuthority!0xff!0x07'
    '{B40AEF77-892A-46F9-9109-438E399BB894}!CertCli!0xfffffe!0x04'
    '{169EC169-5B77-4A3E-9DB6-441799D5CACB}!lsa!0xfffffffe'
    '{5BBB6C18-AA45-49B1-A15F-085F7ED0AA90}!CertificationAuthority!0xC43EFF!0x06'
    '{D0B639E0-E650-4D1D-8F39-1580ADE72784}!lsa!0xffffffff!0x0f'
)

# Single etl + multi flags
$DEV_TEST3Providers = @(
    '{D0B639E0-E650-4D1D-8F39-1580ADE72784}!lsa!0xC43EFF'
    '{169EC169-5B77-4A3E-9DB6-441799D5CACB}!lsa!0xffffff'
)

$DEV_TEST4Providers = @(
    '{D0B639E0-E650-4D1D-8F39-1580ADE72784}!lsa!0xC43EFF'
    '{169EC169-5B77-4A3E-9DB6-441799D5CACB}!lsa!0xffffff'
    '{5BBB6C18-AA45-49B1-A15F-085F7ED0AA90}!CertificationAuthority!0xC43EFF!0x06'
    '{D0B639E0-E650-4D1D-8F39-1580ADE72784}!lsa!0xffffffff!0x0f'
)

#select basic or full tracing option for the same etl guids using different flags
Switch ($global:CustomParams[0])
{
    "full" {
        $DEV_TEST5Providers = @(
        '{D0B639E0-E650-4D1D-8F39-1580ADE72784}!lsa!0xffffffff'
        '{169EC169-5B77-4A3E-9DB6-441799D5CACB}!lsa!0xffffffff'
        )

    }
    "basic" {
        $DEV_TEST5Providers = @(
            '{D0B639E0-E650-4D1D-8F39-1580ADE72784}!lsa!0xC43EFF'
            '{169EC169-5B77-4A3E-9DB6-441799D5CACB}!lsa!0xffffff'
        )    
    }

    Default {
        $DEV_TEST5Providers = @(
            '{D0B639E0-E650-4D1D-8F39-1580ADE72784}!lsa!0xC43EFF'
            '{169EC169-5B77-4A3E-9DB6-441799D5CACB}!lsa!0xfffff!0x12'
        )
    }
}
#endregion Components

#region Scenarios
$DEV_ScenarioTraceList = [Ordered]@{
    'DEV_Scn1' = 'DEV scenario trace 1'
    'DEV_Scn2' = 'DEV scenario trace 2'
}

# DEV_Scn1
$DEV_Scn1_ETWTracingSwitchesStatus = [Ordered]@{
    'DEV_TEST1' = $true
    #'DEV_TEST2' = $true   # Multi etl file trace
    #'DEV_TEST3' = $true   # Single trace
    #'DEV_TEST4' = $true 
    #'DEV_TEST5' = $true
    #'Netsh' = $true
    #'Netsh capturetype=both captureMultilayer=yes provider=Microsoft-Windows-PrimaryNetworkIcon provider={1701C7DC-045C-45C0-8CD6-4D42E3BBF387}' = $true
    #'NetshMaxSize 4096' = $true
    #'Procmon' = $true
    #'ProcmonFilter ProcmonConfiguration.pmc' = $True
    #'ProcmonPath C:\tools' = $True
    #'WPR memory' = $true
    #'WPR memory -onoffproblemdescription "test description"' = $true
    #'skippdbgen' = $true
    #'PerfMon smb' = $true
    #'PerfIntervalSec 20' = $true
    #'PerfMonlong general' = $true
    #'PerfLongIntervalMin 40' = $true
    #'NetshScenario InternetClient_dbg' = $true
    #'NetshScenario InternetClient_dbg,dns_wpp' = $true
    #'NetshScenario InternetClient_dbg,dns_wpp capturetype=both captureMultilayer=yes provider=Microsoft-Windows-PrimaryNetworkIcon provider={1701C7DC-045C-45C0-8CD6-4D42E3BBF387}' = $true
    #'PSR' = $true
    #'WFPdiag' = $true
    #'RASdiag' = $true
    #'PktMon' = $true
    #'AddDescription' = $true
    #'SDP rds' = $True
    #'SDP setup,perf' = $True
    #'SkipSDPList noNetadapters,skipBPA' = $True
    #'xray' = $True
    #'Video' = $True
    #'SysMon' = $True
    #'CommonTask Mini' = $True
    #'CommonTask Full' = $True
    #'CommonTask Dev' = $True
    #'noBasicLog' = $True
    #'noPSR' = $True
    #'noVideo' = $True
    #'Mini' = $True
    #'NoSettingList noSDP,noXray,noBasiclog,noVideo,noPSR' = $True
    #'Xperf Pool' = $True
    #'XPerfMaxFile 4096' = $True
    #'XperfTag TcpE+AleE+AfdE+AfdX' = $True
    #'XperfPIDs 100' = $True
    #'LiveKD Both' = $True
    #'WireShark' = $True
    #'TTD notepad.exe' = $True   # Single process [<processname.exe>|<PID>]
    #'TTD notepad.exe,cmd.exe' = $True   # Multiple processes
    #'TTD tokenbroker' = $True   # Service name
    #'TTD Microsoft.Windows.Photos' = $True  # AppX
    #"TTDPath $env:userprofile\Desktop\PartnerTTDRecorder_x86_x64\amd64\TTD" = $True	# for downlevel OS TTD will find Partner tttracer in \Bin** folder
    #'TTDMode Ring' = $True   # choose [Full|Ring|onLaunch]
    #'TTDMaxFile 2048' = $True
    #'TTDOptions XXX' = $True
    #'CollectComponentLog' = $True
    #'Discard' = $True
    #'ProcDump notepad.exe,mspaint.exe,tokenbroker' = $true
    #'ProcDumpOption Both' = $true
    #'ProcDumpInterval 3:10' = $True
    #'GPResult Both' = $True
    #'PoolMon Both' = $True
    #'Handle Both' = $True
}

# DEV_Scn2
Switch (global:FwGetProductTypeFromReg)
{
    "WinNT" {
        $DEV_Scn2_ETWTracingSwitchesStatus = [Ordered]@{
            'DEV_TEST1' = $true
            'DEV_TEST2' = $true  # Multi etl file trace
            'DEV_TEST3' = $true
            'DEV_TEST4' = $true   # Single trace
            'DEV_TEST5' = $False  # Disabled trace
            'UEX_Task' = $True     # Outside of this module
        }
    }
    "ServerNT" {
        $DEV_Scn2_ETWTracingSwitchesStatus = [Ordered]@{
            'DEV_TEST1' = $true
            'DEV_TEST2' = $true
        }
    }
    "LanmanNT" {
        $DEV_Scn2_ETWTracingSwitchesStatus = [Ordered]@{
            'DEV_TEST1' = $true
            'DEV_TEST2' = $true
        }
    }
    Default {
        $DEV_Scn2_ETWTracingSwitchesStatus = [Ordered]@{
            'DEV_TEST1' = $true
            'DEV_TEST2' = $true
        }
    }
}

# Dev_Scn3 => Multi etl only
$DEV_Scn3_ETWTracingSwitchesStatus = [Ordered]@{
    'DEV_TEST2' = $true   # Multi etl file trace
}

#endregion Scenarios


#region Functions

#region Components Functions

### Pre-Start / Post-Stop / Collect / Diag function for Components tracing

##### Pre-Start / Post-Stop function for trace
function DEV_TEST1PreStart
{
    EnterFunc $MyInvocation.MyCommand.Name
    LogMessage $Loglevel.Info "$($MyInvocation.MyCommand.Name) is called."
    # Testing FwSetEventLog
    #FwSetEventLog "Microsoft-Windows-CAPI2/Operational" -EvtxLogSize:100000 -ClearLog
    #FwSetEventLog 'Microsoft-Windows-CAPI2/Catalog Database Debug' -EvtxLogSize:102400000
    #$PowerShellEvtLogs = @("Microsoft-Windows-PowerShell/Admin", "Microsoft-Windows-PowerShell/Operational")
    #FwSetEventLog $PowerShellEvtLogs
    EndFunc $MyInvocation.MyCommand.Name
}
function DEV_TEST1PostStart
{
    EnterFunc $MyInvocation.MyCommand.Name
    LogMessage $Loglevel.Info "$($MyInvocation.MyCommand.Name) is called."
    EndFunc $MyInvocation.MyCommand.Name
}
function DEV_TEST1PreStop
{
    EnterFunc $MyInvocation.MyCommand.Name
    LogMessage $Loglevel.Info "$($MyInvocation.MyCommand.Name) is called."
	#LogWarn "** Will do Forced Crash now" cyan
	#FwDoCrash
    EndFunc $MyInvocation.MyCommand.Name
}

function DEV_TEST1PostStop
{
    EnterFunc $MyInvocation.MyCommand.Name
    LogMessage $Loglevel.Info "$($MyInvocation.MyCommand.Name) is called."
    # Testing FwResetEventLog
    #FwResetEventLog 'Microsoft-Windows-CAPI2/Operational'
    #FWResetEventLog 'Microsoft-Windows-CAPI2/Catalog Database Debug'
    #$PowerShellEvtLogs = @("Microsoft-Windows-PowerShell/Admin", "Microsoft-Windows-PowerShell/Operational")
    #FwResetEventLog $PowerShellEvtLogs
    EndFunc $MyInvocation.MyCommand.Name
}


function DEV_TEST2PreStart
{
    EnterFunc $MyInvocation.MyCommand.Name
    LogMessage $Loglevel.Info "$($MyInvocation.MyCommand.Name) is called."
    EndFunc $MyInvocation.MyCommand.Name
}

function DEV_TEST2PostStop
{
    EnterFunc $MyInvocation.MyCommand.Name
    LogMessage $Loglevel.Info "$($MyInvocation.MyCommand.Name) is called."
    EndFunc $MyInvocation.MyCommand.Name
}

##### Data Collection
function CollectDEV_TEST1Log
{
    EnterFunc $MyInvocation.MyCommand.Name

    $LogPrefix = "Dev_TEST1"
    $LogFolderforDEV_TEST1 = "$Logfolder\Dev_TEST1"
    FwCreateLogFolder $LogFolderforDEV_TEST1

    <#
    <#--- Log functions ---#>
    #LogDebug "This is message from LogDebug."
    #LogInfo "This is message from LogInfo."
    #LogWarn "This is message from LogWarn."
    #LogError "This is message from LogError."
    #Try{
    #    Throw "Test exception"
    #}Catch{
    #    LogException "This is message from LogException" $_
    #}
    #LogInfoFile "This is message from LogInfoFile."
    #LogWarnFile "This is message from LogWarnFile."
    #LogErrorFile "This is message from LogErrorFile."

    <#--- Test ExportEventLog and FwExportEventLogWithTXTFormat ---#>
    #FwExportEventLog 'System' $LogFolderforDEV_TEST1
    #ExportEventLog "Microsoft-Windows-DNS-Client/Operational" $LogFolderforDEV_TEST1
    #FwExportEventLogWithTXTFormat 'System' $LogFolderforDEV_TEST1

    <#--- FwSetEventLog and FwResetEventLog ---#>
    #$EventLogs = @(
    #    'Microsoft-Windows-WMI-Activity/Trace'
    #    'Microsoft-Windows-WMI-Activity/Debug'
    #)
    #FwSetEventLog $EventLogs
    #Start-Sleep 20
    #FwResetEventLog $EventLogs

	<#--- FwAddEvtLog and FwGetEvtLogList ---#>  
	#($EvtLogsBluetooth) | ForEach-Object { FwAddEvtLog $_ _Stop_}	# see #region groups of Eventlogs for FwAddEvtLog
	#_# Note: FwGetEvtLogList should be called in _Start_Common_Tasks and _Start_Common_Tasks POD functions, otherwise it is called in FW FwCollect_BasicLog/FwCollect_MiniBasicLog functions
		
	<#--- FwAddRegItem and FwGetRegList ---#>
	#FwAddRegItem @("SNMP", "Tcp") _Stop_	# see #region Registry Key modules for FwAddRegItem
	#_# Note: FwGetRegList should be called in _Start_Common_Tasks and _Start_Common_Tasks POD functions, otherwise it is called in FW FwCollect_BasicLog/FwCollect_MiniBasicLog functions

    <#--- Test RunCommands --#>
    #$outFile = "$LogFolderforDEV_TEST1\netinfo.txt"
    #$Commands = @(
    #    "IPCONFIG /ALL | Out-File -Append $outFile"
    #    "netsh interface IP show config | Out-File -Append $outFile"
    #)
    #RunCommands "$LogPrefix" $Commands -ThrowException:$False -ShowMessage:$True

    <#--- FwCopyFiles ---#>
    # Case 1: Copy a single set of files
	#$SourceDestinationPaths = New-Object 'System.Collections.Generic.List[Object]'
	#$SourceDestinationPaths.add(@("C:\Temp\*", "$LogFolderforDEV_TEST1"))
	#FwCopyFiles $SourceDestinationPaths

	# Case 2: Copy a single file
	#$SourceDestinationPaths = New-Object 'System.Collections.Generic.List[Object]'
	#$SourceDestinationPaths.add(@("C:\temp\test-case2.txt", "$LogFolderforDEV_TEST1"))
	#FwCopyFiles $SourceDestinationPaths

	# Case 3: Copy multi sets of files
	#$SourceDestinationPaths = New-Object 'System.Collections.Generic.List[Object]'
	#$SourceDestinationPaths = @(
	#    @("C:\temp\*", "$LogFolderforDEV_TEST1"),
	#    @("C:\temp2\test-case3.txt", "$LogFolderforDEV_TEST1")
	#)
	#FwCopyFiles $SourceDestinationPaths

    <#--- FwExportRegistry and FwExportRegToOneFile ---#>
    #LogInfo '[$LogPrefix] testing FwExportRegistry().'
    #$RecoveryKeys = @(
    #    ('HKLM:System\CurrentControlSet\Control\CrashControl', "$LogFolderforDEV_TEST1\Basic_Registry_CrashControl.txt"),
    #    ('HKLM:System\CurrentControlSet\Control\Session Manager\Memory Management', "$LogFolderforDEV_TEST1\Basic_Registry_MemoryManagement.txt"),
    #    ('HKLM:Software\Microsoft\Windows NT\CurrentVersion\AeDebug', "$LogFolderforDEV_TEST1\Basic_Registry_AeDebug.txt"),
    #    ('HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Option', "$LogFolderforDEV_TEST1\Basic_Registry_ImageFileExecutionOption.txt"),
    #    ('HKLM:System\CurrentControlSet\Control\Session Manager\Power', "$LogFolderforDEV_TEST1\Basic_Registry_Power.txt")
    #)
    #FwExportRegistry $LogPrefix $RecoveryKeys
    #
    #$StartupKeys = @(
    #    "HKCU:Software\Microsoft\Windows\CurrentVersion\Run",
    #    "HKCU:Software\Microsoft\Windows\CurrentVersion\Runonce",
    #    "HKCU:Software\Microsoft\Windows\CurrentVersion\RunonceEx"
    #)
    #FwExportRegToOneFile $LogPrefix $StartupKeys "$LogFolderforDEV_TEST1\Basic_Registry_RunOnce_reg.txt"

    <#---FwCaptureUserDump ---#>
    # Service
    #FwCaptureUserDump -Name "Winmgmt" -DumpFolder $LogFolderforDEV_TEST1 -IsService:$True
    # Process
    #FwCaptureUserDump -Name "notepad" -DumpFolder $LogFolderforDEV_TEST1
    # PID
    #FwCaptureUserDump -ProcPID 4524 -DumpFolder $LogFolderforDEV_TEST1
	
	<#---general collect functions - often used in _Start/Stop_common_tasks---#>
	#FwClearCaches _Start_ 
	#FwCopyWindirTracing IPhlpSvc 
	#FwDoCrash 
	#FwGetCertsInfo _Stop_ Basic
	#FwGetEnv 
	#FwGetGPresultAS 
	#FwGetKlist 
	#FwGetMsInfo32 
	#FwGetNltestDomInfo 
	#FwGetPoolmon 
	#FwGetProxyInfo 
	#FwGetQwinsta 
	#FwGetRegHives 
	#FwRestartInOwnSvc WebClient
	#FwGetSVC 
	#FwGetSVCactive 
	#FwGetSysInfo 
	#FwGetTaskList 
	#FwGetWhoAmI
	#FwTest-TCPport -ComputerName "cesdiagtools.blob.core.windows.net" -Port 80 -Timeout 900
	
    EndFunc $MyInvocation.MyCommand.Name
}
function CollectDEV_TEST2Log
{
    EnterFunc $MyInvocation.MyCommand.Name
    LogInfo "$($MyInvocation.MyCommand.Name) is called."
    EndFunc $MyInvocation.MyCommand.Name
}

##### Diag function
function RunDEV_TEST1Diag
{
    EnterFunc $MyInvocation.MyCommand.Name
    If($global:BoundParameters.containskey('InputlogPath')){
        $diagpath = $global:BoundParameters['InputlogPath']
        LogInfo "diagpath = $diagpath"
    }
    LogMessage $Loglevel.Info "$($MyInvocation.MyCommand.Name) is called."
    EndFunc $MyInvocation.MyCommand.Name
}
<#
function RunDEV_TEST2Diag
{
    EnterFunc $MyInvocation.MyCommand.Name
    LogMessage $Loglevel.Info "$($MyInvocation.MyCommand.Name) is called."
    EndFunc $MyInvocation.MyCommand.Name
}
#>
#endregion Components Functions

#region Scenario Functions

### Pre-Start / Post-Stop / Collect / Diag function for scenario tracing
##### Common tasks
function DEV_Start_Common_Tasks{
    EnterFunc $MyInvocation.MyCommand.Name
    LogInfo "$($MyInvocation.MyCommand.Name) is called."
	#FwGetRegList _Start_
	#FwGetEvtLogList _Start_
    EndFunc $MyInvocation.MyCommand.Name
}

function DEV_Stop_Common_Tasks{
    EnterFunc $MyInvocation.MyCommand.Name
    LogInfo "$($MyInvocation.MyCommand.Name) is called."
	#FwGetRegList _Stop_
	#FwGetEvtLogList _Stop_
    EndFunc $MyInvocation.MyCommand.Name
}

##### DEV_Scn1
function DEV_Scn1ScenarioPreStart
{
    EnterFunc $MyInvocation.MyCommand.Name
    LogMessage $Loglevel.Info "$($MyInvocation.MyCommand.Name) is called."
    EndFunc $MyInvocation.MyCommand.Name
}
function DEV_Scn1ScenarioPostStart
{
    EnterFunc $MyInvocation.MyCommand.Name
    LogMessage $Loglevel.Info "$($MyInvocation.MyCommand.Name) is called."
    EndFunc $MyInvocation.MyCommand.Name
}
function DEV_Scn1ScenarioPreStop
{
    EnterFunc $MyInvocation.MyCommand.Name
    LogMessage $Loglevel.Info "$($MyInvocation.MyCommand.Name) is called."
    EndFunc $MyInvocation.MyCommand.Name
}
function DEV_Scn1ScenarioPostStop
{
    EnterFunc $MyInvocation.MyCommand.Name
    LogMessage $Loglevel.Info "$($MyInvocation.MyCommand.Name) is called."
    EndFunc $MyInvocation.MyCommand.Name
}
function CollectDEV_Scn1ScenarioLog
{
    EnterFunc $MyInvocation.MyCommand.Name
    LogMessage $Loglevel.Info "$($MyInvocation.MyCommand.Name) is called."
    EndFunc $MyInvocation.MyCommand.Name
}
function RunDEV_Scn1ScenarioDiag
{
    EnterFunc $MyInvocation.MyCommand.Name
    LogMessage $Loglevel.Info "$($MyInvocation.MyCommand.Name) is called."
    EndFunc $MyInvocation.MyCommand.Name
}

##### DEV_Scn2
function DEV_Scn2ScenarioPreStart
{
    EnterFunc $MyInvocation.MyCommand.Name
    LogMessage $Loglevel.Info "$($MyInvocation.MyCommand.Name) is called."
    EndFunc $MyInvocation.MyCommand.Name
}
function DEV_Scn2ScenarioPostStop
{
    EnterFunc $MyInvocation.MyCommand.Name
    LogMessage $Loglevel.Info "$($MyInvocation.MyCommand.Name) is called."
    EndFunc $MyInvocation.MyCommand.Name
}
function CollectDEV_Scn2ScenarioLog
{
    EnterFunc $MyInvocation.MyCommand.Name
    LogMessage $Loglevel.Info "$($MyInvocation.MyCommand.Name) is called."
    EndFunc $MyInvocation.MyCommand.Name
}
<#
function RunDEV_Scn2ScenarioDiag
{
    EnterFunc $MyInvocation.MyCommand.Name
    LogMessage $Loglevel.Info "$($MyInvocation.MyCommand.Name) is called."
    EndFunc $MyInvocation.MyCommand.Name
}
#>
#endregion Scenario Functions

#endregion Functions

#region Registry Key modules for FwAddRegItem
	$global:KeysSNMP = @("HKLM:System\CurrentControlSet\Services\SNMP", "HKLM:System\CurrentControlSet\Services\SNMPTRAP")
	$global:KeysTcp = @("HKLM:System\CurrentControlSet\Services\TcpIp\Parameters", "HKLM:System\CurrentControlSet\Services\Tcpip6\Parameters", "HKLM:System\CurrentControlSet\Services\tcpipreg", "HKLM:System\CurrentControlSet\Services\iphlpsvc")
	<# Example:
	$global:KeysHyperV = @("HKLM:Software\Microsoft\Windows NT\CurrentVersion\Virtualization", "HKLM:System\CurrentControlSet\Services\vmsmp\Parameters")
	#>
#endregion Registry Key modules

#region groups of Eventlogs for FwAddEvtLog
	$EvtLogsBluetooth 	= @("Microsoft-Windows-Bluetooth-BthLEPrepairing/Operational", "Microsoft-Windows-Bluetooth-MTPEnum/Operational")
	<# Example:
	$global:EvtLogsEFS		= @("Microsoft-Windows-NTFS/Operational", "Microsoft-Windows-NTFS/WHC")
	#>
#endregion groups of Eventlogs

Export-ModuleMember -Function * -Cmdlet * -Variable * -Alias *



# SIG # Begin signature block
# MIInzQYJKoZIhvcNAQcCoIInvjCCJ7oCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDGKpgp2W9+rUhT
# ISqIp1HrowSLg3jqd7+swzGjIPwp1aCCDYEwggX/MIID56ADAgECAhMzAAACzI61
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
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIZojCCGZ4CAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAsyOtZamvdHJTgAAAAACzDAN
# BglghkgBZQMEAgEFAKCBrjAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQg8/RbgJq1
# Bh4O3PcMvFVbYPmYdP++/zGlA+xRd1fQDHMwQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQCFkVg3qOqryLmbMY4Q51HP/srKCRHIVOgWx20dJrL1
# LPnc9vQGg7gN3F9sbTLBJcqEXutc//MOIkWb0YFHJmNmfhtnMNnNl94YELoN8tur
# 0WcnJL+Xlb8Pjy2imVb0ku+++vI6Jrft06NMa4K2yf05rSnkPpAmQgxznb9q3PRQ
# ZucG7SY/fiWYstImVjp/yZ+BHPRrl4d7Nq5gaIUb9H1kqmxcHlk8ImvqJ4X7BO1R
# P72v9gVkDZTJKRM+GM2PIrg4Ak0+1+eKP4PE+HnojQrA7wZbo1ef0jTVhtNhy81v
# hGklpuJeD+o07BBsdR7lDAi23BYb+L6afZCq7TVZJPhWoYIXLDCCFygGCisGAQQB
# gjcDAwExghcYMIIXFAYJKoZIhvcNAQcCoIIXBTCCFwECAQMxDzANBglghkgBZQME
# AgEFADCCAVkGCyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEICmlsZlIWtU34Oorr1jD5aEjHtyotc3sPxfixEnp
# 8zR7AgZjT/SUQlwYEzIwMjIxMDI2MTQyOTUyLjA5OFowBIACAfSggdikgdUwgdIx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1p
# Y3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhh
# bGVzIFRTUyBFU046M0JENC00QjgwLTY5QzMxJTAjBgNVBAMTHE1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFNlcnZpY2WgghF7MIIHJzCCBQ+gAwIBAgITMwAAAbT7gAhEBdIt
# +gABAAABtDANBgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0Eg
# MjAxMDAeFw0yMjA5MjAyMDIyMDlaFw0yMzEyMTQyMDIyMDlaMIHSMQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQg
# SXJlbGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1Mg
# RVNOOjNCRDQtNEI4MC02OUMzMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFt
# cCBTZXJ2aWNlMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtEemnmUH
# MkIfvOiu27K86ZbwWhksGwV72Dl1uGdqr2pKm+mfzoT+Yngkq9aLEf+XDtADyA+2
# KIZU0iO8WG79eJjzz29flZpBKbKg8xl2P3O9drleuQw3TnNfNN4+QIgjMXpE3txP
# F7M7IRLKZMiOt3FfkFWVmiXJAA7E3OIwJgphg09th3Tvzp8MT8+HOtG3bdrRd/y2
# u8VrQsQTLZiVwTZ6qDYKNT8PQZl7xFrSSO3QzXa91LipZnYOl3siGJDCee1Ba7X1
# i13dQFHxKl5Ff4JzDduOBZ85e2VrpyFy1a3ayGUzBrIw59jhMbjIw9YVcQt9kUWn
# tyCmNk15WybCS+hXpEDDLVj1X5W9snmoW1qu03+unprQjWQaVuO7BfcvQdNVdyKS
# qAeKy1eT2Hcc5n1aAVeXFm6sbVJmZzPQEQR3Jr7W8YcTjkqC5hT2qrYuIcYGOf3P
# j4OqdXm1Qqhuwtskxviv7yy3Z+PxJpxKx+2e6zGRaoQmIlLfg/a42XNVHTf6Wzr5
# k7Q1w7v0uA/sFsgyKmI7HzKHX08xDDSmJooXA5btD6B0lx/Lqs6Qb4KthnA7N2IE
# dJ5sjMIhyHZwBr7fzDskU/+Sgp2UnfqrN1Vda/gb+pmlbJwi8MphvElYzjT7PZK2
# Dm4eorcjx7T2QVe3EIelLuGbxzybblZoRTkCAwEAAaOCAUkwggFFMB0GA1UdDgQW
# BBTLRIXl8ZS4Opy7Eii3Tt44zDLZfjAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJl
# pxtTNRnpcjBfBgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAx
# MCgxKS5jcmwwbAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3Rh
# bXAlMjBQQ0ElMjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQM
# MAoGCCsGAQUFBwMIMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQsFAAOCAgEA
# EtEPBYwpt4JioSq0joGzwqYX6SoNH7YbqpgArdlnrdt6u3ukKREluKEVqS2XajXx
# x0UkXGc4Xi9dp2bSxpuyQnTkq+IQwkg7p1dKrwAa2vdmaNzz3mrSaeUEu40yCThH
# wquQkweoG4eqRRZe19OtVSmDDNC3ZQ6Ig0qz79vivXgy5dFWk4npxA5LxSGR4wBa
# XaIuVhoEa06vd/9/2YsQ99bCiR7SxJRt1XrQ5kJGHUi0Fhgz158qvXgfmq7qNqfq
# fTSmsQRrtbe4Zv/X+qPo/l6ae+SrLkcjRfr0ONV0vFVuNKx6Cb90D5LgNpc9x8V/
# qIHEr+JXbWXW6mARVVqNQCmXlVHjTBjhcXwSmadR1OotcN/sKp2EOM9JPYr86O9Y
# /JAZC9zug9qljKTroZTfYA7LIdcmPr69u1FSD/6ivL6HRHZd/k2EL7FtZwzNcRRd
# FF/VgpkOxHIfqvjXambwoMoT+vtGTtqgoruhhSk0bM1F/pBpi/nPZtVNLGTNaK8W
# t6kscbC9G6f09gz/wBBJOBmvTLPOOT/3taCGSoJoDABWnK+De5pie4KX8BxxKQbJ
# vxz7vRsVJ5R6mGx+Bvav5AjsxvZZw6eQmkI0vPRckxL9TCVCfWS0uyIKmyo6Tdos
# nbBO/osre7r0jS9AH8spEqVlhFcpQNfOg/CvdS2xNVMwggdxMIIFWaADAgECAhMz
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
# 7oJtpQUQwXEGahC0HVUzWLOhcGbyoYIC1zCCAkACAQEwggEAoYHYpIHVMIHSMQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNy
# b3NvZnQgSXJlbGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxl
# cyBUU1MgRVNOOjNCRDQtNEI4MC02OUMzMSUwIwYDVQQDExxNaWNyb3NvZnQgVGlt
# ZS1TdGFtcCBTZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQBlnNiQ85uX9nN4KRJt/gHk
# Jx4JCKCBgzCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
# MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
# b24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqG
# SIb3DQEBBQUAAgUA5wOtOjAiGA8yMDIyMTAyNjIwNTczMFoYDzIwMjIxMDI3MjA1
# NzMwWjB3MD0GCisGAQQBhFkKBAExLzAtMAoCBQDnA606AgEAMAoCAQACAg4wAgH/
# MAcCAQACAhIIMAoCBQDnBP66AgEAMDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQB
# hFkKAwKgCjAIAgEAAgMHoSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQEFBQADgYEA
# cwzt8HG4xJAMrA4LPkZtXIAh7MkcCcMVAYK+pEIebb0OyOAjigSUnCYZJvihtSsl
# D/+2iXAjZrmUoMmkECPOLVbtsSTo8KJBL5o/bp0Hb/we/d9GaPkI/LoT8W6KGTeB
# G6D+xtjjwBswjgq+ABBU1DEQc+ZcBfHevIQnPm9yi/gxggQNMIIECQIBATCBkzB8
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1N
# aWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAbT7gAhEBdIt+gABAAAB
# tDANBglghkgBZQMEAgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEE
# MC8GCSqGSIb3DQEJBDEiBCArRVhxU3n9YzqqBXuWafqUE7B5a/v5CUz6X5gDSU3U
# aTCB+gYLKoZIhvcNAQkQAi8xgeowgecwgeQwgb0EINPI93vmozBwBlFxvfr/rElr
# eFPR4ux7vXKx2ni3AfcGMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENB
# IDIwMTACEzMAAAG0+4AIRAXSLfoAAQAAAbQwIgQgilPxWnURWR8jdCkhhDzQ2lRS
# AkvqHPCEg+sB3XSsAa0wDQYJKoZIhvcNAQELBQAEggIAKp783wxp15fUikQC/HRf
# 83MYBaGBs2YcGvnZm2a0BId7KACxQ1ZofgWHmQYYOdf2xr5Hh48xhgBcKFoWnTca
# OODyrg5UpiTUFna6PVUyhUg2lM9BC2r4Jv7edFOMchrUJVFn7UXICDjfNz9oqi27
# IsD2tGdDPc0VkTNnFx2/pB6sEyh7GlbNtakzErR+1mfJfeHK2iTATV5b0EpMLoeX
# 1/7kl3wsG55t1g3I5s6G7C85WaX3kpasScOsFigBO0iWp3PdJSFbzJAprHTZ1yV+
# ES3rR5GDqyXM7i5AALIcHbp/wQxaylLIHUtwpQr8AqclL4SjlF667reR21kHbndh
# OBUthy2vUEVrXtz0WGFYQ53Xn7LPfU5/12ieeABVrKJYFP+aRRRvpihAnQkBtbqk
# sSJiRg8jtKaggM+F43iMeyQEaxlRHckXCZHvcgvCaLrp5YxMN2oNBIyV1yQc1phd
# /luNcpb86ua4pj8WR85AQavTFIKz6HYEbXpl0Lt6TbBSFsCu4fX5WhKo2kR2VxT1
# N14waf8goN8iZSR/5PpuOImS7eDTgULoGR/OioDbdKBZeiVDiLU+Wfe39Yf/b4Nq
# fN3ZEHsWsy2bu2O0Gsu9vfJ7LLojCalVdOjtjUSjf2NEJbH6tnEeiK3oVFX1DBVS
# P7OX4IRs8yC9AdiZ/vBNCP0=
# SIG # End signature block
