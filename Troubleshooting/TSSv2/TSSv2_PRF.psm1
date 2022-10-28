<#
.SYNOPSIS
   PRF module for collecting ETW traces and various custom tracing functionality

.DESCRIPTION
   Define ETW traces for Windows PRF components 
   Add any custom tracing functinaliy for tracing PRF components
   For Developers:
   1. Switch test: .\TSSv2.ps1 -Start -PRF_TEST1
   2. Scenario test: .\TSSv2.ps1 -start -Scenario PRF_MyScenarioTest

.NOTES  
   Authors    : Takahiro Aizawa 
   Requires   : PowerShell V4 (Supported from Windows 8.1/Windows Server 2012 R2)
   Version    : see $global:TssVerDatePRF

.LINK
	TSSv2 https://internal.support.services.microsoft.com/en-us/help/4619187
	PRF https://internal.support.services.microsoft.com/en-us/help/5009898
#>

<# latest changes
  2021.12.18.0 [rh] _FW: change variable name to $global:StartAutologger from $global:SetAutoLogger to refect the change happened in FW
  2021.11.10.0 [we] #_# replaced all 'Get-WmiObject' with 'Get-CimInstance' to be compatible with PowerShell v7
#>

$global:TssVerDatePRF= "2021.12.18.0"

#------------------------------------------------------------
#region Switches
#------------------------------------------------------------

#---  Perflib Providers ---#
$PRF_PerflibProviders = @(
    '{04D66358-C4A1-419B-8023-23B73902DE2C}!Perflib' # Microsoft-Windows-PDH
    '{E1A5FA6F-2E74-4C70-B292-D34C4338D54C}!Perflib' # LoadperfDll
    '{13B197BD-7CEE-4B4E-8DD0-59314CE374CE}!Perflib' # Microsoft-Windows-Perflib
    '{970407AD-6485-45DA-AA30-58E0037770E4}!Perflib' # PerfLib
    '{BC44FFCD-964B-5B85-8662-0BA87EDAF07A}!Perflib' # Microsoft.Windows.PerfLib
    '{C9BF4A07-D547-4D11-8242-E03A18B5BE01}!Perflib' # PERFLIB
    '{BFFB9DBD-5983-4197-BB1A-243798DDBEC7}!WmiPerf' # WMIPerfClass
    '{970406AD-6475-45DA-AA30-57E0037770E4}!WmiPerf' # WMIPerfInst 
)

#--- RADAR Providers ---#
$PRF_RADARProviders = @(
    '{17FBAB0B-1E4F-45F8-91ED-C1C85BCF6E61}' # RdrResTraceGuid
    '{9D3A5FA0-29F7-423F-B026-E4456ABEEF2C}' # RdrDetTraceGuid
    '{C2B32509-6F1B-4A71-A2D7-EE0B8F5DEBD1}' # RdrLeakDiagTraceGuid
    '{5C9BE3E0-3593-4DCD-8F6D-63840923FFEE}' # Microsoft-Windows-Resource-Leak-Diagnostic
    '{9988748E-C2E8-4054-85F6-0C3E1CAD2470}' # Microsoft-Windows-Resource-Exhaustion-Detector
    '{91F5FB12-FDEA-4095-85D5-614B495CD9DE}' # Microsoft-Windows-Resource-Exhaustion-Resolver
)

#--- Superfetch (sysmain) Providers ---#
$PRF_SysmainProviders = @(
    '{A319D300-015C-48BE-ACDB-47746E154751}' # Microsoft-Windows-FileInfoMinifilter
    '{99806515-9F51-4C2F-B918-1EAE407AA8CB}' # Microsoft-Windows-Superfetch
    '{4D5A5784-B063-4C87-8DEF-DBF683902CE3}' # SuperFetch
    '{164B9D03-A84D-4C1F-9941-715E07E2C6C9}' # SUMAPIGuid
    '{DE441FFA-FAFA-4495-977F-2E9D2509746D}' # PfTlgSysmainProvRegHandle
    '{2A3C1DCD-DDCB-41DE-BE16-E72DF40EE8DD}' # Microsoft.Windows.PrelaunchOptIn
    '{E6307A09-292C-497E-AAD6-498F68E2B619}' # Microsoft-Windows-ReadyBoost
    '{2A274310-42D5-4019-B816-E4B8C7ABE95C}' # Microsoft-Windows-ReadyBoostDriver
    '{648A0644-7D62-4FD3-8841-440064762F95}' # Microsoft-Windows-BackgroundTransfer-ContentPrefetcher
)

#--- Boot Providers---#

#endregion Switches


#------------------------------------------------------------
#region Scenarios
#------------------------------------------------------------

#--- Perflib Scenario ---#
$PRF_Perflib_ETWTracingSwitchesStatus = [Ordered]@{
    'UEX_WMI' = $true
    'UEX_COM' = $true
    'PRF_Perflib' = $true
    'Procmon' = $true
    'WPR General' = $true
}

#--- Boot Scenario ---#
## Usage: TSSv2.ps1 -StartAutoLogger -Scenario PRF_BOOT
$PRF_Boot_ETWTracingSwitchesStatus = [Ordered]@{
    'ADS_LSA' = $true
    'ADS_CredprovAuthui' = $true
    'UEX_Logon' = $true
    'UEX_Shell' = $true
    'UEX_SCM' = $true
    'WPR General' = $true
}

#endregion Scenarios


#------------------------------------------------------------
#region Functions
#------------------------------------------------------------
###
### Pre-Start / Post-Stop function for trace
###

#--- Perflib ---#
function PRF_PerflibPreStart
{
    EnterFunc $MyInvocation.MyCommand.Name
    LogMessage $Loglevel.Info "$($MyInvocation.MyCommand.Name) is called."
    
    # Do nothing at this point. 
    
    EndFunc $MyInvocation.MyCommand.Name
}

###
### Pre-Start / Post-Stop function for scenario trace
###
#--- Perflib Scenario---#
function PRF_PerflibScenarioPreStart
{
    EnterFunc $MyInvocation.MyCommand.Name
    LogMessage $Loglevel.Info "$($MyInvocation.MyCommand.Name) is called."

    # Do nothing at this point. 

    EndFunc $MyInvocation.MyCommand.Name
}

#--- Boot Scenario---#
function PRF_BootScenarioPreStart
{
    EnterFunc $MyInvocation.MyCommand.Name
    LogMessage $Loglevel.Info "$($MyInvocation.MyCommand.Name) is called."
    
    <#
    # Parameter check
    If(!($ParameterArray -contains 'StartAutoLogger')){
        LogDebug "ParameterArray: $ParameterArray"
        LogInfo "Boot Scenario must be called with ""StartAutoLogger"" switch"
        CleanUpandExit
    }   
    #>

    # Netlogon logging
    nltest /dbflag:0x2EFFFFFF 2>&1 | Out-Null

    # Enabling Group Policy Loggging
    mkdir "$($env:windir)\debug\usermode" 2>&1 | Out-Null
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Diagnostics" /f 2>&1 | Out-Null
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Diagnostics" /v GPSvcDebugLevel /t REG_DWORD /d 0x30002 /f 2>&1 | Out-Null

    # Create additional ETW trace (OnOff Collector) for WPR
    logman create trace "autosession\WPR_initiated_WprApp_boottr_WPR OnOff Collector" -ow -o "$LogFolder\WPR_initiated_WprApp_boottr_WPR OnOff Collector.etl" -p "{0063715b-eeda-4007-9429-ad526f62696e}" 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 4096 -ets # Microsoft-Windows-Services
    logman update trace "autosession\WPR_initiated_WprApp_boottr_WPR OnOff Collector" -p "{06184c97-5201-480e-92af-3a3626c5b140}" 0xffffffffffffffff 0xff -ets # Microsoft-Windows-Services-Svchost
    logman update trace "autosession\WPR_initiated_WprApp_boottr_WPR OnOff Collector" -p "{15ca44ff-4d7a-4baa-bba5-0998955e531e}" 0xffffffffffffffff 0xff -ets # Microsoft-Windows-Kernel-Boot
    logman update trace "autosession\WPR_initiated_WprApp_boottr_WPR OnOff Collector" -p "{2a274310-42d5-4019-b816-e4b8c7abe95c}" 0xffffffffffffffff 0xff -ets # Microsoft-Windows-ReadyBoostDriver
    logman update trace "autosession\WPR_initiated_WprApp_boottr_WPR OnOff Collector" -p "{43e63da5-41d1-4fbf-aded-1bbed98fdd1d}" 0xffffffffffffffff 0xff -ets # Microsoft-Windows-Subsys-SMSS
    logman update trace "autosession\WPR_initiated_WprApp_boottr_WPR OnOff Collector" -p "{4ee76bd8-3cf4-44a0-a0ac-3937643e37a3}" 0xffffffffffffffff 0xff -ets # Microsoft-Windows-CodeIntegrity
    logman update trace "autosession\WPR_initiated_WprApp_boottr_WPR OnOff Collector" -p "{5322d61a-9efa-4bc3-a3f9-14be95c144f8}" 0xffffffffffffffff 0xff -ets # Microsoft-Windows-Kernel-Prefetch
    logman update trace "autosession\WPR_initiated_WprApp_boottr_WPR OnOff Collector" -p "{63d2bb1d-e39a-41b8-9a3d-52dd06677588}" 0xffffffffffffffff 0xff -ets # Microsoft-Windows-Shell-AuthUI
    logman update trace "autosession\WPR_initiated_WprApp_boottr_WPR OnOff Collector" -p "{a68ca8b7-004f-d7b6-a698-07e2de0f1f5d}" 0xffffffffffffffff 0xff -ets # Microsoft-Windows-Kernel-General
    logman update trace "autosession\WPR_initiated_WprApp_boottr_WPR OnOff Collector" -p "{aea1b4fa-97d1-45f2-a64c-4d69fffd92c9}" 0xffffffffffffffff 0xff -ets # Microsoft-Windows-GroupPolicy
    logman update trace "autosession\WPR_initiated_WprApp_boottr_WPR OnOff Collector" -p "{b675ec37-bdb6-4648-bc92-f3fdc74d3ca2}" 0xffffffffffffffff 0xff -ets # Microsoft-Windows-Kernel-EventTracing
    logman update trace "autosession\WPR_initiated_WprApp_boottr_WPR OnOff Collector" -p "{dbe9b383-7cf3-4331-91cc-a3cb16a3b538}" 0xffffffffffffffff 0xff -ets # Microsoft-Windows-Winlogon
    logman update trace "autosession\WPR_initiated_WprApp_boottr_WPR OnOff Collector" -p "{de7b24ea-73c8-4a09-985d-5bdadcfa9017}" 0xffffffffffffffff 0xff -ets # Microsoft-Windows-TaskScheduler
    logman update trace "autosession\WPR_initiated_WprApp_boottr_WPR OnOff Collector" -p "{e6307a09-292c-497e-aad6-498f68e2b619}" 0xffffffffffffffff 0xff -ets # Microsoft-Windows-ReadyBoost
    logman update trace "autosession\WPR_initiated_WprApp_boottr_WPR OnOff Collector" -p "{9C205A39-1250-487D-ABD7-E831C6290539}" 0xffffffffffffffff 0xff -ets # Microsoft-Windows-Kernel-PnP

    # Override output folder path
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WPR_initiated_WprApp_boottr_WPR OnOff Collector" /v FileName /t REG_SZ /d "$LogFolder\WPR_initiated_WprApp_boottr_WPR OnOff Collector.etl" /f

    EndFunc $MyInvocation.MyCommand.Name
}

function PRF_BootScenarioPostStop
{
    EnterFunc $MyInvocation.MyCommand.Name
    LogMessage $Loglevel.Info "$($MyInvocation.MyCommand.Name) is called."

    # Disable Group Policy Logging
    reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Diagnostics" /v GPSvcDebugLevel /f 2>&1 | Out-Null
    Copy-Item -Recurse "$env:windir\debug\UserMode" $LogFolder

    # Disable SCM trace
    reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Tracing\SCM\Regular" /t REG_DWORD /v TracingDisabled /d 1 /f 2>&1 | Out-Null
    Copy-Item "$env:windir\system32\LogFiles\Scm\SCM*" $LogFolder

    # Disable Netlogon trace
    nltest /dbflag:0x0 2>&1 | Out-Null
    Copy-Item "$env:windir\debug\netlogon*" $LogFolder

    # Stop Additional ETW trace for WPR
    logman stop "WPR_initiated_WprApp_boottr_WPR OnOff Collector" -ets 2>&1 | Out-Null
    logman delete "autosession\WPR_initiated_WprApp_boottr_WPR OnOff Collector" -ets 2>&1 | Out-Null

    
    # Wait for starting wpr.exe -stop command. 
    Start-Sleep 5
    
    # Merge etl files and delete original files
    $OriginalWPRLogFile = "$LogFolder\WPR-boottrace$LogSuffix.etl"
    $AdditionalETWLogFile = "$LogFolder\WPR_initiated_WprApp_boottr_WPR OnOff Collector.etl"
    $MergedLogFile = "$LogFolder\WPR-boottrace$LogSuffix-merged.etl"

    LogInfo ('[Boot] Waiting for wpr to complete')
    Wait-Process -Name "wpr" | Out-Null

    LogInfo ('[Boot] Merging wpr files')
    xperf -merge "$OriginalWPRLogFile" "$AdditionalETWLogFile" "$MergedLogFile"
    if(Test-Path "$MergedLogFile"){
        Remove-Item "$OriginalWPRLogFile" -Force
        Remove-item "$AdditionalETWLogFile" -Force
    }

    EndFunc $MyInvocation.MyCommand.Name
}


###
### Data Collection
###
#--- Perflib ---#
function CollectPRF_PerflibLog
{
    EnterFunc $MyInvocation.MyCommand.Name
    LogMessage $Loglevel.Info "$($MyInvocation.MyCommand.Name) is called."
    
    # Log folder
    $PerflibLogFolder = "$LogFolder\PerflibLog$LogSuffix"
    $EventLogFolder = "$PerflibLogFolder\EventLog"
    Try{
        FwCreateLogFolder $PerflibLogFolder
        FwCreateLogFolder $EventLogFolder
    }Catch{
        LogException ("Unable to create $PerflibLogFolder.") $_
        Return
    }

    # Registry
    LogMessage $LogLevel.Info ("[Perflib] Exporting registry keys related to performance counter.")
    reg query   "HKLM\System\CurrentControlSet\Services" /s                                                                         | Out-File -FilePath "$PerflibLogFolder\services.txt"
    reg save    "HKLM\System\CurrentControlSet\Services" "$PerflibLogFolder\services.hiv" /y 2>&1                                   | Out-Null 
    reg export  "HKLM\System\CurrentControlSet\Services" "$PerflibLogFolder\services.reg" /y 2>&1                                   | Out-Null 
    reg query   "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Perflib" /s                                                      | Out-File -FilePath "$PerflibLogFolder\Perflib.txt"
    reg save    "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Perflib" "$PerflibLogFolder\Perflib.hiv" /y 2>&1                 | Out-Null 
    reg export  "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Perflib" "$PerflibLogFolder\Perflib.reg" /y 2>&1                 | Out-Null 
    reg query   "HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Perflib" /s                                          | Out-File -FilePath "$PerflibLogFolder\Perflib32.txt"
    reg save    "HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Perflib" "$PerflibLogFolder\Perflib32.hiv" /y 2>&1   | Out-Null 
    reg export  "HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Perflib" "$PerflibLogFolder\Perflib32.reg" /y 2>&1   | Out-Null 
    Get-ChildItem -Recurse "$env:windir\Inf"                                                                                        | Out-File -FilePath "$PerflibLogFolder\inf-dir.txt"
    (Get-ItemProperty -ErrorAction SilentlyContinue -literalpath ("HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib\CurrentLanguage")).Counter    | Out-File -FilePath "$PerflibLogFolder\Counter.txt"
    (Get-ItemProperty -ErrorAction SilentlyContinue -literalpath ("HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib\CurrentLanguage")).Help       | Out-File -FilePath "$PerflibLogFolder\Help.txt"

    # .Dat file
    LogMessage $LogLevel.Info ("[Perflib] Exporting .dat files related to performance counter.")
    Copy-Item "$env:Windir\System32\perf*.dat" $PerflibLogFolder 

    # Command result
    LogMessage $LogLevel.Info ("[Perflib] Enumerating performance counters.")
    $cmd = "typeperf -q"
    Invoke-Expression ($cmd) | Out-File -FilePath "$PerflibLogFolder\typeperf.txt"
    $cmd = "typeperf -qx"
    Invoke-Expression ($cmd) | Out-File -FilePath "$PerflibLogFolder\typeperf-inst.txt"
    $cmd = "lodctr /Q"
    Invoke-Expression ($cmd) | Out-File -FilePath "$PerflibLogFolder\lodctrQuery.txt"
    $cmd = $env:windir + "\SysWOW64\typeperf.exe -q" 
    Invoke-Expression ($cmd) | Out-File -FilePath "$PerflibLogFolder\typeperf32.txt"
    $cmd = $env:windir + "\SysWOW64\typeperf.exe -qx" 
    Invoke-Expression ($cmd) | Out-File -FilePath "$PerflibLogFolder\typeperf32-inst.txt"
    $cmd = $env:windir + "\SysWOW64\lodctr.exe /Q"
    Invoke-Expression ($cmd) | Out-File -FilePath "$PerflibLogFolder\lodctrQuery32.txt"

    Get-CimInstance -Query "select * from meta_class where __CLASS like '%Win32_Perf%'" | Select-Object -Property __CLASS | Sort-Object -Property __CLASS | Out-File -FilePath "$PerflibLogFolder\WMIPerfClasses.txt"
    
    # Eventlog
    LogMessage $LogLevel.Info ("[Perflib] Exporting Event logs related to performance counter.")
    $EventLogs = Get-WinEvent -ListLog * -ErrorAction Ignore
    $PLALogs =  @(
                'System', 'Application', 'Microsoft-Windows-Diagnosis-PLA/Operational'
                   ) 
    ForEach($EventLog in $EventLogs){
        if ($PLALogs -contains $EventLog.LogName){
            $tmpStr = $EventLog.LogName.Replace('/','-')
            $EventLogName = ($tmpStr.Replace(' ','-') + '.evtx')
            wevtutil epl $EventLog.LogName "$EventLogFolder\$EventLogName" 2>&1 | Out-Null
        }
    }
    
    EndFunc $MyInvocation.MyCommand.Name
}

#region Registry Key modules for FwAddRegItem
	<# Example:
	$global:KeysHyperV = @("HKLM:Software\Microsoft\Windows NT\CurrentVersion\Virtualization", "HKLM:System\CurrentControlSet\Services\vmsmp\Parameters")
	#>
#endregion Registry Key modules

#region groups of Eventlogs for FwAddEvtLog
	<# Example:
	$global:EvtLogsEFS		= @("Microsoft-Windows-NTFS/Operational", "Microsoft-Windows-NTFS/WHC")
	#>
#endregion groups of Eventlogs

Export-ModuleMember -Function * -Cmdlet * -Variable * -Alias *
# SIG # Begin signature block
# MIInzQYJKoZIhvcNAQcCoIInvjCCJ7oCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDfV6RiMoZium96
# cgremPfcnZUYyzZJJKIX4hAnvyPZsqCCDYEwggX/MIID56ADAgECAhMzAAACzI61
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
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgajyxLPy5
# CLS1qrV7x3WxJFdyc3p2sWXFlmArwGDsF74wQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQAGSWErG2tUReQroghXEDXnMbIEpOvwT06JEpBsQrxc
# Jw1A8OJapec914ELgKDdIoIlmFS7WAjToSA37cDChY+e+nW1mmc6qdNvr0HRre9D
# 8iUUTldV/GwXVbA3QysMX+ocmr7HMWiWLgZe3j7IHS+AfGWhoyijk7b/nttHG9CQ
# yaL4jAbPVR8a1iDpcSVdMBznJ9TYg45DSI26+FB4sLWWk+T3m0EMSxgIb+FAWHTH
# zg4JbowMAjBJifNWeq6cAGIO+bpWKMik2iOb85k/3BpbTidgOz0tzeB4f3COo9Qp
# yeCsP515GmkxyUY3XDY4PuR/t58Zv5EA9S26uUA5qys1oYIXLDCCFygGCisGAQQB
# gjcDAwExghcYMIIXFAYJKoZIhvcNAQcCoIIXBTCCFwECAQMxDzANBglghkgBZQME
# AgEFADCCAVkGCyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEIBMkNfFGqOVH1Z059uJ36If7EYal+evXUli1Ibah
# JU1UAgZjT+tCuXwYEzIwMjIxMDI2MTQyOTUwLjc2M1owBIACAfSggdikgdUwgdIx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1p
# Y3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhh
# bGVzIFRTUyBFU046OEQ0MS00QkY3LUIzQjcxJTAjBgNVBAMTHE1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFNlcnZpY2WgghF7MIIHJzCCBQ+gAwIBAgITMwAAAbP+Jc4pGxuK
# HAABAAABszANBgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0Eg
# MjAxMDAeFw0yMjA5MjAyMDIyMDNaFw0yMzEyMTQyMDIyMDNaMIHSMQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQg
# SXJlbGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1Mg
# RVNOOjhENDEtNEJGNy1CM0I3MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFt
# cCBTZXJ2aWNlMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtHwPuuYY
# gK4ssGCCsr2N7eElKlz0JPButr/gpvZ67kNlHqgKAW0JuKAy4xxjfVCUev/eS5aE
# cnTmfj63fvs8eid0MNvP91T6r819dIqvWnBTY4vKVjSzDnfVVnWxYB3IPYRAITNN
# 0sPgolsLrCYAKieIkECq+EPJfEnQ26+WTvit1US+uJuwNnHMKVYRri/rYQ2P8fKI
# JRfcxkadj8CEPJrN+lyENag/pwmA0JJeYdX1ewmBcniX4BgCBqoC83w34Sk37RMS
# sKAU5/BlXbVyDu+B6c5XjyCYb8Qx/Qu9EB6KvE9S76M0HclIVtbVZTxnnGwsSg2V
# 7fmJx0RP4bfAM2ZxJeVBizi33ghZHnjX4+xROSrSSZ0/j/U7gYPnhmwnl5SctprB
# c7HFPV+BtZv1VGDVnhqylam4vmAXAdrxQ0xHGwp9+ivqqtdVVDU50k5LUmV6+Glm
# WyxIJUOh0xzfQjd9Z7OfLq006h+l9o+u3AnS6RdwsPXJP7z27i5AH+upQronsemQ
# 27R9HkznEa05yH2fKdw71qWivEN+IR1vrN6q0J9xujjq77+t+yyVwZK4kXOXAQ2d
# T69D4knqMlFSsH6avnXNZQyJZMsNWaEt3rr/8Nr9gGMDQGLSFxi479Zy19aT/fHz
# sAtu2ocBuTqLVwnxrZyiJ66P70EBJKO5eQECAwEAAaOCAUkwggFFMB0GA1UdDgQW
# BBTQGl3CUWdSDBiLOEgh/14F3J/DjTAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJl
# pxtTNRnpcjBfBgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAx
# MCgxKS5jcmwwbAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3Rh
# bXAlMjBQQ0ElMjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQM
# MAoGCCsGAQUFBwMIMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQsFAAOCAgEA
# Woa7N86wCbjAAl8RGYmBZbS00ss+TpViPnf6EGZQgKyoaCP2hc01q2AKr6Me3TcS
# JPNWHG14pY4uhMzHf1wJxQmAM5Agf4aO7KNhVV04Jr0XHqUjr3T84FkWXPYMO4ul
# QG6j/+/d7gqezjXaY7cDqYNCSd3F4lKx0FJuQqpxwHtML+a4U6HODf2Z+KMYgJzW
# RnOIkT/od0oIXyn36+zXIZRHm7OQij7ryr+fmQ23feF1pDbfhUSHTA9IT50KCkpG
# p/GBiwFP/m1drd7xNfImVWgb2PBcGsqdJBvj6TX2MdUHfBVR+We4A0lEj1rNbCpg
# UoNtlaR9Dy2k2gV8ooVEdtaiZyh0/VtWfuQpZQJMDxgbZGVMG2+uzcKpjeYANMlS
# KDhyQ38wboAivxD4AKYoESbg4Wk5xkxfRzFqyil2DEz1pJ0G6xol9nci2Xe8LkLd
# ET3u5RGxUHam8L4KeMW238+RjvWX1RMfNQI774ziFIZLOR+77IGFcwZ4FmoteX1x
# 9+Bg9ydEWNBP3sZv9uDiywsgW40k00Am5v4i/GGiZGu1a4HhI33fmgx+8blwR5nt
# 7JikFngNuS83jhm8RHQQdFqQvbFvWuuyPtzwj5q4SpjO1SkOe6roHGkEhQCUXdQM
# nRIwbnGpb/2EsxadokK8h6sRZMWbriO2ECLQEMzCcLAwggdxMIIFWaADAgECAhMz
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
# cyBUU1MgRVNOOjhENDEtNEJGNy1CM0I3MSUwIwYDVQQDExxNaWNyb3NvZnQgVGlt
# ZS1TdGFtcCBTZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQBxi0Tolt0eEqXCQl4qgJXU
# kiQOYaCBgzCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
# MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
# b24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqG
# SIb3DQEBBQUAAgUA5wOjvjAiGA8yMDIyMTAyNjIwMTcwMloYDzIwMjIxMDI3MjAx
# NzAyWjB3MD0GCisGAQQBhFkKBAExLzAtMAoCBQDnA6O+AgEAMAoCAQACAhrEAgH/
# MAcCAQACAhFTMAoCBQDnBPU+AgEAMDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQB
# hFkKAwKgCjAIAgEAAgMHoSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQEFBQADgYEA
# b6elv9Wk4jlxjZ+StWQgpmnuq90KA68mjgBiCZfaKF/gT6cjMcdh5+zAKXtfEIHg
# OkwPwY2LvtGTMwhMeXhpl/QwDlkgAlRjwwwa1JJbeiD5Sq1YGQgB7tmozxD58VtC
# 7M5+IcnizJyN4UBFziiSplAmmYm7gJV/Vm/C6TE7mBMxggQNMIIECQIBATCBkzB8
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1N
# aWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAbP+Jc4pGxuKHAABAAAB
# szANBglghkgBZQMEAgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEE
# MC8GCSqGSIb3DQEJBDEiBCD99p9ho8n52RXwq7u3yqYEAE7Geja2jgMTcY1ZPcJX
# 9TCB+gYLKoZIhvcNAQkQAi8xgeowgecwgeQwgb0EIIahM9UqENIHtkbTMlBlQzaO
# T+WXXMkaHoo6GfvqT79CMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENB
# IDIwMTACEzMAAAGz/iXOKRsbihwAAQAAAbMwIgQgDiaL4TziB9qFiVntb0DoyY+P
# NeWGSoKV6FVwY5ZMJacwDQYJKoZIhvcNAQELBQAEggIAfUaNLJrhXAwHAyRjsFf5
# 32Zs8cIdXPQrsKegjRbjLkDtsPcJV8kFnyh3h4WZvnmUbWgsV0398SUUB5A5sLpv
# 9w9hKA73BVNu106BE49ij1TM9CfT/+pfZO4uLfAZBO6Rxe0Rg8OY0xiBrqxVMUtM
# 8MNXhYtF19fChs+pexLy3C12rdf88mfwyDGX3UGTdMkA3jc/ORiAy01ESKfiwWpt
# /Z+Dsed4GT2BDgjZsXTAixqyW2SU3eZEWuxXEmhQYiCH4T8FvzEYpn5DRnhoieP9
# gTFCqXyBdcDzVvkcIsUbCiKqjkqJZwfWE/nnPAA3AIvMMwKpiUM+6jkINOCbPLnv
# gaaEZ9ye1sWwrfH22kR+UT/aUbpk/ewnDdS9C9qTULQTxjPlExbSjzkZOGFcc85A
# 6tueskY6AusxTlHZYEVBH5vj5clsYkqf91YyIsUZ13lHRjthCgBCRXBjMGtvv4au
# lw+lLuuDjllZqQfN3BRtFeJwve98ftSGaUZRIEsSjbST1k0OafDdJ1Vpid8V2OfS
# Ry7UCePRbMEg0KdA6vMSpcFhbm65GTkEOZnAhFSYF387W8nFnvbAwHLxBpaiakVT
# 4DlXbfHIWsD3MW9HsFMuugcfk0GeeyH3dVH/RYWoLfk43FoiXMk9LV+0bMUnJnYX
# 9nW1E9a41GW3RVGyW5urlnA=
# SIG # End signature block
