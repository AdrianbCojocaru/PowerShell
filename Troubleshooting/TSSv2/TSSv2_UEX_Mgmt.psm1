<#
.SYNOPSIS
   UEX Scenarios helper module for Managemen
   Collect WMI log and settings
   Collect Printing log and settings
   Collect WinRM log and settings
   Collect Task log and settings


.DESCRIPTION
   Collect WMI log and settings and save them to WMI log folder
   Collect Printing log and settings and save them to printing log folder
   Collect WinRM log and settings and save them to WinRM log folder
   Collect Task log and settings and save them to Task log folder

.NOTES  
   Authors    : Gianni Bragante, Luc Talpe, Ryutaro Hayashi and Milan Milosavljevic
   Requires   : PowerShell V4(Supported from Windows 8.1/Windows Server 2012 R2)
   Version    : see $global:TssVerDateUEX_Mgmt
#>

<# latest changes
  2022.05.31.0 [we] #_# fixed typos, replaced FileVersion with FwFileVersion
  2021.11.10.0 [we] #_# replaced all 'Get-WmiObject' with 'Get-CimInstance' to be compatible with PowerShell v7
  2021.10.22.0 [we] #_# call external \scripts\*-collect.ps1 for UEX_DSC, UEX_Evt, UEX_TSched
#>

$global:TssVerDateUEX_Mgmt= "2022.05.31.0"

Function CollectUEX_DSCLog{
	# invokes external script until fully integrated into TSSv2
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "[$($MyInvocation.MyCommand.Name)] . calling DSC-Collect.ps1"
	.\scripts\DSC-Collect.ps1 -DataPath $global:LogFolder -AcceptEula
	LogInfo "[$($MyInvocation.MyCommand.Name)] . Done DSC-Collect.ps1"
    EndFunc $MyInvocation.MyCommand.Name
}

Function CollectUEX_EvtLog{
	# invokes external script until fully integrated into TSSv2
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "[$($MyInvocation.MyCommand.Name)] . calling Evt-Collect.ps1"
	.\scripts\Evt-Collect.ps1 -DataPath $global:LogFolder -AcceptEula
	LogInfo "[$($MyInvocation.MyCommand.Name)] . Done Evt-Collect.ps1"
    EndFunc $MyInvocation.MyCommand.Name
}

Function CollectUEX_TSchedLog{ # CollectUEX_SchedLog is already defined in TSSv2_UEX_Mgmt.psm1
	# invokes external script until fully integrated into TSSv2
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "[$($MyInvocation.MyCommand.Name)] . calling Sched-Collect.ps1"
	.\scripts\Sched-Collect.ps1 -DataPath $global:LogFolder -AcceptEula
	LogInfo "[$($MyInvocation.MyCommand.Name)] . Done Sched-Collect.ps1"
    EndFunc $MyInvocation.MyCommand.Name
}


#region common functions for UEX_Mgmt
$DefinitionOfNetGetJoin = @"
[DllImport("netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern uint NetApiBufferFree(IntPtr Buffer);
[DllImport("netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern int NetGetJoinInformation(
  string server,
  out IntPtr NameBuffer,
  out int BufferType);
"@

If(!("Win32Api.NetApi32" -as [type])){
    Try{
        Add-Type -MemberDefinition $DefinitionOfNetGetJoin -Namespace Win32Api -Name NetApi32 -ErrorAction Stop
    }Catch{
        LogWarn "Add-Type for NetGetJoinInformation failed."
    }
}Else{
    LogDebug "[Win32Api.NetApi32] has been already added. Skipping adding definition of NetGetJoinInformation." "Gray"
}

Function GetNBDomainName {
  $pNameBuffer = [IntPtr]::Zero
  $joinStatus = 0
  $apiResult = [Win32Api.NetApi32]::NetGetJoinInformation(
    $null,               # lpServer
    [Ref] $pNameBuffer,  # lpNameBuffer
    [Ref] $joinStatus    # BufferType
  )
  if ( $apiResult -eq 0 ) {
    [Runtime.InteropServices.Marshal]::PtrToStringAuto($pNameBuffer)
    [Void] [Win32Api.NetApi32]::NetApiBufferFree($pNameBuffer)
  }
}

Function Win10Ver {
  param(
    [string] $Build
  )

  # See https://www.osgwiki.com/wiki/WSD_Wiki-CFE_Decrypting_Windows_Release_Names

  if ($build -eq 14393) {
    return " (RS1 / 1607)"
  } elseif ($build -eq 15063) {
    return " (RS2 / 1703)"
  } elseif ($build -eq 16299) {
    return " (RS3 / 1709)"
  } elseif ($build -eq 17134) {
    return " (RS4 / 1803)"
  } elseif ($build -eq 17763) {
    return " (RS5 / 1809)"
  } elseif ($build -eq 18362) {
    return " (19H1 / 1903)"
  } elseif ($build -eq 18363) {
    return " (19H2 / 1909)"    
  } elseif ($build -eq 19041) {
    return " (2004 / vb)"  
  } elseif ($build -eq 19042) {
    return " (20H2 / vb)"  
  } elseif ($build -eq 19043) {
    return " (21H1 / vb)"  
  } elseif ($build -eq 19044) {
    return " (21H2 / vb)"  
  } elseif ($build -eq 20348) {
    return " (21H1 / fe)"  
  } elseif ($build -eq 22000) {
    return " (21H2 / co)"  
  }
}

Function FindSep {
  param( [string]$FindIn, [string]$Left,[string]$Right )

  if ($left -eq "") {
    $Start = 0
  } else {
    $Start = $FindIn.IndexOf($Left) 
    if ($Start -gt 0 ) {
      $Start = $Start + $Left.Length
    } else {
       return ""
    }
  }

  if ($Right -eq "") {
    $End = $FindIn.Substring($Start).Length
  } else {
    $End = $FindIn.Substring($Start).IndexOf($Right)
    if ($end -le 0) {
      return ""
    }
  }
  $Found = $FindIn.Substring($Start, $End)
  return $Found
}

Function GetSubVal {
  param( [string]$SubName, [string]$SubValue)
  $SubProp = (Get-Item -Path ("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\EventCollector\Subscriptions\" + $SubName) | Get-ItemProperty)
  if ($SubProp.($SubValue)) {
    return $SubProp.($SubValue)
  } else {
    $cm = $SubProp.ConfigurationMode
    $subVal = (Get-Item -Path ("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\EventCollector\ConfigurationModes\" + $cm) | Get-ItemProperty)
    return $SubVal.($SubValue)
  }
}
Function ChkCert($cert, $store, $descr) {
  $cert = $cert.ToLower()
  if ($cert) {
    if ("0123456789abcdef".Contains($cert[0])) {
      $aCert = $tbCert.Select("Thumbprint = '" + $cert + "' and $store")
      if ($aCert.Count -gt 0) {
        Write-Diag ("[INFO] The $descr certificate was found, the subject is " + $aCert[0].Subject)
        if (($aCert[0].NotAfter) -gt (Get-Date)) {
          Write-Diag ("[INFO] The $descr certificate will expire on " + $aCert[0].NotAfter.ToString("yyyyMMdd HH:mm:ss.fff") )
        } else {
          Write-Diag ("[ERROR] The $descr certificate expired on " + $aCert[0].NotAfter.ToString("yyyyMMdd HH:mm:ss.fff") )
        }
      }  else {
        Write-Diag "[ERROR] The certificate with thumbprint $cert was not found in $store"
      }
    } else {
      Write-Diag "[ERROR] Invalid character in the $cert certificate thumbprint $cert"
    }
  } else {
    Write-Diag "[ERROR] The thumbprint of $descr certificate is empty"
  }
}

Function CollectSystemInfo {
    param( [string] $SysinfoLogFolder )

    LogInfo ("Collecting details about running processes")
    $proc = FwExecWMIQuery -Namespace "root\cimv2" -Query "select Name, CreationDate, ProcessId, ParentProcessId, WorkingSetSize, UserModeTime, KernelModeTime, ThreadCount, HandleCount, CommandLine, ExecutablePath, ExecutionState from Win32_Process"
    if ($PSVersionTable.psversion.ToString() -ge "3.0") {
      $StartTime= @{e={$_.CreationDate.ToString("yyyyMMdd HH:mm:ss")};n="Start time"}
      $Owner = @{N="User";E={(GetOwnerCim($_))}}
    } else {
      $StartTime= @{n='StartTime';e={$_.ConvertToDateTime($_.CreationDate)}}
      $Owner = @{N="User";E={(GetOwnerWmi($_))}}
    }

    if ($proc.count -gt 3) {
      $proc | Sort-Object Name |
      Format-Table -AutoSize -property @{e={$_.ProcessId};Label="PID"}, @{e={$_.ParentProcessId};n="Parent"}, Name,
      @{N="WorkingSet";E={"{0:N0}" -f ($_.WorkingSetSize/1kb)};a="right"},
      @{e={[DateTime]::FromFileTimeUtc($_.UserModeTime).ToString("HH:mm:ss")};n="UserTime"}, @{e={[DateTime]::FromFileTimeUtc($_.KernelModeTime).ToString("HH:mm:ss")};n="KernelTime"},
      @{N="Threads";E={$_.ThreadCount}}, @{N="Handles";E={($_.HandleCount)}}, @{N="State";E={($_.ExecutionState)}}, $StartTime, $Owner, CommandLine |
      Out-String -Width 500 | Out-File ("$SysinfoLogFolder\processes.txt")

      LogInfo ("Retrieving file version of running binaries")
      $binlist = $proc | Group-Object -Property ExecutablePath
      foreach ($file in $binlist) {
        if ($file.Name) {
          FwFileVersion -Filepath ($file.name) | Out-File -FilePath ("$SysinfoLogFolder\FilesVersion.csv") -Append
        }
      }

      LogInfo ("Collecting services details")
      $svc = FwExecWMIQuery -NameSpace "root\cimv2" -Query "select  ProcessId, DisplayName, StartMode,State, Name, PathName, StartName from Win32_Service"

      if ($svc) {
        $svc | Sort-Object DisplayName | Format-Table -AutoSize -Property ProcessId, DisplayName, StartMode,State, Name, PathName, StartName |
        Out-String -Width 400 | Out-File ("$SysinfoLogFolder\services.txt")
      }

      LogInfo ("Collecting system information")
      $pad = 27
      $OS = FwExecWMIQuery -Namespace "root\cimv2" -Query "select Caption, CSName, OSArchitecture, BuildNumber, InstallDate, LastBootUpTime, LocalDateTime, TotalVisibleMemorySize, FreePhysicalMemory, SizeStoredInPagingFiles, FreeSpaceInPagingFiles, MUILanguages from Win32_OperatingSystem"
      $CS = FwExecWMIQuery -Namespace "root\cimv2" -Query "select Model, Manufacturer, SystemType, NumberOfProcessors, NumberOfLogicalProcessors, TotalPhysicalMemory, DNSHostName, Domain, DomainRole from Win32_ComputerSystem"
      $BIOS = FwExecWMIQuery -Namespace "root\cimv2" -query "select BIOSVersion, Manufacturer, ReleaseDate, SMBIOSBIOSVersion from Win32_BIOS"
      $TZ = FwExecWMIQuery -Namespace "root\cimv2" -Query "select Description from Win32_TimeZone"
      $PR = FwExecWMIQuery -Namespace "root\cimv2" -Query "select Name, Caption from Win32_Processor"

      $ctr = Get-Counter -Counter "\Memory\Pool Paged Bytes"
      $PoolPaged = $ctr.CounterSamples[0].CookedValue 
      $ctr = Get-Counter -Counter "\Memory\Pool Nonpaged Bytes"
      $PoolNonPaged = $ctr.CounterSamples[0].CookedValue 

      "Computer name".PadRight($pad) + " : " + $OS.CSName | Out-File -FilePath ("$SysinfoLogFolder\SystemInfo.txt") -Append
      "Model".PadRight($pad) + " : " + $CS.Model | Out-File -FilePath ("$SysinfoLogFolder\SystemInfo.txt") -Append
      "Manufacturer".PadRight($pad) + " : " + $CS.Manufacturer | Out-File -FilePath ("$SysinfoLogFolder\SystemInfo.txt") -Append
      "BIOS Version".PadRight($pad) + " : " + $BIOS.BIOSVersion | Out-File -FilePath ("$SysinfoLogFolder\SystemInfo.txt") -Append
      "BIOS Manufacturer".PadRight($pad) + " : " + $BIOS.Manufacturer | Out-File -FilePath ("$SysinfoLogFolder\SystemInfo.txt") -Append
      "BIOS Release date".PadRight($pad) + " : " + $BIOS.ReleaseDate | Out-File -FilePath ("$SysinfoLogFolder\SystemInfo.txt") -Append
      "SMBIOS Version".PadRight($pad) + " : " + $BIOS.SMBIOSBIOSVersion | Out-File -FilePath ("$SysinfoLogFolder\SystemInfo.txt") -Append
      "SystemType".PadRight($pad) + " : " + $CS.SystemType | Out-File -FilePath ("$SysinfoLogFolder\SystemInfo.txt") -Append
      "Processor".PadRight($pad) + " : " + $PR.Name + " / " + $PR.Caption | Out-File -FilePath ("$SysinfoLogFolder\SystemInfo.txt") -Append
      "Processors physical/logical".PadRight($pad) + " : " + $CS.NumberOfProcessors + " / " + $CS.NumberOfLogicalProcessors | Out-File -FilePath ("$SysinfoLogFolder\SystemInfo.txt") -Append
      "Memory physical/visible".PadRight($pad) + " : " + ("{0:N0}" -f ($CS.TotalPhysicalMemory/1mb)) + " MB / " + ("{0:N0}" -f ($OS.TotalVisibleMemorySize/1kb)) + " MB" | Out-File -FilePath ("$SysinfoLogFolder\SystemInfo.txt") -Append
      "Pool Paged / NonPaged".PadRight($pad) + " : " + ("{0:N0}" -f ($PoolPaged/1mb)) + " MB / " + ("{0:N0}" -f ($PoolNonPaged/1mb)) + " MB" | Out-File -FilePath ("$SysinfoLogFolder\SystemInfo.txt") -Append
      "Free physical memory".PadRight($pad) + " : " + ("{0:N0}" -f ($OS.FreePhysicalMemory/1kb)) + " MB" | Out-File -FilePath ("$SysinfoLogFolder\SystemInfo.txt") -Append
      "Paging files size / free".PadRight($pad) + " : " + ("{0:N0}" -f ($OS.SizeStoredInPagingFiles/1kb)) + " MB / " + ("{0:N0}" -f ($OS.FreeSpaceInPagingFiles/1kb)) + " MB" | Out-File -FilePath ("$SysinfoLogFolder\SystemInfo.txt") -Append
      "Operating System".PadRight($pad) + " : " + $OS.Caption + " " + $OS.OSArchitecture | Out-File -FilePath ("$SysinfoLogFolder\SystemInfo.txt") -Append
      "Build Number".PadRight($pad) + " : " + $OS.BuildNumber + "." + (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ubr + (Win10Ver $OS.BuildNumber)| Out-File -FilePath ("$SysinfoLogFolder\SystemInfo.txt") -Append
      "Time zone".PadRight($pad) + " : " + $TZ.Description | Out-File -FilePath ("$SysinfoLogFolder\SystemInfo.txt") -Append
      "Language packs".PadRight($pad) + " : " + ($OS.MUILanguages -join " ") | Out-File -FilePath ("$SysinfoLogFolder\SystemInfo.txt") -Append
      "Install date".PadRight($pad) + " : " + $OS.InstallDate | Out-File -FilePath ("$SysinfoLogFolder\SystemInfo.txt") -Append
      "Last boot time".PadRight($pad) + " : " + $OS.LastBootUpTime | Out-File -FilePath ("$SysinfoLogFolder\SystemInfo.txt") -Append
      "Local time".PadRight($pad) + " : " + $OS.LocalDateTime | Out-File -FilePath ("$SysinfoLogFolder\SystemInfo.txt") -Append
      "DNS Hostname".PadRight($pad) + " : " + $CS.DNSHostName | Out-File -FilePath ("$SysinfoLogFolder\SystemInfo.txt") -Append
      "DNS Domain name".PadRight($pad) + " : " + $CS.Domain | Out-File -FilePath ("$SysinfoLogFolder\SystemInfo.txt") -Append
      "NetBIOS Domain name".PadRight($pad) + " : " + (GetNBDomainName) | Out-File -FilePath ("$SysinfoLogFolder\SystemInfo.txt") -Append
      $roles = "Standalone Workstation", "Member Workstation", "Standalone Server", "Member Server", "Backup Domain Controller", "Primary Domain Controller"
      "Domain role".PadRight($pad) + " : " + $roles[$CS.DomainRole] | Out-File -FilePath ("$SysinfoLogFolder\SystemInfo.txt") -Append

      $drives = @()
      $drvtype = "Unknown", "No Root Directory", "Removable Disk", "Local Disk", "Network Drive", "Compact Disc", "RAM Disk"
      $Vol = FwExecWMIQuery -NameSpace "root\cimv2" -Query "select * from Win32_LogicalDisk"
      foreach ($disk in $vol) {
        $drv = New-Object PSCustomObject
        $drv | Add-Member -type NoteProperty -name Letter -value $disk.DeviceID 
        $drv | Add-Member -type NoteProperty -name DriveType -value $drvtype[$disk.DriveType]
        $drv | Add-Member -type NoteProperty -name VolumeName -value $disk.VolumeName 
        $drv | Add-Member -type NoteProperty -Name TotalMB -Value ($disk.size)
        $drv | Add-Member -type NoteProperty -Name FreeMB -value ($disk.FreeSpace)
        $drives += $drv
      }
      $drives | 
      Format-Table -AutoSize -property Letter, DriveType, VolumeName, @{N="TotalMB";E={"{0:N0}" -f ($_.TotalMB/1MB)};a="right"}, @{N="FreeMB";E={"{0:N0}" -f ($_.FreeMB/1MB)};a="right"} |
      Out-File -FilePath ("$SysinfoLogFolder\SystemInfo.txt") -Append

      FwExecWMIQuery -Namespace "root\cimv2" -Query "select * from Win32_Product" | Sort-Object Name | Format-Table -AutoSize -Property Name, Version, Vendor, InstallDate | Out-String -Width 400 | Out-File -FilePath ($global:resDir + "\products.txt")
    } else {
      $proc = Get-Process | Where-Object {$_.Name -ne "Idle"}
      $proc | Format-Table -AutoSize -property id, name, @{N="WorkingSet";E={"{0:N0}" -f ($_.workingset/1kb)};a="right"},
      @{N="VM Size";E={"{0:N0}" -f ($_.VirtualMemorySize/1kb)};a="right"},
      @{N="Proc time";E={($_.TotalProcessorTime.ToString().substring(0,8))}}, @{N="Threads";E={$_.threads.count}},
      @{N="Handles";E={($_.HandleCount)}}, StartTime, Path | 
      Out-String -Width 300 | Out-File -FilePath ("$SysinfoLogFolder\SystemInfo.txt") -Append
      LogInfo ("WMI is not working")
    }
}

Function Write-Diag{
    param(
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String] $msg,
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String] $FileName
    )
    $msg = (get-date).ToString("yyyyMMdd HH:mm:ss.fff") + " " + $msg
    Write-Host $msg -ForegroundColor Yellow
    $msg | Out-File -FilePath $FileName -Append
}
#endregion common functions for UEX_Mgmt

<#
.SYNOPSIS
    Collect WMI log and settings
.DESCRIPTION
    Collect WMI log and settings and save them to WMI log folder
.NOTES
    Author: Gianni Bragante, Luc Talpe, Ryutaro Hayashi
    Date:   June 09, 2020
#>
Function CollectUEX_WMILog{  
    EnterFunc $MyInvocation.MyCommand.Name
    $WMILogFolder = "$LogFolder\WMILog$LogSuffix"
    $WMISubscriptions = "$WMILogFolder\Subscriptions"
    $WMIProcDumpFolder = "$WMILogFolder\ProcessDumps"
    $LogPrefix = "WMI"

    Try{
        FwCreateLogFolder $WMILogFolder
        FwCreateLogFolder $WMISubscriptions
        FwCreateLogFolder $WMIProcDumpFolder
    }Catch{
        LogException ("Unable to create $WMILogFolder.") $_ 
        Return
    }

    # Process dumps
    FwCaptureUserDump "WinMgmt" $WMIProcDumpFolder -IsService:$True
    FwCaptureUserDump "WMIPrvse" $WMIProcDumpFolder -IsService:$False
    FwCaptureUserDump "WmiApSrv" $WMIProcDumpFolder -IsService:$False
    FwCaptureUserDump "scrcons" $WMIProcDumpFolder -IsService:$False

    $list = Get-Process
    foreach ($proc in $list)
    {
        $prov = Get-Process -id $proc.id -Module -ErrorAction Ignore | Where-Object {$_.ModuleName -eq "wmidcprv.dll"} 
        if (($prov | Measure-Object).count -gt 0) {
            LogDebug ("[WMI] Found decoupled provider " + $proc.Name + " (" + $proc.id + "), collecting dump")
            FwCaptureUserDump -ProcPID $proc.id -DumpFolder $WMIProcDumpFolder
        }
    }

    # MOFs
    LogInfo ('[WMI] Collecting Autorecover MOFs content') 
    $mof = (Get-Itemproperty -ErrorAction SilentlyContinue -literalpath ("HKLM:\SOFTWARE\Microsoft\Wbem\CIMOM")).'Autorecover MOFs'
    If ($mof.length -ne 0) {
        $mof | Out-File ("$WMILogFolder\Autorecover MOFs.txt")
    }

    LogInfo ('[WMI] Collecting WMI repository and registry.')
    $Commands = @(
        "Get-ChildItem $env:SYSTEMROOT\System32\Wbem -Recurse -ErrorAction SilentlyContinue | Out-File -Append $WMILogFolder\wbemfolder.txt"
        "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Wbem $WMILogFolder\wbem.reg.txt"
    )
    RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$True

    # WMI class keys
    LogInfo ("[WMI] Exporting WMIPrvSE AppIDs and CLSIDs registration keys")
    $Commands = @(
        "reg query ""HKEY_CLASSES_ROOT\AppID\{73E709EA-5D93-4B2E-BBB0-99B7938DA9E4}"" | Out-File $WMILogFolder\WMIPrvSE.reg.txt -Append"
        "reg query ""HKEY_CLASSES_ROOT\AppID\{1F87137D-0E7C-44d5-8C73-4EFFB68962F2}"" | Out-File $WMILogFolder\WMIPrvSE.reg.txt -Append"
        "reg query ""HKEY_CLASSES_ROOT\Wow6432Node\AppID\{73E709EA-5D93-4B2E-BBB0-99B7938DA9E4}"" | Out-File $WMILogFolder\WMIPrvSE.reg.txt -Append"
        "reg query ""HKEY_CLASSES_ROOT\Wow6432Node\AppID\{1F87137D-0E7C-44d5-8C73-4EFFB68962F2}"" | Out-File $WMILogFolder\WMIPrvSE.reg.txt -Append"
        "reg query ""HKEY_CLASSES_ROOT\CLSID\{4DE225BF-CF59-4CFC-85F7-68B90F185355}"" | Out-File $WMILogFolder\WMIPrvSE.reg.txt -Append"
    )
    RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$True

    # OLE/RPC registry keys
    LogInfo ("[WMI] OLE/RPC registry keys")
    $Commands = @(
        "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Ole $WMILogFolder\OLE.reg.txt"
        "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Rpc $WMILogFolder\RPC.reg.txt"
    )
    if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc") {
      $Commands +=  @(
        "reg export ""HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Rpc $WMILogFolder\RPC-policies.reg.txt"
      )
    }
    RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$True

    LogInfo ('[WMI] Exporting event logs')
    $Commands = @(
        "wevtutil epl Application $WMILogFolder\$env:computername-Application.evtx",
        "wevtutil al $WMILogFolder\$env:computername-Application.evtx /l:en-us",
        "wevtutil epl System $WMILogFolder\$env:computername-System.evtx",
        "wevtutil al $WMILogFolder\$env:computername-System.evtx /l:en-us",
        "wevtutil epl Microsoft-Windows-WMI-Activity/Operational $WMILogFolder\$env:computername-WMI-Activity.evtx",
        "wevtutil al $WMILogFolder\$env:computername-WMI-Activity.evtx /l:en-us"
    )
    RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$True

    # WMI-Activity log
    LogInfo ('[WMI] Exporting WMI Operational log to a text file')
    $actLog = Get-WinEvent -logname "Microsoft-Windows-WMI-Activity/Operational" -Oldest -ErrorAction SilentlyContinue
    If(($actLog | Measure-Object).count -gt 0) {
        $actLog | Out-String -width 1000 | Out-File "$WMILogFolder\$env:computername-WMI-Activity.txt"
    }

    # IPCONFIG and NETSTAT
    LogInfo ("[WMI] IPCONFIG and NETSTAT")
    $Commands = @(
        "netstat -anob > $WMILogFolder\NETSTAT.txt"
        "ipconfig /all > $WMILogFolder\IPCONFIG.txt"
    )
    RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$True

    # Service configuration
    LogInfo ("[WMI] Exporting service configuration")
    $Commands = @(
        "sc.exe queryex winmgmt | Out-File $WMILogFolder\WinMgmtServiceConfig.txt -Append"
        "sc.exe qc winmgmt | Out-File $WMILogFolder\WinMgmtServiceConfig.txt -Append"
        "sc.exe enumdepend winmgmt 3000  | Out-File $WMILogFolder\WinMgmtServiceConfig.txt -Append"
        "sc.exe sdshow winmgmt | Out-File $WMILogFolder\WinMgmtServiceConfig.txt -Append"
    )
    RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$True

    # File version
    LogInfo ("[WMI] Getting file version of WMI modules")
    FwFileVersion -Filepath ("$env:windir\system32\wbem\wbemcore.dll") | Out-File -FilePath ("$WMILogFolder\FilesVersion.csv") -Append
    FwFileVersion -Filepath ("$env:windir\system32\wbem\repdrvfs.dll") | Out-File -FilePath ("$WMILogFolder\FilesVersion.csv") -Append
    FwFileVersion -Filepath ("$env:windir\system32\wbem\WmiPrvSE.exe") | Out-File -FilePath ("$WMILogFolder\FilesVersion.csv") -Append
    FwFileVersion -Filepath ("$env:windir\system32\wbem\WmiPerfClass.dll") | Out-File -FilePath ("$WMILogFolder\FilesVersion.csv") -Append
    FwFileVersion -Filepath ("$env:windir\system32\wbem\WmiApRpl.dll") | Out-File -FilePath ("$WMILogFolder\FilesVersion.csv") -Append

    CollectSystemInfo $WMILogFolder

    $WMIActivityLogs = @(
        'Microsoft-Windows-WMI-Activity/Trace'
        'Microsoft-Windows-WMI-Activity/Debug'
    )

    LogInfo ('[WMI] Exporting WMI analysitic logs.')
    [reflection.assembly]::loadwithpartialname("System.Diagnostics.Eventing.Reader") 
    $Eventlogsession = New-Object System.Diagnostics.Eventing.Reader.EventLogSession

    ForEach($WMIActivityLog in $WMIActivityLogs){
        Try{
            $EventLogConfig = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration -ArgumentList $WMIActivityLog,$Eventlogsession -ErrorAction Stop
        }Catch{
            LogException ("Error happened in creating EventLogConfiguration.") $_ $fLogFileOnly
            Continue
        }

        Try{
            $LogPath = [System.Environment]::ExpandEnvironmentVariables($Eventlogconfig.LogFilePath)
            # This is the case where ResetEventLog did nothing as the log already enabled. In this case, 
            # we need to disable it and copy the etl and then re-enable the log as it was orginally enabled.
            If($EventLogConfig.IsEnabled -eq $True){
                $EventLogConfig.IsEnabled=$False
                $EventLogConfig.SaveChanges()
                LogDebug "Copying $LogPath to $WMILogFolder"
                Copy-Item $LogPath $WMILogFolder  -ErrorAction Stop
                LogDebug ('Re-enabling ' + $Eventlogconfig.LogName)
                $EventLogConfig.IsEnabled=$True
                $EventLogConfig.SaveChanges()
            }Else{
                If(Test-path -path $LogPath){
                    LogDebug ('Copying ' + $Eventlogconfig.LogFilePath + " to $WMILogFolder")
                    Copy-Item $LogPath $WMILogFolder -ErrorAction Stop
                }
            }
        }Catch{
            LogException ('An exception happened in CollectWMILog.') $_ $fLogFileOnly
        }
    }

    # Get subscription info
    FwExecWMIQuery -Namespace "root\subscription" -Query "select * from ActiveScriptEventConsumer" | Export-Clixml -Path ("$WMISubscriptions\ActiveScriptEventConsumer.xml")
    FwExecWMIQuery -Namespace "root\subscription" -Query "select * from __eventfilter" | Export-Clixml -Path ("$WMISubscriptions\__eventfilter.xml")
    FwExecWMIQuery -Namespace "root\subscription" -Query "select * from __IntervalTimerInstruction" | Export-Clixml -Path ("$WMISubscriptions\__IntervalTimerInstruction.xml")
    FwExecWMIQuery -Namespace "root\subscription" -Query "select * from __AbsoluteTimerInstruction" | Export-Clixml -Path ("$WMISubscriptions\__AbsoluteTimerInstruction.xml")
    FwExecWMIQuery -Namespace "root\subscription" -Query "select * from __FilterToConsumerBinding" | Export-Clixml -Path ("$WMISubscriptions\__FilterToConsumerBinding.xml")

    # COM Security
    LogInfo ("[WMI] Getting COM Security info")
    $Reg = [WMIClass]"\\.\root\default:StdRegProv"
    $DCOMMachineLaunchRestriction = $Reg.GetBinaryValue(2147483650,"software\microsoft\ole","MachineLaunchRestriction").uValue
    $DCOMMachineAccessRestriction = $Reg.GetBinaryValue(2147483650,"software\microsoft\ole","MachineAccessRestriction").uValue
    $DCOMDefaultLaunchPermission = $Reg.GetBinaryValue(2147483650,"software\microsoft\ole","DefaultLaunchPermission").uValue
    $DCOMDefaultAccessPermission = $Reg.GetBinaryValue(2147483650,"software\microsoft\ole","DefaultAccessPermission").uValue
    
    $converter = new-object system.management.ManagementClass Win32_SecurityDescriptorHelper
    "Default Access Permission = " + ($converter.BinarySDToSDDL($DCOMDefaultAccessPermission)).SDDL | Out-File -FilePath ("$WMILogFolder\COMSecurity.txt") -Append
    "Default Launch Permission = " + ($converter.BinarySDToSDDL($DCOMDefaultLaunchPermission)).SDDL | Out-File -FilePath ("$WMILogFolder\COMSecurity.txt") -Append
    "Machine Access Restriction = " + ($converter.BinarySDToSDDL($DCOMMachineAccessRestriction)).SDDL | Out-File -FilePath ("$WMILogFolder\COMSecurity.txt") -Append
    "Machine Launch Restriction = " + ($converter.BinarySDToSDDL($DCOMMachineLaunchRestriction)).SDDL | Out-File -FilePath ("$WMILogFolder\COMSecurity.txt") -Append

    # Quota info
    LogInfo ("[WMI] Collecting quota details")
    $quota = FwExecWMIQuery -Namespace "Root" -Query "select * from __ProviderHostQuotaConfiguration"
    if ($quota) {
        ("ThreadsPerHost : " + $quota.ThreadsPerHost + "`r`n") + `
        ("HandlesPerHost : " + $quota.HandlesPerHost + "`r`n") + `
        ("ProcessLimitAllHosts : " + $quota.ProcessLimitAllHosts + "`r`n") + `
        ("MemoryPerHost : " + $quota.MemoryPerHost + "`r`n") + `
        ("MemoryAllHosts : " + $quota.MemoryAllHosts + "`r`n") | Out-File -FilePath ("$WMILogFolder\ProviderHostQuotaConfiguration.txt")
    }

    LogInfo ("[WMI] Collecting details of provider hosts")
    New-PSDrive -PSProvider registry -Root HKEY_CLASSES_ROOT -Name HKCR -ErrorAction SilentlyContinue | Out-Null

    "Coupled providers (WMIPrvSE.exe processes)" | Out-File -FilePath ("$WMILogFolder\ProviderHosts.txt") -Append
    "" | Out-File -FilePath ("$WMILogFolder\ProviderHosts.txt") -Append

    $totMem = 0

    $prov = FwExecWMIQuery -NameSpace "root\cimv2" -Query "select HostProcessIdentifier, Provider, Namespace, User from MSFT_Providers"
    if ($prov) {
        $proc = FwExecWMIQuery -NameSpace "root\cimv2" -Query "select ProcessId, HandleCount, ThreadCount, PrivatePageCount, CreationDate, KernelModeTime, UserModeTime from Win32_Process where name = 'wmiprvse.exe'"
        foreach ($prv in $proc) {
            $provhost = $prov | Where-Object {$_.HostProcessIdentifier -eq $prv.ProcessId}

            if (($provhost | Measure-Object).count -gt 0) {
                if ($PSVersionTable.psversion.ToString() -ge "3.0") {
                    $ut = New-TimeSpan -Start $prv.CreationDate
                } else {
                    $ut = New-TimeSpan -Start $prv.ConvertToDateTime($prv.CreationDate)
                }

                $uptime = ($ut.Days.ToString() + "d " + $ut.Hours.ToString("00") + ":" + $ut.Minutes.ToString("00") + ":" + $ut.Seconds.ToString("00"))

                $ks = $prv.KernelModeTime / 10000000
                $kt = [timespan]::fromseconds($ks)
                $kh = $kt.Hours.ToString("00") + ":" + $kt.Minutes.ToString("00") + ":" + $kt.Seconds.ToString("00")

                $us = $prv.UserModeTime / 10000000
                $ut = [timespan]::fromseconds($us)
                $uh = $ut.Hours.ToString("00") + ":" + $ut.Minutes.ToString("00") + ":" + $ut.Seconds.ToString("00")

                "PID" + " " + $prv.ProcessId + " (" + [String]::Format("{0:x}", $prv.ProcessId) + ") Handles:" + $prv.HandleCount +" Threads:" + $prv.ThreadCount + " Private KB:" + ($prv.PrivatePageCount/1kb) + " KernelTime:" + $kh + " UserTime:" + $uh + " Uptime:" + $uptime | Out-File -FilePath ("$WMILogFolder\ProviderHosts.txt") -Append
                $totMem = $totMem + $prv.PrivatePageCount
            } else {
                LogInfo  ("No provider found for the WMIPrvSE process with PID " +  $prv.ProcessId)
            }

            foreach ($provname in $provhost) {
                $provdet = FwExecWMIQuery -NameSpace $provname.Namespace -Query ("select * from __Win32Provider where Name = """ + $provname.Provider + """")
                $hm = $provdet.hostingmodel
                $clsid = $provdet.CLSID
                $dll = (get-itemproperty -ErrorAction SilentlyContinue -literalpath ("HKCR:\CLSID\" + $clsid + "\InprocServer32")).'(default)'
                $dll = $dll.Replace("""","")
                $file = Get-Item ($dll)
                $dtDLL = $file.CreationTime
                $verDLL = $file.VersionInfo.FileVersion

                $provname.Namespace + " " + $provname.Provider + " " + $dll + " " + $hm + " " + $provname.user + " " + $dtDLL + " " + $verDLL | Out-File -FilePath ("$WMILogFolder\ProviderHosts.txt") -Append
            }
            " " | Out-File -FilePath ("$WMILogFolder\ProviderHosts.txt") -Append
        }
    }
    "Total memory used by coupled providers: " + ($totMem/1kb) + " KB" | Out-File -FilePath ("$WMILogFolder\ProviderHosts.txt") -Append
    " " | Out-File -FilePath ("$WMILogFolder\ProviderHosts.txt") -Append

    # Details of decoupled providers
    LogInfo ("[WMI] Collecting details of decoupled providers")
    $list = Get-Process
    $DecoupledProviders = @()
    foreach ($proc in $list) {
        $prov = Get-Process -id $proc.id -Module -ErrorAction Ignore | Where-Object {$_.ModuleName -eq "wmidcprv.dll"} 
        if (($prov | Measure-Object).count -gt 0) {
            $DecoupledProviders += $proc

            if (-not $hdr) {
                "Decoupled providers" | Out-File -FilePath ("$WMILogFolder\ProviderHosts.txt") -Append
                " " | Out-File -FilePath ("$WMILogFolder\ProviderHosts.txt") -Append
                $hdr = $true
            }
            
            $prc = FwExecWMIQuery -Namespace "root\cimv2" -Query ("select ProcessId, CreationDate, HandleCount, ThreadCount, PrivatePageCount, ExecutablePath, KernelModeTime, UserModeTime from Win32_Process where ProcessId = " +  $proc.id)
            if ($PSVersionTable.psversion.ToString() -ge "3.0") {
              $ut = New-TimeSpan -Start $prv.CreationDate
            } else {
              $ut = New-TimeSpan -Start $prv.ConvertToDateTime($prv.CreationDate)
            }
            
            $uptime = ($ut.Days.ToString() + "d " + $ut.Hours.ToString("00") + ":" + $ut.Minutes.ToString("00") + ":" + $ut.Seconds.ToString("00"))
            
            $ks = $prc.KernelModeTime / 10000000
            $kt = [timespan]::fromseconds($ks)
            $kh = $kt.Hours.ToString("00") + ":" + $kt.Minutes.ToString("00") + ":" + $kt.Seconds.ToString("00")
            
            $us = $prc.UserModeTime / 10000000
            $ut = [timespan]::fromseconds($us)
            $uh = $ut.Hours.ToString("00") + ":" + $ut.Minutes.ToString("00") + ":" + $ut.Seconds.ToString("00")
            
            $svc = FwExecWMIQuery -Namespace "root\cimv2" -Query ("select Name from Win32_Service where ProcessId = " +  $prc.ProcessId)
            $svclist = ""
            if ($svc) {
              foreach ($item in $svc) {
                $svclist = $svclist + $item.name + " "
              }
              $svc = " Service: " + $svclist
            } else {
              $svc = ""
            }
            
            ($prc.ExecutablePath + $svc) | Out-File -FilePath ("$WMILogFolder\ProviderHosts.txt") -Append
            "PID " + $prc.ProcessId  + " (" + [String]::Format("{0:x}", $prc.ProcessId) + ")  Handles: " + $prc.HandleCount + " Threads: " + $prc.ThreadCount + " Private KB: " + ($prc.PrivatePageCount/1kb) + " KernelTime:" + $kh + " UserTime:" + $uh + " Uptime:" + $uptime | Out-File -FilePath ("$WMILogFolder\ProviderHosts.txt") -Append
            
            $Keys = Get-ChildItem HKLM:\SOFTWARE\Microsoft\Wbem\Transports\Decoupled\Client
            $Items = $Keys | Foreach-Object {Get-ItemProperty $_.PsPath }
            ForEach ($key in $Items) {
              if ($key.ProcessIdentifier -eq $prc.ProcessId) {
                ($key.Scope + " " + $key.Provider) | Out-File -FilePath ("$WMILogFolder\ProviderHosts.txt") -Append
              }
            }
            " " | Out-File -FilePath ("$WMILogFolder\ProviderHosts.txt") -Append
        }
    }

    EndFunc $MyInvocation.MyCommand.Name
}

Function CollectUEX_EventLogLog{
    EnterFunc $MyInvocation.MyCommand.Name
    $EventLogFolder = "$LogFolder\EventLog$LogSuffix"
    $EventLogDumpFolder = "$EventLogFolder\Process dump"
    $EventLogSubscriptionFolder = "$EventLogFolder\WMISubscriptions"

    Try{
        FwCreateLogFolder $EventLogFolder
        FwCreateLogFolder $EventLogDumpFolder
        FwCreateLogFolder $EventLogSubscriptionFolder
    }Catch{
        LogException ("Unable to create $EventLogFolder.") $_
        Return
    }

    # Process dump
    FwCaptureUserDump "EventLog" $EventLogDumpFolder -IsService:$True

    # Settings and registries
    $Commands =@(
        "auditpol /get /category:* | Out-File -Append $EventLogFolder\auditpol.txt",
        "reg export HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger $EventLogFolder\WMI-Autologger.reg.txt",
        "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels $EventLogFolder\WINEVT-Channels.reg.txt",
        "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers $EventLogFolder\WINEVT-Publishers.reg.txt",
        "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog $EventLogFolder\EventLog-Policies.reg.txt",
        "reg export HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog $EventLogFolder\EventLogService.reg.txt",
        "cacls C:\Windows\System32\winevt\Logs | Out-File -Append $EventLogFolder\Permissions.txt",
        "cacls C:\Windows\System32\LogFiles\WMI\RtBackup | Out-File -Append $EventLogFolder\Permissions.txt",
        "Copy-Item C:\Windows\System32\LogFiles\WMI\RtBackup -Recurse $EventLogFolder",
        "Get-ChildItem $env:windir\System32\winevt\Logs -Recurse | Out-File -Append $EventLogFolder\WinEvtLogs.txt",
        "logman -ets query `"EventLog-Application`" | Out-File -Append $EventLogFolder\EventLog-Application.txt",
        "logman -ets query ""EventLog-System"" | Out-File -Append $EventLogFolder\EventLog-System.txt",
        "logman query providers | Out-File -Append $EventLogFolder\QueryProviders.txt",
        "logman query -ets | Out-File -Append $EventLogFolder\QueryETS.txt",
        "wevtutil el  | Out-File -Append $EventLogFolder\EnumerateLogs.txt",
        "Get-ChildItem $env:windir\System32\LogFiles\WMI\RtBackup -Recurse | Out-File -Append $EventLogFolder\RTBackup.txt"

    )
    RunCommands "Eventlog" $Commands -ThrowException:$False -ShowMessage:$True

    FwExecWMIQuery -Namespace "root\subscription" -Query "select * from ActiveScriptEventConsumer" | Export-Clixml -Path ($EventLogSubscriptionFolder + "\ActiveScriptEventConsumer.xml")
    FwExecWMIQuery -Namespace "root\subscription" -Query "select * from __eventfilter" | Export-Clixml -Path ($EventLogSubscriptionFolder + "\__eventfilter.xml")
    FwExecWMIQuery -Namespace "root\subscription" -Query "select * from __IntervalTimerInstruction" | Export-Clixml -Path ($EventLogSubscriptionFolder + "\__IntervalTimerInstruction.xml")
    FwExecWMIQuery -Namespace "root\subscription" -Query "select * from __AbsoluteTimerInstruction" | Export-Clixml -Path ($EventLogSubscriptionFolder + "\__AbsoluteTimerInstruction.xml")
    FwExecWMIQuery -Namespace "root\subscription" -Query "select * from __FilterToConsumerBinding" | Export-Clixml -Path ($EventLogSubscriptionFolder + "\__FilterToConsumerBinding.xml")

    If((Get-Service EventLog).Status -eq "Running"){
        $EventLogs = @(
            "System",
            "Application",
            "Microsoft-Windows-Kernel-EventTracing/Admin"
        )
        FwExportEventLog $EventLogs $EventLogFolder
        FwEvtLogDetails "Application" $EventLogFolder
        FwEvtLogDetails "System" $EventLogFolder
        FwEvtLogDetails "Security" $EventLogFolder
        FwEvtLogDetails "HardwareEvents" $EventLogFolder
        FwEvtLogDetails "Internet Explorer" $EventLogFolder
        FwEvtLogDetails "Key Management Service" $EventLogFolder
        FwEvtLogDetails "Windows PowerShell" $EventLogFolder
    }Else{
        $Commands =@(
            "Copy-Item C:\Windows\System32\winevt\Logs\Application.evtx $EventLogFolder\$env:computername-Application.evtx"
            "Copy-Item C:\Windows\System32\winevt\Logs\System.evtx $EventLogFolder\$env:computername-System.evtx"
        )
        RunCommands "Eventlog" $Commands -ThrowException:$False -ShowMessage:$True
    }
    EndFunc $MyInvocation.MyCommand.Name
}



<#
.SYNOPSIS
    Collect WinRM log and settings
.DESCRIPTION
    Collect WinRM log and settings and save them to WinRM log folder
.NOTES
    Author: Gianni Bragante, Luc Talpe, Ryutaro Hayashi
    Date:   June 12, 2020
#>
Function CollectUEX_WinRMLog{
    EnterFunc $MyInvocation.MyCommand.Name
    $LogPrefix = "WinRM"
    $WinRMLogFolder = "$LogFolder\WinRMLog$LogSuffix"
    $WinRMEventFolder = "$LogFolder\WinRMLog$LogSuffix\EventLogs"
    $WinRMDumpFolder = "$LogFolder\WinRMLog$LogSuffix\ProcessDumps"
    $fqdn = [System.Net.Dns]::GetHostByName(($env:computerName)).HostName

    Try{
        FwCreateLogFolder $WinRMLogFolder
        FwCreateLogFolder $WinRMEventFolder
        FwCreateLogFolder $WinRMDumpFolder
    }Catch{
        LogException ("Unable to create $WinRMLogFolder.") $_
        Return
    }

    If(!(FwIsElevated)){
        LogMessage $LogLevel.Warning ("[WinRM] Collecting WinRM log needs administrative privilege.")
        Return
    }

    # process dump for WinRM Service
    FwCaptureUserDump "WinRM" $WinRMDumpFolder -IsService $True
    if ((FindServicePid "WinRM") -ne (FindServicePid "WecSvc")) {
      FwCaptureUserDump "WecSvc" $WinRMDumpFolder -IsService $True
    }
    FwCaptureUserDump "wsmprovhost.exe" $WinRMDumpFolder -IsService $False
    FwCaptureUserDump "SME.exe" $WinRMDumpFolder -IsService $False

    # Eventlog
    LogInfo ("[WinRM] Collecting WinRM configuration.")
    $EventLogs = @(
        "System",
        "Application",
        "Microsoft-Windows-CAPI2/Operational",
        "Microsoft-Windows-WinRM/Operational",
        "Microsoft-Windows-EventCollector/Operational",
        "Microsoft-Windows-Forwarding/Operational",
        "Microsoft-Windows-PowerShell/Operational",
        "`"Windows PowerShell`"",
        "Microsoft-Windows-GroupPolicy/Operational",
        "Microsoft-Windows-Kernel-EventTracing/Admin",
        "Microsoft-ServerManagementExperience",
        "Microsoft-Windows-ServerManager-ConfigureSMRemoting/Operational",
        "Microsoft-Windows-ServerManager-DeploymentProvider/Operational",
        "Microsoft-Windows-ServerManager-MgmtProvider/Operational",
        "Microsoft-Windows-ServerManager-MultiMachine/Operational",
        "Microsoft-Windows-FileServices-ServerManager-EventProvider/Operational"
    )
    FwExportEventLog $EventLogs $WinRMEventFolder

    FwEvtLogDetails "Application" $WinRMLogFolder
    FwEvtLogDetails "System" $WinRMLogFolder
    FwEvtLogDetails "Security" $WinRMLogFolder
    FwEvtLogDetails "ForwardedEvents" $WinRMLogFolder

    # Certifications
    LogInfo "[WinRM] Matching issuer thumbprints"
    $Global:tbCert = New-Object system.Data.DataTable
    $col = New-Object system.Data.DataColumn Store,([string]); $tbCert.Columns.Add($col)
    $col = New-Object system.Data.DataColumn Thumbprint,([string]); $tbCert.Columns.Add($col)
    $col = New-Object system.Data.DataColumn Subject,([string]); $tbCert.Columns.Add($col)
    $col = New-Object system.Data.DataColumn Issuer,([string]); $tbCert.Columns.Add($col)
    $col = New-Object system.Data.DataColumn NotAfter,([DateTime]); $tbCert.Columns.Add($col)
    $col = New-Object system.Data.DataColumn IssuerThumbprint,([string]); $tbCert.Columns.Add($col)
    $col = New-Object system.Data.DataColumn EnhancedKeyUsage,([string]); $tbCert.Columns.Add($col)
    $col = New-Object system.Data.DataColumn SerialNumber,([string]); $tbCert.Columns.Add($col)
    $col = New-Object system.Data.DataColumn SubjectKeyIdentifier,([string]); $tbCert.Columns.Add($col)
    $col = New-Object system.Data.DataColumn AuthorityKeyIdentifier,([string]); $tbCert.Columns.Add($col)
    FwGetCertStore "My"
    FwGetCertStore "CA"
    FwGetCertStore "Root"
    $aCert = $Global:tbCert.Select("Store = 'My' or Store = 'CA'")
    foreach ($cert in $aCert) {
      $aIssuer = $Global:tbCert.Select("SubjectKeyIdentifier = '" + ($cert.AuthorityKeyIdentifier).tostring() + "'")
      if ($aIssuer.Count -gt 0) {
        $cert.IssuerThumbprint = ($aIssuer[0].Thumbprint).ToString()
      }
    }
    $Global:tbcert | Export-Csv "$WinRMLogFolder\certificates.tsv" -noType -Delimiter "`t"
    
    # Process and service info
    $proc = FwExecWMIQuery -Namespace "root\cimv2" -Query "select Name, CreationDate, ProcessId, ParentProcessId, WorkingSetSize, UserModeTime, KernelModeTime, ThreadCount, HandleCount, CommandLine, ExecutablePath, ExecutionState from Win32_Process"
    if ($PSVersionTable.psversion.ToString() -ge "3.0") {
      $StartTime= @{e={$_.CreationDate.ToString("yyyyMMdd HH:mm:ss")};n="Start time"}
      $Owner = @{N="User";E={(GetOwnerCim($_))}}
    } else {
      $StartTime= @{n='StartTime';e={$_.ConvertToDateTime($_.CreationDate)}}
      $Owner = @{N="User";E={(GetOwnerWmi($_))}}
    }
    
    if ($proc) {
        $proc | Sort-Object Name |
        Format-Table -AutoSize -property @{e={$_.ProcessId};Label="PID"}, @{e={$_.ParentProcessId};n="Parent"}, Name,
        @{N="WorkingSet";E={"{0:N0}" -f ($_.WorkingSetSize/1kb)};a="right"},
        @{e={[DateTime]::FromFileTimeUtc($_.UserModeTime).ToString("HH:mm:ss")};n="UserTime"}, @{e={[DateTime]::FromFileTimeUtc($_.KernelModeTime).ToString("HH:mm:ss")};n="KernelTime"},
        @{N="Threads";E={$_.ThreadCount}}, @{N="Handles";E={($_.HandleCount)}}, @{N="State";E={($_.ExecutionState)}}, $StartTime, $Owner, CommandLine |
        Out-String -Width 500 | Out-File "$WinRMLogFolder\processes.txt"
        
        LogInfo "[WinRM] Retrieving file version of running binaries"
        $binlist = $proc | Group-Object -Property ExecutablePath
        foreach ($file in $binlist) {
            if ($file.Name) {
                FwFileVersion -Filepath $file.name | Out-File -Append "$WinRMLogFolder\FilesVersion.csv"
            }
        }
    
        LogInfo "[WinRM] Collecting services details"
        $svc = FwExecWMIQuery -NameSpace "root\cimv2" -Query "select  ProcessId, DisplayName, StartMode,State, Name, PathName, StartName from Win32_Service"
        
        if($svc){
            $svc | Sort-Object DisplayName | Format-Table -AutoSize -Property ProcessId, DisplayName, StartMode,State, Name, PathName, StartName |
            Out-String -Width 400 | Out-File "$WinRMLogFolder\services.txt"
        }
    }

    # Event subscripion
    If (Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\EventCollector\Subscriptions") {
        LogInfo "[WinRM] Retrieving subscriptions configuration"
        $cmd = "wecutil es 2>> $ErrorLogFile"
        LogInfo ("[WinRM] Running $cmd")
        $subList = Invoke-Expression $cmd
        
        If(![string]::IsNullOrEmpty($subList)){
            ForEach($sub in $subList){
                LogInfo ("[WinRM] Subsription: " + $sub)
                ("Subscription: " + $sub) | out-file -FilePath ("$WinRMLogFolder\Subscriptions.txt") -Append
                "-----------------------" | out-file -FilePath ("$WinRMLogFolder\Subscriptions.txt") -Append
                $cmd = "wecutil gs `"$sub`" /f:xml 2>> $ErrorLogFile"
                LogInfo ("[WinRM] Running " + $cmd)
                Invoke-Expression ($cmd) | out-file -FilePath ("$WinRMLogFolder\Subscriptions.txt") -Append
                $cmd = "wecutil gr `"$sub`" 2>> $ErrorLogFile"
                LogInfo ("[WinRM] Running " + $cmd)
                Invoke-Expression ($cmd) | out-file -FilePath ("$WinRMLogFolder\Subscriptions.txt") -Append
                " " | out-file -FilePath ("$WinRMLogFolder\Subscriptions.txt") -Append
            }
        }
    }

    # Start WinRM Service
    LogInfo ("[WinRM] Checking if WinRM is running")
    $WinRMService = Get-Service | Where-Object {$_.Name -eq 'WinRM'}
    If($Null -ne $WinRMService){

        If($WinRMService.Status -eq 'Stopped'){
            LogDebug ('[WinRM] Starting WinRM service as it is not running.')
            Start-Service $WinRMService.Name
        }

        $Service = Get-Service $WinRMService.Name
        $Service.WaitForStatus('Running','00:00:05')

        If($Service.Status -ne 'Running'){
            LogMessage $LogLevel.ErrorLogFileOnly ('[WinRM] Starting WinRM service failed.')
        }
    }

    LogInfo "[WinRM] Listing members of Event Log Readers group"
    $Commands = @(
        "net localgroup `"Event Log Readers`" | Out-File -Append $WinRMLogFolder\Groups.txt",
        "net localgroup WinRMRemoteWMIUsers__ | Out-File -Append $WinRMLogFolder\Groups.txt"
    )
    RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$True

    LogInfo "[WinRM] Finding SID of WinRMRemoteWMIUsers__ group"
    Try{
        $objUser = New-Object System.Security.Principal.NTAccount("WinRMRemoteWMIUsers__") -ErrorAction Stop
        $strSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier]).value
        $objSID = New-Object System.Security.Principal.SecurityIdentifier($strSID) -ErrorAction Stop
        $group = $objSID.Translate( [System.Security.Principal.NTAccount]).Value
        " " | Out-File -Append "$WinRMLogFolder\Groups.txt"
        ($group + " = " + $strSID) | Out-File -Append "$WinRMLogFolder\Groups.txt"
    }Catch{
        LogMessage $LogLevel.ErrorLogFileOnly ("An exception happened in group info")
    }

    LogInfo "[WinRM] Getting locale info"
    "Get-Culture:" | Out-File -FilePath ("$WinRMLogFolder\LanguageInfo.txt") -Append
    Get-Culture | Out-File -FilePath ("$WinRMLogFolder\LanguageInfo.txt") -Append
    "Get-WinSystemLocale:" | Out-File -FilePath ("$WinRMLogFolder\LanguageInfo.txt") -Append
    Get-WinSystemLocale | Out-File -FilePath ("$WinRMLogFolder\LanguageInfo.txt") -Append
    "Get-WinHomeLocation:" | Out-File -FilePath ("$WinRMLogFolder\LanguageInfo.txt") -Append
    Get-WinHomeLocation | Out-File -FilePath ("$WinRMLogFolder\LanguageInfo.txt") -Append
    "Get-WinUILanguageOverride:" | Out-File -FilePath ("$WinRMLogFolder\LanguageInfo.txt") -Append
    Get-WinUILanguageOverride | Out-File -FilePath ("$WinRMLogFolder\LanguageInfo.txt") -Append
    "Get-WinUserLanguageList:" | Out-File -FilePath ("$WinRMLogFolder\LanguageInfo.txt") -Append
    Get-WinUserLanguageList | Out-File -FilePath ("$WinRMLogFolder\LanguageInfo.txt") -Append
    "Get-WinAcceptLanguageFromLanguageListOptOut:" | Out-File -FilePath ("$WinRMLogFolder\LanguageInfo.txt") -Append
    Get-WinAcceptLanguageFromLanguageListOptOut | Out-File -FilePath ("$WinRMLogFolder\LanguageInfo.txt") -Append
    "Get-Get-WinCultureFromLanguageListOptOut:" | Out-File -FilePath ("$WinRMLogFolder\LanguageInfo.txt") -Append
    Get-WinCultureFromLanguageListOptOut | Out-File -FilePath ("$WinRMLogFolder\LanguageInfo.txt") -Append
    "Get-WinDefaultInputMethodOverride:" | Out-File -FilePath ("$WinRMLogFolder\LanguageInfo.txt") -Append
    Get-WinDefaultInputMethodOverride | Out-File -FilePath ("$WinRMLogFolder\LanguageInfo.txt") -Append
    "Get-WinLanguageBarOption:" | Out-File -FilePath ("$WinRMLogFolder\LanguageInfo.txt") -Append
    Get-WinLanguageBarOption | Out-File -FilePath ("$WinRMLogFolder\LanguageInfo.txt") -Append
    
    $PSVersionTable | Out-File -Append "$WinRMLogFolder\PSVersion.txt"

    # Http Proxy
    LogInfo "[WinRM] WinHTTP proxy configuration"
    netsh winhttp show proxy 2>> $ErrorLogFile | Out-File -Append "$WinRMLogFolder\WinHTTP-Proxy.txt"
    "------------------" | Out-File -Append "$WinRMLogFolder\WinHTTP-Proxy.txt"
    "NSLookup WPAD:" | Out-File -Append "$WinRMLogFolder\WinHTTP-Proxy.txt"
    "" | Out-File -Append "$WinRMLogFolder\WinHTTP-Proxy.txt"
    nslookup wpad 2>> $ErrorLogFile | Out-File -Append "$WinRMLogFolder\WinHTTP-Proxy.txt"

    # WinRM Configuration
    LogInfo "[WinRM] Retrieving WinRM configuration"
    Try{
        $config = Get-ChildItem WSMan:\localhost\ -Recurse -ErrorAction Stop
        If(!$config){
            LogMessage $LogLevel.ErrorLogFileOnly ("Cannot connect to localhost, trying with FQDN " + $fqdn)
            Connect-WSMan -ComputerName $fqdn -ErrorAction Stop
            $config = Get-ChildItem WSMan:\$fqdn -Recurse -ErrorAction Stop
            Disconnect-WSMan -ComputerName $fqdn -ErrorAction Stop
        }
    }Catch{
        LogException ("An error happened during getting WinRM configuration") $_ $fLogFileOnly
    }
    
    If($Null -ne $config){
        $config | out-string -Width 500 | Out-File -Append "$WinRMLogFolder\WinRM-config.txt"
    }
    $Commands = @(
         "winrm get winrm/config | Out-File -Append $WinRMLogFolder\WinRM-config.txt"
         "winrm e winrm/config/listener | Out-File -Append $WinRMLogFolder\WinRM-config.txt"
         "winrm enum winrm/config/service/certmapping | Out-File -Append $WinRMLogFolder\WinRM-config.txt"
         "WinRM get 'winrm/config/client' | Out-File -Append $WinRMLogFolder/WinRMconfig-client.txt",
         "WinRM enumerate 'winrm/config/listener' | Out-File -Append $WinRMLogFolder/WinRMconfig-listener.txt"
    )
    RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$True

    # Other commands
    $Commands = @(
        "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentials $WinRMLogFolder\AllowFreshCredentials.reg.txt /y",
        "reg export HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\HTTP $WinRMLogFolder\HTTP.reg.txt /y",
        "reg export `"HKEY_USERS\S-1-5-20\Control Panel\International`" $WinRMLogFolder\InternationalNetworkService.reg.txt",
        "reg query HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN /s  | Out-File -Append $WinRMLogFolder/reg-winrm.txt",
        "netsh advfirewall firewall show rule name=all  | Out-File -Append $WinRMLogFolder\FirewallRules.txt",
        "netstat -anob  | Out-File -Append $WinRMLogFolder\netstat.txt",
        "ipconfig /all  | Out-File -Append $WinRMLogFolder\ipconfig.txt",
        "Get-NetConnectionProfile | Out-File -Append $WinRMLogFolder\NetConnectionProfile.txt",
        "Get-WSManCredSSP | Out-File -Append $WinRMLogFolder\WSManCredSSP.txt",
        "gpresult /h $WinRMLogFolder\gpresult.html",
        "gpresult /r | Out-File -Append $WinRMLogFolder\gpresult.txt"
        "Copy-Item $env:windir\system32\logfiles\HTTPERR\* $WinRMLogFolder -ErrorAction Stop",
        "Copy-Item C:\Windows\system32\drivers\etc\hosts $WinRMLogFolder\hosts.txt -ErrorAction Stop",
        "Copy-Item C:\Windows\system32\drivers\etc\lmhosts $WinRMLogFolder\lmhosts.txt -ErrorAction Stop",
        "reg export HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinRM $WinRMLogFolder\WinRM.reg.txt /y",
        "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN $WinRMLogFolder\WSMAN.reg.txt /y",
        "reg export HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM $WinRMLogFolder\WinRM-Policies.reg.txt /y",
        "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System $WinRMLogFolder\System-Policies.reg.txt /y",
        "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\EventCollector $WinRMLogFolder\EventCollector.reg.txt /y",
        "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\EventForwarding $WinRMLogFolder\EventForwarding.reg.txt /y",
        "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog $WinRMLogFolder\EventLog-Policies.reg.txt /y",
        "reg export HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL $WinRMLogFolder\SCHANNEL.reg.txt /y",
        "reg export HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography $WinRMLogFolder\Cryptography.reg.txt /y",
        "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography $WinRMLogFolder\Cryptography-Policy.reg.txt /y",
        "reg export HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa $WinRMLogFolder\LSA.reg.txt /y",
        "reg export HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\HTTP $WinRMLogFolder\HTTP.reg.txt /y",
        "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentials $WinRMLogFolder\AllowFreshCredentials.reg.txt /y",
        "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ServerManager\ServicingStorage\ServerComponentCache $WinRMLogFolder\ServerComponentCache.reg.txt /y",
        "netsh http show sslcert | Out-File -Append $WinRMLogFolder\netsh-http.txt",
        "netsh http show urlacl | Out-File -Append $WinRMLogFolder\netsh-http.txt",
        "netsh http show servicestate | Out-File -Append $WinRMLogFolder\netsh-http.txt",
        "netsh http show iplisten | Out-File -Append $WinRMLogFolder\netsh-http.txt",
        "setspn -L $env:computername | Out-File -Append $WinRMLogFolder\SPN.txt",
        "setspn -Q HTTP/$env:computername | Out-File -Append $WinRMLogFolder\SPN.txt",
        "setspn -Q HTTP/$fqdn | Out-File -Append $WinRMLogFolder\SPN.txt",
        "setspn -F -Q HTTP/$env:computername | Out-File -Append $WinRMLogFolder\SPN.txt",
        "setspn -F -Q HTTP/$fqdn | Out-File -Append $WinRMLogFolder\SPN.txt",
        "setspn -Q WSMAN/$env:computername | Out-File -Append $WinRMLogFolder\SPN.txt",
        "setspn -Q WSMAN/$fqdn | Out-File -Append $WinRMLogFolder\SPN.txt",
        "setspn -F -Q WSMAN/$env:computername | Out-File -Append $WinRMLogFolder\SPN.txt",
        "setspn -F -Q WSMAN/$fqdn | Out-File -Append $WinRMLogFolder\SPN.txt",
        "Certutil -verifystore -v MY | Out-File -Append $WinRMLogFolder\Certificates-My.txt",
        "Certutil -verifystore -v ROOT | Out-File -Append $WinRMLogFolder\Certificates-Root.txt",
        "Certutil -verifystore -v CA | Out-File -Append $WinRMLogFolder\Certificates-Intermediate.txt"
    )
    RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$True

    If(Test-Path -Path "HKLM:\SOFTWARE\Microsoft\InetStp"){
        $Commands = @(
            "$env:SystemRoot\system32\inetsrv\APPCMD list app | Out-File -Append $WinRMLogFolder\iisconfig.txt",
            "$env:SystemRoot\system32\inetsrv\APPCMD list apppool | Out-File -Append $WinRMLogFolder\iisconfig.txt",
            "$env:SystemRoot\system32\inetsrv\APPCMD list site | Out-File -Append $WinRMLogFolder\iisconfig.txt",
            "$env:SystemRoot\system32\inetsrv\APPCMD list module | Out-File -Append $WinRMLogFolder\iisconfig.txt",
            "$env:SystemRoot\system32\inetsrv\APPCMD list wp | Out-File -Append $WinRMLogFolder\iisconfig.txt",
            "$env:SystemRoot\system32\inetsrv\APPCMD list vdir | Out-File -Append $WinRMLogFolder\iisconfig.txt",
            "$env:SystemRoot\system32\inetsrv\APPCMD list config | Out-File -Append $WinRMLogFolder\iisconfig.txt"
        )
        RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$True
    }Else{
        LogDebug ("[WinRM] IIS is not installed")
    }

    EndFunc $MyInvocation.MyCommand.Name
}


#Function CollectUEX_TaskLog{
Function CollectUEX_SchedLog{
    EnterFunc $MyInvocation.MyCommand.Name
    $LogPrefix = "Task"
    $TaskLogFolder = "$LogFolder\TaskLog$LogSuffix"
    $TaskLogTaskFolder = "$LogFolder\TaskLog$LogSuffix\Windows-Tasks"
    $TaskLogSystem32Folder = "$LogFolder\TaskLog$LogSuffix\System32-Tasks"
    $TaskLogDumpFolder = "$LogFolder\TaskLog$LogSuffix\Process dump"

    Try{
        FwCreateLogFolder $TaskLogFolder
        FwCreateLogFolder $TaskLogTaskFolder
        FwCreateLogFolder $TaskLogSystem32Folder
        FwCreateLogFolder $TaskLogDumpFolder
    }Catch{
        LogException ("Unable to create $TaskLogFolder.") $_
        Return
    }

    # Eventlogs
    $EventLogs = @(
        "System",
        "Application",
        "Microsoft-Windows-TaskScheduler/Maintenance",
        "Microsoft-Windows-TaskScheduler/Operational"
    )
    FwExportEventLog $EventLogs $TaskLogFolder

    $Commands = @(
        "schtasks.exe /query /xml | Out-File -Append $TaskLogFolder\schtasks_query.xml",
        "schtasks.exe /query /fo CSV /v | Out-File -Append $TaskLogFolder\schtasks_query.csv",
        "schtasks.exe /query /v | Out-File -Append $TaskLogFolder\schtasks_query.txt",
        "powercfg /LIST | Out-File -Append $TaskLogFolder\powercfg_list.txt",
        "powercfg /QUERY SCHEME_CURRENT | Out-File -Append $TaskLogFolder\powercfg_query_scheme_current.txt",
        "powercfg /AVAILABLESLEEPSTATES | Out-File -Append $TaskLogFolder\powercfg_availablesleepstates.txt",
        "powercfg /LASTWAKE | Out-File -Append $TaskLogFolder\powercfg_lastwake.txt",
        "powercfg /WAKETIMERS | Out-File -Append $TaskLogFolder\powercfg_waketimers.txt",
        "reg query `"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule`" /s | Out-File $TaskLogFolder\Schedule.reg.txt",
        "sc.exe queryex Schedule | Out-File -Append $TaskLogFolder\ScheduleServiceConfig.txt",
        "sc.exe qc Schedule | Out-File -Append $TaskLogFolder\ScheduleServiceConfig.txt",
        "sc.exe enumdepend Schedule 3000 | Out-File -Append $TaskLogFolder\ScheduleServiceConfig.txt",
        "sc.exe sdshow Schedule | Out-File -Append $TaskLogFolder\ScheduleServiceConfig.txt",
        "Get-ScheduledTask | Out-File -Append $TaskLogFolder\Tasks.txt",
        "Copy-Item C:\Windows\Tasks -Recurse $TaskLogTaskFolder",
        "Copy-Item C:\Windows\System32\Tasks -Recurse $TaskLogSystem32Folder"
    )
    RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$True

    # Process dump for Schedule service
    FwCaptureUserDump "Schedule" $TaskLogDumpFolder -IsService:$True

    EndFunc $MyInvocation.MyCommand.Name
}



Function RunUEX_WinRMDiag {
    EnterFunc $MyInvocation.MyCommand.Name
    $WinRMDiagFolder = "$LogFolder\WinRMLog$LogSuffix\Diag"
    $WinRMDiagFile = "$WinRMDiagFolder\WinRM-Diag.txt"

    Try{
        FwCreateLogFolder $WinRMDiagFolder
    }Catch{
        LogMessage ("Unable to create $WMILogFolder.") $_ 
        Return
    }

    LogInfo ("[WinRM] Checking if WinRM is running")
    $WinRMService = Get-Service | Where-Object {$_.Name -eq 'WinRM'}
    If($Null -ne $WinRMService){

        If($WinRMService.Status -eq 'Stopped'){
            LogDebug ('[WinRM] Starting WinRM service as it is not running.')
            Start-Service $WinRMService.Name
        }

        $Service = Get-Service $WinRMService.Name
        $Service.WaitForStatus('Running','00:00:10')

        If($Service.Status -ne 'Running'){
            LogMessage $LogLevel.ErrorLogFileOnly ('[WinRM] Starting WinRM service failed.')
        }
    }

    $Global:tbCert = New-Object system.Data.DataTable
    $col = New-Object system.Data.DataColumn Store,([string]); $tbCert.Columns.Add($col)
    $col = New-Object system.Data.DataColumn Thumbprint,([string]); $tbCert.Columns.Add($col)
    $col = New-Object system.Data.DataColumn Subject,([string]); $tbCert.Columns.Add($col)
    $col = New-Object system.Data.DataColumn Issuer,([string]); $tbCert.Columns.Add($col)
    $col = New-Object system.Data.DataColumn NotAfter,([DateTime]); $tbCert.Columns.Add($col)
    $col = New-Object system.Data.DataColumn IssuerThumbprint,([string]); $tbCert.Columns.Add($col)
    $col = New-Object system.Data.DataColumn EnhancedKeyUsage,([string]); $tbCert.Columns.Add($col)
    $col = New-Object system.Data.DataColumn SerialNumber,([string]); $tbCert.Columns.Add($col)
    $col = New-Object system.Data.DataColumn SubjectKeyIdentifier,([string]); $tbCert.Columns.Add($col)
    $col = New-Object system.Data.DataColumn AuthorityKeyIdentifier,([string]); $tbCert.Columns.Add($col)
    Write-Diag "[INFO] Retrieving certificates from LocalMachine\My store" $WinRMDiagFile
    FwGetCertStore "My"
    Write-Diag "[INFO] Retrieving certificates from LocalMachine\CA store" $WinRMDiagFile
    FwGetCertStore "CA"
    Write-Diag "[INFO] Retrieving certificates from LocalMachine\Root store" $WinRMDiagFile
    FwGetCertStore "Root"
    Write-Diag "[INFO] Matching issuer thumbprints" $WinRMDiagFile
    $aCert = $Global:tbCert.Select("Store = 'My' or Store = 'CA'")
    foreach ($cert in $aCert) {
      $aIssuer = $Global:tbCert.Select("SubjectKeyIdentifier = '" + ($cert.AuthorityKeyIdentifier).tostring() + "'")
      if ($aIssuer.Count -gt 0) {
        $cert.IssuerThumbprint = ($aIssuer[0].Thumbprint).ToString()
      }
    }
    Write-Diag "[INFO] Exporting certificates.tsv" $WinRMDiagFile
    $Global:tbcert | Export-Csv "$WinRMDiagFolder\certificates.tsv" -noType -Delimiter "`t"

    # Diag start
    
    $OSVer = [environment]::OSVersion.Version.Major + [environment]::OSVersion.Version.Minor * 0.1
    
    $subDom = $false
    $subWG = $false
    $Subscriptions = Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\EventCollector\Subscriptions"
    foreach ($sub in $Subscriptions) {
        Write-Diag ("[INFO] Found subscription " + $sub.PSChildname) $WinRMDiagFile
        $SubProp = ($sub | Get-ItemProperty)
        Write-Diag ("[INFO]   SubscriptionType = " + $SubProp.SubscriptionType + ", ConfigurationMode = " + $SubProp.ConfigurationMode) $WinRMDiagFile
        Write-Diag ("[INFO]   MaxLatencyTime = " + (GetSubVal $sub.PSChildname "MaxLatencyTime") + ", HeartBeatInterval = " + (GetSubVal $sub.PSChildname "HeartBeatInterval")) $WinRMDiagFile
        
        if ($SubProp.Locale) {
            if ($SubProp.Locale -eq "en-US") {
              Write-Diag "[INFO]   The subscription's locale is set to en-US" $WinRMDiagFile
            } else {
              Write-Diag ("[WARNING] The subscription's locale is set to " + $SubProp.Locale) $WinRMDiagFile
            }
        } else {
           Write-Diag "[INFO]   The subscription's locale is not set, the default locale will be used." $WinRMDiagFile
        }
        
        if ($SubProp.AllowedSubjects) {
            $subWG = $true
            Write-Diag "[INFO]   Listed non-domain computers:" $WinRMDiagFile
            $list = $SubProp.AllowedSubjects -split ","
            foreach ($item in $list) {
              Write-Diag ("[INFO]   " + $item) $WinRMDiagFile
            }
        } else {
            Write-Diag "[INFO]   No non-domain computers listed, that's ok if this is not a collector in workgroup environment" $WinRMDiagFile
        }
        
        if ($SubProp.AllowedIssuerCAs) {
            $subWG = $true
            Write-Diag "[INFO]   Listed Issuer CAs:" $WinRMDiagFile
            $list = $SubProp.AllowedIssuerCAs -split ","
            foreach ($item in $list) {
              Write-Diag ("[INFO]   " + $item) $WinRMDiagFile
              ChkCert -cert $item -store "(Store = 'CA' or Store = 'Root')" -descr "Issuer CA"
            }
        } else {
            Write-Diag "[INFO]   No Issuer CAs listed, that's ok if this is not a collector in workgroup environment" $WinRMDiagFile
        }
        
        $RegKey = (($sub.Name).replace("HKEY_LOCAL_MACHINE\","HKLM:\") + "\EventSources")
        if (Test-Path -Path $RegKey) {
            $sources = Get-ChildItem -Path $RegKey
            if ($sources.Count -gt 4000) {
              Write-Diag ("[WARNING] There are " + $sources.Count + " sources for this subscription") $WinRMDiagFile
            } else {
              Write-Diag ("[INFO]   There are " + $sources.Count + " sources for this subscription") $WinRMDiagFile
            }
        } else {
            Write-Diag ("[INFO]   No sources found for the subscription " + $sub.Name) $WinRMDiagFile
        }
    }

    if ($OSVer -gt 6.1) {
      Write-Diag "[INFO] Retrieving machine's IP addresses" $WinRMDiagFile
      $iplist = Get-NetIPAddress
    }

    Write-Diag "[INFO] Browsing listeners" $WinRMDiagFile
    $listeners = Get-ChildItem WSMan:\localhost\Listener
    foreach ($listener in $listeners) {
      Write-Diag ("[INFO] Inspecting listener " + $listener.Name) $WinRMDiagFile
      $prop = Get-ChildItem $listener.PSPath
      foreach ($value in $prop) {
        if ($value.Name -eq "CertificateThumbprint") {
          if ($listener.keys[0].Contains("HTTPS")) {
            Write-Diag "[INFO] Found HTTPS listener" $WinRMDiagFile
            $listenerThumbprint = $value.Value.ToLower()
            Write-Diag "[INFO] Found listener certificate $listenerThumbprint" $WinRMDiagFile
            if ($listenerThumbprint) {
              ChkCert -cert $listenerThumbprint -descr "listener" -store "Store = 'My'"
            }
          }
        }
        if ($value.Name.Contains("ListeningOn")) {
          $ip = ($value.value).ToString()
          Write-Diag "[INFO] Listening on $ip" $WinRMDiagFile
          if ($OSVer -gt 6.1) {
            if (($iplist | Where-Object {$_.IPAddress -eq $ip } | measure-object).Count -eq 0 ) {
              Write-Diag "[ERROR] IP address $ip not found" $WinRMDiagFile
            }
          }
        }
      } 
    } 
    
    $svccert = Get-Item WSMan:\localhost\Service\CertificateThumbprint
    if ($svccert.value ) {
      Write-Diag ("[INFO] The Service Certificate thumbprint is " + $svccert.value) $WinRMDiagFile
      ChkCert -cert $svccert.value -descr "Service" -store "Store = 'My'"
    }
    
    $ipfilter = Get-Item WSMan:\localhost\Service\IPv4Filter
    if ($ipfilter.Value) {
      if ($ipfilter.Value -eq "*") {
        Write-Diag "[INFO] IPv4Filter = *" $WinRMDiagFile
      } else {
        Write-Diag ("[WARNING] IPv4Filter = " + $ipfilter.Value) $WinRMDiagFile
      }
    } else {
      Write-Diag ("[WARNING] IPv4Filter is empty, WinRM will not listen on IPv4") $WinRMDiagFile
    }
    
    $ipfilter = Get-Item WSMan:\localhost\Service\IPv6Filter
    if ($ipfilter.Value) {
      if ($ipfilter.Value -eq "*") {
        Write-Diag "[INFO] IPv6Filter = *" $WinRMDiagFile
      } else {
        Write-Diag ("[WARNING] IPv6Filter = " + $ipfilter.Value) $WinRMDiagFile
      }
    } else {
      Write-Diag ("[WARNING] IPv6Filter is empty, WinRM will not listen on IPv6") $WinRMDiagFile
    }
    
    if (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager") {
      $isForwarder = $True
      $RegKey = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager')
    
      Write-Diag "[INFO] Enumerating SubscriptionManager URLs at HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager" $WinRMDiagFile
      $RegKey.PSObject.Properties | ForEach-Object {
        If($_.Name -notlike '*PS*'){
          Write-Diag ("[INFO] " + $_.Name + " " + $_.Value) $WinRMDiagFile
          $IssuerCA = (FindSep -FindIn $_.Value -Left "IssuerCA=" -Right ",").ToLower()
          if (-not $IssuerCA) {
            $IssuerCA = (FindSep -FindIn $_.Value -Left "IssuerCA=" -Right "").ToLower()
          }
          if ($IssuerCA) {
            if ("0123456789abcdef".Contains($IssuerCA[0])) {
              Write-Diag ("[INFO] Found issuer CA certificate thumbprint " + $IssuerCA) $WinRMDiagFile
              $aCert = $tbCert.Select("Thumbprint = '" + $IssuerCA + "' and (Store = 'CA' or Store = 'Root')")
              if ($aCert.Count -eq 0) {
                Write-Diag "[ERROR] The Issuer CA certificate was not found in CA or Root stores" $WinRMDiagFile
              } else {
                Write-Diag ("[INFO] Issuer CA certificate found in store " + $aCert[0].Store + ", subject = " + $aCert[0].Subject) $WinRMDiagFile
                if (($aCert[0].NotAfter) -gt (Get-Date)) {
                  Write-Diag ("[INFO] The Issuer CA certificate will expire on " + $aCert[0].NotAfter.ToString("yyyyMMdd HH:mm:ss.fff") ) $WinRMDiagFile
                } else {
                  Write-Diag ("[ERROR] The Issuer CA certificate expired on " + $aCert[0].NotAfter.ToString("yyyyMMdd HH:mm:ss.fff") ) $WinRMDiagFile
                }
              }
    
              $aCliCert = $tbCert.Select("IssuerThumbprint = '" + $IssuerCA + "' and Store = 'My'")
              if ($aCliCert.Count -eq 0) {
                Write-Diag "[ERROR] Cannot find any certificate issued by this Issuer CA" $WinRMDiagFile
              } else {
                if ($PSVersionTable.psversion.ToString() -ge "3.0") {
                  Write-Diag "[INFO] Listing available client certificates from this IssuerCA" $WinRMDiagFile
                  $num = 0
                  foreach ($cert in $aCliCert) {
                    if ($cert.EnhancedKeyUsage.Contains("Client Authentication")) {
                      Write-Diag ("[INFO]   Found client certificate " + $cert.Thumbprint + " " + $cert.Subject) $WinRMDiagFile
                      if (($Cert.NotAfter) -gt (Get-Date)) {
                        Write-Diag ("[INFO]   The client certificate will expire on " + $cert.NotAfter.ToString("yyyyMMdd HH:mm:ss.fff") ) $WinRMDiagFile
                      } else {
                        Write-Diag ("[ERROR]   The client certificate expired on " + $cert.NotAfter.ToString("yyyyMMdd HH:mm:ss.fff") ) $WinRMDiagFile
                      }
                      $certobj = Get-Item ("CERT:\Localmachine\My\" + $cert.Thumbprint)
                      $keypath = [io.path]::combine("$env:ProgramData\microsoft\crypto\rsa\machinekeys", $certobj.privatekey.cspkeycontainerinfo.uniquekeycontainername)
                      if ([io.file]::exists($keypath)) {
                        $acl = ((get-acl -path $keypath).Access | Where-Object {$_.IdentityReference -eq "NT AUTHORITY\NETWORK SERVICE"})
                        if ($acl) {
                          $rights = $acl.FileSystemRights.ToString()
                          if ($rights.contains("Read") -or $rights.contains("FullControl") ) {
                            Write-Diag ("[INFO]   The NETWORK SERVICE account has permissions on the private key of this certificate: " + $rights) $WinRMDiagFile
                          } else {
                            Write-Diag ("[ERROR]  Incorrect permissions for the NETWORK SERVICE on the private key of this certificate: " + $rights) $WinRMDiagFile
                          }
                        } else {
                          Write-Diag "[ERROR]  Missing permissions for the NETWORK SERVICE account on the private key of this certificate" $WinRMDiagFile
                        }
                      } else {
                        Write-Diag "[ERROR]  Cannot find the private key" $WinRMDiagFile
                      } 
                      $num++
                    }
                  }
                  if ($num -eq 0) {
                    Write-Diag "[ERROR] Cannot find any client certificate issued by this Issuer CA" $WinRMDiagFile
                  } elseif ($num -gt 1) {
                    Write-Diag "[WARNING] More than one client certificate issued by this Issuer CA, the first certificate will be used by WinRM" $WinRMDiagFile
                  }
                }
              }
            } else {
             Write-Diag "[ERROR] Invalid character for the IssuerCA certificate in the SubscriptionManager URL" $WinRMDiagFile
            }
          }
        } 
      }
    } else {
      $isForwarder = $false
      Write-Diag "[INFO] No SubscriptionManager URL configured. It's ok if this machine is not supposed to forward events." $WinRMDiagFile
    }
    
    if ((Get-CimInstance -Class Win32_ComputerSystem).PartOfDomain) {
      $search = New-Object DirectoryServices.DirectorySearcher([ADSI]"GC://$env:USERDNSDOMAIN") # The SPN is searched in the forest connecting to a Global catalog
    
      $SPNReg = ""
      $SPN = "HTTP/" + $env:COMPUTERNAME
      Write-Diag ("[INFO] Searching for the SPN $SPN") $WinRMDiagFile
      $search.filter = "(servicePrincipalName=$SPN)"
      $results = $search.Findall()
      if ($results.count -gt 0) {
        foreach ($result in $results) {
          Write-Diag ("[INFO] The SPN HTTP/$env:COMPUTERNAME is registered for DNS name = " + $result.properties.dnshostname + ", DN = " + $result.properties.distinguishedname + ", Category = " + $result.properties.objectcategory) $WinRMDiagFile
          if ($result.properties.objectcategory[0].Contains("Computer")) {
            if (-not $result.properties.dnshostname[0].Contains($env:COMPUTERNAME)) {
              Write-Diag ("[ERROR] The The SPN $SPN is registered for different DNS host name: " + $result.properties.dnshostname[0]) $WinRMDiagFile
              $SPNReg = "OTHER"
            }
          } else {
            Write-Diag "[ERROR] The The SPN $SPN is NOT registered for a computer account" $WinRMDiagFile
            $SPNReg = "OTHER"
          }
        }
        if ($results.count -gt 1) {
          Write-Diag "[ERROR] The The SPN $SPN is duplicate" $WinRMDiagFile
        }
      } else {
        Write-Diag "[INFO] The The SPN $SPN was not found. That's ok, the SPN HOST/$env:COMPUTERNAME will be used" $WinRMDiagFile
      }
    
      $SPN = "HTTP/" + $env:COMPUTERNAME + ":5985"
      Write-Diag ("[INFO] Searching for the SPN $SPN") $WinRMDiagFile
      $search.filter = "(servicePrincipalName=$SPN)"
      $results = $search.Findall()
      if ($results.count -gt 0) {
        foreach ($result in $results) {
          Write-Diag ("[INFO] The SPN HTTP/$env:COMPUTERNAME is registered for DNS name = " + $result.properties.dnshostname + ", DN = " + $result.properties.distinguishedname + ", Category = " + $result.properties.objectcategory) $WinRMDiagFile
          if ($result.properties.objectcategory[0].Contains("Computer")) {
            if (-not $result.properties.dnshostname[0].Contains($env:COMPUTERNAME)) {
              Write-Diag ("[ERROR] The The SPN $SPN is registered for different DNS host name: " + $result.properties.dnshostname[0]) $WinRMDiagFile
            }
          } else {
            Write-Diag "[ERROR] The The SPN $SPN is NOT registered for a computer account" $WinRMDiagFile
          }
        }
        if ($results.count -gt 1) {
          Write-Diag "[ERROR] The The SPN $SPN is duplicate" $WinRMDiagFile
        }
      } else {
        if ($SPNReg -eq "OTHER") {
          Write-Diag "[WARNING] The The SPN $SPN was not found. It is required to accept WinRM connections since the HTTP/$env:COMPUTERNAME is reqistered to another name" $WinRMDiagFile
        }
      }
    
      Write-Diag "[INFO] Checking the WinRMRemoteWMIUsers__ group" $WinRMDiagFile
      $search = New-Object DirectoryServices.DirectorySearcher([ADSI]"")  # This is a Domain local group, therefore we need to collect to a non-global catalog
      $search.filter = "(samaccountname=WinRMRemoteWMIUsers__)"
      $results = $search.Findall()
      if ($results.count -gt 0) {
        Write-Diag ("[INFO] Found " + $results.Properties.distinguishedname) $WinRMDiagFile
        if ($results.Properties.grouptype -eq  -2147483644) {
          Write-Diag "[INFO] WinRMRemoteWMIUsers__ is a Domain local group" $WinRMDiagFile
        } elseif ($results.Properties.grouptype -eq -2147483646) {
          Write-Diag "[WARNING] WinRMRemoteWMIUsers__ is a Global group" $WinRMDiagFile
        } elseif ($results.Properties.grouptype -eq -2147483640) {
          Write-Diag "[WARNING] WinRMRemoteWMIUsers__ is a Universal group" $WinRMDiagFile
        }
        if (Get-CimInstance -query "select * from Win32_Group where Name = 'WinRMRemoteWMIUsers__' and Domain = '$env:computername'") {
          Write-Diag "[INFO] The group WinRMRemoteWMIUsers__ is also present as machine local group" $WinRMDiagFile
        }
      } else {
        Write-Diag "[ERROR] The WinRMRemoteWMIUsers__ was not found in the domain"  $WinRMDiagFile
        if (Get-CimInstance -query "select * from Win32_Group where Name = 'WinRMRemoteWMIUsers__' and Domain = '$env:computername'") {
          Write-Diag "[INFO] The group WinRMRemoteWMIUsers__ is present as machine local group" $WinRMDiagFile
        } else {
          Write-Diag "[ERROR] The group WinRMRemoteWMIUsers__ is not even present as machine local group" $WinRMDiagFile
        }
      }
      if ((Get-ChildItem WSMan:\localhost\Service\Auth\Kerberos).value -eq "true") {
        Write-Diag "[INFO] Kerberos authentication is enabled for the service" $WinRMDiagFile
      }  else {
        Write-Diag "[WARNING] Kerberos authentication is disabled for the service" $WinRMDiagFile
      }
    } else {
      Write-Diag "[INFO] The machine is not joined to a domain" $WinRMDiagFile
      if (Get-CimInstance -query "select * from Win32_Group where Name = 'WinRMRemoteWMIUsers__' and Domain = '$env:computername'") {
        Write-Diag "[INFO] The group WinRMRemoteWMIUsers__ is present as machine local group" $WinRMDiagFile
      } else {
        Write-Diag "[ERROR] The group WinRMRemoteWMIUsers__ is not present as machine local group" $WinRMDiagFile
      }
      if ((Get-ChildItem WSMan:\localhost\Service\Auth\Certificate).value -eq "false") {
        Write-Diag "[WARNING] Certificate authentication is disabled for the service" $WinRMDiagFile
      }  else {
        Write-Diag "[INFO] Certificate authentication is enabled for the service" $WinRMDiagFile
      }
    }
    
    $iplisten = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters" | Select-Object -ExpandProperty "ListenOnlyList" -ErrorAction SilentlyContinue)
    if ($iplisten) {
      Write-Diag ("[WARNING] The IPLISTEN list is not empty, the listed addresses are " + $iplisten) $WinRMDiagFile
    } else {
      Write-Diag "[INFO] The IPLISTEN list is empty. That's ok: WinRM will listen on all IP addresses" $WinRMDiagFile
    }
    
    $binval = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" -Name WinHttpSettings).WinHttPSettings            
    $proxylength = $binval[12]            
    if ($proxylength -gt 0) {
      $proxy = -join ($binval[(12+3+1)..(12+3+1+$proxylength-1)] | ForEach-Object {([char]$_)})            
      Write-Diag ("[WARNING] A NETSH WINHTTP proxy is configured: " + $proxy) $WinRMDiagFile
      $bypasslength = $binval[(12+3+1+$proxylength)]            
      if ($bypasslength -gt 0) {            
        $bypasslist = -join ($binval[(12+3+1+$proxylength+3+1)..(12+3+1+$proxylength+3+1+$bypasslength)] | ForEach-Object {([char]$_)})            
        Write-Diag ("[WARNING] Bypass list: " + $bypasslist) $WinRMDiagFile
       } else {            
        Write-Diag "[WARNING] No bypass list is configured" $WinRMDiagFile
      }            
      Write-Diag "[WARNING] WinRM does not work very well through proxies, make sure that the target machine is in the bypass list or remove the proxy" $WinRMDiagFile
    } else {
      Write-Diag "[INFO] No NETSH WINHTTP proxy is configured" $WinRMDiagFile
    }
    
    $th = (get-item WSMan:\localhost\Client\TrustedHosts).value
    if ($th) {
      Write-Diag ("[INFO] TrustedHosts contains: $th") $WinRMDiagFile
    } else {
      Write-Diag ("[INFO] TrustedHosts is not configured, it's ok it this machine is not supposed to connect to other machines using NTLM") $WinRMDiagFile
    }
    
    $psver = $PSVersionTable.PSVersion.Major.ToString() + $PSVersionTable.PSVersion.Minor.ToString()
    if ($psver -eq "50") {
      Write-Diag ("[WARNING] Windows Management Framework version " + $PSVersionTable.PSVersion.ToString() + " is no longer supported") $WinRMDiagFile
    } else { 
      Write-Diag ("[INFO] Windows Management Framework version is " + $PSVersionTable.PSVersion.ToString() ) $WinRMDiagFile
    }
    
    $clientcert = Get-ChildItem WSMan:\localhost\ClientCertificate
    if ($clientcert.Count -gt 0) {
      Write-Diag "[INFO] Client certificate mappings" $WinRMDiagFile
      foreach ($certmap in $clientcert) {
        Write-Diag ("[INFO] Certificate mapping " + $certmap.Name) $WinRMDiagFile
        $prop = Get-ChildItem $certmap.PSPath
        foreach ($value in $prop) {
          Write-Diag ("[INFO]   " + $value.Name + " " + $value.Value) $WinRMDiagFile
          if ($value.Name -eq "Issuer") {
            ChkCert -cert $value.Value -descr "mapping" -store "(Store = 'Root' or Store = 'CA')"
          } elseif ($value.Name -eq "UserName") {
            $usr = Get-CimInstance -class Win32_UserAccount | Where-Object {$_.Name -eq $value.value}
            if ($usr) {
              if ($usr.Disabled) {
                Write-Diag ("[ERROR]    The local user account " + $value.value + " is disabled") $WinRMDiagFile
              } else {
                Write-Diag ("[INFO]     The local user account " + $value.value + " is enabled") $WinRMDiagFile
              }
            } else {
              Write-Diag ("[ERROR]    The local user account " + $value.value + " does not exist") $WinRMDiagFile
            }
          } elseif ($value.Name -eq "Subject") {
            if ($value.Value[0] -eq '"') {
              Write-Diag "[ERROR]    The subject does not have to be included in double quotes" $WinRMDiagFile
            }
          }
        }
      }
    } else {
      if ($subWG) {
        Write-Diag "[ERROR] No client certificate mapping configured" $WinRMDiagFile
      }
    }
    
    $aCert = $tbCert.Select("Store = 'Root' and Subject <> Issuer")
    if ($aCert.Count -gt 0) {
      Write-Diag "[ERROR] Found for non-Root certificates in the Root store" $WinRMDiagFile
      foreach ($cert in $acert) {
        Write-Diag ("[ERROR]  Misplaced certificate " + $cert.Subject) $WinRMDiagFile
      }
    }
    
    if ($isForwarder) {
      $evtLogReaders = (Get-CimInstance -Query ("Associators of {Win32_Group.Domain='" + $env:COMPUTERNAME + "',Name='Event Log Readers'} where Role=GroupComponent") | Where-Object {$_.Name -eq "NETWORK SERVICE"} | Measure-Object)
      if ($evtLogReaders.Count -gt 0) {
        Write-Diag "[INFO] The NETWORK SERVICE account is member of the Event Log Readers group" $WinRMDiagFile
      } else {
        Write-Diag "[WARNING] The NETWORK SERVICE account is NOT member of the Event Log Readers group, the events in the Security log cannot be forwarded" $WinRMDiagFile
      }
    }
    
    $fwrules = (Get-NetFirewallPortFilter -Protocol TCP | Where-Object { $_.localport -eq 986} | Get-NetFirewallRule)
    if ($fwrules.count -eq 0) {
      Write-Diag "[INFO] No firewall rule for port 5986" $WinRMDiagFile
    } else {
      Write-Diag "[INFO] Found firewall rule for port 5986" $WinRMDiagFile
    }

    $dir = $env:windir + "\system32\logfiles\HTTPERR"
    if (Test-Path -path $dir) {
      $httperrfiles = Get-ChildItem -path ($dir)
      if ($httperrfiles.Count -gt 100) {
        Write-Diag ("[WARNING] There are " + $httperrfiles.Count + " files in the folder " + $dir) $WinRMDiagFile
      } else {
       Write-Diag ("[INFO] There are " + $httperrfiles.Count + " files in the folder " + $dir) $WinRMDiagFile
      }
      $size = 0 
      foreach ($file in $httperrfiles) {
        $size += $file.Length
      }
      $size = [System.Math]::Ceiling($size / 1024 / 1024) # Convert to MB
      if ($size -gt 100) {
        Write-Diag ("[WARNING] The folder " + $dir + " is using " + $size.ToString() + " MB of disk space") $WinRMDiagFile
      } else {
        Write-Diag ("[INFO] The folder " + $dir + " is using " + $size.ToString() + " MB of disk space") $WinRMDiagFile
      }
    }
    EndFunc $MyInvocation.MyCommand.Name
}




# SIG # Begin signature block
# MIInzQYJKoZIhvcNAQcCoIInvjCCJ7oCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAQ6R8qKTcjFh2T
# y93cgph+XZw+rtjUog+Wx0mt7hMlBqCCDYEwggX/MIID56ADAgECAhMzAAACzI61
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
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgWyYb2bRL
# vL7tvSaHScftsy/NZsmHMZYRCq7L0RbmnakwQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQBIL7NgbRJ6cwNDAtXuzgbta6cdzfnxim2lQQxyQo5H
# F/ecmU62F6FwL0VCa9iLRvtUqQtTMt/NRc1P/xNyRqjxM35VIc9IweM5dWH+mv3P
# lBqr9aUmS2nhnoEAh51PXv0l/kYuzineB683u/TVh93xI2lfqaTA6G5tEUNAv42m
# twT4N7bvwUnt0mfvTX0QE21m/m8Kt6zX9awRX5v9oYKbIPXRfzc2Hps6sLAUy/6r
# 0eeGbpPpa+bduo2ic6TT/iHR4OFUPYNdBheJg7DHeJEu6sqglEmJPvQ4iCv9eRIc
# 9CTXUwTw7M/virSpQJLWetkH5NWLD+RGKUCjET9nJ83MoYIXLDCCFygGCisGAQQB
# gjcDAwExghcYMIIXFAYJKoZIhvcNAQcCoIIXBTCCFwECAQMxDzANBglghkgBZQME
# AgEFADCCAVkGCyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEIH5uT0fbngjiSq4eFb5l18Fs9gMqyfP9mYXr5O48
# dv02AgZjT+tCunIYEzIwMjIxMDI2MTQyOTU3LjA4OVowBIACAfSggdikgdUwgdIx
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
# MC8GCSqGSIb3DQEJBDEiBCBqPAd2fBZugO9+RYO9uOZpzLikG2yb3ITj5U6TQFKj
# jjCB+gYLKoZIhvcNAQkQAi8xgeowgecwgeQwgb0EIIahM9UqENIHtkbTMlBlQzaO
# T+WXXMkaHoo6GfvqT79CMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENB
# IDIwMTACEzMAAAGz/iXOKRsbihwAAQAAAbMwIgQgDiaL4TziB9qFiVntb0DoyY+P
# NeWGSoKV6FVwY5ZMJacwDQYJKoZIhvcNAQELBQAEggIAnkYcvp+An5HjY646LSTq
# 1UK6MvDyV6vnqsPIW69So1jQN9BHc5h+H7vfRChUjbplLzDERRu4PJ73fIY7uR6d
# eU+5NCCcIpLU1uLAziD+0Bi48RzX84TPnko96sEIg/I+rTkLuWK3b1hO51Uuqe4n
# 7k1git8d1KL7Hq/5Ao1rztSAYhN6ghz2iFk9UuUbMQ5v5QwRgw7sF0H0xOrWrxs2
# /DVtl+iV4kabEWXBO3ZGuJPEOKnRutdt8E3OqR8wV07p3VhQoIYwFy9XMFByHN/P
# FqjLv3OAma96gNGa7BPG7TG2aYJdw0Wr/4+IvshwSJ70YrPXW93Shu9KYHxeV943
# RVVLEQi62pTIjgTfPszR+FpFxFd/iSLqcoxbEXbMD9hGKCaz9UcQvQki6leM4jjs
# HokSH93PJ1OAaMGBq61l+YUiWYrxTTjr2001aVDX9TV+gElNTz9yxAYMksrQSNwF
# QUtcxhiYurdL/vAkDbZxUlA7wMAmg/Cvt2pDRvLjIYthvv/36cXq3/cJLiy3UTAI
# 20k5qgGMJdP7SHU+Bcp5YpU0d5LUsCBV4wz3mIsVWyCAMpq7XOqPIGyH4pghpfha
# yDBLdT2hRhdy2fRQ8o5w5kOfxf2aa1I1nxk5iLuXJbdoCx5NBhTKq7KfwCtWE4Rc
# ABtsIurW13KGiLDsz1Zz3BI=
# SIG # End signature block
