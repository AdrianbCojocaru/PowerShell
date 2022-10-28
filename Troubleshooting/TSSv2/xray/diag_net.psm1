# diag_net.ps1
# Created by tdimli
# March 2020
#
# Diagnostic functions for NET area

#Import-Module -Name .\diag_api.psm1 -Force

# version
$NET_version = "1.0.221019.0"

# Area and Area/Component arrays
$NET = @("BranchCache", "DAsrv", "DhcpSrv", "DNScli", "DNSsrv", "Firewall", "HypHost", "NCSI", "NetIO", "Proxy", "rpc", "srv", "VPN", "WFP", "WLAN") #"802Dot1x", "Auth", "BITS", "Container", "CSC", "DAcli", "DFScli", "DFSsrv", "DHCPcli", "General", "HypVM", "IIS", "IPAM", "MsCluster", "MBAM", "MBN", "Miracast", "NCSI", "NFScli", "NFSsrv", "NLB", "NPS", "RAS", "RDMA", "RDScli", "RDSsrv" "SDN" "SdnNC" "SQLtrace" "SBSL" "UNChard" "Winsock" "WIP" "WNV" "Workfolders"

#Component/Diagnostic Function arrays
#$802dot1x = @("net_802dot1x_KB4556307")
$branchcache = @("net_branchcache_KB4565457")
$dasrv = @("net_dasrv_KB4504598")
$dhcpsrv = @("net_dhcpsrv_KB4503857")
$dnscli = @("net_dnscli_KB4562541", "net_dnscli_KB4617560")
$dnssrv = @("net_dnssrv_KB4561750", "net_dnssrv_KB4569509")
$firewall = @("net_firewall_KB4561854")
$hyphost = @("net_hyphost_KB4562593")
$ncsi = @("net_vpn_KB4550202", "net_proxy_KB4569506", "net_ncsi_KB4648334")
$netio = @("net_netio_KB4563820")
$proxy = @("net_proxy_KB4569506")
$rpc = @("net_rpc_KB2506972")
$srv = @("net_srv_KB4562940", "net_srv_KB4612362")
$wfp = @("net_netio_KB4563820")
$vpn = @("net_vpn_KB4553295", "net_vpn_KB4550202", "net_dnscli_KB4562541", "net_proxy_KB4569506")
$wlan = @("net_wlan_KB4557342")

# begin: diagnostic functions

#region 802dot1x
#region net_802dot1x_KB4556307
<# 
Component: 802dot1x
Checks for:
 A post-release issue starting with Feb 2020 updates
 Resolved in 2020.4B and later
 Network indication is skipped when a 802.1x re-auth occurs.
 If account-based VLANs are used, then this may cause connectivity issues
Created by: tdimli
#>
function net_802dot1x_KB4556307
{
    param(
        [Parameter(Mandatory=$true,
        Position=0)]
        [Boolean]
        $offline
    )

    $issueMsg = "
Following 802.1x network adapter (wired or wireless) is in connected state
but has no connectivity:

{0}

You might be hitting an issue affecting wired 802.1x adapters when user logon
triggers a change of VLAN.

Resolution:
Please install following Windows Update (or a later one) to resolve 
this issue:

April 14, 2020—KB4549951 (OS Builds 18362.778 and 18363.778)
https://support.microsoft.com/help/4549951/windows-10-update-kb4549951

 - Addresses an issue that prevents a wired network interface from obtaining a
 new Dynamic Host Configuration Protocol (DHCP) IP address on new subnets and 
 virtual LANs (VLAN) after wired 802.1x re-authentication. The issue occurs if
 you use VLANs that are based on accounts and a VLAN change occurs after a user
 signs in.
"
    # updates (oldest update first), which when installed, may lead to this issue
    $effectingUpdates = @("KB4535996","KB4540673","KB4551762","KB4541335","KB4554364")
    # updates (oldest update first), which when installed, resolve this issue
    $resolvingUpdates = @("KB4549951","KB4550945", "KB4556799")

    if($offline) {
        LogWrite "Cannot run offline, skipping"
        return $RETURNCODE_SKIPPED
    }

    # issue only affects Win10 1903 or later, skip if earlier OS
    $curBuild = [Convert]::ToUInt32($wmi_Win32_OperatingSystem.BuildNumber)
    $reqBuild = 18362
    if ($curBuild -lt $reqBuild ) {
        LogWrite "OS version $($wmi_Win32_OperatingSystem.Version) not affected, skipping"
        return $RETURNCODE_SKIPPED
    }

    # Look for the issue
    $services = Get-Service -Name "dot3svc" -ErrorAction Ignore

    # issue only occurs with Wired Autoconfig, skip if it's not running
    if(($services.Count -eq 0) -or ($services.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running)) {
        # dot3svc (Wired AutoConfig) not running, nothing to check
        LogWrite "Wired AutoConfig (dot3svc) service is not running, nothing to check, skipping"
        return $RETURNCODE_SKIPPED
    }

    # dot3svc (Wired AutoConfig) is running
    try {
        $hotfixes = (Get-HotFix | Sort-Object -Property InstalledOn -Descending)
        foreach($hotfix in $hotfixes) {
            # look if any of the resolving updates that resolve this issue are installed
            if($resolvingUpdates.Contains($hotfix.HotFixID)) {
                LogWrite ("A resolving update ({0}) is installed!" -f $hotfix.HotFixID)
                break
            }
            # look if any of the effecting updates are installed
            if($effectingUpdates.Contains($hotfix.HotFixID)) {
                LogWrite ("An affected update ({0}) is installed!" -f $hotfix.HotFixID)
                # effecting update(s) installed, check for issue
                $netadapters = Get-NetAdapter
                foreach($netadapter in $netadapters) {
                    if(($netadapter.MediaConnectState -eq 1) -and ($netadapter.MediaType -eq "802.3")) { 
                        # adapter in connected state, test connectivity
                        LogWrite ("Testing adapter [{0}] for issue..." -f $netadapter.Name)
                        $netipconfig = Get-NetIPConfiguration -InterfaceIndex $netadapter.ifIndex
                        # has IP address?
                        if($netipconfig.IPv4Address.Count -gt 0) {
                            LogWrite "Pinging default gateway..."
                            $result = Test-Connection -ComputerName $netipconfig.IPv4DefaultGateway.NextHop -Count 1 -Quiet 
                            LogWrite ("Test-Connection returned: {0}" -f $result)
                            if($result -eq $false) {
                                # try again with ping count=4 to avoid false positives
                                $result = Test-Connection -ComputerName $netipconfig.IPv4DefaultGateway.NextHop -Count 4 -Quiet 
                                LogWrite ("Test-Connection (second try) returned: {0}" -f $result)
                                if($result -eq $false) {
                                    # Issue present
                                    $adapterInfo = "`tName: " + $netadapter.Name + ", IP Address: " + $netipconfig.IPv4Address
                                    $issueMsg = [string]::Format($issueMsg, $adapterInfo)
                                    ReportIssue $issueMsg $ISSUETYPE_ERROR #$effectingUpdates $resolvingUpdates
                                    # reporting one instance of the issue is sufficient
                                    break
                                }
                            }
                        }
                    }
                }
                # run the test once
                break
            }
        }
    }
    catch {
        LogWrite "Failed - exiting! (Error: $_)"
        return $RETURNCODE_FAILED
    }

    return $RETURNCODE_SUCCESS
}
#endregion net_802Dot1x_KB4556307
#endregion 802dot1x

#region branchcache
#region net_branchcache_KB4565457
<# 
Component: BranchCache
Checks for:
 An open issue for systems that have configured BranchCache
 If the nummber of BranchCache *.dat files exceeds 1024, then this may cause not shrinking BC issues when it exceeds 180% of configured size
Created by: waltere
#>
function net_branchcache_KB4565457
{
    param(
        [Parameter(Mandatory=$true,
        Position=0)]
        [Boolean]
        $offline
    )

    $issueMsg = "
This computer appears to be affected by a known issue:
BranchCache may fail to shrink cache size (CurrentSizeOnDiskAsNumberOfBytes) if 
the number of *.dat files exceeds 1024 in any PeerDistRepub subfolder, e.g.:
 C:\Windows\ServiceProfiles\NetworkService\AppData\Local\PeerDistRepub\Store\0\*.dat
or 
the total number of *.dat files exceeds 1024 AND 
CurrentSizeOnDiskAsNumberOfBytes breaches the 180% limit of configured MaxCacheSizeAsNumberOfBytes
The CurrentSizeOnDiskAsNumberOfBytes will never decrease as expected.

Note: This might not be directly related to the issue you are troubleshooting.

Indicators of this issue:
 - Number of *.dat files is higher than 1024 
 - CurrentSizeOnDiskAsNumberOfBytes exceeds 1.8 * MaxCacheSizeAsNumberOfBytes
 
Current Branch DataCache usage:
`t MaxCacheSizeAsPercentageOfDiskVolume : {0}
`t MaxCacheSizeAsNumberOfBytes          : {1}
`t CurrentSizeOnDiskAsNumberOfBytes     : {2} ( = {8} % of configured size)
`t CurrentActiveCacheSize               : {3}
`t Total number of *.dat files          : {4}
`t Number of *.dat files in subfolder   : {5} in Folder {6}

{7}

Resolution:
If you need to free the cache, following PowerShell cmdlet can be used to 
delete all data in all cache files:
 Clear-BCCache
"

    if($offline) {
        LogWrite "Cannot run offline, skipping"
        return $RETURNCODE_SKIPPED
    }

    # Look for the issue
	try	{
	    $curBuild = [Convert]::ToUInt32($wmi_Win32_OperatingSystem.BuildNumber)
        $minBuild = 10000
        if ($curBuild -lt $minBuild ) {
            LogWrite "OS version $($wmi_Win32_OperatingSystem.Version) not affected, skipping"
            return $RETURNCODE_SKIPPED
        }

        $bcs = (Get-BCStatus -ErrorAction Ignore)
        if ($bcs -eq $null) {
            LogWrite "Branchcache not installed, skipping"
            return $RETURNCODE_SKIPPED
        }

        if (!$bcs.BranchCacheIsEnabled) {
            LogWrite "Branchcache not enabled, skipping"
            return $RETURNCODE_SKIPPED
        }

        $bcd = (Get-BCDataCache -ErrorAction Ignore)
        if ($bcd -eq $null) {
            LogWrite "Get-BCDataCache failed, skipping"
            return $RETURNCODE_SKIPPED
        }

		$MaxCacheSizeAsPercentageOfDiskVolume = $bcd.MaxCacheSizeAsPercentageOfDiskVolume
		$MaxCacheSizeAsNumberOfBytes = $bcd.MaxCacheSizeAsNumberOfBytes
		$CurrentSizeOnDiskAsNumberOfBytes = $bcd.CurrentSizeOnDiskAsNumberOfBytes
		$CurrentActiveCacheSize = $bcd.CurrentActiveCacheSize * 100 
		$TotNrOfDatFiles  = (Get-ChildItem $ENV:Windir\ServiceProfiles\NetworkService\AppData\Local\PeerDistRepub\Store\0\*.dat -Recurse -ErrorAction Ignore).Count
		$BCDiskUsageInPercent = [math]::Round($CurrentSizeOnDiskAsNumberOfBytes / $MaxCacheSizeAsNumberOfBytes * 100)
		$MaxFilesPerFolder = 1024	# no subfolder should contain more than 1024 *.dat files

		# PeerDistRepubFT: Table of  Directory  | Count | LastWriteTime
		foreach ($file in (Get-ChildItem "$ENV:Windir\ServiceProfiles\NetworkService\AppData\Local\PeerDistRepub\Store\0\" -Directory -ErrorAction Ignore))
        {
            $DatFilesCount = (Get-ChildItem $File.FullName -Recurse -File -ErrorAction Ignore).Count
            $DatFilesFolderName = $($File.FullName)
            if ($DatFilesCount -gt $MaxFilesPerFolder ) {
                break
            }
			$PeerDistRepubFT = [pscustomobject] @{
				'Directory' = $File.FullName
				'Count' = (Get-ChildItem $File.FullName -Recurse -ErrorAction Ignore).Count
				'LastWriteTime' = $File.LastWriteTime
			}
		}
		$Breach180percent = $MaxCacheSizeAsNumberOfBytes * 1.8
		# Issue present if one subfolder exceeds $DatFilesCount -gt 1024
		if (($DatFilesCount -ge $MaxFilesPerFolder ) -or ($CurrentSizeOnDiskAsNumberOfBytes -gt $Breach180percent)) {
			# Issue detected
			$issueMsg = [string]::Format($issueMsg, $MaxCacheSizeAsPercentageOfDiskVolume, $MaxCacheSizeAsNumberOfBytes, $CurrentSizeOnDiskAsNumberOfBytes, $CurrentActiveCacheSize, $TotNrOfDatFiles, $DatFilesCount, $DatFilesFolderName, $PeerDistRepubFT, $BCDiskUsageInPercent)
			ReportIssue $issueMsg $ISSUETYPE_WARNING
		}
	}
	catch {
		LogWrite "Failed - exiting! (Error: $_)"
        return $RETURNCODE_FAILED
    }

    return $RETURNCODE_SUCCESS
}
#endregion net_branchcache_KB4565457
#endregion branchcache

#region dasrv
#region net_dasrv_KB4504598
<# 
Component: dasrv
Checks for:
 DA non-paged pool memory leak, tag NDnd
Created by: tdimli
#>
function net_dasrv_KB4504598
{
    param(
        [Parameter(Mandatory=$true,
        Position=0)]
        [Boolean]
        $offlin
    )

    $issueMsg = "
Considerable amount of non-paged pool memory is allocated with pool tag NDnd:

Tag  Bytes
NDnd {0}

On Direct Access Servers this may be caused by a known memory leak which 
can cause performance degradation due to reduced amount of memory left 
available. If the leak grows too large, it can also deplete the non-paged 
pool memory and may cause the server to crash.

Resolution
This issue is fixed for WS2016 with January 23, 2020 update KB4534307 :
  - Addresses an issue that might cause Direct Access servers to use a large 
  amount of non-paged pool memory ( pooltag: NDnd ). 

Issue is not present in WS2019 and later versions of Windows Servers.

For 2012R2, the solution is to upgrade to a later version where this issue does 
not occur.

Following workarounds can be used for 2012R2 until upgrade can be performed:
  1. Monitor the leak amount and restart servers regularly to avoid the leak 
  growing too large and to prevent NPP memory from being depleted.
  2. MTU size can be reduced down to 1232 bytes to try and avoid packet 
  fragmentation and the resulting leak. This did not work for most customers.
"

    $infoMsg = "
Considerable amount of non-paged pool memory is allocated with pool tag NDnd:

Tag  Bytes
NDnd {0}

Note: This might not be directly related to the issue you are troubleshooting.

This type of memory is used by NDIS to store network packet information.
This corresponds to more than 15K full-size Ethernet packets which is unusual 
and will benefit from further investigation.
Consider collecting an xperf trace, ensuring multiple allocs/leaks (at least 
1 MB) are captured in the trace. Poolmon can be used to monitor that:
  poolmon -iNDnd -p

Following command can be used to capture such a trace:
  1. xperf -on Base+CSwitch+POOL -stackwalk PoolAlloc+PoolFree+PoolAllocSession+PoolFreeSession -PoolTag NDnd -BufferSize 1024 -MaxBuffers 1024 -MaxFile 2048 -FileMode Circular 
  2. Wait for 5-10 minutes or until sufficient allocs/leaks are captured
  3. xperf -d c:\NDnd.etl 

Following command will capture a trace of size specified by MaxSize parameter 
and stop automatically (can also be stopped -if needed- by: xperf -stop):
  xperf -on Base+CSwitch+POOL -stackwalk PoolAlloc+PoolFree+PoolAllocSession+PoolFreeSession -PoolTag NDnd -BufferSize 1024 -MaxBuffers 1024 -MaxFile 1024 -f c:\NDnd.etl

Poolmon: https://docs.microsoft.com/en-us/windows-hardware/drivers/devtest/poolmon
xperf: https://docs.microsoft.com/en-us/windows-hardware/test/wpt/
"

    if($offline) {
        LogWrite "Running offline"
    }
    else {
        LogWrite "Running online"
    }

    # Look for the issue
	try	{
        $curBuild = [Convert]::ToUInt32($wmi_Win32_OperatingSystem.BuildNumber)
        $minBuild = 9200
        $maxBuild = 17134
        if (($curBuild -lt $minBuild) -or ($curBuild -gt $maxBuild)) {
            LogWrite "OS version $($wmi_Win32_OperatingSystem.Version) not affected, skipping"
            return $RETURNCODE_SKIPPED
        }

        # is DA running?
        $services = Get-Service -Name "RaMgmtSvc" -ErrorAction Ignore
        if (($services.Count -eq 0) -or ($services.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running)) {
            LogWrite "Not a DA Server, skipping"
            return $RETURNCODE_SKIPPED
        }

        $puSets = GetPoolUsageByTag "NDnd" "Nonp"
        if ($puSets.Count -gt 0) {
            $threshold = 30 * 1024 * 1024 # 30 MB / > 30K allocs
            $bytesInUse = 0
            foreach ($puSet in $puSets) {
                # find the highest bytes value
                if ($puSet[3] -gt $bytesInUse) {
                    $bytesInUse = $puSet[3]
                }
            }

            if ($bytesInUse -gt $threshold) {
                # we have high usage of NDnd which likely points to an issue
                $iType = $ISSUETYPE_INFO
                $iMsg = $infoMsg
		        $iMsg = [string]::Format($iMsg, $bytesInUse)
		        ReportIssue $iMsg $iType
            }
        }
	}
	catch {
		LogWrite "Failed - exiting! (Error: $_)"
        return $RETURNCODE_FAILED
    }

    return $RETURNCODE_SUCCESS
}
#endregion net_dasrv_KB4504598
#endregion dasrv

#region dhcpsrv
#region net_dhcpsrv_KB4503857
<#
Component: dhcpsrv
Checks for:
 The issue where a DHCP Server has Option 66 (Boot Server Host Name) defined
 but the name(s) cannot be resolved to IP addresses.
 This causes DHCP Server repeatedly spending time to resolve these names and
 prevents it from serving clients. This can cause DHCP outages.
Created by: tdimli
#>
function net_dhcpsrv_KB4503857
{
    param(
        [Parameter(Mandatory=$true,
        Position=0)]
        [Boolean]
        $offline
    )

    $issueMsg = "
Following Option 66 (Boot Server Host Name) values are configured on this DHCP 
Server but cannot be resolved to IP address(es). This can cause a DHCP outage 
where DHCP clients will not be able to receive IP addresses!

Server name(s) that cannot be resolved:
=======================================
{0}
Option 66 config location(s):
=============================
{1}
Resolution:
===========
Check Option 66 entries listed above and ensure that all values are valid and 
any configured names can be resolved and resolved in a timely manner by the 
DHCP Server.

Option 66 entries can only contain a single hostname or IP address, multiple 
values within the same option are not supported. If there are any entries with 
multiple values, please correct them.

Please remove any Option 66 entries that
1. point to decommissioned servers or servers that do not exist anymore
2. are not being used anymore

For servers in the list that are still active and being used as boot servers:
1. Ensure DNS records are created for them so that the names can be resolved

To test if a name can be resolved: 
Command prompt: ping -4 <server-name>
Powershell: Resolve-DnsName -Name <server-name> -Type A
"

    if($offline) { 
        LogWrite "Cannot run offline, skipping"
        return $RETURNCODE_SKIPPED
    }

    # Resolve-DnsName requires WS2012 or later, skip if earlier OS
    $curBuild = [Convert]::ToUInt32($wmi_Win32_OperatingSystem.BuildNumber)
    $reqBuild = 9200
    if ($curBuild -lt $reqBuild ) {
        LogWrite "Cannot run on OS version $($wmi_Win32_OperatingSystem.Version), build $reqBuild or later required, skipping"
        return $RETURNCODE_SKIPPED
    }

    $services = Get-Service -Name "DHCPServer" -ErrorAction Ignore
    if(($services.Count -ne 1) -or ($services.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running)) {
        # No DHCP Server, nothing to check
        LogWrite "DHCPServer service is not running, nothing to check, skipping"
        return $RETURNCODE_SKIPPED
    }

    $dhcpexport = MakeFilename "dhcpexport" "xml"

    LogWrite "Exporting Dhcp Server data..."
    try{
        Export-DhcpServer -File $dhcpexport -Force 
    }
    catch {
        # export failed
        LogWrite "Failed - exiting! (Error: $_)"
        return $RETURNCODE_FAILED
    }

    LogWrite "Inspecting Dhcp Server data..."
    [xml]$Dhcp = Get-Content $dhcpexport

    $badOptions = ""
    $isCritical = $false
    $qTimeLimit = 1000 # anything -ge this will be considered critical failure
    [System.Collections.Generic.List[String]] $failedNames = New-Object "System.Collections.Generic.List[string]"

    # Check Server Options
    foreach ($option in $Dhcp.DHCPServer.IPv4.OptionValues.OptionValue) {
        if ($option.OptionId -eq 66) {
            if ($failedNames.Contains($option.Value)) {
                $qTime = 1
            }
            else {
                $qTime = ResolveDnsName $option.Value
            }
            if ($qTime -gt 0) {
                # failed, add error to return msg
                $badOptions += $option.Value + " (IPv4->Server Options)`r`n"
                if (!$failedNames.Contains($option.Value)) {
                    $failedNames.Add($option.Value)
                }
                if ($qTime -ge $qTimeLimit) {
                    # critical
                    $isCritical = $true
                    LogWrite "$($option.Value) [$qTime ms]"
                }
            }
        }
    }

    # Check IPv4 Policies
    foreach ($policy in $Dhcp.DHCPServer.IPv4.Policies.Policy) {
        foreach ($option in $policy.OptionValues.OptionValue) {
            if ($option.OptionId -eq 66) {
                if ($failedNames.Contains($option.Value)) {
                    $qTime = 1
                }
                else {
                    $qTime = ResolveDnsName $option.Value
                }
                if ($qTime -gt 0) {
                    # failed, add error to return msg
                    $badOptions += $option.Value + " (IPv4->Policies->" + $policy.Name + ")`r`n"
                    if (!$failedNames.Contains($option.Value)) {
                        $failedNames.Add($option.Value)
                    }
                    if ($qTime -ge $qTimeLimit) {
                        # critical
                        $isCritical = $true
                        LogWrite "$($option.Value) [$qTime ms]"
                    }
                }
            }
        }
    }

    # Check Scopes
    foreach ($scope in $Dhcp.DHCPServer.IPv4.Scopes.Scope) {

        # Scope Pptions
        foreach($option in $scope.OptionValues.OptionValue) {
            if ($option.OptionId -eq 66) {
                if ($failedNames.Contains($option.Value)) {
                    $qTime = 1
                }
                else {
                    $qTime = ResolveDnsName $option.Value
                }
                if ($qTime -gt 0) {
                    # failed, add error to return msg
                    $badOptions += $option.Value + " (IPv4->Scope[" + $scope.ScopeId + "])`r`n"
                    if (!$failedNames.Contains($option.Value)) {
                        $failedNames.Add($option.Value)
                    }
                    if ($qTime -ge $qTimeLimit) {
                        # critical
                        $isCritical = $true
                        LogWrite "$($option.Value) [$qTime ms]"
                    }
                }
            }
        }

        # Scope Policies
        foreach ($policy in $scope.Policies.Policy) {
            foreach ($option in $policy.OptionValues.OptionValue) {
                if ($option.OptionId -eq 66) {
                    if ($failedNames.Contains($option.Value)) {
                        $qTime = 1
                    }
                    else {
                        $qTime = ResolveDnsName $option.Value
                    }
                    if ($qTime -gt 0) {
                        # failed, add error to return msg
                        $badOptions += $option.Value + " (IPv4->Scope[" + $scope.ScopeId + "]->Policies->" + $policy.Name + ")`r`n"
                        if (!$failedNames.Contains($option.Value)) {
                            $failedNames.Add($option.Value)
                        }
                        if ($qTime -ge $qTimeLimit) {
                            # critical
                            $isCritical = $true
                            LogWrite "$($option.Value) [$qTime ms]"
                        }
                    }
                }
            }
        }
    }

    if ($failedNames.Count -gt 0){
        $failedNames.Sort()
        $tempInfo = ""
        foreach ($failedName in $failedNames) {
            $tempInfo += '"' + "$failedName" + '"' +"`r`n"
        }
        $issueMsg = [string]::Format($issueMsg, $tempInfo, $badOptions)
        $issueType = $ISSUETYPE_INFO
        if ($isCritical) {
            $issueType = $ISSUETYPE_ERROR
        }
        ReportIssue $issueMsg $issueType
    }
    else {
        # no issue found, no reason to keep DHCP Server export
        Remove-Item $dhcpexport -ErrorAction Ignore
    }

    return $RETURNCODE_SUCCESS
}

# Returns 
#  0 if name can be resolved
# or
#  query time in ms in case of failure
function ResolveDnsName
{
    param(
        [Parameter(Mandatory=$true,
        Position=0)]
        [String]
        $DnsName
    )

    # no need to check if IP address
    try {
        if ($DnsName -match [IPAddress]$DnsName) {
            return 0
        }
    }
    catch {}

    $timeStart = (Get-Date).ToUniversalTime()
    $result = Resolve-DnsName -Name $DnsName -Type A -ErrorVariable DnsError -ErrorAction Ignore
    [UInt64] $timeTaken = ((Get-Date).ToUniversalTime() - $timeStart).TotalMilliseconds
    
    foreach($rec in $result) {
        if ($rec.IP4Address) {
            return 0
        }
    }

    if($timeTaken -eq 0){
        $timeTaken = 1 # return 1ms for 0ms failure case to avoid confusion with success case
    }

    return $timeTaken
}
#endregion net_dhcpsrv_KB4503857
#endregion dhcpsrv

#region dnscli
#region net_dnscli_KB4562541
<# 
Component: dnscli, vpn, da, ras
Checks for:
 The issue where multiple NRPT policies are configured and are in conflict.
 This will result in none of configured NRPT policies being applied.
Created by: tdimli 
#>
function net_dnscli_KB4562541
{
    param(
        [Parameter(Mandatory=$true,
        Position=0)]
        [Boolean]
        $offline
    )

    $issueMsg = "
This computer has local NRPT rules configured when there are also domain 
group policy NRPT rules present. This can cause unexpected name resolution 
behaviour. 
When domain group policy NRPT rules are configured, local NRPT rules are 
ignored and not applied:
`tIf any NRPT settings are configured in domain Group Policy, 
`tthen all local Group Policy NRPT settings are ignored.

More Information:
https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn593632(v=ws.11)

Resolution:
Inspect configured NRPT rules and decide which ones to keep, local or domain 
Group Policy NRPT rules. 

Registry key where local group policy NRPT rules are stored:
  {0}

Registry key where domain group policy NRPT rules are stored:
  {1}

Note: Even if domain group policy registry key is empty, local group policy 
NRPT rules will still be ignored. Please delete the domain group policy 
registry key if it is not being used.
If it is being re-created, identify the policy re-creating it and remove the 
corresponding policy configuration.
"

    if($offline) {
        LogWrite "Cannot run offline, skipping"
        return $RETURNCODE_SKIPPED
    }

    # Look for the issue
    $localNRPTpath = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"
    $domainNRPTpath = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\DnsClient"
    $DnsPolicyConfig = "DnsPolicyConfig"

    try
    {
        # are there any local NRPTs configured which risk being ignored?
        if ((Get-ChildItem -Path "Registry::$localNRPTpath\$DnsPolicyConfig" -ErrorAction Ignore).Count -gt 0) {
            # does domain policy NRPT key exist (empty or not)?
            $domainNRPT = (Get-ChildItem -Path "Registry::$domainNRPTpath" -ErrorAction Ignore)
            if ($domainNRPT -ne $null) {
                if ($domainNRPT.Name.Contains("$domainNRPTpath\$DnsPolicyConfig")) {
                    # issue present: domain Group Policy NRPT key present, local Group Policy NRPT settings are ignored
                    $issueMsg = [string]::Format($issueMsg, "$localNRPTpath\$DnsPolicyConfig", "$domainNRPTpath\$DnsPolicyConfig")
                    ReportIssue $issueMsg $ISSUETYPE_ERROR
                }
            }
        }
    }
	catch {
		LogWrite "Failed - exiting! (Error: $_)"
        return $RETURNCODE_FAILED
    }

    return $RETURNCODE_SUCCESS
}
#endregion net_dnscli_KB4562541
#region net_dnscli_KB4617560
<# 
Component: dnscli
Checks for:
 The issue where DNS names cannot be resolved if SearchList registry value is 
 not of type string.
Created by: tdimli 
#>
function net_dnscli_KB4617560
{
    param(
        [Parameter(Mandatory=$true,
        Position=0)]
        [Boolean]
        $offline
    )

    $issueMsg = "
This computer has SearchList registry value defined as a type other than string:

Key:   HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters
Value: SearchList

This may break DNS name resolution. 

Resolution:
Please inspect and ensure above registry value has the correct type and contains 
a valid DNS suffix search list.

More information on DNS suffix search list:
https://docs.microsoft.com/en-us/troubleshoot/windows-client/networking/configure-domain-suffix-search-list-domain-name-system-clients
"

    if($offline) {
        LogWrite "Cannot run offline, skipping"
        return $RETURNCODE_SKIPPED
    }

    # Look for the issue
    $issueFound = $false
    try
    {
        $regKey = (Get-Item -Path HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters -ErrorAction Ignore)
        if ($regKey -ne $null) {
            if ($regkey.Property.Contains("SearchList")) {
                $regType = $regKey.GetValueKind('SearchList')
                if ($regType -ne $null) {
                    if ($regType -ne 'String') {
                        $issueFound = $true
                    }
                }
            }
        }
        # issue found?
        if ($issueFound) {
            ReportIssue $issueMsg $ISSUETYPE_ERROR
        }
    }
	catch {
		LogWrite "Failed - exiting! (Error: $_)"
        return $RETURNCODE_FAILED
    }

    return $RETURNCODE_SUCCESS
}
#endregion net_dnscli_KB4617560
#endregion dnscli

#region dnssrv
#region net_dnssrv_KB4561750
<# 
Component: dnssrv
Checks for:
 Checks if DNS Server has failed to use the specified interface
 as indicated by event 410
Created by: tdimli
#>
function net_dnssrv_KB4561750
{
    param(
        [Parameter(Mandatory=$true,
        Position=0)]
        [Boolean]
        $offline
    )

    $issueMsg = @"
This DNS Server was configured to listen only on specific IP address(es) but has 
failed to do so. When such a failure occurs, DNS Server will delete the 
configured specific IP address(es) and will listen on all available IP addresses 
instead.

An event is logged in DNS Server event log to indicate this, most recent 
occurrence is displayed below:

Event ID: 410
Logname: DNS Server
Logged: {0}
The DNS server list of restricted interfaces does not contain a valid IP address 
for the server computer. The DNS server will use all IP interfaces on the machine. 
Use the DNS manager server properties, interfaces dialog, to verify and reset the 
IP addresses the DNS server should listen on. For more information, see 
"To restrict a DNS server to listen only on selected addresses" 
in the online Help.

Cause
The problem is that the network interface card for the configured IP address 
was not ready when DNS Server service was starting and as such, it could not 
be used.

As indicated by DNS event 410, this behaviour is expected: DNS Server checks 
existing IP addresses during service start and if none match the configured 
IP addresses, this configuration is considered invalid as DNS Server cannot run 
without any IP addresses. This configuration is deleted and DNS Server 
reverts to listen on all available IP addresses.

Resolution
To resolve this, the "Startup type" of "DNS Server" service can be changed 
to "Automatic (Delayed Start)”.
"@

    if($offline) {
        LogWrite "Cannot run offline, skipping"
        return $RETURNCODE_SKIPPED
    }

    # Look for the issue
	try	{

        $services = Get-Service -Name "DNS" -ErrorAction Ignore
        if($services.Count -ne 1) {
            LogWrite "Not a DNS Server, skipping"
            return $RETURNCODE_SKIPPED
        }

        $startTime = (Get-Date) - (New-TimeSpan -Day 30)
        $Event410 = Get-WinEvent -FilterHashtable @{ LogName="DNS Server"; Id=@(410); StartTime=$startTime} -MaxEvents 100 -ErrorAction Ignore | Sort-Object -Property TimeCreated -Descending

        if ($Event410.Count -gt 0) {
            # Get the latest occurrence
            $mostRecent = $Event410 | Select-Object -First 1

            $issueMsg = [string]::Format($issueMsg, $mostRecent.TimeCreated)
            ReportIssue $issueMsg $ISSUETYPE_ERROR
        }
	}
	catch {
		LogWrite "Failed - exiting! (Error: $_)"
        return $RETURNCODE_FAILED
    }

    return $RETURNCODE_SUCCESS
}
#endregion net_dnssrv_KB4561750
#region net_dnssrv_KB4569509
<# 
Component: dnssrv
Checks for:
 Checks if this DNS Server is protected against vulnerability described in 
 CVE-2020-1350
Created by: tdimli
#>
function net_dnssrv_KB4569509
{
    param(
        [Parameter(Mandatory=$true,
        Position=0)]
        [Boolean]
        $offline
    )

    $issueMsg = "
{0}

Background:
On July 14, 2020, Microsoft released a security update for the issue that is 
described in CVE-2020-1350 | Windows DNS Server Remote Code Execution 
Vulnerability. This advisory describes a Critical Remote Code Execution (RCE) 
vulnerability that affects Windows servers that are configured to run the DNS 
Server role. 

A registry-based workaround can be used to help protect an affected Windows 
server, and it can be implemented without requiring an administrator to restart 
the server. Because of the volatility of this vulnerability, administrators may 
have to implement the workaround before they apply the security update in order 
to enable them to update their systems by using a standard deployment cadence.

For more information please see following support article:
https://support.microsoft.com/help/4569509
"

    $msgNoUpdateNoRegistry = "
This DNS Server is not protected against the vulnerability as described in:
CVE-2020-1350 | Windows DNS Server Remote Code Execution Vulnerability
https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-1350

We strongly recommend that server administrators apply the security update at 
their earliest convenience.

A registry-based workaround can be used to help protect an affected Windows 
server, and it can be implemented without requiring an administrator to restart 
the server. Because of the volatility of this vulnerability, administrators may 
have to implement the workaround before they apply the security update in order 
to enable them to update their systems by using a standard deployment cadence.
"

    $msgNoUpdateRegistry = "
This DNS Server does not appear to have the update to resolve the vulnerability 
as described in:
CVE-2020-1350 | Windows DNS Server Remote Code Execution Vulnerability
https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-1350

The registry-based workaround has been applied. The registry-based workaround 
provides protections to a system when you cannot apply the security update 
immediately and should not be considered as a replacement to the security update. 
We strongly recommend that server administrators apply the security update at 
their earliest convenience.
"

    $msgUpdateAndRegistry = "
This DNS Server has the update to resolve the vulnerability as described in:
CVE-2020-1350 | Windows DNS Server Remote Code Execution Vulnerability
https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-1350

The registry-based workaround also seems to be in place. The workaround is 
compatible with the security update. However, the registry modification will 
no longer be needed after the update is applied. Best practices dictate that 
registry modifications be removed when they are no longer needed to prevent 
potential future impact that could result from running a nonstandard 
configuration.
"

    if($offline) {
        LogWrite "Cannot run offline, skipping"
        return $RETURNCODE_SKIPPED
    }

    # list of updates (for various OS versions) that first fixed this issue
    $requiredUpdates = @(
        "KB4565503", # 2004
        "KB4565483", # 1903 & 1909
        "KB4558998", # 2019
        "KB4565511", # 2016
        "KB4565541", # 2012 R2
        "KB4565537", # 2012
        "KB4565524", # 2008 R2 SP1
        "KB4565536"  # 2008 SP2
    )

    # Look for the issue
	try	{

        $services = Get-Service -Name "DNS" -ErrorAction Ignore
        if(($services.Count -ne 1) -or ($services.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running)) {
            LogWrite "Not an active DNS Server, nothing to check, skipping"
            #return $RETURNCODE_SKIPPED
        }
        
        # check if a resolving update is installed
        $update = HasRequiredUpdate $requiredUpdates

        # check for the registry value workaround
        $regKey = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DNS\Parameters" 
        $regVal = "TcpReceivePacketSize"
        $rItemProperty = Get-ItemProperty -Path "Registry::$regKey" -Name $regVal -ErrorAction Ignore

        if(($rItemProperty) -and ($($rItemProperty.$regVal) -le 0xFF00)) {
            $registry = $true
        }
        else {
            $registry = $false
        }

        if ($update) {
            if ($registry) {
                # update installed but still has the registry workaround in place
                $issueMsg = [string]::Format($issueMsg, $msgUpdateRegistry)
                ReportIssue $issueMsg $ISSUETYPE_INFO
            }
            else {
                # nothing to do: update installed and registry workaround is not present
                LogWrite "A resolving update is installed"
            }
        }
        else {
            if ($registry) {
                # update not installed but protected by registry workaround
                $issueMsg = [string]::Format($issueMsg, $msgNoUpdateRegistry)
                ReportIssue $issueMsg $ISSUETYPE_INFO
            }
            else {
                # vulnerable: no update and no registry workaround in place
                $issueMsg = [string]::Format($issueMsg, $msgNoUpdateNoRegistry)
                ReportIssue $issueMsg $ISSUETYPE_ERROR
            }
        }
	}
	catch {
		LogWrite "Failed - exiting! (Error: $_)"
        return $RETURNCODE_FAILED
    }

    return $RETURNCODE_SUCCESS
}
#endregion net_dnssrv_KB4569509
#endregion dnssrv

#region firewall
#region net_Firewall_KB4561854
<# 
Component: Firewall
Checks for:
 The issue where the Svchost process hosting BFE and Windows Defender Firewall
 takes up an unusual amount of CPU and RAM resources.
 This causes a performance degradation.
Created by: dosorr
#>
function net_firewall_KB4561854
{
    param(
        [Parameter(Mandatory=$true,
        Position=0)]
        [Boolean]
        $offline
    )

    $issueMsg = "
Several duplicates of same firewall rules are present on this device. 
This will lead to unnecessary and additional CPU and memory load on the host 
and can cause a performance degradation. This additional load will appear as 
high CPU and memory consumption by the Svchost process hosting BFE service and 
Windows Defender Firewall.

Duplicate firewall rules:

`t{0} instances of {1}
`t{2} instances of {3}

Note: The higher the number, the more CPU cycles and memory are consumed!

Resolution:
You can delete these duplicate rules using following commands:
  netsh advfirewall firewall delete rule name=`"Core Networking - Teredo (ICMPv6-In)`"
  netsh advfirewall firewall delete rule name=`"Core Networking - Teredo (ICMPv6-Out)`"

You might also want to disable ""Teredo interface"" to prevent this from 
happening again. You can use following GPO setting to disable it:
  Computer Configuration\AdministrativeTeamplates\Network\TCPIPSettings\IPv6TransitionTechnologies
  Set Teredo State: Disabled
"

    if($offline) {
        LogWrite "Cannot run offline, skipping"
        return $RETURNCODE_SKIPPED
    }

    # Look for the issue
	try	{
        $curBuild = [Convert]::ToUInt32($wmi_Win32_OperatingSystem.BuildNumber)
        $minBuild = 10000
        if ($curBuild -lt $minBuild ) {
            LogWrite "OS version $($wmi_Win32_OperatingSystem.Version) not affected, skipping"
            return $RETURNCODE_SKIPPED
        }

        # halve the run-time checking number of duplicate rules for both -in and -out in one call
        $TeredoRuleName = "Core Networking - Teredo (ICMPv6-*)"
		$TeredoRuleCount = (Get-NetFirewallRule -DisplayName $TeredoRuleName -ErrorAction Ignore).Count

		# Issue present if any of the rule is present at least 10 times
		if($TeredoRuleCount -ge 20) {
            # do the full work only if needed
            $TeredoOutRuleName = "Core Networking - Teredo (ICMPv6-Out)"
		    $TeredoInRuleName = "Core Networking - Teredo (ICMPv6-In)"
            $TeredoOutRuleCount = (Get-NetFirewallRule -DisplayName $TeredoOutRuleName -ErrorAction Ignore).Count
		    $TeredoInRuleCount = (Get-NetFirewallRule -DisplayName $TeredoInRuleName -ErrorAction Ignore).Count
			# Issue detected
			$issueMsg = [string]::Format($issueMsg, $TeredoOutRuleCount, $TeredoOutRuleName, $TeredoInRuleCount, $TeredoInRuleName)
			ReportIssue $issueMsg $ISSUETYPE_ERROR
		}
	}
	catch {
		LogWrite "Failed - exiting! (Error: $_)"
        return $RETURNCODE_FAILED
    }

    return $RETURNCODE_SUCCESS
}
#endregion net_Firewall_KB4561854
#endregion firewall

#region hyphost
#region net_hyphost_KB4562593
<# 
Component: vmswitch
Checks for:
 NET: Hyper-V: Multicast, broadcast or unknown unicast 
 packet storm exhausts non-paged pool memory or causes 3B/9E bugchecks on Hyper-V hosts
Created by: vidou 
#>
function net_hyphost_KB4562593
{
    param(
        [Parameter(Mandatory=$true,
        Position=0)]
        [Boolean]
        $offline
    )

    $issueMsg = "
This server had to allocate high amount of memory for packets in a vRss queue 
due to low resource on the physical NIC. 
This will cause packets to be dropped until the queue size falls below 512 MB.

Note: This might not be directly related to the issue you are troubleshooting.
 If you are troubleshooting an issue related to network connectivity/packet 
 drops, or server performance or crashes, then this is likely to be related.

The maximum memory that had to be allocated reached {0} MB within the last {1} 
days checked.
The higher this figure, the more the packet drops and the longer it lasts.

You can obtain more details by reviewing following events in System Event log:
ProviderName: {2}
Event Ids   : {3}

If you are a Microsoft Support Professional, please review KB4562593 for 
further assistance.
"

    if($offline) {
        LogWrite "Cannot run offline, skipping"
        return $RETURNCODE_SKIPPED
    }

    $minBuild = 14393 
    $curBuild = [Convert]::ToUInt32($wmi_Win32_OperatingSystem.BuildNumber)
    $productType = [Convert]::ToUInt32($wmi_Win32_OperatingSystem.ProductType)
    
    # issue may only affect Win10 Server above RS1
    if (($curBuild -lt $minBuild) -or ($productType -eq 1)) {
        LogWrite "OS build ($curBuild) not affected or client SKU ($productType), skipping"
        return $RETURNCODE_SKIPPED
    }

    try {
        #Checking that Hypv and at least one VMSwith is present
        $res = Get-WindowsFeature Hyper-V -ErrorAction Ignore
        if ( $res.InstallState -ne "Installed")
        {
            LogWrite "Hyper-V not installed, skipping"
            return $RETURNCODE_SKIPPED
        }

        #$IssueFound = $false
        #$VmSwitchCount = 0
        $VmSwitchCount = (Get-VMSwitch -ErrorAction Ignore).Count
        
        # if there is no vSwitch then exit
        if ( $VmSwitchCount -lt 1)
        {
            LogWrite "No vmswitch, skipping"
            return $RETURNCODE_SKIPPED
        }

        # examine System event log
        $providerName="Microsoft-Windows-Hyper-V-VmSwitch"
        $eventId = "252"
        $queueThreshold = 512
        $maxQueueSize = 0
        $days = 14
        $startTime = (Get-Date) - (New-TimeSpan -Day $days)
        $Log = Get-WinEvent -FilterHashtable @{ LogName="System"; Id=$eventId; ProviderName=$providerName; StartTime=$startTime } -ErrorAction Ignore
        
        if ($Log -ne $null)
        {
            $IssueFound = $Log.Message.Split(" ") | ForEach-Object{ 
                if( $_ -match "MB")
                { 
                    $CurrentQueueSize=$_ -replace '(\d+).*','$1'
                    if ( [int]$CurrentQueueSize -gt $queueThreshold)
                    {
                        if ($CurrentQueueSize -gt $maxQueueSize) {
                            $maxQueueSize = $CurrentQueueSize
                        }
                        return $true
                    }
                }
            }

            if ( $IssueFound)
            {
                $issueMsg = [string]::Format($issueMsg, $maxQueueSize, $days, $providerName, $eventId)
    		    ReportIssue $issueMsg $ISSUETYPE_ERROR
            }
        }
    }
    catch {
        LogWrite "Failed - exiting! (Error: $_)"
        return $RETURNCODE_FAILED
    }

    return $RETURNCODE_SUCCESS
}
#endregion net_hyphost_KB4562593
#endregion hyphost

#region ncsi
#region net_ncsi_KB4648334
<# 
Component: ncsi, nla
Checks for:
 The issue where corporate connectivity is configured on a non-DA client
 This will result in NCSI/NLA network detection issues
Created by: tdimli, jcabrera
#>
function net_ncsi_KB4648334
{
    param(
        [Parameter(Mandatory=$true,
        Position=0)]
        [Boolean]
        $offline
    )
$issueMsg = "
This computer has corporate connectivity configured.
Corporate connectivity is only needed for Direct Access (DA) but this device 
does not appear to have DA configured (no IPHTTPS interface configured).

Corporate connectivity configuration on a non-DA client may cause network 
detection problems with NCSI.

Resolution:
If this computer is not using Direct Access, please remove corporate connectivity 
configuration to avoid network detection issues.

Registry key where corporate connectivity configuration is stored:
  {0}

Note: If the registry key is being re-created, identify the policy that is 
re-creating it and remove the corresponding policy configuration.
"

    if($offline) {
        LogWrite "Cannot run offline, skipping"
        return $RETURNCODE_SKIPPED
    }

    # Look for the issue
    $CorporateConnectivityPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator\CorporateConnectivity"

    try
    {
        $curBuild = [Convert]::ToUInt32($wmi_Win32_OperatingSystem.BuildNumber)
        $minBuild = 10000 
        if ($curBuild -gt $minBuild) {
            # Windows 10
            # is corporate connectivity configured?
            $regKey = (Get-Item -Path $CorporateConnectivityPath -ErrorAction Ignore)
            LogWrite "$CorporateConnectivityPath exists? $($regkey -ne $null)"
            if ($regKey -ne $null) {
                # is DirectAccess configured (IPHTTPS interface present)?
                if ($null -eq (Get-NetIPHttpsConfiguration -ErrorAction Ignore)) {
                    # issue present: corporate connectivity configured without a DA client
                    $issueMsg = [string]::Format($issueMsg, $CorporateConnectivityPath)
                    ReportIssue $issueMsg $ISSUETYPE_ERROR
                }
            }
        }
        else {
            # issue does not apply to pre-Windows 10
            return $RETURNCODE_SKIPPED
        }
    }
	catch {
		LogWrite "Failed - exiting! (Error: $_)"
        return $RETURNCODE_FAILED
    }

    return $RETURNCODE_SUCCESS
}
#endregion net_ncsi_KB4648334
#endregion ncsi

#region netio
#region net_netio_KB4563820
<# 
Component: dasrv
Checks for:
 NETIO/WFP non-paged pool memory leak, tag Afqc
Created by: tdimli
#>
function net_netio_KB4563820
{
    param(
        [Parameter(Mandatory=$true,
        Position=0)]
        [Boolean]
        $offline
    )

    $issueMsg = "
Considerable amount of {1} pool memory is allocated with pool tag {0}:

Tag  Bytes
{0} {2}

Windows 10 clients and servers (1809 or later) may leak non-paged pool memory 
(NPP, tag Afqc) in certain scenarios.

This memory leak can cause performance degradation due to reduced amount of 
memory left available. If the leak grows too large, it can deplete the {1}  
pool memory and cause the computer to crash.

Resolution
We are currently working on a long-term resolution to address this issue.
Following workarounds can be used until a resolution becomes available:
  1. Monitor the leak amount and restart affected computers regularly to avoid 
  the leak growing too large and to prevent {1} pool memory from being depleted.
  2. If possible, reduce amount of UDP traffic
"

    $infoMsg = "
Considerable amount of {1} pool memory is allocated with pool tag {0}:

Tag: {0}
Pool: {1}
Allocs in use: {3}
Bytes in use: {4}

Note: This might not be directly related to the issue you are troubleshooting.

This tag is used by {2}

{3} allocations being in use for this tag is unusual and may benefit from 
further investigation.
Consider collecting an xperf trace, ensuring multiple allocs/leaks (at least 
1 MB) are captured in the trace. Poolmon can be used to monitor that:
  poolmon -i{0}

Following command can be used to capture such a trace:
  1. xperf -on Base+CSwitch+POOL -stackwalk PoolAlloc+PoolFree+PoolAllocSession+PoolFreeSession -PoolTag {0} -BufferSize 1024 -MaxBuffers 1024 -MaxFile 2048 -FileMode Circular 
  2. Wait for 5-10 minutes or until sufficient allocs/leaks are captured
  3. xperf -d c:\{0}.etl 

Following command will capture a trace of size specified by MaxSize parameter 
and stop automatically (can also be stopped -if needed- by: xperf -stop):
  xperf -on Base+CSwitch+POOL -stackwalk PoolAlloc+PoolFree+PoolAllocSession+PoolFreeSession -PoolTag {0} -BufferSize 1024 -MaxBuffers 1024 -MaxFile 1024 -f c:\{0}.etl

Poolmon: https://docs.microsoft.com/en-us/windows-hardware/drivers/devtest/poolmon
xperf: https://docs.microsoft.com/en-us/windows-hardware/test/wpt/
"

    if($offline) {
        LogWrite "Running offline"
    }
    else {
        LogWrite "Running online"
    }

    # Look for the issue
    $tag = "Afqc"
    $pooltype = "Nonp"
    $comp = "TCPIP/WFP" # who uses this tag
    $threshold = 10 * 1024 # if over 10K allocs are leaked

	try	{
        $puSets = GetPoolUsageByTag $tag $pooltype
        if ($puSets.Count -gt 0) {
            $bytesInUse = 0
            $allocsInUse = 0
            $doubleAllocs = $false
            foreach ($puSet in $puSets) {
                # find the highest diff between allocs and frees
                if ($puSet[2] -gt $allocsInUse) {
                    $allocsInUse = $puSet[2]
                    $bytesInUse = $puSet[3]
                    if ($puSet[0] -ge (2 * $puSet[1])) { # alloc twice, free once issue
                        $doubleAllocs = $true
                    }
                }
            }

            $prodType = [Convert]::ToUInt32($wmi_Win32_OperatingSystem.ProductType)
            $curBuild = [Convert]::ToUInt32($wmi_Win32_OperatingSystem.BuildNumber)
            $minBuild = 17763

            if ($prodType -eq 1) {
                # only checking client SKUs, not servers
                if ($allocsInUse -gt $threshold) {
                    # is this the Afqc/AppLocker issue which affects Win10 RS5 and later?
                    $curBuild = [Convert]::ToUInt32($wmi_Win32_OperatingSystem.BuildNumber)
                    $minBuild = 17763
                    if ($curBuild -lt $minBuild) {
                        # not KB4563820 but we do have high usage of Afqc which still points to an issue
                        LogWrite "OS (Build:$curBuild) not affected by KB4563820 issue, this seems to be a new $tag mem leak"
                        $issueMsg = [string]::Format($infoMsg, $tag, $pooltype, $comp, $allocsInUse, $bytesInUse)
                        $issueType = $ISSUETYPE_INFO
                    }
                    elseif ($doubleAllocs) { 
                        # confirmed double alloc issue as per KB4563820
                        LogWrite "There are twice as many allocs as frees, definitely KB4563820"
		                $issueMsg = [string]::Format($issueMsg, $tag, $pooltype, $bytesInUse)
                        $issueType = $ISSUETYPE_ERROR
                    }
                    else { 
                        # not sure, might be KB4563820 or not, log as info for review
                        LogWrite "There is a leak but not sure if same issue as KB4563820, needs confirmation"
                        $issueMsg = [string]::Format($issueMsg, $tag, $pooltype, $bytesInUse)
                        $issueType = $ISSUETYPE_INFO
                    }
		            ReportIssue $issueMsg $issueType
                }
            }
            else {
                # server SKU
                LogWrite "ProductType ($prodType) is not client, skipping"
                return $Global:RETURNCODE_SKIPPED
            }
        }
	}
	catch {
		LogWrite "Failed - exiting! (Error: $_)"
        return $RETURNCODE_FAILED
    }

    return $RETURNCODE_SUCCESS
}
#endregion net_netio_KB4563820
#endregion netio

#region proxy
#region net_proxy_KB4569506
<# 
Component: vpn
Checks for:
 An issue where modern apps like Edge might stop working or NLA might display 
 "No Internet" after some 3rd party VPNs connect
Created by: tdimli
#>
function net_proxy_KB4569506
{
    param(
        [Parameter(Mandatory=$true,
        Position=0)]
        [Boolean]
        $offline
    )

    $issueMsg = @"

This computer has received an invalid option from DHCP Server:
Option 252, Proxy autodiscovery

Network interface over which the invalid option was received:
{0}

This may cause NCSI to fail to detect network connectivity and 
show "No Internet" 

Note: This might not be directly related to the issue you are troubleshooting.
 If you are troubleshooting an issue related to proxy and/or NCSI connectivity
 detection, then this is probably related.

Resolution
Either remove this invalid option from DHCP server or configure it with a 
valid URL.
"@

    if($offline) {
        LogWrite "Cannot run offline, skipping"
        return $RETURNCODE_SKIPPED
    }

    # Look for the issue
	try	{
        $curBuild = [Convert]::ToUInt32($wmi_Win32_OperatingSystem.BuildNumber)
        $minBuild = 10000
        if ($curBuild -lt $minBuild ) {
            LogWrite "OS version $($wmi_Win32_OperatingSystem.Version) not affected, skipping"
            return $RETURNCODE_SKIPPED
        }

        # Windows 10
        $error = $false
        $ifs = $null
        $connections = (Get-NetAdapter -ErrorAction Ignore)
        foreach ($netAdapter in $connections) {
            if ($netAdapter.MediaConnectionState -eq "Connected") {
                $itemProp = (Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\$($netAdapter.InterfaceGuid) -Name DhcpInterfaceOptions -ErrorAction Ignore)
                if (!$itemProp) {
                    continue
                }
                $DhcpInterfaceOptions = $itemProp.DhcpInterfaceOptions
	            $pointer = 0
	            while ($pointer -lt $DhcpInterfaceOptions.length) 
	            {
		            $code = $DhcpInterfaceOptions[$pointer]
		            $pointer += 4
                    $cLength = $DhcpInterfaceOptions[$pointer]
		            $pointer += 4
		            $length = $DhcpInterfaceOptions[$pointer]
		            $pointer += 3 * 4 + $cLength + $length
                    $align = 4 - ($pointer % 4)
                    if ($align -lt 4) {
                        $pointer += $align
                    }
		
		            if ($code -eq 252)
		            {
                        if ($length -lt 6) {
                            # check for Internet connectivity
                            $prf = (Get-NetConnectionProfile -InterfaceAlias $netAdapter.Name -ErrorAction Ignore)
                            if ($prf) {
                                if ($prf.IPv4Connectivity -ne "Internet") {
                                    if ($error) {
                                        $ifs += ", "
                                    }
                                    else {
                                        $error = $true
                                    }
                                    $ifs += $netAdapter.Name
                                    break
                                }
                            }
                        }
		            }
	            }
            }
        }
        if ($error) {
            $issueMsg = [string]::Format($issueMsg, $ifs)
		    ReportIssue $issueMsg $ISSUETYPE_ERROR
        }
	}
	catch {
		LogWrite "Failed - exiting! (Error: $_)"
        return $RETURNCODE_FAILED
    }

    return $RETURNCODE_SUCCESS
}
#endregion net_proxy_KB4569506
#endregion proxy

#region rpc
#region net_rpc_KB2506972
<# 
Component: rpc
Checks for:
 The issues caused by enabling group policies 
 "Restrictions for unauthenticated RPC clients"
 and 
 "RPC endpoint mapper client authentication"
Created by: tdimli 
#>
function net_rpc_KB2506972
{
    param(
        [Parameter(Mandatory=$true,
        Position=0)]
        [Boolean]
        $offline
    )
$issueMsg = @"
This computer has one or more of the following policies enabled:

 Computer Configuration \ <policies> \ Administrative Templates \ System \ Remote Procedure Call
  Restrictions for unauthenticated RPC clients
  RPC endpoint mapper client authentication

Which map to the DWORD registry settings:

 HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\RpcX
  RestrictRemoteClients
  EnableAuthEpResolution

This machine has these values currently configured as:
{0}
When you enable these authentication protections for RPC, you are no longer 
allowing applications to anonymously query the endpoint mapper: These two settings 
add an additional authentication "callback capability" to RPC connections. 
The problem is most applications don't have the capability to satisfy this 
requirements and fail as a result. This will break most applications including 
some Windows functionality. 

For more information as well as how to fix this:
 "Restrictions for Unauthenticated RPC Clients: The group policy that punches your domain in the face"
 https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/restrictions-for-unauthenticated-rpc-clients-the-group-policy/ba-p/399128
"@

    if($offline) {
        LogWrite "Cannot run offline, skipping"
        return $RETURNCODE_SKIPPED
    }

    # Look for the issue
    $regKey = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" 

    $regVals = @("EnableAuthEpResolution", "RestrictRemoteClients")
    $errMsg = ""
    $issueFound = $false

    try
    {
        foreach ($regVal in $regVals) {
            $rItemProperty = Get-ItemProperty -Path "Registry::$regKey" -Name $regVal -ErrorAction Ignore
            if ($rItemProperty) {
                $errMsg += " $regVal = $($rItemProperty.$regVal)`r`n"
                if ($($rItemProperty.$regVal) -ne 0) {
                    $issueFound = $true
                }
            }
        }
        if ($issueFound) {
            # issue present
            $issueMsg = [string]::Format($issueMsg, $errMsg)
            ReportIssue $issueMsg $ISSUETYPE_ERROR
        }
    }
	catch {
		LogWrite "Failed - exiting! (Error: $_)"
        return $RETURNCODE_FAILED
    }

    return $RETURNCODE_SUCCESS
}
#endregion net_rpc_KB2506972
#endregion rpc

#region srv
#region net_srv_KB4562940
<# 
Component: srv
Checks for:
 The presence of SMBServer 1020/1031/1032 Events
 indicating a stalled I/O of more than 15 Seconds or Live Dump generation.
 Likely Cause: Broken Filterdrivers or extremely poor Storage Performance.
Created by: huberts
#>
function net_srv_KB4562940
{
    param(
        [Parameter(Mandatory=$true,
        Position=0)]
        [Boolean]
        $offline
    )

    $issueMsg = "
This SMB Server has encountered file system operation(s) that has taken longer 
than expected.
The underlying file system has taken too long to respond to an operation. 
This typically indicates a problem with the storage and not SMB.

Note: This might not be directly related to the issue you are troubleshooting.
 If you are troubleshooting an issue related to server performance or hung SMB 
 server, then this is probably related.

An event is logged when file system operation takes longer than the default 
threshold of 15 seconds (120 seconds for asynchronous operations):
Microsoft-Windows-SMBServer/Operational Eventlog, EventID 1020

The latest occurrence was at:
{0}

There have been at least {1} occurrences in the last {2} days.
{3}

For information on troubleshooting SMB-Server Event ID 1020 warnings:
https://docs.microsoft.com/en-us/troubleshoot/windows-server/networking/troubleshoot-event-id-1020-warnings-file-server

"

    $issueMsg1 = "
Additionally the SMB Server tried to generate a live kernel dump because it 
encountered a problem. The reason for this dump is likely the same long-running 
filesystem operation.
Please check the Microsoft-Windows-SMBServer/Operational event log, look for 
event IDs 1031 & 1032 for further details, including the dump reason.
If a live dump was successfully created it can be found under:
%SystemRoot%\LiveKernelReports 
Such a dump is immensely useful for further troubleshooting.
"

    $AdditionalMsgText= "
There seems to be no live kernel dump(s) generated.
"

	# we can run offline, but need a seperate logic to retrieve information from exported .evtx files
    if($offline) {
        LogWrite "Cannot run offline, skipping"
        return $RETURNCODE_SKIPPED
    }

    # Get-SmbShare requires WS2012 or later, skip if earlier OS
    $curBuild = [Convert]::ToUInt32($wmi_Win32_OperatingSystem.BuildNumber)
    $reqBuild = 9200
    if ($curBuild -lt $reqBuild ) {
        LogWrite "Cannot run on OS version $($wmi_Win32_OperatingSystem.Version), build $reqBuild or later required, skipping"
        return $RETURNCODE_SKIPPED
    }
    
    # Look for the issue
    try {
	    # Get a list of shares to see if we are actually on a fileserver
        # Ignore Default Shares such as Temp$, IPC$, etc.
        $SMBshares = Get-SmbShare -ErrorAction Ignore | Where-Object {$_.Path -notlike "$Env:WinDir*" -and $_.Name -notlike "IPC$" -and $_.Name -notmatch "^[A-Z]{1}\$" }
        if ($SMBshares.Count -eq 0) {
            # no shares found -> nothing to check
            LogWrite "No Fileserver Shares found. Nothing to check. Skipping"
            return $RETURNCODE_SKIPPED
        }

        # get a maximum of $NumberOfEventsToCheck Events from the Eventlog (in order to limit runtime)
        $NumberOfEventsToCheck = 500
        $days = 30
        $startTime = (Get-Date) - (New-TimeSpan -Day $days)
        $Eventlog = Get-WinEvent -FilterHashtable @{ LogName="Microsoft-Windows-SMBServer/Operational"; Id=@(1020, 1031, 1032); StartTime=$startTime} -MaxEvents $NumberOfEventsToCheck -ErrorAction Ignore | Sort-Object -Property TimeCreated -Descending

        $Event1020 = $EventLog | Where-Object {$_.ID -eq 1020}
        if ($Event1020.Count -gt 0) {
            # OK! We found some 1020 Event!
            if ($Event1020.Count -gt 1) {
                $issueType = $ISSUETYPE_ERROR
            }
            else {
                $issueType = $ISSUETYPE_WARNING
            }
            # Check the latest occurrence
            $1020_NewestOccurence = $Event1020 | Select-Object -First 1

            # Now lets check if we also have Messages stating that the Server tried to generate a Live Dump and if so provide further input.
            $DumpEvent = $EventLog | Where-Object {$_.ID -eq 1031}
            if ($DumpEvent.Count -ne 0) {
                $AdditionalMsgText = $issueMsg1
            }

            $issueMsg = [string]::Format($issueMsg, $1020_NewestOccurence.TimeCreated, $Event1020.Count, $days, $AdditionalMsgText)
            ReportIssue $issueMsg $issueType
        }
    }
	catch {
		LogWrite "Failed - exiting! (Error: $_)"
        return $RETURNCODE_FAILED
    }

    return $RETURNCODE_SUCCESS
}
#endregion net_srv_KB4562940

#region net_srv_KB4612362
# Created by edspatar
# March 2021
<# 
Component: srv
 
 Checks for:
 Checks for the presence of SMBServer 1015 Events
 indicating an SMB Decryption Failed.
 Likely Cause: One of the RDS users becomes idle and SMB server disconnected its 
 SMB session with the underlying TCP connection for all user SMB sessions built 
 on that TCP connection.
#>
function net_srv_KB4612362
{
    param(
        [Parameter(Mandatory=$true,
        Position=0)]
        [Boolean]
        $offline
    )

$NumberOfEventsToCheck = 500

$issueMsg = @"
This server has logged "Decrypt call failed" error events:
 Microsoft-Windows-SMBServer/Security Eventlog, EventID 1015

The latest occurrence was at:
{0}

There have been at least {1} occurrence(s) in the last {2} days.

This event commonly occurs because a previous SMB session no longer exists.
It may also be caused by packets that are altered on the network between 
the computers due to either errors or a "man-in-the-middle" attack.

If the SMB client is an RDS Server, these events maybe expected due to multiple 
users sharing the same session and when one times out, it will trigger this event 
on others. To confirm, please check for instances of following event on the 
Terminal Server:

Microsoft-Windows-SMBclient/Connectivity
Event ID 30805  
Microsoft-Windows-SMBClient  
Warning
The connection to the share was lost.      
Error: The remote user session has been deleted...

If the server is a Windows Failover Cluster file server, then this message 
may also occur when the file share moves between cluster nodes. There will also 
be an anti-event 30808 indicating the session to the server was re-established. 
If the server is not a failover cluster, it is likely that the server was previously 
online, but it is now inaccessible over the network.

Workaround: To prevent these errors, SMB Encryption can be disabled.
"@

	# we can run offline, but need a seperate logic to retrieve information from exported .evtx files
    if($offline) {
        LogWrite "Cannot run offline, skipping"
        return $RETURNCODE_SKIPPED
    }
    
    # Look for the issue
    try {
	    # Check if SMB encryption is enabled at server level, if not check for shares with EncryptData enabled
        # Ignore Default Shares such as Temp$, IPC$, etc.
        $SMBEncryptedServer = Get-SmbServerConfiguration -ErrorAction Ignore | Where-Object -Property "EncryptData" -eq $true
		if ($SmbServerConfiguration.Count -eq 0) {
			$SMBEncryptedShares = Get-SmbShare -ErrorAction Ignore | Where-Object {$_.Path -notlike "$Env:WinDir*" -and $_.Name -notlike "IPC$" -and $_.Name -notmatch "^[A-Z]{1}\$" -and $_.EncryptData -eq $true}
			if ($SMBEncryptedShares.Count -eq 0) {
				# no shares found -> nothing to check
				LogWrite "No encrypted shares found, nothing to check, skipping"
				return $RETURNCODE_SKIPPED
			}
        }

        # get a maximum of $NumberOfEventsToCheck Events from the Eventlog (in order to limit runtime)
        $NumberOfEventsToCheck = 500
        $days = 30
        $startTime = (Get-Date) - (New-TimeSpan -Day $days)
        $Event1015 = Get-WinEvent -FilterHashtable @{ LogName="Microsoft-Windows-SMBServer/Security"; Id=@(1015); StartTime=$startTime} -MaxEvents $NumberOfEventsToCheck -ErrorAction Ignore | Sort-Object -Property TimeCreated -Descending

        if ($Event1015.Count -gt 0) {
            # OK! We found some 1015 events!
            if ($Event1020.Count -gt 10) {
                $issueType = $ISSUETYPE_ERROR
            }
            else {
                $issueType = $ISSUETYPE_WARNING
            }

            # Check the latest occurrence
            $1015_NewestOccurance = $Event1015 | Select-Object -First 1

            $issueMsg = [string]::Format($issueMsg, $1015_NewestOccurance.TimeCreated, $Event1015.Count, $days)
            ReportIssue $issueMsg $issueType
        }       
    }

	catch {
		LogWrite "Failed - exiting! (Error: $_)"
        return $RETURNCODE_FAILED
    }

    return $RETURNCODE_SUCCESS
}
#endregion net_srv_KB4612362
#endregion srv

#region vpn
#region net_vpn_KB4553295
<# 
Component: aovpn
Checks for:
 An issue where AoVPN might not detect that it's inside
Created by: tdimli
#>
function net_vpn_KB4553295
{
    param(
        [Parameter(Mandatory=$true,
        Position=0)]
        [Boolean]
        $offline
    )

    $issueMsg = @"
There is a domain authenticated connection which is not in the trusted network 
list configured for Always on VPN (AoVPN) connection:
{0}

This might lead to unnecessary AoVPN connections being triggered.

Note: This might not be directly related to the issue you are troubleshooting.
 If you are troubleshooting an issue related to AoVPN trusted network detection 
 and/or AoVPN client initiating a connection when already have connectivity to 
 a DomainAuthenticated network, then this is likely to be related.

Resolution
To avoid a AoVPN connection being established when already connected to a domain 
network via "{0}", add its network name "{1}" to AoVPN 
configuration as a trusted network, e.g.:
<TrustedNetworkDetection>{2}{1}</TrustedNetworkDetection>
"@

    if($offline) {
        LogWrite "Cannot run offline, skipping"
        return $RETURNCODE_SKIPPED
    }

    # Look for the issue
	try	{
        $curBuild = [Convert]::ToUInt32($wmi_Win32_OperatingSystem.BuildNumber)
        $minBuild = 10000
        if ($curBuild -lt $minBuild ) {
            LogWrite "OS version $($wmi_Win32_OperatingSystem.Version) not affected, skipping"
            return $RETURNCODE_SKIPPED
        }

        # Windows 10
        $vpnConn = (Get-VpnConnection -ErrorAction Ignore)
        if ($vpnConn) {
            $trigger = (Get-VpnConnectionTrigger -ConnectionName $vpnConn.Name -ErrorAction Ignore)
            if ($trigger) {
                $trustedNetworks = $trigger.TrustedNetwork
                if ($trustedNetworks) {
                    $connections = (Get-NetConnectionProfile -NetworkCategory DomainAuthenticated -ErrorAction Ignore)
                    foreach ($conn in $connections) {
                        if ($vpnConn.Name -ne $conn.InterfaceAlias) {
                            if (!$trustedNetworks.Contains($conn.Name)) {
                                $iType = $ISSUETYPE_ERROR
                                $badconn = $conn
                            }
                        }
                    }
                    if ($iType -eq $ISSUETYPE_ERROR) {
                        foreach ($net in $trustedNetworks) {
                            $trustedNetworkList += $net + ","
                        }
		                $issueMsg = [string]::Format($issueMsg, $badconn.InterfaceAlias, $badconn.Name, $trustedNetworkList)
		                ReportIssue $issueMsg $iType
                    }
                }
            }
        }
	}
	catch {
		LogWrite "Failed - exiting! (Error: $_)"
        return $RETURNCODE_FAILED
    }

    return $RETURNCODE_SUCCESS
}
#endregion net_vpn_KB4553295

#region net_vpn_KB4550202
<# 
Component: vpn
Checks for:
 An issue where modern apps like Edge might stop working or NLA might display 
 "No Internet" after some 3rd party VPNs connect
Created by: tdimli
#>
function net_vpn_KB4550202
{
    param(
        [Parameter(Mandatory=$true,
        Position=0)]
        [Boolean]
        $offline
    )

    $issueMsg = @"
There is a 3rd party VPN connection which is connected but hidden:
Name: {0}
Guid: {1}

Being hidden when connected might prevent NLA from detecting connectivity 
over this VPN connection and can lead to connectivity issues.

Note: This might not be directly related to the issue you are troubleshooting.
 If you are troubleshooting an issue related to VPN connectivity, such as 
 modern apps like Edge etc. stop working or NLA displaying "No Internet" after 
 a 3rd party VPN is connected.

Resolution
Ensure the VPN adapter is visible when connected. Contact VPN vendor for 
further assistance.
"@

    if($offline) {
        LogWrite "Cannot run offline, skipping"
        return $RETURNCODE_SKIPPED
    }

    # Look for the issue
	try	{
        $curBuild = [Convert]::ToUInt32($wmi_Win32_OperatingSystem.BuildNumber)
        $minBuild = 10000
        if ($curBuild -lt $minBuild ) {
            LogWrite "OS version $($wmi_Win32_OperatingSystem.Version) not affected, skipping"
            return $RETURNCODE_SKIPPED
        }

        # Windows 10
        $vpnConn = (Get-VpnConnection -ErrorAction Ignore)
        if ($vpnConn) {
            if ($vpnConn.ConnectionStatus -eq "Connected") {
                $connections = (Get-NetConnectionProfile -ErrorAction Ignore)
                $vpnHidden = $true
                foreach ($conn in $connections) {
                    if ($vpnConn.Name -eq $conn.InterfaceAlias) {
                        $vpnHidden = $false
                        LogWrite "VPN not hidden"
                    }
                }
                if ($vpnHidden) {
                    foreach ($net in $trustedNetworks) {
                        $trustedNetworkList += $net + ","
                    }
		            $issueMsg = [string]::Format($issueMsg, $vpnConn.Name, $vpnConn.Guid)
		            ReportIssue $issueMsg $ISSUETYPE_ERROR
                }
            }
            else {
                LogWrite "VPN not connected, skipping"
                return $RETURNCODE_SKIPPED
            }
        }
        else {
            LogWrite "No VPN connection, skipping"
            return $RETURNCODE_SKIPPED
        }
	}
	catch {
		LogWrite "Failed - exiting! (Error: $_)"
        return $RETURNCODE_FAILED
    }

    return $RETURNCODE_SUCCESS
}
#endregion net_vpn_KB4550202
#endregion vpn

#region wlan
#region net_wlan_KB4557342
<# 
Component: wlan
Checks for:
 The issue where WLAN profiles cannot be deleted, their password changed or
 network forgotten. 
Created by: dosorr 
#>
function net_wlan_KB4557342
{
    param(
        [Parameter(Mandatory=$true,
        Position=0)]
        [Boolean]
        $offline
    )

    $issueMsg = "
WLAN Profile Hash Table Lookup is disabled on this device. 
This can cause issues when deleting a WiFi profile, forgetting a WiFi network 
or changing its password. For instance, deleting a WLAN profile with 
""netsh wlan delete profile ProfileName"" can fail with ""Element not found.""

Resolution:
To enable WLAN Profile Hash Table Lookup and resolve this issue, please delete 
following registry entry or change its value to 1: 

`t{0}
`tName : {1}
`tType : REG_DWORD
`tValue: 1

This change will require a restart of the ""WLAN AutoConfig"" service to take 
effect.
"

    if($offline) {
        LogWrite "Cannot run offline, skipping"
        return $RETURNCODE_SKIPPED
    }

    # Look for the issue
    try
    {
        $curBuild = [Convert]::ToUInt32($wmi_Win32_OperatingSystem.BuildNumber)
        $minBuild = 10000
        if ($curBuild -lt $minBuild ) {
            LogWrite "OS version $($wmi_Win32_OperatingSystem.Version) not affected, skipping"
            return $RETURNCODE_SKIPPED
        } 

        # Windows 10
        $regKeyPath = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WlanSvc" 
        $regKeySetting = "EnableProfileHashTableLookup"
        $rItemProperty = Get-ItemProperty -Path "Registry::$regKeyPath" -Name $regKeySetting -ErrorAction Ignore

        # Issue if EnableProfileHashTableLookup is set to 0
        if(($rItemProperty) -and ($($rItemProperty.$regKeySetting) -eq 0))
        {
            # Issue detected
            $issueMsg = [string]::Format($issueMsg, $regKeyPath, $regKeySetting)
            ReportIssue $issueMsg $ISSUETYPE_ERROR
        }
    }
	catch {
		LogWrite "Failed - exiting! (Error: $_)"
        return $RETURNCODE_FAILED
    }

    return $RETURNCODE_SUCCESS
}
#endregion net_wlan_KB4557342
#endregion wlan

# end: diagnostic functions

Export-ModuleMember -Function * -Variable *
# SIG # Begin signature block
# MIInygYJKoZIhvcNAQcCoIInuzCCJ7cCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBYIC2Toxa3H9U1
# 0G4EvMCsmy72RQzemfbdBVnDdBTYRqCCDYEwggX/MIID56ADAgECAhMzAAACzI61
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
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgIE8hZEIc
# YraCPcJdMqdD89MoFRMBduJWugWMi7lY8SwwQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQA4bkiWL1eAweMx7qkyGFxAv8c0/WAT6t6q0Z/TKG9v
# vHbp64yQLJBiMcyUFhmCujS0NhGF6O5jR7MmbbwsMR3WgwNu9Zm4sAh+bGATG2Cw
# pbPwVrNKOP8kj58LlT0635RPwcr3N73RZLUAPHKVQc89u+itWxOsj9GX2LJJ2hrU
# FtYccX0KTdGDtizV53tVQyg9rgADwIcAGYHClwc1nxxEheugFeTG0VzER6bkiycs
# JSuSNeTgvthNbCbKjYOD4iGmU/aguaQ6TY7FPvriV4Lg2hIJ24JC5VKhHECiEsJZ
# KEDRI6XJsdLUZSU8p39QiU0aadZDz2cOiRCa2noFYjbJoYIXKTCCFyUGCisGAQQB
# gjcDAwExghcVMIIXEQYJKoZIhvcNAQcCoIIXAjCCFv4CAQMxDzANBglghkgBZQME
# AgEFADCCAVkGCyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEIPPmpoQKO86AdZqyXyz0CiDc3m4uNznpaNNHJV4K
# YHW9AgZjUBtk/XkYEzIwMjIxMDI2MTQyOTUxLjQyNFowBIACAfSggdikgdUwgdIx
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
# CSqGSIb3DQEJBDEiBCCKETI/8quLQtFeYFPIgesnZ2FgpR88Z3UfK3/zE0aJ+DCB
# +gYLKoZIhvcNAQkQAi8xgeowgecwgeQwgb0EIGwneNOyHtovyE16JgYvn/wgGfzN
# R+vv9DuuQzyJzXBBMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIw
# MTACEzMAAAG3IScaB6IqhkYAAQAAAbcwIgQgGeMGQ/+po2xC2zA3wttEvPzv6E6o
# 088k1PA3zlISlhowDQYJKoZIhvcNAQELBQAEggIApveiweVox2gmNisJrgQwYo55
# PcJ/FStoM2go+L5NiQn/rhkP4MCk9lFceI+MrMfov2bcd7KcZA21XBz1UgMiSvIa
# i33eeouHnTpE5uPmMWD8C114/jw9SaSdTltgiY36u8U1xU9WLITQKx/C9vNaR+Mn
# zssdV7nl6KXWgz5nySrqLnpCncCAqhRBP/eCrpWu8YutSwQiWLbvU4jGwodh3/co
# GRxyD0lBLaIIHrsTgy2nMRMyIYMOeQC+TQklB7B3+J21eDfWXfsvp+1R6qpuPGFN
# cySbNkhf6HJ8d3H/nbzLMkmpeA1MnKK64RLDOvh3TfKcb87kgu11PJhXk2oDMURd
# 6VAJNre5vuC+oyhiIZ70V9HvbvxfJYzX9LqVU1atkuu2AnWIkwhZKzgjQ9iLf3Uk
# oPy/cPQa9RKiGqokhVOV7LgT2Fr1S9t11xuetFk1WM0JPCnRl6EayB6I++5Qof2H
# F533nG/++MFVuOp0cCA1MiGljdHlLQkFA/qZKtX+kGLf4zXafGo0xWqZIguqHeYM
# YG7weSVoUH+/+gmlCnsRenVZFyXnntwxx3FBq8SO6NODCcYNJCW4Gw8I9P3CaJr/
# j6iP4qjAKtfHqgduxkxtqwpCdiLGHjVTmqztbf9OmDZ3gsdAo8fEmm6tizYmI2fv
# J0ny4PAhUqqu49/u4ks=
# SIG # End signature block
