#************************************************
# DC_TCPIP-Component.ps1
# Version 1.0: Collects information from the registry, netsh, arp, ipconfig, etc. 
# Version 1.1: Updated IPv6 Transition Technologies section for SKU checks to clean up exceptions.
# Version 1.2: Altered the runPS function correctly a column width issue.
# Version 1.3: Corrected the code for Get-NetCompartment (only runs in WS2012+)
# Version 1.4.09.10.14: Add additional netsh commands for Teredo and ISATAP. TFS264243
# Date: 2009-2014 /WalterE 2019 - GetNetTcpConnEstablished
# Author: Boyd Benson (bbenson@microsoft.com)
# Description: Collects information about TCPIP.
# Called from: Networking Diags
#*******************************************************


Trap [Exception]
	{
	 # Handle exception and throw it to the stdout log file. Then continue with function and script.
		 $Script:ExceptionMessage = $_
		 "[info]: Exception occurred."  | WriteTo-StdOut
		 "[info]: Exception.Message $ExceptionMessage."  | WriteTo-StdOut 
		 $Error.Clear()
		 continue
	}

Import-LocalizedData -BindingVariable ScriptVariable
Write-DiagProgress -Activity $ScriptVariable.ID_CTSTCPIP -Status $ScriptVariable.ID_CTSTCPIPDescription

"[info]:TCPIP-Component:BEGIN" | WriteTo-StdOut


function RunNetSH ([string]$NetSHCommandToExecute="")
{
	Write-DiagProgress -Activity $ScriptVariable.ID_CTSTCPIP -Status "netsh $NetSHCommandToExecute"
	$NetSHCommandToExecuteLength = $NetSHCommandToExecute.Length + 6
	"-" * ($NetSHCommandToExecuteLength)	| Out-File -FilePath $outputFile -append
	"netsh $NetSHCommandToExecute"			| Out-File -FilePath $outputFile -append
	"-" * ($NetSHCommandToExecuteLength)	| Out-File -FilePath $outputFile -append
	$CommandToExecute = "cmd.exe /c netsh.exe " + $NetSHCommandToExecute + " >> $outputFile "
	RunCmD -commandToRun $CommandToExecute  -CollectFiles $false
	"`n`n`n" | Out-File -FilePath $outputFile -append
}


function RunPS ([string]$RunPScmd="", [switch]$ft)
{
	$RunPScmdLength = $RunPScmd.Length
	"-" * ($RunPScmdLength)		| Out-File -FilePath $OutputFile -append
	"$RunPScmd"  				| Out-File -FilePath $OutputFile -append
	"-" * ($RunPScmdLength)  	| Out-File -FilePath $OutputFile -append
	
	if ($ft)
	{
		# This format-table expression is useful to make sure that wide ft output works correctly
		Invoke-Expression $RunPScmd	|format-table -autosize -outvariable $FormatTableTempVar | Out-File -FilePath $outputFile -Width 500 -append
	}
	else
	{
		Invoke-Expression $RunPScmd	| Out-File -FilePath $OutputFile -append
	}
	"`n`n`n" | Out-File -FilePath $outputFile -append
}


function RunNetCmd ([string]$NetCmd="", [string]$NetCmdArg="")
{
	Write-DiagProgress -Activity $ScriptVariable.ID_CTSTCPIP -Status "$NetCmd $NetCmdArg"
	$NetCmdLen = $NetCmd.length
	$NetCmdArgLen = $NetCmdArg.Length
	$NetCmdFullLen = $NetCmdLen + $NetCmdArgLen + 1
	"-" * ($NetCmdFullLen)	| Out-File -FilePath $outputFile -append
	"$NetCmd $NetCmdArg"	| Out-File -FilePath $outputFile -append
	"-" * ($NetCmdFullLen)	| Out-File -FilePath $outputFile -append
	$CommandToExecute = "cmd.exe /c $NetCmd $NetCmdArg >> $outputFile"
	RunCmD -commandToRun $CommandToExecute  -CollectFiles $false
	"`n`n`n" | Out-File -FilePath $outputFile -append
}


function Heading ([string]$header)
{
	"=" * ($borderLen)	| Out-File -FilePath $outputFile -append
	"$header"			| Out-File -FilePath $outputFile -append
	"=" * ($borderLen)	| Out-File -FilePath $outputFile -append
	"`n`n`n" | Out-File -FilePath $outputFile -append
}

function GetNetTcpConnEstablished ()
{
	#get all TCP established connections and match them with its process. Similar output is thrown by using: netstat -ano
	$AllConnections = @()
	$Connections = Get-NetTCPConnection -State Established | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess
	ForEach($Connection In $Connections) {
		$ProcessInfo = Get-Process -PID $Connection.OwningProcess -IncludeUserName | Select-Object Path,UserName,StartTime,Name,Id
		$Obj = New-Object -TypeName PSObject
		Add-Member -InputObject $Obj -MemberType NoteProperty -Name LocalAddress -Value $Connection.LocalAddress
		Add-Member -InputObject $Obj -MemberType NoteProperty -Name LocalPort -Value $Connection.LocalPort
		Add-Member -InputObject $Obj -MemberType NoteProperty -Name RemoteAddress -Value $Connection.RemoteAddress
		Add-Member -InputObject $Obj -MemberType NoteProperty -Name RemotePort -Value $Connection.RemotePort
		Add-Member -InputObject $Obj -MemberType NoteProperty -Name OwningProcessID -Value $Connection.OwningProcess
		Add-Member -InputObject $Obj -MemberType NoteProperty -Name ProcessName -Value $ProcessInfo.Name
		Add-Member -InputObject $Obj -MemberType NoteProperty -Name UserName -Value $ProcessInfo.UserName
		Add-Member -InputObject $Obj -MemberType NoteProperty -Name CommandLine -Value $ProcessInfo.Path
		Add-Member -InputObject $Obj -MemberType NoteProperty -Name StartTime -Value $ProcessInfo.StartTime
		$AllConnections += $Obj
	}
	$AllConnections #|format-table -autosize
}


$sectionDescription = "TCPIP"
$borderLen = 52

# detect OS version and SKU
$wmiOSVersion = Get-CimInstance -Namespace "root\cimv2" -Class Win32_OperatingSystem
[int]$bn = [int]$wmiOSVersion.BuildNumber



####################################################
# General Information
####################################################
#-----MAIN TCPIP INFO  (W2003+)

#----------TCPIP Information from Various Tools
$outputFile = join-path $pwd.path ($ComputerName + "_TCPIP_info.TXT")
"=" * ($borderLen)									| Out-File -FilePath $outputFile -append
"TCPIP Networking Information"						| Out-File -FilePath $OutputFile -append
"=" * ($borderLen)									| Out-File -FilePath $outputFile -append
"Overview"											| Out-File -FilePath $OutputFile -append
"-" * ($borderLen)									| Out-File -FilePath $outputFile -append
"TCPIP Networking Information"						| Out-File -FilePath $OutputFile -append
"   1. hostname"									| Out-File -FilePath $OutputFile -append
"   2. ipconfig /allcompartments /all"				| Out-File -FilePath $OutputFile -append
"   3. route print"									| Out-File -FilePath $OutputFile -append
"   4. arp -a"										| Out-File -FilePath $OutputFile -append
"   5. netstat -nato" 								| Out-File -FilePath $OutputFile -append
"   6. netstat -anob"								| Out-File -FilePath $OutputFile -append
"   7. netstat -es" 								| Out-File -FilePath $OutputFile -append
"=" * ($borderLen)									| Out-File -FilePath $outputFile -append
"`n`n`n`n`n" | Out-File -FilePath $outputFile -append

Heading "TCPIP Networking Information"
RunNetCmd "hostname"
# 4/17/14: If WV/WS2008, run "ipconfig /allcompartments /all". If WXP/WS2003 "ipconfig /all".
if ($bn -gt 6000)
{ RunNetCmd "ipconfig" "/allcompartments /all" }
else
{ RunNetCmd "ipconfig" "/all" }
RunNetCmd "route print"
RunNetCmd "arp" "-a"
RunNetCmd "netstat" "-nato"
RunNetCmd "netstat" "-anob"
RunNetCmd "netstat" "-es"
CollectFiles -filesToCollect $outputFile -fileDescription "TCPIP Info" -SectionDescription $sectionDescription

#----------Registry (General)
$outputFile = join-path $pwd.path ($ComputerName + "_TCPIP_reg_output.TXT")
$CurrentVersionKeys =	"HKLM\SOFTWARE\Policies\Microsoft\Windows\TCPIP",
						"HKLM\SYSTEM\CurrentControlSet\services\TCPIP",
						"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6",
						"HKLM\SYSTEM\CurrentControlSet\Services\tcpipreg",
						"HKLM\SYSTEM\CurrentControlSet\Services\iphlpsvc"
RegQuery -RegistryKeys $CurrentVersionKeys -Recursive $true -outputFile $outputFile -fileDescription "TCPIP registry output" -SectionDescription $sectionDescription

#----------TCP OFFLOAD (netsh)
$outputFile = join-path $pwd.path ($ComputerName + "_TCPIP_OFFLOAD.TXT")

"=" * ($borderLen)								| Out-File -FilePath $outputFile -append
"TCPIP Offload Information"						| Out-File -FilePath $OutputFile -append
"=" * ($borderLen)								| Out-File -FilePath $outputFile -append
"Overview"										| Out-File -FilePath $OutputFile -append
"-" * ($borderLen)								| Out-File -FilePath $outputFile -append
"TCPIP Offload Information"						| Out-File -FilePath $OutputFile -append
"  1. netsh int tcp show global"				| Out-File -FilePath $outputFile -Append
"  2. netsh int ipv4 show offload"				| Out-File -FilePath $outputFile -Append
"  3. netstat -nato -p tcp"						| Out-File -FilePath $outputFile -Append
"=" * ($borderLen)								| Out-File -FilePath $outputFile -Append
"`n`n`n`n`n" | Out-File -FilePath $outputFile -append
RunNetCmd "netsh" "int tcp show global"
RunNetCmd "netsh" "int ipv4 show offload"
RunNetCmd "netstat" "-nato -p tcp"

CollectFiles -filesToCollect $outputFile -fileDescription "TCP OFFLOAD" -SectionDescription $sectionDescription

#----------Copy the Services File
$outputFile = join-path $pwd.path ($ComputerName + "_TCPIP_ServicesFile.TXT")

$servicesfile = "$ENV:windir\system32\drivers\etc\services"
if (test-path $servicesfile)
{
  Copy-Item -Path $servicesfile -Destination $outputFile
  CollectFiles -filesToCollect $outputFile -fileDescription "TCPIP Services File" -SectionDescription $sectionDescription
}
else
{
	"$servicesfile Does not exist" | writeto-stdout
}

# W8/WS2012
if ($bn -gt 9000)
{
	"[info]: TCPIP-Component W8/WS2012+" | WriteTo-StdOut

	####################################################
	# TCPIP Transition Technologies
	####################################################
	$outputFile = join-path $pwd.path ($ComputerName + "_TCPIP_info_pscmdlets_net.TXT")

	"=" * ($borderLen)									| Out-File -FilePath $outputFile -append
	"TCPIP Powershell Cmdlets"							| Out-File -FilePath $OutputFile -append
	"=" * ($borderLen)									| Out-File -FilePath $outputFile -append
	"Overview"											| Out-File -FilePath $OutputFile -append
	"-" * ($borderLen)									| Out-File -FilePath $outputFile -append
	"   1. Get-NetCompartment (WS2012+)"				| Out-File -FilePath $OutputFile -append
	"   2. Get-NetIPAddress"							| Out-File -FilePath $OutputFile -append	
	"   3. Get-NetIPInterface"							| Out-File -FilePath $OutputFile -append
	"   4. Get-NetIPConfiguration"						| Out-File -FilePath $OutputFile -append
	"   5. Get-NetIPv4Protocol"							| Out-File -FilePath $OutputFile -append
	"   6. Get-NetIPv6Protocol"							| Out-File -FilePath $OutputFile -append
	"   7. Get-NetOffloadGlobalSetting"					| Out-File -FilePath $OutputFile -append
	"   8. Get-NetPrefixPolicy"							| Out-File -FilePath $OutputFile -append
	"   9. Get-NetRoute -IncludeAllCompartments"		| Out-File -FilePath $OutputFile -append
	"  10. Get-NetTCPConnection"						| Out-File -FilePath $OutputFile -append
	"  10a. GetNetTCPConnEstablished"					| Out-File -FilePath $OutputFile -append
	"  11. Get-NetTransportFilter"						| Out-File -FilePath $OutputFile -append
	"  12. Get-NetTCPSetting"							| Out-File -FilePath $OutputFile -append
	"  13. Get-NetUDPEndpoint"							| Out-File -FilePath $OutputFile -append
	"  14. Get-NetUDPSetting"							| Out-File -FilePath $OutputFile -append
	"=" * ($borderLen)									| Out-File -FilePath $outputFile -append
	"`n`n`n`n`n" | Out-File -FilePath $outputFile -append

	if ($bn -ge 9600)
	{
		RunPS "Get-NetCompartment"							# W8/WS2012, W8.1/WS2012R2	# fl
	}
	else
	{
		$RunPScmd = "Get-NetCompartment"
		$RunPScmdLength = $RunPScmd.Length
		"-" * ($RunPScmdLength)		| Out-File -FilePath $OutputFile -append
		"$RunPScmd"  				| Out-File -FilePath $OutputFile -append
		"-" * ($RunPScmdLength)  	| Out-File -FilePath $OutputFile -append
		"The Get-NetCompartment pscmdlet is only available in WS2012R2+."	| Out-File -FilePath $OutputFile -append
	}
	RunPS "Get-NetIPAddress"							# W8/WS2012, W8.1/WS2012R2	# fl
	RunPS "Get-NetIPInterface"						-ft	# W8/WS2012, W8.1/WS2012R2	# ft
	RunPS "Get-NetIPConfiguration"						# W8/WS2012, W8.1/WS2012R2	# fl
	RunPS "Get-NetIPv4Protocol"							# W8/WS2012, W8.1/WS2012R2	# fl
	RunPS "Get-NetIPv6Protocol"							# W8/WS2012, W8.1/WS2012R2	# fl
	RunPS "Get-NetOffloadGlobalSetting"					# W8/WS2012, W8.1/WS2012R2	# fl
	RunPS "Get-NetPrefixPolicy"						-ft	# W8/WS2012, W8.1/WS2012R2	# ft
	RunPS "Get-NetRoute -IncludeAllCompartments"	-ft	# W8/WS2012, W8.1/WS2012R2	# ft
	RunPS "Get-NetTCPConnection"					-ft	# W8/WS2012, W8.1/WS2012R2	# ft
	RunPS "GetNetTCPConnEstablished"				-ft	# 
	RunPS "Get-NetTransportFilter"						# W8/WS2012, W8.1/WS2012R2	# fl
	RunPS "Get-NetTCPSetting"							# W8/WS2012, W8.1/WS2012R2	# fl
	RunPS "Get-NetUDPEndpoint"						-ft	# W8/WS2012, W8.1/WS2012R2	# ft
	RunPS "Get-NetUDPSetting"							# W8/WS2012, W8.1/WS2012R2	# fl

	CollectFiles -filesToCollect $outputFile -fileDescription "TCPIP Net Powershell Cmdlets" -SectionDescription $sectionDescription
}

# W8/WS2012
if ($bn -gt 9000)
{
	####################################################
	# TCPIP IPv6 Transition Technologies
	####################################################
	$outputFile = join-path $pwd.path ($ComputerName + "_TCPIP_info_pscmdlets_IPv6Transition.TXT")
	"=" * ($borderLen)									| Out-File -FilePath $outputFile -append
	"IPv6 Transition Technologies Powershell Cmdlets"	| Out-File -FilePath $OutputFile -append
	"=" * ($borderLen)									| Out-File -FilePath $outputFile -append
	"Overview"											| Out-File -FilePath $OutputFile -append
	"-" * ($borderLen)									| Out-File -FilePath $outputFile -append
	"   1. Get-Net6to4Configuration"					| Out-File -FilePath $OutputFile -append
	"   2. Get-NetDnsTransitionConfiguration"			| Out-File -FilePath $OutputFile -append
	"   3. Get-NetDnsTransitionMonitoring"				| Out-File -FilePath $OutputFile -append
	"   4. Get-NetIPHttpsConfiguration"					| Out-File -FilePath $OutputFile -append
	"   5. Get-NetIsatapConfiguration"					| Out-File -FilePath $OutputFile -append
	"   6. Get-NetNatTransitionConfiguration"			| Out-File -FilePath $OutputFile -append
	"   7. Get-NetNatTransitionMonitoring"				| Out-File -FilePath $OutputFile -append
	"   8. Get-NetTeredoConfiguration"					| Out-File -FilePath $OutputFile -append
	"   9. Get-NetTeredoState"							| Out-File -FilePath $OutputFile -append
	"=" * ($borderLen)									| Out-File -FilePath $outputFile -append
	"`n`n`n`n`n" | Out-File -FilePath $outputFile -append

	#Get role, OSVer, hotfix data.
	$cs =  Get-CimInstance -Namespace "root\cimv2" -class win32_computersystem #-ComputerName $ComputerName
	$DomainRole = $cs.domainrole
	
	if ($DomainRole -ge 2)	
	{
		RunPS "Get-Net6to4Configuration"				# W8/WS2012, W8.1/WS2012R2	#fl
		RunPS "Get-NetDnsTransitionConfiguration"		# W8/WS2012, W8.1/WS2012R2	#fl		# server only
		RunPS "Get-NetDnsTransitionMonitoring"			# W8/WS2012, W8.1/WS2012R2	#fl 	# server only
	}
	else
	{
		"------------------------" 									| Out-File -FilePath $outputFile -append
		"Get-Net6to4Configuration"	| Out-File -FilePath $OutputFile -append
		"------------------------" 									| Out-File -FilePath $outputFile -append
		"Not running pscmdlet on non-server SKUs." | Out-File -FilePath $OutputFile -append
		"`n`n`n"	| Out-File -FilePath $OutputFile -append
		"---------------------------------" | Out-File -FilePath $outputFile -append
		"Get-NetDnsTransitionConfiguration" | Out-File -FilePath $OutputFile -append
		"---------------------------------" | Out-File -FilePath $outputFile -append
		"Not running pscmdlet on non-server SKUs."	| Out-File -FilePath $OutputFile -append
		"`n`n`n"	| Out-File -FilePath $OutputFile -append
		"------------------------------" | Out-File -FilePath $outputFile -append
		"Get-NetDnsTransitionMonitoring" | Out-File -FilePath $OutputFile -append
		"------------------------------" | Out-File -FilePath $outputFile -append
		"Not running pscmdlet on non-server SKUs."	| Out-File -FilePath $OutputFile -append
		"`n`n`n"	| Out-File -FilePath $OutputFile -append
	}
	RunPS "Get-NetIPHttpsConfiguration"					# W8/WS2012, W8.1/WS2012R2	#fl
	RunPS "Get-NetIPHttpsState"							# W8/WS2012, W8.1/WS2012R2	#fl
	RunPS "Get-NetIsatapConfiguration"					# W8/WS2012, W8.1/WS2012R2	#fl
	
	if ($cs.DomainRole -ge 2)	
	{
		RunPS "Get-NetNatTransitionConfiguration"		# W8/WS2012, W8.1/WS2012R2	#fl 	#server only
		RunPS "Get-NetNatTransitionMonitoring"		-ft	# W8/WS2012, W8.1/WS2012R2	#ft		#server only
	}
	else
	{
		"---------------------------------" 		| Out-File -FilePath $outputFile -append
		"Get-NetNatTransitionConfiguration"	| Out-File -FilePath $OutputFile -append
		"---------------------------------" 		| Out-File -FilePath $outputFile -append
		"Not running pscmdlet on non-server SKUs." | Out-File -FilePath $OutputFile -append
		"`n`n`n"	| Out-File -FilePath $OutputFile -append
		"------------------------------" 		| Out-File -FilePath $outputFile -append
		"Get-NetNatTransitionMonitoring"			| Out-File -FilePath $OutputFile -append
		"------------------------------" 		| Out-File -FilePath $outputFile -append
		"Not running pscmdlet on non-server SKUs."	| Out-File -FilePath $OutputFile -append
		"`n`n`n"	| Out-File -FilePath $OutputFile -append
	}
	RunPS "Get-NetTeredoConfiguration"					# W8/WS2012, W8.1/WS2012R2	#fl
	RunPS "Get-NetTeredoState"							# W8/WS2012, W8.1/WS2012R2	#fl

	CollectFiles -filesToCollect $outputFile -fileDescription "TCPIP IPv6 Transition Technology Info" -SectionDescription $sectionDescription	
}

#V/WS2008+
if ($bn -gt 6000)
{
	"[info]: TCPIP-Component WV/WS2008+" | WriteTo-StdOut
	$outputFile = join-path $pwd.path ($ComputerName + "_TCPIP_netsh_info.TXT")

	"=" * ($borderLen)									| Out-File -FilePath $outputFile -append
	"TCPIP Netsh Commands"								| Out-File -FilePath $OutputFile -append
	"=" * ($borderLen)									| Out-File -FilePath $outputFile -append
	"Overview"											| Out-File -FilePath $OutputFile -append
	"-" * ($borderLen)									| Out-File -FilePath $outputFile -append
	"TCP Netsh Commands"								| Out-File -FilePath $OutputFile -append
	"   1. netsh int tcp show global"					| Out-File -FilePath $OutputFile -append
	"   2. netsh int tcp show heuristics"						| Out-File -FilePath $OutputFile -append
	"   3. netsh int tcp show chimneyapplications"		| Out-File -FilePath $OutputFile -append
	"   4. netsh int tcp show chimneyports"				| Out-File -FilePath $OutputFile -append
	"   5. netsh int tcp show chimneystats"				| Out-File -FilePath $OutputFile -append
	"   6. netsh int tcp show netdmastats"				| Out-File -FilePath $OutputFile -append
	"   7. netsh int tcp show rscstats"					| Out-File -FilePath $OutputFile -append
	"   8. netsh int tcp show security"					| Out-File -FilePath $OutputFile -append
	"   9. netsh int tcp show supplemental"				| Out-File -FilePath $OutputFile -append
	"  10. netsh int tcp show supplementalports"		| Out-File -FilePath $OutputFile -append
	"  11. netsh int tcp show supplementalsubnets"		| Out-File -FilePath $OutputFile -append
	"-" * ($borderLen)									| Out-File -FilePath $outputFile -append
	"IPv4 Netsh Commands"								| Out-File -FilePath $OutputFile -append
	"   1. netsh int show int"							| Out-File -FilePath $OutputFile -append
	"   2. netsh int ipv4 show int"						| Out-File -FilePath $OutputFile -append
	"   3. netsh int ipv4 show addresses"				| Out-File -FilePath $OutputFile -append
	"   4. netsh int ipv4 show ipaddresses"				| Out-File -FilePath $OutputFile -append
	"   5. netsh int ipv4 show compartments"			| Out-File -FilePath $OutputFile -append
	"   6. netsh int ipv4 show dnsservers"				| Out-File -FilePath $OutputFile -append
	"   7. netsh int ipv4 show winsservers"				| Out-File -FilePath $OutputFile -append
	"   8. netsh int ipv4 show dynamicportrange tcp"	| Out-File -FilePath $OutputFile -append
	"   9. netsh int ipv4 show dynamicportrange udp"	| Out-File -FilePath $OutputFile -append
	"  10. netsh int ipv4 show global"					| Out-File -FilePath $OutputFile -append
	"  11. netsh int ipv4 show icmpstats"				| Out-File -FilePath $OutputFile -append
	"  12. netsh int ipv4 show ipstats"					| Out-File -FilePath $OutputFile -append
	"  13. netsh int ipv4 show joins"					| Out-File -FilePath $OutputFile -append
	"  14. netsh int ipv4 show offload"					| Out-File -FilePath $OutputFile -append
	"  15. netsh int ipv4 show route"					| Out-File -FilePath $OutputFile -append
	"  16. netsh int ipv4 show subint"					| Out-File -FilePath $OutputFile -append
	"  17. netsh int ipv4 show tcpconnections"			| Out-File -FilePath $OutputFile -append
	"  18. netsh int ipv4 show tcpstats"				| Out-File -FilePath $OutputFile -append
	"  19. netsh int ipv4 show udpconnections"			| Out-File -FilePath $OutputFile -append
	"  20. netsh int ipv4 show udpstats"				| Out-File -FilePath $OutputFile -append
	"  21. netsh int ipv4 show destinationcache"		| Out-File -FilePath $OutputFile -append
	"  22. netsh int ipv4 show ipnettomedia"			| Out-File -FilePath $OutputFile -append
	"  23. netsh int ipv4 show neighbors"				| Out-File -FilePath $OutputFile -append
	"-" * ($borderLen)									| Out-File -FilePath $outputFile -append
	"IPv6 Netsh Commands"								| Out-File -FilePath $OutputFile -append
	"   1. netsh int show int"							| Out-File -FilePath $OutputFile -append	
	"   2. netsh int ipv6 show int"						| Out-File -FilePath $OutputFile -append
	"   3. netsh int ipv6 show addresses"				| Out-File -FilePath $OutputFile -append
	"   4. netsh int ipv6 show compartments"			| Out-File -FilePath $OutputFile -append
	"   5. netsh int ipv6 show destinationcache"		| Out-File -FilePath $OutputFile -append
	"   6. netsh int ipv6 show dnsservers"				| Out-File -FilePath $OutputFile -append
	"   7. netsh int ipv6 show dynamicportrange tcp"	| Out-File -FilePath $OutputFile -append
	"   8. netsh int ipv6 show dynamicportrange udp"	| Out-File -FilePath $OutputFile -append
	"   9. netsh int ipv6 show global"					| Out-File -FilePath $OutputFile -append
	"  10. netsh int ipv6 show ipstats"					| Out-File -FilePath $OutputFile -append
	"  11. netsh int ipv6 show joins"					| Out-File -FilePath $OutputFile -append
	"  12. netsh int ipv6 show neighbors"				| Out-File -FilePath $OutputFile -append
	"  13. netsh int ipv6 show offload"					| Out-File -FilePath $OutputFile -append
	"  14. netsh int ipv6 show potentialrouters"		| Out-File -FilePath $OutputFile -append
	"  15. netsh int ipv6 show prefixpolicies"			| Out-File -FilePath $OutputFile -append
	"  16. netsh int ipv6 show privacy"					| Out-File -FilePath $OutputFile -append
	"  17. netsh int ipv6 show route"					| Out-File -FilePath $OutputFile -append
	"  18. netsh int ipv6 show siteprefixes"			| Out-File -FilePath $OutputFile -append
	"  19. netsh int ipv6 show subint"					| Out-File -FilePath $OutputFile -append
	"  20. netsh int ipv6 show tcpstats"				| Out-File -FilePath $OutputFile -append
	"  21. netsh int ipv6 show teredo"					| Out-File -FilePath $OutputFile -append
	"  22. netsh int ipv6 show udpstats"				| Out-File -FilePath $OutputFile -append
	"-" * ($borderLen)									| Out-File -FilePath $outputFile -append
	"IPv6 Transition Technologies"						| Out-File -FilePath $OutputFile -append
	"   1. netsh int ipv6 show int"						| Out-File -FilePath $OutputFile -append
	"   2. netsh int 6to4 show int"						| Out-File -FilePath $OutputFile -append
	"   3. netsh int 6to4 show relay"					| Out-File -FilePath $OutputFile -append
	"   4. netsh int 6to4 show routing"					| Out-File -FilePath $OutputFile -append
	"   5. netsh int 6to4 show state"					| Out-File -FilePath $OutputFile -append
	"   6. netsh int httpstunnel show interfaces"		| Out-File -FilePath $OutputFile -append
	"   7. netsh int httpstunnel show statistics"		| Out-File -FilePath $OutputFile -append
	"   8. netsh int isatap show router"				| Out-File -FilePath $OutputFile -append
	"   9. netsh int isatap show state"					| Out-File -FilePath $OutputFile -append
	"  10. netsh int teredo show state"					| Out-File -FilePath $OutputFile -append
	"  11. netsh int ipv6 show int level=verbose"		| Out-File -FilePath $OutputFile -append
	"-" * ($borderLen)									| Out-File -FilePath $outputFile -append
	"NetIO Netsh Commands"								| Out-File -FilePath $OutputFile -append
	"   1. netio show bindingfilters"					| Out-File -FilePath $OutputFile -append
	"-" * ($borderLen)									| Out-File -FilePath $outputFile -append
	"PortProxy"	| Out-File -FilePath $OutputFile -append
	"   1. netsh int portproxy show all"	| Out-File -FilePath $OutputFile -append
	"=" * ($borderLen)									| Out-File -FilePath $outputFile -append
	"`n`n`n`n`n"	| Out-File -FilePath $OutputFile -append
	
	Heading "TCP Netsh Commands"
	RunNetCmd "netsh" "int tcp show global"
	RunNetCmd "netsh" "int tcp show heuristics"
	RunNetCmd "netsh" "int tcp show chimneyapplications"
	RunNetCmd "netsh" "int tcp show chimneyports"
	RunNetCmd "netsh" "int tcp show chimneystats"
	RunNetCmd "netsh" "int tcp show netdmastats"
	RunNetCmd "netsh" "int tcp show rscstats"
	RunNetCmd "netsh" "int tcp show security"
	RunNetCmd "netsh" "int tcp show supplemental"
	RunNetCmd "netsh" "int tcp show supplementalports"
	RunNetCmd "netsh" "int tcp show supplementalsubnets"

	Heading "IPv4 Netsh Commands"
	RunNetCmd "netsh" "int show int"
	RunNetCmd "netsh" "int ipv4 show int"
	RunNetCmd "netsh" "int ipv4 show addresses"
	RunNetCmd "netsh" "int ipv4 show ipaddresses"
	RunNetCmd "netsh" "int ipv4 show compartments"
	RunNetCmd "netsh" "int ipv4 show dnsservers"
	RunNetCmd "netsh" "int ipv4 show winsservers"
	RunNetCmd "netsh" "int ipv4 show dynamicportrange tcp"
	RunNetCmd "netsh" "int ipv4 show dynamicportrange udp"
	RunNetCmd "netsh" "int ipv4 show global"
	RunNetCmd "netsh" "int ipv4 show icmpstats"
	RunNetCmd "netsh" "int ipv4 show ipstats"
	RunNetCmd "netsh" "int ipv4 show joins"
	RunNetCmd "netsh" "int ipv4 show offload"
	RunNetCmd "netsh" "int ipv4 show route"
	RunNetCmd "netsh" "int ipv4 show subint"
	RunNetCmd "netsh" "int ipv4 show tcpconnections"
	RunNetCmd "netsh" "int ipv4 show tcpstats"
	RunNetCmd "netsh" "int ipv4 show udpconnections"
	RunNetCmd "netsh" "int ipv4 show udpstats"
	RunNetCmd "netsh" "int ipv4 show destinationcache"
	RunNetCmd "netsh" "int ipv4 show ipnettomedia"
	RunNetCmd "netsh" "int ipv4 show neighbors"

	Heading "IPv6 Netsh Commands"
	RunNetCmd "netsh" "int show int"
	RunNetCmd "netsh" "int ipv6 show int"
	RunNetCmd "netsh" "int ipv6 show addresses"
	RunNetCmd "netsh" "int ipv6 show compartments"
	RunNetCmd "netsh" "int ipv6 show destinationcache"
	RunNetCmd "netsh" "int ipv6 show dnsservers"
	RunNetCmd "netsh" "int ipv6 show dynamicportrange tcp"
	RunNetCmd "netsh" "int ipv6 show dynamicportrange udp"
	RunNetCmd "netsh" "int ipv6 show global"
	RunNetCmd "netsh" "int ipv6 show ipstats"
	RunNetCmd "netsh" "int ipv6 show joins"
	RunNetCmd "netsh" "int ipv6 show neighbors"
	RunNetCmd "netsh" "int ipv6 show offload"
	RunNetCmd "netsh" "int ipv6 show potentialrouters"
	RunNetCmd "netsh" "int ipv6 show prefixpolicies"
	RunNetCmd "netsh" "int ipv6 show privacy"
	RunNetCmd "netsh" "int ipv6 show route"
	RunNetCmd "netsh" "int ipv6 show siteprefixes"
	RunNetCmd "netsh" "int ipv6 show siteprefixes"
	RunNetCmd "netsh" "int ipv6 show subint"
	RunNetCmd "netsh" "int ipv6 show tcpstats"
	RunNetCmd "netsh" "int ipv6 show teredo"
	RunNetCmd "netsh" "int ipv6 show udpstats"
	
	Heading "IPv6 Transition Technologies"
	RunNetCmd "netsh" "int ipv6 show int"
	RunNetCmd "netsh" "int 6to4 show int"
	RunNetCmd "netsh" "int 6to4 show relay"
	RunNetCmd "netsh" "int 6to4 show routing"
	RunNetCmd "netsh" "int 6to4 show state"
	RunNetCmd "netsh" "int httpstunnel show interfaces"
	RunNetCmd "netsh" "int httpstunnel show statistics"
	RunNetCmd "netsh int isatap show router"
	RunNetCmd "netsh int isatap show state"	
	RunNetCmd "netsh int teredo show state"	
	RunNetCmd "netsh" "int ipv6 show int level=verbose"

	Heading "NetIO Netsh Commands"
	RunNetCmd "netsh" "netio show bindingfilters"

	Heading "PortProxy"
	RunNetCmd "netsh" "int portproxy show all"
	
	CollectFiles -filesToCollect $outputFile -fileDescription "TCPIP netsh output" -SectionDescription $sectionDescription

	#----------Iphlpsvc EventLog
	#----------WLAN Autoconfig EventLog
	#Iphlpsvc
	$EventLogNames = @()
	$EventLogNames += "Microsoft-Windows-Iphlpsvc/Operational"
	$EventLogNames += "Microsoft-Windows-WLAN-AutoConfig/Operational"

	$Prefix = ""
	$Suffix = "_evt_"
	.\TS_GetEvents.ps1 -EventLogNames $EventLogNames -SectionDescription $sectionDescription -Prefix $Prefix -Suffix $Suffix

}
else # XP/WS2003
{
	"[info]: TCPIP-Component XP/WS2003+" | WriteTo-StdOut
	$outputFile = join-path $pwd.path ($ComputerName + "_TCPIP_netsh_info.TXT")
	
	#----------Netsh for IP (XP/W2003)
	"`n`n`n`n`n" + "=" * (50) + "`r`n[NETSH INT IP]`r`n" + "=" * (50) | Out-File -FilePath $outputFile -Append
	"`n`n"
	"`n" + "-" * (50) + "`r`n[netsh int ipv4 show output]`r`n" + "-" * (50) | Out-File -FilePath $outputFile -Append
	RunNetCmd "netsh" "int show int"
	RunNetCmd "netsh" "int ip show int"
	RunNetCmd "netsh" "int ip show address"
	RunNetCmd "netsh" "int ip show config"
	RunNetCmd "netsh" "int ip show dns"
	RunNetCmd "netsh" "int ip show joins"
	RunNetCmd "netsh" "int ip show offload"
	RunNetCmd "netsh" "int ip show wins"

	# If RRAS is running, run the following commands
	if ((Get-Service "remoteaccess").Status -eq 'Running')
	{
		RunNetCmd "netsh" "int ip show icmp"
		RunNetCmd "netsh" "int ip show interface"
		RunNetCmd "netsh" "int ip show ipaddress"
		RunNetCmd "netsh" "int ip show ipnet"
		RunNetCmd "netsh" "int ip show ipstats"
		RunNetCmd "netsh" "int ip show tcpconn"
		RunNetCmd "netsh" "int ip show tcpstats"
		RunNetCmd "netsh" "int ip show udpconn"
		RunNetCmd "netsh" "int ip show udpstats"
	}
	CollectFiles -filesToCollect $outputFile -fileDescription "TCPIP netsh output" -SectionDescription $sectionDescription
}

"[info]:TCPIP-Component:END" | WriteTo-StdOut



# SIG # Begin signature block
# MIInpAYJKoZIhvcNAQcCoIInlTCCJ5ECAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCU1lEYewn0dC/j
# MW+DU9SqGSHg6rwCZbXDfgX9ZBTR0aCCDYUwggYDMIID66ADAgECAhMzAAACzfNk
# v/jUTF1RAAAAAALNMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjIwNTEyMjA0NjAyWhcNMjMwNTExMjA0NjAyWjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDrIzsY62MmKrzergm7Ucnu+DuSHdgzRZVCIGi9CalFrhwtiK+3FIDzlOYbs/zz
# HwuLC3hir55wVgHoaC4liQwQ60wVyR17EZPa4BQ28C5ARlxqftdp3H8RrXWbVyvQ
# aUnBQVZM73XDyGV1oUPZGHGWtgdqtBUd60VjnFPICSf8pnFiit6hvSxH5IVWI0iO
# nfqdXYoPWUtVUMmVqW1yBX0NtbQlSHIU6hlPvo9/uqKvkjFUFA2LbC9AWQbJmH+1
# uM0l4nDSKfCqccvdI5l3zjEk9yUSUmh1IQhDFn+5SL2JmnCF0jZEZ4f5HE7ykDP+
# oiA3Q+fhKCseg+0aEHi+DRPZAgMBAAGjggGCMIIBfjAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQU0WymH4CP7s1+yQktEwbcLQuR9Zww
# VAYDVR0RBE0wS6RJMEcxLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJh
# dGlvbnMgTGltaXRlZDEWMBQGA1UEBRMNMjMwMDEyKzQ3MDUzMDAfBgNVHSMEGDAW
# gBRIbmTlUAXTgqoXNzcitW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8v
# d3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIw
# MTEtMDctMDguY3JsMGEGCCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDEx
# XzIwMTEtMDctMDguY3J0MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIB
# AE7LSuuNObCBWYuttxJAgilXJ92GpyV/fTiyXHZ/9LbzXs/MfKnPwRydlmA2ak0r
# GWLDFh89zAWHFI8t9JLwpd/VRoVE3+WyzTIskdbBnHbf1yjo/+0tpHlnroFJdcDS
# MIsH+T7z3ClY+6WnjSTetpg1Y/pLOLXZpZjYeXQiFwo9G5lzUcSd8YVQNPQAGICl
# 2JRSaCNlzAdIFCF5PNKoXbJtEqDcPZ8oDrM9KdO7TqUE5VqeBe6DggY1sZYnQD+/
# LWlz5D0wCriNgGQ/TWWexMwwnEqlIwfkIcNFxo0QND/6Ya9DTAUykk2SKGSPt0kL
# tHxNEn2GJvcNtfohVY/b0tuyF05eXE3cdtYZbeGoU1xQixPZAlTdtLmeFNly82uB
# VbybAZ4Ut18F//UrugVQ9UUdK1uYmc+2SdRQQCccKwXGOuYgZ1ULW2u5PyfWxzo4
# BR++53OB/tZXQpz4OkgBZeqs9YaYLFfKRlQHVtmQghFHzB5v/WFonxDVlvPxy2go
# a0u9Z+ZlIpvooZRvm6OtXxdAjMBcWBAsnBRr/Oj5s356EDdf2l/sLwLFYE61t+ME
# iNYdy0pXL6gN3DxTVf2qjJxXFkFfjjTisndudHsguEMk8mEtnvwo9fOSKT6oRHhM
# 9sZ4HTg/TTMjUljmN3mBYWAWI5ExdC1inuog0xrKmOWVMIIHejCCBWKgAwIBAgIK
# YQ6Q0gAAAAAAAzANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlm
# aWNhdGUgQXV0aG9yaXR5IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEw
# OTA5WjB+MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYD
# VQQDEx9NaWNyb3NvZnQgQ29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG
# 9w0BAQEFAAOCAg8AMIICCgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+la
# UKq4BjgaBEm6f8MMHt03a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc
# 6Whe0t+bU7IKLMOv2akrrnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4D
# dato88tt8zpcoRb0RrrgOGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+
# lD3v++MrWhAfTVYoonpy4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nk
# kDstrjNYxbc+/jLTswM9sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6
# A4aN91/w0FK/jJSHvMAhdCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmd
# X4jiJV3TIUs+UsS1Vz8kA/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL
# 5zmhD+kjSbwYuER8ReTBw3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zd
# sGbiwZeBe+3W7UvnSSmnEyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3
# T8HhhUSJxAlMxdSlQy90lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS
# 4NaIjAsCAwEAAaOCAe0wggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRI
# bmTlUAXTgqoXNzcitW2oynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTAL
# BgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBD
# uRQFTuHqp8cx0SOJNDBaBgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jv
# c29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFf
# MDNfMjIuY3JsMF4GCCsGAQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFf
# MDNfMjIuY3J0MIGfBgNVHSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEF
# BQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1h
# cnljcHMuaHRtMEAGCCsGAQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkA
# YwB5AF8AcwB0AGEAdABlAG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn
# 8oalmOBUeRou09h0ZyKbC5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7
# v0epo/Np22O/IjWll11lhJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0b
# pdS1HXeUOeLpZMlEPXh6I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/
# KmtYSWMfCWluWpiW5IP0wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvy
# CInWH8MyGOLwxS3OW560STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBp
# mLJZiWhub6e3dMNABQamASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJi
# hsMdYzaXht/a8/jyFqGaJ+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYb
# BL7fQccOKO7eZS/sl/ahXJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbS
# oqKfenoi+kiVH6v7RyOA9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sL
# gOppO6/8MO0ETI7f33VtY5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtX
# cVZOSEXAQsmbdlsKgEhr/Xmfwb1tbWrJUnMTDXpQzTGCGXUwghlxAgEBMIGVMH4x
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01p
# Y3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTECEzMAAALN82S/+NRMXVEAAAAA
# As0wDQYJYIZIAWUDBAIBBQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQw
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEID/W
# M5x748U21THw3KdlypMLxAfbXwsG4kRpDKIUdq+OMEQGCisGAQQBgjcCAQwxNjA0
# oBSAEgBNAGkAYwByAG8AcwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQu
# Y29tIDANBgkqhkiG9w0BAQEFAASCAQBf14w42v0fgxUtEBzrYq75gi14HeikC73b
# utY835PVYtfIEvEnXzBb09ImPeLopg4IlExX2bDxQDXnVQNFFMJi8zH+aGt5KiGr
# Se966Vy7qZG2/Xo5pbCoJEPymltWhYnDW15mTHr8eyBxoEdDmcnhSLfqivkm2AOI
# RijgzSY/+eXOhoK2rSIh0ekb2WqOsA5rLKiDV6a+qi9MRVUmnjBcofsAehH+0E72
# 65ATDG/S3cOn6EMi/BUoUYL/7IkLJ7qCypE6t1VZnxqzLpUixCZCCetmevUfGrTX
# dtV+YRIIltqSlK87VClHuVbvY/fCx7LSr5Dk4sXnsEKI1y4VCTl+oYIW/TCCFvkG
# CisGAQQBgjcDAwExghbpMIIW5QYJKoZIhvcNAQcCoIIW1jCCFtICAQMxDzANBglg
# hkgBZQMEAgEFADCCAVEGCyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEE
# AYRZCgMBMDEwDQYJYIZIAWUDBAIBBQAEIBzUwyyhb7vWXARRyQ4Czm2Hey31Pnqe
# j8nEUfFJ3Y1cAgZjSBdxmisYEzIwMjIxMDI0MDgxNTMzLjQwMVowBIACAfSggdCk
# gc0wgcoxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNV
# BAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxl
# cyBUU1MgRVNOOjNFN0EtRTM1OS1BMjVEMSUwIwYDVQQDExxNaWNyb3NvZnQgVGlt
# ZS1TdGFtcCBTZXJ2aWNloIIRVDCCBwwwggT0oAMCAQICEzMAAAGg6buMuw6i0XoA
# AQAAAaAwDQYJKoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIw
# MTAwHhcNMjExMjAyMTkwNTIzWhcNMjMwMjI4MTkwNTIzWjCByjELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFt
# ZXJpY2EgT3BlcmF0aW9uczEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046M0U3QS1F
# MzU5LUEyNUQxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2Uw
# ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC/2uIOaHGdAOj2YvhhI6C8
# iFAq7wrl/5WpPjj0fEHCi6Ivx/I02Jss/HVhkfGTMGttR5jRhhrJXydWDnOmzRU3
# B4G525T7pwkFNFBXumM/98l5k0U2XiaZ+bulXHe54x6uj/6v5VGFv+0Hh1dyjGUT
# PaREwS7x98Te5tFHEimPa+AsG2mM+n9NwfQRjd1LiECbcCZFkgwbliQ/akiMr1tZ
# mjkDbxtu2aQcXjEfDna8JH+wZmfdu0X7k6dJ5WGRFwzZiLOJW4QhAEpeh2c1mmbt
# AfBnhSPN+E5yULfpfTT2wX8RbH6XfAg6sZx8896xq0+gUD9mHy8ZtpdEeE1ZA0Hg
# ByDW2rJCbTAJAht71B7Rz2pPQmg5R3+vSCri8BecSB+Z8mwYL3uOS3R6beUBJ7iE
# 4rPS9WC1w1fZR7K44ZSme2dI+O9/nhgb3MLYgm6zx3HhtLoGhGVPL+WoDkMnt93I
# GoO6kNBCM2X+Cs22ql2tPjkIRyxwxF6RsXh/QHnhKJgBzfO+e84I3TYbI0i29zAT
# L6yHOv5sEs1zaNMih27IwfWg4Q7+40L7e68uC6yD8EUEpaD2s2T59NhSauTzCEnA
# p5YrSscc9MQVIi7g+5GAdC8pCv+0iRa7QIvalU+9lWgkyABU/niFHWPjyGoB4x3K
# zo3tXB6aC3yZ/dTRXpJnaQIDAQABo4IBNjCCATIwHQYDVR0OBBYEFHK5LlDYKU6R
# uJFsFC9EzwthjNDoMB8GA1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8G
# A1UdHwRYMFYwVKBSoFCGTmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMv
# Y3JsL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBs
# BggrBgEFBQcBAQRgMF4wXAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0
# LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUy
# MDIwMTAoMSkuY3J0MAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgw
# DQYJKoZIhvcNAQELBQADggIBADF9xgKr+N+slAmlbcEqQBlpL5PfBMqcLkS6ySeG
# JjG+LKX3Wov5pygrhKftXZ90NYWUftIZpzdYs4ehR5RlaE3eYubWlcNlwsKkcrGS
# DJKawbbDGfvO4h/1L13sg66hPib67mG96CAqRVF0c5MA1wiKjjl/5gfrbdNLHgtR
# EQ8zCpbK4+66l1Fd0up9mxcOEEphhJr8U3whwFwoK+QJ/kxWogGtfDiaq6RyoFWh
# P8uKSLVDV+MTETHZb3p2OwnBWE1W6071XDKdxRkN/pAEZ15E1LJNv9iYo1l1P/Rd
# F+IzpMLGDAf/PlVvTUw3VrH9uaqbYr+rRxti+bM3ab1wv9v3xRLc+wPoniSxW2p6
# 9DN4Wo96IDFZIkLR+HcWCiqHVwFXngkCUfdMe3xmvOIXYRkTK0P6wPLfC+Os7oeV
# ReMj2TA1QMMkgZ+rhPO07iW7N57zABvMiHJQdHRMeK3FBgR4faEvTjUAdKRQkKFV
# 82uE7w0UMnseJfX7ELDY9T4aWx2qwEqam9l7GHX4A2Zm0nn1oaa/YxczJ7gIVERS
# GSOWLwEMxcFqBGPm9QSQ7ogMBn5WHwkdTTkmanBb/Z2cDpxBxd1vOjyIm4BOFlLj
# B4pivClO2ZksWKH7qBYloYa07U1O3C8jtbzGUdHyLCaVGBV8DfD5h8eOnyjraBG7
# PNNZMIIHcTCCBVmgAwIBAgITMwAAABXF52ueAptJmQAAAAAAFTANBgkqhkiG9w0B
# AQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAG
# A1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTAw
# HhcNMjEwOTMwMTgyMjI1WhcNMzAwOTMwMTgzMjI1WjB8MQswCQYDVQQGEwJVUzET
# MBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMV
# TWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1T
# dGFtcCBQQ0EgMjAxMDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAOTh
# pkzntHIhC3miy9ckeb0O1YLT/e6cBwfSqWxOdcjKNVf2AX9sSuDivbk+F2Az/1xP
# x2b3lVNxWuJ+Slr+uDZnhUYjDLWNE893MsAQGOhgfWpSg0S3po5GawcU88V29YZQ
# 3MFEyHFcUTE3oAo4bo3t1w/YJlN8OWECesSq/XJprx2rrPY2vjUmZNqYO7oaezOt
# gFt+jBAcnVL+tuhiJdxqD89d9P6OU8/W7IVWTe/dvI2k45GPsjksUZzpcGkNyjYt
# cI4xyDUoveO0hyTD4MmPfrVUj9z6BVWYbWg7mka97aSueik3rMvrg0XnRm7KMtXA
# hjBcTyziYrLNueKNiOSWrAFKu75xqRdbZ2De+JKRHh09/SDPc31BmkZ1zcRfNN0S
# idb9pSB9fvzZnkXftnIv231fgLrbqn427DZM9ituqBJR6L8FA6PRc6ZNN3SUHDSC
# D/AQ8rdHGO2n6Jl8P0zbr17C89XYcz1DTsEzOUyOArxCaC4Q6oRRRuLRvWoYWmEB
# c8pnol7XKHYC4jMYctenIPDC+hIK12NvDMk2ZItboKaDIV1fMHSRlJTYuVD5C4lh
# 8zYGNRiER9vcG9H9stQcxWv2XFJRXRLbJbqvUAV6bMURHXLvjflSxIUXk8A8Fdsa
# N8cIFRg/eKtFtvUeh17aj54WcmnGrnu3tz5q4i6tAgMBAAGjggHdMIIB2TASBgkr
# BgEEAYI3FQEEBQIDAQABMCMGCSsGAQQBgjcVAgQWBBQqp1L+ZMSavoKRPEY1Kc8Q
# /y8E7jAdBgNVHQ4EFgQUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXAYDVR0gBFUwUzBR
# BgwrBgEEAYI3TIN9AQEwQTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3Nv
# ZnQuY29tL3BraW9wcy9Eb2NzL1JlcG9zaXRvcnkuaHRtMBMGA1UdJQQMMAoGCCsG
# AQUFBwMIMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAP
# BgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjE
# MFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kv
# Y3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEF
# BQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9w
# a2kvY2VydHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0MA0GCSqGSIb3DQEB
# CwUAA4ICAQCdVX38Kq3hLB9nATEkW+Geckv8qW/qXBS2Pk5HZHixBpOXPTEztTnX
# wnE2P9pkbHzQdTltuw8x5MKP+2zRoZQYIu7pZmc6U03dmLq2HnjYNi6cqYJWAAOw
# Bb6J6Gngugnue99qb74py27YP0h1AdkY3m2CDPVtI1TkeFN1JFe53Z/zjj3G82jf
# ZfakVqr3lbYoVSfQJL1AoL8ZthISEV09J+BAljis9/kpicO8F7BUhUKz/AyeixmJ
# 5/ALaoHCgRlCGVJ1ijbCHcNhcy4sa3tuPywJeBTpkbKpW99Jo3QMvOyRgNI95ko+
# ZjtPu4b6MhrZlvSP9pEB9s7GdP32THJvEKt1MMU0sHrYUP4KWN1APMdUbZ1jdEgs
# sU5HLcEUBHG/ZPkkvnNtyo4JvbMBV0lUZNlz138eW0QBjloZkWsNn6Qo3GcZKCS6
# OEuabvshVGtqRRFHqfG3rsjoiV5PndLQTHa1V1QJsWkBRH58oWFsc/4Ku+xBZj1p
# /cvBQUl+fpO+y/g75LcVv7TOPqUxUYS8vwLBgqJ7Fx0ViY1w/ue10CgaiQuPNtq6
# TPmb/wrpNPgkNWcr4A245oyZ1uEi6vAnQj0llOZ0dFtq0Z4+7X6gMTN9vMvpe784
# cETRkPHIqzqKOghif9lwY1NNje6CbaUFEMFxBmoQtB1VM1izoXBm8qGCAsswggI0
# AgEBMIH4oYHQpIHNMIHKMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMSYwJAYD
# VQQLEx1UaGFsZXMgVFNTIEVTTjozRTdBLUUzNTktQTI1RDElMCMGA1UEAxMcTWlj
# cm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAEwa4jWja
# cbOYU++95ydJ7hSCi5iggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0Eg
# MjAxMDANBgkqhkiG9w0BAQUFAAIFAOcAbU8wIhgPMjAyMjEwMjQwOTQ3NTlaGA8y
# MDIyMTAyNTA5NDc1OVowdDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA5wBtTwIBADAH
# AgEAAgIJxzAHAgEAAgIRvzAKAgUA5wG+zwIBADA2BgorBgEEAYRZCgQCMSgwJjAM
# BgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEB
# BQUAA4GBAGwqDH2ujTXKEBjhOJPaZjxg+4Yu5uwbsnl2AYg/H+uSTFOyCsFXaRDO
# qtPMUOsLtf/iC2tcBT21KQUae/t1WHy1H1Tz5349Jaen+kX/SaDaxJgiCkGMTTWQ
# etWhYPccitW9WKsJWXB6j529cA1Oe3VSWuFl7nbGrVSHRW8cvv0uMYIEDTCCBAkC
# AQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGg6buMuw6i
# 0XoAAQAAAaAwDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG
# 9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQgRjah0t3/3PhCJwy5svUyL45DcICh8KaT
# xWD6Ryppy9YwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCAvR4o8aGUEIhIt
# 3REvsx0+svnM6Wiaga5SPaK4g6+00zCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0
# YW1wIFBDQSAyMDEwAhMzAAABoOm7jLsOotF6AAEAAAGgMCIEIAEoaZfoDQx8Opct
# nWw6DhyF0Htuzu/HwkUSh6EY8h7/MA0GCSqGSIb3DQEBCwUABIICALoW3fjc1oT9
# 3cq2uR7YTigOGZXXghMbzNRpSTWeKGgpDkwmEeOt1lRRRTuZT9Dp8dlvP41jZGWh
# fXDz25pCzcxRH92YooO0k07hr2M+zJn00KM6YTsaSw5iJTNyH+cfzHdiEVkLNDsP
# f7zmMYcYqS8i1c65DdGo9UmRmuZ7G3Ai9N/KK/RScrT/VuE+jIRBc4DY7QPYXzYF
# iUFYFXspVEYwEaKubwJUrhU7zL7SZXGdKoiIDMi4snZIevKsaalJpdavhVVt1q9f
# x+CZcy/gogpvgLJnF/MRlPCsnSubNGZeVlWCF1jcxQQbLxt9wgoPPksOaPreeEe+
# 45BFJOgb8F2u0zyc9ExQ8qFl0FvjvlYqoNKYaH12t5sf0Pg0caboJ1avD2orj1IK
# wbjApD7s76BmI/8rGIOGwP1ltbhcOE80dw8TjJgjuprmqY9/JM93mxWxmf/8zYut
# dr23eAnOfQ20bD90nZeb8s8g3Kay9Vn/qAZVx7Uqsp1D6n18KWt52/yFJ4HxuEuX
# rFB0KOp3c2rNlQ0oths6oUt9Y1Bg7fGhde6jamiyoavcxxFFUAgAWi0UA162evxR
# 0vvWIaZA4znreF9bLh6pfAZ8q9T27Uqw2wOBboBc6PwIl+3Ia3a+H8Pay3IS61we
# l9SNtRedEAtfHS7WGVg2p+yTz4ryXJyA
# SIG # End signature block
