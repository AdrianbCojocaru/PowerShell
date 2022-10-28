# 2019-03-20 WalterE added Trap #_#

Trap [Exception]
	{
	 # Handle exception and throw it to the stdout log file. Then continue with function and script.
		 $Script:ExceptionMessage = $_
		 "[info]: Exception occurred."  | WriteTo-StdOut
		 "[info]: Exception.Message $ExceptionMessage."  | WriteTo-StdOut 
		 $Error.Clear()
		 continue
	}

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'HH:mm:ss') $Global:SDPtech - Collect Phase module: Common ---"
	# version of the psSDP Diagnostic
	Run-DiagExpression .\DC_NetworkingDiagnostic.ps1
	
	# MSInfo
	Run-DiagExpression .\DC_MSInfo.ps1

	# Obtain pstat output
	Run-DiagExpression .\DC_PStat.ps1

	# CheckSym
	Run-DiagExpression .\DC_ChkSym.ps1

	# AutoRuns Information
	Run-DiagExpression .\DC_Autoruns.ps1

	# Collects Windows Server 2008/R2 Server Manager Information
	Run-DiagExpression .\DC_ServerManagerInfo.ps1

	# List Schedule Tasks using schtasks.exe utility
	Run-DiagExpression .\DC_ScheduleTasks.ps1

	# Collects System and Application Event Logs 
	Run-DiagExpression .\DC_SystemAppEventLogs.ps1

	# Collect Machine Registry Information for Setup and Performance Diagnostics
	Run-DiagExpression .\DC_RegistrySetupPerf.ps1

	# GPResults.exe Output
	Run-DiagExpression .\DC_RSoP.ps1

	# Basic System Information
	Run-DiagExpression .\DC_BasicSystemInformation.ps1

	# Basic System Information TXT output
	Run-DiagExpression .\DC_BasicSystemInformationTXT.ps1

	# Collects information about Driver Verifier (verifier.exe utility)
	Run-DiagExpression .\DC_Verifier.ps1

	# Collects BCD information via BCDInfo tool or boot.ini
	Run-DiagExpression .\DC_BCDInfo.ps1

	# Obtain information about Devices and connections using devcon.exe utility
	Run-DiagExpression .\DC_Devcon.ps1

	# Collects Windows Server 2008/R2 Server Manager Information
	Run-DiagExpression .\DC_ServerManagerLogs.ps1

	# DBErr Data Collector
	Run-DiagExpression .\DC_DBErr.ps1

	# User Rights (privileges) via the userrights.exe tool
	Run-DiagExpression .\DC_UserRights.ps1

	# Services
	Run-DiagExpression .\DC_Services.ps1

	# TaskListSvc
	Run-DiagExpression .\DC_TaskListSvc.ps1

	# List Schedule Tasks using schtasks.exe utility
	Run-DiagExpression .\DC_TaskScheduler.ps1

	# WhoAmI
	Run-DiagExpression .\DC_Whoami.ps1
	
	# PoolMon
	Run-DiagExpression .\DC_PoolMon.ps1
	
	# Collects registry entries for KIR (for 2019) and RBC (for 2016) 
	Run-DiagExpression .\DC_KIR-RBC-RegEntries.ps1

	# Collect summary report 
	Run-DiagExpression .\DC_SummaryReliability.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'HH:mm:ss') $Global:SDPtech - Collect Phase module: Net ---"
	# 802.1x Client Component
	Run-DiagExpression .\DC_8021xClient-Component.ps1

	# BITS Client Component
	Run-DiagExpression .\DC_BitsClient-Component.ps1

	# BITS Server Component
	Run-DiagExpression .\DC_BitsServer-Component.ps1

	# Bluetooth Component
	Run-DiagExpression .\DC_Bluetooth-Component.ps1

	# BranchCache
	Run-DiagExpression .\DC_BranchCache-Component.ps1

	# Bridge
	Run-DiagExpression .\DC_Bridge-Component.ps1

	# Certificates Component
	Run-DiagExpression .\DC_Certificates-Component.ps1

	# CscClient
	Run-DiagExpression .\DC_CscClient-Component.ps1

	# DFS Client Component
	Run-DiagExpression .\DC_DFSClient-Component.ps1
	# DFS Server Component
	Run-DiagExpression .\DC_DFSServer-Component.ps1
	
	# DHCP Client Component
	Run-DiagExpression .\DC_DhcpClient-Component.ps1
	# DHCP Server Component
	Run-DiagExpression .\DC_DhcpServer-Component.ps1

	# DirectAccess Client Component
	Run-DiagExpression .\DC_DirectAccessClient-Component.ps1
	# DirectAccess Server Component
	Run-DiagExpression .\DC_DirectAccessServer-Component.ps1

	# DNS Client Component
	Run-DiagExpression .\DC_DNSClient-Component.ps1
	# DNS Server Component
	Run-DiagExpression .\DC_DNSServer-Component.ps1

	# DNS DHCP Dynamic Updates
	Run-DiagExpression .\DC_DnsDhcpDynamicUpdates.ps1

	# Firewall
	Run-DiagExpression .\DC_Firewall-Component.ps1

	# Capture pfirewall.log 
	Run-DiagExpression .\DC_PFirewall.ps1

	# FolderRedirection
	Run-DiagExpression .\DC_FolderRedirection-Component.ps1

	# GroupPolicyClient
	Run-DiagExpression .\DC_GroupPolicyClient-Component.ps1

	# HTTP
	Run-DiagExpression .\DC_HTTP-Component.ps1

	# InternetExplorer
	Run-DiagExpression .\DC_InternetExplorer-Component.ps1

	# IPAM Component
	Run-DiagExpression .\DC_IPAM-Component.ps1

	# IPsec
	Run-DiagExpression .\DC_IPsec-Component.ps1

	# MUP Component
	Run-DiagExpression .\DC_MUP-Component.ps1

	# NAP Client Component
	Run-DiagExpression .\DC_NAPClient-Component.ps1

	# NAP Server Component
	Run-DiagExpression .\DC_NAPServer-Component.ps1

	# NetLBFO
	Run-DiagExpression .\DC_NetLBFO-Component.ps1

	# NetworkAdapters
	Run-DiagExpression .\DC_NetworkAdapters-Component.ps1

	# NetworkConnections
	Run-DiagExpression .\DC_NetworkConnections-Component.ps1

	# NetworkList
	Run-DiagExpression .\DC_NetworkList-Component.ps1

	# NetworkLocationAwareness
	Run-DiagExpression .\DC_NetworkLocationAwareness-Component.ps1

	# Network Shortcuts (Network Locations)
	Run-DiagExpression .\DC_NetworkShortcuts.ps1

	# NetworkStoreInterface
	Run-DiagExpression .\DC_NetworkStoreInterface-Component.ps1

	# NFS Client Component
	Run-DiagExpression .\DC_NfsClient-Component.ps1

	# NFS Server Component
	Run-DiagExpression .\DC_NfsServer-Component.ps1

	# NLB Component
	Run-DiagExpression .\DC_NLB-Component.ps1

	# NPS
	Run-DiagExpression .\DC_NPS-Component.ps1

	# P2P
	Run-DiagExpression .\DC_P2P-Component.ps1

	# Proxy Configuration
	Run-DiagExpression .\DC_ProxyConfiguration.ps1

	# RAS
	Run-DiagExpression .\DC_RAS-Component.ps1

	# RDG Component
	Run-DiagExpression .\DC_RDG-Component.ps1

	# Remote File Systems Client Component
	Run-DiagExpression .\DC_RemoteFileSystemsClient-Component.ps1

	# Remote File Systems Server Component
	Run-DiagExpression .\DC_RemoteFileSystemsServer-Component.ps1

	# RPC
	Run-DiagExpression .\DC_RPC-Component.ps1

	# SChannel
	Run-DiagExpression .\DC_SChannel-Component.ps1

	# SMB Client Component
	Run-DiagExpression .\DC_SMBClient-Component.ps1

	# SMB Server Component
	Run-DiagExpression .\DC_SMBServer-Component.ps1

	# SNMP
	Run-DiagExpression .\DC_SNMP-Component.ps1

	# TCPIP Component
	Run-DiagExpression .\DC_TCPIP-Component.ps1

	# WebClient
	Run-DiagExpression .\DC_WebClient-Component.ps1

	# WinHTTP
	Run-DiagExpression .\DC_WinHTTP-Component.ps1

	# WINSClient
	Run-DiagExpression .\DC_WINSClient-Component.ps1

	# WinSock
	Run-DiagExpression .\DC_WinSock-Component.ps1

	# WINSServer
	Run-DiagExpression .\DC_WINSServer-Component.ps1
	
	# Collects W32Time information
	Run-DiagExpression .\DC_W32Time.ps1

	# Collects Basic Networking Information (TCP/IP - SMB)
	Run-DiagExpression .\DC_NetBasicInfo.ps1
	
Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'HH:mm:ss') $Global:SDPtech - Collect Phase module: HyperV  ---"
	# Hyper-V Info
	Run-DiagExpression .\DC_HyperVBasicInfo.ps1

	# Hyper-V Networking Info
	Run-DiagExpression .\DC_HyperVNetInfo.ps1

	# Hyper-V Networking Settings
	Run-DiagExpression .\DC_HyperVNetworking.ps1

	# Hyper-V Network Virtualization
	Run-DiagExpression .\DC_HyperVNetworkVirtualization.ps1

	# Hyper-V Replica Information
	if ($Global:skipHVreplica -ne $true) {
	 Run-DiagExpression .\DC_HyperVReplica.ps1
	}

	# Collect the VMGuestSetup.Log file
	Run-DiagExpression .\DC_VMGuestSetupLogCollector.ps1

	# Information about Hyper-V, including Virtual Machine Files and Hyper-V Event Logs
	Run-DiagExpression .\DC_HyperVFiles.ps1

	Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'HH:mm:ss') $Global:SDPtech - Collect Phase module: DOM ---"
	# Applied Security Templates
	Run-DiagExpression .\DC_AppliedSecTempl.ps1

	# Collects functional level and local group membership information (DSMisc)
	Run-DiagExpression .\DC_DSMisc.ps1

	# Kerberos Component
	Run-DiagExpression .\DC_Kerberos-Component.ps1
	
	# Obtain Netlogon Log
	Run-DiagExpression .\DC_NetlogonLog.ps1

	# Collects NetSetup.Log from %windir%\debug
	Run-DiagExpression .\DC_NetSetupLog.ps1

	# Collects winlogon Log from %windir%\security\logs\winlogon.log 
	Run-DiagExpression .\DC_WinlogonLog.ps1

	# Run Repadmin tool with showrepl argument and obtain output
	Run-DiagExpression .\DC_Repadmin.ps1

	# Collects system security settings (INF) via secedit utility
	Run-DiagExpression .\DC_SystemSecuritySettingsINF.ps1

	# Collects registry entries for Directory Services support
	Run-DiagExpression .\DC_DSRegEntries.ps1

	# auditpol output
	Run-DiagExpression .\DC_AuditPol.ps1

	# Kerberos tickets and TGT via klist utility
	Run-DiagExpression .\DC_KList.ps1

	# DCPromo Logs
	Run-DiagExpression .\DC_DCPromoLogs.ps1

	# Determines FSMO role owners
	Run-DiagExpression .\DC_NetdomFSMO.ps1

	# Copies Userenv Log files
	Run-DiagExpression .\DC_UserenvLogs.ps1

	# Collects environment variables (output of SET command)
	Run-DiagExpression .\DC_EnvVars.ps1

	# Collecting Secure Channel Info
	Run-DiagExpression .\DC_SecureChannelInfo.ps1

	# Directory Services related Event Logs
	Run-DiagExpression .\DC_ADEventLogs.ps1

	# Dfsr Informaton
	Run-DiagExpression .\DC_DfsrInfo.ps1

	# BPA DS
	if ($Global:skipBPA -ne $true) {
		Run-DiagExpression .\DC_BPA-DS.ps1
	}

	# Active Directory environment data collection scripts.
	Run-DiagExpression .\DC_CurrentDomainInfo.ps1
	Run-DiagExpression .\DC_DCSiteInfo.ps1
	Run-DiagExpression .\DC_ForestInfo.ps1
	Run-DiagExpression .\DC_TrustList.ps1
	Run-DiagExpression .\DC_UserLogonInfo.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'HH:mm:ss') $Global:SDPtech - Collect Phase module: Print ---"
	# Collect Print Registry Keys
	Run-DiagExpression .\DC_RegPrintKeys.ps1

	# Perf/Printing Event Logs
	Run-DiagExpression .\DC_PerfPrintEventLogs.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'HH:mm:ss') $Global:SDPtech - Collect Phase module: RDS ---"
	Run-DiagExpression .\DC_RDSServerInfo.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'HH:mm:ss') $Global:SDPtech - Collect Phase module: Storage ---"
	# By adding San.exe to the SDP manifest we should be able to solve cases that have a 512e or Advanced Format (4K) disk in it faster.
	Run-DiagExpression .\DC_SanStorageInfo.ps1

	# Collects Fiber Channel information using fcinfo utility
	Run-DiagExpression .\DC_FCInfo.ps1

	# Obtain information about MS-DOS device names (symbolic links) via DOSDev utility
	Run-DiagExpression .\DC_DOSDev.ps1

	# Collects Information about iSCSI though the iscsicli utility
	Run-DiagExpression .\DC_ISCSIInfo.ps1

	# Parse Storage related event logs on System log using evParse.exe and dump to a HTML file
	Run-DiagExpression .\DC_EvParser.ps1

	# Collects VSS information via VSSAdmin tool
	Run-DiagExpression .\DC_VSSAdmin.ps1

	# Collect Machine Registry Information for Storage Related Diagnostics
	Run-DiagExpression .\DC_RegistryStorage.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'HH:mm:ss') $Global:SDPtech - Collect Phase module: Setup ---"
	# Collect Deployment-related Logs (setupact.log, unattended.xml, setuperr.log)
	Run-DiagExpression .\DC_DeploymentLogs.ps1

	# KMS/ MAK activation information using inbox slmgr.vbs
	Run-DiagExpression .\DC_SLMGR.ps1

	# Windows Servicing Logs (CBS logs and others)
	Run-DiagExpression .\DC_ServicingLogs.ps1

	# Collects Cluster - related Event Logs for Cluster Diagnostics
	Run-DiagExpression .\DC_MBAMEventLogs.ps1

	# KB Installation Logs
	Run-DiagExpression .\DC_KBInstallLogs.ps1

	# Collects Windows Setup API Logs
	Run-DiagExpression .\DC_SetupAPILogs.ps1

	# Collect Appx event logs for tshooting application deployment, sideloading, and execution
	Run-DiagExpression .\DC_WindowsStoreAppEvtLogs.ps1

	# Startup repair Diagnostics Data Collection
	Run-DiagExpression .\DC_StartupRepairProcessLog.ps1

	# Enumerate minifilter drivers via Fltmc.exe command
	Run-DiagExpression .\DC_Fltmc.ps1

	# Obtain information about Upper and lower filters Information fltrfind.exe utility
	Run-DiagExpression .\DC_Fltrfind.ps1

	# DC_WDS
	Run-DiagExpression .\DC_WDSFiles.ps1

	if ($Global:runFull -eq $True) {
		#_# newer Setup_Addons
		Run-DiagExpression .\DC_Setup_Addons.ps1
	}
Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'HH:mm:ss') $Global:SDPtech - Collect Phase module: SQL ---"
	# Get_System_Info
	Run-DiagExpression .\SQL_Get_SystemInfo.ps1

	# Get_All_Services
	Run-DiagExpression .\SQL_Get_All_Services.ps1

	# Reg_Debug_Keys
	Run-DiagExpression .\SQL_Debug_Registry.ps1

	# SQL Server Log Collector
	Run-DiagExpression .\DC_CollectSqlLogs.ps1 -Instances $null -CollectSqlErrorlogs -CollectSqlAgentLogs

	# SQL Server XE System Health Collector
	Run-DiagExpression .\DC_GetSqlXeLogs.ps1 -Instances $null -CollectSqlDefaultDiagnosticXeLogs -CollectFailoverClusterDiagnosticXeLogs -CollectAlwaysOnDiagnosticXeLogs

	# SQL Server minidump files Collector
	Run-DiagExpression .\DC_CollectSqlMinidumps.ps1 -Instances $null

	# SQL Server Log Collector
	Run-DiagExpression .\DC_RunSqlDiagScripts.ps1 -Instances $null -CollectSqlDiag -CollectAlwaysOnInfo

	# Misc_SQL_Keys
	Run-DiagExpression .\DC_SQL_Registries.ps1

	# SQL Server Analysis Services Registry Key Collector
	Run-DiagExpression .\DC_GetOlapServerConfigFiles.ps1

	# SQL Server Analysis Services Registry Key Collector
	Run-DiagExpression .\DC_CollectSsasRegKeys.ps1

	# SQL Server Analysis Services MiniDump Collector
	Run-DiagExpression .\DC_CollectASMinidumps.ps1 -Instances $null

	# SQL Server Analysis Services Log and Trace Collector
	Run-DiagExpression .\DC_GetOlapLogAndTraces.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'HH:mm:ss') $Global:SDPtech - Collect Phase module: WinRM ---"
	# Collects Windows Remote Management Event log
	Run-DiagExpression .\DC_WinRMEventLogs.ps1

	# Collects WSMAN and WinRM binary details info
	Run-DiagExpression .\DC_WSMANWinRMInfo.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'HH:mm:ss') $Global:SDPtech - Collect Phase module: Update ---"
	# Update History / Hotfixes
	Run-DiagExpression .\DC_UpdateHistory.ps1

	# Collect WindowsUpdate.Log
	Run-DiagExpression .\DC_WindowsUpdateLog.ps1


Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'HH:mm:ss') $Global:SDPtech - Collect Phase module: Surface ---"
	# Surface 
	Run-DiagExpression .\DC_Surface.ps1

	# Surface Pro 3
	Run-DiagExpression .\DC_SurfacePro3.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'HH:mm:ss') $Global:SDPtech - Collect Phase module: Exchange ---"
	# ExchDump
	Run-DiagExpression .\DC_Ex2003_ExchDump.ps1

	# ExBPA_2003
	if ($Global:skipBPA -ne $true) {
		Run-DiagExpression .\DC_Ex2003_ExBPAcmd.ps1
	}

	# Collects PowerShell - related Event Logs for Exchange Server Diagnostics
	Run-DiagExpression .\DC_ExchangeServerEventLogs.ps1

	# ExchDump
	Run-DiagExpression .\DC_Exchange_RegKeys.ps1

	# ExBPAcmd
	if ($Global:skipBPA -ne $true) {
		Run-DiagExpression .\DC_Ex_ExBPAcmd.ps1
	}

	# Exchange Server 2007-2010 Comprehensive Data Collection
	Run-DiagExpression .\DC_GetExchange2007_2010Data.ps1

	# Exchange Server 2013 Comprehensive Data Collection
	Run-DiagExpression .\DC_GetExchange2013Data.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'HH:mm:ss') $Global:SDPtech - Collect Phase module: Cluster ---"
	# Collects Cluster Logs
	Run-DiagExpression .\DC_ClusterLogs.ps1

	# Export cluster resources properties to a file (2K8 R2 and newer)
	Run-DiagExpression .\DC_ClusterResourcesProperties.ps1

	# Collects Cluster Groups Resource Dependency Report (Win2K8R2)
	Run-DiagExpression .\DC_ClusterDependencyReport.ps1

	# Collects Cluster - related Event Logs for Cluster Diagnostics
	Run-DiagExpression .\DC_ClusterEventLogs.ps1

	# Collects \windows\cluster\reports contents (MHT, XML and Validate*.LOG)
	Run-DiagExpression .\DC_ClusterReportsFiles.ps1

	# Collects Cluster - related registry keys
	Run-DiagExpression .\DC_RegistryCluster.ps1

	# Information about Windows 2008 R2 Cluster Shared Volumes
	Run-DiagExpression .\DC_CSVInfo.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'HH:mm:ss') $Global:SDPtech - Collect Phase module: Performance Data ---"
	# Performance Monitor - System Performance Data Collector
	Run-DiagExpression .\TS_PerfmonSystemPerf.ps1 -NumberOfSeconds 60 -DataCollectorSetXMLName "SystemPerformance.xml"

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'HH:mm:ss') $Global:SDPtech - Collect Phase module: Remote ---"
	# ServerCore R2 Setup
	#Run-DiagExpression .\DC_ServerCoreR2Setup.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'HH:mm:ss') $Global:SDPtech - Collect Phase module: DC_WinStore ---"
	# Windows Store Inbox Applications Interactive [AutoAdded]
	Run-DiagExpression .\DC_WinStoreMain.ps1
	
Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'HH:mm:ss') $Global:SDPtech - Collect Phase: Done ---"	
Write-Host "...Next step: Troubleshooting section, if it hangs, run script with parameter SkipTS"

if ($Global:skipTS -ne $true) {
Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'HH:mm:ss') $Global:SDPtech - Diag Phase module: TS_common ---"

	Run-DiagExpression .\TS_DumpCollector.ps1 -CopyWERMinidumps -CopyMachineMiniDumps -MaxFileSize 300 -CopyMachineMemoryDump -CopyTDRDumps

	# Detects and alerts evaluation media
	Run-DiagExpression .\TS_EvalMediaDetection.ps1

	# Debug/GFlags check
	Run-DiagExpression .\TS_DebugFlagsCheck.ps1

	# Information about Processes resource usage and top Kernel memory tags
	Run-DiagExpression .\TS_ProcessInfo.ps1

	# RC_32GBMemoryKB2634907
	Run-DiagExpression .\RC_32GBMemoryKB2634907.ps1

	# Checking if Registry Size Limit setting is present on the system
	Run-DiagExpression .\TS_RegistrySizeLimitCheck.ps1

	# Running powercfg.exe to obtain power settings information
	Run-DiagExpression .\TS_PowerCFG.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'HH:mm:ss') $Global:SDPtech - Diag Phase module: TS_Net ---"
	# Check for ephemeral port usage
	Run-DiagExpression .\TS_PortUsage.ps1

	Run-DiagExpression .\RC_KB2647170_CnameCheck.ps1

	Run-DiagExpression .\RC_FirewallCheck.ps1

	Run-DiagExpression .\RC_IPv66To4Check.ps1

	Run-DiagExpression .\RC_HTTPRedirectionTSGateway.ps1

	# [Idea ID 6530] [Windows] Check for any configured RPC port range which may cause issues with DCOM or DTC components
	Run-DiagExpression .\TS_RPCPortRangeCheck.ps1

	# [Idea ID 2387] [Windows] Verify if RPC connection are configured to accept only Authenticated sessions
	Run-DiagExpression .\TS_RPCUnauthenticatedSessions.ps1

	# SMB2ClientDriverStateCheck
	Run-DiagExpression .\TS_SMB2ClientDriverStateCheck.ps1

	# SMB2ServerDriverStateCheck
	Run-DiagExpression .\TS_SMB2ServerDriverStateCheck.ps1

	# Opportunistic Locking has been disabled and may impact performance.
	Run-DiagExpression .\TS_LockingKB296264Check.ps1

	# Evaluates whether InfocacheLevel should be increased to 0x10 hex. To resolve slow logon, slow boot issues.
	Run-DiagExpression .\TS_InfoCacheLevelCheck.ps1

	# RSASHA512 Certificate TLS 1.2 Compat Check
	Run-DiagExpression .\TS_DetectSHA512-TLS.ps1

	# IPv6Check
	Run-DiagExpression .\TS_IPv6Check.ps1

	# PMTU Check
	Run-DiagExpression .\TS_PMTUCheck.ps1

	# Detect MTU of 1514
	Run-DiagExpression .\TS_DetectMTU1514.ps1
	
	# Checks for modified TcpIP Reg Parameters and recommend KB
	Run-DiagExpression .\TS_TCPIPSettingsCheck.ps1

	# Checks if the number of 6to4 adapters is larger than the number of physical adapters
	Run-DiagExpression .\TS_AdapterKB980486Check.ps1

	# Checks files in the LanmanServer, if any at .PST files a file is created with listing all of the files in the directory
	Run-DiagExpression .\TS_NetFilePSTCheck.ps1

	# Checks if Windows Server 2008 R2 SP1, Hyper-V, and Tunnel.sys driver are installed if they are generate alert
	Run-DiagExpression .\TS_ServerCoreKB978309Check.ps1

	#_# Run-DiagExpression .\TS_DetectLowPathMTU.ps1
	TS_DetectLowPathMTU.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'HH:mm:ss') $Global:SDPtech - Diag Phase module: TS_HyperV ---"
	# Hyper-V Info 2008R2
	Run-DiagExpression .\TS_HyperVInfo.ps1

	# Detect Virtualization
	Run-DiagExpression .\TS_Virtualization.ps1

	# Missing Hotfix 
	Run-DiagExpression .\TS_HyperVEvent106Check.ps1

	if (test-path $env:Windir\System32\BestPractices\v1.0\Models\Microsoft\Windows\Hyper-V) {
		# Hyper-V BPA
		if ($Global:skipBPA -ne $true) {
		Run-DiagExpression .\TS_BPAInfo.ps1 -BPAModelID "Microsoft/Windows/Hyper-V" -OutputFileName ($Computername + "_HyperV_BPAInfo.HTM") -ReportTitle "Hyper-V Best Practices Analyzer"
		}
	}

	# [Idea ID 6134] [Windows] You cannot start Hyper-V virtual machines after you enable the IO verification option on a HyperV
	Run-DiagExpression .\TS_HyperVCheckVerificationKB2761004.ps1

	# Check for event ID 21203 or 21125
	Run-DiagExpression .\TS_CheckEvtID_KB2475761.ps1

	# [Idea ID 5438] [Windows] Windows 2012 Hyper-V SPN and SCP not registed if customer uses a non default dynamicportrange
	Run-DiagExpression .\TS_HyperVEvent14050Check.ps1

	# [Idea ID 5752] [Windows] BIOS update may be required for some computers before starting Hyper-V on 2012
	Run-DiagExpression .\TS_HyperV2012-CS-BIOS-Check.ps1

	# Hyper-V KB 982210 check
	Run-DiagExpression .\TS_HyperVSCSIDiskEnum.ps1

	# Hyper-V KB 975530 check (Xeon Processor Errata)
	Run-DiagExpression .\TS_HyperVXeon5500Check.ps1
	
	# Checks if Windows Server 2008 R2 SP1, Hyper-V, and Hotfix 2263829 are installed if they are generate alert
	Run-DiagExpression .\TS_HyperVKB2263829Check.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'HH:mm:ss') $Global:SDPtech - Diag Phase module: TS_DOM ---"
	# DCDiag information
	Run-DiagExpression .\TS_DCDiag.ps1
	
	# Check AD Replication Status
	Run-DiagExpression .\TS_ADReplCheck.ps1

	# Checks if CrashOnAuditFail is either 1 or 2
	Run-DiagExpression .\TS_CrashOnAuditFailCheck.ps1

	# SYSVOL and/or NETLOGON shares are missing on domain controller
	Run-DiagExpression .\TS_LSASSHighCPU.ps1

	# SYSVOL and/or NETLOGON shares are missing on domain controller
	Run-DiagExpression .\TS_SysvolNetLogonShareCheck.ps1

	# Missing Rid Set reference attribute detected
	Run-DiagExpression .\TS_ADRidSetReferenceCheck.ps1

	# AD Integrated DNS Server should not point only to itself if it has replica partners.
	Run-DiagExpression .\TS_DCCheckDnsExclusiveToSelf.ps1

	# [Idea ID 3768] [Windows] New rule to verify USN Roll Back
	Run-DiagExpression .\TS_USNRollBackCheck.ps1

	# [Idea ID 2882] [Windows] The stop of Intersite Messaging service on ISTG causes DFSN cannot calculate site costs
	Run-DiagExpression .\TS_IntersiteMessagingStateCheck.ps1

	# [Idea ID 2831] [Windows] DFSR Reg setting UpdateWorkerThreadCount = 64 may cause hang
	Run-DiagExpression .\TS_DfsrUpdateWorkerThreadCountCheck.ps1

	# [Idea ID 2593] [Windows] UDP 389 on DC does not respond
	Run-DiagExpression .\TS_IPv6DisabledonDCCheck.ps1

	# [Idea ID 4724] [Windows] W32Time and time skew
	Run-DiagExpression .\TS_Win32TimeTimeSkewRegCheck.ps1

	# [Idea ID 4796] [Windows] MaxConcurrentApi Problem Detection Lite
	Run-DiagExpression .\TS_MCALite.ps1

	# [Idea ID 5009] [Windows] Weak Key Block Detection
	Run-DiagExpression .\TS_DetectWeakKeys.ps1

	# [Idea ID 6816] [Windows] Detect Certificate Root Store Size Problems
	Run-DiagExpression .\TS_DetectRootSize.ps1
	
	# Check DFSR configuration
	Run-DiagExpression .\TS_DFSRRootCausesCheck.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'HH:mm:ss') $Global:SDPtech - Diag Phase module: TS_Print ---"
	# Print Information Report
	Run-DiagExpression .\TS_PrintInfo.ps1

	# [KSE Rule] [ Windows V3] Presence of lots of folders inside \spool\prtprocs\ causes failure to install print queues
	Run-DiagExpression .\TS_PrtprocsSubfolderBloat.ps1

	# Checks if machine is server 2008 R2 sp0 or sp1, and event log 602 exists, and hotfix kb 2457866 is installed if true generate alert
	Run-DiagExpression .\TS_PrinterKB2457866Check.ps1

	# Checks if a Kyocera print driver is installed then checks if KB982728 is installed
	Run-DiagExpression .\TS_PrinterKB982728Check.ps1

	# Checks if Point and Print Restriction Policy and then look for specifc events on event logs
	Run-DiagExpression .\TS_PrinterKB2618460Check.ps1

	# Checks to see if HP Standard TCP/IP Port key is present on the system
	Run-DiagExpression .\TS_PrintingHPTCPMonCheck.ps1

	# Checking if 'Net Driver HPZ12' or 'Pml Driver HPZ12' is one of the installed services and startup type is something different than Disabled
	Run-DiagExpression .\TS_HPZ12ServiceCheck.ps1

	# Detect the OEM HP driver hpzui4wm.DLL
	Run-DiagExpression .\TS_PrintHpzui4wmCheck.ps1

	# Check for the presence of Zenographics Device Manager User Interface
	Run-DiagExpression .\TS_Check_ZenographicsUI.ps1

	# Check for upgrade from HP UPD 5.2 to 5.3
	Run-DiagExpression .\TS_2628581_HPUPDUpgrade.ps1

	# [Idea ID 2226] [Windows] Old SHD and SPL files residual in the Spool directory cause issues
	Run-DiagExpression .\TS_PrintSpoolerOldSPLSHD.ps1

	# [Idea ID 1872] [Windows] Detecting bloated HKEY_USERS\.default\printers\Devmodes2 registry key on Terminal servers
	Run-DiagExpression .\TS_PrintDevModes2CountCheck.ps1

	# [Idea ID 3462] [Windows] Printing issue - multiple SETxnnn.tmp files
	Run-DiagExpression .\TS_PrintSetTMPSystem32Check.ps1

	# [Idea ID 4091] [Windows] frequent spooler crash due to zsdnt5ui.dll
	Run-DiagExpression .\TS_PrintZSDDMUICheck.ps1

	# [Idea ID 4168] [Windows] Check for existence of 2647753  for printing issues
	Run-DiagExpression .\TS_Win7PrintUpdateRollupCheck.ps1

	# [Idea ID 2374] [Windows] Spooler service hangs since CSR exhausts the 512 threads in thread pool
	Run-DiagExpression .\TS_PrintCSRBloatingCheck.ps1

	# [Idea ID 4805] [Windows] Printers show Offline on Windows 7 clients
	Run-DiagExpression .\TS_PrinterShowOffline.ps1

	# [Idea ID 5470] [Windows] GPP printer fails to add with error code 0x80070704
	Run-DiagExpression .\TS_GPPDeployPrinterCheck.ps1

	# [Idea ID 6863] [Windows] GPP printer fails to be added since LocalEnumForms returns error 8007007a
	Run-DiagExpression .\TS_GPPMapPrinterKB2797136.ps1

	# [KSE Rule] [ Windows V3] HKCU\Software\Hewlett-Packard registry hive increases in size on Citrix servers
	Run-DiagExpression .\TS_HPPrinterDriverVersionCheck.ps1

	# List Schedule Tasks using schtasks.exe utility
	Run-DiagExpression .\TS_SpoolerDumpInfo.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'HH:mm:ss') $Global:SDPtech - Diag Phase module: TS_RDS ---"
	# Checking the presence of Citrix AppSense 8.1
	Run-DiagExpression .\TS_CitrixAppSenseCheck.ps1

	# Check for large number of Inactive Terminal Server ports
	Run-DiagExpression .\TS_KB2655998_InactiveTSPorts.ps1

	# [Idea ID 2285] [Windows] Windows Server 2003 TS Licensing server does not renew new versions of TS Per Device CALs
	Run-DiagExpression .\TS_RemoteDesktopLServerKB2512845.ps1
	
	Run-DiagExpression .\TS_KernelAuthRPCCheck.ps1

	if (test-path $env:Windir\System32\BestPractices\v1.0\Models\Microsoft\Windows\TerminalServices) {
		# BPA RDP
		if ($Global:skipBPA -ne $true) {
		Run-DiagExpression .\TS_BPAInfo.ps1 -BPAModelID "Microsoft/Windows/TerminalServices" -OutputFileName ($Computername + "_TS_BPAInfo.HTM") -ReportTitle "Terminal Services Best Practices Analyzer"
		}
	}
	
Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'HH:mm:ss') $Global:SDPtech - Diag Phase module: TS_Storage ---"
	# Detect 4KB Drives (Disk Sector Size)
	Run-DiagExpression .\TS_DriveSectorSizeInfo.ps1

	# [Idea ID 7345] [Windows] Perfmon - Split IO Counter
	Run-DiagExpression .\TS_DetectSplitIO.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'HH:mm:ss') $Global:SDPtech - Diag Phase module: TS_Setup ---"
	# Collect Setup Event Log for Servicing
	Run-DiagExpression .\TS_ServicingEventLogs.ps1

	# check for WMI corruption on HP systems
	Run-DiagExpression .\TS_HPWMICheck.ps1

	# [Idea ID 1911] [Windows] NTFS metafile cache consumes most of RAM in Win2k8R2 Server
	Run-DiagExpression .\TS_NTFSMetafilePerfCheck.ps1

	# [Idea ID 2346] [Windows] high cpu only on one processor
	Run-DiagExpression .\TS_2K3ProcessorAffinityMaskCheck.ps1

	# [Idea ID 3989] [Windows] STACK MATCH - Win2008R2 - Machine hangs after shutdown, caused by ClearPageFileAtShutdown setting
	Run-DiagExpression .\TS_SBSLClearPageFileAtShutdown.ps1

	# [Idea ID 2753] [Windows] HP DL385 G5p machine cannot generate dump file
	Run-DiagExpression .\TS_ProLiantDL385NMICrashDump.ps1

	# [Idea ID 3253] [Windows] Windows Search service does not start immediately after the machine is booted
	Run-DiagExpression .\TS_WindowsSearchLenovoRapidBootCheck.ps1

	# [Idea ID 2334] [Windows] W2K3 x86 SP2 server running out of paged pool due to D2d tag
	Run-DiagExpression .\TS_KnownKernelTags.ps1

	# [Idea ID 3317] [Windows] DisableEngine reg entry can cause app install or registration failure
	Run-DiagExpression .\TS_AppCompatDisabledCheck.ps1

	# [Idea ID 2357] [Windows] the usage of NPP is very large for XTE.exe
	Run-DiagExpression .\TS_XTENonPagedPoolCheck.ps1

	# [Idea ID 4368] [Windows] Windows Logon Slow and Explorer Slow
	Run-DiagExpression .\TS_2K3CLSIDUserACLCheck.ps1

	# [Idea ID 4649] [Windows] Incorrect values for HeapDecomitFreeBlockThreshold  causes high Private Bytes in multiple processes
	Run-DiagExpression .\TS_HeapDecommitFreeBlockThresholdCheck.ps1

	# [Idea ID 2056] [Windows] Consistent Explorer crash due to wsftpsi.dll
	Run-DiagExpression .\TS_WsftpsiExplorerCrashCheck.ps1

	# [Idea ID 3250] [Windows] Machine exhibits different symptoms due to Confliker attack
	Run-DiagExpression .\TS_Netapi32MS08-067Check.ps1

	# [Idea ID 5194] [Windows] Unable to install vcredist_x86.exe with message (Required file install.ini not found. Setup will now exit)
	Run-DiagExpression .\TS_RegistryEntryForAutorunsCheck.ps1

	# [Idea ID 5452] [Windows] The �Red Arrow� issue in Component Services caused by registry keys corruption
	Run-DiagExpression .\TS_RedArrowRegistryCheck.ps1

	# [Idea ID 5603] [Windows] Unable to start a service due to corruption in the Event Log key
	Run-DiagExpression .\TS_EventLogServiceRegistryCheck.ps1

	# [Idea ID 4783] [Windows] eEye Digital Security causing physical memory depletion
	Run-DiagExpression .\TS_eEyeDigitalSecurityCheck.ps1

	# [Idea ID 5091] [Windows] Super Rule-To check if both 3GB and PAE switch is present in boot.ini for a 32bit OS (Pre - Win 2k8)
	Run-DiagExpression .\TS_SwithesInBootiniCheck.ps1

	# [Idea ID 7018] [Windows] Event Log Service won't start
	Run-DiagExpression .\TS_EventLogStoppedGPPCheck.ps1

	# [Idea ID 8012] [Windows] SDP-UDE check for reg key DisablePagingExecutive
	Run-DiagExpression .\TS_DisablePagingExecutiveCheck.ps1

	# [KSE Rule] [ Windows V3] Server Manager refresh issues and SDP changes reqd for MMC Snapin Issues in 2008, 2008 R2
	Run-DiagExpression .\TS_ServerManagerRefreshKB2762229.ps1

	# [KSE Rule] [ Windows V3] Handle leak in Svchost.exe when a WMI query is triggered by using the Win32_PowerSettingCapabilities
	Run-DiagExpression .\TS_WMIHandleLeakKB2639077.ps1

	# Checks 32 bit windows server 2003 / 2008 to see is DEP is disabled, if so it might not detect more than 4 GB of RAM.
	Run-DiagExpression .\TS_DEPDisabled4GBCheck.ps1

	# [Idea ID 2695] [Windows] Check the Log On account for the Telnet service to verify it's not using the Local System account
	Run-DiagExpression .\TS_TelnetSystemAccount.ps1

	# [Idea ID 2389] [Windows] Hang caused by kernel memory depletion due 'SystemPages' reg key with wrong value
	Run-DiagExpression .\TS_MemoryManagerSystemPagesCheck.ps1

	# [Idea ID 3474] [Windows] Pending Trans Rule - PendingXmlIdentifier, NextQueueEntryIndex, AdvancedInstallersNeedResolving
	Run-DiagExpression .\TS_ServicingComponentsReg.ps1

	# [Idea ID 3472] [Windows] Pending Transactions Rule Idea - Pending.xml
	Run-DiagExpression .\TS_ServicingPendingXml.ps1

	# [Idea ID 5712] [Windows] Run Dism checkhealth on Win8 or 2012 to detect possible servicing corruption
	Run-DiagExpression .\TS_ServicingCorruptionCheck.ps1

	# [Idea ID 1922] [Windows] On Windows 2008 R2 and Windows 7 System state backup fails with event id 5 and error 2155347997
	Run-DiagExpression .\TS_BackupSystemStateKB2182466.ps1

	# [Idea ID 3059] [Windows] Ntbackup high CPU and hang
	Run-DiagExpression .\TS_FilesNotToBackup2K3Check.ps1

	# [Idea ID 2004] [Windows] Bitlocker Drive Preparation fails with Error 'The new active drive cannot be formatted.'
	Run-DiagExpression .\TS_BitlockerDenyWriteFixedPolicy.ps1

	# [Idea ID 6711] [Windows] MSI package fails to install with error code HRESULT -2147319780
	Run-DiagExpression .\TS_MSIPackageInstallationCheck.ps1

	# [Idea ID 3002] [Windows] SP1 installation on Windows 7 and Windows Server 2008 R2 fails with the error 0x800F0826
	Run-DiagExpression .\TS_UsbstorSystemPermissionsSPCheck.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'HH:mm:ss') $Global:SDPtech - Diag Phase module: TS_WinRM ---"
	# Check if hotfix 2480954 installed
	Run-DiagExpression .\TS_KB2480954AndWinRMStateCheck.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'HH:mm:ss') $Global:SDPtech - Diag Phase module: TS_Surface ---"
	# SurfaceDetectWifiDriverVersion
	Run-DiagExpression .\TS_SurfaceDetectWifiDriverVersion.ps1

	# SurfaceDetectFirmwareVersions
	Run-DiagExpression .\TS_SurfaceDetectFirmwareVersions.ps1

	# SurfacePro3DetectWifiDriverVersion
	Run-DiagExpression .\TS_SurfacePro3DetectWifiDriverVersion.ps1

	# SurfacePro3DetectFirmwareVersions
	Run-DiagExpression .\TS_SurfacePro3DetectFirmwareVersions.ps1

	# SurfaceDetectConnectedStandbyStatus
	Run-DiagExpression .\TS_SurfaceDetectConnectedStandbyStatus.ps1
	
	# SurfacePro3DetectConnectedStandbyStatus
	Run-DiagExpression .\TS_SurfacePro3DetectConnectedStandbyStatus.ps1

	# SurfacePro3DetectConnectedStandbyHibernationConfig
	Run-DiagExpression .\TS_SurfacePro3DetectConnectedStandbyHibernationConfig.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'HH:mm:ss') $Global:SDPtech - Diag Phase module: TS_Cluster ---"
 if ($Global:skipTScluster -ne $true) {
	# FailoverCluster Cluster Name Object AD check
	Run-DiagExpression .\TS_ClusterCNOCheck.ps1

	# Collect Basic Cluster System Information
	Run-DiagExpression .\TS_BasicClusterInfo.ps1

	# [Idea ID 2169] [Windows] Xsigo network host driver can cause Cluster disconnects
	Run-DiagExpression .\TS_ClusterXsigoDriverNetworkCheck.ps1

	# [Idea ID 2251] [Windows] Cluster 2003 - Access denied errors during a join, heartbeat, and Cluster Admin open
	Run-DiagExpression .\TS_Cluster2K3NoLmHash.ps1

	# [Idea ID 2513] [Windows] IPv6 rules for Windows Firewall can cause loss of communications between cluster nodes
	Run-DiagExpression .\TS_ClusterIPv6FirewallCheck.ps1

	# [Idea ID 5258] [Windows] Identifying Cluster Hive orphaned resources located in the dependencies key
	Run-DiagExpression .\TS_Cluster_OrphanResource.ps1

	# [Idea ID 6519] [Windows] Invalid Class error on 2012 Clusters (SDP)
	Run-DiagExpression .\TS_ClusterCAUWMINamespaceCheck.ps1

	# [Idea ID 6500] [Windows] Invalid Namespace error on 2008 and 2012 Clusters
	Run-DiagExpression .\TS_ClusterMSClusterWMINamespaceCheck.ps1

	# Cluster Validation Report Troubleshooter
	Run-DiagExpression .\TS_ClusterValidationTests.ps1
 }

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'HH:mm:ss') $Global:SDPtech - Diag Phase module: TS_3rd party ---"
	# [Idea ID 7521] [Windows] McAfee HIPS 7.0 adds numerous extraneous network adapter interfaces to registry
	Run-DiagExpression .\TS_McAfeeHIPS70Check.ps1

	# [Idea ID 986] [Windows] SBSL McAfee Endpoint Encryption for PCs may cause slow boot or delay between CTRL+ALT+DEL and Cred
	Run-DiagExpression .\TS_SBSL_MCAfee_EEPC_SlowBoot.ps1

	# [Idea ID 3181] [Windows] Symantec Endpoint Protection's smc.exe causing handle leak
	Run-DiagExpression .\TS_SEPProcessHandleLeak.ps1

	# Symantec Endpoint Protection MR1 or MR2 check
	Run-DiagExpression .\TS_SymantecEPCheck.ps1
	
	# Check for Sophos BEFLT.SYS version 5.60.1.7
	Run-DiagExpression .\TS_B2693877_Sophos_BEFLTCheck.ps1

	# [KSE Rule] [ Windows V3] HpCISSs2 version 62.26.0.64 causes 0xD1 or 0x9E
	Run-DiagExpression .\TS_HpCISSs2DriverIssueCheck.ps1

	# check for WMI corruption on HP systems
	Run-DiagExpression .\TS_HPWMICheck.ps1

	# Symantec Intrusion Prevenstion System Check
	Run-DiagExpression .\TS_SymantecIPSCheck.ps1

	# [Idea ID 2842] [Windows] Alert Engineers if they are working on a Dell machine models R910, R810 and M910
	Run-DiagExpression .\TS_DellPowerEdgeBiosCheck.ps1

	# [Idea ID 3919] [Windows] Create Shadow Copy fail only on VERTIAS storage foundation volume
	Run-DiagExpression .\TS_VeritasVXIOBadConfigFlags.ps1

	# [Idea ID 5327] [Windows] Machine imaged using vlite 1.2 will fail to install SP1
	Run-DiagExpression .\TS_MachineImageVliteCheck.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- Diag Phase:TS_obsolete W2K3/XP ---"
	# [Idea ID 2446] [Windows] Determining the trimming threshold set by the Memory Manager
	Run-DiagExpression .\TS_2K3PoolUsageMaximum.ps1

	# [Idea ID 2334] [Windows] W2K3 x86 SP2 server running out of paged pool due to D2d tag
	Run-DiagExpression .\TS_KnownKernelTags.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'HH:mm:ss') $Global:SDPtech - TS Phase module: ModernApps ---"
	# [Idea ID 7524] [Windows] WinStore -Modern applications fail to start if 'Audit the access of global system object' is enabled [AutoAdded]
	Run-DiagExpression .\TS_ModernAppsFailureForAuditOptionCheck.ps1

	# [Idea ID 7723] [Windows] WinStore - Modern applications fail to start if incompatible security - av software installed [AutoAdded]
	Run-DiagExpression .\TS_ModernAppsFailureForWindDefenderCheck.ps1

	# [Idea ID 7727] [Windows] WinStore - Cannot install Windows Store Apps [AutoAdded]
	Run-DiagExpression .\TS_ModernAppsFailureForTrustedPathCredentialsCheck.ps1

	# [Idea ID 7712] [Windows] WinStore - Modern Apps fail to run if the UAC File Virtualization driver is not running [AutoAdded]
	Run-DiagExpression .\TS_ModernAppsFailureForUACFileVirtualizationCheck.ps1

	# [Idea ID 7508] [Windows] WinStore - This app cannot open while the User Account Control is turned off [AutoAdded]
	Run-DiagExpression .\TS_ModernAppsFailureForUACDisabledCheck.ps1

	# [Idea ID 6253] [Windows] Win8:APP - Store Apps do not launch due to video resolution [AutoAdded]
	Run-DiagExpression .\TS_StoreAppsFailureForVideoResolutionCheck.ps1

	# [Idea ID 7499] [Windows] Win8:APP - Skype fails to start [AutoAdded]
	Run-DiagExpression .\TS_SkypeFailureForMissingKB2703761Check.ps1

	# [Idea ID 7544] [Windows] WinStore - Apps do not launch, because 'ALL APPLICATIONS PACKAGES' removed from DCOM ACL [AutoAdded]
	Run-DiagExpression .\TS_StoreAppsFailureForDCOMErrorCheck.ps1

	# [Idea ID 7510] [Windows] WinStore - Apps fail to start if default registry permissions modified [AutoAdded]
	Run-DiagExpression .\TS_ModernAppsFailureForRegistryPermissionCheck.ps1

	# [Idea ID 7546] [Windows] WinStore - Modern Apps Fail to Start if the User Profile directory is Moved from default [AutoAdded]
	Run-DiagExpression .\TS_ModernAppsFailureForUserProfileDirCheck.ps1

	# [Idea ID 7547] [Windows] WinStore - Modern Apps Fail to Start if the ProgramData directory is Moved from default [AutoAdded]
	Run-DiagExpression .\TS_ModernAppsFailureForProgramDataDirCheck.ps1

	# [Idea ID 7512] [Windows] WinStore - Apps fail to start if default file permissions modified [AutoAdded]
	Run-DiagExpression .\TS_ModernAppsFailureForFolderPermissionCheck.ps1
}

	if ($Global:runFull -eq $True) {
		#_# newer Setup_Addons, DC_Setup_AppCompat.ps1 long lasting REG task
		Run-DiagExpression .\DC_Setup_Addons.ps1
		Run-DiagExpression .\DC_Setup_AppCompat.ps1
	}

	# Hotfix Rollups
	Run-DiagExpression .\DC_HotfixRollups.ps1
	
Write-Host -BackgroundColor Gray -ForegroundColor Black -Object "*** $(Get-Date -UFormat "%R:%S") DONE TS_AutoAddCommands_ALL.ps1 SkipTS: $Global:skipTS - SkipBPA: $Global:skipBPA"

# SIG # Begin signature block
# MIInrwYJKoZIhvcNAQcCoIInoDCCJ5wCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDrvthiIj95vCu4
# pX5CD/ld4S2MtoUQDhNkBl57owxQzKCCDYEwggX/MIID56ADAgECAhMzAAACzI61
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
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIZhDCCGYACAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAsyOtZamvdHJTgAAAAACzDAN
# BglghkgBZQMEAgEFAKCBsDAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQg+hLShhQe
# 5VdJOiP9rOacpg3B8yvlpjNICGdOcFNaGOQwRAYKKwYBBAGCNwIBDDE2MDSgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRyAGmh0dHBzOi8vd3d3Lm1pY3Jvc29mdC5jb20g
# MA0GCSqGSIb3DQEBAQUABIIBACeNNnnGqK5Vsqct35ILuX1KrnKBvuckhNCX2F7+
# FaozMsaXi0GO/MWkjoQU5LnrigVOX7TX8hEmM5jUmUXx/sjb0myVzEAlObYVU4SN
# g6EOgzTv7V94atNKmq4jBem7iLthm3XfLb+UNUOZ5cPUAbnEdrJn7MZ3PZrDuOJp
# Wt6vbhY3kqk7BB7Qb5/sIZOu/fFCrdlCDOmwg98Rsf1byiiFlUUtOuKdSgXOaVm2
# LDxnL+HgofF/62i1rh5+U5C9Z51whticKPkESibThvk7pq8UCO4ASecA5ISHY4bP
# 8zbCRPzlV4eh7uHzEAUXrkHZZK0stoFqbho5mxV394Tm3F6hghcMMIIXCAYKKwYB
# BAGCNwMDATGCFvgwghb0BgkqhkiG9w0BBwKgghblMIIW4QIBAzEPMA0GCWCGSAFl
# AwQCAQUAMIIBVQYLKoZIhvcNAQkQAQSgggFEBIIBQDCCATwCAQEGCisGAQQBhFkK
# AwEwMTANBglghkgBZQMEAgEFAAQgHo1fC3vZzoECmIUGBN+gUzWbFCQeZyApEAQF
# fAaC1TECBmNOqIenzBgTMjAyMjEwMjQwODE1NDIuMDcyWjAEgAIB9KCB1KSB0TCB
# zjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEpMCcGA1UECxMg
# TWljcm9zb2Z0IE9wZXJhdGlvbnMgUHVlcnRvIFJpY28xJjAkBgNVBAsTHVRoYWxl
# cyBUU1MgRVNOOkY3QTYtRTI1MS0xNTBBMSUwIwYDVQQDExxNaWNyb3NvZnQgVGlt
# ZS1TdGFtcCBTZXJ2aWNloIIRXzCCBxAwggT4oAMCAQICEzMAAAGlAN4IxEAHcU4A
# AQAAAaUwDQYJKoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIw
# MTAwHhcNMjIwMzAyMTg1MTE5WhcNMjMwNTExMTg1MTE5WjCBzjELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEpMCcGA1UECxMgTWljcm9zb2Z0IE9w
# ZXJhdGlvbnMgUHVlcnRvIFJpY28xJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkY3
# QTYtRTI1MS0xNTBBMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2
# aWNlMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAurGG6CBqSLzC6g4w
# x3uuwRCeYCG1XyJTVjSK2werfRN0JckOa9mNpnzK84dgVWFPIPVvkkYm3BmNbPV+
# CUKqzHmoHE/VbHUJmexDW2JGxFZBzXZWQROaRjzHjoyAewbICaE8+myBGeSUZqLs
# epAUHfXH9COTHutsCWvo9uUHi06ZpHWcrGXhUiCy0PB+d4pqgQTDiI3/FN3O1mPD
# IaJjmE2npt562RyLOAkU7f/JEdiHSC2T5tESGuYiBtquuuBvPsyycDu2Uq8Zw72I
# dzr7azKasBXLcLNDggw08VxNPHzBNn6Sm/qUWzV4bzGV+y7Y0NYqyGsyUofYmljN
# YBbV8I4PmKtewTgs6+LFlC9ud5ATr6IZ8hDBpuP59F2i4BTYCIT6Jo2wgNql0ppv
# xYvHPpU9FsQv4zowWRyyiK4oceiyEKnsmGZn2IzTKsTHZd5s6Fr9dDfjYqxEazaH
# TaClfrAHLJPx4PcwlUjFJGbgwsiKW9Zyl303euihrBstTqB2TuCgpZLr37DaO2i5
# cIRi3og99mryV2LQv8LBhu2/uZseYhn05zQkQlzpv2BxUN+g+J6YwpzPXkEt6nLH
# uelDYyIMoixw6oqFe5kj49l6s04eGL++zLb8WP2UHqQmsxhJ9XQXZ+u8FIFcwHvG
# O/ymCpflBdR7ydPFvhR8nRwMC8ECAwEAAaOCATYwggEyMB0GA1UdDgQWBBRfpo8D
# AJeurq1w7vvcWRdLaKka3zAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnp
# cjBfBgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtp
# b3BzL2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5j
# cmwwbAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jv
# c29mdC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQ
# Q0ElMjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUF
# BwMIMA0GCSqGSIb3DQEBCwUAA4ICAQCWmwsX5TAwooRHanRYmejgboYYad+DeqMN
# 1odzm69di0boqYeuoB/9ioeSY2i1KvpkQSeUYIlhHtbe4n7lum+PTfAWoZ5+9Cwo
# hHb6rpOvOjO8/g2yh1ZNPlJWn8LpMQMa4sL2Y5AoDi3IvjQdNbu3FvRwB1+CfIcW
# gj8Gxmj8Vpd7NDyE7jFSOEOnI014npZi9fk0L4e/2eZPLOOrISD8vZxcA6bERa98
# 8BDWV/G+u1TAbvmMZ5Rp7CSHC3NqcKc/eXpiPAkUoHqfv9Ne2t+KTXFjWSB6/UnB
# DlpR0/HBJ0OYYThdM3azqk86Lwg7X305/oAS+HjV4PFHP7XVVRym4afu0lR5JNRI
# ey/NDwQI6PnDvsy/nn8XyFa7Tt6CcbxKtaPn5MXE08KnH8AU2/PP6h1NFNl3gta6
# iZwwdSYsWJQY4B160XpKh8cbkRwWfQNMPVqkFnMI/zGwZBxmDBWqjui/bf+4gmUw
# IsDJNhlX0hMI/T1yJQlsoFUJA2sYSdD9csU72bKzLINGu8eFTm4Y91fPgm3b9k3s
# lBhG5U1K4Kk3CgrQmvWzpyIO8cR4vKJzPGgh70YfdLJ9sfHq/+mEj6ITcNajVMIr
# vkQvqm3qTmLfr+Sfa5JVd1MfjhlWSHf+KFXe8TCzvy4aW+yIxysoGCmjcd1yMMeI
# ehaxR/gYjDCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZI
# hvcNAQELBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# MjAwBgNVBAMTKU1pY3Jvc29mdCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAy
# MDEwMB4XDTIxMDkzMDE4MjIyNVoXDTMwMDkzMDE4MzIyNVowfDELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRp
# bWUtU3RhbXAgUENBIDIwMTAwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoIC
# AQDk4aZM57RyIQt5osvXJHm9DtWC0/3unAcH0qlsTnXIyjVX9gF/bErg4r25Phdg
# M/9cT8dm95VTcVrifkpa/rg2Z4VGIwy1jRPPdzLAEBjoYH1qUoNEt6aORmsHFPPF
# dvWGUNzBRMhxXFExN6AKOG6N7dcP2CZTfDlhAnrEqv1yaa8dq6z2Nr41JmTamDu6
# GnszrYBbfowQHJ1S/rboYiXcag/PXfT+jlPP1uyFVk3v3byNpOORj7I5LFGc6XBp
# Dco2LXCOMcg1KL3jtIckw+DJj361VI/c+gVVmG1oO5pGve2krnopN6zL64NF50Zu
# yjLVwIYwXE8s4mKyzbnijYjklqwBSru+cakXW2dg3viSkR4dPf0gz3N9QZpGdc3E
# XzTdEonW/aUgfX782Z5F37ZyL9t9X4C626p+Nuw2TPYrbqgSUei/BQOj0XOmTTd0
# lBw0gg/wEPK3Rxjtp+iZfD9M269ewvPV2HM9Q07BMzlMjgK8QmguEOqEUUbi0b1q
# GFphAXPKZ6Je1yh2AuIzGHLXpyDwwvoSCtdjbwzJNmSLW6CmgyFdXzB0kZSU2LlQ
# +QuJYfM2BjUYhEfb3BvR/bLUHMVr9lxSUV0S2yW6r1AFemzFER1y7435UsSFF5PA
# PBXbGjfHCBUYP3irRbb1Hode2o+eFnJpxq57t7c+auIurQIDAQABo4IB3TCCAdkw
# EgYJKwYBBAGCNxUBBAUCAwEAATAjBgkrBgEEAYI3FQIEFgQUKqdS/mTEmr6CkTxG
# NSnPEP8vBO4wHQYDVR0OBBYEFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMFwGA1UdIARV
# MFMwUQYMKwYBBAGCN0yDfQEBMEEwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWlj
# cm9zb2Z0LmNvbS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5Lmh0bTATBgNVHSUEDDAK
# BggrBgEFBQcDCDAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMC
# AYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvX
# zpoYxDBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20v
# cGtpL2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYI
# KwYBBQUHAQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNydDANBgkqhkiG
# 9w0BAQsFAAOCAgEAnVV9/Cqt4SwfZwExJFvhnnJL/Klv6lwUtj5OR2R4sQaTlz0x
# M7U518JxNj/aZGx80HU5bbsPMeTCj/ts0aGUGCLu6WZnOlNN3Zi6th542DYunKmC
# VgADsAW+iehp4LoJ7nvfam++Kctu2D9IdQHZGN5tggz1bSNU5HhTdSRXud2f8449
# xvNo32X2pFaq95W2KFUn0CS9QKC/GbYSEhFdPSfgQJY4rPf5KYnDvBewVIVCs/wM
# nosZiefwC2qBwoEZQhlSdYo2wh3DYXMuLGt7bj8sCXgU6ZGyqVvfSaN0DLzskYDS
# PeZKPmY7T7uG+jIa2Zb0j/aRAfbOxnT99kxybxCrdTDFNLB62FD+CljdQDzHVG2d
# Y3RILLFORy3BFARxv2T5JL5zbcqOCb2zAVdJVGTZc9d/HltEAY5aGZFrDZ+kKNxn
# GSgkujhLmm77IVRrakURR6nxt67I6IleT53S0Ex2tVdUCbFpAUR+fKFhbHP+Crvs
# QWY9af3LwUFJfn6Tvsv4O+S3Fb+0zj6lMVGEvL8CwYKiexcdFYmNcP7ntdAoGokL
# jzbaukz5m/8K6TT4JDVnK+ANuOaMmdbhIurwJ0I9JZTmdHRbatGePu1+oDEzfbzL
# 6Xu/OHBE0ZDxyKs6ijoIYn/ZcGNTTY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggLS
# MIICOwIBATCB/KGB1KSB0TCBzjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjEpMCcGA1UECxMgTWljcm9zb2Z0IE9wZXJhdGlvbnMgUHVlcnRvIFJp
# Y28xJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkY3QTYtRTI1MS0xNTBBMSUwIwYD
# VQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloiMKAQEwBwYFKw4DAhoD
# FQCzyXDbRbObEMqI3UuGHuZlZe60qKCBgzCBgKR+MHwxCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0
# YW1wIFBDQSAyMDEwMA0GCSqGSIb3DQEBBQUAAgUA5wBnHjAiGA8yMDIyMTAyNDA1
# MjEzNFoYDzIwMjIxMDI1MDUyMTM0WjB3MD0GCisGAQQBhFkKBAExLzAtMAoCBQDn
# AGceAgEAMAoCAQACAgX6AgH/MAcCAQACAhFiMAoCBQDnAbieAgEAMDYGCisGAQQB
# hFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEAAgMHoSChCjAIAgEAAgMBhqAw
# DQYJKoZIhvcNAQEFBQADgYEAKXuX8Hm3jOk34Tn5wvWL61q/hComrVkXPCHjyAwf
# frd6180+kAdYjSdekh13/RTncpoHq2aV/++u9UPJdjIlfhmk4uqIY0NwqV5FcOag
# 9p+IV2pgUTB8A+FYkIG7TEilju+/RhUxPiP03EPdE+Bl5N5L3BtLDAZ5DaWpNHtp
# rAYxggQNMIIECQIBATCBkzB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAIT
# MwAAAaUA3gjEQAdxTgABAAABpTANBglghkgBZQMEAgEFAKCCAUowGgYJKoZIhvcN
# AQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJBDEiBCAgW3mG8BiPyZizusmv
# hGEpGKAVXf7DMCYWm01RgfisYjCB+gYLKoZIhvcNAQkQAi8xgeowgecwgeQwgb0E
# ILgKOHF+ZgSxoK3YBTzcqGH7okeXKTcHvS98wcyUEtxcMIGYMIGApH4wfDELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGlAN4IxEAHcU4AAQAAAaUwIgQg
# r1lLqKT/ZtKy1G9EAcBEreRtPJ9Kedq6JB9l89VWKlEwDQYJKoZIhvcNAQELBQAE
# ggIAlyT5jQo5Gk8bTMrjIwRX9icIQIEy9EBB+3Ru/P3qad9PudDPemmtcKFvIstZ
# 8wjng4NiRqdoU0RC9M26w284Us72N3qW4INL1ZcIytx78TbHsKYKenGUOEG+9VL2
# fknMzAr3mqIMcmxsidJlVFoXCdm7qVwOgYLzK/DIbGV5c0PPKtvA6934n6QCxtUl
# s9VzphlQoZixlCVDyCKEAtyCuHuEjuBGAYbb2R9i4b2L/R9Hf0td+eYQMfPtxeRH
# qsUyz0oK/vQmp/OywXPO5CmMmOhEhyEyTNyQ+Yyy5m8EeCZa9FyHJ+1hgbe6nRkU
# dbplDfL/1efuNdFei4dQaapLES42rSvYyz269RBhP588qp0bOLhq7OCBF1s0ozUm
# Rk4wrfYV3EE8osgXziFma7ppFrNs8gDe1kNKPdTQQbUxFGuDq4pKPtdjS9/iIjDa
# omhJSi4PjbBTDmCDgN95G6XCxpk4wbcAlFYEIfx2UoVquBo0PeZSv9IOfPelKPGc
# Oo/O8DOlIG1aJbWMipZ0kpviR7wj8T4SKMSofXClz3cyjcGdifCvVl2niK7adK0q
# kovgwSTnnuWySSDqTQYwS2Ll82bEx6jGkgn8WYZ2JyLvUXv95MssqNBUiTT5JKSx
# V+F85FfPp4wdeDUz2L0pzitsQpYVTz3ockYZoQ9FYh1Vp44=
# SIG # End signature block
