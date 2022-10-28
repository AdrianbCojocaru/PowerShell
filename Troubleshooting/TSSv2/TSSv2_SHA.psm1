<#
.SYNOPSIS
   SHA module for collecting ETW traces and various custom tracing functionality

.DESCRIPTION
   Define ETW traces for Windows SHA components 
   Add any custom tracing functinaliy for tracing SHA components
   For Developers:
   1. Component test: .\TSSv2.ps1 -Start -SHA_TEST1
   2. Scenario test:  .\TSSv2.ps1 -start -Scenario SHA_MyScenarioTest

.NOTES  
   Authors    : <your_alias>;WalterE; RobertVi; Kojii
   Requires   : PowerShell V4 (Supported from Windows 8.1/Windows Server 2012 R2)
   Version	: see $global:TssVerDateSHA

.LINK
	TSSv2 https://internal.support.services.microsoft.com/en-us/help/4619187
	SHA https://internal.support.services.microsoft.com/en-us/help/5009525
#>

<# latest changes
  2022.10.24.2 [we] modify $VmlTrace_exe and $FrutiExe invocation
  2022.10.14.0 [we] add SHA_StorageSense
  2022.08.22.0 [rvi] SpaceDB Chkspace collection
  2022.07.21.0 [we] SHA_fix MsCluster definition
  2022.06.10.0 [we] add SHA_VML (use -Mode verbose to restart the Hyper-V service and get FRUTI log); upd SHA_MSCluster
  2022.04.15.0 [ki] add ETW from shacollector
  2022.01.24.0 [we] add SHA_ReFS
  2022.01.24.0 [we] update SHA_Storage with all aka SAN Shotgun from Insightweb
  2022.01.03.0 [we] mod SHA_HypHost/HypVM/ShieldedVM
  2021.12.31.1 [we] #_# _SHA: moved NET_ ShieldedVM,HypHost,HypVM to SHA_
  2021.12.16.0 [rvi] _SHA: fix SHA_SDDC when command was never installed
  2021.12.09.0 [we] _SHA: fix SHA_SDDC
  2021.12.05.0 [we] #_# _SHA: add SHA_SMS per GetSmsLogs.psm1
  2021.11.29.0 [we] #_# moving NET_CSVspace, NET_MPIO, NET_msDSM to SHA
  2021.11.10.0 [we] #_# replaced all 'Get-WmiObject' with 'Get-CimInstance' to be compatible with PowerShell v7
  2021.10.26.0 [we] #_# add MSCluster; add CollectSHA_SDDCLog by calling external psSDP scripts
	ex.1: .\TSSv2.ps1 -Start -Scenario SHA_MSCluster
	ex.2: .\TSSv2.ps1 -CollectLog SHA_SDDC
#>

#region --- Define local SHA Variables
$global:TssVerDateSHA= "2022.10.24.2"
$OSVER3 		= $global:OSVersion.build
if ($OSVER3 -ge 18362) {$FrutiExe = $global:ScriptFolder + "\BIN\fruti_1903.exe"}else{$FrutiExe = $global:ScriptFolder + "\BIN\fruti_RS1.exe"}
if ($OSVER3 -eq 9200) {$VmlTrace_exe = $global:ScriptFolder + "\BIN\VmlTrace_2012.exe"}else{$VmlTrace_exe = $global:ScriptFolder + "\BIN\VmlTrace.exe"}
#endregion --- Define local SHA Variables

#region --- ETW component trace Providers ---

# Normal trace -> data will be collected in a sign
# $SHA_TEST1Providers = @(
# 	'{CC85922F-DB41-11D2-9244-006008269001}' # LSA
# 	'{6B510852-3583-4E2D-AFFE-A67F9F223438}' # Kerberos
# )

<# Normal trace with multi etl files
$SHA_TEST3Providers = @(
	'{98BF1CD3-583E-4926-95EE-A61BF3F46470}!CertCli'
	'{6A71D062-9AFE-4F35-AD08-52134F85DFB9}!CertificationAuthority'
)
#>

$SHA_DummyProviders = @(	#for components without a tracing GUID
	'{eb004a05-9b1a-11d4-9123-0050047759bc}' # Dummy tcp for switches without tracing GUID (issue #70)
)
$SHA_VMLProviders 	= $SHA_DummyProviders

$SHA_MsClusterProviders = @(
    '{9F7FE238-9505-4B84-8B33-268C9204268E}' # Microsoft.Windows.Clustering.ClusterResource
    '{50d577a6-b3e7-4642-9e4d-05200376a5cf}' # Microsoft.Windows.Server.FailoverClustering.Failure
    '{f40422bd-f483-449a-99c7-c4546950112c}' # Microsoft.Windows.Server.FailoverClusteringDevelop
    '{3122168f-2432-45f0-b91c-3af363c14999}' # ClusApiTraceLogProvider
    '{8bdb2a89-5d40-4a5f-afd8-8b1e0ce3abc9}' # Microsoft-Windows-WSDR
    '{baf908ea-3421-4ca9-9b84-6689b8c6f85f}' # Microsoft-Windows-FailoverClustering
    '{a82fda5d-745f-409c-b0fe-18ae0678a0e0}' # Microsoft-Windows-FailoverClustering-Client
    '{0DAD9561-2E3B-49BB-93D7-B49603BA6173}' # DVFLT
    '{b529c110-72ba-4e7f-8ba7-366e3f5faeb0}' # Microsoft.Windows.Clustering.WmiProvider
    '{282968B4-215F-4568-B4A5-C2E5467C301E}' # Microsoft.Windows.Clustering.ClusterService
    '{60431de6-ecae-4926-8e10-0918d219a0a1}' # Microsoft.Windows.Server.FailoverClustering.Set.Critical
    '{49F59745-7F56-4082-A01A-83BC089D1ADD}' # Microsoft.Windows.Health
    '{372968B4-215F-4568-B4A5-C2E5467C301E}' # Microsoft.Windows.Clustering.EbodTargetMgr
    '{1de9cea2-60ce-49fa-a8b7-84139ac12b31}' # Microsoft.Windows.Clustering.S2DCache
    '{0461be3c-bc15-4bad-9a9e-51f3fadfec75}' # Microsoft-Windows-FailoverClustering-WMIProvider	# included in SHA_HyperV
    '{ff3e7036-643f-430f-b015-2933466ff0fd}' # Microsoft-Windows-FailoverClustering-WMI			# included in SHA_HyperV
    '{11B3C6B7-E06F-4191-BBB9-7099FFF55614}' # Microsoft-Windows-FailoverClustering-Manager
    '{f0a43898-4017-4d3b-acac-ff7fb8ac63cd}' # Microsoft-Windows-Health
    '{C1FCCEB3-3F19-42A9-95B9-27B550FA1FBA}' # Microsoft-Windows-FailoverClustering-NetFt
    '{10629806-46F2-4366-9092-53025E067E8C}' # Microsoft-Windows-ClusterAwareUpdating
    '{9B9E93D6-5569-4179-8C8A-5201CB2B9536}' # Microsoft-Windows-ClusterAwareUpdating-Management
    '{7FEF367F-E76C-4592-9912-E12B36A99780}' # Microsoft-Windows-FailoverClustering-ClusDisk-Diagnostic
    '{5d9e8ca1-8634-457b-8d0b-3ba944bc2ff0}' # Microsoft-Windows-FailoverClustering-TargetMgr-Diagnostic
    '{6F0771DD-4096-4E5E-A549-FC1238F5A1B2}' # Microsoft-Windows-FailoverClustering-ClusTflt-Diagnostic
    '{29c07d0e-e5a0-4e85-a004-1f668531ce22}' # Microsoft-Windows-FailoverClustering-Clusport-Diagnostic
    '{4339CD79-93D6-4F55-A96A-F7762E8AF2DE}' # Microsoft-Windows-FailoverClustering-ClusPflt-Diagnostic
    '{40CB8729-8896-4CAB-90E0-2A3AEBA730C2}' # Microsoft-Windows-FailoverClustering-ClusHflt-Diagnostic
    '{E68AB9C0-49F4-4786-A6E0-F323E0BE590C}' # Microsoft-Windows-FailoverClustering-ClusDflt-Diagnostic
    '{53A840C4-8E2B-4D39-A3F6-708834AA4620}' # Microsoft-Windows-FailoverClustering-ClusCflt-Diagnostic
    '{923BCB94-58D2-42BE-BBA9-B1315F363838}' # Microsoft-Windows-FailoverClustering-ClusBflt-Diagnostic
    '{0ac0708a-a44e-49ef-aa7e-fbe8ccc603a6}' # Microsoft-Windows-FailoverClustering-SoftwareStorageBusTarget
    '{7F8DA3B5-A58F-481E-9637-D41435AE6D8B}' # Microsoft-Windows-SDDC-Management
    '{6e580567-c67c-4b96-934e-fc2996e103ae}' # ClusDiskLogger									# included in SHA_Storage
    '{BBB672F4-E56A-4529-90C0-1421E27DE4BE}' # svhdxpr
    '{b6c164c7-4152-4b94-af14-0dac3d0556a3}' # StorageQoSTraceGuid
    '{7e66368d-b895-45f2-811f-fb37940421a6}' # NETFT
    '{8a391cc0-6303-4a25-833f-e7db345941d6}' # VBus
    '{f8f6ae53-b3b3-451f-b204-6b62550efb5c}' # cbflt
    '{EB94F195-9596-49EC-825D-6329F48BD6E9}' # cdflt
    '{7ba7dbd4-e7a9-47db-ac47-4ac1182a82f5}' # cbflt
    '{88AE0E2D-0377-48A1-85C5-FBCC32ACB6BA}' # SddcResGuid
    '{4FA1102E,CC1D,4509,A69F,121E2CC96F9C}' # SddcWmiGuid
    '{FEBD78F8-DDC5-484D-848C-982F1F483278}' # Microsoft-Windows-FailoverClustering-Replication
)
<#
#separated: 
$SHA_MsClusterProviders += @(
	$SHA_ISCSIProviders
	$SHA_MPIOProviders 	# included in SHA_StorageProvider
	$SHA_msDSMProviders 
	$SHA_StorageReplicaProviders 
	$SHA_StorageSpaceProviders 
	$SHA_StorportProviders 
	$SHA_StorageProviders # includes SHA_ISCSI, SHA_MPIO
)
#>

$SHA_CSVFSProviders = @(
	'{0cfda7f5-7549-575e-d095-dcc1e4fbaa3f}' # Microsoft.Windows.Server.CsvFsCritical
	'{4e6177a5-c0a7-4d9b-a686-56ed5435a908}' # nflttrc
	'{B421540C-1FC8-4c24-90CC-C5166E1DE302}' # CSVFLT
	'{d82dba12-8b70-49ee-b844-44d0885951d2}' # CSVFLT
	'{4e6177a5-c0a7-4d9b-a686-56ed5435a904}' # VBus
	'{af14af06-a558-4ff0-a061-9080e33212d6}' # CsvCache
	'{151D3C03-E442-4C4F-AF20-BD48FF41F793}' # Microsoft-Windows-FailoverClustering-CsvFlt-Diagnostic
	'{6a86ae90-4e9b-4186-b1d1-9ce0e02bcbc1}' # Microsoft-Windows-FailoverClustering-CsvFs-Diagnostic
)

$SHA_CSVspaceProviders = @(
	'{595F7F52-C90A-4026-A125-8EB5E083F15E}' # "Microsoft-Windows-StorageSpaces-Driver"
	'{929C083B-4C64-410A-BFD4-8CA1B6FCE362}' # Spaceport
	'{E7D0AD21-B086-406D-BE46-A701A86A5F0A}' # SpTelemetry
)

$SHA_MPIOProviders = @(
	'{8E9AC05F-13FD-4507-85CD-B47ADC105FF6}' # Storage - MPIO
	'{8B86727C-E587-4B89-8FC5-D1F24D43F69C}' # StorPort
	'{FA8DE7C4-ACDE-4443-9994-C4E2359A9EDB}' # Storage - ClassPnP
)

$SHA_MSDSMProviders = @(
	'{DEDADFF5-F99F-4600-B8C9-2D4D9B806B5B}' # Storage - MSDSM
	'{C9C5D896-6FA9-49CD-9BFD-BF5C232C1124}' # MsdsmTraceLoggingProvider
	'{CBC7357A-D802-4950-BB14-817EAD7E0176}' # Reliability DataVerFilter
)

$SHA_ReFSProviders = @(
	'{CD9C6198-BF73-4106-803B-C17D26559018}' # Microsoft-Windows-ReFS
	'{740F3C34-57DF-4BAD-8EEA-72AC69AD5DF5}' # RefsWppTrace
	'{059F0F37-910E-4FF0-A7EE-AE8D49DD319B}' # Microsoft-Windows-ReFS-v1
	'{6D2FD9C5-8BD8-4A5D-8AA8-01E5C3B2AE23}' # Refsv1WppTrace
	'{F9A81F79-369B-443C-9428-FC1DD98316F6}' # Microsoft.Windows.FileSystem.ReFSUtil
	'{61D5C496-C69B-5B72-DE0A-29248A17CACE}' # RefsTelemetryProvider
	'{036647D2-2FB0-4E32-8349-3F5C19C16E5E}' # ReFS
	'{740F3C34-57DF-4BAD-8EEA-72AC69AD5DF5}' # Ntfs_ProtogonWmiLog
	'{AF20A152-62E5-4AA3-A264-48EB87549B75}' # Microsoft-Windows-Minstore-v1
)

$SHA_ShieldedVMProviders = @(
	'{7DEE1FDC-FFA8-4087-912A-95189D6A2D7F}' # Microsoft-Windows-HostGuardianService-Client
	'{0F39F1F2-65CC-4164-83B9-9BCADEDBAF18}' # Microsoft-Windows-ShieldedVM-ProvisioningService
	'{5D0B0AB2-1640-40E4-81F6-05403AF6C38B}' # Microsoft-Windows-ShieldedVM-ProvisioningSecureProcess
	'{5D487FAD-104B-5CA6-CA4E-14C206850501}' # Microsoft-Windows-HostGuardianClient-Service
)

$SHA_StorPortProviders = @(
	'[C4636A1E-7986-4646-BF10-7BC3B4A76E8E}' # "Microsoft-Windows-StorPort"
	'{8B86727C-E587-4B89-8FC5-D1F24D43F69C}' # StorPort
	'{4EEB8774-6C4C-492F-8F2F-5EE4721B7BF7}' # StorportTraceLoggingProvider
)

$SHA_VSSProviders = @(
	'{9138500E-3648-4EDB-AA4C-859E9F7B7C38}' # VSS tracing provider
	'{77D8F687-8130-4A14-B8A6-3B922E05B99C}' # VSS tracing event
	'{f3625a85-421c-4a1e-a54f-6b65c0276c1c}' # VirtualBus
	'{6407345b-94f2-44c8-b3db-4e076be46816}' # WPP_GUID_ASR
	'{89300202-3cec-4981-9171-19f59559e0f2}' # Microsoft-Windows-FileShareShadowCopyProvider
	'{a0d45273-3386-4f3a-b344-0d8fee74e06a}' # Microsoft-Windows-FileShareShadowCopyAgent
	'{67FE2216-727A-40CB-94B2-C02211EDB34A}' # Microsoft-Windows-VolumeSnapshot-Driver
	'{CB017CD2-1F37-4E65-82BC-3E91F6A37559}' # Volsnap(manifest based)
)

$SHA_VDSProviders = @(
	'{012F855E-CC34-4DA0-895F-07AF2826C03E}' # VDS
	'{EAD10F56-E9D4-4B29-A44F-C97299DE5085}' # Microsoft.Windows.Storage.VDS.Service
	'{F5204334-1420-479B-8389-54A4A6BF6EF8}' # volmgr
	'{945186BF-3DD6-4F3F-9C8E-9EDD3FC9D558}' # WPP_GUID_DISK
	'{467C1914-37F0-4C7D-B6DB-5CD7DFE7BD5E}' # Mount Manager Trace
	'{A8169755-BD1C-49a4-B346-4602BCB940AA}' # DISKMGMT
	'{EAD10F56-E9D4-4B29-A44F-C97299DE5086}' # Microsoft.Windows.Storage.DiskManagement
	'{EAD10F56-E9D4-4B29-A44F-C97299DE5088}' # Microsoft.Windows.Storage.DiskRaid
	'{EAD10F56-E9D4-4B29-A44F-C97299DE5090}' # Microsoft.Windows.Storage.VDS.BasicDisk
)

$SHA_WSBProviders = @(
	'{6B1DB052-734F-4E23-AF5E-6CD8AE459F98}' # WPP_GUID_UDFS
	'{944a000f-5f60-4e5a-86fd-d55b84b543e9}' # WPP_GUID_UDFD
	'{6407345b-94f2-44c8-b3db-4e076be46816}' # WPP_GUID_ASR
	'{7e9fb43e-a801-430c-9f36-c1146a51ed07}' # WPP_GUID_DSM
	'{4B966436-6781-4906-8035-9AF94B32C3F7}' # WPP_GUID_SPP
	'{1DB28F2E-8F80-4027-8C5A-A11F7F10F62D}' # Microsoft-Windows-Backup
	'{5602c36e-b813-49d1-a1aa-a0c2d43b4f38}' # BLB
	'{864d2d93-276f-4a88-8bce-d8d174e39c4d}' # Microsoft.Windows.SystemImageBackup.Engine
	'{9138500E-3648-4EDB-AA4C-859E9F7B7C38}' # VSS tracing provider
	'{67FE2216-727A-40CB-94B2-C02211EDB34A}' # Microsoft-Windows-VolumeSnapshot-Driver
	'{CB017CD2-1F37-4E65-82BC-3E91F6A37559}' # Volsnap(manifest based)
)

$SHA_ATAPortProviders = @(
	'{cb587ad1-cc35-4ef1-ad93-36cc82a2d319}' # Microsoft-Windows-ATAPort
	'{d08bd885-501e-489a-bac6-b7d24bfe6bbf}' # ataport guid
)

$SHA_CDROMProviders = @(
	'{9b6123dc-9af6-4430-80d7-7d36f054fb9f}' # Microsoft-Windows-CDROM
	'{A4196372-C3C4-42D5-87BF-7EDB2E9BCC27}' # cdrom.sys
	'{944a000f-5f60-4e5a-86fd-d55b84b543e9}' # WPP_GUID_UDFD
	'{6B1DB052-734F-4E23-AF5E-6CD8AE459F98}' # WPP_GUID_UDFS
	'{F8036571-42D9-480A-BABB-DE7833CB059C}' # IMAPI2FS Tracing
	'{0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E9D}' # IMAPI2 Concatenate Stream
	'{0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E91}' # IMAPI2 Disc Master
	'{0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E93}' # IMAPI2 Disc Recorder
	'{0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E92}' # IMAPI2 Disc Recorder Enumerator
	'{0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E90}' # IMAPI2 dll
	'{0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E9E}' # IMAPI2 Interleave Stream
	'{0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E97}' # IMAPI2 Media Eraser
	'{0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E9F}' # IMAPI2 MSF
	'{0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7EA0}' # IMAPI2 Multisession Sequential
	'{0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E9C}' # IMAPI2 Pseudo-Random Stream
	'{0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E9A}' # IMAPI2 Raw CD Writer
	'{0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E98}' # IMAPI2 Standard Data Writer
	'{0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E99}' # IMAPI2 Track-at-Once CD Writer
	'{0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E94}' # IMAPI2 Utilities
	'{0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E96}' # IMAPI2 Write Engine
	'{0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E9B}' # IMAPI2 Zero Stream
)

$SHA_DedupProviders = @(
	'{F9FE3908-44B8-48D9-9A32-5A763FF5ED79}' # Microsoft-Windows-Deduplication
	'{1D5E499D-739C-45A6-A3E1-8CBE0A352BEB}' # Microsoft-Windows-Deduplication-Change
	'{5ebb59d1-4739-4e45-872d-b8703956d84b}' # SrmTracingProviderGuid
	'{c503ed7b-d3d1-421b-97cd-22f4e7445f2a}' # Microsoft.Windows.Deduplication.Service
	'{c503ed7b-d3d1-421b-97cd-22f4e7455f2a}' # Microsoft.Windows.Deduplication.Pipeline/Store/DataPort/Scanner
	'{611b641a-8c01-449b-ab5b-a9f18adc4e3c}' # DdpFltLogGuid
	'{767c881e-f7f5-418e-a428-a113c3a8630a}' # DdpFltTraceGuid
)

$SHA_FSRMProviders = @(
	'{39af31ab-064d-494b-a0f7-cc90215bdac0}' # Microsoft.Windows.FSRM
	'{3201c659-d580-4833-b17d-1adaf643c64c}' # SrmTracingProviderGuid
	'{6e82d70f-403d-4194-b724-85109b2f2028}' # SrmTracingEventGuid
	'{1214600f-df79-4a03-94f5-65d7cab4fd16}' # Quota
	'{DB4A5343-AC92-4B83-9D84-7ED8FADD7AA5}' # Datascrn
	'{1C7BC728-8199-48BE-BD4D-406A63303C8D}' # Cbafilt
	'{F3C5E28E-63F6-49C7-A204-E48A1BC4B09D}' # Microsoft-Windows-FilterManager
)

$SHA_HyperVProviders = @(
	'{AE7E4D1D-16C7-4807-A2E4-980EDF16D031}' # Microsoft.Windows.HyperV.SysprepProvider
	'{949B9EDC-ADDA-4712-A3E7-D2DCA33E84E8}' # Microsoft.Windows.HyperV.UpgradeComplianceCheck
	'{4DDF50D0-75DE-4FBE-8F08-F8936638E7A1}' # Microsoft.Windows.HyperV.Management
	'{85A7888C-4EF7-5C56-643F-FBD6DC10FEBE}' # Microsoft.Windows.HyperV.KvpExchange
	'{d90b9468-67f0-5b3b-42cc-82ac81ffd960}' # Microsoft.Windows.Subsystem.Lxss
	'{b99cdb5a-039c-5046-e672-1a0de0a40211}' # Microsoft.Windows.Lxss.Manager
	'{06C601B3-6957-4F8C-A15F-74875B24429D}' # Microsoft.Windows.HyperV.Worker
	'{7568b40b-dc66-5a30-55a1-d0ef61b56ac8}' # Microsoft.Windows.HyperV.Worker.Intercepts
	'{5e01db5e-1944-5314-c040-c90b965ea3d3}' # Microsoft.Windows.HyperV.Worker.MemoryManager
	'{1111450B-DACC-40A3-84AB-F7DBA4A6E63A}' # Microsoft.Windows.HyperV.VID
	'{5931D877-4860-4ee7-A95C-610A5F0D1407}' # Microsoft-Windows-Hyper-V-VID
	'{f83552c4-a4e8-50f7-b2d4-a9705c474490}' # Microsoft.Windows.HyperV.TimeSync
	'{a20b1fd7-ac6e-4e79-81c9-23b3c5e97444}' # Microsoft.Windows.HyperV.PCIProxy
	'{b2ed3bdb-cd74-5b2c-f660-85079ca074b3}' # Microsoft.Windows.HyperV.Socket
	'{544d0787-9f6d-432e-8414-e035a8b0541d}' # Microsoft.Windows.HyperV.Storvsp
	'{8dfb8c22-55c0-494d-8c75-a4cc35b0c535}' # Microsoft.Windows.HyperV.Vsmb
	'{2174371b-d5f6-422b-bfc4-bb6f97ddaa84}' # Microsoft.Windows.HyperV.Storage
	'{D0E4BC17-34C7-43fc-9A72-D89A59D6979A}' # Microsoft.Windows.HostNetworkingService.PrivateCloudPlugin
	'{6C28C7E5-331B-4437-9C69-5352A2F7F296}' # Microsoft-Windows-Hyper-V-VmsIf
	'{67DC0D66-3695-47C0-9642-33F76F7BD7AD}' # Microsoft.Windows.Hyper-V.VmSwitch
	'{152FBE4B-C7AD-4f68-BADA-A4FCC1464F6C}' # Microsoft.Windows.Hyper-V.NetVsc
	'{93f693dc-9163-4dee-af64-d855218af242}' # Microsoft-Windows-Hyper-V-NetMgmt
	'{0b4745b0-c990-4780-965a-391afd9424b8}' # Microsoft.Windows.HyperV.NetworkMigrationPlugin
	'{F20F4146-DB1D-4FE8-8C86-49BF5CF7390D}' # L2BridgeTraceLoggingProvider
	'{0c885e0d-6eb6-476c-a048-2457eed3a5c1}' # Microsoft-Windows-Host-Network-Service
	'{f5bf2dc5-fd9c-546d-f37b-9cbe631a065b}' # Microsoft.Windows.HyperV.DynamicMemory
	'{4f542162-e9cf-5eca-7f74-1fb63a59a6c2}' # Microsoft.Windows.HyperV.GuestCrashDump
	'{a572eeb4-c3f7-5b0e-b669-bb200931d134}' # Microsoft.Windows.HyperV.Worker.VmbusPipeIO
	'{51ddfa29-d5c8-4803-be4b-2ecb715570fe}' # Microsoft-Windows-Virtualization-Worker
	'{e5ea3ca6-5eb0-597d-504a-2fd09ccdefda}' # ICVdevDeviceEtwTrace
	'{339aad0a-4124-4968-8147-4cbbb1f8b3d5}' # Microsoft-Windows-Virtualization-UiDevices
	'{13eae551-76ca-4ddc-b974-d3a0f8d44a03}' # Microsoft-Windows-Virtualization-Tpm
	'{7b0ea079-e3bc-424a-b2f0-e3d8478d204b}' # Microsoft-Windows-VStack-VSmb
	'{4D20DF22-E177-4514-A369-F1759FEEDEB3}' # Microsoft-Windows-VIRTDISK
	'{EDACD782-2564-4497-ADE6-7199377850F2}' # Microsoft-Windows-VStack-SynthStor
	'{6c3e21aa-36c0-5476-818a-3d71fc67c9e8}' # Microsoft-Windows-Hyper-V-NvmeDirect
	'{8f9df503-1d12-49ec-bb28-f6ec42d361d4}' # Microsoft-Windows-Virtualization-serial
	'{c29c4fb7-b60e-4fff-9af9-cf21f9b09a34}' # Microsoft-Windows-VStack-SynthNic
	'{a86e166e-7d3c-402d-8fe0-2a3e62c93864}' # Microsoft-Windows-Virtualization-Worker-GPUP
	'{B1D080A6-F3A5-42F6-B6F1-B9FD86C088DA}' # Microsoft-Windows-Hyper-V-DynMem
	'{c7c9e4f7-c41d-5c68-f104-d72a920016c7}' # Microsoft-Windows-Hyper-V-CrashDump
	'{de9ba731-7f33-4f44-98c9-6cac856b9f83}' # Microsoft-Windows-Virtualization-Chipset
	'{02f3a5e3-e742-4720-85a5-f64c4184e511}' # Microsoft-Windows-Virtualization-Config
	'{17103E3F-3C6E-4677-BB17-3B267EB5BE57}' # Microsoft-Windows-Hyper-V-Compute
	'{45F54D37-2377-4B64-B396-370E31ACB204}' # Microsoft-Windows-Hyper-V-ComputeCExec
	'{AF7FD3A7-B248-460C-A9F5-FEC39EF8468C}' # Microsoft-Windows-Hyper-V-ComputeLib
	'{6066F867-7CA1-4418-85FD-36E3F9C0600C}' # Microsoft-Windows-Hyper-V-VMMS
	'{0461BE3C-BC15-4BAD-9A9E-51F3FADFEC75}' # Microsoft-Windows-FailoverClustering-WMIProvider
	'{FF3E7036-643F-430F-B015-2933466FF0FD}' # Microsoft-Windows-FailoverClustering-WMI
	'{177D1599-9764-4E3A-BF9A-C86887AADDCE}' # Microsoft-Windows-Hyper-V-VmbusVdev
	'{09242393-1349-4F4D-9FD7-59CC79F553CE}' # Microsoft-Windows-Hyper-V-EmulatedNic
	'{2ED5C5DF-6026-4E25-9FB1-9A08701125F3}' # Microsoft.Windows.HyperV.VMBus
	'{2B74A015-3873-4C56-9928-EA80C58B2787}' # Heartbeat VDEV (vmicheartbeat)
	'{1CEB22B1-97FF-4703-BEB2-333EB89B522A}' # Microsoft-Windows-Hyper-V-VMSP (VM security process implementation)
	'{AE3F5BF8-AB9F-56D6-29C8-8C312E2FAEC2}' # Microsoft-Windows-Hyper-V-Virtual-PMEM
	'{DA5A028B-B248-4A75-B60A-024FE6457484}' # Microsoft-Windows-Hyper-V-EmulatedDevices
	'{6537FFDF-5765-517E-C03C-55A8E5A97C10}' # Microsoft-Windows-Hyper-V-KernelInt
	'{52FC89F8-995E-434C-A91E-199986449890}' # Microsoft-Windows-Hyper-V-Hypervisor
	'{82DA50E7-D261-4BD1-BBB9-3213E0EFE360}' # Microsoft.Windows.HyperV.MigrationPlugin
	'{C3A331B2-AF4F-5472-FD2F-4313035C4E77}' # Microsoft.Windows.HyperV.GpupVDev
	'{06C601B3-6957-4F8C-A15F-74875B24429D}' # VmwpTelemetryProvider (VmWpStateChange)
	'{8B0287F8-755D-4BC8-BD76-4CE327C4B78B}' # Microsoft-Windows-Hyper-V-WorkerManager
	'{9193A773-E60D-4171-8468-05C000581B71}' # Image Management Service (vhdsvc)
	'{0A18FF18-5362-4739-9671-78023D747B70}' # Virtual Network Management Service (nvspwmi)
	'{86E15E01-EDF1-4AC7-89CF-B19563FD6894}' # Emulated Storage VDEV (emulatedstor)
	'{82D60869-5ADA-4D49-B76A-309B09666584}' # KVP Exchange VDEV (vmickvpexchange)
	'{BC714241-8EDC-4CE3-8714-AA0B51F98FDF}' # Shutdown VDEV (vmicshutdown)
	'{F152DC14-A3A0-4258-BECE-69A3EE4C2DE8}' # Time Synchronization VDEV (vmictimesync)
	'{67E605EE-A4D8-4C46-AE50-893F31E13963}' # VSS VDEV (vmicvss)
	'{64E92ABC-910C-4770-BD9C-C3C54699B8F9}' # Clustering Resource DLL (vmclusres)
	'{5B621A17-3B58-4D03-94F0-314F4E9C79AE}' # Synthetic Fibre Channel VDEV (synthfcvdev)
	'{6357c13a-2eb3-4b91-b580-79682eb76986}' # Virtual FibreChannel Management Service (fcvspwmi)
	'{2ab5188c-5915-4629-9f8f-b3b20c78d1b0}' # VM Memory-Preserving Host Update DLL (vmphu)
    '{573a8439-2c0f-450b-bf98-51a86843d700}' # Dynamic Memory (guest)
    '{F96ABC17-6A5E-4A49-A3F4-A2A86FA03846}' # storvsc (guest)
    '{CB5B2C18-AD73-4EBF-8AF1-73B30B885030}' # VMBus (guest)
)

$SHA_HypVmBusProviders = @(
	'{F2E2CE31-0E8A-4E46-A03B-2E0FE97E93C2}' # Microsoft-Windows-Hyper-V-Guest-Drivers-Vmbus
	'{CB5B2C18-AD73-4EBF-8AF1-73B30B885030}' # VMBusDriverTraceGuid
	'{FA3F78FF-BA6D-4EDE-96B2-9C5BB803E3BA}' # Microsoft-Windows-Hyper-V-KMCL
)

$SHA_HypVmmsProviders = @(
	'{6066F867-7CA1-4418-85FD-36E3F9C0600C}' # Microsoft-Windows-Hyper-V-VMMS
)

$SHA_HypVmWpProviders = @(
	'{51ddfa29-d5c8-4803-be4b-2ecb715570fe}' # Microsoft-Windows-Hyper-V-Worker
	'{06C601B3-6957-4F8C-A15F-74875B24429D}' # VmwpTelemetryProvider
	'{5E01DB5E-1944-5314-C040-C90B965EA3D3}' # WorkerMemManagerProvider
)

$SHA_VmConfigProviders = @(
	'{02f3a5e3-e742-4720-85a5-f64c4184e511}' # Microsoft-Windows-Hyper-V-Config
)

$SHA_VMMProviders = @(
	'{43526B7E-9EE3-41A7-B023-D586F355C00B}' # Microsoft-VirtualMachineManager-Debug
)

$SHA_VHDMPProviders = @(
	'{A9AB8791-8619-4FFF-9F24-E1BB60075972}' # Microsoft-Windows-Hyper-V-VHDMP(WinBlue)
	'{3C70C3B0-2FAE-41D3-B68D-8F7FCAF79ADB}' # Microsoft-Windows-Hyper-V-VHDMP
	'{e14dcdd9-d1ec-4dc3-8395-a606df8ef115}' # virtdisk
	'{9193A773-E60D-4171-8468-05C000581B71}' # Image Management Service (vhdsvc)
	'{f96abc17-6a5e-4a49-a3f4-a2a86fa03846}' # storvsp
	'{52323364-b587-4b4c-9293-ca9904a5c04f}' # storqosflt
)

$SHA_StorageProviders = @(
	'{F96ABC17-6A5E-4A49-A3F4-A2A86FA03846}' # StorVspDriverTraceGuid (SAN shotgun)
	'{8B86727C-E587-4B89-8FC5-D1F24D43F69C}' # StorPort (SAN shotgun)
	'{8E9AC05F-13FD-4507-85CD-B47ADC105FF6}' # Storage - MPIO (SAN shotgun)
	'{DEDADFF5-F99F-4600-B8C9-2D4D9B806B5B}' # Storage - MSDSM (SAN shotgun)
	'{1BABEFB4-59CB-49E5-9698-FD38AC830A91}' # iScsi (SAN shotgun)
	'{945186BF-3DD6-4F3F-9C8E-9EDD3FC9D558}' # Storage - Disk Class Driver Tracing Provider (SAN shotgun)
	'{FA8DE7C4-ACDE-4443-9994-C4E2359A9EDB}' # Storage - ClassPnP Driver Tracing Provider (SAN shotgun)
	#'{13953C6E-C594-414E-8BA7-DEB4BA1878E3}' # Microsoft-Windows-iSCSITarget-Service (SAN shotgun) # excluded on purpose?
	'{467C1914-37F0-4C7D-B6DB-5CD7DFE7BD5E}' # Mountmgr
	'{E3BAC9F8-27BE-4823-8D7F-1CC320C05FA7}' # Microsoft-Windows-MountMgr
	'{F5204334-1420-479B-8389-54A4A6BF6EF8}' # VolMgr
	'{9f7b5df4-b902-48bc-bc94-95068c6c7d26}' # Microsoft-Windows-Volume
	'{0BEE3BC5-A50C-4EC3-A0E0-5AD11F2455A3}' # Partmgr
	'{da58fbef-c209-4bee-84ed-027c421f31bf}' # Volsnap(wpp)
	'{67FE2216-727A-40CB-94B2-C02211EDB34A}' # Microsoft-Windows-VolumeSnapshot-Driver
	'{CB017CD2-1F37-4E65-82BC-3E91F6A37559}' # Volsnap(manifest based)
	'{6E580567-C67C-4B96-934E-FC2996E103AE}' # ClusDiskLogger
	'{C9C5D896-6FA9-49CD-9BFD-BF5C232C1124}' # Microsoft.Windows.Storage.Msdsm
	'{2CC00407-E9D9-4B5E-A760-F4217C9B0170}' # Microsoft.Windows.Storage.Mpio
	'{cc7b00d3-75c9-42cc-ae56-bf6d66a9d15d}' # Microsoft-Windows-MultipathIoControlDriver
	'{9282168F-2432-45F0-B91C-3AF363C149DD}' # StorageWMI
	'{1B992FD1-0CDD-4D6A-B55E-08C61E78D2C2}' # Microsoft.Windows.Storage.MiSpace
)

$SHA_StorageSenseProviders = @(
	'{3A245D5A-F00F-48F6-A94B-C51CDD290F18}' # 
	'{830A1F34-7797-4E31-9B75-C82056330051}' # 
	'{AEA3A1A8-EA43-4802-B750-2DD678910779}' # StorageServiceProvider
	'{B7AFA6AF-AAAB-4F50-B7DC-B61D4DDBE34F}' # Microsoft.Windows.Analog.Shell.SystemSettings.SettingsAppActivity
	'{057597DF-6FD8-438B-BF6D-190CBF0A914C}' # 
)
	
$SHA_ISCSIProviders = @(
	'{1babefb4-59cb-49e5-9698-fd38ac830a91}' # iScsi
)

$SHA_NFSProviders = @(
	'{3c33d8b3-66fa-4427-a31b-f7dfa429d78f}' # NfsSvrNfsGuid
	'{fc33d8b3-66fa-4427-a31b-f7dfa429d78f}' # NfsSvrNfsGuid2
	'{57294EFD-C387-4e08-9144-2028E8A5CB1A}' # NfsSvrNlmGuid
	'{CC9A5284-CC3E-4567-B3F6-3EB24E7CFEC5}' # MsNfsFltGuid
	'{f3bb9731-1d9f-4b8e-a42e-203bf1a32300}' # Nfs4SvrGuid
	'{53c16bac-175c-440b-a266-1e5d5f38313b}' # OncRpcXdrGuid
	'{94B45058-6F59-4696-B6BC-B23B7768343D}' # rpcxdr
	'{e18a05dc-cce3-4093-b5ad-211e4c798a0d}' # PortMapGuid
	'{355c2284-61cb-47bb-8407-4be72b5577b0}' # NfsRdrGuid
	'{6361f674-c2c0-4f6b-ae19-8c62f47ae3fb}' # NfsClientGuid
	'{c4c52165-ad74-4b70-b62f-a8d35a135e7a}' # NfsClientGuid
	'{746A1133-BC1E-47c7-8C95-3D52C39114F9}' # Microsoft-Windows-ServicesForNFS-Client
	'{6E1CBBE9-8C4B-4003-90E2-0C2D599A3EDC}' # Microsoft-Windows-ServicesForNFS-Portmapper
	'{F450221A-07E5-403A-A396-73923DFB2CAD}' # Microsoft-Windows-ServicesForNFS-NFSServerService
	'{3D888EE4-5A93-4633-91E7-FFF8AFD89A7B}' # Microsoft-Windows-ServicesForNFS-ONCRPC
	'{A0CC474A-06CA-427C-BDFF-84733163E262}' # Microsoft-Windows-ServicesForNFS-Cluster
)

$SHA_StorageSpaceProviders = @(
	'{595f7f52-c90a-4026-a125-8eb5e083f15e}' # Microsoft-Windows-StorageSpaces-Driver
	'{aa4c798d-d91b-4b07-a013-787f5803d6fc}' # Microsoft-Windows-StorageSpaces-ManagementAgent
	'{69c8ca7e-1adf-472b-ba4c-a0485986b9f6}' # Microsoft-Windows-StorageSpaces-SpaceManager
	'{A9C7961E-96A0-4E3F-9066-7734A13101C1}' # Microsoft.Windows.Storage.SpaceControl
	'{0254f21f-4809-477e-ad36-c812a8c631a1}' # Microsoft.Windows.Storage.Spaceman
	'{e7d0ad21-b086-406d-be46-a701a86a5f0a}' # Microsoft.Windows.Storage.Spaceport
	'{929c083b-4c64-410a-bfd4-8ca1b6fce362}' # Spaceport
)

$SHA_StorageReplicaProviders = @(
	'{35a2925c-30a3-43eb-b737-03e9659955e2}' # Microsoft-Windows-StorageReplica-Cluster
	'{f661b376-6e59-4483-89f8-d5aca1816ead}' # Microsoft-Windows-StorageReplica
	'{ce171fd7-a5ba-4d95-926b-6dc4d89e8171}' # Microsoft-Windows-StorageReplica-Service
	'{fadca505-ad5e-47a8-9047-b3888ba4a8fc}' # WvrCimGuid
	'{634af965-fe67-49cf-8268-af99f62d1a3e}' # WvrFltGuid
	'{8e37fc9c-8656-46da-b40d-34d97a532d09}' # WvrFltGuid
	'{0e0d5a31-e93f-40d6-83bb-e7663a4f54e3}' # Microsoft.Windows.Server.StorageReplicaCritical
)

$SHA_StorportProviders = @(
	'{8B86727C-E587-4B89-8FC5-D1F24D43F69C}' # storport
	'{4EEB8774-6C4C-492F-8F2F-5EE4721B7BF7}' # Microsoft.Windows.Storage.Storport
	'{C4636A1E-7986-4646-BF10-7BC3B4A76E8E}' # Microsoft-Windows-StorPort
)

$SHA_StorsvcProviders = @(
	'{AEA3A1A8-EA43-4802-B750-2DD678910779}' # StorageServiceProvider
	'{A963A23C-0058-521D-71EC-A1CCE6173F21}' # Microsoft-Windows-Storsvc	
)

$SHA_USBProviders = @(
	'{C88A4EF5-D048-4013-9408-E04B7DB2814A}' # Microsoft-Windows-USB-USBPORT
	'{7426a56b-e2d5-4b30-bdef-b31815c1a74a}' # Microsoft-Windows-USB-USBHUB
	'{D75AEDBE-CFCD-42B9-94AB-F47B224245DD}' # usbport
	'{B10D03B8-E1F6-47F5-AFC2-0FA0779B8188}' # usbhub
	'{30e1d284-5d88-459c-83fd-6345b39b19ec}' # Microsoft-Windows-USB-USBXHCI
	'{36da592d-e43a-4e28-af6f-4bc57c5a11e8}' # Microsoft-Windows-USB-UCX
	'{AC52AD17-CC01-4F85-8DF5-4DCE4333C99B}' # Microsoft-Windows-USB-USBHUB3
	'{6E6CC2C5-8110-490E-9905-9F2ED700E455}' # USBHUB3
	'{6fb6e467-9ed4-4b73-8c22-70b97e22c7d9}' # UCX
	'{9F7711DD-29AD-C1EE-1B1B-B52A0118A54C}' # USBXHCI
	'{04b3644b-27ca-4cac-9243-29bed5c91cf9}' # UsbNotificationTask
	'{468D9E9D-07F5-4537-B650-98389559206E}' # UFX01000
	'{8650230d-68b0-476e-93ed-634490dce145}' # SynopsysWPPGuid
	'{B83729F3-8D84-4BEA-897B-CD9FD667BA01}' # UsbFnChipidea
	'{0CBB6922-F6B6-4ACA-8BF0-81624B491364}' # UsbdTraceGuid
	'{bc6c9364-fc67-42c5-acf7-abed3b12ecc6}' # USBCCGP
	'{3BBABCCA-A210-4570-B501-0E34D88A88FB}' # SDFUSBXHCI
	'{f3006b12-1d83-48d2-948d-6bcd002c14dc}' # UDEHID
	# There are too many GUIDs for USB. So need review on which GUIDs is helpful.
)

$SHA_COMProviders = @(
    '{B46FA1AD-B22D-4362-B072-9F5BA07B046D}' # COMSVCS
    '{BDA92AE8-9F11-4D49-BA1D-A4C2ABCA692E}' # OLE32
    '{9474A749-A98D-4F52-9F45-5B20247E4F01}' # DCOMSCM
    '{9474A749-A98D-4F52-9F45-5B20247E4F01}' # DCOMSCM
    '{A0C4702B-51F7-4EA9-9C74-E39952C694B8}' # COMADMIN
)

$SHA_FltmgrProviders = @(
    '{4F5D14A2-97BB-454B-B848-6F3CE0DF80F1}' # FltMgr
    '{FD66A680-C052-4375-8CC9-225F923CEF88}' # FltMgrTelemetryProvider
    '{F3C5E28E-63F6-49C7-A204-E48A1BC4B09D}' # Microsoft-Windows-FilterManager
)

$SHA_NTFSProviders = @(
    '{B2FC00C4-2941-4D11-983B-B16E8AA4E25D}' # NtfsLog
    '{DD70BC80-EF44-421B-8AC3-CD31DA613A4E}' # Ntfs
    '{E9B319E4-0030-40A7-91CB-04D6A8EF7E09}' # Microsoft-Windows-Ntfs-SQM
    '{8E6A5303-A4CE-498F-AFDB-E03A8A82B077}' # Microsoft-Windows-Ntfs-UBPM
)

$SHA_PNPProviders = @(
    '{F52E9EE1-03D4-4DB3-B2D4-1CDD01C65582}' # PnpInstal
    '{9C205A39-1250-487D-ABD7-E831C6290539}' # Microsoft-Windows-Kernel-PnP
    '{A676B545-4CFB-4306-A067-502D9A0F2220}' # PlugPlay
    '{84051B98-F508-4E54-82FA-8865C697C3B1}' # Microsoft-Windows-PnPMgrTriggerProvider
    '{96F4A050-7E31-453C-88BE-9634F4E02139}' # Microsoft-Windows-UserPnp
    '{D5EBB80C-4407-45E4-A87A-015F6AF60B41}' # Microsoft-Windows-Kernel-PnPConfig
)

$SHA_RPCProviders = @(
    '{272A979B-34B5-48EC-94F5-7225A59C85A0}' # Microsoft-Windows-RPC-Proxy-LBS
    '{879B2576-39D1-4C0F-80A4-CC086E02548C}' # Microsoft-Windows-RPC-Proxy
    '{536CAA1F-798D-4CDB-A987-05F79A9F457E}' # Microsoft-Windows-RPC-LBS
    '{6AD52B32-D609-4BE9-AE07-CE8DAE937E39}' # Microsoft-Windows-RPC 
    '{F4AED7C7-A898-4627-B053-44A7CAA12FCD}' # Microsoft-Windows-RPC-Events
    '{D8975F88-7DDB-4ED0-91BF-3ADF48C48E0C}' # Microsoft-Windows-RPCSS
)

#endregion --- ETW component trace Providers


#region --- Scenario definitions ---  
$SHA_ScenarioTraceList = [Ordered]@{
	"SHA_HypHost"   = "PSR, SDP:HyperV, LBFO,NDIS,VmSwitch,SMBcli,SMBsrv,VMM,HyperV-Host,VMbus,Vmms,VmWp,VmConfig, ETL log(s), VMM-debug, PerfMon:SMB, trace scenario=NetConnection"
	"SHA_HypVM"     = "PSR, SDP:Net, NET_NDIS,HypVM,HyperV-VirtualMachine ETL log(s), trace scenario=InternetClient_dbg"
	"SHA_MScluster" = "PSR, SDP:Cluster, MsCluster,CSVFS,StorPort,AfdTcp,LBFo,iSCSI,-MPIO,-msDSM,-StorageReplica,-StorageSpace,-Storport,-Storage ETL log(s), Perfmon:ALL, trace scenario=NetConnection"
}


$SHA_HypHost_ETWTracingSwitchesStatus = [Ordered]@{
	'SHA_HypVmBus' = $true
	'SHA_HypVmms' = $true
	'SHA_HypVmWp' = $true
	'SHA_VMM' = $true
	'SHA_VmConfig' = $true
	'NET_LBFo' = $true
	'NET_NDIS' = $true
	'NET_VmSwitch' = $true
	'NET_SMBcli' = $true
	'NET_SMBsrv' = $true
	'CommonTask SHA' = $True 
	'NetshScenario NetConnection capturetype=both' = $true
	'PerfMon SMB' = $true
	'PSR' = $true
	'SDP HyperV' = $True
	'xray' = $True
	'CollectComponentLog' = $True
 }
 
 $SHA_HypVM_ETWTracingSwitchesStatus = [Ordered]@{
	'NET_HypVM' = $true
	'NET_NDIS' = $true
	'CommonTask SHA' = $True 
	'NetshScenario InternetClient_dbg' = $true
	'PSR' = $true
	'SDP NET' = $True
	'xray' = $True
	'CollectComponentLog' = $True
 }
 
#Cluster_GetLogs?
$SHA_MScluster_ETWTracingSwitchesStatus = [Ordered]@{
	'SHA_MsCluster' = $true
	'SHA_iSCSI' = $true
	'SHA_MPIO' = $true
	'SHA_msDSM' = $true
	'SHA_StorageReplica' = $true
	'SHA_StorageSpace' = $true
	'SHA_CSVFS' = $true
	'SHA_StorPort' = $true
	'SHA_Storage' = $true
	'NET_LBFo' = $true
	'CommonTask SHA' = $True 
	'NetshScenario NetConnection' = $true
	'PerfMon ALL' = $true
	#'Procmon' = $true
	'PSR' = $true
	#'Video' = $true
	'SDP Cluster' = $True
	'xray' = $True
	'CollectComponentLog' = $True
 }
#endregion --- Scenario definitions ---

#region performance counters
$SHA_SupportedPerfCounter = @{
	'SHA_HyperV' = 'General counters + counter for Hyper-V'
}

$SHA_HyperVCounters = @(
	$global:HyperVCounters
	# Others => Comment out when you want to add
	#'\Hyper-V Dynamic Memory Integration Service(*)\*'
	#'\Hyper-V Hypervisor(*)\*'
	#'\Hyper-V Replica VM(*)\*'
	#'\Hyper-V Virtual Machine Bus(*)\*'
	#'\Hyper-V Virtual Machine Health Summary(*)\*'
	#'\Hyper-V VM Remoting(*)\*'
	#'\Hyper-V VM Save, Snapshot, and Restore(*)\*'
)
#endregion performance counters

<#
Switch (FwGetProductTypeFromReg)
{
	"WinNT" {
		$SHA_MyScenarioTest_ETWTracingSwitchesStatus = [Ordered]@{
			'SHA_TEST1' = $true
			'SHA_TEST2' = $true
			'SHA_TEST3' = $true   # Multi files
			'UEX_Task' = $True   # Outside of this module
		}
	}
	"ServerNT" {
		$SHA_MyScenarioTest_ETWTracingSwitchesStatus = [Ordered]@{
			'SHA_TEST1' = $true
			'SHA_TEST2' = $true
		}
	}
	"LanmanNT" {
		$SHA_MyScenarioTest_ETWTracingSwitchesStatus = [Ordered]@{
			'SHA_TEST1' = $true
			'SHA_TEST2' = $true
		}
	}
	Default {
		$SHA_MyScenarioTest_ETWTracingSwitchesStatus = [Ordered]@{
			'SHA_TEST1' = $true
			'SHA_TEST2' = $true
		}
	}
}
#>


#region ### Pre-Start / Post-Stop / Collect functions for trace components and scenarios 
function SHA_start_common_tasks {
	#collect info for all tss runs at _Start_
	EnterFunc $MyInvocation.MyCommand.Name
	LogDebug "___switch Mini: $global:Mini" "cyan"
	if ($global:Mini -ne $true) {
		FwGetSysInfo _Start_
		FwGetSVC _Start_
		FwGetSVCactive _Start_ 
		FwGetTaskList _Start_
		FwGetSrvWkstaInfo _Start_
		FwGetNltestDomInfo _Start_
		FwGetDFScache _Start_
		FwGetKlist _Start_ 
		FwGetBuildInfo
		if ($global:noClearCache -ne $true) { FwClearCaches _Start_ } else { LogInfo "[$($MyInvocation.MyCommand.Name) skip FwClearCaches" }
		FwGetRegList _Start_
		FwGetPoolmon _Start_
		FwGetSrvRole
	}
	FwGetLogmanInfo _Start_
	LogInfoFile "___ SHA_start_common_tasks DONE"
	EndFunc $MyInvocation.MyCommand.Name
}
function SHA_stop_common_tasks {
	#collect info for all tss runs at _Stop_
	EnterFunc $MyInvocation.MyCommand.Name
	if ($global:Mini -ne $true) {
		FwGetDFScache _Stop_
		FwGetSVC _Stop_
		FwGetSVCactive _Stop_ 
		FwGetTaskList _Stop_
		FwGetKlist _Stop_
		FwGetDSregCmd
		FwGetPowerCfg
		FwGetHotfix
		FwGetPoolmon _Stop_
		FwGetLogmanInfo _Stop_
		FwGetNltestDomInfo _Stop_
		FwGetRegList _Stop_
		("System", "Application") | ForEach-Object { FwAddEvtLog $_ _Stop_}
		FwGetEvtLogList _Stop_
	}
	FwGetSrvWkstaInfo _Stop_
	FwGetRegHives _Stop_
	LogInfoFile "___ SHA_stop_common_tasks DONE"
	EndFunc $MyInvocation.MyCommand.Name
}

function SHA_HypHostPreStart {
	EnterFunc $MyInvocation.MyCommand.Name
	FwGetNetAdapter _Start_
	FwFwGetVMNetAdapter _Start_
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectSHA_HypHostLog {
	EnterFunc $MyInvocation.MyCommand.Name
	($EvtLogsShaHypHost, $global:EvtLogsSMBcli ) | ForEach-Object { FwAddEvtLog $_ _Stop_}
	if ($OSver3 -gt 9600) { $global:EvtLogsSMBcliOpt | ForEach-Object { FwAddEvtLog $_ _Stop_} }
	FwAddRegItem @("HyperV") _Stop_
	FwGetNetAdapter _Stop_
	FwGetVMNetAdapter _Stop_
	LogInfo "[$($MyInvocation.MyCommand.Name)] exporting the Hyper-V configuration"
	Invoke-Command -ScriptBlock { Get-VMHost | Export-Clixml -LiteralPath $global:LogFolder\$($LogPrefix)HyperV_Config.xml }
	EndFunc $MyInvocation.MyCommand.Name
}

function SHA_HypVMPreStart {
	EnterFunc $MyInvocation.MyCommand.Name
	FwSetEventLog "Microsoft-Windows-Hyper-V-NETVSC/Diagnostic"
	LogInfo "[$($MyInvocation.MyCommand.Name)] *** [Hint] Consider running FRUTI.exe for Hyper-V replication issues."
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectSHA_HypVMLog {
	EnterFunc $MyInvocation.MyCommand.Name
	FwResetEventLog @("Microsoft-Windows-Hyper-V-NETVSC/Diagnostic")
	("Microsoft-Windows-Hyper-V-NETVSC/Diagnostic") | ForEach-Object { FwAddEvtLog $_ _Stop_}
	EndFunc $MyInvocation.MyCommand.Name
}

Function Register_SDDC{

	EnterFunc $MyInvocation.MyCommand.Name

	$ispresent = get-command Get-PCStorageDiagnosticInfo -ErrorAction SilentlyContinue

	if ($null -eq $ispresent) {

			$module = 'PrivateCloud.DiagnosticInfo'; $branch = 'master'
			#Remove old version
			if (Test-Path $env:SystemRoot\System32\WindowsPowerShell\v1.0\Modules\$module) {
				Remove-Item -Recurse $env:SystemRoot\System32\WindowsPowerShell\v1.0\Modules\$module -ErrorAction Stop
				Remove-Module $module -ErrorAction SilentlyContinue
			}

			$md = "$env:ProgramFiles\WindowsPowerShell\Modules"
		   	Copy-Item -Recurse $global:ScriptFolder\psSDP\Diag\global\PrivateCloud.DiagnosticInfo $md -Force -ErrorAction Stop

			$ispresent = get-command Get-PCStorageDiagnosticInfo -ErrorAction SilentlyContinue

	} 

	EndFunc $MyInvocation.MyCommand.Name
}

### Data Collection
Function CollectSHA_SDDCLog{
	# invokes external script for PrivateCloud.DiagnosticInfo
	EnterFunc $MyInvocation.MyCommand.Name
	Register_SDDC
	LogInfo "[$($MyInvocation.MyCommand.Name)] . calling GetSddcDiagnosticInfo.ps1"
	if (Test-Path -path "$global:ScriptFolder\psSDP\Diag\global\GetSddcDiagnosticInfo.ps1") {
		LogInfoFile "--- $(Get-Date -Format 'HH:mm:ss') ..starting .\psSDP\Diag\global\GetSddcDiagnosticInfo.ps1 -WriteToPath $global:LogFolder\HealthTest -ZipPrefix $global:LogFolder\_Sddc-Diag"
		& Get-PCStorageDiagnosticInfo -WriteToPath $global:LogFolder\HealthTest -ZipPrefix $global:LogFolder\_Sddc-Diag
		#& "$global:ScriptFolder\psSDP\Diag\global\GetSddcDiagnosticInfo.ps1" -WriteToPath $global:LogFolder\HealthTest -ZipPrefix $global:LogFolder\_Sddc-Diag
		LogInfoFile "--- $(Get-Date -Format 'HH:mm:ss') ...Finished SDDC Diagnostics Data (PrivateCloud.DiagnosticInfo)"
		LogInfo "[$($MyInvocation.MyCommand.Name)] . Done GetSddcDiagnosticInfo.ps1"
	} else { LogWarn "Script GetSddcDiagnosticInfo.ps1 not found!" cyan} 

    # SpaceDB ChkSpace
	if ((!$global:IsLiteMode) -and (Test-Path  $global:SpaceDBPath)){ 
		LogInfo "[$($MyInvocation.MyCommand.Name)] . calling spacedb Chkspace"
		$outFile = $PrefixTime + "SPACEDB_Chkspace" +".txt"

		$Commands = @(
						"$global:SpaceDBPath Chkspace| Out-File -Append $outfile")

		RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
		LogInfo "[$($MyInvocation.MyCommand.Name)] running SpaceDB Chkspace"
	}
	else {
		LogInfo "[$($MyInvocation.MyCommand.Name)] skipped SpaceDB Chkspace"
	}
    


	EndFunc $MyInvocation.MyCommand.Name
}

Function SHA_MsClusterScenarioPreStart{
	EnterFunc $MyInvocation.MyCommand.Name
	#_# if "%_LiveDmp_analytic%" equ "1" call :Start_LiveDump_Analytic_logs
	EndFunc $MyInvocation.MyCommand.Name
}
Function CollectSHA_MsClusterScenarioLog{
	EnterFunc $MyInvocation.MyCommand.Name
	#_# if "%_LiveDmp_analytic%" equ "1" call :Stop_LiveDump_Analytic_logs
	GetClusterRegHives _Stop_
	EndFunc $MyInvocation.MyCommand.Name
}

function CollectSHA_ShieldedVMLog {
	EnterFunc $MyInvocation.MyCommand.Name
	$Commands = @(
		"Get-HgsTrace -RunDiagnostics -Detailed -Path $global:LogFolder\ShieldedVM"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	($EvtLogsShieldedVm) | ForEach-Object { FwAddEvtLog $_ _Stop_}
	EndFunc $MyInvocation.MyCommand.Name
}

Function CollectSHA_SmsLog{
	# invokes external script GetSmsLogs.psm1 until fully integrated into TSSv2
	EnterFunc $MyInvocation.MyCommand.Name
	Try{
		$Global:fServerSKU = (Get-CimInstance -Class CIM_OperatingSystem -ErrorAction Stop).Caption -like "*Server*"
	}Catch{
		LogException "An exception happened in Get-CimInstance for CIM_OperatingSystem" $_ $fLogFileOnly
		$Global:fServerSKU = $False
	}
	if ($Global:fServerSKU) {
		LogInfo "[$($MyInvocation.MyCommand.Name)] . calling GetSmsLogs.psm1"
		Import-Module .\scripts\GetSmsLogs.psm1 -DisableNameChecking
		Get-SmsLogs -Path $global:LogFolder #-AcceptEula
		LogInfo "[$($MyInvocation.MyCommand.Name)] . Done GetSmsLogs.psm1"
	} else { LogWarn " Computer $env:Computername is not running Server SKU"}
	EndFunc $MyInvocation.MyCommand.Name
}

Function SHA_VMLPreStart{
	EnterFunc $MyInvocation.MyCommand.Name
	if ($global:Mode -iMatch "Verbose") {
		LogInfo ".. will restart the Hyper-V service now with script tss_VMLVerbosity.ps1 -set 'Verbose'"
		.\scripts\tss_VMLverbosity.ps1 -set "Verbose"
	}
	if (!$global:IsLiteMode){
		LogInfo ".. starting $VmlTrace_exe $global:VmltraceCmd in circular mode"	# _VmltraceCmd is defined in tss_config.cfg
		$Commands = @(
			"$VmlTrace_exe $global:VmltraceCmd /l $PrefixTime`Vmltrace.etl /n ms_VmlTraceSession 2>&1 | Out-File -Append $global:ErrorLogFile"
		)
		RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
		if ($OSVER3 -ge 14393) {
			$outFile = $PrefixTime + "FRuti.txt"
			#LogInfo ".. starting $frutiExe /t /LN 1001 /f /v /lp $outFile"
			# START !_FrutiExe! /t /LN 1001 /f /v /lp !_PrefixT!FRuti.txt
			$ArgumentList = " /t /LN 1001 /f /v /lp `"$outFile`""
			LogInfo ".. starting $frutiExe $ArgumentList"
			$global:FrutiExeProc = Start-Process -FilePath $FrutiExe -ArgumentList $ArgumentList -PassThru
				
			#$Commands = @(	"$frutiExe /t /LN 1001 /f /v /lp $outFile | Out-File -Append $global:ErrorLogFile")
			#RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
		}
	}else{ LogInfo "Skipping Start of $VmlTrace_exe and $FrutiExe in Lite mode"}
	LogInfo " .. will start dummy SHA_VMLtrace.etl"
	EndFunc $MyInvocation.MyCommand.Name
}
Function CollectSHA_VMLLog{
	EnterFunc $MyInvocation.MyCommand.Name

	if (!$global:IsLiteMode){
		LogInfo ".. stoppping and converting VmlTrace.etl"
		$Commands = @(
			"$VmlTrace_exe /s /n ms_VmlTraceSession 2>&1 | Out-File -Append $global:ErrorLogFile"
		)
		RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
		if ($OSVER3 -ge 14393) {
			$ArgumentList = " /s 2>&1"
			LogInfo ".. stopping $frutiExe $ArgumentList"
			$global:FrutiExeProc = Start-Process -FilePath $FrutiExe -ArgumentList $ArgumentList -Wait -PassThru
			#$Commands = @(	"$frutiExe /s 2>&1 | Out-File -Append $global:ErrorLogFile"	)
			#RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
			if(Test-path "$PrefixTime`Vmltrace.etl") {
				$Commands = @("netsh trace convert $PrefixTime`Vmltrace.etl 2>&1 | Out-File -Append $global:ErrorLogFile")
				RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
			}
		}
	}else{ LogInfo "Skipping Stop of $VmlTrace_exe and $FrutiExe in Lite mode"}
	if ($global:Mode -iMatch "Verbose") {
		LogInfo ".. will restart the Hyper-V service now with script tss_VMLVerbosity.ps1 -set 'Standard'"
		.\scripts\tss_VMLverbosity.ps1 -set "Standard"
	}
	EndFunc $MyInvocation.MyCommand.Name
}
	
#endregion ### Pre-Start / Post-Stop / Collect functions for trace components and scenarios 

#region --- HelperFunctions ---
function GetClusterRegHives {
	param(
		[Parameter(Mandatory=$False)]
		[String]$global:TssPhase				# _Start_ or _Stop_
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $global:TssPhase")
	if (-not (Test-Path "$PrefixCn`RegHive_Cluster.hiv")) {
		LogInfoFile "... collecting Cluster Registry Hives"
		$Commands = @(
			"REG SAVE HKLM\cluster $PrefixCn`RegHive_Cluster.hiv /Y"
		)
		RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	}
	EndFunc $MyInvocation.MyCommand.Name
}

#endregion --- HelperFunctions ---


#region Registry Key modules for FwAddRegItem
	$global:KeysHyperV = @("HKLM:Software\Microsoft\Windows NT\CurrentVersion\Virtualization", "HKLM:System\CurrentControlSet\Services\vmsmp\Parameters")
#endregion Registry Key modules

#region groups of Eventlogs for FwAddEvtLog
	$EvtLogsShaHypHost		= @("Microsoft-Windows-Hyper-V-VMMS-Admin", "Microsoft-Windows-Hyper-V-VMMS-operational", "Microsoft-Windows-Hyper-V-Worker-Admin", "Microsoft-Windows-Hyper-V-VMMS-Networking", "Microsoft-Windows-Hyper-V-EmulatedNic-Admin", "Microsoft-Windows-Hyper-V-Hypervisor-Admin", "Microsoft-Windows-Hyper-V-Hypervisor-Operational", "Microsoft-Windows-Hyper-V-SynthNic-Admin", "Microsoft-Windows-Hyper-V-VmSwitch-Operational", "Microsoft-Windows-MsLbfoProvider/Operational")
	$EvtLogsShieldedVm	= @("Microsoft-Windows-HostGuardianService-Client/Operational", "Microsoft-Windows-HostGuardianService-Client/Admin", "Microsoft-Windows-HostGuardianService-CA/Operational", "Microsoft-Windows-HostGuardianService-CA/Admin", "Microsoft-Windows-HostGuardianService-KeyProtection/Admin", "Microsoft-Windows-HostGuardianService-KeyProtection/Operational", "Microsoft-Windows-HostGuardianService-Attestation/Admin", "Microsoft-Windows-HostGuardianService-Attestation/Operational", "Microsoft-Windows-HostGuardianClient-Service/Operational", "Microsoft-Windows-HostGuardianClient-Service/Admin")
#endregion groups of Eventlogs

Export-ModuleMember -Function * -Cmdlet * -Variable * -Alias *



# SIG # Begin signature block
# MIInzQYJKoZIhvcNAQcCoIInvjCCJ7oCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBjd5La+wJWT5hm
# /zwuDRXLTFIWbztAUL2xmsnj4HgH2aCCDYEwggX/MIID56ADAgECAhMzAAACzI61
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
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgUM/WAKCl
# KNxqP707e9Nnqq0GNJklZNEv/y1xvk7Km3IwQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQCInD8l5MUU64dAHrQTcRSHC7sKmTj4aPr8JHgSoS0Y
# PF/YIvHp6dlbH+htGlvnXbF8oUohlWNOY5UjprFHUJ9jMdUcj1L6uXOvOzRu0OeW
# //mHUfpimEQUEZjuRYJ0x2nEUkoCDAeLT3KE7QUnAyX2qNvUZAnqpzP/JpTmv07B
# qCG6EVM5QZruekhFOj2af06kTWD/5RFhluqCacMcRFwqugzqEPQBQ7DikE0zhoGd
# DeTGSPLn5OnUh1d8A0FP/C0Tuf9iAwgrThJKZqB8vNQZcs64v4TarsMNp50IfAPM
# VTfEjL92BvG2OF2nkOked+fGwL3NxrV3PAgk2uYImVt+oYIXLDCCFygGCisGAQQB
# gjcDAwExghcYMIIXFAYJKoZIhvcNAQcCoIIXBTCCFwECAQMxDzANBglghkgBZQME
# AgEFADCCAVkGCyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEIAPhH4BYn4p8FcKBNevY9nWT2Ydm0KgPV5J5IK5z
# qGkLAgZjT/SUQrIYEzIwMjIxMDI2MTQyOTU0LjIwMVowBIACAfSggdikgdUwgdIx
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
# MC8GCSqGSIb3DQEJBDEiBCCVl8++tqhxoH0vE5m5DTFSkYp+RS9Lvo1AhuF37Nnh
# DzCB+gYLKoZIhvcNAQkQAi8xgeowgecwgeQwgb0EINPI93vmozBwBlFxvfr/rElr
# eFPR4ux7vXKx2ni3AfcGMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENB
# IDIwMTACEzMAAAG0+4AIRAXSLfoAAQAAAbQwIgQgilPxWnURWR8jdCkhhDzQ2lRS
# AkvqHPCEg+sB3XSsAa0wDQYJKoZIhvcNAQELBQAEggIAii3v45F6dgINdfg07T+J
# yCW1AJL5G49sK9bFNbgQU1sdgqZAWATC+L59sJl8BAtHvRrM0GSEHvmbZ9SBXksB
# ru4vmGkrW6JTvdM8IpG5d9+d6OP4mGVDlZck/9wJvISWybgw61PWN+6bFi+0TM5l
# Vcf3CJYg0KsfIDZwhtyN+ydbVphYgUnpZhK75BePIi3Sdh6FFJESTgGeQP9KCGBq
# 5rCkCw6PbVS8nSWWfRBrUL4mUMeXvjRlUKzxH0/iyYCAO5E904/KVNLIGlsOq1hq
# e1iTZ94ZNJHxnkwEjHYn/+4xguyhZlW1gcSRNCYttPf7rkRzMYI/5wpIeYwAGl+H
# pOtzCQ1sR8lLqO1CQLUIxpjDuM+Vh1ZBd9HPFz0MNuN1GEWwJfmGIBsVStAZgJOA
# NlNLaDhFWJl0c/TB+3ImN7cQEZ2PHk1QE0M4J6kC/wZFENBvtDl6f3A0FfKifmDX
# NJpIo4836KqscEuoT6IFR/lQZw2jyoTchut+Y+/p9z/6wFYAtrE12vKFyEEDs4Es
# vnKgkiZIPJtOWbbQzYxt8PBdRyto/2jf9R34HzfxezI8AjiopFY2WdVdJ0Npn/fi
# 4KaxSeic7hHRz4FLyqAXlkONtKnGV4guEFMMBd3lh8o8jbvic4gKzWCIxruqLiR8
# J/YmSnuXiGnMYKlbc5Cn12s=
# SIG # End signature block
