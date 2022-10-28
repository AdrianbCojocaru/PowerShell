<#
.SYNOPSIS
	ADS Scenarios module for collecting ETW traces and various custom tracing functionality

.DESCRIPTION
	Define ETW traces for Windows ADS components 
	Add any custom tracing functinaliy for tracing ADS components
	Use Enter-ADSModule as entry function from the calling Powershell script/module.
	Run 'Get-Help TSSv2_ADS.psm1 -full' for more detail.


.NOTES  
	Authors		: Milan Milosavljevic (milanmil@microsoft.com)
	Requires	: PowerShell V4(Supported from Windows 8.1/Windows Server 2012 R2)
	Version		: see $global:TssVerDateADS

.LINK
	TSSv2 https://internal.support.services.microsoft.com/en-us/help/4619187
	ADS https://internal.support.services.microsoft.com/en-us/help/4619196
#>

<# latest changes
::   2022.10.26.0 [we] _ADS: add 'Directory Service' EvtLog to ADS_LDAPsrv
::   2022.09.27.0 [we] _ADS: fix ADS_GroupPolicy
::   2022.08.28.0 [we] _ADS: add ADS_OCSP,ADS_SBSL
::   2022.08.24.0 [we] _ADS: ESR Remove "Microsoft-Windows-SettingSync*" & Add new CDS ETW provider 
::   2022.07.27.0 [we] _ADS: add to ADS_W32Time: w32tm.exe /query /peers /verbose
::   2022.07.27.0 [we] _ADS: updated tss_ADPerfDataCollection.ps1
::   2022.07.26.0 [we] _ADS: fixed ProcMon path in tss_ADPerfDataCollection, Warning on 'procdump lsass'
::   2022.07.18.0 [we] _ADS: add ADS_w32Time
  2022.07.12.1 [we] add ADS_Netlogon (included also in ADS_Auth) (issue #670)
  2022.07.07.0 [we] ADS_DFSr: copy only DFSR*.log and last 5 DFSR*.log.gz files (#654)
  2022.07.05.0 [we] add Security.evtx to ADS_AUTH (issue #659)
  2022.05.21.0 [we] add 'ADS_Perf' es external script tss_ADPerfDataCollection.ps1
  2022.05.18.0 [we] replaced *-key.txt with *reg_*.txt; replaced $($global:LogFolder)\$($global:LogPrefix) with $($PrefixTime); added FwListProcsAndSvcs
  2022.05.16.0 [we] replaced DSregCmd with FwGetDSregCmd
  2022.04.14.0 [we] avoid dsregcmd for OS < 10
  2022.02.21.0 [we] re-added component functions ADS_AuthPostStop and ADS_ESRPreStart, so that they could be combined with other POD scenarios
  2022.02.06.0 [we] defined ADS scenarios also as components (to allow combination with NET scenarios); removed '_' from provider names, moved some LogInfo into LogInfoFile, added LogInfo "[ADS Stage:] ..."
  2022.02.01.0 [we] changed value LspDbgInfoLevel=0x50410800, Reason: QFE 2022.1B added a new flag and without it we don’t see this final status STATUS_TRUSTED_DOMAIN_FAILURE on RODC.
  2022.02.01.0 [we] removed '_' in Crypto_DPAPI and NTLM_Cred for correct handling of METL traces
  2021.12.31.1 [we] moving NET_ components to ADS: GPedit GPmgmt GPsvc GroupPolicy Profile
  2021.11.29.0 [we] moving NET_ADcore, NET_ADsam, NET_BadPwd, NET_DFSR, NET_LDAPsrv, NET_LockOut to ADS
  2021.11.10.0 [we] replaced all 'Get-WmiObject' with 'Get-CimInstance' to be compatible with PowerShell v7
#>

$global:TssVerDateADS= "2022.10.26.0"

#store data in $global:LogFolder

#region Switches
#
$ADS_DummyProviders = @(
	'{eb004a05-9b1a-11d4-9123-0050047759bc}' # Dummy tcp for switches without tracing GUID (issue #70)
)
$ADS_BadPwdProviders 	= $ADS_DummyProviders
$ADS_GPeditProviders 	= $ADS_DummyProviders
$ADS_GPmgmtProviders 	= $ADS_DummyProviders
$ADS_GPsvcProviders 	= $ADS_DummyProviders
$ADS_PerfProviders		= $ADS_DummyProviders

$ADS_ADcoreProviders = @(
	'{1C83B2FC-C04F-11D1-8AFC-00C04FC21914}' # Active Directory Domain Services: Core; see 2826734 ADPERF: Using Active Directory (AD) Event Tracing 
)

$ADS_ADsamProviders = @(
	'{9A7D7195-B713-4092-BDC5-58F4352E9563}' # SamLib								** see 4135049 ADPERF: Tools: SAM client-side activity tracing *Windows 10 RS1 and above*
	'{1FF6B227-2CA7-40F9-9A66-980EADAA602E}' # WMI_Tracing_Guid
)

$ADS_LDAPsrvProviders = @(
	'{90717974-98DB-4E28-8100-E84200E22B3F}!LDAPsrv!0x8!0xff' # NTDSA
)

$ADS_DFSrProviders = @(
	'{40D22086-BDFE-4893-B4C7-C10651ADB0CA}' # DFSrRoFltWmiGuid	
	'{926D226A-1D6E-4F02-B8D0-64E431C1324B}' # FrsFltWmiGuid
	'{CB25CD9F-703B-4F1B-A8F2-209E5484ACB0}' # DFSFrs
)

$ADS_NetlogonProviders = @(
	'{CA030134-54CD-4130-9177-DAE76A3C5791}' # NETLOGON/ NETLIB
	'{E5BA83F6-07D0-46B1-8BC7-7E669A1D31DC}' # Microsoft-Windows-Security-Netlogon
)

$ADS_ADCSProviders = @(  #remove varous file extension and the following characters (), .  ... as they are not allowed in logman command
	'{98BF1CD3-583E-4926-95EE-A61BF3F46470}!CertCli'				# Microsoft-Windows-CertificationAuthorityClient-CertCli
	'{6A71D062-9AFE-4F35-AD08-52134F85DFB9}!CertificationAuthority'	# Microsoft-Windows-CertificationAuthority
)
if ($OSVER3 -gt 14393) {
	$ADS_ADCSProviders += @(
	'{A7FB5B34-C0A5-4247-A1F6-300E40ECE26B}!CertificationAuthority-EnterprisePolicy'	# Microsoft-Windows-CertificationAuthority-EnterprisePolicy # not supported on WS2016 and below
	)
}

$ADS_PKIClientProviders = @(
	'{82B5AD62-B453-481A-B838-CA1EEAE6E472}'
	'{7A688F0E-F39B-4A7A-BBBB-066E2C1FCB04}'
	'Microsoft-Windows-Security-EnterpriseData-FileRevocationManager'
	'Microsoft-Windows-EFS'
	'{9D2A53B2-1411-5C1C-D88C-F2BF057645BB}'
	'{EA3F84FC-03BB-540E-B6AA-9664F81A31FB}'
	'Microsoft-Windows-Crypto-DPAPI'
	'Microsoft-Windows-CAPI2!CAPI2!0x0000ffffffffffff'
	'Microsoft-Windows-Crypto-NCrypt'
	'Microsoft-Windows-Crypto-BCrypt'
	'Microsoft-Windows-Crypto-CNG'
	'Microsoft-Windows-Crypto-DSSEnh'
	'Microsoft-Windows-Crypto-RSAEnh'
	'{A74EFE00-14BE-4EF9-9DA9-1484D5473303}'
	'{F3A71A4B-6118-4257-8CCB-39A33BA059D4}'
	'{413E55F6-5309-4E2D-A7E7-EA98BA06EE89}'
	'{EAC19293-76ED-48C3-97D3-70D75DA61438}'
	'{84C5F702-EB27-41CB-AED2-64AA9850C3D0}'
	'{1D6540CE-A81B-4E74-AD35-EEF8463F97F5}'
	'{133A980D-035D-4E2D-B250-94577AD8FCED}'
	'{A5BFFA95-ACCA-4C18-B51C-DCA0A33A039D}'
	'{FCA9C1D0-5872-4AC2-BB61-1B64511108BA}'
	'{9B52E09F-0C58-4EAF-877F-70F9B54A7946}'
	'{80DF111F-178D-44FB-AFB4-5D179DE9D4EC}'
	'{DE5DCAEE-6F88-585A-05EE-D8B05B912772}'
)

$ADS_NGCProviders = @(  
	'{B66B577F-AE49-5CCF-D2D7-8EB96BFD440C}!ngc!0x0'
	'{CAC8D861-7B16-5B6B-5FC0-85014776BDAC}!ngc!0x0'
	'{6D7051A0-9C83-5E52-CF8F-0ECAF5D5F6FD}!ngc!0x0'
	'{0ABA6892-455B-551D-7DA8-3A8F85225E1A}!ngc!0x0'
	'{9DF6A82D-5174-5EBF-842A-39947C48BF2A}!ngc!0x0'
	'{9B223F67-67A1-5B53-9126-4593FE81DF25}!ngc!0x0'
	'{89F392FF-EE7C-56A3-3F61-2D5B31A36935}!ngc!0x0'
	'{CDD94AC7-CD2F-5189-E126-2DEB1B2FACBF}!ngc!0x0'
	'{2056054C-97A6-5AE4-B181-38BC6B58007E}!ngc!0x0'
	'{1D6540CE-A81B-4E74-AD35-EEF8463F97F5}!ngc!0xffff'
	'{CDC6BEB9-6D78-5138-D232-D951916AB98F}!ngc!0x0'
	'{C0B2937D-E634-56A2-1451-7D678AA3BC53}!ngc!0x0'
	'{9D4CA978-8A14-545E-C047-A45991F0E92F}!ngc!0x0'
	'{3b9dbf69-e9f0-5389-d054-a94bc30e33f7}!ngc!0x0'
	'{34646397-1635-5d14-4d2c-2febdcccf5e9}!ngc!0x0'
	'{3A8D6942-B034-48e2-B314-F69C2B4655A3}!ngc!0xffffffff'
	'{5AA9A3A3-97D1-472B-966B-EFE700467603}!ngc!0xffffffff'
	'{D5A5B540-C580-4DEE-8BB4-185E34AA00C5}!ngc!0x0'
	'{7955d36a-450b-5e2a-a079-95876bca450a}!ngc!0x0'
	'{c3feb5bf-1a8d-53f3-aaa8-44496392bf69}!ngc!0x0'
	'{78983c7d-917f-58da-e8d4-f393decf4ec0}!ngc!0x0'
	'{36FF4C84-82A2-4B23-8BA5-A25CBDFF3410}!ngc!0x0'
	'{86D5FE65-0564-4618-B90B-E146049DEBF4}!ngc!0x0'
	'{23B8D46B-67DD-40A3-B636-D43E50552C6D}!ngc!0x0'
	'{73370BD6-85E5-430B-B60A-FEA1285808A7}!ngc!0x0'
	'{F0DB7EF8-B6F3-4005-9937-FEB77B9E1B43}!ngc!0x0'
	'{54164045-7C50-4905-963F-E5BC1EEF0CCA}!ngc!0x0'
	'{89A2278B-C662-4AFF-A06C-46AD3F220BCA}!ngc!0x0'
	'{BC0669E1-A10D-4A78-834E-1CA3C806C93B}!ngc!0x0'
	'{BEA18B89-126F-4155-9EE4-D36038B02680}!ngc!0x0'
	'{B2D1F576-2E85-4489-B504-1861C40544B3}!ngc!0x0'
	'{98BF1CD3-583E-4926-95EE-A61BF3F46470}!ngc!0x0'
	'{AF9CC194-E9A8-42BD-B0D1-834E9CFAB799}!ngc!0x0'
	'{d0034f5e-3686-5a74-dc48-5a22dd4f3d5b}!ngc!0xFFFFFFFF'
	'{99eb7b56-f3c6-558c-b9f6-09a33abb4c83}!ngc!0xFFFFFFFF'
	'{aa02d1a4-72d8-5f50-d425-7402ea09253a}!ngc!0x0'
	'{507C53AE-AF42-5938-AEDE-4A9D908640ED}!ngc!0x0'
	'{9FBF7B95-0697-4935-ADA2-887BE9DF12BC}!ngc!0x0'
	'{3DA494E4-0FE2-415C-B895-FB5265C5C83B}!ngc!0x0'
	'{EAC19293-76ED-48C3-97D3-70D75DA61438}!ngc!0xffffffff'
	'{ac01ece8-0b79-5cdb-9615-1b6a4c5fc871}!cdp!0xffffffffffffffff'
	'{6ad52b32-d609-4be9-ae07-ce8dae937e39}!cdp!0xffffffffffffffff'
	'{f4aed7c7-a898-4627-b053-44a7caa12fcd}!cdp!0xffffffffffffffff'
	'{02ad713f-20d4-414f-89d0-da5a6f3470a9}!cdp!0xffffffffffffffff'
	'{acc49822-f0b2-49ff-bff2-1092384822b6}!cdp!0xffffffffffffffff'
	'{f245121c-b6d1-5f8a-ea55-498504b7379e}!cdp!0xffffffffffffffff'
)

$ADS_BioProviders = @(
	'{34BEC984-F11F-4F1F-BB9B-3BA33C8D0132}!Bio!0xffff'
	'{225b3fed-0356-59d1-1f82-eed163299fa8}!Bio!0x0'
	'{9dadd79b-d556-53f2-67c4-129fa62b7512}!Bio!0x0'
	'{1B5106B1-7622-4740-AD81-D9C6EE74F124}!Bio!0x0'
	'{1d480c11-3870-4b19-9144-47a53cd973bd}!Bio!0x0'
	'{e60019f0-b378-42b6-a185-515914d3228c}!Bio!0x0'
	'{48CAFA6C-73AA-499C-BDD8-C0D36F84813E}!Bio!0x0'
	'{add0de40-32b0-4b58-9d5e-938b2f5c1d1f}!Bio!0x0'
	'{e92355c0-41e4-4aed-8d67-df6b2058f090}!Bio!0x0'
	'{85be49ea-38f1-4547-a604-80060202fb27}!Bio!0x0'
	'{F4183A75-20D4-479B-967D-367DBF62A058}!Bio!0x0'
	'{0279b50e-52bd-4ed6-a7fd-b683d9cdf45d}!Bio!0x0'
	'{39A5AA08-031D-4777-A32D-ED386BF03470}!Bio!0x0'
	'{22eb0808-0b6c-5cd4-5511-6a77e6e73a93}!Bio!0x0'
	'{63221D5A-4D00-4BE3-9D38-DE9AAF5D0258}!Bio!0x0'
	'{9df19cfa-e122-5343-284b-f3945ccd65b2}!Bio!0x0'
	'{beb1a719-40d1-54e5-c207-232d48ac6dea}!Bio!0x0'
	'{8A89BB02-E559-57DC-A64B-C12234B7572F}!Bio!0x0'
	'{a0e3d8ea-c34f-4419-a1db-90435b8b21d0}!Bio!0x0'
)

$ADS_LSAProviders = @(
	'{D0B639E0-E650-4D1D-8F39-1580ADE72784}!lsa!0xC43EFF'
	'{169EC169-5B77-4A3E-9DB6-441799D5CACB}!lsa!0xffffff'
	'{DAA76F6A-2D11-4399-A646-1D62B7380F15}!lsa!0xffffff'
	'{366B218A-A5AA-4096-8131-0BDAFCC90E93}!lsa!0xfffffff'
	'{4D9DFB91-4337-465A-A8B5-05A27D930D48}!lsa!0xff'
	'{7FDD167C-79E5-4403-8C84-B7C0BB9923A1}!lsa!0xFFF'
	'{CA030134-54CD-4130-9177-DAE76A3C5791}!lsa!0xfffffff'
	'{5a5e5c0d-0be0-4f99-b57e-9b368dd2c76e}!lsa!0xfffffff'
	'{2D45EC97-EF01-4D4F-B9ED-EE3F4D3C11F3}!lsa!0xfffffff'
	'{C00D6865-9D89-47F1-8ACB-7777D43AC2B9}!lsa!0xfffffff'
	'{7C9FCA9A-EBF7-43FA-A10A-9E2BD242EDE6}!lsa!0xfffffff'
	'{794FE30E-A052-4B53-8E29-C49EF3FC8CBE}!lsa!0xfffffff'
	'{ba634d53-0db8-55c4-d406-5c57a9dd0264}!lsa!0xfffffff'
)

$ADS_NtLmCredSSPProviders = @(
	'{5BBB6C18-AA45-49b1-A15F-085F7ED0AA90}!NtLmCredssp!0x5ffDf'
	'{AC69AE5B-5B21-405F-8266-4424944A43E9}!NtLmCredssp!0xffffffff'
	'{AC43300D-5FCC-4800-8E99-1BD3F85F0320}!NtLmCredssp!0xffffffff'
	'{C92CF544-91B3-4DC0-8E11-C580339A0BF8}!NtLmCredssp!0xffffffff'
	'{6165F3E2-AE38-45D4-9B23-6B4818758BD9}!NtLmCredssp!0xffffffff'
	'{DAA6CAF5-6678-43f8-A6FE-B40EE096E06E}!NtLmCredssp!0xffffffff'
)

$ADS_KerbProviders = @(
	'{6B510852-3583-4e2d-AFFE-A67F9F223438}!Kerb!0x7ffffff'
	'{60A7AB7A-BC57-43E9-B78A-A1D516577AE3}!Kerb!0xffffff'
	'{FACB33C4-4513-4C38-AD1E-57C1F6828FC0}!Kerb!0xffffffff'
	'{97A38277-13C0-4394-A0B2-2A70B465D64F}!Kerb!0xff'
	'{8a4fc74e-b158-4fc1-a266-f7670c6aa75d}!Kerb!0xff'
	'{98E6CFCB-EE0A-41E0-A57B-622D4E1B30B1}!Kerb!0xff'
)

$ADS_KDCProviders = @(
	'{1BBA8B19-7F31-43c0-9643-6E911F79A06B}!kdc!0xfffff'	# Security: KDC
)

$ADS_ProfileProviders = @(
	'{89B1E9F0-5AFF-44A6-9B44-0A07A7CE5845}' # Microsoft-Windows-User Profiles Service
	'{DB00DFB6-29F9-4A9C-9B3B-1F4F9E7D9770}' # Microsoft-Windows-User Profiles General
	'{eb7428f5-ab1f-4322-a4cc-1f1a9b2c5e98}' # Profile
	'{63A3ADBE-9717-410D-A0F5-E07E68823B4D}' # ShellPerfTraceProvider
	'{6B6C257F-5643-43E8-8E5A-C66343DBC650}' # UstCommonProvider
)
if ($OSVER3 -ge 18362) {
	$ADS_ProfileProviders += @( 
		'{9891e0a7-f966-547f-eb21-d98616bf72ee}' # Microsoft.Windows.Shell.UserProfiles
		'{9959adbd-b5ac-5758-3ffa-ee0da5b8fe4b}' # 
		'{7f1bd045-965d-4f47-b3a7-acdbcfb11ca6}' # 
		'{40654520-7460-5c90-3c10-e8b6c8b430c1}' # 
		'{d5ee9312-a511-4c0e-8b35-b6d980f6ba25}' # 
		'{04a241e7-cea7-466d-95a1-87dcf755f1b0}' # 
		'{9aed307f-a41d-40e7-9539-b8d2742578f6}' #
	)
}

$ADS_Profile8Providers = @(			# ToDo:
	'{20c46239-d059-4214-a11e-7d6769cbe020}!Profile8!255!FF' # Microsoft-Windows-Remote-FileSystem-Log, MupLog, included in fskm
)

$ADS_SAMProviders = @(
	'{8E598056-8993-11D2-819E-0000F875A064}!Sam!0xffffffffffffffff'
	'{0D4FDC09-8C27-494A-BDA0-505E4FD8ADAE}!Sam!0xffffffffffffffff'
	'{BD8FEA17-5549-4B49-AA03-1981D16396A9}!Sam!0xffffffffffffffff'
	'{F2969C49-B484-4485-B3B0-B908DA73CEBB}!Sam!0xffffffffffffffff'
	'{548854B9-DA55-403E-B2C7-C3FE8EA02C3C}!Sam!0xffffffffffffffff'
)

$ADS_SSLProviders = @(
	'{37D2C3CD-C5D4-4587-8531-4696C44244C8}!SSL!0x4000ffff'
)

$ADS_EFSProviders = @(
	'{82B5AD62-B453-481A-B838-CA1EEAE6E472}!EFS!0xffffffffffffffff'
	'{7A688F0E-F39B-4A7A-BBBB-066E2C1FCB04}!EFS!0xffffffffffffffff'
	'{2CD58181-0BB6-463E-828A-056FF837F966}!EFS!0xffffffffffffffff'
	'{3663A992-84BE-40EA-BBA9-90C7ED544222}!EFS!0xffffffffffffffff'
)

$ADS_CryptoDPAPIProviders = @(
	'{EA3F84FC-03BB-540e-B6AA-9664F81A31FB}!CryptoDPAPI!0xFFFFFFFF'
	'{A74EFE00-14BE-4ef9-9DA9-1484D5473302}!CryptoDPAPI!0xFFFFFFFF'
	'{A74EFE00-14BE-4ef9-9DA9-1484D5473301}!CryptoDPAPI!0xFFFFFFFF'
	'{A74EFE00-14BE-4ef9-9DA9-1484D5473305}!CryptoDPAPI!0xFFFFFFFF'
	'{786396CD-2FF3-53D3-D1CA-43E41D9FB73B}!CryptoDPAPI!0x0'
	'{9D2A53B2-1411-5C1C-D88C-F2BF057645BB}!CryptoDPAPI!0xffffffffffffffff' # Microsoft.Windows.Security.Dpapi
	'{89FE8F40-CDCE-464E-8217-15EF97D4C7C3}!CryptoDPAPI!0xffffffffffffffff' # Microsoft-Windows-Crypto-DPAPI
	'{DE5DCAEE-6F88-585A-05EE-D8B05B912772}!CryptoDPAPI!0xffffffffffffffff' # WinVerifyTrust
	'{a74efe00-14be-4ef9-9da9-1484d5473304}!CryptoDPAPI!0xffffffffffffffff' 
	# '{5BBCA4A8-B209-48DC-A8C7-B23D3E5216FB}!CryptoDPAPI!0xffffffffffffffff' # Microsoft-Windows-CAPI2 commented out as this also goes in CAPI2 evtx
)

$ADS_CryptoPrimitivesProviders = @(
	'{E8ED09DC-100C-45E2-9FC8-B53399EC1F70}!CryptoPrimitives!0xffffffffffffffff' #  Microsoft-Windows-Crypto-NCrypt
	'{C7E089AC-BA2A-11E0-9AF7-68384824019B}!CryptoPrimitives!0xffffffffffffffff' #  Microsoft-Windows-Crypto-BCrypt
	'{F3A71A4B-6118-4257-8CCB-39A33BA059D4}!CryptoPrimitives!0xffffffffffffffff' #  Microsoft.Windows.Security.BCrypt
	'{E3E0E2F0-C9C5-11E0-8AB9-9EBC4824019B}!CryptoPrimitives!0xffffffffffffffff' #  Microsoft-Windows-Crypto-CNG
	'{43DAD447-735F-4829-A6FF-9829A87419FF}!CryptoPrimitives!0xffffffffffffffff' #  Microsoft-Windows-Crypto-DSSEnh
	'{152FDB2B-6E9D-4B60-B317-815D5F174C4A}!CryptoPrimitives!0xffffffffffffffff' #  Microsoft-Windows-Crypto-RSAEnh
	'{A74EFE00-14BE-4EF9-9DA9-1484D5473303}!CryptoPrimitives!0xffffffffffffffff' #  CNGTraceControlGuid
	'{413E55F6-5309-4E2D-A7E7-EA98BA06EE89}!CryptoPrimitives!0xffffffffffffffff' #  CryptXmlGlobalDebugTraceControlGuid
	'{EAC19293-76ED-48C3-97D3-70D75DA61438}!CryptoPrimitives!0xffffffffffffffff' #  WPP_CRYPTTPMEKSVC_CONTROL_GUID
	'{FCA9C1D0-5872-4AC2-BB61-1B64511108BA}!CryptoPrimitives!0xffffffffffffffff' #  AeCryptoGuid
	'{80DF111F-178D-44FB-AFB4-5D179DE9D4EC}!CryptoPrimitives!0xffffffffffffffff' #  WPP_CRYPT32_CONTROL_GUID
)

$ADS_WebAuthProviders = @(
	'{2A3C6602-411E-4DC6-B138-EA19D64F5BBA}!WebAuth!0xFFFF'
	'{EF98103D-8D3A-4BEF-9DF2-2156563E64FA}!WebAuth!0xFFFF'
	'{FB6A424F-B5D6-4329-B9B5-A975B3A93EAD}!WebAuth!0x000003FF'
	'{D93FE84A-795E-4608-80EC-CE29A96C8658}!WebAuth!0x7FFFFFFF'
	'{3F8B9EF5-BBD2-4C81-B6C9-DA3CDB72D3C5}!WebAuth!0x7'
	'{B1108F75-3252-4b66-9239-80FD47E06494}!WebAuth!0x2FF'
	'{C10B942D-AE1B-4786-BC66-052E5B4BE40E}!WebAuth!0x3FF'
	'{82c7d3df-434d-44fc-a7cc-453a8075144e}!WebAuth!0x2FF'
	'{05f02597-fe85-4e67-8542-69567ab8fd4f}!WebAuth!0xFFFFFFFF'
	'{3C49678C-14AE-47FD-9D3A-4FEF5D796DB9}!WebAuth!0xFFFFFFFF'
	'{077b8c4a-e425-578d-f1ac-6fdf1220ff68}!WebAuth!0xFFFFFFFF'
	'{7acf487e-104b-533e-f68a-a7e9b0431edb}!WebAuth!0xFFFFFFFF'
	'{5836994d-a677-53e7-1389-588ad1420cc5}!WebAuth!0xFFFFFFFF'
	'{4DE9BC9C-B27A-43C9-8994-0915F1A5E24F}!WebAuth!0xFFFFFFFF'
	'{bfed9100-35d7-45d4-bfea-6c1d341d4c6b}!WebAuth!0xFFFFFFFF'
	'{9EBB3B15-B094-41B1-A3B8-0F141B06BADD}!WebAuth!0xFFF'
	'{6ae51639-98eb-4c04-9b88-9b313abe700f}!WebAuth!0xFFFFFFFF'
	'{7B79E9B1-DB01-465C-AC8E-97BA9714BDA2}!WebAuth!0xFFFFFFFF'
	'{86510A0A-FDF4-44FC-B42F-50DD7D77D10D}!WebAuth!0xFFFFFFFF'
	'{08B15CE7-C9FF-5E64-0D16-66589573C50F}!WebAuth!0xFFFFFF7F'
	'{63b6c2d2-0440-44de-a674-aa51a251b123}!WebAuth!0xFFFFFFFF'
	'{4180c4f7-e238-5519-338f-ec214f0b49aa}!WebAuth!0xFFFFFFFF'
	'{EB65A492-86C0-406A-BACE-9912D595BD69}!WebAuth!0xFFFFFFFF'
	'{d49918cf-9489-4bf1-9d7b-014d864cf71f}!WebAuth!0xFFFFFFFF'
	'{5AF52B0D-E633-4ead-828A-4B85B8DAAC2B}!WebAuth!0xFFFF'
	'{2A6FAF47-5449-4805-89A3-A504F3E221A6}!WebAuth!0xFFFF'
	'{EC3CA551-21E9-47D0-9742-1195429831BB}!WebAuth!0xFFFFFFFF'
	'{bb8dd8e5-3650-5ca7-4fea-46f75f152414}!WebAuth!0xFFFFFFFF'
	'{7fad10b2-2f44-5bb2-1fd5-65d92f9c7290}!WebAuth!0xFFFFFFFF'
	'{74D91EC4-4680-40D2-A213-45E2D2B95F50}!WebAuth!0xFFFFFFFF'
	'{556045FD-58C5-4A97-9881-B121F68B79C5}!WebAuth!0xFFFFFFFF'
	'{5A9ED43F-5126-4596-9034-1DCFEF15CD11}!WebAuth!0xFFFFFFFF'
	'{F7C77B8D-3E3D-4AA5-A7C5-1DB8B20BD7F0}!WebAuth!0xFFFFFFFF'
	'{B3A7698A-0C45-44DA-B73D-E181C9B5C8E6}!WebAuth!0xffffffffffffffff'
	'{20f61733-57f1-4127-9f48-4ab7a9308ae2}!WebAuth!0xffffffffffffffff'
	'{2745a526-23f5-4ef1-b1eb-db8932d43330}!WebAuth!0xffffffffffffffff'
	'{4E749B6A-667D-4C72-80EF-373EE3246B08}!WebAuth!0xffffffffffffffff'
	'{d48533a7-98e4-566d-4956-12474e32a680}!WebAuth!0xffffffffffffffff'
	'{072665fb-8953-5a85-931d-d06aeab3d109}!WebAuth!0xffffffffffffffff'
	'{EF00584A-2655-462C-BC24-E7DE630E7FBF}!WebAuth!0xffffffffffffffff'
	'{c632d944-dddb-599f-a131-baf37bf22ef0}!WebAuth!0xffffffffffffffff'
)

$ADS_SmartCardProviders = @(
	'{30EAE751-411F-414C-988B-A8BFA8913F49}!SmartCard!0xffffffffffffffff'
	'{13038E47-FFEC-425D-BC69-5707708075FE}!SmartCard!0xffffffffffffffff'
	'{3FCE7C5F-FB3B-4BCE-A9D8-55CC0CE1CF01}!SmartCard!0xffffffffffffffff'
	'{FB36CAF4-582B-4604-8841-9263574C4F2C}!SmartCard!0xffffffffffffffff'
	'{133A980D-035D-4E2D-B250-94577AD8FCED}!SmartCard!0xffffffffffffffff'
	'{EED7F3C9-62BA-400E-A001-658869DF9A91}!SmartCard!0xffffffffffffffff'
	'{27BDA07D-2CC7-4F82-BC7A-A2F448AB430F}!SmartCard!0xffffffffffffffff'
	'{15DE6EAF-EE08-4DE7-9A1C-BC7534AB8465}!SmartCard!0xffffffffffffffff'
	'{31332297-E093-4B25-A489-BC9194116265}!SmartCard!0xffffffffffffffff'
	'{4fcbf664-a33a-4652-b436-9d558983d955}!SmartCard!0xffffffffffffffff'
	'{DBA0E0E0-505A-4AB6-AA3F-22F6F743B480}!SmartCard!0xffffffffffffffff'
	'{125f2cf1-2768-4d33-976e-527137d080f8}!SmartCard!0xffffffffffffffff'
	'{beffb691-61cc-4879-9cd9-ede744f6d618}!SmartCard!0xffffffffffffffff'
	'{545c1f45-614a-4c72-93a0-9535ac05c554}!SmartCard!0xffffffffffffffff'
	'{AEDD909F-41C6-401A-9E41-DFC33006AF5D}!SmartCard!0xffffffffffffffff'
	'{09AC07B9-6AC9-43BC-A50F-58419A797C69}!SmartCard!0xffffffffffffffff'
	'{AAEAC398-3028-487C-9586-44EACAD03637}!SmartCard!0xffffffffffffffff'
	'{9F650C63-9409-453C-A652-83D7185A2E83}!SmartCard!0xffffffffffffffff'
	'{F5DBD783-410E-441C-BD12-7AFB63C22DA2}!SmartCard!0xffffffffffffffff'
	'{a3c09ba3-2f62-4be5-a50f-8278a646ac9d}!SmartCard!0xffffffffffffffff'
	'{15f92702-230e-4d49-9267-8e25ae03047c}!SmartCard!0xffffffffffffffff'
)

$ADS_CredprovAuthuiProviders = @(
	'{5e85651d-3ff2-4733-b0a2-e83dfa96d757}!CredprovAuthui!0xffffffffffffffff'
	'{D9F478BB-0F85-4E9B-AE0C-9343F302F9AD}!CredprovAuthui!0xffffffffffffffff'
	'{462a094c-fc89-4378-b250-de552c6872fd}!CredprovAuthui!0xffffffffffffffff'
	'{8db3086d-116f-5bed-cfd5-9afda80d28ea}!CredprovAuthui!0xffffffffffffffff'
	'{a55d5a23-1a5b-580a-2be5-d7188f43fae1}!CredprovAuthui!0xFFFF'
	'{4b8b1947-ae4d-54e2-826a-1aee78ef05b2}!CredprovAuthui!0xFFFF'
	'{176CD9C5-C90C-5471-38BA-0EEB4F7E0BD0}!CredprovAuthui!0xffffffffffffffff'
	'{3EC987DD-90E6-5877-CCB7-F27CDF6A976B}!CredprovAuthui!0xffffffffffffffff'
	'{41AD72C3-469E-5FCF-CACF-E3D278856C08}!CredprovAuthui!0xffffffffffffffff'
	'{4F7C073A-65BF-5045-7651-CC53BB272DB5}!CredprovAuthui!0xffffffffffffffff'
	'{A6C5C84D-C025-5997-0D82-E608D1ABBBEE}!CredprovAuthui!0xffffffffffffffff'
	'{C0AC3923-5CB1-5E37-EF8F-CE84D60F1C74}!CredprovAuthui!0xffffffffffffffff'
	'{DF350158-0F8F-555D-7E4F-F1151ED14299}!CredprovAuthui!0xffffffffffffffff'
	'{FB3CD94D-95EF-5A73-B35C-6C78451095EF}!CredprovAuthui!0xffffffffffffffff'
	'{d451642c-63a6-11d7-9720-00b0d03e0347}!CredprovAuthui!0xffffffffffffffff'
	'{b39b8cea-eaaa-5a74-5794-4948e222c663}!CredprovAuthui!0xffffffffffffffff'
	'{dbe9b383-7cf3-4331-91cc-a3cb16a3b538}!CredprovAuthui!0xffffffffffffffff'
	'{c2ba06e2-f7ce-44aa-9e7e-62652cdefe97}!CredprovAuthui!0xffffffffffffffff'
	'{5B4F9E61-4334-409F-B8F8-73C94A2DBA41}!CredprovAuthui!0xffffffffffffffff'
	'{a789efeb-fc8a-4c55-8301-c2d443b933c0}!CredprovAuthui!0xffffffffffffffff'
	'{301779e2-227d-4faf-ad44-664501302d03}!CredprovAuthui!0xffffffffffffffff'
	'{557D257B-180E-4AAE-8F06-86C4E46E9D00}!CredprovAuthui!0xffffffffffffffff'
	'{D33E545F-59C3-423F-9051-6DC4983393A8}!CredprovAuthui!0xffffffffffffffff'
	'{19D78D7D-476C-47B6-A484-285D1290A1F3}!CredprovAuthui!0xffffffffffffffff'
	'{EB7428F5-AB1F-4322-A4CC-1F1A9B2C5E98}!CredprovAuthui!0xffffffffffffffff'
	'{D9391D66-EE23-4568-B3FE-876580B31530}!CredprovAuthui!0xffffffffffffffff'
	'{D138F9A7-0013-46A6-ADCC-A3CE6C46525F}!CredprovAuthui!0xffffffffffffffff'
	'{2955E23C-4E0B-45CA-A181-6EE442CA1FC0}!CredprovAuthui!0xffffffffffffffff'
	'{012616AB-FF6D-4503-A6F0-EFFD0523ACE6}!CredprovAuthui!0xffffffffffffffff'
	'{5A24FCDB-1CF3-477B-B422-EF4909D51223}!CredprovAuthui!0xffffffffffffffff'
	'{63D2BB1D-E39A-41B8-9A3D-52DD06677588}!CredprovAuthui!0xffffffffffffffff'
	'{4B812E8E-9DFC-56FC-2DD2-68B683917260}!CredprovAuthui!0xffffffffffffffff'
	'{169CC90F-317A-4CFB-AF1C-25DB0B0BBE35}!CredprovAuthui!0xffffffffffffffff'
	'{041afd1b-de76-48e9-8b5c-fade631b0dd5}!CredprovAuthui!0xffffffffffffffff'
	'{39568446-adc1-48ec-8008-86c11637fc74}!CredprovAuthui!0xffffffffffffffff'
	'{A5BFFA95-ACCA-4C18-B51C-DCA0A33A039D}!CredprovAuthui!0xffffffffffffffff'  #CertCredProvider
)

$ADS_NTKernelLoggerProviders = @(
	'{9E814AAD-3204-11D2-9A82-006008A86939}!kernel!0x0000000000000005'	# SystemTraceControlGuid 'NT Kernel Logger'
)

$ADS_ShellRoamingProviders = @(
#	'{83D6E83B-900B-48A3-9835-57656B6F6474}!ShellRoaming!0xffffffffffffffff' 	# Microsoft-Windows-SettingSync 			=> replace with ADS_CDS
#	'{C1779399-4943-4610-83EC-CACE7DA7C2DF}!ShellRoaming!0xffffffffffffffff' 	# Microsoft-Windows-SettingSyncMonitorSVC 	=> replace with ADS_CDS
	'{9F973C1D-D056-4E38-84A5-7BE81CDD6AB6}!ShellRoaming!0xffffffffffffffff' 	# Microsoft-Windows-SettingSync-Azure
	'{885735DA-EFA7-4042-B9BC-195BDFA8B7E7}!ShellRoaming!0xffffffffffffffff'	# Microsoft.Windows.BackupAndRoaming.AzureSyncEngine	
	'{d1731de9-f885-4e1f-948b-76d52702ede9}!ShellRoaming!0xffffffffffffffff'	# 
	'{d5272302-4e7c-45be-961c-62e1280a13db}!ShellRoaming!0xffffffffffffffff'	# 
	'{55f422c8-0aa0-529d-95f5-8e69b6a29c98}!ShellRoaming!0xffffffffffffffff'	# 
)
$ADS_CDSProviders = @(
	'{741BB90C-A7A3-49D6-BD82-1E6B858403F7}!CDS!0xffffffffffffffff' 	# Microsoft-Windows-CloudStore
)

$ADS_CDPProviders = @(
	'{A1EA5EFC-402E-5285-3898-22A5ACCE1B76}!cdp!0xffffffffffffffff'
	'{ABB10A7F-67B4-480C-8834-8B049C428715}!cdp!0xffffffffffffffff'
	'{5fe36556-c4cd-509a-8c3e-2a547ea568ae}!cdp!0xffffffffffffffff'
	'{bc1826c8-369c-5b0b-4cd1-3c6ae5bfe2e7}!cdp!0xffffffffffffffff'
	'{9f4cc6dc-1bab-5772-0c71-a89954718d66}!cdp!0xffffffffffffffff'
	'{30ad9f59-ec19-54b2-4bdf-76dbfc7404a6}!cdp!0xffffffffffffffff'
	'{A48E7274-BB8F-520D-7E6F-1737E9D68491}!cdp!0xffffffffffffffff'
	'{833E7812-D1E2-5172-66FD-4DD4B255A3BB}!cdp!0xffffffffffffffff'
	'{D229987F-EDC3-5274-26BF-82BE01D6D97E}!cdp!0xffffffffffffffff'
	'{88cd9180-4491-4640-b571-e3bee2527943}!cdp!0xffffffffffffffff'
	'{4a16abff-346d-56dc-fa87-eb1e29fe670a}!cdp!0xffffffffffffffff'
	'{ed1640e7-9dc0-45b5-a1ef-88b70cf1742c}!cdp!0xffffffffffffffff'
	'{633383CB-D7A9-4964-876A-66B7DC98C0FE}!cdp!0xffffffffffffffff'
	'{A29339AD-B137-486C-A8F3-88C9738E5379}!cdp!0xffffffffffffffff'
	'{f06690ca-9325-5dcf-65bc-fc3164fa8acc}!cdp!0xffffffffffffffff'
)

$ADS_WinHTTPProviders = @(
	'{7D44233D-3055-4B9C-BA64-0D47CA40A232}!WinHTTP!0xffffffffffffffff'
	'{72B18662-744E-4A68-B816-8D562289A850}!WinHTTP!0xffffffffffffffff'
	'{5402E5EA-1BDD-4390-82BE-E108F1E634F5}!WinHTTP!0xffffffffffffffff'
	'{1070F044-721C-504B-C01C-671DADCBC77D}!WinHTTP!0xffffffffffffffff'
	'{7C109AC5-8971-4B39-AA88-ECF239827664}!WinHTTP!0xffffffffffffffff'
	'{ABC3A4DD-BEEF-BEEF-BEEF-E9E36E904E02}!WinHTTP!0xffffffffffffffff'
)

$ADS_CEPCESProviders = @(
	'{F64ED6BA-BD9B-4CE1-90FB-7B8765928134}!cepces!0xffffffffffffffff'	# Microsoft-Windows-EnrollmentPolicyWebService
	'{C3CBA89D-B3D1-48F1-BE6C-9B317A3CF3D5}!cepces!0xffffffffffffffff'	# Microsoft-Windows-EnrollmentWebService
)

$ADS_IISProviders = @(
	'{670080D9-742A-4187-8D16-41143D1290BD}!InetsrvIIS!0xffffffffffffffff'	# Microsoft-Windows-IIS-W3SVC-WP
	'{05448E22-93DE-4A7A-BBA5-92E27486A8BE}!InetsrvIIS!0xffffffffffffffff'	# Microsoft-Windows-IIS-W3SVC
	'Microsoft-Windows-IIS!InetsrvIIS!0xffffffffffffffff'	# Microsoft-Windows-IIS
	'{3A2A4E84-4C21-4981-AE10-3FDA0D9B0F83}!InetsrvIIS!0xffffffffffffffff'
	'{06B94D9A-B15E-456E-A4EF-37C984A2CB4B}!InetsrvIIS!0xffffffffffffffff'
	'{AFF081FE-0247-4275-9C4E-021F3DC1DA35}!InetsrvIIS!0xffffffffffffffff'
	'{7ACDCAC8-8947-F88A-E51A-24018F5129EF}!InetsrvIIS!0xffffffffffffffff'
	'{04C8A86F-3369-12F8-4769-24E484A9E725}!InetsrvIIS!0xffffffffffffffff'
	'{7EA56435-3F2F-3F63-A829-F0B35B5CAD41}!InetsrvIIS!0xffffffffffffffff'
	'{DD5EF90A-6398-47A4-AD34-4DCECDEF795F}!InetsrvIIS!0xffffffffffffffff'	# Microsoft-Windows-HttpService
	'{7B6BC78C-898B-4170-BBF8-1A469EA43FC5}!InetsrvIIS!0xffffffffffffffff'	# Microsoft-Windows-HttpEvent
)

$ADS_GPOProviders = @(
	'{6FC72ED3-75DA-4BC4-8365-C4228CEAEDFE}!gpo!0xffffffffffffffff'	# Microsoft.Windows.GroupPolicy.RegistryCSE
	'{C1DF9318-DA0B-4CD1-92BF-59415E6454F7}!gpo!0xffffffffffffffff'	# Microsoft.Windows.GroupPolicy.CSEs
	'{AEA1B4FA-97D1-45F2-A64C-4D69FFFD92C9}!gpo!0xffffffffffffffff'	# Microsoft-Windows-GroupPolicy
	'{BD2F4252-5E1E-49FC-9A30-F3978AD89EE2}!gpo!0xffffffffffffffff'	# Microsoft-Windows-GroupPolicyTriggerProvider
)

$ADS_GroupPolicyProviders = $ADS_GPOProviders 

$ADS_OCSPProviders = @(
	'{C7D49BBE-356F-4711-ADB9-32FF162CAB9E}' # Microsoft-Windows-OnlineResponderWebProxy
	'{563E23F4-74B1-40A3-BD37-202BC5711CD7}' # Microsoft-Windows-OnlineResponderRevocationProvider
	'{21B2E773-EBED-4CE1-834A-1444F9E20D6E}' # Microsoft-Windows-OnlineResponder
)
$ADS_W32TimeProviders = @(
	'{361E40D2-7B9E-51C4-DE42-A7F1E997A1D7}' # Microsoft.Windows.Shell.SystemSettings.SyncTime
	'{CFFB980E-327C-5B87-19C6-62C4C3BE2290}' # Microsoft-Windows-Time-Service-PTP-Provider
	'{D5ED0171-F751-4198-9BEE-310358EFC3DC}' # Microsoft.Windows.W32Time.PTP
	'{06EDCFEB-0FD0-4E53-ACCA-A6F8BBF81BCB}' # Microsoft-Windows-Time-Service
	'{8EE3A3BF-9379-4DAC-B376-038F498B19A4}' # Microsoft.Windows.W32Time
	'{95559226-8B1D-4B62-AC40-7176901D66F0}' # W32TimeFlightingProvider
	'{63665931-A4EE-47B3-874D-5155A5CFB415}' # AuthzTraceProvider
	'{13F3DA1B-C22C-4CB1-8C77-ED37787953E9}' # Microsoft.Windows.W32Time.Sync
)

$ADS_TESTProviders = @(
'{6B510852-3583-4e2d-AFFE-A67F9F223438}!AdsTest!0x7ffffff'  #this is in fact Kerberos, just for testing
)

# combinations of providers, as seen in ADS-Scenarios, in order to allow component tracing as well (in combination with other scenarios)
$ADS_BasicProviders = @(
	$ADS_CryptoDPAPIProviders
	$ADS_EFSProviders
	$ADS_CryptoPrimitivesProviders
	$ADS_KerbProviders
	$ADS_NtLmCredSSPProviders
	$ADS_KDCProviders
	$ADS_SSLProviders
	$ADS_WebAuthProviders
	$ADS_SmartCardProviders
	$ADS_CredprovAuthuiProviders
	$ADS_NGCProviders
	$ADS_BioProviders
	$ADS_LSAProviders
 )
$ADS_AccountLockoutProviders = @(
	$ADS_KerbProviders
	$ADS_NtLmCredSSPProviders
	$ADS_KDCProviders
	$ADS_SSLProviders
	$ADS_LSAProviders
 )
$ADS_ESRProviders = @(
	$ADS_WebAuthProviders
	$ADS_ShellRoamingProviders
	$ADS_CDSProviders
	$ADS_CDPProviders
	$ADS_WinHTTPProviders
	$ADS_SSLProviders
 )
$ADS_AuthProviders = @( 
	$ADS_CryptoDPAPIProviders
	$ADS_KerbProviders
	$ADS_NtLmCredSSPProviders
	$ADS_SAMProviders
	$ADS_SSLProviders
	$ADS_WebAuthProviders
	$ADS_SmartCardProviders
	$ADS_CredprovAuthuiProviders
	$ADS_NGCProviders
	$ADS_BioProviders
	$ADS_LSAProviders
 )

#endregion ETW Providers


#region --- Scenario definitions ---
$ADS_ScenarioTraceList = [Ordered]@{
	"ADS_AccountLockout" = "Kerb,NtLmCredSSP,KDC,SSL,LSA ETL log(s)"
	"ADS_Auth"       = "Netlogon,CryptoDPAPI,Kerb,NtLmCredSSP,SAM,SSL,WebAuth,SmartCard,CredprovAuthui,NGC,Bio,LSA,NTKernelLogger(only client),KDC(only DC) ETL log(s)"
	"ADS_Basic"      = "CryptoDPAPI,EFS,CryptoPrimitives,Kerb,NtLmCredSSP,KDC,SSL,WebAuth,SmartCard,CredprovAuthui,NGC,Bio,LSA ETL log(s)"
	"ADS_ESR"        = "WebAuth,ShellRoaming,CDP,WinHTTP,SSL ETL log(s)"
	"ADS_OCSP"       = "PSR,SDP Dom, OCSP,HTTP,TLS,IIS ETL log(s), Netsh scenario=NetConnection"
	"ADS_SBSL"       = "Slow Boot/Slow Logon: Profile,Netlogon,WinLogon,GroupPolicy,DCLocator,GPresult,GPsvc,Auth ETL log(s), WhoAmI, Xperf SBSLboot, Netsh scenario=NetConnection; use with -StartAutologger; def. XperfMaxFile=16384"
}

#ADS_Basic Scenario
$ADS_Basic_ETWTracingSwitchesStatus = [Ordered]@{
	'ADS_CryptoDPAPI' = $true
	'ADS_EFS' = $true
	'ADS_CryptoPrimitives' = $true
	'ADS_Kerb' = $true
	'ADS_NtLmCredSSP' = $true
	'ADS_KDC' = $true
	'ADS_SSL' = $true
	'ADS_WebAuth' = $true
	'ADS_SmartCard' = $true
	'ADS_CredprovAuthui' = $true
	'ADS_NGC' = $true
	'ADS_Bio' = $true
	'ADS_LSA' = $true
	'CollectComponentLog' = $True
}

#ADS_ACCOUNTLOCKUT Scenario
$ADS_AccountLockout_ETWTracingSwitchesStatus = [Ordered]@{
	'ADS_Kerb' = $true
	'ADS_NtLmCredSSP' = $true
	'ADS_KDC' = $true
	'ADS_SSL' = $true
	'ADS_LSA' = $true
	'CollectComponentLog' = $True
}

#ADS_Auth Scenario
switch (global:FwGetProductTypeFromReg)
{
	 "WinNT" {
			$ADS_Auth_ETWTracingSwitchesStatus = [Ordered]@{
				'ADS_Netlogon' = $true
				'ADS_NGC' = $true
				'ADS_Bio' = $true
				'ADS_LSA' = $true
				'ADS_NtLmCredSSP' = $true
				'ADS_Kerb' = $true
				# 'ADS_KDC' = $true
				'ADS_SAM' = $true
				'ADS_SSL' = $true
				'ADS_CryptoDPAPI' = $true
				'ADS_WebAuth' = $true
				'ADS_SmartCard' = $true
				'ADS_CredprovAuthui' = $true
				'ADS_NTKernelLogger' = $true
				'CollectComponentLog' = $True
				}
		}
	 "ServerNT" {
			$ADS_Auth_ETWTracingSwitchesStatus = [Ordered]@{
				'ADS_Netlogon' = $true
				'ADS_NGC' = $true
				'ADS_Bio' = $true
				'ADS_LSA' = $true
				'ADS_NtLmCredSSP' = $true
				'ADS_Kerb' = $true
				#'ADS_KDC' = $true
				'ADS_SAM' = $true
				'ADS_SSL' = $true
				'ADS_CryptoDPAPI' = $true
				'ADS_WebAuth' = $true
				'ADS_SmartCard' = $true
				'ADS_CredprovAuthui' = $true
				'CollectComponentLog' = $True
				}
		}
	 "LanmanNT" {
			$ADS_Auth_ETWTracingSwitchesStatus = [Ordered]@{
				'ADS_Netlogon' = $true
				'ADS_NGC' = $true
				'ADS_Bio' = $true
				'ADS_LSA' = $true
				'ADS_NtLmCredSSP' = $true
				'ADS_Kerb' = $true
				'ADS_KDC' = $true  #only for KDC/LanmanNT
				'ADS_SAM' = $true
				'ADS_SSL' = $true
				'ADS_CryptoDPAPI' = $true
				'ADS_WebAuth' = $true
				'ADS_SmartCard' = $true
				'ADS_CredprovAuthui' = $true
				'CollectComponentLog' = $True
				}
		}
	 Default {
		"EmptyProductType"
			$ADS_Auth_ETWTracingSwitchesStatus = [Ordered]@{
				'ADS_Netlogon' = $true
				'ADS_NGC' = $true
				'ADS_Bio' = $true
				'ADS_LSA' = $true
				'ADS_NtLmCredSSP' = $true
				'ADS_Kerb' = $true
				'ADS_KDC' = $true  #only for KDC/LanmanNT
				'ADS_SAM' = $true
				'ADS_SSL' = $true
				'ADS_CryptoDPAPI' = $true
				'ADS_WebAuth' = $true
				'ADS_SmartCard' = $true
				'ADS_CredprovAuthui' = $true
				'CollectComponentLog' = $True
				}
		}
}

#ADS ESR Scenario
$ADS_ESR_ETWTracingSwitchesStatus = [Ordered]@{
	'ADS_WebAuth' = $true
	'ADS_ShellRoaming' = $true
	'ADS_CDP' = $true
	'ADS_WinHTTP' = $true
	'ADS_SSL' = $true
	'CollectComponentLog' = $True
}

#ADS OCPS Scenario - Online Certificate Status Protocol
$ADS_OCSP_ETWTracingSwitchesStatus = [Ordered]@{
	'ADS_OCSP' = $true
	'NET_HttpSys' = $true
	'NET_TLS' = $true
	'NET_IIS' = $true
	'NetshScenario NetConnection' = $true
	#'Procmon' = $true
	'PSR' = $true
	#'Video' = $true
	'SDP DOM' = $True
	#'xray' = $True
	'CollectComponentLog' = $True
}

$ADS_SBSL_ETWTracingSwitchesStatus = [Ordered]@{
	'NET_SBSL' = $true
	'NET_SMBcli' = $true
	'NET_DCLocator' = $true
	'ADS_Auth' = $true
	'ADS_Profile' = $true
	'ADS_GroupPolicy' = $true
	'ADS_GPsvc' = $true
	'NET_Netlogon' = $true
	'NET_WinLogon' = $true
	'Xperf SBSLboot' = $true
	#'CommonTask NET' = $True 
	'NetshScenario NetConnection' = $true
	'PerfMon SMB' = $true
	#'PSR' = $true
	#'Video' = $true
	'SDP NET' = $True
	'xray' = $True
	'CollectComponentLog' = $True
 }
#endregion --- Scenario definitions ---


#region traces_switches_functions
# -------------- TRACES/SWITCHES ---------------


# -------------- AdsTest -----------
# IMPORTANT: this trace should be used only for development and testing purposes

function AdsTestPreStart
{
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] .. started"

	global:FwCollect_BasicLog

	#Event Log - Set Log - Enable
	$EventLogSetLogListOn = New-Object 'System.Collections.Generic.List[Object]'
	$EventLogSetLogListOn = @(  #LogName, enabled, retention, quiet, MaxSize
		@("Microsoft-Windows-CAPI2/Operational", "true", "false", "true", "102400000"),
		@("Microsoft-Windows-Kerberos/Operational", "true", "", "", "")
	)
	ForEach ($EventLog in $EventLogSetLogListOn)
	{
	 global:FwEventLogsSet $EventLog[0] $EventLog[1] $EventLog[2] $EventLog[3] $EventLog[4]
	}

	#Event Log - Export Log
	$EventLogExportLogList = New-Object 'System.Collections.Generic.List[Object]'
	$EventLogExportLogList = @(  #LogName, filename, overwrite
		@("Microsoft-Windows-CAPI2/Operational", "c:\dev\Capi2_Oper.evtx", "true"),
		@("Microsoft-Windows-Kerberos/Operational", "c:\dev\Kerberos_Oper.evtx", "true")
	)
	ForEach ($EventLog in $EventLogExportLogList)
	{
	 global:FwExportSingleEventLog $EventLog[0] $EventLog[1] $EventLog[2] 
	}

	#Event Log - Set Log - Disable
	$EventLogSetLogListOff = New-Object 'System.Collections.Generic.List[Object]'
	$EventLogSetLogListOff = @(  #LogName, enabled, retention, quiet, MaxSize
		@("Microsoft-Windows-CAPI2/Operational", "false", "", "", ""),
		@("Microsoft-Windows-Kerberos/Operational", "false", "", "", "")
	)
	ForEach ($EventLog in $EventLogSetLogListOff)
	{
	 global:FwEventLogsSet $EventLog[0] $EventLog[1] $EventLog[2] $EventLog[3] $EventLog[4]
	}

	 #Event Log - Clear Log
	$EventLogClearLogList = New-Object 'System.Collections.Generic.List[Object]'
	$EventLogClearLogList = @(  #LogName, enabled, retention, quiet, MaxSize
		@("Microsoft-Windows-CAPI2/Operational"),
		@("Microsoft-Windows-Kerberos/Operational")
	)
	ForEach ($EventLog in $EventLogClearLogList)
	{
		global:FwEventLogClear $EventLog[0] 
	}

	#Various registry manipulaiton functions

	# RegAddValues
	$RegAddValues = New-Object 'System.Collections.Generic.List[Object]'

	$RegAddValues = @(  #RegKey, RegValue, Type, Data
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\My Key", "my test1", "REG_DWORD", "0x1"),
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\My Key", "my test2", "REG_DWORD", "0x2")
	)

	ForEach ($regadd in $RegAddValues)
	{
		global:FwAddRegValue $regadd[0] $regadd[1] $regadd[2] $regadd[3]
	}

	# RegExport in TXT
	LogInfo "[$global:TssPhase ADS Stage:] Exporting Reg.keys .. " "gray"
	$RegExportKeyInTxt = New-Object 'System.Collections.Generic.List[Object]'
	$RegExportKeyInTxt = @(  #Key, ExportFile, Format (TXT or REG)
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\My Key", "C:\Dev\regtestexportTXT1.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL", "C:\Dev\regtestexportTXT2.txt", "TXT")
	)
 
	ForEach ($regtxtexport in $RegExportKeyInTxt)
	{
		global:FwExportRegKey $regtxtexport[0] $regtxtexport[1] $regtxtexport[2]
	}

	# RegExport in REG

	$RegExportKeyInReg = New-Object 'System.Collections.Generic.List[Object]'

	$RegExportKeyInReg = @(  #Key, ExportFile, Format (TXT or REG)
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\My Key", "C:\Dev\regtestexportREG1.reg", "REG"),
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL", "C:\Dev\regtestexportREG2.reg", "REG")
	)
 

	ForEach ($regregexport in $RegExportKeyInReg)
	{
		global:FwExportRegKey $regregexport[0] $regregexport[1] $regregexport[2]
	}

	# RegDeleteValues
	$RegDeleteValues = New-Object 'System.Collections.Generic.List[Object]'

	$RegDeleteValues = @(  #RegKey, RegValue
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\My Key", "my test1"),
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\My Key", "my test2")
	)

	ForEach ($regdel in $RegDeleteValues)
	{
		global:FwDeleteRegValue $regdel[0] $regdel[1] 
	}
 
	# Create Folder
	# FwCreateFolder "c:\dev\my folder\test\test2"

	#File Copy Operations:
	$SourceDestinationPaths = New-Object 'System.Collections.Generic.List[Object]'
	$SourceDestinationPaths = @(  #source (* wildcard is supported) and destination
		@("C:\Dev\my folder\test*", "C:\Dev\my folder\dest"), #this will copy all files that match * criteria into dest folder
		@("C:\Dev\my folder\test1.txt", "C:\Dev\my folder\dest\test1.txt") #this will copy test1.txt to destination file name and add logprefix
	)

	global:FwCopyFiles $SourceDestinationPaths
	EndFunc $MyInvocation.MyCommand.Name
}

function AdsTestPostStop
{
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] .. started"
	EndFunc $MyInvocation.MyCommand.Name
}


# -------------- ADS_GPO Trace ---------------

function ADS_GPOPreStart
{
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] .. started"

# import registry
# Key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Group Policy" does not exist by default
$regcontent = 'Windows Registry Editor Version 5.00
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy]
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{0E28E245-9368-4853-AD84-6DA3BA35BB75}]
"LogLevel"=dword:00000003
"TraceLevel"=dword:00000002
"TraceFilePathUser"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,52,\
  00,49,00,56,00,45,00,25,00,5c,00,55,00,73,00,65,00,72,00,2e,00,6c,00,6f,00,\
  67,00,00,00
"TraceFilePathMachine"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,43,00,6f,00,6d,00,70,00,75,00,74,00,65,\
  00,72,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFilePathPlanning"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,50,00,6c,00,61,00,6e,00,6e,00,69,00,6e,\
  00,67,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFileMaxSize"=dword:00000400
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{17D89FEC-5C44-4972-B12D-241CAEF74509}]
"LogLevel"=dword:00000003
"TraceLevel"=dword:00000002
"TraceFilePathUser"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,52,\
  00,49,00,56,00,45,00,25,00,5c,00,55,00,73,00,65,00,72,00,2e,00,6c,00,6f,00,\
  67,00,00,00
"TraceFilePathMachine"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,43,00,6f,00,6d,00,70,00,75,00,74,00,65,\
  00,72,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFilePathPlanning"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,50,00,6c,00,61,00,6e,00,6e,00,69,00,6e,\
  00,67,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFileMaxSize"=dword:00000400
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{1A6364EB-776B-4120-ADE1-B63A406A76B5}]
"LogLevel"=dword:00000003
"TraceLevel"=dword:00000002
"TraceFilePathUser"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,52,\
  00,49,00,56,00,45,00,25,00,5c,00,55,00,73,00,65,00,72,00,2e,00,6c,00,6f,00,\
  67,00,00,00
"TraceFilePathMachine"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,43,00,6f,00,6d,00,70,00,75,00,74,00,65,\
  00,72,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFilePathPlanning"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,50,00,6c,00,61,00,6e,00,6e,00,69,00,6e,\
  00,67,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFileMaxSize"=dword:00000400
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{3A0DBA37-F8B2-4356-83DE-3E90BD5C261F}]
"LogLevel"=dword:00000003
"TraceLevel"=dword:00000002
"TraceFilePathUser"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,52,\
  00,49,00,56,00,45,00,25,00,5c,00,55,00,73,00,65,00,72,00,2e,00,6c,00,6f,00,\
  67,00,00,00
"TraceFilePathMachine"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,43,00,6f,00,6d,00,70,00,75,00,74,00,65,\
  00,72,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFilePathPlanning"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,50,00,6c,00,61,00,6e,00,6e,00,69,00,6e,\
  00,67,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFileMaxSize"=dword:00000400
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{5794DAFD-BE60-433f-88A2-1A31939AC01F}]
"LogLevel"=dword:00000003
"TraceLevel"=dword:00000002
"TraceFilePathUser"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,52,\
  00,49,00,56,00,45,00,25,00,5c,00,55,00,73,00,65,00,72,00,2e,00,6c,00,6f,00,\
  67,00,00,00
"TraceFilePathMachine"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,43,00,6f,00,6d,00,70,00,75,00,74,00,65,\
  00,72,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFilePathPlanning"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,50,00,6c,00,61,00,6e,00,6e,00,69,00,6e,\
  00,67,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFileMaxSize"=dword:00000400
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{6232C319-91AC-4931-9385-E70C2B099F0E}]
"LogLevel"=dword:00000003
"TraceLevel"=dword:00000002
"TraceFilePathUser"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,52,\
  00,49,00,56,00,45,00,25,00,5c,00,55,00,73,00,65,00,72,00,2e,00,6c,00,6f,00,\
  67,00,00,00
"TraceFilePathMachine"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,43,00,6f,00,6d,00,70,00,75,00,74,00,65,\
  00,72,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFilePathPlanning"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,50,00,6c,00,61,00,6e,00,6e,00,69,00,6e,\
  00,67,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFileMaxSize"=dword:00000400
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{6A4C88C6-C502-4f74-8F60-2CB23EDC24E2}]
"LogLevel"=dword:00000003
"TraceLevel"=dword:00000002
"TraceFilePathUser"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,52,\
  00,49,00,56,00,45,00,25,00,5c,00,55,00,73,00,65,00,72,00,2e,00,6c,00,6f,00,\
  67,00,00,00
"TraceFilePathMachine"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,43,00,6f,00,6d,00,70,00,75,00,74,00,65,\
  00,72,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFilePathPlanning"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,50,00,6c,00,61,00,6e,00,6e,00,69,00,6e,\
  00,67,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFileMaxSize"=dword:00000400
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{7150F9BF-48AD-4da4-A49C-29EF4A8369BA}]
"LogLevel"=dword:00000003
"TraceLevel"=dword:00000002
"TraceFilePathUser"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,52,\
  00,49,00,56,00,45,00,25,00,5c,00,55,00,73,00,65,00,72,00,2e,00,6c,00,6f,00,\
  67,00,00,00
"TraceFilePathMachine"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,43,00,6f,00,6d,00,70,00,75,00,74,00,65,\
  00,72,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFilePathPlanning"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,50,00,6c,00,61,00,6e,00,6e,00,69,00,6e,\
  00,67,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFileMaxSize"=dword:00000400
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{728EE579-943C-4519-9EF7-AB56765798ED}]
"LogLevel"=dword:00000003
"TraceLevel"=dword:00000002
"TraceFilePathUser"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,52,\
  00,49,00,56,00,45,00,25,00,5c,00,55,00,73,00,65,00,72,00,2e,00,6c,00,6f,00,\
  67,00,00,00
"TraceFilePathMachine"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,43,00,6f,00,6d,00,70,00,75,00,74,00,65,\
  00,72,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFilePathPlanning"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,50,00,6c,00,61,00,6e,00,6e,00,69,00,6e,\
  00,67,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFileMaxSize"=dword:00000400
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{74EE6C03-5363-4554-B161-627540339CAB}]
"LogLevel"=dword:00000003
"TraceLevel"=dword:00000002
"TraceFilePathUser"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,52,\
  00,49,00,56,00,45,00,25,00,5c,00,55,00,73,00,65,00,72,00,2e,00,6c,00,6f,00,\
  67,00,00,00
"TraceFilePathMachine"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,43,00,6f,00,6d,00,70,00,75,00,74,00,65,\
  00,72,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFilePathPlanning"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,50,00,6c,00,61,00,6e,00,6e,00,69,00,6e,\
  00,67,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFileMaxSize"=dword:00000400
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{91FBB303-0CD5-4055-BF42-E512A681B325}]
"LogLevel"=dword:00000003
"TraceLevel"=dword:00000002
"TraceFilePathUser"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,52,\
  00,49,00,56,00,45,00,25,00,5c,00,55,00,73,00,65,00,72,00,2e,00,6c,00,6f,00,\
  67,00,00,00
"TraceFilePathMachine"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,43,00,6f,00,6d,00,70,00,75,00,74,00,65,\
  00,72,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFilePathPlanning"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,50,00,6c,00,61,00,6e,00,6e,00,69,00,6e,\
  00,67,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFileMaxSize"=dword:00000400
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{A3F3E39B-5D83-4940-B954-28315B82F0A8}]
"LogLevel"=dword:00000003
"TraceLevel"=dword:00000002
"TraceFilePathUser"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,52,\
  00,49,00,56,00,45,00,25,00,5c,00,55,00,73,00,65,00,72,00,2e,00,6c,00,6f,00,\
  67,00,00,00
"TraceFilePathMachine"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,43,00,6f,00,6d,00,70,00,75,00,74,00,65,\
  00,72,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFilePathPlanning"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,50,00,6c,00,61,00,6e,00,6e,00,69,00,6e,\
  00,67,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFileMaxSize"=dword:00000400
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{AADCED64-746C-4633-A97C-D61349046527}]
"LogLevel"=dword:00000003
"TraceLevel"=dword:00000002
"TraceFilePathUser"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,52,\
  00,49,00,56,00,45,00,25,00,5c,00,55,00,73,00,65,00,72,00,2e,00,6c,00,6f,00,\
  67,00,00,00
"TraceFilePathMachine"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,43,00,6f,00,6d,00,70,00,75,00,74,00,65,\
  00,72,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFilePathPlanning"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,50,00,6c,00,61,00,6e,00,6e,00,69,00,6e,\
  00,67,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFileMaxSize"=dword:00000400
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{B087BE9D-ED37-454f-AF9C-04291E351182}]
"LogLevel"=dword:00000003
"TraceLevel"=dword:00000002
"TraceFilePathUser"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,52,\
  00,49,00,56,00,45,00,25,00,5c,00,55,00,73,00,65,00,72,00,2e,00,6c,00,6f,00,\
  67,00,00,00
"TraceFilePathMachine"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,43,00,6f,00,6d,00,70,00,75,00,74,00,65,\
  00,72,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFilePathPlanning"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,50,00,6c,00,61,00,6e,00,6e,00,69,00,6e,\
  00,67,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFileMaxSize"=dword:00000400
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{BC75B1ED-5833-4858-9BB8-CBF0B166DF9D}]
"LogLevel"=dword:00000003
"TraceLevel"=dword:00000002
"TraceFilePathUser"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,52,\
  00,49,00,56,00,45,00,25,00,5c,00,55,00,73,00,65,00,72,00,2e,00,6c,00,6f,00,\
  67,00,00,00
"TraceFilePathMachine"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,43,00,6f,00,6d,00,70,00,75,00,74,00,65,\
  00,72,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFilePathPlanning"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,50,00,6c,00,61,00,6e,00,6e,00,69,00,6e,\
  00,67,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFileMaxSize"=dword:00000400
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{C418DD9D-0D14-4efb-8FBF-CFE535C8FAC7}]
"LogLevel"=dword:00000003
"TraceLevel"=dword:00000002
"TraceFilePathUser"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,52,\
  00,49,00,56,00,45,00,25,00,5c,00,55,00,73,00,65,00,72,00,2e,00,6c,00,6f,00,\
  67,00,00,00
"TraceFilePathMachine"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,43,00,6f,00,6d,00,70,00,75,00,74,00,65,\
  00,72,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFilePathPlanning"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,50,00,6c,00,61,00,6e,00,6e,00,69,00,6e,\
  00,67,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFileMaxSize"=dword:00000400
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{E47248BA-94CC-49c4-BBB5-9EB7F05183D0}]
"LogLevel"=dword:00000003
"TraceLevel"=dword:00000002
"TraceFilePathUser"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,52,\
  00,49,00,56,00,45,00,25,00,5c,00,55,00,73,00,65,00,72,00,2e,00,6c,00,6f,00,\
  67,00,00,00
"TraceFilePathMachine"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,43,00,6f,00,6d,00,70,00,75,00,74,00,65,\
  00,72,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFilePathPlanning"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,50,00,6c,00,61,00,6e,00,6e,00,69,00,6e,\
  00,67,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFileMaxSize"=dword:00000400
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{E4F48E54-F38D-4884-BFB9-D4D2E5729C18}]
"LogLevel"=dword:00000003
"TraceLevel"=dword:00000002
"TraceFilePathUser"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,52,\
  00,49,00,56,00,45,00,25,00,5c,00,55,00,73,00,65,00,72,00,2e,00,6c,00,6f,00,\
  67,00,00,00
"TraceFilePathPlanning"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,50,00,6c,00,61,00,6e,00,6e,00,69,00,6e,\
  00,67,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFileMaxSize"=dword:00000400
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{E5094040-C46C-4115-B030-04FB2E545B00}]
"LogLevel"=dword:00000003
"TraceLevel"=dword:00000002
"TraceFilePathUser"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,52,\
  00,49,00,56,00,45,00,25,00,5c,00,55,00,73,00,65,00,72,00,2e,00,6c,00,6f,00,\
  67,00,00,00
"TraceFilePathMachine"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,43,00,6f,00,6d,00,70,00,75,00,74,00,65,\
  00,72,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFilePathPlanning"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,50,00,6c,00,61,00,6e,00,6e,00,69,00,6e,\
  00,67,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFileMaxSize"=dword:00000400
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{E62688F0-25FD-4c90-BFF5-F508B9D2E31F}]
"LogLevel"=dword:00000003
"TraceLevel"=dword:00000002
"TraceFilePathUser"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,52,\
  00,49,00,56,00,45,00,25,00,5c,00,55,00,73,00,65,00,72,00,2e,00,6c,00,6f,00,\
  67,00,00,00
"TraceFilePathMachine"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,43,00,6f,00,6d,00,70,00,75,00,74,00,65,\
  00,72,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFilePathPlanning"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,50,00,6c,00,61,00,6e,00,6e,00,69,00,6e,\
  00,67,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFileMaxSize"=dword:00000400
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{F9C77450-3A41-477E-9310-9ACD617BD9E3}]
"LogLevel"=dword:00000003
"TraceLevel"=dword:00000002
"TraceFilePathUser"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,52,\
  00,49,00,56,00,45,00,25,00,5c,00,55,00,73,00,65,00,72,00,2e,00,6c,00,6f,00,\
  67,00,00,00
"TraceFilePathMachine"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,43,00,6f,00,6d,00,70,00,75,00,74,00,65,\
  00,72,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFilePathPlanning"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,50,00,6c,00,61,00,6e,00,6e,00,69,00,6e,\
  00,67,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFileMaxSize"=dword:00000400'


	$regcontent | Out-File myreg.reg

	$RegImportResult = (Start-Process -FilePath "reg.exe" -ArgumentList "import myreg.reg" -NoNewWindow -PassThru -Wait ).ExitCode

	LogInfo "RegImportResult = $RegImportResult"
	EndFunc $MyInvocation.MyCommand.Name

}

function CollectADS_GPOLog
{
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] .. started"

	$SourceDestinationPaths = New-Object 'System.Collections.Generic.List[Object]'
	$SourceDestinationPaths = @(  #source (* wildcard is supported) and destination
		#@("C:\User.log", "$($PrefixTime)User.log"),
		#@("C:\Computer.log", "$($PrefixTime)Computer.log")
		#@("C:\Planning.log", "$($PrefixTime)Planing.log")
		@("$env:SystemDrive\User.log", "$($PrefixTime)GPPREF_User.log"),
		@("$env:SystemDrive\Computer.log", "$($PrefixTime)GPPREF_Computer.log"),
		@("$env:SystemDrive\Planning.log", "$($PrefixTime)GPPREF_Planing.log")
	)
	global:FwCopyFiles $SourceDestinationPaths

	#delete log files in $env:SystemDrive\User.log, $env:SystemDrive\Computer.log and $env:SystemDrive\Planing.log
		$FileClearLogList = New-Object 'System.Collections.Generic.List[Object]'
		$FileClearLogList = @(  
		@("$env:SystemDrive\User.log"),
		@("$env:SystemDrive\Computer.log"),
		@("$env:SystemDrive\Planing.log"),
		@("myreg.reg")
		)

		ForEach ($file in $FileClearLogList){
			if (Test-Path $file){
				Remove-Item $file -Force
			}
		}
	EndFunc $MyInvocation.MyCommand.Name
}

function ADS_GPOPostStop
{
#delete registry
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] .. started"
	Get-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy" | Remove-Item -Recurse -Force -Verbose -Confirm:$false
	EndFunc $MyInvocation.MyCommand.Name

}



# -------------- ADS_ADCS ---------------


function ADS_ADCSPreStart
{
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] .. started"

	$CertSrvProcess = "CertSrv" 
	$process = Get-Process $CertSrvProcess -ErrorAction SilentlyContinue
	If (!($process)) {
		LogWarn "ADCS Certification Authority is not running on this box.`n"
		$UserConsent = Read-Host -Prompt 'Are you sure you want to continue with the data collection[Y/N]'
		if ($UserConsent -ne 'Y'){
			LogWarn("Script execution cancelled, exiting.")
			global:FwCleanUpandExit
		} 
	}

	wevtutil.exe clear-log "Microsoft-Windows-CAPI2/Operational" 2>&1 | Out-Null
	wevtutil.exe sl "Microsoft-Windows-CAPI2/Operational" /ms:102400000 2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-Kerberos/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null
	wevtutil.exe clear-log "Microsoft-Windows-Kerberos/Operational" 2>&1 | Out-Null

	certutil.exe -f -setreg ca\debug 0xffffffe3 2>&1 | Out-Null
	certutil.exe getreg ca\loglevel 4 2>&1 | Out-Null
	
	Net.exe Stop Certsvc 2>&1 | Out-Null
	Net.exe Start Certsvc 2>&1 | Out-Null

	FwListProcsAndSvcs
	#Get-Process | Out-File -FilePath "$($PrefixTime)start-tasklist.txt" 2>&1 | Out-Null

	LogInfo "ADS ADCS (cert authority) tracing started"
	EndFunc $MyInvocation.MyCommand.Name
}


function CollectADS_ADCSLog
{
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] .. started"

	wevtutil epl System "$($PrefixTime)System.evtx" /overwrite:true 2>&1 | Out-Null
	wevtutil epl Application "$($PrefixTime)Application.evtx" /overwrite:true 2>&1 | Out-Null

	certutil.exe -v -silent -store my > "$($PrefixTime)machine-store.txt" 2>&1 | Out-Null
	certutil.exe -v -user -silent -store my > "$($PrefixTime)user-store.txt" 2>&1 | Out-Null

	certutil.exe -v -template > "$($PrefixTime)templateCache.txt" 2>&1 | Out-Null
	#certutil.exe -v -dstemplate > "$($PrefixTime)templateAD.txt" 2>&1 | Out-Null

	ipconfig /all > "$($PrefixTime)ipconfig-info.txt" 2>&1 | Out-Null

	Copy-Item "$($Env:windir)\certsrv.log" -Destination "$($PrefixTime)certsrv.log" 2>&1 | Out-Null
	Copy-Item "$($Env:windir)\certocm.log" -Destination "$($PrefixTime)certocm.log" 2>&1 | Out-Null
	Copy-Item "$($Env:windir)\certutil.log" -Destination "$($PrefixTime)certutil.log" 2>&1 | Out-Null
	Copy-Item "$($Env:windir)\certmmc.log" -Destination "$($PrefixTime)certmmc.log" 2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-CAPI2/Operational" /enabled:false  2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-CAPI2/Operational" "$($PrefixTime)Capi2_Oper.evtx" /overwrite:true  2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-Kerberos/Operational" /enabled:false  2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-Kerberos/Operational" "$($PrefixTime)Kerb_Oper.evtx" /overwrite:true  2>&1 | Out-Null

	Get-ChildItem env:* |  Out-File -FilePath "$($PrefixTime)env.txt" 2>&1 | Out-Null

	reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v BuildLabEx > "$($PrefixTime)build.txt" 2>&1 | Out-Null
	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography" /s > "$($PrefixTime)reg_HKLMControl-Cryptography.txt" 2>&1 | Out-Null
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography" /s > "$($PrefixTime)reg_HKLMSoftware-Cryptography.txt"
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography" /s > "$($PrefixTime)reg_HKLMSoftware-policies-Cryptography.txt" 2>&1 | Out-Null
	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc" /s > "$($PrefixTime)reg_CertSvc.txt" 2>&1 | Out-Null

	FwListProcsAndSvcs
	#Get-Process | Out-File -FilePath "$($PrefixTime)stop-tasklist.txt" 2>&1 | Out-Null

	klist > "$($PrefixTime)tickets-stop.txt" 2>&1 | Out-Null
	klist -li 0x3e7 > "$($PrefixTime)ticketscomputer-stop.txt" 2>&1 | Out-Null

	FwCaptureUserDump "CertSvc" $global:LogFolder -IsService:$True

	certutil -f -setreg ca\debug 0x0 2>&1 | Out-Null
	certutil -getreg ca\loglevel 3 2>&1 | Out-Null

	Net Stop Certsvc 2>&1 | Out-Null
	Net Start Certsvc 2>&1 | Out-Null

	LogInfoFile "ADS ADCS (cert authority) tracing completed"
	EndFunc $MyInvocation.MyCommand.Name
}

# -------------- ADS_BadPwd ---------------
function CollectADS_BadPwdLog {
	EnterFunc $MyInvocation.MyCommand.Name
	.\scripts\tss_FindUserBadPwdAttempts.ps1 -DataPath $global:LogFolder
	EndFunc $MyInvocation.MyCommand.Name
}
# -------------- ADS_LockOut --------------- #_# ToDo: compare to ADS_AccountLockoutS
function CollectADS_LockOutLog {
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "[$($MyInvocation.MyCommand.Name)] you need to have domain admin privilege to run this script GetLockoutEvents"
	.\scripts\tss_GetLockoutEvents.ps1 -DataPath $global:LogFolder
	EndFunc $MyInvocation.MyCommand.Name
}

# -------------- ADS_DFSr ---------------
function CollectADS_DFSrLog {
	EnterFunc $MyInvocation.MyCommand.Name
	FwExportEventLog @("DFS Replication") $global:LogFolder
	LogInfoFile "[$($MyInvocation.MyCommand.Name)]  copy DFSR*.log and last 5 *DFSR*.log.gz files"
	FwCreateFolder $global:LogFolder\DFSR
	Get-ChildItem $Env:SystemRoot\debug\*DFSR*.log.gz | Sort-Object -Property LastWriteTime | Select-Object -Last 5 | Copy-Item -Destination $global:LogFolder\DFSR\
	$Commands = @(
		"xcopy /i/q/y/H $Env:SystemRoot\debug\Dfsr*.log $global:LogFolder\DFSR"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	EndFunc $MyInvocation.MyCommand.Name
}

# -------------- ADS_CEPCES ---------------

function ADS_CEPCESPreStart
{
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] .. started"	

	wevtutil.exe set-log "Microsoft-Windows-EnrollmentPolicyWebService/Admin" /enabled:true 2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-EnrollmentWebService/Admin" /enabled:true 2>&1 | Out-Null

	FwListProcsAndSvcs
	#Get-Process | Out-File -FilePath "$($PrefixTime)start-tasklist.txt" 2>&1 | Out-Null

	LogInfoFile "ADS_CEPCESPreStart completed"
	EndFunc $MyInvocation.MyCommand.Name
}


function CollectADS_CEPCESLog
{
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] .. started"	
	wevtutil.exe set-log "Microsoft-Windows-EnrollmentPolicyWebService/Admin" /enabled:false  2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-EnrollmentPolicyWebService/Admin" "$($PrefixTime)EnrollmentPolicy.evtx" /overwrite:true  2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-EnrollmentWebService/Admin" /enabled:false  2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-EnrollmentWebService/Admin" "$($PrefixTime)EnrollmentWeb.evtx" /overwrite:true  2>&1 | Out-Null
	wevtutil epl System "$($PrefixTime)System.evtx" /overwrite:true 2>&1 | Out-Null
	wevtutil epl Application "$($PrefixTime)Application.evtx" /overwrite:true 2>&1 | Out-Null
	Get-ChildItem env:* |  Out-File -FilePath "$($PrefixTime)env.txt" 2>&1 | Out-Null
	FwListProcsAndSvcs
	#Get-Process | Out-File -FilePath "$($PrefixTime)stop-tasklist.txt" 2>&1 | Out-Null
	LogInfoFile "CollectADS_CEPCESLog completed"
	EndFunc $MyInvocation.MyCommand.Name

}

function ADS_GPeditPreStart {
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "[$($MyInvocation.MyCommand.Name)] adding Group Policy Management Editor Reg Debug keys"
	if (!(Test-Path -Path $env:SystemRoot\debug\usermode)){FwCreateFolder $env:SystemRoot\debug\usermode}
	FwAddRegValue "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" "GPEditDebugLevel" "REG_DWORD" $global:GPEditDebugLevel	#_# $global:GPEditDebugLevel = "0x10002"
	FwAddRegValue "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" "GPTextDebugLevel" "REG_DWORD" "0x10002"
	LogWarn "[Info] [$($MyInvocation.MyCommand.Name)] consider to add -LDAPcli tracing" Cyan
	LogInfoFile " starting dummy ADS_GPeditTrace.etl"
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectADS_GPeditLog {
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "[$($MyInvocation.MyCommand.Name)] resetting GPedit Debug Reg Key to default"
	FwDeleteRegValue "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" "GPEditDebugLevel"
	FwDeleteRegValue "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" "GPTextDebugLevel"
	LogInfo "[$($MyInvocation.MyCommand.Name)]  collecting debug GPedit.log into debug\usermode\"
	#pushd %windir%\debug\usermode
	# FOR /F "usebackq delims==" %%i IN (`dir /B %windir%\debug\usermode\GPedit*.*`) DO ( Copy /y %%i $global:LogFolder\$($LogPrefix)%%i)
	#popd
	$Commands = @(
		"xcopy /e/y $env:WinDir\debug\usermode\*.* $global:LogFolder\debug\usermode\ "
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	EndFunc $MyInvocation.MyCommand.Name
}

function ADS_GPmgmtPreStart {
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "[$($MyInvocation.MyCommand.Name)] adding Group Policy Management Console Reg Debug keys"
	FwAddRegValue "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Diagnostics" "GPMgmtTraceLevel" "REG_DWORD" "0x2"
	FwAddRegValue "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Diagnostics" "GPMgmtLogFileOnly" "REG_DWORD" "0x1"
	LogInfoFile " starting dummy ADS_GPmgmtTrace.etl"
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectADS_GPmgmtLog {
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "[$($MyInvocation.MyCommand.Name)] resetting GPmgmt Reg Keys to default"
	FwDeleteRegValue "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Diagnostics" "GPMgmtTraceLevel"
	FwDeleteRegValue "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Diagnostics" "GPMgmtLogFileOnly"
	LogInfo "[$($MyInvocation.MyCommand.Name)] collecting debug $env:temp\GPmgmt.log"
	$Commands = @(
		"xcopy /y $env:temp\GPmgmt*.* $global:LogFolder\GPmgmt\ "
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	EndFunc $MyInvocation.MyCommand.Name
}

function ADS_GPsvcPreStart {
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "[$($MyInvocation.MyCommand.Name)] adding Group Policy Processing Reg Debug key: GPSvcDebugLevel=0x30002"
	if (!(Test-Path -Path $env:SystemRoot\debug\usermode)){FwCreateFolder $env:SystemRoot\debug\usermode}
	FwAddRegValue "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Diagnostics" "GPSvcDebugLevel" "REG_DWORD" "0x30002"
	FwAddRegValue "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Diagnostics" "RunDiagnosticLoggingGlobal" "REG_DWORD" "0x1"
	$Commands = @( "NLTEST /DbFlag:0x2EFFFFFF | Out-File -Append $global:ErrorLogFile")
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	FwAddRegItem @("GPsvc") _Start_ 
	LogInfoFile " starting dummy ADS_GPsvcTrace.etl"
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectADS_GPsvcLog {
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "[$($MyInvocation.MyCommand.Name)] resetting GPsvc Reg Keys to default"
	FwDeleteRegValue "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Diagnostics" "GPSvcDebugLevel"
	FwDeleteRegValue "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Diagnostics" "RunDiagnosticLoggingGlobal"
	$Commands = @( "NLTEST /DbFlag:0x0 | Out-File -Append $global:ErrorLogFile")
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	LogInfo "[$($MyInvocation.MyCommand.Name)] collecting debug GPsvc.log"
	# call :doCmd Copy /y %SystemRoot%\debug\usermode\GPsvc.* $global:LogFolder\$($LogPrefix)GPsvc.*	
	$Commands = @(
		"xCopy /y $env:SystemRoot\debug\usermode\GPsvc.* $global:LogFolder\GPsvc\ "
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	FwAddRegItem @("GPsvc","Print") _Stop_ 
	$EvtLogsGPsvc | ForEach-Object { FwAddEvtLog $_ _Stop_} 
	EndFunc $MyInvocation.MyCommand.Name
}

function CollectADS_GroupPolicyLog {
	EnterFunc $MyInvocation.MyCommand.Name
	$EvtLogsGPsvc | ForEach-Object { FwAddEvtLog $_ _Stop_} 
	EndFunc $MyInvocation.MyCommand.Name
}

function CollectADS_LDAPsrvLog {
	EnterFunc $MyInvocation.MyCommand.Name
	$EvtLogsLDAPsrv | ForEach-Object { FwAddEvtLog $_ _Stop_} 
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectADS_ProfileLog {
	EnterFunc $MyInvocation.MyCommand.Name
	FwAddRegItem @("Print") _Stop_ 
	$EvtLogsGPsvc | ForEach-Object { FwAddEvtLog $_ _Stop_} 
	EndFunc $MyInvocation.MyCommand.Name
}

Function CollectADS_PerfLog{
	# invokes external script until fully integrated into TSSv2
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "[$($MyInvocation.MyCommand.Name)] . calling tss_ADPerfDataCollection.ps1"
	.\scripts\tss_ADPerfDataCollection.ps1 -DataPath $global:LogFolder -AcceptEula
	LogInfo "[$($MyInvocation.MyCommand.Name)] . Done tss_ADPerfDataCollection.ps1"
    EndFunc $MyInvocation.MyCommand.Name
}

function ADS_NetlogonPreStart {
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "[$($MyInvocation.MyCommand.Name)] .. Enabling Netlogon service debug log DbFlag:$global:NetLogonFlag"
	FwAddRegValue "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" "DbFlag" "REG_DWORD" "$global:NetLogonFlag"
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectADS_NetlogonLog {
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "[$($MyInvocation.MyCommand.Name)] .. Disabling Netlogon service debug log, copying $env:SystemRoot\debug"
	FwAddRegValue "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" "DbFlag" "REG_DWORD" "0x0"
	$Commands = @(
			"xcopy /i/q/y $env:SystemRoot\debug\netlogon*.* $global:LogFolder\WinDir-debug"
		)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	EndFunc $MyInvocation.MyCommand.Name
}
#endregion traces_switches_functions


#region scenarios_functions

# -------------- SCENARIOS ---------------


# -------------- ADS_AccountLockout SCENARIO ---------------

function ADS_AccountLockoutScenarioPreStart
{
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] .. started"

	global:FwEventLogsSet "Security" "true" "false" "true" "102400000"
	
	# better use FwAuditPolSet function: FwAuditPolSet "AccountLockout" @('"Logon","Logoff","Account Lockout","Special Logon","Other Logon/Logoff Events","User Account Management","Kerberos Service Ticket Operations","Other Account Logon events","Kerberos Authentication Service","Credential Validation"')
	auditpol /set /subcategory:"Logon" /success:enable /failure:enable 2>&1 | Out-Null
	auditpol /set /subcategory:"Logoff" /success:enable /failure:enable 2>&1 | Out-Null
	auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable 2>&1 | Out-Null
	auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable 2>&1 | Out-Null
	auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable 2>&1 | Out-Null
	auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable 2>&1 | Out-Null
	auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable 2>&1 | Out-Null
	auditpol /set /subcategory:"Other Account Logon events" /success:enable /failure:enable 2>&1 | Out-Null
	auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable 2>&1 | Out-Null
	auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable 2>&1 | Out-Null
		
	# **Netlogon logging**
	nltest /dbflag:0x2EFFFFFF 2>&1 | Out-Null
	EndFunc $MyInvocation.MyCommand.Name
}
function ADS_AccountLockoutPreStart{
	ADS_AccountLockoutScenarioPreStart
}

function ADS_AccountLockoutScenarioPostStop
{
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] .. started"
	# *** Disable logging
	
	# better use FwAuditPolUnSet function: FwAuditPolSet "AccountLockout" @('"Logon","Logoff","Account Lockout","Special Logon","Other Logon/Logoff Events","User Account Management","Kerberos Service Ticket Operations","Other Account Logon events","Kerberos Authentication Service","Credential Validation"')
	auditpol /set /subcategory:"Logon" /success:disable /failure:disable 2>&1 | Out-Null
	auditpol /set /subcategory:"Logoff" /success:disable /failure:disable 2>&1 | Out-Null
	auditpol /set /subcategory:"Account Lockout" /success:disable /failure:disable 2>&1 | Out-Null
	auditpol /set /subcategory:"Special Logon" /success:disable /failure:disable 2>&1 | Out-Null
	auditpol /set /subcategory:"Other Logon/Logoff Events" /success:disable /failure:disable 2>&1 | Out-Null
	auditpol /set /subcategory:"User Account Management" /success:disable /failure:disable 2>&1 | Out-Null
	auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:disable /failure:disable 2>&1 | Out-Null
	auditpol /set /subcategory:"Other Account Logon events" /success:disable /failure:disable 2>&1 | Out-Null
	auditpol /set /subcategory:"Kerberos Authentication Service" /success:disable /failure:disable 2>&1 | Out-Null
	auditpol /set /subcategory:"Credential Validation" /success:disable /failure:disable 2>&1 | Out-Null

	nltest /dbflag:0x0  2>&1 | Out-Null

	global:FwEventLogsSet "Security" "false" "" "" ""

	EndFunc $MyInvocation.MyCommand.Name
}
function ADS_AccountLockoutPostStop{
	ADS_AccountLockoutScenarioPostStop
}


function CollectADS_AccountLockoutScenarioLog
{
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] .. started"	

	wevtutil.exe export-log "Security" "$($PrefixTime)Security.evtx" /overwrite:true  2>&1 | Out-Null
	wevtutil epl System "$($PrefixTime)System.evtx" /overwrite:true 2>&1 | Out-Null
	wevtutil epl Application "$($PrefixTime)Application.evtx" /overwrite:true 2>&1 | Out-Null

	$SourceDestinationPaths = New-Object 'System.Collections.Generic.List[Object]'
	$SourceDestinationPaths = @(  #source (* wildcard is supported) and destination
		@("$($env:windir)\debug\Netlogon.*", "$global:LogFolder"),	#this will copy test1.txt to destination file name and add logprefix
		@("$($env:windir)\system32\Lsass.log", "$($PrefixTime)Lsass.log"),
		@("$($env:windir)\debug\Lsp.*", "$global:LogFolder")
	)

	global:FwCopyFiles $SourceDestinationPaths 
	
	Get-ChildItem env:* |  Out-File -FilePath "$($PrefixTime)env.txt" 2>&1 | Out-Null
	FwListProcsAndSvcs
	#Get-Process | Out-File -FilePath "$($PrefixTime)stop-tasklist.txt" 2>&1 | Out-Null

	LogInfoFile "CollectADS_AccountLockoutScenarioLog completed"
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectADS_AccountLockoutLog{
	CollectADS_AccountLockoutScenarioLog
}

<#
function RunADS_AccountLockoutScenarioDiag
{
	#EnterFunc $MyInvocation.MyCommand.Name
	#LogInfoFile "[$($MyInvocation.MyCommand.Name)] .. started"
	#EndFunc $MyInvocation.MyCommand.Name
}
#>


# -------------- ADS_Basic SCENARIO ---------------

function ADS_BasicScenarioPreStart
{
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] .. started"

	$PreTraceLogs = $global:LogFolder + "\PreTraceLogs"
	if (!(Test-Path $PreTraceLogs)) {FwCreateFolder $PreTraceLogs}
	if (!(Test-Path -Path $env:SystemRoot\debug\usermode)){FwCreateFolder $env:SystemRoot\debug\usermode}

	logman query * -ets > "$($PreTraceLogs)\$($global:LogPrefix)running-etl-providers.txt" 2>&1 | Out-Null

	# Event Logs

	#Event Log - Export Log
	$EventLogExportLogList = New-Object 'System.Collections.Generic.List[Object]'
	$EventLogExportLogList = @(  #LogName, filename, overwrite
		@("Microsoft-Windows-CAPI2/Operational", "$($PreTraceLogs)\$($global:LogPrefix)Capi2_Oper.evtx", "true"),
		@("Microsoft-Windows-Kerberos/Operational", "$($PreTraceLogs)\$($global:LogPrefix)Kerberos_Oper.evtx", "true"),
		@("Microsoft-Windows-Kerberos-Key-Distribution-Center/Operational", "$($PreTraceLogs)\$($global:LogPrefix)Kdc_Oper.evtx", "true"),
		@("Microsoft-Windows-Kerberos-KdcProxy/Operational", "$($PreTraceLogs)\$($global:LogPrefix)Kdc_Proxy_Oper.evtx", "true"),
		@("Microsoft-Windows-WebAuthN/Operational", "$($PreTraceLogs)\$($global:LogPrefix)WebAuthN_Oper.evtx", "true"),
		@("Microsoft-Windows-WebAuth/Operational", "$($PreTraceLogs)\$($global:LogPrefix)WebAuth_Oper.evtx", "true"),
		@("Microsoft-Windows-Biometrics/Operational", "$($PreTraceLogs)\$($global:LogPrefix)WinBio_oper.evtx", "true"),
		@("Microsoft-Windows-HelloForBusiness/Operational", "$($PreTraceLogs)\$($global:LogPrefix)Hfb_Oper.evtx", "true"),
		@("Microsoft-Windows-CertPoleEng/Operational", "$($PreTraceLogs)\$($global:LogPrefix)CertPoleEng_Oper.evtx", "true")
	)
	ForEach ($EventLog in $EventLogExportLogList){
		global:FwExportSingleEventLog $EventLog[0] $EventLog[1] $EventLog[2] 
	}


	#Event Log - Set Log - Enable
	$EventLogSetLogListOn = New-Object 'System.Collections.Generic.List[Object]'
	$EventLogSetLogListOn = @(  #LogName, enabled, retention, quiet, MaxSize
		@("Microsoft-Windows-CAPI2/Operational", "true", "false", "true", "102400000"),
		@("Microsoft-Windows-Kerberos/Operational", "true", "false", "true", ""),
		@("Microsoft-Windows-Kerberos-Key-Distribution-Center/Operational", "true", "false", "true", ""),
		@("Microsoft-Windows-Kerberos-KdcProxy/Operational", "true", "false", "true", ""),
		@("Microsoft-Windows-WebAuthN/Operational", "true", "false", "true", ""),
		@("Microsoft-Windows-WebAuth/Operational", "true", "false", "true", ""),
		@("Microsoft-Windows-Biometrics/Operational", "true", "false", "true", ""),
		@("Microsoft-Windows-HelloForBusiness/Operational", "true", "false", "true", ""),
		@("Microsoft-Windows-CertPoleEng/Operational", "true", "false", "true", "")
	)
	ForEach ($EventLog in $EventLogSetLogListOn)
	{
	global:FwEventLogsSet $EventLog[0] $EventLog[1] $EventLog[2] $EventLog[3] $EventLog[4]
	}


	#Event Log - Clear Log
	$EventLogClearLogList = New-Object 'System.Collections.Generic.List[Object]'
	$EventLogClearLogList = @(  #LogName, enabled, retention, quiet, MaxSize
		@("Microsoft-Windows-CAPI2/Operational"),
		@("Microsoft-Windows-Kerberos/Operational")
	)
	ForEach ($EventLog in $EventLogClearLogList)
	{
		global:FwEventLogClear $EventLog[0] 
	}
	
	# Registry

	reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Diagnostics" /f 2>&1 | Out-Null
  

	# *** ENABLE LOGGING VIA REGISTRY ***

	$RegAddValues = New-Object 'System.Collections.Generic.List[Object]'

	$RegAddValues = @(  #RegKey, RegValue, Type, Data
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\NegoExtender\Parameters", "InfoLevel", "REG_DWORD", "0xFFFF"),	# **NEGOEXT**
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\Pku2u\Parameters", "InfoLevel", "REG_DWORD", "0xFFFF"),	# **PKU2U **
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA", "SPMInfoLevel", "REG_DWORD", "0xC43EFF"),	# **LSA**
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA", "LogToFile", "REG_DWORD", "0x1"),	# **LSA**
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA", "NegEventMask", "REG_DWORD", "0xF"),	# **LSA**
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA", "LspDbgInfoLevel", "REG_DWORD", "0x50410800"), # **LSP Logging** Reason: QFE 2022.1B added a new flag and without it we don’t see this final status STATUS_TRUSTED_DOMAIN_FAILURE on RODC
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA", "LspDbgTraceOptions", "REG_DWORD", "0x1"), # **LSP Logging**
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA\Kerberos\Parameters", "LogLevel", "REG_DWORD", "0x1"), # **KERBEROS Logging to SYSTEM event log**
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL", "EventLogging", "REG_DWORD", "0x7"), # **SCHANNEL Logging to SYSTEM event log**
		@("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Diagnostics", "GPSvcDebugLevel", "REG_DWORD", "0x30002"), # **Enabling Group Policy Logging**
		@("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Diagnostics", "FdeployDebugLevel", "REG_DWORD", "0xF"), # **Enabling Folder Redirection Logging**
		@("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}", "ExtensionDebugLevel", "REG_DWORD", "0x2") # **disable Winlogon Logging (Security Client Side Extension) **
	)

	ForEach ($regadd in $RegAddValues)
	{
		global:FwAddRegValue $regadd[0] $regadd[1] $regadd[2] $regadd[3]
	}


	# **Netlogon logging**
	nltest /dbflag:0x2EFFFFFF 2>&1 | Out-Null


	# ** Turn on debug and verbose Cert Enroll event logging **

	Start-Sleep -s 7

	switch ((Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\ProductOptions).ProductType)
	{
	"WinNT" {
			#write-host "WinNT"
			certutil -setreg -f Enroll\Debug 0xffffffe3 2>&1 | Out-Null
		}
	"ServerNT" {
			#write-host "ServerNT, Cert Enroll logging disabled by default"
			certutil -setreg -f Enroll\Debug 0xffffffe3 2>&1 | Out-Null
		}
	"LanmanNT" {
			#write-host "LanmanNT, Cert Enroll logging not disabled by default"
			certutil -setreg -f Enroll\Debug 0xffffffe3 2>&1 | Out-Null
		}
	}



	certutil -setreg ngc\Debug 1 2>&1 | Out-Null
	certutil -setreg Enroll\LogLevel 5 2>&1 | Out-Null

	FwGetDSregCmd
	FwGetTasklist
	FwGetSVC
	FwGetSVCactive
	#tasklist /svc > "$($PreTraceLogs)\$($global:LogPrefix)Tasklist.txt" 2>&1 | Out-Null
	#sc.exe query > "$($PreTraceLogs)\$($global:LogPrefix)Services-config.txt" 2>&1 | Out-Null
	#net start > "$($PreTraceLogs)\$($global:LogPrefix)Services-started.txt" 2>&1 | Out-Null

	FwGetKlist
	#klist > "$($PreTraceLogs)\$($global:LogPrefix)Tickets.txt" 2>&1 | Out-Null
	#klist -li 0x3e7 > "$($PreTraceLogs)\$($global:LogPrefix)Tickets-localsystem.txt" 2>&1 | Out-Null

	$Commands = @(
		"ipconfig /all | Out-File -Append $($PrefixTime)Ipconfig-info.txt"
		"ipconfig /displaydns | Out-File -Append $($PrefixTime)DisplayDns.txt"
		"netstat -ano  | Out-File -Append $($PrefixTime)netstat.txt"
		)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False  

	EndFunc $MyInvocation.MyCommand.Name
}
function ADS_BasicPreStart{
	ADS_BasicScenarioPreStart
}

function ADS_BasicScenarioPostStop
{
	EnterFunc $MyInvocation.MyCommand.Name
	
	$CertinfoCertenroll = $global:LogFolder + "\Certinfo_and_Certenroll"


	#create CertinfoCertenroll in LogFolder
	FwCreateFolder $CertinfoCertenroll


	#tasklist /svc > "$($PrefixTime)Tasklist.txt" 2>&1 | Out-Null
	FwGetKlist
	#klist > "$($PrefixTime)Tickets.txt" 2>&1 | Out-Null
	#klist -li 0x3e7 > "$($PrefixTime)Tickets-localsystem.txt" 2>&1 | Out-Null


	# *** Clean up additional logging

	nltest /dbflag:0x0  2>&1 | Out-Null


	# RegDeleteValues
	$RegDeleteValues = New-Object 'System.Collections.Generic.List[Object]'

	$RegDeleteValues = @(  #RegKey, RegValue
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA", "SPMInfoLevel"),
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA", "LogToFile"),
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA", "NegEventMask"),
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA\NegoExtender\Parameters", "InfoLevel"),
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA\Pku2u\Parameters", "InfoLevel"),
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA", "LspDbgInfoLevel"),
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA", "LspDbgTraceOptions"),
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA\Kerberos\Parameters", "LogLevel"),
		@("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Diagnostics", "GPSvcDebugLevel"),
		@("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Diagnostics", "FdeployDebugLevel") # **Enabling Folder Redirection Logging**
	)
	ForEach ($regdel in $RegDeleteValues)
	{
		global:FwDeleteRegValue $regdel[0] $regdel[1] 
	}

	reg add HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL /v EventLogging /t REG_DWORD /d 1 /f  2>&1 | Out-Null

	reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}" /v ExtensionDebugLevel /t REG_DWORD /d 0 /f  # **disable Winlogon Logging (Security Client Side Extension) **

	# *** Event/Operational logs
	#Event Log - Set Log - Disable
	$EventLogSetLogListOn = New-Object 'System.Collections.Generic.List[Object]'
	$EventLogSetLogListOn = @(  #LogName, enabled, retention, quiet, MaxSize
		@("Microsoft-Windows-CAPI2/Operational", "false", "", "", ""),
		@("Microsoft-Windows-Kerberos/Operational", "false", "", "", ""),
		@("Microsoft-Windows-Kerberos-Key-Distribution-Center/Operational", "false", "", "", ""),
		@("Microsoft-Windows-Kerberos-KdcProxy/Operational", "false", "", "", ""),
		@("Microsoft-Windows-WebAuthN/Operational", "false", "", "", ""),
		@("Microsoft-Windows-WebAuth/Operational", "false", "", "", ""),
		@("Microsoft-Windows-Biometrics/Operational", "false", "", "", ""),
		@("Microsoft-Windows-HelloForBusiness/Operational", "false", "", "", ""),
		@("Microsoft-Windows-CertPoleEng/Operational", "false", "", "", "")
	)
	ForEach ($EventLog in $EventLogSetLogListOn)
	{
	global:FwEventLogsSet $EventLog[0] $EventLog[1] $EventLog[2] $EventLog[3] $EventLog[4]
	}


	#Event Log - Export Log
	$EventLogExportLogList = New-Object 'System.Collections.Generic.List[Object]'
	$EventLogExportLogList = @(  #LogName, filename, overwrite
		@("Microsoft-Windows-CAPI2/Operational", "$($PrefixTime)Capi2_Oper.evtx", "true"),
		@("Microsoft-Windows-Kerberos/Operational", "$($PrefixTime)Kerberos_Oper.evtx", "true"),
		@("Microsoft-Windows-Kerberos-Key-Distribution-Center/Operational", "$($PrefixTime)Kdc_Oper.evtx", "true"),
		@("Microsoft-Windows-Kerberos-KdcProxy/Operational", "$($PrefixTime)Kdc_Proxy_Oper.evtx", "true"),
		@("Microsoft-Windows-WebAuthN/Operational", "$($PrefixTime)WebAuthN_Oper.evtx", "true"),
		@("Microsoft-Windows-WebAuth/Operational", "$($PrefixTime)WebAuth_Oper.evtx", "true"),
		@("Microsoft-Windows-Biometrics/Operational", "$($PrefixTime)WinBio_oper.evtx", "true"),
		@("Microsoft-Windows-HelloForBusiness/Operational", "$($PrefixTime)Hfb_Oper.evtx", "true"),
		@("Microsoft-Windows-CertPoleEng/Operational", "$($PrefixTime)CertPoleEng_Oper.evtx", "true"),
		@("SYSTEM", "$($PrefixTime)System.evtx", "true"),
		@("APPLICATION", "$($PrefixTime)Application.evtx", "true"),
		@("Microsoft-Windows-GroupPolicy/Operational", "$($PrefixTime)GroupPolicy.evtx", "true")
	)
	ForEach ($EventLog in $EventLogExportLogList){
		global:FwExportSingleEventLog $EventLog[0] $EventLog[1] $EventLog[2] 
	}


	#Event Log - Set Log - Enable
	$EventLogSetLogListOn = New-Object 'System.Collections.Generic.List[Object]'
	$EventLogSetLogListOn = @(  #LogName, enabled, retention, quiet, MaxSize
		@("Microsoft-Windows-WebAuthN/Operational", "true", "false", "true", ""),
		@("Microsoft-Windows-Biometrics/Operational", "true", "false", "true", ""),
		@("Microsoft-Windows-HelloForBusiness/Operational", "true", "false", "true", "")
	)
	ForEach ($EventLog in $EventLogSetLogListOn)
	{
	global:FwEventLogsSet $EventLog[0] $EventLog[1] $EventLog[2] $EventLog[3] $EventLog[4]
	}


	wevtutil query-events Application "/q:*[System[Provider[@Name='Microsoft-Windows-CertificateServicesClient-CertEnroll']]]" > "$CertinfoCertenroll\$($global:LogPrefix)CertificateServicesClientLog.xml" 2>&1 | Out-Null
	certutil -policycache "$CertinfoCertenroll\$($global:LogPrefix)CertificateServicesClientLog.xml" > "$CertinfoCertenroll\$($global:LogPrefix)ReadableClientLog.txt" 2>&1 | Out-Null


	# *** NGC
	$Commands = @(
		"certutil -delreg Enroll\Debug"
		"certutil -delreg ngc\Debug"
		"certutil -delreg Enroll\LogLevel"
		"ipconfig /all | Out-File -Append $($PrefixTime)Ipconfig-info.txt"
		"ipconfig /displaydns | Out-File -Append $($PrefixTime)DisplayDns.txt"
		"netstat -ano  | Out-File -Append $($PrefixTime)netstat.txt"
		)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False	

	# *** Netlogon, LSASS, LSP, Netsetup and Gpsvc log
	$SourceDestinationPaths = New-Object 'System.Collections.Generic.List[Object]'
	$SourceDestinationPaths = @(  #source (* wildcard is supported) and destination
		@("$($env:windir)\Ngc*.log", "$global:LogFolder"),	#this will copy all files that match * criteria into dest folder
		@("$($env:windir)\debug\Netlogon.*", "$global:LogFolder"),	#this will copy test1.txt to destination file name and add logprefix
		@("$($env:windir)\system32\Lsass.log", "$($PrefixTime)Lsass.log"),
		@("$($env:windir)\debug\Lsp.*", "$global:LogFolder"),
		@("$($env:windir)\debug\Netsetup.log", "$($PrefixTime)Netsetup.log"),
		@("$($env:windir)\debug\usermode\gpsvc.*", "$global:LogFolder"),
		@("$($env:windir)\CertEnroll.log", "$CertinfoCertenroll\$($global:LogPrefix)CertEnroll-fromWindir.log"), # *** Cert enrolment info
		@("$($env:userprofile)\CertEnroll.log", "$CertinfoCertenroll\$($global:LogPrefix)CertEnroll-fromUserProfile.log"), # *** Cert enrolment info
		@("$($env:LocalAppData)\CertEnroll.log", "$CertinfoCertenroll\$($global:LogPrefix)CertEnroll-fromLocalAppData.log"), # *** Cert enrolment info
		@("$($env:windir)\security\logs\winlogon.log", "$($PrefixTime)Winlogon.log") # *** Winlogon log
	)

	global:FwCopyFiles $SourceDestinationPaths 


	# *** Credman
	cmdkey.exe /list > "$($PrefixTime)Credman.txt"  2>&1 | Out-Null

	# *** Build info 
	$ProductName = $global:OperatingSystemInfo.ProductName
	$CurrentVersion = $global:OperatingSystemInfo.CurrentVersion
	$ReleaseId = $global:OperatingSystemInfo.ReleaseId
	$BuildLabEx = $global:OperatingSystemInfo.BuildLabEx
	$CurrentBuildHex = $global:OperatingSystemInfo.CurrentBuild

	LogInfoFile ($env:COMPUTERNAME + " " + $ProductName + " " + $ReleaseId + " Version:" + $CurrentVersion + " " + $CurrentBuildHex)
	LogInfoFile ("BuildLabEx: " + $BuildLabEx)

	# *** Reg exports
	LogInfo "[$global:TssPhase ADS Stage:] Exporting Reg.keys .. " "gray"
	$RegExportKeyInTxt = New-Object 'System.Collections.Generic.List[Object]'

	$RegExportKeyInTxt = @(  #Key, ExportFile, Format (TXT or REG)
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa", "$($PrefixTime)reg_Lsa.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies", "$($PrefixTime)reg_Policies.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System", "$($PrefixTime)reg_SystemGP.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer", "$($PrefixTime)reg_Lanmanserver.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation", "$($PrefixTime)reg_Lanmanworkstation.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon", "$($PrefixTime)reg_Netlogon.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL", "$($PrefixTime)reg_Schannel.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography", "$($PrefixTime)reg_Cryptography-HKLMControl.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography", "$($PrefixTime)reg_Cryptography-HKLMSoftware.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography", "$($PrefixTime)reg_Cryptography-HKLMSoftware-Policies.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider", "$($PrefixTime)reg_SCardCredentialProviderGP.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication", "$($PrefixTime)reg_Authentication.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Authentication", "$($PrefixTime)reg_Authentication-key-Wow64.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "$($PrefixTime)reg_Winlogon.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Winlogon", "$($PrefixTime)reg_Winlogon-CCS.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc", "$($PrefixTime)reg_KDC.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\KPSSVC", "$($PrefixTime)reg_KDCProxy.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Winbio", "$($PrefixTime)reg_Winbio.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WbioSrvc", "$($PrefixTime)reg_Wbiosrvc.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Biometrics", "$($PrefixTime)reg_Winbio-Policy.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\EAS\Policies", "$($PrefixTime)reg_Eas.txt", "TXT"),
		@("HKEY_CURRENT_USER\SOFTWARE\Microsoft\SCEP", "$($PrefixTime)reg_Scep.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SQMClient", "$($PrefixTime)reg_MachineId.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Policies\PassportForWork", "$($PrefixTime)reg_NgcPolicyIntune.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\PassportForWork", "$($PrefixTime)reg_NgcPolicyGp.txt", "TXT"),
		@("HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\PassportForWork", "$($PrefixTime)reg_NgcPolicyGpUser.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography\Ngc", "$($PrefixTime)reg_NgcCryptoConfig.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\current\device\DeviceLock", "$($PrefixTime)reg_DeviceLockPolicy.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Policies\PassportForWork\SecurityKey ", "$($PrefixTime)reg_FIDOPolicyIntune.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FIDO", "$($PrefixTime)reg_FIDOGp.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Rpc", "$($PrefixTime)reg_RpcGP.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\Parameters", "$($PrefixTime)reg_NTDS.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LDAP", "$($PrefixTime)reg_LdapClient.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard", "$($PrefixTime)reg_DeviceGuard.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions", "$($PrefixTime)reg_GPExtensions.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\SharedPC", "$($PrefixTime)reg_SharedPC.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PasswordLess", "$($PrefixTime)reg_Passwordless.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Authz", "$($PrefixTime)reg_Authz.txt", "TXT")
	)
	ForEach ($regtxtexport in $RegExportKeyInTxt){
		global:FwExportRegKey $regtxtexport[0] $regtxtexport[1] $regtxtexport[2]
	}

	LogInfo "[$global:TssPhase ADS Stage:] 'http show sslcert' .. " "gray"
	netsh http show sslcert > "$($PrefixTime)http-show-sslcert.txt" 2>&1 | Out-Null 
	netsh http show urlacl > "$($PrefixTime)http-show-urlacl.txt" 2>&1 | Out-Null 

	nltest /DOMAIN_TRUSTS /ALL_TRUSTS /V > "$($PrefixTime)trustinfo.txt" 2>&1 | Out-Null 

	$domain = (Get-CimInstance Win32_ComputerSystem).Domain

		switch ((Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\ProductOptions).ProductType)
		{
		"WinNT" {
				nltest /sc_query:$domain > "$($PrefixTime)SecureChannel.txt" 2>&1 | Out-Null 
			}
		"ServerNT" {
				nltest /sc_query:$domain > "$($PrefixTime)SecureChannel.txt" 2>&1 | Out-Null 
			}
		"LanmanNT" {
				LogInfo "LanmanNT, skip nltest"
				#certutil -setreg -f Enroll\Debug 0xffffffe3 2>&1 | Out-Null
			}
		}

	# *** Cert info
	LogInfo "[$global:TssPhase ADS Stage:] 'certutil -v' .. " "gray"
	certutil -v -silent -store my > "$CertinfoCertenroll\$($global:LogPrefix)Machine-Store.txt"  2>&1 | Out-Null
	certutil -v -silent -user -store my > "$CertinfoCertenroll\$($global:LogPrefix)User-Store.txt" 2>&1 | Out-Null
	Certutil -v -silent -scinfo > "$CertinfoCertenroll\$($global:LogPrefix)Scinfo.txt" 2>&1 | Out-Null
	certutil -tpminfo > "$CertinfoCertenroll\$($global:LogPrefix)Tpm-Cert-Info.txt" 2>&1 | Out-Null
	certutil -v -silent -user -store my "Microsoft Smart Card Key Storage Provider" > "$CertinfoCertenroll\$($global:LogPrefix)CertMY_SmartCard.txt" 2>&1 | Out-Null
	Certutil -v -silent -user -key -csp "Microsoft Passport Key Storage Provider" > "$CertinfoCertenroll\$($global:LogPrefix)Cert_MPassportKey.txt" 2>&1 | Out-Null
	certutil -v -silent -store "Homegroup Machine Certificates" > "$CertinfoCertenroll\$($global:LogPrefix)Homegroup-Machine-Store.txt" 2>&1 | Out-Null
	certutil -v -enterprise -store NTAuth > "$CertinfoCertenroll\$($global:LogPrefix)NTAuth-store.txt" 2>&1 | Out-Null
	certutil -v -store -enterprise root > "$CertinfoCertenroll\$($global:LogPrefix)Machine-Root-AD-store.txt" 2>&1 | Out-Null
	certutil -v -store root > "$CertinfoCertenroll\$($global:LogPrefix)Machine-Root-Registry-store.txt" 2>&1 | Out-Null
	certutil -v -silent -store -grouppolicy root > "$CertinfoCertenroll\$($global:LogPrefix)Machine-Root-GP-Store.txt" 2>&1 | Out-Null
	certutil -v -store authroot > "$CertinfoCertenroll\$($global:LogPrefix)Machine-Root-ThirdParty-Store.txt" 2>&1 | Out-Null
	certutil -v -store -enterprise ca > "$CertinfoCertenroll\$($global:LogPrefix)Machine-CA-AD-store.txt" 2>&1 | Out-Null
	certutil -v -store ca > "$CertinfoCertenroll\$($global:LogPrefix)Machine-CA-Registry-store.txt" 2>&1 | Out-Null
	certutil -v -silent -store -grouppolicy ca > "$CertinfoCertenroll\$($global:LogPrefix)Machine-CA-GP-Store.txt" 2>&1 | Out-Null
	
	LogInfo "[$global:TssPhase ADS Stage:] 'schtasks' .. " "gray"
	schtasks.exe /query /v > "$($PrefixTime)Schtasks.query.v.txt"  2>&1 | Out-Null
	schtasks.exe /query /xml > "$($PrefixTime)Schtasks.query.xml.txt"  2>&1 | Out-Null

	LogInfo "[$global:TssPhase ADS Stage:] 'Services' .. " "gray"
	FwGetTasklist
	FwGetSVC
	FwGetSVCactive
	#sc.exe query > "$($PrefixTime)Services-config.txt" 2>&1 | Out-Null
	#net start > "$($PrefixTime)Services-started.txt" 2>&1 | Out-Null

	fltmc > "$($PrefixTime)FilterManager.txt" 2>&1 | Out-Null

	LogInfo "[$global:TssPhase ADS Stage:] 'gpresult /h' .. " "gray"
	gpresult /h "$($PrefixTime)GPOresult.html"  2>&1 | Out-Null

	(Get-ChildItem env:*).GetEnumerator() | Sort-Object Name | Out-File -FilePath "$($PrefixTime)Env.txt"

	LogInfo "[$global:TssPhase ADS Stage:] 'FileVersionInfo' .. " "gray"
	$env:COMPUTERNAME + " " + $ProductName + " " + $ReleaseId + " Version:" + $CurrentVersion + " " + $CurrentBuildHex | Out-File -Append "$($PrefixTime)Build.txt"
	"BuildLabEx: " + $BuildLabEx | Out-File -Append "$($PrefixTime)Build.txt"

	$SystemFiles = @(
	"$($env:windir)\System32\kerberos.dll"
	"$($env:windir)\System32\lsasrv.dll"
	"$($env:windir)\System32\netlogon.dll"
	"$($env:windir)\System32\kdcsvc.dll"
	"$($env:windir)\System32\msv1_0.dll"
	"$($env:windir)\System32\schannel.dll"
	"$($env:windir)\System32\dpapisrv.dll"
	"$($env:windir)\System32\basecsp.dll"
	"$($env:windir)\System32\scksp.dll"
	"$($env:windir)\System32\bcrypt.dll"
	"$($env:windir)\System32\bcryptprimitives.dll"
	"$($env:windir)\System32\ncrypt.dll"
	"$($env:windir)\System32\ncryptprov.dll"
	"$($env:windir)\System32\cryptsp.dll"
	"$($env:windir)\System32\rsaenh.dll"
	"$($env:windir)\System32\Cryptdll.dll"
	)

	ForEach($File in $SystemFiles){
		if (Test-Path $File -PathType leaf) {
			$FileVersionInfo = (get-Item $File).VersionInfo
			$FileVersionInfo.FileName + ",  " + $FileVersionInfo.FileVersion | Out-File -Append "$($PrefixTime)Build.txt"
		}
	}		
  
	LogInfo "[$global:TssPhase ADS Stage:] 'Hotfix Info' .. " "gray"  
	Get-CimInstance -Class "win32_quickfixengineering" | Select-Object -Property "Description", "HotfixID", @{Name="InstalledOn"; Expression={([DateTime]($_.InstalledOn)).ToLocalTime()}} | Out-File -Append "$($PrefixTime)Qfes_installed.txt"

	EndFunc $MyInvocation.MyCommand.Name
}
function ADS_BasicPostStop{
	ADS_BasicScenarioPostStop
}

# -------------- ADSAUTH SCENARIO ---------------

function ADS_AuthScenarioPreStart
{
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] .. started"

	#create PreTraceLogs in LogFolder
	$PreTraceLogs = $global:LogFolder + "\PreTraceLogs"
	if (!(Test-Path $PreTraceLogs))
	{
		New-Item -ItemType directory -Path $PreTraceLogs | Out-Null
		LogInfo ($PreTraceLogs + " created") "gray"
	}
	else
	{
		#write-debug ($PreTraceLogs + ' already exists.')
		LogInfo ($PreTraceLogs + " already exists" )
	}

	LogInfo "===== Microsoft CSS Authentication Scripts tracing is starting ====="

	logman query * -ets > "$($PreTraceLogs)\$($global:LogPrefix)running-etl-providers.txt" 2>&1 | Out-Null

	LogInfo "[$global:TssPhase ADS Stage:] 'enable Eventlogs' .. " "gray"
	wevtutil.exe set-log "Microsoft-Windows-CAPI2/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-CAPI2/Operational" "$($PreTraceLogs)\$($global:LogPrefix)Capi2_Oper.evtx" /overwrite:true 2>&1 | Out-Null
	wevtutil.exe clear-log "Microsoft-Windows-CAPI2/Operational" 2>&1 | Out-Null
	wevtutil.exe sl "Microsoft-Windows-CAPI2/Operational" /ms:102400000 2>&1 | Out-Null


	wevtutil.exe set-log "Microsoft-Windows-Kerberos/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null
	wevtutil.exe clear-log "Microsoft-Windows-Kerberos/Operational" 2>&1 | Out-Null


	wevtutil.exe set-log "Microsoft-Windows-Kerberos-Key-Distribution-Center/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null
	# wevtutil.exe clear-log "Microsoft-Windows-Kerberos-Key-Distribution-Center/Operational" 2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-Kerberos-KdcProxy/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null
	# wevtutil.exe clear-log "Microsoft-Windows-Kerberos-KdcProxy/Operational" 2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-WebAuth/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-WebAuthN/Operational" /enabled:false 2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-WebAuthN/Operational" "$($PreTraceLogs)\$($global:LogPrefix)WebAuthn_Oper.evtx" /overwrite:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-WebAuthN/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-CertPoleEng/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null
	wevtutil.exe clear-log "Microsoft-Windows-CertPoleEng/Operational" 2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-IdCtrls/Operational" /enabled:false | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-IdCtrls/Operational" "$($PreTraceLogs)\$($global:LogPrefix)Idctrls_Oper.evtx" /overwrite:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-IdCtrls/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-User Control Panel/Operational" /enabled:false 2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-User Control Panel/Operational" "$($PreTraceLogs)\$($global:LogPrefix)UserControlPanel_Oper.evtx" /overwrite:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-User Control Panel/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-Authentication/AuthenticationPolicyFailures-DomainController" /enabled:true /rt:false /q:true 2>&1 | Out-Null
	# wevtutil.exe clear-log "Microsoft-Windows-Authentication/AuthenticationPolicyFailures-DomainController" 2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-Authentication/ProtectedUser-Client" /enabled:true /rt:false /q:true 2>&1 | Out-Null
	# wevtutil.exe clear-log "Microsoft-Windows-Authentication/ProtectedUser-Client" 2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-Authentication/ProtectedUserFailures-DomainController" /enabled:true /rt:false /q:true 2>&1 | Out-Null
	# wevtutil.exe clear-log "Microsoft-Windows-Authentication/ProtectedUserFailures-DomainController" 2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-Authentication/ProtectedUserSuccesses-DomainController" /enabled:true /rt:false /q:true 2>&1 | Out-Null
	# wevtutil.exe clear-log "Microsoft-Windows-Authentication/ProtectedUserSuccesses-DomainController" 2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-Biometrics/Operational" /enabled:false 2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-Biometrics/Operational" "$($PreTraceLogs)\$($global:LogPrefix)WinBio_oper.evtx" /overwrite:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-Biometrics/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-LiveId/Operational" /enabled:false 2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-LiveId/Operational" "$($PreTraceLogs)\$($global:LogPrefix)LiveId_Oper.evtx" /overwrite:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-LiveId/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-AAD/Analytic" /enabled:true /rt:false /q:true 2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-AAD/Operational" /enabled:false 2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-AAD/Operational" "$($PreTraceLogs)\$($global:LogPrefix)Aad_oper.evtx" /ow:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-AAD/Operational"  /enabled:true /rt:false /q:true 2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-User Device Registration/Admin" /enabled:false 2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-User Device Registration/Admin" "$($PreTraceLogs)\$($global:LogPrefix)UsrDeviceReg_Adm.evtx" /overwrite:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-User Device Registration/Admin" /enabled:true /rt:false /q:true 2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-User Device Registration/Debug" /enabled:true /rt:false /q:true 2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-HelloForBusiness/Operational" /enabled:false 2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-HelloForBusiness/Operational" "$($PreTraceLogs)\$($global:LogPrefix)Hfb_Oper.evtx" /overwrite:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-HelloForBusiness/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-Shell-Core/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-WMI-Activity/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null

	
	wevtutil.exe set-log "Microsoft-Windows-Crypto-DPAPI/Operational" /enabled:false 2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-Crypto-DPAPI/Operational" "$($PreTraceLogs)\$($global:LogPrefix)DPAPI_Oper.evtx" /overwrite:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-Crypto-DPAPI/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null

	LogInfo "[$global:TssPhase ADS Stage:] 'enable logging via Registry' .. " "gray"
	# *** ENABLE LOGGING VIA REGISTRY ***

	# **NEGOEXT**
	reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\NegoExtender\Parameters /v InfoLevel /t REG_DWORD /d 0xFFFF /f 2>&1 | Out-Null

	# **PKU2U **
	reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Pku2u\Parameters /v InfoLevel /t REG_DWORD /d 0xFFFF /f 2>&1 | Out-Null

	# **LSA**
	reg add HKLM\SYSTEM\CurrentControlSet\Control\LSA /v SPMInfoLevel /t REG_DWORD /d 0xC43EFF /f 2>&1 | Out-Null
	reg add HKLM\SYSTEM\CurrentControlSet\Control\LSA /v LogToFile /t REG_DWORD /d 1 /f 2>&1 | Out-Null
	reg add HKLM\SYSTEM\CurrentControlSet\Control\LSA /v NegEventMask /t REG_DWORD /d 0xF /f 2>&1 | Out-Null

	# **LSP Logging**
	reg add HKLM\SYSTEM\CurrentControlSet\Control\LSA /v LspDbgInfoLevel /t REG_DWORD /d 0x50410800 /f 2>&1 | Out-Null
	reg add HKLM\SYSTEM\CurrentControlSet\Control\LSA /v LspDbgTraceOptions /t REG_DWORD /d 0x1 /f 2>&1 | Out-Null

	# **KERBEROS Logging to SYSTEM event log**
	reg add HKLM\SYSTEM\CurrentControlSet\Control\LSA\Kerberos\Parameters /v LogLevel /t REG_DWORD /d 1 /f 2>&1 | Out-Null

	# **SCHANNEL Logging to SYSTEM event log**
	# reg add HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL /v EventLogging /t REG_DWORD /d 7 /f 2>&1 | Out-Null

	
	# **Net Trace** 
	# netsh is part of Diag Framework, ust "-netsh" swicth
	# This is legacy implementation from AUTH
	<#switch ((Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\ProductOptions).ProductType)
	{
	"WinNT" {
			netsh trace start InternetClient persistent=yes traceFile="$($PrefixTime)Netmon.etl" capture=yes capturetype=both maxsize=1024 #2>&1 | Out-Null
		}
	"ServerNT" {
			netsh trace start persistent=yes traceFile="$($PrefixTime)Netmon.etl" capture=yes capturetype=both maxsize=1024 #2>&1 | Out-Null
		}
	"LanmanNT" {
			netsh trace start persistent=yes traceFile="$($PrefixTime)Netmon.etl" capture=yes capturetype=both maxsize=1024 #2>&1 | Out-Null
		}
	}
	#>


	# **WFP - disabled by default 
	# netsh wfp capture start file="$($PrefixTime)wfpdiag.cab" 2>&1 | Out-Null

	# **Netlogon logging**
	nltest /dbflag:0x2EFFFFFF 2>&1 | Out-Null


	# **Enabling Group Policy Loggging**
	if (!(Test-Path -Path $env:SystemRoot\debug\usermode)){FwCreateFolder $env:SystemRoot\debug\usermode}
	
	reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Diagnostics" /f 2>&1 | Out-Null
	reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Diagnostics" /v GPSvcDebugLevel /t REG_DWORD /d 0x30002 /f 2>&1 | Out-Null

	LogInfo "[$global:TssPhase ADS Stage:] 'Turn on debug and verbose Cert Enroll logging' .. " "gray"
	# ** Turn on debug and verbose Cert Enroll  logging **

	Start-Sleep -s 7

	switch ((Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\ProductOptions).ProductType)
	{
	"WinNT" {
			#write-host "WinNT"
			LogInfo "Enabling Certificate Enrolment debug logging..."
			LogInfo "Verbose Certificate Enrolment debug output may be written to this window"
			LogInfo "It is also written to a log file which will be collected when the stop-auth script is run"
			
			certutil -setreg -f Enroll\Debug 0xffffffe3 2>&1 | Out-Null

		}
	"ServerNT" {
			LogInfo "ServerNT, Cert Enroll logging disabled by default"
			#certutil -setreg -f Enroll\Debug 0xffffffe3 2>&1 | Out-Null
		}
	"LanmanNT" {
			LogInfo "LanmanNT, Cert Enroll logging disabled by default"
			#certutil -setreg -f Enroll\Debug 0xffffffe3 2>&1 | Out-Null
		}
	}

	certutil -setreg ngc\Debug 1 2>&1 | Out-Null
	certutil -setreg Enroll\LogLevel 5 2>&1 | Out-Null

	LogInfo "[$global:TssPhase ADS Stage:] 'dsregcmd/tasklist/klist logs' .. " "gray"
	FwGetDSregCmd
	FwGetTasklist
	FwGetSVC
	FwGetSVCactive
	#tasklist /svc > "$($PreTraceLogs)\$($global:LogPrefix)Tasklist.txt" 2>&1 | Out-Null
	#sc.exe query > "$($PreTraceLogs)\$($global:LogPrefix)Services-config.txt" 2>&1 | Out-Null
	#net start > "$($PreTraceLogs)\$($global:LogPrefix)Services-started.txt" 2>&1 | Out-Null

	$Commands = @(
		"ipconfig /all | Out-File -Append $($PrefixTime)Ipconfig-info.txt"
		"ipconfig /displaydns | Out-File -Append $($PrefixTime)DisplayDns.txt"
		"netstat -ano  | Out-File -Append $($PrefixTime)netstat.txt"
		"ipconfig /flushdns"
		)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False  

	FwGetKlist
	#klist > "$($PreTraceLogs)\$($global:LogPrefix)Tickets.txt" 2>&1 | Out-Null
	#klist -li 0x3e7 > "$($PreTraceLogs)\$($global:LogPrefix)Tickets-localsystem.txt" 2>&1 | Out-Null


	LogInfo "===== Microsoft CSS Authentication Scripts started tracing ====="
	EndFunc $MyInvocation.MyCommand.Name
	
}
function ADS_AuthPreStart{
	ADS_AuthScenarioPreStart
}

function ADS_AuthScenarioPostStop
{
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] .. started"

	$SCCMEnrollmentFolder = $global:LogFolder + "\SCCM-enrollment"
	$DeviceManagementMDMFolder = $global:LogFolder + "\DeviceManagement_and_MDM"
	$CertinfoCertenroll = $global:LogFolder + "\Certinfo_and_Certenroll"
	if (!(Test-Path -Path $SCCMEnrollmentFolder)){FwCreateFolder $SCCMEnrollmentFolder}
	if (!(Test-Path -Path $DeviceManagementMDMFolder)){FwCreateFolder $DeviceManagementMDMFolder}
	if (!(Test-Path -Path $CertinfoCertenroll)){FwCreateFolder $CertinfoCertenroll}

	LogInfo "[$global:TssPhase ADS Stage:] 'tasklist / klist' .. " "gray"
	#tasklist /svc > "$($PrefixTime)Tasklist.txt" 2>&1 | Out-Null
	klist > "$($PrefixTime)Tickets.txt" 2>&1 | Out-Null
	klist -li 0x3e7 > "$($PrefixTime)Tickets-localsystem.txt" 2>&1 | Out-Null

	LogInfo "[$global:TssPhase ADS Stage:] 'Clean up additional logging' .. " "gray"
	# *** Clean up additional logging
	reg delete HKLM\SYSTEM\CurrentControlSet\Control\LSA /v SPMInfoLevel /f  2>&1 | Out-Null
	reg delete HKLM\SYSTEM\CurrentControlSet\Control\LSA /v LogToFile /f  2>&1 | Out-Null
	reg delete HKLM\SYSTEM\CurrentControlSet\Control\LSA /v NegEventMask /f  2>&1 | Out-Null
	reg delete HKLM\SYSTEM\CurrentControlSet\Control\LSA\NegoExtender\Parameters /v InfoLevel /f  2>&1 | Out-Null
	reg delete HKLM\SYSTEM\CurrentControlSet\Control\LSA\Pku2u\Parameters /v InfoLevel /f  2>&1 | Out-Null
	reg delete HKLM\SYSTEM\CurrentControlSet\Control\LSA /v LspDbgInfoLevel /f  2>&1 | Out-Null
	reg delete HKLM\SYSTEM\CurrentControlSet\Control\LSA /v LspDbgTraceOptions /f  2>&1 | Out-Null
	reg delete HKLM\SYSTEM\CurrentControlSet\Control\LSA\Kerberos\Parameters /v LogLevel /f  2>&1 | Out-Null
	reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Diagnostics" /v GPSvcDebugLevel /f  2>&1 | Out-Null
	nltest /dbflag:0x0  2>&1 | Out-Null

	# reg add HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL /v EventLogging /t REG_DWORD /d 1 /f  2>&1 | Out-Null

	LogInfo "[$global:TssPhase ADS Stage:] 'Event/Operational logs' .. " "gray"
	# *** Event/Operational logs

	wevtutil.exe set-log "Microsoft-Windows-CAPI2/Operational" /enabled:false  2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-CAPI2/Operational" "$($PrefixTime)Capi2_Oper.evtx" /overwrite:true  2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-Kerberos/Operational" /enabled:false  2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-Kerberos/Operational" "$($PrefixTime)Kerb_Oper.evtx" /overwrite:true  2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-Kerberos-key-Distribution-Center/Operational" /enabled:false  2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-Kerberos-key-Distribution-Center/Operational" "$($PrefixTime)Kdc_Oper.evtx" /overwrite:true  2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-Kerberos-KdcProxy/Operational" /enabled:false  2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-Kerberos-KdcProxy/Operational" "$($PrefixTime)KdcProxy_Oper.evtx" /overwrite:true  2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-WebAuth/Operational" /enabled:false  2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-WebAuth/Operational" "$($PrefixTime)WebAuth_Oper.evtx" /overwrite:true  2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-WebAuthN/Operational" /enabled:false  2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-WebAuthN/Operational" "$($PrefixTime)WebAuthn_Oper.evtx" /overwrite:true  2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-WebAuthN/Operational" /enabled:true /rt:false /q:true  2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-CertPoleEng/Operational" /enabled:false  2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-CertPoleEng/Operational" "$($PrefixTime)Certpoleng_Oper.evtx" /overwrite:true  2>&1 | Out-Null

	LogInfo "[$global:TssPhase ADS Stage:] 'Eventlog: CertificateServicesClient-CertEnroll' .. (please be patient)" "gray"
	wevtutil query-events Application "/q:*[System[Provider[@Name='Microsoft-Windows-CertificateServicesClient-CertEnroll']]]" > "$CertinfoCertenroll\$($global:LogPrefix)CertificateServicesClientLog.xml" 2>&1 | Out-Null
	certutil -policycache "$CertinfoCertenroll\$($global:LogPrefix)CertificateServicesClientLog.xml" > "$CertinfoCertenroll\$($global:LogPrefix)ReadableClientLog.txt" 2>&1 | Out-Null #we# ToDo: this step loops on my machine Waltere-VDI

	wevtutil.exe set-log "Microsoft-Windows-IdCtrls/Operational" /enabled:false  2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-IdCtrls/Operational" "$($PrefixTime)Idctrls_Oper.evtx" /overwrite:true  2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-IdCtrls/Operational" /enabled:true /rt:false /q:true  2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-User Control Panel/Operational"  /enabled:false  2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-User Control Panel/Operational" "$($PrefixTime)UserControlPanel_Oper.evtx" /overwrite:true  2>&1 | Out-Null
	# wevtutil.exe set-log "Microsoft-Windows-User Control Panel/Operational" /enabled:true /rt:false /q:true  2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-Authentication/AuthenticationPolicyFailures-DomainController" /enabled:false  2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-Authentication/AuthenticationPolicyFailures-DomainController" "$($PrefixTime)Auth_Policy_Fail_DC.evtx" /overwrite:true  2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-Authentication/ProtectedUser-Client" /enabled:false  2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-Authentication/ProtectedUser-Client" "$($PrefixTime)Auth_ProtectedUser_Client.evtx" /overwrite:true  2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-Authentication/ProtectedUserFailures-DomainController" /enabled:false  2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-Authentication/ProtectedUserFailures-DomainController" "$($PrefixTime)Auth_ProtectedUser_Fail_DC.evtx" /overwrite:true  2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-Authentication/ProtectedUserSuccesses-DomainController" /enabled:false  2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-Authentication/ProtectedUserSuccesses-DomainController" "$($PrefixTime)Auth_ProtectedUser_Success_DC.evtx" /overwrite:true  2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-Biometrics/Operational" /enabled:false  2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-Biometrics/Operational" "$($PrefixTime)WinBio_oper.evtx" /overwrite:true  2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-Biometrics/Operational" /enabled:true /rt:false /q:true  2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-LiveId/Operational" /enabled:false  2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-LiveId/Operational" "$($PrefixTime)LiveId_Oper.evtx" /overwrite:true  2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-LiveId/Operational" /enabled:true /rt:false /q:true  2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-AAD/Analytic" /enabled:false  2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-AAD/Analytic" "$($PrefixTime)Aad_Analytic.evtx" /overwrite:true  2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-AAD/Operational" /enabled:false  2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-AAD/Operational" "$($PrefixTime)Aad_Oper.evtx" /overwrite:true  2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-AAD/Operational"  /enabled:true /rt:false /q:true  2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-User Device Registration/Debug" /enabled:false  2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-User Device Registration/Debug" "$($PrefixTime)UsrDeviceReg_Dbg.evtx" /overwrite:true  2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-User Device Registration/Admin" /enabled:false  2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-User Device Registration/Admin" "$($PrefixTime)UsrDeviceReg_Adm.evtx" /overwrite:true  2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-User Device Registration/Admin" /enabled:true /rt:false /q:true  2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-HelloForBusiness/Operational" /enabled:false  2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-HelloForBusiness/Operational" "$($PrefixTime)Hfb_Oper.evtx" /overwrite:true  2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-HelloForBusiness/Operational" /enabled:true /rt:false /q:true  2>&1 | Out-Null

	wevtutil.exe export-log SYSTEM "$($PrefixTime)System.evtx" /overwrite:true  2>&1 | Out-Null
	wevtutil.exe export-log APPLICATION "$($PrefixTime)Application.evtx" /overwrite:true  2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-Shell-Core/Operational" /enabled:false  2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-Shell-Core/Operational" "$($PrefixTime)ShellCore_Oper.evtx" /overwrite:true  2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-Shell-Core/Operational" /enabled:true /rt:false /q:true  2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-WMI-Activity/Operational" /enabled:false  2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-WMI-Activity/Operational" "$($PrefixTime)WMI-Activity_Oper.evtx" /overwrite:true  2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-WMI-Activity/Operational" /enabled:true /rt:false /q:true  2>&1 | Out-Null

	wevtutil.exe export-log "Microsoft-Windows-GroupPolicy/Operational" "$($PrefixTime)GroupPolicy.evtx" /overwrite:true  2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-Crypto-DPAPI/Operational" /enabled:false 2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-Crypto-DPAPI/Operational" "$($PrefixTime)DPAPI_Oper.evtx" /overwrite:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-Crypto-DPAPI/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null

	LogInfo "[$global:TssPhase ADS Stage:] 'dsregcmd' .. " "gray"
	# *** NGC
	FwGetDSregCmd
	certutil -delreg Enroll\Debug  2>&1 | Out-Null
	certutil -delreg ngc\Debug  2>&1 | Out-Null
	certutil -delreg Enroll\LogLevel  2>&1 | Out-Null
	Copy-Item -Path "$($env:windir)\Ngc*.log" -Destination "$global:LogFolder" -Force 2>&1 | Out-Null
	Get-ChildItem -Path "$global:LogFolder" -Filter "Ngc*.log" | Rename-Item -NewName {$global:LogPrefix + $_.Name}



	# *** netsh wfp capture stop
	#netsh is part of TSSv2 Framework, this is AUTH script specific
	<#
	write-host ""
	write-host "Stopping Network Trace and merging"
	write-host "This may take some time depending on the size of the network capture , please wait...."
	write-host ""

	netsh trace stop  2>&1 | Out-Null
	#>
 
	$Commands = @(
		"ipconfig /all | Out-File -Append $($PrefixTime)Ipconfig-info.txt"
		"ipconfig /displaydns | Out-File -Append $($PrefixTime)DisplayDns.txt"
		"netstat -ano  | Out-File -Append $($PrefixTime)netstat.txt"
		)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False  

	# netsh wfp capture stop

	# *** Netlogon, LSASS, LSP, Netsetup and Gpsvc log

	Copy-Item -Path "$($env:windir)\debug\Netlogon.*" -Destination "$global:LogFolder" -Force 2>&1 | Out-Null
	Get-ChildItem -Path "$global:LogFolder" -Filter "Netlogon.*" | Rename-Item -NewName {$global:LogPrefix + $_.Name}
	Copy-Item -Path "$($env:windir)\system32\Lsass.log" -Destination "$($PrefixTime)Lsass.log" -Force 2>&1 | Out-Null
	Copy-Item -Path "$($env:windir)\debug\Lsp.*" -Destination "$global:LogFolder" -Force 2>&1 | Out-Null
	Get-ChildItem -Path "$global:LogFolder" -Filter "Lsp.*" | Rename-Item -NewName {$global:LogPrefix + $_.Name}
	Copy-Item -Path "$($env:windir)\debug\Netsetup.log" -Destination "$($PrefixTime)Netsetup.log" -Force 2>&1 | Out-Null
	Copy-Item -Path "$($env:windir)\debug\usermode\gpsvc.*" -Destination "$global:LogFolder" -Force 2>&1 | Out-Null
	Get-ChildItem -Path "$global:LogFolder" -Filter "gpsvc.*" | Rename-Item -NewName {$global:LogPrefix + $_.Name}

	# *** Credman
	cmdkey.exe /list > "$($PrefixTime)Credman.txt"  2>&1 | Out-Null

	# *** Build info 

	$ProductName = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion").ProductName
	$CurrentVersion = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion").CurrentVersion
	$ReleaseId = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion").ReleaseId
	$BuildLabEx = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion").BuildLabEx
	$CurrentBuildHex = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion").CurrentBuild
	$UBRHEX = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion").UBR

	LogInfoFile "Computername: $env:COMPUTERNAME ProductName: $ProductName ReleaseId: $ReleaseId Version: $CurrentVersion CurrentBuildHex: $CurrentBuildHex"
	LogInfoFile "BuildLabEx:  $BuildLabEx"

	# *** Reg exports
	LogInfo "[$global:TssPhase ADS Stage:] Exporting Reg.keys .. " "gray"
	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /s > "$($PrefixTime)reg_Lsa.txt" 2>&1 | Out-Null
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies" /s > "$($PrefixTime)reg_Policies.txt" 2>&1 | Out-Null
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /s > "$($PrefixTime)reg_SystemGP.txt" 2>&1 | Out-Null
	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer" /s > "$($PrefixTime)reg_Lanmanserver.txt" 2>&1 | Out-Null
	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation" /s > "$($PrefixTime)reg_Lanmanworkstation.txt" 2>&1 | Out-Null
	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon" /s > "$($PrefixTime)reg_Netlogon.txt" 2>&1 | Out-Null
	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" /s > "$($PrefixTime)reg_Schannel.txt" 2>&1 | Out-Null

	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography" /s > "$($PrefixTime)reg_Cryptography-HKLMControl.txt" 2>&1 | Out-Null 
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography" /s > "$($PrefixTime)reg_Cryptography-HKLMSoftware.txt" 2>&1 | Out-Null 
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography" /s > "$($PrefixTime)reg_Cryptography-HKLMSoftware-Policies.txt" 2>&1 | Out-Null 
	
	reg query "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Cryptography" /s > "$($PrefixTime)reg_Cryptography-HKCUSoftware-Policies.txt" 2>&1 | Out-Null 
	reg query "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Cryptography" /s > "$($PrefixTime)reg_Cryptography-HKCUSoftware.txt" 2>&1 | Out-Null 

	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider" /s > "$($PrefixTime)reg_SCardCredentialProviderGP.txt" 2>&1 | Out-Null 

	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication" /s > "$($PrefixTime)reg_Authentication.txt" 2>&1 | Out-Null 
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Authentication" /s > "$($PrefixTime)reg_Authentication-key-Wow64.txt" 2>&1 | Out-Null 
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /s > "$($PrefixTime)reg_Winlogon.txt" 2>&1 | Out-Null 
	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Winlogon" /s > "$($PrefixTime)reg_Winlogon-CCS.txt" 2>&1 | Out-Null 

	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\IdentityStore" /s > "$($PrefixTime)reg_Idstore-Config.txt" 2>&1 | Out-Null 
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\IdentityCRL" /s >> "$($PrefixTime)reg_Idstore-Config.txt" 2>&1 | Out-Null 
	reg query "HKEY_USERS\.Default\Software\Microsoft\IdentityCRL" /s >> "$($PrefixTime)reg_Idstore-Config.txt" 2>&1 | Out-Null 

	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc" /s > "$($PrefixTime)reg_KDC.txt" 2>&1 | Out-Null 
	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\KPSSVC" /s > "$($PrefixTime)reg_KDCProxy.txt" 2>&1 | Out-Null 

	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CloudDomainJoin" /s > "$($PrefixTime)reg_CDJ.txt" 2>&1 | Out-Null 
	reg query "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\WorkplaceJoin" /s > "$($PrefixTime)reg_WPJ.txt" 2>&1 | Out-Null 
	reg query "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\WorkplaceJoin\AADNGC" /s > "$($PrefixTime)reg_AADNGC.txt" 2>&1 | Out-Null 
	reg query "HKEY_LOCAL_MACHINE\Software\Policies\Windows\WorkplaceJoin" /s > "$($PrefixTime)reg_WPJ-Policy.txt" 2>&1 | Out-Null 

	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Winbio" /s > "$($PrefixTime)reg_Winbio.txt" 2>&1 | Out-Null 
	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WbioSrvc" /s > "$($PrefixTime)reg_Wbiosrvc.txt" 2>&1 | Out-Null 
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Biometrics" /s > "$($PrefixTime)reg_Winbio-Policy.txt" 2>&1 | Out-Null 

	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\EAS\Policies" /s > "$($PrefixTime)reg_Eas.txt" 2>&1 | Out-Null 

	reg query "HKEY_CURRENT_USER\SOFTWARE\Microsoft\SCEP" /s > "$($PrefixTime)reg_Scep.txt" 2>&1 | Out-Null 
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SQMClient" /s > "$($PrefixTime)reg_MachineId.txt" 2>&1 | Out-Null 

	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Policies\PassportForWork" /s > "$($PrefixTime)reg_NgcPolicyIntune.txt" 2>&1 | Out-Null 
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\PassportForWork" /s > "$($PrefixTime)reg_NgcPolicyGp.txt" 2>&1  | Out-Null 
	reg query "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\PassportForWork" /s > "$($PrefixTime)reg_NgcPolicyGpUser.txt" 2>&1 | Out-Null 
	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography\Ngc" /s > "$($PrefixTime)reg_NgcCryptoConfig.txt" 2>&1 | Out-Null  
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\current\device\DeviceLock" /s > "$($PrefixTime)reg_DeviceLockPolicy.txt" 2>&1 | Out-Null 

	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Policies\PassportForWork\SecurityKey " /s > "$($PrefixTime)reg_FIDOPolicyIntune.txt" 2>&1 | Out-Null 
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FIDO" /s > "$($PrefixTime)reg_FIDOGp.txt" 2>&1 | Out-Null 

	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" /s > "$($PrefixTime)reg_RpcGP.txt" 2>&1 | Out-Null 
	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /s > "$($PrefixTime)reg_NTDS.txt" 2>&1 | Out-Null 
	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LDAP" /s > "$($PrefixTime)reg_LdapClient.txt" 2>&1 | Out-Null 
	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard" /s > "$($PrefixTime)reg_DeviceGuard.txt" 2>&1 | Out-Null 

	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\CCMSetup" /s > "$SCCMEnrollmentFolder\$($global:LogPrefix)CCMSetup.txt" 2>&1 | Out-Null 
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\CCM" /s > "$SCCMEnrollmentFolder\$($global:LogPrefix)CCM.txt" 2>&1 | Out-Null 


	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\.NETFramework\v2.0.50727" > "$($PrefixTime)reg_DotNET-TLS.txt" 2>&1 | Out-Null 
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319" >> "$($PrefixTime)reg_DotNET-TLS.txt" 2>&1 | Out-Null 
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" >> "$($PrefixTime)reg_DotNET-TLS.txt" 2>&1 | Out-Null 
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727" >> "$($PrefixTime)reg_DotNET-TLS.txt" 2>&1 | Out-Null 

	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\SharedPC" > "$($PrefixTime)reg_SharedPC.txt" 2>&1 | Out-Null  
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PasswordLess" > "$($PrefixTime)reg_Passwordless.txt" 2>&1 | Out-Null
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Authz" /s > "$($PrefixTime)reg_Authz.txt" 2>&1 | Out-Null 

	LogInfo "[$global:TssPhase ADS Stage:] 'http show sslcert' .. " "gray"
	netsh http show sslcert > "$($PrefixTime)http-show-sslcert.txt" 2>&1 | Out-Null 
	netsh http show urlacl > "$($PrefixTime)http-show-urlacl.txt" 2>&1 | Out-Null 

	nltest /DOMAIN_TRUSTS /ALL_TRUSTS /V > "$($PrefixTime)trustinfo.txt" 2>&1 | Out-Null 

	$domain = (Get-CimInstance Win32_ComputerSystem).Domain

		switch ((Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\ProductOptions).ProductType)
		{
		"WinNT" {
				nltest /sc_query:$domain > "$($PrefixTime)SecureChannel.txt" 2>&1 | Out-Null 
			}
		"ServerNT" {
				nltest /sc_query:$domain > "$($PrefixTime)SecureChannel.txt" 2>&1 | Out-Null 
			}
		"LanmanNT" {
				LogInfo("LanmanNT, skip nltest")
				#certutil -setreg -f Enroll\Debug 0xffffffe3 2>&1 | Out-Null
			}
		}

	# *** Cert info
	LogInfo "Collecting Cert info, please wait...."
	LogInfo "[$global:TssPhase ADS Stage:] 'certutil -v' .. " "gray"
	certutil -v -silent -store my > "$CertinfoCertenroll\$($global:LogPrefix)Machine-Store.txt"  2>&1 | Out-Null
	certutil -v -silent -user -store my > "$CertinfoCertenroll\$($global:LogPrefix)User-Store.txt" 2>&1 | Out-Null
	Certutil -v -silent -scinfo > "$CertinfoCertenroll\$($global:LogPrefix)Scinfo.txt" 2>&1 | Out-Null
	certutil -tpminfo > "$CertinfoCertenroll\$($global:LogPrefix)Tpm-Cert-Info.txt" 2>&1 | Out-Null
	certutil -v -silent -user -store my "Microsoft Smart Card Key Storage Provider" > "$CertinfoCertenroll\$($global:LogPrefix)CertMY_SmartCard.txt" 2>&1 | Out-Null
	Certutil -v -silent -user -key -csp "Microsoft Passport Key Storage Provider" > "$CertinfoCertenroll\$($global:LogPrefix)Cert_MPassportKey.txt" 2>&1 | Out-Null
	certutil -v -silent -store "Homegroup Machine Certificates" > "$CertinfoCertenroll\$($global:LogPrefix)Homegroup-Machine-Store.txt" 2>&1 | Out-Null
	certutil -v -enterprise -store NTAuth > "$CertinfoCertenroll\$($global:LogPrefix)NTAuth-store.txt" 2>&1 | Out-Null
	certutil -v -store -enterprise root > "$CertinfoCertenroll\$($global:LogPrefix)Machine-Root-AD-store.txt" 2>&1 | Out-Null
	certutil -v -store root > "$CertinfoCertenroll\$($global:LogPrefix)Machine-Root-Registry-store.txt" 2>&1 | Out-Null
	certutil -v -silent -store -grouppolicy root > "$CertinfoCertenroll\$($global:LogPrefix)Machine-Root-GP-Store.txt" 2>&1 | Out-Null
	certutil -v -store authroot > "$CertinfoCertenroll\$($global:LogPrefix)Machine-Root-ThirdParty-Store.txt" 2>&1 | Out-Null
	certutil -v -store -enterprise ca > "$CertinfoCertenroll\$($global:LogPrefix)Machine-CA-AD-store.txt" 2>&1 | Out-Null
	certutil -v -store ca > "$CertinfoCertenroll\$($global:LogPrefix)Machine-CA-Registry-store.txt" 2>&1 | Out-Null
	certutil -v -silent -store -grouppolicy ca > "$CertinfoCertenroll\$($global:LogPrefix)Machine-CA-GP-Store.txt" 2>&1 | Out-Null
	certutil -v -template > "$CertinfoCertenroll\$($global:LogPrefix)Cert-template-cache-machine.txt" 2>&1 | Out-Null
	certutil -v -template -user > "$CertinfoCertenroll\$($global:LogPrefix)Cert-template-cache-user.txt" 2>&1 | Out-Null


	LogInfo "[$global:TssPhase ADS Stage:] 'Cert enrolment info' .. " "gray"
	# *** Cert enrolment info
	Copy-Item "$($env:windir)\CertEnroll.log" -Destination "$CertinfoCertenroll\$($global:LogPrefix)CertEnroll-fromWindir.log" -Force 2>&1 | Out-Null
	Copy-Item "$($env:windir)\certmmc.log" -Destination "$CertinfoCertenroll\$($global:LogPrefix)CAConsole.log.log" -Force 2>&1 | Out-Null
	Copy-Item "$($env:windir)\certocm.log" -Destination "$CertinfoCertenroll\$($global:LogPrefix)ADCS-InstallConfig.log" -Force 2>&1 | Out-Null
	Copy-Item "$($env:windir)\certsrv.log" -Destination "$CertinfoCertenroll\$($global:LogPrefix)ADCS-Debug.log" -Force 2>&1 | Out-Null
	Copy-Item "$($env:windir)\CertUtil.log" -Destination "$CertinfoCertenroll\$($global:LogPrefix)CertEnroll-Certutil.log" -Force 2>&1 | Out-Null
	Copy-Item "$($env:windir)\certreq.log" -Destination "$CertinfoCertenroll\$($global:LogPrefix)CertEnroll-Certreq.log" -Force 2>&1 | Out-Null

	Copy-Item "$($env:userprofile)\CertEnroll.log" -Destination "$CertinfoCertenroll\$($global:LogPrefix)CertEnroll-fromUserProfile.log" -Force 2>&1 | Out-Null
	Copy-Item "$($env:LocalAppData)\CertEnroll.log" -Destination "$CertinfoCertenroll\$($global:LogPrefix)CertEnroll-fromLocalAppData.log" -Force 2>&1 | Out-Null


	schtasks.exe /query /v > "$($PrefixTime)Schtasks.query.v.txt"  2>&1 | Out-Null
	schtasks.exe /query /xml > "$($PrefixTime)Schtasks.query.xml.txt"  2>&1 | Out-Null

	# *** Device enrolment information
	LogInfo "Collecting Device enrolment information, please wait...."

	# **SCCM** 
	$SCCMDIR = "$($env:SystemRoot)\CCM\Logs"
	if (!(Test-Path $SCCMDIR))
	{
		Copy-Item -Path "$($SCCMDIR)\CertEnrollAgent*.log" -Destination "$global:LogFolder" -Force 2>&1 | Out-Null
		Get-ChildItem -Path "$global:LogFolder" -Filter "CertEnrollAgent*.log" | Rename-Item -NewName {$global:LogPrefix + $_.Name}
	
		Copy-Item -Path "$($SCCMDIR)\StateMessage*.log" -Destination "$global:LogFolder" -Force 2>&1 | Out-Null
		Get-ChildItem -Path "$global:LogFolder" -Filter "StateMessage*.log" | Rename-Item -NewName {$global:LogPrefix + $_.Name}
	
		Copy-Item -Path "$($SCCMDIR)\DCMAgent*.log" -Destination "$global:LogFolder" -Force 2>&1 | Out-Null
		Get-ChildItem -Path "$global:LogFolder" -Filter "DCMAgent*.log" | Rename-Item -NewName {$global:LogPrefix + $_.Name}
	
		Copy-Item -Path "$($SCCMDIR)\ClientLocation*.log" -Destination "$global:LogFolder" -Force 2>&1 | Out-Null
		Get-ChildItem -Path "$global:LogFolder" -Filter "ClientLocation*.log" | Rename-Item -NewName {$global:LogPrefix + $_.Name}
	
		Copy-Item -Path "$($SCCMDIR)\CcmEval*.log" -Destination "$global:LogFolder" -Force 2>&1 | Out-Null
		Get-ChildItem -Path "$global:LogFolder" -Filter "CcmEval*.log" | Rename-Item -NewName {$global:LogPrefix + $_.Name}
	
		Copy-Item -Path "$($SCCMDIR)\CcmRepair*.log" -Destination "$global:LogFolder" -Force 2>&1 | Out-Null
		Get-ChildItem -Path "$global:LogFolder" -Filter "CcmRepair*.log" | Rename-Item -NewName {$global:LogPrefix + $_.Name}
	
		Copy-Item -Path "$($SCCMDIR)\PolicyAgent.log" -Destination "$SCCMEnrollmentFolder\$($global:LogPrefix)PolicyAgent.log" -Force 2>&1 | Out-Null
	
		Copy-Item -Path "$($SCCMDIR)\CIDownloader.log" -Destination "$SCCMEnrollmentFolder\$($global:LogPrefix)CIDownloader.log" -Force 2>&1 | Out-Null

		Copy-Item -Path "$($SCCMDIR)\PolicyEvaluator.log" -Destination "$SCCMEnrollmentFolder\$($global:LogPrefix)PolicyEvaluator.log" -Force 2>&1 | Out-Null

		Copy-Item -Path "$($SCCMDIR)\DcmWmiProvider*.log" -Destination "$global:LogFolder" -Force 2>&1 | Out-Null
		Get-ChildItem -Path "$global:LogFolder" -Filter "DcmWmiProvider*.log" | Rename-Item -NewName {$global:LogPrefix + $_.Name}
	
		Copy-Item -Path "$($SCCMDIR)\CIAgent*.log" -Destination "$global:LogFolder" -Force 2>&1 | Out-Null
		Get-ChildItem -Path "$global:LogFolder" -Filter "CIAgent*.log" | Rename-Item -NewName {$global:LogPrefix + $_.Name}
	
		Copy-Item -Path "$($SCCMDIR)\CcmMessaging.log" -Destination "$SCCMEnrollmentFolder\$($global:LogPrefix)CcmMessaging.log" -Force 2>&1 | Out-Null
	
		Copy-Item -Path "$($SCCMDIR)\ClientIDManagerStartup.log" -Destination "$SCCMEnrollmentFolder\$($global:LogPrefix)ClientIDManagerStartup.log" -Force 2>&1 | Out-Null	
	
		Copy-Item -Path "$($SCCMDIR)\LocationServices.log" -Destination "$SCCMEnrollmentFolder\$($global:LogPrefix)LocationServices.log" -Force 2>&1 | Out-Null	
	}

	$SCCMDIR = "$($env:SystemRoot)\CCMSetup\Logs"
	if (!(Test-Path $SCCMDIR))
	{
		Copy-Item -Path "$($SCCMDIR)\ccmsetup.log" -Destination "$SCCMEnrollmentFolder\$($global:LogPrefix)ccmsetup.log" -Force 2>&1 | Out-Null
	}

	$SCCMDIR = ""

	# **MDM**
	reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Enrollments" /s > "$DeviceManagementMDMFolder\$($global:LogPrefix)MDMEnrollments.txt" 2>&1 | Out-Null
	reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\EnterpriseResourceManager" /s > "$DeviceManagementMDMFolder\$($global:LogPrefix)MDMEnterpriseResourceManager.txt" 2>&1 | Out-Null
	reg query "HKEY_CURRENT_USER\Software\Microsoft\SCEP" /s > "$DeviceManagementMDMFolder\$($global:LogPrefix)MDMSCEP-User.txt" 2>&1 | Out-Null
	reg query "HKEY_CURRENT_USER\S-1-5-18\Software\Microsoft\SCEP" /s > "$DeviceManagementMDMFolder\$($global:LogPrefix)MDMSCEP-SystemUser.txt" 2>&1 | Out-Null

	
	wevtutil query-events Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin /format:text >"$DeviceManagementMDMFolder\$($global:LogPrefix)DmEventLog.txt" 2>&1  | Out-Null
	
	#DmEventLog.txt and Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider-Admin.txt might contain the same content
	$DiagProvierEntries = wevtutil el 
	foreach ($DiagProvierEntry in $DiagProvierEntries)
	{
		$tempProvider = $DiagProvierEntry.Split('/')
		if ($tempProvider[0] -eq "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider")
		{
			wevtutil qe $($DiagProvierEntry) /f:text /l:en-us > "$DeviceManagementMDMFolder\$($global:LogPrefix)$($tempProvider[0])-$($tempProvider[1]).txt"	2>&1 | Out-Null
		}
	}
	
	LogInfo "[$global:TssPhase ADS Stage:] 'Device configuration' .. " "gray"
	LogInfo "Collecting Device configuration information, please wait...."

	FwGetTasklist
	FwGetSVC
	FwGetSVCactive
	#sc.exe query > "$($PrefixTime)Services-config.txt" 2>&1 | Out-Null
	#net start > "$($PrefixTime)Services-started.txt" 2>&1 | Out-Null
	LogInfo "[$global:TssPhase ADS Stage:] 'fltmc' .. " "gray"
	fltmc > "$($PrefixTime)FilterManager.txt" 2>&1 | Out-Null
	LogInfo "[$global:TssPhase ADS Stage:] 'Whoami' .. " "gray"
	Whoami /all > "$($PrefixTime)whoami.txt" 2>&1 | Out-Null

	LogInfo "[$global:TssPhase ADS Stage:] 'gpresult /h' .. " "gray"
	gpresult /h "$($PrefixTime)GPOresult.html"  2>&1 | Out-Null


	(Get-ChildItem env:*).GetEnumerator() | Sort-Object Name | Out-File -FilePath "$($PrefixTime)Env.txt"

	LogInfo "[$global:TssPhase ADS Stage:] 'FileVersionInfo' .. " "gray"
	$env:COMPUTERNAME + " " + $ProductName + " " + $ReleaseId + " Version:" + $CurrentVersion + " " + $CurrentBuildHex | Out-File -Append "$($PrefixTime)Build.txt"
	"BuildLabEx: " + $BuildLabEx | Out-File -Append "$($PrefixTime)Build.txt"

	$SystemFiles = @(
	"$($env:windir)\System32\kerberos.dll"
	"$($env:windir)\System32\lsasrv.dll"
	"$($env:windir)\System32\netlogon.dll"
	"$($env:windir)\System32\kdcsvc.dll"
	"$($env:windir)\System32\msv1_0.dll"
	"$($env:windir)\System32\schannel.dll"
	"$($env:windir)\System32\dpapisrv.dll"
	"$($env:windir)\System32\basecsp.dll"
	"$($env:windir)\System32\scksp.dll"
	"$($env:windir)\System32\bcrypt.dll"
	"$($env:windir)\System32\bcryptprimitives.dll"
	"$($env:windir)\System32\ncrypt.dll"
	"$($env:windir)\System32\ncryptprov.dll"
	"$($env:windir)\System32\cryptsp.dll"
	"$($env:windir)\System32\rsaenh.dll"
	"$($env:windir)\System32\Cryptdll.dll"
	)

	ForEach($File in $SystemFiles){
		if (Test-Path $File -PathType leaf)
		{
			$FileVersionInfo = (get-Item $File).VersionInfo
			$FileVersionInfo.FileName + ",  " + $FileVersionInfo.FileVersion | Out-File -Append "$($PrefixTime)Build.txt"
		}
	}
	
	LogInfo "[$global:TssPhase ADS Stage:] 'Hotfix Info' .. " "gray"  
	Get-CimInstance -Class "win32_quickfixengineering" | Select-Object -Property "Description", "HotfixID", @{Name="InstalledOn"; Expression={([DateTime]($_.InstalledOn)).ToLocalTime()}} | Out-File -Append "$($PrefixTime)Qfes_installed.txt"

	LogInfoFile "===== Microsoft CSS Authentication Scripts completed tracing ====="
	EndFunc $MyInvocation.MyCommand.Name
} 
function ADS_AuthPostStop{
	ADS_AuthScenarioPostStop
}

function CollectADS_AuthScenarioLog{
	FwExportEventLog "Security" $global:LogFolder -DaysBack 10
}

function CollectADS_AuthLog{
	CollectADS_AuthScenarioLog
}

# -------------- ADSESR SCENARIO ---------------

function ADS_ESRScenarioPreStart
{
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] .. started"
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v BuildLabEx > "$($PrefixTime)build.txt" 2>&1 | Out-Null 

	# -- ** Starting WAM tracing and saving it in .\ESRLogs **

	#set.exe SslDbFlags=0x4000ffff
	$env:SslDbFlags = '0x4000ffff'

	<#
	this is already implemetedin WebAuth and NGC ETL...verify
	set.exe _TRACEGUID.WAM=077b8c4a-e425-578d-f1ac-6fdf1220ff68
	[System.Environment]::SetEnvironmentVariable('_TRACEGUID.WAM','077b8c4a-e425-578d-f1ac-6fdf1220ff68',[System.EnvironmentVariableTarget]::Machine)
	set.exe _TRACEGUID.MSAWamProvider=5836994d-a677-53e7-1389-588ad1420cc5
	set.exe _TRACEGUID.CXH=d0034f5e-3686-5a74-dc48-5a22dd4f3d5b
	set.exe _TRACEGUID.AADWamProvider=4DE9BC9C-B27A-43C9-8994-0915F1A5E24F
	set.exe _TRACEGUID.BackgroundInfra=63b6c2d2-0440-44de-a674-aa51a251b123
	set.exe _TRACEGUID.ResourceManager=4180c4f7-e238-5519-338f-ec214f0b49aa
	set.exe _TRACEGUID.AppModel=EB65A492-86C0-406A-BACE-9912D595BD69
	#>

	wevtutil.exe set-log "Microsoft-Windows-CAPI2/Operational" /e:true /rt:false /q:true  2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-CloudStore/Debug" /e:true /rt:false /q:true  2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-AAD/Analytic" /e:true /rt:false /q:true  2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-AAD/Operational" /e:true /rt:false /q:true  2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-User Device Registration/Debug" /e:true /rt:false /q:true  2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-User Device Registration/Admin" /e:true /rt:false /q:true  2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-PushNotification-Platform/Debug" /e:true /rt:false /q:true  2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-PushNotification-Platform/Admin" /e:true /rt:false /q:true  2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-CAPI2/Operational" /e:true /rt:false /q:true  2>&1 | Out-Null

	# ** Flushing DNS Cache **
	ipconfig /flushdns

	# ** IP Configuration **
	ipconfig /all > "$($PrefixTime)Ipconfig-info.txt" 2>&1 | Out-Null
	#ipconfig /all> .\ipconfig.txt

	# ** Collecting Tasklist output at the time of starting the script **
	FwGetTasklist
	#tasklist /svc > "$($PrefixTime)Tasklist.txt" 2>&1 | Out-Null

	EndFunc $MyInvocation.MyCommand.Name
}
function ADS_ESRPreStart{
	ADS_ESRScenarioPreStart
}

function ADS_ESRScenarioPostStop
{	
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] .. started"
	<#
	this is already implemetedin WebAuth and NGC ETL...verify
	set.exe _TRACEGUID.WAM=077b8c4a-e425-578d-f1ac-6fdf1220ff68
	[System.Environment]::SetEnvironmentVariable('_TRACEGUID.WAM','077b8c4a-e425-578d-f1ac-6fdf1220ff68',[System.EnvironmentVariableTarget]::Machine)
	set.exe _TRACEGUID.MSAWamProvider=5836994d-a677-53e7-1389-588ad1420cc5
	set.exe _TRACEGUID.CXH=d0034f5e-3686-5a74-dc48-5a22dd4f3d5b
	set.exe _TRACEGUID.AADWamProvider=4DE9BC9C-B27A-43C9-8994-0915F1A5E24F
	set.exe _TRACEGUID.BackgroundInfra=63b6c2d2-0440-44de-a674-aa51a251b123
	set.exe _TRACEGUID.ResourceManager=4180c4f7-e238-5519-338f-ec214f0b49aa
	set.exe _TRACEGUID.AppModel=EB65A492-86C0-406A-BACE-9912D595BD69
	#>

	#create CDPLogs in LogFolder
	$CDPLogs = $global:LogFolder + "\CDPlogs"
	if (!(Test-Path $CDPLogs))
	{
		New-Item -ItemType directory -Path $CDPLogs | Out-Null
		#Write-debug ("New log folder" + $CDPLogs + " created")
		LogInfo ($CDPLogs + " created") "gray"
	}
	else
	{
		#write-debug ($CDPLogs + ' already exists.')
		LopInfo ($CDPLogs + " already exists")
	}


	#settingsynchost.exe -loadandrundiagscript .\
	#settingsynchost.exe -loadandrundiagscript $($global:LogFolder)  #settingsynchost.exe is not present on Win11 machine... need to check with ESR script owner
	FwGetDSregCmd

	wevtutil.exe set-log "Microsoft-Windows-CAPI2/Operational" /e:false  2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-CloudStore/Debug" /e:false  2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-AAD/Analytic" /e:false  2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-AAD/Operational" /e:false  2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-User Device Registration/Debug" /e:false  2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-User Device Registration/Admin" /e:false  2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-PushNotification-Platform/Debug" /e:false  2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-PushNotification-Platform/Admin" /e:false  2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-CAPI2/Operational" /e:false  2>&1 | Out-Null


	wevtutil.exe export-log "Microsoft-Windows-AAD/Operational" "$($PrefixTime)aad_oper.evtx" /overwrite:true 2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-AAD/Analytic" "$($PrefixTime)aad_analytic.evtx" /overwrite:true 2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-User Device Registration/Admin" "$($PrefixTime)usrdevicereg_adm.evtx" /overwrite:true 2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-User Device Registration/Debug" "$($PrefixTime)usrdevicereg_dbg.evtx" /overwrite:true 2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-PushNotification-Platform/Admin" "$($PrefixTime)push-notification-platform_adm.evtx" /overwrite:true 2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-PushNotification-Platform/Debug" "$($PrefixTime)push-notification-platform_dbg.evtx" /overwrite:true 2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-CloudStore/Debug" "$($PrefixTime)CDS-Debug.evtx" /overwrite:true 2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-CloudStore/Operational" "$($PrefixTime)CDS-Operational.evtx" /overwrite:true 2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-CAPI2/Operational" "$($PrefixTime)CAPI2.evtx" /overwrite:true 2>&1 | Out-Null

	# - ** Collecting Tasklist output at the time of starting the script **
	FwGetTasklist
	#tasklist /svc > "$($PrefixTime)tasklist-at-stop.txt" 2>&1 | Out-Null

	# -- ** Capture DNS Cache **
	ipconfig /displaydns > "$($PrefixTime)DisplayDns.txt" 2>&1 | Out-Null

	#reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies" /s > "$($PrefixTime)reg_CDPlogs_Policies-key1.txt" 2>&1 | Out-Null 
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies" /s > "$CDPLogs\$($global:LogPrefix)reg_CDPlogs_Policies-key1.txt" 2>&1 | Out-Null 
	
	#reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /s > "$($PrefixTime)reg_CDPlogs_Policies-key2.txt" 2>&1 | Out-Null 
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /s > "$CDPLogs\$($global:LogPrefix)reg_CDPlogs_Policies-key2.txt" 2>&1 | Out-Null 

	#set.exe > env.txt
	(Get-ChildItem env:*).GetEnumerator() | Sort-Object Name | Out-File -FilePath "$($PrefixTime)Env.txt"
	
	EndFunc $MyInvocation.MyCommand.Name
}
function ADS_ESRPostStop{
	ADS_ESRScenarioPostStop
}

function ADS_OCSPPreStart {
	#  https://supportability.visualstudio.com/WindowsDirectoryServices/_wiki/wikis/WindowsDirectoryServices/414016/Workflow-PKI-Server-Online-Responder-(OCSP)
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "Set Debug Flags, running IISreset, restarting OCSP service to activate OCSP service debug logging"
	$Commands = @("$Sys32\certutil.exe -setreg -f Debug 0xffffffe3")
	If(FwIsOsCommandAvailable IISreset.exe){ $Commands += @("$Sys32\IISreset.exe")}
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	if (Get-Service -Name "OCSPsvc" -ErrorAction Ignore) {
		LogInfo "[$($MyInvocation.MyCommand.Name)] restarting Service 'OCSPsvc'"
		Restart-Service -Name "OCSPsvc" -Force
	} else { LogWarn "[$($MyInvocation.MyCommand.Name)] Service 'OCSPsvc' not found"}
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] * OCSP reference: https://technet.microsoft.com/en-us/library/cc770413(v=WS.10).aspx"
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] * IIS Failed Request Tracing: https://www.iis.net/learn/troubleshoot/using-failed-request-tracing/troubleshooting-failed-requests-using-tracing-in-iis-85"
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] * Online Responder http://technet.microsoft.com/en-us/library/cc732526.aspx"
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectADS_OCSPLog{
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "Set Debug Flags, running IISreset, restarting OCSP service to activate OCSP service debug logging"
	$Commands = @("$Sys32\certutil.exe -setreg -f Debug 0xffffffe3")
	If(FwIsOsCommandAvailable IISreset.exe){ $Commands += @("$Sys32\IISreset.exe")}
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False	
	if (Get-Service -Name "OCSPsvc" -ErrorAction Ignore) {
		LogInfo "[$($MyInvocation.MyCommand.Name)] restarting Service 'OCSPsvc'"
		Restart-Service -Name "OCSPsvc" -Force
	} else { LogWarn "[$($MyInvocation.MyCommand.Name)] Service 'OCSPsvc' not found"}
	FwAddRegItem @("OCSP") _Stop_
	if (Test-Path $env:SystemRoot\ServiceProfiles\networkservice\OCSPsvc.log) {
		$SourceDestinationPaths = New-Object 'System.Collections.Generic.List[Object]'
		$SourceDestinationPaths = @(
			@("$env:SystemRoot\ServiceProfiles\networkservice\OCSPsvc.log", "$global:LogFolder\OCSP_serviceprofiles\")
		)
		FwCopyFiles $SourceDestinationPaths -ShowMessage:$False
	}
	if (Test-Path $PrefixTime`OCSP.etl) {
		LogInfo "[$($MyInvocation.MyCommand.Name)] .. Converting OCSP.etl using command: netsh trace convert input=OCSP.etl"
		$Commands = @(
			"netsh trace convert input=$PrefixTime`OCSP.etl | Out-File -append -FilePath $global:ErrorLogFile"
			)
		RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	}
	EndFunc $MyInvocation.MyCommand.Name
}

function CollectADS_SBSLLog {
	CollectNET_SBSLLog
}

function ADS_W32TimePreStart {
	EnterFunc $MyInvocation.MyCommand.Name
	$w32tm_FileLogName = (get-itemproperty HKLM:\SYSTEM\CurrentControlSet\services\W32Time\Config\).FileLogName
	# If $w32tm_FileLogName is null (because FileLogName is not set) then throw an error.
	If ($null -eq $w32tm_FileLogName)	{
		LogInfoFile "[$($MyInvocation.MyCommand.Name)] W32Tm FileLogName registry value is not set. Any previous W32Time debug logging is not enabled."
		} 
	# If $w32tm_FileLogName is populated, check if the path exists and if so, copy the file to TSS directory, prepending the computer name.
	Else {
		LogInfoFile "[$($MyInvocation.MyCommand.Name)] previous W32Tm FileLogName = $w32tm_FileLogName" 
		$SourceDestinationPaths = New-Object 'System.Collections.Generic.List[Object]'
		$SourceDestinationPaths.add(@("$w32tm_FileLogName", "$PrefixTime`W32Time_debug_till-Start.log"))
		FwCopyFiles $SourceDestinationPaths
	}
	LogInfo "[$($MyInvocation.MyCommand.Name)] .. Enabling W32Time service debug logging"
	$Commands = @(
		"w32tm.exe /debug /enable /file:$($PrefixTime)w32tm_debug.txt /size:100000000 /entries:0-300"
		)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False 
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectADS_W32TimeLog {
	EnterFunc $MyInvocation.MyCommand.Name
	# w32tm /query /status for local machine, PDC, and authenticating DC.
	$OutputFile = "$($PrefixTime)W32Time_Query_Status.TXT"

	$Domain = [adsi]("LDAP://RootDSE")
	$AUTHDC_DNSHOSTNAME = $Domain.dnshostname
	$DomainDN = $Domain.defaultNamingContext
	if ($DomainDN) {
		$PDC_NTDS_DN = ([adsi]("LDAP://"+ $DomainDN)).fsmoroleowner
		$PDC_NTDS = [adsi]("LDAP://"+ $PDC_NTDS_DN)
		$PDC = $PDC_NTDS.psbase.get_parent() #_# -ErrorAction SilentlyContinue
	} else { LogInfoFile "[$($MyInvocation.MyCommand.Name)] could not resolve DomainDN ($DomainDN) via LDAP://RootDSE" }
	if ($null -ne $PDC) { $PDC_DNSHOSTNAME = $PDC.dnshostname }

	"[INFO] The following errors are expected to occur under the following conditions: " | Out-File -append -FilePath $OutputFile 
	"   -  'Access is Denied' is expected if TSS was run with an account that does not have local administrative rights on the target machine. " | Out-File -append -FilePath $OutputFile 
	"   -  'The RPC server is unavailable' is expected if Windows Firewall is enabled on the target machine, or the target machine is otherwise unreachable. `n `n " | Out-File -append -FilePath $OutputFile 
	"Output of 'w32tm /query /status /verbose'" | Out-File -append -FilePath $OutputFile 
	"========================================= " | Out-File -append -FilePath $OutputFile 
	cmd /d /c w32tm.exe /query /status /verbose | Out-File -append -FilePath $OutputFile 

	if ($global:ParameterArray -notcontains 'noHang') {  #_# below command might appear hung on some systems
		If ($null -ne $PDC_DNSHOSTNAME) { 
			"`n[INFO] The PDC Emulator for this computer's domain is $PDC_DNSHOSTNAME `n" | Out-File -append -FilePath $OutputFile 
			"Output of 'w32tm /query /computer:$PDC_DNSHOSTNAME /status /verbose'" | Out-File -append -FilePath $OutputFile 
			"=========================================================================== " | Out-File -append -FilePath $OutputFile 
			cmd /d /c w32tm.exe /query /computer:$PDC_DNSHOSTNAME /status /verbose | Out-File -append -FilePath $OutputFile 
			}
		Else {
			"[Error] Unable to determine the PDC Emulator for the domain." | Out-File -append -FilePath $OutputFile 
			}
		If ($null -ne $AUTHDC_DNSHOSTNAME) {
			"`n[INFO] This computer's authenticating domain controller is $AUTHDC_DNSHOSTNAME `n" | Out-File -append -FilePath $OutputFile 
			"Output of 'w32tm /query /computer:$AUTHDC_DNSHOSTNAME /status /verbose'" | Out-File -append -FilePath $OutputFile 
			"=========================================================================== " | Out-File -append -FilePath $OutputFile 
			cmd /d /c w32tm.exe /query /computer:$AUTHDC_DNSHOSTNAME /status /verbose | Out-File -append -FilePath $OutputFile 
			}
		Else {
			"[Error] Unable to determine this computer's authenticating domain controller." | Out-File -append -FilePath $OutputFile 
			}
		$outStripchart = "$($PrefixTime)W32Time_Stripchart.TXT"
		If ($null -ne $PDC_DNSHOSTNAME) {
			"[INFO] The PDC Emulator for this computer's domain is $PDC_DNSHOSTNAME `n" | Out-File -append $outStripchart
			"Output of 'w32tm /stripchart /computer:$PDC_DNSHOSTNAME /samples:5 /dataonly'" | Out-File -append $outStripchart
			"===================================================================================== " | Out-File -append -FilePath $outStripchart 
			cmd /d /c w32tm.exe /stripchart /computer:$PDC_DNSHOSTNAME /samples:5 /dataonly | Out-File -append $outStripchart
			}
		Else {
			"[Error] Unable to determine the PDC Emulator for the domain." | Out-File -append $outStripchart
			}
		If ($null -ne $AUTHDC_DNSHOSTNAME) {
			"`n`n[INFO] This computer's authenticating domain controller is $AUTHDC_DNSHOSTNAME `n" | Out-File -append $outStripchart
			"Output of 'w32tm /stripchart /computer:$AUTHDC_DNSHOSTNAME /samples:5 /dataonly'" | Out-File -append $outStripchart
			"===================================================================================== " | Out-File -append -FilePath $outStripchart 
			cmd /d /c w32tm.exe /stripchart /computer:$AUTHDC_DNSHOSTNAME /samples:5 /dataonly | Out-File -append $outStripchart
			}
		Else {
			"[Error] Unable to determine this computer's authenticating domain controller." | Out-File -append $outStripchart
			}
	}
	
	LogInfo "[$($MyInvocation.MyCommand.Name)] .. Disabling W32Time service debug logging"
	$Commands = @(
		"w32tm.exe /query /status /verbose	| Out-File -Append $PrefixTime`W32Time_query_status_verbose.txt"
		"w32tm.exe /query /configuration	| Out-File -Append $PrefixTime`W32Time_query_configuration.txt"
		"w32tm.exe /query /peers			| Out-File -Append $PrefixTime`W32Time_query_peers.txt"
		"w32tm.exe /query /peers /verbose	| Out-File -Append $PrefixTime`W32Time_query_peers.txt"
		"sc.exe query w32time				| Out-File -Append $PrefixTime`W32Time_Service_Status.txt"
		"sc.exe sdshow w32time				| Out-File -Append $PrefixTime`W32Time_Service_Perms.txt"
		"w32tm.exe /monitor					| Out-File -Append $PrefixTime`W32Time_Monitor.txt"
		"w32tm.exe /testif /qps				| Out-File -Append $PrefixTime`W32Time_TestIf_QPS.txt"
		"w32tm.exe /tz						| Out-File -Append $PrefixTime`W32Time_TimeZone.txt"
		"REG QUERY `"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time`" /s | Out-File -Append $PrefixTime`W32Time_Reg_Key.txt"
		"Get-Acl HKLM:\SYSTEM\CurrentControlSet\services\W32Time | Format-List | Out-File  -Append $PrefixTime`W32Time_Reg_Key_Perms.txt"
		"w32tm.exe /debug /disable"
		)
	RunCommands $LogPrefix $Commands -ThrowException:$False ## -ShowMessage:$False 
	#Get-Acl HKLM:\SYSTEM\CurrentControlSet\services\W32Time | Format-List | Out-File  -Append $PrefixTime`W32Time_Reg_Key_Perms.txt
	EndFunc $MyInvocation.MyCommand.Name
}
#endregion scenarios_functions


#region misc
# ------------------------------------------------------
# ---------- ADS specific add ins / functions ----------
#-------------------------------------------------------

function Export-ADSRegistry
{
[CmdletBinding(DefaultParameterSetName = 'None')]
param
(
	[Parameter(Mandatory)]
	[ValidateNotNullorEmpty()]
	[Array]$RegistryPaths
)

foreach ($path in $RegistryPaths)
	{
	$reg_file = $global:LogFolder + "\registryexport.reg"
		FwExportRegToOneFile "reg" $path $reg_file
	}
}

#endregion misc

#region Registry Key modules for FwAddRegItem
	$global:KeysGPsvc = @("HKLM:Software\Policies\Microsoft")
	$global:KeysPrint = @("HKLM:Software\Microsoft\Windows NT\CurrentVersion\Ports", "HKLM:Software\Policies\Microsoft\Windows NT\Printers", "HKLM:System\CurrentControlSet\Control\Print\Printers")
	$global:KeysKIRMyKnobs = @("HKLM:Software\Microsoft\Windows\CurrentVersion\QualityCompat", "HKLM:System\CurrentControlSet\Control\Session Manager\Memory Management", "HKLM:System\CurrentControlSet\Policies")
	$global:KeysOCSP = @("HKLM:System\CurrentControlSet\Services\OcspSvc")
#endregion Registry Key modules

#region groups of Eventlogs for FwAddEvtLog
	$EvtLogsGPsvc		= @("Microsoft-Windows-GroupPolicy/Operational") 
	$EvtLogsLDAPsrv		= @("Directory Service")
#endregion groups of Eventlogs

Export-ModuleMember -Function * -Cmdlet * -Variable * -Alias *


# SIG # Begin signature block
# MIInzQYJKoZIhvcNAQcCoIInvjCCJ7oCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBm5lFMkX1hYiYp
# JZAAXV936XTBdJ7vzTpPGtTy7lwamaCCDYEwggX/MIID56ADAgECAhMzAAACzI61
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
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgc1tqJNvV
# AFrTZcAEvwaaM+jxaKxTD7Ma42QBJqXPY3EwQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQAklR5OeD1uopX1dZCo8Ma/1yq5o9M5JjftltnA5U8b
# 5sbALY7bRVCA6PaLSd/qFr7WaUqqwzKl/cCSUc3TOujD3qGAnrzbayeC+vwM82Sn
# ya8ABphx+BHh5lULRj34Q1uzBzdNsnDuEO6n6pvJKCDQKKD7nSIbp4L6nW/MTnzF
# vDAMYH1gGDn/6nEfOBHB7McYAz8QycAF96/7PwWaHAdHJvTNkeN4p8Uc0JivVnKe
# 0my4LznXpnXzsOGEATfCXPQXfsPvSlC3L2JcKqeZpL6ufMMyH9LKWhHIbyTaqFBu
# MyTdo0ws7cyuqCF+Sg+8728Ezq4FlppJvFRSNN1eB9XkoYIXLDCCFygGCisGAQQB
# gjcDAwExghcYMIIXFAYJKoZIhvcNAQcCoIIXBTCCFwECAQMxDzANBglghkgBZQME
# AgEFADCCAVkGCyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEIAoCw15d9UK23N5FceIzT7CX0K7BJIE2+rsojwgC
# qt91AgZjT/SUQkkYEzIwMjIxMDI2MTQyOTUxLjg0NVowBIACAfSggdikgdUwgdIx
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
# MC8GCSqGSIb3DQEJBDEiBCCXCtdY2BfImG6AFpIOZiYUvbhpWfBUwgD7bt/iirt1
# 8DCB+gYLKoZIhvcNAQkQAi8xgeowgecwgeQwgb0EINPI93vmozBwBlFxvfr/rElr
# eFPR4ux7vXKx2ni3AfcGMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENB
# IDIwMTACEzMAAAG0+4AIRAXSLfoAAQAAAbQwIgQgilPxWnURWR8jdCkhhDzQ2lRS
# AkvqHPCEg+sB3XSsAa0wDQYJKoZIhvcNAQELBQAEggIAjHAxCS8+911/Hrf2oKYq
# TQXitTxvFHGNMwWqXrz/smGFap0PJyH4QqPiM1LUTg9sHXrsyd6etJWNvzTqzGo1
# 49o+eKL6QBAly+SBVFGoclDlsL+Cwsmb2jT1sFpHyI8JrtiA5F2BE72UrXVX1qmA
# Vpm8W03EVTmFyZqe4KoGLxqAzUNUX+NZXypbaGfyQyG9nGHbaBAjZjw5z+cObsLi
# yV+ZvfUxkH6vqpPP9WP9GF6c+M+ksREUyLa7yWgPCwPSrza4WjoB+xSMgSd9N4g4
# hOtUKtmaq9HUwd+bzU05E3TrdnHhygZLB8U4GX86B4fmuPmRk8QWkk45zgQLrfuF
# ZK6DzqSoGoiO+Ahac856P772OvutoTIRz0Z4/XhgWZb+aK2cWO56UvaFYiFdRmG8
# 3clTvjfS8cdmogkfNNJgcaa32Bmzugc6Foynr7l/G+HSocKf/AJ4WRP1yG7DORsn
# QRog36OKMTe8bK0b3cM5k43HDEEooyb8PQOuo1Uzos0ov932bzd+ZZqqo8+oNphP
# /ZOiXG35FPvu0rn4Ur8LPicdcWWKjnRr97PjkaApp1xPTpTR44cLaa3UmRnJltkR
# h29NZ+eHZTnqVEa87MilgvyyMG5wfOjfBcHJsuxrUNF9bqP7UcSpYayv3/iJQQJ4
# w6HXJxqK0eSsS0ARfzjRsZg=
# SIG # End signature block
