<# File: TSSv2_UEX.psm1
.SYNOPSIS
   UEX module for collecting ETW traces and various custom tracing functionality

.DESCRIPTION
   Define ETW traces for Windows UEX components 
   Add any custom tracing functinaliy for tracing PRF components

.NOTES  
   Authors    : Ryutaro Hayashi (ryhayash@microsoft.com) and Milan Milosavljevic (milanmil@microsoft.com)
   Requires   : PowerShell V4(Supported from Windows 8.1/Windows Server 2012 R2)
   Version    : see $global:TssVerDateUEX

.LINK
	TSSv2 https://internal.support.services.microsoft.com/en-us/help/4619187
	UEX <tbd> 
#>

<# latest changes
  2022.07.27.0 [rh] add Get-StartApps to -UEX_Logon
  2022.06.08.0 [rh] add AssignedAccess registries to -UEX_Logon
  2022.05.31.0 [we] #_# fixed typos, replaced FileVersion with FwFileVersion
  2022.05.29.0 [rh] remove CollectUEX_BasicLog() as it was replaced with -Basiclog
  2022.05.16.0 [we] use FW functions like FwGetMsInfo32, FwCollect_BasicLog
  2022.04.28.0 [rh] add shell CSP provider to UEX_Shell and UEX_DM
  2022.04.19.0 [we] add UEX_PrintEx, UEX_DSC, UEX_Evt, UEX_Tsched dummy providers
  2021.12.29.0 [we] #_# fix #381 for Get-Timezone on Srv2012
  2021.12.08.0 [we] #_# add collect -UEX_PrintEx -> change later to UEX_Print, once SME's decide to remove current UEX_Print component
  2021.10.22.0 [we] #_# call external \scripts\*-collect.ps1 for UEX_DSC, UEX_Evt, UEX_TSched
#>

$global:TssVerDateUEX = "2022.09.14.0"

#region Switches
$UEX_DummyProviders = @(
	'{eb004a05-9b1a-11d4-9123-0050047759bc}' # Dummy tcp for switches without tracing GUID (issue #70)
)
$UEX_PrintExProviders = $UEX_DummyProviders
$UEX_DSCProviders = $UEX_DummyProviders
$UEX_EvtProviders = $UEX_DummyProviders
$UEX_TSchedProviders = $UEX_DummyProviders

#---  RDS PROVIDERS ---#
$UEX_RDSProviders = @(
    '{82A94E1C-C1B3-4E4A-AC87-43BD802E458E}' # KernVC
    '{FA801570-83A9-11DF-B3A9-8C26DFD72085}' # RdCentralDbPlugin
    '{D4199645-41BE-4FD5-9D71-A612C508FDC6}' # RDPApiTrace
    '{D4199645-41BE-4FD5-9D73-A612C508FDC6}' # RDPApiTraceTS
    '{796F204A-44FC-47DF-8AE4-77C210BD5AF4}' # RdpClip
    '{D4199645-41BE-4FD5-9D71-A612C508FDC7}' # RDPEncComTrace
    '{8A99FD17-7D82-45D9-A965-F9A3F9FA85E5}' # RdpFilterTrace
    '{C5615DDA-2DAC-479B-83AB-F18C95601774}' # rdpInput
    '{15D9261C-EFDF-4C4A-8D3C-098A15DC483D}' # RdpNetEmu
    '{6CDD992D-B35C-40A6-AF1E-D727C11DECFD}' # RdvgKmdTrace
    '{84214511-602B-4456-9CB9-7800ED3432F6}' # RdvgmTrace
    '{6AABAEA6-DF19-4528-97D8-3A420CEE69A0}' # RdvgUmd11Trace
    '{2A11472B-451F-4FCA-8590-9724D41C604E}' # RDVVGHelper
    '{C29D637F-AFB5-43F9-96F8-936429371F32}' # RdvVmCore
    '{482F83D3-E8CB-4727-8A28-FC51544C5A28}' # RdvVmTransport
    '{80342309-054F-4E2E-9D3D-FCCFBDCAA92F}' # CtVmtLibTraceGuid
    '{5283D5F6-65B5-425F-A30B-F16C057D6B57}' # termsrv
    '{0B938561-4D72-4312-ACF6-109D34C26148}' # CMProxyGuest
    '{5CE9C675-02A0-4B9D-89E6-77C13EF68E75}' # CMProxyHost
    '{7ADA0B31-F4C2-43F4-9566-2EBDD3A6B604}' # CentralPublishingTrace
    '{1FD4C5A9-27B7-418B-8DFC-216E7FA7B990}' # TSCPubStubTrace
    '{81B84BCE-06B4-40AE-9840-8F04DD7A8DF7}' # TSCPubWmiProvider
    '{BF936B9C-DA45-4494-A236-101FE5A2A51D}' # TSPublishingAppFilteringTrace
    '{0CEA2AEE-1A4C-4DE7-B11F-161F3BE94669}' # TSPublishingIconHelperTrace
    '{E43CAB68-0AB4-4F47-BF30-E61CAC7BBD8A}' # TSPublishingWmiProvider
    '{D2B9C1C5-0C37-47EB-AA79-CD0CF0CE2FA6}' # TSFairShare
    '{4199EE71-D55D-47D7-9F57-34A1D5B2C904}' # TerminalServer-MediaFoundationPlugin
    '{0ED38D2B-4ACC-4E23-A8EC-D0DACBC34637}' # tsprint
    '{FAC7FCCE-62FC-4BE0-BD67-311750B5BCFF}' # XPSClientPlgin
    '{5A966D1C-6B48-11DA-8BDE-F66BAD1E3F3A}' # RDPENDPTrace
    '{C127C1A8-6CEB-11DA-8BDE-F66BAD1E3F3A}' # RDPINITTrace
    '{BFA655DC-6C51-11DA-8BDE-F66BAD1E3F3A}' # RDPSHELLTrace
    '{A1F3B16A-C510-41C1-8B58-E695880F3A80}' # tsscan
    '{ECA5427C-F28F-4942-A54B-7E86DA46BDBE}' # TSUrbUtils
    '{7211AE02-1EB0-454A-88FA-EA16632DCB45}' # TSUsbBusFilter
    '{39A585FF-6C36-492B-93C0-35B71E65A345}' # TSUsbGenericDriver
    '{A0674FB6-BA0D-456F-B079-A2B029D8342C}' # TSUsbHubTrace
    '{48738267-0545-431D-8087-7349127811D0}' # TSUsbRedirectionServiceTrace
    '{600BE610-F0E8-4912-B397-D2CC76060114}' # USBDRTrace
    '{6E530C0D-677F-488B-B163-0415CB65883D}' # VMMWSFilterPluginTrace
    '{70A43AE8-E131-42BD-89E0-23704FB27C6A}' # TSWebProxyTrace
    '{070F54B9-7EB0-4C99-8DFA-2AA8D8AB0D89}' # WorkspaceTrace
    '{3C3E7039-99CF-4446-8D81-4AC5A8560E7B}' # WorkspaceRuntimeTrace(wksprt.exe)
    '{3E3E7039-99DF-4446-8C81-4AD5A8560E7B}' # WorkspaceBrokerAxTrace(wkspbrokerAx.dll)
    '{449E4E69-329E-4EB1-9DDF-809D17A2E0C1}' # sdclient(WS2016 or earlier)
    '{ae8ab061-654e-4d72-9f4b-c799ba919ec8}' # sessionmsg
    '{73BFB78F-12B5-4738-A66C-A77BCD55FA12}' # rdpdr
    '{C14F3000-0B2D-4464-99AC-FA764AF708CF}' # rdpbus
    '{4BDD50B0-BF12-4991-8B11-C455F14289DB}' # rdpvideominiport
    '{73C5EC49-C807-489D-9E45-D36D72235F84}' # UMRDPTrace
    '{2A0A7EC8-5E2B-47AB-B553-32E1C7AEF0EF}' # VmHostAgentTrace
    '{C10870A3-617D-42E9-80C7-1C4BE2709E06}' # VmPluginTrace
    '{0046A6B4-A24C-40D5-B0E6-C8EC031BD82A}' # tsrpc (WS2016 or earlier)
    '{9ED727C4-4AB6-4B66-92D7-2072E87C9124}' # tssrvlic (WS2016 or earlier)
    '{508371B1-7651-4B33-4B33-5884F824BD1B}' # TSVIPCli (WS2016 or earlier)
    '{AE4C5843-A9A3-4EB9-81F3-65D57D250180}' # TSVIPPool(WS2016 or earlier)
    '{432EEF91-C605-482B-83BE-0963604F1397}' # RDVGSMSTrace (WS2012R2 or earlier)
    '{0C38D54D-EF5F-4179-95FA-6D4EDA073000}' # RDVVGHelperSerivce (WS2012R2 or earlier)
    '{3C3E7089-99CF-4446-8D81-4AC5A8560E6A}' # SessionBrokerTrace
    '{59DE359D-EC83-445C-9323-B75E2056D5A5}' # SessionEnv
    '{986CC918-7434-4FAB-B37F-C4BA7AD1E293}' # TSSdJetTrace
    '{70DB53D8-B6F3-428D-AA33-5B2CE56718C5}' # Gateway Client Trace
    '{6F539394-F34F-45FD-B4CA-BD5C547B0BCB}' # Gateway Edge Trace
    '{909ED641-D5EF-4299-B898-F13451A59F50}' # AaTsPPTrace
    '{588F5E4C-6853-4FCB-BD7D-75F926276C20}' # TSAllowTrace
    '{28711274-D721-465E-9C7E-D359422E96CD}' # lsclientservice
    '{9EA2030F-DB66-47EF-BF2C-619CC76F3E1B}' # LSCSHostPolicy
    '{26C7EAC9-9675-43CB-9EF1-B9CD4564595F}' # lscspolicyloader
    '{97166ECD-4F97-442F-A909-9EB9AE6D2458}' # lscsvmbuspipechannel
    '{A489F3D1-F149-4968-BDCE-4F7D93516DA8}' # lserver
    '{F8FCF9E0-535A-4BA6-975F-7AC82FBDC631}' # TLSBrandTrace
    '{5F328364-2E3D-4F73-B099-0D5C839E32A0}' # CredentialsPlugin
    '{DAA6CAF5-6678-43F8-A6FE-B40EE096E00E}' # mstscax.dll
    '{DAA6CAF5-6678-43F8-A6FE-B40EE096E06E}' # mstscax.dll
    '{0C51B20C-F755-48A8-8123-BF6DA2ADC727}' # mstsc.exe
    '{62F277AE-2CCF-4AA9-A8AA-32752200BC18}' # CtDwm
    '{97E97A1E-C0A9-4B8D-87C4-42105A957D7B}' # RdpDwmDirect
    '{6165F3E2-AE38-45D4-9B23-6B4818758BD9}' # TSPkg
    '{37D2C3CD-C5D4-4587-8531-4696C44244C8}' # schannel(schannel.dll)
    '{DC1A94A6-0A1A-433E-B470-3C72353B7309}' # Microsoft.Windows.RemoteDesktop.RAIL.Server.Diagnostics(From RS5)
    '{3ec987dd-90e6-5877-ccb7-f27cdf6a976b}' # Microsoft.Windows.LogonUI.WinlogonRPC
    '{c0ac3923-5cb1-5e37-ef8f-ce84d60f1c74}' # Microsoft.Windows.TSSessionUX
    '{302383D5-5DC2-4BEA-AC7E-4154A1272583}' # Microsoft.Windows.RemoteDesktop.MultiPoint
    '{26771A7F-04D4-4597-BBF6-3AF9F7818B25}' # Microsoft.Windows.RemoteDesktop.Virtualization
    '{F115DDAF-E07E-4B15-9721-427134B41EBA}' # RDP(RDPEncryption)
    '{a8f457b8-a2b8-56cc-f3f5-3c00430937bb}' # RDP(RDPEmulation)
    '{C6FDD8E3-770B-4964-9F0C-227457146B49}' # RDP(SessEnvRpcTelemetry)
    '{89d48904-939f-4177-aad4-2fdb26b8329f}' # Microsoft.Windows.RemoteDesktop.RDSHFarm.UVhd
    '{D9F94C5A-94F8-4CD0-A054-A1EE67A2DA6B}' # Microsoft.Windows.RemoteDesktop.SessionHost
    '{da539211-d525-422a-8a92-bcbe4367159c}' # Microsoft.Windows.RemoteDesktop.RDSLSTelemetry
    '{76de1e7b-74d9-585f-1f85-affa9242808c}' # RDWin32ClientAxTelemetryProvider
    '{61dd194a-b8cb-4de5-a018-4c7f6f9e9988}' # RDP.MSTSCTelemetry
    '{76de1e7b-74d5-575e-1f81-4ffe6a42777b}' # RDWin32ClientAxTelemetryProvider
    '{7756e5a6-21b2-4c40-855e-88cf2b13c7cb}' # RDP.MSTSCAXTelemetry
    '{204AE8F0-42F7-4A13-97CD-B490927CB725}' # Microsoft.Windows.VGPU.RDVGM
    '{EB4AC9D0-AE00-4963-8435-5163ABD35572}' # Microsoft.Windows.RemoteDesktop.Gateway
    '{660cfa71-2a70-4e80-bdf3-f1424919d01c}' # Microsoft.RDS.RdClient.Client.FeedSubscription
    '{55184039-1cbe-4d35-9f9e-85d0075943df}' # Microsoft.RDS.RADC.FeedSubscription
    '{00508371-7651-4b33-4b33-5884f824bd1b}' # TSVIPCli
    '{32817e55-7bfe-45e0-af68-a413fa6e0083}' # TSMSISrv
    '{AE4C5843-A9A3-4EB9-81F3-65D57D250180}' # TSVIPPool
    '{0ba29edf-a2f4-4212-b06b-6d5712210652}' # TSVIPSrv
    '{c0c89c53-dd3f-4782-a78f-5378111a8305}' # RDSNetFairshare
    '{D2E990DA-8504-4702-A5E5-367FC2F823BF}' # AUInstallAgent(From WS2019)
    '{FB1A70CC-BE28-40C1-BD6A-47671538383A}' # Microsoft.Windows.RemoteDesktop.CertManager(From WS2019)
    '{997FB36F-0208-4ED7-865B-E19816C3782D}' # Microsoft.Windows.RemoteDesktop.SessionConfig(From WS2019)
    '{E80ADCF1-C790-4108-8BB9-8A5CA3466C04}' # Microsoft-Windows-TerminalServices-RDP-AvcSoftwareDecoder(From WS2019)
    '{D953B8D8-7EA7-44B1-9EF5-C34AF653329D}' # RDP.Graphics(From WS2019)
    '{78be48bd-5d52-4e39-823d-226cd5551f37}' # RDP.ServerStack(From WS2019)
    '{9512fdbc-24e6-44fa-a8a3-af44d3447216}' # RDP.Graphics(From WS2019)
    '{CA341B3C-B9D2-4D0F-9BD3-D88183596DB9}' # RDP.ServerStack.Diagnostics(From WS2019)
    '{8A633D91-8B07-4AAE-9A00-D07E2AFD29D6}' # RDP.Transport
    '{fdff33ec-70aa-46d3-ba65-7210009fa2a7}' # Microsoft-Windows-Hyper-V-Integration-RDV(vmicrdv.dll)
    '{77B0D57B-97B8-4f42-83B0-4FDA12D3D79A}' # Microsoft-Windows-RemoteApp and Desktop Connection Management
    '{1B8B402D-78DC-46fb-BF71-46E64AEDF165}' # Microsoft-Windows-RemoteApp and Desktop Connections(TSWorkspace.dll)
    '{1139C61B-B549-4251-8ED3-27250A1EDEC8}' # Microsoft-Windows-RemoteDesktopServices-RdpCoreTS(RdpCoreTS.dll)
    '{10d520e2-205c-4c22-b25c-ac7a779c55b2}' # Microsoft-Windows-RemoteDesktopServices-RemoteFX-Manager(rdvgm.exe)
    '{10AB3154-C36A-4F24-9D91-FFB5BCD331EF}' # Microsoft-Windows-RemoteDesktopServices-RemoteFX-SessionLicensing(LSClientService.dll)
    '{1B4F0E96-6876-49c8-BFBA-072DAE6543B3}' # Microsoft-Windows-RemoteDesktopServices-vGPU-KModeDriver(rdvgkmd.sys)
    '{5AE63087-6A35-40b0-AE15-CEA95A71A8C0}' # Microsoft-Windows-RemoteDesktopServices-vGPU-UModeDriver(rdvgumd32.dll)
    '{1deb930f-e136-4b08-9761-d7e3a5d14faa}' # Microsoft-Windows-RemoteDesktopServices-vGPU-UModeDriver64(rdvgumd64.dll)
    '{6e400999-5b82-475f-b800-cef6fe361539}' # Microsoft-Windows-TerminalServices-ClientUSBDevices(tsusbflt.sys)
    '{3f7b2f99-b863-4045-ad05-f6afb62e7af1}' # Microsoft-Windows-TerminalServices-MediaRedirection(tsmf.dll)
    '{27a8c1e2-eb19-463e-8424-b399df27a216}' # Microsoft-Windows-TerminalServices-PnPDevices(umrdp.dll)
    '{952773BF-C2B7-49BC-88F4-920744B82C43}' # Microsoft-Windows-TerminalServices-Printers(umrdp.dll)
    '{C76BAA63-AE81-421C-B425-340B4B24157F}' # Microsoft-Windows-TerminalServices-RemoteConnectionManager(termsrv.dll)
    '{dcbe5aaa-16e2-457c-9337-366950045f0a}' # Microsoft-Windows-TerminalServices-ServerUSBDevices(tsusbhub.sys)
    '{4d5ae6a1-c7c8-4e6d-b840-4d8080b42e1b}' # Microsoft-Windows-TerminalServices-Gateway(aaedge.dll)
    '{4D99F017-0EB1-4B52-8419-14AEBD13D770}' # Microsoft-Windows-TerminalServices-Licensing(lserver.dll)
    '{5d896912-022d-40aa-a3a8-4fa5515c76d7}' # Microsoft-Windows-TerminalServices-LocalSessionManager(lsm.dll)
    '{D1737620-6A25-4BEF-B07B-AAC3DF44EFC9}' # Microsoft-Windows-TerminalServices-SessionBroker(tssdis.exe)
    '{2184B5C9-1C83-4304-9C58-A9E76F718993}' # Microsoft-Windows-TerminalServices-SessionBroker-Client(tssdjet.dll)
    '{32817e55-7bfe-45e0-af68-a413fa6e0083}' # Microsoft-Windows-TerminalServices-TSAppSrv-TSMSI(TSMSISrv.dll)
    '{6ba29edf-a2f4-4212-b06b-6d5712210652}' # Microsoft-Windows-TerminalServices-TSAppSrv-TSVIP(TSVIPSrv.dll)
    '{8d83aec0-01de-4772-a317-2093b6dc3bab}' # Microsoft-Windows-TerminalServices-TSFairShare-Events(TSFairShare.sys)
    '{92618A87-2F6A-4B75-9AE2-E77BE7EAF43C}' # Microsoft-Windows-TerminalServices-TSV-VmHostAgent(tsvmhasvc.dll)
    '{28aa95bb-d444-4719-a36f-40462168127e}' # Microsoft-Windows-TerminalServices-ClientActiveXCore(mstscax.dll)
    '{8bddcf41-9630-47e8-914a-d4952112ea19}' # Microsoft-Windows-RemoteDesktopServices-RemoteFX-SessionManager(rdvgsm.dll)(WS2012R2 or earlier)
    '{7bfcf102-7378-431c-9284-0b968258991a}' # Microsoft-Windows-RemoteDesktopServices-RemoteDesktopSessionManager(RDPWD.sys)(WS2012 or ealier)
    '{b1c94ed9-ac9b-410e-aa48-4ffc5e45f4e3}' # Microsoft-Windows-TerminalServices-MediaRedirection-DShow(DShowRdpFilter.dll) (WS2008R2)
    '{D2E990DA-8504-4702-A5E5-367FC2F823BF}' # Microsoft-Windows-All-User-Install-Agent(RDSAppXHelper.dll)
    #'{127e0dc5-e13b-4935-985e-78fd508b1d80}' # Microsoft-Windows-TerminalServices-RdpSoundDriver(rdpendp.dll) => Too many logs will be recorded.
    '{1B9B72FC-678A-41C1-9365-824658F887E9}' # RDMSTrace
    '{9F58B00C-09C7-4CBC-8D19-969DCD5D5A6D}' # TSMMCTrace
    '{FB750AD9-8544-427F-B284-8ED9C6C221AE}' # Microsoft-Windows-Rdms-UI(Manifest)
    '{05da6b40-219e-4f17-92e6-d663fd87cba8}' # Microsoft-Windows-Remote-Desktop-Management-Service(rdms.dll)
    '{43471865-f3ee-5dcf-bf8b-193fcbbe0f37}' # Microsoft.Windows.RemoteDesktopServices.RailPlugin
    '{48EF6C18-022B-4394-BEE5-7B822B42AE4C}' # Microsoft.RDS.Windows.Client.MSRDC
    '{335934AA-6DD9-486C-88A5-F8D6A7D2BAEF}' # Microsoft.RDS.Windows.Client.AX
    '{4A49AFE3-776E-467A-ACA0-71F9C6C8499F}' # Microsoft.Windows.RemoteDesktop.RAIL.RdpInit
    '{39825FFA-F1B4-41B7-8221-20D4B8DBE57E}' # Microsoft.Windows.RemoteDesktop.RAIL.RdpShell
    '{48DAB7B6-34F4-44C8-8355-35124FE39BFF}' # RdpXTraceProvider
    '{CC3716F0-0336-44FB-A442-86276F4B712C}' # RdpWinTraceProvider
    '{59906E55-0817-4CDA-BA3B-D34E33ED4EE7}' # TokenValTrace
    '{5795AAB9-B0E3-419E-B0EF-7AEF943CFFA8}' # Microsoft.Windows.RemoteDesktop.Base
    '{8375996D-5801-4FE9-B0AE-F5C428758960}' # Microsoft.Windows.RemoteDesktop.ServerBase
    '{c8e6dc53-660c-44ee-8d00-e47f189db87f}' # Microsoft-Windows-RemoteDesktopServices-RdpCoreCDV
    '{E7C53BC0-EFF4-4DEE-993B-D48CB69766BD}' # Microsoft-Windows-DesktopSharing-Sharer
    '{642DF441-8193-4514-869F-7815DCA48372}' # Microsoft-Windows-DesktopSharing-Viewer
    '{080656C2-C24F-4660-8F5A-CE83656B0E7C}' # Microsoft.Windows.RemoteDesktop.ClientCore
    '{3EF15ADF-1300-44A1-B85C-2A83549F5B9E}' # Microsoft.Windows.RemoteDesktop.Legacy
)

$UEX_AppVProviders = @(
    '{E4F68870-5AE8-4E5B-9CE7-CA9ED75B0245}' # Microsoft-AppV-Client
    '{0D21725F-A0BD-4D1D-AE8E-6910F1093419}' # Microsoft-AppV-Sequencer
    '{7561449A-FC50-469B-B76E-88F43CF79ECF}' # Microsoft-AppV-Sequencer-Debug
    '{9CC69D1C-7917-4ACD-8066-6BF8B63E551B}' # Microsoft-AppV-ServiceLog
    '{FB4A19EE-EB5A-47A4-BC52-E71AAC6D0859}' # Microsoft-AppV-SharedPerformance
    '{C901E37D-B5F4-4582-AE6E-C1459F358B30}' # Microsoft-AppV-Sequencer-PRS
    '{271aebf7-e83b-580f-7525-5e9563fe161a}' # Microsoft.Windows.AppMan.AppV
    '{582C6A21-F5B4-4E52-B592-0E8229BF1737}' # Microsoft.Windows.AppMan.Shared.Logging
    '{df9b8c8f-ed83-5cd0-acec-4790d087c32b}' # Microsoft.Windows.AppMan.AppV.Sequencer
    '{28CB46C7-4003-4E50-8BD9-442086762D12}' # Microsoft-AppV-Client-StreamingUX
    '{34BEC984-F11F-4F1F-BB9B-3BA33C8D0132}' # this is ADS Bio provider, just for testing guid conflicts
    '{86f50c0c-6a4c-4b9c-a370-62b45ebe6e85}' # Microsoft-AppV-Server-Management
    '{84D85C22-6552-4A3F-BC85-C525B952861B}' # Microsoft-AppV-Server-Management-Private
    '{825C7963-9E32-4E3B-B74A-DF2CC3B6822B}' # Microsoft-AppV-Server-Publishing
    '{213B8D98-9A5E-4453-A2AB-A9B68A3C3EEA}' # Microsoft-AppV-Server-Publishing-Private
    '{1BEAA11B-B9C8-4D95-B567-D12C799C7D6E}' # Microsoft-AppV-Server-Reporting
    '{ECE17739-6097-4CC6-9B1C-FE40258A442B}' # Microsoft-AppV-Server-Reporting-Private

)

#---  LOGON PROVIDERS ---#
$UEX_LogonProviders = @(
    '{D451642C-63A6-11D7-9720-00B0D03E0347}' # WinLogon
    '{a789efeb-fc8a-4c55-8301-c2d443b933c0}' # UmsHlpr
    '{301779e2-227d-4faf-ad44-664501302d03}' # WlClNtfy
    '{5B4F9E61-4334-409F-B8F8-73C94A2DBA41}' # Userinit
    '{c2ba06e2-f7ce-44aa-9e7e-62652cdefe97}' # WinInit
    '{855ed56a-6120-4564-b083-34cb9d598a22}' # SetupLib
    '{d138f9a7-0013-46a6-adcc-a3ce6c46525f}' # WMsgSrv
    '{19d78d7d-476c-47b6-a484-285d1290a1f3}' # SysNtfy
    '{557D257B-180E-4AAE-8F06-86C4E46E9D00}' # LSM
    '{EB7428F5-AB1F-4322-A4CC-1F1A9B2C5E98}' # UserProfileService
    '{9891e0a7-f966-547f-eb21-d98616bf72ee}' # Microsoft.Windows.Shell.UserProfiles
    '{9959adbd-b5ac-5758-3ffa-ee0da5b8fe4b}' # Microsoft.Windows.ProfileService
    '{40654520-7460-5c90-3c10-e8b6c8b430c1}' # Microsoft.Windows.ProfExt
    '{D33E545F-59C3-423F-9051-6DC4983393A8}' # winsta
    '{b39b8cea-eaaa-5a74-5794-4948e222c663}' # Microsoft.Windows.Security.Winlogon
    '{8db3086d-116f-5bed-cfd5-9afda80d28ea}' # Microsoft-OSG-OSS-CredProvFramework
    '{5AA2DC10-E0E7-4BB2-A186-D230D79442D7}' # Microsoft.CAndE.ADFabric.CDJ.Recovery
    '{7ae961f7-1262-48e2-b237-acba331cc970}' # Microsoft.CAndE.ADFabric.CDJ.AzureSecureVMJoin
    '{fb3cd94d-95ef-5a73-b35c-6c78451095ef}' # Microsoft.Windows.CredProvDataModel
    '{a6c5c84d-c025-5997-0d82-e608d1abbbee}' # Microsoft.Windows.CredentialProvider.PicturePassword
    '{41ad72c3-469e-5fcf-cacf-e3d278856c08}' # Microsoft.Windows.BlockedShutdown
    '{df350158-0f8f-555d-7e4f-f1151ed14299}' # Microsoft.Windows.BioFeedback
    '{D33E545F-59C3-423F-9051-6DC4983393A8}' # winsta
    '{557D257B-180E-4AAE-8F06-86C4E46E9D00}' # LSM(From WS2019)
    '{4f7c073a-65bf-5045-7651-cc53bb272db5}' # Microsoft.Windows.LogonController
    '{3ec987dd-90e6-5877-ccb7-f27cdf6a976b}' # Microsoft.Windows.LogonUI.WinlogonRPC
    '{c0ac3923-5cb1-5e37-ef8f-ce84d60f1c74}' # Microsoft.Windows.TSSessionUX
    '{DBE9B383-7CF3-4331-91CC-A3CB16A3B538}' # Microsoft-Windows-Winlogon(Manifest)
    '{63D2BB1D-E39A-41b8-9A3D-52DD06677588}' # Microsoft-Windows-Shell-AuthUI(credprovhost.dll)
    '{DB00DFB6-29F9-4A9C-9B3B-1F4F9E7D9770}' # Microsoft-Windows-User Profiles General
    '{89B1E9F0-5AFF-44A6-9B44-0A07A7CE5845}' # Microsoft-Windows-User Profiles Service
    '{B059B83F-D946-4B13-87CA-4292839DC2F2}' # Microsoft-Windows-User-Loader
    '{EEA178E3-E9D4-41CA-BB56-CEDE1A476629}' # Microsoft-Windows-User-PnP
    '{1941DE80-2226-413B-AFA4-164FD76914C1}' # Microsoft.Windows.Desktop.Shell.WindowsUIImmersive.LockScreen
    '{176cd9c5-c90c-5471-38ba-0eeb4f7e0bd0}' # Microsoft.Windows.UI.Logon
    '{74cc4a0b-f577-5929-abcb-aa4bea374cb3}' # Microsoft.Windows.Shell.LockAppHost
    '{f8e28969-b1df-57fa-23f6-42260c77135c}' # Microsoft.Windows.ImageSanitization
    '{1915117c-a61c-54d4-6548-56cac6dbfede}' # Microsoft.Windows.Shell.AboveLockActivationManager
    '{e58f5f9c-3abb-5fc1-5ae5-dbe956bdbd33}' # Microsoft.Windows.Shell.AboveLockShellComponent
    '{b2149bc3-9dfd-5866-92a7-b556b3a6aed0}' # Microsoft.Windows.Shell.DefaultLockApp
    '{9ca921e3-25a4-5d34-39da-a59bd8bdf7a2}' # Microsoft.Windows.Shell.LockAppBroker
    '{b93d4107-dc22-5d11-c2e1-afba7a88d694}' # Microsoft.Windows.Shell.Tracing.LockAppBroker
    '{96319132-2f52-5969-f14c-0d0a171b357a}' # Microsoft.Windows.Shell.LockFrameworkUAP
    '{4191edaf-80c5-5ae3-49aa-325bd25cab2e}' # Microsoft.Windows.ComposableShell.Components.LockScreenHost.LockScreenShow
    '{355d4f62-3d5b-5372-213f-6d9d804c75df}' # Microsoft.Windows.AssignedAccess.MdmAlert
    '{94097d3d-2a5a-5b8a-cdbd-194dd2e51a00}' # Microsoft.Windows.AssignedAccess
    '{8530DB6E-51C0-43D6-9D02-A8C2088526CD}' # Microsoft-Windows-AssignedAccess
    '{F2311B48-32BE-4902-A22A-7240371DBB2C}' # Microsoft-Windows-AssignedAccessBroker
    '{5e85651d-3ff2-4733-b0a2-e83dfa96d757}' # UserMgrSvcTraceLoggingProvider
    '{077b8c4a-e425-578d-f1ac-6fdf1220ff68}' # Microsoft.Windows.Security.TokenBroker
    '{7acf487e-104b-533e-f68a-a7e9b0431edb}' # Microsoft.Windows.Security.TokenBroker.BrowserSSO
    '{BB86E31D-F955-40F3-9E68-AD0B49E73C27}' # Microsoft-Windows-User-UserManager-Events
    '{076a2c5c-40e9-5a75-73b0-8d7697c282b2}' # Microsoft.Windows.Security.Vault.RoamingSecurity
    '{a15c1ac4-a508-59ae-3158-275f96f30cb8}' # Microsoft.Windows.Security.Vault.Roaming
    '{98177d7f-7d3a-51ef-2d41-2414bb2c0bdb}' # Microsoft.Windows.Security.Wininit
    '{1ef1b3bd-ba20-5fd6-68c1-beb652b5d0c2}' # Microsoft.Windows.Shell.LockScreenContent
    '{b45275fa-3b9c-40f2-aaad-10060f77f0c0}' # Microsoft.Windows.Shell.CloudExperienceHost.DatVPrep
    '{F1C13488-91AC-4350-94DE-5F060589C584}' # Microsoft.Windows.Shell.LockScreenBoost
    '{3D14CA27-6EB2-4789-9B52-33EC88ECF5B0}' # Microsoft.Windows.Shell.LockScreenData
    '{1f44367c-cd89-5c01-ad03-bf60b9588564}' # Microsoft.Windows.LockAppBroker
    '{be69781c-b63b-41a1-8e24-a4fc7b3fc498}' # Microsoft-Windows-Sens
    '{A0CA1D82-539D-4FB0-944B-1620C6E86231}' # Microsoft-Windows-Sens/Debug
    '{2D710779-B24B-4ADB-81EF-CD6DED5A9B2A}' # Microsoft.Windows.Shell.LockScreenController
    '{75816B5C-ECD1-4DBC-B38A-47A9646E60BE}' # Microsoft.Windows.Shell.LockScreenExperienceManager
    '{68767976-7ddc-57d7-4318-9a6db4625165}' # Microsoft.Windows.Shell.WelcomeScreen
)

$UEX_KerberosProviders = @(
    '{6B510852-3583-4E2D-AFFE-A67F9F223438}' # Kerberos
    )


$UEX_AuthProviders = @(
    '{6165F3E2-AE38-45D4-9B23-6B4818758BD9}' # TSPkg
    '{37D2C3CD-C5D4-4587-8531-4696C44244C8}' # schannel(schannel.dll)
    '{5BBB6C18-AA45-49B1-A15F-085F7ED0AA90}' # NTLM
    '{6B510852-3583-4E2D-AFFE-A67F9F223438}' # Kerberos
    '{BBA3ADD2-C229-4CDB-AE2B-57EB6966B0C4}' # Kerberos Client
    '{CC85922F-DB41-11D2-9244-006008269001}' # LSA
    '{F33959B4-DBEC-11D2-895B-00C04F79AB69}' # NetLogon
    '{C5D1EB66-79E9-47C3-A578-A6F25DA14D49}' # SpapiWBLog
    '{5bbca4a8-b209-48dc-a8c7-b23d3e5216fb}' # Microsoft-Windows-CAPI2(crypt32.dll)
    '{1f678132-5938-4686-9fdc-c8ff68f15c85}' # Schannel(lsasrv.dll)
    '{91CC1150-71AA-47E2-AE18-C96E61736B6F}' # Microsoft-Windows-Schannel-Events(Manifest)
    '{4C88AF3D-5D47-458A-8624-515C122B7188}' # Microsoft.Windows.OneCoreUap.Shell.Auth.CredUX
    '{4b8b1947-ae4d-54e2-826a-1aee78ef05b2}' # Microsoft.Windows.WinBioDataModel
    '{a55d5a23-1a5b-580a-2be5-d7188f43fae1}' # Microsoft.Windows.Shell.BioEnrollment
    '{DC3B5BCF-BF7B-42CE-803C-71AF48F0F546}' # Microsoft.Windows.CredProviders.PasswordProvider
    '{fb3cd94d-95ef-5a73-b35c-6c78451095ef}' # Microsoft.Windows.CredProvDataModel
    '{5a4dad98-5dce-5efb-a9b2-54e8de8af594}' # Microsoft.Windows.Shell.Auth.LocalServiceCredUIBroker
    '{3bb1472f-46dc-5a12-4916-25706f703352}' # Microsoft.Windows.CredDialogBroker
    '{f2018623-63ac-5837-7cfb-f67ec5c39961}' # Microsoft.Windows.Shell.CredDialogHost
    '{d30325be-5b5e-508c-d76a-2d5e5fe60a5c}' # Microsoft.Windows.CredentialEnrollmentManager
    '{f245121c-b6d1-5f8a-ea55-498504b7379e}' # Microsoft.Windows.DeviceLockSettings
    '{350b80a3-32c3-47b3-9e58-32e5a48ce66f}' # Microsoft.Windows.SuggestedUsersDataModel
    '{c11d96bf-1615-4d64-ada3-5803cdbac698}' # Microsoft.Windows.Shell.Auth.CredUI
    '{1D86A602-D4EE-48FA-94B1-59EE686D07D0}' # MicrosoftWindowsShellAuthCredUI
    '{04063501-1c04-5e01-5e72-4e2400121550}' # Microsoft-Windows-UserTrustedSignals-CredProv
    '{5512152d-88f8-5f1e-ed9f-6412175a39dc}' # Microsoft.Windows.UI.PicturePassword
    '{462a094c-fc89-4378-b250-de552c6872fd}' # Microsoft.Windows.Shell.Auth.CredUIBroker
    '{24532ca4-409f-5d6c-3ded-e11946573f56}' # Microsoft.Windows.CredUXController
    '{4f7c073a-65bf-5045-7651-cc53bb272db5}' # Microsoft.Windows.LogonController
    '{9a7b2945-e29a-5477-e857-794ae72a85d9}' # Microsoft.Windows.AuthExt
    '{f0c781fb-3451-566e-121c-9020159a5306}' # Microsoft.Windows.SharedPC.AccountManager
    '{80B3FF7A-BAB0-4ED1-958C-E89A6D5557B3}' # Microsoft.Windows.Shell.SystemSettings.WorkAccessHandlers
    '{7fdd167c-79e5-4403-8c84-b7c0bb9923a1}' # VaultGlobalDebugTraceControlGuid
)

#---  LSA PROVIDERS ---#
$UEX_LSAProviders = @(
    '{D0B639E0-E650-4D1D-8F39-1580ADE72784}' # LsaTraceControlGuid
    '{DAA76F6A-2D11-4399-A646-1D62B7380F15}' # LsaAuditTraceControlGuid
    '{169EC169-5B77-4A3E-9DB6-441799D5CACB}' # LsaDsTraceControlGuid
    '{0D4FDC09-8C27-494A-BDA0-505E4FD8ADAE}' # Microsoft-Windows-Directory-Services-SAM
    '{BD8FEA17-5549-4B49-AA03-1981D16396A9}' # Microsoft-Windows-Directory-Services-SAM-Utility
    '{9A7D7195-B713-4092-BDC5-58F4352E9563}' # SamLib
    '{44415D2B-56DC-437D-AEB2-482A480183A5}' # OFFLINESAM
    '{F2969C49-B484-4485-B3B0-B908DA73CEBB}' # SamSrv
    '{548854b9-da55-403e-b2c7-c3fe8ea02c3c}' # SamSrv2
    '{8e598056-8993-11d2-819e-0000f875a064}' # SampControlGuid
)

#---  CRYPT PROVIDERS ---#
$UEX_CRYPTProviders = @(
    '{5BBCA4A8-B209-48DC-A8C7-B23D3E5216FB}' # Microsoft-Windows-CAPI2
    '{80DF111F-178D-44FB-AFB4-5D179DE9D4EC}' # WPP_CRYPT32_CONTROL_GUID
    '{EAC19293-76ED-48C3-97D3-70D75DA61438}' # WPP_CRYPTTPMEKSVC_CONTROL_GUID
    '{9B52E09F-0C58-4eaf-877F-70F9B54A7946}' # WPP_CHAT_CONTROL_GUID
    '{A74EFE00-14BE-4ef9-9DA9-1484D5473301}' # CNGTraceControlGuid
    '{A74EFE00-14BE-4ef9-9DA9-1484D5473302}' # CNGTraceControlGuid
    '{A74EFE00-14BE-4ef9-9DA9-1484D5473303}' # CNGTraceControlGuid
    '{A74EFE00-14BE-4ef9-9DA9-1484D5473304}' # CNGTraceControlGuid
    '{EA3F84FC-03BB-540e-B6AA-9664F81A31FB}' # DPAPIGlobalDebugTraceControlGuid
    '{9D2A53B2-1411-5C1C-D88C-F2BF057645BB}' # Microsoft.Windows.Security.Dpapi
    '{89FE8F40-CDCE-464E-8217-15EF97D4C7C3}' # Microsoft-Windows-Crypto-DPAPI
)

#---  WMI PROVIDERS ---#
$UEX_WMIProviders = @(
    '{1FF6B227-2CA7-40F9-9A66-980EADAA602E}' # WMI_Tracing_Guid
    '{8E6B6962-AB54-4335-8229-3255B919DD0E}' # WMI_Tracing_Client_Operations_Info_Guid
    '{1418EF04-B0B4-4623-BF7E-D74AB47BBDAA}' # Microsoft-Windows-WMI-Activity
    '{2CF953C0-8DF7-48E1-99B9-6816A2FBDC9F}' # Microsoft-Windows-WMIAdapter
    '{1EDEEE53-0AFE-4609-B846-D8C0B2075B1F}' # Microsoft-Windows-WMI
)

#---  UE-V PROVIDERS ---#
$UEX_UEVProviders = @(
    "{1ED6976A-4171-4764-B415-7EA08BC46C51}" # Microsoft-User Experience Virtualization-App Agent
    "{21D79DB0-8E03-41CD-9589-F3EF7001A92A}" # Microsoft-User Experience Virtualization-IPC
    "{57003E21-269B-4BDC-8434-B3BF8D57D2D5}" # Microsoft-User Experience Virtualization-SQM Uploader
    "{61BC445E-7A8D-420E-AB36-9C7143881B98}" # Microsoft-User Experience Virtualization-Admin
    "{e4dda0af-d7b4-5d40-4174-4d0be05ae338}" # Microsoft.Windows.AppMan.UEV
)

#---  COM/DCOM/WinRT/RPC PROVIDERS ---#
$UEX_COMProviders = @(
    '{9474a749-a98d-4f52-9f45-5b20247e4f01}' # DCOMSCM
    '{bda92ae8-9f11-4d49-ba1d-a4c2abca692e}' # OLE32(combase.dll)
    '{d4263c98-310c-4d97-ba39-b55354f08584}' # Microsoft-Windows-COM(advapi32.dll)
    '{0f177893-4a9c-4709-b921-f432d67f43d5}' # Microsoft-Windows-Complus(comres.dll)
    '{1B562E86-B7AA-4131-BADC-B6F3A001407E}' # Microsoft-Windows-DistributedCOM(combase.dll)
    '{B46FA1AD-B22D-4362-B072-9F5BA07B046D}' # COMSVCS(COM+)
    '{A0C4702B-51F7-4ea9-9C74-E39952C694B8}' # COMADMIN(COM+)
    '{1AFF6089-E863-4D36-BDFD-3581F07440BE}' # CombaseTraceLoggingProvider 
    '{6AD52B32-D609-4BE9-AE07-CE8DAE937E39}' # Microsoft-Windows-RPC(rpcrt4.dll)
    '{F4AED7C7-A898-4627-B053-44A7CAA12FCD}' # Microsoft-Windows-RPC-Events(rpcrt4.dll)
    '{d8975f88-7ddb-4ed0-91bf-3adf48c48e0c}' # Microsoft-Windows-RPCSS(RpcEpMap.dll)
    '{097d1686-4038-46be-b551-10fda0387165}' # CLBCATQ
    '{A86F8471-C31D-4FBC-A035-665D06047B03}' # Microsoft-Windows-WinRT-Error
    '{bf406804-6afa-46e7-8a48-6c357e1d6d61}' # Microsoft-Windows-COMRuntime
    '{7913ac64-a5cd-40cd-b096-4e8c4028eaab}' # Microsoft-Windows-WinTypes-Perf
    '{f0558438-f56a-5987-47da-040ca757ef05}' # Microsoft.Windows.WinRtClassActivation
    '{53201895-60E8-4fb0-9643-3F80762D658F}' # COM+ Services
    '{272A979B-34B5-48EC-94F5-7225A59C85A0}' # Microsoft-Windows-RPC-Proxy-LBS
    '{879b2576-39d1-4c0f-80a4-cc086e02548c}' # Microsoft-Windows-RPC-Proxy
    '{536caa1f-798d-4cdb-a987-05f79a9f457e}' # Microsoft-Windows-RPC-LBS
)

#---  Appx + ShellExperienceHost PROVIDERS ---#
$UEX_AppxProviders = @(
    '{BA44067A-3C4B-459C-A8F6-18F0D3CF0870}' # AppXDeployment WPP tracing
    '{8127F6D4-59F9-4abf-8952-3E3A02073D5F}' # Microsoft-Windows-AppXDeployment
    '{3F471139-ACB7-4A01-B7A7-FF5DA4BA2D43}' # Microsoft-Windows-AppXDeployment-Server
    '{fe762fb1-341a-4dd4-b399-be1868b3d918}' # Microsoft.Windows.AppXDeploymentServer
    '{BA723D81-0D0C-4F1E-80C8-54740F508DDF}' # Microsoft-Windows-AppxPackagingOM
    '{f0be35f8-237b-4814-86b5-ade51192e503}' # Microsoft-Windows-AppReadiness
    '{C567E5D7-A908-49C0-8C2C-A8DC3E8F0CF6}' # Microsoft.Windows.ARS.Tiles
    '{594bf743-ce2e-48ee-83ee-3d50a0add692}' # Microsoft.Windows.AppModel.TileDataModel
    '{3d6120a6-0986-51c4-213a-e2975903051d}' # Microsoft-Windows-Shell-Launcher
    '{39ddcb8d-ef82-5c84-89ca-09580bf0a947}' # Microsoft-Windows-Shell-AppResolver
    '{F84AA759-31D3-59BF-2C89-3748CF17FD7E}' # Microsoft-Windows-Desktop-Shell-Windowing
    '{3C42000F-CC27-48C3-A005-48F6E38B131F}' # Microsoft-WindowsPhone-AppPlatProvider
    '{15322370-3694-59f5-f979-0c7a918b81da}' # Microsoft.Windows.Desktop.Shell.ViewManagerInterop
    '{D75DF9F1-5F3D-49D0-9D15-2A55BD1C012E}' # ViewManagerInterop
    '{EF00584A-2655-462C-BC24-E7DE630E7FBF}' # Microsoft.Windows.AppLifeCycle
    '{58E68FB9-538C-47FA-8CEC-BC112DC6264A}' # EventProvider_IAM
    '{5C6E364D-3A8F-41D4-B7BB-2B03432CB665}' # VIEWMGRLIB(WPP)
    '{9C6FC32A-E17A-11DF-B1C4-4EBADFD72085}' # PLM
    '{29CFB5C5-E518-4960-A985-E18E570F935B}' # ACTIVATIONLIB(WPP)
    '{cf7f94b3-08dc-5257-422f-497d7dc86ab3}' # ActivationManager
    '{F1EF270A-0D32-4352-BA52-DBAB41E1D859}' # Microsoft-Windows-AppModel-Runtime
    '{BFF15E13-81BF-45EE-8B16-7CFEAD00DA86}' # Microsoft-Windows-AppModel-State
    '{41B5F6E6-F53C-4645-A991-135C2011C074}' # Microsoft.Windows.AppModel.StateManagerTelemetry
    '{5B5AB841-7D2E-4A95-BB4F-095CDF66D8F0}' # Microsoft-Windows-Roaming
    '{EB65A492-86C0-406A-BACE-9912D595BD69}' # Microsoft-Windows-AppModel-Exec
    '{315a8872-923e-4ea2-9889-33cd4754bf64}' # Microsoft-Windows-Immersive-Shell
    '{5F0E257F-C224-43E5-9555-2ADCB8540A58}' # Microsoft-Windows-Immersive-Shell-API
    '{8360D517-2805-4654-AA04-E9985B4433B4}' # Microsoft-Windows-AppModel-CoreApplication
    '{35D4A1FA-4036-40DC-A907-E330F3104E24}' # Microsoft-Windows-Desktop-ApplicationManager
    '{076A5FE9-E0F4-43DC-B246-9EA382B5C69F}' # Microsoft.Windows.Desktop.Shell.ViewManagement
    '{8BFE6B98-510E-478D-B868-142CD4DEDC1A}' # Windows.Internal.Shell.ModalExperience
    '{fa386406-8e25-47f7-a03f-413635a55dc0}' # TwinUITraceLoggingProvider
    '{c17f56cb-764e-5d2d-3b4e-0711ad368aaf}' # Microsoft.Windows.Shell.ApplicationHost
    '{4fc2cbef-b755-5b53-94db-8d816ca8c9cd}' # Microsoft.Windows.Shell.WindowMessageService
    '{072665fb-8953-5a85-931d-d06aeab3d109}' # Microsoft.Windows.ProcessLifetimeManager
    '{678e492b-5de1-50c5-7219-ae4aa7d6a141}' # Microsoft-Windows-Desktop-ApplicationFrame
    '{f6a774e5-2fc7-5151-6220-e514f1f387b6}' # Microsoft.Windows.HostActivityManager
    '{D2440861-BF3E-4F20-9FDC-E94E88DBE1F6}' # BiCommonTracingGuid(WPP)
    '{e6835967-e0d2-41fb-bcec-58387404e25a}' # Microsoft-Windows-BrokerInfrastructure
    '{63b6c2d2-0440-44de-a674-aa51a251b123}' # Microsoft.Windows.BrokerInfrastructure
    '{1941f2b9-0939-5d15-d529-cd333c8fed83}' # Microsoft.Windows.BackgroundManager
    '{d82215e3-bddf-54fa-895b-685099453b1c}' # Microsoft.Windows.BackgroundActivityModerator
    '{4a743cbb-3286-435c-a674-b428328940e4}' # PsmTrace(WPP)
    '{d49918cf-9489-4bf1-9d7b-014d864cf71f}' # Microsoft-Windows-PSM-Legacy(ProcessStateManager)
    '{0001376b-930d-50cd-2b29-491ca938cd54}' # Microsoft-Windows-PSM
    '{4180c4f7-e238-5519-338f-ec214f0b49aa}' # Microsoft-Windows-ResourceManager
    '{e8109b99-3a2c-4961-aa83-d1a7a148ada8}' # BrokerCommon(WPP)
    '{369f0950-bf83-53a7-b3f0-771a8926329d}' # Microsoft-Windows-Shell-ServiceHostBuilder
    '{3B3877A1-AE3B-54F1-0101-1E2424F6FCBB}' # SIHost
    '{770CA594-B467-4811-B355-28F5E5706987}' # Microsoft-Windows-ApplicationResourceManagementSystem
    '{a0b7550f-4e9a-4f03-ad41-b8042d06a2f7}' # Microsoft-Windows-CoreUIComponents
    '{89592015-D996-4636-8F61-066B5D4DD739}' # Microsoft.Windows.StateRepository
    '{1ded4f74-5def-425d-ae55-4fd4e9bbe0a7}' # Microsoft.Windows.StateRepository.Common
    '{a89336e8-e6cf-485c-9c6a-ddb6614f278a}' # Microsoft.Windows.StateRepository.Client
    '{312326fa-036d-4888-bc77-c3de2ff9ae06}' # Microsoft.Windows.StateRepository.Broker
    '{551ff9b3-0b7e-4408-b008-0068c8da2ff1}' # Microsoft.Windows.StateRepository.Service
    '{7237c668-b9a2-4fbd-9987-87d4502b9e00}' # Microsoft.Windows.StateRepository.Tools
    '{80a49605-87cb-4480-be97-d6ccb3dde5f2}' # Microsoft.Windows.StateRepository.Upgrade
    '{bf4c9654-66d1-5720-7b51-d2ae226735ea}' # Microsoft.Windows.ErrorHandling.Fallback
    '{CC79CF77-70D9-4082-9B52-23F3A3E92FE4}' # Microsoft.Windows.WindowsErrorReporting
    '{1AFF6089-E863-4D36-BDFD-3581F07440BE}' # CombaseTraceLoggingProvider
    '{f0558438-f56a-5987-47da-040ca757ef05}' # Microsoft.Windows.WinRtClassActivation
    '{5526aed1-f6e5-5896-cbf0-27d9f59b6be7}' # Microsoft.Windows.ApplicationModel.DesktopAppx
    '{fe0ab4b4-19b6-485b-89bb-60fd931fdd56}' # Microsoft.Windows.AppxPackaging
    '{19c13211-dec8-42d5-885a-c4cfa82ea1ed}' # Microsoft.Windows.Mrt.Runtime
    '{932a397d-97ed-50f9-29ab-051457f7af3e}' # Microsoft.Windows.Desktop.LanguageBCP47
    '{aa1b41d3-d193-4660-9b47-dd701ba55841}' # Microsoft-Windows-AppXDeploymentFallback
    '{BB86E31D-F955-40F3-9E68-AD0B49E73C27}' # Microsoft-Windows-User-UserManager-Events
    '{8CCCA27D-F1D8-4DDA-B5DD-339AEE937731}' # Microsoft.Windows.Compatibility.Apphelp
    '{b89fa39d-0d71-41c6-ba55-effb40eb2098}' # Microsoft.Windows.AppXDeploymentClient
    '{d9e5f8fb-06b1-4796-8fa8-abb07f4fc662}' # Microsoft.Windows.AppXDeploymentExtensions
    '{2f29dca8-fbb3-4944-8953-2d390f0fe746}' # DEPLOYMENT_WPP_GUID
    '{4dab1c21-6842-4376-b7aa-6629aa5e0d2c}' # Microsoft.Windows.AppXAllUserStore
    '{AF9FB9DF-E373-4653-84CE-01D8857E79FD}' # Microsoft.Windows.AppxMigrationPlugin
    '{8FD4B82B-602F-4470-8577-CBB56F702EBF}' # Microsoft.Windows.AppXDeploymentClient.WPP
    '{c94526b9-c642-489c-adfc-224530dda439}' # APPREADINESS_WPP_TRACE_GUID
)

$UEX_StartMenuProviders = @(
    '{a5934a92-d47c-55c9-7a3d-4f9acb7f44fe}' # Microsoft.Windows.Shell.StartMenu.Frame(Until RS2)
    '{d3e36643-28fd-5ccd-99b7-3b13c721ee51}' # Microsoft.Windows.Shell.StartMenu.Experience
    '{2ca51213-29c5-564f-fd60-355148e8b47f}' # Microsoft.Windows.Shell.SingleViewExperience
    '{53E167D9-E368-4150-9563-4ED25700CCC7}' # Microsoft.Windows.Shell.ExperienceHost
    '{66FEB609-F4B6-4224-BF13-121F8A4829B4}' # Microsoft.Windows.Start.SharedStartModel.Cache
    '{45D87330-FFEC-4A95-9F07-206A4452555D}' # Microsoft.Windows.Start.ImageQueueManager
    '{e7137ec0-0e64-4c48-a590-5b62661d3abc}' # Microsoft.Windows.ShellCore.SharedVerbProvider
    '{65cacb72-8567-457a-bc48-e16b67fb3e27}' # Microsoft.Windows.ShellCore.StartLayoutInitialization
    '{8d43f18f-af82-450a-bfb7-d6f1b53570ba}' # Microsoft.Windows.ShellCore.SharedModel
    '{36F1D421-D446-43AE-8AA7-A4F85CB176D3}' # Microsoft.Windows.UI.Shell.StartUI.WinRTHelpers
    '{9BB1A5A5-ABD6-4F8E-9507-12CC2B314896}' # Microsoft.Windows.Shell.TileDataLayerItemWrappers
    '{a331d81d-2f6f-50de-2461-a5530d0465d7}' # Microsoft.Windows.Shell.DataStoreCache
    '{6cfc5fc0-7e30-51e0-898b-57ac43152695}' # Microsoft.Windows.Shell.DataStoreTransformers
    '{2d069757-4018-5cf0-e4a2-bf70a1a0183c}' # Microsoft.Windows.Shell.MRTTransformer
    '{F2CDC8A0-AF2C-450F-9859-3251CCE0D234}' # WindowsInternal.Shell.UnifiedTile
    '{97CA8142-10B1-4BAA-9FBB-70A7D11231C3}' # Microsoft-Windows-ShellCommon-StartLayoutPopulation
    '{98CCAAD9-6464-48D7-9A66-C13718226668}' # Microsoft.Windows.AppModel.Tiles
    '{1a554939-2d19-5b10-ceda-ee4dd6910d59}' # Microsoft.Windows.ShellCommon.StartLayout
    '{8cba0f81-8ad7-5395-2125-5703822c822a}' # Microsoft.Windows.ContentDeliveryManager
    '{4690f625-1ceb-402e-acef-db8f00f3a446}' # Microsoft.Windows.Shell.TileControl
    '{c8416d9b-12d3-41f8-9a4c-c8d7033f4d30}' # Microsoft-Windows-Shell-Launcher-Curation
    '{c6ba71ae-658c-5a9b-94f5-b2026290198a}' # Microsoft.Windows.Desktop.Shell.QuickActions
    '{7B434BC1-8EFF-41A3-87E9-5D8AF3099784}' # Microsoft.Windows.Shell.KeyboardHosting.ShellKeyboardManager
    '{cbc427d6-f93e-5bcf-3137-d22fe2305d1f}' # Microsoft.Windows.Shell.ClockCalendar
    '{F84AA759-31D3-59BF-2C89-3748CF17FD7E}' # Microsoft-Windows-Desktop-Shell-Windowing
    '{BAA05370-7451-48D2-8F38-778380946CE9}' # Microsoft.Windows.SharedStartModel.NotificationQueueManager
    '{462B9C75-E5D7-4E0D-8AA1-294D175566BB}' # Microsoft-Windows-Shell-ActionCenter
    '{2c00a440-76de-4fe3-856f-00557535be83}' # Microsoft.Windows.Shell.ControlCenter
)

$UEX_CortanaProviders = @(
    '{E34441D9-5BCF-4958-B787-3BF824F362D7}' # Microsoft.Windows.Shell.CortanaSearch
    '{0FE37773-6C29-5233-0DD0-50E974F24203}' # Microsoft-Windows-Shell-CortanaDss
    '{2AF7F6B8-E17E-52A1-F715-FA43D637798A}' # Microsoft-Windows-Shell-CortanaHistoryUploader
    '{66f03b1f-1aec-5184-d349-a81761122be4}' # Microsoft.Windows.Shell.CortanaHome
    '{c0d0fe1d-53e4-5b98-71d7-c51fe5c10003}' # Microsoft-Windows-Shell-CortanaNL
    '{b9ca7b47-8bad-5693-9481-028527614d30}' # Microsoft.Windows.Shell.CortanaNotebook
    '{8E6931A7-4C49-5FB7-A500-65B951D7652F}' # Microsoft.Windows.Shell.CortanaPersonality
    '{5B7144A2-F0F6-4F99-A66D-FB2477E4CEE6}' # Microsoft.Windows.Shell.CortanaPlaces
    '{0E6F34B3-0637-55AB-F0BB-8B8FA83EDA04}' # Microsoft-Windows-Shell-CortanaProactive
    '{94041064-dbc2-4668-a729-b7b82747a0c2}' # Microsoft.Windows.Shell.CortanaReminders
    '{9B3FE00F-DAC4-4437-A77B-DE27B87046D4}' # Microsoft.Windows.Shell.CortanaSearch
    '{d8caafb9-7211-5dc8-7c1f-8027d50640ec}' # Microsoft.Windows.Shell.CortanaSignals
    '{a1f18f1f-bf5c-54d1-214d-8e1d3fe8427f}' # Microsoft-Windows-Shell-CortanaValidation
    '{2AEDC292-3FA5-472A-8EB4-33978D449853}' # Microsoft.Windows.Shell.CortanaSync
    '{92F43F71-2741-40B2-A566-70EEBCF2D181}' # Microsoft-Windows-Shell-CortanaValidation
    '{1aea69ee-2cfc-5eb1-f1f6-18f99a528b11}' # Microsoft-Windows-Shell-Cortana-IntentExtraction
    '{88BCD62D-F7AE-45B7-B578-4BF2B8AB867B}' # Microsoft-Windows-Shell-CortanaTrace
    '{ff32ada1-5a4b-583c-889e-a3c027b201f5}' # Microsoft.Web.Platform
    '{FC7BA620-EB50-483D-97A0-72D8268A14B5}' # Microsoft.Web.Platform.Chakra
    '{F65B3890-19BA-486E-A5F6-0378B356E0CE}' # Microsoft.Windows.UserSpeechPreferences
    '{adbb52ad-4e74-56c1-ecbe-cc4539ac4b2d}' # Microsoft.Windows.SpeechPlatform.Settings
    # '{57277741-3638-4A4B-BDBA-0AC6E45DA56C}' # Microsoft-JScript(chakra.dll)  // Too many logs will be recorded.
)

$UEX_WinRMProviders = @(
    '{A7975C8F-AC13-49F1-87DA-5A984A4AB417}' # Microsoft-Windows-WinRM
    '{04C6E16D-B99F-4A3A-9B3E-B8325BBC781E}' # WinRM(WPP)
    '{72B18662-744E-4A68-B816-8D562289A850}' # Windows HTTP Services
    '{7D44233D-3055-4B9C-BA64-0D47CA40A232}' # Microsoft-Windows-WinHttp
    '{B3A7698A-0C45-44DA-B73D-E181C9B5C8E6}' # WinHttp(WPP)
    '{4E749B6A-667D-4C72-80EF-373EE3246B08}' # WinInet(WPP)
    '{DD5EF90A-6398-47A4-AD34-4DCECDEF795F}' # Microsoft-Windows-HttpService
    '{20F61733-57F1-4127-9F48-4AB7A9308AE2}' # UxWppGuid(HTTP.sys - WPP)
    '{C42A2738-2333-40A5-A32F-6ACC36449DCC}' # Microsoft-Windows-HttpLog
    '{DD5EF90A-6398-47A4-AD34-4DCECDEF795F}' # Microsoft-Windows-HttpService
    '{7B6BC78C-898B-4170-BBF8-1A469EA43FC5}' # Microsoft-Windows-HttpEvent
    '{F5344219-87A4-4399-B14A-E59CD118ABB8}' # Microsoft-Windows-Http-SQM-Provider
    '{c0a36be8-a515-4cfa-b2b6-2676366efff7}' # WinRSMgr
    '{f1cab2c0-8beb-4fa2-90e1-8f17e0acdd5d}' # WinRSexe
    '{03992646-3dfe-4477-80e3-85936ace7abb}' # WinRSCmd
    '{651d672b-e11f-41b7-add3-c2f6a4023672}' # IPMIPrv
    '{D5C6A3E9-FA9C-434e-9653-165B4FC869E4}' # IpmiDrv
    '{6e1b64d7-d3be-4651-90fb-3583af89d7f1}' # WSManProvHost
    '{D5C6A3E9-FA9C-434e-9653-165B4FC869E4}' # IpmiDrv
    '{6FCDF39A-EF67-483D-A661-76D715C6B008}' # Event Forwarding
)

$UEX_DWMProviders = @(
    '{d29d56ea-4867-4221-b02e-cfd998834075}' # Microsoft-Windows-Dwm-Dwm(dwm.exe)
    '{9e9bba3c-2e38-40cb-99f4-9e8281425164}' # Microsoft-Windows-Dwm-Core
    '{292a52c4-fa27-4461-b526-54a46430bd54}' # Microsoft-Windows-Dwm-Api
    '{31f60101-3703-48ea-8143-451f8de779d2}' # Microsoft-Windows-DesktopWindowManager-Diag
    '{802ec45a-1e99-4b83-9920-87c98277ba9d}' # Microsoft-Windows-DxgKrnl
    '{93112de2-0aa3-4ed7-91e3-4264555220c1}' # Microsoft.Windows.Dwm.DComp
    '{504665a2-31f7-4b2f-bf1b-9635312e8088}' # Microsoft.Windows.Dwm.DwmApi
    '{1bf43430-9464-4b83-b7fb-e2638876aeef}' # Microsoft.Windows.Dwm.DwmCore
    '{45ac0c12-fa92-4407-bc96-577642890490}' # Microsoft.Windows.Dwm.DwmInit
    '{707d4382-a144-4d0a-827c-3f4422b5cf1f}' # Microsoft.Windows.Dwm.GhostWindow
    '{289E2456-EE16-4C81-AAF1-7414D66CA0BE}' # WindowsDwmCore
    '{c7a6e2fd-24f6-48fd-aad8-03ee14faf5ce}' # Microsoft.Windows.Dwm.WindowFrame
    '{11a377e3-be1e-4ee7-abda-81c6eda62e71}' # DwmAltTab
    '{25bd019c-3858-4ea4-a7b3-55b9ec8977e5}' # DwmRedir
    '{57e0b31d-de8c-4181-bcd1-f70e880b49fc}' # Microsoft-Windows-Dwm-Redir
    '{8c416c79-d49b-4f01-a467-e56d3aa8234c}' # DwmWin32kWin8
    '{8c9dd1ad-e6e5-4b07-b455-684a9d879900}' # Microsoft-Windows-Dwm-Core-Win7
    '{8cc44e31-7f28-4f45-9938-4810ff517464}' # DwmScheduler
    '{92ae46d7-6d9c-4727-9ed5-e49af9c24cbf}' # Microsoft-Windows-Dwm-Api-Win7
    '{98583af0-fc93-4e71-96d5-9f8da716c6b8}' # Microsoft-Windows-Dwm-Udwm
    '{bc2eeeec-b77a-4a52-b6a4-dffb1b1370cb}' # Microsoft-Windows-Dwm-Dwm
    '{e7ef96be-969f-414f-97d7-3ddb7b558ccc}' # DwmWin32k
    '{ed56cd5c-617b-49a5-9b80-eca3e02414bd}' # Dw
    '{72AB269D-8B68-4A17-B599-FCB1226A0319}' # Microsoft_Windows_Dwm_Udwm_Provider
    '{0C24D94B-8305-4D60-9765-5AFFD5462872}' # Microsoft.Windows.Udwm
    '{1a289bed-9134-4b49-9c10-4f98675cad08}' # Microsoft.Windows.Dwm.DwmRedir
)

$UEX_EventLogProviders = @(
    '{FC65DDD8-D6EF-4962-83D5-6E5CFE9CE148}' # Microsoft-Windows-Eventlog
    '{B0CA1D82-539D-4FB0-944B-1620C6E86231}' # WMI EventLogTrace
    '{565BBECA-5B04-49BB-81C6-3E21527FCC8A}' # Microsoft-Windows-Eventlog-ForwardPlugin
    '{35AC6CE8-6104-411D-976C-877F183D2D32}' # Microsoft-Windows-EventLog-WMIProvider
    '{899DAACE-4868-4295-AFCD-9EB8FB497561}' # Microsoft-Windows-EventSystem
)

$UEX_ShellProviders = @(
    # Shell
    '{30336ed4-e327-447c-9de0-51b652c86108}' # Microsoft-Windows-Shell-Core(shsvcs.dll) => Too many logs will be logged.
    '{46FCB024-5EA4-446C-B6C4-C7A4EE784198}' # ShellTraceProvider
    '{687AE510-1C00-4108-A958-ACFA78ECCCD5}' # Microsoft.Windows.Shell.AccountsControl
    '{c6fe0c47-96ef-5d29-c249-c3cecc6f9930}' # Microsoft.Windows.Shell.SyncPartnership.Api
    '{DC3B5BCF-BF7B-42CE-803C-71AF48F0F546}' # Microsoft.Windows.CredProviders.PasswordProvider
    '{d0034f5e-3686-5a74-dc48-5a22dd4f3d5b}' # Microsoft.Windows.Shell.CloudExperienceHost
    '{ff91e668-f7be-577e-14a3-44d801cccfa0}' # Microsoft.Windows.Shell.CloudExperienceHostCore
    '{f385e1a5-0346-5411-11a2-e8c8afe3b6ca}' # Microsoft.Windows.Desktop.Shell.CloudExperienceHostSpeech
    '{e305fb0f-da8e-52b5-a918-7a4f17a2531a}' # Microsoft.Windows.Shell.DefaultAssoc
    '{ee97cdc4-b095-5c70-6e37-a541eb74c2b5}' # Microsoft.Windows.AppLifeCycle.UI
    '{df8dab3f-b1c9-58d3-2ea1-4c08592bb71b}' # Microsoft.Windows.Shell.Taskbar
    '{653fe5bd-e1d2-5d40-d93c-a551a97cd49a}' # Microsoft.Windows.Desktop.Shell.NotificationArea
    '{5AFB7971-45E5-4d49-AAEB-1B04D39872CF}' # Microsoft.Windows.MobilityExperience
    '{7ca6a4dd-dae5-5fb7-ec8e-4a6c648fadf9}' # Microsoft.Windows.ShellPlacements
    '{55e357f8-ef0d-5ffd-a4dd-50e3d8f707cb}' # Microsoft.Windows.Desktop.Shell.CoreApplication.CoreApplicationView
    '{5487F421-E4DE-41D4-BFF3-72A4D6584898}' # Microsoft.Windows.Shell.SystemSettings.SettingHandlersSystem
    '{79c43bcd-08ea-5914-1e38-9e3008863a0c}' # Microsoft.Windows.Settings.Accessibility
    '{571ac9d5-12fd-4438-b630-61fb26bbb0ac}' # Microsoft.Windows.Shell.SystemSettings.BatterySaver
    '{e04d85e2-56a2-5bb7-5dab-6f761366a4c2}' # Microsoft.Windows.Shell.SystemSettings.BatterySaver.Desktop
    '{d43920c8-d57d-4e58-9283-f0fddd4afdcb}' # WindowsFlightingSettings
    '{080e197d-7cc1-54a3-e889-27636425992a}' # Microsoft.Windows.Shell.ShareUXSettings
    '{DB7BD825-B56F-48c4-8196-22BC145DDB08}' # Microsoft.Windows.Shell.SystemSettings.SIUF
    '{830a1f34-7797-4e31-9b75-c82056330051}' # Microsoft.Windows.Shell.SystemSettings.StorageSense
    '{0e6f34b3-0637-55ab-f0bb-8b8fa83eda04}' # Microsoft-Windows-Shell-CortanaProactive
    '{C11543B0-3A34-4F10-B50B-4DDB76FF2C6E}' # Microsoft.Windows.Shell.ThumbnailCache
    '{382B5E24-181E-417F-A8D6-2155F749E724}' # Microsoft.Windows.ShellExecute
    # Windows.Storage.dll
    '{79172b48-631e-5d2c-9f04-1ad99f6e1046}' # Microsoft.Windows.Desktop.Shell.Shell32
    '{9399df73-403c-5d8f-70c7-25aa3184c6f3}' # Microsoft.Windows.Shell.Libraries
    '{f168d2fa-5642-58bb-361e-127980c64a1b}' # Microsoft.Windows.Shell.OpenWith
    '{59a3be04-f025-4585-acfc-34456b550813}' # Microsoft.Windows.Shell.Edp
    '{8e12dcd2-fe15-5af4-2a6a-e707d9dc7de5}' # MicrosoftWindowsFileExplorer
    '{A40B455C-253C-4311-AC6D-6E667EDCCEFC}' # CloudFileAggregateProvider
    '{32980F26-C8F5-5767-6B26-635B3FA83C61}' # FileExplorerAggregateProvider
    '{8939299F-2315-4C5C-9B91-ABB86AA0627D}' # Microsoft-Windows-KnownFolders
    '{E0142D4F-9E39-5B3B-9DEB-8B576025FF5E}' # Microsoft.Windows.CentennialActivation
    '{3889f5d8-66b1-44d9-b52c-48ca283ac5d8}' # Microsoft.Windows.DataPackage
    '{e1fa35be-5192-5b1e-f23e-e2a38f6414b9}' # Microsoft.Windows.FileExplorerPerf
    '{B87CF16B-0BF8-4492-A510-D5F59626B033}' # Microsoft.Windows.FileExplorerErrorFallback
    '{08f5d47e-67d3-4ee0-8e0c-cbd309ab5d1b}' # Microsoft.Windows.Shell.CloudFiles
    '{f85b4793-1347-5620-7572-b79d5a28da82}' # Microsoft.Windows.Shell.DataLayer
    '{4E21A072-576A-4254-838B-059D479563BA}' # Microsoft.Windows.ComposableShell.Components.ContextMenu
    '{783f30af-5514-51bc-5b99-5d33b678539b}' # Microsoft.Windows.Shell.StorageSearch
    '{E5067383-0952-468C-9399-2E963F38B097}' # Microsoft\\ThemeUI
    '{869FB599-80AA-485D-BCA7-DB18D72B7219}' # Microsoft-Windows-ThemeUI
    '{61F044AF-9104-4CA5-81EE-CB6C51BB01AB}' # Microsoft-Windows-ThemeCPL
    '{D3F64994-CCA2-4F97-8622-07D451397C09}' # MicrosoftWindowsShellUserInfo
    '{1941DE80-2226-413B-AFA4-164FD76914C1}' # Microsoft.Windows.Desktop.Shell.WindowsUIImmersive.LockScreen
    '{9dc9156d-fbd5-5780-bd80-b1fd208442d6}' # Windows.UI.Popups
    '{46668d11-2db1-5756-2a4b-98fce8b0375f}' # Microsoft.Windows.Shell.Windowing.LightDismiss
    '{f8e28969-b1df-57fa-23f6-42260c77135c}' # Microsoft.Windows.ImageSanitization
    '{239d82f3-77e1-541b-2cbc-50274c47b5f7}' # Microsoft.Windows.Shell.BridgeWindow
    '{4fc2cbef-b755-5b53-94db-8d816ca8c9cd}' # Microsoft.Windows.Shell.WindowMessageService
    '{d2ff0031-cf02-500b-5898-8af98680cedb}' # Microsoft.Windows.Shell.ProjectionManager
    '{3635a139-1289-567e-b0ef-71e7adf3adf2}' # Microsoft.Windows.Shell.PlayToReceiverManager
    '{f71512b7-5d8e-41ee-aad8-4a6aebd29d4e}' # Microsoft.Windows.Shell.InkWorkspaceHostedAppsManager
    '{50c2b532-05e6-4616-ae28-2a023fe55216}' # Microsoft.Windows.Shell.PenSignalManager
    '{69ecab7c-aa2d-5d2e-e85c-debcf6fc9016}' # Microsoft.Windows.Desktop.OverrideScaling
    '{C127316F-7E36-5489-189A-99E57A8E788D}' # Microsoft-Windows-Explorer-ThumbnailMTC
    '{8911c0ab-6f93-4513-86d5-3de7175dd720}' # Microsoft.Windows.Shell.NotesManager
    '{08194E35-5511-4C06-9008-8C2CE1FE6B52}' # Microsoft.Windows.Shell.MSAWindowManager
    '{158715e0-18df-56cb-1a2e-d29da8fb9973}' # Microsoft.Windows.Desktop.Shell.MonitorManager
    '{D81F69FC-478D-4631-AD03-44046980BBFA}' # MicrosoftWindowsTwinUISwitcher
    '{ED576CEC-4ED0-4E09-9291-67EAD252DDE2}' # Microsoft.Windows.Desktop.Shell.KeyboardOcclusionMitigation
    '{34581546-9f8e-45f4-b73c-1c0ac79f7b20}' # Microsoft.Windows.Shell.PenWorkspace.ExperienceManager
    '{2ca51213-29c5-564f-fd60-355148e8b47f}' # Microsoft.Windows.Shell.SingleViewExperience
    '{F84AA759-31D3-59BF-2C89-3748CF17FD7E}' # Microsoft-Windows-Desktop-Shell-Windowing
    '{4cd50c2c-1018-53d5-74a1-4214e0941c20}' # Microsoft.Windows.Shell.ClickNote
    '{1608b891-0406-5011-1238-3e93b292a6ef}' # Microsoft.Windows.Shell.Autoplay
    '{7B0C2561-285F-46BB-9229-09D11947AE28}' # Microsoft.Windows.Desktop.Shell.AccessibilityDock
    '{6924642c-34a3-5050-2915-053f31e18534}' # Microsoft.Windows.Shell.CoreApplicationBridge
    '{64aa695c-9c53-58ad-2fe7-9358ab788507}' # Microsoft.Windows.Shell.Desktop.Themes
    '{dc140d17-88f7-55d0-fcb1-068435d69c4b}' # Microsoft.Windows.Shell.RunDialog
    '{75d2b56f-3f9d-5b1c-0792-d243507f67ce}' # Microsoft.Windows.Shell.PostBootReminder
    '{8D07CB9D-CA74-44E4-B389-C7068A51393E}' # Microsoft.Windows.Shell.IconCache
    '{4a9fe8c1-cde0-5f0a-f472-69b949097daf}' # Microsoft.Windows.Shell.Desktop.IconLayout
    '{59a36fc6-225a-41bf-b1b4-b558a37798cd}' # Microsoft.Windows.Shell.CoCreateInstanceAsSystemTaskServer
    '{44db9cfe-6db3-4a53-be9a-3057fa778b50}' # Microsoft.Windows.Shell.FileExplorer.Banners
    '{3d4b08aa-1df6-4549-b479-cf49b47cfcd3}' # Microsoft-Windows-BackupAndRoaming-SyncHandlers
    '{6e43b858-f3d9-5db1-0070-f99259784399}' # Microsoft.Windows.Desktop.Shell.LanguageOptions
    '{2446bc6d-2a96-5948-96ba-db27816dee43}' # Microsoft.Windows.Shell.SharingWizard
    '{45896826-7c5e-5a91-763d-67db83540f1b}' # Microsoft.Windows.Desktop.Shell.FontFolder
    '{9a9d6c4e-0c84-5401-7148-5d809fa78018}' # Microsoft.Windows.Desktop.Shell.RegionOptions
    '{ed7432ee-0f83-5083-030b-39f66ba307c5}' # Microsoft.Windows.Desktop.ScreenSaver
    '{8fe8ebd4-0f51-5f91-9481-cd2cfefdf96e}' # Microsoft.Windows.Desktop.Shell.Charmap
    '{28e9d7c3-908a-5980-90cc-1581dd9d451d}' # Microsoft.Windows.Desktop.Shell.EUDCEditor
    '{6d960cb7-fb14-5ed4-95fd-4d157414ecdb}' # Microsoft.Windows.Desktop.Shell.OOBEMonitor
    '{5391f591-9ca5-5833-7c1d-ad0ddec652cd}' # Microsoft.Windows.Desktop.Shell.MachineOOBE
    '{2cfa8474-fc39-51c6-c0ac-f08e5da70d91}' # Microsoft.Windows.Shell.Desktop.FirstLogonAnim
    '{451ceb17-c9c0-596d-78a3-df866a3867fb}' # Microsoft.Windows.Desktop.DesktopShellHostExtensions
    '{b93d4107-dc22-5d11-c2e1-afba7a88d694}' # Microsoft.Windows.Shell.Tracing.LockAppBroker
    '{e58f5f9c-3abb-5fc1-5ae5-dbe956bdbd33}' # Microsoft.Windows.Shell.AboveLockShellComponent
    '{1915117c-a61c-54d4-6548-56cac6dbfede}' # Microsoft.Windows.Shell.AboveLockActivationManager
    '{b82b78d7-831a-4747-bce9-ccc6d109ecf3}' # Microsoft.Windows.Shell.Prerelease
    '{2de4263a-8b3d-5824-1c83-6182d50c5356}' # Microsoft.Windows.Shell.Desktop.LogonAnaheimPromotion
    '{F1C13488-91AC-4350-94DE-5F060589C584}' # Microsoft.Windows.Shell.LockScreenBoost
    '{a51097ad-c000-5ea3-bbd4-863addaedd23}' # Microsoft.Windows.Desktop.Shell.ImmersiveIcons
    '{ffe467f7-4f51-4061-82be-c2ed8946a961}' # Microsoft.Windows.Shell.CoCreateInstanceAsSystem
    '{8A5010B1-0DCD-5AA6-5390-B288A15AC820}' # Microsoft-Windows-LockScreen-MediaTransportControlsUI
    '{C0B1CBF9-F523-51C9-15B0-02351517DAF8}' # Microsoft-Windows-Explorer-MediaTransportControlsUI
    '{1EE8CA37-11AE-4815-800E-58D6BAE1FEF9}' # Microsoft.Windows.Shell.SystemSettings.SettingsPane
    '{1ABBDEEA-0CF0-46B1-8EC2-DAAD6F165F8F}' # Microsoft.Windows.Shell.SystemSettings.HotKeyActivation
    '{7e8b48e9-dfa1-5073-f3f2-6251909a4d9d}' # Microsoft.Windows.BackupAndRoaming.Restore
    '{58b09b7d-fd44-5a27-101d-5d2472a7bb42}' # Microsoft.Windows.Shell.PrivacyConsentLogging
    '{04d28e21-00aa-5228-cfd0-d70863aa5ce9}' # Microsoft.Windows.Shell.Desktop.LogonFramework
    '{24fd15bb-a367-42b2-9210-e39c6467bf3a}' # Microsoft.Windows.Shell.Homegroup
    '{1d6a5020-c697-53bf-0f85-ae99be728db3}' # Microsoft.Windows.Shell.Display
    '{6b2cb30d-2176-5de5-c0f5-65aedfbb1b1f}' # Microsoft-Windows-Desktop-Shell-Personalization
    '{15584c9b-7d86-5fe0-a123-4a0f438a82c0}' # Microsoft.Windows.Shell.ServiceProvider
    '{354F4275-62B7-51B3-44C3-A1CB50CA4BC5}' # Microsoft-Windows-WebServicesWizard-OPW
    '{9cd954e1-c547-52c4-50c7-1a3f5df69321}' # Microsoft.Windows.Shell.SystemTray
    '{9d9f8d9d-81f1-4173-a667-4c54a4831dba}' # Microsoft.Windows.Shell.NetPlWiz
    '{397fe846-4109-5a9b-f2eb-c1d3b72630fd}' # Microsoft.Windows.Desktop.TextInput.InputSwitch
    '{feabe86d-d7a7-5e6d-9665-92819bc73768}' # Microsoft.Windows.Desktop.Shell.TimeDateOptions
    '{9493aaa3-34b7-5b53-daf1-cb9b80c7e772}' # Microsoft.Windows.Shell.DesktopUvc
    '{69219098-3c47-5f65-4b95-2e2ae89c07fc}' # WindowsInternal.Shell.Start.TraceLoggingProvider
    '{f0c781fb-3451-566e-121c-9020159a5306}' # Microsoft.Windows.SharedPC.AccountManager
    '{e49b2c1a-1ad0-505c-a11a-73dba0c60f50}' # Microsoft.Windows.Shell.Theme
    '{2c00a440-76de-4fe3-856f-00557535be83}' # Microsoft.Windows.Shell.ControlCenter
    '{462B9C75-E5D7-4E0D-8AA1-294D175566BB}' # Microsoft-Windows-Shell-ActionCenter
    '{f401924c-6fb0-5abb-be79-b010fb9ba7d4}' # Microsoft.Windows.Shell.FilePicker
    '{d173c6af-d86c-5327-17b8-5dcc03543da5}' # Microsoft.Windows.Mobile.Shell.FileExplorer
    '{813552F2-2082-4873-8E75-2DE43AA7B725}' # Microsoft.Windows.Mobile.Shell.Share
    '{08f5d47e-67d3-4ee0-8e0c-cbd309ab5d1b}' # Microsoft.Windows.Shell.CloudFiles
    '{c45c91e9-3750-5f9d-63c2-ec9d4991fcda}' # Microsoft.Windows.Shell.CloudStore.Internal
    # CLDAPI.DLL
    '{62e03996-3f13-473b-ba8c-9a507277abf8}' # Microsoft-OneCore-SyncEngine-Service
    '{6FDFA2FD-23C7-5152-1A51-618729D0E93D}' # Microsoft.Windows.FileSystem.CloudFiles
    # OneDriveSettingSyncProvider.dll
    '{F43C3C35-22E2-53EB-F169-07594054779E}' # Microsoft-Windows-SettingSync-OneDrive
    '{22111816-32de-5f2f-7260-2e7c4a7899ce}' # Microsoft.Windows.Shell.Personalization.CSP
)

$UEX_CldFltProviders = @(
    '{d8de3faf-8a2e-4a80-aedb-c86c7cc02a73}' # CldFltLogGuid
)

$UEX_IMEProviders = @(
    '{E2242B38-9453-42FD-B446-00746E76EB82}' # Microsoft-Windows-IME-CustomerFeedbackManager
    '{31BCAC7F-4AB8-47A1-B73A-A161EE68D585}' # Microsoft-Windows-IME-JPAPI
    '{3AD571F3-BDAE-4942-8733-4D1B85870A1E}' # Microsoft-Windows-IME-JPPRED
    '{8C8A69AD-CC89-481F-BBAD-FD95B5006256}' # Microsoft-Windows-IME-JPTIP
    '{BDD4B92E-19EF-4497-9C4A-E10E7FD2E227}' # Microsoft-Windows-IME-TIP
    '{FD44A6E7-580F-4A9C-83D9-D820B7D3A033}' # Microsoft-Windows-IME-OEDCompiler
    '{4FBA1227-F606-4E5F-B9E8-FAB9AB5740F3}' # Microsoft-Windows-TSF-msctf
    '{ebadf775-48aa-4bf3-8f8e-ec68d113c98e}' # Microsoft-Windows-TextInput
    '{7B434BC1-8EFF-41A3-87E9-5D8AF3099784}' # Microsoft-Windows-Shell-KeyboardHosting-ShellKeyboardManager
    '{34c25d46-d194-5918-c399-d3641f0c609d}' # Microsoft-Windows-ComposableShell-Components-InputHost
    '{5C3E3AA8-3BA4-43CD-A7DE-3BF5F70F9CA4}' # Microsoft-Windows-Shell-TextInput-InputPanel
    '{7e6b69b9-2aec-4fb3-9426-69a0f2b61a86}' # Microsoft-Windows-Win32kBase-Input
    '{74B655A2-8958-410E-80E2-3457051B8DFF}' # Microsoft-Windows-TSF-msutb
    '{4DD778B8-379C-4D8C-B659-517A43D6DF7D}' # Microsoft-Windows-TSF-UIManager
    '{39A63500-7D76-49CD-994F-FFD796EF5A53}' # Microsoft-Windows-TextPredictionEngine
    '{E2C15FD7-8924-4C8C-8CFE-DA0BE539CE27}' # Microsoft-Windows-IME-Broker
    '{7C4117B1-ED82-4F47-B2CA-29E4E25719C7}' # Microsoft-Windows-IME-CandidateUI
    '{1B734B40-A458-4B81-954F-AD7C9461BED8}' # Microsoft-Windows-IME-CustomerFeedbackManagerUI
    '{DBC388BC-89C2-4FE0-B71F-6E4881FB575C}' # Microsoft-Windows-IME-JPLMP
    '{14371053-1813-471A-9510-1CF1D0A055A8}' # Microsoft-Windows-IME-JPSetting
    '{7562948E-2671-4DDA-8F8F-BF945EF984A1}' # Microsoft-Windows-IME-KRAPI
    '{E013E74B-97F4-4E1C-A120-596E5629ECFE}' # Microsoft-Windows-IME-KRTIP
    '{F67B2345-47FA-4721-A6FB-FE08110EECF7}' # Microsoft-Windows-IME-TCCORE
    '{D5268C02-6F51-436F-983B-74F2EFBFAF3A}' # Microsoft-Windows-IME-TCTIP
    '{28e9d7c3-908a-5980-90cc-1581dd9d451d}' # Microsoft.Windows.Desktop.Shell.EUDCEditor
    '{397fe846-4109-5a9b-f2eb-c1d3b72630fd}' # Microsoft.Windows.Desktop.TextInput.InputSwitch
    '{c442c41d-98c0-4a33-845d-902ed64f695b}' # Microsoft.Windows.TextInput.ImeSettings
    '{6f72e560-ef48-5597-9970-e83a697071ac}' # Microsoft.Windows.Desktop.Shell.InputDll
    '{03e60cf9-4fa0-5ddd-7452-1d05ce7d61bd}' # Microsoft.Windows.Desktop.TextInput.UIManager
    '{86df9ee3-15c5-589d-4355-17cc2371dae1}' # Microsoft.Windows.Desktop.TextInput.TabNavigation
    '{887B7E68-7106-4E20-B8A1-2506C336EC2E}' # Microsoft-Windows-InputManager
    '{ED07CE1C-CEE3-41E0-93E2-EEB312301848}' # Microsoft-WindowsPhone-Input
    '{BB8E7234-BBF4-48A7-8741-339206ED1DFB}' # Microsoft-Windows-InputSwitch
    '{E978F84E-582D-4167-977E-32AF52706888}' # Microsoft-Windows-TabletPC-InputPanel
    '{3F30522E-D47A-407C-9067-2E928D00D54E}' # TouchKeyboard
    '{B2A2AFC4-FD0B-5A85-9EEF-0CE26805CB02}' # Microsoft.Windows.Input.HidClass
    '{6465DA78-E7A0-4F39-B084-8F53C7C30DC6}' # Microsoft-Windows-Input-HIDCLASS
    '{83BDA64C-A52C-4B37-8E61-086C22A4CD15}' # Microsoft.Windows.InputStateManager
    '{36D7CADA-005D-4F57-A37A-DA52FB3C1296}' # Tablet Input Perf
    '{2C3E6D9F-8298-450F-8E5D-49B724F1216F}' # Microsoft-Windows-TabletPC-Platform-Input-Ninput
    '{E5AA2A53-30BE-40F5-8D84-AD3F40A404CD}' # Microsoft-Windows-TabletPC-Platform-Input-Wisp
    '{B5FD844A-01D4-4B10-A57F-58B13B561582}' # Microsoft-Windows-TabletPC-Platform-Input-Core
    '{A8106E5C-293A-4CD0-9397-2E6FAC7F9749}' # Microsoft-Windows-TabletPC-InputPersonalization
    '{4f6a3c95-b86c-59f7-d8ed-d5b0b6a683d6}' # Microsoft.Windows.Desktop.TextInput.TextServiceFramework
    '{78eba95a-9f43-44b0-8391-6992cb068def}' # Microsoft.Windows.Desktop.TextInput.MsCtfIme
    '{f7febf94-a5f7-464b-abbd-84a042681d00}' # Microsoft.Windows.Desktop.TextInput.ThreadInputManager"
    '{06404639-ec4f-56d8-f82e-49bf6ad1b96a}' # Microsoft.Windows.Desktop.TextInput.BopomofoIme
    '{2593bdf1-313b-5c29-355c-6065ba331797}' # Microsoft.Windows.Desktop.TextInput.ImeCommon
    '{68259fff-ce2b-4a91-8df0-9656cdb7a4d6}' # Microsoft.Windows.Desktop.TextInput.MSCand20
    '{a703f75d-9c1d-59c0-6b0a-a1251f1c6c55}' # Microsoft.Windows.DeskTop.TextInput.ModeIndicator
    '{a097d80a-cae1-5a27-bdea-58bd574c9901}' # Microsoft.Windows.Desktop.TextInput.CloudSuggestionFlyout
    '{47a8ea0f-be9f-5a94-1586-5ded19d57c3d}' # Microsoft.Windows.Desktop.TextInput.JapaneseIme
    '{ca8d5125-1b72-5208-5147-0d345b85bd11}' # Microsoft.Windows.Desktop.TextInput.KoreanIme
    '{e3905915-dd2b-5802-062b-85f03eb993d5}' # Microsoft.Windows.Desktop.TextInput.OldKoreanIme
    '{54cedcd4-5f61-54b3-d8e2-dd26feae36b2}' # Microsoft.Windows.Shell.MTF.DesktopInputHistoryDS
    '{99d75be6-d696-565a-1c56-25d65942b571}' # Microsoft.Windows.Shell.MTF.LMDS
    '{89DB9EAC-5750-580C-39D6-6978396822DD}' # Microsoft.Windows.TextInput.Gip
    '{2D66BB8D-2A6B-5A2D-A09C-4F57A1776BD1}' # Microsoft.Windows.TextInput.ChsIme
    '{4B7BD959-BFEA-5953-583C-FB7BF825BC92}' # Microsoft.Windows.Desktop.TextInput.ChtIme
    '{FF5023D9-8341-5DFB-3C33-17A1AB76A426}' # Microsoft.Windows.Shell.CandidateWindow
    '{73AE0EC4-37FC-4B10-92C0-7F6D9D0539B9}' # Microsoft-Windows-TextInput-ExpressiveInput
    '{D49F5FDD-C4AB-47BD-BD68-A9A8688A92AB}' # Microsoft.Windows.TextInput.Gip.Perf
    '{6BE754E7-F231-4DB7-A9B6-3720F91A7AD2}' # Microsoft.Windows.TextInput.Gip.LegacyBopomofo.Perf
    '{04708A84-8C97-4B32-A8A9-2762C83573C0}' # Microsoft-IPX-Core
    '{C3AF4B8A-C24F-56D4-CE67-DEF9F522A0DD}' # Microsoft.Windows.Shell.TouchKeyboardExperience
    '{68396F5F-E685-5C1B-3181-A17CF8D96FA6}' # Microsoft-Windows-Desktop-TextInput-TouchKeyboard
    '{04acff1a-30a0-4e6c-81bd-ad3ff3c67771}' # Microsoft.WindowsInternal.ComposableShell.Experiences.SuggestionUI.Web
    '{9cecf4ae-61a9-41bc-ac51-06bd5f4a30d1}' # Microsoft.WindowsInternal.ComposableShell.Experiences.SuggestionUI
    '{2a72b023-e9bf-4b39-9924-7f1872bd0959}' # Microsoft.WindowsInternal.Client.Components.PackageFeed
    '{393ff4cc-f02d-5d0a-4180-b79bf8da529d}' # Microsoft.Windows.Shell.MTF.Platform
    '{C73DBAB0-5395-4D87-8134-290D28AC0E01}' # Microsoft.Windows.Fundamentals.UserInitiatedFeedback
    '{5FB75EAC-9F0B-550C-339F-FC21FDE966CD}' # Microsoft.Windows.InputCore.TraceLogging.UIF
    '{A90E365C-CC39-4B68-B943-DCD45C83BB52}' # Microsoft.Windows.InputCore.Manifested.UIF
    '{47C779CD-4EFD-49D7-9B10-9F16E5C25D06}' # Microsoft.Windows.HID.HidClass
    '{E742C27D-29B1-4E4B-94EE-074D3AD72836}' # Microsoft.Windows.HID.I2C
    '{0A6B3BB2-3504-49C1-81D0-6A4B88B96427}' # Microsoft.Windows.HID.SPI
    '{896F2806-9D0E-4D5F-AA25-7ACDBF4EAF2C}' # Microsoft.Windows.HID.USB
    '{07699FF6-D2C0-4323-B927-2C53442ED29B}' # Microsoft.Windows.HID.BTH
    '{0107CF95-313A-473E-9078-E73CD932F2FE}' # Microsoft.Windows.HID.GATT
    '{B41B0A56-4483-48EF-A772-0B007CBEA8C6}' # Microsoft.Windows.HID.kbd
    '{09281F1F-F66E-485A-99A2-91638F782C49}' # Microsoft.Windows.HID.kbdclass
    '{BBBC2565-8272-486E-B5E5-2BC4630374BA}' # Microsoft.Windows.HID.mou
    '{FC8DF8FD-D105-40A9-AF75-2EEC294ADF8D}' # Microsoft.Windows.HID.mouclass
    '{46BCE2CC-ED23-41DF-BE49-6BB8EC04CF70}' # Microsoft.Windows.Drivers.MtConfig
    '{4B2862FE-F8BE-41FF-984A-0AF845F78E86}' # Microsoft.Windows.HID.Buttonconverter
    '{78396E52-9753-4D63-8CF5-A936B4989FF2}' # Microsoft.Windows.HID.HidInterrupt
    '{5A81715A-84C0-4DEF-AE38-EDDE40DF5B3A}' # Microsoft.Windows.HID.GPIO
    '{51B2172F-205D-40C1-9A30-ED090FF72E6C}' # Microsoft.Windows.HID.VHF
    '{E6086B4D-AEFF-472B-BDA7-EEC662AFBF11}' # Microsoft.Windows.HID.SpbCx
    '{6E6CC2C5-8110-490E-9905-9F2ED700E455}' # Microsoft.Windows.USB.UsbHub3
    '{6FB6E467-9ED4-4B73-8C22-70B97E22C7D9}' # Microsoft.Windows.USB.ucx01000
    '{9F7711DD-29AD-C1EE-1B1B-B52A0118A54C}' # Microsoft.Windows.USB.XHCI
    '{BC6C9364-FC67-42C5-ACF7-ABED3B12ECC6}' # Microsoft.Windows.USB.CCGP
    '{B10D03B8-E1F6-47F5-AFC2-0FA0779B8188}' # Microsoft.Windows.USB.Hub
    '{D75AEDBE-CFCD-42B9-94AB-F47B224245DD}' # Microsoft.Windows.USB.Port
    '{7FFB8EB8-2C86-45D6-A7C5-C023D9C070C1}' # Microsoft.Windows.Drivers.I8042prt
    '{8D83BA5C-E85E-4859-B18E-314BA4475A12}' # Microsoft.Windows.Drivers.msgpioclx
    '{D88ACE07-CAC0-11D8-A4C6-000D560BCBA5}' # Microsoft.Windows.Drivers.bthport
    '{CDEF60FA-5777-4B02-9980-1E2C0DF22635}' # Microsoft.Windows.Power.DeviceProblems
    '{3374F1C0-597F-4AA1-B2C2-12789D9C8C3F}' # Microsoft.Windows.RIM_RS1.WPP
    '{0F81EC00-9E52-48E6-B899-EB3BBEEDE741}' # Microsoft.Windows.Win32kBase.WPP
    '{03914E49-F3DD-40B9-BB7F-9445BF46D43E}' # Microsoft.Windows.Win32kMin.WPP
    '{335D5E04-5638-4E58-AA36-7ED1CFE76FD6}' # Microsoft.Windows.Win32kFull.WPP
    '{9C648335-6987-470C-B588-3DE7A6A1FDAC}' # Microsoft.Windows.Win32kNs.WPP
    '{487D6E37-1B9D-46D3-A8FD-54CE8BDF8A53}' # Microsoft.Windows.Win32k.TraceLogging
    '{8C416C79-D49B-4F01-A467-E56D3AA8234C}' # Microsoft.Windows.Win32k.UIF
    '{7D30FE49-D67F-42D7-A360-9A0639EC5719}' # Microsoft.Windows.OneCore.MinUser
    '{331C3B3A-2005-44C2-AC5E-77220C37D6B4}' # Microsoft.Windows.Kernel.Power
    '{029769EE-ED48-4166-894E-357918A77E68}' # Microsoft.Windows.WCOS.Adapter
    '{9956C4CC-7B21-4D55-B22D-3A0EA2BDDEB9}' # Microsoft.Windows.OneCore.MinUserExt
    '{A7F923A4-8693-4876-92F4-4FF49791D3CF}' # Microsoft.Windows.Ninput.Interaction
    '{2BED2D8B-72D4-4D19-B0AC-DC27BF3B24EA}' # Microsoft.Windows.Dwm.Tests
    '{461B985D-2EBE-49C1-B506-BBF6C753A82B}' # Microsoft.Windows.Dwm.LiftedTests
    '{2729BE56-B41A-54BE-8C2A-8DA6127A8E38}' # Microsoft.Windows.Dwm.Interaction
    '{07E4CEB9-D0CC-48A6-AF64-00F7A7D1198F}' # Microsoft.Windows.Dwm.LiftedInteraction
    '{9E9BBA3C-2E38-40CB-99F4-9E8281425164}' # Microsoft.Windows.Dwm.Core.Input
    '{973C694B-79A6-480E-89A5-C8C20745D461}' # Microsoft.Windows.OneCore.MinInput
    '{23E0D3D9-6334-4EDD-9C80-54D3D7CFA8DA}' # Microsoft.Windows.WinUI.WPP
    '{CB18E7B3-F5B0-412F-9F18-5D87FEFCD662}' # Microsoft.Windows.DirectManipulation.WPP
    '{5786E035-EF2D-4178-84F2-5A6BBEDBB947}' # Microsoft.Windows.DirectManipulation
    '{EE8FDBA0-14D6-50EC-A17A-33F388F21065}' # Microsoft.Windows.DirectInk
    '{C44219D0-F344-11DF-A5E2-B307DFD72085}' # Microsoft.Windows.DirectComposition
    '{7D99F6A4-1BEC-4C09-9703-3AAA8148347F}' # Microsoft.Windows.Dwm.Redir
    '{531A35AB-63CE-4BCF-AA98-F88C7A89E455}' # Microsoft.Windows.XAML
    '{A3D95055-34CC-4E4A-B99F-EC88F5370495}' # Microsoft.Windows.CoreWindow
    '{55A5DC53-E24E-5B53-5B52-EA83A0CC4E0C}' # Microsoft.Windows.Heat.HeatCore
    '{54225112-EAA1-5E29-C8F8-1CB9924D6049}' # Microsoft.Windows.Heat.HeatCore.Test
    '{4AE53EDA-2033-5DD2-8850-99823083A9E5}' # Microsoft.Windows.Heat.Processor
    '{A0B7550F-4E9A-4F03-AD41-B8042D06A2F7}' # Microsoft.Windows.CoreUIComponents
)

$UEX_PrintProviders = @(
    '{C9BF4A01-D547-4D11-8242-E03A18B5BE01}' # LOCALSPL
    '{C9BF4A02-D547-4D11-8242-E03A18B5BE01}' # WINSPOOL
    '{C9BF4A03-D547-4D11-8242-E03A18B5BE01}' # WIN32SPL
    '{C9BF4A04-D547-4D11-8242-E03A18B5BE01}' # BIDISPL
    '{C9BF4A05-D547-4D11-8242-E03A18B5BE01}' # SPLWOW64
    '{C9BF4A06-D547-4D11-8242-E03A18B5BE01}' # SPLLIB
    '{C9BF4A07-D547-4D11-8242-E03A18B5BE01}' # PERFLIB
    '{C9BF4A08-D547-4D11-8242-E03A18B5BE01}' # ASYNCNTFY
    '{C9BF4A09-D547-4D11-8242-E03A18B5BE01}' # REMNTFY
    '{C9BF4A0A-D547-4D11-8242-E03A18B5BE01}' # GPPRNEXT
    '{C9BF4A0B-D547-4D11-8242-E03A18B5BE01}' # SANDBOX
    '{C9BF4A0C-D547-4D11-8242-E03A18B5BE01}' # SANDBOXHOST
    '{C9BF4A0D-D547-4d11-8242-E03A18B5BE01}' # MSW3PRT
    '{C9BF4A9E-D547-4D11-8242-E03A18B5BE01}' # SPOOLSV
    '{C9BF4A9F-D547-4D11-8242-E03A18B5BE01}' # SPOOLSS
    '{09737B09-A25E-44D8-AA75-07F7572458E2}' # PRNNTFY
    '{301CCC25-D58B-4C5E-B6A5-15BCF8B0077F}' # INETPPUI
    '{34F7D4F8-CD95-4B06-8BF6-D929DE4AD9DE}' # PRNCACHE
    '{528F557E-A4D4-4063-A17A-9F45FAF8C042}' # HGPRINT
    '{3EA31F33-8F51-481D-AEB7-4CA37AB12E48}' # LPDSVC
    '{62A0EB6C-3E3E-471D-960C-7C574A72534C}' # TCPMon
    '{6D1E0446-6C52-4B85-840D-D2CB10AF5C63}' # WSDPrPxy
    '{836767A6-AF31-4938-B4C0-EF86749A9AEF}' # WSDMON
    '{9558985E-3BC8-45EF-A2FD-2E6FF06FB886}' # WSDPRINT
    '{9677DFEF-EACF-4173-8977-FFB0086B11E6}' # BridgeGuid
    '{99F5F45C-FD1E-439F-A910-20D0DC759D28}' # USBMon
    '{9E6D0D9B-1CE5-44B5-8B98-F32ED89077EC}' # LPRHelp
    '{A83C80B9-AE01-4981-91C6-94F00C0BB8AA}' # printui
    '{AAED978E-5B0C-4F71-B35C-16E9C0794FF9}' # CommonGuid
    '{B42BD277-C2BA-468B-AB3D-05B1A1714BA3}' # PRINTLIB
    '{B795C7DF-07BC-4362-938E-E8ABD81A9A01}' # NTPRINT
    '{C9BF4A9E-D547-4D11-8242-E03A18B5BEEE}' # INETPP
    '{CE444D6A-F287-4977-BBBD-89A0DD65B71D}' # CDIGuid
    '{D34AE79A-15FB-44F9-9FD8-3098E6FFFD49}' # D34AE79A
    '{EB4C6075-0B67-4A79-A0A3-7CD9DF881194}' # XpsRasFilter
    '{EE7E960D-5E42-4C28-8F61-D8FA8B0DD84D}' # ServerGuid
    '{F30FAB8E-84BB-48D4-8E80-F8967EF0FE6A}' # LPRMon
    '{F4DF4FA4-66C2-4C14-ABB1-19D099D7E213}' # COMPONENTGuid
    '{34F7D4F8-CD95-4B06-8BF6-D929DE4AD9DE}' # PRNCACHE
    '{883DFB21-94EE-4C9B-9922-D5C42B552E09}' # PRNFLDR
    '{3048407B-56AA-4D41-82B2-7D5F4B1CDD39}' # DAFPRINT
    '{2F6A026F-D4C4-41B8-A59E-2EC834419B67}' # PUIOBJ
    '{79B3B0B7-F082-4CEC-91BC-5E4B9CC3033A}' # FDPRINT
    '{CAC16EB2-12D0-46B8-B484-F179C900772B}' # PMCSNAP
    '{0DC96237-BBD4-4BC9-8184-46DF83B1F1F0}' # DOXXPS
    '{0675CF90-F2B8-11DB-BB42-0013729B82C4}' # DOXPKG
    '{986DE178-EA3F-4E27-BBEE-34E0F61535DD}' # XpsRchVw
    '{64F02056-AFD9-42D9-B221-6C94733B09B1}' # XpsIFilter
    '{2BEADE0B-84CD-44A5-90A7-5B6FB2FF83C8}' # XpsShellExt
    '{AAACB431-6067-4A42-8883-3C01526DD43A}' # XpsRender
    '{0DC96237-BBD4-4BC9-8184-46DF83B1F1F0}' # DOXXPS
    '{986DE178-EA3F-4E27-BBEE-34E0F61535DD}' # XpsRchVw
    '{12DC38E3-E395-4C8E-9156-B5642057F5FA}' # Microsoft-Windows-PrintDialogs3D
    '{27E76321-1E5B-4A82-BA0C-26E978F15072}' # Microsoft-Windows-PrintDialogs
    '{747EF6FD-E535-4D16-B510-42C90F6873A1}' # Microsoft-Windows-PrintService
    '{7F812073-B28D-4AFC-9CED-B8010F914EF6}' # Microsoft-Windows-PrintService-USBMon
    '{952773BF-C2B7-49BC-88F4-920744B82C43}' # Microsoft-Windows-TerminalServices-Printers
    '{0ED38D2B-4ACC-4E23-A8EC-D0DACBC34637}' # tsprint
    '{9B4A618C-07B8-4182-BA5A-5B1943A92EA1}' # MSXpsFilters
    '{A6D25EF4-A3B3-4E5F-A872-24E71103FBDC}' # MicrosoftRenderFilter
    '{AEFE45F4-8548-42B4-B1C8-25673B07AD8B}' # PrintFilterPipelinesvc
    '{BE967569-E3C8-425B-AD0E-4F2C790B1848}' # Microsoft-Windows-Graphics-Printing3D
    '{CF3F502E-B40D-4071-996F-00981EDF938E}' # Microsoft-Windows-PrintBRM
    '{E7AA32FB-77D0-477F-987D-7E83DF1B7ED0}' # Microsoft-Windows-Graphics-Printing
    '{7672778D-86FE-41D0-85C8-82CAA8CE6168}' # ESUPDATE(Maybe not used now)
    '{7663DA2F-1594-4C33-83DD-D5C64BBED68A}' # ObjectsGuid
    '{5ED940EB-18F9-4227-A454-8EF1CE5B3272}' # SetupLPR
    '{27239FD0-425E-11D8-9E39-000039252FD8}' # COMMONGuid
    '{04160794-60B6-4EC7-96FF-4953691F94AA}' # SetupIPP
    '{C59DA080-9CCE-4415-A77D-08457D7A059F}' # JScriptLib
    '{19E93940-A1BD-497F-BC58-CA333880BAB4}' # PrintExtension
    '{DD6A31CB-C9C6-4EF9-B738-F306C29352F4}' # MODERNPRINT
    '{3FB15E5D-DF1A-46FC-BEFE-27A4B82D75EE}' # PREFDLG
    '{02EA8EB9-9811-46d6-AEEE-430ADCC2AA18}' # DLGHOST
    '{D3A10B55-1EAD-453d-8FC7-35DA3D6A04D2}' # TCPMIB
    '{B48AE058-218A-4338-9B97-9F5F9E4EB5D2}' # USBJSCRIPT
)

$UEX_TaskProviders = @(
     '{077E5C98-2EF4-41D6-937B-465A791C682E}' # Microsoft-Windows-DesktopActivityBroker
     '{6A187A25-2325-45F4-A928-B554329EBD51}' # Scheduler
     '{047311A9-FA52-4A68-A1E4-4E289FBB8D17}' # TaskEng_JobCtlGuid
     '{10FF35F4-901F-493F-B272-67AFB81008D4}' # UBPM
     '{19043218-3029-4BE2-A6C1-B6763CECB3CC}' # EventAggregation
     '{0dd85d84-97cd-4710-903f-3b28bacbcbd2}' # Microsoft.Windows.TaskScheduler
     '{DE7B24EA-73C8-4A09-985D-5BDADCFA9017}' # Microsoft-Windows-TaskScheduler
     '{6966FE51-E224-4BAA-99BC-897B3ED3B823}' # Microsoft.Windows.BrokerBase
     '{0657ADC1-9AE8-4E18-932D-E6079CDA5AB3}' # Microsoft-Windows-TimeBroker
     '{E8109B99-3A2C-4961-AA83-D1A7A148ADA8}' # System/TimeBroker WPP
)

$UEX_SearchProviders = @(
    '{44e18db2-6cfd-4a07-8fe7-6073794c531a}' # Microsoft.Windows.Search.Indexer
    '{CA4E628D-8567-4896-AB6B-835B221F373F}' # Microsoft-Windows-Search(tquery.dll)
    '{dab065a9-620f-45ba-b5d6-d6bb8efedee9}' # Microsoft-Windows-Search-ProtocolHandlers
    '{49c2c27c-fe2d-40bf-8c4e-c3fb518037e7}' # Microsoft-Windows-Search-Core
    '{FC6F77DD-769A-470E-BCF9-1B6555A118BE}' # Microsoft-Windows-Search-ProfileNotify
)

$UEX_PhotoProviders = @(
    '{054B421C-7DEF-54EF-EF59-41B32C8F94BC}'
    '{6A1E3074-FFEE-5D94-F0B9-F1E92857AC55}'
    '{3C20A2BD-0497-5E1D-AD49-7B789B9D7318}'
    '{1EE9AB78-81DE-5903-9F1B-4C73E2F3501D}'
    '{8F4FD2AF-C8DB-5CC1-27EC-54A4BCF3AAB5}'
    '{EBDDC69C-80FB-5062-B3BA-C203645A72EE}'
    '{DCA2B5B9-047F-5768-688F-9B4C705B541F}'
)

$UEX_AlarmProviders = @(
    '{B333D303-D0C7-4D0B-A417-D331DA97E7D3}' # Microsoft.Windows.AlarmsAndClock
)

$UEX_CalcProviders = @(
    '{0905CA09-610E-401E-B650-2F212980B9E0}' # MicrosoftCalculator
)

$UEX_StoreProviders = @(
    '{53e3d721-2aa0-4743-b2db-299d872b8e3d}' # Microsoft_Windows_Store_Client_UI
    '{945a8954-c147-4acd-923f-40c45405a658}' # Microsoft-Windows-WindowsUpdateClient
    '{9c2a37f3-e5fd-5cae-bcd1-43dafeee1ff0}' # Microsoft-Windows-Store
    '{5F0B026E-BCC1-5001-95D3-65E170A11EFA}' # Microsoft.Store
    '{6938F4E9-4F5F-54FE-EDFF-7D728ACECA12}' # Microsoft.Windows.Store.Partner
    '{9bfa0c89-0339-4bd1-b631-e8cd1d909c41}' # Microsoft.Windows.StoreAgent.Telemetry
    '{FF79A477-C45F-4A52-8AE0-2B324346D4E4}' # Windows-ApplicationModel-Store-SDK
    '{f4b9ce38-744d-4916-b645-f1574e19bbaa}' # Microsoft.Windows.PushToInstall
    '{DD2E708D-F725-5C93-D0D1-91C985457612}' # Microsoft.Windows.ApplicationModel.Store.Telemetry
    '{13020F14-3A73-4DB1-8BE0-679E16CE17C2}' # Microsoft.Windows.Store.LicenseManager.UsageAudit
    '{AF9F58EC-0C04-4BE9-9EB5-55FF6DBE72D7}' # Microsoft.Windows.LicenseManager.Telemetry
    '{4DE9BC9C-B27A-43C9-8994-0915F1A5E24F}' # Microsoft.Windows.AAD
    '{84C5F702-EB27-41CB-AED2-64AA9850C3D0}' # CryptNgcCtlGuid(Until RS4)
    '{B66B577F-AE49-5CCF-D2D7-8EB96BFD440C}' # Microsoft.Windows.Security.NGC.KspSvc
    '{CAC8D861-7B16-5B6B-5FC0-85014776BDAC}' # Microsoft.Windows.Security.NGC.CredProv
    '{6D7051A0-9C83-5E52-CF8F-0ECAF5D5F6FD}' # Microsoft.Windows.Security.NGC.CryptNgc
    '{0ABA6892-455B-551D-7DA8-3A8F85225E1A}' # Microsoft.Windows.Security.NGC.NgcCtnr
    '{9DF6A82D-5174-5EBF-842A-39947C48BF2A}' # Microsoft.Windows.Security.NGC.NgcCtnrSvc
    '{9B223F67-67A1-5B53-9126-4593FE81DF25}' # Microsoft.Windows.Security.NGC.KeyStaging
    '{89F392FF-EE7C-56A3-3F61-2D5B31A36935}' # Microsoft.Windows.Security.NGC.CSP
    '{CDD94AC7-CD2F-5189-E126-2DEB1B2FACBF}' # Microsoft.Windows.Security.NGC.LocalAccountMigPlugin
    '{2056054C-97A6-5AE4-B181-38BC6B58007E}' # Microsoft.Windows.Security.NGC.NgcIsoCtnr
    '{786396CD-2FF3-53D3-D1CA-43E41D9FB73B}' # Microsoft.Windows.Security.CryptoWinRT
    '{9D4CA978-8A14-545E-C047-A45991F0E92F}' # Microsoft.Windows.Security.NGC.Recovery
    '{507C53AE-AF42-5938-AEDE-4A9D908640ED}' # Microsoft.Windows.Security.Credentials.UserConsentVerifier
    '{CDC6BEB9-6D78-5138-D232-D951916AB98F}' # Microsoft.Windows.Security.NGC.NgcIsoCtnr
    '{C0B2937D-E634-56A2-1451-7D678AA3BC53}' # Microsoft.Windows.Security.Ngc.Truslet
    '{34646397-1635-5d14-4d2c-2febdcccf5e9}' # Microsoft.Windows.Security.NGC.KeyCredMgr
    '{3b9dbf69-e9f0-5389-d054-a94bc30e33f7}' # Microsoft.Windows.Security.NGC.Local
    '{1D6540CE-A81B-4E74-AD35-EEF8463F97F5}' # CryptNgcCtlGuid(WPP -> Until RS4)
    '{3A8D6942-B034-48e2-B314-F69C2B4655A3}' # TpmCtlGuid(WPP)
    '{D5A5B540-C580-4DEE-8BB4-185E34AA00C5}' # Microsoft.Windows.DeviceManagement.SCEP
    '{7955d36a-450b-5e2a-a079-95876bca450a}' # Microsoft.Windows.Security.DevCredProv
    '{c3feb5bf-1a8d-53f3-aaa8-44496392bf69}' # Microsoft.Windows.Security.DevCredSvc
    '{78983c7d-917f-58da-e8d4-f393decf4ec0}' # Microsoft.Windows.Security.DevCredClient
    '{36FF4C84-82A2-4B23-8BA5-A25CBDFF3410}' # Microsoft.Windows.Security.DevCredWinRt
    '{5bbca4a8-b209-48dc-a8c7-b23d3e5216fb}' # Microsoft-Windows-CAPI2
    '{73370BD6-85E5-430B-B60A-FEA1285808A7}' # Microsoft-Windows-CertificateServicesClient
    '{F0DB7EF8-B6F3-4005-9937-FEB77B9E1B43}' # Microsoft-Windows-CertificateServicesClient-AutoEnrollment
    '{54164045-7C50-4905-963F-E5BC1EEF0CCA}' # Microsoft-Windows-CertificateServicesClient-CertEnroll
    '{89A2278B-C662-4AFF-A06C-46AD3F220BCA}' # Microsoft-Windows-CertificateServicesClient-CredentialRoaming
    '{BC0669E1-A10D-4A78-834E-1CA3C806C93B}' # Microsoft-Windows-CertificateServicesClient-Lifecycle-System
    '{BEA18B89-126F-4155-9EE4-D36038B02680}' # Microsoft-Windows-CertificateServicesClient-Lifecycle-User
    '{B2D1F576-2E85-4489-B504-1861C40544B3}' # Microsoft-Windows-CertificateServices-Deployment
    '{98BF1CD3-583E-4926-95EE-A61BF3F46470}' # Microsoft-Windows-CertificationAuthorityClient-CertCli
    '{AF9CC194-E9A8-42BD-B0D1-834E9CFAB799}' # Microsoft-Windows-CertPolEng
    '{d0034f5e-3686-5a74-dc48-5a22dd4f3d5b}' # Microsoft-Windows-Shell-CloudExperienceHost
    '{aa02d1a4-72d8-5f50-d425-7402ea09253a}' # Microsoft.Windows.Shell.CloudDomainJoin.Client
    '{9FBF7B95-0697-4935-ADA2-887BE9DF12BC}' # Microsoft-Windows-DM-Enrollment-Provider
    '{3DA494E4-0FE2-415C-B895-FB5265C5C83B}' # Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider
    '{8db3086d-116f-5bed-cfd5-9afda80d28ea}' # Microsoft-OSG-OSS-CredProvFramework
    '{7D44233D-3055-4B9C-BA64-0D47CA40A232}' # Microsoft-Windows-WinHttp
)

$UEX_ContactSupportProviders = @(
    '{B6CC0D55-9ECC-49A8-B929-2B9022426F2A}' # Microsoft-Client-Licensing-Platform-Instrumentation
    '{8127F6D4-59F9-4ABF-8952-3E3A02073D5F}' # Microsoft-Windows-AppXDeployment
    '{3F471139-ACB7-4A01-B7A7-FF5DA4BA2D43}' # Microsoft-Windows-AppXDeployment-Server
    '{8FD4B82B-602F-4470-8577-CBB56F702EBF}' # Microsoft.Windows.AppXDeploymentClient.WPP
    '{FE762FB1-341A-4DD4-B399-BE1868B3D918}' # Microsoft.Windows.AppXDeploymentServer
    '{BA44067A-3C4B-459C-A8F6-18F0D3CF0870}' # DEPLOYMENT_WPP_GUID
    '{B9DA9FE6-AE5F-4F3E-B2FA-8E623C11DC75}' # Microsoft-Windows-SetupPlatform-AutoLogger
    '{9213C3E1-0D6C-52DD-78EA-F3B082111406}' # Microsoft-Windows-PriResources-Deployment
    '{06184C97-5201-480E-92AF-3A3626C5B140}' # Microsoft-Windows-Services-Svchost
    '{89592015-D996-4636-8F61-066B5D4DD739}' # Microsoft.Windows.StateRepository
    '{551FF9B3-0B7E-4408-B008-0068C8DA2FF1}' # Microsoft.Windows.StateRepository.Service
    '{DB00DFB6-29F9-4A9C-9B3B-1F4F9E7D9770}' # Microsoft-Windows-User Profiles General
    '{6AF9E939-1D95-430A-AFA3-7526FADEE37D}' # ClipSvcProvider
    '{B94D76C5-9D56-454A-8D1B-6CA30898160E}' # Microsoft.ClipSvc
    '{9A2EDB8F-5883-499F-ACED-6E4B69D43DDF}' # WldpTraceLoggingProvider
    '{A323CDC2-81B0-48B2-80C8-B749A221478A}' # Castle(WPP)
    '{A74EFE00-14BE-4EF9-9DA9-1484D5473302}' # CNGTraceControlGuid
    '{F0558438-F56A-5987-47DA-040CA75AEF05}' # Microsoft.Windows.WinRtClassActivation
    '{F25BCD2E-2690-55DC-3BC4-07B65B1B41C9}' # Microsoft.Windows.User32
    '{30336ED4-E327-447C-9DE0-51B652C86108}' # Microsoft-Windows-Shell-Core 
    '{1AFF6089-E863-4D36-BDFD-3581F07440BE}' # ComBaseTraceLoggingProvider
    '{6AD52B32-D609-4BE9-AE07-CE8DAE937E39}' # Microsoft-Windows-RPC
    '{F4AED7C7-A898-4627-B053-44A7CAA12FCD}' # Microsoft-Windows-RPC-Events 
    '{A86F8471-C31D-4FBC-A035-665D06047B03}' # Microsoft-Windows-WinRT-Error
    '{BDA92AE8-9F11-4D49-BA1D-A4C2ABCA692E}' # Microsoft-Windows-COMbase
)

$UEX_SpeechProviders = @(
    '{7f02214a-4eb1-50e4-adff-62654d1e42f6}'  # NLClientPlatformAPI
    '{a9da5902-9012-4f82-bdc8-905c88db93ee}'  # Bing-Platform-ConversationalUnderstanding-Client
    '{8eb79eb6-8701-4d39-9196-9efc81a31489}'  # Microsoft-Speech-SAPI
    '{46f27ed9-a8d6-5c0c-8c30-6e846b4c4e46}'  # Windows.ApplicationModel.VoiceCommands.VoiceCommandServiceConnection
    '{70400dee-6c5b-5209-4052-b9f8cf41b7d7}'  # Microsoft.Windows.ReactiveAgentFramework
    '{5656A338-AC25-4E57-93DC-4703091CB85A}'  # Microsoft-Windows-NUI-Audio
    '{E5514D5F-A8E4-4658-B381-63227E390476}'  # Microsoft-WindowsPhone-Speech-Ux
    '{614f2573-da68-5a1b-c2c6-cba6de5de7f8}'  # Microsoft.Windows.Media.Speech.Internal.SoundController.WinRT
    '{E6C38788-C835-4D10-B26E-5920C34E5F20}'  # Microsoft-Speech-WinRT
    '{07f283ce-2538-5e77-44d2-04212575a63d}'  # Microsoft.Windows.Analog.Speech.RecognizerClient
    '{2a8bc2a0-4cf9-5429-c90c-f5cd30dc6dd1}'  # Microsoft.Windows.Analog.Speech.RecognizerServer
)

$UEX_SystemSettingsProviders = @(
    '{c1be8ae8-b6b1-566a-8453-ec627f8eb2de}' # Microsoft.Windows.Shell.MockDataSystemSettings
    '{B7AFA6AF-AAAB-4F50-B7DC-B61D4DDBE34F}' # Microsoft.Windows.Shell.SystemSettings.SettingsAppActivity
    '{8BCDF442-3070-4118-8C94-E8843BE363B3}' # Microsoft-Windows-SystemSettingsThreshold
    '{1EE8CA37-11AE-4815-800E-58D6BAE1FEF9}' # Microsoft.Windows.Shell.SystemSettings.SettingsPane
    '{1ABBDEEA-0CF0-46B1-8EC2-DAAD6F165F8F}' # Microsoft.Windows.Shell.SystemSettings.HotKeyActivation
    '{80B3FF7A-BAB0-4ED1-958C-E89A6D5557B3}' # Microsoft.Windows.Shell.SystemSettings.WorkAccessHandlers
    '{68D9DE11-9358-4C97-8B72-A7CE49EF593C}' # Wi-Fi Calling Logging
    '{0ae9ad8e-d4d3-5486-f015-498e0b6860ef}' # Microsoft.Windows.Shell.SystemSettings.UserPage
    '{44f1a90c-4250-5bab-f09b-df45384c6951}' # Microsoft.Windows.Shell.SystemSettings.RegionSettings
    '{6bee332c-7ddb-5ec2-dec4-91b8be7612f8}' # Microsoft.Windows.Shell.PersonalizeSettingsTelemetry
    '{f323b60d-51ff-5c64-f7d1-f8149e2b3d81}' # Microsoft.Windows.Shell.SystemSettings.Pen
    '{6b2dfe1c-ae63-55d0-edea-60c166860d63}' # Microsoft.Windows.Shell.SystemSettings.OtherPeoplePage
    '{e613a5d7-363e-5200-b311-02b426d8a73b}' # Microsoft.Windows.Desktop.Shell.LanguageFeaturesOnDemandSettings
    '{c442c41d-98c0-4a33-845d-902ed64f695b}' # Microsoft.Windows.TextInput.ImeSettings
    '{9a35425e-61bc-4d68-8542-568a28963abe}' # Microsoft.Windows.Shell.SystemSettings.AdvancedGraphics
    '{ec696ee4-fac7-4df4-9aaa-3862cb16eb4b}' # Microsoft.Windows.Shell.SystemSettings.FontPreview
    '{23cd8d50-ed49-5a0b-4562-65dff962d5f1}' # Microsoft.Windows.Mobile.Shell.DisplaySettings
    '{55f422c8-0aa0-529d-95f5-8e69b6a29c98}' # Microsoft.Windows.Shell.SystemSettings.SignInOptionsPage
    '{e3bfeaae-cb1d-5f12-e2e5-b9d2d7ca7bf0}' # Microsoft.Windows.Shell.SystemSettings.Devices
    '{17d6a222-af97-560b-6f18-389900d6ad1e}' # Microsoft.Windows.Desktop.Shell.LanguagePackInstallSettings
    '{8b5a39e9-7fc8-5ccb-18c9-d410973436a9}' # Microsoft.Windows.Shell.TabShell
    '{56143DD6-AD65-4FB1-972C-6DFA2BEF0916}' # Microsoft.Windows.Shell.SystemSettings.BluetoothHandler
    '{6cd9d548-4f28-5e7c-503d-86e3cd9db63d}' # Microsoft.Windows.DeveloperPlatform.DeveloperOptions
    '{4b82b48e-8625-5aba-2a86-b5266e869e10}' # Microsoft.Windows.Shell.SystemSettings.KeyboardSettings
    '{fc27cce8-72b0-5a6f-8fe3-22bfcfefd495}' # Microsoft.Windows.Shell.SystemSettings.MediaRadioManagerSink
    '{35a6b23c-c542-5414-bc49-b0f81b96a266}' # Microsoft.Windows.Shell.SystemSettings.OneDriveBackup
    '{e2a3ad70-42b5-452c-a113-20476e27e37c}' # Microsoft.Windows.Desktop.Shell.SystemSettingsThreshold.Handlers
    '{3A245D5A-F00F-48F6-A94B-C51CDD290F18}' # Microsoft-Windows-Desktop-Shell-SystemSettingsV2-Handlers
    '{068b0237-1f0a-593a-bc39-5155685f1bef}' # Microsoft.PPI.Settings.AdminFlow
    '{57d940ae-e2fc-55c3-f31b-253c5b172135}' # Microsoft.Windows.Shell.SystemSettings.ManageUser
    '{e6fcf13b-1ab7-4236-823b-0c0cf5c589d5}' # Microsoft.Windows.Upgrade.Uninstall
    '{e881df47-b77c-48c5-b321-1454b88fdd6b}' # Microsoft.Windows.Shell.SystemSettings.ManageOrganization
    '{2e07964e-7d10-5d8e-761d-99b038f42bb6}' # Microsoft.Windows.Shell.SystemSettings.AdminFlow
    '{e881df47-b77c-48c5-b321-1454b88fdd6b}' # Microsoft.Windows.Shell.SystemSettings.ManageOrganization
    '{3e8fb07b-3e10-5981-01a9-fbd924fd5436}' # Microsoft.Windows.Shell.AssignedAccessSettings
    '{a306fcf9-ad27-5c4d-f69a-22506ef908ad}' # Microsoft.Windows.Shell.SystemSettings.RemoteDesktopAdminFlow
)

$UEX_WPNProviders = @(
    '{F0AE506B-805E-434A-A005-7971D555179C}' # Wpn(WPP)
    '{4ff58fbe-3d4d-447a-ac26-7da2c51f4b7d}' # WpnSrum(WPP)
    '{2FDB1F25-8DE1-4BC1-BAC2-E445E5B38743}' # Microsoft.Windows.Notifications.WpnApps
    '{B92D1FF0-92EC-444D-B7EC-C016F971C000}' # Microsoft.Windows.Notifications.WpnCore
    '{EE845016-EBE1-41EB-BE52-5E3AE58339F2}' # WNSCP
    '{833c9bbd-6422-59cb-83bb-c695934a0cf5}' # Microsoft.Windows.PerProcessSystemDpi
    '{5cad3597-5fec-4c62-9ce1-9d7abc723d3a}' # Microsoft-Windows-PushNotifications-Developer
    '{815a1f4a-3f8d-4b37-9b31-5142f9d724a5}' # Microsoft-Windows-PushNotifications-InProc
    '{88cd9180-4491-4640-b571-e3bee2527943}' # Microsoft-Windows-PushNotifications-Platform
    '{eb3540f2-1909-5d51-b72d-a3ecb0b9bf08}' # Microsoft.Windows.Shell.NotificationController
    '{33b3eaa6-d8dd-5096-8687-6f520d32fc9e}' # Microsoft.Windows.Shell.NotificationSettings
    '{4bfe0fde-99d6-5630-8a47-da7bfaefd876}' # Microsoft-Windows-Shell-NotificationCenter
    '{7145ABF9-99F5-4CCF-A2B6-C9B2E05BA8B3}' # Microsoft.Windows.Shell.NotificationQuietHours
    '{ce575084-01be-5ef2-75f2-2d822e70cec9}' # Microsoft.Windows.Internal.Shell.Session.WnfPolicy
    '{1870FBB0-2247-44D8-BF46-B02130A8A477}' # Microsoft.Windows.Notifications.WpnApis
)

$UEX_XAMLProviders = @(
    '{59E7A714-73A4-4147-B47E-0957048C75C4}' # Microsoft-Windows-XAML-Diagnostics
    '{922CDCF3-6123-42DA-A877-1A24F23E39C5}' # Microsoft-WindowsPhone-CoreMessaging
    '{A0B7550F-4E9A-4F03-AD41-B8042D06A2F7}' # Microsoft-WindowsPhone-CoreUIComponents
    '{DB6F6DDB-AC77-4E88-8253-819DF9BBF140}' # Microsoft-Windows-Direct3D11
    '{C44219D0-F344-11DF-A5E2-B307DFD72085}' # Microsoft-Windows-DirectComposition
    '{5786E035-EF2D-4178-84F2-5A6BBEDBB947}' # Microsoft-Windows-DirectManipulation
    '{8360BD0F-A7DC-4391-91A7-A457C5C381E4}' # Microsoft-Windows-DUI
    '{8429E243-345B-47C1-8A91-2C94CAF0DAAB}' # Microsoft-Windows-DUSER
    '{292A52C4-FA27-4461-B526-54A46430BD54}' # Microsoft-Windows-Dwm-Api
    '{CA11C036-0102-4A2D-A6AD-F03CFED5D3C9}' # Microsoft-Windows-DXGI
    '{950D4EDA-1729-47CC-8F1E-D9ED5AA17642}' # Windows.Ui.Xaml
    '{531A35AB-63CE-4BCF-AA98-F88C7A89E455}' # Microsoft-Windows-XAML
)

$UEX_ShutdownProviders = @(
    '{206f6dea-d3c5-4d10-bc72-989f03c8b84b}' # WinInit
    '{e8316a2d-0d94-4f52-85dd-1e15b66c5891}' # CsrEventProvider
    '{9D55B53D-449B-4824-A637-24F9D69AA02F}' # WinsrvControlGuid
    '{dbe9b383-7cf3-4331-91cc-a3cb16a3b538}' # Microsoft-Windows-Winlogon 
    '{e8316a2d-0d94-4f52-85dd-1e15b66c5891}' # Microsoft-Windows-Subsys-Csr
    '{331c3b3a-2005-44c2-ac5e-77220c37d6b4}' # Microsoft-Windows-Kernel-Power
    '{23b76a75-ce4f-56ef-f903-c3a2d6ae3f6b}' # Microsoft.Windows.Kernel.BootEnvironment
    '{a68ca8b7-004f-d7b6-a698-07e2de0f1f5d}' # Microsoft-Windows-Kernel-General
    '{15ca44ff-4d7a-4baa-bba5-0998955e531e}' # Microsoft-Windows-Kernel-Boot
)

$UEX_Win32kProviders = @(
    '{e75a83ec-ef30-4e3c-a5fb-1e7626e48f43}' # Win32kPalmMetrics
    '{72a4952f-db5c-4d90-8f9d-0ed3465b315e}' # Win32kDeadzonePalmTelemetryProvider
    '{7e6b69b9-2aec-4fb3-9426-69a0f2b61a86}' # Microsoft.Windows.Win32kBase.Input
    '{ce20d1cc-faee-4ef6-9bf2-2837cef71258}' # Win32kSyscallLogging
    '{deb96c0a-d2d9-5868-a5d5-50ee13513c8b}' # Microsoft.Windows.Graphics.Display
    '{703fcc13-b66f-5868-ddd9-e2db7f381ffb}' # Microsoft.Windows.TlgAggregateInternal
    '{aad8d3a1-0ce4-4c7e-bf32-15b2836659b7}' # Microsoft.Windows.WER.MTT
    '{6d1b249d-131b-468a-899b-fb0ad9551772}' # TelemetryAssert
    '{03914E49-F3DD-40B9-BB7F-9445BF46D43E}' # Microsoft.Windows.Win32kMin.WPP
    '{0F81EC00-9E52-48E6-B899-EB3BBEEDE741}' # Microsoft.Windows.Win32kBase.WPP
    '{335D5E04-5638-4E58-AA36-7ED1CFE76FD6}' # Microsoft.Windows.Win32kFull.WPP
    '{9C648335-6987-470C-B588-3DE7A6A1FDAC}' # Microsoft.Windows.Win32kNs.WPP
    '{487D6E37-1B9D-46D3-A8FD-54CE8BDF8A53}' # Microsoft.Windows.Win32k.TraceLogging
    '{8C416C79-D49B-4F01-A467-E56D3AA8234C}' # Microsoft.Windows.Win32k.UIF
)

$UEX_FontProviders = @(
    '{8479f1a8-524e-5226-d27e-05636c12b837}' # Microsoft.Windows.Desktop.Fonts.FontManagementSystem
    '{0ae92c9d-6960-566e-221f-5784660d04c3}' # Microsoft.Windows.Fonts.FontEmbedding
    '{E856C26A-E105-4683-A948-6920DCC42E45}' # Microsoft-Windows-DirectWrite-FontCache
    '{487d6e37-1b9d-46d3-a8fd-54ce8bdf8a53}' # Win32kTraceLogging
)

$UEX_AppCompatProviders = @(
    '{EEF54E71-0661-422d-9A98-82FD4940B820}' # Microsoft-Windows-Application-Experience
    '{4CB314DF-C11F-47d7-9C04-65FB0051561B}' # Microsoft-Windows-Program-Compatibility-Assistant
    '{DD17FA14-CDA6-7191-9B61-37A28F7A10DA}' # Microsoft.Windows.Appraiser.General
    '{03A70C9D-084B-4905-B341-F6377E734858}' # Microsoft.Windows.Appraiser.Instrumentation
    '{CAEA06A5-D164-4AFA-8CDF-444E3AE008A0}' # Microsoft.Windows.Appraiser.Critical
    '{F5647876-050D-4CF0-BA2F-C498B41C152A}' # DPIScalingProvider
    '{1f87779d-1ad0-45cd-8d2e-0ac9406bc878}' # Microsoft.Windows.Compatibility.Inventory.Agent
    '{32c3bee9-e3f4-4757-95a3-90e6d43299ec}' # Microsoft.Windows.Compatibility.Inventory.WMI
    '{9EFCB348-D13C-4B3A-8AB1-869AAB424C34}' # Microsoft.Windows.Inventory.General
    '{45D5CCD7-6E27-4318-82DD-69BD83A8F672}' # Microsoft.Windows.Inventory.Indicators
    '{407C75AC-661F-4C74-A4B0-ACDD9A643E42}' # Microsoft.Windows.PCA.PushApphelp
    '{95ABB8AF-1790-48BD-85AC-5FEED398DD9E}' # Microsoft.Windows.PCA.Siuf
    '{511A5C98-B374-446E-9625-108624A3CCAA}' # Microsoft.Windows.Compatibility.PCA
    '{74791F71-8F1E-4D6A-AA73-AE7FB15B0D24}' # Microsoft.Windows.AppHelp.Dialog
    '{E7558269-3FA5-46ed-9F4D-3C6E282DDE55}' # Microsoft-Windows-UAC
    '{b059b83f-d946-4b13-87ca-4292839dc2f2}' # Microsoft-Windows-User-Loader 
    '{c02afc2b-e24e-4449-ad76-bcc2c2575ead}' # Microsoft-Windows-UAC-FileVirtualization
    '{AD8AA069-A01B-40A0-BA40-948D1D8DEDC5}' # Microsoft-Windows-WER-Diagnostics
)

$UEX_MediaProviders = @(
    '{F3F14FF3-7B80-4868-91D0-D77E497B025E}' # Microsoft-Windows-WMP
    '{AE4BD3BE-F36F-45B6-8D21-BDD6FB832853}' # Microsoft-Windows-Audio
    '{7C314E58-8246-47D1-8F7A-4049DC543E0B}' # Microsoft-Windows-WMPNSSUI
    '{614696C9-85AF-4E64-B389-D2C0DB4FF87B}' # Microsoft-Windows-WMPNSS-PublicAPI
    '{BE3A31EA-AA6C-4196-9DCC-9CA13A49E09F}' # Microsoft-Windows-Photo-Image-Codec
    '{02012A8A-ADF5-4FAB-92CB-CCB7BB3E689A}' # Microsoft-Windows-ShareMedia-ControlPanel
    '{B20E65AC-C905-4014-8F78-1B6A508142EB}' # Microsoft-Windows-MediaFoundation-Performance-Core
    '{3F7B2F99-B863-4045-AD05-F6AFB62E7AF1}' # Microsoft-Windows-TerminalServices-MediaRedirection
    '{42D580DA-4673-5AA7-6246-88FDCAF5FFBB}' # Microsoft.Windows.CastQuality
    '{1F930302-F484-4E01-A8A7-264354C4B8E3}' # Microsoft.Windows.Cast.MiracastLogging
    '{596426A4-3A6D-526C-5C63-7CA60DB99F8F}' # Microsoft.Windows.WindowsMediaPlayer	
    '{E27950EB-1768-451F-96AC-CC4E14F6D3D0}' # AudioTrace
    '{A9C1A3B7-54F3-4724-ADCE-58BC03E3BC78}' # Windows Media Player Trace
    '{E2821408-C59D-418F-AD3F-AA4E792AEB79}' # SqmClientTracingGuid
    '{6E7B1892-5288-5FE5-8F34-E3B0DC671FD2}' # Microsoft.Windows.Audio.Client
    '{AAC97853-E7FC-4B93-860A-914ED2DEEE5A}' # MediaServer
    '{E1CCD9F8-6E9F-43ad-9A32-8DBEBE72A489}' # WMPDMCCoreGuid
    '{d3045008-e530-485e-81b7-c6d54dbd9044}' # CTRLGUID_EVR_WPP
    '{00000000-0dc9-401d-b9b8-05e4eca4977e}' # CTRLGUID_MF_PLATFORM
    '{00000001-0dc9-401d-b9b8-05e4eca4977e}' # CTRLGUID_MF_PIPELINE
    '{00000002-0dc9-401d-b9b8-05e4eca4977e}' # CTRLGUID_MF_CORE_SINKS
    '{00000003-0dc9-401d-b9b8-05e4eca4977e}' # CTRLGUID_MF_CORE_SOURCES
    '{00000004-0dc9-401d-b9b8-05e4eca4977e}' # CTRLGUID_MF_NETWORK
    '{00000005-0dc9-401d-b9b8-05e4eca4977e}' # CTRLGUID_MF_CORE_MFTS
    '{00000006-0dc9-401d-b9b8-05e4eca4977e}' # CTRLGUID_MF_PLAY
    '{00000007-0dc9-401d-b9b8-05e4eca4977e}' # CTRLGUID_MF_CAPTURE_ENGINE
    '{00000008-0dc9-401d-b9b8-05e4eca4977e}' # CTRLGUID_MF_VIDEO_PROCESSOR
    '{C9C074D2-FF9B-410F-8AC6-81C7B8E60D0F}' # MediaEngineCtrlGuid
    '{982824E5-E446-46AE-BC74-836401FFB7B6}' # Microsoft-Windows-Media-Streaming
    '{8F2048E0-F260-4F57-A8D1-932376291682}' # Microsoft-Windows-MediaEngine
    '{8F0DB3A8-299B-4D64-A4ED-907B409D4584}' # Microsoft-Windows-Runtime-Media
    '{DD2FE441-6C12-41FD-8232-3709C6045F63}' # Microsoft-Windows-DirectAccess-MediaManager
    '{D2402FDE-7526-5A7B-501A-25DC7C9C282E}' # Microsoft-Windows-Media-Protection-PlayReady-Performance
    '{B8197C10-845F-40CA-82AB-9341E98CFC2B}' # Microsoft-Windows-MediaFoundation-MFCaptureEngine
    '{4B7EAC67-FC53-448C-A49D-7CC6DB524DA7}' # Microsoft-Windows-MediaFoundation-MFReadWrite
    '{A4112D1A-6DFA-476E-BB75-E350D24934E1}' # Microsoft-Windows-MediaFoundation-MSVProc
    '{F404B94E-27E0-4384-BFE8-1D8D390B0AA3}' # Microsoft-Windows-MediaFoundation-Performance
    '{BC97B970-D001-482F-8745-B8D7D5759F99}' # Microsoft-Windows-MediaFoundation-Platform
    '{B65471E1-019D-436F-BC38-E15FA8E87F53}' # Microsoft-Windows-MediaFoundation-PlayAPI
    '{323DAD74-D3EC-44A8-8B9D-CAFEB4999274}' # Microsoft-Windows-WLAN-MediaManager
    '{F4C9BE26-414F-42D7-B540-8BFF965E6D32}' # Microsoft-Windows-WWAN-MediaManager
    '{4199EE71-D55D-47D7-9F57-34A1D5B2C904}' # TSMFTrace
    '{A9C1A3B7-54F3-4724-ADCE-58BC03E3BC78}' # CtlGuidWMP
    '{3CC2D4AF-DA5E-4ED4-BCBE-3CF995940483}' # Microsoft-Windows-DirectShow-KernelSupport
    '{968F313B-097F-4E09-9CDD-BC62692D138B}' # Microsoft-Windows-DirectShow-Core
    '{9A010476-792D-57BE-6AF9-8DE32164F021}' # Microsoft.Windows.DirectShow.FilterGraph
    '{E5E16361-C9F0-4BF4-83DD-C3F30E37D773}' # VmgTraceControlGuid
    '{A0386E75-F70C-464C-A9CE-33C44E091623}' # DXVA2 (DirectX Video Acceleration 2)
    '{86EFFF39-2BDD-4EFD-BD0B-853D71B2A9DC}' # Microsoft-Windows-MPEG2_DLNA-Encoder
    '{AE5CF422-786A-476A-AC96-753B05877C99}' # Microsoft-Windows-MSMPEG2VDEC 
    '{51311DE3-D55E-454A-9C58-43DC7B4C01D2}' # Microsoft-Windows-MSMPEG2ADEC
    '{0A95E01D-9317-4506-8796-FB946ACD7016}' # CodecLogger
    '{EA6D6E3B-7014-4AB1-85DB-4A50CDA32A82}' # Codec
    '{7F2BD991-AE93-454A-B219-0BC23F02262A}' # Microsoft-Windows-MP4SDECD
    '{2A49DE31-8A5B-4D3A-A904-7FC7409AE90D}' # Microsoft-Windows-MFH264Enc
    '{55BACC9F-9AC0-46F5-968A-A5A5DD024F8A}' # Microsoft-Windows-wmvdecod
    '{313B0545-BF9C-492E-9173-8DE4863B8573}' # Microsoft-Windows-WMVENCOD
    '{3293F985-41D3-4B6A-B187-2FF4AA91F2FC}' # Multimedia-HEVCDECODER / Microsoft-OneCore-Multimedia-HEVCDECODER
    '{D17B213A-C505-49C9-98CC-734253EF65D4}' # Microsoft-Windows-msmpeg2venc
    '{B6C06841-5C8C-47A6-BEDE-6159F4D4A701}' # MyDriver1TraceGuid
    '{E80ADCF1-C790-4108-8BB9-8A5CA3466C04}' # Microsoft-Windows-TerminalServices-RDP-AvcSoftwareDecoder
    '{3f7b2f99-b863-4045-ad05-f6afb62e7af1}' # Microsoft-Windows-TerminalServices-MediaRedirection(tsmf.dll)
)

$UEX_VANProviders = @(
    '{111FFC99-3987-4bf8-8398-61853120CB3D}' # PNIandNetcenterGUID
    '{9A59814D-6DF5-429c-BD0D-2D41B4A5E9D3}' # PNIandNetcenterGUID
    '{2c929297-cd5c-4187-b508-51a2754a95a3}' # VAN WPP
    '{e6dec100-4e0f-4927-92be-e69d7c15c821}' # WlanMM WPP
)

$UEX_UserDataAccessProviders = @(
    '{D1F688BF-012F-4AEC-A38C-E7D4649F8CD2}' # Microsoft-Windows-UserDataAccess-UserDataUtils
    '{fb19ee2c-0d22-4a2e-969e-dd41ae0ce1a9}' # Microsoft-Windows-UserDataAccess-UserDataService
    '{56f519ab-9df6-4345-8491-a4ba21ac825b}' # Microsoft-Windows-UserDataAccess-UnifiedStore
    '{99C66BA7-5A97-40D5-AA01-8A07FB3DB292}' # Microsoft-Windows-UserDataAccess-PimIndexMaintenance
    '{B9B2DE3C-3FBD-4F42-8FF7-33C3BAD35FD4}' # Microsoft-Windows-UserDataAccess-UserDataApis
    '{0BD19909-EB6F-4b16-8074-6DCE803F091D}' # Microsoft-Windows-UserDataAccess-Poom
    '{83A9277A-D2FC-4b34-BF81-8CEB4407824F}' # Microsoft-Windows-UserDataAccess-CEMAPI
    '{f5988abb-323a-4098-8a34-85a3613d4638}' # Microsoft-Windows-UserDataAccess-CallHistoryClient
    '{15773AD5-AA2F-422A-9129-4A83F4C19DB0}' # Microsoft.Windows.UserDataAccess.UserDataService
    '{cb76d769-a1ed-4fb1-98c3-266951610fd8}' # Microsoft.Windows.UserDataAccess.Unistore
    '{0a0a7808-8dda-4ba0-a656-b2c740ab9108}' # Microsoft.Windows.UserDataAccess.UserDataApisBase
    '{553ebe04-ceb2-47ee-b394-bb83b97de219}' # Microsoft.Windows.UserDataAccess.UserDataAccounts
    '{d6eac963-c24f-434d-be23-4aa21904148f}' # Microsoft.Windows.UserDataAccess.TaskApis
    '{ee3112cb-4b76-49eb-a73b-712ad05e18cb}' # Microsoft.Windows.UserDataAccess.EmailApis
    '{3f7fafe6-1dd2-4720-b75b-e3268a0e6120}' # Microsoft.Windows.UserDataAccess.ContactApis
    '{412f73f7-ebf9-466f-90e7-606accdbcd15}' # Microsoft.Windows.UserDataAccess.Cemapi
    '{a94f431e-5460-465f-bf2e-6245b56d6ce9}' # Microsoft.Windows.UserDataAccess.AppointmentApis
    '{E0A18F5C-07F3-4A44-B149-0F8F13EF6887}' # Microsoft.Windows.ApplicationModel.Chat.ChatMessageBlocking
    '{FCC174D3-8890-434A-812D-BDED72EDE356}' # Microsoft.Windows.Unistack.FailureTrigger
    '{870ac05a-7777-5c66-c3f0-c1f6b7129ef6}' # Microsoft.Windows.Messaging.Service
    '{1e2462be-b025-48da-8c1f-7b60b8ccae53}' # microsoft-windows-appmodel-messagingdatamodel
    '{3da5aa05-5152-551f-a243-80a4e743c70e}' # Microsoft.Windows.Messaging.App
)

$UEX_WMIBridgeProviders = @(
    '{A76DBA2C-9683-4BA7-8FE4-C82601E117BB}' # Microsoft.Windows.DeviceManagement.WmiBridge
)

$UEX_WERProviders = @(
    '{E46EEAD8-0C54-4489-9898-8FA79D059E0E}' # Microsoft-Windows-Feedback-Service-TriggerProvider
    '{2E4201B6-4891-4912-A139-23268D5EB46E}' # WerFaultTracingGuid
    '{31EC0DFD-E734-4181-9C80-C9974C40BCEB}' # TpClientWppGuid
    '{36082273-7635-44A5-8D35-D2A266538B00}' # WerMgrTracingGuid
    '{3E19A300-75D9-4027-86BA-948B70416220}' # WerConsoleTracingGuid
    '{5EF9EC44-FB87-4F51-AF4E-CED084013281}' # FaultRepTracingGuid
    '{6851ADEB-79DA-4250-A440-F1F52D28711D}' # WerSvcTracingGuid
    '{75638A28-E9ED-42B2-9F8F-C2B1F89CF5EE}' # InfraTracingGuid
    '{7930F74B-E328-4350-89C6-11FD93771488}' # WerFaultTracingGuid
    '{9760D9C2-2FBF-4CDA-889F-8DAB2BDD98B0}' # DWTracingGuid
    '{A0EF609D-0A14-424C-9270-3B2691A0A394}' # ErcLuaSupportTracingGuid
    '{DC02AB24-0AA6-4499-8D86-A8E5F83741F5}' # HangRepTracingGuid
    '{E2821408-C59D-418F-AD3F-AA4E792AEB79}' # SqmClientTracingGuid
    '{F904D5CC-2CCA-47B0-A3CE-A05944692545}' # WerFaultSilentProcessExitLibTracingGuid
    '{FCD00FEF-04FA-41C0-889E-AE613D97602B}' # WerUITracingGuid
    '{1377561D-9312-452C-AD13-C4A1C9C906E0}' # FaultReportingTracingGuid
    '{CC79CF77-70D9-4082-9B52-23F3A3E92FE4}' # WindowsErrorReportingTracingGuid
    '{97945555-b04c-47c0-b399-e453d509a5f0}' # WERSecureVerticalTracingGuid
    '{2b87e57e-7bd0-43a3-a278-02e62d59b2b1}' # WERVerticalTracingGuid
    '{3E0D88DE-AE5C-438A-BB1C-C2E627F8AECB}' # HangReporting
    '{4A743CBB-3286-435C-A674-B428328940E4}' # PSMTracingGuid
    '{D2440861-BF3E-4F20-9FDC-E94E88DBE1F6}' # BrokerInfrastructureWPP
    '{9C6FC32A-E17A-11DF-B1C4-4EBADFD72085}' # PLM WPP tracing
    '{EB65A492-86C0-406A-BACE-9912D595BD69}' # Microsoft-Windows-AppModel-Exec
)

$UEX_ClipboardProviders = @(
    '{f917a1ee-0a04-5157-9a8b-9ba716e318cb}' # Microsoft.Windows.ClipboardHistory.UI
    '{e0be2aaa-b6c3-5f17-4e86-1cde27b51ac1}' # Microsoft.Windows.ClipboardHistory.Service
    '{28d62fb0-2131-41d6-84e8-e2325867964c}' # Microsoft.Windows.AppModel.Clipboard
    '{3e0e3a92-b00b-4456-9dee-f40aba77f00e}' # Microsoft.Windows.OLE.Clipboard
    '{A29339AD-B137-486C-A8F3-88C9738E5379}' # Microsoft.Windows.ApplicationModel.DataTransfer.CloudClipboard
    '{ABB10A7F-67B4-480C-8834-8B049C428715}' # Microsoft.Windows.CDP.Core
    '{796F204A-44FC-47DF-8AE4-77C210BD5AF4}' # RdpClip
)

$UEX_MMCProviders = @(
    '{9C88041D-349D-4647-8BFD-2C0A167BFE58}' # MMC
)

$UEX_QuickAssistProviders = @(
    '{91558F59-B78A-4994-8B64-8067B33BDD71}' # Microsoft.RemoteAssistance
)

$UEX_FSLogixProviders = @(
    '{9a2c09eb-fbd6-5127-090f-402799cb18a2}' # Microsoft.FSLogix.Frxsvc
    '{5f7d6ea0-7bfa-5c0a-4674-acce76757f19}' # Microsoft.FSLogix.Frxccds
    '{83afe79f-c9c6-5152-3636-05de47c1fa72}' # Microsoft.FSLogix.Search
    '{65fa0e9f-db27-5053-a4e0-e40c42ba5271}' # Microsoft.FSLogix.UsermodeDll
    '{578c4cac-e98c-5315-f3e6-fbc0a97b286f}' # Microsoft.FSLogix.ConfigurationTool
    '{048a4a25-ff60-5d27-8f58-71c0f9d3fc92}' # Microsoft.FSLogix.RuleEditor
    '{f1a8d80a-2d4d-5dfc-7c26-88b5cce761c9}' # Microsoft.FSLogix.JavaRuleEditor
    '{6d14bf0a-be6f-592f-cbcc-61b5e8d18c5c}' # Microsoft.FSLogix.IE_Plugin
    '{f9317b16-badc-55b3-a0cf-9a0a126e12fd}' # Microsoft.FSLogix.FrxLauncher
    '{220d0827-a763-50ac-6999-a59a7ca5d316}' # Microsoft.FSLogix.TrayTool
    '{e5cd7d19-e708-5957-ba97-11858c57eb80}' # Microsoft.FSLogix.Frxdrvvt
    '{6352de6a-8fc2-5afe-a709-fb70e825dc24}' # Microsoft.FSLogix.Frxdrv
    '{becf2b11-c4a9-5e4c-e0d2-c22092799316}' # Microsoft.FSLogix.Diagnostic
    '{5d97526b-4987-550f-4bee-347e84c5a5c6}' # Microsoft.FSLogix.Frxccd
    '{EE5D17C5-1B3E-4792-B0F9-F8C5FC6AC22A}' # Azure Storage
)

$UEX_WSCProviders = @(
    '{1B0AC240-CBB8-4d55-8539-9230A44081A5}' # SecurityCenter
    '{9DAC2C1E-7C5C-40eb-833B-323E85A1CE84}' # WSCInterop
    '{e6b5b34f-bd4d-5cdc-8346-ef4dc6cf1927}' # Microsoft.Windows.Security.WSC
    '{6d357dbe-57a2-5317-7970-19192e402ae6}' # Microsoft.Windows.Defender.Shield
    '{3a47280f-ef8d-41af-9288-64db7a9890d3}' # Microsoft.Windows.Defender.SecurityHealthAgent
    '{7a01e7fb-b6a4-4585-b1a8-ea2094ecb4c5}' # Microsoft.Antimalware.Scan.Interface
)

$UEX_LicenseManagerProviders = @(
    '{5e30c57a-8730-4809-945e-0d5df7aa58e5}' # Microsoft.ClientLicensing.InheritedActivation
    '{CFBEA673-BF20-4BD8-B595-29B82D43DF39}' # Microsoft.ClipUp
    '{466F3B39-9929-45E6-B891-D867BD20B738}' # Microsoft.Windows.Licensing.UpgradeSubscription
    '{B94D76C5-9D56-454A-8D1B-6CA30898160E}' # Microsoft.ClipSvc
    '{4b0cf5b8-5962-479b-9635-7dfb7c8265bc}' # ClipCLoggingProvider
    '{961d7772-0a35-4869-89ad-056fbfc0e51f}' # Microsoft.Windows.LicensingCSP
    '{B4B126DE-32FE-4591-9AC5-B0778D79A0E7}' # Microsoft.ClipSp
    '{ED0C10A5-5396-4A96-9EE3-6F4AA0D1120D}' # Microsoft.ClipC
)

$UEX_ServerManagerProviders = @(
    '{C2E6D0D9-5DF8-4C77-A82B-C96C84579543}' # Microsoft-Windows-ServerManager-ManagementProvider
    '{D8D37081-10BD-4A89-A971-1CDA6899BDB3}' # Microsoft-Windows-ServerManager-MultiMachine
    '{66AF9A38-2D94-11E0-A076-8534E0D72085}' # Microsoft-Windows-ServerManager-DeploymentProvider
    '{6e27f02d-8a55-477e-88b5-6f1ba07e14b4}' # Microsoft-Windows-ServerManager-ConfigureSMRemoting
)

$UEX_WVDProviders = @(
    '{C3B02229-FF93-4D28-ACFC-4FB28AC6CDB5}' # RdClientWinRT
    '{97A820E5-5F64-4573-8114-99B450D0B067}' # RDCoreApp
    '{6FA2A01C-9F89-474B-A71A-A783925EFE45}' # RDCoreNanoCom
    '{CA341B3C-B9D2-4D0F-9BD3-D88183596DB9}' # RDP.ServerStack.Diagnostics
    '{6CBE573A-121B-4E02-A09D-6C0B6B96D676}' # RDP.ServerStack.QOE
    '{50134CDD-5FE1-4315-8C8D-50900921ACCE}' # Microsoft.Windows.HVSI.RDP
    '{080656C2-C24F-4660-8F5A-CE83656B0E7C}' # Microsoft.Windows.RemoteDesktop.ClientCore
    '{48EF6C18-022B-4394-BEE5-7B822B42AE4C}' # Microsoft.RDS.Windows.Client.MSRDC
    '{335934AA-6DD9-486C-88A5-F8D6A7D2BAEF}' # Microsoft.RDS.Windows.Client.AX
    '{43471865-f3ee-5dcf-bf8b-193fcbbe0f37}' # Microsoft.Windows.RemoteDesktopServices.RailPlugin
    '{FB9FF164-54F0-43DD-BF86-1C761FAB3052}' # msrdcsh
    '{E80ADCF1-C790-4108-8BB9-8A5CA3466C04}' # Microsoft-Windows-TerminalServices-RDP-AvcSoftwareDecoder
    '{eb6594d8-6fad-53f7-350e-f4e4c531f68c}' # Microsoft.Windows.RDP.NamedPipe
    '{7756e5a6-21b2-4c40-855e-88cf2b13c7cb}' # RDP.MSTSCAXTelemetry
    '{76de1e7b-74d5-575e-1f81-4ffe6a42777b}' # RDWin32ClientAxTelemetryProvider
    '{D953B8D8-7EA7-44B1-9EF5-C34AF653329D}' # RDP.Graphics
    '{8A633D91-8B07-4AAE-9A00-D07E2AFD29D6}' # RDP.Transport
    '{a8f457b8-a2b8-56cc-f3f5-3c00430937bb}' # RDPEmulationTraceLogging
    '{93C56D9B-7FDB-4E06-8DED-26000EEE0F60}' # MSTSCFeedbackHub
    '{4f50731a-89cf-4782-b3e0-dce8c90476ba}' # Microsoft Telemetry provider group
    '{140C2428-F60D-43F9-9B07-3E5F622438A0}' # CacNxTraceGuid(WPP)
    '{eca5427c-f28f-4942-a54b-7e86da46bdbe}' # TSUrbUtils(WPP)
    '{7211ae02-1eb0-454a-88fa-ea16632dcb45}' # TSUsbBusFilter(WPP)
    '{39a585ff-6c36-492b-93c0-35b71e65a345}' # TSUsbGenericDriver(WPP)
    '{a0674fb6-ba0d-456f-b079-a2b029d8342c}' # TSUsbHubTrace(WPP)
    '{48738267-0545-431d-8087-7349127811d0}' # TSUsbRedirectionServiceTrace(WPP)
)

$UEX_MSRAProviders = @(
    '{5b0a651a-8807-45cc-9656-7579815b6af0}' # Microsoft-Windows-RemoteAssistance
    '{BBBC81CF-E219-469C-A405-F820EE496194}' # Microsoft-Windows-P2P-PNRP
)

$UEX_DMProviders = @(
    '{9bfa0c89-0339-4bd1-b631-e8cd1d909c41}' # Microsoft.Windows.StoreAgent.Telemetry
    '{E0C6F6DE-258A-50E0-AC1A-103482D118BC}' # Microsoft-Windows-Install-Agent
    '{F36F2574-AC04-4A3D-8263-B97DA864B0BC}' # Microsoft-WindowsPhone-EnrollmentClient-Provider
    '{0e71a49b-ca69-5999-a395-626493eb0cbd}' # Microsoft.Windows.EnterpriseModernAppManagement
    '{16EAA7BB-5B6E-4615-BF44-B8195B5BF873}' # Microsoft.Windows.EnterpriseDesktopAppManagement
    '{FADD8651-7B42-423F-B37D-3B98B9E81560}' # Microsoft.Windows.DeviceManagement.SyncMLDpu
    '{18F2AB69-92B9-47E4-B9DB-B4AC2E4C7115}' # Microsoft.Windows.DeviceManagement.WAPDpu
    '{F9E3B648-9AF1-4DC3-9A8E-BF42C0FBCE9A}' # Microsoft.Windows.EnterpriseManagement.Enrollment
    '{E74EFD1A-B62D-4B83-AB00-66F4A166A2D3}' # Microsoft.Windows.EMPS.Enrollment
    '{0BA3FB88-9AF5-4D80-B3B3-A94AC136B6C5}' # Microsoft.Windows.DeviceManagement.ConfigManager2
    '{76FA08A3-6807-48DB-855D-2C12702630EF}' # Microsoft.Windows.EnterpriseManagement.ConfigManagerHook
    '{FFDB0CFD-833C-4F16-AD3F-EC4BE3CC1AF5}' # Microsoft.Windows.EnterpriseManagement.PolicyManager
    '{5AFBA129-D6B7-4A6F-8FC0-B92EC134C86C}' # Microsoft.Windows.EnterpriseManagement.DeclaredConfiguration
    '{F058515F-DBB8-4C0D-9E21-A6BC2C422EAB}' # Microsoft.Windows.DeviceManagement.SecurityPolicyCsp
    '{33466AA0-09A2-4C47-9B7B-1B8A4DC3A9C9}' # Microsoft-Windows-DeviceManagement-W7NodeProcessor
    '{F5123688-4272-436C-AFE1-F8DFA7AB39A8}' # Microsoft.Windows.DeviceManagement.DevDetailCsp
    '{FE5A93CC-0B38-424A-83B0-3C3FE2ACB8C9}' # Microsoft.Windows.DeviceManagement.DevInfo
    '{E1A8D70D-11F0-420E-A170-29C6B686342D}' # Microsoft.Windows.DeviceManagement.DmAccCsp
    '{6222F3F1-237E-4B0F-8D12-C20072D42197}' # Microsoft.Windows.EnterpriseManagement.ResourceManagerUnenrollHook
    '{6B865228-DEFA-455A-9E25-27D71E8FE5FA}' # Microsoft.Windows.EnterpriseManagement.ResourceManager
    '{797C5746-634F-4C59-8AE9-93F900670DCC}' # Microsoft.Windows.DeviceManagement.OMADMPRC
    '{0EC685CD-64E4-4375-92AD-4086B6AF5F1D}' # Microsoft.Windows.DeviceManagement.OmaDmClient
    '{F3B5BC3C-A182-4F7D-806D-070012D8D16D}' # Microsoft.Windows.DeviceManagement.SessionManagement
    '{86625C04-72E1-4D36-9C86-CA142FD0A946}' # Microsoft.Windows.DeviceManagement.OmaDmApiProvider
    '{22111816-32de-5f2f-7260-2e7c4a7899ce}' # Microsoft.Windows.Shell.Personalization.CSP
)

$UEX_ImmersiveUIProviders = @(
    '{74827cbb-1e0f-45a2-8523-c605866d2f22}' # Microsoft-Windows-WindowsUIImmersive
    '{ee818f02-698c-48be-8ff2-326c6dd34db5}' # SystemInitiatedFeedbackLoggingProvider
    '{EE9969D1-3438-42EA-B879-1AA52A135844}' # HostingFramework
    '{7D45E281-B342-4B07-9061-43056E1C4BA4}' # PopupWindow
    '{239d82f3-77e1-541b-2cbc-50274c47b5f7}' # Microsoft.Windows.Shell.BridgeWindow
    '{f8e28969-b1df-57fa-23f6-42260c77135c}' # Microsoft.Windows.ImageSanitization
    '{46668d11-2db1-5756-2a4b-98fce8b0375f}' # Microsoft.Windows.Shell.Windowing.LightDismiss
    '{9dc9156d-fbd5-5780-bd80-b1fd208442d6}' # Windows.UI.Popups
    '{1941DE80-2226-413B-AFA4-164FD76914C1}' # Microsoft.Windows.Desktop.Shell.WindowsUIImmersive.LockScreen
    '{D3F64994-CCA2-4F97-8622-07D451397C09}' # MicrosoftWindowsShellUserInfo
)

$UEX_SCMProviders = @(
    '{0063715b-eeda-4007-9429-ad526f62696e}' # Microsoft-Windows-Services
    '{06184c97-5201-480e-92af-3a3626c5b140}' # Microsoft-Windows-Services-Svchost
    '{555908D1-A6D7-4695-8E1E-26931D2012F4}' # Service Control Manager
    '{b8ddcea7-b520-4909-bceb-e0170c9f0e99}' # ScmTraceLoggingGuid
    '{EBCCA1C2-AB46-4A1D-8C2A-906C2FF25F39}' # ScmWppLoggingGuid
    '{06184c97-5201-480e-92af-3a3626c5b140}' # Microsoft.Windows.SvchostTelemetryProvider
)

$UEX_CameraProviders = @(
    '{e647b5bf-99a4-41fe-8789-56c6bb3fa9c8}' # Microsoft.Windows.Apps.Camera
    '{f4296e10-4a0a-506c-7899-eb93382208e6}' # Microsoft.Windows.Apps.Camera
    '{EF00584A-2655-462C-BC24-E7DE630E7FBF}' # Microsoft.Windows.AppLifeCycle
    '{4f50731a-89cf-4782-b3e0-dce8c90476ba}' # TraceLoggingOptionMicrosoftTelemetry
    '{c7de053a-0c2e-4a44-91a2-5222ec2ecdf1}' # TraceLoggingOptionWindowsCoreTelemetry
    '{B8197C10-845F-40ca-82AB-9341E98CFC2B}' # Microsoft-Windows-MediaFoundation-MFCaptureEngine
    '{B20E65AC-C905-4014-8F78-1B6A508142EB}' # Microsoft-Windows-MediaFoundation-Performance-Core
    '{548C4417-CE45-41FF-99DD-528F01CE0FE1}' # Microsoft-Windows-Ks(Kernel Streaming)
    '{8F0DB3A8-299B-4D64-A4ED-907B409D4584}' # Microsoft-Windows-Runtime-Media
    '{A4112D1A-6DFA-476E-BB75-E350D24934E1}' # Microsoft-Windows-MediaFoundation-MSVProc
    '{AE5C851E-B4B0-4F47-9D6A-2B2F02E39A5A}' # Microsoft.Windows.Sensors.SensorService
    '{A676B545-4CFB-4306-A067-502D9A0F2220}' # PlugPlayControlGuid
)

$UEX_ESENTProviders = @(
    '{478EA8A8-00BE-4BA6-8E75-8B9DC7DB9F78}' # Microsoft-ETW-ESE
    '{02f42b1b-4b78-48ce-8cdf-d98f8b443b93}' # Microsoft.Windows.ESENT.TraceLogging
)

$UEX_CloudSyncProviders = @(
    '{278c595e-310c-5d49-0cca-546ce8745f9e}' # Microsoft.Windows.Shell.SyncOperation
    '{c906ed7b-d3d9-435b-97cd-22f4e7445f2a}' # Microsoft.Windows.WorkFolders
    '{885735DA-EFA7-4042-B9BC-195BDFA8B7E7}' # Microsoft.Windows.BackupAndRoaming.AzureSyncEngine
    '{95EA8EB8-6F34-45BC-8FA3-BAFEAF6C9915}' # Microsoft.Windows.BackupAndRoaming.SyncEngine
    '{49B5ED52-D5A9-47A6-9BFB-4C6C6AA200CE}' # Microsoft.Windows.BackupAndRoaming.Diagnostics
    '{40BA871E-4C49-41BC-A90C-753FF294F160}' # Microsoft.Windows.BackupAndRoaming.SyncOperations
    '{06ee5c69-51c7-5ebe-0c8f-a049cc071d3f}' # Microsoft.Windows.BackupAndRoaming.AzureWilProvider
    '{D84556B5-1EBE-5073-BCBE-F34AFDF8094D}' # Microsoft.Windows.SettingSync.AzureTracingProvide
    '{3c1be35c-79fd-55ec-2d51-2d7b19e1d377}' # Microsoft.Windows.BackupAndRoaming.WilProvider
    '{83D6E83B-900B-48a3-9835-57656B6F6474}' # Microsoft-Windows-SettingSync
    '{1284e99b-ff7a-405a-a60f-a46ec9fed1a7}' # MSF_MDS_ESE_WPP_CONTROL_GUID
    '{111157cb-ee69-427f-8b4e-ef0feaeaeef2}' # ECS_WPP_CONTROL_GUID
)

$UEX_DeviceStoreProviders = @(
    '{F7155847-D7FA-413A-809F-CFB02894905C}' # Microsoft\Shell\DeviceCenter
)

$UEX_RDWebRTCProviders = @(
    '{E75983D3-3045-49D7-9E5D-6E7EECC45261}' # RDPWebRTCRedirectorClient
    '{AAA1F55E-F99C-45CB-B318-FAEB798DB8E0}' # RDPWebRTCRedirectorHost
    '{2EFD4CDE-32FD-4A55-A310-2DB9A49D4262}' # CTRLGUID_RDC_WEBRTC_REDIRECTOR
)

$UEX_AppIDProviders = @(
    '{1C15C3C7-20B4-446C-8D5E-3BBEC6461664}' # AppIDLog
    '{3CB2A168-FE19-4A4E-BDAD-DCF422F13473}' # Microsoft-Windows-AppID
    '{D02A9C27-79B8-40D6-9B97-CF3F8B7B5D60}' # Microsoft-Windows-AppIDServiceTrigger
    '{CBDA4DBF-8D5D-4F69-9578-BE14AA540D22}' # Microsoft-Windows-AppLocker
    '{77FE4532-3F5C-5786-632B-FB3201BCE29B}' # Microsoft.Windows.Security.AppIdLogger
    '{5AF61464-71AD-4419-A92A-7766E9A5ABC3}' # Microsoft-Windows-AppID-AppRep
)

$UEX_RestartManagerProviders = @(
    '{0888E5EF-9B98-4695-979D-E92CE4247224}' # Microsoft-Windows-RestartManager
)
#endregion Switches

#region Scenarios
$UEX_Logon_ETWTracingSwitchesStatus = [Ordered]@{
    'UEX_Logon' = $True
    'UEX_Shell' = $True
    'UEX_RDS' = $True
    'ADS_LSA' = $True
}

$UEX_UWP_ETWTracingSwitchesStatus = [Ordered]@{
    'UEX_AppX' = $True
    'UEX_COM' = $True
    'UEX_Shell' = $True
    'WPR General' = $true
    'Procmon' = $true
    'PSR' = $true
}

$UEX_Store_ETWTracingSwitchesStatus = [Ordered]@{
    'UEX_AppX' = $True
    'UEX_StartMenu' = $True
    'UEX_COM' = $True
    'UEX_Shell' = $True
    'WPR General' = $true
    'Procmon' = $true
    'PSR' = $true
}

$UEX_StartMenu_ETWTracingSwitchesStatus = [Ordered]@{
    'UEX_AppX' = $True
    'UEX_Store' = $True
    'UEX_COM' = $True
    'UEX_Shell' = $True
    'WPR General' = $true
    'Procmon' = $true
    'PSR' = $true
}

$UEX_Task_ETWTracingSwitchesStatus = [Ordered]@{
    'UEX_Task' = $True
    'UEX_Shell' = $True
    'UEX_Logon' = $True
    'WPR General' = $true
    'Procmon' = $true
    'PSR' = $true
}

$UEX_Cortana_ETWTracingSwitchesStatus = [Ordered]@{
    'UEX_AppX' = $True
    'UEX_Cortana' = $True
    'UEX_Shell' = $True
    'UEX_COM' = $True
    'UEX_Search' = $True
    'WPR General' = $true
    'Procmon' = $true
    'PSR' = $true
}

$UEX_Photo_ETWTracingSwitchesStatus = [Ordered]@{
    'UEX_AppX' = $True
    'UEX_Photo' = $True
    'UEX_Shell' = $True
    'UEX_COM' = $True
    'WPR General' = $true
    'Procmon' = $true
    'PSR' = $true
}

$UEX_QuickAssist_ETWTracingSwitchesStatus = [Ordered]@{
    'UEX_QuickAssist' = $True
    'NetshScenario InternetClient_dbg' = $true
    'PSR' = $true
}

$UEX_Search_ETWTracingSwitchesStatus = [Ordered]@{
    'UEX_Shell' = $True
    'UEX_Search' = $True
    'WPR General' = $true
    'Procmon' = $true
    'PSR' = $true
}

$UEX_ServerManager_ETWTracingSwitchesStatus = [Ordered]@{
    'UEX_WinRM' = $True
    'UEX_WMI' = $True
    'UEX_ServerManager' = $True
    'Netsh' = $true
    'PSR' = $true
}

$UEX_WinRM_ETWTracingSwitchesStatus = [Ordered]@{
    'UEX_WinRM' = $True
    'UEX_WMI' = $True
    'Netsh' = $true
    'PSR' = $true
}

$UEX_WMI_ETWTracingSwitchesStatus = [Ordered]@{
    'UEX_WMI' = $True
    'UEX_COM' = $True
    'Netsh' = $true
    'WPR General' = $true
    'PSR' = $true
}

$UEX_Clipboard_ETWTracingSwitchesStatus = [Ordered]@{
    'UEX_Clipboard' = $True
    'UEX_Win32k' = $True
    'UEX_Shell' = $True
    'WPR General' = $true
    'Procmon' = $true
    'PSR' = $true
}
#endregion Scenarios

#region performance counters
$UEX_SupportedPerfCounter = @{
    'UEX_RDS' = 'General counters + counter for RDCB'
    'UEX_Print' = 'General counters + Print related counters'
    'UEX_IME' = 'General counters + Input delay counters'
}

$UEX_RDSCounters = @(
    $global:GeneralCounters
    '\Terminal Services\*'
    '\Remote Desktop Connection Broker Counterset(*)\*'
    '\Remote Desktop Connection Broker Redirector Counterset(*)\*'
)

$UEX_PrintCounters = @(
    $global:GeneralCounters
    '\Paging File(*)\*'
    '\Cache(*)\*'
    '\Network Adapter(*)\*'
    '\Network Interface(*)\*'
    '\Server(*)\*'
    '\Server Work Queues(*)\*'
    '\Print Queue(*)\*'
)

$UEX_IMECounters = @(
    $global:GeneralCounters
    '\User Input Delay per Process(*)\*'
    '\User Input Delay per Session(*)\*'
)
#endregion performance counters

#region Pre-Start / Post-Stop function
Function UEX_WMIPreStart{
    EnterFunc $MyInvocation.MyCommand.Name
    LogDebug ('Enabling analytic logs for WMI')
    Try{
        FwSetEventLog 'Microsoft-Windows-WMI-Activity/Trace'
        FwSetEventLog 'Microsoft-Windows-WMI-Activity/Debug'
    }Catch{
        $ErrorMessage = 'An exception happened in FwSetEventLog.'
        LogException $ErrorMessage $_ $fLogFileOnly
        Throw ($ErrorMessage)
    }
    EndFunc $MyInvocation.MyCommand.Name
}

Function UEX_WMIPostStop{
    EnterFunc $MyInvocation.MyCommand.Name
    LogDebug ('Disabling analytic logs for WMI')

    Try{
        FwResetEventLog 'Microsoft-Windows-WMI-Activity/Trace'
        FwResetEventLog 'Microsoft-Windows-WMI-Activity/Debug'
    }Catch{
        $ErrorMessage = 'An exception happened in FwResetEventLog.'
        LogException $ErrorMessage $_ $fLogFileOnly
        Throw ($ErrorMessage)
    }
    EndFunc $MyInvocation.MyCommand.Name
}

Function UEX_RDSPreStart{
    EnterFunc $MyInvocation.MyCommand.Name
    reg add HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\RDMS /t REG_DWORD /v EnableDeploymentUILog /d 1 /f | Out-Null
    reg add HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\RDMS  /t REG_DWORD /v EnableUILog /d 1 /f | Out-Null
    EndFunc $MyInvocation.MyCommand.Name
}

Function UEX_RDSPostStop{
    EnterFunc $MyInvocation.MyCommand.Name
    If(Test-Path -Path "C:\Windows\Logs\RDMSDeploymentUI.txt"){
        LogInfo ('[RDS] Copying RDMS-Deplyment log')
        Copy-Item "C:\Windows\Logs\RDMSDeploymentUI.txt" $LogFolder -Force -ErrorAction SilentlyContinue
    }
    If(Test-Path -Path "$env:temp\RdmsUI-trace.log"){
        LogInfo ('[RDS] Copying RDMS-UI log')
        Copy-Item "$env:temp\RdmsUI-trace.log" $LogFolder -Force -ErrorAction SilentlyContinue
    }
    reg delete HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\RDMS /F | Out-Null
    EndFunc $MyInvocation.MyCommand.Name
}

Function UEX_PrintPreStart{
    EnterFunc $MyInvocation.MyCommand.Name
    Try{
        FwSetEventLog 'Microsoft-Windows-PrintService/Admin'
        FwSetEventLog 'Microsoft-Windows-PrintService/Operational'
        FwSetEventLog 'Microsoft-Windows-PrintService/Debug'
    }Catch{
        $ErrorMessage = 'An exception happened in FwSetEventLog'
        LogException $ErrorMessage $_ $fLogFileOnly
        Throw ($ErrorMessage)
    }
    EndFunc $MyInvocation.MyCommand.Name
}
Function UEX_PrintPostStop{
    EnterFunc $MyInvocation.MyCommand.Name
    $fResult = $True
    Try{
        FwResetEventLog 'Microsoft-Windows-PrintService/Admin'
        FwResetEventLog 'Microsoft-Windows-PrintService/Operational'
        FwResetEventLog 'Microsoft-Windows-PrintService/Debug'
    }Catch{
        $ErrorMessage = 'An exception happened in FwResetEventLog'
        LogException $ErrorMessage $_ $fLogFileOnly
        Throw ($ErrorMessage)
    }
    EndFunc $MyInvocation.MyCommand.Name
}

Function CollectUEX_PrintExLog{
  # invokes external script until fully integrated into TSSv2
  EnterFunc $MyInvocation.MyCommand.Name
  LogInfo "[$($MyInvocation.MyCommand.Name)] . calling Print-Collect.ps1"
  .\scripts\Print-Collect.ps1 -DataPath $global:LogFolder -AcceptEula
  LogInfo "[$($MyInvocation.MyCommand.Name)] . Done Print-Collect.ps1"
    EndFunc $MyInvocation.MyCommand.Name
}

Function UEX_TaskPreStart{
    EnterFunc $MyInvocation.MyCommand.Name
    Try{
        FwSetEventLog 'Microsoft-Windows-TaskScheduler/Operational'
        FwSetEventLog 'Microsoft-Windows-TaskScheduler/Maintenance'
    }Catch{
        $ErrorMessage = 'An exception happened in FwSetEventLog'
        LogException $ErrorMessage $_ $fLogFileOnly
        Throw ($ErrorMessage)
    }
    EndFunc $MyInvocation.MyCommand.Name
}

Function UEX_TaskPostStop{
    EnterFunc $MyInvocation.MyCommand.Name
    Try{
        FwResetEventLog 'Microsoft-Windows-TaskScheduler/Operational'
        FwResetEventLog 'Microsoft-Windows-TaskScheduler/Maintenance'
    }Catch{
        $ErrorMessage = 'An exception happened in FwResetEventLog'
        LogException $ErrorMessage $_ $fLogFileOnly
        Throw ($ErrorMessage)
    }
    EndFunc $MyInvocation.MyCommand.Name
}

Function UEX_IMEPreStart{
    EnterFunc $MyInvocation.MyCommand.Name
    Try{
        FwSetEventLog 'Microsoft-Windows-IME-Broker/Analytic'
        FwSetEventLog 'Microsoft-Windows-IME-CandidateUI/Analytic'
        FwSetEventLog 'Microsoft-Windows-IME-CustomerFeedbackManager/Debug'
        FwSetEventLog 'Microsoft-Windows-IME-CustomerFeedbackManagerUI/Analytic'
        FwSetEventLog 'Microsoft-Windows-IME-JPAPI/Analytic'
        FwSetEventLog 'Microsoft-Windows-IME-JPLMP/Analytic'
        FwSetEventLog 'Microsoft-Windows-IME-JPPRED/Analytic'
        FwSetEventLog 'Microsoft-Windows-IME-JPSetting/Analytic'
        FwSetEventLog 'Microsoft-Windows-IME-JPTIP/Analytic'
        FwSetEventLog 'Microsoft-Windows-IME-KRAPI/Analytic'
        FwSetEventLog 'Microsoft-Windows-IME-KRTIP/Analytic'
        FwSetEventLog 'Microsoft-Windows-IME-OEDCompiler/Analytic'
        FwSetEventLog 'Microsoft-Windows-IME-TCCORE/Analytic'
        FwSetEventLog 'Microsoft-Windows-IME-TCTIP/Analytic'
        FwSetEventLog 'Microsoft-Windows-IME-TIP/Analytic'
        FwSetEventLog 'Microsoft-Windows-TaskScheduler/Operational'
    }Catch{
        $ErrorMessage = 'An exception happened in FwSetEventLog'
        LogException $ErrorMessage $_ $fLogFileOnly
        Throw ($ErrorMessage)
    }
    EndFunc $MyInvocation.MyCommand.Name
}

Function UEX_IMEPostStop{
    EnterFunc $MyInvocation.MyCommand.Name
    $fResult = $True
    Try{
        FwResetEventLog 'Microsoft-Windows-IME-Broker/Analytic'
        FwResetEventLog 'Microsoft-Windows-IME-CandidateUI/Analytic'
        FwResetEventLog 'Microsoft-Windows-IME-CustomerFeedbackManager/Debug'
        FwResetEventLog 'Microsoft-Windows-IME-CustomerFeedbackManagerUI/Analytic'
        FwResetEventLog 'Microsoft-Windows-IME-JPAPI/Analytic'
        FwResetEventLog 'Microsoft-Windows-IME-JPLMP/Analytic'
        FwResetEventLog 'Microsoft-Windows-IME-JPPRED/Analytic'
        FwResetEventLog 'Microsoft-Windows-IME-JPSetting/Analytic'
        FwResetEventLog 'Microsoft-Windows-IME-JPTIP/Analytic'
        FwResetEventLog 'Microsoft-Windows-IME-KRAPI/Analytic'
        FwResetEventLog 'Microsoft-Windows-IME-KRTIP/Analytic'
        FwResetEventLog 'Microsoft-Windows-IME-OEDCompiler/Analytic'
        FwResetEventLog 'Microsoft-Windows-IME-TCCORE/Analytic'
        FwResetEventLog 'Microsoft-Windows-IME-TCTIP/Analytic'
        FwResetEventLog 'Microsoft-Windows-IME-TIP/Analytic'
        FwResetEventLog 'Microsoft-Windows-TaskScheduler/Operational'
    }Catch{
        $ErrorMessage = 'An exception happened in FwResetEventLog'
        LogException $ErrorMessage $_ $fLogFileOnly
        Throw ($ErrorMessage)
    }
    EndFunc $MyInvocation.MyCommand.Name
}

Function UEX_COMPreStart{
    EnterFunc $MyInvocation.MyCommand.Name
    If($EnableCOMDebug.IsPresent){
        $COMDebugRegKey = "HKLM:Software\Microsoft\OLE\Tracing"
        If(!(Test-Path -Path "$COMDebugRegKey")){
            Try{
                LogInfo ("[COM] Creating `'HKLM\Software\Microsoft\OLE\Tracing`' key.")
                New-Item $COMDebugRegKey -ErrorAction Stop | Out-Null
            }Catch{
                LogMessage $LogLevel.Error ("Unable to creat `'HKLM\Software\Microsoft\OLE\Tracing`' key.")
                Return
            }
        }

        Try{
            LogInfo ("[COM] Enabling COM debug and setting `'ExecutablesToTrace`' to `'*`'.")
            Set-Itemproperty -path $COMDebugRegKey -Name 'ExecutablesToTrace' -value '*' -Type String -ErrorAction Stop
        }Catch{
            LogException ("Unable to set `'ExecutablesToTrace`' registry.") $_
            LogMessage $LogLevel.Warning ("[COM] COM trace will continue with normal level.")
        }
    }
    EndFunc $MyInvocation.MyCommand.Name
}

Function UEX_COMPostStop{
    $COMDebugRegKey = "HKLM:Software\Microsoft\OLE\Tracing"
    If(Test-Path -Path "$COMDebugRegKey"){
        $TracingKey = Get-ItemProperty -Path "HKLM:Software\Microsoft\OLE\Tracing" -ErrorAction Stop
        If($Null -ne $TracingKey.ExecutablesToTrace){
            Try{
                LogInfo ("[COM] Deleting `'ExecutablesToTrace`' registry.")
                Remove-ItemProperty -Path $COMDebugRegKey -Name 'ExecutablesToTrace' -ErrorAction Stop
            }Catch{
                LogException ("Unable to delete `'ExecutablesToTrace`' registry.") $_
                LogMessage $LogLevel.Warning ("[COM] Please remove `'ExecutablesToTrace`' under HKLM\Software\Microsoft\OLE\Tracing key manually.")
            }
        }
    }
}

Function UEX_SCMPreStart{
    EnterFunc $MyInvocation.MyCommand.Name
    # This function is used only for Win8.1 or WS2012R2
    If($OSVersion.Build -le 9600){
        LogInfo "[SCM] Setting HKLM\Software\Microsoft\Windows NT\CurrentVersion\Tracing\SCM\Regular\TracingDisabled to 0"
        Try{
            RunCommands "SCM" "reg add `"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Tracing\SCM\Regular`" /v TracingDisabled /t REG_DWORD /d 0 /f | Out-Null" -ThrowException:$True -ShowMessage:$True
        }Catch{
            $Message = "[SCM] Error during setting TracingDisabled registry to 0."
            LogException $Message $_
            Throw($Message) # This is critical. So throw exception and notify upper level.
        }
    }Else{
        LogDebug "This is $($OSVersion.Major).$($OSVersion.Minor).$($OSVersion.Build) and do nothing."
    }
    EndFunc $MyInvocation.MyCommand.Name
}

Function UEX_SCMPostStop{
    EndFunc $MyInvocation.MyCommand.Name
    # This function is used only for Win8.1 or WS2012R2
    If($OSVersion.Build -le 9600){
        # Copying etl files to log folder
        If(Test-Path -Path "$env:SYSTEMROOT\system32\LogFiles\Scm\SCM*"){
            LogInfo "[SCM] Copying $env:SYSTEMROOT\system32\LogFiles\Scm\SCM* to log folder"
            FwCreateLogFolder "$LogFolder\SCM"
            Copy-Item "C:\Windows\system32\LogFiles\Scm\SCM*" "$LogFolder\SCM" -Force -ErrorAction SilentlyContinue | Out-Null
            Move-Item "$LogFolder\*SCMTrace.etl" "$LogFolder\SCM" #-ErrorAction SilentlyContinue | Out-Null
        }Else{
            LogDebug "[SCM] WARNING: SCM tracing is enabled but $env:SYSTEMROOT\system32\LogFiles\Scm does not exist."
        }
        
        # Disabling registry
        LogInfo "[SCM] Setting HKLM\Software\Microsoft\Windows NT\CurrentVersion\Tracing\SCM\Regular\TracingDisabled to 1"
        Try{
            RunCommands "SCM" "reg add `"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Tracing\SCM\Regular`" /v TracingDisabled /t REG_DWORD /d 1 /f | Out-Null" -ThrowException:$True -ShowMessage:$True
        }Catch{
            LogException "[SCM] Error happens during deleting TracingDisabled." $_
        }
    }Else{
        LogDebug "This is $($OSVersion.Major).$($OSVersion.Minor).$($OSVersion.Build) and do nothing."
    }
    EndFunc $MyInvocation.MyCommand.Name
}
#endregion Pre-Start / Post-Stop function


#region Functions
#UEX Entry

    ForEach ($UEX_ETWSwitchStatus in $ETWTracingSwitchesStatus)
    {
    switch ($UEX_ETWSwitchStatus)
        {
        "UEX_Scenario1" {Start-UEX_Scenario1 ('1', '2')}

        "UEX_Scenario2" {Start-UEX_Scenario2 ('dummy parameter')}

        "UEX_Robert" {Start-UEX_Robert ('dummy parameter')}
    
        default{
            Write-Host "No match found in Start-UEX* module functions of TSSv2_UEX.psm1."
            }
    
        }

    }   


#Implementations of the specific data collection scenario


# -------------- UEX_Scenario1 ---------------

function Start-UEX_Scenario1 
{
[CmdletBinding(DefaultParameterSetName = 'None')]
param
(

	[Parameter(Mandatory)]
	[ValidateNotNullorEmpty()]
	[Array]$UEX_Scenario1_params
)

#register stop function
$global:StopModuleCallbackFunctions += 'Stop-UEX_Scenario1'

#add your custom code

}


function Stop-UEX_Scenario1 
{

#add your custom code

Write-Host "Stop UEX_Scenario_1"

}


# -------------- UEX_Scenario2 ---------------

function Start-UEX_Scenario2
{
[CmdletBinding(DefaultParameterSetName = 'None')]
param
(

	[Parameter(Mandatory)]
	[ValidateNotNullorEmpty()]
	[Array]$UEX_Scenario2_params
)

#register stop function
$global:StopModuleCallbackFunctions += 'Stop-UEX_Scenario2'

#add your custom code

}


function Stop-UEX_Scenario2 
{

#add your custom code

Write-Host "Stop UEX_Scenario_2"

}



function Stop-UEX_Scenario1 
{

#add your custom code

Write-Host "Stop UEX_Scenario_1"

}


# -------------- UEX_Robert ---------------

function Start-UEX_Robert
{
[CmdletBinding(DefaultParameterSetName = 'None')]
param
(

	[Parameter(Mandatory)]
	[ValidateNotNullorEmpty()]
	[Array]$UEX_Rober_params
)

#register stop function
$global:StopModuleCallbackFunctions += 'Stop-UEX_Scenario2'

#add your custom code

}


function Stop-UEX_Robert
{

#add your custom code

Write-Host "Stop UEX_Robert"

}


########## CollectLog Functions ############


Function CollectUEX_AppCompatLog{
    EnterFunc $MyInvocation.MyCommand.Name
    $AppCompatLogFolder = "$LogFolder\AppCompatLog$LogSuffix"
    $LogPrefix = 'AppCompat'
    Try{
        FwCreateLogFolder $AppCompatLogFolder
    }Catch{
        LogException ("Unable to create $AppCompatLogFolder.") $_
        Return
    }

    $AppCompatRegistries = @(
        ('HKLM:Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags', "$AppCompatLogFolder\AppCompatFlags-HKLM-Reg.txt"),
        ('HKCU:Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags', "$AppCompatLogFolder\AppCompatFlags-HKCU-Reg.txt")
    )
    FwExportRegistry $LogPrefix $AppCompatRegistries
    REG SAVE 'HKLM\System\CurrentControlSet\Control\Session Manager\AppCompatCache' "$AppCompatLogFolder\AppCompatCache.HIV" 2>&1 | Out-Null

    EndFunc $MyInvocation.MyCommand.Name
}

Function CollectUEX_IMELog{
    EnterFunc $MyInvocation.MyCommand.Name
    $IMELogFolder = "$LogFolder\IMELog$LogSuffix"
    $IMELogEventFolder = "$IMELogFolder\event"
    $IMELogDumpFolder = "$IMELogFolder\dump"

    Try{
        FwCreateLogFolder $IMELogFolder
        FwCreateLogFolder $IMELogEventFolder
        FwCreateLogFolder $IMELogDumpFolder
    }Catch{
        LogException ("Unable to create $IMELogFolder.") $_
        Return
    }

    # Event log
    LogInfo ("[IME] Exporting event logs.")
    $EventLogs = @(
        'Microsoft-Windows-IME-Broker/Analytic',
        'Microsoft-Windows-IME-CandidateUI/Analytic',
        'Microsoft-Windows-IME-CustomerFeedbackManager/Debug',
        'Microsoft-Windows-IME-CustomerFeedbackManagerUI/Analytic',
        'Microsoft-Windows-IME-JPAPI/Analytic',
        'Microsoft-Windows-IME-JPLMP/Analytic',
        'Microsoft-Windows-IME-JPPRED/Analytic',
        'Microsoft-Windows-IME-JPSetting/Analytic',
        'Microsoft-Windows-IME-JPTIP/Analytic',
        'Microsoft-Windows-IME-KRAPI/Analytic',
        'Microsoft-Windows-IME-KRTIP/Analytic',
        'Microsoft-Windows-IME-OEDCompiler/Analytic',
        'Microsoft-Windows-IME-TCCORE/Analytic',
        'Microsoft-Windows-IME-TCTIP/Analytic',
        'Microsoft-Windows-IME-TIP/Analytic',
        'Microsoft-Windows-TaskScheduler/Operational'
    )
    FwExportEventLog $EventLogs $IMELogEventFolder

    LogInfo ("[IME] Exporting HKCU registries.")
    reg query "HKCU\Control Panel"                                      /s | Out-File -Append "$IMELogFolder\reg-HKCU.txt"
    reg query "HKCU\Keyboard Layout"                                    /s | Out-File -Append "$IMELogFolder\reg-HKCU.txt"
    reg query "HKCU\Software\AppDataLow\Software\Microsoft\IME"         /s | Out-File -Append "$IMELogFolder\reg-HKCU.txt"
    reg query "HKCU\Software\Microsoft\CTF"                             /s | Out-File -Append "$IMELogFolder\reg-HKCU.txt"
    reg query "HKCU\Software\Microsoft\IME"                             /s | Out-File -Append "$IMELogFolder\reg-HKCU.txt"
    reg query "HKCU\Software\Microsoft\IMEJP"                           /s | Out-File -Append "$IMELogFolder\reg-HKCU.txt"
    reg query "HKCU\Software\Microsoft\IMEMIP"                          /s | Out-File -Append "$IMELogFolder\reg-HKCU.txt"
    reg query "HKCU\Software\Microsoft\Input"                           /s | Out-File -Append "$IMELogFolder\reg-HKCU.txt"
    reg query "HKCU\Software\Microsoft\InputMethod"                     /s | Out-File -Append "$IMELogFolder\reg-HKCU.txt"
    reg query "HKCU\Software\Microsoft\Keyboard"                        /s | Out-File -Append "$IMELogFolder\reg-HKCU.txt"
    reg query "HKCU\Software\Microsoft\Speech"                          /s | Out-File -Append "$IMELogFolder\reg-HKCU.txt"
    reg query "HKCU\Software\Microsoft\Speech Virtual"                  /s | Out-File -Append "$IMELogFolder\reg-HKCU.txt"
    reg query "HKCU\Software\Microsoft\Speech_OneCore"                  /s | Out-File -Append "$IMELogFolder\reg-HKCU.txt"
    reg query "HKCU\Software\Microsoft\Spelling"                        /s | Out-File -Append "$IMELogFolder\reg-HKCU.txt"
    reg query "HKCU\Software\Policies"                                  /s | Out-File -Append "$IMELogFolder\reg-HKCU.txt"

    LogInfo ("[IME] Exporting HKLM registries.")
    reg query "HKLM\SOFTWARE\Microsoft\CTF"                             /s | Out-File -Append "$IMELogFolder\reg-HKLM.txt"
    reg query "HKLM\SOFTWARE\Microsoft\IME"                             /s | Out-File -Append "$IMELogFolder\reg-HKLM.txt"
    reg query "HKLM\SOFTWARE\Microsoft\IMEJP"                           /s | Out-File -Append "$IMELogFolder\reg-HKLM.txt"
    reg query "HKLM\SOFTWARE\Microsoft\IMEKR"                           /s | Out-File -Append "$IMELogFolder\reg-HKLM.txt"
    reg query "HKLM\SOFTWARE\Microsoft\IMETC"                           /s | Out-File -Append "$IMELogFolder\reg-HKLM.txt"
    reg query "HKLM\SOFTWARE\Microsoft\Input"                           /s | Out-File -Append "$IMELogFolder\reg-HKLM.txt"
    reg query "HKLM\SOFTWARE\Microsoft\InputMethod"                     /s | Out-File -Append "$IMELogFolder\reg-HKLM.txt"
    reg query "HKLM\SOFTWARE\Microsoft\MTF"                             /s | Out-File -Append "$IMELogFolder\reg-HKLM.txt"
    reg query "HKLM\SOFTWARE\Microsoft\MTFFuzzyFactors"                 /s | Out-File -Append "$IMELogFolder\reg-HKLM.txt"
    reg query "HKLM\SOFTWARE\Microsoft\MTFInputType"                    /s | Out-File -Append "$IMELogFolder\reg-HKLM.txt"
    reg query "HKLM\SOFTWARE\Microsoft\MTFKeyboardMappings"             /s | Out-File -Append "$IMELogFolder\reg-HKLM.txt"
    reg query "HKLM\SOFTWARE\Microsoft\PolicyManager"                   /s | Out-File -Append "$IMELogFolder\reg-HKLM.txt"
    reg query "HKLM\SOFTWARE\Microsoft\Speech"                          /s | Out-File -Append "$IMELogFolder\reg-HKLM.txt"
    reg query "HKLM\SOFTWARE\Microsoft\Speech_OneCore"                  /s | Out-File -Append "$IMELogFolder\reg-HKLM.txt"
    reg query "HKLM\SOFTWARE\Microsoft\Spelling"                        /s | Out-File -Append "$IMELogFolder\reg-HKLM.txt"
    reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies" /s | Out-File -Append "$IMELogFolder\reg-HKLM.txt"
    reg query "HKLM\SOFTWARE\Policies"                                  /s | Out-File -Append "$IMELogFolder\reg-HKLM.txt"

    LogInfo ("[IME] Collecting command outputs.")
    Try{
        tasklist /M MsCtfMonitor.dll | Out-File -Append "$IMELogFolder\tasklist_MsCtfMonitor.txt"
        tree "%APPDATA%\Microsoft\IME" /f | Out-File -Append "$IMELogFolder\tree_APPDATA_IME.txt"
        tree "%APPDATA%\Microsoft\InputMethod" /f | Out-File -Append "$IMELogFolder\tree_APPDATA_InputMethod.txt"
        tree "%LOCALAPPDATA%\Microsoft\IME" /f | Out-File -Append "$IMELogFolder\tree_LOCALAPPDATA_IME.txt"
        tree "C:\windows\system32\ime" /f | Out-File -Append "$IMELogFolder\tree_windows_system32_ime.txt"
        tree "C:\windows\ime" /f | Out-File -Append "$IMELogFolder\tree_windows_ime.txt"
        Get-WinLanguageBarOption | Out-File -Append "$IMELogFolder\get-winlanguagebaroption.txt"
    }Catch{
        LogException ("ERROR: Execute command") $_ $fLogFileOnly
    }

    # Process dump
    LogInfo ("[IME] Collecting process dumps.")
    FwCaptureUserDump "ctfmon" $IMELogDumpFolder -IsService:$False
    FwCaptureUserDump "TextInputHost" $IMELogDumpFolder -IsService:$False
    if ( Get-Process | Where-Object Name -eq imebroker ) {
        foreach ($proc in (Get-Process imebroker)) {
            FwCaptureUserDump -ProcPID $proc.Id -DumpFolder $IMELogDumpFolder
        }
    }
    foreach ($proc in (Get-Process taskhostw)) {
        if ($proc.Modules | Where-Object {$_.ModuleName -eq "msctfmonitor.dll"}) {
            FwCaptureUserDump -ProcPID $proc.Id -DumpFolder $IMELogDumpFolder
        }
    }

    EndFunc $MyInvocation.MyCommand.Name
}

Function CollectUEX_FontLog{
    EnterFunc $MyInvocation.MyCommand.Name
    $FontLogFolder = "$LogFolder\FontLog$LogSuffix"
    Try{
        FwCreateLogFolder $FontLogFolder
    }Catch{
        LogException ("Unable to create $FontLogFolder.") $_
        Return
    }

    LogInfo ("[Font] Exporting registries.")
    reg query "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Font Management" /s | Out-File "$FontLogFolder\reg-HKCU_FontManagement.txt"
    reg query "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /s | Out-File "$FontLogFolder\reg-HKCU_Fonts.txt"

    reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers" /s | Out-File "$FontLogFolder\reg-HKLM_FontDrivers.txt"
    reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Management" /s | Out-File "$FontLogFolder\reg-HKLM_FontManagement.txt"
    reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\FontDPI" /s | Out-File "$FontLogFolder\reg-HKLM_FontDPI.txt"
    reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\FontIntensityCorrection" /s | Out-File "$FontLogFolder\reg-HKLM_FontIntensityCorrection.txt"
    reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\FontLink" /s | Out-File "$FontLogFolder\reg-HKLM_FontLink.txt"
    reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\FontMapper" /s | Out-File "$FontLogFolder\reg-HKLM_FontMapper.txt"
    reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\FontMapperFamilyFallback" /s | Out-File "$FontLogFolder\reg-HKLM_FontMapperFamilyFallback.txt"
    reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts" /s | Out-File "$FontLogFolder\reg-HKLM_Fonts.txt"
    reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\FontSubstitutes" /s | Out-File "$FontLogFolder\reg-HKLM_FontSubstitetes.txt"
}

Function CollectUEX_NlsLog{
    EnterFunc $MyInvocation.MyCommand.Name
    $NlsLogFolder = "$LogFolder\NlsLog$LogSuffix"
    Try{
        FwCreateLogFolder $NlsLogFolder
    }Catch{
        LogException ("Unable to create $NlsLogFolder.") $_
        Return
    }

    LogInfo ("[Nls] Exporting registries.")
    $NlsRegLogFolder = "$NlsLogFolder\Reg"
    Try{
        New-Item $NlsRegLogFolder -ItemType Directory -ErrorAction Stop | Out-Null
        reg save "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion" $NlsRegLogFolder\Software.hiv 2>&1 | Out-Null
        reg save "HKLM\SOFTWARE\Microsoft\Windows NT" $NlsRegLogFolder\WindowsNT.hiv 2>&1 | Out-Null
        reg save "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" $NlsRegLogFolder\WindowsUpdate.hiv 2>&1 | Out-Null
        
        reg save "HKLM\SYSTEM\CurrentControlSet" $NlsRegLogFolder\SYSTEM.hiv 2>&1 | Out-Null
        reg save "HKLM\SYSTEM\DriverDatabase" $NlsRegLogFolder\DriverDatabase.hiv 2>&1 | Out-Null
        reg save "HKLM\SYSTEM\CurrentControlSet\Services" $NlsRegLogFolder\Services.hiv 2>&1 | Out-Null

        reg save "HKCU\Control Panel" $NlsRegLogFolder\hkcu_ControlPanel.hiv 2>&1 | Out-Null
        reg save "HKCU\Software\Classes\Local Settings" $NlsRegLogFolder\hkcu_LocalSettings.hiv 2>&1 | Out-Null
    }Catch{
        LogException ("ERROR: Exporting from Registry") $_ $fLogFileOnly
    }

    LogInfo ("[Nls] Collecting command outputs.")
    Try{
      dism /online /get-intl 2>&1| Out-File -Append "$NlsLogFolder\dism-get-intl.txt"
      dism /online /get-features 2>&1| Out-File -Append "$NlsLogFolder\dism-get-features.txt"
      dism /online /get-packages 2>&1| Out-File "$NlsLogFolder\dism-get-package.txt" 
  
      Get-WinUserLanguageList | Out-File "$NlsLogFolder\get-winuserlist.txt"
      Get-Culture | Out-File "$NlsLogFolder\get-culture.txt"
      Get-WinHomeLocation | Out-File "$NlsLogFolder\get-winhomelocation.txt"
      Get-WinSystemLocale | Out-File "$NlsLogFolder\get-winsystemlocale.txt"
      Get-WinLanguageBarOption | Out-File "$NlsLogFolder\get-winlanguagebaroption.txt"
      #we# Get-TimeZone | Out-File "$NlsLogFolder\get-timezone.txt"
	  If(($PSVersionTable.PSVersion.Major -le 4) -or ($OSVersion.Build -le 9600)){ # PowerShell 4.0 / #we# Get-TimeZone fails on Srv2012R2 with PS v5.0 
			$TimeZone = [System.TimeZoneInfo]::Local.DisplayName
	  }Else{
			$TimeZone = (Get-TimeZone).DisplayName
	  }
	  $TimeZone | Out-File "$NlsLogFolder\get-timezone.txt"
    }Catch{
        LogException ("ERROR: Execute command") $_ $fLogFileOnly
    }

    LogInfo ("[Nls] Collecting Panther files.")
    $NlsPantherLogFolder = "$NlsLogFolder\Panther"
    Try{
        New-Item $NlsPantherLogFolder -ItemType Directory -ErrorAction Stop | Out-Null
        Copy-Item C:\Windows\Panther\* $NlsPantherLogFolder
    }Catch{
        LogException ("ERROR: Copying files from C:\Windows\Panther") $_ $fLogFileOnly
    }

    LogInfo ("[Nls] Collecting Setupapi files.")
    $NlsSetupApiLogFolder = "$NlsLogFolder\Setupapi"
    Try{
        New-Item $NlsSetupApiLogFolder -ItemType Directory -ErrorAction Stop | Out-Null
        Copy-Item "C:\Windows\inf\Setupapi*" $NlsSetupApiLogFolder
    }Catch{
        LogException ("ERROR: Copying files from C:\Windows\Inf\Setup*") $_ $fLogFileOnly
    }

    EndFunc $MyInvocation.MyCommand.Name
}

Function CollectUEX_StartMenuLog{
    EnterFunc $MyInvocation.MyCommand.Name
    $StartLogFolder = "$LogFolder\StartMenuLog$LogSuffix"
    Try{
        FwCreateLogFolder $StartLogFolder
    }Catch{
        LogException ("Unable to create $StartLogFolder.") $_
        Return
    }

    $cacheDumpToolPath = "$env:windir\system32\datastorecachedumptool.exe"

    ### Data Layer State ###
    LogInfo ("[StartMenu] Collecting data for DataLayerState.")
    mkdir "$StartLogFolder\DataLayerState" | Out-Null
    Copy-Item "$Env:LocalAppData\Microsoft\Windows\appsfolder*" "$StartLogFolder\DataLayerState\" -ErrorAction SilentlyContinue | Out-Null
    Copy-Item "$Env:LocalAppData\Microsoft\Windows\Caches\`{3D*" "$StartLogFolder\DataLayerState\" -ErrorAction SilentlyContinue | Out-Null
    Copy-Item "$env:LocalAppData\Microsoft\Windows\Application Shortcuts\" "$StartLogFolder\DataLayerState\Shortcuts\ApplicationShortcuts\" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
    Copy-Item "$env:ProgramData\Microsoft\Windows\Start Menu\" "$StartLogFolder\DataLayerState\Shortcuts\CommonStartMenu\" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
    Copy-Item "$env:APPDATA\Microsoft\Windows\Start Menu\" "$StartLogFolder\DataLayerState\Shortcuts\StartMenu\" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null

    if (Test-Path ("$env:windir\panther\miglog.xml")) {
        Copy-Item "$env:windir\panther\miglog.xml" "$StartLogFolder\DataLayerState" -ErrorAction SilentlyContinue  | Out-Null
    } else {
        "No miglog.xml present on system. Probably not an upgrade" > "$StartLogFolder\DataLayerState\miglog_EMPTY.txt"
    }

    ### Trace ###
    LogInfo ("[StartMenu] Collecting trace files.")
    mkdir "$StartLogFolder\Trace" | Out-Null
    Copy-Item "$env:LocalAppData\Packages\Microsoft.Windows.ShellExperienceHost_cw5n1h2txyewy\TempState\StartUiTraceloggingSession*" "$StartLogFolder\Trace" -ErrorAction SilentlyContinue | Out-Null
    Copy-Item "$env:LocalAppData\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\TempState\StartUiTraceloggingSession*" "$StartLogFolder\Trace" -ErrorAction SilentlyContinue | Out-Null

    ### Tile Cache ###
    LogInfo ("[StartMenu] Collecting data for Tile Cache.")
    mkdir "$StartLogFolder\TileCache" | Out-Null
    mkdir "$StartLogFolder\TileCache\ShellExperienceHost" | Out-Null
    mkdir "$StartLogFolder\TileCache\StartMenuExperienceHost" | Out-Null

    Copy-Item "$env:LocalAppData\Packages\Microsoft.Windows.ShellExperienceHost_cw5n1h2txyewy\TempState\Tile*" "$StartLogFolder\TileCache\ShellExperienceHost" -Force -ErrorAction SilentlyContinue | Out-Null
    Copy-Item "$env:LocalAppData\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\TempState\Tile*" "$StartLogFolder\TileCache\StartMenuExperienceHost" -Force -ErrorAction SilentlyContinue | Out-Null

    # After copying off the cache files we should attempt to dump them.  This functionality was added to DataStoreCacheDumpTool.exe in late RS4 and will silently NOOP for
    # builds older than that.
    if (Test-Path -PathType Leaf $cacheDumpToolPath) {
        $allTileCaches = Get-ChildItem -Recurse "$StartLogFolder\TileCache\TileCache*Header.bin";
        foreach ($cache in $allTileCaches) {
            FwInvokeUnicodeTool("$cacheDumpToolPath -v $cache > $cache.html");
        }
    }

    ### Upgrade dumps ###
    $dump_files = Get-ChildItem "$env:LocalAppData\Packages\Microsoft.Windows.ShellExperienceHost_cw5n1h2txyewy\TempState\" -Filter *.archive
    if ($dump_files.count -gt 0)
    {
        LogInfo ("[StartMenu] Collecting data for UpgradeDumps.")
        mkdir "$StartLogFolder\UpgradeDumps" | Out-Null
        Copy-Item "$env:LocalAppData\Packages\Microsoft.Windows.ShellExperienceHost_cw5n1h2txyewy\TempState\*.archive" "$StartLogFolder\UpgradeDumps\" -Force -ErrorAction SilentlyContinue | Out-Null
    }

    ### UTM ###
    LogInfo ("[StartMenu] Collecting data for UTM.")
    $UTMLogFolder = "$StartLogFolder\UnifiedTileModel"
    mkdir "$UTMLogFolder\ShellExperienceHost" | Out-Null
    mkdir "$UTMLogFolder\StartMenuExperienceHost" | Out-Null

    Copy-Item "$env:LocalAppData\Packages\Microsoft.Windows.ShellExperienceHost_cw5n1h2txyewy\TempState\StartUnifiedTileModelCache*" "$UTMLogFolder\ShellExperienceHost" -Force -ErrorAction SilentlyContinue | Out-Null
    Copy-Item "$env:LocalAppData\Packages\Microsoft.Windows.ShellExperienceHost_cw5n1h2txyewy\TempState\UnifiedTileCache*" "$UTMLogFolder\ShellExperienceHost" -Force -ErrorAction SilentlyContinue | Out-Null
    Copy-Item "$env:LocalAppData\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\TempState\StartUnifiedTileModelCache*" "$UTMLogFolder\StartMenuExperienceHost" -Force -ErrorAction SilentlyContinue | Out-Null

    if (Test-Path -PathType Leaf $cacheDumpToolPath) {
        LogInfo ("[StartMenu] Dumping the tile cache with datastorecachedumptool.exe.")
        # The cache dump tool is present in the OS image.  Use it.  If the cache file exists then dump it.  Regardless of whether it exists also take
        # a live dump.
        if (Test-Path -PathType Leaf "$UTMLogFolder\ShellExperienceHost\StartUnifiedTileModelCache.dat") {
            FwInvokeUnicodeTool("$cacheDumpToolPath -f $UTMLogFolder\ShellExperienceHost\StartUnifiedTileModelCache.dat") | Out-File "$UTMLogFolder\ShellExperienceHost\StartUnifiedTileModelCacheDump.log"
        }
        elseif (Test-Path -PathType Leaf "$UTMLogFolder\ShellExperienceHost\UnifiedTileCache.dat") {
            FwInvokeUnicodeTool("$cacheDumpToolPath -f $UTMLogFolder\ShellExperienceHost\UnifiedTileCache.dat") | Out-File "$UTMLogFolder\ShellExperienceHost\UnifiedTileCacheDump.log"
        }

        if (Test-Path -PathType Leaf "$UTMLogFolder\StartMenuExperienceHost\StartUnifiedTileModelCache.dat") {
            FwInvokeUnicodeTool("$cacheDumpToolPath -f $UTMLogFolder\StartMenuExperienceHost\StartUnifiedTileModelCache.dat") | Out-File "$UTMLogFolder\StartMenuExperienceHost\StartUnifiedTileModelCacheDump.log"
        }
    }

    ### CDSData ###
    LogInfo ("[StartMenu] Collecting data for CloudDataStore.")
    mkdir "$StartLogFolder\CloudDataStore" | Out-Null
    Invoke-Expression "reg.exe export HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\Store $StartLogFolder\CloudDataStore\Store.txt 2>&1" | Out-Null
    Invoke-Expression "reg.exe export HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore $StartLogFolder\CloudDataStore\CloudStore.txt 2>&1" | Out-Null
    Invoke-Expression "reg.exe export HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CuratedTileCollections $StartLogFolder\CloudDataStore\CuratedTileCollections.txt 2>&1" | Out-Null

    ### DefaultLayout ###
    LogInfo ("[StartMenu] Collecting data for DefaultLayout.")
    mkdir "$StartLogFolder\DefaultLayout" | Out-Null
    Copy-Item "$env:LocalAppData\Microsoft\windows\shell\*" "$StartLogFolder\DefaultLayout" -Force -ErrorAction SilentlyContinue

    ### ContentDeliveryManagagerData ###
    LogInfo ("[StartMenu] Collecting data for ContentDeliveryManager.")
    $cdmLogDirectory = "$StartLogFolder\ContentDeliveryManager"
    mkdir $cdmLogDirectory | Out-Null

    $cdmLocalStateDirectory = "$env:LocalAppData\Packages\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy\LocalState\";

    # Copy the entire cdm local state directory
    Copy-Item $cdmLocalStateDirectory $cdmLogDirectory -Recurse -Force -ErrorAction SilentlyContinue

    # Extract and highlight key start files
    $cdmExtractedLogDirectory = (Join-Path $cdmLogDirectory "Extracted");
    mkdir $cdmExtractedLogDirectory | Out-Null

    # Collection of folders to extract and give readable names. The last number in most of these is the subscription ID.
    Try{
        @(
            @{'SourceName'    = "TargetedContentCache\v3\314558"
              'ExtractedName' = "TargetedContentCache PgStart Internal"},
            @{'SourceName'    = "TargetedContentCache\v3\314559"
              'ExtractedName' = "TargetedContentCache PgStart External"},
            @{'SourceName'    = "TargetedContentCache\v3\338381"
              'ExtractedName' = "TargetedContentCache Start Suggestions Internal"},
            @{'SourceName'    = "TargetedContentCache\v3\338388"
              'ExtractedName' = "TargetedContentCache Start Suggestions External"},
            @{'SourceName'    = "ContentManagementSDK\Creatives\314558"
              'ExtractedName' = "ContentManagementSDK PgStart Internal"},
            @{'SourceName'    = "ContentManagementSDK\Creatives\314559"
              'ExtractedName' = "ContentManagementSDK PgStart External"},
            @{'SourceName'    = "ContentManagementSDK\Creatives\338381"
              'ExtractedName' = "ContentManagementSDK Start Suggestions Internal"},
            @{'SourceName'    = "ContentManagementSDK\Creatives\338388"
              'ExtractedName' = "ContentManagementSDK Start Suggestions External"}
              
        ) | ForEach-Object {
            $sourceLogDirectory = (Join-Path $cdmLocalStateDirectory $_.SourceName);

            if (Test-Path -Path $sourceLogDirectory -PathType Container)
            {
                $extractedLogDirectory = Join-Path $cdmExtractedLogDirectory $_.ExtractedName;
    
                mkdir $extractedLogDirectory | Out-Null
    
                Get-ChildItem $sourceLogDirectory | Foreach-Object {
                    $destinationLogFilePath = Join-Path $extractedLogDirectory "$($_.BaseName).json"
                    Get-Content $_.FullName | ConvertFrom-Json | ConvertTo-Json -Depth 10 > $destinationLogFilePath;
                }
            }
            else
            {
                $extractedLogFilePath = Join-Path $cdmExtractedLogDirectory "NoFilesFor_$($_.ExtractedName)";
                $null > $extractedLogFilePath;
            }
        }
    }Catch{
        LogException ("An error happened during converting JSON data. This might be ignorable.") $_ $fLogFileOnly
    }

    Invoke-Expression "reg.exe query HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager /s >> $cdmLogDirectory\Registry.txt"

    ### App Resolver Cache ###
    LogInfo ("[StartMenu] Copying ARCache.")
    Try{
        New-Item "$StartLogFolder\ARCache" -ItemType Directory -ErrorAction Stop | Out-Null
        Copy-Item "$env:userprofile\AppData\Local\Microsoft\Windows\Caches\*" "$StartLogFolder\ARCache" 
    }Catch{
        LogException  ("Unable to copy ARCache.") $_ $fLogFileOnly
    }

    ### Program shortcut ###
    LogInfo ("[StartMenu] Copying program shortcut files.")
    Copy-Item "$env:userprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs" "$StartLogFolder\Programs-user" -Recurse
    Copy-Item "C:\ProgramData\Microsoft\Windows\Start Menu\Programs" "$StartLogFolder\Programs-system" -Recurse

    whoami /user /fo list | Out-File (Join-Path $StartLogFolder 'userinfo.txt')

    EndFunc $MyInvocation.MyCommand.Name
}

Function CollectUEX_LogonLog{
    EnterFunc $MyInvocation.MyCommand.Name
    $LogonLogFolder = "$LogFolder\LogonLog$LogSuffix"
    $LogPrefix = 'Logon'
    
    Try{
        FwCreateLogFolder $LogonLogFolder
    }Catch{
        LogException  ("Unable to create $LogonLogFolder.") $_
        Return
    }

    $LogonRegistries = @(
        ('HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication', "$LogonLogFolder\Logon_Reg.txt"),
        ('HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon', "$LogonLogFolder\Winlogon_Reg.txt"),
        ('HKLM:SOFTWARE\Microsoft\Windows\AssignedAccessConfiguration', "$LogonLogFolder\AssignedAccess_Reg.txt"),
        ('HKLM:SOFTWARE\Microsoft\Windows\AssignedAccessCsp', "$LogonLogFolder\AssignedAccessCsp_Reg.txt"),
        ('HKLM:SOFTWARE\Microsoft\Windows Embedded\Shell Launcher', "$LogonLogFolder\ShellLauncher_Reg.txt"),
        ('HKLM:SOFTWARE\Microsoft\Provisioning\Diagnostics\ConfigManager\AssignedAccess', "$LogonLogFolder\ConfigManager_AssignedAccess_Reg.txt"),
        ('HKLM:SOFTWARE\Microsoft\Windows\EnterpriseResourceManager\AllowedNodePaths\CSP\AssignedAccess', "$LogonLogFolder\CSP_AssignedAccess_Reg.txt"),
        ('HKLM:SYSTEM\CurrentControlSet\Services\AssignedAccessManagerSvc', "$LogonLogFolder\AssignedAccessManagerSvc_Reg.txt")
    )
    FwExportRegistry $LogPrefix $LogonRegistries

    Try{
        Get-AssignedAccess -ErrorAction Stop| Out-File -Append "$LogonLogFolder\Get-AssignedAccess.txt"
        Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-File -Append "$LogonLogFolder\Get-AppxPackage-AllUsers.txt"
        (Get-StartApps -ErrorAction SilentlyContinue).AppId | Out-File -Append "$LogonLogFolder\Get-StartApps.txt"
    }Catch{
        LogException  ("An error happened in Get-AssignedAccess") $_ $fLogFileOnly
    }
    EndFunc $MyInvocation.MyCommand.Name
}

Function CollectUEX_RDSLog{
    EnterFunc $MyInvocation.MyCommand.Name
    $RDSLogFolder = "$LogFolder\RDSLog$LogSuffix"

    Try{
        FwCreateLogFolder $RDSLogFolder
    }Catch{
        LogException  ("Unable to create $RDSLogFolder.") $_
        Return
    }

    # For future use
    #$RDSobject = Get-CimInstance -Class Win32_TerminalServiceSetting -Namespace root\cimv2\TerminalServices -ErrorAction SilentlyContinue
    #$RDSGateWay = Get-CimInstance -Class Win32_TSGatewayServer -Namespace root\cimv2\TerminalServices -ErrorAction SilentlyContinue
    #$RDSCB = Get-CimInstance -Class Win32_SessionDirectoryServer -Namespace root\cimv2 -ErrorAction SilentlyContinue
    #$RDSLS = Get-CimInstance -Class Win32_TSLicenseServer -Namespace root\cimv2 -ErrorAction SilentlyContinue

    # Event log
    $RDSEventLogs = Get-WinEvent -ListLog "*TerminalServices*" -ErrorAction SilentlyContinue
    $RDSEventLogs += Get-WinEvent -ListLog "*RemoteApp*" -ErrorAction SilentlyContinue
    $RDSEventLogs += Get-WinEvent -ListLog "*RemoteDesktop*" -ErrorAction SilentlyContinue
    $RDSEventLogs += Get-WinEvent -ListLog "*Rdms*" -ErrorAction SilentlyContinue
    $RDSEventLogs += Get-WinEvent -ListLog "*Hyper-V-Guest-Drivers*" -ErrorAction SilentlyContinue
    $EventLogs = @()
    ForEach($RDSEventLog in $RDSEventLogs){
        $EventLogs += $RDSEventLog.LogName
    }
    FwExportEventLog $EventLogs $RDSLogFolder

    # Registries
    $RDSRegistries = @(
        ("HKCU:Software\Microsoft\Terminal Server Client", "$RDSLogFolder\Reg-HKCU-Terminal_Server_Client.txt"),
        ("HKLM:Software\Microsoft\Terminal Server Client", "$RDSLogFolder\Reg-HKLM-Terminal_Server_Client.txt"),
        ("HKLM:SOFTWARE\Policies\Microsoft\SystemCertificates", "$RDSLogFolder\Reg-HKLM-SystemCertificates.txt"),
        ("HKLM:SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings", "$RDSLogFolder\Reg-HKLM-Internet_Settings.txt"),
        ("HKLM:SYSTEM\CurrentControlSet\Control\Keyboard Layouts", "$RDSLogFolder\Reg-HKLM-Keyboard_Layouts.txt"),
        ("HKLM:SYSTEM\CurrentControlSet\Services\i8042prt", "$RDSLogFolder\Reg-HKLM-i8042prt.txt"),
        ("HKLM:SYSTEM\CurrentControlSet\Control\terminal Server", "$RDSLogFolder\Reg-HKLM-terminal_Server.txt"),
        ("HKLM:Softwar\Microsoft\Windows NT\CurrentVersion\TerminalServerGateway", "$RDSLogFolder\Reg-HKLM-TerminalServerGateway.txt"),
        ("HKCU:Software\Microsoft\Terminal Server Gateway", "$RDSLogFolder\Reg-HKCU-Terminal_Server_Gateway.txt"),
        ("HKLM:Software\Policies\Microsoft\Windows NT\Terminal Services", "$RDSLogFolder\Reg-HKLM-Terminal_Services.txt"),
        ("HKCU:Software\Policies\Microsoft\Windows NT\Terminal Services", "$RDSLogFolder\Reg-HKCU-Terminal_Services.txt"),
        ("HKLM:SOFTWARE\Microsoft\MSLicensing", "$RDSLogFolder\Reg-HKLM-MSLicensing.txt")
    )
    FwExportRegistry "RDS" $RDSRegistries

    # Commands
    $Commands = @(
        "certutil -store `"Remote Desktop`" | Out-File -Append $RDSLogFolder\RDPcert.txt",
        "qwinsta  | Out-File -Append $RDSLogFolder\qwinsta.txt"
    )
    Runcommands "RDS" $Commands -ThrowException:$False -ShowMessage:$True

    # !!! Below section only work on RDCB !!!
    # Get Servers of the farm:
    Try{
        $RDDeploymentServer = Get-RDServer -ErrorAction Stop
    }Catch{
        LogInfo ("[RDS] This system would not be RD Conection Broker and skipping collecting data for RD deployment.")
        Return
    }

    LogInfo ("[RDS] Getting RD deployment info. This may take a while.")
    $LogFile = "$RDSLogFolder\RDDeployment-info.txt"
    $BrokerServers = @()
    $WebAccessServers = @()
    $RDSHostServers = @()
    $GatewayServers = @()

    ForEach($Server in $RDDeploymentServer){
        Switch($Server.Roles){
            "RDS-CONNECTION-BROKER" {$BrokerServers += $Server.Server}
            "RDS-WEB-ACCESS" {$WebAccessServers += $Server.Server}
            "RDS-RD-SERVER" {$RDSHostServers += $Server.Server}
            "RDS-GATEWAY" {$GatewayServers += $Server.Server}
        }
    }
    Write-Output ("Machines involved in the deployment : " + $servers.Count) | Out-File -Append $LogFile
    Write-Output ("    -Broker(s) : " + $BrokerServers.Count) | Out-File -Append $LogFile

    ForEach($BrokerServer in $BrokerServers){
        $ServicesStatus = Get-CimInstance -ComputerName $BrokerServer -Query "Select * from Win32_Service where Name='rdms' or Name='tssdis' or Name='tscpubrpc'"
        ForEach ($stat in $ServicesStatus){
            Write-Output ("		      - " + $stat.Name + " service is " + $stat.State) | Out-File -Append $LogFile
        }
    }

    Write-Output ("`n	-RDS Host(s) : " + $RDSHostServers.Count) | Out-File -Append $LogFile
    ForEach($RDSHostServer in $RDSHostServers){
        Write-Output ("		" +	$RDSHostServer) | Out-File -Append $LogFile
        $ServicesStatus = Get-CimInstance -ComputerName $RDSHostServer -Query "Select * from Win32_Service where Name='TermService'"
        ForEach($stat in $ServicesStatus){
            Write-Output ("		      - " + $stat.Name +  "service is " + $stat.State) | Out-File -Append $LogFile
        }
    }

    Write-Output ("`n	-Web Access Server(s) : " + $WebAccessServers.Count) | Out-File -Append $LogFile
    ForEach($WebAccessServer in $WebAccessServers){
        Write-Output ("		" +	$WebAccessServer) | Out-File -Append $LogFile
    }

    Write-Output ("`n	-Gateway server(s) : " + $GatewayServers.Count) | Out-File -Append $LogFile
    ForEach($GatewayServer in $GatewayServers){
        Write-Output ("		" +	$GatewayServer) | Out-File -Append $LogFile
        $ServicesStatus = Get-CimInstance -ComputerName $GatewayServer -Query "Select * from Win32_Service where Name='TSGateway'"
        ForEach($stat in $ServicesStatus){
            Write-Output ("		      - " + $stat.Name + " service is " + $stat.State) | Out-File -Append $LogFile
        }
    }

    #Get active broker server.
    $ActiveBroker = Invoke-WmiMethod -Path ROOT\cimv2\rdms:Win32_RDMSEnvironment -Name GetActiveServer
    $ConnectionBroker = $ActiveBroker.ServerName
    Write-Output ("`nActiveManagementServer (broker) : " +	$ActiveBroker.ServerName) | Out-File -Append $LogFile

    # Deployment Properties
    Write-Output ("`nDeployment details : ") | Out-File -Append $LogFile
    # Is Broker configured in High Availability?
    $HighAvailabilityBroker = Get-RDConnectionBrokerHighAvailability
    $BoolHighAvail = $false
    If($null -eq $HighAvailabilityBroker)
    {
        $BoolHighAvail = $false
        Write-Output ("	Is Connection Broker configured for High Availability : " + $BoolHighAvail) | Out-File -Append $LogFile
    }Else{
        $BoolHighAvail = $true
        Write-Output ("	Is Connection Broker configured for High Availability : " + $BoolHighAvail) | Out-File -Append $LogFile
        Write-Output ("		- Client Access Name (Round Robin DNS) : " + $HighAvailabilityBroker.ClientAccessName) | Out-File -Append $LogFile
        Write-Output ("		- DatabaseConnectionString : " + $HighAvailabilityBroker.DatabaseConnectionString) | Out-File -Append $LogFile
        Write-Output ("		- DatabaseSecondaryConnectionString : " + $HighAvailabilityBroker.DatabaseSecondaryConnectionString) | Out-File -Append $LogFile
        Write-Output ("		- DatabaseFilePath : " + $HighAvailabilityBroker.DatabaseFilePath) | Out-File -Append $LogFile
    }
    
    #Gateway Configuration
    $GatewayConfig = Get-RDDeploymentGatewayConfiguration -ConnectionBroker $ConnectionBroker
    Write-Output ("`n	Gateway Mode : " + $GatewayConfig.GatewayMode) | Out-File -Append $LogFile
    If($GatewayConfig.GatewayMode -eq "custom"){
        Write-Output ("		- LogonMethod : " + $GatewayConfig.LogonMethod) | Out-File -Append $LogFile
        Write-Output ("		- GatewayExternalFQDN : " + $GatewayConfig.GatewayExternalFQDN) | Out-File -Append $LogFile
        Write-Output ("		- GatewayBypassLocal : " + $GatewayConfig.BypassLocal) | Out-File -Append $LogFile
        Write-Output ("		- GatewayUseCachedCredentials : " + $GatewayConfig.UseCachedCredentials) | Out-File -Append $LogFile
    }
    
    # RD Licencing
    $LicencingConfig = Get-RDLicenseConfiguration -ConnectionBroker $ConnectionBroker
    Write-Output ("`n	Licencing Mode : " + $LicencingConfig.Mode) | Out-File -Append $LogFile
    If($LicencingConfig.Mode -ne "NotConfigured"){
        Write-Output ("		- Licencing Server(s) : " + $LicencingConfig.LicenseServer.Count) | Out-File -Append $LogFile
        foreach ($licserver in $LicencingConfig.LicenseServer)
        {
            Write-Output ("		       - Licencing Server : " + $licserver) | Out-File -Append $LogFile
        }
    }
    # RD Web Access
    Write-Output ("`n	Web Access Server(s) : " + $WebAccessServers.Count) | Out-File -Append $LogFile
    ForEach($WebAccessServer in $WebAccessServers){
        Write-Output ("	     - Name : " + $WebAccessServer) | Out-File -Append $LogFile
        Write-Output ("	     - Url : " + "https://" + $WebAccessServer + "/rdweb") | Out-File -Append $LogFile
    }
    
    # Certificates
    #Get-ChildItem -Path cert:\LocalMachine\my -Recurse | Format-Table -Property DnsNameList, EnhancedKeyUsageList, NotAfter, SendAsTrustedIssuer
    Write-Output ("`n	Certificates ") | Out-File -Append $LogFile
    $certificates = Get-RDCertificate -ConnectionBroker $ConnectionBroker
    ForEach($certificate in $certificates){
    Write-Output ("		- Role : " + $certificate.Role) | Out-File -Append $LogFile
    Write-Output ("			- Level : " + $certificate.Level) | Out-File -Append $LogFile
    Write-Output ("			- Expires on : " + $certificate.ExpiresOn) | Out-File -Append $LogFile
    Write-Output ("			- Issued To : " + $certificate.IssuedTo) | Out-File -Append $LogFile
    Write-Output ("			- Issued By : " + $certificate.IssuedBy) | Out-File -Append $LogFile
    Write-Output ("			- Thumbprint : " + $certificate.Thumbprint) | Out-File -Append $LogFile
    Write-Output ("			- Subject : " + $certificate.Subject) | Out-File -Append $LogFile
    Write-Output ("			- Subject Alternate Name : " + $certificate.SubjectAlternateName) | Out-File -Append $LogFile
    }

    #RDS Collections
    $collectionnames = Get-RDSessionCollection 
    $client = $null
    $connection = $null
    $loadbalancing = $null 
    $Security = $null
    $UserGroup = $null
    $UserProfileDisks = $null

    Write-Output ("`nRDS Collections : ") | Out-File -Append $LogFile
    ForEach($Collection in $collectionnames){
        $CollectionName = $Collection.CollectionName
        Write-Output ("	Collection : " +  $CollectionName) | Out-File -Append $LogFile
        Write-Output ("		Resource Type : " + $Collection.ResourceType) | Out-File -Append $LogFile
        If($Collection.ResourceType -eq "RemoteApp programs"){
            Write-Output ("			Remote Apps : ")
            $remoteapps = Get-RDRemoteApp -ConnectionBroker $ConnectionBroker -CollectionName $CollectionName
            foreach ($remoteapp in $remoteapps)
            {
                Write-Output ("			- DisplayName : " + $remoteapp.DisplayName) | Out-File -Append $LogFile
                Write-Output ("				- Alias : " + $remoteapp.Alias) | Out-File -Append $LogFile
                Write-Output ("				- FilePath : " + $remoteapp.FilePath) | Out-File -Append $LogFile
                Write-Output ("				- Show In WebAccess : " + $remoteapp.ShowInWebAccess) | Out-File -Append $LogFile
                Write-Output ("				- CommandLineSetting : " + $remoteapp.CommandLineSetting) | Out-File -Append $LogFile
                Write-Output ("				- RequiredCommandLine : " + $remoteapp.RequiredCommandLine) | Out-File -Append $LogFile
                Write-Output ("				- UserGroups : " + $remoteapp.UserGroups) | Out-File -Append $LogFile
            }
        }

        # $rdshServers
        $rdshservers = Get-RDSessionHost -ConnectionBroker $ConnectionBroker -CollectionName $CollectionName
        Write-Output ("`n		Servers in that collection : ") | Out-File -Append $LogFile
        ForEach ($rdshServer in $rdshservers)
        {
            Write-Output ("			- SessionHost : " + $rdshServer.SessionHost) | Out-File -Append $LogFile
            Write-Output ("				- NewConnectionAllowed : " + $rdshServer.NewConnectionAllowed) | Out-File -Append $LogFile
        }
        
        $client = Get-RDSessionCollectionConfiguration -ConnectionBroker $ConnectionBroker -CollectionName $CollectionName -Client 
        Write-Output ("		Client Settings : ") | Out-File -Append $LogFile
        Write-Output ("			- MaxRedirectedMonitors : " + $client.MaxRedirectedMonitors) | Out-File -Append $LogFile
        Write-Output ("			- RDEasyPrintDriverEnabled : " + $client.RDEasyPrintDriverEnabled) | Out-File -Append $LogFile
        Write-Output ("			- ClientPrinterRedirected : " + $client.ClientPrinterRedirected) | Out-File -Append $LogFile
        Write-Output ("			- ClientPrinterAsDefault : " + $client.ClientPrinterAsDefault) | Out-File -Append $LogFile
        Write-Output ("			- ClientDeviceRedirectionOptions : " + $client.ClientDeviceRedirectionOptions) | Out-File -Append $LogFile
        
        $connection = Get-RDSessionCollectionConfiguration -ConnectionBroker $ConnectionBroker -CollectionName $CollectionName -Connection
        Write-Output ("`n		Connection Settings : ") | Out-File -Append $LogFile
        Write-Output ("			- DisconnectedSessionLimitMin : " + $connection.DisconnectedSessionLimitMin) | Out-File -Append $LogFile
        Write-Output ("			- BrokenConnectionAction : " + $connection.BrokenConnectionAction) | Out-File -Append $LogFile
        Write-Output ("			- TemporaryFoldersDeletedOnExit : " + $connection.TemporaryFoldersDeletedOnExit) | Out-File -Append $LogFile
        Write-Output ("			- AutomaticReconnectionEnabled : " + $connection.AutomaticReconnectionEnabled) | Out-File -Append $LogFile
        Write-Output ("			- ActiveSessionLimitMin : " + $connection.ActiveSessionLimitMin) | Out-File -Append $LogFile
        Write-Output ("			- IdleSessionLimitMin : " + $connection.IdleSessionLimitMin) | Out-File -Append $LogFile
        
        $loadbalancing = Get-RDSessionCollectionConfiguration -ConnectionBroker $ConnectionBroker -CollectionName $CollectionName -LoadBalancing
        Write-Output ("`n		Load Balancing Settings : ") | Out-File -Append $LogFile
        ForEach($SessHost in $loadbalancing){
            Write-Output ("			- SessionHost : " + $SessHost.SessionHost) | Out-File -Append $LogFile
            Write-Output ("				- RelativeWeight : " + $SessHost.RelativeWeight) | Out-File -Append $LogFile
            Write-Output ("				- SessionLimit : " + $SessHost.SessionLimit) | Out-File -Append $LogFile
        }
        
        $Security = Get-RDSessionCollectionConfiguration -ConnectionBroker $ConnectionBroker -CollectionName $CollectionName -Security
        Write-Output ("`n		Security Settings : ") | Out-File -Append $LogFile
        Write-Output ("			- AuthenticateUsingNLA : " + $Security.AuthenticateUsingNLA) | Out-File -Append $LogFile
        Write-Output ("			- EncryptionLevel : " + $Security.EncryptionLevel) | Out-File -Append $LogFile
        Write-Output ("			- SecurityLayer : " + $Security.SecurityLayer) | Out-File -Append $LogFile
        
        $UserGroup = Get-RDSessionCollectionConfiguration -ConnectionBroker $ConnectionBroker -CollectionName $CollectionName -UserGroup 
        Write-Output ("`n		User Group Settings : ") | Out-File -Append $LogFile
        Write-Output ("			- UserGroup  : " + $UserGroup.UserGroup) | Out-File -Append $LogFile
        
        $UserProfileDisks = Get-RDSessionCollectionConfiguration -ConnectionBroker $ConnectionBroker -CollectionName $CollectionName -UserProfileDisk
        Write-Output ("		User Profile Disk Settings : ") | Out-File -Append $LogFile
        Write-Output ("			- EnableUserProfileDisk : " + $UserProfileDisks.EnableUserProfileDisk) | Out-File -Append $LogFile
        Write-Output ("			- MaxUserProfileDiskSizeGB : " + $UserProfileDisks.MaxUserProfileDiskSizeGB) | Out-File -Append $LogFile
        Write-Output ("			- DiskPath : " + $UserProfileDisks.DiskPath) | Out-File -Append $LogFile
        Write-Output ("			- ExcludeFilePath : " + $UserProfileDisks.ExcludeFilePath) | Out-File -Append $LogFile
        Write-Output ("			- ExcludeFolderPath : " + $UserProfileDisks.ExcludeFolderPath) | Out-File -Append $LogFile
        Write-Output ("			- IncludeFilePath : " + $UserProfileDisks.IncludeFilePath) | Out-File -Append $LogFile
        Write-Output ("			- IncludeFolderPath : " + $UserProfileDisks.IncludeFolderPath) | Out-File -Append $LogFile
        
        $CustomRdpProperty = Get-RDSessionCollectionConfiguration -ConnectionBroker $ConnectionBroker -CollectionName $CollectionName        
        Write-Output ("`n		Custom Rdp Properties : " + $CustomRdpProperty.CustomRdpProperty) | Out-File -Append $LogFile
        
        $usersConnected = Get-RDUserSession -ConnectionBroker $ConnectionBroker -CollectionName $CollectionName
        Write-Output ("`n		Users connected to this collection : ") | Out-File -Append $LogFile
        Foreach($userconnected in $usersConnected){
            Write-Output ("			User : " + $userConnected.DomainName + "\" + $userConnected.UserName) | Out-File -Append $LogFile
            Write-Output ("				- HostServer : " + $userConnected.HostServer) | Out-File -Append $LogFile
            Write-Output ("				- UnifiedSessionID : " + $userConnected.UnifiedSessionID) | Out-File -Append $LogFile
        }
    }
    EndFunc $MyInvocation.MyCommand.Name
}

Function CollectUEX_ShellLog{
    EnterFunc $MyInvocation.MyCommand.Name
    $ShellLogFolder = "$LogFolder\ShellLog$LogSuffix"
    $LogPrefix = 'Shell'
    
    Try{
        FwCreateLogFolder $ShellLogFolder
    }Catch{
        LogException  ("Unable to create $ShellLogFolder.") $_
        Return
    }

    $ShellRegistries = @(
        ('HKLM:Software\Policies\Microsoft\Windows\Explorer', "$ShellLogFolder\ExplorerPolicy_HKLM-Reg.txt"),
        ('HKCU:Software\Microsoft\Windows\CurrentVersion\Policies\Explorer', "$ShellLogFolder\ExplorerPolicy_HKCU-Reg.txt"),
        ("HKCU:Software\Microsoft\Windows\Shell\Associations", "$ShellLogFolder\HKCU-Associations_Reg.txt"),
        ("HKCU:Software\Microsoft\Windows\CurrentVersion\FileAssociations", "$ShellLogFolder\HKCU-FileAssociations_Reg.txt"),
        ("HKCU:SOFTWARE\Microsoft\Windows\CurrentVersion\ThumbnailCache", "$ShellLogFolder\HKCU-ThumbnailCache_Reg.txt")
    )
    FwExportRegistry $LogPrefix $ShellRegistries

    # Explorer reg
    REG SAVE 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer' "$ShellLogFolder\HKCU-Explorer_Reg.HIV" 2>&1 | Out-Null
    REG SAVE 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' "$ShellLogFolder\HKLM-Explorer_Reg.HIV" 2>&1 | Out-Null

    # ARCache. Use ARCacheDump.exe to dump ARCache({GUID}.X.ver0x000000000000000X.db)
    LogInfo ("[Shell] Copying ARCache.")
    Try{
        New-Item "$ShellLogFolder\ARCache" -ItemType Directory -ErrorAction Stop | Out-Null
        Copy-Item "$env:userprofile\AppData\Local\Microsoft\Windows\Caches\*" "$ShellLogFolder\ARCache" 
    }Catch{
        LogException  ("Unable to copy ARCache.") $_ $fLogFileOnly
    }

    LogInfo ("[Shell] Copying program shortcut files.")
    Copy-Item "$env:userprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs" "$ShellLogFolder\Programs-user" -Recurse
    Copy-Item "C:\ProgramData\Microsoft\Windows\Start Menu\Programs" "$ShellLogFolder\Programs-system" -Recurse

    EndFunc $MyInvocation.MyCommand.Name
}

Function CollectUEX_CortanaLog{
    EnterFunc $MyInvocation.MyCommand.Name
    $LogPrefix = 'Cortana'
    $ComponentLogFolder = "$LogFolder\$LogPrefix"+ "Log" + $LogSuffix
    
    Try{
        FwCreateLogFolder $ComponentLogFolder
    }Catch{
        LogException  ("Unable to create $ComponentLogFolder.") $_
        Return
    }

    $CortanaRegistries = @(
        ("HKLM:SOFTWARE\Policies\Microsoft\Windows\Windows Search" ,"$ComponentLogFolder\CortanaPolicy_Reg.txt"),
        ("HKLM:SOFTWARE\Microsoft\Windows Search", "$ComponentLogFolder\HKLM-Cortana_Reg.txt"),
        ("HKCU:Software\Microsoft\Windows\CurrentVersion\Search", "$ComponentLogFolder\HKCU-Cortana_Reg.txt")
    )
    FwExportRegistry $LogPrefix $CortanaRegistries

    EndFunc $MyInvocation.MyCommand.Name
}

Function CollectUEX_UEVLog{
    EnterFunc $MyInvocation.MyCommand.Name
    Try{
        $Status = Get-UevStatus -ErrorAction SilentlyContinue
    }Catch{
        LogInfo ("Get-UevStatus failed. Probably this system does not have UE-V feature.")
        Return
    }
    If($Null -ne $Status -and !$Status.UevEnabled){
        LogMessage $LogLevel.Warning ("UEV is not enabled.")
        Return
    }

    $UEVTasks =@(
        "Monitor Application Settings",
        "Sync Controller Application",
        "Synchronize Settings at Logoff",
        "Template Auto Update"
    )

    $UEVLogFolder = "$LogFolder\UEVLog$LogSuffix"
    Try{
        FwCreateLogFolder $UEVLogFolder
    }Catch{
        LogException  ("Unable to create $UEVLogFolder.") $_
        Return
    }

    Try{
        $RegistryFolder = Join-Path $UEVLogFolder "Registry" 
        New-Item $RegistryFolder -ItemType Directory -ErrorAction Stop | Out-Null
        $SchedulerFolder = Join-Path $UEVLogFolder "TaskScheduler" 
        New-Item $SchedulerFolder -ItemType Directory -ErrorAction Stop | Out-Null
        $TemplateFolder = Join-Path $UEVLogFolder "UEV-Templates" 
        New-Item $TemplateFolder -ItemType Directory -ErrorAction Stop | Out-Null
        $PackageFolder = Join-Path $UEVLogFolder "UEV-Packages" 
        New-Item $PackageFolder -ItemType Directory -ErrorAction Stop | Out-Null
        #$EventLogFolder = Join-Path $UEVLogFolder "EventLogs" 
        #New-Item $EventLogFolder -ItemType Directory | Out-Null
    }Catch{
        LogException ("An exception happened during creation of logfoler") $_
        Return
    }

    LogInfo ("[UEV] Exporting UE-V regstries.")
    reg export "HKLM\SOFTWARE\Microsoft\UEV" (Join-Path $RegistryFolder "UEV.reg") | Out-Null
    reg export "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule" (Join-Path $RegistryFolder "Schedule.reg")| Out-Null
    reg save "HKLM\SYSTEM" (Join-Path $RegistryFolder "SYSTEM.hiv")| Out-Null
    reg save "HKLM\Software" (Join-Path $RegistryFolder "Software.hiv")| Out-Null

    # UEV Tasks
    LogInfo ("[UEV] Exporting UE-V tasks.")
    ForEach($UEVTask in $UEVTasks){
        schtasks /query /xml /tn ("\Microsoft\UE-V\" + $UEVTask) > ($SchedulerFolder + "\" + $UEVTask + ".xml")
    }

    # UEV configuration
    LogInfo ("[UEV] Running UE-V commandlets")
    Get-UEVStatus | Out-File (Join-Path $UEVLogFolder "Get-UevStatus.txt")
    Get-UEVConfiguration | Out-File (Join-Path $UEVLogFolder "Get-UEVConfiguration.txt")
    Get-UEVTemplate  | Out-File (Join-Path $UEVLogFolder "Get-UEVTemplate.txt")

    # UEV template
    LogInfo ("[UEV] Copying all templates to log folder.")
    Copy-Item  ("C:\ProgramData\Microsoft\UEV\Templates\*") $TemplateFolder -Recurse

    # UEV package
    $UEVConfig = Get-UEVConfiguration

    If($UEVConfig.SettingsStoragePath.Length -ne 0){
        $PackagePath = [System.Environment]::ExpandEnvironmentVariables($UEVConfig.SettingsStoragePath + "\SettingsPackages")

        If($PackagePath -ne $Null){
            LogInfo ("[UEV] Found package path: $PackagePath")
            If(Test-Path -Path $PackagePath){
                $PackageFiles = Get-ChildItem $PackagePath "*.pkgx" -Recurse -Depth 5
                If($PackageFiles.Length -ne 0 -and $Null -ne $PackageFiles){
                    LogInfo ('[UEV] Copying UE-V packages')
                    ForEach($PackageFile in $PackageFiles){
                        Copy-Item  $PackageFile.fullname $PackageFolder -Recurse
                    }
                }
            }
        }
    }
    EndFunc $MyInvocation.MyCommand.Name
}

Function CollectUEX_PrintLog{
    EnterFunc $MyInvocation.MyCommand.Name
    $PrintLogFolder = "$LogFolder\PrintLog$LogSuffix"
    $PrintLogDumpFolder = "$PrintLogFolder\Process dump"
    $PrintLogInfFolder = "$PrintLogFolder\inf"

    Try{
        FwCreateLogFolder $PrintLogFolder
        FwCreateLogFolder $PrintLogDumpFolder
        FwCreateLogFolder $PrintLogInfFolder
    }Catch{
        LogException ("Unable to create $PrintLogFolder.") $_
        Return
    }

    # Event log
    $EventLogs = @(
        "System",
        "Application",
        "Microsoft-Windows-DeviceSetupManager/Admin",
        "Microsoft-Windows-DeviceSetupManager/Operational",
        "Microsoft-Windows-PrintService/Admin",
        "Microsoft-Windows-PrintService/Operational"
    )
    FwExportEventLog $EventLogs $PrintLogFolder

    # File version
    LogInfo ("[Printing] Getting file version of printing modules")
    FwFileVersion -FilePath "$env:windir\System32\localspl.dll" | Out-File -Append "$PrintLogFolder\FilesVersion.csv"
    FwFileVersion -FilePath "$env:windir\system32\spoolsv.exe" | Out-File -Append "$PrintLogFolder\FilesVersion.csv"
    FwFileVersion -FilePath "$env:windir\system32\win32spl.dll" | Out-File -Append "$PrintLogFolder\FilesVersion.csv"
    FwFileVersion -FilePath "$env:windir\system32\spoolss.dll" | Out-File -Append "$PrintLogFolder\FilesVersion.csv"
    FwFileVersion -FilePath "$env:windir\system32\PrintIsolationProxy.dll" | Out-File -Append "$PrintLogFolder\FilesVersion.csv"
    FwFileVersion -FilePath "$env:windir\system32\winspool.drv" | Out-File -Append "$PrintLogFolder\FilesVersion.csv"

    # Other commands
    $Commands = @(
        "reg export `'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Print\Providers\Client Side Rendering Print Provider`' $PrintLogFolder\reg-HKLM-Csr.txt",
        "reg query `'HKCU\Printers`' /s | Out-File $PrintLogFolder\reg-HKCU-Printers.txt",
        "reg query `'HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`' /s | Out-File $PrintLogFolder\reg-HKCU-Windows.txt",
        "reg query `'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Print`' /s | Out-File $PrintLogFolder\reg-HKLM-Software-Print.txt",
        "reg query `'HKLM\SYSTEM\CurrentControlSet\Control\Print`' /s | Out-File $PrintLogFolder\reg-HKLM-System-Print.txt",
        "reg query `'HKLM\SYSTEM\CurrentControlSet\Control\DeviceClasses`' /s | Out-File $PrintLogFolder\reg-HKLM-System-DeviceClasses.txt",
        "reg query `'HKLM\SYSTEM\CurrentControlSet\Control\DeviceContainers`' /s | Out-File $PrintLogFolder\reg-HKLM-System-DeviceContainers.txt",
        "reg query `'HKLM\SYSTEM\CurrentControlSet\Enum\SWD`' /s | Out-File $PrintLogFolder\reg-HKLM-System-SWD.txt",
        "reg query `'HKLM\SYSTEM\DriverDatabase`' /s | Out-File $PrintLogFolder\reg-HKLM-System-DriverDatabase.txt",
        "reg export `'HKEY_CURRENT_USER\Printers\Connections`' $PrintLogFolder\reg-HKCU-User_Print_connections.reg.txt",
        "Copy-Item C:\Windows\INF\setupapi.dev.log -Destination $PrintLogFolder",
        "sc.exe queryex spooler | Out-File -Append $PrintLogFolder\Spooler_ServiceConfig.txt",
        "cscript C:\Windows\System32\Printing_Admin_Scripts\en-US\prndrvr.vbs -l | Out-File -Append $PrintLogFolder\prndrvr_en.txt",
        "cscript C:\Windows\System32\Printing_Admin_Scripts\en-US\prnmngr.vbs -l | Out-File -Append $PrintLogFolder\prnmngr_en.txt",
        "cscript C:\Windows\System32\Printing_Admin_Scripts\en-US\prnjobs.vbs -l | Out-File -Append $PrintLogFolder\prnjobs_en.txt",
        "cscript C:\Windows\System32\Printing_Admin_Scripts\en-US\prnport.vbs -l | Out-File -Append $PrintLogFolder\prnport_en.txt",
        "cscript C:\Windows\System32\Printing_Admin_Scripts\ja-JP\prndrvr.vbs -l | Out-File -Append $PrintLogFolder\prndrvr_ja.txt",
        "cscript C:\Windows\System32\Printing_Admin_Scripts\ja-JP\prnmngr.vbs -l | Out-File -Append $PrintLogFolder\prnmngr_ja.txt",
        "cscript C:\Windows\System32\Printing_Admin_Scripts\ja-JP\prnjobs.vbs -l | Out-File -Append $PrintLogFolder\prnjobs_ja.txt",
        "cscript C:\Windows\System32\Printing_Admin_Scripts\ja-JP\prnport.vbs -l | Out-File -Append $PrintLogFolder\prnport_ja.txt",
        "tree C:\Windows\Inf /f | Out-File -Append $PrintLogFolder\tree_inf.txt",
        "tree C:\Windows\System32\DriverStore /f | Out-File -Append $PrintLogFolder\tree_DriverStore.txt",
        "tree C:\Windows\System32\spool /f | Out-File -Append $PrintLogFolder\tree_spool.txt",
        "Copy-Item `"C:\Windows\Inf\oem*.inf`" $PrintLogInfFolder",
        "Copy-Item `"C:\Windows\inf\Setupapi*`" $PrintLogInfFolder",
        "pnputil /export-pnpstate $PrintLogFolder\pnputil_pnpstate.pnp",
        "pnputil -e | Out-File -Append $PrintLogFolder\pnputil_e.txt",
        "reg query `"HKLM\DRIVERS\DriverDatabase`" /s | Out-File $PrintLogFolder\reg-HKLM-Drivers-DriverDatabase.txt"
    )
    RunCommands "Printing" $Commands -ThrowException:$False -ShowMessage:$True

    # Process dump
    FwCaptureUserDump "spoolsv" $PrintLogDumpFolder -IsService:$False
    FwCaptureUserDump "splwow64" $PrintLogDumpFolder -IsService:$False
    FwCaptureUserDump "PrintIsolationHost" $PrintLogDumpFolder -IsService:$False

    EndFunc $MyInvocation.MyCommand.Name
}

Function CollectUEX_AppXLog{
    EnterFunc $MyInvocation.MyCommand.Name
    $AppXLogFolder = "$LogFolder\AppXLog$LogSuffix"
    Try{
        FwCreateLogFolder $AppXLogFolder
    }Catch{
        LogException ("Unable to create $AppXLogFolder.") $_
        Return
    }

    LogInfo ("[AppX] Running Get-AppxPackage")
    ForEach ($p in $(Get-AppxPackage)){ 
        ForEach ($n in ($p).Dependencies.PackageFullName){ 
            $p.packagefullname + '--' + $n | Out-File -Append "$AppXLogFolder\appxpackage_output.txt"
        }
    }

    If(FwIsElevated){
        LogInfo ("[AppX] Running Get-AppxPackage -allusers")
        Try{
            ForEach ($p in $(Get-AppxPackage -AllUsers)){
                ForEach ($n in ($p).PackageUserInformation){
                    $p.packagefullname + ' -- ' + $n.UserSecurityId.Sid + ' [' + $n.UserSecurityId.UserName + '] : ' + $n.InstallState | Out-File -Append "$AppXLogFolder/Get-Appxpackage-installeduser.txt"
                }
            }
        }Catch{
            LogException  ("An error happened in Get-AppxPackage.") $_ $fLogFileOnly
        }
        Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Out-File (Join-Path $AppXLogFolder 'Get-AppxProvisionedPackage-online.txt')
    }

    LogInfo ("[AppX] Exporting event logs.")
    $AppXEventlogs = @(
    "Microsoft-Windows-Shell-Core/Operational"
    "Microsoft-Windows-ShellCommon-StartLayoutPopulation/Operational"
    "Microsoft-Windows-TWinUI/Operational"
    "Microsoft-Windows-AppModel-RunTime/Admin"
    "Microsoft-Windows-AppReadiness/Operational"
    "Microsoft-Windows-AppReadiness/Admin"
    "Microsoft-Windows-AppXDeployment/Operational"
    "Microsoft-Windows-AppXDeploymentServer/Operational"
    "Microsoft-Windows-AppxPackaging/Operational"
    "Microsoft-Windows-BackgroundTaskInfrastructure/Operational"
    "Microsoft-Windows-StateRepository/Operational"
    "Microsoft-Windows-Store/Operational"
    "Microsoft-Windows-CloudStore/Operational"
    "Microsoft-Windows-CoreApplication/Operational"
    "Microsoft-Windows-CodeIntegrity/Operational"
    "Microsoft-Windows-PushNotification-Platform/Operational"
    "Microsoft-Windows-ApplicationResourceManagementSystem/Operational"
    )
    FwExportEventLog $AppXEventlogs $AppXLogFolder

    LogInfo ("[AppX] Exporting registries.")
    $AppxRegistries = @(
        ("HKCU:Software\Classes\Extensions\ContractId\Windows.Launch", "$AppXLogFolder\reg-HKCU-WindowsLaunch.txt"),
        ("HKLM:Software\Microsoft\Windows\CurrentVersion\Policies", "$AppXLogFolder\reg-HKLM-Policies.txt"),
        ("HKLM:Software\Microsoft\Windows\CurrentVersion\Policies", "$AppXLogFolder\reg-HKLM-Policies.txt"),
        ("HKLM:Software\Policies\Microsoft\Windows\AppX", "$AppXLogFolder\reg-HKLM-AppXPolicy.txt"),
        ("HKLM:Software\Microsoft\Windows\CurrentVersion\SystemProtectedUserData" , "$AppXLogFolder\reg-HKLM-SystemProtectedUserData.txt"),
        ("HKEY_CLASSES_ROOT:Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel", "$AppXLogFolder\reg-HKCR-AppModel.txt")
    )
    FwExportRegistry "AppX" $AppxRegistries

    # Size of these keys are large so use reg export to shorten export time.
    $Commands = @(
        "Get-ChildItem `"c:\program files\windowsapps`" -Recurse -ErrorAction Stop | Out-File $AppXLogFolder\dir-windowsapps.txt",
        "Get-ChildItem `"c:\Windows\SystemApps`" -Recurse -ErrorAction Stop | Out-File -Append $AppXLogFolder\dir-systemapps.txt",
        "Get-Appxpackage -ErrorAction Stop | Out-File $AppXLogFolder\Get-Appxpackage.txt"
        "Get-AppxPackage -alluser -ErrorAction Stop | Out-File $AppXLogFolder\Get-AppxPackage-alluser.txt",
        "New-Item $AppXLogFolder\Panther -ItemType Directory -ErrorAction Stop | Out-Null",
        "Copy-Item C:\Windows\Panther\*.log $AppXLogFolder\Panther -ErrorAction SilentlyContinue | Out-Null",
        "Copy-Item $env:ProgramData\Microsoft\Windows\AppXProvisioning.xml $AppXLogFolder -ErrorAction SilentlyContinue | Out-Null",
        "whoami /user /fo list | Out-File $AppXLogFolder\userinfo.txt",
        "New-Item $AppXLogFolder\ARCache -ItemType Directory -ErrorAction Stop | Out-Null",
        "Copy-Item $env:userprofile\AppData\Local\Microsoft\Windows\Caches\* $AppXLogFolder\ARCache",
        "REG EXPORT HKLM\Software\Microsoft\windows\currentversion\appx $AppXLogFolder\reg-HKLM-appx.txt | Out-Null",
        "REG EXPORT HKLM\System\SetUp\Upgrade\AppX $AppXLogFolder\reg-HKLM-AppXUpgrade.txt | Out-Null",
        "REG EXPORT HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository $AppXLogFolder\reg-HKLM-StateRepository.txt | Out-Null",
        "REG EXPORT `"HKLM\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel`" $AppXLogFolder\reg-LM-Classes-AppModel.txt | Out-Null",
        "REG EXPORT `"HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel`" $AppXLogFolder\reg-HKCU-Classes-AppModel.txt | Out-Null",
        "REG SAVE `"HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer`" $AppXLogFolder\reg-HKCU-AppContainer.hiv | Out-Null",
        "REG EXPORT HKLM\Software\Microsoft\Windows\CurrentVersion\AppModel $AppXLogFolder\reg-HKLM-AppModel.txt",
        "REG EXPORT HKCU\Software\Microsoft\Windows\CurrentVersion\AppModel $AppXLogFolder\reg-HKCU-AppModel.txt",
        "tree $env:USERPROFILE\AppData\Local\Microsoft\Windows\Shell /f | Out-File $AppXLogFolder\tree_UserProfile_Shell.txt",
        "tree $env:USERPROFILE\AppData\Local\Packages /f | Out-File $AppXLogFolder\tree_UserProfile_Packages.txt",
        "tree `"C:\Program Files\WindowsApps`" /f | Out-File $AppXLogFolder\tree_ProgramFiles_WindowsApps.txt",
        "ls `"C:\Program Files\WindowsApps`" -Recurse -ErrorAction SilentlyContinue | Out-File $AppXLogFolder\dir_ProgramFiles_WindowsApps.txt",
        "tree `"C:\Users\Default\AppData\Local\Microsoft\Windows\Shell`" /f | Out-File $AppXLogFolder\tree_Default_Shell.txt"
    )
    RunCommands "AppX" $Commands -ThrowException:$False -ShowMessage:$True

    EndFunc $MyInvocation.MyCommand.Name
}

Function CollectUEX_WMILog{
    EnterFunc $MyInvocation.MyCommand.Name
    $WMILogFolder = "$LogFolder\WMILog$LogSuffix"
    $WMISubscriptions = "$WMILogFolder\Subscriptions"
    $WMIProcDumpFolder = "$WMILogFolder\Process dump"
    $LogPrefix = "WMI"

    Try{
        FwCreateLogFolder $WMILogFolder
        FwCreateLogFolder $WMISubscriptions
        FwCreateLogFolder $WMIProcDumpFolder
    }Catch{
        LogMessage ("Unable to create $WMILogFolder.") $_ 
        Return
    }

    # Process dump
    FwCaptureUserDump "WinMgmt" $WMIProcDumpFolder -IsService:$True
    FwCaptureUserDump "WMIPrvse" $WMIProcDumpFolder -IsService:$False
    ForEach($DecoupledProvider in $DecoupledProviders){
        FwCaptureUserDump $DecoupledProvider.ProcessName $WMIProcDumpFolder -IsService:$False
    }

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

    # MOFs
    LogInfo ('[WMI] Collecting Autorecover MOFs content') 
    $mof = (Get-Itemproperty -ErrorAction SilentlyContinue -literalpath ("HKLM:\SOFTWARE\Microsoft\Wbem\CIMOM")).'Autorecover MOFs'
    If ($mof.length -ne 0) {
        $mof | Out-File ("$WMILogFolder\Autorecover MOFs.txt")
    }

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

    # File version
    LogInfo ("[WMI] Getting file version of WMI modules")
    FwFileVersion -Filepath ("$env:windir\system32\wbem\wbemcore.dll") | Out-File -FilePath ("$WMILogFolder\FilesVersion.csv") -Append
    FwFileVersion -Filepath ("$env:windir\system32\wbem\repdrvfs.dll") | Out-File -FilePath ("$WMILogFolder\FilesVersion.csv") -Append
    FwFileVersion -Filepath ("$env:windir\system32\wbem\WmiPrvSE.exe") | Out-File -FilePath ("$WMILogFolder\FilesVersion.csv") -Append
    FwFileVersion -Filepath ("$env:windir\system32\wbem\WmiPerfClass.dll") | Out-File -FilePath ("$WMILogFolder\FilesVersion.csv") -Append
    FwFileVersion -Filepath ("$env:windir\system32\wbem\WmiApRpl.dll") | Out-File -FilePath ("$WMILogFolder\FilesVersion.csv") -Append

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

    # Details of decoupled providers
    LogInfo ("[WMI] Collecting details of decoupled providers")
    $list = Get-Process
    $DecoupledProviders = @()
    foreach ($proc in $list) {
        $prov = Get-Process -id $proc.id -Module -ErrorAction SilentlyContinue | Where-Object {$_.ModuleName -eq "wmidcprv.dll"} 
        if (($prov | Measure-Object).count -gt 0) {
            $DecoupledProviders += $proc

            if (-not $hdr) {
                "Decoupled providers" | Out-File -FilePath ("$WMILogFolder\ProviderHosts.txt") -Append
                " " | Out-File -FilePath ("$WMILogFolder\ProviderHosts.txt") -Append
                $hdr = $true
            }
            
            $prc = FwExecWMIQuery -Namespace "root\cimv2" -Query ("select ProcessId, CreationDate, HandleCount, ThreadCount, PrivatePageCount, ExecutablePath, KernelModeTime, UserModeTime from Win32_Process where ProcessId = " +  $proc.id)
            $ut= New-TimeSpan -Start $prc.ConvertToDateTime($prc.CreationDate)
            
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

    # Service configuration
    LogInfo ("[WMI] Exporting service configuration")
    $Commands = @(
        "sc.exe queryex winmgmt | Out-File $WMILogFolder\WinMgmtServiceConfig.txt -Append"
        "sc.exe qc winmgmt | Out-File $WMILogFolder\WinMgmtServiceConfig.txt -Append"
        "sc.exe enumdepend winmgmt 3000  | Out-File $WMILogFolder\WinMgmtServiceConfig.txt -Append"
        "sc.exe sdshow winmgmt | Out-File $WMILogFolder\WinMgmtServiceConfig.txt -Append"
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

    $Commands = @(
        "wevtutil epl Application $WMILogFolder\Application.evtx",
        "wevtutil al $WMILogFolder\Application.evtx /l:en-us",
        "wevtutil epl System $WMILogFolder\System.evtx",
        "wevtutil al $WMILogFolder\System.evtx /l:en-us",
        "wevtutil epl Microsoft-Windows-WMI-Activity/Operational $WMILogFolder\Microsoft-Windows-WMI-Activity-Operational.evtx",
        "wevtutil al $WMILogFolder\Microsoft-Windows-WMI-Activity-Operational.evtx /l:en-us"
    )
    RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$True

    # WMI-Activity log
    LogInfo ('[WMI] Exporting WMI Operational log.')
    $actLog = Get-WinEvent -logname "Microsoft-Windows-WMI-Activity/Operational" -Oldest -ErrorAction SilentlyContinue
    If(($actLog | Measure-Object).count -gt 0) {
        $actLog | Out-String -width 1000 | Out-File "$WMILogFolder\Microsoft-Windows-WMI-Activity-Operational.txt"
    }

    LogInfo ('[WMI] Collecting WMI repository and registry.')
    $Commands = @(
        "Get-ChildItem $env:SYSTEMROOT\System32\Wbem -Recurse -ErrorAction SilentlyContinue | Out-File -Append $WMILogFolder\wbemfolder.txt"
        "REG QUERY 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\wbem' /s 2>&1 | Out-File -Append $WMILogFolder\wbem.reg"
    )
    RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$True

    EndFunc $MyInvocation.MyCommand.Name
}

Function CollectUEX_WinRMLog{
    EnterFunc $MyInvocation.MyCommand.Name
    $LogPrefix = "WinRM"
    $WinRMLogFolder = "$LogFolder\WinRMLog$LogSuffix"
    $WinRMEventFolder = "$LogFolder\WinRMLog$LogSuffix\Eventlog"
    $WinRMDumpFolder = "$LogFolder\WinRMLog$LogSuffix\Process dump"
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
    FwCaptureUserDump "WecSvc" $WinRMDumpFolder -IsService $True
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
                ("Subsription: " + $sub) | out-file -FilePath ("$WinRMLogFolder\Subscriptions.txt") -Append
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
        "ipconfig /all  | Out-File -Append $WinRMLogFolder\ipconfig_all.txt",
        "ipconfig /displaydns  | Out-File -Append $WinRMLogFolder\ipconfig_displaydns.txt",
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

Function CollectUEX_TaskLog{
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

Function CollectUEX_FSLogixLog{
    EnterFunc $MyInvocation.MyCommand.Name
    $FSLogixLogFolder = "$global:LogFolder\FSLogix$global:LogSuffix"
    $LogPrefix = "FSLogix"

    Try{
        FwCreateLogFolder "$FSLogixLogFolder\Logs"
    }Catch{
        LogException "Unable to create $FSLogixLogFolder." $_
        Return
    }

    # Eveng logs
    $EventLogsWithTextFmt = @(
        "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
        "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Admin",
        "Microsoft-FSLogix-Apps/Admin",
        "Microsoft-FSLogix-Apps/Operational",
        "Microsoft-FSLogix-CloudCache/Admin",
        "Microsoft-FSLogix-CloudCache/Operational",
        "Microsoft-Windows-GroupPolicy/Operational",
        "Microsoft-Windows-User Profile Service/Operational"
    )
    FwExportEventLog $EventLogsWithTextFmt $FSLogixLogFolder

    $EventLogsEvtxOnly = @(
        "Microsoft-Windows-VHDMP-Operational",
        "Microsoft-Windows-SMBClient/Operational",
        "Microsoft-Windows-SMBClient/Connectivity",
        "Microsoft-Windows-SMBClient/Security",
        "Microsoft-Windows-SMBServer/Operational",
        "Microsoft-Windows-SMBServer/Connectivity",
        "Microsoft-Windows-SMBServer/Security"
    )
    FwExportEventLog $EventLogsEvtxOnly $FSLogixLogFolder -NoExportWithText

    # frx
    $frxcmd = "c:\program files\fslogix\apps\frx.exe"
    If(Test-Path $frxcmd){
        # As command path contains space, we need to use '&' operator to run the command
        $Commands = @(
            "& '$frxcmd' version | Out-File -Append -FilePath $FSLogixLogFolder\frx-list.txt",
            "& '$frxcmd' list-redirects | Out-File -Append -FilePath $FSLogixLogFolder\frx-list.txt",
            "& '$frxcmd' list-rules | Out-File -Append -FilePath $FSLogixLogFolder\frx-list.txt"
        )
        RunCommands $LogPrefix $Commands -ShowMessage:$True
    }

    # Log files
	$SourceDestinationPaths = New-Object 'System.Collections.Generic.List[Object]'
    $SourceDestinationPaths.add(@("C:\ProgramData\FSLogix\Logs\*", "$FSLogixLogFolder/Logs"))
    FwCopyFiles $SourceDestinationPaths

    # Registry
	$RegKeys = @(
		('HKLM:SOFTWARE\FSLogix', "$FSLogixLogFolder\Reg-SW-FSLogix.txt"),
		('HKLM:SOFTWARE\Policies\FSLogix', "$FSLogixLogFolder\Reg-SW-Policies-FSLogix.txt"),
        ('HKLM:SOFTWARE\Microsoft\Windows Defender\Exclusions', "$FSLogixLogFolder\Reg-SW-MS-WinDef-Exclusions.txt"),
        ('HKLM:SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions', "$FSLogixLogFolder\Reg-SW-GPO-MS-WinDef-Exclusions.txt"),
        ('HKCU:SOFTWARE\Microsoft\Office', "$FSLogixLogFolder\Reg-SW-MS-Office.txt"),
        ('HKCU:Software\Policies\Microsoft\office', "$FSLogixLogFolder\Reg-SW-Policies-MS-Office.txt"),
        ('HKCU:SOFTWARE\Microsoft\OneDrive', "$FSLogixLogFolder\Reg-SW-MS-OneDrive.txt"),
        ('HKLM:SOFTWARE\Microsoft\OneDrive', "$FSLogixLogFolder\Reg-SW-MS-OneDrive.txt"),
        ('HKLM:SOFTWARE\Policies\Microsoft\OneDrive', "$FSLogixLogFolder\Reg-SW-Pol-MS-OneDrive.txt"),
        ('HKLM:SOFTWARE\Microsoft\Windows Search', "$FSLogixLogFolder\Reg-SW-MS-WindowsSearch.txt"),
        ('HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList', "$FSLogixLogFolder\Reg-SW-MS-WinNT-CV-ProfileList.txt"),
        ('HKCU:Volatile Environment', "$FSLogixLogFolder\Reg-VolatileEnvironment.txt"),
        ('HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers', "$FSLogixLogFolder\Reg-SW-MS-Win-CV-Auth-CredProviders.txt")
	)
	FwExportRegistry "FSLogix" $RegKeys
	
    # Below registies have binary data. So exporting them as hive format
    REG SAVE 'HKCU\SOFTWARE\Microsoft\Office' "$FSLogixLogFolder\Reg-SW-MS-Office.hiv" 2>&1 | Out-Null
    REG SAVE 'HKLM\SOFTWARE\Microsoft\Windows Search' "$FSLogixLogFolder\Reg-SW-MS-WindowsSearch.hiv" 2>&1 | Out-Null
    REG SAVE 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' "$FSLogixLogFolder\Reg-SW-MS-WinNT-CV-ProfileList.hiv" 2>&1 | Out-Null

    #Collecting user/profile information
    RunCommands $LogPrefix "Whoami /all 2>&1 | Out-File -Append $FSLogixLogFolder\WhoAmI-all.txt" -ShowMessage:$True

    #Collecting FSLogix group memberships
    $Commands = @()
    if ([ADSI]::Exists("WinNT://localhost/FSLogix ODFC Exclude List")) {
        $Commands += "& net localgroup 'FSLogix ODFC Exclude List' 2>&1 | Out-File -Append -FilePath $FSLogixLogFolder\LocalGroupsMembership.txt"
    } else {
        LogWarnFile "[$LogPrefix] 'FSLogix ODFC Exclude List' group not found."
    }

    if ([ADSI]::Exists("WinNT://localhost/FSLogix ODFC Include List")) {
        $Commands += "net localgroup 'FSLogix ODFC Include List' 2>&1 | Out-File -Append -FilePath $FSLogixLogFolder\LocalGroupsMembership.txt"
    } else {
        LogWarnFile "[$LogPrefix] 'FSLogix ODFC Include List' group not found."
    }

    if ([ADSI]::Exists("WinNT://localhost/FSLogix Profile Exclude List")) {
        $Commands += "net localgroup 'FSLogix Profile Exclude List' 2>&1 | Out-File -Append -FilePath $FSLogixLogFolder\LocalGroupsMembership.txt"
    } else {
        LogWarnFile "[$LogPrefix] 'FSLogix Profile Exclude List' group not found."
    }

    if ([ADSI]::Exists("WinNT://localhost/FSLogix Profile Include List")) {
        $Commands += "net localgroup 'FSLogix Profile Include List' 2>&1 | Out-File -Append -FilePath $FSLogixLogFolder\LocalGroupsMembership.txt"
    } else {
        LogWarnFile "[$LogPrefix] 'FSLogix Profile Include List' group not found."
    }

    If($Commands.count -gt 0){
        RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$True -ShowError:$False
    }
}
#endregion Functions

#region Registry Key modules for FwAddRegItem
	$global:KeysFSLogix = @("HKLM:Software\FSLogix", "HKLM:Software\Policies\Fslogix")
#endregion Registry Key modules

#region groups of Eventlogs for FwAddEvtLog
	<# Example:
	$global:EvtLogsEFS		= @("Microsoft-Windows-NTFS/Operational", "Microsoft-Windows-NTFS/WHC")
	#>
#endregion groups of Eventlogs

Export-ModuleMember -Function * -Cmdlet * -Variable * -Alias *



# SIG # Begin signature block
# MIInzAYJKoZIhvcNAQcCoIInvTCCJ7kCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCTMbnDyL9tJfyB
# wSNuj75IyQQiTBX5ZVDfZf6hBnIVvaCCDYEwggX/MIID56ADAgECAhMzAAACzI61
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
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIZoTCCGZ0CAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAsyOtZamvdHJTgAAAAACzDAN
# BglghkgBZQMEAgEFAKCBrjAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQg4EdvLt20
# VBdB9o37dZ6qyNdCA9qvKN15uLavu4pOyWQwQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQBOaRsXJ3lFVVMjU2wmJGJOc+pAxUNLkl/xVc3jjWFW
# XUmX0SVzVYO7IrH5G8Q6miLx6g0YzFWFO1KDYoHVBc3OhhaKcWcuZq+hi3YbB3lS
# /5Ndec2dlZUuV8SWxujMxubHwtdnQNTWtYSfDU8YKShzCzn0gU1Ex74BNJp8gFD1
# IMCoFTeJOMKey4OYTa+z19BufNqGRuI8zOWrajX9aFGBtkoyTVQt6kapZMBWEY3M
# owXGITyo/DWavOL90S7hehDmJam3fUACe00C9rsTVv9pN4WpDlICi6sfVuy0Qq8O
# DtQXiNYUGYIPZaW22GALflWvmM7oQDUGNyMMkt0ivypZoYIXKzCCFycGCisGAQQB
# gjcDAwExghcXMIIXEwYJKoZIhvcNAQcCoIIXBDCCFwACAQMxDzANBglghkgBZQME
# AgEFADCCAVgGCyqGSIb3DQEJEAEEoIIBRwSCAUMwggE/AgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEIAMLEi4it4OuHcDFBwDD4sqgb+fxAzas4W+QMIxU
# dnsPAgZjT+tCufwYEjIwMjIxMDI2MTQyOTU0LjE5WjAEgAIB9KCB2KSB1TCB0jEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
# bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UECxMkTWlj
# cm9zb2Z0IElyZWxhbmQgT3BlcmF0aW9ucyBMaW1pdGVkMSYwJAYDVQQLEx1UaGFs
# ZXMgVFNTIEVTTjo4RDQxLTRCRjctQjNCNzElMCMGA1UEAxMcTWljcm9zb2Z0IFRp
# bWUtU3RhbXAgU2VydmljZaCCEXswggcnMIIFD6ADAgECAhMzAAABs/4lzikbG4oc
# AAEAAAGzMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
# YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
# Q29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAy
# MDEwMB4XDTIyMDkyMDIwMjIwM1oXDTIzMTIxNDIwMjIwM1owgdIxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJ
# cmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046OEQ0MS00QkY3LUIzQjcxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2UwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC0fA+65hiA
# riywYIKyvY3t4SUqXPQk8G62v+Cm9nruQ2UeqAoBbQm4oDLjHGN9UJR6/95LloRy
# dOZ+Prd++zx6J3Qw28/3VPqvzX10iq9acFNji8pWNLMOd9VWdbFgHcg9hEAhM03S
# w+CiWwusJgAqJ4iQQKr4Q8l8SdDbr5ZO+K3VRL64m7A2ccwpVhGuL+thDY/x8ogl
# F9zGRp2PwIQ8ms36XIQ1qD+nCYDQkl5h1fV7CYFyeJfgGAIGqgLzfDfhKTftExKw
# oBTn8GVdtXIO74HpzlePIJhvxDH9C70QHoq8T1LvozQdyUhW1tVlPGecbCxKDZXt
# +YnHRE/ht8AzZnEl5UGLOLfeCFkeeNfj7FE5KtJJnT+P9TuBg+eGbCeXlJy2msFz
# scU9X4G1m/VUYNWeGrKVqbi+YBcB2vFDTEcbCn36K+qq11VUNTnSTktSZXr4aWZb
# LEglQ6HTHN9CN31ns58urTTqH6X2j67cCdLpF3Cw9ck/vPbuLkAf66lCuiex6ZDb
# tH0eTOcRrTnIfZ8p3DvWpaK8Q34hHW+s3qrQn3G6OOrvv637LJXBkriRc5cBDZ1P
# r0PiSeoyUVKwfpq+dc1lDIlkyw1ZoS3euv/w2v2AYwNAYtIXGLjv1nLX1pP98fOw
# C27ahwG5OotXCfGtnKInro/vQQEko7l5AQIDAQABo4IBSTCCAUUwHQYDVR0OBBYE
# FNAaXcJRZ1IMGIs4SCH/XgXcn8ONMB8GA1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWn
# G1M1GelyMF8GA1UdHwRYMFYwVKBSoFCGTmh0dHA6Ly93d3cubWljcm9zb2Z0LmNv
# bS9wa2lvcHMvY3JsL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEw
# KDEpLmNybDBsBggrBgEFBQcBAQRgMF4wXAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwVGltZS1TdGFt
# cCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwGA1UdEwEB/wQCMAAwFgYDVR0lAQH/BAww
# CgYIKwYBBQUHAwgwDgYDVR0PAQH/BAQDAgeAMA0GCSqGSIb3DQEBCwUAA4ICAQBa
# hrs3zrAJuMACXxEZiYFltLTSyz5OlWI+d/oQZlCArKhoI/aFzTWrYAqvox7dNxIk
# 81YcbXilji6EzMd/XAnFCYAzkCB/ho7so2FVXTgmvRcepSOvdPzgWRZc9gw7i6VA
# bqP/793uCp7ONdpjtwOpg0JJ3cXiUrHQUm5CqnHAe0wv5rhToc4N/Zn4oxiAnNZG
# c4iRP+h3SghfKffr7NchlEebs5CKPuvKv5+ZDbd94XWkNt+FRIdMD0hPnQoKSkan
# 8YGLAU/+bV2t3vE18iZVaBvY8Fwayp0kG+PpNfYx1Qd8FVH5Z7gDSUSPWs1sKmBS
# g22VpH0PLaTaBXyihUR21qJnKHT9W1Z+5CllAkwPGBtkZUwbb67NwqmN5gA0yVIo
# OHJDfzBugCK/EPgApigRJuDhaTnGTF9HMWrKKXYMTPWknQbrGiX2dyLZd7wuQt0R
# Pe7lEbFQdqbwvgp4xbbfz5GO9ZfVEx81AjvvjOIUhks5H7vsgYVzBngWai15fXH3
# 4GD3J0RY0E/exm/24OLLCyBbjSTTQCbm/iL8YaJka7VrgeEjfd+aDH7xuXBHme3s
# mKQWeA25LzeOGbxEdBB0WpC9sW9a67I+3PCPmrhKmM7VKQ57qugcaQSFAJRd1Ayd
# EjBucalv/YSzFp2iQryHqxFkxZuuI7YQItAQzMJwsDCCB3EwggVZoAMCAQICEzMA
# AAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNVBAYTAlVT
# MRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBSb290
# IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDEwMB4XDTIxMDkzMDE4MjIyNVoXDTMw
# MDkzMDE4MzIyNVowfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwggIiMA0G
# CSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDk4aZM57RyIQt5osvXJHm9DtWC0/3u
# nAcH0qlsTnXIyjVX9gF/bErg4r25PhdgM/9cT8dm95VTcVrifkpa/rg2Z4VGIwy1
# jRPPdzLAEBjoYH1qUoNEt6aORmsHFPPFdvWGUNzBRMhxXFExN6AKOG6N7dcP2CZT
# fDlhAnrEqv1yaa8dq6z2Nr41JmTamDu6GnszrYBbfowQHJ1S/rboYiXcag/PXfT+
# jlPP1uyFVk3v3byNpOORj7I5LFGc6XBpDco2LXCOMcg1KL3jtIckw+DJj361VI/c
# +gVVmG1oO5pGve2krnopN6zL64NF50ZuyjLVwIYwXE8s4mKyzbnijYjklqwBSru+
# cakXW2dg3viSkR4dPf0gz3N9QZpGdc3EXzTdEonW/aUgfX782Z5F37ZyL9t9X4C6
# 26p+Nuw2TPYrbqgSUei/BQOj0XOmTTd0lBw0gg/wEPK3Rxjtp+iZfD9M269ewvPV
# 2HM9Q07BMzlMjgK8QmguEOqEUUbi0b1qGFphAXPKZ6Je1yh2AuIzGHLXpyDwwvoS
# CtdjbwzJNmSLW6CmgyFdXzB0kZSU2LlQ+QuJYfM2BjUYhEfb3BvR/bLUHMVr9lxS
# UV0S2yW6r1AFemzFER1y7435UsSFF5PAPBXbGjfHCBUYP3irRbb1Hode2o+eFnJp
# xq57t7c+auIurQIDAQABo4IB3TCCAdkwEgYJKwYBBAGCNxUBBAUCAwEAATAjBgkr
# BgEEAYI3FQIEFgQUKqdS/mTEmr6CkTxGNSnPEP8vBO4wHQYDVR0OBBYEFJ+nFV0A
# XmJdg/Tl0mWnG1M1GelyMFwGA1UdIARVMFMwUQYMKwYBBAGCN0yDfQEBMEEwPwYI
# KwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvRG9jcy9S
# ZXBvc2l0b3J5Lmh0bTATBgNVHSUEDDAKBggrBgEFBQcDCDAZBgkrBgEEAYI3FAIE
# DB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNV
# HSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBWBgNVHR8ETzBNMEugSaBHhkVo
# dHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNSb29D
# ZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUHAQEETjBMMEoGCCsGAQUFBzAC
# hj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1
# dF8yMDEwLTA2LTIzLmNydDANBgkqhkiG9w0BAQsFAAOCAgEAnVV9/Cqt4SwfZwEx
# JFvhnnJL/Klv6lwUtj5OR2R4sQaTlz0xM7U518JxNj/aZGx80HU5bbsPMeTCj/ts
# 0aGUGCLu6WZnOlNN3Zi6th542DYunKmCVgADsAW+iehp4LoJ7nvfam++Kctu2D9I
# dQHZGN5tggz1bSNU5HhTdSRXud2f8449xvNo32X2pFaq95W2KFUn0CS9QKC/GbYS
# EhFdPSfgQJY4rPf5KYnDvBewVIVCs/wMnosZiefwC2qBwoEZQhlSdYo2wh3DYXMu
# LGt7bj8sCXgU6ZGyqVvfSaN0DLzskYDSPeZKPmY7T7uG+jIa2Zb0j/aRAfbOxnT9
# 9kxybxCrdTDFNLB62FD+CljdQDzHVG2dY3RILLFORy3BFARxv2T5JL5zbcqOCb2z
# AVdJVGTZc9d/HltEAY5aGZFrDZ+kKNxnGSgkujhLmm77IVRrakURR6nxt67I6Ile
# T53S0Ex2tVdUCbFpAUR+fKFhbHP+CrvsQWY9af3LwUFJfn6Tvsv4O+S3Fb+0zj6l
# MVGEvL8CwYKiexcdFYmNcP7ntdAoGokLjzbaukz5m/8K6TT4JDVnK+ANuOaMmdbh
# IurwJ0I9JZTmdHRbatGePu1+oDEzfbzL6Xu/OHBE0ZDxyKs6ijoIYn/ZcGNTTY3u
# gm2lBRDBcQZqELQdVTNYs6FwZvKhggLXMIICQAIBATCCAQChgdikgdUwgdIxCzAJ
# BgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25k
# MR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jv
# c29mdCBJcmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVz
# IFRTUyBFU046OEQ0MS00QkY3LUIzQjcxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1l
# LVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVAHGLROiW3R4SpcJCXiqAldSS
# JA5hoIGDMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJKoZI
# hvcNAQEFBQACBQDnA6O+MCIYDzIwMjIxMDI2MjAxNzAyWhgPMjAyMjEwMjcyMDE3
# MDJaMHcwPQYKKwYBBAGEWQoEATEvMC0wCgIFAOcDo74CAQAwCgIBAAICGsQCAf8w
# BwIBAAICEVMwCgIFAOcE9T4CAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGE
# WQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQUFAAOBgQBv
# p6W/1aTiOXGNn5K1ZCCmae6r3QoDryaOAGIJl9ooX+BPpyMxx2Hn7MApe18QgeA6
# TA/BjYu+0ZMzCEx5eGmX9DAOWSACVGPDDBrUklt6IPlKrVgZCAHu2ajPEPnxW0Ls
# zn4hyeLMnI3hQEXOKJKmUCaZibuAlX9Wb8LpMTuYEzGCBA0wggQJAgEBMIGTMHwx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1p
# Y3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABs/4lzikbG4ocAAEAAAGz
# MA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQw
# LwYJKoZIhvcNAQkEMSIEIJUFFrDTkbUoFOIbsbhAucp9din3v+YvbzyZpRBnWdWU
# MIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQghqEz1SoQ0ge2RtMyUGVDNo5P
# 5ZdcyRoeijoZ++pPv0IwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0Eg
# MjAxMAITMwAAAbP+Jc4pGxuKHAABAAABszAiBCAOJovhPOIH2oWJWe1vQOjJj481
# 5YZKgpXoVXBjlkwlpzANBgkqhkiG9w0BAQsFAASCAgCJmBe82zZafjLkc64l3IGu
# jpUh65qUM/hDjI2yfRgVwb8T2lspAygo6YtsAXOQyKPgpsDuNBSf2tCG4Ms/UZhH
# Tnm3Ww5n5YU5sSGWmviZ+IZuU02lHOKzEXyueYTSDRW9Y8zXovDT3uea5DY63ObT
# gxelZCNPCDhCS+CkHqvKl9rRC5UBYD7xg1vD2rdi+SP4mf8RPrBda6SEb8uEOWL8
# 0izaNv8ZS9lUa7aAk7DI7i9HnKGk+mhYhvo6UxKWDUun1cN3Qgq2qU4R+7FWlsKi
# o+5lGSS6ads5WK+Oz+lkPuhGwfgM2zAm9JlgFfH7dFomsd1aTVoQEmf2kQmMe0aL
# 1lDpeOwvcxBYj2jj9K+x9EYrqZxCy6nQmpkpG+u6dc4se/tdLqQdLGUH+8Oy5k2k
# rLneFb/hCx7TN3Qlo9PcGNrTzOti4yeJQIZwwRjJMdMi9nq4OEV5CzWlUXT0u3N2
# p8gdaX290wA6N0Lr9y4jlPL1OMJnuOl2UjD6qQIAay13XVZWf36/0loxjRRWaqKx
# btJmqwe3gMUeX2gmv0ub1W3gEqqfPhXP90cch0hZWkdqnEVNzGE/wLVyM/NrFhjj
# FTPwe165MgVZ6oyW605mrdzE293t+ZacJZWwzkMiSNJjX83A4CP4LCOPhH2Bs9rf
# HRlPPR0IE/Leb4ilSK2mkg==
# SIG # End signature block
