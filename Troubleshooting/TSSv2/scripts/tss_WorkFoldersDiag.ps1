<# Script name: tss_WorkFoldersDiag.ps1

#  Copyright (c) Microsoft Corporation.  All rights reserved.
#  
# THIS SAMPLE CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND,
# WHETHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
# IF THIS CODE AND INFORMATION IS MODIFIED, THE ENTIRE RISK OF USE OR RESULTS IN
# CONNECTION WITH THE USE OF THIS CODE AND INFORMATION REMAINS WITH THE USER. 
#
# Author:
#     Anu Raghavan (araghav) - August, 2013
# Version: 8.1
#>

#region ::::: Script Input PARAMETERS :::::
[CmdletBinding()]param(
  [Parameter(Mandatory=$true, Position=0)] [String] $DataPath,
  [Parameter(Mandatory=$false, Position=1)] [Switch] $AdvancedMode = $false,
  [Parameter(Mandatory=$false, Position=2)] [Int] $TraceLevel = 255,
  [Parameter(Mandatory=$false, Position=3)] [Switch] $Cleanup = $false,
  [Parameter(Mandatory=$false, Position=4)] [Switch] $RunTrace = $false,
  [Parameter(Mandatory)]
  [ValidateSet("Start","Stop")]
  [string]$Stage
)
$ScriptVer="22.02.04"	#Date: 2022-02-04
$OutputDirectory = $DataPath
$LogSeparator = '################################################################################################################'
#endregion ::::: Script Input PARAMETERS :::::

function Get-EventsTxt($EventLog, $OutFile)
# SYNOPSIS: extract Eventlog content in TXT format
{	$Events = Get-WinEvent $EventLog -MaxEvents 300 -ErrorAction SilentlyContinue
    if($null -eq $Events)
    {   # Error occurred - do nothing
	    Write-Host ' $EventLog : No event log entries found.'
    }
    else
    {   'Number of event log entries collected: ' + $Events.Count | Out-File $OutFile
	    foreach($Event in $Events)
	    {   $LogSeparator | Out-File $OutFile -append
		    $Event | Out-File $OutFile -append
		    'Full message:' | Out-File $OutFile -append
		    $Event.Message | Out-File $OutFile -append
	    }
    }
}

function Get-Registry($Path, $OutFile)
# SYNOPSIS: get the content of Registry keys
{
    if ((Test-Path $Path) -eq $true)
    {
        Get-Item $Path | Out-File $OutFile -append
	    Get-ChildItem $Path -Recurse | Out-File $OutFile -append
    }
}

function Get-WorkFoldersInfo
# SYNOPSIS: collect WorkFolder client and server info
{
	param (
	  [Parameter(Mandatory=$true, Position=0)] [String] $OutputDirectory,
	  [Parameter(Mandatory=$false, Position=1)] [Switch] $AdvancedMode = $false,
	  [Parameter(Mandatory=$false, Position=2)] [Int] $TraceLevel = 255,
	  [Parameter(Mandatory=$false, Position=3)] [Switch] $Cleanup = $True,
	  [Parameter(Mandatory=$false, Position=4)] [Switch] $RunTrace = $false,
	  [Parameter(Mandatory)]
        [ValidateSet("Start","Stop")]
        [string]$Stage
	)

	$OldErrorActionPreference = $ErrorActionPreference
	$ErrorActionPreference = "SilentlyContinue"

	# Validate input
	$Done = $false
	while ($Done -eq $false)
	{
		if ($null -eq $OutputDirectory)	{	$Done = $false	}
		elseif ((Test-Path $OutputDirectory) -eq $false) {	$Done = $false	}
		else {	$Done = $true	}

		if ($Done -eq $false)
		{	Write-Error "Path selected is invalid."
			$OutputDirectory = Read-Host "Specify another path for OutputDirectory [Note that all contents already present in this directory will be erased.]"
		}
	}
	while (($TraceLevel -lt 1) -or ($TraceLevel -gt 255))
	{	$TraceLevel = Read-Host "Invalid trace level specified. Please specify a value between 1 and 255"}

	# Create Temp directory structure to accumulate output + Collect generic info
	$Script:TempOutputPath = $OutputDirectory + '\Temp'
	$Script:GeneralDirectory = $Script:TempOutputPath + '\General'
	$Script:IsServer = Test-Path ($env:Systemroot + '\System32\SyncShareSvc.dll')
	$Script:IsClient = Test-Path ($env:Systemroot + '\System32\WorkFoldersSvc.dll')
	
if ($Stage -eq "Start") 
{ 
	Write-Host "v$ScriptVer Starting collection of debug information for Work Folders on this machine ..." -ForegroundColor White -BackgroundColor DarkGreen
	Write-Host "$(Get-Date -Format 'HH:mm:ss') Setting up WorkFoldersDiag environment ..."
	if ($AdvancedMode) {  	Write-Host "... running in AdvancedMode" }

	New-Item $Script:TempOutputPath -type directory | Out-Null
	New-Item $Script:GeneralDirectory -type directory | Out-Null
	$GeneralInfoFile = $Script:GeneralDirectory + '\' + $env:COMPUTERNAME + '_MachineInfo.txt'
	$LocalVolumesFile = $Script:GeneralDirectory + '\' + $env:COMPUTERNAME + '_LocalVolumes.txt'
	$ClusterVolumesFile = $Script:GeneralDirectory + '\' + $env:COMPUTERNAME + '_ClusterVolumes.txt'
	'VersionString: ' + [System.Environment]::OSVersion.VersionString | Out-File $GeneralInfoFile
	'Version: ' + [System.Environment]::OSVersion.Version | Out-File $GeneralInfoFile -append
	'ServicePack: ' + [System.Environment]::OSVersion.ServicePack | Out-File $GeneralInfoFile -append
	'Platform: ' + [System.Environment]::OSVersion.Platform | Out-File $GeneralInfoFile -append

	$OS = Get-CimInstance -class win32_OperatingSystem
	if ($OS.ProductType -gt 1)
	{	'OS SKU Type: Server' | Out-File $GeneralInfoFile -append
		try { $Cluster = Get-Cluster -EA Ignore}
		catch { 
			#Write-host "...not running on cluster environment"
			}
		$IsCluster = $null -ne $Cluster
		if ($IsCluster) {  'This machine is part of a cluster' | Out-File $GeneralInfoFile -append }
		else {    'This machine is a stand alone machine, it is not part of a cluster' | Out-File $GeneralInfoFile -append }
	}
	else
	{	'OS SKU Type: Client' | Out-File $GeneralInfoFile -append}


	if ($Script:IsServer) {
		'Work Folders server component is installed on this machine.' | Out-File $GeneralInfoFile -append 
		'List of versions of binaries for the Work Folders server component:' | Out-File $GeneralInfoFile -append
		$ServerBinaries = @(
		($env:Systemroot + '\System32\SyncShareSvc.dll'),
		($env:Systemroot + '\System32\SyncShareSrv.dll'),
		($env:Systemroot + '\System32\SyncShareTTLib.dll'),
		($env:Systemroot + '\System32\SyncShareTTSvc.exe')
		)
		Foreach($Binary in $ServerBinaries)
		{ 	[System.Diagnostics.FileVersionInfo]::GetVersionInfo($Binary) | Format-List | Out-File $GeneralInfoFile -append }
		Copy-Item ($env:Systemroot + '\System32\SyncShareSvc.config') $Script:GeneralDirectory
		$WFmode = "Server"
	}
	if ($Script:IsClient) {
		'Work Folders client component is installed on this machine.' | Out-File $GeneralInfoFile -append
		'List of versions of binaries for the Work Folders client component:' | Out-File $GeneralInfoFile -append
		$ClientBinaries = @(
		($env:Systemroot + '\System32\WorkFoldersShell.dll'),
		($env:Systemroot + '\System32\WorkFoldersGPExt.dll'),
		($env:Systemroot + '\System32\WorkFoldersControl.dll'),
		($env:Systemroot + '\System32\WorkFoldersSvc.dll'),
		($env:Systemroot + '\System32\WorkFolders.exe')
		)
		Foreach($Binary in $ClientBinaries)
		{ 	[System.Diagnostics.FileVersionInfo]::GetVersionInfo($Binary) | Format-List | Out-File $GeneralInfoFile -append }
		$WFmode = "Client"
	}
	
	$WFmodeDirectory = $null
	$WFmodeDirectory = $Script:TempOutputPath + '\' + $WFmode
	New-Item $WFmodeDirectory -type directory | Out-Null
		
	"List of local volumes:" | Out-File $LocalVolumesFile -append
	Get-WmiObject Win32_Volume | Out-File $LocalVolumesFile -append

	if ($IsCluster)
	{
		"List of cluster volumes:" | Out-File $ClusterVolumesFile -append
		Get-WmiObject MSCluster_Resource -Namespace root/mscluster | where-object{$_.Type -eq 'Physical Disk'} |
			ForEach-Object{ Get-WmiObject -Namespace root/mscluster -Query "Associators of {$_} Where ResultClass=MSCluster_Disk" } |
			ForEach-Object{ Get-WmiObject -Namespace root/mscluster -Query "Associators of {$_} Where ResultClass=MSCluster_DiskPartition" } |
			Out-File $ClusterVolumesFile -append
	}

	if ($RunTrace) {  	Write-Host "... Start Work Folders tracing" 
		### Start Work Folders tracing
		#Write-Host "$(Get-Date -Format 'HH:mm:ss') Start Work Folders $WFmode tracing ..."
		$TracesDirectory = $Script:TempOutputPath + '\Traces'
		New-Item $TracesDirectory -type directory | Out-Null
		$TracingCommand = 'logman start WorkFoldersTrace -o "$TracesDirectory\WorkFoldersTrace.etl" --max -ets -p "{111157cb-ee69-427f-8b4e-ef0feaeaeef2}" 0xffffffff ' + $TraceLevel
		Invoke-Expression $TracingCommand | Out-Null # start traces
		$TracingCommand = 'logman start WorkFoldersTraceEFS -o "$TracesDirectory\WorkFoldersTraceEFS.etl" --max -ets -p "{C755EF4D-DE1C-4E7D-A10D-B8D1E26F5035}" 0xffffffff ' + $TraceLevel
		Invoke-Expression $TracingCommand | Out-Null # start EFS traces
		$TracingCommand = 'logman start WorkFoldersTraceESE -o "$TracesDirectory\WorkFoldersTraceESE.etl" --max -ets -p "{1284E99B-FF7A-405A-A60F-A46EC9FED1A7}" 0xffffffff ' + $TraceLevel
		Invoke-Expression $TracingCommand | Out-Null # start ESE traces
		Write-Host "$(Get-Date -Format 'HH:mm:ss') Work Folders $WFmode Tracing started."
		
		### Start Interactive Repro
		Write-Host "`n === Please reproduce the WorkFolder problem then press the 's' key to stop tracing. ===`n" -ForegroundColor Green
		do {
			$UserDone = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
		} until ($UserDone.Character -ieq 's')
		###
		Write-Host "$(Get-Date -Format 'HH:mm:ss') Collecting WorkFolder traces with TraceLevel $TraceLevel ..."

		Start-Sleep(5) # Allow time to make sure traces get written

		Invoke-Expression 'logman stop WorkFoldersTrace -ets' | Out-Null # stop traces
		Invoke-Expression 'logman stop WorkFoldersTraceEFS -ets' | Out-Null # stop EFS traces
		Invoke-Expression 'logman stop WorkFoldersTraceESE -ets' | Out-Null # stop ESE traces

		Write-Host "$(Get-Date -Format 'HH:mm:ss') WorkFolder Tracing stopped."
	}
}
if ($Stage -eq "Stop") 
{	
	###
	if ($Script:IsClient) {$WFmode = "Client"}
	if ($Script:IsServer)
	{
		$ServerSetting = Get-SyncServerSetting
		$Shares = Get-SyncShare
		$WFmode = "Server"
	}
	
	$WFmodeDirectory = $Script:TempOutputPath + '\' + $WFmode
	
	if ($AdvancedMode)
	{ #_# Stopping Service WorkFolderssvc
		if ($Script:IsClient) { Write-Host "$(Get-Date -Format 'HH:mm:ss') Stopping Service WorkFolderssvc."
						Stop-Service WorkFolderssvc }
		if ($Script:IsServer) { Write-Host "$(Get-Date -Format 'HH:mm:ss') Stopping Services SyncShareSvc, SyncShareTTSvc."
						Stop-Service SyncShareSvc
						Stop-Service SyncShareTTSvc }
	}

	Write-Host "$(Get-Date -Format 'HH:mm:ss') Saving WorkFolders $WFmode configuration information ..."
	$ConfigDirectory = $WFmodeDirectory + '\Config'
	New-Item $ConfigDirectory -type directory | Out-Null
	$RegConfigFile = $ConfigDirectory + '\' + $env:COMPUTERNAME + '_RegistryConfig.txt'
	$MetadataDirectory = $WFmodeDirectory + '\' + $WFmode + 'Metadata'
	if ($AdvancedMode) { New-Item $MetadataDirectory -type directory | Out-Null   }

	if ($Script:IsServer)
	{
		Get-Registry 'hklm:\SYSTEM\CurrentControlSet\Services\SyncShareSvc' $RegConfigFile
		Get-Registry 'hklm:\SYSTEM\CurrentControlSet\Services\SyncShareTTSvc' $RegConfigFile
		$SyncShareSrvHive = 'hklm:\SOFTWARE\Microsoft\Windows\CurrentVersion\SyncShareSrv'
		if ($IsCluster) { $SyncShareSrvHive = 'hklm:\Cluster\SyncShareSrv' }
		Get-Registry $SyncShareSrvHive $RegConfigFile

		$ConfigFile = $ConfigDirectory + '\' + $env:COMPUTERNAME + '_CmdletConfig.txt'
		$LogSeparator | Out-File $ConfigFile -append
		'Config for sync server:' | Out-File $ConfigFile -append
		$LogSeparator | Out-File $ConfigFile -append
		$ServerSetting | Out-File $ConfigFile -append
		$LogSeparator | Out-File $ConfigFile -append
		'End config for sync server:' | Out-File $ConfigFile -append
		$LogSeparator | Out-File $ConfigFile -append

		foreach ($Share in $Shares)
		{
			$LogSeparator | Out-File $ConfigFile -append
			'Config for sync share ' + $Share.Name | Out-File $ConfigFile -append
			$LogSeparator | Out-File $ConfigFile -append
			$Share | Out-File $ConfigFile -append

			$acl = Get-Acl $Share.Path -EA SilentlyContinue
			'ACLs on ' + $Share.Path + ':' | Out-File $ConfigFile -append
			$acl | Out-File $ConfigFile -append
			$acl.Access | Out-File $ConfigFile -append

			$acl = Get-Acl $Share.StagingFolder -EA SilentlyContinue
			'ACLs on ' + $Share.StagingFolder + ':' | Out-File $ConfigFile -append
			$acl | Out-File $ConfigFile -append
			$acl.Access | Out-File $ConfigFile -append

			$MetadataFolder = $Share.StagingFolder + '\Metadata'
			$acl = Get-Acl $MetadataFolder -EA SilentlyContinue
			'ACLs on ' + $MetadataFolder + ':' | Out-File $ConfigFile -append
			$acl | Out-File $ConfigFile -append
			$acl.Access | Out-File $ConfigFile -append

			if ($AdvancedMode) { Get-ChildItem $MetadataFolder | ForEach-Object{ Copy-Item $_.FullName $MetadataDirectory } }
			
			foreach ($user in $Share.User)
			{
				'Full list of users on this sync share:' | Out-File $ConfigFile -append
				$user | Out-File $ConfigFile -append
			}

			$LogSeparator | Out-File $ConfigFile -append
			'End config for sync share ' + $Share.Name | Out-File $ConfigFile -append
			$LogSeparator | Out-File $ConfigFile -append
		}
	}

	if ($Script:IsClient)
	{
		Get-Registry 'hklm:SOFTWARE\Microsoft\Windows\CurrentVersion\WorkFolders' $RegConfigFile
		Get-Registry 'hkcu:SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\WorkFolders' $RegConfigFile
		Get-Registry 'hkcu:SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings' $RegConfigFile
		if ($AdvancedMode) { Get-ChildItem ($env:LOCALAPPDATA + '\Microsoft\Windows\WorkFolders\Metadata') | ForEach-Object{ Copy-Item $_.FullName $MetadataDirectory } }
	}

	### event log entries
	Write-Host "$(Get-Date -Format 'HH:mm:ss') Collecting WorkFolders $WFmode event log entries ..."
	$EventLogDirectory = $WFmodeDirectory + '\' + $WFmode + 'EventLogs'
	New-Item $EventLogDirectory -type directory | Out-Null

	if ($Script:IsServer)
	{
		Get-EventsTxt Microsoft-Windows-SyncShare/Operational ($EventLogDirectory + '\' + $env:COMPUTERNAME + '_SyncShare_Operational.txt')
		#_# ToDo: Get-EventsTxt Microsoft-Windows-SyncShare/Debug ($EventLogDirectory + '\' + $env:COMPUTERNAME + '_SyncShare_Debug.txt')
		Get-EventsTxt Microsoft-Windows-SyncShare/Reporting ($EventLogDirectory + '\' + $env:COMPUTERNAME + '_SyncShare_Reporting.txt')
	}

	if ($Script:IsClient)
	{
		Get-EventsTxt Microsoft-Windows-WorkFolders/Operational ($EventLogDirectory + '\' + $env:COMPUTERNAME + '_WorkFolders_Operational.txt')
		#_# ToDo: Get-EventsTxt Microsoft-Windows-WorkFolders/Debug ($EventLogDirectory + '\' + $env:COMPUTERNAME + '_WorkFolders_Debug.txt')
		#_# ToDo: Get-EventsTxt Microsoft-Windows-WorkFolders/Analytic ($EventLogDirectory + '\' + $env:COMPUTERNAME + '_WorkFolders_Analytic.txt')
		Get-EventsTxt Microsoft-Windows-WorkFolders/WHC ($EventLogDirectory + '\' + $env:COMPUTERNAME + '_WorkFolders_ManagementAgent.txt')
	}
	Write-Host "$(Get-Date -Format 'HH:mm:ss') Collection of WorkFolders $WFmode event log entries done."

	if ($AdvancedMode)
	{ #_# Starting Service WorkFolderssvc
		if ($Script:IsClient) {  Write-Host "$(Get-Date -Format 'HH:mm:ss') Restarting Service WorkFolderssvc"
						Start-Service WorkFolderssvc }
		if ($Script:IsServer) {  Write-Host "$(Get-Date -Format 'HH:mm:ss') Restarting Services SyncShareSvc, SyncShareTTSvc"
						Start-Service SyncShareSvc
						Start-Service SyncShareTTSvc }
	}
	### Compress data
	Write-Host "$(Get-Date -Format 'HH:mm:ss') Finalizing/Zipping output ..."
	# In the output directory, remove the system and hidden attributes from files
	attrib ($Script:TempOutputPath + '\*') -H -S /s
	# Zip the output directory
	Add-Type -AssemblyName System.IO.Compression
	Add-Type -AssemblyName System.IO.Compression.FileSystem
	$OutputZipFile = $OutputDirectory + '\' + $env:COMPUTERNAME + '_WorkFoldersDiagOutput.zip'
	[System.IO.Compression.ZipFile]::CreateFromDirectory($Script:TempOutputPath, $OutputZipFile)
	Write-Host "All information have been saved in $OutputZipFile." -ForegroundColor Green 

	###
	Write-Host "Cleaning up environment ..."
	if ($Cleanup) { Write-Host "$(Get-Date -Format 'HH:mm:ss') Cleaning output directory $Script:TempOutputPath ..."
					Remove-Item $Script:TempOutputPath -Recurse -Force }

	$ErrorActionPreference = $OldErrorActionPreference
	Write-Host "$(Get-Date -Format 'HH:mm:ss') Done - tss_WorkFoldersDiag" -ForegroundColor White -BackgroundColor DarkGreen
	Write-Host " "
}
} # end of function Get-WorkFoldersInfo

#region ::::: MAIN ::::
Get-WorkFoldersInfo -OutputDirectory $dataPath $AdvancedMode -TraceLevel $TraceLevel -Stage $Stage
#endregion ::::: MAIN :::::


# SIG # Begin signature block
# MIInrQYJKoZIhvcNAQcCoIInnjCCJ5oCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBO3X5nRSPI+pqT
# fVFpR+EvNb4WJQN5JztzJfBjdAQZ6KCCDYEwggX/MIID56ADAgECAhMzAAACzI61
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
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIZgjCCGX4CAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAsyOtZamvdHJTgAAAAACzDAN
# BglghkgBZQMEAgEFAKCBrjAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgS+0flYiY
# 7fRH647fP++eGPQduTI5qKD0Jhk5Um2p6VAwQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQA784G2dU9G8rH243xooDazaSb0xIua+c+N5blw1hoJ
# hrTzHr4pS8XTi5iN9fv70cUdMgT7NLswWCghuoD9sK4UsZgWNxOQu/DwonqZALfa
# P7Fz5k9WDyWx1DxqJU7nDQ13QfHZW51vaKQ5Xl0ABe1G/T8zvFOaEn/G3aSOHNrW
# Z1BsPCTgaEULbwn7otapz8CjM5Hdm9zO82cA0x/PQhuKwdRD7t6MHvS8AtKCpm4U
# KQ7tHN/j7n0sGvszmExouv03TTjBfuiG5cesyBVxQ+fEzChaNOpCcTsK8d1JEwN8
# pQoIes29c+M/apf29iyYsnfASc85Wx3Cl3FayCsKrl1CoYIXDDCCFwgGCisGAQQB
# gjcDAwExghb4MIIW9AYJKoZIhvcNAQcCoIIW5TCCFuECAQMxDzANBglghkgBZQME
# AgEFADCCAVUGCyqGSIb3DQEJEAEEoIIBRASCAUAwggE8AgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEIL49HBpd14yTjZgEG65u0QVBMmg1O0HVlA8wgd9v
# j/8MAgZjTvWAgQUYEzIwMjIxMDI2MTQzMTM0LjU1NVowBIACAfSggdSkgdEwgc4x
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1p
# Y3Jvc29mdCBPcGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMg
# VFNTIEVTTjozMkJELUUzRDUtM0IxRDElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgU2VydmljZaCCEV8wggcQMIIE+KADAgECAhMzAAABrfzfTVjjXTLpAAEA
# AAGtMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# MB4XDTIyMDMwMjE4NTEzNloXDTIzMDUxMTE4NTEzNlowgc4xCzAJBgNVBAYTAlVT
# MRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVy
# YXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjozMkJE
# LUUzRDUtM0IxRDElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2Vydmlj
# ZTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAOieUyqlTSrVLhvY7TO8
# vgC+T5N/y/MXeR3oNwE0rLI1Eg/gM5g9NhP+KqqJc/7uPL4TsoALb+RVf6roYNll
# yQrYmquUjwsq262MD5L9l9rU1plz2tMPehP8addVlNIjYIBh0NC4CyME6txVppQr
# 7eFd/bW0X9tnZy1aDW+zoaJB2FY8haokq5cRONEW4uoVsTTXsICkbYOAYffIIGak
# MFXVvB30NcsuiDn6uDk83XXTs0tnSr8FxzPoD8SgPPIcWaWPEjCQLr5I0BxfdUli
# wNPHIPEglqosrClRjXG7rcZWbWeODgATi0i6DUsv1Wn0LOW4svK4/Wuc/v9dlmuI
# ramv9whbgCykUuYZy8MxTzsQqU2Rxcm8h89CXA5jf1k7k3ZiaLUJ003MjtTtNXzl
# gb+k1A5eL17G3C4Ejw5AoViM+UBGQvxuTxpFeaGoQFqeOGGtEK0qk0wdUX9p/4Au
# 9Xsle5D5fvypBdscXBslUBcT6+CYq0kQ9smsTyhV4DK9wb9Zn7ObEOfT0AQyppI6
# jwzBjHhAGFyrKYjIbglMaEixjRv7XdNic2VuYKyS71A0hs6dbbDx/V7hDbdv2srt
# Z2VTO0y2E+4QqMRKtABv4AggjYKz5TYGuQ4VbbPY8fBO9Xqva3Gnx1ZDOQ3nGVFK
# HwarGDcNdB3qesvtJbIGJgJjAgMBAAGjggE2MIIBMjAdBgNVHQ4EFgQUfVB0HQS8
# qiFabmqEqOV9LrLGwVkwHwYDVR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIw
# XwYDVR0fBFgwVjBUoFKgUIZOaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9w
# cy9jcmwvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3Js
# MGwGCCsGAQUFBwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3Nv
# ZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENB
# JTIwMjAxMCgxKS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcD
# CDANBgkqhkiG9w0BAQsFAAOCAgEAi9AdRbsx/gOSdBXndwRejQuutQqce3k3bgs1
# slPjZSx6FDXp1IZzjOyT1Jo/3eUWDBFJdi+Heu1NoyDdGn9vL6rxly1L68K4MnfL
# Bm+ybyjN+xa1eNa4+4cOoOuxE2Kt8jtmZbIhx2jvY7F9qY/lanR5PSbUKyClhNQh
# xsnNUp/JSQ+o7nAuQJ+wsCwPCrXYE7C+TvKDja6e6WU0K4RiBXFGU1z6Mt3K9wlM
# D/QGU4+/IGZDmE+/Z/k0JfJjZyxCAlcmhe3rgdhDzAsGxJYq4PblGZTBdr8wkQwp
# P2jggyMMawMM5DggwvXaDbrqCQ8gksNhCZzTqfS2dbgLF0m7HfwlUMrcnzi/bdTS
# RWzIXg5QsH1t5XaaIH+TZ1uZBtwXJ8EOXr6S+2A6q8RQVY10KnBH6YpGE9OhXPfu
# Iu882muFEdh4EXbPdARUR1IMSIxg88khSBC/YBwQhCpjTksq5J3Z+jyHWZ4MnXX5
# R42mAR584iRYc7agYvuotDEqcD0U9lIjgW31PqfqZQ1tuYZTiGcKE9QcYGvZFKnV
# dkqK8V0M9e+kF5CqDOrMMYRV2+I/FhyQsJHxK/G53D0O5bvdIh2gDnEHRAFihdZj
# 29Z7W0paGPotGX0oB5r9wqNjM3rbvuEe6FJ323MPY1x9/N1g126T/SokqADJBTKq
# yBYN4zMwggdxMIIFWaADAgECAhMzAAAAFcXna54Cm0mZAAAAAAAVMA0GCSqGSIb3
# DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIw
# MAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAx
# MDAeFw0yMTA5MzAxODIyMjVaFw0zMDA5MzAxODMyMjVaMHwxCzAJBgNVBAYTAlVT
# MRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1l
# LVN0YW1wIFBDQSAyMDEwMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA
# 5OGmTOe0ciELeaLL1yR5vQ7VgtP97pwHB9KpbE51yMo1V/YBf2xK4OK9uT4XYDP/
# XE/HZveVU3Fa4n5KWv64NmeFRiMMtY0Tz3cywBAY6GB9alKDRLemjkZrBxTzxXb1
# hlDcwUTIcVxRMTegCjhuje3XD9gmU3w5YQJ6xKr9cmmvHaus9ja+NSZk2pg7uhp7
# M62AW36MEBydUv626GIl3GoPz130/o5Tz9bshVZN7928jaTjkY+yOSxRnOlwaQ3K
# Ni1wjjHINSi947SHJMPgyY9+tVSP3PoFVZhtaDuaRr3tpK56KTesy+uDRedGbsoy
# 1cCGMFxPLOJiss254o2I5JasAUq7vnGpF1tnYN74kpEeHT39IM9zfUGaRnXNxF80
# 3RKJ1v2lIH1+/NmeRd+2ci/bfV+AutuqfjbsNkz2K26oElHovwUDo9Fzpk03dJQc
# NIIP8BDyt0cY7afomXw/TNuvXsLz1dhzPUNOwTM5TI4CvEJoLhDqhFFG4tG9ahha
# YQFzymeiXtcodgLiMxhy16cg8ML6EgrXY28MyTZki1ugpoMhXV8wdJGUlNi5UPkL
# iWHzNgY1GIRH29wb0f2y1BzFa/ZcUlFdEtsluq9QBXpsxREdcu+N+VLEhReTwDwV
# 2xo3xwgVGD94q0W29R6HXtqPnhZyacaue7e3PmriLq0CAwEAAaOCAd0wggHZMBIG
# CSsGAQQBgjcVAQQFAgMBAAEwIwYJKwYBBAGCNxUCBBYEFCqnUv5kxJq+gpE8RjUp
# zxD/LwTuMB0GA1UdDgQWBBSfpxVdAF5iXYP05dJlpxtTNRnpcjBcBgNVHSAEVTBT
# MFEGDCsGAQQBgjdMg30BATBBMD8GCCsGAQUFBwIBFjNodHRwOi8vd3d3Lm1pY3Jv
# c29mdC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5odG0wEwYDVR0lBAwwCgYI
# KwYBBQUHAwgwGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGG
# MA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU1fZWy4/oolxiaNE9lJBb186a
# GMQwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3Br
# aS9jcmwvcHJvZHVjdHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3JsMFoGCCsG
# AQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraS9jZXJ0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcnQwDQYJKoZIhvcN
# AQELBQADggIBAJ1VffwqreEsH2cBMSRb4Z5yS/ypb+pcFLY+TkdkeLEGk5c9MTO1
# OdfCcTY/2mRsfNB1OW27DzHkwo/7bNGhlBgi7ulmZzpTTd2YurYeeNg2LpypglYA
# A7AFvonoaeC6Ce5732pvvinLbtg/SHUB2RjebYIM9W0jVOR4U3UkV7ndn/OOPcbz
# aN9l9qRWqveVtihVJ9AkvUCgvxm2EhIRXT0n4ECWOKz3+SmJw7wXsFSFQrP8DJ6L
# GYnn8AtqgcKBGUIZUnWKNsIdw2FzLixre24/LAl4FOmRsqlb30mjdAy87JGA0j3m
# Sj5mO0+7hvoyGtmW9I/2kQH2zsZ0/fZMcm8Qq3UwxTSwethQ/gpY3UA8x1RtnWN0
# SCyxTkctwRQEcb9k+SS+c23Kjgm9swFXSVRk2XPXfx5bRAGOWhmRaw2fpCjcZxko
# JLo4S5pu+yFUa2pFEUep8beuyOiJXk+d0tBMdrVXVAmxaQFEfnyhYWxz/gq77EFm
# PWn9y8FBSX5+k77L+DvktxW/tM4+pTFRhLy/AsGConsXHRWJjXD+57XQKBqJC482
# 2rpM+Zv/Cuk0+CQ1ZyvgDbjmjJnW4SLq8CdCPSWU5nR0W2rRnj7tfqAxM328y+l7
# vzhwRNGQ8cirOoo6CGJ/2XBjU02N7oJtpQUQwXEGahC0HVUzWLOhcGbyoYIC0jCC
# AjsCAQEwgfyhgdSkgdEwgc4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1ZXJ0byBSaWNv
# MSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjozMkJELUUzRDUtM0IxRDElMCMGA1UE
# AxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUA
# QJLRrUVR4ZbBDgWPjuNqVctUzpCggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFt
# cCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUFAAIFAOcDVu4wIhgPMjAyMjEwMjYxMDQ5
# MThaGA8yMDIyMTAyNzEwNDkxOFowdzA9BgorBgEEAYRZCgQBMS8wLTAKAgUA5wNW
# 7gIBADAKAgEAAgIn8gIB/zAHAgEAAgIRMjAKAgUA5wSobgIBADA2BgorBgEEAYRZ
# CgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0G
# CSqGSIb3DQEBBQUAA4GBAGiQ6JzenbUXn/heSklKAJaqxJ0k02LtdHTLOzq15/4a
# ocXynbMNKYwi3KhHeNxXAYBMzxvxyjntK6hC3/WTciftys3vzwG3CTL4IdQxT3Fg
# yCtTaC7VkEdMa2exlIkYUQRHG3T2Q56T85J83fZtxWW4yQHUhVhjwaxpEin0Kd+n
# MYIEDTCCBAkCAQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMA
# AAGt/N9NWONdMukAAQAAAa0wDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJ
# AzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQgMjztkwM6qlw7JiEtUV28
# yq3/nykhEWOyLsG1fX2qyAgwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCCf
# 6nw9CR5e1+Ottcn1w992Kmn8YMTY/DWPIHeMbMtQgjCBmDCBgKR+MHwxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29m
# dCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABrfzfTVjjXTLpAAEAAAGtMCIEIL3e
# RA8TZr2OyZE1ES8ChjKo2GGEtMUvVcKcIYRdxku4MA0GCSqGSIb3DQEBCwUABIIC
# AFnF82gUJOdUzIaOg+79B5AfvVQLY0lTXqQehrkXwmmO/eq46RGCcYhrE2Hyuggk
# DCL5fo/Gqocs0BV2s0mVBY8N/gV5h45Hi+8cBNrpJMIrn0l3beKUaJYCLpi6U1zu
# 8fPkUymeptsPzoUjDoCM1oBjLVuNjS7Bc1zjh0r8iC1Am5RzuNIAO7o1YU2uobY7
# hOgkOIyXRXRdgQpf50DFl6bfIuKHwINjSu0x1bjXEUZSNTIv2/GoeGvoFiB3EGES
# bmIJVzmMo6gP90V0upOdz/wvBnPzczRgqdS4h4JTboC0kzrLm6izqPd+g2sFT1qi
# hNAHg0rX/TbxD9B0+5nnPmi5bl6Zetn3NcURXvg/Rag4TCFz77dC1N0g9KZrMzRf
# bnU21MDfaYl4+h5HoBR+AQE5LLl1aZH1rW5tnwjB3n+i/UPXU838VFx1cmb70tmR
# LOB41G2jNtR+2dAMLV03We2uFT9lb0TOMLU6DcNXETWQizo4/x8hEPe8BHaFO4fj
# +tQD5HYwD6DTUYwCphIuIAbHll2Ap//Rkl3cgVJOPwFwTdleXsGPG1ncD3phTkAg
# MCKTt4MeACkJWsUmt3hRgQ1COlaa6jb/FIIlEEoEQ3ZmRqZ8s2wgn35Ssn1MAJGU
# 6LhkH4/BdTEjIAyrINkvI62ZA7vAhhlY5sHlXw223K+3
# SIG # End signature block
