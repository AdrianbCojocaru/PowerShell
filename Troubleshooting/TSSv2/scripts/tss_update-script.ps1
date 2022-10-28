# Name: tss_update-script.ps1 for TSSv2

<# 
.SYNOPSIS
	Script to [auto-]update TSSv2 to latest version or download latest zip from CesdiagTools/GitHub.

.DESCRIPTION
	Script will search on "https://microsoft.githubenterprise.com/css-windows/WindowsCSSToolsDevRep/releases/tag" for latest TSSv2 version
	If local version does not match the remote CesdiagTools/GitHub version, it will download and replace TSSv2 with latest version
	Script gets the current version from $global:TssVerDate or by running ".\TSSv2 -ver" and compares to version 'https://cesdiagtools.blob.core.windows.net/windows/TSSv2.ver'.

.PARAMETER tss_action
	choose action from allowed values: "Download" or "Update" or "Version"
		Download	= download latest CesdiagTools/GitHub version
		Update		= update current local version
		Version		= decide based on local version, try AutoUpdate if local version is lower than CesdiagTools/GitHub version
	Ex: -tss_action "Download"
	
.PARAMETER tss_file
	Specify filename from allowed values: "TSSv2.zip" , "TSSv2_ttd.zip" , "TSSv2_diff.zip" or "TSSv2Lite.zip"
	Ex: -tss_file "TSSv2.zip"
	
.PARAMETER TSS_path
	Specify the local path where TSSv2.ps1 is located.
	Ex: -TSS_path "C:\TSSv2"

.PARAMETER UpdMode
	Specify the mode: 
		Online  = complete package (TSSv2.zip) from aka.ms/getTSS
		Full    = complete package (TSSv2.zip) from CesdiagTools/GitHub
		Quick   = differential package only (TSSv2_diff.zip): replace only TSSv2.ps1, TSSv2_[POD].psm1 and config\tss_config.cfg files; will not update \BIN* folders
		Force   = run a Full update, regardless of current installed version

.PARAMETER tss_arch
	Specify the System Architecture.
	Allowed values:
		x64 - For 64-bit systems
		x86 - For 32-bit systems
	Ex: -tss_arch "x64"

.EXAMPLE
	.\tss_update-script.ps1 -tss_action "Update" -TSS_path "C:\TSSv2" -tss_file "TSSv2.zip"
	Example 1: Update TSSv2 in folder C:\TSSv2
	
.LINK
	https://microsoft.githubenterprise.com/css-windows/WindowsCSSToolsDevRep/releases/tag
	Public Download: TSSv2:    https://cesdiagtools.blob.core.windows.net/windows/TSSv2.zip -or- https://aka.ms/getTSSv2 or aka.ms/getTSS
#>


param(
	[ValidateSet("download","update","version")]
	[Parameter(Mandatory=$False,Position=0,HelpMessage='Choose from: download|update|version')]
	[string]$tss_action 	= "download"
	,
	[string]$TSS_path 		= (Split-Path $MyInvocation.MyCommand.Path -Parent | Split-Path -Parent),
	[ValidateSet("Online","Full","Quick","Force","Lite")]
	[string]$UpdMode 		= "Online"
	,
	$verOnline
	,
	[ValidateSet("TSSv2.zip","TSSv2_diff.zip","TSSv2Lite.zip","TSSv2_ttd.zip")]
	[string]$tss_file 		= "TSSv2.zip"
	,
	[ValidateSet("x64","x86")]
	[string]$tss_arch 		= "x64",
	[string]$CentralStore	= "",								# updating from Central Enterprise Store
	[switch]$AutoUpd		= $False,							# 
	[switch]$UseExitCode 	= $true								# This will cause the script to bail out after the error is logged if an error occurs.
)

#region  ::::: [Variables] -----------------------------------------------------------#
$updScriptVersion	= "2022.05.22"
$UpdLogfile 		= $TSS_path + "\_tss_Update-Log.txt"
$script:ChkFailed	= $FALSE
$invocation 		= (Get-Variable MyInvocation).Value
$ScriptGrandParentPath 	= $MyInvocation.MyCommand.Path | Split-Path -Parent | Split-Path -Parent
$scriptName 		= $invocation.MyCommand.Name
if ($UpdMode -match 'Online') {
	$TssReleaseServer = "cesdiagtools.blob.core.windows.net"
	$tss_release_url  = "https://cesdiagtools.blob.core.windows.net/windows"
} else {
	$TssReleaseServer = "api.Github.com"
	$tss_release_url  = "https://api.github.com/repos/walter-1/TSSv2/releases"
}
$NumExecutable = (Get-ChildItem "$global:ScriptFolder\BIN\" -Name "*.exe" -ErrorAction Ignore).count 
If($NumExecutable -lt 20){
	$LiteMode=$True
}Else{
	$LiteMode=$False
}
#endregion  ::::: [Variables] --------------------------------------------------------#

$ScriptBeginTimeStamp = Get-Date

# Check if last "\" was provided in $TSS_path, if it was not, add it
if (-not $TSS_path.EndsWith("\")){
	$TSS_path = $TSS_path + "\"
}

#region  ::::: [Functions] -----------------------------------------------------------#
function ExitWithCode ($Ecode) {
	# set ErrorLevel to be picked up by invoking CMD script
	if ( $UseExitCode ) {
		Write-Verbose "[Update] Return Code: $Ecode"
		#error.clear()	# clear script errors
		exit $Ecode
		}
}

function get_local_tss_version {
	<#
	.SYNOPSIS
		Function returns current or LKG TSSv2 version locally from "$TSSv2_ps1_script -ver" command.
	#>
	param($type="current")
	switch ($type) {
        "current"  	{ $TSSv2_ps1_script = "TSSv2.ps1" }
        "LKG" 		{ $TSSv2_ps1_script = "TSSv2-LKG.ps1" }
	}
	if ( -not (Test-Path $TSSv2_ps1_script)) {
		$TSSv2_ps1_script = "TSSv2.ps1"
	}  
	Get-Content ..\$TSSv2_ps1_script | Where-Object {$_ -match 'global:TssVerDate ='} | ForEach-Object { $v2version=($_ -Split '\s+')[3] }
	$TSSv2version = $v2version.Replace("""","")
	Write-verbose "[get_local_tss_version] TSSv2version= $TSSv2version"
	return [version]$TSSv2version
}

function get_latest_tss_version {
	<#
	.SYNOPSIS
		Function will get latest version from CesdiagTools/GitHub Release page
	.LINK
		https://github.com/walter-1/TSSv2/releases
		https://cesdiagtools.blob.core.windows.net/windows/TSSv2.zip
	#>
	EnterFunc ($MyInvocation.MyCommand.Name + "(URL: $RFL_release_url)" )
	if ($UpdMode -match 'Online') {
		return $verOnline # = TSSv2.ver
	} else {
		# GitHub: Get web content and convert from JSON
		[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
		try { $web_content = Invoke-WebRequest -Uri $tss_release_url -UseBasicParsing | ConvertFrom-Json } catch { "`n*** Failure during TSSv2 update. Exception Message:`n $($_.Exception.Message)" | Out-File $UpdLogfile -Append }
		if ($web_content.tag_name) {
			[version]$expected_latest_tss_version = $web_content.tag_name.replace("v","")
			write-verbose "$UpdateSource Version of '$tss_release_url': --> $expected_latest_tss_version"
			return $expected_latest_tss_version
		}
		else 
		{ Write-Host -ForegroundColor Red "[ERROR] cannot securely access $TssReleaseServer. Please download https://aka.ms/getTSS"
			"`n $ScriptBeginTimeStamp [ERROR] cannot securely access $TssReleaseServer. Please download https://aka.ms/getTSS" | Out-File $UpdLogfile -Append
			$script:ChkFailed=$TRUE
			return 2022.0.0.0
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

function DownloadFileFromGitHubRelease {
	param(
		$action = "download", 
		$file, 
		$installedTSSver)
	# Download latest TSSv2 release from CesdiagTools/GitHub
	$repo = "walter-1/TSSv2"
	$releases = "https://api.github.com/repos/$repo/releases"
	#Determining latest release , Set TLS to 1.2
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
	$tag = (Invoke-WebRequest $releases -UseBasicParsing | ConvertFrom-Json)[0].tag_name
	$downloadURL = "https://github.com/$repo/releases/download/$tag/$file"
	Write-Verbose "downloadURL: $downloadURL"
	$name = $file.Split(".")[0]
	$zip = "$name-$tag.zip"
	$TmpDir = "$name-$tag"
	Write-Verbose "Name: $name - Zip: $zip - Dir: $TmpDir - Tag/version: $tag"
	
	#_# faster Start-BitsTransfer $downloadURL -Destination $zip # is not allowed for GitHub
	Write-Host ".. Secure download of latest release: $downloadURL"
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
	Invoke-WebRequest $downloadURL -OutFile $zip

	if ($action -match "download") {
		Write-Host -ForegroundColor Green "[Info] Downloaded version to folder: $TSS_path`scripts\$tss_file"
		}
	if ($action -match "update") {
		#save current script and expand
		Write-Host "... saving a copy of current installed TSSv2.ps1 to $($TSS_path + "TSSv2.ps1_v" + $installedTSSver)"
		Copy-Item ($TSS_path + "TSSv2.ps1") ($TSS_path + "TSSv2.ps1_v" + $installedTSSver) -Force -ErrorAction SilentlyContinue
		Write-Host "... saving a copy of current \config\tss_config.cfg to $($TSS_path + "config\tss_config.cfg_backup")"
		Copy-Item ($TSS_path + "config\tss_config.cfg") ($TSS_path + "config\tss_config.cfg_backup") -Force -ErrorAction SilentlyContinue
		Write-Host "[Expand-Archive] Extracting release files from $zip"
		Expand-Archive  -Path $zip -DestinationPath $ENV:temp\$TmpDir -Force
		Write-Host ".. Cleaning up .."
		Write-Verbose "Cleaning up target dir: Remove-Item $name -Recurse"
		Write-Verbose "Copying from temp dir: $ENV:temp\$TmpDir to target dir: $TSS_path"
		Copy-Item $ENV:temp\$TmpDir\* -Destination $TSS_path -Recurse -Force
		Write-Verbose "Removing temp file: $zip and folder $TmpDir"
		Remove-Item $zip -Force
		Write-Verbose "Remove-Item $ENV:temp\$TmpDir -Recurse"
		Remove-Item $ENV:temp\$TmpDir -Recurse -Force -ErrorAction SilentlyContinue
		Write-Host -ForegroundColor Gray "[Info] Updated with latest TSSv2 version $script:expected_latest_tss_version"
	}
}

function DownloadTssZipFromCesdiagRelease {
	param(
		$file	# TSSv2.zip or TSSv2Lite.zip
	)
	switch ($file) {
        "TSSv2.zip"  	{ $downloadURL = $tss_release_url + "/TSSv2.zip" }
        "TSSv2Lite.zip" { $downloadURL = $tss_release_url + "/TSSv2Lite.zip"  }
	}
	
	# faster Start-BitsTransfer
	Write-Host ".. Secure download of latest release: $downloadURL"
	Start-BitsTransfer $downloadURL -Destination "$ENV:temp\TSSv2_download.zip"
	#save current script and expand
	Write-Host "... saving a copy of current installed TSSv2.ps1 to $($TSS_path + "TSSv2.ps1_v" + $installedTSSver)"
	Copy-Item ($TSS_path + "TSSv2.ps1") ($TSS_path + "TSSv2.ps1_v" + $installedTSSver) -Force -ErrorAction SilentlyContinue
	Write-Host "... saving a copy of current \config\tss_config.cfg to $($TSS_path + "config\tss_config.cfg_backup")"
	Copy-Item ($TSS_path + "config\tss_config.cfg") ($TSS_path + "config\tss_config.cfg_backup") -Force -ErrorAction SilentlyContinue
	Write-Host "[Expand-Archive] Extracting release files from $ENV:temp\TSSv2_download.zip"
	expand-archive -LiteralPath "$ENV:temp\TSSv2_download.zip" -DestinationPath $TSS_path -force
	#ToDo
}
#endregion  ::::: [Functions] --------------------------------------------------------#


#region  ::::: [MAIN] ----------------------------------------------------------------#
# detect OS version and SKU # Note: gwmi / Get-WmiObject is no more supportd in PS v7 -> use Get-CimInstance
If($Host.Version.Major -ge 7){
	[Reflection.Assembly]::LoadWithPartialName("System.ServiceProcess.servicecontroller") | Out-Null
	$wmiOSVersion = Get-CimInstance -Namespace "root\cimv2" -Class Win32_OperatingSystem
} else {$wmiOSVersion = Get-WmiObject -Namespace "root\cimv2" -Class Win32_OperatingSystem}
[int]$bn = [int]$wmiOSVersion.BuildNumber
#Write-verbose "installed-version: $(get_local_tss_version current) - Build: $bn"
$installedTSSver = New-Object System.Version([version]$(get_local_tss_version "current"))
Write-verbose "installedTSSver: $installedTSSver"

## :: Criteria to use Quick vs. Online update: Quick if UpdMode = Quick; Online = if updates in xray or psSDP are needed, ...
# Choose download file based on $UpdMode (and current installed TSSv2 build)
If($LiteMode) {$tss_file = "TSSv2Lite.zip"} else {$tss_file = "TSSv2.zip" }
switch ($UpdMode) {
        "Quick"	{ 	$tss_file = "TSSv2_diff.zip"
					$UpdateSource= "GitHub"}
        "Lite"	{ 	$tss_file = "TSSv2Lite.zip"
					$UpdateSource= "GitHub"}
		"Online"{ 	#$tss_file = "TSSv2.zip"
					$UpdateSource= "CesdiagTools"}
#		"Force" { 	$tss_file = "TSSv2.zip" }	# always perform a Full update
        default	{ 	$tss_file = "TSSv2.zip"
					$UpdateSource= "CesdiagTools"}
}
		
# Check for Internet connectivity // Test-NetConnection does not work for Win7
$checkConn = FwTestConnWebSite $TssReleaseServer -ErrorAction SilentlyContinue
if ( $checkConn -eq "True") {
	# Determine which edition we need, ? based on existence of .\x64\TTTracer.exe # + ToDo Lite based on existence/number of *.exe in \BIN folder
	if ($UpdMode -Notmatch "Online") {
		$script:expectedVersion = New-Object System.Version(get_latest_tss_version)
	}
	if ("$($script:expectedVersion)" -eq "0.0") { Write-Verbose "Bail out: $script:expectedVersion"; ExitWithCode 20}
	# Check if TSSv2 exists in $TSS_path
	if (-not (Test-Path ($TSS_path + "TSSv2.ps1"))){
		Write-Host -ForegroundColor Red "[Warning] TSSv2.ps1 could not be located in $TSS_path"
		DownloadFileFromGitHubRelease "update" $tss_file $installedTSSver
	}

	if (Test-Path ($TSS_path + "TSSv2.ps1")){
		if ($UpdMode -match "Online") {
			DownloadTssZipFromCesdiagRelease -File "TSSv2.zip"
		}
		elseif ($UpdMode -match "Force") {	# update regardless of current local version
		Write-Host -ForegroundColor Cyan "[Forced update:] to latest version $script:expectedVersion from $UpdateSource`n"
		 if (Test-Path ($TSS_path + "x64\TTTracer.exe")) { Write-Host -ForegroundColor Yellow "[note:] This procedure will not refresh iDNA part"}
									DownloadFileFromGitHubRelease "update" $tss_file $installedTSSver
		} else {
			Write-Host "[Info] checking current version $installedTSSver in $TSS_path against latest released $UpdateSource version $script:expectedVersion."
			if ($($installedTSSver.CompareTo($script:expectedVersion)) -eq 0) { 		# If versions match, display message
				"`n [Info] Latest TSSv2 version $script:expectedVersion is installed. " | Out-File $UpdLogfile -Append
				Write-Host -ForegroundColor Cyan "[Info] Latest TSSv2 version $script:expectedVersion is installed.`n"}
			elseif ($($installedTSSver.CompareTo($script:expectedVersion)) -lt 0) {	# if installed current version is lower than latest $UpdateSource Release version
				"`n [Action: $tss_action -[Warning] Actually installed TSSv2 version $installedTSSver is outdated] " | Out-File $UpdLogfile -Append
				Write-Host -ForegroundColor red "[Warning] Actually installed TSSv2 version $installedTSSver is outdated"
				Write-Host "[Info] Expected latest TSSv2 version on $($UpdateSource) = $script:expectedVersion"
				Write-Host -ForegroundColor yellow "[Warning] ** Update will overwrite customized configuration, latest \config\tss_config.cfg is preserved in \config\tss_config.cfg_backup. ** "
				switch($tss_action)
					{
					"download"		{ 	Write-Host "[download:] latest $tss_file"
										DownloadFileFromGitHubRelease "download" $tss_file $installedTSSver
									}
					"update"		{ 	Write-Host "[update:] to latest version $script:expectedVersion from $UpdateSource " 
										 if (Test-Path ($TSS_path + "x64\TTTracer.exe")) { Write-Host -ForegroundColor Yellow "[note:] This procedure will not refresh iDNA/TTD part"}
										DownloadFileFromGitHubRelease "update" $tss_file $installedTSSver
									}
					"version"		{ 	Write-Host -background darkRed "[version:] installed TSSv2 version is outdated, please run 'TSS Update', trying AutoUpate" # or answer next question with 'Yes'"
										Write-Host -ForegroundColor Cyan "[Info] running AutoUpdate now... (to avoid updates, append TSSv2 switch 'noUpdate')"
										DownloadFileFromGitHubRelease "update" $tss_file $installedTSSver
									}
					}
					"`n [Action: $tss_action - OK] " | Out-File $UpdLogfile -Append
			}
			else {	# if installed current version is greater than latest CesdiagTools/GitHub Release version
				if ($script:ChkFailed) {Write-Host -ForegroundColor Gray "[Info] Version check failed! Expected version on $($UpdateSource) = $script:expectedVersion. Please download https://aka.ms/getTSS `n"}
				Write-Verbose "Match: Current installed TSSv2 version:  $installedTSSver"
				Write-Verbose "Expected latest TSSv2 version on $($UpdateSource) = $script:expectedVersion"
			}
		}
	}
} else {
	Write-Host -ForegroundColor Red "[failed update] Missing secure internet connection to $TssReleaseServer. Please download https://aka.ms/getTSS `n"
							"`n [failed update] Missing secure internet connection to $TssReleaseServer. Please download https://aka.ms/getTSS `n" | Out-File $UpdLogfile -Append
}

$ScriptEndTimeStamp = Get-Date
$Duration = $(New-TimeSpan -Start $ScriptBeginTimeStamp -End $ScriptEndTimeStamp)

Write-Host -ForegroundColor Black -background gray "[Info] Script $scriptName v$updScriptVersion execution finished. Duration: $Duration"
if ($AutoUpd) { Write-Host -ForegroundColor Yellow  "[AutoUpdate done] .. Please repeat your TSSv2 command now."}
#endregion  ::::: [MAIN] -------------------------------------------------------------#

#region  ::::: [ToDo] ----------------------------------------------------------------#
<# 
 ToDo: 
 - save any CX changed file like \config\tss_config.cfg into a [backup_v...] subfolder with prev. version, --> easy restoration, if there is no schema change
	see "...saving a copy of installed TSSv2.ps1  ..."
 - allow TSSv2 to update from CX Central Enterprise store \\server\share\tss defined in \config\tss_config.cfg, if update from CesdiagTools/GitHub fails
 
- Implement a scheduled task for periodic update check
Example one-line command: schtasks.exe /Create /SC DAILY /MO 1 /TN "tss Updater" /TR "powershell \path\to\script\get-latest-tss.ps1 -TSS_path 'path\to\where\tss\is' -tss_arch 'x64'" /ST 12:00 /F
	[/SC DAILY]: Run daily
	[/MO 1]: Every Day
	[/TN "tss Updater"]: Task Name
	[/TR "powershell \path\to\script\get-latest-tss.ps1 -TSS_path 'path\to\where\tss\is' -tss_arch 'x64'"]: Command to run
	[/ST 12:00]: Run at 12 PM
	[/F]: Force update
#>
#endregion  ::::: [ToDo] ----------------------------------------------------------------#


# SIG # Begin signature block
# MIInqgYJKoZIhvcNAQcCoIInmzCCJ5cCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCxEPh+N9ngZ1o4
# 4SACifkVuIS7SjshEiR22oMsJGg/1KCCDYEwggX/MIID56ADAgECAhMzAAACzI61
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
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIZfzCCGXsCAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAsyOtZamvdHJTgAAAAACzDAN
# BglghkgBZQMEAgEFAKCBrjAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgpT3YUSCN
# THmbf6EqQ6xuZVpou3xOp2MSuR2e50XR8UIwQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQCPtU4CvWSGcgSZB7UBkJrQTWgLId9c8oUTovjv/ykd
# zPCefZJ6gYV4hfVqPc2p4WRG8T2vS6fgR1IjpOKJxhJBYOyJ1gfvFLilHCPvLMKp
# 1ndTOhySKTm/DkeTAvzXoiSZrsf4o9AnWLhMB86w+SXVq9GjmamzM9Cy9YZJcxDE
# Tw2QReD1Q1nobTFEHK8WiJLA6ayZOqY23TCxPaMfSDBa68deig3FFNIIfMah8/cw
# jFgbioelYmJvh8m3kwNlnd+o5bZBPcvXh0VlJpIFDMgjoAHUy2x5LRv3zEZix3wx
# 2tobIKYfd1dddXWnHsXMhk7kbRlliIT42917nN0khWAwoYIXCTCCFwUGCisGAQQB
# gjcDAwExghb1MIIW8QYJKoZIhvcNAQcCoIIW4jCCFt4CAQMxDzANBglghkgBZQME
# AgEFADCCAVUGCyqGSIb3DQEJEAEEoIIBRASCAUAwggE8AgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEIGkeIpjB93o/OIdkQYMFg/N1CtJX/1I7cv+IhDaw
# +ZBBAgZjTo6Xd74YEzIwMjIxMDI2MTQzMTMzLjc2NlowBIACAfSggdSkgdEwgc4x
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1p
# Y3Jvc29mdCBPcGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMg
# VFNTIEVTTjpDNEJELUUzN0YtNUZGQzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgU2VydmljZaCCEVwwggcQMIIE+KADAgECAhMzAAABo/uas457hkNPAAEA
# AAGjMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# MB4XDTIyMDMwMjE4NTExNloXDTIzMDUxMTE4NTExNlowgc4xCzAJBgNVBAYTAlVT
# MRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVy
# YXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjpDNEJE
# LUUzN0YtNUZGQzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2Vydmlj
# ZTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAO+9TcrLeyoKcCqLbNtz
# 7Nt2JbP1TEzzMhi84gS6YLI7CF6dVSA5I1bFCHcw6ZF2eF8Qiaf0o2XSXf/jp5sg
# mUYtMbGi4neAtWSNK5yht4iyQhBxn0TIQqF+NisiBxW+ehMYWEbFI+7cSdX/dWw+
# /Y8/Mu9uq3XCK5P2G+ZibVwOVH95+IiTGnmocxWgds0qlBpa1rYg3bl8XVe5L2qT
# UmJBvnQpx2bUru70lt2/HoU5bBbLKAhCPpxy4nmsrdOR3Gv4UbfAmtpQntP758NR
# Phg1bACH06FlvbIyP8/uRs3x2323daaGpJQYQoZpABg62rFDTJ4+e06tt+xbfvp8
# M9lo8a1agfxZQ1pIT1VnJdaO98gWMiMW65deFUiUR+WngQVfv2gLsv6o7+Ocpzy6
# RHZIm6WEGZ9LBt571NfCsx5z0Ilvr6SzN0QbaWJTLIWbXwbUVKYebrXEVFMyhuVG
# QHesZB+VwV386hYonMxs0jvM8GpOcx0xLyym42XA99VSpsuivTJg4o8a1ACJbTBV
# FoEA3VrFSYzOdQ6vzXxrxw6i/T138m+XF+yKtAEnhp+UeAMhlw7jP99EAlgGUl0K
# kcBjTYTz+jEyPgKadrU1of5oFi/q9YDlrVv9H4JsVe8GHMOkPTNoB4028j88OEe4
# 26BsfcXLki0phPp7irW0AbRdAgMBAAGjggE2MIIBMjAdBgNVHQ4EFgQUUFH7szwm
# CLHPTS9Bo2irLnJji6owHwYDVR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIw
# XwYDVR0fBFgwVjBUoFKgUIZOaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9w
# cy9jcmwvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3Js
# MGwGCCsGAQUFBwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3Nv
# ZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENB
# JTIwMjAxMCgxKS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcD
# CDANBgkqhkiG9w0BAQsFAAOCAgEAWvLep2mXw6iuBxGu0PsstmXI5gLmgPkTKQnj
# gZlsoeipsta9oku0MTVxlHVdcdBbFcVHMLRRkUFIkfKnaclyl5eyj03weD6b/pUf
# FyDZB8AZpGUXhTYLNR8PepM6yD6g+0E1nH0MhOGoE6XFufkbn6eIdNTGuWwBeEr2
# DNiGhDGlwaUH5ELz3htuyMyWKAgYF28C4iyyhYdvlG9VN6JnC4mc/EIt50BCHp8Z
# QAk7HC3ROltg1gu5NjGaSVdisai5OJWf6e5sYQdDBNYKXJdiHei1N7K+L5s1vV+C
# 6d3TsF9+ANpioBDAOGnFSYt4P+utW11i37iLLLb926pCL4Ly++GU0wlzYfn7n22R
# yQmvD11oyiZHhmRssDBqsA+nvCVtfnH183Df5oBBVskzZcJTUjCxaagDK7AqB6QA
# 3H7l/2SFeeqfX/Dtdle4B+vPV4lq1CCs0A1LB9lmzS0vxoRDusY80DQi10K3SfZK
# 1hyyaj9a8pbZG0BsBp2Nwc4xtODEeBTWoAzF9ko4V6d09uFFpJrLoV+e8cJU/hT3
# +SlW7dnr5dtYvziHTpZuuRv4KU6F3OQzNpHf7cBLpWKRXRjGYdVnAGb8NzW6wWTj
# ZjMCNdCFG7pkKLMOGdqPDFdfk+EYE5RSG9yxS76cPfXqRKVtJZScIF64ejnXbFIs
# 5bh8KwEwggdxMIIFWaADAgECAhMzAAAAFcXna54Cm0mZAAAAAAAVMA0GCSqGSIb3
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
# vzhwRNGQ8cirOoo6CGJ/2XBjU02N7oJtpQUQwXEGahC0HVUzWLOhcGbyoYICzzCC
# AjgCAQEwgfyhgdSkgdEwgc4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1ZXJ0byBSaWNv
# MSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjpDNEJELUUzN0YtNUZGQzElMCMGA1UE
# AxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUA
# Hl/pXkLMAbPapCwa+GXc3SlDDROggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFt
# cCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUFAAIFAOcDmK4wIhgPMjAyMjEwMjYxNTI5
# NTBaGA8yMDIyMTAyNzE1Mjk1MFowdDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA5wOY
# rgIBADAHAgEAAgIOLDAHAgEAAgIRQjAKAgUA5wTqLgIBADA2BgorBgEEAYRZCgQC
# MSgwJjAMBgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqG
# SIb3DQEBBQUAA4GBADnkCmk0y5O7qZMsfyilAAJxoLHUpSZDzhFfPk0m64r+xbqz
# 4qhTP/o3CT1+n/oB9g1sviCM5i1Yt3MyPjGZnuRzxIiV/9OYfg3uCjZs9N9rXg4v
# tXInFshfcGBVXy4ge27jBcZG4KEciJFHTnp3/QXDvaNcrLjKt5SxrGEMb4rXMYIE
# DTCCBAkCAQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGj
# +5qzjnuGQ08AAQAAAaMwDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzEN
# BgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQgGrdYFYDSLX3gBB1EtP2Vh4Hi
# GHfVVSJ/VnjgzjqPIfkwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCCM+Liw
# BnHMMoOd/sgbaYxpwvEJlREZl/pTPklz6euN/jCBmDCBgKR+MHwxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABo/uas457hkNPAAEAAAGjMCIEIDC0nCyP
# 10lXW9DNsfxkGk0nLuc64ArGwU44NcFl/LnyMA0GCSqGSIb3DQEBCwUABIICACHd
# 8jxRA7vZNAHMrtnvLvC24LPaXeFpS3kohH8vdn746LIspS/aZYWuIBstgzX4xOJT
# OjYa9VMp2zuKfxZK6TnqCEbdguj/6gLUTur8uu7RAoq0CNAfgP4Ay9Spy3L6B8OP
# iO3BSzdy+5z01/modQm/g3biIyb0ATKgH/lkX86X7dninCIJbUWR5xsoS4yROhCf
# MZQemLuhy8Pk1KrA+L9v7NddvgITSYgFFvIgrfPxC5pmH+z+mescqjEuvMurQPz7
# XMEj1XlirH9riiWKDY1d03pdSJKs6yAV9ChS9rmaf03YT2oid3HBdi6qQaH2K3eb
# dOyIPjz4ByMCFNzPBoqtVKvNQ/9YGli5qc7nq0+tE2Z0HCojL0ARLEoDb/n2DDA6
# z7Neo4r7hgeeoux0O1ObEd39FkboDdtYYc51vnOZ6K937Q3T4q5qUGCB4BOi42Y3
# yPE/0qLhLqeQ43ARea9bHuSLj/AJz3Clpnt791uVtbLJmpu9Tzcj2YRnPsITDbpR
# SOYVvDl6i3QWaJiWXpw+k29sXX9laSQnCUqvxAiOKu6MYIIXjA40zIuRfTLefciu
# vb+TjmgfvVN9DU6WfBsU3IcIVrPrcE/X+ohSQ1f+4GGLJnH+N4Tsk+EyFcOw7O8M
# mlHPgIzvL5Xd2B56Iw+DQpNdJ6zoUBH18Qcw2iFk
# SIG # End signature block
