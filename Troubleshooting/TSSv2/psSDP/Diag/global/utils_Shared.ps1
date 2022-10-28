# ***********************************************************************************************
# Version 1.0
# Date: 02-17-2012 -- Last edit: 2022-06-01
# Author: Vinay Pamnani - vinpa@microsoft.com
# Description:  Utility Script to load common functions.
# 		1. Defines commonly used functions in the Troubleshooter
# ***********************************************************************************************

trap [Exception]
{
	WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText "[utils_Shared]"
	continue
}
##########################################
# Set Variables
##########################################

$ComputerName = $ENV:COMPUTERNAME
$windir = $Env:windir 
$ProgFiles64 = $ENV:ProgramFiles 
$ProgFiles86 = ${Env:ProgramFiles(x86)} 
$system32 = $windir + "\system32"
$SystemRoot = $Env:SystemRoot
$OS = Get-CimInstance Win32_OperatingSystem

##########################
## Function Definitions ##
##########################

Function Check-RegKeyExists($RegKey){
	# To check if a Registry Key exists
	# Taken from Kurt Saren's FEP Scripts
	$RegKey = $RegKey -replace "HKLM\\", "HKLM:\"
	$RegKey = $RegKey -replace "HKCU\\", "HKCU:\"
	return (Test-Path $RegKey)
}

Function Get-RegValue($RegKey, $RegValue){
	# To get a specified Registry Value
	# Taken from Kurt Saren's FEP Scripts
	$RegKey = $RegKey -replace "HKLM\\", "HKLM:\"
	$RegKey = $RegKey -replace "HKCU\\", "HKCU:\"
	If (Check-RegValueExists $RegKey $RegValue)
	{
		return (Get-ItemProperty -Path $RegKey).$RegValue
	}
	Else
	{
		return $null
	}
}

Function Check-RegValueExists ($RegKey, $RegValue){
	# To check if a Registry Value exists
	$RegKey = $RegKey -replace "HKLM\\", "HKLM:\"
	$RegKey = $RegKey -replace "HKCU\\", "HKCU:\"

	If (Test-Path $RegKey)
	{
		If (Get-ItemProperty -Path $RegKey -Name $RegValue -ErrorAction SilentlyContinue)
		{
			$true
		}
		Else
		{
			$false
			$Error.Clear()
		}
	}
	Else
	{
		$false
	}
}

Function Get-RegValueWithError($RegKey, $RegValue){
	# Modified version of Get-RegValue to get the error as well, instead of checking if the value is null everytime I call Get-RegValue
	$RegKey = $RegKey -replace "HKLM\\", "HKLM:\"
	$RegKey = $RegKey -replace "HKCU\\", "HKCU:\"
	If (Check-RegValueExists $RegKey $RegValue)
	{
		$Value = (Get-ItemProperty -Path $RegKey -ErrorAction SilentlyContinue -ErrorVariable RegError).$RegValue
		if ($RegError.Count -gt 0) {
			Return "ERROR: $($RegValue.Exception[0].Message)"
		}

		if ($null -ne $Value) {
			Return $Value
		}
		else {
			Return "ERROR: Registry value is NULL."
		}
	}
	Else
	{
		Return "ERROR: Registry value does not exist."
	}
}

Function Copy-FilesWithStructure(){
	# Copy files with structure
	# Always uses Recurse and filtering is done by -Include switch which can take multiple parameters.
	param (
		$Source,
		$Destination,
		$Include
	)

	process {
		# This function uses -Include with Get-ChildItem so that multiple patterns can be specified

		if ($Source.EndsWith("\")) {
			$Source = $Source.Substring(0, $Source.Length - 1)
		}

		TraceOut "Copying $Include files from $Source to $Destination"

		if (Test-Path $Source) {
			try {
				if ($Source -eq (Join-Path $Env:windir "Temp")) {
					$Files = Get-ChildItem $Source -Recurse -Include $Include | Where-Object {-not ($_.FullName -like '*SDIAG_*') -and -not($_.FullName -like '*MATS-Temp*')}
				}
				else {
					$Files = Get-ChildItem $Source -Recurse -Include $Include
				}

				$FileCount = ($Files | Measure-Object).Count
				if ($FileCount -eq 0) {
					TraceOut "    No files match the Include criteria."
					return
				}

				TraceOut "    Found $FileCount files matching specified criteria"
				$Files | ForEach-Object {
					$targetFile = $_.FullName.Replace($Source, $Destination)    # Replace the source location with destination in file path
        			New-Item -ItemType File -Path $targetFile -Force | Out-Null # This creates the folder structure to the file including the 0 byte file #_#
        			Copy-Item $_.FullName -Destination $targetFile -Force -ErrorAction SilentlyContinue -ErrorVariable CopyErr		# Copy and overwrite the file
					if ($CopyErr.Count -ne 0) {
						TraceOut "    ERROR occurred while copying $Source file: $($CopyErr.Exception)"
					}
					$CopyErr.Clear()
    			}
			}
			catch [Exception] {
				TraceOut "    ERROR: $_"
			}
		}
		else {
			TraceOut "    $Source does not exist."
		}
	}
}

Function Copy-Files(){
	# Copy files with specified filter
	# Uses Recurse if specified. Filtering is done by -Filter switch which takes only a single parameter.
	param(
		$Source,
		$Destination,
		$Filter,
		[switch]$Recurse,
		[switch]$RenameFileToPath
	)

	process {
		TraceOut "Copying $Filter files from $Source to $Destination"

		if (Test-Path $Source) {
			if ($Recurse) {
				$Files = Get-ChildItem $Source -Recurse -Filter $Filter | Where-Object {-not ($_.FullName -like '*SDIAG_*') -and -not($_.FullName -like '*MATS-Temp*')}
			}
			else {
				$Files = Get-ChildItem $Source -Filter $Filter | Where-Object {-not ($_.FullName -like '*SDIAG_*') -and -not($_.FullName -like '*MATS-Temp*')}
			}

			$FileCount = ($Files | Measure-Object).Count

			if ($FileCount -eq 0) {
				TraceOut "    No files match the Include criteria."
				return
			}

			TraceOut "    Found $FileCount files matching specified criteria"
			$Files | `
			ForEach-Object {
				$FilePath = $_.FullName

				if ($RenameFileToPath) {
					$DestFileName = ($FilePath -replace "\\","_" ) -replace ":","" }
				else {
					$DestFileName = $_.Name
				}

				Copy-Item $FilePath (Join-Path $Destination $DestFileName) -ErrorAction SilentlyContinue -ErrorVariable CopyErr -Force
				if ($CopyErr.Count -ne 0) {
					TraceOut "    ERROR occurred while copying $Source files: $($CopyErr.Exception)"
				}
				$CopyErr.Clear()
			}
		}
		else {
			TraceOut "    $Source does not exist."
		}
	}
}

Function Export-RegKey ([string]$RegKey, [string]$OutFile, [string]$FileDescription="", [boolean]$collectFiles=$true, [boolean]$Recurse=$true, [boolean]$UpdateDiagProgress=$true, [boolean]$ForceRegExe=$false){
	# To export a Registry Key with subkeys and all values (decimal)
	# This function should call ExportRegKey if ForceRegExe=$false, to export the values in decimal instead of Hex, which is not user friendly.
	TraceOut "Registry Key to Export: $RegKey"

	if ($UpdateDiagProgress) {
		Import-LocalizedData -BindingVariable UtilsCTSStrings
		$RegKeyString = $UtilsCTSStrings.ID_RegistryKeys
		Write-DiagProgress -Activity $UtilsCTSStrings.ID_ExportingRegistryKeys -Status "$RegKeyString $RegKey" -ErrorAction SilentlyContinue
	}
	$sectionDescription = "Registry Keys"

	If (-not (Check-RegKeyExists $RegKey)) {
		TraceOut "    Registry Key does not exist!"
		return
	}

	$ScriptToRun = Join-Path $Pwd.Path "ExportReg.ps1" #-# this is curently not used, as all invocations use -ForceRegExe
	If ($Recurse -eq $true) {
		If ($OSVersion.Major -ge 6 -and -not($ForceRegExe)) {
			$CmdToRun = "Powershell.exe -ExecutionPolicy Bypass $ScriptToRun '$RegKey' `"$OutFile`" -Recurse `$true"  } # if needed, call ExportRegKey()

		Else {
			$CmdToRun = "cmd.exe /c Reg.exe Query `"$RegKey`" /s >> $OutFile" }
	}
	Else {
		If ($OSVersion.Major -ge 6 -and -not($ForceRegExe)) {
			$CmdToRun = "Powershell.exe -ExecutionPolicy Bypass $ScriptToRun '$RegKey' `"$OutFile`" -Recurse `$false" } # if needed, call ExportRegKey()
		Else {
			$CmdToRun = "cmd.exe /c Reg.exe Query `"$RegKey`" >> $OutFile" }
	}

	TraceOut "    Running command: $CmdToRun"
	If ($collectFiles -eq $true) {
		# Background Execution used because recursive parsing of Registry Key and Subkeys takes time
		Runcmd -commandToRun $CmdToRun -fileDescription $fileDescription -sectionDescription $sectionDescription -filesToCollect $OutFile -BackgroundExecution | Out-Null #_#
	}
	Else {
		# Background Execution not used because it's ignored when collectFiles is set to False
		Runcmd -commandToRun $CmdToRun -filesToCollect $OutFile -collectFiles $false -useSystemDiagnosticsObject | Out-Null #_#
	}
	TraceOut "    Registry Key Export Completed for $RegKey."
}

function Get-CertInfo (){
	param(
		$Path
	)

	$Temp = Get-ChildItem $Path -ErrorAction SilentlyContinue

	if (($Temp | Measure-Object).Count -gt 0) {
		$Return = $Temp | Select-Object Subject, Issuer, Thumbprint, HasPrivateKey, NotAfter, NotBefore, FriendlyName | Format-Table -AutoSize | Out-String -Width 1000
	}
	else {
		$Return = "`r`n  None.`r`n`r`n"
	}

	return $Return
}

Function Get-PendingReboot{
	# Taken from https://gallery.technet.microsoft.com/scriptcenter/Get-PendingReboot-Query-bdb79542
	<#
	.SYNOPSIS
		Gets the pending reboot status on a local or remote computer.

	.DESCRIPTION
		This function will query the registry on a local or remote computer and determine if the
		system is pending a reboot, from either Microsoft Patching or a Software Installation.
		For Windows 2008+ the function will query the CBS registry key as another factor in determining
		pending reboot state.  "PendingFileRenameOperations" and "Auto Update\RebootRequired" are observed
		as being consistant across Windows Server 2003 & 2008.

		CBServicing = Component Based Servicing (Windows 2008)
		WindowsUpdate = Windows Update / Auto Update (Windows 2003 / 2008)
		CCMClientSDK = SCCM 2012 Clients only (DetermineIfRebootPending method) otherwise $null value
		PendFileRename = PendingFileRenameOperations (Windows 2003 / 2008)

	.PARAMETER ComputerName
		A single Computer or an array of computer names.  The default is localhost ($env:COMPUTERNAME).

	.PARAMETER ErrorLog
		A single path to send error data to a log file.

	.EXAMPLE
		PS C:\> Get-PendingReboot -ComputerName (Get-Content C:\ServerList.txt) | Format-Table -AutoSize

		Computer CBServicing WindowsUpdate CCMClientSDK PendFileRename PendFileRenVal RebootPending
		-------- ----------- ------------- ------------ -------------- -------------- -------------
		DC01     False   False           False      False
		DC02     False   False           False      False
		FS01     False   False           False      False

		This example will capture the contents of C:\ServerList.txt and query the pending reboot
		information from the systems contained in the file and display the output in a table. The
		null values are by design, since these systems do not have the SCCM 2012 client installed,
		nor was the PendingFileRenameOperations value populated.

	.EXAMPLE
		PS C:\> Get-PendingReboot

		Computer     : WKS01
		CBServicing  : False
		WindowsUpdate      : True
		CCMClient    : False
		PendComputerRename : False
		PendFileRename     : False
		PendFileRenVal     :
		RebootPending      : True

		This example will query the local machine for pending reboot information.

	.EXAMPLE
		PS C:\> $Servers = Get-Content C:\Servers.txt
		PS C:\> Get-PendingReboot -Computer $Servers | Export-Csv C:\PendingRebootReport.csv -NoTypeInformation

		This example will create a report that contains pending reboot information.

	.LINK
		Component-Based Servicing:
		http://technet.microsoft.com/en-us/library/cc756291(v=WS.10).aspx

		PendingFileRename/Auto Update:
		http://support.microsoft.com/kb/2723674
		http://technet.microsoft.com/en-us/library/cc960241.aspx
		http://blogs.msdn.com/b/hansr/archive/2006/02/17/patchreboot.aspx

		SCCM 2012/CCM_ClientSDK:
		http://msdn.microsoft.com/en-us/library/jj902723.aspx

	.NOTES
		Author:  Brian Wilhite
		Email:   bcwilhite (at) live.com
		Date:    29AUG2012
		PSVer:   2.0/3.0/4.0/5.0
		Updated: 01DEC2014
		UpdNote: Added CCMClient property - Used with SCCM 2012 Clients only
		   Added ValueFromPipelineByPropertyName=$true to the ComputerName Parameter
		   Removed $Data variable from the PSObject - it is not needed
		   Bug with the way CCMClientSDK returned null value if it was false
		   Removed unneeded variables
		   Added PendFileRenVal - Contents of the PendingFileRenameOperations Reg Entry
		   Removed .Net Registry connection, replaced with WMI StdRegProv
		   Added ComputerPendingRename
	#>

[CmdletBinding()]
param(
  [Parameter(Position=0,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
  [Alias("CN","Computer")]
  [String[]]$ComputerName="$env:COMPUTERNAME"
  )

Begin {  }## End Begin Script Block
Process {
	TraceOut "Get-PendingReboot: Entered"
	$Computer = $ComputerName

	Try {
		## Setting pending values to false to cut down on the number of else statements
		$CompPendRen,$PendFileRename,$Pending,$SCCM = $false,$false,$false,$false

		## Setting CBSRebootPend to null since not all versions of Windows has this value
		$CBSRebootPend = $null

		## Querying WMI for build version
		$WMI_OS = Get-CimInstance -Class Win32_OperatingSystem -Property BuildNumber, CSName -ComputerName $Computer -ErrorAction Stop

		## Making registry connection to the local/remote computer
		$HKLM = [UInt32] "0x80000002"
		$WMI_Reg = [WMIClass] "\\$Computer\root\default:StdRegProv"

		## If Vista/2008 & Above query the CBS Reg Key
		If ([Int32]$WMI_OS.BuildNumber -ge 6001) {
			$RegSubKeysCBS = $WMI_Reg.EnumKey($HKLM,"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\")
			$CBSRebootPend = $RegSubKeysCBS.sNames -contains "RebootPending"
		}

		## Query WUAU from the registry
		$RegWUAURebootReq = $WMI_Reg.EnumKey($HKLM,"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\")
		$WUAURebootReq = $RegWUAURebootReq.sNames -contains "RebootRequired"

		## Query PendingFileRenameOperations from the registry
		$RegSubKeySM = $WMI_Reg.GetMultiStringValue($HKLM,"SYSTEM\CurrentControlSet\Control\Session Manager\","PendingFileRenameOperations")
		$RegValuePFRO = $RegSubKeySM.sValue

		## Query ComputerName and ActiveComputerName from the registry
		$ActCompNm = $WMI_Reg.GetStringValue($HKLM,"SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName\","ComputerName")
		$CompNm = $WMI_Reg.GetStringValue($HKLM,"SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName\","ComputerName")
		If ($ActCompNm -ne $CompNm) {
			$CompPendRen = $true
		}

		## If PendingFileRenameOperations has a value set $RegValuePFRO variable to $true
		If ($RegValuePFRO) {
			$PendFileRename = $true
		}

		## Determine SCCM 2012 Client Reboot Pending Status
		## To avoid nested 'if' statements and unneeded WMI calls to determine if the CCM_ClientUtilities class exist, setting EA = 0
		$CCMClientSDK = $null
		$CCMSplat = @{
		NameSpace='ROOT\ccm\ClientSDK'
		Class='CCM_ClientUtilities'
		Name='DetermineIfRebootPending'
		ComputerName=$Computer
		ErrorAction='Stop'
		}
		## Try CCMClientSDK
		Try {
			$CCMClientSDK = Invoke-WmiMethod @CCMSplat
		} Catch [System.UnauthorizedAccessException] {
			$CcmStatus = Get-Service -Name CcmExec -ComputerName $Computer -ErrorAction SilentlyContinue
			If ($CcmStatus.Status -ne 'Running') {
			TraceOut "Get-PendingReboot Error - CcmExec service is not running."
			$CCMClientSDK = $null
		}
		} Catch {
			$CCMClientSDK = $null
		}

		If ($CCMClientSDK) {
			If ($CCMClientSDK.ReturnValue -ne 0) {
				TraceOut  "Get-PendingReboot Error: DetermineIfRebootPending returned error code $($CCMClientSDK.ReturnValue)"
			}
			If ($CCMClientSDK.IsHardRebootPending -or $CCMClientSDK.RebootPending) {
				$SCCM = $true
			}
		}

		Else {
			$SCCM = $null
		}

		## Creating Custom PSObject and Select-Object Splat
		$SelectSplat = @{
		Property=(
		'Computer',
		'RebootPending',
		'CBS',
		'WindowsUpdate',
		'CCMClientSDK',
		'PendingComputerRename',
		'PendingFileRenameOperations',
		'PendingFileRenameValue'
		)}

		New-Object -TypeName PSObject -Property @{
		Computer=$WMI_OS.CSName
		RebootPending=($CompPendRen -or $CBSRebootPend -or $WUAURebootReq -or $SCCM -or $PendFileRename)
		CBS=$CBSRebootPend
		WindowsUpdate=$WUAURebootReq
		CCMClientSDK=$SCCM
		PendingComputerRename=$CompPendRen
		PendingFileRenameOperations=$PendFileRename
		PendingFileRenameValue=$RegValuePFRO
		} | Select-Object @SelectSplat
	}
	Catch {
		TraceOut "Get-PendingReboot Error: $_"
	}

	TraceOut "Get-PendingReboot: Exiting."
}## End Process

End {  }## End End
}## End Function Get-PendingReboot

function TraceOut {
	#_# ___ from utils_shared.ps1 in SUVP
	##########################################
	# TraceOut (Taken from Vinay Pamnani)
	#-----------------
	# To standardize Logging to StdOut.log
	##########################################
    param (
		$WhatToWrite
		)
	process
	{
			$SName = ([System.IO.Path]::GetFileName($MyInvocation.ScriptName))
			$SName = $SName.Substring(0, $SName.LastIndexOf("."))
			$SLine = $MyInvocation.ScriptLineNumber.ToString()
			$STime =Get-Date -Format G
			WriteTo-StdOut "$STime [$ComputerName][$SName][$SLine] $WhatToWrite"
	}
}

function global:GetRegValue ($RegKey, $RegValue){
	##########################################
	# GetRegValue -- currently not used
	#-----------------
	# Used to quickly get a registry value
	##########################################
	$bkey=$RegKey -replace "HKLM\\", "HKLM:\"
	$bkey=$bkey -replace "HKCU\\", "HKCU:\"
	$bkey=$bkey -replace "HKU\\", "Registry::HKEY_USERS\"
	return (Get-ItemProperty -path $bkey).$RegValue
}

function global:RegKeyExist ($RegKey){
	##########################################
	# RegKeyExist -- currently not used
	#-----------------
	# Used to quickly check if a regsitry key exist
	##########################################
	$bkey=$RegKey -replace "HKLM\\", "HKLM:\"
	$bkey=$bkey -replace "HKCU\\", "HKCU:\"
	$bkey=$bkey -replace "HKU\\", "Registry::HKEY_USERS\"
	return (Test-Path $bkey)
}

##########################################
# pow
#-----------------
# to calculate powers
##########################################

function global:calcdate ($values){
	##########################################
	# calcdate -- currently not used
	#-----------------
	# to convert the binary date
	##########################################
	$calcvalues=$values -split " "
	
     [int64]$ourSeconds = [int]$calcvalues[7]*[math]::pow(2,56) + [int]$calcvalues[6]*[math]::pow(2,48) + [int]$calcvalues[5]*[math]::pow(2,40) + [int]$calcvalues[4]*[math]::pow(2,32) + [int]$calcvalues[3]*[math]::pow(2,24) + [int]$calcvalues[2]*[math]::pow(2,16) + [int]$calcvalues[1]*[math]::pow(2,8) + [int]$calcvalues[0] 
     [DateTime] $DDate = [DateTime]::FromFileTime($ourSeconds);	
     return $DDate;
}

function DirectoryOutput ($dir, $fDesc, $sDesc){
	##########################################
	# DirectoryOutput
	#-----------------
	# Gets directory output and copies to SDP
	##########################################
	$CommandLineToExecute = "cmd.exe /c dir /s $dir > $OutputFile"
	RunCMD -commandToRun $CommandLineToExecute -filesToCollect $OutputFile -fileDescription $fDesc -sectionDescription $sDesc
}

Function CopyDeploymentFile ($sourceFileName, $destinationFileName, $fileDescription){
	##########################################
	# CopyDeploymentFile
	#-----------------
	# Copies specified file to SDP
	##########################################
	if (test-path $sourceFileName) {
		$sourceFile = Get-Item $sourceFileName
		#copy the file only if it is not a 0KB file.
		if ($sourceFile.Length -gt 0) 
		{
			$CommandLineToExecute = "cmd.exe /c copy `"$sourceFileName`" `"$destinationFileName`""
			"Collecting " + $sourceFileName | WriteTo-StdOut 
			RunCmD -commandToRun $CommandLineToExecute -sectionDescription $sectionDescription -filesToCollect $destinationFileName -fileDescription $fileDescription
		}
	}
}

function query_registry ($key){
	##########################################
	# query_registry
	#-----------------
	# Runs reg.exe to query the registry
	##########################################
	$CommandLineToExecute = "cmd.exe /c reg.exe query $key >> $OutputFile"
	$Header = "Querying Registry: " + $key + ":"
	$Header | Out-File $OutputFile 
	$Header | WriteTo-StdOut 
	RunCMD -commandToRun $CommandLineToExecute
}

function logCmdToExecute(){
	##########################################
	# logCmdToExecute
	#-----------------
	# Logs $CommandLineToExecute
	##########################################
	$CommandLineToExecute | WriteTo-StdOut 
}

function logStart(){
	# Adds start in StdOut
	"Start collecting " + $OutputFile | WriteTo-StdOut 
}

function logStop(){
	# Adds stop in StdOut
	"Stop collecting " + $OutputFile | WriteTo-StdOut 
}

function ExportRegKey{	# -- obsolete
	# this function was previously a separate script ExportReg.ps1 , but it is no more used, as Reg.EXE as it is a LOT quicker than ExportReg.ps1
	PARAM([string]$RegKey, [string]$OutFile, [Boolean]$Recurse=$true)
	Write-Host "Export Reg Started for $RegKey"
	Write-Host "Destination: $OutFile"
	"`r`n" + "-" * ($RegKey.Length + 2) + "`r`n[" + $RegKey + "]`r`n" + "-" * ($RegKey.Length + 2) + "`r`n" | Out-File $OutFile -Append
	$PSRegKey= $RegKey -replace "HKLM\\", "HKLM:\" -replace "HKCU\\", "HKCU:\" -replace "HKU\\", "Registry::HKEY_USERS\"
	If (Test-Path $PSRegKey) {
		Write-Host "Registry Key Exists."
		# Print values from the Key
		$key = Get-Item $PSRegKey
		"[$key]" | Out-File $OutFile -Append
		$values = Get-ItemProperty $key.PSPath
		ForEach ($value in ($key.Property | Sort-Object)) {
			"    " + $value + " = " + $values.$value | Out-File $OutFile -Append				
		}
		If ($Recurse) {
			Write-Host "Recurse = $Recurse"
			# Print values from subkeys
			$SubKeys = Get-ChildItem $PSRegKey -Recurse -ErrorAction SilentlyContinue
			If ($null -ne $SubKeys) {
				Write-Host "SubKeys exist."
				ForEach ($subkey in $SubKeys) {
					$key = Get-Item $subkey.PSPath
					"" | Out-File $OutFile -Append
					"[$key]" | Out-File $OutFile -Append
					$values = Get-ItemProperty $key.PSPath
					ForEach ($value in ($key.Property | Sort-Object)) {
						"    " + $value + " = " + $values.$value | Out-File $OutFile -Append
					}			
				}
			}
			Else {
				Write-Host "No Subkeys Found"
			}
		}
	}	
	Else {
		Write-Host "Registry Key does not Exist!"
		"    Registry Key does not exist" | Out-File $OutFile -Append
	}
	Write-Host "Registry Export Complete."
}


# SIG # Begin signature block
# MIInoQYJKoZIhvcNAQcCoIInkjCCJ44CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAY+EObaeZHxdPj
# HU7GVMUEArKYbkNd87Pv99kFAa9kQaCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
# OfsCcUI2AAAAAALLMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjIwNTEyMjA0NTU5WhcNMjMwNTExMjA0NTU5WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQC3sN0WcdGpGXPZIb5iNfFB0xZ8rnJvYnxD6Uf2BHXglpbTEfoe+mO//oLWkRxA
# wppditsSVOD0oglKbtnh9Wp2DARLcxbGaW4YanOWSB1LyLRpHnnQ5POlh2U5trg4
# 3gQjvlNZlQB3lL+zrPtbNvMA7E0Wkmo+Z6YFnsf7aek+KGzaGboAeFO4uKZjQXY5
# RmMzE70Bwaz7hvA05jDURdRKH0i/1yK96TDuP7JyRFLOvA3UXNWz00R9w7ppMDcN
# lXtrmbPigv3xE9FfpfmJRtiOZQKd73K72Wujmj6/Su3+DBTpOq7NgdntW2lJfX3X
# a6oe4F9Pk9xRhkwHsk7Ju9E/AgMBAAGjggFzMIIBbzAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUrg/nt/gj+BBLd1jZWYhok7v5/w4w
# RQYDVR0RBD4wPKQ6MDgxHjAcBgNVBAsTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEW
# MBQGA1UEBRMNMjMwMDEyKzQ3MDUyODAfBgNVHSMEGDAWgBRIbmTlUAXTgqoXNzci
# tW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3JsMGEG
# CCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3J0
# MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIBAJL5t6pVjIRlQ8j4dAFJ
# ZnMke3rRHeQDOPFxswM47HRvgQa2E1jea2aYiMk1WmdqWnYw1bal4IzRlSVf4czf
# zx2vjOIOiaGllW2ByHkfKApngOzJmAQ8F15xSHPRvNMmvpC3PFLvKMf3y5SyPJxh
# 922TTq0q5epJv1SgZDWlUlHL/Ex1nX8kzBRhHvc6D6F5la+oAO4A3o/ZC05OOgm4
# EJxZP9MqUi5iid2dw4Jg/HvtDpCcLj1GLIhCDaebKegajCJlMhhxnDXrGFLJfX8j
# 7k7LUvrZDsQniJZ3D66K+3SZTLhvwK7dMGVFuUUJUfDifrlCTjKG9mxsPDllfyck
# 4zGnRZv8Jw9RgE1zAghnU14L0vVUNOzi/4bE7wIsiRyIcCcVoXRneBA3n/frLXvd
# jDsbb2lpGu78+s1zbO5N0bhHWq4j5WMutrspBxEhqG2PSBjC5Ypi+jhtfu3+x76N
# mBvsyKuxx9+Hm/ALnlzKxr4KyMR3/z4IRMzA1QyppNk65Ui+jB14g+w4vole33M1
# pVqVckrmSebUkmjnCshCiH12IFgHZF7gRwE4YZrJ7QjxZeoZqHaKsQLRMp653beB
# fHfeva9zJPhBSdVcCW7x9q0c2HVPLJHX9YCUU714I+qtLpDGrdbZxD9mikPqL/To
# /1lDZ0ch8FtePhME7houuoPcMIIHejCCBWKgAwIBAgIKYQ6Q0gAAAAAAAzANBgkq
# hkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5
# IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEwOTA5WjB+MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQg
# Q29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+laUKq4BjgaBEm6f8MMHt03
# a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc6Whe0t+bU7IKLMOv2akr
# rnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4Ddato88tt8zpcoRb0Rrrg
# OGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+lD3v++MrWhAfTVYoonpy
# 4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nkkDstrjNYxbc+/jLTswM9
# sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6A4aN91/w0FK/jJSHvMAh
# dCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmdX4jiJV3TIUs+UsS1Vz8k
# A/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL5zmhD+kjSbwYuER8ReTB
# w3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zdsGbiwZeBe+3W7UvnSSmn
# Eyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3T8HhhUSJxAlMxdSlQy90
# lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS4NaIjAsCAwEAAaOCAe0w
# ggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRIbmTlUAXTgqoXNzcitW2o
# ynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYD
# VR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBDuRQFTuHqp8cx0SOJNDBa
# BgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2Ny
# bC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3JsMF4GCCsG
# AQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3J0MIGfBgNV
# HSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEFBQcCARYzaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1hcnljcHMuaHRtMEAGCCsG
# AQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkAYwB5AF8AcwB0AGEAdABl
# AG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn8oalmOBUeRou09h0ZyKb
# C5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7v0epo/Np22O/IjWll11l
# hJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0bpdS1HXeUOeLpZMlEPXh6
# I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/KmtYSWMfCWluWpiW5IP0
# wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvyCInWH8MyGOLwxS3OW560
# STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBpmLJZiWhub6e3dMNABQam
# ASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJihsMdYzaXht/a8/jyFqGa
# J+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYbBL7fQccOKO7eZS/sl/ah
# XJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbSoqKfenoi+kiVH6v7RyOA
# 9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sLgOppO6/8MO0ETI7f33Vt
# Y5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtXcVZOSEXAQsmbdlsKgEhr
# /Xmfwb1tbWrJUnMTDXpQzTGCGYEwghl9AgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIOZm0TSKUx+VusTDOzeMNr+V
# NleKnBEPYZYK98Dj4LNDMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQBnxJHY9w3flx46Su+2XCAjjrQ8pFoovE4lElMiswBQXWJXWhm13tUI
# ojcgUP6+RXRoVmpqkwC78+hMJZeYVinONVXBIHUYDV3A+wGFp6aCxgfrQbnrmCnI
# GQnToJ0bxoqqETMXkvVVXplA9HrTxNgqgboqsjmZKolTjoU/Hp0H19FOIqvR+ulC
# 444SdbhA9MBYqfSZrBbW1qJIoIlj4G1MW6orjcCGi45huAUWhPG8q2FNZcih/FHH
# s1fekyvUy/YY31GzN+IqTmd9HI4PQkcYIB+st61jB7RdDBKPT8YGvkRCtEdIDzPQ
# MrY7+VfJp9cHqOz3RPkkL+qB2a6l1zByoYIXCTCCFwUGCisGAQQBgjcDAwExghb1
# MIIW8QYJKoZIhvcNAQcCoIIW4jCCFt4CAQMxDzANBglghkgBZQMEAgEFADCCAVUG
# CyqGSIb3DQEJEAEEoIIBRASCAUAwggE8AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIBTafD/gZXLLL6pIrd5AIUMOqimEOqqg5ZL40ePs3ptvAgZi2xAP
# lWIYEzIwMjIwODAxMDgxNTIzLjUwM1owBIACAfSggdSkgdEwgc4xCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1pY3Jvc29mdCBP
# cGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo4
# OTdBLUUzNTYtMTcwMTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2Vy
# dmljZaCCEVwwggcQMIIE+KADAgECAhMzAAABqwkJ76tj1OipAAEAAAGrMA0GCSqG
# SIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# JjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIyMDMw
# MjE4NTEyOFoXDTIzMDUxMTE4NTEyOFowgc4xCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo4OTdBLUUzNTYtMTcw
# MTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCCAiIwDQYJ
# KoZIhvcNAQEBBQADggIPADCCAgoCggIBAMmdS1o5dehASUsscLqyx2wm/WirNUfq
# kGBymDItYzEnoKtkhrd7wNsJs4g+BuM3uBX81WnO270lkrC0e1mmDqQt420Tmb8l
# wsjQKM6mEaNQIfXDronrVN3aw1lx9bAf7VZEA3kHFql6YAO3kjQ6PftA4iVHX3JV
# v98ntjkbtqzKeJMaNWd8dBaAD3RCliMoajTDGbyYNKTvxBhWILyJ8WYdJ/NBDpqP
# zQl+pxm6ZZVSeBQAIOubZjU0vfpECxHC5vI1ErrqapG+0oBhhON+gllVklPAWZv2
# iv0mgjCTj7YNKX7yL2x2TvrvHVq5GPNa5fNbpy39t5cviiYqMf1RZVZccdr+2vAp
# k5ib5a4O8SiAgPSUwYGoOwbZG1onHij0ATPLkgKUfgaPzFfd5JZSbRl2Xg347/Lj
# WQLR+KjAyACFb06bqWzvHtQJTND8Y0j5Y2SBnSCqV2zNHSVts4+aUfkUhsKS+GAX
# S3j5XUgYA7SMNog76Nnss5l01nEX7sHDdYykYhzuQKFrT70XVTZeX25tSBfy3Vac
# zYd1JSI/9wOGqbFU52NyrlsA1qimxOhsuds7Pxo+jO3RjV/kC+AEOoVaXDdminsc
# 3PtlBCVh/sgYno9AUymblSRmee1gwlnlZJ0uiHKI9q2HFgZWM10yPG5gVt0prXnJ
# Fi1Wxmmg+BH/AgMBAAGjggE2MIIBMjAdBgNVHQ4EFgQUFFvO8o1eNcSCIQZMvqGf
# dNL+pqowHwYDVR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXwYDVR0fBFgw
# VjBUoFKgUIZOaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWlj
# cm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3JsMGwGCCsGAQUF
# BwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3Br
# aW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgx
# KS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDCDANBgkqhkiG
# 9w0BAQsFAAOCAgEAykuUgTc1KMszMgsHbhgjgEGv/dCHFf0by99C45SR770/udCN
# NeqlT610Ehz13xGFU6Hci+TLUPUnhvUnSuz7xkiWRru5RjZZmSonEVv8npa3z1Qv
# eUfngtyi0Jd6qlSykoEVJ6tDuR1Kw9xU9yvthZWhQs/ymyOwh+mxt0C9wbeLJ92e
# r2vc9ly12pFxbCNDJ+mQ7v520hAvreWqZ02GOJhw0R4c1iP39iNBzHOoz+DsO0sY
# jwhaz9HrvYMEzOD1MJdLPWfUFsZ//iTd3jzEykk02WjnZNzIe2ENfmQ/KblGXHeS
# e8JYqimTFxl5keMfLUELjAh0mhQ1vLCJZ20BwC4O57Eg7yO/YuBno+4RrV0CD2gp
# 4BO10KFW2SQ/MhvRWK7HbgS6Bzt70rkIeSUto7pRkHMqrnhubITcXddky6GtZsmw
# M3hvqXuStMeU1W5NN3HA8ypjPLd/bomfGx96Huw8OrftcQvk7thdNu4JhAyKUXUP
# 7dKMCJfrOdplg0j1tE0aiE+pDTSQVmPzGezCL42slyPJVXpu4xxE0hpACr2ua0LH
# v/LB6RV5C4CO4Ms/pfal//F3O+hJZe5ixevzKNkXXbxPOa1R+SIrW/rHZM6RIDLT
# JxTGFDM1hQDyafGu9S/a7umkvilgBHNxZfk0IYE7RRWJcG7oiY+FGdx1cs0wggdx
# MIIFWaADAgECAhMzAAAAFcXna54Cm0mZAAAAAAAVMA0GCSqGSIb3DQEBCwUAMIGI
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylN
# aWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0yMTA5
# MzAxODIyMjVaFw0zMDA5MzAxODMyMjVaMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBD
# QSAyMDEwMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA5OGmTOe0ciEL
# eaLL1yR5vQ7VgtP97pwHB9KpbE51yMo1V/YBf2xK4OK9uT4XYDP/XE/HZveVU3Fa
# 4n5KWv64NmeFRiMMtY0Tz3cywBAY6GB9alKDRLemjkZrBxTzxXb1hlDcwUTIcVxR
# MTegCjhuje3XD9gmU3w5YQJ6xKr9cmmvHaus9ja+NSZk2pg7uhp7M62AW36MEByd
# Uv626GIl3GoPz130/o5Tz9bshVZN7928jaTjkY+yOSxRnOlwaQ3KNi1wjjHINSi9
# 47SHJMPgyY9+tVSP3PoFVZhtaDuaRr3tpK56KTesy+uDRedGbsoy1cCGMFxPLOJi
# ss254o2I5JasAUq7vnGpF1tnYN74kpEeHT39IM9zfUGaRnXNxF803RKJ1v2lIH1+
# /NmeRd+2ci/bfV+AutuqfjbsNkz2K26oElHovwUDo9Fzpk03dJQcNIIP8BDyt0cY
# 7afomXw/TNuvXsLz1dhzPUNOwTM5TI4CvEJoLhDqhFFG4tG9ahhaYQFzymeiXtco
# dgLiMxhy16cg8ML6EgrXY28MyTZki1ugpoMhXV8wdJGUlNi5UPkLiWHzNgY1GIRH
# 29wb0f2y1BzFa/ZcUlFdEtsluq9QBXpsxREdcu+N+VLEhReTwDwV2xo3xwgVGD94
# q0W29R6HXtqPnhZyacaue7e3PmriLq0CAwEAAaOCAd0wggHZMBIGCSsGAQQBgjcV
# AQQFAgMBAAEwIwYJKwYBBAGCNxUCBBYEFCqnUv5kxJq+gpE8RjUpzxD/LwTuMB0G
# A1UdDgQWBBSfpxVdAF5iXYP05dJlpxtTNRnpcjBcBgNVHSAEVTBTMFEGDCsGAQQB
# gjdMg30BATBBMD8GCCsGAQUFBwIBFjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20v
# cGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5odG0wEwYDVR0lBAwwCgYIKwYBBQUHAwgw
# GQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB
# /wQFMAMBAf8wHwYDVR0jBBgwFoAU1fZWy4/oolxiaNE9lJBb186aGMQwVgYDVR0f
# BE8wTTBLoEmgR4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJv
# ZHVjdHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3JsMFoGCCsGAQUFBwEBBE4w
# TDBKBggrBgEFBQcwAoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0
# cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcnQwDQYJKoZIhvcNAQELBQADggIB
# AJ1VffwqreEsH2cBMSRb4Z5yS/ypb+pcFLY+TkdkeLEGk5c9MTO1OdfCcTY/2mRs
# fNB1OW27DzHkwo/7bNGhlBgi7ulmZzpTTd2YurYeeNg2LpypglYAA7AFvonoaeC6
# Ce5732pvvinLbtg/SHUB2RjebYIM9W0jVOR4U3UkV7ndn/OOPcbzaN9l9qRWqveV
# tihVJ9AkvUCgvxm2EhIRXT0n4ECWOKz3+SmJw7wXsFSFQrP8DJ6LGYnn8AtqgcKB
# GUIZUnWKNsIdw2FzLixre24/LAl4FOmRsqlb30mjdAy87JGA0j3mSj5mO0+7hvoy
# GtmW9I/2kQH2zsZ0/fZMcm8Qq3UwxTSwethQ/gpY3UA8x1RtnWN0SCyxTkctwRQE
# cb9k+SS+c23Kjgm9swFXSVRk2XPXfx5bRAGOWhmRaw2fpCjcZxkoJLo4S5pu+yFU
# a2pFEUep8beuyOiJXk+d0tBMdrVXVAmxaQFEfnyhYWxz/gq77EFmPWn9y8FBSX5+
# k77L+DvktxW/tM4+pTFRhLy/AsGConsXHRWJjXD+57XQKBqJC4822rpM+Zv/Cuk0
# +CQ1ZyvgDbjmjJnW4SLq8CdCPSWU5nR0W2rRnj7tfqAxM328y+l7vzhwRNGQ8cir
# Ooo6CGJ/2XBjU02N7oJtpQUQwXEGahC0HVUzWLOhcGbyoYICzzCCAjgCAQEwgfyh
# gdSkgdEwgc4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAn
# BgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQL
# Ex1UaGFsZXMgVFNTIEVTTjo4OTdBLUUzNTYtMTcwMTElMCMGA1UEAxMcTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAW6h6/24WCo7W
# Zz6CEVAeLztcmD6ggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAx
# MDANBgkqhkiG9w0BAQUFAAIFAOaRa9gwIhgPMjAyMjA4MDEwMTAwMDhaGA8yMDIy
# MDgwMjAxMDAwOFowdDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA5pFr2AIBADAHAgEA
# AgIG1DAHAgEAAgIRNzAKAgUA5pK9WAIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgor
# BgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUA
# A4GBAAEU+pL+fVXcuqgydyRS2xu0KXbaAiTD3MltCnjkn3ekNvFgcP+4OrTJe4DA
# punTRCb4bvJrYifK/egPCUPI67+Obaj9M50cuVtH9NzEUFs8QheQObEU6tG04X/B
# v0cqzEG3yZKdp0O0h1k6MMtIrIccKN3JPMbdFmEHAeb7w1TAMYIEDTCCBAkCAQEw
# gZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcT
# B1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UE
# AxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGrCQnvq2PU6KkA
# AQAAAaswDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0B
# CRABBDAvBgkqhkiG9w0BCQQxIgQgJKgrdAO71U6HxkqaDyuj/vFDEZH9UbuuA6VX
# /poLunkwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCAOHK/6sIVgEVSVD3Ar
# vk6OyQKvRxFHKyraUzbN1/AKVzCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFBDQSAyMDEwAhMzAAABqwkJ76tj1OipAAEAAAGrMCIEIHI+RQKHTZ2Id7/ufvKq
# /DQk+dqQy1YkmvsPNzOkpL0iMA0GCSqGSIb3DQEBCwUABIICADM/RAjPBIa71Cme
# 4An8uGmcPX4eHQy0wNXkAsTtzBbnhpU/ksIyaYZPmXSzJn2sMiW5KPjIZIng3/Yz
# D1gAQh3Y7b+0bLGGiNWEIpD5yAcYOBIYoqJhuSGvDM2rnPOtdkw5Aqvkz0fWa7oX
# UwOkZKxwD0ZLuI/kifaQ/6MCqZ23gPZkH1FOqOP3xN2D/Ib20rwom/jDA93ge/22
# Q0S0wuDVZ0tJl6//R4vbfEYxwYLC01wMowBNHYVNHkcnh4x/KpPMfVKA58gD8kCm
# Ic5cSPA/AoOVA8xTKQVUM0yA+ehe/dQ1ZhrKoKpaim92iZFribEP2cwZY9Fw4yiW
# LmIRMfyn/EYyp41cFH4wHFjnES13V8B4Xg64twxD555eUU+SEKD4FHLhHXGibr/b
# 2cmJwB5Rlg1qKf17GAeHuPMAyj2PcIomgm9csCV4j4wFbk/QvmTFz1W2mdwFdsgI
# DVWBcJNY2o4sik1BgFQEKlz2gWuaWeg3WWgjTp4jQdaW9iIMNns3nTXgJktjH6MT
# 2PcmfM4dYztZvJxnIpMV2u3Dhm9Nw1C2kXcKHjffZNH9eOd+H3tTBU1tYSvtIprb
# yls7PJQ5QcYwjoNNLPu+8KgREjpwgene8x5o5dYWM2wsQRk7bwKvxzkMjZq9vBu2
# ejqZusVrl8VZmaWLS/tEiLVThieX
# SIG # End signature block
