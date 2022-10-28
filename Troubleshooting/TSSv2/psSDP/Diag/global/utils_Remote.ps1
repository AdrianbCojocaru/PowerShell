#************************************************
# utils_Remote.ps1
# Version 2.0.4
# Date: 10-18-2010
# Author: Andre Teixeira - andret@microsoft.com
# Description: This script is a Replacement Windows Troubleshooting Platform cmdlets and utils_cts.ps1 functions on Remote Machine to allow running WTP scripts using PowerShell.exe on a remote machine
#************************************************

$ErrorActionPreference = "Continue"

$ScriptExecutionInfo_Summary = New-Object PSObject

$OutputFolder = $PWD.Path + "\Output"

$xmlUpdateDiagRootCause = [xml] "<?xml version=""1.0"" encoding=""UTF-8""?><Root/>"
$xmlGetDiagInput = [xml] "<?xml version=""1.0"" encoding=""UTF-8""?><Root/>"


if( $Host -and $Host.UI -and $Host.UI.RawUI ) { 
  $rawUI = $Host.UI.RawUI 
  $oldSize = $rawUI.BufferSize 
  $typeName = $oldSize.GetType( ).FullName 
  $newSize = New-Object $typeName (500, $oldSize.Height) 
#  $rawUI.BufferSize = $newSize 
} 

#_#
function FirstTimeExecution()
{
	return $true
}

function SkipSecondExecution()
{

}

Function Run-DiagExpression{
	$ScriptTimeStarted = Get-Date
    $line = [string]::join(" ", $MyInvocation.Line.Trim().Split(" ")[1..($MyInvocation.Line.Trim().Split(" ").Count)])
	"`n[" + $Computername + "] Running " + $line + ":`n----------------------------------------------`n"
	Invoke-Expression $line -ErrorAction Continue
	if ($null -ne $ScriptExecutionInfo_Summary.$line) {
		$X = 1
		$memberExist = $true
		do {
			if ($null -eq $ScriptExecutionInfo_Summary.($line + " [$X]")) {
				$memberExist = $false
				$line += " [$X]"
			}
			$X += 1
		} while ($memberExist)
	}
    add-member -inputobject $ScriptExecutionInfo_Summary -membertype noteproperty -name $line -value (GetAgeDescription(New-TimeSpan $ScriptTimeStarted))
}


Function UtilsAddXMLElement ([string] $ElementName="Item", 
						[string] $Value,
						[string] $AttributeName="Name", 
						[string] $AttributeValue,
						[string] $xpath="/Root",
						[xml] $XMLDoc)
{
	[System.Xml.XmlElement] $rootElement=$xmlDoc.SelectNodes($xpath).Item(0)
	if ($null -ne $rootElement) {
		[System.Xml.XmlElement] $element = $xmlDoc.CreateElement($ElementName)
		if ($attributeValue -ne $null) {$element.SetAttribute($AttributeName, $attributeValue)}
		if ($Value -ne $null) { 
			if ($Host.Version.Major -gt 1) { #PowerShell 2.0
				$element.innerXML = $Value
			} else {
				$element.set_InnerXml($Value)
			}
		}
		$x = $rootElement.AppendChild($element)
	} else {
		"UtilsAddXMLElement: Error: Path $xpath returned a null value. Current XML document: `n" + $xmlDoc.get_OuterXml() | WriteTo-StdOut
		"               ElementName = $ElementName`n               Value: $Value`n               AttributeName: $AttributeName`n               AttributeValue: $AttributeValue" | WriteTo-StdOut
	}
}

Function UtilsAddXMLAttribute([string] $AttributeName, 
						[string] $AttributeValue,
						[string] $xpath="",
						[xml] $XMLDoc)
{
	[System.Xml.XmlElement] $rootElement=$xmlDoc.SelectNodes($xpath).Item(0)
	if ($null -ne $rootElement) {
		$rootElement.SetAttribute($AttributeName, $attributeValue)
	} else {
		"Error. Path $xpath returned a null value. Current XML document: `n" + $xmlDoc.get_OuterXml()
	}
}

Function Write-DiagProgress ($Activity, $Status)
{
	trap [Exception] 
	{
		#Ignore any error like - when the file is locked
		continue
	}
	
	#On ServerCore, $Activity go to WriteDiagProgress.txt. Discart $status
	if ($null -ne $Activity) 
	{
		$Activity + ": " + $Status | Out-File ($OutputFolder + "\WriteDiagProgress.txt") -Encoding "UTF8" -ErrorAction Continue
		"   Write-DiagProgress: " + $Activity + ": " + $Status
	} else {
	 ""	| Out-File ($OutputFolder + "\WriteDiagProgress.txt") -Encoding "UTF8"
	}
}

Function Update-DiagRootCause
{
	Param ([string] $Id,
			[boolean] $Detected,
			[Collections.Hashtable] $Parameter)
	
	#Check if a Root cause was detected previously:
	$RootCauseAlreadyDetected = $xmlUpdateDiagRootCause.SelectSingleNode("//Item[ID = '$Id']")
	if ($RootCauseAlreadyDetected -ne $null)
	{
		#Root Cause was detected previously. Delete the existing occurence. Consider the last occurence only
		$null = $RootCauseAlreadyDetected.RemoveAll()
	}
	
	$itemID = "Item" + (Get-Random)
	UtilsAddXMLElement -ElementName "Item" -AttributeName "Name" -attributeValue $itemID -XMLDoc $xmlUpdateDiagRootCause
	UtilsAddXMLElement -ElementName "ID" -Value $Id -xpath "/Root/Item[@Name = '$itemID']" -XMLDoc $xmlUpdateDiagRootCause
	
	if ($Detected -eq $true)
	{
		$DetectedText = "True"
	} else {
		$DetectedText = "False"
	}	
	UtilsAddXMLElement -ElementName "Detected" -Value $DetectedText -xpath "/Root/Item[@Name = '$itemID']" -XMLDoc $xmlUpdateDiagRootCause
	
	if ($Parameter -ne $null)
	{
		UtilsAddXMLElement -ElementName "Parameters" -Value "" -xpath "/Root/Item[@Name = '$itemID']" -XMLDoc $xmlUpdateDiagRootCause
		
		foreach ($Key in $Parameter.Keys)
		{
			UtilsAddXMLElement -ElementName $Key -Value ($Parameter.get_Item($Key)) -xpath "/Root/Item[@Name = '$itemID']/Parameters" -XMLDoc $xmlUpdateDiagRootCause
		}
	}
	
	$xmlUpdateDiagRootCause.Save($OutputFolder + "\UpdateDiagRootCause.xml")
}

Function Get-DiagInput
{
	Param ([string] $Id,
			[Collections.Hashtable] $Parameter,
			[Collections.Hashtable[]] $Choice)
	
    trap {
		"ERROR: While processing Get-DiagInput ($ID): " + $_.Exception.Message + "`r`n" + $_.Exception.ErrorRecord.InvocationInfo.PositionMessage | Out-Host
		return $null
		continue
    }

	
	$itemID = "Item" + (Get-Random)
	UtilsAddXMLElement -ElementName "Item" -AttributeName "Name" -attributeValue $itemID -XMLDoc $xmlGetDiagInput
	UtilsAddXMLElement -ElementName "ID" -Value $Id -xpath "/Root/Item[@Name = '$itemID']" -XMLDoc $xmlGetDiagInput

	if ($Parameter -ne $null)
	{
		UtilsAddXMLElement -ElementName "Parameters" -Value "" -xpath "/Root/Item[@Name = '$itemID']" -XMLDoc $xmlGetDiagInput
		
		foreach ($Key in $Parameter.Keys)
		{
			UtilsAddXMLElement -ElementName "Parameter" -Value ($Parameter.get_Item($Key))  -AttributeName "Name" -AttributeValue $Key -xpath "/Root/Item[@Name = '$itemID']/Parameters" -XMLDoc $xmlGetDiagInput
		}
	}

	if (($null -ne $Choice) -and ($Choice.Count -ne 0))
	{
		$Choice | Export-Clixml -Path ($OutputFolder + "\Choices.xml")
		UtilsAddXMLElement -ElementName "Choices" -Value ($OutputFolder + "\Choices.xml") -xpath "/Root/Item[@Name = '$itemID']" -XMLDoc $xmlGetDiagInput
	}
	
	$xmlGetDiagInput.Save($OutputFolder + "\GetDiagInput.xml")
	
	#Wait for an answer from the source machine:
	$Now = Get-Date
	
	"[$Now] Waiting for answer from Get-DiagInput [$Id]" | Out-Host
	
	while (-not (Test-Path ($OutputFolder + "\GetDiagInputResponse.xml")))
	{
		Start-Sleep -Seconds 1
	}
	
	$Now = Get-Date
	"[$Now] Finished waiting for a response" | Out-Host
	
	"`r`n Before: "| Out-Host
	$xmlGetDiagInput.InnerXml | Out-Host
	
	#Reset $xmlGetDiagInput:
	$script:xmlGetDiagInput = [xml] "<?xml version=""1.0"" encoding=""UTF-8""?><Root/>"
	
	"`r`n After: "| Out-Host
	$xmlGetDiagInput.InnerXml | Out-Host
	
	$GetDiagInputAnswer = Import-Clixml -Path ($OutputFolder + "\GetDiagInputResponse.xml")
	Remove-Item ($OutputFolder + "\GetDiagInputResponse.xml")
	
	return $GetDiagInputAnswer

}


Filter Update-DiagReport
{
Param ([xml]$xml, 
		[string] $Id,
		[string] $Name,
		[string] $File,
		[string] $Verbosity = "Informational")
	
	if ($xml -eq $null) {$xml=$_}
	
	$itemID = "Item" + (Get-Random)
	$UpdateDiagReportXMLFilePath = $OutputFolder + "\UpdateDiagReport.xml"
	
	if (Test-Path $UpdateDiagReportXMLFilePath) 
	{
		[xml] $xmlUpdateDiagReport = Get-Content $UpdateDiagReportXMLFilePath
	} else {
		$xmlUpdateDiagReport = [xml] "<?xml version=""1.0"" encoding=""UTF-8""?><Root/>"
	}

	UtilsAddXMLElement -ElementName "Item" -AttributeName "Name" -attributeValue $itemID -XMLDoc $xmlUpdateDiagReport
	
	if ($null -eq $xml) 
	{
		$Type = "File"
	} else {
		$Type = "XML"
	}
	
	UtilsAddXMLAttribute -AttributeName "Type" -attributeValue $Type -xpath "/Root/Item[@Name = '$itemID']"  -XMLDoc $xmlUpdateDiagReport
	
	#Automatically add Computer Name in the Section Header so names won't conflict in the report
	if (($Type -eq "XML") -and ($Name.Contains($ComputerName) -eq $false))
	{
		$Name = $ComputerName + " - " + $Name 
	}
	
	if ($null -ne $RootCauseID)
	{
		$RootCause = $RootCauseID
	}
	else 
	{
		$RootCause = ""
	}
	
	UtilsAddXMLAttribute -AttributeName "ScriptName" -attributeValue ([System.IO.Path]::GetFileName($MyInvocation.ScriptName)) -xpath "/Root/Item[@Name = '$itemID']" -XMLDoc $xmlUpdateDiagReport
	UtilsAddXMLAttribute -AttributeName "RootCauseID" -attributeValue $RootCause -xpath "/Root/Item[@Name = '$itemID']" -XMLDoc $xmlUpdateDiagReport
	UtilsAddXMLElement -ElementName "ID" -Value $Id -xpath "/Root/Item[@Name = '$itemID']"  -XMLDoc $xmlUpdateDiagReport
	UtilsAddXMLElement -ElementName "Name" -Value $Name -xpath "/Root/Item[@Name = '$itemID']"  -XMLDoc $xmlUpdateDiagReport
	UtilsAddXMLElement -ElementName "Verbosity" -Value $Verbosity -xpath "/Root/Item[@Name = '$itemID']"  -XMLDoc $xmlUpdateDiagReport
	
	if ($null -ne $xml) 
	{
		#UtilsAddXMLElement -ElementName "XML" -Value ($xml.InnerXML) -xpath "/Root/Item[@Name = '$itemID']"
		$XMLContent = $null
		if ($null -ne $xml.get_ChildNodes().get_ItemOf(1)) 
		{
			$XMLContent = $xml.get_ChildNodes().get_ItemOf(1).get_OuterXml()
		} else {
			$XMLContent = $xml.get_ChildNodes().get_ItemOf(0).get_OuterXml()
		}
		
		UtilsAddXMLElement -ElementName "XML" -Value $XMLContent -xpath "/Root/Item[@Name = '$itemID']" -XMLDoc $xmlUpdateDiagReport
	} else {
		if (Test-Path ($File)) 
		{
			$FileFolder = [System.IO.Path]::GetDirectoryName($File)
			if (($FileFolder -ne $PWD.Path) -and ($FileFolder.Length -ne 0))
			{
				#File is not located on current folder. Copy file to current folder and remove local path				
				Copy-Item -Path $File -Destination $PWD.Path
			}
			$File = [System.IO.Path]::GetFileName($File)
			UtilsAddXMLElement -ElementName "File" -Value $File -xpath "/Root/Item[@Name = '$itemID']" -XMLDoc $xmlUpdateDiagReport
		} else {
			"[Utils_Remote] Update-DiagReport Error: $File does not exist"
		}
	}

	$xmlUpdateDiagReport.Save($UpdateDiagReportXMLFilePath)
}


# SIG # Begin signature block
# MIInmAYJKoZIhvcNAQcCoIIniTCCJ4UCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCjMcJ9Hg4dlaWv
# qp16qgAqwn+FFupHZDTZZ033T5pC+qCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGXgwghl0AgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIBPl5aXXYihMr9oo1DS+lI0v
# Um76Wf9Rhg44KqS0OYS7MEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQCjDPRBlerMTWX//wW9QC7YsACh20nM9BIihnh23X2cjMzhneOvx4S5
# UXoDMjMDPypyCkgSqXNqNWQGASLHvQDxZMJpZLp7L8hnfMiU3eRk5yQk3ov8T5Lw
# erOKPbZhOCIPVRm3SUwgoKVpyOgmq3JTzYG0vqKaY2V45EfZJmsb3zmikmD6ELuI
# H9ECfnVfMRchc5gg9KhnlfxeMGYgPqBk8n127EzZX+w5aJnGETl0+igC9cBCxQOw
# s5I6F3tg69GFxdieByDJBZm9mm0i4ASijJ2fH6dQ5iTnuKiVLHgOi1sqriTpsGTt
# naA1DVkkx4vuE0OZpQnYB+JruAKjfP8boYIXADCCFvwGCisGAQQBgjcDAwExghbs
# MIIW6AYJKoZIhvcNAQcCoIIW2TCCFtUCAQMxDzANBglghkgBZQMEAgEFADCCAVEG
# CyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIEalcatYCOF6QzIeIlFd6dPByEShW/8iWcA/liz5Hy0JAgZi0AB1
# Pp8YEzIwMjIwODAxMDgxNTE1LjYyMlowBIACAfSggdCkgc0wgcoxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBB
# bWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjNCQkQt
# RTMzOC1FOUExMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# oIIRVzCCBwwwggT0oAMCAQICEzMAAAGd/onl+Xu7TMAAAQAAAZ0wDQYJKoZIhvcN
# AQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjExMjAyMTkw
# NTE5WhcNMjMwMjI4MTkwNTE5WjCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9u
# czEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046M0JCRC1FMzM4LUU5QTExJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQDgEWh60BxJFuR+mlFuFCtG3mR2XHNCfPMTXcp06Yew
# AtS1bbGzK7hDC1JRMethcmiKM/ebdCcG6v6k4lQyLlSaHmHkIUC5pNEtlutzpsVN
# +jo+Nbdyu9w0BMh4KzfduLdxbda1VztKDSXjE3eEl5Of+5hY3pHoJX9Nh/5r4tc4
# Nvqt9tvVcYeIxpchZ81AK3+UzpA+hcR6HS67XA8+cQUB1fGyRoVh1sCu0+ofdVDc
# WOG/tcSKtJch+eRAVDe7IRm84fPsPTFz2dIJRJA/PUaZR+3xW4Fd1ZbLNa/wMbq3
# vaYtKogaSZiiCyUxU7mwoA32iyTcGHC7hH8MgZWVOEBu7CfNvMyrsR8Quvu3m91D
# qsc5gZHMxvgeAO9LLiaaU+klYmFWQvLXpilS1iDXb/82+TjwGtxEnc8x/EvLkk7U
# kj4uKZ6J8ynlgPhPRqejcoKlHsKgxWmD3wzEXW1a09d1L2Io004w01i31QAMB/GL
# hgmmMIE5Z4VI2Jlh9sX2nkyh5QOnYOznECk4za9cIdMKP+sde2nhvvcSdrGXQ8fW
# O/+N1mjT0SIkX41XZjm+QMGR03ta63pfsj3g3E5a1r0o9aHgcuphW0lwrbBA/TGM
# o5zC8Z5WI+Rwpr0MAiDZGy5h2+uMx/2+/F4ZiyKauKXqd7rIl1seAYQYxKQ4SemB
# 0QIDAQABo4IBNjCCATIwHQYDVR0OBBYEFNbfEI3hKujMnF4Rgdvay4rZG1XkMB8G
# A1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCG
# Tmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUy
# MFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4w
# XAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2Vy
# dHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwG
# A1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQAD
# ggIBAIbHcpxLt2h0LNJ334iCNZYsta2Eant9JUeipwebFIwQMij7SIQ83iJ4Y4OL
# 5YwlppwvF516AhcHevYMScY6NAXSAGhp5xYtkEckeV6gNbcp3C4I3yotWvDd9KQC
# h7LdIhpiYCde0SF4N5JRZUHXIMczvNhe8+dEuiCnS1sWiGPUFzNJfsAcNs1aBkHI
# taSxM0AVHgZfgK8R2ihVktirxwYG0T9o1h0BkRJ3PfuJF+nOjt1+eFYYgq+bOLQs
# /SdgY4DbUVfrtLdEg2TbS+siZw4dqzM+tLdye5XGyJlKBX7aIs4xf1Hh1ymMX24Y
# Jlm8vyX+W4x8yytPmziNHtshxf7lKd1Pm7t+7UUzi8QBhby0vYrfrnoW1Kws+z34
# uoc2+D2VFxrH39xq/8KbeeBpuL5++CipoZQsd5QO5Ni81nBlwi/71JsZDEomso/k
# 4JioyvVAM2818CgnsNJnMZZSxM5kyeRdYh9IbjGdPddPVcv0kPKrNalPtRO4ih0G
# VkL/a4BfEBtXDeEUIsM4A00QehD+ESV3I0UbW+b4NTmbRcjnVFk5t6nuK/FoFQc5
# N4XueYAOw2mMDhAoFE+2xtTHk2ewd9xGkbFDl2b6u/FbhsUb5+XoP0PdJ3FTNP6G
# /7Vr4sIOxar4PpY674aQCiMSywwtIWOoqRS/OP/rSjF9E/xfMIIHcTCCBVmgAwIB
# AgITMwAAABXF52ueAptJmQAAAAAAFTANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0
# IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTAwHhcNMjEwOTMwMTgyMjI1
# WhcNMzAwOTMwMTgzMjI1WjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDCC
# AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAOThpkzntHIhC3miy9ckeb0O
# 1YLT/e6cBwfSqWxOdcjKNVf2AX9sSuDivbk+F2Az/1xPx2b3lVNxWuJ+Slr+uDZn
# hUYjDLWNE893MsAQGOhgfWpSg0S3po5GawcU88V29YZQ3MFEyHFcUTE3oAo4bo3t
# 1w/YJlN8OWECesSq/XJprx2rrPY2vjUmZNqYO7oaezOtgFt+jBAcnVL+tuhiJdxq
# D89d9P6OU8/W7IVWTe/dvI2k45GPsjksUZzpcGkNyjYtcI4xyDUoveO0hyTD4MmP
# frVUj9z6BVWYbWg7mka97aSueik3rMvrg0XnRm7KMtXAhjBcTyziYrLNueKNiOSW
# rAFKu75xqRdbZ2De+JKRHh09/SDPc31BmkZ1zcRfNN0Sidb9pSB9fvzZnkXftnIv
# 231fgLrbqn427DZM9ituqBJR6L8FA6PRc6ZNN3SUHDSCD/AQ8rdHGO2n6Jl8P0zb
# r17C89XYcz1DTsEzOUyOArxCaC4Q6oRRRuLRvWoYWmEBc8pnol7XKHYC4jMYcten
# IPDC+hIK12NvDMk2ZItboKaDIV1fMHSRlJTYuVD5C4lh8zYGNRiER9vcG9H9stQc
# xWv2XFJRXRLbJbqvUAV6bMURHXLvjflSxIUXk8A8FdsaN8cIFRg/eKtFtvUeh17a
# j54WcmnGrnu3tz5q4i6tAgMBAAGjggHdMIIB2TASBgkrBgEEAYI3FQEEBQIDAQAB
# MCMGCSsGAQQBgjcVAgQWBBQqp1L+ZMSavoKRPEY1Kc8Q/y8E7jAdBgNVHQ4EFgQU
# n6cVXQBeYl2D9OXSZacbUzUZ6XIwXAYDVR0gBFUwUzBRBgwrBgEEAYI3TIN9AQEw
# QTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9E
# b2NzL1JlcG9zaXRvcnkuaHRtMBMGA1UdJQQMMAoGCCsGAQUFBwMIMBkGCSsGAQQB
# gjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/
# MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1UdHwRPME0wS6BJ
# oEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01p
# Y1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYB
# BQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljUm9v
# Q2VyQXV0XzIwMTAtMDYtMjMuY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQCdVX38Kq3h
# LB9nATEkW+Geckv8qW/qXBS2Pk5HZHixBpOXPTEztTnXwnE2P9pkbHzQdTltuw8x
# 5MKP+2zRoZQYIu7pZmc6U03dmLq2HnjYNi6cqYJWAAOwBb6J6Gngugnue99qb74p
# y27YP0h1AdkY3m2CDPVtI1TkeFN1JFe53Z/zjj3G82jfZfakVqr3lbYoVSfQJL1A
# oL8ZthISEV09J+BAljis9/kpicO8F7BUhUKz/AyeixmJ5/ALaoHCgRlCGVJ1ijbC
# HcNhcy4sa3tuPywJeBTpkbKpW99Jo3QMvOyRgNI95ko+ZjtPu4b6MhrZlvSP9pEB
# 9s7GdP32THJvEKt1MMU0sHrYUP4KWN1APMdUbZ1jdEgssU5HLcEUBHG/ZPkkvnNt
# yo4JvbMBV0lUZNlz138eW0QBjloZkWsNn6Qo3GcZKCS6OEuabvshVGtqRRFHqfG3
# rsjoiV5PndLQTHa1V1QJsWkBRH58oWFsc/4Ku+xBZj1p/cvBQUl+fpO+y/g75LcV
# v7TOPqUxUYS8vwLBgqJ7Fx0ViY1w/ue10CgaiQuPNtq6TPmb/wrpNPgkNWcr4A24
# 5oyZ1uEi6vAnQj0llOZ0dFtq0Z4+7X6gMTN9vMvpe784cETRkPHIqzqKOghif9lw
# Y1NNje6CbaUFEMFxBmoQtB1VM1izoXBm8qGCAs4wggI3AgEBMIH4oYHQpIHNMIHK
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxN
# aWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNT
# IEVTTjozQkJELUUzMzgtRTlBMTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAt+lDSRX92KFyij71Jn20CoSyyuCg
# gYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYw
# JAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0B
# AQUFAAIFAOaRkLAwIhgPMjAyMjA4MDEwNzM3MjBaGA8yMDIyMDgwMjA3MzcyMFow
# dzA9BgorBgEEAYRZCgQBMS8wLTAKAgUA5pGQsAIBADAKAgEAAgIiFAIB/zAHAgEA
# AgIRwzAKAgUA5pLiMAIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMC
# oAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBAG0flC5o
# 3nfbeONYN62eVFhoaQPRqngb9jI5nmRcDbs2f0QoDM1cx+8dFgju7DbN6BIbJwAc
# f8ARFUTKHsdJugPVgt0AStfK+Jh24+0PWnxyRymIZAnN/Ufm5SVCFqS5+sJUf4uP
# BZiAnxw4bEUCPNX44mKs1oM1/bpMplvknhriMYIEDTCCBAkCAQEwgZMwfDELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGd/onl+Xu7TMAAAQAAAZ0wDQYJ
# YIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkq
# hkiG9w0BCQQxIgQgT5EsJQY3J0ZPjUvcQL68wITke7OOJ7CagA/JuvWLum4wgfoG
# CyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCD1HmOt4IqgT4A0n4JblX/fzFLyEu4O
# BDOb+mpMlYdFoTCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# AhMzAAABnf6J5fl7u0zAAAEAAAGdMCIEIPC6k4XcrTRcOe8jIhqeQlXoooW1cr3v
# 1A2paYqNVWNdMA0GCSqGSIb3DQEBCwUABIICAEdUSUpdEyrk5GqUv9tb2QAoaku2
# Y+0bgEeq+eYLaTfriGIXx1cWmgrrv1OPcVOQv2WW68EzwvbFrHMDca9cfKwTDhCx
# p0JrzmrVLXutCxBxNGU6wqa2EnyAjrR8k6nMm7gDt5qx8CjTos2t/9duC3a4hg0p
# P2ymyLSZ3QfoKXf7pUZruPKN9ct7tYXwz4uBff5zOmeCzyyG2Fk13uf04KKoD3bU
# YpnwzBAFZTl60HoEWC/euvu8fh4TXiHn28/tKmpLQgBCnMLJQyvHsta7NSnZInxB
# VBsxA+vnr281qyQmKhaAFlrw2FNTdCCOhAdP3iD6bU6oLtfNRQuk10HLR2KBGHWi
# Wv1BNHPogeWG0KOcNdo22sk4yGX2GO7ob4m3VcJYVeZfgNqXryeHVMuKAtd90rY3
# VQzGWX0PRvzqCQgeewopc03c2BNUJ2oCBqOXuxn21aNBZ/yx0PSKeTLMOF3ZmdYQ
# u92ep/s4JRBX5/FS5FPoWftaNSPlsuPqtaEVlFnDUV5D5bfYIWUsGeHyrv3U9ol1
# 45vo39Q8o8Uu4+HGUr4FauQIuVN5ZnV7Gw173oi1uMoGtkCqTG49lognU3R9LkVP
# KVxpjmhNaByX3H8QsYCK9SMK8dVum/OB0rjJO2GVQ5fi/yNoDAsOgjmOM4Ve1Sm/
# uNTM4ICkj6GYdcSB
# SIG # End signature block
