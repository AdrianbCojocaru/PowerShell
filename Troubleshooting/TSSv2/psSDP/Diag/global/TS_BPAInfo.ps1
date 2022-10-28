#************************************************
# TS_BPAInfo.ps1
# Version 1.5.6
# Date: 12-10-2010 / 2019 WalterE
# Author: Andre Teixeira - andret@microsoft.com
# Description: - This script is used to obtain a report from any inbox BPA Module information or other BPAs with MBCA support.
#************************************************
# 2019-07-30 WalterE added Trap #_#

Param ($BPAModelID = $null, $OutputFileName, $ReportTitle, $ModuleName="BestPractices", $InvokeCommand="Invoke-BpaModel", $GetBPAModelCommand="Get-BPAModel", $GetBPAResultCommand="Get-BpaResult")

Trap [Exception]
{
	WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText "TS_BPAInfo.ps1 Error, ReportTitle: $ReportTitle, BPAModelID: $BPAModelID"
		 #_# Handle exception and throw it to the stdout log file. Then continue with function and script.
			 $Script:ExceptionMessage = $_
			 "[info]: Exception occurred."  | WriteTo-StdOut
			 "[info]: Exception.Message $ExceptionMessage."  | WriteTo-StdOut 
		 $Error.Clear()
	continue 
}

Function Write-ScriptProgress ($Activity = "", $Status = "") {
	if ($Activity -ne $LastActivity) {
		if (-not $TroubleShootingModuleLoaded -and ($Activity -ne "")) {
			$Activity | Out-Host
		}
		if ($Activity -ne "") {
			Set-variable -Name "LastActivity" -Value $Activity -Scope "global"
		} else {
			$Activity = $LastActivity
		}	
	}
	if ($TroubleShootingModuleLoaded) {
			Write-DiagProgress -activity $Activity -status $Status
		
	} else {
		"    [" + (Get-Date) + "] " + $Status | Out-Host
	}
}

Function SaveToHTMLFile($SourceXMLDoc, $HTMLFileName){
	
	$XMLFilename = $Env:TEMP + "\" + [System.IO.Path]::GetFileNameWithoutExtension($HTMLFileName) + ".XML"
	$SourceXMLDoc.Save($XMLFilename)
	
	[xml] $XSLContent = Get-Content 'BPAInfo.xsl'

	$XSLObject = New-Object System.Xml.Xsl.XslTransform
	$XSLObject.Load($XSLContent)
	$XSLObject.Transform($XMLFilename, $HTMLFilename)
    
	Remove-Item $XMLFilename
	"Output saved to $HTMLFilename" | WriteTo-StdOut -ShortFormat
}

Function AddXMLElement ([xml] $xmlDoc,
						[string] $ElementName="Item", 
						[string] $Value,
						[string] $AttributeName="name", 
						[string] $attributeValue,
						[string] $xpath="/Root")
{
	[System.Xml.XmlElement] $rootElement=$xmlDoc.SelectNodes($xpath).Item(0)
	if ($null -ne $rootElement) { 
		[System.Xml.XmlElement] $element = $xmlDoc.CreateElement($ElementName)
		if ($attributeValue.Length -ne 0) {$element.SetAttribute($AttributeName, $attributeValue)}
		if ($Value.lenght -ne 0) { 
			if ($PowerShellV2) {
				$element.innerXML = $Value
			} else {
				$element.set_InnerXml($Value)
			}
		}
		$Null = $rootElement.AppendChild($element)
	} else {
		"Error. Path $xpath returned a null value. Current XML document: `n" + $xmlDoc.OuterXml
	}
}

#***********************************************
#*  Starts here
#***********************************************

if (($ModuleName -eq "BestPractices") -and ($InvokeCommand -eq "Invoke-BpaModel") -and ($OSVersion.Build -lt 7600)){
	"Inbox BPAs Not Supported on OS Build " + $OSVersion.Build | WriteTo-StdOut
}
else{
	if (Test-Path (Join-Path $PWD.Path 'BPAInfo.xsl')){
		if ($null -ne $BPAModelID){
			Import-LocalizedData -BindingVariable BPAInfo

			if ((Get-CimInstance -Class Win32_ComputerSystem).DomainRole -gt 1){ #Server
				if ((Get-Host).Name -ne "Default Host"){
					#_# "Windows Troubleshooting Platform not loaded."
					#_# $TroubleshootingModuleLoaded = $false
					$TroubleshootingModuleLoaded = $true
				} else {
					$TroubleshootingModuleLoaded = $true
				}
				
				Write-ScriptProgress -activity $ReportTitle -status $BPAInfo.ID_BPAStarting
				
				$PowerShellV2 = (((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine").PowerShellVersion).Substring(0,1) -ge 2)
				
				$Error.Clear()
				Import-Module $ModuleName
				
				if ($Error.Count -eq 0){
					$InstalledBPAs = Invoke-Expression "$GetBPAModelCommand"
					if ($null -ne (($InstalledBPAs | where-object {$_.Id -eq $BPAModelID}).Id)){
						Write-ScriptProgress -activity $ReportTitle -status $BPAInfo.ID_BPARunning	
						$BPAResults = Invoke-Expression "$InvokeCommand $BPAModelID"
						if ($null -ne ($BPAResults | where-object {($_.ModelID -eq $BPAModelID) -and ($_.Success -eq $true)})){
							Write-ScriptProgress -activity $ReportTitle -status $BPAInfo.ID_BPAGenerating	
							$BPAXMLDoc = Invoke-Expression "$GetBPAResultCommand $BPAModelID | ConvertTo-XML"
							
							if ($null -ne $BPAXMLDoc){
								AddXMLElement -xmlDoc $BPAXMLDoc -ElementName "Machine" -Value $Env:COMPUTERNAME -xpath "/Objects"
								AddXMLElement -xmlDoc $BPAXMLDoc -ElementName "TimeField" -Value ($BPAResults[0].Detail).ScanTime -xpath "/Objects"
								AddXMLElement -xmlDoc $BPAXMLDoc -ElementName "ModelId" -Value ($BPAResults[0].Detail).ModelId -xpath "/Objects"
								AddXMLElement -xmlDoc $BPAXMLDoc -ElementName "ReportTitle" -Value $ReportTitle -xpath "/Objects"
								AddXMLElement -xmlDoc $BPAXMLDoc -ElementName "OutputFileName" -Value $OutputFileName -xpath "/Objects"
								
								SaveToHTMLFile -HTMLFileName $OutputFileName -SourceXMLDoc $BPAXMLDoc
								
								if ($TroubleshootingModuleLoaded){
									CollectFiles -filesToCollect $OutputFileName -fileDescription $ReportTitle -sectionDescription "Best Practices Analyzer reports"
									
									$XMLName = [System.IO.Path]::GetFileNameWithoutExtension($OutputFileName) + ".xml"
									$BPAXMLDoc.Save($XMLName)
									
									CollectFiles -filesToCollect $XMLName -fileDescription $ReportTitle -sectionDescription "Best Practices Analyzer RAW XML Files" -Verbosity "Debug"
									if ($BPAXMLDoc.SelectNodes("(//Object[(Property[@Name=`'Severity`'] = `'Warning`') or (Property[@Name=`'Severity`'] = `'Error`')])").Count -ne 0){
										$BPAXMLFile = [System.IO.Path]::GetFullPath($PWD.Path + ("\..\BPAResults.XML"))
										if (Test-Path $BPAXMLFile){
											[xml] $ExistingBPAXMLDoc = Get-Content $BPAXMLFile
											AddXMLElement -xmlDoc $ExistingBPAXMLDoc -xpath "/Root" -ElementName "BPAModel" -Value $BPAXMLDoc.SelectNodes("/Objects").Item(0).InnerXML
											$ExistingBPAXMLDoc.Save($BPAXMLFile)
										} else {
											[xml] $BPAFileXMLDoc = "<Root/>"
											AddXMLElement  -xmlDoc $BPAFileXMLDoc -xpath "/Root" -ElementName "BPAModel" -Value $BPAXMLDoc.SelectNodes("/Objects").Item(0).InnerXML
											$BPAFileXMLDoc.Save($BPAXMLFile)
										}
										Update-DiagRootCause -id RC_BPAInfo -Detected $true
									}
								}
								Write-ScriptProgress -activity $ReportTitle -status "Completed."
							} else {
								"$GetBPAResultCommand did not return any result" | WriteTo-StdOut -ShortFormat
							}
						}
					
					} else{
						$Msg = "ERROR: BPA Module $BPAModelID is not installed. Follow the list of installed BPAs: `r`n"
						foreach ($BPA in $InstalledBPAs){
							$Msg += "   " + $BPA.Id + "`r`n"
						}
						$Msg | WriteTo-StdOut -ShortFormat
					}
				} else{
					"ERROR: Unable to load BestPractices module - $ModuleName"  | WriteTo-StdOut -ShortFormat
				}
			}
		}
		else{
			"ERROR: BPAModelID was not specified. BPAInfo not executed"  | WriteTo-StdOut -ShortFormat
		}
	}
	else{
		"ERROR: BPAInfo.xsl not found. Make sure to use <Folder source> instead of <File source>" | WriteTo-StdOut -IsError
		"ERROR: BPAInfo.xsl not found. Make sure to use <Folder source> instead of <File source>" | WriteTo-ErrorDebugReport
	}
}


# SIG # Begin signature block
# MIInrgYJKoZIhvcNAQcCoIInnzCCJ5sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAfHDUPs+innFNo
# Fqu25pMW3vgmtvflOqlrZFf4TS5oJaCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGY4wghmKAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIK9p80J5/X6zUjsKOo1nJc9T
# H5ztSOUsPx3Ud9duZghPMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQCIqdKtZGGZdBRAjnS5Yu/SjnertAjNO2btxTRJb5Sys0raVxotic1a
# x8VW1U1v1gSD1QofDJ6vNHxQbyAgdu5I2gSf55G6vLcZVw9NGEf5D/yar3IugGXw
# ejnFYMFP0ge1rfu0W128OSIC9OAcghuIWqBvqNdfMrPrZaW9a/gK4VTS9Gi4vzPD
# OF0y/Z9QOVFAuZAFScgneBCrpmXAC/8M4PTdQHTcmzidEWmC3O7U61WSlJbBhvNV
# CdTCqHQD04ZMVqj0cdlhyJFGnr92dVhMBJMUAhFSEcAFhFE1ZsWHQoSaeB3HofZJ
# Qog3L4qvwN6w1hnXJUBXwEioH5Q/XjOCoYIXFjCCFxIGCisGAQQBgjcDAwExghcC
# MIIW/gYJKoZIhvcNAQcCoIIW7zCCFusCAQMxDzANBglghkgBZQMEAgEFADCCAVkG
# CyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEILdzRr16gox32JOw75te2Y3fc8qzeqj5oLzqgN2W1uqQAgZi3n8Z
# S0EYEzIwMjIwODA4MDkxNTI4LjE4OVowBIACAfSggdikgdUwgdIxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJ
# cmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046RkM0MS00QkQ0LUQyMjAxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WgghFlMIIHFDCCBPygAwIBAgITMwAAAY5Z20YAqBCUzAABAAABjjAN
# BgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0y
# MTEwMjgxOTI3NDVaFw0yMzAxMjYxOTI3NDVaMIHSMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBP
# cGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkZDNDEt
# NEJENC1EMjIwMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAqiMCq6OMzLa5wrtcf7Bf
# 9f1WXW9kpqbOBzgPJvaGLrZG7twgwqTRWf1FkjpJKBOG5QPIRy7a6IFVAy0W+tBa
# FX4In4DbBf2tGubyY9+hRU+hRewPJH5CYOvpPh77FfGM63+OlwRXp5YER6tC0WRK
# n3mryWpt4CwADuGv0LD2QjnhhgtRVidsiDnn9+aLjMuNapUhstGqCr7JcQZt0ZrP
# UHW/TqTJymeU1eqgNorEbTed6UQyLaTVAmhXNQXDChfa526nW7RQ7L4tXX9Lc0og
# uiCSkPlu5drNA6NM8z+UXQOAHxVfIQXmi+Y3SV2hr2dcxby9nlTzYvf4ZDr5Wpcw
# t7tTdRIJibXHsXWMKrmOziliGDToLx34a/ctZE4NOLnlrKQWN9ZG+Ox5zRarK1Eh
# ShahM0uQNhb6BJjp3+c0eNzMFJ2qLZqDp2/3Yl5Q+4k+MDHLTipP6VBdxcdVfd4m
# grVTx3afO5KNfgMngGGfhSawGraRW28EhrLOspmIxii92E7vjncJ2tcjhLCjBArV
# pPh3cZG5g3ZVy5iiAaoDaswpNgnMFAK5Un1reK+MFhPi9iMnvUPwtTDDJt5YED5D
# AT3mBUxp5QH3t7RhZwAJNLWLtpTeGF7ub81sSKYv2ardazAe9XLS10tV2oOPrcni
# GJzlXW7VPvxqQNxe8lCDA20CAwEAAaOCATYwggEyMB0GA1UdDgQWBBTsQfkz9gT4
# 4N/5G8vNHayep+aV5DAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBf
# BgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3Bz
# L2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmww
# bAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0El
# MjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMI
# MA0GCSqGSIb3DQEBCwUAA4ICAQA1UK9xzIeTlKhSbLn0bekR5gYh6bB1XQpluCqC
# A15skZ37UilaFJw8+GklDLzlNhSP2mOiOzVyCq8kkpqnfUc01ZaBezQxg77qevj2
# iMyg39YJfeiCIhxYOFugwepYrPO8MlB/oue/VhIiDb1eNYTlPSmv3palsgtkrb0o
# o0F0uWmX4EQVGKRo0UENtZetVIxa0J9DpUdjQWPeEh9cEM+RgE265w5WAVb+WNx0
# iWiF4iTbCmrWaVEOX92dNqBm9bT1U7nGwN5CygpNAgEaYnrTMx1N4AjxObACDN5D
# dvGlu/O0DfMWVc6qk6iKDFC6WpXQSkMlrlXII/Nhp+0+noU6tfEpHKLt7fYm9of5
# i/QomcCwo/ekiOCjYktp393ovoC1O2uLtbLnMVlE5raBLBNSbINZ6QLxiA41lXnV
# VLIzDihUL8MU9CMvG4sdbhk2FX8zvrsP5PeBIw1faenMZuz0V3UXCtU5Okx5fmio
# WiiLZSCi1ljaxX+BEwQiinCi+vE59bTYI5FbuR8tDuGLiVu/JSpVFXrzWMP2Kn11
# sCLAGEjqJYUmO1tRY29Kd7HcIj2niSB0PQOCjYlnCnywnDinqS1CXvRsisjVlS1R
# p4Tmuks+pGxiMGzF58zcb+hoFKyONuL3b+tgxTAz3sF3BVX9uk9M5F+OEoeyLyGf
# LekNAjCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcN
# AQELBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAw
# BgNVBAMTKU1pY3Jvc29mdCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDEw
# MB4XDTIxMDkzMDE4MjIyNVoXDTMwMDkzMDE4MzIyNVowfDELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgUENBIDIwMTAwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDk
# 4aZM57RyIQt5osvXJHm9DtWC0/3unAcH0qlsTnXIyjVX9gF/bErg4r25PhdgM/9c
# T8dm95VTcVrifkpa/rg2Z4VGIwy1jRPPdzLAEBjoYH1qUoNEt6aORmsHFPPFdvWG
# UNzBRMhxXFExN6AKOG6N7dcP2CZTfDlhAnrEqv1yaa8dq6z2Nr41JmTamDu6Gnsz
# rYBbfowQHJ1S/rboYiXcag/PXfT+jlPP1uyFVk3v3byNpOORj7I5LFGc6XBpDco2
# LXCOMcg1KL3jtIckw+DJj361VI/c+gVVmG1oO5pGve2krnopN6zL64NF50ZuyjLV
# wIYwXE8s4mKyzbnijYjklqwBSru+cakXW2dg3viSkR4dPf0gz3N9QZpGdc3EXzTd
# EonW/aUgfX782Z5F37ZyL9t9X4C626p+Nuw2TPYrbqgSUei/BQOj0XOmTTd0lBw0
# gg/wEPK3Rxjtp+iZfD9M269ewvPV2HM9Q07BMzlMjgK8QmguEOqEUUbi0b1qGFph
# AXPKZ6Je1yh2AuIzGHLXpyDwwvoSCtdjbwzJNmSLW6CmgyFdXzB0kZSU2LlQ+QuJ
# YfM2BjUYhEfb3BvR/bLUHMVr9lxSUV0S2yW6r1AFemzFER1y7435UsSFF5PAPBXb
# GjfHCBUYP3irRbb1Hode2o+eFnJpxq57t7c+auIurQIDAQABo4IB3TCCAdkwEgYJ
# KwYBBAGCNxUBBAUCAwEAATAjBgkrBgEEAYI3FQIEFgQUKqdS/mTEmr6CkTxGNSnP
# EP8vBO4wHQYDVR0OBBYEFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMFwGA1UdIARVMFMw
# UQYMKwYBBAGCN0yDfQEBMEEwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9z
# b2Z0LmNvbS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5Lmh0bTATBgNVHSUEDDAKBggr
# BgEFBQcDCDAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYw
# DwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoY
# xDBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtp
# L2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYB
# BQUHAQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20v
# cGtpL2NlcnRzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNydDANBgkqhkiG9w0B
# AQsFAAOCAgEAnVV9/Cqt4SwfZwExJFvhnnJL/Klv6lwUtj5OR2R4sQaTlz0xM7U5
# 18JxNj/aZGx80HU5bbsPMeTCj/ts0aGUGCLu6WZnOlNN3Zi6th542DYunKmCVgAD
# sAW+iehp4LoJ7nvfam++Kctu2D9IdQHZGN5tggz1bSNU5HhTdSRXud2f8449xvNo
# 32X2pFaq95W2KFUn0CS9QKC/GbYSEhFdPSfgQJY4rPf5KYnDvBewVIVCs/wMnosZ
# iefwC2qBwoEZQhlSdYo2wh3DYXMuLGt7bj8sCXgU6ZGyqVvfSaN0DLzskYDSPeZK
# PmY7T7uG+jIa2Zb0j/aRAfbOxnT99kxybxCrdTDFNLB62FD+CljdQDzHVG2dY3RI
# LLFORy3BFARxv2T5JL5zbcqOCb2zAVdJVGTZc9d/HltEAY5aGZFrDZ+kKNxnGSgk
# ujhLmm77IVRrakURR6nxt67I6IleT53S0Ex2tVdUCbFpAUR+fKFhbHP+CrvsQWY9
# af3LwUFJfn6Tvsv4O+S3Fb+0zj6lMVGEvL8CwYKiexcdFYmNcP7ntdAoGokLjzba
# ukz5m/8K6TT4JDVnK+ANuOaMmdbhIurwJ0I9JZTmdHRbatGePu1+oDEzfbzL6Xu/
# OHBE0ZDxyKs6ijoIYn/ZcGNTTY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggLUMIIC
# PQIBATCCAQChgdikgdUwgdIxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlvbnMgTGlt
# aXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046RkM0MS00QkQ0LUQyMjAxJTAj
# BgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMC
# GgMVAD1iK+pPThHqgpa5xsPmiYruWVuMoIGDMIGApH4wfDELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEFBQACBQDmmskxMCIYDzIwMjIwODA4
# MDcyODQ5WhgPMjAyMjA4MDkwNzI4NDlaMHQwOgYKKwYBBAGEWQoEATEsMCowCgIF
# AOaayTECAQAwBwIBAAICFW8wBwIBAAICEVkwCgIFAOacGrECAQAwNgYKKwYBBAGE
# WQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDAN
# BgkqhkiG9w0BAQUFAAOBgQAtzD2WE4tOrsC6OX0THvEDospBv9wmsQGdQ6y4EmML
# sMhdJtCxj3LXXkJduPn+mJfo3c+b3UvuDnZJzIgPYFjzj5dxSEIGzJx22RA7hvoC
# jA/XCoycWSs+NEH7K0Tu9fKm82IDwcvOnSgWY79N8oB7W/KUf01qx2tqNE6kPE0/
# aTGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMz
# AAABjlnbRgCoEJTMAAEAAAGOMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0B
# CQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEIPyLgsNh+YWidw2mn7Z9
# ChtBElJoG5uOtd40PMvF9riXMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQg
# vQWPITvigaUuV5+f/lWs3BXZwJ/l1mf+yelu5nXmxCUwgZgwgYCkfjB8MQswCQYD
# VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
# MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3Nv
# ZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAY5Z20YAqBCUzAABAAABjjAiBCA0
# rhrDkyYlreDir1lk4vABDI8HD1QPk65nUqHAUzZG+TANBgkqhkiG9w0BAQsFAASC
# AgAgGEOP2c3vjB7wMFu7Wp+eUW7w5WD5mUm4YFmQLI6azvnqvOSg6p5g3lMUIFdx
# QWFZPxuSOhIaVQHtLliakpXkWrHO43yqk8loujdV9F4pO79pXu/+aqsY2hkFwr5j
# rivGt5mkxYKR1elU2CBpw4EaTBTZIkh8ZxoFwcic7taBhW5RHnaCpFKQVobSf377
# 4LMGGQ+2lvlfGYgas/F3AE5K1rN0oynpgORklt+z653RwOgv1zufX/u4G+m6sfxC
# 5bsE8eX2exi1wsu7TAOe0IS+MsuG5+kUMj3yOxJBQhDVy2oh5YUuwjztfw+F5jAh
# 3vM9HBIN0CfViWTUrxQfTZizLwoW+EphscIECEb3POfEfkI1gWmhGO1pOwEM6h+J
# XeCZIsh6ZG7jje6SW35dhMn7ua255UlgBs+uw+g9DavT/4lOROFtzwcvN+dnOj0f
# XV+4Eajb4JTK9Lu4EHAXx2UCRjdfF6nVbDWMxAf/71oGSY0tS9B5OkU9xSMtwXV5
# 2/HkXhhx5lE2NFGzxBkeV7+mxeMS0DwXatokqoNSnHwNaLEpRGLJLwfnOnmtw7gY
# 7ij5gAMfWtgt8QR7ts+O97jRbBSQZCB3aAqJwQyqHssuBz2rxZsm/4WYmB6R08B8
# qPkPHP7im7huYbXU24Vm6jY5O7VvmBznNGCquNOnhvVL9Q==
# SIG # End signature block
