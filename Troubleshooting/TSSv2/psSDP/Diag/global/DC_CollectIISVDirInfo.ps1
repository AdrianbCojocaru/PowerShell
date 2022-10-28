﻿# **********************************************************************************************************************************************************
# Version 1.0
# Date: 11/14/2012
# Author: Vinay Pamnani - vinpa@microsoft.com
# Description: 
#		
# **********************************************************************************************************************************************************

trap [Exception] 
{ 
	WriteTo-ErrorDebugReport -ErrorRecord $_ 
	continue 
}

TraceOut "Started"

Import-LocalizedData -BindingVariable ScriptStrings
$sectionDescription = "IIS Configuration"

# ----------------
# Write Progress
# ----------------
Write-DiagProgress -Activity $ScriptStrings.ID_SCCM_ACTIVITY_IISVDirInfo -Status $ScriptStrings.ID_SCCM_IISVDirInfo_VDIR

Function ParseSSLFlags 
{
	param (
		$sslFlag
		)
	process
	{
			$RetVal = ""
			If ($sslFlag -eq 0) {$RetVal = "None"}
			If ($sslFlag -eq 8) {$RetVal = "Require SSL - Ignore client certificates"}
			If ($sslFlag -eq 40) {$RetVal = "Require SSL - Accept client certificates "}
			If ($sslFlag -eq 104) {$RetVal = "Require SSL - Require client certificates "}
			If ($sslFlag -band 256) {$RetVal += " - Require 128-bit SSL"}
			Return $RetVal
	}
}

If ($Is_IIS)
{
	Set-Variable -Name sites -Value @()
	$sites += "Default Web Site"
	
	If ($Is_WSUS) {
		$siteID = Get-RegValue ($Reg_WSUS + "\Server\Setup") "IISTargetWebSiteIndex"
		If ($siteID -ne 1) {
			$sites += "WSUS Administration"
		}
	}
	
	$IISInfoFile = Join-Path $Pwd.Path ($ComputerName + "_IIS_VDirInfo.txt")		
	
	if($OSVersion.Build -ge 6000)
	{
		# IIS 7.0 and Higher
		[System.Reflection.Assembly]::LoadFrom( "C:\windows\system32\inetsrv\Microsoft.Web.Administration.dll" )
		$serverManager = (New-Object Microsoft.Web.Administration.ServerManager)
		
		$config = $serverManager.GetApplicationHostConfiguration()
		
		
		"------------------------------------" | Out-File $IISInfoFile
		"IIS Virtual Directories Information" | Out-File $IISInfoFile -Append
		"------------------------------------" | Out-File $IISInfoFile -Append
		"" | Out-File $IISInfoFile -Append
		"  +--WEBSITES" | Out-File $IISInfoFile -Append
		
		$sites | ForEach-Object `
		{
			$currentSiteName = $_
			$currentSite = $serverManager.Sites[$currentSiteName]
			"       |  |" | Out-File $IISInfoFile -Append
			"       +--" + $currentSiteName | Out-File $IISInfoFile -Append
						
			$currentSite.Applications | ForEach-Object `
			{
				If ($_.Path -ne '/') {
					"       |  |" | Out-File $IISInfoFile -Append
					"       |  +--APP: " + $_.Path | Out-File $IISInfoFile -Append
					"       |  |   AppPool: " + $_.ApplicationPoolName | Out-File $IISInfoFile -Append
					$_.VirtualDirectories | ForEach-Object { "       |  |   Physical Path: " + $_.PhysicalPath | Out-File $IISInfoFile -Append }
					$anonymousAuthenticationSection = $config.GetSection("system.webServer/security/authentication/anonymousAuthentication", ($currentSiteName + $_.Path))
	    			"       |  |   Anonymous Auth Enabled: " + $anonymousAuthenticationSection["Enabled"] | Out-File $IISInfoFile -Append
					"       |  |   Anonymous Auth UserName: " + $anonymousAuthenticationSection["userName"] | Out-File $IISInfoFile -Append
				    $windowsAuthenticationSection = $config.GetSection("system.webServer/security/authentication/windowsAuthentication", ($currentSiteName + $_.Path))
				    "       |  |   Windows Auth Enabled: " + $windowsAuthenticationSection["Enabled"] | Out-File $IISInfoFile -Append
					$accessSection = $config.GetSection("system.webServer/security/access", ($currentSiteName + $_.Path))
				    "       |  |   SSL Flags: " + (ParseSSLFlags($accessSection["sslFlags"])) | Out-File $IISInfoFile -Append
				    #$handlersSection = $config.GetSection("system.webServer/handlers", ($currentSiteName + $_.Path))
				    #"       |  |   Access Policy: " + $handlersSection["accessPolicy"] | Out-File $IISInfoFile -Append
				}
				Else {
					$_.VirtualDirectories | ForEach-Object `
					{
						If ($_.Path -ne '/') {
						"       |  |" | Out-File $IISInfoFile -Append
						"       |  +--VDIR: " + $_.Path | Out-File $IISInfoFile -Append
						"       |  |   AppPool: Not Applicable" | Out-File $IISInfoFile -Append
						"       |  |   Physical Path: " + $_.PhysicalPath | Out-File $IISInfoFile -Append
						$anonymousAuthenticationSection = $config.GetSection("system.webServer/security/authentication/anonymousAuthentication", ($currentSiteName + $_.Path))
		    			"       |  |   Anonymous Auth Enabled: " + $anonymousAuthenticationSection["Enabled"] | Out-File $IISInfoFile -Append
						"       |  |   Anonymous Auth UserName: " + $anonymousAuthenticationSection["userName"] | Out-File $IISInfoFile -Append
					    $windowsAuthenticationSection = $config.GetSection("system.webServer/security/authentication/windowsAuthentication", ($currentSiteName + $_.Path))
					    "       |  |   Windows Auth Enabled: " + $windowsAuthenticationSection["Enabled"] | Out-File $IISInfoFile -Append
						$accessSection = $config.GetSection("system.webServer/security/access", ($currentSiteName + $_.Path))
				    	"       |  |   SSL Flags: " + (ParseSSLFlags($accessSection["sslFlags"])) | Out-File $IISInfoFile -Append
					    #$handlersSection = $config.GetSection("system.webServer/handlers", ($currentSiteName + $_.Path))
					    #"       |  |   Access Policy: " + $handlersSection["accessPolicy"] | Out-File $IISInfoFile -Append
						}
					}
				}
			}			
		}
	}
	else
	{
		# IIS 6.0		
		$CommandLineToExecute = $Env:windir + "\system32\cscript.exe IISVDirInfo.VBS $IISInfoFile"
		RunCmD -commandToRun $CommandLineToExecute -collectFiles $false		
	}
	
	CollectFiles -filesToCollect $IISInfoFile -fileDescription "IIS VDIR Information" -sectionDescription $sectionDescription -noFileExtensionsOnDescription
}

TraceOut "Completed"
# SIG # Begin signature block
# MIIjiAYJKoZIhvcNAQcCoIIjeTCCI3UCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCudnPRXhrVTVO7
# Dmq6pHMyuNHYWji/fvDlBDvbYNnBvqCCDYEwggX/MIID56ADAgECAhMzAAAB32vw
# LpKnSrTQAAAAAAHfMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjAxMjE1MjEzMTQ1WhcNMjExMjAyMjEzMTQ1WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQC2uxlZEACjqfHkuFyoCwfL25ofI9DZWKt4wEj3JBQ48GPt1UsDv834CcoUUPMn
# s/6CtPoaQ4Thy/kbOOg/zJAnrJeiMQqRe2Lsdb/NSI2gXXX9lad1/yPUDOXo4GNw
# PjXq1JZi+HZV91bUr6ZjzePj1g+bepsqd/HC1XScj0fT3aAxLRykJSzExEBmU9eS
# yuOwUuq+CriudQtWGMdJU650v/KmzfM46Y6lo/MCnnpvz3zEL7PMdUdwqj/nYhGG
# 3UVILxX7tAdMbz7LN+6WOIpT1A41rwaoOVnv+8Ua94HwhjZmu1S73yeV7RZZNxoh
# EegJi9YYssXa7UZUUkCCA+KnAgMBAAGjggF+MIIBejAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUOPbML8IdkNGtCfMmVPtvI6VZ8+Mw
# UAYDVR0RBEkwR6RFMEMxKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMRYwFAYDVQQFEw0yMzAwMTIrNDYzMDA5MB8GA1UdIwQYMBaAFEhu
# ZOVQBdOCqhc3NyK1bajKdQKVMFQGA1UdHwRNMEswSaBHoEWGQ2h0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY0NvZFNpZ1BDQTIwMTFfMjAxMS0w
# Ny0wOC5jcmwwYQYIKwYBBQUHAQEEVTBTMFEGCCsGAQUFBzAChkVodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY0NvZFNpZ1BDQTIwMTFfMjAx
# MS0wNy0wOC5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAnnqH
# tDyYUFaVAkvAK0eqq6nhoL95SZQu3RnpZ7tdQ89QR3++7A+4hrr7V4xxmkB5BObS
# 0YK+MALE02atjwWgPdpYQ68WdLGroJZHkbZdgERG+7tETFl3aKF4KpoSaGOskZXp
# TPnCaMo2PXoAMVMGpsQEQswimZq3IQ3nRQfBlJ0PoMMcN/+Pks8ZTL1BoPYsJpok
# t6cql59q6CypZYIwgyJ892HpttybHKg1ZtQLUlSXccRMlugPgEcNZJagPEgPYni4
# b11snjRAgf0dyQ0zI9aLXqTxWUU5pCIFiPT0b2wsxzRqCtyGqpkGM8P9GazO8eao
# mVItCYBcJSByBx/pS0cSYwBBHAZxJODUqxSXoSGDvmTfqUJXntnWkL4okok1FiCD
# Z4jpyXOQunb6egIXvkgQ7jb2uO26Ow0m8RwleDvhOMrnHsupiOPbozKroSa6paFt
# VSh89abUSooR8QdZciemmoFhcWkEwFg4spzvYNP4nIs193261WyTaRMZoceGun7G
# CT2Rl653uUj+F+g94c63AhzSq4khdL4HlFIP2ePv29smfUnHtGq6yYFDLnT0q/Y+
# Di3jwloF8EWkkHRtSuXlFUbTmwr/lDDgbpZiKhLS7CBTDj32I0L5i532+uHczw82
# oZDmYmYmIUSMbZOgS65h797rj5JJ6OkeEUJoAVwwggd6MIIFYqADAgECAgphDpDS
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
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIVXTCCFVkCAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAd9r8C6Sp0q00AAAAAAB3zAN
# BglghkgBZQMEAgEFAKCBpDAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgR/IkcJGD
# FULYAiaQr35vuoYmOGPhzHpAUywTWGYb9+AwOAYKKwYBBAGCNwIBDDEqMCigCIAG
# AFQAUwBToRyAGmh0dHBzOi8vd3d3Lm1pY3Jvc29mdC5jb20gMA0GCSqGSIb3DQEB
# AQUABIIBABFX0ax6SUb74abZV1XUuSNBCJ6a7MqmL6PgGfegYGgVd0vDux1XxvK2
# tkiL88vKv73d4Lv+G7WhefT6H5xKkwu1KQU+RIDIrHUbcacl9CPaiphpmzXuzj6o
# xruQQ4JzUZ+AmXT/fKWafRrS1U5OMuP6ciFewm6XTe53tdtjzmjfIemqsg0TdISe
# r1SsE5R/7nmtgAfEa7nD+CLNfE+2C+OT3XmF21DcDonI5Ljku/08v3SDlfDbROHS
# MSAsWBNnkvOaXwmU08sHgdWoesMc8scal7doBoNfpzTeW7ZekzQMBDaVZBvDZ0oR
# C1mruS0HOs4q0UbNdI0BEYyxa8Ol/TahghLxMIIS7QYKKwYBBAGCNwMDATGCEt0w
# ghLZBgkqhkiG9w0BBwKgghLKMIISxgIBAzEPMA0GCWCGSAFlAwQCAQUAMIIBVQYL
# KoZIhvcNAQkQAQSgggFEBIIBQDCCATwCAQEGCisGAQQBhFkKAwEwMTANBglghkgB
# ZQMEAgEFAAQgf7tMzR4C83uQeYuBaVbOaCEh1sJ5B464ObTmf69LyNUCBmGB56/O
# nBgTMjAyMTExMTExNjUzMzYuMTgyWjAEgAIB9KCB1KSB0TCBzjELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEpMCcGA1UECxMgTWljcm9zb2Z0IE9w
# ZXJhdGlvbnMgUHVlcnRvIFJpY28xJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjc4
# ODAtRTM5MC04MDE0MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2
# aWNloIIORDCCBPUwggPdoAMCAQICEzMAAAFchtLj7Dn2izgAAAAAAVwwDQYJKoZI
# hvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAO
# BgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEm
# MCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjEwMTE0
# MTkwMjE3WhcNMjIwNDExMTkwMjE3WjCBzjELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEpMCcGA1UECxMgTWljcm9zb2Z0IE9wZXJhdGlvbnMgUHVl
# cnRvIFJpY28xJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjc4ODAtRTM5MC04MDE0
# MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIIBIjANBgkq
# hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0CorPq8qH2JAsmgS8lwJTB3l+dq3BBeY
# hkyUnzi/iewy5+d8lsbrbd/9Tw4G7WzI5c5ntXMc54L/6shmvNwlBpDyvmUJCOf1
# +IbeOT6mo9IVGXfD1gYWOi7L8XG5IDqz8y/tvQZLRtodOUkWBG4MoGAGxNqAZHhJ
# GYecV2tKFPe2TVPdYBItMYhJ4YbHiLQPIO7PzNBWamkvz4FTKI+KvRb9dk6y4DoU
# TGPeBO/JMt+INWGY1zDM+/ktCWshWKvSbb7tQNNjyKfMeX/YKUfg3ja6ptaT0fYj
# iukIJxRZIHDWbwN7iFOxMZARPuqJH4V8js9CUlD715/sA0B+U9I2GwIDAQABo4IB
# GzCCARcwHQYDVR0OBBYEFF/zFKw5KHKAkAV/uJp7LWMYwbo+MB8GA1UdIwQYMBaA
# FNVjOlyKMZDzQ3t8RhvFM2hahW1VMFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9j
# cmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1RpbVN0YVBDQV8y
# MDEwLTA3LTAxLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6
# Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljVGltU3RhUENBXzIwMTAt
# MDctMDEuY3J0MAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJ
# KoZIhvcNAQELBQADggEBAHh5TPbXfiBzDhwj9TLZ7aOQ7u16krtPlZe3vpr8DP+l
# 00I3oHUPpBhFEcv3QmYaVkx1S3Ab8DoT1Go2oO/1odDz/YUsVyus05OANDRyNn/0
# zHyy2jXuTitbbZC9Ng5AEHXii40CwOWhn1qpz9C2aLwkUd3oxzu8TmgOB5UabfLx
# 6vtSAufiCRMhifyV5M9j0fbK6gt9dtDxeuXRZYUFuZmbq3cMQb6vqtoiY0ns+sFA
# eel1fEKOMXlY08xg14oRYD5GTIDkUPlgDS4pe2U13keC/Bxaj8AIbK4+W7HBgFwM
# JlAUVq2i/S42M6xDEQxGADOkDm+oQ47H9NQRgWRxEEkwggZxMIIEWaADAgECAgph
# CYEqAAAAAAACMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZp
# Y2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0xMDA3MDEyMTM2NTVaFw0yNTA3MDEyMTQ2
# NTVaMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMIIBIjANBgkqhkiG9w0B
# AQEFAAOCAQ8AMIIBCgKCAQEAqR0NvHcRijog7PwTl/X6f2mUa3RUENWlCgCChfvt
# fGhLLF/Fw+Vhwna3PmYrW/AVUycEMR9BGxqVHc4JE458YTBZsTBED/FgiIRUQwzX
# Tbg4CLNC3ZOs1nMwVyaCo0UN0Or1R4HNvyRgMlhgRvJYR4YyhB50YWeRX4FUsc+T
# TJLBxKZd0WETbijGGvmGgLvfYfxGwScdJGcSchohiq9LZIlQYrFd/XcfPfBXday9
# ikJNQFHRD5wGPmd/9WbAA5ZEfu/QS/1u5ZrKsajyeioKMfDaTgaRtogINeh4HLDp
# mc085y9Euqf03GS9pAHBIAmTeM38vMDJRF1eFpwBBU8iTQIDAQABo4IB5jCCAeIw
# EAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFNVjOlyKMZDzQ3t8RhvFM2hahW1V
# MBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMB
# Af8EBTADAQH/MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1Ud
# HwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3By
# b2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEFBQcBAQRO
# MEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2Vy
# dHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0MIGgBgNVHSABAf8EgZUwgZIw
# gY8GCSsGAQQBgjcuAzCBgTA9BggrBgEFBQcCARYxaHR0cDovL3d3dy5taWNyb3Nv
# ZnQuY29tL1BLSS9kb2NzL0NQUy9kZWZhdWx0Lmh0bTBABggrBgEFBQcCAjA0HjIg
# HQBMAGUAZwBhAGwAXwBQAG8AbABpAGMAeQBfAFMAdABhAHQAZQBtAGUAbgB0AC4g
# HTANBgkqhkiG9w0BAQsFAAOCAgEAB+aIUQ3ixuCYP4FxAz2do6Ehb7Prpsz1Mb7P
# BeKp/vpXbRkws8LFZslq3/Xn8Hi9x6ieJeP5vO1rVFcIK1GCRBL7uVOMzPRgEop2
# zEBAQZvcXBf/XPleFzWYJFZLdO9CEMivv3/Gf/I3fVo/HPKZeUqRUgCvOA8X9S95
# gWXZqbVr5MfO9sp6AG9LMEQkIjzP7QOllo9ZKby2/QThcJ8ySif9Va8v/rbljjO7
# Yl+a21dA6fHOmWaQjP9qYn/dxUoLkSbiOewZSnFjnXshbcOco6I8+n99lmqQeKZt
# 0uGc+R38ONiU9MalCpaGpL2eGq4EQoO4tYCbIjggtSXlZOz39L9+Y1klD3ouOVd2
# onGqBooPiRa6YacRy5rYDkeagMXQzafQ732D8OE7cQnfXXSYIghh2rBQHm+98eEA
# 3+cxB6STOvdlR3jo+KhIq/fecn5ha293qYHLpwmsObvsxsvYgrRyzR30uIUBHoD7
# G4kqVDmyW9rIDVWZeodzOwjmmC3qjeAzLhIp9cAvVCch98isTtoouLGp25ayp0Ki
# yc8ZQU3ghvkqmqMRZjDTu3QyS99je/WZii8bxyGvWbWu3EQ8l1Bx16HSxVXjad5X
# wdHeMMD9zOZN+w2/XU/pnR4ZOC+8z1gFLu8NoFA12u8JJxzVs341Hgi62jbb01+P
# 3nSISRKhggLSMIICOwIBATCB/KGB1KSB0TCBzjELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEpMCcGA1UECxMgTWljcm9zb2Z0IE9wZXJhdGlvbnMg
# UHVlcnRvIFJpY28xJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjc4ODAtRTM5MC04
# MDE0MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloiMKAQEw
# BwYFKw4DAhoDFQCe4qWjxp8oR5Wcfl3rI/ieTmnwTKCBgzCBgKR+MHwxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29m
# dCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqGSIb3DQEBBQUAAgUA5TeaszAiGA8y
# MDIxMTExMTE3MzU0N1oYDzIwMjExMTEyMTczNTQ3WjB3MD0GCisGAQQBhFkKBAEx
# LzAtMAoCBQDlN5qzAgEAMAoCAQACAiFfAgH/MAcCAQACAhIKMAoCBQDlOOwzAgEA
# MDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEAAgMHoSChCjAI
# AgEAAgMBhqAwDQYJKoZIhvcNAQEFBQADgYEAVXAdKn/lMW/gnsO2JEUsF6mB+jVg
# poyQ/hEO/28e1Au/U5H4FmntnWQIq4D1vxPgSbBupOIyq2QvLrBWuHISKG4/0dyT
# Fxk3t4wBO3LTRbE3hbqitkULxYxAxzzb4mvZC+3fWy+P2FtNdXSJwQ76uV3YY9eO
# WjcF77irx2hv+3UxggMNMIIDCQIBATCBkzB8MQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQ
# Q0EgMjAxMAITMwAAAVyG0uPsOfaLOAAAAAABXDANBglghkgBZQMEAgEFAKCCAUow
# GgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJBDEiBCByHQmI
# Db8kcGPi2MmeGPYECfKvM1Pc3G4KELxp95UlWTCB+gYLKoZIhvcNAQkQAi8xgeow
# gecwgeQwgb0EIE8tZFfCIE9sADBJzKQgK1A99C4giEZvFe+0XI8MGea1MIGYMIGA
# pH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcT
# B1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UE
# AxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAFchtLj7Dn2izgA
# AAAAAVwwIgQgqSv4EQvpBzWF6zocglBNqyq/V0k68HrqFqM/DvcP7LYwDQYJKoZI
# hvcNAQELBQAEggEASDpK/lUn+3pCWhzkyXACcpAGOVbThtuh/8cVFAvZPN3Jo3qx
# Mi3AfHF6EhkECFFq8yAi12X4e8t3o/inxW1h3r8vWDHhAR25pPvpk132jSmf54UZ
# XW7x0wmEyu4V/oXDkfP3gAlcN0Wz/X6Gacbakt+BUv6oFDiHU0VuXUO7uf8Ywkps
# 7Jp02xEP8aEMhDNEMhByL+nS47sRK5Yi9H9W8BwVv3co0yTy/Nn1xRma4kdpL6iB
# xm/aNHkUzN+yQ7WxXwYEK8EH9eNawFBCS7toElAJyIlgtwcaqauLhulJrGbMFb6A
# JrawIWSrp1lpzh6+DwQK8y53A4ywAVkPwSghIQ==
# SIG # End signature block
