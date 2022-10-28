﻿#************************************************
# DC_WinStoreCollect.ps1
# Version 1.0
# Date: 2009-2019
# Author: Walter Eder (waltere@microsoft.com)
# Description: Collects Windows Store information.
# Called from: TS_AutoAddCommands_Apps.ps1
#*******************************************************

Trap [Exception]
	{
	 # Handle exception and throw it to the stdout log file. Then continue with function and script.
		 $Script:ExceptionMessage = $_
		 "[info]: Exception occurred."  | WriteTo-StdOut
		 "[info]: Exception.Message $ExceptionMessage."  | WriteTo-StdOut 
		 $Error.Clear()
		 continue
		 # later use return to return the exception message to an object:   return $Script:ExceptionMessage
	}

Write-verbose "$(Get-Date -UFormat "%R:%S") : Start of script DC_WinStoreCollect.ps1"

"Starting WinStoreCollect.ps1 script" | WriteTo-StdOut
"============================================================" | WriteTo-StdOut
#_# Import-LocalizedData -BindingVariable ScriptStrings

# Registry keys
"Getting Windows Store Registry Keys." | WriteTo-StdOut

$Regkeys = "HKLM\Software\Policies\Microsoft\WindowsStore"
$OutputFile = $ComputerName + "_Regkeys_WindowsStorePolicies_HKLM.txt"
RegQuery -RegistryKeys $Regkeys -Recursive $true -OutputFile $OutputFile -fileDescription "WindowsStore Policies Registry Key" -SectionDescription "Software Registry keys" 

$Regkeys = "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WSService\Packages" 
$OutputFile = $ComputerName + "_Regkeys_WSServicePackages_HKLM.txt"
RegQuery -RegistryKeys $Regkeys -Recursive $true -OutputFile $OutputFile -fileDescription "WSService Packages Registry Key" -SectionDescription "Software Registry keys"

# Saved Directories
"Getting Copies of Windows Store files" | WriteTo-StdOut
Write-DiagProgress -Activity $ScriptStrings.ID_WindowsStorefiles_Title -Status $ScriptStrings.ID_WindowsStorefiles_Status
$sectionDescription = "Windows Store files"
if(test-path "$env:windir\ImmersiveControlPanel")
{
	$DesinationTempFolder = Join-Path ($PWD.Path) ([System.Guid]::NewGuid().ToString())
	Copy-Item "$env:windir\ImmersiveControlPanel" -Destination $DesinationTempFolder -Force -Recurse -ErrorAction SilentlyContinue
	CompressCollectFiles -filesToCollect $DesinationTempFolder -DestinationFileName "ImmersiveControlPanel.zip" -fileDescription "Files under \Windows\ImmersiveControlPanel" -sectionDescription $sectionDescription -Recursive
	Remove-Item $DesinationTempFolder -Force -Recurse
}
if(test-path "$env:localappdata\Packages\WinStore_cw5n1h2txyewy\AC\Temp\Winstore.log")
{
	CollectFiles -filesToCollect "$env:localappdata\Packages\WinStore_cw5n1h2txyewy\AC\Temp\Winstore.log" -fileDescription "Winstore log" -sectionDescription $sectionDescription
}
if(test-path "$env:localappdata\Temp\WinStore.log")
{
	CollectFiles -filesToCollect "$env:localappdata\Temp\WinStore.log" -fileDescription "Broker log" -sectionDescription $sectionDescription
}

# Directory Listings
"Getting Directory Listing of Windows Store files" | WriteTo-StdOut
Write-DiagProgress -Activity $ScriptStrings.ID_WindowsStoreDirectoryListings_Title -Status $ScriptStrings.ID_WindowsStoreDirectoryListings_Status
$sectionDescription = "Windows Store Directory Listings"
if(test-path "$env:localappdata\Microsoft\Windows Store\Checkpoints")
{
	Get-ChildItem -Recurse "$env:localappdata\Microsoft\Windows Store\Checkpoints" >> "DirList_CheckPointDir.txt"
	CollectFiles -filesToCollect "DirList_CheckPointDir.txt" -fileDescription "CheckPoint Directory Listings" -sectionDescription $sectionDescription
}
if(test-path "$env:windir\Winstore")
{
	Get-ChildItem -Recurse "$env:windir\Winstore"                                  >> "DirList_WinStoreDir.txt"
	CollectFiles -filesToCollect "DirList_WinStoreDir.txt" -fileDescription "WinStore Directory Listings" -sectionDescription $sectionDescription
}

# Event Logs
"Getting Windows Store Event Logs" | WriteTo-StdOut
$sectionDescription = "Event Logs"
$EventLogNames = "Microsoft-WS-Licensing/Admin"
Run-DiagExpression .\TS_GetEvents.ps1 -EventLogNames $EventLogNames -SectionDescription $sectionDescription

# Running WSRun application:
$sectionDescription = "WinStore package and licensing information"
$OSProcessorArch = $Env:PROCESSOR_ARCHITECTURE
$ToolName = "wsrun" + $OSProcessorArch + ".exe"
$OutputFile = $ComputerName + "_WSRunResults.log"
$CommandLineToExecute = "cmd.exe /c $ToolName WSRunCommand.wsrun > $OutputFile"
"Executing $CommandLineToExecute to get WinStore package and licensing information" | WriteTo-StdOut
Write-DiagProgress -Activity $ScriptStrings.ID_WSRuntool_Title -Status $ScriptStrings.ID_WSRuntool_Status
RunCmD -commandToRun $CommandLineToExecute	-filesToCollect "WSRunResults.log" -fileDescription "WinStore package and licensing information" -sectionDescription $sectionDescription

Write-verbose "$(Get-Date -UFormat "%R:%S") :   end of script DC_WinStoreCollect.ps1"


# SIG # Begin signature block
# MIInowYJKoZIhvcNAQcCoIInlDCCJ5ACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDbtkXb5n927/7n
# jp/o782c3zA0N1Kwjv0E9/bVGSLXXqCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGYMwghl/AgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIDS2bAx2kTdjwEy9MN8Z9E7X
# nfnEqmrm8sZFeVrUzFIsMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQCE14E43BIo4H3SgCrLZWIr77X6SH9kQhp1FcD/NY1piGQjniz+tgza
# FWsWOMpItvwcRMlYY3nnBzLb1P82E6NpqEYuKMoydWypK0pBUNZDSJZqdpgpD4DM
# pt/Gy/ezp8h+MxCFUUFKLBC2asaa0d9hg7iqH9Ze1bNs9MRj2hed4Uq7CITeNnDi
# m2G82tNwueu+7s26KYcAQuwUkpyPNU1GwmWv2lRUoV5KB/8B17ARGhhhjxg7hd9r
# XioNcGa9a4nd2oZUKmwlQ85/6ci/1WTle1Em93Ztz814VxeCLxpGUljKq/ODXzh6
# gDs/AzEiaDze5KbhG3ts0BvFSvRGTP1/oYIXCzCCFwcGCisGAQQBgjcDAwExghb3
# MIIW8wYJKoZIhvcNAQcCoIIW5DCCFuACAQMxDzANBglghkgBZQMEAgEFADCCAVQG
# CyqGSIb3DQEJEAEEoIIBQwSCAT8wggE7AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIHy7ZRxDhhC5P2uUsa4Bkxo1B25n7n0SzoSzSWjQg3O0AgZi2wZs
# W2MYEjIwMjIwODAxMDc1MTUxLjYyWjAEgAIB9KCB1KSB0TCBzjELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEpMCcGA1UECxMgTWljcm9zb2Z0IE9w
# ZXJhdGlvbnMgUHVlcnRvIFJpY28xJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjRE
# MkYtRTNERC1CRUVGMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2
# aWNloIIRXzCCBxAwggT4oAMCAQICEzMAAAGwoeODMuiNO8AAAQAAAbAwDQYJKoZI
# hvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAO
# BgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEm
# MCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjIwMzAy
# MTg1MTQyWhcNMjMwNTExMTg1MTQyWjCBzjELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEpMCcGA1UECxMgTWljcm9zb2Z0IE9wZXJhdGlvbnMgUHVl
# cnRvIFJpY28xJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjREMkYtRTNERC1CRUVG
# MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIICIjANBgkq
# hkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAnMZtOwzX0oKdBzlELtWiCXJJcwou63/J
# ZY9BYPpUCUmAF7FUrHafXOBfej/EDZmBn80UZyA0NEInuYmI55bvF4eeg1c+WDsS
# Nha6V+Teg4CPprs7Xka9ySliy8tzH6jxJ7wKt8hvjQQnxbRDHhMhd/TIPAAnj+o7
# 3h0n+EZpt4liDganQbS5CaHAWi8BZMeUPVyL6ynfoDFP3AiEerD/vS3My+ucMXuO
# ZCNpVQ+eM6A87IVZmJWvt7quRKXhqdPW0u/bdJaFeoyzXjCiW/hl5BxY/zitXYWu
# vUpvCQhrS+UeOW/jEb1rqeVNF+jQJhRAN+tk4xcIjkpwA3YFnp9VvT2q0J2xZ003
# EHTLiXAyOe42bHzkU1/M9wxmObAAX1pFRQwse/rbojru3X51mhU+kqp9I2Ya1W30
# MRNaSYOKmcaDj4F1OmW+AZWr0Xcpk8MUdpvFsulJZ9db3Qxlc64UfzIIzMMk1TN7
# ICrK0UXItmKvePhPUbHuVF4I5Q/DWm5XNtYqylXsyh1mO038hRZ1Uh2Tcc+nhA3X
# DB1W91c6xh2EbySCMbIBkgPmivsL/vmHIpBvkXRn4R7Ti5j0r6wNneXfPxNBlYB9
# i6ttkIxZaeYlWy7lXg9Hk875ToPu0C0y8xQs1iJtP36zFVkr9ZB6vYkn2rdnuWMW
# ziWCmZ9zoBUCAwEAAaOCATYwggEyMB0GA1UdDgQWBBQ63wEkNwEmbh3LoBJketcg
# R9Y2PzAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBfBgNVHR8EWDBW
# MFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNy
# b3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmwwbAYIKwYBBQUH
# AQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtp
# b3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEp
# LmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3
# DQEBCwUAA4ICAQDdc+KHmw21R8DIueVeroxlKkKHRMX64b6eEgnjj/9wxxAYRWJn
# Y3brc3C+tCMIU6eL/6jF/vqNyZSFwpYteT2GF3u98UGFlnNwXlo2zTtSWKCzbim9
# 5qwW6GYnjLzY5ibUbU5FiwWd1l28X/82tgbFpepQ2VEdCWyRX+mZxyo7c6LrAsdw
# 8HX9ZFMsm1hsiKLAT+5MUQUQvjnBYP/WZMI8SQVfeGWJcTKnFfN1nWTpeoZPKwYC
# 0tdQHsgLoIfbpjKApC5cbxCNwkEBQb/0XfI1k51sW+fsWKdnI1whUvGV3uHRsQt9
# DOEiN6WP7mwEqEtxoVTS9uNuZ/RYQ2AWafIk2Iysvv/YVg4uyCJANsnHoOnLUR++
# 5Eax0vl/6NVV2zmgxoquHGBXugShusDpnnqedZg3juzDCi65wd/TKbUNBYfLYMc4
# VFE3vK/77N6zQZII6NFFg8ruuvVBz47eex3rTg6CbmdH1CqE45zY5BOu+1KBcFK2
# 7m8XpbwM9yyezndxDiB1xHVj02DkhgTDEJnPNiyr2hqXGUf5kf8Dontkx5I0o2St
# c/HqmkVdTEe4LeTibNXJk0ZY/9mBxQ6LapXTeboibK2+LWR8Z7ph0KHfY86BZ40f
# 2V8q353Uz6rgiEkuZfQTZlkgJgRv1DSuiZ4xfwZn5xuG42wWKYmBr9+OOzCCB3Ew
# ggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcNAQELBQAwgYgx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1p
# Y3Jvc29mdCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDEwMB4XDTIxMDkz
# MDE4MjIyNVoXDTMwMDkzMDE4MzIyNVowfDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENB
# IDIwMTAwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDk4aZM57RyIQt5
# osvXJHm9DtWC0/3unAcH0qlsTnXIyjVX9gF/bErg4r25PhdgM/9cT8dm95VTcVri
# fkpa/rg2Z4VGIwy1jRPPdzLAEBjoYH1qUoNEt6aORmsHFPPFdvWGUNzBRMhxXFEx
# N6AKOG6N7dcP2CZTfDlhAnrEqv1yaa8dq6z2Nr41JmTamDu6GnszrYBbfowQHJ1S
# /rboYiXcag/PXfT+jlPP1uyFVk3v3byNpOORj7I5LFGc6XBpDco2LXCOMcg1KL3j
# tIckw+DJj361VI/c+gVVmG1oO5pGve2krnopN6zL64NF50ZuyjLVwIYwXE8s4mKy
# zbnijYjklqwBSru+cakXW2dg3viSkR4dPf0gz3N9QZpGdc3EXzTdEonW/aUgfX78
# 2Z5F37ZyL9t9X4C626p+Nuw2TPYrbqgSUei/BQOj0XOmTTd0lBw0gg/wEPK3Rxjt
# p+iZfD9M269ewvPV2HM9Q07BMzlMjgK8QmguEOqEUUbi0b1qGFphAXPKZ6Je1yh2
# AuIzGHLXpyDwwvoSCtdjbwzJNmSLW6CmgyFdXzB0kZSU2LlQ+QuJYfM2BjUYhEfb
# 3BvR/bLUHMVr9lxSUV0S2yW6r1AFemzFER1y7435UsSFF5PAPBXbGjfHCBUYP3ir
# Rbb1Hode2o+eFnJpxq57t7c+auIurQIDAQABo4IB3TCCAdkwEgYJKwYBBAGCNxUB
# BAUCAwEAATAjBgkrBgEEAYI3FQIEFgQUKqdS/mTEmr6CkTxGNSnPEP8vBO4wHQYD
# VR0OBBYEFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMFwGA1UdIARVMFMwUQYMKwYBBAGC
# N0yDfQEBMEEwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9w
# a2lvcHMvRG9jcy9SZXBvc2l0b3J5Lmh0bTATBgNVHSUEDDAKBggrBgEFBQcDCDAZ
# BgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/
# BAUwAwEB/zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBWBgNVHR8E
# TzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9k
# dWN0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUHAQEETjBM
# MEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRz
# L01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNydDANBgkqhkiG9w0BAQsFAAOCAgEA
# nVV9/Cqt4SwfZwExJFvhnnJL/Klv6lwUtj5OR2R4sQaTlz0xM7U518JxNj/aZGx8
# 0HU5bbsPMeTCj/ts0aGUGCLu6WZnOlNN3Zi6th542DYunKmCVgADsAW+iehp4LoJ
# 7nvfam++Kctu2D9IdQHZGN5tggz1bSNU5HhTdSRXud2f8449xvNo32X2pFaq95W2
# KFUn0CS9QKC/GbYSEhFdPSfgQJY4rPf5KYnDvBewVIVCs/wMnosZiefwC2qBwoEZ
# QhlSdYo2wh3DYXMuLGt7bj8sCXgU6ZGyqVvfSaN0DLzskYDSPeZKPmY7T7uG+jIa
# 2Zb0j/aRAfbOxnT99kxybxCrdTDFNLB62FD+CljdQDzHVG2dY3RILLFORy3BFARx
# v2T5JL5zbcqOCb2zAVdJVGTZc9d/HltEAY5aGZFrDZ+kKNxnGSgkujhLmm77IVRr
# akURR6nxt67I6IleT53S0Ex2tVdUCbFpAUR+fKFhbHP+CrvsQWY9af3LwUFJfn6T
# vsv4O+S3Fb+0zj6lMVGEvL8CwYKiexcdFYmNcP7ntdAoGokLjzbaukz5m/8K6TT4
# JDVnK+ANuOaMmdbhIurwJ0I9JZTmdHRbatGePu1+oDEzfbzL6Xu/OHBE0ZDxyKs6
# ijoIYn/ZcGNTTY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggLSMIICOwIBATCB/KGB
# 1KSB0TCBzjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEpMCcG
# A1UECxMgTWljcm9zb2Z0IE9wZXJhdGlvbnMgUHVlcnRvIFJpY28xJjAkBgNVBAsT
# HVRoYWxlcyBUU1MgRVNOOjREMkYtRTNERC1CRUVGMSUwIwYDVQQDExxNaWNyb3Nv
# ZnQgVGltZS1TdGFtcCBTZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQACni+Q3d8PkU0F
# VhmSVl5L8kU8GKCBgzCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# MA0GCSqGSIb3DQEBBQUAAgUA5pFiOzAiGA8yMDIyMDgwMTAwMTkwN1oYDzIwMjIw
# ODAyMDAxOTA3WjB3MD0GCisGAQQBhFkKBAExLzAtMAoCBQDmkWI7AgEAMAoCAQAC
# AghgAgH/MAcCAQACAhCkMAoCBQDmkrO7AgEAMDYGCisGAQQBhFkKBAIxKDAmMAwG
# CisGAQQBhFkKAwKgCjAIAgEAAgMHoSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQEF
# BQADgYEAIgZGGzaelnzrN7ldftsFEP9wldx7rXJO52nSZysrovrUJC0UpT3vLFfv
# SrpVChuSMTJAd8fUe/gIX8ri4rYpMyPUp7FBqoyZ9LWgezR65UOXsdqjmo51DOWt
# j6vjsZsFB5kDTjT37wSfPk+3GgsSC9OSuO5mEk3/wm2t+y4TxZ8xggQNMIIECQIB
# ATCBkzB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYD
# VQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAbCh44My6I07
# wAABAAABsDANBglghkgBZQMEAgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3
# DQEJEAEEMC8GCSqGSIb3DQEJBDEiBCAB5WOSlFffHRS1HWXWj40K1ptTz/y1mOF9
# P9MuB3LLMzCB+gYLKoZIhvcNAQkQAi8xgeowgecwgeQwgb0EIM0GC0N3y5/0pOMZ
# /Ubrsh8qZw0UmZ5ZN3qKUDLnFYSgMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzAR
# BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgUENBIDIwMTACEzMAAAGwoeODMuiNO8AAAQAAAbAwIgQgWffTs1GpYMWZq6+U
# 4r3iS9a9TYXy88FzeEuFn3IPfMIwDQYJKoZIhvcNAQELBQAEggIAIQSf8E3iv9fh
# OTd1SdGovSQiINPI3wAyvCwNgBFuEQeCClSpZfbIrNoveyV64GctRnkuYJ3ntew4
# KFd7lPHML9tKAhJCC59vMCK85Z2fNTMfyS+nEutLFXte/h+TcohUX5F0jJLSWDoy
# DbgbP2+DisfmTTa4IZF2MbxJ6FC2Yny0oNY5SeSBFyjRGAobchUBgOOJDt0MDMXV
# pNLo/+eV3ZpMGsKuzAvtKfu+pG2dI1+sKS/zEh4EMMLKlhO0GHGjoOTYoPtZd4wA
# KAZtp4IfvrZuKucaQ52D7iXg8TQlKj74iQ2VHf4mn4v8+wQ/bDdywTw/pBtRzdUJ
# j4CkyetDPWQirrO2S9ouJZSdlZsR7U1y0DChoZtEwKrEGNxvAR7GITvlNB8Pn6D1
# MAPuhLutwHyfwDkIK9QuFn681nxtn/6erFNa7VaNaLYxHaRH0ZMUk4hMoQ//NvTw
# NSVb/GrqCISyWE0KgUiz5rovqI21cAwIsAmuXyqDZLR2SCcS25nUPuEIafAoaET8
# hbRYBL4LLHcVO9w/PvM4jOZuYbcdC3CwzdBezgkDj55+4eDMgDKaAINcj6Q7rhP+
# /gDnerGgGaPcQnv/fbox7wRWSvaPsWDwwys4YZOfwvWk3KDL9yzuakVpidOpqys8
# LZJhZXY08s8ocDTmKhXxW2d4z00FRM0=
# SIG # End signature block
