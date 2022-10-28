# 2021-07-08 WalterE added Trap #_# ToDo for SUVP

Trap [Exception]
	{
	 # Handle exception and throw it to the stdout log file. Then continue with function and script.
		 $Script:ExceptionMessage = $_
		 "[info]: Exception occurred."  | WriteTo-StdOut
		 "[info]: Exception.Message $ExceptionMessage."  | WriteTo-StdOut 
		 $Error.Clear()
		 continue
	}

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'HH:mm:ss') $Global:SDPtech - Collect Phase module: common ---"
	# version of the psSDP Diagnostic - "_psSDP_DiagnosticVersion.TXT"
	Run-DiagExpression .\DC_NetworkingDiagnostic.ps1

	# MSInfo
	Run-DiagExpression .\DC_MSInfo.ps1

	# Obtain pstat output
	Run-DiagExpression .\DC_PStat.ps1

	# CheckSym
	Run-DiagExpression .\DC_ChkSym.ps1

	# AutoRuns Information
	Run-DiagExpression .\DC_Autoruns.ps1

	# Collects Windows Server 2008/R2 Server Manager Information
	Run-DiagExpression .\DC_ServerManagerInfo.ps1

	# List Schedule Tasks using schtasks.exe utility
	Run-DiagExpression .\DC_ScheduleTasks.ps1

	# Collect Machine Registry Information for Setup and Performance Diagnostics
	Run-DiagExpression .\DC_RegistrySetupPerf.ps1
	
	# GPResults.exe Output
	Run-DiagExpression .\DC_RSoP.ps1

	# Basic System Information
	Run-DiagExpression .\DC_BasicSystemInformation.ps1

	# Basic System Information TXT output
	Run-DiagExpression .\DC_BasicSystemInformationTXT.ps1

	# Services
	Run-DiagExpression .\DC_Services.ps1

	# TaskListSvc
	Run-DiagExpression .\DC_TaskListSvc.ps1

	# User Rights (privileges) via the userrights.exe tool
	Run-DiagExpression .\DC_UserRights.ps1
	
	# WhoAmI
	Run-DiagExpression .\DC_Whoami.ps1

	# PoolMon
	Run-DiagExpression .\DC_PoolMon.ps1
	
	# Collects registry entries for KIR (for 2019) and RBC (for 2016) 
	Run-DiagExpression .\DC_KIR-RBC-RegEntries.ps1
	
	#_# Collect summary report 
	Run-DiagExpression .\DC_SummaryReliability.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'HH:mm:ss') $Global:SDPtech - Collect Phase module: Network ---"
	Run-DiagExpression .\DC_Get_Network.ps1
	Run-DiagExpression .\DC_Firewall-Component.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'HH:mm:ss') $Global:SDPtech - Collect Phase module: SVUP ---"
	#Event Logs - System & Application logs
	$EventLogNames = "System", "Application", "Security"
	Run-DiagExpression .\TS_GetEvents.ps1 -EventLogNames $EventLogNames -Days 15

	Run-DiagExpression .\TS_Virtualization.ps1 

	# WMI Query to Security Center
	Run-DiagExpression .\DC_WMISecurityCenter.ps1

	Run-DiagExpression .\DC_EnvVars.ps1

	#_# Run-DiagExpression .\DC_Office_Inventory.ps1 -> ROIscan
	Run-DiagExpression .\DC_ROIScan.ps1
	#Run Query_Registry. This collects all of the HKLM txt files
	Run-DiagExpression .\DC_Query_Registry.ps1
	#Run-DiagExpression .\DC_RegistryFEPClient.ps1
	Run-DiagExpression .\DC_Reg_ACLs.ps1
	Run-DiagExpression .\DC_Dirs.ps1
	#Run-DiagExpression .\DC_Driver_Dir.ps1
	Run-DiagExpression .\DC_FileVersions.ps1
	Run-DiagExpression .\DC_Handle.ps1
	Run-DiagExpression .\DC_Hardware.ps1
	Run-DiagExpression .\DC_Disk_Quota.ps1
	Run-DiagExpression .\DC_Certificates.ps1
	Run-DiagExpression .\DC_Get-Files.ps1
	#_# Run-DiagExpression .\DC_Checksym.ps1 #see common DC_ChkSym
	Run-DiagExpression .\DC_WGADiag.ps1
	Run-DiagExpression .\DC_File_ACLs.ps1
	Run-DiagExpression .\DC_ClassRegistration.ps1
	Run-DiagExpression .\DC_Descriptors.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'HH:mm:ss') $Global:SDPtech - Collect Phase module: Setup ---"
	# Fltmc
	Run-DiagExpression .\DC_Fltmc.ps1
	# Obtain information about Upper and lower filters Information fltrfind.exe utility
	Run-DiagExpression .\DC_Fltrfind.ps1
	# Collects Windows and ConfigMgr OSD Logs #_# added 2021.12.08
	Run-DiagExpression .\DC_CollectWindowsLogs.ps1
	
Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'HH:mm:ss') $Global:SDPtech - Collect Phase module: Update ---"
	# Update History
	Run-DiagExpression .\DC_UpdateHistory.ps1

	# Collect WindowsUpdate.Log
	Run-DiagExpression .\DC_WindowsUpdateLog.ps1
	
	# Hotfix Rollups
	Run-DiagExpression .\DC_HotfixRollups.ps1

Write-Host "*** $(Get-Date -UFormat "%R:%S") DONE TS_AutoAddCommands_SUVP.ps1 SkipTS: $Global:skipTS - SkipBPA: $Global:skipBPA"


# SIG # Begin signature block
# MIInuwYJKoZIhvcNAQcCoIInrDCCJ6gCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAfL5hVm4eEn2GZ
# +0S14iM+GjUPDLIS3MfKq3kUNXGFdqCCDYEwggX/MIID56ADAgECAhMzAAACUosz
# qviV8znbAAAAAAJSMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjEwOTAyMTgzMjU5WhcNMjIwOTAxMTgzMjU5WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDQ5M+Ps/X7BNuv5B/0I6uoDwj0NJOo1KrVQqO7ggRXccklyTrWL4xMShjIou2I
# sbYnF67wXzVAq5Om4oe+LfzSDOzjcb6ms00gBo0OQaqwQ1BijyJ7NvDf80I1fW9O
# L76Kt0Wpc2zrGhzcHdb7upPrvxvSNNUvxK3sgw7YTt31410vpEp8yfBEl/hd8ZzA
# v47DCgJ5j1zm295s1RVZHNp6MoiQFVOECm4AwK2l28i+YER1JO4IplTH44uvzX9o
# RnJHaMvWzZEpozPy4jNO2DDqbcNs4zh7AWMhE1PWFVA+CHI/En5nASvCvLmuR/t8
# q4bc8XR8QIZJQSp+2U6m2ldNAgMBAAGjggF+MIIBejAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUNZJaEUGL2Guwt7ZOAu4efEYXedEw
# UAYDVR0RBEkwR6RFMEMxKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMRYwFAYDVQQFEw0yMzAwMTIrNDY3NTk3MB8GA1UdIwQYMBaAFEhu
# ZOVQBdOCqhc3NyK1bajKdQKVMFQGA1UdHwRNMEswSaBHoEWGQ2h0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY0NvZFNpZ1BDQTIwMTFfMjAxMS0w
# Ny0wOC5jcmwwYQYIKwYBBQUHAQEEVTBTMFEGCCsGAQUFBzAChkVodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY0NvZFNpZ1BDQTIwMTFfMjAx
# MS0wNy0wOC5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAFkk3
# uSxkTEBh1NtAl7BivIEsAWdgX1qZ+EdZMYbQKasY6IhSLXRMxF1B3OKdR9K/kccp
# kvNcGl8D7YyYS4mhCUMBR+VLrg3f8PUj38A9V5aiY2/Jok7WZFOAmjPRNNGnyeg7
# l0lTiThFqE+2aOs6+heegqAdelGgNJKRHLWRuhGKuLIw5lkgx9Ky+QvZrn/Ddi8u
# TIgWKp+MGG8xY6PBvvjgt9jQShlnPrZ3UY8Bvwy6rynhXBaV0V0TTL0gEx7eh/K1
# o8Miaru6s/7FyqOLeUS4vTHh9TgBL5DtxCYurXbSBVtL1Fj44+Od/6cmC9mmvrti
# yG709Y3Rd3YdJj2f3GJq7Y7KdWq0QYhatKhBeg4fxjhg0yut2g6aM1mxjNPrE48z
# 6HWCNGu9gMK5ZudldRw4a45Z06Aoktof0CqOyTErvq0YjoE4Xpa0+87T/PVUXNqf
# 7Y+qSU7+9LtLQuMYR4w3cSPjuNusvLf9gBnch5RqM7kaDtYWDgLyB42EfsxeMqwK
# WwA+TVi0HrWRqfSx2olbE56hJcEkMjOSKz3sRuupFCX3UroyYf52L+2iVTrda8XW
# esPG62Mnn3T8AuLfzeJFuAbfOSERx7IFZO92UPoXE1uEjL5skl1yTZB3MubgOA4F
# 8KoRNhviFAEST+nG8c8uIsbZeb08SeYQMqjVEmkwggd6MIIFYqADAgECAgphDpDS
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
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIZkDCCGYwCAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAlKLM6r4lfM52wAAAAACUjAN
# BglghkgBZQMEAgEFAKCBsDAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgt5znO1qc
# YfdW9BTS2dfcyfevfxfWSt4+kIwP/ZTU8cUwRAYKKwYBBAGCNwIBDDE2MDSgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRyAGmh0dHBzOi8vd3d3Lm1pY3Jvc29mdC5jb20g
# MA0GCSqGSIb3DQEBAQUABIIBABr1LrtHu8UxVUI8wwC41DtaukAs2cO2ujq4Ud6r
# lciv1Ir5hOIaCrkk4iYVboPyeKjOQsq/m6ehSFZE44sSjIXl7XlCNTAYNsATdxWl
# UzhaAuU/cMmPSpLlqnvLMjRg1uGlGP1B2IoRVMGPRycU6JiEeuIs9LjSJ0UUzTh9
# 8iZQcHfrdg5ELDB28JqbFHi1pP7GOrR9OnqcghCAUD3lBcBPyP4Wkr5TYTElUK3F
# l7BS+58nRSyK1lyjmfW6nrAl4lSBkya5lMFq2N4fOQB9n7ILQ8GuYPvRQDooXBnB
# Xmf6eaoRk4y04tfRhjhqeb9+MhyEgcZlulHMcz7vplDcVbqhghcYMIIXFAYKKwYB
# BAGCNwMDATGCFwQwghcABgkqhkiG9w0BBwKgghbxMIIW7QIBAzEPMA0GCWCGSAFl
# AwQCAQUAMIIBWAYLKoZIhvcNAQkQAQSgggFHBIIBQzCCAT8CAQEGCisGAQQBhFkK
# AwEwMTANBglghkgBZQMEAgEFAAQgCignQ55u4qrVT+OQWntUk33M7ECh0bXVzD3e
# hW+lJBMCBmGVXnnjcBgSMjAyMTEyMDkxMzU1MDkuOTlaMASAAgH0oIHYpIHVMIHS
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRN
# aWNyb3NvZnQgSXJlbGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRo
# YWxlcyBUU1MgRVNOOjE3OUUtNEJCMC04MjQ2MSUwIwYDVQQDExxNaWNyb3NvZnQg
# VGltZS1TdGFtcCBTZXJ2aWNloIIRaDCCBxQwggT8oAMCAQICEzMAAAGKPjiN0g4C
# +ugAAQAAAYowDQYJKoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENB
# IDIwMTAwHhcNMjExMDI4MTkyNzQyWhcNMjMwMTI2MTkyNzQyWjCB0jELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UECxMkTWljcm9zb2Z0
# IElyZWxhbmQgT3BlcmF0aW9ucyBMaW1pdGVkMSYwJAYDVQQLEx1UaGFsZXMgVFNT
# IEVTTjoxNzlFLTRCQjAtODI0NjElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgU2VydmljZTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALf/rreh
# gwMgGb3oAYWoFndBqKk/JRRzHqaFjTizzxBKC7smuF95/iteBb5WcBZisKmqegfu
# hJCE0o5HnE0gekEQOJIr3ScnZS7yq4PLnbQbuuyyso0KsEcw0E0YRAsaVN9LXQRP
# wHsj/eZO6p3YSLvzqU+EBshiVIjA5ZmQIgz2ORSZIrVIBr8DAR8KICc/BVRARZ1Y
# gFEUyeJAQ4lOqaW7+DyPe/r0IabKQyvvN4GsmokQt4DUxst4jonuj7JdN3L2CIhX
# ACUT+DtEZHhZb/0kKKJs9ybbDHfaKEv1ztL0jfYdg1SjjTI2hToJzeUZOYgqsJp+
# qrJnvoWqEf06wgUtM1417Fk4JJY1Abbde1AW1vES/vSzcN3IzyfBGEYJTDVwmCzO
# hswg1xLxPU//7AL/pNXPOLZqImQ2QagYK/0ry/oFbDs9xKA2UNuqk2tWxJ/56cTJ
# l3LaGUnvEkQ6oCtCVFoYyl4J8mjgAxAfhbXyIvo3XFCW6T7QC+JFr1UkSoqVb/DB
# LmES3sVxAxAYvleLXygKWYROIGtKfkAomsBywWTaI91EDczOUFZhmotzJ0BW2ZIa
# m1A8qaPb2lhHlXjt+SX3S1o8EYLzF91SmS+e3e45kY4lZZbl42RS8fq4SS+yWFab
# Tj7RdTALTGJaejroJzqRvuFuDBh6o+2GHz9FAgMBAAGjggE2MIIBMjAdBgNVHQ4E
# FgQUI9pD2P1sGdSXrqdJR4Q+MZBpJAMwHwYDVR0jBBgwFoAUn6cVXQBeYl2D9OXS
# ZacbUzUZ6XIwXwYDVR0fBFgwVjBUoFKgUIZOaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIw
# MTAoMSkuY3JsMGwGCCsGAQUFBwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBUaW1lLVN0
# YW1wJTIwUENBJTIwMjAxMCgxKS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAK
# BggrBgEFBQcDCDANBgkqhkiG9w0BAQsFAAOCAgEAxfTBErD1w3kbXxaNX+e+Yj3x
# fQEVm3rrjXzOfNyH08X82X9nb/5ntwzYvynDTRJ0dUym2bRuy7INHMv6SiBEDiRt
# n2GlsCCCmMLsgySNkOJFYuZs21f9Aufr0ELEHAr37DPCuV9n34nyYu7anhtK+fAo
# 4MHu8QWL4Lj5o1DccE1rxI2SD36Y1VKGjwpeqqrNHhVG+23C4c0xBGAZwI/DBDYY
# j+SCXeD6eZRah07aXnOu2BZhrjv7iAP04zwX3LTOZFCPrs38of8iHbQzbZCM/nv8
# Zl0hYYkBEdLgY0aG0GVenPtEzbb0TS2slOLuxHpHezmg180EdEblhmkosLTel3Pz
# 6DT9K3sxujr3MqMNajKFJFBEO6qg9EKvEBcCtAygnWUibcgSjAaY1GApzVGW2L00
# 1puA1yuUWIH9t21QSVuF6OcOPdBx6OE41jas9ez6j8jAk5zPB3AKk5z3jBNHT2L2
# 3cMwzIG7psnWyWqv9OhSJpCeyl7PY8ag4hNj03mJ2o/Np+kP/z6mx7scSZsEDuH8
# 3ToFagBJBtVw5qaVSlv6ycQTdyMcla+kD/XIWNjGFWtG2wAiNnb1PkdkCZROQI6D
# CsuvFiNaZhU9ySga62nKcuh1Ixq7Vfv9VOdm66xJQpVcuRW/PlGVmS6fNnLgs7ST
# DEqlvpD+c8lQUryzPuAwggdxMIIFWaADAgECAhMzAAAAFcXna54Cm0mZAAAAAAAV
# MA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRo
# b3JpdHkgMjAxMDAeFw0yMTA5MzAxODIyMjVaFw0zMDA5MzAxODMyMjVaMHwxCzAJ
# BgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25k
# MR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jv
# c29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEA5OGmTOe0ciELeaLL1yR5vQ7VgtP97pwHB9KpbE51yMo1V/YBf2xK
# 4OK9uT4XYDP/XE/HZveVU3Fa4n5KWv64NmeFRiMMtY0Tz3cywBAY6GB9alKDRLem
# jkZrBxTzxXb1hlDcwUTIcVxRMTegCjhuje3XD9gmU3w5YQJ6xKr9cmmvHaus9ja+
# NSZk2pg7uhp7M62AW36MEBydUv626GIl3GoPz130/o5Tz9bshVZN7928jaTjkY+y
# OSxRnOlwaQ3KNi1wjjHINSi947SHJMPgyY9+tVSP3PoFVZhtaDuaRr3tpK56KTes
# y+uDRedGbsoy1cCGMFxPLOJiss254o2I5JasAUq7vnGpF1tnYN74kpEeHT39IM9z
# fUGaRnXNxF803RKJ1v2lIH1+/NmeRd+2ci/bfV+AutuqfjbsNkz2K26oElHovwUD
# o9Fzpk03dJQcNIIP8BDyt0cY7afomXw/TNuvXsLz1dhzPUNOwTM5TI4CvEJoLhDq
# hFFG4tG9ahhaYQFzymeiXtcodgLiMxhy16cg8ML6EgrXY28MyTZki1ugpoMhXV8w
# dJGUlNi5UPkLiWHzNgY1GIRH29wb0f2y1BzFa/ZcUlFdEtsluq9QBXpsxREdcu+N
# +VLEhReTwDwV2xo3xwgVGD94q0W29R6HXtqPnhZyacaue7e3PmriLq0CAwEAAaOC
# Ad0wggHZMBIGCSsGAQQBgjcVAQQFAgMBAAEwIwYJKwYBBAGCNxUCBBYEFCqnUv5k
# xJq+gpE8RjUpzxD/LwTuMB0GA1UdDgQWBBSfpxVdAF5iXYP05dJlpxtTNRnpcjBc
# BgNVHSAEVTBTMFEGDCsGAQQBgjdMg30BATBBMD8GCCsGAQUFBwIBFjNodHRwOi8v
# d3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5odG0wEwYD
# VR0lBAwwCgYIKwYBBQUHAwgwGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwCwYD
# VR0PBAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU1fZWy4/oolxi
# aNE9lJBb186aGMQwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDovL2NybC5taWNyb3Nv
# ZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMu
# Y3JsMFoGCCsGAQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0cDovL3d3dy5taWNy
# b3NvZnQuY29tL3BraS9jZXJ0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcnQw
# DQYJKoZIhvcNAQELBQADggIBAJ1VffwqreEsH2cBMSRb4Z5yS/ypb+pcFLY+Tkdk
# eLEGk5c9MTO1OdfCcTY/2mRsfNB1OW27DzHkwo/7bNGhlBgi7ulmZzpTTd2YurYe
# eNg2LpypglYAA7AFvonoaeC6Ce5732pvvinLbtg/SHUB2RjebYIM9W0jVOR4U3Uk
# V7ndn/OOPcbzaN9l9qRWqveVtihVJ9AkvUCgvxm2EhIRXT0n4ECWOKz3+SmJw7wX
# sFSFQrP8DJ6LGYnn8AtqgcKBGUIZUnWKNsIdw2FzLixre24/LAl4FOmRsqlb30mj
# dAy87JGA0j3mSj5mO0+7hvoyGtmW9I/2kQH2zsZ0/fZMcm8Qq3UwxTSwethQ/gpY
# 3UA8x1RtnWN0SCyxTkctwRQEcb9k+SS+c23Kjgm9swFXSVRk2XPXfx5bRAGOWhmR
# aw2fpCjcZxkoJLo4S5pu+yFUa2pFEUep8beuyOiJXk+d0tBMdrVXVAmxaQFEfnyh
# YWxz/gq77EFmPWn9y8FBSX5+k77L+DvktxW/tM4+pTFRhLy/AsGConsXHRWJjXD+
# 57XQKBqJC4822rpM+Zv/Cuk0+CQ1ZyvgDbjmjJnW4SLq8CdCPSWU5nR0W2rRnj7t
# fqAxM328y+l7vzhwRNGQ8cirOoo6CGJ/2XBjU02N7oJtpQUQwXEGahC0HVUzWLOh
# cGbyoYIC1zCCAkACAQEwggEAoYHYpIHVMIHSMQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBPcGVy
# YXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjE3OUUtNEJC
# MC04MjQ2MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloiMK
# AQEwBwYFKw4DAhoDFQCA8PNjrxtTBQQdp/+MHlaqc1fEoaCBgzCBgKR+MHwxCzAJ
# BgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25k
# MR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jv
# c29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqGSIb3DQEBBQUAAgUA5Vw0cDAi
# GA8yMDIxMTIwOTE1NTMyMFoYDzIwMjExMjEwMTU1MzIwWjB3MD0GCisGAQQBhFkK
# BAExLzAtMAoCBQDlXDRwAgEAMAoCAQACAhsXAgH/MAcCAQACAhG7MAoCBQDlXYXw
# AgEAMDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEAAgMHoSCh
# CjAIAgEAAgMBhqAwDQYJKoZIhvcNAQEFBQADgYEAhvCLYeA5ubKkwB7zarToeDcy
# BLTQ3uZ5f0oz4GYDyYYWpdu80klKQ+tQVYuMJBOElFb2685Fa9+PMyz5EVe2u6Pi
# j8R8esqLRerIXYr+RdN1IoF6AlEqysMMs8mr38YLoAKwJm+Dvblg3yQY91nbBv6/
# KVcJDXih7kTzCw+hHjsxggQNMIIECQIBATCBkzB8MQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFt
# cCBQQ0EgMjAxMAITMwAAAYo+OI3SDgL66AABAAABijANBglghkgBZQMEAgEFAKCC
# AUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJBDEiBCA/
# swF99ILIm/UBoa65xyyoCf8pAHzdH+TI8oaJBfsrvzCB+gYLKoZIhvcNAQkQAi8x
# geowgecwgeQwgb0EIPS94Kt130q+fvO/fzD4MbWQhQaE7RHkOH6AkjlNVCm9MIGY
# MIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGKPjiN0g4C
# +ugAAQAAAYowIgQgPeeZQlB6JxedGwuvyc0hzSybUdf1G0RMpY1ZJym/pfgwDQYJ
# KoZIhvcNAQELBQAEggIAB6HwF+sqii8dxoEc7oE1WtadJmt/GO1/+qVGDUp95aJb
# LT9qoc3gvLXHWPYjf+/+l9yDlmrC9pkUlyYIXnMVyQu9YKjpiCvmjKL034Y6eE27
# P/QfpFzDlRA7M4PYI0C5Vb/iJVtoGqovZjf8fMz9bFBbb+anbqmS9eb5+9SYtp7z
# 0GPf80KIFVUrRO/yrQVRTjDzc4HKQgYfPMCuJkpAid2rlRhabz5D6UssQ+2EMn00
# /894bbEZZjq21wpGi0c6zsnLpv2Tr2rNuHSdAe01TL2L+GG3QNtHUtZOf0Tr0I89
# uMfjV6pMlJcFCoyyJhfvj4SIBzDKzYsB+ZrbjvVCtJtJdKx0lwaoUV9cJl/0VRiT
# qM5b7bJvoK3PsOUjpaV4nWBROF2EDKSn/SvElKuq6mQNUK9TaNEXZbGe8Y4vSb9q
# SL6Pydk+F26An4Ggr3o2vFsy9LZPtqokMYWBr0ZijyVhWLYw7pvuYvSwhJytANER
# QnU+DruszBdm5mONOy2EBDlrCMK7KaqOH3ahwgjYeWqCH9MWI+wb4rvQGT4KkdfZ
# DhJIixNndRGKgUPJ+RSTJ8LJHyoW2fpkhswQI+tcaZ5+nNEKs3v8f0ZK7Y4xBmd5
# fM0Klol9NlXiF38VAd0YXSFbs8Lpj2jag4PaAc2Abvlne/yPcdaxXBMRAk+7L18=
# SIG # End signature block
